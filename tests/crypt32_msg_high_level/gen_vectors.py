#!/usr/bin/env python3
# Authoring-time generator for vectors.h (fixed RSA certs, CAPI private key blobs, openssl-built messages,
# object-query samples, hash known answers). Output is checked in; random material is fixed at authoring time.
import datetime, subprocess, os, tempfile, hashlib
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

D = datetime.datetime
tmp = tempfile.mkdtemp()
def w(n, b): p = os.path.join(tmp, n); open(p, 'wb').write(b); return p
def name(cn): return x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CryptT"), x509.NameAttribute(NameOID.COMMON_NAME, cn)])
der = lambda o: o.public_bytes(serialization.Encoding.DER)
pem = lambda o: o.public_bytes(serialization.Encoding.PEM)
def key(bits=1024): return rsa.generate_private_key(65537, bits)
ca_k = key(2048); ca_n = name("CryptT MH CA")
def cert(cn, k, serial, issuer_key=ca_k, issuer=ca_n):
    b = (x509.CertificateBuilder().subject_name(name(cn)).issuer_name(issuer).public_key(k.public_key())
         .serial_number(serial).not_valid_before(D(2020,1,1)).not_valid_after(D(2060,1,1)))
    return b.sign(issuer_key, hashes.SHA256())
ca = cert("CryptT MH CA", ca_k, 1)
keys = {n: key() for n in ("s1","s2","r1","r2")}
certs = {"s1": cert("CryptT MH Signer 1", keys["s1"], 0x2001),
         "s2": cert("CryptT MH Signer 2", keys["s2"], 0x2002),
         "r1": cert("CryptT MH Recipient 1", keys["r1"], 0x2003),
         "r2": cert("CryptT MH Recipient 2", keys["r2"], 0x2004)}

def le(n, size): return n.to_bytes(size, 'little')
def privblob(k):
    pn = k.private_numbers(); bits = k.key_size; nb = bits // 8; hb = bits // 16
    hdr = bytes([7, 2, 0, 0]) + (0xA400).to_bytes(4, 'little')
    rk = b'RSA2' + bits.to_bytes(4, 'little') + (pn.public_numbers.e).to_bytes(4, 'little')
    return (hdr + rk + le(pn.public_numbers.n, nb) + le(pn.p, hb) + le(pn.q, hb) + le(pn.dmp1, hb)
            + le(pn.dmq1, hb) + le(pn.iqmp, hb) + le(pn.d, nb))

PAYLOAD = b"CryptT high-level message payload 0123456789abcdef"
pl = w("payload.bin", PAYLOAD)
files = {}
for n in keys:
    files[n+"_cert"] = w(n+".pem", pem(certs[n]))
    files[n+"_key"] = w(n+"_key.pem", keys[n].private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
files["ca"] = w("ca.pem", pem(ca))
def ossl(*a, **kw):
    return subprocess.check_output(["openssl"] + list(a), **kw)
def smime_sign(extra, signers=("s1",), md="sha256"):
    args = ["smime","-sign","-binary","-in",pl,"-outform","DER","-md",md,"-certfile",files["ca"]] + extra
    for s in signers: args += ["-signer", files[s+"_cert"], "-inkey", files[s+"_key"]]
    return ossl(*args)
M = {}
M["m_sig_attr"] = smime_sign(["-nodetach"])
M["m_sig_noattr"] = smime_sign(["-nodetach","-noattr"])
M["m_sig_det_attr"] = smime_sign([])
M["m_sig_det_noattr"] = smime_sign(["-noattr"])
M["m_sig_two_noattr"] = smime_sign(["-nodetach","-noattr"], ("s1","s2"))
M["m_sig_nocert"] = smime_sign(["-nodetach","-noattr","-nocerts"])
M["m_sig_sha1"] = smime_sign(["-nodetach","-noattr"], md="sha1")
M["m_sig_sha512"] = smime_sign(["-nodetach","-noattr"], md="sha512")
def smime_enc(cipher, rcpts):
    return ossl("smime","-encrypt","-binary","-in",pl,"-outform","DER",cipher,*[files[r+"_cert"] for r in rcpts])
M["m_env_aes256"] = smime_enc("-aes256", ("r1",))
M["m_env_aes128"] = smime_enc("-aes128", ("r1",))
M["m_env_des3"] = smime_enc("-des3", ("r1",))
M["m_env_two"] = smime_enc("-aes128", ("r1","r2"))
M["m_env_r2"] = smime_enc("-aes128", ("r2",))
allpem = w("all.pem", pem(certs["s1"]) + pem(certs["s2"]))
M["m_certs_only"] = ossl("crl2pkcs7","-nocrl","-certfile",allpem,"-outform","DER")

def L(n):
    if n < 0x80: return bytes([n])
    b = n.to_bytes((n.bit_length()+7)//8, 'big'); return bytes([0x80|len(b)]) + b
def T(tag, c): return bytes([tag]) + L(len(c)) + c
def oid(s):
    p = [int(x) for x in s.split('.')]; o = bytes([p[0]*40+p[1]])
    for v in p[2:]:
        e = [v & 0x7f]; v >>= 7
        while v: e.append(0x80 | (v & 0x7f)); v >>= 7
        o += bytes(reversed(e))
    return T(6, o)
def integer(n): return T(2, n.to_bytes(n.bit_length()//8+1, 'big'))

# digested-data (hashed) messages, hand built: version 0, digestAlgorithm, contentInfo, digest
def hashed(alg_oid, h, detach=False):
    algid = T(0x30, oid(alg_oid) + b"\x05\x00")
    ci = T(0x30, oid("1.2.840.113549.1.7.1") + (b"" if detach else T(0xa0, T(4, PAYLOAD))))
    dd = T(0x30, integer(0) + algid + ci + T(4, h(PAYLOAD).digest()))
    return T(0x30, oid("1.2.840.113549.1.7.5") + T(0xa0, dd))
M["m_hashed_sha256"] = hashed("2.16.840.1.101.3.4.2.1", hashlib.sha256)
M["m_hashed_sha1"] = hashed("1.3.14.3.2.26", hashlib.sha1)
M["m_hashed_sha256_det"] = hashed("2.16.840.1.101.3.4.2.1", hashlib.sha256, True)

# object samples
def crl(tu, serials):
    b = x509.CertificateRevocationListBuilder().issuer_name(ca_n).last_update(tu).next_update(D(2060,1,1))
    for s in serials:
        b = b.add_revoked_certificate(x509.RevokedCertificateBuilder().serial_number(s).revocation_date(D(2022,1,1)).build())
    return b.sign(ca_k, hashes.SHA256())
crl1 = crl(D(2022,1,1), [0x2001])
M["o_cert"] = der(certs["s1"]); M["o_crl"] = der(crl1)
M["o_p7_crl"] = ossl("crl2pkcs7","-in",w("crl.pem",pem(crl1)),"-certfile",allpem,"-outform","DER")
csr = (x509.CertificateSigningRequestBuilder().subject_name(name("CryptT MH Request"))
       .sign(keys["s1"], hashes.SHA256()))
M["o_p10"] = der(csr)
M["o_pfx"] = ossl("pkcs12","-export","-inkey",files["s1_key"],"-in",files["s1_cert"],"-certfile",files["ca"],
    "-passout","pass:cryptt","-keypbe","PBE-SHA1-3DES","-certpbe","PBE-SHA1-3DES","-macalg","sha1")

M["o_pair"] = T(0x30, T(0xa0, der(certs["s1"])) + T(0xa1, der(certs["s2"])))
M["o_pair_fwd"] = T(0x30, T(0xa0, der(certs["s1"])))

def arr(n, b): return "static const BYTE %s[] = {%s};\n" % (n, ",".join("0x%02x" % x for x in b))
out = ["/* generated by gen_vectors.py - do not edit */\n"]
out.append(arr("v_payload", PAYLOAD))
out.append(arr("v_ca", der(ca)))
for n in keys:
    out.append(arr("v_%s_cert" % n, der(certs[n])))
    out.append(arr("v_%s_key" % n, privblob(keys[n])))
for n, b in M.items(): out.append(arr("v_" + n, b))
for nm, h in (("md5", hashlib.md5), ("sha1", hashlib.sha1), ("sha256", hashlib.sha256), ("sha384", hashlib.sha384), ("sha512", hashlib.sha512)):
    out.append(arr("v_h_%s" % nm, h(PAYLOAD).digest()))
    out.append(arr("v_h_%s_abc" % nm, h(b"abc").digest()))
    out.append(arr("v_h_%s_empty" % nm, h(b"").digest()))
open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "vectors.h"), "w").write("".join(out))
print("ok", {k: len(v) for k, v in M.items()})
