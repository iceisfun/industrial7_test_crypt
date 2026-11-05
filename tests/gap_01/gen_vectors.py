#!/usr/bin/env python3
# Authoring-time generator for vectors.h (fixed RSA identities, openssl-built signed/enveloped messages,
# hand-built digested-data messages). Output is checked in; random material is fixed at authoring time.
import datetime, subprocess, os, tempfile, hashlib
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding, utils

D = datetime.datetime
tmp = tempfile.mkdtemp()
def w(n, b): p = os.path.join(tmp, n); open(p, 'wb').write(b); return p
def name(cn): return x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CryptT"), x509.NameAttribute(NameOID.COMMON_NAME, cn)])
der = lambda o: o.public_bytes(serialization.Encoding.DER)
pem = lambda o: o.public_bytes(serialization.Encoding.PEM)
def mk(cn, serial, nb, na):
    k = rsa.generate_private_key(65537, 1024)
    n = name(cn)
    c = (x509.CertificateBuilder().subject_name(n).issuer_name(n).public_key(k.public_key())
         .serial_number(serial).not_valid_before(nb).not_valid_after(na).sign(k, hashes.SHA256()))
    return k, c
def le(n, size): return n.to_bytes(size, 'little')
def privblob(k, algid=0xA400):
    pn = k.private_numbers(); bits = k.key_size; nb = bits // 8; hb = bits // 16
    hdr = bytes([7, 2, 0, 0]) + algid.to_bytes(4, 'little')
    rk = b'RSA2' + bits.to_bytes(4, 'little') + (pn.public_numbers.e).to_bytes(4, 'little')
    return (hdr + rk + le(pn.public_numbers.n, nb) + le(pn.p, hb) + le(pn.q, hb) + le(pn.dmp1, hb)
            + le(pn.dmq1, hb) + le(pn.iqmp, hb) + le(pn.d, nb))
def ossl(*a): return subprocess.check_output(["openssl"] + list(a), stderr=subprocess.DEVNULL)

kA, cA = mk("CryptT Gap1 A", 0x3A01, D(2020,1,1), D(2060,1,1))
kB, cB = mk("CryptT Gap1 B", 0x3A02, D(2020,1,1), D(2060,1,1))
# cC: same serial and issuer as A but different key (CertCompareCertificate compares serial+issuer only)
kC, cC = mk("CryptT Gap1 A", 0x3A01, D(2021,6,1), D(2050,1,1))
PAYLOAD = b"gap1 payload: the quick brown fox 0123456789"
pl = w("payload.bin", PAYLOAD)
fA = w("a.pem", pem(cA)); fAk = w("a_key.pem", kA.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
def sign(extra, md="sha256"):
    return ossl("smime","-sign","-binary","-in",pl,"-outform","DER","-md",md,"-signer",fA,"-inkey",fAk,*extra)
M = {}

# raw PKCS#1 v1.5 SHA-256 signature by key A over PAYLOAD (deterministic) and EC certs/signatures
SIG_A = kA.sign(PAYLOAD, padding.PKCS1v15(), hashes.SHA256())
def ec_ident(curve, cn, serial, h):
    k = ec.generate_private_key(curve)
    n = name(cn)
    c = (x509.CertificateBuilder().subject_name(n).issuer_name(n).public_key(k.public_key())
         .serial_number(serial).not_valid_before(D(2020,1,1)).not_valid_after(D(2060,1,1)).sign(k, h))
    sz = (curve.key_size + 7) // 8
    r, s_ = utils.decode_dss_signature(k.sign(PAYLOAD, ec.ECDSA(h)))
    pn = k.public_key().public_numbers()
    return c, pn.x.to_bytes(sz, 'big'), pn.y.to_bytes(sz, 'big'), r.to_bytes(sz, 'big') + s_.to_bytes(sz, 'big')
cE256, x256, y256, sig256 = ec_ident(ec.SECP256R1(), "CryptT Gap1 EC256", 0x3A10, hashes.SHA256())
cE384, x384, y384, sig384 = ec_ident(ec.SECP384R1(), "CryptT Gap1 EC384", 0x3A11, hashes.SHA384())
M["sig_att"] = sign(["-nodetach"])
M["sig_att_sha1"] = sign(["-nodetach"], "sha1")
M["sig_att_noattr"] = sign(["-nodetach","-noattr"])
M["sig_att_nocerts"] = sign(["-nodetach","-nocerts"])
M["sig_det"] = sign([])
M["sig_det_noattr"] = sign(["-noattr"])
M["env_aes256"] = ossl("smime","-encrypt","-binary","-aes256","-in",pl,"-outform","DER",fA)
M["env_aes128"] = ossl("smime","-encrypt","-binary","-aes128","-in",pl,"-outform","DER",fA)
M["env_3des"] = ossl("smime","-encrypt","-binary","-des3","-in",pl,"-outform","DER",fA)

# hand-built PKCS#7 DigestedData
def tlv(t, c):
    n = len(c)
    if n < 128: l = bytes([n])
    else:
        b = n.to_bytes((n.bit_length()+7)//8, 'big'); l = bytes([0x80|len(b)]) + b
    return bytes([t]) + l + c
def oid(s):
    p = [int(x) for x in s.split('.')]; b = bytes([p[0]*40+p[1]])
    for v in p[2:]:
        e = [v & 0x7f]; v >>= 7
        while v: e.insert(0, 0x80 | (v & 0x7f)); v >>= 7
        b += bytes(e)
    return tlv(6, b)
def digested(hashname, hoid, data, detached=False, corrupt=False):
    h = hashlib.new(hashname, data).digest()
    if corrupt: h = bytes([h[0] ^ 1]) + h[1:]
    alg = tlv(0x30, oid(hoid) + tlv(5, b''))
    inner = tlv(0x30, oid("1.2.840.113549.1.7.1") + (b'' if detached else tlv(0xA0, tlv(4, data))))
    dd = tlv(0x30, tlv(2, b'\x00') + alg + inner + tlv(4, h))
    return tlv(0x30, oid("1.2.840.113549.1.7.5") + tlv(0xA0, dd))
H = {"sha1": "1.3.14.3.2.26", "sha256": "2.16.840.1.101.3.4.2.1", "md5": "1.2.840.113549.2.5", "sha512": "2.16.840.1.101.3.4.2.3"}
for hn, ho in H.items():
    M["dig_"+hn] = digested(hn, ho, PAYLOAD)
    M["digdet_"+hn] = digested(hn, ho, PAYLOAD, detached=True)
M["dig_sha256_bad"] = digested("sha256", H["sha256"], PAYLOAD, corrupt=True)
M["digdet_sha256_bad"] = digested("sha256", H["sha256"], PAYLOAD, detached=True, corrupt=True)
M["dig_sha256_empty"] = digested("sha256", H["sha256"], b"")

def arr(n, b): return "static const BYTE %s[] = {%s};\n" % (n, ",".join("0x%02x" % x for x in b))
out = ["/* generated by gen_vectors.py - do not edit */\n"]
out.append(arr("v_payload", PAYLOAD))
out.append(arr("v_certA", der(cA))); out.append(arr("v_keyA", privblob(kA)))
out.append(arr("v_certB", der(cB))); out.append(arr("v_keyB", privblob(kB)))
out.append(arr("v_certC", der(cC)))
out.append(arr("v_sigA", SIG_A))
out.append(arr("v_certE256", der(cE256))); out.append(arr("v_e256x", x256)); out.append(arr("v_e256y", y256)); out.append(arr("v_e256sig", sig256))
out.append(arr("v_certE384", der(cE384))); out.append(arr("v_e384x", x384)); out.append(arr("v_e384y", y384)); out.append(arr("v_e384sig", sig384))
for k, v in M.items(): out.append(arr("v_" + k, v))
for h in H: out.append("static const BYTE v_h_%s[] = {%s};\n" % (h, ",".join("0x%02x" % x for x in hashlib.new(h, PAYLOAD).digest())))
open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "vectors.h"), "w").write("".join(out))
