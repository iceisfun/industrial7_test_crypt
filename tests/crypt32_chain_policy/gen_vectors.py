#!/usr/bin/env python3
# Authoring-time generator for vectors.h (offline chain fixtures). Output is checked in.
import datetime, ipaddress
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID as E
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

D = datetime.datetime
der = lambda o: o.public_bytes(serialization.Encoding.DER)
def key(): return rsa.generate_private_key(65537, 2048)
def name(cn): return x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CryptT Policy"), x509.NameAttribute(NameOID.COMMON_NAME, cn)])

K = {}
def k(n):
    if n not in K: K[n] = key()
    return K[n]
leafkey = key()
out = []   # (cname, der)
OBJ = {}
def mk(cname, cn, subj_key, issuer, issuer_key, nb=D(2020,1,1), na=D(2049,1,1), serial=None,
       ca=None, pathlen=None, eku=None, san=None, bc=True, keyusage=None):
    b = (x509.CertificateBuilder().subject_name(name(cn)).issuer_name(issuer if issuer is not None else name(cn))
         .public_key(subj_key.public_key()).serial_number(serial or (len(out) + 0x2000))
         .not_valid_before(nb).not_valid_after(na))
    if ca is not None and bc:
        b = b.add_extension(x509.BasicConstraints(ca=ca, path_length=pathlen), critical=True)
    if ca:
        b = b.add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
    if eku: b = b.add_extension(x509.ExtendedKeyUsage(eku), critical=False)
    if san is not None: b = b.add_extension(x509.SubjectAlternativeName(san), critical=False)
    c = b.sign(issuer_key if issuer_key is not None else subj_key, hashes.SHA256())
    out.append((cname, der(c))); OBJ[cname] = (c, name(cn))
    return c

def ca(cname, cn, issuer_c, issuer_k, **kw):
    kk = k(cname)
    return mk(cname, cn, kk, issuer_c.subject if issuer_c is not None else None, issuer_k, **kw)

root = ca("root", "CryptT Policy Root", None, None, ca=True)
root2 = ca("root2", "CryptT Untrusted Root", None, None, ca=True)
inter = ca("inter", "CryptT Policy Intermediate", root, k("root"), ca=True, pathlen=0)
intshort = ca("intshort", "CryptT Short Intermediate", root, k("root"), ca=True, nb=D(2022,1,1), na=D(2026,1,1))
inter_ee = ca("inter_ee", "CryptT Not A CA", root, k("root"), ca=False)
inter_nobc = ca("inter_nobc", "CryptT No BC Intermediate", root, k("root"), ca=None)
inter_pl0 = ca("inter_pl0", "CryptT PathLen0", root, k("root"), ca=True, pathlen=0)
inter_sub = ca("inter_sub", "CryptT Sub Under PathLen0", inter_pl0, k("inter_pl0"), ca=True)
inter_missing = ca("inter_missing", "CryptT Missing Intermediate", root, k("root"), ca=True)
selfleaf = mk("selfleaf", "CryptT Self Signed Leaf", leafkey, None, None, ca=False)

def leaf(cname, cn, issuer, ikey, **kw):
    return mk(cname, cn, leafkey, issuer.subject, ikey, **kw)
DNS = x509.DNSName
srv = leaf("srv", "www.example.test", inter, k("inter"), ca=False, eku=[E.SERVER_AUTH], san=[DNS("www.example.test")])
leaf("wild", "wild.example.test", inter, k("inter"), ca=False, eku=[E.SERVER_AUTH], san=[DNS("*.wild.example.test")])
leaf("pwild", "pwild.example.test", inter, k("inter"), ca=False, eku=[E.SERVER_AUTH], san=[DNS("w*.pw.example.test")])
leaf("cnonly", "cn.example.test", inter, k("inter"), ca=False, eku=[E.SERVER_AUTH])
leaf("cnwild", "*.cnwild.example.test", inter, k("inter"), ca=False, eku=[E.SERVER_AUTH])
leaf("sanmismatch", "cn-match.example.test", inter, k("inter"), ca=False, eku=[E.SERVER_AUTH], san=[DNS("other.example.test")])
leaf("sannodns", "cn-fallback.example.test", inter, k("inter"), ca=False, eku=[E.SERVER_AUTH], san=[x509.RFC822Name("a@example.test")])
leaf("ip", "ip-host.example.test", inter, k("inter"), ca=False, eku=[E.SERVER_AUTH],
     san=[x509.IPAddress(ipaddress.ip_address("192.0.2.7")), x509.IPAddress(ipaddress.ip_address("2001:db8::1"))])
leaf("multisan", "multi.example.test", inter, k("inter"), ca=False, eku=[E.SERVER_AUTH],
     san=[DNS("a.example.test"), DNS("b.example.test"), x509.IPAddress(ipaddress.ip_address("198.51.100.9"))])
leaf("idn", "idn.example.test", inter, k("inter"), ca=False, eku=[E.SERVER_AUTH], san=[DNS("xn--bcher-kva.example.test")])
leaf("client", "CryptT Client", inter, k("inter"), ca=False, eku=[E.CLIENT_AUTH])
leaf("noeku", "CryptT No EKU", inter, k("inter"), ca=False)
leaf("code", "CryptT Code Signer", inter, k("inter"), ca=False, eku=[E.CODE_SIGNING])
leaf("email", "CryptT Email", inter, k("inter"), ca=False, eku=[E.EMAIL_PROTECTION])
leaf("expired", "CryptT Expired", inter, k("inter"), ca=False, eku=[E.SERVER_AUTH], san=[DNS("www.example.test")], nb=D(2020,1,1), na=D(2021,1,1))
leaf("notyet", "CryptT Not Yet Valid", inter, k("inter"), ca=False, eku=[E.SERVER_AUTH], san=[DNS("www.example.test")], nb=D(2040,1,1), na=D(2045,1,1))
leaf("nested", "CryptT Not Nested", intshort, k("intshort"), ca=False, eku=[E.SERVER_AUTH], san=[DNS("www.example.test")], nb=D(2021,1,1), na=D(2030,1,1))
revoked = leaf("revoked", "CryptT Revoked", inter, k("inter"), ca=False, eku=[E.SERVER_AUTH], san=[DNS("www.example.test")], serial=0x7777)
leaf("orphan", "CryptT Orphan", inter_missing, k("inter_missing"), ca=False, eku=[E.SERVER_AUTH], san=[DNS("www.example.test")])
leaf("untrusted", "CryptT Untrusted Leaf", root2, k("root2"), ca=False, eku=[E.SERVER_AUTH], san=[DNS("www.example.test")])
leaf("under_ee", "CryptT Under Non-CA", inter_ee, k("inter_ee"), ca=False, eku=[E.SERVER_AUTH], san=[DNS("www.example.test")])
leaf("under_nobc", "CryptT Under No-BC", inter_nobc, k("inter_nobc"), ca=False, eku=[E.SERVER_AUTH], san=[DNS("www.example.test")])
leaf("deep", "CryptT Too Deep", inter_sub, k("inter_sub"), ca=False, eku=[E.SERVER_AUTH], san=[DNS("www.example.test")])
leaf("direct", "CryptT Direct From Root", root, k("root"), ca=False, eku=[E.SERVER_AUTH, E.CODE_SIGNING], san=[DNS("www.example.test")])
# a CA certificate used as an end entity (basic constraints CA:TRUE)
cacert = mk("caleaf", "CryptT CA As Leaf", leafkey, root.subject, k("root"), ca=True)

crl = (x509.CertificateRevocationListBuilder().issuer_name(inter.subject)
       .last_update(D(2024,1,1)).next_update(D(2049,1,1))
       .add_revoked_certificate(x509.RevokedCertificateBuilder().serial_number(0x7777).revocation_date(D(2023,6,1)).build())
       .sign(k("inter"), hashes.SHA256()))
crl_empty = (x509.CertificateRevocationListBuilder().issuer_name(inter.subject)
       .last_update(D(2024,1,1)).next_update(D(2049,1,1)).sign(k("inter"), hashes.SHA256()))

def arr(n, b):
    s = "static const unsigned char %s[] = {" % n
    s += ",".join(("\n" if i % 16 == 0 else "") + "0x%02x" % x for i, x in enumerate(b)) + "};\n"
    return s
h = "/* generated by gen_vectors.py - do not edit */\n"
for n, b in out: h += arr("v_" + n, b)
h += arr("v_crl", der(crl)) + arr("v_crl_empty", der(crl_empty))
h += "enum {" + ",".join("C_" + n.upper() for n, _ in out) + ",C__COUNT};\n"
h += "static const struct { const char *name; const unsigned char *p; unsigned n; } g_certs[] = {\n"
h += ",\n".join('  {"%s", v_%s, sizeof v_%s}' % (n, n, n) for n, _ in out) + "};\n"
open("vectors.h", "w").write(h)
print(len(out), "certs")
