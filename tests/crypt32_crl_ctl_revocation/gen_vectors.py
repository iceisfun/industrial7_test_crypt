#!/usr/bin/env python3
# Authoring-time generator for vectors.h (not part of the build). Needs python3 + cryptography + openssl CLI.
import datetime, hashlib, subprocess, tempfile, os, sys
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

UTC = datetime.timezone.utc
def dt(y, m, d): return datetime.datetime(y, m, d, tzinfo=UTC)
THIS = dt(2020, 1, 1); NEXT = dt(2049, 1, 1); EXP_NEXT = dt(2020, 2, 1); REVD = dt(2020, 6, 1)
def ft(t): return (int(t.timestamp()) + 11644473600) * 10000000
out = []
def arr(name, b):
    s = ", ".join("0x%02x" % x for x in b)
    lines = []
    for i in range(0, len(b), 16):
        lines.append("    " + ", ".join("0x%02x" % x for x in b[i:i+16]))
    out.append("static const unsigned char %s[] = {\n%s\n};" % (name, ",\n".join(lines)))
def const(name, v): out.append("#define %s %s" % (name, v))
def name(cn): return x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "cryptt"), x509.NameAttribute(NameOID.COMMON_NAME, cn)])
DER = serialization.Encoding.DER

def mkkey(bits): return rsa.generate_private_key(65537, bits)
ca1k, ca2k, sk = mkkey(2048), mkkey(2048), mkkey(1024)
def mkcert(subj, key, issuer, ikey, serial, ca=False, ekus=None, cdp=None):
    b = (x509.CertificateBuilder().subject_name(name(subj)).issuer_name(name(issuer)).public_key(key.public_key())
         .serial_number(serial).not_valid_before(THIS).not_valid_after(NEXT))
    b = b.add_extension(x509.BasicConstraints(ca=ca, path_length=None), True)
    b = b.add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
    if ikey is not key:
        b = b.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ikey.public_key()), False)
    if cdp: b = b.add_extension(x509.CRLDistributionPoints([x509.DistributionPoint([x509.UniformResourceIdentifier(cdp)], None, None, None)]), False)
    return b.sign(ikey, hashes.SHA256())
ca1 = mkcert("cryptt CA1", ca1k, "cryptt CA1", ca1k, 1, True)
ca2 = mkcert("cryptt CA2", ca2k, "cryptt CA2", ca2k, 1, True)
sc = mkcert("cryptt CTL signer", sk, "cryptt CA1", ca1k, 0x77)
leafkey = mkkey(1024)
leaf = {}
def addleaf(tag, serial, ca=ca1, key=ca1k, iss="cryptt CA1", cdp=None):
    leaf[tag] = mkcert("cryptt leaf %s" % tag, leafkey, iss, key, serial, cdp=cdp)
    arr("v_cert_" + tag, leaf[tag].public_bytes(DER))
arr("v_ca1", ca1.public_bytes(DER)); arr("v_ca2", ca2.public_bytes(DER)); arr("v_signer", sc.public_bytes(DER))
addleaf("1001", 0x1001); addleaf("1002", 0x1002); addleaf("1003", 0x1003)
addleaf("c2_1001", 0x1001, key=ca2k, iss="cryptt CA2")
addleaf("cdp_match", 0x3001, cdp="file:///cryptt/none.crl"); addleaf("cdp_other", 0x3002, cdp="file:///cryptt/other.crl")
for r in range(0, 11): 
    if r != 7: addleaf("r%d" % r, 0x2000 + r)
arr("v_ca1_subject", ca1.subject.public_bytes())
arr("v_ca2_subject", ca2.subject.public_bytes())
arr("v_ca1_serial", b"\x01")
# signer private key blob (RSA 1024 PRIVATEKEYBLOB, CALG_RSA_SIGN)
pn = sk.private_numbers(); pub = pn.public_numbers
def le(x, n): return x.to_bytes(n, "little")
blob = bytes([7, 2, 0, 0]) + le(0x2400, 4) + b"RSA2" + le(1024, 4) + le(pub.e, 4) + le(pub.n, 128) + le(pn.p, 64) + le(pn.q, 64) + le(pn.dmp1, 64) + le(pn.dmq1, 64) + le(pn.iqmp, 64) + le(pn.d, 128)
arr("v_signer_keyblob", blob)

def crl(issuer_cert, key, issuer_name, entries, number, this=THIS, nxt=NEXT, delta_base=None, idp=None, aki=True):
    b = x509.CertificateRevocationListBuilder().issuer_name(name(issuer_name)).last_update(this)
    if nxt: b = b.next_update(nxt)
    else: b = b.next_update(dt(2049, 1, 1))
    for serial, reason in entries:
        eb = x509.RevokedCertificateBuilder().serial_number(serial).revocation_date(REVD)
        if reason is not None: eb = eb.add_extension(x509.CRLReason(reason), False)
        if serial == 0x1002 or reason == x509.ReasonFlags.key_compromise:
            eb = eb.add_extension(x509.InvalidityDate(dt(2020, 5, 1)), False)
        b = b.add_revoked_certificate(eb.build())
    if number is not None: b = b.add_extension(x509.CRLNumber(number), False)
    if aki: b = b.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_cert.public_key()), False)
    if delta_base is not None: b = b.add_extension(x509.DeltaCRLIndicator(delta_base), True)
    if idp is not None: b = b.add_extension(idp, True)
    return b.sign(key, hashes.SHA256())
RF = x509.ReasonFlags
c = crl(ca1, ca1k, "cryptt CA1", [(0x1001, RF.key_compromise), (0x1002, RF.certificate_hold)], 5)
arr("v_crl_basic", c.public_bytes(DER))
c = crl(ca1, ca1k, "cryptt CA1", [(0x1001, RF.key_compromise)], 4, nxt=None, this=THIS, ) 
arr("v_crl_basic_older", c.public_bytes(DER))
c = crl(ca1, ca1k, "cryptt CA1", [(0x1001, RF.key_compromise), (0x1002, RF.certificate_hold), (0x1003, RF.superseded)], 7, this=dt(2021, 1, 1))
arr("v_crl_basic_newer", c.public_bytes(DER))
c = crl(ca1, ca1k, "cryptt CA1", [(0x1001, RF.key_compromise)], 3, nxt=EXP_NEXT)
arr("v_crl_expired", c.public_bytes(DER))
c = crl(ca1, ca1k, "cryptt CA1", [], 2)
arr("v_crl_empty", c.public_bytes(DER))
c = crl(ca1, ca1k, "cryptt CA1", [(0x1002, RF.remove_from_crl)], 6, delta_base=5)
arr("v_crl_delta", c.public_bytes(DER))
idp = x509.IssuingDistributionPoint(full_name=[x509.UniformResourceIdentifier("file:///cryptt/none.crl")], relative_name=None, only_contains_user_certs=True, only_contains_ca_certs=False, only_some_reasons=None, indirect_crl=False, only_contains_attribute_certs=False)
c = crl(ca1, ca1k, "cryptt CA1", [(0x1001, None)], 8, idp=idp)
arr("v_crl_idp", c.public_bytes(DER))
c = crl(ca2, ca2k, "cryptt CA2", [(0x1001, RF.ca_compromise)], 1)
arr("v_crl_ca2", c.public_bytes(DER))
c = crl(ca1, ca1k, "cryptt CA1", [(0x2000 + r, None if r == 0 else (RF.key_compromise, RF.ca_compromise, RF.affiliation_changed, RF.superseded, RF.cessation_of_operation, RF.certificate_hold, None, RF.remove_from_crl, RF.privilege_withdrawn, RF.aa_compromise)[r-1]) for r in range(0, 11) if r != 7], 9)
arr("v_crl_reasons", c.public_bytes(DER))
c = crl(ca1, ca1k, "cryptt CA1", [(0x1001, None)], None, aki=False)
arr("v_crl_noext", c.public_bytes(DER))

# ---- hand-made DER ----
def L(n):
    if n < 0x80: return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big"); return bytes([0x80 | len(b)]) + b
def T(tag, *c):
    body = b"".join(c); return bytes([tag]) + L(len(body)) + body
def SEQ(*c): return T(0x30, *c)
def SET(*c): return T(0x31, *c)
def INT(v): 
    n = max(1, (v.bit_length() + 8) // 8); return T(2, v.to_bytes(n, "big"))
def OCT(b): return T(4, b)
def NUL(): return b"\x05\x00"
def UTC_(t): return T(0x17, t.strftime("%y%m%d%H%M%SZ").encode())
def OID(s):
    p = [int(x) for x in s.split(".")]; b = bytes([p[0] * 40 + p[1]])
    for v in p[2:]:
        e = [v & 0x7f]; v >>= 7
        while v: e.insert(0, 0x80 | (v & 0x7f)); v >>= 7
        b += bytes(e)
    return T(6, b)
ISS = ca1.subject.public_bytes()
SHA1RSA = SEQ(OID("1.2.840.113549.1.1.5"), NUL())
# unsigned v1 CRL (no version, no nextUpdate, two entries)
tbs = SEQ(SHA1RSA, ISS, UTC_(THIS), SEQ(SEQ(INT(0x1001), UTC_(REVD)), SEQ(INT(0x1002), UTC_(REVD))))
arr("v_crl_v1_nonext", tbs)
# v1 CRL with next update, no entries (revokedCertificates absent)
arr("v_crl_v1_noentries", SEQ(SHA1RSA, ISS, UTC_(THIS), UTC_(NEXT)))
# truncated copy of the basic CRL is made at run time

# ---- CTL ----
def sha1(c): return hashlib.sha1(c.public_bytes(DER)).digest()
USAGES = ["1.3.6.1.5.5.7.3.3", "1.3.6.1.5.5.7.3.1"]
def ctl_content(listid, seq, this, nxt, entries, usages=USAGES, subjalg=True):
    parts = [SEQ(*[OID(u) for u in usages])]
    if listid is not None: parts.append(OCT(listid))
    if seq is not None: parts.append(INT(seq))
    parts.append(UTC_(this))
    if nxt: parts.append(UTC_(nxt))
    parts.append(SEQ(OID("1.3.14.3.2.26"), NUL()))
    if entries is not None: parts.append(SEQ(*entries))
    return SEQ(*parts)
def ent(h, attrs=None):
    return SEQ(OCT(h), SET(*attrs)) if attrs else SEQ(OCT(h))
fname = "cryptt friendly".encode("utf-16-le") + b"\0\0"
prop11 = SEQ(OID("1.3.6.1.4.1.311.10.11.11"), SET(OCT(fname)))
desc = "cryptt desc".encode("utf-16-le") + b"\0\0"
prop13 = SEQ(OID("1.3.6.1.4.1.311.10.11.13"), SET(OCT(desc)))
e1, e2, e3 = ent(sha1(leaf["1001"]), [prop11]), ent(sha1(leaf["1002"]), [prop13]), ent(sha1(leaf["1003"]), [prop13])
ctl = ctl_content(b"cryptt-list-1", 0x0102, THIS, NEXT, [e1, e2, e3])
arr("v_ctl_content", ctl)
arr("v_ctl_content_min", ctl_content(None, None, THIS, None, [e1]))
arr("v_ctl_content_noentries", ctl_content(None, None, THIS, None, None))
arr("v_ctl_content_expired", ctl_content(b"cryptt-list-exp", 1, THIS, EXP_NEXT, [e1, e2]))
for tag, h in (("1001", leaf["1001"]), ("1002", leaf["1002"]), ("1003", leaf["1003"]), ("r0", leaf["r0"])):
    arr("v_sha1_" + tag, sha1(h))
arr("v_md5_1001", hashlib.md5(leaf["1001"].public_bytes(DER)).digest())
arr("v_ctl_prop11_value", fname); arr("v_ctl_prop13_value", desc)
# hand-assembled PKCS#7 SignedData with inner content type szOID_CTL, content as raw [0] ANY (no OCTET STRING)
from cryptography.hazmat.primitives.asymmetric import padding
def signed_msg(ctlder, ctype="1.3.6.1.4.1.311.10.1", certs=True, octet=False):
    sha256 = SEQ(OID("2.16.840.1.101.3.4.2.1"), NUL())
    inner = OCT(ctlder) if octet else ctlder
    ci = SEQ(OID(ctype), T(0xa0, inner))
    digest = hashlib.sha256(inner if octet is False else ctlder).digest()
    attrs = [SEQ(OID("1.2.840.113549.1.9.3"), SET(OID(ctype))), SEQ(OID("1.2.840.113549.1.9.4"), SET(OCT(digest)))]
    attrs_set = SET(*attrs)
    sig = sk.sign(attrs_set, padding.PKCS1v15(), hashes.SHA256())
    ias = SEQ(sc.issuer.public_bytes(), INT(sc.serial_number))
    si = SEQ(INT(1), ias, sha256, T(0xa0, *attrs), SEQ(OID("1.2.840.113549.1.1.1"), NUL()), OCT(sig))
    parts = [INT(1), SET(sha256), ci]
    if certs: parts.append(T(0xa0, sc.public_bytes(DER)))
    parts.append(SET(si))
    return SEQ(OID("1.2.840.113549.1.7.2"), T(0xa0, SEQ(*parts))), sig
def sign(content, tag, certs=True):
    d, sig = signed_msg(content, certs=certs); arr(tag, d); return d
s1 = sign(ctl, "v_ctl_signed")
sign(ctl, "v_ctl_signed_nocerts", certs=False)
sign(ctl_content(b"cryptt-list-exp", 1, THIS, EXP_NEXT, [e1, e2]), "v_ctl_signed_expired")
sign(ctl_content(None, None, THIS, None, [e1]), "v_ctl_signed_min")
# flip a bit inside the final signature value
bad = bytearray(s1); bad[-3] ^= 0x55; arr("v_ctl_signed_badsig", bytes(bad))
d, _ = signed_msg(ctl, ctype="1.2.840.113549.1.7.1", octet=True); arr("v_ctl_signed_wrongtype", d)
arr("v_ctl_signed_usage_only", signed_msg(ctl_content(None, None, THIS, None, [], usages=["1.3.6.1.5.5.7.3.3"]) , certs=True)[0])

const("V_THIS_FT", "0x%xULL" % ft(THIS)); const("V_NEXT_FT", "0x%xULL" % ft(NEXT)); const("V_EXP_NEXT_FT", "0x%xULL" % ft(EXP_NEXT))
const("V_REVD_FT", "0x%xULL" % ft(REVD)); const("V_INVD_FT", "0x%xULL" % ft(dt(2020, 5, 1))); const("V_NEWER_THIS_FT", "0x%xULL" % ft(dt(2021, 1, 1)))
sys.stdout.write("/* generated by gen_vectors.py - do not edit */\n#ifndef VECTORS_H\n#define VECTORS_H\n" + "\n".join(out) + "\n#endif\n")
