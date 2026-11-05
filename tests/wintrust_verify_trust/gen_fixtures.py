#!/usr/bin/env python3
"""Authoring-time generator for fixtures.h: a hand-built PE32+, its Authenticode-signed twin
(self-signed RSA-2048/SHA-256, code-signing EKU, validity 2020..2120), and a handful of certificates.
Run:  python3 gen_fixtures.py > fixtures.h   (output is deterministic apart from key material, which is
embedded; regenerate only when the fixtures need to change)."""
import hashlib, struct, datetime, sys
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

def tlv(t, c): 
    n = len(c)
    if n < 0x80: l = bytes([n])
    elif n < 0x100: l = bytes([0x81, n])
    elif n < 0x10000: l = bytes([0x82, n >> 8, n & 255])
    else: l = bytes([0x83, n >> 16, (n >> 8) & 255, n & 255])
    return bytes([t]) + l + c
def seq(*a): return tlv(0x30, b''.join(a))
def sset(*a): return tlv(0x31, b''.join(a))
def oid(s):
    p = [int(x) for x in s.split('.')]
    b = bytes([p[0]*40 + p[1]])
    for v in p[2:]:
        e = [v & 0x7f]; v >>= 7
        while v: e.append(0x80 | (v & 0x7f)); v >>= 7
        b += bytes(reversed(e))
    return tlv(6, b)
def octets(b): return tlv(4, b)
def integer(i):
    b = i.to_bytes((i.bit_length() + 8) // 8, 'big'); return tlv(2, b)
NULL = bytes([5, 0])
SHA256 = seq(oid('2.16.840.1.101.3.4.2.1'), NULL)

def make_pe(sections_fill=b'\xc3'):
    hdr = bytearray(0x200)
    hdr[0:2] = b'MZ'; struct.pack_into('<I', hdr, 0x3c, 0x40)
    hdr[0x40:0x44] = b'PE\0\0'
    struct.pack_into('<HHIIIHH', hdr, 0x44, 0x8664, 1, 0x5A5A5A5A, 0, 0, 0xF0, 0x22)
    o = 0x58
    struct.pack_into('<HBBIIIII', hdr, o, 0x20b, 14, 0, 0x200, 0, 0, 0x1000, 0x1000)
    struct.pack_into('<Q', hdr, o + 24, 0x140000000)
    struct.pack_into('<IIHHHHHHIIIIHHQQQQII', hdr, o + 32, 0x1000, 0x200, 6, 0, 0, 0, 6, 0, 0, 0x2000, 0x200, 0, 3, 0,
                     0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    sec = bytearray(40)
    sec[0:6] = b'.text\0'
    struct.pack_into('<IIIIIIHHI', sec, 8, 0x10, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0x60000020)
    hdr[0x148:0x148 + 40] = sec
    body = bytearray(0x200); body[0:1] = sections_fill
    for i in range(1, 0x10): body[i] = 0xCC
    return bytes(hdr + body)

CHK = 0x58 + 64
DIR4 = 0x58 + 112 + 4 * 8
def pe_hash(pe):
    h = hashlib.sha256()
    h.update(pe[:CHK]); h.update(pe[CHK+4:DIR4]); h.update(pe[DIR4+8:0x200]); h.update(pe[0x200:0x400])
    return h.digest()

def spc_indirect(digest):
    link = tlv(0xA2, tlv(0x80, '<<<Obsolete>>>'.encode('utf-16-be')))
    peimg = seq(tlv(3, b'\x00'), tlv(0xA0, link))
    data = seq(oid('1.3.6.1.4.1.311.2.1.15'), peimg)
    return seq(data, seq(SHA256, octets(digest)))

def pkcs7(content_der, cert_der, key, cert):
    content_inner = content_der[2:] if content_der[1] < 0x80 else content_der[2 + (content_der[1] & 0x7f):]
    md = hashlib.sha256(content_inner).digest()
    attrs = [seq(oid('1.2.840.113549.1.9.3'), sset(oid('1.3.6.1.4.1.311.2.1.4'))),
             seq(oid('1.2.840.113549.1.9.4'), sset(octets(md)))]
    attrs.sort()
    aset = b''.join(attrs)
    sig = key.sign(sset(aset), padding.PKCS1v15(), hashes.SHA256())
    ias = seq(cert.issuer.public_bytes(), integer(cert.serial_number))
    si = seq(integer(1), ias, SHA256, tlv(0xA0, aset), seq(oid('1.2.840.113549.1.1.1'), NULL), octets(sig))
    sd = seq(integer(1), sset(SHA256), seq(oid('1.3.6.1.4.1.311.2.1.4'), tlv(0xA0, content_der)),
             tlv(0xA0, cert_der), sset(si))
    return seq(oid('1.2.840.113549.1.7.2'), tlv(0xA0, sd))

def name(cn): return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
NB = datetime.datetime(2020, 1, 1); NA = datetime.datetime(2120, 1, 1)
def mkcert(subj, key, issuer_name, issuer_key, serial, ca=False, eku=None, ski=True, aki_key=None, aki=True):
    b = (x509.CertificateBuilder().subject_name(subj).issuer_name(issuer_name).public_key(key.public_key())
         .serial_number(serial).not_valid_before(NB).not_valid_after(NA))
    if ca: b = b.add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
    if eku: b = b.add_extension(x509.ExtendedKeyUsage(eku), False)
    if ski: b = b.add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
    if aki: b = b.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key((aki_key or issuer_key).public_key()), False)
    return b.sign(issuer_key, hashes.SHA256())

def carr(nm, b):
    out = 'static const unsigned char %s[%d] = {\n' % (nm, len(b))
    for i in range(0, len(b), 16): out += '  ' + ','.join('0x%02x' % x for x in b[i:i+16]) + ',\n'
    return out + '};\n'

def main():
    k_self = rsa.generate_private_key(65537, 2048)
    code = [ExtendedKeyUsageOID.CODE_SIGNING]
    c_self = mkcert(name('cryptt WVT self-signed signer'), k_self, name('cryptt WVT self-signed signer'), k_self, 0x1001, eku=code)
    k_ca = rsa.generate_private_key(65537, 2048); k_leaf = rsa.generate_private_key(65537, 2048)
    c_ca = mkcert(name('cryptt WVT test CA'), k_ca, name('cryptt WVT test CA'), k_ca, 0x2001, ca=True)
    c_leaf = mkcert(name('cryptt WVT leaf'), k_leaf, name('cryptt WVT test CA'), k_ca, 0x2002, eku=code)
    c_tls = mkcert(name('cryptt WVT tls leaf'), k_leaf, name('cryptt WVT test CA'), k_ca, 0x2003, eku=[ExtendedKeyUsageOID.SERVER_AUTH])
    c_noext = mkcert(name('cryptt WVT noext'), k_leaf, name('cryptt WVT noext'), k_leaf, 0x3001, ski=False, aki=False)
    c_akimm = mkcert(name('cryptt WVT akimm'), k_leaf, name('cryptt WVT akimm'), k_ca, 0x3002, ski=True, aki=True)  # same names, AKI != SKI
    pe = bytearray(make_pe())
    digest = pe_hash(bytes(pe))
    cd = c_self.public_bytes(serialization.Encoding.DER)
    p7 = pkcs7(spc_indirect(digest), cd, k_self, c_self)
    pad = (-len(p7)) % 8
    wc = struct.pack('<IHH', len(p7) + 8 + pad, 0x200, 2) + p7 + b'\0' * pad
    signed = bytearray(pe) + wc
    struct.pack_into('<II', signed, DIR4, 0x400, len(wc))
    assert pe_hash(bytes(signed[:0x400])) == digest
    print('/* generated by gen_fixtures.py - do not edit */')
    print('#define FIX_PE_HASH_OFF 0x%x' % 0x200)
    print(carr('fix_pe_unsigned', bytes(pe)))
    print(carr('fix_pe_signed', bytes(signed)))
    print(carr('fix_pe_sha256', digest))
    D = lambda c: c.public_bytes(serialization.Encoding.DER)
    for n, c in (('self', c_self), ('ca', c_ca), ('leaf', c_leaf), ('tls', c_tls), ('noext', c_noext), ('akimm', c_akimm)):
        print(carr('fix_cert_' + n, D(c)))
    print(carr('fix_p7_signed', p7))
main()
