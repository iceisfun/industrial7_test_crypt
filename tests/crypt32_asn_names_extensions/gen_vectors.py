#!/usr/bin/env python3
"""Authoring-time generator for asn_vectors.h: builds DER by structure (not by hand-counting lengths)."""
import sys
def L(n):
    if n < 128: return bytes([n])
    b = n.to_bytes((n.bit_length()+7)//8, 'big'); return bytes([0x80|len(b)]) + b
def tlv(t, c=b''): return bytes([t]) + L(len(c)) + c
def seq(*a): return tlv(0x30, b''.join(a))
def sset(*a): return tlv(0x31, b''.join(a))
def oid(s):
    p = [int(x) for x in s.split('.')]
    out = bytes([p[0]*40+p[1]])
    for v in p[2:]:
        q = [v & 0x7f]; v >>= 7
        while v: q.append(0x80 | (v & 0x7f)); v >>= 7
        out += bytes(reversed(q))
    return tlv(6, out)
def integer(v):
    n = max(1, (v.bit_length()+8)//8); return tlv(2, v.to_bytes(n, 'big', signed=True))
def boolean(b): return tlv(1, b'\xff' if b else b'\x00')
def octets(b): return tlv(4, b)
def bits(b, unused=0): return tlv(3, bytes([unused]) + b)
def ia5(s): return tlv(0x16, s.encode())
def ctx(n, c=b'', cons=True): return tlv((0xA0 if cons else 0x80) | n, c)
def utc(s): return tlv(0x17, s.encode())
def gen(s): return tlv(0x18, s.encode())
def enum(v): return tlv(0x0a, bytes([v]))
def name(cn): return seq(sset(seq(oid('2.5.4.3'), tlv(0x13, cn.encode()))))
def name2(c, cn): return seq(sset(seq(oid('2.5.4.6'), tlv(0x13, c.encode()))), sset(seq(oid('2.5.4.3'), tlv(0x13, cn.encode()))))

V = {}
N = name('Test')
V['name_cn_test'] = N
V['name_c_cn'] = name2('US', 'Test')
V['name_empty'] = seq()
V['name_empty_indef'] = bytes([0x30,0x80,0,0])
V['name_multi_attr_rdn'] = seq(sset(seq(oid('2.5.4.6'), tlv(0x13, b'US')), seq(oid('2.5.4.3'), tlv(0x13, b'Test'))))
V['name_value_printable'] = tlv(0x13, b'Test')
V['name_value_utf8'] = tlv(0x0c, 'hé'.encode())
V['name_value_bmp'] = tlv(0x1e, 'Té€'.encode('utf-16-be'))
V['name_value_t61_latin1'] = tlv(0x14, b'T\xe9st')
V['name_value_t61_utf8'] = tlv(0x14, 'Tést'.encode())
V['name_value_univ'] = tlv(0x1c, 'Aé'.encode('utf-32-be'))
V['name_value_null'] = bytes([5,0])
V['name_cn_utf8'] = seq(sset(seq(oid('2.5.4.3'), tlv(0x0c, 'hé'.encode()))))
# alt names
dns = lambda s: tlv(0x82, s.encode())
V['alt_empty'] = seq()
V['alt_dns'] = seq(dns('a.com'))
V['alt_rfc822'] = seq(tlv(0x81, b'a@b.c'))
V['alt_url'] = seq(tlv(0x86, b'http://x'))
V['alt_ip4'] = seq(tlv(0x87, bytes([1,2,3,4])))
V['alt_ip4mask'] = seq(tlv(0x87, bytes([10,0,0,0,255,0,0,0])))
V['alt_ip6'] = seq(tlv(0x87, bytes(range(16))))
V['alt_regid'] = seq(tlv(0x88, oid('1.2.3.4')[2:]))
V['alt_dir'] = seq(ctx(4, N))
V['alt_other'] = seq(ctx(0, oid('1.2.3.4') + ctx(0, integer(1))))
V['alt_multi'] = seq(dns('a.com'), tlv(0x81, b'a@b.c'), tlv(0x87, bytes([1,2,3,4])))
V['alt_dns_puny'] = seq(dns('xn--bcher-kva.example'))
V['alt_rfc822_puny'] = seq(tlv(0x81, b'user@xn--bcher-kva.example'))
V['alt_url_puny'] = seq(tlv(0x86, b'http://xn--bcher-kva.example/p'))
V['alt_bad_choice'] = seq(tlv(0x8f, b'x'))
V['alt_x400'] = seq(ctx(3, b'\x30\x00'))
V['alt_edi'] = seq(ctx(5, b'\xa0\x00'))
# basic constraints
V['bc2_empty'] = seq()
V['bc2_ca'] = seq(boolean(True))
V['bc2_ca_pl3'] = seq(boolean(True), integer(3))
V['bc2_ca_pl0'] = seq(boolean(True), integer(0))
V['bc2_pl3'] = seq(integer(3))
V['bc2_false_explicit'] = seq(boolean(False))
V['bc2_nondder_true'] = seq(tlv(1, b'\x01'))
V['bc2_inverted'] = seq(integer(3), boolean(True))
V['bc_ca'] = seq(bits(b'\x80'))
V['bc_ca_pl2'] = seq(bits(b'\x80'), integer(2))
V['bc_ca_pl2_sub'] = seq(bits(b'\x80'), integer(2), seq(N))
V['bc_empty'] = seq(tlv(3, b'\x00'))
# key usage
V['ku_ds'] = bits(b'\x80', 7)
V['ku_two'] = bits(b'\xa0\x80', 7)
V['ku_cert_crl'] = bits(b'\x06', 1)
V['ku_empty'] = bytes([3,1,0])
V['ku_bad_unused'] = bytes([3,2,8,0x80])
# eku
V['eku_empty'] = seq()
V['eku_two'] = seq(oid('1.3.6.1.5.5.7.3.1'), oid('1.3.6.1.5.5.7.3.2'))
V['eku_any'] = seq(oid('2.5.29.37.0'))
V['eku_bad_item'] = seq(integer(1))
# aki
V['aki_empty'] = seq()
V['aki_keyid'] = seq(tlv(0x80, b'\x01\x02\x03\x04'))
V['aki2_keyid'] = seq(tlv(0x80, b'\x01\x02\x03\x04'))
V['aki2_issuer_url'] = seq(ctx(1, tlv(0x86, b'http://x')))
V['aki2_issuer_dir'] = seq(ctx(1, ctx(4, N)))
V['aki2_serial'] = seq(tlv(0x82, b'\x03\x02\x01'))  # INTEGER blobs are little-endian in memory
V['aki2_all'] = seq(tlv(0x80, b'\x01\x02\x03\x04'), ctx(1, ctx(4, N)), tlv(0x82, b'\x01'))
V['aki_serial1'] = seq(tlv(0x82, b'\x01'))
V['aki_issuer_serial'] = seq(ctx(1, ctx(4, N)), tlv(0x82, b'\x01'))
# SKI
V['ski_3'] = octets(b'\x01\x02\x03')
V['ski_empty'] = octets(b'')
# key attributes / restriction
V['ka_keyid'] = seq(octets(b'\x01\x02\x03'))
V['ka_keyid_usage'] = seq(octets(b'\x01\x02\x03'), bits(b'\x80', 7))
V['ka_empty'] = seq()
V['kur_pol'] = seq(seq(seq(oid('1.2.3'))), bits(b'\x80', 7))
V['kur_usage_only'] = seq(bits(b'\x80', 7))
V['kur_empty'] = seq()
# policies
V['pol_none'] = seq()
V['pol_one'] = seq(seq(oid('1.2.3')))
V['pol_cps'] = seq(seq(oid('1.2.3'), seq(seq(oid('1.3.6.1.5.5.7.2.1'), ia5('http://x')))))
V['pol_two_q'] = seq(seq(oid('1.2.3'), seq(seq(oid('1.3.6.1.5.5.7.2.1'), ia5('a')), seq(oid('1.3.6.1.5.5.7.2.2')))), seq(oid('2.5.29.32.0')))
V['pmap_none'] = seq()
V['pmap_one'] = seq(seq(oid('1.2.3'), oid('1.2.4')))
V['pcon_empty'] = seq()
V['pcon_req0'] = seq(tlv(0x80, b'\x00'))
V['pcon_req2_inh1'] = seq(tlv(0x80, b'\x02'), tlv(0x81, b'\x01'))
V['pcon_inh_only'] = seq(tlv(0x81, b'\x05'))
# crl dist points
fn = lambda *e: ctx(0, ctx(0, b''.join(e)))
V['cdp_empty'] = seq()
V['cdp_url'] = seq(seq(fn(tlv(0x86, b'http://x'))))
V['cdp_url_reason'] = seq(seq(fn(tlv(0x86, b'http://x')), tlv(0x81, b'\x07\x80')))
V['cdp_url_issuer'] = seq(seq(fn(tlv(0x86, b'http://x')), ctx(2, ctx(4, N)[:] ) ))
V['cdp_issuer_only'] = seq(seq(ctx(2, ctx(4, N))))
V['cdp_rdn'] = seq(seq(ctx(0, ctx(1, seq(oid('2.5.4.3'), tlv(0x13, b'Test'))))))
V['cdp_two'] = seq(seq(fn(tlv(0x86, b'http://x'))), seq(fn(tlv(0x86, b'http://y'))))
V['cdp_noname'] = seq(seq())
# aia
V['aia_ocsp'] = seq(seq(oid('1.3.6.1.5.5.7.48.1'), tlv(0x86, b'http://o')))
V['aia_two'] = seq(seq(oid('1.3.6.1.5.5.7.48.1'), tlv(0x86, b'http://o')), seq(oid('1.3.6.1.5.5.7.48.2'), dns('ca.example')))
V['aia_empty'] = seq()
# idp
V['idp_empty'] = seq()
V['idp_user'] = seq(tlv(0x81, b'\xff'))
V['idp_ca'] = seq(tlv(0x82, b'\xff'))
V['idp_indirect'] = seq(tlv(0x84, b'\xff'))
V['idp_user_indirect'] = seq(tlv(0x81, b'\xff'), tlv(0x84, b'\xff'))
V['idp_url'] = seq(fn(tlv(0x86, b'http://x')))
V['idp_reasons'] = seq(tlv(0x83, b'\x06\x80'))
# name constraints
st = lambda base, mn=None, mx=None: seq(base, *( [tlv(0x80, bytes([mn]))] if mn else []), *([tlv(0x81, bytes([mx]))] if mx is not None else []))
V['nc_empty'] = seq()
V['nc_perm'] = seq(ctx(0, st(dns('a.com'))))
V['nc_excl'] = seq(ctx(1, st(dns('a.com'))))
V['nc_both'] = seq(ctx(0, st(dns('a.com')), st(tlv(0x81, b'x@y.z'))), ctx(1, st(tlv(0x86, b'http://x'))))
V['nc_minmax'] = seq(ctx(0, st(dns('a.com'), 1, 5)))
V['nc_max0'] = seq(ctx(0, st(dns('a.com'), None, 0)))
# crl reason
for i in (0,1,5,10): V['enum_%d' % i] = enum(i)
V['enum_256'] = tlv(0x0a, b'\x01\x00')
# choice of time
V['time_2000'] = utc('000101000000Z')
V['time_1950'] = utc('500101000000Z')
V['time_2049'] = utc('491231235959Z')
V['time_2050'] = gen('20500101000000Z')
V['time_1949'] = gen('19491231235959Z')
V['time_2007_gen'] = gen('20070102030405Z')
V['time_nosec'] = utc('0001010000Z')
V['time_off_plus'] = utc('000101000000+0100')
V['time_off_minus'] = utc('000101000000-0130')
V['time_bad_month'] = utc('001301000000Z')
V['time_bad_tag'] = tlv(0x13, b'000101000000Z')
V['time_gen_frac'] = gen('20070102030405.5Z')
# template
V['tmpl_major'] = seq(oid('1.3.6.1.4.1.311.21.8.1.2'), integer(100))
V['tmpl_minor'] = seq(oid('1.3.6.1.4.1.311.21.8.1.2'), integer(100), integer(5))
V['tmpl_minor0'] = seq(oid('1.3.6.1.4.1.311.21.8.1.2'), integer(100), integer(0))
V['enroll_certtype'] = tlv(0x1e, 'User'.encode('utf-16-be'))
V['ca_version'] = integer(0x00010002)
V['ns_cert_type'] = bits(b'\x80', 7)
# extensions
V['ext_empty'] = seq()
V['ext_one'] = seq(seq(oid('2.5.29.19'), octets(seq())))
V['ext_critical'] = seq(seq(oid('2.5.29.19'), boolean(True), octets(seq(boolean(True)))))
V['ext_two'] = seq(seq(oid('2.5.29.19'), octets(seq())), seq(oid('2.5.29.15'), boolean(True), octets(bits(b'\x80',7))))
V['ext_critical_false_explicit'] = seq(seq(oid('2.5.29.19'), boolean(False), octets(seq())))
# TBS cert
sha1rsa = seq(oid('1.2.840.113549.1.1.5'), bytes([5,0]))
sha1rsa_np = seq(oid('1.2.840.113549.1.1.5'))
spki = seq(seq(oid('1.2.840.113549.1.1.1'), bytes([5,0])), bits(seq(integer(0x010001+0x100000000), integer(3)), 0))
V['spki_rsa_tiny'] = spki
V['sigalg_sha1rsa_null'] = sha1rsa
V['sigalg_sha1rsa_np'] = sha1rsa_np
tbs_base = lambda ver, ext='': seq(*( [ctx(0, integer(ver))] if ver else []), integer(1), sha1rsa_np, N, seq(utc('000101000000Z'), utc('491231235959Z')), N, spki, *([ext] if ext else []))
V['tbs_v1'] = seq(integer(1), sha1rsa_np, N, seq(utc('000101000000Z'), utc('491231235959Z')), N, spki)
V['tbs_v1_nullparams'] = seq(integer(1), sha1rsa, N, seq(utc('000101000000Z'), utc('491231235959Z')), N, spki)
V['tbs_v3'] = seq(ctx(0, integer(2)), integer(1), sha1rsa_np, N, seq(utc('000101000000Z'), utc('491231235959Z')), N, spki)
V['tbs_v3_serial2'] = seq(ctx(0, integer(2)), tlv(2, b'\x02\x01'), sha1rsa_np, N, seq(utc('000101000000Z'), utc('491231235959Z')), N, spki)
V['tbs_v3_ext'] = seq(ctx(0, integer(2)), integer(1), sha1rsa_np, N, seq(utc('000101000000Z'), utc('491231235959Z')), N, spki, ctx(3, V['ext_one']))
V['tbs_v3_uid'] = seq(ctx(0, integer(2)), integer(1), sha1rsa_np, N, seq(utc('000101000000Z'), utc('491231235959Z')), N, spki, tlv(0x81, b'\x00\x01'), tlv(0x82, b'\x00\x02'))
V['tbs_v3_gentime'] = seq(ctx(0, integer(2)), integer(1), sha1rsa_np, N, seq(utc('000101000000Z'), gen('20500101000000Z')), N, spki)
V['tbs_truncated'] = V['tbs_v1'][:-3]
V['x509_cert'] = seq(V['tbs_v1'], sha1rsa_np, bits(b'\x01\x02\x03', 0))
V['x509_cert_nullparams'] = seq(V['tbs_v1'], sha1rsa, bits(b'\x01\x02\x03', 0))
V['x509_cert_v3'] = seq(V['tbs_v3'], sha1rsa_np, bits(b'\x01\x02\x03', 0))
V['x509_cert_tiny'] = seq(integer(5), sha1rsa_np, bits(b'\x01\x02\x03', 0))
# CRL TBS
rev = seq(integer(1), utc('000101000000Z'))
V['crl_v1_nonext'] = seq(sha1rsa_np, N, utc('000101000000Z'))
V['crl_v1_next'] = seq(sha1rsa_np, N, utc('000101000000Z'), utc('491231235959Z'))
V['crl_v1_entry'] = seq(sha1rsa_np, N, utc('000101000000Z'), utc('491231235959Z'), seq(rev))
V['crl_v2_ext'] = seq(integer(1), sha1rsa_np, N, utc('000101000000Z'), utc('491231235959Z'), ctx(0, V['ext_one']))
V['crl_v2_entry_ext'] = seq(integer(1), sha1rsa_np, N, utc('000101000000Z'), utc('491231235959Z'), seq(seq(integer(1), utc('000101000000Z'), V['ext_one'])))
# CSR
V['csr_noattr'] = seq(integer(0), N, spki, ctx(0, b''))
V['csr_attr'] = seq(integer(0), N, spki, ctx(0, seq(oid('1.2.840.113549.1.9.14'), sset(V['ext_empty']))))
# cert request info with CTL? no
if __name__ == '__main__':
    out = ['/* generated by gen_vectors.py - DER built structurally at authoring time */']
    for k, v in V.items():
        out.append('static const BYTE v_%s[] = {%s};' % (k, ','.join('0x%02x' % b for b in v)))
    open(sys.argv[1] if len(sys.argv) > 1 else 'asn_vectors.h', 'w').write('\n'.join(out) + '\n')
