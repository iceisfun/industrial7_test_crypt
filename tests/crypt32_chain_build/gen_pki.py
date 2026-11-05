#!/usr/bin/env python3
"""Authoring-time generator for pki.c / pki.h (python cryptography).  Not part of the build.
Builds a small deterministic-by-construction PKI used by the offline chain tests."""
import datetime as dt, sys, os
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID as EK, ObjectIdentifier as OID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

def D(y, m=1, d=1): return dt.datetime(y, m, d)
KEYS = {}
def key(n, bits=2048):
    if n not in KEYS: KEYS[n] = rsa.generate_private_key(65537, bits)
    return KEYS[n]
def name(cn, ou=None):
    a = [x509.NameAttribute(NameOID.COUNTRY_NAME, 'US'), x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'cryptt')]
    if ou: a.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ou))
    a.append(x509.NameAttribute(NameOID.COMMON_NAME, cn))
    return x509.Name(a)

CERTS = {}   # id -> (cert, keyname)
def make(cid, cn, issuer=None, keyname=None, ca=None, pathlen=None, nb=D(2021), na=D(2040), serial=None,
         eku=None, ku=None, sans=None, nc_perm=None, nc_excl=None, policies=None, md=hashes.SHA256(),
         aki=True, bits=2048, extra=None, subject=None, issuer_name=None, bc_critical=True, v1=False):
    keyname = keyname or cid
    k = key(keyname, bits)
    subj = subject or name(cn)
    if issuer is None:
        ik, iname, icert = k, subj, None
    else:
        icert, ikn = CERTS[issuer]; ik = key(ikn); iname = icert.subject
    if issuer_name: iname = issuer_name
    b = (x509.CertificateBuilder().subject_name(subj).issuer_name(iname).public_key(k.public_key())
         .serial_number(serial or (0x1000 + len(CERTS))).not_valid_before(nb).not_valid_after(na))
    if ca is not None:
        b = b.add_extension(x509.BasicConstraints(ca=ca, path_length=pathlen if ca else None), critical=bc_critical)
    if ku: b = b.add_extension(ku, critical=True)
    if eku: b = b.add_extension(x509.ExtendedKeyUsage(eku), critical=False)
    if sans: b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), critical=False)
    if nc_perm or nc_excl:
        b = b.add_extension(x509.NameConstraints([x509.DNSName(s) for s in nc_perm] if nc_perm else None,
                                                 [x509.DNSName(s) for s in nc_excl] if nc_excl else None), critical=True)
    if policies:
        b = b.add_extension(x509.CertificatePolicies([x509.PolicyInformation(OID(p), None) for p in policies]), critical=False)
    b = b.add_extension(x509.SubjectKeyIdentifier.from_public_key(k.public_key()), critical=False)
    if aki and issuer is not None:
        b = b.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ik.public_key()), critical=False)
    cert = b.sign(ik, md)
    CERTS[cid] = (cert, keyname)
    return cert

CA_KU = x509.KeyUsage(False, False, False, False, False, True, True, False, False)
EE_KU = x509.KeyUsage(True, False, True, False, False, False, False, False, False)
SRV = [EK.SERVER_AUTH, EK.CLIENT_AUTH]
# --- main hierarchy
make('root', 'cryptt Chain Root', ca=True, nb=D(2020), na=D(2049, 12, 31), ku=CA_KU, serial=0x0101)
make('inter', 'cryptt Chain Intermediate', issuer='root', ca=True, pathlen=0, nb=D(2020, 6), na=D(2045), ku=CA_KU, serial=0x0201)
make('leaf', 'leaf.cryptt.test', issuer='inter', ca=False, eku=SRV, ku=EE_KU, sans=['leaf.cryptt.test'], serial=0x0301)
make('leaf_root', 'leaf directly under root', issuer='root', ca=False, eku=SRV, ku=EE_KU, serial=0x0302)
make('leaf_nobc', 'leaf without extensions', issuer='inter', serial=0x0303)
make('leaf_expired', 'expired leaf', issuer='inter', ca=False, nb=D(2021), na=D(2022), serial=0x0304)
make('leaf_future', 'future leaf', issuer='inter', ca=False, nb=D(2040), na=D(2041), serial=0x0305)
make('leaf_code', 'code signing leaf', issuer='inter', ca=False, eku=[EK.CODE_SIGNING], serial=0x0306)
make('leaf_email', 'email leaf', issuer='inter', ca=False, eku=[EK.EMAIL_PROTECTION, EK.CLIENT_AUTH], serial=0x0307)
make('leaf_anyeku', 'any eku leaf', issuer='inter', ca=False, eku=[EK.ANY_EXTENDED_KEY_USAGE], serial=0x0308)
make('leaf_ca', 'leaf that claims CA', issuer='inter', ca=True, ku=CA_KU, serial=0x0309)
# --- weak signature (signed through the openssl CLI: python cryptography refuses sha1/md5)
import subprocess, tempfile
def weak(cid, cn, md, serial):
    d = tempfile.mkdtemp()
    ic, ikn = CERTS['inter']
    open(d + '/ca.pem', 'wb').write(ic.public_bytes(serialization.Encoding.PEM))
    open(d + '/ca.key', 'wb').write(key(ikn).private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    k = key(cid); kp = d + '/k.key'
    open(kp, 'wb').write(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    open(d + '/e.ext', 'w').write('basicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth,clientAuth\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n')
    subprocess.run(['openssl','req','-new','-key',kp,'-subj','/C=US/O=cryptt/CN='+cn,'-out',d+'/c.csr'],check=True,capture_output=True)
    r = subprocess.run(['openssl','x509','-req','-in',d+'/c.csr','-CA',d+'/ca.pem','-CAkey',d+'/ca.key','-'+md,'-not_before','20210101000000Z',
        '-not_after','20400101000000Z','-set_serial',hex(serial),'-extfile',d+'/e.ext','-outform','DER','-out',d+'/o.der'],capture_output=True)
    if r.returncode: print('weak', md, 'failed', r.stderr, file=sys.stderr); return
    CERTS[cid] = (x509.load_der_x509_certificate(open(d+'/o.der','rb').read()), cid)
weak('leaf_sha1', 'sha1 signed leaf', 'sha1', 0x0310)
weak('leaf_md5', 'md5 signed leaf', 'md5', 0x0311)
make('leaf_rsa1024', 'rsa1024 leaf', issuer='inter', ca=False, bits=1024, eku=SRV, serial=0x0312)
# --- constraints
make('inter_pl0', 'pathlen0 intermediate', issuer='root', ca=True, pathlen=0, ku=CA_KU, serial=0x0401)
make('sub_ca', 'sub CA under pathlen0', issuer='inter_pl0', ca=True, ku=CA_KU, serial=0x0402)
make('leaf_pl', 'leaf under sub CA', issuer='sub_ca', ca=False, eku=SRV, serial=0x0403)
make('inter_pl1', 'pathlen1 intermediate', issuer='root', ca=True, pathlen=1, ku=CA_KU, serial=0x0404)
make('sub_ca1', 'sub CA under pathlen1', issuer='inter_pl1', ca=True, ku=CA_KU, serial=0x0405)
make('leaf_pl1', 'leaf under pathlen1', issuer='sub_ca1', ca=False, eku=SRV, serial=0x0406)
make('inter_noca', 'intermediate with CA false', issuer='root', ca=False, serial=0x0410)
make('leaf_noca', 'leaf under non CA', issuer='inter_noca', ca=False, eku=SRV, serial=0x0411)
make('inter_nobc', 'intermediate without basic constraints', issuer='root', ku=CA_KU, serial=0x0412)
make('leaf_nobc2', 'leaf under no-bc intermediate', issuer='inter_nobc', ca=False, serial=0x0413)
make('inter_noku', 'intermediate without keyCertSign', issuer='root', ca=True,
     ku=x509.KeyUsage(True, False, False, False, False, False, False, False, False), serial=0x0414)
make('leaf_noku', 'leaf under no-keyCertSign intermediate', issuer='inter_noku', ca=False, eku=SRV, serial=0x0415)
make('inter_nc', 'name constrained intermediate', issuer='root', ca=True, ku=CA_KU, nc_perm=['permitted.cryptt.test'], serial=0x0420)
make('leaf_nc_ok', 'nc ok', issuer='inter_nc', ca=False, sans=['a.permitted.cryptt.test'], eku=SRV, serial=0x0421)
make('leaf_nc_bad', 'nc bad', issuer='inter_nc', ca=False, sans=['bad.other.test'], eku=SRV, serial=0x0422)
make('leaf_nc_mixed', 'nc mixed', issuer='inter_nc', ca=False, sans=['a.permitted.cryptt.test', 'b.other.test'], eku=SRV, serial=0x0423)
make('inter_ncx', 'excluding intermediate', issuer='root', ca=True, ku=CA_KU, nc_excl=['excluded.cryptt.test'], serial=0x0424)
make('leaf_ncx_bad', 'ncx bad', issuer='inter_ncx', ca=False, sans=['x.excluded.cryptt.test'], eku=SRV, serial=0x0425)
make('leaf_ncx_ok', 'ncx ok', issuer='inter_ncx', ca=False, sans=['x.fine.cryptt.test'], eku=SRV, serial=0x0426)
# --- EKU constrained intermediate
make('inter_eku', 'eku constrained intermediate', issuer='root', ca=True, ku=CA_KU, eku=[EK.CODE_SIGNING], serial=0x0430)
make('leaf_eku_ok', 'leaf code signing under eku inter', issuer='inter_eku', ca=False, eku=[EK.CODE_SIGNING], serial=0x0431)
make('leaf_eku_bad', 'leaf server under code-only inter', issuer='inter_eku', ca=False, eku=[EK.SERVER_AUTH], serial=0x0432)
# --- issuance policy
P1 = '1.3.6.1.4.1.99999.1'; P2 = '1.3.6.1.4.1.99999.2'
make('inter_pol', 'policy intermediate', issuer='root', ca=True, ku=CA_KU, policies=[P1], serial=0x0440)
make('leaf_pol', 'policy leaf', issuer='inter_pol', ca=False, eku=SRV, policies=[P1], serial=0x0441)
# --- second root + cross-signing (inter_x has inter's subject and key, issued by root2)
make('root2', 'cryptt Chain Root Two', ca=True, nb=D(2020), na=D(2049, 12, 31), ku=CA_KU, serial=0x0102)
make('inter_x', 'cryptt Chain Intermediate', issuer='root2', keyname='inter', ca=True, pathlen=0,
     nb=D(2020, 6), na=D(2045), ku=CA_KU, serial=0x0202, subject=CERTS['inter'][0].subject)
# --- a lookalike root: same subject as root, different key (name match, key mismatch)
make('root_fake', 'cryptt Chain Root', ca=True, nb=D(2020), na=D(2049, 12, 31), ku=CA_KU, serial=0x0103)
make('leaf_fake', 'leaf signed by fake root', issuer='root_fake', ca=False, eku=SRV, serial=0x0104)
# --- intermediate whose validity ends before pTime used in tests
make('inter_short', 'short lived intermediate', issuer='root', ca=True, ku=CA_KU, nb=D(2021), na=D(2023), serial=0x0450)
make('leaf_short', 'leaf under short lived intermediate', issuer='inter_short', ca=False, eku=SRV, nb=D(2021), na=D(2040), serial=0x0451)
# --- cyclic pair: A signed by B's key, B signed by A's key; leaf_cyc under A
ka = key('cycA'); kb = key('cycB')
nA = name('cycle A'); nB = name('cycle B')
def cyc(cid, subj, pub, issn, signer):
    b = (x509.CertificateBuilder().subject_name(subj).issuer_name(issn).public_key(pub.public_key())
         .serial_number(0x0500 + len(CERTS)).not_valid_before(D(2021)).not_valid_after(D(2040))
         .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
         .add_extension(CA_KU, critical=True)
         .add_extension(x509.SubjectKeyIdentifier.from_public_key(pub.public_key()), critical=False)
         .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(signer.public_key()), critical=False))
    CERTS[cid] = (b.sign(signer, hashes.SHA256()), cid)
cyc('cycA', nA, ka, nB, kb); cyc('cycB', nB, kb, nA, ka)
make('leaf_cyc', 'leaf under cycle', issuer='cycA', ca=False, eku=SRV, serial=0x0510)
# --- revocation: leaf_rev revoked by inter's CRL; inter_rev revoked by root's CRL
make('leaf_rev', 'revoked leaf', issuer='inter', ca=False, eku=SRV, serial=0x0601)
make('leaf_good_crl', 'unrevoked leaf with cdp', issuer='inter', ca=False, eku=SRV, serial=0x0602)
make('inter_rev', 'revoked intermediate', issuer='root', ca=True, ku=CA_KU, serial=0x0603)
make('leaf_under_rev', 'leaf under revoked intermediate', issuer='inter_rev', ca=False, eku=SRV, serial=0x0604)
make('leaf_hold', 'leaf on hold', issuer='inter', ca=False, eku=SRV, serial=0x0605)

def crl(issuer_id, revoked, this=D(2025), nxt=D(2045), num=1):
    ic, ikn = CERTS[issuer_id]
    b = (x509.CertificateRevocationListBuilder().issuer_name(ic.subject).last_update(this).next_update(nxt)
         .add_extension(x509.CRLNumber(num), critical=False)
         .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key(ikn).public_key()), critical=False))
    for sn, reason in revoked:
        rb = x509.RevokedCertificateBuilder().serial_number(CERTS[sn][0].serial_number).revocation_date(D(2024, 6))
        if reason is not None:
            rb = rb.add_extension(x509.CRLReason(reason), critical=False)
        b = b.add_revoked_certificate(rb.build())
    return b.sign(key(ikn), hashes.SHA256())
CRLS = {
  'crl_inter': crl('inter', [('leaf_rev', x509.ReasonFlags.key_compromise), ('leaf_hold', x509.ReasonFlags.certificate_hold)]),
  'crl_inter_clean': crl('inter', []),
  'crl_root': crl('root', [('inter_rev', x509.ReasonFlags.cessation_of_operation)]),
  'crl_root_clean': crl('root', []),
  'crl_inter_expired': crl('inter', [], this=D(2021), nxt=D(2022)),
  'crl_inter_wrongsig': None,
}
del CRLS['crl_inter_wrongsig']

def arr(n, b):
    s = 'const BYTE %s[] = {\n' % n
    for i in range(0, len(b), 16):
        s += '  ' + ','.join('0x%02x' % x for x in b[i:i+16]) + ',\n'
    return s + '};\n'
ids = list(CERTS) ; crls = list(CRLS)
with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'pki.c'), 'w') as f:
    f.write('/* GENERATED by gen_pki.py; do not edit. */\n#include "pki.h"\n')
    for i in ids: f.write(arr('der_' + i, CERTS[i][0].public_bytes(serialization.Encoding.DER)))
    for i in crls: f.write(arr('der_' + i, CRLS[i].public_bytes(serialization.Encoding.DER)))
    f.write('const PKI_ITEM pki_items[] = {\n')
    for i in ids: f.write('  {"%s", der_%s, sizeof der_%s, 0x%x},\n' % (i, i, i, CERTS[i][0].serial_number))
    for i in crls: f.write('  {"%s", der_%s, sizeof der_%s, 0},\n' % (i, i, i))
    f.write('  {0,0,0,0}\n};\n')
with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'pki.h'), 'w') as f:
    f.write('/* GENERATED by gen_pki.py; do not edit. */\n#ifndef PKI_H\n#define PKI_H\n#include "t.h"\n')
    f.write('typedef struct { const char *id; const BYTE *der; DWORD len; unsigned serial; } PKI_ITEM;\nextern const PKI_ITEM pki_items[];\n')
    for i in ids + crls: f.write('extern const BYTE der_%s[];\n' % i)
    f.write('#endif\n')
print(len(ids), 'certs', len(crls), 'crls', file=sys.stderr)
