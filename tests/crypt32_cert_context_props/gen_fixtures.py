#!/usr/bin/env python3
"""Authoring-time generator for fixtures.c / fixtures.h (openssl CLI + hashlib). Not part of the build."""
import subprocess, os, tempfile, hashlib, sys
d = tempfile.mkdtemp()
def sh(*a, **k):
    return subprocess.run(a, check=True, capture_output=True, cwd=d, **k)
def key(name, kind):
    if kind == 'rsa': sh('openssl','genpkey','-algorithm','RSA','-pkeyopt','rsa_keygen_bits:2048','-out',name+'.key')
    elif kind == 'rsa1024': sh('openssl','genpkey','-algorithm','RSA','-pkeyopt','rsa_keygen_bits:1024','-out',name+'.key')
    elif kind == 'p256': sh('openssl','genpkey','-algorithm','EC','-pkeyopt','ec_paramgen_curve:P-256','-out',name+'.key')
    elif kind == 'p384': sh('openssl','genpkey','-algorithm','EC','-pkeyopt','ec_paramgen_curve:P-384','-out',name+'.key')
def ext(name, text):
    open(os.path.join(d,name+'.ext'),'w').write(text)
def cert_v1(name, subj, kind, nb, na, md, issuer, serial):
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    import datetime
    if not os.path.exists(os.path.join(d,name+'.key')): key(name, kind)
    ld = lambda n: serialization.load_pem_private_key(open(os.path.join(d,n+'.key'),'rb').read(), None)
    k = ld(name); ik = ld(issuer) if issuer else k
    mp = {'C':NameOID.COUNTRY_NAME,'O':NameOID.ORGANIZATION_NAME,'CN':NameOID.COMMON_NAME,'OU':NameOID.ORGANIZATIONAL_UNIT_NAME,'emailAddress':NameOID.EMAIL_ADDRESS}
    def nm(sx): return x509.Name([x509.NameAttribute(mp[p.split('=',1)[0]], p.split('=',1)[1]) for p in sx.strip('/').split('/')])
    isub = None
    if issuer: isub = x509.load_pem_x509_certificate(open(os.path.join(d,issuer+'.pem'),'rb').read()).subject
    p = lambda t: datetime.datetime.strptime(t,'%Y%m%d%H%M%SZ')
    b = x509.CertificateBuilder().subject_name(nm(subj)).issuer_name(isub or nm(subj)).public_key(k.public_key()).serial_number(int(serial,16)).not_valid_before(p(nb)).not_valid_after(p(na))
    h = {'sha1':hashes.SHA1(),'sha256':hashes.SHA256(),'sha384':hashes.SHA384()}[md]
    c = b.sign(ik, h)
    open(os.path.join(d,name+'.pem'),'wb').write(c.public_bytes(serialization.Encoding.PEM))
    der = c.public_bytes(serialization.Encoding.DER)
    # rewrite as a true X.509 v1 certificate: drop [0] version, re-sign
    from cryptography.hazmat.primitives.asymmetric import padding, ec
    def enc_len(n):
        if n < 128: return bytes([n])
        b = n.to_bytes((n.bit_length()+7)//8,'big'); return bytes([0x80|len(b)])+b
    def T(tag, body): return bytes([tag])+enc_len(len(body))+body
    outer = kids(der,0)
    tbs_p, tbs_l = outer[0]; sigalg = der[outer[1][0]:outer[1][0]+outer[1][1]]
    f = kids(der, tbs_p)
    assert der[f[0][0]] == 0xa0
    body = b''.join(der[p:p+l] for p,l in f[1:])
    tbs = T(0x30, body)
    if isinstance(ik, ec.EllipticCurvePrivateKey): sig = ik.sign(tbs, ec.ECDSA(h))
    else: sig = ik.sign(tbs, padding.PKCS1v15(), h)
    return T(0x30, tbs + sigalg + T(0x03, b'\x00'+sig))
def cert(name, subj, kind, nb, na, md, issuer=None, exts=None, serial=None, selfsign=False, v1=False):
    if exts is None: return cert_v1(name, subj, kind, nb, na, md, issuer, serial)
    if not os.path.exists(os.path.join(d,name+'.key')): key(name, kind)
    csr = ['openssl','req','-new','-key',name+'.key','-subj',subj,'-out',name+'.csr']
    sh(*csr)
    a = ['openssl','x509','-req','-in',name+'.csr','-not_before',nb,'-not_after',na,'-'+md,'-outform','DER','-out',name+'.der']
    if issuer is None: a += ['-signkey',name+'.key']
    else: a += ['-CA',issuer+'.pem','-CAkey',issuer+'.key']
    if serial: a += ['-set_serial',serial]
    elif issuer: a += ['-set_serial','0x'+os.urandom(0).hex() or '1']
    if exts is not None:
        ext(name, exts); a += ['-extfile',name+'.ext']
    sh(*a)
    sh('openssl','x509','-inform','DER','-in',name+'.der','-out',name+'.pem')
    return open(os.path.join(d,name+'.der'),'rb').read()


def tlv(b, o):
    tag = b[o]; l = b[o+1]; h = 2
    if l & 0x80:
        n = l & 0x7f; l = int.from_bytes(b[o+2:o+2+n],'big'); h = 2+n
    return tag, h, l
def kids(b, o):
    tag,h,l = tlv(b,o); p = o+h; end = p+l; out=[]
    while p < end:
        t,hh,ll = tlv(b,p); out.append((p, hh+ll)); p += hh+ll
    return out
def parse(der):
    c = kids(der,0); outer_sig = c[1][0]
    tbs = der[c[0][0]:c[0][0]+c[0][1]]
    f = kids(der, c[0][0])
    i = 0
    if der[f[0][0]] == 0xa0: i = 1
    ser_p, ser_l = f[i]
    t,h,l = tlv(der, ser_p); serial = der[ser_p+h:ser_p+h+l]
    iss = der[f[i+2][0]:f[i+2][0]+f[i+2][1]]
    sub = der[f[i+4][0]:f[i+4][0]+f[i+4][1]]
    spki = der[f[i+5][0]:f[i+5][0]+f[i+5][1]]
    sk = kids(der, f[i+5][0]); bp,bl = sk[1]
    t,h,l = tlv(der,bp); pub = der[bp+h+1:bp+h+l]
    def oid(p):
        t,h,l = tlv(der,p); b = der[p+h:p+h+l]; a=[b[0]//40,b[0]%40]; v=0
        for x in b[1:]:
            v=(v<<7)|(x&0x7f)
            if not x&0x80: a.append(v); v=0
        return '.'.join(map(str,a))
    sa = kids(der, outer_sig)
    sigoid = oid(sa[0][0]); cbSigPara = sa[1][1] if len(sa)>1 else 0
    ka = kids(der, kids(der, f[i+5][0])[0][0])
    keyoid = oid(ka[0][0]); cbKeyPara = ka[1][1] if len(ka)>1 else 0
    keypara = der[ka[1][0]:ka[1][0]+ka[1][1]] if len(ka)>1 else b''
    cext = 0
    for (p,l) in f[i+6:]:
        if der[p]==0xa3: cext = len(kids(der, kids(der,p)[0][0]))
    vt = kids(der, f[i+3][0]); tm=[]
    for (p,l) in vt:
        t,h,ln = tlv(der,p); sx = der[p+h:p+h+ln].decode()
        if t==0x17: sx = ('19' if int(sx[:2])>=50 else '20')+sx
        tm.append([int(sx[0:4]),int(sx[4:6]),int(sx[6:8]),int(sx[8:10]),int(sx[10:12]),int(sx[12:14])])
    return dict(sigoid=sigoid,cbSigPara=cbSigPara,keyoid=keyoid,cbKeyPara=cbKeyPara,keypara=keypara,cext=cext,nb=tm[0],na=tm[1],tbs=tbs, serial=serial, iss=iss, sub=sub, spki=spki, pub=pub, ver=(der[f[0][0]+4] if i else 0))

C = {}
rootexts = "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n"
C['root'] = cert('root','/C=US/O=cryptt/CN=Test Root CA','rsa','20200101000000Z','20491231235959Z','sha256',exts=rootexts,serial='0x0100')
C['inter'] = cert('inter','/C=US/O=cryptt/OU=Inter/CN=Test Intermediate','rsa','20200601000000Z','20450101000000Z','sha256',issuer='root',
    exts="basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n",serial='0x0201')
C['leaf'] = cert('leaf','/C=US/O=cryptt/CN=leaf.cryptt.test','rsa','20210101000000Z','20400101000000Z','sha256',issuer='root',
    exts="basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=DNS:leaf.cryptt.test,DNS:alt.cryptt.test\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n",serial='0x00FF01')
C['leafi'] = cert('leafi','/C=US/O=cryptt/CN=leaf under intermediate','rsa','20210301000000Z','20300101000000Z','sha256',issuer='inter',
    exts="keyUsage=digitalSignature\nextendedKeyUsage=codeSigning\n",serial='0x7001')
C['sha1leaf'] = cert('sha1leaf','/C=US/O=cryptt/CN=sha1 leaf','rsa','20210101000000Z','20400101000000Z','sha1',issuer='root',exts='keyUsage=digitalSignature\n',serial='0x0f')
C['ec256'] = cert('ec256','/C=US/O=cryptt/CN=ec p256 self','p256','20210101000000Z','20400101000000Z','sha256',
    exts="keyUsage=critical,digitalSignature\nextendedKeyUsage=codeSigning\n",serial='0x1234')
C['ec384v1'] = cert('ec384v1','/CN=ec384 v1','p384','20210101000000Z','20400101000000Z','sha384',serial='0x05')
C['expired'] = cert('expired','/CN=expired cert','rsa','20000101000000Z','20010101000000Z','sha256',serial='0x80')
C['future'] = cert('future','/CN=future cert','rsa','20470101000000Z','20480101000000Z','sha256',serial='0x81')
C['nestbad'] = cert('nestbad','/C=US/O=cryptt/CN=starts before issuer','rsa','20190101000000Z','20300101000000Z','sha256',issuer='root',serial='0x42')
C['nestbad2'] = cert('nestbad2','/C=US/O=cryptt/CN=ends after issuer','rsa','20210101000000Z','20500601000000Z','sha256',issuer='root',serial='0x43')
# impostor: same subject DN as root, different key; leaf2 issued by impostor (issuer DN == root subject DN)
C['root2'] = cert('root2','/C=US/O=cryptt/CN=Test Root CA','rsa','20200101000000Z','20491231235959Z','sha256',exts=rootexts,serial='0x0100')
C['leaf2'] = cert('leaf2','/C=US/O=cryptt/CN=forged leaf','rsa','20210101000000Z','20400101000000Z','sha256',issuer='root2',serial='0x44')
C['leafexp'] = cert('leafexp','/C=US/O=cryptt/CN=expired leaf','rsa','20050101000000Z','20060101000000Z','sha256',issuer='root',serial='0x50')
C['leaffut'] = cert('leaffut','/C=US/O=cryptt/CN=future leaf','rsa','20460101000000Z','20470101000000Z','sha256',issuer='root',serial='0x51')
C['rsa1024'] = cert('rsa1024','/CN=rsa1024 self','rsa1024','20210101000000Z','20400101000000Z','sha256',serial='0x45')
C['negserial'] = cert('negserial','/CN=high bit serial','rsa','20210101000000Z','20400101000000Z','sha256',serial='0x00ff80aa55')
C['utf8'] = cert('utf8','/C=DE/O=cryptt/CN=Gr\u00fc\u00dfe cryptt/emailAddress=a@cryptt.test','rsa','20210101000000Z','20400101000000Z','sha256',serial='0x46')
names = sorted(C)

H = lambda n, b: hashlib.new(n, b).digest()
def arr(b): return ','.join('0x%02x'%x for x in b)
hc = ['/* GENERATED by gen_fixtures.py (openssl CLI + hashlib); do not edit. */','#include "fixtures.h"']
hh = ['#ifndef FIXTURES_H','#define FIXTURES_H','#include "t.h"','#include <wincrypt.h>',
      'typedef struct { const char *name; const BYTE *der; DWORD cb; int version; const BYTE *serial_le; DWORD cbSerial;',
      '  BYTE sha1[20], md5[16], sha256[32], sighash[48]; DWORD cbSigHash; BYTE subjmd5[16], issmd5[16], pubmd5[16], issser_md5[16]; BYTE spkisha1[20]; BYTE ski[20]; int hasski; BYTE aki[20]; int hasaki;',
      '  const BYTE *subj; DWORD cbSubj; const BYTE *iss; DWORD cbIss; const BYTE *pub; DWORD cbPub; const BYTE *spki; DWORD cbSpki;',
      '  const char *sigoid, *keyoid; int cbSigPara, cbKeyPara; BYTE keypara[16]; int cext; int nb[6], na[6]; } FX;']
fxs=[]
for n in names:
    der = C[n]; p = parse(der)
    sigalg = {'sha1':'sha1','sha256':'sha256','sha384':'sha384'}
    md = 'sha1' if n=='sha1leaf' else 'sha384' if n=='ec384v1' else 'sha256'
    ser_le = bytes(reversed(p['serial']))
    # CERT_INFO serial is little-endian, DER leading 00 padding byte removed by decoder
    s = ser_le
    while len(s)>1 and s[-1]==0 and len(p['serial'])>1 and p['serial'][0]==0: s = s[:-1]; break
    i1 = der.find(bytes([0x06,3,0x55,0x1d,0x0e])); ski = bytes(20)
    if i1 > 0: ski = der[i1+9: i1+29] if der[i1+5:i1+9]==bytes([4,0x16,4,0x14]) else bytes(20)
    i2 = der.find(bytes([0x06,3,0x55,0x1d,0x23])); aki = bytes(20)
    if i2 > 0 and der[i2+5:i2+13]==bytes([4,0x18,0x30,0x16,0x80,0x14]) if i2>0 else False: aki = der[i2+11:i2+31]
    hc.append('static const BYTE %s_der[] = {%s};' % (n, arr(der)))
    for k in ('subj','iss','pub','spki'):
        hc.append('static const BYTE %s_%s[] = {%s};' % (n,k,arr(p[{'subj':'sub','iss':'iss','pub':'pub','spki':'spki'}[k]])))
    hc.append('static const BYTE %s_ser[] = {%s};' % (n, arr(s)))
    fxs.append('const FX fx_%s = {"%s", %s_der, %d, %d, %s_ser, %d, {%s},{%s},{%s},{%s},%d,{%s},{%s},{%s},{%s},{%s},{%s},%d,{%s},%d, %s_subj,%d, %s_iss,%d, %s_pub,%d, %s_spki,%d, "%s","%s",%d,%d,{%s},%d,{%s},{%s}};' % (
        n,n,n,len(der),p['ver']+1,n,len(s),arr(H('sha1',der)),arr(H('md5',der)),arr(H('sha256',der)),
        arr(H(md,p['tbs']).ljust(48,b'\0')), hashlib.new(md).digest_size,
        arr(H('md5',p['sub'])),arr(H('md5',p['iss'])),arr(H('md5',p['pub'])),
        arr(H('md5',p['iss']+s)), arr(H('sha1',p['spki'])), arr(ski), 1 if ski!=bytes(20) else 0, arr(aki), 1 if aki!=bytes(20) else 0, n,len(p['sub']),n,len(p['iss']),n,len(p['pub']),n,len(p['spki']), p['sigoid'],p['keyoid'],p['cbSigPara'],p['cbKeyPara'],arr(p['keypara'].ljust(16,b'\0')),p['cext'],','.join(map(str,p['nb'])),','.join(map(str,p['na']))))
    hh.append('extern const FX fx_%s;' % n)
hh.append('#endif')
hc2=['const FX *const ccp_all[] = { ' + ', '.join('&fx_'+n for n in names) + ' };','const int ccp_nall = %d;'%len(names)]
open('fixtures.c','w').write('\n'.join(hc+fxs+hc2)+'\n')
open('fixtures.h','w').write('\n'.join(hh)+'\n')
# print some info
for n in names:
    p=parse(C[n]); print(n,len(C[n]),'v',p['ver']+1,'ser',p['serial'].hex())
