/* Self-signed certificates, signing, public key export/import, private key acquisition. Keys are
 * ephemeral CNG keys (NCryptCreatePersistedKey with a NULL name) or BCrypt key handles. */
#include "ccp.h"
#include <bcrypt.h>

typedef struct { NCRYPT_PROV_HANDLE prov; NCRYPT_KEY_HANDLE key; } EKEY;

static int ekey_new(EKEY *k, LPCWSTR alg, DWORD bits) {
    SECURITY_STATUS st;
    memset(k, 0, sizeof *k);
    if (!NCR(NCryptOpenStorageProvider) || !NCR(NCryptCreatePersistedKey)) return 0;
    st = NCR(NCryptOpenStorageProvider)(&k->prov, MS_KEY_STORAGE_PROVIDER, 0);
    if (st) return 0;
    st = NCR(NCryptCreatePersistedKey)(k->prov, &k->key, alg, NULL, 0, 0);
    if (st) { NCR(NCryptFreeObject)(k->prov); k->prov = 0; return 0; }
    if (bits) NCR(NCryptSetProperty)(k->key, NCRYPT_LENGTH_PROPERTY, (PBYTE)&bits, 4, 0);
    st = NCR(NCryptFinalizeKey)(k->key, 0);
    if (st) { NCR(NCryptFreeObject)(k->key); NCR(NCryptFreeObject)(k->prov); memset(k, 0, sizeof *k); return 0; }
    return 1;
}
static void ekey_free(EKEY *k) { if (k->key) NCR(NCryptFreeObject)(k->key); if (k->prov) NCR(NCryptFreeObject)(k->prov); memset(k, 0, sizeof *k); }
/* Test prologue: create a key or skip (emulator) / fail (real Windows). */
#define NEED_KEY(k, alg, bits) do { if (!ekey_new(&(k), alg, bits)) { if (t_is_wine()) t_skip("ephemeral CNG key unsupported"); else CHECKF(0, "ephemeral key creation failed"); return; } } while (0)

static CERT_NAME_BLOB name_blob(const char *str, BYTE **mem) {
    CERT_NAME_BLOB nb; DWORD cb = 0;
    memset(&nb, 0, sizeof nb);
    *mem = NULL;
    if (!C32(CertStrToNameA)(ENC, str, CERT_X500_NAME_STR, NULL, NULL, &cb, NULL) || !cb) return nb;
    *mem = (BYTE *)LocalAlloc(LPTR, cb);
    if (!C32(CertStrToNameA)(ENC, str, CERT_X500_NAME_STR, NULL, *mem, &cb, NULL)) { LocalFree(*mem); *mem = NULL; return nb; }
    nb.cbData = cb; nb.pbData = *mem; return nb;
}
static void st_of(SYSTEMTIME *st, int y, int m, int d, int h, int mi, int s) { memset(st, 0, sizeof *st); st->wYear = y; st->wMonth = m; st->wDay = d; st->wHour = h; st->wMinute = mi; st->wSecond = s; }
static long long ft_diff(FILETIME a, FILETIME b) { ULARGE_INTEGER x, y; x.LowPart = a.dwLowDateTime; x.HighPart = a.dwHighDateTime; y.LowPart = b.dwLowDateTime; y.HighPart = b.dwHighDateTime; return (long long)(x.QuadPart - y.QuadPart); }
/* offset/length of the TBSCertificate inside a certificate encoding */
static int tbs_span(const BYTE *d, DWORD n, DWORD *off, DWORD *len) {
    DWORD p = 1, l, h;
    if (n < 8 || d[0] != 0x30) return 0;
    if (d[p] & 0x80) p += 1 + (d[p] & 0x7f); else p += 1;
    if (d[p] != 0x30) return 0;
    h = 2; l = d[p + 1];
    if (l & 0x80) { DWORD k = l & 0x7f, i; l = 0; for (i = 0; i < k; i++) l = (l << 8) | d[p + 2 + i]; h = 2 + k; }
    *off = p; *len = h + l; return 1;
}
static PCCERT_CONTEXT selfsign(EKEY *k, const char *dn, DWORD flags, const char *sigoid, SYSTEMTIME *s, SYSTEMTIME *e, PCERT_EXTENSIONS ext) {
    BYTE *mem; CERT_NAME_BLOB nb = name_blob(dn, &mem); CRYPT_ALGORITHM_IDENTIFIER alg; PCCERT_CONTEXT c;
    if (!nb.cbData) return NULL;
    memset(&alg, 0, sizeof alg); alg.pszObjId = (LPSTR)sigoid;
    c = C32(CertCreateSelfSignCertificate)(k->key, &nb, flags, NULL, sigoid ? &alg : NULL, s, e, ext);
    LocalFree(mem);
    return c;
}
static BOOL verify_self(PCCERT_CONTEXT c) {
    return C32(CryptVerifyCertificateSignatureEx)(0, ENC, CRYPT_VERIFY_CERT_SIGN_SUBJECT_CERT, (void *)c, CRYPT_VERIFY_CERT_SIGN_ISSUER_PUBKEY, &c->pCertInfo->SubjectPublicKeyInfo, 0, NULL);
}

/* ---- CertCreateSelfSignCertificate ---- */
TEST(ccp_selfsign_rsa_defaults) {
    EKEY k; PCCERT_CONTEXT c; BYTE *mem; CERT_NAME_BLOB nb; SYSTEMTIME now; FILETIME fnow;
    REQUIRE(C32(CertCreateSelfSignCertificate)); REQUIRE(C32(CertStrToNameA));
    NEED_KEY(k, BCRYPT_RSA_ALGORITHM, 2048);
    nb = name_blob("CN=cryptt selfsign default,O=cryptt", &mem);
    CHECK(nb.cbData > 0);
    GetSystemTime(&now); SystemTimeToFileTime(&now, &fnow);
    c = C32(CertCreateSelfSignCertificate)(k.key, &nb, 0, NULL, NULL, NULL, NULL, NULL);
    CHECK(c != NULL);
    if (c) {
        CERT_INFO *ci = c->pCertInfo;
        EXPECT_EQ(ci->dwVersion, CERT_V3);
        CHECK(blob_eq(&ci->Subject, nb.pbData, nb.cbData) && blob_eq(&ci->Issuer, nb.pbData, nb.cbData));
        CHECK(ci->SignatureAlgorithm.pszObjId && !strcmp(ci->SignatureAlgorithm.pszObjId, szOID_RSA_SHA1RSA));
        CHECK(ci->SubjectPublicKeyInfo.Algorithm.pszObjId && !strcmp(ci->SubjectPublicKeyInfo.Algorithm.pszObjId, szOID_RSA_RSA));
        EXPECT_EQ(ci->SubjectPublicKeyInfo.PublicKey.cbData, 270);
        EXPECT_EQ(ci->cExtension, 0);
        CHECK(C32(CertGetPublicKeyLength)(ENC, &ci->SubjectPublicKeyInfo) == 2048);
        /* default validity: starts now, lasts 365 days */
        CHECK(ft_diff(ci->NotAfter, ci->NotBefore) >= 365LL * 86400 * 10000000 - 10000000 && ft_diff(ci->NotAfter, ci->NotBefore) <= 365LL * 86400 * 10000000);
        CHECK(llabs(ft_diff(ci->NotBefore, fnow)) < 120LL * 10000000);
        CHECK(verify_self(c));
        CHECK(C32(CryptVerifyCertificateSignatureEx)(0, ENC, CRYPT_VERIFY_CERT_SIGN_SUBJECT_CERT, (void *)c, CRYPT_VERIFY_CERT_SIGN_ISSUER_CERT, (void *)c, 0, NULL));
        ccp_free(c);
    }
    LocalFree(mem); ekey_free(&k);
}
TEST(ccp_selfsign_serial_number_shape) {
    EKEY k; PCCERT_CONTEXT a, b;
    REQUIRE(C32(CertCreateSelfSignCertificate));
    NEED_KEY(k, BCRYPT_RSA_ALGORITHM, 2048);
    a = selfsign(&k, "CN=cryptt serial a", 0, NULL, NULL, NULL, NULL);
    b = selfsign(&k, "CN=cryptt serial a", 0, NULL, NULL, NULL, NULL);
    CHECK(a && b);
    if (a && b) {
        CRYPT_INTEGER_BLOB *sa = &a->pCertInfo->SerialNumber, *sb = &b->pCertInfo->SerialNumber;
        EXPECT_EQ(sa->cbData, 16); EXPECT_EQ(sb->cbData, 16);
        CHECK(!(sa->pbData[15] & 0x80) && !(sb->pbData[15] & 0x80));           /* a positive integer */
        CHECK(sa->pbData[15] != 0 || sa->pbData[14] != 0);
        CHECK(memcmp(sa->pbData, sb->pbData, 16) != 0);                        /* new serial every time */
        CHECK(a->cbCertEncoded != 0 && memcmp(a->pbCertEncoded, b->pbCertEncoded, a->cbCertEncoded < b->cbCertEncoded ? a->cbCertEncoded : b->cbCertEncoded) != 0);
    }
    ccp_free(a); ccp_free(b); ekey_free(&k);
}
TEST(ccp_selfsign_explicit_validity) {
    EKEY k; PCCERT_CONTEXT c; SYSTEMTIME s, e; FILETIME fs, fe;
    REQUIRE(C32(CertCreateSelfSignCertificate));
    NEED_KEY(k, BCRYPT_RSA_ALGORITHM, 2048);
    st_of(&s, 2022, 3, 4, 5, 6, 7); st_of(&e, 2033, 12, 31, 23, 59, 58);
    c = selfsign(&k, "CN=cryptt validity", 0, NULL, &s, &e, NULL);
    CHECK(c != NULL);
    if (c) {
        SystemTimeToFileTime(&s, &fs); SystemTimeToFileTime(&e, &fe);
        CHECK(!memcmp(&c->pCertInfo->NotBefore, &fs, sizeof fs));
        CHECK(!memcmp(&c->pCertInfo->NotAfter, &fe, sizeof fe));
        ccp_free(c);
    }
    /* only the end time given: the start is "now" */
    c = selfsign(&k, "CN=cryptt validity2", 0, NULL, NULL, &e, NULL);
    CHECK(c != NULL);
    if (c) { SystemTimeToFileTime(&e, &fe); CHECK(!memcmp(&c->pCertInfo->NotAfter, &fe, sizeof fe)); CHECK(ft_diff(c->pCertInfo->NotAfter, c->pCertInfo->NotBefore) > 0); ccp_free(c); }
    /* only the start time given: end = start + 365 days */
    c = selfsign(&k, "CN=cryptt validity3", 0, NULL, &s, NULL, NULL);
    CHECK(c != NULL);
    if (c) { CHECK(ft_diff(c->pCertInfo->NotAfter, c->pCertInfo->NotBefore) == 365LL * 86400 * 10000000); ccp_free(c); }
    ekey_free(&k);
}
TEST(ccp_selfsign_invalid_time_fails) {
    EKEY k; PCCERT_CONTEXT c; SYSTEMTIME s, e;
    REQUIRE(C32(CertCreateSelfSignCertificate));
    NEED_KEY(k, BCRYPT_RSA_ALGORITHM, 2048);
    st_of(&s, 2022, 13, 4, 5, 6, 7); st_of(&e, 2033, 12, 31, 23, 59, 58);
    SET_ERR(0);
    c = selfsign(&k, "CN=cryptt badtime", 0, NULL, &s, &e, NULL);
    CHECK(c == NULL);
    CHECK(GetLastError() != 0);
    ccp_free(c); ekey_free(&k);
}
TEST(ccp_selfsign_explicit_signature_algorithms) {
    EKEY k; const char *algs[] = {szOID_RSA_SHA256RSA, szOID_RSA_SHA384RSA, szOID_RSA_SHA512RSA, szOID_RSA_SHA1RSA}; int i;
    REQUIRE(C32(CertCreateSelfSignCertificate));
    NEED_KEY(k, BCRYPT_RSA_ALGORITHM, 2048);
    for (i = 0; i < 4; i++) {
        PCCERT_CONTEXT c = selfsign(&k, "CN=cryptt sigalg", 0, algs[i], NULL, NULL, NULL);
        CHECKF(c != NULL, "%s", algs[i]);
        if (c) {
            CHECKF(!strcmp(c->pCertInfo->SignatureAlgorithm.pszObjId, algs[i]), "%s", algs[i]);
            CHECKF(verify_self(c), "verify %s", algs[i]);
            { BYTE h[64]; DWORD cb = sizeof h; CHECKF(C32(CryptHashToBeSigned)(0, ENC, c->pbCertEncoded, c->cbCertEncoded, h, &cb) && cb == (i == 0 ? 32 : i == 1 ? 48 : i == 2 ? 64 : 20), "tbs hash size %s", algs[i]); }
            ccp_free(c);
        }
    }
    ekey_free(&k);
}
TEST(ccp_selfsign_unknown_signature_algorithm_fails) {
    EKEY k; PCCERT_CONTEXT c;
    REQUIRE(C32(CertCreateSelfSignCertificate));
    NEED_KEY(k, BCRYPT_RSA_ALGORITHM, 2048);
    SET_ERR(0);
    c = selfsign(&k, "CN=cryptt badalg", 0, "1.2.3.4.5.6", NULL, NULL, NULL);
    CHECK(c == NULL);
    t_note("unknown signature algorithm OID: last error 0x%lx", (unsigned long)GetLastError());
    CHECK(GetLastError() != 0);
    ccp_free(c); ekey_free(&k);
}
TEST(ccp_selfsign_extensions) {
    EKEY k; PCCERT_CONTEXT c; CERT_EXTENSION ex[2]; CERT_EXTENSIONS exs; CERT_BASIC_CONSTRAINTS2_INFO bc; CRYPT_BIT_BLOB kub; BYTE kubyte = 0x86; BYTE *bcenc = NULL, *kuenc = NULL; DWORD bccb = 0, kucb = 0;
    REQUIRE(C32(CertCreateSelfSignCertificate)); REQUIRE(C32(CryptEncodeObjectEx));
    NEED_KEY(k, BCRYPT_RSA_ALGORITHM, 2048);
    memset(&bc, 0, sizeof bc); bc.fCA = TRUE; bc.fPathLenConstraint = TRUE; bc.dwPathLenConstraint = 3;
    CHECK(C32(CryptEncodeObjectEx)(ENC, X509_BASIC_CONSTRAINTS2, &bc, CRYPT_ENCODE_ALLOC_FLAG, NULL, &bcenc, &bccb));
    kub.cbData = 1; kub.pbData = &kubyte; kub.cUnusedBits = 1;
    CHECK(C32(CryptEncodeObjectEx)(ENC, X509_KEY_USAGE, &kub, CRYPT_ENCODE_ALLOC_FLAG, NULL, &kuenc, &kucb));
    memset(ex, 0, sizeof ex);
    ex[0].pszObjId = (LPSTR)szOID_BASIC_CONSTRAINTS2; ex[0].fCritical = TRUE; ex[0].Value.cbData = bccb; ex[0].Value.pbData = bcenc;
    ex[1].pszObjId = (LPSTR)szOID_KEY_USAGE; ex[1].fCritical = FALSE; ex[1].Value.cbData = kucb; ex[1].Value.pbData = kuenc;
    exs.cExtension = 2; exs.rgExtension = ex;
    c = selfsign(&k, "CN=cryptt ext", 0, szOID_RSA_SHA256RSA, NULL, NULL, &exs);
    CHECK(c != NULL);
    if (c) {
        PCERT_EXTENSION e;
        EXPECT_EQ(c->pCertInfo->cExtension, 2);
        e = C32(CertFindExtension)(szOID_BASIC_CONSTRAINTS2, c->pCertInfo->cExtension, c->pCertInfo->rgExtension);
        CHECK(e != NULL && e->fCritical && blob_eq(&e->Value, bcenc, bccb));
        e = C32(CertFindExtension)(szOID_KEY_USAGE, c->pCertInfo->cExtension, c->pCertInfo->rgExtension);
        CHECK(e != NULL && !e->fCritical && blob_eq(&e->Value, kuenc, kucb));
        { BYTE ku = 0; CHECK(C32(CertGetIntendedKeyUsage)(ENC, c->pCertInfo, &ku, 1) && ku == 0x86); }
        CHECK(verify_self(c));
        ccp_free(c);
    }
    if (bcenc) LocalFree(bcenc); if (kuenc) LocalFree(kuenc);
    ekey_free(&k);
}
TEST(ccp_selfsign_zero_extensions_struct) {
    EKEY k; PCCERT_CONTEXT c; CERT_EXTENSIONS exs;
    REQUIRE(C32(CertCreateSelfSignCertificate));
    NEED_KEY(k, BCRYPT_RSA_ALGORITHM, 2048);
    exs.cExtension = 0; exs.rgExtension = NULL;
    c = selfsign(&k, "CN=cryptt ext0", 0, NULL, NULL, NULL, &exs);
    CHECK(c != NULL);
    if (c) { EXPECT_EQ(c->pCertInfo->cExtension, 0); ccp_free(c); }
    ekey_free(&k);
}
TEST(ccp_selfsign_ecdsa_defaults_and_explicit) {
    EKEY k; PCCERT_CONTEXT c;
    REQUIRE(C32(CertCreateSelfSignCertificate));
    NEED_KEY(k, BCRYPT_ECDSA_P256_ALGORITHM, 0);
    c = selfsign(&k, "CN=cryptt ec default", 0, NULL, NULL, NULL, NULL);
    CHECK(c != NULL);
    if (c) {
        CERT_INFO *ci = c->pCertInfo;
        CHECK(!strcmp(ci->SignatureAlgorithm.pszObjId, szOID_ECDSA_SHA1));
        CHECK(!strcmp(ci->SubjectPublicKeyInfo.Algorithm.pszObjId, szOID_ECC_PUBLIC_KEY));
        EXPECT_EQ(ci->SubjectPublicKeyInfo.PublicKey.cbData, 65);
        CHECK(ci->SubjectPublicKeyInfo.PublicKey.pbData[0] == 0x04);
        { static const BYTE p256[] = {0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}; CHECK(blob_eq(&ci->SubjectPublicKeyInfo.Algorithm.Parameters, p256, sizeof p256)); }
        CHECK(C32(CertGetPublicKeyLength)(ENC, &ci->SubjectPublicKeyInfo) == 256);
        CHECK(verify_self(c));
        ccp_free(c);
    }
    c = selfsign(&k, "CN=cryptt ec sha256", 0, szOID_ECDSA_SHA256, NULL, NULL, NULL);
    CHECK(c != NULL);
    if (c) { CHECK(!strcmp(c->pCertInfo->SignatureAlgorithm.pszObjId, szOID_ECDSA_SHA256)); CHECK(verify_self(c)); ccp_free(c); }
    ekey_free(&k);
}
TEST(ccp_selfsign_ecdsa_p384_p521) {
    EKEY k; LPCWSTR algs[] = {BCRYPT_ECDSA_P384_ALGORITHM, BCRYPT_ECDSA_P521_ALGORITHM}; DWORD pub[] = {97, 133}, bits[] = {384, 521}; const char *sig[] = {szOID_ECDSA_SHA384, szOID_ECDSA_SHA512}; int i;
    REQUIRE(C32(CertCreateSelfSignCertificate));
    for (i = 0; i < 2; i++) {
        PCCERT_CONTEXT c;
        if (!ekey_new(&k, algs[i], 0)) { if (t_is_wine()) { t_skip("ephemeral CNG key unsupported"); return; } CHECK(0); return; }
        c = selfsign(&k, "CN=cryptt ec big", 0, sig[i], NULL, NULL, NULL);
        CHECKF(c != NULL, "curve %d", i);
        if (c) {
            EXPECT_EQ(c->pCertInfo->SubjectPublicKeyInfo.PublicKey.cbData, pub[i]);
            CHECK(C32(CertGetPublicKeyLength)(ENC, &c->pCertInfo->SubjectPublicKeyInfo) == bits[i]);
            CHECKF(verify_self(c), "verify curve %d", i);
            ccp_free(c);
        }
        ekey_free(&k);
    }
}
TEST(ccp_selfsign_no_sign_flag) {
    EKEY k; PCCERT_CONTEXT c;
    REQUIRE(C32(CertCreateSelfSignCertificate));
    NEED_KEY(k, BCRYPT_RSA_ALGORITHM, 2048);
    c = selfsign(&k, "CN=cryptt nosign", CERT_CREATE_SELFSIGN_NO_SIGN, szOID_RSA_SHA256RSA, NULL, NULL, NULL);
    CHECK(c != NULL);
    if (c) {
        SET_ERR(0);
        CHECK(!verify_self(c));      /* unsigned: no valid signature */
        ccp_free(c);
    }
    ekey_free(&k);
}
TEST(ccp_selfsign_key_info_property) {
    EKEY k; PCCERT_CONTEXT c; DWORD cb = 0;
    REQUIRE(C32(CertCreateSelfSignCertificate));
    NEED_KEY(k, BCRYPT_RSA_ALGORITHM, 2048);
    c = selfsign(&k, "CN=cryptt keyinfo none", CERT_CREATE_SELFSIGN_NO_KEY_INFO, NULL, NULL, NULL, NULL);
    CHECK(c != NULL);
    if (c) {
        SET_ERR(0);
        EXPECT_FAIL(!ccp_getprop(c, CERT_KEY_PROV_INFO_PROP_ID, NULL, &cb), CRYPT_E_NOT_FOUND_);
        ccp_free(c);
    }
    c = selfsign(&k, "CN=cryptt keyinfo default", 0, NULL, NULL, NULL, NULL);
    CHECK(c != NULL);
    if (c) {
        cb = 0;
        t_note("KEY_PROV_INFO property present for an ephemeral CNG key without key info: %d (err 0x%lx)", ccp_getprop(c, CERT_KEY_PROV_INFO_PROP_ID, NULL, &cb), (unsigned long)GetLastError());
        ccp_free(c);
    }
    ekey_free(&k);
}
TEST(ccp_selfsign_with_given_key_prov_info_missing_container) {
    CRYPT_KEY_PROV_INFO ki; BYTE *mem; CERT_NAME_BLOB nb; PCCERT_CONTEXT c; static WCHAR cn[] = L"cryptt_no_such_key_container_xx"; static WCHAR pn[] = MS_KEY_STORAGE_PROVIDER;
    REQUIRE(C32(CertCreateSelfSignCertificate)); REQUIRE(C32(CertStrToNameA));
    nb = name_blob("CN=cryptt missing key", &mem);
    memset(&ki, 0, sizeof ki); ki.pwszContainerName = cn; ki.pwszProvName = pn; ki.dwProvType = 0; ki.dwKeySpec = 0;   /* CNG key storage provider, named key that does not exist */
    SET_ERR(0);
    c = C32(CertCreateSelfSignCertificate)(0, &nb, 0, &ki, NULL, NULL, NULL, NULL);
    CHECK(c == NULL);
    t_note("missing named CNG key: last error 0x%lx", (unsigned long)GetLastError());
    CHECK(GetLastError() != 0);
    ccp_free(c); LocalFree(mem);
}
TEST(ccp_selfsign_context_properties_and_enum) {
    EKEY k; PCCERT_CONTEXT c; BYTE h[20]; DWORD cb = 20;
    REQUIRE(C32(CertCreateSelfSignCertificate));
    NEED_KEY(k, BCRYPT_RSA_ALGORITHM, 2048);
    c = selfsign(&k, "CN=cryptt props", 0, szOID_RSA_SHA256RSA, NULL, NULL, NULL);
    CHECK(c != NULL);
    if (c) {
        BYTE exp[20]; DWORD ecb = 20;
        CHECK(ccp_getprop(c, CERT_SHA1_HASH_PROP_ID, h, &cb) && cb == 20);
        CHECK(C32(CryptHashCertificate)(0, CALG_SHA1, 0, c->pbCertEncoded, c->cbCertEncoded, exp, &ecb) && !memcmp(exp, h, 20));
        cb = 20; CHECK(ccp_getprop(c, CERT_KEY_IDENTIFIER_PROP_ID, h, &cb) && cb == 20);       /* no SKI extension: SHA1 of the SPKI */
        { BYTE hh[20]; DWORD hcb = 20; CHECK(C32(CryptHashPublicKeyInfo)(0, 0, 0, ENC, &c->pCertInfo->SubjectPublicKeyInfo, hh, &hcb) && !memcmp(hh, h, 20)); }
        ccp_free(c);
    }
    ekey_free(&k);
}
TEST(ccp_selfsign_survives_store_roundtrip) {
    EKEY k; PCCERT_CONTEXT c, d; HCERTSTORE s;
    REQUIRE(C32(CertCreateSelfSignCertificate));
    NEED_KEY(k, BCRYPT_RSA_ALGORITHM, 2048);
    c = selfsign(&k, "CN=cryptt storert", 0, szOID_RSA_SHA256RSA, NULL, NULL, NULL);
    s = ccp_mem();
    CHECK(c && s);
    if (c && s) {
        PCCERT_CONTEXT in = NULL;
        CHECK(C32(CertAddCertificateContextToStore)(s, c, CERT_STORE_ADD_NEW, &in));
        CHECK(in != NULL);
        d = C32(CertFindCertificateInStore)(s, ENC, 0, CERT_FIND_SUBJECT_STR_W, (void *)L"cryptt storert", NULL);
        CHECK(d != NULL);
        if (d) { CHECK(d->cbCertEncoded == c->cbCertEncoded && !memcmp(d->pbCertEncoded, c->pbCertEncoded, d->cbCertEncoded)); ccp_free(d); }
        d = C32(CertGetIssuerCertificateFromStore)(s, c, NULL, &(DWORD){0});
        CHECK(d == NULL); EXPECT_ERR(CRYPT_E_SELF_SIGNED);
        ccp_free(in);
    }
    ccp_free(c); ccp_close(s); ekey_free(&k);
}
/* ---- CryptSignCertificate / CryptSignAndEncodeCertificate ---- */
TEST(ccp_sign_certificate_rsa_sha256_size_and_determinism) {
    EKEY k; DWORD off, len, cb = 0, cb2 = 0; CRYPT_ALGORITHM_IDENTIFIER alg; BYTE sig1[512], sig2[512];
    REQUIRE(C32(CryptSignCertificate));
    NEED_KEY(k, BCRYPT_RSA_ALGORITHM, 2048);
    CHECK(tbs_span(fx_leaf.der, fx_leaf.cb, &off, &len));
    memset(&alg, 0, sizeof alg); alg.pszObjId = (LPSTR)szOID_RSA_SHA256RSA;
    CHECK(C32(CryptSignCertificate)(k.key, CERT_NCRYPT_KEY_SPEC, ENC, fx_leaf.der + off, len, &alg, NULL, NULL, &cb));
    EXPECT_EQ(cb, 256);
    cb = 255; SET_ERR(0);
    CHECK(!C32(CryptSignCertificate)(k.key, CERT_NCRYPT_KEY_SPEC, ENC, fx_leaf.der + off, len, &alg, NULL, sig1, &cb));
    t_note("CNG signature into a 255 byte buffer: err 0x%lx, cb %lu", (unsigned long)GetLastError(), (unsigned long)cb);
    cb = 512; cb2 = 512;
    CHECK(C32(CryptSignCertificate)(k.key, CERT_NCRYPT_KEY_SPEC, ENC, fx_leaf.der + off, len, &alg, NULL, sig1, &cb) && cb == 256);
    CHECK(C32(CryptSignCertificate)(k.key, CERT_NCRYPT_KEY_SPEC, ENC, fx_leaf.der + off, len, &alg, NULL, sig2, &cb2) && cb2 == 256);
    CHECK(!memcmp(sig1, sig2, 256));                        /* PKCS#1 v1.5 signatures are deterministic */
    ekey_free(&k);
}
TEST(ccp_sign_certificate_signature_verifies_with_bcrypt) {
    EKEY k; DWORD off, len, cb = 512, pcb = 0; CRYPT_ALGORITHM_IDENTIFIER alg; BYTE sig[512]; BCRYPT_KEY_HANDLE bk = NULL; CERT_PUBLIC_KEY_INFO *pki; BYTE h[32]; DWORD hcb = 32; BCRYPT_PKCS1_PADDING_INFO pad; NTSTATUS st;
    REQUIRE(C32(CryptSignCertificate)); REQUIRE(C32(CryptImportPublicKeyInfoEx2)); REQUIRE(UIN("bcrypt.dll", BCryptVerifySignature));
    NEED_KEY(k, BCRYPT_RSA_ALGORITHM, 2048);
    CHECK(tbs_span(fx_leaf.der, fx_leaf.cb, &off, &len));
    memset(&alg, 0, sizeof alg); alg.pszObjId = (LPSTR)szOID_RSA_SHA256RSA;
    CHECK(C32(CryptSignCertificate)(k.key, CERT_NCRYPT_KEY_SPEC, ENC, fx_leaf.der + off, len, &alg, NULL, sig, &cb));
    CHECK(C32(CryptExportPublicKeyInfoEx)(k.key, CERT_NCRYPT_KEY_SPEC, ENC, NULL, 0, NULL, NULL, &pcb));
    pki = (CERT_PUBLIC_KEY_INFO *)LocalAlloc(LPTR, pcb);
    CHECK(C32(CryptExportPublicKeyInfoEx)(k.key, CERT_NCRYPT_KEY_SPEC, ENC, NULL, 0, NULL, pki, &pcb));
    CHECK(C32(CryptImportPublicKeyInfoEx2)(ENC, pki, 0, NULL, &bk));
    CHECK(bk != NULL);
    if (bk) {
        CHECK(C32(CryptHashToBeSigned)(0, ENC, fx_leaf.der, fx_leaf.cb, h, &hcb) && hcb == 32);
        pad.pszAlgId = BCRYPT_SHA256_ALGORITHM;
        st = UIN("bcrypt.dll", BCryptVerifySignature)(bk, &pad, h, 32, sig, cb, BCRYPT_PAD_PKCS1);
        EXPECT_EQ(st, 0);
        sig[5] ^= 1;
        st = UIN("bcrypt.dll", BCryptVerifySignature)(bk, &pad, h, 32, sig, cb, BCRYPT_PAD_PKCS1);
        CHECK(st != 0);
        UIN("bcrypt.dll", BCryptDestroyKey)(bk);
    }
    LocalFree(pki); ekey_free(&k);
}
TEST(ccp_sign_certificate_ecdsa_signature_length) {
    EKEY k; DWORD off, len, cb = 0; CRYPT_ALGORITHM_IDENTIFIER alg;
    REQUIRE(C32(CryptSignCertificate));
    NEED_KEY(k, BCRYPT_ECDSA_P256_ALGORITHM, 0);
    CHECK(tbs_span(fx_leaf.der, fx_leaf.cb, &off, &len));
    memset(&alg, 0, sizeof alg); alg.pszObjId = (LPSTR)szOID_ECDSA_SHA256;
    CHECK(C32(CryptSignCertificate)(k.key, CERT_NCRYPT_KEY_SPEC, ENC, fx_leaf.der + off, len, &alg, NULL, NULL, &cb));
    t_note("ECDSA P-256 signature size reported: %lu (DER-encoded SEQUENCE of two INTEGERs)", (unsigned long)cb);
    CHECK(cb >= 8 && cb <= 72);
    ekey_free(&k);
}
TEST(ccp_sign_certificate_bad_algorithm_and_encoding) {
    EKEY k; DWORD off, len, cb = 0; CRYPT_ALGORITHM_IDENTIFIER alg;
    REQUIRE(C32(CryptSignCertificate));
    NEED_KEY(k, BCRYPT_RSA_ALGORITHM, 2048);
    CHECK(tbs_span(fx_leaf.der, fx_leaf.cb, &off, &len));
    memset(&alg, 0, sizeof alg); alg.pszObjId = "1.2.3.4.5.6";
    SET_ERR(0);
    CHECK(!C32(CryptSignCertificate)(k.key, CERT_NCRYPT_KEY_SPEC, ENC, fx_leaf.der + off, len, &alg, NULL, NULL, &cb));
    t_note("unknown signature OID: err 0x%lx", (unsigned long)GetLastError());
    CHECK(GetLastError() != 0);
    alg.pszObjId = (LPSTR)szOID_RSA_SHA256RSA;
    SET_ERR(0);
    CHECK(!C32(CryptSignCertificate)(k.key, CERT_NCRYPT_KEY_SPEC, 0, fx_leaf.der + off, len, &alg, NULL, NULL, &cb));
    CHECK(GetLastError() != 0);
    ekey_free(&k);
}
TEST(ccp_sign_and_encode_certificate_roundtrip) {
    EKEY k; PCCERT_CONTEXT src = ccp_ctx(&fx_leaf), out; CRYPT_ALGORITHM_IDENTIFIER alg; DWORD cb = 0, cb2; BYTE *buf; CERT_INFO ci; DWORD pcb = 0; CERT_PUBLIC_KEY_INFO *pki;
    REQUIRE(C32(CryptSignAndEncodeCertificate));
    NEED_KEY(k, BCRYPT_RSA_ALGORITHM, 2048);
    if (!src) { CHECK(0); ekey_free(&k); return; }
    ci = *src->pCertInfo;
    memset(&alg, 0, sizeof alg); alg.pszObjId = (LPSTR)szOID_RSA_SHA256RSA;
    ci.SignatureAlgorithm = alg;
    CHECK(C32(CryptSignAndEncodeCertificate)(k.key, CERT_NCRYPT_KEY_SPEC, ENC, X509_CERT_TO_BE_SIGNED, &ci, &alg, NULL, NULL, &cb));
    CHECK(cb > 300);
    buf = (BYTE *)LocalAlloc(LPTR, cb + 8);
    cb2 = cb - 1; SET_ERR(0);
    EXPECT_FAIL(!C32(CryptSignAndEncodeCertificate)(k.key, CERT_NCRYPT_KEY_SPEC, ENC, X509_CERT_TO_BE_SIGNED, &ci, &alg, NULL, buf, &cb2), ERROR_MORE_DATA);
    EXPECT_EQ(cb2, cb);
    cb2 = cb;
    CHECK(C32(CryptSignAndEncodeCertificate)(k.key, CERT_NCRYPT_KEY_SPEC, ENC, X509_CERT_TO_BE_SIGNED, &ci, &alg, NULL, buf, &cb2));
    out = C32(CertCreateCertificateContext)(ENC, buf, cb2);
    CHECK(out != NULL);
    if (out) {
        CHECK(blob_eq(&out->pCertInfo->Subject, fx_leaf.subj, fx_leaf.cbSubj) && blob_eq(&out->pCertInfo->Issuer, fx_leaf.iss, fx_leaf.cbIss));
        CHECK(ccp_serial_ok(&out->pCertInfo->SerialNumber, &fx_leaf));
        CHECK(!strcmp(out->pCertInfo->SignatureAlgorithm.pszObjId, szOID_RSA_SHA256RSA));
        EXPECT_EQ(out->pCertInfo->cExtension, src->pCertInfo->cExtension);
        /* signed with the new key, not with the original issuer's key */
        CHECK(C32(CryptExportPublicKeyInfoEx)(k.key, CERT_NCRYPT_KEY_SPEC, ENC, NULL, 0, NULL, NULL, &pcb));
        pki = (CERT_PUBLIC_KEY_INFO *)LocalAlloc(LPTR, pcb);
        CHECK(C32(CryptExportPublicKeyInfoEx)(k.key, CERT_NCRYPT_KEY_SPEC, ENC, NULL, 0, NULL, pki, &pcb));
        CHECK(C32(CryptVerifyCertificateSignature)(0, ENC, buf, cb2, pki));
        { PCCERT_CONTEXT root = ccp_ctx(&fx_root); CHECK(!C32(CryptVerifyCertificateSignature)(0, ENC, buf, cb2, &root->pCertInfo->SubjectPublicKeyInfo)); ccp_free(root); }
        LocalFree(pki); ccp_free(out);
    }
    LocalFree(buf); ccp_free(src); ekey_free(&k);
}
TEST(ccp_sign_and_encode_certificate_bad_struct_type) {
    EKEY k; PCCERT_CONTEXT src = ccp_ctx(&fx_leaf); CRYPT_ALGORITHM_IDENTIFIER alg; DWORD cb = 0;
    REQUIRE(C32(CryptSignAndEncodeCertificate));
    NEED_KEY(k, BCRYPT_RSA_ALGORITHM, 2048);
    if (!src) { CHECK(0); ekey_free(&k); return; }
    memset(&alg, 0, sizeof alg); alg.pszObjId = (LPSTR)szOID_RSA_SHA256RSA;
    SET_ERR(0);
    CHECK(!C32(CryptSignAndEncodeCertificate)(k.key, CERT_NCRYPT_KEY_SPEC, ENC, (LPCSTR)(ULONG_PTR)9999, src->pCertInfo, &alg, NULL, NULL, &cb));
    CHECK(GetLastError() != 0);
    ccp_free(src); ekey_free(&k);
}

/* ---- public key export / import ---- */
TEST(ccp_export_public_key_info_ex_rsa) {
    EKEY k; DWORD cb = 0, cb2; CERT_PUBLIC_KEY_INFO *p; BYTE *buf;
    REQUIRE(C32(CryptExportPublicKeyInfoEx));
    NEED_KEY(k, BCRYPT_RSA_ALGORITHM, 2048);
    CHECK(C32(CryptExportPublicKeyInfoEx)(k.key, CERT_NCRYPT_KEY_SPEC, ENC, NULL, 0, NULL, NULL, &cb));
    CHECK(cb > sizeof *p + 270);
    buf = (BYTE *)LocalAlloc(LPTR, cb + 8); p = (CERT_PUBLIC_KEY_INFO *)buf;
    cb2 = cb - 1; SET_ERR(0);
    EXPECT_FAIL(!C32(CryptExportPublicKeyInfoEx)(k.key, CERT_NCRYPT_KEY_SPEC, ENC, NULL, 0, NULL, p, &cb2), ERROR_MORE_DATA);
    EXPECT_EQ(cb2, cb);
    cb2 = cb;
    CHECK(C32(CryptExportPublicKeyInfoEx)(k.key, CERT_NCRYPT_KEY_SPEC, ENC, NULL, 0, NULL, p, &cb2));
    CHECK(!strcmp(p->Algorithm.pszObjId, szOID_RSA_RSA));
    CHECK(p->Algorithm.Parameters.cbData == 2 && p->Algorithm.Parameters.pbData[0] == 5 && p->Algorithm.Parameters.pbData[1] == 0);
    EXPECT_EQ(p->PublicKey.cbData, 270);
    EXPECT_EQ(p->PublicKey.cUnusedBits, 0);
    { static const BYTE hdr[] = {0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00}; CHECK(!memcmp(p->PublicKey.pbData, hdr, sizeof hdr)); }
    { static const BYTE e[] = {0x02, 0x03, 0x01, 0x00, 0x01}; CHECK(!memcmp(p->PublicKey.pbData + 270 - 5, e, 5)); }       /* public exponent 65537 */
    CHECK((BYTE *)p->Algorithm.pszObjId >= buf && (BYTE *)p->PublicKey.pbData >= buf && (BYTE *)p->PublicKey.pbData < buf + cb);
    LocalFree(buf); ekey_free(&k);
}
TEST(ccp_export_public_key_info_ex_explicit_oid) {
    EKEY k; DWORD cb = 0; CERT_PUBLIC_KEY_INFO *p;
    REQUIRE(C32(CryptExportPublicKeyInfoEx));
    NEED_KEY(k, BCRYPT_RSA_ALGORITHM, 2048);
    CHECK(C32(CryptExportPublicKeyInfoEx)(k.key, CERT_NCRYPT_KEY_SPEC, ENC, (LPSTR)szOID_RSA_RSA, 0, NULL, NULL, &cb));
    p = (CERT_PUBLIC_KEY_INFO *)LocalAlloc(LPTR, cb);
    CHECK(C32(CryptExportPublicKeyInfoEx)(k.key, CERT_NCRYPT_KEY_SPEC, ENC, (LPSTR)szOID_RSA_RSA, 0, NULL, p, &cb));
    CHECK(!strcmp(p->Algorithm.pszObjId, szOID_RSA_RSA));
    LocalFree(p);
    SET_ERR(0);
    cb = 0;
    CHECK(!C32(CryptExportPublicKeyInfoEx)(k.key, CERT_NCRYPT_KEY_SPEC, ENC, "1.2.3.4.5", 0, NULL, NULL, &cb) || cb > 0);
    ekey_free(&k);
}
TEST(ccp_export_public_key_info_ex_ec) {
    EKEY k; DWORD cb = 0; CERT_PUBLIC_KEY_INFO *p;
    REQUIRE(C32(CryptExportPublicKeyInfoEx));
    NEED_KEY(k, BCRYPT_ECDSA_P256_ALGORITHM, 0);
    CHECK(C32(CryptExportPublicKeyInfoEx)(k.key, CERT_NCRYPT_KEY_SPEC, ENC, NULL, 0, NULL, NULL, &cb));
    p = (CERT_PUBLIC_KEY_INFO *)LocalAlloc(LPTR, cb);
    CHECK(C32(CryptExportPublicKeyInfoEx)(k.key, CERT_NCRYPT_KEY_SPEC, ENC, NULL, 0, NULL, p, &cb));
    CHECK(!strcmp(p->Algorithm.pszObjId, szOID_ECC_PUBLIC_KEY));
    { static const BYTE p256[] = {0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}; CHECK(blob_eq(&p->Algorithm.Parameters, p256, sizeof p256)); }
    EXPECT_EQ(p->PublicKey.cbData, 65);
    CHECK(p->PublicKey.pbData[0] == 4);
    EXPECT_EQ(p->PublicKey.cUnusedBits, 0);
    LocalFree(p); ekey_free(&k);
}
TEST(ccp_export_public_key_info_from_bcrypt_handle) {
    BCRYPT_ALG_HANDLE a = NULL; BCRYPT_KEY_HANDLE bk = NULL; DWORD cb = 0; CERT_PUBLIC_KEY_INFO *p;
    REQUIRE(C32(CryptExportPublicKeyInfoFromBCryptKeyHandle)); REQUIRE(UIN("bcrypt.dll", BCryptOpenAlgorithmProvider));
    if (UIN("bcrypt.dll", BCryptOpenAlgorithmProvider)(&a, BCRYPT_RSA_ALGORITHM, NULL, 0)) { CHECK(0); return; }
    CHECK(UIN("bcrypt.dll", BCryptGenerateKeyPair)(a, &bk, 1024, 0) == 0);
    CHECK(UIN("bcrypt.dll", BCryptFinalizeKeyPair)(bk, 0) == 0);
    CHECK(C32(CryptExportPublicKeyInfoFromBCryptKeyHandle)(bk, ENC, NULL, 0, NULL, NULL, &cb));
    p = (CERT_PUBLIC_KEY_INFO *)LocalAlloc(LPTR, cb);
    { DWORD small = cb - 1; SET_ERR(0); EXPECT_FAIL(!C32(CryptExportPublicKeyInfoFromBCryptKeyHandle)(bk, ENC, NULL, 0, NULL, p, &small), ERROR_MORE_DATA); EXPECT_EQ(small, cb); }
    CHECK(C32(CryptExportPublicKeyInfoFromBCryptKeyHandle)(bk, ENC, NULL, 0, NULL, p, &cb));
    CHECK(!strcmp(p->Algorithm.pszObjId, szOID_RSA_RSA));
    EXPECT_EQ(p->PublicKey.cbData, 140);          /* 1024-bit RSAPublicKey */
    CHECK(C32(CertGetPublicKeyLength)(ENC, p) == 1024);
    LocalFree(p);
    UIN("bcrypt.dll", BCryptDestroyKey)(bk); UIN("bcrypt.dll", BCryptCloseAlgorithmProvider)(a, 0);
}
TEST(ccp_export_public_key_info_from_bcrypt_handle_ec) {
    BCRYPT_ALG_HANDLE a = NULL; BCRYPT_KEY_HANDLE bk = NULL; DWORD cb = 0; CERT_PUBLIC_KEY_INFO *p;
    REQUIRE(C32(CryptExportPublicKeyInfoFromBCryptKeyHandle)); REQUIRE(UIN("bcrypt.dll", BCryptOpenAlgorithmProvider));
    if (UIN("bcrypt.dll", BCryptOpenAlgorithmProvider)(&a, BCRYPT_ECDSA_P384_ALGORITHM, NULL, 0)) { if (t_is_wine()) t_skip("no P-384"); else CHECK(0); return; }
    CHECK(UIN("bcrypt.dll", BCryptGenerateKeyPair)(a, &bk, 384, 0) == 0);
    CHECK(UIN("bcrypt.dll", BCryptFinalizeKeyPair)(bk, 0) == 0);
    CHECK(C32(CryptExportPublicKeyInfoFromBCryptKeyHandle)(bk, ENC, NULL, 0, NULL, NULL, &cb));
    p = (CERT_PUBLIC_KEY_INFO *)LocalAlloc(LPTR, cb);
    CHECK(C32(CryptExportPublicKeyInfoFromBCryptKeyHandle)(bk, ENC, NULL, 0, NULL, p, &cb));
    CHECK(!strcmp(p->Algorithm.pszObjId, szOID_ECC_PUBLIC_KEY));
    { static const BYTE p384[] = {0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22}; CHECK(blob_eq(&p->Algorithm.Parameters, p384, sizeof p384)); }
    EXPECT_EQ(p->PublicKey.cbData, 97);
    LocalFree(p);
    UIN("bcrypt.dll", BCryptDestroyKey)(bk); UIN("bcrypt.dll", BCryptCloseAlgorithmProvider)(a, 0);
}
TEST(ccp_import_public_key_info_ex2_rsa_properties) {
    PCCERT_CONTEXT c = ccp_ctx(&fx_root); BCRYPT_KEY_HANDLE bk = NULL; WCHAR name[32]; DWORD len = 0, got = 0;
    REQUIRE(C32(CryptImportPublicKeyInfoEx2)); REQUIRE(UIN("bcrypt.dll", BCryptGetProperty));
    if (!c) { CHECK(0); return; }
    CHECK(C32(CryptImportPublicKeyInfoEx2)(ENC, &c->pCertInfo->SubjectPublicKeyInfo, 0, NULL, &bk));
    CHECK(bk != NULL);
    if (bk) {
        CHECK(UIN("bcrypt.dll", BCryptGetProperty)(bk, BCRYPT_ALGORITHM_NAME, (PUCHAR)name, sizeof name, &got, 0) == 0 && !lstrcmpW(name, BCRYPT_RSA_ALGORITHM));
        CHECK(UIN("bcrypt.dll", BCryptGetProperty)(bk, BCRYPT_KEY_LENGTH, (PUCHAR)&len, 4, &got, 0) == 0 && len == 2048);
        UIN("bcrypt.dll", BCryptDestroyKey)(bk);
    }
    ccp_free(c);
}
TEST(ccp_import_public_key_info_ex2_verifies_fixture_signature) {
    int i; REQUIRE(C32(CryptImportPublicKeyInfoEx2)); REQUIRE(UIN("bcrypt.dll", BCryptVerifySignature));
    for (i = 0; i < 6; i++) {
        static const struct { const FX *sub, *iss; } t[] = {{&fx_leaf, &fx_root}, {&fx_inter, &fx_root}, {&fx_leafi, &fx_inter}, {&fx_nestbad, &fx_root}, {&fx_leaffut, &fx_root}, {&fx_leafexp, &fx_root}};
        PCCERT_CONTEXT is = ccp_ctx(t[i].iss); BCRYPT_KEY_HANDLE bk = NULL; BCRYPT_PKCS1_PADDING_INFO pad; NTSTATUS st; const FX *f = t[i].sub;
        if (!is) { CHECK(0); continue; }
        CHECK(C32(CryptImportPublicKeyInfoEx2)(ENC, &is->pCertInfo->SubjectPublicKeyInfo, 0, NULL, &bk));
        if (bk) {
            pad.pszAlgId = BCRYPT_SHA256_ALGORITHM;
            /* RSA-2048 signature = the trailing 256 octets of the certificate */
            st = UIN("bcrypt.dll", BCryptVerifySignature)(bk, &pad, (PUCHAR)f->sighash, 32, (PUCHAR)f->der + f->cb - 256, 256, BCRYPT_PAD_PKCS1);
            CHECKF(st == 0, "%s st=0x%lx", f->name, (unsigned long)st);
            st = UIN("bcrypt.dll", BCryptVerifySignature)(bk, &pad, (PUCHAR)f->sha256, 32, (PUCHAR)f->der + f->cb - 256, 256, BCRYPT_PAD_PKCS1);
            CHECKF(st != 0, "%s wrong digest", f->name);
            UIN("bcrypt.dll", BCryptDestroyKey)(bk);
        }
        ccp_free(is);
    }
}
TEST(ccp_import_public_key_info_ex2_ec) {
    PCCERT_CONTEXT c = ccp_ctx(&fx_ec256); BCRYPT_KEY_HANDLE bk = NULL; BCRYPT_PKCS1_PADDING_INFO pad; WCHAR name[32]; DWORD got = 0;
    REQUIRE(C32(CryptImportPublicKeyInfoEx2));
    if (!c) { CHECK(0); return; }
    if (!C32(CryptImportPublicKeyInfoEx2)(ENC, &c->pCertInfo->SubjectPublicKeyInfo, 0, NULL, &bk)) { if (t_is_wine()) t_skip("ECC import unsupported"); else CHECK(0); ccp_free(c); return; }
    CHECK(bk != NULL);
    if (bk) {
        if (UIN("bcrypt.dll", BCryptGetProperty)(bk, BCRYPT_ALGORITHM_NAME, (PUCHAR)name, sizeof name, &got, 0) == 0) t_note("imported EC key algorithm name: %ls", name);
        UIN("bcrypt.dll", BCryptDestroyKey)(bk);
    }
    (void)pad;
    ccp_free(c);
}
TEST(ccp_import_public_key_info_ex2_bad_params) {
    PCCERT_CONTEXT c = ccp_ctx(&fx_root); BCRYPT_KEY_HANDLE bk = NULL; CERT_PUBLIC_KEY_INFO bad;
    REQUIRE(C32(CryptImportPublicKeyInfoEx2));
    if (!c) { CHECK(0); return; }
    bad = c->pCertInfo->SubjectPublicKeyInfo; bad.Algorithm.pszObjId = "1.2.3.4.5.6.7";
    SET_ERR(0);
    CHECK(!C32(CryptImportPublicKeyInfoEx2)(ENC, &bad, 0, NULL, &bk));
    CHECK(bk == NULL); CHECK(GetLastError() != 0);
    t_note("unknown public key algorithm: err 0x%lx", (unsigned long)GetLastError());
    bad = c->pCertInfo->SubjectPublicKeyInfo; bad.PublicKey.cbData = 10;
    SET_ERR(0);
    CHECK(!C32(CryptImportPublicKeyInfoEx2)(ENC, &bad, 0, NULL, &bk));
    CHECK(GetLastError() != 0);
    SET_ERR(0);
    CHECK(!C32(CryptImportPublicKeyInfoEx2)(0, &c->pCertInfo->SubjectPublicKeyInfo, 0, NULL, &bk));
    CHECK(GetLastError() != 0);
    ccp_free(c);
}
TEST(ccp_import_public_key_info_capi_verifycontext) {
    PCCERT_CONTEXT c = ccp_ctx(&fx_root); HCRYPTPROV prov = 0; HCRYPTKEY key = 0; DWORD len = 0, cb = 4;
    REQUIRE(C32(CryptImportPublicKeyInfo)); REQUIRE(ADV(CryptAcquireContextW)); REQUIRE(ADV(CryptGetKeyParam));
    if (!c) { CHECK(0); return; }
    if (!ADV(CryptAcquireContextW)(&prov, NULL, MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) { CHECK(0); ccp_free(c); return; }
    CHECK(C32(CryptImportPublicKeyInfo)(prov, ENC, &c->pCertInfo->SubjectPublicKeyInfo, &key));
    CHECK(key != 0);
    if (key) {
        CHECK(ADV(CryptGetKeyParam)(key, KP_KEYLEN, (BYTE *)&len, &cb, 0) && len == 2048);
        ADV(CryptDestroyKey)(key);
    }
    /* algorithm override must agree with the key */
    key = 0;
    CHECK(C32(CryptImportPublicKeyInfoEx)(prov, ENC, &c->pCertInfo->SubjectPublicKeyInfo, 0, 0, NULL, &key));
    if (key) ADV(CryptDestroyKey)(key);
    ADV(CryptReleaseContext)(prov, 0);
    ccp_free(c);
}
TEST(ccp_import_public_key_info_capi_bad_encoding) {
    PCCERT_CONTEXT c = ccp_ctx(&fx_root); HCRYPTPROV prov = 0; HCRYPTKEY key = 0; CERT_PUBLIC_KEY_INFO bad;
    REQUIRE(C32(CryptImportPublicKeyInfo)); REQUIRE(ADV(CryptAcquireContextW));
    if (!c) { CHECK(0); return; }
    if (!ADV(CryptAcquireContextW)(&prov, NULL, MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) { CHECK(0); ccp_free(c); return; }
    bad = c->pCertInfo->SubjectPublicKeyInfo; bad.PublicKey.cbData = 20;
    SET_ERR(0);
    CHECK(!C32(CryptImportPublicKeyInfo)(prov, ENC, &bad, &key));
    CHECK(key == 0); CHECK(GetLastError() != 0);
    SET_ERR(0);
    CHECK(!C32(CryptImportPublicKeyInfo)(prov, 0, &c->pCertInfo->SubjectPublicKeyInfo, &key));
    CHECK(GetLastError() != 0);
    ADV(CryptReleaseContext)(prov, 0);
    ccp_free(c);
}
TEST(ccp_create_key_identifier_from_csp) {
    PCCERT_CONTEXT c = ccp_ctx(&fx_root); HCRYPTPROV prov = 0; HCRYPTKEY key = 0; DWORD cb = 0; BYTE *blob; BYTE id[32]; DWORD idcb = sizeof id;
    REQUIRE(C32(CryptCreateKeyIdentifierFromCSP)); REQUIRE(ADV(CryptExportKey)); REQUIRE(ADV(CryptAcquireContextW));
    if (!c) { CHECK(0); return; }
    if (!ADV(CryptAcquireContextW)(&prov, NULL, MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) { CHECK(0); ccp_free(c); return; }
    CHECK(C32(CryptImportPublicKeyInfo)(prov, ENC, &c->pCertInfo->SubjectPublicKeyInfo, &key));
    CHECK(ADV(CryptExportKey)(key, 0, PUBLICKEYBLOB, 0, NULL, &cb));
    blob = (BYTE *)LocalAlloc(LPTR, cb);
    CHECK(ADV(CryptExportKey)(key, 0, PUBLICKEYBLOB, 0, blob, &cb));
    CHECK(C32(CryptCreateKeyIdentifierFromCSP)(ENC, NULL, (PUBLICKEYSTRUC *)blob, cb, 0, NULL, id, &idcb));
    EXPECT_EQ(idcb, 20);
    CHECK(!memcmp(id, fx_root.spkisha1, 20));
    t_note("key identifier from CSP blob %s the SHA1 of the encoded SubjectPublicKeyInfo", !memcmp(id, fx_root.spkisha1, 20) ? "equals" : "differs from");
    idcb = 0;
    CHECK(C32(CryptCreateKeyIdentifierFromCSP)(ENC, NULL, (PUBLICKEYSTRUC *)blob, cb, 0, NULL, NULL, &idcb) && idcb == 20);
    idcb = 19; SET_ERR(0);
    EXPECT_FAIL(!C32(CryptCreateKeyIdentifierFromCSP)(ENC, NULL, (PUBLICKEYSTRUC *)blob, cb, 0, NULL, id, &idcb), ERROR_MORE_DATA);
    LocalFree(blob); if (key) ADV(CryptDestroyKey)(key);
    ADV(CryptReleaseContext)(prov, 0); ccp_free(c);
}

/* ---- CryptAcquireCertificatePrivateKey ---- */
TEST(ccp_acquire_key_invalid_flag_combination) {
    PCCERT_CONTEXT c = ccp_ctx(&fx_root); HCRYPTPROV_OR_NCRYPT_KEY_HANDLE h = 1; DWORD spec = 5; BOOL free_ = 7;
    REQUIRE(C32(CryptAcquireCertificatePrivateKey));
    if (!c) { CHECK(0); return; }
    SET_ERR(0);
    CHECK(!C32(CryptAcquireCertificatePrivateKey)(c, CRYPT_ACQUIRE_SILENT_FLAG | CRYPT_ACQUIRE_WINDOW_HANDLE_FLAG, NULL, &h, &spec, &free_));
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
    ccp_free(c);
}
TEST(ccp_acquire_key_without_key_properties) {
    PCCERT_CONTEXT c = ccp_ctx(&fx_leaf); HCRYPTPROV_OR_NCRYPT_KEY_HANDLE h = 1; DWORD spec = 5; BOOL free_ = 7; DWORD fl[] = {0, CRYPT_ACQUIRE_CACHE_FLAG, CRYPT_ACQUIRE_USE_PROV_INFO_FLAG, CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG, CRYPT_ACQUIRE_SILENT_FLAG}; int k;
    REQUIRE(C32(CryptAcquireCertificatePrivateKey));
    if (!c) { CHECK(0); return; }
    for (k = 0; k < 5; k++) {
        SET_ERR(0);
        CHECKF(!C32(CryptAcquireCertificatePrivateKey)(c, fl[k], NULL, &h, &spec, &free_), "flags 0x%lx", (unsigned long)fl[k]);
        EXPECT_ERR(CRYPT_E_NO_KEY_PROPERTY_);
    }
    ccp_free(c);
}
TEST(ccp_acquire_key_cached_ncrypt_key_context) {
    EKEY k; PCCERT_CONTEXT c = ccp_ctx(&fx_root); HCRYPTPROV_OR_NCRYPT_KEY_HANDLE h = 0; DWORD spec = 0; BOOL free_ = 7;
    REQUIRE(C32(CryptAcquireCertificatePrivateKey));
    NEED_KEY(k, BCRYPT_RSA_ALGORITHM, 2048);
    if (!c) { CHECK(0); ekey_free(&k); return; }
    CHECK(C32(CertSetCertificateContextProperty)(c, CERT_NCRYPT_KEY_HANDLE_PROP_ID, CERT_STORE_NO_CRYPT_RELEASE_FLAG, (void *)k.key));
    CHECK(C32(CryptAcquireCertificatePrivateKey)(c, CRYPT_ACQUIRE_CACHE_FLAG | CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG, NULL, &h, &spec, &free_));
    CHECK(h == k.key);
    EXPECT_EQ(spec, CERT_NCRYPT_KEY_SPEC);
    EXPECT_EQ(free_, 0);                         /* cached handle: the caller must not free it */
    free_ = 7; h = 0;
    CHECK(C32(CryptAcquireCertificatePrivateKey)(c, CRYPT_ACQUIRE_CACHE_FLAG | CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG, NULL, &h, NULL, NULL));
    CHECK(h == k.key);
    ccp_free(c);                                  /* NO_CRYPT_RELEASE: the key is still ours */
    ekey_free(&k);
}
TEST(ccp_acquire_key_pfcallerfree_and_spec_optional) {
    EKEY k; PCCERT_CONTEXT c = ccp_ctx(&fx_root); HCRYPTPROV_OR_NCRYPT_KEY_HANDLE h = 0;
    REQUIRE(C32(CryptAcquireCertificatePrivateKey));
    NEED_KEY(k, BCRYPT_RSA_ALGORITHM, 2048);
    if (!c) { CHECK(0); ekey_free(&k); return; }
    CHECK(C32(CertSetCertificateContextProperty)(c, CERT_NCRYPT_KEY_HANDLE_PROP_ID, CERT_STORE_NO_CRYPT_RELEASE_FLAG, (void *)k.key));
    CHECK(C32(CryptAcquireCertificatePrivateKey)(c, CRYPT_ACQUIRE_CACHE_FLAG | CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG, NULL, &h, NULL, NULL));
    CHECK(h == k.key);
    ccp_free(c); ekey_free(&k);
}
TEST(ccp_ncrypt_key_handle_property_roundtrip) {
    EKEY k; PCCERT_CONTEXT c = ccp_ctx(&fx_root); ULONG_PTR h = 0; DWORD cb = sizeof h, spec = 0, scb = 4; CERT_KEY_CONTEXT kc; DWORD kcb = sizeof kc;
    REQUIRE(C32(CertSetCertificateContextProperty));
    NEED_KEY(k, BCRYPT_RSA_ALGORITHM, 2048);
    if (!c) { CHECK(0); ekey_free(&k); return; }
    CHECK(C32(CertSetCertificateContextProperty)(c, CERT_NCRYPT_KEY_HANDLE_PROP_ID, CERT_STORE_NO_CRYPT_RELEASE_FLAG, (void *)k.key));
    CHECK(ccp_getprop(c, CERT_NCRYPT_KEY_HANDLE_PROP_ID, &h, &cb) && cb == sizeof h && h == (ULONG_PTR)k.key);
    cb = 8; SET_ERR(0);
    CHECK(!ccp_getprop(c, CERT_KEY_PROV_HANDLE_PROP_ID, &h, &cb));                  /* a CNG key is not a CSP handle */
    EXPECT_ERR(CRYPT_E_NOT_FOUND_);
    CHECK(ccp_getprop(c, CERT_KEY_SPEC_PROP_ID, &spec, &scb) && spec == CERT_NCRYPT_KEY_SPEC);
    CHECK(ccp_getprop(c, CERT_KEY_CONTEXT_PROP_ID, &kc, &kcb) && kcb == sizeof kc && kc.cbSize == sizeof kc && kc.dwKeySpec == CERT_NCRYPT_KEY_SPEC && kc.hNCryptKey == k.key);
    ccp_free(c); ekey_free(&k);
}
TEST(ccp_key_prov_handle_property_roundtrip) {
    PCCERT_CONTEXT c = ccp_ctx(&fx_root); HCRYPTPROV prov = 0; ULONG_PTR h = 0; DWORD cb = sizeof h, spec = 0, scb = 4; HCRYPTPROV_OR_NCRYPT_KEY_HANDLE a = 0; DWORD aspec = 0; BOOL free_ = 7; DWORD sp = AT_KEYEXCHANGE;
    REQUIRE(C32(CertSetCertificateContextProperty)); REQUIRE(ADV(CryptAcquireContextW));
    if (!c) { CHECK(0); return; }
    if (!ADV(CryptAcquireContextW)(&prov, NULL, MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) { CHECK(0); ccp_free(c); return; }
    CHECK(C32(CertSetCertificateContextProperty)(c, CERT_KEY_SPEC_PROP_ID, 0, &sp));
    CHECK(C32(CertSetCertificateContextProperty)(c, CERT_KEY_PROV_HANDLE_PROP_ID, CERT_STORE_NO_CRYPT_RELEASE_FLAG, (void *)prov));
    CHECK(ccp_getprop(c, CERT_KEY_PROV_HANDLE_PROP_ID, &h, &cb) && cb == sizeof h && h == (ULONG_PTR)prov);
    cb = 8; SET_ERR(0);
    CHECK(!ccp_getprop(c, CERT_NCRYPT_KEY_HANDLE_PROP_ID, &h, &cb));
    EXPECT_ERR(CRYPT_E_NOT_FOUND_);
    CHECK(ccp_getprop(c, CERT_KEY_SPEC_PROP_ID, &spec, &scb) && spec == AT_KEYEXCHANGE);
    CHECK(C32(CryptAcquireCertificatePrivateKey)(c, CRYPT_ACQUIRE_CACHE_FLAG, NULL, &a, &aspec, &free_));
    CHECK(a == prov);
    EXPECT_EQ(aspec, AT_KEYEXCHANGE);
    EXPECT_EQ(free_, 0);
    CHECK(C32(CertSetCertificateContextProperty)(c, CERT_KEY_PROV_HANDLE_PROP_ID, 0, NULL));        /* delete: handle is not released (flag) */
    { DWORD z = 8; SET_ERR(0); CHECK(!ccp_getprop(c, CERT_KEY_PROV_HANDLE_PROP_ID, &h, &z)); }
    ADV(CryptReleaseContext)(prov, 0);
    ccp_free(c);
}
TEST(ccp_key_context_property_handle_not_released_with_flag) {
    PCCERT_CONTEXT c = ccp_ctx(&fx_root); HCRYPTPROV prov = 0; CERT_KEY_CONTEXT kc; BYTE b[16]; DWORD n = 16;
    REQUIRE(C32(CertSetCertificateContextProperty)); REQUIRE(ADV(CryptAcquireContextW));
    if (!c) { CHECK(0); return; }
    if (!ADV(CryptAcquireContextW)(&prov, NULL, MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) { CHECK(0); ccp_free(c); return; }
    memset(&kc, 0, sizeof kc); kc.cbSize = sizeof kc; kc.hCryptProv = prov; kc.dwKeySpec = AT_SIGNATURE;
    CHECK(C32(CertSetCertificateContextProperty)(c, CERT_KEY_CONTEXT_PROP_ID, CERT_STORE_NO_CRYPT_RELEASE_FLAG, &kc));
    ccp_free(c);                                   /* releases nothing: the flag keeps ownership with us */
    CHECK(ADV(CryptGenRandom)(prov, 16, b));         /* still a valid provider handle */
    (void)n;
    CHECK(ADV(CryptReleaseContext)(prov, 0));
}
TEST(ccp_find_certificate_key_prov_info_no_match) {
    PCCERT_CONTEXT c = ccp_ctx(&fx_rsa1024); DWORD cb = 0;
    REQUIRE(C32(CryptFindCertificateKeyProvInfo));
    if (!c) { CHECK(0); return; }
    SET_ERR(0);
    CHECK(!C32(CryptFindCertificateKeyProvInfo)(c, CRYPT_FIND_SILENT_KEYSET_FLAG | CRYPT_FIND_USER_KEYSET_FLAG, NULL));
    t_note("no key for a freshly authored certificate: last error 0x%lx", (unsigned long)GetLastError());
    CHECK(GetLastError() != 0);
    CHECK(!ccp_getprop(c, CERT_KEY_PROV_INFO_PROP_ID, NULL, &cb));          /* nothing was attached */
    ccp_free(c);
}

#define NOT_WINE(why) do { if (t_is_wine()) { t_skip(why); return; } } while (0)
/* ---- CryptSignMessageWithKey / CryptVerifyMessageSignatureWithKey ---- */
static void fill_sign_para(CRYPT_KEY_SIGN_MESSAGE_PARA *p, NCRYPT_KEY_HANDLE key, const char *hashoid) {
    memset(p, 0, sizeof *p);
    p->cbSize = sizeof *p; p->dwMsgAndCertEncodingType = ENC; p->hNCryptKey = key; p->dwKeySpec = CERT_NCRYPT_KEY_SPEC;
    p->HashAlgorithm.pszObjId = (LPSTR)hashoid; p->PubKeyAlgorithm.pszObjId = (LPSTR)szOID_RSA_RSA;
}
TEST(ccp_sign_message_with_key_roundtrip) {
    NOT_WINE("emulator aborts: CryptSignMessageWithKey family is unimplemented");
    EKEY k; CRYPT_KEY_SIGN_MESSAGE_PARA sp; CRYPT_KEY_VERIFY_MESSAGE_PARA vp; static const BYTE msg[] = "message signed by cryptt"; DWORD cb = 0, dcb = 0, pcb = 0; BYTE *sig, dec[64]; CERT_PUBLIC_KEY_INFO *pki;
    REQUIRE(C32(CryptSignMessageWithKey)); REQUIRE(C32(CryptVerifyMessageSignatureWithKey));
    NEED_KEY(k, BCRYPT_RSA_ALGORITHM, 2048);
    fill_sign_para(&sp, k.key, szOID_NIST_sha256);
    CHECK(C32(CryptSignMessageWithKey)(&sp, msg, sizeof msg, NULL, &cb));
    CHECK(cb > 256 + sizeof msg);
    sig = (BYTE *)LocalAlloc(LPTR, cb + 8);
    { DWORD s2 = cb - 1; SET_ERR(0); EXPECT_FAIL(!C32(CryptSignMessageWithKey)(&sp, msg, sizeof msg, sig, &s2), ERROR_MORE_DATA); EXPECT_EQ(s2, cb); }
    CHECK(C32(CryptSignMessageWithKey)(&sp, msg, sizeof msg, sig, &cb));
    CHECK(C32(CryptExportPublicKeyInfoEx)(k.key, CERT_NCRYPT_KEY_SPEC, ENC, NULL, 0, NULL, NULL, &pcb));
    pki = (CERT_PUBLIC_KEY_INFO *)LocalAlloc(LPTR, pcb);
    CHECK(C32(CryptExportPublicKeyInfoEx)(k.key, CERT_NCRYPT_KEY_SPEC, ENC, NULL, 0, NULL, pki, &pcb));
    memset(&vp, 0, sizeof vp); vp.cbSize = sizeof vp; vp.dwMsgEncodingType = ENC;
    CHECK(C32(CryptVerifyMessageSignatureWithKey)(&vp, pki, sig, cb, NULL, &dcb));
    EXPECT_EQ(dcb, sizeof msg);
    { DWORD s2 = sizeof msg - 1; SET_ERR(0); EXPECT_FAIL(!C32(CryptVerifyMessageSignatureWithKey)(&vp, pki, sig, cb, dec, &s2), ERROR_MORE_DATA); EXPECT_EQ(s2, sizeof msg); }
    dcb = sizeof dec;
    CHECK(C32(CryptVerifyMessageSignatureWithKey)(&vp, pki, sig, cb, dec, &dcb));
    CHECK(dcb == sizeof msg && !memcmp(dec, msg, sizeof msg));
    /* the signed blob is a CERT_SIGNED_CONTENT_INFO: SEQUENCE { content, algorithm, signature } */
    CHECK(sig[0] == 0x30);
    /* tampering breaks it */
    sig[cb - 1] ^= 1; dcb = sizeof dec; SET_ERR(0);
    CHECK(!C32(CryptVerifyMessageSignatureWithKey)(&vp, pki, sig, cb, dec, &dcb));
    sig[cb - 1] ^= 1;
    { PCCERT_CONTEXT r = ccp_ctx(&fx_root); dcb = sizeof dec; SET_ERR(0);
      CHECK(!C32(CryptVerifyMessageSignatureWithKey)(&vp, &r->pCertInfo->SubjectPublicKeyInfo, sig, cb, dec, &dcb)); ccp_free(r); }
    LocalFree(pki); LocalFree(sig); ekey_free(&k);
}
TEST(ccp_sign_message_with_key_bad_params) {
    NOT_WINE("emulator aborts: CryptSignMessageWithKey family is unimplemented");
    EKEY k; CRYPT_KEY_SIGN_MESSAGE_PARA sp; static const BYTE msg[] = {1, 2, 3}; DWORD cb = 0;
    REQUIRE(C32(CryptSignMessageWithKey));
    NEED_KEY(k, BCRYPT_RSA_ALGORITHM, 2048);
    fill_sign_para(&sp, k.key, szOID_NIST_sha256);
    sp.cbSize = sizeof sp - 4; SET_ERR(0);
    CHECK(!C32(CryptSignMessageWithKey)(&sp, msg, 3, NULL, &cb)); CHECK(GetLastError() != 0);
    fill_sign_para(&sp, k.key, "1.2.3.4.5"); SET_ERR(0);
    CHECK(!C32(CryptSignMessageWithKey)(&sp, msg, 3, NULL, &cb)); CHECK(GetLastError() != 0);
    fill_sign_para(&sp, k.key, szOID_NIST_sha256); sp.dwMsgAndCertEncodingType = 0; SET_ERR(0);
    CHECK(!C32(CryptSignMessageWithKey)(&sp, msg, 3, NULL, &cb)); CHECK(GetLastError() != 0);
    ekey_free(&k);
}
TEST(ccp_verify_message_signature_with_key_garbage) {
    NOT_WINE("emulator aborts: CryptSignMessageWithKey family is unimplemented");
    CRYPT_KEY_VERIFY_MESSAGE_PARA vp; PCCERT_CONTEXT r = ccp_ctx(&fx_root); BYTE out[16]; DWORD cb = sizeof out; static const BYTE junk[] = {0x30, 0x03, 0x02, 0x01, 0x01};
    REQUIRE(C32(CryptVerifyMessageSignatureWithKey));
    if (!r) { CHECK(0); return; }
    memset(&vp, 0, sizeof vp); vp.cbSize = sizeof vp; vp.dwMsgEncodingType = ENC;
    SET_ERR(0);
    CHECK(!C32(CryptVerifyMessageSignatureWithKey)(&vp, &r->pCertInfo->SubjectPublicKeyInfo, junk, sizeof junk, out, &cb));
    CHECK(GetLastError() != 0);
    SET_ERR(0);
    CHECK(!C32(CryptVerifyMessageSignatureWithKey)(&vp, &r->pCertInfo->SubjectPublicKeyInfo, fx_root.der, fx_root.cb, out, &cb));   /* a certificate is signed content, but for another purpose */
    ccp_free(r);
}
