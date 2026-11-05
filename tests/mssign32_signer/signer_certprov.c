/* GetCryptProvFromCert(Ex), FreeCryptProvFromCert(Ex), SpcGetCertFromKey: provider acquisition for a signing certificate. */
#include "mssfix.h"

#define NEED_NOWINE() do { if (t_is_wine()) { t_skip("mssign32 stubs under Wine"); return; } } while (0)
static PCCERT_CONTEXT mkcert(int which) {
    DWORD cb; const BYTE *der = fx_cert_der(which, &cb);
    return U(CertCreateCertificateContext)(X509_ASN_ENCODING, der, cb);
}
static int have_key(HCRYPTPROV h, DWORD spec) {
    HCRYPTKEY k = 0;
    if (!U(CryptGetUserKey)(h, spec, &k)) return 0;
    U(CryptDestroyKey)(k);
    return 1;
}

/* ---- GetCryptProvFromCert / Ex ---- */
#define SENT_H   ((HCRYPTPROV)0x7777)
#define SENT_P   ((LPWSTR)(ULONG_PTR)0x5555)
typedef struct { HCRYPTPROV h; DWORD spec; BOOL did; LPWSTR tmp, name; DWORD type; } OUTS;
static void outs_poison(OUTS *o) { o->h = SENT_H; o->spec = 0x99; o->did = 0x55; o->tmp = SENT_P; o->name = SENT_P; o->type = 0x66; }
static BOOL gcp(int ex, PCCERT_CONTEXT c, OUTS *o) {
    if (ex) return UN(GetCryptProvFromCertEx)(NULL, c, &o->h, &o->spec, &o->did, &o->tmp, &o->name, &o->type);
    return UN(GetCryptProvFromCert)(NULL, c, &o->h, &o->spec, &o->did, &o->tmp, &o->name, &o->type);
}
TEST(mssigner_gcp_null_cert) {
    REQUIRE(UN(GetCryptProvFromCert)); REQUIRE(UN(GetCryptProvFromCertEx));
    for (int ex = 0; ex < 2; ex++) {
        OUTS o; outs_poison(&o);
        SET_ERR(0);
        BOOL r = gcp(ex, NULL, &o);
        CHECKF(!r, "ex=%d", ex);
        EXPECT_ERR(HR_NO_KEY_PROP);
        EXPECT_EQ(o.h, 0); EXPECT_EQ(o.spec, 0); EXPECT_EQ(o.did, 0);
        CHECK(o.tmp == NULL); CHECK(o.name == NULL);
    }
}
TEST(mssigner_gcp_cert_without_key_info) {
    REQUIRE(UN(GetCryptProvFromCert)); REQUIRE(UN(GetCryptProvFromCertEx));
    PCCERT_CONTEXT c = mkcert(FX_A);
    CHECK(c != NULL); if (!c) return;
    for (int ex = 0; ex < 2; ex++) {
        OUTS o; outs_poison(&o);
        SET_ERR(0);
        BOOL r = gcp(ex, c, &o);
        CHECKF(!r, "ex=%d", ex);
        EXPECT_ERR(HR_NO_KEY_PROP);
        EXPECT_EQ(o.h, 0); EXPECT_EQ(o.did, 0);
        CHECK(o.tmp == NULL); CHECK(o.name == NULL);
    }
    U(CertFreeCertificateContext)(c);
}
TEST(mssigner_gcp_ex_uses_key_context_property) {
    REQUIRE(UN(GetCryptProvFromCertEx));
    FX f;
    if (!fx_open(&f, FX_A, 1) || !fx_cert_attach(&f)) { t_skip("no key fixture"); return; }
    OUTS o; outs_poison(&o);
    BOOL r = gcp(1, f.cert, &o);
    CHECK(r);
    if (r) {
        CHECK(o.h == f.hProv);
        EXPECT_EQ(o.spec, 1);
        CHECK(o.did == FALSE);          /* handle owned by the certificate's key context */
        CHECK(o.tmp == NULL);
        CHECK(o.name == NULL);
    }
    fx_close(&f);
}
TEST(mssigner_gcp_plain_key_context_property) {
    REQUIRE(UN(GetCryptProvFromCert));
    FX f;
    if (!fx_open(&f, FX_A, 1) || !fx_cert_attach(&f)) { t_skip("no key fixture"); return; }
    OUTS o; outs_poison(&o);
    SET_ERR(0);
    BOOL r = gcp(0, f.cert, &o);
    t_note("GetCryptProvFromCert with cached key context: ret=%d hProv==ours:%d spec=%lu did=%d err=0x%08lx",
           r, o.h == f.hProv, o.spec, o.did, GetLastError());
    CHECK(r == (o.h != 0));
    if (r && o.did) { UN(FreeCryptProvFromCert)(o.did, o.h, o.name, o.type, o.tmp); }
    fx_close(&f);
}
TEST(mssigner_gcp_ex_from_pvk_file_property) {
    /* A certificate carrying CERT_PVK_FILE_PROP_ID ("file\0keyspec\0provtype\0provider\0\0") makes the helper
     * load the key from the file into a temporary container (GetProviderInfoFromCert + PvkGetCryptProv). */
    REQUIRE(UN(GetCryptProvFromCertEx)); REQUIRE(UN(FreeCryptProvFromCert));
    char p[MAX_PATH]; BYTE pvk[2048]; DWORD n = fx_pvk(FX_A, 1, 0, 0, pvk, sizeof pvk);
    t_tmpfile(p, sizeof p, "cert.pvk"); CHECK(fx_write_file(p, pvk, n));
    LPWSTR wp = fx_w(p);
    WCHAR prop[MAX_PATH + 160]; WCHAR *q = prop;
    lstrcpyW(q, wp); q += lstrlenW(q) + 1;
    lstrcpyW(q, L"1"); q += 2;
    lstrcpyW(q, L"24"); q += 3;
    lstrcpyW(q, MS_ENH_RSA_AES_PROV_W); q += lstrlenW(q) + 1;
    *q++ = 0;
    CRYPT_DATA_BLOB blob = { (DWORD)((BYTE *)q - (BYTE *)prop), (BYTE *)prop };
    PCCERT_CONTEXT c = mkcert(FX_A);
    CHECK(c != NULL);
    if (c && U(CertSetCertificateContextProperty)(c, CERT_PVK_FILE_PROP_ID, 0, &blob)) {
        OUTS o; outs_poison(&o);
        BOOL r = gcp(1, c, &o);
        CHECK(r);
        if (r) {
            CHECK(o.h != 0 && have_key(o.h, AT_KEYEXCHANGE));
            EXPECT_EQ(o.spec, 1);
            CHECK(o.did == TRUE);
            CHECK(o.tmp != NULL && lstrlenW(o.tmp) == 38);
            CHECK(o.name != NULL && !lstrcmpW(o.name, MS_ENH_RSA_AES_PROV_W));
            EXPECT_EQ(o.type, 24);
            WCHAR cname[64]; lstrcpynW(cname, o.tmp ? o.tmp : L"", 64);
            UN(FreeCryptProvFromCert)(o.did, o.h, o.name, o.type, o.tmp);
            HCRYPTPROV h2 = 0;
            SET_ERR(0);
            BOOL a = U(CryptAcquireContextW)(&h2, cname, MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, 0);
            CHECK(!a); EXPECT_ERR(NTE_BAD_KEYSET);
            if (a) U(CryptReleaseContext)(h2, 0);
        }
    } else CHECK(0);
    free(wp); DeleteFileA(p);
    if (c) U(CertFreeCertificateContext)(c);
}
TEST(mssigner_gcp_pvk_property_missing_file) {
    REQUIRE(UN(GetCryptProvFromCertEx));
    WCHAR prop[MAX_PATH + 160]; WCHAR *q = prop;
    lstrcpyW(q, L"C:\\cryptt_nonexistent_dir\\x.pvk"); q += lstrlenW(q) + 1;
    lstrcpyW(q, L"1"); q += 2;
    lstrcpyW(q, L"24"); q += 3;
    lstrcpyW(q, MS_ENH_RSA_AES_PROV_W); q += lstrlenW(q) + 1;
    *q++ = 0;
    CRYPT_DATA_BLOB blob = { (DWORD)((BYTE *)q - (BYTE *)prop), (BYTE *)prop };
    PCCERT_CONTEXT c = mkcert(FX_A);
    CHECK(c != NULL); if (!c) return;
    CHECK(U(CertSetCertificateContextProperty)(c, CERT_PVK_FILE_PROP_ID, 0, &blob));
    OUTS o; outs_poison(&o);
    SET_ERR(0);
    BOOL r = gcp(1, c, &o);
    CHECK(!r);
    EXPECT_ERR(HR_FILE_NOT_FOUND);       /* PvkGetCryptProv's HRESULT is installed as the last error */
    EXPECT_EQ(o.h, 0); CHECK(o.tmp == NULL);
    U(CertFreeCertificateContext)(c);
}

/* ---- FreeCryptProvFromCert / Ex ---- */
static HCRYPTPROV two_refs(void) {
    HCRYPTPROV h = 0;
    if (!U(CryptAcquireContextW)(&h, NULL, MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) return 0;
    U(CryptContextAddRef)(h, NULL, 0);
    return h;
}
static int usable(HCRYPTPROV h) { BYTE b[4]; return U(CryptGenRandom)(h, 4, b); }
TEST(mssigner_freecp_did_not_acquire_is_noop) {
    REQUIRE(UN(FreeCryptProvFromCert)); REQUIRE(UN(FreeCryptProvFromCertEx));
    HCRYPTPROV h = two_refs(); if (!h) { t_skip("no provider"); return; }
    UN(FreeCryptProvFromCert)(FALSE, h, NULL, 0, NULL);
    CHECK(usable(h));
    UN(FreeCryptProvFromCertEx)(FALSE, h, 1, NULL, 0, NULL);
    CHECK(usable(h));
    UN(FreeCryptProvFromCert)(TRUE, 0, NULL, 0, NULL);          /* handle 0: nothing */
    UN(FreeCryptProvFromCertEx)(TRUE, 0, 1, NULL, 0, NULL);
    CHECK(usable(h));
    U(CryptReleaseContext)(h, 0); U(CryptReleaseContext)(h, 0);
}
TEST(mssigner_freecp_releases_one_reference) {
    REQUIRE(UN(FreeCryptProvFromCert)); REQUIRE(UN(FreeCryptProvFromCertEx));
    HCRYPTPROV h = two_refs(); if (!h) { t_skip("no provider"); return; }
    UN(FreeCryptProvFromCert)(TRUE, h, NULL, 0, NULL);          /* 2 -> 1 */
    CHECK(usable(h));
    U(CryptContextAddRef)(h, NULL, 0);
    UN(FreeCryptProvFromCertEx)(TRUE, h, AT_KEYEXCHANGE, NULL, 0, NULL);   /* ordinary key spec: CAPI release */
    CHECK(usable(h));
    CHECK(U(CryptReleaseContext)(h, 0));
}
TEST(mssigner_freecp_ex_ncrypt_handle) {
    /* dwKeySpec == CERT_NCRYPT_KEY_SPEC (-1) with no temporary container frees the handle with NCryptFreeObject */
    REQUIRE(UN(FreeCryptProvFromCertEx));
    NCRYPT_PROV_HANDLE h = 0;
    SECURITY_STATUS s = U(NCryptOpenStorageProvider)(&h, MS_KEY_STORAGE_PROVIDER, 0);
    CHECK(s == 0 && h);
    if (s) return;
    UN(FreeCryptProvFromCertEx)(TRUE, (HCRYPTPROV)h, (DWORD)-1, NULL, 0, NULL);
    SECURITY_STATUS s2 = U(NCryptFreeObject)(h);                /* already freed */
    EXPECT_EQ((DWORD)s2, (DWORD)NTE_INVALID_HANDLE);
    if (!s2) { /* freed twice would be a bug of the test; nothing more to do */ }
}
TEST(mssigner_freecp_ex_ncrypt_not_acquired_keeps_handle) {
    REQUIRE(UN(FreeCryptProvFromCertEx));
    NCRYPT_PROV_HANDLE h = 0;
    if (U(NCryptOpenStorageProvider)(&h, MS_KEY_STORAGE_PROVIDER, 0) != 0) { t_skip("no KSP"); return; }
    UN(FreeCryptProvFromCertEx)(FALSE, (HCRYPTPROV)h, (DWORD)-1, NULL, 0, NULL);
    SECURITY_STATUS s = U(NCryptFreeObject)(h);
    EXPECT_EQ((DWORD)s, 0);
}

/* ---- SpcGetCertFromKey ---- */
static HCERTSTORE memstore(void) { return U(CertOpenStore)(CERT_STORE_PROV_MEMORY, 0, 0, 0, NULL); }
static void add(HCERTSTORE st, int which) {
    PCCERT_CONTEXT c = mkcert(which);
    if (c) { U(CertAddCertificateContextToStore)(st, c, CERT_STORE_ADD_ALWAYS, NULL); U(CertFreeCertificateContext)(c); }
}
TEST(mssigner_spcgetcert_finds_matching_cert_and_sets_handle_prop) {
    REQUIRE(UN(SpcGetCertFromKey));
    for (int w = 0; w < 2; w++) {
        FX f; if (!fx_open(&f, w, 1)) { t_skip("no key fixture"); return; }
        HCERTSTORE st = memstore(); add(st, FX_A); add(st, FX_B);
        PCCERT_CONTEXT out = (PCCERT_CONTEXT)(ULONG_PTR)1;
        LONG r = UN(SpcGetCertFromKey)(X509_ASN_ENCODING, st, f.hProv, 1, &out);
        CHECKF(r == 0, "key %d: 0x%08lx", w, (DWORD)r);
        CHECK(out != NULL && out != (PCCERT_CONTEXT)1);
        if (r == 0 && out) {
            DWORD cb; const BYTE *der = fx_cert_der(w, &cb);
            CHECK(out->cbCertEncoded == cb && !memcmp(out->pbCertEncoded, der, cb));
            HCRYPTPROV hp = 0; DWORD sz = sizeof hp;
            CHECK(U(CertGetCertificateContextProperty)(out, CERT_KEY_PROV_HANDLE_PROP_ID, &hp, &sz));
            CHECK(hp == f.hProv);
            U(CertFreeCertificateContext)(out);
        }
        U(CertCloseStore)(st, 0);
        fx_close(&f);
    }
}
TEST(mssigner_spcgetcert_no_matching_cert) {
    REQUIRE(UN(SpcGetCertFromKey));
    FX f; if (!fx_open(&f, FX_A, 1)) { t_skip("no key fixture"); return; }
    HCERTSTORE st = memstore(); add(st, FX_B);
    PCCERT_CONTEXT out = (PCCERT_CONTEXT)(ULONG_PTR)1;
    LONG r = UN(SpcGetCertFromKey)(X509_ASN_ENCODING, st, f.hProv, 1, &out);
    EXPECT_EQ((DWORD)r, HR_NO_MATCH);
    CHECK(out == NULL);
    U(CertCloseStore)(st, 0);
    /* empty store */
    st = memstore();
    out = (PCCERT_CONTEXT)(ULONG_PTR)1;
    r = UN(SpcGetCertFromKey)(X509_ASN_ENCODING, st, f.hProv, 1, &out);
    EXPECT_EQ((DWORD)r, HR_NO_MATCH);
    CHECK(out == NULL);
    U(CertCloseStore)(st, 0);
    fx_close(&f);
}
TEST(mssigner_spcgetcert_null_output_pointer) {
    REQUIRE(UN(SpcGetCertFromKey));
    FX f; if (!fx_open(&f, FX_A, 1)) { t_skip("no key fixture"); return; }
    HCERTSTORE st = memstore(); add(st, FX_A);
    EXPECT_EQ((DWORD)UN(SpcGetCertFromKey)(X509_ASN_ENCODING, st, f.hProv, 1, NULL), HR_INVALIDARG);
    U(CertCloseStore)(st, 0);
    fx_close(&f);
}
TEST(mssigner_spcgetcert_context_without_key) {
    REQUIRE(UN(SpcGetCertFromKey));
    FX f; if (!fx_open_empty(&f)) { t_skip("no context"); return; }
    HCERTSTORE st = memstore(); add(st, FX_A);
    PCCERT_CONTEXT out = (PCCERT_CONTEXT)(ULONG_PTR)1;
    LONG r = UN(SpcGetCertFromKey)(X509_ASN_ENCODING, st, f.hProv, 1, &out);
    CHECK(r < 0);
    t_note("no user key in the context: 0x%08lx", (DWORD)r);
    CHECK(out == NULL);
    U(CertCloseStore)(st, 0);
    fx_close(&f);
}
TEST(mssigner_spcgetcert_key_spec_variants) {
    REQUIRE(UN(SpcGetCertFromKey));
    FX f; if (!fx_open(&f, FX_A, 2)) { t_skip("no key fixture"); return; }
    HCERTSTORE st = memstore(); add(st, FX_A);
    PCCERT_CONTEXT out = NULL;
    LONG r = UN(SpcGetCertFromKey)(X509_ASN_ENCODING, st, f.hProv, 2, &out);
    EXPECT_EQ((DWORD)r, 0);
    if (out) U(CertFreeCertificateContext)(out);
    out = (PCCERT_CONTEXT)(ULONG_PTR)1;
    r = UN(SpcGetCertFromKey)(X509_ASN_ENCODING, st, f.hProv, 1, &out);     /* only a signature key exists */
    CHECK(r < 0);
    CHECK(out == NULL);
    U(CertCloseStore)(st, 0);
    fx_close(&f);
}
