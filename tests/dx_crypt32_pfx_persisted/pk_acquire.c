/* CryptAcquireCertificatePrivateKey on certificates whose key was persisted by the PFX import. */
#include "pk.h"

#define ACQ(c, fl, ph, pspec, pcf) U(CryptAcquireCertificatePrivateKey)(c, fl, NULL, ph, pspec, pcf)

/* ---- legacy-or-KSP agnostic basics --------------------------------------------------------------- */
#define ACQ_BASIC(nm, fx, imp, fl) TEST(pfxp_acquire_##nm) { \
    PK_SETUP(fx, imp); \
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE h = 0; DWORD spec = 0; BOOL cf = FALSE; \
    SET_ERR(0); \
    BOOL ok = ACQ(c, fl, &h, &spec, &cf); \
    CHECK(ok); \
    if (ok) { CHECK(h != 0); CHECK(cf == TRUE); \
        CRYPT_KEY_PROV_INFO *i = pk_info(c); \
        if (i) { if (i->dwProvType == 0) CHECK(spec == CERT_NCRYPT_KEY_SPEC); else CHECK(spec == AT_KEYEXCHANGE || spec == AT_SIGNATURE); pk_free_info(i); } \
        pk_release(h, spec, cf); } \
    pk_done(c, s); }
ACQ_BASIC(rsa_default,         fx_rsa_pfx, 0, 0)
ACQ_BASIC(rsa_silent,          fx_rsa_pfx, 0, CRYPT_ACQUIRE_SILENT_FLAG)
ACQ_BASIC(rsa_ksp_prefer,      fx_rsa_pfx, PKCS12_ALWAYS_CNG_KSP, CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG)
ACQ_BASIC(rsa_ksp_only,        fx_rsa_pfx, PKCS12_ALWAYS_CNG_KSP, CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG)
ACQ_BASIC(rsa_ksp_only_silent, fx_rsa_pfx, PKCS12_ALWAYS_CNG_KSP, CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG | CRYPT_ACQUIRE_SILENT_FLAG)
ACQ_BASIC(ec_prefer,           fx_ec_pfx, 0, CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG)
ACQ_BASIC(ec_only,             fx_ec_pfx, 0, CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG)
ACQ_BASIC(ec_only_silent,      fx_ec_pfx, 0, CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG | CRYPT_ACQUIRE_SILENT_FLAG)
ACQ_BASIC(ec_exportable_only,  fx_ec_pfx, CRYPT_EXPORTABLE, CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG)

TEST(pfxp_acquire_ksp_key_name_property) {
    PK_SETUP(fx_rsa_pfx, PKCS12_ALWAYS_CNG_KSP);
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE h = 0; DWORD spec = 0; BOOL cf = FALSE;
    if (ACQ(c, CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG, &h, &spec, &cf)) {
        WCHAR nm[256]; DWORD cb = 0; CRYPT_KEY_PROV_INFO *i = pk_info(c);
        SECURITY_STATUS st = U(NCryptGetProperty)(h, NCRYPT_NAME_PROPERTY, (PBYTE)nm, sizeof nm, &cb, 0);
        EXPECT_HR(st, 0);
        if (!st && i) CHECK(!lstrcmpW(nm, i->pwszContainerName));
        pk_free_info(i); pk_release(h, spec, cf);
    } else CHECKF(0, "acquire failed %lx", GetLastError());
    pk_done(c, s);
}
TEST(pfxp_acquire_ksp_key_properties_rsa) {
    PK_SETUP(fx_rsa_pfx, PKCS12_ALWAYS_CNG_KSP);
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE h = 0; DWORD spec = 0; BOOL cf = FALSE;
    if (ACQ(c, CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG, &h, &spec, &cf)) {
        WCHAR g[64]; DWORD cb = 0, bits = 0;
        EXPECT_HR(U(NCryptGetProperty)(h, NCRYPT_ALGORITHM_GROUP_PROPERTY, (PBYTE)g, sizeof g, &cb, 0), 0);
        CHECK(!lstrcmpW(g, NCRYPT_RSA_ALGORITHM_GROUP));
        EXPECT_HR(U(NCryptGetProperty)(h, NCRYPT_LENGTH_PROPERTY, (PBYTE)&bits, 4, &cb, 0), 0);
        EXPECT_EQ(bits, 2048);
        pk_release(h, spec, cf);
    } else CHECKF(0, "acquire failed %lx", GetLastError());
    pk_done(c, s);
}
TEST(pfxp_acquire_ksp_key_properties_ec) {
    PK_SETUP(fx_ec_pfx, 0);
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE h = 0; DWORD spec = 0; BOOL cf = FALSE;
    if (ACQ(c, CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG, &h, &spec, &cf)) {
        WCHAR g[64]; DWORD cb = 0, bits = 0;
        EXPECT_HR(U(NCryptGetProperty)(h, NCRYPT_ALGORITHM_GROUP_PROPERTY, (PBYTE)g, sizeof g, &cb, 0), 0);
        EXPECT_WSTR(g, L"ECDH"); /* a PFX EC key lands in the ECDH group, not ECDSA */
        EXPECT_HR(U(NCryptGetProperty)(h, NCRYPT_LENGTH_PROPERTY, (PBYTE)&bits, 4, &cb, 0), 0);
        EXPECT_EQ(bits, 256);
        pk_release(h, spec, cf);
    } else CHECKF(0, "acquire failed %lx", GetLastError());
    pk_done(c, s);
}
TEST(pfxp_acquire_ksp_provider_handle_property) {
    PK_SETUP(fx_rsa_pfx, PKCS12_ALWAYS_CNG_KSP);
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE h = 0; DWORD spec = 0; BOOL cf = FALSE;
    if (ACQ(c, CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG, &h, &spec, &cf)) {
        WCHAR nm[256]; DWORD cb = 0; NCRYPT_PROV_HANDLE ph = 0;
        EXPECT_HR(U(NCryptGetProperty)(h, NCRYPT_PROVIDER_HANDLE_PROPERTY, (PBYTE)&ph, sizeof ph, &cb, 0), 0);
        if (ph) { EXPECT_HR(U(NCryptGetProperty)(ph, NCRYPT_NAME_PROPERTY, (PBYTE)nm, sizeof nm, &cb, 0), 0); CHECK(!lstrcmpW(nm, MS_KEY_STORAGE_PROVIDER)); U(NCryptFreeObject)(ph); }
        pk_release(h, spec, cf);
    } else CHECKF(0, "acquire failed %lx", GetLastError());
    pk_done(c, s);
}

/* ---- caching ------------------------------------------------------------------------------------ */
#define CACHE_TEST(nm, fx, imp, fl) TEST(pfxp_acquire_cache_##nm) { \
    PK_SETUP(fx, imp); \
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE h1 = 0, h2 = 0; DWORD sp1 = 0, sp2 = 0; BOOL cf1 = TRUE, cf2 = TRUE; DWORD cb = 0; \
    BOOL ok1 = ACQ(c, CRYPT_ACQUIRE_CACHE_FLAG | fl, &h1, &sp1, &cf1); \
    CHECK(ok1); \
    if (ok1) { \
        CHECK(cf1 == FALSE); \
        CHECK(U(CertGetCertificateContextProperty)(c, CERT_KEY_CONTEXT_PROP_ID, NULL, &cb)); \
        EXPECT_EQ(cb, sizeof(CERT_KEY_CONTEXT)); \
        BOOL ok2 = ACQ(c, CRYPT_ACQUIRE_CACHE_FLAG | fl, &h2, &sp2, &cf2); \
        CHECK(ok2); CHECK(cf2 == FALSE); CHECK(h1 == h2); CHECK(sp1 == sp2); \
        CERT_KEY_CONTEXT kc; cb = sizeof kc; \
        if (U(CertGetCertificateContextProperty)(c, CERT_KEY_CONTEXT_PROP_ID, &kc, &cb)) { \
            EXPECT_EQ(kc.cbSize, sizeof kc); CHECK(kc.hCryptProv == h1); CHECK(kc.dwKeySpec == sp1); } \
    } \
    pk_done(c, s); }
CACHE_TEST(rsa_csp_or_ksp, fx_rsa_pfx, 0, 0)
CACHE_TEST(rsa_ksp,        fx_rsa_pfx, PKCS12_ALWAYS_CNG_KSP, CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG)
CACHE_TEST(ec,             fx_ec_pfx, 0, CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG)
CACHE_TEST(rsa_silent,     fx_rsa_pfx, 0, CRYPT_ACQUIRE_SILENT_FLAG)

TEST(pfxp_acquire_nocache_gives_distinct_owned_handles) {
    PK_SETUP(fx_rsa_pfx, PKCS12_ALWAYS_CNG_KSP);
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE h1 = 0, h2 = 0; DWORD sp1, sp2; BOOL cf1 = FALSE, cf2 = FALSE, cb;
    BOOL a = ACQ(c, CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG, &h1, &sp1, &cf1);
    BOOL b = ACQ(c, CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG, &h2, &sp2, &cf2);
    CHECK(a); CHECK(b);
    if (a && b) { CHECK(cf1 && cf2); CHECK(h1 != h2); }
    DWORD n = 0; SET_ERR(0);
    CHECK(!U(CertGetCertificateContextProperty)(c, CERT_KEY_CONTEXT_PROP_ID, NULL, &n));
    if (a) pk_release(h1, sp1, cf1);
    if (b) pk_release(h2, sp2, cf2);
    pk_done(c, s);
}
TEST(pfxp_acquire_use_prov_info_flag_no_cache_bit) {
    /* with USE_PROV_INFO_FLAG caching depends on CERT_SET_KEY_CONTEXT_PROP_ID in the property's dwFlags (observed) */
    PK_SETUP(fx_rsa_pfx, PKCS12_ALWAYS_CNG_KSP);
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE h = 0; DWORD sp = 0; BOOL cf = FALSE;
    CRYPT_KEY_PROV_INFO *i = pk_info(c);
    int nobit = i && (i->dwFlags & CERT_SET_KEY_CONTEXT_PROP_ID) == 0;
    pk_free_info(i);
    BOOL ok = ACQ(c, CRYPT_ACQUIRE_USE_PROV_INFO_FLAG | CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG, &h, &sp, &cf);
    CHECK(ok); if (ok) { if (nobit) CHECK(cf == TRUE); pk_release(h, sp, cf); }
    pk_done(c, s);
}
TEST(pfxp_acquire_use_prov_info_flag_with_cache_bit) {
    PK_SETUP(fx_rsa_pfx, PKCS12_ALWAYS_CNG_KSP);
    CRYPT_KEY_PROV_INFO *i = pk_info(c);
    if (i) {
        i->dwFlags |= CERT_SET_KEY_CONTEXT_PROP_ID;
        CHECK(U(CertSetCertificateContextProperty)(c, CERT_KEY_PROV_INFO_PROP_ID, 0, i));
        pk_free_info(i);
        HCRYPTPROV_OR_NCRYPT_KEY_HANDLE h = 0, h2 = 0; DWORD sp = 0, sp2 = 0; BOOL cf = TRUE, cf2 = TRUE;
        BOOL ok = ACQ(c, CRYPT_ACQUIRE_USE_PROV_INFO_FLAG | CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG, &h, &sp, &cf);
        CHECK(ok);
        if (ok) {
            CHECK(cf == FALSE);
            BOOL ok2 = ACQ(c, CRYPT_ACQUIRE_USE_PROV_INFO_FLAG | CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG, &h2, &sp2, &cf2);
            CHECK(ok2); if (ok2) { CHECK(cf2 == FALSE); CHECK(h == h2); }
        }
    }
    pk_done(c, s);
}

/* ---- argument validation ------------------------------------------------------------------------ */
TEST(pfxp_acquire_silent_and_window_handle_conflict) {
    PK_SETUP(fx_rsa_pfx, PKCS12_ALWAYS_CNG_KSP);
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE h = 0; DWORD sp = 0; BOOL cf = FALSE; HWND w = NULL;
    SET_ERR(0);
    BOOL ok = U(CryptAcquireCertificatePrivateKey)(c, CRYPT_ACQUIRE_SILENT_FLAG | CRYPT_ACQUIRE_WINDOW_HANDLE_FLAG, &w, &h, &sp, &cf);
    CHECK(!ok); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    if (ok) pk_release(h, sp, cf);
    pk_done(c, s);
}
TEST(pfxp_acquire_null_cert) {
    PK_NEEDS();
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE h = 0; DWORD sp = 0; BOOL cf = FALSE;
    T_EXPECT_FAULT(ACQ(NULL, 0, &h, &sp, &cf));
}
TEST(pfxp_acquire_no_key_property) {
    PK_NEEDS();
    PCCERT_CONTEXT c = U(CertCreateCertificateContext)(X509_ASN_ENCODING, fx_rsa_der, sizeof fx_rsa_der);
    CHECK(c != NULL); if (!c) return;
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE h = 0; DWORD sp = 0; BOOL cf = FALSE;
    SET_ERR(0);
    CHECK(!ACQ(c, 0, &h, &sp, &cf));
    EXPECT_HR(GetLastError(), CRYPT_E_NO_KEY_PROPERTY);
    U(CertFreeCertificateContext)(c);
}
TEST(pfxp_acquire_no_key_property_ncrypt_flag) {
    PK_NEEDS();
    PCCERT_CONTEXT c = U(CertCreateCertificateContext)(X509_ASN_ENCODING, fx_ec_der, sizeof fx_ec_der);
    CHECK(c != NULL); if (!c) return;
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE h = 0; DWORD sp = 0; BOOL cf = FALSE;
    SET_ERR(0);
    CHECK(!ACQ(c, CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG | CRYPT_ACQUIRE_SILENT_FLAG, &h, &sp, &cf));
    EXPECT_HR(GetLastError(), CRYPT_E_NO_KEY_PROPERTY);
    U(CertFreeCertificateContext)(c);
}
TEST(pfxp_acquire_nonexistent_ksp_container) {
    PK_NEEDS();
    PCCERT_CONTEXT c = U(CertCreateCertificateContext)(X509_ASN_ENCODING, fx_rsa_der, sizeof fx_rsa_der);
    CHECK(c != NULL); if (!c) return;
    WCHAR name[96]; wsprintfW(name, L"cryptt_nokey_%lu", GetCurrentProcessId());
    CRYPT_KEY_PROV_INFO ki; memset(&ki, 0, sizeof ki);
    ki.pwszContainerName = name; ki.pwszProvName = (LPWSTR)MS_KEY_STORAGE_PROVIDER; ki.dwProvType = 0; ki.dwKeySpec = 0;
    CHECK(U(CertSetCertificateContextProperty)(c, CERT_KEY_PROV_INFO_PROP_ID, 0, &ki));
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE h = 0; DWORD sp = 0; BOOL cf = FALSE;
    SET_ERR(0);
    BOOL ok = ACQ(c, CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG | CRYPT_ACQUIRE_SILENT_FLAG, &h, &sp, &cf);
    CHECK(!ok);
    t_note("missing KSP key: GetLastError=0x%08lx", GetLastError());
    DWORD e = GetLastError();
    CHECKF(e == NTE_BAD_KEYSET || e == NTE_NO_KEY || e == NTE_BAD_KEYSET_PARAM, "unexpected 0x%08lx", e);
    U(CertFreeCertificateContext)(c);
}
TEST(pfxp_acquire_nonexistent_csp_container) {
    PK_NEEDS();
    PCCERT_CONTEXT c = U(CertCreateCertificateContext)(X509_ASN_ENCODING, fx_rsa_der, sizeof fx_rsa_der);
    CHECK(c != NULL); if (!c) return;
    WCHAR name[96]; wsprintfW(name, L"cryptt_nokey_%lu", GetCurrentProcessId());
    CRYPT_KEY_PROV_INFO ki; memset(&ki, 0, sizeof ki);
    ki.pwszContainerName = name; ki.pwszProvName = (LPWSTR)MS_ENH_RSA_AES_PROV_W; ki.dwProvType = PROV_RSA_AES; ki.dwKeySpec = AT_KEYEXCHANGE;
    CHECK(U(CertSetCertificateContextProperty)(c, CERT_KEY_PROV_INFO_PROP_ID, 0, &ki));
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE h = 0; DWORD sp = 0; BOOL cf = FALSE;
    SET_ERR(0);
    BOOL ok = ACQ(c, CRYPT_ACQUIRE_SILENT_FLAG, &h, &sp, &cf);
    CHECK(!ok);
    EXPECT_HR(GetLastError(), NTE_BAD_KEYSET);
    U(CertFreeCertificateContext)(c);
}
TEST(pfxp_acquire_unknown_provider_name) {
    PK_NEEDS();
    PCCERT_CONTEXT c = U(CertCreateCertificateContext)(X509_ASN_ENCODING, fx_rsa_der, sizeof fx_rsa_der);
    CHECK(c != NULL); if (!c) return;
    WCHAR name[96]; wsprintfW(name, L"cryptt_noprov_%lu", GetCurrentProcessId());
    CRYPT_KEY_PROV_INFO ki; memset(&ki, 0, sizeof ki);
    ki.pwszContainerName = name; ki.pwszProvName = L"cryptt no such provider"; ki.dwProvType = PROV_RSA_AES; ki.dwKeySpec = AT_KEYEXCHANGE;
    CHECK(U(CertSetCertificateContextProperty)(c, CERT_KEY_PROV_INFO_PROP_ID, 0, &ki));
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE h = 0; DWORD sp = 0; BOOL cf = FALSE;
    SET_ERR(0);
    CHECK(!ACQ(c, CRYPT_ACQUIRE_SILENT_FLAG, &h, &sp, &cf));
    t_note("unknown CSP name: 0x%08lx", GetLastError());
    CHECK(GetLastError() != 0);
    U(CertFreeCertificateContext)(c);
}

/* ---- the property can be copied to another context of the same certificate ----------------------- */
TEST(pfxp_acquire_via_copied_prov_info) {
    PK_SETUP(fx_rsa_pfx, PKCS12_ALWAYS_CNG_KSP);
    CRYPT_KEY_PROV_INFO *i = pk_info(c);
    PCCERT_CONTEXT c2 = U(CertCreateCertificateContext)(X509_ASN_ENCODING, c->pbCertEncoded, c->cbCertEncoded);
    CHECK(c2 != NULL && i != NULL);
    if (c2 && i) {
        HCRYPTPROV_OR_NCRYPT_KEY_HANDLE h = 0; DWORD sp = 0; BOOL cf = FALSE;
        CHECK(U(CertSetCertificateContextProperty)(c2, CERT_KEY_PROV_INFO_PROP_ID, 0, i));
        CHECK(ACQ(c2, CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG, &h, &sp, &cf));
        if (h) pk_release(h, sp, cf);
    }
    if (c2) U(CertFreeCertificateContext)(c2);
    pk_free_info(i);
    pk_done(c, s);
}
TEST(pfxp_acquire_via_copied_prov_info_csp) {
    PK_SETUP(fx_rsa_pfx, 0);
    CRYPT_KEY_PROV_INFO *i = pk_info(c);
    PCCERT_CONTEXT c2 = U(CertCreateCertificateContext)(X509_ASN_ENCODING, c->pbCertEncoded, c->cbCertEncoded);
    CHECK(c2 != NULL && i != NULL);
    if (c2 && i) {
        HCRYPTPROV_OR_NCRYPT_KEY_HANDLE h = 0; DWORD sp = 0; BOOL cf = FALSE;
        CHECK(U(CertSetCertificateContextProperty)(c2, CERT_KEY_PROV_INFO_PROP_ID, 0, i));
        CHECK(ACQ(c2, 0, &h, &sp, &cf));
        if (h) pk_release(h, sp, cf);
    }
    if (c2) U(CertFreeCertificateContext)(c2);
    pk_free_info(i);
    pk_done(c, s);
}
/* property round trip of the key provider info on the persisted cert */
TEST(pfxp_prov_info_property_roundtrip) {
    PK_SETUP(fx_rsa_pfx, PKCS12_ALWAYS_CNG_KSP);
    CRYPT_KEY_PROV_INFO *i = pk_info(c);
    DWORD cb1 = 0, cb2 = 0;
    CHECK(U(CertGetCertificateContextProperty)(c, CERT_KEY_PROV_INFO_PROP_ID, NULL, &cb1));
    CHECK(i != NULL);
    if (i) {
        CHECK(U(CertSetCertificateContextProperty)(c, CERT_KEY_PROV_INFO_PROP_ID, 0, i));
        CHECK(U(CertGetCertificateContextProperty)(c, CERT_KEY_PROV_INFO_PROP_ID, NULL, &cb2));
        EXPECT_EQ(cb1, cb2);
    }
    pk_free_info(i);
    pk_done(c, s);
}
TEST(pfxp_prov_info_buffer_protocol) {
    PK_SETUP(fx_rsa_pfx, PKCS12_ALWAYS_CNG_KSP);
    DWORD cb = 0, small = 0; BYTE *buf;
    CHECK(U(CertGetCertificateContextProperty)(c, CERT_KEY_PROV_INFO_PROP_ID, NULL, &cb));
    CHECK(cb > sizeof(CRYPT_KEY_PROV_INFO));
    buf = (BYTE *)LocalAlloc(LPTR, cb + 8);
    if (buf) {
        small = cb - 1; SET_ERR(0);
        CHECK(!U(CertGetCertificateContextProperty)(c, CERT_KEY_PROV_INFO_PROP_ID, buf, &small));
        EXPECT_ERR(ERROR_MORE_DATA); EXPECT_EQ(small, cb);
        small = 0; SET_ERR(0);
        CHECK(!U(CertGetCertificateContextProperty)(c, CERT_KEY_PROV_INFO_PROP_ID, buf, &small));
        EXPECT_ERR(ERROR_MORE_DATA); EXPECT_EQ(small, cb);
        small = cb + 8;
        CHECK(U(CertGetCertificateContextProperty)(c, CERT_KEY_PROV_INFO_PROP_ID, buf, &small));
        EXPECT_EQ(small, cb);
        LocalFree(buf);
    }
    pk_done(c, s);
}
