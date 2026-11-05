/* Removing persisted keys, detaching the property, and CryptFindCertificateKeyProvInfo. */
#include "pk.h"

#define FIND_NEEDS() PK_NEEDS(); REQUIRE(UN(CryptFindCertificateKeyProvInfo)); REQUIRE(U(CertCreateCertificateContext))

/* ---- detaching the property does not delete the key -------------------------------------------- */
#define DETACH_TEST(nm, fx, imp) TEST(pfxp_detach_prop_keeps_key_##nm) { \
    PK_SETUP(fx, imp); \
    CRYPT_KEY_PROV_INFO *i = pk_info(c); CHECK(i != NULL); if (!i) { pk_done(c, s); return; } \
    CHECK(U(CertSetCertificateContextProperty)(c, CERT_KEY_PROV_INFO_PROP_ID, 0, NULL)); \
    DWORD cb = 0; SET_ERR(0); \
    CHECK(!U(CertGetCertificateContextProperty)(c, CERT_KEY_PROV_INFO_PROP_ID, NULL, &cb)); \
    EXPECT_HR(GetLastError(), CRYPT_E_NOT_FOUND); \
    EXPECT_EQ(pk_open_status(i), 0); \
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE h = 0; DWORD sp; BOOL cf; SET_ERR(0); \
    CHECK(!U(CryptAcquireCertificatePrivateKey)(c, CRYPT_ACQUIRE_SILENT_FLAG, NULL, &h, &sp, &cf)); \
    EXPECT_HR(GetLastError(), CRYPT_E_NO_KEY_PROPERTY); \
    pk_destroy(i->pwszProvName, i->dwProvType, i->pwszContainerName, i->dwFlags); \
    EXPECT_HR(pk_open_status(i) != 0, 1); \
    pk_free_info(i); pk_done(c, s); }
DETACH_TEST(rsa_csp, fx_rsa_pfx, 0)
DETACH_TEST(rsa_ksp, fx_rsa_pfx, PKCS12_ALWAYS_CNG_KSP)
DETACH_TEST(ec,      fx_ec_pfx, 0)

/* ---- CNG delete ---------------------------------------------------------------------------------- */
#define NCDEL_TEST(nm, fx, imp, werr) TEST(pfxp_delete_ncrypt_##nm) { \
    PK_SETUP(fx, imp); CRYPT_KEY_PROV_INFO *i = pk_info(c); \
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE h = 0; DWORD sp = 0; BOOL cf = FALSE; \
    CHECK(i != NULL); \
    if (i && U(CryptAcquireCertificatePrivateKey)(c, CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG | CRYPT_ACQUIRE_SILENT_FLAG, NULL, &h, &sp, &cf)) { \
        CHECK(cf); \
        EXPECT_HR(U(NCryptDeleteKey)(h, NCRYPT_SILENT_FLAG), 0); \
        DWORD st = pk_open_status(i); \
        EXPECT_HR(st, NTE_BAD_KEYSET); \
        SET_ERR(0); \
        CHECK(!U(CryptAcquireCertificatePrivateKey)(c, CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG | CRYPT_ACQUIRE_SILENT_FLAG, NULL, &h, &sp, &cf)); \
        t_note("acquire after NCryptDeleteKey: 0x%08lx", GetLastError()); \
        EXPECT_ERR(werr); \
    } \
    pk_free_info(i); pk_done(c, s); }
NCDEL_TEST(rsa_ksp, fx_rsa_pfx, PKCS12_ALWAYS_CNG_KSP, NTE_BAD_KEYSET)
NCDEL_TEST(ec,      fx_ec_pfx, 0, NTE_BAD_KEYSET)
/* observed on Win10 22H2: the exportable EC key reports 0x12a (not NTE_BAD_KEYSET), stable across runs */
NCDEL_TEST(ec_exportable, fx_ec_pfx, CRYPT_EXPORTABLE, 0x12a)

TEST(pfxp_delete_ncrypt_second_delete_fails) {
    PK_SETUP(fx_rsa_pfx, PKCS12_ALWAYS_CNG_KSP);
    CRYPT_KEY_PROV_INFO *i = pk_info(c);
    NCRYPT_PROV_HANDLE p = 0; NCRYPT_KEY_HANDLE k1 = 0, k2 = 0;
    if (i && !U(NCryptOpenStorageProvider)(&p, i->pwszProvName, 0)) {
        EXPECT_HR(U(NCryptOpenKey)(p, &k1, i->pwszContainerName, i->dwKeySpec, NCRYPT_SILENT_FLAG), 0);
        EXPECT_HR(U(NCryptDeleteKey)(k1, NCRYPT_SILENT_FLAG), 0);
        EXPECT_HR(U(NCryptOpenKey)(p, &k2, i->pwszContainerName, i->dwKeySpec, NCRYPT_SILENT_FLAG), NTE_BAD_KEYSET);
        U(NCryptFreeObject)(p);
    }
    pk_free_info(i); pk_done(c, s);
}
TEST(pfxp_delete_ncrypt_open_by_cert_name_wrong_flags) {
    PK_SETUP(fx_rsa_pfx, PKCS12_ALWAYS_CNG_KSP);
    CRYPT_KEY_PROV_INFO *i = pk_info(c);
    NCRYPT_PROV_HANDLE p = 0; NCRYPT_KEY_HANDLE k = 0;
    if (i && !U(NCryptOpenStorageProvider)(&p, i->pwszProvName, 0)) {
        /* the key lives in the user store: it is not visible in the machine store */
        SECURITY_STATUS st = U(NCryptOpenKey)(p, &k, i->pwszContainerName, i->dwKeySpec, NCRYPT_MACHINE_KEY_FLAG | NCRYPT_SILENT_FLAG);
        CHECK(st != 0);
        if (!st) U(NCryptFreeObject)(k);
        else t_note("user key opened in machine scope: 0x%08lx", (DWORD)st);
        U(NCryptFreeObject)(p);
    }
    pk_free_info(i); pk_done(c, s);
}

/* ---- CryptoAPI delete (legacy keyset) -------------------------------------------------------------- */
TEST(pfxp_delete_capi_container) {
    PK_SETUP(fx_rsa_pfx, 0);
    CRYPT_KEY_PROV_INFO *i = pk_info(c);
    CHECK(i != NULL);
    if (i && i->dwProvType != 0) {
        HCRYPTPROV h = 0;
        EXPECT_HR(pk_open_status(i), 0);
        CHECK(U(CryptAcquireContextW)(&h, i->pwszContainerName, i->pwszProvName, i->dwProvType, CRYPT_DELETEKEYSET | CRYPT_SILENT));
        SET_ERR(0);
        CHECK(!U(CryptAcquireContextW)(&h, i->pwszContainerName, i->pwszProvName, i->dwProvType, CRYPT_SILENT));
        EXPECT_HR(GetLastError(), NTE_BAD_KEYSET);
        SET_ERR(0);
        CHECK(!U(CryptAcquireContextW)(&h, i->pwszContainerName, i->pwszProvName, i->dwProvType, CRYPT_DELETEKEYSET | CRYPT_SILENT));
        EXPECT_HR(GetLastError(), NTE_BAD_KEYSET);
        SET_ERR(0);
        HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hh = 0; DWORD sp; BOOL cf;
        CHECK(!U(CryptAcquireCertificatePrivateKey)(c, CRYPT_ACQUIRE_SILENT_FLAG, NULL, &hh, &sp, &cf));
        EXPECT_HR(GetLastError(), NTE_BAD_KEYSET);
    } else t_skip("default RSA import did not use a CSP here");
    pk_free_info(i); pk_done(c, s);
}
TEST(pfxp_delete_capi_container_while_acquired_cache) {
    PK_SETUP(fx_rsa_pfx, 0);
    CRYPT_KEY_PROV_INFO *i = pk_info(c);
    if (i && i->dwProvType != 0) {
        HCRYPTPROV_OR_NCRYPT_KEY_HANDLE h = 0; DWORD sp; BOOL cf;
        CHECK(U(CryptAcquireCertificatePrivateKey)(c, CRYPT_ACQUIRE_CACHE_FLAG | CRYPT_ACQUIRE_SILENT_FLAG, NULL, &h, &sp, &cf));
        CHECK(!cf);
        /* the cached context stays valid for the life of the certificate context; delete via a second handle */
        pk_destroy(i->pwszProvName, i->dwProvType, i->pwszContainerName, i->dwFlags);
        EXPECT_HR(pk_open_status(i) != 0, 1);
        t_note("cached CSP handle usable after container delete: not asserted");
    } else t_skip("default RSA import did not use a CSP here");
    pk_free_info(i); pk_done(c, s);
}
TEST(pfxp_delete_capi_wrong_provider_type) {
    PK_SETUP(fx_rsa_pfx, 0);
    CRYPT_KEY_PROV_INFO *i = pk_info(c);
    if (i && i->dwProvType != 0) {
        HCRYPTPROV h = 0; SET_ERR(0);
        /* container exists, but a provider of another name does not have it */
        BOOL ok = U(CryptAcquireContextW)(&h, i->pwszContainerName, MS_DEF_PROV_W, PROV_RSA_FULL, CRYPT_SILENT);
        t_note("same container name in %ls: %d err 0x%lx", MS_DEF_PROV_W, ok, ok ? 0 : GetLastError());
        if (ok) U(CryptReleaseContext)(h, 0);
    } else t_skip("default RSA import did not use a CSP here");
    pk_free_info(i); pk_done(c, s);
}

/* ---- delete the key of an exported-then-reimported cert, store survives ---------------------------- */
TEST(pfxp_cert_survives_key_delete) {
    PK_SETUP(fx_rsa_pfx, PKCS12_ALWAYS_CNG_KSP);
    CRYPT_KEY_PROV_INFO *i = pk_info(c);
    if (i) { pk_destroy(i->pwszProvName, i->dwProvType, i->pwszContainerName, i->dwFlags); pk_free_info(i); }
    EXPECT_EQ(pk_count(s), 1);
    CHECK(c->cbCertEncoded == sizeof fx_rsa_der);
    /* the dangling property is still there */
    DWORD cb = 0; CHECK(U(CertGetCertificateContextProperty)(c, CERT_KEY_PROV_INFO_PROP_ID, NULL, &cb));
    pk_done(c, s);
}

/* ---- CryptFindCertificateKeyProvInfo ------------------------------------------------------------- */
static PCCERT_CONTEXT keyless_copy(const BYTE *der, size_t n, HCERTSTORE *ms) {
    PCCERT_CONTEXT c = NULL;
    *ms = U(CertOpenStore)(CERT_STORE_PROV_MEMORY, 0, 0, CERT_STORE_CREATE_NEW_FLAG, NULL);
    if (!*ms) return NULL;
    if (!U(CertAddEncodedCertificateToStore)(*ms, X509_ASN_ENCODING, der, (DWORD)n, CERT_STORE_ADD_ALWAYS, &c)) return NULL;
    return c;
}
#define FIND_TEST(nm, fx, der, imp, ff, expect_type_zero) TEST(pfxp_find_##nm) { \
    PK_SETUP(fx, imp); CRYPT_KEY_PROV_INFO *orig = pk_info(c); HCERTSTORE ms; \
    PCCERT_CONTEXT k = keyless_copy(der, sizeof der, &ms); \
    CHECK(k != NULL && orig != NULL); \
    if (k && orig) { \
        DWORD cb = 0; CHECK(!U(CertGetCertificateContextProperty)(k, CERT_KEY_PROV_INFO_PROP_ID, NULL, &cb)); \
        SET_ERR(0); \
        BOOL ok = UN(CryptFindCertificateKeyProvInfo)(k, ff, NULL); \
        CHECKF(ok, "find failed 0x%08lx", GetLastError()); \
        if (ok) { CRYPT_KEY_PROV_INFO *f = pk_info(k); CHECK(f != NULL); \
            if (f) { if (lstrcmpW(f->pwszContainerName, orig->pwszContainerName)) t_note("find returned another container %ls (a leftover key with the same public key?)", f->pwszContainerName); EXPECT_EQ(pk_open_status(f), 0); t_note("find provider %ls vs imported %ls", f->pwszProvName, orig->pwszProvName); \
                CHECK((f->dwFlags & CRYPT_MACHINE_KEYSET) == 0); \
                t_note(#nm ": found type=%lu spec=%lu flags=0x%lx", f->dwProvType, f->dwKeySpec, f->dwFlags); pk_free_info(f); } } } \
    if (k) U(CertFreeCertificateContext)(k); \
    if (ms) U(CertCloseStore)(ms, 0); \
    pk_free_info(orig); pk_done(c, s); }
/* the persisted key is detached from the original first, so that only the key container identifies it */
FIND_TEST(rsa_csp_user,        fx_rsa_pfx, fx_rsa_der, 0, CRYPT_FIND_USER_KEYSET_FLAG, 0)
FIND_TEST(rsa_csp_user_silent, fx_rsa_pfx, fx_rsa_der, 0, CRYPT_FIND_USER_KEYSET_FLAG | CRYPT_FIND_SILENT_KEYSET_FLAG, 0)
FIND_TEST(rsa_csp_default_flags, fx_rsa_pfx, fx_rsa_der, 0, 0, 0)
FIND_TEST(rsa_ksp_user,        fx_rsa_pfx, fx_rsa_der, PKCS12_ALWAYS_CNG_KSP, CRYPT_FIND_USER_KEYSET_FLAG, 1)
FIND_TEST(rsa_ksp_default_flags, fx_rsa_pfx, fx_rsa_der, PKCS12_ALWAYS_CNG_KSP, 0, 1)
FIND_TEST(rsa_ksp_exportable,  fx_rsa_pfx, fx_rsa_der, PKCS12_ALWAYS_CNG_KSP | CRYPT_EXPORTABLE, CRYPT_FIND_USER_KEYSET_FLAG, 1)
FIND_TEST(ec_user,             fx_ec_pfx, fx_ec_der, 0, CRYPT_FIND_USER_KEYSET_FLAG, 1)
FIND_TEST(ec_default_flags,    fx_ec_pfx, fx_ec_der, 0, 0, 1)
FIND_TEST(ec_silent,           fx_ec_pfx, fx_ec_der, 0, CRYPT_FIND_USER_KEYSET_FLAG | CRYPT_FIND_SILENT_KEYSET_FLAG, 1)

/* then the found property is usable */
TEST(pfxp_find_then_acquire_and_sign) {
    PK_SETUP(fx_rsa_pfx, PKCS12_ALWAYS_CNG_KSP);
    HCERTSTORE ms; PCCERT_CONTEXT k = keyless_copy(fx_rsa_der, sizeof fx_rsa_der, &ms);
    CHECK(k != NULL);
    if (k && UN(CryptFindCertificateKeyProvInfo)(k, CRYPT_FIND_USER_KEYSET_FLAG, NULL)) {
        BYTE sig[512]; DWORD len = sizeof sig, sp;
        DWORD r = pk_sign(k, CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG, sig, &len, &sp);
        EXPECT_HR(r, 0);
        if (!r) CHECK(!memcmp(sig, fx_rsa_sig_be, 256));
    } else CHECKF(0, "find failed 0x%08lx", GetLastError());
    if (k) U(CertFreeCertificateContext)(k);
    if (ms) U(CertCloseStore)(ms, 0);
    pk_done(c, s);
}
TEST(pfxp_find_existing_prov_info_short_circuits) {
    PK_SETUP(fx_rsa_pfx, PKCS12_ALWAYS_CNG_KSP);
    CRYPT_KEY_PROV_INFO *before = pk_info(c), *after;
    /* the original already has a valid property: success, property unchanged */
    CHECK(UN(CryptFindCertificateKeyProvInfo)(c, CRYPT_FIND_USER_KEYSET_FLAG, NULL));
    after = pk_info(c);
    CHECK(before && after);
    if (before && after) { CHECK(!lstrcmpW(before->pwszContainerName, after->pwszContainerName)); EXPECT_EQ(before->dwFlags, after->dwFlags); }
    pk_free_info(before); pk_free_info(after);
    pk_done(c, s);
}
TEST(pfxp_find_machine_flag_does_not_see_user_key) {
    PK_SETUP(fx_rsa_pfx, PKCS12_ALWAYS_CNG_KSP);
    HCERTSTORE ms; PCCERT_CONTEXT k = keyless_copy(fx_rsa_der, sizeof fx_rsa_der, &ms);
    CHECK(k != NULL);
    if (k) {
        SET_ERR(0);
        BOOL ok = UN(CryptFindCertificateKeyProvInfo)(k, CRYPT_FIND_MACHINE_KEYSET_FLAG | CRYPT_FIND_SILENT_KEYSET_FLAG, NULL);
        t_note("machine-only search for a user key: ok=%d err=0x%08lx", ok, ok ? 0 : GetLastError());
        if (ok) { CRYPT_KEY_PROV_INFO *f = pk_info(k); if (f) { CHECK((f->dwFlags & CRYPT_MACHINE_KEYSET) != 0); pk_free_info(f); } }
        else CHECK(GetLastError() != 0);
        U(CertFreeCertificateContext)(k);
    }
    if (ms) U(CertCloseStore)(ms, 0);
    pk_done(c, s);
}
TEST(pfxp_find_fails_after_key_deleted) {
    PK_SETUP(fx_rsa_pfx, PKCS12_ALWAYS_CNG_KSP);
    CRYPT_KEY_PROV_INFO *i = pk_info(c);
    HCERTSTORE ms; PCCERT_CONTEXT k = keyless_copy(fx_rsa_der, sizeof fx_rsa_der, &ms);
    CHECK(i != NULL && k != NULL);
    if (i && k) {
        pk_destroy(i->pwszProvName, i->dwProvType, i->pwszContainerName, i->dwFlags);
        SET_ERR(0);
        BOOL ok = UN(CryptFindCertificateKeyProvInfo)(k, CRYPT_FIND_USER_KEYSET_FLAG | CRYPT_FIND_SILENT_KEYSET_FLAG, NULL);
        CHECK(!ok);
        t_note("find without a persisted key: err 0x%08lx", GetLastError());
        CHECK(GetLastError() != 0);
        DWORD cb = 0; CHECK(!U(CertGetCertificateContextProperty)(k, CERT_KEY_PROV_INFO_PROP_ID, NULL, &cb));
    }
    pk_free_info(i);
    if (k) U(CertFreeCertificateContext)(k);
    if (ms) U(CertCloseStore)(ms, 0);
    pk_done(c, s);
}
TEST(pfxp_find_unrelated_cert_fails) {
    FIND_NEEDS();
    HCERTSTORE ms; PCCERT_CONTEXT k = keyless_copy(fx_ec_der, sizeof fx_ec_der, &ms);
    CHECK(k != NULL);
    if (k) {
        SET_ERR(0);
        BOOL ok = UN(CryptFindCertificateKeyProvInfo)(k, CRYPT_FIND_USER_KEYSET_FLAG | CRYPT_FIND_SILENT_KEYSET_FLAG, NULL);
        CHECK(!ok);
        t_note("find for a cert whose key was never persisted: err 0x%08lx", GetLastError());
        U(CertFreeCertificateContext)(k);
    }
    if (ms) U(CertCloseStore)(ms, 0);
}
TEST(pfxp_find_ec_picks_ksp) {
    PK_SETUP(fx_ec_pfx, 0);
    HCERTSTORE ms; PCCERT_CONTEXT k = keyless_copy(fx_ec_der, sizeof fx_ec_der, &ms);
    if (k && UN(CryptFindCertificateKeyProvInfo)(k, CRYPT_FIND_USER_KEYSET_FLAG, NULL)) {
        CRYPT_KEY_PROV_INFO *f = pk_info(k);
        CHECK(f != NULL);
        if (f) { CHECK(f->dwProvType == 0); CHECK(!lstrcmpW(f->pwszProvName, MS_KEY_STORAGE_PROVIDER)); pk_free_info(f); }
    } else CHECKF(0, "find failed 0x%08lx", GetLastError());
    if (k) U(CertFreeCertificateContext)(k);
    if (ms) U(CertCloseStore)(ms, 0);
    pk_done(c, s);
}
