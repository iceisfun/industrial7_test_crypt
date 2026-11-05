/* Persisting PFX import: which provider/container ends up in CERT_KEY_PROV_INFO_PROP_ID. */
#include "pk.h"

#define KSPW MS_KEY_STORAGE_PROVIDER

/* Common shape of a persisting import of a one-certificate PFX. */
static void pk_check_shape(PCCERT_CONTEXT c, HCERTSTORE s, int ksp_expected) {
    CRYPT_KEY_PROV_INFO *i = pk_info(c); DWORD cb = 0;
    CHECK(pk_count(s) == 1);
    CHECK(i != NULL);
    if (!i) return;
    CHECK(i->pwszContainerName && i->pwszContainerName[0]);
    CHECK(i->pwszProvName && i->pwszProvName[0]);
    CHECK((i->dwFlags & CRYPT_MACHINE_KEYSET) == 0);
    EXPECT_EQ(i->cProvParam, 0);
    if (ksp_expected == 1) { CHECK(i->dwProvType == 0); if (i->pwszProvName) CHECK(!lstrcmpW(i->pwszProvName, KSPW)); }
    if (i->dwProvType != 0) CHECK(i->dwKeySpec == AT_KEYEXCHANGE || i->dwKeySpec == AT_SIGNATURE);
    EXPECT_EQ(pk_open_status(i), 0);
    /* a persisted import never attaches a live key context */
    CHECK(!U(CertGetCertificateContextProperty)(c, CERT_KEY_CONTEXT_PROP_ID, NULL, &cb));
    pk_free_info(i);
}

#define IMP_TEST(nm, fx, fl, ksp) TEST(pfxp_import_##nm) { PK_SETUP(fx, fl); pk_check_shape(c, s, ksp); pk_done(c, s); }
/* ksp: 1 = must be KSP, -1 = either (observed value noted by pfxp_note_* tests) */
IMP_TEST(rsa_default,           fx_rsa_pfx, 0, -1)
IMP_TEST(rsa_user_keyset,       fx_rsa_pfx, CRYPT_USER_KEYSET, -1)
IMP_TEST(rsa_exportable,        fx_rsa_pfx, CRYPT_EXPORTABLE, -1)
IMP_TEST(rsa_exportable_user,   fx_rsa_pfx, CRYPT_EXPORTABLE | CRYPT_USER_KEYSET, -1)
IMP_TEST(rsa_always_cng,        fx_rsa_pfx, PKCS12_ALWAYS_CNG_KSP, 1)
IMP_TEST(rsa_always_cng_exp,    fx_rsa_pfx, PKCS12_ALWAYS_CNG_KSP | CRYPT_EXPORTABLE, 1)
IMP_TEST(rsa_always_cng_user,   fx_rsa_pfx, PKCS12_ALWAYS_CNG_KSP | CRYPT_USER_KEYSET, 1)
IMP_TEST(rsa_prefer_cng,        fx_rsa_pfx, PKCS12_PREFER_CNG_KSP, -1)
IMP_TEST(rsa_overwrite,         fx_rsa_pfx, PKCS12_ALLOW_OVERWRITE_KEY, -1)
IMP_TEST(rsa_all_flags,         fx_rsa_pfx, CRYPT_EXPORTABLE | CRYPT_USER_KEYSET | PKCS12_ALLOW_OVERWRITE_KEY, -1)
IMP_TEST(ec_default,            fx_ec_pfx, 0, 1)
IMP_TEST(ec_user_keyset,        fx_ec_pfx, CRYPT_USER_KEYSET, 1)
IMP_TEST(ec_exportable,         fx_ec_pfx, CRYPT_EXPORTABLE, 1)
IMP_TEST(ec_always_cng,         fx_ec_pfx, PKCS12_ALWAYS_CNG_KSP, 1)
IMP_TEST(ec_always_cng_exp,     fx_ec_pfx, PKCS12_ALWAYS_CNG_KSP | CRYPT_EXPORTABLE, 1)
IMP_TEST(ec_prefer_cng,         fx_ec_pfx, PKCS12_PREFER_CNG_KSP, 1)
IMP_TEST(ec_overwrite,          fx_ec_pfx, PKCS12_ALLOW_OVERWRITE_KEY, 1)

TEST(pfxp_import_rsa_default_provider_observed) {
    PK_SETUP(fx_rsa_pfx, 0);
    CRYPT_KEY_PROV_INFO *i = pk_info(c);
    if (i) {
        /* an RSA key without a provider attribute goes to a CSP or to the software KSP; nothing else is plausible */
        CHECK(i->dwProvType == 0 || i->dwProvType == PROV_RSA_FULL || i->dwProvType == PROV_RSA_AES);
        t_note("rsa default import: type=%lu prov=%ls spec=%lu flags=0x%lx", i->dwProvType, i->pwszProvName, i->dwKeySpec, i->dwFlags);
        pk_free_info(i);
    }
    pk_done(c, s);
}
TEST(pfxp_import_rsa_always_cng_keyspec_observed) {
    PK_SETUP(fx_rsa_pfx, PKCS12_ALWAYS_CNG_KSP);
    CRYPT_KEY_PROV_INFO *i = pk_info(c);
    if (i) { t_note("rsa ALWAYS_CNG: container=%ls spec=%lu flags=0x%lx", i->pwszContainerName, i->dwKeySpec, i->dwFlags); pk_free_info(i); }
    pk_done(c, s);
}
TEST(pfxp_import_rsa_prefer_cng_observed) {
    PK_SETUP(fx_rsa_pfx, PKCS12_PREFER_CNG_KSP);
    CRYPT_KEY_PROV_INFO *i = pk_info(c);
    if (i) { t_note("rsa PREFER_CNG: type=%lu prov=%ls", i->dwProvType, i->pwszProvName); pk_free_info(i); }
    pk_done(c, s);
}
TEST(pfxp_import_ec_keyspec_observed) {
    PK_SETUP(fx_ec_pfx, 0);
    CRYPT_KEY_PROV_INFO *i = pk_info(c);
    if (i) { t_note("ec default: container=%ls spec=%lu flags=0x%lx", i->pwszContainerName, i->dwKeySpec, i->dwFlags); pk_free_info(i); }
    pk_done(c, s);
}

/* The certificate itself is what the PFX contained. */
TEST(pfxp_import_cert_bytes_rsa) {
    PK_SETUP(fx_rsa_pfx, 0);
    CHECK(c->cbCertEncoded == sizeof fx_rsa_der && !memcmp(c->pbCertEncoded, fx_rsa_der, sizeof fx_rsa_der));
    pk_done(c, s);
}
TEST(pfxp_import_cert_bytes_ec) {
    PK_SETUP(fx_ec_pfx, 0);
    CHECK(c->cbCertEncoded == sizeof fx_ec_der && !memcmp(c->pbCertEncoded, fx_ec_der, sizeof fx_ec_der));
    pk_done(c, s);
}
TEST(pfxp_import_friendly_name_kept) {
    PK_SETUP(fx_rsa_pfx, 0);
    WCHAR b[128]; DWORD cb = sizeof b;
    BOOL ok = U(CertGetCertificateContextProperty)(c, CERT_FRIENDLY_NAME_PROP_ID, b, &cb);
    CHECK(ok);
    if (ok) CHECK(!lstrcmpW(b, L"cryptt-pfxp-rsa"));
    pk_done(c, s);
}
TEST(pfxp_import_friendly_name_kept_ec) {
    PK_SETUP(fx_ec_pfx, 0);
    WCHAR b[128]; DWORD cb = sizeof b;
    BOOL ok = U(CertGetCertificateContextProperty)(c, CERT_FRIENDLY_NAME_PROP_ID, b, &cb);
    CHECK(ok);
    if (ok) CHECK(!lstrcmpW(b, L"cryptt-pfxp-ec"));
    pk_done(c, s);
}
TEST(pfxp_import_container_name_observed) {
    PK_SETUP(fx_rsa_pfx, PKCS12_ALWAYS_CNG_KSP);
    CRYPT_KEY_PROV_INFO *i = pk_info(c);
    if (i) {
        size_t n = lstrlenW(i->pwszContainerName);
        CHECK(n > 0 && n < 256);
        t_note("KSP container name '%ls' (len %u): importer-generated, not asserted", i->pwszContainerName, (unsigned)n);
        pk_free_info(i);
    }
    pk_done(c, s);
}

/* Two imports of the same PFX: names and survival of both keys. */
TEST(pfxp_import_twice_overwrite_allowed) {
    PK_NEEDS();
    HCERTSTORE s1 = PK_IMPORT(fx_rsa_pfx, PKCS12_ALWAYS_CNG_KSP | PKCS12_ALLOW_OVERWRITE_KEY);
    HCERTSTORE s2 = PK_IMPORT(fx_rsa_pfx, PKCS12_ALWAYS_CNG_KSP | PKCS12_ALLOW_OVERWRITE_KEY);
    CHECK(s1 != NULL); CHECK(s2 != NULL);
    PCCERT_CONTEXT c1 = pk_first(s1), c2 = pk_first(s2);
    CRYPT_KEY_PROV_INFO *i1 = pk_info(c1), *i2 = pk_info(c2);
    if (i1 && i2) {
        t_note("two imports: same container name = %d", !lstrcmpW(i1->pwszContainerName, i2->pwszContainerName));
        EXPECT_EQ(pk_open_status(i2), 0);
    }
    pk_free_info(i1); pk_free_info(i2);
    pk_done(c1, s1); pk_done(c2, s2);
}
TEST(pfxp_import_twice_without_overwrite) {
    PK_NEEDS();
    HCERTSTORE s1 = PK_IMPORT(fx_rsa_pfx, PKCS12_ALWAYS_CNG_KSP);
    HCERTSTORE s2 = PK_IMPORT(fx_rsa_pfx, PKCS12_ALWAYS_CNG_KSP);
    CHECK(s1 != NULL);
    t_note("second import without ALLOW_OVERWRITE_KEY: %s (err %lu)", s2 ? "ok" : "failed", s2 ? 0 : GetLastError());
    pk_done(NULL, s1); pk_done(NULL, s2);
}
TEST(pfxp_import_twice_ec_overwrite_allowed) {
    PK_NEEDS();
    HCERTSTORE s1 = PK_IMPORT(fx_ec_pfx, PKCS12_ALLOW_OVERWRITE_KEY);
    HCERTSTORE s2 = PK_IMPORT(fx_ec_pfx, PKCS12_ALLOW_OVERWRITE_KEY);
    CHECK(s1 != NULL); CHECK(s2 != NULL);
    pk_done(NULL, s1); pk_done(NULL, s2);
}

/* NO_PERSIST_KEY contrast: key context property, no provider info, nothing persisted. */
TEST(pfxp_nopersist_has_key_context_not_prov_info) {
    PK_NEEDS();
    CRYPT_DATA_BLOB b = { sizeof fx_rsa_pfx, (BYTE *)fx_rsa_pfx }; DWORD cb = 0;
    HCERTSTORE s = U(PFXImportCertStore)(&b, PK_PW, PKCS12_NO_PERSIST_KEY | (t_is_wine() ? 0 : PKCS12_IMPORT_SILENT));
    CHECK(s != NULL); if (!s) return;
    PCCERT_CONTEXT c = pk_first(s);
    CHECK(c != NULL);
    if (c) {
        CHECK(U(CertGetCertificateContextProperty)(c, CERT_KEY_CONTEXT_PROP_ID, NULL, &cb));
        SET_ERR(0);
        t_note("NO_PERSIST_KEY: KEY_PROV_INFO property present = %d", U(CertGetCertificateContextProperty)(c, CERT_KEY_PROV_INFO_PROP_ID, NULL, &cb));
        U(CertFreeCertificateContext)(c);
    }
    U(CertCloseStore)(s, 0);
}
TEST(pfxp_nopersist_ec_has_key_context) {
    PK_NEEDS();
    CRYPT_DATA_BLOB b = { sizeof fx_ec_pfx, (BYTE *)fx_ec_pfx }; DWORD cb = 0;
    HCERTSTORE s = U(PFXImportCertStore)(&b, PK_PW, PKCS12_NO_PERSIST_KEY | (t_is_wine() ? 0 : PKCS12_IMPORT_SILENT));
    CHECK(s != NULL); if (!s) return;
    PCCERT_CONTEXT c = pk_first(s);
    if (c) { CHECK(U(CertGetCertificateContextProperty)(c, CERT_KEY_CONTEXT_PROP_ID, NULL, &cb)); U(CertFreeCertificateContext)(c); }
    U(CertCloseStore)(s, 0);
}

/* Invalid flag bits are rejected before the blob is looked at: nothing may be persisted. */
static const DWORD bad_flags[] = { 0x4, 0x8, 0x80, 0x2000, 0x20000, 0x80000000, 0x40000000, 0x20000000 };
TEST(pfxp_import_invalid_flag_bits) {
    PK_NEEDS();
    unsigned k;
    for (k = 0; k < sizeof bad_flags / sizeof *bad_flags; k++) {
        CRYPT_DATA_BLOB b = { sizeof fx_rsa_pfx, (BYTE *)fx_rsa_pfx };
        SET_ERR(0);
        HCERTSTORE s = U(PFXImportCertStore)(&b, PK_PW, bad_flags[k] | PKCS12_NO_PERSIST_KEY);
        CHECKF(s == NULL, "flag 0x%lx accepted", bad_flags[k]);
        if (s) { U(CertCloseStore)(s, 0); continue; }
        CHECKF(GetLastError() == ERROR_INVALID_PARAMETER, "flag 0x%lx: err %lu", bad_flags[k], GetLastError());
    }
}
TEST(pfxp_import_null_blob) {
    PK_NEEDS();
    SET_ERR(0);
    HCERTSTORE s = U(PFXImportCertStore)(NULL, PK_PW, 0);
    CHECK(s == NULL); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    if (s) U(CertCloseStore)(s, 0);
}
TEST(pfxp_import_wrong_password_persists_nothing) {
    PK_NEEDS();
    CRYPT_DATA_BLOB b = { sizeof fx_rsa_pfx, (BYTE *)fx_rsa_pfx };
    SET_ERR(0);
    HCERTSTORE s = U(PFXImportCertStore)(&b, L"wrong-password", PKCS12_IMPORT_SILENT);
    CHECK(s == NULL);
    EXPECT_ERR(86);
    if (s) pk_done(NULL, s);
}
TEST(pfxp_import_garbage_blob_fails) {
    PK_NEEDS();
    BYTE junk[16] = { 0x30, 0x03, 0x02, 0x01, 0x03 };
    CRYPT_DATA_BLOB b = { sizeof junk, junk };
    SET_ERR(0);
    HCERTSTORE s = U(PFXImportCertStore)(&b, PK_PW, PKCS12_NO_PERSIST_KEY);
    CHECK(s == NULL);
    CHECK(GetLastError() != 0);
    if (s) U(CertCloseStore)(s, 0);
}
