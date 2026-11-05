#include "pp.h"

#define NEED_IMPORT() do { REQUIRE(U(PFXImportCertStore)); REQUIRE(U(CertEnumCertificatesInStore)); REQUIRE(U(CertCloseStore)); } while (0)

/* ---- argument validation ------------------------------------------------- */
TEST(pfximport_null_blob_is_invalid_parameter) {
    PP_WINE_SKIP("null blob accepted");
    NEED_IMPORT();
    SET_ERR(0);
    HCERTSTORE s = U(PFXImportCertStore)(NULL, L"test", PP_NP);
    EXPECT_FAIL(s == NULL, ERROR_INVALID_PARAMETER);
    pp_close(s);
}
TEST(pfximport_null_blob_null_password_flags0) {
    PP_WINE_SKIP("null blob accepted");
    NEED_IMPORT();
    SET_ERR(0);
    HCERTSTORE s = U(PFXImportCertStore)(NULL, NULL, 0);
    EXPECT_FAIL(s == NULL, ERROR_INVALID_PARAMETER);
    pp_close(s);
}
TEST(pfximport_reserved_flag_bits_are_invalid_parameter) {
    PP_WINE_SKIP("flags");
    NEED_IMPORT();
    /* mask of rejected bits taken from the import routine: 0xefee208c */
    static const DWORD bad[] = {0x4, 0x8, 0x80, 0x2000, 0x20000, 0x40000, 0x80000, 0x200000, 0x400000,
        0x800000, 0x1000000, 0x2000000, 0x4000000, 0x8000000, 0x20000000, 0x40000000, 0x80000000};
    for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) {
        SET_ERR(0);
        HCERTSTORE s = pp_import(fx_leg3des, sizeof fx_leg3des, L"test", PP_NP | bad[i]);
        CHECKF(s == NULL, "flag 0x%lx", bad[i]);
        EXPECT_ERR(ERROR_INVALID_PARAMETER);
        pp_close(s);
    }
}
TEST(pfximport_invalid_flag_checked_before_password) {
    PP_WINE_SKIP("flags");
    NEED_IMPORT();
    SET_ERR(0);
    HCERTSTORE s = pp_import(fx_leg3des, sizeof fx_leg3des, L"wrong password", PP_NP | 0x4);
    CHECK(s == NULL);
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
    pp_close(s);
}
TEST(pfximport_invalid_flag_checked_before_blob_parse) {
    PP_WINE_SKIP("flags");
    NEED_IMPORT();
    static const BYTE g[] = {1, 2, 3};
    SET_ERR(0);
    HCERTSTORE s = pp_import(g, sizeof g, L"x", 0x80);
    CHECK(s == NULL);
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
}
TEST(pfximport_garbage_blob_fails) {
    NEED_IMPORT();
    static const BYTE g[] = {1, 2, 3, 4, 5, 6, 7, 8, 9};
    SET_ERR(0);
    HCERTSTORE s = pp_import(g, sizeof g, L"test", PP_NP);
    CHECK(s == NULL);
    EXPECT_ERR(CRYPT_E_BAD_ENCODE);
    pp_close(s);
}
TEST(pfximport_empty_blob_fails) {
    NEED_IMPORT();
    CRYPT_DATA_BLOB b = {0, NULL};
    SET_ERR(0);
    HCERTSTORE s = U(PFXImportCertStore)(&b, L"test", PP_NP);
    CHECK(s == NULL);
    EXPECT_ERR(CRYPT_E_BAD_ENCODE);
    pp_close(s);
}
TEST(pfximport_certificate_der_is_not_a_pfx) {
    NEED_IMPORT();
    SET_ERR(0);
    HCERTSTORE s = pp_import(fx_cert1, sizeof fx_cert1, L"test", PP_NP);
    CHECK(s == NULL);
    EXPECT_ERR(CRYPT_E_BAD_ENCODE);
    pp_close(s);
}

/* ---- password handling --------------------------------------------------- */
TEST(pfximport_right_password_one_cert) {
    NEED_IMPORT();
    HCERTSTORE s = PP_IMPORT(fx_leg3des, L"test", PP_NP);
    CHECKF(s != NULL, "err %lu", GetLastError());
    if (!s) return;
    EXPECT_EQ(pp_count(s), 1);
    pp_close(s);
}
TEST(pfximport_wrong_password_is_invalid_password) {
    PP_WINE_SKIP("error mapping");
    NEED_IMPORT();
    SET_ERR(0);
    HCERTSTORE s = PP_IMPORT(fx_leg3des, L"wrong", PP_NP);
    EXPECT_FAIL(s == NULL, PP_ERR_INVALID_PASSWORD);
    pp_close(s);
}
TEST(pfximport_null_password_on_protected_pfx_fails) {
    PP_WINE_SKIP("error mapping");
    NEED_IMPORT();
    SET_ERR(0);
    HCERTSTORE s = PP_IMPORT(fx_leg3des, NULL, PP_NP);
    EXPECT_FAIL(s == NULL, PP_ERR_INVALID_PASSWORD);
    pp_close(s);
}
TEST(pfximport_empty_password_on_protected_pfx_fails) {
    PP_WINE_SKIP("error mapping");
    NEED_IMPORT();
    SET_ERR(0);
    HCERTSTORE s = PP_IMPORT(fx_leg3des, L"", PP_NP);
    EXPECT_FAIL(s == NULL, PP_ERR_INVALID_PASSWORD);
    pp_close(s);
}
TEST(pfximport_password_is_case_sensitive) {
    PP_WINE_SKIP("error mapping");
    NEED_IMPORT();
    SET_ERR(0);
    HCERTSTORE s = PP_IMPORT(fx_leg3des, L"Test", PP_NP);
    EXPECT_FAIL(s == NULL, PP_ERR_INVALID_PASSWORD);
    pp_close(s);
}
TEST(pfximport_empty_password_pfx_null_password) {
    NEED_IMPORT();
    HCERTSTORE s = PP_IMPORT(fx_legempty, NULL, PP_NP);
    CHECKF(s != NULL, "err %lu", GetLastError());
    if (s) EXPECT_EQ(pp_count(s), 1);
    pp_close(s);
}
TEST(pfximport_empty_password_pfx_empty_string) {
    NEED_IMPORT();
    HCERTSTORE s = PP_IMPORT(fx_legempty, L"", PP_NP);
    CHECKF(s != NULL, "err %lu", GetLastError());
    if (s) EXPECT_EQ(pp_count(s), 1);
    pp_close(s);
}
TEST(pfximport_empty_password_pfx_nonempty_password) {
    PP_WINE_SKIP("error mapping");
    NEED_IMPORT();
    SET_ERR(0);
    HCERTSTORE s = PP_IMPORT(fx_legempty, L"something", PP_NP);
    EXPECT_FAIL(s == NULL, PP_ERR_INVALID_PASSWORD);
    pp_close(s);
}
TEST(pfximport_32_char_password) {
    PP_WINE_SKIP("error mapping");
    NEED_IMPORT();
    HCERTSTORE s = PP_IMPORT(fx_leg32, L"abcdefghijklmnopqrstuvwxyz012345", PP_NP);
    CHECKF(s != NULL, "err %lu", GetLastError());
    pp_close(s);
    SET_ERR(0);
    s = PP_IMPORT(fx_leg32, L"abcdefghijklmnopqrstuvwxyz01234", PP_NP);
    EXPECT_FAIL(s == NULL, PP_ERR_INVALID_PASSWORD);
    pp_close(s);
}
TEST(pfximport_long_password_prefix_is_not_retried) {
    NEED_IMPORT();
    /* Win10 22H2: a password longer than 32 characters is NOT retried truncated; the import is rejected as a bad password */
    SET_ERR(0);
    HCERTSTORE s = PP_IMPORT(fx_leg32, L"abcdefghijklmnopqrstuvwxyz012345TAIL", PP_NP);
    CHECK(s == NULL);
    EXPECT_ERR(PP_ERR_INVALID_PASSWORD);
    pp_close(s);
}
TEST(pfximport_wrong_password_repeated_is_stable) {
    PP_WINE_SKIP("error mapping");
    NEED_IMPORT();
    for (int i = 0; i < 5; i++) {
        SET_ERR(0);
        HCERTSTORE s = PP_IMPORT(fx_leg3des, L"bad", PP_NP);
        CHECK(s == NULL);
        EXPECT_ERR(PP_ERR_INVALID_PASSWORD);
    }
    HCERTSTORE s = PP_IMPORT(fx_leg3des, L"test", PP_NP);
    CHECK(s != NULL);
    pp_close(s);
}

/* ---- imported content ---------------------------------------------------- */
TEST(pfximport_cert_bytes_match_source) {
    NEED_IMPORT();
    HCERTSTORE s = PP_IMPORT(fx_leg3des, L"test", PP_NP);
    if (!s) { CHECK(s != NULL); return; }
    PCCERT_CONTEXT c = pp_find_der(s, fx_cert1, sizeof fx_cert1);
    CHECK(c != NULL);
    if (c) { EXPECT_EQ(c->dwCertEncodingType & X509_ASN_ENCODING, X509_ASN_ENCODING); U(CertFreeCertificateContext)(c); }
    pp_close(s);
}
TEST(pfximport_friendly_name_preserved) {
    PP_WINE_SKIP("friendly names");
    NEED_IMPORT();
    HCERTSTORE s = PP_IMPORT(fx_leg3des, L"test", PP_NP);
    if (!s) { CHECK(s != NULL); return; }
    PCCERT_CONTEXT c = U(CertEnumCertificatesInStore)(s, NULL);
    CHECK(c != NULL);
    if (c) { CHECK(pp_has_friendly(c, L"cryptt friendly")); U(CertFreeCertificateContext)(c); }
    pp_close(s);
}
TEST(pfximport_cert_only_pfx_has_no_key_props) {
    PP_WINE_SKIP("cert-only pfx");
    NEED_IMPORT();
    HCERTSTORE s = PP_IMPORT(fx_legcert, L"test", PP_NP);
    if (!s) { CHECK(s != NULL); return; }
    EXPECT_EQ(pp_count(s), 1);
    PCCERT_CONTEXT c = U(CertEnumCertificatesInStore)(s, NULL);
    if (c) {
        SET_ERR(0);
        CHECK(!pp_has_prop(c, CERT_KEY_PROV_INFO_PROP_ID, NULL));
        EXPECT_ERR(CRYPT_E_NOT_FOUND);
        CHECK(!pp_has_prop(c, CERT_KEY_CONTEXT_PROP_ID, NULL));
        /* this fixture carries no friendly name; Win10 reports the property absent */
        { WCHAR fb[128]; SET_ERR(0); CHECK(!pp_friendly(c, fb, 128)); EXPECT_ERR(CRYPT_E_NOT_FOUND); }
        U(CertFreeCertificateContext)(c);
    }
    pp_close(s);
}
TEST(pfximport_two_certs_in_one_pfx) {
    PP_WINE_SKIP("multi-cert friendly names");
    NEED_IMPORT();
    HCERTSTORE s = PP_IMPORT(fx_legtwo, L"test", PP_NP);
    if (!s) { CHECK(s != NULL); return; }
    EXPECT_EQ(pp_count(s), 2);
    PCCERT_CONTEXT a = pp_find_der(s, fx_cert1, sizeof fx_cert1);
    PCCERT_CONTEXT b = pp_find_der(s, fx_cert2, sizeof fx_cert2);
    CHECK(a != NULL); CHECK(b != NULL);
    if (b) {
        /* only the leaf has a key */
        CHECK(!pp_has_prop(b, CERT_KEY_PROV_INFO_PROP_ID, NULL));
        CHECK(!pp_has_prop(b, CERT_KEY_CONTEXT_PROP_ID, NULL));
        U(CertFreeCertificateContext)(b);
    }
    if (a) { CHECK(pp_has_friendly(a, L"cryptt friendly")); U(CertFreeCertificateContext)(a); }
    pp_close(s);
}
TEST(pfximport_rc2_encrypted_certs) {
    PP_WINE_SKIP("rc2");
    NEED_IMPORT();
    HCERTSTORE s = PP_IMPORT(fx_legrc2, L"test", PP_NP);
    CHECKF(s != NULL, "err %lu", GetLastError());
    if (s) { EXPECT_EQ(pp_count(s), 1); CHECK(pp_find_der(s, fx_cert1, sizeof fx_cert1) != NULL); }
    pp_close(s);
}
TEST(pfximport_unencrypted_cert_bag) {
    PP_WINE_SKIP("plain bag");
    NEED_IMPORT();
    HCERTSTORE s = PP_IMPORT(fx_legplaincert, L"test", PP_NP);
    CHECKF(s != NULL, "err %lu", GetLastError());
    if (s) EXPECT_EQ(pp_count(s), 1);
    pp_close(s);
}
TEST(pfximport_pbes2_aes_fixture_imports) {
    PP_WINE_SKIP("pbes2");
    NEED_IMPORT();
    SET_ERR(0);
    HCERTSTORE s = PP_IMPORT(fx_pbes2, L"test", PP_NP);
    CHECKF(s != NULL, "err %lu", GetLastError());
    if (s) { EXPECT_EQ(pp_count(s), 1); CHECK(pp_find_der(s, fx_cert1, sizeof fx_cert1) != NULL); }
    pp_close(s);
    SET_ERR(0);
    s = PP_IMPORT(fx_pbes2, L"wrong", PP_NP);
    CHECK(s == NULL);
    pp_close(s);
}
TEST(pfximport_store_is_independent_and_closable_twice_imported) {
    NEED_IMPORT();
    HCERTSTORE a = PP_IMPORT(fx_leg3des, L"test", PP_NP);
    HCERTSTORE b = PP_IMPORT(fx_leg3des, L"test", PP_NP);
    CHECK(a != NULL && b != NULL);
    CHECK(a != b);
    pp_close(a);
    if (b) EXPECT_EQ(pp_count(b), 1);
    pp_close(b);
}
TEST(pfximport_store_is_writable_memory_store) {
    PP_WINE_SKIP("cert-only pfx");
    NEED_IMPORT();
    REQUIRE(U(CertAddEncodedCertificateToStore));
    HCERTSTORE s = PP_IMPORT(fx_legcert, L"test", PP_NP);
    if (!s) { CHECK(s != NULL); return; }
    BOOL r = U(CertAddEncodedCertificateToStore)(s, X509_ASN_ENCODING, fx_cert2, sizeof fx_cert2, CERT_STORE_ADD_NEW, NULL);
    CHECK(r);
    EXPECT_EQ(pp_count(s), 2);
    pp_close(s);
}
TEST(pfximport_find_by_sha1_hash_and_subject) {
    PP_WINE_SKIP("find flags");
    NEED_IMPORT();
    REQUIRE(U(CertFindCertificateInStore)); REQUIRE(U(CryptHashCertificate));
    HCERTSTORE s = PP_IMPORT(fx_leg3des, L"test", PP_NP);
    if (!s) { CHECK(s != NULL); return; }
    BYTE h[20]; DWORD cb = sizeof h;
    CHECK(U(CryptHashCertificate)(0, CALG_SHA1, 0, fx_cert1, sizeof fx_cert1, h, &cb));
    CRYPT_HASH_BLOB hb = {sizeof h, h};
    PCCERT_CONTEXT c = U(CertFindCertificateInStore)(s, X509_ASN_ENCODING, 0, CERT_FIND_SHA1_HASH, &hb, NULL);
    CHECK(c != NULL);
    if (c) U(CertFreeCertificateContext)(c);
    h[0] ^= 1;
    SET_ERR(0);
    c = U(CertFindCertificateInStore)(s, X509_ASN_ENCODING, 0, CERT_FIND_SHA1_HASH, &hb, NULL);
    EXPECT_FAIL(c == NULL, CRYPT_E_NOT_FOUND);
    c = U(CertFindCertificateInStore)(s, X509_ASN_ENCODING, 0, CERT_FIND_SUBJECT_STR_W, L"cryptt pfx leaf", NULL);
    CHECK(c != NULL);
    if (c) U(CertFreeCertificateContext)(c);
    c = U(CertFindCertificateInStore)(s, X509_ASN_ENCODING, 0, CERT_FIND_HAS_PRIVATE_KEY, NULL, NULL);
    CHECK(c != NULL);
    if (c) U(CertFreeCertificateContext)(c);
    pp_close(s);
}
TEST(pfximport_find_has_private_key_absent_for_cert_only) {
    PP_WINE_SKIP("cert-only pfx");
    NEED_IMPORT();
    REQUIRE(U(CertFindCertificateInStore));
    HCERTSTORE s = PP_IMPORT(fx_legcert, L"test", PP_NP);
    if (!s) { CHECK(s != NULL); return; }
    SET_ERR(0);
    PCCERT_CONTEXT c = U(CertFindCertificateInStore)(s, X509_ASN_ENCODING, 0, CERT_FIND_HAS_PRIVATE_KEY, NULL, NULL);
    EXPECT_FAIL(c == NULL, CRYPT_E_NOT_FOUND);
    pp_close(s);
}

/* ---- key properties with PKCS12_NO_PERSIST_KEY ------------------------------ */
static PCCERT_CONTEXT import_leaf(HCERTSTORE *ps, DWORD flags) {
    *ps = PP_IMPORT(fx_leg3des, L"test", flags);
    if (!*ps) return NULL;
    return pp_find_der(*ps, fx_cert1, sizeof fx_cert1);
}
TEST(pfximport_nopersist_sets_key_context) {
    NEED_IMPORT();
    HCERTSTORE s; PCCERT_CONTEXT c = import_leaf(&s, PP_NP);
    CHECKF(c != NULL, "err %lu", GetLastError());
    if (c) {
        CERT_KEY_CONTEXT kc; DWORD cb = sizeof kc; memset(&kc, 0, sizeof kc);
        BOOL r = U(CertGetCertificateContextProperty)(c, CERT_KEY_CONTEXT_PROP_ID, &kc, &cb);
        CHECKF(r, "err %lu", GetLastError());
        if (r) {
            EXPECT_EQ(kc.cbSize, sizeof(CERT_KEY_CONTEXT));
            CHECK(kc.hCryptProv != 0);
            EXPECT_EQ(kc.dwKeySpec, AT_KEYEXCHANGE);
        }
        U(CertFreeCertificateContext)(c);
    }
    pp_close(s);
}
TEST(pfximport_nopersist_has_no_key_prov_info) {
    NEED_IMPORT();
    HCERTSTORE s; PCCERT_CONTEXT c = import_leaf(&s, PP_NP);
    CHECKF(c != NULL, "err %lu", GetLastError());
    if (c) {
        DWORD cb = 0;
        BOOL r = pp_has_prop(c, CERT_KEY_PROV_INFO_PROP_ID, &cb);
        EXPECT_EQ(r, 0);              /* no persisted key: only the key-context property is set */
        EXPECT_EQ(cb, 0);
        U(CertFreeCertificateContext)(c);
    }
    pp_close(s);
}
TEST(pfximport_nopersist_exportable_flag_combo) {
    PP_WINE_SKIP("flags");
    NEED_IMPORT();
    HCERTSTORE s; PCCERT_CONTEXT c = import_leaf(&s, PP_NP | CRYPT_EXPORTABLE);
    CHECKF(c != NULL, "err %lu", GetLastError());
    if (c) { CHECK(pp_has_prop(c, CERT_KEY_CONTEXT_PROP_ID, NULL)); CHECK(!pp_has_prop(c, CERT_KEY_PROV_INFO_PROP_ID, NULL)); U(CertFreeCertificateContext)(c); }
    pp_close(s);
}
TEST(pfximport_nopersist_user_keyset_combo) {
    PP_WINE_SKIP("flags");
    NEED_IMPORT();
    HCERTSTORE s; PCCERT_CONTEXT c = import_leaf(&s, PP_NP | CRYPT_USER_KEYSET);
    CHECKF(c != NULL, "err %lu", GetLastError());
    if (c) U(CertFreeCertificateContext)(c);
    pp_close(s);
}
TEST(pfximport_nopersist_always_cng_ksp) {
    PP_WINE_SKIP("flags");
    NEED_IMPORT();
    HCERTSTORE s; PCCERT_CONTEXT c = import_leaf(&s, PP_NP | PKCS12_ALWAYS_CNG_KSP);
    CHECKF(c != NULL, "err %lu", GetLastError());
    if (c) {
        CERT_KEY_CONTEXT kc; DWORD cb = sizeof kc; memset(&kc, 0, sizeof kc);
        if (U(CertGetCertificateContextProperty)(c, CERT_KEY_CONTEXT_PROP_ID, &kc, &cb)) {
            EXPECT_EQ(kc.dwKeySpec, CERT_NCRYPT_KEY_SPEC);
            CHECK(kc.hNCryptKey != 0);
        } else CHECKF(0, "no key context with ALWAYS_CNG_KSP, err %lu", GetLastError());
        U(CertFreeCertificateContext)(c);
    }
    pp_close(s);
}
TEST(pfximport_nopersist_prefer_cng_ksp) {
    PP_WINE_SKIP("flags");
    NEED_IMPORT();
    HCERTSTORE s; PCCERT_CONTEXT c = import_leaf(&s, PP_NP | PKCS12_PREFER_CNG_KSP);
    CHECKF(c != NULL, "err %lu", GetLastError());
    if (c) { CHECK(pp_has_prop(c, CERT_KEY_CONTEXT_PROP_ID, NULL)); CHECK(!pp_has_prop(c, CERT_KEY_PROV_INFO_PROP_ID, NULL)); U(CertFreeCertificateContext)(c); }
    pp_close(s);
}
TEST(pfximport_nopersist_allow_overwrite_flag) {
    PP_WINE_SKIP("flags");
    NEED_IMPORT();
    HCERTSTORE s; PCCERT_CONTEXT c = import_leaf(&s, PP_NP | PKCS12_ALLOW_OVERWRITE_KEY);
    CHECKF(c != NULL, "err %lu", GetLastError());
    if (c) U(CertFreeCertificateContext)(c);
    pp_close(s);
}
TEST(pfximport_include_extended_properties_flag) {
    PP_WINE_SKIP("flags");
    NEED_IMPORT();
    HCERTSTORE s; PCCERT_CONTEXT c = import_leaf(&s, PP_NP | PKCS12_INCLUDE_EXTENDED_PROPERTIES);
    CHECKF(c != NULL, "err %lu", GetLastError());
    if (c) { CHECK(pp_has_friendly(c, L"cryptt friendly")); U(CertFreeCertificateContext)(c); }
    pp_close(s);
}
TEST(pfximport_user_protected_flag_silent) {
    PP_WINE_SKIP("flags");
    NEED_IMPORT();
    /* CRYPT_USER_PROTECTED with no-persist: no key is stored, so no UI protection can be requested */
    HCERTSTORE s = PP_IMPORT(fx_leg3des, L"test", PP_NP | CRYPT_USER_PROTECTED);
    CHECKF(s != NULL, "err %lu", GetLastError());
    pp_close(s);
}
TEST(pfximport_machine_keyset_nopersist) {
    PP_WINE_SKIP("flags");
    NEED_IMPORT();
    HCERTSTORE s = PP_IMPORT(fx_leg3des, L"test", PP_NP | CRYPT_MACHINE_KEYSET);
    CHECKF(s != NULL, "err %lu", GetLastError());
    pp_close(s);
}
TEST(pfximport_virtual_isolation_flag_accepted) {
    PP_WINE_SKIP("flags");
    NEED_IMPORT();
    HCERTSTORE s = PP_IMPORT(fx_legcert, L"test", PP_NP | PKCS12_VIRTUAL_ISOLATION_KEY);
    CHECKF(s != NULL, "err %lu", GetLastError());
    pp_close(s);
}

/* ---- PKCS12_ONLY_CERTIFICATES ------------------------------------------------ */
TEST(pfximport_only_certificates_ignores_keys) {
    PP_WINE_SKIP("flags");
    NEED_IMPORT();
    HCERTSTORE s = PP_IMPORT(fx_leg3des, L"test", PKCS12_ONLY_CERTIFICATES | PKCS12_IMPORT_SILENT);
    CHECKF(s != NULL, "err %lu", GetLastError());
    if (s) {
        PCCERT_CONTEXT c = pp_find_der(s, fx_cert1, sizeof fx_cert1);
        CHECK(c != NULL);
        if (c) {
            DWORD cb;
            BOOL r = pp_has_prop(c, CERT_KEY_PROV_INFO_PROP_ID, &cb);
            EXPECT_EQ(r, 1);          /* observed: the key provider info is still attached although keys are not imported */
            U(CertFreeCertificateContext)(c);
        }
    }
    pp_close(s);
}
TEST(pfximport_only_certificates_wrong_password_still_reads_plain_bag) {
    PP_WINE_SKIP("flags");
    NEED_IMPORT();
    /* with ONLY_CERTIFICATES the routine first tries the unencrypted-certificates path (observed) */
    HCERTSTORE s = PP_IMPORT(fx_legplaincert, L"definitely wrong", PKCS12_ONLY_CERTIFICATES | PKCS12_IMPORT_SILENT);
    CHECKF(s != NULL, "err %lu", GetLastError());
    EXPECT_EQ(pp_count(s), 1);
    pp_close(s);
}
TEST(pfximport_only_not_encrypted_certificates_plain_bag) {
    PP_WINE_SKIP("flags");
    NEED_IMPORT();
    HCERTSTORE s = PP_IMPORT(fx_legplaincert, NULL, PKCS12_ONLY_NOT_ENCRYPTED_CERTIFICATES | PKCS12_IMPORT_SILENT);
    CHECKF(s != NULL, "err %lu", GetLastError());
    if (s) { EXPECT_EQ(pp_count(s), 1); CHECK(pp_find_der(s, fx_cert1, sizeof fx_cert1) != NULL); }
    pp_close(s);
}
TEST(pfximport_only_not_encrypted_certificates_encrypted_bag) {
    PP_WINE_SKIP("flags");
    NEED_IMPORT();
    SET_ERR(0);
    HCERTSTORE s = PP_IMPORT(fx_leg3des, NULL, PKCS12_ONLY_NOT_ENCRYPTED_CERTIFICATES | PKCS12_IMPORT_SILENT);
    CHECK(s == NULL);
    EXPECT_ERR(CRYPT_E_NOT_FOUND);
    pp_close(s);
}

/* ---- I_PFXImportCertStoreEx --------------------------------------------------- */
TEST(pfximport_internal_ex_resolves) {
    PP_WINE_SKIP("internal exports absent");
    CHECK(t_proc_in("crypt32.dll", "I_PFXImportCertStoreEx") != NULL);
    CHECK(t_proc_in("crypt32.dll", "I_PFXHMAC") != NULL);
    CHECK(t_proc_in("crypt32.dll", "I_PFXDecrypt") != NULL);
    CHECK(t_proc_in("crypt32.dll", "PFXExportCertStore2") != NULL);
}
TEST(pfximport_internal_ex_matches_public_api) {
    REQUIRE(UN(I_PFXImportCertStoreEx)); REQUIRE(U(CertEnumCertificatesInStore));
    CRYPT_DATA_BLOB b = pp_blob_of(fx_leg3des, sizeof fx_leg3des);
    HCERTSTORE s = UN(I_PFXImportCertStoreEx)(NULL, &b, L"test", PP_NP, NULL);
    CHECKF(s != NULL, "err %lu", GetLastError());
    if (s) EXPECT_EQ(pp_count(s), 1);
    pp_close(s);
}
TEST(pfximport_internal_ex_reserved_pointer_must_be_null) {
    REQUIRE(UN(I_PFXImportCertStoreEx));
    CRYPT_DATA_BLOB b = pp_blob_of(fx_leg3des, sizeof fx_leg3des);
    int dummy;
    SET_ERR(0);
    HCERTSTORE s = UN(I_PFXImportCertStoreEx)(NULL, &b, L"test", PP_NP, &dummy);
    EXPECT_FAIL(s == NULL, ERROR_INVALID_PARAMETER);
}
TEST(pfximport_internal_ex_verify_only_returns_boolean) {
    REQUIRE(UN(I_PFXImportCertStoreEx));
    /* flag 0x10000000 (the PFXVerifyPassword path) returns 1 / NULL, not a store */
    CRYPT_DATA_BLOB b = pp_blob_of(fx_leg3des, sizeof fx_leg3des);
    HCERTSTORE r = UN(I_PFXImportCertStoreEx)(NULL, &b, L"test", PP_VERIFY_ONLY, NULL);
    EXPECT_EQ((ULONG_PTR)r, 1);
    SET_ERR(0);
    r = UN(I_PFXImportCertStoreEx)(NULL, &b, L"bad", PP_VERIFY_ONLY, NULL);
    EXPECT_FAIL(r == NULL, PP_ERR_INVALID_PASSWORD);
}
TEST(pfximport_internal_ex_null_blob) {
    REQUIRE(UN(I_PFXImportCertStoreEx));
    SET_ERR(0);
    HCERTSTORE s = UN(I_PFXImportCertStoreEx)(NULL, NULL, L"test", PP_NP, NULL);
    EXPECT_FAIL(s == NULL, ERROR_INVALID_PARAMETER);
}
