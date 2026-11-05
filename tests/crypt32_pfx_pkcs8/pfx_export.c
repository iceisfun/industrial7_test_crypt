#include "pp.h"

#define NEED_EXPORT() do { REQUIRE(U(PFXExportCertStoreEx)); REQUIRE(U(PFXExportCertStore)); REQUIRE(U(PFXImportCertStore)); \
    REQUIRE(U(CertEnumCertificatesInStore)); REQUIRE(U(CertCloseStore)); REQUIRE(U(CertOpenStore)); REQUIRE(U(PFXIsPFXBlob)); } while (0)
#define PP_WINE_NO_EXPORT() PP_WINE_SKIP("limited PFX export")

#define E_NTE_NO_KEY        ((DWORD)0x8009000D)
#define E_NTE_BAD_KEY       ((DWORD)0x8009000B)
#define E_NTE_BAD_KEY_STATE ((DWORD)0x8009000C)
#define E_NTE_PERM          ((DWORD)0x80090010)

/* store with the leaf (+ its key) from the 3DES fixture; exportable or not */
static HCERTSTORE leaf_store(int exportable) {
    return PP_IMPORT(fx_leg3des, L"test", PP_NP | (exportable ? CRYPT_EXPORTABLE : 0));
}
static HCERTSTORE cert_only_store(void) {
    HCERTSTORE s = pp_memstore();
    if (s) U(CertAddEncodedCertificateToStore)(s, X509_ASN_ENCODING, fx_cert1, sizeof fx_cert1, CERT_STORE_ADD_NEW, NULL);
    return s;
}
static int reimport_has_key(const CRYPT_DATA_BLOB *b, LPCWSTR pw) {
    HCERTSTORE s = U(PFXImportCertStore)((CRYPT_DATA_BLOB *)b, pw, PP_NP);
    int r = -1;
    if (s) { PCCERT_CONTEXT c = pp_first_with_key(s); r = c != NULL; if (c) U(CertFreeCertificateContext)(c); pp_close(s); }
    return r;
}

/* ---- argument validation -------------------------------------------------- */
TEST(pfxexport_ex_null_store_and_blob) {
    NEED_EXPORT(); PP_WINE_NO_EXPORT();
    SET_ERR(0);
    BOOL r = U(PFXExportCertStoreEx)(NULL, NULL, NULL, NULL, 0);
    EXPECT_FAIL(!r, ERROR_INVALID_PARAMETER);
}
TEST(pfxexport_ex_null_store) {
    NEED_EXPORT(); PP_WINE_NO_EXPORT();
    CRYPT_DATA_BLOB b = {0, NULL};
    SET_ERR(0);
    BOOL r = U(PFXExportCertStoreEx)(NULL, &b, L"x", NULL, 0);
    EXPECT_FAIL(!r, ERROR_INVALID_PARAMETER);
}
TEST(pfxexport_ex_null_blob) {
    NEED_EXPORT(); PP_WINE_NO_EXPORT();
    HCERTSTORE s = pp_memstore();
    SET_ERR(0);
    BOOL r = U(PFXExportCertStoreEx)(s, NULL, L"x", NULL, 0);
    EXPECT_FAIL(!r, ERROR_INVALID_PARAMETER);
    pp_close(s);
}
TEST(pfxexport_legacy_null_args) {
    NEED_EXPORT(); PP_WINE_NO_EXPORT();
    CRYPT_DATA_BLOB b = {0, NULL};
    SET_ERR(0);
    BOOL r = U(PFXExportCertStore)(NULL, &b, L"x", 0);
    EXPECT_FAIL(!r, ERROR_INVALID_PARAMETER);
    HCERTSTORE s = pp_memstore();
    SET_ERR(0);
    r = U(PFXExportCertStore)(s, NULL, L"x", 0);
    EXPECT_FAIL(!r, ERROR_INVALID_PARAMETER);
    pp_close(s);
}
TEST(pfxexport_ex_rejected_flag_bits) {
    NEED_EXPORT(); PP_WINE_NO_EXPORT();
    /* mask 0xcc00 is rejected by the common export routine */
    static const DWORD bad[] = {0x400, 0x800, 0x4000, 0x8000, 0xcc00};
    HCERTSTORE s = pp_memstore();
    for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) {
        CRYPT_DATA_BLOB b = {0, NULL};
        SET_ERR(0);
        BOOL r = U(PFXExportCertStoreEx)(s, &b, L"x", NULL, bad[i]);
        CHECKF(!r, "ex flag 0x%lx", bad[i]);
        EXPECT_ERR(ERROR_INVALID_PARAMETER);
        SET_ERR(0);
        r = U(PFXExportCertStore)(s, &b, L"x", bad[i]);
        CHECKF(!r, "legacy flag 0x%lx", bad[i]);
        EXPECT_ERR(ERROR_INVALID_PARAMETER);
    }
    pp_close(s);
}
TEST(pfxexport_ex_pbes2_unknown_algorithm_not_supported) {
    NEED_EXPORT(); PP_WINE_NO_EXPORT();
    HCERTSTORE s = pp_memstore();
    PKCS12_PBES2_EXPORT_PARAMS p; memset(&p, 0, sizeof p);
    p.dwSize = sizeof p; p.pwszPbes2Alg = (LPWSTR)L"NOT-AN-ALGORITHM";
    CRYPT_DATA_BLOB b = {0, NULL};
    SET_ERR(0);
    BOOL r = U(PFXExportCertStoreEx)(s, &b, L"x", &p, PKCS12_EXPORT_PBES2_PARAMS);
    EXPECT_FAIL(!r, ERROR_NOT_SUPPORTED);
    pp_close(s);
}
TEST(pfxexport_ex_domain_sids_flag_without_descriptor) {
    NEED_EXPORT(); PP_WINE_NO_EXPORT();
    /* PKCS12_PROTECT_TO_DOMAIN_SIDS with no protection descriptor in pvPara -> invalid parameter */
    HCERTSTORE s = pp_memstore();
    CRYPT_DATA_BLOB b = {0, NULL};
    SET_ERR(0);
    BOOL r = U(PFXExportCertStoreEx)(s, &b, L"x", NULL, PKCS12_PROTECT_TO_DOMAIN_SIDS);
    EXPECT_FAIL(!r, ERROR_INVALID_PARAMETER);
    pp_close(s);
}

/* ---- empty store ---------------------------------------------------------- */
TEST(pfxexport_empty_store_size_query) {
    NEED_EXPORT(); PP_WINE_NO_EXPORT();
    HCERTSTORE s = pp_memstore();
    CRYPT_DATA_BLOB b = {0, NULL};
    SET_ERR(0);
    BOOL r = U(PFXExportCertStoreEx)(s, &b, L"pw", NULL, 0);
    t_note("empty store size query: ret=%d err=0x%lx cb=%lu", r, GetLastError(), b.cbData);
    if (r) CHECK(b.cbData > 0);
    pp_close(s);
}
TEST(pfxexport_empty_store_produces_valid_pfx) {
    NEED_EXPORT(); PP_WINE_NO_EXPORT();
    HCERTSTORE s = pp_memstore();
    CRYPT_DATA_BLOB b;
    if (!pp_export_ex(s, &b, L"pw", NULL, 0)) { t_note("empty store export fails: 0x%lx", GetLastError()); pp_close(s); return; }
    if (b.pbData) {
        CHECK(U(PFXIsPFXBlob)(&b));
        if (U(PFXVerifyPassword)) { CHECK(U(PFXVerifyPassword)(&b, L"pw", 0)); CHECK(!U(PFXVerifyPassword)(&b, L"other", 0)); }
        HCERTSTORE s2 = U(PFXImportCertStore)(&b, L"pw", PP_NP);
        t_note("empty pfx re-import: %s (err %lu)", s2 ? "store" : "NULL", GetLastError());
        if (s2) EXPECT_EQ(pp_count(s2), 0);
        pp_close(s2);
        LocalFree(b.pbData);
    }
    pp_close(s);
}
TEST(pfxexport_empty_store_legacy_api) {
    NEED_EXPORT(); PP_WINE_NO_EXPORT();
    HCERTSTORE s = pp_memstore();
    CRYPT_DATA_BLOB b;
    if (pp_export(s, &b, L"pw", 0) && b.pbData) { CHECK(U(PFXIsPFXBlob)(&b)); LocalFree(b.pbData); }
    else t_note("empty store legacy export fails: 0x%lx", GetLastError());
    pp_close(s);
}

/* ---- size protocol ---------------------------------------------------------- */
TEST(pfxexport_ex_size_query_then_fill) {
    NEED_EXPORT(); PP_WINE_NO_EXPORT();
    HCERTSTORE s = leaf_store(1);
    if (!s) { CHECK(s != NULL); return; }
    CRYPT_DATA_BLOB b = {0, NULL};
    BOOL r = U(PFXExportCertStoreEx)(s, &b, L"rt", NULL, EXPORT_PRIVATE_KEYS);
    CHECKF(r, "size query err %lu", GetLastError());
    DWORD need = b.cbData;
    CHECK(need > 100);
    BYTE *buf = (BYTE *)LocalAlloc(LPTR, need + 64);
    memset(buf, 0xAA, need + 64);
    b.pbData = buf; b.cbData = need + 64;
    r = U(PFXExportCertStoreEx)(s, &b, L"rt", NULL, EXPORT_PRIVATE_KEYS);
    CHECKF(r, "fill err %lu", GetLastError());
    CHECK(b.cbData <= need + 64);
    t_note("size query %lu, final %lu", need, b.cbData);
    CHECK(U(PFXIsPFXBlob)(&b));
    /* bytes past the reported length are untouched */
    int untouched = 1;
    for (DWORD i = b.cbData; i < need + 64; i++) if (buf[i] != 0xAA) untouched = 0;
    CHECK(untouched);
    LocalFree(buf);
    pp_close(s);
}
TEST(pfxexport_ex_small_buffer_observed) {
    NEED_EXPORT(); PP_WINE_NO_EXPORT();
    HCERTSTORE s = leaf_store(1);
    if (!s) { CHECK(s != NULL); return; }
    CRYPT_DATA_BLOB b = {0, NULL};
    CHECK(U(PFXExportCertStoreEx)(s, &b, L"rt", NULL, EXPORT_PRIVATE_KEYS));
    DWORD need = b.cbData;
    BYTE *buf = (BYTE *)LocalAlloc(LPTR, need);
    b.pbData = buf; b.cbData = need - 1;
    SET_ERR(0);
    BOOL r = U(PFXExportCertStoreEx)(s, &b, L"rt", NULL, EXPORT_PRIVATE_KEYS);
    t_note("buffer one byte short: ret=%d err=%lu cbData=%lu (need %lu)", r, GetLastError(), b.cbData, need);
    b.cbData = 1;
    SET_ERR(0);
    r = U(PFXExportCertStoreEx)(s, &b, L"rt", NULL, EXPORT_PRIVATE_KEYS);
    t_note("buffer of 1 byte: ret=%d err=%lu cbData=%lu", r, GetLastError(), b.cbData);
    LocalFree(buf);
    pp_close(s);
}
TEST(pfxexport_legacy_size_query_then_fill) {
    NEED_EXPORT(); PP_WINE_NO_EXPORT();
    HCERTSTORE s = leaf_store(1);
    if (!s) { CHECK(s != NULL); return; }
    CRYPT_DATA_BLOB b;
    CHECK(pp_export(s, &b, L"rt", EXPORT_PRIVATE_KEYS));
    if (b.pbData) { CHECK(U(PFXIsPFXBlob)(&b)); LocalFree(b.pbData); }
    pp_close(s);
}

/* ---- passwords ----------------------------------------------------------------- */
TEST(pfxexport_password_binds_the_blob) {
    NEED_EXPORT(); PP_WINE_NO_EXPORT();
    HCERTSTORE s = leaf_store(1);
    if (!s) { CHECK(s != NULL); return; }
    CRYPT_DATA_BLOB b;
    CHECK(pp_export_ex(s, &b, L"export-pw", NULL, EXPORT_PRIVATE_KEYS));
    if (b.pbData) {
        HCERTSTORE s2 = U(PFXImportCertStore)(&b, L"export-pw", PP_NP);
        CHECKF(s2 != NULL, "err %lu", GetLastError());
        pp_close(s2);
        SET_ERR(0);
        s2 = U(PFXImportCertStore)(&b, L"test", PP_NP);
        EXPECT_FAIL(s2 == NULL, PP_ERR_INVALID_PASSWORD);
        SET_ERR(0);
        s2 = U(PFXImportCertStore)(&b, NULL, PP_NP);
        EXPECT_FAIL(s2 == NULL, PP_ERR_INVALID_PASSWORD);
        if (U(PFXVerifyPassword)) CHECK(U(PFXVerifyPassword)(&b, L"export-pw", 0));
        LocalFree(b.pbData);
    }
    pp_close(s);
}
TEST(pfxexport_null_password_roundtrip) {
    NEED_EXPORT(); PP_WINE_NO_EXPORT();
    HCERTSTORE s = leaf_store(1);
    if (!s) { CHECK(s != NULL); return; }
    CRYPT_DATA_BLOB b;
    CHECK(pp_export_ex(s, &b, NULL, NULL, EXPORT_PRIVATE_KEYS));
    if (b.pbData) {
        HCERTSTORE s2 = U(PFXImportCertStore)(&b, NULL, PP_NP);
        CHECKF(s2 != NULL, "null err %lu", GetLastError());
        pp_close(s2);
        s2 = U(PFXImportCertStore)(&b, L"", PP_NP);
        CHECKF(s2 != NULL, "empty err %lu", GetLastError());
        pp_close(s2);
        LocalFree(b.pbData);
    }
    pp_close(s);
}
TEST(pfxexport_empty_password_roundtrip) {
    NEED_EXPORT(); PP_WINE_NO_EXPORT();
    HCERTSTORE s = leaf_store(1);
    if (!s) { CHECK(s != NULL); return; }
    CRYPT_DATA_BLOB b;
    CHECK(pp_export_ex(s, &b, L"", NULL, EXPORT_PRIVATE_KEYS));
    if (b.pbData) {
        HCERTSTORE s2 = U(PFXImportCertStore)(&b, L"", PP_NP);
        CHECKF(s2 != NULL, "empty err %lu", GetLastError());
        pp_close(s2);
        s2 = U(PFXImportCertStore)(&b, NULL, PP_NP);
        CHECKF(s2 != NULL, "null err %lu", GetLastError());
        pp_close(s2);
        LocalFree(b.pbData);
    }
    pp_close(s);
}
TEST(pfxexport_unicode_password_roundtrip) {
    NEED_EXPORT(); PP_WINE_NO_EXPORT();
    static const WCHAR pw[] = {0x00e9, 0x4e2d, 0x0416, 'p', 0xd83d, 0xde00, 0};
    HCERTSTORE s = leaf_store(1);
    if (!s) { CHECK(s != NULL); return; }
    CRYPT_DATA_BLOB b;
    CHECK(pp_export_ex(s, &b, pw, NULL, EXPORT_PRIVATE_KEYS));
    if (b.pbData) {
        HCERTSTORE s2 = U(PFXImportCertStore)(&b, pw, PP_NP);
        CHECKF(s2 != NULL, "err %lu", GetLastError());
        pp_close(s2);
        LocalFree(b.pbData);
    }
    pp_close(s);
}
TEST(pfxexport_ex_and_legacy_interoperate) {
    NEED_EXPORT(); PP_WINE_NO_EXPORT();
    HCERTSTORE s = leaf_store(1);
    if (!s) { CHECK(s != NULL); return; }
    CRYPT_DATA_BLOB a, b;
    CHECK(pp_export_ex(s, &a, L"x", NULL, EXPORT_PRIVATE_KEYS));
    CHECK(pp_export(s, &b, L"x", EXPORT_PRIVATE_KEYS));
    if (a.pbData && b.pbData) {
        CHECK(reimport_has_key(&a, L"x") == 1);
        CHECK(reimport_has_key(&b, L"x") == 1);
        /* random salts: two exports never produce identical bytes */
        CHECK(a.cbData != b.cbData || memcmp(a.pbData, b.pbData, a.cbData) != 0);
    }
    if (a.pbData) LocalFree(a.pbData);
    if (b.pbData) LocalFree(b.pbData);
    pp_close(s);
}
TEST(pfxexport_same_store_twice_differs) {
    NEED_EXPORT(); PP_WINE_NO_EXPORT();
    HCERTSTORE s = leaf_store(1);
    if (!s) { CHECK(s != NULL); return; }
    CRYPT_DATA_BLOB a, b;
    CHECK(pp_export_ex(s, &a, L"x", NULL, 0));
    CHECK(pp_export_ex(s, &b, L"x", NULL, 0));
    if (a.pbData && b.pbData) CHECK(a.cbData != b.cbData || memcmp(a.pbData, b.pbData, a.cbData) != 0);
    if (a.pbData) LocalFree(a.pbData);
    if (b.pbData) LocalFree(b.pbData);
    pp_close(s);
}

/* ---- keys: EXPORT_PRIVATE_KEYS & friends ------------------------------------------- */
TEST(pfxexport_without_private_keys_flag_drops_key) {
    NEED_EXPORT(); PP_WINE_NO_EXPORT();
    HCERTSTORE s = leaf_store(1);
    if (!s) { CHECK(s != NULL); return; }
    CRYPT_DATA_BLOB b;
    CHECK(pp_export_ex(s, &b, L"x", NULL, 0));
    if (b.pbData) { CHECK(reimport_has_key(&b, L"x") == 0); LocalFree(b.pbData); }
    pp_close(s);
}
TEST(pfxexport_with_private_keys_flag_keeps_key) {
    NEED_EXPORT(); PP_WINE_NO_EXPORT();
    HCERTSTORE s = leaf_store(1);
    if (!s) { CHECK(s != NULL); return; }
    CRYPT_DATA_BLOB b;
    CHECK(pp_export_ex(s, &b, L"x", NULL, EXPORT_PRIVATE_KEYS));
    if (b.pbData) { CHECK(reimport_has_key(&b, L"x") == 1); LocalFree(b.pbData); }
    pp_close(s);
}
TEST(pfxexport_with_keys_is_larger_than_without) {
    NEED_EXPORT(); PP_WINE_NO_EXPORT();
    HCERTSTORE s = leaf_store(1);
    if (!s) { CHECK(s != NULL); return; }
    CRYPT_DATA_BLOB a = {0, NULL}, b = {0, NULL};
    CHECK(U(PFXExportCertStoreEx)(s, &a, L"x", NULL, 0));
    CHECK(U(PFXExportCertStoreEx)(s, &b, L"x", NULL, EXPORT_PRIVATE_KEYS));
    CHECK(b.cbData > a.cbData);
    pp_close(s);
}
TEST(pfxexport_cert_only_store_with_private_keys_flag) {
    NEED_EXPORT(); PP_WINE_NO_EXPORT();
    HCERTSTORE s = cert_only_store();
    CRYPT_DATA_BLOB b;
    /* "if available": no key is not an error unless REPORT_NO_PRIVATE_KEY is given */
    CHECK(pp_export_ex(s, &b, L"x", NULL, EXPORT_PRIVATE_KEYS));
    if (b.pbData) {
        CHECK(reimport_has_key(&b, L"x") == 0);
        HCERTSTORE s2 = U(PFXImportCertStore)(&b, L"x", PP_NP);
        if (s2) { EXPECT_EQ(pp_count(s2), 1); CHECK(pp_find_der(s2, fx_cert1, sizeof fx_cert1) != NULL); }
        pp_close(s2);
        LocalFree(b.pbData);
    }
    pp_close(s);
}
TEST(pfxexport_report_no_private_key) {
    NEED_EXPORT(); PP_WINE_NO_EXPORT();
    HCERTSTORE s = cert_only_store();
    CRYPT_DATA_BLOB b = {0, NULL};
    SET_ERR(0);
    BOOL r = U(PFXExportCertStoreEx)(s, &b, L"x", NULL, EXPORT_PRIVATE_KEYS | REPORT_NO_PRIVATE_KEY);
    CHECK(!r);
    DWORD e = GetLastError();
    CHECKF(e == CRYPT_E_NOT_FOUND || e == E_NTE_NO_KEY, "err 0x%lx", e);
    SET_ERR(0);
    r = U(PFXExportCertStore)(s, &b, L"x", EXPORT_PRIVATE_KEYS | REPORT_NO_PRIVATE_KEY);
    CHECK(!r);
    e = GetLastError();
    CHECKF(e == CRYPT_E_NOT_FOUND || e == E_NTE_NO_KEY, "legacy err 0x%lx", e);
    pp_close(s);
}
TEST(pfxexport_report_no_private_key_satisfied_by_key_context) {
    NEED_EXPORT(); PP_WINE_NO_EXPORT();
    HCERTSTORE s = leaf_store(1);
    if (!s) { CHECK(s != NULL); return; }
    CRYPT_DATA_BLOB b;
    BOOL r = pp_export_ex(s, &b, L"x", NULL, EXPORT_PRIVATE_KEYS | REPORT_NO_PRIVATE_KEY);
    CHECKF(r, "err 0x%lx", GetLastError());
    if (b.pbData) LocalFree(b.pbData);
    pp_close(s);
}
TEST(pfxexport_report_not_able_to_export_private_key) {
    NEED_EXPORT(); PP_WINE_NO_EXPORT();
    HCERTSTORE s = leaf_store(0); /* imported without CRYPT_EXPORTABLE */
    if (!s) { CHECK(s != NULL); return; }
    CRYPT_DATA_BLOB b = {0, NULL};
    SET_ERR(0);
    BOOL r = U(PFXExportCertStoreEx)(s, &b, L"x", NULL, EXPORT_PRIVATE_KEYS | REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY);
    CHECK(!r);
    DWORD e = GetLastError();
    CHECKF(e == E_NTE_BAD_KEY || e == E_NTE_BAD_KEY_STATE || e == E_NTE_PERM, "err 0x%lx", e);
    pp_close(s);
}
TEST(pfxexport_nonexportable_key_without_report_flag_observed) {
    NEED_EXPORT(); PP_WINE_NO_EXPORT();
    HCERTSTORE s = leaf_store(0);
    if (!s) { CHECK(s != NULL); return; }
    CRYPT_DATA_BLOB b;
    SET_ERR(0);
    BOOL r = pp_export_ex(s, &b, L"x", NULL, EXPORT_PRIVATE_KEYS);
    t_note("non-exportable key, EXPORT_PRIVATE_KEYS only: ret=%d err=0x%lx has_key=%d", r, GetLastError(), r ? reimport_has_key(&b, L"x") : -9);
    if (r && b.pbData) LocalFree(b.pbData);
    pp_close(s);
}

/* ---- certs, friendly names, extended properties ---------------------------------------- */
TEST(pfxexport_roundtrip_cert_bytes_and_friendly_name) {
    NEED_EXPORT(); PP_WINE_NO_EXPORT();
    HCERTSTORE s = leaf_store(1);
    if (!s) { CHECK(s != NULL); return; }
    CRYPT_DATA_BLOB b;
    CHECK(pp_export_ex(s, &b, L"rt", NULL, EXPORT_PRIVATE_KEYS));
    if (b.pbData) {
        HCERTSTORE s2 = U(PFXImportCertStore)(&b, L"rt", PP_NP);
        CHECK(s2 != NULL);
        if (s2) {
            EXPECT_EQ(pp_count(s2), 1);
            PCCERT_CONTEXT c = pp_find_der(s2, fx_cert1, sizeof fx_cert1);
            CHECK(c != NULL);
            if (c) { CHECK(pp_has_friendly(c, L"cryptt friendly")); U(CertFreeCertificateContext)(c); }
        }
        pp_close(s2);
        LocalFree(b.pbData);
    }
    pp_close(s);
}
TEST(pfxexport_roundtrip_two_certs) {
    NEED_EXPORT(); PP_WINE_NO_EXPORT();
    HCERTSTORE s = PP_IMPORT(fx_legtwo, L"test", PP_NP | CRYPT_EXPORTABLE);
    if (!s) { CHECK(s != NULL); return; }
    CRYPT_DATA_BLOB b;
    CHECK(pp_export_ex(s, &b, L"rt", NULL, EXPORT_PRIVATE_KEYS));
    if (b.pbData) {
        HCERTSTORE s2 = U(PFXImportCertStore)(&b, L"rt", PP_NP);
        CHECK(s2 != NULL);
        if (s2) {
            EXPECT_EQ(pp_count(s2), 2);
            PCCERT_CONTEXT a = pp_find_der(s2, fx_cert1, sizeof fx_cert1), c = pp_find_der(s2, fx_cert2, sizeof fx_cert2);
            CHECK(a != NULL); CHECK(c != NULL);
            if (a) U(CertFreeCertificateContext)(a);
            if (c) U(CertFreeCertificateContext)(c);
        }
        pp_close(s2);
        LocalFree(b.pbData);
    }
    pp_close(s);
}
TEST(pfxexport_memory_store_certs_only_roundtrip) {
    NEED_EXPORT(); PP_WINE_NO_EXPORT();
    HCERTSTORE s = pp_memstore();
    U(CertAddEncodedCertificateToStore)(s, X509_ASN_ENCODING, fx_cert1, sizeof fx_cert1, CERT_STORE_ADD_NEW, NULL);
    U(CertAddEncodedCertificateToStore)(s, X509_ASN_ENCODING, fx_cert2, sizeof fx_cert2, CERT_STORE_ADD_NEW, NULL);
    CRYPT_DATA_BLOB b;
    CHECK(pp_export(s, &b, L"pw", 0));
    if (b.pbData) {
        HCERTSTORE s2 = U(PFXImportCertStore)(&b, L"pw", PP_NP);
        CHECK(s2 != NULL);
        if (s2) EXPECT_EQ(pp_count(s2), 2);
        pp_close(s2);
        LocalFree(b.pbData);
    }
    pp_close(s);
}
TEST(pfxexport_friendly_name_set_on_memory_cert) {
    NEED_EXPORT(); PP_WINE_NO_EXPORT();
    HCERTSTORE s = pp_memstore();
    PCCERT_CONTEXT c = NULL;
    U(CertAddEncodedCertificateToStore)(s, X509_ASN_ENCODING, fx_cert2, sizeof fx_cert2, CERT_STORE_ADD_NEW, &c);
    if (!c) { CHECK(c != NULL); pp_close(s); return; }
    CRYPT_DATA_BLOB fn = {sizeof(L"cryptt custom name"), (BYTE *)L"cryptt custom name"};
    CHECK(U(CertSetCertificateContextProperty)(c, CERT_FRIENDLY_NAME_PROP_ID, 0, &fn));
    U(CertFreeCertificateContext)(c);
    CRYPT_DATA_BLOB b;
    CHECK(pp_export(s, &b, L"pw", 0));
    if (b.pbData) {
        HCERTSTORE s2 = U(PFXImportCertStore)(&b, L"pw", PP_NP);
        if (s2) {
            PCCERT_CONTEXT c2 = U(CertEnumCertificatesInStore)(s2, NULL);
            CHECK(c2 != NULL);
            if (c2) { CHECK(pp_has_friendly(c2, L"cryptt custom name")); U(CertFreeCertificateContext)(c2); }
        } else CHECK(s2 != NULL);
        pp_close(s2);
        LocalFree(b.pbData);
    }
    pp_close(s);
}
TEST(pfxexport_extended_properties_flag) {
    NEED_EXPORT(); PP_WINE_NO_EXPORT();
    HCERTSTORE s = pp_memstore();
    PCCERT_CONTEXT c = NULL;
    U(CertAddEncodedCertificateToStore)(s, X509_ASN_ENCODING, fx_cert2, sizeof fx_cert2, CERT_STORE_ADD_NEW, &c);
    if (!c) { CHECK(c != NULL); pp_close(s); return; }
    static const BYTE desc[] = {'d', 0, 'e', 0, 's', 0, 'c', 0, 0, 0};
    CRYPT_DATA_BLOB db = {sizeof desc, (BYTE *)desc};
    CHECK(U(CertSetCertificateContextProperty)(c, CERT_DESCRIPTION_PROP_ID, 0, &db));
    U(CertFreeCertificateContext)(c);
    CRYPT_DATA_BLOB with, without;
    CHECK(pp_export_ex(s, &with, L"pw", NULL, PKCS12_INCLUDE_EXTENDED_PROPERTIES));
    CHECK(pp_export_ex(s, &without, L"pw", NULL, 0));
    if (with.pbData) {
        HCERTSTORE s2 = U(PFXImportCertStore)(&with, L"pw", PP_NP | PKCS12_INCLUDE_EXTENDED_PROPERTIES);
        CHECK(s2 != NULL);
        if (s2) {
            PCCERT_CONTEXT c2 = U(CertEnumCertificatesInStore)(s2, NULL);
            CHECK(c2 != NULL);
            if (c2) {
                CHECK(pp_has_prop(c2, CERT_DESCRIPTION_PROP_ID, NULL));
                U(CertFreeCertificateContext)(c2);
            }
        }
        pp_close(s2);
    }
    if (without.pbData) {
        HCERTSTORE s2 = U(PFXImportCertStore)(&without, L"pw", PP_NP | PKCS12_INCLUDE_EXTENDED_PROPERTIES);
        if (s2) {
            PCCERT_CONTEXT c2 = U(CertEnumCertificatesInStore)(s2, NULL);
            if (c2) { t_note("description prop without export flag present=%d", pp_has_prop(c2, CERT_DESCRIPTION_PROP_ID, NULL)); U(CertFreeCertificateContext)(c2); }
        }
        pp_close(s2);
    }
    if (with.pbData) LocalFree(with.pbData);
    if (without.pbData) LocalFree(without.pbData);
    pp_close(s);
}

/* ---- certificate encryption flags ------------------------------------------------------ */
TEST(pfxexport_disable_encrypt_certificates_gives_plain_cert_bag) {
    NEED_EXPORT(); PP_WINE_NO_EXPORT();
    HCERTSTORE s = cert_only_store();
    CRYPT_DATA_BLOB b;
    CHECK(pp_export_ex(s, &b, L"pw", NULL, PKCS12_DISABLE_ENCRYPT_CERTIFICATES));
    if (b.pbData) {
        HCERTSTORE s2 = U(PFXImportCertStore)(&b, NULL, PKCS12_ONLY_NOT_ENCRYPTED_CERTIFICATES | PKCS12_IMPORT_SILENT);
        CHECKF(s2 != NULL, "err 0x%lx", GetLastError());
        if (s2) { EXPECT_EQ(pp_count(s2), 1); CHECK(pp_find_der(s2, fx_cert1, sizeof fx_cert1) != NULL); }
        pp_close(s2);
        LocalFree(b.pbData);
    }
    pp_close(s);
}
TEST(pfxexport_encrypt_certificates_flag_hides_certs_from_plain_reader) {
    NEED_EXPORT(); PP_WINE_NO_EXPORT();
    HCERTSTORE s = cert_only_store();
    CRYPT_DATA_BLOB b;
    CHECK(pp_export_ex(s, &b, L"pw", NULL, PKCS12_ENCRYPT_CERTIFICATES));
    if (b.pbData) {
        SET_ERR(0);
        HCERTSTORE s2 = U(PFXImportCertStore)(&b, NULL, PKCS12_ONLY_NOT_ENCRYPTED_CERTIFICATES | PKCS12_IMPORT_SILENT);
        t_note("ONLY_NOT_ENCRYPTED on ENCRYPT_CERTIFICATES export: %s certs=%d err=0x%lx", s2 ? "store" : "NULL", pp_count(s2), GetLastError());
        pp_close(s2);
        HCERTSTORE s3 = U(PFXImportCertStore)(&b, L"pw", PP_NP);
        CHECK(s3 != NULL);
        if (s3) EXPECT_EQ(pp_count(s3), 1);
        pp_close(s3);
        LocalFree(b.pbData);
    }
    pp_close(s);
}
TEST(pfxexport_disable_encrypt_certificates_still_password_protected_for_full_import) {
    NEED_EXPORT(); PP_WINE_NO_EXPORT();
    HCERTSTORE s = leaf_store(1);
    if (!s) { CHECK(s != NULL); return; }
    CRYPT_DATA_BLOB b;
    CHECK(pp_export_ex(s, &b, L"pw", NULL, EXPORT_PRIVATE_KEYS | PKCS12_DISABLE_ENCRYPT_CERTIFICATES));
    if (b.pbData) {
        CHECK(reimport_has_key(&b, L"pw") == 1);
        SET_ERR(0);
        HCERTSTORE s2 = U(PFXImportCertStore)(&b, L"nope", PP_NP);
        EXPECT_FAIL(s2 == NULL, PP_ERR_INVALID_PASSWORD);
        LocalFree(b.pbData);
    }
    pp_close(s);
}

/* ---- PBES2 export ---------------------------------------------------------------------- */
static BOOL pbes2_export(HCERTSTORE s, CRYPT_DATA_BLOB *b, LPCWSTR pw, LPCWSTR alg, DWORD extra) {
    PKCS12_PBES2_EXPORT_PARAMS p; memset(&p, 0, sizeof p);
    p.dwSize = sizeof p; p.pwszPbes2Alg = (LPWSTR)alg;
    return pp_export_ex(s, b, pw, &p, PKCS12_EXPORT_PBES2_PARAMS | extra);
}
TEST(pfxexport_pbes2_aes256_sha256_roundtrip) {
    NEED_EXPORT(); PP_WINE_NO_EXPORT();
    HCERTSTORE s = leaf_store(1);
    if (!s) { CHECK(s != NULL); return; }
    CRYPT_DATA_BLOB b;
    BOOL r = pbes2_export(s, &b, L"pbes2pw", PKCS12_PBES2_ALG_AES256_SHA256, EXPORT_PRIVATE_KEYS);
    CHECKF(r, "err 0x%lx", GetLastError());
    if (r && b.pbData) {
        CHECK(U(PFXIsPFXBlob)(&b));
        CHECK(reimport_has_key(&b, L"pbes2pw") == 1);
        SET_ERR(0);
        HCERTSTORE s2 = U(PFXImportCertStore)(&b, L"wrong", PP_NP);
        EXPECT_FAIL(s2 == NULL, PP_ERR_INVALID_PASSWORD);
        /* PBES2 blobs carry the PBES2 OID (1.2.840.113549.1.5.13): 06 09 2A 86 48 86 F7 0D 01 05 0D */
        static const BYTE oid[] = {0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0d};
        int found = 0;
        for (DWORD i = 0; i + sizeof oid <= b.cbData; i++) if (!memcmp(b.pbData + i, oid, sizeof oid)) { found = 1; break; }
        CHECK(found);
        LocalFree(b.pbData);
    }
    pp_close(s);
}
TEST(pfxexport_pbes2_algorithm_name_case_insensitive) {
    NEED_EXPORT(); PP_WINE_NO_EXPORT();
    HCERTSTORE s = cert_only_store();
    CRYPT_DATA_BLOB b;
    BOOL r = pbes2_export(s, &b, L"pw", L"aes256-sha256", 0);
    CHECKF(r, "err 0x%lx", GetLastError());
    if (r && b.pbData) LocalFree(b.pbData);
    pp_close(s);
}
TEST(pfxexport_pbes2_null_algorithm_string_uses_default) {
    NEED_EXPORT(); PP_WINE_NO_EXPORT();
    HCERTSTORE s = cert_only_store();
    CRYPT_DATA_BLOB b;
    BOOL r = pbes2_export(s, &b, L"pw", NULL, 0);
    CHECKF(r, "err 0x%lx", GetLastError());
    if (r && b.pbData) {
        CHECK(U(PFXIsPFXBlob)(&b));
        LocalFree(b.pbData);
    }
    pp_close(s);
}
TEST(pfxexport_pbes2_flag_with_null_para_uses_default) {
    NEED_EXPORT(); PP_WINE_NO_EXPORT();
    HCERTSTORE s = cert_only_store();
    CRYPT_DATA_BLOB b;
    BOOL r = pp_export_ex(s, &b, L"pw", NULL, PKCS12_EXPORT_PBES2_PARAMS);
    t_note("PKCS12_EXPORT_PBES2_PARAMS with pvPara NULL: ret=%d err=0x%lx", r, GetLastError());
    if (r && b.pbData) LocalFree(b.pbData);
    pp_close(s);
}
TEST(pfxexport_pbes2_unsupported_names) {
    NEED_EXPORT(); PP_WINE_NO_EXPORT();
    static const WCHAR *names[] = {L"", L"AES256", L"SHA256", L"AES128-SHA256", L"AES256-SHA1", L"3DES", L"AES256-SHA256 "};
    HCERTSTORE s = cert_only_store();
    for (size_t i = 0; i < sizeof names / sizeof *names; i++) {
        CRYPT_DATA_BLOB b;
        SET_ERR(0);
        BOOL r = pbes2_export(s, &b, L"pw", names[i], 0);
        t_note("PBES2 name \"%ls\": ret=%d err=%lu", names[i], r, GetLastError());
        if (r && b.pbData) LocalFree(b.pbData);
    }
    pp_close(s);
}

/* ---- PFXExportCertStore2 (undocumented in the SDK headers; layout from the legacy wrapper) ---- */
TEST(pfxexport_store2_roundtrip_like_legacy) {
    NEED_EXPORT(); PP_WINE_NO_EXPORT();
    REQUIRE(UN(PFXExportCertStore2));
    HCERTSTORE s = leaf_store(1);
    if (!s) { CHECK(s != NULL); return; }
    static const WCHAR pw[] = L"s2pw";
    DWORD it = 2000;
    int cb = sizeof pw;
    pp_alg_and_param a[4] = {
        {"1.2.840.113549.1.12.1.3", pw, cb, &it, 4},
        {"1.2.840.113549.1.12.1.3", pw, cb, &it, 4},
        {"1.2.840.113549.1.12.1.3", pw, cb, &it, 4},
        {"1.3.14.3.2.26", pw, cb, &it, 4},
    };
    CRYPT_DATA_BLOB b = {0, NULL};
    BOOL r = UN(PFXExportCertStore2)(s, &b, a, EXPORT_PRIVATE_KEYS);
    CHECKF(r, "size err 0x%lx", GetLastError());
    if (r) {
        b.pbData = (BYTE *)LocalAlloc(LPTR, b.cbData);
        r = UN(PFXExportCertStore2)(s, &b, a, EXPORT_PRIVATE_KEYS);
        CHECKF(r, "err 0x%lx", GetLastError());
        if (r) { CHECK(U(PFXIsPFXBlob)(&b)); CHECK(reimport_has_key(&b, pw) == 1); }
        LocalFree(b.pbData);
    }
    pp_close(s);
}
TEST(pfxexport_store2_null_args) {
    NEED_EXPORT(); PP_WINE_NO_EXPORT();
    REQUIRE(UN(PFXExportCertStore2));
    CRYPT_DATA_BLOB b = {0, NULL};
    SET_ERR(0);
    BOOL r = UN(PFXExportCertStore2)(NULL, &b, NULL, 0);
    EXPECT_FAIL(!r, ERROR_INVALID_PARAMETER);
    HCERTSTORE s = pp_memstore();
    SET_ERR(0);
    r = UN(PFXExportCertStore2)(s, NULL, NULL, 0);
    EXPECT_FAIL(!r, ERROR_INVALID_PARAMETER);
    SET_ERR(0);
    r = UN(PFXExportCertStore2)(s, &b, NULL, 0x4000);
    EXPECT_FAIL(!r, ERROR_INVALID_PARAMETER);
    pp_close(s);
}
