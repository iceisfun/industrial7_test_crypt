/* Handle-ordering and argument-validation rules of the NCrypt router that are visible in its code. */
#include "nc.h"

TEST(ncextra_setprop_handle_checked_before_name) {
    REQUIRE(U(NCryptSetProperty));
    DWORD v = 0;
    EXPECT_SS(U(NCryptSetProperty)(0, NULL, (PBYTE)&v, 4, 0), NC_INVALID_HANDLE);
    EXPECT_SS(U(NCryptSetProperty)(0, NCRYPT_LENGTH_PROPERTY, (PBYTE)&v, 4, 0), NC_INVALID_HANDLE);
}
TEST(ncextra_setprop_accepts_provider_handle_checks_name) {
    REQUIRE(U(NCryptSetProperty));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    DWORD v = 0;
    /* a provider handle is a valid object for SetProperty, so a NULL name is a parameter error, not a handle error */
    EXPECT_SS(U(NCryptSetProperty)(p, NULL, (PBYTE)&v, 4, 0), NC_INVALID_PARAMETER);
    nc_free(p);
}
TEST(ncextra_getprop_accepts_provider_and_key) {
    REQUIRE(U(NCryptGetProperty));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE k = nc_newkey(p, BCRYPT_ECDSA_P256_ALGORITHM, 0, 0xFFFFFFFFu, TRUE); NEED(k, "key");
    DWORD cb = 0;
    EXPECT_SS(U(NCryptGetProperty)(p, NCRYPT_NAME_PROPERTY, NULL, 0, &cb, 0), 0);
    EXPECT_EQ(cb, sizeof(NC_MSKSP));
    EXPECT_SS(U(NCryptGetProperty)(k, NCRYPT_ALGORITHM_PROPERTY, NULL, 0, &cb, 0), 0);
    EXPECT_EQ(cb, 22);
    nc_free(k); nc_free(p);
}
TEST(ncextra_export_key_must_be_key_handle) {
    REQUIRE(U(NCryptExportKey));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    BYTE buf[128]; DWORD cb = 0;
    /* a provider handle in the key slot is rejected (the router insists on the key tag 0x44440002) */
    EXPECT_SS(U(NCryptExportKey)((NCRYPT_KEY_HANDLE)p, 0, BCRYPT_ECCPUBLIC_BLOB, NULL, buf, sizeof buf, &cb, 0), NC_INVALID_HANDLE);
    nc_free(p);
}
TEST(ncextra_import_invalid_import_key_handle) {
    REQUIRE(U(NCryptImportKey));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE k = 0x1;
    /* hImportKey must be a key handle; a provider handle is not */
    EXPECT_SS(U(NCryptImportKey)(p, (NCRYPT_KEY_HANDLE)p, BCRYPT_ECCPUBLIC_BLOB, NULL, &k, (PBYTE)k_ec256_pub, sizeof k_ec256_pub, 0), NC_INVALID_HANDLE);
    nc_free(p);
}
TEST(ncextra_import_provider_still_usable_after_failed_import) {
    REQUIRE(U(NCryptImportKey));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE k = 0x1;
    EXPECT_SS(U(NCryptImportKey)(p, (NCRYPT_KEY_HANDLE)p, BCRYPT_ECCPUBLIC_BLOB, NULL, &k, (PBYTE)k_ec256_pub, sizeof k_ec256_pub, 0), NC_INVALID_HANDLE);
    /* the failed call must not leak or consume the provider reference */
    NCRYPT_KEY_HANDLE g = nc_import(p, BCRYPT_ECCPUBLIC_BLOB, NCV(k_ec256_pub));
    CHECK(g != 0);
    nc_free(g);
    EXPECT_SS(U(NCryptIsAlgSupported)(p, BCRYPT_RSA_ALGORITHM, 0), 0);
    EXPECT_SS(U(NCryptFreeObject)(p), 0);
}
TEST(ncextra_key_handle_rejected_as_provider_everywhere) {
    REQUIRE(U(NCryptCreatePersistedKey));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE k = nc_newkey(p, BCRYPT_ECDSA_P256_ALGORITHM, 0, 0xFFFFFFFFu, TRUE); NEED(k, "key");
    DWORD n = 0; NCryptAlgorithmName *l = NULL;
    EXPECT_SS(U(NCryptEnumAlgorithms)(k, NCRYPT_SIGNATURE_OPERATION, &n, &l, 0), NC_INVALID_HANDLE);
    EXPECT_SS(U(NCryptIsAlgSupported)(k, BCRYPT_RSA_ALGORITHM, 0), NC_INVALID_HANDLE);
    NCRYPT_KEY_HANDLE o = 0x2;
    EXPECT_SS(U(NCryptCreatePersistedKey)((NCRYPT_PROV_HANDLE)k, &o, BCRYPT_RSA_ALGORITHM, NULL, 0, 0), NC_INVALID_HANDLE);
    EXPECT_EQ(o, 2);
    nc_free(k); nc_free(p);
}
TEST(ncextra_derive_requires_secret_handle) {
    NC_NOWINE();
    REQUIRE(U(NCryptDeriveKey)); REQUIRE(U(NCryptKeyDerivation));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE k = nc_newkey(p, BCRYPT_ECDH_P256_ALGORITHM, 0, 0xFFFFFFFFu, TRUE); NEED(k, "key");
    BYTE out[32]; DWORD cb = 0;
    EXPECT_SS(U(NCryptDeriveKey)((NCRYPT_SECRET_HANDLE)k, BCRYPT_KDF_RAW_SECRET, NULL, out, 32, &cb, 0), NC_INVALID_HANDLE);
    EXPECT_SS(U(NCryptDeriveKey)((NCRYPT_SECRET_HANDLE)p, BCRYPT_KDF_RAW_SECRET, NULL, out, 32, &cb, 0), NC_INVALID_HANDLE);
    nc_free(k); nc_free(p);
}
TEST(ncextra_agreement_both_slots_must_be_keys) {
    NC_NOWINE();
    REQUIRE(U(NCryptSecretAgreement));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE a = nc_import(p, BCRYPT_ECCPRIVATE_BLOB, NCV(k_ecdh256_a_priv)); NEED(a, "key");
    NCRYPT_SECRET_HANDLE s = 0x3;
    EXPECT_SS(U(NCryptSecretAgreement)(a, 0, &s, 0), NC_INVALID_HANDLE);
    EXPECT_SS(U(NCryptSecretAgreement)(0, a, &s, 0), NC_INVALID_HANDLE);
    EXPECT_SS(U(NCryptSecretAgreement)(a, (NCRYPT_KEY_HANDLE)p, &s, 0), NC_INVALID_HANDLE);
    EXPECT_EQ(s, 3);
    nc_free(a); nc_free(p);
}
TEST(ncextra_enumalgs_op_filter_per_algorithm) {
    REQUIRE(U(NCryptEnumAlgorithms)); REQUIRE(U(NCryptFreeBuffer));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    DWORD n = 0; NCryptAlgorithmName *l = NULL;
    EXPECT_SS(U(NCryptEnumAlgorithms)(p, NCRYPT_SIGNATURE_OPERATION, &n, &l, 0), 0);
    if (l) {
        for (DWORD i = 0; i < n; i++) CHECK(l[i].pszName && l[i].pszName[0]);
        CHECK(!U(NCryptIsKeyHandle)((NCRYPT_KEY_HANDLE)l));   /* a returned list is a plain buffer, not a handle */
        EXPECT_SS(U(NCryptFreeBuffer)(l), 0);
    }
    nc_free(p);
}
TEST(ncextra_free_buffer_algorithm_list_then_provider) {
    REQUIRE(U(NCryptEnumAlgorithms)); REQUIRE(U(NCryptFreeBuffer));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    DWORD n = 0; NCryptAlgorithmName *l = NULL;
    EXPECT_SS(U(NCryptEnumAlgorithms)(p, NCRYPT_SIGNATURE_OPERATION, &n, &l, 0), 0);
    /* the list holds its own reference on the provider, so the provider handle may be closed first */
    EXPECT_SS(U(NCryptFreeObject)(p), 0);
    if (l) { CHECK(n > 0 && l[0].pszName != NULL); EXPECT_SS(U(NCryptFreeBuffer)(l), 0); }
}
TEST(ncextra_sign_bad_handle_ordering) {
    REQUIRE(U(NCryptSignHash)); REQUIRE(U(NCryptVerifySignature));
    BYTE b[64]; DWORD cb = 0;
    EXPECT_SS(U(NCryptSignHash)(0, NULL, b, 32, b, 64, &cb, 0), NC_INVALID_HANDLE);
    EXPECT_SS(U(NCryptVerifySignature)(0, NULL, b, 32, b, 64, 0), NC_INVALID_HANDLE);
}
