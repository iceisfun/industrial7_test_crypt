#include "pp.h"

/* ---- PFXIsPFXBlob ---------------------------------------------------- */
static const struct { const char *name; const BYTE *p; size_t n; } fixtures[] = {
    {"leg3des", fx_leg3des, sizeof fx_leg3des}, {"legempty", fx_legempty, sizeof fx_legempty},
    {"legcert", fx_legcert, sizeof fx_legcert}, {"legplaincert", fx_legplaincert, sizeof fx_legplaincert},
    {"legrc2", fx_legrc2, sizeof fx_legrc2}, {"pbes2", fx_pbes2, sizeof fx_pbes2},
    {"legtwo", fx_legtwo, sizeof fx_legtwo}, {"leg32", fx_leg32, sizeof fx_leg32},
};

TEST(pfxblob_valid_fixtures_all_variants) {
    REQUIRE(U(PFXIsPFXBlob));
    for (size_t i = 0; i < sizeof fixtures / sizeof *fixtures; i++) {
        CRYPT_DATA_BLOB b = pp_blob_of(fixtures[i].p, fixtures[i].n);
        CHECKF(U(PFXIsPFXBlob)(&b), "fixture %s", fixtures[i].name);
    }
}
TEST(pfxblob_empty_blob_is_not_pfx) {
    REQUIRE(U(PFXIsPFXBlob));
    CRYPT_DATA_BLOB b = {0, NULL};
    CHECK(!U(PFXIsPFXBlob)(&b));
    BYTE z = 0; b.cbData = 0; b.pbData = &z;
    CHECK(!U(PFXIsPFXBlob)(&b));
}
TEST(pfxblob_garbage_is_not_pfx) {
    REQUIRE(U(PFXIsPFXBlob));
    static const BYTE g1[] = {0x00}, g2[] = {0x30}, g3[] = {0x30, 0x00}, g4[] = {0x05, 0x00},
        g5[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, g6[] = "this is not a pfx at all";
    const struct { const BYTE *p; size_t n; } t[] = {{g1, 1}, {g2, 1}, {g3, 2}, {g4, 2}, {g5, 8}, {g6, sizeof g6}};
    for (size_t i = 0; i < 6; i++) {
        CRYPT_DATA_BLOB b = pp_blob_of(t[i].p, t[i].n);
        CHECKF(!U(PFXIsPFXBlob)(&b), "garbage %zu", i);
    }
}
TEST(pfxblob_other_der_objects_are_not_pfx) {
    REQUIRE(U(PFXIsPFXBlob));
    CRYPT_DATA_BLOB b = pp_blob_of(fx_cert1, sizeof fx_cert1);
    CHECK(!U(PFXIsPFXBlob)(&b));
    b = pp_blob_of(fx_p8plain, sizeof fx_p8plain);
    CHECK(!U(PFXIsPFXBlob)(&b));
    b = pp_blob_of(fx_p8enc, sizeof fx_p8enc);
    CHECK(!U(PFXIsPFXBlob)(&b));
}
TEST(pfxblob_truncated_pfx_is_not_pfx) {
    REQUIRE(U(PFXIsPFXBlob));
    for (size_t cut = 1; cut <= 64; cut *= 2) {
        CRYPT_DATA_BLOB b = pp_blob_of(fx_leg3des, sizeof fx_leg3des - cut);
        if (t_is_wine()) { t_note("emulator accepts truncated blobs, cut %zu", cut); continue; } /* length header exceeds data: a DER decoder rejects */
        CHECKF(!U(PFXIsPFXBlob)(&b), "cut %zu", cut);
    }
    CRYPT_DATA_BLOB b = pp_blob_of(fx_leg3des, 4);
    CHECK(!U(PFXIsPFXBlob)(&b));
    b = pp_blob_of(fx_leg3des, 20);
    CHECK(!U(PFXIsPFXBlob)(&b));
}
TEST(pfxblob_does_not_need_password_or_modify_input) {
    REQUIRE(U(PFXIsPFXBlob));
    BYTE *copy = (BYTE *)LocalAlloc(LPTR, sizeof fx_leg3des);
    memcpy(copy, fx_leg3des, sizeof fx_leg3des);
    CRYPT_DATA_BLOB b = pp_blob_of(copy, sizeof fx_leg3des);
    CHECK(U(PFXIsPFXBlob)(&b));
    CHECK(!memcmp(copy, fx_leg3des, sizeof fx_leg3des));
    EXPECT_EQ(b.cbData, sizeof fx_leg3des);
    EXPECT_EQ(b.pbData, copy);
    LocalFree(copy);
}
TEST(pfxblob_corrupt_version_is_not_pfx) {
    REQUIRE(U(PFXIsPFXBlob));
    /* PFX ::= SEQUENCE { version INTEGER (3), ... }: version INTEGER sits at offset 4 */
    BYTE *copy = (BYTE *)LocalAlloc(LPTR, sizeof fx_leg3des);
    memcpy(copy, fx_leg3des, sizeof fx_leg3des);
    CRYPT_DATA_BLOB b = pp_blob_of(copy, sizeof fx_leg3des);
    EXPECT_EQ(copy[4], 0x02); EXPECT_EQ(copy[6], 0x03);
    copy[4] = 0x04; /* OCTET STRING instead of INTEGER */
    CHECK(!U(PFXIsPFXBlob)(&b));
    copy[4] = 0x02; copy[6] = 0x03;
    CHECK(U(PFXIsPFXBlob)(&b));
    LocalFree(copy);
}
TEST(pfxblob_trailing_data_is_still_a_pfx) {
    REQUIRE(U(PFXIsPFXBlob));
    BYTE *copy = (BYTE *)LocalAlloc(LPTR, sizeof fx_leg3des + 16);
    memcpy(copy, fx_leg3des, sizeof fx_leg3des);
    CRYPT_DATA_BLOB b = pp_blob_of(copy, sizeof fx_leg3des + 16);
    CHECK(U(PFXIsPFXBlob)(&b));       /* the outer length header decides; trailing zeros are ignored */
    LocalFree(copy);
}

/* ---- PFXVerifyPassword ------------------------------------------------ */
TEST(pfxverify_right_password) {
    REQUIRE(U(PFXVerifyPassword)); PP_WINE_NO_VERIFY();
    CRYPT_DATA_BLOB b = pp_blob_of(fx_leg3des, sizeof fx_leg3des);
    SET_ERR(0);
    CHECK(U(PFXVerifyPassword)(&b, L"test", 0));
}
TEST(pfxverify_wrong_password_sets_invalid_password) {
    REQUIRE(U(PFXVerifyPassword)); PP_WINE_NO_VERIFY();
    CRYPT_DATA_BLOB b = pp_blob_of(fx_leg3des, sizeof fx_leg3des);
    SET_ERR(0);
    BOOL r = U(PFXVerifyPassword)(&b, L"wrong", 0);
    EXPECT_FAIL(!r, PP_ERR_INVALID_PASSWORD);
}
TEST(pfxverify_password_is_case_sensitive) {
    REQUIRE(U(PFXVerifyPassword)); PP_WINE_NO_VERIFY();
    CRYPT_DATA_BLOB b = pp_blob_of(fx_leg3des, sizeof fx_leg3des);
    SET_ERR(0);
    BOOL r = U(PFXVerifyPassword)(&b, L"TEST", 0);
    EXPECT_FAIL(!r, PP_ERR_INVALID_PASSWORD);
    CHECK(!U(PFXVerifyPassword)(&b, L"Test", 0));
    CHECK(!U(PFXVerifyPassword)(&b, L"test ", 0));
    CHECK(!U(PFXVerifyPassword)(&b, L" test", 0));
    CHECK(!U(PFXVerifyPassword)(&b, L"tes", 0));
}
TEST(pfxverify_null_or_empty_password_on_protected_pfx_fails) {
    REQUIRE(U(PFXVerifyPassword)); PP_WINE_NO_VERIFY();
    CRYPT_DATA_BLOB b = pp_blob_of(fx_leg3des, sizeof fx_leg3des);
    SET_ERR(0);
    BOOL r = U(PFXVerifyPassword)(&b, NULL, 0);
    EXPECT_FAIL(!r, PP_ERR_INVALID_PASSWORD);
    SET_ERR(0);
    r = U(PFXVerifyPassword)(&b, L"", 0);
    EXPECT_FAIL(!r, PP_ERR_INVALID_PASSWORD);
}
TEST(pfxverify_empty_password_pfx_accepts_null_and_empty) {
    REQUIRE(U(PFXVerifyPassword)); PP_WINE_NO_VERIFY();
    /* a NULL and an empty password are retried against each other (observed on the import path) */
    CRYPT_DATA_BLOB b = pp_blob_of(fx_legempty, sizeof fx_legempty);
    CHECK(U(PFXVerifyPassword)(&b, NULL, 0));
    CHECK(U(PFXVerifyPassword)(&b, L"", 0));
}
TEST(pfxverify_empty_password_pfx_rejects_nonempty) {
    REQUIRE(U(PFXVerifyPassword)); PP_WINE_NO_VERIFY();
    CRYPT_DATA_BLOB b = pp_blob_of(fx_legempty, sizeof fx_legempty);
    SET_ERR(0);
    BOOL r = U(PFXVerifyPassword)(&b, L"x", 0);
    EXPECT_FAIL(!r, PP_ERR_INVALID_PASSWORD);
}
TEST(pfxverify_null_blob_is_invalid_parameter) {
    REQUIRE(U(PFXVerifyPassword)); PP_WINE_NO_VERIFY();
    SET_ERR(0);
    BOOL r = U(PFXVerifyPassword)(NULL, L"test", 0);
    EXPECT_FAIL(!r, ERROR_INVALID_PARAMETER);
}
TEST(pfxverify_flags_are_ignored) {
    REQUIRE(U(PFXVerifyPassword)); PP_WINE_NO_VERIFY();
    /* Windows passes a fixed private flag value and drops dwFlags */
    CRYPT_DATA_BLOB b = pp_blob_of(fx_leg3des, sizeof fx_leg3des);
    CHECK(U(PFXVerifyPassword)(&b, L"test", 0xffffffff));
    CHECK(U(PFXVerifyPassword)(&b, L"test", PKCS12_ALWAYS_CNG_KSP | PKCS12_ONLY_CERTIFICATES));
    CHECK(!U(PFXVerifyPassword)(&b, L"nope", 0xffffffff));
}
TEST(pfxverify_garbage_blob) {
    REQUIRE(U(PFXVerifyPassword)); PP_WINE_NO_VERIFY();
    static const BYTE g[] = {1, 2, 3, 4, 5, 6, 7, 8};
    CRYPT_DATA_BLOB b = pp_blob_of(g, sizeof g);
    SET_ERR(0);
    BOOL r = U(PFXVerifyPassword)(&b, L"test", 0);
    CHECK(!r);
    EXPECT_ERR(CRYPT_E_BAD_ENCODE);
    b.cbData = 0; b.pbData = NULL;
    SET_ERR(0);
    CHECK(!U(PFXVerifyPassword)(&b, L"test", 0));
}
TEST(pfxverify_cert_only_pfx_password_checked_by_mac) {
    REQUIRE(U(PFXVerifyPassword)); PP_WINE_NO_VERIFY();
    CRYPT_DATA_BLOB b = pp_blob_of(fx_legcert, sizeof fx_legcert);
    CHECK(U(PFXVerifyPassword)(&b, L"test", 0));
    CHECK(!U(PFXVerifyPassword)(&b, L"bad", 0));
}
TEST(pfxverify_matrix_of_fixtures) {
    REQUIRE(U(PFXVerifyPassword)); PP_WINE_NO_VERIFY();
    const struct { const BYTE *p; size_t n; LPCWSTR pw; } t[] = {
        {fx_legplaincert, sizeof fx_legplaincert, L"test"},
        {fx_legrc2, sizeof fx_legrc2, L"test"},
        {fx_legtwo, sizeof fx_legtwo, L"test"},
        {fx_leg32, sizeof fx_leg32, L"abcdefghijklmnopqrstuvwxyz012345"},
    };
    for (size_t i = 0; i < 4; i++) {
        CRYPT_DATA_BLOB b = pp_blob_of(t[i].p, t[i].n);
        CHECKF(U(PFXVerifyPassword)(&b, t[i].pw, 0), "row %zu right", i);
        CHECKF(!U(PFXVerifyPassword)(&b, L"zzz", 0), "row %zu wrong", i);
    }
}
TEST(pfxverify_pbes2_fixture_verifies) {
    REQUIRE(U(PFXVerifyPassword)); PP_WINE_NO_VERIFY();
    CRYPT_DATA_BLOB b = pp_blob_of(fx_pbes2, sizeof fx_pbes2);
    BOOL r = U(PFXVerifyPassword)(&b, L"test", 0);
    CHECKF(r, "err %lu", GetLastError());
    CHECK(!U(PFXVerifyPassword)(&b, L"wrong", 0));
}
TEST(pfxverify_long_password_is_not_truncated) {
    REQUIRE(U(PFXVerifyPassword)); PP_WINE_NO_VERIFY();
    /* Win10 22H2: a longer password is not accepted by truncation to its first 32 characters */
    CRYPT_DATA_BLOB b = pp_blob_of(fx_leg32, sizeof fx_leg32);
    CHECK(U(PFXVerifyPassword)(&b, L"abcdefghijklmnopqrstuvwxyz012345", 0));
    BOOL r = U(PFXVerifyPassword)(&b, L"abcdefghijklmnopqrstuvwxyz012345EXTRA", 0);
    CHECK(!r);
}
TEST(pfxverify_does_not_change_blob) {
    REQUIRE(U(PFXVerifyPassword)); PP_WINE_NO_VERIFY();
    BYTE *copy = (BYTE *)LocalAlloc(LPTR, sizeof fx_leg3des);
    memcpy(copy, fx_leg3des, sizeof fx_leg3des);
    CRYPT_DATA_BLOB b = pp_blob_of(copy, sizeof fx_leg3des);
    CHECK(U(PFXVerifyPassword)(&b, L"test", 0));
    CHECK(!memcmp(copy, fx_leg3des, sizeof fx_leg3des));
    LocalFree(copy);
}
TEST(pfxverify_creates_no_persistent_keys_observable) {
    REQUIRE(U(PFXVerifyPassword)); PP_WINE_NO_VERIFY();
    /* repeated verification stays cheap and repeatable */
    CRYPT_DATA_BLOB b = pp_blob_of(fx_leg3des, sizeof fx_leg3des);
    for (int i = 0; i < 20; i++) CHECK(U(PFXVerifyPassword)(&b, L"test", 0));
}
TEST(pfxverify_corrupted_mac_fails) {
    REQUIRE(U(PFXVerifyPassword)); PP_WINE_NO_VERIFY();
    BYTE *copy = (BYTE *)LocalAlloc(LPTR, sizeof fx_leg3des);
    memcpy(copy, fx_leg3des, sizeof fx_leg3des);
    copy[sizeof fx_leg3des - 3] ^= 0x55; /* inside the MAC iteration/salt tail */
    CRYPT_DATA_BLOB b = pp_blob_of(copy, sizeof fx_leg3des);
    SET_ERR(0);
    BOOL r = U(PFXVerifyPassword)(&b, L"test", 0);
    CHECK(!r);
    EXPECT_ERR(CRYPT_E_BAD_ENCODE);
    LocalFree(copy);
}
