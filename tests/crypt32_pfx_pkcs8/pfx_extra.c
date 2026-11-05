#include "pp.h"

/* flag-mask validation through the Ex entry point (mask 0xefee208c, reserved must be NULL) */
TEST(pfxextra_ex_rejects_each_reserved_bit) {
    PP_WINE_SKIP("Ex entry point absent");
    REQUIRE(UN(I_PFXImportCertStoreEx)); REQUIRE(U(CertCloseStore));
    CRYPT_DATA_BLOB b = pp_blob_of(fx_leg3des, sizeof fx_leg3des);
    for (int bit = 0; bit < 32; bit++) {
        DWORD f = 1u << bit;
        if (!(0xefee208cu & f)) continue;
        SET_ERR(0);
        HCERTSTORE s = UN(I_PFXImportCertStoreEx)(NULL, &b, L"test", PP_NP | f, NULL);
        CHECKF(s == NULL, "flag 0x%lx", f);
        EXPECT_ERR(ERROR_INVALID_PARAMETER);
        pp_close(s);
    }
}
TEST(pfxextra_ex_accepts_documented_flag_combos) {
    PP_WINE_SKIP("flags");
    REQUIRE(UN(I_PFXImportCertStoreEx)); REQUIRE(U(CertEnumCertificatesInStore)); REQUIRE(U(CertCloseStore));
    static const DWORD ok[] = {0, PKCS12_ALLOW_OVERWRITE_KEY, PKCS12_INCLUDE_EXTENDED_PROPERTIES, CRYPT_EXPORTABLE};
    for (size_t i = 0; i < sizeof ok / sizeof *ok; i++) {
        CRYPT_DATA_BLOB b = pp_blob_of(fx_leg3des, sizeof fx_leg3des);
        HCERTSTORE s = UN(I_PFXImportCertStoreEx)(NULL, &b, L"test", PP_NP | ok[i], NULL);
        CHECKF(s != NULL, "flags 0x%lx err %lu", ok[i], GetLastError());
        if (s) CHECKF(pp_count(s) >= 1, "flags 0x%lx", ok[i]);
        pp_close(s);
    }
}
TEST(pfxextra_isblob_ignores_trailing_nothing_and_rejects_truncation) {
    REQUIRE(U(PFXIsPFXBlob));
    /* a valid PFX cut short is no longer a well-formed PFX */
    for (size_t cut = 1; cut <= 8; cut++) {
        CRYPT_DATA_BLOB b = pp_blob_of(fx_leg3des, sizeof fx_leg3des - cut);
        t_label("cut %zu", cut);
        CHECK(!U(PFXIsPFXBlob)(&b));
    }
}
TEST(pfxextra_verify_each_fixture_with_known_password) {
    PP_WINE_NO_VERIFY();
    REQUIRE(U(PFXVerifyPassword));
    CRYPT_DATA_BLOB b = pp_blob_of(fx_leg3des, sizeof fx_leg3des);
    CHECK(U(PFXVerifyPassword)(&b, L"test", 0));
    SET_ERR(0);
    CHECK(!U(PFXVerifyPassword)(&b, L"TEST", 0));
    EXPECT_ERR(PP_ERR_INVALID_PASSWORD);
}
