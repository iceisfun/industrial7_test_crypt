#include "ck.h"
/* Additional symmetric-key edge cases: chunked KATs for AES-192/256, cross-key param independence. */

TEST(extra_aes192_256_cbc_chunked_equals_kat) {
    NEED_CRYPT(); NEED_PROV(p);
    static const struct { ALG_ID a; const BYTE *k; DWORD kl; const BYTE *ct; } t[] = {
        { CALG_AES_192, sp_key192, 24, sp_cbc192 }, { CALG_AES_256, sp_key256, 32, sp_cbc256 } };
    for (unsigned i = 0; i < 2; i++) {
        HCRYPTKEY k = ck_key(p, t[i].a, t[i].k, t[i].kl); if (!k) { CHECK(0); continue; }
        BYTE b[64]; memcpy(b, sp_pt, 64);
        CHECK(ck_set_iv(k, sp_iv));
        DWORD n = 16;
        CHECK(U(CryptEncrypt)(k, 0, FALSE, 0, b, &n, 16)); EXPECT_EQ(n, 16);
        n = 48;
        CHECK(U(CryptEncrypt)(k, 0, FALSE, 0, b + 16, &n, 48)); EXPECT_EQ(n, 48);
        CHECK_BYTES(b, t[i].ct, 64);
        U(CryptDestroyKey)(k);
    }
    ck_release(p);
}
TEST(extra_decrypt_kat_cbc_back_to_plain) {
    NEED_CRYPT(); NEED_PROV(p);
    HCRYPTKEY k = ck_key(p, CALG_AES_256, sp_key256, 32); if (!k) { CHECK(0); ck_release(p); return; }
    BYTE b[64]; memcpy(b, sp_cbc256, 64);
    CHECK(ck_set_iv(k, sp_iv));
    DWORD n = 64;
    CHECK(U(CryptDecrypt)(k, 0, FALSE, 0, b, &n)); EXPECT_EQ(n, 64);
    CHECK_BYTES(b, sp_pt, 64);
    U(CryptDestroyKey)(k); ck_release(p);
}
TEST(extra_setparam_on_one_key_does_not_affect_another) {
    NEED_CRYPT(); NEED_PROV(p);
    HCRYPTKEY a = ck_key(p, CALG_AES_128, sp_key128, 16), b = ck_key(p, CALG_AES_128, sp_key128, 16);
    if (!a || !b) { CHECK(0); ck_release(p); return; }
    CHECK(ck_set_mode(a, CRYPT_MODE_ECB));
    BOOL ok; DWORD m = ck_param_dw(b, KP_MODE, &ok);
    CHECK(ok); EXPECT_EQ(m, CRYPT_MODE_CBC);
    m = ck_param_dw(a, KP_MODE, &ok); CHECK(ok); EXPECT_EQ(m, CRYPT_MODE_ECB);
    U(CryptDestroyKey)(a); U(CryptDestroyKey)(b); ck_release(p);
}
TEST(extra_des_cbc_iv_decrypt_matches_kat) {
    NEED_CRYPT(); NEED_PROV(p);
    HCRYPTKEY k = ck_key(p, CALG_DES, des_key, 8); if (!k) { CHECK(0); ck_release(p); return; }
    BYTE b[24]; memcpy(b, des_cbc24, 24);
    CHECK(ck_set_iv(k, des_iv));
    DWORD n = 24;
    CHECK(U(CryptDecrypt)(k, 0, FALSE, 0, b, &n)); EXPECT_EQ(n, 24);
    CHECK_BYTES(b, des_pt24, 24);
    U(CryptDestroyKey)(k); ck_release(p);
}
