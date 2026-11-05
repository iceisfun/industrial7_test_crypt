#include "cp.h"
#include "vectors.h"
#include "rsa_vectors.h"
/* CPEncrypt / CPDecrypt: known answers (FIPS 197, SP 800-38A, DES/3DES classics, openssl-generated
 * padded vectors), padding rules, buffer protocol and handle validation. */

static int hx(const char *s, BYTE *out) {
    int n = 0;
    while (s[0] && s[1]) { unsigned v; char t[3] = { s[0], s[1], 0 }; sscanf(t, "%x", &v); out[n++] = (BYTE)v; s += 2; }
    return n;
}
static void rc4_ref(const BYTE *key, int kl, const BYTE *in, BYTE *out, int n) {
    BYTE S[256]; int i, j = 0;
    for (i = 0; i < 256; i++) S[i] = (BYTE)i;
    for (i = 0; i < 256; i++) { j = (j + S[i] + key[i % kl]) & 255; BYTE t = S[i]; S[i] = S[j]; S[j] = t; }
    i = j = 0;
    for (int x = 0; x < n; x++) {
        i = (i + 1) & 255; j = (j + S[i]) & 255; BYTE t = S[i]; S[i] = S[j]; S[j] = t;
        out[x] = in[x] ^ S[(S[i] + S[j]) & 255];
    }
}
/* Build a key with optional mode/iv/padding settings. */
static ULONG_PTR mk(const cpf *f, ULONG_PTR p, ALG_ID alg, const char *keyhex, DWORD mode, const char *ivhex) {
    BYTE key[64], iv[32]; int kl = hx(keyhex, key);
    ULONG_PTR k = cp_key(f, p, alg, key, kl);
    if (!k) return 0;
    if (mode) f->SetKeyParam(p, k, KP_MODE, (BYTE *)&mode, 0);
    if (ivhex) { hx(ivhex, iv); f->SetKeyParam(p, k, KP_IV, iv, 0); }
    return k;
}
/* Encrypt in place with Final flag; returns TRUE and the new length in *n. */
static BOOL enc(const cpf *f, ULONG_PTR p, ULONG_PTR k, BOOL fin, BYTE *buf, DWORD *n, DWORD cap) {
    return f->Encrypt(p, k, 0, fin, 0, buf, n, cap);
}
static BOOL dec(const cpf *f, ULONG_PTR p, ULONG_PTR k, BOOL fin, BYTE *buf, DWORD *n) {
    return f->Decrypt(p, k, 0, fin, 0, buf, n);
}
/* single known answer, both directions, no padding (Final = FALSE) */
static void kat_raw(const cpf *f, ULONG_PTR p, ALG_ID alg, const char *key, DWORD mode, const char *iv,
                    const char *pt, const char *ct, const char *what) {
    BYTE P[128], C[128], buf[160]; int pl = hx(pt, P), cl = hx(ct, C);
    ULONG_PTR k = mk(f, p, alg, key, mode, iv);
    if (!k) { CHECKF(0, "%s: key failed 0x%lx", what, GetLastError()); return; }
    DWORD n = pl; memcpy(buf, P, pl);
    BOOL r = enc(f, p, k, FALSE, buf, &n, sizeof buf);
    CHECKF(r, "%s: encrypt err=0x%lx", what, GetLastError());
    if (r) { CHECKF(n == (DWORD)cl, "%s: enc len %lu", what, n); if (n == (DWORD)cl) t_check(!memcmp(buf, C, cl), __FILE__, __LINE__, what, "encrypt mismatch"); }
    f->DestroyKey(p, k);
    k = mk(f, p, alg, key, mode, iv);
    n = cl; memcpy(buf, C, cl);
    r = dec(f, p, k, FALSE, buf, &n);
    CHECKF(r, "%s: decrypt err=0x%lx", what, GetLastError());
    if (r) { CHECKF(n == (DWORD)pl, "%s: dec len %lu", what, n); if (n == (DWORD)pl) t_check(!memcmp(buf, P, pl), __FILE__, __LINE__, what, "decrypt mismatch"); }
    f->DestroyKey(p, k);
}
#define NIST_PT_ALL "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710"

/* ---- AES known answers ----------------------------------------------------------------- */
TEST(cpd_encrypt_kat_aes_fips197) {
    NEED_RSA(); ULONG_PTR p = rsa_aes(&R); REQUIRE(p);
    kat_raw(&R, p, CALG_AES_128, "000102030405060708090a0b0c0d0e0f", CRYPT_MODE_ECB, NULL,
            "00112233445566778899aabbccddeeff", "69c4e0d86a7b0430d8cdb78070b4c55a", "aes128 fips197");
    kat_raw(&R, p, CALG_AES_192, "000102030405060708090a0b0c0d0e0f1011121314151617", CRYPT_MODE_ECB, NULL,
            "00112233445566778899aabbccddeeff", "dda97ca4864cdfe06eaf70a0ec0d7191", "aes192 fips197");
    kat_raw(&R, p, CALG_AES_256, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", CRYPT_MODE_ECB, NULL,
            "00112233445566778899aabbccddeeff", "8ea2b7ca516745bfeafc49904b496089", "aes256 fips197");
    cp_rel(&R, p);
}
TEST(cpd_encrypt_kat_aes_sp800_38a_ecb) {
    NEED_RSA(); ULONG_PTR p = rsa_aes(&R); REQUIRE(p);
    kat_raw(&R, p, CALG_AES_128, "2b7e151628aed2a6abf7158809cf4f3c", CRYPT_MODE_ECB, NULL, NIST_PT_ALL,
            "3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699de785895a96fdbaaf43b1cd7f598ece23881b00e3ed0306887b0c785e27e8ad3f8223207104725dd4", "ecb128 4 blocks");
    kat_raw(&R, p, CALG_AES_192, "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", CRYPT_MODE_ECB, NULL,
            "6bc1bee22e409f96e93d7e117393172a", "bd334f1d6e45f25ff712a214571fa5cc", "ecb192 block 1");
    kat_raw(&R, p, CALG_AES_256, "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", CRYPT_MODE_ECB, NULL,
            "6bc1bee22e409f96e93d7e117393172a", "f3eed1bdb5d2a03c064b5a7e3db181f8", "ecb256 block 1");
    cp_rel(&R, p);
}
TEST(cpd_encrypt_kat_aes_sp800_38a_cbc) {
    NEED_RSA(); ULONG_PTR p = rsa_aes(&R); REQUIRE(p);
    kat_raw(&R, p, CALG_AES_128, "2b7e151628aed2a6abf7158809cf4f3c", CRYPT_MODE_CBC, "000102030405060708090a0b0c0d0e0f", NIST_PT_ALL,
            "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7", "cbc128 4 blocks");
    kat_raw(&R, p, CALG_AES_192, "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", CRYPT_MODE_CBC, "000102030405060708090a0b0c0d0e0f",
            "6bc1bee22e409f96e93d7e117393172a", "4f021db243bc633d7178183a9fa071e8", "cbc192 block 1");
    kat_raw(&R, p, CALG_AES_256, "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", CRYPT_MODE_CBC, "000102030405060708090a0b0c0d0e0f",
            "6bc1bee22e409f96e93d7e117393172a", "f58c4c04d6e5f1ba779eabfb5f7bfbd6", "cbc256 block 1");
    cp_rel(&R, p);
}
TEST(cpd_encrypt_default_mode_is_cbc_with_zero_iv) {
    NEED_RSA(); ULONG_PTR p = rsa_aes(&R); REQUIRE(p);
    BYTE key[16]; hx("2b7e151628aed2a6abf7158809cf4f3c", key);
    ULONG_PTR k = cp_key(&R, p, CALG_AES_128, key, 16); REQUIRE(k);
    BYTE buf[32]; hx("6bc1bee22e409f96e93d7e117393172a", buf); DWORD n = 16;
    OKAY(enc(&R, p, k, FALSE, buf, &n, sizeof buf));
    /* CBC with a zero IV on the first block is the same as ECB */
    BYTE want[16]; hx("3ad77bb40d7a3660a89ecaf32466ef97", want);
    SAMEBYTES(buf, want, 16);
    R.DestroyKey(p, k);
    cp_rel(&R, p);
}
TEST(cpd_encrypt_streaming_chains_cbc_state) {
    NEED_RSA(); ULONG_PTR p = rsa_aes(&R); REQUIRE(p);
    BYTE P[64], C[64], want[64]; hx(NIST_PT_ALL, P);
    hx("7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7", want);
    ULONG_PTR k = mk(&R, p, CALG_AES_128, "2b7e151628aed2a6abf7158809cf4f3c", CRYPT_MODE_CBC, "000102030405060708090a0b0c0d0e0f"); REQUIRE(k);
    for (int i = 0; i < 4; i++) {
        BYTE blk[32]; memcpy(blk, P + 16 * i, 16); DWORD n = 16;
        OKAY(enc(&R, p, k, FALSE, blk, &n, sizeof blk));
        memcpy(C + 16 * i, blk, 16);
    }
    SAMEBYTES(C, want, 64);
    R.DestroyKey(p, k);
    /* decrypt in 2 chunks of 2 blocks */
    k = mk(&R, p, CALG_AES_128, "2b7e151628aed2a6abf7158809cf4f3c", CRYPT_MODE_CBC, "000102030405060708090a0b0c0d0e0f"); REQUIRE(k);
    BYTE out[64]; memcpy(out, want, 64);
    DWORD n = 32;
    OKAY(dec(&R, p, k, FALSE, out, &n)); EXPECT_EQ(n, 32);
    n = 32;
    OKAY(dec(&R, p, k, FALSE, out + 32, &n)); EXPECT_EQ(n, 32);
    SAMEBYTES(out, P, 64);
    R.DestroyKey(p, k);
    cp_rel(&R, p);
}
TEST(cpd_encrypt_cfb8_vector) {
    NEED_RSA(); ULONG_PTR p = rsa_aes(&R); REQUIRE(p);
    ULONG_PTR k = mk(&R, p, CALG_AES_128, "2b7e151628aed2a6abf7158809cf4f3c", CRYPT_MODE_CFB, "000102030405060708090a0b0c0d0e0f"); REQUIRE(k);
    BYTE buf[64]; memcpy(buf, cp_pt30, 30); DWORD n = 30;
    SET_ERR(0);
    BOOL r = R.Encrypt(p, k, 0, FALSE, 0, buf, &n, sizeof buf);
    CHECKF(r, "cfb encrypt err=0x%lx", GetLastError());
    if (r) {
        CHECK(n == 30);
        if (n == 30) { int same = !memcmp(buf, v_aes128_cfb8_ct, 30); CHECK(same); if (!same) t_note("CFB with the default feedback size differs from CFB-8"); }
    }
    R.DestroyKey(p, k);
    cp_rel(&R, p);
}
TEST(cpd_encrypt_cfb_default_mode_bits_note) {
    NEED_RSA(); ULONG_PTR p = rsa_aes(&R); REQUIRE(p);
    BYTE key[16] = { 1 };
    ULONG_PTR k = cp_key(&R, p, CALG_AES_128, key, 16); REQUIRE(k);
    BOOL ok; DWORD v = cp_kp_dw(&R, p, k, KP_MODE_BITS, &ok);
    CHECK(ok);
    t_note("default KP_MODE_BITS of an AES key: %lu", v);
    R.DestroyKey(p, k);
    cp_rel(&R, p);
}

/* ---- padded vectors --------------------------------------------------------------------- */
static void kat_padded(const cpf *f, ULONG_PTR p, ALG_ID alg, const char *key, DWORD mode, const char *iv,
                       const BYTE *ct, DWORD ctlen, const char *what) {
    BYTE buf[128]; DWORD n = 30;
    ULONG_PTR k = mk(f, p, alg, key, mode, iv);
    if (!k) { CHECKF(0, "%s: key failed 0x%lx", what, GetLastError()); return; }
    memcpy(buf, cp_pt30, 30);
    BOOL r = f->Encrypt(p, k, 0, TRUE, 0, buf, &n, sizeof buf);
    CHECKF(r, "%s: encrypt err=0x%lx", what, GetLastError());
    if (r) { CHECKF(n == ctlen, "%s: len %lu want %lu", what, n, ctlen); if (n == ctlen) t_check(!memcmp(buf, ct, ctlen), __FILE__, __LINE__, what, "ciphertext mismatch"); }
    f->DestroyKey(p, k);
    k = mk(f, p, alg, key, mode, iv);
    memcpy(buf, ct, ctlen); n = ctlen;
    r = f->Decrypt(p, k, 0, TRUE, 0, buf, &n);
    CHECKF(r, "%s: decrypt err=0x%lx", what, GetLastError());
    if (r) { CHECKF(n == 30, "%s: plain len %lu", what, n); if (n == 30) t_check(!memcmp(buf, cp_pt30, 30), __FILE__, __LINE__, what, "plaintext mismatch"); }
    f->DestroyKey(p, k);
}
TEST(cpd_encrypt_padded_aes_cbc_vectors) {
    NEED_RSA(); ULONG_PTR p = rsa_aes(&R); REQUIRE(p);
    kat_padded(&R, p, CALG_AES_128, "000102030405060708090a0b0c0d0e0f", CRYPT_MODE_CBC, "0f0e0d0c0b0a09080706050403020100", v_aes128_cbc_ct, sizeof v_aes128_cbc_ct, "aes128 cbc");
    kat_padded(&R, p, CALG_AES_192, "000102030405060708090a0b0c0d0e0f1011121314151617", CRYPT_MODE_CBC, "0f0e0d0c0b0a09080706050403020100", v_aes192_cbc_ct, sizeof v_aes192_cbc_ct, "aes192 cbc");
    kat_padded(&R, p, CALG_AES_256, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", CRYPT_MODE_CBC, "0f0e0d0c0b0a09080706050403020100", v_aes256_cbc_ct, sizeof v_aes256_cbc_ct, "aes256 cbc");
    cp_rel(&R, p);
}
TEST(cpd_encrypt_padded_aes_ecb_vectors) {
    NEED_RSA(); ULONG_PTR p = rsa_aes(&R); REQUIRE(p);
    kat_padded(&R, p, CALG_AES_256, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", CRYPT_MODE_ECB, NULL, v_aes256_ecb_ct, sizeof v_aes256_ecb_ct, "aes256 ecb");
    kat_padded(&R, p, CALG_AES_128, "2b7e151628aed2a6abf7158809cf4f3c", CRYPT_MODE_ECB, NULL, v_aes128_sp_ecb_padded_ct, sizeof v_aes128_sp_ecb_padded_ct, "aes128 ecb");
    cp_rel(&R, p);
}
TEST(cpd_encrypt_padded_des_family_vectors) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    kat_padded(&R, p, CALG_3DES, "0123456789abcdef23456789abcdef01456789abcdef0123", CRYPT_MODE_CBC, "0001020304050607", v_3des_cbc_ct, sizeof v_3des_cbc_ct, "3des cbc");
    kat_padded(&R, p, CALG_DES, "133457799bbcdff1", CRYPT_MODE_CBC, "0001020304050607", v_des_cbc_ct, sizeof v_des_cbc_ct, "des cbc");
    kat_padded(&R, p, CALG_3DES_112, "0123456789abcdef23456789abcdef01", CRYPT_MODE_CBC, "0001020304050607", v_3des112_cbc_ct, sizeof v_3des112_cbc_ct, "3des112 cbc");
    cp_rel(&R, p);
}
TEST(cpd_encrypt_kat_des_classics) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    kat_raw(&R, p, CALG_DES, "133457799bbcdff1", CRYPT_MODE_ECB, NULL, "0123456789abcdef", "85e813540f0ab405", "des ecb classic");
    kat_raw(&R, p, CALG_3DES, "0123456789abcdef23456789abcdef01456789abcdef0123", CRYPT_MODE_ECB, NULL, "4e6f772069732074", "314f8327fa7a09a8", "3des ecb");
    kat_raw(&R, p, CALG_3DES_112, "0123456789abcdef23456789abcdef01", CRYPT_MODE_ECB, NULL, "4e6f772069732074", "b7835779ee26acb7", "3des112 ecb");
    cp_rel(&R, p);
}
TEST(cpd_encrypt_des_key_parity_bits_ignored) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    /* Flipping the parity (low) bit of every key byte must not change the cipher. */
    kat_raw(&R, p, CALG_DES, "133457799bbcdff1", CRYPT_MODE_ECB, NULL, "0123456789abcdef", "85e813540f0ab405", "des parity base");
    kat_raw(&R, p, CALG_DES, "123556789abddef0", CRYPT_MODE_ECB, NULL, "0123456789abcdef", "85e813540f0ab405", "des parity flipped");
    cp_rel(&R, p);
}
TEST(cpd_encrypt_rc4_matches_reference) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    BYTE chk[16], exp[9];
    rc4_ref((const BYTE *)"Key", 3, (const BYTE *)"Plaintext", chk, 9);
    hx("bbf316e8d940af0ad3", exp);
    SAMEBYTES(chk, exp, 9);
    struct { const char *key; } keys[] = { { "0102030405060708090a0b0c0d0e0f10" }, { "ffffffffffffffffffffffffffffffff" }, { "000102030405060708090a0b0c0d0e0f" } };
    for (int i = 0; i < 3; i++) {
        BYTE kb[16]; int kl = hx(keys[i].key, kb);
        ULONG_PTR k = cp_key(&R, p, CALG_RC4, kb, kl); if (!k) { CHECKF(0, "key %d: 0x%lx", i, GetLastError()); continue; }
        BYTE buf[40], want[40]; memcpy(buf, cp_pt30, 30); DWORD n = 30;
        OKAY(R.Encrypt(p, k, 0, TRUE, 0, buf, &n, sizeof buf));
        EXPECT_EQ(n, 30);
        rc4_ref(kb, kl, cp_pt30, want, 30);
        SAMEBYTES(buf, want, 30);
        R.DestroyKey(p, k);
    }
    cp_rel(&R, p);
}
TEST(cpd_encrypt_rc4_vector_openssl) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR k = mk(&R, p, CALG_RC4, "0102030405060708090a0b0c0d0e0f10", 0, NULL); REQUIRE(k);
    BYTE buf[40]; memcpy(buf, cp_pt30, 30); DWORD n = 30;
    OKAY(R.Encrypt(p, k, 0, TRUE, 0, buf, &n, sizeof buf));
    EXPECT_EQ(n, 30);
    SAMEBYTES(buf, v_rc4_128_ct, 30);
    R.DestroyKey(p, k);
    cp_rel(&R, p);
}
TEST(cpd_encrypt_rc4_stream_continues_across_calls) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    BYTE kb[16]; for (int i = 0; i < 16; i++) kb[i] = (BYTE)(i + 1);
    ULONG_PTR k = cp_key(&R, p, CALG_RC4, kb, 16); REQUIRE(k);
    BYTE out[30], want[30]; DWORD n;
    memcpy(out, cp_pt30, 30);
    n = 10; OKAY(R.Encrypt(p, k, 0, FALSE, 0, out, &n, 10));
    n = 7;  OKAY(R.Encrypt(p, k, 0, FALSE, 0, out + 10, &n, 7));
    n = 13; OKAY(R.Encrypt(p, k, 0, TRUE, 0, out + 17, &n, 13));
    rc4_ref(kb, 16, cp_pt30, want, 30);
    SAMEBYTES(out, want, 30);
    R.DestroyKey(p, k);
    cp_rel(&R, p);
}
TEST(cpd_encrypt_rc2_roundtrip_and_openssl_note) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR k = mk(&R, p, CALG_RC2, "0102030405060708090a0b0c0d0e0f10", CRYPT_MODE_CBC, "0001020304050607"); REQUIRE(k);
    BYTE buf[64]; memcpy(buf, cp_pt30, 30); DWORD n = 30;
    OKAY(R.Encrypt(p, k, 0, TRUE, 0, buf, &n, sizeof buf));
    EXPECT_EQ(n, 32);
    t_note("RC2-128 CBC (default effective length) matches the openssl reference: %s", n == 32 && !memcmp(buf, v_rc2_cbc_ct, 32) ? "yes" : "no");
    ULONG_PTR k2 = mk(&R, p, CALG_RC2, "0102030405060708090a0b0c0d0e0f10", CRYPT_MODE_CBC, "0001020304050607");
    OKAY(R.Decrypt(p, k2, 0, TRUE, 0, buf, &n));
    EXPECT_EQ(n, 30);
    SAMEBYTES(buf, cp_pt30, 30);
    R.DestroyKey(p, k); R.DestroyKey(p, k2);
    cp_rel(&R, p);
}

/* ---- padding and length rules ----------------------------------------------------------- */
TEST(cpd_encrypt_final_pads_to_block_boundary) {
    NEED_RSA(); ULONG_PTR p = rsa_aes(&R); REQUIRE(p);
    BYTE key[16] = { 3 };
    ULONG_PTR k = cp_key(&R, p, CALG_AES_128, key, 16); REQUIRE(k);
    DWORD lens[] = { 0, 1, 15, 16, 17, 31, 32, 33 };
    DWORD want[] = { 16, 16, 16, 32, 32, 32, 48, 48 };
    for (size_t i = 0; i < NELEM(lens); i++) {
        BYTE buf[80]; memset(buf, 0x61, sizeof buf); DWORD n = lens[i];
        ULONG_PTR k2 = cp_key(&R, p, CALG_AES_128, key, 16);
        SET_ERR(0);
        BOOL r = R.Encrypt(p, k2, 0, TRUE, 0, buf, &n, sizeof buf);
        CHECKF(r, "len %lu err=0x%lx", lens[i], GetLastError());
        if (r) CHECKF(n == want[i], "len %lu -> %lu want %lu", lens[i], n, want[i]);
        R.DestroyKey(p, k2);
    }
    R.DestroyKey(p, k);
    cp_rel(&R, p);
}
TEST(cpd_encrypt_pkcs5_pad_bytes) {
    NEED_RSA(); ULONG_PTR p = rsa_aes(&R); REQUIRE(p);
    BYTE key[16] = { 9 };
    for (DWORD len = 0; len < 40; len += 7) {
        ULONG_PTR k = cp_key(&R, p, CALG_AES_128, key, 16), k2 = cp_key(&R, p, CALG_AES_128, key, 16); if (!k || !k2) { CHECK(k && k2); continue; }
        cp_set_mode(&R, p, k, CRYPT_MODE_ECB); cp_set_mode(&R, p, k2, CRYPT_MODE_ECB);
        BYTE buf[80]; memset(buf, 0x70, sizeof buf); DWORD n = len;
        OKAY(R.Encrypt(p, k, 0, TRUE, 0, buf, &n, sizeof buf));
        DWORD padded = ((len / 16) + 1) * 16;
        EXPECT_EQ(n, padded);
        /* raw decrypt without removing padding exposes the pad bytes */
        DWORD m = n;
        OKAY(R.Decrypt(p, k2, 0, FALSE, 0, buf, &m));
        if (m == padded) for (DWORD i = len; i < padded; i++) CHECKF(buf[i] == padded - len, "len %lu pad byte %lu = 0x%02x", len, i, buf[i]);
        R.DestroyKey(p, k); R.DestroyKey(p, k2);
    }
    cp_rel(&R, p);
}
TEST(cpd_decrypt_final_removes_padding) {
    NEED_RSA(); ULONG_PTR p = rsa_aes(&R); REQUIRE(p);
    BYTE key[16] = { 4 };
    for (DWORD len = 0; len < 50; len += 5) {
        ULONG_PTR k = cp_key(&R, p, CALG_AES_128, key, 16), k2 = cp_key(&R, p, CALG_AES_128, key, 16); if (!k || !k2) { CHECK(k && k2); continue; }
        BYTE buf[96], pt[64]; for (DWORD i = 0; i < len; i++) pt[i] = (BYTE)(i * 3 + 1);
        memcpy(buf, pt, len); DWORD n = len;
        OKAY(R.Encrypt(p, k, 0, TRUE, 0, buf, &n, sizeof buf));
        OKAY(R.Decrypt(p, k2, 0, TRUE, 0, buf, &n));
        EXPECT_EQ(n, len);
        if (n == len) SAMEBYTES(buf, pt, len);
        R.DestroyKey(p, k); R.DestroyKey(p, k2);
    }
    cp_rel(&R, p);
}
TEST(cpd_decrypt_bad_padding_bad_data) {
    NEED_RSA(); ULONG_PTR p = rsa_aes(&R); REQUIRE(p);
    BYTE key[16] = { 5 };
    struct { const char *last16; } t[] = {
        { "00000000000000000000000000000000" },   /* pad byte 0 */
        { "00000000000000000000000000000011" },   /* pad byte 17 */
        { "00000000000000000000000000000102" },   /* inconsistent */
        { "01010101010101010101010101010100" },
    };
    for (size_t i = 0; i < NELEM(t); i++) {
        ULONG_PTR k = cp_key(&R, p, CALG_AES_128, key, 16), k2 = cp_key(&R, p, CALG_AES_128, key, 16);
        cp_set_mode(&R, p, k, CRYPT_MODE_ECB); cp_set_mode(&R, p, k2, CRYPT_MODE_ECB);
        BYTE buf[32]; hx(t[i].last16, buf); DWORD n = 16;
        OKAY(R.Encrypt(p, k, 0, FALSE, 0, buf, &n, sizeof buf));
        n = 16;
        FAILS(R.Decrypt(p, k2, 0, TRUE, 0, buf, &n), CPE_BAD_DATA);
        R.DestroyKey(p, k); R.DestroyKey(p, k2);
    }
    cp_rel(&R, p);
}
TEST(cpd_decrypt_final_length_not_block_multiple) {
    NEED_RSA(); ULONG_PTR p = rsa_aes(&R); REQUIRE(p);
    BYTE key[16] = { 6 };
    DWORD bad[] = { 1, 15, 17, 31 };
    for (size_t i = 0; i < NELEM(bad); i++) {
        ULONG_PTR k = cp_key(&R, p, CALG_AES_128, key, 16);
        BYTE buf[64] = { 0 }; DWORD n = bad[i];
        FAILS(R.Decrypt(p, k, 0, TRUE, 0, buf, &n), CPE_BAD_DATA);
        R.DestroyKey(p, k);
    }
    cp_rel(&R, p);
}
TEST(cpd_decrypt_zero_length_final_bad_len) {
    NEED_RSA(); ULONG_PTR p = rsa_aes(&R); REQUIRE(p);
    BYTE key[16] = { 6 };
    ULONG_PTR k = cp_key(&R, p, CALG_AES_128, key, 16); REQUIRE(k);
    BYTE buf[16]; DWORD n = 0;
    FAILS(R.Decrypt(p, k, 0, TRUE, 0, buf, &n), CPE_BAD_LEN);
    n = 0;
    OKAY(R.Decrypt(p, k, 0, FALSE, 0, buf, &n));
    EXPECT_EQ(n, 0);
    /* length is tested before any handle: zero handles give the same results */
    n = 0;
    FAILS(R.Decrypt(0, 0, 0, TRUE, 0, buf, &n), CPE_BAD_LEN);
    n = 0;
    OKAY(R.Decrypt(0, 0, 0, FALSE, 0, buf, &n));
    R.DestroyKey(p, k);
    cp_rel(&R, p);
}
TEST(cpd_encrypt_zero_length_nonfinal_is_noop_success) {
    NEED_RSA();
    /* The shortcut precedes the provider/key lookups. */
    BYTE buf[16]; DWORD n = 0;
    OKAY(R.Encrypt(0, 0, 0, FALSE, 0, buf, &n, sizeof buf));
    EXPECT_EQ(n, 0);
    n = 0;
    OKAY(R.Encrypt(0, 0, 0, FALSE, 0, NULL, &n, 0));
}
TEST(cpd_encrypt_nonfinal_short_data_bad_data_reports_block) {
    NEED_RSA(); ULONG_PTR p = rsa_aes(&R); REQUIRE(p);
    BYTE key[16] = { 7 };
    DWORD lens[] = { 1, 5, 15 };
    for (size_t i = 0; i < NELEM(lens); i++) {
        ULONG_PTR k = cp_key(&R, p, CALG_AES_128, key, 16);
        BYTE buf[48] = { 0 }; DWORD n = lens[i];
        FAILS(R.Encrypt(p, k, 0, FALSE, 0, buf, &n, sizeof buf), CPE_BAD_DATA);
        EXPECT_EQ(n, 16);
        R.DestroyKey(p, k);
    }
    ULONG_PTR kd = cp_key(&R, p, CALG_DES, key, 8);
    BYTE buf[16] = { 0 }; DWORD n = 3;
    FAILS(R.Encrypt(p, kd, 0, FALSE, 0, buf, &n, sizeof buf), CPE_BAD_DATA);
    EXPECT_EQ(n, 8);
    R.DestroyKey(p, kd);
    cp_rel(&R, p);
}
TEST(cpd_encrypt_nonfinal_unaligned_longer_data_note) {
    NEED_RSA(); ULONG_PTR p = rsa_aes(&R); REQUIRE(p);
    BYTE key[16] = { 7 };
    ULONG_PTR k = cp_key(&R, p, CALG_AES_128, key, 16);
    BYTE buf[48] = { 0 }; DWORD n = 20;
    SET_ERR(0);
    BOOL r = R.Encrypt(p, k, 0, FALSE, 0, buf, &n, sizeof buf);
    t_note("non-final encrypt of 20 bytes (AES): %d err=0x%lx n=%lu", r, GetLastError(), n);
    R.DestroyKey(p, k);
    cp_rel(&R, p);
}
TEST(cpd_encrypt_buffer_protocol_with_padding) {
    NEED_RSA(); ULONG_PTR p = rsa_aes(&R); REQUIRE(p);
    BYTE key[16] = { 8 };
    ULONG_PTR k = cp_key(&R, p, CALG_AES_128, key, 16); REQUIRE(k);
    BYTE buf[64]; memcpy(buf, cp_pt30, 30);
    DWORD n = 30;
    OKAY(R.Encrypt(p, k, 0, TRUE, 0, NULL, &n, 0));
    EXPECT_EQ(n, 32);
    n = 30;
    FAILS(R.Encrypt(p, k, 0, TRUE, 0, buf, &n, 31), ERROR_MORE_DATA);
    EXPECT_EQ(n, 32);
    n = 30;
    FAILS(R.Encrypt(p, k, 0, TRUE, 0, buf, &n, 30), ERROR_MORE_DATA);
    EXPECT_EQ(n, 32);
    /* the failed attempts must not have consumed the key's chaining state */
    n = 30; memcpy(buf, cp_pt30, 30);
    OKAY(R.Encrypt(p, k, 0, TRUE, 0, buf, &n, 32));
    EXPECT_EQ(n, 32);
    R.DestroyKey(p, k);
    cp_rel(&R, p);
}
TEST(cpd_encrypt_exact_fit_final_aligned_needs_extra_block) {
    NEED_RSA(); ULONG_PTR p = rsa_aes(&R); REQUIRE(p);
    BYTE key[16] = { 8 };
    ULONG_PTR k = cp_key(&R, p, CALG_AES_128, key, 16); REQUIRE(k);
    BYTE buf[64] = { 1 };
    DWORD n = 16;
    FAILS(R.Encrypt(p, k, 0, TRUE, 0, buf, &n, 16), ERROR_MORE_DATA);
    EXPECT_EQ(n, 32);
    n = 16;
    OKAY(R.Encrypt(p, k, 0, TRUE, 0, buf, &n, 32));
    EXPECT_EQ(n, 32);
    R.DestroyKey(p, k);
    cp_rel(&R, p);
}
TEST(cpd_encrypt_stream_cipher_no_expansion_and_size_query) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    BYTE key[16] = { 8 };
    ULONG_PTR k = cp_key(&R, p, CALG_RC4, key, 16); REQUIRE(k);
    BYTE buf[40]; memcpy(buf, cp_pt30, 30);
    DWORD n = 30;
    OKAY(R.Encrypt(p, k, 0, TRUE, 0, NULL, &n, 0));
    EXPECT_EQ(n, 30);
    n = 30;
    OKAY(R.Encrypt(p, k, 0, TRUE, 0, buf, &n, 30));
    EXPECT_EQ(n, 30);
    R.DestroyKey(p, k);
    cp_rel(&R, p);
}
TEST(cpd_decrypt_stream_roundtrip_final_flag_irrelevant) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    BYTE key[16] = { 9, 9 };
    ULONG_PTR a = cp_key(&R, p, CALG_RC4, key, 16), b = cp_key(&R, p, CALG_RC4, key, 16); REQUIRE(a && b);
    BYTE buf[30]; memcpy(buf, cp_pt30, 30); DWORD n = 30;
    OKAY(R.Encrypt(p, a, 0, FALSE, 0, buf, &n, 30));
    CHECK(memcmp(buf, cp_pt30, 30) != 0);
    n = 30;
    OKAY(R.Decrypt(p, b, 0, TRUE, 0, buf, &n));
    EXPECT_EQ(n, 30);
    SAMEBYTES(buf, cp_pt30, 30);
    R.DestroyKey(p, a); R.DestroyKey(p, b);
    cp_rel(&R, p);
}

/* ---- parameter validation --------------------------------------------------------------- */
TEST(cpd_encrypt_flags_checked_first) {
    NEED_RSA();
    BYTE buf[16] = { 0 }; DWORD n = 16;
    DWORD bad[] = { 0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x80, 0x100, 0x8000, 0x80000000 };
    for (size_t i = 0; i < NELEM(bad); i++) { n = 16; FAILS(R.Encrypt(0, 0, 0, TRUE, bad[i], buf, &n, 16), CPE_BAD_FLAGS); }
    n = 0;
    FAILS(R.Encrypt(0, 0, 0, FALSE, 0x1, buf, &n, 16), CPE_BAD_FLAGS);
}
TEST(cpd_decrypt_flags_checked_first) {
    NEED_RSA();
    BYTE buf[16] = { 0 }; DWORD n = 16;
    DWORD bad[] = { 0x1, 0x2, 0x4, 0x8, 0x10, 0x80, 0x100, 0x8000, 0x80000000, 0x60 };
    for (size_t i = 0; i < NELEM(bad); i++) { n = 16; FAILS(R.Decrypt(0, 0, 0, TRUE, bad[i], buf, &n), CPE_BAD_FLAGS); }
}
TEST(cpd_encrypt_wrong_handle_kinds) {
    NEED_RSA(); ULONG_PTR p = rsa_aes(&R), p2 = rsa_aes(&R); REQUIRE(p && p2);
    BYTE key[16] = { 2 };
    ULONG_PTR k = cp_key(&R, p, CALG_AES_128, key, 16), h = cp_mkhash(&R, p, CALG_MD5);
    BYTE buf[48] = { 0 }; DWORD n;
    if (k && h) {
        n = 16; FAILS(R.Encrypt(k, k, 0, FALSE, 0, buf, &n, 48), CPE_BAD_UID);
        n = 16; FAILS(R.Encrypt(p, h, 0, FALSE, 0, buf, &n, 48), CPE_BAD_KEY);
        n = 16; FAILS(R.Encrypt(p2, k, 0, FALSE, 0, buf, &n, 48), CPE_BAD_UID);
        n = 16; FAILS(R.Encrypt(p, p, 0, FALSE, 0, buf, &n, 48), CPE_BAD_KEY);
    }
    if (k) R.DestroyKey(p, k);
    if (h) R.DestroyHash(p, h);
    cp_rel(&R, p); cp_rel(&R, p2);
}
TEST(cpd_decrypt_wrong_handle_kinds) {
    NEED_RSA(); ULONG_PTR p = rsa_aes(&R), p2 = rsa_aes(&R); REQUIRE(p && p2);
    BYTE key[16] = { 2 };
    ULONG_PTR k = cp_key(&R, p, CALG_AES_128, key, 16), h = cp_mkhash(&R, p, CALG_MD5);
    BYTE buf[48] = { 0 }; DWORD n;
    if (k && h) {
        n = 16; FAILS(R.Decrypt(k, k, 0, FALSE, 0, buf, &n), CPE_BAD_UID);
        n = 16; FAILS(R.Decrypt(p, h, 0, FALSE, 0, buf, &n), CPE_BAD_KEY);
        n = 16; FAILS(R.Decrypt(p2, k, 0, FALSE, 0, buf, &n), CPE_BAD_UID);
    }
    if (k) R.DestroyKey(p, k);
    if (h) R.DestroyHash(p, h);
    cp_rel(&R, p); cp_rel(&R, p2);
}
TEST(cpd_encrypt_with_hash_hashes_plaintext) {
    NEED_RSA(); ULONG_PTR p = rsa_aes(&R); REQUIRE(p);
    BYTE key[16] = { 2 };
    ULONG_PTR k = cp_key(&R, p, CALG_AES_128, key, 16), h = cp_mkhash(&R, p, CALG_MD5); REQUIRE(k && h);
    BYTE buf[48]; memcpy(buf, cp_pt30, 30); DWORD n = 30;
    OKAY(R.Encrypt(p, k, h, TRUE, 0, buf, &n, sizeof buf));
    EXPECT_EQ(n, 32);
    BYTE got[16], want[16]; DWORD gl = 16;
    OKAY(R.GetHashParam(p, h, HP_HASHVAL, got, &gl, 0));
    EXPECT_EQ(cp_hash(&R, p, CALG_MD5, cp_pt30, 30, want, 16), 16);
    SAMEBYTES(got, want, 16);
    R.DestroyHash(p, h);
    h = cp_mkhash(&R, p, CALG_MD5);
    ULONG_PTR k2 = cp_key(&R, p, CALG_AES_128, key, 16);
    OKAY(R.Decrypt(p, k2, h, TRUE, 0, buf, &n));
    EXPECT_EQ(n, 30);
    gl = 16;
    OKAY(R.GetHashParam(p, h, HP_HASHVAL, got, &gl, 0));
    SAMEBYTES(got, want, 16);
    R.DestroyHash(p, h); R.DestroyKey(p, k); R.DestroyKey(p, k2);
    cp_rel(&R, p);
}
TEST(cpd_encrypt_with_finished_hash_fails) {
    NEED_RSA(); ULONG_PTR p = rsa_aes(&R); REQUIRE(p);
    BYTE key[16] = { 2 };
    ULONG_PTR k = cp_key(&R, p, CALG_AES_128, key, 16), h = cp_mkhash(&R, p, CALG_MD5); REQUIRE(k && h);
    BYTE d[16]; DWORD dl = 16;
    OKAY(R.GetHashParam(p, h, HP_HASHVAL, d, &dl, 0));
    BYTE buf[48]; memcpy(buf, cp_pt30, 30); DWORD n = 30;
    SET_ERR(0);
    BOOL r = R.Encrypt(p, k, h, TRUE, 0, buf, &n, sizeof buf);
    CHECK(!r);
    if (!r) EXPECT_ERR(CPE_BAD_HASH_STATE);
    R.DestroyHash(p, h); R.DestroyKey(p, k);
    cp_rel(&R, p);
}
TEST(cpd_encrypt_with_wrong_kind_as_hash_fails) {
    NEED_RSA(); ULONG_PTR p = rsa_aes(&R); REQUIRE(p);
    BYTE key[16] = { 2 };
    ULONG_PTR k = cp_key(&R, p, CALG_AES_128, key, 16); REQUIRE(k);
    BYTE buf[48]; memcpy(buf, cp_pt30, 30); DWORD n = 30;
    SET_ERR(0);
    BOOL r = R.Encrypt(p, k, k, TRUE, 0, buf, &n, sizeof buf);
    CHECK(!r);
    if (!r) t_note("Encrypt with a key handle as hHash -> 0x%lx", GetLastError());
    R.DestroyKey(p, k);
    cp_rel(&R, p);
}
TEST(cpd_encrypt_key_from_derivekey_roundtrip_across_providers) {
    NEED_RSA(); ULONG_PTR a = rsa_aes(&R), b = rsa_aes(&R); REQUIRE(a && b);
    ULONG_PTR k1 = 0, k2 = 0;
    for (int i = 0; i < 2; i++) {
        ULONG_PTR pp = i ? b : a;
        ULONG_PTR h = cp_mkhash(&R, pp, CALG_SHA_256);
        OKAY(R.HashData(pp, h, (const BYTE *)"shared secret", 13, 0));
        OKAY(R.DeriveKey(pp, CALG_AES_256, h, 0, i ? &k2 : &k1));
        R.DestroyHash(pp, h);
    }
    if (k1 && k2) {
        BYTE buf[64]; memcpy(buf, cp_pt30, 30); DWORD n = 30;
        OKAY(R.Encrypt(a, k1, 0, TRUE, 0, buf, &n, sizeof buf));
        OKAY(R.Decrypt(b, k2, 0, TRUE, 0, buf, &n));
        EXPECT_EQ(n, 30);
        SAMEBYTES(buf, cp_pt30, 30);
    }
    if (k1) R.DestroyKey(a, k1);
    if (k2) R.DestroyKey(b, k2);
    cp_rel(&R, a); cp_rel(&R, b);
}

/* ---- RSA encrypt/decrypt ---------------------------------------------------------------- */
static ULONG_PTR rsa_import_priv(const cpf *f, ULONG_PTR p) {
    ULONG_PTR k = 0;
    if (!f->ImportKey(p, rsa_priv_blob, sizeof rsa_priv_blob, 0, 0, &k)) return 0;
    return k;
}
TEST(cpd_rsa_decrypt_pkcs1_vector) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR k = rsa_import_priv(&R, p); REQUIRE(k);
    BYTE buf[128]; memcpy(buf, rsa_ct_pkcs1_hello, 128); DWORD n = 128;
    OKAY(R.Decrypt(p, k, 0, TRUE, 0, buf, &n));
    EXPECT_EQ(n, 9);
    if (n == 9) t_check(!memcmp(buf, "hello csp", 9), __FILE__, __LINE__, "plaintext", "mismatch");
    R.DestroyKey(p, k);
    cp_rel(&R, p);
}
TEST(cpd_rsa_decrypt_oaep_vector) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR k = rsa_import_priv(&R, p); REQUIRE(k);
    BYTE buf[128]; memcpy(buf, rsa_ct_oaep_hello, 128); DWORD n = 128;
    OKAY(R.Decrypt(p, k, 0, TRUE, CRYPT_OAEP, buf, &n));
    EXPECT_EQ(n, 10);
    if (n == 10) t_check(!memcmp(buf, "hello oaep", 10), __FILE__, __LINE__, "plaintext", "mismatch");
    /* The same ciphertext fails as PKCS#1 v1.5, and the PKCS#1 vector fails as OAEP */
    memcpy(buf, rsa_ct_oaep_hello, 128); n = 128;
    SET_ERR(0);
    CHECK(!R.Decrypt(p, k, 0, TRUE, 0, buf, &n));
    memcpy(buf, rsa_ct_pkcs1_hello, 128); n = 128;
    SET_ERR(0);
    CHECK(!R.Decrypt(p, k, 0, TRUE, CRYPT_OAEP, buf, &n));
    R.DestroyKey(p, k);
    cp_rel(&R, p);
}
TEST(cpd_rsa_decrypt_tampered_ciphertext) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR k = rsa_import_priv(&R, p); REQUIRE(k);
    for (int pos = 0; pos < 128; pos += 9) {
        BYTE buf[128]; memcpy(buf, rsa_ct_pkcs1_hello, 128); buf[pos] ^= 1; DWORD n = 128;
        SET_ERR(0);
        BOOL r = R.Decrypt(p, k, 0, TRUE, 0, buf, &n);
        CHECKF(!r, "tampered byte %d decrypted", pos);
        if (!r) EXPECT_ERR(CPE_BAD_DATA);
    }
    R.DestroyKey(p, k);
    cp_rel(&R, p);
}
TEST(cpd_rsa_decrypt_wrong_length) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR k = rsa_import_priv(&R, p); REQUIRE(k);
    DWORD lens[] = { 1, 127, 129, 256 };
    for (size_t i = 0; i < NELEM(lens); i++) {
        BYTE buf[300]; memset(buf, 1, sizeof buf); DWORD n = lens[i];
        SET_ERR(0);
        BOOL r = R.Decrypt(p, k, 0, TRUE, 0, buf, &n);
        CHECKF(!r, "length %lu decrypted", lens[i]);
        if (!r) t_note("RSA decrypt of %lu bytes -> 0x%lx", lens[i], GetLastError());
    }
    R.DestroyKey(p, k);
    cp_rel(&R, p);
}
TEST(cpd_rsa_encrypt_roundtrip_and_sizes) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR k = rsa_import_priv(&R, p); REQUIRE(k);
    BYTE buf[200]; DWORD n = 11;
    memcpy(buf, "hello world", 11);
    OKAY(R.Encrypt(p, k, 0, TRUE, 0, NULL, &n, 0));
    EXPECT_EQ(n, 128);
    n = 11;
    FAILS(R.Encrypt(p, k, 0, TRUE, 0, buf, &n, 127), ERROR_MORE_DATA);
    EXPECT_EQ(n, 128);
    n = 11;
    OKAY(R.Encrypt(p, k, 0, TRUE, 0, buf, &n, sizeof buf));
    EXPECT_EQ(n, 128);
    DWORD m = n;
    BYTE c2[128]; memcpy(c2, buf, 128);
    OKAY(R.Decrypt(p, k, 0, TRUE, 0, buf, &m));
    EXPECT_EQ(m, 11);
    if (m == 11) SAMEBYTES(buf, "hello world", 11);
    /* PKCS#1 type 2 padding is randomised */
    BYTE b2[200]; memcpy(b2, "hello world", 11); n = 11;
    OKAY(R.Encrypt(p, k, 0, TRUE, 0, b2, &n, sizeof b2));
    CHECK(memcmp(b2, c2, 128) != 0);
    R.DestroyKey(p, k);
    cp_rel(&R, p);
}
TEST(cpd_rsa_encrypt_max_plaintext_lengths) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR k = rsa_import_priv(&R, p); REQUIRE(k);
    BYTE buf[300]; memset(buf, 'x', sizeof buf);
    DWORD n = 117;
    OKAY(R.Encrypt(p, k, 0, TRUE, 0, buf, &n, sizeof buf));
    EXPECT_EQ(n, 128);
    memset(buf, 'x', sizeof buf); n = 118;
    FAILS(R.Encrypt(p, k, 0, TRUE, 0, buf, &n, sizeof buf), CPE_BAD_LEN);
    n = 118;
    FAILS(R.Encrypt(p, k, 0, TRUE, 0, NULL, &n, 0), CPE_BAD_LEN);
    /* OAEP with SHA-1: 128 - 2*20 - 2 = 86 */
    memset(buf, 'x', sizeof buf); n = 86;
    OKAY(R.Encrypt(p, k, 0, TRUE, CRYPT_OAEP, buf, &n, sizeof buf));
    EXPECT_EQ(n, 128);
    memset(buf, 'x', sizeof buf); n = 87;
    FAILS(R.Encrypt(p, k, 0, TRUE, CRYPT_OAEP, buf, &n, sizeof buf), CPE_BAD_LEN);
    R.DestroyKey(p, k);
    cp_rel(&R, p);
}
TEST(cpd_rsa_encrypt_public_key_only_roundtrip) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR pub = 0;
    OKAY(R.ImportKey(p, rsa_pub_blob, sizeof rsa_pub_blob, 0, 0, &pub)); REQUIRE(pub);
    BYTE buf[200]; DWORD n = 5;
    memcpy(buf, "abcde", 5);
    OKAY(R.Encrypt(p, pub, 0, TRUE, 0, buf, &n, sizeof buf));
    EXPECT_EQ(n, 128);
    ULONG_PTR priv = rsa_import_priv(&R, p); REQUIRE(priv);
    OKAY(R.Decrypt(p, priv, 0, TRUE, 0, buf, &n));
    EXPECT_EQ(n, 5);
    if (n == 5) SAMEBYTES(buf, "abcde", 5);
    /* a public-only key cannot decrypt */
    memcpy(buf, rsa_ct_pkcs1_hello, 128); n = 128;
    SET_ERR(0);
    CHECK(!R.Decrypt(p, pub, 0, TRUE, 0, buf, &n));
    t_note("Decrypt with a public-only key -> 0x%lx", GetLastError());
    R.DestroyKey(p, pub); R.DestroyKey(p, priv);
    cp_rel(&R, p);
}
TEST(cpd_rsa_decrypt_no_padding_check_flag) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR k = rsa_import_priv(&R, p); REQUIRE(k);
    BYTE buf[128]; memcpy(buf, rsa_ct_pkcs1_hello, 128); DWORD n = 128;
    SET_ERR(0);
    BOOL r = R.Decrypt(p, k, 0, TRUE, CRYPT_DECRYPT_RSA_NO_PADDING_CHECK, buf, &n);
    if (r) {
        EXPECT_EQ(n, 128);
        CHECK(buf[0] == 0 || buf[127] == 0);
        t_note("NO_PADDING_CHECK decrypt returns %lu bytes", n);
    } else t_note("NO_PADDING_CHECK decrypt fails 0x%lx", GetLastError());
    memcpy(buf, rsa_ct_pkcs1_hello, 128); n = 128;
    FAILS(R.Decrypt(p, k, 0, TRUE, CRYPT_DECRYPT_RSA_NO_PADDING_CHECK | CRYPT_OAEP, buf, &n), CPE_BAD_FLAGS);
    R.DestroyKey(p, k);
    cp_rel(&R, p);
}
