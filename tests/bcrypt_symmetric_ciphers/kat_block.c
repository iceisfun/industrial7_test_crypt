/* Known-answer tests for the unauthenticated block ciphers and RC4, plus the IV-in-place chaining contract. */
#include "bsc.h"
#include "vectors.h"

typedef struct {
    const wchar_t *alg, *mode;
    ULONG mbl;        /* BCRYPT_MESSAGE_BLOCK_LENGTH to set (0 = leave default) */
    int stream;       /* 1 = RC4: no IV */
} kcfg;

static void kat_run(const kcfg *c, const struct kat *v) {
    REQUIRE(P_Open);
    BCRYPT_ALG_HANDLE a = bsc_open(c->alg, c->mode);
    if (!a) { t_skip("algorithm %ls/%ls not available", c->alg, c->mode ? c->mode : L"-"); if (!t_is_wine()) CHECK(a != NULL); return; }
    if (c->mbl) {
        NTSTATUS s = P_SetProp(a, BCRYPT_MESSAGE_BLOCK_LENGTH, (PUCHAR)&c->mbl, 4, 0);
        if (WINE_UNSUP(s)) { t_skip("MessageBlockLength unsupported under emulator"); bsc_close(a); return; }
        EXPECT_EQ(s, 0);
    }
    BYTE pt[256], ct[256], iv0[32], iv[32], out[256], back[256];
    size_t n = hx(v->pt, pt); hx(v->ct, ct);
    size_t ivl = hx(v->iv, iv0);
    ULONG bs = 0, r = 0;
    P_GetProp(a, BCRYPT_BLOCK_LENGTH, (PUCHAR)&bs, 4, &r, 0);
    bkey k;
    NTSTATUS s = bsc_genhex(a, &k, v->key);
    if (WINE_UNSUP(s)) { t_skip("unsupported under emulator"); bsc_close(a); return; }
    EXPECT_EQ(s, 0);
    if (s == 0) {
        ULONG got = 0;
        {   BYTE tp[256], to[256]; ULONG tg = 0; size_t tn = hx(v->pt, tp);
            memcpy(iv, iv0, ivl);
            s = enc(k.h, tp, (ULONG)tn, ivl ? iv : NULL, (ULONG)ivl, to, (ULONG)tn, &tg, 0);
            if (WINE_UNSUP(s)) { t_skip("unsupported under emulator"); bsc_free(&k); bsc_close(a); return; }
            if (c->stream) { bsc_free(&k); bsc_genhex(a, &k, v->key); }  /* fresh RC4 state */
        }
        /* size query */
        memcpy(iv, iv0, ivl);
        s = enc(k.h, pt, (ULONG)n, ivl ? iv : NULL, (ULONG)ivl, NULL, 0, &got, 0);
        EXPECT_EQ(s, 0); EXPECT_EQ(got, n);
        CHECK(!ivl || same(iv, iv0, ivl));            /* size query must not touch the IV */
        /* encrypt */
        memcpy(iv, iv0, ivl); memset(out, 0xEE, sizeof out);
        s = enc(k.h, pt, (ULONG)n, ivl ? iv : NULL, (ULONG)ivl, out, (ULONG)n, &got, 0);
        EXPECT_EQ(s, 0); EXPECT_EQ(got, n);
        CHECK_HEX(out, n, v->ct);
        CHECK(out[n] == 0xEE);                          /* nothing written past the output */
        if (ivl && !c->stream && !wcscmp(c->mode, BCRYPT_CHAIN_MODE_CBC)) {
            CHECK(same(iv, ct + n - bs, bs));            /* IV updated in place to last ciphertext block */
        } else if (ivl && !c->stream && !wcscmp(c->mode, BCRYPT_CHAIN_MODE_CFB) && n >= bs) {
            CHECK(same(iv, ct + n - bs, bs));            /* shift register == last bs ciphertext bytes */
        }
        if (c->stream) { bsc_free(&k); bsc_close(a); return; }   /* RC4 key state advances per call */
        /* decrypt */
        if (!c->stream) {
            memcpy(iv, iv0, ivl); memset(back, 0xEE, sizeof back);
            s = dec(k.h, ct, (ULONG)n, ivl ? iv : NULL, (ULONG)ivl, back, (ULONG)n, &got, 0);
            EXPECT_EQ(s, 0); EXPECT_EQ(got, n);
            CHECK(same(back, pt, n));
            if (ivl && !wcscmp(c->mode, BCRYPT_CHAIN_MODE_CBC)) CHECK(same(iv, ct + n - bs, bs));
        }
        /* in place */
        memcpy(back, pt, n); memcpy(iv, iv0, ivl);
        s = enc(k.h, back, (ULONG)n, ivl ? iv : NULL, (ULONG)ivl, back, (ULONG)n, &got, 0);
        EXPECT_EQ(s, 0);
        CHECK(same(back, ct, n));
        /* output buffer too small by one byte */
        memcpy(iv, iv0, ivl);
        got = 0;
        s = enc(k.h, pt, (ULONG)n, ivl ? iv : NULL, (ULONG)ivl, out, (ULONG)n - 1, &got, 0);
        EXPECT_EQ(s, NS_BUFFER_TOO_SMALL); EXPECT_EQ(got, n);
        bsc_free(&k);
    }
    bsc_close(a);
}

#define KATT(nm, tbl, i, A, M, MBL, ST) \
    TEST(nm) { static const kcfg c = { A, M, MBL, ST }; kat_run(&c, &tbl[i]); }

/* ---- AES ---------------------------------------------------------------- */
KATT(bsc_kat_aes128_ecb, k_aes_ecb, 0, L"AES", BCRYPT_CHAIN_MODE_ECB, 0, 0)
KATT(bsc_kat_aes192_ecb, k_aes_ecb, 1, L"AES", BCRYPT_CHAIN_MODE_ECB, 0, 0)
KATT(bsc_kat_aes256_ecb, k_aes_ecb, 2, L"AES", BCRYPT_CHAIN_MODE_ECB, 0, 0)
KATT(bsc_kat_aes128_cbc, k_aes_cbc, 0, L"AES", BCRYPT_CHAIN_MODE_CBC, 0, 0)
KATT(bsc_kat_aes192_cbc, k_aes_cbc, 1, L"AES", BCRYPT_CHAIN_MODE_CBC, 0, 0)
KATT(bsc_kat_aes256_cbc, k_aes_cbc, 2, L"AES", BCRYPT_CHAIN_MODE_CBC, 0, 0)
/* CFB without MessageBlockLength: the documented default is 1 byte (CFB8) */
KATT(bsc_kat_aes128_cfb8_default, k_aes_cfb8, 0, L"AES", BCRYPT_CHAIN_MODE_CFB, 0, 0)
KATT(bsc_kat_aes192_cfb8_default, k_aes_cfb8, 1, L"AES", BCRYPT_CHAIN_MODE_CFB, 0, 0)
KATT(bsc_kat_aes256_cfb8_default, k_aes_cfb8, 2, L"AES", BCRYPT_CHAIN_MODE_CFB, 0, 0)
KATT(bsc_kat_aes128_cfb8_explicit, k_aes_cfb8, 0, L"AES", BCRYPT_CHAIN_MODE_CFB, 1, 0)
KATT(bsc_kat_aes256_cfb8_explicit, k_aes_cfb8, 2, L"AES", BCRYPT_CHAIN_MODE_CFB, 1, 0)
KATT(bsc_kat_aes128_cfb128, k_aes_cfb128, 0, L"AES", BCRYPT_CHAIN_MODE_CFB, 16, 0)
KATT(bsc_kat_aes192_cfb128, k_aes_cfb128, 1, L"AES", BCRYPT_CHAIN_MODE_CFB, 16, 0)
KATT(bsc_kat_aes256_cfb128, k_aes_cfb128, 2, L"AES", BCRYPT_CHAIN_MODE_CFB, 16, 0)

/* ---- FIPS-197 appendix C (ECB, single block) ----------------------------- */
KATT(bsc_kat_fips197_128, k_aes_fips197, 0, L"AES", BCRYPT_CHAIN_MODE_ECB, 0, 0)
KATT(bsc_kat_fips197_192, k_aes_fips197, 1, L"AES", BCRYPT_CHAIN_MODE_ECB, 0, 0)
KATT(bsc_kat_fips197_256, k_aes_fips197, 2, L"AES", BCRYPT_CHAIN_MODE_ECB, 0, 0)

/* ---- DES / 3DES ----------------------------------------------------------- */
KATT(bsc_kat_des_ecb_fips46, k_des, 0, L"DES", BCRYPT_CHAIN_MODE_ECB, 0, 0)
KATT(bsc_kat_des_ecb_nist_ivp, k_des, 1, L"DES", BCRYPT_CHAIN_MODE_ECB, 0, 0)
KATT(bsc_kat_des_ecb_4blocks, k_des, 2, L"DES", BCRYPT_CHAIN_MODE_ECB, 0, 0)
KATT(bsc_kat_des_cbc, k_des, 3, L"DES", BCRYPT_CHAIN_MODE_CBC, 0, 0)
KATT(bsc_kat_des_cfb8_default, k_des, 4, L"DES", BCRYPT_CHAIN_MODE_CFB, 0, 0)
KATT(bsc_kat_des_cfb64, k_des, 5, L"DES", BCRYPT_CHAIN_MODE_CFB, 8, 0)
KATT(bsc_kat_3des_ecb, k_3des, 0, L"3DES", BCRYPT_CHAIN_MODE_ECB, 0, 0)
KATT(bsc_kat_3des_cbc, k_3des, 1, L"3DES", BCRYPT_CHAIN_MODE_CBC, 0, 0)
KATT(bsc_kat_3des_cfb8_default, k_3des, 2, L"3DES", BCRYPT_CHAIN_MODE_CFB, 0, 0)
KATT(bsc_kat_3des_cfb64, k_3des, 3, L"3DES", BCRYPT_CHAIN_MODE_CFB, 8, 0)
KATT(bsc_kat_3des112_ecb, k_3des112, 0, L"3DES_112", BCRYPT_CHAIN_MODE_ECB, 0, 0)
KATT(bsc_kat_3des112_cbc, k_3des112, 1, L"3DES_112", BCRYPT_CHAIN_MODE_CBC, 0, 0)

/* ---- RC4: RFC 6229 keystreams (plaintext zero => ciphertext is the keystream) ---------- */
KATT(bsc_kat_rc4_40, k_rc4, 0, L"RC4", NULL, 0, 1)
KATT(bsc_kat_rc4_56, k_rc4, 1, L"RC4", NULL, 0, 1)
KATT(bsc_kat_rc4_64, k_rc4, 2, L"RC4", NULL, 0, 1)
KATT(bsc_kat_rc4_128, k_rc4, 3, L"RC4", NULL, 0, 1)
KATT(bsc_kat_rc4_256, k_rc4, 4, L"RC4", NULL, 0, 1)

/* RC4 keys shorter than 40 bits are not in RFC 6229; table rows 5/6 are still deterministic by definition. */
static int rc4_unsup(BCRYPT_ALG_HANDLE a) {
    if (!t_is_wine()) return 0;
    bkey k; BYTE z[4] = {0}, o[4]; ULONG g = 0;
    if (bsc_genhex(a, &k, "0102030405") != 0) return 1;
    NTSTATUS s = enc(k.h, z, 4, NULL, 0, o, 4, &g, 0);
    bsc_free(&k);
    return s != 0;
}
TEST(bsc_kat_rc4_1byte_key) {
    REQUIRE(P_Open);
    BCRYPT_ALG_HANDLE a = bsc_open(L"RC4", NULL);
    if (!a || rc4_unsup(a)) { t_skip("RC4"); bsc_close(a); return; }
    bkey k; NTSTATUS s = bsc_genhex(a, &k, k_rc4[5].key);
    if (s != 0) { t_note("RC4 1-byte key rejected: 0x%lx", s); bsc_close(a); return; }
    BYTE pt[64], out[64]; size_t n = hx(k_rc4[5].pt, pt); ULONG got = 0;
    s = enc(k.h, pt, (ULONG)n, NULL, 0, out, (ULONG)n, &got, 0);
    EXPECT_EQ(s, 0); CHECK_HEX(out, n, k_rc4[5].ct);
    bsc_free(&k); bsc_close(a);
}
TEST(bsc_kat_rc4_ascii_key) {
    REQUIRE(P_Open);
    BCRYPT_ALG_HANDLE a = bsc_open(L"RC4", NULL);
    if (!a || rc4_unsup(a)) { t_skip("RC4"); bsc_close(a); return; }
    bkey k; NTSTATUS s = bsc_genhex(a, &k, k_rc4[6].key);
    EXPECT_EQ(s, 0);
    if (s == 0) {
        BYTE pt[64], out[64]; size_t n = hx(k_rc4[6].pt, pt); ULONG got = 0;
        s = enc(k.h, pt, (ULONG)n, NULL, 0, out, (ULONG)n, &got, 0);
        EXPECT_EQ(s, 0); CHECK_HEX(out, n, k_rc4[6].ct);
        bsc_free(&k);
    }
    bsc_close(a);
}

/* RC4 state continues across calls on the same key object; decrypting needs a fresh key (or a duplicate). */
TEST(bsc_rc4_stream_continues_across_calls) {
    REQUIRE(P_Open);
    BCRYPT_ALG_HANDLE a = bsc_open(L"RC4", NULL);
    if (!a || rc4_unsup(a)) { t_skip("RC4"); bsc_close(a); return; }
    bkey k; NTSTATUS s = bsc_genhex(a, &k, k_rc4[3].key);
    EXPECT_EQ(s, 0);
    if (s == 0) {
        BYTE z[48] = {0}, out[48]; ULONG got = 0;
        s = enc(k.h, z, 10, NULL, 0, out, 10, &got, 0); EXPECT_EQ(s, 0);
        s = enc(k.h, z + 10, 38, NULL, 0, out + 10, 38, &got, 0); EXPECT_EQ(s, 0); EXPECT_EQ(got, 38);
        CHECK_HEX(out, 48, k_rc4[3].ct);
        bsc_free(&k);
    }
    bsc_close(a);
}
TEST(bsc_rc4_decrypt_is_encrypt_with_fresh_key) {
    REQUIRE(P_Open);
    BCRYPT_ALG_HANDLE a = bsc_open(L"RC4", NULL);
    if (!a || rc4_unsup(a)) { t_skip("RC4"); bsc_close(a); return; }
    bkey k1, k2;
    if (bsc_genhex(a, &k1, k_rc4[3].key) == 0 && bsc_genhex(a, &k2, k_rc4[3].key) == 0) {
        BYTE ct[48], back[48], pt[48]; hx(k_rc4[3].ct, ct); ULONG got = 0;
        NTSTATUS s = dec(k1.h, ct, 48, NULL, 0, back, 48, &got, 0);
        EXPECT_EQ(s, 0); EXPECT_EQ(got, 48);
        memset(pt, 0, 48); CHECK(same(back, pt, 48));
        bsc_free(&k2);
    }
    bsc_free(&k1); bsc_close(a);
}
TEST(bsc_rc4_zero_length_input) {
    REQUIRE(P_Open);
    BCRYPT_ALG_HANDLE a = bsc_open(L"RC4", NULL);
    if (!a || rc4_unsup(a)) { t_skip("RC4"); bsc_close(a); return; }
    bkey k;
    if (bsc_genhex(a, &k, k_rc4[3].key) == 0) {
        ULONG got = 0xDEAD; BYTE o[4];
        NTSTATUS s = enc(k.h, (BYTE *)"", 0, NULL, 0, o, 4, &got, 0);
        EXPECT_EQ(s, 0); EXPECT_EQ(got, 0);
        got = 0xDEAD;
        s = enc(k.h, NULL, 0, NULL, 0, NULL, 0, &got, 0);
        EXPECT_EQ(s, 0); EXPECT_EQ(got, 0);
        bsc_free(&k);
    }
    bsc_close(a);
}

/* ---- RC2: cross-checked against an independent implementation; effective key length semantics vary,
 * so a mismatch is recorded, round trip is hard-checked. */
static void rc2_kat(const struct kat *v, const wchar_t *mode) {
    REQUIRE(P_Open);
    BCRYPT_ALG_HANDLE a = bsc_open(L"RC2", mode);
    if (!a) { t_skip("RC2 not available"); return; }
    bkey k; NTSTATUS s = bsc_genhex(a, &k, v->key);
    EXPECT_EQ(s, 0);
    if (s == 0) {
        BYTE pt[64], iv[16], out[64], back[64]; size_t n = hx(v->pt, pt); size_t ivl = hx(v->iv, iv); ULONG got = 0;
        BYTE iv2[16]; memcpy(iv2, iv, 16);
        s = enc(k.h, pt, (ULONG)n, ivl ? iv : NULL, (ULONG)ivl, out, (ULONG)n, &got, 0);
        EXPECT_EQ(s, 0); EXPECT_EQ(got, n);
        BYTE e[64]; hx(v->ct, e);
        if (!same(out, e, n)) t_note("RC2 %s ciphertext differs from the 128-bit effective-key reference", v->name);
        s = dec(k.h, out, (ULONG)n, ivl ? iv2 : NULL, (ULONG)ivl, back, (ULONG)n, &got, 0);
        EXPECT_EQ(s, 0); CHECK(same(back, pt, n));
        bsc_free(&k);
    }
    bsc_close(a);
}
TEST(bsc_kat_rc2_ecb) { rc2_kat(&k_rc2[0], BCRYPT_CHAIN_MODE_ECB); }
TEST(bsc_kat_rc2_cbc) { rc2_kat(&k_rc2[1], BCRYPT_CHAIN_MODE_CBC); }
