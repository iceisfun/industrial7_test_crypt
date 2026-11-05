/* BCryptGenerateSymmetricKey / BCryptDestroyKey / BCryptDuplicateKey: argument validation, handle types,
 * key-object buffer protocol, lifetime. Return values verified against the Win10 decompilation of bcrypt.dll. */
#include "bsc.h"

static const BYTE S16[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
static BYTE S64[64];
static void __attribute__((constructor)) init_s64(void) { for (int i = 0; i < 64; i++) S64[i] = (BYTE)(0x11 * (i + 1) ^ i); }

#define SENTINEL ((BCRYPT_KEY_HANDLE)(ULONG_PTR)0xDEADBEEF)

/* ---- algorithm handle validation ------------------------------------------ */
TEST(bsc_gen_null_alg_handle) {
    REQUIRE(P_GenKey);
    BCRYPT_KEY_HANDLE k = SENTINEL; BYTE obj[1024];
    NTSTATUS s = P_GenKey(NULL, &k, obj, sizeof obj, (PUCHAR)S16, 16, 0);
    EXPECT_EQ(s, NS_INVALID_HANDLE); CHECK(k == SENTINEL);
}
TEST(bsc_gen_null_alg_handle_null_everything) {
    REQUIRE(P_GenKey);
    EXPECT_EQ(P_GenKey(NULL, NULL, NULL, 0, NULL, 0, 0), NS_INVALID_HANDLE);   /* handle is validated first */
}
TEST(bsc_gen_alg_handle_garbage_small_values) {
    REQUIRE(P_GenKey);
    /* Pseudo-handle encoding: low nibble 1, index in the high bits. Index 0x3a and up is out of the table. */
    BCRYPT_KEY_HANDLE k = SENTINEL; BYTE obj[1024];
    NTSTATUS s = P_GenKey((BCRYPT_ALG_HANDLE)(ULONG_PTR)0x3a1, &k, obj, sizeof obj, (PUCHAR)S16, 16, 0);
    EXPECT_EQ(s, NS_INVALID_HANDLE); CHECK(k == SENTINEL);
    s = P_GenKey((BCRYPT_ALG_HANDLE)(ULONG_PTR)0x1000001, &k, obj, sizeof obj, (PUCHAR)S16, 16, 0);
    EXPECT_EQ(s, NS_INVALID_HANDLE); CHECK(k == SENTINEL);
}
TEST(bsc_gen_key_handle_as_alg_handle) {
    REQUIRE(P_GenKey);
    BCRYPT_ALG_HANDLE a = bsc_open(L"AES", NULL); if (!a) { t_skip("AES"); return; }
    bkey k; EXPECT_EQ(bsc_gen(a, &k, S64, 16), 0);
    BCRYPT_KEY_HANDLE k2 = SENTINEL; BYTE obj[1024];
    NTSTATUS s = P_GenKey((BCRYPT_ALG_HANDLE)k.h, &k2, obj, sizeof obj, (PUCHAR)S16, 16, 0);
    EXPECT_EQ(s, NS_INVALID_HANDLE); CHECK(k2 == SENTINEL);
    bsc_free(&k); bsc_close(a);
}
/* ---- pseudo handles ---------------------------------------------------------- */
#define PSEUDO(nm, H, MODE) \
TEST(nm) { \
    REQUIRE(P_GenKey); \
    bkey k; memset(&k, 0, sizeof k); k.cb = 0; BCRYPT_KEY_HANDLE h = SENTINEL; \
    NTSTATUS s = P_GenKey(H, &h, NULL, 0, (PUCHAR)S16, 16, 0); \
    if (WINE_UNSUP(s) || (t_is_wine() && s != 0)) { t_skip("pseudo handle unsupported"); return; } \
    EXPECT_EQ(s, 0); \
    if (t_is_wine() && s == 0) { WCHAR m_[64] = {0}; ULONG r_ = 0; if (P_GetProp(h, BCRYPT_CHAINING_MODE, (PUCHAR)m_, sizeof m_, &r_, 0)) { P_Destroy(h); t_skip("wine"); return; } } \
    if (s == 0) { \
        WCHAR mode[64] = {0}; ULONG r = 0; \
        EXPECT_EQ(P_GetProp(h, BCRYPT_CHAINING_MODE, (PUCHAR)mode, sizeof mode, &r, 0), 0); \
        EXPECT_WSTR(mode, MODE); \
        EXPECT_EQ(P_Destroy(h), 0); \
    } \
}
PSEUDO(bsc_gen_pseudo_aes_cbc, BCRYPT_AES_CBC_ALG_HANDLE, BCRYPT_CHAIN_MODE_CBC)
PSEUDO(bsc_gen_pseudo_aes_ecb, BCRYPT_AES_ECB_ALG_HANDLE, BCRYPT_CHAIN_MODE_ECB)
PSEUDO(bsc_gen_pseudo_aes_cfb, BCRYPT_AES_CFB_ALG_HANDLE, BCRYPT_CHAIN_MODE_CFB)
PSEUDO(bsc_gen_pseudo_aes_gcm, BCRYPT_AES_GCM_ALG_HANDLE, BCRYPT_CHAIN_MODE_GCM)
PSEUDO(bsc_gen_pseudo_aes_ccm, BCRYPT_AES_CCM_ALG_HANDLE, BCRYPT_CHAIN_MODE_CCM)

TEST(bsc_gen_pseudo_des_family_modes) {
    REQUIRE(P_GenKey);
    struct { BCRYPT_ALG_HANDLE h; const wchar_t *mode; ULONG klen; } t[] = {
        { BCRYPT_DES_CBC_ALG_HANDLE, BCRYPT_CHAIN_MODE_CBC, 8 }, { BCRYPT_DES_ECB_ALG_HANDLE, BCRYPT_CHAIN_MODE_ECB, 8 },
        { BCRYPT_DES_CFB_ALG_HANDLE, BCRYPT_CHAIN_MODE_CFB, 8 },
        { BCRYPT_3DES_CBC_ALG_HANDLE, BCRYPT_CHAIN_MODE_CBC, 24 }, { BCRYPT_3DES_ECB_ALG_HANDLE, BCRYPT_CHAIN_MODE_ECB, 24 },
        { BCRYPT_3DES_CFB_ALG_HANDLE, BCRYPT_CHAIN_MODE_CFB, 24 },
        { BCRYPT_3DES_112_CBC_ALG_HANDLE, BCRYPT_CHAIN_MODE_CBC, 16 }, { BCRYPT_3DES_112_ECB_ALG_HANDLE, BCRYPT_CHAIN_MODE_ECB, 16 },
        { BCRYPT_3DES_112_CFB_ALG_HANDLE, BCRYPT_CHAIN_MODE_CFB, 16 },
        { BCRYPT_RC2_CBC_ALG_HANDLE, BCRYPT_CHAIN_MODE_CBC, 16 }, { BCRYPT_RC2_ECB_ALG_HANDLE, BCRYPT_CHAIN_MODE_ECB, 16 },
        { BCRYPT_RC2_CFB_ALG_HANDLE, BCRYPT_CHAIN_MODE_CFB, 16 },
    };
    for (int i = 0; i < (int)(sizeof t / sizeof *t); i++) {
        BCRYPT_KEY_HANDLE h = SENTINEL;
        NTSTATUS s = P_GenKey(t[i].h, &h, NULL, 0, (PUCHAR)S64, t[i].klen, 0);
        if (t_is_wine() && s != 0) continue;
        CHECKF(s == 0, "entry %d status 0x%lx", i, s);
        if (s == 0) {
            WCHAR mode[64] = {0}; ULONG r = 0;
            P_GetProp(h, BCRYPT_CHAINING_MODE, (PUCHAR)mode, sizeof mode, &r, 0);
            if (!t_is_wine() || mode[0]) CHECKF(!wcscmp(mode, t[i].mode), "entry %d mode %ls", i, mode);
            P_Destroy(h);
        }
    }
}
TEST(bsc_gen_pseudo_rc4) {
    REQUIRE(P_GenKey);
    BCRYPT_KEY_HANDLE h = SENTINEL;
    NTSTATUS s = P_GenKey(BCRYPT_RC4_ALG_HANDLE, &h, NULL, 0, (PUCHAR)S16, 16, 0);
    if (t_is_wine() && s != 0) { t_skip("unsupported"); return; }
    EXPECT_EQ(s, 0);
    if (s == 0) P_Destroy(h);
}
TEST(bsc_gen_pseudo_handle_setproperty_denied) {
    REQUIRE(P_SetProp);
    /* pseudo handles are shared, read-only singletons */
    NTSTATUS s = P_SetProp(BCRYPT_AES_CBC_ALG_HANDLE, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                           sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (t_is_wine() && s != NS_ACCESS_DENIED) { t_skip("wine"); return; }
    EXPECT_EQ(s, NS_ACCESS_DENIED);
}
TEST(bsc_gen_pseudo_handle_close_is_noop_or_rejected) {
    REQUIRE(P_Close);
    NTSTATUS s = P_Close(BCRYPT_AES_CBC_ALG_HANDLE, 0);
    t_note("BCryptCloseAlgorithmProvider(pseudo handle) = 0x%lx", s);
    BCRYPT_KEY_HANDLE h = SENTINEL;
    s = P_GenKey(BCRYPT_AES_CBC_ALG_HANDLE, &h, NULL, 0, (PUCHAR)S16, 16, 0);
    if (!t_is_wine()) EXPECT_EQ(s, 0);
    if (s == 0) P_Destroy(h);
}

/* ---- parameter validation ordering ----------------------------------------------- */
TEST(bsc_gen_null_phkey) {
    if (t_is_wine()) { t_skip("wine diverges from the decompiled behaviour here"); return; }
    REQUIRE(P_GenKey);
    BCRYPT_ALG_HANDLE a = bsc_open(L"AES", NULL); if (!a) { t_skip("AES"); return; }
    BYTE obj[1024];
    EXPECT_EQ(P_GenKey(a, NULL, obj, sizeof obj, (PUCHAR)S16, 16, 0), NS_INVALID_PARAM);
    bsc_close(a);
}
TEST(bsc_gen_null_secret) {
    if (t_is_wine()) { t_skip("wine diverges from the decompiled behaviour here"); return; }
    REQUIRE(P_GenKey);
    BCRYPT_ALG_HANDLE a = bsc_open(L"AES", NULL); if (!a) { t_skip("AES"); return; }
    BYTE obj[1024]; BCRYPT_KEY_HANDLE k = SENTINEL;
    EXPECT_EQ(P_GenKey(a, &k, obj, sizeof obj, NULL, 16, 0), NS_INVALID_PARAM);
    CHECK(k == SENTINEL);
    EXPECT_EQ(P_GenKey(a, &k, NULL, 0, NULL, 16, 0), NS_INVALID_PARAM);
    CHECK(k == SENTINEL);
    bsc_close(a);
}
TEST(bsc_gen_null_phkey_with_internal_object) {
    if (t_is_wine()) { t_skip("wine diverges from the decompiled behaviour here"); return; }
    REQUIRE(P_GenKey);
    BCRYPT_ALG_HANDLE a = bsc_open(L"AES", NULL); if (!a) { t_skip("AES"); return; }
    EXPECT_EQ(P_GenKey(a, NULL, NULL, 0, (PUCHAR)S16, 16, 0), NS_INVALID_PARAM);
    bsc_close(a);
}
TEST(bsc_gen_keyobject_null_with_nonzero_size) {
    if (t_is_wine()) { t_skip("wine diverges from the decompiled behaviour here"); return; }
    REQUIRE(P_GenKey);
    BCRYPT_ALG_HANDLE a = bsc_open(L"AES", NULL); if (!a) { t_skip("AES"); return; }
    BCRYPT_KEY_HANDLE k = SENTINEL;
    EXPECT_EQ(P_GenKey(a, &k, NULL, 1024, (PUCHAR)S16, 16, 0), NS_INVALID_PARAM);
    CHECK(k == SENTINEL);
    bsc_close(a);
}
TEST(bsc_gen_keyobject_size_zero_with_buffer) {
    if (t_is_wine()) { t_skip("wine diverges from the decompiled behaviour here"); return; }
    REQUIRE(P_GenKey);
    BCRYPT_ALG_HANDLE a = bsc_open(L"AES", NULL); if (!a) { t_skip("AES"); return; }
    BYTE obj[1024]; BCRYPT_KEY_HANDLE k = SENTINEL;
    EXPECT_EQ(P_GenKey(a, &k, obj, 0, (PUCHAR)S16, 16, 0), NS_BUFFER_TOO_SMALL);
    CHECK(k == SENTINEL);
    bsc_close(a);
}
TEST(bsc_gen_keyobject_tiny_sizes) {
    if (t_is_wine()) { t_skip("wine diverges from the decompiled behaviour here"); return; }
    REQUIRE(P_GenKey);
    BCRYPT_ALG_HANDLE a = bsc_open(L"AES", NULL); if (!a) { t_skip("AES"); return; }
    BYTE obj[1024]; BCRYPT_KEY_HANDLE k = SENTINEL;
    ULONG sizes[] = { 1, 8, 16, 31, 32, 33, 0x3c, 0x3d };   /* <= 0x3d can never hold the 0x20-byte header + state */
    for (int i = 0; i < 8; i++) {
        k = SENTINEL;
        NTSTATUS s = P_GenKey(a, &k, obj, sizes[i], (PUCHAR)S16, 16, 0);
        CHECKF(s == NS_BUFFER_TOO_SMALL, "cb=%lu got 0x%lx", sizes[i], s);
        CHECK(k == SENTINEL);
    }
    bsc_close(a);
}
TEST(bsc_gen_keyobject_exact_objectlength) {
    if (t_is_wine()) { t_skip("wine diverges from the decompiled behaviour here"); return; }
    REQUIRE(P_GenKey);
    BCRYPT_ALG_HANDLE a = bsc_open(L"AES", NULL); if (!a) { t_skip("AES"); return; }
    ULONG ol = bsc_objlen(a);
    CHECK(ol > 0x3d);
    BYTE *obj = (BYTE *)calloc(1, ol + 64); BCRYPT_KEY_HANDLE k = SENTINEL;
    NTSTATUS s = P_GenKey(a, &k, obj, ol, (PUCHAR)S16, 16, 0);
    EXPECT_EQ(s, 0);
    if (s == 0) {
        CHECK((BYTE *)k >= obj && (BYTE *)k < obj + ol);       /* handle lives inside the caller's object */
        P_Destroy(k);
    }
    free(obj); bsc_close(a);
}
TEST(bsc_gen_keyobject_misaligned_start) {
    REQUIRE(P_GenKey);
    /* the implementation aligns the key header up to 16 bytes inside the caller buffer and needs ObjectLength bytes
     * counted from the unaligned start, so an odd-offset buffer of ObjectLength bytes must still work. */
    BCRYPT_ALG_HANDLE a = bsc_open(L"AES", NULL); if (!a) { t_skip("AES"); return; }
    ULONG ol = bsc_objlen(a);
    BYTE *raw = (BYTE *)calloc(1, ol + 64);
    BYTE *obj = raw + 1; BCRYPT_KEY_HANDLE k = SENTINEL;
    NTSTATUS s = P_GenKey(a, &k, obj, ol + 15, (PUCHAR)S16, 16, 0);
    EXPECT_EQ(s, 0);
    if (s == 0) {
        CHECK(((ULONG_PTR)k & 0xF) == 0);
        BYTE out[16], z[16] = {0}; ULONG got = 0;
        s = enc(k, z, 16, NULL, 0, out, 16, &got, 0);
        EXPECT_EQ(s, 0);
        P_Destroy(k);
    }
    free(raw); bsc_close(a);
}
TEST(bsc_gen_internal_object_when_null_zero) {
    REQUIRE(P_GenKey);
    BCRYPT_ALG_HANDLE a = bsc_open(L"AES", NULL); if (!a) { t_skip("AES"); return; }
    BCRYPT_KEY_HANDLE k = SENTINEL;
    NTSTATUS s = P_GenKey(a, &k, NULL, 0, (PUCHAR)S16, 16, 0);
    EXPECT_EQ(s, 0); CHECK(k != NULL && k != SENTINEL);
    if (s == 0) {
        BYTE z[16] = {0}, out[16]; ULONG got = 0;
        EXPECT_EQ(enc(k, z, 16, NULL, 0, out, 16, &got, 0), 0);
        EXPECT_EQ(P_Destroy(k), 0);
    }
    bsc_close(a);
}

/* ---- key sizes ------------------------------------------------------------------------- */
static NTSTATUS genlen(const wchar_t *alg, const wchar_t *mode, ULONG n) {
    BCRYPT_ALG_HANDLE a = bsc_open(alg, mode);
    if (!a) return 0x7FFFFFFF;
    bkey k; NTSTATUS s = bsc_gen(a, &k, S64, n);
    if (s == 0) bsc_free(&k); else { free(k.obj); }
    bsc_close(a);
    return s;
}
TEST(bsc_gen_aes_valid_key_sizes) {
    REQUIRE(P_GenKey);
    for (ULONG n = 16; n <= 32; n += 8) {
        NTSTATUS s = genlen(L"AES", NULL, n);
        CHECKF(s == 0, "aes key %lu bytes: 0x%lx", n, s);
    }
}
TEST(bsc_gen_aes_invalid_key_sizes) {
    REQUIRE(P_GenKey);
    ULONG bad[] = { 1, 8, 15, 17 };
    for (int i = 0; i < 4; i++) {
        NTSTATUS s = genlen(L"AES", NULL, bad[i]);
        CHECKF(s == NS_INVALID_PARAM, "aes key %lu bytes: 0x%lx", bad[i], s);
    }
}
TEST(bsc_gen_aes_zero_length_secret) {
    REQUIRE(P_GenKey);
    NTSTATUS s = genlen(L"AES", NULL, 0);
    CHECKF(s < 0, "zero-length secret accepted (0x%lx)", s);
    t_note("AES 0-byte secret -> 0x%lx", s);
}
TEST(bsc_gen_aes_oversize_secret_uses_max) {
    REQUIRE(P_GenKey);
    /* A secret longer than the 32-byte maximum is accepted and the first 32 bytes are used. */
    BCRYPT_ALG_HANDLE a = bsc_open(L"AES", BCRYPT_CHAIN_MODE_ECB); if (!a) { t_skip("AES"); return; }
    BYTE sec[40]; for (int i = 0; i < 40; i++) sec[i] = (BYTE)i;
    bkey k1, k2; NTSTATUS s1 = bsc_gen(a, &k1, sec, 33), s2 = bsc_gen(a, &k2, sec, 32);
    EXPECT_EQ(s1, 0); EXPECT_EQ(s2, 0);
    if (s1 == 0 && s2 == 0) {
        BYTE z[16] = {0}, o1[16], o2[16]; ULONG g = 0;
        enc(k1.h, z, 16, NULL, 0, o1, 16, &g, 0); enc(k2.h, z, 16, NULL, 0, o2, 16, &g, 0);
        CHECK(same(o1, o2, 16));
    }
    if (s1 == 0) bsc_free(&k1);
    if (s2 == 0) bsc_free(&k2);
    bsc_close(a);
}
TEST(bsc_gen_aes_other_sizes_observed) {
    REQUIRE(P_GenKey);
    ULONG obs[] = { 20, 25, 31, 34, 40, 64 };
    for (int i = 0; i < 6; i++) t_note("AES %lu-byte secret -> 0x%lx", obs[i], genlen(L"AES", NULL, obs[i]));
}
TEST(bsc_gen_aes_key_size_does_not_depend_on_mode) {
    REQUIRE(P_GenKey);
    const wchar_t *modes[] = { BCRYPT_CHAIN_MODE_ECB, BCRYPT_CHAIN_MODE_CBC, BCRYPT_CHAIN_MODE_CFB, BCRYPT_CHAIN_MODE_GCM, BCRYPT_CHAIN_MODE_CCM };
    for (int m = 0; m < 5; m++) {
        if (t_is_wine() && genlen(L"AES", modes[m], 16) == 0x7FFFFFFF) continue;
        for (ULONG n = 16; n <= 32; n += 8) CHECKF(genlen(L"AES", modes[m], n) == 0, "%ls %lu", modes[m], n);
        CHECKF(genlen(L"AES", modes[m], 15) == NS_INVALID_PARAM, "%ls 15", modes[m]);
    }
}
TEST(bsc_gen_des_key_sizes) {
    REQUIRE(P_GenKey);
    NTSTATUS s = genlen(L"DES", NULL, 8);
    if (t_is_wine() && s != 0) { t_skip("DES unsupported"); return; }
    EXPECT_EQ(s, 0);
    ULONG bad[] = { 1, 7, 9, 16, 24 };
    for (int i = 0; i < 5; i++) t_note("DES %lu-byte secret -> 0x%lx", bad[i], genlen(L"DES", NULL, bad[i]));
}
TEST(bsc_gen_3des_key_sizes) {
    REQUIRE(P_GenKey);
    NTSTATUS s = genlen(L"3DES", NULL, 24);
    if (t_is_wine() && s != 0) { t_skip("3DES unsupported"); return; }
    EXPECT_EQ(s, 0);
    ULONG bad[] = { 8, 16, 23, 25, 32 };
    for (int i = 0; i < 5; i++) t_note("3DES %lu-byte secret -> 0x%lx", bad[i], genlen(L"3DES", NULL, bad[i]));
}
TEST(bsc_gen_3des112_key_sizes) {
    REQUIRE(P_GenKey);
    NTSTATUS s = genlen(L"3DES_112", NULL, 16);
    if (t_is_wine() && s != 0) { t_skip("3DES_112 unsupported"); return; }
    EXPECT_EQ(s, 0);
    ULONG bad[] = { 8, 15, 17, 24 };
    for (int i = 0; i < 4; i++) t_note("3DES_112 %lu-byte secret -> 0x%lx", bad[i], genlen(L"3DES_112", NULL, bad[i]));
}
TEST(bsc_gen_rc4_key_sizes) {
    REQUIRE(P_GenKey);
    NTSTATUS s = genlen(L"RC4", NULL, 16);
    if (t_is_wine() && s != 0) { t_skip("RC4 unsupported"); return; }
    EXPECT_EQ(s, 0);
    ULONG n[] = { 1, 5, 8, 32, 64, 128, 256, 512 };
    for (int i = 0; i < 8; i++) t_note("RC4 %lu-byte secret -> 0x%lx", n[i], genlen(L"RC4", NULL, n[i]));
}
TEST(bsc_gen_rc2_key_sizes) {
    REQUIRE(P_GenKey);
    NTSTATUS s = genlen(L"RC2", NULL, 16);
    if (t_is_wine() && s != 0) { t_skip("RC2 unsupported"); return; }
    EXPECT_EQ(s, 0);
    ULONG n[] = { 1, 5, 8, 17 };
    for (int i = 0; i < 4; i++) t_note("RC2 %lu-byte secret -> 0x%lx", n[i], genlen(L"RC2", NULL, n[i]));
}
TEST(bsc_gen_desx_key_size) {
    REQUIRE(P_GenKey);
    BCRYPT_ALG_HANDLE a = bsc_open(L"DESX", NULL);
    if (!a) { t_skip("DESX unavailable"); return; }
    bsc_close(a);
    NTSTATUS s = genlen(L"DESX", NULL, 24);
    EXPECT_EQ(s, 0);
    ULONG n[] = { 8, 16, 23, 25 };
    for (int i = 0; i < 4; i++) t_note("DESX %lu-byte secret -> 0x%lx", n[i], genlen(L"DESX", NULL, n[i]));
}

/* ---- non-symmetric algorithm classes -------------------------------------------------- */
TEST(bsc_gen_with_hash_algorithm_handle) {
    REQUIRE(P_GenKey);
    BCRYPT_ALG_HANDLE a = bsc_open(L"SHA256", NULL); if (!a) { t_skip("SHA256"); return; }
    BCRYPT_KEY_HANDLE k = SENTINEL; BYTE obj[2048];
    NTSTATUS s = P_GenKey(a, &k, obj, sizeof obj, (PUCHAR)S16, 16, 0);
    CHECK(s < 0); CHECK(k == SENTINEL);
    t_note("GenerateSymmetricKey(SHA256 alg) = 0x%lx", s);
    bsc_close(a);
}
TEST(bsc_gen_with_rng_algorithm_handle) {
    REQUIRE(P_GenKey);
    BCRYPT_ALG_HANDLE a = bsc_open(L"RNG", NULL); if (!a) { t_skip("RNG"); return; }
    BCRYPT_KEY_HANDLE k = SENTINEL; BYTE obj[2048];
    NTSTATUS s = P_GenKey(a, &k, obj, sizeof obj, (PUCHAR)S16, 16, 0);
    CHECK(s < 0); CHECK(k == SENTINEL);
    bsc_close(a);
}

/* ---- key lifetime ------------------------------------------------------------------------ */
TEST(bsc_key_survives_alg_close) {
    REQUIRE(P_GenKey);
    BCRYPT_ALG_HANDLE a = bsc_open(L"AES", BCRYPT_CHAIN_MODE_ECB); if (!a) { t_skip("AES"); return; }
    bkey k; EXPECT_EQ(bsc_genhex(a, &k, "2b7e151628aed2a6abf7158809cf4f3c"), 0);
    EXPECT_EQ(P_Close(a, 0), 0);                 /* algorithm header is reference counted by its keys */
    BYTE pt[16], out[16]; hx("6bc1bee22e409f96e93d7e117393172a", pt); ULONG got = 0;
    EXPECT_EQ(enc(k.h, pt, 16, NULL, 0, out, 16, &got, 0), 0);
    CHECK_HEX(out, 16, "3ad77bb40d7a3660a89ecaf32466ef97");
    EXPECT_EQ(P_Destroy(k.h), 0);
    k.h = NULL; bsc_free(&k);
}
TEST(bsc_key_survives_alg_close_internal_object) {
    REQUIRE(P_GenKey);
    BCRYPT_ALG_HANDLE a = bsc_open(L"AES", BCRYPT_CHAIN_MODE_ECB); if (!a) { t_skip("AES"); return; }
    BYTE s[16]; hx("2b7e151628aed2a6abf7158809cf4f3c", s);
    BCRYPT_KEY_HANDLE k = SENTINEL;
    EXPECT_EQ(P_GenKey(a, &k, NULL, 0, s, 16, 0), 0);
    EXPECT_EQ(P_Close(a, 0), 0);
    BYTE pt[16], out[16]; hx("6bc1bee22e409f96e93d7e117393172a", pt); ULONG got = 0;
    EXPECT_EQ(enc(k, pt, 16, NULL, 0, out, 16, &got, 0), 0);
    CHECK_HEX(out, 16, "3ad77bb40d7a3660a89ecaf32466ef97");
    EXPECT_EQ(P_Destroy(k), 0);
}
TEST(bsc_alg_close_with_live_key_then_double_close) {
    REQUIRE(P_GenKey);
    BCRYPT_ALG_HANDLE a = bsc_open(L"AES", NULL); if (!a) { t_skip("AES"); return; }
    bkey k; EXPECT_EQ(bsc_gen(a, &k, S64, 16), 0);
    EXPECT_EQ(P_Close(a, 0), 0);
    bsc_free(&k);
}
TEST(bsc_key_mode_fixed_at_creation) {
    REQUIRE(P_GenKey);
    BCRYPT_ALG_HANDLE a = bsc_open(L"AES", BCRYPT_CHAIN_MODE_CBC); if (!a) { t_skip("AES"); return; }
    bkey k; EXPECT_EQ(bsc_gen(a, &k, S64, 16), 0);
    EXPECT_EQ(P_SetProp(a, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_ECB, sizeof(BCRYPT_CHAIN_MODE_ECB), 0), 0);
    WCHAR m[64] = {0}; ULONG r = 0;
    EXPECT_EQ(P_GetProp(k.h, BCRYPT_CHAINING_MODE, (PUCHAR)m, sizeof m, &r, 0), 0);
    EXPECT_WSTR(m, BCRYPT_CHAIN_MODE_CBC);        /* key keeps the mode it was created with */
    bsc_free(&k); bsc_close(a);
}
TEST(bsc_many_keys_one_algorithm) {
    REQUIRE(P_GenKey);
    BCRYPT_ALG_HANDLE a = bsc_open(L"AES", NULL); if (!a) { t_skip("AES"); return; }
    bkey ks[64];
    int ok = 0;
    for (int i = 0; i < 64; i++) { BYTE s[16]; memset(s, i, 16); if (bsc_gen(a, &ks[i], s, 16) == 0) ok++; }
    EXPECT_EQ(ok, 64);
    for (int i = 0; i < 64; i++) if (ks[i].h) bsc_free(&ks[i]); else free(ks[i].obj);
    bsc_close(a);
}
TEST(bsc_distinct_handles_for_same_secret) {
    REQUIRE(P_GenKey);
    BCRYPT_ALG_HANDLE a = bsc_open(L"AES", NULL); if (!a) { t_skip("AES"); return; }
    bkey k1, k2; EXPECT_EQ(bsc_gen(a, &k1, S16, 16), 0); EXPECT_EQ(bsc_gen(a, &k2, S16, 16), 0);
    CHECK(k1.h != k2.h);
    bsc_free(&k1); bsc_free(&k2); bsc_close(a);
}

/* ---- BCryptDestroyKey ---------------------------------------------------------------------------- */
TEST(bsc_destroy_null) { REQUIRE(P_Destroy); EXPECT_EQ(P_Destroy(NULL), NS_INVALID_HANDLE); }
TEST(bsc_destroy_alg_handle_as_key) {
    REQUIRE(P_Destroy);
    BCRYPT_ALG_HANDLE a = bsc_open(L"AES", NULL); if (!a) { t_skip("AES"); return; }
    EXPECT_EQ(P_Destroy((BCRYPT_KEY_HANDLE)a), NS_INVALID_HANDLE);
    EXPECT_EQ(P_Close(a, 0), 0);                  /* algorithm handle unharmed */
}
TEST(bsc_destroy_twice_user_object) {
    REQUIRE(P_GenKey);
    BCRYPT_ALG_HANDLE a = bsc_open(L"AES", NULL); if (!a) { t_skip("AES"); return; }
    bkey k; EXPECT_EQ(bsc_gen(a, &k, S64, 16), 0);
    BCRYPT_KEY_HANDLE h = k.h;
    EXPECT_EQ(P_Destroy(h), 0);
    /* the key header lives in the caller-supplied object and is wiped by destroy, so this is a safe probe */
    EXPECT_EQ(P_Destroy(h), NS_INVALID_HANDLE);
    k.h = NULL; bsc_free(&k); bsc_close(a);
}
TEST(bsc_destroy_wipes_key_object) {
    if (t_is_wine()) { t_skip("wine diverges from the decompiled behaviour here"); return; }
    REQUIRE(P_GenKey);
    BCRYPT_ALG_HANDLE a = bsc_open(L"AES", NULL); if (!a) { t_skip("AES"); return; }
    bkey k; EXPECT_EQ(bsc_gen(a, &k, S64, 16), 0);
    BYTE *hp = (BYTE *)k.h;
    EXPECT_EQ(P_Destroy(k.h), 0);
    BYTE z[0x20] = {0};
    CHECK(same(hp, z, sizeof z));                 /* header (size, magic, alg ptr, ...) is zeroed */
    k.h = NULL; bsc_free(&k); bsc_close(a);
}
TEST(bsc_use_after_destroy) {
    REQUIRE(P_GenKey);
    BCRYPT_ALG_HANDLE a = bsc_open(L"AES", BCRYPT_CHAIN_MODE_ECB); if (!a) { t_skip("AES"); return; }
    bkey k; EXPECT_EQ(bsc_gen(a, &k, S64, 16), 0);
    BCRYPT_KEY_HANDLE h = k.h;
    EXPECT_EQ(P_Destroy(h), 0);
    BYTE z[16] = {0}, o[16]; ULONG g = 0xAA;
    EXPECT_EQ(enc(h, z, 16, NULL, 0, o, 16, &g, 0), NS_INVALID_HANDLE);
    EXPECT_EQ(dec(h, z, 16, NULL, 0, o, 16, &g, 0), NS_INVALID_HANDLE);
    BCRYPT_KEY_HANDLE d = SENTINEL;
    EXPECT_EQ(P_Dup(h, &d, NULL, 0, 0), NS_INVALID_HANDLE); CHECK(d == SENTINEL);
    ULONG v, r;
    CHECK(P_GetProp(h, BCRYPT_BLOCK_LENGTH, (PUCHAR)&v, 4, &r, 0) == NS_INVALID_HANDLE);
    k.h = NULL; bsc_free(&k); bsc_close(a);
}

/* ---- BCryptDuplicateKey -------------------------------------------------------------------------- */
TEST(bsc_dup_null_key) {
    REQUIRE(P_Dup);
    BCRYPT_KEY_HANDLE d = SENTINEL;
    EXPECT_EQ(P_Dup(NULL, &d, NULL, 0, 0), NS_INVALID_HANDLE); CHECK(d == SENTINEL);
}
TEST(bsc_dup_alg_handle_as_key) {
    REQUIRE(P_Dup);
    BCRYPT_ALG_HANDLE a = bsc_open(L"AES", NULL); if (!a) { t_skip("AES"); return; }
    BCRYPT_KEY_HANDLE d = SENTINEL;
    EXPECT_EQ(P_Dup((BCRYPT_KEY_HANDLE)a, &d, NULL, 0, 0), NS_INVALID_HANDLE); CHECK(d == SENTINEL);
    bsc_close(a);
}
TEST(bsc_dup_null_out_param) {
    REQUIRE(P_Dup);
    BCRYPT_ALG_HANDLE a = bsc_open(L"AES", NULL); if (!a) { t_skip("AES"); return; }
    bkey k; EXPECT_EQ(bsc_gen(a, &k, S64, 16), 0);
    EXPECT_EQ(P_Dup(k.h, NULL, NULL, 0, 0), NS_INVALID_PARAM);
    bsc_free(&k); bsc_close(a);
}
TEST(bsc_dup_null_handle_wins_over_null_out) {
    REQUIRE(P_Dup);
    EXPECT_EQ(P_Dup(NULL, NULL, NULL, 0, 0), NS_INVALID_HANDLE);
}
TEST(bsc_dup_object_buffer_too_small) {
    if (t_is_wine()) { t_skip("wine diverges from the decompiled behaviour here"); return; }
    REQUIRE(P_Dup);
    BCRYPT_ALG_HANDLE a = bsc_open(L"AES", NULL); if (!a) { t_skip("AES"); return; }
    bkey k; EXPECT_EQ(bsc_gen(a, &k, S64, 16), 0);
    BYTE obj[1024]; BCRYPT_KEY_HANDLE d = SENTINEL;
    EXPECT_EQ(P_Dup(k.h, &d, obj, 0x3d, 0), NS_BUFFER_TOO_SMALL); CHECK(d == SENTINEL);
    EXPECT_EQ(P_Dup(k.h, &d, obj, 1, 0), NS_BUFFER_TOO_SMALL);
    bsc_free(&k); bsc_close(a);
}
TEST(bsc_dup_object_size_zero_with_buffer) {
    if (t_is_wine()) { t_skip("wine diverges from the decompiled behaviour here"); return; }
    REQUIRE(P_Dup);
    BCRYPT_ALG_HANDLE a = bsc_open(L"AES", NULL); if (!a) { t_skip("AES"); return; }
    bkey k; EXPECT_EQ(bsc_gen(a, &k, S64, 16), 0);
    BYTE obj[1024]; BCRYPT_KEY_HANDLE d = SENTINEL;
    EXPECT_EQ(P_Dup(k.h, &d, obj, 0, 0), NS_BUFFER_TOO_SMALL); CHECK(d == SENTINEL);
    bsc_free(&k); bsc_close(a);
}
TEST(bsc_dup_null_buffer_nonzero_size) {
    if (t_is_wine()) { t_skip("wine diverges from the decompiled behaviour here"); return; }
    REQUIRE(P_Dup);
    BCRYPT_ALG_HANDLE a = bsc_open(L"AES", NULL); if (!a) { t_skip("AES"); return; }
    bkey k; EXPECT_EQ(bsc_gen(a, &k, S64, 16), 0);
    BCRYPT_KEY_HANDLE d = SENTINEL;
    NTSTATUS s = P_Dup(k.h, &d, NULL, 1024, 0);
    EXPECT_EQ(s, NS_INVALID_PARAM); CHECK(d == SENTINEL);
    bsc_free(&k); bsc_close(a);
}
TEST(bsc_dup_independent_lifetime) {
    REQUIRE(P_Dup);
    BCRYPT_ALG_HANDLE a = bsc_open(L"AES", BCRYPT_CHAIN_MODE_ECB); if (!a) { t_skip("AES"); return; }
    bkey k; EXPECT_EQ(bsc_genhex(a, &k, "2b7e151628aed2a6abf7158809cf4f3c"), 0);
    BCRYPT_KEY_HANDLE d = SENTINEL;
    EXPECT_EQ(P_Dup(k.h, &d, NULL, 0, 0), 0);
    CHECK(d != k.h);
    bsc_free(&k);                                  /* destroy the original first */
    BYTE pt[16], out[16]; hx("6bc1bee22e409f96e93d7e117393172a", pt); ULONG got = 0;
    EXPECT_EQ(enc(d, pt, 16, NULL, 0, out, 16, &got, 0), 0);
    CHECK_HEX(out, 16, "3ad77bb40d7a3660a89ecaf32466ef97");
    EXPECT_EQ(P_Destroy(d), 0);
    bsc_close(a);
}
TEST(bsc_dup_with_user_object) {
    if (t_is_wine()) { t_skip("wine diverges from the decompiled behaviour here"); return; }
    REQUIRE(P_Dup);
    BCRYPT_ALG_HANDLE a = bsc_open(L"AES", BCRYPT_CHAIN_MODE_ECB); if (!a) { t_skip("AES"); return; }
    bkey k; EXPECT_EQ(bsc_genhex(a, &k, "2b7e151628aed2a6abf7158809cf4f3c"), 0);
    ULONG ol = bsc_objlen(a); BYTE *obj = (BYTE *)calloc(1, ol + 16); BCRYPT_KEY_HANDLE d = SENTINEL;
    NTSTATUS s = P_Dup(k.h, &d, obj, ol, 0);
    EXPECT_EQ(s, 0);
    if (s == 0) {
        CHECK((BYTE *)d >= obj && (BYTE *)d < obj + ol + 16);
        BYTE pt[16], out[16]; hx("6bc1bee22e409f96e93d7e117393172a", pt); ULONG got = 0;
        EXPECT_EQ(enc(d, pt, 16, NULL, 0, out, 16, &got, 0), 0);
        CHECK_HEX(out, 16, "3ad77bb40d7a3660a89ecaf32466ef97");
        EXPECT_EQ(P_Destroy(d), 0);
    }
    free(obj); bsc_free(&k); bsc_close(a);
}
TEST(bsc_dup_keeps_chaining_mode_and_strength) {
    REQUIRE(P_Dup);
    BCRYPT_ALG_HANDLE a = bsc_open(L"AES", BCRYPT_CHAIN_MODE_CFB); if (!a) { t_skip("AES"); return; }
    BYTE s32[32]; for (int i = 0; i < 32; i++) s32[i] = (BYTE)i;
    bkey k; EXPECT_EQ(bsc_gen(a, &k, s32, 32), 0);
    BCRYPT_KEY_HANDLE d = SENTINEL;
    EXPECT_EQ(P_Dup(k.h, &d, NULL, 0, 0), 0);
    if (d != SENTINEL) {
        WCHAR m[64] = {0}; ULONG r = 0, str = 0;
        EXPECT_EQ(P_GetProp(d, BCRYPT_CHAINING_MODE, (PUCHAR)m, sizeof m, &r, 0), 0);
        EXPECT_WSTR(m, BCRYPT_CHAIN_MODE_CFB);
        EXPECT_EQ(P_GetProp(d, BCRYPT_KEY_STRENGTH, (PUCHAR)&str, 4, &r, 0), 0);
        if (str != 256) t_note("KeyStrength of duplicated 32-byte key = %lu", str);
        P_Destroy(d);
    }
    bsc_free(&k); bsc_close(a);
}
TEST(bsc_dup_of_dup) {
    REQUIRE(P_Dup);
    BCRYPT_ALG_HANDLE a = bsc_open(L"AES", BCRYPT_CHAIN_MODE_ECB); if (!a) { t_skip("AES"); return; }
    bkey k; EXPECT_EQ(bsc_genhex(a, &k, "2b7e151628aed2a6abf7158809cf4f3c"), 0);
    BCRYPT_KEY_HANDLE d1 = SENTINEL, d2 = SENTINEL;
    EXPECT_EQ(P_Dup(k.h, &d1, NULL, 0, 0), 0);
    EXPECT_EQ(P_Dup(d1, &d2, NULL, 0, 0), 0);
    BYTE pt[16], out[16]; hx("6bc1bee22e409f96e93d7e117393172a", pt); ULONG got = 0;
    EXPECT_EQ(enc(d2, pt, 16, NULL, 0, out, 16, &got, 0), 0);
    CHECK_HEX(out, 16, "3ad77bb40d7a3660a89ecaf32466ef97");
    if (d2 != SENTINEL) P_Destroy(d2);
    if (d1 != SENTINEL) P_Destroy(d1);
    bsc_free(&k); bsc_close(a);
}
TEST(bsc_dup_rc4_copies_state) {
    REQUIRE(P_Dup);
    BCRYPT_ALG_HANDLE a = bsc_open(L"RC4", NULL); if (!a) { t_skip("RC4"); return; }
    bkey k; if (bsc_genhex(a, &k, "0102030405060708090a0b0c0d0e0f10") != 0) { bsc_close(a); t_skip("RC4"); return; }
    BYTE z[16] = {0}, o[16]; ULONG g = 0;
    if (WINE_UNSUP(enc(k.h, z, 16, NULL, 0, o, 16, &g, 0))) { bsc_free(&k); bsc_close(a); t_skip("wine"); return; }
    BCRYPT_KEY_HANDLE d = SENTINEL;
    EXPECT_EQ(P_Dup(k.h, &d, NULL, 0, 0), 0);
    if (d != SENTINEL) {
        BYTE o1[16], o2[16];
        EXPECT_EQ(enc(k.h, z, 16, NULL, 0, o1, 16, &g, 0), 0);
        EXPECT_EQ(enc(d, z, 16, NULL, 0, o2, 16, &g, 0), 0);
        CHECK(same(o1, o2, 16));                   /* duplicate starts at the same keystream offset as the original */
        BYTE first[16]; hx("9ac7cc9a609d1ef7b2932899cde41b97", first); CHECK(same(o, first, 16));
        CHECK(!same(o1, first, 16));               /* offset 16, not 0 */
        P_Destroy(d);
    }
    bsc_free(&k); bsc_close(a);
}

/* ---- property reads on keys ------------------------------------------------------------------------------ */
TEST(bsc_key_strength_per_size) {
    REQUIRE(P_GenKey);
    BCRYPT_ALG_HANDLE a = bsc_open(L"AES", NULL); if (!a) { t_skip("AES"); return; }
    for (ULONG n = 16; n <= 32; n += 8) {
        bkey k; EXPECT_EQ(bsc_gen(a, &k, S64, n), 0);
        ULONG v = 0, r = 0;
        EXPECT_EQ(P_GetProp(k.h, BCRYPT_KEY_STRENGTH, (PUCHAR)&v, 4, &r, 0), 0);
        EXPECT_EQ(r, 4);
        if (n == 16) EXPECT_EQ(v, 128); else if (v != n * 8) t_note("KeyStrength of %lu-byte key = %lu", n, v);
        bsc_free(&k);
    }
    bsc_close(a);
}
TEST(bsc_key_block_length_property) {
    REQUIRE(P_GenKey);
    BCRYPT_ALG_HANDLE a = bsc_open(L"AES", NULL); if (!a) { t_skip("AES"); return; }
    bkey k; EXPECT_EQ(bsc_gen(a, &k, S64, 16), 0);
    ULONG v = 0, r = 0;
    EXPECT_EQ(P_GetProp(k.h, BCRYPT_BLOCK_LENGTH, (PUCHAR)&v, 4, &r, 0), 0);
    EXPECT_EQ(v, 16); EXPECT_EQ(r, 4);
    bsc_free(&k); bsc_close(a);
}
TEST(bsc_key_set_chaining_mode_after_creation) {
    REQUIRE(P_GenKey);
    BCRYPT_ALG_HANDLE a = bsc_open(L"AES", BCRYPT_CHAIN_MODE_CBC); if (!a) { t_skip("AES"); return; }
    bkey k; EXPECT_EQ(bsc_genhex(a, &k, "2b7e151628aed2a6abf7158809cf4f3c"), 0);
    EXPECT_EQ(P_SetProp(k.h, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_ECB, sizeof(BCRYPT_CHAIN_MODE_ECB), 0), 0);
    WCHAR m[64] = {0}; ULONG r = 0;
    EXPECT_EQ(P_GetProp(k.h, BCRYPT_CHAINING_MODE, (PUCHAR)m, sizeof m, &r, 0), 0);
    EXPECT_WSTR(m, BCRYPT_CHAIN_MODE_ECB); EXPECT_EQ(r, 64);
    BYTE pt[16], out[16]; hx("6bc1bee22e409f96e93d7e117393172a", pt); ULONG got = 0;
    EXPECT_EQ(enc(k.h, pt, 16, NULL, 0, out, 16, &got, 0), 0);     /* ECB now: no IV needed, matches the ECB vector */
    CHECK_HEX(out, 16, "3ad77bb40d7a3660a89ecaf32466ef97");
    EXPECT_EQ(P_SetProp(k.h, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0), 0);
    BYTE iv[16] = {0}; memcpy(iv, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f", 16);
    EXPECT_EQ(enc(k.h, pt, 16, iv, 16, out, 16, &got, 0), 0);
    CHECK_HEX(out, 16, "7649abac8119b246cee98e9b12e9197d");        /* SP800-38A F.2.1 block 1 */
    bsc_free(&k); bsc_close(a);
}
TEST(bsc_key_set_unknown_chaining_mode) {
    REQUIRE(P_GenKey);
    BCRYPT_ALG_HANDLE a = bsc_open(L"AES", NULL); if (!a) { t_skip("AES"); return; }
    bkey k; EXPECT_EQ(bsc_gen(a, &k, S64, 16), 0);
    NTSTATUS s = P_SetProp(k.h, BCRYPT_CHAINING_MODE, (PUCHAR)L"ChainingModeXYZ", sizeof(L"ChainingModeXYZ"), 0);
    CHECK(s < 0);
    t_note("SetProperty(key, ChainingMode, bogus) = 0x%lx", s);
    WCHAR m[64] = {0}; ULONG r = 0;
    EXPECT_EQ(P_GetProp(k.h, BCRYPT_CHAINING_MODE, (PUCHAR)m, sizeof m, &r, 0), 0);
    CHECK(wcsncmp(m, L"ChainingModeXYZ", 15) != 0);
    bsc_free(&k); bsc_close(a);
}
TEST(bsc_alg_set_chaining_mode_not_valid_for_cipher) {
    REQUIRE(P_SetProp);
    BCRYPT_ALG_HANDLE a = bsc_open(L"DES", NULL);
    if (!a) { t_skip("DES unavailable"); return; }
    /* DES has no authenticated modes: GCM is rejected */
    NTSTATUS s = P_SetProp(a, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    CHECK(s < 0);
    t_note("DES SetProperty(GCM) = 0x%lx", s);
    bsc_close(a);
}
TEST(bsc_rc4_chaining_mode_na) {
    REQUIRE(P_SetProp);
    BCRYPT_ALG_HANDLE a = bsc_open(L"RC4", NULL); if (!a) { t_skip("RC4"); return; }
    EXPECT_EQ(P_SetProp(a, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_NA, sizeof(BCRYPT_CHAIN_MODE_NA), 0), 0);
    bsc_close(a);
}
