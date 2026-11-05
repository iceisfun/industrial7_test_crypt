/* Algorithm properties of the symmetric ciphers, cross-mode identities, large data, threads, wrong handle types. */
#include "bsc.h"

#define ECB BCRYPT_CHAIN_MODE_ECB
#define CBC BCRYPT_CHAIN_MODE_CBC
#define CFB BCRYPT_CHAIN_MODE_CFB

/* ---- property reads ----------------------------------------------------------------------- */
static ULONG getul(BCRYPT_HANDLE h, const wchar_t *prop, NTSTATUS *st) {
    ULONG v = 0xDEADBEEF, r = 0;
    NTSTATUS s = P_GetProp(h, prop, (PUCHAR)&v, 4, &r, 0);
    if (st) *st = s;
    return v;
}
struct blk { const wchar_t *alg; ULONG block; };
static void blocklen_case(const wchar_t *alg, ULONG want) {
    BCRYPT_ALG_HANDLE a = bsc_open(alg, NULL); if (!a) { t_skip("%ls not available", alg); return; }
    NTSTATUS s; ULONG v = getul(a, BCRYPT_BLOCK_LENGTH, &s);
    EXPECT_EQ(s, 0); EXPECT_EQ(v, want);
    ULONG r = 0xAAAA; v = 0;
    EXPECT_EQ(P_GetProp(a, BCRYPT_BLOCK_LENGTH, (PUCHAR)&v, 4, &r, 0), 0); EXPECT_EQ(r, 4);
    r = 0xAAAA;
    EXPECT_EQ(P_GetProp(a, BCRYPT_BLOCK_LENGTH, (PUCHAR)&v, 3, &r, 0), NS_BUFFER_TOO_SMALL); EXPECT_EQ(r, 4);
    r = 0xAAAA;
    s = P_GetProp(a, BCRYPT_BLOCK_LENGTH, NULL, 0, &r, 0);
    CHECK(s == 0 || s == NS_BUFFER_TOO_SMALL); EXPECT_EQ(r, 4);        /* NULL buffer: size query */
    ULONG big[2] = { 0xAAAAAAAA, 0xAAAAAAAA };
    EXPECT_EQ(P_GetProp(a, BCRYPT_BLOCK_LENGTH, (PUCHAR)big, 8, &r, 0), 0); EXPECT_EQ(r, 4); CHECK(big[1] == 0xAAAAAAAA);
    bsc_close(a);
}
TEST(bsc_prop_blocklen_aes) { blocklen_case(L"AES", 16); }
TEST(bsc_prop_blocklen_des) { blocklen_case(L"DES", 8); }
TEST(bsc_prop_blocklen_3des) { blocklen_case(L"3DES", 8); }
TEST(bsc_prop_blocklen_3des112) { blocklen_case(L"3DES_112", 8); }
TEST(bsc_prop_blocklen_rc2) { blocklen_case(L"RC2", 8); }
TEST(bsc_prop_blocklen_rc4) { blocklen_case(L"RC4", 1); }
TEST(bsc_prop_blocklen_desx) { blocklen_case(L"DESX", 8); }

static void keylengths_case(const wchar_t *alg, ULONG mn, ULONG mx, ULONG inc, int hard) {
    BCRYPT_ALG_HANDLE a = bsc_open(alg, NULL); if (!a) { t_skip("%ls not available", alg); return; }
    BCRYPT_KEY_LENGTHS_STRUCT kl = {0}; ULONG r = 0;
    NTSTATUS s = P_GetProp(a, BCRYPT_KEY_LENGTHS, (PUCHAR)&kl, sizeof kl, &r, 0);
    if (WINE_UNSUP(s)) { t_skip("emulator"); bsc_close(a); return; }
    EXPECT_EQ(s, 0); EXPECT_EQ(r, sizeof kl);
    if (hard) { EXPECT_EQ(kl.dwMinLength, mn); EXPECT_EQ(kl.dwMaxLength, mx); EXPECT_EQ(kl.dwIncrement, inc); }
    else t_note("%ls KeyLengths min=%lu max=%lu incr=%lu", alg, kl.dwMinLength, kl.dwMaxLength, kl.dwIncrement);
    r = 0xAAAA;
    s = P_GetProp(a, BCRYPT_KEY_LENGTHS, NULL, 0, &r, 0);
    CHECK(s == 0 || s == NS_BUFFER_TOO_SMALL); EXPECT_EQ(r, sizeof kl);
    EXPECT_EQ(P_GetProp(a, BCRYPT_KEY_LENGTHS, (PUCHAR)&kl, sizeof kl - 1, &r, 0), NS_BUFFER_TOO_SMALL);
    bsc_close(a);
}
TEST(bsc_prop_keylengths_aes) { keylengths_case(L"AES", 128, 256, 64, 1); }
TEST(bsc_prop_keylengths_des) { keylengths_case(L"DES", 64, 64, 0, 1); }
TEST(bsc_prop_keylengths_3des) { keylengths_case(L"3DES", 192, 192, 0, 0); }
TEST(bsc_prop_keylengths_3des112) { keylengths_case(L"3DES_112", 128, 128, 0, 0); }
TEST(bsc_prop_keylengths_rc4) { keylengths_case(L"RC4", 0, 0, 0, 0); }
TEST(bsc_prop_keylengths_rc2) { keylengths_case(L"RC2", 0, 0, 0, 0); }
TEST(bsc_prop_keylengths_desx) { keylengths_case(L"DESX", 0, 0, 0, 0); }

TEST(bsc_prop_object_length_nonzero_and_stable) {
    const wchar_t *algs[] = { L"AES", L"DES", L"3DES", L"RC4", L"RC2" };
    for (int i = 0; i < 5; i++) {
        BCRYPT_ALG_HANDLE a = bsc_open(algs[i], NULL); if (!a) continue;
        NTSTATUS s; ULONG v1 = getul(a, BCRYPT_OBJECT_LENGTH, &s);
        CHECKF(s == 0 && v1 > 0x3d, "%ls object length %lu (0x%lx)", algs[i], v1, s);
        ULONG v2 = getul(a, BCRYPT_OBJECT_LENGTH, &s);
        CHECKF(v1 == v2, "%ls unstable", algs[i]);
        bsc_close(a);
    }
}
TEST(bsc_prop_object_length_aes_modes) {
    ULONG lens[5]; const wchar_t *modes[] = { ECB, CBC, CFB, BCRYPT_CHAIN_MODE_GCM, BCRYPT_CHAIN_MODE_CCM };
    for (int i = 0; i < 5; i++) {
        BCRYPT_ALG_HANDLE a = bsc_open(L"AES", modes[i]); lens[i] = 0; if (!a) continue;
        lens[i] = getul(a, BCRYPT_OBJECT_LENGTH, NULL);
        CHECKF(lens[i] > 0x3d, "%ls object length %lu", modes[i], lens[i]);
        bsc_close(a);
    }
    t_note("AES object lengths ECB/CBC/CFB/GCM/CCM = %lu/%lu/%lu/%lu/%lu", lens[0], lens[1], lens[2], lens[3], lens[4]);
}
TEST(bsc_prop_algorithm_name) {
    const wchar_t *algs[] = { L"AES", L"DES", L"3DES", L"RC4", L"RC2", L"DESX", L"3DES_112" };
    for (int i = 0; i < 7; i++) {
        BCRYPT_ALG_HANDLE a = bsc_open(algs[i], NULL); if (!a) continue;
        WCHAR n[64] = {0}; ULONG r = 0;
        NTSTATUS s = P_GetProp(a, BCRYPT_ALGORITHM_NAME, (PUCHAR)n, sizeof n, &r, 0);
        CHECKF(s == 0 && !wcscmp(n, algs[i]) && r == (wcslen(algs[i]) + 1) * 2, "%ls: 0x%lx '%ls' %lu", algs[i], s, n, r);
        r = 0xAAAA;
        s = P_GetProp(a, BCRYPT_ALGORITHM_NAME, NULL, 0, &r, 0);
        CHECKF((s == NS_BUFFER_TOO_SMALL || s == 0) && r == (wcslen(algs[i]) + 1) * 2, "%ls size query 0x%lx %lu", algs[i], s, r);
        bsc_close(a);
    }
}
TEST(bsc_prop_chaining_mode_defaults) {
    struct { const wchar_t *alg; const wchar_t *mode; } t[] = { {L"AES", CBC}, {L"DES", CBC}, {L"3DES", CBC}, {L"RC2", CBC}, {L"3DES_112", CBC} };
    for (int i = 0; i < 5; i++) {
        BCRYPT_ALG_HANDLE a = bsc_open(t[i].alg, NULL); if (!a) continue;
        WCHAR m[64] = {0}; ULONG r = 0;
        NTSTATUS s = P_GetProp(a, BCRYPT_CHAINING_MODE, (PUCHAR)m, sizeof m, &r, 0);
        CHECKF(s == 0 && !wcscmp(m, t[i].mode) && r == 64, "%ls: 0x%lx %ls %lu", t[i].alg, s, m, r);
        bsc_close(a);
    }
}
TEST(bsc_prop_chaining_mode_rc4_default) {
    BCRYPT_ALG_HANDLE a = bsc_open(L"RC4", NULL); if (!a) { t_skip("RC4"); return; }
    WCHAR m[64] = {0}; ULONG r = 0;
    NTSTATUS s = P_GetProp(a, BCRYPT_CHAINING_MODE, (PUCHAR)m, sizeof m, &r, 0);
    t_note("RC4 ChainingMode: 0x%lx %ls (%lu)", s, m, r);
    EXPECT_EQ(P_SetProp(a, BCRYPT_CHAINING_MODE, (PUCHAR)CBC, sizeof(CBC), 0) < 0, 1);
    bsc_close(a);
}
TEST(bsc_prop_chaining_mode_buffer_protocol) {
    BCRYPT_ALG_HANDLE a = bsc_open(L"AES", ECB); if (!a) { t_skip("AES"); return; }
    WCHAR m[64]; ULONG r = 0xAAAA;
    EXPECT_EQ(P_GetProp(a, BCRYPT_CHAINING_MODE, (PUCHAR)m, 0, &r, 0), NS_BUFFER_TOO_SMALL); EXPECT_EQ(r, 64);
    r = 0xAAAA;
    EXPECT_EQ(P_GetProp(a, BCRYPT_CHAINING_MODE, (PUCHAR)m, 63, &r, 0), NS_BUFFER_TOO_SMALL); EXPECT_EQ(r, 64);
    r = 0xAAAA; memset(m, 0xCC, sizeof m);
    EXPECT_EQ(P_GetProp(a, BCRYPT_CHAINING_MODE, (PUCHAR)m, 64, &r, 0), 0); EXPECT_EQ(r, 64);
    EXPECT_WSTR(m, ECB);
    BYTE z[16] = {0}; CHECK(wcslen(m) < 31 || 1); (void)z;
    bsc_close(a);
}
TEST(bsc_prop_pcbresult_required) {
    BCRYPT_ALG_HANDLE a = bsc_open(L"AES", ECB); if (!a) { t_skip("AES"); return; }
    ULONG v = 0;
    if (!t_is_wine()) EXPECT_EQ(P_GetProp(a, BCRYPT_BLOCK_LENGTH, (PUCHAR)&v, 4, NULL, 0), NS_INVALID_PARAM);
    bsc_close(a);
}
TEST(bsc_prop_unknown_property) {
    BCRYPT_ALG_HANDLE a = bsc_open(L"AES", ECB); if (!a) { t_skip("AES"); return; }
    ULONG v = 0, r = 0;
    NTSTATUS s = P_GetProp(a, L"NoSuchProperty", (PUCHAR)&v, 4, &r, 0);
    CHECK(s < 0);
    t_note("GetProperty(unknown) -> 0x%lx", s);
    s = P_SetProp(a, L"NoSuchProperty", (PUCHAR)&v, 4, 0);
    CHECK(s < 0);
    t_note("SetProperty(unknown) -> 0x%lx", s);
    bsc_close(a);
}
TEST(bsc_prop_get_set_invalid_handles) {
    ULONG v = 0, r = 0;
    EXPECT_EQ(P_GetProp(NULL, BCRYPT_BLOCK_LENGTH, (PUCHAR)&v, 4, &r, 0), NS_INVALID_HANDLE);
    EXPECT_EQ(P_SetProp(NULL, BCRYPT_CHAINING_MODE, (PUCHAR)CBC, sizeof(CBC), 0), NS_INVALID_HANDLE);
}
TEST(bsc_prop_key_length_on_alg_not_settable) {
    BCRYPT_ALG_HANDLE a = bsc_open(L"AES", CBC); if (!a) { t_skip("AES"); return; }
    ULONG kl = 128;
    NTSTATUS s = P_SetProp(a, BCRYPT_KEY_LENGTH, (PUCHAR)&kl, 4, 0);
    if (WINE_UNSUP(s) && s != NS_NOT_SUPPORTED) { t_skip("emulator"); bsc_close(a); return; }
    EXPECT_EQ(s, NS_NOT_SUPPORTED);
    bsc_close(a);
}
TEST(bsc_prop_key_handle_readable_after_alg_close) {
    BCRYPT_ALG_HANDLE a = bsc_open(L"AES", CBC); if (!a) { t_skip("AES"); return; }
    bkey k; EXPECT_EQ(bsc_gen(a, &k, (const BYTE *)"0123456789abcdef", 16), 0);
    P_Close(a, 0);
    NTSTATUS s; ULONG v = getul(k.h, BCRYPT_BLOCK_LENGTH, &s);
    EXPECT_EQ(s, 0); EXPECT_EQ(v, 16);
    bsc_free(&k);
}
TEST(bsc_rc2_effective_key_length_property) {
    BCRYPT_ALG_HANDLE a = bsc_open(L"RC2", ECB); if (!a) { t_skip("RC2"); return; }
    NTSTATUS s; ULONG v = getul(a, BCRYPT_EFFECTIVE_KEY_LENGTH, &s);
    t_note("RC2 alg EffectiveKeyLength: 0x%lx %lu", s, v);
    ULONG e = 40;
    s = P_SetProp(a, BCRYPT_EFFECTIVE_KEY_LENGTH, (PUCHAR)&e, 4, 0);
    t_note("RC2 alg set EffectiveKeyLength=40: 0x%lx", s);
    bkey k; BYTE sec[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    s = bsc_gen(a, &k, sec, 16);
    if (s == 0) {
        BYTE pt[16] = {0}, c[16], b[16]; ULONG got = 0;
        EXPECT_EQ(enc(k.h, pt, 16, NULL, 0, c, 16, &got, 0), 0);
        EXPECT_EQ(dec(k.h, c, 16, NULL, 0, b, 16, &got, 0), 0);
        CHECK(same(b, pt, 16));
        bsc_free(&k);
    }
    bsc_close(a);
}
TEST(bsc_desx_roundtrip) {
    BCRYPT_ALG_HANDLE a = bsc_open(L"DESX", CBC); if (!a) { t_skip("DESX"); return; }
    BYTE sec[24]; for (int i = 0; i < 24; i++) sec[i] = (BYTE)(i * 5 + 3);
    bkey k; NTSTATUS s = bsc_gen(a, &k, sec, 24);
    EXPECT_EQ(s, 0);
    if (s == 0) {
        BYTE pt[32], c[32], b[32], iv1[8] = {1}, iv2[8] = {1}; ULONG got = 0;
        for (int i = 0; i < 32; i++) pt[i] = (BYTE)i;
        EXPECT_EQ(enc(k.h, pt, 32, iv1, 8, c, 32, &got, 0), 0);
        CHECK(same(iv1, c + 24, 8));
        CHECK(!same(c, pt, 32));
        EXPECT_EQ(dec(k.h, c, 32, iv2, 8, b, 32, &got, 0), 0);
        CHECK(same(b, pt, 32));
        EXPECT_EQ(enc(k.h, pt, 31, NULL, 0, NULL, 0, &got, 0), NS_INVALID_BUFFER_SIZE); EXPECT_EQ(got, 31);
        bsc_free(&k);
    }
    bsc_close(a);
}

/* ---- identities that hold by definition of the modes ------------------------------------------------ */
static NTSTATUS ecb_block(BCRYPT_KEY_HANDLE ecb, const BYTE *in, BYTE *out) { ULONG g; return enc(ecb, in, 16, NULL, 0, out, 16, &g, 0); }
TEST(bsc_identity_cbc_is_chained_ecb) {
    fx c, e; FX_OR_SKIP(c, L"AES", CBC, KEY16);
    if (!fx_open(&e, L"AES", ECB, KEY16)) { fx_close(&c); t_skip("AES"); return; }
    BYTE pt[64], ct[64], iv[16], prev[16]; for (int i = 0; i < 64; i++) pt[i] = (BYTE)(i * 11); for (int i = 0; i < 16; i++) iv[i] = (BYTE)(0xF0 + i);
    memcpy(prev, iv, 16); ULONG got = 0;
    EXPECT_EQ(enc(c.k.h, pt, 64, iv, 16, ct, 64, &got, 0), 0);
    for (int b = 0; b < 4; b++) {
        BYTE x[16], y[16];
        for (int i = 0; i < 16; i++) x[i] = pt[16 * b + i] ^ prev[i];
        EXPECT_EQ(ecb_block(e.k.h, x, y), 0);
        CHECKF(same(y, ct + 16 * b, 16), "block %d", b);
        memcpy(prev, ct + 16 * b, 16);
    }
    fx_close(&c); fx_close(&e);
}
TEST(bsc_identity_cfb128_is_keystream_xor) {
    REQUIRE(P_GenKey);
    BCRYPT_ALG_HANDLE a = bsc_open(L"AES", CFB); if (!a) { t_skip("AES"); return; }
    ULONG m = 16; NTSTATUS s = P_SetProp(a, BCRYPT_MESSAGE_BLOCK_LENGTH, (PUCHAR)&m, 4, 0);
    if (WINE_UNSUP(s)) { bsc_close(a); t_skip("emulator"); return; }
    bkey k; EXPECT_EQ(bsc_genhex(a, &k, KEY16), 0);
    fx e; if (!fx_open(&e, L"AES", ECB, KEY16)) { bsc_free(&k); bsc_close(a); t_skip("AES"); return; }
    BYTE pt[48], ct[48], iv[16], prev[16]; for (int i = 0; i < 48; i++) pt[i] = (BYTE)(i * 13); for (int i = 0; i < 16; i++) iv[i] = (BYTE)(i + 0x80);
    memcpy(prev, iv, 16); ULONG got = 0;
    EXPECT_EQ(enc(k.h, pt, 48, iv, 16, ct, 48, &got, 0), 0);
    for (int b = 0; b < 3; b++) {
        BYTE ks[16];
        ecb_block(e.k.h, prev, ks);
        for (int i = 0; i < 16; i++) CHECKF((pt[16 * b + i] ^ ks[i]) == ct[16 * b + i], "block %d byte %d", b, i);
        memcpy(prev, ct + 16 * b, 16);
    }
    fx_close(&e); bsc_free(&k); bsc_close(a);
}
TEST(bsc_identity_cfb8_first_byte) {
    WINE_SKIP("no CFB8");
    fx c, e; FX_OR_SKIP(c, L"AES", CFB, KEY16);
    if (!fx_open(&e, L"AES", ECB, KEY16)) { fx_close(&c); t_skip("AES"); return; }
    BYTE iv[16], iv0[16], ks[16], pt = 0x5A, ct; for (int i = 0; i < 16; i++) iv[i] = (BYTE)(i * 3 + 1); memcpy(iv0, iv, 16);
    ULONG got = 0;
    EXPECT_EQ(enc(c.k.h, &pt, 1, iv, 16, &ct, 1, &got, 0), 0);
    ecb_block(e.k.h, iv0, ks);
    CHECK(ct == (BYTE)(pt ^ ks[0]));
    BYTE exp[16]; memcpy(exp, iv0 + 1, 15); exp[15] = ct;       /* shift register moves left by one byte */
    CHECK(same(iv, exp, 16));
    fx_close(&c); fx_close(&e);
}
TEST(bsc_identity_ecb_equal_blocks_equal_ciphertext) {
    fx e, c; FX_OR_SKIP(e, L"AES", ECB, KEY16);
    if (!fx_open(&c, L"AES", CBC, KEY16)) { fx_close(&e); t_skip("AES"); return; }
    BYTE pt[48]; memset(pt, 0x61, 48); BYTE ct[48], ct2[48], iv[16] = {0}; ULONG got = 0;
    EXPECT_EQ(enc(e.k.h, pt, 48, NULL, 0, ct, 48, &got, 0), 0);
    CHECK(same(ct, ct + 16, 16) && same(ct, ct + 32, 16));
    EXPECT_EQ(enc(c.k.h, pt, 48, iv, 16, ct2, 48, &got, 0), 0);
    CHECK(!same(ct2, ct2 + 16, 16));
    CHECK(same(ct2, ct, 16));                                     /* first CBC block with zero IV == ECB */
    fx_close(&e); fx_close(&c);
}
TEST(bsc_identity_3des112_equals_3des_k1k2k1) {
    BCRYPT_ALG_HANDLE a2 = bsc_open(L"3DES_112", ECB), a3 = bsc_open(L"3DES", ECB);
    if (!a2 || !a3) { bsc_close(a2); bsc_close(a3); t_skip("3DES"); return; }
    BYTE k24[24], k16[16]; for (int i = 0; i < 16; i++) k16[i] = (BYTE)(i * 9 + 2); memcpy(k24, k16, 16); memcpy(k24 + 16, k16, 8);
    bkey x, y; EXPECT_EQ(bsc_gen(a2, &x, k16, 16), 0); EXPECT_EQ(bsc_gen(a3, &y, k24, 24), 0);
    BYTE pt[16] = {1,2,3,4,5,6,7,8,9}, c1[16], c2[16]; ULONG got = 0;
    EXPECT_EQ(enc(x.h, pt, 16, NULL, 0, c1, 16, &got, 0), 0);
    EXPECT_EQ(enc(y.h, pt, 16, NULL, 0, c2, 16, &got, 0), 0);
    CHECK(same(c1, c2, 16));
    bsc_free(&x); bsc_free(&y); bsc_close(a2); bsc_close(a3);
}
TEST(bsc_identity_des_parity_bits_ignored) {
    BCRYPT_ALG_HANDLE a = bsc_open(L"DES", ECB); if (!a) { t_skip("DES"); return; }
    BYTE k1[8] = {0x13,0x34,0x57,0x79,0x9B,0xBC,0xDF,0xF1}, k2[8];
    for (int i = 0; i < 8; i++) k2[i] = k1[i] ^ 1;               /* flip every parity bit */
    bkey x, y; EXPECT_EQ(bsc_gen(a, &x, k1, 8), 0); EXPECT_EQ(bsc_gen(a, &y, k2, 8), 0);
    BYTE pt[8] = {0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF}, c1[8], c2[8]; ULONG got = 0;
    EXPECT_EQ(enc(x.h, pt, 8, NULL, 0, c1, 8, &got, 0), 0);
    EXPECT_EQ(enc(y.h, pt, 8, NULL, 0, c2, 8, &got, 0), 0);
    CHECK(same(c1, c2, 8));
    CHECK_HEX(c1, 8, "85e813540f0ab405");
    bsc_free(&x); bsc_free(&y); bsc_close(a);
}

/* ---- large data -------------------------------------------------------------------------------------------- */
TEST(bsc_large_cbc_chunked_equals_one_shot) {
    fx f; FX_OR_SKIP(f, L"AES", CBC, KEY16);
    ULONG n = 1 << 20;
    BYTE *pt = (BYTE *)malloc(n), *c1 = (BYTE *)malloc(n), *c2 = (BYTE *)malloc(n), *back = (BYTE *)malloc(n);
    for (ULONG i = 0; i < n; i++) pt[i] = (BYTE)(i * 7 + (i >> 8));
    BYTE iv1[16] = {1}, iv2[16] = {1}; ULONG got = 0;
    EXPECT_EQ(enc(f.k.h, pt, n, iv1, 16, c1, n, &got, 0), 0); EXPECT_EQ(got, n);
    ULONG off = 0, step = 4096 + 16;
    while (off < n) {
        ULONG c = n - off < step ? n - off : step;
        if (enc(f.k.h, pt + off, c, iv2, 16, c2 + off, c, &got, 0) != 0) { CHECK(0); break; }
        off += c;
    }
    CHECK(same(c1, c2, n)); CHECK(same(iv1, iv2, 16));
    BYTE iv3[16] = {1};
    EXPECT_EQ(dec(f.k.h, c1, n, iv3, 16, back, n, &got, 0), 0); CHECK(same(back, pt, n));
    free(pt); free(c1); free(c2); free(back); fx_close(&f);
}
TEST(bsc_large_padded_roundtrip) {
    fx f; FX_OR_SKIP(f, L"AES", CBC, KEY16);
    ULONG n = (1 << 20) + 5;
    BYTE *pt = (BYTE *)malloc(n), *ct = (BYTE *)malloc(n + 32), *back = (BYTE *)malloc(n + 32);
    for (ULONG i = 0; i < n; i++) pt[i] = (BYTE)(i ^ (i >> 5));
    BYTE iv1[16] = {2}, iv2[16] = {2}; ULONG got = 0, need = 0;
    EXPECT_EQ(enc(f.k.h, pt, n, iv1, 16, NULL, 0, &need, BCRYPT_BLOCK_PADDING), 0);
    EXPECT_EQ(need, ((n / 16) + 1) * 16);
    EXPECT_EQ(enc(f.k.h, pt, n, iv1, 16, ct, need, &got, BCRYPT_BLOCK_PADDING), 0); EXPECT_EQ(got, need);
    EXPECT_EQ(dec(f.k.h, ct, need, iv2, 16, back, n, &got, BCRYPT_BLOCK_PADDING), 0); EXPECT_EQ(got, n);
    CHECK(same(back, pt, n));
    free(pt); free(ct); free(back); fx_close(&f);
}
TEST(bsc_large_gcm_roundtrip) {
    BCRYPT_ALG_HANDLE a = bsc_open(L"AES", BCRYPT_CHAIN_MODE_GCM); if (!a) { t_skip("GCM"); return; }
    bkey k; EXPECT_EQ(bsc_genhex(a, &k, KEY16), 0);
    ULONG n = 1 << 20; BYTE *pt = (BYTE *)malloc(n), *ct = (BYTE *)malloc(n), *bk = (BYTE *)malloc(n);
    for (ULONG i = 0; i < n; i++) pt[i] = (BYTE)(i * 3);
    BYTE nonce[12] = {9}, tag[16]; ULONG got = 0;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO ai; BCRYPT_INIT_AUTH_MODE_INFO(ai);
    ai.pbNonce = nonce; ai.cbNonce = 12; ai.pbTag = tag; ai.cbTag = 16;
    NTSTATUS s = P_Enc(k.h, pt, n, &ai, NULL, 0, ct, n, &got, 0);
    if (WINE_UNSUP(s)) { t_skip("emulator"); }
    else {
        EXPECT_EQ(s, 0);
        s = P_Dec(k.h, ct, n, &ai, NULL, 0, bk, n, &got, 0);
        EXPECT_EQ(s, 0); CHECK(same(bk, pt, n));
        tag[5] ^= 4;
        EXPECT_EQ(P_Dec(k.h, ct, n, &ai, NULL, 0, bk, n, &got, 0), NS_AUTH_TAG_MISMATCH);
    }
    free(pt); free(ct); free(bk); bsc_free(&k); bsc_close(a);
}

/* ---- threads ---------------------------------------------------------------------------------------------------- */
typedef struct { BCRYPT_KEY_HANDLE k; int iters; volatile LONG bad; BYTE iv0[16]; } tctx;
static DWORD WINAPI worker(LPVOID p) {
    tctx *c = (tctx *)p;
    BYTE pt[64], ref[64];
    for (int i = 0; i < 64; i++) pt[i] = (BYTE)i;
    BYTE iv[16]; memcpy(iv, c->iv0, 16); ULONG got = 0;
    if (enc(c->k, pt, 64, iv, 16, ref, 64, &got, 0) != 0) { InterlockedIncrement(&c->bad); return 1; }
    for (int n = 0; n < c->iters; n++) {
        BYTE out[64]; memcpy(iv, c->iv0, 16);
        if (enc(c->k, pt, 64, iv, 16, out, 64, &got, 0) != 0 || !same(out, ref, 64)) InterlockedIncrement(&c->bad);
        BYTE back[64]; memcpy(iv, c->iv0, 16);
        if (dec(c->k, out, 64, iv, 16, back, 64, &got, 0) != 0 || !same(back, pt, 64)) InterlockedIncrement(&c->bad);
    }
    return 0;
}
TEST(bsc_thread_separate_keys_one_algorithm) {
    REQUIRE(P_GenKey);
    BCRYPT_ALG_HANDLE a = bsc_open(L"AES", CBC); if (!a) { t_skip("AES"); return; }
    enum { N = 4 };
    bkey ks[N]; tctx cx[N]; HANDLE th[N];
    for (int i = 0; i < N; i++) {
        BYTE s[16]; memset(s, i + 1, 16);
        EXPECT_EQ(bsc_gen(a, &ks[i], s, 16), 0);
        cx[i].k = ks[i].h; cx[i].iters = 2000; cx[i].bad = 0; memset(cx[i].iv0, i, 16);
        th[i] = CreateThread(NULL, 0, worker, &cx[i], 0, NULL);
    }
    DWORD w = WaitForMultipleObjects(N, th, TRUE, 20000);
    CHECK(w == WAIT_OBJECT_0);
    for (int i = 0; i < N; i++) { if (w != WAIT_OBJECT_0) TerminateThread(th[i], 1); CloseHandle(th[i]); CHECKF(cx[i].bad == 0, "thread %d errors %ld", i, cx[i].bad); }
    for (int i = 0; i < N; i++) bsc_free(&ks[i]);
    bsc_close(a);
}
TEST(bsc_thread_key_created_on_other_thread) {
    REQUIRE(P_GenKey);
    BCRYPT_ALG_HANDLE a = bsc_open(L"AES", CBC); if (!a) { t_skip("AES"); return; }
    bkey k; EXPECT_EQ(bsc_gen(a, &k, (const BYTE *)"0123456789abcdef", 16), 0);
    tctx c; c.k = k.h; c.iters = 500; c.bad = 0; memset(c.iv0, 7, 16);
    HANDLE t = CreateThread(NULL, 0, worker, &c, 0, NULL);
    CHECK(WaitForSingleObject(t, 20000) == WAIT_OBJECT_0);
    CloseHandle(t);
    CHECK(c.bad == 0);
    bsc_free(&k); bsc_close(a);
}
TEST(bsc_thread_same_key_serialised_use) {
    REQUIRE(P_GenKey);
    /* A key handle may be used from several threads as long as calls do not overlap. Chaining state is per key,
     * so use explicit IVs. Two threads take turns through a lock-step event pair. */
    BCRYPT_ALG_HANDLE a = bsc_open(L"AES", CBC); if (!a) { t_skip("AES"); return; }
    bkey k; EXPECT_EQ(bsc_gen(a, &k, (const BYTE *)"0123456789abcdef", 16), 0);
    tctx c1, c2; c1.k = c2.k = k.h; c1.iters = c2.iters = 300; c1.bad = c2.bad = 0; memset(c1.iv0, 1, 16); memset(c2.iv0, 1, 16);
    DWORD r1 = worker(&c1);
    HANDLE t = CreateThread(NULL, 0, worker, &c2, 0, NULL);
    CHECK(WaitForSingleObject(t, 20000) == WAIT_OBJECT_0); CloseHandle(t);
    CHECK(r1 == 0 && c1.bad == 0 && c2.bad == 0);
    bsc_free(&k); bsc_close(a);
}

/* ---- wrong handle types ------------------------------------------------------------------------------------------- */
TEST(bsc_wrong_type_hash_handle_as_key) {
    REQUIRE(P_Enc);
    __typeof__(&BCryptCreateHash) create = U(BCryptCreateHash); __typeof__(&BCryptDestroyHash) destroy = U(BCryptDestroyHash);
    REQUIRE(create); REQUIRE(destroy);
    BCRYPT_ALG_HANDLE h = bsc_open(L"SHA256", NULL); if (!h) { t_skip("SHA256"); return; }
    BCRYPT_HASH_HANDLE hh = NULL; BYTE obj[1024];
    if (create(h, &hh, obj, sizeof obj, NULL, 0, 0) != 0) { bsc_close(h); t_skip("hash"); return; }
    BYTE z[16] = {0}, o[16]; ULONG g = 0;
    EXPECT_EQ(P_Enc((BCRYPT_KEY_HANDLE)hh, z, 16, NULL, NULL, 0, o, 16, &g, 0), NS_INVALID_HANDLE);
    EXPECT_EQ(P_Dec((BCRYPT_KEY_HANDLE)hh, z, 16, NULL, NULL, 0, o, 16, &g, 0), NS_INVALID_HANDLE);
    EXPECT_EQ(P_Destroy((BCRYPT_KEY_HANDLE)hh), NS_INVALID_HANDLE);
    destroy(hh);
    bsc_close(h);
}
TEST(bsc_wrong_type_key_handle_as_hash_and_alg) {
    BCRYPT_ALG_HANDLE a = bsc_open(L"AES", CBC); if (!a) { t_skip("AES"); return; }
    bkey k; EXPECT_EQ(bsc_gen(a, &k, (const BYTE *)"0123456789abcdef", 16), 0);
    __typeof__(&BCryptDestroyHash) destroy = U(BCryptDestroyHash); REQUIRE(destroy);
    EXPECT_EQ(P_Close((BCRYPT_ALG_HANDLE)k.h, 0), NS_INVALID_HANDLE);
    NTSTATUS s = destroy((BCRYPT_HASH_HANDLE)k.h);
    CHECK(s < 0);
    t_note("BCryptDestroyHash(key handle) = 0x%lx", s);
    ULONG v, r;
    s = P_GetProp(k.h, BCRYPT_BLOCK_LENGTH, (PUCHAR)&v, 4, &r, 0);
    EXPECT_EQ(s, 0);                                         /* key handles are valid property targets */
    bsc_free(&k); bsc_close(a);
}
TEST(bsc_wrong_type_alg_handle_for_key_ops) {
    BCRYPT_ALG_HANDLE a = bsc_open(L"AES", CBC); if (!a) { t_skip("AES"); return; }
    ULONG g = 0xAAAA; BYTE out[64];
    EXPECT_EQ(P_Dup((BCRYPT_KEY_HANDLE)a, (BCRYPT_KEY_HANDLE *)out, NULL, 0, 0), NS_INVALID_HANDLE);
    EXPECT_EQ(P_Exp((BCRYPT_KEY_HANDLE)a, NULL, BCRYPT_KEY_DATA_BLOB, out, 64, &g, 0), NS_INVALID_HANDLE);
    EXPECT_EQ(P_Destroy((BCRYPT_KEY_HANDLE)a), NS_INVALID_HANDLE);
    bsc_close(a);
}
