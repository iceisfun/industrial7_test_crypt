/* Authenticated modes: AES-GCM and AES-CCM through BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO.
 * Constraints below (12-byte GCM nonce, 12..16 byte GCM tag, CCM nonce 7..13 / even tag 4..16, structure validation,
 * chaining flags) were read from bcryptprimitives.dll (MSBlockEncrypt/MSBlockDecrypt/AesGcmFn/AesCcm) and bcrypt.dll. */
#include "bsc.h"
#include "vectors.h"

#define GCM BCRYPT_CHAIN_MODE_GCM
#define CCM BCRYPT_CHAIN_MODE_CCM

typedef struct { BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO i; BYTE tag[16]; } ainfo;
static void ai_init(ainfo *a, const BYTE *nonce, ULONG cbn, const BYTE *aad, ULONG cba, ULONG cbtag) {
    memset(a, 0, sizeof *a);
    BCRYPT_INIT_AUTH_MODE_INFO(a->i);
    a->i.pbNonce = (PUCHAR)nonce; a->i.cbNonce = cbn;
    a->i.pbAuthData = (PUCHAR)aad; a->i.cbAuthData = cba;
    a->i.pbTag = a->tag; a->i.cbTag = cbtag;
    memset(a->tag, 0xFF, 16);
}
static NTSTATUS aenc(BCRYPT_KEY_HANDLE k, ainfo *a, const BYTE *in, ULONG n, BYTE *iv, ULONG cbiv, BYTE *out, ULONG cbo, ULONG *got, ULONG fl) {
    return P_Enc(k, (PUCHAR)in, n, a ? &a->i : NULL, iv, cbiv, out, cbo, got, fl);
}
static NTSTATUS adec(BCRYPT_KEY_HANDLE k, ainfo *a, const BYTE *in, ULONG n, BYTE *iv, ULONG cbiv, BYTE *out, ULONG cbo, ULONG *got, ULONG fl) {
    return P_Dec(k, (PUCHAR)in, n, a ? &a->i : NULL, iv, cbiv, out, cbo, got, fl);
}

/* ---- known answers ------------------------------------------------------------------ */
static void gcm_row(const struct gcmv *v) {
    fx f; FX_OR_SKIP(f, L"AES", GCM, v->key);
    BYTE nonce[128], aad[128], pt[128], ct[128], tag[16], out[128], back[128];
    ULONG nn = (ULONG)hx(v->iv, nonce), na = (ULONG)hx(v->aad, aad), np = (ULONG)hx(v->pt, pt);
    hx(v->ct, ct); hx(v->tag, tag);
    ainfo a; ULONG got = 0xAAAA;
    ai_init(&a, nonce, nn, na ? aad : NULL, na, 16);
    memset(out, 0xEE, sizeof out);
    NTSTATUS s = aenc(f.k.h, &a, pt, np, NULL, 0, out, np, &got, 0);
    if (WINE_UNSUP(s)) { t_skip("unsupported under emulator"); fx_close(&f); return; }
    if (nn != 12) {                                    /* 12 byte nonces only */
        if (!t_is_wine()) EXPECT_EQ(s, NS_INVALID_PARAM);
        fx_close(&f); return;
    }
    EXPECT_EQ(s, 0); EXPECT_EQ(got, np);
    CHECK(same(out, ct, np)); CHECK(out[np] == 0xEE);
    CHECK(same(a.tag, tag, 16));
    /* decrypt */
    ai_init(&a, nonce, nn, na ? aad : NULL, na, 16); memcpy(a.tag, tag, 16);
    memset(back, 0xEE, sizeof back); got = 0xAAAA;
    s = adec(f.k.h, &a, ct, np, NULL, 0, back, np, &got, 0);
    EXPECT_EQ(s, 0); EXPECT_EQ(got, np); CHECK(same(back, pt, np));
    /* in place */
    memcpy(back, ct, np); ai_init(&a, nonce, nn, na ? aad : NULL, na, 16); memcpy(a.tag, tag, 16);
    s = adec(f.k.h, &a, back, np, NULL, 0, back, np, &got, 0);
    EXPECT_EQ(s, 0); CHECK(same(back, pt, np));
    fx_close(&f);
}
#define GCMT(nm, idx) TEST(nm) { gcm_row(&k_gcm[idx]); }
GCMT(bsc_gcm_kat_tc1_empty128, 0)
GCMT(bsc_gcm_kat_tc2_16zero128, 1)
GCMT(bsc_gcm_kat_tc3_64b128, 2)
GCMT(bsc_gcm_kat_tc4_60b_aad128, 3)
GCMT(bsc_gcm_nonce8_rejected, 4)
GCMT(bsc_gcm_nonce60_rejected, 5)
GCMT(bsc_gcm_kat_tc7_empty192, 6)
GCMT(bsc_gcm_kat_tc10_aad192, 7)
GCMT(bsc_gcm_kat_tc13_empty256, 8)
GCMT(bsc_gcm_kat_tc16_aad256, 9)
GCMT(bsc_gcm_kat_aad_only128, 10)
GCMT(bsc_gcm_kat_17byte128, 11)
GCMT(bsc_gcm_kat_1byte128, 12)
GCMT(bsc_gcm_kat_15byte_aad5_128, 13)

static void ccm_row(const struct ccmv *v) {
    fx f; FX_OR_SKIP(f, L"AES", CCM, v->key);
    BYTE nonce[16], aad[64], pt[128], ct[128], tag[16], out[128], back[128];
    ULONG nn = (ULONG)hx(v->nonce, nonce), na = (ULONG)hx(v->aad, aad), np = (ULONG)hx(v->pt, pt), nt = (ULONG)hx(v->tag, tag);
    hx(v->ct, ct);
    ainfo a; ULONG got = 0xAAAA;
    ai_init(&a, nonce, nn, na ? aad : NULL, na, nt);
    memset(out, 0xEE, sizeof out);
    NTSTATUS s = aenc(f.k.h, &a, np ? pt : (BYTE *)"", np, NULL, 0, out, np, &got, 0);
    if (WINE_UNSUP(s) || (t_is_wine() && s != 0)) { t_skip("CCM unsupported/differs under emulator"); fx_close(&f); return; }
    EXPECT_EQ(s, 0); EXPECT_EQ(got, np);
    CHECK(same(out, ct, np)); CHECK(out[np] == 0xEE);
    CHECK(same(a.tag, tag, nt));
    BYTE ff[16]; memset(ff, 0xFF, 16); CHECK(same(a.tag + nt, ff, 16 - nt));   /* only cbTag bytes written */
    ai_init(&a, nonce, nn, na ? aad : NULL, na, nt); memcpy(a.tag, tag, nt);
    memset(back, 0xEE, sizeof back);
    s = adec(f.k.h, &a, ct, np, NULL, 0, back, np, &got, 0);
    EXPECT_EQ(s, 0); EXPECT_EQ(got, np); CHECK(same(back, pt, np));
    fx_close(&f);
}
#define CCMT(nm, idx) TEST(nm) { ccm_row(&k_ccm[idx]); }
CCMT(bsc_ccm_kat_sp38c_ex1_n7_t4, 0)
CCMT(bsc_ccm_kat_sp38c_ex2_n8_t6, 1)
CCMT(bsc_ccm_kat_sp38c_ex3_n12_t8, 2)
CCMT(bsc_ccm_kat_n7_t16_noaad, 3)
CCMT(bsc_ccm_kat_n13_t12_aad, 4)
CCMT(bsc_ccm_kat_n12_t10, 5)
CCMT(bsc_ccm_kat_n8_t14_aes192, 6)
CCMT(bsc_ccm_kat_n11_t8_aes256, 7)
CCMT(bsc_ccm_kat_n9_t4_empty, 8)
CCMT(bsc_ccm_kat_n10_t16_1byte, 9)

/* ---- GCM tag lengths ----------------------------------------------------------------- */
TEST(bsc_gcm_truncated_tag_is_prefix) {
    const struct gcmv *v = &k_gcm[3];
    fx f; FX_OR_SKIP(f, L"AES", GCM, v->key);
    BYTE nonce[16], aad[32], pt[64], ct[64], tag[16], out[64]; ULONG nn = (ULONG)hx(v->iv, nonce), na = (ULONG)hx(v->aad, aad), np = (ULONG)hx(v->pt, pt);
    hx(v->ct, ct); hx(v->tag, tag);
    for (ULONG tl = 12; tl <= 16; tl++) {
        ainfo a; ULONG got = 0;
        ai_init(&a, nonce, nn, aad, na, tl);
        NTSTATUS s = aenc(f.k.h, &a, pt, np, NULL, 0, out, np, &got, 0);
        CHECKF(s == 0, "tag len %lu: 0x%lx", tl, s);
        CHECKF(same(a.tag, tag, tl), "tag len %lu prefix", tl);
        BYTE ff[16]; memset(ff, 0xFF, 16);
        CHECKF(same(a.tag + tl, ff, 16 - tl), "tag len %lu overrun", tl);
        /* and the shortened tag verifies */
        ai_init(&a, nonce, nn, aad, na, tl); memcpy(a.tag, tag, tl);
        s = adec(f.k.h, &a, ct, np, NULL, 0, out, np, &got, 0);
        CHECKF(s == 0, "tag len %lu verify: 0x%lx", tl, s);
    }
    fx_close(&f);
}
TEST(bsc_gcm_tag_length_out_of_range) {
    const struct gcmv *v = &k_gcm[3];
    fx f; FX_OR_SKIP(f, L"AES", GCM, v->key);
    BYTE nonce[16], aad[32], pt[64], out[64]; ULONG nn = (ULONG)hx(v->iv, nonce), na = (ULONG)hx(v->aad, aad), np = (ULONG)hx(v->pt, pt);
    ULONG bad[] = { 0, 1, 4, 8, 11 };
    for (int i = 0; i < 5; i++) {
        ainfo a; ULONG got = 0;
        ai_init(&a, nonce, nn, aad, na, bad[i]);
        NTSTATUS s = aenc(f.k.h, &a, pt, np, NULL, 0, out, np, &got, 0);
        if (t_is_wine()) continue;
        CHECKF(s == NS_INVALID_PARAM, "cbTag=%lu 0x%lx", bad[i], s);
    }
    /* 17 and above: the tag buffer used here is only 16 bytes, so use an oversized buffer */
    struct { BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO i; BYTE tag[32]; } big;
    memset(&big, 0, sizeof big); BCRYPT_INIT_AUTH_MODE_INFO(big.i);
    big.i.pbNonce = nonce; big.i.cbNonce = nn; big.i.pbAuthData = aad; big.i.cbAuthData = na; big.i.pbTag = big.tag; big.i.cbTag = 17;
    ULONG got = 0;
    NTSTATUS s = P_Enc(f.k.h, pt, np, &big.i, NULL, 0, out, np, &got, 0);
    if (!t_is_wine()) EXPECT_EQ(s, NS_INVALID_PARAM);
    big.i.cbTag = 32;
    s = P_Enc(f.k.h, pt, np, &big.i, NULL, 0, out, np, &got, 0);
    if (!t_is_wine()) EXPECT_EQ(s, NS_INVALID_PARAM);
    fx_close(&f);
}
TEST(bsc_gcm_nonce_length_must_be_12) {
    const struct gcmv *v = &k_gcm[3];
    fx f; FX_OR_SKIP(f, L"AES", GCM, v->key);
    BYTE nonce[64]; memset(nonce, 0x42, 64); BYTE pt[16] = {0}, out[16];
    ULONG bad[] = { 0, 1, 7, 8, 11, 13, 16, 32, 60 };
    for (int i = 0; i < 9; i++) {
        ainfo a; ULONG got = 0;
        ai_init(&a, nonce, bad[i], NULL, 0, 16);
        NTSTATUS s = aenc(f.k.h, &a, pt, 16, NULL, 0, out, 16, &got, 0);
        if (t_is_wine()) continue;
        CHECKF(s == NS_INVALID_PARAM, "cbNonce=%lu 0x%lx", bad[i], s);
    }
    ainfo a; ULONG got = 0;
    ai_init(&a, nonce, 12, NULL, 0, 16);
    EXPECT_EQ(aenc(f.k.h, &a, pt, 16, NULL, 0, out, 16, &got, 0), 0);
    fx_close(&f);
}

/* ---- structure validation (validateAuthCipherModeInfo) ---------------------------------------- */
static void setup_gcm(fx *f, ainfo *a, BYTE *nonce) {
    memset(nonce, 0x24, 12);
    ai_init(a, nonce, 12, NULL, 0, 16);
}
TEST(bsc_auth_missing_info_struct) {
    fx f; FX_OR_SKIP(f, L"AES", GCM, KEY16);
    BYTE pt[16] = {0}, out[16]; ULONG got = 0xAAAA;
    EXPECT_EQ(aenc(f.k.h, NULL, pt, 16, NULL, 0, out, 16, &got, 0), NS_INVALID_PARAM);
    EXPECT_EQ(adec(f.k.h, NULL, pt, 16, NULL, 0, out, 16, &got, 0), NS_INVALID_PARAM);
    fx_close(&f);
}
TEST(bsc_auth_info_cbsize_too_small) {
    WINE_SKIP("struct validation differs");
    fx f; FX_OR_SKIP(f, L"AES", GCM, KEY16);
    BYTE nonce[12], pt[16] = {0}, out[16]; ULONG got = 0xAAAA; ainfo a;
    ULONG bad[] = { 0, 1, 0x20, 0x50, 0x57 };
    for (int i = 0; i < 5; i++) {
        setup_gcm(&f, &a, nonce); a.i.cbSize = bad[i];
        NTSTATUS s = aenc(f.k.h, &a, pt, 16, NULL, 0, out, 16, &got, 0);
        CHECKF(s == NS_INVALID_PARAM, "cbSize=0x%lx -> 0x%lx", bad[i], s);
    }
    setup_gcm(&f, &a, nonce); a.i.cbSize = 0x58;
    EXPECT_EQ(aenc(f.k.h, &a, pt, 16, NULL, 0, out, 16, &got, 0), 0);
    setup_gcm(&f, &a, nonce); a.i.cbSize = 0x200;
    EXPECT_EQ(aenc(f.k.h, &a, pt, 16, NULL, 0, out, 16, &got, 0), 0);
    CHECK(sizeof(BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO) == 0x58);
    fx_close(&f);
}
TEST(bsc_auth_info_version) {
    WINE_SKIP("struct validation differs");
    fx f; FX_OR_SKIP(f, L"AES", GCM, KEY16);
    BYTE nonce[12], pt[16] = {0}, out[16]; ULONG got = 0xAAAA; ainfo a;
    ULONG bad[] = { 0, 2, 3, 0x100 };
    for (int i = 0; i < 4; i++) {
        setup_gcm(&f, &a, nonce); a.i.dwInfoVersion = bad[i];
        NTSTATUS s = aenc(f.k.h, &a, pt, 16, NULL, 0, out, 16, &got, 0);
        CHECKF(s == NS_INVALID_PARAM, "version=%lu -> 0x%lx", bad[i], s);
    }
    fx_close(&f);
}
TEST(bsc_auth_info_null_nonce) {
    WINE_SKIP("struct validation differs");
    fx f; FX_OR_SKIP(f, L"AES", GCM, KEY16);
    BYTE nonce[12], pt[16] = {0}, out[16]; ULONG got = 0xAAAA; ainfo a;
    setup_gcm(&f, &a, nonce); a.i.pbNonce = NULL;
    EXPECT_EQ(aenc(f.k.h, &a, pt, 16, NULL, 0, out, 16, &got, 0), NS_INVALID_PARAM);
    EXPECT_EQ(adec(f.k.h, &a, pt, 16, NULL, 0, out, 16, &got, 0), NS_INVALID_PARAM);
    fx_close(&f);
}
TEST(bsc_auth_info_unknown_flags) {
    WINE_SKIP("struct validation differs");
    fx f; FX_OR_SKIP(f, L"AES", GCM, KEY16);
    BYTE nonce[12], pt[16] = {0}, out[16]; ULONG got = 0xAAAA; ainfo a;
    ULONG bad[] = { 4, 8, 0x10, 0x20, 0x80, 0x80000000, 0xFFFFFFFC };
    for (int i = 0; i < 7; i++) {
        setup_gcm(&f, &a, nonce); a.i.dwFlags = bad[i];
        NTSTATUS s = aenc(f.k.h, &a, pt, 16, NULL, 0, out, 16, &got, 0);
        CHECKF(s == NS_INVALID_PARAM, "dwFlags=0x%lx -> 0x%lx", bad[i], s);
    }
    fx_close(&f);
}
TEST(bsc_auth_chain_flags_require_mac_context) {
    WINE_SKIP("struct validation differs");
    fx f; FX_OR_SKIP(f, L"AES", GCM, KEY16);
    BYTE nonce[12], pt[16] = {0}, out[16], iv[16] = {0}; ULONG got = 0xAAAA; ainfo a;
    ULONG fl[] = { BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG, BCRYPT_AUTH_MODE_IN_PROGRESS_FLAG, 3 };
    for (int i = 0; i < 3; i++) {
        setup_gcm(&f, &a, nonce); a.i.dwFlags = fl[i];        /* pbMacContext == NULL */
        NTSTATUS s = aenc(f.k.h, &a, pt, 16, iv, 16, out, 16, &got, 0);
        CHECKF(s == NS_INVALID_PARAM, "flags=%lu -> 0x%lx", fl[i], s);
    }
    fx_close(&f);
}
TEST(bsc_auth_padding_flag_rejected) {
    fx f; FX_OR_SKIP(f, L"AES", GCM, KEY16);
    BYTE nonce[12], pt[32] = {0}, out[48]; ULONG got = 0xAAAA; ainfo a;
    setup_gcm(&f, &a, nonce);
    NTSTATUS s = aenc(f.k.h, &a, pt, 32, NULL, 0, out, 48, &got, BCRYPT_BLOCK_PADDING);
    EXPECT_EQ(s, NS_INVALID_PARAM);
    s = adec(f.k.h, &a, pt, 32, NULL, 0, out, 48, &got, BCRYPT_BLOCK_PADDING);
    EXPECT_EQ(s, NS_INVALID_PARAM);
    fx_close(&f);
}
TEST(bsc_auth_info_ignored_by_non_auth_mode) {
    fx f; FX_OR_SKIP(f, L"AES", BCRYPT_CHAIN_MODE_CBC, KEY16);
    BYTE pt[16] = {0}, out[16], iv[16] = {0}; ULONG got = 0xAAAA;
    BYTE junk[16] = {1};
    NTSTATUS s = P_Enc(f.k.h, pt, 16, junk, iv, 16, out, 16, &got, 0);      /* pPaddingInfo is not used by symmetric block modes */
    t_note("CBC encrypt with non-NULL pPaddingInfo -> 0x%lx", s);
    fx_close(&f);
}

/* ---- size protocol for authenticated modes ------------------------------------------------------ */
TEST(bsc_gcm_size_query_with_data_leaves_tag) {
    fx f; FX_OR_SKIP(f, L"AES", GCM, KEY16);
    BYTE nonce[12], pt[32] = {0}; ULONG got = 0xAAAA; ainfo a;
    setup_gcm(&f, &a, nonce);
    EXPECT_EQ(aenc(f.k.h, &a, pt, 32, NULL, 0, NULL, 0, &got, 0), 0);
    EXPECT_EQ(got, 32);
    BYTE ff[16]; memset(ff, 0xFF, 16); CHECK(same(a.tag, ff, 16));
    EXPECT_EQ(aenc(f.k.h, &a, pt, 0, NULL, 0, NULL, 0, &got, 0), 0);
    EXPECT_EQ(got, 0); CHECK(same(a.tag, ff, 16));
    fx_close(&f);
}
TEST(bsc_gcm_null_input_null_output_computes_tag) {
    const struct gcmv *v = &k_gcm[10];                 /* AAD only */
    fx f; FX_OR_SKIP(f, L"AES", GCM, v->key);
    BYTE nonce[12], aad[32], tag[16]; ULONG nn = (ULONG)hx(v->iv, nonce), na = (ULONG)hx(v->aad, aad); hx(v->tag, tag);
    ainfo a; ULONG got = 0xAAAA;
    ai_init(&a, nonce, nn, aad, na, 16);
    EXPECT_EQ(aenc(f.k.h, &a, NULL, 0, NULL, 0, NULL, 0, &got, 0), 0);
    EXPECT_EQ(got, 0);
    CHECK(same(a.tag, tag, 16));
    fx_close(&f);
}
TEST(bsc_gcm_output_too_small) {
    const struct gcmv *v = &k_gcm[3];
    fx f; FX_OR_SKIP(f, L"AES", GCM, v->key);
    BYTE nonce[12], aad[32], pt[64], out[64]; ULONG nn = (ULONG)hx(v->iv, nonce), na = (ULONG)hx(v->aad, aad), np = (ULONG)hx(v->pt, pt);
    ainfo a; ULONG got = 0xAAAA;
    ai_init(&a, nonce, nn, aad, na, 16);
    EXPECT_EQ(aenc(f.k.h, &a, pt, np, NULL, 0, out, np - 1, &got, 0), NS_BUFFER_TOO_SMALL);
    EXPECT_EQ(got, np);
    BYTE ff[16]; memset(ff, 0xFF, 16); CHECK(same(a.tag, ff, 16));
    EXPECT_EQ(aenc(f.k.h, &a, pt, np, NULL, 0, out, np + 20, &got, 0), 0); EXPECT_EQ(got, np);
    fx_close(&f);
}
TEST(bsc_gcm_iv_buffer_untouched_in_single_call) {
    const struct gcmv *v = &k_gcm[3];
    fx f; FX_OR_SKIP(f, L"AES", GCM, v->key);
    BYTE nonce[12], aad[32], pt[64], out[64], iv[16], iv0[16]; ULONG nn = (ULONG)hx(v->iv, nonce), na = (ULONG)hx(v->aad, aad), np = (ULONG)hx(v->pt, pt);
    memset(iv, 0x5C, 16); memcpy(iv0, iv, 16);
    ainfo a; ULONG got = 0;
    ai_init(&a, nonce, nn, aad, na, 16);
    EXPECT_EQ(aenc(f.k.h, &a, pt, np, iv, 16, out, np, &got, 0), 0);
    CHECK(same(iv, iv0, 16));
    CHECK_HEX(out, np, v->ct);
    fx_close(&f);
}
TEST(bsc_gcm_repeated_use_same_key_is_stateless) {
    const struct gcmv *v = &k_gcm[3];
    fx f; FX_OR_SKIP(f, L"AES", GCM, v->key);
    BYTE nonce[12], aad[32], pt[64], o1[64], o2[64]; ULONG nn = (ULONG)hx(v->iv, nonce), na = (ULONG)hx(v->aad, aad), np = (ULONG)hx(v->pt, pt);
    ainfo a; ULONG got = 0;
    ai_init(&a, nonce, nn, aad, na, 16); EXPECT_EQ(aenc(f.k.h, &a, pt, np, NULL, 0, o1, np, &got, 0), 0);
    BYTE t1[16]; memcpy(t1, a.tag, 16);
    ai_init(&a, nonce, nn, aad, na, 16); EXPECT_EQ(aenc(f.k.h, &a, pt, np, NULL, 0, o2, np, &got, 0), 0);
    CHECK(same(o1, o2, np)); CHECK(same(a.tag, t1, 16));
    fx_close(&f);
}

/* ---- authentication failures ------------------------------------------------------------------------------ */
typedef struct { fx f; BYTE nonce[12], aad[32], pt[64], ct[64], tag[16]; ULONG nn, na, np; } gcase;
static int gcase_open(gcase *g, int row) {
    const struct gcmv *v = &k_gcm[row];
    if (!fx_open(&g->f, L"AES", GCM, v->key)) return 0;
    g->nn = (ULONG)hx(v->iv, g->nonce); g->na = (ULONG)hx(v->aad, g->aad); g->np = (ULONG)hx(v->pt, g->pt);
    hx(v->ct, g->ct); hx(v->tag, g->tag);
    return 1;
}
#define GC(g, row) gcase g; if (!gcase_open(&g, row)) { if (!t_is_wine()) CHECK(0); t_skip("no GCM"); return; }
TEST(bsc_gcm_tag_mismatch) {
    GC(g, 3);
    ainfo a; BYTE out[64]; ULONG got = 0xAAAA;
    ai_init(&a, g.nonce, g.nn, g.aad, g.na, 16); memcpy(a.tag, g.tag, 16); a.tag[0] ^= 1;
    NTSTATUS s = adec(g.f.k.h, &a, g.ct, g.np, NULL, 0, out, g.np, &got, 0);
    EXPECT_EQ(s, NS_AUTH_TAG_MISMATCH);
    t_note("pcbResult after tag mismatch = %lu", got);
    fx_close(&g.f);
}
TEST(bsc_gcm_tag_mismatch_last_byte) {
    GC(g, 3);
    ainfo a; BYTE out[64]; ULONG got = 0;
    ai_init(&a, g.nonce, g.nn, g.aad, g.na, 16); memcpy(a.tag, g.tag, 16); a.tag[15] ^= 0x80;
    EXPECT_EQ(adec(g.f.k.h, &a, g.ct, g.np, NULL, 0, out, g.np, &got, 0), NS_AUTH_TAG_MISMATCH);
    fx_close(&g.f);
}
TEST(bsc_gcm_ciphertext_tamper) {
    GC(g, 3);
    ainfo a; BYTE out[64], ct[64]; ULONG got = 0; memcpy(ct, g.ct, g.np); ct[g.np - 1] ^= 1;
    ai_init(&a, g.nonce, g.nn, g.aad, g.na, 16); memcpy(a.tag, g.tag, 16);
    EXPECT_EQ(adec(g.f.k.h, &a, ct, g.np, NULL, 0, out, g.np, &got, 0), NS_AUTH_TAG_MISMATCH);
    fx_close(&g.f);
}
TEST(bsc_gcm_aad_tamper) {
    GC(g, 3);
    ainfo a; BYTE out[64], aad[32]; ULONG got = 0; memcpy(aad, g.aad, g.na); aad[0] ^= 1;
    ai_init(&a, g.nonce, g.nn, aad, g.na, 16); memcpy(a.tag, g.tag, 16);
    EXPECT_EQ(adec(g.f.k.h, &a, g.ct, g.np, NULL, 0, out, g.np, &got, 0), NS_AUTH_TAG_MISMATCH);
    ai_init(&a, g.nonce, g.nn, g.aad, g.na - 1, 16); memcpy(a.tag, g.tag, 16);
    EXPECT_EQ(adec(g.f.k.h, &a, g.ct, g.np, NULL, 0, out, g.np, &got, 0), NS_AUTH_TAG_MISMATCH);
    ai_init(&a, g.nonce, g.nn, NULL, 0, 16); memcpy(a.tag, g.tag, 16);
    EXPECT_EQ(adec(g.f.k.h, &a, g.ct, g.np, NULL, 0, out, g.np, &got, 0), NS_AUTH_TAG_MISMATCH);
    fx_close(&g.f);
}
TEST(bsc_gcm_nonce_tamper) {
    GC(g, 3);
    ainfo a; BYTE out[64], nonce[12]; ULONG got = 0; memcpy(nonce, g.nonce, 12); nonce[11] ^= 1;
    ai_init(&a, nonce, 12, g.aad, g.na, 16); memcpy(a.tag, g.tag, 16);
    EXPECT_EQ(adec(g.f.k.h, &a, g.ct, g.np, NULL, 0, out, g.np, &got, 0), NS_AUTH_TAG_MISMATCH);
    fx_close(&g.f);
}
TEST(bsc_gcm_wrong_key_mismatch) {
    GC(g, 3);
    fx h; if (!fx_open(&h, L"AES", GCM, "00112233445566778899aabbccddeeff")) { fx_close(&g.f); t_skip("AES"); return; }
    ainfo a; BYTE out[64]; ULONG got = 0;
    ai_init(&a, g.nonce, g.nn, g.aad, g.na, 16); memcpy(a.tag, g.tag, 16);
    EXPECT_EQ(adec(h.k.h, &a, g.ct, g.np, NULL, 0, out, g.np, &got, 0), NS_AUTH_TAG_MISMATCH);
    fx_close(&h); fx_close(&g.f);
}
TEST(bsc_gcm_truncated_tag_mismatch) {
    GC(g, 3);
    ainfo a; BYTE out[64]; ULONG got = 0;
    ai_init(&a, g.nonce, g.nn, g.aad, g.na, 12); memcpy(a.tag, g.tag, 12); a.tag[11] ^= 1;
    EXPECT_EQ(adec(g.f.k.h, &a, g.ct, g.np, NULL, 0, out, g.np, &got, 0), NS_AUTH_TAG_MISMATCH);
    fx_close(&g.f);
}
TEST(bsc_gcm_decrypt_size_query_no_verification) {
    GC(g, 3);
    ainfo a; ULONG got = 0xAAAA;
    ai_init(&a, g.nonce, g.nn, g.aad, g.na, 16); memcpy(a.tag, g.tag, 16); a.tag[0] ^= 1;     /* bad tag, but only sizing */
    NTSTATUS s = adec(g.f.k.h, &a, g.ct, g.np, NULL, 0, NULL, 0, &got, 0);
    EXPECT_EQ(s, 0); EXPECT_EQ(got, g.np);
    fx_close(&g.f);
}
TEST(bsc_gcm_decrypt_output_too_small) {
    GC(g, 3);
    ainfo a; BYTE out[64]; ULONG got = 0xAAAA;
    ai_init(&a, g.nonce, g.nn, g.aad, g.na, 16); memcpy(a.tag, g.tag, 16);
    EXPECT_EQ(adec(g.f.k.h, &a, g.ct, g.np, NULL, 0, out, g.np - 1, &got, 0), NS_BUFFER_TOO_SMALL);
    EXPECT_EQ(got, g.np);
    fx_close(&g.f);
}
TEST(bsc_ccm_tag_mismatch) {
    const struct ccmv *v = &k_ccm[4];
    fx f; FX_OR_SKIP(f, L"AES", CCM, v->key);
    BYTE nonce[16], aad[16], ct[64], tag[16], out[64]; ULONG nn = (ULONG)hx(v->nonce, nonce), na = (ULONG)hx(v->aad, aad), nc = (ULONG)hx(v->ct, ct), nt = (ULONG)hx(v->tag, tag);
    ainfo a; ULONG got = 0xAAAA;
    ai_init(&a, nonce, nn, aad, na, nt); memcpy(a.tag, tag, nt);
    NTSTATUS s = adec(f.k.h, &a, ct, nc, NULL, 0, out, nc, &got, 0);
    if (t_is_wine() && s != 0) { t_skip("emulator CCM"); fx_close(&f); return; }
    EXPECT_EQ(s, 0);
    a.tag[0] ^= 1;
    EXPECT_EQ(adec(f.k.h, &a, ct, nc, NULL, 0, out, nc, &got, 0), NS_AUTH_TAG_MISMATCH);
    a.tag[0] ^= 1; ct[0] ^= 1;
    EXPECT_EQ(adec(f.k.h, &a, ct, nc, NULL, 0, out, nc, &got, 0), NS_AUTH_TAG_MISMATCH);
    fx_close(&f);
}

/* ---- CCM parameter limits (AesCcm) ---------------------------------------------------------------------------- */
static NTSTATUS ccm_try(ULONG nonce_len, ULONG tag_len, ULONG data_len, int *haveccm) {
    fx f; if (!fx_open(&f, L"AES", CCM, KEY16)) { *haveccm = 0; return 0; }
    *haveccm = 1;
    BYTE nonce[32]; memset(nonce, 0x21, sizeof nonce);
    BYTE *pt = (BYTE *)calloc(1, data_len + 16), *out = (BYTE *)calloc(1, data_len + 16);
    struct { BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO i; BYTE tag[32]; } a;
    memset(&a, 0, sizeof a); BCRYPT_INIT_AUTH_MODE_INFO(a.i);
    a.i.pbNonce = nonce; a.i.cbNonce = nonce_len; a.i.pbTag = a.tag; a.i.cbTag = tag_len;
    ULONG got = 0;
    NTSTATUS s = P_Enc(f.k.h, pt, data_len, &a.i, NULL, 0, out, data_len, &got, 0);
    free(pt); free(out); fx_close(&f);
    return s;
}
TEST(bsc_ccm_nonce_length_range) {
    int have;
    for (ULONG n = 0; n <= 16; n++) {
        NTSTATUS s = ccm_try(n, 16, 16, &have);
        if (!have) { t_skip("no CCM"); return; }
        if (t_is_wine()) continue;
        int valid = (n >= 7 && n <= 13);
        CHECKF(valid ? s == 0 : s == NS_INVALID_PARAM, "nonce %lu -> 0x%lx", n, s);
    }
}
TEST(bsc_ccm_tag_length_range) {
    int have;
    for (ULONG t = 0; t <= 20; t++) {
        NTSTATUS s = ccm_try(12, t, 16, &have);
        if (!have) { t_skip("no CCM"); return; }
        if (t_is_wine()) continue;
        int valid = (t >= 4 && t <= 16 && (t % 2) == 0);
        CHECKF(valid ? s == 0 : s == NS_INVALID_PARAM, "tag %lu -> 0x%lx", t, s);
    }
}
TEST(bsc_ccm_message_length_limit_for_nonce_13) {
    int have;
    NTSTATUS s1 = ccm_try(13, 16, 65535, &have);
    if (!have) { t_skip("no CCM"); return; }
    if (t_is_wine()) { t_skip("emulator"); return; }
    EXPECT_EQ(s1, 0);                               /* L = 2 length bytes: max 65535 */
    NTSTATUS s2 = ccm_try(13, 16, 65536, &have);
    EXPECT_EQ(s2, NS_INVALID_PARAM);
    NTSTATUS s3 = ccm_try(12, 16, 65536, &have);    /* L = 3: fine */
    EXPECT_EQ(s3, 0);
}
TEST(bsc_ccm_chaining_flags_rejected) {
    fx f; FX_OR_SKIP(f, L"AES", CCM, KEY16);
    if (t_is_wine()) { t_skip("emulator"); fx_close(&f); return; }
    BYTE nonce[12] = {1}, pt[16] = {0}, out[16], mac[16] = {0}, iv[16] = {0}; ULONG got = 0;
    ULONG fl[] = { 1, 2, 3 };
    for (int i = 0; i < 3; i++) {
        ainfo a; ai_init(&a, nonce, 12, NULL, 0, 16);
        a.i.dwFlags = fl[i]; a.i.pbMacContext = mac; a.i.cbMacContext = 16;
        NTSTATUS s = aenc(f.k.h, &a, pt, 16, iv, 16, out, 16, &got, 0);
        CHECKF(s == NS_INVALID_PARAM, "flags %lu -> 0x%lx", fl[i], s);
    }
    fx_close(&f);
}
TEST(bsc_ccm_mac_context_alone_rejected) {
    fx f; FX_OR_SKIP(f, L"AES", CCM, KEY16);
    if (t_is_wine()) { t_skip("emulator"); fx_close(&f); return; }
    BYTE nonce[12] = {1}, pt[16] = {0}, out[16], mac[16] = {0}; ULONG got = 0;
    ainfo a; ai_init(&a, nonce, 12, NULL, 0, 16); a.i.pbMacContext = mac; a.i.cbMacContext = 16;
    NTSTATUS s = aenc(f.k.h, &a, pt, 16, NULL, 0, out, 16, &got, 0);
    EXPECT_EQ(s, NS_INVALID_PARAM);
    fx_close(&f);
}
TEST(bsc_ccm_partial_block_data_is_fine) {
    fx f; FX_OR_SKIP(f, L"AES", CCM, KEY16);
    BYTE nonce[12] = {1}, pt[40] = {0}, out[40]; ULONG got = 0;
    for (ULONG n = 0; n <= 33; n++) {
        ainfo a; ai_init(&a, nonce, 12, NULL, 0, 16);
        NTSTATUS s = aenc(f.k.h, &a, pt, n, NULL, 0, out, n, &got, 0);
        if (t_is_wine() && s != 0) { t_skip("emulator"); break; }
        CHECKF(s == 0 && got == n, "n=%lu s=0x%lx", n, s);
    }
    fx_close(&f);
}

/* ---- GCM chaining (BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG / IN_PROGRESS_FLAG) --------------------------------------------- */
typedef struct { BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO i; BYTE tag[16]; BYTE mac[16]; BYTE iv[16]; } chain;
static void chain_init(chain *c, const BYTE *nonce, ULONG nn, const BYTE *aad, ULONG na) {
    memset(c, 0, sizeof *c); BCRYPT_INIT_AUTH_MODE_INFO(c->i);
    c->i.pbNonce = (PUCHAR)nonce; c->i.cbNonce = nn; c->i.pbAuthData = (PUCHAR)aad; c->i.cbAuthData = na;
    c->i.pbTag = c->tag; c->i.cbTag = 16; c->i.pbMacContext = c->mac; c->i.cbMacContext = 16;
}
TEST(bsc_gcm_chained_matches_single_call) {
    WINE_SKIP("GCM chaining not implemented");
    GC(g, 3);
    ULONG cut1 = 32, cut2 = 16, rest = g.np - 48;              /* 60 bytes: 32 + 16 + 12 */
    chain c; chain_init(&c, g.nonce, g.nn, g.aad, g.na);
    BYTE out[64]; ULONG got = 0xAAAA;
    c.i.dwFlags = BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG;
    NTSTATUS s = P_Enc(g.f.k.h, g.pt, cut1, &c.i, c.iv, 16, out, cut1, &got, 0);
    if (t_is_wine() && s != 0) { t_skip("emulator: no chaining"); fx_close(&g.f); return; }
    EXPECT_EQ(s, 0); EXPECT_EQ(got, cut1);
    c.i.pbAuthData = NULL; c.i.cbAuthData = 0;                  /* AAD only in the first call */
    c.i.dwFlags = BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG | BCRYPT_AUTH_MODE_IN_PROGRESS_FLAG;
    s = P_Enc(g.f.k.h, g.pt + cut1, cut2, &c.i, c.iv, 16, out + cut1, cut2, &got, 0);
    EXPECT_EQ(s, 0); EXPECT_EQ(got, cut2);
    c.i.dwFlags = BCRYPT_AUTH_MODE_IN_PROGRESS_FLAG;            /* final call: produces the tag */
    s = P_Enc(g.f.k.h, g.pt + cut1 + cut2, rest, &c.i, c.iv, 16, out + cut1 + cut2, rest, &got, 0);
    EXPECT_EQ(s, 0); EXPECT_EQ(got, rest);
    CHECK(same(out, g.ct, g.np));
    CHECK(same(c.tag, g.tag, 16));
    fx_close(&g.f);
}
TEST(bsc_gcm_chained_decrypt_verifies_at_end) {
    GC(g, 3);
    chain c; chain_init(&c, g.nonce, g.nn, g.aad, g.na);
    BYTE out[64]; ULONG got = 0xAAAA;
    c.i.dwFlags = BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG;
    NTSTATUS s = P_Dec(g.f.k.h, g.ct, 48, &c.i, c.iv, 16, out, 48, &got, 0);
    if (t_is_wine() && s != 0) { t_skip("emulator: no chaining"); fx_close(&g.f); return; }
    EXPECT_EQ(s, 0);
    c.i.pbAuthData = NULL; c.i.cbAuthData = 0;
    c.i.dwFlags = BCRYPT_AUTH_MODE_IN_PROGRESS_FLAG; memcpy(c.tag, g.tag, 16);
    s = P_Dec(g.f.k.h, g.ct + 48, g.np - 48, &c.i, c.iv, 16, out + 48, g.np - 48, &got, 0);
    EXPECT_EQ(s, 0);
    CHECK(same(out, g.pt, g.np));
    fx_close(&g.f);
}
TEST(bsc_gcm_chained_decrypt_bad_tag) {
    GC(g, 3);
    chain c; chain_init(&c, g.nonce, g.nn, g.aad, g.na);
    BYTE out[64]; ULONG got = 0xAAAA;
    c.i.dwFlags = BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG;
    NTSTATUS s = P_Dec(g.f.k.h, g.ct, 48, &c.i, c.iv, 16, out, 48, &got, 0);
    if (t_is_wine() && s != 0) { t_skip("emulator: no chaining"); fx_close(&g.f); return; }
    c.i.pbAuthData = NULL; c.i.cbAuthData = 0;
    c.i.dwFlags = BCRYPT_AUTH_MODE_IN_PROGRESS_FLAG; memcpy(c.tag, g.tag, 16); c.tag[3] ^= 0x10;
    s = P_Dec(g.f.k.h, g.ct + 48, g.np - 48, &c.i, c.iv, 16, out + 48, g.np - 48, &got, 0);
    EXPECT_EQ(s, NS_AUTH_TAG_MISMATCH);
    fx_close(&g.f);
}
TEST(bsc_gcm_chained_requires_block_multiples_until_final) {
    GC(g, 3);
    if (t_is_wine()) { t_skip("emulator"); fx_close(&g.f); return; }
    chain c; chain_init(&c, g.nonce, g.nn, g.aad, g.na);
    BYTE out[64]; ULONG got = 0xAAAA;
    c.i.dwFlags = BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG;
    NTSTATUS s = P_Enc(g.f.k.h, g.pt, 17, &c.i, c.iv, 16, out, 17, &got, 0);
    EXPECT_EQ(s, NS_INVALID_BUFFER_SIZE);
    fx_close(&g.f);
}
TEST(bsc_gcm_chained_needs_iv_buffer) {
    GC(g, 3);
    if (t_is_wine()) { t_skip("emulator"); fx_close(&g.f); return; }
    chain c; chain_init(&c, g.nonce, g.nn, g.aad, g.na);
    BYTE out[64]; ULONG got = 0xAAAA;
    c.i.dwFlags = BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG;
    EXPECT_EQ(P_Enc(g.f.k.h, g.pt, 16, &c.i, NULL, 0, out, 16, &got, 0), NS_INVALID_PARAM);
    c.i.cbMacContext = 8;
    EXPECT_EQ(P_Enc(g.f.k.h, g.pt, 16, &c.i, c.iv, 16, out, 16, &got, 0), NS_INVALID_PARAM);
    fx_close(&g.f);
}
TEST(bsc_gcm_chained_state_lives_in_caller_buffers) {
    WINE_SKIP("GCM chaining not implemented");
    /* The same chain driven through two different key handles (same key material) yields the same result, so all
     * chaining state is in pbMacContext / pbIV / the info struct, not in the key. */
    GC(g, 3);
    fx h; if (!fx_open(&h, L"AES", GCM, k_gcm[3].key)) { fx_close(&g.f); t_skip("AES"); return; }
    chain c; chain_init(&c, g.nonce, g.nn, g.aad, g.na);
    BYTE out[64]; ULONG got = 0xAAAA;
    c.i.dwFlags = BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG;
    NTSTATUS s = P_Enc(g.f.k.h, g.pt, 32, &c.i, c.iv, 16, out, 32, &got, 0);
    if (t_is_wine() && s != 0) { t_skip("emulator"); fx_close(&h); fx_close(&g.f); return; }
    EXPECT_EQ(s, 0);
    c.i.pbAuthData = NULL; c.i.cbAuthData = 0;
    c.i.dwFlags = BCRYPT_AUTH_MODE_IN_PROGRESS_FLAG;
    s = P_Enc(h.k.h, g.pt + 32, g.np - 32, &c.i, c.iv, 16, out + 32, g.np - 32, &got, 0);
    EXPECT_EQ(s, 0);
    CHECK(same(out, g.ct, g.np)); CHECK(same(c.tag, g.tag, 16));
    fx_close(&h); fx_close(&g.f);
}
TEST(bsc_gcm_chained_info_counters_advance) {
    GC(g, 3);
    chain c; chain_init(&c, g.nonce, g.nn, g.aad, g.na);
    BYTE out[64]; ULONG got = 0xAAAA;
    c.i.dwFlags = BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG;
    NTSTATUS s = P_Enc(g.f.k.h, g.pt, 32, &c.i, c.iv, 16, out, 32, &got, 0);
    if (t_is_wine() && s != 0) { t_skip("emulator"); fx_close(&g.f); return; }
    EXPECT_EQ(s, 0);
    t_note("after chained call: cbAAD=%lu cbData=%llu", c.i.cbAAD, (unsigned long long)c.i.cbData);
    CHECK(c.i.cbAAD == g.na || c.i.cbAAD == 0);
    fx_close(&g.f);
}

/* ---- algorithm properties of the authenticated modes ---------------------------------------------------------------------- */
TEST(bsc_prop_auth_tag_lengths_gcm) {
    REQUIRE(P_GetProp);
    BCRYPT_ALG_HANDLE a = bsc_open(L"AES", GCM); if (!a) { t_skip("AES-GCM"); return; }
    BCRYPT_AUTH_TAG_LENGTHS_STRUCT t = {0}; ULONG r = 0;
    EXPECT_EQ(P_GetProp(a, BCRYPT_AUTH_TAG_LENGTH, NULL, 0, &r, 0), 0);
    EXPECT_EQ(r, sizeof t);
    EXPECT_EQ(P_GetProp(a, BCRYPT_AUTH_TAG_LENGTH, (PUCHAR)&t, sizeof t, &r, 0), 0);
    EXPECT_EQ(t.dwMinLength, 12); EXPECT_EQ(t.dwMaxLength, 16); EXPECT_EQ(t.dwIncrement, 1);
    bsc_close(a);
}
TEST(bsc_prop_auth_tag_lengths_ccm) {
    REQUIRE(P_GetProp);
    BCRYPT_ALG_HANDLE a = bsc_open(L"AES", CCM); if (!a) { t_skip("AES-CCM"); return; }
    BCRYPT_AUTH_TAG_LENGTHS_STRUCT t = {0}; ULONG r = 0;
    NTSTATUS s = P_GetProp(a, BCRYPT_AUTH_TAG_LENGTH, (PUCHAR)&t, sizeof t, &r, 0);
    EXPECT_EQ(s, 0);
    t_note("CCM tag lengths min=%lu max=%lu incr=%lu", t.dwMinLength, t.dwMaxLength, t.dwIncrement);
    bsc_close(a);
}
TEST(bsc_prop_auth_tag_lengths_not_for_cbc) {
    REQUIRE(P_GetProp);
    BCRYPT_ALG_HANDLE a = bsc_open(L"AES", BCRYPT_CHAIN_MODE_CBC); if (!a) { t_skip("AES"); return; }
    ULONG r = 0;
    EXPECT_EQ(P_GetProp(a, BCRYPT_AUTH_TAG_LENGTH, NULL, 0, &r, 0), NS_NOT_SUPPORTED);
    bsc_close(a);
}
TEST(bsc_prop_auth_tag_lengths_not_on_key) {
    fx f; FX_OR_SKIP(f, L"AES", GCM, KEY16);
    BCRYPT_AUTH_TAG_LENGTHS_STRUCT t; ULONG r = 0;
    EXPECT_EQ(P_GetProp(f.k.h, BCRYPT_AUTH_TAG_LENGTH, (PUCHAR)&t, sizeof t, &r, 0), NS_NOT_SUPPORTED);
    fx_close(&f);
}
TEST(bsc_prop_is_authenticated_cipher_note) {
    REQUIRE(P_GetProp);
    BCRYPT_ALG_HANDLE a = bsc_open(L"AES", GCM); if (!a) { t_skip("AES-GCM"); return; }
    ULONG v = 0, r = 0;
    NTSTATUS s = P_GetProp(a, L"AlgorithmFlags", (PUCHAR)&v, 4, &r, 0);
    t_note("AES-GCM AlgorithmFlags: status 0x%lx value 0x%lx", s, v);
    bsc_close(a);
}
TEST(bsc_gcm_chaining_mode_property_roundtrip) {
    BCRYPT_ALG_HANDLE a = bsc_open(L"AES", GCM); if (!a) { t_skip("AES-GCM"); return; }
    WCHAR m[64] = {0}; ULONG r = 0;
    EXPECT_EQ(P_GetProp(a, BCRYPT_CHAINING_MODE, (PUCHAR)m, sizeof m, &r, 0), 0);
    EXPECT_WSTR(m, GCM); EXPECT_EQ(r, 64);
    EXPECT_EQ(P_GetProp(a, BCRYPT_CHAINING_MODE, (PUCHAR)m, 0, &r, 0), NS_BUFFER_TOO_SMALL);
    EXPECT_EQ(r, 64);
    EXPECT_EQ(P_GetProp(a, BCRYPT_CHAINING_MODE, (PUCHAR)m, 63, &r, 0), NS_BUFFER_TOO_SMALL);
    bsc_close(a);
}
TEST(bsc_auth_cipher_block_length_16) {
    BCRYPT_ALG_HANDLE a = bsc_open(L"AES", GCM); if (!a) { t_skip("AES-GCM"); return; }
    ULONG v = 0, r = 0;
    EXPECT_EQ(P_GetProp(a, BCRYPT_BLOCK_LENGTH, (PUCHAR)&v, 4, &r, 0), 0);
    EXPECT_EQ(v, 16);
    bsc_close(a);
}
