/* BCryptEncrypt / BCryptDecrypt calling protocol for the unauthenticated modes: argument validation order,
 * size-query protocol, padding, IV handling and key-resident chaining state.
 * Statuses observed on Windows 10 for bcrypt.dll (dispatch) and bcryptprimitives.dll (MSBlockEncrypt/Decrypt). */
#include "bsc.h"

static void fillseq(BYTE *b, int n, int start) { for (int i = 0; i < n; i++) b[i] = (BYTE)(start + i); }
static const char *K = KEY16;
#define CBC BCRYPT_CHAIN_MODE_CBC
#define ECB BCRYPT_CHAIN_MODE_ECB
#define CFB BCRYPT_CHAIN_MODE_CFB

/* ================= argument validation ================= */
TEST(bsc_enc_null_pcbresult_checked_first) {
    WINE_SKIP("diverges from decompiled Windows behaviour");
    REQUIRE(P_Enc);
    BYTE z[16] = {0}, o[16];
    /* pcbResult is validated before the key handle */
    EXPECT_EQ(P_Enc(NULL, z, 16, NULL, NULL, 0, o, 16, NULL, 0), NS_INVALID_PARAM);
    fx f; FX_OR_SKIP(f, L"AES", CBC, K);
    EXPECT_EQ(P_Enc(f.k.h, z, 16, NULL, NULL, 0, o, 16, NULL, 0), NS_INVALID_PARAM);
    EXPECT_EQ(P_Enc(f.k.h, z, 16, NULL, NULL, 0, NULL, 0, NULL, 0), NS_INVALID_PARAM);
    fx_close(&f);
}
TEST(bsc_dec_null_pcbresult_checked_first) {
    WINE_SKIP("diverges from decompiled Windows behaviour");
    REQUIRE(P_Dec);
    BYTE z[16] = {0}, o[16];
    EXPECT_EQ(P_Dec(NULL, z, 16, NULL, NULL, 0, o, 16, NULL, 0), NS_INVALID_PARAM);
    fx f; FX_OR_SKIP(f, L"AES", CBC, K);
    EXPECT_EQ(P_Dec(f.k.h, z, 16, NULL, NULL, 0, o, 16, NULL, 0), NS_INVALID_PARAM);
    fx_close(&f);
}
TEST(bsc_enc_dec_null_key) {
    REQUIRE(P_Enc);
    BYTE z[16] = {0}, o[16]; ULONG n = 0x1234;
    EXPECT_EQ(P_Enc(NULL, z, 16, NULL, NULL, 0, o, 16, &n, 0), NS_INVALID_HANDLE);
    EXPECT_EQ(P_Dec(NULL, z, 16, NULL, NULL, 0, o, 16, &n, 0), NS_INVALID_HANDLE);
    CHECK(n == 0x1234);                          /* *pcbResult not written on handle failure */
}
TEST(bsc_enc_dec_algorithm_handle_as_key) {
    REQUIRE(P_Enc);
    BCRYPT_ALG_HANDLE a = bsc_open(L"AES", NULL); if (!a) { t_skip("AES"); return; }
    BYTE z[16] = {0}, o[16]; ULONG n = 0x1234;
    EXPECT_EQ(P_Enc((BCRYPT_KEY_HANDLE)a, z, 16, NULL, NULL, 0, o, 16, &n, 0), NS_INVALID_HANDLE);
    EXPECT_EQ(P_Dec((BCRYPT_KEY_HANDLE)a, z, 16, NULL, NULL, 0, o, 16, &n, 0), NS_INVALID_HANDLE);
    CHECK(n == 0x1234);
    bsc_close(a);
}
TEST(bsc_enc_dec_destroyed_key_user_object) {
    fx f; FX_OR_SKIP(f, L"AES", CBC, K);
    BCRYPT_KEY_HANDLE h = f.k.h;
    EXPECT_EQ(P_Destroy(h), 0);
    f.k.h = NULL;
    BYTE z[16] = {0}, o[16]; ULONG n = 7;
    EXPECT_EQ(P_Enc(h, z, 16, NULL, NULL, 0, o, 16, &n, 0), NS_INVALID_HANDLE);
    EXPECT_EQ(P_Dec(h, z, 16, NULL, NULL, 0, o, 16, &n, 0), NS_INVALID_HANDLE);
    fx_close(&f);
}

/* ================= size-query protocol, no padding ================= */
TEST(bsc_enc_size_query_multiples_of_block) {
    fx f; FX_OR_SKIP(f, L"AES", CBC, K);
    BYTE in[96]; fillseq(in, 96, 0);
    for (ULONG n = 0; n <= 96; n += 16) {
        ULONG got = 0xAAAA;
        NTSTATUS s = enc(f.k.h, in, n, NULL, 0, NULL, 0, &got, 0);
        CHECKF(s == 0 && got == n, "n=%lu s=0x%lx got=%lu", n, s, got);
    }
    fx_close(&f);
}
TEST(bsc_enc_size_query_partial_block_fails) {
    fx f; FX_OR_SKIP(f, L"AES", CBC, K);
    BYTE in[96]; fillseq(in, 96, 0);
    ULONG ns[] = { 1, 8, 15, 17, 31, 33, 47 };
    for (int i = 0; i < 7; i++) {
        ULONG got = 0xAAAA;
        NTSTATUS s = enc(f.k.h, in, ns[i], NULL, 0, NULL, 0, &got, 0);
        CHECKF(s == NS_INVALID_BUFFER_SIZE, "n=%lu s=0x%lx", ns[i], s);
        CHECKF(got == ns[i], "n=%lu pcbResult=%lu (input length is reported)", ns[i], got);
    }
    fx_close(&f);
}
TEST(bsc_enc_partial_block_with_output_buffer) {
    fx f; FX_OR_SKIP(f, L"AES", CBC, K);
    BYTE in[32], out[48]; fillseq(in, 32, 0); memset(out, 0x5A, sizeof out);
    ULONG got = 0xAAAA;
    EXPECT_EQ(enc(f.k.h, in, 17, NULL, 0, out, 48, &got, 0), NS_INVALID_BUFFER_SIZE);
    EXPECT_EQ(got, 17);
    BYTE e[48]; memset(e, 0x5A, 48); CHECK(same(out, e, 48));       /* nothing written */
    fx_close(&f);
}
TEST(bsc_enc_zero_length_no_padding) {
    fx f; FX_OR_SKIP(f, L"AES", CBC, K);
    BYTE out[16]; memset(out, 0x77, 16); ULONG got = 0xAAAA;
    EXPECT_EQ(enc(f.k.h, NULL, 0, NULL, 0, NULL, 0, &got, 0), 0); EXPECT_EQ(got, 0);
    got = 0xAAAA;
    EXPECT_EQ(enc(f.k.h, (BYTE *)"", 0, NULL, 0, out, 16, &got, 0), 0); EXPECT_EQ(got, 0);
    BYTE e[16]; memset(e, 0x77, 16); CHECK(same(out, e, 16));
    fx_close(&f);
}
TEST(bsc_dec_zero_length_no_padding) {
    fx f; FX_OR_SKIP(f, L"AES", CBC, K);
    BYTE out[16]; ULONG got = 0xAAAA;
    EXPECT_EQ(dec(f.k.h, NULL, 0, NULL, 0, NULL, 0, &got, 0), 0); EXPECT_EQ(got, 0);
    got = 0xAAAA;
    EXPECT_EQ(dec(f.k.h, (BYTE *)"", 0, NULL, 0, out, 16, &got, 0), 0); EXPECT_EQ(got, 0);
    fx_close(&f);
}
TEST(bsc_enc_null_output_ignores_cboutput) {
    fx f; FX_OR_SKIP(f, L"AES", CBC, K);
    BYTE in[32]; fillseq(in, 32, 0); ULONG got = 0xAAAA;
    EXPECT_EQ(enc(f.k.h, in, 32, NULL, 0, NULL, 1000, &got, 0), 0);
    EXPECT_EQ(got, 32);
    fx_close(&f);
}
TEST(bsc_enc_output_buffer_boundaries) {
    fx f; FX_OR_SKIP(f, L"AES", ECB, K);
    BYTE in[32], ref[32], out[64]; fillseq(in, 32, 0);
    ULONG got = 0;
    EXPECT_EQ(enc(f.k.h, in, 32, NULL, 0, ref, 32, &got, 0), 0);
    ULONG cbs[] = { 0, 1, 15, 16, 17, 31 };
    for (int i = 0; i < 6; i++) {
        got = 0xAAAA; memset(out, 0xA5, sizeof out);
        NTSTATUS s = enc(f.k.h, in, 32, NULL, 0, out, cbs[i], &got, 0);
        CHECKF(s == NS_BUFFER_TOO_SMALL, "cbOutput=%lu s=0x%lx", cbs[i], s);
        CHECKF(got == 32, "cbOutput=%lu pcbResult=%lu", cbs[i], got);
    }
    got = 0xAAAA; memset(out, 0xA5, sizeof out);
    EXPECT_EQ(enc(f.k.h, in, 32, NULL, 0, out, 32, &got, 0), 0); EXPECT_EQ(got, 32); CHECK(same(out, ref, 32)); CHECK(out[32] == 0xA5);
    got = 0xAAAA; memset(out, 0xA5, sizeof out);
    EXPECT_EQ(enc(f.k.h, in, 32, NULL, 0, out, 64, &got, 0), 0); EXPECT_EQ(got, 32); CHECK(same(out, ref, 32)); CHECK(out[32] == 0xA5);
    fx_close(&f);
}
TEST(bsc_dec_output_buffer_boundaries) {
    fx f; FX_OR_SKIP(f, L"AES", ECB, K);
    BYTE in[32], ct[32], out[64]; fillseq(in, 32, 0);
    ULONG got = 0;
    EXPECT_EQ(enc(f.k.h, in, 32, NULL, 0, ct, 32, &got, 0), 0);
    ULONG cbs[] = { 0, 1, 16, 31 };
    for (int i = 0; i < 4; i++) {
        got = 0xAAAA;
        NTSTATUS s = dec(f.k.h, ct, 32, NULL, 0, out, cbs[i], &got, 0);
        CHECKF(s == NS_BUFFER_TOO_SMALL, "cbOutput=%lu s=0x%lx", cbs[i], s);
        CHECKF(got == 32, "cbOutput=%lu pcbResult=%lu", cbs[i], got);
    }
    got = 0xAAAA; memset(out, 0xA5, sizeof out);
    EXPECT_EQ(dec(f.k.h, ct, 32, NULL, 0, out, 32, &got, 0), 0); EXPECT_EQ(got, 32); CHECK(same(out, in, 32));
    fx_close(&f);
}
TEST(bsc_dec_partial_block_fails) {
    fx f; FX_OR_SKIP(f, L"AES", CBC, K);
    BYTE in[48] = {0}, out[48]; ULONG ns[] = { 1, 15, 17, 33 };
    for (int i = 0; i < 4; i++) {
        ULONG got = 0xAAAA;
        NTSTATUS s = dec(f.k.h, in, ns[i], NULL, 0, NULL, 0, &got, 0);
        CHECKF(s == NS_INVALID_BUFFER_SIZE && got == ns[i], "n=%lu s=0x%lx got=%lu", ns[i], s, got);
        got = 0xAAAA;
        s = dec(f.k.h, in, ns[i], NULL, 0, out, 48, &got, 0);
        CHECKF(s == NS_INVALID_BUFFER_SIZE && got == ns[i], "n=%lu s=0x%lx got=%lu", ns[i], s, got);
    }
    fx_close(&f);
}
TEST(bsc_ecb_partial_block_fails) {
    fx f; FX_OR_SKIP(f, L"AES", ECB, K);
    BYTE in[48] = {0}; ULONG got = 0xAAAA;
    EXPECT_EQ(enc(f.k.h, in, 15, NULL, 0, NULL, 0, &got, 0), NS_INVALID_BUFFER_SIZE); EXPECT_EQ(got, 15);
    EXPECT_EQ(dec(f.k.h, in, 20, NULL, 0, NULL, 0, &got, 0), NS_INVALID_BUFFER_SIZE); EXPECT_EQ(got, 20);
    fx_close(&f);
}

/* ================= BCRYPT_BLOCK_PADDING ================= */
TEST(bsc_pad_size_query_table) {
    fx f; FX_OR_SKIP(f, L"AES", CBC, K);
    BYTE in[80]; fillseq(in, 80, 0);
    struct { ULONG in, out; } t[] = { {0,16},{1,16},{7,16},{15,16},{16,32},{17,32},{31,32},{32,48},{33,48},{47,48},{48,64},{63,64},{64,80} };
    for (int i = 0; i < 13; i++) {
        ULONG got = 0xAAAA; BYTE iv[16] = {0};
        NTSTATUS s = enc(f.k.h, in, t[i].in, iv, 16, NULL, 0, &got, BCRYPT_BLOCK_PADDING);
        CHECKF(s == 0 && got == t[i].out, "in=%lu s=0x%lx got=%lu want %lu", t[i].in, s, got, t[i].out);
    }
    fx_close(&f);
}
TEST(bsc_pad_size_query_does_not_touch_iv) {
    fx f; FX_OR_SKIP(f, L"AES", CBC, K);
    BYTE in[17]; fillseq(in, 17, 0); BYTE iv[16]; fillseq(iv, 16, 0x40); BYTE iv0[16]; memcpy(iv0, iv, 16);
    ULONG got = 0;
    EXPECT_EQ(enc(f.k.h, in, 17, iv, 16, NULL, 0, &got, BCRYPT_BLOCK_PADDING), 0);
    CHECK(same(iv, iv0, 16));
    fx_close(&f);
}
TEST(bsc_pad_ecb_bytes_are_pkcs7) {
    fx f; FX_OR_SKIP(f, L"AES", ECB, K);
    for (ULONG n = 0; n <= 33; n++) {
        BYTE in[64], ct[64], pt[64]; fillseq(in, 64, 0x30);
        ULONG got = 0, need = (n / 16 + 1) * 16;
        NTSTATUS s = enc(f.k.h, in, n, NULL, 0, ct, need, &got, BCRYPT_BLOCK_PADDING);
        CHECKF(s == 0 && got == need, "n=%lu s=0x%lx got=%lu", n, s, got);
        s = dec(f.k.h, ct, need, NULL, 0, pt, need, &got, 0);       /* raw ECB decrypt exposes the pad */
        CHECKF(s == 0 && got == need, "n=%lu raw dec", n);
        CHECKF(same(pt, in, n), "n=%lu prefix", n);
        BYTE pv = (BYTE)(need - n); int ok = 1;
        for (ULONG j = n; j < need; j++) if (pt[j] != pv) ok = 0;
        CHECKF(ok, "n=%lu pad byte %u", n, pv);
    }
    fx_close(&f);
}
TEST(bsc_pad_roundtrip_all_lengths_cbc) {
    fx f; FX_OR_SKIP(f, L"AES", CBC, K);
    for (ULONG n = 0; n <= 70; n++) {
        BYTE in[80], ct[96], pt[96], iv1[16] = {1}, iv2[16] = {1}; fillseq(in, 80, 7);
        ULONG got = 0, need = (n / 16 + 1) * 16;
        NTSTATUS s = enc(f.k.h, in, n, iv1, 16, ct, sizeof ct, &got, BCRYPT_BLOCK_PADDING);
        if (s != 0 || got != need) { CHECKF(0, "n=%lu enc s=0x%lx got=%lu", n, s, got); continue; }
        CHECKF(same(iv1, ct + need - 16, 16), "n=%lu iv updated to last ct block", n);
        ULONG got2 = 0;
        s = dec(f.k.h, ct, need, iv2, 16, pt, sizeof pt, &got2, BCRYPT_BLOCK_PADDING);
        CHECKF(s == 0 && got2 == n && same(pt, in, n), "n=%lu dec s=0x%lx got=%lu", n, s, got2);
    }
    fx_close(&f);
}
TEST(bsc_pad_enc_output_too_small) {
    fx f; FX_OR_SKIP(f, L"AES", CBC, K);
    BYTE in[48]; fillseq(in, 48, 0);
    BYTE out[64]; BYTE iv[16] = {0}; ULONG got;
    got = 0xAAAA; EXPECT_EQ(enc(f.k.h, in, 17, iv, 16, out, 31, &got, BCRYPT_BLOCK_PADDING), NS_BUFFER_TOO_SMALL); EXPECT_EQ(got, 32);
    got = 0xAAAA; EXPECT_EQ(enc(f.k.h, in, 32, iv, 16, out, 32, &got, BCRYPT_BLOCK_PADDING), NS_BUFFER_TOO_SMALL); EXPECT_EQ(got, 48);
    got = 0xAAAA; EXPECT_EQ(enc(f.k.h, in, 0, iv, 16, out, 15, &got, BCRYPT_BLOCK_PADDING), NS_BUFFER_TOO_SMALL); EXPECT_EQ(got, 16);
    BYTE z[16] = {0};
    CHECK(same(iv, z, 16));                       /* failed call leaves the IV alone */
    fx_close(&f);
}
TEST(bsc_pad_dec_size_query_reports_input_length) {
    fx f; FX_OR_SKIP(f, L"AES", CBC, K);
    BYTE in[17], ct[32], iv[16] = {0}; fillseq(in, 17, 0); ULONG got = 0;
    EXPECT_EQ(enc(f.k.h, in, 17, iv, 16, ct, 32, &got, BCRYPT_BLOCK_PADDING), 0);
    BYTE iv2[16] = {0};
    got = 0xAAAA;
    EXPECT_EQ(dec(f.k.h, ct, 32, iv2, 16, NULL, 0, &got, BCRYPT_BLOCK_PADDING), 0);
    EXPECT_EQ(got, 32);                           /* upper bound (ciphertext length), not the exact plaintext length */
    BYTE z[16] = {0}; CHECK(same(iv2, z, 16));
    fx_close(&f);
}
TEST(bsc_pad_dec_output_sizes) {
    fx f; FX_OR_SKIP(f, L"AES", CBC, K);
    BYTE in[17], ct[32], iv[16] = {0}, pt[48]; fillseq(in, 17, 0); ULONG got = 0;
    EXPECT_EQ(enc(f.k.h, in, 17, iv, 16, ct, 32, &got, BCRYPT_BLOCK_PADDING), 0);
    /* buffer smaller than ciphertext minus one block: rejected before decrypting, ciphertext length reported */
    memset(iv, 0, 16); got = 0xAAAA;
    EXPECT_EQ(dec(f.k.h, ct, 32, iv, 16, pt, 15, &got, BCRYPT_BLOCK_PADDING), NS_BUFFER_TOO_SMALL); EXPECT_EQ(got, 32);
    /* big enough to try, too small for the real plaintext: exact plaintext length reported */
    memset(iv, 0, 16); got = 0xAAAA;
    EXPECT_EQ(dec(f.k.h, ct, 32, iv, 16, pt, 16, &got, BCRYPT_BLOCK_PADDING), NS_BUFFER_TOO_SMALL); EXPECT_EQ(got, 17);
    /* exactly the plaintext length */
    memset(iv, 0, 16); got = 0xAAAA; memset(pt, 0xEE, sizeof pt);
    EXPECT_EQ(dec(f.k.h, ct, 32, iv, 16, pt, 17, &got, BCRYPT_BLOCK_PADDING), 0); EXPECT_EQ(got, 17);
    CHECK(same(pt, in, 17)); CHECK(pt[17] == 0xEE);
    CHECK(same(iv, ct + 16, 16));
    fx_close(&f);
}
TEST(bsc_pad_dec_full_pad_block_yields_empty) {
    fx f; FX_OR_SKIP(f, L"AES", CBC, K);
    BYTE ct[16], iv[16] = {0}, pt[16], none = 0; ULONG got = 0;
    /* a NULL input pointer is rejected even for a zero-length input; a valid pointer with length 0 encrypts one pad block */
    EXPECT_EQ(enc(f.k.h, NULL, 0, iv, 16, ct, 16, &got, BCRYPT_BLOCK_PADDING), NS_INVALID_PARAM); EXPECT_EQ(got, 16);
    memset(iv, 0, 16); got = 0;
    EXPECT_EQ(enc(f.k.h, &none, 0, iv, 16, ct, 16, &got, BCRYPT_BLOCK_PADDING), 0); EXPECT_EQ(got, 16);
    memset(iv, 0, 16); got = 0xAAAA;
    EXPECT_EQ(dec(f.k.h, ct, 16, iv, 16, pt, 16, &got, BCRYPT_BLOCK_PADDING), 0); EXPECT_EQ(got, 0);
    memset(iv, 0, 16); got = 0xAAAA;
    EXPECT_EQ(dec(f.k.h, ct, 16, iv, 16, pt, 0, &got, BCRYPT_BLOCK_PADDING), 0);
    EXPECT_EQ(got, 0);
    fx_close(&f);
}
TEST(bsc_pad_dec_input_not_block_multiple) {
    fx f; FX_OR_SKIP(f, L"AES", CBC, K);
    BYTE ct[48] = {0}, pt[48]; ULONG got = 0xAAAA;
    EXPECT_EQ(dec(f.k.h, ct, 17, NULL, 0, NULL, 0, &got, BCRYPT_BLOCK_PADDING), NS_INVALID_BUFFER_SIZE); EXPECT_EQ(got, 17);
    got = 0xAAAA;
    EXPECT_EQ(dec(f.k.h, ct, 31, NULL, 0, pt, 48, &got, BCRYPT_BLOCK_PADDING), NS_INVALID_BUFFER_SIZE); EXPECT_EQ(got, 31);
    fx_close(&f);
}
TEST(bsc_pad_dec_zero_length_input) {
    fx f; FX_OR_SKIP(f, L"AES", CBC, K);
    BYTE pt[16]; ULONG got = 0xAAAA;
    NTSTATUS s = dec(f.k.h, NULL, 0, NULL, 0, pt, 16, &got, BCRYPT_BLOCK_PADDING);
    t_note("padded decrypt of empty input: status 0x%lx size %lu", s, got);
    fx_close(&f);
}
/* Padding failure: build a valid ciphertext of crafted plaintext blocks with an unpadded ECB key, then decrypt padded. */
static NTSTATUS badpad(const BYTE *lastblock, ULONG *pcb) {
    fx f; if (!fx_open(&f, L"AES", BCRYPT_CHAIN_MODE_ECB, KEY16)) return 0x7FFFFFFF;
    BYTE ct[32], in[32], pt[32]; fillseq(in, 16, 0x41); memcpy(in + 16, lastblock, 16);
    ULONG got = 0;
    enc(f.k.h, in, 32, NULL, 0, ct, 32, &got, 0);
    memset(pt, 0xEE, 32); got = 0xAAAA;
    NTSTATUS s = dec(f.k.h, ct, 32, NULL, 0, pt, 32, &got, BCRYPT_BLOCK_PADDING);
    if (pcb) *pcb = got;
    fx_close(&f);
    return s;
}
TEST(bsc_pad_bad_last_byte_zero) {
    WINE_SKIP("diverges from decompiled Windows behaviour");
    BYTE b[16]; memset(b, 0x11, 16); b[15] = 0;
    NTSTATUS s = badpad(b, NULL); if (s == 0x7FFFFFFF) { t_skip("AES"); return; }
    EXPECT_EQ(s, NS_DATA_ERROR);
}
TEST(bsc_pad_bad_last_byte_over_block) {
    WINE_SKIP("diverges from decompiled Windows behaviour");
    BYTE b[16]; memset(b, 0x11, 16); b[15] = 17;
    NTSTATUS s = badpad(b, NULL); if (s == 0x7FFFFFFF) { t_skip("AES"); return; }
    EXPECT_EQ(s, NS_DATA_ERROR);
    b[15] = 0xFF; EXPECT_EQ(badpad(b, NULL), NS_DATA_ERROR);
}
TEST(bsc_pad_bad_inconsistent_pad_bytes) {
    WINE_SKIP("diverges from decompiled Windows behaviour");
    BYTE b[16]; memset(b, 0x11, 16); b[15] = 4; b[14] = 4; b[13] = 4; b[12] = 3;
    NTSTATUS s = badpad(b, NULL); if (s == 0x7FFFFFFF) { t_skip("AES"); return; }
    EXPECT_EQ(s, NS_DATA_ERROR);
    memset(b, 0x10, 16); b[0] = 0x0F;                  /* 16-byte pad with a wrong first byte */
    EXPECT_EQ(badpad(b, NULL), NS_DATA_ERROR);
}
TEST(bsc_pad_good_variants) {
    BYTE b[16]; ULONG got = 0;
    memset(b, 0x11, 16); b[15] = 1;
    NTSTATUS s = badpad(b, &got); if (s == 0x7FFFFFFF) { t_skip("AES"); return; }
    EXPECT_EQ(s, 0); EXPECT_EQ(got, 31);
    memset(b, 0x11, 16); b[15] = b[14] = 2;
    EXPECT_EQ(badpad(b, &got), 0); EXPECT_EQ(got, 30);
    memset(b, 0x10, 16);
    EXPECT_EQ(badpad(b, &got), 0); EXPECT_EQ(got, 16);
}
TEST(bsc_pad_bad_padding_reports_length_note) {
    BYTE b[16]; memset(b, 0x11, 16); b[15] = 0; ULONG got = 0;
    NTSTATUS s = badpad(b, &got); if (s == 0x7FFFFFFF) { t_skip("AES"); return; }
    t_note("bad padding: status 0x%lx, *pcbResult = %lu", s, got);
}
TEST(bsc_pad_bad_padding_does_not_return_plaintext_status_ok) {
    WINE_SKIP("diverges from decompiled Windows behaviour");
    BYTE b[16]; memset(b, 0x11, 16); b[15] = 9;      /* 9 requested but only one 9 present */
    NTSTATUS s = badpad(b, NULL); if (s == 0x7FFFFFFF) { t_skip("AES"); return; }
    CHECK(s < 0);
}
TEST(bsc_pad_wrong_key_usually_fails_padding) {
    fx a, b;
    if (!fx_open(&a, L"AES", CBC, K)) { t_skip("AES"); return; }
    if (!fx_open(&b, L"AES", CBC, "ffeeddccbbaa99887766554433221100")) { fx_close(&a); t_skip("AES"); return; }
    BYTE in[40], ct[48], pt[48], iv[16] = {0}; fillseq(in, 40, 0); ULONG got = 0;
    EXPECT_EQ(enc(a.k.h, in, 40, iv, 16, ct, 48, &got, BCRYPT_BLOCK_PADDING), 0);
    memset(iv, 0, 16);
    NTSTATUS s = dec(b.k.h, ct, 48, iv, 16, pt, 48, &got, BCRYPT_BLOCK_PADDING);
    t_note("decrypt with wrong key: 0x%lx", s);
    fx_close(&a); fx_close(&b);
}
TEST(bsc_pad_flag_in_cfb8_pads_to_block_size) {
    fx f; FX_OR_SKIP(f, L"AES", CFB, K);
    BYTE in[40]; fillseq(in, 40, 0); ULONG got = 0xAAAA; BYTE iv[16] = {0};
    EXPECT_EQ(enc(f.k.h, in, 17, iv, 16, NULL, 0, &got, BCRYPT_BLOCK_PADDING), 0); EXPECT_EQ(got, 32);
    got = 0xAAAA;
    EXPECT_EQ(enc(f.k.h, in, 32, iv, 16, NULL, 0, &got, BCRYPT_BLOCK_PADDING), 0); EXPECT_EQ(got, 48);
    fx_close(&f);
}

/* ================= IV handling ================= */
TEST(bsc_iv_cbc_updated_in_place_per_call) {
    fx f; FX_OR_SKIP(f, L"AES", CBC, K);
    BYTE in[48], ct[48], iv[16]; fillseq(in, 48, 0); fillseq(iv, 16, 0xA0); ULONG got = 0;
    BYTE iv0[16]; memcpy(iv0, iv, 16);
    EXPECT_EQ(enc(f.k.h, in, 48, iv, 16, ct, 48, &got, 0), 0);
    CHECK(same(iv, ct + 32, 16));
    /* chained in 3 single-block calls produces the same ciphertext */
    BYTE ct2[48], ivb[16]; memcpy(ivb, iv0, 16);
    for (int i = 0; i < 3; i++) {
        EXPECT_EQ(enc(f.k.h, in + 16 * i, 16, ivb, 16, ct2 + 16 * i, 16, &got, 0), 0);
        CHECK(same(ivb, ct2 + 16 * i, 16));
    }
    CHECK(same(ct, ct2, 48));
    fx_close(&f);
}
TEST(bsc_iv_cbc_decrypt_updates_iv_to_last_ciphertext_block) {
    fx f; FX_OR_SKIP(f, L"AES", CBC, K);
    BYTE in[48], ct[48], pt[48], iv[16] = {0}; fillseq(in, 48, 0); ULONG got = 0;
    EXPECT_EQ(enc(f.k.h, in, 48, iv, 16, ct, 48, &got, 0), 0);
    memset(iv, 0, 16);
    EXPECT_EQ(dec(f.k.h, ct, 48, iv, 16, pt, 48, &got, 0), 0);
    CHECK(same(pt, in, 48)); CHECK(same(iv, ct + 32, 16));
    /* decrypt chained call by call */
    BYTE iv2[16] = {0};
    for (int i = 0; i < 3; i++) {
        BYTE o[16];
        EXPECT_EQ(dec(f.k.h, ct + 16 * i, 16, iv2, 16, o, 16, &got, 0), 0);
        CHECK(same(o, in + 16 * i, 16));
    }
    fx_close(&f);
}
TEST(bsc_iv_in_place_ct_over_pt_buffer) {
    fx f; FX_OR_SKIP(f, L"AES", CBC, K);
    BYTE in[32], ref[32], iv[16] = {0}, iv2[16] = {0}; fillseq(in, 32, 3); ULONG got = 0;
    EXPECT_EQ(enc(f.k.h, in, 32, iv, 16, ref, 32, &got, 0), 0);
    BYTE buf[32]; memcpy(buf, in, 32);
    EXPECT_EQ(enc(f.k.h, buf, 32, iv2, 16, buf, 32, &got, 0), 0);
    CHECK(same(buf, ref, 32));
    memset(iv2, 0, 16);
    EXPECT_EQ(dec(f.k.h, buf, 32, iv2, 16, buf, 32, &got, 0), 0);
    CHECK(same(buf, in, 32));
    fx_close(&f);
}
TEST(bsc_iv_too_short_is_buffer_size_error) {
    WINE_SKIP("diverges from decompiled Windows behaviour");
    fx f; FX_OR_SKIP(f, L"AES", CBC, K);
    BYTE in[16] = {0}, out[16], iv[32] = {0}; ULONG got = 0xAAAA;
    ULONG lens[] = { 0, 1, 8, 15 };
    for (int i = 0; i < 4; i++) {
        NTSTATUS s = enc(f.k.h, in, 16, iv, lens[i], out, 16, &got, 0);
        CHECKF(s == NS_INVALID_BUFFER_SIZE, "cbIV=%lu s=0x%lx", lens[i], s);
        s = dec(f.k.h, in, 16, iv, lens[i], out, 16, &got, 0);
        CHECKF(s == NS_INVALID_BUFFER_SIZE, "dec cbIV=%lu s=0x%lx", lens[i], s);
    }
    fx_close(&f);
}
TEST(bsc_iv_longer_than_block_uses_prefix) {
    WINE_SKIP("diverges from decompiled Windows behaviour");
    fx f; FX_OR_SKIP(f, L"AES", CBC, K);
    BYTE in[16] = {9}, ref[16], out[16], iv16[16], iv32[32]; fillseq(iv16, 16, 0x10); fillseq(iv32, 32, 0x10); iv32[16] = 0xCC;
    ULONG got = 0;
    EXPECT_EQ(enc(f.k.h, in, 16, iv16, 16, ref, 16, &got, 0), 0);
    NTSTATUS s = enc(f.k.h, in, 16, iv32, 32, out, 16, &got, 0);
    EXPECT_EQ(s, 0);
    CHECK(same(out, ref, 16));
    CHECK(same(iv32, ref, 16));                  /* first 16 bytes updated */
    CHECK(iv32[16] == 0xCC);                     /* remainder untouched */
    fx_close(&f);
}
TEST(bsc_iv_null_pointer_with_nonzero_length_is_ignored) {
    fx f; FX_OR_SKIP(f, L"AES", CBC, K);
    BYTE in[16] = {0}, out[16]; ULONG got = 0;
    EXPECT_EQ(enc(f.k.h, in, 16, NULL, 16, out, 16, &got, 0), 0);
    EXPECT_EQ(enc(f.k.h, in, 16, NULL, 1000, out, 16, &got, 0), 0);
    fx_close(&f);
}
static void s_note_ecb_size_query(BCRYPT_KEY_HANDLE k) {
    BYTE in[16] = {0}, iv[16] = {0}; ULONG got = 0;
    NTSTATUS s = enc(k, in, 16, iv, 16, NULL, 0, &got, 0);
    t_note("ECB size query with IV pointer -> 0x%lx (%lu)", s, got);
}
TEST(bsc_iv_ecb_with_iv_pointer_is_rejected) {
    fx f; FX_OR_SKIP(f, L"AES", ECB, K);
    BYTE in[16] = {0}, out[16], iv[16] = {0}; ULONG got = 0xAAAA;
    EXPECT_EQ(enc(f.k.h, in, 16, iv, 16, out, 16, &got, 0), NS_INVALID_PARAM);
    EXPECT_EQ(dec(f.k.h, in, 16, iv, 16, out, 16, &got, 0), NS_INVALID_PARAM);
    EXPECT_EQ(enc(f.k.h, in, 16, iv, 32, out, 16, &got, 0), NS_INVALID_PARAM);
    s_note_ecb_size_query(f.k.h);
    fx_close(&f);
}
TEST(bsc_iv_ecb_with_short_iv_buffer_size_error) {
    WINE_SKIP("diverges from decompiled Windows behaviour");
    fx f; FX_OR_SKIP(f, L"AES", ECB, K);
    BYTE in[16] = {0}, out[16], iv[16] = {0}; ULONG got = 0;
    NTSTATUS s = enc(f.k.h, in, 16, iv, 8, out, 16, &got, 0);
    CHECKF(s == NS_INVALID_BUFFER_SIZE, "0x%lx", s);          /* length check precedes the ECB rejection */
    fx_close(&f);
}
TEST(bsc_iv_ecb_null_iv_with_length_ok) {
    fx f; FX_OR_SKIP(f, L"AES", ECB, K);
    BYTE in[16] = {0}, out[16]; ULONG got = 0;
    EXPECT_EQ(enc(f.k.h, in, 16, NULL, 16, out, 16, &got, 0), 0);
    EXPECT_EQ(enc(f.k.h, in, 16, NULL, 0, out, 16, &got, 0), 0);
    fx_close(&f);
}
TEST(bsc_iv_null_iv_first_call_is_zero_iv) {
    fx f, g; FX_OR_SKIP(f, L"AES", CBC, K);
    if (!fx_open(&g, L"AES", CBC, K)) { fx_close(&f); t_skip("AES"); return; }
    BYTE in[16]; fillseq(in, 16, 0x20); BYTE a[16], b[16], z[16] = {0}; ULONG got = 0;
    EXPECT_EQ(enc(f.k.h, in, 16, NULL, 0, a, 16, &got, 0), 0);
    EXPECT_EQ(enc(g.k.h, in, 16, z, 16, b, 16, &got, 0), 0);
    CHECK(same(a, b, 16));
    fx_close(&f); fx_close(&g);
}
TEST(bsc_iv_key_holds_chaining_state_for_null_iv_calls) {
    /* With pbIV == NULL the key's own chaining value is used and advanced: two NULL-IV calls equal one two-block call. */
    fx f, g; FX_OR_SKIP(f, L"AES", CBC, K);
    if (!fx_open(&g, L"AES", CBC, K)) { fx_close(&f); t_skip("AES"); return; }
    BYTE in[32], one[32], two[32], z[16] = {0}; fillseq(in, 32, 0); ULONG got = 0;
    EXPECT_EQ(enc(f.k.h, in, 32, z, 16, one, 32, &got, 0), 0);
    EXPECT_EQ(enc(g.k.h, in, 16, NULL, 0, two, 16, &got, 0), 0);
    EXPECT_EQ(enc(g.k.h, in + 16, 16, NULL, 0, two + 16, 16, &got, 0), 0);
    CHECK(same(one, two, 32));
    fx_close(&f); fx_close(&g);
}
TEST(bsc_iv_explicit_iv_call_then_null_iv_continues_chain) {
    /* After a call with an explicit IV the key stores the updated chaining value; a later NULL-IV call continues it. */
    fx f, g; FX_OR_SKIP(f, L"AES", CBC, K);
    if (!fx_open(&g, L"AES", CBC, K)) { fx_close(&f); t_skip("AES"); return; }
    BYTE in[32], one[32], two[32], iv[16]; fillseq(in, 32, 0x55); fillseq(iv, 16, 0x90); ULONG got = 0;
    BYTE iv0[16]; memcpy(iv0, iv, 16);
    EXPECT_EQ(enc(f.k.h, in, 32, iv, 16, one, 32, &got, 0), 0);
    BYTE ivb[16]; memcpy(ivb, iv0, 16);
    EXPECT_EQ(enc(g.k.h, in, 16, ivb, 16, two, 16, &got, 0), 0);
    EXPECT_EQ(enc(g.k.h, in + 16, 16, NULL, 0, two + 16, 16, &got, 0), 0);
    CHECK(same(one, two, 32));
    fx_close(&f); fx_close(&g);
}
TEST(bsc_iv_explicit_iv_overrides_stored_state) {
    fx f, g; FX_OR_SKIP(f, L"AES", CBC, K);
    if (!fx_open(&g, L"AES", CBC, K)) { fx_close(&f); t_skip("AES"); return; }
    BYTE in[16], a[16], b[16], iv[16], iv2[16]; fillseq(in, 16, 1); fillseq(iv, 16, 0x33); memcpy(iv2, iv, 16); ULONG got = 0;
    BYTE junk[16]; BYTE ivj[16] = {0};
    EXPECT_EQ(enc(f.k.h, in, 16, ivj, 16, junk, 16, &got, 0), 0);     /* advance the stored state of f */
    EXPECT_EQ(enc(f.k.h, in, 16, iv, 16, a, 16, &got, 0), 0);
    EXPECT_EQ(enc(g.k.h, in, 16, iv2, 16, b, 16, &got, 0), 0);
    CHECK(same(a, b, 16));
    fx_close(&f); fx_close(&g);
}
TEST(bsc_iv_state_is_per_key) {
    fx f, g; FX_OR_SKIP(f, L"AES", CBC, K);
    if (!fx_open(&g, L"AES", CBC, K)) { fx_close(&f); t_skip("AES"); return; }
    BYTE in[16], a[16], b[16], e[16], z[16] = {0}; fillseq(in, 16, 9); ULONG got = 0;
    EXPECT_EQ(enc(f.k.h, in, 16, NULL, 0, a, 16, &got, 0), 0);
    EXPECT_EQ(enc(f.k.h, in, 16, NULL, 0, a, 16, &got, 0), 0);        /* f advanced twice */
    EXPECT_EQ(enc(g.k.h, in, 16, NULL, 0, b, 16, &got, 0), 0);          /* g is fresh: zero IV */
    fx h; FX_OR_SKIP(h, L"AES", ECB, K);
    EXPECT_EQ(enc(h.k.h, in, 16, NULL, 0, e, 16, &got, 0), 0);
    CHECK(same(b, e, 16));                                              /* zero IV CBC block 1 == ECB */
    fx_close(&h); fx_close(&f); fx_close(&g);
}
TEST(bsc_iv_failed_call_does_not_advance_state) {
    fx f, g; FX_OR_SKIP(f, L"AES", CBC, K);
    if (!fx_open(&g, L"AES", CBC, K)) { fx_close(&f); t_skip("AES"); return; }
    BYTE in[32], a[16], b[16]; fillseq(in, 32, 4); ULONG got = 0;
    BYTE small[8];
    NTSTATUS s = enc(f.k.h, in, 16, NULL, 0, small, 8, &got, 0);       /* too small */
    EXPECT_EQ(s, NS_BUFFER_TOO_SMALL);
    s = enc(f.k.h, in, 17, NULL, 0, a, 16, &got, 0);                    /* partial block */
    EXPECT_EQ(s, NS_INVALID_BUFFER_SIZE);
    EXPECT_EQ(enc(f.k.h, in, 16, NULL, 0, a, 16, &got, 0), 0);
    EXPECT_EQ(enc(g.k.h, in, 16, NULL, 0, b, 16, &got, 0), 0);
    CHECK(same(a, b, 16));
    fx_close(&f); fx_close(&g);
}
TEST(bsc_iv_size_query_does_not_advance_state) {
    fx f, g; FX_OR_SKIP(f, L"AES", CBC, K);
    if (!fx_open(&g, L"AES", CBC, K)) { fx_close(&f); t_skip("AES"); return; }
    BYTE in[16], a[16], b[16]; fillseq(in, 16, 4); ULONG got = 0;
    EXPECT_EQ(enc(f.k.h, in, 16, NULL, 0, NULL, 0, &got, 0), 0);
    EXPECT_EQ(enc(f.k.h, in, 16, NULL, 0, a, 16, &got, 0), 0);
    EXPECT_EQ(enc(g.k.h, in, 16, NULL, 0, b, 16, &got, 0), 0);
    CHECK(same(a, b, 16));
    fx_close(&f); fx_close(&g);
}
TEST(bsc_iv_duplicate_key_copies_chain_state) {
    WINE_SKIP("diverges from decompiled Windows behaviour");
    fx f; FX_OR_SKIP(f, L"AES", CBC, K);
    BYTE in[32], a[32], b[32]; fillseq(in, 32, 4); ULONG got = 0;
    EXPECT_EQ(enc(f.k.h, in, 16, NULL, 0, a, 16, &got, 0), 0);
    BCRYPT_KEY_HANDLE d = NULL;
    if (P_Dup(f.k.h, &d, NULL, 0, 0) == 0) {
        EXPECT_EQ(enc(f.k.h, in + 16, 16, NULL, 0, a + 16, 16, &got, 0), 0);
        EXPECT_EQ(enc(d, in + 16, 16, NULL, 0, b + 16, 16, &got, 0), 0);
        CHECK(same(a + 16, b + 16, 16));
        P_Destroy(d);
    }
    fx_close(&f);
}

/* ================= CFB ================= */
TEST(bsc_cfb8_any_length_without_padding) {
    WINE_SKIP("no CFB8 / MessageBlockLength");
    fx f; FX_OR_SKIP(f, L"AES", CFB, K);
    BYTE in[40], out[40]; fillseq(in, 40, 0);
    for (ULONG n = 0; n <= 33; n++) {
        BYTE iv[16] = {0}; ULONG got = 0xAAAA;
        NTSTATUS s = enc(f.k.h, in, n, iv, 16, out, 40, &got, 0);
        CHECKF(s == 0 && got == n, "n=%lu s=0x%lx got=%lu", n, s, got);
    }
    fx_close(&f);
}
TEST(bsc_cfb8_chunked_equals_one_shot) {
    WINE_SKIP("no CFB8 / MessageBlockLength");
    fx f; FX_OR_SKIP(f, L"AES", CFB, K);
    BYTE in[40], one[40], two[40], iv1[16], iv2[16]; fillseq(in, 40, 0); fillseq(iv1, 16, 0x70); memcpy(iv2, iv1, 16); ULONG got = 0;
    EXPECT_EQ(enc(f.k.h, in, 40, iv1, 16, one, 40, &got, 0), 0);
    ULONG cuts[] = { 1, 3, 13, 23 };            /* 1,3,13,23 = 40 */
    ULONG off = 0;
    for (int i = 0; i < 4; i++) {
        EXPECT_EQ(enc(f.k.h, in + off, cuts[i], iv2, 16, two + off, cuts[i], &got, 0), 0);
        off += cuts[i];
    }
    CHECK(same(one, two, 40));
    CHECK(same(iv1, iv2, 16));                  /* shift register equal after the same stream */
    CHECK(same(iv1, one + 24, 16));
    fx_close(&f);
}
TEST(bsc_cfb8_decrypt_chunked) {
    WINE_SKIP("no CFB8 / MessageBlockLength");
    fx f; FX_OR_SKIP(f, L"AES", CFB, K);
    BYTE in[40], ct[40], pt[40], iv1[16], iv2[16]; fillseq(in, 40, 0x11); fillseq(iv1, 16, 0x70); memcpy(iv2, iv1, 16); ULONG got = 0;
    EXPECT_EQ(enc(f.k.h, in, 40, iv1, 16, ct, 40, &got, 0), 0);
    ULONG off = 0, cuts[] = { 5, 5, 7, 23 };
    for (int i = 0; i < 4; i++) { EXPECT_EQ(dec(f.k.h, ct + off, cuts[i], iv2, 16, pt + off, cuts[i], &got, 0), 0); off += cuts[i]; }
    CHECK(same(pt, in, 40));
    CHECK(same(iv1, iv2, 16));
    fx_close(&f);
}
TEST(bsc_cfb128_requires_block_multiple) {
    REQUIRE(P_GenKey);
    BCRYPT_ALG_HANDLE a = bsc_open(L"AES", CFB); if (!a) { t_skip("AES"); return; }
    ULONG mbl = 16;
    NTSTATUS s = P_SetProp(a, BCRYPT_MESSAGE_BLOCK_LENGTH, (PUCHAR)&mbl, 4, 0);
    if (WINE_UNSUP(s)) { bsc_close(a); t_skip("emulator"); return; }
    EXPECT_EQ(s, 0);
    bkey k; EXPECT_EQ(bsc_genhex(a, &k, K), 0);
    BYTE in[48] = {0}, out[48], iv[16] = {0}; ULONG got = 0xAAAA;
    EXPECT_EQ(enc(k.h, in, 32, iv, 16, out, 48, &got, 0), 0);
    got = 0xAAAA; memset(iv, 0, 16);
    s = enc(k.h, in, 17, iv, 16, out, 48, &got, 0);
    EXPECT_EQ(s, NS_INVALID_BUFFER_SIZE); EXPECT_EQ(got, 17);
    bsc_free(&k); bsc_close(a);
}
TEST(bsc_cfb_message_block_length_property) {
    WINE_SKIP("no CFB8 / MessageBlockLength");
    REQUIRE(P_GenKey);
    BCRYPT_ALG_HANDLE a = bsc_open(L"AES", CFB); if (!a) { t_skip("AES"); return; }
    ULONG v = 99, r = 0;
    NTSTATUS s = P_GetProp(a, BCRYPT_MESSAGE_BLOCK_LENGTH, (PUCHAR)&v, 4, &r, 0);
    EXPECT_EQ(s, 0); EXPECT_EQ(v, 1); EXPECT_EQ(r, 4);
    ULONG bad[] = { 0, 2, 8, 15, 17, 32 };
    for (int i = 0; i < 6; i++) {
        ULONG m = bad[i];
        s = P_SetProp(a, BCRYPT_MESSAGE_BLOCK_LENGTH, (PUCHAR)&m, 4, 0);
        t_note("SetProperty(MessageBlockLength=%lu) on AES-CFB -> 0x%lx", m, s);
    }
    ULONG m = 16;
    s = P_SetProp(a, BCRYPT_MESSAGE_BLOCK_LENGTH, (PUCHAR)&m, 4, 0);
    if (!WINE_UNSUP(s)) { EXPECT_EQ(s, 0); v = 0; P_GetProp(a, BCRYPT_MESSAGE_BLOCK_LENGTH, (PUCHAR)&v, 4, &r, 0); EXPECT_EQ(v, 16); }
    bsc_close(a);
}
TEST(bsc_cfb_message_block_length_wrong_size_buffer) {
    WINE_SKIP("no CFB8 / MessageBlockLength");
    REQUIRE(P_GenKey);
    BCRYPT_ALG_HANDLE a = bsc_open(L"AES", CFB); if (!a) { t_skip("AES"); return; }
    ULONG m = 16;
    NTSTATUS s = P_SetProp(a, BCRYPT_MESSAGE_BLOCK_LENGTH, (PUCHAR)&m, 0, 0);
    EXPECT_EQ(s, NS_INVALID_PARAM);
    s = P_SetProp(a, BCRYPT_MESSAGE_BLOCK_LENGTH, (PUCHAR)&m, 3, 0);
    t_note("MessageBlockLength with cbInput=3 -> 0x%lx", s);
    bsc_close(a);
}
TEST(bsc_message_block_length_not_available_for_cbc) {
    REQUIRE(P_GenKey);
    BCRYPT_ALG_HANDLE a = bsc_open(L"AES", CBC); if (!a) { t_skip("AES"); return; }
    ULONG v = 0, r = 0;
    NTSTATUS s = P_GetProp(a, BCRYPT_MESSAGE_BLOCK_LENGTH, (PUCHAR)&v, 4, &r, 0);
    t_note("GetProperty(MessageBlockLength) on CBC alg = 0x%lx (%lu)", s, v);
    ULONG m = 16;
    s = P_SetProp(a, BCRYPT_MESSAGE_BLOCK_LENGTH, (PUCHAR)&m, 4, 0);
    t_note("SetProperty(MessageBlockLength) on CBC alg = 0x%lx", s);
    bsc_close(a);
}

/* ================= misc flags ================= */
TEST(bsc_enc_unknown_flag_bits_observed) {
    fx f; FX_OR_SKIP(f, L"AES", CBC, K);
    BYTE in[16] = {0}, out[16]; BYTE iv[16] = {0};
    ULONG flags[] = { 2, 4, 0x80, 0x100, 0x80000000 };
    for (int i = 0; i < 5; i++) {
        ULONG got = 0;
        NTSTATUS s = enc(f.k.h, in, 16, iv, 16, out, 16, &got, flags[i]);
        t_note("Encrypt flags=0x%lx -> 0x%lx (%lu)", flags[i], s, got);
    }
    fx_close(&f);
}
TEST(bsc_enc_padding_with_rc4_observed) {
    REQUIRE(P_GenKey);
    BCRYPT_ALG_HANDLE a = bsc_open(L"RC4", NULL); if (!a) { t_skip("RC4"); return; }
    bkey k; if (bsc_genhex(a, &k, K) != 0) { bsc_close(a); t_skip("RC4"); return; }
    BYTE in[10] = {0}; ULONG got = 0xAAAA;
    NTSTATUS s = enc(k.h, in, 10, NULL, 0, NULL, 0, &got, BCRYPT_BLOCK_PADDING);
    t_note("RC4 + BLOCK_PADDING size query -> 0x%lx (%lu)", s, got);
    s = enc(k.h, in, 10, NULL, 0, NULL, 0, &got, 0);
    if (!WINE_UNSUP(s)) { EXPECT_EQ(s, 0); EXPECT_EQ(got, 10); }
    bsc_free(&k); bsc_close(a);
}
TEST(bsc_stream_cipher_any_length) {
    REQUIRE(P_GenKey);
    BCRYPT_ALG_HANDLE a = bsc_open(L"RC4", NULL); if (!a) { t_skip("RC4"); return; }
    bkey k; if (bsc_genhex(a, &k, K) != 0) { bsc_close(a); t_skip("RC4"); return; }
    BYTE in[40] = {0}, out[40]; ULONG got = 0xAAAA;
    NTSTATUS s = enc(k.h, in, 1, NULL, 0, out, 40, &got, 0);
    if (WINE_UNSUP(s)) { bsc_free(&k); bsc_close(a); t_skip("emulator"); return; }
    EXPECT_EQ(s, 0); EXPECT_EQ(got, 1);
    s = enc(k.h, in, 39, NULL, 0, out, 38, &got, 0);
    EXPECT_EQ(s, NS_BUFFER_TOO_SMALL); EXPECT_EQ(got, 39);
    bsc_free(&k); bsc_close(a);
}
