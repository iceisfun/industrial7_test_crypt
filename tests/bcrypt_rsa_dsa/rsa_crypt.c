/* BCrypt RSA encryption: PKCS#1 v1.5, OAEP, no padding. */
#include "rd.h"

static BCRYPT_ALG_HANDLE g_a;
static BCRYPT_KEY_HANDLE fx(ULONG magic) { return g_a ? rd_fixed_rsa(g_a, magic) : NULL; }
#define BEGIN() NEED_BCRYPT(); g_a = rd_alg(BCRYPT_RSA_ALGORITHM); if (!g_a) { t_skip("no RSA provider"); return; }
#define END() rd_closealg(g_a); g_a = NULL

static NTSTATUS enc(BCRYPT_KEY_HANDLE k, const UCHAR *in, ULONG il, void *pad, UCHAR *out, ULONG ol, ULONG *n, ULONG fl) {
    return U(BCryptEncrypt)(k, (PUCHAR)in, il, pad, NULL, 0, out, ol, n, fl);
}
static NTSTATUS dec(BCRYPT_KEY_HANDLE k, const UCHAR *in, ULONG il, void *pad, UCHAR *out, ULONG ol, ULONG *n, ULONG fl) {
    return U(BCryptDecrypt)(k, (PUCHAR)in, il, pad, NULL, 0, out, ol, n, fl);
}

/* ---------- known-answer decryption ---------- */
TEST(rsa_crypt_decrypt_pkcs1_known_answer) {
    BEGIN();
    BCRYPT_KEY_HANDLE k = fx(BCRYPT_RSAPRIVATE_MAGIC); CHECK(k);
    UCHAR out[128]; ULONG n = 0;
    EXPECT_EQ(dec(k, kCtPkcs1, 128, NULL, out, sizeof out, &n, BCRYPT_PAD_PKCS1), ST_SUCCESS);
    EXPECT_EQ(n, sizeof kPlain);
    CHECK(n == sizeof kPlain && !memcmp(out, kPlain, n));
    rd_destroy(k); END();
}
TEST(rsa_crypt_decrypt_pkcs1_fullprivate_key) {
    BEGIN();
    BCRYPT_KEY_HANDLE k = fx(BCRYPT_RSAFULLPRIVATE_MAGIC); CHECK(k);
    UCHAR out[128]; ULONG n = 0;
    EXPECT_EQ(dec(k, kCtPkcs1, 128, NULL, out, sizeof out, &n, BCRYPT_PAD_PKCS1), ST_SUCCESS);
    CHECK(n == sizeof kPlain && !memcmp(out, kPlain, n));
    rd_destroy(k); END();
}
TEST(rsa_crypt_decrypt_oaep_sha1_known_answer) {
    BEGIN();
    BCRYPT_KEY_HANDLE k = fx(BCRYPT_RSAPRIVATE_MAGIC); CHECK(k);
    BCRYPT_OAEP_PADDING_INFO pi = { BCRYPT_SHA1_ALGORITHM, NULL, 0 };
    UCHAR out[128]; ULONG n = 0;
    EXPECT_EQ(dec(k, kCtOaepSha1, 128, &pi, out, sizeof out, &n, BCRYPT_PAD_OAEP), ST_SUCCESS);
    CHECK(n == sizeof kPlain && !memcmp(out, kPlain, n));
    rd_destroy(k); END();
}
TEST(rsa_crypt_decrypt_oaep_sha256_known_answer) {
    BEGIN();
    BCRYPT_KEY_HANDLE k = fx(BCRYPT_RSAPRIVATE_MAGIC); CHECK(k);
    BCRYPT_OAEP_PADDING_INFO pi = { BCRYPT_SHA256_ALGORITHM, NULL, 0 };
    UCHAR out[128]; ULONG n = 0;
    EXPECT_EQ(dec(k, kCtOaepSha256, 128, &pi, out, sizeof out, &n, BCRYPT_PAD_OAEP), ST_SUCCESS);
    CHECK(n == sizeof kPlain && !memcmp(out, kPlain, n));
    rd_destroy(k); END();
}
TEST(rsa_crypt_decrypt_oaep_sha256_label_known_answer) {
    BEGIN();
    BCRYPT_KEY_HANDLE k = fx(BCRYPT_RSAPRIVATE_MAGIC); CHECK(k);
    UCHAR label[3] = { 'l', 'b', 'l' };
    BCRYPT_OAEP_PADDING_INFO pi = { BCRYPT_SHA256_ALGORITHM, label, 3 };
    UCHAR out[128]; ULONG n = 0;
    EXPECT_EQ(dec(k, kCtOaepSha256Lbl, 128, &pi, out, sizeof out, &n, BCRYPT_PAD_OAEP), ST_SUCCESS);
    CHECK(n == sizeof kPlain && !memcmp(out, kPlain, n));
    /* wrong label, no label, different hash: all fail */
    UCHAR bad[3] = { 'l', 'b', 'x' };
    pi.pbLabel = bad;
    NTSTATUS s = dec(k, kCtOaepSha256Lbl, 128, &pi, out, sizeof out, &n, BCRYPT_PAD_OAEP);
    CHECK(s != 0); t_note("OAEP wrong label: 0x%lx", (unsigned long)s);
    pi.pbLabel = NULL; pi.cbLabel = 0;
    CHECK(dec(k, kCtOaepSha256Lbl, 128, &pi, out, sizeof out, &n, BCRYPT_PAD_OAEP) != 0);
    pi.pbLabel = label; pi.cbLabel = 2;
    CHECK(dec(k, kCtOaepSha256Lbl, 128, &pi, out, sizeof out, &n, BCRYPT_PAD_OAEP) != 0);
    rd_destroy(k); END();
}
TEST(rsa_crypt_decrypt_oaep_wrong_hash_fails) {
    BEGIN();
    BCRYPT_KEY_HANDLE k = fx(BCRYPT_RSAPRIVATE_MAGIC); CHECK(k);
    UCHAR out[128]; ULONG n = 0;
    BCRYPT_OAEP_PADDING_INFO pi = { BCRYPT_SHA256_ALGORITHM, NULL, 0 };
    NTSTATUS s = dec(k, kCtOaepSha1, 128, &pi, out, sizeof out, &n, BCRYPT_PAD_OAEP);
    CHECK(s != 0); t_note("OAEP sha1 ciphertext with sha256 info: 0x%lx", (unsigned long)s);
    pi.pszAlgId = BCRYPT_SHA1_ALGORITHM;
    CHECK(dec(k, kCtOaepSha256, 128, &pi, out, sizeof out, &n, BCRYPT_PAD_OAEP) != 0);
    rd_destroy(k); END();
}
TEST(rsa_crypt_decrypt_cross_padding_fails) {
    BEGIN();
    BCRYPT_KEY_HANDLE k = fx(BCRYPT_RSAPRIVATE_MAGIC); CHECK(k);
    UCHAR out[128]; ULONG n = 0;
    BCRYPT_OAEP_PADDING_INFO pi = { BCRYPT_SHA1_ALGORITHM, NULL, 0 };
    CHECK(dec(k, kCtPkcs1, 128, &pi, out, sizeof out, &n, BCRYPT_PAD_OAEP) != 0);
    CHECK(dec(k, kCtOaepSha1, 128, NULL, out, sizeof out, &n, BCRYPT_PAD_PKCS1) != 0);
    rd_destroy(k); END();
}
TEST(rsa_crypt_no_padding_known_answer) {
    BEGIN();
    BCRYPT_KEY_HANDLE pub = fx(BCRYPT_RSAPUBLIC_MAGIC), prv = fx(BCRYPT_RSAPRIVATE_MAGIC); CHECK(pub && prv);
    UCHAR out[128]; ULONG n = 0;
    EXPECT_EQ(enc(pub, kRawPlain, 128, NULL, out, sizeof out, &n, BCRYPT_PAD_NONE), ST_SUCCESS);
    EXPECT_EQ(n, 128);
    CHECK(!memcmp(out, kRawCt, 128));            /* textbook RSA is deterministic */
    EXPECT_EQ(dec(prv, kRawCt, 128, NULL, out, sizeof out, &n, BCRYPT_PAD_NONE), ST_SUCCESS);
    EXPECT_EQ(n, 128);
    CHECK(!memcmp(out, kRawPlain, 128));
    rd_destroy(pub); rd_destroy(prv); END();
}
TEST(rsa_crypt_no_padding_encrypt_with_private_key) {
    BEGIN();
    BCRYPT_KEY_HANDLE prv = fx(BCRYPT_RSAFULLPRIVATE_MAGIC); CHECK(prv);
    UCHAR out[128]; ULONG n = 0;
    EXPECT_EQ(enc(prv, kRawPlain, 128, NULL, out, sizeof out, &n, BCRYPT_PAD_NONE), ST_SUCCESS);
    CHECK(!memcmp(out, kRawCt, 128));
    rd_destroy(prv); END();
}
TEST(rsa_crypt_no_padding_input_at_least_modulus_fails) {
    BEGIN();
    BCRYPT_KEY_HANDLE pub = fx(BCRYPT_RSAPUBLIC_MAGIC); CHECK(pub);
    UCHAR in[128], out[128]; ULONG n = 0;
    memset(in, 0xff, sizeof in);
    NTSTATUS s = enc(pub, in, 128, NULL, out, sizeof out, &n, BCRYPT_PAD_NONE);
    EXPECT_EQ(s, ST_INVALID_PARAMETER);
    memcpy(in, kRsaN, 128);   /* exactly the modulus */
    s = enc(pub, in, 128, NULL, out, sizeof out, &n, BCRYPT_PAD_NONE);
    t_note("no-padding input equal to the modulus: 0x%lx", (unsigned long)s);
    EXPECT_EQ(s, ST_INVALID_PARAMETER);
    UCHAR big[129]; memset(big, 1, sizeof big);
    n = 0;
    s = enc(pub, big, 129, NULL, out, sizeof out, &n, BCRYPT_PAD_NONE);
    /* 129 bytes: Win10 only uses the first modulus-size bytes */
    EXPECT_EQ(s, ST_SUCCESS); EXPECT_EQ(n, 128);
    { UCHAR out2[128]; ULONG n2 = 0;
      NTSTATUS s2 = enc(pub, big, 128, NULL, out2, sizeof out2, &n2, BCRYPT_PAD_NONE);
      t_note("129-byte input same as first 128 bytes: s2=0x%lx same=%d", (unsigned long)s2, !memcmp(out, out2, 128)); }
    rd_destroy(pub); END();
}
TEST(rsa_crypt_no_padding_short_input) {
    BEGIN();
    BCRYPT_KEY_HANDLE pub = fx(BCRYPT_RSAPUBLIC_MAGIC), prv = fx(BCRYPT_RSAPRIVATE_MAGIC); CHECK(pub && prv);
    UCHAR in[16], out[128], back[128]; ULONG n = 0, m = 0;
    for (int i = 0; i < 16; i++) in[i] = (UCHAR)(0x90 + i);
    NTSTATUS s = enc(pub, in, sizeof in, NULL, out, sizeof out, &n, BCRYPT_PAD_NONE);
    t_note("no-padding 16-byte input: 0x%lx n=%lu", (unsigned long)s, n);
    if (s == 0) {
        EXPECT_EQ(n, 128);
        EXPECT_EQ(dec(prv, out, n, NULL, back, sizeof back, &m, BCRYPT_PAD_NONE), ST_SUCCESS);
        /* the integer value is preserved: the 16 input bytes are the least significant bytes of the result */
        if (m >= 16) CHECK(!memcmp(back + m - 16, in, 16));
        t_note("no-padding decrypt of short input returned %lu bytes", m);
    }
    rd_destroy(pub); rd_destroy(prv); END();
}

/* ---------- size protocol ---------- */
TEST(rsa_crypt_encrypt_size_query_all_paddings) {
    BEGIN();
    static const ULONG sizes[] = { 512, 1024, 2048 };
    for (int i = 0; i < 3; i++) {
        BCRYPT_KEY_HANDLE k = rd_gen(g_a, sizes[i]); CHECK(k); if (!k) continue;
        UCHAR in[16] = { 1, 2, 3 }; ULONG n = 0xdead;
        BCRYPT_OAEP_PADDING_INFO oi = { BCRYPT_SHA1_ALGORITHM, NULL, 0 };
        EXPECT_EQ(enc(k, in, sizeof in, NULL, NULL, 0, &n, BCRYPT_PAD_PKCS1), ST_SUCCESS);
        EXPECT_EQ(n, sizes[i] / 8);
        n = 0xdead;
        EXPECT_EQ(enc(k, in, sizeof in, &oi, NULL, 0, &n, BCRYPT_PAD_OAEP), ST_SUCCESS);
        EXPECT_EQ(n, sizes[i] / 8);
        n = 0xdead;
        { NTSTATUS sn = enc(k, in, sizeof in, NULL, NULL, 0, &n, BCRYPT_PAD_NONE);
          t_note("PAD_NONE size query (16-byte input, %lu-bit key): 0x%lx n=%lu", sizes[i], (unsigned long)sn, n); }
        rd_destroy(k);
    }
    END();
}
TEST(rsa_crypt_encrypt_buffer_too_small) {
    BEGIN();
    BCRYPT_KEY_HANDLE pub = fx(BCRYPT_RSAPUBLIC_MAGIC); CHECK(pub);
    UCHAR in[10] = { 9 }, out[256]; ULONG sizes[] = { 0, 1, 64, 127 };
    for (int i = 0; i < 4; i++) {
        ULONG n = 0;
        NTSTATUS s = enc(pub, in, sizeof in, NULL, out, sizes[i], &n, BCRYPT_PAD_PKCS1);
        CHECKF(s == (NTSTATUS)ST_BUFFER_TOO_SMALL, "cb=%lu -> 0x%lx", sizes[i], (unsigned long)s);
        EXPECT_EQ(n, 128);
    }
    ULONG n = 0;
    EXPECT_EQ(enc(pub, in, sizeof in, NULL, out, 128, &n, BCRYPT_PAD_PKCS1), ST_SUCCESS);
    EXPECT_EQ(n, 128);
    EXPECT_EQ(enc(pub, in, sizeof in, NULL, out, 256, &n, BCRYPT_PAD_PKCS1), ST_SUCCESS);
    EXPECT_EQ(n, 128);
    rd_destroy(pub); END();
}
TEST(rsa_crypt_decrypt_size_query_pkcs1) {
    BEGIN();
    BCRYPT_KEY_HANDLE k = fx(BCRYPT_RSAPRIVATE_MAGIC); CHECK(k);
    ULONG n = 0xdead;
    EXPECT_EQ(dec(k, kCtPkcs1, 128, NULL, NULL, 0, &n, BCRYPT_PAD_PKCS1), ST_SUCCESS);
    t_note("PKCS1 decrypt size query returns %lu (plaintext is %lu)", n, (ULONG)sizeof kPlain);
    CHECK(n >= sizeof kPlain && n <= 128);
    rd_destroy(k); END();
}
TEST(rsa_crypt_decrypt_size_query_oaep) {
    BEGIN();
    BCRYPT_KEY_HANDLE k = fx(BCRYPT_RSAPRIVATE_MAGIC); CHECK(k);
    BCRYPT_OAEP_PADDING_INFO pi = { BCRYPT_SHA1_ALGORITHM, NULL, 0 };
    ULONG n = 0xdead;
    NTSTATUS s = dec(k, kCtOaepSha1, 128, &pi, NULL, 0, &n, BCRYPT_PAD_OAEP);
    EXPECT_EQ(s, ST_SUCCESS);
    t_note("OAEP decrypt size query returns %lu (plaintext is %lu)", n, (ULONG)sizeof kPlain);
    CHECK(n >= sizeof kPlain && n <= 128);
    rd_destroy(k); END();
}
TEST(rsa_crypt_decrypt_buffer_too_small) {
    BEGIN();
    BCRYPT_KEY_HANDLE k = fx(BCRYPT_RSAPRIVATE_MAGIC); CHECK(k);
    UCHAR out[128]; ULONG n = 0;
    NTSTATUS s = dec(k, kCtPkcs1, 128, NULL, out, sizeof kPlain - 1, &n, BCRYPT_PAD_PKCS1);
    if (s == 0) t_note("short PKCS1 decrypt buffer accepted (seen on Windows 10 1809)");
    else { EXPECT_EQ(s, ST_BUFFER_TOO_SMALL); EXPECT_EQ(n, sizeof kPlain); }
    s = dec(k, kCtPkcs1, 128, NULL, out, 0, &n, BCRYPT_PAD_PKCS1);
    CHECK(s == (NTSTATUS)ST_BUFFER_TOO_SMALL || s == 0);
    memset(out, 0xcc, sizeof out);
    s = dec(k, kCtPkcs1, 128, NULL, out, sizeof kPlain, &n, BCRYPT_PAD_PKCS1);
    EXPECT_EQ(s, ST_SUCCESS);
    EXPECT_EQ(n, sizeof kPlain);
    CHECK(!memcmp(out, kPlain, n) && out[n] == 0xcc);
    rd_destroy(k); END();
}

/* ---------- round trips ---------- */
TEST(rsa_crypt_pkcs1_roundtrip_message_lengths) {
    BEGIN();
    BCRYPT_KEY_HANDLE k = rd_gen(g_a, 1024); CHECK(k); if (!k) { END(); return; }
    ULONG lens[] = { 1, 2, 16, 32, 100, 116, 117 };   /* max = 128 - 11 */
    for (size_t i = 0; i < sizeof lens / sizeof *lens; i++) {
        UCHAR in[128], ct[128], pt[128]; ULONG n = 0, m = 0;
        for (ULONG j = 0; j < lens[i]; j++) in[j] = (UCHAR)(j * 5 + 1);
        NTSTATUS s = enc(k, in, lens[i], NULL, ct, sizeof ct, &n, BCRYPT_PAD_PKCS1);
        CHECKF(s == 0, "len %lu enc 0x%lx", lens[i], (unsigned long)s); if (s) continue;
        EXPECT_EQ(n, 128);
        s = dec(k, ct, n, NULL, pt, sizeof pt, &m, BCRYPT_PAD_PKCS1);
        EXPECT_EQ(s, ST_SUCCESS);
        CHECK(m == lens[i] && !memcmp(pt, in, m));
    }
    rd_destroy(k); END();
}
TEST(rsa_crypt_pkcs1_message_too_long) {
    BEGIN();
    BCRYPT_KEY_HANDLE k = rd_gen(g_a, 1024); CHECK(k); if (!k) { END(); return; }
    UCHAR in[200] = { 1 }, ct[128]; ULONG n = 0;
    ULONG lens[] = { 118, 119, 128, 129, 200 };
    for (int i = 0; i < 5; i++) {
        NTSTATUS s = enc(k, in, lens[i], NULL, ct, sizeof ct, &n, BCRYPT_PAD_PKCS1);
        CHECKF(s != 0, "len %lu encrypted", lens[i]);
        t_note("PKCS1 encrypt of %lu bytes on 1024-bit key: 0x%lx", lens[i], (unsigned long)s);
    }
    rd_destroy(k); END();
}
TEST(rsa_crypt_pkcs1_is_randomised) {
    BEGIN();
    BCRYPT_KEY_HANDLE k = fx(BCRYPT_RSAPUBLIC_MAGIC); CHECK(k);
    UCHAR a[128], b[128]; ULONG n = 0;
    EXPECT_EQ(enc(k, kPlain, sizeof kPlain, NULL, a, sizeof a, &n, BCRYPT_PAD_PKCS1), ST_SUCCESS);
    EXPECT_EQ(enc(k, kPlain, sizeof kPlain, NULL, b, sizeof b, &n, BCRYPT_PAD_PKCS1), ST_SUCCESS);
    CHECK(memcmp(a, b, 128) != 0);
    BCRYPT_OAEP_PADDING_INFO oi = { BCRYPT_SHA256_ALGORITHM, NULL, 0 };
    EXPECT_EQ(enc(k, kPlain, sizeof kPlain, &oi, a, sizeof a, &n, BCRYPT_PAD_OAEP), ST_SUCCESS);
    EXPECT_EQ(enc(k, kPlain, sizeof kPlain, &oi, b, sizeof b, &n, BCRYPT_PAD_OAEP), ST_SUCCESS);
    CHECK(memcmp(a, b, 128) != 0);
    rd_destroy(k); END();
}
TEST(rsa_crypt_pkcs1_encrypt_decrypts_with_known_key) {
    BEGIN();
    BCRYPT_KEY_HANDLE pub = fx(BCRYPT_RSAPUBLIC_MAGIC), prv = fx(BCRYPT_RSAPRIVATE_MAGIC); CHECK(pub && prv);
    UCHAR ct[128], pt[128]; ULONG n = 0, m = 0;
    EXPECT_EQ(enc(pub, kPlain, sizeof kPlain, NULL, ct, sizeof ct, &n, BCRYPT_PAD_PKCS1), ST_SUCCESS);
    /* PKCS#1 v1.5 encryption block: 00 02 <non-zero padding> 00 <msg>; check via raw decrypt */
    UCHAR raw[128];
    EXPECT_EQ(dec(prv, ct, n, NULL, raw, sizeof raw, &m, BCRYPT_PAD_NONE), ST_SUCCESS);
    if (m == 128) {
        CHECK(raw[0] == 0x00 && raw[1] == 0x02);
        int z = 2; while (z < 128 && raw[z] != 0) z++;
        CHECK(z >= 10 && z < 128);
        CHECK(128 - (z + 1) == (int)sizeof kPlain && !memcmp(raw + z + 1, kPlain, sizeof kPlain));
        CHECK(z - 2 == 128 - 3 - (int)sizeof kPlain);   /* padding string fills the block */
    } else t_note("raw decrypt returned %lu bytes", m);
    EXPECT_EQ(dec(prv, ct, n, NULL, pt, sizeof pt, &m, BCRYPT_PAD_PKCS1), ST_SUCCESS);
    CHECK(m == sizeof kPlain && !memcmp(pt, kPlain, m));
    rd_destroy(pub); rd_destroy(prv); END();
}
typedef struct { LPCWSTR h; ULONG hl; } oaepcase;
static const oaepcase g_oc[] = { { BCRYPT_SHA1_ALGORITHM, 20 }, { BCRYPT_SHA256_ALGORITHM, 32 }, { BCRYPT_SHA384_ALGORITHM, 48 }, { BCRYPT_SHA512_ALGORITHM, 64 } };
TEST(rsa_crypt_oaep_roundtrip_hashes_and_max_length) {
    BEGIN();
    BCRYPT_KEY_HANDLE k = rd_gen(g_a, 2048); CHECK(k); if (!k) { END(); return; }
    for (size_t i = 0; i < sizeof g_oc / sizeof *g_oc; i++) {
        ULONG maxm = 256 - 2 * g_oc[i].hl - 2;
        BCRYPT_OAEP_PADDING_INFO pi = { g_oc[i].h, NULL, 0 };
        UCHAR in[256], ct[256], pt[256]; ULONG n = 0, m = 0;
        for (int j = 0; j < 256; j++) in[j] = (UCHAR)(j + 7);
        ULONG lens[] = { 0, 1, maxm / 2, maxm };
        for (int c = 0; c < 4; c++) {
            NTSTATUS s = enc(k, in, lens[c], &pi, ct, sizeof ct, &n, BCRYPT_PAD_OAEP);
            if (lens[c] == 0) { t_note("OAEP %ls zero-length message: 0x%lx", g_oc[i].h, (unsigned long)s); if (s) continue; }
            else CHECKF(s == 0, "%ls len %lu: 0x%lx", g_oc[i].h, lens[c], (unsigned long)s);
            if (s) continue;
            EXPECT_EQ(n, 256);
            s = dec(k, ct, n, &pi, pt, sizeof pt, &m, BCRYPT_PAD_OAEP);
            EXPECT_EQ(s, ST_SUCCESS);
            CHECK(m == lens[c] && !memcmp(pt, in, m));
        }
        NTSTATUS s = enc(k, in, maxm + 1, &pi, ct, sizeof ct, &n, BCRYPT_PAD_OAEP);
        CHECKF(s != 0, "%ls len %lu should be too long", g_oc[i].h, maxm + 1);
        t_note("OAEP %ls max=%lu, max+1 -> 0x%lx", g_oc[i].h, maxm, (unsigned long)s);
    }
    rd_destroy(k); END();
}
TEST(rsa_crypt_oaep_hash_too_large_for_key) {
    BEGIN();
    BCRYPT_KEY_HANDLE k = rd_gen(g_a, 1024); CHECK(k); if (!k) { END(); return; }
    BCRYPT_OAEP_PADDING_INFO pi = { BCRYPT_SHA512_ALGORITHM, NULL, 0 };   /* 128 - 2*64 - 2 < 0 */
    UCHAR in[1] = { 1 }, ct[128]; ULONG n = 0;
    NTSTATUS s = enc(k, in, 1, &pi, ct, sizeof ct, &n, BCRYPT_PAD_OAEP);
    CHECK(s != 0); t_note("OAEP SHA-512 on 1024-bit key: 0x%lx", (unsigned long)s);
    rd_destroy(k); END();
}
TEST(rsa_crypt_oaep_label_roundtrip) {
    BEGIN();
    BCRYPT_KEY_HANDLE k = rd_gen(g_a, 1024); CHECK(k); if (!k) { END(); return; }
    UCHAR label[300]; for (int i = 0; i < 300; i++) label[i] = (UCHAR)i;
    ULONG ll[] = { 0, 1, 16, 300 };
    for (int i = 0; i < 4; i++) {
        BCRYPT_OAEP_PADDING_INFO pi = { BCRYPT_SHA256_ALGORITHM, ll[i] ? label : NULL, ll[i] };
        UCHAR ct[128], pt[128]; ULONG n = 0, m = 0;
        EXPECT_EQ(enc(k, kPlain, sizeof kPlain, &pi, ct, sizeof ct, &n, BCRYPT_PAD_OAEP), ST_SUCCESS);
        EXPECT_EQ(dec(k, ct, n, &pi, pt, sizeof pt, &m, BCRYPT_PAD_OAEP), ST_SUCCESS);
        CHECK(m == sizeof kPlain && !memcmp(pt, kPlain, m));
        if (ll[i]) {
            pi.pbLabel = NULL; pi.cbLabel = 0;
            CHECK(dec(k, ct, n, &pi, pt, sizeof pt, &m, BCRYPT_PAD_OAEP) != 0);
        }
    }
    rd_destroy(k); END();
}
TEST(rsa_crypt_oaep_default_label_equals_null_label) {
    BEGIN();
    BCRYPT_KEY_HANDLE k = fx(BCRYPT_RSAPRIVATE_MAGIC); CHECK(k);
    /* label pointer set but zero length behaves as no label */
    UCHAR dummy[4] = { 1, 2, 3, 4 };
    BCRYPT_OAEP_PADDING_INFO pi = { BCRYPT_SHA1_ALGORITHM, dummy, 0 };
    UCHAR out[128]; ULONG n = 0;
    NTSTATUS s = dec(k, kCtOaepSha1, 128, &pi, out, sizeof out, &n, BCRYPT_PAD_OAEP);
    t_note("OAEP pbLabel set, cbLabel 0: 0x%lx", (unsigned long)s);
    if (s == 0) CHECK(n == sizeof kPlain && !memcmp(out, kPlain, n));
    rd_destroy(k); END();
}
TEST(rsa_crypt_tampered_ciphertext_fails) {
    BEGIN();
    BCRYPT_KEY_HANDLE k = fx(BCRYPT_RSAPRIVATE_MAGIC); CHECK(k);
    UCHAR ct[128], out[128]; ULONG n = 0;
    BCRYPT_OAEP_PADDING_INFO pi = { BCRYPT_SHA1_ALGORITHM, NULL, 0 };
    memcpy(ct, kCtOaepSha1, 128); ct[64] ^= 1;
    NTSTATUS s = dec(k, ct, 128, &pi, out, sizeof out, &n, BCRYPT_PAD_OAEP);
    CHECK(s != 0); t_note("tampered OAEP ciphertext: 0x%lx", (unsigned long)s);
    memcpy(ct, kCtPkcs1, 128); ct[10] ^= 1;
    s = dec(k, ct, 128, NULL, out, sizeof out, &n, BCRYPT_PAD_PKCS1);
    CHECK(s != 0); t_note("tampered PKCS1 ciphertext: 0x%lx", (unsigned long)s);
    rd_destroy(k); END();
}

/* ---------- argument validation ---------- */
TEST(rsa_crypt_ciphertext_wrong_length) {
    BEGIN();
    BCRYPT_KEY_HANDLE k = fx(BCRYPT_RSAPRIVATE_MAGIC); CHECK(k);
    UCHAR in[256], out[256]; ULONG n = 0;
    memcpy(in, kCtPkcs1, 128); memset(in + 128, 0, 128);
    ULONG lens[] = { 127, 129, 64, 256 };
    for (int i = 0; i < 4; i++) {
        n = 0;
        NTSTATUS sp = dec(k, in, lens[i], NULL, out, sizeof out, &n, BCRYPT_PAD_PKCS1);
        /* Win10 ignores bytes beyond the modulus size (the trailing bytes here are zero) and rejects short input */
        t_label("len %lu", lens[i]);
        if (lens[i] < 128) { EXPECT_EQ(sp, ST_INVALID_PARAMETER); }
        else { EXPECT_EQ(sp, ST_SUCCESS); EXPECT_EQ(n, sizeof kPlain); CHECK(n == sizeof kPlain && !memcmp(out, kPlain, n)); }
        n = 0;
        NTSTATUS sn = dec(k, in, lens[i], NULL, out, sizeof out, &n, BCRYPT_PAD_NONE);
        if (lens[i] < 128) { EXPECT_EQ(sn, ST_INVALID_PARAMETER); }
        else { EXPECT_EQ(sn, ST_SUCCESS); EXPECT_EQ(n, 128); }
        t_label(NULL);
    }
    rd_destroy(k); END();
}
TEST(rsa_crypt_null_pcbresult_and_handle) {
    BEGIN();
    BCRYPT_KEY_HANDLE k = fx(BCRYPT_RSAPUBLIC_MAGIC); CHECK(k);
    UCHAR out[128]; ULONG n = 0;
    EXPECT_EQ(U(BCryptEncrypt)(k, (PUCHAR)kPlain, sizeof kPlain, NULL, NULL, 0, out, sizeof out, NULL, BCRYPT_PAD_PKCS1), ST_INVALID_PARAMETER);
    EXPECT_EQ(U(BCryptDecrypt)(k, (PUCHAR)kCtPkcs1, 128, NULL, NULL, 0, out, sizeof out, NULL, BCRYPT_PAD_PKCS1), ST_INVALID_PARAMETER);
    EXPECT_EQ(enc(NULL, kPlain, sizeof kPlain, NULL, out, sizeof out, &n, BCRYPT_PAD_PKCS1), ST_INVALID_HANDLE);
    EXPECT_EQ(dec(NULL, kCtPkcs1, 128, NULL, out, sizeof out, &n, BCRYPT_PAD_PKCS1), ST_INVALID_HANDLE);
    EXPECT_EQ(enc((BCRYPT_KEY_HANDLE)g_a, kPlain, sizeof kPlain, NULL, out, sizeof out, &n, BCRYPT_PAD_PKCS1), ST_INVALID_HANDLE);
    rd_destroy(k); END();
}
TEST(rsa_crypt_oaep_without_padding_info) {
    BEGIN();
    BCRYPT_KEY_HANDLE pub = fx(BCRYPT_RSAPUBLIC_MAGIC), prv = fx(BCRYPT_RSAPRIVATE_MAGIC); CHECK(pub && prv);
    UCHAR out[128]; ULONG n = 0;
    EXPECT_EQ(enc(pub, kPlain, sizeof kPlain, NULL, out, sizeof out, &n, BCRYPT_PAD_OAEP), ST_INVALID_PARAMETER);
    EXPECT_EQ(dec(prv, kCtOaepSha1, 128, NULL, out, sizeof out, &n, BCRYPT_PAD_OAEP), ST_INVALID_PARAMETER);
    rd_destroy(pub); rd_destroy(prv); END();
}
TEST(rsa_crypt_oaep_non_hash_alg) {
    BEGIN();
    BCRYPT_KEY_HANDLE pub = fx(BCRYPT_RSAPUBLIC_MAGIC); CHECK(pub);
    UCHAR out[128]; ULONG n = 0;
    BCRYPT_OAEP_PADDING_INFO pi = { BCRYPT_AES_ALGORITHM, NULL, 0 };
    NTSTATUS s = enc(pub, kPlain, sizeof kPlain, &pi, out, sizeof out, &n, BCRYPT_PAD_OAEP);
    CHECK(s != 0); t_note("OAEP with AES as hash: 0x%lx", (unsigned long)s);
    pi.pszAlgId = NULL;
    s = enc(pub, kPlain, sizeof kPlain, &pi, out, sizeof out, &n, BCRYPT_PAD_OAEP);
    CHECK(s != 0); t_note("OAEP with NULL hash id: 0x%lx", (unsigned long)s);
    rd_destroy(pub); END();
}
TEST(rsa_crypt_flags_zero_and_invalid) {
    BEGIN();
    BCRYPT_KEY_HANDLE pub = fx(BCRYPT_RSAPUBLIC_MAGIC); CHECK(pub);
    UCHAR out[128]; ULONG n = 0;
    NTSTATUS s = enc(pub, kPlain, sizeof kPlain, NULL, out, sizeof out, &n, 0);
    t_note("RSA encrypt flags=0: 0x%lx", (unsigned long)s);
    s = enc(pub, kPlain, sizeof kPlain, NULL, out, sizeof out, &n, BCRYPT_PAD_PSS);
    CHECK(s != 0); t_note("RSA encrypt with PSS flag: 0x%lx", (unsigned long)s);
    s = enc(pub, kPlain, sizeof kPlain, NULL, out, sizeof out, &n, 0x80000000);
    CHECK(s != 0); t_note("RSA encrypt with bogus flag: 0x%lx", (unsigned long)s);
    rd_destroy(pub); END();
}
TEST(rsa_crypt_decrypt_with_public_key_only_fails) {
    BEGIN();
    BCRYPT_KEY_HANDLE pub = fx(BCRYPT_RSAPUBLIC_MAGIC); CHECK(pub);
    UCHAR out[128]; ULONG n = 0;
    NTSTATUS s = dec(pub, kCtPkcs1, 128, NULL, out, sizeof out, &n, BCRYPT_PAD_PKCS1);
    CHECK(s != 0); t_note("decrypt with public-only key: 0x%lx", (unsigned long)s);
    s = dec(pub, kRawCt, 128, NULL, out, sizeof out, &n, BCRYPT_PAD_NONE);
    CHECK(s != 0);
    rd_destroy(pub); END();
}
TEST(rsa_crypt_iv_ignored_for_rsa) {
    BEGIN();
    BCRYPT_KEY_HANDLE pub = fx(BCRYPT_RSAPUBLIC_MAGIC); CHECK(pub);
    UCHAR out[128], iv[16] = { 0 }; ULONG n = 0;
    NTSTATUS s = U(BCryptEncrypt)(pub, (PUCHAR)kPlain, sizeof kPlain, NULL, iv, sizeof iv, out, sizeof out, &n, BCRYPT_PAD_PKCS1);
    t_note("RSA encrypt with IV supplied: 0x%lx", (unsigned long)s);
    rd_destroy(pub); END();
}
TEST(rsa_crypt_cross_key_decrypt_fails) {
    BEGIN();
    BCRYPT_KEY_HANDLE other = rd_gen(g_a, 1024); CHECK(other);
    UCHAR out[128]; ULONG n = 0;
    if (other) {
        NTSTATUS s = dec(other, kCtPkcs1, 128, NULL, out, sizeof out, &n, BCRYPT_PAD_PKCS1);
        CHECK(s != 0 || n != sizeof kPlain || memcmp(out, kPlain, n));
        t_note("decrypt with unrelated key: 0x%lx", (unsigned long)s);
    }
    rd_destroy(other); END();
}
TEST(rsa_crypt_unfinalized_decrypt_invalid_handle) {
    BEGIN();
    BCRYPT_KEY_HANDLE k = NULL;
    EXPECT_EQ(U(BCryptGenerateKeyPair)(g_a, &k, 512, 0), ST_SUCCESS);
    UCHAR in[64] = { 1 }, out[64]; ULONG n = 0;
    if (k) {
        NTSTATUS sd = dec(k, in, 64, NULL, out, sizeof out, &n, BCRYPT_PAD_NONE);
        NTSTATUS se = enc(k, in, 16, NULL, out, sizeof out, &n, BCRYPT_PAD_PKCS1);
        CHECK(sd != 0 && se != 0);
        t_note("unfinalized decrypt=0x%lx encrypt=0x%lx", (unsigned long)sd, (unsigned long)se);
        rd_destroy(k);
    }
    END();
}
TEST(rsa_crypt_in_place_pkcs1) {
    BEGIN();
    BCRYPT_KEY_HANDLE prv = fx(BCRYPT_RSAPRIVATE_MAGIC); CHECK(prv);
    UCHAR buf[128]; ULONG n = 0;
    memcpy(buf, kCtPkcs1, 128);
    NTSTATUS s = dec(prv, buf, 128, NULL, buf, sizeof buf, &n, BCRYPT_PAD_PKCS1);
    t_note("in-place decrypt: 0x%lx n=%lu", (unsigned long)s, n);
    if (s == 0) CHECK(n == sizeof kPlain && !memcmp(buf, kPlain, n));
    rd_destroy(prv); END();
}
TEST(rsa_crypt_legacy_key_encrypt_decrypt) {
    BEGIN();
    BCRYPT_KEY_HANDLE k = rd_gen(g_a, 1024); CHECK(k); if (!k) { END(); return; }
    UCHAR *b; ULONG bl; BCRYPT_KEY_HANDLE k2 = NULL;
    if (rd_export(k, LEGACY_RSAPRIVATE_BLOB, &b, &bl) == 0) {
        if (rd_import(g_a, LEGACY_RSAPRIVATE_BLOB, b, bl, &k2) == 0) {
            UCHAR ct[128], pt[128]; ULONG n = 0, m = 0;
            EXPECT_EQ(enc(k2, kPlain, sizeof kPlain, NULL, ct, sizeof ct, &n, BCRYPT_PAD_PKCS1), ST_SUCCESS);
            EXPECT_EQ(dec(k, ct, n, NULL, pt, sizeof pt, &m, BCRYPT_PAD_PKCS1), ST_SUCCESS);
            CHECK(m == sizeof kPlain && !memcmp(pt, kPlain, m));
            rd_destroy(k2);
        } else CHECK(0);
        free(b);
    } else t_note("legacy private export unavailable");
    rd_destroy(k); END();
}
