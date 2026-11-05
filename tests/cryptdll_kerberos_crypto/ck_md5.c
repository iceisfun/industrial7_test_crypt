/* MD5Init / MD5Update / MD5Final (forwarded to ntdll): RFC 1321 vectors and context layout. */
#include "ck.h"
#include "ck_vec.h"

#define MD5_NEED() do { if (!CKP(MD5Init) || !CKP(MD5Update) || !CKP(MD5Final)) { t_skip("missing MD5 exports"); return; } } while (0)

static void md5_oneshot(const BYTE *p, size_t n, CK_MD5_CTX *c) {
    CKP(MD5Init)(c);
    if (n) CKP(MD5Update)(c, p, (ULONG)n);
    CKP(MD5Final)(c);
}

TEST(ckmd5_context_size_and_offsets) {
    CHECK(sizeof(CK_MD5_CTX) == 104);
    CHECK(offsetof(CK_MD5_CTX, buf) == 8);
    CHECK(offsetof(CK_MD5_CTX, in) == 24);
    CHECK(offsetof(CK_MD5_CTX, digest) == 88);
}

TEST(ckmd5_init_sets_counters_and_state) {
    MD5_NEED();
    CK_MD5_CTX c; memset(&c, 0x5a, sizeof c);
    CKP(MD5Init)(&c);
    EXPECT_EQ(c.i[0], 0); EXPECT_EQ(c.i[1], 0);
    EXPECT_EQ(c.buf[0], 0x67452301); EXPECT_EQ(c.buf[1], 0xefcdab89);
    EXPECT_EQ(c.buf[2], 0x98badcfe); EXPECT_EQ(c.buf[3], 0x10325476);
}

TEST(ckmd5_init_leaves_input_and_digest_untouched) {
    MD5_NEED();
    CK_MD5_CTX c; memset(&c, 0xAA, sizeof c);
    CKP(MD5Init)(&c);
    for (int i = 0; i < 64; i++) CHECK(c.in[i] == 0xAA);
    for (int i = 0; i < 16; i++) CHECK(c.digest[i] == 0xAA);
}

TEST(ckmd5_rfc1321_suite) {
    MD5_NEED();
    static const struct { const char *m, *d; } v[] = {
        { "", "d41d8cd98f00b204e9800998ecf8427e" },
        { "a", "0cc175b9c0f1b6a831c399e269772661" },
        { "abc", "900150983cd24fb0d6963f7d28e17f72" },
        { "message digest", "f96b697d7cb7938d525a2f31aaf161d0" },
        { "abcdefghijklmnopqrstuvwxyz", "c3fcd3d76192e4007dfb496cca67e13b" },
        { "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "d174ab98d277d9f5a5611c2c9f419d9f" },
        { "12345678901234567890123456789012345678901234567890123456789012345678901234567890", "57edf4a22be3c955ac49da2e2107b67a" },
    };
    for (size_t i = 0; i < sizeof v / sizeof v[0]; i++) {
        CK_MD5_CTX c; md5_oneshot((const BYTE *)v[i].m, strlen(v[i].m), &c);
        CHECKF(ck_eqhex(c.digest, 16, v[i].d), "vector %zu", i);
    }
}

TEST(ckmd5_generated_kat_table) {
    MD5_NEED();
    for (size_t i = 0; i < CK_MD5_KAT_N; i++) {
        size_t n; BYTE *m = ck_hexa(ck_md5_kat[i].in, &n);
        CK_MD5_CTX c; md5_oneshot(m, n, &c);
        CHECKF(ck_eqhex(c.digest, 16, ck_md5_kat[i].out), "len %zu", n);
        free(m);
    }
}

TEST(ckmd5_million_a) {
    MD5_NEED();
    BYTE blk[1000]; memset(blk, 'a', sizeof blk);
    CK_MD5_CTX c; CKP(MD5Init)(&c);
    for (int i = 0; i < 1000; i++) CKP(MD5Update)(&c, blk, sizeof blk);
    CKP(MD5Final)(&c);
    CHECK(ck_eqhex(c.digest, 16, "7707d6ae4e027c70eea2a935c2296f21"));
}

TEST(ckmd5_every_split_point_gives_same_digest) {
    MD5_NEED();
    BYTE msg[150]; for (int i = 0; i < 150; i++) msg[i] = (BYTE)(i * 7 + 1);
    CK_MD5_CTX ref; md5_oneshot(msg, sizeof msg, &ref);
    for (int s = 0; s <= 150; s++) {
        CK_MD5_CTX c; CKP(MD5Init)(&c);
        if (s) CKP(MD5Update)(&c, msg, s);
        if (150 - s) CKP(MD5Update)(&c, msg + s, 150 - s);
        CKP(MD5Final)(&c);
        CHECKF(!memcmp(c.digest, ref.digest, 16), "split %d", s);
    }
}

TEST(ckmd5_byte_at_a_time) {
    MD5_NEED();
    BYTE msg[200]; for (int i = 0; i < 200; i++) msg[i] = (BYTE)(255 - i);
    CK_MD5_CTX ref; md5_oneshot(msg, sizeof msg, &ref);
    CK_MD5_CTX c; CKP(MD5Init)(&c);
    for (int i = 0; i < 200; i++) CKP(MD5Update)(&c, msg + i, 1);
    CKP(MD5Final)(&c);
    CHECK(!memcmp(c.digest, ref.digest, 16));
}

TEST(ckmd5_unaligned_input_buffers) {
    MD5_NEED();
    BYTE raw[512]; BYTE msg[300];
    for (int i = 0; i < 300; i++) msg[i] = (BYTE)(i * 31 + 7);
    CK_MD5_CTX ref; md5_oneshot(msg, sizeof msg, &ref);
    for (int off = 0; off < 8; off++) {
        memcpy(raw + off, msg, sizeof msg);
        CK_MD5_CTX c; md5_oneshot(raw + off, sizeof msg, &c);
        CHECKF(!memcmp(c.digest, ref.digest, 16), "offset %d", off);
    }
}

TEST(ckmd5_zero_length_update_is_noop) {
    MD5_NEED();
    CK_MD5_CTX c; CKP(MD5Init)(&c);
    CKP(MD5Update)(&c, "abc", 3);
    CK_MD5_CTX before = c;
    CKP(MD5Update)(&c, "zzz", 0);
    CHECK(!memcmp(&before, &c, sizeof c));
    CKP(MD5Final)(&c);
    CHECK(ck_eqhex(c.digest, 16, "900150983cd24fb0d6963f7d28e17f72"));
}

TEST(ckmd5_update_counts_bits) {
    MD5_NEED();
    CK_MD5_CTX c; CKP(MD5Init)(&c);
    BYTE z[100] = {0};
    CKP(MD5Update)(&c, z, 1);   EXPECT_EQ(c.i[0], 8);
    CKP(MD5Update)(&c, z, 63);  EXPECT_EQ(c.i[0], 512);
    CKP(MD5Update)(&c, z, 100); EXPECT_EQ(c.i[0], 1312);
    EXPECT_EQ(c.i[1], 0);
}

TEST(ckmd5_bit_counter_carry_into_high_word) {
    MD5_NEED();
    CK_MD5_CTX c; CKP(MD5Init)(&c);
    c.i[0] = 0xFFFFFFF8u; c.i[1] = 5;
    CKP(MD5Update)(&c, "x", 1);
    EXPECT_EQ(c.i[0], 0); EXPECT_EQ(c.i[1], 6);
}

TEST(ckmd5_bit_counter_high_bits_of_length) {
    MD5_NEED();
    /* length >> 29 is added to the high counter word: a 2^29-byte update would add 1. Use the counter directly
       with a modest update so no huge buffer is needed. */
    CK_MD5_CTX c; CKP(MD5Init)(&c);
    c.i[0] = 0x80000000u; c.i[1] = 0;        /* 2^28 bytes absorbed, buffer offset 0 */
    BYTE blk[64] = {0};
    CKP(MD5Update)(&c, blk, 64);
    EXPECT_EQ(c.i[0], 0x80000000u + 512u); EXPECT_EQ(c.i[1], 0);
    c.i[0] = 0xFFFFFE00u;
    CKP(MD5Update)(&c, blk, 64);
    EXPECT_EQ(c.i[0], 0); EXPECT_EQ(c.i[1], 1);
}

TEST(ckmd5_final_zeroes_input_block) {
    MD5_NEED(); CK_NOWINE();
    CK_MD5_CTX c; CKP(MD5Init)(&c);
    CKP(MD5Update)(&c, "abc", 3);
    CKP(MD5Final)(&c);
    for (int i = 0; i < 64; i++) CHECKF(c.in[i] == 0, "in[%d]", i);
}

TEST(ckmd5_final_padded_bit_count) {
    MD5_NEED(); CK_NOWINE();
    /* after Final the counter includes the 0x80 pad, zero fill and the 8-byte length: a multiple of 512 bits */
    static const unsigned lens[] = { 0, 1, 3, 55, 56, 57, 63, 64, 65, 100, 119, 120, 127, 128 };
    for (size_t k = 0; k < sizeof lens / sizeof lens[0]; k++) {
        unsigned L = lens[k], m = L % 64, pad = m < 56 ? 56 - m : 120 - m, total = L + pad + 8;
        BYTE buf[200] = {0};
        CK_MD5_CTX c; CKP(MD5Init)(&c);
        if (L) CKP(MD5Update)(&c, buf, L);
        CKP(MD5Final)(&c);
        CHECKF(c.i[0] == total * 8u && c.i[1] == 0 && total % 64 == 0, "len %u i0=%lu want %u", L, (unsigned long)c.i[0], total * 8);
    }
}

TEST(ckmd5_digest_equals_state_words) {
    MD5_NEED();
    CK_MD5_CTX c; md5_oneshot((const BYTE *)"abc", 3, &c);
    CHECK(!memcmp(c.digest, c.buf, 16));
}

TEST(ckmd5_reinit_after_final_restarts) {
    MD5_NEED();
    CK_MD5_CTX c; md5_oneshot((const BYTE *)"garbage", 7, &c);
    CKP(MD5Init)(&c);
    CKP(MD5Update)(&c, "abc", 3);
    CKP(MD5Final)(&c);
    CHECK(ck_eqhex(c.digest, 16, "900150983cd24fb0d6963f7d28e17f72"));
}

TEST(ckmd5_hmac_md5_rfc2202_using_md5_primitives) {
    MD5_NEED();
    BYTE k1[16]; memset(k1, 0x0b, 16);
    BYTE o[16];
    ck_hmac_md5(k1, 16, (const BYTE *)"Hi There", 8, NULL, 0, o);
    CHECK(ck_eqhex(o, 16, "9294727a3638bb1c13f48ef8158bfc9d"));
    ck_hmac_md5((const BYTE *)"Jefe", 4, (const BYTE *)"what do ya want for nothing?", 28, NULL, 0, o);
    CHECK(ck_eqhex(o, 16, "750c783e6ab0b503eaa86e310a5db738"));
    BYTE k3[16], d3[50]; memset(k3, 0xaa, 16); memset(d3, 0xdd, 50);
    ck_hmac_md5(k3, 16, d3, 50, NULL, 0, o);
    CHECK(ck_eqhex(o, 16, "56be34521d144c88dbb8c733f0e8b3f6"));
}

TEST(ckmd5_two_contexts_interleaved) {
    MD5_NEED();
    CK_MD5_CTX a, b; CKP(MD5Init)(&a); CKP(MD5Init)(&b);
    CKP(MD5Update)(&a, "ab", 2); CKP(MD5Update)(&b, "message ", 8);
    CKP(MD5Update)(&a, "c", 1);  CKP(MD5Update)(&b, "digest", 6);
    CKP(MD5Final)(&a); CKP(MD5Final)(&b);
    CHECK(ck_eqhex(a.digest, 16, "900150983cd24fb0d6963f7d28e17f72"));
    CHECK(ck_eqhex(b.digest, 16, "f96b697d7cb7938d525a2f31aaf161d0"));
}
