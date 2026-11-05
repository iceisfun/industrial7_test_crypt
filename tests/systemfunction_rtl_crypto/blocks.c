#include "sf.h"
#include "vec.h"
#define N(a) ((int)(sizeof(a) / sizeof((a)[0])))

/* 16-byte block helpers built on DES:
 *   012 014 020 022 : encrypt 16 bytes, 14-byte key (halves use key[0..7) and key[7..14))
 *   013 015 021 023 : the matching decrypt
 *   016 018         : encrypt 16 bytes, the same 7-byte key for both halves
 *   017 019         : decrypt counterpart of 016/018 (advapi32 only)
 *   024 026         : encrypt 16 bytes, key = 4-byte index repeated to 14 bytes
 *   025 027         : decrypt counterpart
 */
static void blk14(int fn, int decrypt)
{
    const char *m[2]; int k, i; sf_mods(fn, m);
    for (k = 0; k < 2; k++) {
        sf_block_fn f = (sf_block_fn)sf_in(m[k], fn);
        if (!f) { t_skip("missing %03d", fn); return; }
        for (i = 0; i < N(blk_vecs); i++) {
            BYTE o[18]; memset(o, 0x3C, sizeof o);
            f(decrypt ? blk_vecs[i].ct : blk_vecs[i].pt, blk_vecs[i].key, o + 1);
            CHECK_BYTES(o + 1, decrypt ? blk_vecs[i].pt : blk_vecs[i].ct, 16);
            EXPECT_EQ(o[0], 0x3C); EXPECT_EQ(o[17], 0x3C);
        }
    }
}
#define BLK14(fn, dec) TEST(sfrc_blk_##fn) { blk14(fn, dec); }
BLK14(12, 0) BLK14(14, 0) BLK14(20, 0) BLK14(22, 0)
BLK14(13, 1) BLK14(15, 1) BLK14(21, 1) BLK14(23, 1)

TEST(sfrc_blk_encrypt_aliases_agree)
{
    static const int fns[] = {12, 14, 20, 22};
    int i, j;
    for (i = 0; i < N(blk_vecs); i++) {
        BYTE ref[16]; sf_block_fn f0 = (sf_block_fn)sf_in("cryptsp.dll", 12);
        REQUIRE(f0);
        f0(blk_vecs[i].pt, blk_vecs[i].key, ref);
        for (j = 1; j < 4; j++) {
            BYTE o[16]; sf_block_fn f = (sf_block_fn)sf_in("cryptsp.dll", fns[j]);
            REQUIRE(f);
            f(blk_vecs[i].pt, blk_vecs[i].key, o);
            CHECK_BYTES(o, ref, 16);
        }
    }
}
TEST(sfrc_blk_decrypt_aliases_agree)
{
    static const int fns[] = {13, 15, 21, 23};
    int i, j;
    for (i = 0; i < N(blk_vecs); i++) {
        for (j = 0; j < 4; j++) {
            BYTE o[16]; sf_block_fn f = (sf_block_fn)sf_in("cryptsp.dll", fns[j]);
            REQUIRE(f);
            f(blk_vecs[i].ct, blk_vecs[i].key, o);
            CHECK_BYTES(o, blk_vecs[i].pt, 16);
        }
    }
}
TEST(sfrc_blk_halves_use_overlapping_key_windows)
{
    /* key byte 6 belongs to the first half only, key byte 7 to the second half only. */
    sf_block_fn f = (sf_block_fn)sf_in("cryptsp.dll", 12);
    BYTE pt[16], key[14], a[16], b[16];
    int i;
    REQUIRE(f);
    for (i = 0; i < 16; i++) pt[i] = (BYTE)(i * 11);
    for (i = 0; i < 14; i++) key[i] = (BYTE)(i * 7 + 1);
    f(pt, key, a);
    key[6] ^= 0x80; f(pt, key, b);
    CHECK(memcmp(a, b, 8) != 0); CHECK_BYTES(a + 8, b + 8, 8);
    key[6] ^= 0x80; key[7] ^= 0x80; f(pt, key, b);
    CHECK_BYTES(a, b, 8); CHECK(memcmp(a + 8, b + 8, 8) != 0);
}
TEST(sfrc_blk_ecb_equal_halves_give_equal_output_with_equal_key_windows)
{
    sf_block_fn f = (sf_block_fn)sf_in("cryptsp.dll", 12);
    BYTE pt[16], key[14], a[16];
    int i;
    REQUIRE(f);
    for (i = 0; i < 8; i++) { pt[i] = pt[8 + i] = (BYTE)(i + 40); }
    for (i = 0; i < 7; i++) key[i] = key[7 + i] = (BYTE)(i + 90);
    f(pt, key, a);
    CHECK_BYTES(a, a + 8, 8);
}
TEST(sfrc_blk_roundtrip_in_place_note)
{
    sf_block_fn e = (sf_block_fn)sf_in("cryptsp.dll", 12), d = (sf_block_fn)sf_in("cryptsp.dll", 13);
    BYTE b[16]; int i;
    REQUIRE(e); REQUIRE(d);
    memcpy(b, blk_vecs[0].pt, 16);
    e(b, blk_vecs[0].key, b);
    t_note("012 in place equals out-of-place: %d", !memcmp(b, blk_vecs[0].ct, 16));
    d(b, blk_vecs[0].key, b);
    t_note("013 in place restores plaintext: %d", !memcmp(b, blk_vecs[0].pt, 16));
    (void)i;
}

/* ---- 016/018 and 017/019 ---- */
static void blk7(int fn, int decrypt)
{
    const char *m[2]; int k, i; sf_mods(fn, m);
    for (k = 0; k < 2; k++) {
        sf_block_fn f = (sf_block_fn)sf_in(m[k], fn);
        if (!f) { t_skip("missing %03d", fn); return; }
        for (i = 0; i < N(blk7_vecs); i++) {
            BYTE o[18]; memset(o, 0x4D, sizeof o);
            f(decrypt ? blk7_vecs[i].ct : blk7_vecs[i].pt, blk7_vecs[i].key, o + 1);
            CHECK_BYTES(o + 1, decrypt ? blk7_vecs[i].pt : blk7_vecs[i].ct, 16);
            EXPECT_EQ(o[0], 0x4D); EXPECT_EQ(o[17], 0x4D);
        }
    }
}
TEST(sfrc_blk7_016) { blk7(16, 0); }
TEST(sfrc_blk7_018) { blk7(18, 0); }
TEST(sfrc_blk7_017) { blk7(17, 1); }
TEST(sfrc_blk7_019) { blk7(19, 1); }
TEST(sfrc_blk7_same_key_for_both_halves)
{
    sf_block_fn f = (sf_block_fn)sf_in("cryptsp.dll", 16), e = (sf_block_fn)sf_in("cryptbase.dll", 1);
    BYTE pt[16], key[7] = {1,2,3,4,5,6,7}, a[16], t[8];
    int i;
    REQUIRE(f); REQUIRE(e);
    for (i = 0; i < 16; i++) pt[i] = (BYTE)(255 - i);
    f(pt, key, a);
    e(pt, key, t); CHECK_BYTES(a, t, 8);
    e(pt + 8, key, t); CHECK_BYTES(a + 8, t, 8);
}
TEST(sfrc_blk7_roundtrip_016_017)
{
    sf_block_fn e = (sf_block_fn)sf_in("advapi32.dll", 16), d = (sf_block_fn)sf_in("advapi32.dll", 17);
    int i;
    REQUIRE(e); REQUIRE(d);
    for (i = 0; i < N(blk7_vecs); i++) {
        BYTE c[16], p[16];
        e(blk7_vecs[i].pt, blk7_vecs[i].key, c); d(c, blk7_vecs[i].key, p);
        CHECK_BYTES(p, blk7_vecs[i].pt, 16);
    }
}
TEST(sfrc_blk7_roundtrip_018_019)
{
    sf_block_fn e = (sf_block_fn)sf_in("advapi32.dll", 18), d = (sf_block_fn)sf_in("advapi32.dll", 19);
    int i;
    REQUIRE(e); REQUIRE(d);
    for (i = 0; i < N(blk7_vecs); i++) {
        BYTE c[16], p[16];
        e(blk7_vecs[i].pt, blk7_vecs[i].key, c); d(c, blk7_vecs[i].key, p);
        CHECK_BYTES(p, blk7_vecs[i].pt, 16);
    }
}

/* ---- 024..027: key from 4-byte index ---- */
static void idx(int fn, int decrypt)
{
    const char *m[2]; int k, i; sf_mods(fn, m);
    for (k = 0; k < 2; k++) {
        sf_block_fn f = (sf_block_fn)sf_in(m[k], fn);
        if (!f) { t_skip("missing %03d", fn); return; }
        for (i = 0; i < N(idx_vecs); i++) {
            BYTE o[18]; memset(o, 0x5E, sizeof o);
            f(decrypt ? idx_vecs[i].ct : idx_vecs[i].pt, idx_vecs[i].idx, o + 1);
            CHECK_BYTES(o + 1, decrypt ? idx_vecs[i].pt : idx_vecs[i].ct, 16);
            EXPECT_EQ(o[0], 0x5E); EXPECT_EQ(o[17], 0x5E);
        }
    }
}
TEST(sfrc_idx_024) { idx(24, 0); }
TEST(sfrc_idx_026) { idx(26, 0); }
TEST(sfrc_idx_025) { idx(25, 1); }
TEST(sfrc_idx_027) { idx(27, 1); }
TEST(sfrc_idx_equals_014_with_expanded_key)
{
    sf_block_fn a = (sf_block_fn)sf_in("cryptsp.dll", 24), b = (sf_block_fn)sf_in("cryptsp.dll", 14);
    int i, j;
    REQUIRE(a); REQUIRE(b);
    for (i = 0; i < N(idx_vecs); i++) {
        BYTE key[14], x[16], y[16];
        for (j = 0; j < 14; j++) key[j] = idx_vecs[i].idx[j % 4];
        a(idx_vecs[i].pt, idx_vecs[i].idx, x);
        b(idx_vecs[i].pt, key, y);
        CHECK_BYTES(x, y, 16);
    }
}
TEST(sfrc_idx_only_four_bytes_read)
{
    /* the index is a 4-byte value: put it at the end of a page-like buffer with guard bytes */
    sf_block_fn a = (sf_block_fn)sf_in("cryptsp.dll", 24);
    BYTE x[16], y[16]; BYTE i1[8], i2[8];
    REQUIRE(a);
    memset(i1, 0xAA, 8); memset(i2, 0x55, 8);
    memcpy(i1, idx_vecs[0].idx, 4); memcpy(i2, idx_vecs[0].idx, 4);
    a(idx_vecs[0].pt, i1, x); a(idx_vecs[0].pt, i2, y);
    CHECK_BYTES(x, y, 16);
}
TEST(sfrc_idx_roundtrip_all)
{
    static const int en[] = {24, 26}, de[] = {25, 27};
    int a, b, i;
    for (a = 0; a < 2; a++) for (b = 0; b < 2; b++) {
        sf_block_fn e = (sf_block_fn)sf_in("cryptsp.dll", en[a]), d = (sf_block_fn)sf_in("advapi32.dll", de[b]);
        REQUIRE(e); REQUIRE(d);
        for (i = 0; i < N(idx_vecs); i++) {
            BYTE c[16], p[16];
            e(idx_vecs[i].pt, idx_vecs[i].idx, c); d(c, idx_vecs[i].idx, p);
            CHECK_BYTES(p, idx_vecs[i].pt, 16);
        }
    }
}
TEST(sfrc_idx_different_index_different_cipher)
{
    sf_block_fn e = (sf_block_fn)sf_in("cryptsp.dll", 24);
    BYTE a[16], b[16], i1[4] = {1,0,0,0}, i2[4] = {2,0,0,0};
    REQUIRE(e);
    e(idx_vecs[0].pt, i1, a); e(idx_vecs[0].pt, i2, b);
    CHECK(memcmp(a, b, 16) != 0);
}

/* ---- 030/031: 16-byte constant-length compare, returns BOOLEAN ---- */
static void cmp_run(int fn)
{
    const char *m[2]; int k, i; sf_mods(fn, m);
    for (k = 0; k < 2; k++) {
        sf_cmp_fn f = (sf_cmp_fn)sf_in(m[k], fn);
        BYTE a[20], b[20];
        if (!f) { t_skip("missing %03d", fn); return; }
        for (i = 0; i < 20; i++) { a[i] = (BYTE)(i * 13 + 5); b[i] = a[i]; }
        EXPECT_EQ(f(a, b), 1);
        EXPECT_EQ(f(a, a), 1);
        for (i = 0; i < 16; i++) {
            b[i] ^= 0x01;
            EXPECT_EQ(f(a, b), 0);
            b[i] ^= 0x01;
        }
        for (i = 0; i < 16; i++) {
            b[i] ^= 0x80;
            EXPECT_EQ(f(a, b), 0);
            b[i] ^= 0x80;
        }
        /* bytes beyond the 16th are not compared */
        for (i = 16; i < 20; i++) { b[i] ^= 0xFF; EXPECT_EQ(f(a, b), 1); }
    }
}
TEST(sfrc_cmp_030) { cmp_run(30); }
TEST(sfrc_cmp_031) { cmp_run(31); }
TEST(sfrc_cmp_all_zero_and_all_ff)
{
    sf_cmp_fn f = (sf_cmp_fn)sf_in("cryptsp.dll", 30);
    BYTE z[16] = {0}, o[16];
    REQUIRE(f);
    memset(o, 0xff, 16);
    EXPECT_EQ(f(z, z), 1); EXPECT_EQ(f(o, o), 1); EXPECT_EQ(f(z, o), 0);
}
TEST(sfrc_cmp_030_matches_031_on_random_pairs)
{
    sf_cmp_fn a = (sf_cmp_fn)sf_in("cryptsp.dll", 30), b = (sf_cmp_fn)sf_in("cryptsp.dll", 31);
    int i;
    REQUIRE(a); REQUIRE(b);
    for (i = 0; i < N(md4_vecs); i++) {
        EXPECT_EQ(a(md4_vecs[i].in, md4_vecs[i].out), b(md4_vecs[i].in, md4_vecs[i].out));
        EXPECT_EQ(a(md4_vecs[i].in, md4_vecs[i].in), 1);
    }
}
