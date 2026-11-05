#include "sf.h"
#include "vec.h"
#define N(a) ((int)(sizeof(a) / sizeof((a)[0])))

/* SystemFunction001/002: single DES-ECB block, 7-byte key (bits spread to 8 bytes, parity ignored).
 * Argument order: (data8, key7, out8). Returns 0 or STATUS_UNSUCCESSFUL. */

static void des_kat(int fn, int decrypt)
{
    const char *m[2]; int k, i; sf_mods(fn, m);
    for (k = 0; k < 2; k++) {
        sf_block_fn f = (sf_block_fn)sf_in(m[k], fn);
        if (!f) { t_skip("missing SystemFunction%03d in %s", fn, m[k]); return; }
        for (i = 0; i < N(des_vecs); i++) {
            BYTE out[10]; memset(out, 0xEE, sizeof out);
            LONG r = f(decrypt ? des_vecs[i].ct : des_vecs[i].pt, des_vecs[i].key, out + 1);
            NTST(r, ST_SUCCESS);
            CHECK_BYTES(out + 1, decrypt ? des_vecs[i].pt : des_vecs[i].ct, 8);
            EXPECT_EQ(out[0], 0xEE); EXPECT_EQ(out[9], 0xEE);
        }
    }
}
TEST(sfrc_des_001_encrypt_kat) { des_kat(1, 0); }
TEST(sfrc_des_002_decrypt_kat) { des_kat(2, 1); }

TEST(sfrc_des_fips_classic_vector)
{
    /* DES key 133457799BBCDFF1 with parity bits stripped = 7 bytes 12 69 5b c9 b7 b7 f8 */
    static const BYTE k[7] = {0x12,0x69,0x5b,0xc9,0xb7,0xb7,0xf8};
    static const BYTE pt[8] = {0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF};
    static const BYTE ct[8] = {0x85,0xE8,0x13,0x54,0x0F,0x0A,0xB4,0x05};
    sf_block_fn e = (sf_block_fn)sf_in("cryptbase.dll", 1), d = (sf_block_fn)sf_in("cryptbase.dll", 2);
    BYTE o[8];
    REQUIRE(e); REQUIRE(d);
    NTST(e(pt, k, o), 0); CHECK_BYTES(o, ct, 8);
    NTST(d(ct, k, o), 0); CHECK_BYTES(o, pt, 8);
}
TEST(sfrc_des_weak_key_zero_vector)
{
    static const BYTE z[8] = {0}, ff[8] = {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff};
    static const BYTE c0[8] = {0x8c,0xa6,0x4d,0xe9,0xc1,0xb1,0x23,0xa7};
    static const BYTE c1[8] = {0x73,0x59,0xb2,0x16,0x3e,0x4e,0xdc,0x58};
    static const BYTE k0[7] = {0}, k1[7] = {0xff,0xff,0xff,0xff,0xff,0xff,0xff};
    sf_block_fn e = (sf_block_fn)sf_in("advapi32.dll", 1);
    BYTE o[8];
    REQUIRE(e);
    NTST(e(z, k0, o), 0); CHECK_BYTES(o, c0, 8);
    NTST(e(ff, k1, o), 0); CHECK_BYTES(o, c1, 8);
}
TEST(sfrc_des_roundtrip_all_pairs)
{
    const char *m[2]; int i, a, b; sf_mods(1, m);
    for (a = 0; a < 2; a++) for (b = 0; b < 2; b++) {
        sf_block_fn e = (sf_block_fn)sf_in(sf_impl(1), 1);
        sf_block_fn d = (sf_block_fn)sf_in(a ? "advapi32.dll" : "cryptbase.dll", 2);
        sf_block_fn e2 = (sf_block_fn)sf_in(b ? "advapi32.dll" : "cryptbase.dll", 1);
        if (!e || !d || !e2) { t_skip("missing exports"); return; }
        for (i = 0; i < N(des_vecs); i++) {
            BYTE c[8], p[8];
            NTST(e2(des_vecs[i].pt, des_vecs[i].key, c), 0);
            NTST(d(c, des_vecs[i].key, p), 0);
            CHECK_BYTES(p, des_vecs[i].pt, 8);
        }
    }
}
TEST(sfrc_des_001_null_output_fails)
{
    sf_block_fn e = (sf_block_fn)sf_in("cryptbase.dll", 1);
    static const BYTE pt[8] = {1,2,3,4,5,6,7,8}, k[7] = {1,2,3,4,5,6,7};
    REQUIRE(e);
    NTST(e(pt, k, NULL), ST_UNSUCCESSFUL);
}
TEST(sfrc_des_001_null_data_fails_and_clears_output_ends)
{
    sf_block_fn e = (sf_block_fn)sf_in("cryptbase.dll", 1);
    static const BYTE k[7] = {1,2,3,4,5,6,7};
    BYTE o[8]; memset(o, 0xAA, 8);
    REQUIRE(e);
    NTST(e(NULL, k, o), ST_UNSUCCESSFUL);
    /* The helper zeroes the first and last output byte before validating the input pointer. */
    EXPECT_EQ(o[0], 0); EXPECT_EQ(o[7], 0);
    EXPECT_EQ(o[3], 0xAA);
}
TEST(sfrc_des_002_null_output_and_data_fail)
{
    sf_block_fn d = (sf_block_fn)sf_in("cryptbase.dll", 2);
    static const BYTE ct[8] = {1,2,3,4,5,6,7,8}, k[7] = {1,2,3,4,5,6,7};
    BYTE o[8];
    REQUIRE(d);
    NTST(d(ct, k, NULL), ST_UNSUCCESSFUL);
    NTST(d(NULL, k, o), ST_UNSUCCESSFUL);
}
TEST(sfrc_des_001_in_place_note)
{
    sf_block_fn e = (sf_block_fn)sf_in("cryptbase.dll", 1);
    BYTE b[8]; memcpy(b, des_vecs[7].pt, 8);
    REQUIRE(e);
    NTST(e(b, des_vecs[7].key, b), 0);
    t_note("DES in-place (out==in) matches out-of-place: %d", !memcmp(b, des_vecs[7].ct, 8));
}
TEST(sfrc_des_every_key_bit_matters)
{
    sf_block_fn e = (sf_block_fn)sf_in("cryptbase.dll", 1);
    static const BYTE pt[8] = {0x10,0x32,0x54,0x76,0x98,0xba,0xdc,0xfe};
    BYTE k[7] = {0x0f,0x1e,0x2d,0x3c,0x4b,0x5a,0x69}, base[8], o[8];
    int bit;
    REQUIRE(e);
    NTST(e(pt, k, base), 0);
    for (bit = 0; bit < 56; bit++) {
        BYTE k2[7]; memcpy(k2, k, 7); k2[bit / 8] ^= (BYTE)(1 << (bit % 8));
        NTST(e(pt, k2, o), 0);
        CHECKF(memcmp(o, base, 8) != 0, "key bit %d did not change ciphertext", bit);
    }
}
TEST(sfrc_des_every_plaintext_bit_matters)
{
    sf_block_fn e = (sf_block_fn)sf_in("cryptbase.dll", 1);
    BYTE pt[8] = {0}, base[8], o[8], k[7] = {9,8,7,6,5,4,3};
    int bit;
    REQUIRE(e);
    NTST(e(pt, k, base), 0);
    for (bit = 0; bit < 64; bit++) {
        BYTE p2[8] = {0}; p2[bit / 8] = (BYTE)(1 << (bit % 8));
        NTST(e(p2, k, o), 0);
        CHECKF(memcmp(o, base, 8) != 0, "pt bit %d", bit);
    }
}
TEST(sfrc_des_complement_property)
{
    /* DES(~k, ~p) == ~DES(k, p): holds for any key including the 7-byte expansion. */
    sf_block_fn e = (sf_block_fn)sf_in("cryptbase.dll", 1);
    int i, j;
    REQUIRE(e);
    for (i = 0; i < N(des_vecs); i++) {
        BYTE k[7], p[8], c1[8], c2[8];
        for (j = 0; j < 7; j++) k[j] = (BYTE)~des_vecs[i].key[j];
        for (j = 0; j < 8; j++) p[j] = (BYTE)~des_vecs[i].pt[j];
        NTST(e(p, k, c2), 0);
        for (j = 0; j < 8; j++) c1[j] = (BYTE)~des_vecs[i].ct[j];
        CHECK_BYTES(c2, c1, 8);
    }
}

/* ---- SystemFunction003: DES-encrypt the constant "KGS!@#$%" with a 7-byte key ---- */
TEST(sfrc_des_003_kgs_constant)
{
    sf_des1_fn f = (sf_des1_fn)sf_in("cryptbase.dll", 3);
    int i;
    REQUIRE(f);
    for (i = 0; i < N(des_vecs); i++) {
        BYTE o[8], want[8];
        sf_block_fn e = (sf_block_fn)sf_in("cryptbase.dll", 1);
        NTST(f(des_vecs[i].key, o), 0);
        NTST(e((const BYTE *)"KGS!@#$%", des_vecs[i].key, want), 0);
        CHECK_BYTES(o, want, 8);
    }
}
TEST(sfrc_des_003_empty_key_half_of_lm_hash)
{
    sf_des1_fn f = (sf_des1_fn)sf_in("advapi32.dll", 3);
    static const BYTE z[7] = {0}, want[8] = {0xaa,0xd3,0xb4,0x35,0xb5,0x14,0x04,0xee};
    BYTE o[8];
    REQUIRE(f);
    NTST(f(z, o), 0); CHECK_BYTES(o, want, 8);
}
TEST(sfrc_des_003_null_output_fails)
{
    sf_des1_fn f = (sf_des1_fn)sf_in("cryptbase.dll", 3);
    static const BYTE z[7] = {0};
    REQUIRE(f);
    NTST(f(z, NULL), ST_UNSUCCESSFUL);
}

/* ---- SystemFunction006: LM OWF of an ANSI password ---- */
static int has_lower(const char *s) { for (; *s; s++) if (*s >= 'a' && *s <= 'z') return 1; return 0; }

static void lm_run(const char *dll)
{
    sf_lm_fn f = (sf_lm_fn)sf_in(dll, 6);
    int i;
    if (!f) { t_skip("missing 006"); return; }
    for (i = 0; i < N(lm_vecs); i++) {
        BYTE o[18]; memset(o, 0x5A, sizeof o);
        LONG r = f(lm_vecs[i].pw, o + 1);
        NTST(r, ST_SUCCESS);
        EXPECT_EQ(o[0], 0x5A); EXPECT_EQ(o[17], 0x5A);
        if (!has_lower(lm_vecs[i].pw)) CHECK_BYTES(o + 1, lm_vecs[i].lm, 16);
        else if (memcmp(o + 1, lm_vecs[i].lm, 16))
            t_note("006(\"%s\") is not the hash of the upper-cased password: no case folding in this export", lm_vecs[i].pw);
        else t_note("006(\"%s\") equals the upper-cased hash: case folded", lm_vecs[i].pw);
    }
}
TEST(sfrc_lm_006_vectors_advapi32) { lm_run("advapi32.dll"); }
TEST(sfrc_lm_006_vectors_cryptsp) { lm_run("cryptsp.dll"); }
TEST(sfrc_lm_006_empty_password)
{
    static const BYTE w[16] = {0xaa,0xd3,0xb4,0x35,0xb5,0x14,0x04,0xee,0xaa,0xd3,0xb4,0x35,0xb5,0x14,0x04,0xee};
    sf_lm_fn f = (sf_lm_fn)sf_in("cryptsp.dll", 6);
    BYTE o[16];
    REQUIRE(f);
    NTST(f("", o), 0); CHECK_BYTES(o, w, 16);
}
TEST(sfrc_lm_006_uppercase_password_known)
{
    static const BYTE w[16] = {0xe5,0x2c,0xac,0x67,0x41,0x9a,0x9a,0x22,0x4a,0x3b,0x10,0x8f,0x3f,0xa6,0xcb,0x6d};
    sf_lm_fn f = (sf_lm_fn)sf_in("cryptsp.dll", 6);
    BYTE o[16];
    REQUIRE(f);
    NTST(f("PASSWORD", o), 0); CHECK_BYTES(o, w, 16);
}
TEST(sfrc_lm_006_mixed_case_observation)
{
    static const BYTE w[16] = {0xe5,0x2c,0xac,0x67,0x41,0x9a,0x9a,0x22,0x4a,0x3b,0x10,0x8f,0x3f,0xa6,0xcb,0x6d};
    sf_lm_fn f = (sf_lm_fn)sf_in("cryptsp.dll", 6);
    BYTE o[16];
    REQUIRE(f);
    NTST(f("Password", o), 0);
    t_note("LM(\"Password\") equals LM(\"PASSWORD\"): %d (documented LM semantic upper-cases)", !memcmp(o, w, 16));
}
TEST(sfrc_lm_006_only_first_14_chars)
{
    sf_lm_fn f = (sf_lm_fn)sf_in("cryptsp.dll", 6);
    BYTE a[16], b[16];
    REQUIRE(f);
    NTST(f("ABCDEFGHIJKLMN", a), 0);
    NTST(f("ABCDEFGHIJKLMNOPQRST", b), 0);
    CHECK_BYTES(a, b, 16);
}
TEST(sfrc_lm_006_halves_independent)
{
    sf_lm_fn f = (sf_lm_fn)sf_in("cryptsp.dll", 6);
    BYTE a[16], b[16];
    REQUIRE(f);
    NTST(f("ABCDEFGXXXXXXX", a), 0);
    NTST(f("ABCDEFGYYYYYYY", b), 0);
    CHECK_BYTES(a, b, 8);
    CHECK(memcmp(a + 8, b + 8, 8) != 0);
}
TEST(sfrc_lm_006_first_half_is_003_of_first_7_chars)
{
    sf_lm_fn f = (sf_lm_fn)sf_in("cryptsp.dll", 6);
    sf_des1_fn g = (sf_des1_fn)sf_in("cryptbase.dll", 3);
    BYTE a[16], h[8];
    REQUIRE(f); REQUIRE(g);
    NTST(f("PASSWORD", a), 0);
    NTST(g((const BYTE *)"PASSWOR", h), 0);
    CHECK_BYTES(a, h, 8);
    NTST(g((const BYTE *)"D\0\0\0\0\0\0", h), 0);
    CHECK_BYTES(a + 8, h, 8);
}
TEST(sfrc_lm_006_embedded_nul_terminates)
{
    sf_lm_fn f = (sf_lm_fn)sf_in("cryptsp.dll", 6);
    BYTE a[16], b[16];
    REQUIRE(f);
    NTST(f("AB\0CD", a), 0);
    NTST(f("AB", b), 0);
    CHECK_BYTES(a, b, 16);
}
TEST(sfrc_lm_006_pair_equal) 
{
    sf_lm_fn a = (sf_lm_fn)sf_in("advapi32.dll", 6), b = (sf_lm_fn)sf_in("cryptsp.dll", 6);
    BYTE x[16], y[16];
    REQUIRE(a); REQUIRE(b);
    NTST(a("TESTING123", x), 0); NTST(b("TESTING123", y), 0);
    CHECK_BYTES(x, y, 16);
}

/* ---- SystemFunction007: NT OWF (MD4 of the UTF-16LE bytes) of a UNICODE_STRING ---- */
static void nt_run(const char *dll)
{
    sf_nt_fn f = (sf_nt_fn)sf_in(dll, 7);
    int i;
    if (!f) { t_skip("missing 007"); return; }
    for (i = 0; i < N(nt_vecs); i++) {
        UNICODE_STRING us; BYTE o[18]; memset(o, 0x5A, sizeof o);
        us.Length = (USHORT)(lstrlenW(nt_vecs[i].pw) * 2); us.MaximumLength = us.Length + 2;
        us.Buffer = (PWSTR)nt_vecs[i].pw;
        LONG r = f(&us, o + 1);
        CHECKF(r >= 0, "status 0x%lx", (unsigned long)r);
        CHECK_BYTES(o + 1, nt_vecs[i].nt, 16);
        EXPECT_EQ(o[0], 0x5A); EXPECT_EQ(o[17], 0x5A);
    }
}
TEST(sfrc_nt_007_vectors_advapi32) { nt_run("advapi32.dll"); }
TEST(sfrc_nt_007_vectors_cryptsp) { nt_run("cryptsp.dll"); }
TEST(sfrc_nt_007_password_known_answer)
{
    static const BYTE w[16] = {0xa4,0xf4,0x9c,0x40,0x65,0x10,0xbd,0xca,0xb6,0x82,0x4e,0xe7,0xc3,0x0f,0xd8,0x52};
    sf_nt_fn f = (sf_nt_fn)sf_in("cryptsp.dll", 7);
    static WCHAR pw[] = L"Password";
    UNICODE_STRING us = { 16, 18, pw };
    BYTE o[16];
    REQUIRE(f);
    CHECK(f(&us, o) >= 0); CHECK_BYTES(o, w, 16);
}
TEST(sfrc_nt_007_empty_is_md4_of_empty)
{
    static const BYTE w[16] = {0x31,0xd6,0xcf,0xe0,0xd1,0x6a,0xe9,0x31,0xb7,0x3c,0x59,0xd7,0xe0,0xc0,0x89,0xc0};
    sf_nt_fn f = (sf_nt_fn)sf_in("cryptsp.dll", 7);
    static WCHAR pw[] = L"x";
    UNICODE_STRING us = { 0, 2, pw };
    BYTE o[16];
    REQUIRE(f);
    CHECK(f(&us, o) >= 0); CHECK_BYTES(o, w, 16);
}
TEST(sfrc_nt_007_length_not_nul_governs)
{
    sf_nt_fn f = (sf_nt_fn)sf_in("cryptsp.dll", 7);
    static WCHAR pw[] = L"Pass\0word";
    UNICODE_STRING a = { 8, 18, pw }, b = { 16, 18, pw };
    static WCHAR p4[] = L"Pass";
    UNICODE_STRING c = { 8, 10, p4 };
    BYTE x[16], y[16], z[16];
    REQUIRE(f);
    CHECK(f(&a, x) >= 0); CHECK(f(&b, y) >= 0); CHECK(f(&c, z) >= 0);
    CHECK_BYTES(x, z, 16);
    CHECK(memcmp(x, y, 16) != 0);
}
TEST(sfrc_nt_007_case_sensitive)
{
    sf_nt_fn f = (sf_nt_fn)sf_in("cryptsp.dll", 7);
    static WCHAR p1[] = L"abc", p2[] = L"ABC";
    UNICODE_STRING a = { 6, 8, p1 }, b = { 6, 8, p2 };
    BYTE x[16], y[16];
    REQUIRE(f);
    CHECK(f(&a, x) >= 0); CHECK(f(&b, y) >= 0);
    CHECK(memcmp(x, y, 16) != 0);
}
TEST(sfrc_nt_007_odd_length_hashes_all_bytes_note)
{
    sf_nt_fn f = (sf_nt_fn)sf_in("cryptsp.dll", 7);
    static WCHAR p[] = L"abcd";
    UNICODE_STRING a = { 3, 8, p };
    BYTE x[16]; LONG r;
    REQUIRE(f);
    r = f(&a, x);
    t_note("007 with odd Length 3 -> status 0x%lx", (unsigned long)r);
}
TEST(sfrc_nt_007_maximum_length_ignored)
{
    sf_nt_fn f = (sf_nt_fn)sf_in("cryptsp.dll", 7);
    static WCHAR p[] = L"hello";
    UNICODE_STRING a = { 10, 10, p }, b = { 10, 12, p };
    BYTE x[16], y[16];
    REQUIRE(f);
    CHECK(f(&a, x) >= 0); CHECK(f(&b, y) >= 0);
    CHECK_BYTES(x, y, 16);
}
/* ---- SystemFunction008/009: LM/NT challenge-response (24 bytes) ---- */
static void resp_run(int fn)
{
    const char *m[2]; int k, i; sf_mods(fn, m);
    for (k = 0; k < 2; k++) {
        sf_block_fn f = (sf_block_fn)sf_in(m[k], fn);
        if (!f) { t_skip("missing %03d", fn); return; }
        for (i = 0; i < N(resp_vecs); i++) {
            BYTE o[26]; memset(o, 0x77, sizeof o);
            LONG r = f(resp_vecs[i].ch, resp_vecs[i].h, o + 1);
            NTST(r, ST_SUCCESS);
            CHECK_BYTES(o + 1, resp_vecs[i].r, 24);
            EXPECT_EQ(o[0], 0x77); EXPECT_EQ(o[25], 0x77);
        }
    }
}
TEST(sfrc_resp_008_vectors) { resp_run(8); }
TEST(sfrc_resp_009_vectors) { resp_run(9); }
TEST(sfrc_resp_008_equals_009)
{
    sf_block_fn a = (sf_block_fn)sf_in("cryptsp.dll", 8), b = (sf_block_fn)sf_in("cryptsp.dll", 9);
    int i;
    REQUIRE(a); REQUIRE(b);
    for (i = 0; i < N(resp_vecs); i++) {
        BYTE x[24], y[24];
        NTST(a(resp_vecs[i].ch, resp_vecs[i].h, x), 0);
        NTST(b(resp_vecs[i].ch, resp_vecs[i].h, y), 0);
        CHECK_BYTES(x, y, 24);
    }
}
TEST(sfrc_resp_composition_from_001)
{
    sf_block_fn f = (sf_block_fn)sf_in("cryptsp.dll", 9), e = (sf_block_fn)sf_in("cryptbase.dll", 1);
    int i;
    REQUIRE(f); REQUIRE(e);
    for (i = 0; i < N(resp_vecs); i++) {
        BYTE o[24], pad[7], t[8];
        NTST(f(resp_vecs[i].ch, resp_vecs[i].h, o), 0);
        NTST(e(resp_vecs[i].ch, resp_vecs[i].h, t), 0);            CHECK_BYTES(o, t, 8);
        NTST(e(resp_vecs[i].ch, resp_vecs[i].h + 7, t), 0);        CHECK_BYTES(o + 8, t, 8);
        memset(pad, 0, 7); pad[0] = resp_vecs[i].h[14]; pad[1] = resp_vecs[i].h[15];
        NTST(e(resp_vecs[i].ch, pad, t), 0);                       CHECK_BYTES(o + 16, t, 8);
    }
}
TEST(sfrc_resp_known_lm_response)
{
    /* challenge 0123456789abcdef, LM hash of PASSWORD */
    sf_block_fn f = (sf_block_fn)sf_in("cryptsp.dll", 8);
    sf_lm_fn lm = (sf_lm_fn)sf_in("cryptsp.dll", 6);
    static const BYTE ch[8] = {1,0x23,0x45,0x67,0x89,0xab,0xcd,0xef};
    BYTE h[16], o[24];
    REQUIRE(f); REQUIRE(lm);
    NTST(lm("PASSWORD", h), 0);
    NTST(f(ch, h, o), 0);
    CHECK_BYTES(o, resp_vecs[0].r, 24);
}
TEST(sfrc_resp_challenge_affects_all_thirds)
{
    sf_block_fn f = (sf_block_fn)sf_in("cryptsp.dll", 9);
    BYTE c1[8] = {0}, c2[8] = {0}, h[16], a[24], b[24];
    int i;
    REQUIRE(f);
    for (i = 0; i < 16; i++) h[i] = (BYTE)(i * 17 + 3);
    c2[0] = 1;
    NTST(f(c1, h, a), 0); NTST(f(c2, h, b), 0);
    CHECK(memcmp(a, b, 8) != 0); CHECK(memcmp(a + 8, b + 8, 8) != 0); CHECK(memcmp(a + 16, b + 16, 8) != 0);
}

/* ---- SystemFunction010/011: session key = MD4 of the 16-byte NT hash (first arg unused) ---- */
static void sess_run(int fn)
{
    const char *m[2]; int k, i; sf_mods(fn, m);
    for (k = 0; k < 2; k++) {
        sf_sess_fn f = (sf_sess_fn)sf_in(m[k], fn);
        if (!f) { t_skip("missing"); return; }
        for (i = 0; i < N(md4_vecs); i++) {
            BYTE o[18]; memset(o, 0x31, sizeof o);
            NTST(f(NULL, md4_vecs[i].in, o + 1), 0);
            CHECK_BYTES(o + 1, md4_vecs[i].out, 16);
            EXPECT_EQ(o[0], 0x31); EXPECT_EQ(o[17], 0x31);
            /* first argument is ignored */
            memset(o, 0, sizeof o);
            NTST(f(o + 5, md4_vecs[i].in, o), 0);
        }
    }
}
TEST(sfrc_sess_010_md4_of_hash) { sess_run(10); }
TEST(sfrc_sess_011_md4_of_hash) { sess_run(11); }
TEST(sfrc_sess_010_first_argument_ignored)
{
    sf_sess_fn f = (sf_sess_fn)sf_in("cryptsp.dll", 10);
    BYTE a[16], b[16], junk[16] = {1,2,3};
    REQUIRE(f);
    NTST(f(NULL, md4_vecs[0].in, a), 0);
    NTST(f(junk, md4_vecs[0].in, b), 0);
    CHECK_BYTES(a, b, 16);
}
