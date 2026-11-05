#include "sf.h"
#include "vec.h"
#define SKIP_WINE_RC4() do { if (t_is_wine()) { t_skip("emulator SystemFunction032/033 is a stub/unimplemented"); return; } } while (0)
#define N(a) ((int)(sizeof(a) / sizeof((a)[0])))

/* SystemFunction004 / 005: (data, key, out) with SF_USTR descriptors.
 *   004 encrypt: ValidateDataKey -> key empty/NULL gives STATUS_INVALID_PARAMETER_2;
 *        out capacity (MaximumLength) < roundup8(len + 8) gives STATUS_BUFFER_TOO_SMALL
 *        and out->Length = required size;
 *        output = DES(len,1) header block then DES blocks of the zero-padded data, the 7-byte
 *        key window slides by 7 (reflecting at the end) per block.
 *   005 decrypt: input length must be a multiple of 8 and >= 8 (STATUS_INVALID_PARAMETER_1),
 *        revision in the header must be 1 (STATUS_UNKNOWN_REVISION). */

static LONG enc4(const char *dll, const BYTE *key, ULONG klen, const BYTE *pt, ULONG plen, BYTE *out, ULONG cap, ULONG *outlen)
{
    sf_ustr3_fn f = (sf_ustr3_fn)sf_in(dll, 4);
    SF_USTR d = { plen, plen, (PVOID)pt }, k = { klen, klen, (PVOID)key }, o = { 0, cap, out };
    LONG r;
    static BYTE dummy[1];
    if (!d.Buffer) d.Buffer = dummy;
    r = f(&d, &k, &o);
    if (outlen) *outlen = o.Length;
    return r;
}
static LONG dec5(const char *dll, const BYTE *key, ULONG klen, const BYTE *ct, ULONG clen, BYTE *out, ULONG cap, ULONG *outlen)
{
    sf_ustr3_fn f = (sf_ustr3_fn)sf_in(dll, 5);
    SF_USTR d = { clen, clen, (PVOID)ct }, k = { klen, klen, (PVOID)key }, o = { 0, cap, out };
    LONG r = f(&d, &k, &o);
    if (outlen) *outlen = o.Length;
    return r;
}

static void enc4_kat(const char *dll)
{
    int i;
    if (!sf_in(dll, 4)) { t_skip("missing 004"); return; }
    for (i = 0; i < N(enc4_vecs); i++) {
        const enc4_vec_t *v = &enc4_vecs[i];
        BYTE out[400]; ULONG ol = 0; LONG r;
        if (t_is_wine() && v->plen == 0) continue;   /* emulator underflows on empty data */
        memset(out, 0xCD, sizeof out);
        r = enc4(dll, v->key, v->klen, v->pt, v->plen, out, v->clen, &ol);
        CHECKF(r == 0, "vec %d status 0x%lx", i, (unsigned long)r);
        EXPECT_EQ(ol, v->clen);
        CHECK_BYTES(out, v->ct, v->clen);
        EXPECT_EQ(out[v->clen], 0xCD);
    }
}
TEST(sfrc_data_004_kat_advapi32) { enc4_kat("advapi32.dll"); }
TEST(sfrc_data_004_kat_cryptbase) { enc4_kat("cryptbase.dll"); }

static void dec5_kat(const char *dll)
{
    int i;
    if (!sf_in(dll, 5)) { t_skip("missing 005"); return; }
    for (i = 0; i < N(enc4_vecs); i++) {
        const enc4_vec_t *v = &enc4_vecs[i];
        BYTE out[400]; ULONG ol = 0; LONG r;
        memset(out, 0xCD, sizeof out);
        r = dec5(dll, v->key, v->klen, v->ct, v->clen, out, 400, &ol);
        CHECKF(r == 0, "vec %d status 0x%lx", i, (unsigned long)r);
        EXPECT_EQ(ol, v->plen);
        CHECK_BYTES(out, v->pt, v->plen);
        EXPECT_EQ(out[v->plen], 0xCD);
    }
}
TEST(sfrc_data_005_kat_advapi32) { dec5_kat("advapi32.dll"); }
TEST(sfrc_data_005_kat_cryptbase) { dec5_kat("cryptbase.dll"); }

TEST(sfrc_data_004_required_size_formula)
{
    static const BYTE key[3] = {1,2,3};
    ULONG len, ol; BYTE out[8], in[1] = {0};
    if (!sf_in("cryptbase.dll", 4)) { t_skip("missing"); return; }
    for (len = 0; len < 40; len++) {
        if (t_is_wine() && len == 0) continue;
        ULONG want = ((len + 8) + 7) & ~7u;
        BYTE *buf = (BYTE *)malloc(len ? len : 1);
        memset(buf, 0x11, len ? len : 1);
        ol = 0;
        LONG r = enc4("cryptbase.dll", key, 3, buf, len, out, 0, &ol);
        NTST(r, ST_BUF_TOO_SMALL);
        EXPECT_EQ(ol, want);
        free(buf);
    }
    (void)in;
}
TEST(sfrc_data_004_exact_capacity_boundary)
{
    static const BYTE key[3] = {9,8,7};
    BYTE pt[13] = {1,2,3,4,5,6,7,8,9,10,11,12,13}, out[40]; ULONG ol;
    if (!sf_in("cryptbase.dll", 4)) { t_skip("missing"); return; }
    memset(out, 0x99, sizeof out);
    NTST(enc4("cryptbase.dll", key, 3, pt, 13, out, 23, &ol), ST_BUF_TOO_SMALL); EXPECT_EQ(ol, 24);
    EXPECT_EQ(out[0], 0x99);  /* nothing written on failure */
    NTST(enc4("cryptbase.dll", key, 3, pt, 13, out, 24, &ol), 0); EXPECT_EQ(ol, 24);
    EXPECT_EQ(out[24], 0x99);
    NTST(enc4("cryptbase.dll", key, 3, pt, 13, out, 40, &ol), 0); EXPECT_EQ(ol, 24);
}
TEST(sfrc_data_004_empty_key_is_param2)
{
    BYTE pt[8] = {1}, out[64]; ULONG ol;
    SF_USTR d = { 8, 8, pt }, k, o = { 0, 64, out };
    sf_ustr3_fn f = (sf_ustr3_fn)sf_in("cryptbase.dll", 4);
    REQUIRE(f);
    k.Length = 0; k.MaximumLength = 4; k.Buffer = pt;
    NTST(f(&d, &k, &o), ST_INVALID_PARAM2);
    if (t_is_wine()) { t_skip("emulator dereferences a NULL key buffer"); return; }
    k.Length = 4; k.MaximumLength = 4; k.Buffer = NULL;
    NTST(f(&d, &k, &o), ST_INVALID_PARAM2);
    k.Length = 0; k.Buffer = NULL;
    NTST(f(&d, &k, &o), ST_INVALID_PARAM2);
    (void)ol;
}
TEST(sfrc_data_004_key_checked_before_size)
{
    BYTE pt[8] = {1}, out[1]; 
    SF_USTR d = { 8, 8, pt }, k = { 0, 0, NULL }, o = { 0, 0, out };
    sf_ustr3_fn f = (sf_ustr3_fn)sf_in("cryptbase.dll", 4);
    REQUIRE(f);
    NTST(f(&d, &k, &o), ST_INVALID_PARAM2);
    EXPECT_EQ(o.Length, 0);
}
TEST(sfrc_data_005_empty_key_is_param2)
{
    BYTE ct[16] = {1}, out[64];
    SF_USTR d = { 16, 16, ct }, k = { 0, 0, NULL }, o = { 0, 64, out };
    sf_ustr3_fn f = (sf_ustr3_fn)sf_in("cryptbase.dll", 5);
    REQUIRE(f);
    NTST(f(&d, &k, &o), ST_INVALID_PARAM2);
}
TEST(sfrc_data_005_bad_input_lengths_are_param1)
{
    static const BYTE key[4] = {1,2,3,4};
    static const ULONG lens[] = {0, 1, 4, 7, 9, 12, 15, 17, 23};
    BYTE ct[32], out[64]; int i;
    if (!sf_in("cryptbase.dll", 5)) { t_skip("missing"); return; }
    memset(ct, 0x42, sizeof ct);
    for (i = 0; i < N(lens); i++) {
        ULONG ol;
        NTST(dec5("cryptbase.dll", key, 4, ct, lens[i], out, 64, &ol), ST_INVALID_PARAM1);
    }
}
TEST(sfrc_data_005_wrong_key_unknown_revision)
{
    const enc4_vec_t *v = &enc4_vecs[5];
    static const BYTE wrong[7] = {'1','2','3','4','5','6','8'};
    BYTE out[200]; ULONG ol;
    if (!sf_in("cryptbase.dll", 5)) { t_skip("missing"); return; }
    NTST(dec5("cryptbase.dll", wrong, 7, v->ct, v->clen, out, 200, &ol), ST_UNKNOWN_REV);
}
TEST(sfrc_data_005_small_output_reports_plain_length)
{
    const enc4_vec_t *v = &enc4_vecs[5];   /* 16 bytes */
    BYTE out[32]; ULONG ol = 0;
    if (!sf_in("cryptbase.dll", 5)) { t_skip("missing"); return; }
    memset(out, 0x66, sizeof out);
    NTST(dec5("cryptbase.dll", v->key, v->klen, v->ct, v->clen, out, 15, &ol), ST_BUF_TOO_SMALL);
    EXPECT_EQ(ol, v->plen);
    EXPECT_EQ(out[0], 0x66);
    NTST(dec5("cryptbase.dll", v->key, v->klen, v->ct, v->clen, out, 16, &ol), 0);
    EXPECT_EQ(ol, v->plen);
    CHECK_BYTES(out, v->pt, v->plen);
}
TEST(sfrc_data_005_truncated_ciphertext_rejected)
{
    /* header says 70 bytes but only 16 bytes of ciphertext follow */
    const enc4_vec_t *v = &enc4_vecs[14];
    BYTE out[200]; ULONG ol;
    if (!sf_in("cryptbase.dll", 5)) { t_skip("missing"); return; }
    NTST(dec5("cryptbase.dll", v->key, v->klen, v->ct, 16, out, 200, &ol), ST_INVALID_PARAM1);
}
TEST(sfrc_data_005_header_only_zero_length)
{
    const enc4_vec_t *v = &enc4_vecs[0];  /* key KEY, 0 bytes */
    BYTE out[8]; ULONG ol = 99;
    if (!sf_in("cryptbase.dll", 5)) { t_skip("missing"); return; }
    CHECK(v->plen == 0 && v->clen == 8);
    NTST(dec5("cryptbase.dll", v->key, v->klen, v->ct, v->clen, out, 8, &ol), 0);
    EXPECT_EQ(ol, 0);
}
TEST(sfrc_data_short_key_is_cyclically_extended)
{
    /* keys shorter than 7 bytes act as their cyclic extension to 7 bytes */
    static const BYTE k2[2] = {'A','B'}, k7[7] = {'A','B','A','B','A','B','A'};
    BYTE pt[20], a[40], b[40]; ULONG la, lb; int i;
    if (!sf_in("cryptbase.dll", 4)) { t_skip("missing"); return; }
    for (i = 0; i < 20; i++) pt[i] = (BYTE)(i * 5);
    NTST(enc4("cryptbase.dll", k2, 2, pt, 20, a, 40, &la), 0);
    NTST(enc4("cryptbase.dll", k7, 7, pt, 20, b, 40, &lb), 0);
    EXPECT_EQ(la, lb); CHECK_BYTES(a, b, la);
}
TEST(sfrc_data_key_bytes_beyond_window_matter_only_when_longer_than_7)
{
    static const BYTE k8a[8] = {1,2,3,4,5,6,7,8}, k8b[8] = {1,2,3,4,5,6,7,9};
    BYTE pt[8] = {0}, a[40], b[40]; ULONG la, lb;
    if (!sf_in("cryptbase.dll", 4)) { t_skip("missing"); return; }
    NTST(enc4("cryptbase.dll", k8a, 8, pt, 8, a, 40, &la), 0);
    NTST(enc4("cryptbase.dll", k8b, 8, pt, 8, b, 40, &lb), 0);
    /* header block uses key[0..7) and is identical; the data block uses the reflected window */
    CHECK_BYTES(a, b, 8);
    CHECK(memcmp(a + 8, b + 8, 8) != 0);
}
TEST(sfrc_data_roundtrip_lengths_and_keys)
{
    BYTE pt[120], ct[160], rt[160]; int kl, len;
    BYTE key[40];
    if (!sf_in("cryptbase.dll", 4) || !sf_in("cryptbase.dll", 5)) { t_skip("missing"); return; }
    for (kl = 0; kl < 40; kl++) key[kl] = (BYTE)(kl * 29 + 3);
    for (kl = 1; kl <= 40; kl += 3) {
        for (len = 0; len <= 100; len += 7) {
            ULONG lc = 0, lr = 0; int i;
            if (t_is_wine() && len == 0) continue;   /* emulator underflows on empty data */
            for (i = 0; i < len; i++) pt[i] = (BYTE)(i * 3 + kl);
            LONG r = enc4("advapi32.dll", key, kl, pt, len, ct, 160, &lc);
            NTST(r, 0);
            EXPECT_EQ(lc, ((len + 8) + 7) & ~7u);
            r = dec5("cryptbase.dll", key, kl, ct, lc, rt, 160, &lr);
            NTST(r, 0);
            EXPECT_EQ(lr, len);
            CHECK_BYTES(rt, pt, len);
        }
    }
}
TEST(sfrc_data_roundtrip_large)
{
    BYTE *pt = (BYTE *)malloc(65536), *ct = (BYTE *)malloc(65600), *rt = (BYTE *)malloc(65600);
    static const BYTE key[11] = {1,1,2,3,5,8,13,21,34,55,89};
    ULONG lc = 0, lr = 0; int i;
    if (!sf_in("cryptbase.dll", 4)) { t_skip("missing"); free(pt); free(ct); free(rt); return; }
    for (i = 0; i < 65536; i++) pt[i] = (BYTE)(i ^ (i >> 8));
    NTST(enc4("cryptbase.dll", key, 11, pt, 65536, ct, 65600, &lc), 0);
    EXPECT_EQ(lc, 65544);
    NTST(dec5("cryptbase.dll", key, 11, ct, lc, rt, 65600, &lr), 0);
    EXPECT_EQ(lr, 65536);
    CHECK(!memcmp(pt, rt, 65536));
    free(pt); free(ct); free(rt);
}
TEST(sfrc_data_004_does_not_modify_inputs)
{
    BYTE pt[13], pt0[13], key[9] = {1,2,3,4,5,6,7,8,9}, key0[9], out[64]; ULONG ol; int i;
    if (!sf_in("cryptbase.dll", 4)) { t_skip("missing"); return; }
    for (i = 0; i < 13; i++) pt[i] = pt0[i] = (BYTE)(i + 100);
    memcpy(key0, key, 9);
    NTST(enc4("cryptbase.dll", key, 9, pt, 13, out, 64, &ol), 0);
    CHECK_BYTES(pt, pt0, 13); CHECK_BYTES(key, key0, 9);
}
TEST(sfrc_data_005_does_not_modify_input)
{
    const enc4_vec_t *v = &enc4_vecs[10];
    BYTE ct[200], out[200]; ULONG ol;
    if (!sf_in("cryptbase.dll", 5)) { t_skip("missing"); return; }
    memcpy(ct, v->ct, v->clen);
    NTST(dec5("cryptbase.dll", v->key, v->klen, ct, v->clen, out, 200, &ol), 0);
    CHECK_BYTES(ct, v->ct, v->clen);
}
TEST(sfrc_data_005_ciphertext_bit_flip_in_data_block)
{
    const enc4_vec_t *v = &enc4_vecs[10];  /* 40 bytes data, 8-byte key */
    BYTE ct[200], out[200]; ULONG ol;
    if (!sf_in("cryptbase.dll", 5)) { t_skip("missing"); return; }
    memcpy(ct, v->ct, v->clen);
    ct[8 + 3] ^= 0x01;   /* inside the first data block: only that 8-byte plaintext block is garbled */
    NTST(dec5("cryptbase.dll", v->key, v->klen, ct, v->clen, out, 200, &ol), 0);
    CHECK(memcmp(out, v->pt, 8) != 0);
    CHECK_BYTES(out + 8, v->pt + 8, v->plen - 8);
}

/* ---- SystemFunction032 / 033: RC4 in place, (data USTR, key USTR) ---- */
static void rc4_run(const char *dll, int fn)
{
    sf_ustr2_fn f = (sf_ustr2_fn)sf_in(dll, fn);
    int i;
    SKIP_WINE_RC4();
    if (!f) { t_skip("missing"); return; }
    for (i = 0; i < N(rc4_vecs); i++) {
        const rc4_vec_t *v = &rc4_vecs[i];
        BYTE buf[1100]; SF_USTR d, k;
        memset(buf, 0xAB, sizeof buf);
        memcpy(buf + 1, v->pt, v->plen);
        d.Length = d.MaximumLength = v->plen; d.Buffer = buf + 1;
        k.Length = k.MaximumLength = v->klen; k.Buffer = (PVOID)v->key;
        NTST(f(&d, &k), 0);
        CHECK_BYTES(buf + 1, v->ct, v->plen);
        EXPECT_EQ(buf[0], 0xAB); EXPECT_EQ(buf[1 + v->plen], 0xAB);
        EXPECT_EQ(d.Length, v->plen);
        /* RC4 is its own inverse */
        k.Length = v->klen;
        NTST(f(&d, &k), 0);
        CHECK_BYTES(buf + 1, v->pt, v->plen);
    }
}
TEST(sfrc_rc4_032_vectors_advapi32) { rc4_run("advapi32.dll", 32); }
TEST(sfrc_rc4_032_vectors_cryptsp) { rc4_run("cryptsp.dll", 32); }
TEST(sfrc_rc4_033_vectors_advapi32) { rc4_run("advapi32.dll", 33); }
TEST(sfrc_rc4_033_vectors_cryptsp) { rc4_run("cryptsp.dll", 33); }
TEST(sfrc_rc4_published_key_plaintext_vector)
{
    SKIP_WINE_RC4();
    static const BYTE exp[9] = {0xBB,0xF3,0x16,0xE8,0xD9,0x40,0xAF,0x0A,0xD3};
    sf_ustr2_fn f = (sf_ustr2_fn)sf_in("advapi32.dll", 32);
    BYTE d[9]; BYTE k[3] = {'K','e','y'};
    SF_USTR du = { 9, 9, d }, ku = { 3, 3, k };
    REQUIRE(f);
    memcpy(d, "Plaintext", 9);
    NTST(f(&du, &ku), 0);
    CHECK_BYTES(d, exp, 9);
}
TEST(sfrc_rc4_zero_length_data_is_noop_success)
{
    SKIP_WINE_RC4();
    sf_ustr2_fn f = (sf_ustr2_fn)sf_in("cryptsp.dll", 32);
    BYTE d[4] = {1,2,3,4}, k[3] = {1,2,3};
    SF_USTR du = { 0, 4, d }, ku = { 3, 3, k };
    REQUIRE(f);
    NTST(f(&du, &ku), 0);
    CHECK(d[0] == 1 && d[3] == 4);
}
TEST(sfrc_rc4_maximum_length_ignored)
{
    SKIP_WINE_RC4();
    sf_ustr2_fn f = (sf_ustr2_fn)sf_in("cryptsp.dll", 32);
    BYTE d1[5] = {1,2,3,4,5}, d2[5] = {1,2,3,4,5}, k[3] = {7,8,9};
    SF_USTR a = { 5, 5, d1 }, b = { 5, 100, d2 }, ku = { 3, 3, k }, kv = { 3, 0, k };
    REQUIRE(f);
    NTST(f(&a, &ku), 0); NTST(f(&b, &kv), 0);
    CHECK_BYTES(d1, d2, 5);
}
TEST(sfrc_rc4_partial_length_only_touches_prefix)
{
    SKIP_WINE_RC4();
    sf_ustr2_fn f = (sf_ustr2_fn)sf_in("cryptsp.dll", 32);
    BYTE d[16], ref[16], k[4] = {4,3,2,1};
    SF_USTR du = { 10, 16, d }, ku = { 4, 4, k }, all = { 16, 16, ref };
    int i;
    REQUIRE(f);
    for (i = 0; i < 16; i++) d[i] = ref[i] = (BYTE)(i + 1);
    NTST(f(&du, &ku), 0); NTST(f(&all, &ku), 0);
    CHECK_BYTES(d, ref, 10);
    for (i = 10; i < 16; i++) EXPECT_EQ(d[i], i + 1);
}
TEST(sfrc_rc4_keystream_restarts_each_call)
{
    SKIP_WINE_RC4();
    sf_ustr2_fn f = (sf_ustr2_fn)sf_in("cryptsp.dll", 32);
    BYTE d[32] = {0}, k[5] = {1,2,3,4,5};
    SF_USTR h1 = { 16, 16, d }, h2 = { 16, 16, d + 16 }, ku = { 5, 5, k };
    REQUIRE(f);
    NTST(f(&h1, &ku), 0); NTST(f(&h2, &ku), 0);
    CHECK_BYTES(d, d + 16, 16);
}
TEST(sfrc_rc4_keystream_prefix_property)
{
    SKIP_WINE_RC4();
    sf_ustr2_fn f = (sf_ustr2_fn)sf_in("cryptsp.dll", 32);
    BYTE a[64] = {0}, b[20] = {0}, k[9] = {9,8,7,6,5,4,3,2,1};
    SF_USTR ua = { 64, 64, a }, ub = { 20, 20, b }, ku = { 9, 9, k };
    REQUIRE(f);
    NTST(f(&ua, &ku), 0); NTST(f(&ub, &ku), 0);
    CHECK_BYTES(a, b, 20);
}
TEST(sfrc_rc4_key_length_matters)
{
    SKIP_WINE_RC4();
    sf_ustr2_fn f = (sf_ustr2_fn)sf_in("cryptsp.dll", 32);
    BYTE a[16] = {0}, b[16] = {0}, k[8] = {1,2,3,4,5,6,7,8};
    SF_USTR ua = { 16, 16, a }, ub = { 16, 16, b }, k7 = { 7, 7, k }, k8 = { 8, 8, k };
    REQUIRE(f);
    NTST(f(&ua, &k7), 0); NTST(f(&ub, &k8), 0);
    CHECK(memcmp(a, b, 16) != 0);
}
TEST(sfrc_rc4_032_equals_033)
{
    SKIP_WINE_RC4();
    sf_ustr2_fn a = (sf_ustr2_fn)sf_in("cryptsp.dll", 32), b = (sf_ustr2_fn)sf_in("cryptsp.dll", 33);
    int i;
    REQUIRE(a); REQUIRE(b);
    for (i = 0; i < N(rc4_vecs); i++) {
        const rc4_vec_t *v = &rc4_vecs[i];
        BYTE x[1100], y[1100]; SF_USTR dx = { v->plen, v->plen, x }, dy = { v->plen, v->plen, y };
        SF_USTR k = { v->klen, v->klen, (PVOID)v->key };
        memcpy(x, v->pt, v->plen); memcpy(y, v->pt, v->plen);
        NTST(a(&dx, &k), 0); NTST(b(&dy, &k), 0);
        CHECK_BYTES(x, y, v->plen);
    }
}
TEST(sfrc_rc4_binary_key_with_embedded_zeros)
{
    SKIP_WINE_RC4();
    sf_ustr2_fn f = (sf_ustr2_fn)sf_in("cryptsp.dll", 32);
    static const BYTE exp[16] = {0xb2,0x39,0x63,0x05,0xf0,0x3d,0xc0,0x27,0xcc,0xc3,0x52,0x4a,0x0a,0x11,0x18,0xa8};
    BYTE d[16] = {0}, k[5] = {1,2,3,4,5};
    SF_USTR du = { 16, 16, d }, ku = { 5, 5, k };
    REQUIRE(f);
    NTST(f(&du, &ku), 0);
    CHECK_BYTES(d, exp, 16);   /* RFC 6229 40-bit key 0102030405 keystream offset 0 */
}
