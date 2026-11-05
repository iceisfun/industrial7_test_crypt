/* Known-answer hashing through CryptCreateHash/CryptHashData/CryptGetHashParam. */
#include "h.h"
#include "vectors.h"

static BYTE g_big[1000];

/* hash every vector row for one algorithm, one-shot, and compare */
static void kat_rows(HCRYPTPROV p, ALG_ID alg, const char *const *digs) {
    size_t i;
    for (i = 0; i < HV_NMSGS; i++) {
        BYTE m[1100], d[64]; DWORD dl = sizeof d; int ml = h_hex2bin(hv_msgs[i].hex, m, sizeof m);
        char what[64];
        SET_ERR(0);
        BOOL ok = h_hash(p, alg, m, (DWORD)ml, d, &dl);
        CHECKF(ok, "hash of %s failed err 0x%lx", hv_msgs[i].name, GetLastError());
        if (!ok) continue;
        CHECKF(dl == h_digest_len(alg), "len %lu for %s", dl, hv_msgs[i].name);
        BYTE e[64]; int el = h_hex2bin(digs[i], e, sizeof e);
        CHECKF(el == (int)dl && !memcmp(d, e, dl), "digest mismatch for %s", hv_msgs[i].name);
    }
}
/* hash incrementally (chunk bytes at a time) and compare */
static void kat_chunked(HCRYPTPROV p, ALG_ID alg, const char *const *digs, DWORD chunk) {
    size_t i;
    for (i = 0; i < HV_NMSGS; i++) {
        BYTE m[1100], d[64]; DWORD dl = sizeof d, off; int ml = h_hex2bin(hv_msgs[i].hex, m, sizeof m);
        HCRYPTHASH h = 0;
        if (!U(CryptCreateHash)(p, alg, 0, 0, &h)) { CHECK(0); return; }
        for (off = 0; off < (DWORD)ml; off += chunk) {
            DWORD n = (DWORD)ml - off < chunk ? (DWORD)ml - off : chunk;
            CHECK(U(CryptHashData)(h, m + off, n, 0));
        }
        CHECK(U(CryptGetHashParam)(h, HP_HASHVAL, d, &dl, 0));
        BYTE e[64]; int el = h_hex2bin(digs[i], e, sizeof e);
        CHECKF(el == (int)dl && !memcmp(d, e, dl), "chunk %lu digest mismatch for %s", chunk, hv_msgs[i].name);
        U(CryptDestroyHash)(h);
    }
}
static void kat_million(HCRYPTPROV p, ALG_ID alg, const char *hex) {
    HCRYPTHASH h = 0; BYTE d[64]; DWORD dl = sizeof d; int i;
    memset(g_big, 'a', sizeof g_big);
    if (!U(CryptCreateHash)(p, alg, 0, 0, &h)) { CHECK(0); return; }
    for (i = 0; i < 1000; i++) CHECK(U(CryptHashData)(h, g_big, sizeof g_big, 0));
    CHECK(U(CryptGetHashParam)(h, HP_HASHVAL, d, &dl, 0));
    BYTE e[64]; int el = h_hex2bin(hex, e, sizeof e);
    CHECK(el == (int)dl && !memcmp(d, e, dl));
    U(CryptDestroyHash)(h);
}

#define KAT_TESTS(NAME, ALG)                                                        \
TEST(capi_hash_kat_##NAME) {                                                         \
    REQUIRE(U(CryptCreateHash)); REQUIRE(U(CryptHashData)); REQUIRE(U(CryptGetHashParam)); \
    HCRYPTPROV p = h_acq_aes(); if (!p) return; kat_rows(p, ALG, hv_dig_##NAME); h_rel(p); } \
TEST(capi_hash_kat_chunk1_##NAME) {                                                  \
    REQUIRE(U(CryptCreateHash));                                                    \
    HCRYPTPROV p = h_acq_aes(); if (!p) return; kat_chunked(p, ALG, hv_dig_##NAME, 1); h_rel(p); } \
TEST(capi_hash_kat_chunk7_##NAME) {                                                  \
    REQUIRE(U(CryptCreateHash));                                                    \
    HCRYPTPROV p = h_acq_aes(); if (!p) return; kat_chunked(p, ALG, hv_dig_##NAME, 7); h_rel(p); } \
TEST(capi_hash_kat_chunk64_##NAME) {                                                 \
    REQUIRE(U(CryptCreateHash));                                                    \
    HCRYPTPROV p = h_acq_aes(); if (!p) return; kat_chunked(p, ALG, hv_dig_##NAME, 64); h_rel(p); } \
TEST(capi_hash_kat_million_a_##NAME) {                                               \
    REQUIRE(U(CryptCreateHash));                                                    \
    HCRYPTPROV p = h_acq_aes(); if (!p) return; kat_million(p, ALG, hv_million_##NAME); h_rel(p); }

KAT_TESTS(MD2, CALG_MD2)
KAT_TESTS(MD4, CALG_MD4)
KAT_TESTS(MD5, CALG_MD5)
KAT_TESTS(SHA1, CALG_SHA1)
KAT_TESTS(SHA256, CALG_SHA_256)
KAT_TESTS(SHA384, CALG_SHA_384)
KAT_TESTS(SHA512, CALG_SHA_512)

/* the same legacy algorithms on the Base and Enhanced RSA providers */
#define LEGACY_PROV_TEST(NAME, ALG, PT, PN, TAG) \
TEST(capi_hash_kat_##NAME##_##TAG) { REQUIRE(U(CryptCreateHash)); \
    HCRYPTPROV p = h_acq(PT, PN); if (!p) return; kat_rows(p, ALG, hv_dig_##NAME); h_rel(p); }
LEGACY_PROV_TEST(MD2, CALG_MD2, PROV_RSA_FULL, PROVNAME_BASE, base)
LEGACY_PROV_TEST(MD4, CALG_MD4, PROV_RSA_FULL, PROVNAME_BASE, base)
LEGACY_PROV_TEST(MD5, CALG_MD5, PROV_RSA_FULL, PROVNAME_BASE, base)
LEGACY_PROV_TEST(SHA1, CALG_SHA1, PROV_RSA_FULL, PROVNAME_BASE, base)
LEGACY_PROV_TEST(MD2, CALG_MD2, PROV_RSA_FULL, PROVNAME_ENH, enh)
LEGACY_PROV_TEST(MD4, CALG_MD4, PROV_RSA_FULL, PROVNAME_ENH, enh)
LEGACY_PROV_TEST(MD5, CALG_MD5, PROV_RSA_FULL, PROVNAME_ENH, enh)
LEGACY_PROV_TEST(SHA1, CALG_SHA1, PROV_RSA_FULL, PROVNAME_ENH, enh)

/* CRYPT_USERDATA (1) is accepted by CPHashData and does not change the digest */
TEST(capi_hash_userdata_flag_same_digest) {
    REQUIRE(U(CryptCreateHash));
    HCRYPTPROV p = h_acq_aes(); if (!p) return;
    HCRYPTHASH h = 0; BYTE d[20]; DWORD dl = 20;
    CHECK(U(CryptCreateHash)(p, CALG_SHA1, 0, 0, &h));
    CHECK(U(CryptHashData)(h, (const BYTE *)"abc", 3, CRYPT_USERDATA));
    CHECK(U(CryptGetHashParam)(h, HP_HASHVAL, d, &dl, 0));
    EXPECT_HEX(d, 20, "a9993e364706816aba3e25717850c26c9cd0d89d");
    U(CryptDestroyHash)(h); h_rel(p);
}

/* one-shot 1,000,000 byte buffer (single CryptHashData call) */
TEST(capi_hash_single_call_1mb_sha1) {
    REQUIRE(U(CryptCreateHash));
    HCRYPTPROV p = h_acq_aes(); if (!p) return;
    BYTE *buf = (BYTE *)malloc(1000000); BYTE d[20]; DWORD dl = 20;
    if (!buf) { h_rel(p); return; }
    memset(buf, 'a', 1000000);
    CHECK(h_hash(p, CALG_SHA1, buf, 1000000, d, &dl));
    EXPECT_HEX(d, 20, "34aa973cd4c4daa4f61eeb2bdbad27316534016f");
    free(buf); h_rel(p);
}
TEST(capi_hash_single_call_1mb_md5) {
    REQUIRE(U(CryptCreateHash));
    HCRYPTPROV p = h_acq_aes(); if (!p) return;
    BYTE *buf = (BYTE *)malloc(1000000); BYTE d[16]; DWORD dl = 16;
    if (!buf) { h_rel(p); return; }
    memset(buf, 'a', 1000000);
    CHECK(h_hash(p, CALG_MD5, buf, 1000000, d, &dl));
    EXPECT_HEX(d, 16, "7707d6ae4e027c70eea2a935c2296f21");
    free(buf); h_rel(p);
}

/* a fresh hash with no data hashed yields the empty-message digest */
TEST(capi_hash_empty_getval_equals_empty_digest) {
    REQUIRE(U(CryptCreateHash));
    HCRYPTPROV p = h_acq_aes(); if (!p) return;
    HCRYPTHASH h = 0; BYTE d[32]; DWORD dl = 32;
    CHECK(U(CryptCreateHash)(p, CALG_SHA_256, 0, 0, &h));
    CHECK(U(CryptGetHashParam)(h, HP_HASHVAL, d, &dl, 0));
    CHECK(dl == 32);
    EXPECT_HEX(d, 32, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    U(CryptDestroyHash)(h); h_rel(p);
}
/* CryptHashData with length 0 is a successful no-op (a NULL pointer is then accepted) */
TEST(capi_hash_zero_length_hashdata_noop) {
    REQUIRE(U(CryptCreateHash));
    HCRYPTPROV p = h_acq_aes(); if (!p) return;
    HCRYPTHASH h = 0; BYTE d[16]; DWORD dl = 16;
    CHECK(U(CryptCreateHash)(p, CALG_MD5, 0, 0, &h));
    CHECK(U(CryptHashData)(h, NULL, 0, 0));
    CHECK(U(CryptHashData)(h, (const BYTE *)"abc", 0, 0));
    CHECK(U(CryptHashData)(h, (const BYTE *)"abc", 3, 0));
    CHECK(U(CryptHashData)(h, NULL, 0, 0));
    CHECK(U(CryptGetHashParam)(h, HP_HASHVAL, d, &dl, 0));
    EXPECT_HEX(d, 16, "900150983cd24fb0d6963f7d28e17f72");
    U(CryptDestroyHash)(h); h_rel(p);
}
/* two independent hash objects on one provider do not interfere */
TEST(capi_hash_interleaved_objects_independent) {
    REQUIRE(U(CryptCreateHash));
    HCRYPTPROV p = h_acq_aes(); if (!p) return;
    HCRYPTHASH a = 0, b = 0; BYTE da[20], db[16]; DWORD la = 20, lb = 16;
    CHECK(U(CryptCreateHash)(p, CALG_SHA1, 0, 0, &a));
    CHECK(U(CryptCreateHash)(p, CALG_MD5, 0, 0, &b));
    CHECK(a != b);
    CHECK(U(CryptHashData)(a, (const BYTE *)"a", 1, 0));
    CHECK(U(CryptHashData)(b, (const BYTE *)"a", 1, 0));
    CHECK(U(CryptHashData)(a, (const BYTE *)"bc", 2, 0));
    CHECK(U(CryptHashData)(b, (const BYTE *)"bc", 2, 0));
    CHECK(U(CryptGetHashParam)(a, HP_HASHVAL, da, &la, 0));
    CHECK(U(CryptGetHashParam)(b, HP_HASHVAL, db, &lb, 0));
    EXPECT_HEX(da, 20, "a9993e364706816aba3e25717850c26c9cd0d89d");
    EXPECT_HEX(db, 16, "900150983cd24fb0d6963f7d28e17f72");
    U(CryptDestroyHash)(a); U(CryptDestroyHash)(b); h_rel(p);
}
/* hash created on one provider handle still works after another provider handle is released */
TEST(capi_hash_survives_other_provider_release) {
    REQUIRE(U(CryptCreateHash));
    HCRYPTPROV p = h_acq_aes(), q = h_acq_aes(); if (!p || !q) { h_rel(p); h_rel(q); return; }
    HCRYPTHASH h = 0; BYTE d[20]; DWORD dl = 20;
    CHECK(p != q);
    CHECK(U(CryptCreateHash)(p, CALG_SHA1, 0, 0, &h));
    h_rel(q);
    CHECK(U(CryptHashData)(h, (const BYTE *)"abc", 3, 0));
    CHECK(U(CryptGetHashParam)(h, HP_HASHVAL, d, &dl, 0));
    EXPECT_HEX(d, 20, "a9993e364706816aba3e25717850c26c9cd0d89d");
    U(CryptDestroyHash)(h); h_rel(p);
}
/* bytes in the data buffer beyond the length are not hashed; high bytes hash verbatim */
TEST(capi_hash_all_byte_values_md5) {
    REQUIRE(U(CryptCreateHash));
    HCRYPTPROV p = h_acq_aes(); if (!p) return;
    BYTE buf[256], d[16]; DWORD dl = 16; int i;
    for (i = 0; i < 256; i++) buf[i] = (BYTE)i;
    CHECK(h_hash(p, CALG_MD5, buf, 256, d, &dl));
    EXPECT_HEX(d, 16, "e2c865db4162bed963bfaa9ef6ac18f0");
    h_rel(p);
}
