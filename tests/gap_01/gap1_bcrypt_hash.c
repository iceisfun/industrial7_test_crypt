/* BCryptCreateMultiHash, BCryptProcessMultiOperations, BCryptDuplicateHash. */
#include "gap1.h"

static const BYTE sha256_abc[32] = {0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad};
static const BYTE sha256_empty[32] = {0xe3,0xb0,0xc4,0x42,0x98,0xfc,0x1c,0x14,0x9a,0xfb,0xf4,0xc8,0x99,0x6f,0xb9,0x24,0x27,0xae,0x41,0xe4,0x64,0x9b,0x93,0x4c,0xa4,0x95,0x99,0x1b,0x78,0x52,0xb8,0x55};
/* HMAC-SHA256, RFC 4231 test case 1 */
static const BYTE hmac_rfc4231_1[32] = {0xb0,0x34,0x4c,0x61,0xd8,0xdb,0x38,0x53,0x5c,0xa8,0xaf,0xce,0xaf,0x0b,0xf1,0x2b,0x88,0x1d,0xc2,0x00,0xc9,0x83,0x3d,0xa7,0x26,0xe9,0x37,0x6c,0x2e,0x32,0xcf,0xf7};

static BCRYPT_ALG_HANDLE open_alg(const WCHAR *name, ULONG flags) {
    BCRYPT_ALG_HANDLE h = NULL;
    if (U(BCryptOpenAlgorithmProvider)(&h, name, NULL, flags) != 0) return NULL;
    return h;
}
static void close_alg(BCRYPT_ALG_HANDLE h) { if (h) U(BCryptCloseAlgorithmProvider)(h, 0); }
static ULONG getprop(BCRYPT_HANDLE h, const WCHAR *prop) {
    ULONG v = 0, n = 0;
    U(BCryptGetProperty)(h, prop, (PUCHAR)&v, sizeof v, &n, 0);
    return v;
}
static NTSTATUS one_shot(BCRYPT_ALG_HANDLE a, const void *d, ULONG cb, BYTE *out, ULONG cbout) {
    BCRYPT_HASH_HANDLE h; NTSTATUS s = U(BCryptCreateHash)(a, &h, NULL, 0, NULL, 0, 0);
    if (s) return s;
    s = U(BCryptHashData)(h, (PUCHAR)d, cb, 0);
    if (!s) s = U(BCryptFinishHash)(h, out, cbout, 0);
    U(BCryptDestroyHash)(h);
    return s;
}

/* ---------------- BCryptDuplicateHash ---------------- */
TEST(gap1_duphash_invalid_handles) {
    REQUIRE(U(BCryptDuplicateHash));
    BCRYPT_HASH_HANDLE n = NULL;
    EXPECT_EQ(U(BCryptDuplicateHash)(NULL, &n, NULL, 0, 0), ST_INVALID_HANDLE);
    CHECK(n == NULL);
    EXPECT_EQ(U(BCryptDuplicateHash)(NULL, NULL, NULL, 0, 0), ST_INVALID_HANDLE);
    /* an algorithm handle is not a hash handle */
    BCRYPT_ALG_HANDLE a = open_alg(L"SHA256", 0); REQUIRE(a);
    EXPECT_EQ(U(BCryptDuplicateHash)(a, &n, NULL, 0, 0), ST_INVALID_HANDLE);
    /* neither is a key handle */
    BCRYPT_ALG_HANDLE aes = open_alg(L"AES", 0);
    if (aes) {
        BCRYPT_KEY_HANDLE k = NULL; BYTE kb[16] = {0};
        if (U(BCryptGenerateSymmetricKey)(aes, &k, NULL, 0, kb, 16, 0) == 0) {
            EXPECT_EQ(U(BCryptDuplicateHash)(k, &n, NULL, 0, 0), ST_INVALID_HANDLE);
            U(BCryptDestroyKey)(k);
        }
        close_alg(aes);
    }
    close_alg(a);
}
TEST(gap1_duphash_destroyed_handle) {
    REQUIRE(U(BCryptDuplicateHash));
    BCRYPT_ALG_HANDLE a = open_alg(L"SHA256", 0); REQUIRE(a);
    BCRYPT_HASH_HANDLE h; CHECK(U(BCryptCreateHash)(a, &h, NULL, 0, NULL, 0, 0) == 0);
    CHECK(U(BCryptDestroyHash)(h) == 0);
    BCRYPT_HASH_HANDLE n = NULL;
    EXPECT_EQ(U(BCryptDuplicateHash)(h, &n, NULL, 0, 0), ST_INVALID_HANDLE);
    close_alg(a);
}
TEST(gap1_duphash_null_output_pointer) {
    REQUIRE(U(BCryptDuplicateHash));
    BCRYPT_ALG_HANDLE a = open_alg(L"SHA256", 0); REQUIRE(a);
    BCRYPT_HASH_HANDLE h; CHECK(U(BCryptCreateHash)(a, &h, NULL, 0, NULL, 0, 0) == 0);
    EXPECT_EQ(U(BCryptDuplicateHash)(h, NULL, NULL, 0, 0), ST_INVALID_PARAMETER);
    ULONG ol = getprop(a, BCRYPT_OBJECT_LENGTH);
    BYTE *buf = calloc(1, ol + 64);
    EXPECT_EQ(U(BCryptDuplicateHash)(h, NULL, buf, ol + 64, 0), ST_INVALID_PARAMETER);
    free(buf);
    /* the original is unaffected */
    BYTE out[32];
    CHECK(U(BCryptHashData)(h, (PUCHAR)"abc", 3, 0) == 0);
    CHECK(U(BCryptFinishHash)(h, out, 32, 0) == 0);
    CHECK(!memcmp(out, sha256_abc, 32));
    U(BCryptDestroyHash)(h); close_alg(a);
}
TEST(gap1_duphash_object_buffer_protocol) {
    REQUIRE(U(BCryptDuplicateHash));
    BCRYPT_ALG_HANDLE a = open_alg(L"SHA256", 0); REQUIRE(a);
    BCRYPT_HASH_HANDLE h; CHECK(U(BCryptCreateHash)(a, &h, NULL, 0, NULL, 0, 0) == 0);
    BCRYPT_HASH_HANDLE n = NULL; BYTE tiny[0x100];
    /* non-NULL buffer with a size below the 0x46 floor */
    EXPECT_EQ(U(BCryptDuplicateHash)(h, &n, tiny, 0, 0), ST_BUFFER_TOO_SMALL);
    EXPECT_EQ(U(BCryptDuplicateHash)(h, &n, tiny, 0x45, 0), ST_BUFFER_TOO_SMALL);
    CHECK(n == NULL);
    /* NULL buffer with a non-zero size */
    EXPECT_EQ(U(BCryptDuplicateHash)(h, &n, NULL, 0x200, 0), ST_INVALID_PARAMETER);
    CHECK(n == NULL);
    U(BCryptDestroyHash)(h); close_alg(a);
}
TEST(gap1_duphash_caller_buffer_misaligned) {
    REQUIRE(U(BCryptDuplicateHash));
    BCRYPT_ALG_HANDLE a = open_alg(L"SHA256", 0); REQUIRE(a);
    ULONG ol = getprop(a, BCRYPT_OBJECT_LENGTH);
    CHECK(ol > 0x46 - 1);
    BCRYPT_HASH_HANDLE h; CHECK(U(BCryptCreateHash)(a, &h, NULL, 0, NULL, 0, 0) == 0);
    CHECK(U(BCryptHashData)(h, (PUCHAR)"ab", 2, 0) == 0);
    BYTE *raw = calloc(1, ol + 256);
    BCRYPT_HASH_HANDLE n = NULL;
    /* the implementation aligns the object internally, so an odd address is fine given slack */
    NTSTATUS s = U(BCryptDuplicateHash)(h, &n, raw + 1, ol + 128, 0);
    CHECKF(s == 0, "status 0x%lx", (unsigned long)s);
    if (s == 0) {
        BYTE o1[32], o2[32];
        CHECK(U(BCryptHashData)(n, (PUCHAR)"c", 1, 0) == 0);
        CHECK(U(BCryptFinishHash)(n, o1, 32, 0) == 0);
        CHECK(U(BCryptHashData)(h, (PUCHAR)"c", 1, 0) == 0);
        CHECK(U(BCryptFinishHash)(h, o2, 32, 0) == 0);
        CHECK(!memcmp(o1, o2, 32));
        CHECK(!memcmp(o1, sha256_abc, 32));
        CHECK(U(BCryptDestroyHash)(n) == 0);
    }
    U(BCryptDestroyHash)(h); free(raw); close_alg(a);
}
TEST(gap1_duphash_state_is_independent) {
    REQUIRE(U(BCryptDuplicateHash));
    BCRYPT_ALG_HANDLE a = open_alg(L"SHA256", 0); REQUIRE(a);
    BCRYPT_HASH_HANDLE h, d;
    CHECK(U(BCryptCreateHash)(a, &h, NULL, 0, NULL, 0, 0) == 0);
    CHECK(U(BCryptHashData)(h, (PUCHAR)"ab", 2, 0) == 0);
    CHECK(U(BCryptDuplicateHash)(h, &d, NULL, 0, 0) == 0);
    CHECK(d != h);
    BYTE o1[32], o2[32], ref[32];
    CHECK(U(BCryptHashData)(h, (PUCHAR)"c", 1, 0) == 0);
    CHECK(U(BCryptHashData)(d, (PUCHAR)"cdef", 4, 0) == 0);
    CHECK(U(BCryptFinishHash)(h, o1, 32, 0) == 0);
    CHECK(U(BCryptFinishHash)(d, o2, 32, 0) == 0);
    CHECK(!memcmp(o1, sha256_abc, 32));
    CHECK(one_shot(a, "abcdef", 6, ref, 32) == 0);
    CHECK(!memcmp(o2, ref, 32));
    CHECK(memcmp(o1, o2, 32) != 0);
    U(BCryptDestroyHash)(h); U(BCryptDestroyHash)(d); close_alg(a);
}
TEST(gap1_duphash_survives_original_destroy) {
    REQUIRE(U(BCryptDuplicateHash));
    BCRYPT_ALG_HANDLE a = open_alg(L"SHA256", 0); REQUIRE(a);
    BCRYPT_HASH_HANDLE h, d;
    CHECK(U(BCryptCreateHash)(a, &h, NULL, 0, NULL, 0, 0) == 0);
    CHECK(U(BCryptHashData)(h, (PUCHAR)"ab", 2, 0) == 0);
    CHECK(U(BCryptDuplicateHash)(h, &d, NULL, 0, 0) == 0);
    CHECK(U(BCryptDestroyHash)(h) == 0);
    BYTE o[32];
    CHECK(U(BCryptHashData)(d, (PUCHAR)"c", 1, 0) == 0);
    CHECK(U(BCryptFinishHash)(d, o, 32, 0) == 0);
    CHECK(!memcmp(o, sha256_abc, 32));
    CHECK(U(BCryptDestroyHash)(d) == 0);
    close_alg(a);
}
TEST(gap1_duphash_of_duplicate_chain) {
    REQUIRE(U(BCryptDuplicateHash));
    BCRYPT_ALG_HANDLE a = open_alg(L"SHA256", 0); REQUIRE(a);
    BCRYPT_HASH_HANDLE h[5];
    CHECK(U(BCryptCreateHash)(a, &h[0], NULL, 0, NULL, 0, 0) == 0);
    for (int i = 1; i < 5; i++) {
        CHECK(U(BCryptHashData)(h[i-1], (PUCHAR)"a", 1, 0) == 0);
        CHECK(U(BCryptDuplicateHash)(h[i-1], &h[i], NULL, 0, 0) == 0);
    }
    BYTE o[32], ref[32];
    for (int i = 0; i < 5; i++) {
        CHECK(U(BCryptFinishHash)(h[i], o, 32, 0) == 0);
        char s[8]; int cnt = i < 4 ? i + 1 : 4; memset(s, 'a', cnt);   /* h[i-1] got its 'a' before h[i] was cloned from it */
        one_shot(a, s, cnt, ref, 32);
        CHECKF(!memcmp(o, ref, 32), "level %d", i);
        U(BCryptDestroyHash)(h[i]);
    }
    close_alg(a);
}
TEST(gap1_duphash_empty_state) {
    REQUIRE(U(BCryptDuplicateHash));
    BCRYPT_ALG_HANDLE a = open_alg(L"SHA256", 0); REQUIRE(a);
    BCRYPT_HASH_HANDLE h, d; BYTE o[32];
    CHECK(U(BCryptCreateHash)(a, &h, NULL, 0, NULL, 0, 0) == 0);
    CHECK(U(BCryptDuplicateHash)(h, &d, NULL, 0, 0) == 0);
    CHECK(U(BCryptFinishHash)(d, o, 32, 0) == 0);
    CHECK(!memcmp(o, sha256_empty, 32));
    U(BCryptDestroyHash)(h); U(BCryptDestroyHash)(d); close_alg(a);
}
TEST(gap1_duphash_all_hash_algs) {
    REQUIRE(U(BCryptDuplicateHash));
    static const WCHAR *algs[] = { L"MD2", L"MD4", L"MD5", L"SHA1", L"SHA256", L"SHA384", L"SHA512" };
    for (unsigned i = 0; i < sizeof algs / sizeof *algs; i++) {
        BCRYPT_ALG_HANDLE a = open_alg(algs[i], 0);
        if (!a) { t_note("%ls not available", algs[i]); continue; }
        ULONG hl = getprop(a, BCRYPT_HASH_LENGTH);
        BCRYPT_HASH_HANDLE h, d; BYTE o1[64], o2[64], ref[64];
        CHECKF(U(BCryptCreateHash)(a, &h, NULL, 0, NULL, 0, 0) == 0, "%ls", algs[i]);
        U(BCryptHashData)(h, (PUCHAR)"first-", 6, 0);
        CHECKF(U(BCryptDuplicateHash)(h, &d, NULL, 0, 0) == 0, "%ls", algs[i]);
        U(BCryptHashData)(h, (PUCHAR)"A", 1, 0); U(BCryptHashData)(d, (PUCHAR)"B", 1, 0);
        U(BCryptFinishHash)(h, o1, hl, 0); U(BCryptFinishHash)(d, o2, hl, 0);
        one_shot(a, "first-A", 7, ref, hl); CHECKF(!memcmp(o1, ref, hl), "%ls orig", algs[i]);
        one_shot(a, "first-B", 7, ref, hl); CHECKF(!memcmp(o2, ref, hl), "%ls dup", algs[i]);
        U(BCryptDestroyHash)(h); U(BCryptDestroyHash)(d); close_alg(a);
    }
}
TEST(gap1_duphash_hmac_keeps_key) {
    REQUIRE(U(BCryptDuplicateHash));
    BCRYPT_ALG_HANDLE a = open_alg(L"SHA256", BCRYPT_ALG_HANDLE_HMAC_FLAG); REQUIRE(a);
    BYTE key[20]; memset(key, 0x0b, 20);
    BCRYPT_HASH_HANDLE h, d; BYTE o1[32], o2[32];
    CHECK(U(BCryptCreateHash)(a, &h, NULL, 0, key, 20, 0) == 0);
    CHECK(U(BCryptHashData)(h, (PUCHAR)"Hi ", 3, 0) == 0);
    CHECK(U(BCryptDuplicateHash)(h, &d, NULL, 0, 0) == 0);
    CHECK(U(BCryptHashData)(h, (PUCHAR)"There", 5, 0) == 0);
    CHECK(U(BCryptHashData)(d, (PUCHAR)"There", 5, 0) == 0);
    CHECK(U(BCryptFinishHash)(h, o1, 32, 0) == 0);
    CHECK(U(BCryptFinishHash)(d, o2, 32, 0) == 0);
    CHECK(!memcmp(o1, hmac_rfc4231_1, 32));
    CHECK(!memcmp(o2, hmac_rfc4231_1, 32));
    U(BCryptDestroyHash)(h); U(BCryptDestroyHash)(d); close_alg(a);
}
TEST(gap1_duphash_after_finish) {
    REQUIRE(U(BCryptDuplicateHash));
    BCRYPT_ALG_HANDLE a = open_alg(L"SHA256", 0); REQUIRE(a);
    BCRYPT_HASH_HANDLE h, d; BYTE o[32];
    CHECK(U(BCryptCreateHash)(a, &h, NULL, 0, NULL, 0, 0) == 0);
    U(BCryptHashData)(h, (PUCHAR)"abc", 3, 0);
    CHECK(U(BCryptFinishHash)(h, o, 32, 0) == 0);
    NTSTATUS s = U(BCryptDuplicateHash)(h, &d, NULL, 0, 0);
    t_note("duplicate of a finished hash -> 0x%08lx", (unsigned long)s);
    if (s == 0) U(BCryptDestroyHash)(d);
    NTSTATUS s2 = U(BCryptHashData)(h, (PUCHAR)"x", 1, 0);
    t_note("hash data after finish (non-reusable) -> 0x%08lx", (unsigned long)s2);
    U(BCryptDestroyHash)(h); close_alg(a);
}
TEST(gap1_duphash_alg_closed_before_hash) {
    REQUIRE(U(BCryptDuplicateHash));
    BCRYPT_ALG_HANDLE a = open_alg(L"SHA256", 0); REQUIRE(a);
    BCRYPT_HASH_HANDLE h, d; BYTE o[32];
    CHECK(U(BCryptCreateHash)(a, &h, NULL, 0, NULL, 0, 0) == 0);
    U(BCryptHashData)(h, (PUCHAR)"ab", 2, 0);
    CHECK(U(BCryptDuplicateHash)(h, &d, NULL, 0, 0) == 0);
    /* hash objects hold a reference on the algorithm object (refcount at +0x10) */
    NTSTATUS cs = U(BCryptCloseAlgorithmProvider)(a, 0);
    CHECK(cs == 0);
    CHECK(U(BCryptHashData)(d, (PUCHAR)"c", 1, 0) == 0);
    CHECK(U(BCryptFinishHash)(d, o, 32, 0) == 0);
    CHECK(!memcmp(o, sha256_abc, 32));
    CHECK(U(BCryptDestroyHash)(d) == 0);
    CHECK(U(BCryptDestroyHash)(h) == 0);
}
TEST(gap1_duphash_flags_note) {
    REQUIRE(U(BCryptDuplicateHash));
    BCRYPT_ALG_HANDLE a = open_alg(L"SHA256", 0); REQUIRE(a);
    BCRYPT_HASH_HANDLE h, d = NULL;
    CHECK(U(BCryptCreateHash)(a, &h, NULL, 0, NULL, 0, 0) == 0);
    NTSTATUS s = U(BCryptDuplicateHash)(h, &d, NULL, 0, 0x80000000);
    t_note("duplicate with unknown flag bit -> 0x%08lx", (unsigned long)s);
    if (s == 0) U(BCryptDestroyHash)(d);
    U(BCryptDestroyHash)(h); close_alg(a);
}

/* ---------------- BCryptCreateMultiHash ---------------- */
TEST(gap1_multihash_invalid_algorithm_handle) {
    REQUIRE(U(BCryptCreateMultiHash));
    BCRYPT_HASH_HANDLE h = NULL;
    EXPECT_EQ(U(BCryptCreateMultiHash)(NULL, &h, 2, NULL, 0, NULL, 0, 0), ST_INVALID_HANDLE);
    CHECK(h == NULL);
    EXPECT_EQ(U(BCryptCreateMultiHash)(NULL, &h, 0, NULL, 0, NULL, 0, 0), ST_INVALID_HANDLE);   /* handle checked before count */
}
TEST(gap1_multihash_hash_handle_is_not_alg_handle) {
    REQUIRE(U(BCryptCreateMultiHash));
    BCRYPT_ALG_HANDLE a = open_alg(L"SHA256", 0); REQUIRE(a);
    BCRYPT_HASH_HANDLE h, m = NULL;
    CHECK(U(BCryptCreateHash)(a, &h, NULL, 0, NULL, 0, 0) == 0);
    EXPECT_EQ(U(BCryptCreateMultiHash)(h, &m, 2, NULL, 0, NULL, 0, 0), ST_INVALID_HANDLE);
    U(BCryptDestroyHash)(h); close_alg(a);
}
TEST(gap1_multihash_zero_count) {
    REQUIRE(U(BCryptCreateMultiHash));
    static const WCHAR *algs[] = { L"SHA1", L"SHA256", L"SHA384", L"SHA512", L"MD5", L"AES" };
    for (unsigned i = 0; i < sizeof algs / sizeof *algs; i++) {
        BCRYPT_ALG_HANDLE a = open_alg(algs[i], 0);
        if (!a) continue;
        BCRYPT_HASH_HANDLE h = NULL;
        EXPECT_EQ(U(BCryptCreateMultiHash)(a, &h, 0, NULL, 0, NULL, 0, 0), ST_INVALID_PARAMETER);
        CHECK(h == NULL);
        close_alg(a);
    }
}
TEST(gap1_multihash_object_buffer_validation) {
    REQUIRE(U(BCryptCreateMultiHash));
    BCRYPT_ALG_HANDLE a = open_alg(L"SHA256", 0); REQUIRE(a);
    BCRYPT_HASH_HANDLE h = NULL; BYTE buf[0x200];
    /* size without a buffer */
    EXPECT_EQ(U(BCryptCreateMultiHash)(a, &h, 2, NULL, 0x200, NULL, 0, 0), ST_INVALID_PARAMETER);
    /* buffer without the output handle pointer */
    EXPECT_EQ(U(BCryptCreateMultiHash)(a, NULL, 2, buf, sizeof buf, NULL, 0, 0), ST_INVALID_PARAMETER);
    /* a caller buffer under the 0x46 floor */
    EXPECT_EQ(U(BCryptCreateMultiHash)(a, &h, 2, buf, 0x45, NULL, 0, 0), ST_BUFFER_TOO_SMALL);
    EXPECT_EQ(U(BCryptCreateMultiHash)(a, &h, 2, buf, 0, NULL, 0, 0), ST_BUFFER_TOO_SMALL);
    CHECK(h == NULL);
    close_alg(a);
}
TEST(gap1_multihash_buffer_checks_precede_class_check) {
    REQUIRE(U(BCryptCreateMultiHash));
    BCRYPT_ALG_HANDLE a = open_alg(L"AES", 0); REQUIRE(a);
    BCRYPT_HASH_HANDLE h = NULL; BYTE buf[0x400];
    EXPECT_EQ(U(BCryptCreateMultiHash)(a, &h, 2, buf, 0x45, NULL, 0, 0), ST_BUFFER_TOO_SMALL);
    /* big enough buffer, but a cipher algorithm cannot be a hash */
    EXPECT_EQ(U(BCryptCreateMultiHash)(a, &h, 2, buf, sizeof buf, NULL, 0, 0), ST_NOT_SUPPORTED);
    CHECK(h == NULL);
    close_alg(a);
}
TEST(gap1_multihash_asymmetric_alg_not_supported) {
    REQUIRE(U(BCryptCreateMultiHash));
    BCRYPT_ALG_HANDLE a = open_alg(L"RSA", 0);
    if (a) {
        BCRYPT_HASH_HANDLE h = NULL; BYTE buf[0x400];
        EXPECT_EQ(U(BCryptCreateMultiHash)(a, &h, 2, buf, sizeof buf, NULL, 0, 0), ST_NOT_SUPPORTED);
        close_alg(a);
    }
}
TEST(gap1_multihash_support_matrix_note) {
    REQUIRE(U(BCryptCreateMultiHash));
    static const WCHAR *algs[] = { L"MD2", L"MD4", L"MD5", L"SHA1", L"SHA256", L"SHA384", L"SHA512" };
    for (unsigned i = 0; i < sizeof algs / sizeof *algs; i++) {
        BCRYPT_ALG_HANDLE a = open_alg(algs[i], 0);
        if (!a) { t_note("%ls: cannot open", algs[i]); continue; }
        BCRYPT_MULTI_OBJECT_LENGTH_STRUCT ml = {0}; ULONG n = 0;
        NTSTATUS ps = U(BCryptGetProperty)(a, BCRYPT_MULTI_OBJECT_LENGTH, (PUCHAR)&ml, sizeof ml, &n, 0);
        BCRYPT_HASH_HANDLE h = NULL;
        NTSTATUS s = U(BCryptCreateMultiHash)(a, &h, 4, NULL, 0, NULL, 0, 0);
        t_note("%ls: MultiObjectLength prop 0x%08lx (perObject %lu perElement %lu), CreateMultiHash(4) 0x%08lx",
               algs[i], (unsigned long)ps, ml.cbPerObject, ml.cbPerElement, (unsigned long)s);
        if (s == 0) U(BCryptDestroyHash)(h);
        close_alg(a);
    }
}
TEST(gap1_multihash_hmac_secret_note) {
    REQUIRE(U(BCryptCreateMultiHash));
    BCRYPT_ALG_HANDLE a = open_alg(L"SHA256", BCRYPT_ALG_HANDLE_HMAC_FLAG); REQUIRE(a);
    BCRYPT_HASH_HANDLE h = NULL; BYTE key[20]; memset(key, 0x0b, 20);
    NTSTATUS s = U(BCryptCreateMultiHash)(a, &h, 2, NULL, 0, key, 20, 0);
    t_note("CreateMultiHash on an HMAC algorithm handle -> 0x%08lx", (unsigned long)s);
    if (s == 0) U(BCryptDestroyHash)(h);
    close_alg(a);
}

/* ---------------- BCryptProcessMultiOperations ---------------- */
TEST(gap1_multiops_invalid_handle) {
    REQUIRE(U(BCryptProcessMultiOperations));
    BCRYPT_MULTI_HASH_OPERATION op = { 0, BCRYPT_HASH_OPERATION_HASH_DATA, (PUCHAR)"abc", 3 };
    EXPECT_EQ(U(BCryptProcessMultiOperations)(NULL, BCRYPT_OPERATION_TYPE_HASH, &op, sizeof op, 0), ST_INVALID_HANDLE);
    EXPECT_EQ(U(BCryptProcessMultiOperations)(NULL, BCRYPT_OPERATION_TYPE_HASH, NULL, 0, 0), ST_INVALID_HANDLE);
}
TEST(gap1_multiops_alg_handle_rejected) {
    REQUIRE(U(BCryptProcessMultiOperations));
    BCRYPT_ALG_HANDLE a = open_alg(L"SHA256", 0); REQUIRE(a);
    BCRYPT_MULTI_HASH_OPERATION op = { 0, BCRYPT_HASH_OPERATION_HASH_DATA, (PUCHAR)"abc", 3 };
    EXPECT_EQ(U(BCryptProcessMultiOperations)(a, BCRYPT_OPERATION_TYPE_HASH, &op, sizeof op, 0), ST_INVALID_HANDLE);
    close_alg(a);
}
TEST(gap1_multiops_single_hash_object_rejected) {
    /* an ordinary (single) hash object has no multi capability: handle error, even with NULL operations */
    REQUIRE(U(BCryptProcessMultiOperations));
    BCRYPT_ALG_HANDLE a = open_alg(L"SHA256", 0); REQUIRE(a);
    BCRYPT_HASH_HANDLE h; CHECK(U(BCryptCreateHash)(a, &h, NULL, 0, NULL, 0, 0) == 0);
    BCRYPT_MULTI_HASH_OPERATION op = { 0, BCRYPT_HASH_OPERATION_HASH_DATA, (PUCHAR)"abc", 3 };
    NTSTATUS s1 = U(BCryptProcessMultiOperations)(h, BCRYPT_OPERATION_TYPE_HASH, &op, sizeof op, 0);
    NTSTATUS s2 = U(BCryptProcessMultiOperations)(h, BCRYPT_OPERATION_TYPE_HASH, NULL, 0, 0);
    t_note("single hash: with ops 0x%08lx, NULL ops 0x%08lx", (unsigned long)s1, (unsigned long)s2);
    U(BCryptDestroyHash)(h); close_alg(a);
}
static NTSTATUS make_multi(BCRYPT_ALG_HANDLE a, ULONG n, BCRYPT_HASH_HANDLE *h) {
    return U(BCryptCreateMultiHash)(a, h, n, NULL, 0, NULL, 0, 0);
}
TEST(gap1_multiops_null_operations) {
    REQUIRE(U(BCryptProcessMultiOperations)); REQUIRE(U(BCryptCreateMultiHash));
    BCRYPT_ALG_HANDLE a = open_alg(L"SHA256", 0); REQUIRE(a);
    BCRYPT_HASH_HANDLE h;
    if (make_multi(a, 4, &h) != 0) { close_alg(a); t_skip("multi-hash not supported here"); return; }
    EXPECT_EQ(U(BCryptProcessMultiOperations)(h, BCRYPT_OPERATION_TYPE_HASH, NULL, 0, 0), ST_INVALID_PARAMETER);
    EXPECT_EQ(U(BCryptProcessMultiOperations)(h, BCRYPT_OPERATION_TYPE_HASH, NULL, 16, 0), ST_INVALID_PARAMETER);
    U(BCryptDestroyHash)(h); close_alg(a);
}
TEST(gap1_multiops_hash_four_lanes) {
    REQUIRE(U(BCryptProcessMultiOperations)); REQUIRE(U(BCryptCreateMultiHash));
    BCRYPT_ALG_HANDLE a = open_alg(L"SHA256", 0); REQUIRE(a);
    BCRYPT_HASH_HANDLE h;
    if (make_multi(a, 4, &h) != 0) { close_alg(a); t_skip("multi-hash not supported here"); return; }
    BYTE out[4][32]; memset(out, 0, sizeof out);
    BCRYPT_MULTI_HASH_OPERATION ops[8];
    const char *msgs[4] = { "abc", "", "abc", "abcdef" };
    int n = 0;
    for (int i = 0; i < 4; i++) {
        if (strlen(msgs[i])) { ops[n].iHash = i; ops[n].hashOperation = BCRYPT_HASH_OPERATION_HASH_DATA; ops[n].pbBuffer = (PUCHAR)msgs[i]; ops[n].cbBuffer = (ULONG)strlen(msgs[i]); n++; }
    }
    for (int i = 0; i < 4; i++) { ops[n].iHash = i; ops[n].hashOperation = BCRYPT_HASH_OPERATION_FINISH_HASH; ops[n].pbBuffer = out[i]; ops[n].cbBuffer = 32; n++; }
    NTSTATUS s = U(BCryptProcessMultiOperations)(h, BCRYPT_OPERATION_TYPE_HASH, ops, n * sizeof ops[0], 0);
    EXPECT_EQ(s, 0);
    if (s == 0) {
        BCRYPT_ALG_HANDLE b = open_alg(L"SHA256", 0); BYTE ref[32];
        CHECK(!memcmp(out[0], sha256_abc, 32));
        CHECK(!memcmp(out[1], sha256_empty, 32));
        CHECK(!memcmp(out[2], sha256_abc, 32));
        one_shot(b, "abcdef", 6, ref, 32);
        CHECK(!memcmp(out[3], ref, 32));
        close_alg(b);
    }
    U(BCryptDestroyHash)(h); close_alg(a);
}
TEST(gap1_multiops_incremental_chunks) {
    REQUIRE(U(BCryptProcessMultiOperations)); REQUIRE(U(BCryptCreateMultiHash));
    BCRYPT_ALG_HANDLE a = open_alg(L"SHA256", 0); REQUIRE(a);
    BCRYPT_HASH_HANDLE h;
    if (make_multi(a, 2, &h) != 0) { close_alg(a); t_skip("multi-hash not supported here"); return; }
    BCRYPT_MULTI_HASH_OPERATION o1[2] = { {0, BCRYPT_HASH_OPERATION_HASH_DATA, (PUCHAR)"a", 1}, {1, BCRYPT_HASH_OPERATION_HASH_DATA, (PUCHAR)"abc", 3} };
    BCRYPT_MULTI_HASH_OPERATION o2[2] = { {0, BCRYPT_HASH_OPERATION_HASH_DATA, (PUCHAR)"bc", 2}, {1, BCRYPT_HASH_OPERATION_HASH_DATA, (PUCHAR)"", 0} };
    BYTE out[2][32];
    BCRYPT_MULTI_HASH_OPERATION o3[2] = { {0, BCRYPT_HASH_OPERATION_FINISH_HASH, out[0], 32}, {1, BCRYPT_HASH_OPERATION_FINISH_HASH, out[1], 32} };
    EXPECT_EQ(U(BCryptProcessMultiOperations)(h, BCRYPT_OPERATION_TYPE_HASH, o1, sizeof o1, 0), 0);
    NTSTATUS s2 = U(BCryptProcessMultiOperations)(h, BCRYPT_OPERATION_TYPE_HASH, o2, sizeof o2, 0);
    t_note("zero-length hash-data operation among others -> 0x%08lx", (unsigned long)s2);
    if (s2 != 0) { BCRYPT_MULTI_HASH_OPERATION o2b = o2[0]; U(BCryptProcessMultiOperations)(h, BCRYPT_OPERATION_TYPE_HASH, &o2b, sizeof o2b, 0); }
    EXPECT_EQ(U(BCryptProcessMultiOperations)(h, BCRYPT_OPERATION_TYPE_HASH, o3, sizeof o3, 0), 0);
    CHECK(!memcmp(out[0], sha256_abc, 32));
    CHECK(!memcmp(out[1], sha256_abc, 32));
    U(BCryptDestroyHash)(h); close_alg(a);
}
TEST(gap1_multiops_bad_operation_note) {
    REQUIRE(U(BCryptProcessMultiOperations)); REQUIRE(U(BCryptCreateMultiHash));
    BCRYPT_ALG_HANDLE a = open_alg(L"SHA256", 0); REQUIRE(a);
    BCRYPT_HASH_HANDLE h;
    if (make_multi(a, 2, &h) != 0) { close_alg(a); t_skip("multi-hash not supported here"); return; }
    BCRYPT_MULTI_HASH_OPERATION bad = { 7, BCRYPT_HASH_OPERATION_HASH_DATA, (PUCHAR)"abc", 3 };   /* lane out of range */
    NTSTATUS s = U(BCryptProcessMultiOperations)(h, BCRYPT_OPERATION_TYPE_HASH, &bad, sizeof bad, 0);
    t_note("lane index 7 of 2 -> 0x%08lx", (unsigned long)s);
    CHECK(s != 0);
    BCRYPT_MULTI_HASH_OPERATION badt = { 0, (BCRYPT_HASH_OPERATION_TYPE)9, (PUCHAR)"abc", 3 };
    s = U(BCryptProcessMultiOperations)(h, BCRYPT_OPERATION_TYPE_HASH, &badt, sizeof badt, 0);
    t_note("operation type 9 -> 0x%08lx", (unsigned long)s);
    CHECK(s != 0);
    s = U(BCryptProcessMultiOperations)(h, (BCRYPT_MULTI_OPERATION_TYPE)2, &bad, sizeof bad, 0);
    t_note("multi operation type 2 -> 0x%08lx", (unsigned long)s);
    CHECK(s != 0);
    U(BCryptDestroyHash)(h); close_alg(a);
}
