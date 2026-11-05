/* BCrypt RSA signatures: PKCS#1 v1.5 and PSS, fixed vectors, argument validation. */
#include "rd.h"

typedef struct { LPCWSTR alg; const UCHAR *hash; ULONG hl; const UCHAR *sig; } hvec;
#define HV(a, n) { a, kHash_##n, sizeof kHash_##n, kSigPkcs1_##n }
static const hvec g_hv[] = {
    HV(BCRYPT_MD5_ALGORITHM, md5), HV(BCRYPT_SHA1_ALGORITHM, sha1), HV(BCRYPT_SHA256_ALGORITHM, sha256),
    HV(BCRYPT_SHA384_ALGORITHM, sha384), HV(BCRYPT_SHA512_ALGORITHM, sha512),
};
#define NHV (sizeof g_hv / sizeof *g_hv)

static BCRYPT_ALG_HANDLE g_a;
static BCRYPT_KEY_HANDLE fx(ULONG magic) { return g_a ? rd_fixed_rsa(g_a, magic) : NULL; }
#define BEGIN() NEED_BCRYPT(); g_a = rd_alg(BCRYPT_RSA_ALGORITHM); if (!g_a) { t_skip("no RSA provider"); return; }
#define END() rd_closealg(g_a); g_a = NULL

static NTSTATUS sign(BCRYPT_KEY_HANDLE k, void *pad, const UCHAR *h, ULONG hl, UCHAR *out, ULONG cb, ULONG *n, ULONG fl) {
    return U(BCryptSignHash)(k, pad, (PUCHAR)h, hl, out, cb, n, fl);
}
static NTSTATUS verify(BCRYPT_KEY_HANDLE k, void *pad, const UCHAR *h, ULONG hl, const UCHAR *sig, ULONG sl, ULONG fl) {
    return U(BCryptVerifySignature)(k, pad, (PUCHAR)h, hl, (PUCHAR)sig, sl, fl);
}

/* ---------- PKCS#1 v1.5 known answers ---------- */
TEST(rsa_sign_pkcs1_known_answer_all_hashes) {
    BEGIN();
    BCRYPT_KEY_HANDLE k = fx(BCRYPT_RSAPRIVATE_MAGIC); CHECK(k);
    for (size_t i = 0; k && i < NHV; i++) {
        BCRYPT_PKCS1_PADDING_INFO pi = { g_hv[i].alg };
        UCHAR sig[128]; ULONG n = 0;
        NTSTATUS s = sign(k, &pi, g_hv[i].hash, g_hv[i].hl, sig, sizeof sig, &n, BCRYPT_PAD_PKCS1);
        CHECKF(s == 0, "%ls sign 0x%lx", g_hv[i].alg, (unsigned long)s);
        EXPECT_EQ(n, 128);
        CHECKF(!memcmp(sig, g_hv[i].sig, 128), "%ls signature mismatch", g_hv[i].alg);
    }
    rd_destroy(k); END();
}
TEST(rsa_sign_pkcs1_verify_known_answer_private_key) {
    BEGIN();
    BCRYPT_KEY_HANDLE k = fx(BCRYPT_RSAPRIVATE_MAGIC); CHECK(k);
    for (size_t i = 0; k && i < NHV; i++) {
        BCRYPT_PKCS1_PADDING_INFO pi = { g_hv[i].alg };
        EXPECT_EQ(verify(k, &pi, g_hv[i].hash, g_hv[i].hl, g_hv[i].sig, 128, BCRYPT_PAD_PKCS1), ST_SUCCESS);
    }
    rd_destroy(k); END();
}
TEST(rsa_sign_pkcs1_verify_known_answer_public_key) {
    BEGIN();
    BCRYPT_KEY_HANDLE k = fx(BCRYPT_RSAPUBLIC_MAGIC); CHECK(k);
    for (size_t i = 0; k && i < NHV; i++) {
        BCRYPT_PKCS1_PADDING_INFO pi = { g_hv[i].alg };
        EXPECT_EQ(verify(k, &pi, g_hv[i].hash, g_hv[i].hl, g_hv[i].sig, 128, BCRYPT_PAD_PKCS1), ST_SUCCESS);
    }
    rd_destroy(k); END();
}
TEST(rsa_sign_pkcs1_verify_wrong_hash_alg_id_fails) {
    BEGIN();
    BCRYPT_KEY_HANDLE k = fx(BCRYPT_RSAPUBLIC_MAGIC); CHECK(k);
    /* same-length digests under a different DigestInfo OID must not verify: sha256 sig as if sha256 but hash bytes of sha1 padded? use sha1 vs md5 */
    BCRYPT_PKCS1_PADDING_INFO pi = { BCRYPT_SHA1_ALGORITHM };
    EXPECT_EQ(verify(k, &pi, kHash_sha1, 20, kSigPkcs1_sha256, 128, BCRYPT_PAD_PKCS1), ST_INVALID_SIGNATURE);
    pi.pszAlgId = BCRYPT_MD5_ALGORITHM;
    EXPECT_EQ(verify(k, &pi, kHash_md5, 16, kSigPkcs1_sha1, 128, BCRYPT_PAD_PKCS1), ST_INVALID_SIGNATURE);
    /* sha1 signature verified against sha256 info with the right sha256 digest */
    pi.pszAlgId = BCRYPT_SHA256_ALGORITHM;
    EXPECT_EQ(verify(k, &pi, kHash_sha256, 32, kSigPkcs1_sha1, 128, BCRYPT_PAD_PKCS1), ST_INVALID_SIGNATURE);
    rd_destroy(k); END();
}
TEST(rsa_sign_pkcs1_null_alg_id_raw_hash) {
    BEGIN();
    BCRYPT_KEY_HANDLE k = fx(BCRYPT_RSAPRIVATE_MAGIC); CHECK(k);
    BCRYPT_PKCS1_PADDING_INFO pi = { NULL };
    UCHAR sig[128]; ULONG n = 0;
    EXPECT_EQ(sign(k, &pi, kHash_sha1, 20, sig, sizeof sig, &n, BCRYPT_PAD_PKCS1), ST_SUCCESS);
    EXPECT_EQ(n, 128);
    CHECK(!memcmp(sig, kSigRaw_sha1, 128));
    EXPECT_EQ(sign(k, &pi, kHash_sha256, 32, sig, sizeof sig, &n, BCRYPT_PAD_PKCS1), ST_SUCCESS);
    CHECK(!memcmp(sig, kSigRaw_sha256, 128));
    EXPECT_EQ(verify(k, &pi, kHash_sha256, 32, kSigRaw_sha256, 128, BCRYPT_PAD_PKCS1), ST_SUCCESS);
    EXPECT_EQ(verify(k, &pi, kHash_sha1, 20, kSigRaw_sha1, 128, BCRYPT_PAD_PKCS1), ST_SUCCESS);
    /* a signature carrying a DigestInfo does not verify as a bare-hash signature */
    EXPECT_EQ(verify(k, &pi, kHash_sha1, 20, kSigPkcs1_sha1, 128, BCRYPT_PAD_PKCS1), ST_INVALID_SIGNATURE);
    /* and a bare-hash signature does not verify with an algorithm id */
    BCRYPT_PKCS1_PADDING_INFO p1 = { BCRYPT_SHA1_ALGORITHM };
    EXPECT_EQ(verify(k, &p1, kHash_sha1, 20, kSigRaw_sha1, 128, BCRYPT_PAD_PKCS1), ST_INVALID_SIGNATURE);
    rd_destroy(k); END();
}
TEST(rsa_sign_pkcs1_null_alg_id_arbitrary_hash_length) {
    BEGIN();
    BCRYPT_KEY_HANDLE k = fx(BCRYPT_RSAPRIVATE_MAGIC); CHECK(k);
    BCRYPT_PKCS1_PADDING_INFO pi = { NULL };
    UCHAR in[40], sig[128]; ULONG n = 0;
    for (int i = 0; i < 40; i++) in[i] = (UCHAR)(i * 3 + 1);
    ULONG lens[] = { 1, 16, 20, 33, 40 };
    for (int i = 0; i < 5; i++) {
        NTSTATUS s = sign(k, &pi, in, lens[i], sig, sizeof sig, &n, BCRYPT_PAD_PKCS1);
        t_note("bare PKCS1 sign of %lu-byte input: 0x%lx", lens[i], (unsigned long)s);
        if (s == 0) EXPECT_EQ(verify(k, &pi, in, lens[i], sig, 128, BCRYPT_PAD_PKCS1), ST_SUCCESS);
    }
    rd_destroy(k); END();
}

/* ---------- PSS ---------- */
TEST(rsa_sign_pss_known_answer_verify) {
    BEGIN();
    BCRYPT_KEY_HANDLE k = fx(BCRYPT_RSAPUBLIC_MAGIC); CHECK(k);
    BCRYPT_PSS_PADDING_INFO p1 = { BCRYPT_SHA1_ALGORITHM, 20 };
    EXPECT_EQ(verify(k, &p1, kHash_sha1, 20, kSigPss_sha1_20, 128, BCRYPT_PAD_PSS), ST_SUCCESS);
    BCRYPT_PSS_PADDING_INFO p2 = { BCRYPT_SHA256_ALGORITHM, 32 };
    EXPECT_EQ(verify(k, &p2, kHash_sha256, 32, kSigPss_sha256_32, 128, BCRYPT_PAD_PSS), ST_SUCCESS);
    BCRYPT_PSS_PADDING_INFO p3 = { BCRYPT_SHA256_ALGORITHM, 0 };
    EXPECT_EQ(verify(k, &p3, kHash_sha256, 32, kSigPss_sha256_0, 128, BCRYPT_PAD_PSS), ST_SUCCESS);
    rd_destroy(k); END();
}
TEST(rsa_sign_pss_salt_length_must_match) {
    BEGIN();
    BCRYPT_KEY_HANDLE k = fx(BCRYPT_RSAPUBLIC_MAGIC); CHECK(k);
    BCRYPT_PSS_PADDING_INFO p = { BCRYPT_SHA256_ALGORITHM, 20 };
    EXPECT_EQ(verify(k, &p, kHash_sha256, 32, kSigPss_sha256_32, 128, BCRYPT_PAD_PSS), ST_INVALID_SIGNATURE);
    p.cbSalt = 0;
    EXPECT_EQ(verify(k, &p, kHash_sha256, 32, kSigPss_sha256_32, 128, BCRYPT_PAD_PSS), ST_INVALID_SIGNATURE);
    p.cbSalt = 32;
    EXPECT_EQ(verify(k, &p, kHash_sha256, 32, kSigPss_sha256_0, 128, BCRYPT_PAD_PSS), ST_INVALID_SIGNATURE);
    p.cbSalt = 33;
    EXPECT_EQ(verify(k, &p, kHash_sha256, 32, kSigPss_sha256_32, 128, BCRYPT_PAD_PSS), ST_INVALID_SIGNATURE);
    rd_destroy(k); END();
}
TEST(rsa_sign_pss_hash_must_match) {
    BEGIN();
    BCRYPT_KEY_HANDLE k = fx(BCRYPT_RSAPUBLIC_MAGIC); CHECK(k);
    BCRYPT_PSS_PADDING_INFO p = { BCRYPT_SHA1_ALGORITHM, 32 };
    NTSTATUS s = verify(k, &p, kHash_sha1, 20, kSigPss_sha256_32, 128, BCRYPT_PAD_PSS);
    EXPECT_EQ(s, ST_INVALID_SIGNATURE);
    rd_destroy(k); END();
}
TEST(rsa_sign_pss_roundtrip_salt_lengths) {
    BEGIN();
    BCRYPT_KEY_HANDLE k = fx(BCRYPT_RSAPRIVATE_MAGIC), pub = fx(BCRYPT_RSAPUBLIC_MAGIC); CHECK(k && pub);
    ULONG salts[] = { 0, 1, 8, 20, 32, 62, 94 };
    for (size_t i = 0; k && pub && i < sizeof salts / sizeof *salts; i++) {
        BCRYPT_PSS_PADDING_INFO p = { BCRYPT_SHA256_ALGORITHM, salts[i] };
        UCHAR sig[128]; ULONG n = 0;
        NTSTATUS s = sign(k, &p, kHash_sha256, 32, sig, sizeof sig, &n, BCRYPT_PAD_PSS);
        CHECKF(s == 0, "salt %lu sign 0x%lx", salts[i], (unsigned long)s);
        if (s) continue;
        EXPECT_EQ(n, 128);
        EXPECT_EQ(verify(pub, &p, kHash_sha256, 32, sig, 128, BCRYPT_PAD_PSS), ST_SUCCESS);
        sig[127] ^= 1;
        EXPECT_EQ(verify(pub, &p, kHash_sha256, 32, sig, 128, BCRYPT_PAD_PSS), ST_INVALID_SIGNATURE);
    }
    rd_destroy(k); rd_destroy(pub); END();
}
TEST(rsa_sign_pss_salt_too_large_fails) {
    BEGIN();
    BCRYPT_KEY_HANDLE k = fx(BCRYPT_RSAPRIVATE_MAGIC); CHECK(k);
    /* 1024-bit modulus: emLen = 128, max salt for SHA-256 = 128 - 32 - 2 = 94 */
    BCRYPT_PSS_PADDING_INFO p = { BCRYPT_SHA256_ALGORITHM, 95 };
    UCHAR sig[128]; ULONG n = 0;
    NTSTATUS s = sign(k, &p, kHash_sha256, 32, sig, sizeof sig, &n, BCRYPT_PAD_PSS);
    t_note("PSS salt 95 on 1024-bit/SHA-256: 0x%lx", (unsigned long)s);
    p.cbSalt = 1000;
    s = sign(k, &p, kHash_sha256, 32, sig, sizeof sig, &n, BCRYPT_PAD_PSS);
    t_note("PSS salt 1000 on 1024-bit/SHA-256: 0x%lx", (unsigned long)s);
    rd_destroy(k); END();
}
TEST(rsa_sign_pss_randomised_vs_zero_salt) {
    BEGIN();
    BCRYPT_KEY_HANDLE k = fx(BCRYPT_RSAPRIVATE_MAGIC); CHECK(k);
    UCHAR s1[128], s2[128]; ULONG n = 0;
    BCRYPT_PSS_PADDING_INFO p = { BCRYPT_SHA256_ALGORITHM, 32 };
    EXPECT_EQ(sign(k, &p, kHash_sha256, 32, s1, sizeof s1, &n, BCRYPT_PAD_PSS), ST_SUCCESS);
    EXPECT_EQ(sign(k, &p, kHash_sha256, 32, s2, sizeof s2, &n, BCRYPT_PAD_PSS), ST_SUCCESS);
    CHECK(memcmp(s1, s2, 128) != 0);
    p.cbSalt = 0;
    EXPECT_EQ(sign(k, &p, kHash_sha256, 32, s1, sizeof s1, &n, BCRYPT_PAD_PSS), ST_SUCCESS);
    EXPECT_EQ(sign(k, &p, kHash_sha256, 32, s2, sizeof s2, &n, BCRYPT_PAD_PSS), ST_SUCCESS);
    CHECK(!memcmp(s1, s2, 128));
    CHECK(!memcmp(s1, kSigPss_sha256_0, 128));   /* deterministic by definition */
    rd_destroy(k); END();
}
TEST(rsa_sign_pss_null_padding_info) {
    BEGIN();
    BCRYPT_KEY_HANDLE k = fx(BCRYPT_RSAPRIVATE_MAGIC); CHECK(k);
    UCHAR sig[128]; ULONG n = 0;
    EXPECT_EQ(sign(k, NULL, kHash_sha256, 32, sig, sizeof sig, &n, BCRYPT_PAD_PSS), ST_INVALID_PARAMETER);
    EXPECT_EQ(verify(k, NULL, kHash_sha256, 32, kSigPss_sha256_32, 128, BCRYPT_PAD_PSS), ST_INVALID_PARAMETER);
    rd_destroy(k); END();
}
TEST(rsa_sign_pss_cross_padding_does_not_verify) {
    BEGIN();
    BCRYPT_KEY_HANDLE k = fx(BCRYPT_RSAPUBLIC_MAGIC); CHECK(k);
    BCRYPT_PSS_PADDING_INFO pp = { BCRYPT_SHA256_ALGORITHM, 32 };
    BCRYPT_PKCS1_PADDING_INFO pk = { BCRYPT_SHA256_ALGORITHM };
    EXPECT_EQ(verify(k, &pp, kHash_sha256, 32, kSigPkcs1_sha256, 128, BCRYPT_PAD_PSS), ST_INVALID_SIGNATURE);
    EXPECT_EQ(verify(k, &pk, kHash_sha256, 32, kSigPss_sha256_32, 128, BCRYPT_PAD_PKCS1), ST_INVALID_SIGNATURE);
    rd_destroy(k); END();
}

/* ---------- size protocol ---------- */
TEST(rsa_sign_size_query_null_output) {
    BEGIN();
    BCRYPT_KEY_HANDLE k = fx(BCRYPT_RSAPRIVATE_MAGIC); CHECK(k);
    BCRYPT_PKCS1_PADDING_INFO pi = { BCRYPT_SHA256_ALGORITHM };
    ULONG n = 0xdead;
    EXPECT_EQ(sign(k, &pi, kHash_sha256, 32, NULL, 0, &n, BCRYPT_PAD_PKCS1), ST_SUCCESS);
    EXPECT_EQ(n, 128);
    n = 0xdead;
    BCRYPT_PSS_PADDING_INFO pp = { BCRYPT_SHA256_ALGORITHM, 32 };
    EXPECT_EQ(sign(k, &pp, kHash_sha256, 32, NULL, 0, &n, BCRYPT_PAD_PSS), ST_SUCCESS);
    EXPECT_EQ(n, 128);
    rd_destroy(k); END();
}
TEST(rsa_sign_size_buffer_too_small) {
    BEGIN();
    BCRYPT_KEY_HANDLE k = fx(BCRYPT_RSAPRIVATE_MAGIC); CHECK(k);
    BCRYPT_PKCS1_PADDING_INFO pi = { BCRYPT_SHA256_ALGORITHM };
    UCHAR sig[256]; ULONG sizes[] = { 0, 1, 64, 127 };
    for (int i = 0; i < 4; i++) {
        ULONG n = 0;
        memset(sig, 0xcc, sizeof sig);
        NTSTATUS s = sign(k, &pi, kHash_sha256, 32, sig, sizes[i], &n, BCRYPT_PAD_PKCS1);
        CHECKF(s == (NTSTATUS)ST_BUFFER_TOO_SMALL, "cb=%lu -> 0x%lx", sizes[i], (unsigned long)s);
        EXPECT_EQ(n, 128);
        CHECK(sig[0] == 0xcc);
    }
    rd_destroy(k); END();
}
TEST(rsa_sign_size_buffer_exact_and_larger) {
    BEGIN();
    BCRYPT_KEY_HANDLE k = fx(BCRYPT_RSAPRIVATE_MAGIC); CHECK(k);
    BCRYPT_PKCS1_PADDING_INFO pi = { BCRYPT_SHA256_ALGORITHM };
    UCHAR sig[256]; ULONG n = 0;
    memset(sig, 0xcc, sizeof sig);
    EXPECT_EQ(sign(k, &pi, kHash_sha256, 32, sig, 128, &n, BCRYPT_PAD_PKCS1), ST_SUCCESS);
    EXPECT_EQ(n, 128);
    CHECK(!memcmp(sig, kSigPkcs1_sha256, 128));
    CHECK(sig[128] == 0xcc);
    memset(sig, 0xcc, sizeof sig);
    EXPECT_EQ(sign(k, &pi, kHash_sha256, 32, sig, 256, &n, BCRYPT_PAD_PKCS1), ST_SUCCESS);
    EXPECT_EQ(n, 128);
    CHECK(!memcmp(sig, kSigPkcs1_sha256, 128));
    CHECK(sig[128] == 0xcc);
    rd_destroy(k); END();
}
TEST(rsa_sign_signature_length_property) {
    BEGIN();
    static const ULONG sizes[] = { 512, 1024, 1536, 2048 };
    for (int i = 0; i < 4; i++) {
        BCRYPT_KEY_HANDLE k = rd_gen(g_a, sizes[i]); CHECK(k); if (!k) continue;
        BCRYPT_PKCS1_PADDING_INFO pi = { BCRYPT_SHA1_ALGORITHM };
        ULONG n = 0;
        EXPECT_EQ(sign(k, &pi, kHash_sha1, 20, NULL, 0, &n, BCRYPT_PAD_PKCS1), ST_SUCCESS);
        EXPECT_EQ(n, sizes[i] / 8);
        rd_destroy(k);
    }
    END();
}

/* ---------- argument validation ---------- */
TEST(rsa_sign_null_pcbresult) {
    BEGIN();
    BCRYPT_KEY_HANDLE k = fx(BCRYPT_RSAPRIVATE_MAGIC); CHECK(k);
    BCRYPT_PKCS1_PADDING_INFO pi = { BCRYPT_SHA256_ALGORITHM };
    UCHAR sig[128];
    EXPECT_EQ(sign(k, &pi, kHash_sha256, 32, sig, sizeof sig, NULL, BCRYPT_PAD_PKCS1), ST_INVALID_PARAMETER);
    rd_destroy(k); END();
}
TEST(rsa_sign_null_key) {
    BEGIN();
    BCRYPT_PKCS1_PADDING_INFO pi = { BCRYPT_SHA256_ALGORITHM };
    UCHAR sig[128]; ULONG n = 0;
    NTSTATUS s = sign(NULL, &pi, kHash_sha256, 32, sig, sizeof sig, &n, BCRYPT_PAD_PKCS1);
    CHECK(s != 0);
    t_note("BCryptSignHash(NULL key): 0x%lx", (unsigned long)s);
    EXPECT_EQ(verify(NULL, &pi, kHash_sha256, 32, kSigPkcs1_sha256, 128, BCRYPT_PAD_PKCS1), ST_INVALID_HANDLE);
    END();
}
TEST(rsa_sign_algorithm_handle_as_key) {
    BEGIN();
    BCRYPT_PKCS1_PADDING_INFO pi = { BCRYPT_SHA256_ALGORITHM };
    UCHAR sig[128]; ULONG n = 0;
    NTSTATUS s = sign((BCRYPT_KEY_HANDLE)g_a, &pi, kHash_sha256, 32, sig, sizeof sig, &n, BCRYPT_PAD_PKCS1);
    CHECK(s != 0);
    EXPECT_EQ(verify((BCRYPT_KEY_HANDLE)g_a, &pi, kHash_sha256, 32, kSigPkcs1_sha256, 128, BCRYPT_PAD_PKCS1), ST_INVALID_HANDLE);
    END();
}
TEST(rsa_sign_verify_null_hash_or_signature) {
    BEGIN();
    BCRYPT_KEY_HANDLE k = fx(BCRYPT_RSAPUBLIC_MAGIC); CHECK(k);
    BCRYPT_PKCS1_PADDING_INFO pi = { BCRYPT_SHA256_ALGORITHM };
    EXPECT_EQ(verify(k, &pi, NULL, 32, kSigPkcs1_sha256, 128, BCRYPT_PAD_PKCS1), ST_INVALID_PARAMETER);
    EXPECT_EQ(verify(k, &pi, kHash_sha256, 32, NULL, 128, BCRYPT_PAD_PKCS1), ST_INVALID_PARAMETER);
    EXPECT_EQ(verify(k, &pi, NULL, 0, NULL, 0, BCRYPT_PAD_PKCS1), ST_INVALID_PARAMETER);
    rd_destroy(k); END();
}
TEST(rsa_sign_null_padding_info_pkcs1) {
    BEGIN();
    BCRYPT_KEY_HANDLE k = fx(BCRYPT_RSAPRIVATE_MAGIC); CHECK(k);
    UCHAR sig[128]; ULONG n = 0;
    EXPECT_EQ(sign(k, NULL, kHash_sha256, 32, sig, sizeof sig, &n, BCRYPT_PAD_PKCS1), ST_INVALID_PARAMETER);
    EXPECT_EQ(verify(k, NULL, kHash_sha256, 32, kSigPkcs1_sha256, 128, BCRYPT_PAD_PKCS1), ST_INVALID_PARAMETER);
    rd_destroy(k); END();
}
TEST(rsa_sign_flags_zero_rejected) {
    BEGIN();
    BCRYPT_KEY_HANDLE k = fx(BCRYPT_RSAPRIVATE_MAGIC); CHECK(k);
    BCRYPT_PKCS1_PADDING_INFO pi = { BCRYPT_SHA256_ALGORITHM };
    UCHAR sig[128]; ULONG n = 0;
    NTSTATUS s = sign(k, &pi, kHash_sha256, 32, sig, sizeof sig, &n, 0);
    EXPECT_EQ(s, ST_INVALID_PARAMETER);
    EXPECT_EQ(sign(k, NULL, kHash_sha256, 32, sig, sizeof sig, &n, 0), ST_INVALID_PARAMETER);
    s = verify(k, &pi, kHash_sha256, 32, kSigPkcs1_sha256, 128, 0);
    CHECK(s == (NTSTATUS)ST_INVALID_SIGNATURE || s == (NTSTATUS)ST_INVALID_PARAMETER);
    rd_destroy(k); END();
}
TEST(rsa_sign_flag_combinations_rejected) {
    BEGIN();
    BCRYPT_KEY_HANDLE k = fx(BCRYPT_RSAPRIVATE_MAGIC); CHECK(k);
    BCRYPT_PKCS1_PADDING_INFO pi = { BCRYPT_SHA256_ALGORITHM };
    UCHAR sig[128]; ULONG n = 0;
    /* neither the PKCS1 (2) nor the PSS (8) bit set: the padding step rejects the call */
    ULONG bad[] = { BCRYPT_PAD_NONE, BCRYPT_PAD_OAEP, 0x80000000, 0x10 };
    for (int i = 0; i < 4; i++) {
        NTSTATUS s = sign(k, &pi, kHash_sha256, 32, sig, sizeof sig, &n, bad[i]);
        CHECKF(s == (NTSTATUS)ST_INVALID_PARAMETER, "flags 0x%lx -> 0x%lx", bad[i], (unsigned long)s);
    }
    /* both bits set: PKCS1 takes precedence in the padding step */
    NTSTATUS s = sign(k, &pi, kHash_sha256, 32, sig, sizeof sig, &n, BCRYPT_PAD_PKCS1 | BCRYPT_PAD_PSS);
    t_note("sign flags PKCS1|PSS -> 0x%lx", (unsigned long)s);
    rd_destroy(k); END();
}
TEST(rsa_sign_non_hash_alg_id_not_supported) {
    BEGIN();
    BCRYPT_KEY_HANDLE k = fx(BCRYPT_RSAPRIVATE_MAGIC); CHECK(k);
    UCHAR sig[128]; ULONG n = 0;
    BCRYPT_PKCS1_PADDING_INFO pi = { BCRYPT_AES_ALGORITHM };
    EXPECT_EQ(sign(k, &pi, kHash_sha256, 32, sig, sizeof sig, &n, BCRYPT_PAD_PKCS1), ST_NOT_SUPPORTED);
    EXPECT_EQ(verify(k, &pi, kHash_sha256, 32, kSigPkcs1_sha256, 128, BCRYPT_PAD_PKCS1), ST_NOT_SUPPORTED);
    pi.pszAlgId = L"NOSUCHHASH";
    NTSTATUS s = sign(k, &pi, kHash_sha256, 32, sig, sizeof sig, &n, BCRYPT_PAD_PKCS1);
    CHECK(s != 0); t_note("unknown hash name: 0x%lx", (unsigned long)s);
    rd_destroy(k); END();
}
TEST(rsa_sign_hash_length_mismatch) {
    BEGIN();
    BCRYPT_KEY_HANDLE k = fx(BCRYPT_RSAPRIVATE_MAGIC); CHECK(k);
    UCHAR sig[128]; ULONG n = 0;
    BCRYPT_PKCS1_PADDING_INFO pi = { BCRYPT_SHA256_ALGORITHM };
    EXPECT_EQ(sign(k, &pi, kHash_sha1, 20, sig, sizeof sig, &n, BCRYPT_PAD_PKCS1), ST_INVALID_PARAMETER);
    EXPECT_EQ(sign(k, &pi, kHash_sha256, 31, sig, sizeof sig, &n, BCRYPT_PAD_PKCS1), ST_INVALID_PARAMETER);
    EXPECT_EQ(sign(k, &pi, kHash_sha512, 64, sig, sizeof sig, &n, BCRYPT_PAD_PKCS1), ST_INVALID_PARAMETER);
    pi.pszAlgId = BCRYPT_SHA1_ALGORITHM;
    EXPECT_EQ(sign(k, &pi, kHash_sha256, 32, sig, sizeof sig, &n, BCRYPT_PAD_PKCS1), ST_INVALID_PARAMETER);
    NTSTATUS s = verify(k, &pi, kHash_sha256, 32, kSigPkcs1_sha1, 128, BCRYPT_PAD_PKCS1);
    CHECK(s != 0); t_note("verify with hash length != alg digest size: 0x%lx", (unsigned long)s);
    rd_destroy(k); END();
}
TEST(rsa_sign_zero_length_hash) {
    BEGIN();
    BCRYPT_KEY_HANDLE k = fx(BCRYPT_RSAPRIVATE_MAGIC); CHECK(k);
    UCHAR sig[128]; ULONG n = 0;
    BCRYPT_PKCS1_PADDING_INFO pi = { BCRYPT_SHA256_ALGORITHM };
    CHECK(sign(k, &pi, kHash_sha256, 0, sig, sizeof sig, &n, BCRYPT_PAD_PKCS1) != 0);
    rd_destroy(k); END();
}
TEST(rsa_sign_with_public_only_key_fails) {
    BEGIN();
    BCRYPT_KEY_HANDLE k = fx(BCRYPT_RSAPUBLIC_MAGIC); CHECK(k);
    BCRYPT_PKCS1_PADDING_INFO pi = { BCRYPT_SHA256_ALGORITHM };
    UCHAR sig[128]; ULONG n = 0;
    NTSTATUS s = sign(k, &pi, kHash_sha256, 32, sig, sizeof sig, &n, BCRYPT_PAD_PKCS1);
    CHECK(s != 0);
    t_note("sign with public-only key: 0x%lx", (unsigned long)s);
    s = sign(k, &pi, kHash_sha256, 32, NULL, 0, &n, BCRYPT_PAD_PKCS1);
    t_note("size query with public-only key: 0x%lx n=%lu", (unsigned long)s, n);
    BCRYPT_PSS_PADDING_INFO pp = { BCRYPT_SHA256_ALGORITHM, 32 };
    CHECK(sign(k, &pp, kHash_sha256, 32, sig, sizeof sig, &n, BCRYPT_PAD_PSS) != 0);
    rd_destroy(k); END();
}

/* ---------- tampering ---------- */
TEST(rsa_sign_tamper_each_signature_byte_region) {
    BEGIN();
    BCRYPT_KEY_HANDLE k = fx(BCRYPT_RSAPUBLIC_MAGIC); CHECK(k);
    BCRYPT_PKCS1_PADDING_INFO pi = { BCRYPT_SHA256_ALGORITHM };
    ULONG pos[] = { 0, 1, 63, 64, 126, 127 };
    for (int i = 0; i < 6; i++) {
        UCHAR sig[128]; memcpy(sig, kSigPkcs1_sha256, 128);
        sig[pos[i]] ^= 0x01;
        NTSTATUS s = verify(k, &pi, kHash_sha256, 32, sig, 128, BCRYPT_PAD_PKCS1);
        if (pos[i] == 0) { CHECKF(s != 0, "flip byte 0 verified"); t_note("flip byte 0 -> 0x%lx", (unsigned long)s); }
        else CHECKF(s == (NTSTATUS)ST_INVALID_SIGNATURE, "flip byte %lu -> 0x%lx", pos[i], (unsigned long)s);
    }
    rd_destroy(k); END();
}
TEST(rsa_sign_tamper_hash) {
    BEGIN();
    BCRYPT_KEY_HANDLE k = fx(BCRYPT_RSAPUBLIC_MAGIC); CHECK(k);
    BCRYPT_PKCS1_PADDING_INFO pi = { BCRYPT_SHA256_ALGORITHM };
    for (int i = 0; i < 32; i += 7) {
        UCHAR h[32]; memcpy(h, kHash_sha256, 32); h[i] ^= 0x80;
        EXPECT_EQ(verify(k, &pi, h, 32, kSigPkcs1_sha256, 128, BCRYPT_PAD_PKCS1), ST_INVALID_SIGNATURE);
    }
    rd_destroy(k); END();
}
TEST(rsa_sign_signature_wrong_length) {
    BEGIN();
    BCRYPT_KEY_HANDLE k = fx(BCRYPT_RSAPUBLIC_MAGIC); CHECK(k);
    BCRYPT_PKCS1_PADDING_INFO pi = { BCRYPT_SHA256_ALGORITHM };
    UCHAR big[256]; memset(big, 0, sizeof big); memcpy(big, kSigPkcs1_sha256, 128);
    ULONG lens[] = { 0, 1, 64, 127, 129, 256 };
    for (int i = 0; i < 6; i++) {
        NTSTATUS s = verify(k, &pi, kHash_sha256, 32, big, lens[i], BCRYPT_PAD_PKCS1);
        CHECKF(s != 0, "sig length %lu verified", lens[i]);
        t_note("verify with signature length %lu: 0x%lx", lens[i], (unsigned long)s);
    }
    rd_destroy(k); END();
}
TEST(rsa_sign_signature_not_below_modulus) {
    BEGIN();
    BCRYPT_KEY_HANDLE k = fx(BCRYPT_RSAPUBLIC_MAGIC); CHECK(k);
    BCRYPT_PKCS1_PADDING_INFO pi = { BCRYPT_SHA256_ALGORITHM };
    UCHAR sig[128]; memset(sig, 0xff, 128);
    NTSTATUS s = verify(k, &pi, kHash_sha256, 32, sig, 128, BCRYPT_PAD_PKCS1);
    CHECK(s != 0); t_note("signature 0xFF..FF (>= modulus): 0x%lx", (unsigned long)s);
    memset(sig, 0, 128);
    s = verify(k, &pi, kHash_sha256, 32, sig, 128, BCRYPT_PAD_PKCS1);
    CHECK(s != 0); t_note("signature all-zero: 0x%lx", (unsigned long)s);
    rd_destroy(k); END();
}
TEST(rsa_sign_verify_with_other_key_fails) {
    BEGIN();
    BCRYPT_KEY_HANDLE other = rd_gen(g_a, 1024); CHECK(other);
    BCRYPT_PKCS1_PADDING_INFO pi = { BCRYPT_SHA256_ALGORITHM };
    if (other) EXPECT_EQ(verify(other, &pi, kHash_sha256, 32, kSigPkcs1_sha256, 128, BCRYPT_PAD_PKCS1), ST_INVALID_SIGNATURE);
    rd_destroy(other); END();
}

/* ---------- generated keys, round trips, key sizes ---------- */
typedef struct { ULONG bits; LPCWSTR alg; const UCHAR *h; ULONG hl; int ok; } szcase;
static const szcase g_sz[] = {
    { 512, BCRYPT_MD5_ALGORITHM, kHash_md5, 16, 1 },   { 512, BCRYPT_SHA1_ALGORITHM, kHash_sha1, 20, 1 },
    { 512, BCRYPT_SHA256_ALGORITHM, kHash_sha256, 32, 1 },  /* 51 + 11 <= 64 */
    { 512, BCRYPT_SHA384_ALGORITHM, kHash_sha384, 48, 0 },  /* DigestInfo (67 bytes) + 11 > 64 */
    { 512, BCRYPT_SHA512_ALGORITHM, kHash_sha512, 64, 0 },  /* DigestInfo (83 bytes) + 11 > 64 */
    { 640, BCRYPT_SHA384_ALGORITHM, kHash_sha384, 48, 1 },  /* 78 <= 80 */
    { 640, BCRYPT_SHA512_ALGORITHM, kHash_sha512, 64, 0 },  /* 94 > 80 */
    { 768, BCRYPT_SHA512_ALGORITHM, kHash_sha512, 64, 1 },  /* 94 <= 96 */
    { 1024, BCRYPT_SHA512_ALGORITHM, kHash_sha512, 64, 1 }, { 2048, BCRYPT_SHA256_ALGORITHM, kHash_sha256, 32, 1 },
};
TEST(rsa_sign_generated_key_roundtrip_table) {
    BEGIN();
    for (size_t i = 0; i < sizeof g_sz / sizeof *g_sz; i++) {
        const szcase *c = &g_sz[i];
        BCRYPT_KEY_HANDLE k = rd_gen(g_a, c->bits); CHECK(k); if (!k) continue;
        BCRYPT_PKCS1_PADDING_INFO pi = { c->alg };
        UCHAR sig[512]; ULONG n = 0;
        NTSTATUS s = sign(k, &pi, c->h, c->hl, sig, sizeof sig, &n, BCRYPT_PAD_PKCS1);
        if (c->ok) {
            CHECKF(s == 0, "%lu/%ls sign 0x%lx", c->bits, c->alg, (unsigned long)s);
            EXPECT_EQ(n, c->bits / 8);
            if (s == 0) EXPECT_EQ(verify(k, &pi, c->h, c->hl, sig, n, BCRYPT_PAD_PKCS1), ST_SUCCESS);
        } else {
            CHECKF(s != 0, "%lu/%ls should not fit", c->bits, c->alg);
            t_note("%lu-bit key with %ls: 0x%lx", c->bits, c->alg, (unsigned long)s);
        }
        rd_destroy(k);
    }
    END();
}
TEST(rsa_sign_exported_public_key_verifies) {
    BEGIN();
    BCRYPT_KEY_HANDLE k = rd_gen(g_a, 1024); CHECK(k); if (!k) { END(); return; }
    BCRYPT_PKCS1_PADDING_INFO pi = { BCRYPT_SHA256_ALGORITHM };
    UCHAR sig[128]; ULONG n = 0;
    EXPECT_EQ(sign(k, &pi, kHash_sha256, 32, sig, sizeof sig, &n, BCRYPT_PAD_PKCS1), ST_SUCCESS);
    UCHAR *b; ULONG bl; BCRYPT_KEY_HANDLE pub = NULL;
    EXPECT_EQ(rd_export(k, BCRYPT_RSAPUBLIC_BLOB, &b, &bl), ST_SUCCESS);
    if (b) {
        EXPECT_EQ(rd_import(g_a, BCRYPT_RSAPUBLIC_BLOB, b, bl, &pub), ST_SUCCESS);
        if (pub) {
            EXPECT_EQ(verify(pub, &pi, kHash_sha256, 32, sig, 128, BCRYPT_PAD_PKCS1), ST_SUCCESS);
            sig[5] ^= 4;
            EXPECT_EQ(verify(pub, &pi, kHash_sha256, 32, sig, 128, BCRYPT_PAD_PKCS1), ST_INVALID_SIGNATURE);
        }
        free(b);
    }
    rd_destroy(pub); rd_destroy(k); END();
}
TEST(rsa_sign_exported_private_key_signs_same) {
    BEGIN();
    BCRYPT_KEY_HANDLE k = rd_gen(g_a, 1024), k2 = NULL; CHECK(k); if (!k) { END(); return; }
    BCRYPT_PKCS1_PADDING_INFO pi = { BCRYPT_SHA1_ALGORITHM };
    UCHAR s1[128], s2[128]; ULONG n = 0;
    LPCWSTR types[] = { BCRYPT_RSAPRIVATE_BLOB, BCRYPT_RSAFULLPRIVATE_BLOB };
    EXPECT_EQ(sign(k, &pi, kHash_sha1, 20, s1, sizeof s1, &n, BCRYPT_PAD_PKCS1), ST_SUCCESS);
    for (int i = 0; i < 2; i++) {
        UCHAR *b; ULONG bl;
        if (rd_export(k, types[i], &b, &bl) != 0) { CHECK(0); continue; }
        EXPECT_EQ(rd_import(g_a, types[i], b, bl, &k2), ST_SUCCESS);
        if (k2) {
            EXPECT_EQ(sign(k2, &pi, kHash_sha1, 20, s2, sizeof s2, &n, BCRYPT_PAD_PKCS1), ST_SUCCESS);
            CHECK(!memcmp(s1, s2, 128));   /* PKCS#1 v1.5 is deterministic */
            rd_destroy(k2); k2 = NULL;
        }
        free(b);
    }
    rd_destroy(k); END();
}
TEST(rsa_sign_works_across_threads) {
    BEGIN();
    BCRYPT_KEY_HANDLE k = fx(BCRYPT_RSAPRIVATE_MAGIC); CHECK(k); if (!k) { END(); return; }
    struct { BCRYPT_KEY_HANDLE k; NTSTATUS s; UCHAR sig[128]; } ctx = { k, 1, {0} };
    DWORD WINAPI th(LPVOID p) {
        typeof(ctx) *c = p; BCRYPT_PKCS1_PADDING_INFO pi = { BCRYPT_SHA256_ALGORITHM }; ULONG n = 0;
        c->s = U(BCryptSignHash)(c->k, &pi, (PUCHAR)kHash_sha256, 32, c->sig, 128, &n, BCRYPT_PAD_PKCS1);
        return 0;
    }
    HANDLE h = CreateThread(NULL, 0, th, &ctx, 0, NULL);
    CHECK(h != NULL);
    if (h) { CHECK(WaitForSingleObject(h, 10000) == WAIT_OBJECT_0); CloseHandle(h); }
    EXPECT_EQ(ctx.s, ST_SUCCESS);
    CHECK(!memcmp(ctx.sig, kSigPkcs1_sha256, 128));
    rd_destroy(k); END();
}
TEST(rsa_sign_key_after_destroy_is_invalid_for_verify) {
    BEGIN();
    BCRYPT_KEY_HANDLE k = fx(BCRYPT_RSAPUBLIC_MAGIC); CHECK(k); if (!k) { END(); return; }
    EXPECT_EQ(U(BCryptDestroyKey)(k), ST_SUCCESS);
    BCRYPT_PKCS1_PADDING_INFO pi = { BCRYPT_SHA256_ALGORITHM };
    EXPECT_EQ(U(BCryptDestroyKey)(NULL), ST_INVALID_HANDLE);
    END();
}
TEST(rsa_sign_rsa_sign_provider_keys) {
    BEGIN();
    BCRYPT_ALG_HANDLE as = rd_alg(BCRYPT_RSA_SIGN_ALGORITHM); CHECK(as);
    BCRYPT_KEY_HANDLE k = as ? rd_fixed_rsa(as, BCRYPT_RSAPRIVATE_MAGIC) : NULL; CHECK(k);
    if (k) {
        BCRYPT_PKCS1_PADDING_INFO pi = { BCRYPT_SHA256_ALGORITHM };
        UCHAR sig[128]; ULONG n = 0;
        EXPECT_EQ(sign(k, &pi, kHash_sha256, 32, sig, sizeof sig, &n, BCRYPT_PAD_PKCS1), ST_SUCCESS);
        CHECK(!memcmp(sig, kSigPkcs1_sha256, 128));
        rd_destroy(k);
    }
    rd_closealg(as); END();
}
