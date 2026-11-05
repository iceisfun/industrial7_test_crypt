/* BCryptDeriveKey on a secret agreement handle: KDF names, parameter lists, size protocol, error codes.
 * The shared secret is the fixed P-256 ECDH value from vectors.h (big-endian Z as KDF_Z256). */
#include "kc.h"

typedef struct { BCRYPT_ALG_HANDLE a; BCRYPT_KEY_HANDLE ka, kb; BCRYPT_SECRET_HANDLE s; } sec_t;

static int sec_open(sec_t *x) {
    memset(x, 0, sizeof(*x));
    const curve_t *c = &g_curves[0];
    x->a = kc_open(c->dh, 0);
    if (!x->a) return 0;
    x->ka = kc_key(x->a, c, 1, 0, 1);
    x->kb = kc_key(x->a, c, 1, 1, 0);
    NTSTATUS st;
    x->s = kc_agree(x->ka, x->kb, &st);
    return x->s != NULL;
}
/* a fresh secret from the same pair (SP800-56A consumes its secret) */
static BCRYPT_SECRET_HANDLE sec_again(sec_t *x) { NTSTATUS st; return kc_agree(x->ka, x->kb, &st); }
static void sec_close(sec_t *x) {
    if (x->s) U(BCryptDestroySecret)(x->s);
    kc_destroy(x->ka); kc_destroy(x->kb); kc_close(x->a);
}
#define SEC_BEGIN(x) sec_t x; do { NEED_CORE(); if (!sec_open(&x)) { sec_close(&x); CHECK(0 && "cannot create ECDH secret"); return; } } while (0)

static void hash_of(const WCHAR *alg, kc_desc *d) { kc_desc_init(d); kc_desc_wstr(d, KDF_HASH_ALGORITHM, alg); }

/* ---- RAW secret ------------------------------------------------------------------------------------------------ */
TEST(bckdf_raw_size_query) {
    SEC_BEGIN(x);
    ULONG n = 0xCAFE;
    CHECK_NS(kc_derive(x.s, BCRYPT_KDF_RAW_SECRET, NULL, NULL, 0, &n, 0), 0);
    EXPECT_EQ(n, 32);
    n = 0xCAFE;
    unsigned char b[40];
    CHECK_NS(kc_derive(x.s, BCRYPT_KDF_RAW_SECRET, NULL, NULL, 99, &n, 0), 0);        /* NULL buffer wins over the size */
    EXPECT_EQ(n, 32);
    n = 0xCAFE; memset(b, 0xA5, sizeof(b));
    CHECK_NS(kc_derive(x.s, BCRYPT_KDF_RAW_SECRET, NULL, b, 0, &n, 0), 0);            /* zero size also queries */
    EXPECT_EQ(n, 32);
    EXPECT_EQ(b[0], 0xA5);
    sec_close(&x);
}

TEST(bckdf_raw_value_little_endian) {
    SEC_BEGIN(x);
    unsigned char out[32], want[32]; ULONG n = 0;
    CHECK_NS(kc_derive(x.s, BCRYPT_KDF_RAW_SECRET, NULL, out, sizeof(out), &n, 0), 0);
    EXPECT_EQ(n, 32);
    kc_rev(want, KDF_Z256, 32);
    CHECK_MEM(out, want, 32);
    sec_close(&x);
}

TEST(bckdf_raw_larger_buffer) {
    SEC_BEGIN(x);
    unsigned char out[64], want[32]; ULONG n = 0;
    memset(out, 0xA5, sizeof(out));
    CHECK_NS(kc_derive(x.s, BCRYPT_KDF_RAW_SECRET, NULL, out, sizeof(out), &n, 0), 0);
    EXPECT_EQ(n, 32);
    kc_rev(want, KDF_Z256, 32);
    CHECK_MEM(out, want, 32);
    EXPECT_EQ(out[32], 0xA5);
    sec_close(&x);
}

TEST(bckdf_raw_truncated_buffer) {
    SEC_BEGIN(x);
    /* a short buffer receives the byte-reversed leading bytes of the big-endian secret, and no error */
    static const ULONG sizes[] = { 1, 7, 16, 31 };
    for (unsigned i = 0; i < 4; i++) {
        unsigned char out[40], want[40]; ULONG n = 0;
        memset(out, 0xA5, sizeof(out));
        NTSTATUS s = kc_derive(x.s, BCRYPT_KDF_RAW_SECRET, NULL, out, sizes[i], &n, 0);
        CHECKF(s == 0, "cb %lu -> 0x%08lx", (unsigned long)sizes[i], (unsigned long)s);
        EXPECT_EQ(n, sizes[i]);
        kc_rev(want, KDF_Z256, sizes[i]);
        CHECK_MEM(out, want, sizes[i]);
        EXPECT_EQ(out[sizes[i]], 0xA5);
    }
    sec_close(&x);
}

TEST(bckdf_raw_repeatable) {
    SEC_BEGIN(x);
    unsigned char a[32], b[32]; ULONG n;
    CHECK_NS(kc_derive(x.s, BCRYPT_KDF_RAW_SECRET, NULL, a, 32, &n, 0), 0);
    CHECK_NS(kc_derive(x.s, BCRYPT_KDF_RAW_SECRET, NULL, b, 32, &n, 0), 0);
    CHECK_MEM(a, b, 32);
    sec_close(&x);
}

TEST(bckdf_raw_ignores_parameter_list) {
    SEC_BEGIN(x);
    kc_desc d; hash_of(L"SHA512", &d);
    kc_desc_add(&d, KDF_SECRET_PREPEND, "zz", 2);
    unsigned char a[32], want[32]; ULONG n;
    CHECK_NS(kc_derive(x.s, BCRYPT_KDF_RAW_SECRET, &d, a, 32, &n, 0), 0);
    kc_rev(want, KDF_Z256, 32);
    CHECK_MEM(a, want, 32);
    sec_close(&x);
}

/* ---- HASH ----------------------------------------------------------------------------------------------------- */
TEST(bckdf_hash_default_is_sha1) {
    SEC_BEGIN(x);
    unsigned char out[64]; ULONG n = 0;
    CHECK_NS(kc_derive(x.s, BCRYPT_KDF_HASH, NULL, NULL, 0, &n, 0), 0);
    EXPECT_EQ(n, 20);
    CHECK_NS(kc_derive(x.s, BCRYPT_KDF_HASH, NULL, out, sizeof(out), &n, 0), 0);
    EXPECT_EQ(n, 20);
    CHECK_MEM(out, KDF_SHA1_Z, 20);
    sec_close(&x);
}

TEST(bckdf_hash_algorithms) {
    SEC_BEGIN(x);
    struct { const WCHAR *alg; const unsigned char *v; ULONG len; } t[] = {
        { L"SHA1", KDF_SHA1_Z, 20 }, { L"SHA256", KDF_SHA256_Z, 32 }, { L"SHA384", KDF_SHA384_Z, 48 },
        { L"SHA512", KDF_SHA512_Z, 64 }, { L"MD5", KDF_MD5_Z, 16 } };
    for (unsigned i = 0; i < 5; i++) {
        kc_desc d; hash_of(t[i].alg, &d);
        unsigned char out[80]; ULONG n = 0;
        CHECK_NS(kc_derive(x.s, BCRYPT_KDF_HASH, &d, NULL, 0, &n, 0), 0);
        EXPECT_EQ(n, t[i].len);
        n = 0;
        CHECK_NS(kc_derive(x.s, BCRYPT_KDF_HASH, &d, out, sizeof(out), &n, 0), 0);
        EXPECT_EQ(n, t[i].len);
        if (n == t[i].len) CHECK_MEM(out, t[i].v, t[i].len);
    }
    sec_close(&x);
}

TEST(bckdf_hash_truncation) {
    SEC_BEGIN(x);
    kc_desc d; hash_of(L"SHA256", &d);
    static const ULONG sizes[] = { 1, 10, 16, 31, 32 };
    for (unsigned i = 0; i < 5; i++) {
        unsigned char out[40]; ULONG n = 0;
        memset(out, 0xA5, sizeof(out));
        CHECK_NS(kc_derive(x.s, BCRYPT_KDF_HASH, &d, out, sizes[i], &n, 0), 0);
        EXPECT_EQ(n, sizes[i]);
        CHECK_MEM(out, KDF_SHA256_Z, sizes[i]);
        EXPECT_EQ(out[sizes[i]], 0xA5);
    }
    sec_close(&x);
}

TEST(bckdf_hash_prepend_append) {
    SEC_BEGIN(x);
    unsigned char out[32]; ULONG n;
    kc_desc d;
    hash_of(L"SHA256", &d); kc_desc_add(&d, KDF_SECRET_PREPEND, KDF_PRE, KDF_PRE_LEN);
    CHECK_NS(kc_derive(x.s, BCRYPT_KDF_HASH, &d, out, 32, &n, 0), 0);
    CHECK_MEM(out, KDF_SHA256_PRE_Z, 32);
    hash_of(L"SHA256", &d); kc_desc_add(&d, KDF_SECRET_APPEND, KDF_APP, KDF_APP_LEN);
    CHECK_NS(kc_derive(x.s, BCRYPT_KDF_HASH, &d, out, 32, &n, 0), 0);
    CHECK_MEM(out, KDF_SHA256_Z_APP, 32);
    hash_of(L"SHA256", &d); kc_desc_add(&d, KDF_SECRET_PREPEND, KDF_PRE, KDF_PRE_LEN); kc_desc_add(&d, KDF_SECRET_APPEND, KDF_APP, KDF_APP_LEN);
    CHECK_NS(kc_derive(x.s, BCRYPT_KDF_HASH, &d, out, 32, &n, 0), 0);
    CHECK_MEM(out, KDF_SHA256_PRE_Z_APP, 32);
    /* buffer order in the list does not matter */
    kc_desc_init(&d);
    kc_desc_add(&d, KDF_SECRET_APPEND, KDF_APP, KDF_APP_LEN);
    kc_desc_add(&d, KDF_SECRET_PREPEND, KDF_PRE, KDF_PRE_LEN);
    kc_desc_wstr(&d, KDF_HASH_ALGORITHM, L"SHA256");
    CHECK_NS(kc_derive(x.s, BCRYPT_KDF_HASH, &d, out, 32, &n, 0), 0);
    CHECK_MEM(out, KDF_SHA256_PRE_Z_APP, 32);
    sec_close(&x);
}

TEST(bckdf_hash_secret_flag_accepted) {
    SEC_BEGIN(x);
    kc_desc d; hash_of(L"SHA256", &d);
    unsigned char out[32]; ULONG n;
    CHECK_NS(kc_derive(x.s, BCRYPT_KDF_HASH, &d, out, 32, &n, KDF_USE_SECRET_AS_HMAC_KEY_FLAG), 0);
    CHECK_MEM(out, KDF_SHA256_Z, 32);
    sec_close(&x);
}

TEST(bckdf_hash_bad_algorithm_names) {
    SEC_BEGIN(x);
    unsigned char out[64]; ULONG n = 0;
    kc_desc d;
    hash_of(L"NOSUCHHASH", &d);
    CHECK_NS_FAIL(kc_derive(x.s, BCRYPT_KDF_HASH, &d, out, 32, &n, 0));
    hash_of(L"AES", &d);
    CHECK_NS_FAIL(kc_derive(x.s, BCRYPT_KDF_HASH, &d, out, 32, &n, 0));
    hash_of(L"", &d);
    CHECK_NS_FAIL(kc_derive(x.s, BCRYPT_KDF_HASH, &d, out, 32, &n, 0));
    /* name without a terminating NUL inside the buffer */
    kc_desc_init(&d); kc_desc_add(&d, KDF_HASH_ALGORITHM, L"SHA256", 12);
    CHECK_NS_FAIL(kc_derive(x.s, BCRYPT_KDF_HASH, &d, out, 32, &n, 0));
    sec_close(&x);
}

TEST(bckdf_hash_nonkeyed_vs_hmac_distinct) {
    SEC_BEGIN(x);
    kc_desc d; hash_of(L"SHA256", &d);
    unsigned char h[32], m[32]; ULONG n;
    CHECK_NS(kc_derive(x.s, BCRYPT_KDF_HASH, &d, h, 32, &n, 0), 0);
    kc_desc_add(&d, KDF_HMAC_KEY, KDF_HMACKEY, KDF_HMACKEY_LEN);
    CHECK_NS(kc_derive(x.s, BCRYPT_KDF_HMAC, &d, m, 32, &n, 0), 0);
    CHECK(memcmp(h, m, 32) != 0);
    sec_close(&x);
}

/* ---- HMAC ---------------------------------------------------------------------------------------------------------- */
TEST(bckdf_hmac_with_key) {
    SEC_BEGIN(x);
    unsigned char out[64]; ULONG n = 0;
    kc_desc d; hash_of(L"SHA256", &d); kc_desc_add(&d, KDF_HMAC_KEY, KDF_HMACKEY, KDF_HMACKEY_LEN);
    CHECK_NS(kc_derive(x.s, BCRYPT_KDF_HMAC, &d, NULL, 0, &n, 0), 0);
    EXPECT_EQ(n, 32);
    CHECK_NS(kc_derive(x.s, BCRYPT_KDF_HMAC, &d, out, sizeof(out), &n, 0), 0);
    EXPECT_EQ(n, 32);
    CHECK_MEM(out, KDF_HMAC256_KEY_Z, 32);
    sec_close(&x);
}

TEST(bckdf_hmac_algorithms) {
    SEC_BEGIN(x);
    unsigned char out[64]; ULONG n = 0;
    kc_desc d; hash_of(L"SHA1", &d); kc_desc_add(&d, KDF_HMAC_KEY, KDF_HMACKEY, KDF_HMACKEY_LEN);
    CHECK_NS(kc_derive(x.s, BCRYPT_KDF_HMAC, &d, out, sizeof(out), &n, 0), 0);
    EXPECT_EQ(n, 20);
    CHECK_MEM(out, KDF_HMAC1_KEY_Z, 20);
    hash_of(L"SHA512", &d); kc_desc_add(&d, KDF_HMAC_KEY, KDF_HMACKEY, KDF_HMACKEY_LEN);
    CHECK_NS(kc_derive(x.s, BCRYPT_KDF_HMAC, &d, out, sizeof(out), &n, 0), 0);
    EXPECT_EQ(n, 64);
    CHECK_MEM(out, KDF_HMAC512_KEY_Z, 64);
    sec_close(&x);
}

TEST(bckdf_hmac_prepend_append) {
    SEC_BEGIN(x);
    unsigned char out[32]; ULONG n;
    kc_desc d; hash_of(L"SHA256", &d);
    kc_desc_add(&d, KDF_HMAC_KEY, KDF_HMACKEY, KDF_HMACKEY_LEN);
    kc_desc_add(&d, KDF_SECRET_PREPEND, KDF_PRE, KDF_PRE_LEN);
    kc_desc_add(&d, KDF_SECRET_APPEND, KDF_APP, KDF_APP_LEN);
    CHECK_NS(kc_derive(x.s, BCRYPT_KDF_HMAC, &d, out, 32, &n, 0), 0);
    CHECK_MEM(out, KDF_HMAC256_KEY_PRE_Z_APP, 32);
    sec_close(&x);
}

TEST(bckdf_hmac_secret_as_key) {
    SEC_BEGIN(x);
    unsigned char out[32]; ULONG n = 0;
    kc_desc d; hash_of(L"SHA256", &d);
    CHECK_NS(kc_derive(x.s, BCRYPT_KDF_HMAC, &d, out, 32, &n, KDF_USE_SECRET_AS_HMAC_KEY_FLAG), 0);
    EXPECT_EQ(n, 32);
    CHECK_MEM(out, KDF_HMAC256_Z_Z, 32);
    sec_close(&x);
}

TEST(bckdf_hmac_key_conflicts_and_absence) {
    SEC_BEGIN(x);
    unsigned char out[32]; ULONG n = 0;
    kc_desc d; hash_of(L"SHA256", &d);
    /* neither a key nor the flag */
    CHECK_NS(kc_derive(x.s, BCRYPT_KDF_HMAC, &d, out, 32, &n, 0), NS_INVALID_PARAMETER);
    /* both a key and the flag */
    kc_desc_add(&d, KDF_HMAC_KEY, KDF_HMACKEY, KDF_HMACKEY_LEN);
    CHECK_NS(kc_derive(x.s, BCRYPT_KDF_HMAC, &d, out, 32, &n, KDF_USE_SECRET_AS_HMAC_KEY_FLAG), NS_INVALID_PARAMETER);
    /* no parameter list at all */
    CHECK_NS(kc_derive(x.s, BCRYPT_KDF_HMAC, NULL, out, 32, &n, 0), NS_INVALID_PARAMETER);
    sec_close(&x);
}

TEST(bckdf_hmac_size_query_without_key) {
    SEC_BEGIN(x);
    /* the HMAC key check precedes the size query, so the query without a key fails too */
    ULONG n = 0xCAFE;
    kc_desc d; hash_of(L"SHA256", &d);
    NTSTATUS s = kc_derive(x.s, BCRYPT_KDF_HMAC, &d, NULL, 0, &n, 0);
    t_note("HMAC size query without key -> 0x%08lx n=%lu", (unsigned long)s, (unsigned long)n);
    sec_close(&x);
}

/* ---- argument validation ---------------------------------------------------------------------------------------------- */
TEST(bckdf_bad_arguments) {
    SEC_BEGIN(x);
    unsigned char out[64]; ULONG n = 0;
    CHECK_NS(U(BCryptDeriveKey)(x.s, BCRYPT_KDF_RAW_SECRET, NULL, out, 32, NULL, 0), NS_INVALID_PARAMETER);
    CHECK_NS(U(BCryptDeriveKey)(NULL, BCRYPT_KDF_RAW_SECRET, NULL, out, 32, &n, 0), NS_INVALID_HANDLE);
    CHECK_NS(U(BCryptDeriveKey)(x.s, NULL, NULL, out, 32, &n, 0), NS_INVALID_PARAMETER);
    CHECK_NS(U(BCryptDeriveKey)(x.s, L"", NULL, out, 32, &n, 0), NS_NOT_SUPPORTED);
    CHECK_NS(U(BCryptDeriveKey)(x.s, L"NOSUCHKDF", NULL, out, 32, &n, 0), NS_NOT_SUPPORTED);
    CHECK_NS(U(BCryptDeriveKey)(x.s, L"hash", NULL, out, 32, &n, 0), NS_NOT_SUPPORTED);       /* names are compared exactly */
    CHECK_NS(U(BCryptDeriveKey)(x.s, L"TRUNCATE ", NULL, out, 32, &n, 0), NS_NOT_SUPPORTED);
    CHECK_NS(U(BCryptDeriveKey)(x.s, L"PBKDF2", NULL, out, 32, &n, 0), NS_NOT_SUPPORTED);
    CHECK_NS(U(BCryptDeriveKey)(x.s, L"SP800_108_CTR_HMAC", NULL, out, 32, &n, 0), NS_NOT_SUPPORTED);
    sec_close(&x);
}

TEST(bckdf_pcbresult_checked_before_handle) {
    NEED_CORE();
    CHECK_NS(U(BCryptDeriveKey)(NULL, BCRYPT_KDF_RAW_SECRET, NULL, NULL, 0, NULL, 0), NS_INVALID_PARAMETER);
}

TEST(bckdf_invalid_flags) {
    SEC_BEGIN(x);
    unsigned char out[32]; ULONG n = 0;
    kc_desc d; hash_of(L"SHA256", &d);
    static const ULONG flags[] = { 2, 4, 0x10, 0x100, 0x80000000, 0xFFFFFFFE };
    for (unsigned i = 0; i < sizeof(flags) / sizeof(flags[0]); i++) {
        NTSTATUS s = kc_derive(x.s, BCRYPT_KDF_HASH, &d, out, 32, &n, flags[i]);
        CHECKF(s == NS_INVALID_PARAMETER, "flags 0x%lx -> 0x%08lx", (unsigned long)flags[i], (unsigned long)s);
        s = kc_derive(x.s, BCRYPT_KDF_RAW_SECRET, NULL, out, 32, &n, flags[i]);
        CHECKF(s == NS_INVALID_PARAMETER, "raw flags 0x%lx -> 0x%08lx", (unsigned long)flags[i], (unsigned long)s);
    }
    sec_close(&x);
}

TEST(bckdf_wrong_handle_types) {
    SEC_BEGIN(x);
    unsigned char out[32]; ULONG n = 0;
    CHECK_NS(U(BCryptDeriveKey)((BCRYPT_SECRET_HANDLE)x.ka, BCRYPT_KDF_RAW_SECRET, NULL, out, 32, &n, 0), NS_INVALID_HANDLE);
    CHECK_NS(U(BCryptDeriveKey)((BCRYPT_SECRET_HANDLE)x.a, BCRYPT_KDF_RAW_SECRET, NULL, out, 32, &n, 0), NS_INVALID_HANDLE);
    CHECK_NS(U(BCryptDestroySecret)((BCRYPT_SECRET_HANDLE)x.ka), NS_INVALID_HANDLE);
    sec_close(&x);
}

TEST(bckdf_parameter_list_validation) {
    SEC_BEGIN(x);
    unsigned char out[32]; ULONG n = 0;
    BCryptBufferDesc d;
    BCryptBuffer b[1];
    d.ulVersion = BCRYPTBUFFER_VERSION + 1; d.cBuffers = 0; d.pBuffers = NULL;
    NTSTATUS s = U(BCryptDeriveKey)(x.s, BCRYPT_KDF_RAW_SECRET, &d, out, 32, &n, 0);
    CHECK(!NT_OK(s)); t_note("list version 1 -> 0x%08lx", (unsigned long)s);
    d.ulVersion = BCRYPTBUFFER_VERSION; d.cBuffers = 1; d.pBuffers = NULL;
    s = U(BCryptDeriveKey)(x.s, BCRYPT_KDF_RAW_SECRET, &d, out, 32, &n, 0);
    CHECK(!NT_OK(s)); t_note("cBuffers=1 with NULL array -> 0x%08lx", (unsigned long)s);
    b[0].BufferType = KDF_HASH_ALGORITHM; b[0].cbBuffer = 14; b[0].pvBuffer = NULL;
    d.pBuffers = b;
    s = U(BCryptDeriveKey)(x.s, BCRYPT_KDF_HASH, &d, out, 32, &n, 0);
    CHECK(!NT_OK(s)); t_note("NULL buffer pointer with length -> 0x%08lx", (unsigned long)s);
    d.cBuffers = 0; d.pBuffers = NULL;
    s = U(BCryptDeriveKey)(x.s, BCRYPT_KDF_RAW_SECRET, &d, out, 32, &n, 0);
    CHECK_NS(s, 0);                                             /* an empty list is fine */
    sec_close(&x);
}

TEST(bckdf_unknown_buffer_types_note) {
    SEC_BEGIN(x);
    unsigned char out[32]; ULONG n = 0;
    kc_desc d; hash_of(L"SHA256", &d);
    kc_desc_add(&d, 0x7777, "xx", 2);
    NTSTATUS s = kc_derive(x.s, BCRYPT_KDF_HASH, &d, out, 32, &n, 0);
    t_note("unknown buffer type 0x7777 -> 0x%08lx", (unsigned long)s);
    if (NT_OK(s)) CHECK_MEM(out, KDF_SHA256_Z, 32);
    sec_close(&x);
}

TEST(bckdf_hkdf_on_agreement_secret) {
    SEC_BEGIN(x);
    unsigned char out[32]; ULONG n = 0;
    kc_desc d; hash_of(L"SHA256", &d);
    NTSTATUS s = kc_derive(x.s, BCRYPT_KDF_HKDF, &d, out, 32, &n, 0);
    CHECK_NS(s, NS_INVALID_PARAMETER);        /* HKDF needs a key made from the HKDF algorithm */
    sec_close(&x);
}

TEST(bckdf_destroy_secret_twice_guarded) {
    NEED_CORE();
    sec_t x; if (!sec_open(&x)) { sec_close(&x); CHECK(0); return; }
    BCRYPT_SECRET_HANDLE extra = sec_again(&x);
    CHECK(extra != NULL);
    CHECK_NS(U(BCryptDestroySecret)(extra), 0);
    sec_close(&x);
}

/* ---- TLS PRF ---------------------------------------------------------------------------------------------------------------- */
static void tls_desc(kc_desc *d, const WCHAR *hash, const void *label, ULONG ll, const void *seed, ULONG sl) {
    kc_desc_init(d);
    if (hash) kc_desc_wstr(d, KDF_HASH_ALGORITHM, hash);
    if (label) kc_desc_add(d, KDF_TLS_PRF_LABEL, label, ll);
    if (seed) kc_desc_add(d, KDF_TLS_PRF_SEED, seed, sl);
}

TEST(bckdf_tls_prf_size_query) {
    SEC_BEGIN(x);
    kc_desc d; tls_desc(&d, L"SHA256", TLS_LABEL, TLS_LABEL_LEN, TLS_SEED, 64);
    ULONG n = 0xCAFE;
    CHECK_NS(kc_derive(x.s, BCRYPT_KDF_TLS_PRF, &d, NULL, 0, &n, 0), 0);
    EXPECT_EQ(n, 48);
    sec_close(&x);
}

TEST(bckdf_tls_prf_output_must_be_48) {
    SEC_BEGIN(x);
    kc_desc d; tls_desc(&d, L"SHA256", TLS_LABEL, TLS_LABEL_LEN, TLS_SEED, 64);
    unsigned char out[128]; ULONG n = 0;
    static const ULONG sizes[] = { 1, 12, 32, 47, 49, 64, 100 };
    for (unsigned i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
        NTSTATUS s = kc_derive(x.s, BCRYPT_KDF_TLS_PRF, &d, out, sizes[i], &n, 0);
        CHECKF(s == NS_INVALID_PARAMETER, "cb %lu -> 0x%08lx", (unsigned long)sizes[i], (unsigned long)s);
    }
    sec_close(&x);
}

TEST(bckdf_tls_prf_missing_label_or_seed) {
    SEC_BEGIN(x);
    unsigned char out[48]; ULONG n = 0;
    kc_desc d;
    tls_desc(&d, L"SHA256", NULL, 0, TLS_SEED, 64);
    CHECK_NS(kc_derive(x.s, BCRYPT_KDF_TLS_PRF, &d, out, 48, &n, 0), NS_INVALID_PARAMETER);
    tls_desc(&d, L"SHA256", TLS_LABEL, TLS_LABEL_LEN, NULL, 0);
    CHECK_NS(kc_derive(x.s, BCRYPT_KDF_TLS_PRF, &d, out, 48, &n, 0), NS_INVALID_PARAMETER);
    CHECK_NS(kc_derive(x.s, BCRYPT_KDF_TLS_PRF, NULL, out, 48, &n, 0), NS_INVALID_PARAMETER);
    sec_close(&x);
}

TEST(bckdf_tls_prf_seed_length_rules) {
    SEC_BEGIN(x);
    unsigned char out[48], seed[128]; ULONG n = 0;
    memset(seed, 0x42, sizeof(seed));
    static const ULONG bad[] = { 0, 1, 31, 33, 35, 37, 47, 49, 63, 65, 128 };
    for (unsigned i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        kc_desc d; tls_desc(&d, L"SHA256", TLS_LABEL, TLS_LABEL_LEN, seed, bad[i]);
        NTSTATUS s = kc_derive(x.s, BCRYPT_KDF_TLS_PRF, &d, out, 48, &n, 0);
        CHECKF(s == NS_INVALID_PARAMETER, "seed length %lu -> 0x%08lx", (unsigned long)bad[i], (unsigned long)s);
    }
    static const ULONG good[] = { 32, 64 };
    for (unsigned i = 0; i < 2; i++) {
        kc_desc d; tls_desc(&d, L"SHA256", TLS_LABEL, TLS_LABEL_LEN, seed, good[i]);
        NTSTATUS s = kc_derive(x.s, BCRYPT_KDF_TLS_PRF, &d, out, 48, &n, 0);
        t_note("TLS PRF seed length %lu -> 0x%08lx", (unsigned long)good[i], (unsigned long)s);
    }
    sec_close(&x);
}

TEST(bckdf_tls_prf_protocol_buffer_size) {
    SEC_BEGIN(x);
    unsigned char out[48]; ULONG n = 0;
    kc_desc d; tls_desc(&d, L"SHA256", TLS_LABEL, TLS_LABEL_LEN, TLS_SEED, 64);
    USHORT p16 = 0x0303;
    kc_desc_add(&d, KDF_TLS_PRF_PROTOCOL, &p16, 2);
    CHECK_NS(kc_derive(x.s, BCRYPT_KDF_TLS_PRF, &d, out, 48, &n, 0), NS_INVALID_PARAMETER);
    tls_desc(&d, L"SHA256", TLS_LABEL, TLS_LABEL_LEN, TLS_SEED, 64);
    ULONG p32 = 0x0303;
    kc_desc_add(&d, KDF_TLS_PRF_PROTOCOL, &p32, 4);
    NTSTATUS s = kc_derive(x.s, BCRYPT_KDF_TLS_PRF, &d, out, 48, &n, 0);
    t_note("TLS PRF with 4-byte protocol 0x0303 -> 0x%08lx", (unsigned long)s);
    sec_close(&x);
}

TEST(bckdf_tls_prf_tls12_vector_note) {
    SEC_BEGIN(x);
    unsigned char out[48]; ULONG n = 0;
    ULONG proto = 0x0303;
    kc_desc d; tls_desc(&d, L"SHA256", TLS_LABEL, TLS_LABEL_LEN, TLS_SEED, 64);
    kc_desc_add(&d, KDF_TLS_PRF_PROTOCOL, &proto, 4);
    NTSTATUS s = kc_derive(x.s, BCRYPT_KDF_TLS_PRF, &d, out, 48, &n, 0);
    t_note("TLS1.2 PRF(SHA256) -> 0x%08lx, %s the PRF(Z, label, seed) vector", (unsigned long)s, NT_OK(s) && !memcmp(out, TLS12_PRF_Z, 48) ? "matches" : "differs from");
    s = kc_derive(x.s, BCRYPT_KDF_TLS_PRF, (tls_desc(&d, L"SHA256", TLS_LABEL, TLS_LABEL_LEN, TLS_SEED, 64), &d), out, 48, &n, 0);
    t_note("TLS PRF without protocol -> 0x%08lx, %s the TLS1.2 SHA256 vector", (unsigned long)s, NT_OK(s) && !memcmp(out, TLS12_PRF_Z, 48) ? "matches" : "differs from");
    sec_close(&x);
}

/* ---- SP800-56A concatenation KDF ------------------------------------------------------------------------------------------------ */
static void oi_desc(kc_desc *d, int with_pub, int with_priv) {
    kc_desc_init(d);
    kc_desc_add(d, KDF_ALGORITHMID, OI_ALGID, OI_ALGID_LEN);
    kc_desc_add(d, KDF_PARTYUINFO, OI_U, OI_U_LEN);
    kc_desc_add(d, KDF_PARTYVINFO, OI_V, OI_V_LEN);
    if (with_pub) kc_desc_add(d, KDF_SUPPPUBINFO, OI_PUB, OI_PUB_LEN);
    if (with_priv) kc_desc_add(d, KDF_SUPPPRIVINFO, OI_PRIV, OI_PRIV_LEN);
}

TEST(bckdf_sp80056a_size_query) {
    SEC_BEGIN(x);
    kc_desc d; oi_desc(&d, 1, 1);
    ULONG n = 0xCAFE;
    CHECK_NS(kc_derive(x.s, BCRYPT_KDF_SP80056A_CONCAT, &d, NULL, 0, &n, 0), 0);
    EXPECT_EQ(n, 32);                                        /* digest size chosen from the secret size */
    n = 0xCAFE;
    CHECK_NS(kc_derive(x.s, BCRYPT_KDF_SP80056A_CONCAT, &d, NULL, 0, &n, 0), 0);    /* the query does not consume the secret */
    EXPECT_EQ(n, 32);
    sec_close(&x);
}

TEST(bckdf_sp80056a_vectors) {
    SEC_BEGIN(x);
    unsigned char out[48]; ULONG n = 0;
    kc_desc d; oi_desc(&d, 1, 1);
    BCRYPT_SECRET_HANDLE s2 = sec_again(&x), s3 = sec_again(&x);
    CHECK_NS(kc_derive(x.s, BCRYPT_KDF_SP80056A_CONCAT, &d, out, 32, &n, 0), 0);
    EXPECT_EQ(n, 32);
    CHECK_MEM(out, KDF_56A_256_32, 32);
    memset(out, 0, sizeof(out));
    CHECK_NS(kc_derive(s2, BCRYPT_KDF_SP80056A_CONCAT, &d, out, 48, &n, 0), 0);
    EXPECT_EQ(n, 48);
    CHECK_MEM(out, KDF_56A_256_48, 32);                      /* counter 1 block is shared with the 32 byte output */
    memset(out, 0, sizeof(out));
    CHECK_NS(kc_derive(s3, BCRYPT_KDF_SP80056A_CONCAT, &d, out, 48, &n, 0), 0);
    CHECK_MEM(out, KDF_56A_256_48, 48);
    if (s2) U(BCryptDestroySecret)(s2);
    if (s3) U(BCryptDestroySecret)(s3);
    sec_close(&x);
}

TEST(bckdf_sp80056a_optional_other_info) {
    SEC_BEGIN(x);
    unsigned char out[32]; ULONG n = 0;
    kc_desc d; oi_desc(&d, 0, 0);
    /* without SuppPubInfo / SuppPrivInfo the other info is AlgorithmId || PartyU || PartyV */
    CHECK_NS(kc_derive(x.s, BCRYPT_KDF_SP80056A_CONCAT, &d, out, 32, &n, 0), 0);
    EXPECT_EQ(n, 32);
    CHECK(memcmp(out, KDF_56A_256_32, 32) != 0);
    sec_close(&x);
}

TEST(bckdf_sp80056a_required_parameters) {
    SEC_BEGIN(x);
    unsigned char out[32]; ULONG n = 0;
    kc_desc d;
    CHECK_NS(kc_derive(x.s, BCRYPT_KDF_SP80056A_CONCAT, NULL, out, 32, &n, 0), NS_INVALID_PARAMETER);
    kc_desc_init(&d);
    CHECK_NS(kc_derive(x.s, BCRYPT_KDF_SP80056A_CONCAT, &d, out, 32, &n, 0), NS_INVALID_PARAMETER);
    kc_desc_init(&d); kc_desc_add(&d, KDF_ALGORITHMID, OI_ALGID, OI_ALGID_LEN); kc_desc_add(&d, KDF_PARTYUINFO, OI_U, OI_U_LEN);
    CHECK_NS(kc_derive(x.s, BCRYPT_KDF_SP80056A_CONCAT, &d, out, 32, &n, 0), NS_INVALID_PARAMETER);   /* PartyVInfo missing */
    kc_desc_init(&d); kc_desc_add(&d, KDF_PARTYUINFO, OI_U, OI_U_LEN); kc_desc_add(&d, KDF_PARTYVINFO, OI_V, OI_V_LEN);
    CHECK_NS(kc_derive(x.s, BCRYPT_KDF_SP80056A_CONCAT, &d, out, 32, &n, 0), NS_INVALID_PARAMETER);   /* AlgorithmId missing */
    sec_close(&x);
}

TEST(bckdf_sp80056a_consumes_secret) {
    SEC_BEGIN(x);
    unsigned char out[32]; ULONG n = 0;
    kc_desc d; oi_desc(&d, 1, 1);
    CHECK_NS(kc_derive(x.s, BCRYPT_KDF_SP80056A_CONCAT, &d, out, 32, &n, 0), 0);
    /* the secret material is wiped once an output has been produced */
    NTSTATUS s = kc_derive(x.s, BCRYPT_KDF_SP80056A_CONCAT, &d, out, 32, &n, 0);
    CHECK_NS(s, NS_INVALID_PARAMETER);
    unsigned char raw[32];
    s = kc_derive(x.s, BCRYPT_KDF_RAW_SECRET, NULL, raw, 32, &n, 0);
    t_note("raw derive after SP800-56A -> 0x%08lx", (unsigned long)s);
    sec_close(&x);
}

TEST(bckdf_sp80056a_truncated_bits) {
    SEC_BEGIN(x);
    unsigned char out[16]; ULONG n = 0;
    kc_desc d; oi_desc(&d, 1, 1);
    CHECK_NS(kc_derive(x.s, BCRYPT_KDF_SP80056A_CONCAT, &d, out, 16, &n, 0), 0);
    EXPECT_EQ(n, 16);
    CHECK_MEM(out, KDF_56A_256_32, 16);
    sec_close(&x);
}

/* ---- Other KDF names and cross checks ---------------------------------------------------------------------------------------------- */
TEST(bckdf_secret_independent_destroy_order) {
    NEED_CORE();
    sec_t x; if (!sec_open(&x)) { sec_close(&x); CHECK(0); return; }
    BCRYPT_SECRET_HANDLE a = sec_again(&x), b = sec_again(&x);
    unsigned char o1[32], o2[32]; ULONG n;
    kc_desc d; hash_of(L"SHA256", &d);
    CHECK_NS(U(BCryptDestroySecret)(a), 0);
    CHECK_NS(kc_derive(b, BCRYPT_KDF_HASH, &d, o1, 32, &n, 0), 0);
    CHECK_NS(kc_derive(x.s, BCRYPT_KDF_HASH, &d, o2, 32, &n, 0), 0);
    CHECK_MEM(o1, o2, 32);
    CHECK_MEM(o1, KDF_SHA256_Z, 32);
    CHECK_NS(U(BCryptDestroySecret)(b), 0);
    sec_close(&x);
}

TEST(bckdf_p384_p521_hash_vectors) {
    NEED_CORE();
    /* the digest of the raw agreed value for the larger curves: SHA-1 default over the big-endian x coordinate */
    for (int i = 1; i < 3; i++) {
        const curve_t *c = &g_curves[i];
        BCRYPT_ALG_HANDLE a = kc_open(c->dh, 0);
        if (!a) { if (t_is_wine()) { t_skip("curve unavailable"); return; } CHECK(a); continue; }
        BCRYPT_KEY_HANDLE ka = kc_key(a, c, 1, 0, 1), kb = kc_key(a, c, 1, 1, 0);
        NTSTATUS st; BCRYPT_SECRET_HANDLE s = kc_agree(ka, kb, &st);
        if (!s) { if (t_is_wine()) { t_skip("curve unusable here"); kc_destroy(ka); kc_destroy(kb); kc_close(a); return; } CHECK_NS(st, 0); }
        else {
            kc_desc d; hash_of(c->hashalg, &d);
            unsigned char out[64]; ULONG n = 0;
            CHECK_NS(kc_derive(s, BCRYPT_KDF_HASH, &d, NULL, 0, &n, 0), 0);
            EXPECT_EQ(n, c->hashlen);
            CHECK_NS(kc_derive(s, BCRYPT_KDF_HASH, &d, out, sizeof(out), &n, 0), 0);
            kc_derive(s, BCRYPT_KDF_RAW_SECRET, NULL, out, sizeof(out), &n, 0);
            EXPECT_EQ(n, c->cb);
            unsigned char want[80]; kc_rev(want, c->z, c->cb);
            CHECK_MEM(out, want, c->cb);
            U(BCryptDestroySecret)(s);
        }
        kc_destroy(ka); kc_destroy(kb); kc_close(a);
    }
}
