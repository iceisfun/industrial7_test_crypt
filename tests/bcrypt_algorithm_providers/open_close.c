/* BCryptOpenAlgorithmProvider / BCryptCloseAlgorithmProvider conformance (area bcrypt_algorithm_providers). */
#include "ap.h"

/* ---------- per-algorithm: open with default / primitive provider, bad flag, reopen ---------- */
#define SENTINEL ((BCRYPT_ALG_HANDLE)(ULONG_PTR)0x1234567890ull)

static void do_open(const struct algd *a, LPCWSTR impl) {
    NEED_CORE();
    BCRYPT_ALG_HANDLE h = SENTINEL;
    NTSTATUS s = AP_OPEN(&h, a->id, impl, 0);
    if (s < 0 && !a->hard) { t_note("%ls: open failed 0x%08lx (not mandatory)", a->id, (unsigned long)s); return; }
    NT_OK(s);
    if (s < 0) return;
    CHECK(h != NULL && h != SENTINEL);
    CHECK(((ULONG_PTR)h & 0xf) != 1);            /* real handles are never pseudo-handle shaped */
    CHECK(((ULONG_PTR)h & 7) == 0);              /* heap pointers, 8-byte aligned */
    NT_OK(AP_CLOSE(h));
}
static void do_flag1(const struct algd *a) {
    NEED_CORE();
    BCRYPT_ALG_HANDLE h = SENTINEL;
    NT_EQ(AP_OPEN(&h, a->id, NULL, 1), AP_INVALID_PARAM);
    CHECK(h == SENTINEL);                         /* output untouched on failure */
    h = SENTINEL;
    NT_EQ(AP_OPEN(&h, a->id, MS_PRIMITIVE_PROVIDER, 1), AP_INVALID_PARAM);
    CHECK(h == SENTINEL);
}
static void do_reopen(const struct algd *a) {
    NEED_CORE();
    BCRYPT_ALG_HANDLE h1 = NULL, h2 = NULL;
    NTSTATUS s = AP_OPEN(&h1, a->id, NULL, 0);
    if (s < 0) { if (a->hard) NT_OK(s); return; }
    NT_OK(AP_OPEN(&h2, a->id, NULL, 0));
    CHECK(h1 != h2);                               /* every open allocates a distinct object */
    NT_OK(AP_CLOSE(h1));
    WCHAR nm[64]; ULONG cb = 0;
    NT_OK(ap_getstr(h2, BCRYPT_ALGORITHM_NAME, nm, 64, &cb));   /* second handle survives closing the first */
    NT_OK(AP_CLOSE(h2));
}
#define GEN_OPEN(tag, ...) \
  TEST(ap_open_##tag)     { do_open(&g_algs[A_##tag], NULL); } \
  TEST(ap_openprim_##tag) { do_open(&g_algs[A_##tag], MS_PRIMITIVE_PROVIDER); } \
  TEST(ap_openflag1_##tag){ do_flag1(&g_algs[A_##tag]); } \
  TEST(ap_reopen_##tag)   { do_reopen(&g_algs[A_##tag]); }
ALG_LIST(GEN_OPEN)

/* ---------- argument validation ---------- */
TEST(ap_open_null_phandle) {
    NEED_CORE();
    NT_EQ(AP_OPEN(NULL, BCRYPT_AES_ALGORITHM, NULL, 0), AP_INVALID_PARAM);
    NT_EQ(AP_OPEN(NULL, BCRYPT_AES_ALGORITHM, MS_PRIMITIVE_PROVIDER, 0), AP_INVALID_PARAM);
    NT_EQ(AP_OPEN(NULL, NULL, NULL, 0), AP_INVALID_PARAM);
}
TEST(ap_open_null_algid) {
    NEED_CORE();
    BCRYPT_ALG_HANDLE h = SENTINEL;
    NT_EQ(AP_OPEN(&h, NULL, NULL, 0), AP_INVALID_PARAM);
    CHECK(h == SENTINEL);
    NT_EQ(AP_OPEN(&h, NULL, MS_PRIMITIVE_PROVIDER, 0), AP_INVALID_PARAM);
    CHECK(h == SENTINEL);
}
TEST(ap_open_flag_bit0_rejected_even_with_valid_args) {
    NEED_CORE();
    static const ULONG fl[] = { 1, 1 | BCRYPT_ALG_HANDLE_HMAC_FLAG, 1 | BCRYPT_HASH_REUSABLE_FLAG, 0x81, 0xffffffffu };
    for (unsigned i = 0; i < sizeof(fl) / sizeof(fl[0]); i++) {
        BCRYPT_ALG_HANDLE h = SENTINEL;
        NTSTATUS s = AP_OPEN(&h, BCRYPT_SHA256_ALGORITHM, NULL, fl[i]);
        NT_EQ(s, AP_INVALID_PARAM);
        CHECK(h == SENTINEL);
    }
}
TEST(ap_open_empty_algid) {
    NEED_CORE();
    BCRYPT_ALG_HANDLE h = SENTINEL;
    NTSTATUS s = AP_OPEN(&h, L"", NULL, 0);
    NT_FAILED(s);
    t_note("empty algorithm id -> 0x%08lx", (unsigned long)s);
    if (s >= 0) AP_CLOSE(h);
}
TEST(ap_open_unknown_algid) {
    NEED_CORE();
    static const WCHAR *const bad[] = { L"NoSuchAlgorithm", L"AES256", L"SHA-256", L"SHA2", L"RSA2048", L"ECDSA_P257", L" AES", L"AES " };
    for (unsigned i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        BCRYPT_ALG_HANDLE h = SENTINEL;
        NTSTATUS s = AP_OPEN(&h, bad[i], NULL, 0);
        NT_FAILED(s);
        CHECK(h == SENTINEL);
        if (i == 0) NT_EQ(s, AP_NOT_FOUND);       /* unknown algorithm: STATUS_NOT_FOUND */
        else t_note("%ls -> 0x%08lx", bad[i], (unsigned long)s);
        if (s >= 0) AP_CLOSE(h);
    }
}
TEST(ap_open_long_algid_rejected) {
    NEED_CORE();
    static WCHAR big[600];
    for (int i = 0; i < 599; i++) big[i] = L'A';
    big[599] = 0;
    BCRYPT_ALG_HANDLE h = SENTINEL;
    NTSTATUS s = AP_OPEN(&h, big, NULL, 0);
    NT_FAILED(s);
    t_note("599-char algorithm id -> 0x%08lx", (unsigned long)s);
    if (s >= 0) AP_CLOSE(h);
}
TEST(ap_open_bogus_provider) {
    NEED_CORE();
    static const WCHAR *const bad[] = { L"Microsoft No Such Provider", L"Microsoft Primitive Provide", L"Microsoft Primitive Provider 2" };
    for (unsigned i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        BCRYPT_ALG_HANDLE h = SENTINEL;
        NTSTATUS s = AP_OPEN(&h, BCRYPT_AES_ALGORITHM, bad[i], 0);
        NT_FAILED(s);
        t_note("provider \"%ls\" -> 0x%08lx", bad[i], (unsigned long)s);
        if (s >= 0) AP_CLOSE(h);
    }
}
TEST(ap_open_bogus_provider_bogus_alg) {
    NEED_CORE();
    BCRYPT_ALG_HANDLE h = SENTINEL;
    NTSTATUS s = AP_OPEN(&h, L"NoSuchAlgorithm", L"Microsoft No Such Provider", 0);
    NT_FAILED(s);
    t_note("bogus alg + bogus provider -> 0x%08lx", (unsigned long)s);
}
TEST(ap_open_empty_provider) {
    NEED_CORE();
    BCRYPT_ALG_HANDLE h = NULL;
    NTSTATUS s = AP_OPEN(&h, BCRYPT_AES_ALGORITHM, L"", 0);
    t_note("empty provider string -> 0x%08lx", (unsigned long)s);
    if (s >= 0) { CHECK(h != NULL); AP_CLOSE(h); }
}
TEST(ap_open_provider_name_case) {
    NEED_CORE();
    BCRYPT_ALG_HANDLE h = NULL;
    NTSTATUS s = AP_OPEN(&h, BCRYPT_AES_ALGORITHM, L"microsoft primitive provider", 0);
    t_note("lower-case provider name -> 0x%08lx", (unsigned long)s);
    if (s >= 0) AP_CLOSE(h);
    h = NULL;
    s = AP_OPEN(&h, L"aes", NULL, 0);
    t_note("lower-case algorithm id -> 0x%08lx", (unsigned long)s);
    if (s >= 0) AP_CLOSE(h);
}
TEST(ap_open_platform_crypto_provider) {
    NEED_CORE();
    BCRYPT_ALG_HANDLE h = SENTINEL;
    /* the Platform Crypto Provider needs a TPM: either outcome is legal, but it must not leak a handle on failure */
    NTSTATUS s = AP_OPEN(&h, BCRYPT_RSA_ALGORITHM, MS_PLATFORM_CRYPTO_PROVIDER, 0);
    t_note("MS_PLATFORM_CRYPTO_PROVIDER RSA -> 0x%08lx", (unsigned long)s);
    if (s >= 0) { CHECK(h != NULL && h != SENTINEL); NT_OK(AP_CLOSE(h)); }
    else CHECK(h == SENTINEL);
    h = SENTINEL;
    s = AP_OPEN(&h, BCRYPT_AES_ALGORITHM, MS_PLATFORM_CRYPTO_PROVIDER, 0);
    t_note("MS_PLATFORM_CRYPTO_PROVIDER AES -> 0x%08lx", (unsigned long)s);
    if (s >= 0) AP_CLOSE(h);
}
TEST(ap_open_primitive_provider_unsupported_alg) {
    NEED_CORE();
    BCRYPT_ALG_HANDLE h = SENTINEL;
    NTSTATUS s = AP_OPEN(&h, L"NoSuchAlgorithm", MS_PRIMITIVE_PROVIDER, 0);
    NT_FAILED(s);
    t_note("primitive provider + unknown alg -> 0x%08lx", (unsigned long)s);
}

/* ---------- flags ---------- */
static const struct algd *hash_algs[] = { &g_algs[A_md2], &g_algs[A_md4], &g_algs[A_md5], &g_algs[A_sha1], &g_algs[A_sha256], &g_algs[A_sha384], &g_algs[A_sha512] };
#define NHASH ((int)(sizeof(hash_algs) / sizeof(hash_algs[0])))

TEST(ap_open_hmac_flag_on_hash_algs) {
    NEED_CORE();
    for (int i = 0; i < NHASH; i++) {
        BCRYPT_ALG_HANDLE h = NULL;
        NT_OK(AP_OPEN(&h, hash_algs[i]->id, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG));
        if (!h) continue;
        ULONG v = 0, cb = 0;
        NT_OK(ap_getdw(h, BCRYPT_HASH_LENGTH, &v, &cb));
        EXPECT_EQ(v, hash_algs[i]->hlen);
        EXPECT_EQ(cb, 4);
        NT_OK(ap_getdw(h, BCRYPT_IS_KEYED_HASH, &v, &cb));   /* an HMAC handle reports itself as keyed */
        EXPECT_EQ(v, 1);
        EXPECT_EQ(cb, 4);
        NT_OK(AP_CLOSE(h));
    }
}
TEST(ap_open_plain_hash_is_not_keyed) {
    NEED_CORE();
    for (int i = 0; i < NHASH; i++) {
        BCRYPT_ALG_HANDLE h = NULL;
        NT_OK(AP_OPEN(&h, hash_algs[i]->id, NULL, 0));
        if (!h) continue;
        ULONG v = 77, cb = 0;
        NT_OK(ap_getdw(h, BCRYPT_IS_KEYED_HASH, &v, &cb));
        EXPECT_EQ(v, 0);
        EXPECT_EQ(cb, 4);
        NT_OK(AP_CLOSE(h));
    }
}
TEST(ap_open_hmac_objectlength_larger_than_plain) {
    NEED_CORE();
    for (int i = 0; i < NHASH; i++) {
        BCRYPT_ALG_HANDLE hp = NULL, hm = NULL;
        NT_OK(AP_OPEN(&hp, hash_algs[i]->id, NULL, 0));
        NT_OK(AP_OPEN(&hm, hash_algs[i]->id, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG));
        ULONG lp = 0, lm = 0, cb;
        if (hp && hm) {
            NT_OK(ap_getdw(hp, BCRYPT_OBJECT_LENGTH, &lp, &cb));
            NT_OK(ap_getdw(hm, BCRYPT_OBJECT_LENGTH, &lm, &cb));
            CHECK(lp > 0);
            CHECK(lm > lp);       /* HMAC keeps inner and outer state */
        }
        if (hp) AP_CLOSE(hp);
        if (hm) AP_CLOSE(hm);
    }
}
TEST(ap_open_reusable_flag_on_hash_algs) {
    NEED_CORE();
    for (int i = 0; i < NHASH; i++) {
        BCRYPT_ALG_HANDLE h = NULL, hp = NULL;
        NT_OK(AP_OPEN(&h, hash_algs[i]->id, NULL, BCRYPT_HASH_REUSABLE_FLAG));
        NT_OK(AP_OPEN(&hp, hash_algs[i]->id, NULL, 0));
        ULONG v = 77, cb = 0;
        if (h) { NT_OK(ap_getdw(h, BCRYPT_IS_REUSABLE_HASH, &v, &cb)); EXPECT_EQ(v, 1); EXPECT_EQ(cb, 4); AP_CLOSE(h); }
        v = 77;
        if (hp) { NT_OK(ap_getdw(hp, BCRYPT_IS_REUSABLE_HASH, &v, &cb)); EXPECT_EQ(v, 0); EXPECT_EQ(cb, 4); AP_CLOSE(hp); }
    }
}
TEST(ap_open_hmac_and_reusable_combined) {
    NEED_CORE();
    BCRYPT_ALG_HANDLE h = NULL;
    NT_OK(AP_OPEN(&h, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG | BCRYPT_HASH_REUSABLE_FLAG));
    if (!h) return;
    ULONG v = 0, cb;
    NT_OK(ap_getdw(h, BCRYPT_IS_KEYED_HASH, &v, &cb)); EXPECT_EQ(v, 1);
    NT_OK(ap_getdw(h, BCRYPT_IS_REUSABLE_HASH, &v, &cb)); EXPECT_EQ(v, 1);
    NT_OK(AP_CLOSE(h));
}
TEST(ap_open_hash_flags_on_nonhash_algs) {
    NEED_CORE();
    static const struct { const WCHAR *id; ULONG fl; } c[] = {
        { BCRYPT_AES_ALGORITHM, BCRYPT_ALG_HANDLE_HMAC_FLAG }, { BCRYPT_AES_ALGORITHM, BCRYPT_HASH_REUSABLE_FLAG },
        { BCRYPT_RSA_ALGORITHM, BCRYPT_ALG_HANDLE_HMAC_FLAG }, { BCRYPT_RNG_ALGORITHM, BCRYPT_ALG_HANDLE_HMAC_FLAG },
        { BCRYPT_ECDSA_P256_ALGORITHM, BCRYPT_ALG_HANDLE_HMAC_FLAG }, { BCRYPT_PBKDF2_ALGORITHM, BCRYPT_HASH_REUSABLE_FLAG },
    };
    for (unsigned i = 0; i < sizeof(c) / sizeof(c[0]); i++) {
        BCRYPT_ALG_HANDLE h = SENTINEL;
        NTSTATUS s = AP_OPEN(&h, c[i].id, NULL, c[i].fl);
        t_note("%ls flags=0x%lx -> 0x%08lx", c[i].id, (unsigned long)c[i].fl, (unsigned long)s);
        if (s >= 0) AP_CLOSE(h); else CHECK(h == SENTINEL);
    }
}
TEST(ap_open_capi_aes_flag) {
    NEED_CORE();
    BCRYPT_ALG_HANDLE h = NULL;
    NTSTATUS s = AP_OPEN(&h, BCRYPT_AES_ALGORITHM, NULL, BCRYPT_CAPI_AES_FLAG);
    t_note("AES + BCRYPT_CAPI_AES_FLAG -> 0x%08lx", (unsigned long)s);
    if (s >= 0) { ULONG v, cb; NT_OK(ap_getdw(h, BCRYPT_BLOCK_LENGTH, &v, &cb)); EXPECT_EQ(v, 16); NT_OK(AP_CLOSE(h)); }
}
TEST(ap_open_unknown_flag_bits) {
    NEED_CORE();
    static const ULONG fl[] = { 0x2, 0x4, 0x40, 0x80, 0x100, 0x80000000u };
    for (unsigned i = 0; i < sizeof(fl) / sizeof(fl[0]); i++) {
        BCRYPT_ALG_HANDLE h = SENTINEL;
        NTSTATUS s = AP_OPEN(&h, BCRYPT_SHA256_ALGORITHM, NULL, fl[i]);
        t_note("SHA256 flags=0x%lx -> 0x%08lx", (unsigned long)fl[i], (unsigned long)s);
        if (s >= 0) AP_CLOSE(h); else CHECK(h == SENTINEL);
    }
}

/* ---------- close ---------- */
TEST(ap_close_null_handle) {
    NEED_CORE();
    NT_EQ(AP_CLOSE(NULL), AP_INVALID_HANDLE);
    NT_EQ(U(BCryptCloseAlgorithmProvider)(NULL, 0xffffffffu), AP_INVALID_HANDLE);
}
TEST(ap_close_ignores_flags) {
    NEED_CORE();
    BCRYPT_ALG_HANDLE h = NULL;
    NT_OK(AP_OPEN(&h, BCRYPT_SHA256_ALGORITHM, NULL, 0));
    if (!h) return;
    NT_OK(U(BCryptCloseAlgorithmProvider)(h, 0xffffffffu));      /* dwFlags is not consulted */
}
TEST(ap_close_double_close) {
    NEED_CORE();
    BCRYPT_ALG_HANDLE h = NULL;
    NT_OK(AP_OPEN(&h, BCRYPT_AES_ALGORITHM, NULL, 0));
    if (!h) return;
    NT_OK(AP_CLOSE(h));
    /* the object header is zeroed before it is freed, so a stale handle fails validation */
    NTSTATUS s2 = AP_CLOSE(h);          /* stale heap memory: only the failure is guaranteed */
    NT_FAILED(s2);
    t_note("double close -> 0x%08lx", (unsigned long)s2);
}
TEST(ap_close_then_getprop_and_setprop_fail) {
    NEED_CORE();
    BCRYPT_ALG_HANDLE h = NULL;
    NT_OK(AP_OPEN(&h, BCRYPT_AES_ALGORITHM, NULL, 0));
    if (!h) return;
    NT_OK(AP_CLOSE(h));
    ULONG v = 0, cb = 0;
    NT_FAILED(ap_getdw(h, BCRYPT_BLOCK_LENGTH, &v, &cb));
    NT_FAILED(AP_SET(h, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC)));
}
TEST(ap_close_pseudo_handle_is_invalid) {
    NEED_CORE();
    static const ULONG_PTR ph[] = { 0x01, 0x21, 0x41, 0x51, 0x61, 0x81, 0x1a1, 0x1e1, 0x2e1, 0x391 };
    for (unsigned i = 0; i < sizeof(ph) / sizeof(ph[0]); i++) {
        NT_EQ(AP_CLOSE((BCRYPT_ALG_HANDLE)ph[i]), AP_INVALID_HANDLE);
    }
    /* pseudo-handles stay usable after the failed close */
    ULONG v = 0, cb;
    NT_OK(ap_getdw((BCRYPT_ALG_HANDLE)(ULONG_PTR)0x41, BCRYPT_HASH_LENGTH, &v, &cb));
    EXPECT_EQ(v, 32);
}
TEST(ap_close_hash_handle_is_wrong_type) {
    NEED_CORE(); REQUIRE(U(BCryptCreateHash)); REQUIRE(U(BCryptDestroyHash));
    BCRYPT_ALG_HANDLE a = NULL; BCRYPT_HASH_HANDLE hh = NULL;
    NT_OK(AP_OPEN(&a, BCRYPT_SHA256_ALGORITHM, NULL, 0));
    if (!a) return;
    NT_OK(U(BCryptCreateHash)(a, &hh, NULL, 0, NULL, 0, 0));
    if (hh) {
        NT_EQ(U(BCryptCloseAlgorithmProvider)((BCRYPT_ALG_HANDLE)hh, 0), AP_INVALID_HANDLE);
        NT_OK(U(BCryptDestroyHash)(hh));
    }
    NT_OK(AP_CLOSE(a));
}
TEST(ap_close_key_handle_is_wrong_type) {
    NEED_CORE(); REQUIRE(U(BCryptGenerateSymmetricKey)); REQUIRE(U(BCryptDestroyKey));
    BCRYPT_ALG_HANDLE a = NULL; BCRYPT_KEY_HANDLE k = NULL;
    UCHAR secret[16] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 };
    NT_OK(AP_OPEN(&a, BCRYPT_AES_ALGORITHM, NULL, 0));
    if (!a) return;
    NT_OK(U(BCryptGenerateSymmetricKey)(a, &k, NULL, 0, secret, sizeof(secret), 0));
    if (k) {
        NT_EQ(U(BCryptCloseAlgorithmProvider)((BCRYPT_ALG_HANDLE)k, 0), AP_INVALID_HANDLE);
        NT_OK(U(BCryptDestroyKey)(k));
    }
    NT_OK(AP_CLOSE(a));
}
TEST(ap_close_with_live_key_keeps_key_usable) {
    NEED_CORE(); REQUIRE(U(BCryptGenerateSymmetricKey)); REQUIRE(U(BCryptDestroyKey)); REQUIRE(U(BCryptEncrypt));
    BCRYPT_ALG_HANDLE a = NULL; BCRYPT_KEY_HANDLE k = NULL;
    UCHAR secret[16] = { 0 }, pt[16] = { 0 }, ct[16];
    ULONG n = 0;
    NT_OK(AP_OPEN(&a, BCRYPT_AES_ALGORITHM, NULL, 0));
    if (!a) return;
    NT_OK(AP_SET(a, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_ECB, sizeof(BCRYPT_CHAIN_MODE_ECB)));
    NT_OK(U(BCryptGenerateSymmetricKey)(a, &k, NULL, 0, secret, sizeof(secret), 0));
    NT_OK(AP_CLOSE(a));                 /* a key keeps the provider alive */
    if (!k) return;
    NT_OK(U(BCryptEncrypt)(k, pt, 16, NULL, NULL, 0, ct, 16, &n, 0));
    EXPECT_EQ(n, 16);
    /* AES-128 ECB of an all-zero block under an all-zero key (FIPS-197 / NIST known answer) */
    static const UCHAR kat[16] = { 0x66,0xe9,0x4b,0xd4,0xef,0x8a,0x2c,0x3b,0x88,0x4c,0xfa,0x59,0xca,0x34,0x2b,0x2e };
    CHECK(memcmp(ct, kat, 16) == 0);
    NT_OK(U(BCryptDestroyKey)(k));
}

/* ---------- lifetime / threading ---------- */
static DWORD WINAPI close_thread(LPVOID p) {
    BCRYPT_ALG_HANDLE h = (BCRYPT_ALG_HANDLE)p;
    return (DWORD)U(BCryptCloseAlgorithmProvider)(h, 0);
}
TEST(ap_close_from_other_thread) {
    NEED_CORE();
    BCRYPT_ALG_HANDLE h = NULL;
    NT_OK(AP_OPEN(&h, BCRYPT_SHA1_ALGORITHM, NULL, 0));
    if (!h) return;
    ULONG v, cb;
    NT_OK(ap_getdw(h, BCRYPT_HASH_LENGTH, &v, &cb));
    EXPECT_EQ(v, 20);
    HANDLE th = CreateThread(NULL, 0, close_thread, h, 0, NULL);
    CHECK(th != NULL);
    if (th) {
        DWORD w = WaitForSingleObject(th, 10000), ec = 0xffffffff;
        EXPECT_EQ(w, WAIT_OBJECT_0);
        GetExitCodeThread(th, &ec);
        EXPECT_EQ(ec, 0);
        CloseHandle(th);
    }
}
static DWORD WINAPI open_thread(LPVOID p) {
    BCRYPT_ALG_HANDLE *out = (BCRYPT_ALG_HANDLE *)p;
    return (DWORD)U(BCryptOpenAlgorithmProvider)(out, BCRYPT_SHA256_ALGORITHM, NULL, 0);
}
TEST(ap_handle_opened_in_thread_usable_in_main) {
    NEED_CORE();
    BCRYPT_ALG_HANDLE h = NULL;
    HANDLE th = CreateThread(NULL, 0, open_thread, &h, 0, NULL);
    CHECK(th != NULL);
    if (!th) return;
    EXPECT_EQ(WaitForSingleObject(th, 10000), WAIT_OBJECT_0);
    DWORD ec = 1; GetExitCodeThread(th, &ec); CloseHandle(th);
    EXPECT_EQ(ec, 0);
    if (!h) return;
    ULONG v, cb;
    NT_OK(ap_getdw(h, BCRYPT_HASH_LENGTH, &v, &cb));
    EXPECT_EQ(v, 32);
    NT_OK(AP_CLOSE(h));
}
TEST(ap_open_close_many_handles) {
    NEED_CORE();
    enum { N = 128 };
    BCRYPT_ALG_HANDLE hs[N];
    int ok = 0;
    for (int i = 0; i < N; i++) { hs[i] = NULL; if (AP_OPEN(&hs[i], i & 1 ? BCRYPT_AES_ALGORITHM : BCRYPT_SHA256_ALGORITHM, NULL, 0) >= 0) ok++; }
    EXPECT_EQ(ok, N);
    for (int i = 0; i < N; i++) for (int j = i + 1; j < N; j++) if (hs[i] && hs[i] == hs[j]) { CHECK(0); }
    for (int i = 0; i < N; i++) if (hs[i]) NT_OK(AP_CLOSE(hs[i]));
}
TEST(ap_open_close_loop) {
    NEED_CORE();
    int bad = 0;
    for (int i = 0; i < 2000; i++) {
        BCRYPT_ALG_HANDLE h = NULL;
        if (AP_OPEN(&h, BCRYPT_SHA256_ALGORITHM, NULL, 0) < 0) { bad++; break; }
        if (AP_CLOSE(h) < 0) { bad++; break; }
    }
    EXPECT_EQ(bad, 0);
}
TEST(ap_open_every_hard_alg_simultaneously) {
    NEED_CORE();
    BCRYPT_ALG_HANDLE hs[A_COUNT];
    memset(hs, 0, sizeof(hs));
    for (int i = 0; i < A_COUNT; i++) {
        NTSTATUS s = ap_open_alg(&g_algs[i], &hs[i], 0);
        if (g_algs[i].hard) NT_OK(s);
    }
    /* independent objects: each reports its own algorithm name */
    for (int i = 0; i < A_COUNT; i++) {
        if (!hs[i]) continue;
        WCHAR nm[64]; ULONG cb;
        if (ap_getstr(hs[i], BCRYPT_ALGORITHM_NAME, nm, 64, &cb) >= 0 && g_algs[i].fam != F_ECDSA && g_algs[i].fam != F_ECDH)
            EXPECT_EQ(lstrcmpW(nm, g_algs[i].id), 0);
    }
    for (int i = 0; i < A_COUNT; i++) if (hs[i]) NT_OK(AP_CLOSE(hs[i]));
}
TEST(ap_open_via_forwarder_module_consistent) {
    /* bcrypt.dll is the home of the export; the exports of other crypt modules must not shadow it */
    REQUIRE(UIN("bcrypt.dll", BCryptOpenAlgorithmProvider));
    REQUIRE(UIN("bcrypt.dll", BCryptCloseAlgorithmProvider));
    BCRYPT_ALG_HANDLE h = NULL;
    NT_OK(UIN("bcrypt.dll", BCryptOpenAlgorithmProvider)(&h, BCRYPT_MD5_ALGORITHM, NULL, 0));
    if (h) NT_OK(UIN("bcrypt.dll", BCryptCloseAlgorithmProvider)(h, 0));
}
TEST(ap_freebuffer_null_is_noop) {
    REQUIRE(U(BCryptFreeBuffer));
    U(BCryptFreeBuffer)(NULL);
    CHECK(1);
}
