/* BCryptGenRandom: handle protocol, flags, sizes, statistical sanity. */
#include "rng_common.h"

#define GEN(h, b, n, f) U(BCryptGenRandom)((h), (b), (n), (f))

TEST(rngg_null_handle_flags0_null_buffer) {
    REQUIRE(U(BCryptGenRandom));
    EQ_NT(GEN(NULL, NULL, 0, 0), NS_INVALID_HANDLE);
}
TEST(rngg_null_handle_flags0_zero_len) {
    REQUIRE(U(BCryptGenRandom));
    unsigned char b[16];
    EQ_NT(GEN(NULL, b, 0, 0), NS_INVALID_HANDLE);
}
TEST(rngg_null_handle_flags0_buffer) {
    REQUIRE(U(BCryptGenRandom));
    unsigned char b[64]; memset(b, 0xA5, sizeof b);
    EQ_NT(GEN(NULL, b, sizeof b, 0), NS_INVALID_HANDLE);
    /* a failing call must not have produced output */
    unsigned i, same = 1; for (i = 0; i < sizeof b; i++) if (b[i] != 0xA5) same = 0;
    CHECK(same);
}
TEST(rngg_null_handle_entropy_flag_only) {
    REQUIRE(U(BCryptGenRandom));
    unsigned char b[16];
    EQ_NT(GEN(NULL, b, sizeof b, BCRYPT_RNG_USE_ENTROPY_IN_BUFFER), NS_INVALID_HANDLE);
}
TEST(rngg_sysrng_basic) {
    REQUIRE(U(BCryptGenRandom));
    unsigned char b[256] = {0};
    EQ_NT(GEN(NULL, b, sizeof b, BCRYPT_USE_SYSTEM_PREFERRED_RNG), NS_SUCCESS);
    CHECK(!rng_all_zero(b, sizeof b));
}
TEST(rngg_sysrng_entropy_in_buffer) {
    REQUIRE(U(BCryptGenRandom));
    unsigned char b[256]; memset(b, 0x11, sizeof b);
    EQ_NT(GEN(NULL, b, sizeof b, BCRYPT_USE_SYSTEM_PREFERRED_RNG | BCRYPT_RNG_USE_ENTROPY_IN_BUFFER), NS_SUCCESS);
    CHECK(!rng_all_zero(b, sizeof b));
}
TEST(rngg_sysrng_null_buffer_nonzero_len) {
    REQUIRE(U(BCryptGenRandom));
    EQ_NT(GEN(NULL, NULL, 256, BCRYPT_USE_SYSTEM_PREFERRED_RNG), NS_INVALID_PARAMETER);
}
TEST(rngg_sysrng_zero_len_with_buffer) {
    REQUIRE(U(BCryptGenRandom));
    unsigned char b[4] = {1, 2, 3, 4};
    EQ_NT(GEN(NULL, b, 0, BCRYPT_USE_SYSTEM_PREFERRED_RNG), NS_SUCCESS);
    CHECK(b[0] == 1 && b[1] == 2 && b[2] == 3 && b[3] == 4);
}
TEST(rngg_sysrng_zero_len_null_buffer) {
    REQUIRE(U(BCryptGenRandom));
    LONG s = GEN(NULL, NULL, 0, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    t_note("BCryptGenRandom(NULL,NULL,0,SYSPREF) = 0x%lx (not verified; forwarded to the RNG provider)", (unsigned long)s);
}
TEST(rngg_sysrng_with_handle_is_invalid_parameter) {
    if (t_is_wine()) { t_skip("emulator differs: flag/handle validation order"); return; }
    /* flag 2 with a non-NULL handle fails before any handle validation */
    REQUIRE(U(BCryptGenRandom));
    unsigned char b[16];
    EQ_NT(GEN(BCRYPT_RNG_ALG_HANDLE, b, sizeof b, BCRYPT_USE_SYSTEM_PREFERRED_RNG), NS_INVALID_PARAMETER);
    EQ_NT(GEN(BCRYPT_SHA256_ALG_HANDLE, b, sizeof b, BCRYPT_USE_SYSTEM_PREFERRED_RNG), NS_INVALID_PARAMETER);
}
TEST(rngg_sysrng_with_handle_and_entropy_flag) {
    if (t_is_wine()) { t_skip("emulator differs: flag/handle validation order"); return; }
    REQUIRE(U(BCryptGenRandom));
    unsigned char b[16];
    EQ_NT(GEN(BCRYPT_RNG_ALG_HANDLE, b, sizeof b, 3), NS_INVALID_PARAMETER);
}
TEST(rngg_pseudo_handle_rng) {
    REQUIRE(U(BCryptGenRandom));
    unsigned char b[256] = {0};
    EQ_NT(GEN(BCRYPT_RNG_ALG_HANDLE, b, sizeof b, 0), NS_SUCCESS);
    CHECK(!rng_all_zero(b, sizeof b));
}
TEST(rngg_pseudo_handle_rng_entropy_flag) {
    REQUIRE(U(BCryptGenRandom));
    unsigned char b[64]; memset(b, 0x42, sizeof b);
    EQ_NT(GEN(BCRYPT_RNG_ALG_HANDLE, b, sizeof b, BCRYPT_RNG_USE_ENTROPY_IN_BUFFER), NS_SUCCESS);
}
TEST(rngg_pseudo_handle_zero_len) {
    REQUIRE(U(BCryptGenRandom));
    unsigned char b[4] = {9, 9, 9, 9};
    LONG s = GEN(BCRYPT_RNG_ALG_HANDLE, b, 0, 0);
    EXPECT_EQ(s, NS_SUCCESS);
    CHECK(b[0] == 9 && b[3] == 9);
}
TEST(rngg_pseudo_handle_non_rng_types) {
    if (t_is_wine()) { t_skip("emulator differs: flag/handle validation order"); return; }
    /* a hash/cipher pseudo handle refers to an algorithm that is not an RNG: STATUS_INVALID_HANDLE */
    REQUIRE(U(BCryptGenRandom));
    unsigned char b[16];
    EQ_NT(GEN(BCRYPT_SHA256_ALG_HANDLE, b, sizeof b, 0), NS_INVALID_HANDLE);
    EQ_NT(GEN(BCRYPT_SHA1_ALG_HANDLE, b, sizeof b, 0), NS_INVALID_HANDLE);
    EQ_NT(GEN(BCRYPT_MD5_ALG_HANDLE, b, sizeof b, 0), NS_INVALID_HANDLE);
    EQ_NT(GEN(BCRYPT_AES_CBC_ALG_HANDLE, b, sizeof b, 0), NS_INVALID_HANDLE);
    EQ_NT(GEN(BCRYPT_RSA_ALG_HANDLE, b, sizeof b, 0), NS_INVALID_HANDLE);
    EQ_NT(GEN(BCRYPT_ECDSA_P256_ALG_HANDLE, b, sizeof b, 0), NS_INVALID_HANDLE);
}
TEST(rngg_pseudo_handle_out_of_table) {
    if (t_is_wine()) { t_skip("emulator differs: flag/handle validation order"); return; }
    /* pseudo handle index above the table size (0x39) is rejected */
    REQUIRE(U(BCryptGenRandom));
    unsigned char b[16];
    EQ_NT(GEN((BCRYPT_ALG_HANDLE)(ULONG_PTR)0x3A1, b, sizeof b, 0), NS_INVALID_HANDLE);
    EQ_NT(GEN((BCRYPT_ALG_HANDLE)(ULONG_PTR)0xFFF1, b, sizeof b, 0), NS_INVALID_HANDLE);
}
TEST(rngg_garbage_handle_small_value) {
    if (t_is_wine()) { t_skip("emulator differs: flag/handle validation order"); return; }
    REQUIRE(U(BCryptGenRandom));
    unsigned char b[16];
    /* low nibble != 1 and not a readable pointer would fault; use only pseudo-handle-shaped values */
    EQ_NT(GEN((BCRYPT_ALG_HANDLE)(ULONG_PTR)0x11, b, sizeof b, 0), NS_INVALID_HANDLE); /* idx 1: not an RNG */
}
TEST(rngg_pseudo_handle_close_rejected) {
    REQUIRE(U(BCryptCloseAlgorithmProvider));
    REQUIRE(U(BCryptGenRandom));
    unsigned char b[8];
    EQ_NT(U(BCryptCloseAlgorithmProvider)(BCRYPT_RNG_ALG_HANDLE, 0), NS_INVALID_HANDLE);
    /* still usable after the rejected close */
    EQ_NT(GEN(BCRYPT_RNG_ALG_HANDLE, b, sizeof b, 0), NS_SUCCESS);
}

/* ---- opened RNG algorithm handles ---- */
TEST(rngg_open_rng_provider) {
    REQUIRE(U(BCryptOpenAlgorithmProvider)); REQUIRE(U(BCryptGenRandom)); REQUIRE(U(BCryptCloseAlgorithmProvider));
    BCRYPT_ALG_HANDLE h = NULL; unsigned char b[128] = {0};
    EQ_NT(U(BCryptOpenAlgorithmProvider)(&h, BCRYPT_RNG_ALGORITHM, NULL, 0), NS_SUCCESS);
    CHECK(h != NULL);
    if (!h) return;
    EQ_NT(GEN(h, b, sizeof b, 0), NS_SUCCESS);
    CHECK(!rng_all_zero(b, sizeof b));
    EQ_NT(GEN(h, b, 0, 0), NS_SUCCESS);
    EQ_NT(U(BCryptCloseAlgorithmProvider)(h, 0), NS_SUCCESS);
}
TEST(rngg_open_rng_algorithm_name_property) {
    REQUIRE(U(BCryptOpenAlgorithmProvider)); REQUIRE(U(BCryptGetProperty)); REQUIRE(U(BCryptCloseAlgorithmProvider));
    BCRYPT_ALG_HANDLE h = NULL; WCHAR nm[16] = {0}; ULONG got = 0;
    EQ_NT(U(BCryptOpenAlgorithmProvider)(&h, L"RNG", NULL, 0), NS_SUCCESS);
    if (!h) return;
    EQ_NT(U(BCryptGetProperty)(h, BCRYPT_ALGORITHM_NAME, (PUCHAR)nm, sizeof nm, &got, 0), NS_SUCCESS);
    CHECK(!lstrcmpW(nm, L"RNG"));
    EXPECT_EQ(got, 8);
    U(BCryptCloseAlgorithmProvider)(h, 0);
}
TEST(rngg_open_rng_case_insensitive_name) {
    REQUIRE(U(BCryptOpenAlgorithmProvider)); REQUIRE(U(BCryptCloseAlgorithmProvider));
    BCRYPT_ALG_HANDLE h = NULL;
    LONG s = U(BCryptOpenAlgorithmProvider)(&h, L"rng", NULL, 0);
    t_note("OpenAlgorithmProvider(L\"rng\") = 0x%lx", (unsigned long)s);
    if (h) U(BCryptCloseAlgorithmProvider)(h, 0);
}
TEST(rngg_open_rng_double_close) {
    REQUIRE(U(BCryptOpenAlgorithmProvider)); REQUIRE(U(BCryptCloseAlgorithmProvider));
    BCRYPT_ALG_HANDLE h = NULL;
    EQ_NT(U(BCryptOpenAlgorithmProvider)(&h, L"RNG", NULL, 0), NS_SUCCESS);
    if (!h) return;
    EQ_NT(U(BCryptCloseAlgorithmProvider)(h, 0), NS_SUCCESS);
    /* the handle memory is unmapped/reused after close; only the first close is asserted */
}
TEST(rngg_open_rng_with_entropy_flag) {
    REQUIRE(U(BCryptOpenAlgorithmProvider)); REQUIRE(U(BCryptGenRandom)); REQUIRE(U(BCryptCloseAlgorithmProvider));
    BCRYPT_ALG_HANDLE h = NULL; unsigned char b[64]; memset(b, 0x77, sizeof b);
    EQ_NT(U(BCryptOpenAlgorithmProvider)(&h, L"RNG", NULL, 0), NS_SUCCESS);
    if (!h) return;
    EQ_NT(GEN(h, b, sizeof b, BCRYPT_RNG_USE_ENTROPY_IN_BUFFER), NS_SUCCESS);
    U(BCryptCloseAlgorithmProvider)(h, 0);
}
TEST(rngg_open_hash_handle_rejected) {
    REQUIRE(U(BCryptOpenAlgorithmProvider)); REQUIRE(U(BCryptGenRandom)); REQUIRE(U(BCryptCloseAlgorithmProvider));
    BCRYPT_ALG_HANDLE h = NULL; unsigned char b[16];
    EQ_NT(U(BCryptOpenAlgorithmProvider)(&h, BCRYPT_SHA256_ALGORITHM, NULL, 0), NS_SUCCESS);
    if (!h) return;
    EQ_NT(GEN(h, b, sizeof b, 0), NS_INVALID_HANDLE);
    U(BCryptCloseAlgorithmProvider)(h, 0);
}
TEST(rngg_open_aes_handle_rejected) {
    REQUIRE(U(BCryptOpenAlgorithmProvider)); REQUIRE(U(BCryptGenRandom)); REQUIRE(U(BCryptCloseAlgorithmProvider));
    BCRYPT_ALG_HANDLE h = NULL; unsigned char b[16];
    EQ_NT(U(BCryptOpenAlgorithmProvider)(&h, BCRYPT_AES_ALGORITHM, NULL, 0), NS_SUCCESS);
    if (!h) return;
    EQ_NT(GEN(h, b, sizeof b, 0), NS_INVALID_HANDLE);
    U(BCryptCloseAlgorithmProvider)(h, 0);
}
TEST(rngg_hash_object_handle_rejected) {
    /* a BCRYPT_HASH_HANDLE has magic 0x55555553, not an algorithm handle */
    REQUIRE(U(BCryptOpenAlgorithmProvider)); REQUIRE(U(BCryptCreateHash)); REQUIRE(U(BCryptDestroyHash));
    REQUIRE(U(BCryptGenRandom)); REQUIRE(U(BCryptCloseAlgorithmProvider));
    BCRYPT_ALG_HANDLE a = NULL; BCRYPT_HASH_HANDLE hh = NULL; unsigned char b[16], obj[1024];
    EQ_NT(U(BCryptOpenAlgorithmProvider)(&a, BCRYPT_SHA256_ALGORITHM, NULL, 0), NS_SUCCESS);
    if (!a) return;
    EQ_NT(U(BCryptCreateHash)(a, &hh, obj, sizeof obj, NULL, 0, 0), NS_SUCCESS);
    if (hh) {
        EQ_NT(GEN((BCRYPT_ALG_HANDLE)hh, b, sizeof b, 0), NS_INVALID_HANDLE);
        U(BCryptDestroyHash)(hh);
    }
    U(BCryptCloseAlgorithmProvider)(a, 0);
}
TEST(rngg_unknown_algorithm_variants) {
    REQUIRE(U(BCryptOpenAlgorithmProvider)); REQUIRE(U(BCryptCloseAlgorithmProvider));
    static const WCHAR *names[] = { BCRYPT_RNG_FIPS186_DSA_ALGORITHM, BCRYPT_RNG_DUAL_EC_ALGORITHM, L"RNG_UNKNOWN_xyz" };
    unsigned i;
    for (i = 0; i < 3; i++) {
        BCRYPT_ALG_HANDLE h = NULL;
        LONG s = U(BCryptOpenAlgorithmProvider)(&h, names[i], NULL, 0);
        t_note("Open(%ls) = 0x%lx", names[i], (unsigned long)s);
        if (i == 2) { CHECK(s < 0); CHECK(h == NULL); }
        if (h) U(BCryptCloseAlgorithmProvider)(h, 0);
    }
}
TEST(rngg_fips186_dsa_rng_generates) {
    REQUIRE(U(BCryptOpenAlgorithmProvider)); REQUIRE(U(BCryptCloseAlgorithmProvider)); REQUIRE(U(BCryptGenRandom));
    BCRYPT_ALG_HANDLE h = NULL; unsigned char b[64] = {0};
    LONG s = U(BCryptOpenAlgorithmProvider)(&h, BCRYPT_RNG_FIPS186_DSA_ALGORITHM, NULL, 0);
    if (s < 0 || !h) { t_note("FIPS186DSARNG not available: 0x%lx", (unsigned long)s); return; }
    s = GEN(h, b, sizeof b, 0);
    t_note("FIPS186DSARNG GenRandom = 0x%lx zero=%d", (unsigned long)s, rng_all_zero(b, sizeof b));
    U(BCryptCloseAlgorithmProvider)(h, 0);
}
TEST(rngg_dual_ec_rng_observe) {
    REQUIRE(U(BCryptOpenAlgorithmProvider)); REQUIRE(U(BCryptCloseAlgorithmProvider)); REQUIRE(U(BCryptGenRandom));
    BCRYPT_ALG_HANDLE h = NULL; unsigned char b[64] = {0};
    LONG s = U(BCryptOpenAlgorithmProvider)(&h, BCRYPT_RNG_DUAL_EC_ALGORITHM, NULL, 0);
    t_note("DUALECRNG open = 0x%lx (expected to be removed on build 19041)", (unsigned long)s);
    if (s >= 0 && h) { s = GEN(h, b, sizeof b, 0); t_note("DUALECRNG gen = 0x%lx", (unsigned long)s); U(BCryptCloseAlgorithmProvider)(h, 0); }
}

/* ---- statistical sanity (weak by nature) ---- */
TEST(rngg_two_calls_differ) {
    REQUIRE(U(BCryptGenRandom));
    unsigned char a[32], b[32];
    EQ_NT(GEN(NULL, a, sizeof a, BCRYPT_USE_SYSTEM_PREFERRED_RNG), NS_SUCCESS);
    EQ_NT(GEN(NULL, b, sizeof b, BCRYPT_USE_SYSTEM_PREFERRED_RNG), NS_SUCCESS);
    CHECK(memcmp(a, b, sizeof a) != 0);
    t_note("weak assertion: 256-bit outputs of two calls differ (collision probability 2^-256)");
}
TEST(rngg_pseudo_vs_sysrng_differ) {
    REQUIRE(U(BCryptGenRandom));
    unsigned char a[32], b[32];
    EQ_NT(GEN(NULL, a, sizeof a, BCRYPT_USE_SYSTEM_PREFERRED_RNG), NS_SUCCESS);
    EQ_NT(GEN(BCRYPT_RNG_ALG_HANDLE, b, sizeof b, 0), NS_SUCCESS);
    CHECK(memcmp(a, b, sizeof a) != 0);
}
TEST(rngg_sizes_one_to_sixtyfive) {
    REQUIRE(U(BCryptGenRandom));
    unsigned char b[80]; unsigned n;
    for (n = 1; n <= 65; n++) {
        memset(b, 0, sizeof b);
        memset(b + n, 0xCC, sizeof b - n);
        LONG s = GEN(NULL, b, n, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        CHECKF(s == 0, "n=%u status 0x%lx", n, (unsigned long)s);
        /* bytes past the requested size are untouched */
        unsigned i, clean = 1; for (i = n; i < sizeof b; i++) if (b[i] != 0xCC) clean = 0;
        CHECKF(clean, "n=%u wrote past the requested length", n);
    }
}
TEST(rngg_no_overrun_on_pseudo_handle) {
    REQUIRE(U(BCryptGenRandom));
    unsigned char b[40]; unsigned n;
    for (n = 1; n < 33; n += 4) {
        memset(b, 0xCC, sizeof b);
        EQ_NT(GEN(BCRYPT_RNG_ALG_HANDLE, b, n, 0), NS_SUCCESS);
        unsigned i, clean = 1; for (i = n; i < sizeof b; i++) if (b[i] != 0xCC) clean = 0;
        CHECKF(clean, "n=%u", n);
    }
}
TEST(rngg_unaligned_buffers) {
    REQUIRE(U(BCryptGenRandom));
    unsigned char raw[80]; unsigned off;
    for (off = 0; off < 8; off++) {
        memset(raw, 0, sizeof raw);
        EQ_NT(GEN(NULL, raw + off, 33, BCRYPT_USE_SYSTEM_PREFERRED_RNG), NS_SUCCESS);
        CHECKF(!rng_all_zero(raw + off, 33), "off=%u", off);
        CHECKF(rng_all_zero(raw, off), "off=%u wrote before buffer", off);
        CHECKF(rng_all_zero(raw + off + 33, sizeof raw - off - 33), "off=%u wrote after buffer", off);
    }
}
TEST(rngg_large_buffer_64k) {
    REQUIRE(U(BCryptGenRandom));
    size_t n = 65536; unsigned char *b = (unsigned char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, n + 16);
    if (!b) { t_skip("alloc"); return; }
    EQ_NT(GEN(NULL, b, (ULONG)n, BCRYPT_USE_SYSTEM_PREFERRED_RNG), NS_SUCCESS);
    CHECK(rng_popcount_plausible(b, n));
    CHECK(rng_histogram_plausible(b, n));
    CHECK(rng_all_zero(b + n, 16));
    t_note("weak assertion: popcount within 11 sigma and byte histogram without gaps for 64 KiB");
    HeapFree(GetProcessHeap(), 0, b);
}
TEST(rngg_large_buffer_1mib) {
    REQUIRE(U(BCryptGenRandom));
    size_t n = 1 << 20; unsigned char *b = (unsigned char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, n);
    if (!b) { t_skip("alloc"); return; }
    EQ_NT(GEN(NULL, b, (ULONG)n, BCRYPT_USE_SYSTEM_PREFERRED_RNG), NS_SUCCESS);
    CHECK(rng_popcount_plausible(b, n));
    CHECK(rng_histogram_plausible(b, n));
    /* first and last 4 KiB must both be filled */
    CHECK(!rng_all_zero(b, 4096));
    CHECK(!rng_all_zero(b + n - 4096, 4096));
    HeapFree(GetProcessHeap(), 0, b);
}
TEST(rngg_large_buffer_pseudo_handle) {
    REQUIRE(U(BCryptGenRandom));
    size_t n = 200000; unsigned char *b = (unsigned char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, n);
    if (!b) { t_skip("alloc"); return; }
    EQ_NT(GEN(BCRYPT_RNG_ALG_HANDLE, b, (ULONG)n, 0), NS_SUCCESS);
    CHECK(rng_popcount_plausible(b, n));
    CHECK(!rng_all_zero(b + n - 4096, 4096));
    HeapFree(GetProcessHeap(), 0, b);
}
TEST(rngg_no_repeated_blocks) {
    REQUIRE(U(BCryptGenRandom));
    enum { N = 512 };
    static unsigned char blk[N][16]; int i, j, dup = 0;
    for (i = 0; i < N; i++) EQ_NT(GEN(NULL, blk[i], 16, BCRYPT_USE_SYSTEM_PREFERRED_RNG), NS_SUCCESS);
    for (i = 0; i < N; i++) for (j = i + 1; j < N; j++) if (!memcmp(blk[i], blk[j], 16)) dup++;
    CHECK(dup == 0);
}
TEST(rngg_bit_balance_per_position) {
    /* each of the 8 bit positions of 8192 bytes is set between 40% and 60% of the time (>12 sigma) */
    REQUIRE(U(BCryptGenRandom));
    enum { N = 8192 };
    static unsigned char b[N]; unsigned cnt[8] = {0}; int i, k;
    EQ_NT(GEN(NULL, b, N, BCRYPT_USE_SYSTEM_PREFERRED_RNG), NS_SUCCESS);
    for (i = 0; i < N; i++) for (k = 0; k < 8; k++) cnt[k] += (b[i] >> k) & 1;
    for (k = 0; k < 8; k++) CHECKF(cnt[k] > N * 40 / 100 && cnt[k] < N * 60 / 100, "bit %d count %u", k, cnt[k]);
}
TEST(rngg_entropy_in_buffer_changes_nothing_visible) {
    /* with BCRYPT_RNG_USE_ENTROPY_IN_BUFFER the buffer is entropy input; output must still be random */
    REQUIRE(U(BCryptGenRandom));
    unsigned char a[64], b[64];
    memset(a, 0x5A, sizeof a); memset(b, 0x5A, sizeof b);
    EQ_NT(GEN(NULL, a, sizeof a, BCRYPT_USE_SYSTEM_PREFERRED_RNG | BCRYPT_RNG_USE_ENTROPY_IN_BUFFER), NS_SUCCESS);
    EQ_NT(GEN(NULL, b, sizeof b, BCRYPT_USE_SYSTEM_PREFERRED_RNG | BCRYPT_RNG_USE_ENTROPY_IN_BUFFER), NS_SUCCESS);
    CHECK(memcmp(a, b, sizeof a) != 0);
}
TEST(rngg_unknown_flag_bits_observe) {
    REQUIRE(U(BCryptGenRandom));
    unsigned char b[16]; ULONG f;
    for (f = 4; f <= 0x80; f <<= 1) {
        LONG s = GEN(BCRYPT_RNG_ALG_HANDLE, b, sizeof b, f);
        t_note("GenRandom(pseudo RNG, flags=0x%lx) = 0x%lx", (unsigned long)f, (unsigned long)s);
    }
}

/* ---- parity between exporting modules ---- */
TEST(rngg_ncrypt_forwarder_parity) {
    typeof(&BCryptGenRandom) f = UIN("ncrypt.dll", BCryptGenRandom);
    REQUIRE(f);
    unsigned char b[32] = {0};
    EQ_NT(f(NULL, NULL, 0, 0), NS_INVALID_HANDLE);
    EQ_NT(f(NULL, b, sizeof b, BCRYPT_USE_SYSTEM_PREFERRED_RNG), NS_SUCCESS);
    CHECK(!rng_all_zero(b, sizeof b));
    if (!t_is_wine()) EQ_NT(f(BCRYPT_RNG_ALG_HANDLE, b, sizeof b, BCRYPT_USE_SYSTEM_PREFERRED_RNG), NS_INVALID_PARAMETER);
}
TEST(rngg_bcrypt_module_export_present) {
    HMODULE m = t_module("bcrypt.dll");
    CHECK(m != NULL);
    CHECK(GetProcAddress(m, "BCryptGenRandom") != NULL);
    CHECK(GetProcAddress(m, "BCryptGetFipsAlgorithmMode") != NULL);
    CHECK(GetProcAddress(m, "BCryptGenRandomXYZ") == NULL);
}
struct rngg_S { unsigned char out[8][1024]; LONG st[8]; };
typedef struct { struct rngg_S *s; int i; } Arg;
static DWORD WINAPI rngg_worker(LPVOID p) {
    Arg *a = (Arg *)p; int k;
    for (k = 0; k < 50; k++) {
        a->s->st[a->i] = GEN(NULL, a->s->out[a->i], 1024, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        if (a->s->st[a->i]) break;
    }
    return 0;
}
TEST(rngg_concurrent_threads) {
    REQUIRE(U(BCryptGenRandom));
    struct rngg_S *s;
    s = (struct rngg_S *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof *s);
    if (!s) { t_skip("alloc"); return; }
    HANDLE th[8]; int i;
    static Arg args[8];
    for (i = 0; i < 8; i++) { args[i].s = s; args[i].i = i; th[i] = CreateThread(NULL, 0, rngg_worker, &args[i], 0, NULL); }
    WaitForMultipleObjects(8, th, TRUE, 20000);
    for (i = 0; i < 8; i++) { CloseHandle(th[i]); EXPECT_EQ(s->st[i], 0); CHECK(!rng_all_zero(s->out[i], 1024)); }
    for (i = 1; i < 8; i++) CHECK(memcmp(s->out[0], s->out[i], 1024) != 0);
    HeapFree(GetProcessHeap(), 0, s);
}

/* different processes must not share the stream */
CHILD(rngg_emit) {
    typeof(&BCryptGenRandom) f = U(BCryptGenRandom);
    unsigned char b[16]; DWORD w; HANDLE o = GetStdHandle(STD_OUTPUT_HANDLE);
    if (!f || f(NULL, b, sizeof b, BCRYPT_USE_SYSTEM_PREFERRED_RNG)) return 3;
    WriteFile(o, b, sizeof b, &w, NULL);
    return w == sizeof b ? 0 : 4;
}
TEST(rngg_child_processes_differ) {
    REQUIRE(U(BCryptGenRandom));
    unsigned char out[2][16]; int k;
    for (k = 0; k < 2; k++) {
        SECURITY_ATTRIBUTES sa = { sizeof sa, NULL, TRUE };
        HANDLE rd, wr; PROCESS_INFORMATION pi; DWORD r = 0, ec = 99;
        if (!CreatePipe(&rd, &wr, &sa, 0)) { t_skip("pipe"); return; }
        SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);
        HANDLE hp = t_spawn_child("rngg_emit", "", 0, NULL, wr, NULL, TRUE, NULL, &pi);
        CloseHandle(wr);
        if (!hp) { CloseHandle(rd); t_skip("spawn"); return; }
        memset(out[k], 0, 16);
        ReadFile(rd, out[k], 16, &r, NULL);
        WaitForSingleObject(pi.hProcess, 10000);
        GetExitCodeProcess(pi.hProcess, &ec);
        CloseHandle(pi.hProcess); CloseHandle(pi.hThread); CloseHandle(rd);
        EXPECT_EQ(ec, 0); EXPECT_EQ(r, 16);
    }
    CHECK(memcmp(out[0], out[1], 16) != 0);
}
