/* RNG provider flag/handle protocol: through BCryptGenRandom and through the primitive provider table. */
#include "rng_common.h"

#define GEN(h, b, n, f) U(BCryptGenRandom)((h), (b), (n), (f))
#define NS_UNSUCCESSFUL_NOT_SUPPORTED NS_NOT_SUPPORTED

/* Only bit 0 (BCRYPT_RNG_USE_ENTROPY_IN_BUFFER) is accepted by the RNG provider; bit 1 is the
 * system-preferred selector handled by BCryptGenRandom itself. Everything else is rejected. */
TEST(rngx_pseudo_rng_every_unknown_flag_bit_rejected) {
    REQUIRE(U(BCryptGenRandom));
    if (t_is_wine()) { t_skip("emulator accepts unknown flags"); return; }
    unsigned char b[16]; int bit;
    for (bit = 1; bit < 32; bit++) {
        memset(b, 0xCC, sizeof b);
        LONG s = GEN(BCRYPT_RNG_ALG_HANDLE, b, sizeof b, 1UL << bit);
        CHECKF(s == NS_INVALID_PARAMETER, "flag bit %d -> 0x%lx", bit, (unsigned long)s);
        if (s < 0) { unsigned i, same = 1; for (i = 0; i < sizeof b; i++) if (b[i] != 0xCC) same = 0; CHECKF(same, "bit %d: output written on failure", bit); }
    }
}
TEST(rngx_pseudo_rng_entropy_flag_plus_unknown_bit_rejected) {
    REQUIRE(U(BCryptGenRandom));
    if (t_is_wine()) { t_skip("emulator accepts unknown flags"); return; }
    unsigned char b[16];
    EQ_NT(GEN(BCRYPT_RNG_ALG_HANDLE, b, sizeof b, 1 | 4), NS_INVALID_PARAMETER);
    EQ_NT(GEN(BCRYPT_RNG_ALG_HANDLE, b, sizeof b, 1 | 0x80000000UL), NS_INVALID_PARAMETER);
    EQ_NT(GEN(BCRYPT_RNG_ALG_HANDLE, b, sizeof b, 0xFFFFFFFCUL), NS_INVALID_PARAMETER);
}
TEST(rngx_sysrng_unknown_flag_bits_rejected) {
    REQUIRE(U(BCryptGenRandom));
    if (t_is_wine()) { t_skip("emulator accepts unknown flags"); return; }
    /* bit 1 is stripped before the provider sees the flags; any other bit than bit 0 is rejected by it */
    unsigned char b[16]; int bit;
    for (bit = 2; bit < 32; bit++) {
        LONG s = GEN(NULL, b, sizeof b, BCRYPT_USE_SYSTEM_PREFERRED_RNG | (1UL << bit));
        CHECKF(s == NS_INVALID_PARAMETER, "flags 2|bit %d -> 0x%lx", bit, (unsigned long)s);
    }
}
TEST(rngx_null_handle_unknown_flags_is_invalid_handle) {
    REQUIRE(U(BCryptGenRandom));
    unsigned char b[16]; int bit;
    /* without the system-preferred bit a NULL handle is rejected before any flag is examined */
    for (bit = 2; bit < 32; bit++)
        CHECKF(GEN(NULL, b, sizeof b, 1UL << bit) == NS_INVALID_HANDLE, "bit %d", bit);
}
TEST(rngx_non_rng_pseudo_handle_checked_before_flags) {
    REQUIRE(U(BCryptGenRandom));
    if (t_is_wine()) { t_skip("emulator differs: handle validation order"); return; }
    unsigned char b[16];
    /* the handle type is validated first: a hash handle gives INVALID_HANDLE even with a bad flag bit */
    EQ_NT(GEN(BCRYPT_SHA256_ALG_HANDLE, b, sizeof b, 4), NS_INVALID_HANDLE);
    EQ_NT(GEN(BCRYPT_SHA256_ALG_HANDLE, b, sizeof b, 1), NS_INVALID_HANDLE);
}
TEST(rngx_pseudo_rng_null_buffer_invalid_parameter) {
    REQUIRE(U(BCryptGenRandom));
    if (t_is_wine()) { t_skip("emulator differs for NULL buffers"); return; }
    /* the provider checks the buffer pointer, even when the length is zero */
    EQ_NT(GEN(BCRYPT_RNG_ALG_HANDLE, NULL, 0, 0), NS_INVALID_PARAMETER);
    EQ_NT(GEN(BCRYPT_RNG_ALG_HANDLE, NULL, 16, 0), NS_INVALID_PARAMETER);
    EQ_NT(GEN(BCRYPT_RNG_ALG_HANDLE, NULL, 16, BCRYPT_RNG_USE_ENTROPY_IN_BUFFER), NS_INVALID_PARAMETER);
}
TEST(rngx_sysrng_null_buffer_invalid_parameter) {
    REQUIRE(U(BCryptGenRandom));
    if (t_is_wine()) { t_skip("emulator differs for NULL buffers"); return; }
    EQ_NT(GEN(NULL, NULL, 0, BCRYPT_USE_SYSTEM_PREFERRED_RNG), NS_INVALID_PARAMETER);
    EQ_NT(GEN(NULL, NULL, 16, BCRYPT_USE_SYSTEM_PREFERRED_RNG), NS_INVALID_PARAMETER);
    EQ_NT(GEN(NULL, NULL, 16, BCRYPT_USE_SYSTEM_PREFERRED_RNG | BCRYPT_RNG_USE_ENTROPY_IN_BUFFER), NS_INVALID_PARAMETER);
}
TEST(rngx_opened_rng_null_buffer_and_flags) {
    REQUIRE(U(BCryptOpenAlgorithmProvider)); REQUIRE(U(BCryptCloseAlgorithmProvider)); REQUIRE(U(BCryptGenRandom));
    if (t_is_wine()) { t_skip("emulator differs for NULL buffers/flags"); return; }
    BCRYPT_ALG_HANDLE h = NULL; unsigned char b[16];
    EQ_NT(U(BCryptOpenAlgorithmProvider)(&h, BCRYPT_RNG_ALGORITHM, NULL, 0), NS_SUCCESS);
    if (!h) return;
    EQ_NT(GEN(h, NULL, 0, 0), NS_INVALID_PARAMETER);
    EQ_NT(GEN(h, NULL, 16, 0), NS_INVALID_PARAMETER);
    EQ_NT(GEN(h, b, sizeof b, 4), NS_INVALID_PARAMETER);
    EQ_NT(GEN(h, b, sizeof b, 0x100), NS_INVALID_PARAMETER);
    EQ_NT(GEN(h, b, sizeof b, BCRYPT_USE_SYSTEM_PREFERRED_RNG), NS_INVALID_PARAMETER);
    EQ_NT(GEN(h, b, sizeof b, 0), NS_SUCCESS);
    U(BCryptCloseAlgorithmProvider)(h, 0);
}
TEST(rngx_open_rng_nonzero_flags) {
    REQUIRE(U(BCryptOpenAlgorithmProvider)); REQUIRE(U(BCryptCloseAlgorithmProvider));
    BCRYPT_ALG_HANDLE h = NULL;
    LONG s = U(BCryptOpenAlgorithmProvider)(&h, BCRYPT_RNG_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    t_note("Open(RNG, HMAC flag) = 0x%lx", (unsigned long)s);
    if (h) U(BCryptCloseAlgorithmProvider)(h, 0);
}

/* ---------- through the bcryptprimitives RNG function table (child processes isolate a wrong layout guess) ---------- */
typedef NTSTATUS (WINAPI *GetRngIf_pfn)(LPCWSTR provider, LPCWSTR algid, void **ppTable, ULONG flags);
typedef NTSTATUS (WINAPI *x_open_t)(BCRYPT_ALG_HANDLE *, LPCWSTR, ULONG);
typedef NTSTATUS (WINAPI *x_close_t)(BCRYPT_ALG_HANDLE, ULONG);
typedef NTSTATUS (WINAPI *x_gen_t)(BCRYPT_ALG_HANDLE, PUCHAR, ULONG, ULONG);
typedef struct { BCRYPT_INTERFACE_VERSION Version; void *fn[24]; } x_vt_t;

static x_vt_t *x_table(void) {
    GetRngIf_pfn f = (GetRngIf_pfn)t_proc_in("bcryptprimitives.dll", "GetRngInterface"); void *t = NULL;
    if (!f || f(NULL, L"RNG", &t, 0)) return NULL;
    return (x_vt_t *)t;
}

CHILD(rngx_vt_open_matrix) {
    x_vt_t *t = x_table(); BCRYPT_ALG_HANDLE h; LONG s;
    static const struct { const WCHAR *n; ULONG fl; LONG want; } m[] = {
        { L"RNG", 0, 0 }, { L"RNG", 1, 0 }, { L"FIPS186DSARNG", 0, 0 }, { L"FIPS186DSARNG", 1, 0 },
        { L"RNG", 2, (LONG)0xC000000D }, { L"RNG", 4, (LONG)0xC000000D }, { L"RNG", 8, (LONG)0xC000000D },
        { L"RNG", 0x10, (LONG)0xC000000D }, { L"RNG", 0x80000000UL, (LONG)0xC000000D },
        { L"rng", 0, (LONG)0xC00000BB }, { L"Rng", 0, (LONG)0xC00000BB }, { L"", 0, (LONG)0xC00000BB },
        { L"RNG ", 0, (LONG)0xC00000BB }, { L"SHA256", 0, (LONG)0xC00000BB }, { L"AES", 0, (LONG)0xC00000BB },
        { L"fips186dsarng", 0, (LONG)0xC00000BB },
        { L"DUALECRNG", 1, (LONG)0xC00000BB },
    };
    unsigned i;
    if (!t) return 10;
    for (i = 0; i < sizeof m / sizeof *m; i++) {
        h = (BCRYPT_ALG_HANDLE)(ULONG_PTR)0x1234;
        s = ((x_open_t)t->fn[0])(&h, m[i].n, m[i].fl);
        if (s != m[i].want) return 100 + i;
        if (s == 0) {
            if (!h || h == (BCRYPT_ALG_HANDLE)(ULONG_PTR)0x1234) return 150 + i;
            if (((x_close_t)t->fn[3])(h, 0)) return 200 + i;
        } else if (h != (BCRYPT_ALG_HANDLE)(ULONG_PTR)0x1234) return 50 + i;   /* output untouched on failure */
    }
    return 0;
}
TEST(rngx_vt_open_matrix) {
    REQUIRE(t_proc_in("bcryptprimitives.dll", "GetRngInterface"));
    DWORD ec = t_run_child("rngx_vt_open_matrix", "", 20000);
    if (ec) t_note("child exit %lu: 10 table; 50+i output modified; 100+i status mismatch at row i; 150+i handle; 200+i close", (unsigned long)ec);
    CHECK(ec == 0);
}
CHILD(rngx_vt_gen_matrix) {
    x_vt_t *t = x_table(); BCRYPT_ALG_HANDLE h = NULL, g = NULL, d = NULL; unsigned char b[32]; LONG s;
    if (!t) return 10;
    if (((x_open_t)t->fn[0])(&h, L"RNG", 0)) return 11;
    if (((x_gen_t)t->fn[4])(h, b, sizeof b, 0)) return 12;
    if (((x_gen_t)t->fn[4])(h, b, sizeof b, 1)) return 13;                       /* entropy-in-buffer */
    if (((x_gen_t)t->fn[4])(h, b, sizeof b, 2) != (LONG)0xC000000D) return 14;
    if (((x_gen_t)t->fn[4])(h, b, sizeof b, 0x10) != (LONG)0xC000000D) return 15;
    if (((x_gen_t)t->fn[4])(h, NULL, 0, 0) != (LONG)0xC000000D) return 16;       /* NULL buffer even for 0 bytes */
    if (((x_gen_t)t->fn[4])(h, NULL, 8, 0) != (LONG)0xC000000D) return 17;
    if (((x_gen_t)t->fn[4])(NULL, b, sizeof b, 0) != (LONG)0xC0000008) return 18;
    if (((x_gen_t)t->fn[4])(NULL, NULL, 0, 0) != (LONG)0xC0000008) return 19;    /* handle first */
    if (((x_gen_t)t->fn[4])(h, b, 0, 0)) return 20;
    if (((x_open_t)t->fn[0])(&g, L"FIPS186DSARNG", 0)) return 21;
    s = ((x_gen_t)t->fn[4])(g, b, sizeof b, 0);
    if (s) return 22;
    if (((x_open_t)t->fn[0])(&d, L"DUALECRNG", 0)) return 23;
    s = ((x_gen_t)t->fn[4])(d, b, sizeof b, 0);
    if (s) return 24;
    if (((x_close_t)t->fn[3])(d, 0) || ((x_close_t)t->fn[3])(g, 0) || ((x_close_t)t->fn[3])(h, 0)) return 25;
    return 0;
}
TEST(rngx_vt_gen_matrix) {
    REQUIRE(t_proc_in("bcryptprimitives.dll", "GetRngInterface"));
    DWORD ec = t_run_child("rngx_vt_gen_matrix", "", 20000);
    if (ec) t_note("child exit %lu (see rngx_vt_gen_matrix for the code table)", (unsigned long)ec);
    CHECK(ec == 0);
}
CHILD(rngx_vt_fake_handles) {
    x_vt_t *t = x_table(); unsigned char b[16];
    /* locally built blocks shaped like an RNG handle: {size, magic 'GRNM', type} */
    ULONG good[3]  = { 0xc, 0x4d524e47, 0x50001 };
    ULONG t2[3]    = { 0xc, 0x4d524e47, 0x50002 };
    ULONG badmg[3] = { 0xc, 0x12345678, 0x50001 };
    ULONG badty[3] = { 0xc, 0x4d524e47, 0x50000 };
    ULONG badty2[3] = { 0xc, 0x4d524e47, 0x50004 };
    ULONG hashty[3] = { 0xc, 0x4d524e47, 0x00060001 };
    if (!t) return 10;
    if (((x_gen_t)t->fn[4])((BCRYPT_ALG_HANDLE)good, b, sizeof b, 0)) return 11;
    if (((x_gen_t)t->fn[4])((BCRYPT_ALG_HANDLE)t2, b, sizeof b, 0)) return 12;
    if (((x_gen_t)t->fn[4])((BCRYPT_ALG_HANDLE)badmg, b, sizeof b, 0) != (LONG)0xC0000008) return 13;
    if (((x_gen_t)t->fn[4])((BCRYPT_ALG_HANDLE)badty, b, sizeof b, 0) != (LONG)0xC0000008) return 14;
    if (((x_gen_t)t->fn[4])((BCRYPT_ALG_HANDLE)badty2, b, sizeof b, 0) != (LONG)0xC0000008) return 15;
    if (((x_gen_t)t->fn[4])((BCRYPT_ALG_HANDLE)hashty, b, sizeof b, 0) != (LONG)0xC0000008) return 16;
    return 0;
}
TEST(rngx_vt_generate_validates_handle_magic_and_type) {
    REQUIRE(t_proc_in("bcryptprimitives.dll", "GetRngInterface"));
    DWORD ec = t_run_child("rngx_vt_fake_handles", "", 20000);
    if (ec) t_note("child exit %lu (11/12 accepted blocks, 13-16 rejected blocks)", (unsigned long)ec);
    CHECK(ec == 0);
}
