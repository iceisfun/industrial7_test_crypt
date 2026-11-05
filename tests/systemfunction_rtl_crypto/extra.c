#include "sf.h"
#define N(a) ((int)(sizeof(a) / sizeof((a)[0])))

/* Ordinals of the cryptbase / cryptsp SystemFunction exports (Windows 10 export tables). */
static const struct { const char *dll; int fn; int ord; } ords[] = {
    {"cryptbase.dll", 1, 1}, {"cryptbase.dll", 2, 2}, {"cryptbase.dll", 3, 3}, {"cryptbase.dll", 4, 4},
    {"cryptbase.dll", 5, 5}, {"cryptbase.dll", 28, 6}, {"cryptbase.dll", 29, 7}, {"cryptbase.dll", 34, 8},
    {"cryptbase.dll", 36, 9}, {"cryptbase.dll", 40, 10}, {"cryptbase.dll", 41, 11},
    {"cryptsp.dll", 6, 41}, {"cryptsp.dll", 7, 42}, {"cryptsp.dll", 8, 43}, {"cryptsp.dll", 9, 44},
    {"cryptsp.dll", 10, 45}, {"cryptsp.dll", 11, 46}, {"cryptsp.dll", 12, 47}, {"cryptsp.dll", 13, 48},
    {"cryptsp.dll", 14, 49}, {"cryptsp.dll", 15, 50}, {"cryptsp.dll", 16, 51}, {"cryptsp.dll", 18, 52},
    {"cryptsp.dll", 20, 53}, {"cryptsp.dll", 21, 54}, {"cryptsp.dll", 22, 55}, {"cryptsp.dll", 23, 56},
    {"cryptsp.dll", 24, 57}, {"cryptsp.dll", 25, 58}, {"cryptsp.dll", 26, 59}, {"cryptsp.dll", 27, 60},
    {"cryptsp.dll", 30, 61}, {"cryptsp.dll", 31, 62}, {"cryptsp.dll", 32, 63}, {"cryptsp.dll", 33, 64},
    {"cryptsp.dll", 35, 65},
};

TEST(sfrc_extra_ordinals_match_names)
{
    int i;
    if (t_is_wine()) { t_skip("emulator export layout"); return; }
    for (i = 0; i < N(ords); i++) {
        HMODULE h = t_module(ords[i].dll);
        FARPROC byname, byord;
        if (!h) { t_skip("no %s", ords[i].dll); return; }
        byname = sf_raw(ords[i].dll, ords[i].fn);
        byord = GetProcAddress(h, (LPCSTR)(ULONG_PTR)ords[i].ord);
        CHECKF(byname != NULL, "%s SystemFunction%03d missing", ords[i].dll, ords[i].fn);
        CHECKF(byord == byname, "%s ordinal %d != SystemFunction%03d", ords[i].dll, ords[i].ord, ords[i].fn);
    }
}
TEST(sfrc_extra_getprocaddress_bad_names)
{
    HMODULE h = t_module("advapi32.dll");
    REQUIRE(h);
    CHECK(GetProcAddress(h, "SystemFunction000") == NULL);
    CHECK(GetLastError() == ERROR_PROC_NOT_FOUND);
    CHECK(GetProcAddress(h, "SystemFunction042") == NULL);
    CHECK(GetProcAddress(h, "systemfunction036") == NULL);   /* names are case sensitive */
    CHECK(GetProcAddress(h, "SystemFunction36") == NULL);
}
TEST(sfrc_extra_cryptbase_has_no_lm_nt_functions)
{
    HMODULE h = t_module("cryptbase.dll");
    int i;
    static const int absent[] = {6, 7, 8, 9, 10, 11, 12, 13, 32, 33};
    if (!h || t_is_wine()) { t_skip("no split cryptbase"); return; }
    for (i = 0; i < N(absent); i++) CHECKF(sf_raw("cryptbase.dll", absent[i]) == NULL, "SystemFunction%03d in cryptbase", absent[i]);
}
TEST(sfrc_extra_cryptsp_has_no_des_or_memory_functions)
{
    int i;
    static const int absent[] = {1, 2, 3, 4, 5, 36, 40, 41};
    if (!t_module("cryptsp.dll") || t_is_wine()) { t_skip("no split cryptsp"); return; }
    for (i = 0; i < N(absent); i++) CHECKF(sf_raw("cryptsp.dll", absent[i]) == NULL, "SystemFunction%03d in cryptsp", absent[i]);
}

/* ---- 040/041 argument validation that happens in user mode ---- */
static LONG mem(int fn, void *p, ULONG n, ULONG fl) { return ((sf_mem_fn)sf_adv(fn))(p, n, fl); }

TEST(sfrc_extra_mem_invalid_flag_needs_no_valid_buffer)
{
    /* The flag is decoded in user mode before any buffer is touched, so a NULL buffer with an
     * undefined flag fails with STATUS_INVALID_PARAMETER and does not fault. */
    static const ULONG flags[] = {3, 8, 0x100, 0xFFFFFFFFu};
    int i, fn;
    REQUIRE(sf_adv(40)); REQUIRE(sf_adv(41));
    for (fn = 40; fn <= 41; fn++) for (i = 0; i < N(flags); i++) {
        NTST(mem(fn, NULL, 0, flags[i]), ST_INVALID_PARAM);
        NTST(mem(fn, NULL, 16, flags[i]), ST_INVALID_PARAM);
    }
}
TEST(sfrc_extra_mem_defined_flags_set)
{
    /* flags 0,1,2,4 pass the user-mode decode; 3,5,6,7 do not */
    ULONG f;
    BYTE b[16];
    REQUIRE(sf_adv(40));
    for (f = 0; f < 8; f++) {
        LONG r;
        memset(b, 0x42, 16);
        r = mem(40, b, 16, f);
        if (f == 3 || f >= 5) NTST(r, ST_INVALID_PARAM);
        else if (f == 4) t_note("flag 4 -> 0x%lx", (unsigned long)r);
        else NTST(r, 0);
    }
}
TEST(sfrc_extra_mem_large_roundtrip)
{
    ULONG n = 4u << 20, i; BYTE *b, *o; int fl;
    REQUIRE(sf_adv(40)); REQUIRE(sf_adv(41));
    b = (BYTE *)malloc(n); o = (BYTE *)malloc(n);
    if (!b || !o) { free(b); free(o); t_skip("alloc"); return; }
    for (i = 0; i < n; i++) b[i] = (BYTE)(i * 7 + (i >> 8));
    memcpy(o, b, n);
    for (fl = 0; fl < 3; fl++) {
        LONG r = mem(40, b, n, (ULONG)fl);
        if (r != 0) { t_note("4MiB encrypt flag %d -> 0x%lx", fl, (unsigned long)r); break; }
        CHECK(memcmp(b, o, n) != 0);
        NTST(mem(41, b, n, (ULONG)fl), 0);
        CHECK(!memcmp(b, o, n));
    }
    free(b); free(o);
}
TEST(sfrc_extra_mem_blocks_not_independent_ecb_note)
{
    /* Two equal plaintext blocks: observation of the chaining mode */
    BYTE b[16];
    REQUIRE(sf_adv(40));
    memset(b, 0x5A, 16);
    NTST(mem(40, b, 16, 0), 0);
    t_note("equal plaintext blocks encrypt to equal ciphertext blocks (ECB-like): %d", !memcmp(b, b + 8, 8));
}
TEST(sfrc_extra_mem_only_range_modified)
{
    BYTE b[64], o[64]; int i, diff_head = 0, diff_tail = 0;
    REQUIRE(sf_adv(40)); REQUIRE(sf_adv(41));
    memset(b, 0xC3, 64); memcpy(o, b, 64);
    NTST(mem(40, b + 16, 32, 1), 0);
    for (i = 0; i < 16; i++) diff_head |= b[i] != o[i];
    for (i = 48; i < 64; i++) diff_tail |= b[i] != o[i];
    CHECK(!diff_head); CHECK(!diff_tail);
    CHECK(memcmp(b + 16, o + 16, 32) != 0);
    NTST(mem(41, b + 16, 32, 1), 0);
    CHECK(!memcmp(b, o, 64));
}
static DWORD WINAPI mt_worker(LPVOID p)
{
    int k; BYTE b[64], o[64];
    for (k = 0; k < 200; k++) {
        int i;
        for (i = 0; i < 64; i++) b[i] = (BYTE)(i + k + (int)(ULONG_PTR)p);
        memcpy(o, b, 64);
        if (mem(40, b, 64, (ULONG)(k % 3)) != 0) return 1;
        if (mem(41, b, 64, (ULONG)(k % 3)) != 0) return 2;
        if (memcmp(b, o, 64)) return 3;
    }
    return 0;
}
TEST(sfrc_extra_mem_concurrent_threads)
{
    HANDLE h[4]; int i;
    REQUIRE(sf_adv(40)); REQUIRE(sf_adv(41));
    for (i = 0; i < 4; i++) h[i] = CreateThread(NULL, 0, mt_worker, (LPVOID)(ULONG_PTR)i, 0, NULL);
    for (i = 0; i < 4; i++) {
        DWORD ec = 99;
        CHECK(h[i] != NULL);
        if (!h[i]) continue;
        CHECK(WaitForSingleObject(h[i], 20000) == WAIT_OBJECT_0);
        GetExitCodeThread(h[i], &ec); EXPECT_EQ(ec, 0); CloseHandle(h[i]);
    }
}

/* ---- 036 ---- */
TEST(sfrc_extra_rand_returns_boolean_one)
{
    BYTE b[16]; BYTE r;
    REQUIRE(sf_adv(36));
    r = ((sf_rand_fn)sf_adv(36))(b, 16);
    EXPECT_EQ(r, 1);
}
TEST(sfrc_extra_rand_matches_cryptbase_and_advapi_pointer)
{
    if (t_is_wine()) { t_skip("emulator forwarders"); return; }
    REQUIRE(sf_raw("advapi32.dll", 36)); REQUIRE(sf_raw("cryptbase.dll", 36));
    CHECK(sf_raw("advapi32.dll", 36) == sf_raw("cryptbase.dll", 36));
    CHECK(sf_raw("advapi32.dll", 40) == sf_raw("cryptbase.dll", 40));
    CHECK(sf_raw("advapi32.dll", 41) == sf_raw("cryptbase.dll", 41));
}
TEST(sfrc_extra_rand_bit_balance)
{
    BYTE b[4096]; int i, bits = 0;
    REQUIRE(sf_adv(36));
    EXPECT_EQ(((sf_rand_fn)sf_adv(36))(b, sizeof b), 1);
    for (i = 0; i < 4096; i++) { BYTE v = b[i]; while (v) { bits += v & 1; v >>= 1; } }
    /* 32768 bits; mean 16384, sigma ~90: +-1000 is >10 sigma */
    CHECKF(bits > 15384 && bits < 17384, "set bits %d", bits);
}

/* ---- 003 / 001 consistency across modules, parity-bit independence ---- */
TEST(sfrc_extra_des_003_both_modules_agree)
{
    sf_des1_fn a = (sf_des1_fn)sf_in("advapi32.dll", 3), b = (sf_des1_fn)sf_in("cryptbase.dll", 3);
    BYTE k[7] = {0x41,0x42,0x43,0x44,0x45,0x46,0x47}, x[8], y[8];
    REQUIRE(a); REQUIRE(b);
    NTST(a(k, x), 0); NTST(b(k, y), 0);
    CHECK_BYTES(x, y, 8);
}
TEST(sfrc_extra_des_001_output_not_dependent_on_prior_contents)
{
    sf_block_fn e = (sf_block_fn)sf_in("cryptbase.dll", 1);
    static const BYTE pt[8] = {1,2,3,4,5,6,7,8}, k[7] = {7,6,5,4,3,2,1};
    BYTE a[8], b[8];
    REQUIRE(e);
    memset(a, 0x00, 8); memset(b, 0xFF, 8);
    NTST(e(pt, k, a), 0); NTST(e(pt, k, b), 0);
    CHECK_BYTES(a, b, 8);
}
TEST(sfrc_extra_des_001_002_inverse_random_looking)
{
    sf_block_fn e = (sf_block_fn)sf_in("cryptbase.dll", 1), d = (sf_block_fn)sf_in("cryptbase.dll", 2);
    int i, j;
    REQUIRE(e); REQUIRE(d);
    for (i = 0; i < 200; i++) {
        BYTE p[8], k[7], c[8], q[8];
        for (j = 0; j < 8; j++) p[j] = (BYTE)(i * 13 + j * 29 + (i >> 3));
        for (j = 0; j < 7; j++) k[j] = (BYTE)(i * 7 + j * 53 + 5);
        NTST(e(p, k, c), 0); NTST(d(c, k, q), 0);
        CHECK_BYTES(q, p, 8);
    }
}
