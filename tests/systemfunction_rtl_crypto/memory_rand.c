#include "sf.h"
#define N(a) ((int)(sizeof(a) / sizeof((a)[0])))

/* SystemFunction036 (RtlGenRandom): BOOLEAN f(PVOID buf, ULONG len), forwards to ProcessPrng.
 * SystemFunction040/041 (RtlEncryptMemory/RtlDecryptMemory): NTSTATUS f(PVOID mem, ULONG size, ULONG flags),
 * in place; flags 0 SAME_PROCESS, 1 CROSS_PROCESS, 2 SAME_LOGON, 4 (system), else STATUS_INVALID_PARAMETER
 * (the flag check precedes the kernel call). Size must be a multiple of 8 (kernel check). */

static const char *both[2] = {"advapi32.dll", "cryptbase.dll"};

TEST(sfrc_rand_036_returns_true_and_fills)
{
    int m;
    for (m = 0; m < 2; m++) {
        sf_rand_fn f = (sf_rand_fn)sf_in(both[m], 36);
        BYTE b[64], z[64] = {0};
        REQUIRE(f);
        memset(b, 0, sizeof b);
        EXPECT_EQ(f(b, 64), 1);
        CHECK(memcmp(b, z, 64) != 0);
    }
}
TEST(sfrc_rand_036_two_calls_differ)
{
    sf_rand_fn f = (sf_rand_fn)sf_in("advapi32.dll", 36);
    BYTE a[32], b[32];
    REQUIRE(f);
    EXPECT_EQ(f(a, 32), 1); EXPECT_EQ(f(b, 32), 1);
    CHECK(memcmp(a, b, 32) != 0);
}
TEST(sfrc_rand_036_exact_length_no_overrun)
{
    sf_rand_fn f = (sf_rand_fn)sf_in("advapi32.dll", 36);
    ULONG len;
    REQUIRE(f);
    for (len = 1; len <= 70; len++) {
        BYTE b[96]; memset(b, 0xA5, sizeof b);
        EXPECT_EQ(f(b + 8, len), 1);
        { ULONG i; int bad = 0; for (i = 0; i < 8; i++) if (b[i] != 0xA5) bad = 1;
          for (i = 8 + len; i < 96; i++) if (b[i] != 0xA5) bad = 1;
          CHECKF(!bad, "guard bytes touched at len %lu", len); }
    }
}
TEST(sfrc_rand_036_large_buffer)
{
    sf_rand_fn f = (sf_rand_fn)sf_in("cryptbase.dll", 36);
    ULONG n = 1 << 20, i, hist[256] = {0}, mx = 0;
    BYTE *b;
    REQUIRE(f);
    b = (BYTE *)calloc(n, 1);
    EXPECT_EQ(f(b, n), 1);
    for (i = 0; i < n; i++) hist[b[i]]++;
    for (i = 0; i < 256; i++) if (hist[i] > mx) mx = hist[i];
    /* expected ~4096 per value; a loose bound that only catches degenerate output */
    CHECKF(mx < 6000, "max bucket %lu", mx);
    for (i = 0; i < 256; i++) CHECKF(hist[i] > 2500, "bucket %lu = %lu", i, hist[i]);
    free(b);
}
TEST(sfrc_rand_036_not_trivially_patterned)
{
    sf_rand_fn f = (sf_rand_fn)sf_in("advapi32.dll", 36);
    BYTE b[256]; int i, same = 0;
    REQUIRE(f);
    EXPECT_EQ(f(b, 256), 1);
    for (i = 1; i < 256; i++) same += b[i] == b[i - 1];
    CHECK(same < 20);
}
TEST(sfrc_rand_036_zero_length_note)
{
    sf_rand_fn f = (sf_rand_fn)sf_in("advapi32.dll", 36);
    BYTE b[4] = {1,2,3,4};
    BYTE r;
    REQUIRE(f);
    r = f(b, 0);
    t_note("RtlGenRandom(buf, 0) -> %u", r);
    CHECK(b[0] == 1 && b[3] == 4);
}
static DWORD WINAPI rand_thread(LPVOID p)
{
    sf_rand_fn f = (sf_rand_fn)sf_in("advapi32.dll", 36);
    return f && f(p, 32) ? 0 : 1;
}
TEST(sfrc_rand_036_threads_get_distinct_streams)
{
    BYTE out[4][32]; HANDLE h[4]; int i, j;
    REQUIRE(sf_in("advapi32.dll", 36));
    memset(out, 0, sizeof out);
    for (i = 0; i < 4; i++) h[i] = CreateThread(NULL, 0, rand_thread, out[i], 0, NULL);
    for (i = 0; i < 4; i++) {
        CHECK(h[i] != NULL);
        if (h[i]) { CHECK(WaitForSingleObject(h[i], 10000) == WAIT_OBJECT_0); CloseHandle(h[i]); }
    }
    for (i = 0; i < 4; i++) for (j = i + 1; j < 4; j++) CHECK(memcmp(out[i], out[j], 32) != 0);
}
CHILD(sfrc_rand_child)
{
    sf_rand_fn f = (sf_rand_fn)sf_in("advapi32.dll", 36);
    BYTE b[32], z[32] = {0};
    if (!f) return 3;
    if (f(b, 32) != 1) return 2;
    return memcmp(b, z, 32) ? 0 : 1;
}
TEST(sfrc_rand_036_works_in_fresh_process)
{
    REQUIRE(sf_in("advapi32.dll", 36));
    EXPECT_EQ(t_run_child("sfrc_rand_child", "", 20000), 0);
}

/* ---- 040 / 041 ---- */
static LONG enc(const char *dll, void *p, ULONG n, ULONG fl) { return ((sf_mem_fn)sf_in(dll, 40))(p, n, fl); }
static LONG dec(const char *dll, void *p, ULONG n, ULONG fl) { return ((sf_mem_fn)sf_in(dll, 41))(p, n, fl); }
#define NEED_MEM() do { if (!sf_in("advapi32.dll", 40) || !sf_in("advapi32.dll", 41)) { t_skip("missing 040/041"); return; } } while (0)

static void fill(BYTE *b, ULONG n, int seed) { ULONG i; for (i = 0; i < n; i++) b[i] = (BYTE)(i * 31 + seed); }

static void roundtrip(ULONG flag)
{
    static const ULONG sizes[] = {8, 16, 24, 32, 40, 64, 128, 256, 1024, 4096, 65536};
    int s, m;
    NEED_MEM();
    for (m = 0; m < 2; m++) for (s = 0; s < N(sizes); s++) {
        BYTE *b = (BYTE *)malloc(sizes[s] + 16), *o = (BYTE *)malloc(sizes[s]);
        LONG r;
        memset(b, 0xEE, sizes[s] + 16);
        fill(b + 8, sizes[s], s + 1); memcpy(o, b + 8, sizes[s]);
        r = enc(both[m], b + 8, sizes[s], flag);
        CHECKF(r == 0, "enc size %lu flag %lu status 0x%lx", sizes[s], flag, (unsigned long)r);
        if (r == 0) {
            if (sizes[s] >= 16) CHECK(memcmp(b + 8, o, sizes[s]) != 0);
            { int g = 0, i; for (i = 0; i < 8; i++) g |= b[i] != 0xEE; for (i = 0; i < 8; i++) g |= b[8 + sizes[s] + i] != 0xEE; CHECKF(!g, "guard bytes touched, size %lu", sizes[s]); }
            r = dec(both[1 - m], b + 8, sizes[s], flag);
            CHECKF(r == 0, "dec size %lu status 0x%lx", sizes[s], (unsigned long)r);
            CHECK(!memcmp(b + 8, o, sizes[s]));
        }
        free(b); free(o);
    }
}
TEST(sfrc_mem_roundtrip_same_process) { roundtrip(0); }
TEST(sfrc_mem_roundtrip_cross_process) { roundtrip(1); }
TEST(sfrc_mem_roundtrip_same_logon) { roundtrip(2); }

TEST(sfrc_mem_smallest_block_8_bytes)
{
    BYTE b[8], o[8]; LONG r;
    NEED_MEM();
    fill(b, 8, 9); memcpy(o, b, 8);
    r = enc("advapi32.dll", b, 8, 0);
    t_note("RtlEncryptMemory size 8 -> 0x%lx", (unsigned long)r);
    if (r == 0) { NTST(dec("advapi32.dll", b, 8, 0), 0); CHECK(!memcmp(b, o, 8)); }
}
TEST(sfrc_mem_non_multiple_of_8_rejected)
{
    static const ULONG sizes[] = {1, 2, 3, 4, 5, 6, 7, 9, 10, 15, 17, 23, 25, 31, 4095};
    int s, f;
    NEED_MEM();
    if (t_is_wine()) { t_skip("emulator does not validate the size"); return; }
    for (s = 0; s < N(sizes); s++) for (f = 0; f < 3; f++) {
        BYTE b[4104], o[4104];
        fill(b, sizeof b, 5); memcpy(o, b, sizeof b);
        NTST(enc("advapi32.dll", b, sizes[s], (ULONG)f), ST_INVALID_PARAM);
        CHECK(!memcmp(b, o, sizeof b));
        NTST(dec("advapi32.dll", b, sizes[s], (ULONG)f), ST_INVALID_PARAM);
        CHECK(!memcmp(b, o, sizeof b));
    }
}
TEST(sfrc_mem_invalid_flags_rejected_without_touching_buffer)
{
    static const ULONG flags[] = {3, 5, 6, 7, 8, 0x10, 0x100, 0x80000000u, 0xFFFFFFFFu};
    int i, m;
    NEED_MEM();
    for (m = 0; m < 2; m++) for (i = 0; i < N(flags); i++) {
        BYTE b[32], o[32];
        fill(b, 32, 77); memcpy(o, b, 32);
        NTST(enc(both[m], b, 32, flags[i]), ST_INVALID_PARAM);
        CHECK(!memcmp(b, o, 32));
        NTST(dec(both[m], b, 32, flags[i]), ST_INVALID_PARAM);
        CHECK(!memcmp(b, o, 32));
    }
}
TEST(sfrc_mem_flag_checked_before_size)
{
    BYTE b[32];
    NEED_MEM();
    memset(b, 0, 32);
    /* both invalid: the flag is rejected in user mode, so the answer is the same either way */
    NTST(enc("advapi32.dll", b, 3, 9), ST_INVALID_PARAM);
}
TEST(sfrc_mem_ciphertext_differs_from_plaintext_all_flags)
{
    ULONG f;
    NEED_MEM();
    for (f = 0; f < 3; f++) {
        BYTE b[64], o[64];
        fill(b, 64, 1); memcpy(o, b, 64);
        NTST(enc("advapi32.dll", b, 64, f), 0);
        { int i, same = 0; for (i = 0; i < 64; i++) same += b[i] == o[i]; CHECKF(same < 16, "flag %lu: %d equal bytes", f, same); }
    }
}
TEST(sfrc_mem_decrypt_without_encrypt_scrambles)
{
    BYTE b[32], o[32];
    NEED_MEM();
    fill(b, 32, 3); memcpy(o, b, 32);
    NTST(dec("advapi32.dll", b, 32, 0), 0);
    CHECK(memcmp(b, o, 32) != 0);
}
TEST(sfrc_mem_wrong_flag_does_not_roundtrip)
{
    ULONG f, g;
    NEED_MEM();
    if (t_is_wine()) { t_skip("emulator uses a single key"); return; }
    for (f = 0; f < 3; f++) for (g = 0; g < 3; g++) {
        BYTE b[32], o[32];
        if (f == g) continue;
        fill(b, 32, 11); memcpy(o, b, 32);
        NTST(enc("advapi32.dll", b, 32, f), 0);
        NTST(dec("advapi32.dll", b, 32, g), 0);
        CHECKF(memcmp(b, o, 32) != 0, "enc flag %lu dec flag %lu round-tripped", f, g);
    }
}
TEST(sfrc_mem_double_encrypt_double_decrypt)
{
    BYTE b[48], o[48];
    NEED_MEM();
    fill(b, 48, 21); memcpy(o, b, 48);
    NTST(enc("advapi32.dll", b, 48, 0), 0);
    NTST(enc("advapi32.dll", b, 48, 0), 0);
    NTST(dec("advapi32.dll", b, 48, 0), 0);
    CHECK(memcmp(b, o, 48) != 0);
    NTST(dec("advapi32.dll", b, 48, 0), 0);
    CHECK(!memcmp(b, o, 48));
}
TEST(sfrc_mem_same_plaintext_same_process_is_stable_note)
{
    BYTE a[32], b[32];
    NEED_MEM();
    fill(a, 32, 4); memcpy(b, a, 32);
    NTST(enc("advapi32.dll", a, 32, 0), 0);
    NTST(enc("advapi32.dll", b, 32, 0), 0);
    t_note("same plaintext encrypts to same ciphertext twice in one process: %d", !memcmp(a, b, 32));
}
TEST(sfrc_mem_flag_4_note)
{
    BYTE b[32], o[32]; LONG r;
    NEED_MEM();
    fill(b, 32, 8); memcpy(o, b, 32);
    r = enc("advapi32.dll", b, 32, 4);
    t_note("RtlEncryptMemory(flag 4) -> 0x%lx", (unsigned long)r);
    if (r == 0) { r = dec("advapi32.dll", b, 32, 4); t_note("decrypt(flag 4) -> 0x%lx roundtrip=%d", (unsigned long)r, !memcmp(b, o, 32)); }
}
TEST(sfrc_mem_zero_size_note)
{
    BYTE b[8] = {1}; LONG r;
    NEED_MEM();
    r = enc("advapi32.dll", b, 0, 0);
    t_note("RtlEncryptMemory size 0 -> 0x%lx", (unsigned long)r);
    r = dec("advapi32.dll", b, 0, 0);
    t_note("RtlDecryptMemory size 0 -> 0x%lx", (unsigned long)r);
}
TEST(sfrc_mem_forwarders_interchangeable)
{
    int a, b;
    NEED_MEM();
    for (a = 0; a < 2; a++) for (b = 0; b < 2; b++) {
        BYTE x[40], o[40];
        fill(x, 40, a * 2 + b); memcpy(o, x, 40);
        NTST(enc(both[a], x, 40, 1), 0);
        NTST(dec(both[b], x, 40, 1), 0);
        CHECK(!memcmp(x, o, 40));
    }
}
TEST(sfrc_mem_heap_and_stack_and_global_buffers)
{
    static BYTE g[64]; BYTE s[64]; BYTE *h = (BYTE *)HeapAlloc(GetProcessHeap(), 0, 64);
    BYTE *bufs[3]; int i;
    NEED_MEM();
    bufs[0] = g; bufs[1] = s; bufs[2] = h;
    for (i = 0; i < 3; i++) {
        BYTE o[64];
        fill(bufs[i], 64, 50 + i); memcpy(o, bufs[i], 64);
        NTST(enc("advapi32.dll", bufs[i], 64, 0), 0);
        NTST(dec("advapi32.dll", bufs[i], 64, 0), 0);
        CHECK(!memcmp(bufs[i], o, 64));
    }
    HeapFree(GetProcessHeap(), 0, h);
}
TEST(sfrc_mem_virtualalloc_page_boundary)
{
    BYTE *p;
    NEED_MEM();
    p = (BYTE *)VirtualAlloc(NULL, 8192, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!p) { t_skip("VirtualAlloc"); return; }
    {
        BYTE o[64];
        BYTE *at = p + 4096 - 32;      /* buffer spans the page boundary */
        fill(at, 64, 6); memcpy(o, at, 64);
        NTST(enc("advapi32.dll", at, 64, 0), 0);
        NTST(dec("advapi32.dll", at, 64, 0), 0);
        CHECK(!memcmp(at, o, 64));
    }
    VirtualFree(p, 0, MEM_RELEASE);
}
TEST(sfrc_mem_readonly_buffer_note)
{
    /* In-place API on a read-only page: the kernel probes the buffer. Observation only. */
    BYTE *p; DWORD old; LONG r;
    NEED_MEM();
    p = (BYTE *)VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!p) { t_skip("VirtualAlloc"); return; }
    fill(p, 64, 2);
    VirtualProtect(p, 4096, PAGE_READONLY, &old);
    r = enc("advapi32.dll", p, 64, 0);
    t_note("encrypt on PAGE_READONLY buffer -> 0x%lx", (unsigned long)r);
    VirtualFree(p, 0, MEM_RELEASE);
}

static DWORD WINAPI dec_thread(LPVOID p)
{
    void **a = (void **)p;
    LONG r = dec("advapi32.dll", a[0], 32, (ULONG)(ULONG_PTR)a[1]);
    return (DWORD)r;
}
TEST(sfrc_mem_other_thread_decrypts_all_flags)
{
    ULONG f;
    NEED_MEM();
    for (f = 0; f < 3; f++) {
        BYTE b[32], o[32]; void *a[2]; HANDLE h; DWORD ec = 0xdead;
        fill(b, 32, 90 + f); memcpy(o, b, 32);
        NTST(enc("advapi32.dll", b, 32, f), 0);
        a[0] = b; a[1] = (void *)(ULONG_PTR)f;
        h = CreateThread(NULL, 0, dec_thread, a, 0, NULL);
        CHECK(h != NULL);
        if (h) { CHECK(WaitForSingleObject(h, 10000) == WAIT_OBJECT_0); GetExitCodeThread(h, &ec); CloseHandle(h); }
        EXPECT_EQ(ec, 0);
        CHECKF(!memcmp(b, o, 32), "flag %lu: other thread could not decrypt", f);
    }
}

/* ---- cross-process semantics via a child ----
 * child args: <flag> <hex ciphertext> <hex plaintext>; exit 0 = decrypted to plaintext,
 * 1 = decrypt succeeded but differs, 2 = decrypt failed, 3 = missing export */
CHILD(sfrc_mem_child)
{
    BYTE ct[64], pt[64]; int n, n2; ULONG flag; LONG r;
    sf_mem_fn f = (sf_mem_fn)sf_in("advapi32.dll", 41);
    if (argc < 4) return 4;
    if (!f) return 3;
    flag = (ULONG)atoi(argv[1]);
    n = sf_unhex(argv[2], ct, 64); n2 = sf_unhex(argv[3], pt, 64);
    if (n != n2) return 4;
    r = f(ct, (ULONG)n, flag);
    if (r != 0) return 2;
    return memcmp(ct, pt, (size_t)n) ? 1 : 0;
}
static DWORD xproc(ULONG flag)
{
    BYTE b[32], o[32]; char hc[80], hp[80], args[200];
    fill(b, 32, 123); memcpy(o, b, 32);
    if (enc("advapi32.dll", b, 32, flag) != 0) return 0xBAD0;
    sf_hex(b, 32, hc); sf_hex(o, 32, hp);
    wsprintfA(args, "%lu %s %s", flag, hc, hp);
    return t_run_child("sfrc_mem_child", args, 20000);
}
TEST(sfrc_mem_cross_process_flag_decrypts_in_child)
{
    NEED_MEM();
    if (t_is_wine()) { t_skip("emulator semantics"); return; }
    EXPECT_EQ(xproc(1), 0);
}
TEST(sfrc_mem_same_logon_flag_decrypts_in_child)
{
    NEED_MEM();
    if (t_is_wine()) { t_skip("emulator semantics"); return; }
    EXPECT_EQ(xproc(2), 0);
}
TEST(sfrc_mem_same_process_flag_does_not_decrypt_in_child)
{
    NEED_MEM();
    if (t_is_wine()) { t_skip("emulator semantics"); return; }
    EXPECT_EQ(xproc(0), 1);
}
TEST(sfrc_mem_child_invalid_flag_reports_failure)
{
    BYTE b[16]; char hc[40], args[120];
    NEED_MEM();
    memset(b, 0x11, 16); sf_hex(b, 16, hc);
    wsprintfA(args, "7 %s %s", hc, hc);
    EXPECT_EQ(t_run_child("sfrc_mem_child", args, 20000), 2);
}
