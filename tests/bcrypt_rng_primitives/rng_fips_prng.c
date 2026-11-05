/* BCryptGetFipsAlgorithmMode, ProcessPrng, ProcessPrngGuid, SystemFunction036, CryptGenRandom. */
#include "rng_common.h"

UDECL(BOOL, ProcessPrng, (PBYTE pbData, SIZE_T cbData));
UDECL(BOOL, ProcessPrngGuid, (GUID *pGuid));
UDECL(BOOLEAN, SystemFunction036, (PVOID RandomBuffer, ULONG RandomBufferLength));
#define UINN(dll, name) ((name##_pfn)t_proc_in(dll, #name))
#define PRNG_BP() ((ProcessPrng_pfn)t_proc_in("bcryptprimitives.dll", "ProcessPrng"))

/* ================= BCryptGetFipsAlgorithmMode ================= */
static int rng_reg_dword_nonzero(HKEY root, const char *sub, const char *val, int *present) {
    HKEY k; DWORD type = 0, data = 0, cb = sizeof data; int r = 0;
    *present = 0;
    if (RegOpenKeyExA(root, sub, 0, KEY_QUERY_VALUE | KEY_WOW64_64KEY, &k) != ERROR_SUCCESS) return 0;
    if (RegQueryValueExA(k, val, NULL, &type, (LPBYTE)&data, &cb) == ERROR_SUCCESS && type == REG_DWORD && cb == 4) {
        *present = 1; r = (data & 0xff) != 0;   /* the implementation tests the first data byte */
    }
    RegCloseKey(k);
    return r;
}
static int rng_expected_fips(void) {
    int pr;
    if (rng_reg_dword_nonzero(HKEY_LOCAL_MACHINE, "System\\CurrentControlSet\\Control\\Lsa\\FipsAlgorithmPolicy", "Enabled", &pr)) return 1;
    if (rng_reg_dword_nonzero(HKEY_LOCAL_MACHINE, "System\\CurrentControlSet\\Control\\Lsa", "FipsAlgorithmPolicy", &pr)) return 1;
    if (rng_reg_dword_nonzero(HKEY_LOCAL_MACHINE, "System\\CurrentControlSet\\Control\\Lsa\\FipsAlgorithmPolicy", "MDMEnabled", &pr)) return 1;
    return 0;
}

TEST(rngf_null_pointer) {
    REQUIRE(U(BCryptGetFipsAlgorithmMode));
    EQ_NT(U(BCryptGetFipsAlgorithmMode)(NULL), NS_INVALID_PARAMETER);
}
TEST(rngf_returns_success) {
    REQUIRE(U(BCryptGetFipsAlgorithmMode));
    BOOLEAN e = 0x55;
    EQ_NT(U(BCryptGetFipsAlgorithmMode)(&e), NS_SUCCESS);
}
TEST(rngf_output_is_boolean) {
    REQUIRE(U(BCryptGetFipsAlgorithmMode));
    BOOLEAN e = 0x55;
    EQ_NT(U(BCryptGetFipsAlgorithmMode)(&e), NS_SUCCESS);
    CHECKF(e == 0 || e == 1, "value 0x%x", e);
}
TEST(rngf_output_overwritten_when_preset_true) {
    REQUIRE(U(BCryptGetFipsAlgorithmMode));
    BOOLEAN a = 1, b = 0;
    EQ_NT(U(BCryptGetFipsAlgorithmMode)(&a), NS_SUCCESS);
    EQ_NT(U(BCryptGetFipsAlgorithmMode)(&b), NS_SUCCESS);
    EXPECT_EQ(a, b);   /* the callee always clears the output first */
}
TEST(rngf_matches_policy_registry) {
    REQUIRE(U(BCryptGetFipsAlgorithmMode));
    if (t_is_wine()) { t_skip("emulator reads policy differently"); return; }
    BOOLEAN e = 0x55;
    EQ_NT(U(BCryptGetFipsAlgorithmMode)(&e), NS_SUCCESS);
    EXPECT_EQ(e, rng_expected_fips());
    t_note("FIPS algorithm mode on this machine: %d", e);
}
TEST(rngf_repeatable) {
    REQUIRE(U(BCryptGetFipsAlgorithmMode));
    BOOLEAN a = 7, b = 7;
    EQ_NT(U(BCryptGetFipsAlgorithmMode)(&a), NS_SUCCESS);
    EQ_NT(U(BCryptGetFipsAlgorithmMode)(&b), NS_SUCCESS);
    EXPECT_EQ(a, b);
}
TEST(rngf_ncrypt_forwarder) {
    typeof(&BCryptGetFipsAlgorithmMode) f = UIN("ncrypt.dll", BCryptGetFipsAlgorithmMode);
    REQUIRE(f);
    BOOLEAN e = 0x55, e2 = 0x55;
    EQ_NT(f(NULL), NS_INVALID_PARAMETER);
    EQ_NT(f(&e), NS_SUCCESS);
    EQ_NT(U(BCryptGetFipsAlgorithmMode)(&e2), NS_SUCCESS);
    EXPECT_EQ(e, e2);
}
TEST(rngf_does_not_touch_other_bytes) {
    REQUIRE(U(BCryptGetFipsAlgorithmMode));
    BOOLEAN buf[4] = { 0x55, 0x55, 0x55, 0x55 };
    EQ_NT(U(BCryptGetFipsAlgorithmMode)(&buf[1]), NS_SUCCESS);
    CHECK(buf[0] == 0x55 && buf[2] == 0x55 && buf[3] == 0x55);
}
TEST(rngf_cryptsp_getfips_alias_absent) {
    /* the Win32 equivalent is advapi32!... not exported; the BCrypt one lives in bcrypt.dll only */
    HMODULE m = t_module("advapi32.dll");
    CHECK(m != NULL);
    CHECK(GetProcAddress(m, "BCryptGetFipsAlgorithmMode") == NULL);
}

/* ================= ProcessPrng ================= */
TEST(rngp_basic) {
    ProcessPrng_pfn f = PRNG_BP(); REQUIRE(f);
    unsigned char b[64] = {0};
    CHECK(f(b, sizeof b) == TRUE);
    CHECK(!rng_all_zero(b, sizeof b));
}
TEST(rngp_returns_exactly_one) {
    ProcessPrng_pfn f = PRNG_BP(); REQUIRE(f);
    unsigned char b[8];
    EXPECT_EQ(f(b, sizeof b), 1);
}
TEST(rngp_size_zero_leaves_buffer) {
    ProcessPrng_pfn f = PRNG_BP(); REQUIRE(f);
    unsigned char b[8]; memset(b, 0x6B, sizeof b);
    CHECK(f(b, 0) == TRUE);
    unsigned i; for (i = 0; i < sizeof b; i++) CHECK(b[i] == 0x6B);
}
TEST(rngp_size_zero_null_buffer) {
    ProcessPrng_pfn f = PRNG_BP(); REQUIRE(f);
    CHECK(f(NULL, 0) == TRUE);   /* decomp: the generate loop is skipped for size 0 and 1 is returned */
}
TEST(rngp_size_one) {
    ProcessPrng_pfn f = PRNG_BP(); REQUIRE(f);
    unsigned char b[3] = {0xCC, 0, 0xCC};
    CHECK(f(b + 1, 1) == TRUE);
    CHECK(b[0] == 0xCC && b[2] == 0xCC);
}
TEST(rngp_exact_bounds_all_sizes_1_to_70) {
    ProcessPrng_pfn f = PRNG_BP(); REQUIRE(f);
    unsigned char b[96]; unsigned n, i;
    for (n = 1; n <= 70; n++) {
        memset(b, 0xCC, sizeof b);
        CHECKF(f(b + 8, n) == TRUE, "n=%u", n);
        for (i = 0; i < 8; i++) CHECKF(b[i] == 0xCC, "n=%u underrun", n);
        for (i = 8 + n; i < sizeof b; i++) CHECKF(b[i] == 0xCC, "n=%u overrun at %u", n, i);
    }
}
TEST(rngp_chunk_boundaries) {
    /* the implementation generates in chunks of at most 64 KiB */
    ProcessPrng_pfn f = PRNG_BP(); REQUIRE(f);
    static const SIZE_T sizes[] = { 65535, 65536, 65537, 131071, 131072, 131073, 196608 };
    unsigned k;
    for (k = 0; k < sizeof sizes / sizeof *sizes; k++) {
        SIZE_T n = sizes[k];
        unsigned char *b = (unsigned char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, n + 32);
        if (!b) { t_skip("alloc"); return; }
        CHECKF(f(b + 16, n) == TRUE, "n=%zu", n);
        CHECKF(rng_all_zero(b, 16) && rng_all_zero(b + 16 + n, 16), "n=%zu out of bounds write", n);
        CHECKF(!rng_all_zero(b + 16, 4096), "n=%zu head zero", n);
        CHECKF(!rng_all_zero(b + 16 + n - 4096, 4096), "n=%zu tail zero", n);
        if (n > 65536) CHECKF(!rng_all_zero(b + 16 + 65536 - 64, 128), "n=%zu chunk seam zero", n);
        HeapFree(GetProcessHeap(), 0, b);
    }
}
TEST(rngp_statistics_1mib) {
    ProcessPrng_pfn f = PRNG_BP(); REQUIRE(f);
    SIZE_T n = 1 << 20; unsigned char *b = (unsigned char *)HeapAlloc(GetProcessHeap(), 0, n);
    if (!b) { t_skip("alloc"); return; }
    CHECK(f(b, n) == TRUE);
    CHECK(rng_popcount_plausible(b, n));
    CHECK(rng_histogram_plausible(b, n));
    t_note("weak assertion: popcount and histogram sanity only");
    HeapFree(GetProcessHeap(), 0, b);
}
TEST(rngp_two_calls_differ) {
    ProcessPrng_pfn f = PRNG_BP(); REQUIRE(f);
    unsigned char a[32], b[32];
    CHECK(f(a, sizeof a) && f(b, sizeof b));
    CHECK(memcmp(a, b, sizeof a) != 0);
}
TEST(rngp_no_duplicate_blocks) {
    ProcessPrng_pfn f = PRNG_BP(); REQUIRE(f);
    enum { N = 512 }; static unsigned char blk[N][16]; int i, j, dup = 0;
    for (i = 0; i < N; i++) CHECK(f(blk[i], 16));
    for (i = 0; i < N; i++) for (j = i + 1; j < N; j++) if (!memcmp(blk[i], blk[j], 16)) dup++;
    CHECK(dup == 0);
}
TEST(rngp_unaligned) {
    ProcessPrng_pfn f = PRNG_BP(); REQUIRE(f);
    unsigned char raw[80]; unsigned off;
    for (off = 0; off < 16; off++) {
        memset(raw, 0, sizeof raw);
        CHECK(f(raw + off, 41) == TRUE);
        CHECKF(!rng_all_zero(raw + off, 41), "off=%u", off);
        CHECKF(rng_all_zero(raw, off) && rng_all_zero(raw + off + 41, sizeof raw - off - 41), "off=%u bounds", off);
    }
}
TEST(rngp_bit_balance) {
    ProcessPrng_pfn f = PRNG_BP(); REQUIRE(f);
    enum { N = 8192 }; static unsigned char b[N]; unsigned cnt[8] = {0}; int i, k;
    CHECK(f(b, N));
    for (i = 0; i < N; i++) for (k = 0; k < 8; k++) cnt[k] += (b[i] >> k) & 1;
    for (k = 0; k < 8; k++) CHECKF(cnt[k] > N * 40 / 100 && cnt[k] < N * 60 / 100, "bit %d count %u", k, cnt[k]);
}
static DWORD WINAPI prng_worker(LPVOID p) {
    unsigned char *o = (unsigned char *)p; int i; ProcessPrng_pfn f = PRNG_BP();
    for (i = 0; i < 100; i++) if (!f(o, 512)) return 1;
    return 0;
}
TEST(rngp_threads) {
    ProcessPrng_pfn f = PRNG_BP(); REQUIRE(f);
    static unsigned char out[8][512]; HANDLE th[8]; int i; DWORD ec;
    memset(out, 0, sizeof out);
    for (i = 0; i < 8; i++) th[i] = CreateThread(NULL, 0, prng_worker, out[i], 0, NULL);
    WaitForMultipleObjects(8, th, TRUE, 20000);
    for (i = 0; i < 8; i++) { ec = 9; GetExitCodeThread(th[i], &ec); CloseHandle(th[i]); EXPECT_EQ(ec, 0); CHECK(!rng_all_zero(out[i], 512)); }
    for (i = 1; i < 8; i++) CHECK(memcmp(out[0], out[i], 512) != 0);
}
TEST(rngp_export_present_in_bcryptprimitives) {
    HMODULE m = t_module("bcryptprimitives.dll");
    CHECK(m != NULL);
    CHECK(GetProcAddress(m, "ProcessPrng") != NULL);
    if (!t_is_wine()) CHECK(GetProcAddress(m, "ProcessPrngGuid") != NULL);
}
TEST(rngp_kernel_forwarders) {
    /* newer OS builds also expose ProcessPrng from other modules; only observe */
    const char *mods[] = { "bcrypt.dll", "kernelbase.dll", "kernel32.dll", "ntdll.dll", "cryptbase.dll" };
    unsigned i;
    for (i = 0; i < 5; i++) { HMODULE m = t_module(mods[i]); t_note("%s exports ProcessPrng: %d", mods[i], m && GetProcAddress(m, "ProcessPrng") != NULL); }
}
CHILD(rngp_emit) {
    ProcessPrng_pfn f = PRNG_BP(); unsigned char b[16]; DWORD w = 0; HANDLE o = GetStdHandle(STD_OUTPUT_HANDLE);
    if (!f || !f(b, sizeof b)) return 3;
    WriteFile(o, b, sizeof b, &w, NULL);
    return w == sizeof b ? 0 : 4;
}
TEST(rngp_child_processes_differ) {
    ProcessPrng_pfn f = PRNG_BP(); REQUIRE(f);
    unsigned char out[2][16]; int k;
    for (k = 0; k < 2; k++) {
        SECURITY_ATTRIBUTES sa = { sizeof sa, NULL, TRUE }; HANDLE rd, wr; PROCESS_INFORMATION pi; DWORD r = 0, ec = 99;
        if (!CreatePipe(&rd, &wr, &sa, 0)) { t_skip("pipe"); return; }
        SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);
        HANDLE hp = t_spawn_child("rngp_emit", "", 0, NULL, wr, NULL, TRUE, NULL, &pi);
        CloseHandle(wr);
        if (!hp) { CloseHandle(rd); t_skip("spawn"); return; }
        memset(out[k], 0, 16);
        ReadFile(rd, out[k], 16, &r, NULL);
        WaitForSingleObject(pi.hProcess, 10000); GetExitCodeProcess(pi.hProcess, &ec);
        CloseHandle(pi.hProcess); CloseHandle(pi.hThread); CloseHandle(rd);
        EXPECT_EQ(ec, 0); EXPECT_EQ(r, 16);
    }
    CHECK(memcmp(out[0], out[1], 16) != 0);
}

/* ================= ProcessPrngGuid ================= */
static void check_v4_guid(const GUID *g, int i) {
    CHECKF((g->Data3 >> 12) == 4, "[%d] version nibble 0x%x", i, g->Data3 >> 12);
    CHECKF((g->Data4[0] & 0xC0) == 0x80, "[%d] variant bits 0x%x", i, g->Data4[0]);
}
TEST(rngg2_basic_is_v4) {
    ProcessPrngGuid_pfn f = (ProcessPrngGuid_pfn)t_proc_in("bcryptprimitives.dll", "ProcessPrngGuid"); REQUIRE(f);
    GUID g; memset(&g, 0, sizeof g);
    CHECK(f(&g) == TRUE);
    check_v4_guid(&g, 0);
    CHECK(!rng_all_zero((unsigned char *)&g, sizeof g));
}
TEST(rngg2_many_are_v4_and_unique) {
    ProcessPrngGuid_pfn f = (ProcessPrngGuid_pfn)t_proc_in("bcryptprimitives.dll", "ProcessPrngGuid"); REQUIRE(f);
    enum { N = 400 }; static GUID g[N]; int i, j, dup = 0;
    for (i = 0; i < N; i++) { CHECK(f(&g[i]) == TRUE); check_v4_guid(&g[i], i); }
    for (i = 0; i < N; i++) for (j = i + 1; j < N; j++) if (!memcmp(&g[i], &g[j], sizeof(GUID))) dup++;
    CHECK(dup == 0);
}
TEST(rngg2_overwrites_all_16_bytes) {
    ProcessPrngGuid_pfn f = (ProcessPrngGuid_pfn)t_proc_in("bcryptprimitives.dll", "ProcessPrngGuid"); REQUIRE(f);
    unsigned char raw[16 + 32]; memset(raw, 0xEE, sizeof raw);
    CHECK(f((GUID *)(raw + 16)) == TRUE);
    unsigned i; for (i = 0; i < 16; i++) CHECK(raw[i] == 0xEE);
    for (i = 32; i < 48; i++) CHECK(raw[i] == 0xEE);
    check_v4_guid((GUID *)(raw + 16), 0);
}
TEST(rngg2_random_bits_cover_variant_bytes) {
    /* byte 8 keeps 6 random bits, Data3 keeps 12: over many samples all low bits flip */
    ProcessPrngGuid_pfn f = (ProcessPrngGuid_pfn)t_proc_in("bcryptprimitives.dll", "ProcessPrngGuid"); REQUIRE(f);
    unsigned char or8 = 0, and8 = 0xFF; unsigned or3 = 0, and3 = 0xFFFF; int i;
    for (i = 0; i < 300; i++) {
        GUID g; CHECK(f(&g)); or8 |= g.Data4[0]; and8 &= g.Data4[0]; or3 |= g.Data3; and3 &= g.Data3;
    }
    CHECK(or8 == 0xBF && (and8 & 0xC0) == 0x80 && (and8 & 0x3F) == 0);
    CHECK(or3 == 0x4FFF && and3 == 0x4000);
}
TEST(rngg2_not_equal_to_coCreateGuid_pattern) {
    ProcessPrngGuid_pfn f = (ProcessPrngGuid_pfn)t_proc_in("bcryptprimitives.dll", "ProcessPrngGuid"); REQUIRE(f);
    GUID a, b; CHECK(f(&a) && f(&b));
    CHECK(memcmp(&a, &b, sizeof a) != 0);
}

/* ================= SystemFunction036 / RtlGenRandom ================= */
static const char *const SF_MODS[] = { "advapi32.dll", "cryptbase.dll" };
static void sf_each(void (*fn)(SystemFunction036_pfn f, const char *mod)) {
    int i;
    for (i = 0; i < 2; i++) {
        SystemFunction036_pfn f = UINN(SF_MODS[i], SystemFunction036);
        if (!f) { if (!t_is_wine()) CHECKF(0, "SystemFunction036 missing from %s", SF_MODS[i]); continue; }
        fn(f, SF_MODS[i]);
    }
}
static void sf_basic(SystemFunction036_pfn f, const char *m) {
    unsigned char b[64] = {0};
    CHECKF(f(b, sizeof b) == TRUE, "%s", m);
    CHECKF(!rng_all_zero(b, sizeof b), "%s", m);
}
TEST(rngs_basic_each_module) { sf_each(sf_basic); }
static void sf_zero(SystemFunction036_pfn f, const char *m) {
    unsigned char b[4] = {1, 2, 3, 4};
    CHECKF(f(b, 0) == TRUE, "%s", m);
    CHECKF(b[0] == 1 && b[3] == 4, "%s", m);
    CHECKF(f(NULL, 0) == TRUE, "%s zero with NULL", m);
}
TEST(rngs_zero_length_each_module) { sf_each(sf_zero); }
static void sf_sizes(SystemFunction036_pfn f, const char *m) {
    unsigned char b[96]; unsigned n, i;
    for (n = 1; n <= 40; n++) {
        memset(b, 0xCC, sizeof b);
        CHECKF(f(b + 4, n) == TRUE, "%s n=%u", m, n);
        for (i = 0; i < 4; i++) CHECKF(b[i] == 0xCC, "%s n=%u underrun", m, n);
        for (i = 4 + n; i < sizeof b; i++) CHECKF(b[i] == 0xCC, "%s n=%u overrun", m, n);
    }
}
TEST(rngs_sizes_each_module) { sf_each(sf_sizes); }
static void sf_large(SystemFunction036_pfn f, const char *m) {
    SIZE_T n = 70000; unsigned char *b = (unsigned char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, n);
    if (!b) return;
    CHECKF(f(b, (ULONG)n) == TRUE, "%s", m);
    CHECKF(!rng_all_zero(b, 4096) && !rng_all_zero(b + n - 4096, 4096), "%s", m);
    CHECKF(rng_popcount_plausible(b, n), "%s", m);
    HeapFree(GetProcessHeap(), 0, b);
}
TEST(rngs_large_each_module) { sf_each(sf_large); }
static void sf_differ(SystemFunction036_pfn f, const char *m) {
    unsigned char a[32], b[32];
    CHECK(f(a, sizeof a) && f(b, sizeof b));
    CHECKF(memcmp(a, b, sizeof a) != 0, "%s", m);
}
TEST(rngs_two_calls_differ) { sf_each(sf_differ); }
TEST(rngs_advapi_forwards_to_cryptbase) {
    FARPROC a = t_proc_in("advapi32.dll", "SystemFunction036"), c = t_proc_in("cryptbase.dll", "SystemFunction036");
    REQUIRE(a); REQUIRE(c);
    if (t_is_wine()) { t_skip("emulator does not forward"); return; }
    CHECK(a == c);   /* advapi32's export is a forwarder to CRYPTBASE.SystemFunction036 */
}
TEST(rngs_return_type_is_byte_sized_boolean) {
    /* BOOLEAN: only AL is defined; compare via the typed pointer */
    SystemFunction036_pfn f = UINN("cryptbase.dll", SystemFunction036); REQUIRE(f);
    unsigned char b[8];
    EXPECT_EQ(f(b, sizeof b), 1);
}
TEST(rngs_ordinal_resolution) {
    /* cryptbase exports SystemFunction036 as ordinal 9 */
    FARPROC byname = t_proc_in("cryptbase.dll", "SystemFunction036");
    FARPROC byord = t_proc_ord("cryptbase.dll", 9);
    REQUIRE(byname);
    if (t_is_wine()) { t_note("ordinal differs on emulator"); return; }
    CHECK(byord == byname);
}
TEST(rngs_matches_processprng_semantics) {
    SystemFunction036_pfn f = UINN("cryptbase.dll", SystemFunction036); REQUIRE(f);
    unsigned char a[16], b[16]; ProcessPrng_pfn p = PRNG_BP(); REQUIRE(p);
    CHECK(f(a, sizeof a) && p(b, sizeof b));
    CHECK(memcmp(a, b, sizeof a) != 0);
}
TEST(rngs_rtlgenrandom_not_a_named_export) {
    /* RtlGenRandom is the header name for SystemFunction036; there is no export under that name */
    CHECK(GetProcAddress(t_module("advapi32.dll"), "RtlGenRandom") == NULL);
    CHECK(GetProcAddress(t_module("cryptbase.dll"), "RtlGenRandom") == NULL);
}

/* ================= CryptGenRandom ================= */
static int cgr_acquire(HCRYPTPROV *p, DWORD type) {
    *p = 0;
    return U(CryptAcquireContextW)(p, NULL, NULL, type, CRYPT_VERIFYCONTEXT | CRYPT_SILENT);
}
TEST(rngc_basic_rsa_full) {
    REQUIRE(U(CryptAcquireContextW)); REQUIRE(U(CryptGenRandom)); REQUIRE(U(CryptReleaseContext));
    HCRYPTPROV p; unsigned char b[64] = {0};
    if (!cgr_acquire(&p, PROV_RSA_FULL)) { t_skip("no provider 0x%lx", GetLastError()); return; }
    CHECK(U(CryptGenRandom)(p, sizeof b, b) == TRUE);
    CHECK(!rng_all_zero(b, sizeof b));
    CHECK(U(CryptReleaseContext)(p, 0));
}
TEST(rngc_basic_rsa_aes) {
    REQUIRE(U(CryptAcquireContextW)); REQUIRE(U(CryptGenRandom)); REQUIRE(U(CryptReleaseContext));
    HCRYPTPROV p; unsigned char b[64] = {0};
    if (!cgr_acquire(&p, PROV_RSA_AES)) { t_skip("no provider 0x%lx", GetLastError()); return; }
    CHECK(U(CryptGenRandom)(p, sizeof b, b) == TRUE);
    CHECK(!rng_all_zero(b, sizeof b));
    CHECK(U(CryptReleaseContext)(p, 0));
}
TEST(rngc_dss_provider) {
    REQUIRE(U(CryptAcquireContextW)); REQUIRE(U(CryptGenRandom)); REQUIRE(U(CryptReleaseContext));
    HCRYPTPROV p; unsigned char b[32] = {0};
    if (!cgr_acquire(&p, PROV_DSS)) { t_note("PROV_DSS verify-context not available: %lu", GetLastError()); return; }
    CHECK(U(CryptGenRandom)(p, sizeof b, b) == TRUE);
    CHECK(!rng_all_zero(b, sizeof b));
    CHECK(U(CryptReleaseContext)(p, 0));
}
TEST(rngc_null_buffer_invalid_parameter) {
    if (t_is_wine()) { t_skip("emulator faults or differs here"); return; }
    REQUIRE(U(CryptAcquireContextW)); REQUIRE(U(CryptGenRandom)); REQUIRE(U(CryptReleaseContext));
    HCRYPTPROV p;
    if (!cgr_acquire(&p, PROV_RSA_AES)) { t_skip("no provider"); return; }
    SET_ERR(0);
    CHECK(U(CryptGenRandom)(p, 16, NULL) == FALSE);
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0);
    CHECK(U(CryptGenRandom)(p, 0, NULL) == FALSE);
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
    U(CryptReleaseContext)(p, 0);
}
TEST(rngc_zero_length) {
    REQUIRE(U(CryptAcquireContextW)); REQUIRE(U(CryptGenRandom)); REQUIRE(U(CryptReleaseContext));
    HCRYPTPROV p; unsigned char b[4] = {1, 2, 3, 4};
    if (!cgr_acquire(&p, PROV_RSA_AES)) { t_skip("no provider"); return; }
    BOOL r = U(CryptGenRandom)(p, 0, b);
    t_note("CryptGenRandom(len 0) = %d", r);
    CHECK(b[0] == 1 && b[3] == 4);
    U(CryptReleaseContext)(p, 0);
}
TEST(rngc_sizes_bounds) {
    REQUIRE(U(CryptAcquireContextW)); REQUIRE(U(CryptGenRandom)); REQUIRE(U(CryptReleaseContext));
    HCRYPTPROV p; unsigned char b[96]; unsigned n, i;
    if (!cgr_acquire(&p, PROV_RSA_AES)) { t_skip("no provider"); return; }
    for (n = 1; n <= 40; n++) {
        memset(b, 0xCC, sizeof b);
        CHECKF(U(CryptGenRandom)(p, n, b + 4) == TRUE, "n=%u", n);
        for (i = 0; i < 4; i++) CHECKF(b[i] == 0xCC, "n=%u underrun", n);
        for (i = 4 + n; i < sizeof b; i++) CHECKF(b[i] == 0xCC, "n=%u overrun", n);
    }
    U(CryptReleaseContext)(p, 0);
}
TEST(rngc_large) {
    REQUIRE(U(CryptAcquireContextW)); REQUIRE(U(CryptGenRandom)); REQUIRE(U(CryptReleaseContext));
    HCRYPTPROV p; SIZE_T n = 100000;
    if (!cgr_acquire(&p, PROV_RSA_AES)) { t_skip("no provider"); return; }
    unsigned char *b = (unsigned char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, n);
    if (!b) { U(CryptReleaseContext)(p, 0); t_skip("alloc"); return; }
    CHECK(U(CryptGenRandom)(p, (DWORD)n, b) == TRUE);
    CHECK(rng_popcount_plausible(b, n));
    CHECK(!rng_all_zero(b + n - 4096, 4096));
    HeapFree(GetProcessHeap(), 0, b);
    U(CryptReleaseContext)(p, 0);
}
TEST(rngc_differs_between_calls_and_providers) {
    REQUIRE(U(CryptAcquireContextW)); REQUIRE(U(CryptGenRandom)); REQUIRE(U(CryptReleaseContext));
    HCRYPTPROV p1, p2; unsigned char a[32], b[32], c[32];
    if (!cgr_acquire(&p1, PROV_RSA_AES) || !cgr_acquire(&p2, PROV_RSA_FULL)) { t_skip("no provider"); return; }
    CHECK(U(CryptGenRandom)(p1, 32, a)); CHECK(U(CryptGenRandom)(p1, 32, b)); CHECK(U(CryptGenRandom)(p2, 32, c));
    CHECK(memcmp(a, b, 32) != 0); CHECK(memcmp(a, c, 32) != 0); CHECK(memcmp(b, c, 32) != 0);
    U(CryptReleaseContext)(p1, 0); U(CryptReleaseContext)(p2, 0);
}
TEST(rngc_buffer_used_as_seed_still_random) {
    /* docs: the buffer content is used as additional seed; the result must still differ */
    REQUIRE(U(CryptAcquireContextW)); REQUIRE(U(CryptGenRandom)); REQUIRE(U(CryptReleaseContext));
    HCRYPTPROV p; unsigned char a[32], b[32];
    if (!cgr_acquire(&p, PROV_RSA_AES)) { t_skip("no provider"); return; }
    memset(a, 0x33, 32); memset(b, 0x33, 32);
    CHECK(U(CryptGenRandom)(p, 32, a)); CHECK(U(CryptGenRandom)(p, 32, b));
    CHECK(memcmp(a, b, 32) != 0);
    U(CryptReleaseContext)(p, 0);
}
TEST(rngc_advapi_and_cryptsp_parity) {
    if (t_is_wine()) { t_skip("emulator faults or differs here"); return; }
    typeof(&CryptGenRandom) fa = UIN("advapi32.dll", CryptGenRandom), fs = UIN("cryptsp.dll", CryptGenRandom);
    typeof(&CryptAcquireContextW) acq = UIN("advapi32.dll", CryptAcquireContextW);
    typeof(&CryptReleaseContext) rel = UIN("advapi32.dll", CryptReleaseContext);
    REQUIRE(fa); REQUIRE(fs); REQUIRE(acq); REQUIRE(rel);
    HCRYPTPROV p = 0; unsigned char a[32] = {0}, b[32] = {0};
    if (!acq(&p, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) { t_skip("no provider"); return; }
    CHECK(fa(p, 32, a)); CHECK(fs(p, 32, b));
    CHECK(!rng_all_zero(a, 32) && !rng_all_zero(b, 32) && memcmp(a, b, 32) != 0);
    SET_ERR(0); CHECK(fa(p, 4, NULL) == FALSE); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(fs(p, 4, NULL) == FALSE); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    rel(p, 0);
}
TEST(rngc_released_provider_flag_reserved) {
    REQUIRE(U(CryptAcquireContextW)); REQUIRE(U(CryptReleaseContext));
    HCRYPTPROV p;
    if (!cgr_acquire(&p, PROV_RSA_AES)) { t_skip("no provider"); return; }
    SET_ERR(0);
    BOOL r = U(CryptReleaseContext)(p, 0);
    CHECK(r == TRUE);
}
TEST(rngc_invalid_provider_object_magic) {
    if (t_is_wine()) { t_skip("emulator faults or differs here"); return; }
    /* a provider handle is validated against a magic value: a zeroed block is rejected */
    REQUIRE(U(CryptGenRandom));
    static unsigned char fake[512]; unsigned char b[8];
    memset(fake, 0, sizeof fake);
    SET_ERR(0);
    CHECK(U(CryptGenRandom)((HCRYPTPROV)(ULONG_PTR)fake, 8, b) == FALSE);
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
}
TEST(rngc_compare_apis_all_nonconstant) {
    REQUIRE(U(CryptAcquireContextW)); REQUIRE(U(CryptGenRandom)); REQUIRE(U(CryptReleaseContext)); REQUIRE(U(BCryptGenRandom));
    HCRYPTPROV p; unsigned char c[32], bc[32], sf[32];
    SystemFunction036_pfn f = UINN("advapi32.dll", SystemFunction036); REQUIRE(f);
    if (!cgr_acquire(&p, PROV_RSA_AES)) { t_skip("no provider"); return; }
    CHECK(U(CryptGenRandom)(p, 32, c));
    EQ_NT(U(BCryptGenRandom)(NULL, bc, 32, BCRYPT_USE_SYSTEM_PREFERRED_RNG), NS_SUCCESS);
    CHECK(f(sf, 32));
    CHECK(memcmp(c, bc, 32) && memcmp(c, sf, 32) && memcmp(bc, sf, 32));
    U(CryptReleaseContext)(p, 0);
}
