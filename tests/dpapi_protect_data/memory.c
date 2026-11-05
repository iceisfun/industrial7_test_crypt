#include "dp.h"
/* CryptProtectMemory / CryptUnprotectMemory (crypt32 -> SystemFunction040/041 -> ksecdd) */

UDECL(LONG, SystemFunction040, (PVOID, ULONG, ULONG));
UDECL(LONG, SystemFunction041, (PVOID, ULONG, ULONG));

#define BS CRYPTPROTECTMEMORY_BLOCK_SIZE
static const DWORD FLAGS3[3] = { CRYPTPROTECTMEMORY_SAME_PROCESS, CRYPTPROTECTMEMORY_CROSS_PROCESS, CRYPTPROTECTMEMORY_SAME_LOGON };
static const char *const FNAME[3] = { "same_process", "cross_process", "same_logon" };

static int mem_roundtrip(DWORD n, DWORD flags, int must_change) {
    BYTE *buf = malloc(n), *orig = malloc(n);
    dp_fill(buf, n, n + flags); memcpy(orig, buf, n);
    SET_ERR(0x1234);
    BOOL r = U(CryptProtectMemory)(buf, n, flags);
    DWORD e = GetLastError();
    CHECKF(r, "protect n=%lu flags=%lu err=%lu", n, flags, e);
    int ok = 0;
    if (r) {
        if (must_change) CHECKF(memcmp(buf, orig, n) != 0, "n=%lu flags=%lu buffer unchanged", n, flags);
        SET_ERR(0x1234);
        r = U(CryptUnprotectMemory)(buf, n, flags);
        e = GetLastError();
        CHECKF(r, "unprotect n=%lu flags=%lu err=%lu", n, flags, e);
        ok = r && !memcmp(buf, orig, n);
        CHECKF(ok, "n=%lu flags=%lu round trip mismatch", n, flags);
    }
    free(buf); free(orig);
    return ok;
}

/* ---- round trips ---- */

#define RT_TEST(nm, N) \
TEST(dpapi_mem_rt_##nm) { DP_NEED_MEM(); for (int f = 0; f < 3; f++) mem_roundtrip(N, FLAGS3[f], 0); }
RT_TEST(16, 16)
RT_TEST(32, 32)
RT_TEST(48, 48)
RT_TEST(64, 64)
RT_TEST(128, 128)
RT_TEST(160, 160)
RT_TEST(256, 256)
RT_TEST(1024, 1024)
RT_TEST(4096, 4096)
RT_TEST(8192, 8192)
RT_TEST(65536, 65536)

TEST(dpapi_mem_block_size_constant) { EXPECT_EQ(CRYPTPROTECTMEMORY_BLOCK_SIZE, 16); EXPECT_EQ(CRYPTPROTECTMEMORY_SAME_PROCESS, 0); EXPECT_EQ(CRYPTPROTECTMEMORY_CROSS_PROCESS, 1); EXPECT_EQ(CRYPTPROTECTMEMORY_SAME_LOGON, 2); }

TEST(dpapi_mem_protect_changes_buffer_in_place) {
    DP_NEED_MEM(); DP_NOT_WINE();
    for (int f = 0; f < 3; f++) {
        mem_roundtrip(64, FLAGS3[f], 1);
        mem_roundtrip(16, FLAGS3[f], 1);
        mem_roundtrip(1024, FLAGS3[f], 1);
    }
}
TEST(dpapi_mem_zeros_do_not_stay_zero) {
    DP_NEED_MEM(); DP_NOT_WINE();
    BYTE b[64]; memset(b, 0, sizeof b);
    CHECK(U(CryptProtectMemory)(b, sizeof b, 0));
    BYTE z[64] = { 0 };
    CHECK(memcmp(b, z, sizeof b) != 0);
    CHECK(U(CryptUnprotectMemory)(b, sizeof b, 0));
    CHECK(!memcmp(b, z, sizeof b));
}
TEST(dpapi_mem_only_requested_bytes_touched) {
    DP_NEED_MEM();
    BYTE raw[16 + 48 + 16];
    memset(raw, 0xCC, sizeof raw);
    dp_fill(raw + 16, 48, 3);
    BYTE tail[16]; memcpy(tail, raw + 64, 16);
    CHECK(U(CryptProtectMemory)(raw + 16, 48, 0));
    for (int i = 0; i < 16; i++) { CHECKF(raw[i] == 0xCC, "head byte %d", i); CHECKF(raw[64 + i] == 0xCC, "tail byte %d", i); }
    CHECK(U(CryptUnprotectMemory)(raw + 16, 48, 0));
    BYTE exp[48]; dp_fill(exp, 48, 3);
    CHECK(!memcmp(raw + 16, exp, 48));
}
TEST(dpapi_mem_blocks_independent_sizes_prefix) {
    DP_NEED_MEM(); DP_NOT_WINE();
    /* unprotecting only the first 32 bytes of a 64 byte protected buffer restores the first 32 bytes (observed) */
    BYTE b[64], o[64]; dp_fill(b, 64, 1); memcpy(o, b, 64);
    CHECK(U(CryptProtectMemory)(b, 64, 0));
    CHECK(U(CryptUnprotectMemory)(b, 32, 0));
    EXPECT_EQ(!memcmp(b, o, 32), 1);
}
TEST(dpapi_mem_double_protect_roundtrips) {
    DP_NEED_MEM(); DP_NOT_WINE();
    BYTE b[48], o[48]; dp_fill(b, 48, 5); memcpy(o, b, 48);
    CHECK(U(CryptProtectMemory)(b, 48, 0));
    BYTE once[48]; memcpy(once, b, 48);
    CHECK(U(CryptProtectMemory)(b, 48, 0));
    CHECK(memcmp(b, once, 48) != 0);
    CHECK(U(CryptUnprotectMemory)(b, 48, 0));
    CHECK(!memcmp(b, once, 48));
    CHECK(U(CryptUnprotectMemory)(b, 48, 0));
    CHECK(!memcmp(b, o, 48));
}
TEST(dpapi_mem_protect_is_deterministic_in_one_process) {
    DP_NEED_MEM(); DP_NOT_WINE();
    BYTE a[32], b[32]; dp_fill(a, 32, 6); memcpy(b, a, 32);
    CHECK(U(CryptProtectMemory)(a, 32, 0)); CHECK(U(CryptProtectMemory)(b, 32, 0));
    EXPECT_EQ(!memcmp(a, b, 32), 1);
}
TEST(dpapi_mem_flags_produce_distinct_ciphertext) {
    DP_NEED_MEM(); DP_NOT_WINE();
    BYTE c[3][32];
    for (int f = 0; f < 3; f++) { dp_fill(c[f], 32, 7); CHECK(U(CryptProtectMemory)(c[f], 32, FLAGS3[f])); }
    EXPECT_EQ(!memcmp(c[0], c[1], 32), 0); EXPECT_EQ(!memcmp(c[0], c[2], 32), 0); EXPECT_EQ(!memcmp(c[1], c[2], 32), 0);
    BYTE p[32]; dp_fill(p, 32, 7);
    CHECK(memcmp(c[0], p, 32) != 0 && memcmp(c[1], p, 32) != 0 && memcmp(c[2], p, 32) != 0);
}
TEST(dpapi_mem_wrong_flag_succeeds_but_does_not_restore) {
    DP_NEED_MEM(); DP_NOT_WINE();
    for (int a = 0; a < 3; a++) for (int b = 0; b < 3; b++) {
        if (a == b) continue;
        BYTE buf[32], o[32]; dp_fill(buf, 32, 8); memcpy(o, buf, 32);
        CHECK(U(CryptProtectMemory)(buf, 32, FLAGS3[a]));
        SET_ERR(0);
        BOOL r = U(CryptUnprotectMemory)(buf, 32, FLAGS3[b]);
        t_label("protect %s, unprotect %s", FNAME[a], FNAME[b]);
        EXPECT_EQ(r, 1);                              /* no error, but the bytes are not the plaintext */
        EXPECT_EQ(!memcmp(buf, o, 32), 0);
    }
}
TEST(dpapi_mem_unprotect_never_protected_succeeds_with_garbage) {
    DP_NEED_MEM(); DP_NOT_WINE();
    BYTE buf[32], o[32]; dp_fill(buf, 32, 9); memcpy(o, buf, 32);
    SET_ERR(0);
    BOOL r = U(CryptUnprotectMemory)(buf, 32, 0);
    EXPECT_EQ(r, 1);
    CHECK(memcmp(buf, o, 32) != 0);   /* decrypting plaintext cannot give the same bytes back */
}
/* ---- parameter validation ---- */

TEST(dpapi_mem_size_not_multiple_of_block) {
    DP_NOT_WINE();
    DP_NEED_MEM();
    static const DWORD sizes[] = { 1, 2, 7, 8, 15, 17, 24, 31, 33, 47, 63, 100, 4095 };
    for (int f = 0; f < 3; f++) for (size_t i = 0; i < sizeof sizes / sizeof *sizes; i++) {
        BYTE *buf = calloc(1, sizes[i] + 16);
        SET_ERR(0);
        BOOL r = U(CryptProtectMemory)(buf, sizes[i], FLAGS3[f]);
        t_label("protect size %lu flags %lu", sizes[i], FLAGS3[f]);
        if (sizes[i] % 8 == 0) { EXPECT_EQ(r, 1); }   /* observed: any multiple of 8 is accepted */
        else { EXPECT_EQ(r, 0); EXPECT_EQ(GetLastError(), 87); }
        SET_ERR(0);
        r = U(CryptUnprotectMemory)(buf, sizes[i], FLAGS3[f]);
        t_label("unprotect size %lu flags %lu", sizes[i], FLAGS3[f]);
        if (sizes[i] % 8 == 0) { EXPECT_EQ(r, 1); }
        else { EXPECT_EQ(r, 0); EXPECT_EQ(GetLastError(), 87); }
        free(buf);
    }
}
TEST(dpapi_mem_misaligned_size_leaves_buffer) {
    DP_NOT_WINE();
    DP_NEED_MEM();
    BYTE b[48], o[48]; dp_fill(b, 48, 2); memcpy(o, b, 48);
    CHECK(!U(CryptProtectMemory)(b, 17, 0));
    CHECK(!U(CryptUnprotectMemory)(b, 17, 0));
    CHECK(!memcmp(b, o, 48));
}
TEST(dpapi_mem_size_zero_is_invalid_parameter) {
    DP_NEED_MEM();
    BYTE b[16] = { 0 };
    SET_ERR(0);
    BOOL r = U(CryptProtectMemory)(b, 0, 0);
    EXPECT_EQ(r, 0); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0);
    r = U(CryptUnprotectMemory)(b, 0, 0);
    EXPECT_EQ(r, 0); EXPECT_ERR(ERROR_INVALID_PARAMETER);
}
TEST(dpapi_mem_null_buffer_is_invalid_access) {
    DP_NEED_MEM();
    SET_ERR(0);
    BOOL r = U(CryptProtectMemory)(NULL, 16, 0);
    EXPECT_EQ(r, 0); EXPECT_ERR(ERROR_NOACCESS);
    SET_ERR(0);
    r = U(CryptUnprotectMemory)(NULL, 16, 0);
    EXPECT_EQ(r, 0); EXPECT_ERR(ERROR_NOACCESS);
}
static void bad_flag(DWORD fl) {
    BYTE b[32], o[32]; dp_fill(b, 32, 1); memcpy(o, b, 32);
    SET_ERR(0);
    BOOL r = U(CryptProtectMemory)(b, 32, fl);
    CHECKF(!r, "protect flags 0x%lx succeeded", fl); CHECKF(GetLastError() == ERROR_INVALID_PARAMETER, "protect flags 0x%lx err %lu", fl, GetLastError());
    SET_ERR(0);
    r = U(CryptUnprotectMemory)(b, 32, fl);
    CHECKF(!r, "unprotect flags 0x%lx succeeded", fl); CHECKF(GetLastError() == ERROR_INVALID_PARAMETER, "unprotect flags 0x%lx err %lu", fl, GetLastError());
    CHECKF(!memcmp(b, o, 32), "flags 0x%lx modified the buffer", fl);
}
#define BADFLAG_TEST(nm, v) TEST(dpapi_mem_bad_flags_##nm) { DP_NEED_MEM(); DP_NOT_WINE(); bad_flag(v); }
BADFLAG_TEST(3, 3)
BADFLAG_TEST(5, 5)
BADFLAG_TEST(6, 6)
BADFLAG_TEST(7, 7)
BADFLAG_TEST(8, 8)
BADFLAG_TEST(0x10, 0x10)
BADFLAG_TEST(0x100, 0x100)
BADFLAG_TEST(0x10000, 0x10000)
BADFLAG_TEST(0x80000000, 0x80000000u)
BADFLAG_TEST(0xffffffff, 0xffffffffu)
TEST(dpapi_mem_flag_4_protects_but_cannot_be_unprotected) {
    DP_NEED_MEM();
    BYTE b[32]; dp_fill(b, 32, 1);
    SET_ERR(0);
    BOOL r = U(CryptProtectMemory)(b, 32, 4);
    EXPECT_EQ(r, 1);          /* flags 4 is not in dpapi.h: protect accepts it, unprotect with it is denied */
    { BYTE o[32]; dp_fill(o, 32, 1); SET_ERR(0); EXPECT_EQ(U(CryptUnprotectMemory)(b, 32, 4), 0); EXPECT_ERR(ERROR_ACCESS_DENIED); CHECK(memcmp(b, o, 32) != 0); }
}
TEST(dpapi_mem_bad_flag_precedes_size_check) {
    DP_NOT_WINE();
    DP_NEED_MEM();
    BYTE b[32] = { 0 };
    SET_ERR(0);
    CHECK(!U(CryptProtectMemory)(b, 17, 9)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
}

/* ---- SystemFunction040/041 (the real implementation behind the wrappers) ---- */

TEST(dpapi_sysfn_resolve_in_cryptbase) {
    DP_NOT_WINE();
    CHECK(t_proc_in("cryptbase.dll", "SystemFunction040") != NULL);
    CHECK(t_proc_in("cryptbase.dll", "SystemFunction041") != NULL);
}
TEST(dpapi_sysfn_resolve_forwarded) {
    DP_NOT_WINE();
    FARPROC a = t_proc_in("advapi32.dll", "SystemFunction040"), b = t_proc_in("cryptbase.dll", "SystemFunction040");
    FARPROC a1 = t_proc_in("advapi32.dll", "SystemFunction041"), b1 = t_proc_in("cryptbase.dll", "SystemFunction041");
    CHECK(a != NULL); CHECK(a1 != NULL);
    CHECK(a == b);        /* advapi32 forwards to CRYPTBASE */
    CHECK(a1 == b1);
    CHECK(a != a1);
}
TEST(dpapi_sysfn_bad_flags_status_invalid_parameter) {
    DP_NOT_WINE();
    SystemFunction040_pfn f = (SystemFunction040_pfn)t_proc_in("cryptbase.dll", "SystemFunction040");
    SystemFunction041_pfn g = (SystemFunction041_pfn)t_proc_in("cryptbase.dll", "SystemFunction041");
    if (!f || !g) { t_skip("missing SystemFunction040/041"); return; }
    BYTE b[32] = { 0 };
    static const ULONG bad[] = { 3, 5, 8, 0x100, 0xffffffffu };
    for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) {
        CHECKF((ULONG)f(b, 32, bad[i]) == 0xC000000D, "040 flags 0x%lx -> 0x%lx", bad[i], (ULONG)f(b, 32, bad[i]));
        CHECKF((ULONG)g(b, 32, bad[i]) == 0xC000000D, "041 flags 0x%lx", bad[i]);
    }
}
TEST(dpapi_sysfn_roundtrip_status_success) {
    DP_NOT_WINE();
    SystemFunction040_pfn f = (SystemFunction040_pfn)t_proc_in("cryptbase.dll", "SystemFunction040");
    SystemFunction041_pfn g = (SystemFunction041_pfn)t_proc_in("cryptbase.dll", "SystemFunction041");
    if (!f || !g) { t_skip("missing SystemFunction040/041"); return; }
    BYTE b[32], o[32]; dp_fill(b, 32, 4); memcpy(o, b, 32);
    CHECK(f(b, 32, 0) == 0);
    CHECK(g(b, 32, 0) == 0);
    CHECK(!memcmp(b, o, 32));
}
TEST(dpapi_sysfn_wrapper_equivalence) {
    DP_NOT_WINE();
    DP_NEED_MEM();
    SystemFunction040_pfn f = (SystemFunction040_pfn)t_proc_in("cryptbase.dll", "SystemFunction040");
    SystemFunction041_pfn g = (SystemFunction041_pfn)t_proc_in("cryptbase.dll", "SystemFunction041");
    if (!f || !g) { t_skip("missing SystemFunction040/041"); return; }
    /* protect via Rtl entry point, unprotect via the crypt32 wrapper and the other way round */
    BYTE b[32], o[32]; dp_fill(b, 32, 12); memcpy(o, b, 32);
    CHECK(f(b, 32, 1) == 0);
    CHECK(U(CryptUnprotectMemory)(b, 32, 1));
    CHECK(!memcmp(b, o, 32));
    CHECK(U(CryptProtectMemory)(b, 32, 2));
    CHECK(g(b, 32, 2) == 0);
    CHECK(!memcmp(b, o, 32));
}
TEST(dpapi_mem_crypt32_forwards_to_dpapi) {
    DP_NOT_WINE();
    /* crypt32 exports CryptProtectMemory/CryptUnprotectMemory/CryptUpdateProtectedState as forwarders to DPAPI.dll */
    static const char *const n[] = { "CryptProtectMemory", "CryptUnprotectMemory", "CryptUpdateProtectedState" };
    for (int i = 0; i < 3; i++) {
        FARPROC a = t_proc_in("crypt32.dll", n[i]), b = t_proc_in("dpapi.dll", n[i]);
        CHECKF(a != NULL && b != NULL, "%s", n[i]);
        CHECKF(a == b, "%s: crypt32 %p dpapi %p", n[i], a, b);
    }
}
TEST(dpapi_data_crypt32_exports_are_not_forwarders) {
    DP_NOT_WINE();
    /* CryptProtectData / CryptUnprotectData are implemented in crypt32 itself */
    static const char *const n[] = { "CryptProtectData", "CryptUnprotectData" };
    HMODULE m = t_module("crypt32.dll");
    for (int i = 0; i < 2; i++) {
        FARPROC a = t_proc_in("crypt32.dll", n[i]);
        CHECKF(a != NULL, "%s", n[i]);
        HMODULE h = NULL;
        GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCSTR)a, &h);
        CHECKF(h == m, "%s lives in %p", n[i], h);
    }
}

/* ---- threads ---- */

typedef struct { BYTE buf[64]; BYTE orig[64]; int rc; } thr_t;
static DWORD WINAPI unprotect_thread(LPVOID p) {
    thr_t *t = p;
    t->rc = U(CryptUnprotectMemory)(t->buf, 64, CRYPTPROTECTMEMORY_SAME_PROCESS) ? (memcmp(t->buf, t->orig, 64) ? 2 : 0) : 1;
    return 0;
}
TEST(dpapi_mem_same_process_across_threads) {
    DP_NEED_MEM();
    thr_t t; dp_fill(t.buf, 64, 20); memcpy(t.orig, t.buf, 64); t.rc = -1;
    CHECK(U(CryptProtectMemory)(t.buf, 64, CRYPTPROTECTMEMORY_SAME_PROCESS));
    HANDLE h = CreateThread(NULL, 0, unprotect_thread, &t, 0, NULL);
    CHECK(h != NULL);
    if (h) { CHECK(WaitForSingleObject(h, 10000) == WAIT_OBJECT_0); CloseHandle(h); }
    CHECK(t.rc == 0);
}
static DWORD WINAPI protect_thread(LPVOID p) {
    thr_t *t = p;
    t->rc = U(CryptProtectMemory)(t->buf, 64, CRYPTPROTECTMEMORY_SAME_PROCESS) ? 0 : 1;
    return 0;
}
TEST(dpapi_mem_protect_on_thread_unprotect_on_main) {
    DP_NEED_MEM();
    thr_t t; dp_fill(t.buf, 64, 21); memcpy(t.orig, t.buf, 64); t.rc = -1;
    HANDLE h = CreateThread(NULL, 0, protect_thread, &t, 0, NULL);
    CHECK(h != NULL);
    if (h) { CHECK(WaitForSingleObject(h, 10000) == WAIT_OBJECT_0); CloseHandle(h); }
    CHECK(t.rc == 0);
    CHECK(U(CryptUnprotectMemory)(t.buf, 64, CRYPTPROTECTMEMORY_SAME_PROCESS));
    CHECK(!memcmp(t.buf, t.orig, 64));
}

/* ---- cross-process ---- */

/* argv: 1=flags 2=hex ciphertext 3=hex expected plaintext. exit: 0 recovered, 1 call failed, 2 not recovered */
CHILD(dpapi_mem_unprot) {
    if (argc < 4) return 9;
    if (!U(CryptUnprotectMemory)) return 8;
    BYTE c[4096], e[4096];
    int n = dp_unhex(argv[2], c, sizeof c), m = dp_unhex(argv[3], e, sizeof e);
    if (n != m || n % 16) return 7;
    if (!U(CryptUnprotectMemory)(c, (DWORD)n, (DWORD)atoi(argv[1]))) return 1;
    return memcmp(c, e, n) ? 2 : 0;
}
CHILD(dpapi_mem_selfrt) {
    BYTE b[64], o[64]; dp_fill(b, 64, 30); memcpy(o, b, 64);
    DWORD fl = argc > 1 ? (DWORD)atoi(argv[1]) : 0;
    if (!U(CryptProtectMemory)(b, 64, fl)) return 1;
    if (!U(CryptUnprotectMemory)(b, 64, fl)) return 2;
    return memcmp(b, o, 64) ? 3 : 0;
}

static DWORD child_mem(DWORD protect_flags, DWORD unprotect_flags) {
    BYTE b[48], o[48]; dp_fill(b, 48, 40 + protect_flags); memcpy(o, b, 48);
    if (!U(CryptProtectMemory)(b, 48, protect_flags)) return 0xFFFF;
    char hc[200], ho[200], args[512];
    dp_hex(b, 48, hc); dp_hex(o, 48, ho);
    snprintf(args, sizeof args, "%lu %s %s", unprotect_flags, hc, ho);
    return t_run_child("dpapi_mem_unprot", args, 20000);
}
TEST(dpapi_mem_child_self_roundtrip) {
    DP_NEED_MEM();
    for (int f = 0; f < 3; f++) { char a[16]; snprintf(a, sizeof a, "%lu", FLAGS3[f]); CHECKF(t_run_child("dpapi_mem_selfrt", a, 20000) == 0, "flags %d", f); }
}
TEST(dpapi_mem_cross_process_recovers) {
    DP_NEED_MEM(); DP_NOT_WINE();
    EXPECT_EQ(child_mem(CRYPTPROTECTMEMORY_CROSS_PROCESS, CRYPTPROTECTMEMORY_CROSS_PROCESS), 0);
}
TEST(dpapi_mem_same_logon_recovers_in_child) {
    DP_NEED_MEM(); DP_NOT_WINE();
    EXPECT_EQ(child_mem(CRYPTPROTECTMEMORY_SAME_LOGON, CRYPTPROTECTMEMORY_SAME_LOGON), 0);
}
TEST(dpapi_mem_same_process_not_recovered_in_child) {
    DP_NEED_MEM(); DP_NOT_WINE();
    DWORD rc = child_mem(CRYPTPROTECTMEMORY_SAME_PROCESS, CRYPTPROTECTMEMORY_SAME_PROCESS);
    EXPECT_EQ(rc, 2);                      /* the call succeeds in the child but yields garbage: the key is bound to the protecting process */
}
TEST(dpapi_mem_cross_process_blob_wrong_flag_in_child) {
    DP_NEED_MEM(); DP_NOT_WINE();
    DWORD rc = child_mem(CRYPTPROTECTMEMORY_CROSS_PROCESS, CRYPTPROTECTMEMORY_SAME_LOGON);
    EXPECT_EQ(rc, 2);          /* succeeds, garbage */
}
TEST(dpapi_mem_same_logon_blob_wrong_flag_in_child) {
    DP_NEED_MEM(); DP_NOT_WINE();
    DWORD rc = child_mem(CRYPTPROTECTMEMORY_SAME_LOGON, CRYPTPROTECTMEMORY_CROSS_PROCESS);
    EXPECT_EQ(rc, 2);          /* succeeds, garbage */
}
TEST(dpapi_mem_cross_process_flag_rejected_in_child_bad_size) {
    DP_NOT_WINE();
    DP_NEED_MEM();
    BYTE b[32]; dp_fill(b, 32, 1);
    char hc[80], args[200];
    dp_hex(b, 32, hc);
    snprintf(args, sizeof args, "1 %s %s", hc, hc);   /* identical hex, 32 bytes: valid length; child must not hang */
    DWORD rc = t_run_child("dpapi_mem_unprot", args, 20000);
    CHECK(rc != 0xDEAD0001 && rc != 0xDEAD0000);
    EXPECT_EQ(rc, 2);                                  /* the call succeeds, plaintext cannot reproduce itself */
}
