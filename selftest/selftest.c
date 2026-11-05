/* Harness self-test.  Default run: every test must pass on Windows 10 22H2 (std and adm).
 * Fault run (env SELFTEST_FAULTS=1, T_TIMEOUT_S=5): the stf_* tests deliberately hang/crash/fail; the expected output is
 * described in the comment next to each test and checked by eye or by tools/check_selftest.py. */
#include "t.h"
#include <wincrypt.h>

static int faults_enabled(void) { char b[4]; return GetEnvironmentVariableA("SELFTEST_FAULTS", b, sizeof b) && b[0] == '1'; }
#define REQUIRE_FAULTS() do { if (!faults_enabled()) { t_skip("fault run only (SELFTEST_FAULTS=1)"); return; } } while (0)

/* ---- macros evaluate their arguments once ---- */
static int g_calls;
static int next_call(void) { return ++g_calls; }
static const char *next_str(void) { g_calls++; return "abc"; }
TEST(st_args_evaluated_once) {
    g_calls = 0; EXPECT_EQ(next_call(), 1); EXPECT_EQ(g_calls, 1);
    g_calls = 0; EXPECT_NE(next_call(), 0); EXPECT_EQ(g_calls, 1);
    g_calls = 0; EXPECT_STR(next_str(), "abc"); EXPECT_EQ(g_calls, 1);
    g_calls = 0; SET_ERR(77); EXPECT_ERR((g_calls++, 77)); EXPECT_EQ(g_calls, 1);
    g_calls = 0; CHECK(next_call() == 1); EXPECT_EQ(g_calls, 1);
    g_calls = 0; CHECKF(next_call() > 0, "x %d", next_call()); EXPECT_EQ(g_calls, 2);
}
TEST(st_narrow_compare) {
    HRESULT hr = (HRESULT)0x80090005L; LONG l = (LONG)0x80090005L; NTSTATUS st = (NTSTATUS)0xC0000005;
    EXPECT_EQ(hr, 0x80090005); EXPECT_EQ(hr, 0x80090005L); EXPECT_EQ(l, 0x80090005u); EXPECT_EQ(st, 0xC0000005);
    EXPECT_NE(hr, 0x80090004);
    unsigned long long big = 0x180090005ULL; EXPECT_NE(big, 0x80090005u);     /* wide operands compare exactly */
    void *p = NULL; EXPECT_EQ(p, NULL); EXPECT_NE(&hr, NULL);
}

/* ---- GetProcAddress failure codes (probed on Win10 22H2) ---- */
TEST(st_gpa_errors) {
    HMODULE k = GetModuleHandleA("kernel32.dll"), c = t_module("crypt32.dll");
    EXPECT_GPA_FAIL(k, "NoSuchExport_xyz");
    EXPECT_GPA_FAIL(k, "");
    EXPECT_GPA_FAIL(k, MAKEINTRESOURCEA(0));
    EXPECT_GPA_FAIL(k, MAKEINTRESOURCEA(0xFFFF));
    EXPECT_GPA_FAIL(k, MAKEINTRESOURCEA(60000));
    EXPECT_GPA_FAIL(c, MAKEINTRESOURCEA(1000));          /* below Base 1001 */
    EXPECT_GPA_FAIL(c, MAKEINTRESOURCEA(2001));          /* above Base+count */
    EXPECT_GPA_FAIL(c, "NoSuchExport_xyz");
    SetLastError(0); FARPROC p = GetProcAddress((HMODULE)(ULONG_PTR)0x1234, "x");
    EXPECT_EQ(p, NULL); EXPECT_ERR(ERROR_MOD_NOT_FOUND);
    SetLastError(0); p = GetProcAddress(NULL, "NoSuchExport_xyz");
    EXPECT_EQ(p, NULL); EXPECT_ERR(ERROR_PROC_NOT_FOUND);
}

/* ---- legacy CryptoAPI error rule (probed): advapi32 rejects bad handles/pointers with 87 before the CSP is called;
 *      the CSP's NTE_* only appear for a valid handle and a bad value ---- */
TEST(st_capi_error_rule) {
    HCRYPTPROV p = 0; HCRYPTHASH h = 0; HCRYPTKEY k = 0; BYTE buf[64]; DWORD n = sizeof buf;
    EXPECT_CAPI_FAIL(CryptAcquireContextA(&p, NULL, "bogus", PROV_RSA_FULL, CRYPT_VERIFYCONTEXT), NTE_KEYSET_NOT_DEF);
    EXPECT_CAPI_FAIL(CryptAcquireContextA(&p, NULL, NULL, 9999, CRYPT_VERIFYCONTEXT), NTE_BAD_PROV_TYPE);
    EXPECT_CAPI_FAIL(CryptAcquireContextA(NULL, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT), ERROR_INVALID_PARAMETER);
    EXPECT_CAPI_FAIL(CryptAcquireContextA(&p, NULL, NULL, PROV_RSA_FULL, 0x7F000000), NTE_BAD_FLAGS);
    EXPECT_CAPI_FAIL(CryptGenRandom(0, 8, buf), ERROR_INVALID_PARAMETER);
    EXPECT_CAPI_FAIL(CryptReleaseContext(0, 0), ERROR_INVALID_PARAMETER);
    EXPECT_CAPI_FAIL(CryptDestroyKey(0x1234), ERROR_INVALID_PARAMETER);
    EXPECT_CAPI_FAIL(CryptHashData(0x1234, buf, 4, 0), ERROR_INVALID_PARAMETER);
    EXPECT_CAPI_FAIL(CryptGetKeyParam(0x1234, KP_ALGID, buf, &n, 0), ERROR_INVALID_PARAMETER);
    EXPECT_CAPI_OK(CryptAcquireContextA(&p, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT));
    REQUIRE_OK(p != 0);
    EXPECT_CAPI_FAIL(CryptCreateHash(p, 0xdead, 0, 0, &h), NTE_BAD_ALGID);
    EXPECT_CAPI_FAIL(CryptCreateHash(p, CALG_SHA1, 0, 0, NULL), ERROR_INVALID_PARAMETER);
    EXPECT_CAPI_FAIL(CryptCreateHash(p, CALG_SHA1, 0, 5, &h), NTE_BAD_FLAGS);
    EXPECT_CAPI_FAIL(CryptGenKey(p, 0xdead, 0, &k), NTE_BAD_ALGID);
    EXPECT_CAPI_FAIL(CryptGenKey(p, CALG_AES_128, 0, NULL), ERROR_INVALID_PARAMETER);
    EXPECT_CAPI_OK(CryptCreateHash(p, CALG_SHA_256, 0, 0, &h));
    REQUIRE_OK(h != 0);
    EXPECT_CAPI_FAIL(CryptHashData(h, NULL, 5, 0), NTE_BAD_DATA);
    n = sizeof buf; EXPECT_CAPI_FAIL(CryptGetHashParam(h, 0x99, buf, &n, 0), NTE_BAD_TYPE);
    EXPECT_CAPI_FAIL(CryptGetUserKey(p, AT_SIGNATURE, &k), NTE_NO_KEY);
    n = sizeof buf; EXPECT_CAPI_FAIL(CryptGetProvParam(p, 0x999, buf, &n, 0), NTE_BAD_TYPE);
    EXPECT_CAPI_FAIL(CryptEnumProvidersA(9999, NULL, 0, &n, NULL, &n), ERROR_NO_MORE_ITEMS);
    CryptDestroyHash(h); CryptReleaseContext(p, 0);
}

/* ---- last-error convention ---- */
TEST(st_last_error_helpers) {
    EXPECT_FAILS(DeleteFileA("C:\\i7t_no_such_dir\\no_such_file.tmp"), ERROR_PATH_NOT_FOUND);
    EXPECT_FAILS_RET(CreateFileA("C:\\i7t_no_such_dir\\x", GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL), INVALID_HANDLE_VALUE, ERROR_PATH_NOT_FOUND);
    EXPECT_SUCCEEDS(GetCurrentProcessId());
    DWORD e; BOOL r = T_CALL_ERR(&e, CloseHandle((HANDLE)(ULONG_PTR)0x7777));
    CHECK(!r); EXPECT_EQ(e, ERROR_INVALID_HANDLE);
    e = T_LASTERR_AFTER(SetEvent(NULL)); EXPECT_EQ(e, ERROR_INVALID_HANDLE);
    SET_ERR(0x1234); (void)GetCurrentProcessId(); EXPECT_ERR(0x1234);          /* success leaves the old value alone */
}

/* ---- size-query protocol ---- */
TEST(st_size_query_protocol) {
    BYTE in[3] = { 1, 2, 3 }; DWORD q = 0, f = 0; char out[64];
    BOOL (WINAPI *f2s)(const BYTE *, DWORD, DWORD, LPSTR, DWORD *) = (void *)t_proc_in("crypt32.dll", "CryptBinaryToStringA");
    REQUIRE(f2s);
    REQUIRE_OK(f2s(in, 3, CRYPT_STRING_BASE64, NULL, &q));
    f = sizeof out; REQUIRE_OK(f2s(in, 3, CRYPT_STRING_BASE64, out, &f));
    t_note("CryptBinaryToStringA base64 3 bytes: query=%lu final=%lu", q, f);
    EXPECT_SIZE_QUERY(q, f, 6);
    REQUIRE_SANE_SIZE(q);
}

/* ---- REQUIRE_OK leaves the test; T_TRY / T_EXPECT_FAULT contain a fault ---- */
static int reach_after(int ok) { int reached = 0; (void)reached; return ok; }
static void require_helper(int *reached, int ok) { REQUIRE_OK(ok); *reached = 1; }
TEST(st_require_ok_flow) { int reached = 0; require_helper(&reached, 1); EXPECT_EQ(reached, 1); }
TEST(st_expect_fault) {
    T_EXPECT_FAULT(*(volatile int *)0 = 1);
    T_EXPECT_FAULT(RaiseException(EXCEPTION_ACCESS_VIOLATION, 0, 0, NULL));
    T_EXPECT_FAULT(*(volatile int *)8 = 1);
    CHECK(IsBadReadPtr(NULL, 4));            /* foreign code that catches its own fault is not a failure */
    CHECK(IsBadWritePtr((void *)16, 4));
    volatile int after = 1; EXPECT_EQ(after, 1);
}

/* ---- environment ---- */
TEST(st_environment_probes) {
    t_note("elevated=%d destructive=%d join=%d tpm=%d (0x%08lx) wine=%d", t_is_elevated(), t_is_destructive(), t_join_status(), t_has_tpm(), (unsigned long)t_tpm_status(), t_is_wine());
    CHECK(t_is_elevated() == 0 || t_is_elevated() == 1);
    CHECK(t_join_status() >= 0 && t_join_status() <= 3);
    CHECK(!t_is_domain_joined());          /* the oracle guest is a workgroup machine */
    CHECK(!t_is_wine());
    if (t_has_tpm()) EXPECT_EQ(t_tpm_status(), 0);
    else EXPECT_EQ(t_tpm_status(), 0x8028400F);
    HANDLE h = OpenSCManagerA(NULL, NULL, SC_MANAGER_CREATE_SERVICE | SC_MANAGER_ENUMERATE_SERVICE);   /* write access to the SCM needs elevation */
    if (t_is_elevated()) CHECK(h != NULL); else CHECK(h == NULL);
    if (h) CloseServiceHandle(h);
}
TEST(st_require_elevated_skip) {
    REQUIRE_ELEVATED();
    CHECK(t_is_elevated());
}
TEST(st_require_tpm_skip) { REQUIRE_TPM(); CHECK(t_has_tpm()); }
TEST(st_require_destructive_skip) { REQUIRE_DESTRUCTIVE(); CHECK(t_is_destructive()); }

/* ---- unique names, sweeper, defer ---- */
static int g_swept_start, g_stale_removed;
#define SW_PATH "Software\\I7T_selftest_probe"
T_SWEEPER(selftest_reg) {
    if (phase == T_SWEEP_START) {
        /* leftovers of an earlier (killed) run: create one stale key, as if a crash had left it, then sweep must remove it */
        HKEY k, k2;
        if (RegCreateKeyExA(HKEY_CURRENT_USER, SW_PATH, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &k, NULL) == 0) {
            char nm[260]; snprintf(nm, sizeof nm, "%sstale_1", prefix);
            if (RegCreateKeyExA(k, nm, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &k2, NULL) == 0) RegCloseKey(k2);
            RegSetValueExA(k, "keepme", 0, REG_SZ, (const BYTE *)"x", 2);
            snprintf(nm, sizeof nm, "%sstale_value", prefix); RegSetValueExA(k, nm, 0, REG_SZ, (const BYTE *)"x", 2);
            RegCloseKey(k);
        }
        g_stale_removed = t_reg_sweep_subkeys(HKEY_CURRENT_USER, SW_PATH, prefix) + 100 * t_reg_sweep_values(HKEY_CURRENT_USER, SW_PATH, prefix);
        g_swept_start = 1;
    } else {
        t_reg_sweep_subkeys(HKEY_CURRENT_USER, SW_PATH, prefix);
        HKEY r; if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software", 0, DELETE, &r) == 0) { RegDeleteKeyA(r, "I7T_selftest_probe"); RegCloseKey(r); }
    }
}
static int g_defer_ran;
static void defer_mark(void *a) { *(int *)a = 1; }
TEST(st_unique_names) {
    const char *a = t_unique("key"), *b = t_unique("key");
    CHECK(strcmp(a, b) != 0);
    CHECK(!strncmp(a, t_area_prefix(), strlen(t_area_prefix())));
    EXPECT_STR(t_area_prefix(), "I7T_selftest_");
    CHECK(!strncmp(a, "I7T_selftest_key_", 17));
    const WCHAR *w = t_unique_w("w"); CHECK(w[0] == L'I' && w[3] == L'_');
    if (!g_swept_start) { t_skip("worker was restarted after a fault: the start sweep ran in an earlier worker"); return; }
    EXPECT_EQ(g_stale_removed, 101);       /* one stale subkey + one stale value removed, "keepme" untouched */
    HKEY k; EXPECT_EQ(RegOpenKeyExA(HKEY_CURRENT_USER, SW_PATH, 0, KEY_READ, &k), 0);
    if (k) { CHECK(RegQueryValueExA(k, "keepme", NULL, NULL, NULL, NULL) == 0); RegCloseKey(k); }
}
/* tests run in REVERSE order of declaration (constructor order), so this one is declared first to run after the next one */
TEST(st_defer_ran) { if (!g_defer_ran) { t_skip("order: deferred test did not run before"); return; } CHECK(g_defer_ran); }
TEST(st_defer_runs_at_test_end) { g_defer_ran = 0; t_defer(defer_mark, &g_defer_ran); EXPECT_EQ(g_defer_ran, 0); }
TEST(st_timeout_extension) { t_set_timeout(120); Sleep(200); CHECK(t_test_name()[0] == 's'); }
TEST(st_label_clean_per_test) { t_label("stage %d", 1); t_label(NULL); CHECK(1); }

/* ====================== fault run only: each of these must be contained ======================
 * Tests run in REVERSE order of declaration, so they are declared 09..00 to execute as 00..09. */
TEST(stf_09_still_running) { REQUIRE_FAULTS(); CHECK(1); }               /* expect: OK, proves the run went on */
CHILD(sleeper) { Sleep(600000); return 0; }
TEST(stf_08_hang_with_child) {                                            /* expect: TIMEOUT, child killed with the tree */
    REQUIRE_FAULTS();
    t_spawn_child("sleeper", "", 0, NULL, NULL, NULL, FALSE, NULL, NULL);
    Sleep(INFINITE);
}
TEST(stf_07_fastfail_worker_death) { REQUIRE_FAULTS(); __fastfail(7); }   /* expect: FAIL worker process died, run resumes */
TEST(stf_06_hang_watchdog) { REQUIRE_FAULTS(); Sleep(INFINITE); }         /* expect: TIMEOUT after T_TIMEOUT_S */
static int recurse(int n) { volatile char pad[4096]; pad[0] = (char)n; return n ? recurse(n + 1) + pad[0] : 0; }
TEST(stf_05_stack_overflow) { REQUIRE_FAULTS(); recurse(1); }             /* expect: FAIL stack overflow (or worker died), run goes on */
static DWORD WINAPI av_thread(LPVOID a) { *(volatile int *)0 = 1; return 0; }
TEST(stf_04_av_in_helper_thread) {                                        /* expect: FAIL unhandled exception in a helper thread */
    REQUIRE_FAULTS();
    HANDLE t = CreateThread(NULL, 0, av_thread, NULL, 0, NULL); WaitForSingleObject(t, 5000); CloseHandle(t);
}
TEST(stf_03_try_contains) {   /* expect: one FAIL (exception) + NOTE; the check after T_TRY still runs and passes */
    REQUIRE_FAULTS();
    T_TRY(*(volatile int *)16 = 1);
    CHECK(1);
}
TEST(stf_02_av_in_test) { REQUIRE_FAULTS(); CHECK(1); *(volatile int *)0 = 1; CHECKF(0, "must NOT be reached"); }
TEST(stf_01_require_aborts) { REQUIRE_FAULTS(); REQUIRE_OK(0 == 1); CHECKF(0, "must NOT be reached"); }
TEST(stf_00_failing_checks_with_labels) {   /* expect: 4 FAIL lines, labelled, with got/want; the test FAILs, the run continues */
    REQUIRE_FAULTS();
    t_label("stage A"); EXPECT_EQ(2 + 2, 5);
    t_label("stage B"); EXPECT_SIZE_QUERY(3, 5, 5);
    t_label("stage C"); EXPECT_CAPI_FAIL(CryptReleaseContext(0, 0), NTE_BAD_UID);
    EXPECT_GPA_FAIL(GetModuleHandleA("kernel32.dll"), MAKEINTRESOURCEA(1));
}
