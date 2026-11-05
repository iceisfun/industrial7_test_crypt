#include "t.h"
#include "modules.h"
#include <io.h>
#include <malloc.h>

/* ======================================================================================================
 * State shared between the supervisor and the worker process (a named file mapping), or a local copy
 * when running in-process (T_INPROC=1).  All counters are updated with interlocked operations.
 * ====================================================================================================== */
typedef struct {
    volatile LONG cur, in_test, kind, done, fatal;     /* kind: 0 test, 1 sweep */
    volatile LONG ran, tfail, tskip, pass, fail, cur_fail, cur_skip, nto, ncrash;
    volatile LONGLONG deadline;                         /* GetTickCount64() value after which the current item is hung */
    volatile LONG timeout_s;                            /* budget of the current item, for the TIMEOUT message */
    char name[192];
} shared_t;
static shared_t g_local;
static shared_t *S = &g_local;

static const char *g_mods[] = { T_MODULE_LIST, NULL };
static DWORD g_tls = TLS_OUT_OF_INDEXES;
static DWORD g_main_tid;
static char g_label[160];
#define DEFAULT_TIMEOUT_S 60
static unsigned g_timeout_s = DEFAULT_TIMEOUT_S;

HMODULE t_module(const char *dll) { return LoadLibraryA(dll); }   /* refcounted; modules stay loaded */
FARPROC t_proc_in(const char *dll, const char *name) { HMODULE m = t_module(dll); return m ? GetProcAddress(m, name) : NULL; }
FARPROC t_proc_ord(const char *dll, unsigned ord) { HMODULE m = t_module(dll); return m ? GetProcAddress(m, (LPCSTR)(ULONG_PTR)ord) : NULL; }
FARPROC t_proc(const char *name) {
    for (int i = 0; g_mods[i]; i++) { FARPROC p = t_proc_in(g_mods[i], name); if (p) return p; }
    return NULL;
}
int t_is_wine(void) { HMODULE n = GetModuleHandleA("ntdll.dll"); return n && GetProcAddress(n, "wine_get_version") != NULL; }

#define MAXT 8192
static struct { const char *n; t_fn f; } g_t[MAXT];
static int g_nt;
void t_register(const char *n, t_fn f) { if (g_nt < MAXT) { g_t[g_nt].n = n; g_t[g_nt].f = f; g_nt++; } }
static struct { const char *n; t_child_fn f; } g_c[512];
static int g_nc;
void t_register_child(const char *n, t_child_fn f) { if (g_nc < 512) { g_c[g_nc].n = n; g_c[g_nc].f = f; g_nc++; } }

/* ---- assertions ---------------------------------------------------------------------------------- */
static void fail_count(void) { InterlockedIncrement(&S->fail); InterlockedIncrement(&S->cur_fail); }
static void fail_begin(const char *file, int line, const char *expr) {
    fail_count();
    printf("  FAIL %s:%d: %s", file, line, expr);
}
static void fail_end(void) { if (g_label[0]) printf(" [%s]", g_label); printf("\n"); }

void t_label(const char *fmt, ...) {
    if (!fmt) { g_label[0] = 0; return; }
    va_list a; va_start(a, fmt); vsnprintf(g_label, sizeof g_label, fmt, a); va_end(a);
}
void t_check(int ok, const char *file, int line, const char *expr, const char *fmt, ...) {
    if (ok) { InterlockedIncrement(&S->pass); return; }
    fail_begin(file, line, expr);
    if (fmt) { va_list a; va_start(a, fmt); printf(" ("); vprintf(fmt, a); printf(")"); va_end(a); }
    fail_end();
}
void t_note(const char *fmt, ...) {
    va_list a; va_start(a, fmt); printf("  NOTE "); vprintf(fmt, a); if (g_label[0]) printf(" [%s]", g_label); printf("\n"); va_end(a);
}
void t_skip(const char *fmt, ...) {
    va_list a; va_start(a, fmt); printf("  SKIP "); vprintf(fmt, a); printf("\n"); va_end(a); InterlockedExchange(&S->cur_skip, 1);
}

static unsigned long long narrow_v(ULONG_PTR v, int narrow) { return narrow ? (unsigned long long)(uint32_t)v : (unsigned long long)v; }
void t_expect_eq(ULONG_PTR a, ULONG_PTR b, int narrow, const char *file, int line, const char *expr) {
    unsigned long long x = narrow_v(a, narrow), y = narrow_v(b, narrow);
    if (x == y) { InterlockedIncrement(&S->pass); return; }
    fail_begin(file, line, expr); printf(" (got 0x%llx want 0x%llx)", x, y); fail_end();
}
void t_expect_ne(ULONG_PTR a, ULONG_PTR b, int narrow, const char *file, int line, const char *expr) {
    unsigned long long x = narrow_v(a, narrow), y = narrow_v(b, narrow);
    if (x != y) { InterlockedIncrement(&S->pass); return; }
    fail_begin(file, line, expr); printf(" (got 0x%llx)", x); fail_end();
}
void t_expect_str(const char *a, const char *b, const char *file, int line, const char *expr) {
    if (a && b && !strcmp(a, b)) { InterlockedIncrement(&S->pass); return; }
    fail_begin(file, line, expr); printf(" (got \"%s\" want \"%s\")", a ? a : "(null)", b ? b : "(null)"); fail_end();
}
void t_expect_wstr(const WCHAR *a, const WCHAR *b, const char *file, int line, const char *expr) {
    if (a && b && !lstrcmpW(a, b)) { InterlockedIncrement(&S->pass); return; }
    fail_begin(file, line, expr); printf(" (got \"%ls\" want \"%ls\")", a ? a : L"(null)", b ? b : L"(null)"); fail_end();
}

const char *t_err_name(DWORD c) {
    switch (c) {
#define N(x) case x: return #x
    N(ERROR_SUCCESS); N(ERROR_FILE_NOT_FOUND); N(ERROR_PATH_NOT_FOUND); N(ERROR_ACCESS_DENIED); N(ERROR_INVALID_HANDLE);
    N(ERROR_NOT_ENOUGH_MEMORY); N(ERROR_INVALID_DATA); N(ERROR_NOT_SUPPORTED); N(ERROR_INVALID_PARAMETER); N(ERROR_BAD_LENGTH);
    N(ERROR_INSUFFICIENT_BUFFER); N(ERROR_MOD_NOT_FOUND); N(ERROR_PROC_NOT_FOUND); N(ERROR_INVALID_ORDINAL); N(ERROR_ALREADY_EXISTS);
    N(ERROR_MORE_DATA); N(ERROR_NO_MORE_ITEMS); N(ERROR_NOT_FOUND); N(ERROR_INVALID_FLAGS); N(ERROR_INVALID_NAME); N(ERROR_PRIVILEGE_NOT_HELD);
    N(ERROR_TIMEOUT); N(ERROR_BAD_ARGUMENTS); N(ERROR_INVALID_FUNCTION); N(ERROR_FILE_EXISTS); N(ERROR_NO_TOKEN); N(ERROR_NONE_MAPPED);
    N(NTE_BAD_UID); N(NTE_BAD_HASH); N(NTE_BAD_KEY); N(NTE_BAD_LEN); N(NTE_BAD_DATA); N(NTE_BAD_SIGNATURE); N(NTE_BAD_VER);
    N(NTE_BAD_ALGID); N(NTE_BAD_FLAGS); N(NTE_BAD_TYPE); N(NTE_BAD_KEY_STATE); N(NTE_BAD_HASH_STATE); N(NTE_NO_KEY); N(NTE_NO_MEMORY);
    N(NTE_EXISTS); N(NTE_PERM); N(NTE_NOT_FOUND); N(NTE_DOUBLE_ENCRYPT); N(NTE_BAD_PROVIDER); N(NTE_BAD_PROV_TYPE); N(NTE_BAD_PUBLIC_KEY);
    N(NTE_BAD_KEYSET); N(NTE_PROV_TYPE_NOT_DEF); N(NTE_PROV_TYPE_ENTRY_BAD); N(NTE_KEYSET_NOT_DEF); N(NTE_KEYSET_ENTRY_BAD);
    N(NTE_PROV_TYPE_NO_MATCH); N(NTE_SIGNATURE_FILE_BAD); N(NTE_PROVIDER_DLL_FAIL); N(NTE_PROV_DLL_NOT_FOUND); N(NTE_BAD_KEYSET_PARAM);
    N(NTE_FAIL); N(NTE_SYS_ERR); N(NTE_SILENT_CONTEXT); N(NTE_TOKEN_KEYSET_STORAGE_FULL); N(NTE_TEMPORARY_PROFILE); N(NTE_FIXEDPARAMETER);
    N(NTE_INVALID_HANDLE); N(NTE_INVALID_PARAMETER); N(NTE_BUFFER_TOO_SMALL); N(NTE_NOT_SUPPORTED); N(NTE_NO_MORE_ITEMS);
    N(NTE_BUFFERS_OVERLAP); N(NTE_DECRYPTION_FAILURE); N(NTE_INTERNAL_ERROR); N(NTE_UI_REQUIRED); N(NTE_HMAC_NOT_SUPPORTED);
   
#undef N
    }
    return "?";
}
void t_expect_err(DWORD got, DWORD want, const char *file, int line, const char *expr) {
    if (got == want) { InterlockedIncrement(&S->pass); return; }
    fail_begin(file, line, expr);
    printf(" (GetLastError got %lu want %lu; 0x%08lx %s vs 0x%08lx %s)", got, want, got, t_err_name(got), want, t_err_name(want)); fail_end();
}
void t_expect_fail_ret(ULONG_PTR ret, ULONG_PTR failval, DWORD err, DWORD want, const char *file, int line, const char *expr) {
    if (ret != failval) { fail_begin(file, line, expr); printf(" (call returned 0x%llx, expected failure 0x%llx)", (unsigned long long)ret, (unsigned long long)failval); fail_end(); return; }
    t_expect_err(err, want, file, line, expr);
}
void t_expect_succeeds(ULONG_PTR ret, DWORD err, const char *file, int line, const char *expr) {
    if (ret) { InterlockedIncrement(&S->pass); return; }
    fail_begin(file, line, expr); printf(" (call failed, GetLastError 0x%08lx %s)", err, t_err_name(err)); fail_end();
}
void t_expect_capi_err(int failed, DWORD got, DWORD want, const char *file, int line, const char *expr) {
    if (!failed) { fail_begin(file, line, expr); printf(" (call unexpectedly succeeded)"); fail_end(); return; }
    if (got == want) { InterlockedIncrement(&S->pass); return; }
    fail_begin(file, line, expr);
    printf(" (GetLastError got 0x%08lx %s want 0x%08lx %s)", got, t_err_name(got), want, t_err_name(want)); fail_end();
}
int t_require(int ok, const char *file, int line, const char *expr) {
    DWORD e = GetLastError();
    if (ok) { InterlockedIncrement(&S->pass); return 1; }
    fail_begin(file, line, expr); printf(" (REQUIRE failed, GetLastError 0x%08lx %s; test aborted)", e, t_err_name(e)); fail_end();
    return 0;
}
int t_size_sane(DWORD cb, const char *file, int line, const char *expr) {
    if (cb <= (64u << 20)) { InterlockedIncrement(&S->pass); return 1; }
    fail_begin(file, line, expr); printf(" (implausible size %lu; test aborted)", cb); fail_end();
    return 0;
}
void t_expect_size_query(DWORD q, DWORD f, DWORD want, int exact, const char *file, int line, const char *expr) {
    if (q >= f) InterlockedIncrement(&S->pass); else { fail_begin(file, line, expr); printf(" (size query %lu < final size %lu)", q, f); fail_end(); }
    if (f == want) InterlockedIncrement(&S->pass); else { fail_begin(file, line, expr); printf(" (final size got %lu want %lu, query %lu)", f, want, q); fail_end(); }
    if (exact) { if (q == f) InterlockedIncrement(&S->pass); else { fail_begin(file, line, expr); printf(" (size query %lu != final size %lu)", q, f); fail_end(); } }
}
DWORD t_gpa_expected_err(LPCSTR nm) {
    if (!nm) return ERROR_INVALID_PARAMETER;
    if ((ULONG_PTR)nm <= 0xFFFF) return (ULONG_PTR)nm == 0 ? ERROR_INVALID_PARAMETER : ERROR_INVALID_ORDINAL;
    return ERROR_PROC_NOT_FOUND;
}
void t_expect_gpa_err(FARPROC p, DWORD err, LPCSTR nm, const char *file, int line) {
    char what[96];
    if ((ULONG_PTR)nm <= 0xFFFF) snprintf(what, sizeof what, "GetProcAddress(#%lu)", (unsigned long)(ULONG_PTR)nm);
    else snprintf(what, sizeof what, "GetProcAddress(\"%.60s\")", nm);
    if (p) { fail_begin(file, line, what); printf(" (resolved unexpectedly)"); fail_end(); return; }
    t_expect_err(err, t_gpa_expected_err(nm), file, line, what);
}

/* ---- fault frames ---------------------------------------------------------------------------------- */
void t_frame_push(t_frame *f) { f->prev = g_tls == TLS_OUT_OF_INDEXES ? NULL : (t_frame *)TlsGetValue(g_tls); if (g_tls != TLS_OUT_OF_INDEXES) TlsSetValue(g_tls, f); }
void t_frame_pop(t_frame *f) { if (g_tls != TLS_OUT_OF_INDEXES) TlsSetValue(g_tls, f->prev); }
static void post_fault(t_frame *f);
void t_frame_report(t_frame *f, const char *file, int line, const char *what) {
    post_fault(f);
    t_note("fault 0x%08lx contained by T_TRY at %s:%d: %s", f->code, file, line, what);
}
static void __attribute__((noreturn, used)) fault_stub(void) {
    t_frame *f = (t_frame *)TlsGetValue(g_tls);
    f->faulted = 1;
    __builtin_longjmp(f->buf, 1);
}
/* Called only for exceptions nobody handled (so exceptions that foreign code catches itself are not failures). */
static LONG WINAPI uef(EXCEPTION_POINTERS *ep) {
    DWORD c = ep->ExceptionRecord->ExceptionCode;
    t_frame *f = g_tls == TLS_OUT_OF_INDEXES ? NULL : (t_frame *)TlsGetValue(g_tls);
    if (f && !(ep->ExceptionRecord->ExceptionFlags & EXCEPTION_NONCONTINUABLE)) {
        f->code = c; f->faulted = 1;
        if (!f->quiet) {
            fail_count();
            printf("  FAIL exception 0x%08lx at %p in %s", c, ep->ExceptionRecord->ExceptionAddress, S->name);
            if ((c == EXCEPTION_ACCESS_VIOLATION || c == EXCEPTION_IN_PAGE_ERROR) && ep->ExceptionRecord->NumberParameters >= 2)
                printf(" (%s %p)", ep->ExceptionRecord->ExceptionInformation[0] == 0 ? "read" : ep->ExceptionRecord->ExceptionInformation[0] == 1 ? "write" : "exec", (void *)ep->ExceptionRecord->ExceptionInformation[1]);
            fail_end();
        }
        CONTEXT *x = ep->ContextRecord;
        x->Rip = (DWORD64)(ULONG_PTR)fault_stub;
        x->Rsp = ((x->Rsp - 0x200) & ~(DWORD64)0xF) - 8;
        x->EFlags &= ~0x400u;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (GetCurrentThreadId() != g_main_tid) {
        fail_count();
        printf("  FAIL unhandled exception 0x%08lx at %p in a helper thread during %s (thread ended)", c, ep->ExceptionRecord->ExceptionAddress, S->name);
        fail_end();
        ExitThread(0xC0DE0002);
    }
    return EXCEPTION_CONTINUE_SEARCH;
}
/* stack overflow: no printing here (almost no stack left); the failure is reported by post_fault() after the jump */
static LONG CALLBACK veh_so(PEXCEPTION_POINTERS ep) {
    if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_STACK_OVERFLOW) return EXCEPTION_CONTINUE_SEARCH;
    t_frame *f = g_tls == TLS_OUT_OF_INDEXES ? NULL : (t_frame *)TlsGetValue(g_tls);
    if (!f) return EXCEPTION_CONTINUE_SEARCH;
    f->code = ep->ExceptionRecord->ExceptionCode; f->faulted = 1;
    CONTEXT *x = ep->ContextRecord;
    x->Rip = (DWORD64)(ULONG_PTR)fault_stub;
    x->Rsp = ((x->Rsp - 0x100) & ~(DWORD64)0xF) - 8;
    return EXCEPTION_CONTINUE_EXECUTION;
}
static void post_fault(t_frame *f) {
    if (f->code == EXCEPTION_STACK_OVERFLOW) {
        _resetstkoflw();
        if (!f->quiet) { fail_count(); printf("  FAIL stack overflow in %s", S->name); fail_end(); }
    }
}
const char *t_self_path(void) { static char p[MAX_PATH * 2]; if (!p[0]) GetModuleFileNameA(NULL, p, sizeof p); return p; }
HANDLE t_spawn_child(const char *name, const char *extra, DWORD flags, HANDLE hin, HANDLE hout, HANDLE herr, BOOL inherit, const char *env, PROCESS_INFORMATION *pi_out) {
    char cmd[4096]; STARTUPINFOA si; PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof si); si.cb = sizeof si;
    if (hin || hout || herr) { si.dwFlags |= STARTF_USESTDHANDLES; si.hStdInput = hin; si.hStdOutput = hout; si.hStdError = herr; }
    snprintf(cmd, sizeof cmd, "\"%s\" --child %s %s", t_self_path(), name, extra ? extra : "");
    memset(&pi, 0, sizeof pi);
    if (!CreateProcessA(NULL, cmd, NULL, NULL, inherit, flags, (LPVOID)env, NULL, &si, &pi)) return NULL;
    if (pi_out) *pi_out = pi; else CloseHandle(pi.hThread);
    return pi.hProcess;
}
DWORD t_run_child(const char *name, const char *extra, DWORD timeout_ms) {
    PROCESS_INFORMATION pi; DWORD code = 0xDEAD0000;
    HANDLE h = t_spawn_child(name, extra, 0, NULL, NULL, NULL, FALSE, NULL, &pi);
    if (!h) return 0xDEAD0000;
    if (WaitForSingleObject(h, timeout_ms) != WAIT_OBJECT_0) { TerminateProcess(h, 1); WaitForSingleObject(h, 5000); code = 0xDEAD0001; }
    else GetExitCodeProcess(h, &code);
    CloseHandle(pi.hThread); CloseHandle(h);
    return code;
}

static char g_tmp[MAX_PATH];
static void rmtree(const char *dir) {
    char pat[MAX_PATH + 4], sub[MAX_PATH + 300]; WIN32_FIND_DATAA fd;
    snprintf(pat, sizeof pat, "%s\\*", dir);
    HANDLE h = FindFirstFileA(pat, &fd);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            if (!strcmp(fd.cFileName, ".") || !strcmp(fd.cFileName, "..")) continue;
            snprintf(sub, sizeof sub, "%s\\%s", dir, fd.cFileName);
            SetFileAttributesA(sub, FILE_ATTRIBUTE_NORMAL);
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) rmtree(sub); else DeleteFileA(sub);
        } while (FindNextFileA(h, &fd));
        FindClose(h);
    }
    RemoveDirectoryA(dir);
}
static void cleanup_tmp(void) { if (g_tmp[0]) { char d[MAX_PATH]; strcpy(d, g_tmp); d[strlen(d) - 1] = 0; rmtree(d); g_tmp[0] = 0; } }
const char *t_tmpdir(void) {
    if (!g_tmp[0]) {
        char base[MAX_PATH]; if (!GetTempPathA(sizeof base, base)) strcpy(base, ".\\");
        snprintf(g_tmp, sizeof g_tmp, "%s" T_TMP_PREFIX "_%lu\\", base, GetCurrentProcessId());
        CreateDirectoryA(g_tmp, NULL);
        atexit(cleanup_tmp);
    }
    return g_tmp;
}
void t_tmpfile(char *out, size_t cap, const char *leaf) { snprintf(out, cap, "%s%s", t_tmpdir(), leaf); }


/* ======================================================================================================
 * Environment probes
 * ====================================================================================================== */
static int g_elev = -1, g_join = -1, g_tpm = -1; static long g_tpm_st;
int t_is_elevated(void) {
    if (g_elev < 0) {
        HANDLE tok; g_elev = 0;
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) {
            TOKEN_ELEVATION te; DWORD n = 0;
            if (GetTokenInformation(tok, TokenElevation, &te, sizeof te, &n)) g_elev = te.TokenIsElevated ? 1 : 0;
            CloseHandle(tok);
        }
    }
    return g_elev;
}
int t_is_destructive(void) { char b[8]; return GetEnvironmentVariableA("ORACLE_DESTRUCTIVE", b, sizeof b) && b[0] == '1'; }
int t_join_status(void) {
    if (g_join < 0) {
        g_join = 0;
        HMODULE m = LoadLibraryA("netapi32.dll");
        if (m) {
            typedef DWORD (WINAPI *gji_t)(LPCWSTR, LPWSTR *, int *); typedef DWORD (WINAPI *nbf_t)(void *);
            gji_t gji = (gji_t)GetProcAddress(m, "NetGetJoinInformation"); nbf_t nbf = (nbf_t)GetProcAddress(m, "NetApiBufferFree");
            LPWSTR nm = NULL; int type = 0;
            if (gji && gji(NULL, &nm, &type) == 0) { g_join = type; if (nm && nbf) nbf(nm); }
        }
    }
    return g_join;
}
int t_is_domain_joined(void) { return t_join_status() == 3; }
long t_tpm_status(void) {
    if (g_tpm < 0) {
        g_tpm = 0; g_tpm_st = (long)0x8028400F; /* TBS_E_TPM_NOT_FOUND */
        HMODULE m = LoadLibraryA("tbs.dll");
        if (m) {
            typedef UINT32 (WINAPI *gdi_t)(UINT32, void *);
            gdi_t gdi = (gdi_t)GetProcAddress(m, "Tbsi_GetDeviceInfo");
            struct { UINT32 structVersion, tpmVersion, tpmInterfaceType, tpmImpRevision; } info; memset(&info, 0, sizeof info);
            if (gdi) { g_tpm_st = (long)gdi(sizeof info, &info); g_tpm = g_tpm_st == 0; }
        }
    }
    return g_tpm_st;
}
int t_has_tpm(void) { t_tpm_status(); return g_tpm == 1; }

/* ======================================================================================================
 * Unique names, sweepers, deferred cleanups
 * ====================================================================================================== */
static char g_area[48];
const char *t_area_name(void) {
    if (!g_area[0]) {
        char p[MAX_PATH]; GetModuleFileNameA(NULL, p, sizeof p);
        const char *b = strrchr(p, '\\'); b = b ? b + 1 : p;
        snprintf(g_area, sizeof g_area, "%s", b);
        char *d = strrchr(g_area, '.'); if (d) *d = 0;
        for (char *c = g_area; *c; c++) if (!((*c >= '0' && *c <= '9') || (*c >= 'A' && *c <= 'Z') || (*c >= 'a' && *c <= 'z') || *c == '_')) *c = '_';
    }
    return g_area;
}
const char *t_area_prefix(void) { static char p[80]; if (!p[0]) snprintf(p, sizeof p, "I7T_%s_", t_area_name()); return p; }
const char *t_unique(const char *tag) {
    static char buf[8][200]; static volatile LONG n; static volatile LONG k;
    LONG i = InterlockedIncrement(&k);
    char *b = buf[i & 7];
    snprintf(b, 200, "%s%s_%lu_%ld", t_area_prefix(), tag ? tag : "x", GetCurrentProcessId(), (long)InterlockedIncrement(&n));
    return b;
}
const WCHAR *t_unique_w(const char *tag) {
    static WCHAR wb[8][200]; static volatile LONG k;
    const char *a = t_unique(tag); WCHAR *w = wb[InterlockedIncrement(&k) & 7];
    MultiByteToWideChar(CP_ACP, 0, a, -1, w, 200);
    return w;
}
static t_sweep_fn g_sw[64]; static int g_nsw;
void t_sweeper_add(t_sweep_fn fn) { if (g_nsw < 64) g_sw[g_nsw++] = fn; }
static struct { void (*fn)(void *); void *arg; } g_defer[128]; static int g_ndefer;
void t_defer(void (*fn)(void *), void *arg) { if (g_ndefer < 128) { g_defer[g_ndefer].fn = fn; g_defer[g_ndefer].arg = arg; g_ndefer++; } }

static int reg_collect(HKEY k, int values, const char *prefix, char (*names)[260], int max) {
    int n = 0, pl = (int)strlen(prefix);
    for (DWORD i = 0; n < max; i++) {
        char nm[260]; DWORD cch = sizeof nm; LONG r;
        r = values ? RegEnumValueA(k, i, nm, &cch, NULL, NULL, NULL, NULL) : RegEnumKeyExA(k, i, nm, &cch, NULL, NULL, NULL, NULL);
        if (r != ERROR_SUCCESS) break;
        if (!strncmp(nm, prefix, pl)) strcpy(names[n++], nm);
    }
    return n;
}
static int reg_sweep(HKEY root, const char *path, const char *prefix, int values) {
    HKEY k; static char names[256][260]; int cnt = 0;
    if (RegOpenKeyExA(root, path, 0, KEY_READ | KEY_WRITE | DELETE, &k) != ERROR_SUCCESS) return 0;
    int n = reg_collect(k, values, prefix, names, 256);
    for (int i = 0; i < n; i++) {
        LONG r = values ? RegDeleteValueA(k, names[i]) : RegDeleteTreeA(k, names[i]);
        if (r == ERROR_SUCCESS && !values) r = RegDeleteKeyA(k, names[i]);   /* RegDeleteTree on a subkey name leaves the key itself */
        if (r == ERROR_SUCCESS || r == ERROR_FILE_NOT_FOUND) cnt++;
    }
    RegCloseKey(k);
    return cnt;
}
int t_reg_sweep_subkeys(HKEY root, const char *path, const char *prefix) { return reg_sweep(root, path, prefix, 0); }
int t_reg_sweep_values(HKEY root, const char *path, const char *prefix) { return reg_sweep(root, path, prefix, 1); }

/* ======================================================================================================
 * Runner (worker side)
 * ====================================================================================================== */
static void set_deadline(unsigned secs) { S->timeout_s = (LONG)secs; S->deadline = (LONGLONG)GetTickCount64() + (LONGLONG)secs * 1000; }
void t_set_timeout(unsigned seconds) { g_timeout_s = seconds; set_deadline(seconds); }
const char *t_test_name(void) { return S->name; }

static void run_defers(void) {
    while (g_ndefer > 0) {
        g_ndefer--; void (*fn)(void *) = g_defer[g_ndefer].fn; void *arg = g_defer[g_ndefer].arg;
        t_frame fr; fr.faulted = 0; fr.quiet = 0; fr.code = 0; t_frame_push(&fr);
        if (!__builtin_setjmp(fr.buf)) { fn(arg); t_frame_pop(&fr); } else { t_frame_pop(&fr); post_fault(&fr); }
    }
}
static void run_sweeps(int phase) {
    if (!g_nsw) return;
    S->kind = 1; snprintf(S->name, sizeof S->name, "<sweep %s>", phase ? "end" : "start");
    set_deadline(DEFAULT_TIMEOUT_S * 2); S->in_test = 1;
    for (int i = 0; i < g_nsw; i++) {
        t_frame fr; fr.faulted = 0; fr.quiet = 0; fr.code = 0; t_frame_push(&fr);
        if (!__builtin_setjmp(fr.buf)) { g_sw[i](phase, t_area_prefix()); t_frame_pop(&fr); } else { t_frame_pop(&fr); post_fault(&fr); }
    }
    S->in_test = 0; S->kind = 0;
}
static void run_one(int i) {
    unsigned t0 = GetTickCount();
    g_timeout_s = getenv("T_TIMEOUT_S") ? (unsigned)atoi(getenv("T_TIMEOUT_S")) : DEFAULT_TIMEOUT_S;
    if (!g_timeout_s) g_timeout_s = DEFAULT_TIMEOUT_S;
    S->cur = i; S->kind = 0; snprintf(S->name, sizeof S->name, "%s", g_t[i].n);
    S->cur_fail = 0; S->cur_skip = 0; g_label[0] = 0; g_ndefer = 0;
    set_deadline(g_timeout_s); S->in_test = 1;
    printf("RUN  %s\n", g_t[i].n);
    SetLastError(0);
    t_frame fr; fr.faulted = 0; fr.quiet = 0; fr.code = 0; t_frame_push(&fr);
    if (!__builtin_setjmp(fr.buf)) { g_t[i].f(); } else { post_fault(&fr); }
    TlsSetValue(g_tls, NULL);
    run_defers();
    unsigned dt = GetTickCount() - t0;
    if (dt >= 5000) t_note("test took %u ms", dt);
    InterlockedIncrement(&S->ran);
    if (S->cur_fail) InterlockedIncrement(&S->tfail); else if (S->cur_skip) InterlockedIncrement(&S->tskip);
    printf("%s %s\n", S->cur_fail ? "FAIL" : S->cur_skip ? "SKIP" : "OK  ", g_t[i].n);
    S->in_test = 0;
}
static int run_tests(const char *filter, int from, int first, int skip_sweep) {
    g_tls = TlsAlloc(); g_main_tid = GetCurrentThreadId();
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    SetUnhandledExceptionFilter(uef);
    AddVectoredExceptionHandler(0, veh_so);
    if (!t_module(g_mods[0])) { printf("FATAL cannot load %s\n", g_mods[0]); S->fatal = 1; return 2; }
    if (first && !skip_sweep) run_sweeps(T_SWEEP_START);
    for (int i = from; i < g_nt; i++) {
        if (filter && !strstr(g_t[i].n, filter)) continue;
        run_one(i);
    }
    if (!skip_sweep) run_sweeps(T_SWEEP_END);
    return 0;
}

/* ======================================================================================================
 * Supervisor
 * ====================================================================================================== */
static void print_summary(void) {
    printf("SUMMARY tests=%ld failed=%ld skipped=%ld checks_pass=%ld checks_fail=%ld", S->ran, S->tfail, S->tskip, S->pass, S->fail);
    if (S->nto || S->ncrash) printf(" timeouts=%ld crashes=%ld", S->nto, S->ncrash);
    printf("\n");
}
static int supervise(const char *filter) {
    char mname[96]; DWORD pid = GetCurrentProcessId();
    snprintf(mname, sizeof mname, "Local\\i7t_%lu_%lu", pid, GetTickCount());
    HANDLE hm = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, sizeof(shared_t), mname);
    shared_t *sh = hm ? (shared_t *)MapViewOfFile(hm, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(shared_t)) : NULL;
    HANDLE job = CreateJobObjectA(NULL, NULL);
    if (!sh || !job) return -1;                          /* caller falls back to in-process */
    S = sh; memset(sh, 0, sizeof *sh);
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION li; memset(&li, 0, sizeof li);
    li.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    SetInformationJobObject(job, JobObjectExtendedLimitInformation, &li, sizeof li);
    printf("ENV area=%s elevated=%d destructive=%d join=%d tpm=0x%08lx wine=%d\n", t_area_name(), t_is_elevated(), t_is_destructive(), t_join_status(), (unsigned long)t_tpm_status(), t_is_wine());

    HANDLE hin = GetStdHandle(STD_INPUT_HANDLE), hout = GetStdHandle(STD_OUTPUT_HANDLE), herr = GetStdHandle(STD_ERROR_HANDLE);
    int use_std = hout && hout != INVALID_HANDLE_VALUE;
    if (use_std) {
        if (!herr || herr == INVALID_HANDLE_VALUE) herr = hout;
        if (hin == INVALID_HANDLE_VALUE) hin = NULL;
        if (hin) SetHandleInformation(hin, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
        SetHandleInformation(hout, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
        SetHandleInformation(herr, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
    }
    int from = 0, first = 1, skip_sweep = 0, launches = 0, idle_deaths = 0;
    for (;;) {
        char ev[160]; snprintf(ev, sizeof ev, "%s|%d|%d|%d", mname, from, first, skip_sweep);
        SetEnvironmentVariableA("T_WORKER", ev);
        STARTUPINFOA si; PROCESS_INFORMATION pi; memset(&si, 0, sizeof si); memset(&pi, 0, sizeof pi); si.cb = sizeof si;
        if (use_std) { si.dwFlags = STARTF_USESTDHANDLES; si.hStdInput = hin; si.hStdOutput = hout; si.hStdError = herr; }
        char *cl = _strdup(GetCommandLineA());
        BOOL ok = CreateProcessA(NULL, cl, NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
        free(cl);
        SetEnvironmentVariableA("T_WORKER", NULL);
        if (!ok) { if (!launches) return -1; printf("FATAL cannot launch worker (%lu)\n", GetLastError()); break; }
        launches++;
        if (!AssignProcessToJobObject(job, pi.hProcess)) { /* nested in a job that forbids it: still supervise the single process */ }
        ResumeThread(pi.hThread); CloseHandle(pi.hThread);
        int killed = 0;
        for (;;) {
            if (WaitForSingleObject(pi.hProcess, 200) == WAIT_OBJECT_0) break;
            if (S->in_test && (LONGLONG)GetTickCount64() > S->deadline) { killed = 1; TerminateJobObject(job, 0xDEAD0001); TerminateProcess(pi.hProcess, 0xDEAD0001); WaitForSingleObject(pi.hProcess, 10000); break; }
        }
        DWORD rc = 0; GetExitCodeProcess(pi.hProcess, &rc); CloseHandle(pi.hProcess);
        TerminateJobObject(job, 0);                                        /* leftover descendants of the worker */
        if (S->fatal) return 2;
        if (S->done) break;
        if (S->in_test && S->kind == 0) {
            char nm[192]; snprintf(nm, sizeof nm, "%s", S->name);
            if (killed) { InterlockedIncrement(&S->nto); printf("TIMEOUT %s (exceeded %ld s; worker tree killed)\n", nm, S->timeout_s); printf("  FAIL timeout in %s\n", nm); }
            else { InterlockedIncrement(&S->ncrash); printf("  FAIL worker process died (exit 0x%08lx) in %s\n", rc, nm); }
            InterlockedIncrement(&S->fail); InterlockedIncrement(&S->ran); InterlockedIncrement(&S->tfail);
            printf("FAIL %s\n", nm);
            from = S->cur + 1; first = 0; S->in_test = 0;
        } else {
            /* died outside a test (sweep or start-up): do not repeat the sweeps, resume where we were */
            if (++idle_deaths > 2) { printf("FATAL worker keeps dying outside tests (exit 0x%08lx)\n", rc); break; }
            skip_sweep = 1; first = 0; S->in_test = 0; if (S->cur >= from) from = S->cur + 1;
            printf("  NOTE worker died outside a test (exit 0x%08lx, %s); continuing without sweeps\n", rc, S->name);
        }
        if (launches > g_nt + 8) break;
    }
    print_summary();
    return S->tfail ? 1 : 0;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    if (argc > 2 && !strcmp(argv[1], "--child")) {
        for (int i = 0; i < g_nc; i++) if (!strcmp(g_c[i].n, argv[2])) return g_c[i].f(argc - 2, argv + 2);
        return 0xC0DE0001;
    }
    const char *filter = argc > 1 && strncmp(argv[1], "--", 2) ? argv[1] : NULL;
    char w[256];
    if (GetEnvironmentVariableA("T_WORKER", w, sizeof w)) {            /* worker process */
        SetEnvironmentVariableA("T_WORKER", NULL);
        char *p1 = strchr(w, '|'); if (!p1) return 3; *p1++ = 0;
        int from = 0, first = 1, skip = 0; sscanf(p1, "%d|%d|%d", &from, &first, &skip);
        HANDLE hm = OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, w);
        shared_t *sh = hm ? (shared_t *)MapViewOfFile(hm, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(shared_t)) : NULL;
        if (!sh) { printf("FATAL worker cannot open shared state\n"); return 3; }
        S = sh;
        int rc = run_tests(filter, from, first, skip);
        if (!rc) S->done = 1;
        return rc;
    }
    if (!getenv("T_INPROC")) { int r = supervise(filter); if (r >= 0) return r; S = &g_local; }
    int rc = run_tests(filter, 0, 1, 0);
    if (rc) return rc;
    S->done = 1;
    print_summary();
    return S->tfail ? 1 : 0;
}
