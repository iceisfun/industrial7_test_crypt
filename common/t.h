/* Minimal conformance-test harness.
 *
 * The DLL under test is never linked. Every call goes through
 *   LoadLibrary -> GetProcAddress -> invoke
 * U(Name) gives a function pointer typed from the SDK header declaration of Name
 * (via __typeof__), resolved by searching the modules listed in modules.h in order.
 * The harness itself only uses trivial kernel32 services (printf, exceptions, temp dir).
 */
#ifndef T_H
#define T_H
#define WIN32_LEAN_AND_MEAN
#define WINVER 0x0A00
#define _WIN32_WINNT 0x0A00
#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>

/* ---- module lookup ---------------------------------------------------- */
HMODULE t_module(const char *dll);                 /* LoadLibrary (cached) */
FARPROC t_proc(const char *name);                  /* search modules.h list in order */
FARPROC t_proc_in(const char *dll, const char *name); /* one specific module (forwarders resolve) */
FARPROC t_proc_ord(const char *dll, unsigned ord);

/* U(CreateFileW)(...)       pointer typed from the SDK declaration, any listed module
 * UIN("x.dll", Name)(...)   same, pinned to one module (use this to test forwarders) */
#define U(name)         ((__typeof__(&name))t_proc(#name))
#define UIN(dll, name)  ((__typeof__(&name))t_proc_in(dll, #name))
/* Functions missing from the SDK headers: declare a typedef, then UN(name). */
#define UDECL(ret, name, args) typedef ret (WINAPI *name##_pfn) args
#define UN(name)        ((name##_pfn)t_proc(#name))

/* ---- tests ------------------------------------------------------------- */
typedef void (*t_fn)(void);
void t_register(const char *name, t_fn fn);
#define TEST(n) \
    static void test_##n(void); \
    static void __attribute__((constructor)) reg_##n(void) { t_register(#n, test_##n); } \
    static void test_##n(void)

/* Child processes: the exe re-launches itself as  exe --child <name> [args]  */
typedef int (*t_child_fn)(int argc, char **argv);
void t_register_child(const char *name, t_child_fn fn);
#define CHILD(n) \
    static int child_##n(int argc, char **argv); \
    static void __attribute__((constructor)) regc_##n(void) { t_register_child(#n, child_##n); } \
    static int child_##n(int argc, char **argv)
HANDLE t_spawn_child(const char *name, const char *extra_args, DWORD creation_flags, HANDLE hin, HANDLE hout, HANDLE herr, BOOL inherit, const char *env_or_null, PROCESS_INFORMATION *pi_out);
DWORD  t_run_child(const char *name, const char *extra_args, DWORD timeout_ms); /* exit code; 0xDEAD0000 spawn failed, 0xDEAD0001 timeout (killed) */
const char *t_self_path(void);

/* Scratch directory unique to this process, removed at exit (trailing backslash). */
const char *t_tmpdir(void);
void t_tmpfile(char *out, size_t cap, const char *leaf);

/* ---- assertions (non-fatal, counted, thread safe) --------------------- */
void t_check(int ok, const char *file, int line, const char *expr, const char *fmt, ...);
#define CHECK(c)          t_check(!!(c), __FILE__, __LINE__, #c, NULL)
#define CHECKF(c, ...)    t_check(!!(c), __FILE__, __LINE__, #c, __VA_ARGS__)

/* EXPECT_EQ / EXPECT_NE / EXPECT_STR / EXPECT_WSTR / EXPECT_ERR evaluate every argument exactly once (they are
 * functions underneath), so a call with side effects is never re-executed for the got/want message.
 * When BOTH operands are at most 4 bytes wide the compare is done on 32 bits, so an HRESULT/NTSTATUS (signed int)
 * compares equal to its unsigned literal (0x80090005); wider operands (pointers, 64 bit) compare exactly. */
void t_expect_eq(ULONG_PTR a, ULONG_PTR b, int narrow, const char *file, int line, const char *expr);
void t_expect_ne(ULONG_PTR a, ULONG_PTR b, int narrow, const char *file, int line, const char *expr);
void t_expect_str(const char *a, const char *b, const char *file, int line, const char *expr);
void t_expect_wstr(const WCHAR *a, const WCHAR *b, const char *file, int line, const char *expr);
void t_expect_err(DWORD got, DWORD want, const char *file, int line, const char *expr);
#define T_NARROW_(a, b)   (sizeof(a) <= 4 && sizeof(b) <= 4)
#define EXPECT_EQ(a, b)   t_expect_eq((ULONG_PTR)(a), (ULONG_PTR)(b), T_NARROW_(a, b), __FILE__, __LINE__, #a " == " #b)
#define EXPECT_NE(a, b)   t_expect_ne((ULONG_PTR)(a), (ULONG_PTR)(b), T_NARROW_(a, b), __FILE__, __LINE__, #a " != " #b)
#define EXPECT_STR(a, b)  t_expect_str((a), (b), __FILE__, __LINE__, #a " == " #b)
#define EXPECT_WSTR(a, b) t_expect_wstr((a), (b), __FILE__, __LINE__, #a " == " #b)
/* Check GetLastError right after a call that must fail (read it FIRST, nothing in between). */
#define EXPECT_ERR(err)   do { DWORD e_ = GetLastError(); t_expect_err(e_, (DWORD)(err), __FILE__, __LINE__, #err); } while (0)
#define SET_ERR(e)        SetLastError(e)
/* A call that must FAIL with a specific error: is_failure is the call's failure test, e.g. EXPECT_FAIL(!f(), 87). */
#define EXPECT_FAIL(is_failure, err) do { int f_ = !!(is_failure); DWORD e_ = GetLastError(); \
    t_check(f_, __FILE__, __LINE__, #is_failure, "call unexpectedly succeeded"); \
    t_expect_err(e_, (DWORD)(err), __FILE__, __LINE__, #err); } while (0)

/* ---- last-error convention ----------------------------------------------
 * Last error is only meaningful after a call that FAILED; a successful call leaves it as it was (observed on Win10:
 * stale values survive success). So: SET_ERR(0) -> call -> check the return value FIRST -> only then the error.
 *   T_CALL_ERR(&e, call)        SET_ERR(0), run call, store GetLastError() in e, value of the expression is the call's result
 *   T_LASTERR_AFTER(call)       the error code after the call (result discarded), same discipline
 *   EXPECT_FAILS(call, err)     call must return 0/FALSE/NULL and set exactly err
 *   EXPECT_FAILS_RET(call, failval, err)   same with another failure sentinel (INVALID_HANDLE_VALUE, (DWORD)-1, ...)
 *   EXPECT_SUCCEEDS(call)       call must return nonzero (on failure the message carries the last error) */
#define T_CALL_ERR(perr, call) ({ SetLastError(0); __typeof__(call) tr_ = (call); *(perr) = GetLastError(); tr_; })
#define T_LASTERR_AFTER(call)  ({ SetLastError(0); (void)(call); GetLastError(); })
void t_expect_fail_ret(ULONG_PTR ret, ULONG_PTR failval, DWORD err, DWORD want, const char *file, int line, const char *expr);
void t_expect_succeeds(ULONG_PTR ret, DWORD err, const char *file, int line, const char *expr);
#define EXPECT_FAILS_RET(call, failval, want) do { DWORD ge_; ULONG_PTR r_ = (ULONG_PTR)T_CALL_ERR(&ge_, (call)); \
    t_expect_fail_ret(r_, (ULONG_PTR)(failval), ge_, (DWORD)(want), __FILE__, __LINE__, #call); } while (0)
#define EXPECT_FAILS(call, want) EXPECT_FAILS_RET(call, 0, want)
#define EXPECT_SUCCEEDS(call) do { DWORD ge_; ULONG_PTR r_ = (ULONG_PTR)T_CALL_ERR(&ge_, (call)); \
    t_expect_succeeds(r_, ge_, __FILE__, __LINE__, #call); } while (0)

/* ---- stage label: disambiguates failures that share a file:line (table driven checks, a_enc_eq style helpers).
 * t_label() sets text appended as [label] to every FAIL/NOTE of the current test until changed; cleared per test. */
void t_label(const char *fmt, ...);

/* ---- abort-on-failed-precondition --------------------------------------
 * REQUIRE_OK(expr): if expr is false, count a FAIL (with the last error) and return from the TEST function.
 * Use after setup calls whose results later code indexes with (sizes, handles, buffers).  Not for use in helper
 * functions that return a value: there use  if (!t_require(...)) return X;  */
int  t_require(int ok, const char *file, int line, const char *expr);
#define REQUIRE_OK(expr)       do { if (!t_require(!!(expr), __FILE__, __LINE__, #expr)) return; } while (0)
#define REQUIRE_NOTNULL(p)     do { if (!t_require((p) != NULL, __FILE__, __LINE__, #p " != NULL")) return; } while (0)
#define REQUIRE_EQ(a, b)       do { if (!t_require((ULONG_PTR)(a) == (ULONG_PTR)(b), __FILE__, __LINE__, #a " == " #b)) return; } while (0)
/* sanity limit for a size obtained from a size query before it is used for LocalAlloc/indexing (default 64 MiB) */
int  t_size_sane(DWORD cb, const char *file, int line, const char *expr);
#define REQUIRE_SANE_SIZE(cb)  do { if (!t_size_sane((cb), __FILE__, __LINE__, #cb)) return; } while (0)

/* ---- size-query protocol -------------------------------------------------
 * Many APIs return a conservative size for the NULL-output query and a smaller exact size for the real call.
 * EXPECT_SIZE_QUERY(query_cb, final_cb, want_final) checks the two separately: query >= final, final == want.
 * EXPECT_SIZE_QUERY_EXACT additionally pins the query value (when Win10 returns exactly the final size). */
void t_expect_size_query(DWORD query, DWORD final, DWORD want, int exact, const char *file, int line, const char *expr);
#define EXPECT_SIZE_QUERY(q, f, want)        t_expect_size_query((q), (f), (want), 0, __FILE__, __LINE__, #f)
#define EXPECT_SIZE_QUERY_EXACT(q, f, want)  t_expect_size_query((q), (f), (want), 1, __FILE__, __LINE__, #f)

/* ---- GetProcAddress failure codes (probed on Win10 22H2, identical std/adm, kernel32/bcrypt/crypt32/ncrypt/wintrust)
 *   unknown name (also "")                         ERROR_PROC_NOT_FOUND     127
 *   ordinal 0 / NULL name pointer                  ERROR_INVALID_PARAMETER   87
 *   ordinal below Base, above Base+count, 0xFFFF,
 *     or an unused slot inside the table (hole)    ERROR_INVALID_ORDINAL    182
 *   invalid module handle                          ERROR_MOD_NOT_FOUND      126
 *   NULL module (= the exe itself) + unknown name  ERROR_PROC_NOT_FOUND     127
 * EXPECT_GPA_FAIL(hmod, name_or_MAKEINTRESOURCE(ord)) runs the call and checks both the NULL result and the code. */
DWORD t_gpa_expected_err(LPCSTR name_or_ord);
void  t_expect_gpa_err(FARPROC p, DWORD err, LPCSTR name_or_ord, const char *file, int line);
#define EXPECT_GPA_FAIL(hmod, nm) do { LPCSTR n_ = (LPCSTR)(nm); SetLastError(0); FARPROC p_ = GetProcAddress((hmod), n_); \
    DWORD e_ = GetLastError(); t_expect_gpa_err(p_, e_, n_, __FILE__, __LINE__); } while (0)

/* ---- legacy CryptoAPI (advapi32 CryptXxx / cryptsp) error codes ----------------------------------------------
 * Probed on Win10 22H2 (std and adm identical), a valid provider handle unless stated.  The advapi32 layer validates
 * handles and pointers BEFORE the CSP is called and reports ERROR_INVALID_PARAMETER (87), never an NTE_* code, for:
 *   provider/hash/key handle 0 or never issued (0x1234), NULL output pointer or NULL length pointer, CryptReleaseContext
 *   with flags != 0, CryptAcquireContext with NULL phProv, CryptGetDefaultProvider with an unknown type.
 * The CSP's own NTE_* codes only appear for a valid handle with a bad value:
 *   unknown/zero ALG_ID -> NTE_BAD_ALGID 0x80090008; nonzero reserved flags -> NTE_BAD_FLAGS 0x80090009;
 *   unknown parameter id or blob type -> NTE_BAD_TYPE 0x8009000a; bad data (NULL data pointer on a valid hash, bad
 *   padding/length) -> NTE_BAD_DATA 0x80090005; garbage key blob of valid size -> NTE_BAD_VER 0x80090007 ;
 *   missing key in a container -> NTE_NO_KEY 0x8009000d; unknown provider name -> NTE_KEYSET_NOT_DEF 0x80090019;
 *   unknown provider type -> NTE_PROV_TYPE_NOT_DEF 0x80090014.  A too small buffer is ERROR_MORE_DATA/234 (0xea)
 *   for CryptEncrypt and 0x103 (ERROR_NO_MORE_ITEMS) for enumerations past the end.
 * ERROR_NOT_SUPPORTED (50) is returned by entry points the provider does not implement: pin it per call.
 * Use these macros so the observed code is printed with its symbolic name, then pin the observed code. */
const char *t_err_name(DWORD code);
void t_expect_capi_err(int failed, DWORD got, DWORD want, const char *file, int line, const char *expr);
/* call returns BOOL (FALSE on failure). */
#define EXPECT_CAPI_FAIL(call, want) do { DWORD ge_; BOOL r_ = (BOOL)T_CALL_ERR(&ge_, (call)); \
    t_expect_capi_err(!r_, ge_, (DWORD)(want), __FILE__, __LINE__, #call); } while (0)
#define EXPECT_CAPI_OK(call) EXPECT_SUCCEEDS(call)
/* Pin-by-probe: print what Win10 returns, never fails.  Use once on the oracle, then replace by EXPECT_CAPI_FAIL. */
#define PROBE_CALL(call) do { DWORD ge_; ULONG_PTR r_ = (ULONG_PTR)T_CALL_ERR(&ge_, (call)); \
    t_note("PROBE %s -> ret=0x%llx err=0x%08lx (%s)", #call, (unsigned long long)r_, ge_, t_err_name(ge_)); } while (0)

void t_note(const char *fmt, ...);   /* observed/version-dependent behaviour: logged, never fails */
void t_skip(const char *fmt, ...);   /* skip the rest of the current test (a skip reason is mandatory) */
#define REQUIRE(ptr) do { if (!(ptr)) { t_skip("missing export: " #ptr); return; } } while (0)
int  t_is_wine(void);                /* true under an emulator exposing wine_get_version */

/* Area guards. t_set_guard(fn) (call from a constructor) makes the runner call fn() before every test of the exe; a
 * non-NULL return is a skip reason and the test body is not run. Guards cache their answer and decide from observed
 * behaviour of the module under test, never from the OS name. The reason is printed as  SKIP <reason>  per test, so a
 * degraded system is visible in the results instead of showing as a wall of failures.
 *   t_probe_ncrypt_ssl()  NULL when ncrypt!SslOpenProvider/SslFreeObject are real: exported, callable without an
 *                         exception, and opening "Microsoft SSL Protocol Provider" succeeds. Stub exports raise.
 *   t_probe_ncrypt_ksp()  NULL when the software key storage provider can create and finalize ephemeral RSA and
 *                         ECDSA_P256 keys (NCryptOpenStorageProvider/CreatePersistedKey/FinalizeKey/FreeObject). */
typedef const char *(*t_guard_fn)(void);
void t_set_guard(t_guard_fn fn);
const char *t_probe_ncrypt_ssl(void);
const char *t_probe_ncrypt_ksp(void);

/* ---- faults, watchdog ------------------------------------------------------
 * Every run is supervised: the exe re-launches itself as a worker; the supervisor kills the worker's job tree when one
 * test exceeds its timeout (default 60 s, env T_TIMEOUT_S) and prints  TIMEOUT <test>  + FAIL <test>, and it also reports
 * a worker that dies (fast-fail, stack overflow, heap corruption) as  FAIL <test>  and resumes with the NEXT test, so SUMMARY
 * is always printed.  Env T_INPROC=1 disables the supervisor (single process, no watchdog; for a debugger or wine).
 * t_set_timeout(s) sets the budget of the current test (e.g. long key generation); t_test_name() is the running test.
 * An access violation (or any 0xC.. exception) that nothing handles is reported as a failure of the current test and the
 * run continues with the next test; faults inside foreign code that handles them itself are NOT failures.
 * T_TRY(stmt) / T_TRY_BEGIN .. T_TRY_END(what) contain a fault to one statement/block (counted as a failure, run goes on);
 * T_EXPECT_FAULT(stmt) passes only if stmt faults (Win10 does not validate that pointer).  Locals modified inside the
 * block and read after a fault must be volatile. */
void t_set_timeout(unsigned seconds);
const char *t_test_name(void);
typedef struct t_frame { void *buf[5]; struct t_frame *prev; volatile int faulted; int quiet; DWORD code; } t_frame;
void t_frame_push(t_frame *f);
void t_frame_pop(t_frame *f);
void t_frame_report(t_frame *f, const char *file, int line, const char *what);
/* do not return/break/goto out of a T_TRY block (the frame would stay registered) */
#define T_TRY_BEGIN        { t_frame tf_; tf_.faulted = 0; tf_.quiet = 0; t_frame_push(&tf_); if (!__builtin_setjmp(tf_.buf)) {
#define T_TRY_END(what)    t_frame_pop(&tf_); } else { t_frame_pop(&tf_); t_frame_report(&tf_, __FILE__, __LINE__, what); } }
#define T_TRY(...)         T_TRY_BEGIN __VA_ARGS__; T_TRY_END(#__VA_ARGS__)
#define T_EXPECT_FAULT(...) { t_frame tf_; tf_.faulted = 0; tf_.quiet = 1; t_frame_push(&tf_); \
    if (!__builtin_setjmp(tf_.buf)) { __VA_ARGS__; t_frame_pop(&tf_); } else { t_frame_pop(&tf_); } \
    t_check(tf_.faulted, __FILE__, __LINE__, "fault expected: " #__VA_ARGS__, "no exception"); }

/* ---- environment probes (cached) with skip reasons -------------------------------------------------------------
 * REQUIRE_xxx() skip the current test with an explicit reason and return.  An "ENV ..." line is printed at start. */
int  t_is_elevated(void);            /* token is elevated (adm/dx harness modes: yes, std: no) */
int  t_is_destructive(void);         /* env ORACLE_DESTRUCTIVE=1 (dx mode): registry/store/provider changes are allowed */
int  t_join_status(void);            /* NETSETUP_JOIN_STATUS: 0 unknown 1 unjoined 2 workgroup 3 domain (netapi32) */
int  t_is_domain_joined(void);
int  t_has_tpm(void);                /* tbs.dll Tbsi_GetDeviceInfo succeeded */
long t_tpm_status(void);             /* the raw TBS result */
#define REQUIRE_ELEVATED()   do { if (!t_is_elevated()) { t_skip("requires an elevated token (std mode)"); return; } } while (0)
#define REQUIRE_NOT_ELEVATED() do { if (t_is_elevated()) { t_skip("requires a non-elevated token (adm mode)"); return; } } while (0)
#define REQUIRE_DESTRUCTIVE() do { if (!t_is_destructive()) { t_skip("requires ORACLE_DESTRUCTIVE=1 (dx mode)"); return; } } while (0)
#define REQUIRE_WORKGROUP()  do { if (t_is_domain_joined()) { t_skip("requires a non-domain machine"); return; } } while (0)
#define REQUIRE_DOMAIN()     do { if (!t_is_domain_joined()) { t_skip("requires a domain-joined machine (workgroup guest)"); return; } } while (0)
#define REQUIRE_TPM()        do { if (!t_has_tpm()) { t_skip("requires a TPM (tbs 0x%08lx)", (unsigned long)t_tpm_status()); return; } } while (0)
#define REQUIRE_NO_TPM()     do { if (t_has_tpm()) { t_skip("requires a machine without TPM"); return; } } while (0)

/* ---- unique names and cleanup for registry/provider/store registrations ---------------------------------------
 * t_unique("tag") -> "CRYPTT_<area>_<tag>_<pid>_<n>" (rotating static buffers; t_unique_w for UTF-16).  t_area_prefix() is
 * "CRYPTT_<area>_": everything an area registers must start with it so a sweep can remove leftovers of earlier (crashed or
 * killed) runs without touching other areas running in parallel.
 * T_SWEEPER(name) { ... } defines a sweep function; the body sees  int phase  (T_SWEEP_START before the first test,
 * T_SWEEP_END after the last) and  const char *prefix  (t_area_prefix()).  Sweeps are idempotent and best effort.
 * t_defer(fn, arg) runs fn(arg) when the current test finishes (pass, fail, skip, fault or REQUIRE return), LIFO.
 * t_reg_sweep_subkeys / t_reg_sweep_values delete keys/values below a path whose NAME starts with prefix (return count). */
#define T_SWEEP_START 0
#define T_SWEEP_END   1
const char *t_area_name(void);
const char *t_area_prefix(void);
const char *t_unique(const char *tag);
const WCHAR *t_unique_w(const char *tag);
typedef void (*t_sweep_fn)(int phase, const char *prefix);
void t_sweeper_add(t_sweep_fn fn);
#define T_SWEEPER(n) \
    static void sweep_##n(int phase, const char *prefix); \
    static void __attribute__((constructor)) regsw_##n(void) { t_sweeper_add(sweep_##n); } \
    static void sweep_##n(int phase, const char *prefix)
void t_defer(void (*fn)(void *), void *arg);
int  t_reg_sweep_subkeys(HKEY root, const char *path, const char *prefix);
int  t_reg_sweep_values(HKEY root, const char *path, const char *prefix);
#endif
