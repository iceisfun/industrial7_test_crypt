/* Export surface of the configuration APIs, configuration-change notification events and BCryptSetAuditingInterface. */
#include "cr.h"

/* ============================================================ exports */
static const struct { const char *name; unsigned ord; } cr_exports[] = {
    { "BCryptEnumContextFunctionProviders", 21 }, { "BCryptEnumContextFunctions", 22 }, { "BCryptEnumContexts", 23 },
    { "BCryptEnumRegisteredProviders", 25 }, { "BCryptFreeBuffer", 29 }, { "BCryptQueryContextConfiguration", 42 },
    { "BCryptQueryContextFunctionConfiguration", 43 }, { "BCryptQueryContextFunctionProperty", 44 },
    { "BCryptQueryProviderRegistration", 45 }, { "BCryptRegisterConfigChangeNotify", 46 }, { "BCryptResolveProviders", 50 },
    { "BCryptSetAuditingInterface", 52 }, { "BCryptUnregisterConfigChangeNotify", 56 },
};
#define CR_N_EXPORTS (sizeof cr_exports / sizeof cr_exports[0])

TEST(crexp_names_resolve_in_bcrypt)
{
    HMODULE m = t_module("bcrypt.dll"); REQUIRE(m);
    for (size_t i = 0; i < CR_N_EXPORTS; i++) {
        FARPROC p = GetProcAddress(m, cr_exports[i].name);
        CHECKF(p != NULL, "%s not exported by bcrypt.dll", cr_exports[i].name);
    }
}
TEST(crexp_ordinals_match_names)
{
    HMODULE m = t_module("bcrypt.dll"); REQUIRE(m);
    for (size_t i = 0; i < CR_N_EXPORTS; i++) {
        FARPROC byname = GetProcAddress(m, cr_exports[i].name);
        FARPROC byord = GetProcAddress(m, (LPCSTR)(ULONG_PTR)cr_exports[i].ord);
        CHECKF(byord != NULL && byord == byname, "%s ordinal %u: name=%p ordinal=%p", cr_exports[i].name, cr_exports[i].ord, (void *)byname, (void *)byord);
    }
}
TEST(crexp_lookup_is_case_sensitive)
{
    HMODULE m = t_module("bcrypt.dll"); REQUIRE(m);
    for (size_t i = 0; i < CR_N_EXPORTS; i++) {
        char lower[64]; size_t n = strlen(cr_exports[i].name);
        for (size_t k = 0; k <= n; k++) lower[k] = (char)tolower((unsigned char)cr_exports[i].name[k]);
        SET_ERR(0);
        FARPROC p = GetProcAddress(m, lower);
        CHECKF(p == NULL, "%s resolved case-insensitively", lower);
        EXPECT_ERR(ERROR_PROC_NOT_FOUND);
    }
}
TEST(crexp_no_ansi_wide_variants)
{
    HMODULE m = t_module("bcrypt.dll"); REQUIRE(m);
    for (size_t i = 0; i < CR_N_EXPORTS; i++) {
        char nm[80];
        snprintf(nm, sizeof nm, "%sA", cr_exports[i].name); SET_ERR(0);
        CHECKF(GetProcAddress(m, nm) == NULL, "%s exists", nm);
        EXPECT_ERR(ERROR_PROC_NOT_FOUND);
        snprintf(nm, sizeof nm, "%sW", cr_exports[i].name);
        CHECKF(GetProcAddress(m, nm) == NULL, "%s exists", nm);
    }
}
TEST(crexp_not_forwarded_out_of_bcrypt)
{
    HMODULE m = t_module("bcrypt.dll"); REQUIRE(m);
    /* The implementation lives in bcrypt.dll itself: the address lies inside the loaded image. */
    for (size_t i = 0; i < CR_N_EXPORTS; i++) {
        FARPROC p = GetProcAddress(m, cr_exports[i].name);
        HMODULE owner = NULL;
        BOOL ok = GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCWSTR)p, &owner);
        CHECKF(ok && owner == m, "%s resolves into another module", cr_exports[i].name);
    }
}
TEST(crexp_getprocaddress_bad_arguments)
{
    HMODULE m = t_module("bcrypt.dll"); REQUIRE(m);
    SET_ERR(0);
    FARPROC p = GetProcAddress(m, "BCryptNoSuchExport_cryptt");
    CHECK(p == NULL); EXPECT_ERR(ERROR_PROC_NOT_FOUND);
    /* ordinal outside the export table: ERROR_INVALID_ORDINAL (probed, std and adm) */
    EXPECT_GPA_FAIL(m, MAKEINTRESOURCEA(0xFFF0));
}

/* ============================================================ configuration change notification */
TEST(crnot_register_null_pointer)
{
    REQUIRE(U(BCryptRegisterConfigChangeNotify));
    EXPECT_EQ(U(BCryptRegisterConfigChangeNotify)(NULL), CRS_INVALID_PARAMETER);
}
TEST(crnot_unregister_null_handle)
{
    REQUIRE(U(BCryptUnregisterConfigChangeNotify));
    EXPECT_EQ(U(BCryptUnregisterConfigChangeNotify)(NULL), CRS_INVALID_PARAMETER);
}
TEST(crnot_register_returns_waitable_event)
{
    REQUIRE(U(BCryptRegisterConfigChangeNotify)); REQUIRE(U(BCryptUnregisterConfigChangeNotify));
    HANDLE h = (HANDLE)(ULONG_PTR)0x1234;
    NTSTATUS st = U(BCryptRegisterConfigChangeNotify)(&h);
    EXPECT_EQ(st, CRS_OK);
    if (st != CRS_OK) return;
    CHECK(h != NULL && h != INVALID_HANDLE_VALUE && h != (HANDLE)(ULONG_PTR)0x1234);
    DWORD fl = 0;
    CHECK(GetHandleInformation(h, &fl));
    /* nothing has changed the configuration: not signaled */
    EXPECT_EQ(WaitForSingleObject(h, 0), WAIT_TIMEOUT);
    EXPECT_EQ(U(BCryptUnregisterConfigChangeNotify)(h), CRS_OK);
}
TEST(crnot_event_is_auto_reset_and_modifiable)
{
    REQUIRE(U(BCryptRegisterConfigChangeNotify)); REQUIRE(U(BCryptUnregisterConfigChangeNotify));
    HANDLE h = NULL;
    if (U(BCryptRegisterConfigChangeNotify)(&h) != CRS_OK) { CHECK(0); return; }
    CHECK(SetEvent(h));
    EXPECT_EQ(WaitForSingleObject(h, 0), WAIT_OBJECT_0);
    EXPECT_EQ(WaitForSingleObject(h, 0), WAIT_TIMEOUT);       /* auto-reset: the wait consumed the signal */
    CHECK(SetEvent(h)); CHECK(ResetEvent(h));
    EXPECT_EQ(WaitForSingleObject(h, 0), WAIT_TIMEOUT);
    EXPECT_EQ(U(BCryptUnregisterConfigChangeNotify)(h), CRS_OK);
}
TEST(crnot_unregister_closes_the_handle)
{
    REQUIRE(U(BCryptRegisterConfigChangeNotify)); REQUIRE(U(BCryptUnregisterConfigChangeNotify));
    HANDLE h = NULL;
    if (U(BCryptRegisterConfigChangeNotify)(&h) != CRS_OK) { CHECK(0); return; }
    EXPECT_EQ(U(BCryptUnregisterConfigChangeNotify)(h), CRS_OK);
    DWORD fl = 0;
    SET_ERR(0);
    CHECK(!GetHandleInformation(h, &fl));
    EXPECT_ERR(ERROR_INVALID_HANDLE);
}
TEST(crnot_register_zeroes_output_on_entry)
{
    REQUIRE(U(BCryptRegisterConfigChangeNotify)); REQUIRE(U(BCryptUnregisterConfigChangeNotify));
    /* The out handle is initialised to NULL before anything else; a stale value never survives a successful call. */
    HANDLE h = (HANDLE)(ULONG_PTR)0xABCDEF0;
    NTSTATUS st = U(BCryptRegisterConfigChangeNotify)(&h);
    EXPECT_EQ(st, CRS_OK);
    CHECK(h != (HANDLE)(ULONG_PTR)0xABCDEF0);
    if (st == CRS_OK) U(BCryptUnregisterConfigChangeNotify)(h);
}
TEST(crnot_multiple_registrations_are_independent)
{
    REQUIRE(U(BCryptRegisterConfigChangeNotify)); REQUIRE(U(BCryptUnregisterConfigChangeNotify));
    HANDLE hs[8] = { 0 };
    int n = 0;
    for (; n < 8; n++) { NTSTATUS st = U(BCryptRegisterConfigChangeNotify)(&hs[n]); CHECKF(st == CRS_OK, "registration %d: 0x%lx", n, (ULONG)st); if (st != CRS_OK) break; }
    for (int i = 0; i < n; i++) for (int j = i + 1; j < n; j++) CHECK(hs[i] != hs[j]);
    /* signalling one does not signal another */
    if (n >= 2) {
        CHECK(SetEvent(hs[0]));
        EXPECT_EQ(WaitForSingleObject(hs[1], 0), WAIT_TIMEOUT);
        EXPECT_EQ(WaitForSingleObject(hs[0], 0), WAIT_OBJECT_0);
    }
    for (int i = n - 1; i >= 0; i--) EXPECT_EQ(U(BCryptUnregisterConfigChangeNotify)(hs[i]), CRS_OK);
}
TEST(crnot_unregister_in_registration_order)
{
    REQUIRE(U(BCryptRegisterConfigChangeNotify)); REQUIRE(U(BCryptUnregisterConfigChangeNotify));
    HANDLE a = NULL, b = NULL, c = NULL;
    EXPECT_EQ(U(BCryptRegisterConfigChangeNotify)(&a), CRS_OK);
    EXPECT_EQ(U(BCryptRegisterConfigChangeNotify)(&b), CRS_OK);
    EXPECT_EQ(U(BCryptRegisterConfigChangeNotify)(&c), CRS_OK);
    EXPECT_EQ(U(BCryptUnregisterConfigChangeNotify)(a), CRS_OK);
    EXPECT_EQ(U(BCryptUnregisterConfigChangeNotify)(b), CRS_OK);
    EXPECT_EQ(U(BCryptUnregisterConfigChangeNotify)(c), CRS_OK);
}
static DWORD WINAPI unreg_thread(LPVOID arg)
{
    NTSTATUS st = U(BCryptUnregisterConfigChangeNotify)((HANDLE)arg);
    return (DWORD)st;
}
TEST(crnot_unregister_from_another_thread)
{
    REQUIRE(U(BCryptRegisterConfigChangeNotify)); REQUIRE(U(BCryptUnregisterConfigChangeNotify));
    HANDLE h = NULL;
    if (U(BCryptRegisterConfigChangeNotify)(&h) != CRS_OK) { CHECK(0); return; }
    HANDLE th = CreateThread(NULL, 0, unreg_thread, h, 0, NULL);
    if (!th) { U(BCryptUnregisterConfigChangeNotify)(h); t_skip("CreateThread"); return; }
    EXPECT_EQ(WaitForSingleObject(th, 10000), WAIT_OBJECT_0);
    DWORD code = 0xFFFFFFFF; GetExitCodeThread(th, &code);
    EXPECT_EQ(code, CRS_OK);
    CloseHandle(th);
    DWORD fl; SET_ERR(0);
    CHECK(!GetHandleInformation(h, &fl)); EXPECT_ERR(ERROR_INVALID_HANDLE);
}
TEST(crnot_register_unregister_cycles_do_not_leak_handles)
{
    REQUIRE(U(BCryptRegisterConfigChangeNotify)); REQUIRE(U(BCryptUnregisterConfigChangeNotify));
    DWORD before = 0, after = 0;
    GetProcessHandleCount(GetCurrentProcess(), &before);
    for (int i = 0; i < 200; i++) {
        HANDLE h = NULL;
        NTSTATUS st = U(BCryptRegisterConfigChangeNotify)(&h);
        if (st != CRS_OK) { CHECKF(0, "cycle %d register: 0x%lx", i, (ULONG)st); break; }
        st = U(BCryptUnregisterConfigChangeNotify)(h);
        if (st != CRS_OK) { CHECKF(0, "cycle %d unregister: 0x%lx", i, (ULONG)st); CloseHandle(h); break; }
    }
    GetProcessHandleCount(GetCurrentProcess(), &after);
    CHECKF(after < before + 20, "handle count %lu -> %lu", before, after);
}
TEST(crnot_unregister_foreign_event_records)
{
    REQUIRE(U(BCryptUnregisterConfigChangeNotify));
    /* An event that was never registered: the status is decided by the configuration driver; record it, then make sure it is closed. */
    HANDLE h = CreateEventW(NULL, FALSE, FALSE, NULL);
    if (!h) { t_skip("CreateEvent"); return; }
    NTSTATUS st = U(BCryptUnregisterConfigChangeNotify)(h);
    DWORD fl = 0;
    BOOL still = GetHandleInformation(h, &fl);
    t_note("Unregister(never registered event) -> 0x%08lx, handle %s", (ULONG)st, still ? "still open" : "closed");
    if (st < 0) CHECK(still);        /* a failed unregister does not close the handle */
    if (still) CloseHandle(h);
}
CHILD(cr_notify_child)
{
    HANDLE h = NULL;
    if (U(BCryptRegisterConfigChangeNotify)(&h) != CRS_OK || !h) return 2;
    if (WaitForSingleObject(h, 0) != WAIT_TIMEOUT) return 3;
    return 0;                         /* exits with the registration still active */
}
TEST(crnot_registration_may_be_abandoned_at_process_exit)
{
    REQUIRE(U(BCryptRegisterConfigChangeNotify));
    EXPECT_EQ(t_run_child("cr_notify_child", "", 20000), 0);
    /* the service keeps working afterwards */
    HANDLE h = NULL;
    EXPECT_EQ(U(BCryptRegisterConfigChangeNotify)(&h), CRS_OK);
    if (h) U(BCryptUnregisterConfigChangeNotify)(h);
}

/* ============================================================ BCryptSetAuditingInterface */
typedef DWORD (WINAPI *auditing_fn)(void);
TEST(craud_export_resolves)
{
    HMODULE m = t_module("bcrypt.dll"); REQUIRE(m);
    CHECK(GetProcAddress(m, "BCryptSetAuditingInterface") != NULL);
    CHECK(GetProcAddress(m, (LPCSTR)(ULONG_PTR)52) == GetProcAddress(m, "BCryptSetAuditingInterface"));
}
/* The body only asks whether the calling token holds (has enabled) the privilege with LUID 7 (SeTcbPrivilege). */
static int tcb_enabled(int *known)
{
    *known = 0;
    HANDLE tok = NULL;
    if (!U(OpenProcessToken)(GetCurrentProcess(), TOKEN_QUERY, &tok)) return 0;
    LUID luid;
    int r = 0;
    if (U(LookupPrivilegeValueW)(NULL, L"SeTcbPrivilege", &luid) && luid.LowPart == 7 && luid.HighPart == 0) {
        PRIVILEGE_SET ps; BOOL res = FALSE;
        ps.PrivilegeCount = 1; ps.Control = 0; ps.Privilege[0].Luid = luid; ps.Privilege[0].Attributes = 0;
        if (U(PrivilegeCheck)(tok, &ps, &res)) { *known = 1; r = res ? 1 : 0; }
    }
    CloseHandle(tok);
    return r;
}
TEST(craud_result_follows_tcb_privilege)
{
    HMODULE m = t_module("bcrypt.dll"); REQUIRE(m);
    auditing_fn f = (auditing_fn)GetProcAddress(m, "BCryptSetAuditingInterface");
    REQUIRE(f);
    int known; int enabled = tcb_enabled(&known);
    if (!known) { t_skip("could not evaluate SeTcbPrivilege"); return; }
    DWORD r = f();
    t_note("BCryptSetAuditingInterface -> 0x%08lx (SeTcbPrivilege %s)", r, enabled ? "enabled" : "not enabled");
    EXPECT_EQ(r, enabled ? 0 : (DWORD)CRS_PRIV_NOT_HELD);
}
TEST(craud_is_repeatable_and_leaves_no_state)
{
    HMODULE m = t_module("bcrypt.dll"); REQUIRE(m);
    auditing_fn f = (auditing_fn)GetProcAddress(m, "BCryptSetAuditingInterface");
    REQUIRE(f);
    DWORD a = f(), b = f(), c = f();
    EXPECT_EQ(a, b); EXPECT_EQ(b, c);
    DWORD hc0 = 0, hc1 = 0;
    GetProcessHandleCount(GetCurrentProcess(), &hc0);
    for (int i = 0; i < 100; i++) f();
    GetProcessHandleCount(GetCurrentProcess(), &hc1);
    EXPECT_EQ(hc1, hc0);          /* the token handle it opens is always closed again */
}
