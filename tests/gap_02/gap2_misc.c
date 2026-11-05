/* Assorted internal exports with decomp-verified, side-effect-free behaviour. */
#include "gap2.h"
#include <string.h>
#define NOWINE(why) do { if (t_is_wine()) { t_skip("emulator: " why); return; } } while (0)
#define E_INVALIDARG_ 0x80070057u

/* ---- wintrust: WTIsFirstConfigCiResultPreferred(a, b, &preferred) ----------------------------
 * result blocks: DWORD state at +4 (1 best, 2 next, anything else last), BYTE flag at +0xc. */
typedef LONG (WINAPI *pf_pref)(const void *a, const void *b, char *out);
static void mkres(BYTE *b, DWORD state, BYTE flag) { memset(b, 0, 0x40); memcpy(b + 4, &state, 4); b[0xc] = flag; }
static int model_pref(DWORD sa, BYTE fa, DWORD sb, BYTE fb) {
    if (fa != fb) return fa;
    if (sa == 1) return 1;
    if (sb == 1) return 0;
    if (sa == 2) return 1;
    if (sb == 2) return 0;
    return 1;
}
TEST(gap2_wt_firstconfigci_null_args) {
    NOWINE("stub"); pf_pref f = (pf_pref)t_proc_in("wintrust.dll", "WTIsFirstConfigCiResultPreferred"); REQUIRE(f);
    BYTE a[0x40], b[0x40]; mkres(a, 1, 0); mkres(b, 1, 0);
    char out = 0x5a;
    EXPECT_EQ((DWORD)f(NULL, b, &out), E_INVALIDARG_); EXPECT_EQ(out, 0x5a);
    EXPECT_EQ((DWORD)f(a, NULL, &out), E_INVALIDARG_);
    EXPECT_EQ((DWORD)f(a, b, NULL), E_INVALIDARG_);
    EXPECT_EQ((DWORD)f(NULL, NULL, NULL), E_INVALIDARG_);
}
TEST(gap2_wt_firstconfigci_ordering_table) {
    NOWINE("stub"); pf_pref f = (pf_pref)t_proc_in("wintrust.dll", "WTIsFirstConfigCiResultPreferred"); REQUIRE(f);
    DWORD states[] = { 0, 1, 2, 3, 7 };
    for (int fa = 0; fa < 2; fa++) for (int fb = 0; fb < 2; fb++)
    for (unsigned i = 0; i < 5; i++) for (unsigned j = 0; j < 5; j++) {
        BYTE a[0x40], b[0x40]; mkres(a, states[i], (BYTE)fa); mkres(b, states[j], (BYTE)fb);
        char out = 0x5a;
        EXPECT_EQ(f(a, b, &out), 0);
        CHECKF(out == model_pref(states[i], (BYTE)fa, states[j], (BYTE)fb),
               "sa=%lu fa=%d sb=%lu fb=%d got %d", states[i], fa, states[j], fb, out);
    }
}
TEST(gap2_wt_firstconfigci_equal_inputs_prefer_first) {
    NOWINE("stub"); pf_pref f = (pf_pref)t_proc_in("wintrust.dll", "WTIsFirstConfigCiResultPreferred"); REQUIRE(f);
    BYTE a[0x40]; mkres(a, 2, 1); char out = 0;
    EXPECT_EQ(f(a, a, &out), 0); EXPECT_EQ(out, 1);
}

/* ---- WTValidateBioSignaturePolicy(NULL, &flag) ------------------------------------------------ */
TEST(gap2_wt_validatebiosignaturepolicy_null_provider) {
    NOWINE("stub"); typedef LONG (WINAPI *pf)(void *pd, char *out);
    pf f = (pf)t_proc_in("wintrust.dll", "WTValidateBioSignaturePolicy"); REQUIRE(f);
    char out = 0x5a;
    EXPECT_EQ((DWORD)f(NULL, &out), E_INVALIDARG_);
    EXPECT_EQ(out, 0);                 /* output is cleared before the argument is rejected */
}

/* ---- ncrypt!NCryptSetAuditingInterface: privilege probe --------------------------------------- */
TEST(gap2_ncrypt_setauditinginterface_matches_tcb_privilege_state) {
    NOWINE("stub"); typedef DWORD (WINAPI *pf)(void);
    pf f = (pf)t_proc_in("ncrypt.dll", "NCryptSetAuditingInterface"); REQUIRE(f);
    HANDLE tok = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) { t_skip("no token"); return; }
    PRIVILEGE_SET ps = {0}; ps.PrivilegeCount = 1; ps.Privilege[0].Luid.LowPart = 7;   /* SeTcbPrivilege */
    BOOL held = FALSE;
    BOOL ok = PrivilegeCheck(tok, &ps, &held);
    DWORD perr = GetLastError();
    CloseHandle(tok);
    DWORD r = f();
    if (!ok) {   /* the export maps the same Win32 failure: positive codes become 0xC007xxxx */
        EXPECT_EQ(r, (int)perr < 1 ? perr : ((perr & 0xffff) | 0xC0070000u));
        return;
    }
    if (held) EXPECT_EQ(r, 0);
    else EXPECT_EQ(r, 0xC0000061u);      /* STATUS_PRIVILEGE_NOT_HELD */
}

/* ---- cryptui!FormatDateStringAutoLayout(&str, FILETIME, withTime) ------------------------------- */
typedef int (WINAPI *pf_fmtdate)(WCHAR **out, FILETIME ft, int withTime);
static FILETIME mkft(ULONGLONG v) { FILETIME f; f.dwLowDateTime = (DWORD)v; f.dwHighDateTime = (DWORD)(v >> 32); return f; }
TEST(gap2_cryptui_formatdate_date_only_and_with_time) {
    NOWINE("stub"); pf_fmtdate f = (pf_fmtdate)t_proc_in("cryptui.dll", "FormatDateStringAutoLayout"); REQUIRE(f);
    FILETIME ft = mkft(132223104000000000ULL);   /* 2020-01-01 00:00:00 UTC */
    WCHAR *d = NULL, *dt = NULL;
    EXPECT_EQ(f(&d, ft, 0), 1);
    EXPECT_EQ(f(&dt, ft, 1), 1);
    CHECK(d && d[0]); CHECK(dt && dt[0]);
    if (d && dt) {
        CHECK(lstrlenW(dt) > lstrlenW(d));
    }
    if (d) CHECK(LocalFree(d) == NULL);
    if (dt) CHECK(LocalFree(dt) == NULL);
}
TEST(gap2_cryptui_formatdate_out_of_range_filetime_fails) {
    NOWINE("stub"); pf_fmtdate f = (pf_fmtdate)t_proc_in("cryptui.dll", "FormatDateStringAutoLayout"); REQUIRE(f);
    WCHAR *s = (WCHAR *)(ULONG_PTR)1;
    EXPECT_EQ(f(&s, mkft(0xFFFFFFFFFFFFFFFFULL), 1), 0);
    CHECK(s == (WCHAR *)(ULONG_PTR)1);
}
TEST(gap2_cryptui_commoninit_returns_one) {
    NOWINE("stub"); typedef int (WINAPI *pf)(void);
    pf f = (pf)t_proc_in("cryptui.dll", "CommonInit"); REQUIRE(f);
    EXPECT_EQ(f(), 1);
    EXPECT_EQ(f(), 1);
}

/* ---- wintrust: CatalogCompactHashDatabase / pause are service-backed; presence only -------------- */
TEST(gap2_wt_service_entry_points_resolve) {
    const char *n[] = { "CatalogCompactHashDatabase", "CryptCATAdminPauseServiceForBackup", "SoftpubDllRegisterServer",
        "SoftpubDllUnregisterServer", "mscat32DllRegisterServer", "mscat32DllUnregisterServer", "WTGetBioSignatureInfo",
        "WTGetPluginSignatureInfo", "WTIsFirstConfigCiResultPreferred", "WTLogConfigCiScriptEvent", "WTLogConfigCiSignerEvent",
        "WTValidateBioSignaturePolicy", "ConfigCiPackageFamilyNameCheck", "SrpCheckSmartlockerEAandProcessToken" };
    for (unsigned i = 0; i < sizeof n / sizeof *n; i++) { FARPROC p = t_proc_in("wintrust.dll", n[i]); if (t_is_wine() && !p) continue; CHECKF(p != NULL, "wintrust!%s", n[i]); }
}
TEST(gap2_registration_entry_points_resolve) {
    const char *w[] = { "SoftpubDllRegisterServer", "SoftpubDllUnregisterServer", "mscat32DllRegisterServer", "mscat32DllUnregisterServer" };
    for (unsigned i = 0; i < 4; i++) { FARPROC p = t_proc_in("wintrust.dll", w[i]); if (t_is_wine() && !p) continue; CHECKF(p != NULL, "%s", w[i]); }
    FARPROC a = t_proc_in("mssip32.dll", "mssip32DllRegisterServer");
    FARPROC b = t_proc_in("mssip32.dll", "mssip32DllUnregisterServer");
    if (!t_is_wine()) { CHECK(a != NULL); CHECK(b != NULL); }
    const char *s[] = { "CAPISysPrep_Generalize", "CryptoSysPrep_Clean", "CryptoSysPrep_Specialize", "CryptoSysPrep_Specialize_Clone", "CryptoSysPrep_Specialize_Offline" };
    for (unsigned i = 0; i < 5; i++) { FARPROC p = t_proc_in("capisp.dll", s[i]); if (t_is_wine() && !p) continue; CHECKF(p != NULL, "capisp!%s", s[i]); }
    t_note("sysprep/registration entry points are resolved only; calling them mutates machine state");
}
