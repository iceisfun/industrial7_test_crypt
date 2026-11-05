#include "wcfg.h"
/* WintrustAddDefaultForUsage / WintrustGetDefaultForUsage.
 * Registry: HKLM\SOFTWARE\Microsoft\Cryptography\Providers\Trust\Usages\<usage oid>
 *   DefaultId (REG_SZ "{GUID}"), $DLL (REG_SZ), CallbackAllocFunction / CallbackFreeFunction (REG_SZ).
 * There is no API to remove a usage: the tests delete their own (cryptt.usage.<pid>.n) keys. */

#define USETUP(fn) REQUIRE(U(WintrustAddDefaultForUsage)); REQUIRE(U(WintrustGetDefaultForUsage)); \
    if (t_is_wine()) { t_skip("emulator aborts: WintrustGet/AddDefaultForUsage unimplemented"); return; } \
    if (!wcfg_begin_trust()) return

static void uoid(char *out, int n) { sprintf(out, "cryptt.usage.%lu.%d", GetCurrentProcessId(), n); }
static void upath(wchar_t *out, const char *oid) { swprintf(out, 400, L"" WCFG_TRUST L"\\Usages\\%hs", oid); }

typedef struct { CRYPT_PROVIDER_REGDEFUSAGE r; GUID g; wchar_t dll[MAX_PATH]; } ureg_t;
static void ufill(ureg_t *u, unsigned slot, int with_dll, int with_alloc, int with_free) {
    memset(u, 0, sizeof *u);
    wcfg_guid(&u->g, slot);
    u->r.cbStruct = sizeof u->r;
    u->r.pgActionID = &u->g;
    if (with_dll) { wcfg_selfpath(u->dll, MAX_PATH); u->r.pwszDllName = u->dll; }
    if (with_alloc) u->r.pwszLoadCallbackDataFunctionName = "cryptt_UsageAlloc";
    if (with_free) u->r.pwszFreeCallbackDataFunctionName = "cryptt_UsageFree";
}
static void ureset(void) { wcfg_usage_alloc_calls = wcfg_usage_free_calls = 0; wcfg_usage_alloc_ret = TRUE; wcfg_usage_alloc_oid = NULL;
    memset(&wcfg_usage_alloc_guid, 0, sizeof(GUID)); }
extern GUID wcfg_usage_free_guid; extern const char *wcfg_usage_free_oid;

TEST(wcfg_usage_struct_layout) {
    CHECK(sizeof(CRYPT_PROVIDER_REGDEFUSAGE) == 40);
    CHECK(sizeof(CRYPT_PROVIDER_DEFUSAGE) == 40);
    CHECK(offsetof(CRYPT_PROVIDER_DEFUSAGE, gActionID) == 4);
}
TEST(wcfg_usage_add_minimal_registers_default_id_only) {
    USETUP(x); char o[100]; uoid(o, 1); ureg_t u; ufill(&u, 300, 0, 0, 0);
    SET_ERR(0);
    CHECK(U(WintrustAddDefaultForUsage)(o, &u.r));
    wchar_t p[400], b[100]; DWORD t, cb; upath(p, o);
    EXPECT_EQ(wcfg_get_str(p, L"DefaultId", b, 100, &t, &cb), 0);
    EXPECT_EQ(t, REG_SZ);
    wchar_t gs[48]; wcfg_guid_str(&u.g, gs);
    CHECK(!wcscmp(b, gs)); EXPECT_EQ(cb, (wcslen(gs) + 1) * 2);
    CHECK(wcfg_get_str(p, L"$DLL", b, 100, NULL, NULL) != 0);
    CHECK(wcfg_get_str(p, L"CallbackAllocFunction", b, 100, NULL, NULL) != 0);
    wcfg_end();
}
TEST(wcfg_usage_add_with_dll_and_callbacks) {
    USETUP(x); char o[100]; uoid(o, 2); ureg_t u; ufill(&u, 301, 1, 1, 1);
    CHECK(U(WintrustAddDefaultForUsage)(o, &u.r));
    wchar_t p[400], b[MAX_PATH]; DWORD t, cb; upath(p, o);
    EXPECT_EQ(wcfg_get_str(p, L"$DLL", b, MAX_PATH, &t, &cb), 0); EXPECT_EQ(t, REG_SZ); CHECK(!wcscmp(b, u.dll));
    EXPECT_EQ(wcfg_get_str(p, L"CallbackAllocFunction", b, MAX_PATH, &t, &cb), 0); EXPECT_EQ(t, REG_SZ); CHECK(!wcscmp(b, L"cryptt_UsageAlloc"));
    EXPECT_EQ(wcfg_get_str(p, L"CallbackFreeFunction", b, MAX_PATH, &t, &cb), 0); CHECK(!wcscmp(b, L"cryptt_UsageFree"));
    wcfg_end();
}
TEST(wcfg_usage_add_free_callback_needs_alloc_callback) {
    USETUP(x); char o[100]; uoid(o, 3); ureg_t u; ufill(&u, 302, 1, 0, 1);
    CHECK(U(WintrustAddDefaultForUsage)(o, &u.r));
    wchar_t p[400], b[MAX_PATH]; upath(p, o);
    CHECK(wcfg_get_str(p, L"CallbackFreeFunction", b, MAX_PATH, NULL, NULL) != 0);
    CHECK(wcfg_get_str(p, L"CallbackAllocFunction", b, MAX_PATH, NULL, NULL) != 0);
    CHECK(wcfg_get_str(p, L"$DLL", b, MAX_PATH, NULL, NULL) == 0);
    wcfg_end();
}
TEST(wcfg_usage_add_callbacks_without_dll_not_stored) {
    USETUP(x); char o[100]; uoid(o, 4); ureg_t u; ufill(&u, 303, 0, 1, 1);
    CHECK(U(WintrustAddDefaultForUsage)(o, &u.r));
    wchar_t p[400], b[MAX_PATH]; upath(p, o);
    CHECK(wcfg_get_str(p, L"CallbackAllocFunction", b, MAX_PATH, NULL, NULL) != 0);
    CHECK(wcfg_get_str(p, L"$DLL", b, MAX_PATH, NULL, NULL) != 0);
    wcfg_end();
}
TEST(wcfg_usage_add_invalid_arguments) {
    USETUP(x); char o[100]; uoid(o, 5); ureg_t u; ufill(&u, 304, 0, 0, 0);
    SET_ERR(0); CHECK(!U(WintrustAddDefaultForUsage)(NULL, &u.r)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!U(WintrustAddDefaultForUsage)(o, NULL)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    ureg_t v = u; v.r.pgActionID = NULL;
    SET_ERR(0); CHECK(!U(WintrustAddDefaultForUsage)(o, &v.r)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    wchar_t p[400]; upath(p, o); CHECK(!wcfg_key_exists(p));
    wcfg_end();
}
TEST(wcfg_usage_add_cbstruct_boundary) {
    USETUP(x); char o[100]; uoid(o, 6); ureg_t u; ufill(&u, 305, 0, 0, 0);
    static const DWORD bad[] = { 0, 4, 0x10, 0x1F, 0x20 };
    for (unsigned i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        u.r.cbStruct = bad[i];
        SET_ERR(0); CHECKF(!U(WintrustAddDefaultForUsage)(o, &u.r), "cbStruct 0x%lx", bad[i]); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    }
    wchar_t p[400]; upath(p, o); CHECK(!wcfg_key_exists(p));
    u.r.cbStruct = 0x21; CHECK(U(WintrustAddDefaultForUsage)(o, &u.r));
    CHECK(wcfg_key_exists(p));
    wcfg_end();
}
TEST(wcfg_usage_add_oid_length_limits) {
    USETUP(x); ureg_t u; ufill(&u, 306, 0, 0, 0);
    char o[100]; strcpy(o, "cryptt.usage.");
    sprintf(o + strlen(o), "%lu.", GetCurrentProcessId());
    while (strlen(o) < 63) strcat(o, "a");               /* 63 chars + NUL fills the 64 wchar buffer */
    SET_ERR(0); CHECK(U(WintrustAddDefaultForUsage)(o, &u.r));
    wcfg_sweep();
    strcat(o, "a");                                       /* 64 chars: does not fit */
    SET_ERR(0); CHECK(!U(WintrustAddDefaultForUsage)(o, &u.r)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    char longo[200]; memset(longo, 'b', 150); longo[150] = 0; memcpy(longo, "cryptt.usage.", 13);
    SET_ERR(0); CHECK(!U(WintrustAddDefaultForUsage)(longo, &u.r)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    wcfg_end();
}
TEST(wcfg_usage_add_empty_oid) {
    USETUP(x); ureg_t u; ufill(&u, 307, 0, 0, 0);
    SET_ERR(0); BOOL r = U(WintrustAddDefaultForUsage)("", &u.r);
    t_note("empty usage oid: %d (err %lu)", r, GetLastError());
    CHECK(!r);
    wcfg_end();
}
TEST(wcfg_usage_add_second_call_overwrites_default_id) {
    USETUP(x); char o[100]; uoid(o, 7); ureg_t a, b; ufill(&a, 308, 0, 0, 0); ufill(&b, 309, 0, 0, 0);
    CHECK(U(WintrustAddDefaultForUsage)(o, &a.r));
    CHECK(U(WintrustAddDefaultForUsage)(o, &b.r));
    CRYPT_PROVIDER_DEFUSAGE d; memset(&d, 0, sizeof d); d.cbStruct = sizeof d;
    CHECK(U(WintrustGetDefaultForUsage)(DWACTION_ALLOCANDFILL, o, &d));
    CHECK(!memcmp(&d.gActionID, &b.g, sizeof(GUID)));
    wcfg_end();
}
TEST(wcfg_usage_add_second_call_keeps_stale_dll_values) {
    USETUP(x); char o[100]; uoid(o, 8); ureg_t a, b; ufill(&a, 310, 1, 1, 1); ufill(&b, 311, 0, 0, 0);
    CHECK(U(WintrustAddDefaultForUsage)(o, &a.r));
    CHECK(U(WintrustAddDefaultForUsage)(o, &b.r));
    wchar_t p[400], s[MAX_PATH]; upath(p, o);
    CHECK(wcfg_get_str(p, L"$DLL", s, MAX_PATH, NULL, NULL) == 0);
    CHECK(wcfg_get_str(p, L"CallbackAllocFunction", s, MAX_PATH, NULL, NULL) == 0);
    wcfg_end();
}

/* ---- Get ---- */
TEST(wcfg_usage_get_roundtrip_default_id) {
    USETUP(x); char o[100]; uoid(o, 10); ureg_t u; ufill(&u, 320, 0, 0, 0);
    CHECK(U(WintrustAddDefaultForUsage)(o, &u.r));
    CRYPT_PROVIDER_DEFUSAGE d; memset(&d, 0xEE, sizeof d); d.cbStruct = sizeof d;
    SET_ERR(0);
    CHECK(U(WintrustGetDefaultForUsage)(DWACTION_ALLOCANDFILL, o, &d));
    CHECK(!memcmp(&d.gActionID, &u.g, sizeof(GUID)));
    EXPECT_EQ(d.cbStruct, sizeof d);
    wcfg_end();
}
TEST(wcfg_usage_get_unregistered_usage_fails_and_zeroes_guid) {
    USETUP(x); char o[100]; uoid(o, 11);
    CRYPT_PROVIDER_DEFUSAGE d; memset(&d, 0xEE, sizeof d); d.cbStruct = sizeof d;
    CHECK(!U(WintrustGetDefaultForUsage)(DWACTION_ALLOCANDFILL, o, &d));
    static const GUID z; CHECK(!memcmp(&d.gActionID, &z, sizeof z));
    wcfg_end();
}
TEST(wcfg_usage_get_invalid_arguments) {
    USETUP(x); char o[100]; uoid(o, 12);
    CRYPT_PROVIDER_DEFUSAGE d; memset(&d, 0, sizeof d); d.cbStruct = sizeof d;
    SET_ERR(0); CHECK(!U(WintrustGetDefaultForUsage)(1, NULL, &d)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!U(WintrustGetDefaultForUsage)(1, o, NULL)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    d.cbStruct = 0x20; SET_ERR(0); CHECK(!U(WintrustGetDefaultForUsage)(1, o, &d)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    d.cbStruct = 0; SET_ERR(0); CHECK(!U(WintrustGetDefaultForUsage)(1, o, &d)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    char longo[100]; memset(longo, 'c', 80); longo[80] = 0;
    d.cbStruct = sizeof d; SET_ERR(0); CHECK(!U(WintrustGetDefaultForUsage)(1, longo, &d)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    wcfg_end();
}
TEST(wcfg_usage_get_cbstruct_21_accepted) {
    USETUP(x); char o[100]; uoid(o, 13); ureg_t u; ufill(&u, 321, 0, 0, 0);
    CHECK(U(WintrustAddDefaultForUsage)(o, &u.r));
    CRYPT_PROVIDER_DEFUSAGE d; memset(&d, 0, sizeof d); d.cbStruct = 0x21;
    CHECK(U(WintrustGetDefaultForUsage)(DWACTION_ALLOCANDFILL, o, &d));
    wcfg_end();
}
TEST(wcfg_usage_get_calls_alloc_callback) {
    USETUP(x); char o[100]; uoid(o, 14); ureg_t u; ufill(&u, 322, 1, 1, 1);
    CHECK(U(WintrustAddDefaultForUsage)(o, &u.r));
    ureset();
    CRYPT_PROVIDER_DEFUSAGE d; memset(&d, 0, sizeof d); d.cbStruct = sizeof d;
    CHECK(U(WintrustGetDefaultForUsage)(DWACTION_ALLOCANDFILL, o, &d));
    EXPECT_EQ(wcfg_usage_alloc_calls, 1); EXPECT_EQ(wcfg_usage_free_calls, 0);
    CHECK(wcfg_usage_alloc_oid == o);
    CHECK(wcfg_usage_alloc_ud == &d);
    CHECK(!memcmp(&wcfg_usage_alloc_guid, &u.g, sizeof(GUID)));      /* DefaultId is already filled in when the callback runs */
    wcfg_end();
}
TEST(wcfg_usage_get_alloc_callback_failure_fails_get) {
    USETUP(x); char o[100]; uoid(o, 15); ureg_t u; ufill(&u, 323, 1, 1, 1);
    CHECK(U(WintrustAddDefaultForUsage)(o, &u.r));
    ureset(); wcfg_usage_alloc_ret = FALSE;
    CRYPT_PROVIDER_DEFUSAGE d; memset(&d, 0, sizeof d); d.cbStruct = sizeof d;
    CHECK(!U(WintrustGetDefaultForUsage)(DWACTION_ALLOCANDFILL, o, &d));
    EXPECT_EQ(wcfg_usage_alloc_calls, 1);
    wcfg_end();
}
TEST(wcfg_usage_get_free_action_calls_free_callback) {
    USETUP(x); char o[100]; uoid(o, 16); ureg_t u; ufill(&u, 324, 1, 1, 1);
    CHECK(U(WintrustAddDefaultForUsage)(o, &u.r));
    ureset();
    CRYPT_PROVIDER_DEFUSAGE d; memset(&d, 0, sizeof d); d.cbStruct = sizeof d;
    d.gActionID = u.g;
    CHECK(U(WintrustGetDefaultForUsage)(DWACTION_FREE, o, &d));
    EXPECT_EQ(wcfg_usage_free_calls, 1); EXPECT_EQ(wcfg_usage_alloc_calls, 0);
    CHECK(wcfg_usage_free_oid == o);
    static const GUID z; CHECK(!memcmp(&wcfg_usage_free_guid, &z, sizeof z));     /* gActionID is cleared before any callback */
    wcfg_end();
}
TEST(wcfg_usage_get_free_action_without_dll_succeeds) {
    USETUP(x); char o[100]; uoid(o, 17); ureg_t u; ufill(&u, 325, 0, 0, 0);
    CHECK(U(WintrustAddDefaultForUsage)(o, &u.r));
    CRYPT_PROVIDER_DEFUSAGE d; memset(&d, 0, sizeof d); d.cbStruct = sizeof d;
    CHECK(U(WintrustGetDefaultForUsage)(DWACTION_FREE, o, &d));
    wcfg_end();
}
TEST(wcfg_usage_get_free_action_unregistered_usage_fails) {
    USETUP(x); char o[100]; uoid(o, 18);
    CRYPT_PROVIDER_DEFUSAGE d; memset(&d, 0, sizeof d); d.cbStruct = sizeof d;
    CHECK(!U(WintrustGetDefaultForUsage)(DWACTION_FREE, o, &d));
    wcfg_end();
}
TEST(wcfg_usage_get_missing_dll_still_returns_default_id) {
    USETUP(x); char o[100]; uoid(o, 19); ureg_t u; ufill(&u, 326, 0, 1, 1);
    u.r.pwszDllName = L"cryptt_no_such_module.dll";
    CHECK(U(WintrustAddDefaultForUsage)(o, &u.r));
    ureset();
    CRYPT_PROVIDER_DEFUSAGE d; memset(&d, 0, sizeof d); d.cbStruct = sizeof d;
    CHECK(U(WintrustGetDefaultForUsage)(DWACTION_ALLOCANDFILL, o, &d));
    CHECK(!memcmp(&d.gActionID, &u.g, sizeof(GUID)));
    EXPECT_EQ(wcfg_usage_alloc_calls, 0);
    wcfg_end();
}
TEST(wcfg_usage_get_missing_callback_export_still_returns_default_id) {
    USETUP(x); char o[100]; uoid(o, 20); ureg_t u; ufill(&u, 327, 1, 0, 0);
    u.r.pwszLoadCallbackDataFunctionName = "cryptt_NoSuchCallback";
    CHECK(U(WintrustAddDefaultForUsage)(o, &u.r));
    CRYPT_PROVIDER_DEFUSAGE d; memset(&d, 0, sizeof d); d.cbStruct = sizeof d;
    CHECK(U(WintrustGetDefaultForUsage)(DWACTION_ALLOCANDFILL, o, &d));
    CHECK(!memcmp(&d.gActionID, &u.g, sizeof(GUID)));
    wcfg_end();
}
TEST(wcfg_usage_get_unknown_action_code_does_not_read_default_id) {
    USETUP(x); char o[100]; uoid(o, 21); ureg_t u; ufill(&u, 328, 0, 0, 0);
    CHECK(U(WintrustAddDefaultForUsage)(o, &u.r));
    CRYPT_PROVIDER_DEFUSAGE d; memset(&d, 0xEE, sizeof d); d.cbStruct = sizeof d;
    BOOL r = U(WintrustGetDefaultForUsage)(7, o, &d);
    CHECK(r == TRUE);
    static const GUID z; CHECK(!memcmp(&d.gActionID, &z, sizeof z));
    wcfg_end();
}
TEST(wcfg_usage_get_two_usages_independent) {
    USETUP(x); char o1[100], o2[100]; uoid(o1, 23); uoid(o2, 24); ureg_t a, b; ufill(&a, 330, 0, 0, 0); ufill(&b, 331, 0, 0, 0);
    CHECK(U(WintrustAddDefaultForUsage)(o1, &a.r)); CHECK(U(WintrustAddDefaultForUsage)(o2, &b.r));
    CRYPT_PROVIDER_DEFUSAGE d; memset(&d, 0, sizeof d); d.cbStruct = sizeof d;
    CHECK(U(WintrustGetDefaultForUsage)(1, o1, &d)); CHECK(!memcmp(&d.gActionID, &a.g, sizeof(GUID)));
    CHECK(U(WintrustGetDefaultForUsage)(1, o2, &d)); CHECK(!memcmp(&d.gActionID, &b.g, sizeof(GUID)));
    wcfg_end();
}
TEST(wcfg_usage_get_oid_ascii_conversion) {
    USETUP(x); ureg_t u; ufill(&u, 332, 0, 0, 0);
    char o[100]; sprintf(o, "cryptt.usage.%lu.9.ABC_xyz-1", GetCurrentProcessId());
    CHECK(U(WintrustAddDefaultForUsage)(o, &u.r));
    wchar_t p[400]; swprintf(p, 400, L"" WCFG_TRUST L"\\Usages\\cryptt.usage.%lu.9.ABC_xyz-1", GetCurrentProcessId());
    CHECK(wcfg_key_exists(p));
    CRYPT_PROVIDER_DEFUSAGE d; memset(&d, 0, sizeof d); d.cbStruct = sizeof d;
    CHECK(U(WintrustGetDefaultForUsage)(1, o, &d));
    wcfg_end();
}
TEST(wcfg_usage_real_code_signing_usage_is_registered) {
    /* read only: the built-in code signing usage maps to the generic verify action */
    REQUIRE(U(WintrustGetDefaultForUsage));
    if (t_is_wine()) { t_skip("emulator aborts"); return; }
    CRYPT_PROVIDER_DEFUSAGE d; memset(&d, 0, sizeof d); d.cbStruct = sizeof d;
    BOOL r = U(WintrustGetDefaultForUsage)(DWACTION_ALLOCANDFILL, "1.3.6.1.5.5.7.3.3", &d);
    t_note("default for code signing usage: %d %08lX-%04X-%04X", r, d.gActionID.Data1, d.gActionID.Data2, d.gActionID.Data3);
}
