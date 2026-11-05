#include "wcfg.h"
/* WintrustAddActionID / WintrustRemoveActionID: registry layout and argument handling.
 * Key = HKLM\SOFTWARE\Microsoft\Cryptography\Providers\Trust\<kind>\{GUID}, values $DLL / $Function (REG_SZ, wide). */

#define SETUP(fn) REQUIRE(U(fn)); if (!wcfg_begin_trust()) return
#define SETUPW(fn) SETUP(fn); if (t_is_wine()) { t_skip("emulator differs from decomp"); wcfg_end(); return; }
#define E_INVAL 0x57

static const char *const kind_field[8] = { "Init", "Object", "Signature", "Certificate", "CertificatePolicy", "Final", "Test", "Cleanup" };

static CRYPT_TRUST_REG_ENTRY *entry(wcfg_reg_t *x, int k) {
    CRYPT_TRUST_REG_ENTRY *e[8] = { &x->r.sInitProvider, &x->r.sObjectProvider, &x->r.sSignatureProvider, &x->r.sCertificateProvider,
        &x->r.sCertificatePolicyProvider, &x->r.sFinalPolicyProvider, &x->r.sTestPolicyProvider, &x->r.sCleanupProvider };
    return e[k];
}

TEST(wcfg_action_struct_layout) {
    CHECK(sizeof(CRYPT_TRUST_REG_ENTRY) == 24);
    CHECK(sizeof(CRYPT_REGISTER_ACTIONID) == 200);
    CHECK(offsetof(CRYPT_REGISTER_ACTIONID, sInitProvider) == 8);
    CHECK(offsetof(CRYPT_REGISTER_ACTIONID, sCleanupProvider) == 176);
}

/* every provider slot lands in its own registry key, with both values, as REG_SZ */
#define KIND_TEST(K, NAME) TEST(wcfg_action_add_registers_##NAME) { \
    SETUP(WintrustAddActionID); GUID g; wcfg_guid(&g, 1); wcfg_reg_t x; wcfg_fill_reg(&x); \
    CRYPT_TRUST_REG_ENTRY *e = entry(&x, K); e->pwszDLLName = L"d" #NAME L".dll"; e->pwszFunctionName = L"f" #NAME; \
    SET_ERR(0); CHECK(wcfg_add(&g, 0, &x)); \
    wchar_t dll[300], fn[300]; CHECK(wcfg_prov_registered(K, &g, dll, fn)); \
    CHECK(!wcscmp(dll, L"d" #NAME L".dll")); CHECK(!wcscmp(fn, L"f" #NAME)); \
    wchar_t gs[48], p[300]; wcfg_guid_str(&g, gs); swprintf(p, 300, L"" WCFG_TRUST L"\\%ls\\%ls", wcfg_kind[K], gs); \
    DWORD t = 0, cb = 0; wchar_t b[300]; \
    EXPECT_EQ(wcfg_get_str(p, L"$DLL", b, 300, &t, &cb), 0); EXPECT_EQ(t, REG_SZ); EXPECT_EQ(cb, (wcslen(L"d" #NAME L".dll") + 1) * 2); \
    EXPECT_EQ(wcfg_get_str(p, L"$Function", b, 300, &t, &cb), 0); EXPECT_EQ(t, REG_SZ); EXPECT_EQ(cb, (wcslen(L"f" #NAME) + 1) * 2); \
    for (int k = 0; k < 8; k++) CHECKF(wcfg_prov_registered(k, &g, NULL, NULL), "kind %d registered", k); \
    CHECK(WintrustRemoveActionID_ok(&g)); wcfg_end(); }

static int WintrustRemoveActionID_ok(const GUID *g) { return U(WintrustRemoveActionID)((GUID *)g); }
KIND_TEST(0, init)
KIND_TEST(1, object)
KIND_TEST(2, signature)
KIND_TEST(3, certificate)
KIND_TEST(4, certpolicy)
KIND_TEST(5, final)
KIND_TEST(6, test)
KIND_TEST(7, cleanup)

TEST(wcfg_action_add_returns_true_and_keeps_last_error_unspecified) {
    SETUP(WintrustAddActionID); GUID g; wcfg_guid(&g, 2); wcfg_reg_t x; wcfg_fill_reg(&x);
    BOOL r = wcfg_add(&g, 0, &x);
    CHECK(r == TRUE);
    U(WintrustRemoveActionID)(&g); wcfg_end();
}

TEST(wcfg_action_add_null_info_fails_invalid_parameter) {
    SETUP(WintrustAddActionID); GUID g; wcfg_guid(&g, 3);
    SET_ERR(0); BOOL r = U(WintrustAddActionID)(&g, 0, NULL); CHECK(!r); EXPECT_ERR(E_INVAL);
    SET_ERR(0); r = U(WintrustAddActionID)(&g, WT_ADD_ACTION_ID_RET_RESULT_FLAG, NULL); CHECK(!r); EXPECT_ERR(E_INVAL);
    CHECK(!wcfg_prov_registered(0, &g, NULL, NULL));
    wcfg_end();
}

static const DWORD bad_cb[] = { 0, 4, 8, 0x20, 0x58, 0xA8, 0xAF };
TEST(wcfg_action_add_small_cbstruct_fails) {
    SETUP(WintrustAddActionID); GUID g; wcfg_guid(&g, 4); wcfg_reg_t x;
    for (unsigned i = 0; i < sizeof bad_cb / sizeof bad_cb[0]; i++) {
        wcfg_fill_reg(&x); x.r.cbStruct = bad_cb[i];
        SET_ERR(0); BOOL r = wcfg_add(&g, 0, &x);
        CHECKF(!r, "cbStruct 0x%lx must fail", bad_cb[i]); EXPECT_ERR(E_INVAL);
        CHECKF(!wcfg_prov_registered(0, &g, NULL, NULL), "nothing written for cbStruct 0x%lx", bad_cb[i]);
    }
    wcfg_end();
}
TEST(wcfg_action_add_cbstruct_b0_skips_cleanup) {
    SETUPW(WintrustAddActionID); GUID g; wcfg_guid(&g, 5); wcfg_reg_t x; wcfg_fill_reg(&x);
    x.r.cbStruct = WCFG_REG_SIZE_NOCLEANUP;
    CHECK(wcfg_add(&g, 0, &x));
    for (int k = 0; k < 7; k++) CHECKF(wcfg_prov_registered(k, &g, NULL, NULL), "kind %d", k);
    CHECK(!wcfg_prov_registered(7, &g, NULL, NULL));
    wcfg_end();
}
TEST(wcfg_action_add_cbstruct_c7_skips_cleanup) {
    SETUPW(WintrustAddActionID); GUID g; wcfg_guid(&g, 6); wcfg_reg_t x; wcfg_fill_reg(&x);
    x.r.cbStruct = 0xC7;
    CHECK(wcfg_add(&g, 0, &x));
    CHECK(wcfg_prov_registered(5, &g, NULL, NULL));
    CHECK(!wcfg_prov_registered(7, &g, NULL, NULL));
    wcfg_end();
}
TEST(wcfg_action_add_cbstruct_c8_registers_cleanup) {
    SETUP(WintrustAddActionID); GUID g; wcfg_guid(&g, 7); wcfg_reg_t x; wcfg_fill_reg(&x);
    CHECK(wcfg_add(&g, 0, &x));
    wchar_t d[300], f[300];
    CHECK(wcfg_prov_registered(7, &g, d, f)); CHECK(!wcscmp(f, L"cryptt_Cleanup"));
    wcfg_end();
}
TEST(wcfg_action_add_cbstruct_larger_than_struct_is_accepted) {
    SETUPW(WintrustAddActionID); GUID g; wcfg_guid(&g, 8);
    struct { wcfg_reg_t x; BYTE pad[64]; } big; memset(&big, 0, sizeof big);
    wcfg_fill_reg(&big.x); big.x.r.cbStruct = 0x200;
    CHECK(wcfg_add(&g, 0, &big.x));
    CHECK(wcfg_prov_registered(7, &g, NULL, NULL));
    wcfg_end();
}

TEST(wcfg_action_add_null_guid_ignored_without_flag_fails_with_flag) {
    SETUPW(WintrustAddActionID); wcfg_reg_t x; wcfg_fill_reg(&x);
    /* every SetRegProvider fails with invalid parameter; without the flag the failure is swallowed */
    SET_ERR(0); BOOL r = U(WintrustAddActionID)(NULL, 0, &x.r);
    CHECK(r == TRUE);
    SET_ERR(0); r = U(WintrustAddActionID)(NULL, WT_ADD_ACTION_ID_RET_RESULT_FLAG, &x.r);
    CHECK(!r); EXPECT_ERR(E_INVAL);
    wcfg_end();
}

/* one provider with a NULL dll or function name: that provider is not written, the others are,
 * and the result is TRUE unless WT_ADD_ACTION_ID_RET_RESULT_FLAG is given */
static void null_field_case(int kind, int null_dll, unsigned slot) {
    GUID g; wcfg_guid(&g, slot); wcfg_reg_t x; wcfg_fill_reg(&x);
    CRYPT_TRUST_REG_ENTRY *e = entry(&x, kind);
    if (null_dll) e->pwszDLLName = NULL; else e->pwszFunctionName = NULL;
    SET_ERR(0);
    BOOL r = wcfg_add(&g, 0, &x);
    CHECKF(r, "%s %s NULL: result without flag", kind_field[kind], null_dll ? "dll" : "function");
    for (int k = 0; k < 8; k++) {
        int reg = wcfg_prov_registered(k, &g, NULL, NULL);
        if (k == kind) CHECKF(!reg, "%s not registered", kind_field[k]);
        else CHECKF(reg, "%s registered", kind_field[k]);
    }
    wcfg_remove_action_raw(&g);
    SET_ERR(0);
    r = wcfg_add(&g, WT_ADD_ACTION_ID_RET_RESULT_FLAG, &x);
    CHECKF(!r, "%s %s NULL: result with flag", kind_field[kind], null_dll ? "dll" : "function");
    EXPECT_ERR(E_INVAL);
    wcfg_remove_action_raw(&g);
}
#define NULLF_TEST(K) \
    TEST(wcfg_action_add_null_dll_##K) { SETUP(WintrustAddActionID); null_field_case(K, 1, 10 + K); wcfg_end(); } \
    TEST(wcfg_action_add_null_func_##K) { SETUP(WintrustAddActionID); null_field_case(K, 0, 20 + K); wcfg_end(); }
NULLF_TEST(0) NULLF_TEST(1) NULLF_TEST(2) NULLF_TEST(3) NULLF_TEST(4) NULLF_TEST(5) NULLF_TEST(6) NULLF_TEST(7)

TEST(wcfg_action_add_flag_bits_other_than_one_ignored) {
    SETUPW(WintrustAddActionID); GUID g; wcfg_guid(&g, 30); wcfg_reg_t x; wcfg_fill_reg(&x);
    CHECK(wcfg_add(&g, 2, &x));
    wcfg_remove_action_raw(&g);
    x.r.sObjectProvider.pwszDLLName = NULL;
    CHECK(wcfg_add(&g, 0xFFFFFFFE, &x));          /* bit 0 clear: failure swallowed */
    wcfg_remove_action_raw(&g);
    CHECK(!wcfg_add(&g, 0xFFFFFFFF, &x));         /* bit 0 set */
    wcfg_end();
}
TEST(wcfg_action_add_cleanup_failure_reported_only_with_flag) {
    SETUP(WintrustAddActionID); GUID g; wcfg_guid(&g, 31); wcfg_reg_t x; wcfg_fill_reg(&x);
    x.r.sCleanupProvider.pwszDLLName = NULL;
    SET_ERR(0); CHECK(wcfg_add(&g, 0, &x));
    wcfg_remove_action_raw(&g);
    SET_ERR(0); CHECK(!wcfg_add(&g, 1, &x)); EXPECT_ERR(E_INVAL);
    wcfg_end();
}
TEST(wcfg_action_add_all_null_providers_returns_true_without_flag) {
    SETUP(WintrustAddActionID); GUID g; wcfg_guid(&g, 32); wcfg_reg_t x; memset(&x, 0, sizeof x);
    x.r.cbStruct = WCFG_REG_SIZE_FULL;
    CHECK(wcfg_add(&g, 0, &x));
    for (int k = 0; k < 8; k++) CHECK(!wcfg_prov_registered(k, &g, NULL, NULL));
    SET_ERR(0); CHECK(!wcfg_add(&g, 1, &x)); EXPECT_ERR(E_INVAL);
    wcfg_end();
}
TEST(wcfg_action_add_empty_strings_are_stored) {
    SETUP(WintrustAddActionID); GUID g; wcfg_guid(&g, 33); wcfg_reg_t x; wcfg_fill_reg(&x);
    x.r.sInitProvider.pwszDLLName = L""; x.r.sInitProvider.pwszFunctionName = L"";
    CHECK(wcfg_add(&g, 1, &x));
    wchar_t d[300] = L"x", f[300] = L"x";
    CHECK(wcfg_prov_registered(0, &g, d, f)); CHECK(!d[0]); CHECK(!f[0]);
    wchar_t gs[48], p[300]; wcfg_guid_str(&g, gs); swprintf(p, 300, L"" WCFG_TRUST L"\\Initialization\\%ls", gs);
    DWORD t, cb; wchar_t b[10];
    EXPECT_EQ(wcfg_get_str(p, L"$DLL", b, 10, &t, &cb), 0); EXPECT_EQ(t, REG_SZ); EXPECT_EQ(cb, 2);
    wcfg_end();
}
TEST(wcfg_action_add_overwrites_existing_values) {
    SETUP(WintrustAddActionID); GUID g; wcfg_guid(&g, 34); wcfg_reg_t x; wcfg_fill_reg(&x);
    x.r.sFinalPolicyProvider.pwszFunctionName = L"first";
    CHECK(wcfg_add(&g, 1, &x));
    x.r.sFinalPolicyProvider.pwszFunctionName = L"second_longer_name";
    CHECK(wcfg_add(&g, 1, &x));
    wchar_t f[300]; CHECK(wcfg_prov_registered(5, &g, NULL, f)); CHECK(!wcscmp(f, L"second_longer_name"));
    x.r.sFinalPolicyProvider.pwszFunctionName = L"s";
    CHECK(wcfg_add(&g, 1, &x));
    CHECK(wcfg_prov_registered(5, &g, NULL, f)); CHECK(!wcscmp(f, L"s"));
    wcfg_end();
}
TEST(wcfg_action_add_two_actions_are_independent) {
    SETUP(WintrustAddActionID); GUID a, b; wcfg_guid(&a, 35); wcfg_guid(&b, 36); wcfg_reg_t x; wcfg_fill_reg(&x);
    x.r.sInitProvider.pwszFunctionName = L"fa";
    CHECK(wcfg_add(&a, 1, &x));
    x.r.sInitProvider.pwszFunctionName = L"fb";
    CHECK(wcfg_add(&b, 1, &x));
    wchar_t f[300];
    CHECK(wcfg_prov_registered(0, &a, NULL, f)); CHECK(!wcscmp(f, L"fa"));
    CHECK(wcfg_prov_registered(0, &b, NULL, f)); CHECK(!wcscmp(f, L"fb"));
    CHECK(U(WintrustRemoveActionID)(&a));
    CHECK(!wcfg_prov_registered(0, &a, NULL, NULL));
    CHECK(wcfg_prov_registered(0, &b, NULL, NULL));
    wcfg_end();
}
TEST(wcfg_action_add_guid_text_form_is_uppercase_braced) {
    SETUP(WintrustAddActionID);
    GUID g = { 0xABCDEF01, 0x23AB, 0xCDEF, { 0x63, 0x72, 0x79, 0x70, 0x74, 0x74, 0xFA, 0x21 } };
    g.Data1 = 0xAB000000u | GetCurrentProcessId();
    wcfg_reg_t x; wcfg_fill_reg(&x);
    CHECK(wcfg_add(&g, 1, &x));
    wchar_t gs[48]; wcfg_guid_str(&g, gs);
    CHECK(wcsstr(gs, L"23AB-CDEF-6372-797074") != NULL);
    CHECK(wcfg_prov_registered(0, &g, NULL, NULL));
    U(WintrustRemoveActionID)(&g);
    CHECK(!wcfg_prov_registered(0, &g, NULL, NULL));
    wcfg_end();
}
TEST(wcfg_action_add_long_dll_name) {
    SETUP(WintrustAddActionID); GUID g; wcfg_guid(&g, 37); wcfg_reg_t x; wcfg_fill_reg(&x);
    static wchar_t big[1200]; for (int i = 0; i < 1100; i++) big[i] = L'a' + (i % 26); big[1100] = 0;
    x.r.sInitProvider.pwszDLLName = big;
    CHECK(wcfg_add(&g, 1, &x));
    static wchar_t back[1300]; DWORD cb;
    wchar_t gs[48], p[300]; wcfg_guid_str(&g, gs); swprintf(p, 300, L"" WCFG_TRUST L"\\Initialization\\%ls", gs);
    EXPECT_EQ(wcfg_get_str(p, L"$DLL", back, 1300, NULL, &cb), 0);
    CHECK(!wcscmp(back, big));
    wcfg_end();
}

/* -------------------------------------------------------------- remove */
TEST(wcfg_action_remove_deletes_all_eight_keys) {
    SETUP(WintrustRemoveActionID); GUID g; wcfg_guid(&g, 40); wcfg_reg_t x; wcfg_fill_reg(&x);
    CHECK(wcfg_add(&g, 1, &x));
    for (int k = 0; k < 8; k++) CHECK(wcfg_prov_registered(k, &g, NULL, NULL));
    CHECK(U(WintrustRemoveActionID)(&g));
    for (int k = 0; k < 8; k++) CHECKF(!wcfg_prov_registered(k, &g, NULL, NULL), "kind %d removed", k);
    wchar_t gs[48], p[300]; wcfg_guid_str(&g, gs);
    for (int k = 0; k < 8; k++) { swprintf(p, 300, L"" WCFG_TRUST L"\\%ls\\%ls", wcfg_kind[k], gs); CHECK(!wcfg_key_exists(p)); }
    wcfg_end();
}
TEST(wcfg_action_remove_keeps_parent_keys) {
    SETUP(WintrustRemoveActionID); GUID g; wcfg_guid(&g, 41); wcfg_reg_t x; wcfg_fill_reg(&x);
    CHECK(wcfg_add(&g, 1, &x)); CHECK(U(WintrustRemoveActionID)(&g));
    wchar_t p[300];
    for (int k = 0; k < 8; k++) { swprintf(p, 300, L"" WCFG_TRUST L"\\%ls", wcfg_kind[k]); CHECKF(wcfg_key_exists(p), "%ls still exists", wcfg_kind[k]); }
    wcfg_end();
}
TEST(wcfg_action_remove_unregistered_still_true) {
    SETUP(WintrustRemoveActionID); GUID g; wcfg_guid(&g, 42);
    SET_ERR(0);
    CHECK(U(WintrustRemoveActionID)(&g) == TRUE);
    CHECK(U(WintrustRemoveActionID)(&g) == TRUE);
    wcfg_end();
}
TEST(wcfg_action_remove_twice) {
    SETUP(WintrustRemoveActionID); GUID g; wcfg_guid(&g, 43); wcfg_reg_t x; wcfg_fill_reg(&x);
    CHECK(wcfg_add(&g, 1, &x));
    CHECK(U(WintrustRemoveActionID)(&g)); CHECK(U(WintrustRemoveActionID)(&g));
    wcfg_end();
}
TEST(wcfg_action_remove_null_guid_returns_true_with_invalid_parameter) {
    SETUP(WintrustRemoveActionID);
    SET_ERR(0); BOOL r = U(WintrustRemoveActionID)(NULL);
    CHECK(r == TRUE); EXPECT_ERR(E_INVAL);
    wcfg_end();
}
TEST(wcfg_action_remove_partial_registration) {
    SETUPW(WintrustRemoveActionID); GUID g; wcfg_guid(&g, 44); wcfg_reg_t x; wcfg_fill_reg(&x);
    x.r.cbStruct = WCFG_REG_SIZE_NOCLEANUP;
    CHECK(wcfg_add(&g, 1, &x));
    CHECK(U(WintrustRemoveActionID)(&g));
    for (int k = 0; k < 8; k++) CHECK(!wcfg_prov_registered(k, &g, NULL, NULL));
    wcfg_end();
}
TEST(wcfg_action_remove_does_not_touch_other_guid_same_slot) {
    SETUP(WintrustRemoveActionID); GUID a, b; wcfg_guid(&a, 45); wcfg_guid(&b, 46); wcfg_reg_t x; wcfg_fill_reg(&x);
    CHECK(wcfg_add(&a, 1, &x)); CHECK(wcfg_add(&b, 1, &x));
    CHECK(U(WintrustRemoveActionID)(&b));
    for (int k = 0; k < 8; k++) CHECK(wcfg_prov_registered(k, &a, NULL, NULL));
    wcfg_end();
}
TEST(wcfg_action_remove_ignores_extra_values_and_subkeys_failure) {
    /* RegDeleteKeyEx fails on keys that have subkeys; Remove still returns TRUE and leaves them */
    SETUP(WintrustRemoveActionID); GUID g; wcfg_guid(&g, 47); wcfg_reg_t x; wcfg_fill_reg(&x);
    CHECK(wcfg_add(&g, 1, &x));
    wchar_t gs[48], p[400]; wcfg_guid_str(&g, gs);
    swprintf(p, 400, L"" WCFG_TRUST L"\\Initialization\\%ls\\child", gs);
    HKEY k; DWORD d;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, p, 0, NULL, 0, KEY_WRITE, NULL, &k, &d) == 0) {
        RegCloseKey(k);
        CHECK(U(WintrustRemoveActionID)(&g) == TRUE);
        swprintf(p, 400, L"" WCFG_TRUST L"\\Initialization\\%ls", gs);
        CHECK(wcfg_key_exists(p));
        CHECK(!wcfg_prov_registered(1, &g, NULL, NULL));
        swprintf(p, 400, L"" WCFG_TRUST L"\\Initialization\\%ls\\child", gs);
        RegDeleteKeyExW(HKEY_LOCAL_MACHINE, p, 0, 0);
        swprintf(p, 400, L"" WCFG_TRUST L"\\Initialization\\%ls", gs);
        RegDeleteKeyExW(HKEY_LOCAL_MACHINE, p, 0, 0);
    } else t_note("could not create child key");
    wcfg_end();
}

/* -------------------------------------------------------------- WintrustLoadFunctionPointers */
static int pfn_ok(CRYPT_PROVIDER_FUNCTIONS *p) { return p->pfnInitialize != NULL; }

TEST(wcfg_action_loadfp_returns_registered_functions) {
    SETUPW(WintrustLoadFunctionPointers); GUID g; wcfg_guid(&g, 50); wcfg_reg_t x; wcfg_fill_reg(&x);
    CHECK(wcfg_add(&g, 1, &x));
    CRYPT_PROVIDER_FUNCTIONS f; memset(&f, 0, sizeof f); f.cbStruct = sizeof f;
    CHECK(sizeof f == 0x80);
    BOOL r = U(WintrustLoadFunctionPointers)(&g, &f);
    CHECK(r);
    HMODULE h = LoadLibraryW(x.dll);
    CHECK(f.pfnInitialize == (void *)GetProcAddress(h, "cryptt_Init"));
    CHECK(f.pfnObjectTrust == (void *)GetProcAddress(h, "cryptt_Object"));
    CHECK(f.pfnSignatureTrust == (void *)GetProcAddress(h, "cryptt_Sig"));
    CHECK(f.pfnCertificateTrust == (void *)GetProcAddress(h, "cryptt_Cert"));
    CHECK(f.pfnCertCheckPolicy == (void *)GetProcAddress(h, "cryptt_CertCheck"));
    CHECK(f.pfnFinalPolicy == (void *)GetProcAddress(h, "cryptt_Final"));
    CHECK(f.pfnTestFinalPolicy == (void *)GetProcAddress(h, "cryptt_Test"));
    CHECK(f.pfnCleanupPolicy == (void *)GetProcAddress(h, "cryptt_Cleanup"));
    CHECK(f.pfnAlloc && f.pfnFree && f.pfnAddStore2Chain && f.pfnAddSgnr2Chain && f.pfnAddCert2Chain && f.pfnAddPrivData2Chain);
    CHECK(f.cbStruct == 0x80);
    if (h) FreeLibrary(h);
    wcfg_end();
}
TEST(wcfg_action_loadfp_small_cbstruct_leaves_cleanup_untouched) {
    SETUPW(WintrustLoadFunctionPointers); GUID g; wcfg_guid(&g, 51); wcfg_reg_t x; wcfg_fill_reg(&x);
    CHECK(wcfg_add(&g, 1, &x));
    CRYPT_PROVIDER_FUNCTIONS f; memset(&f, 0, sizeof f); f.cbStruct = 0x78;
    CHECK(U(WintrustLoadFunctionPointers)(&g, &f));
    CHECK(f.pfnInitialize != NULL);
    CHECK(f.pfnCleanupPolicy == NULL);
    wcfg_end();
}
TEST(wcfg_action_loadfp_cbstruct_below_78_fails) {
    SETUPW(WintrustLoadFunctionPointers); GUID g; wcfg_guid(&g, 52); wcfg_reg_t x; wcfg_fill_reg(&x);
    CHECK(wcfg_add(&g, 1, &x));
    CRYPT_PROVIDER_FUNCTIONS f; memset(&f, 0, sizeof f);
    f.cbStruct = 0x77; CHECK(!U(WintrustLoadFunctionPointers)(&g, &f)); CHECK(f.pfnInitialize == NULL);
    f.cbStruct = 0; CHECK(!U(WintrustLoadFunctionPointers)(&g, &f));
    CHECK(!U(WintrustLoadFunctionPointers)(&g, NULL));
    wcfg_end();
}
TEST(wcfg_action_loadfp_unregistered_fails) {
    SETUPW(WintrustLoadFunctionPointers); GUID g; wcfg_guid(&g, 53);
    CRYPT_PROVIDER_FUNCTIONS f; memset(&f, 0, sizeof f); f.cbStruct = sizeof f;
    CHECK(!U(WintrustLoadFunctionPointers)(&g, &f));
    CHECK(f.pfnInitialize == NULL && f.pfnAlloc == NULL);
    wcfg_end();
}
/* Initialization, Certificate and FinalPolicy are the mandatory providers */
static void mandatory_case(int kind, unsigned slot, int expect) {
    GUID g; wcfg_guid(&g, slot); wcfg_reg_t x; wcfg_fill_reg(&x);
    CRYPT_TRUST_REG_ENTRY *e = entry(&x, kind); e->pwszDLLName = NULL; e->pwszFunctionName = NULL;
    CHECK(wcfg_add(&g, 0, &x));
    CRYPT_PROVIDER_FUNCTIONS f; memset(&f, 0, sizeof f); f.cbStruct = sizeof f;
    BOOL r = U(WintrustLoadFunctionPointers)(&g, &f);
    CHECKF((r != 0) == expect, "%s missing: loadfp=%d want %d", kind_field[kind], r, expect);
    if (expect) {
        void *p[8] = { f.pfnInitialize, f.pfnObjectTrust, f.pfnSignatureTrust, f.pfnCertificateTrust, f.pfnCertCheckPolicy, f.pfnFinalPolicy, f.pfnTestFinalPolicy, f.pfnCleanupPolicy };
        CHECKF(p[kind] == NULL, "%s pointer is NULL", kind_field[kind]);
        for (int k = 0; k < 8; k++) if (k != kind) CHECKF(p[k] != NULL, "%s pointer set", kind_field[k]);
    }
    wcfg_remove_action_raw(&g);
}
#define MAND_TEST(K, EXPECT, NAME) TEST(wcfg_action_loadfp_without_##NAME) { SETUPW(WintrustLoadFunctionPointers); mandatory_case(K, 60 + K, EXPECT); wcfg_end(); }
MAND_TEST(0, 0, init)
MAND_TEST(1, 1, object)
MAND_TEST(2, 1, signature)
MAND_TEST(3, 0, certificate)
MAND_TEST(4, 1, certpolicy)
MAND_TEST(5, 0, final)
MAND_TEST(6, 1, test)
MAND_TEST(7, 1, cleanup)

TEST(wcfg_action_loadfp_missing_export_fails_for_mandatory) {
    SETUPW(WintrustLoadFunctionPointers); GUID g; wcfg_guid(&g, 70); wcfg_reg_t x; wcfg_fill_reg(&x);
    x.r.sFinalPolicyProvider.pwszFunctionName = L"cryptt_NoSuchExport";
    CHECK(wcfg_add(&g, 1, &x));
    CRYPT_PROVIDER_FUNCTIONS f; memset(&f, 0, sizeof f); f.cbStruct = sizeof f;
    CHECK(!U(WintrustLoadFunctionPointers)(&g, &f));
    wcfg_end();
}
TEST(wcfg_action_loadfp_missing_dll_fails) {
    SETUPW(WintrustLoadFunctionPointers); GUID g; wcfg_guid(&g, 71); wcfg_reg_t x; wcfg_fill_reg(&x);
    x.r.sInitProvider.pwszDLLName = L"cryptt_no_such_module.dll";
    CHECK(wcfg_add(&g, 1, &x));
    CRYPT_PROVIDER_FUNCTIONS f; memset(&f, 0, sizeof f); f.cbStruct = sizeof f;
    CHECK(!U(WintrustLoadFunctionPointers)(&g, &f));
    wcfg_end();
}
TEST(wcfg_action_loadfp_missing_export_for_optional_provider) {
    SETUPW(WintrustLoadFunctionPointers); GUID g; wcfg_guid(&g, 72); wcfg_reg_t x; wcfg_fill_reg(&x);
    x.r.sObjectProvider.pwszFunctionName = L"cryptt_NoSuchExport";
    CHECK(wcfg_add(&g, 1, &x));
    CRYPT_PROVIDER_FUNCTIONS f; memset(&f, 0, sizeof f); f.cbStruct = sizeof f;
    BOOL r = U(WintrustLoadFunctionPointers)(&g, &f);
    CHECK(r);
    if (r) CHECK(f.pfnObjectTrust == NULL);
    wcfg_end();
}
TEST(wcfg_action_loadfp_wintrust_dll_name_is_special) {
    SETUPW(WintrustLoadFunctionPointers); GUID g; wcfg_guid(&g, 73); wcfg_reg_t x; wcfg_fill_reg(&x);
    static const wchar_t *fn[8] = { L"SoftpubInitialize", L"SoftpubLoadMessage", L"SoftpubLoadSignature", L"WintrustCertificateTrust",
        L"SoftpubCheckCert", L"SoftpubAuthenticode", L"SoftpubDumpStructure", L"SoftpubCleanup" };
    for (int k = 0; k < 8; k++) { entry(&x, k)->pwszDLLName = L"wintrust.dll"; entry(&x, k)->pwszFunctionName = (WCHAR *)fn[k]; }
    CHECK(wcfg_add(&g, 1, &x));
    CRYPT_PROVIDER_FUNCTIONS f; memset(&f, 0, sizeof f); f.cbStruct = sizeof f;
    BOOL r = U(WintrustLoadFunctionPointers)(&g, &f);
    CHECK(r);
    HMODULE h = GetModuleHandleW(L"wintrust.dll");
    CHECK(h != NULL);
    if (h && r) {
        CHECK(f.pfnInitialize == (void *)GetProcAddress(h, "SoftpubInitialize"));
        CHECK(f.pfnObjectTrust == (void *)GetProcAddress(h, "SoftpubLoadMessage"));
        CHECK(f.pfnSignatureTrust == (void *)GetProcAddress(h, "SoftpubLoadSignature"));
        CHECK(f.pfnCertificateTrust == (void *)GetProcAddress(h, "WintrustCertificateTrust"));
        CHECK(f.pfnCertCheckPolicy == (void *)GetProcAddress(h, "SoftpubCheckCert"));
        CHECK(f.pfnFinalPolicy == (void *)GetProcAddress(h, "SoftpubAuthenticode"));
        CHECK(f.pfnTestFinalPolicy == (void *)GetProcAddress(h, "SoftpubDumpStructure"));
        CHECK(f.pfnCleanupPolicy == (void *)GetProcAddress(h, "SoftpubCleanup"));
    }
    wcfg_end();
}
TEST(wcfg_action_loadfp_provider_cached_per_process) {
    /* the loaded provider table is searched before the registry: removing the registration does not
     * unload an already resolved provider, and re-registering other functions is not picked up */
    SETUPW(WintrustLoadFunctionPointers); GUID g; wcfg_guid(&g, 74); wcfg_reg_t x; wcfg_fill_reg(&x);
    CHECK(wcfg_add(&g, 1, &x));
    CRYPT_PROVIDER_FUNCTIONS f; memset(&f, 0, sizeof f); f.cbStruct = sizeof f;
    CHECK(U(WintrustLoadFunctionPointers)(&g, &f));
    void *final1 = (void *)f.pfnFinalPolicy;
    x.r.sFinalPolicyProvider.pwszFunctionName = L"cryptt_FinalAlt";
    CHECK(wcfg_add(&g, 1, &x));
    memset(&f, 0, sizeof f); f.cbStruct = sizeof f;
    CHECK(U(WintrustLoadFunctionPointers)(&g, &f));
    CHECK(f.pfnFinalPolicy == final1);
    CHECK(U(WintrustRemoveActionID)(&g));
    memset(&f, 0, sizeof f); f.cbStruct = sizeof f;
    BOOL r = U(WintrustLoadFunctionPointers)(&g, &f);
    CHECK(r);
    if (r) CHECK(f.pfnFinalPolicy == final1);
    wcfg_end();
}
TEST(wcfg_action_loadfp_failed_load_is_not_cached) {
    SETUPW(WintrustLoadFunctionPointers); GUID g; wcfg_guid(&g, 75); wcfg_reg_t x; wcfg_fill_reg(&x);
    x.r.sInitProvider.pwszFunctionName = L"cryptt_NoSuchExport";
    CHECK(wcfg_add(&g, 1, &x));
    CRYPT_PROVIDER_FUNCTIONS f; memset(&f, 0, sizeof f); f.cbStruct = sizeof f;
    CHECK(!U(WintrustLoadFunctionPointers)(&g, &f));
    x.r.sInitProvider.pwszFunctionName = L"cryptt_Init";
    CHECK(wcfg_add(&g, 1, &x));
    memset(&f, 0, sizeof f); f.cbStruct = sizeof f;
    CHECK(U(WintrustLoadFunctionPointers)(&g, &f));
    wcfg_end();
}
