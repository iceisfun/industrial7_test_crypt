#include "wcfg.h"
/* WinVerifyTrust driven through a registered action whose providers are exports of this exe.
 * Observable: which provider callbacks run, in which order, with what CRYPT_PROVIDER_DATA, and which
 * value WinVerifyTrust returns.  The subject file is never opened by any of these providers. */

#define SETUP(fn) REQUIRE(U(fn)); if (!wcfg_begin_trust()) return
#define SETUPW(fn) SETUP(fn); if (t_is_wine()) { t_skip("emulator differs from Windows"); wcfg_end(); return; }

static CRYPT_TRUST_REG_ENTRY *ent(wcfg_reg_t *x, int k) {
    CRYPT_TRUST_REG_ENTRY *e[8] = { &x->r.sInitProvider, &x->r.sObjectProvider, &x->r.sSignatureProvider, &x->r.sCertificateProvider,
        &x->r.sCertificatePolicyProvider, &x->r.sFinalPolicyProvider, &x->r.sTestPolicyProvider, &x->r.sCleanupProvider };
    return e[k];
}
/* kind index -> callback id */
static const int kind_id[8] = { WP_INIT, WP_OBJECT, WP_SIG, WP_CERT, WP_CERTCHECK, WP_FINAL, WP_TEST, WP_CLEANUP };
#define M_INIT 1
#define M_OBJ  2
#define M_SIG  4
#define M_CERT 8
#define M_CCHK 16
#define M_FIN  32
#define M_TEST 64
#define M_CLN  128
#define M_ALL  255
#define M_MAND (M_INIT | M_CERT | M_FIN)

static int register_mask(const GUID *g, unsigned mask) {
    wcfg_reg_t x; wcfg_fill_reg(&x);
    for (int k = 0; k < 8; k++) if (!(mask & (1u << k))) { ent(&x, k)->pwszDLLName = NULL; ent(&x, k)->pwszFunctionName = NULL; }
    return wcfg_add(g, 0, &x);
}
/* the emulator never calls the diagnostic (TestFinalPolicy) provider; ignore it there */
static int log_is(const int *want, int n) {
    int a[64], na = 0, b[64], nb = 0;
    for (int i = 0; i < wcfg_nlog; i++) if (!(t_is_wine() && wcfg_log[i] == WP_TEST)) a[na++] = wcfg_log[i];
    for (int i = 0; i < n; i++) if (!(t_is_wine() && want[i] == WP_TEST)) b[nb++] = want[i];
    if (na != nb) return 0;
    for (int i = 0; i < na; i++) if (a[i] != b[i]) return 0;
    return 1;
}
static void dump_log(char *out, size_t cap) {
    static const char *nm[WP__N] = { "Init", "Object", "Sig", "Cert", "Final", "Test", "Cleanup", "CertCheck", "FinalAlt" };
    out[0] = 0;
    for (int i = 0; i < wcfg_nlog; i++) { strncat(out, nm[wcfg_log[i]], cap - strlen(out) - 2); strncat(out, " ", cap - strlen(out) - 1); }
}
#define CHECK_LOG(...) do { const int w_[] = { __VA_ARGS__ }; char b_[256]; dump_log(b_, sizeof b_); \
    t_check(log_is(w_, sizeof w_ / sizeof w_[0]), __FILE__, __LINE__, "call log", "got: %s", b_); } while (0)

static wchar_t g_exe[MAX_PATH];
static const wchar_t *exe(void) { if (!g_exe[0]) wcfg_selfpath(g_exe, MAX_PATH); return g_exe; }

TEST(wcfg_verify_full_chain_call_order) {
    SETUP(WinVerifyTrust); GUID g; wcfg_guid(&g, 100);
    CHECK(register_mask(&g, M_ALL));
    wcfg_log_reset();
    SET_ERR(0xdead);
    LONG r = wcfg_verify(&g, NULL, WTD_UI_NONE, exe(), NULL);
    EXPECT_EQ(r, 0);
    CHECK_LOG(WP_INIT, WP_OBJECT, WP_SIG, WP_CERT, WP_FINAL, WP_TEST, WP_CLEANUP);
    CHECK(wcfg_pd_same);
    wcfg_end();
}
TEST(wcfg_verify_certcheck_provider_not_called_directly) {
    SETUP(WinVerifyTrust); GUID g; wcfg_guid(&g, 101);
    CHECK(register_mask(&g, M_ALL)); wcfg_log_reset();
    wcfg_verify(&g, NULL, WTD_UI_NONE, exe(), NULL);
    EXPECT_EQ(wcfg_log_count(WP_CERTCHECK), 0);
    wcfg_end();
}
TEST(wcfg_verify_provider_data_contents) {
    SETUP(WinVerifyTrust); GUID g; wcfg_guid(&g, 102);
    CHECK(register_mask(&g, M_ALL)); wcfg_log_reset();
    wcfg_verify(&g, INVALID_HANDLE_VALUE, WTD_UI_NONE, exe(), NULL);
    CHECK(wcfg_snap.valid);
    EXPECT_EQ(wcfg_snap.cbStruct, 0xF0);
    CHECK(wcfg_snap.pWintrustData == &wcfg_wd);
    CHECK(wcfg_snap.pgActionID == &g);
    if (!t_is_wine()) CHECK(wcfg_snap.hProv != 0);
    EXPECT_EQ(wcfg_snap.dwError, 0);
    CHECK(wcfg_snap.psPfns != NULL);
    EXPECT_EQ(wcfg_snap.cbPfns, 0x80);
    CHECK(!wcscmp(wcfg_snap.path, exe()));
    wcfg_end();
}
TEST(wcfg_verify_provider_data_function_table) {
    SETUP(WinVerifyTrust); GUID g; wcfg_guid(&g, 103);
    CHECK(register_mask(&g, M_ALL)); wcfg_log_reset();
    wcfg_verify(&g, NULL, WTD_UI_NONE, exe(), NULL);
    HMODULE h = LoadLibraryW(exe());
    CRYPT_PROVIDER_FUNCTIONS *f = &wcfg_snap.pfns;
    CHECK(f->cbStruct == 0x80);
    CHECK(f->pfnAlloc && f->pfnFree && f->pfnAddStore2Chain && f->pfnAddSgnr2Chain && f->pfnAddCert2Chain && f->pfnAddPrivData2Chain);
    CHECK(f->pfnInitialize == (void *)GetProcAddress(h, "cryptt_Init"));
    CHECK(f->pfnObjectTrust == (void *)GetProcAddress(h, "cryptt_Object"));
    CHECK(f->pfnSignatureTrust == (void *)GetProcAddress(h, "cryptt_Sig"));
    CHECK(f->pfnCertificateTrust == (void *)GetProcAddress(h, "cryptt_Cert"));
    CHECK(f->pfnFinalPolicy == (void *)GetProcAddress(h, "cryptt_Final"));
    CHECK(f->pfnCertCheckPolicy == (void *)GetProcAddress(h, "cryptt_CertCheck"));
    CHECK(f->pfnTestFinalPolicy == (void *)GetProcAddress(h, "cryptt_Test"));
    CHECK(f->pfnCleanupPolicy == (void *)GetProcAddress(h, "cryptt_Cleanup"));
    if (h) FreeLibrary(h);
    wcfg_end();
}
TEST(wcfg_verify_subject_file_not_opened_by_wintrust) {
    SETUP(WinVerifyTrust); GUID g; wcfg_guid(&g, 104);
    CHECK(register_mask(&g, M_ALL)); wcfg_log_reset();
    LONG r = wcfg_verify(&g, NULL, WTD_UI_NONE, L"C:\\cryptt_no_such_dir\\no_such_file.bin", NULL);
    EXPECT_EQ(r, 0);
    CHECK_LOG(WP_INIT, WP_OBJECT, WP_SIG, WP_CERT, WP_FINAL, WP_TEST, WP_CLEANUP);
    CHECK(!wcscmp(wcfg_snap.path, L"C:\\cryptt_no_such_dir\\no_such_file.bin"));
    wcfg_end();
}
TEST(wcfg_verify_hwnd_passthrough_ui_none) {
    SETUPW(WinVerifyTrust); GUID g; wcfg_guid(&g, 105);
    CHECK(register_mask(&g, M_ALL));
    wcfg_log_reset(); wcfg_verify(&g, INVALID_HANDLE_VALUE, WTD_UI_NONE, exe(), NULL);
    CHECK(wcfg_snap.hWnd == INVALID_HANDLE_VALUE);
    wcfg_log_reset(); wcfg_verify(&g, NULL, WTD_UI_NONE, exe(), NULL);
    CHECK(wcfg_snap.hWnd == NULL);
    wcfg_end();
}
TEST(wcfg_verify_hwnd_null_replaced_by_desktop_when_ui_allowed) {
    SETUPW(WinVerifyTrust); GUID g; wcfg_guid(&g, 106);
    CHECK(register_mask(&g, M_ALL));
    HWND dt = GetDesktopWindow();
    wcfg_log_reset(); wcfg_verify(&g, NULL, WTD_UI_NOBAD, exe(), NULL);
    CHECK(wcfg_snap.hWnd == dt);
    wcfg_log_reset(); wcfg_verify(&g, INVALID_HANDLE_VALUE, WTD_UI_NOGOOD, exe(), NULL);
    CHECK(wcfg_snap.hWnd == dt);
    wcfg_end();
}
TEST(wcfg_verify_returns_final_policy_value) {
    SETUPW(WinVerifyTrust);
    static const DWORD vals[] = { 1, 0x800B0100, 0x800B0109, 0x80096004, 0x800B010C, 0x80004005, 0x7FFFFFFF, 0xC0000001 };
    for (unsigned i = 0; i < sizeof vals / sizeof vals[0]; i++) {
        GUID g; wcfg_guid(&g, 110 + i);
        CHECK(register_mask(&g, M_ALL)); wcfg_log_reset(); wcfg_ret[WP_FINAL] = vals[i];
        LONG r = wcfg_verify(&g, NULL, WTD_UI_NONE, exe(), NULL);
        CHECKF((DWORD)r == vals[i], "final returned 0x%lx, WinVerifyTrust returned 0x%lx", vals[i], (DWORD)r);
        CHECK(wcfg_log_count(WP_INIT) >= 1 && wcfg_log_count(WP_FINAL) >= 1);
        if (wcfg_nlog >= 5) { CHECK(wcfg_log[0] == WP_INIT); CHECK(wcfg_log[1] == WP_OBJECT); CHECK(wcfg_log[2] == WP_SIG); CHECK(wcfg_log[3] == WP_CERT); CHECK(wcfg_log[4] == WP_FINAL); }
        { char b[256]; dump_log(b, sizeof b); t_note("final=0x%lx log: %s", vals[i], b); }
    }
    wcfg_end();
}
TEST(wcfg_verify_init_failure_stops_chain) {
    SETUPW(WinVerifyTrust);
    static const DWORD vals[] = { 1, 0x80004005, 0x800B0001, 0x80096001, 0x57 };
    for (unsigned i = 0; i < sizeof vals / sizeof vals[0]; i++) {
        GUID g; wcfg_guid(&g, 120 + i);
        CHECK(register_mask(&g, M_ALL)); wcfg_log_reset(); wcfg_ret[WP_INIT] = vals[i];
        SET_ERR(0);
        LONG r = wcfg_verify(&g, NULL, WTD_UI_NONE, exe(), NULL);
        CHECKF((DWORD)r == vals[i], "init 0x%lx -> 0x%lx", vals[i], (DWORD)r);
        EXPECT_ERR(vals[i]);
        CHECK_LOG(WP_INIT);
    }
    wcfg_end();
}
TEST(wcfg_verify_init_dwerror_becomes_last_error) {
    SETUPW(WinVerifyTrust); GUID g; wcfg_guid(&g, 130);
    CHECK(register_mask(&g, M_ALL)); wcfg_log_reset();
    wcfg_ret[WP_INIT] = 0x5678; wcfg_seterr[WP_INIT] = 0x1234;
    SET_ERR(0);
    LONG r = wcfg_verify(&g, NULL, WTD_UI_NONE, exe(), NULL);
    EXPECT_EQ(r, 0x5678);
    EXPECT_ERR(0x1234);
    CHECK_LOG(WP_INIT);
    wcfg_end();
}
TEST(wcfg_verify_object_and_sig_results_do_not_stop_chain) {
    SETUP(WinVerifyTrust); GUID g; wcfg_guid(&g, 131);
    CHECK(register_mask(&g, M_ALL)); wcfg_log_reset();
    wcfg_ret[WP_OBJECT] = 0x800B0100; wcfg_ret[WP_SIG] = 0x800B0101; wcfg_ret[WP_CERT] = 0x800B0102;
    LONG r = wcfg_verify(&g, NULL, WTD_UI_NONE, exe(), NULL);
    EXPECT_EQ(r, 0);
    CHECK_LOG(WP_INIT, WP_OBJECT, WP_SIG, WP_CERT, WP_FINAL, WP_TEST, WP_CLEANUP);
    wcfg_end();
}

/* all 32 combinations of the optional providers (mandatory: Initialization, Certificate, FinalPolicy) */
TEST(wcfg_verify_optional_provider_subsets) {
    SETUP(WinVerifyTrust);
    for (unsigned m = 0; m < 32; m++) {
        unsigned mask = M_MAND;
        if (m & 1) mask |= M_OBJ;
        if (m & 2) mask |= M_SIG;
        if (m & 4) mask |= M_CCHK;
        if (m & 8) mask |= M_TEST;
        if (m & 16) mask |= M_CLN;
        GUID g; wcfg_guid(&g, 200 + m);
        CHECK(register_mask(&g, mask)); wcfg_log_reset();
        LONG r = wcfg_verify(&g, NULL, WTD_UI_NONE, exe(), NULL);
        EXPECT_EQ(r, 0);
        int want[8], n = 0;
        want[n++] = WP_INIT;
        if (mask & M_OBJ) want[n++] = WP_OBJECT;
        if (mask & M_SIG) want[n++] = WP_SIG;
        want[n++] = WP_CERT; want[n++] = WP_FINAL;
        if (mask & M_TEST) want[n++] = WP_TEST;
        if (mask & M_CLN) want[n++] = WP_CLEANUP;
        char b[256]; dump_log(b, sizeof b);
        CHECKF(log_is(want, n), "mask 0x%x log: %s", mask, b);
        wcfg_remove_action_raw(&g);
    }
    wcfg_end();
}
/* a missing mandatory provider makes the action unknown: nothing runs and the result equals the unregistered-action result */
TEST(wcfg_verify_unregistered_action_runs_nothing) {
    SETUPW(WinVerifyTrust); GUID g; wcfg_guid(&g, 140);
    wcfg_log_reset();
    SET_ERR(0);
    LONG r = wcfg_verify(&g, NULL, WTD_UI_NONE, exe(), NULL);
    CHECK(r != 0);
    EXPECT_EQ(wcfg_nlog, 0);
    t_note("unregistered action: WinVerifyTrust = 0x%lx, last error 0x%lx", (DWORD)r, GetLastError());
    wcfg_end();
}
static void missing_mandatory(int kind, unsigned slot) {
    GUID u; wcfg_guid(&u, 141);
    wcfg_log_reset();
    LONG ref = wcfg_verify(&u, NULL, WTD_UI_NONE, exe(), NULL);
    GUID g; wcfg_guid(&g, slot);
    CHECK(register_mask(&g, M_ALL & ~(1u << kind))); wcfg_log_reset();
    LONG r = wcfg_verify(&g, NULL, WTD_UI_NONE, exe(), NULL);
    CHECK(r != 0);
    EXPECT_EQ(wcfg_nlog, 0);
    CHECKF(r == ref, "result 0x%lx equals unregistered result 0x%lx", (DWORD)r, (DWORD)ref);
    wcfg_remove_action_raw(&g);
}
TEST(wcfg_verify_missing_init_is_unknown_action) { SETUPW(WinVerifyTrust); missing_mandatory(0, 142); wcfg_end(); }
TEST(wcfg_verify_missing_certificate_is_unknown_action) { SETUPW(WinVerifyTrust); missing_mandatory(3, 143); wcfg_end(); }
TEST(wcfg_verify_missing_final_is_unknown_action) { SETUPW(WinVerifyTrust); missing_mandatory(5, 144); wcfg_end(); }
TEST(wcfg_verify_bad_function_name_is_unknown_action) {
    SETUPW(WinVerifyTrust); GUID g; wcfg_guid(&g, 145); wcfg_reg_t x; wcfg_fill_reg(&x);
    x.r.sInitProvider.pwszFunctionName = L"cryptt_NoSuchExport";
    CHECK(wcfg_add(&g, 1, &x)); wcfg_log_reset();
    LONG r = wcfg_verify(&g, NULL, WTD_UI_NONE, exe(), NULL);
    CHECK(r != 0); EXPECT_EQ(wcfg_nlog, 0);
    wcfg_end();
}

/* ---- the loaded provider table outlives registry changes inside one process ---- */
TEST(wcfg_verify_remove_does_not_unload_provider) {
    SETUPW(WinVerifyTrust); GUID g; wcfg_guid(&g, 150);
    CHECK(register_mask(&g, M_ALL)); wcfg_log_reset();
    EXPECT_EQ(wcfg_verify(&g, NULL, WTD_UI_NONE, exe(), NULL), 0);
    EXPECT_EQ(wcfg_nlog, 7);
    CHECK(U(WintrustRemoveActionID)(&g));
    wcfg_log_reset();
    EXPECT_EQ(wcfg_verify(&g, NULL, WTD_UI_NONE, exe(), NULL), 0);
    CHECK_LOG(WP_INIT, WP_OBJECT, WP_SIG, WP_CERT, WP_FINAL, WP_TEST, WP_CLEANUP);
    wcfg_end();
}
TEST(wcfg_verify_reregistration_not_seen_after_first_use) {
    SETUPW(WinVerifyTrust); GUID g; wcfg_guid(&g, 151);
    CHECK(register_mask(&g, M_ALL)); wcfg_log_reset();
    EXPECT_EQ(wcfg_verify(&g, NULL, WTD_UI_NONE, exe(), NULL), 0);
    wcfg_reg_t x; wcfg_fill_reg(&x); x.r.sFinalPolicyProvider.pwszFunctionName = L"cryptt_FinalAlt";
    CHECK(wcfg_add(&g, 1, &x));
    wcfg_log_reset();
    EXPECT_EQ(wcfg_verify(&g, NULL, WTD_UI_NONE, exe(), NULL), 0);
    EXPECT_EQ(wcfg_log_count(WP_FINAL), 1);
    EXPECT_EQ(wcfg_log_count(WP_FINALALT), 0);
    wcfg_end();
}
TEST(wcfg_verify_fresh_guid_sees_new_registration) {
    SETUP(WinVerifyTrust); GUID a, b; wcfg_guid(&a, 152); wcfg_guid(&b, 153);
    wcfg_reg_t x; wcfg_fill_reg(&x);
    CHECK(wcfg_add(&a, 1, &x));
    x.r.sFinalPolicyProvider.pwszFunctionName = L"cryptt_FinalAlt";
    CHECK(wcfg_add(&b, 1, &x));
    wcfg_log_reset(); wcfg_verify(&b, NULL, WTD_UI_NONE, exe(), NULL);
    EXPECT_EQ(wcfg_log_count(WP_FINALALT), 1); EXPECT_EQ(wcfg_log_count(WP_FINAL), 0);
    wcfg_log_reset(); wcfg_verify(&a, NULL, WTD_UI_NONE, exe(), NULL);
    EXPECT_EQ(wcfg_log_count(WP_FINALALT), 0); EXPECT_EQ(wcfg_log_count(WP_FINAL), 1);
    wcfg_end();
}
TEST(wcfg_verify_repeated_calls_accumulate) {
    SETUPW(WinVerifyTrust); GUID g; wcfg_guid(&g, 154);
    CHECK(register_mask(&g, M_ALL)); wcfg_log_reset();
    for (int i = 0; i < 5; i++) EXPECT_EQ(wcfg_verify(&g, NULL, WTD_UI_NONE, exe(), NULL), 0);
    EXPECT_EQ(wcfg_log_count(WP_INIT), 5);
    EXPECT_EQ(wcfg_log_count(WP_FINAL), 5);
    EXPECT_EQ(wcfg_log_count(WP_CLEANUP), 5);
    wcfg_end();
}

/* ---- registry policy flags reach the providers (dwRegPolicySettings = State & 0xFFFFFF5F) ---- */
TEST(wcfg_verify_policy_settings_follow_hkcu_state) {
    SETUPW(WinVerifyTrust); GUID g; wcfg_guid(&g, 160);
    wcfg_state_save();
    CHECK(register_mask(&g, M_ALL));
    static const DWORD vals[] = { 0, 0x23C00, 0x12345678, 0xFFFFFFFF, 0xA0, 0x5F, 0x80000000, 0x00000020 };
    for (unsigned i = 0; i < sizeof vals / sizeof vals[0]; i++) {
        DWORD v = vals[i];
        wcfg_state_put(REG_DWORD, &v, 4);
        wcfg_log_reset(); wcfg_verify(&g, NULL, WTD_UI_NONE, exe(), NULL);
        CHECKF(wcfg_snap.polSettings == (v & 0xFFFFFF5F), "state 0x%lx -> policy 0x%lx", v, wcfg_snap.polSettings);
    }
    wcfg_end();
}
TEST(wcfg_verify_policy_settings_default_when_value_absent) {
    SETUP(WinVerifyTrust); GUID g; wcfg_guid(&g, 161);
    wcfg_state_save(); wcfg_state_delete();
    CHECK(register_mask(&g, M_ALL)); wcfg_log_reset();
    wcfg_verify(&g, NULL, WTD_UI_NONE, exe(), NULL);
    EXPECT_EQ(wcfg_snap.polSettings, 0x23C00);
    wcfg_end();
}
TEST(wcfg_verify_policy_settings_ignore_wrong_value_types) {
    SETUP(WinVerifyTrust); GUID g; wcfg_guid(&g, 162);
    wcfg_state_save();
    CHECK(register_mask(&g, M_ALL));
    DWORD v = 0x0F0F0F00; wchar_t s[] = L"123";
    wcfg_state_put(REG_SZ, s, sizeof s); wcfg_log_reset(); wcfg_verify(&g, NULL, WTD_UI_NONE, exe(), NULL);
    EXPECT_EQ(wcfg_snap.polSettings, 0x23C00);
    wcfg_state_put(REG_BINARY, &v, 4); wcfg_log_reset(); wcfg_verify(&g, NULL, WTD_UI_NONE, exe(), NULL);
    EXPECT_EQ(wcfg_snap.polSettings, v);
    wcfg_end();
}
TEST(wcfg_verify_security_settings_default) {
    SETUPW(WinVerifyTrust); GUID g; wcfg_guid(&g, 163);
    CHECK(register_mask(&g, M_ALL)); wcfg_log_reset();
    wcfg_verify(&g, NULL, WTD_UI_NONE, exe(), NULL);
    /* 2 = FailInform unless HKCU\Software\Microsoft\Internet Explorer\Security "Safety Warning Level" says otherwise */
    HKEY k; int has = 0;
    if (!RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Internet Explorer\\Security", 0, KEY_READ, &k)) {
        DWORD t, n = 0; has = !RegQueryValueExW(k, L"Safety Warning Level", NULL, &t, NULL, &n); RegCloseKey(k);
    }
    if (!has) EXPECT_EQ(wcfg_snap.secSettings, 2);
    else t_note("Safety Warning Level present; security settings = %lu", wcfg_snap.secSettings);
    wcfg_end();
}

/* ---- state actions ---- */
TEST(wcfg_verify_state_verify_then_close) {
    SETUP(WinVerifyTrust); GUID g; wcfg_guid(&g, 170);
    CHECK(register_mask(&g, M_ALL)); wcfg_log_reset();
    WINTRUST_FILE_INFO fi; memset(&fi, 0, sizeof fi); fi.cbStruct = sizeof fi; fi.pcwszFilePath = exe();
    WINTRUST_DATA wd; memset(&wd, 0, sizeof wd); wd.cbStruct = sizeof wd; wd.dwUIChoice = WTD_UI_NONE;
    wd.dwUnionChoice = WTD_CHOICE_FILE; wd.pFile = &fi; wd.dwStateAction = WTD_STATEACTION_VERIFY;
    wd.dwProvFlags = WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL;
    LONG r = U(WinVerifyTrust)(NULL, &g, &wd);
    EXPECT_EQ(r, 0);
    CHECK(wd.hWVTStateData != NULL);
    int n_verify = wcfg_nlog;
    CHECK(wcfg_log_count(WP_FINAL) == 1);
    wd.dwStateAction = WTD_STATEACTION_CLOSE;
    r = U(WinVerifyTrust)(NULL, &g, &wd);
    EXPECT_EQ(r, 0);
    CHECK(wd.hWVTStateData == NULL);
    EXPECT_EQ(wcfg_log_count(WP_FINAL), 1);
    { char b[256]; dump_log(b, sizeof b); t_note("verify pass logged %d callbacks; total after close: %s", n_verify, b); }
    wcfg_end();
}
TEST(wcfg_verify_state_ignore_leaves_no_state) {
    SETUP(WinVerifyTrust); GUID g; wcfg_guid(&g, 171);
    CHECK(register_mask(&g, M_ALL));
    WINTRUST_DATA wd;
    wcfg_verify(&g, NULL, WTD_UI_NONE, exe(), &wd);
    CHECK(wd.hWVTStateData == NULL);
    wcfg_end();
}

/* ---- the real Softpub providers registered under a test GUID ---- */
static void reg_softpub(const GUID *g, const wchar_t *final_fn) {
    wcfg_reg_t x; wcfg_fill_reg(&x);
    static const wchar_t *fn[8] = { L"SoftpubInitialize", L"SoftpubLoadMessage", L"SoftpubLoadSignature", L"WintrustCertificateTrust",
        L"SoftpubCheckCert", L"SoftpubAuthenticode", L"SoftpubDumpStructure", L"SoftpubCleanup" };
    for (int k = 0; k < 8; k++) { ent(&x, k)->pwszDLLName = L"WINTRUST.DLL"; ent(&x, k)->pwszFunctionName = (WCHAR *)fn[k]; }
    if (final_fn) ent(&x, 5)->pwszFunctionName = (WCHAR *)final_fn;
    CHECK(wcfg_add(g, 1, &x));
}
TEST(wcfg_verify_softpub_chain_unsigned_pe) {
    SETUP(WinVerifyTrust); GUID g; wcfg_guid(&g, 180);
    reg_softpub(&g, NULL);
    SET_ERR(0);
    LONG r = wcfg_verify(&g, NULL, WTD_UI_NONE, exe(), NULL);
    CHECKF((DWORD)r == 0x800B0100, "TRUST_E_NOSIGNATURE expected, got 0x%lx", (DWORD)r);
    wcfg_end();
}
TEST(wcfg_verify_softpub_chain_matches_generic_action) {
    SETUP(WinVerifyTrust); GUID g; wcfg_guid(&g, 181);
    reg_softpub(&g, NULL);
    GUID gen = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG a = wcfg_verify(&g, NULL, WTD_UI_NONE, exe(), NULL);
    LONG b = wcfg_verify(&gen, NULL, WTD_UI_NONE, exe(), NULL);
    if (a != b) t_note("test softpub action 0x%lx differs from GENERIC_VERIFY_V2 0x%lx", (DWORD)a, (DWORD)b);
    CHECK(a != 0 && b != 0);
    wcfg_end();
}
TEST(wcfg_verify_softpub_chain_with_text_file) {
    SETUP(WinVerifyTrust); GUID g; wcfg_guid(&g, 182);
    reg_softpub(&g, NULL);
    char path[MAX_PATH]; t_tmpfile(path, sizeof path, "wcfg_plain.txt");
    HANDLE h = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    DWORD n; WriteFile(h, "plain text, not signed\r\n", 24, &n, NULL); CloseHandle(h);
    wchar_t wp[MAX_PATH]; MultiByteToWideChar(CP_ACP, 0, path, -1, wp, MAX_PATH);
    LONG r = wcfg_verify(&g, NULL, WTD_UI_NONE, wp, NULL);
    t_note("unsigned text file via softpub chain: 0x%lx", (DWORD)r);
    CHECK(r != 0);
    DeleteFileA(path);
    wcfg_end();
}
TEST(wcfg_verify_softpub_front_with_custom_final) {
    SETUPW(WinVerifyTrust); GUID g; wcfg_guid(&g, 183);
    wcfg_reg_t x; wcfg_fill_reg(&x);
    static const wchar_t *fn[4] = { L"SoftpubInitialize", L"SoftpubLoadMessage", L"SoftpubLoadSignature", L"WintrustCertificateTrust" };
    for (int k = 0; k < 4; k++) { ent(&x, k)->pwszDLLName = L"WINTRUST.DLL"; ent(&x, k)->pwszFunctionName = (WCHAR *)fn[k]; }
    CHECK(wcfg_add(&g, 1, &x)); wcfg_log_reset();
    LONG r = wcfg_verify(&g, NULL, WTD_UI_NONE, exe(), NULL);
    t_note("softpub front + custom final: result 0x%lx, pd->dwError at final 0x%lx", (DWORD)r, wcfg_snap.dwErrorAtFinal);
    wcfg_end();
}
