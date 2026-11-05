/* cryptext.dll shell handlers (rundll32-style: HRESULT fn(HWND, HINSTANCE, LPCSTR/LPCWSTR cmdline, int)). */
#include "ui.h"

typedef HRESULT (WINAPI *ext_fn)(HWND, HINSTANCE, const void *, int);
static ext_fn ext_get(const char *name) { return (ext_fn)t_proc_in("cryptext.dll", name); }

static void ext_run(UIRES *r, const char *name, const char *path) {
    int wide = name[strlen(name) - 1] == 'W';
    ext_fn f = ext_get(name); WCHAR wp[MAX_PATH];
    if (!f) { r->extra[7] = 1; return; }
    if (path) ui_wide(path, wp, MAX_PATH);
    UI_CALL(r, (DWORD)f(NULL, NULL, !path ? NULL : wide ? (const void *)wp : (const void *)path, 1));
}
static void ext_missing(UIRES *r, const char *name) {
    char p[MAX_PATH]; snprintf(p, sizeof p, "%s\\cryptt_does_not_exist.bin", ui_dir);
    ext_run(r, name, p);
}

/* ---- NULL command line: E_FAIL and no UI -------------------------------------- */
#define EXT_NULL(exp) \
    UICASE(extnull_##exp, UIF_NODLG) { ext_run(r, "CryptExt" #exp, NULL); } \
    TEST(ui_cryptext_null_cmdline_##exp) { if (!ext_get("CryptExt" #exp)) { t_skip("missing export CryptExt" #exp); return; } UIRES r; \
        if (!ui_exec("extnull_" #exp, &r) || r.extra[7]) return; ui_expect_nodialog(&r); ui_chk_ret(r.ret, 0x80004005, "CryptExt" #exp "(NULL)"); }
#define EXT_NULL_PAIR(n) EXT_NULL(n) EXT_NULL(n##W)
EXT_NULL_PAIR(OpenCER) EXT_NULL_PAIR(OpenCRL) EXT_NULL_PAIR(OpenCTL) EXT_NULL_PAIR(OpenCAT)
EXT_NULL_PAIR(OpenPKCS7) EXT_NULL_PAIR(OpenPFX) EXT_NULL_PAIR(OpenSTR)
EXT_NULL_PAIR(AddCER) EXT_NULL_PAIR(AddCRL) EXT_NULL_PAIR(AddCTL) EXT_NULL_PAIR(AddPFX) EXT_NULL_PAIR(AddSPC)
EXT_NULL(OpenP7RW)

/* ---- missing file: error message box, return 0 --------------------------------- */
#define EXT_MISS(exp) \
    UICASE(extmiss_##exp, UIF_MSGBOX) { ext_missing(r, "CryptExt" #exp); } \
    TEST(ui_cryptext_missing_file_##exp) { if (!ext_get("CryptExt" #exp)) { t_skip("missing export CryptExt" #exp); return; } UIRES r; \
        if (!ui_exec("extmiss_" #exp, &r) || r.extra[7]) return; ui_expect_dialog(&r, "CryptExt" #exp); ui_chk_ret(r.ret, 0, __func__); }
#define EXT_MISS_PAIR(n) EXT_MISS(n) EXT_MISS(n##W)
EXT_MISS_PAIR(OpenCER) EXT_MISS_PAIR(OpenCRL) EXT_MISS_PAIR(OpenCTL) EXT_MISS_PAIR(OpenCAT)
EXT_MISS_PAIR(OpenPKCS7) EXT_MISS_PAIR(OpenPFX) EXT_MISS_PAIR(OpenSTR)
EXT_MISS_PAIR(AddCER) EXT_MISS_PAIR(AddCRL) EXT_MISS_PAIR(AddCTL) EXT_MISS_PAIR(AddPFX) EXT_MISS_PAIR(AddSPC)

/* ---- wrong content type: CryptQueryObject fails -> message box ------------------- */
static void ext_wrong(UIRES *r, const char *name, const char *leaf, const void *data, DWORD len) {
    char p[MAX_PATH]; ui_write_file(leaf, data, len, p, sizeof p); ext_run(r, name, p);
}
UICASE(extwrong_cer_given_crl, UIF_MSGBOX) { ext_wrong(r, "CryptExtOpenCERW", "w1.cer", fx_crl, sizeof fx_crl); }
UICASE(extwrong_crl_given_cer, UIF_MSGBOX) { ext_wrong(r, "CryptExtOpenCRLW", "w2.crl", fx_cert, sizeof fx_cert); }
UICASE(extwrong_ctl_given_cer, UIF_MSGBOX) { ext_wrong(r, "CryptExtOpenCTLW", "w3.stl", fx_cert, sizeof fx_cert); }
UICASE(extwrong_cat_given_ctl, UIF_MSGBOX) { ext_wrong(r, "CryptExtOpenCATW", "w4.cat", fx_ctl, sizeof fx_ctl); }
UICASE(extwrong_cer_given_text, UIF_MSGBOX) { static const char t[] = "this is not a certificate\r\n"; ext_wrong(r, "CryptExtOpenCERW", "w5.cer", t, sizeof t - 1); }
UICASE(extwrong_cer_given_empty, UIF_MSGBOX) { ext_wrong(r, "CryptExtOpenCERW", "w6.cer", "", 0); }
UICASE(extwrong_cer_a_given_crl, UIF_MSGBOX) { ext_wrong(r, "CryptExtOpenCER", "w7.cer", fx_crl, sizeof fx_crl); }
UICASE(extwrong_addcer_given_crl, UIF_MSGBOX) { ext_wrong(r, "CryptExtAddCERW", "w8.cer", fx_crl, sizeof fx_crl); }
UICASE(extwrong_addpfx_given_cer, UIF_MSGBOX) { ext_wrong(r, "CryptExtAddPFXW", "w9.pfx", fx_cert, sizeof fx_cert); }
#define EXT_WRONG(nm) TEST(ui_cryptext_wrong_content_##nm) { if (!ext_get("CryptExtOpenCERW")) { t_skip("missing export"); return; } UIRES r; \
    if (!ui_exec("extwrong_" #nm, &r) || r.extra[7]) return; ui_expect_dialog(&r, #nm); ui_chk_ret(r.ret, 0, __func__); }
EXT_WRONG(cer_given_crl) EXT_WRONG(crl_given_cer) EXT_WRONG(ctl_given_cer) EXT_WRONG(cat_given_ctl)
EXT_WRONG(cer_given_text) EXT_WRONG(cer_given_empty) EXT_WRONG(cer_a_given_crl) EXT_WRONG(addcer_given_crl) EXT_WRONG(addpfx_given_cer)

/* ---- valid files: viewers and import wizards ------------------------------------- */
static void ext_valid(UIRES *r, const char *name, const char *leaf, const void *data, DWORD len) {
    char p[MAX_PATH]; ui_write_file(leaf, data, len, p, sizeof p); ext_run(r, name, p);
}
UICASE(extok_opencerw, 0) { ext_valid(r, "CryptExtOpenCERW", "v1.cer", fx_cert, sizeof fx_cert); }
UICASE(extok_opencer, 0) { ext_valid(r, "CryptExtOpenCER", "v2.cer", fx_cert, sizeof fx_cert); }
UICASE(extok_opencrlw, 0) { ext_valid(r, "CryptExtOpenCRLW", "v3.crl", fx_crl, sizeof fx_crl); }
UICASE(extok_opencrl, 0) { ext_valid(r, "CryptExtOpenCRL", "v4.crl", fx_crl, sizeof fx_crl); }
UICASE(extok_openctlw, 0) { ext_valid(r, "CryptExtOpenCTLW", "v5.stl", fx_ctl, sizeof fx_ctl); }
UICASE(extok_openctl, 0) { ext_valid(r, "CryptExtOpenCTL", "v6.stl", fx_ctl, sizeof fx_ctl); }
UICASE(extok_opencerw_p7b, 0) { ext_valid(r, "CryptExtOpenCERW", "v7.p7b", fx_p7b, sizeof fx_p7b); }
UICASE(extok_addcerw, 0) { ext_valid(r, "CryptExtAddCERW", "v8.cer", fx_cert, sizeof fx_cert); }
UICASE(extok_addcer, 0) { ext_valid(r, "CryptExtAddCER", "v9.cer", fx_cert, sizeof fx_cert); }
UICASE(extok_addcrlw, 0) { ext_valid(r, "CryptExtAddCRLW", "v10.crl", fx_crl, sizeof fx_crl); }
UICASE(extok_addctlw, 0) { ext_valid(r, "CryptExtAddCTLW", "v11.stl", fx_ctl, sizeof fx_ctl); }
UICASE(extok_addpfxw, 0) { ext_valid(r, "CryptExtAddPFXW", "v12.pfx", fx_pfx, sizeof fx_pfx); }
UICASE(extok_addspcw, 0) { ext_valid(r, "CryptExtAddSPCW", "v13.p7b", fx_p7b, sizeof fx_p7b); }
#define EXT_OK(nm, exp, viewer) TEST(ui_cryptext_valid_file_##nm) { if (!ext_get(exp)) { t_skip("missing export " exp); return; } UIRES r; \
    if (!ui_exec("extok_" #nm, &r) || r.extra[7]) return; \
    if (viewer) ui_expect_dialog(&r, exp); else ui_expect_window(&r, exp); ui_chk_ret(r.ret, 0, __func__); }
EXT_OK(opencerw, "CryptExtOpenCERW", 1) EXT_OK(opencer, "CryptExtOpenCER", 1)
EXT_OK(opencrlw, "CryptExtOpenCRLW", 1) EXT_OK(opencrl, "CryptExtOpenCRL", 1)
EXT_OK(openctlw, "CryptExtOpenCTLW", 1) EXT_OK(openctl, "CryptExtOpenCTL", 1)
EXT_OK(opencerw_p7b, "CryptExtOpenCERW", 1)
EXT_OK(addcerw, "CryptExtAddCERW", 0) EXT_OK(addcer, "CryptExtAddCER", 0) EXT_OK(addcrlw, "CryptExtAddCRLW", 0)
EXT_OK(addctlw, "CryptExtAddCTLW", 0) EXT_OK(addpfxw, "CryptExtAddPFXW", 0) EXT_OK(addspcw, "CryptExtAddSPCW", 0)

/* ---- A and W parity for the missing-file path ------------------------------------- */
TEST(ui_cryptext_a_w_parity_missing_file_same_title) {
    if (!ext_get("CryptExtOpenCER") || !ext_get("CryptExtOpenCERW")) { t_skip("missing export"); return; }
    UIRES a, w;
    if (!ui_exec("extmiss_OpenCER", &a) || !ui_exec("extmiss_OpenCERW", &w)) return;
    if (!a.saw_dlg || !w.saw_dlg) { t_note("no dialogs to compare"); return; }
    CHECK(!lstrcmpW(a.dlg_title, w.dlg_title));
    EXPECT_EQ(a.ret, w.ret);
}

/* ---- additional exports: P7R, MachineOnlyAndHwnd variants (verified in the Win10 binary) ---------- */
UICASE(extnull_addcer_machine, UIF_NODLG) { ext_run(r, "CryptExtAddCERMachineOnlyAndHwndW", NULL); }
UICASE(extnull_addpfx_machine, UIF_NODLG) { ext_run(r, "CryptExtAddPFXMachineOnlyAndHwndW", NULL); }
UICASE(extargc_addpfx_machine, UIF_NODLG) {
    /* exactly two arguments (file, hwnd) are required; otherwise E_INVALIDARG before any UI */
    static const char *cl[] = { "", "onlyone.pfx", "a.pfx 1 extra" };
    for (int i = 0; i < 3; i++) {
        ext_fn f = ext_get("CryptExtAddPFXMachineOnlyAndHwndW"); WCHAR wp[MAX_PATH];
        if (!f) { r->extra[7] = 1; return; }
        ui_wide(cl[i], wp, MAX_PATH);
        UI_SUB(r, (DWORD)f(NULL, NULL, wp, 1));
    }
}
#define EXT_NULLX(tn, key, exp) TEST(ui_cryptext_null_cmdline_##tn) { if (!ext_get(exp)) { t_skip("missing export " exp); return; } UIRES r; \
    if (!ui_exec(key, &r) || r.extra[7]) return; ui_expect_nodialog(&r); ui_chk_ret(r.ret & 0xFFFFFFFF, 0x80004005, exp "(NULL)"); }
EXT_NULLX(AddCERMachineOnlyAndHwndW, "extnull_addcer_machine", "CryptExtAddCERMachineOnlyAndHwndW")
EXT_NULLX(AddPFXMachineOnlyAndHwndW, "extnull_addpfx_machine", "CryptExtAddPFXMachineOnlyAndHwndW")
TEST(ui_cryptext_addpfx_machine_wrong_argument_count_invalid_arg) {
    if (!ext_get("CryptExtAddPFXMachineOnlyAndHwndW")) { t_skip("missing export"); return; } UIRES r;
    if (!ui_exec("extargc_addpfx_machine", &r) || r.extra[7]) return;
    ui_expect_nodialog(&r); EXPECT_EQ(r.nsub, 3);
    for (DWORD i = 0; i < r.nsub; i++) ui_chk_ret(r.sub_ret[i] & 0xFFFFFFFF, 0x80070057, "AddPFXMachineOnlyAndHwndW argc");
}

/* ---- export presence (GetProcAddress by name) for the whole interactive surface ---------------------- */
static void exp_table(const char *dll, const char *const *names, int n) {
    HMODULE m = LoadLibraryA(dll);
    if (!m) { t_skip("module %s not loadable", dll); return; }
    for (int i = 0; i < n; i++) CHECKF(GetProcAddress(m, names[i]) != NULL || t_is_wine(), "%s!%s missing", dll, names[i]);
    CHECK(GetProcAddress(m, "CryptttNoSuchExport") == NULL);
}
TEST(ui_exports_cryptui_dialog_entry_points) {
    static const char *const n[] = { "CryptUIDlgViewCertificateW", "CryptUIDlgViewCertificateA", "CryptUIDlgSelectCertificateFromStore",
        "CryptUIDlgSelectCertificateW", "CryptUIDlgSelectCertificateA", "CryptUIDlgSelectStoreW", "CryptUIDlgSelectStoreA", "CryptUIDlgCertMgr",
        "CryptUIDlgViewCRLW", "CryptUIDlgViewCRLA", "CryptUIDlgViewCTLW", "CryptUIDlgViewCTLA", "CryptUIDlgViewSignerInfoW",
        "CryptUIDlgViewSignerInfoA", "CryptUIDlgViewContext", "CryptUIStartCertMgr", "CryptUIWizImport", "CryptUIWizExport",
        "CryptUIWizDigitalSign", "CryptUIWizBuildCTL", "CryptUIDlgViewCertificatePropertiesW" };
    exp_table("cryptui.dll", n, (int)(sizeof n / sizeof *n));
}
TEST(ui_exports_cryptdlg_entry_points) {
    static const char *const n[] = { "CertSelectCertificateW", "CertSelectCertificateA", "CertViewPropertiesW", "CertViewPropertiesA",
        "CertConfigureTrustW", "CertConfigureTrustA", "CertTrustFinalPolicy", "CertTrustInit", "CertTrustCleanup", "CertTrustCertPolicy" };
    exp_table("cryptdlg.dll", n, (int)(sizeof n / sizeof *n));
}
TEST(ui_exports_cryptext_handlers) {
    static const char *const n[] = { "CryptExtOpenCER", "CryptExtOpenCERW", "CryptExtOpenCRL", "CryptExtOpenCRLW", "CryptExtOpenCTL",
        "CryptExtOpenCTLW", "CryptExtOpenCAT", "CryptExtOpenCATW", "CryptExtOpenPKCS7", "CryptExtOpenPKCS7W", "CryptExtOpenPFX",
        "CryptExtOpenPFXW", "CryptExtOpenSTR", "CryptExtOpenSTRW", "CryptExtOpenP7R", "CryptExtOpenP7RW", "CryptExtAddCER", "CryptExtAddCERW",
        "CryptExtAddCRL", "CryptExtAddCRLW", "CryptExtAddCTL", "CryptExtAddCTLW", "CryptExtAddPFX", "CryptExtAddPFXW", "CryptExtAddSPC",
        "CryptExtAddSPCW", "CryptExtAddP7R", "CryptExtAddP7RW", "CryptExtAddCERMachineOnlyAndHwndW", "CryptExtAddPFXMachineOnlyAndHwndW" };
    exp_table("cryptext.dll", n, (int)(sizeof n / sizeof *n));
}
