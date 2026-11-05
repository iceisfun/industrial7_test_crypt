/* Selection and manager dialogs: CryptUIDlgSelectCertificate*, SelectStore*, CertMgr, StartCertMgr,
 * cryptdlg CertSelectCertificate / CertViewProperties / CertConfigureTrust / CertTrustFinalPolicy. */
#include "ui.h"

static const WCHAR kTitleW[] = L"cryptt select title";

/* ---- CryptUIDlgSelectCertificateFromStore ---------------------------------- */
UICASE(selfs_null_store, UIF_NODLG) {
    UI_CALL(r, U(CryptUIDlgSelectCertificateFromStore)(NULL, NULL, NULL, NULL, 0, 0, NULL));
    r->extra[0] = 1;
    UI_SUB(r, U(CryptUIDlgSelectCertificateFromStore)(NULL, NULL, kTitleW, kTitleW, 0xFFFFFFFF, 0xFFFFFFFF, NULL));
}
TEST(ui_selectcert_fromstore_null_store_invalid_arg) {
    REQUIRE(U(CryptUIDlgSelectCertificateFromStore)); UIRES r;
    if (!ui_exec("selfs_null_store", &r)) return;
    ui_expect_nodialog(&r);
    EXPECT_EQ(r.ret, 0); ui_chk_err(r.err, E_INVALIDARG_, "FromStore(NULL)");
    ui_expect_all_invalid(&r, "FromStore(NULL, all flags)");
}

UICASE(selfs_cancel, 0) {
    HCERTSTORE s = ui_mem_store(1);
    UI_CALL(r, U(CryptUIDlgSelectCertificateFromStore)(s, NULL, NULL, NULL, 0, 0, NULL));
    if (r->ret) U(CertFreeCertificateContext)((PCCERT_CONTEXT)(ULONG_PTR)r->ret);
    if (s) U(CertCloseStore)(s, 0);
}
UICASE(selfs_title, 0) {
    HCERTSTORE s = ui_mem_store(1);
    UI_CALL(r, U(CryptUIDlgSelectCertificateFromStore)(s, NULL, kTitleW, L"cryptt display string", 0, 0, NULL));
    if (r->ret) U(CertFreeCertificateContext)((PCCERT_CONTEXT)(ULONG_PTR)r->ret);
    if (s) U(CertCloseStore)(s, 0);
}
UICASE(selfs_dontuse_cols, 0) {
    HCERTSTORE s = ui_mem_store(1);
    UI_CALL(r, U(CryptUIDlgSelectCertificateFromStore)(s, NULL, NULL, NULL,
        CRYPTUI_SELECT_ISSUEDTO_COLUMN | CRYPTUI_SELECT_ISSUEDBY_COLUMN | CRYPTUI_SELECT_EXPIRATION_COLUMN, 0, NULL));
    if (r->ret) U(CertFreeCertificateContext)((PCCERT_CONTEXT)(ULONG_PTR)r->ret);
    if (s) U(CertCloseStore)(s, 0);
}
UICASE(selfs_empty_store, 0) {
    HCERTSTORE s = ui_mem_store(0);
    UI_CALL(r, U(CryptUIDlgSelectCertificateFromStore)(s, NULL, NULL, NULL, 0, 0, NULL));
    if (r->ret) U(CertFreeCertificateContext)((PCCERT_CONTEXT)(ULONG_PTR)r->ret);
    if (s) U(CertCloseStore)(s, 0);
}
#define SELFS_TEST(nm, key) TEST(ui_selectcert_fromstore_##nm) { REQUIRE(U(CryptUIDlgSelectCertificateFromStore)); UIRES r; if (!ui_exec(key, &r)) return; \
    ui_expect_window(&r, key); EXPECT_EQ(r.ret, 0); }
SELFS_TEST(close_returns_null, "selfs_cancel")
SELFS_TEST(with_title_close_returns_null, "selfs_title")
SELFS_TEST(dontuse_columns_close_returns_null, "selfs_dontuse_cols")
SELFS_TEST(empty_store_returns_null, "selfs_empty_store")

/* ---- CryptUIDlgSelectCertificateW/A (0x80-byte struct) ------------------------ */
static void selcert_call(UIRES *r, int wide, DWORD size, DWORD cdisp, DWORD flags, const void *title) {
    BYTE s[0x80]; HCERTSTORE st = ui_mem_store(1);
    memset(s, 0, sizeof s);
    put32(s, 0, size); put32(s, 0x10, flags); put64(s, 0x18, title);
    put32(s, 0x48, cdisp); put64(s, 0x50, &st);
    if (wide) UI_CALL(r, UN(CryptUIDlgSelectCertificateW)(s)); else UI_CALL(r, UN(CryptUIDlgSelectCertificateA)(s));
    if (r->ret) U(CertFreeCertificateContext)((PCCERT_CONTEXT)(ULONG_PTR)r->ret);
    if (st) U(CertCloseStore)(st, 0);
}
UICASE(selw_plain, 0) { selcert_call(r, 1, 0x80, 1, 0, NULL); }
UICASE(selw_size78, 0) { selcert_call(r, 1, 0x78, 1, 0, NULL); }
UICASE(selw_title, 0) { selcert_call(r, 1, 0x80, 1, 0, kTitleW); }
UICASE(sela_plain, 0) { selcert_call(r, 0, 0x80, 1, 0, NULL); }
UICASE(selw_badsize, UIF_NODLG) {
    static const DWORD sz[] = { 0, 4, 0x58, 0x77, 0x79, 0x7F, 0x81, 0x88, 0x100 };
    for (int i = 0; i < 9; i++) { BYTE s[0x200]; memset(s, 0, sizeof s); put32(s, 0, sz[i]); UI_SUB(r, UN(CryptUIDlgSelectCertificateW)(s)); }
}
TEST(ui_selectcert_w_wrong_dwsize_rejected) {
    UI_NEED(CryptUIDlgSelectCertificateW); UIRES r;
    if (!ui_exec("selw_badsize", &r)) return;
    ui_expect_nodialog(&r); EXPECT_EQ(r.nsub, 9);
    ui_expect_all_invalid(&r, "SelectCertificateW bad size");
}
TEST(ui_selectcert_w_close_returns_null) {
    UI_NEED(CryptUIDlgSelectCertificateW); UIRES r;
    if (!ui_exec("selw_plain", &r)) return;
    ui_expect_window(&r, "SelectCertificateW"); EXPECT_EQ(r.ret, 0);
}
TEST(ui_selectcert_w_size_0x78_accepted) {
    UI_NEED(CryptUIDlgSelectCertificateW); UIRES r;
    if (!ui_exec("selw_size78", &r)) return;
    ui_expect_window(&r, "SelectCertificateW 0x78"); EXPECT_EQ(r.ret, 0);
    CHECK(r.err != E_INVALIDARG_ || r.found_any);
}
TEST(ui_selectcert_w_title_close_returns_null) {
    UI_NEED(CryptUIDlgSelectCertificateW); UIRES r;
    if (!ui_exec("selw_title", &r)) return;
    ui_expect_window(&r, "SelectCertificateW title"); EXPECT_EQ(r.ret, 0);
    t_note("caption \"%ls\" (modern UI may not use the supplied title)", r.dlg_title);
}
TEST(ui_selectcert_a_close_returns_null) {
    UI_NEED(CryptUIDlgSelectCertificateA); UIRES r;
    if (!ui_exec("sela_plain", &r)) return;
    ui_expect_window(&r, "SelectCertificateA"); EXPECT_EQ(r.ret, 0);
}

/* legacy list UI is chosen when cStores (+0x58) is set */
UICASE(selw_legacy, 0) {
    BYTE s[0x80]; HCERTSTORE st = ui_mem_store(1);
    memset(s, 0, sizeof s);
    put32(s, 0, 0x80); put64(s, 0x18, kTitleW); put32(s, 0x58, 1); put64(s, 0x60, &st);
    UI_CALL(r, UN(CryptUIDlgSelectCertificateW)(s));
    r->extra[0] = *(DWORD *)(s + 0x68);
    if (r->ret) U(CertFreeCertificateContext)((PCCERT_CONTEXT)(ULONG_PTR)r->ret);
    if (st) U(CertCloseStore)(st, 0);
}
TEST(ui_selectcert_w_legacy_store_list_dialog) {
    UI_NEED(CryptUIDlgSelectCertificateW); UIRES r;
    if (!ui_exec("selw_legacy", &r)) return;
    ui_expect_dialog(&r, "legacy select");
    EXPECT_EQ(r.ret, 0);
    if (!t_is_wine()) CHECK(!lstrcmpW(r.dlg_title, kTitleW));
}

/* ---- CryptUIDlgSelectStoreW/A (0x40-byte struct) ------------------------------- */
UICASE(selst_badsize, UIF_NODLG) {
    static const DWORD sz[] = { 0, 0x3F, 0x41, 0x48, 0x100 };
    for (int i = 0; i < 5; i++) { BYTE s[0x200]; memset(s, 0, sizeof s); put32(s, 0, sz[i]); UI_SUB(r, UN(CryptUIDlgSelectStoreW)(s)); }
}
UICASE(selst_plain, 0) {
    BYTE s[0x40]; memset(s, 0, sizeof s);
    put32(s, 0, 0x40); put64(s, 0x18, kTitleW);
    UI_CALL(r, UN(CryptUIDlgSelectStoreW)(s));
    if (r->ret) U(CertCloseStore)((HCERTSTORE)(ULONG_PTR)r->ret, 0);
}
TEST(ui_selectstore_w_wrong_dwsize_rejected) {
    UI_NEED(CryptUIDlgSelectStoreW); UIRES r;
    if (!ui_exec("selst_badsize", &r)) return;
    ui_expect_nodialog(&r); EXPECT_EQ(r.nsub, 5);
    ui_expect_all_invalid(&r, "SelectStoreW bad size");
}
TEST(ui_selectstore_w_close_returns_null) {
    UI_NEED(CryptUIDlgSelectStoreW); UIRES r;
    if (!ui_exec("selst_plain", &r)) return;
    ui_expect_dialog(&r, "SelectStoreW");
    EXPECT_EQ(r.ret, 0);
}

/* ---- CryptUIDlgCertMgr / CryptUIStartCertMgr ------------------------------------ */
static void mgr_call(UIRES *r, DWORD flags, const WCHAR *title, LPCSTR oid) {
    CRYPTUI_CERT_MGR_STRUCT m; memset(&m, 0, sizeof m);
    m.dwSize = sizeof m; m.dwFlags = flags; m.pwszTitle = title; m.pszInitUsageOID = oid;
    UI_CALL(r, U(CryptUIDlgCertMgr)(&m));
}
#define MGR_TAB(n) UICASE(mgr_tab##n, 0) { mgr_call(r, n, NULL, NULL); } \
    TEST(ui_certmgr_tab_##n) { REQUIRE(U(CryptUIDlgCertMgr)); UIRES r; if (!ui_exec("mgr_tab" #n, &r)) return; ui_expect_dialog(&r, "CertMgr tab " #n); \
        t_note("CertMgr tab " #n ": ret=%llu err=0x%lx", r.ret, r.err); }
MGR_TAB(0) MGR_TAB(1) MGR_TAB(2) MGR_TAB(3) MGR_TAB(4)
UICASE(mgr_single_tab, 0) { mgr_call(r, CRYPTUI_CERT_MGR_SINGLE_TAB_FLAG | 4, NULL, NULL); }
UICASE(mgr_title, 0) { mgr_call(r, 0, kTitleW, NULL); }
UICASE(mgr_oid, 0) { mgr_call(r, 0, NULL, szOID_PKIX_KP_CLIENT_AUTH); }
UICASE(mgr_badflags, UIF_NODLG) {
    CRYPTUI_CERT_MGR_STRUCT m; memset(&m, 0, sizeof m); m.dwSize = sizeof m;
    for (DWORD f = 5; f <= 15; f++) { m.dwFlags = f; UI_SUB(r, U(CryptUIDlgCertMgr)(&m)); }
    m.dwFlags = 0x25; UI_SUB(r, U(CryptUIDlgCertMgr)(&m));
    m.dwFlags = 0xFF; UI_SUB(r, U(CryptUIDlgCertMgr)(&m));
}
UICASE(mgr_badsize, UIF_NODLG) {
    static const DWORD sz[] = { 0, 4, 0x27, 0x29, 0x30, 0x100 };
    for (int i = 0; i < 6; i++) { BYTE s[0x200]; memset(s, 0, sizeof s); put32(s, 0, sz[i]); UI_SUB(r, U(CryptUIDlgCertMgr)((void *)s)); }
    UI_SUB(r, U(CryptUIDlgCertMgr)(NULL));
}
UICASE(startmgr, 0) { UI_CALL(r, UN(CryptUIStartCertMgr)()); }
TEST(ui_certmgr_single_tab_flag) { REQUIRE(U(CryptUIDlgCertMgr)); UIRES r; if (!ui_exec("mgr_single_tab", &r)) return; ui_expect_dialog(&r, "CertMgr single tab"); }
TEST(ui_certmgr_custom_title_is_caption) {
    REQUIRE(U(CryptUIDlgCertMgr)); UIRES r; if (!ui_exec("mgr_title", &r)) return;
    ui_expect_dialog(&r, "CertMgr title");
    if (!t_is_wine()) CHECKF(!lstrcmpW(r.dlg_title, kTitleW), "caption \"%ls\"", r.dlg_title);
}
TEST(ui_certmgr_init_usage_oid) { REQUIRE(U(CryptUIDlgCertMgr)); UIRES r; if (!ui_exec("mgr_oid", &r)) return; ui_expect_dialog(&r, "CertMgr oid"); }
TEST(ui_certmgr_tab_selector_above_4_invalid_arg) {
    REQUIRE(U(CryptUIDlgCertMgr)); UIRES r; if (!ui_exec("mgr_badflags", &r)) return;
    ui_expect_nodialog(&r); EXPECT_EQ(r.nsub, 13);
    ui_expect_all_invalid(&r, "CertMgr tab > 4");
}
TEST(ui_certmgr_wrong_dwsize_or_null_invalid_arg) {
    REQUIRE(U(CryptUIDlgCertMgr)); UIRES r; if (!ui_exec("mgr_badsize", &r)) return;
    ui_expect_nodialog(&r); EXPECT_EQ(r.nsub, 7);
    ui_expect_all_invalid(&r, "CertMgr bad size / NULL");
}
TEST(ui_startcertmgr_opens_manager_and_returns_false) {
    UI_NEED(CryptUIStartCertMgr); UIRES r;
    if (!ui_exec("startmgr", &r)) return;
    ui_expect_dialog(&r, "CryptUIStartCertMgr");
    EXPECT_EQ(r.ret, 0);   /* the stub discards the manager's result */
}

/* ---- cryptdlg legacy entry points ----------------------------------------------- */
UICASE(css_w, 0) {
    BYTE s[0xA0]; HCERTSTORE st = ui_mem_store(1); PCCERT_CONTEXT out[1] = { NULL };
    memset(s, 0, sizeof s);
    put32(s, 0, 0xA0); put64(s, 0x28, kTitleW);
    put32(s, 0x30, 1); put64(s, 0x38, &st);
    put32(s, 0x48, 0); put64(s, 0x50, out);
    UI_CALL(r, UN(CertSelectCertificateW)(s));
    r->extra[0] = (DWORD)(out[0] != NULL);
    if (out[0]) U(CertFreeCertificateContext)(out[0]);
    if (st) U(CertCloseStore)(st, 0);
}
TEST(ui_cryptdlg_certselectcertificatew_close_selects_nothing) {
    UI_NEED(CertSelectCertificateW); UIRES r;
    if (!ui_exec("css_w", &r)) return;
    ui_expect_window(&r, "CertSelectCertificateW");
    EXPECT_EQ(r.extra[0], 0);
    if (!t_is_wine()) EXPECT_EQ(r.ret & 0xFF, 0);
}

UICASE(cvp_w, 0) {
    BYTE s[0xB0]; PCCERT_CONTEXT c = ui_cert();
    memset(s, 0, sizeof s);
    put32(s, 0, 0xA8); put64(s, 0x20, kTitleW); put64(s, 0x28, c);
    if (!c) { r->extra[7] = 1; return; }
    UI_CALL(r, UN(CertViewPropertiesW)(s));
    U(CertFreeCertificateContext)(c);
}
TEST(ui_cryptdlg_certviewpropertiesw_shows_dialog) {
    UI_NEED(CertViewPropertiesW); UIRES r;
    if (!ui_exec("cvp_w", &r)) return;
    if (r.extra[7]) { t_note("no cert fixture"); return; }
    ui_expect_window(&r, "CertViewPropertiesW");
}

UICASE(cfgtrust, UIF_NODLG) {
    UI_SUB(r, UN(CertConfigureTrustW)());
    UI_SUB(r, UN(CertConfigureTrustA)());
}
TEST(ui_cryptdlg_certconfiguretrust_is_noop_stub) {
    UI_NEED(CertConfigureTrustW); UIRES r;
    if (!ui_exec("cfgtrust", &r)) return;
    ui_expect_nodialog(&r);
    /* in the Win10 binary both exports are "xor eax,eax; ret" */
    if (!t_is_wine()) { EXPECT_EQ(r.sub_ret[0], 0); EXPECT_EQ(r.sub_ret[1] & 0xFFFFFFFF, 0); }
}

UICASE(tfp_small, UIF_NODLG) {
    static const DWORD cb[] = { 0, 1, 0x10, 0x90, 0xCF };
    for (int i = 0; i < 5; i++) { BYTE s[0x100]; memset(s, 0, sizeof s); put32(s, 0, cb[i]); UI_SUB(r, (DWORD)UN(CertTrustFinalPolicy)(s)); }
}
TEST(ui_cryptdlg_certtrustfinalpolicy_small_struct_invalid_arg) {
    UI_NEED(CertTrustFinalPolicy); UIRES r;
    if (!ui_exec("tfp_small", &r)) return;
    ui_expect_nodialog(&r); EXPECT_EQ(r.nsub, 5);
    for (DWORD i = 0; i < r.nsub; i++)
        CHECKF((r.sub_ret[i] & 0xFFFFFFFF) == 0x80070057, "cbStruct #%lu returned 0x%llx", i, r.sub_ret[i]);
}
