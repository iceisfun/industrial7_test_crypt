/* View dialogs: CryptUIDlgViewCertificateW/A, ViewCRL, ViewCTL, ViewSignerInfo, ViewContext. */
#include "ui.h"

static const WCHAR kTitleW[] = L"cryptt custom dialog title";
static const char  kTitleA[] = "cryptt custom dialog title";

/* ---- helpers on the worker thread ------------------------------------------ */
static void view_w(UIRES *r, DWORD flags, const WCHAR *title, HWND parent, DWORD start, DWORD cstores, HCERTSTORE *stores, LPCSTR *purp, DWORD npurp) {
    PCCERT_CONTEXT c = ui_cert();
    CRYPTUI_VIEWCERTIFICATE_STRUCTW v; BOOL chg = 0x55;
    memset(&v, 0, sizeof v);
    v.dwSize = sizeof v; v.hwndParent = parent; v.dwFlags = flags; v.szTitle = title; v.pCertContext = c;
    v.nStartPage = start; v.cStores = cstores; v.rghStores = stores; v.rgszPurposes = purp; v.cPurposes = npurp;
    if (!c) { r->extra[7] = 1; return; }
    UI_CALL(r, U(CryptUIDlgViewCertificateW)(&v, &chg));
    r->extra[0] = chg;
    U(CertFreeCertificateContext)(c);
}
static void view_a(UIRES *r, DWORD flags, const char *title, DWORD start) {
    PCCERT_CONTEXT c = ui_cert();
    CRYPTUI_VIEWCERTIFICATE_STRUCTA v; BOOL chg = 0x55;
    memset(&v, 0, sizeof v);
    v.dwSize = sizeof v; v.dwFlags = flags; v.szTitle = title; v.pCertContext = c; v.nStartPage = start;
    if (!c) { r->extra[7] = 1; return; }
    UI_CALL(r, U(CryptUIDlgViewCertificateA)(&v, &chg));
    r->extra[0] = chg;
    U(CertFreeCertificateContext)(c);
}
static int fixture_ok(const UIRES *r) {
    if (r->extra[7]) { t_note("fixture could not be created; dialog not exercised"); return 0; }
    return 1;
}
static void view_result(const UIRES *r, const char *what) {
    if (!fixture_ok(r)) return;
    ui_expect_dialog(r, what);
    /* The viewer is a property sheet: closing it without OK yields FALSE. */
    /* Return is (PropertySheet result > 0); a close request is not guaranteed to map to 0 on every build: note only. */
    t_note("%s: ret=%llu err=0x%lx", what, r->ret, r->err);
    t_note("%s: ret=%llu lasterr=0x%lx pfPropertiesChanged=%lu title=\"%ls\"", what, r->ret, r->err, r->extra[0], r->dlg_title);
    if (!t_is_wine()) EXPECT_EQ(r->extra[0], 0);   /* *pfPropertiesChanged is reset to FALSE by the call */
}

#define VIEW_W_FLAGS(nm, fl) \
    UICASE(vcw_##nm, 0) { view_w(r, fl, NULL, NULL, 0, 0, NULL, NULL, 0); } \
    TEST(ui_viewcert_w_flags_##nm) { REQUIRE(U(CryptUIDlgViewCertificateW)); UIRES r; if (!ui_exec("vcw_" #nm, &r)) return; view_result(&r, "ViewCertificateW flags " #nm); }

VIEW_W_FLAGS(plain, 0)
VIEW_W_FLAGS(hide_hierarchy, CRYPTUI_HIDE_HIERARCHYPAGE)
VIEW_W_FLAGS(hide_details, CRYPTUI_HIDE_DETAILPAGE)
VIEW_W_FLAGS(hide_both, CRYPTUI_HIDE_HIERARCHYPAGE | CRYPTUI_HIDE_DETAILPAGE)
VIEW_W_FLAGS(disable_editprops, CRYPTUI_DISABLE_EDITPROPERTIES)
VIEW_W_FLAGS(enable_editprops, CRYPTUI_ENABLE_EDITPROPERTIES)
VIEW_W_FLAGS(disable_addtostore, CRYPTUI_DISABLE_ADDTOSTORE)
VIEW_W_FLAGS(enable_addtostore, CRYPTUI_ENABLE_ADDTOSTORE)
VIEW_W_FLAGS(dont_open_stores, CRYPTUI_DONT_OPEN_STORES)
VIEW_W_FLAGS(only_root_store, CRYPTUI_ONLY_OPEN_ROOT_STORE)
VIEW_W_FLAGS(warn_untrusted_root, CRYPTUI_WARN_UNTRUSTED_ROOT)
VIEW_W_FLAGS(warn_remote_trust, CRYPTUI_WARN_REMOTE_TRUST)
VIEW_W_FLAGS(disable_export, CRYPTUI_DISABLE_EXPORT)
VIEW_W_FLAGS(accept_decline, CRYPTUI_ACCEPT_DECLINE_STYLE)
VIEW_W_FLAGS(ignore_untrusted_root, CRYPTUI_IGNORE_UNTRUSTED_ROOT)
VIEW_W_FLAGS(everything_off, CRYPTUI_HIDE_HIERARCHYPAGE | CRYPTUI_HIDE_DETAILPAGE | CRYPTUI_DISABLE_EDITPROPERTIES | CRYPTUI_DISABLE_ADDTOSTORE | CRYPTUI_DISABLE_EXPORT | CRYPTUI_DONT_OPEN_STORES)

#define VIEW_A_FLAGS(nm, fl) \
    UICASE(vca_##nm, 0) { view_a(r, fl, NULL, 0); } \
    TEST(ui_viewcert_a_flags_##nm) { REQUIRE(U(CryptUIDlgViewCertificateA)); UIRES r; if (!ui_exec("vca_" #nm, &r)) return; view_result(&r, "ViewCertificateA flags " #nm); }

VIEW_A_FLAGS(plain, 0)
VIEW_A_FLAGS(hide_hierarchy, CRYPTUI_HIDE_HIERARCHYPAGE)
VIEW_A_FLAGS(hide_details, CRYPTUI_HIDE_DETAILPAGE)
VIEW_A_FLAGS(disable_export, CRYPTUI_DISABLE_EXPORT)
VIEW_A_FLAGS(dont_open_stores, CRYPTUI_DONT_OPEN_STORES)

/* ---- titles ---------------------------------------------------------------- */
UICASE(vc_title_w, 0) { view_w(r, 0, kTitleW, NULL, 0, 0, NULL, NULL, 0); }
UICASE(vc_title_a, 0) { view_a(r, 0, kTitleA, 0); }
UICASE(vc_title_w_long, 0) {
    WCHAR t[300]; for (int i = 0; i < 299; i++) t[i] = L'a' + (i % 26); t[299] = 0;
    view_w(r, 0, t, NULL, 0, 0, NULL, NULL, 0);
}
TEST(ui_viewcert_title_w_is_window_caption) {
    REQUIRE(U(CryptUIDlgViewCertificateW)); UIRES r;
    if (!ui_exec("vc_title_w", &r) || !fixture_ok(&r)) return;
    ui_expect_dialog(&r, "title W");
    if (t_is_wine()) { t_note("caption \"%ls\"", r.dlg_title); return; }
    CHECKF(!lstrcmpW(r.dlg_title, kTitleW), "caption \"%ls\"", r.dlg_title);
}
TEST(ui_viewcert_title_a_is_window_caption) {
    REQUIRE(U(CryptUIDlgViewCertificateA)); UIRES r;
    if (!ui_exec("vc_title_a", &r) || !fixture_ok(&r)) return;
    ui_expect_dialog(&r, "title A");
    if (t_is_wine()) { t_note("caption \"%ls\"", r.dlg_title); return; }
    CHECKF(!lstrcmpW(r.dlg_title, kTitleW), "caption \"%ls\"", r.dlg_title);
}
TEST(ui_viewcert_title_long_w) {
    REQUIRE(U(CryptUIDlgViewCertificateW)); UIRES r;
    if (!ui_exec("vc_title_w_long", &r) || !fixture_ok(&r)) return;
    ui_expect_dialog(&r, "long title");
    CHECK(r.dlg_title[0] == L'a');
}
UICASE(vc_default_title, 0) { view_w(r, 0, NULL, NULL, 0, 0, NULL, NULL, 0); }
TEST(ui_viewcert_default_title_nonempty_localised) {
    REQUIRE(U(CryptUIDlgViewCertificateW)); UIRES r;
    if (!ui_exec("vc_default_title", &r) || !fixture_ok(&r)) return;
    ui_expect_dialog(&r, "default title");
    CHECK(lstrlenW(r.dlg_title) > 0);
    t_note("default caption (locale dependent): \"%ls\"", r.dlg_title);
}

/* ---- start page ------------------------------------------------------------ */
#define START_CASE(nm, start) \
    UICASE(vc_start_##nm, 0) { view_w(r, 0, NULL, NULL, start, 0, NULL, NULL, 0); } \
    TEST(ui_viewcert_start_page_##nm) { REQUIRE(U(CryptUIDlgViewCertificateW)); UIRES r; if (!ui_exec("vc_start_" #nm, &r) || !fixture_ok(&r)) return; ui_expect_dialog(&r, "start page " #nm); }
START_CASE(0, 0)
START_CASE(1, 1)
START_CASE(2, 2)
START_CASE(3, 3)
START_CASE(relative0, 0x8000)

/* ---- stores / purposes / owner window --------------------------------------- */
UICASE(vc_stores, 0) {
    HCERTSTORE s = ui_mem_store(1);
    view_w(r, CRYPTUI_DONT_OPEN_STORES, NULL, NULL, 0, 1, &s, NULL, 0);
    if (s) U(CertCloseStore)(s, 0);
}
TEST(ui_viewcert_extra_memory_store) { REQUIRE(U(CryptUIDlgViewCertificateW)); UIRES r; if (!ui_exec("vc_stores", &r) || !fixture_ok(&r)) return; ui_expect_dialog(&r, "stores"); }

UICASE(vc_purposes, 0) {
    LPCSTR p[2] = { szOID_PKIX_KP_CLIENT_AUTH, szOID_PKIX_KP_SERVER_AUTH };
    view_w(r, CRYPTUI_DONT_OPEN_STORES, NULL, NULL, 0, 0, NULL, p, 2);
}
TEST(ui_viewcert_with_purposes) { REQUIRE(U(CryptUIDlgViewCertificateW)); UIRES r; if (!ui_exec("vc_purposes", &r) || !fixture_ok(&r)) return; ui_expect_dialog(&r, "purposes"); }

UICASE(vc_owner, 0) {
    HWND own = CreateWindowExA(0, "STATIC", "cryptt owner", WS_POPUP, 0, 0, 10, 10, NULL, NULL, NULL, NULL);
    r->extra[1] = own != NULL;
    view_w(r, 0, NULL, own, 0, 0, NULL, NULL, 0);
    r->extra[2] = own && IsWindow(own);
    if (own) DestroyWindow(own);
}
TEST(ui_viewcert_with_owner_window) {
    REQUIRE(U(CryptUIDlgViewCertificateW)); UIRES r;
    if (!ui_exec("vc_owner", &r) || !fixture_ok(&r)) return;
    ui_expect_dialog(&r, "owner");
    if (!t_is_wine()) { CHECK(r.extra[1]); CHECK(r.extra[2]); }   /* the owner survives the dialog */
}

/* ---- argument validation: no window, exact return and last error ------------- */
static void view_badsize(UIRES *r, int wide) {
    static const DWORD sz[] = { 0, 1, 0x48, 0x70, 0x74, 0x77, 0x79, 0x80, 0x100, 0xFFFFFFFF };
    PCCERT_CONTEXT c = ui_cert();
    for (int i = 0; i < 10; i++) {
        BYTE buf[0x200]; BOOL chg = 0x55;
        memset(buf, 0, sizeof buf);
        ((CRYPTUI_VIEWCERTIFICATE_STRUCTW *)buf)->pCertContext = c;
        *(DWORD *)buf = sz[i];
        if (wide) UI_SUB(r, U(CryptUIDlgViewCertificateW)((void *)buf, &chg));
        else UI_SUB(r, U(CryptUIDlgViewCertificateA)((void *)buf, &chg));
        r->extra[i % 8] += (chg == 0x55);   /* flag untouched on failure */
    }
    if (c) U(CertFreeCertificateContext)(c);
}
UICASE(vc_badsize_w, UIF_NODLG) { view_badsize(r, 1); }
UICASE(vc_badsize_a, UIF_NODLG) { view_badsize(r, 0); }
static void check_badsize(UIRES *r, const char *what) {
    ui_expect_nodialog(r);
    EXPECT_EQ(r->nsub, 10);
    ui_expect_all_invalid(r, what);
}
TEST(ui_viewcert_w_wrong_dwsize_rejected) { REQUIRE(U(CryptUIDlgViewCertificateW)); UIRES r; if (!ui_exec("vc_badsize_w", &r)) return; check_badsize(&r, "W"); }
TEST(ui_viewcert_a_wrong_dwsize_rejected) { REQUIRE(U(CryptUIDlgViewCertificateA)); UIRES r; if (!ui_exec("vc_badsize_a", &r)) return; check_badsize(&r, "A"); }
TEST(ui_viewcert_badsize_leaves_changed_flag_untouched) {
    REQUIRE(U(CryptUIDlgViewCertificateW)); UIRES r;
    if (!ui_exec("vc_badsize_w", &r)) return;
    /* the size check precedes the reset of *pfPropertiesChanged */
    DWORD untouched = 0; for (int i = 0; i < 8; i++) untouched += r.extra[i];
    EXPECT_EQ(untouched, 10);
}

/* ---- ViewContext ------------------------------------------------------------- */
UICASE(vctx_cert, 0) {
    PCCERT_CONTEXT c = ui_cert(); if (!c) { r->extra[7] = 1; return; }
    UI_CALL(r, U(CryptUIDlgViewContext)(1, c, NULL, kTitleW, 0, NULL));
    U(CertFreeCertificateContext)(c);
}
UICASE(vctx_crl, 0) {
    PCCRL_CONTEXT c = ui_crl(); if (!c) { r->extra[7] = 1; return; }
    UI_CALL(r, U(CryptUIDlgViewContext)(2, c, NULL, kTitleW, 0, NULL));
    U(CertFreeCRLContext)(c);
}
UICASE(vctx_ctl, 0) {
    PCCTL_CONTEXT c = ui_ctl(); if (!c) { r->extra[7] = 1; return; }
    UI_CALL(r, U(CryptUIDlgViewContext)(3, c, NULL, kTitleW, 0, NULL));
    U(CertFreeCTLContext)(c);
}
UICASE(vctx_bad_type, UIF_NODLG) {
    static const DWORD types[] = { 0, 4, 5, 0x10, 0xFFFFFFFF };
    PCCERT_CONTEXT c = ui_cert();
    for (int i = 0; i < 5; i++) UI_SUB(r, U(CryptUIDlgViewContext)(types[i], c, NULL, NULL, 0, NULL));
    if (c) U(CertFreeCertificateContext)(c);
}
TEST(ui_viewcontext_certificate_shows_viewer) {
    REQUIRE(U(CryptUIDlgViewContext)); UIRES r;
    if (!ui_exec("vctx_cert", &r) || !fixture_ok(&r)) return;
    ui_expect_dialog(&r, "ViewContext cert");
    if (!t_is_wine()) CHECK(!lstrcmpW(r.dlg_title, kTitleW));
}
TEST(ui_viewcontext_crl_shows_viewer) {
    REQUIRE(U(CryptUIDlgViewContext)); UIRES r;
    if (!ui_exec("vctx_crl", &r) || !fixture_ok(&r)) return;
    ui_expect_dialog(&r, "ViewContext crl");
    if (!t_is_wine()) CHECK(!lstrcmpW(r.dlg_title, kTitleW));
}
TEST(ui_viewcontext_ctl_shows_viewer) {
    REQUIRE(U(CryptUIDlgViewContext)); UIRES r;
    if (!ui_exec("vctx_ctl", &r) || !fixture_ok(&r)) return;
    ui_expect_dialog(&r, "ViewContext ctl");
}
TEST(ui_viewcontext_unknown_type_is_invalid_arg) {
    REQUIRE(U(CryptUIDlgViewContext)); UIRES r;
    if (!ui_exec("vctx_bad_type", &r)) return;
    ui_expect_nodialog(&r);
    ui_expect_all_invalid(&r, __func__);
}

/* ---- View CRL --------------------------------------------------------------- */
static void crl_call(UIRES *r, int wide, DWORD flags, const void *title) {
    PCCRL_CONTEXT c = ui_crl(); BYTE s[0x48];
    if (!c) { r->extra[7] = 1; return; }
    memset(s, 0, sizeof s);
    put32(s, 0, 0x48); put32(s, 0x10, flags); put64(s, 0x18, title); put64(s, 0x20, c);
    if (wide) UI_CALL(r, UN(CryptUIDlgViewCRLW)(s)); else UI_CALL(r, UN(CryptUIDlgViewCRLA)(s));
    U(CertFreeCRLContext)(c);
}
UICASE(crl_w_plain, 0) { crl_call(r, 1, 0, NULL); }
UICASE(crl_w_hide_list, 0) { crl_call(r, 1, 1, NULL); }
UICASE(crl_w_title, 0) { crl_call(r, 1, 0, kTitleW); }
UICASE(crl_a_plain, 0) { crl_call(r, 0, 0, NULL); }
UICASE(crl_a_hide_list, 0) { crl_call(r, 0, 1, NULL); }
UICASE(crl_a_title, 0) { crl_call(r, 0, 0, kTitleA); }
UICASE(crl_badsize, UIF_NODLG) {
    static const DWORD sz[] = { 0, 0x40, 0x47, 0x49, 0x58, 0x100 };
    PCCRL_CONTEXT c = ui_crl();
    for (int i = 0; i < 6; i++) {
        BYTE s[0x200]; memset(s, 0, sizeof s); put32(s, 0, sz[i]); put64(s, 0x20, c);
        UI_SUB(r, UN(CryptUIDlgViewCRLW)(s));
    }
    if (c) U(CertFreeCRLContext)(c);
}
#define CRL_TEST(nm, fn, key, tt) \
    TEST(ui_viewcrl_##nm) { if (!UN(fn)) { t_skip("missing export: " #fn); return; } UIRES r; if (!ui_exec(key, &r) || !fixture_ok(&r)) return; ui_expect_dialog(&r, key); if (tt && !t_is_wine()) CHECK(!lstrcmpW(r.dlg_title, kTitleW)); if (!t_is_wine()) EXPECT_EQ(r.ret, 0); }
CRL_TEST(w_plain, CryptUIDlgViewCRLW, "crl_w_plain", 0)
CRL_TEST(w_hide_revocation_list_page, CryptUIDlgViewCRLW, "crl_w_hide_list", 0)
CRL_TEST(w_title, CryptUIDlgViewCRLW, "crl_w_title", 1)
CRL_TEST(a_plain, CryptUIDlgViewCRLA, "crl_a_plain", 0)
CRL_TEST(a_hide_revocation_list_page, CryptUIDlgViewCRLA, "crl_a_hide_list", 0)
CRL_TEST(a_title, CryptUIDlgViewCRLA, "crl_a_title", 1)
TEST(ui_viewcrl_w_wrong_dwsize_rejected) {
    UI_NEED(CryptUIDlgViewCRLW);
    UIRES r; if (!ui_exec("crl_badsize", &r)) return;
    ui_expect_nodialog(&r);
    ui_expect_all_invalid(&r, __func__);
}

/* ---- View CTL --------------------------------------------------------------- */
static void ctl_call(UIRES *r, int wide, DWORD flags, const void *title) {
    PCCTL_CONTEXT c = ui_ctl(); BYTE s[0x58];
    if (!c) { r->extra[7] = 1; return; }
    memset(s, 0, sizeof s);
    put32(s, 0, 0x58); put32(s, 0x10, flags); put64(s, 0x18, title); put64(s, 0x20, c);
    if (wide) UI_CALL(r, UN(CryptUIDlgViewCTLW)(s)); else UI_CALL(r, UN(CryptUIDlgViewCTLA)(s));
    U(CertFreeCTLContext)(c);
}
UICASE(ctl_w_plain, 0) { ctl_call(r, 1, 0, NULL); }
UICASE(ctl_w_title, 0) { ctl_call(r, 1, 0, kTitleW); }
UICASE(ctl_a_plain, 0) { ctl_call(r, 0, 0, NULL); }
UICASE(ctl_a_title, 0) { ctl_call(r, 0, 0, kTitleA); }
UICASE(ctl_badsize, UIF_NODLG) {
    static const DWORD sz[] = { 0, 0x48, 0x57, 0x59, 0x60, 0x100 };
    PCCTL_CONTEXT c = ui_ctl();
    for (int i = 0; i < 6; i++) {
        BYTE s[0x200]; memset(s, 0, sizeof s); put32(s, 0, sz[i]); put64(s, 0x20, c);
        UI_SUB(r, UN(CryptUIDlgViewCTLW)(s));
    }
    if (c) U(CertFreeCTLContext)(c);
}
#define CTL_TEST(nm, fn, key, tt) \
    TEST(ui_viewctl_##nm) { if (!UN(fn)) { t_skip("missing export: " #fn); return; } UIRES r; if (!ui_exec(key, &r) || !fixture_ok(&r)) return; ui_expect_dialog(&r, key); if (tt && !t_is_wine()) CHECK(!lstrcmpW(r.dlg_title, kTitleW)); }
CTL_TEST(w_plain, CryptUIDlgViewCTLW, "ctl_w_plain", 0)
CTL_TEST(w_title, CryptUIDlgViewCTLW, "ctl_w_title", 1)
CTL_TEST(a_plain, CryptUIDlgViewCTLA, "ctl_a_plain", 0)
CTL_TEST(a_title, CryptUIDlgViewCTLA, "ctl_a_title", 1)
TEST(ui_viewctl_w_wrong_dwsize_rejected) {
    UI_NEED(CryptUIDlgViewCTLW);
    UIRES r; if (!ui_exec("ctl_badsize", &r)) return;
    ui_expect_nodialog(&r);
    ui_expect_all_invalid(&r, __func__);
}

/* ---- View signer info --------------------------------------------------------- */
static void signer_call(UIRES *r, int wide, const void *title) {
    HCRYPTMSG m = U(CryptMsgOpenToDecode)(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, 0, 0, NULL, NULL);
    BYTE *si = NULL; DWORD n = 0; BYTE s[0x60];
    if (!m || !U(CryptMsgUpdate)(m, fx_ctl, sizeof fx_ctl, TRUE) ||
        !U(CryptMsgGetParam)(m, CMSG_SIGNER_INFO_PARAM, 0, NULL, &n) || !(si = HeapAlloc(GetProcessHeap(), 0, n)) ||
        !U(CryptMsgGetParam)(m, CMSG_SIGNER_INFO_PARAM, 0, si, &n)) {
        r->extra[7] = 1; if (m) U(CryptMsgClose)(m); return;
    }
    memset(s, 0, sizeof s);
    put32(s, 0, 0x60); put64(s, 0x18, title); put64(s, 0x20, si); put64(s, 0x28, m);
    if (wide) UI_CALL(r, UN(CryptUIDlgViewSignerInfoW)(s)); else UI_CALL(r, UN(CryptUIDlgViewSignerInfoA)(s));
    HeapFree(GetProcessHeap(), 0, si);
    U(CryptMsgClose)(m);
}
UICASE(signer_w, 0) { signer_call(r, 1, NULL); }
UICASE(signer_w_title, 0) { signer_call(r, 1, kTitleW); }
UICASE(signer_a, 0) { signer_call(r, 0, NULL); }
UICASE(signer_badsize, UIF_NODLG) {
    static const DWORD sz[] = { 0, 0x58, 0x5F, 0x61, 0x68, 0x200 };
    for (int i = 0; i < 6; i++) { BYTE s[0x300]; memset(s, 0, sizeof s); put32(s, 0, sz[i]); UI_SUB(r, UN(CryptUIDlgViewSignerInfoW)(s)); }
}
TEST(ui_viewsigner_w_plain) { UI_NEED(CryptUIDlgViewSignerInfoW); UIRES r; if (!ui_exec("signer_w", &r) || !fixture_ok(&r)) return; ui_expect_dialog(&r, "signer W"); }
TEST(ui_viewsigner_w_title) { UI_NEED(CryptUIDlgViewSignerInfoW); UIRES r; if (!ui_exec("signer_w_title", &r) || !fixture_ok(&r)) return; ui_expect_dialog(&r, "signer W title"); if (!t_is_wine()) CHECK(!lstrcmpW(r.dlg_title, kTitleW)); }
TEST(ui_viewsigner_a_plain) { if (!UN(CryptUIDlgViewSignerInfoA)) { t_skip("missing export"); return; } UIRES r; if (!ui_exec("signer_a", &r) || !fixture_ok(&r)) return; ui_expect_dialog(&r, "signer A"); }
TEST(ui_viewsigner_w_wrong_dwsize_rejected) {
    UI_NEED(CryptUIDlgViewSignerInfoW);
    UIRES r; if (!ui_exec("signer_badsize", &r)) return;
    ui_expect_nodialog(&r);
    ui_expect_all_invalid(&r, __func__);
}

/* ---- certificate properties (CryptUIDlgViewCertificatePropertiesW, struct 0x58) -------- */
UICASE(props_badsize, UIF_NODLG) {
    static const DWORD sz[] = { 0, 0x50, 0x57, 0x59, 0x78 };
    for (int i = 0; i < 5; i++) { BYTE s[0x300]; memset(s, 0, sizeof s); put32(s, 0, sz[i]); UI_SUB(r, UN(CryptUIDlgViewCertificatePropertiesW)(s)); }
}
TEST(ui_certprops_w_wrong_dwsize_rejected) {
    UI_NEED(CryptUIDlgViewCertificatePropertiesW);
    UIRES r; if (!ui_exec("props_badsize", &r)) return;
    ui_expect_nodialog(&r);
    ui_expect_all_invalid(&r, __func__);
}
