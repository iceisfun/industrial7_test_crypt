/* Wizards started WITHOUT CRYPTUI_WIZ_NO_UI: CryptUIWizImport / Export / DigitalSign / BuildCTL.
 * Every wizard is cancelled by the watcher; imports target a memory store and use
 * CRYPTUI_WIZ_IMPORT_NO_CHANGE_DEST_STORE so that nothing can reach a persistent store. */
#include "ui.h"

static const WCHAR kWizTitle[] = L"cryptt wizard title";

/* ---- import ---------------------------------------------------------------- */
static void imp_file(UIRES *r, const char *leaf, const void *data, DWORD len, const WCHAR *pwd, const WCHAR *title, DWORD flags) {
    char path[MAX_PATH]; WCHAR wp[MAX_PATH]; CRYPTUI_WIZ_IMPORT_SRC_INFO s; HCERTSTORE st = ui_mem_store(0);
    ui_write_file(leaf, data, len, path, sizeof path); ui_wide(path, wp, MAX_PATH);
    memset(&s, 0, sizeof s);
    s.dwSize = sizeof s; s.dwSubjectChoice = CRYPTUI_WIZ_IMPORT_SUBJECT_FILE; s.pwszFileName = wp; s.pwszPassword = pwd;
    UI_CALL(r, U(CryptUIWizImport)(flags | CRYPTUI_WIZ_IMPORT_NO_CHANGE_DEST_STORE, NULL, title, &s, st));
    r->extra[0] = (DWORD)(U(CertEnumCertificatesInStore)(st, NULL) != NULL);   /* nothing was imported */
    if (st) U(CertCloseStore)(st, 0);
}
#define IMPCASE(nm, leaf, arr, pwd, title, flags) \
    UICASE(wimp_##nm, 0) { imp_file(r, leaf, arr, sizeof arr, pwd, title, flags); } \
    TEST(ui_wizimport_##nm) { REQUIRE(U(CryptUIWizImport)); UIRES r; if (!ui_exec("wimp_" #nm, &r)) return; \
        ui_expect_window(&r, "CryptUIWizImport " #nm, L"NativeHWNDHost"); \
        EXPECT_EQ(r.extra[0], 0); \
        EXPECT_EQ(r.ret, 1);   /* probed std and adm: a cancelled import wizard returns TRUE */ }
IMPCASE(cer_file, "i1.cer", fx_cert, NULL, NULL, 0)
IMPCASE(cer_file_titled, "i2.cer", fx_cert, NULL, kWizTitle, 0)
IMPCASE(crl_file, "i3.crl", fx_crl, NULL, NULL, 0)
IMPCASE(ctl_file, "i4.stl", fx_ctl, NULL, NULL, 0)
IMPCASE(p7b_file, "i5.p7b", fx_p7b, NULL, NULL, 0)
IMPCASE(pfx_file, "i6.pfx", fx_pfx, L"cryptt", NULL, 0)
IMPCASE(pfx_file_wrong_password, "wiz.pfx", fx_pfx, L"wrong", NULL, 0)
IMPCASE(cer_allow_cert_only, "i8.cer", fx_cert, NULL, NULL, CRYPTUI_WIZ_IMPORT_ALLOW_CERT)
IMPCASE(cer_to_currentuser, "i9.cer", fx_cert, NULL, NULL, CRYPTUI_WIZ_IMPORT_TO_CURRENTUSER)

UICASE(wimp_no_source, 0) {
    HCERTSTORE st = ui_mem_store(0);
    UI_CALL(r, U(CryptUIWizImport)(CRYPTUI_WIZ_IMPORT_NO_CHANGE_DEST_STORE, NULL, NULL, NULL, st));
    if (st) U(CertCloseStore)(st, 0);
}
TEST(ui_wizimport_without_source_asks_for_file) {
    REQUIRE(U(CryptUIWizImport)); UIRES r;
    if (!ui_exec("wimp_no_source", &r)) return;
    ui_expect_window(&r, "CryptUIWizImport(NULL source)", L"NativeHWNDHost");
}

UICASE(wimp_certctx, 0) {
    PCCERT_CONTEXT c = ui_cert(); HCERTSTORE st = ui_mem_store(0); CRYPTUI_WIZ_IMPORT_SRC_INFO s;
    memset(&s, 0, sizeof s);
    s.dwSize = sizeof s; s.dwSubjectChoice = CRYPTUI_WIZ_IMPORT_SUBJECT_CERT_CONTEXT; s.pCertContext = c;
    UI_CALL(r, U(CryptUIWizImport)(CRYPTUI_WIZ_IMPORT_NO_CHANGE_DEST_STORE, NULL, NULL, &s, st));
    r->extra[0] = (DWORD)(U(CertEnumCertificatesInStore)(st, NULL) != NULL);
    if (c) U(CertFreeCertificateContext)(c);
    if (st) U(CertCloseStore)(st, 0);
}
TEST(ui_wizimport_cert_context_wizard_cancelled_imports_nothing) {
    REQUIRE(U(CryptUIWizImport)); UIRES r;
    if (!ui_exec("wimp_certctx", &r)) return;
    ui_expect_window(&r, "CryptUIWizImport cert context", L"NativeHWNDHost");
    EXPECT_EQ(r.extra[0], 0);
}

UICASE(wimp_store_src, 0) {
    HCERTSTORE src = ui_mem_store(1), st = ui_mem_store(0); CRYPTUI_WIZ_IMPORT_SRC_INFO s;
    memset(&s, 0, sizeof s);
    s.dwSize = sizeof s; s.dwSubjectChoice = CRYPTUI_WIZ_IMPORT_SUBJECT_CERT_STORE; s.hCertStore = src;
    UI_CALL(r, U(CryptUIWizImport)(CRYPTUI_WIZ_IMPORT_NO_CHANGE_DEST_STORE, NULL, NULL, &s, st));
    r->extra[0] = (DWORD)(U(CertEnumCertificatesInStore)(st, NULL) != NULL);
    if (src) U(CertCloseStore)(src, 0);
    if (st) U(CertCloseStore)(st, 0);
}
TEST(ui_wizimport_store_source_wizard_cancelled_imports_nothing) {
    REQUIRE(U(CryptUIWizImport)); UIRES r;
    if (!ui_exec("wimp_store_src", &r)) return;
    ui_expect_window(&r, "CryptUIWizImport store source", L"NativeHWNDHost");
    EXPECT_EQ(r.extra[0], 0);
}

/* ---- export ---------------------------------------------------------------- */
static void exp_call(UIRES *r, DWORD choice, const WCHAR *title, int preset_name, int with_fmt) {
    PCCERT_CONTEXT c = ui_cert(); PCCRL_CONTEXT crl = ui_crl(); PCCTL_CONTEXT ctl = ui_ctl();
    HCERTSTORE st = ui_mem_store(1); CRYPTUI_WIZ_EXPORT_INFO e; CRYPTUI_WIZ_EXPORT_CERTCONTEXT_INFO ci;
    char path[MAX_PATH]; WCHAR wp[MAX_PATH];
    snprintf(path, sizeof path, "%s\\exported_%lu.out", ui_dir, choice); ui_wide(path, wp, MAX_PATH);
    memset(&e, 0, sizeof e); memset(&ci, 0, sizeof ci);
    e.dwSize = sizeof e; e.dwSubjectChoice = choice;
    if (preset_name) e.pwszExportFileName = wp;
    switch (choice) {
    case CRYPTUI_WIZ_EXPORT_CERT_CONTEXT: e.pCertContext = c; break;
    case CRYPTUI_WIZ_EXPORT_CTL_CONTEXT: e.pCTLContext = ctl; break;
    case CRYPTUI_WIZ_EXPORT_CRL_CONTEXT: e.pCRLContext = crl; break;
    default: e.hCertStore = st; break;
    }
    ci.dwSize = sizeof ci; ci.dwExportFormat = CRYPTUI_WIZ_EXPORT_FORMAT_DER;
    UI_CALL(r, U(CryptUIWizExport)(0, NULL, title, &e, with_fmt ? &ci : NULL));
    r->extra[0] = GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES;   /* cancelled: no file */
    if (c) U(CertFreeCertificateContext)(c);
    if (crl) U(CertFreeCRLContext)(crl);
    if (ctl) U(CertFreeCTLContext)(ctl);
    if (st) U(CertCloseStore)(st, 0);
}
#define EXPCASE(nm, choice, title, preset, fmt) \
    UICASE(wexp_##nm, 0) { exp_call(r, choice, title, preset, fmt); } \
    TEST(ui_wizexport_##nm) { REQUIRE(U(CryptUIWizExport)); UIRES r; if (!ui_exec("wexp_" #nm, &r)) return; \
        ui_expect_window(&r, "CryptUIWizExport " #nm, L"NativeHWNDHost"); EXPECT_EQ(r.extra[0], 0); \
        EXPECT_EQ(r.ret, 0); EXPECT_EQ(r.err, ERROR_CANCELLED);   /* probed std and adm: a cancelled export wizard fails with ERROR_CANCELLED */ }
EXPCASE(cert_context, CRYPTUI_WIZ_EXPORT_CERT_CONTEXT, NULL, 0, 0)
EXPCASE(cert_context_titled, CRYPTUI_WIZ_EXPORT_CERT_CONTEXT, kWizTitle, 0, 0)
EXPCASE(cert_context_preset_name, CRYPTUI_WIZ_EXPORT_CERT_CONTEXT, NULL, 1, 0)
EXPCASE(cert_context_with_format_info, CRYPTUI_WIZ_EXPORT_CERT_CONTEXT, NULL, 0, 1)
EXPCASE(ctl_context, CRYPTUI_WIZ_EXPORT_CTL_CONTEXT, NULL, 0, 0)
EXPCASE(crl_context, CRYPTUI_WIZ_EXPORT_CRL_CONTEXT, NULL, 0, 0)
EXPCASE(cert_store, CRYPTUI_WIZ_EXPORT_CERT_STORE, NULL, 0, 0)
EXPCASE(cert_store_certificates_only, CRYPTUI_WIZ_EXPORT_CERT_STORE_CERTIFICATES_ONLY, NULL, 0, 0)

/* ---- digital sign ---------------------------------------------------------- */
UICASE(wsign_file, 0) {
    static const char body[] = "cryptt digital sign wizard subject, must stay unchanged\r\n";
    char path[MAX_PATH]; WCHAR wp[MAX_PATH]; CRYPTUI_WIZ_DIGITAL_SIGN_INFO si; PCCRYPTUI_WIZ_DIGITAL_SIGN_CONTEXT ctx = (void *)(ULONG_PTR)0x1234;
    ui_write_file("sign_subject.txt", body, sizeof body - 1, path, sizeof path); ui_wide(path, wp, MAX_PATH);
    memset(&si, 0, sizeof si);
    si.dwSize = sizeof si; si.dwSubjectChoice = CRYPTUI_WIZ_DIGITAL_SIGN_SUBJECT_FILE; si.pwszFileName = wp;
    UI_CALL(r, U(CryptUIWizDigitalSign)(0, NULL, kWizTitle, &si, &ctx));
    r->extra[0] = ctx == (void *)(ULONG_PTR)0x1234;   /* *ppSignContext untouched or written */
    r->extra[1] = ctx == NULL;
    if (ctx && ctx != (void *)(ULONG_PTR)0x1234) U(CryptUIWizFreeDigitalSignContext)(ctx);
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    DWORD n = 0; char buf[256];
    if (h != INVALID_HANDLE_VALUE) { ReadFile(h, buf, sizeof buf, &n, NULL); CloseHandle(h); }
    r->extra[2] = (n == sizeof body - 1 && !memcmp(buf, body, n));
}
TEST(ui_wizdigitalsign_file_wizard_cancelled_leaves_file_unchanged) {
    REQUIRE(U(CryptUIWizDigitalSign)); UIRES r;
    if (!ui_exec("wsign_file", &r)) return;
    ui_expect_window(&r, "CryptUIWizDigitalSign", L"#32770");
    EXPECT_EQ(r.extra[2], 1);
    /* probed std and adm: a cancelled sign wizard returns TRUE and sets *ppSignContext to NULL */
    EXPECT_EQ(r.ret, 1); EXPECT_EQ(r.extra[1], 1);
}
UICASE(wsign_nosubject, 0) {
    PCCRYPTUI_WIZ_DIGITAL_SIGN_CONTEXT ctx = NULL;
    UI_CALL(r, U(CryptUIWizDigitalSign)(0, NULL, NULL, NULL, &ctx));
    if (ctx) U(CryptUIWizFreeDigitalSignContext)(ctx);
}
TEST(ui_wizdigitalsign_without_subject_wizard_cancelled) {
    REQUIRE(U(CryptUIWizDigitalSign)); UIRES r;
    if (!ui_exec("wsign_nosubject", &r)) return;
    ui_expect_window(&r, "CryptUIWizDigitalSign(NULL)", L"#32770");
    EXPECT_EQ(r.ret, 0); EXPECT_EQ(r.err, 0);   /* probed std and adm: FALSE without setting a last error (last error stays 0) */
}

/* ---- build CTL ------------------------------------------------------------- */
UICASE(wctl_fresh, 0) {
    PCCTL_CONTEXT out = (PCCTL_CONTEXT)(ULONG_PTR)0x1234;
    UI_CALL(r, UN(CryptUIWizBuildCTL)(0, NULL, kWizTitle, NULL, NULL, &out));
    r->extra[0] = (out == NULL);   /* the out pointer is cleared before the wizard runs */
    if (out && out != (PCCTL_CONTEXT)(ULONG_PTR)0x1234) U(CertFreeCTLContext)(out);
}
TEST(ui_wizbuildctl_cancel_clears_out_context) {
    UI_NEED(CryptUIWizBuildCTL); UIRES r;
    if (!ui_exec("wctl_fresh", &r)) return;
    ui_expect_window(&r, "CryptUIWizBuildCTL", L"#32770");
    EXPECT_EQ(r.extra[0], 1);
}
