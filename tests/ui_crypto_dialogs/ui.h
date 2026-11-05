/* Shared scaffolding for the guarded-UI area.
 *
 * Every dialog is driven inside a short-lived child process (run via t_run_child, 20 s kill timeout):
 * the child runs the entry point on a worker thread while its main thread acts as the watcher that finds
 * the process's new top-level windows, closes them (WM_CLOSE, then IDCANCEL, then for message boxes the
 * default button) and records what it saw into a result file that the parent test reads back.
 * All entry points are resolved through LoadLibrary/GetProcAddress (U / UIN / UN). */
#ifndef UI_H
#define UI_H
#include "t.h"
#include <wincrypt.h>
#include <prsht.h>
#include <cryptuiapi.h>
#include "ui_fixtures.h"

#define UI_MAGIC 0x55494331u
typedef struct UIRES {
    DWORD magic;
    DWORD completed;      /* worker thread returned */
    DWORD timed_out;      /* worker had to be terminated */
    DWORD found_any;      /* a new top-level window of this process appeared */
    DWORD found_ms;       /* ms from start of the call until it appeared */
    DWORD saw_dlg;        /* a window of class #32770 appeared */
    DWORD actions;        /* number of close attempts issued */
    DWORD nwin_seen;      /* distinct new windows seen */
    DWORD base_wins, after_wins;
    DWORD nsub;
    unsigned long long ret;
    DWORD err;
    unsigned long long sub_ret[16];
    DWORD sub_err[16];
    DWORD extra[8];
    WCHAR dlg_title[128];
    WCHAR dlg_cls[64];
    WCHAR first_cls[64];
} UIRES;

typedef void (*ui_fn)(UIRES *);
#define UIF_NODLG  1   /* validation case: no window expected; runs even without an interactive desktop */
#define UIF_MSGBOX 2   /* a message box is expected: the watcher may press its default button */
void ui_register(const char *name, ui_fn fn, DWORD flags);
extern char ui_dir[MAX_PATH];  /* fixture directory (child side) */

#define UICASE(n, flags) \
    static void uic_##n(UIRES *r); \
    static void __attribute__((constructor)) uireg_##n(void) { ui_register(#n, uic_##n, flags); } \
    static void uic_##n(UIRES *r)

#define UI_CALL(r, expr) do { SET_ERR(0xDEADBEEF); (r)->ret = (unsigned long long)(ULONG_PTR)(expr); (r)->err = GetLastError(); } while (0)
#define UI_SUB(r, expr) do { int i_ = (r)->nsub++; SET_ERR(0xDEADBEEF); (r)->sub_ret[i_] = (unsigned long long)(ULONG_PTR)(expr); (r)->sub_err[i_] = GetLastError(); } while (0)

/* parent side */
const char *ui_unavailable(void);                 /* NULL when an interactive desktop can be used */
int  ui_exec(const char *name, UIRES *r);         /* 1 = result valid; 0 = skipped/unavailable (already reported) */
void ui_expect_dialog(const UIRES *r, const char *what);   /* strict on Windows, notes only on Wine */
void ui_expect_clean(const UIRES *r);             /* completed, no timeout, no leaked windows */
void ui_expect_nodialog(const UIRES *r);
void ui_expect_window(const UIRES *r, const char *what);       /* a window of any class appeared and went away */
void ui_expect_all_invalid(const UIRES *r, const char *what);   /* every sub-result: FALSE/NULL + E_INVALIDARG */
void ui_chk_err(DWORD got, DWORD want, const char *what);       /* exact on Windows, note on an emulator */
/* Some entry points are unimplemented stubs under Wine and abort the process there. */
#define UI_WINE_UNIMPL() (t_is_wine() ? (t_skip("export is an unimplemented stub under Wine"), 1) : 0)

/* fixtures, child side (all via GetProcAddress) */
PCCERT_CONTEXT ui_cert(void);
PCCRL_CONTEXT  ui_crl(void);
PCCTL_CONTEXT  ui_ctl(void);
HCERTSTORE     ui_mem_store(int with_cert);
void ui_write_file(const char *leaf, const void *data, DWORD len, char *path, size_t cap);
void ui_wide(const char *s, WCHAR *w, int cap);

#define E_INVALIDARG_ ((DWORD)0x80070057)
#define E_FAIL_ ((DWORD)0x80004005)

#define UI_NEED(name) do { if (!UN(name)) { t_skip("missing export: " #name); return; } if (UI_WINE_UNIMPL()) return; } while (0)

/* Entry points missing from the SDK headers. */
UDECL(BOOL, CryptUIDlgViewCRLW, (void *));
UDECL(BOOL, CryptUIDlgViewCRLA, (void *));
UDECL(BOOL, CryptUIDlgViewCTLW, (void *));
UDECL(BOOL, CryptUIDlgViewCTLA, (void *));
UDECL(BOOL, CryptUIDlgViewSignerInfoW, (void *));
UDECL(BOOL, CryptUIDlgViewSignerInfoA, (void *));
UDECL(PCCERT_CONTEXT, CryptUIDlgSelectCertificateW, (void *));
UDECL(PCCERT_CONTEXT, CryptUIDlgSelectCertificateA, (void *));
UDECL(HCERTSTORE, CryptUIDlgSelectStoreW, (void *));
UDECL(HCERTSTORE, CryptUIDlgSelectStoreA, (void *));
UDECL(BOOL, CryptUIStartCertMgr, (void));
UDECL(BOOL, CryptUIWizBuildCTL, (DWORD, HWND, LPCWSTR, const void *, const void *, PCCTL_CONTEXT *));
UDECL(BOOL, CryptUIDlgViewCertificatePropertiesW, (void *));
UDECL(LONG, CertTrustFinalPolicy, (void *));
UDECL(BOOL, CertConfigureTrustW, (void));
UDECL(BOOL, CertConfigureTrustA, (void));
UDECL(BOOL, CertSelectCertificateW, (void *));
UDECL(BOOL, CertSelectCertificateA, (void *));
UDECL(BOOL, CertViewPropertiesW, (void *));
UDECL(BOOL, CertViewPropertiesA, (void *));
UDECL(HRESULT, CryptExtOpenCER, (HWND, HINSTANCE, LPCSTR));
UDECL(HRESULT, CryptExtOpenCERW, (HWND, HINSTANCE, LPCWSTR));

/* Raw struct poking for structures the SDK headers do not declare (x64 layouts taken from the DLL). */
static inline void put32(void *b, int off, DWORD v) { *(DWORD *)((BYTE *)b + off) = v; }
static inline void put64(void *b, int off, const void *v) { *(const void **)((BYTE *)b + off) = v; }

#endif
