#include "ui.h"

char ui_dir[MAX_PATH];

/* ---- case registry -------------------------------------------------------- */
#define MAXCASE 512
static struct { const char *n; ui_fn f; DWORD fl; } g_case[MAXCASE];
static int g_ncase;
void ui_register(const char *name, ui_fn fn, DWORD flags) {
    if (g_ncase < MAXCASE) { g_case[g_ncase].n = name; g_case[g_ncase].f = fn; g_case[g_ncase].fl = flags; g_ncase++; }
}
static int find_case(const char *n) { for (int i = 0; i < g_ncase; i++) if (!strcmp(g_case[i].n, n)) return i; return -1; }

/* ---- interactive desktop detection ----------------------------------------- */
const char *ui_unavailable(void) {
    const char *off = getenv("CRYPTT_NO_UI");
    if (off && *off == '1') return "CRYPTT_NO_UI=1";
    if (t_is_wine()) {
        const char *d = getenv("TP_DISPLAY");
        if (!d || !*d) return "Wine without TP_DISPLAY (headless)";
    }
    HWINSTA ws = GetProcessWindowStation();
    if (!ws) return "no window station";
    USEROBJECTFLAGS fl; DWORD need = 0;
    memset(&fl, 0, sizeof fl);
    if (!GetUserObjectInformationW(ws, UOI_FLAGS, &fl, sizeof fl, &need)) return "GetUserObjectInformation failed";
    if (!(fl.dwFlags & WSF_VISIBLE)) return "non-interactive window station";
    if (GetSystemMetrics(SM_CXSCREEN) <= 0) return "no screen";
    return NULL;
}

/* ---- parent side ----------------------------------------------------------- */
int ui_exec(const char *name, UIRES *r) {
    int ci = find_case(name);
    if (ci < 0) { CHECKF(0, "unknown ui case %s", name); return 0; }
    if (!(g_case[ci].fl & UIF_NODLG)) {
        const char *why = ui_unavailable();
        if (why) { t_skip("no interactive desktop: %s", why); return 0; }
    }
    char res[MAX_PATH], dir[MAX_PATH], extra[3 * MAX_PATH];
    snprintf(res, sizeof res, "%sres_%s.bin", t_tmpdir(), name);
    strcpy(dir, t_tmpdir()); dir[strlen(dir) - 1] = 0;
    DeleteFileA(res);
    snprintf(extra, sizeof extra, "%s \"%s\" \"%s\"", name, res, dir);
    DWORD code = t_run_child("ui_run", extra, 20000);
    memset(r, 0, sizeof *r);
    HANDLE h = CreateFileA(res, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    DWORD got = 0;
    if (h != INVALID_HANDLE_VALUE) { ReadFile(h, r, sizeof *r, &got, NULL); CloseHandle(h); }
    DeleteFileA(res);
    if (code == 0xDEAD0001) { CHECKF(0, "ui child %s was killed after 20 s", name); return 0; }
    if (got != sizeof *r || r->magic != UI_MAGIC) {
        if (t_is_wine()) t_note("ui child %s produced no result (exit 0x%lx)", name, code);
        else CHECKF(0, "ui child %s died (exit 0x%lx)", name, code);
        return 0;
    }
    return 1;
}

void ui_expect_clean(const UIRES *r) {
    CHECK(r->completed == 1);
    CHECK(r->timed_out == 0);
    if (r->after_wins != r->base_wins) {
        if (t_is_wine()) t_note("window count after %lu, baseline %lu", r->after_wins, r->base_wins);
        else CHECKF(0, "window count did not return to baseline: after %lu base %lu", r->after_wins, r->base_wins);
    }
}

void ui_expect_dialog(const UIRES *r, const char *what) {
    int strict = !t_is_wine();
    if (!r->found_any) { if (strict) CHECKF(0, "no window appeared: %s", what); else t_note("%s: no window appeared", what); return; }
    CHECKF(r->found_ms <= 5000 || !strict, "dialog appeared after %lu ms", r->found_ms);
    if (!r->saw_dlg) {
        if (strict) CHECKF(0, "no #32770 window, first class %ls", r->first_cls); else t_note("%s: no #32770, first class %ls", what, r->first_cls);
    } else {
        CHECK(!lstrcmpW(r->dlg_cls, L"#32770"));
        if (!r->dlg_title[0]) { if (strict) CHECKF(0, "dialog title empty: %s", what); else t_note("%s: empty title", what); }
    }
    ui_expect_clean(r);
}

void ui_expect_window(const UIRES *r, const char *what) {
    if (!r->found_any) { if (!t_is_wine()) CHECKF(0, "no window appeared: %s", what); else t_note("%s: no window appeared", what); }
    else t_note("%s: window class \"%ls\" after %lu ms", what, r->first_cls, r->found_ms);
    ui_expect_clean(r);
}

void ui_expect_nodialog(const UIRES *r) {
    CHECKF(!r->found_any, "unexpected window class %ls", r->first_cls);
    ui_expect_clean(r);
}

void ui_chk_err(DWORD got, DWORD want, const char *what) {
    if (got == want) { CHECK(1); return; }
    if (t_is_wine()) t_note("%s: last error 0x%lx, Windows gives 0x%lx", what, got, want);
    else CHECKF(0, "%s: last error 0x%lx want 0x%lx", what, got, want);
}
void ui_expect_all_invalid(const UIRES *r, const char *what) {
    for (DWORD i = 0; i < r->nsub; i++) {
        CHECKF(r->sub_ret[i] == 0, "%s #%lu returned 0x%llx", what, i, r->sub_ret[i]);
        ui_chk_err(r->sub_err[i], E_INVALIDARG_, what);
    }
}

/* ---- fixtures (child side) ------------------------------------------------- */
PCCERT_CONTEXT ui_cert(void) {
    return U(CertCreateCertificateContext) ? U(CertCreateCertificateContext)(X509_ASN_ENCODING, fx_cert, sizeof fx_cert) : NULL;
}
PCCRL_CONTEXT ui_crl(void) {
    return U(CertCreateCRLContext) ? U(CertCreateCRLContext)(X509_ASN_ENCODING, fx_crl, sizeof fx_crl) : NULL;
}
PCCTL_CONTEXT ui_ctl(void) {
    return U(CertCreateCTLContext) ? U(CertCreateCTLContext)(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, fx_ctl, sizeof fx_ctl) : NULL;
}
HCERTSTORE ui_mem_store(int with_cert) {
    if (!U(CertOpenStore)) return NULL;
    HCERTSTORE s = U(CertOpenStore)(CERT_STORE_PROV_MEMORY, 0, 0, CERT_STORE_CREATE_NEW_FLAG, NULL);
    if (s && with_cert && U(CertAddEncodedCertificateToStore))
        U(CertAddEncodedCertificateToStore)(s, X509_ASN_ENCODING, fx_cert, sizeof fx_cert, CERT_STORE_ADD_ALWAYS, NULL);
    return s;
}
void ui_write_file(const char *leaf, const void *data, DWORD len, char *path, size_t cap) {
    snprintf(path, cap, "%s\\%s", ui_dir, leaf);
    HANDLE h = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) { DWORD w; WriteFile(h, data, len, &w, NULL); CloseHandle(h); }
}
void ui_wide(const char *s, WCHAR *w, int cap) { MultiByteToWideChar(CP_ACP, 0, s, -1, w, cap); }

/* ---- child side: worker + watcher ------------------------------------------ */
typedef struct { ui_fn fn; UIRES *r; volatile LONG done; } WORK;
static DWORD WINAPI worker(LPVOID p) {
    WORK *w = p;
    w->fn(w->r);
    InterlockedExchange(&w->done, 1);
    return 0;
}

#define MAXW 64
typedef struct { HWND h[MAXW]; int n; } WLIST;
static BOOL CALLBACK enum_cb(HWND h, LPARAM lp) {
    WLIST *l = (WLIST *)lp; DWORD pid;
    GetWindowThreadProcessId(h, &pid);
    if (pid == GetCurrentProcessId() && IsWindowVisible(h) && l->n < MAXW) l->h[l->n++] = h;
    return TRUE;
}
static void list_windows(WLIST *l) { l->n = 0; EnumWindows(enum_cb, (LPARAM)l); }
static int in_list(const WLIST *l, HWND h) { for (int i = 0; i < l->n; i++) if (l->h[i] == h) return 1; return 0; }

static BOOL CALLBACK defbtn_cb(HWND h, LPARAM lp) {
    WCHAR c[32];
    if (GetClassNameW(h, c, 32) && !lstrcmpiW(c, L"Button")) {
        LONG st = GetWindowLongW(h, GWL_STYLE);
        if ((st & BS_TYPEMASK) == BS_DEFPUSHBUTTON && IsWindowEnabled(h)) { *(HWND *)lp = h; return FALSE; }
    }
    return TRUE;
}

static void close_attempt(HWND h, int n, DWORD flags) {
    switch (n) {
    case 0: PostMessageW(h, WM_CLOSE, 0, 0); break;
    case 1: PostMessageW(h, WM_COMMAND, MAKEWPARAM(IDCANCEL, BN_CLICKED), 0); break;
    case 2: PostMessageW(h, WM_SYSCOMMAND, SC_CLOSE, 0); break;
    default:
        if (flags & UIF_MSGBOX) {
            HWND b = NULL;
            EnumChildWindows(h, defbtn_cb, (LPARAM)&b);
            if (b) SendMessageTimeoutW(b, BM_CLICK, 0, 0, SMTO_ABORTIFHUNG, 500, NULL);
            else PostMessageW(h, WM_COMMAND, MAKEWPARAM(IDOK, BN_CLICKED), 0);
        } else if (n == 3) PostMessageW(h, WM_COMMAND, MAKEWPARAM(IDCANCEL, BN_CLICKED), 0);
        break;
    }
}

int run_child_case(int ci, const char *resfile) {
    UIRES *r = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof *r);
    WLIST base, cur;
    struct { HWND h; DWORD tries; DWORD last; } seen[MAXW];
    int nseen = 0;
    DWORD flags = g_case[ci].fl;
    r->magic = UI_MAGIC;
    list_windows(&base);
    r->base_wins = base.n;
    WORK w = { g_case[ci].f, r, 0 };
    DWORD t0 = GetTickCount();
    HANDLE th = CreateThread(NULL, 0, worker, &w, 0, NULL);
    if (!th) return 0xC0DE0003;
    memset(seen, 0, sizeof seen);
    while (!w.done && GetTickCount() - t0 < 12000) {
        list_windows(&cur);
        for (int i = 0; i < cur.n; i++) {
            HWND h = cur.h[i];
            if (in_list(&base, h)) continue;
            int k;
            for (k = 0; k < nseen; k++) if (seen[k].h == h) break;
            DWORD now = GetTickCount();
            if (k == nseen && nseen < MAXW) {
                seen[nseen].h = h; seen[nseen].tries = 0; seen[nseen].last = now; nseen++;
                WCHAR cls[64] = L"", title[128] = L"";
                GetClassNameW(h, cls, 64); GetWindowTextW(h, title, 128);
                r->nwin_seen++;
                if (!r->found_any) { r->found_any = 1; r->found_ms = now - t0; lstrcpynW(r->first_cls, cls, 64); }
                if (!r->saw_dlg && !lstrcmpW(cls, L"#32770")) {
                    r->saw_dlg = 1; lstrcpynW(r->dlg_cls, cls, 64); lstrcpynW(r->dlg_title, title, 128);
                }
            }
            if (k < nseen && now - seen[k].last >= (seen[k].tries == 0 ? 200 : 400)) {
                close_attempt(h, seen[k].tries++, flags);
                seen[k].last = now; r->actions++;
            }
        }
        Sleep(30);
    }
    if (!w.done) {
        r->timed_out = 1;
        TerminateThread(th, 0);   /* only ever in this disposable child */
    } else {
        /* let the windows disappear */
        DWORD t1 = GetTickCount();
        for (;;) {
            list_windows(&cur);
            int extra = 0;
            for (int i = 0; i < cur.n; i++) if (!in_list(&base, cur.h[i])) extra++;
            r->after_wins = base.n + extra;
            if (!extra || GetTickCount() - t1 > 2000) break;
            Sleep(50);
        }
    }
    r->completed = (DWORD)w.done;
    if (r->timed_out) { list_windows(&cur); r->after_wins = cur.n; }
    HANDLE h = CreateFileA(resfile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) { DWORD wr; WriteFile(h, r, sizeof *r, &wr, NULL); CloseHandle(h); }
    return 0;
}

/* exe --child ui_run <case> <resultfile> <fixture dir> */
CHILD(ui_run) {
    if (argc < 4) return 0xC0DE0004;
    int ci = find_case(argv[1]);
    if (ci < 0) return 0xC0DE0002;
    strncpy(ui_dir, argv[3], sizeof ui_dir - 1);
    int rc = run_child_case(ci, argv[2]);
    ExitProcess(rc);   /* do not wait on anything a stuck dialog may still own */
    return rc;
}

/* ---- self tests of the scaffolding (no dialogs) ---------------------------- */
UICASE(core_selftest_nodlg, UIF_NODLG) { UI_CALL(r, 42); r->extra[0] = 7; }
TEST(ui_core_child_roundtrip) {
    UIRES r;
    if (!ui_exec("core_selftest_nodlg", &r)) return;
    EXPECT_EQ(r.ret, 42); EXPECT_EQ(r.extra[0], 7);
    CHECK(r.completed); CHECK(!r.found_any);
    EXPECT_EQ(r.err, 0xDEADBEEF);
}
TEST(ui_core_desktop_probe) {
    const char *why = ui_unavailable();
    t_note("interactive desktop: %s", why ? why : "available");
    HWINSTA ws = GetProcessWindowStation();
    CHECK(ws != NULL);
    WCHAR nm[128] = L""; DWORD need;
    CHECK(GetUserObjectInformationW(ws, UOI_NAME, nm, sizeof nm, &need));
    CHECK(nm[0] != 0);
    USEROBJECTFLAGS fl; memset(&fl, 0, sizeof fl);
    CHECK(GetUserObjectInformationW(ws, UOI_FLAGS, &fl, sizeof fl, &need));
    t_note("window station %ls flags 0x%lx", nm, fl.dwFlags);
}
