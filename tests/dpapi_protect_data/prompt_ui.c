#include "dp.h"
/* Intentional prompt rows: the DPAPI prompt really is shown (a modal window in this session) and the test answers it.
 * Every row has its own bounded execution: the DPAPI call runs on a helper thread, this thread looks for the window of
 * this process (<= 8 s per window), sends OK / Cancel / close, then waits <= 10 s for the call. A case marker is flushed
 * before the call is entered, so a hang is attributable. Rows that cannot show a window (UI forbidden) are the
 * dpapi_prompt_policy_conflict_* and dpapi_flags_* tests in data_basic.c.
 * Observed on Win10: the window title is the szPrompt of the prompt struct, or "Access a Protected Item" without one;
 * a creating prompt says "An application is creating a Protected item.", an access prompt "An application is requesting
 * access to a Protected item."; Cancel and the close box both give ERROR_CANCELLED (1223). */

#define UI_MAXDLG 4
#define USR(n) UIN("user32.dll", n)
static const BYTE UI_SECRET[] = "dpapi prompt payload";

typedef struct { void (*run)(void *); void *ctx; volatile LONG done; } UIJOB;
typedef struct { int n; int stuck; char title[UI_MAXDLG][96]; char text[UI_MAXDLG][96]; } UIOBS;

static DWORD WINAPI ui_thread(LPVOID p) { UIJOB *j = (UIJOB *)p; j->run(j->ctx); InterlockedExchange(&j->done, 1); return 0; }
static BOOL CALLBACK ui_enum(HWND h, LPARAM lp) {
    char cls[32]; DWORD pid = 0;
    USR(GetWindowThreadProcessId)(h, &pid);
    if (pid != GetCurrentProcessId() || !USR(IsWindowVisible)(h)) return TRUE;
    cls[0] = 0; USR(GetClassNameA)(h, cls, sizeof cls);
    if (!strcmp(cls, "#32770")) { *(HWND *)lp = h; return FALSE; }
    return TRUE;
}
/* cmds: one letter per window, in order: O = OK, C = Cancel, X = close box. More windows than letters repeat the last. */
static void ui_drive(UIJOB *j, const char *cmds, UIOBS *o, const char *what) {
    HANDLE th; size_t nc = strlen(cmds);
    memset(o, 0, sizeof *o); j->done = 0;
    t_note("interactive row: %s", what); fflush(stdout);
    th = CreateThread(NULL, 0, ui_thread, j, 0, NULL);
    if (!th) { CHECK(0); return; }
    for (;;) {
        HWND d = NULL; DWORD t0 = GetTickCount(); char c; int k;
        while (!j->done && !d && GetTickCount() - t0 < 8000) { USR(EnumWindows)(ui_enum, (LPARAM)&d); if (!d) Sleep(50); }
        if (j->done) break;
        if (!d || o->n >= UI_MAXDLG) { o->stuck = 1; if (d) USR(PostMessageA)(d, WM_CLOSE, 0, 0); break; }
        k = o->n++;
        USR(GetWindowTextA)(d, o->title[k], sizeof o->title[k]);
        USR(GetDlgItemTextA)(d, 1024, o->text[k], sizeof o->text[k]);
        Sleep(300);
        c = cmds[(size_t)k < nc ? (size_t)k : nc - 1];
        if (c == 'X') USR(PostMessageA)(d, WM_CLOSE, 0, 0); else USR(PostMessageA)(d, WM_COMMAND, c == 'O' ? IDOK : IDCANCEL, 0);
        t0 = GetTickCount();
        while (USR(IsWindow)(d) && GetTickCount() - t0 < 5000) Sleep(50);
    }
    if (WaitForSingleObject(th, 10000) != WAIT_OBJECT_0) { o->stuck = 1; TerminateThread(th, 0); }
    CloseHandle(th);
    CHECKF(!o->stuck, "%s: the DPAPI call did not return within its bounds", what);
}

typedef struct { DWORD pflags; const WCHAR *prompt; DWORD flags; BOOL r; DWORD err; DATA_BLOB blob; } UIPROT;
static void ui_do_protect(void *p) {
    UIPROT *c = (UIPROT *)p; CRYPTPROTECT_PROMPTSTRUCT ps = { sizeof ps, c->pflags, NULL, c->prompt };
    DATA_BLOB in = { sizeof UI_SECRET, (BYTE *)UI_SECRET };
    SET_ERR(0); c->r = U(CryptProtectData)(&in, L"cryptt prompt row", NULL, NULL, &ps, c->flags, &c->blob); c->err = GetLastError();
}
typedef struct { DATA_BLOB in; const WCHAR *prompt; DWORD pflags; int use_ps; DWORD flags; BOOL r; DWORD err; DATA_BLOB plain; } UIUNPROT;
static void ui_do_unprotect(void *p) {
    UIUNPROT *c = (UIUNPROT *)p; CRYPTPROTECT_PROMPTSTRUCT ps = { sizeof ps, c->pflags, NULL, c->prompt };
    SET_ERR(0); c->r = U(CryptUnprotectData)(&c->in, NULL, NULL, NULL, c->use_ps ? &ps : NULL, c->flags, &c->plain); c->err = GetLastError();
}
static int plain_ok(const DATA_BLOB *b) { return b->cbData == sizeof UI_SECRET && b->pbData && !memcmp(b->pbData, UI_SECRET, sizeof UI_SECRET); }

static void ui_protect(UIPROT *c, DWORD pflags, const WCHAR *prompt, const char *cmds, UIOBS *o, const char *what) {
    UIJOB j; memset(c, 0, sizeof *c); c->pflags = pflags; c->prompt = prompt;
    j.run = ui_do_protect; j.ctx = c; ui_drive(&j, cmds, o, what);
}
static void ui_unprotect(UIUNPROT *c, const BYTE *blob, DWORD cb, int use_ps, const WCHAR *prompt, DWORD pflags, DWORD flags, const char *cmds, UIOBS *o, const char *what) {
    UIJOB j; memset(c, 0, sizeof *c); c->in.cbData = cb; c->in.pbData = (BYTE *)blob; c->use_ps = use_ps; c->prompt = prompt; c->pflags = pflags; c->flags = flags;
    j.run = ui_do_unprotect; j.ctx = c; ui_drive(&j, cmds, o, what);
}
static const char CREATING[] = "An application is creating a Protected item.";
static const char ACCESSING[] = "An application is requesting access to a Protected item.";
static const char ACCESS_TITLE[] = "Access a Protected Item";

/* ---- PROMPT_ON_PROTECT ---- */
TEST(dpapi_ui_prompt_on_protect_ok_blob_prompts_on_access_too) {
    DP_NEED_DATA(); DP_NOT_WINE();
    UIPROT c; UIOBS o; UIUNPROT u;
    ui_protect(&c, CRYPTPROTECT_PROMPT_ON_PROTECT, L"cryptt protect row", "O", &o, "PROMPT_ON_PROTECT, answer OK");
    EXPECT_EQ(o.n, 1);
    if (o.n == 1) { EXPECT_STR(o.title[0], "cryptt protect row"); EXPECT_STR(o.text[0], CREATING); }
    EXPECT_EQ(c.r, 1);
    /* the blob records the prompt request: unprotecting it also prompts (the flags given at protect time are enforced) */
    if (c.blob.pbData) {
        ui_unprotect(&u, c.blob.pbData, c.blob.cbData, 0, NULL, 0, CRYPTPROTECT_UI_FORBIDDEN, "O", &o, "unprotect of a PROMPT_ON_PROTECT blob, UI forbidden");
        EXPECT_EQ(o.n, 0); EXPECT_EQ(u.r, 0); EXPECT_EQ(u.err, ERROR_PASSWORD_RESTRICTION); dp_free(&u.plain);
        ui_unprotect(&u, c.blob.pbData, c.blob.cbData, 0, NULL, 0, 0, "O", &o, "unprotect of a PROMPT_ON_PROTECT blob, UI allowed, answer OK");
        EXPECT_EQ(o.n, 1);
        if (o.n == 1) { EXPECT_STR(o.title[0], ACCESS_TITLE); EXPECT_STR(o.text[0], ACCESSING); }
        EXPECT_EQ(u.r, 1); CHECK(plain_ok(&u.plain)); dp_free(&u.plain);
    } else CHECK(0);
    dp_free(&c.blob);
}
TEST(dpapi_ui_prompt_on_protect_cancel) {
    DP_NEED_DATA(); DP_NOT_WINE();
    UIPROT c; UIOBS o;
    ui_protect(&c, CRYPTPROTECT_PROMPT_ON_PROTECT, L"cryptt protect row", "C", &o, "PROMPT_ON_PROTECT, answer Cancel");
    EXPECT_EQ(o.n, 1);
    EXPECT_EQ(c.r, 0); EXPECT_EQ(c.err, ERROR_CANCELLED);
    CHECK(c.blob.pbData == NULL && c.blob.cbData == 0);
    dp_free(&c.blob);
}
TEST(dpapi_ui_prompt_on_protect_close_box) {
    DP_NEED_DATA(); DP_NOT_WINE();
    UIPROT c; UIOBS o;
    ui_protect(&c, CRYPTPROTECT_PROMPT_ON_PROTECT, NULL, "X", &o, "PROMPT_ON_PROTECT without text, close the window");
    EXPECT_EQ(o.n, 1);
    EXPECT_EQ(c.r, 0); EXPECT_EQ(c.err, ERROR_CANCELLED);
    CHECK(c.blob.pbData == NULL);
    dp_free(&c.blob);
}

/* ---- PROMPT_ON_UNPROTECT: the prompt is also shown when the blob is created, and again on every unprotect ---- */
static int pou_blob(UIPROT *c) {
    UIOBS o;
    ui_protect(c, CRYPTPROTECT_PROMPT_ON_UNPROTECT, L"cryptt unprotect row", "O", &o, "PROMPT_ON_UNPROTECT blob creation, answer OK");
    EXPECT_EQ(o.n, 1); EXPECT_EQ(c->r, 1);
    if (o.n == 1) { EXPECT_STR(o.title[0], "cryptt unprotect row"); EXPECT_STR(o.text[0], CREATING); }
    return c->r && c->blob.pbData != NULL;
}
TEST(dpapi_ui_prompt_on_unprotect_access_ok) {
    DP_NEED_DATA(); DP_NOT_WINE();
    UIPROT c; UIOBS o; UIUNPROT u;
    if (!pou_blob(&c)) { CHECK(0); return; }
    ui_unprotect(&u, c.blob.pbData, c.blob.cbData, 0, NULL, 0, 0, "O", &o, "unprotect of a PROMPT_ON_UNPROTECT blob, NULL prompt, answer OK");
    EXPECT_EQ(o.n, 1);
    if (o.n == 1) { EXPECT_STR(o.title[0], ACCESS_TITLE); EXPECT_STR(o.text[0], ACCESSING); }
    EXPECT_EQ(u.r, 1); CHECK(plain_ok(&u.plain));
    dp_free(&u.plain); dp_free(&c.blob);
}
TEST(dpapi_ui_prompt_on_unprotect_access_cancel_and_close) {
    DP_NEED_DATA(); DP_NOT_WINE();
    UIPROT c; UIOBS o; UIUNPROT u;
    if (!pou_blob(&c)) { CHECK(0); return; }
    ui_unprotect(&u, c.blob.pbData, c.blob.cbData, 0, NULL, 0, 0, "C", &o, "unprotect of a PROMPT_ON_UNPROTECT blob, answer Cancel");
    EXPECT_EQ(o.n, 1); EXPECT_EQ(u.r, 0); EXPECT_EQ(u.err, ERROR_CANCELLED); CHECK(u.plain.pbData == NULL);
    dp_free(&u.plain);
    ui_unprotect(&u, c.blob.pbData, c.blob.cbData, 0, NULL, 0, 0, "X", &o, "unprotect of a PROMPT_ON_UNPROTECT blob, close the window");
    EXPECT_EQ(o.n, 1); EXPECT_EQ(u.r, 0); EXPECT_EQ(u.err, ERROR_CANCELLED); CHECK(u.plain.pbData == NULL);
    dp_free(&u.plain); dp_free(&c.blob);
}
TEST(dpapi_ui_prompt_on_unprotect_title_from_prompt_struct) {
    DP_NEED_DATA(); DP_NOT_WINE();
    UIPROT c; UIOBS o; UIUNPROT u;
    if (!pou_blob(&c)) { CHECK(0); return; }
    ui_unprotect(&u, c.blob.pbData, c.blob.cbData, 1, L"cryptt access row", 0, 0, "O", &o, "unprotect with a prompt struct (flags 0) naming the window, answer OK");
    EXPECT_EQ(o.n, 1);
    if (o.n == 1) { EXPECT_STR(o.title[0], "cryptt access row"); EXPECT_STR(o.text[0], ACCESSING); }
    EXPECT_EQ(u.r, 1); CHECK(plain_ok(&u.plain));
    dp_free(&u.plain); dp_free(&c.blob);
}
TEST(dpapi_ui_prompt_on_unprotect_blob_with_ui_forbidden_is_refused) {
    DP_NEED_DATA(); DP_NOT_WINE();
    UIPROT c; UIOBS o; UIUNPROT u;
    if (!pou_blob(&c)) { CHECK(0); return; }
    /* the blob demands a prompt, the caller forbids UI: refused with ERROR_PASSWORD_RESTRICTION and no window, with or without a prompt struct */
    ui_unprotect(&u, c.blob.pbData, c.blob.cbData, 0, NULL, 0, CRYPTPROTECT_UI_FORBIDDEN, "O", &o, "PROMPT_ON_UNPROTECT blob, UI forbidden, NULL prompt");
    EXPECT_EQ(o.n, 0); EXPECT_EQ(u.r, 0); EXPECT_EQ(u.err, ERROR_PASSWORD_RESTRICTION); CHECK(u.plain.pbData == NULL);
    dp_free(&u.plain);
    ui_unprotect(&u, c.blob.pbData, c.blob.cbData, 1, L"cryptt access row", CRYPTPROTECT_PROMPT_ON_UNPROTECT, CRYPTPROTECT_UI_FORBIDDEN, "O", &o, "PROMPT_ON_UNPROTECT blob, UI forbidden, prompt struct");
    EXPECT_EQ(o.n, 0); EXPECT_EQ(u.r, 0); EXPECT_EQ(u.err, ERROR_PASSWORD_RESTRICTION);
    dp_free(&u.plain); dp_free(&c.blob);
}

/* ---- a blob whose flags field was tampered to demand a prompt (bit 0x1 PROMPT_ON_UNPROTECT, 0x2 PROMPT_ON_PROTECT) ----
 * The same blob unprotected with UI forbidden is dpapi_tamper_flags_field_observed (1325); without it, the window comes up. */
static void tampered_prompt_row(DWORD bit) {
    UIPROT c; UIOBS o; UIUNPROT u; BYTE *copy; char what[96];
    memset(&c, 0, sizeof c);
    CHECK(dp_protect(UI_SECRET, sizeof UI_SECRET, L"cryptt tamper row", NULL, 0, CRYPTPROTECT_UI_FORBIDDEN, &c.blob));
    if (!c.blob.pbData) return;
    copy = (BYTE *)malloc(c.blob.cbData); memcpy(copy, c.blob.pbData, c.blob.cbData);
    dp_wr(copy, 40, dp_rd(copy, 40) ^ bit);
    snprintf(what, sizeof what, "blob flags ^ 0x%lx, NULL prompt, answer OK", bit);
    ui_unprotect(&u, copy, c.blob.cbData, 0, NULL, 0, 0, "O", &o, what);
    EXPECT_EQ(o.n, 1);
    if (o.n == 1) { EXPECT_STR(o.title[0], ACCESS_TITLE); EXPECT_STR(o.text[0], ACCESSING); }
    EXPECT_EQ(u.r, 0); EXPECT_EQ(u.err, ERROR_INVALID_DATA);         /* the answer is accepted, then the altered blob is rejected */
    dp_free(&u.plain);
    snprintf(what, sizeof what, "blob flags ^ 0x%lx, NULL prompt, answer Cancel", bit);
    ui_unprotect(&u, copy, c.blob.cbData, 0, NULL, 0, 0, "C", &o, what);
    EXPECT_EQ(o.n, 1); EXPECT_EQ(u.r, 0); EXPECT_EQ(u.err, ERROR_CANCELLED);
    dp_free(&u.plain); free(copy); dp_free(&c.blob);
}
TEST(dpapi_ui_tampered_flags_prompt_on_unprotect_bit) { DP_NEED_DATA(); DP_NOT_WINE(); tampered_prompt_row(0x1); }
TEST(dpapi_ui_tampered_flags_prompt_on_protect_bit) { DP_NEED_DATA(); DP_NOT_WINE(); tampered_prompt_row(0x2); }
