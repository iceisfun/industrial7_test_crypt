#include "cfg.h"
#include <wchar.h>
#include <stdlib.h>

const ULONG cfg_valid_ifaces[11] = {1,2,3,4,5,6,7,0x10001,0x10002,0x10003,0x10004};
const ULONG cfg_bad_ifaces[7] = {0, 8, 9, 0x10000, 0x10005, 0x20001, 0xFFFFFFFF};
const ULONG cfg_bad_tables[6] = {0, 3, 4, 0x10000, 0x80000000, 0xFFFFFFFF};

#define MAXREM 128
static WCHAR g_ctx[MAXREM][96];  static int g_nctx;
static WCHAR g_prov[MAXREM][96]; static int g_nprov;
static int g_seq, g_swept, g_atexit;

int cfg_is_elevated(void) {
    HANDLE tok = NULL; TOKEN_ELEVATION te; DWORD n = 0; int r = 0;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) {
        if (GetTokenInformation(tok, TokenElevation, &te, sizeof te, &n)) r = te.TokenIsElevated != 0;
        CloseHandle(tok);
    }
    return r;
}

void cfg_name(WCHAR *out, size_t cch, const char *tag, int kind) {
    WCHAR wt[40]; int i;
    for (i = 0; tag[i] && i < 39; i++) wt[i] = (WCHAR)tag[i];
    wt[i] = 0;
    _snwprintf(out, cch, L"cryptt_%ls_%lu_%d", wt, GetCurrentProcessId(), ++g_seq);
    out[cch - 1] = 0;
    if (kind == 0 && g_nctx < MAXREM) wcscpy(g_ctx[g_nctx++], out);
    if (kind == 1 && g_nprov < MAXREM) wcscpy(g_prov[g_nprov++], out);
}

static void *getfn(const char *n) { return (void *)t_proc(n); }

static int enum_strings(ULONG cnt, PWSTR *arr, WCHAR out[][96], int max) {
    int i, n = (int)cnt < max ? (int)cnt : max;
    for (i = 0; i < n; i++) { wcsncpy(out[i], arr[i], 95); out[i][95] = 0; }
    return n;
}

int cfg_enum_ctx(ULONG table, WCHAR out[][96], int max, NTSTATUS *st) {
    ULONG cb = 0; PCRYPT_CONTEXTS p = NULL; int n;
    NTSTATUS s = U(BCryptEnumContexts)(table, &cb, &p);
    if (st) *st = s;
    if (!NT_OK(s) || !p) return -1;
    n = enum_strings(p->cContexts, p->rgpszContexts, out, max);
    U(BCryptFreeBuffer)(p);
    return n;
}
int cfg_enum_funcs(ULONG table, const WCHAR *ctx, ULONG iface, WCHAR out[][96], int max, NTSTATUS *st) {
    ULONG cb = 0; PCRYPT_CONTEXT_FUNCTIONS p = NULL; int n;
    NTSTATUS s = U(BCryptEnumContextFunctions)(table, ctx, iface, &cb, &p);
    if (st) *st = s;
    if (!NT_OK(s) || !p) return -1;
    n = enum_strings(p->cFunctions, p->rgpszFunctions, out, max);
    U(BCryptFreeBuffer)(p);
    return n;
}
int cfg_enum_fprov(ULONG table, const WCHAR *ctx, ULONG iface, const WCHAR *fn, WCHAR out[][96], int max, NTSTATUS *st) {
    ULONG cb = 0; PCRYPT_CONTEXT_FUNCTION_PROVIDERS p = NULL; int n;
    NTSTATUS s = U(BCryptEnumContextFunctionProviders)(table, ctx, iface, fn, &cb, &p);
    if (st) *st = s;
    if (!NT_OK(s) || !p) return -1;
    n = enum_strings(p->cProviders, p->rgpszProviders, out, max);
    U(BCryptFreeBuffer)(p);
    return n;
}
int cfg_enum_registered(WCHAR out[][96], int max, NTSTATUS *st) {
    ULONG cb = 0; PCRYPT_PROVIDERS p = NULL; int n;
    NTSTATUS s = U(BCryptEnumRegisteredProviders)(&cb, &p);
    if (st) *st = s;
    if (!NT_OK(s) || !p) return -1;
    n = enum_strings(p->cProviders, p->rgpszProviders, out, max);
    U(BCryptFreeBuffer)(p);
    return n;
}
int cfg_has_ctx(ULONG table, const WCHAR *ctx) {
    static WCHAR l[512][96]; int i, n = cfg_enum_ctx(table, l, 512, NULL);
    for (i = 0; i < n; i++) if (!lstrcmpiW(l[i], ctx)) return 1;
    return 0;
}
int cfg_has_provider(const WCHAR *name) {
    static WCHAR l[512][96]; int i, n = cfg_enum_registered(l, 512, NULL);
    for (i = 0; i < n; i++) if (!lstrcmpiW(l[i], name)) return 1;
    return 0;
}
void cfg_sysdll(WCHAR *out, size_t cch, const WCHAR *leaf) {
    UINT n = GetSystemDirectoryW(out, (UINT)cch);
    _snwprintf(out + n, cch - n, L"\\%ls", leaf);
    out[cch - 1] = 0;
}

void cfg_cleanup_all(void) {
    int i;
    if (!getfn("BCryptDeleteContext")) return;
    for (i = 0; i < g_nctx; i++) U(BCryptDeleteContext)(CRYPT_LOCAL, g_ctx[i]);
    for (i = 0; i < g_nprov; i++) UN(BCryptUnregisterProvider)(g_prov[i]);
    g_nctx = g_nprov = 0;
}

static void sweep(void) {
    static WCHAR l[512][96]; int i, n;
    n = cfg_enum_ctx(CRYPT_LOCAL, l, 512, NULL);
    for (i = 0; i < n; i++) if (!wcsncmp(l[i], L"cryptt_", 7)) U(BCryptDeleteContext)(CRYPT_LOCAL, l[i]);
    n = cfg_enum_registered(l, 512, NULL);
    for (i = 0; i < n; i++) if (!wcsncmp(l[i], L"cryptt_", 7)) UN(BCryptUnregisterProvider)(l[i]);
}

int cfg_begin(void) {
    if (!U(BCryptCreateContext)) { t_skip("missing export: BCryptCreateContext"); return 0; }
    if (!cfg_is_elevated()) { t_skip("not elevated: HKLM CNG configuration is admin-only"); return 0; }
    if (t_is_wine()) { t_skip("emulator has no CNG configuration driver"); return 0; }
    if (!g_atexit) { g_atexit = 1; atexit(cfg_cleanup_all); }
    if (!g_swept) { g_swept = 1; sweep(); }
    return 1;
}
