/* Shared declarations/helpers for the DPAPI-NG (ncrypt protection descriptor) tests.
 * None of these APIs are in the mingw headers, so every entry point is declared here and resolved
 * with GetProcAddress through UN(). */
#ifndef NPD_H
#define NPD_H
#include "t.h"
#include <stdlib.h>

#define NPD_NTE_BAD_FLAGS       0x80090009u
#define NPD_NTE_BAD_DATA        0x80090005u
#define NPD_NTE_NO_MEMORY       0x8009000Eu
#define NPD_NTE_NOT_FOUND       0x80090011u
#define NPD_NTE_INVALID_HANDLE  0x80090026u
#define NPD_NTE_INVALID_PARAM   0x80090027u
#define NPD_NTE_NOT_SUPPORTED   0x80090029u
#define NPD_HR_FILE_NOT_FOUND   0x80070002u
#define NPD_HR_MORE_DATA        0x800700EAu

#define NPD_NAMED_FLAG          0x1u
#define NPD_MACHINE_FLAG        0x20u
#define NPD_SILENT_FLAG         0x40u
#define NPD_UNPROTECT_NO_DECRYPT 0x1u
#define NPD_INFO_DESCRIPTOR_STRING 1

typedef PVOID (WINAPI *npd_alloc_fn)(SIZE_T);
typedef void  (WINAPI *npd_free_fn)(PVOID);
typedef struct { DWORD cbSize; npd_alloc_fn pfnAlloc; npd_free_fn pfnFree; } NPD_ALLOC_PARA;
typedef LONG (WINAPI *npd_stream_cb)(void *ctx, const BYTE *data, SIZE_T cb, BOOL final);
typedef struct { npd_stream_cb pfnStreamOutput; void *pvCallbackCtxt; } NPD_STREAM_INFO;
/* Ex callback: extra descriptor handle argument BEFORE fFinal (PFNCryptStreamOutputCallbackEx) */
typedef LONG (WINAPI *npd_stream_cb_ex)(void *ctx, const BYTE *data, SIZE_T cb, void *hDescriptor, BOOL final);
typedef struct { npd_stream_cb_ex pfnStreamOutput; void *pvCallbackCtxt; } NPD_STREAM_INFO_EX;

UDECL(LONG, NCryptCreateProtectionDescriptor, (LPCWSTR, DWORD, void **));
UDECL(LONG, NCryptCloseProtectionDescriptor, (void *));
UDECL(LONG, NCryptGetProtectionDescriptorInfo, (void *, const NPD_ALLOC_PARA *, DWORD, void **));
UDECL(LONG, NCryptRegisterProtectionDescriptorName, (LPCWSTR, LPCWSTR, DWORD));
UDECL(LONG, NCryptQueryProtectionDescriptorName, (LPCWSTR, PWSTR, SIZE_T *, DWORD));
UDECL(LONG, NCryptProtectSecret, (void *, DWORD, const BYTE *, ULONG, const NPD_ALLOC_PARA *, HWND, BYTE **, ULONG *));
UDECL(LONG, NCryptUnprotectSecret, (void **, DWORD, const BYTE *, ULONG, const NPD_ALLOC_PARA *, HWND, BYTE **, ULONG *));
UDECL(LONG, NCryptStreamOpenToProtect, (void *, DWORD, HWND, NPD_STREAM_INFO *, void **));
UDECL(LONG, NCryptStreamOpenToUnprotect, (NPD_STREAM_INFO *, DWORD, HWND, void **));
UDECL(LONG, NCryptStreamOpenToUnprotectEx, (NPD_STREAM_INFO_EX *, DWORD, HWND, void **));
UDECL(LONG, NCryptStreamUpdate, (void *, const BYTE *, SIZE_T, BOOL));
UDECL(LONG, NCryptStreamClose, (void *));
UDECL(LONG, NCryptProtectKey, (void *, void *, void *, DWORD, void *, void *, void *, DWORD));
UDECL(LONG, NCryptUnprotectKey, (void *, void *, void *, void *, void *, void *, DWORD));
UDECL(LONG, NCryptOpenKeyProtector, (void **, LPCWSTR, DWORD));
UDECL(LONG, NCryptCloseKeyProtector, (void *));
UDECL(LONG, NCryptDuplicateKeyProtectorHandle, (void *, void **, DWORD));
UDECL(LONG, NCryptCreateClaim, (ULONG_PTR, ULONG_PTR, DWORD, void *, BYTE *, DWORD, DWORD *, DWORD));
UDECL(LONG, NCryptVerifyClaim, (ULONG_PTR, ULONG_PTR, DWORD, void *, BYTE *, DWORD, void *, DWORD));
UDECL(LONG, NCryptOpenStorageProvider, (ULONG_PTR *, LPCWSTR, DWORD));
UDECL(LONG, NCryptCreatePersistedKey, (ULONG_PTR, ULONG_PTR *, LPCWSTR, LPCWSTR, DWORD, DWORD));
UDECL(LONG, NCryptFreeObject, (ULONG_PTR));

/* Wine exports these as aborting stubs: skip (no-op on Windows) */
#define NREQ(fn) do { if (!(fn)) { t_skip("missing export: " #fn); return; } if (t_is_wine()) { t_skip("not implemented under wine"); return; } } while (0)
#define SS(rc) ((DWORD)(rc))
#define EXPECT_SS(rc, want) EXPECT_EQ((DWORD)(rc), (DWORD)(want))

/* callback sink: collects everything delivered by a stream */
typedef struct {
    BYTE  *buf; size_t len, cap;
    int    calls, final_calls, after_final;
    int    last_final;
    int    notif, notif_bad;   /* Ex: leading descriptor notification (no data); notif_bad if it was not cb==0 with a descriptor */
    size_t first_size;
    LONG   ret;            /* value the callback returns */
    int    fail_at;        /* 1-based call that returns fail_ret instead (0 = never) */
    LONG   fail_ret;
} npd_sink;

static LONG WINAPI npd_cb(void *ctx, const BYTE *p, SIZE_T cb, BOOL fin) {
    npd_sink *s = (npd_sink *)ctx;
    s->calls++;
    if (s->calls == 1) s->first_size = cb;
    if (s->final_calls) s->after_final++;
    if (fin) s->final_calls++;
    s->last_final = fin ? 1 : 0;
    if (cb) {
        if (s->len + cb > s->cap) {
            size_t nc = (s->len + cb) * 2 + 64;
            BYTE *nb = (BYTE *)realloc(s->buf, nc);
            if (!nb) return 0x8007000E;
            s->buf = nb; s->cap = nc;
        }
        memcpy(s->buf + s->len, p, cb);
        s->len += cb;
    }
    if (s->fail_at && s->calls == s->fail_at) return s->fail_ret;
    return s->ret;
}
static LONG WINAPI npd_cb_ex(void *ctx, const BYTE *p, SIZE_T cb, void *hdesc, BOOL fin) {
    npd_sink *s = (npd_sink *)ctx;
    if (!s->notif && !s->calls) {   /* Win10: the first Ex callback is a descriptor notification, not data */
        s->notif = 1;
        if (cb != 0 || !hdesc) s->notif_bad = 1;
        return s->ret;
    }
    return npd_cb(ctx, p, cb, fin);
}
static void npd_sink_free(npd_sink *s) { free(s->buf); memset(s, 0, sizeof *s); }

/* a descriptor from a string, NULL on failure (never NULL-checks the DLL: callers REQUIRE) */
static void *npd_desc(const wchar_t *str) {
    void *h = NULL;
    if (!UN(NCryptCreateProtectionDescriptor) || t_is_wine()) return NULL;
    LONG rc = UN(NCryptCreateProtectionDescriptor)(str, 0, &h);
    return rc == 0 ? h : NULL;
}
static void npd_desc_close(void *h) { if (h) UN(NCryptCloseProtectionDescriptor)(h); }

/* does LOCAL=user protect/unprotect work in this environment? (cached) */
static int npd_works(void) {
    static int state = -1;
    if (state >= 0) return state;
    state = 0;
    if (t_is_wine() || !UN(NCryptProtectSecret) || !UN(NCryptUnprotectSecret)) return 0;
    void *d = npd_desc(L"LOCAL=user");
    if (!d) return 0;
    BYTE in[4] = {1, 2, 3, 4}, *blob = NULL, *out = NULL; ULONG cb = 0, co = 0;
    if (UN(NCryptProtectSecret)(d, NPD_SILENT_FLAG, in, 4, NULL, NULL, &blob, &cb) == 0 && blob) {
        void *d2 = NULL;
        if (UN(NCryptUnprotectSecret)(&d2, NPD_SILENT_FLAG, blob, cb, NULL, NULL, &out, &co) == 0 && out) {
            state = (co == 4 && !memcmp(out, in, 4));
            LocalFree(out);
            npd_desc_close(d2);
        }
        LocalFree(blob);
    }
    npd_desc_close(d);
    return state;
}
/* on Windows 10 LOCAL=user protect/unprotect must work (a failure is counted, not skipped); only an emulator skips */
#define REQUIRE_WORKING() do { if (t_is_wine()) { t_skip("not implemented under wine"); return; } if (!t_require(npd_works(), __FILE__, __LINE__, "LOCAL=user protect/unprotect works")) return; } while (0)

/* length of a DER/BER TLV header + definite content, -1 if not definite or short */
static long npd_der_total(const BYTE *p, size_t n) {
    if (n < 2) return -1;
    if (p[1] < 0x80) return 2 + p[1];
    int nb = p[1] & 0x7f;
    if (nb == 0 || nb > 4 || (size_t)(2 + nb) > n) return -1;
    unsigned long l = 0;
    for (int i = 0; i < nb; i++) l = (l << 8) | p[2 + i];
    return (long)(2 + nb + l);
}

static void npd_fill(BYTE *p, size_t n, unsigned seed) {
    for (size_t i = 0; i < n; i++) { seed = seed * 1103515245u + 12345u; p[i] = (BYTE)(seed >> 16); }
}
#endif
