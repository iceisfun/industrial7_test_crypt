/* Shared fixtures for the persisted-key area. Every call into the DLLs goes through GetProcAddress. */
#ifndef DXK_H
#define DXK_H
#include "t.h"
#include <ncrypt.h>
#include <wincrypt.h>
#include <stdlib.h>
#include <wchar.h>

#define S(x) ((DWORD)(x))
#define EXPECT_S(a, b) do { DWORD a_ = S(a), b_ = S(b); t_check(a_ == b_, __FILE__, __LINE__, #a " == " #b, "got 0x%08lx want 0x%08lx", a_, b_); } while (0)
#define KPFX L"cryptt_"
#define KSP MS_KEY_STORAGE_PROVIDER
#define PN L"cryptt_%lu_%ls"

static inline void k_name(WCHAR *out, size_t n, const WCHAR *tag)
{ _snwprintf(out, n, PN, GetCurrentProcessId(), tag); out[n - 1] = 0; }

static inline int k_is_admin(void)
{
    HANDLE tok; TOKEN_ELEVATION el; DWORD cb = 0; int r = 0;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) return 0;
    if (GetTokenInformation(tok, TokenElevation, &el, sizeof el, &cb)) r = el.TokenIsElevated != 0;
    CloseHandle(tok); return r;
}

static inline SECURITY_STATUS k_prov(NCRYPT_PROV_HANDLE *h)
{ return U(NCryptOpenStorageProvider)(h, KSP, 0); }
static inline void k_free(ULONG_PTR h) { if (h) U(NCryptFreeObject)(h); }

/* Delete a key by name (user or machine store). Returns the NCryptOpenKey/Delete status. */
static inline SECURITY_STATUS k_del(NCRYPT_PROV_HANDLE p, const WCHAR *name, DWORD scope)
{
    NCRYPT_KEY_HANDLE k = 0;
    SECURITY_STATUS s = U(NCryptOpenKey)(p, &k, name, 0, scope | NCRYPT_SILENT_FLAG);
    if (s) return s;
    s = U(NCryptDeleteKey)(k, NCRYPT_SILENT_FLAG);
    if (s) k_free(k);
    return s;
}

/* Delete every key whose name starts with prefix (pid==0: any pid). */
static inline void k_sweep(NCRYPT_PROV_HANDLE p, DWORD scope, int this_pid_only)
{
    WCHAR *names[256]; int n = 0, i; PVOID st = NULL; NCryptKeyName *kn;
    WCHAR pre[64]; _snwprintf(pre, 64, L"cryptt_%lu_", GetCurrentProcessId());
    for (;;) {
        SECURITY_STATUS s = U(NCryptEnumKeys)(p, NULL, &kn, &st, scope | NCRYPT_SILENT_FLAG);
        if (s) break;
        if (!wcsncmp(kn->pszName, KPFX, 7) && (!this_pid_only || !wcsncmp(kn->pszName, pre, wcslen(pre))) && n < 256)
            names[n++] = _wcsdup(kn->pszName);
        U(NCryptFreeBuffer)(kn);
    }
    if (st) U(NCryptFreeBuffer)(st);
    for (i = 0; i < n; i++) { k_del(p, names[i], scope); free(names[i]); }
}

static void k_atexit(void)
{
    NCRYPT_PROV_HANDLE p;
    if (!U(NCryptOpenStorageProvider) || k_prov(&p)) return;
    k_sweep(p, 0, 1);
    if (k_is_admin()) k_sweep(p, NCRYPT_MACHINE_KEY_FLAG, 1);
    k_free(p);
}
static int k_inited;
/* Opens the provider; sweeps leftovers once per process; registers exit cleanup. Returns 0 on success. */
static inline SECURITY_STATUS k_begin(NCRYPT_PROV_HANDLE *p)
{
    SECURITY_STATUS s = k_prov(p);
    if (s) return s;
    if (!k_inited) {
        k_inited = 1;
        k_sweep(*p, 0, 0);
        if (k_is_admin()) k_sweep(*p, NCRYPT_MACHINE_KEY_FLAG, 0);
        atexit(k_atexit);
    }
    return 0;
}
/* Create (+ optionally set bits) and finalize a persisted key. */
static inline SECURITY_STATUS k_make(NCRYPT_PROV_HANDLE p, const WCHAR *name, const WCHAR *alg, DWORD bits, DWORD spec, DWORD cflags, NCRYPT_KEY_HANDLE *out)
{
    NCRYPT_KEY_HANDLE k = 0;
    SECURITY_STATUS s = U(NCryptCreatePersistedKey)(p, &k, alg, name, spec, cflags);
    if (s) return s;
    if (bits) U(NCryptSetProperty)(k, NCRYPT_LENGTH_PROPERTY, (PBYTE)&bits, 4, 0);
    s = U(NCryptFinalizeKey)(k, NCRYPT_SILENT_FLAG);
    if (s) { k_free(k); return s; }
    if (out) *out = k; else k_free(k);
    return 0;
}
#define K_NEEDS() if (t_is_wine()) { t_skip("emulator ncrypt has no persistent key storage; validation semantics differ"); return; } REQUIRE(U(NCryptOpenStorageProvider)); REQUIRE(U(NCryptCreatePersistedKey)); \
    REQUIRE(U(NCryptOpenKey)); REQUIRE(U(NCryptDeleteKey)); REQUIRE(U(NCryptEnumKeys)); \
    REQUIRE(U(NCryptFreeObject)); REQUIRE(U(NCryptFreeBuffer)); REQUIRE(U(NCryptFinalizeKey)); \
    REQUIRE(U(NCryptSetProperty)); REQUIRE(U(NCryptGetProperty))
#define K_BEGIN(p) NCRYPT_PROV_HANDLE p = 0; do { K_NEEDS(); SECURITY_STATUS sb_ = k_begin(&p); \
    if (sb_) { t_skip("cannot open software KSP: 0x%08lx", S(sb_)); return; } } while (0)

#define KP_BEGIN(p) K_BEGIN(p); if (t_is_wine()) { t_skip("persistent KSP storage not implemented"); return; }

static inline int k_has_name(NCRYPT_PROV_HANDLE p, DWORD scope, const WCHAR *name, NCryptKeyName *copy_out)
{
    PVOID st = NULL; NCryptKeyName *kn; int found = 0;
    while (!U(NCryptEnumKeys)(p, NULL, &kn, &st, scope | NCRYPT_SILENT_FLAG)) {
        if (!lstrcmpiW(kn->pszName, name)) { found = 1; if (copy_out) { *copy_out = *kn; copy_out->pszName = copy_out->pszAlgid = NULL;
            copy_out->dwFlags = kn->dwFlags; copy_out->dwLegacyKeySpec = kn->dwLegacyKeySpec; } }
        U(NCryptFreeBuffer)(kn);
    }
    if (st) U(NCryptFreeBuffer)(st);
    return found;
}
#endif
