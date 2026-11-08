/* Shared helpers for ncrypt_browser_paths: the NCrypt calls a browser makes (provider open/enum, ephemeral ECDSA P-256 and
 * RSA 2048 keys, sign/verify, properties, public key blobs, opaque transport export). Ephemeral keys only (NULL key name):
 * nothing is persisted. Expectations written OBS(n, call, UNK) while probing; Windows 10 values replace UNK. */
#ifndef BP_H
#define BP_H
#include "t.h"
#include <bcrypt.h>
#include <ncrypt.h>

#define UNK 0x5EED5EED5EED5EEDull
static void obs_(int n, ULONG_PTR got, unsigned long long want, const char *file, int line, const char *expr)
{
    if (want == UNK) t_note("OBS %d 0x%llx", n, (unsigned long long)got);
    else t_expect_eq(got, (ULONG_PTR)want, 0, file, line, expr);
}
#define OBS(n, expr, want)  T_TRY_BEGIN obs_((n), (DWORD)(expr), (want), __FILE__, __LINE__, #expr); T_TRY_END(#expr)
/* the call faults (Windows 10 does not validate the handle pointer) */
#define OBSF(n, expr)       T_EXPECT_FAULT((void)(expr))
/* looped check: expectation for the k-th execution comes from the table VT_<n> */
#define OBSV(n, expr)       do { static int c_##n; T_TRY_BEGIN obs_((n), (DWORD)(expr), VT_##n[c_##n], __FILE__, __LINE__, #expr); T_TRY_END(#expr) c_##n++; } while (0)
#define OBSN(n, expr)       t_note("OBSN %d 0x%llx", (n), (unsigned long long)(ULONG_PTR)(expr))

#define BP_NEED() do { if (t_is_wine()) { t_skip("ncrypt key storage is not faithful under the emulator"); return; } } while (0)

static const WCHAR BP_KSP[] = L"Microsoft Software Key Storage Provider";
static NCRYPT_PROV_HANDLE bp_prov(void) {
    NCRYPT_PROV_HANDLE h = 0;
    if (!U(NCryptOpenStorageProvider)) return 0;
    if (!t_require(U(NCryptOpenStorageProvider)(&h, BP_KSP, 0) == 0 && h, __FILE__, __LINE__, "NCryptOpenStorageProvider")) return 0;
    return h;
}
static void bp_free(NCRYPT_HANDLE h) { if (h) U(NCryptFreeObject)(h); }
/* ephemeral key: NULL name; length 0 = default; finalize */
static NCRYPT_KEY_HANDLE bp_key(NCRYPT_PROV_HANDLE p, LPCWSTR alg, DWORD bits, DWORD expol, DWORD usage, int finalize) {
    NCRYPT_KEY_HANDLE k = 0;
    if (U(NCryptCreatePersistedKey)(p, &k, alg, NULL, 0, 0) != 0) return 0;
    if (bits) U(NCryptSetProperty)(k, L"Length", (PBYTE)&bits, 4, 0);
    if (expol) U(NCryptSetProperty)(k, L"Export Policy", (PBYTE)&expol, 4, 0);
    if (usage) U(NCryptSetProperty)(k, L"Key Usage", (PBYTE)&usage, 4, 0);
    if (finalize && U(NCryptFinalizeKey)(k, 0) != 0) { U(NCryptFreeObject)(k); return 0; }
    return k;
}
static void bp_digest(BYTE *d, DWORD n) { DWORD i; for (i = 0; i < n; i++) d[i] = (BYTE)(i * 7 + 3); }
#endif
