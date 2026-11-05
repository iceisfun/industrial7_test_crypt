/* Shared helpers for the wintrust_verify_trust area. Every wintrust/crypt32 call goes through U()/UIN()/UN(). */
#ifndef WVT_H
#define WVT_H
#include "t.h"
#include <wincrypt.h>
#include <wintrust.h>
#include <softpub.h>
#include <mssip.h>
#include "fixtures.h"

#ifndef TRUST_E_NOSIGNATURE
#define TRUST_E_NOSIGNATURE ((LONG)0x800B0100)
#endif
#define WVT_E_PROVIDER_UNKNOWN   ((LONG)0x800B0001)
#define WVT_E_NOSIGNATURE        ((LONG)0x800B0100)
#define WVT_E_SUBJECT_FORM       ((LONG)0x800B0003)
#define WVT_E_BAD_DIGEST         ((LONG)0x80096010)
#define WVT_E_CERT_SIGNATURE     ((LONG)0x80096004)
#define WVT_E_UNTRUSTEDROOT      ((LONG)0x800B0109)
#define WVT_E_CHAINING           ((LONG)0x800B010A)
#define WVT_E_FILE_ERROR         ((LONG)0x80092003)
#define WVT_E_INVALIDARG         ((LONG)0x80070057)
#ifndef WTD_DISABLE_MD2_MD4
#define WTD_DISABLE_MD2_MD4 0x00002000
#endif
#define WTD_MOTW_FLAG 0x00004000

/* Windows 10 layout of WINTRUST_DATA (0x58 bytes): the SDK struct plus pSignatureSettings. */
typedef struct { WINTRUST_DATA d; void *pSignatureSettings; } WVTD;
typedef struct { DWORD cbStruct, dwIndex, dwFlags, cSecondarySigs, dwVerifiedSigIndex; void *pCryptoPolicy; } WVT_SIGSET;
/* CRYPT_PROVIDER_DATA on Windows 10 is 0xF0 bytes: SDK fields plus pSigState/pSigSettings. */
typedef struct { CRYPT_PROVIDER_DATA d; void *pSigState; void *pSigSettings; } WVT_PD;

static const GUID WVT_V2      = WINTRUST_ACTION_GENERIC_VERIFY_V2;
static const GUID WVT_CERTV   = WINTRUST_ACTION_GENERIC_CERT_VERIFY;
static const GUID WVT_CHAINV  = WINTRUST_ACTION_GENERIC_CHAIN_VERIFY;
static const GUID WVT_HTTPS   = HTTPSPROV_ACTION;
static const GUID WVT_DRIVER  = DRIVER_ACTION_VERIFY;
static const GUID WVT_TPTEST  = WINTRUST_ACTION_TRUSTPROVIDER_TEST;
static const GUID WVT_PE_SIP  = { 0xC689AAB8, 0x8E78, 0x11D0, { 0x8C, 0x47, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE } };

#define WVT_FN(name) U(name)
#define WVT_REQUIRE_WVT() do { if (!U(WinVerifyTrust) || !U(WinVerifyTrustEx)) { t_skip("WinVerifyTrust missing"); return; } } while (0)

/* Pointer types for functions that are not in the mingw headers. */
UDECL(WCHAR *, WTHelperGetFileName, (void *));
UDECL(HANDLE,  WTHelperGetFileHandle, (void *));
UDECL(BOOL,    WTHelperGetKnownUsages, (DWORD, PCCRYPT_OID_INFO **));
UDECL(BOOL,    WTHelperCheckCertUsage, (PCCERT_CONTEXT, LPCSTR));
UDECL(BOOL,    WTHelperGetAgencyInfo, (PCCERT_CONTEXT, DWORD *, void *));
UDECL(BOOL,    WTHelperIsInRootStore, (CRYPT_PROVIDER_DATA *, PCCERT_CONTEXT));
UDECL(BOOL,    WTHelperOpenKnownStores, (CRYPT_PROVIDER_DATA *));
UDECL(BOOL,    WTHelperCertFindIssuerCertificate, (PCCERT_CONTEXT, DWORD, HCERTSTORE *, DWORD, DWORD, PCCERT_CONTEXT *, DWORD *));
UDECL(BOOL,    TrustIsCertificateSelfSigned, (PCCERT_CONTEXT, DWORD, DWORD));
UDECL(BOOL,    TrustOpenStores, (ULONG_PTR, DWORD *, HCERTSTORE *, DWORD));
UDECL(BOOL,    TrustDecode, (void *, BYTE **, DWORD *, DWORD, DWORD, LPCSTR, const BYTE *, DWORD, DWORD));
UDECL(BOOL,    TrustFreeDecode, (void *, BYTE **));
UDECL(BOOL,    WVTEnc, (DWORD, LPCSTR, const void *, BYTE *, DWORD *));
UDECL(BOOL,    WVTDec, (DWORD, LPCSTR, const BYTE *, DWORD, DWORD, void *, DWORD *));

/* ---- fixtures ---------------------------------------------------------- */
static void wvt_path(WCHAR *out, const char *leaf) {
    char a[MAX_PATH]; t_tmpfile(a, sizeof a, leaf);
    MultiByteToWideChar(CP_ACP, 0, a, -1, out, MAX_PATH);
}
static int wvt_write(const WCHAR *path, const void *data, DWORD n) {
    HANDLE h = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return 0;
    DWORD w = 0; BOOL ok = n == 0 || WriteFile(h, data, n, &w, NULL);
    CloseHandle(h); return ok && w == n;
}
static void wvt_del(const WCHAR *path) { DeleteFileW(path); }

/* Standard WINTRUST_DATA for a file subject, UI none, no revocation, IGNORE state. */
static void wvt_init_file(WVTD *w, WINTRUST_FILE_INFO *fi, const WCHAR *path) {
    memset(w, 0, sizeof *w); memset(fi, 0, sizeof *fi);
    fi->cbStruct = sizeof *fi; fi->pcwszFilePath = path;
    w->d.cbStruct = sizeof *w;
    w->d.dwUIChoice = WTD_UI_NONE; w->d.fdwRevocationChecks = WTD_REVOKE_NONE;
    w->d.dwUnionChoice = WTD_CHOICE_FILE; w->d.pFile = fi;
    w->d.dwStateAction = WTD_STATEACTION_IGNORE;
    w->d.dwProvFlags = WTD_REVOCATION_CHECK_NONE;
}
/* Verify; returns the result, *err receives GetLastError right after the call. */
static LONG wvt_call(const GUID *g, WVTD *w, DWORD *err) {
    SetLastError(0xdeadbeef);
    LONG r = U(WinVerifyTrust)(NULL, (GUID *)g, w);
    if (err) *err = GetLastError();
    return r;
}
static LONG wvt_close(const GUID *g, WVTD *w) {
    w->d.dwStateAction = WTD_STATEACTION_CLOSE;
    return U(WinVerifyTrust)(NULL, (GUID *)g, w);
}
/* Verify an in-memory file image written to a scratch path (IGNORE state). */
static LONG wvt_verify_bytes(const void *img, DWORD n, DWORD provflags, const char *leaf, DWORD *err) {
    WCHAR p[MAX_PATH]; WVTD w; WINTRUST_FILE_INFO fi;
    wvt_path(p, leaf);
    if (!wvt_write(p, img, n)) { t_note("cannot write fixture %s", leaf); return 0x7fffffff; }
    wvt_init_file(&w, &fi, p); w.d.dwProvFlags |= provflags;
    LONG r = wvt_call(&WVT_V2, &w, err);
    wvt_del(p);
    return r;
}
static const char *wvt_hex(const void *p, DWORD n, char *out, size_t cap) {
    static const char H[] = "0123456789abcdef"; DWORD i;
    for (i = 0; i < n && 2 * i + 2 < cap; i++) { out[2*i] = H[((BYTE*)p)[i] >> 4]; out[2*i+1] = H[((BYTE*)p)[i] & 15]; }
    out[2*i] = 0; return out;
}
#endif
