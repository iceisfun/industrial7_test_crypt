/* Shared helpers for crypt32_pfx_pkcs8. Every crypt32 entry point is resolved through GetProcAddress. */
#ifndef PP_H
#define PP_H
#include "t.h"
#include <wincrypt.h>
#include "fixtures.h"

/* the emulator's PFXVerifyPassword is a stub that always fails */
#define PP_WINE_NO_VERIFY() do { if (t_is_wine()) { t_skip("emulator stubs PFXVerifyPassword"); return; } } while (0)
#define PP_FIX(a) pp_blob_of(a, sizeof(a))
#define PP_ERR_INVALID_PASSWORD 86
#ifndef PKCS12_IMPORT_SILENT
#define PKCS12_IMPORT_SILENT 0x40
#endif
/* flag values of the private verify path used by PFXVerifyPassword (seen in the decomp) */
#define PP_VERIFY_ONLY 0x10000000

static inline CRYPT_DATA_BLOB pp_blob_of(const BYTE *p, size_t n) {
    CRYPT_DATA_BLOB b; b.cbData = (DWORD)n; b.pbData = (BYTE *)p; return b;
}

/* PFXExportCertStore2 / I_PFX* are not in the SDK headers. */
typedef struct pp_alg_and_param {
    const char *pszObjId; LPCWSTR pwszPassword; int cbPassword; const DWORD *pIterations; int dwType;
} pp_alg_and_param;
UDECL(BOOL, PFXExportCertStore2, (HCERTSTORE, CRYPT_DATA_BLOB *, pp_alg_and_param *, DWORD));
UDECL(HCERTSTORE, I_PFXImportCertStoreEx, (HWND, CRYPT_DATA_BLOB *, LPCWSTR, DWORD, void *));
UDECL(BOOL, I_PFXHMAC, (void));
UDECL(BOOL, I_PFXDecrypt, (void));

/* Import with PKCS12_NO_PERSIST_KEY | PKCS12_IMPORT_SILENT unless told otherwise. */
static inline HCERTSTORE pp_import(const BYTE *p, size_t n, LPCWSTR pw, DWORD flags) {
    CRYPT_DATA_BLOB b = pp_blob_of(p, n);
    return U(PFXImportCertStore)(&b, pw, flags);
}
#define PP_IMPORT(fx, pw, fl) pp_import(fx, sizeof(fx), pw, fl)
#define PP_NP (PKCS12_NO_PERSIST_KEY | PKCS12_IMPORT_SILENT)

static inline int pp_count(HCERTSTORE s) {
    int n = 0; PCCERT_CONTEXT c = NULL;
    if (!s) return -1;
    while ((c = U(CertEnumCertificatesInStore)(s, c)) != NULL) n++;
    return n;
}
static inline void pp_close(HCERTSTORE s) { if (s) U(CertCloseStore)(s, 0); }
/* first context whose encoded bytes equal der (caller frees) */
static inline PCCERT_CONTEXT pp_find_der(HCERTSTORE s, const BYTE *der, size_t n) {
    PCCERT_CONTEXT c = NULL;
    while ((c = U(CertEnumCertificatesInStore)(s, c)) != NULL)
        if (c->cbCertEncoded == n && !memcmp(c->pbCertEncoded, der, n)) return c;
    return NULL;
}
static inline PCCERT_CONTEXT pp_first_with_key(HCERTSTORE s) {
    PCCERT_CONTEXT c = NULL; DWORD cb;
    while ((c = U(CertEnumCertificatesInStore)(s, c)) != NULL) {
        cb = 0;
        if (U(CertGetCertificateContextProperty)(c, CERT_KEY_PROV_INFO_PROP_ID, NULL, &cb)) return c;
        cb = 0;
        if (U(CertGetCertificateContextProperty)(c, CERT_KEY_CONTEXT_PROP_ID, NULL, &cb)) return c;
    }
    return NULL;
}
static inline BOOL pp_has_prop(PCCERT_CONTEXT c, DWORD id, DWORD *pcb) {
    DWORD cb = 0; BOOL r = U(CertGetCertificateContextProperty)(c, id, NULL, &cb);
    if (pcb) *pcb = cb; return r;
}
/* friendly name of cert, "" when absent */
static inline BOOL pp_friendly(PCCERT_CONTEXT c, WCHAR *out, DWORD cch) {
    DWORD cb = cch * sizeof(WCHAR);
    return U(CertGetCertificateContextProperty)(c, CERT_FRIENDLY_NAME_PROP_ID, out, &cb);
}
static inline int pp_has_friendly(PCCERT_CONTEXT c, const WCHAR *want) {
    WCHAR b[128]; if (!pp_friendly(c, b, 128)) return 0; return !lstrcmpW(b, want);
}
/* export to allocated blob via PFXExportCertStoreEx; returns TRUE, caller LocalFree(out->pbData) */
static inline BOOL pp_export_ex(HCERTSTORE s, CRYPT_DATA_BLOB *out, LPCWSTR pw, void *rsv, DWORD fl) {
    out->cbData = 0; out->pbData = NULL;
    if (!U(PFXExportCertStoreEx)(s, out, pw, rsv, fl)) return FALSE;
    out->pbData = (BYTE *)LocalAlloc(LPTR, out->cbData ? out->cbData : 1);
    if (!out->pbData) return FALSE;
    if (!U(PFXExportCertStoreEx)(s, out, pw, rsv, fl)) { LocalFree(out->pbData); out->pbData = NULL; return FALSE; }
    return TRUE;
}
static inline BOOL pp_export(HCERTSTORE s, CRYPT_DATA_BLOB *out, LPCWSTR pw, DWORD fl) {
    out->cbData = 0; out->pbData = NULL;
    if (!U(PFXExportCertStore)(s, out, pw, fl)) return FALSE;
    out->pbData = (BYTE *)LocalAlloc(LPTR, out->cbData ? out->cbData : 1);
    if (!out->pbData) return FALSE;
    if (!U(PFXExportCertStore)(s, out, pw, fl)) { LocalFree(out->pbData); out->pbData = NULL; return FALSE; }
    return TRUE;
}
/* memory store with the given DER certs */
static inline HCERTSTORE pp_memstore(void) { return U(CertOpenStore)(CERT_STORE_PROV_MEMORY, 0, 0, CERT_STORE_CREATE_NEW_FLAG, NULL); }
#endif
