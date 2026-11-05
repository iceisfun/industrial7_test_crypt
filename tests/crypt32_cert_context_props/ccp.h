/* Shared helpers for crypt32_cert_context_props. Every crypt32 entry point is resolved by
 * GetProcAddress (C32()); trivial scaffolding (LocalFree, GetLastError) may be direct. */
#ifndef CCP_H
#define CCP_H
#include "t.h"
#include <wincrypt.h>
#include <ncrypt.h>
#include "fixtures.h"

#define C32(name)  UIN("crypt32.dll", name)
#define ADV(name)  UIN("advapi32.dll", name)
#define NCR(name)  UIN("ncrypt.dll", name)

#define ENC X509_ASN_ENCODING
#define ENC_P7 (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING)
#define E_INVALIDARG_ ((DWORD)0x80070057)
#define CRYPT_E_NOT_FOUND_ ((DWORD)0x80092004)
#define CRYPT_E_EXISTS_ ((DWORD)0x80092005)
#define CRYPT_E_NO_KEY_PROPERTY_ ((DWORD)0x8009200B)
#define CRYPT_E_ASN1_FIRST ((DWORD)0x80093100)
#define CRYPT_E_ASN1_LAST ((DWORD)0x800931FF)
#define NTE_BAD_ALGID_ ((DWORD)0x80090008)
#define NTE_BAD_KEY_ ((DWORD)0x8009000B)
#define NTE_BAD_SIGNATURE_ ((DWORD)0x80090006)
#define NTE_BAD_FLAGS_ ((DWORD)0x80090009)
#define NTE_BAD_ALGID_ ((DWORD)0x80090008)
#define CRYPT_E_SECURITY_SETTINGS_ ((DWORD)0x80092026)
#define CRYPT_E_ASN1_BADTAG_ ((DWORD)0x8009310B)
#define NTE_NO_KEY_ ((DWORD)0x8009000D)

static inline int is_asn1_err(DWORD e) { return e >= CRYPT_E_ASN1_FIRST && e <= CRYPT_E_ASN1_LAST; }
#define EXPECT_ASN1_ERR() do { DWORD e_ = GetLastError(); \
    t_check(is_asn1_err(e_), __FILE__, __LINE__, "CRYPT_E_ASN1_*", "GetLastError got 0x%lx", e_); } while (0)

/* FILETIME from a calendar date (UTC), via trivial kernel32 scaffolding. */
static inline FILETIME ft_ymd(int y, int m, int d) {
    SYSTEMTIME st; FILETIME ft;
    memset(&st, 0, sizeof st); st.wYear = y; st.wMonth = m; st.wDay = d;
    SystemTimeToFileTime(&st, &ft); return ft;
}

/* All fixtures, for table driven tests. */
extern const FX *const ccp_all[];
extern const int ccp_nall;

/* Create a certificate context from a fixture (NULL on failure). */
static inline PCCERT_CONTEXT ccp_ctx(const FX *f) { return C32(CertCreateCertificateContext)(ENC, f->der, f->cb); }
static inline void ccp_free(PCCERT_CONTEXT c) { if (c) C32(CertFreeCertificateContext)(c); }
static inline HCERTSTORE ccp_mem(void) { return C32(CertOpenStore)(CERT_STORE_PROV_MEMORY, 0, 0, 0, NULL); }
static inline void ccp_close(HCERTSTORE s) { if (s) C32(CertCloseStore)(s, 0); }
/* Add a fixture to a store (ADD_ALWAYS); returns the store's context (caller frees) or NULL. */
static inline PCCERT_CONTEXT ccp_add(HCERTSTORE s, const FX *f) {
    PCCERT_CONTEXT c = NULL;
    if (!C32(CertAddEncodedCertificateToStore)(s, ENC, f->der, f->cb, CERT_STORE_ADD_ALWAYS, &c)) return NULL;
    return c;
}
/* Serial comparison: CERT_INFO keeps the DER 00 pad octet of a serial whose top bit is set (observed on Win10). */
static inline int ccp_serial_ok(const CRYPT_INTEGER_BLOB *b, const FX *f) {
    DWORD n = f->cbSerial;
    if (n && (f->serial_le[n - 1] & 0x80)) return b->cbData == n + 1 && b->pbData[n] == 0 && !memcmp(b->pbData, f->serial_le, n);
    return b->cbData == n && !memcmp(b->pbData, f->serial_le, n);
}
static inline int blob_eq(const CRYPT_DATA_BLOB *b, const BYTE *p, DWORD n) { return b->cbData == n && (n == 0 || !memcmp(b->pbData, p, n)); }
/* Read a property into a fixed buffer. Returns BOOL; *cb gets the length. */
static inline BOOL ccp_getprop(PCCERT_CONTEXT c, DWORD id, void *buf, DWORD *cb) { return C32(CertGetCertificateContextProperty)(c, id, buf, cb); }
#endif
