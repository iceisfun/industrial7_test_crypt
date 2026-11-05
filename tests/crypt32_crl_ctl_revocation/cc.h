/* Shared helpers for crypt32_crl_ctl_revocation. All DLL calls go through U() (GetProcAddress). */
#ifndef CC_H
#define CC_H
#include "t.h"
#include <wincrypt.h>
#include "vectors.h"

#define VEC(x) (x), (DWORD)sizeof(x)
#define CC_PROP_CERT 32
#define CC_PROP_CRL 33
#define CC_PROP_CTL 34
#define CC_X509 X509_ASN_ENCODING
#define CC_X509P7 (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING)
#define CC_E_INVALIDARG ((DWORD)0x80070057)
#define CC_E_NOT_FOUND  ((DWORD)0x80092004)
#define CC_E_EXISTS     ((DWORD)0x80092005)
#define CC_E_EOD        ((DWORD)0x80093102)
#define CC_E_NO_REVOCATION_CHECK ((DWORD)0x80092012)
#define CC_E_REVOCATION_OFFLINE  ((DWORD)0x80092013)
#define CC_E_NO_MATCH   ((DWORD)0x80092009)
#define CC_E_BAD_MSG    ((DWORD)0x8009200D)
#define CC_E_NOT_IN_REVOCATION_DATABASE ((DWORD)0x80092011)

HCERTSTORE cc_store(void);                 /* fresh memory store (CertOpenStore) */
void cc_close(HCERTSTORE s);
PCCRL_CONTEXT cc_crl(const BYTE *p, DWORD n);
PCCERT_CONTEXT cc_cert(const BYTE *p, DWORD n);
PCCTL_CONTEXT cc_ctl(const BYTE *p, DWORD n);
int cc_count_crls(HCERTSTORE s);
int cc_count_ctls(HCERTSTORE s);
int cc_count_certs(HCERTSTORE s);
BOOL cc_add_crl(HCERTSTORE s, const BYTE *p, DWORD n, DWORD disp, PCCRL_CONTEXT *out);
BOOL cc_add_ctl(HCERTSTORE s, const BYTE *p, DWORD n, DWORD disp, PCCTL_CONTEXT *out);
ULONGLONG cc_ft(FILETIME f);
BOOL cc_hash(ALG_ID alg, const BYTE *p, DWORD n, BYTE *out, DWORD *cb);
int cc_props_crl(PCCRL_CONTEXT c);
int cc_props_ctl(PCCTL_CONTEXT c);
/* Ephemeral signer: imports v_signer_keyblob into a VERIFYCONTEXT RSA provider. */
BOOL cc_signer(HCRYPTPROV *prov, PCCERT_CONTEXT *cert);
void cc_signer_free(HCRYPTPROV prov, PCCERT_CONTEXT cert);
/* Build a signed CTL (CryptMsgEncodeAndSignCTL). Caller LocalFree()s result. */
BYTE *cc_sign_ctl(PCTL_INFO info, DWORD flags, DWORD *cb);
#endif
