/* Shared helpers for the crypt32 certificate store tests. Every crypt32 call goes through U(). */
#ifndef SM_H
#define SM_H
#include "t.h"
#include <wincrypt.h>
#include "vectors.h"

#define ENC (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING)
#define VEC(a) (a), (DWORD)sizeof(a)
#define HR_NOT_FOUND ((DWORD)0x80092004)   /* CRYPT_E_NOT_FOUND */
#define HR_EXISTS    ((DWORD)0x80092005)   /* CRYPT_E_EXISTS */
#define HR_PENDING   ((DWORD)0x8009200F)   /* CRYPT_E_PENDING_CLOSE */
#define HR_INVALIDARG ((DWORD)0x80070057)
#define HR_MALFORMED ((DWORD)0x800B0108)   /* CERT_E_MALFORMED */
#define DISP_NEW 1
#define DISP_USE 2
#define DISP_REPL 3
#define DISP_ALWAYS 4
#define DISP_REPL_INH 5
#define DISP_NEWER 6
#define DISP_NEWER_INH 7

static HCERTSTORE sm_mem(void) { return U(CertOpenStore)(CERT_STORE_PROV_MEMORY, 0, 0, 0, NULL); }
static void sm_close(HCERTSTORE h) { if (h) U(CertCloseStore)(h, 0); }

static int sm_ncerts(HCERTSTORE h) {
    int n = 0; PCCERT_CONTEXT c = NULL;
    while ((c = U(CertEnumCertificatesInStore)(h, c)) != NULL) n++;
    return n;
}
static int sm_ncrls(HCERTSTORE h) {
    int n = 0; PCCRL_CONTEXT c = NULL;
    while ((c = U(CertEnumCRLsInStore)(h, c)) != NULL) n++;
    return n;
}
static int sm_nctls(HCERTSTORE h) {
    int n = 0; PCCTL_CONTEXT c = NULL;
    while ((c = U(CertEnumCTLsInStore)(h, c)) != NULL) n++;
    return n;
}
/* Add a DER certificate; returns TRUE/FALSE, context (if requested) is returned in *out (caller frees). */
static BOOL sm_addc(HCERTSTORE h, const BYTE *p, DWORD n, DWORD disp, PCCERT_CONTEXT *out) {
    return U(CertAddEncodedCertificateToStore)(h, X509_ASN_ENCODING, p, n, disp, out);
}
static BOOL sm_addcrl(HCERTSTORE h, const BYTE *p, DWORD n, DWORD disp, PCCRL_CONTEXT *out) {
    return U(CertAddEncodedCRLToStore)(h, X509_ASN_ENCODING, p, n, disp, out);
}
static BOOL sm_addctl(HCERTSTORE h, const BYTE *p, DWORD n, DWORD disp, PCCTL_CONTEXT *out) {
    return U(CertAddEncodedCTLToStore)(h, X509_ASN_ENCODING, p, n, disp, out);
}
static void sm_freec(PCCERT_CONTEXT c) { if (c) U(CertFreeCertificateContext)(c); }
static int sm_same_enc(PCCERT_CONTEXT c, const BYTE *p, DWORD n) {
    return c && c->cbCertEncoded == n && !memcmp(c->pbCertEncoded, p, n);
}
/* A store with certs A, B, C. */
static HCERTSTORE sm_abc(void) {
    HCERTSTORE h = sm_mem();
    if (!h) return NULL;
    sm_addc(h, VEC(v_cert_a), DISP_NEW, NULL);
    sm_addc(h, VEC(v_cert_b), DISP_NEW, NULL);
    sm_addc(h, VEC(v_cert_c), DISP_NEW, NULL);
    return h;
}
/* Open a serialized store/PKCS7 etc. from memory. */
#endif
