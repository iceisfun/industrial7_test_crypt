/* Shared helpers for the gap_00 area. Everything is resolved through U()/UIN(). */
#ifndef GAP0_H
#define GAP0_H
#include "t.h"
#include <wincrypt.h>
#include "gap0_data.h"

#define G0_ENC (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING)
#define G0_E_INVALIDARG 0x80070057u
#define G0_CRYPT_E_NOT_FOUND 0x80092004u
#define G0_CRYPT_E_NOT_IN_REVOCATION_DATABASE 0x80092014u
#define G0_NTE_BAD_ALGID 0x80090008u
#define G0_CRYPT_E_INVALID_MSG_TYPE 0x80091004u
#define G0_CRYPT_E_HASH_VALUE 0x80091007u

/* The embedded self-signed certificate (no AIA, no CDP). Caller frees with CertFreeCertificateContext. */
static PCCERT_CONTEXT g0_ss_cert(void) {
    return U(CertCreateCertificateContext)(G0_ENC, gap0_ss_cert, sizeof gap0_ss_cert);
}

/* Chain for the self-signed certificate, offline-only retrieval. */
static PCCERT_CHAIN_CONTEXT g0_ss_chain(void) {
    PCCERT_CONTEXT c = g0_ss_cert();
    PCCERT_CHAIN_CONTEXT ch = NULL;
    if (!c) return NULL;
    CERT_CHAIN_PARA para; memset(&para, 0, sizeof para); para.cbSize = sizeof para;
    if (!U(CertGetCertificateChain)(NULL, c, NULL, NULL, &para, CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL, NULL, &ch)) ch = NULL;
    U(CertFreeCertificateContext)(c);
    return ch;
}
#endif
