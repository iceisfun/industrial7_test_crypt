#include "cc.h"

HCERTSTORE cc_store(void) { return U(CertOpenStore)(CERT_STORE_PROV_MEMORY, 0, 0, 0, NULL); }
void cc_close(HCERTSTORE s) { if (s) U(CertCloseStore)(s, 0); }
PCCRL_CONTEXT cc_crl(const BYTE *p, DWORD n) { return U(CertCreateCRLContext)(CC_X509, p, n); }
PCCERT_CONTEXT cc_cert(const BYTE *p, DWORD n) { return U(CertCreateCertificateContext)(CC_X509, p, n); }
PCCTL_CONTEXT cc_ctl(const BYTE *p, DWORD n) { return U(CertCreateCTLContext)(CC_X509, p, n); }

int cc_count_crls(HCERTSTORE s) {
    int n = 0; PCCRL_CONTEXT c = NULL;
    while ((c = U(CertEnumCRLsInStore)(s, c)) != NULL) n++;
    return n;
}
int cc_count_ctls(HCERTSTORE s) {
    int n = 0; PCCTL_CONTEXT c = NULL;
    while ((c = U(CertEnumCTLsInStore)(s, c)) != NULL) n++;
    return n;
}
int cc_count_certs(HCERTSTORE s) {
    int n = 0; PCCERT_CONTEXT c = NULL;
    while ((c = U(CertEnumCertificatesInStore)(s, c)) != NULL) n++;
    return n;
}
BOOL cc_add_crl(HCERTSTORE s, const BYTE *p, DWORD n, DWORD disp, PCCRL_CONTEXT *out) {
    return U(CertAddEncodedCRLToStore)(s, CC_X509, p, n, disp, out);
}
BOOL cc_add_ctl(HCERTSTORE s, const BYTE *p, DWORD n, DWORD disp, PCCTL_CONTEXT *out) {
    return U(CertAddEncodedCTLToStore)(s, CC_X509, p, n, disp, out);
}
ULONGLONG cc_ft(FILETIME f) { return ((ULONGLONG)f.dwHighDateTime << 32) | f.dwLowDateTime; }
BOOL cc_hash(ALG_ID alg, const BYTE *p, DWORD n, BYTE *out, DWORD *cb) {
    return U(CryptHashCertificate)(0, alg, 0, p, n, out, cb);
}
int cc_props_crl(PCCRL_CONTEXT c) {
    int n = 0; DWORD id = 0;
    while ((id = U(CertEnumCRLContextProperties)(c, id)) != 0) n++;
    return n;
}
int cc_props_ctl(PCCTL_CONTEXT c) {
    int n = 0; DWORD id = 0;
    while ((id = U(CertEnumCTLContextProperties)(c, id)) != 0) n++;
    return n;
}

/* Win10: CryptMsg signing with SHA-2 fails (NTE_BAD_ALGID) when the key lives in a VERIFYCONTEXT provider, so the
   signing key is imported into a uniquely named temporary container that cc_signer_free deletes. */
#define CC_MAXPROV 8
static struct { HCRYPTPROV p; wchar_t name[96]; } g_provs[CC_MAXPROV];
BOOL cc_signer(HCRYPTPROV *prov, PCCERT_CONTEXT *cert) {
    HCRYPTKEY key = 0; int slot = -1;
    *prov = 0; *cert = NULL;
    for (int i = 0; i < CC_MAXPROV; i++) if (!g_provs[i].p) { slot = i; break; }
    if (slot < 0) return FALSE;
    const wchar_t *nm = t_unique_w("k");
    if (!U(CryptAcquireContextW)(prov, nm, MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, CRYPT_NEWKEYSET)) { *prov = 0; return FALSE; }
    if (!U(CryptImportKey)(*prov, v_signer_keyblob, sizeof(v_signer_keyblob), 0, 0, &key)) {
        HCRYPTPROV d = 0;
        U(CryptReleaseContext)(*prov, 0); *prov = 0;
        U(CryptAcquireContextW)(&d, nm, MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, CRYPT_DELETEKEYSET);
        return FALSE;
    }
    U(CryptDestroyKey)(key);
    g_provs[slot].p = *prov; wcsncpy(g_provs[slot].name, nm, 95);
    *cert = cc_cert(VEC(v_signer));
    if (!*cert) { cc_signer_free(*prov, NULL); *prov = 0; return FALSE; }
    return TRUE;
}
void cc_signer_free(HCRYPTPROV prov, PCCERT_CONTEXT cert) {
    if (cert) U(CertFreeCertificateContext)(cert);
    if (!prov) return;
    for (int i = 0; i < CC_MAXPROV; i++) if (g_provs[i].p == prov) {
        HCRYPTPROV d = 0;
        g_provs[i].p = 0;
        U(CryptReleaseContext)(prov, 0);
        U(CryptAcquireContextW)(&d, g_provs[i].name, MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, CRYPT_DELETEKEYSET);
        return;
    }
    U(CryptReleaseContext)(prov, 0);
}
BYTE *cc_sign_ctl(PCTL_INFO info, DWORD flags, DWORD *cb) {
    HCRYPTPROV prov; PCCERT_CONTEXT sc; BYTE *buf = NULL;
    CMSG_SIGNER_ENCODE_INFO si; CERT_BLOB cb1; CMSG_SIGNED_ENCODE_INFO se;
    *cb = 0;
    if (!cc_signer(&prov, &sc)) return NULL;
    memset(&si, 0, sizeof si); si.cbSize = sizeof si;
    si.pCertInfo = sc->pCertInfo; si.hCryptProv = prov; si.dwKeySpec = AT_SIGNATURE;
    si.HashAlgorithm.pszObjId = (LPSTR)szOID_NIST_sha256;
    cb1.cbData = sc->cbCertEncoded; cb1.pbData = sc->pbCertEncoded;
    memset(&se, 0, sizeof se); se.cbSize = sizeof se; se.cSigners = 1; se.rgSigners = &si;
    se.cCertEncoded = 1; se.rgCertEncoded = &cb1;
    if (U(CryptMsgEncodeAndSignCTL)(CC_X509P7, info, &se, flags, NULL, cb)) {
        buf = LocalAlloc(LPTR, *cb ? *cb : 1);
        if (buf && !U(CryptMsgEncodeAndSignCTL)(CC_X509P7, info, &se, flags, buf, cb)) { LocalFree(buf); buf = NULL; }
    }
    cc_signer_free(prov, sc);
    return buf;
}
