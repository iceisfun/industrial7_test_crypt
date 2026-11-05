#include "ml.h"

const BYTE *ml_memmem(const BYTE *h, size_t hn, const BYTE *n, size_t nn) {
    size_t i;
    if (!nn || hn < nn) return NULL;
    for (i = 0; i + nn <= hn; i++) if (h[i] == n[0] && !memcmp(h + i, n, nn)) return h + i;
    return NULL;
}

/* Win10: CryptMsg signing with SHA-2 fails (NTE_BAD_TYPE) on a VERIFYCONTEXT provider, so the signing key lives in a
   uniquely named temporary container that ml_prov_release deletes. */
#define ML_MAXPROV 16
static struct { HCRYPTPROV p; wchar_t name[96]; } g_provs[ML_MAXPROV];
HCRYPTPROV ml_prov(const BYTE *blob, DWORD cb) {
    HCRYPTPROV p = 0; HCRYPTKEY k = 0; int slot = -1;
    if (!blob) {
        if (!U(CryptAcquireContextW)(&p, NULL, MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) return 0;
        return p;
    }
    for (int i = 0; i < ML_MAXPROV; i++) if (!g_provs[i].p) { slot = i; break; }
    if (slot < 0) return 0;
    const wchar_t *nm = t_unique_w("k");
    if (!U(CryptAcquireContextW)(&p, nm, MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, CRYPT_NEWKEYSET)) return 0;
    if (!U(CryptImportKey)(p, blob, cb, 0, 0, &k)) {
        U(CryptReleaseContext)(p, 0); p = 0;
        U(CryptAcquireContextW)(&p, nm, MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, CRYPT_DELETEKEYSET);
        return 0;
    }
    U(CryptDestroyKey)(k);
    g_provs[slot].p = p; wcsncpy(g_provs[slot].name, nm, 95);
    return p;
}
void ml_prov_release(HCRYPTPROV p) {
    if (!p) return;
    for (int i = 0; i < ML_MAXPROV; i++) if (g_provs[i].p == p) {
        HCRYPTPROV d = 0;
        g_provs[i].p = 0;
        U(CryptReleaseContext)(p, 0);
        U(CryptAcquireContextW)(&d, g_provs[i].name, MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, CRYPT_DELETEKEYSET);
        return;
    }
    U(CryptReleaseContext)(p, 0);
}
PCCERT_CONTEXT ml_cert(const BYTE *der, DWORD cb) { return U(CertCreateCertificateContext)(X509_ASN_ENCODING, der, cb); }
void ml_cert_free(PCCERT_CONTEXT c) { if (c) U(CertFreeCertificateContext)(c); }
void ml_free(void *p) { if (p) LocalFree(p); }

BYTE *ml_param(HCRYPTMSG m, DWORD pt, DWORD idx, DWORD *cb) {
    DWORD n = 0; BYTE *b;
    if (!mGetParam()(m, pt, idx, NULL, &n)) return NULL;
    b = (BYTE *)LocalAlloc(LPTR, n + 16);
    if (!b) return NULL;
    if (!mGetParam()(m, pt, idx, b, &n)) { DWORD e = GetLastError(); LocalFree(b); SetLastError(e); return NULL; }
    if (cb) *cb = n;
    return b;
}
BOOL ml_param_dword(HCRYPTMSG m, DWORD pt, DWORD idx, DWORD *out) {
    DWORD n = sizeof(DWORD), v = 0xCCCCCCCC;
    if (!mGetParam()(m, pt, idx, &v, &n)) return FALSE;
    *out = v; return n == sizeof(DWORD);
}

BYTE *ml_encode_data(DWORD flags, const BYTE *data, DWORD cb, DWORD *out_cb) {
    HCRYPTMSG m = mOpenEnc()(ENC, flags, CMSG_DATA, NULL, NULL, NULL);
    BYTE *r = NULL;
    if (!m) return NULL;
    if (mUpdate()(m, data, cb, TRUE)) r = ml_param(m, CMSG_CONTENT_PARAM, 0, out_cb);
    mClose()(m);
    return r;
}

HCRYPTMSG ml_decode(const BYTE *der, DWORD cb, DWORD type, DWORD flags) {
    HCRYPTMSG m = mOpenDec()(ENC, flags, type, 0, NULL, NULL);
    if (!m) return NULL;
    if (!mUpdate()(m, der, cb, TRUE)) { DWORD e = GetLastError(); mClose()(m); SetLastError(e); return NULL; }
    return m;
}

BOOL ml_signer_init(ml_signer_t *s, const char *hash_oid) {
    memset(s, 0, sizeof *s);
    s->prov = ml_prov(V_KEY1, V_KEY1_LEN);
    s->cert = ml_cert(V_CERT1, V_CERT1_LEN);
    if (!s->prov || !s->cert) return FALSE;
    s->si[0].cbSize = sizeof(CMSG_SIGNER_ENCODE_INFO);
    s->si[0].pCertInfo = s->cert->pCertInfo;
    s->si[0].hCryptProv = s->prov;
    s->si[0].dwKeySpec = AT_KEYEXCHANGE;
    s->si[0].HashAlgorithm.pszObjId = (LPSTR)hash_oid;
    s->se.cbSize = sizeof(CMSG_SIGNED_ENCODE_INFO);
    s->se.cSigners = 1;
    s->se.rgSigners = s->si;
    return TRUE;
}
void ml_signer_done(ml_signer_t *s) {
    ml_cert_free(s->cert); ml_cert_free(s->cert2);
    ml_prov_release(s->prov); ml_prov_release(s->prov2);
}
BYTE *ml_sign(ml_signer_t *s, DWORD flags, const char *hash_oid, const BYTE *data, DWORD cb, DWORD *out_cb) {
    HCRYPTMSG m; BYTE *r = NULL;
    s->si[0].HashAlgorithm.pszObjId = (LPSTR)hash_oid;
    m = mOpenEnc()(ENC, flags, CMSG_SIGNED, &s->se, NULL, NULL);
    if (!m) return NULL;
    if (mUpdate()(m, data, cb, TRUE)) r = ml_param(m, CMSG_CONTENT_PARAM, 0, out_cb);
    mClose()(m);
    return r;
}

/* Skip ContentInfo { OID, [0] EXPLICIT bare }: returns a pointer to the bare content inside der (definite lengths only). */
static const BYTE *tlv(const BYTE *p, const BYTE *end, BYTE tag, const BYTE **body, DWORD *blen) {
    DWORD n; if (p >= end || *p != tag) return NULL;
    p++; if (p >= end) return NULL;
    if (*p < 0x80) { n = *p++; } else { int k = *p++ & 0x7f; n = 0; if (k < 1 || k > 4) return NULL; while (k--) { if (p >= end) return NULL; n = (n << 8) | *p++; } }
    if ((size_t)(end - p) < n) return NULL;
    *body = p; *blen = n; return p + n;
}
const BYTE *ml_unwrap(const BYTE *der, DWORD cb, DWORD *out_cb) {
    const BYTE *b, *b2, *b3; DWORD n, n2, n3;
    if (!tlv(der, der + cb, 0x30, &b, &n)) return NULL;
    if (!(b2 = tlv(b, b + n, 0x06, &b3, &n3))) return NULL;
    if (!tlv(b2, b + n, 0xa0, &b3, &n3)) return NULL;
    *out_cb = n3; return b3;
}
