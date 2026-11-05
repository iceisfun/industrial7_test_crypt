#include "gap1.h"
g1_id g1_A, g1_B;
static int g_state;
static int make_id(g1_id *id, const BYTE *cert, DWORD ccb, const BYTE *key, DWORD kcb) {
    PCCERT_CONTEXT (WINAPI *cc)(DWORD, const BYTE *, DWORD) = (void *)t_proc("CertCreateCertificateContext");
    typeof(&CryptAcquireContextW) acq = U(CryptAcquireContextW);
    typeof(&CryptImportKey) imp = U(CryptImportKey);
    typeof(&CryptDestroyKey) dk = U(CryptDestroyKey);
    if (!cc || !acq || !imp || !dk) return 0;
    id->cert = cc(ENC, cert, ccb);
    if (!id->cert) return 0;
    if (!acq(&id->prov, NULL, MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) return 0;
    HCRYPTKEY k = 0;
    if (!imp(id->prov, key, kcb, 0, 0, &k)) return 0;
    dk(k);
    return 1;
}
int g1_init(void) {
    if (g_state) { if (g_state < 0) t_skip("fixture setup failed"); return g_state > 0; }
    g_state = -1;
    if (!make_id(&g1_A, BLOB(v_certA), BLOB(v_keyA)) || !make_id(&g1_B, BLOB(v_certB), BLOB(v_keyB))) {
        t_skip("fixture setup failed: %lu", GetLastError()); return 0; }
    g_state = 1;
    return 1;
}
DWORD g1_der_hdr(const BYTE *p, DWORD cb) {
    if (cb < 2) return 0;
    if (!(p[1] & 0x80)) return 2;
    DWORD nb = p[1] & 0x7f;
    if (nb == 0 || nb > 4 || cb < 2 + nb) return 0;
    return 2 + nb;
}
DWORD g1_der_total(const BYTE *p, DWORD cb) {
    DWORD h = g1_der_hdr(p, cb); if (!h) return 0;
    DWORD len = 0;
    if (!(p[1] & 0x80)) len = p[1]; else for (DWORD i = 0; i < h - 2; i++) len = (len << 8) | p[2 + i];
    return h + len;
}
int g1_has(const BYTE *hay, DWORD n, const void *needle, DWORD m) {
    if (m == 0 || n < m) return 0;
    for (DWORD i = 0; i + m <= n; i++) if (!memcmp(hay + i, needle, m)) return 1;
    return 0;
}
