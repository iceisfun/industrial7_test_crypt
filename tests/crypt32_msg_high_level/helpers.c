#include "mh.h"
#include <stdlib.h>

mh_id mh_ids[MH_N];
HCERTSTORE mh_priv_store, mh_pub_store;
HCRYPTPROV mh_prov[MH_N];
HCERTSTORE mh_dec_stores[1];
static int g_init_state;   /* 0 = untried, 1 = ok, -1 = failed */

static const struct { const BYTE *cert; DWORD ccb; const BYTE *key; DWORD kcb; } g_fix[MH_N] = {
    { v_s1_cert, sizeof v_s1_cert, v_s1_key, sizeof v_s1_key },
    { v_s2_cert, sizeof v_s2_cert, v_s2_key, sizeof v_s2_key },
    { v_r1_cert, sizeof v_r1_cert, v_r1_key, sizeof v_r1_key },
    { v_r2_cert, sizeof v_r2_cert, v_r2_key, sizeof v_r2_key },
};

int mh_init(void) {
    if (g_init_state) { if (g_init_state < 0) t_skip("fixture setup failed"); return g_init_state > 0; }
    g_init_state = -1;
    HMODULE m = t_module("crypt32.dll");
    if (!m) { t_skip("crypt32 missing"); return 0; }
    typeof(&CertOpenStore) open = U(CertOpenStore);
    typeof(&CertAddEncodedCertificateToStore) add = U(CertAddEncodedCertificateToStore);
    typeof(&CertSetCertificateContextProperty) setp = U(CertSetCertificateContextProperty);
    typeof(&CryptAcquireContextW) acq = U(CryptAcquireContextW);
    typeof(&CryptImportKey) imp = U(CryptImportKey);
    if (!open || !add || !setp || !acq || !imp) { t_skip("missing fixture exports"); return 0; }
    mh_priv_store = open(CERT_STORE_PROV_MEMORY, 0, 0, CERT_STORE_NO_CRYPT_RELEASE_FLAG, NULL);
    mh_pub_store = open(CERT_STORE_PROV_MEMORY, 0, 0, 0, NULL);
    if (!mh_priv_store || !mh_pub_store) { t_skip("memory store"); return 0; }
    add(mh_pub_store, ENC, v_ca, sizeof v_ca, CERT_STORE_ADD_ALWAYS, NULL);
    for (int i = 0; i < MH_N; i++) {
        if (!add(mh_priv_store, ENC, g_fix[i].cert, g_fix[i].ccb, CERT_STORE_ADD_ALWAYS, &mh_ids[i].priv) ||
            !add(mh_pub_store, ENC, g_fix[i].cert, g_fix[i].ccb, CERT_STORE_ADD_ALWAYS, &mh_ids[i].pub)) {
            t_skip("cert add %d failed: %lu", i, GetLastError()); return 0; }
        HCRYPTPROV prov = 0; HCRYPTKEY key = 0;
        if (!acq(&prov, NULL, MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
            t_skip("CryptAcquireContext failed: %lx", GetLastError()); return 0; }
        if (!imp(prov, g_fix[i].key, g_fix[i].kcb, 0, 0, &key)) {
            t_skip("CryptImportKey %d failed: %lx", i, GetLastError()); return 0; }
        typeof(&CryptDestroyKey) dk = U(CryptDestroyKey); if (dk) dk(key);  /* provider keeps the key */
        DWORD spec = AT_KEYEXCHANGE;
        mh_prov[i] = prov;
        CERT_KEY_CONTEXT kc; memset(&kc, 0, sizeof kc);
        kc.cbSize = sizeof kc; kc.hCryptProv = prov; kc.dwKeySpec = spec;
        if (!setp(mh_ids[i].priv, CERT_KEY_CONTEXT_PROP_ID, 0, &kc)) {
            t_skip("set key context prop failed: %lx", GetLastError()); return 0; }
    }
    mh_dec_stores[0] = mh_priv_store;
    g_init_state = 1;
    return 1;
}

void mh_sign_para(CRYPT_SIGN_MESSAGE_PARA *p, int who, const char *hashoid) {
    memset(p, 0, sizeof *p);
    p->cbSize = sizeof *p; p->dwMsgEncodingType = ENC;
    p->pSigningCert = mh_ids[who].priv;
    p->HashAlgorithm.pszObjId = (LPSTR)hashoid;
}
void mh_verify_para(CRYPT_VERIFY_MESSAGE_PARA *p) {
    memset(p, 0, sizeof *p);
    p->cbSize = sizeof *p; p->dwMsgAndCertEncodingType = ENC;
}
void mh_hash_para(CRYPT_HASH_MESSAGE_PARA *p, const char *oid) {
    memset(p, 0, sizeof *p);
    p->cbSize = sizeof *p; p->dwMsgEncodingType = ENC; p->HashAlgorithm.pszObjId = (LPSTR)oid;
}
void mh_enc_para(CRYPT_ENCRYPT_MESSAGE_PARA *p, const char *oid) {
    memset(p, 0, sizeof *p);
    p->cbSize = sizeof *p; p->dwMsgEncodingType = ENC; p->ContentEncryptionAlgorithm.pszObjId = (LPSTR)oid;
}
void mh_dec_para(CRYPT_DECRYPT_MESSAGE_PARA *p) {
    memset(p, 0, sizeof *p);
    p->cbSize = sizeof *p; p->dwMsgAndCertEncodingType = ENC; p->cCertStore = 1; p->rghCertStore = mh_dec_stores;
}

BYTE *mh_sign(int who, const char *hashoid, int detached, DWORD flags, const BYTE *data, DWORD cb, DWORD *pcb) {
    typeof(&CryptSignMessage) sign = U(CryptSignMessage);
    if (!sign) return NULL;
    CRYPT_SIGN_MESSAGE_PARA p; mh_sign_para(&p, who, hashoid); p.dwFlags = flags;
    const BYTE *a[1] = { data }; DWORD l[1] = { cb };
    DWORD n = 0;
    if (!sign(&p, detached, 1, a, l, NULL, &n) || !n) return NULL;
    BYTE *out = malloc(n);
    if (!out) return NULL;
    if (!sign(&p, detached, 1, a, l, out, &n)) { free(out); return NULL; }
    *pcb = n;
    return out;
}

int mh_count_certs(HCERTSTORE s) {
    typeof(&CertEnumCertificatesInStore) en = U(CertEnumCertificatesInStore);
    int n = 0; PCCERT_CONTEXT c = NULL;
    while ((c = en(s, c)) != NULL) n++;
    return n;
}

DWORD mh_der_hdr(const BYTE *p, DWORD cb) {
    if (cb < 2) return 0;
    if (!(p[1] & 0x80)) return 2;
    DWORD nb = p[1] & 0x7f;
    if (nb == 0 || nb > 4 || cb < 2 + nb) return 0;
    return 2 + nb;
}
DWORD mh_der_total(const BYTE *p, DWORD cb) {
    DWORD h = mh_der_hdr(p, cb); if (!h) return 0;
    DWORD len = 0;
    if (!(p[1] & 0x80)) len = p[1]; else for (DWORD i = 0; i < h - 2; i++) len = (len << 8) | p[2 + i];
    return h + len;
}
int mh_has(const BYTE *hay, DWORD n, const void *needle, DWORD m) {
    if (m == 0 || n < m) return 0;
    for (DWORD i = 0; i + m <= n; i++) if (!memcmp(hay + i, needle, m)) return 1;
    return 0;
}

char *mh_to_b64(const BYTE *p, DWORD cb, DWORD strflags, DWORD *pcch) {
    typeof(&CryptBinaryToStringA) f = U(CryptBinaryToStringA);
    DWORD n = 0;
    if (!f || !f(p, cb, strflags, NULL, &n)) return NULL;
    char *s = malloc(n + 1);
    if (!s || !f(p, cb, strflags, s, &n)) { free(s); return NULL; }
    s[n] = 0; if (pcch) *pcch = n;
    return s;
}
char *mh_to_asnhex(const BYTE *p, DWORD cb, DWORD *pcch) {
    char *s = malloc(5 + 2 * cb + 1);
    if (!s) return NULL;
    memcpy(s, "{ASN}", 5);
    for (DWORD i = 0; i < cb; i++) sprintf(s + 5 + 2 * i, "%02X", p[i]);
    if (pcch) *pcch = 5 + 2 * cb;
    return s;
}

int mh_cb_calls;
static PCCERT_CONTEXT WINAPI mh_get_signer(void *arg, DWORD enc, PCERT_INFO id, HCERTSTORE msgstore) {
    typeof(&CertGetSubjectCertificateFromStore) g = U(CertGetSubjectCertificateFromStore);
    mh_cb_calls++;
    return g(mh_pub_store, enc, id);
}
void mh_verify_para_cb(CRYPT_VERIFY_MESSAGE_PARA *p) {
    mh_verify_para(p);
    p->pfnGetSignerCertificate = mh_get_signer;
}

HCERTSTORE mh_make_store(unsigned privmask, unsigned pubmask) {
    if (!mh_init()) return NULL;
    typeof(&CertOpenStore) open = U(CertOpenStore);
    typeof(&CertAddEncodedCertificateToStore) add = U(CertAddEncodedCertificateToStore);
    typeof(&CertSetCertificateContextProperty) setp = U(CertSetCertificateContextProperty);
    typeof(&CertFreeCertificateContext) fr = U(CertFreeCertificateContext);
    HCERTSTORE s = open(CERT_STORE_PROV_MEMORY, 0, 0, CERT_STORE_NO_CRYPT_RELEASE_FLAG, NULL);
    if (!s) return NULL;
    for (int i = 0; i < MH_N; i++) {
        PCCERT_CONTEXT c = NULL;
        if ((privmask | pubmask) & (1u << i)) {
            if (!add(s, ENC, g_fix[i].cert, g_fix[i].ccb, CERT_STORE_ADD_ALWAYS, &c)) continue;
            if (privmask & (1u << i)) {
                CERT_KEY_CONTEXT kc; memset(&kc, 0, sizeof kc);
                kc.cbSize = sizeof kc; kc.hCryptProv = mh_prov[i]; kc.dwKeySpec = AT_KEYEXCHANGE;
                setp(c, CERT_KEY_CONTEXT_PROP_ID, 0, &kc);
            }
            fr(c);
        }
    }
    return s;
}

const BYTE *mh_ctl_blob(DWORD *pn) {
    static BYTE *blob; static DWORD n; static int tried;
    if (!tried) {
        tried = 1;
        if (!mh_init()) return NULL;
        BYTE th[2][20]; CTL_ENTRY ent[2]; memset(ent, 0, sizeof ent);
        for (int i = 0; i < 2; i++) {
            DWORD l = 20;
            if (!U(CertGetCertificateContextProperty)(mh_ids[i].pub, CERT_HASH_PROP_ID, th[i], &l)) return NULL;
            ent[i].SubjectIdentifier.cbData = 20; ent[i].SubjectIdentifier.pbData = th[i];
        }
        static char usage[] = "1.3.6.1.5.5.7.3.2"; LPSTR usages[1] = { usage };
        static BYTE listid[] = "CryptTMHList"; static BYTE seq[1] = { 1 };
        CTL_INFO ci; memset(&ci, 0, sizeof ci);
        ci.SubjectUsage.cUsageIdentifier = 1; ci.SubjectUsage.rgpszUsageIdentifier = usages;
        ci.ListIdentifier.cbData = sizeof listid - 1; ci.ListIdentifier.pbData = listid;
        ci.SequenceNumber.cbData = 1; ci.SequenceNumber.pbData = seq;
        SYSTEMTIME st; memset(&st, 0, sizeof st); st.wYear = 2022; st.wMonth = 1; st.wDay = 1;
        SystemTimeToFileTime(&st, &ci.ThisUpdate);
        ci.SubjectAlgorithm.pszObjId = (LPSTR)OID_SHA1;
        ci.cCTLEntry = 2; ci.rgCTLEntry = ent;
        CMSG_SIGNER_ENCODE_INFO si; memset(&si, 0, sizeof si);
        si.cbSize = sizeof si; si.pCertInfo = mh_ids[MH_S1].priv->pCertInfo; si.hCryptProv = mh_prov[MH_S1];
        si.dwKeySpec = AT_KEYEXCHANGE; si.HashAlgorithm.pszObjId = (LPSTR)OID_SHA256;
        CMSG_SIGNED_ENCODE_INFO sg; memset(&sg, 0, sizeof sg); sg.cbSize = sizeof sg; sg.cSigners = 1; sg.rgSigners = &si;
        DWORD need = 0;
        if (!U(CryptMsgEncodeAndSignCTL)(ENC, &ci, &sg, 0, NULL, &need) || !need) return NULL;
        blob = malloc(need);
        if (!U(CryptMsgEncodeAndSignCTL)(ENC, &ci, &sg, 0, blob, &need)) { free(blob); blob = NULL; return NULL; }
        n = need;
    }
    if (blob && pn) *pn = n;
    return blob;
}
