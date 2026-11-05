#include "gap1.h"
g1_id g1_A, g1_B;
static int g_state;
/* The identities live in named (persisted) containers: with an ephemeral CRYPT_VERIFYCONTEXT provider the message
   signing path fails for SHA-2 hashes (0x8009000a) and enveloped content cannot be decrypted. */
static WCHAR g_nameA[96], g_nameB[96];
static int make_id(g1_id *id, WCHAR *name, const char *tag, const BYTE *cert, DWORD ccb, const BYTE *key, DWORD kcb) {
    PCCERT_CONTEXT (WINAPI *cc)(DWORD, const BYTE *, DWORD) = (void *)t_proc("CertCreateCertificateContext");
    typeof(&CryptAcquireContextW) acq = U(CryptAcquireContextW);
    typeof(&CryptImportKey) imp = U(CryptImportKey);
    typeof(&CryptDestroyKey) dk = U(CryptDestroyKey);
    if (!cc || !acq || !imp || !dk) return 0;
    id->cert = cc(ENC, cert, ccb);
    if (!id->cert) return 0;
    lstrcpyW(name, t_unique_w(tag));
    if (!acq(&id->prov, name, MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, CRYPT_NEWKEYSET)) return 0;
    HCRYPTKEY k = 0;
    if (!imp(id->prov, key, kcb, 0, 0, &k)) return 0;
    dk(k);
    return 1;
}
static void del_container(const WCHAR *name) {
    HCRYPTPROV p = 0;
    U(CryptAcquireContextW)(&p, name, MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, CRYPT_DELETEKEYSET);
}
T_SWEEPER(gap1_containers) {
    HCRYPTPROV p = 0;
    if (phase == T_SWEEP_END) {
        g_state = 0;
        if (g1_A.prov) U(CryptReleaseContext)(g1_A.prov, 0);
        if (g1_B.prov) U(CryptReleaseContext)(g1_B.prov, 0);
        g1_A.prov = g1_B.prov = 0;
        if (g_nameA[0]) del_container(g_nameA);
        if (g_nameB[0]) del_container(g_nameB);
        return;
    }
    if (!U(CryptAcquireContextW)(&p, NULL, MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) return;
    char stale[64][160]; int n = 0;
    BYTE buf[512]; DWORD cb, fl = CRYPT_FIRST;
    for (;;) {
        cb = sizeof buf;
        if (!U(CryptGetProvParam)(p, PP_ENUMCONTAINERS, buf, &cb, fl)) break;
        fl = CRYPT_NEXT;
        if (!strncmp((char *)buf, prefix, strlen(prefix)) && n < 64) { lstrcpynA(stale[n++], (char *)buf, sizeof stale[0]); }
    }
    U(CryptReleaseContext)(p, 0);
    for (int i = 0; i < n; i++) { WCHAR w[160]; MultiByteToWideChar(CP_ACP, 0, stale[i], -1, w, 160); del_container(w); }
}
int g1_init(void) {
    if (g_state) { if (g_state < 0) t_skip("fixture setup failed"); return g_state > 0; }
    g_state = -1;
    if (!make_id(&g1_A, g_nameA, "A", BLOB(v_certA), BLOB(v_keyA)) || !make_id(&g1_B, g_nameB, "B", BLOB(v_certB), BLOB(v_keyB))) {
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

NCRYPT_KEY_HANDLE g1_cng_key(const BYTE *k) {
    static NCRYPT_PROV_HANDLE ksp;
    if (!ksp && U(NCryptOpenStorageProvider)(&ksp, MS_KEY_STORAGE_PROVIDER, 0) != 0) return 0;
    DWORD bits, e; memcpy(&bits, k + 12, 4); memcpy(&e, k + 16, 4);
    DWORD nb = bits / 8, hb = bits / 16;
    BYTE be[4] = { (BYTE)(e >> 24), (BYTE)(e >> 16), (BYTE)(e >> 8), (BYTE)e };
    DWORD eoff = 0; while (eoff < 3 && !be[eoff]) eoff++;
    DWORD cbE = 4 - eoff, tot = 24 + cbE + nb + hb * 5 + nb;
    BYTE *blob = calloc(1, tot);
    BCRYPT_RSAKEY_BLOB *h = (BCRYPT_RSAKEY_BLOB *)blob;
    h->Magic = BCRYPT_RSAFULLPRIVATE_MAGIC; h->BitLength = bits; h->cbPublicExp = cbE; h->cbModulus = nb; h->cbPrime1 = hb; h->cbPrime2 = hb;
    BYTE *w = blob + 24; memcpy(w, be + eoff, cbE); w += cbE;
    const BYTE *src = k + 20; const DWORD lens[7] = { nb, hb, hb, hb, hb, hb, nb };
    for (int i = 0; i < 7; i++) { for (DWORD j = 0; j < lens[i]; j++) w[j] = src[lens[i] - 1 - j]; w += lens[i]; src += lens[i]; }
    NCRYPT_KEY_HANDLE key = 0;
    SECURITY_STATUS st = U(NCryptImportKey)(ksp, 0, BCRYPT_RSAFULLPRIVATE_BLOB, NULL, &key, blob, tot, 0);
    free(blob);
    return st == 0 ? key : 0;
}
