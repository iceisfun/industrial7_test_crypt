#include "ck.h"
#include <ctype.h>

static int hv(int c) { return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1; }
size_t ck_hex(const char *h, BYTE *out, size_t cap) {
    size_t n = 0;
    while (h[0] && h[1] && n < cap) { out[n++] = (BYTE)(hv(h[0]) * 16 + hv(h[1])); h += 2; }
    return n;
}
BYTE *ck_hexa(const char *h, size_t *n) {
    size_t l = strlen(h) / 2;
    BYTE *p = (BYTE *)malloc(l ? l : 1);
    *n = ck_hex(h, p, l);
    return p;
}
int ck_eqhex(const BYTE *p, size_t n, const char *h) {
    size_t l; BYTE *e = ck_hexa(h, &l);
    int r = l == n && (n == 0 || !memcmp(p, e, n));
    free(e);
    return r;
}
void ck_rc4(const BYTE *key, size_t klen, BYTE *d, size_t n) {
    BYTE S[256], t; int i, j = 0; size_t k;
    for (i = 0; i < 256; i++) S[i] = (BYTE)i;
    for (i = 0; i < 256; i++) { j = (j + S[i] + key[i % klen]) & 255; t = S[i]; S[i] = S[j]; S[j] = t; }
    i = j = 0;
    for (k = 0; k < n; k++) {
        i = (i + 1) & 255; j = (j + S[i]) & 255; t = S[i]; S[i] = S[j]; S[j] = t;
        d[k] ^= S[(S[i] + S[j]) & 255];
    }
}
void ck_md5(const BYTE *d, size_t n, BYTE out[16]) {
    CK_MD5_CTX c;
    CKP(MD5Init)(&c); CKP(MD5Update)(&c, d, (ULONG)n); CKP(MD5Final)(&c);
    memcpy(out, c.digest, 16);
}
void ck_hmac_md5(const BYTE *key, size_t kl, const BYTE *d1, size_t n1, const BYTE *d2, size_t n2, BYTE out[16]) {
    BYTE ip[64], op[64], in[16]; size_t i; CK_MD5_CTX c;
    BYTE kb[64] = {0};
    if (kl > 64) ck_md5(key, kl, kb); else memcpy(kb, key, kl);
    for (i = 0; i < 64; i++) { ip[i] = kb[i] ^ 0x36; op[i] = kb[i] ^ 0x5c; }
    CKP(MD5Init)(&c); CKP(MD5Update)(&c, ip, 64);
    if (n1) CKP(MD5Update)(&c, d1, (ULONG)n1);
    if (n2) CKP(MD5Update)(&c, d2, (ULONG)n2);
    CKP(MD5Final)(&c); memcpy(in, c.digest, 16);
    CKP(MD5Init)(&c); CKP(MD5Update)(&c, op, 64); CKP(MD5Update)(&c, in, 16); CKP(MD5Final)(&c);
    memcpy(out, c.digest, 16);
}
WCHAR *ck_wide(const char *hex16, USHORT *bytes) {
    size_t n; BYTE *b = ck_hexa(hex16, &n);
    WCHAR *w = (WCHAR *)calloc(n / 2 + 2, sizeof(WCHAR));
    memcpy(w, b, n); free(b); *bytes = (USHORT)n;
    return w;
}
const CSX *ck_cs(LONG et) {
    CSX *p = NULL;
    if (!CKP(CDLocateCSystem) || CKP(CDLocateCSystem)(et, &p) != 0) return NULL;
    return p;
}
const CKX *ck_ck(LONG ty) {
    CKX *p = NULL;
    if (!CKP(CDLocateCheckSum) || CKP(CDLocateCheckSum)(ty, &p) != 0) return NULL;
    return p;
}
NTSTATUS ck_run_checksum(LONG type, int ex, const BYTE *key, ULONG keylen, ULONG usage,
                         const BYTE *data, size_t n, BYTE *out, size_t *outlen) {
    const CKX *c = ck_ck(type); PVOID ctx = NULL; NTSTATUS st; BYTE buf[128];
    if (!c) return NS_NO_CHECKSUM;
    memset(buf, 0, sizeof buf);
    if (ex) {
        if (!c->InitializeEx) return NS_NOT_SUPPORTED;
        st = ((ckx_initex_fn)c->InitializeEx)((PUCHAR)key, keylen, usage, &ctx);
    } else {
        if (!c->Initialize) return NS_NOT_SUPPORTED;
        st = ((ckx_init_fn)c->Initialize)(0, &ctx);
    }
    if (st) return st;
    if (n) { st = ((ckx_sum_fn)c->Sum)(ctx, (ULONG)n, (PUCHAR)data); if (st) return st; }
    st = ((ckx_final_fn)c->Finalize)(ctx, buf);
    if (!st) {
        size_t l = c->Size < sizeof buf ? c->Size : sizeof buf;
        memcpy(out, buf, l); if (outlen) *outlen = l;
    }
    ((ckx_finish_fn)c->Finish)(&ctx);
    return st;
}
NTSTATUS ck_cs_encrypt(LONG et, const BYTE *key, ULONG keylen, ULONG usage, const BYTE *in, ULONG inlen,
                       BYTE *out, ULONG *outlen) {
    const CSX *c = ck_cs(et); PVOID st = NULL; NTSTATUS r;
    if (!c) return NS_NO_CSYSTEM;
    r = ((csx_init_fn)c->Initialize)((PUCHAR)key, keylen, usage, &st);
    if (r) return r;
    r = ((csx_crypt_fn)c->Encrypt)(st, (PUCHAR)in, inlen, out, outlen);
    ((csx_fin_fn)c->Finish)(&st);
    return r;
}
NTSTATUS ck_cs_decrypt(LONG et, const BYTE *key, ULONG keylen, ULONG usage, const BYTE *in, ULONG inlen,
                       BYTE *out, ULONG *outlen) {
    const CSX *c = ck_cs(et); PVOID st = NULL; NTSTATUS r;
    if (!c) return NS_NO_CSYSTEM;
    r = ((csx_init_fn)c->Initialize)((PUCHAR)key, keylen, usage, &st);
    if (r) return r;
    r = ((csx_crypt_fn)c->Decrypt)(st, (PUCHAR)in, inlen, out, outlen);
    ((csx_fin_fn)c->Finish)(&st);
    return r;
}

static BYTE g_seq_base;
static BOOLEAN WINAPI ck_rng_seq(PUCHAR buf, ULONG len) { for (ULONG i = 0; i < len; i++) buf[i] = (BYTE)(g_seq_base + i); return TRUE; }
int ck_install_seq_rng(BYTE base) {
    RNX r; memset(&r, 0, sizeof r);
    r.Type = 0x7e57; r.P2 = (void *)ck_rng_seq; g_seq_base = base;
    return CKP(CDRegisterRng) && CKP(CDRegisterRng)(&r) == TRUE;
}
