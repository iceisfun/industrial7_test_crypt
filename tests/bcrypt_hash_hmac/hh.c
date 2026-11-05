#include "hh.h"

const struct hh_alg hh_algs[] = {
    { "MD2",    L"MD2",    16, 16,  BCRYPT_MD2_ALG_HANDLE,    BCRYPT_HMAC_MD2_ALG_HANDLE },
    { "MD4",    L"MD4",    16, 64,  BCRYPT_MD4_ALG_HANDLE,    BCRYPT_HMAC_MD4_ALG_HANDLE },
    { "MD5",    L"MD5",    16, 64,  BCRYPT_MD5_ALG_HANDLE,    BCRYPT_HMAC_MD5_ALG_HANDLE },
    { "SHA1",   L"SHA1",   20, 64,  BCRYPT_SHA1_ALG_HANDLE,   BCRYPT_HMAC_SHA1_ALG_HANDLE },
    { "SHA256", L"SHA256", 32, 64,  BCRYPT_SHA256_ALG_HANDLE, BCRYPT_HMAC_SHA256_ALG_HANDLE },
    { "SHA384", L"SHA384", 48, 128, BCRYPT_SHA384_ALG_HANDLE, BCRYPT_HMAC_SHA384_ALG_HANDLE },
    { "SHA512", L"SHA512", 64, 128, BCRYPT_SHA512_ALG_HANDLE, BCRYPT_HMAC_SHA512_ALG_HANDLE },
};
const unsigned hh_nalgs = sizeof hh_algs / sizeof hh_algs[0];
const struct hh_alg *hh_find(const char *name) {
    for (unsigned i = 0; i < hh_nalgs; i++) if (!strcmp(hh_algs[i].name, name)) return &hh_algs[i];
    return NULL;
}

static int hexv(char c) { return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : c >= 'A' && c <= 'F' ? c - 'A' + 10 : 0; }
ULONG hh_unhex(const char *h, BYTE *out) {
    ULONG n = 0;
    for (; h[0] && h[1]; h += 2) out[n++] = (BYTE)(hexv(h[0]) * 16 + hexv(h[1]));
    return n;
}
void hh_tohex(const BYTE *p, ULONG n, char *out) {
    static const char d[] = "0123456789abcdef";
    for (ULONG i = 0; i < n; i++) { out[2 * i] = d[p[i] >> 4]; out[2 * i + 1] = d[p[i] & 15]; }
    out[2 * n] = 0;
}
int hh_eqhex(const BYTE *p, ULONG n, const char *hex) {
    BYTE tmp[256]; ULONG m = hh_unhex(hex, tmp);
    return m == n && !memcmp(p, tmp, n);
}
BYTE *hh_spec_new(const struct hh_spec *s, ULONG *len) {
    ULONG n = s->kind == 'l' ? (ULONG)(strlen(s->hex) / 2) : s->len;
    BYTE *b = malloc(n ? n : 1);
    if (s->kind == 'p') for (ULONG i = 0; i < n; i++) b[i] = (BYTE)(i * s->a + s->b);
    else if (s->kind == 'r') memset(b, s->a, n);
    else hh_unhex(s->hex, b);
    *len = n;
    return b;
}
void hh_lcg_fill(BYTE *p, ULONG n, ULONG seed) {
    for (ULONG i = 0; i < n; i++) { seed = seed * 1664525u + 1013904223u; p[i] = (BYTE)(seed >> 24); }
}
BCRYPT_ALG_HANDLE hh_open(const WCHAR *name, ULONG flags) {
    BCRYPT_ALG_HANDLE h = NULL;
    NTSTATUS st = HH_P_OPEN()(&h, name, NULL, flags);
    EXPECT_EQ(st, 0);
    return st == 0 ? h : NULL;
}
void hh_close(BCRYPT_ALG_HANDLE h) { if (h) HH_P_CLOSE()(h, 0); }
ULONG hh_prop_ulong(void *h, const WCHAR *prop, int *ok) {
    ULONG v = 0, cb = 0;
    NTSTATUS st = HH_P_GETPROP()(h, prop, (PUCHAR)&v, sizeof v, &cb, 0);
    if (ok) *ok = (st == 0 && cb == sizeof v);
    return v;
}
ULONG hh_objlen(BCRYPT_ALG_HANDLE h) { int ok; ULONG v = hh_prop_ulong(h, BCRYPT_OBJECT_LENGTH, &ok); return ok ? v : 0; }

NTSTATUS hh_compute(BCRYPT_ALG_HANDLE a, const BYTE *key, ULONG kl, const BYTE *d, ULONG n, ULONG chunk, int mode, BYTE *out, ULONG outlen) {
    BCRYPT_HASH_HANDLE h = NULL; BYTE *obj = NULL; ULONG ol = 0;
    if (mode == 1) { ol = hh_objlen(a); obj = _aligned_malloc(ol ? ol : 16, 16); }
    NTSTATUS st = HH_P_CREATE()(a, &h, obj, ol, (PUCHAR)key, kl, mode == 2 ? BCRYPT_HASH_REUSABLE_FLAG : 0);
    if (st) { if (obj) _aligned_free(obj); return st; }
    if (!chunk || chunk >= n) {
        st = HH_P_DATA()(h, (PUCHAR)d, n, 0);
    } else {
        for (ULONG o = 0; o < n && !st; o += chunk) st = HH_P_DATA()(h, (PUCHAR)d + o, n - o < chunk ? n - o : chunk, 0);
    }
    if (!st) st = HH_P_FINISH()(h, out, outlen, 0);
    NTSTATUS st2 = HH_P_DESTROY()(h);
    if (!st) st = st2;
    if (obj) _aligned_free(obj);
    return st;
}
