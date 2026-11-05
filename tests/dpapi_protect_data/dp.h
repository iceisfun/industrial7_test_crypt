#ifndef DP_H
#define DP_H
#include "t.h"
#include <wincrypt.h>
#include <dpapi.h>
#include <stdlib.h>

/* DPAPI helpers shared by the dpapi_protect_data files. All DLL calls go through GetProcAddress. */

#define DP_NEED_DATA() do { if (!U(CryptProtectData) || !U(CryptUnprotectData)) { t_skip("missing CryptProtectData/CryptUnprotectData"); return; } } while (0)
#define DP_NEED_MEM()  do { if (!U(CryptProtectMemory) || !U(CryptUnprotectMemory)) { t_skip("missing CryptProtectMemory/CryptUnprotectMemory"); return; } } while (0)

/* real Windows blob layout is not reproduced by emulators: layout/tamper tests skip there */
#define DP_NOT_WINE() do { if (t_is_wine()) { t_skip("blob layout / in-place memory crypto is Windows specific"); return; } } while (0)

#define DP_PROVIDER_GUID { 0xdf9d8cd0, 0x1501, 0x11d1, { 0x8c, 0x7a, 0x00, 0xc0, 0x4f, 0xc2, 0x97, 0xeb } }

typedef struct {
    DWORD ok;
    DWORD o_ver, o_prov, o_mkver, o_mk, o_flags, o_dlen, o_descr, dlen;
    DWORD o_algc, o_keylen, o_saltlen, o_salt, saltlen;
    DWORD o_strlen, o_str, strlen_;
    DWORD o_algh, o_hashlen, o_hmaclen, o_hmac, hmaclen;
    DWORD o_cipherlen, o_cipher, cipherlen;
    DWORD o_signlen, o_sign, signlen;
    DWORD end;
} dp_blob_t;

static inline DWORD dp_rd(const BYTE *b, DWORD o) { DWORD v; memcpy(&v, b + o, 4); return v; }
static inline void dp_wr(BYTE *b, DWORD o, DWORD v) { memcpy(b + o, &v, 4); }

/* walks the documented field sequence; ok=1 only when every field lies inside the blob */
static inline dp_blob_t dp_parse(const BYTE *b, DWORD n) {
    dp_blob_t p; memset(&p, 0, sizeof p);
    if (n < 0x34) return p;
    p.o_ver = 0; p.o_prov = 4; p.o_mkver = 20; p.o_mk = 24; p.o_flags = 40; p.o_dlen = 44; p.o_descr = 48;
    p.dlen = dp_rd(b, 44);
    unsigned long long o = 48ull + p.dlen;
    #define NEED(k) if (o + (k) > n) return p
    p.o_algc = (DWORD)o; NEED(8); p.o_keylen = (DWORD)o + 4; o += 8;
    NEED(4); p.o_saltlen = (DWORD)o; p.saltlen = dp_rd(b, (DWORD)o); o += 4;
    p.o_salt = (DWORD)o; NEED(p.saltlen); o += p.saltlen;
    NEED(4); p.o_strlen = (DWORD)o; p.strlen_ = dp_rd(b, (DWORD)o); o += 4;
    p.o_str = (DWORD)o; NEED(p.strlen_); o += p.strlen_;
    NEED(12); p.o_algh = (DWORD)o; p.o_hashlen = (DWORD)o + 4; p.o_hmaclen = (DWORD)o + 8; p.hmaclen = dp_rd(b, (DWORD)o + 8); o += 12;
    p.o_hmac = (DWORD)o; NEED(p.hmaclen); o += p.hmaclen;
    NEED(4); p.o_cipherlen = (DWORD)o; p.cipherlen = dp_rd(b, (DWORD)o); o += 4;
    p.o_cipher = (DWORD)o; NEED(p.cipherlen); o += p.cipherlen;
    NEED(4); p.o_signlen = (DWORD)o; p.signlen = dp_rd(b, (DWORD)o); o += 4;
    p.o_sign = (DWORD)o; NEED(p.signlen); o += p.signlen;
    #undef NEED
    p.end = (DWORD)o; p.ok = 1;
    return p;
}

/* Protect with the usual defaults; returns the BOOL, blob in *out (LocalFree it with dp_free). */
static inline BOOL dp_protect(const void *data, DWORD len, LPCWSTR descr, const void *ent, DWORD entlen, DWORD flags, DATA_BLOB *out) {
    DATA_BLOB in = { len, (BYTE *)data }, e = { entlen, (BYTE *)ent };
    return U(CryptProtectData)(&in, descr, ent ? &e : NULL, NULL, NULL, flags, out);
}
static inline BOOL dp_unprotect(const void *blob, DWORD len, LPWSTR *descr, const void *ent, DWORD entlen, DWORD flags, DATA_BLOB *out) {
    DATA_BLOB in = { len, (BYTE *)blob }, e = { entlen, (BYTE *)ent };
    return U(CryptUnprotectData)(&in, descr, ent ? &e : NULL, NULL, NULL, flags, out);
}
static inline void dp_free(DATA_BLOB *b) { if (b->pbData) LocalFree(b->pbData); b->pbData = NULL; b->cbData = 0; }

/* patterned plaintext */
static inline void dp_fill(BYTE *p, DWORD n, DWORD seed) { for (DWORD i = 0; i < n; i++) p[i] = (BYTE)((i * 131u + seed * 17u + (i >> 8) * 7u) ^ 0x5a); }

static inline void dp_hex(const BYTE *b, DWORD n, char *out) { static const char h[] = "0123456789abcdef"; for (DWORD i = 0; i < n; i++) { out[2*i] = h[b[i] >> 4]; out[2*i+1] = h[b[i] & 15]; } out[2*n] = 0; }
static inline int dp_unhex(const char *s, BYTE *out, DWORD cap) {
    DWORD n = 0; while (s[0] && s[1] && n < cap) { char t[3] = { s[0], s[1], 0 }; out[n++] = (BYTE)strtoul(t, NULL, 16); s += 2; } return (int)n;
}

#endif
