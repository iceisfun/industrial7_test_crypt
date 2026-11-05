/* Shared helpers for the crypt32_string_formats area. */
#ifndef SF_H
#define SF_H
#include "t.h"
#include <wincrypt.h>
#include <stdlib.h>
#include <ctype.h>

#define NELEM(a) (sizeof(a) / sizeof((a)[0]))

#ifndef CRYPT_E_INVALID_X500_STRING
#define CRYPT_E_INVALID_X500_STRING ((DWORD)0x80092023)

#endif
#ifndef CRYPT_E_NOT_FOUND
#define CRYPT_E_NOT_FOUND ((DWORD)0x80092004)

#endif
#define SF_E_INVALIDARG ((DWORD)0x80070057)

/* ---- reference models (derived from the observed Windows 10 output layout) ---- */

/* Base64 with 64-char lines. eol may be "" (no line breaks at all). url=1 uses -_ and no padding. */
static size_t sf_ref_b64(const BYTE *p, DWORD cb, const char *eol, int url, int pct, char *out)
{
    static const char std[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    static const char uri[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    const char *tab = url ? uri : std;
    size_t o = 0, col = 0, el = strlen(eol);
    DWORD i;
    for (i = 0; i < cb; i += 3) {
        DWORD rem = cb - i;
        unsigned b0 = p[i], b1 = rem > 1 ? p[i + 1] : 0, b2 = rem > 2 ? p[i + 2] : 0;
        char q[4]; int k;
        q[0] = tab[b0 >> 2];
        q[1] = tab[((b0 & 3) << 4) | (b1 >> 4)];
        q[2] = rem > 1 ? tab[((b1 & 15) << 2) | (b2 >> 6)] : '=';
        q[3] = rem > 2 ? tab[b2 & 63] : '=';
        for (k = 0; k < 4; k++) {
            const char *s; char one[2] = { q[k], 0 }; size_t l;
            if (url && q[k] == '=') break;
            s = one;
            if (pct) { if (q[k] == '+') s = "%2B"; else if (q[k] == '/') s = "%2F"; else if (q[k] == '=') s = "%3D"; }
            l = strlen(s);
            if (col >= 64) { memcpy(out + o, eol, el); o += el; col = 0; }
            memcpy(out + o, s, l); o += l; col += l;
        }
    }
    if (o) { memcpy(out + o, eol, el); o += el; }
    out[o] = 0;
    return o;
}

/* HEX family (fmt 4, 5, 0xa, 0xb, 0xc). */
static size_t sf_ref_hex(const BYTE *p, DWORD cb, DWORD fmt, const char *eol, char *out)
{
    size_t o = 0; DWORD off;
    int ascii = (fmt == 5 || fmt == 0xb), addr = (fmt == 0xa || fmt == 0xb);
    int nocrlf = (eol[0] == 0);
    for (off = 0; off < cb; off += 16) {
        DWORD n = cb - off < 16 ? cb - off : 16, j;
        for (j = 0; j < n; j++) {
            const char *term = "", *sep = " ";
            char a[16] = "";
            if (j % 8 == 0) sep = (fmt == 4 && nocrlf) ? " " : "  ";
            if (j == 0) {
                if (addr) sprintf(a, "%04x", (unsigned)off);
                sep = addr ? "\t" : "";
                if (off) term = (fmt == 0xc) ? "" : (fmt == 4 && nocrlf) ? " " : eol;
            }
            if (fmt == 0xc) sep = "";
            o += sprintf(out + o, "%s%s%s%02x", term, a, sep, p[off + j]);
        }
        if (ascii) {
            int pad = 52 - (n > 8 ? 1 : 0) - 3 * (int)n;
            while (pad-- > 0) out[o++] = ' ';
            for (j = 0; j < n; j++) { BYTE c = p[off + j]; out[o++] = (c >= 0x20 && c <= 0x7e) ? c : '.'; }
        }
    }
    if (cb) { size_t el = strlen(eol); memcpy(out + o, eol, el); o += el; }
    out[o] = 0;
    return o;
}

/* ---- CryptBinaryToString protocol checker ---- */
static void sf_widen(const char *s, WCHAR *w) { do { *w++ = (BYTE)*s; } while (*s++); }

/* Checks size query (A and W), exact buffer, one-short buffer, content, A/W parity.
 * nul=0 for CRYPT_STRING_BINARY (no terminator is produced). */
static void sf_check_b2s(const char *file, int line, const BYTE *p, DWORD cb, DWORD fl,
                         const char *exp, size_t explen, int nul)
{
    BOOL (WINAPI *fa)(const BYTE*, DWORD, DWORD, LPSTR, DWORD*) = (void*)t_proc("CryptBinaryToStringA");
    BOOL (WINAPI *fw)(const BYTE*, DWORD, DWORD, LPWSTR, DWORD*) = (void*)t_proc("CryptBinaryToStringW");
    DWORD n; BOOL r; size_t want = explen + (nul ? 1 : 0);
    char *buf = malloc(want + 64); WCHAR *wb = malloc((want + 64) * sizeof(WCHAR));
    if (!fa || !fw || !buf || !wb) { t_check(0, file, line, "sf_check_b2s setup", NULL); free(buf); free(wb); return; }
    n = 0x7777; SET_ERR(0);
    r = fa(p, cb, fl, NULL, &n);
    t_check(r && n == want, file, line, "A size query", "r=%d n=%lu want %zu fl=%#lx err=%lu", r, n, want, fl, GetLastError());
    n = 0x7777;
    r = fw(p, cb, fl, NULL, &n);
    t_check(r && n == want, file, line, "W size query", "r=%d n=%lu want %zu fl=%#lx", r, n, want, fl);
    memset(buf, 0xAA, want + 64);
    n = (DWORD)want; SET_ERR(0);
    r = fa(p, cb, fl, buf, &n);
    t_check(r, file, line, "A exact buffer", "fl=%#lx err=%lu", fl, GetLastError());
    t_check(n == explen, file, line, "A returned length", "got %lu want %zu fl=%#lx", n, explen, fl);
    t_check(memcmp(buf, exp, explen) == 0, file, line, "A content", "fl=%#lx got '%.*s'", fl, (int)(explen < 200 ? explen : 200), buf);
    if (nul) t_check(buf[explen] == 0, file, line, "A NUL terminator", NULL);
    else t_check((BYTE)buf[explen] == 0xAA, file, line, "A binary: no terminator written", NULL);
    if (want > 1) {
        memset(buf, 0xAA, want + 64);
        n = (DWORD)want - 1; SET_ERR(0);
        r = fa(p, cb, fl, buf, &n);
        t_check(!r && GetLastError() == ERROR_MORE_DATA, file, line, "A one-short -> ERROR_MORE_DATA", "r=%d err=%lu fl=%#lx", r, GetLastError(), fl);
    }
    if (nul) {
        memset(wb, 0xAA, (want + 64) * sizeof(WCHAR));
        n = (DWORD)want; SET_ERR(0);
        r = fw(p, cb, fl, wb, &n);
        t_check(r && n == explen, file, line, "W exact buffer", "r=%d n=%lu want %zu fl=%#lx err=%lu", r, n, explen, fl, GetLastError());
        if (r) {
            WCHAR *we = malloc((want + 1) * sizeof(WCHAR)); sf_widen(exp, we);
            t_check(memcmp(wb, we, want * sizeof(WCHAR)) == 0, file, line, "W content equals widened A content", "fl=%#lx", fl);
            free(we);
        }
        if (want > 1) {
            n = (DWORD)want - 1; SET_ERR(0);
            r = fw(p, cb, fl, wb, &n);
            t_check(!r, file, line, "W one-short fails", "fl=%#lx", fl);
        }
    }
    free(buf); free(wb);
}
#define B2S(p, cb, fl, exp) sf_check_b2s(__FILE__, __LINE__, (const BYTE*)(p), (cb), (fl), (exp), strlen(exp), 1)
#define B2S_RAW(p, cb, fl, exp, explen, nul) sf_check_b2s(__FILE__, __LINE__, (const BYTE*)(p), (cb), (fl), (exp), (explen), (nul))

/* ---- CryptStringToBinary helper ---- */
typedef struct { BOOL ok; DWORD err; DWORD cb; DWORD skip; DWORD flags; BYTE data[4096]; } sf_dec;
/* Decodes with a size query first, then a real call. wide=1 uses the W entry point. */
static void sf_decode(const char *s, DWORD cch, DWORD fl, int wide, sf_dec *d)
{
    BOOL (WINAPI *fa)(LPCSTR, DWORD, DWORD, BYTE*, DWORD*, DWORD*, DWORD*) = (void*)t_proc("CryptStringToBinaryA");
    BOOL (WINAPI *fw)(LPCWSTR, DWORD, DWORD, BYTE*, DWORD*, DWORD*, DWORD*) = (void*)t_proc("CryptStringToBinaryW");
    DWORD n = 0x5555, sk = 0x5555, fg = 0x5555; BOOL r;
    WCHAR *w = NULL;
    memset(d, 0, sizeof *d);
    if (wide) { size_t l = strlen(s) + 1; w = malloc(l * sizeof(WCHAR)); sf_widen(s, w); }
    SET_ERR(0);
    r = wide ? fw(w, cch, fl, NULL, &n, &sk, &fg) : fa(s, cch, fl, NULL, &n, &sk, &fg);
    d->ok = r; d->err = GetLastError(); d->cb = n; d->skip = sk; d->flags = fg;
    if (r && n <= sizeof d->data) {
        DWORD n2 = n, sk2 = 0x5555, fg2 = 0x5555;
        SET_ERR(0);
        r = wide ? fw(w, cch, fl, d->data, &n2, &sk2, &fg2) : fa(s, cch, fl, d->data, &n2, &sk2, &fg2);
        d->ok = r; d->err = GetLastError(); d->cb = n2; d->skip = sk2; d->flags = fg2;
    }
    free(w);
}
/* Expect a successful decode of s to exactly (exp, explen). */
static void sf_expect_dec(const char *file, int line, const char *s, DWORD cch, DWORD fl, const void *exp, DWORD explen)
{
    int wide;
    for (wide = 0; wide < 2; wide++) {
        sf_dec d; sf_decode(s, cch, fl, wide, &d);
        t_check(d.ok, file, line, wide ? "W decode ok" : "A decode ok", "fl=%#lx err=%lu input '%.60s'", fl, d.err, s);
        if (d.ok) {
            t_check(d.cb == explen, file, line, "decoded length", "got %lu want %lu fl=%#lx input '%.60s'", d.cb, explen, fl, s);
            if (d.cb == explen) t_check(memcmp(d.data, exp, explen) == 0, file, line, "decoded bytes", "fl=%#lx input '%.60s'", fl, s);
        }
    }
}
#define DEC_OK(s, fl, exp, explen) sf_expect_dec(__FILE__, __LINE__, (s), 0, (fl), (exp), (explen))
#define DEC_OK_STR(s, fl, expstr) sf_expect_dec(__FILE__, __LINE__, (s), 0, (fl), (expstr), (DWORD)strlen(expstr))
static void sf_expect_decfail2(const char *file, int line, const char *s, DWORD cch, DWORD fl, DWORD errA, DWORD errW)
{
    int wide;
    for (wide = 0; wide < 2; wide++) {
        DWORD err = wide ? errW : errA;
        sf_dec d; sf_decode(s, cch, fl, wide, &d);
        t_check(!d.ok, file, line, wide ? "W decode must fail" : "A decode must fail", "fl=%#lx input '%.60s'", fl, s);
        if (!d.ok) t_check(d.err == err, file, line, "decode error code", "got %lu want %lu fl=%#lx input '%.60s' %s", d.err, err, fl, s, wide ? "W" : "A");
    }
}
static void sf_expect_decfail(const char *file, int line, const char *s, DWORD cch, DWORD fl, DWORD err)
{ sf_expect_decfail2(file, line, s, cch, fl, err, err); }
#define DEC_FAIL(s, fl, err) sf_expect_decfail2(__FILE__, __LINE__, (s), 0, (fl), (err), (err))
/* empty input with cch == 0: the A entry point reports ERROR_INVALID_DATA, the W entry point ERROR_INVALID_PARAMETER (probed) */
#define DEC_FAIL_AW(s, fl, errA, errW) sf_expect_decfail2(__FILE__, __LINE__, (s), 0, (fl), (errA), (errW))

/* HRESULT-or-Win32 last-error check by value */
#define EXPECT_LE(v) do { DWORD e_ = GetLastError(); t_check(e_ == (DWORD)(v), __FILE__, __LINE__, #v, "GetLastError got %#lx want %#lx", e_, (DWORD)(v)); } while (0)


/* ---- DER name builder ---- */
typedef struct { int nrdn; const char *oid; BYTE tag; const void *v; int n; } sf_attr; /* nrdn=1: begins a new RDN; n<0: strlen */

static int sf_der_hdr(BYTE *o, BYTE tag, int len)
{
    int k = 0; o[k++] = tag;
    if (len < 0x80) o[k++] = (BYTE)len;
    else if (len < 0x100) { o[k++] = 0x81; o[k++] = (BYTE)len; }
    else { o[k++] = 0x82; o[k++] = (BYTE)(len >> 8); o[k++] = (BYTE)len; }
    return k;
}
static int sf_der_oid(BYTE *o, const char *s)
{
    unsigned a = 0, b = 0; int k = 0, first = 1, idx = 0; const char *p = s; BYTE tmp[64];
    while (*p) {
        unsigned long v = strtoul(p, (char **)&p, 10);
        if (idx == 0) a = (unsigned)v; else if (idx == 1) { b = (unsigned)v; tmp[k++] = (BYTE)(a * 40 + b); }
        else { BYTE enc[8]; int e = 0; do { enc[e++] = (BYTE)(v & 0x7f); v >>= 7; } while (v); while (e--) tmp[k++] = enc[e] | (e ? 0x80 : 0); }
        idx++; if (*p == '.') p++;
    }
    (void)first;
    { int h = sf_der_hdr(o, 0x06, k); memcpy(o + h, tmp, k); return h + k; }
}
static DWORD sf_build_name(BYTE *out, const sf_attr *a, int cnt)
{
    static BYTE rdns[8192]; int rn = 0, i = 0;
    while (i < cnt) {
        BYTE set[2048]; int sn = 0, j = i;
        do {
            BYTE attr[1024], one[1024]; int an = 0, on, vl = a[j].n < 0 ? (int)strlen((const char*)a[j].v) : a[j].n, h;
            an += sf_der_oid(attr + an, a[j].oid);
            h = sf_der_hdr(attr + an, a[j].tag, vl); an += h; memcpy(attr + an, a[j].v, vl); an += vl;
            on = sf_der_hdr(one, 0x30, an); memcpy(one + on, attr, an); on += an;
            memcpy(set + sn, one, on); sn += on;
            j++;
        } while (j < cnt && !a[j].nrdn);
        { BYTE hd[8]; int hl = sf_der_hdr(hd, 0x31, sn); memcpy(rdns + rn, hd, hl); rn += hl; memcpy(rdns + rn, set, sn); rn += sn; }
        i = j;
    }
    { int hl = sf_der_hdr(out, 0x30, rn); memcpy(out + hl, rdns, rn); return (DWORD)(hl + rn); }
}
#define PS 0x13   /* PrintableString */
#define U8 0x0c   /* UTF8String */
#define IA 0x16   /* IA5String */
#define T6 0x14   /* TeletexString */
#define BM 0x1e   /* BMPString */
#define NM 0x12   /* NumericString */

extern const BYTE sf_cert_leaf[], sf_cert_ou[], sf_cert_o[], sf_cert_ca[], sf_cert_idn[], sf_cert_em[];
extern const DWORD sf_cert_leaf_len, sf_cert_ou_len, sf_cert_o_len, sf_cert_ca_len, sf_cert_idn_len, sf_cert_em_len;

#define NAME_OF(buf, blob, ...) do { const sf_attr a_[] = { __VA_ARGS__ }; (blob).cbData = sf_build_name(buf, a_, (int)NELEM(a_)); (blob).pbData = buf; } while (0)

#endif
