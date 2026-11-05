#include "asn.h"

alloc_stat g_as;
const char *a_ctx = "";
static void a_stage(const char *st) { t_label("%s%s%s", a_ctx, *a_ctx ? " " : "", st); }
void *WINAPI as_alloc(size_t n) {
    g_as.allocs++; g_as.lastsz = n;
    if (g_as.fail) { g_as.last = NULL; return NULL; }
    g_as.last = HeapAlloc(GetProcessHeap(), 0, n ? n : 1);
    return g_as.last;
}
void WINAPI as_free(void *p) { g_as.frees++; HeapFree(GetProcessHeap(), 0, p); }

BYTE *a_enc(LPCSTR oid, const void *s, DWORD flags, DWORD *cb) {
    BYTE *p = NULL; DWORD n = 0;
    if (!U(CryptEncodeObjectEx)) return NULL;
    BOOL r = U(CryptEncodeObjectEx)(ENC, oid, (void *)s, flags | CRYPT_ENCODE_ALLOC_FLAG, NULL, &p, &n);
    if (cb) *cb = n;
    if (!r) return NULL;
    return p;
}

static void a_hex(char *o, size_t osz, const BYTE *p, DWORD n) {
    DWORD i; o[0] = 0;
    for (i = 0; p && i < n && i < 190 && strlen(o) + 3 < osz; i++) sprintf(o + strlen(o), "%02x", p[i]);
}
static void a_cb(const char *file, int line, DWORD got, DWORD want) {
    t_check(got == want, file, line, "cb == n", "got %lu want %lu", got, want);
}
static void a_bytes(const char *file, int line, const BYTE *got, DWORD gotn, const BYTE *exp, DWORD n) {
    char h1[240], h2[240];
    int ok = gotn >= n && !memcmp(got, exp, n);
    a_hex(h1, sizeof h1, got, gotn < n ? gotn : n); a_hex(h2, sizeof h2, exp, n);
    t_check(ok, file, line, "bytes == exp", "got %s want %s", h1, h2);
}

void a_diff(const char *file, int line, const char *what, const BYTE *got, DWORD gn, const BYTE *want, DWORD wn) {
    char h1[400], h2[400];
    a_hex(h1, sizeof h1, got, gn); a_hex(h2, sizeof h2, want, wn);
    t_check(got && gn == wn && !memcmp(got, want, wn), file, line, what, "got %lu bytes %s want %lu bytes %s", gn, h1, wn, h2);
}

void a_enc_eq(const char *file, int line, LPCSTR oid, const void *s, DWORD flags, const BYTE *exp, DWORD n) {
    DWORD cb; BOOL r;
    /* size query */
    a_stage("size-query");
    cb = 0xCCCC; SET_ERR(0);
    r = U(CryptEncodeObjectEx)(ENC, oid, (void *)s, flags, NULL, NULL, &cb);
    AEQ(r);
    if (!r) { t_note("size query failed err 0x%lx", GetLastError()); t_label(NULL); return; }
    /* a query may over-report; the final length is checked below */
    t_check(cb >= n, file, line, "query cb >= n", "got %lu want >= %lu", cb, n);
    if (cb > 0x10000) { t_label(NULL); return; }
    /* too small */
    if (n > 0) {
        BYTE *small_ = (BYTE *)LocalAlloc(LPTR, n);
        a_stage("too-small");
        cb = n - 1; SET_ERR(0);
        r = U(CryptEncodeObjectEx)(ENC, oid, (void *)s, flags, NULL, small_, &cb);
        AEQ(!r); AEQ(GetLastError() == ERROR_MORE_DATA); t_check(cb >= n, file, line, "more-data cb >= n", "got %lu want >= %lu", cb, n);
        LocalFree(small_);
    }
    /* exact buffer, then oversized buffer */
    BYTE *buf = (BYTE *)LocalAlloc(LPTR, n + 16);
    a_stage("exact");
    cb = n; SET_ERR(0);
    r = U(CryptEncodeObjectEx)(ENC, oid, (void *)s, flags, NULL, buf, &cb);
    AEQ(r); a_cb(file, line, cb, n); a_bytes(file, line, buf, cb, exp, n);
    a_stage("oversize");
    memset(buf, 0xEE, n + 16);
    cb = n + 16;
    r = U(CryptEncodeObjectEx)(ENC, oid, (void *)s, flags, NULL, buf, &cb);
    AEQ(r); a_cb(file, line, cb, n); a_bytes(file, line, buf, cb, exp, n);
    { DWORD i, clean = 1; for (i = cb < n + 16 ? cb : n + 16; i < n + 16; i++) if (buf[i] != 0xEE) clean = 0; AEQ(clean); }
    LocalFree(buf);
    /* ALLOC */
    a_stage("alloc");
    BYTE *p = NULL; cb = 0;
    r = U(CryptEncodeObjectEx)(ENC, oid, (void *)s, flags | CRYPT_ENCODE_ALLOC_FLAG, NULL, &p, &cb);
    AEQ(r); a_cb(file, line, cb, n); AEQ(p != NULL);
    if (r && p) { a_bytes(file, line, p, cb, exp, n); LocalFree(p); }
    /* legacy entry point (flags 0 only) */
    if (flags == 0) {
        a_stage("legacy");
        buf = (BYTE *)LocalAlloc(LPTR, n + 1);
        cb = n + 1;
        r = U(CryptEncodeObject)(ENC, oid, (void *)s, buf, &cb);
        AEQ(r); a_cb(file, line, cb, n); a_bytes(file, line, buf, cb, exp, n);
        LocalFree(buf);
    }
    t_label(NULL);
}

void a_enc_fail(const char *file, int line, LPCSTR oid, const void *s, DWORD flags, DWORD err) {
    DWORD cb = 0, e; BOOL r;
    SET_ERR(0);
    r = U(CryptEncodeObjectEx)(ENC, oid, (void *)s, flags, NULL, NULL, &cb);
    e = GetLastError();
    t_check(!r, file, line, "encode size-query fails", "ret %d err 0x%lx cb %lu", r, e, cb);
    if (err) t_check(e == err, file, line, "encode size-query error", "got 0x%lx want 0x%lx", e, err);
    BYTE buf[2048]; cb = sizeof buf; SET_ERR(0);
    r = U(CryptEncodeObjectEx)(ENC, oid, (void *)s, flags, NULL, buf, &cb);
    e = GetLastError();
    t_check(!r, file, line, "encode with buffer fails", "ret %d err 0x%lx", r, e);
    if (err) t_check(e == err, file, line, "encode with buffer error", "got 0x%lx want 0x%lx", e, err);
    BYTE *p = (BYTE *)(ULONG_PTR)1; cb = 77; SET_ERR(0);
    r = U(CryptEncodeObjectEx)(ENC, oid, (void *)s, flags | CRYPT_ENCODE_ALLOC_FLAG, NULL, &p, &cb);
    e = GetLastError();
    t_check(!r, file, line, "encode ALLOC fails", "ret %d err 0x%lx", r, e);
    if (err) t_check(e == err, file, line, "encode ALLOC error", "got 0x%lx want 0x%lx", e, err);
    t_note("%s:%d encode failure: err 0x%lx out ptr %p cb %lu", file, line, e, p, cb);
    if (r && p) LocalFree(p);
}

void *a_dec(const char *file, int line, LPCSTR oid, const BYTE *der, DWORD n, DWORD flags, DWORD *pcb) {
    DWORD cb = 0; BOOL r;
    if (pcb) *pcb = 0;
    /* size query */
    SET_ERR(0);
    r = U(CryptDecodeObjectEx)(ENC, oid, der, n, flags, NULL, NULL, &cb);
    AEQ(r);
    if (!r) { t_note("  (%s:%d decode size-query failed 0x%lx)", file, line, GetLastError()); return NULL; }
    AEQ(cb > 0);
    /* too small buffer */
    if (cb >= 8) {
        void *small_ = LocalAlloc(LPTR, cb);
        DWORD c2 = cb / 2; SET_ERR(0);
        r = U(CryptDecodeObjectEx)(ENC, oid, der, n, flags, NULL, small_, &c2);
        AEQ(!r); AEQ(GetLastError() == ERROR_MORE_DATA); AEQ(c2 == cb);
        LocalFree(small_);
    }
    /* caller buffer */
    void *buf = LocalAlloc(LPTR, cb + 8);
    DWORD c3 = cb;
    r = U(CryptDecodeObjectEx)(ENC, oid, der, n, flags, NULL, buf, &c3);
    AEQ(r); AEQ(c3 <= cb);
    LocalFree(buf);
    /* ALLOC */
    void *p = NULL; DWORD c4 = 0;
    r = U(CryptDecodeObjectEx)(ENC, oid, der, n, flags | CRYPT_DECODE_ALLOC_FLAG, NULL, &p, &c4);
    AEQ(r); AEQ(p != NULL);
    if (pcb) *pcb = c4;
    return r ? p : NULL;
}

void a_dec_fail(const char *file, int line, LPCSTR oid, const BYTE *der, DWORD n, DWORD flags, DWORD err) {
    DWORD cb = 0, e; BOOL r;
    SET_ERR(0);
    r = U(CryptDecodeObjectEx)(ENC, oid, der, n, flags, NULL, NULL, &cb);
    e = GetLastError();
    t_check(!r, file, line, "decode size-query fails", "ret %d err 0x%lx", r, e);
    if (err) t_check(e == (err == A_ERR_NONE ? 0 : err), file, line, "decode size-query error", "got 0x%lx want 0x%lx", e, err == A_ERR_NONE ? 0 : err);
    void *p = (void *)(ULONG_PTR)1; cb = 99; SET_ERR(0);
    r = U(CryptDecodeObjectEx)(ENC, oid, der, n, flags | CRYPT_DECODE_ALLOC_FLAG, NULL, &p, &cb);
    e = GetLastError();
    t_check(!r, file, line, "decode ALLOC fails", "ret %d err 0x%lx", r, e);
    if (err) t_check(e == (err == A_ERR_NONE ? 0 : err), file, line, "decode ALLOC error", "got 0x%lx want 0x%lx", e, err == A_ERR_NONE ? 0 : err);
    /* the output pointer is either untouched or NULL on failure (it depends on the decoder); it is never an allocation */
    t_check(p == NULL || p == (void *)(ULONG_PTR)1, file, line, "no allocation returned on failure", "p %p cb %lu", p, cb);
    if (r && p) LocalFree(p);
}

void a_roundtrip_to(const char *file, int line, LPCSTR oid, const BYTE *der, DWORD n, const BYTE *exp, DWORD en) {
    DWORD cb = 0; BOOL r;
    void *p = NULL;
    r = U(CryptDecodeObjectEx)(ENC, oid, der, n, CRYPT_DECODE_ALLOC_FLAG, NULL, &p, &cb);
    t_check(r, file, line, "roundtrip decode", "err 0x%lx", GetLastError());
    if (!r) return;
    DWORD ecb = 0; BYTE *e = a_enc(oid, p, 0, &ecb);
    t_check(e != NULL, file, line, "roundtrip encode", "err 0x%lx", GetLastError());
    if (e) { a_diff(file, line, "roundtrip bytes", e, ecb, exp, en); LocalFree(e); }
    LocalFree(p);
}
void a_roundtrip(const char *file, int line, LPCSTR oid, const BYTE *der, DWORD n) { a_roundtrip_to(file, line, oid, der, n, der, n); }

void a_alias(const char *file, int line, LPCSTR a, LPCSTR b, const void *s) {
    DWORD ca = 0, cb = 0;
    BYTE *pa = a_enc(a, s, 0, &ca), *pb = a_enc(b, s, 0, &cb);
    AEQ(pa != NULL); AEQ(pb != NULL);
    if (pa && pb) { AEQ(ca == cb); AEQ(ca == cb && !memcmp(pa, pb, ca)); }
    if (pa) LocalFree(pa);
    if (pb) LocalFree(pb);
}

FILETIME a_ft(int y, int mo, int d, int h, int mi, int s) {
    SYSTEMTIME st; FILETIME ft;
    memset(&st, 0, sizeof st); st.wYear = y; st.wMonth = mo; st.wDay = d; st.wHour = h; st.wMinute = mi; st.wSecond = s;
    SystemTimeToFileTime(&st, &ft);
    return ft;
}
int a_ft_eq(FILETIME a, FILETIME b) { return a.dwLowDateTime == b.dwLowDateTime && a.dwHighDateTime == b.dwHighDateTime; }
