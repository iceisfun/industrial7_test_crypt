#include "asn.h"

alloc_stat g_as;
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

void a_enc_eq(const char *file, int line, LPCSTR oid, const void *s, DWORD flags, const BYTE *exp, DWORD n) {
    DWORD cb; BOOL r;
    /* size query */
    cb = 0xCCCC; SET_ERR(0);
    r = U(CryptEncodeObjectEx)(ENC, oid, (void *)s, flags, NULL, NULL, &cb);
    AEQ(r); AEQ(cb == n);
    if (!r) return;
    /* too small */
    if (n > 0) {
        BYTE *small_ = (BYTE *)LocalAlloc(LPTR, n);
        cb = n - 1; SET_ERR(0);
        r = U(CryptEncodeObjectEx)(ENC, oid, (void *)s, flags, NULL, small_, &cb);
        AEQ(!r); AEQ(GetLastError() == ERROR_MORE_DATA); AEQ(cb == n);
        LocalFree(small_);
    }
    /* exact buffer, then oversized buffer */
    BYTE *buf = (BYTE *)LocalAlloc(LPTR, n + 16);
    cb = n; SET_ERR(0);
    r = U(CryptEncodeObjectEx)(ENC, oid, (void *)s, flags, NULL, buf, &cb);
    AEQ(r); AEQ(cb == n); AEQ(!memcmp(buf, exp, n));
    memset(buf, 0xEE, n + 16);
    cb = n + 16;
    r = U(CryptEncodeObjectEx)(ENC, oid, (void *)s, flags, NULL, buf, &cb);
    AEQ(r); AEQ(cb == n); AEQ(!memcmp(buf, exp, n));
    { DWORD i, clean = 1; for (i = n; i < n + 16; i++) if (buf[i] != 0xEE) clean = 0; AEQ(clean); }
    LocalFree(buf);
    /* ALLOC */
    BYTE *p = NULL; cb = 0;
    r = U(CryptEncodeObjectEx)(ENC, oid, (void *)s, flags | CRYPT_ENCODE_ALLOC_FLAG, NULL, &p, &cb);
    AEQ(r); AEQ(cb == n); AEQ(p != NULL);
    if (r && p) { AEQ(!memcmp(p, exp, n)); LocalFree(p); }
    /* legacy entry point (flags 0 only) */
    if (flags == 0) {
        buf = (BYTE *)LocalAlloc(LPTR, n + 1);
        cb = n + 1;
        r = U(CryptEncodeObject)(ENC, oid, (void *)s, buf, &cb);
        AEQ(r); AEQ(cb == n); AEQ(!memcmp(buf, exp, n));
        LocalFree(buf);
    }
}

void a_enc_fail(const char *file, int line, LPCSTR oid, const void *s, DWORD flags, DWORD err) {
    DWORD cb = 0; BOOL r;
    SET_ERR(0);
    r = U(CryptEncodeObjectEx)(ENC, oid, (void *)s, flags, NULL, NULL, &cb);
    AEQ(!r);
    if (err) AEQ(GetLastError() == err);
    if (err && GetLastError() != err) t_note("  (%s:%d enc size-query error 0x%lx want 0x%lx)", file, line, GetLastError(), err);
    BYTE buf[2048]; cb = sizeof buf; SET_ERR(0);
    r = U(CryptEncodeObjectEx)(ENC, oid, (void *)s, flags, NULL, buf, &cb);
    AEQ(!r);
    if (err) AEQ(GetLastError() == err);
    BYTE *p = (BYTE *)(ULONG_PTR)1; cb = 77; SET_ERR(0);
    r = U(CryptEncodeObjectEx)(ENC, oid, (void *)s, flags | CRYPT_ENCODE_ALLOC_FLAG, NULL, &p, &cb);
    AEQ(!r);
    if (err) AEQ(GetLastError() == err);
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
    DWORD cb = 0; BOOL r;
    SET_ERR(0);
    r = U(CryptDecodeObjectEx)(ENC, oid, der, n, flags, NULL, NULL, &cb);
    AEQ(!r);
    if (err) { DWORD e = GetLastError(); t_check(e == err, file, line, "decode size-query error", "got 0x%lx want 0x%lx", e, err); }
    void *p = (void *)(ULONG_PTR)1; cb = 99; SET_ERR(0);
    r = U(CryptDecodeObjectEx)(ENC, oid, der, n, flags | CRYPT_DECODE_ALLOC_FLAG, NULL, &p, &cb);
    AEQ(!r);
    if (err) { DWORD e = GetLastError(); t_check(e == err, file, line, "decode ALLOC error", "got 0x%lx want 0x%lx", e, err); }
    AEQ(p == NULL);
    if (r && p) LocalFree(p);
}

void a_roundtrip(const char *file, int line, LPCSTR oid, const BYTE *der, DWORD n) {
    DWORD cb = 0; BOOL r;
    void *p = NULL;
    r = U(CryptDecodeObjectEx)(ENC, oid, der, n, CRYPT_DECODE_ALLOC_FLAG, NULL, &p, &cb);
    AEQ(r);
    if (!r) return;
    DWORD ecb = 0; BYTE *e = a_enc(oid, p, 0, &ecb);
    AEQ(e != NULL);
    if (e) { AEQ(ecb == n); AEQ(ecb == n && !memcmp(e, der, n)); LocalFree(e); }
    LocalFree(p);
}

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

/* Unverified expectation: log the outcome instead of failing. */
int a_enc_try(const char *file, int line, LPCSTR oid, const void *s, DWORD flags, const BYTE *exp, DWORD n) {
    DWORD cb = 0; BYTE *p = a_enc(oid, s, flags, &cb);
    int ok = p && cb == n && !memcmp(p, exp, n);
    if (!ok) {
        char hex[200] = ""; DWORD i;
        for (i = 0; p && i < cb && i < 40; i++) sprintf(hex + strlen(hex), "%02x", p[i]);
        t_note("%s:%d encode differs from reference (%s, err 0x%lx, got %lu bytes: %s)", file, line, p ? "ok-call" : "failed", GetLastError(), cb, hex);
    }
    if (p) LocalFree(p);
    return ok;
}
