#include "kp.h"

typedef BOOL (WINAPI *encex_t)(DWORD, LPCSTR, const void *, DWORD, PCRYPT_ENCODE_PARA, void *, DWORD *);
typedef BOOL (WINAPI *enc_t)(DWORD, LPCSTR, const void *, BYTE *, DWORD *);
typedef BOOL (WINAPI *decex_t)(DWORD, LPCSTR, const BYTE *, DWORD, DWORD, PCRYPT_DECODE_PARA, void *, DWORD *);
typedef BOOL (WINAPI *dec_t)(DWORD, LPCSTR, const BYTE *, DWORD, DWORD, void *, DWORD *);

static encex_t pEncEx(void) { return (encex_t)t_proc_in("crypt32.dll", "CryptEncodeObjectEx"); }
static enc_t   pEnc(void)   { return (enc_t)t_proc_in("crypt32.dll", "CryptEncodeObject"); }
static decex_t pDecEx(void) { return (decex_t)t_proc_in("crypt32.dll", "CryptDecodeObjectEx"); }
static dec_t   pDec(void)   { return (dec_t)t_proc_in("crypt32.dll", "CryptDecodeObject"); }

void kp_free(void *p) { if (p) LocalFree(p); }

BYTE *kp_enc_alloc(LPCSTR type, const void *info, DWORD flags, DWORD *cb) {
    BYTE *out = (BYTE *)(ULONG_PTR)1; DWORD n = 0;
    if (!pEncEx()(KP_ENC, type, info, flags | CRYPT_ENCODE_ALLOC_FLAG, NULL, &out, &n)) return NULL;
    if (cb) *cb = n;
    return out;
}
void *kp_dec_alloc(LPCSTR type, const BYTE *der, size_t len, DWORD flags, DWORD *cb) {
    void *out = (void *)(ULONG_PTR)1; DWORD n = 0;
    if (!pDecEx()(KP_ENC, type, der, (DWORD)len, flags | CRYPT_DECODE_ALLOC_FLAG, NULL, &out, &n)) return NULL;
    if (cb) *cb = n;
    return out;
}

void kp_blob_is(const char *file, int line, const char *what, DWORD cb, const BYTE *pb, const BYTE *want, size_t n) {
    t_check(cb == n && (n == 0 || (pb && !memcmp(pb, want, n))), file, line, what, "blob mismatch: cb=%lu want %zu", (unsigned long)cb, n);
}

void kp_check_enc(const char *file, int line, LPCSTR type, const void *info, const BYTE *want, size_t n) {
    DWORD cb = 0xCCCCCCCC; BOOL ok; BYTE *buf;
    /* size query */
    SetLastError(0xDEAD);
    ok = pEncEx()(KP_ENC, type, info, 0, NULL, NULL, &cb);
    t_check(ok && cb == n, file, line, "Ex size query", "ok=%d cb=%lu want %zu err=%lx", ok, (unsigned long)cb, n, GetLastError());
    if (!ok || cb != n) return;
    buf = (BYTE *)LocalAlloc(LPTR, n + 8);
    /* too small */
    if (n > 0) {
        memset(buf, 0xAA, n + 8);
        cb = (DWORD)n - 1; SetLastError(0xDEAD);
        ok = pEncEx()(KP_ENC, type, info, 0, NULL, buf, &cb);
        t_check(!ok && GetLastError() == ERROR_MORE_DATA && cb == n, file, line, "Ex too small", "ok=%d err=%lx cb=%lu", ok, GetLastError(), (unsigned long)cb);
    }
    /* exact + guard bytes */
    memset(buf, 0xAA, n + 8);
    cb = (DWORD)n;
    ok = pEncEx()(KP_ENC, type, info, 0, NULL, buf, &cb);
    t_check(ok && cb == n && !memcmp(buf, want, n), file, line, "Ex exact bytes", "ok=%d cb=%lu err=%lx", ok, (unsigned long)cb, GetLastError());
    { size_t i; int bad = 0; for (i = n; i < n + 8; i++) if (buf[i] != 0xAA) bad = 1; t_check(!bad, file, line, "no write past cb", NULL); }
    /* oversize buffer: cb is lowered to actual length */
    memset(buf, 0xAA, n + 8);
    cb = (DWORD)n + 8;
    ok = pEncEx()(KP_ENC, type, info, 0, NULL, buf, &cb);
    t_check(ok && cb == n && !memcmp(buf, want, n), file, line, "Ex oversize buffer", "cb=%lu", (unsigned long)cb);
    /* plain API */
    cb = 0; ok = pEnc()(KP_ENC, type, info, NULL, &cb);
    t_check(ok && cb == n, file, line, "plain size query", "ok=%d cb=%lu", ok, (unsigned long)cb);
    memset(buf, 0xAA, n + 8); cb = (DWORD)n;
    ok = pEnc()(KP_ENC, type, info, buf, &cb);
    t_check(ok && cb == n && !memcmp(buf, want, n), file, line, "plain exact", NULL);
    LocalFree(buf);
    /* alloc */
    { DWORD c2 = 0; BYTE *a = kp_enc_alloc(type, info, 0, &c2);
      t_check(a && c2 == n && !memcmp(a, want, n), file, line, "Ex alloc", "a=%p c2=%lu", a, (unsigned long)c2);
      kp_free(a); }
}

void kp_check_enc_fail(const char *file, int line, LPCSTR type, const void *info, DWORD err) {
    DWORD cb = 100; BYTE buf[512]; BOOL ok;
    SetLastError(0xDEAD);
    ok = pEncEx()(KP_ENC, type, info, 0, NULL, buf, &cb);
    t_check(!ok, file, line, "Ex must fail", NULL);
    if (err) t_check(GetLastError() == err, file, line, "Ex last error", "got 0x%lx want 0x%lx", GetLastError(), (unsigned long)err);
    SetLastError(0xDEAD); cb = 100;
    ok = pEnc()(KP_ENC, type, info, buf, &cb);
    t_check(!ok, file, line, "plain must fail", NULL);
    if (err) t_check(GetLastError() == err, file, line, "plain last error", "got 0x%lx want 0x%lx", GetLastError(), (unsigned long)err);
}

void kp_check_dec_fail(const char *file, int line, LPCSTR type, const BYTE *der, size_t n, DWORD err) {
    DWORD cb = 4096; BYTE buf[4096]; BOOL ok;
    SetLastError(0xDEAD);
    ok = pDecEx()(KP_ENC, type, der, (DWORD)n, 0, NULL, buf, &cb);
    t_check(!ok, file, line, "decode must fail", NULL);
    if (err == KP_E_TRUNC) t_check(GetLastError() == KP_E_EOD || GetLastError() == KP_E_CORRUPT, file, line, "decode last error (EOD or CORRUPT)", "got 0x%lx", GetLastError());
    else if (err) t_check(GetLastError() == err, file, line, "decode last error", "got 0x%lx want 0x%lx", GetLastError(), (unsigned long)err);
    SetLastError(0xDEAD); cb = 4096;
    ok = pDec()(KP_ENC, type, der, (DWORD)n, 0, buf, &cb);
    t_check(!ok, file, line, "plain decode must fail", NULL);
    if (err == KP_E_TRUNC) t_check(GetLastError() == KP_E_EOD || GetLastError() == KP_E_CORRUPT, file, line, "plain decode last error (EOD or CORRUPT)", "got 0x%lx", GetLastError());
    else if (err) t_check(GetLastError() == err, file, line, "plain decode last error", "got 0x%lx want 0x%lx", GetLastError(), (unsigned long)err);
}

void *kp_check_dec(const char *file, int line, LPCSTR type, const BYTE *der, size_t n, DWORD flags) {
    DWORD cb = 0, cb2; BOOL ok; BYTE *buf; void *res;
    SetLastError(0xDEAD);
    ok = pDecEx()(KP_ENC, type, der, (DWORD)n, flags, NULL, NULL, &cb);
    t_check(ok && cb > 0, file, line, "decode size query", "ok=%d cb=%lu err=0x%lx", ok, (unsigned long)cb, GetLastError());
    if (!ok) return NULL;
    buf = (BYTE *)LocalAlloc(LPTR, cb + 16);
    cb2 = 1; SetLastError(0xDEAD);
    ok = pDecEx()(KP_ENC, type, der, (DWORD)n, flags, NULL, buf, &cb2);
    t_check(!ok && GetLastError() == ERROR_MORE_DATA && cb2 == cb, file, line, "decode too small", "ok=%d err=0x%lx cb2=%lu cb=%lu", ok, GetLastError(), (unsigned long)cb2, (unsigned long)cb);
    LocalFree(buf);
    res = kp_dec_alloc(type, der, n, flags, &cb2);
    t_check(res != NULL && cb2 == cb, file, line, "decode alloc", "res=%p cb2=%lu cb=%lu", res, (unsigned long)cb2, (unsigned long)cb);
    return res;
}

int kp_type_known(LPCSTR type) {
    BYTE buf[16]; DWORD cb = sizeof buf; static const BYTE der[] = {0x30, 0};
    SetLastError(0);
    pDecEx()(KP_ENC, type, der, 2, 0, NULL, buf, &cb);
    return GetLastError() != ERROR_FILE_NOT_FOUND;
}
