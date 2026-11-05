/* Shared declarations for the SystemFunctionNNN tests.
 * Identities and signatures of the cryptbase / cryptsp / advapi32 exports were
 * confirmed by probing Windows 10 22H2. */
#ifndef SF_H
#define SF_H
#include "t.h"

#define ST_SUCCESS        ((LONG)0x00000000)
#define ST_UNSUCCESSFUL   ((LONG)0xC0000001)
#define ST_INVALID_PARAM  ((LONG)0xC000000D)
#define ST_BUF_TOO_SMALL  ((LONG)0xC0000023)
#define ST_INVALID_PARAM1 ((LONG)0xC00000EF)
#define ST_INVALID_PARAM2 ((LONG)0xC00000F0)
#define ST_UNKNOWN_REV    ((LONG)0xC0000058)

/* ULONG-length string used by SystemFunction004/005/032/033 */
typedef struct { ULONG Length; ULONG MaximumLength; PVOID Buffer; } SF_USTR;

typedef LONG    (WINAPI *sf_block_fn)(const BYTE *in, const BYTE *key, BYTE *out);
typedef LONG    (WINAPI *sf_des1_fn)(const BYTE *key7, BYTE *out8);
typedef LONG    (WINAPI *sf_ustr3_fn)(SF_USTR *data, SF_USTR *key, SF_USTR *out);
typedef LONG    (WINAPI *sf_ustr2_fn)(SF_USTR *data, SF_USTR *key);
typedef LONG    (WINAPI *sf_lm_fn)(const char *pw, BYTE *out16);
typedef LONG    (WINAPI *sf_nt_fn)(const UNICODE_STRING *pw, BYTE *out16);
typedef LONG    (WINAPI *sf_sess_fn)(const void *unused, const BYTE *in16, BYTE *out16);
typedef BYTE    (WINAPI *sf_cmp_fn)(const void *a, const void *b);
typedef BYTE    (WINAPI *sf_rand_fn)(void *buf, ULONG len);
typedef LONG    (WINAPI *sf_mem_fn)(void *mem, ULONG size, ULONG flags);

/* Which DLL really implements each export (advapi32 forwards the rest). */
static const char *sf_impl(int n)
{
    switch (n) {
    case 1: case 2: case 3: case 4: case 5: case 28: case 29: case 34: case 36: case 40: case 41:
        return "cryptbase.dll";
    case 17: case 19:
        return "advapi32.dll";
    default:
        return "cryptsp.dll";
    }
}

static FARPROC sf_raw(const char *dll, int n)
{
    char nm[32];
    wsprintfA(nm, "SystemFunction%03d", n);
    return t_proc_in(dll, nm);
}
/* Like sf_raw, but under an emulator that lacks the split cryptbase/cryptsp modules the
 * lookup falls back to advapi32 so the behavioural tests can still be exercised there. */
static FARPROC sf_in(const char *dll, int n)
{
    FARPROC p;
    if (t_is_wine()) return sf_raw("advapi32.dll", n);   /* emulator: the split modules are stubs */
    p = sf_raw(dll, n);
    return p;
}
static FARPROC sf_adv(int n) { return sf_in("advapi32.dll", n); }

/* The two modules through which function n is reachable (may be the same twice). */
static void sf_mods(int n, const char *out[2]) { out[0] = "advapi32.dll"; out[1] = sf_impl(n); }

static void sf_hex(const BYTE *p, size_t n, char *out)
{
    static const char d[] = "0123456789abcdef";
    size_t i;
    for (i = 0; i < n; i++) { out[2 * i] = d[p[i] >> 4]; out[2 * i + 1] = d[p[i] & 15]; }
    out[2 * n] = 0;
}
static int sf_unhex(const char *s, BYTE *out, size_t max)
{
    size_t n = 0;
    while (s[0] && s[1] && n < max) {
        int a = s[0] <= '9' ? s[0] - '0' : (s[0] | 32) - 'a' + 10;
        int b = s[1] <= '9' ? s[1] - '0' : (s[1] | 32) - 'a' + 10;
        out[n++] = (BYTE)(a * 16 + b); s += 2;
    }
    return (int)n;
}

/* CHECK that two byte buffers are equal, printing both as hex on failure. */
#define CHECK_BYTES(got, want, n) do { \
    char g_[1100], w_[1100]; size_t n_ = (size_t)(n); \
    if (n_ > 500) n_ = 500; \
    sf_hex((const BYTE *)(got), n_, g_); sf_hex((const BYTE *)(want), n_, w_); \
    t_check(!memcmp((got), (want), (size_t)(n)), __FILE__, __LINE__, "bytes " #got " == " #want, "got %s want %s", g_, w_); } while (0)

#define NTST(a, b) EXPECT_EQ((ULONG)(a), (ULONG)(b))
#endif
