/* Shared helpers for the ncrypt_provider_ephemeral_keys area. Every NCrypt call goes through U()/UIN(). */
#ifndef NC_H
#define NC_H
#include "t.h"
#include <bcrypt.h>
#include <ncrypt.h>
#include "nc_vectors.h"

#define NC_BAD_SIGNATURE     0x80090006u
#define NC_BAD_DATA          0x80090005u
#define NC_BAD_FLAGS         0x80090009u
#define NC_BAD_KEY_STATE     0x8009000Bu
#define NC_PERMISSION_DENIED 0x80090010u
#define NC_NOT_FOUND         0x80090011u
#define NC_INVALID_HANDLE    0x80090026u
#define NC_INVALID_PARAMETER 0x80090027u
#define NC_BUFFER_TOO_SMALL  0x80090028u
#define NC_NOT_SUPPORTED     0x80090029u
#define NC_NO_MEMORY         0x8009000Eu

/* SECURITY_STATUS is a LONG: compare as DWORD so the high bit does not sign-extend. */
#define EXPECT_SS(a, code) do { DWORD s_ = (DWORD)(a); t_check(s_ == (DWORD)(code), __FILE__, __LINE__, #a " == " #code, "got 0x%08lx want 0x%08lx", s_, (DWORD)(code)); } while (0)
#define EXPECT_SS_FAIL(a) do { DWORD s_ = (DWORD)(a); t_check(s_ != 0, __FILE__, __LINE__, #a " must fail", "unexpected success"); } while (0)
/* Skip (and flag on real Windows) when an object could not be created. */
#define NEED(x, what) do { if (!(x)) { CHECKF(t_is_wine(), "cannot create %s", what); t_skip("%s unavailable", what); return; } } while (0)
#define NCV(arr) (arr), (DWORD)sizeof(arr)

static const WCHAR NC_MSKSP[] = L"Microsoft Software Key Storage Provider";

static NCRYPT_PROV_HANDLE nc_prov(void)
{
    NCRYPT_PROV_HANDLE h = 0;
    if (!U(NCryptOpenStorageProvider)) return 0;
    if (U(NCryptOpenStorageProvider)(&h, NULL, 0) != 0) return 0;
    return h;
}

static void nc_free(NCRYPT_HANDLE h) { if (h) U(NCryptFreeObject)(h); }

/* Create an ephemeral key. bits==0: leave default; expol/usage == 0xFFFFFFFF: leave default. */
static NCRYPT_KEY_HANDLE nc_newkey_ex(NCRYPT_PROV_HANDLE p, LPCWSTR alg, DWORD bits, DWORD expol, DWORD usage, BOOL finalize, DWORD createflags)
{
    NCRYPT_KEY_HANDLE k = 0;
    if (U(NCryptCreatePersistedKey)(p, &k, alg, NULL, 0, createflags) != 0) return 0;
    if (bits && U(NCryptSetProperty)(k, NCRYPT_LENGTH_PROPERTY, (PBYTE)&bits, 4, 0) != 0) goto fail;
    if (expol != 0xFFFFFFFFu && U(NCryptSetProperty)(k, NCRYPT_EXPORT_POLICY_PROPERTY, (PBYTE)&expol, 4, 0) != 0) goto fail;
    if (usage != 0xFFFFFFFFu && U(NCryptSetProperty)(k, NCRYPT_KEY_USAGE_PROPERTY, (PBYTE)&usage, 4, 0) != 0) goto fail;
    if (finalize && U(NCryptFinalizeKey)(k, 0) != 0) goto fail;
    return k;
fail:
    U(NCryptFreeObject)(k);
    return 0;
}
static NCRYPT_KEY_HANDLE nc_newkey(NCRYPT_PROV_HANDLE p, LPCWSTR alg, DWORD bits, DWORD expol, BOOL finalize)
{
    return nc_newkey_ex(p, alg, bits, expol, 0xFFFFFFFFu, finalize, 0);
}
#define NC_EXP_ALL (NCRYPT_ALLOW_EXPORT_FLAG | NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG)

/* Import a plaintext BCRYPT blob as an ephemeral key (no key name buffer => not persisted). */
static NCRYPT_KEY_HANDLE nc_import(NCRYPT_PROV_HANDLE p, LPCWSTR type, const void *blob, DWORD cb)
{
    NCRYPT_KEY_HANDLE k = 0;
    if (U(NCryptImportKey)(p, 0, type, NULL, &k, (PBYTE)blob, cb, 0) != 0) return 0;
    return k;
}

static DWORD nc_getdw(NCRYPT_HANDLE h, LPCWSTR prop, DWORD *out)
{
    DWORD cb = 0;
    *out = 0xCDCDCDCDu;
    return (DWORD)U(NCryptGetProperty)(h, prop, (PBYTE)out, 4, &cb, 0);
}

/* Returns malloc'd property bytes (caller frees) or NULL; *pcb receives the size. */
static BYTE *nc_getprop(NCRYPT_HANDLE h, LPCWSTR prop, DWORD *pcb)
{
    DWORD cb = 0;
    BYTE *b;
    if (U(NCryptGetProperty)(h, prop, NULL, 0, &cb, 0) != 0 || !cb) return NULL;
    b = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cb + 8);
    if (!b) return NULL;
    if (U(NCryptGetProperty)(h, prop, b, cb, &cb, 0) != 0) { HeapFree(GetProcessHeap(), 0, b); return NULL; }
    *pcb = cb;
    return b;
}
static void nc_hfree(void *p) { if (p) HeapFree(GetProcessHeap(), 0, p); }

static int nc_isdigest(const BYTE *a, const BYTE *b, size_t n) { return !memcmp(a, b, n); }
#endif
