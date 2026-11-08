/* Shared helpers for ncrypt_ssl_args: argument validation of the ncrypt.dll Ssl* provider functions.
 * Expectations are written as OBS(n, call, UNK) while probing; the value Windows 10 returned replaces UNK.
 * OBSN is a note only (version/SKU dependent). No handshake, no network, no persistent state. */
#ifndef SA_H
#define SA_H
#include "t.h"
#include <bcrypt.h>
#include <ncrypt.h>

#define UNK 0x5EED5EED5EED5EEDull
static void obs_(int n, ULONG_PTR got, unsigned long long want, const char *file, int line, const char *expr)
{
    if (want == UNK) t_note("OBS %d 0x%llx", n, (unsigned long long)got);
    else t_expect_eq(got, (ULONG_PTR)want, 0, file, line, expr);
}
/* 32-bit status / value */
#define OBS(n, expr, want)  T_TRY_BEGIN obs_((n), (DWORD)(expr), (want), __FILE__, __LINE__, #expr); T_TRY_END(#expr)
/* the call faults (Windows 10 does not validate the handle pointer) */
#define OBSF(n, expr)       T_EXPECT_FAULT((void)(expr))
/* looped check: expectation for the k-th execution comes from the table VT_<n> */
#define OBSV(n, expr)       do { static int c_##n; T_TRY_BEGIN obs_((n), (DWORD)(expr), VT_##n[c_##n], __FILE__, __LINE__, #expr); T_TRY_END(#expr) c_##n++; } while (0)
/* note only */
#define OBSN(n, expr)       t_note("OBSN %d 0x%llx", (n), (unsigned long long)(ULONG_PTR)(expr))

#define SA_NEED() do { if (t_is_wine()) { t_skip("ncrypt Ssl* exports are aborting stubs under the emulator"); return; } } while (0)
#define SA_MAGIC_PROV 0x44444441u
#define SA_MAGIC_KEY  0x44444442u
#define SA_NTE_BAD_HANDLE 0x80090026u
#define SA_NTE_BAD_PARAM  0x80090027u

typedef LONG (WINAPI *sa_open_t)(ULONG_PTR *, LPCWSTR, DWORD);
typedef LONG (WINAPI *sa_freeobj_t)(ULONG_PTR);
typedef LONG (WINAPI *sa_freebuf_t)(void *);
typedef LONG (WINAPI *sa_incdec_t)(ULONG_PTR);
/* argument shapes taken from the public sslprovider.h layout; every argument is a 64 bit slot on x64 */
typedef LONG (WINAPI *sa_genmaster_t)(ULONG_PTR prov, ULONG_PTR priv, ULONG_PTR pub, ULONG_PTR *pmaster, DWORD proto, DWORD cs, void *params, BYTE *out, DWORD cbout, DWORD *pcb, DWORD flags);
typedef LONG (WINAPI *sa_gensess_t)(ULONG_PTR prov, ULONG_PTR master, ULONG_PTR *pread, ULONG_PTR *pwrite, void *params, DWORD flags);
typedef LONG (WINAPI *sa_impmaster_t)(ULONG_PTR prov, ULONG_PTR priv, ULONG_PTR *pmaster, DWORD proto, DWORD cs, void *params, BYTE *enc, DWORD cbenc, DWORD flags);
typedef LONG (WINAPI *sa_genpre_t)(ULONG_PTR prov, ULONG_PTR pub, ULONG_PTR *ppre, DWORD proto, DWORD cs, void *params, BYTE *out, DWORD cbout, DWORD *pcb, DWORD flags);
typedef LONG (WINAPI *sa_impkey_t)(ULONG_PTR prov, ULONG_PTR *pkey, LPCWSTR type, BYTE *blob, DWORD cb, DWORD flags);
typedef LONG (WINAPI *sa_expkey_t)(ULONG_PTR prov, ULONG_PTR key, LPCWSTR type, BYTE *out, DWORD cbout, DWORD *pcb, DWORD flags);
typedef LONG (WINAPI *sa_packet_t)(ULONG_PTR prov, ULONG_PTR key, BYTE *in, DWORD cbin, BYTE *out, DWORD cbout, DWORD *pcb, ULONGLONG seq, DWORD ctype, DWORD flags);
typedef LONG (WINAPI *sa_eap_t)(ULONG_PTR prov, ULONG_PTR master, BYTE *rand, DWORD cbrand, BYTE *out, DWORD cbout, DWORD *pcb, DWORD flags);
typedef LONG (WINAPI *sa_hashhs_t)(ULONG_PTR prov, ULONG_PTR hash, BYTE *in, DWORD cb, DWORD flags);
typedef LONG (WINAPI *sa_mkhash_t)(ULONG_PTR prov, ULONG_PTR *phash, DWORD proto, DWORD cs, DWORD flags);
typedef LONG (WINAPI *sa_lookup_info_t)(ULONG_PTR, DWORD, void *, void *, void *, DWORD);
typedef LONG (WINAPI *sa_lookup_len_t)(ULONG_PTR, DWORD, DWORD, DWORD, void *, DWORD, DWORD);
typedef LONG (WINAPI *sa_enumcs_t)(ULONG_PTR, ULONG_PTR, void **, void **, DWORD);
typedef LONG (WINAPI *sa_enumcsex_t)(ULONG_PTR, ULONG_PTR, void **, void **, DWORD, DWORD);
typedef LONG (WINAPI *sa_gen12_t)(ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR);

#define SF(type, name) type name = (type)t_proc_in("ncrypt.dll", #name)

static const WCHAR SA_PROV[] = L"Microsoft SSL Protocol Provider";
static ULONG_PTR sa_open(void) {
    SF(sa_open_t, SslOpenProvider); ULONG_PTR h = 0;
    if (!SslOpenProvider) return 0;
    if (!t_require(SslOpenProvider(&h, (LPCWSTR)SA_PROV, 0) == 0 && h != 0, __FILE__, __LINE__, "SslOpenProvider")) return 0;
    return h;
}
static void sa_close(ULONG_PTR h) { SF(sa_freeobj_t, SslFreeObject); if (h && SslFreeObject) SslFreeObject(h); }
static DWORD sa_ref(ULONG_PTR h) { return ((DWORD *)h)[4]; }
/* forged header: size, magic, 0, flag word, refcount */
static void sa_forge(DWORD *buf, DWORD size, DWORD magic, DWORD w3) {
    memset(buf, 0, 0x200); buf[0] = size; buf[1] = magic; buf[3] = w3;
}
/* a fresh public RSA key blob (generated with bcrypt, in memory) */
static BYTE *sa_rsa_pub_blob(DWORD bits, DWORD *pcb) {
    BCRYPT_ALG_HANDLE a = NULL; BCRYPT_KEY_HANDLE k = NULL; BYTE *b = NULL; ULONG cb = 0;
    if (U(BCryptOpenAlgorithmProvider)(&a, BCRYPT_RSA_ALGORITHM, NULL, 0)) return NULL;
    if (!U(BCryptGenerateKeyPair)(a, &k, bits, 0) && !U(BCryptFinalizeKeyPair)(k, 0)) {
        if (!U(BCryptExportKey)(k, NULL, BCRYPT_RSAPUBLIC_BLOB, NULL, 0, &cb, 0) && cb) {
            b = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cb);
            if (b && U(BCryptExportKey)(k, NULL, BCRYPT_RSAPUBLIC_BLOB, b, cb, &cb, 0)) { HeapFree(GetProcessHeap(), 0, b); b = NULL; }
        }
    }
    if (k) U(BCryptDestroyKey)(k);
    U(BCryptCloseAlgorithmProvider)(a, 0);
    if (b) *pcb = cb;
    return b;
}
#endif
