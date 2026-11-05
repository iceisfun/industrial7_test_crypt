/* Shared helpers for the crypt32 ASN.1 certificate-structure tests.
 * Every call goes through GetProcAddress (U()); expectations are fixed DER vectors from asn_vectors.h. */
#ifndef ASN_H
#define ASN_H
#include "t.h"
#include <wincrypt.h>
#include "asn_vectors.h"

#define ENC X509_ASN_ENCODING
extern const char *a_ctx; /* optional row label added to the stage label of encode checks */
#define A_SZ(a) ((DWORD)sizeof(a))
#define AEQ(c) t_check(!!(c), file, line, #c, NULL)

#ifndef CRYPT_E_ASN1_ERROR
#define CRYPT_E_ASN1_ERROR 0x80093100L
#endif
/* expected last error for a_dec_fail: the decoder leaves it at 0 */
#define A_ERR_NONE      ((DWORD)0xFFFFFFFE)
#define HR_ASN1_EOD     ((DWORD)0x80093102)
#define HR_ASN1_CORRUPT ((DWORD)0x80093103)
#define HR_ASN1_LARGE   ((DWORD)0x80093104)
#define HR_ASN1_BADTAG  ((DWORD)0x8009310B)
#define HR_ASN1_CHOICE  ((DWORD)0x8009310C)
#define HR_INVALIDARG   ((DWORD)0x80070057)
#define HR_OUTOFMEMORY  ((DWORD)0x8007000E)

/* ---- custom allocator -------------------------------------------------- */
typedef struct { int allocs, frees; void *last; size_t lastsz; int fail; } alloc_stat;
extern alloc_stat g_as;
void *WINAPI as_alloc(size_t n);
void WINAPI as_free(void *p);
#define AS_RESET() do { memset(&g_as, 0, sizeof g_as); } while (0)

/* ---- encode ------------------------------------------------------------ */
/* Full protocol check of CryptEncodeObjectEx/CryptEncodeObject against the expected DER. */
void a_enc_eq(const char *file, int line, LPCSTR oid, const void *s, DWORD flags, const BYTE *exp, DWORD n);
#define ENC_EQ(oid, s, v) a_enc_eq(__FILE__, __LINE__, oid, s, 0, v, A_SZ(v))
#define ENC_EQF(oid, s, fl, v) a_enc_eq(__FILE__, __LINE__, oid, s, fl, v, A_SZ(v))
/* ALLOC encode; returns LocalAlloc'd buffer or NULL (error left in GetLastError). */
BYTE *a_enc(LPCSTR oid, const void *s, DWORD flags, DWORD *cb);
/* Encode must fail: checks FALSE (size query and with buffer) and GetLastError == err (err==0: any). */
void a_enc_fail(const char *file, int line, LPCSTR oid, const void *s, DWORD flags, DWORD err);
#define ENC_FAIL(oid, s, err) a_enc_fail(__FILE__, __LINE__, oid, s, 0, err)

/* ---- decode ------------------------------------------------------------ */
/* Decode with the full size protocol check; returns LocalAlloc'd struct (ALLOC) or NULL. */
void *a_dec(const char *file, int line, LPCSTR oid, const BYTE *der, DWORD n, DWORD flags, DWORD *cb);
#define DEC(oid, v, fl, pcb) a_dec(__FILE__, __LINE__, oid, v, A_SZ(v), fl, pcb)
/* Decode must fail with err (0: any error) for both ALLOC and size-query forms. */
void a_dec_fail(const char *file, int line, LPCSTR oid, const BYTE *der, DWORD n, DWORD flags, DWORD err);
#define DEC_FAIL(oid, v, err) a_dec_fail(__FILE__, __LINE__, oid, v, A_SZ(v), 0, err)
/* decode(v) -> encode -> must equal v. */
void a_roundtrip(const char *file, int line, LPCSTR oid, const BYTE *der, DWORD n);
#define ROUNDTRIP(oid, v) a_roundtrip(__FILE__, __LINE__, oid, v, A_SZ(v))
/* decode(v) -> encode -> must equal exp (for inputs the encoder normalizes). */
void a_roundtrip_to(const char *file, int line, LPCSTR oid, const BYTE *der, DWORD n, const BYTE *exp, DWORD en);
#define ROUNDTRIP_TO(oid, v, e) a_roundtrip_to(__FILE__, __LINE__, oid, v, A_SZ(v), e, A_SZ(e))
/* Encode oid1 and oid2 of the same struct: identical output (alias check). */
void a_alias(const char *file, int line, LPCSTR a, LPCSTR b, const void *s);

/* Byte-exact comparison; a mismatch prints both buffers in hex. */
void a_diff(const char *file, int line, const char *what, const BYTE *got, DWORD gn, const BYTE *want, DWORD wn);
#define DIFF(what, got, gn, want, wn) a_diff(__FILE__, __LINE__, what, got, gn, want, wn)

FILETIME a_ft(int y, int mo, int d, int h, int mi, int s);
int a_ft_eq(FILETIME a, FILETIME b);
#define PTR_IN(p, base, sz) ((const BYTE *)(p) >= (const BYTE *)(base) && (const BYTE *)(p) < (const BYTE *)(base) + (sz))
#endif
