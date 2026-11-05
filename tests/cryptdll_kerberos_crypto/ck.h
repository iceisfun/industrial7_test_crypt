/* Shared declarations for the cryptdll_kerberos_crypto area.
 * Nothing here links against cryptdll.dll: every entry point is resolved with GetProcAddress
 * (t_proc_in("cryptdll.dll", ...)) and invoked through a typed pointer.
 *
 * cryptdll.dll is the Kerberos/NTLM crypto toolbox. It has no public header for these exports; the
 * prototypes and table layouts below were taken from the Windows 10 19041 decompilation:
 *   - the crypto-system table has 0x80-byte entries (up to 23 usable), checksum table 0x40-byte entries
 *     (up to 24), RNG table 0x18-byte entries (up to 4);
 *   - lookup helpers return NTSTATUS-like codes (0x80080341 / 0x80080342 when not found).
 */
#ifndef CK_H
#define CK_H
#include "t.h"
#include <stdlib.h>
#include <stdint.h>
#include <wchar.h>

#define CK_DLL "cryptdll.dll"
#define CKP(name) ((name##_pfn)t_proc_in(CK_DLL, #name))

#define NS_OK            ((NTSTATUS)0x00000000)
#define NS_UNSUCCESSFUL  ((NTSTATUS)0xC0000001)
#define NS_NOT_IMPL      ((NTSTATUS)0xC0000002)
#define NS_INVALID_PARAM ((NTSTATUS)0xC000000D)
#define NS_BUF_TOO_SMALL ((NTSTATUS)0xC0000023)
#define NS_NOT_SUPPORTED ((NTSTATUS)0xC00000BB)
#define NS_INSUFF_RES    ((NTSTATUS)0xC000009A)
#define NS_NO_CSYSTEM    ((NTSTATUS)0x80080341)
#define NS_NO_CHECKSUM   ((NTSTATUS)0x80080342)
#define NS_MSG_ALTERED   ((NTSTATUS)0x8009030F)

/* encryption types */
#define ET_DES_CRC 1
#define ET_DES_MD5 3
#define ET_AES128 17
#define ET_AES256 18
#define ET_RC4_HMAC 23
#define ET_RC4_HMAC_EXP 24
#define ET_RC4_MD4 (-128)
#define ET_DES_PLAIN (-132)
#define ET_RC4_HMAC_OLD (-133)
#define ET_RC4_PLAIN_OLD (-134)
#define ET_RC4_HMAC_OLD_EXP (-135)
#define ET_RC4_PLAIN_OLD_EXP (-136)
#define ET_RC4_PLAIN (-140)
#define ET_RC4_PLAIN_EXP (-141)
#define ET_AES128_PLAIN (-148)
#define ET_AES256_PLAIN (-149)
/* checksum types */
#define CS_CRC32 1
#define CS_MD4 2
#define CS_MD5 7
#define CS_AES128 15
#define CS_AES256 16
#define CS_SHA1 (-131)
#define CS_REAL_CRC32 (-132)
#define CS_MD5_HMAC (-137)
#define CS_HMAC_MD5 (-138)
#define CS_AES128_KI (-150)
#define CS_AES256_KI (-151)

#define CSYS_INTEGRITY 0x4   /* attribute bit toggled by CDGetIntegrityVect */

/* crypto system entry (0x80 bytes) */
typedef struct {
    ULONG EncryptionType, BlockSize, ExportableEncryptionType, KeySize;     /* 0x00 */
    ULONG HeaderSize, PreferredCheckSum, Attributes, Pad;                   /* 0x10 */
    PCWSTR Name;                                                            /* 0x20 */
    void *Initialize, *Encrypt, *Decrypt, *Finish, *HashPassword, *RandomKey, *Control; /* 0x28..0x58 */
    void *Rsv60, *Rsv68, *Rsv70;                                            /* 0x60.. */
    void *PrfPlus;                                                          /* 0x78 */
} CSX;
/* checksum entry (0x40 bytes) */
typedef struct {
    ULONG Type, Size, Attributes, Pad;
    void *Initialize, *Sum, *Finalize, *Finish, *InitializeEx, *InitializeEx2;
} CKX;
/* rng entry (0x18 bytes) */
typedef struct { ULONG Type, Pad; void *P1; void *P2; } RNX;

typedef NTSTATUS (WINAPI *csx_init_fn)(PUCHAR key, ULONG keysz, ULONG usage, PVOID *st);
typedef NTSTATUS (WINAPI *csx_crypt_fn)(PVOID st, PUCHAR in, ULONG inlen, PUCHAR out, PULONG outlen);
typedef NTSTATUS (WINAPI *csx_fin_fn)(PVOID *st);
typedef NTSTATUS (WINAPI *csx_hashpw_fn)(PUNICODE_STRING pw, PUNICODE_STRING salt, ULONG count, PUCHAR key);
typedef NTSTATUS (WINAPI *csx_rndkey_fn)(PUCHAR seed, ULONG seedlen, PUCHAR key);
typedef NTSTATUS (WINAPI *csx_ctl_fn)(ULONG fn, PVOID st, PUCHAR in, ULONG len);
typedef NTSTATUS (WINAPI *csx_prf_fn)(PUCHAR key, ULONG keylen, PUCHAR s, ULONG slen, PUCHAR out, ULONG outlen);
typedef NTSTATUS (WINAPI *ckx_init_fn)(ULONG seed, PVOID *ctx);
typedef NTSTATUS (WINAPI *ckx_sum_fn)(PVOID ctx, ULONG len, PUCHAR buf);
typedef NTSTATUS (WINAPI *ckx_final_fn)(PVOID ctx, PUCHAR out);
typedef NTSTATUS (WINAPI *ckx_finish_fn)(PVOID *ctx);
typedef NTSTATUS (WINAPI *ckx_initex_fn)(PUCHAR key, ULONG keysz, ULONG usage, PVOID *ctx);
typedef BOOLEAN (WINAPI *rng_fn)(PUCHAR buf, ULONG len);

/* exports (not in any SDK header) */
UDECL(NTSTATUS, CDLocateCSystem, (LONG etype, CSX **out));
UDECL(NTSTATUS, CDLocateCheckSum, (LONG type, CKX **out));
UDECL(BOOLEAN, CDLocateRng, (LONG type, RNX **out));
UDECL(NTSTATUS, CDRegisterCSystem, (const CSX *cs));
UDECL(NTSTATUS, CDRegisterCheckSum, (const CKX *ck));
UDECL(BOOLEAN, CDRegisterRng, (const RNX *r));
UDECL(NTSTATUS, CDFindCommonCSystem, (ULONG n, const LONG *types, LONG *out));
UDECL(NTSTATUS, CDFindCommonCSystemWithKey, (ULONG n, const LONG *types, ULONG kn, const LONG *ktypes, LONG *out));
UDECL(NTSTATUS, CDBuildVect, (ULONG *n, LONG *vect));
UDECL(NTSTATUS, CDBuildIntegrityVect, (ULONG *n, LONG *vect));
UDECL(NTSTATUS, CDGetIntegrityVect, (ULONG *mask));
UDECL(BOOLEAN, CDGenerateRandomBits, (PUCHAR buf, ULONG len));
UDECL(NTSTATUS, HMACwithSHA, (PUCHAR key, ULONG keylen, PUCHAR data, ULONG datalen, PVOID out, ULONG outlen));
UDECL(NTSTATUS, PBKDF2, (PUCHAR pw, ULONG pwlen, PUCHAR salt, ULONG saltlen, ULONG iter, ULONG dklen, PUCHAR dk));
UDECL(NTSTATUS, KRBFXCF2, (LONG et1, PUCHAR k1, ULONG k1len, PUCHAR p1, ULONG p1len,
                           LONG et2, PUCHAR k2, ULONG k2len, PUCHAR p2, ULONG p2len, PUCHAR out));
UDECL(NTSTATUS, aesCTSEncryptMsg, (ULONG keylen, PUCHAR key, ULONG msglen, PUCHAR data, PUCHAR iv));
UDECL(NTSTATUS, aesCTSDecryptMsg, (ULONG keylen, PUCHAR key, ULONG msglen, PUCHAR data, PUCHAR iv));

typedef struct { ULONG i[2]; ULONG buf[4]; UCHAR in[64]; UCHAR digest[16]; } CK_MD5_CTX;
UDECL(void, MD5Init, (CK_MD5_CTX *c));
UDECL(void, MD5Update, (CK_MD5_CTX *c, const void *p, ULONG n));
UDECL(void, MD5Final, (CK_MD5_CTX *c));

/* ---- helpers (ck_common.c) ---- */
size_t ck_hex(const char *h, BYTE *out, size_t cap);          /* decode hex string, returns byte count */
BYTE  *ck_hexa(const char *h, size_t *n);                      /* malloc'd; free() it */
int    ck_eqhex(const BYTE *p, size_t n, const char *h);       /* bytes equal hex string (and same length) */
void   ck_rc4(const BYTE *key, size_t klen, BYTE *data, size_t n);
void   ck_hmac_md5(const BYTE *key, size_t kl, const BYTE *d1, size_t n1, const BYTE *d2, size_t n2, BYTE out[16]);
void   ck_md5(const BYTE *d, size_t n, BYTE out[16]);
WCHAR *ck_wide(const char *hex16, USHORT *bytes);              /* hex of UTF-16LE -> malloc'd WCHAR buffer */
const CSX *ck_cs(LONG etype);                                  /* CDLocateCSystem or NULL */
const CKX *ck_ck(LONG type);                                   /* CDLocateCheckSum or NULL */
/* run a checksum through its function table. ex: 0 Initialize, 1 InitializeEx. returns NTSTATUS of first failure */
NTSTATUS ck_run_checksum(LONG type, int ex, const BYTE *key, ULONG keylen, ULONG usage,
                         const BYTE *data, size_t n, BYTE *out, size_t *outlen);
/* encrypt/decrypt through a crypto system. */
NTSTATUS ck_cs_encrypt(LONG et, const BYTE *key, ULONG keylen, ULONG usage, const BYTE *in, ULONG inlen,
                       BYTE *out, ULONG *outlen);
NTSTATUS ck_cs_decrypt(LONG et, const BYTE *key, ULONG keylen, ULONG usage, const BYTE *in, ULONG inlen,
                       BYTE *out, ULONG *outlen);

/* the emulator's cryptdll is a partial stub; the expectations here are for the real DLL */
#define CK_NOWINE() do { if (t_is_wine()) { t_skip("emulator cryptdll differs from Windows"); return; } } while (0)
/* deterministic confounder source: registers (in the current process only!) a generator that yields base, base+1, ...
 * Use only from CHILD() code: there is no unregister. Returns 1 on success. */
int ck_install_seq_rng(BYTE base);
#define CK_NEED(fn) do { if (t_is_wine()) { t_skip("emulator cryptdll exports abort when called"); return; } if (!CKP(fn)) { t_skip("missing export: " #fn); return; } } while (0)
#define EXPECT_NS(call, want) do { NTSTATUS st_ = (call); NTSTATUS w_ = (NTSTATUS)(want); \
    t_check(st_ == w_, __FILE__, __LINE__, #call " == " #want, "got 0x%08lx want 0x%08lx", (unsigned long)st_, (unsigned long)w_); } while (0)
/* child-process assertion: exit with the source line on failure */
#define CC(cond) do { if (!(cond)) return __LINE__; } while (0)
#endif
