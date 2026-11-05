/* Shared helpers for the capi_cp_direct area: the CSP provider entry points (CP*) exported by
 * rsaenh.dll and dssenh.dll are resolved with GetProcAddress and called directly.
 *
 * ABI notes (from the decompilation of the Windows 10 x64 providers):
 *  - rsaenh's CPAcquireContext reads the VTableProvStruc as: Version (+0), dwProvType (+24, only when
 *    Version > 1) and pszProvName (+48, only when Version > 2).  With Version > 2 the name is used
 *    unconditionally, so a NULL name must never be passed with Version >= 3.
 *  - dssenh's CPAcquireContext reads the same fields but derives the provider name from dwProvType when
 *    Version < 3.
 *  - Provider, key and hash handles are opaque (XOR-obfuscated pointers).  Most entry points
 *    dereference them without any SEH protection, so these tests never pass invalid or destroyed
 *    handles; they pass handles of the WRONG KIND (key as provider, hash as key ...) which the
 *    provider recognises by a type tag.
 */
#ifndef CP_H
#define CP_H
#include "t.h"
#include <wincrypt.h>

#define CPE_BAD_UID     0x80090001L
#define CPE_BAD_HASH    0x80090002L
#define CPE_BAD_KEY     0x80090003L
#define CPE_BAD_LEN     0x80090004L
#define CPE_BAD_DATA    0x80090005L
#define CPE_BAD_SIGNATURE 0x80090006L
#define CPE_BAD_ALGID   0x80090008L
#define CPE_BAD_FLAGS   0x80090009L
#define CPE_BAD_TYPE    0x8009000AL
#define CPE_BAD_KEY_STATE 0x8009000BL
#define CPE_BAD_HASH_STATE 0x8009000CL
#define CPE_NO_KEY      0x8009000DL
#define CPE_FAIL        0x80090020L
#define CPE_PROV_TYPE_NO_MATCH 0x80090014L
#define CPE_PERM        0x80090010L
#define CPE_BAD_KEYSET  0x80090016L
#define CPE_KEYSET_NOT_DEF 0x80090019L

#define NELEM(a) (sizeof(a) / sizeof((a)[0]))

typedef struct {
    DWORD Version;
    PVOID FuncVerifyImage;
    PVOID FuncReturnhWnd;
    DWORD dwProvType;
    BYTE *pbContextInfo;
    DWORD cbContextInfo;
    char *pszProvName;
} cp_vtbl;

typedef struct cpf {
    HMODULE mod;
    BOOL (WINAPI *Acquire)(ULONG_PTR *, CHAR *, DWORD, cp_vtbl *);
    BOOL (WINAPI *Release)(ULONG_PTR, DWORD);
    BOOL (WINAPI *GenKey)(ULONG_PTR, ALG_ID, DWORD, ULONG_PTR *);
    BOOL (WINAPI *DeriveKey)(ULONG_PTR, ALG_ID, ULONG_PTR, DWORD, ULONG_PTR *);
    BOOL (WINAPI *DestroyKey)(ULONG_PTR, ULONG_PTR);
    BOOL (WINAPI *SetKeyParam)(ULONG_PTR, ULONG_PTR, DWORD, const BYTE *, DWORD);
    BOOL (WINAPI *GetKeyParam)(ULONG_PTR, ULONG_PTR, DWORD, BYTE *, DWORD *, DWORD);
    BOOL (WINAPI *SetProvParam)(ULONG_PTR, DWORD, const BYTE *, DWORD);
    BOOL (WINAPI *GetProvParam)(ULONG_PTR, DWORD, BYTE *, DWORD *, DWORD);
    BOOL (WINAPI *SetHashParam)(ULONG_PTR, ULONG_PTR, DWORD, const BYTE *, DWORD);
    BOOL (WINAPI *GetHashParam)(ULONG_PTR, ULONG_PTR, DWORD, BYTE *, DWORD *, DWORD);
    BOOL (WINAPI *ExportKey)(ULONG_PTR, ULONG_PTR, ULONG_PTR, DWORD, DWORD, BYTE *, DWORD *);
    BOOL (WINAPI *ImportKey)(ULONG_PTR, const BYTE *, DWORD, ULONG_PTR, DWORD, ULONG_PTR *);
    BOOL (WINAPI *Encrypt)(ULONG_PTR, ULONG_PTR, ULONG_PTR, BOOL, DWORD, BYTE *, DWORD *, DWORD);
    BOOL (WINAPI *Decrypt)(ULONG_PTR, ULONG_PTR, ULONG_PTR, BOOL, DWORD, BYTE *, DWORD *);
    BOOL (WINAPI *CreateHash)(ULONG_PTR, ALG_ID, ULONG_PTR, DWORD, ULONG_PTR *);
    BOOL (WINAPI *HashData)(ULONG_PTR, ULONG_PTR, const BYTE *, DWORD, DWORD);
    BOOL (WINAPI *HashSessionKey)(ULONG_PTR, ULONG_PTR, ULONG_PTR, DWORD);
    BOOL (WINAPI *SignHash)(ULONG_PTR, ULONG_PTR, DWORD, LPCWSTR, DWORD, BYTE *, DWORD *);
    BOOL (WINAPI *DestroyHash)(ULONG_PTR, ULONG_PTR);
    BOOL (WINAPI *VerifySignature)(ULONG_PTR, ULONG_PTR, const BYTE *, DWORD, ULONG_PTR, LPCWSTR, DWORD);
    BOOL (WINAPI *GenRandom)(ULONG_PTR, DWORD, BYTE *);
    BOOL (WINAPI *GetUserKey)(ULONG_PTR, DWORD, ULONG_PTR *);
    BOOL (WINAPI *DuplicateHash)(ULONG_PTR, ULONG_PTR, DWORD *, DWORD, ULONG_PTR *);
    BOOL (WINAPI *DuplicateKey)(ULONG_PTR, ULONG_PTR, DWORD *, DWORD, ULONG_PTR *);
} cpf;

/* Resolve all 25 entry points of one provider DLL through LoadLibrary + GetProcAddress. */
static int cp_bind(cpf *f, const char *dll) {
    memset(f, 0, sizeof *f);
    f->mod = t_module(dll);
    if (!f->mod) return 0;
#define B(n) do { f->n = (void *)t_proc_in(dll, "CP" #n); if (!f->n) return 0; } while (0)
    f->Acquire = (void *)t_proc_in(dll, "CPAcquireContext"); if (!f->Acquire) return 0;
    f->Release = (void *)t_proc_in(dll, "CPReleaseContext"); if (!f->Release) return 0;
    B(GenKey); B(DeriveKey); B(DestroyKey); B(SetKeyParam); B(GetKeyParam);
    B(SetProvParam); B(GetProvParam); B(SetHashParam); B(GetHashParam); B(ExportKey); B(ImportKey);
    B(Encrypt); B(Decrypt); B(CreateHash); B(HashData); B(HashSessionKey); B(SignHash); B(DestroyHash);
    B(VerifySignature); B(GenRandom); B(GetUserKey); B(DuplicateHash); B(DuplicateKey);
#undef B
    return 1;
}
#define NEED_RSA() cpf R; if (!cp_bind(&R, "rsaenh.dll")) { t_skip("rsaenh.dll CP exports missing"); return; }
#define NEED_DSS() cpf D; if (!cp_bind(&D, "dssenh.dll")) { t_skip("dssenh.dll CP exports missing"); return; }

/* Provider names (ANSI literals so the harness needs no wincrypt macros). */
#define N_BASE   "Microsoft Base Cryptographic Provider v1.0"
#define N_ENH    "Microsoft Enhanced Cryptographic Provider v1.0"
#define N_STRONG "Microsoft Strong Cryptographic Provider"
#define N_AES    "Microsoft Enhanced RSA and AES Cryptographic Provider"
#define N_SIG    "Microsoft RSA Signature Cryptographic Provider"
#define N_DSS_BASE "Microsoft Base DSS Cryptographic Provider"
#define N_DSS_ENH  "Microsoft Enhanced DSS and Diffie-Hellman Cryptographic Provider"

/* Acquire with an explicit VTableProvStruc. */
static BOOL cp_acq_ex(const cpf *f, ULONG_PTR *prov, char *container, DWORD flags,
                      DWORD version, DWORD type, char *name) {
    cp_vtbl v; memset(&v, 0, sizeof v);
    v.Version = version; v.dwProvType = type; v.pszProvName = name;
    *prov = 0;
    return f->Acquire(prov, container, flags, &v);
}
/* rsaenh: ephemeral context, Version 3 as the system advapi32 passes it. */
static ULONG_PTR rsa_open(const cpf *f, DWORD type, char *name) {
    ULONG_PTR p = 0;
    if (!cp_acq_ex(f, &p, NULL, CRYPT_VERIFYCONTEXT, 3, type, name)) return 0;
    return p;
}
static ULONG_PTR rsa_enh(const cpf *f)  { return rsa_open(f, PROV_RSA_FULL, N_ENH); }
static ULONG_PTR rsa_base(const cpf *f) { return rsa_open(f, PROV_RSA_FULL, N_BASE); }
static ULONG_PTR rsa_aes(const cpf *f)  { return rsa_open(f, PROV_RSA_AES, N_AES); }
/* dssenh: Version 2 lets the provider derive its own name from the type. */
static ULONG_PTR dss_open(const cpf *f, DWORD type) {
    ULONG_PTR p = 0;
    if (!cp_acq_ex(f, &p, NULL, CRYPT_VERIFYCONTEXT, 2, type, NULL)) return 0;
    return p;
}
static void cp_rel(const cpf *f, ULONG_PTR p) { if (p) f->Release(p, 0); }

/* Expect a call to fail with a specific last error. */
#define FAILS(call, err) do { SetLastError(0x1234abcd); BOOL r_ = (call); \
    t_check(!r_, __FILE__, __LINE__, #call, "unexpected success"); EXPECT_ERR(err); } while (0)
#define OKAY(call) do { SetLastError(0); BOOL r_ = (call); \
    t_check(r_, __FILE__, __LINE__, #call, "failed, GetLastError=0x%lx", GetLastError()); } while (0)
#define SAMEBYTES(a, b, n) t_check(!memcmp((a), (b), (n)), __FILE__, __LINE__, "bytes " #a " == " #b, "mismatch")

/* Plaintext key import (PLAINTEXTKEYBLOB). */
typedef struct { BLOBHEADER h; DWORD cb; BYTE key[64]; } cp_plain;
static BOOL cp_import_plain(const cpf *f, ULONG_PTR p, ALG_ID alg, const void *key, DWORD len,
                            DWORD flags, ULONG_PTR *out) {
    cp_plain b; memset(&b, 0, sizeof b);
    b.h.bType = PLAINTEXTKEYBLOB; b.h.bVersion = CUR_BLOB_VERSION; b.h.aiKeyAlg = alg; b.cb = len;
    memcpy(b.key, key, len);
    *out = 0;
    return f->ImportKey(p, (BYTE *)&b, (DWORD)(offsetof(cp_plain, key) + len), 0, flags, out);
}
static ULONG_PTR cp_key(const cpf *f, ULONG_PTR p, ALG_ID alg, const void *key, DWORD len) {
    ULONG_PTR k = 0;
    if (!cp_import_plain(f, p, alg, key, len, CRYPT_EXPORTABLE | CRYPT_NO_SALT, &k)) return 0;
    return k;
}
static BOOL cp_set_mode(const cpf *f, ULONG_PTR p, ULONG_PTR k, DWORD m) { return f->SetKeyParam(p, k, KP_MODE, (BYTE *)&m, 0); }
static BOOL cp_set_pad(const cpf *f, ULONG_PTR p, ULONG_PTR k, DWORD m) { return f->SetKeyParam(p, k, KP_PADDING, (BYTE *)&m, 0); }
static BOOL cp_set_iv(const cpf *f, ULONG_PTR p, ULONG_PTR k, const void *iv) { return f->SetKeyParam(p, k, KP_IV, (const BYTE *)iv, 0); }

/* One-shot hash of a buffer.  Returns digest length or 0. */
static DWORD cp_hash(const cpf *f, ULONG_PTR p, ALG_ID alg, const void *data, DWORD len, BYTE *out, DWORD cap) {
    ULONG_PTR h = 0; DWORD n = cap;
    if (!f->CreateHash(p, alg, 0, 0, &h)) return 0;
    if (len && !f->HashData(p, h, (const BYTE *)data, len, 0)) { f->DestroyHash(p, h); return 0; }
    if (!f->GetHashParam(p, h, HP_HASHVAL, out, &n, 0)) n = 0;
    f->DestroyHash(p, h);
    return n;
}
static ULONG_PTR cp_mkhash(const cpf *f, ULONG_PTR p, ALG_ID alg) {
    ULONG_PTR h = 0;
    if (!f->CreateHash(p, alg, 0, 0, &h)) return 0;
    return h;
}
static DWORD cp_hp_dw(const cpf *f, ULONG_PTR p, ULONG_PTR h, DWORD hp, BOOL *ok) {
    DWORD v = 0xCCCCCCCC, n = 4; BOOL r = f->GetHashParam(p, h, hp, (BYTE *)&v, &n, 0);
    if (ok) { *ok = r; }
    return v;
}
static DWORD cp_kp_dw(const cpf *f, ULONG_PTR p, ULONG_PTR k, DWORD kp, BOOL *ok) {
    DWORD v = 0xCCCCCCCC, n = 4; BOOL r = f->GetKeyParam(p, k, kp, (BYTE *)&v, &n, 0);
    if (ok) { *ok = r; }
    return v;
}
static DWORD cp_pp_dw(const cpf *f, ULONG_PTR p, DWORD pp, BOOL *ok) {
    DWORD v = 0xCCCCCCCC, n = 4; BOOL r = f->GetProvParam(p, pp, (BYTE *)&v, &n, 0);
    if (ok) { *ok = r; }
    return v;
}

/* Data shared between files. */
static const BYTE cp_abc[3] = { 'a', 'b', 'c' };
static const BYTE cp_pt30[30] = "The quick brown fox jumps over";
#endif
