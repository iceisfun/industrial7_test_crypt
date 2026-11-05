/* Shared helpers for dx_crypt32_pfx_persisted: persisted PFX private keys (user key containers / KSP keys).
 * Every DLL call goes through GetProcAddress (U()). Key names are GUIDs chosen by the import itself, so a
 * journal file records every persisted key; leftovers of earlier runs are swept at the first use. */
#ifndef PK_H
#define PK_H
#include "t.h"
#include <wincrypt.h>
#include <ncrypt.h>
#include <bcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include "fixtures.h"

#define PK_PW L"cryptt-pw"
#define S32(x) ((DWORD)(x))
static inline void pk_expect_hr(DWORD a, DWORD b, const char *f, int l, const char *e) { t_check(a == b, f, l, e, "got 0x%08lx want 0x%08lx", a, b); }
#define EXPECT_HR(a, b) pk_expect_hr(S32(a), S32(b), __FILE__, __LINE__, #a " == " #b)
#ifndef PKCS12_IMPORT_SILENT
#define PKCS12_IMPORT_SILENT 0x40
#endif
#ifndef PKCS12_PREFER_CNG_KSP
#define PKCS12_PREFER_CNG_KSP 0x100
#endif
#ifndef PKCS12_ALWAYS_CNG_KSP
#define PKCS12_ALWAYS_CNG_KSP 0x200
#endif
#ifndef PKCS12_ALLOW_OVERWRITE_KEY
#define PKCS12_ALLOW_OVERWRITE_KEY 0x4000
#endif
#ifndef CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG
#define CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG 0x40000
#endif
#ifndef CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG
#define CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG 0x20000
#endif
#ifndef CRYPT_ACQUIRE_WINDOW_HANDLE_FLAG
#define CRYPT_ACQUIRE_WINDOW_HANDLE_FLAG 0x80
#endif
#ifndef CRYPT_FIND_USER_KEYSET_FLAG
#define CRYPT_FIND_USER_KEYSET_FLAG 0x1
#define CRYPT_FIND_MACHINE_KEYSET_FLAG 0x2
#define CRYPT_FIND_SILENT_KEYSET_FLAG 0x40
#endif
UDECL(BOOL, CryptFindCertificateKeyProvInfo, (PCCERT_CONTEXT, DWORD, void *));

static const char *pk_jpath(void) {
    static char p[MAX_PATH + 64];
    if (!p[0]) { GetTempPathA(MAX_PATH, p); lstrcatA(p, "cryptt_pfxp_journal.txt"); }
    return p;
}
static void pk_destroy(const WCHAR *prov, DWORD type, const WCHAR *cont, DWORD flags) {
    if (!prov || !cont) return;
    if (type == 0) {
        NCRYPT_PROV_HANDLE p = 0; NCRYPT_KEY_HANDLE k = 0;
        if (!U(NCryptOpenStorageProvider) || U(NCryptOpenStorageProvider)(&p, prov, 0)) return;
        if (!U(NCryptOpenKey)(p, &k, cont, 0, (flags & NCRYPT_MACHINE_KEY_FLAG) | NCRYPT_SILENT_FLAG)) {
            if (U(NCryptDeleteKey)(k, NCRYPT_SILENT_FLAG)) U(NCryptFreeObject)(k);
        }
        U(NCryptFreeObject)(p);
    } else {
        HCRYPTPROV h = 0;
        U(CryptAcquireContextW)(&h, cont, prov, type, CRYPT_DELETEKEYSET | CRYPT_SILENT | (flags & CRYPT_MACHINE_KEYSET));
    }
}
static void pk_sweep_journal(void) {
    FILE *f = fopen(pk_jpath(), "r"); char line[1024];
    if (!f) return;
    while (fgets(line, sizeof line, f)) {
        char *a = strchr(line, '|'), *b, *c; WCHAR prov[256], cont[256]; DWORD type, fl;
        if (!a) continue;
        *a++ = 0; b = strchr(a, '|'); if (!b) continue; *b++ = 0; c = strchr(b, '|'); if (!c) continue; *c++ = 0;
        type = (DWORD)atol(line); fl = (DWORD)atol(c);
        MultiByteToWideChar(CP_UTF8, 0, a, -1, prov, 256); MultiByteToWideChar(CP_UTF8, 0, b, -1, cont, 256);
        pk_destroy(prov, type, cont, fl);
    }
    fclose(f);
    DeleteFileA(pk_jpath());
}
static int pk_inited;
static void pk_atexit(void) { pk_sweep_journal(); }
static void pk_init(void) { if (!pk_inited) { pk_inited = 1; pk_sweep_journal(); atexit(pk_atexit); } }

static void pk_journal(const CRYPT_KEY_PROV_INFO *i) {
    FILE *f; char prov[512], cont[512];
    if (!i || !i->pwszProvName || !i->pwszContainerName) return;
    WideCharToMultiByte(CP_UTF8, 0, i->pwszProvName, -1, prov, sizeof prov, NULL, NULL);
    WideCharToMultiByte(CP_UTF8, 0, i->pwszContainerName, -1, cont, sizeof cont, NULL, NULL);
    f = fopen(pk_jpath(), "a"); if (!f) return;
    fprintf(f, "%lu|%s|%s|%lu\n", i->dwProvType, prov, cont, i->dwFlags); fclose(f);
}
/* LocalAlloc'ed CRYPT_KEY_PROV_INFO (strings inline) or NULL */
static CRYPT_KEY_PROV_INFO *pk_info(PCCERT_CONTEXT c) {
    DWORD cb = 0; void *p;
    if (!c || !U(CertGetCertificateContextProperty)(c, CERT_KEY_PROV_INFO_PROP_ID, NULL, &cb) || !cb) return NULL;
    p = LocalAlloc(LPTR, cb);
    if (!p) return NULL;
    if (!U(CertGetCertificateContextProperty)(c, CERT_KEY_PROV_INFO_PROP_ID, p, &cb)) { LocalFree(p); return NULL; }
    return (CRYPT_KEY_PROV_INFO *)p;
}
static void pk_track_store(HCERTSTORE s) {
    PCCERT_CONTEXT c = NULL;
    while ((c = U(CertEnumCertificatesInStore)(s, c)) != NULL) { CRYPT_KEY_PROV_INFO *i = pk_info(c); if (i) { pk_journal(i); LocalFree(i); } }
}
/* Persisting import (no NO_PERSIST_KEY); silent; keys journaled. NULL on failure. */
static HCERTSTORE pk_import_pw(const BYTE *p, size_t n, LPCWSTR pw, DWORD flags) {
    CRYPT_DATA_BLOB b; HCERTSTORE s;
    pk_init();
    b.cbData = (DWORD)n; b.pbData = (BYTE *)p;
    s = U(PFXImportCertStore)(&b, pw, flags | (t_is_wine() ? 0 : PKCS12_IMPORT_SILENT));
    if (s) pk_track_store(s);
    return s;
}
#define PK_IMPORT(fx, fl) pk_import_pw(fx, sizeof(fx), PK_PW, fl)
static PCCERT_CONTEXT pk_first(HCERTSTORE s) { return s ? U(CertEnumCertificatesInStore)(s, NULL) : NULL; }
static int pk_count(HCERTSTORE s) { int n = 0; PCCERT_CONTEXT c = NULL; while (s && (c = U(CertEnumCertificatesInStore)(s, c)) != NULL) n++; return n; }

/* Status of opening the key named by info: 0 on success. */
static DWORD pk_open_status(const CRYPT_KEY_PROV_INFO *i) {
    if (i->dwProvType == 0) {
        NCRYPT_PROV_HANDLE p = 0; NCRYPT_KEY_HANDLE k = 0; SECURITY_STATUS s;
        s = U(NCryptOpenStorageProvider)(&p, i->pwszProvName, 0);
        if (s) return s;
        s = U(NCryptOpenKey)(p, &k, i->pwszContainerName, i->dwKeySpec, (i->dwFlags & NCRYPT_MACHINE_KEY_FLAG) | NCRYPT_SILENT_FLAG);
        if (!s) U(NCryptFreeObject)(k);
        U(NCryptFreeObject)(p);
        return s;
    } else {
        HCRYPTPROV h = 0;
        if (!U(CryptAcquireContextW)(&h, i->pwszContainerName, i->pwszProvName, i->dwProvType, CRYPT_SILENT | (i->dwFlags & CRYPT_MACHINE_KEYSET))) return GetLastError();
        U(CryptReleaseContext)(h, 0);
        return 0;
    }
}
/* Delete the persisted key of every cert of the store, free ctx, close the store. */
static void pk_done(PCCERT_CONTEXT c, HCERTSTORE s) {
    PCCERT_CONTEXT e = NULL;
    if (c) U(CertFreeCertificateContext)(c);
    while (s && (e = U(CertEnumCertificatesInStore)(s, e)) != NULL) {
        CRYPT_KEY_PROV_INFO *i = pk_info(e);
        if (i) { pk_destroy(i->pwszProvName, i->dwProvType, i->pwszContainerName, i->dwFlags); LocalFree(i); }
    }
    if (s) U(CertCloseStore)(s, 0);
}
/* Release a handle returned by CryptAcquireCertificatePrivateKey (when the caller owns it). */
static void pk_release(HCRYPTPROV_OR_NCRYPT_KEY_HANDLE h, DWORD spec, BOOL callerFree) {
    if (!h || !callerFree) return;
    if (spec == CERT_NCRYPT_KEY_SPEC) U(NCryptFreeObject)(h); else U(CryptReleaseContext)(h, 0);
}
static void pk_free_info(CRYPT_KEY_PROV_INFO *i) { if (i) LocalFree(i); }

#define PK_NEEDS() do { if (t_is_wine()) { t_skip("emulator: PFX import neither persists keys nor validates flags like Windows"); return; } REQUIRE(U(PFXImportCertStore)); REQUIRE(U(PFXExportCertStoreEx)); REQUIRE(U(CertGetCertificateContextProperty)); \
    REQUIRE(U(CertSetCertificateContextProperty)); REQUIRE(U(CryptAcquireCertificatePrivateKey)); REQUIRE(U(CertEnumCertificatesInStore)); \
    REQUIRE(U(CertCloseStore)); REQUIRE(U(CertFreeCertificateContext)); REQUIRE(U(NCryptOpenStorageProvider)); REQUIRE(U(NCryptOpenKey)); \
    REQUIRE(U(NCryptDeleteKey)); REQUIRE(U(NCryptFreeObject)); REQUIRE(U(CryptAcquireContextW)); REQUIRE(U(CryptReleaseContext)); } while (0)

/* Import one fixture (persisting). Declares s and c; skips the test when the import itself fails. */
#define PK_SETUP(fx, fl) PK_NEEDS(); \
    HCERTSTORE s = PK_IMPORT(fx, fl); \
    if (!s && t_is_wine()) { t_skip("emulator cannot persist this PFX key (err %lu)", GetLastError()); return; } \
    if (!s) { CHECKF(0, "persisting import failed, GetLastError=%lu", GetLastError()); return; } \
    PCCERT_CONTEXT c = pk_first(s); \
    if (!c) { CHECKF(0, "imported store is empty"); pk_done(NULL, s); return; }

static inline int pk_is_ksp(const CRYPT_KEY_PROV_INFO *i) { return i && i->dwProvType == 0; }

/* Sign fx_hash (SHA-256) with the key behind the cert. RSA: PKCS#1 v1.5 big-endian signature; EC: raw r||s.
 * Returns 0 on success. */
static int pk_sha1; /* set by pk_sign: 1 when the legacy CSP signed a SHA-1 hash (the Enhanced CSP has no SHA-256) */
static DWORD pk_sign_h(PCCERT_CONTEXT c, HCRYPTPROV_OR_NCRYPT_KEY_HANDLE h, DWORD spec, BYTE *sig, DWORD *plen) {
    DWORD r = 0;
    if (spec == CERT_NCRYPT_KEY_SPEC) {
        BCRYPT_PKCS1_PADDING_INFO pi; void *pad = NULL; DWORD fl = 0;
        int rsa = !strcmp(c->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId, "1.2.840.113549.1.1.1");
        if (rsa) { pi.pszAlgId = BCRYPT_SHA256_ALGORITHM; pad = &pi; fl = BCRYPT_PAD_PKCS1; }
        r = (DWORD)U(NCryptSignHash)(h, pad, (PBYTE)fx_hash, 32, sig, *plen, plen, fl);
    } else {
        HCRYPTHASH hh = 0; DWORD i, n;
        pk_sha1 = 1;
        if (!U(CryptCreateHash)(h, CALG_SHA1, 0, 0, &hh)) r = GetLastError();
        else if (!U(CryptSetHashParam)(hh, HP_HASHVAL, (BYTE *)fx_hash, 0)) r = GetLastError();
        else if (!U(CryptSignHashW)(hh, spec, NULL, 0, sig, plen)) r = GetLastError();
        else { n = *plen; for (i = 0; i < n / 2; i++) { BYTE t = sig[i]; sig[i] = sig[n - 1 - i]; sig[n - 1 - i] = t; } }
        if (hh) U(CryptDestroyHash)(hh);
    }
    return r;
}
static DWORD pk_sign(PCCERT_CONTEXT c, DWORD acqflags, BYTE *sig, DWORD *plen, DWORD *pspec) {
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE h = 0; DWORD spec = 0; BOOL cf = FALSE; DWORD r;
    pk_sha1 = 0;
    if (!U(CryptAcquireCertificatePrivateKey)(c, acqflags, NULL, &h, &spec, &cf)) return GetLastError();
    if (pspec) *pspec = spec;
    r = pk_sign_h(c, h, spec, sig, plen);
    pk_release(h, spec, cf);
    return r;
}
/* Sign with the key held by the CERT_KEY_CONTEXT property (a no-persist import has no key provider info). */
static DWORD pk_sign_keyctx(PCCERT_CONTEXT c, BYTE *sig, DWORD *plen, DWORD *pspec) {
    CERT_KEY_CONTEXT kc; DWORD cb = sizeof kc;
    pk_sha1 = 0;
    kc.cbSize = sizeof kc;
    if (!U(CertGetCertificateContextProperty)(c, CERT_KEY_CONTEXT_PROP_ID, &kc, &cb)) return GetLastError();
    if (pspec) *pspec = kc.dwKeySpec;
    return pk_sign_h(c, kc.hCryptProv, kc.dwKeySpec, sig, plen);
}
/* Verify with the public key of the cert via CNG (no key in a store involved). */
static DWORD pk_verify(PCCERT_CONTEXT c, const BYTE *sig, DWORD len) {
    BCRYPT_KEY_HANDLE hk = 0; BCRYPT_PKCS1_PADDING_INFO pi; void *pad = NULL; DWORD fl = 0; NTSTATUS st;
    int rsa = !strcmp(c->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId, "1.2.840.113549.1.1.1");
    if (!U(CryptImportPublicKeyInfoEx2)(X509_ASN_ENCODING, &c->pCertInfo->SubjectPublicKeyInfo, 0, NULL, &hk)) return GetLastError();
    if (rsa) { pi.pszAlgId = pk_sha1 ? BCRYPT_SHA1_ALGORITHM : BCRYPT_SHA256_ALGORITHM; pad = &pi; fl = BCRYPT_PAD_PKCS1; }
    st = U(BCryptVerifySignature)(hk, pad, (PUCHAR)fx_hash, (rsa && pk_sha1) ? 20 : 32, (PUCHAR)sig, len, fl);
    U(BCryptDestroyKey)(hk);
    return (DWORD)st;
}
#endif
