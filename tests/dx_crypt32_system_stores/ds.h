#ifndef DS_H
#define DS_H
#include "t.h"
#include <wincrypt.h>
#include <wchar.h>

/* Shared helpers for the dx_crypt32_system_stores area.
 *
 * Every store this area creates is named  cryptt_ss_<pid>_<tag>  and lives under
 *   HKCU\Software\Microsoft\SystemCertificates\<name>            (CERT_SYSTEM_STORE_CURRENT_USER)
 *   HKLM\Software\Microsoft\SystemCertificates\<name>            (CERT_SYSTEM_STORE_LOCAL_MACHINE, admin only)
 * Leftover stores with the prefix are swept at the start of every test and at process exit.
 * Nothing in ROOT / MY / CA or any other real store is touched. */

#define DS_PFX        L"cryptt_ss_"
#define DS_E_INVALIDARG ((DWORD)0x80070057)
#define DS_E_ACCESSDENIED ((DWORD)0x80070005)
#define DS_SYS_W      ((LPCSTR)(ULONG_PTR)10)   /* CERT_STORE_PROV_SYSTEM_W */
#define DS_SYS_A      ((LPCSTR)(ULONG_PTR)9)    /* CERT_STORE_PROV_SYSTEM_A */
#define DS_SYSREG_W   ((LPCSTR)(ULONG_PTR)12)   /* CERT_STORE_PROV_SYSTEM_REGISTRY_W */
#define DS_SYSREG_A   ((LPCSTR)(ULONG_PTR)11)   /* CERT_STORE_PROV_SYSTEM_REGISTRY_A */
#define DS_ENC        (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING)
#define DS_NCERTS     4

int  ds_begin(int machine);         /* sweep + atexit; machine=1 needs HKLM write; 0 => caller returns (t_skip done) */
void ds_end(void);                  /* sweep */
void ds_sweep(void);
wchar_t *ds_name(wchar_t *out, size_t cap, const char *tag);   /* cryptt_ss_<pid>_<tag> */

/* CertOpenStore(SYSTEM_W, name) with loc | flags (loc is a CERT_SYSTEM_STORE_* location, 0 = current user) */
HCERTSTORE ds_open_loc(const wchar_t *name, DWORD loc, DWORD flags);
HCERTSTORE ds_open(const wchar_t *name, DWORD flags);          /* current user */
/* Open the store named `name` (must exist) and report whether it contains cert idx */
int  ds_stored(const wchar_t *name, DWORD loc, int idx);
int  ds_count(HCERTSTORE h);
int  ds_count_named(const wchar_t *name, DWORD loc, DWORD flags);   /* open, count certs, close; -1 if open failed */

const BYTE *ds_der(int idx, DWORD *cb);
const char *ds_sha1(int idx);
const wchar_t *ds_cn(int idx);
const BYTE *ds_crl(DWORD *cb);
PCCERT_CONTEXT ds_add(HCERTSTORE h, int idx, DWORD disp);       /* CertAddEncodedCertificateToStore; returns the context or NULL */
PCCERT_CONTEXT ds_find(HCERTSTORE h, int idx);                  /* by SHA1 hash; caller frees */
void ds_sync(HCERTSTORE h);                                    /* emulator-only commit, no-op on Windows */
BOOL ds_del(PCCERT_CONTEXT c);                                  /* CertDeleteCertificateFromStore + sync */
int  ds_add_ok(HCERTSTORE h, int idx);                          /* add with CERT_STORE_ADD_REPLACE_EXISTING, free context */

/* Raw registry scaffolding (direct advapi32). loc: 0 / CERT_SYSTEM_STORE_CURRENT_USER or CERT_SYSTEM_STORE_LOCAL_MACHINE */
int  ds_key_exists(DWORD loc, const wchar_t *store, const wchar_t *sub);      /* sub may be NULL */
int  ds_cert_key_exists(DWORD loc, const wchar_t *store, int idx);
LONG ds_cert_blob(DWORD loc, const wchar_t *store, int idx, DWORD *type, DWORD *cb);
int  ds_subkey_count(DWORD loc, const wchar_t *store, const wchar_t *sub);    /* -1 if absent */
LONG ds_reg_value(DWORD loc, const wchar_t *store, const wchar_t *sub, const wchar_t *val, DWORD *type, void *buf, DWORD *cb);

#define SETUP(fn) REQUIRE(U(fn)); if (!ds_begin(0)) return
#define SETUP_LM(fn) REQUIRE(U(fn)); if (!ds_begin(1)) return
#endif
