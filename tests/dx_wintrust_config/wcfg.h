#ifndef WCFG_H
#define WCFG_H
#include "t.h"
#include <wincrypt.h>
#include <wintrust.h>
#include <softpub.h>
#include <mssip.h>
#include <mscat.h>
#include <stdlib.h>
#include <wchar.h>

/* Test action / SIP subject GUIDs: Data1 = pid, Data2 = slot, Data3 = 0xC77,
 * Data4 = "cryptt!!".  The fixed tail makes leftovers of dead runs recognisable. */
#define WCFG_SLOTS 64
void wcfg_guid(GUID *g, unsigned slot);
void wcfg_guid_str(const GUID *g, wchar_t *out);      /* "{XXXXXXXX-...}" uppercase, 38 chars + NUL */

/* privilege / state gates: 1 = go ahead, 0 = test was skipped (return from the test) */
int  wcfg_begin_trust(void);      /* HKLM ...\Providers\Trust writable */
int  wcfg_begin_oid(void);        /* HKLM ...\OID\EncodingType 0 writable */
void wcfg_end(void);              /* removes every registry artefact of this area */
void wcfg_sweep(void);

/* raw registry helpers (scaffolding; HKLM native view) */
#define WCFG_TRUST L"SOFTWARE\\Microsoft\\Cryptography\\Providers\\Trust"
extern const wchar_t *const wcfg_kind[8];   /* Initialization, Message, Signature, Certificate, CertCheck, FinalPolicy, DiagnosticPolicy, Cleanup */
int  wcfg_key_exists(const wchar_t *path);
LONG wcfg_get_str(const wchar_t *path, const wchar_t *name, wchar_t *out, DWORD cch, DWORD *type, DWORD *cb);
int  wcfg_prov_registered(unsigned kind, const GUID *g, wchar_t *dll, wchar_t *fn);  /* both values present */
void wcfg_selfpath(wchar_t *out, DWORD cch);
void wcfg_remove_action_raw(const GUID *g);

/* HKCU policy "State" value save/restore */
int  wcfg_state_save(void);
void wcfg_state_restore(void);
int  wcfg_state_raw(DWORD *type, BYTE *buf, DWORD *cb);   /* 1 if present */
void wcfg_state_put(DWORD type, const void *p, DWORD cb);
void wcfg_state_delete(void);

/* ---- exported provider callbacks living in this exe (resolved by LoadLibrary/GetProcAddress) ---- */
enum { WP_INIT, WP_OBJECT, WP_SIG, WP_CERT, WP_FINAL, WP_TEST, WP_CLEANUP, WP_CERTCHECK, WP_FINALALT, WP__N };
extern int      wcfg_log[64];
extern int      wcfg_nlog;
extern DWORD    wcfg_ret[WP__N];       /* value returned by each callback */
extern DWORD    wcfg_seterr[WP__N];    /* if non-zero stored into pd->dwError before returning */
extern void    *wcfg_pd_seen;          /* pd pointer of the first call */
extern int      wcfg_pd_same;          /* all calls saw the same pd */
typedef struct {
    DWORD cbStruct; WINTRUST_DATA *pWintrustData; HWND hWnd; GUID *pgActionID; HCRYPTPROV hProv;
    DWORD dwError, secSettings, polSettings; CRYPT_PROVIDER_FUNCTIONS *psPfns; DWORD cbPfns;
    WCHAR path[MAX_PATH]; DWORD fOpened; int valid; DWORD dwErrorAtFinal; DWORD dwProvFlags; CRYPT_PROVIDER_FUNCTIONS pfns;
} wcfg_snap_t;
extern wcfg_snap_t wcfg_snap;
void wcfg_log_reset(void);
int  wcfg_log_count(int id);
/* The exported entry names ("cryptt_*") */
extern const char *const wcfg_names[WP__N];
extern const wchar_t *const wcfg_wnames[WP__N];

/* build a full registration of the in-exe providers under guid; extra bits via the returned struct */
typedef struct { CRYPT_REGISTER_ACTIONID r; wchar_t dll[MAX_PATH]; } wcfg_reg_t;
void wcfg_fill_reg(wcfg_reg_t *x);              /* all 8 providers = exe exports, cbStruct = 0xC8 */
BOOL wcfg_add(const GUID *g, DWORD flags, wcfg_reg_t *x);
#define WCFG_REG_SIZE_NOCLEANUP 0xB0
#define WCFG_REG_SIZE_FULL      0xC8

/* verify an unsigned file with the given action; returns WinVerifyTrust's value */
extern WINTRUST_DATA wcfg_wd;
LONG wcfg_verify(const GUID *g, HWND hwnd, DWORD uichoice, const wchar_t *file, WINTRUST_DATA *out_wd);

/* ---- usage-callback exports ---- */
extern int wcfg_usage_alloc_calls, wcfg_usage_free_calls;
extern const char *wcfg_usage_alloc_oid; extern void *wcfg_usage_alloc_ud; extern GUID wcfg_usage_alloc_guid;
extern BOOL wcfg_usage_alloc_ret;

/* ---- SIP exports ---- */
typedef struct { int n; void *info; DWORD a, b; void *p1, *p2; BOOL ret; DWORD err; } wcfg_sipcall_t;
enum { SC_GET, SC_PUT, SC_CREATE, SC_VERIFY, SC_REMOVE, SC_IS, SC_IS2, SC_CAPS };
extern wcfg_sipcall_t wcfg_sipc[8];
void wcfg_sip_reset(void);
extern const char *const wcfg_sip_names[8];
extern const wchar_t *const wcfg_sip_wnames[8];
extern const wchar_t wcfg_magic[];          /* file magic recognised by the in-exe IsMyFileType */
extern GUID wcfg_sip_guid_for_is;           /* subject returned by IsMyFileType */

typedef struct SIP_ADD_NEWPROVIDER_EX_ {
    DWORD cbStruct; GUID *pgSubject; WCHAR *pwszDLLFileName; WCHAR *pwszMagicNumber; WCHAR *pwszIsFunctionName;
    WCHAR *pwszGetFuncName; WCHAR *pwszPutFuncName; WCHAR *pwszCreateFuncName; WCHAR *pwszVerifyFuncName;
    WCHAR *pwszRemoveFuncName; WCHAR *pwszIsFunctionNameFmt2; WCHAR *pwszGetCapFuncName;
} SIP_ADD_NEWPROVIDER_EX;
#define SIP_ADD_FULL_SIZE  0x60
#define SIP_ADD_FMT2_SIZE  0x58
#define SIP_ADD_BASE_SIZE  0x50
void wcfg_sip_fill(SIP_ADD_NEWPROVIDER_EX *a, const GUID *g, const wchar_t *dll);   /* in-exe funcs, all optionals */

extern const char *const wcfg_sip_funcset[9];   /* registry function-set names */
int wcfg_sip_key_present(unsigned set, const GUID *g, wchar_t *dll, wchar_t *fn);

#define CK_E_INVALIDARG 0x80070057u
#define CK_TRUST_E_SUBJECT_FORM_UNKNOWN 0x800B0003u
#endif
