#include "wcfg.h"

const wchar_t *const wcfg_kind[8] = { L"Initialization", L"Message", L"Signature", L"Certificate",
    L"CertCheck", L"FinalPolicy", L"DiagnosticPolicy", L"Cleanup" };
const char *const wcfg_sip_funcset[9] = { "CryptSIPDllGetSignedDataMsg", "CryptSIPDllPutSignedDataMsg",
    "CryptSIPDllCreateIndirectData", "CryptSIPDllVerifyIndirectData", "CryptSIPDllRemoveSignedDataMsg",
    "CryptSIPDllIsMyFileType", "CryptSIPDllIsMyFileType2", "CryptSIPDllGetCaps", NULL };

/* ------------------------------------------------------------------ GUIDs */
void wcfg_guid(GUID *g, unsigned slot) {
    memset(g, 0, sizeof *g);
    g->Data1 = GetCurrentProcessId(); g->Data2 = (USHORT)slot; g->Data3 = 0x0C77;
    memcpy(g->Data4, "cryptt!!", 8);
}
void wcfg_guid_str(const GUID *g, wchar_t *out) {
    char b[48];
    snprintf(b, sizeof b, "{%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}", (unsigned long)g->Data1, g->Data2, g->Data3,
        g->Data4[0], g->Data4[1], g->Data4[2], g->Data4[3], g->Data4[4], g->Data4[5], g->Data4[6], g->Data4[7]);
    for (int i = 0; ; i++) { out[i] = (unsigned char)b[i]; if (!b[i]) break; }
}
void wcfg_selfpath(wchar_t *out, DWORD cch) { GetModuleFileNameW(NULL, out, cch); }

/* ------------------------------------------------------------------ registry scaffolding */
int wcfg_key_exists(const wchar_t *path) {
    HKEY k; if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0, KEY_READ, &k)) return 0; RegCloseKey(k); return 1;
}
LONG wcfg_get_str(const wchar_t *path, const wchar_t *name, wchar_t *out, DWORD cch, DWORD *type, DWORD *cbout) {
    HKEY k; DWORD t = 0, cb = cch * 2; LONG r = RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0, KEY_READ, &k);
    if (r) return r;
    r = RegQueryValueExW(k, name, NULL, &t, (BYTE *)out, &cb);
    RegCloseKey(k);
    if (type) *type = t;
    if (cbout) *cbout = cb;
    return r;
}
static void kind_path(wchar_t *out, unsigned kind, const GUID *g) {
    wchar_t gs[48]; wcfg_guid_str(g, gs);
    swprintf(out, 300, L"" WCFG_TRUST L"\\%ls\\%ls", wcfg_kind[kind], gs);
}
int wcfg_prov_registered(unsigned kind, const GUID *g, wchar_t *dll, wchar_t *fn) {
    wchar_t p[300]; wchar_t d[300] = L"", f[300] = L"";
    kind_path(p, kind, g);
    LONG a = wcfg_get_str(p, L"$DLL", d, 300, NULL, NULL);
    LONG b = wcfg_get_str(p, L"$Function", f, 300, NULL, NULL);
    if (dll) wcscpy(dll, d);
    if (fn) wcscpy(fn, f);
    return a == 0 && b == 0;
}
void wcfg_remove_action_raw(const GUID *g) {
    wchar_t p[300];
    for (unsigned k = 0; k < 8; k++) { kind_path(p, k, g); RegDeleteKeyExW(HKEY_LOCAL_MACHINE, p, 0, 0); }
}
int wcfg_sip_key_present(unsigned set, const GUID *g, wchar_t *dll, wchar_t *fn) {
    wchar_t gs[48], p[400], d[300] = L"", f[300] = L"";
    wcfg_guid_str(g, gs);
    swprintf(p, 400, L"SOFTWARE\\Microsoft\\Cryptography\\OID\\EncodingType 0\\%hs\\%ls", wcfg_sip_funcset[set], gs);
    LONG a = wcfg_get_str(p, L"Dll", d, 300, NULL, NULL);
    LONG b = wcfg_get_str(p, L"FuncName", f, 300, NULL, NULL);
    if (dll) wcscpy(dll, d);
    if (fn) wcscpy(fn, f);
    return a == 0 && b == 0;
}

static int is_ours(const wchar_t *n) {
    size_t l = wcslen(n);
    return l > 20 && !wcscmp(n + l - 19, L"-6372-797074742121}");
}
static void sweep_under(const wchar_t *base, int (*pred)(const wchar_t *)) {
    HKEY k;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, base, 0, KEY_READ | KEY_WRITE, &k)) return;
    for (int round = 0; round < 4; round++) {
        wchar_t names[64][96]; int n = 0; DWORD i = 0, cch;
        for (;;) { cch = 96; if (RegEnumKeyExW(k, i++, names[n], &cch, NULL, NULL, NULL, NULL)) break; if (pred(names[n]) && n < 63) n++; }
        for (int j = 0; j < n; j++) RegDeleteKeyExW(k, names[j], 0, 0);
        if (!n) break;
    }
    RegCloseKey(k);
}
static int is_usage(const wchar_t *n) { return !wcsncmp(n, L"cryptt.usage.", 13); }
void wcfg_sweep(void) {
    wchar_t p[400];
    for (unsigned k = 0; k < 8; k++) { swprintf(p, 400, L"" WCFG_TRUST L"\\%ls", wcfg_kind[k]); sweep_under(p, is_ours); }
    sweep_under(L"" WCFG_TRUST L"\\Usages", is_usage);
    for (unsigned s = 0; wcfg_sip_funcset[s]; s++) {
        swprintf(p, 400, L"SOFTWARE\\Microsoft\\Cryptography\\OID\\EncodingType 0\\%hs", wcfg_sip_funcset[s]);
        sweep_under(p, is_ours);
    }
}

static int g_swept;
static int probe(const wchar_t *path) {
    HKEY k; DWORD d;
    wchar_t p[400]; swprintf(p, 400, L"%ls\\cryptt_probe_%lu", path, GetCurrentProcessId());
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, p, 0, NULL, 0, KEY_WRITE, NULL, &k, &d)) return 0;
    RegCloseKey(k); RegDeleteKeyExW(HKEY_LOCAL_MACHINE, p, 0, 0); return 1;
}
static void at_exit_cleanup(void) { wcfg_end(); }
static int begin(const wchar_t *path, const char *what) {
    if (!probe(path)) { t_skip("needs elevation: HKLM %ls not writable (%s)", path, what); return 0; }
    if (!g_swept) { g_swept = 1; wcfg_sweep(); atexit(at_exit_cleanup); }
    return 1;
}
int wcfg_begin_trust(void) { return begin(L"" WCFG_TRUST L"\\Initialization", "trust provider registry"); }
int wcfg_begin_oid(void) { return begin(L"SOFTWARE\\Microsoft\\Cryptography\\OID\\EncodingType 0\\CryptSIPDllPutSignedDataMsg", "OID registry"); }
void wcfg_end(void) { wcfg_sweep(); wcfg_state_restore(); }

/* ------------------------------------------------------------------ HKCU State value */
#define STATE_KEY L"Software\\Microsoft\\Windows\\CurrentVersion\\WinTrust\\Trust Providers\\Software Publishing"
static struct { int saved, keyexisted, present; DWORD type, cb; BYTE data[64]; } sv;
int wcfg_state_raw(DWORD *type, BYTE *buf, DWORD *cb) {
    HKEY k; DWORD t = 0, n = *cb;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, STATE_KEY, 0, KEY_READ, &k)) return 0;
    LONG r = RegQueryValueExW(k, L"State", NULL, &t, buf, &n);
    RegCloseKey(k);
    if (r) return 0;
    *type = t; *cb = n; return 1;
}
int wcfg_state_save(void) {
    HKEY k;
    if (sv.saved) return 1;
    memset(&sv, 0, sizeof sv);
    sv.keyexisted = !RegOpenKeyExW(HKEY_CURRENT_USER, STATE_KEY, 0, KEY_READ, &k);
    if (sv.keyexisted) RegCloseKey(k);
    sv.cb = sizeof sv.data;
    sv.present = wcfg_state_raw(&sv.type, sv.data, &sv.cb);
    sv.saved = 1;
    return 1;
}
void wcfg_state_put(DWORD type, const void *p, DWORD cb) {
    HKEY k; DWORD d;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, STATE_KEY, 0, NULL, 0, KEY_WRITE, NULL, &k, &d)) return;
    RegSetValueExW(k, L"State", 0, type, p, cb); RegCloseKey(k);
}
void wcfg_state_delete(void) {
    HKEY k;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, STATE_KEY, 0, KEY_WRITE, &k)) return;
    RegDeleteValueW(k, L"State"); RegCloseKey(k);
}
void wcfg_state_restore(void) {
    if (!sv.saved) return;
    if (sv.present) wcfg_state_put(sv.type, sv.data, sv.cb);
    else {
        wcfg_state_delete();
        if (!sv.keyexisted) RegDeleteKeyW(HKEY_CURRENT_USER, STATE_KEY);
    }
    sv.saved = 0;
}

/* ------------------------------------------------------------------ provider callbacks */
int wcfg_log[64]; int wcfg_nlog;
DWORD wcfg_ret[WP__N], wcfg_seterr[WP__N];
void *wcfg_pd_seen; int wcfg_pd_same;
wcfg_snap_t wcfg_snap;
const char *const wcfg_names[WP__N] = { "cryptt_Init", "cryptt_Object", "cryptt_Sig", "cryptt_Cert", "cryptt_Final",
    "cryptt_Test", "cryptt_Cleanup", "cryptt_CertCheck", "cryptt_FinalAlt" };
const wchar_t *const wcfg_wnames[WP__N] = { L"cryptt_Init", L"cryptt_Object", L"cryptt_Sig", L"cryptt_Cert", L"cryptt_Final",
    L"cryptt_Test", L"cryptt_Cleanup", L"cryptt_CertCheck", L"cryptt_FinalAlt" };

void wcfg_log_reset(void) {
    wcfg_nlog = 0; memset(wcfg_log, 0, sizeof wcfg_log); memset(wcfg_ret, 0, sizeof wcfg_ret); memset(wcfg_seterr, 0, sizeof wcfg_seterr);
    wcfg_pd_seen = NULL; wcfg_pd_same = 1; memset(&wcfg_snap, 0, sizeof wcfg_snap);
}
int wcfg_log_count(int id) { int c = 0; for (int i = 0; i < wcfg_nlog; i++) if (wcfg_log[i] == id) c++; return c; }

static LONG common(int id, CRYPT_PROVIDER_DATA *pd) {
    if (wcfg_nlog < 64) wcfg_log[wcfg_nlog++] = id;
    if (!wcfg_pd_seen) { wcfg_pd_seen = pd; wcfg_pd_same = 1; } else if (pd != wcfg_pd_seen) wcfg_pd_same = 0;
    if (id == WP_INIT && pd && !wcfg_snap.valid) {
        wcfg_snap.cbStruct = pd->cbStruct; wcfg_snap.pWintrustData = pd->pWintrustData; wcfg_snap.hWnd = pd->hWndParent;
        wcfg_snap.pgActionID = pd->pgActionID; wcfg_snap.hProv = pd->hProv; wcfg_snap.dwError = pd->dwError;
        wcfg_snap.secSettings = pd->dwRegSecuritySettings; wcfg_snap.polSettings = pd->dwRegPolicySettings;
        wcfg_snap.psPfns = pd->psPfns; wcfg_snap.fOpened = pd->fOpenedFile; wcfg_snap.dwProvFlags = pd->dwProvFlags;
        if (pd->psPfns) wcfg_snap.cbPfns = pd->psPfns->cbStruct;
        if (pd->pWintrustData && pd->pWintrustData->dwUnionChoice == WTD_CHOICE_FILE && pd->pWintrustData->pFile &&
            pd->pWintrustData->pFile->pcwszFilePath)
            wcsncpy(wcfg_snap.path, pd->pWintrustData->pFile->pcwszFilePath, MAX_PATH - 1);
        wcfg_snap.valid = 1;
    }
    if (id == WP_FINAL && pd) wcfg_snap.dwErrorAtFinal = pd->dwError;
    if (wcfg_seterr[id] && pd) pd->dwError = wcfg_seterr[id];
    return (LONG)wcfg_ret[id];
}
#define EXP __declspec(dllexport)
EXP LONG WINAPI cryptt_Init(CRYPT_PROVIDER_DATA *pd)    { return common(WP_INIT, pd); }
EXP LONG WINAPI cryptt_Object(CRYPT_PROVIDER_DATA *pd)  { return common(WP_OBJECT, pd); }
EXP LONG WINAPI cryptt_Sig(CRYPT_PROVIDER_DATA *pd)     { return common(WP_SIG, pd); }
EXP LONG WINAPI cryptt_Cert(CRYPT_PROVIDER_DATA *pd)    { return common(WP_CERT, pd); }
EXP LONG WINAPI cryptt_Final(CRYPT_PROVIDER_DATA *pd)   { return common(WP_FINAL, pd); }
EXP LONG WINAPI cryptt_FinalAlt(CRYPT_PROVIDER_DATA *pd){ return common(WP_FINALALT, pd); }
EXP LONG WINAPI cryptt_Test(CRYPT_PROVIDER_DATA *pd)    { return common(WP_TEST, pd); }
EXP LONG WINAPI cryptt_Cleanup(CRYPT_PROVIDER_DATA *pd) { return common(WP_CLEANUP, pd); }
EXP BOOL WINAPI cryptt_CertCheck(CRYPT_PROVIDER_DATA *pd, DWORD a, BOOL b, DWORD c) { common(WP_CERTCHECK, pd); return TRUE; }

void wcfg_fill_reg(wcfg_reg_t *x) {
    memset(x, 0, sizeof *x);
    wcfg_selfpath(x->dll, MAX_PATH);
    x->r.cbStruct = WCFG_REG_SIZE_FULL;
    CRYPT_TRUST_REG_ENTRY *e[8] = { &x->r.sInitProvider, &x->r.sObjectProvider, &x->r.sSignatureProvider, &x->r.sCertificateProvider,
        &x->r.sCertificatePolicyProvider, &x->r.sFinalPolicyProvider, &x->r.sTestPolicyProvider, &x->r.sCleanupProvider };
    static const int ids[8] = { WP_INIT, WP_OBJECT, WP_SIG, WP_CERT, WP_CERTCHECK, WP_FINAL, WP_TEST, WP_CLEANUP };
    for (int i = 0; i < 8; i++) { e[i]->cbStruct = sizeof *e[i]; e[i]->pwszDLLName = x->dll; e[i]->pwszFunctionName = (WCHAR *)wcfg_wnames[ids[i]]; }
}
BOOL wcfg_add(const GUID *g, DWORD flags, wcfg_reg_t *x) { return U(WintrustAddActionID)((GUID *)g, flags, &x->r); }

LONG wcfg_verify(const GUID *g, HWND hwnd, DWORD ui, const wchar_t *file, WINTRUST_DATA *out) {
    WINTRUST_FILE_INFO fi; WINTRUST_DATA wd;
    memset(&fi, 0, sizeof fi); fi.cbStruct = sizeof fi; fi.pcwszFilePath = file;
    memset(&wd, 0, sizeof wd); wd.cbStruct = sizeof wd; wd.dwUIChoice = ui; wd.fdwRevocationChecks = WTD_REVOKE_NONE;
    wd.dwUnionChoice = WTD_CHOICE_FILE; wd.pFile = &fi; wd.dwStateAction = WTD_STATEACTION_IGNORE;
    wd.dwProvFlags = WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL;
    LONG r = U(WinVerifyTrust)(hwnd, (GUID *)g, &wd);
    if (out) *out = wd;
    return r;
}

/* ------------------------------------------------------------------ usage callbacks */
int wcfg_usage_alloc_calls, wcfg_usage_free_calls;
const char *wcfg_usage_alloc_oid; void *wcfg_usage_alloc_ud; GUID wcfg_usage_alloc_guid; BOOL wcfg_usage_alloc_ret = TRUE;
EXP BOOL WINAPI cryptt_UsageAlloc(const char *oid, CRYPT_PROVIDER_DEFUSAGE *u) {
    wcfg_usage_alloc_calls++; wcfg_usage_alloc_oid = oid; wcfg_usage_alloc_ud = u; wcfg_usage_alloc_guid = u->gActionID;
    return wcfg_usage_alloc_ret;
}
GUID wcfg_usage_free_guid; const char *wcfg_usage_free_oid;
EXP BOOL WINAPI cryptt_UsageFree(const char *oid, CRYPT_PROVIDER_DEFUSAGE *u) {
    wcfg_usage_free_calls++; wcfg_usage_free_oid = oid; wcfg_usage_free_guid = u->gActionID; return TRUE;
}

/* ------------------------------------------------------------------ SIP callbacks */
wcfg_sipcall_t wcfg_sipc[8];
const char *const wcfg_sip_names[8] = { "cryptt_SipGet", "cryptt_SipPut", "cryptt_SipCreate", "cryptt_SipVerify", "cryptt_SipRemove",
    "cryptt_SipIs", "cryptt_SipIs2", "cryptt_SipCaps" };
const wchar_t *const wcfg_sip_wnames[8] = { L"cryptt_SipGet", L"cryptt_SipPut", L"cryptt_SipCreate", L"cryptt_SipVerify",
    L"cryptt_SipRemove", L"cryptt_SipIs", L"cryptt_SipIs2", L"cryptt_SipCaps" };
const wchar_t wcfg_magic[] = L"CRYPTTST";
GUID wcfg_sip_guid_for_is, wcfg_sip_guid_for_is2;
void wcfg_sip_reset(void) { memset(wcfg_sipc, 0, sizeof wcfg_sipc); for (int i = 0; i < 8; i++) wcfg_sipc[i].ret = TRUE; }

EXP BOOL WINAPI cryptt_SipGet(SIP_SUBJECTINFO *i, DWORD *enc, DWORD idx, DWORD *pcb, BYTE *pb) {
    wcfg_sipcall_t *c = &wcfg_sipc[SC_GET]; c->n++; c->info = i; c->p1 = enc; c->a = idx; c->p2 = pcb; SetLastError(c->err); return c->ret; }
EXP BOOL WINAPI cryptt_SipPut(SIP_SUBJECTINFO *i, DWORD enc, DWORD *pidx, DWORD cb, BYTE *pb) {
    wcfg_sipcall_t *c = &wcfg_sipc[SC_PUT]; c->n++; c->info = i; c->a = enc; c->p1 = pidx; c->b = cb; c->p2 = pb; SetLastError(c->err); return c->ret; }
EXP BOOL WINAPI cryptt_SipCreate(SIP_SUBJECTINFO *i, DWORD *pcb, SIP_INDIRECT_DATA *id) {
    wcfg_sipcall_t *c = &wcfg_sipc[SC_CREATE]; c->n++; c->info = i; c->p1 = pcb; c->p2 = id; SetLastError(c->err); return c->ret; }
EXP BOOL WINAPI cryptt_SipVerify(SIP_SUBJECTINFO *i, SIP_INDIRECT_DATA *id) {
    wcfg_sipcall_t *c = &wcfg_sipc[SC_VERIFY]; c->n++; c->info = i; c->p2 = id; SetLastError(c->err); return c->ret; }
EXP BOOL WINAPI cryptt_SipRemove(SIP_SUBJECTINFO *i, DWORD idx) {
    wcfg_sipcall_t *c = &wcfg_sipc[SC_REMOVE]; c->n++; c->info = i; c->a = idx; SetLastError(c->err); return c->ret; }
static int has_magic(HANDLE h, const char *m) {
    char b[8]; DWORD n = 0;
    if (h == INVALID_HANDLE_VALUE || h == NULL) return 0;
    SetFilePointer(h, 0, NULL, FILE_BEGIN);
    return ReadFile(h, b, 8, &n, NULL) && n == 8 && !memcmp(b, m, 8);
}
EXP BOOL WINAPI cryptt_SipIs(HANDLE h, GUID *g) {
    wcfg_sipcall_t *c = &wcfg_sipc[SC_IS]; c->n++; c->p1 = h; c->p2 = g;
    if (has_magic(h, "CRYPTTST")) { *g = wcfg_sip_guid_for_is; return TRUE; }
    return FALSE;
}
EXP BOOL WINAPI cryptt_SipIs2(const WCHAR *path, GUID *g) {
    wcfg_sipcall_t *c = &wcfg_sipc[SC_IS2]; c->n++; c->p1 = (void *)path; c->p2 = g;
    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    int ok = has_magic(h, "CRYPTTS2");
    if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
    if (ok) { *g = wcfg_sip_guid_for_is2; return TRUE; }
    return FALSE;
}
EXP DWORD WINAPI cryptt_SipCaps(void *capset) { wcfg_sipcall_t *c = &wcfg_sipc[SC_CAPS]; c->n++; c->info = capset; return c->ret; }

void wcfg_sip_fill(SIP_ADD_NEWPROVIDER_EX *a, const GUID *g, const wchar_t *dll) {
    memset(a, 0, sizeof *a);
    a->cbStruct = SIP_ADD_FULL_SIZE; a->pgSubject = (GUID *)g; a->pwszDLLFileName = (WCHAR *)dll;
    a->pwszMagicNumber = (WCHAR *)wcfg_magic; a->pwszIsFunctionName = (WCHAR *)wcfg_sip_wnames[SC_IS];
    a->pwszGetFuncName = (WCHAR *)wcfg_sip_wnames[SC_GET]; a->pwszPutFuncName = (WCHAR *)wcfg_sip_wnames[SC_PUT];
    a->pwszCreateFuncName = (WCHAR *)wcfg_sip_wnames[SC_CREATE]; a->pwszVerifyFuncName = (WCHAR *)wcfg_sip_wnames[SC_VERIFY];
    a->pwszRemoveFuncName = (WCHAR *)wcfg_sip_wnames[SC_REMOVE]; a->pwszIsFunctionNameFmt2 = (WCHAR *)wcfg_sip_wnames[SC_IS2];
    a->pwszGetCapFuncName = (WCHAR *)wcfg_sip_wnames[SC_CAPS];
}
