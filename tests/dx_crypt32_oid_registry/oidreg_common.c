#include "oidreg.h"
#include <shlobj.h>

static int g_can = -1, g_atexit;
static int g_pre[4];        /* pre-existing: OID\EncodingType 0, 1, 0\CryptDllFindOIDInfo, 777 */

FARPROC oidr_proc(const char *name) {
    DWORD e = GetLastError(); FARPROC p = t_proc(name); SetLastError(e); return p;
}
int oidr_not_wine(void) {
    DWORD e = GetLastError(); int r = !t_is_wine(); SetLastError(e); return r;
}

int oidr_can_write(void) {
    if (g_can < 0) {
        HKEY k;
        LONG rc = RegOpenKeyExW(HKEY_LOCAL_MACHINE, OIDR_ROOT, 0, KEY_CREATE_SUB_KEY | KEY_SET_VALUE, &k);
        if (rc == 0) { RegCloseKey(k); g_can = 1; } else g_can = 0;
    }
    return g_can;
}

int oidr_key_exists(const wchar_t *sub) {
    HKEY k; wchar_t p[600];
    _snwprintf(p, 600, OIDR_ROOT L"\\%ls", sub);
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, p, 0, KEY_QUERY_VALUE, &k) != 0) return 0;
    RegCloseKey(k); return 1;
}

int oidr_value_count(const wchar_t *sub) {
    HKEY k; wchar_t p[600]; DWORD n = 0;
    _snwprintf(p, 600, OIDR_ROOT L"\\%ls", sub);
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, p, 0, KEY_QUERY_VALUE, &k) != 0) return -1;
    RegQueryInfoKeyW(k, NULL, NULL, NULL, NULL, NULL, NULL, &n, NULL, NULL, NULL, NULL);
    RegCloseKey(k); return (int)n;
}

LONG oidr_raw_get(const wchar_t *sub, const wchar_t *name, DWORD *type, void *buf, DWORD *cb) {
    HKEY k; wchar_t p[600]; LONG rc;
    _snwprintf(p, 600, OIDR_ROOT L"\\%ls", sub);
    rc = RegOpenKeyExW(HKEY_LOCAL_MACHINE, p, 0, KEY_QUERY_VALUE, &k);
    if (rc) return rc;
    rc = RegQueryValueExW(k, name, NULL, type, (BYTE *)buf, cb);
    RegCloseKey(k); return rc;
}

char *oidr_set(char *buf, size_t cap, const char *tag) {
    snprintf(buf, cap, "cryptt_oidreg_%lu_%s", GetCurrentProcessId(), tag); return buf;
}
char *oidr_oid(char *buf, size_t cap, unsigned n) {
    snprintf(buf, cap, "2.999.1347.%lu.%u", GetCurrentProcessId(), n); return buf;
}
wchar_t *oidr_wide(wchar_t *buf, size_t cap, const char *s) {
    MultiByteToWideChar(CP_ACP, 0, s, -1, buf, (int)cap); return buf;
}
void oidr_path(wchar_t *buf, size_t cap, unsigned enc, const char *func, const char *oid) {
    wchar_t f[300], o[300];
    _snwprintf(buf, cap, L"EncodingType %u\\%ls\\%ls", enc, oidr_wide(f, 300, func), oidr_wide(o, 300, oid));
}

static void del_tree(HKEY root, const wchar_t *path) { RegDeleteTreeW(root, path); }

/* delete subkeys of root\path whose names start with prefix (case-insensitive) */
static void del_children_prefix(HKEY root, const wchar_t *path, const wchar_t *prefix) {
    HKEY k;
    if (RegOpenKeyExW(root, path, 0, KEY_READ | KEY_WRITE | DELETE, &k) != 0) return;
    for (;;) {
        wchar_t names[64][300]; int n = 0; DWORD i = 0;
        for (;;) {
            DWORD len = 300;
            if (RegEnumKeyExW(k, i++, names[n], &len, NULL, NULL, NULL, NULL) != 0) break;
            if (!_wcsnicmp(names[n], prefix, wcslen(prefix)) && ++n == 64) break;
        }
        if (!n) break;
        for (int j = 0; j < n; j++) RegDeleteTreeW(k, names[j]);
    }
    RegCloseKey(k);
}

static void del_empty(const wchar_t *sub, int *pre) {
    HKEY k; wchar_t p[600]; DWORD nv = 1, ns = 1;
    if (*pre) return;
    _snwprintf(p, 600, OIDR_ROOT L"\\%ls", sub);
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, p, 0, KEY_QUERY_VALUE, &k) != 0) return;
    RegQueryInfoKeyW(k, NULL, NULL, NULL, &ns, NULL, NULL, &nv, NULL, NULL, NULL, NULL);
    RegCloseKey(k);
    if (!nv && !ns) RegDeleteKeyW(HKEY_LOCAL_MACHINE, p);
}

void oidr_sweep(void) {
    HKEY k; wchar_t p[600];
    if (oidr_can_write()) {
        _snwprintf(p, 600, OIDR_ROOT L"\\EncodingType 777");
        del_tree(HKEY_LOCAL_MACHINE, p);
        _snwprintf(p, 600, OIDR_ROOT L"\\EncodingType 0");
        del_children_prefix(HKEY_LOCAL_MACHINE, p, L"cryptt_oidreg_");
        _snwprintf(p, 600, OIDR_ROOT L"\\EncodingType 1");
        del_children_prefix(HKEY_LOCAL_MACHINE, p, L"cryptt_oidreg_");
        _snwprintf(p, 600, OIDR_ROOT L"\\EncodingType 0\\" L"CryptDllFindOIDInfo");
        del_children_prefix(HKEY_LOCAL_MACHINE, p, L"2.999.1347.");
        del_empty(L"EncodingType 0\\CryptDllFindOIDInfo", &g_pre[2]);
        del_empty(L"EncodingType 0", &g_pre[0]);
        del_empty(L"EncodingType 1", &g_pre[1]);
    }
    oidr_kid_cleanup();
}

static void atexit_sweep(void) { oidr_sweep(); }

int oidr_begin(void) {
    if (!oidr_can_write()) { t_skip("not elevated: HKLM OID registry is not writable"); return 0; }
    if (!g_atexit) {
        g_pre[0] = oidr_key_exists(L"EncodingType 0");
        g_pre[1] = oidr_key_exists(L"EncodingType 1");
        g_pre[2] = oidr_key_exists(L"EncodingType 0\\CryptDllFindOIDInfo");
        g_pre[3] = oidr_key_exists(L"EncodingType 777");
        atexit(atexit_sweep); g_atexit = 1;
    }
    oidr_sweep();
    return 1;
}
void oidr_end(void) { oidr_sweep(); }

/* ---- key identifiers ----------------------------------------------------------------------------- */
#define MAXKID 64
static BYTE g_kids[MAXKID][20]; static size_t g_kidlen[MAXKID]; static int g_nkid;

void oidr_kid(CRYPT_HASH_BLOB *b, BYTE *st, const char *tag, size_t len) {
    DWORD pid = GetCurrentProcessId();
    memset(st, 0, 20);
    memcpy(st, "cryptt", 6);
    memcpy(st + 6, &pid, 4);
    for (size_t i = 0; tag[i] && 10 + i < 20; i++) st[10 + i] = (BYTE)tag[i];
    b->cbData = (DWORD)len; b->pbData = st;
    if (len >= 1 && len <= 20 && g_nkid < MAXKID) {
        memcpy(g_kids[g_nkid], st, len); g_kidlen[g_nkid++] = len;
    }
}

void oidr_kid_track(const BYTE *id, size_t len) {
    if (len >= 1 && len <= 20 && g_nkid < MAXKID) { memcpy(g_kids[g_nkid], id, len); g_kidlen[g_nkid++] = len; }
}

static void hexname(wchar_t *out, const BYTE *p, size_t n) {
    for (size_t i = 0; i < n; i++) _snwprintf(out + 2 * i, 3, L"%02X", p[i]);
}

static void del_kid_everywhere(const BYTE *id, size_t n) {
    wchar_t hx[48], p[400]; wchar_t appdata[MAX_PATH];
    hexname(hx, id, n);
    _snwprintf(p, 400, L"Software\\Microsoft\\SystemCertificates\\My\\Keys\\%ls", hx);
    RegDeleteTreeW(HKEY_CURRENT_USER, p);
    if (oidr_can_write()) RegDeleteTreeW(HKEY_LOCAL_MACHINE, p);
    if (GetEnvironmentVariableW(L"APPDATA", appdata, MAX_PATH)) {
        _snwprintf(p, 400, L"%ls\\Microsoft\\SystemCertificates\\My\\Keys\\%ls", appdata, hx);
        DeleteFileW(p);
    }
}

static void sweep_kid_prefix(void) {
    /* leftovers from crashed runs: any element whose hex name starts with "cryptt" (63 72 79 70 74 74) */
    static const wchar_t *pre = L"637279707474";
    wchar_t appdata[MAX_PATH], dir[400];
    for (int m = 0; m < 2; m++) {
        HKEY root = m ? HKEY_LOCAL_MACHINE : HKEY_CURRENT_USER;
        if (m && !oidr_can_write()) continue;
        del_children_prefix(root, L"Software\\Microsoft\\SystemCertificates\\My\\Keys", pre);
    }
    if (GetEnvironmentVariableW(L"APPDATA", appdata, MAX_PATH)) {
        WIN32_FIND_DATAW fd; HANDLE h;
        _snwprintf(dir, 400, L"%ls\\Microsoft\\SystemCertificates\\My\\Keys\\%ls*", appdata, pre);
        h = FindFirstFileW(dir, &fd);
        if (h != INVALID_HANDLE_VALUE) {
            do {
                wchar_t f[500];
                _snwprintf(f, 500, L"%ls\\Microsoft\\SystemCertificates\\My\\Keys\\%ls", appdata, fd.cFileName);
                DeleteFileW(f);
            } while (FindNextFileW(h, &fd));
            FindClose(h);
        }
    }
}

void oidr_kid_cleanup(void) {
    for (int i = 0; i < g_nkid; i++) del_kid_everywhere(g_kids[i], g_kidlen[i]);
    g_nkid = 0;
    sweep_kid_prefix();
}

static int g_kid_atexit;
int oidr_kid_begin(int machine) {
    if (machine && !oidr_can_write()) { t_skip("not elevated: machine key identifier store is not writable"); return 0; }
    if (!g_kid_atexit) { atexit(oidr_kid_cleanup); g_kid_atexit = 1; }
    oidr_kid_cleanup();
    return 1;
}
