#include "ds.h"
#include "vectors.h"

static int g_atexit, g_pid_sweep;
#define SC_ROOT L"Software\\Microsoft\\SystemCertificates"

static HKEY rootkey(DWORD loc) { return (loc & 0xff0000) == CERT_SYSTEM_STORE_LOCAL_MACHINE ? HKEY_LOCAL_MACHINE : HKEY_CURRENT_USER; }

static void sweep_hive(HKEY root) {
    HKEY k;
    if (RegOpenKeyExW(root, SC_ROOT, 0, KEY_READ | KEY_WRITE, &k)) return;
    for (int round = 0; round < 8; round++) {
        wchar_t nm[300]; int found = 0;
        for (DWORD i = 0;; i++) {
            DWORD n = 300;
            if (RegEnumKeyExW(k, i, nm, &n, NULL, NULL, NULL, NULL)) break;
            if (!wcsncmp(nm, DS_PFX, wcslen(DS_PFX))) { RegDeleteTreeW(k, nm); RegDeleteKeyW(k, nm); found = 1; }
        }
        if (!found) break;
    }
    RegCloseKey(k);
}
void ds_sweep(void) { sweep_hive(HKEY_CURRENT_USER); sweep_hive(HKEY_LOCAL_MACHINE); }
void ds_end(void) { ds_sweep(); }
static void at_exit(void) { ds_sweep(); }

int ds_begin(int machine) {
    if (!g_atexit) { g_atexit = 1; atexit(at_exit); }
    if (machine) {
        HKEY k; DWORD disp;
        wchar_t p[200]; _snwprintf(p, 200, SC_ROOT L"\\" DS_PFX L"probe_%lu", GetCurrentProcessId());
        LONG rc = RegCreateKeyExW(HKEY_LOCAL_MACHINE, p, 0, NULL, 0, KEY_WRITE, NULL, &k, &disp);
        if (rc) { t_skip("HKLM SystemCertificates not writable (not elevated), rc=%ld", rc); return 0; }
        RegCloseKey(k); RegDeleteKeyW(HKEY_LOCAL_MACHINE, p);
    }
    ds_sweep();
    return 1;
}

wchar_t *ds_name(wchar_t *out, size_t cap, const char *tag) {
    _snwprintf(out, cap, DS_PFX L"%lu_%hs", GetCurrentProcessId(), tag);
    out[cap - 1] = 0;
    return out;
}

HCERTSTORE ds_open_loc(const wchar_t *name, DWORD loc, DWORD flags) {
    return U(CertOpenStore)(DS_SYS_W, 0, 0, (loc ? loc : CERT_SYSTEM_STORE_CURRENT_USER) | flags, name);
}
HCERTSTORE ds_open(const wchar_t *name, DWORD flags) { return ds_open_loc(name, 0, flags); }

int ds_count(HCERTSTORE h) {
    int n = 0; PCCERT_CONTEXT c = NULL;
    while ((c = U(CertEnumCertificatesInStore)(h, c)) != NULL) n++;
    return n;
}
int ds_count_named(const wchar_t *name, DWORD loc, DWORD flags) {
    HCERTSTORE h = ds_open_loc(name, loc, flags);
    if (!h) return -1;
    int n = ds_count(h);
    U(CertCloseStore)(h, 0);
    return n;
}

const BYTE *ds_der(int i, DWORD *cb) {
    static const unsigned char *const p[] = { ds_cert0_der, ds_cert1_der, ds_cert2_der, ds_cert3_der };
    static const DWORD n[] = { sizeof ds_cert0_der, sizeof ds_cert1_der, sizeof ds_cert2_der, sizeof ds_cert3_der };
    if (cb) *cb = n[i];
    return p[i];
}
const char *ds_sha1(int i) {
    static const char *const s[] = { ds_cert0_sha1, ds_cert1_sha1, ds_cert2_sha1, ds_cert3_sha1 };
    return s[i];
}
const wchar_t *ds_cn(int i) {
    static const wchar_t *const s[] = { ds_cert0_cn, ds_cert1_cn, ds_cert2_cn, ds_cert3_cn };
    return s[i];
}
const BYTE *ds_crl(DWORD *cb) { if (cb) *cb = sizeof ds_crl_der; return ds_crl_der; }

void ds_sync(HCERTSTORE h) {
    /* Windows writes registry-backed stores through on every change. The emulator defers until commit/close,
     * so flush there to let the registry inspections below mean the same thing on both. No-op on Windows. */
    if (t_is_wine()) U(CertControlStore)(h, 0, CERT_STORE_CTRL_COMMIT, NULL);
}
PCCERT_CONTEXT ds_add(HCERTSTORE h, int idx, DWORD disp) {
    DWORD cb; const BYTE *d = ds_der(idx, &cb); PCCERT_CONTEXT out = NULL;
    if (!U(CertAddEncodedCertificateToStore)(h, X509_ASN_ENCODING, d, cb, disp, &out)) return NULL;
    ds_sync(h);
    return out;
}
BOOL ds_del(PCCERT_CONTEXT c) {     /* CertDeleteCertificateFromStore (frees c) + sync */
    HCERTSTORE h = c->hCertStore;
    BOOL r = U(CertDeleteCertificateFromStore)(c);
    ds_sync(h);
    return r;
}
int ds_add_ok(HCERTSTORE h, int idx) {
    PCCERT_CONTEXT c = ds_add(h, idx, CERT_STORE_ADD_REPLACE_EXISTING);
    if (!c) return 0;
    U(CertFreeCertificateContext)(c);
    return 1;
}
PCCERT_CONTEXT ds_find(HCERTSTORE h, int idx) {
    BYTE hash[20]; const char *s = ds_sha1(idx);
    for (int i = 0; i < 20; i++) { unsigned v; sscanf(s + 2 * i, "%2x", &v); hash[i] = (BYTE)v; }
    CRYPT_HASH_BLOB b = { 20, hash };
    return U(CertFindCertificateInStore)(h, X509_ASN_ENCODING, 0, CERT_FIND_SHA1_HASH, &b, NULL);
}
int ds_stored(const wchar_t *name, DWORD loc, int idx) {
    HCERTSTORE h = ds_open_loc(name, loc, CERT_STORE_OPEN_EXISTING_FLAG);
    if (!h) return -1;
    PCCERT_CONTEXT c = ds_find(h, idx);
    int r = c != NULL;
    if (c) U(CertFreeCertificateContext)(c);
    U(CertCloseStore)(h, 0);
    return r;
}

static void subpath(wchar_t *out, size_t cap, const wchar_t *store, const wchar_t *sub) {
    if (sub) _snwprintf(out, cap, SC_ROOT L"\\%s\\%s", store, sub);
    else _snwprintf(out, cap, SC_ROOT L"\\%s", store);
    out[cap - 1] = 0;
}
int ds_key_exists(DWORD loc, const wchar_t *store, const wchar_t *sub) {
    wchar_t p[600]; HKEY k; subpath(p, 600, store, sub);
    if (RegOpenKeyExW(rootkey(loc), p, 0, KEY_READ, &k)) return 0;
    RegCloseKey(k); return 1;
}
int ds_cert_key_exists(DWORD loc, const wchar_t *store, int idx) {
    wchar_t sub[100]; _snwprintf(sub, 100, L"Certificates\\%hs", ds_sha1(idx));
    return ds_key_exists(loc, store, sub);
}
LONG ds_reg_value(DWORD loc, const wchar_t *store, const wchar_t *sub, const wchar_t *val, DWORD *type, void *buf, DWORD *cb) {
    wchar_t p[600]; HKEY k; subpath(p, 600, store, sub);
    LONG rc = RegOpenKeyExW(rootkey(loc), p, 0, KEY_READ, &k);
    if (rc) return rc;
    rc = RegQueryValueExW(k, val, NULL, type, (BYTE *)buf, cb);
    RegCloseKey(k);
    return rc;
}
LONG ds_cert_blob(DWORD loc, const wchar_t *store, int idx, DWORD *type, DWORD *cb) {
    wchar_t sub[100]; _snwprintf(sub, 100, L"Certificates\\%hs", ds_sha1(idx));
    *cb = 0;
    return ds_reg_value(loc, store, sub, L"Blob", type, NULL, cb);
}
int ds_subkey_count(DWORD loc, const wchar_t *store, const wchar_t *sub) {
    wchar_t p[600]; HKEY k; DWORD n = 0; subpath(p, 600, store, sub);
    if (RegOpenKeyExW(rootkey(loc), p, 0, KEY_READ, &k)) return -1;
    RegQueryInfoKeyW(k, NULL, NULL, NULL, &n, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    RegCloseKey(k); return (int)n;
}
