#include "dxc.h"
#include <stdlib.h>

const dxc_prov dxc_provs[] = {
    { MS_DEF_PROV_A,        PROV_RSA_FULL, 0 },
    { MS_ENHANCED_PROV_A,   PROV_RSA_FULL, 0 },
    { MS_STRONG_PROV_A,     PROV_RSA_FULL, 0 },
    { MS_ENH_RSA_AES_PROV_A, PROV_RSA_AES, 0 },
    { MS_DEF_DSS_PROV_A,    PROV_DSS,      1 },
    { MS_DEF_DSS_DH_PROV_A, PROV_DSS_DH,   1 },
    { MS_ENH_DSS_DH_PROV_A, PROV_DSS_DH,   1 },
};
const int dxc_nprov = 7;

const char *dxc_name(const char *tag) {
    static char b[8][160]; static int i;
    char *p = b[i++ & 7];
    snprintf(p, 160, "%s_%lu_%s", T_TMP_PREFIX, GetCurrentProcessId(), tag);
    return p;
}
const WCHAR *dxc_wname(const char *tag) {
    static WCHAR b[8][160]; static int i;
    WCHAR *p = b[i++ & 7];
    const char *a = dxc_name(tag);
    int n = 0; while (a[n]) { p[n] = (WCHAR)a[n]; n++; } p[n] = 0;
    return p;
}

BOOL dxc_acq(HCRYPTPROV *h, const char *cont, int pi, DWORD flags) {
    return U(CryptAcquireContextA)(h, cont, dxc_provs[pi].a, dxc_provs[pi].type, flags);
}
void dxc_rel(HCRYPTPROV h) { if (h) U(CryptReleaseContext)(h, 0); }

BOOL dxc_have(int pi) {
    static signed char c[16];
    if (!U(CryptAcquireContextA) || !U(CryptReleaseContext) || !U(CryptGetProvParam)) return 0;
    if (c[pi] == 0) {
        HCRYPTPROV h = 0;
        DWORD save = GetLastError();
        c[pi] = dxc_acq(&h, NULL, pi, CRYPT_VERIFYCONTEXT) ? 1 : -1;
        dxc_rel(h);
        SetLastError(save);
    }
    return c[pi] > 0;
}

BOOL dxc_gpp(HCRYPTPROV h, DWORD p, void *buf, DWORD *n, DWORD fl) {
    return U(CryptGetProvParam)(h, p, (BYTE *)buf, n, fl);
}

int dxc_enum_in(HCRYPTPROV h, char names[][264], int max) {
    int n = 0;
    DWORD fl = CRYPT_FIRST;
    for (;;) {
        char buf[600]; DWORD len = sizeof buf;
        if (!dxc_gpp(h, PP_ENUMCONTAINERS, buf, &len, fl)) {
            if (GetLastError() == ERROR_NO_MORE_ITEMS) return n;
            return -1;
        }
        fl = CRYPT_NEXT;
        if (n < max) { strncpy(names[n], buf, 263); names[n][263] = 0; n++; }
        if (n >= 4000) return n;
    }
}

int dxc_enum(int pi, DWORD machine, char names[][264], int max) {
    HCRYPTPROV h = 0; int n;
    DWORD save = GetLastError();
    if (!dxc_acq(&h, NULL, pi, CRYPT_VERIFYCONTEXT | machine)) { SetLastError(save); return -1; }
    n = dxc_enum_in(h, names, max);
    dxc_rel(h);
    SetLastError(save);
    return n;
}

void dxc_del(const char *cont, int pi, DWORD machine) {
    HCRYPTPROV h = 0;
    DWORD save = GetLastError();
    dxc_acq(&h, cont, pi, CRYPT_DELETEKEYSET | machine);
    SetLastError(save);
}

static char (*g_names)[264];
void dxc_prepare(int pi, DWORD machine) {
    static unsigned char done[16][2];
    int mi = machine ? 1 : 0;
    if (done[pi][mi]) return;
    done[pi][mi] = 1;
    if (!g_names) g_names = malloc(264 * 512);
    if (!g_names) return;
    int n = dxc_enum(pi, machine, g_names, 512);
    for (int i = 0; i < n; i++)
        if (!strncmp(g_names[i], T_TMP_PREFIX "_", sizeof(T_TMP_PREFIX)))
            dxc_del(g_names[i], pi, machine);
}

BOOL dxc_exists(const char *cont, int pi, DWORD machine) {
    HCRYPTPROV h = 0;
    DWORD save = GetLastError();
    BOOL ok = dxc_acq(&h, cont, pi, machine);
    dxc_rel(h);
    SetLastError(save);
    return ok;
}

BOOL dxc_is_admin(void) {
    BOOL r = FALSE; HANDLE tok;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) {
        TOKEN_ELEVATION el; DWORD n;
        if (GetTokenInformation(tok, TokenElevation, &el, sizeof el, &n)) r = el.TokenIsElevated != 0;
        CloseHandle(tok);
    }
    return r;
}

BOOL dxc_machine_ok(int pi) {
    if (!dxc_have(pi)) { t_skip("provider not available"); return 0; }
    if (!dxc_is_admin() && !t_is_wine()) { t_skip("not elevated"); return 0; }
    dxc_prepare(pi, CRYPT_MACHINE_KEYSET);
    return 1;
}

int dxc_export(HCRYPTKEY k, HCRYPTKEY expkey, DWORD blobtype, DWORD flags, BYTE *out, DWORD cap) {
    DWORD n = cap;
    if (!U(CryptExportKey)(k, expkey, blobtype, flags, out, &n)) return -1;
    return (int)n;
}

/* Runs last when constructors register in link order; independent otherwise. */
TEST(dxc_zz_no_leftovers_for_this_pid) {
    REQUIRE(U(CryptAcquireContextA));
    char tag[40]; snprintf(tag, sizeof tag, "%s_%lu_", T_TMP_PREFIX, GetCurrentProcessId());
    static char names[300][264];
    for (int pi = 0; pi < dxc_nprov; pi++) {
        if (!dxc_have(pi)) continue;
        int n = dxc_enum(pi, 0, names, 300);
        for (int i = 0; i < n; i++)
            CHECKF(strncmp(names[i], tag, strlen(tag)) != 0, "leftover %s (prov %d)", names[i], pi);
    }
}
