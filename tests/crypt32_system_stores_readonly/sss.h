#ifndef SSS_H
#define SSS_H
#include "t.h"
#include <wincrypt.h>
#include <wchar.h>

#ifndef CERT_SYSTEM_STORE_LOCATION_SHIFT
#define CERT_SYSTEM_STORE_LOCATION_SHIFT 16
#endif
#define SSS_LOC(id) ((DWORD)(id) << 16)
#define SSS_E_INVALIDARG ((DWORD)0x80070057)

typedef struct { const wchar_t *name; DWORD flag; } sss_loc_t;
static const sss_loc_t sss_locs[] = {
    { L"CurrentUser", CERT_SYSTEM_STORE_CURRENT_USER },
    { L"LocalMachine", CERT_SYSTEM_STORE_LOCAL_MACHINE },
    { L"CurrentService", CERT_SYSTEM_STORE_CURRENT_SERVICE },
    { L"Services", CERT_SYSTEM_STORE_SERVICES },
    { L"Users", CERT_SYSTEM_STORE_USERS },
    { L"CurrentUserGroupPolicy", CERT_SYSTEM_STORE_CURRENT_USER_GROUP_POLICY },
    { L"LocalMachineGroupPolicy", CERT_SYSTEM_STORE_LOCAL_MACHINE_GROUP_POLICY },
    { L"LocalMachineEnterprise", CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE },
};
#define SSS_NLOCS (sizeof(sss_locs)/sizeof(sss_locs[0]))

/* enumeration capture */
typedef struct {
    int n;
    wchar_t names[64][64];
    DWORD flags[64];
    int stop_after;      /* stop (return FALSE) after this many, 0 = never */
    void *arg_seen;
    void *resv_seen;
    int resv_nonnull;
    DWORD info_cb0;      /* pStoreInfo->cbSize of the first physical/system callback */
    int info_null;
} sss_cap_t;

static BOOL WINAPI sss_cb_loc(LPCWSTR name, DWORD flags, void *resv, void *arg) {
    sss_cap_t *c = (sss_cap_t *)arg;
    if (c->n < 64) { lstrcpynW(c->names[c->n], name ? name : L"(null)", 64); c->flags[c->n] = flags; }
    c->n++;
    if (resv) c->resv_nonnull++;
    return !(c->stop_after && c->n >= c->stop_after);
}
static BOOL WINAPI sss_cb_store(const void *sys, DWORD flags, PCERT_SYSTEM_STORE_INFO info, void *resv, void *arg) {
    sss_cap_t *c = (sss_cap_t *)arg;
    if (c->n < 64) { lstrcpynW(c->names[c->n], sys ? (LPCWSTR)sys : L"(null)", 64); c->flags[c->n] = flags; }
    if (c->n == 0) { c->info_null = info == NULL; c->info_cb0 = info ? info->cbSize : 0; }
    c->n++;
    if (resv) c->resv_nonnull++;
    return !(c->stop_after && c->n >= c->stop_after);
}
static BOOL WINAPI sss_cb_phys(const void *sys, DWORD flags, LPCWSTR name, PCERT_PHYSICAL_STORE_INFO info, void *resv, void *arg) {
    sss_cap_t *c = (sss_cap_t *)arg;
    if (c->n < 64) { lstrcpynW(c->names[c->n], name ? name : L"(null)", 64); c->flags[c->n] = flags; }
    if (c->n == 0) { c->info_null = info == NULL; c->info_cb0 = info ? info->cbSize : 0; }
    c->n++;
    if (resv) c->resv_nonnull++;
    return !(c->stop_after && c->n >= c->stop_after);
}
static int sss_has(const sss_cap_t *c, const wchar_t *name) {
    int m = c->n < 64 ? c->n : 64;
    for (int i = 0; i < m; i++) if (!lstrcmpiW(c->names[i], name)) return 1;
    return 0;
}
static int sss_count_certs(HCERTSTORE h) {
    int n = 0; PCCERT_CONTEXT c = NULL;
    while ((c = U(CertEnumCertificatesInStore)(h, c)) != NULL) n++;
    return n;
}
static void sss_wuniq(wchar_t *out, size_t cap, const wchar_t *tag) {
    static int seq;
    _snwprintf(out, cap, L"cryptt_%s_%lu_%d", tag, GetCurrentProcessId(), ++seq);
}
#endif
