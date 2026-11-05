/* Environment facts of the oracle (no TPM, workgroup, elevation) and the unique-name / cleanup behaviour used by dx areas. */
#include "ew.h"
typedef UINT32 (WINAPI *tbs_create_fn)(const void *, void **);

TEST(ew_env_no_tpm) {
    typedef struct { UINT32 version; UINT32 flags; } CTXP;
    CTXP c2 = {2, 4}, c1 = {1, 0}; void *ctx = NULL; tbs_create_fn cc;
    REQUIRE_NO_TPM();
    cc = (tbs_create_fn)t_proc_in("tbs.dll", "Tbsi_Context_Create");
    REQUIRE(cc);
    EXPECT_EQ(t_tpm_status(), 0x8028400F);                                  /* TBS_E_TPM_NOT_FOUND */
    EXPECT_EQ(cc(&c2, &ctx), 0x8028400F);
    EXPECT_EQ(cc(&c1, &ctx), 0x8028400F);
    EXPECT_EQ(cc(NULL, &ctx), 0x80284002);                                   /* control: parameter check precedes the device check */
    CHECK(ctx == NULL);
}
TEST(ew_env_workgroup) {
    typedef NET_API_STATUS (NET_API_FUNCTION *njg_fn)(LPCWSTR, LPWSTR *, PNETSETUP_JOIN_STATUS);
    njg_fn njg = (njg_fn)t_proc_in("netapi32.dll", "NetGetJoinInformation"); LPWSTR nm = NULL; NETSETUP_JOIN_STATUS js = 0;
    WCHAR dns[300]; DWORD n = 300;
    REQUIRE_WORKGROUP();
    REQUIRE(njg);
    EXPECT_EQ(njg(NULL, &nm, &js), 0);
    EXPECT_EQ(js, NetSetupWorkgroupName);
    if (nm) { EXPECT_WSTR(nm, L"WORKGROUP"); ((NET_API_STATUS (NET_API_FUNCTION *)(LPVOID))t_proc_in("netapi32.dll", "NetApiBufferFree"))(nm); }
    EXPECT_EQ(t_join_status(), 2);
    CHECK(!t_is_domain_joined());
    SET_ERR(0); CHECK(GetComputerNameExW(ComputerNameDnsDomain, dns, &n)); EXPECT_EQ(n, 0); EXPECT_EQ(dns[0], 0);   /* no DNS domain */
    EXPECT_EQ(njg(NULL, NULL, &js), 87);                                      /* control: NULL name buffer pointer */
}
TEST(ew_env_hklm_write_depends_on_elevation) {
    HKEY k = NULL; LONG e; const char *path = "SOFTWARE\\I7T_e_win10_findings_probe_hklm";
    e = RegCreateKeyExA(HKEY_CURRENT_USER, "Software\\I7T_e_win10_findings_probe_hkcu", 0, NULL, 0, KEY_WRITE, NULL, &k, NULL);
    EXPECT_EQ(e, 0);                                                         /* control: HKCU is writable in both modes */
    if (k) { RegCloseKey(k); RegDeleteKeyA(HKEY_CURRENT_USER, "Software\\I7T_e_win10_findings_probe_hkcu"); }
    if (t_is_elevated()) {
        k = NULL; e = RegCreateKeyExA(HKEY_LOCAL_MACHINE, path, 0, NULL, 0, KEY_WRITE, NULL, &k, NULL);
        EXPECT_EQ(e, 0);
        if (k) { RegCloseKey(k); RegDeleteKeyA(HKEY_LOCAL_MACHINE, path); }
    } else {
        k = NULL; e = RegCreateKeyExA(HKEY_LOCAL_MACHINE, path, 0, NULL, 0, KEY_WRITE, NULL, &k, NULL);
        EXPECT_EQ(e, ERROR_ACCESS_DENIED);
        if (k) { RegCloseKey(k); RegDeleteKeyA(HKEY_LOCAL_MACHINE, path); }
    }
}
TEST(ew_unique_names_and_prefix) {
    char a[200], b[200]; const char *pre = t_area_prefix();
    EXPECT_STR(t_area_name(), "e_win10_findings");
    EXPECT_STR(pre, "I7T_e_win10_findings_");
    strcpy(a, t_unique("tag")); strcpy(b, t_unique("tag"));
    CHECK(!strncmp(a, pre, strlen(pre)));
    CHECK(!strncmp(b, pre, strlen(pre)));
    CHECK(strcmp(a, b) != 0);                                                /* the counter distinguishes equal tags */
    { char want[64]; sprintf(want, "I7T_e_win10_findings_tag_%lu_", (unsigned long)GetCurrentProcessId()); CHECK(!strncmp(a, want, strlen(want))); }
    { const WCHAR *w = t_unique_w("tag"); char c[200]; int i; for (i = 0; w[i] && i < 199; i++) c[i] = (char)w[i]; c[i] = 0;
      CHECK(!strncmp(c, pre, strlen(pre))); CHECK(strcmp(c, a) != 0 && strcmp(c, b) != 0); }
}
T_SWEEPER(ew_reg) {
    (void)phase;
    t_reg_sweep_subkeys(HKEY_CURRENT_USER, "Software\\I7T_e_win10_findings_dx", prefix);
    RegDeleteKeyA(HKEY_CURRENT_USER, "Software\\I7T_e_win10_findings_dx");
}
TEST(ew_dx_registry_sweep_removes_only_prefixed) {
    HKEY root = NULL, k = NULL; const char *base = "Software\\I7T_e_win10_findings_dx"; char mine[200], other[] = "keepme_i7t"; int n;
    REQUIRE_DESTRUCTIVE();
    REQUIRE_EQ(RegCreateKeyExA(HKEY_CURRENT_USER, base, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &root, NULL), 0);
    strcpy(mine, t_unique("regkey"));
    REQUIRE_EQ(RegCreateKeyExA(root, mine, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &k, NULL), 0); RegCloseKey(k);
    REQUIRE_EQ(RegCreateKeyExA(root, other, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &k, NULL), 0); RegCloseKey(k);
    RegCloseKey(root);
    n = t_reg_sweep_subkeys(HKEY_CURRENT_USER, base, t_area_prefix());
    EXPECT_EQ(n, 1);
    EXPECT_EQ(RegOpenKeyExA(HKEY_CURRENT_USER, base, 0, KEY_READ, &root), 0);
    if (root) {
        EXPECT_EQ(RegOpenKeyExA(root, mine, 0, KEY_READ, &k), ERROR_FILE_NOT_FOUND);                    /* swept */
        EXPECT_EQ(RegOpenKeyExA(root, other, 0, KEY_READ, &k), 0);                                      /* control: foreign name survives */
        if (k) RegCloseKey(k);
        RegDeleteKeyA(root, other); RegCloseKey(root);
    }
    EXPECT_EQ(t_reg_sweep_subkeys(HKEY_CURRENT_USER, base, t_area_prefix()), 0);                        /* idempotent */
    RegDeleteKeyA(HKEY_CURRENT_USER, base);
}
TEST(ew_ncrypt_unique_key_lifecycle) {
    NCRYPT_PROV_HANDLE p = 0; NCRYPT_KEY_HANDLE k = 0, k2 = 0; const WCHAR *name = t_unique_w("life");
    REQUIRE(NCR(NCryptOpenStorageProvider));
    REQUIRE_EQ(NCR(NCryptOpenStorageProvider)(&p, MS_KEY_STORAGE_PROVIDER, 0), 0);
    EXPECT_EQ(NCR(NCryptOpenKey)(p, &k2, name, 0, 0), ERR_NTE_BAD_KEYSET);                               /* control: not there yet */
    REQUIRE_EQ(NCR(NCryptCreatePersistedKey)(p, &k, BCRYPT_ECDSA_P256_ALGORITHM, name, 0, 0), 0);
    EXPECT_EQ(NCR(NCryptFinalizeKey)(k, 0), 0);
    EXPECT_EQ(NCR(NCryptOpenKey)(p, &k2, name, 0, 0), 0);
    if (k2) NCR(NCryptFreeObject)(k2);
    EXPECT_EQ(NCR(NCryptDeleteKey)(k, 0), 0);
    k2 = 0; EXPECT_EQ(NCR(NCryptOpenKey)(p, &k2, name, 0, 0), ERR_NTE_BAD_KEYSET);
    NCR(NCryptFreeObject)(p);
}
