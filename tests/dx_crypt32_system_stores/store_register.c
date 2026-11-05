#include "ds.h"
/* CertRegisterSystemStore / CertUnregisterSystemStore / CertRegisterPhysicalStore /
 * CertUnregisterPhysicalStore / CertEnumSystemStore / CertEnumPhysicalStore for current-user (and,
 * elevated, local-machine) test stores.
 * Flag masks and E_INVALIDARG paths come from observed behaviour:
 *   register  (system+physical) rejects dwFlags & 0xd7ff   -> only CREATE_NEW 0x2000 and BACKUP_RESTORE 0x800 pass
 *   unregister (system+physical) rejects dwFlags & 0xb7ef   -> only DELETE 0x10, BACKUP_RESTORE 0x800, OPEN_EXISTING 0x4000 pass */

#define CU CERT_SYSTEM_STORE_CURRENT_USER
#define NAME(tag) wchar_t nm[120]; ds_name(nm, 120, tag)
#define NAME2(tag) wchar_t nm2[120]; ds_name(nm2, 120, tag)
#define WINE_SKIP(why) do { if (t_is_wine()) { t_skip("emulator: " why); return; } } while (0)

static BOOL regsys(const wchar_t *n, DWORD fl) { return U(CertRegisterSystemStore)((void *)n, CU | fl, NULL, NULL); }
static BOOL unregsys(const wchar_t *n, DWORD fl) { return U(CertUnregisterSystemStore)((void *)n, CU | fl); }

static BOOL regphys(const wchar_t *store, DWORD fl, const wchar_t *phys, const char *prov, DWORD openflags,
                    const wchar_t *params, DWORD pflags, DWORD prio) {
    CERT_PHYSICAL_STORE_INFO i; memset(&i, 0, sizeof i);
    i.cbSize = sizeof i; i.pszOpenStoreProvider = (LPSTR)prov; i.dwOpenEncodingType = 0; i.dwOpenFlags = openflags;
    if (params) { i.OpenParameters.pbData = (BYTE *)params; i.OpenParameters.cbData = (DWORD)((wcslen(params) + 1) * 2); }
    i.dwFlags = pflags; i.dwPriority = prio;
    return U(CertRegisterPhysicalStore)((void *)store, CU | fl, phys, &i, NULL);
}
static BOOL unregphys(const wchar_t *store, DWORD fl, const wchar_t *phys) {
    return U(CertUnregisterPhysicalStore)((void *)store, CU | fl, phys);
}

typedef struct { int n; wchar_t names[16][64]; DWORD prio[16], pflags[16], cb[16], openflags[16]; char prov[16][32]; DWORD blobcb[16]; wchar_t blob[16][64]; DWORD flags0; } phys_cap_t;
static BOOL WINAPI phys_cb(const void *sys, DWORD flags, LPCWSTR name, PCERT_PHYSICAL_STORE_INFO info, void *resv, void *arg) {
    phys_cap_t *c = (phys_cap_t *)arg;
    if (c->n < 16) {
        int k = c->n;
        lstrcpynW(c->names[k], name ? name : L"(null)", 64);
        if (info) {
            c->cb[k] = info->cbSize; c->prio[k] = info->dwPriority; c->pflags[k] = info->dwFlags; c->openflags[k] = info->dwOpenFlags;
            if ((ULONG_PTR)info->pszOpenStoreProvider > 0xffff) { strncpy(c->prov[k], info->pszOpenStoreProvider, 31); c->prov[k][31] = 0; }
            else sprintf(c->prov[k], "#%u", (unsigned)(ULONG_PTR)info->pszOpenStoreProvider);
            c->blobcb[k] = info->OpenParameters.cbData;
            if (info->OpenParameters.pbData && info->OpenParameters.cbData < 120) memcpy(c->blob[k], info->OpenParameters.pbData, info->OpenParameters.cbData);
        }
    }
    if (c->n == 0) c->flags0 = flags;
    c->n++;
    return TRUE;
}
static BOOL enum_phys(const wchar_t *store, DWORD fl, phys_cap_t *c) {
    memset(c, 0, sizeof *c);
    return U(CertEnumPhysicalStore)((void *)store, CU | fl, c, phys_cb);
}
static int phys_index(const phys_cap_t *c, const wchar_t *n) {
    int m = c->n < 16 ? c->n : 16;
    for (int i = 0; i < m; i++) if (!lstrcmpiW(c->names[i], n)) return i;
    return -1;
}
typedef struct { int found; DWORD flags; wchar_t want[120]; } sys_cap_t;
static BOOL WINAPI sys_cb(const void *sys, DWORD flags, PCERT_SYSTEM_STORE_INFO info, void *resv, void *arg) {
    sys_cap_t *c = (sys_cap_t *)arg;
    if (sys && !lstrcmpiW((LPCWSTR)sys, c->want)) { c->found++; c->flags = flags; }
    return TRUE;
}

/* ---- CertRegisterSystemStore ------------------------------------------------------------------ */
TEST(dxss_regsys_creates_store_key) {
    SETUP(CertRegisterSystemStore); NAME("rs1");
    CHECK(!ds_key_exists(0, nm, NULL));
    SET_ERR(0);
    CHECK(regsys(nm, 0));
    CHECK(ds_key_exists(0, nm, NULL));
    ds_end();
}
TEST(dxss_regsys_store_is_openable_existing) {
    SETUP(CertRegisterSystemStore); NAME("rs2");
    CHECK(regsys(nm, 0));
    HCERTSTORE h = ds_open(nm, CERT_STORE_OPEN_EXISTING_FLAG);
    CHECK(h != NULL);
    if (h) { EXPECT_EQ(ds_count(h), 0); U(CertCloseStore)(h, 0); }
    ds_end();
}
TEST(dxss_regsys_twice_succeeds) {
    SETUP(CertRegisterSystemStore); NAME("rs3");
    CHECK(regsys(nm, 0));
    CHECK(regsys(nm, 0));
    ds_end();
}
TEST(dxss_regsys_does_not_touch_existing_certs) {
    SETUP(CertRegisterSystemStore); NAME("rs4");
    HCERTSTORE h = ds_open(nm, 0);
    if (h) { CHECK(ds_add_ok(h, 0)); U(CertCloseStore)(h, 0); } else CHECK(0);
    CHECK(regsys(nm, 0));
    EXPECT_EQ(ds_stored(nm, 0, 0), 1);
    ds_end();
}
TEST(dxss_regsys_create_new_fresh_succeeds) {
    SETUP(CertRegisterSystemStore); NAME("rs5");
    CHECK(regsys(nm, CERT_STORE_CREATE_NEW_FLAG));
    CHECK(ds_key_exists(0, nm, NULL));
    ds_end();
}
TEST(dxss_regsys_create_new_existing_fails_with_file_exists) {
    SETUP(CertRegisterSystemStore); NAME("rs6");
    CHECK(regsys(nm, 0));
    SET_ERR(0);
    EXPECT_FAIL(!regsys(nm, CERT_STORE_CREATE_NEW_FLAG), ERROR_FILE_EXISTS);
    ds_end();
}
TEST(dxss_regsys_rejected_flags) {
    SETUP(CertRegisterSystemStore); WINE_SKIP("no flag validation in registration");
    static const DWORD bad[] = { CERT_STORE_NO_CRYPT_RELEASE_FLAG, CERT_STORE_SET_LOCALIZED_NAME_FLAG, CERT_STORE_DEFER_CLOSE_UNTIL_LAST_FREE_FLAG,
        CERT_STORE_DELETE_FLAG, CERT_STORE_UNSAFE_PHYSICAL_FLAG, CERT_STORE_SHARE_STORE_FLAG, CERT_STORE_SHARE_CONTEXT_FLAG,
        CERT_STORE_MANIFOLD_FLAG, CERT_STORE_ENUM_ARCHIVED_FLAG, CERT_STORE_UPDATE_KEYID_FLAG, CERT_STORE_MAXIMUM_ALLOWED_FLAG,
        CERT_STORE_OPEN_EXISTING_FLAG, CERT_STORE_READONLY_FLAG };
    for (unsigned i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        wchar_t nm[120]; char tag[16]; sprintf(tag, "rf%u", i); ds_name(nm, 120, tag);
        SET_ERR(0);
        BOOL r = regsys(nm, bad[i]);
        DWORD e = GetLastError();
        CHECKF(!r, "flag 0x%lx accepted", bad[i]);
        CHECKF(e == DS_E_INVALIDARG, "flag 0x%lx: error 0x%lx", bad[i], e);
        CHECKF(!ds_key_exists(0, nm, NULL), "flag 0x%lx created a key", bad[i]);
    }
    ds_end();
}
TEST(dxss_regsys_null_name_invalid_arg) {
    SETUP(CertRegisterSystemStore); WINE_SKIP("different error");
    SET_ERR(0);
    EXPECT_FAIL(!U(CertRegisterSystemStore)(NULL, CU, NULL, NULL), DS_E_INVALIDARG);
}
TEST(dxss_regsys_empty_name_invalid_arg) {
    SETUP(CertRegisterSystemStore); WINE_SKIP("different error");
    SET_ERR(0);
    EXPECT_FAIL(!U(CertRegisterSystemStore)((void *)L"", CU, NULL, NULL), DS_E_INVALIDARG);
}
TEST(dxss_regsys_ignores_info_and_reserved) {
    SETUP(CertRegisterSystemStore); NAME("rs7");
    CERT_SYSTEM_STORE_INFO si = { sizeof si };
    CHECK(U(CertRegisterSystemStore)((void *)nm, CU, &si, NULL));
    ds_end();
}
TEST(dxss_regsys_unknown_location_fails) {
    SETUP(CertRegisterSystemStore); NAME("rs8");
    SET_ERR(0);
    BOOL r = U(CertRegisterSystemStore)((void *)nm, (DWORD)0xFE << 16, NULL, NULL);
    CHECK(!r);
    t_note("unknown location register: last error 0x%lx", GetLastError());
    ds_end();
}
TEST(dxss_regsys_backup_restore_flag_allowed) {
    SETUP(CertRegisterSystemStore); NAME("rs9");
    SET_ERR(0);
    BOOL r = regsys(nm, CERT_STORE_BACKUP_RESTORE_FLAG);
    t_note("register with BACKUP_RESTORE (needs backup privilege): %d err 0x%lx", r, GetLastError());
    if (r) CHECK(ds_key_exists(0, nm, NULL));
    ds_end();
}

/* ---- CertUnregisterSystemStore ---------------------------------------------------------------- */
TEST(dxss_unregsys_removes_key) {
    SETUP(CertUnregisterSystemStore); NAME("us1");
    WINE_SKIP("registration/unregistration/physical store APIs are stubs");
    CHECK(regsys(nm, 0));
    CHECK(unregsys(nm, 0));
    CHECK(!ds_key_exists(0, nm, NULL));
    ds_end();
}
TEST(dxss_unregsys_missing_store_fails_not_found) {
    SETUP(CertUnregisterSystemStore); NAME("us2");
    WINE_SKIP("registration/unregistration/physical store APIs are stubs");
    SET_ERR(0);
    EXPECT_FAIL(!unregsys(nm, 0), ERROR_FILE_NOT_FOUND);
    ds_end();
}
TEST(dxss_unregsys_twice_second_fails) {
    SETUP(CertUnregisterSystemStore); NAME("us3");
    WINE_SKIP("registration/unregistration/physical store APIs are stubs");
    CHECK(regsys(nm, 0));
    CHECK(unregsys(nm, 0));
    SET_ERR(0);
    EXPECT_FAIL(!unregsys(nm, 0), ERROR_FILE_NOT_FOUND);
    ds_end();
}
TEST(dxss_unregsys_deletes_certs_and_crls) {
    SETUP(CertUnregisterSystemStore); NAME("us4");
    WINE_SKIP("registration/unregistration/physical store APIs are stubs");
    HCERTSTORE h = ds_open(nm, 0);
    if (!h) { CHECK(h != NULL); return; }
    DWORD cb; const BYTE *d = ds_crl(&cb);
    for (int i = 0; i < 3; i++) CHECK(ds_add_ok(h, i));
    CHECK(U(CertAddEncodedCRLToStore)(h, X509_ASN_ENCODING, d, cb, CERT_STORE_ADD_NEW, NULL));
    ds_sync(h);
    U(CertCloseStore)(h, 0);
    CHECK(ds_cert_key_exists(0, nm, 0));
    CHECK(unregsys(nm, 0));
    CHECK(!ds_key_exists(0, nm, NULL));
    CHECK(!ds_cert_key_exists(0, nm, 0));
    EXPECT_EQ(ds_count_named(nm, 0, CERT_STORE_OPEN_EXISTING_FLAG), -1);
    EXPECT_EQ(ds_count_named(nm, 0, 0), 0);   /* a plain open re-creates it empty */
    ds_end();
}
TEST(dxss_unregsys_then_open_existing_fails) {
    SETUP(CertUnregisterSystemStore); NAME("us5");
    WINE_SKIP("registration/unregistration/physical store APIs are stubs");
    CHECK(regsys(nm, 0));
    CHECK(unregsys(nm, 0));
    SET_ERR(0);
    HCERTSTORE h = ds_open(nm, CERT_STORE_OPEN_EXISTING_FLAG);
    CHECK(h == NULL);
    EXPECT_ERR(ERROR_FILE_NOT_FOUND);
    if (h) U(CertCloseStore)(h, 0);
    ds_end();
}
TEST(dxss_unregsys_rejected_flags) {
    SETUP(CertUnregisterSystemStore); WINE_SKIP("no flag validation in unregistration");
    static const DWORD bad[] = { CERT_STORE_NO_CRYPT_RELEASE_FLAG, CERT_STORE_SET_LOCALIZED_NAME_FLAG, CERT_STORE_DEFER_CLOSE_UNTIL_LAST_FREE_FLAG,
        CERT_STORE_UNSAFE_PHYSICAL_FLAG, CERT_STORE_SHARE_STORE_FLAG, CERT_STORE_SHARE_CONTEXT_FLAG, CERT_STORE_MANIFOLD_FLAG,
        CERT_STORE_ENUM_ARCHIVED_FLAG, CERT_STORE_UPDATE_KEYID_FLAG, CERT_STORE_MAXIMUM_ALLOWED_FLAG,
        CERT_STORE_CREATE_NEW_FLAG, CERT_STORE_READONLY_FLAG };
    NAME("ur1");
    CHECK(regsys(nm, 0));
    for (unsigned i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        SET_ERR(0);
        BOOL r = unregsys(nm, bad[i]);
        DWORD e = GetLastError();
        CHECKF(!r, "flag 0x%lx accepted", bad[i]);
        CHECKF(e == DS_E_INVALIDARG, "flag 0x%lx: error 0x%lx", bad[i], e);
        CHECKF(ds_key_exists(0, nm, NULL), "flag 0x%lx removed the store", bad[i]);
    }
    ds_end();
}
TEST(dxss_unregsys_null_name_invalid_arg) {
    SETUP(CertUnregisterSystemStore); WINE_SKIP("different error");
    SET_ERR(0);
    EXPECT_FAIL(!U(CertUnregisterSystemStore)(NULL, CU), DS_E_INVALIDARG);
}
TEST(dxss_unregsys_open_existing_flag_allowed) {
    SETUP(CertUnregisterSystemStore); NAME("us6");
    WINE_SKIP("registration/unregistration/physical store APIs are stubs");
    CHECK(regsys(nm, 0));
    CHECK(unregsys(nm, CERT_STORE_OPEN_EXISTING_FLAG));
    CHECK(!ds_key_exists(0, nm, NULL));
    ds_end();
}
TEST(dxss_unregsys_delete_flag_allowed) {
    SETUP(CertUnregisterSystemStore); NAME("us7");
    WINE_SKIP("registration/unregistration/physical store APIs are stubs");
    CHECK(regsys(nm, 0));
    CHECK(unregsys(nm, CERT_STORE_DELETE_FLAG));
    CHECK(!ds_key_exists(0, nm, NULL));
    ds_end();
}
TEST(dxss_unregsys_removes_physical_stores_too) {
    SETUP(CertUnregisterSystemStore); NAME("us8"); NAME2("us8t");
    WINE_SKIP("registration/unregistration/physical store APIs are stubs");
    CHECK(regsys(nm, 0));
    CHECK(regphys(nm, 0, L"p1", (const char *)10, CU, nm2, 0, 1));
    CHECK(ds_key_exists(0, nm, L"PhysicalStores\\p1"));
    CHECK(unregsys(nm, 0));
    CHECK(!ds_key_exists(0, nm, L"PhysicalStores\\p1"));
    CHECK(!ds_key_exists(0, nm, NULL));
    ds_end();
}
TEST(dxss_unregsys_leaves_other_stores) {
    SETUP(CertUnregisterSystemStore); NAME("us9"); NAME2("us9b");
    WINE_SKIP("registration/unregistration/physical store APIs are stubs");
    CHECK(regsys(nm, 0)); CHECK(regsys(nm2, 0));
    CHECK(unregsys(nm, 0));
    CHECK(ds_key_exists(0, nm2, NULL));
    ds_end();
}

/* ---- CertEnumSystemStore ----------------------------------------------------------------------- */
TEST(dxss_enumsys_lists_registered_store) {
    SETUP(CertEnumSystemStore); NAME("es1");
    CHECK(regsys(nm, 0));
    sys_cap_t c; memset(&c, 0, sizeof c); lstrcpyW(c.want, nm);
    SET_ERR(0);
    CHECK(U(CertEnumSystemStore)(CU, NULL, &c, sys_cb));
    EXPECT_EQ(c.found, 1);
    EXPECT_EQ(c.flags & 0xff0000, CU);
    ds_end();
}
TEST(dxss_enumsys_unregistered_store_absent) {
    SETUP(CertEnumSystemStore); NAME("es2");
    WINE_SKIP("registration/unregistration/physical store APIs are stubs");
    CHECK(regsys(nm, 0)); CHECK(unregsys(nm, 0));
    sys_cap_t c; memset(&c, 0, sizeof c); lstrcpyW(c.want, nm);
    CHECK(U(CertEnumSystemStore)(CU, NULL, &c, sys_cb));
    EXPECT_EQ(c.found, 0);
    ds_end();
}
TEST(dxss_enumsys_plain_open_makes_store_visible) {
    SETUP(CertEnumSystemStore); NAME("es3");
    HCERTSTORE h = ds_open(nm, 0);
    if (h) U(CertCloseStore)(h, 0);
    sys_cap_t c; memset(&c, 0, sizeof c); lstrcpyW(c.want, nm);
    CHECK(U(CertEnumSystemStore)(CU, NULL, &c, sys_cb));
    EXPECT_EQ(c.found, 1);
    ds_end();
}
TEST(dxss_enumsys_not_listed_in_local_machine) {
    SETUP(CertEnumSystemStore); NAME("es4");
    CHECK(regsys(nm, 0));
    sys_cap_t c; memset(&c, 0, sizeof c); lstrcpyW(c.want, nm);
    CHECK(U(CertEnumSystemStore)(CERT_SYSTEM_STORE_LOCAL_MACHINE, NULL, &c, sys_cb));
    EXPECT_EQ(c.found, 0);
    ds_end();
}

/* ---- CertRegisterPhysicalStore ----------------------------------------------------------------- */
TEST(dxss_regphys_writes_registry_values) {
    SETUP(CertRegisterPhysicalStore); NAME("rp1"); NAME2("rp1t");
    WINE_SKIP("registration/unregistration/physical store APIs are stubs");
    CHECK(regsys(nm, 0));
    SET_ERR(0);
    CHECK(regphys(nm, 0, L"phys1", (const char *)10, CU | CERT_STORE_OPEN_EXISTING_FLAG, nm2, CERT_PHYSICAL_STORE_ADD_ENABLE_FLAG, 77));
    const wchar_t *sub = L"PhysicalStores\\phys1";
    CHECK(ds_key_exists(0, nm, sub));
    DWORD type = 0, cb, dw;
    wchar_t sz[64]; cb = sizeof sz;
    EXPECT_EQ(ds_reg_value(0, nm, sub, L"OpenStoreProvider", &type, sz, &cb), 0);
    EXPECT_EQ(type, REG_SZ);
    EXPECT_WSTR(sz, L"#10");                      /* numeric provider ids are stored as "#<n>" (wide) */
    cb = 4; EXPECT_EQ(ds_reg_value(0, nm, sub, L"Priority", &type, &dw, &cb), 0); EXPECT_EQ(type, REG_DWORD); EXPECT_EQ(dw, 77);
    cb = 4; EXPECT_EQ(ds_reg_value(0, nm, sub, L"Flags", &type, &dw, &cb), 0); EXPECT_EQ(dw, CERT_PHYSICAL_STORE_ADD_ENABLE_FLAG);
    cb = 4; EXPECT_EQ(ds_reg_value(0, nm, sub, L"OpenFlags", &type, &dw, &cb), 0); EXPECT_EQ(dw, CU | CERT_STORE_OPEN_EXISTING_FLAG);
    cb = 4; EXPECT_EQ(ds_reg_value(0, nm, sub, L"OpenEncodingType", &type, &dw, &cb), 0); EXPECT_EQ(dw, 0);
    wchar_t pb[200]; cb = sizeof pb;
    EXPECT_EQ(ds_reg_value(0, nm, sub, L"OpenParameters", &type, pb, &cb), 0);
    EXPECT_EQ(type, REG_BINARY);
    EXPECT_EQ(cb, (wcslen(nm2) + 1) * 2);
    CHECK(!wcscmp(pb, nm2));
    ds_end();
}
TEST(dxss_regphys_string_provider_stored_verbatim) {
    SETUP(CertRegisterPhysicalStore); NAME("rp2"); NAME2("rp2t");
    WINE_SKIP("registration/unregistration/physical store APIs are stubs");
    CHECK(regsys(nm, 0));
    CHECK(regphys(nm, 0, L"phys1", "System", CU, nm2, 0, 0));
    DWORD type = 0, cb; wchar_t sz[64]; cb = sizeof sz;
    EXPECT_EQ(ds_reg_value(0, nm, L"PhysicalStores\\phys1", L"OpenStoreProvider", &type, sz, &cb), 0);
    EXPECT_EQ(type, REG_SZ);
    EXPECT_WSTR(sz, L"System");
    EXPECT_EQ(cb, 14);
    ds_end();
}
TEST(dxss_regphys_provider_numeric_boundary) {
    SETUP(CertRegisterPhysicalStore); NAME("rp3");
    WINE_SKIP("registration/unregistration/physical store APIs are stubs");
    CHECK(regsys(nm, 0));
    CHECK(regphys(nm, 0, L"a", (const char *)0xFFFF, CU, NULL, 0, 0));      /* < 0x10000: treated as an id */
    DWORD type, cb; wchar_t sz[32]; cb = sizeof sz;
    EXPECT_EQ(ds_reg_value(0, nm, L"PhysicalStores\\a", L"OpenStoreProvider", &type, sz, &cb), 0);
    EXPECT_WSTR(sz, L"#65535");
    ds_end();
}
TEST(dxss_regphys_creates_system_store_if_missing) {
    SETUP(CertRegisterPhysicalStore); NAME("rp4"); NAME2("rp4t");
    WINE_SKIP("registration/unregistration/physical store APIs are stubs");
    CHECK(!ds_key_exists(0, nm, NULL));
    SET_ERR(0);
    CHECK(regphys(nm, 0, L"p", (const char *)10, CU, nm2, 0, 0));
    t_note("RegisterPhysicalStore into a new system store: store key created=%d", ds_key_exists(0, nm, NULL));
    CHECK(ds_key_exists(0, nm, L"PhysicalStores\\p"));
    ds_end();
}
TEST(dxss_regphys_zero_length_params_ok) {
    SETUP(CertRegisterPhysicalStore); NAME("rp5");
    WINE_SKIP("registration/unregistration/physical store APIs are stubs");
    CHECK(regsys(nm, 0));
    CERT_PHYSICAL_STORE_INFO i; memset(&i, 0, sizeof i); i.cbSize = sizeof i; i.pszOpenStoreProvider = (LPSTR)(ULONG_PTR)10;
    CHECK(U(CertRegisterPhysicalStore)((void *)nm, CU, L"empty", &i, NULL));
    DWORD type = 0, cb = 0;
    LONG rc = ds_reg_value(0, nm, L"PhysicalStores\\empty", L"OpenParameters", &type, NULL, &cb);
    EXPECT_EQ(rc, 0); EXPECT_EQ(type, REG_BINARY); EXPECT_EQ(cb, 0);
    ds_end();
}
TEST(dxss_regphys_cbsize_too_small_invalid_arg) {
    SETUP(CertRegisterPhysicalStore); WINE_SKIP("no cbSize validation"); NAME("rp6");
    CHECK(regsys(nm, 0));
    CERT_PHYSICAL_STORE_INFO i; memset(&i, 0, sizeof i); i.pszOpenStoreProvider = (LPSTR)(ULONG_PTR)10;
    for (DWORD cbs = 0; cbs < 0x30; cbs += 0x10 /*0,16,32*/) {
        i.cbSize = cbs;
        SET_ERR(0);
        CHECKF(!U(CertRegisterPhysicalStore)((void *)nm, CU, L"p", &i, NULL), "cbSize %lu accepted", cbs);
        EXPECT_ERR(DS_E_INVALIDARG);
    }
    i.cbSize = 0x2f; SET_ERR(0);
    CHECK(!U(CertRegisterPhysicalStore)((void *)nm, CU, L"p", &i, NULL)); EXPECT_ERR(DS_E_INVALIDARG);
    i.cbSize = 0x30; CHECK(U(CertRegisterPhysicalStore)((void *)nm, CU, L"p", &i, NULL));
    i.cbSize = 0x100; CHECK(U(CertRegisterPhysicalStore)((void *)nm, CU, L"q", &i, NULL));
    ds_end();
}
TEST(dxss_regphys_null_info_invalid_arg) {
    SETUP(CertRegisterPhysicalStore); WINE_SKIP("different error"); NAME("rp7");
    CHECK(regsys(nm, 0));
    SET_ERR(0);
    EXPECT_FAIL(!U(CertRegisterPhysicalStore)((void *)nm, CU, L"p", NULL, NULL), DS_E_INVALIDARG);
    CHECK(!ds_key_exists(0, nm, L"PhysicalStores\\p"));
    ds_end();
}
TEST(dxss_regphys_bad_physical_names_invalid_arg) {
    SETUP(CertRegisterPhysicalStore); WINE_SKIP("different error"); NAME("rp8"); NAME2("rp8t");
    CHECK(regsys(nm, 0));
    static const wchar_t *const bad[] = { NULL, L"", L"a\\b", L"\\", L"x\\" };
    for (unsigned i = 0; i < 5; i++) {
        SET_ERR(0);
        BOOL r = regphys(nm, 0, bad[i], (const char *)10, CU, nm2, 0, 0);
        DWORD e = GetLastError();
        CHECKF(!r, "name %u accepted", i);
        CHECKF(e == DS_E_INVALIDARG, "name %u error 0x%lx", i, e);
    }
    EXPECT_EQ(ds_subkey_count(0, nm, L"PhysicalStores") <= 0, 1);
    ds_end();
}
TEST(dxss_regphys_null_system_store_invalid_arg) {
    SETUP(CertRegisterPhysicalStore); WINE_SKIP("different error"); NAME2("rp9t");
    SET_ERR(0);
    BOOL r = regphys(NULL, 0, L"p", (const char *)10, CU, nm2, 0, 0);
    CHECK(!r); EXPECT_ERR(DS_E_INVALIDARG);
    ds_end();
}
TEST(dxss_regphys_rejected_flags) {
    SETUP(CertRegisterPhysicalStore); WINE_SKIP("no flag validation"); NAME("rpf"); NAME2("rpft");
    CHECK(regsys(nm, 0));
    static const DWORD bad[] = { CERT_STORE_DELETE_FLAG, CERT_STORE_UNSAFE_PHYSICAL_FLAG, CERT_STORE_SHARE_STORE_FLAG, CERT_STORE_ENUM_ARCHIVED_FLAG,
        CERT_STORE_MAXIMUM_ALLOWED_FLAG, CERT_STORE_OPEN_EXISTING_FLAG, CERT_STORE_READONLY_FLAG, CERT_STORE_UPDATE_KEYID_FLAG };
    for (unsigned i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        SET_ERR(0);
        BOOL r = regphys(nm, bad[i], L"p", (const char *)10, CU, nm2, 0, 0);
        DWORD e = GetLastError();
        CHECKF(!r, "flag 0x%lx accepted", bad[i]);
        CHECKF(e == DS_E_INVALIDARG, "flag 0x%lx: error 0x%lx", bad[i], e);
    }
    CHECK(!ds_key_exists(0, nm, L"PhysicalStores\\p"));
    ds_end();
}
TEST(dxss_regphys_create_new_existing_fails) {
    SETUP(CertRegisterPhysicalStore); NAME("rpc"); NAME2("rpct");
    WINE_SKIP("registration/unregistration/physical store APIs are stubs");
    CHECK(regsys(nm, 0));
    CHECK(regphys(nm, CERT_STORE_CREATE_NEW_FLAG, L"p", (const char *)10, CU, nm2, 0, 0));
    SET_ERR(0);
    BOOL r = regphys(nm, CERT_STORE_CREATE_NEW_FLAG, L"p", (const char *)10, CU, nm2, 0, 0);
    CHECK(!r);
    EXPECT_ERR(ERROR_FILE_EXISTS);
    ds_end();
}
TEST(dxss_regphys_twice_overwrites_values) {
    SETUP(CertRegisterPhysicalStore); NAME("rpo"); NAME2("rpot");
    WINE_SKIP("registration/unregistration/physical store APIs are stubs");
    CHECK(regsys(nm, 0));
    CHECK(regphys(nm, 0, L"p", (const char *)10, CU, nm2, 0, 5));
    CHECK(regphys(nm, 0, L"p", (const char *)10, CU, nm2, 0, 9));
    DWORD type, cb = 4, dw = 0;
    EXPECT_EQ(ds_reg_value(0, nm, L"PhysicalStores\\p", L"Priority", &type, &dw, &cb), 0);
    EXPECT_EQ(dw, 9);
    EXPECT_EQ(ds_subkey_count(0, nm, L"PhysicalStores"), 1);
    ds_end();
}
TEST(dxss_regphys_name_case_insensitive_same_key) {
    SETUP(CertRegisterPhysicalStore); NAME("rpn"); NAME2("rpnt");
    WINE_SKIP("registration/unregistration/physical store APIs are stubs");
    CHECK(regsys(nm, 0));
    CHECK(regphys(nm, 0, L"Phys", (const char *)10, CU, nm2, 0, 1));
    CHECK(regphys(nm, 0, L"PHYS", (const char *)10, CU, nm2, 0, 2));
    EXPECT_EQ(ds_subkey_count(0, nm, L"PhysicalStores"), 1);
    ds_end();
}

/* ---- CertEnumPhysicalStore ---------------------------------------------------------------------- */
TEST(dxss_enumphys_plain_store_lists_default) {
    SETUP(CertEnumPhysicalStore); NAME("ep1");
    WINE_SKIP("registration/unregistration/physical store APIs are stubs");
    CHECK(regsys(nm, 0));
    phys_cap_t c; SET_ERR(0);
    CHECK(enum_phys(nm, 0, &c));
    CHECK(phys_index(&c, L".Default") >= 0);
    ds_end();
}
TEST(dxss_enumphys_lists_registered_and_default) {
    SETUP(CertEnumPhysicalStore); NAME("ep2"); NAME2("ep2t");
    WINE_SKIP("registration/unregistration/physical store APIs are stubs");
    CHECK(regsys(nm, 0));
    CHECK(regphys(nm, 0, L"mine", (const char *)10, CU, nm2, 0, 3));
    phys_cap_t c;
    CHECK(enum_phys(nm, 0, &c));
    CHECK(phys_index(&c, L"mine") >= 0);
    CHECK(phys_index(&c, L".Default") >= 0);
    /* Win10 lists the registered store, then the three built-in physical stores of every system store */
    EXPECT_EQ(c.n, 4);
    if (c.n == 4) {
        EXPECT_EQ(phys_index(&c, L"mine"), 0);
        EXPECT_EQ(phys_index(&c, L".Default"), 1);
        EXPECT_EQ(phys_index(&c, L".GroupPolicy"), 2);
        EXPECT_EQ(phys_index(&c, L".LocalMachine"), 3);
    }
    ds_end();
}
TEST(dxss_enumphys_registered_before_default) {
    SETUP(CertEnumPhysicalStore); NAME("ep3"); NAME2("ep3t");
    WINE_SKIP("registration/unregistration/physical store APIs are stubs");
    CHECK(regsys(nm, 0));
    CHECK(regphys(nm, 0, L"mine", (const char *)10, CU, nm2, 0, 3));
    phys_cap_t c;
    CHECK(enum_phys(nm, 0, &c));
    int a = phys_index(&c, L"mine"), d = phys_index(&c, L".Default");
    CHECK(a >= 0 && d >= 0 && a < d);
    ds_end();
}
TEST(dxss_enumphys_priority_descending) {
    SETUP(CertEnumPhysicalStore); NAME("ep4"); NAME2("ep4t");
    WINE_SKIP("registration/unregistration/physical store APIs are stubs");
    CHECK(regsys(nm, 0));
    CHECK(regphys(nm, 0, L"lo", (const char *)10, CU, nm2, 0, 5));
    CHECK(regphys(nm, 0, L"hi", (const char *)10, CU, nm2, 0, 50));
    CHECK(regphys(nm, 0, L"mid", (const char *)10, CU, nm2, 0, 20));
    phys_cap_t c;
    CHECK(enum_phys(nm, 0, &c));
    int hi = phys_index(&c, L"hi"), mid = phys_index(&c, L"mid"), lo = phys_index(&c, L"lo");
    CHECK(hi >= 0 && mid >= 0 && lo >= 0);
    CHECK(hi < mid && mid < lo);
    ds_end();
}
TEST(dxss_enumphys_equal_priority_all_listed) {
    SETUP(CertEnumPhysicalStore); NAME("ep5"); NAME2("ep5t");
    WINE_SKIP("registration/unregistration/physical store APIs are stubs");
    CHECK(regsys(nm, 0));
    for (int i = 0; i < 5; i++) { wchar_t pn[8]; _snwprintf(pn, 8, L"e%d", i); CHECK(regphys(nm, 0, pn, (const char *)10, CU, nm2, 0, 7)); }
    phys_cap_t c;
    CHECK(enum_phys(nm, 0, &c));
    for (int i = 0; i < 5; i++) { wchar_t pn[8]; _snwprintf(pn, 8, L"e%d", i); CHECK(phys_index(&c, pn) >= 0); }
    ds_end();
}
TEST(dxss_enumphys_info_roundtrip_system_string_provider) {
    SETUP(CertEnumPhysicalStore); NAME("ep6"); NAME2("ep6t");
    WINE_SKIP("registration/unregistration/physical store APIs are stubs");
    CHECK(regsys(nm, 0));
    CHECK(regphys(nm, 0, L"rt", "System", CU | CERT_STORE_OPEN_EXISTING_FLAG, nm2, CERT_PHYSICAL_STORE_ADD_ENABLE_FLAG, 42));
    phys_cap_t c;
    CHECK(enum_phys(nm, 0, &c));
    int k = phys_index(&c, L"rt");
    CHECK(k >= 0);
    if (k >= 0) {
        EXPECT_EQ(c.cb[k], sizeof(CERT_PHYSICAL_STORE_INFO));
        EXPECT_EQ(c.prio[k], 42);
        EXPECT_EQ(c.pflags[k], CERT_PHYSICAL_STORE_ADD_ENABLE_FLAG);
        EXPECT_STR(c.prov[k], "System");
        EXPECT_EQ(c.blobcb[k], (wcslen(nm2) + 1) * 2);
        CHECK(!wcscmp(c.blob[k], nm2));
        CHECK((c.openflags[k] & CERT_STORE_OPEN_EXISTING_FLAG) != 0);
    }
    ds_end();
}
TEST(dxss_enumphys_numeric_provider_reported) {
    SETUP(CertEnumPhysicalStore); NAME("ep7"); NAME2("ep7t");
    WINE_SKIP("registration/unregistration/physical store APIs are stubs");
    CHECK(regsys(nm, 0));
    CHECK(regphys(nm, 0, L"num", (const char *)10, CU, nm2, 0, 1));
    phys_cap_t c;
    CHECK(enum_phys(nm, 0, &c));
    int k = phys_index(&c, L"num");
    CHECK(k >= 0);
    if (k >= 0) t_note("numeric provider reported to enum callback as \"%s\"", c.prov[k]);
    ds_end();
}
TEST(dxss_enumphys_unregistered_physical_disappears) {
    SETUP(CertEnumPhysicalStore); NAME("ep8"); NAME2("ep8t");
    WINE_SKIP("registration/unregistration/physical store APIs are stubs");
    CHECK(regsys(nm, 0));
    CHECK(regphys(nm, 0, L"gone", (const char *)10, CU, nm2, 0, 1));
    CHECK(unregphys(nm, 0, L"gone"));
    phys_cap_t c;
    CHECK(enum_phys(nm, 0, &c));
    CHECK(phys_index(&c, L"gone") < 0);
    CHECK(phys_index(&c, L".Default") >= 0);
    ds_end();
}
TEST(dxss_enumphys_missing_store_open_existing_fails) {
    SETUP(CertEnumPhysicalStore); NAME("ep9");
    WINE_SKIP("registration/unregistration/physical store APIs are stubs");
    phys_cap_t c; SET_ERR(0);
    BOOL r = enum_phys(nm, CERT_STORE_OPEN_EXISTING_FLAG, &c);
    /* Win10: enumeration of a missing store succeeds and reports the three built-in physical stores */
    CHECK(r);
    EXPECT_EQ(c.n, 3);
    CHECK(phys_index(&c, L".Default") >= 0);
    CHECK(phys_index(&c, L".GroupPolicy") >= 0);
    CHECK(phys_index(&c, L".LocalMachine") >= 0);
    CHECK(!ds_key_exists(0, nm, NULL));
    ds_end();
}
TEST(dxss_enumphys_invalid_flags_rejected) {
    SETUP(CertEnumPhysicalStore); NAME("epa");
    WINE_SKIP("registration/unregistration/physical store APIs are stubs");
    CHECK(regsys(nm, 0));
    static const DWORD bad[] = { CERT_STORE_CREATE_NEW_FLAG, CERT_STORE_ENUM_ARCHIVED_FLAG, CERT_STORE_UPDATE_KEYID_FLAG, CERT_STORE_MANIFOLD_FLAG };
    for (unsigned i = 0; i < 4; i++) {
        phys_cap_t c; SET_ERR(0);
        BOOL r = enum_phys(nm, bad[i], &c);
        t_note("EnumPhysicalStore flag 0x%lx: %d err 0x%lx", bad[i], r, GetLastError());
        if (!t_is_wine()) CHECKF(!r, "flag 0x%lx accepted", bad[i]);
    }
    ds_end();
}

/* ---- CertUnregisterPhysicalStore ---------------------------------------------------------------- */
TEST(dxss_unregphys_removes_key) {
    SETUP(CertUnregisterPhysicalStore); NAME("up1"); NAME2("up1t");
    WINE_SKIP("registration/unregistration/physical store APIs are stubs");
    CHECK(regsys(nm, 0));
    CHECK(regphys(nm, 0, L"p", (const char *)10, CU, nm2, 0, 1));
    CHECK(ds_key_exists(0, nm, L"PhysicalStores\\p"));
    SET_ERR(0);
    CHECK(unregphys(nm, 0, L"p"));
    CHECK(!ds_key_exists(0, nm, L"PhysicalStores\\p"));
    CHECK(ds_key_exists(0, nm, NULL));
    ds_end();
}
TEST(dxss_unregphys_missing_name_fails_not_found) {
    SETUP(CertUnregisterPhysicalStore); NAME("up2");
    WINE_SKIP("registration/unregistration/physical store APIs are stubs");
    CHECK(regsys(nm, 0));
    SET_ERR(0);
    EXPECT_FAIL(!unregphys(nm, 0, L"nosuch"), ERROR_FILE_NOT_FOUND);
    ds_end();
}
TEST(dxss_unregphys_twice_second_fails) {
    SETUP(CertUnregisterPhysicalStore); NAME("up3"); NAME2("up3t");
    WINE_SKIP("registration/unregistration/physical store APIs are stubs");
    CHECK(regsys(nm, 0));
    CHECK(regphys(nm, 0, L"p", (const char *)10, CU, nm2, 0, 1));
    CHECK(unregphys(nm, 0, L"p"));
    SET_ERR(0);
    EXPECT_FAIL(!unregphys(nm, 0, L"p"), ERROR_FILE_NOT_FOUND);
    ds_end();
}
TEST(dxss_unregphys_default_cannot_be_removed) {
    SETUP(CertUnregisterPhysicalStore); NAME("up4");
    WINE_SKIP("registration/unregistration/physical store APIs are stubs");
    HCERTSTORE h = ds_open(nm, 0);
    if (h) { CHECK(ds_add_ok(h, 0)); U(CertCloseStore)(h, 0); }
    SET_ERR(0);
    BOOL r = unregphys(nm, 0, L".Default");
    DWORD e = GetLastError();
    CHECK(!r);                           /* .Default is implicit: there is no registry key to delete */
    EXPECT_EQ(e, ERROR_FILE_NOT_FOUND);
    EXPECT_EQ(ds_stored(nm, 0, 0), 1);   /* and the store's own certificates are untouched */
    phys_cap_t c;
    CHECK(enum_phys(nm, 0, &c));
    CHECK(phys_index(&c, L".Default") >= 0);
    ds_end();
}
TEST(dxss_unregphys_rejected_flags) {
    SETUP(CertUnregisterPhysicalStore); WINE_SKIP("no flag validation"); NAME("up5"); NAME2("up5t");
    CHECK(regsys(nm, 0));
    CHECK(regphys(nm, 0, L"p", (const char *)10, CU, nm2, 0, 1));
    static const DWORD bad[] = { CERT_STORE_CREATE_NEW_FLAG, CERT_STORE_READONLY_FLAG, CERT_STORE_MAXIMUM_ALLOWED_FLAG, CERT_STORE_SHARE_STORE_FLAG, CERT_STORE_ENUM_ARCHIVED_FLAG };
    for (unsigned i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        SET_ERR(0);
        BOOL r = unregphys(nm, bad[i], L"p");
        DWORD e = GetLastError();
        CHECKF(!r, "flag 0x%lx accepted", bad[i]);
        CHECKF(e == DS_E_INVALIDARG, "flag 0x%lx: error 0x%lx", bad[i], e);
    }
    CHECK(ds_key_exists(0, nm, L"PhysicalStores\\p"));
    ds_end();
}
TEST(dxss_unregphys_open_existing_flag_allowed) {
    SETUP(CertUnregisterPhysicalStore); NAME("up6"); NAME2("up6t");
    WINE_SKIP("registration/unregistration/physical store APIs are stubs");
    CHECK(regsys(nm, 0));
    CHECK(regphys(nm, 0, L"p", (const char *)10, CU, nm2, 0, 1));
    CHECK(unregphys(nm, CERT_STORE_OPEN_EXISTING_FLAG, L"p"));
    CHECK(!ds_key_exists(0, nm, L"PhysicalStores\\p"));
    ds_end();
}
TEST(dxss_unregphys_null_system_store_invalid_arg) {
    SETUP(CertUnregisterPhysicalStore); WINE_SKIP("different error");
    SET_ERR(0);
    EXPECT_FAIL(!unregphys(NULL, 0, L"p"), DS_E_INVALIDARG);
}
TEST(dxss_unregphys_other_physical_kept) {
    SETUP(CertUnregisterPhysicalStore); NAME("up7"); NAME2("up7t");
    WINE_SKIP("registration/unregistration/physical store APIs are stubs");
    CHECK(regsys(nm, 0));
    CHECK(regphys(nm, 0, L"a", (const char *)10, CU, nm2, 0, 1));
    CHECK(regphys(nm, 0, L"b", (const char *)10, CU, nm2, 0, 2));
    CHECK(unregphys(nm, 0, L"a"));
    CHECK(ds_key_exists(0, nm, L"PhysicalStores\\b"));
    ds_end();
}

/* ---- physical stores shape the collection that CertOpenStore returns ------------------------------ */
static HCERTSTORE mkstore_with(const wchar_t *n, int cert) {
    HCERTSTORE h = ds_open(n, 0);
    if (h) { ds_add_ok(h, cert); ds_sync(h); }
    return h;
}
TEST(dxss_collection_includes_linked_physical_store) {
    SETUP(CertOpenStore); NAME("co1"); NAME2("co1t");
    WINE_SKIP("registration/unregistration/physical store APIs are stubs");
    HCERTSTORE t = mkstore_with(nm2, 1);
    if (t) U(CertCloseStore)(t, 0);
    CHECK(regsys(nm, 0));
    CHECK(regphys(nm, 0, L"link", (const char *)10, CU, nm2, 0, 10));
    HCERTSTORE h = ds_open(nm, 0);
    CHECK(h != NULL);
    if (h) {
        PCCERT_CONTEXT c = ds_find(h, 1);
        CHECK(c != NULL);
        if (c) U(CertFreeCertificateContext)(c);
        U(CertCloseStore)(h, 0);
    }
    ds_end();
}
TEST(dxss_collection_includes_default_and_linked) {
    SETUP(CertOpenStore); NAME("co2"); NAME2("co2t");
    WINE_SKIP("registration/unregistration/physical store APIs are stubs");
    HCERTSTORE t = mkstore_with(nm2, 1);
    if (t) U(CertCloseStore)(t, 0);
    CHECK(regsys(nm, 0));
    HCERTSTORE own = mkstore_with(nm, 0);
    if (own) U(CertCloseStore)(own, 0);
    CHECK(regphys(nm, 0, L"link", (const char *)10, CU, nm2, 0, 10));
    HCERTSTORE h = ds_open(nm, 0);
    CHECK(h != NULL);
    if (h) {
        EXPECT_EQ(ds_count(h), 2);
        PCCERT_CONTEXT a = ds_find(h, 0), b = ds_find(h, 1);
        CHECK(a != NULL && b != NULL);
        if (a) U(CertFreeCertificateContext)(a);
        if (b) U(CertFreeCertificateContext)(b);
        U(CertCloseStore)(h, 0);
    }
    ds_end();
}
TEST(dxss_collection_priority_orders_enumeration) {
    SETUP(CertOpenStore); NAME("co3"); NAME2("co3a"); wchar_t nm3[120]; ds_name(nm3, 120, "co3b");
    WINE_SKIP("registration/unregistration/physical store APIs are stubs");
    HCERTSTORE a = mkstore_with(nm2, 1); if (a) U(CertCloseStore)(a, 0);
    HCERTSTORE b = mkstore_with(nm3, 2); if (b) U(CertCloseStore)(b, 0);
    CHECK(regsys(nm, 0));
    CHECK(regphys(nm, 0, L"low", (const char *)10, CU, nm2, 0, 10));
    CHECK(regphys(nm, 0, L"high", (const char *)10, CU, nm3, 0, 200));
    HCERTSTORE h = ds_open(nm, 0);
    CHECK(h != NULL);
    if (h) {
        PCCERT_CONTEXT first = U(CertEnumCertificatesInStore)(h, NULL);
        CHECK(first != NULL);
        if (first) {
            DWORD cb; const BYTE *d2 = ds_der(2, &cb);
            CHECK(first->cbCertEncoded == cb && !memcmp(first->pbCertEncoded, d2, cb));   /* higher priority store first */
            U(CertFreeCertificateContext)(first);
        }
        U(CertCloseStore)(h, 0);
    }
    ds_end();
}
TEST(dxss_collection_open_disable_flag_hides_store) {
    SETUP(CertOpenStore); NAME("co4"); NAME2("co4t");
    WINE_SKIP("registration/unregistration/physical store APIs are stubs");
    HCERTSTORE t = mkstore_with(nm2, 1); if (t) U(CertCloseStore)(t, 0);
    CHECK(regsys(nm, 0));
    CHECK(regphys(nm, 0, L"link", (const char *)10, CU, nm2, CERT_PHYSICAL_STORE_OPEN_DISABLE_FLAG, 10));
    HCERTSTORE h = ds_open(nm, 0);
    CHECK(h != NULL);
    if (h) { EXPECT_EQ(ds_count(h), 0); U(CertCloseStore)(h, 0); }
    ds_end();
}
TEST(dxss_collection_add_enable_routes_new_certs_to_linked_store) {
    SETUP(CertOpenStore); NAME("co5"); NAME2("co5t");
    WINE_SKIP("registration/unregistration/physical store APIs are stubs");
    HCERTSTORE t = ds_open(nm2, 0); if (t) U(CertCloseStore)(t, 0);
    CHECK(regsys(nm, 0));
    CHECK(regphys(nm, 0, L"link", (const char *)10, CU, nm2, CERT_PHYSICAL_STORE_ADD_ENABLE_FLAG, 100));
    HCERTSTORE h = ds_open(nm, 0);
    CHECK(h != NULL);
    if (h) { CHECK(ds_add_ok(h, 3)); ds_sync(h); U(CertCloseStore)(h, 0); }
    EXPECT_EQ(ds_stored(nm2, 0, 3), 1);
    ds_end();
}
TEST(dxss_collection_without_add_enable_adds_go_to_default) {
    SETUP(CertOpenStore); NAME("co6"); NAME2("co6t");
    WINE_SKIP("registration/unregistration/physical store APIs are stubs");
    HCERTSTORE t = ds_open(nm2, 0); if (t) U(CertCloseStore)(t, 0);
    CHECK(regsys(nm, 0));
    CHECK(regphys(nm, 0, L"link", (const char *)10, CU, nm2, 0, 100));
    HCERTSTORE h = ds_open(nm, 0);
    CHECK(h != NULL);
    if (h) { CHECK(ds_add_ok(h, 3)); ds_sync(h); U(CertCloseStore)(h, 0); }
    EXPECT_EQ(ds_stored(nm2, 0, 3), 0);
    CHECK(ds_cert_key_exists(0, nm, 3));
    ds_end();
}
TEST(dxss_collection_unregistered_physical_no_longer_visible) {
    SETUP(CertOpenStore); NAME("co7"); NAME2("co7t");
    WINE_SKIP("registration/unregistration/physical store APIs are stubs");
    HCERTSTORE t = mkstore_with(nm2, 1); if (t) U(CertCloseStore)(t, 0);
    CHECK(regsys(nm, 0));
    CHECK(regphys(nm, 0, L"link", (const char *)10, CU, nm2, 0, 10));
    CHECK(unregphys(nm, 0, L"link"));
    EXPECT_EQ(ds_count_named(nm, 0, 0), 0);
    EXPECT_EQ(ds_stored(nm2, 0, 1), 1);   /* the target store itself is untouched */
    ds_end();
}
TEST(dxss_collection_delete_cert_from_linked_store_updates_target) {
    SETUP(CertOpenStore); NAME("co8"); NAME2("co8t");
    WINE_SKIP("registration/unregistration/physical store APIs are stubs");
    HCERTSTORE t = mkstore_with(nm2, 1); if (t) U(CertCloseStore)(t, 0);
    CHECK(regsys(nm, 0));
    CHECK(regphys(nm, 0, L"link", (const char *)10, CU, nm2, CERT_PHYSICAL_STORE_ADD_ENABLE_FLAG, 10));
    HCERTSTORE h = ds_open(nm, 0);
    PCCERT_CONTEXT c = h ? ds_find(h, 1) : NULL;
    CHECK(c != NULL);
    if (c) ds_del(c);
    if (h) U(CertCloseStore)(h, 0);
    EXPECT_EQ(ds_stored(nm2, 0, 1), 0);
    ds_end();
}

/* ---- local machine (elevated only) ------------------------------------------------------------------- */
TEST(dxss_lm_register_unregister_system_store) {
    SETUP_LM(CertRegisterSystemStore); NAME("lr1");
    WINE_SKIP("machine stores live elsewhere");
    DWORD L = CERT_SYSTEM_STORE_LOCAL_MACHINE;
    CHECK(U(CertRegisterSystemStore)((void *)nm, L, NULL, NULL));
    CHECK(ds_key_exists(L, nm, NULL));
    CHECK(!ds_key_exists(0, nm, NULL));
    CHECK(U(CertUnregisterSystemStore)((void *)nm, L));
    CHECK(!ds_key_exists(L, nm, NULL));
    ds_end();
}
TEST(dxss_lm_register_physical_store) {
    SETUP_LM(CertRegisterPhysicalStore); NAME("lr2"); NAME2("lr2t");
    WINE_SKIP("machine stores live elsewhere");
    DWORD L = CERT_SYSTEM_STORE_LOCAL_MACHINE;
    CHECK(U(CertRegisterSystemStore)((void *)nm, L, NULL, NULL));
    CERT_PHYSICAL_STORE_INFO i; memset(&i, 0, sizeof i); i.cbSize = sizeof i; i.pszOpenStoreProvider = (LPSTR)(ULONG_PTR)10;
    i.dwOpenFlags = L; i.OpenParameters.pbData = (BYTE *)nm2; i.OpenParameters.cbData = (DWORD)((wcslen(nm2) + 1) * 2); i.dwPriority = 4;
    CHECK(U(CertRegisterPhysicalStore)((void *)nm, L, L"p", &i, NULL));
    CHECK(ds_key_exists(L, nm, L"PhysicalStores\\p"));
    CHECK(U(CertUnregisterPhysicalStore)((void *)nm, L, L"p"));
    CHECK(!ds_key_exists(L, nm, L"PhysicalStores\\p"));
    ds_end();
}
