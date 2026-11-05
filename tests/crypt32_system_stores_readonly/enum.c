#include "sss.h"
/* CertEnumSystemStoreLocation / CertEnumSystemStore / CertEnumPhysicalStore: read-only enumeration. */

TEST(sss_loc_enum_basic) {
    REQUIRE(U(CertEnumSystemStoreLocation));
    sss_cap_t c; memset(&c, 0, sizeof c);
    SET_ERR(0);
    CHECK(U(CertEnumSystemStoreLocation)(0, &c, sss_cb_loc));
    CHECK(c.n >= 8);
    t_note("locations enumerated: %d", c.n);
    for (int i = 0; i < c.n && i < 64; i++) t_note("  loc[%d] \"%ls\" flags=0x%08lx", i, c.names[i], c.flags[i]);
}
TEST(sss_loc_enum_fixed_order_and_flags) {
    REQUIRE(U(CertEnumSystemStoreLocation));
    sss_cap_t c; memset(&c, 0, sizeof c);
    CHECK(U(CertEnumSystemStoreLocation)(0, &c, sss_cb_loc));
    for (unsigned i = 0; i < SSS_NLOCS && i < (unsigned)c.n; i++) {
        CHECKF(!lstrcmpW(c.names[i], sss_locs[i].name), "idx %u got %ls want %ls", i, c.names[i], sss_locs[i].name);
        EXPECT_EQ(c.flags[i], sss_locs[i].flag);
    }
}
TEST(sss_loc_enum_reserved_null) {
    REQUIRE(U(CertEnumSystemStoreLocation));
    sss_cap_t c; memset(&c, 0, sizeof c);
    CHECK(U(CertEnumSystemStoreLocation)(0, &c, sss_cb_loc));
    EXPECT_EQ(c.resv_nonnull, 0);
}
TEST(sss_loc_enum_arg_passthrough) {
    REQUIRE(U(CertEnumSystemStoreLocation));
    sss_cap_t c; memset(&c, 0, sizeof c);
    c.stop_after = 1;
    U(CertEnumSystemStoreLocation)(0, &c, sss_cb_loc);
    EXPECT_EQ(c.n, 1);   /* callback saw our own pvArg (it incremented our struct) */
}
TEST(sss_loc_enum_callback_false_stops) {
    REQUIRE(U(CertEnumSystemStoreLocation));
    for (int stop = 1; stop <= 3; stop++) {
        sss_cap_t c; memset(&c, 0, sizeof c); c.stop_after = stop;
        BOOL r = U(CertEnumSystemStoreLocation)(0, &c, sss_cb_loc);
        CHECKF(!r, "stop=%d returned TRUE", stop);
        EXPECT_EQ(c.n, stop);
    }
}
TEST(sss_loc_enum_invalid_flag_bits) {
    REQUIRE(U(CertEnumSystemStoreLocation));
    static const DWORD bits[] = { 0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x100, 0x200, 0x400, 0x2000, 0x273f };
    for (unsigned i = 0; i < sizeof bits / sizeof bits[0]; i++) {
        sss_cap_t c; memset(&c, 0, sizeof c);
        SET_ERR(0);
        BOOL r = U(CertEnumSystemStoreLocation)(bits[i], &c, sss_cb_loc);
        CHECKF(!r, "flags 0x%lx succeeded", bits[i]);
        EXPECT_ERR(SSS_E_INVALIDARG);
        EXPECT_EQ(c.n, 0);
    }
}
TEST(sss_loc_enum_high_flags_ignored_or_valid) {
    REQUIRE(U(CertEnumSystemStoreLocation));
    sss_cap_t c; memset(&c, 0, sizeof c);
    BOOL r = U(CertEnumSystemStoreLocation)(0x00010000, &c, sss_cb_loc);
    t_note("flags 0x10000 -> %d n=%d gle=%lu", r, c.n, GetLastError());
}

/* ---- CertEnumSystemStore ---- */
TEST(sss_store_enum_each_location) {
    REQUIRE(U(CertEnumSystemStore));
    for (unsigned i = 0; i < SSS_NLOCS; i++) {
        sss_cap_t c; memset(&c, 0, sizeof c);
        SET_ERR(0);
        BOOL r = U(CertEnumSystemStore)(sss_locs[i].flag, NULL, &c, sss_cb_store);
        t_note("%ls: ret=%d n=%d gle=%lu", sss_locs[i].name, r, c.n, GetLastError());
        for (int k = 0; k < c.n && k < 64; k++) t_note("    %ls (flags 0x%lx)", c.names[k], c.flags[k]);
    }
}
static void store_present(DWORD loc, const wchar_t *locname, const wchar_t *const *names, int nn) {
    sss_cap_t c; memset(&c, 0, sizeof c);
    BOOL r = U(CertEnumSystemStore)(loc, NULL, &c, sss_cb_store);
    CHECKF(r, "enum %ls failed gle=%lu", locname, GetLastError());
    for (int i = 0; i < nn; i++)
        CHECKF(sss_has(&c, names[i]), "%ls: store %ls missing", locname, names[i]);
}
TEST(sss_store_enum_current_user_standard_names) {
    REQUIRE(U(CertEnumSystemStore));
    static const wchar_t *n[] = { L"My", L"Root", L"CA" };
    store_present(CERT_SYSTEM_STORE_CURRENT_USER, L"CurrentUser", n, 3);
}
TEST(sss_store_enum_local_machine_standard_names) {
    REQUIRE(U(CertEnumSystemStore));
    static const wchar_t *n[] = { L"My", L"Root", L"CA" };
    store_present(CERT_SYSTEM_STORE_LOCAL_MACHINE, L"LocalMachine", n, 3);
}
TEST(sss_store_enum_optional_names_note) {
    REQUIRE(U(CertEnumSystemStore));
    static const wchar_t *n[] = { L"AuthRoot", L"TrustedPublisher", L"Disallowed", L"TrustedPeople", L"Trust", L"ClientAuthIssuer", L"SmartCardRoot", L"UserDS" };
    DWORD locs[2] = { CERT_SYSTEM_STORE_CURRENT_USER, CERT_SYSTEM_STORE_LOCAL_MACHINE };
    for (int l = 0; l < 2; l++) {
        sss_cap_t c; memset(&c, 0, sizeof c);
        U(CertEnumSystemStore)(locs[l], NULL, &c, sss_cb_store);
        for (unsigned i = 0; i < sizeof n / sizeof n[0]; i++) t_note("loc %d store %ls present=%d", l, n[i], sss_has(&c, n[i]));
    }
}
TEST(sss_store_enum_callback_flags_are_location_only) {
    REQUIRE(U(CertEnumSystemStore));
    DWORD locs[2] = { CERT_SYSTEM_STORE_CURRENT_USER, CERT_SYSTEM_STORE_LOCAL_MACHINE };
    for (int l = 0; l < 2; l++) {
        sss_cap_t c; memset(&c, 0, sizeof c);
        CHECK(U(CertEnumSystemStore)(locs[l], NULL, &c, sss_cb_store));
        CHECK(c.n > 0);
        for (int i = 0; i < c.n && i < 64; i++) EXPECT_EQ(c.flags[i], locs[l]);
    }
}
TEST(sss_store_enum_callback_args) {
    REQUIRE(U(CertEnumSystemStore));
    sss_cap_t c; memset(&c, 0, sizeof c);
    CHECK(U(CertEnumSystemStore)(CERT_SYSTEM_STORE_CURRENT_USER, NULL, &c, sss_cb_store));
    EXPECT_EQ(c.resv_nonnull, 0);
    CHECK(!c.info_null);
    t_note("pStoreInfo->cbSize=%lu (sizeof=%zu)", c.info_cb0, sizeof(CERT_SYSTEM_STORE_INFO));
}
TEST(sss_store_enum_names_unique) {
    REQUIRE(U(CertEnumSystemStore));
    sss_cap_t c; memset(&c, 0, sizeof c);
    CHECK(U(CertEnumSystemStore)(CERT_SYSTEM_STORE_CURRENT_USER, NULL, &c, sss_cb_store));
    int m = c.n < 64 ? c.n : 64;
    for (int i = 0; i < m; i++)
        for (int j = i + 1; j < m; j++)
            CHECKF(lstrcmpiW(c.names[i], c.names[j]) != 0, "duplicate store name %ls", c.names[i]);
}
TEST(sss_store_enum_callback_false_stops) {
    REQUIRE(U(CertEnumSystemStore));
    sss_cap_t c; memset(&c, 0, sizeof c); c.stop_after = 1;
    BOOL r = U(CertEnumSystemStore)(CERT_SYSTEM_STORE_CURRENT_USER, NULL, &c, sss_cb_store);
    CHECK(!r);
    EXPECT_EQ(c.n, 1);
}
TEST(sss_store_enum_all_enumerated_names_openable) {
    REQUIRE(U(CertEnumSystemStore)); REQUIRE(U(CertOpenStore)); REQUIRE(U(CertCloseStore));
    sss_cap_t c; memset(&c, 0, sizeof c);
    CHECK(U(CertEnumSystemStore)(CERT_SYSTEM_STORE_CURRENT_USER, NULL, &c, sss_cb_store));
    int m = c.n < 64 ? c.n : 64;
    for (int i = 0; i < m; i++) {
        HCERTSTORE h = U(CertOpenStore)(CERT_STORE_PROV_SYSTEM_W, 0, 0,
            CERT_SYSTEM_STORE_CURRENT_USER | CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG, c.names[i]);
        DWORD e = GetLastError();
        t_note("open existing %ls -> %p (gle=%lu)", c.names[i], h, h ? 0 : e);
        if (h) U(CertCloseStore)(h, 0);
    }
}
TEST(sss_store_enum_invalid_flag_bits_note) {
    REQUIRE(U(CertEnumSystemStore));
    static const DWORD bits[] = { 0x1, 0x2, 0x4, 0x10, 0x100, 0x200, 0x2000 };
    for (unsigned i = 0; i < sizeof bits / sizeof bits[0]; i++) {
        sss_cap_t c; memset(&c, 0, sizeof c);
        SET_ERR(0);
        BOOL r = U(CertEnumSystemStore)(CERT_SYSTEM_STORE_CURRENT_USER | bits[i], NULL, &c, sss_cb_store);
        t_note("flags CU|0x%lx -> %d n=%d gle=0x%lx", bits[i], r, c.n, GetLastError());
    }
}
TEST(sss_store_enum_unknown_location_fails) {
    REQUIRE(U(CertEnumSystemStore));
    sss_cap_t c; memset(&c, 0, sizeof c);
    SET_ERR(0);
    BOOL r = U(CertEnumSystemStore)(SSS_LOC(0xF0), NULL, &c, sss_cb_store);
    CHECK(!r);
    EXPECT_EQ(c.n, 0);
    t_note("unknown location id 0xF0 gle=%lu", GetLastError());
}
TEST(sss_store_enum_current_service_without_para_note) {
    REQUIRE(U(CertEnumSystemStore));
    sss_cap_t c; memset(&c, 0, sizeof c);
    SET_ERR(0);
    BOOL r = U(CertEnumSystemStore)(CERT_SYSTEM_STORE_CURRENT_SERVICE, NULL, &c, sss_cb_store);
    t_note("CURRENT_SERVICE NULL para -> %d n=%d gle=0x%lx", r, c.n, GetLastError());
}
TEST(sss_store_enum_services_users_note) {
    REQUIRE(U(CertEnumSystemStore));
    DWORD f[2] = { CERT_SYSTEM_STORE_SERVICES, CERT_SYSTEM_STORE_USERS };
    for (int i = 0; i < 2; i++) {
        sss_cap_t c; memset(&c, 0, sizeof c);
        BOOL r = U(CertEnumSystemStore)(f[i], NULL, &c, sss_cb_store);
        t_note("loc 0x%lx -> %d n=%d", f[i], r, c.n);
        for (int k = 0; k < c.n && k < 8; k++) t_note("   %ls", c.names[k]);
    }
}
TEST(sss_store_enum_policy_and_enterprise_note) {
    REQUIRE(U(CertEnumSystemStore));
    DWORD f[3] = { CERT_SYSTEM_STORE_CURRENT_USER_GROUP_POLICY, CERT_SYSTEM_STORE_LOCAL_MACHINE_GROUP_POLICY, CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE };
    for (int i = 0; i < 3; i++) {
        sss_cap_t c; memset(&c, 0, sizeof c);
        BOOL r = U(CertEnumSystemStore)(f[i], NULL, &c, sss_cb_store);
        t_note("loc 0x%lx -> %d n=%d gle=%lu", f[i], r, c.n, GetLastError());
    }
}
TEST(sss_store_enum_relocate_hkcu_base_note) {
    REQUIRE(U(CertEnumSystemStore));
    CERT_SYSTEM_STORE_RELOCATE_PARA p; memset(&p, 0, sizeof p);
    p.hKeyBase = HKEY_CURRENT_USER; p.pvSystemStore = L"Root";
    sss_cap_t c; memset(&c, 0, sizeof c);
    SET_ERR(0);
    BOOL r = U(CertEnumSystemStore)(CERT_SYSTEM_STORE_CURRENT_USER | CERT_SYSTEM_STORE_RELOCATE_FLAG, &p, &c, sss_cb_store);
    t_note("relocate enum -> %d n=%d gle=%lu", r, c.n, GetLastError());
}
TEST(sss_store_enum_relocate_null_para_fails) {
    REQUIRE(U(CertEnumSystemStore));
    sss_cap_t c; memset(&c, 0, sizeof c);
    SET_ERR(0);
    BOOL r = U(CertEnumSystemStore)(CERT_SYSTEM_STORE_CURRENT_USER | CERT_SYSTEM_STORE_RELOCATE_FLAG, NULL, &c, sss_cb_store);
    t_note("relocate NULL para -> %d n=%d gle=0x%lx", r, c.n, GetLastError());
}

/* ---- CertEnumPhysicalStore ---- */
typedef struct { const wchar_t *name; DWORD loc; } sss_phys_in;
static void phys_enum(DWORD loc, const wchar_t *store, sss_cap_t *c, BOOL *ret) {
    memset(c, 0, sizeof *c);
    *ret = U(CertEnumPhysicalStore)(store, loc, c, sss_cb_phys);
}
TEST(sss_phys_enum_has_default) {
    REQUIRE(U(CertEnumPhysicalStore));
    if (t_is_wine()) { t_skip("emulator lacks physical store enumeration"); return; }
    static const wchar_t *stores[] = { L"My", L"Root", L"CA" };
    DWORD locs[2] = { CERT_SYSTEM_STORE_CURRENT_USER, CERT_SYSTEM_STORE_LOCAL_MACHINE };
    for (int l = 0; l < 2; l++)
        for (int s = 0; s < 3; s++) {
            sss_cap_t c; BOOL r;
            phys_enum(locs[l], stores[s], &c, &r);
            CHECKF(r, "loc %d %ls failed gle=%lu", l, stores[s], GetLastError());
            CHECKF(sss_has(&c, L".Default"), "loc %d %ls lacks .Default", l, stores[s]);
        }
}
TEST(sss_phys_enum_report_names) {
    REQUIRE(U(CertEnumPhysicalStore));
    static const wchar_t *stores[] = { L"My", L"Root", L"CA", L"TrustedPublisher", L"Disallowed", L"AuthRoot" };
    DWORD locs[2] = { CERT_SYSTEM_STORE_CURRENT_USER, CERT_SYSTEM_STORE_LOCAL_MACHINE };
    for (int l = 0; l < 2; l++)
        for (int s = 0; s < 6; s++) {
            sss_cap_t c; BOOL r;
            phys_enum(locs[l], stores[s], &c, &r);
            t_note("loc %d %ls -> %d n=%d", l, stores[s], r, c.n);
            for (int k = 0; k < c.n && k < 16; k++) t_note("    %ls", c.names[k]);
        }
}
TEST(sss_phys_enum_callback_args) {
    REQUIRE(U(CertEnumPhysicalStore));
    if (t_is_wine()) { t_skip("emulator lacks physical store enumeration"); return; }
    sss_cap_t c; BOOL r;
    phys_enum(CERT_SYSTEM_STORE_CURRENT_USER, L"Root", &c, &r);
    CHECK(r);
    EXPECT_EQ(c.resv_nonnull, 0);
    CHECK(!c.info_null);
    EXPECT_EQ(c.info_cb0, sizeof(CERT_PHYSICAL_STORE_INFO));
    for (int i = 0; i < c.n && i < 64; i++) EXPECT_EQ(c.flags[i], CERT_SYSTEM_STORE_CURRENT_USER);
}
TEST(sss_phys_enum_callback_false_stops) {
    REQUIRE(U(CertEnumPhysicalStore));
    if (t_is_wine()) { t_skip("emulator lacks physical store enumeration"); return; }
    sss_cap_t c; memset(&c, 0, sizeof c); c.stop_after = 1;
    BOOL r = U(CertEnumPhysicalStore)(L"Root", CERT_SYSTEM_STORE_CURRENT_USER, &c, sss_cb_phys);
    CHECK(!r);
    EXPECT_EQ(c.n, 1);
}
static BOOL WINAPI sss_cb_info(const void *s, DWORD f, LPCWSTR n, PCERT_PHYSICAL_STORE_INFO i, void *r, void *a) {
    if (!lstrcmpiW(n, L".Default") && i)
        t_note(".Default: provider=%s flags=0x%lx openflags=0x%lx", i->pszOpenStoreProvider ? i->pszOpenStoreProvider : "(null)", i->dwFlags, i->dwOpenFlags);
    return TRUE;
}
TEST(sss_phys_enum_default_info_note) {
    REQUIRE(U(CertEnumPhysicalStore));
    U(CertEnumPhysicalStore)(L"Root", CERT_SYSTEM_STORE_CURRENT_USER, NULL, sss_cb_info);
}
TEST(sss_phys_enum_nonexistent_store_note) {
    REQUIRE(U(CertEnumPhysicalStore));
    wchar_t nm[64]; sss_wuniq(nm, 64, L"nophys");
    sss_cap_t c; BOOL r;
    SET_ERR(0);
    phys_enum(CERT_SYSTEM_STORE_CURRENT_USER, nm, &c, &r);
    t_note("nonexistent physical enum -> %d n=%d gle=%lu", r, c.n, GetLastError());
}
TEST(sss_phys_enum_invalid_flag_bits_note) {
    REQUIRE(U(CertEnumPhysicalStore));
    static const DWORD bits[] = { 0x1, 0x2, 0x4, 0x10, 0x100, 0x200, 0x2000 };
    for (unsigned i = 0; i < sizeof bits / sizeof bits[0]; i++) {
        sss_cap_t c; BOOL r;
        SET_ERR(0);
        phys_enum(CERT_SYSTEM_STORE_CURRENT_USER | bits[i], L"Root", &c, &r);
        t_note("phys flags CU|0x%lx -> %d n=%d gle=0x%lx", bits[i], r, c.n, GetLastError());
    }
}
TEST(sss_phys_enum_unknown_location_note) {
    REQUIRE(U(CertEnumPhysicalStore));
    sss_cap_t c; BOOL r;
    SET_ERR(0);
    phys_enum(SSS_LOC(0xF0), L"Root", &c, &r);
    CHECK(!r);
    t_note("phys unknown loc gle=0x%lx", GetLastError());
}
TEST(sss_phys_enum_services_current_service_note) {
    REQUIRE(U(CertEnumPhysicalStore));
    sss_cap_t c; BOOL r;
    SET_ERR(0);
    phys_enum(CERT_SYSTEM_STORE_CURRENT_SERVICE, L"My", &c, &r);
    t_note("CURRENT_SERVICE My -> %d n=%d gle=0x%lx", r, c.n, GetLastError());
}
TEST(sss_phys_enum_policy_locations_note) {
    REQUIRE(U(CertEnumPhysicalStore));
    DWORD f[3] = { CERT_SYSTEM_STORE_CURRENT_USER_GROUP_POLICY, CERT_SYSTEM_STORE_LOCAL_MACHINE_GROUP_POLICY, CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE };
    for (int i = 0; i < 3; i++) {
        sss_cap_t c; BOOL r;
        phys_enum(f[i], L"Root", &c, &r);
        t_note("phys loc 0x%lx Root -> %d n=%d gle=%lu", f[i], r, c.n, GetLastError());
    }
}
TEST(sss_phys_enum_store_name_case_insensitive) {
    REQUIRE(U(CertEnumPhysicalStore));
    sss_cap_t a, b; BOOL ra, rb;
    phys_enum(CERT_SYSTEM_STORE_CURRENT_USER, L"Root", &a, &ra);
    phys_enum(CERT_SYSTEM_STORE_CURRENT_USER, L"ROOT", &b, &rb);
    EXPECT_EQ(ra, rb);
    EXPECT_EQ(a.n, b.n);
}
