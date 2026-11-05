#include "sss.h"
/* Additional read-only system store coverage: flag validation tables, access state, nesting, parity. */

#define OPEN_RO2 (CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG)
#define SSS_ACCESS_STATE_PROP 14
#define SSS_ACC_WRITE 0x1
#define SSS_ACC_SYSTEM 0x2
#define SSS_ACC_LM 0x4
#define SSS_ACC_GP 0x8
#define SSS_ACC_SHARED 0x10

/* every bit inside the rejected mask 0x273f */
static const DWORD sss_bad_bits[] = { 0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x100, 0x200, 0x400, 0x2000 };
/* bits outside the mask that are not rejected by the location enumerator */
static const DWORD sss_ok_bits[] = { 0x40, 0x80, 0x800, 0x1000, 0x4000, 0x8000, 0x80000000u };

TEST(sss_loc_enum_each_bad_bit_einvalidarg) {
    REQUIRE(U(CertEnumSystemStoreLocation));
    for (unsigned i = 0; i < sizeof sss_bad_bits / sizeof sss_bad_bits[0]; i++) {
        sss_cap_t c; memset(&c, 0, sizeof c);
        SET_ERR(0);
        BOOL r = U(CertEnumSystemStoreLocation)(sss_bad_bits[i], &c, sss_cb_loc);
        CHECKF(!r, "bit 0x%lx accepted", sss_bad_bits[i]);
        EXPECT_ERR(SSS_E_INVALIDARG);
        EXPECT_EQ(c.n, 0);
    }
}
TEST(sss_loc_enum_unmasked_bits_accepted) {
    REQUIRE(U(CertEnumSystemStoreLocation));
    for (unsigned i = 0; i < sizeof sss_ok_bits / sizeof sss_ok_bits[0]; i++) {
        sss_cap_t c; memset(&c, 0, sizeof c);
        BOOL r = U(CertEnumSystemStoreLocation)(sss_ok_bits[i], &c, sss_cb_loc);
        CHECKF(r, "flags 0x%lx rejected gle=%lu", sss_ok_bits[i], GetLastError());
        CHECKF(c.n >= 8, "flags 0x%lx n=%d", sss_ok_bits[i], c.n);
    }
}
TEST(sss_loc_enum_location_flags_in_ids_range) {
    REQUIRE(U(CertEnumSystemStoreLocation));
    sss_cap_t c; memset(&c, 0, sizeof c);
    CHECK(U(CertEnumSystemStoreLocation)(0, &c, sss_cb_loc));
    for (int i = 0; i < c.n && i < 64; i++) {
        CHECKF((c.flags[i] & 0xFFFF) == 0, "loc %d flags 0x%lx has low bits", i, c.flags[i]);
        CHECKF((c.flags[i] >> 16) != 0, "loc %d has no location id", i);
        for (int j = i + 1; j < c.n && j < 64; j++) CHECK(c.flags[i] != c.flags[j]);
    }
}
TEST(sss_loc_enum_names_nonempty_unique) {
    REQUIRE(U(CertEnumSystemStoreLocation));
    sss_cap_t c; memset(&c, 0, sizeof c);
    CHECK(U(CertEnumSystemStoreLocation)(0, &c, sss_cb_loc));
    for (int i = 0; i < c.n && i < 64; i++) {
        CHECK(c.names[i][0] != 0);
        for (int j = i + 1; j < c.n && j < 64; j++) CHECK(lstrcmpiW(c.names[i], c.names[j]) != 0);
    }
}
TEST(sss_loc_enum_repeatable) {
    REQUIRE(U(CertEnumSystemStoreLocation));
    sss_cap_t a, b; memset(&a, 0, sizeof a); memset(&b, 0, sizeof b);
    CHECK(U(CertEnumSystemStoreLocation)(0, &a, sss_cb_loc));
    CHECK(U(CertEnumSystemStoreLocation)(0, &b, sss_cb_loc));
    EXPECT_EQ(a.n, b.n);
    for (int i = 0; i < a.n && i < 64; i++) { CHECK(!lstrcmpW(a.names[i], b.names[i])); EXPECT_EQ(a.flags[i], b.flags[i]); }
}
TEST(sss_loc_enum_callback_same_thread) {
    REQUIRE(U(CertEnumSystemStoreLocation));
    sss_cap_t c; memset(&c, 0, sizeof c); c.tid = GetCurrentThreadId();
    CHECK(U(CertEnumSystemStoreLocation)(0, &c, sss_cb_loc));
    EXPECT_EQ(c.tid_bad, 0);
}
static BOOL WINAPI nest_cb(LPCWSTR n, DWORD f, void *r, void *arg) {
    int *cnt = (int *)arg;
    sss_cap_t inner; memset(&inner, 0, sizeof inner);
    BOOL ok = U(CertEnumSystemStoreLocation)(0, &inner, sss_cb_loc);
    if (ok) cnt[1] = inner.n; else cnt[2]++;
    cnt[0]++;
    return cnt[0] < 2;
}
TEST(sss_loc_enum_nested_enumeration) {
    REQUIRE(U(CertEnumSystemStoreLocation));
    sss_cap_t base; memset(&base, 0, sizeof base);
    CHECK(U(CertEnumSystemStoreLocation)(0, &base, sss_cb_loc));
    int cnt[3] = {0, 0, 0};
    BOOL r = U(CertEnumSystemStoreLocation)(0, cnt, nest_cb);
    CHECK(!r);
    EXPECT_EQ(cnt[0], 2);
    EXPECT_EQ(cnt[2], 0);
    EXPECT_EQ(cnt[1], base.n);
}

/* ---- CertEnumSystemStore flag validation ---- */
TEST(sss_store_enum_each_bad_bit_einvalidarg) {
    if (t_is_wine()) { t_skip("emulator does not validate these flags"); return; }
    REQUIRE(U(CertEnumSystemStore));
    DWORD locs[2] = { CERT_SYSTEM_STORE_CURRENT_USER, CERT_SYSTEM_STORE_LOCAL_MACHINE };
    for (int l = 0; l < 2; l++)
        for (unsigned i = 0; i < sizeof sss_bad_bits / sizeof sss_bad_bits[0]; i++) {
            sss_cap_t c; memset(&c, 0, sizeof c);
            SET_ERR(0);
            BOOL r = U(CertEnumSystemStore)(locs[l] | sss_bad_bits[i], NULL, &c, sss_cb_store);
            CHECKF(!r, "loc %d bit 0x%lx accepted", l, sss_bad_bits[i]);
            EXPECT_ERR(SSS_E_INVALIDARG);
            EXPECT_EQ(c.n, 0);
        }
}
TEST(sss_store_enum_relocate_flag_null_para_einvalidarg) {
    if (t_is_wine()) { t_skip("emulator does not validate these flags"); return; }
    REQUIRE(U(CertEnumSystemStore));
    sss_cap_t c; memset(&c, 0, sizeof c);
    SET_ERR(0);
    BOOL r = U(CertEnumSystemStore)(CERT_SYSTEM_STORE_CURRENT_USER | CERT_SYSTEM_STORE_RELOCATE_FLAG, NULL, &c, sss_cb_store);
    CHECK(!r);
    EXPECT_ERR(SSS_E_INVALIDARG);
    EXPECT_EQ(c.n, 0);
}
TEST(sss_store_enum_relocate_null_hkey_einvalidarg) {
    if (t_is_wine()) { t_skip("emulator does not validate these flags"); return; }
    REQUIRE(U(CertEnumSystemStore));
    CERT_SYSTEM_STORE_RELOCATE_PARA p; memset(&p, 0, sizeof p);
    p.hKeyBase = NULL; p.pvSystemStore = L"x";
    sss_cap_t c; memset(&c, 0, sizeof c);
    SET_ERR(0);
    BOOL r = U(CertEnumSystemStore)(CERT_SYSTEM_STORE_CURRENT_USER | CERT_SYSTEM_STORE_RELOCATE_FLAG, &p, &c, sss_cb_store);
    CHECK(!r);
    EXPECT_ERR(SSS_E_INVALIDARG);
    EXPECT_EQ(c.n, 0);
}
TEST(sss_store_enum_my_root_ca_order) {
    REQUIRE(U(CertEnumSystemStore));
    DWORD locs[2] = { CERT_SYSTEM_STORE_CURRENT_USER, CERT_SYSTEM_STORE_LOCAL_MACHINE };
    for (int l = 0; l < 2; l++) {
        sss_cap_t c; memset(&c, 0, sizeof c);
        CHECK(U(CertEnumSystemStore)(locs[l], NULL, &c, sss_cb_store));
        int im = -1, ir = -1, ic = -1;
        for (int i = 0; i < c.n && i < 64; i++) {
            if (!lstrcmpiW(c.names[i], L"My")) im = i;
            if (!lstrcmpiW(c.names[i], L"Root")) ir = i;
            if (!lstrcmpiW(c.names[i], L"CA")) ic = i;
        }
        CHECK(im >= 0 && ir >= 0 && ic >= 0);
        t_label("loc %d", l);
        EXPECT_EQ(im, 0); EXPECT_EQ(ir, 1); EXPECT_EQ(ic, 3); /* probed std and adm: registry key order My, Root, Trust, CA */
    }
}
TEST(sss_store_enum_names_wellformed) {
    REQUIRE(U(CertEnumSystemStore));
    DWORD locs[2] = { CERT_SYSTEM_STORE_CURRENT_USER, CERT_SYSTEM_STORE_LOCAL_MACHINE };
    for (int l = 0; l < 2; l++) {
        sss_cap_t c; memset(&c, 0, sizeof c);
        CHECK(U(CertEnumSystemStore)(locs[l], NULL, &c, sss_cb_store));
        for (int i = 0; i < c.n && i < 64; i++) {
            CHECK(c.names[i][0] != 0);
            CHECK(wcschr(c.names[i], L'\\') == NULL);
        }
    }
}
TEST(sss_store_enum_callback_same_thread_and_info_size) {
    REQUIRE(U(CertEnumSystemStore));
    sss_cap_t c; memset(&c, 0, sizeof c); c.tid = GetCurrentThreadId();
    CHECK(U(CertEnumSystemStore)(CERT_SYSTEM_STORE_LOCAL_MACHINE, NULL, &c, sss_cb_store));
    EXPECT_EQ(c.tid_bad, 0);
    EXPECT_EQ(c.info_cb0, sizeof(CERT_SYSTEM_STORE_INFO));
}
TEST(sss_store_enum_repeatable) {
    REQUIRE(U(CertEnumSystemStore));
    sss_cap_t a, b; memset(&a, 0, sizeof a); memset(&b, 0, sizeof b);
    CHECK(U(CertEnumSystemStore)(CERT_SYSTEM_STORE_LOCAL_MACHINE, NULL, &a, sss_cb_store));
    CHECK(U(CertEnumSystemStore)(CERT_SYSTEM_STORE_LOCAL_MACHINE, NULL, &b, sss_cb_store));
    CHECK(a.n > 0);
    if (a.n == b.n) for (int i = 0; i < a.n && i < 64; i++) CHECK(!lstrcmpW(a.names[i], b.names[i]));
    else CHECKF(0, "store set changed between enumerations: %d vs %d", a.n, b.n);
}
TEST(sss_store_enum_stop_at_each_position) {
    REQUIRE(U(CertEnumSystemStore));
    sss_cap_t all; memset(&all, 0, sizeof all);
    CHECK(U(CertEnumSystemStore)(CERT_SYSTEM_STORE_CURRENT_USER, NULL, &all, sss_cb_store));
    for (int stop = 1; stop <= 3 && stop < all.n; stop++) {
        sss_cap_t c; memset(&c, 0, sizeof c); c.stop_after = stop;
        BOOL r = U(CertEnumSystemStore)(CERT_SYSTEM_STORE_CURRENT_USER, NULL, &c, sss_cb_store);
        CHECKF(!r, "stop=%d returned TRUE", stop);
        EXPECT_EQ(c.n, stop);
        for (int i = 0; i < stop; i++) CHECK(!lstrcmpW(c.names[i], all.names[i]));
    }
}
TEST(sss_store_enum_user_machine_sets_share_predefined) {
    REQUIRE(U(CertEnumSystemStore));
    sss_cap_t u, m; memset(&u, 0, sizeof u); memset(&m, 0, sizeof m);
    CHECK(U(CertEnumSystemStore)(CERT_SYSTEM_STORE_CURRENT_USER, NULL, &u, sss_cb_store));
    CHECK(U(CertEnumSystemStore)(CERT_SYSTEM_STORE_LOCAL_MACHINE, NULL, &m, sss_cb_store));
    t_note("CU stores=%d LM stores=%d", u.n, m.n);
    CHECK(sss_has(&u, L"Root") == sss_has(&m, L"Root"));
    CHECK(sss_has(&u, L"My") == sss_has(&m, L"My"));
}
TEST(sss_store_enum_location_ids_dispatch) {
    REQUIRE(U(CertEnumSystemStore));
    /* every id 0..0xA is dispatched by the table; ids beyond need a registered handler */
    for (DWORD id = 0x20; id < 0x24; id++) {
        sss_cap_t c; memset(&c, 0, sizeof c);
        BOOL r = U(CertEnumSystemStore)(SSS_LOC(id), NULL, &c, sss_cb_store);
        CHECKF(!r, "unregistered location %lu succeeded", id);
        EXPECT_EQ(c.n, 0);
    }
}

/* ---- CertEnumPhysicalStore parameter validation ---- */
TEST(sss_phys_enum_null_store_name_einvalidarg) {
    if (t_is_wine()) { t_skip("emulator differs from Windows behaviour"); return; }
    REQUIRE(U(CertEnumPhysicalStore));
    sss_cap_t c; memset(&c, 0, sizeof c);
    SET_ERR(0);
    BOOL r = U(CertEnumPhysicalStore)(NULL, CERT_SYSTEM_STORE_CURRENT_USER, &c, sss_cb_phys);
    CHECK(!r);
    EXPECT_ERR(SSS_E_INVALIDARG);
    EXPECT_EQ(c.n, 0);
}
TEST(sss_phys_enum_empty_store_name_einvalidarg) {
    if (t_is_wine()) { t_skip("emulator differs from Windows behaviour"); return; }
    REQUIRE(U(CertEnumPhysicalStore));
    sss_cap_t c; memset(&c, 0, sizeof c);
    SET_ERR(0);
    BOOL r = U(CertEnumPhysicalStore)(L"", CERT_SYSTEM_STORE_CURRENT_USER, &c, sss_cb_phys);
    CHECK(!r);
    EXPECT_ERR(SSS_E_INVALIDARG);
    EXPECT_EQ(c.n, 0);
}
TEST(sss_phys_enum_relocate_null_para_einvalidarg) {
    if (t_is_wine()) { t_skip("emulator differs from Windows behaviour"); return; }
    REQUIRE(U(CertEnumPhysicalStore));
    sss_cap_t c; memset(&c, 0, sizeof c);
    SET_ERR(0);
    BOOL r = U(CertEnumPhysicalStore)(NULL, CERT_SYSTEM_STORE_CURRENT_USER | CERT_SYSTEM_STORE_RELOCATE_FLAG, &c, sss_cb_phys);
    CHECK(!r);
    EXPECT_ERR(SSS_E_INVALIDARG);
    EXPECT_EQ(c.n, 0);
}
TEST(sss_phys_enum_relocate_null_hkey_einvalidarg) {
    if (t_is_wine()) { t_skip("emulator differs from Windows behaviour"); return; }
    REQUIRE(U(CertEnumPhysicalStore));
    CERT_SYSTEM_STORE_RELOCATE_PARA p; memset(&p, 0, sizeof p);
    p.hKeyBase = NULL; p.pwszSystemStore = L"Root";
    sss_cap_t c; memset(&c, 0, sizeof c);
    SET_ERR(0);
    BOOL r = U(CertEnumPhysicalStore)(&p, CERT_SYSTEM_STORE_CURRENT_USER | CERT_SYSTEM_STORE_RELOCATE_FLAG, &c, sss_cb_phys);
    CHECK(!r);
    EXPECT_ERR(SSS_E_INVALIDARG);
    EXPECT_EQ(c.n, 0);
}
TEST(sss_phys_enum_default_present_for_predefined_all_locs_note) {
    REQUIRE(U(CertEnumPhysicalStore));
    static const wchar_t *st[] = { L"My", L"Root", L"CA", L"Disallowed", L"TrustedPeople", L"TrustedPublisher", L"AuthRoot" };
    for (unsigned s = 0; s < sizeof st / sizeof st[0]; s++)
        for (int l = 0; l < 2; l++) {
            sss_cap_t c; BOOL r;
            memset(&c, 0, sizeof c);
            r = U(CertEnumPhysicalStore)(st[s], l ? CERT_SYSTEM_STORE_LOCAL_MACHINE : CERT_SYSTEM_STORE_CURRENT_USER, &c, sss_cb_phys);
            t_label("%ls %s", st[s], l ? "LM" : "CU");
            /* probed std and adm: succeeds and lists .Default; the other physical stores differ (CU Root 3, LM Root 5, others 3) */
            EXPECT_EQ(r, 1); EXPECT_EQ(sss_has(&c, L".Default") != 0, 1);
            EXPECT_EQ(c.n, (s == 1 && l == 1) ? 5 : (s == 0) ? 1 : 3);
        }
}
TEST(sss_phys_enum_same_thread) {
    REQUIRE(U(CertEnumPhysicalStore));
    if (t_is_wine()) { t_skip("emulator lacks physical store enumeration"); return; }
    sss_cap_t c; memset(&c, 0, sizeof c); c.tid = GetCurrentThreadId();
    CHECK(U(CertEnumPhysicalStore)(L"Root", CERT_SYSTEM_STORE_LOCAL_MACHINE, &c, sss_cb_phys));
    CHECK(c.n >= 1);
    EXPECT_EQ(c.tid_bad, 0);
    for (int i = 0; i < c.n && i < 64; i++) /* Win10 (probed, std and adm): callback flags are the location id plus bit 0x1 */ EXPECT_EQ(c.flags[i], CERT_SYSTEM_STORE_LOCAL_MACHINE | 1);
}
static BOOL WINAPI nest_phys(const void *s, DWORD f, LPCWSTR n, PCERT_PHYSICAL_STORE_INFO i, void *r, void *arg) {
    int *cnt = (int *)arg;
    sss_cap_t inner; memset(&inner, 0, sizeof inner);
    BOOL ok = U(CertEnumPhysicalStore)(L"Root", CERT_SYSTEM_STORE_CURRENT_USER, &inner, sss_cb_phys);
    if (!ok) cnt[1]++;
    cnt[0]++;
    return FALSE;
}
TEST(sss_phys_enum_nested_from_callback) {
    REQUIRE(U(CertEnumPhysicalStore));
    if (t_is_wine()) { t_skip("emulator lacks physical store enumeration"); return; }
    int cnt[2] = {0, 0};
    BOOL r = U(CertEnumPhysicalStore)(L"Root", CERT_SYSTEM_STORE_CURRENT_USER, cnt, nest_phys);
    CHECK(!r);
    EXPECT_EQ(cnt[0], 1);
    EXPECT_EQ(cnt[1], 0);
}

/* ---- CertGetStoreProperty(CERT_ACCESS_STATE_PROP_ID) ---- */
static DWORD access_state(HCERTSTORE h, BOOL *ok) {
    DWORD v = 0xdeadbeef, cb = sizeof v;
    *ok = U(CertGetStoreProperty)(h, SSS_ACCESS_STATE_PROP, &v, &cb);
    return v;
}
TEST(sss_access_state_cu_readonly_root) {
    if (t_is_wine()) { t_skip("emulator differs from Windows behaviour"); return; }
    REQUIRE(U(CertGetStoreProperty)); REQUIRE(U(CertOpenStore)); REQUIRE(U(CertCloseStore));
    HCERTSTORE h = U(CertOpenStore)(CERT_STORE_PROV_SYSTEM_W, 0, 0, CERT_SYSTEM_STORE_CURRENT_USER | OPEN_RO2, L"Root");
    CHECK(h != NULL); if (!h) return;
    BOOL ok; DWORD v = access_state(h, &ok);
    CHECK(ok);
    EXPECT_EQ(v, SSS_ACC_SYSTEM);   /* read-only: no persist-write bit */
    U(CertCloseStore)(h, 0);
}
TEST(sss_access_state_lm_readonly_root) {
    if (t_is_wine()) { t_skip("emulator differs from Windows behaviour"); return; }
    REQUIRE(U(CertGetStoreProperty)); REQUIRE(U(CertOpenStore)); REQUIRE(U(CertCloseStore));
    HCERTSTORE h = U(CertOpenStore)(CERT_STORE_PROV_SYSTEM_W, 0, 0, CERT_SYSTEM_STORE_LOCAL_MACHINE | OPEN_RO2, L"Root");
    CHECK(h != NULL); if (!h) return;
    BOOL ok; DWORD v = access_state(h, &ok);
    CHECK(ok);
    EXPECT_EQ(v, SSS_ACC_SYSTEM | SSS_ACC_LM);
    U(CertCloseStore)(h, 0);
}
TEST(sss_access_state_cu_gp_readonly) {
    if (t_is_wine()) { t_skip("emulator differs from Windows behaviour"); return; }
    REQUIRE(U(CertGetStoreProperty)); REQUIRE(U(CertOpenStore)); REQUIRE(U(CertCloseStore));
    HCERTSTORE h = U(CertOpenStore)(CERT_STORE_PROV_SYSTEM_W, 0, 0, CERT_SYSTEM_STORE_CURRENT_USER_GROUP_POLICY | OPEN_RO2, L"Root");
    CHECKF(h != NULL, "CU group policy Root gle=%lu", GetLastError()); /* probed std and adm: opens (read only) even though no policy store exists */
    if (!h) return;
    BOOL ok; DWORD v = access_state(h, &ok);
    CHECK(ok);
    CHECK(v & SSS_ACC_SYSTEM);
    CHECK(v & SSS_ACC_GP);
    CHECK(!(v & SSS_ACC_WRITE));
    U(CertCloseStore)(h, 0);
}
TEST(sss_access_state_open_system_store_has_system_bit) {
    if (t_is_wine()) { t_skip("emulator differs from Windows behaviour"); return; }
    REQUIRE(U(CertGetStoreProperty)); REQUIRE(U(CertOpenSystemStoreW)); REQUIRE(U(CertCloseStore));
    HCERTSTORE h = U(CertOpenSystemStoreW)(0, L"CA");
    CHECK(h != NULL); if (!h) return;
    BOOL ok; DWORD v = access_state(h, &ok);
    CHECK(ok);
    CHECK(v & SSS_ACC_SYSTEM);
    CHECK(!(v & (SSS_ACC_LM | SSS_ACC_GP)));
    U(CertCloseStore)(h, 0);
}
TEST(sss_access_state_memory_store_no_system_bits) {
    if (t_is_wine()) { t_skip("emulator differs from Windows behaviour"); return; }
    REQUIRE(U(CertGetStoreProperty)); REQUIRE(U(CertOpenStore)); REQUIRE(U(CertCloseStore));
    HCERTSTORE h = U(CertOpenStore)(CERT_STORE_PROV_MEMORY, 0, 0, 0, NULL);
    CHECK(h != NULL); if (!h) return;
    BOOL ok; DWORD v = access_state(h, &ok);
    CHECK(ok);
    EXPECT_EQ(v & (SSS_ACC_SYSTEM | SSS_ACC_LM | SSS_ACC_GP | SSS_ACC_SHARED), 0);
    U(CertCloseStore)(h, 0);
}
TEST(sss_access_state_size_protocol) {
    if (t_is_wine()) { t_skip("emulator differs from Windows behaviour"); return; }
    REQUIRE(U(CertGetStoreProperty)); REQUIRE(U(CertOpenStore)); REQUIRE(U(CertCloseStore));
    HCERTSTORE h = U(CertOpenStore)(CERT_STORE_PROV_SYSTEM_W, 0, 0, CERT_SYSTEM_STORE_CURRENT_USER | OPEN_RO2, L"Root");
    CHECK(h != NULL); if (!h) return;
    DWORD cb = 0, v = 0x55555555;
    /* size query */
    SET_ERR(0);
    CHECK(U(CertGetStoreProperty)(h, SSS_ACCESS_STATE_PROP, NULL, &cb));
    EXPECT_EQ(cb, 4);
    /* too small */
    for (cb = 0; cb < 4; cb++) {
        DWORD c2 = cb; v = 0x55555555;
        SET_ERR(0);
        BOOL r = U(CertGetStoreProperty)(h, SSS_ACCESS_STATE_PROP, &v, &c2);
        CHECKF(!r, "cb=%lu succeeded", cb);
        EXPECT_ERR(ERROR_MORE_DATA);
        EXPECT_EQ(c2, 4);
        EXPECT_EQ(v, 0x55555555);
    }
    /* larger buffer: size is rewritten to 4 */
    cb = 16; v = 0;
    CHECK(U(CertGetStoreProperty)(h, SSS_ACCESS_STATE_PROP, &v, &cb));
    EXPECT_EQ(cb, 4);
    EXPECT_EQ(v, SSS_ACC_SYSTEM);
    U(CertCloseStore)(h, 0);
}
TEST(sss_access_state_stable_across_calls) {
    if (t_is_wine()) { t_skip("emulator differs from Windows behaviour"); return; }
    REQUIRE(U(CertGetStoreProperty)); REQUIRE(U(CertOpenStore)); REQUIRE(U(CertCloseStore));
    HCERTSTORE h = U(CertOpenStore)(CERT_STORE_PROV_SYSTEM_W, 0, 0, CERT_SYSTEM_STORE_LOCAL_MACHINE | OPEN_RO2, L"CA");
    CHECK(h != NULL); if (!h) return;
    BOOL o1, o2; DWORD a = access_state(h, &o1), b = access_state(h, &o2);
    CHECK(o1 && o2);
    EXPECT_EQ(a, b);
    U(CertCloseStore)(h, 0);
}
TEST(sss_access_state_collection_of_readonly_members) {
    REQUIRE(U(CertGetStoreProperty)); REQUIRE(U(CertOpenStore)); REQUIRE(U(CertAddStoreToCollection)); REQUIRE(U(CertCloseStore));
    HCERTSTORE col = U(CertOpenStore)(CERT_STORE_PROV_COLLECTION, 0, 0, 0, NULL);
    HCERTSTORE a = U(CertOpenStore)(CERT_STORE_PROV_SYSTEM_W, 0, 0, CERT_SYSTEM_STORE_CURRENT_USER | OPEN_RO2, L"Root");
    CHECK(col && a);
    if (col && a) {
        CHECK(U(CertAddStoreToCollection)(col, a, CERT_PHYSICAL_STORE_ADD_ENABLE_FLAG, 0));
        BOOL ok; DWORD v = access_state(col, &ok);
        CHECK(ok);
        EXPECT_EQ(v, 0); /* probed std and adm: a collection reports no system/write bits */
    }
    if (col) U(CertCloseStore)(col, 0);
    if (a) U(CertCloseStore)(a, 0);
}

/* ---- unset / unknown properties ---- */
TEST(sss_prop_unknown_sets_cb_zero_and_not_found) {
    if (t_is_wine()) { t_skip("emulator differs from Windows behaviour"); return; }
    REQUIRE(U(CertGetStoreProperty)); REQUIRE(U(CertOpenStore)); REQUIRE(U(CertCloseStore));
    HCERTSTORE h = U(CertOpenStore)(CERT_STORE_PROV_MEMORY, 0, 0, 0, NULL);
    CHECK(h != NULL); if (!h) return;
    static const DWORD ids[] = { 0x7ff0, 0x7ff1, CERT_STORE_LOCALIZED_NAME_PROP_ID, 3, 20 };
    for (unsigned i = 0; i < sizeof ids / sizeof ids[0]; i++) {
        DWORD cb = 77; BYTE buf[16];
        SET_ERR(0);
        BOOL r = U(CertGetStoreProperty)(h, ids[i], buf, &cb);
        CHECKF(!r, "prop %lu present", ids[i]);
        EXPECT_ERR(CRYPT_E_NOT_FOUND);
        EXPECT_EQ(cb, 0);
        cb = 77;
        SET_ERR(0);
        r = U(CertGetStoreProperty)(h, ids[i], NULL, &cb);
        CHECK(!r);
        EXPECT_ERR(CRYPT_E_NOT_FOUND);
        EXPECT_EQ(cb, 0);
    }
    U(CertCloseStore)(h, 0);
}
TEST(sss_prop_unknown_on_system_stores) {
    if (t_is_wine()) { t_skip("emulator differs from Windows behaviour"); return; }
    REQUIRE(U(CertGetStoreProperty)); REQUIRE(U(CertOpenStore)); REQUIRE(U(CertCloseStore));
    DWORD locs[2] = { CERT_SYSTEM_STORE_CURRENT_USER, CERT_SYSTEM_STORE_LOCAL_MACHINE };
    for (int l = 0; l < 2; l++) {
        HCERTSTORE h = U(CertOpenStore)(CERT_STORE_PROV_SYSTEM_W, 0, 0, locs[l] | OPEN_RO2, L"Root");
        CHECK(h != NULL); if (!h) continue;
        DWORD cb = 5; SET_ERR(0);
        CHECK(!U(CertGetStoreProperty)(h, 0x7ff2, NULL, &cb));
        EXPECT_ERR(CRYPT_E_NOT_FOUND);
        EXPECT_EQ(cb, 0);
        U(CertCloseStore)(h, 0);
    }
}

/* ---- parity and context properties ---- */
TEST(sss_open_provider_a_w_parity) {
    REQUIRE(U(CertOpenStore)); REQUIRE(U(CertCloseStore)); REQUIRE(U(CertEnumCertificatesInStore));
    DWORD locs[2] = { CERT_SYSTEM_STORE_CURRENT_USER, CERT_SYSTEM_STORE_LOCAL_MACHINE };
    for (int l = 0; l < 2; l++) {
        HCERTSTORE a = U(CertOpenStore)(CERT_STORE_PROV_SYSTEM_A, 0, 0, locs[l] | OPEN_RO2, "Root");
        HCERTSTORE w = U(CertOpenStore)(CERT_STORE_PROV_SYSTEM_W, 0, 0, locs[l] | OPEN_RO2, L"Root");
        CHECK(a && w);
        if (a && w) EXPECT_EQ(sss_count_certs(a), sss_count_certs(w));
        if (a) U(CertCloseStore)(a, 0);
        if (w) U(CertCloseStore)(w, 0);
    }
}
TEST(sss_open_name_case_insensitive) {
    REQUIRE(U(CertOpenStore)); REQUIRE(U(CertCloseStore)); REQUIRE(U(CertEnumCertificatesInStore));
    HCERTSTORE a = U(CertOpenStore)(CERT_STORE_PROV_SYSTEM_W, 0, 0, CERT_SYSTEM_STORE_LOCAL_MACHINE | OPEN_RO2, L"root");
    HCERTSTORE b = U(CertOpenStore)(CERT_STORE_PROV_SYSTEM_W, 0, 0, CERT_SYSTEM_STORE_LOCAL_MACHINE | OPEN_RO2, L"ROOT");
    CHECK(a && b);
    if (a && b) EXPECT_EQ(sss_count_certs(a), sss_count_certs(b));
    if (a) U(CertCloseStore)(a, 0);
    if (b) U(CertCloseStore)(b, 0);
}
TEST(sss_open_registry_provider_matches_system_provider) {
    REQUIRE(U(CertOpenStore)); REQUIRE(U(CertCloseStore)); REQUIRE(U(CertEnumCertificatesInStore));
    HCERTSTORE a = U(CertOpenStore)(CERT_STORE_PROV_SYSTEM_REGISTRY_W, 0, 0, CERT_SYSTEM_STORE_LOCAL_MACHINE | OPEN_RO2, L"Root");
    HCERTSTORE b = U(CertOpenStore)(CERT_STORE_PROV_SYSTEM_W, 0, 0, CERT_SYSTEM_STORE_LOCAL_MACHINE | OPEN_RO2, L"Root");
    CHECK(a != NULL);
    CHECK(b != NULL);
    /* probed std and adm: the registry provider sees only the .Default physical store; the system provider also merges .AuthRoot and others, so it holds more */
    if (a && b) CHECK(sss_count_certs(a) < sss_count_certs(b));
    if (a) U(CertCloseStore)(a, 0);
    if (b) U(CertCloseStore)(b, 0);
}
TEST(sss_cert_contexts_well_formed_in_system_store) {
    REQUIRE(U(CertOpenStore)); REQUIRE(U(CertCloseStore)); REQUIRE(U(CertEnumCertificatesInStore));
    DWORD locs[2] = { CERT_SYSTEM_STORE_CURRENT_USER, CERT_SYSTEM_STORE_LOCAL_MACHINE };
    for (int l = 0; l < 2; l++) {
        HCERTSTORE h = U(CertOpenStore)(CERT_STORE_PROV_SYSTEM_W, 0, 0, locs[l] | OPEN_RO2, L"Root");
        CHECK(h != NULL); if (!h) continue;
        PCCERT_CONTEXT c = NULL; int n = 0;
        while ((c = U(CertEnumCertificatesInStore)(h, c)) != NULL && n < 2000) {
            n++;
            CHECK(c->cbCertEncoded > 4);
            CHECK(c->pbCertEncoded && c->pbCertEncoded[0] == 0x30);
            CHECK(c->pCertInfo != NULL);
            CHECK(c->dwCertEncodingType & X509_ASN_ENCODING);
            CHECK(c->hCertStore == h);
        }
        t_note("loc %d Root contexts checked: %d", l, n);
        U(CertCloseStore)(h, 0);
    }
}
TEST(sss_enum_certs_independent_cursors) {
    REQUIRE(U(CertOpenSystemStoreW)); REQUIRE(U(CertCloseStore)); REQUIRE(U(CertEnumCertificatesInStore));
    HCERTSTORE h = U(CertOpenSystemStoreW)(0, L"Root");
    CHECK(h != NULL); if (!h) return;
    PCCERT_CONTEXT a = U(CertEnumCertificatesInStore)(h, NULL);
    if (a) {
        PCCERT_CONTEXT b = U(CertEnumCertificatesInStore)(h, NULL);
        CHECK(b != NULL);
        if (b) { CHECK(b->cbCertEncoded == a->cbCertEncoded); U(CertFreeCertificateContext)(b); }
        U(CertFreeCertificateContext)(a);
    } else CHECK(a != NULL); /* probed std and adm: CurrentUser Root is never empty */
    U(CertCloseStore)(h, 0);
}

/* ---- collections ---- */
TEST(sss_collection_nested_counts) {
    REQUIRE(U(CertOpenStore)); REQUIRE(U(CertAddStoreToCollection)); REQUIRE(U(CertEnumCertificatesInStore));
    HCERTSTORE inner = U(CertOpenStore)(CERT_STORE_PROV_COLLECTION, 0, 0, 0, NULL);
    HCERTSTORE outer = U(CertOpenStore)(CERT_STORE_PROV_COLLECTION, 0, 0, 0, NULL);
    HCERTSTORE r = U(CertOpenStore)(CERT_STORE_PROV_SYSTEM_W, 0, 0, CERT_SYSTEM_STORE_LOCAL_MACHINE | OPEN_RO2, L"Root");
    CHECK(inner && outer && r);
    if (inner && outer && r) {
        CHECK(U(CertAddStoreToCollection)(inner, r, 0, 0));
        CHECK(U(CertAddStoreToCollection)(outer, inner, 0, 0));
        EXPECT_EQ(sss_count_certs(outer), sss_count_certs(r));
    }
    if (outer) U(CertCloseStore)(outer, 0);
    if (inner) U(CertCloseStore)(inner, 0);
    if (r) U(CertCloseStore)(r, 0);
}
TEST(sss_collection_with_empty_memory_member) {
    REQUIRE(U(CertOpenStore)); REQUIRE(U(CertAddStoreToCollection)); REQUIRE(U(CertEnumCertificatesInStore));
    HCERTSTORE col = U(CertOpenStore)(CERT_STORE_PROV_COLLECTION, 0, 0, 0, NULL);
    HCERTSTORE mem = U(CertOpenStore)(CERT_STORE_PROV_MEMORY, 0, 0, 0, NULL);
    HCERTSTORE r = U(CertOpenStore)(CERT_STORE_PROV_SYSTEM_W, 0, 0, CERT_SYSTEM_STORE_CURRENT_USER | OPEN_RO2, L"Root");
    CHECK(col && mem && r);
    if (col && mem && r) {
        CHECK(U(CertAddStoreToCollection)(col, mem, 0, 0));
        EXPECT_EQ(sss_count_certs(col), 0);
        CHECK(U(CertAddStoreToCollection)(col, r, 0, 0));
        EXPECT_EQ(sss_count_certs(col), sss_count_certs(r));
    }
    if (col) U(CertCloseStore)(col, 0);
    if (mem) U(CertCloseStore)(mem, 0);
    if (r) U(CertCloseStore)(r, 0);
}
TEST(sss_collection_close_member_keeps_collection_valid) {
    REQUIRE(U(CertOpenStore)); REQUIRE(U(CertAddStoreToCollection)); REQUIRE(U(CertEnumCertificatesInStore));
    HCERTSTORE col = U(CertOpenStore)(CERT_STORE_PROV_COLLECTION, 0, 0, 0, NULL);
    HCERTSTORE r = U(CertOpenStore)(CERT_STORE_PROV_SYSTEM_W, 0, 0, CERT_SYSTEM_STORE_LOCAL_MACHINE | OPEN_RO2, L"Root");
    CHECK(col && r);
    if (col && r) {
        int n = sss_count_certs(r);
        CHECK(U(CertAddStoreToCollection)(col, r, 0, 0));
        CHECK(U(CertCloseStore)(r, 0));   /* collection holds its own reference */
        r = NULL;
        EXPECT_EQ(sss_count_certs(col), n);
    }
    if (col) U(CertCloseStore)(col, 0);
    if (r) U(CertCloseStore)(r, 0);
}

/* ---- localized names ---- */
TEST(sss_locname_near_misses_not_found) {
    REQUIRE(U(CryptFindLocalizedName));
    static const wchar_t *n[] = { L"Roo", L"Rootx", L" Root", L"Root\\", L"\\Root", L"My ", L"C", L"CAA", L"." };
    for (unsigned i = 0; i < sizeof n / sizeof n[0]; i++)
        CHECKF(U(CryptFindLocalizedName)(n[i]) == NULL, "%ls matched", n[i]);
}
TEST(sss_locname_repeat_stable_100) {
    REQUIRE(U(CryptFindLocalizedName));
    LPCWSTR first = U(CryptFindLocalizedName)(L"My");
    CHECK(first != NULL);
    for (int i = 0; i < 100; i++) CHECK(U(CryptFindLocalizedName)(L"My") == first);
}
TEST(sss_locname_distinct_per_store) {
    REQUIRE(U(CryptFindLocalizedName));
    LPCWSTR a = U(CryptFindLocalizedName)(L"My"), b = U(CryptFindLocalizedName)(L"Root"), c = U(CryptFindLocalizedName)(L"CA");
    CHECK(a && b && c);
    if (a && b && c) { CHECK(lstrcmpW(a, b) != 0); CHECK(lstrcmpW(a, c) != 0); CHECK(lstrcmpW(b, c) != 0); }
}
TEST(sss_locname_does_not_clobber_last_error_note) {
    REQUIRE(U(CryptFindLocalizedName));
    SET_ERR(1234);
    U(CryptFindLocalizedName)(L"NoSuch_cryptt");
    EXPECT_ERR(ERROR_PROC_NOT_FOUND); /* probed std and adm: an unknown name leaves 127, not the previous value */
}
TEST(sss_locname_enumerated_store_names_note) {
    REQUIRE(U(CertEnumSystemStore)); REQUIRE(U(CryptFindLocalizedName));
    sss_cap_t c; memset(&c, 0, sizeof c);
    CHECK(U(CertEnumSystemStore)(CERT_SYSTEM_STORE_CURRENT_USER, NULL, &c, sss_cb_store));
    for (int i = 0; i < c.n && i < 64; i++) {
        LPCWSTR l = U(CryptFindLocalizedName)(c.names[i]);
        t_label("%ls", c.names[i]);
        /* probed std and adm: every store enumerated for CurrentUser has a localized name */
        CHECK(l != NULL && *l);
    }
}
TEST(sss_locname_location_names_from_enumeration_note) {
    REQUIRE(U(CertEnumSystemStoreLocation)); REQUIRE(U(CryptFindLocalizedName));
    sss_cap_t c; memset(&c, 0, sizeof c);
    CHECK(U(CertEnumSystemStoreLocation)(0, &c, sss_cb_loc));
    for (int i = 0; i < c.n && i < 64; i++) {
        LPCWSTR l = U(CryptFindLocalizedName)(c.names[i]);
        t_label("%ls", c.names[i]);
        CHECK(l == NULL); /* probed std and adm: location names have no localized form */
    }
}

/* ---- open parameter handling ---- */
TEST(sss_open_unknown_location_id_fails) {
    REQUIRE(U(CertOpenStore));
    SET_ERR(0);
    HCERTSTORE h = U(CertOpenStore)(CERT_STORE_PROV_SYSTEM_W, 0, 0, SSS_LOC(0x7F) | OPEN_RO2, L"Root");
    CHECK(h == NULL);
    EXPECT_ERR(ERROR_FILE_NOT_FOUND); /* probed std and adm */
    if (h) U(CertCloseStore)(h, 0);
}
TEST(sss_open_nonexistent_does_not_create) {
    REQUIRE(U(CertOpenStore)); REQUIRE(U(CertEnumSystemStore));
    wchar_t nm[64]; sss_wuniq(nm, 64, L"nocreate");
    HCERTSTORE h = U(CertOpenStore)(CERT_STORE_PROV_SYSTEM_W, 0, 0, CERT_SYSTEM_STORE_CURRENT_USER | OPEN_RO2, nm);
    CHECK(h == NULL);
    if (h) U(CertCloseStore)(h, 0);
    HCERTSTORE h2 = U(CertOpenStore)(CERT_STORE_PROV_SYSTEM_W, 0, 0, CERT_SYSTEM_STORE_CURRENT_USER | OPEN_RO2, nm);
    CHECK(h2 == NULL);
    if (h2) U(CertCloseStore)(h2, 0);
    sss_cap_t c; memset(&c, 0, sizeof c);
    CHECK(U(CertEnumSystemStore)(CERT_SYSTEM_STORE_CURRENT_USER, NULL, &c, sss_cb_store));
    CHECK(!sss_has(&c, nm));
}
TEST(sss_open_nonexistent_lm_not_enumerated_after) {
    REQUIRE(U(CertOpenStore)); REQUIRE(U(CertEnumSystemStore));
    wchar_t nm[64]; sss_wuniq(nm, 64, L"nocreatelm");
    HCERTSTORE h = U(CertOpenStore)(CERT_STORE_PROV_SYSTEM_W, 0, 0, CERT_SYSTEM_STORE_LOCAL_MACHINE | OPEN_RO2, nm);
    CHECK(h == NULL);
    if (h) U(CertCloseStore)(h, 0);
    sss_cap_t c; memset(&c, 0, sizeof c);
    CHECK(U(CertEnumSystemStore)(CERT_SYSTEM_STORE_LOCAL_MACHINE, NULL, &c, sss_cb_store));
    CHECK(!sss_has(&c, nm));
}
TEST(sss_open_every_enumerated_lm_store_readonly_note) {
    REQUIRE(U(CertEnumSystemStore)); REQUIRE(U(CertOpenStore)); REQUIRE(U(CertCloseStore));
    sss_cap_t c; memset(&c, 0, sizeof c);
    CHECK(U(CertEnumSystemStore)(CERT_SYSTEM_STORE_LOCAL_MACHINE, NULL, &c, sss_cb_store));
    for (int i = 0; i < c.n && i < 64; i++) {
        HCERTSTORE h = U(CertOpenStore)(CERT_STORE_PROV_SYSTEM_W, 0, 0, CERT_SYSTEM_STORE_LOCAL_MACHINE | OPEN_RO2, c.names[i]);
        t_label("%ls", c.names[i]);
        CHECK(h != NULL); /* probed std and adm: every enumerated LocalMachine store opens read only */
        if (h) U(CertCloseStore)(h, 0);
    }
}
TEST(sss_open_predefined_names_cu_openable_readonly) {
    REQUIRE(U(CertOpenStore)); REQUIRE(U(CertCloseStore));
    static const wchar_t *n[] = { L"Root", L"My", L"CA" };
    for (int i = 0; i < 3; i++) {
        HCERTSTORE h = U(CertOpenStore)(CERT_STORE_PROV_SYSTEM_W, 0, 0, CERT_SYSTEM_STORE_CURRENT_USER | OPEN_RO2, n[i]);
        t_label("%ls", n[i]);
        CHECKF(h != NULL, "gle=%lu", GetLastError());
        if (h) U(CertCloseStore)(h, 0);
    }
}
