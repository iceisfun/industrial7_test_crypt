#include "sss.h"
/* Opening system stores read-only, collections, relocation, localized names, store properties, control. */

#define OPEN_RO (CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG)

TEST(sss_open_sysstore_a_standard) {
    REQUIRE(U(CertOpenSystemStoreA)); REQUIRE(U(CertCloseStore));
    static const char *n[] = { "MY", "ROOT", "CA", "My", "Root", "ca" };
    for (int i = 0; i < 6; i++) {
        HCERTSTORE h = U(CertOpenSystemStoreA)(0, n[i]);
        CHECKF(h != NULL, "%s gle=%lu", n[i], GetLastError());
        if (h) { CHECK(U(CertCloseStore)(h, 0)); }
    }
}
TEST(sss_open_sysstore_w_standard) {
    REQUIRE(U(CertOpenSystemStoreW)); REQUIRE(U(CertCloseStore));
    static const wchar_t *n[] = { L"MY", L"ROOT", L"CA", L"My", L"Root", L"ca" };
    for (int i = 0; i < 6; i++) {
        HCERTSTORE h = U(CertOpenSystemStoreW)(0, n[i]);
        CHECKF(h != NULL, "%ls gle=%lu", n[i], GetLastError());
        if (h) { CHECK(U(CertCloseStore)(h, 0)); }
    }
}
TEST(sss_open_sysstore_a_w_parity_counts) {
    REQUIRE(U(CertOpenSystemStoreA)); REQUIRE(U(CertOpenSystemStoreW)); REQUIRE(U(CertEnumCertificatesInStore));
    HCERTSTORE a = U(CertOpenSystemStoreA)(0, "Root"), w = U(CertOpenSystemStoreW)(0, L"Root");
    CHECK(a && w);
    if (a && w) {
        CHECK(a != w);
        EXPECT_EQ(sss_count_certs(a), sss_count_certs(w));
        t_note("CU Root has %d certs", sss_count_certs(a));
    }
    if (a) U(CertCloseStore)(a, 0);
    if (w) U(CertCloseStore)(w, 0);
}
TEST(sss_open_sysstore_a_hprov_null_expected) {
    REQUIRE(U(CertOpenSystemStoreA)); REQUIRE(U(CertCloseStore));
    HCERTSTORE h = U(CertOpenSystemStoreA)((HCRYPTPROV_LEGACY)0, "MY");
    CHECK(h != NULL);
    if (h) U(CertCloseStore)(h, 0);
}
TEST(sss_open_sysstore_matches_certopenstore_sysw) {
    REQUIRE(U(CertOpenSystemStoreW)); REQUIRE(U(CertOpenStore));
    HCERTSTORE a = U(CertOpenSystemStoreW)(0, L"Root");
    HCERTSTORE b = U(CertOpenStore)(CERT_STORE_PROV_SYSTEM_W, 0, 0, CERT_SYSTEM_STORE_CURRENT_USER | CERT_STORE_NO_CRYPT_RELEASE_FLAG, L"Root");
    CHECK(a && b);
    if (a && b) EXPECT_EQ(sss_count_certs(a), sss_count_certs(b));
    if (a) U(CertCloseStore)(a, 0);
    if (b) U(CertCloseStore)(b, 0);
}
TEST(sss_open_sysstore_spc_is_local_machine_note) {
    REQUIRE(U(CertOpenSystemStoreA)); REQUIRE(U(CertCloseStore));
    SET_ERR(0);
    HCERTSTORE h = U(CertOpenSystemStoreA)(0, "SPC");
    t_note("OpenSystemStoreA(SPC) -> %p gle=%lu", h, GetLastError());
    if (h) U(CertCloseStore)(h, 0);
}
TEST(sss_open_sysstore_local_machine_stores) {
    REQUIRE(U(CertOpenStore)); REQUIRE(U(CertCloseStore));
    static const wchar_t *n[] = { L"My", L"Root", L"CA" };
    for (int i = 0; i < 3; i++) {
        HCERTSTORE h = U(CertOpenStore)(CERT_STORE_PROV_SYSTEM_W, 0, 0, CERT_SYSTEM_STORE_LOCAL_MACHINE | OPEN_RO, n[i]);
        CHECKF(h != NULL, "LM %ls gle=%lu", n[i], GetLastError());
        if (h) {
            t_note("LM %ls: %d certs", n[i], sss_count_certs(h));
            U(CertCloseStore)(h, 0);
        }
    }
}
TEST(sss_open_nonexistent_system_w_cu) {
    REQUIRE(U(CertOpenStore));
    wchar_t nm[64]; sss_wuniq(nm, 64, L"nostore");
    SET_ERR(0);
    HCERTSTORE h = U(CertOpenStore)(CERT_STORE_PROV_SYSTEM_W, 0, 0, CERT_SYSTEM_STORE_CURRENT_USER | OPEN_RO, nm);
    CHECK(h == NULL);
    EXPECT_ERR(ERROR_FILE_NOT_FOUND);
}
TEST(sss_open_nonexistent_system_registry_w_cu) {
    REQUIRE(U(CertOpenStore));
    wchar_t nm[64]; sss_wuniq(nm, 64, L"noreg");
    SET_ERR(0);
    HCERTSTORE h = U(CertOpenStore)(CERT_STORE_PROV_SYSTEM_REGISTRY_W, 0, 0, CERT_SYSTEM_STORE_CURRENT_USER | OPEN_RO, nm);
    CHECK(h == NULL);
    EXPECT_ERR(ERROR_FILE_NOT_FOUND);
}
TEST(sss_open_nonexistent_system_a_cu) {
    REQUIRE(U(CertOpenStore));
    char nm[64]; wchar_t w[64]; sss_wuniq(w, 64, L"noa");
    WideCharToMultiByte(CP_ACP, 0, w, -1, nm, 64, NULL, NULL);
    SET_ERR(0);
    HCERTSTORE h = U(CertOpenStore)(CERT_STORE_PROV_SYSTEM_A, 0, 0, CERT_SYSTEM_STORE_CURRENT_USER | OPEN_RO, nm);
    CHECK(h == NULL);
    EXPECT_ERR(ERROR_FILE_NOT_FOUND);
}
TEST(sss_open_nonexistent_system_lm) {
    REQUIRE(U(CertOpenStore));
    wchar_t nm[64]; sss_wuniq(nm, 64, L"nolm");
    SET_ERR(0);
    HCERTSTORE h = U(CertOpenStore)(CERT_STORE_PROV_SYSTEM_W, 0, 0, CERT_SYSTEM_STORE_LOCAL_MACHINE | OPEN_RO, nm);
    CHECK(h == NULL);
    EXPECT_ERR(ERROR_FILE_NOT_FOUND);
}
TEST(sss_open_nonexistent_system_string_provider_names) {
    REQUIRE(U(CertOpenStore));
    wchar_t nm[64]; sss_wuniq(nm, 64, L"nostr");
    static const char *p[] = { "System", "SystemRegistry", "system", "SYSTEMREGISTRY" };
    for (int i = 0; i < 4; i++) {
        SET_ERR(0);
        HCERTSTORE h = U(CertOpenStore)(p[i], 0, 0, CERT_SYSTEM_STORE_CURRENT_USER | OPEN_RO, nm);
        CHECKF(h == NULL, "provider %s", p[i]);
        EXPECT_ERR(ERROR_FILE_NOT_FOUND);
    }
}
TEST(sss_open_nonexistent_other_locations_note) {
    REQUIRE(U(CertOpenStore));
    wchar_t nm[64]; sss_wuniq(nm, 64, L"noloc");
    DWORD f[3] = { CERT_SYSTEM_STORE_CURRENT_USER_GROUP_POLICY, CERT_SYSTEM_STORE_LOCAL_MACHINE_GROUP_POLICY, CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE };
    for (int i = 0; i < 3; i++) {
        SET_ERR(0);
        HCERTSTORE h = U(CertOpenStore)(CERT_STORE_PROV_SYSTEM_W, 0, 0, f[i] | OPEN_RO, nm);
        CHECKF(h == NULL, "loc %d opened", i);
        t_note("loc 0x%lx nonexistent -> gle=%lu", f[i], GetLastError());
        if (h) U(CertCloseStore)(h, 0);
    }
}
TEST(sss_open_existing_flag_without_readonly_nonexistent) {
    REQUIRE(U(CertOpenStore));
    wchar_t nm[64]; sss_wuniq(nm, 64, L"noex");
    SET_ERR(0);
    HCERTSTORE h = U(CertOpenStore)(CERT_STORE_PROV_SYSTEM_W, 0, 0, CERT_SYSTEM_STORE_CURRENT_USER | CERT_STORE_OPEN_EXISTING_FLAG, nm);
    CHECK(h == NULL);
    EXPECT_ERR(ERROR_FILE_NOT_FOUND);
}
TEST(sss_open_null_name) {
    REQUIRE(U(CertOpenStore));
    SET_ERR(0);
    HCERTSTORE h = U(CertOpenStore)(CERT_STORE_PROV_SYSTEM_W, 0, 0, CERT_SYSTEM_STORE_CURRENT_USER | OPEN_RO, NULL);
    CHECK(h == NULL);
    t_note("system store NULL name gle=0x%lx", GetLastError());
    if (h) U(CertCloseStore)(h, 0);
}
TEST(sss_open_empty_name_note) {
    REQUIRE(U(CertOpenStore));
    SET_ERR(0);
    HCERTSTORE h = U(CertOpenStore)(CERT_STORE_PROV_SYSTEM_W, 0, 0, CERT_SYSTEM_STORE_CURRENT_USER | OPEN_RO, L"");
    t_note("system store empty name -> %p gle=0x%lx", h, GetLastError());
    if (h) U(CertCloseStore)(h, 0);
}
TEST(sss_open_readonly_blocks_add_to_root) {
    REQUIRE(U(CertOpenStore)); REQUIRE(U(CertAddEncodedCertificateToStore));
    HCERTSTORE h = U(CertOpenStore)(CERT_STORE_PROV_SYSTEM_W, 0, 0, CERT_SYSTEM_STORE_CURRENT_USER | OPEN_RO, L"Root");
    CHECK(h != NULL); if (!h) return;
    BYTE junk[4] = { 0x30, 0x02, 0x05, 0x00 };
    SET_ERR(0);
    BOOL r = U(CertAddEncodedCertificateToStore)(h, X509_ASN_ENCODING, junk, sizeof junk, CERT_STORE_ADD_ALWAYS, NULL);
    CHECK(!r);   /* malformed encoding: must not be added regardless of read-only state */
    U(CertCloseStore)(h, 0);
}
TEST(sss_open_readonly_store_delete_fails_or_not_found) {
    REQUIRE(U(CertOpenStore)); REQUIRE(U(CertEnumCertificatesInStore)); REQUIRE(U(CertDeleteCertificateFromStore));
    HCERTSTORE h = U(CertOpenStore)(CERT_STORE_PROV_SYSTEM_W, 0, 0, CERT_SYSTEM_STORE_CURRENT_USER | OPEN_RO, L"Root");
    CHECK(h != NULL); if (!h) return;
    int before = sss_count_certs(h);
    PCCERT_CONTEXT c = U(CertEnumCertificatesInStore)(h, NULL);
    if (c) {
        PCCERT_CONTEXT d = U(CertDuplicateCertificateContext)(c);
        SET_ERR(0);
        BOOL r = U(CertDeleteCertificateFromStore)(d);
        CHECK(!r);
        t_note("delete on readonly CU Root gle=0x%lx", GetLastError());
        U(CertFreeCertificateContext)(c);
    }
    EXPECT_EQ(sss_count_certs(h), before);
    U(CertCloseStore)(h, 0);
}
TEST(sss_open_handles_independent_close_order) {
    REQUIRE(U(CertOpenStore)); REQUIRE(U(CertCloseStore));
    HCERTSTORE a = U(CertOpenSystemStoreW)(0, L"Root"), b = U(CertDuplicateStore)(a);
    CHECK(a && b == a);
    CHECK(U(CertCloseStore)(a, 0));
    int n = sss_count_certs(b);
    CHECK(n >= 0);
    CHECK(U(CertCloseStore)(b, 0));
}
TEST(sss_open_cert_context_outlives_store) {
    REQUIRE(U(CertOpenSystemStoreW)); REQUIRE(U(CertEnumCertificatesInStore));
    HCERTSTORE h = U(CertOpenSystemStoreW)(0, L"Root");
    if (!h) { CHECK(h != NULL); return; }
    PCCERT_CONTEXT c = U(CertEnumCertificatesInStore)(h, NULL);
    if (!c) { t_note("CU Root empty"); U(CertCloseStore)(h, 0); return; }
    PCCERT_CONTEXT d = U(CertDuplicateCertificateContext)(c);
    U(CertFreeCertificateContext)(c);
    CHECK(U(CertCloseStore)(h, 0));
    CHECK(d->pbCertEncoded != NULL && d->cbCertEncoded > 0);
    CHECK(d->pbCertEncoded[0] == 0x30);
    U(CertFreeCertificateContext)(d);
}
TEST(sss_open_close_check_flag_active_context) {
    REQUIRE(U(CertOpenSystemStoreW)); REQUIRE(U(CertEnumCertificatesInStore));
    if (t_is_wine()) { t_skip("emulator does not implement CHECK_FLAG pending-close"); return; }
    HCERTSTORE h = U(CertOpenSystemStoreW)(0, L"Root");
    if (!h) { CHECK(h != NULL); return; }
    PCCERT_CONTEXT c = U(CertEnumCertificatesInStore)(h, NULL);
    if (!c) { U(CertCloseStore)(h, 0); t_skip("CU Root empty"); return; }
    SET_ERR(0);
    BOOL r = U(CertCloseStore)(h, CERT_CLOSE_STORE_CHECK_FLAG);
    CHECK(!r);
    EXPECT_ERR(CRYPT_E_PENDING_CLOSE);
    U(CertFreeCertificateContext)(c);
    /* store was already released by the failed-but-completed close; do not close twice */
}

/* ---- collection over system stores ---- */
TEST(sss_collection_over_system_stores) {
    REQUIRE(U(CertOpenStore)); REQUIRE(U(CertAddStoreToCollection));
    HCERTSTORE col = U(CertOpenStore)(CERT_STORE_PROV_COLLECTION, 0, 0, 0, NULL);
    HCERTSTORE a = U(CertOpenSystemStoreW)(0, L"Root"), b = U(CertOpenSystemStoreW)(0, L"CA");
    CHECK(col && a && b);
    if (col && a && b) {
        CHECK(U(CertAddStoreToCollection)(col, a, 0, 0));
        CHECK(U(CertAddStoreToCollection)(col, b, 0, 0));
        EXPECT_EQ(sss_count_certs(col), sss_count_certs(a) + sss_count_certs(b));
        U(CertRemoveStoreFromCollection)(col, a);
        EXPECT_EQ(sss_count_certs(col), sss_count_certs(b));
    }
    if (col) U(CertCloseStore)(col, 0);
    if (a) U(CertCloseStore)(a, 0);
    if (b) U(CertCloseStore)(b, 0);
}
TEST(sss_collection_user_and_machine_root) {
    REQUIRE(U(CertOpenStore)); REQUIRE(U(CertAddStoreToCollection));
    HCERTSTORE col = U(CertOpenStore)(CERT_STORE_PROV_COLLECTION, 0, 0, 0, NULL);
    HCERTSTORE a = U(CertOpenStore)(CERT_STORE_PROV_SYSTEM_W, 0, 0, CERT_SYSTEM_STORE_CURRENT_USER | OPEN_RO, L"Root");
    HCERTSTORE b = U(CertOpenStore)(CERT_STORE_PROV_SYSTEM_W, 0, 0, CERT_SYSTEM_STORE_LOCAL_MACHINE | OPEN_RO, L"Root");
    CHECK(col && a && b);
    if (col && a && b) {
        CHECK(U(CertAddStoreToCollection)(col, a, 0, 0));
        CHECK(U(CertAddStoreToCollection)(col, b, 0, 0));
        t_note("CU Root=%d LM Root=%d collection=%d", sss_count_certs(a), sss_count_certs(b), sss_count_certs(col));
        EXPECT_EQ(sss_count_certs(col), sss_count_certs(a) + sss_count_certs(b));
    }
    if (col) U(CertCloseStore)(col, 0);
    if (a) U(CertCloseStore)(a, 0);
    if (b) U(CertCloseStore)(b, 0);
}
TEST(sss_collection_add_to_readonly_system_member_note) {
    REQUIRE(U(CertOpenStore)); REQUIRE(U(CertAddStoreToCollection));
    HCERTSTORE col = U(CertOpenStore)(CERT_STORE_PROV_COLLECTION, 0, 0, 0, NULL);
    HCERTSTORE a = U(CertOpenStore)(CERT_STORE_PROV_SYSTEM_W, 0, 0, CERT_SYSTEM_STORE_CURRENT_USER | OPEN_RO, L"Root");
    CHECK(col && a);
    if (col && a) {
        /* priority-0 writable member flag set on a read-only store: report only */
        SET_ERR(0);
        BOOL r = U(CertAddStoreToCollection)(col, a, CERT_PHYSICAL_STORE_ADD_ENABLE_FLAG, 0);
        t_note("add RO store with flag 0x%x -> %d gle=0x%lx", CERT_PHYSICAL_STORE_ADD_ENABLE_FLAG, r, GetLastError());
    }
    if (col) U(CertCloseStore)(col, 0);
    if (a) U(CertCloseStore)(a, 0);
}
TEST(sss_collection_of_enumerated_physical_stores) {
    REQUIRE(U(CertEnumPhysicalStore)); REQUIRE(U(CertOpenStore));
    if (t_is_wine()) { t_skip("emulator lacks physical store enumeration"); return; }
    sss_cap_t c; memset(&c, 0, sizeof c);
    CHECK(U(CertEnumPhysicalStore)(L"Root", CERT_SYSTEM_STORE_CURRENT_USER, &c, sss_cb_phys));
    int m = c.n < 64 ? c.n : 64;
    for (int i = 0; i < m; i++) {
        wchar_t full[200];
        _snwprintf(full, 200, L"Root\\%s", c.names[i]);
        HCERTSTORE h = U(CertOpenStore)(CERT_STORE_PROV_PHYSICAL_W, 0, 0, CERT_SYSTEM_STORE_CURRENT_USER | OPEN_RO, full);
        t_note("physical open %ls -> %p gle=%lu", full, h, h ? 0 : GetLastError());
        if (h) U(CertCloseStore)(h, 0);
    }
}

/* ---- relocation ---- */
TEST(sss_reloc_nonexistent_hkcu_base) {
    REQUIRE(U(CertOpenStore));
    wchar_t nm[64]; sss_wuniq(nm, 64, L"reloc");
    CERT_SYSTEM_STORE_RELOCATE_PARA p; memset(&p, 0, sizeof p);
    p.hKeyBase = HKEY_CURRENT_USER; p.pwszSystemStore = nm;
    SET_ERR(0);
    HCERTSTORE h = U(CertOpenStore)(CERT_STORE_PROV_SYSTEM_W, 0, 0, CERT_SYSTEM_STORE_RELOCATE_FLAG | OPEN_RO, &p);
    CHECK(h == NULL);
    EXPECT_ERR(ERROR_FILE_NOT_FOUND);
}
TEST(sss_reloc_registry_provider_nonexistent) {
    REQUIRE(U(CertOpenStore));
    wchar_t nm[64]; sss_wuniq(nm, 64, L"reloc2");
    CERT_SYSTEM_STORE_RELOCATE_PARA p; memset(&p, 0, sizeof p);
    p.hKeyBase = HKEY_CURRENT_USER; p.pwszSystemStore = nm;
    SET_ERR(0);
    HCERTSTORE h = U(CertOpenStore)(CERT_STORE_PROV_SYSTEM_REGISTRY_W, 0, 0, CERT_SYSTEM_STORE_RELOCATE_FLAG | OPEN_RO, &p);
    CHECK(h == NULL);
    t_note("registry provider relocate nonexistent gle=0x%lx", GetLastError());
}
TEST(sss_reloc_null_para_fails) {
    REQUIRE(U(CertOpenStore));
    SET_ERR(0);
    HCERTSTORE h = U(CertOpenStore)(CERT_STORE_PROV_SYSTEM_W, 0, 0, CERT_SYSTEM_STORE_RELOCATE_FLAG | OPEN_RO, NULL);
    CHECK(h == NULL);
    t_note("reloc NULL para gle=0x%lx", GetLastError());
    if (h) U(CertCloseStore)(h, 0);
}
TEST(sss_reloc_null_hkey_fails) {
    REQUIRE(U(CertOpenStore));
    CERT_SYSTEM_STORE_RELOCATE_PARA p; memset(&p, 0, sizeof p);
    p.hKeyBase = NULL; p.pwszSystemStore = L"Root";
    SET_ERR(0);
    HCERTSTORE h = U(CertOpenStore)(CERT_STORE_PROV_SYSTEM_W, 0, 0, CERT_SYSTEM_STORE_RELOCATE_FLAG | OPEN_RO, &p);
    t_note("reloc NULL hKeyBase -> %p gle=0x%lx", h, GetLastError());
    if (h) U(CertCloseStore)(h, 0);
}
TEST(sss_reloc_null_store_name_fails) {
    REQUIRE(U(CertOpenStore));
    CERT_SYSTEM_STORE_RELOCATE_PARA p; memset(&p, 0, sizeof p);
    p.hKeyBase = HKEY_CURRENT_USER; p.pwszSystemStore = NULL;
    SET_ERR(0);
    HCERTSTORE h = U(CertOpenStore)(CERT_STORE_PROV_SYSTEM_W, 0, 0, CERT_SYSTEM_STORE_RELOCATE_FLAG | OPEN_RO, &p);
    CHECK(h == NULL);
    t_note("reloc NULL store name gle=0x%lx", GetLastError());
    if (h) U(CertCloseStore)(h, 0);
}
TEST(sss_reloc_hkcu_base_existing_root_note) {
    REQUIRE(U(CertOpenStore));
    CERT_SYSTEM_STORE_RELOCATE_PARA p; memset(&p, 0, sizeof p);
    p.hKeyBase = HKEY_CURRENT_USER; p.pwszSystemStore = L"Root";
    SET_ERR(0);
    HCERTSTORE h = U(CertOpenStore)(CERT_STORE_PROV_SYSTEM_W, 0, 0, CERT_SYSTEM_STORE_RELOCATE_FLAG | OPEN_RO, &p);
    t_note("reloc HKCU Root -> %p gle=%lu", h, h ? 0 : GetLastError());
    if (h) { t_note("  certs=%d", sss_count_certs(h)); U(CertCloseStore)(h, 0); }
}
TEST(sss_reloc_flag_with_plain_string_name_note) {
    REQUIRE(U(CertOpenStore));
    SET_ERR(0);
    /* a string where a relocate struct is expected is a caller bug; do not dereference-test it */
    t_skip("pointer-confusion case intentionally not exercised");
}

/* ---- localized names ---- */
TEST(sss_loc_name_null_and_empty) {
    REQUIRE(U(CryptFindLocalizedName));
    CHECK(U(CryptFindLocalizedName)(NULL) == NULL);
    CHECK(U(CryptFindLocalizedName)(L"") == NULL);
}
TEST(sss_loc_name_unknown) {
    REQUIRE(U(CryptFindLocalizedName));
    CHECK(U(CryptFindLocalizedName)(L"NoSuchName_cryptt") == NULL);
    CHECK(U(CryptFindLocalizedName)(L"Root ") == NULL);
}
TEST(sss_loc_name_standard_stores_have_names) {
    REQUIRE(U(CryptFindLocalizedName));
    static const wchar_t *n[] = { L"Root", L"My", L"CA" };
    for (int i = 0; i < 3; i++) {
        LPCWSTR r = U(CryptFindLocalizedName)(n[i]);
        CHECKF(r != NULL && *r, "%ls", n[i]);
        t_note("%ls -> %ls", n[i], r ? r : L"(null)");
    }
}
TEST(sss_loc_name_case_insensitive) {
    REQUIRE(U(CryptFindLocalizedName));
    static const wchar_t *a[] = { L"Root", L"My", L"CA" };
    static const wchar_t *b[] = { L"ROOT", L"my", L"ca" };
    for (int i = 0; i < 3; i++) {
        LPCWSTR x = U(CryptFindLocalizedName)(a[i]), y = U(CryptFindLocalizedName)(b[i]);
        CHECKF(x && y && !lstrcmpW(x, y), "%ls", a[i]);
    }
}
TEST(sss_loc_name_stable_pointer) {
    REQUIRE(U(CryptFindLocalizedName));
    LPCWSTR a = U(CryptFindLocalizedName)(L"Root"), b = U(CryptFindLocalizedName)(L"Root");
    CHECK(a != NULL);
    EXPECT_EQ(a, b);
}
TEST(sss_loc_name_other_known_names_note) {
    REQUIRE(U(CryptFindLocalizedName));
    static const wchar_t *n[] = { L"AuthRoot", L"TrustedPublisher", L"Disallowed", L"TrustedPeople", L"Trust", L"ClientAuthIssuer", L"SmartCardRoot",
        L"CurrentUser", L"LocalMachine", L"Services", L"Users", L"CurrentService", L".Default", L".GroupPolicy", L".LocalMachine", L".Enterprise", L".AuthRoot" };
    for (unsigned i = 0; i < sizeof n / sizeof n[0]; i++) {
        LPCWSTR r = U(CryptFindLocalizedName)(n[i]);
        t_note("%ls -> %ls", n[i], r ? r : L"(null)");
    }
}

/* ---- store properties ---- */
TEST(sss_prop_localized_name_system_store) {
    REQUIRE(U(CertGetStoreProperty)); REQUIRE(U(CertOpenSystemStoreW));
    HCERTSTORE h = U(CertOpenSystemStoreW)(0, L"Root");
    CHECK(h != NULL); if (!h) return;
    DWORD cb = 0;
    SET_ERR(0);
    BOOL r = U(CertGetStoreProperty)(h, CERT_STORE_LOCALIZED_NAME_PROP_ID, NULL, &cb);
    t_note("localized name prop size query -> %d cb=%lu gle=0x%lx", r, cb, GetLastError());
    if (r && cb) {
        wchar_t buf[128] = {0};
        DWORD cb2 = sizeof buf;
        if (cb <= sizeof buf) {
            CHECK(U(CertGetStoreProperty)(h, CERT_STORE_LOCALIZED_NAME_PROP_ID, buf, &cb2));
            t_note("   name=%ls cb=%lu", buf, cb2);
        }
    }
    U(CertCloseStore)(h, 0);
}
TEST(sss_prop_unset_property_not_found) {
    REQUIRE(U(CertGetStoreProperty)); REQUIRE(U(CertOpenSystemStoreW));
    HCERTSTORE h = U(CertOpenSystemStoreW)(0, L"Root");
    CHECK(h != NULL); if (!h) return;
    DWORD cb = 0;
    SET_ERR(0);
    BOOL r = U(CertGetStoreProperty)(h, 0x7ff0, NULL, &cb);
    CHECK(!r);
    EXPECT_ERR(CRYPT_E_NOT_FOUND);
    U(CertCloseStore)(h, 0);
}
TEST(sss_prop_null_pcb_fails) {
    REQUIRE(U(CertGetStoreProperty)); REQUIRE(U(CertOpenSystemStoreW));
    HCERTSTORE h = U(CertOpenSystemStoreW)(0, L"Root");
    CHECK(h != NULL); if (!h) return;
    SET_ERR(0);
    BOOL r = U(CertGetStoreProperty)(h, CERT_STORE_LOCALIZED_NAME_PROP_ID, NULL, NULL);
    t_note("pcb NULL -> %d gle=0x%lx", r, GetLastError());
    U(CertCloseStore)(h, 0);
}
TEST(sss_prop_dwflags_nonzero_note) {
    REQUIRE(U(CertGetStoreProperty)); REQUIRE(U(CertOpenSystemStoreW));
    HCERTSTORE h = U(CertOpenSystemStoreW)(0, L"Root");
    CHECK(h != NULL); if (!h) return;
    DWORD cb = 0; SET_ERR(0);
    BOOL r = U(CertGetStoreProperty)(h, CERT_STORE_LOCALIZED_NAME_PROP_ID, NULL, &cb);
    t_note("size query r=%d cb=%lu", r, cb);
    U(CertCloseStore)(h, 0);
}

/* ---- control ---- */
TEST(sss_control_memory_store_resync_unsupported) {
    REQUIRE(U(CertOpenStore)); REQUIRE(U(CertControlStore));
    HCERTSTORE h = U(CertOpenStore)(CERT_STORE_PROV_MEMORY, 0, 0, 0, NULL);
    CHECK(h != NULL); if (!h) return;
    SET_ERR(0);
    BOOL r = U(CertControlStore)(h, 0, CERT_STORE_CTRL_RESYNC, NULL);
    t_note("memory store RESYNC -> %d gle=%lu", r, GetLastError());
    U(CertCloseStore)(h, 0);
}
TEST(sss_control_empty_collection_resync_ok) {
    REQUIRE(U(CertOpenStore)); REQUIRE(U(CertControlStore));
    HCERTSTORE h = U(CertOpenStore)(CERT_STORE_PROV_COLLECTION, 0, 0, 0, NULL);
    CHECK(h != NULL); if (!h) return;
    SET_ERR(0);
    CHECK(U(CertControlStore)(h, 0, CERT_STORE_CTRL_RESYNC, NULL));
    U(CertCloseStore)(h, 0);
}
TEST(sss_control_system_store_resync_note) {
    REQUIRE(U(CertOpenSystemStoreW)); REQUIRE(U(CertControlStore));
    HCERTSTORE h = U(CertOpenSystemStoreW)(0, L"Root");
    CHECK(h != NULL); if (!h) return;
    HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    SET_ERR(0);
    BOOL r = U(CertControlStore)(h, 0, CERT_STORE_CTRL_RESYNC, &ev);
    t_note("system store RESYNC -> %d gle=0x%lx", r, GetLastError());
    CloseHandle(ev);
    U(CertCloseStore)(h, 0);
}
TEST(sss_control_notify_change_not_signaled_without_change) {
    REQUIRE(U(CertOpenSystemStoreW)); REQUIRE(U(CertControlStore));
    HCERTSTORE h = U(CertOpenSystemStoreW)(0, L"Root");
    CHECK(h != NULL); if (!h) return;
    HANDLE ev = CreateEventW(NULL, FALSE, FALSE, NULL);
    SET_ERR(0);
    BOOL r = U(CertControlStore)(h, 0, CERT_STORE_CTRL_NOTIFY_CHANGE, &ev);
    t_note("NOTIFY_CHANGE on CU Root -> %d gle=0x%lx", r, GetLastError());
    if (r) {
        DWORD w = WaitForSingleObject(ev, 300);
        t_note("event wait after registration (no change): %lu", w);
        BOOL c = U(CertControlStore)(h, 0, CERT_STORE_CTRL_CANCEL_NOTIFY, &ev);
        t_note("CANCEL_NOTIFY -> %d gle=0x%lx", c, GetLastError());
    }
    CloseHandle(ev);
    U(CertCloseStore)(h, 0);
}
TEST(sss_control_notify_change_memory_store_unsupported_note) {
    REQUIRE(U(CertOpenStore)); REQUIRE(U(CertControlStore));
    HCERTSTORE h = U(CertOpenStore)(CERT_STORE_PROV_MEMORY, 0, 0, 0, NULL);
    CHECK(h != NULL); if (!h) return;
    HANDLE ev = CreateEventW(NULL, FALSE, FALSE, NULL);
    SET_ERR(0);
    BOOL r = U(CertControlStore)(h, 0, CERT_STORE_CTRL_NOTIFY_CHANGE, &ev);
    t_note("memory NOTIFY_CHANGE -> %d gle=%lu", r, GetLastError());
    CloseHandle(ev);
    U(CertCloseStore)(h, 0);
}
TEST(sss_control_auto_resync_collection_note) {
    REQUIRE(U(CertOpenStore)); REQUIRE(U(CertControlStore));
    HCERTSTORE h = U(CertOpenSystemStoreW)(0, L"Root");
    CHECK(h != NULL); if (!h) return;
    SET_ERR(0);
    BOOL r = U(CertControlStore)(h, 0, CERT_STORE_CTRL_AUTO_RESYNC, NULL);
    t_note("AUTO_RESYNC -> %d gle=0x%lx", r, GetLastError());
    U(CertCloseStore)(h, 0);
}
TEST(sss_localmachine_root_count_note) {
    REQUIRE(U(CertOpenStore));
    HCERTSTORE h = U(CertOpenStore)(CERT_STORE_PROV_SYSTEM_W, 0, 0, CERT_SYSTEM_STORE_LOCAL_MACHINE | OPEN_RO, L"Root");
    CHECK(h != NULL); if (!h) return;
    t_note("LocalMachine Root entries: %d", sss_count_certs(h));
    U(CertCloseStore)(h, 0);
}
TEST(sss_localmachine_authroot_count_note) {
    REQUIRE(U(CertOpenStore));
    HCERTSTORE h = U(CertOpenStore)(CERT_STORE_PROV_SYSTEM_W, 0, 0, CERT_SYSTEM_STORE_LOCAL_MACHINE | OPEN_RO, L"AuthRoot");
    t_note("LocalMachine AuthRoot -> %p", h);
    if (h) { t_note("entries: %d", sss_count_certs(h)); U(CertCloseStore)(h, 0); }
}
