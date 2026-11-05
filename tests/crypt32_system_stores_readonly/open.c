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
/* display names are language dependent: pinned exactly only on an English UI (the oracle), where Win10 gives the strings below */
static void sss_pin_en(LPCWSTR got, LPCWSTR want) {
    if ((GetUserDefaultUILanguage() & 0xFF) == 0x09) { CHECKF(got && !lstrcmpW(got, want), "got %ls want %ls", got ? got : L"(null)", want); }
    else CHECK(got != NULL && *got);
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
    /* probed std and adm: "SPC" is the LocalMachine store of that name, which a non-elevated process cannot open for write (ERROR_ACCESS_DENIED) */
    DWORD e = GetLastError();
    if (t_is_elevated()) { CHECK(h != NULL); } else { CHECK(h == NULL); EXPECT_EQ(e, ERROR_ACCESS_DENIED); }
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
        t_label("loc 0x%lx", f[i]);
        EXPECT_ERR(ERROR_FILE_NOT_FOUND); /* probed std and adm */
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
    EXPECT_ERR(SSS_E_INVALIDARG); /* probed std and adm */
    if (h) U(CertCloseStore)(h, 0);
}
TEST(sss_open_empty_name_note) {
    REQUIRE(U(CertOpenStore));
    SET_ERR(0);
    HCERTSTORE h = U(CertOpenStore)(CERT_STORE_PROV_SYSTEM_W, 0, 0, CERT_SYSTEM_STORE_CURRENT_USER | OPEN_RO, L"");
    EXPECT_EQ(h == NULL, 1); EXPECT_ERR(SSS_E_INVALIDARG); /* probed std and adm */
    if (h) U(CertCloseStore)(h, 0);
}
TEST(sss_open_handles_independent_close_order) {
    REQUIRE(U(CertOpenSystemStoreW)); REQUIRE(U(CertCloseStore)); REQUIRE(U(CertDuplicateStore));
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
    CHECK(c != NULL); /* probed std and adm: CurrentUser Root is never empty */
    if (!c) { U(CertCloseStore)(h, 0); return; }
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
    CHECK(c != NULL); /* probed std and adm: CurrentUser Root is never empty */
    if (!c) { U(CertCloseStore)(h, 0); return; }
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
        EXPECT_EQ(r, 1); /* probed std and adm: accepted; the flag only matters for later writes */
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
        t_label("%ls", full);
        CHECKF(h != NULL, "gle=%lu", GetLastError()); /* probed std and adm: every enumerated physical store opens by its Name\\Physical path */
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
    EXPECT_ERR(SSS_E_INVALIDARG); /* probed std and adm: the registry provider rejects the relocate flag */
}
TEST(sss_reloc_null_para_fails) {
    REQUIRE(U(CertOpenStore));
    SET_ERR(0);
    HCERTSTORE h = U(CertOpenStore)(CERT_STORE_PROV_SYSTEM_W, 0, 0, CERT_SYSTEM_STORE_RELOCATE_FLAG | OPEN_RO, NULL);
    CHECK(h == NULL);
    EXPECT_ERR(ERROR_FILE_NOT_FOUND); /* probed std and adm */
    if (h) U(CertCloseStore)(h, 0);
}
TEST(sss_reloc_null_hkey_fails) {
    REQUIRE(U(CertOpenStore));
    CERT_SYSTEM_STORE_RELOCATE_PARA p; memset(&p, 0, sizeof p);
    p.hKeyBase = NULL; p.pwszSystemStore = L"Root";
    SET_ERR(0);
    HCERTSTORE h = U(CertOpenStore)(CERT_STORE_PROV_SYSTEM_W, 0, 0, CERT_SYSTEM_STORE_RELOCATE_FLAG | OPEN_RO, &p);
    CHECK(h == NULL);
    EXPECT_ERR(ERROR_FILE_NOT_FOUND); /* probed std and adm */
    if (h) U(CertCloseStore)(h, 0);
}
TEST(sss_reloc_null_store_name_fails) {
    REQUIRE(U(CertOpenStore));
    CERT_SYSTEM_STORE_RELOCATE_PARA p; memset(&p, 0, sizeof p);
    p.hKeyBase = HKEY_CURRENT_USER; p.pwszSystemStore = NULL;
    SET_ERR(0);
    HCERTSTORE h = U(CertOpenStore)(CERT_STORE_PROV_SYSTEM_W, 0, 0, CERT_SYSTEM_STORE_RELOCATE_FLAG | OPEN_RO, &p);
    CHECK(h == NULL);
    EXPECT_ERR(ERROR_FILE_NOT_FOUND); /* probed std and adm */
    if (h) U(CertCloseStore)(h, 0);
}
TEST(sss_reloc_hkcu_base_existing_root_note) {
    REQUIRE(U(CertOpenStore));
    CERT_SYSTEM_STORE_RELOCATE_PARA p; memset(&p, 0, sizeof p);
    p.hKeyBase = HKEY_CURRENT_USER; p.pwszSystemStore = L"Root";
    SET_ERR(0);
    HCERTSTORE h = U(CertOpenStore)(CERT_STORE_PROV_SYSTEM_W, 0, 0, CERT_SYSTEM_STORE_RELOCATE_FLAG | OPEN_RO, &p);
    /* probed std and adm: HKCU is the base key, so the store would be HKCU\\Root, which does not exist */
    CHECK(h == NULL);
    EXPECT_ERR(ERROR_FILE_NOT_FOUND);
    if (h) U(CertCloseStore)(h, 0);
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
        t_label("%ls", n[i]);
        sss_pin_en(r, i == 0 ? L"Trusted Root Certification Authorities" : i == 1 ? L"Personal" : L"Intermediate Certification Authorities");
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
    /* probed std and adm (English UI): store names have display names, location names do not; the .Xxx physical store names do */
    static const wchar_t *want[] = { L"Third-Party Root Certification Authorities", L"Trusted Publishers", L"Untrusted Certificates", L"Trusted People",
        L"Enterprise Trust", L"Client Authentication Issuers", L"Smart Card Trusted Roots", NULL, NULL, NULL, NULL, NULL,
        L"Registry", L"Group Policy", L"Local Computer", L"Enterprise", L"Third-Party" };
    for (unsigned i = 0; i < sizeof n / sizeof n[0]; i++) {
        LPCWSTR r = U(CryptFindLocalizedName)(n[i]);
        t_label("%ls", n[i]);
        if (!want[i]) CHECK(r == NULL); else sss_pin_en(r, want[i]);
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
    /* probed std and adm: the property is not stored on a system store handle (the name comes from CryptFindLocalizedName), size left 0 */
    EXPECT_EQ(r, 0); EXPECT_ERR(CRYPT_E_NOT_FOUND); EXPECT_EQ(cb, 0);
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

/* ---- control ---- */
TEST(sss_control_memory_store_resync_unsupported) {
    REQUIRE(U(CertOpenStore)); REQUIRE(U(CertControlStore));
    HCERTSTORE h = U(CertOpenStore)(CERT_STORE_PROV_MEMORY, 0, 0, 0, NULL);
    CHECK(h != NULL); if (!h) return;
    SET_ERR(0);
    BOOL r = U(CertControlStore)(h, 0, CERT_STORE_CTRL_RESYNC, NULL);
    EXPECT_EQ(r, 0); EXPECT_ERR(ERROR_CALL_NOT_IMPLEMENTED); /* probed std and adm */
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
    EXPECT_EQ(r, 1); /* probed std and adm */
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
    EXPECT_EQ(r, 1); /* probed std and adm */
    if (r) {
        DWORD w = WaitForSingleObject(ev, 300);
        EXPECT_EQ(w, WAIT_TIMEOUT); /* probed std and adm: not signalled without a change */
        BOOL c = U(CertControlStore)(h, 0, CERT_STORE_CTRL_CANCEL_NOTIFY, &ev);
        EXPECT_EQ(c, 1);
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
    EXPECT_EQ(r, 0); EXPECT_ERR(ERROR_CALL_NOT_IMPLEMENTED); /* probed std and adm */
    CloseHandle(ev);
    U(CertCloseStore)(h, 0);
}
TEST(sss_control_auto_resync_collection_note) {
    REQUIRE(U(CertOpenStore)); REQUIRE(U(CertControlStore));
    HCERTSTORE h = U(CertOpenSystemStoreW)(0, L"Root");
    CHECK(h != NULL); if (!h) return;
    SET_ERR(0);
    BOOL r = U(CertControlStore)(h, 0, CERT_STORE_CTRL_AUTO_RESYNC, NULL);
    EXPECT_EQ(r, 1); /* probed std and adm */
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
