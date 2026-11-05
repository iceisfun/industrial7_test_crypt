#include "ds.h"
/* CertOpenStore(SYSTEM_*), CertOpenSystemStore, CertAddEncodedCertificateToSystemStore*: creation,
 * persistence as registry keys under SystemCertificates\<store>\Certificates\<SHA1>, deletion. */

/* Registry write-through before close: Windows registry-backed stores write on every change; the emulator defers. */
#define LIVE(c) do { if (t_is_wine()) t_note("pre-close registry check skipped under emulator: " #c); else CHECK(c); } while (0)
#define NAME(tag) wchar_t nm[120]; ds_name(nm, 120, tag)

TEST(dxss_open_creates_registry_key) {
    SETUP(CertOpenStore); NAME("oc1");
    CHECK(!ds_key_exists(0, nm, NULL));
    HCERTSTORE h = ds_open(nm, 0);
    CHECK(h != NULL);
    CHECK(ds_key_exists(0, nm, NULL));
    if (h) CHECK(U(CertCloseStore)(h, 0));
    CHECK(ds_key_exists(0, nm, NULL));   /* closing keeps the store */
    ds_end();
}
TEST(dxss_open_new_store_is_empty) {
    SETUP(CertOpenStore); NAME("oe1");
    HCERTSTORE h = ds_open(nm, 0);
    CHECK(h != NULL);
    if (h) { EXPECT_EQ(ds_count(h), 0); U(CertCloseStore)(h, 0); }
    ds_end();
}
TEST(dxss_open_existing_flag_missing_store_fails) {
    SETUP(CertOpenStore); NAME("ox1");
    SET_ERR(0);
    HCERTSTORE h = ds_open(nm, CERT_STORE_OPEN_EXISTING_FLAG);
    DWORD e = GetLastError();
    CHECK(h == NULL);
    EXPECT_EQ(e, ERROR_FILE_NOT_FOUND);
    CHECK(!ds_key_exists(0, nm, NULL));   /* failing open must not create the key */
    if (h) U(CertCloseStore)(h, 0);
    ds_end();
}
TEST(dxss_open_existing_flag_after_create_succeeds) {
    SETUP(CertOpenStore); NAME("ox2");
    HCERTSTORE a = ds_open(nm, 0);
    CHECK(a != NULL);
    HCERTSTORE b = ds_open(nm, CERT_STORE_OPEN_EXISTING_FLAG);
    CHECK(b != NULL);
    if (b) U(CertCloseStore)(b, 0);
    if (a) U(CertCloseStore)(a, 0);
    ds_end();
}
TEST(dxss_create_new_flag_creates_store) {
    SETUP(CertOpenStore); NAME("cn1");
    HCERTSTORE h = ds_open(nm, CERT_STORE_CREATE_NEW_FLAG);
    CHECK(h != NULL);
    CHECK(ds_key_exists(0, nm, NULL));
    if (h) { EXPECT_EQ(ds_count(h), 0); U(CertCloseStore)(h, 0); }
    ds_end();
}
TEST(dxss_create_new_flag_existing_store_fails) {
    SETUP(CertOpenStore); NAME("cn2");
    HCERTSTORE a = ds_open(nm, CERT_STORE_CREATE_NEW_FLAG);
    CHECK(a != NULL);
    SET_ERR(0);
    HCERTSTORE b = ds_open(nm, CERT_STORE_CREATE_NEW_FLAG);
    DWORD e = GetLastError();
    CHECK(b == NULL);
    EXPECT_EQ(e, ERROR_FILE_EXISTS);   /* OpenSubKeyEx: store key already present */
    if (b) U(CertCloseStore)(b, 0);
    if (a) U(CertCloseStore)(a, 0);
    ds_end();
}
TEST(dxss_create_new_flag_after_plain_open_fails) {
    SETUP(CertOpenStore); NAME("cn3");
    HCERTSTORE a = ds_open(nm, 0);
    CHECK(a != NULL);
    if (a) U(CertCloseStore)(a, 0);
    HCERTSTORE b = ds_open(nm, CERT_STORE_CREATE_NEW_FLAG);
    CHECK(b == NULL);
    if (b) U(CertCloseStore)(b, 0);
    ds_end();
}
TEST(dxss_create_new_and_open_existing_together_fails) {
    SETUP(CertOpenStore); NAME("cn4");
    if (t_is_wine()) { t_skip("emulator ignores this flag combination"); return; }
    HCERTSTORE h = ds_open(nm, CERT_STORE_CREATE_NEW_FLAG | CERT_STORE_OPEN_EXISTING_FLAG);
    CHECK(h == NULL);   /* missing: nothing to open; present: CREATE_NEW refuses */
    if (h) U(CertCloseStore)(h, 0);
    HCERTSTORE a = ds_open(nm, 0);
    CHECK(a != NULL);
    if (a) U(CertCloseStore)(a, 0);
    SET_ERR(0);
    h = ds_open(nm, CERT_STORE_CREATE_NEW_FLAG | CERT_STORE_OPEN_EXISTING_FLAG);
    CHECK(h == NULL);
    EXPECT_ERR(ERROR_FILE_EXISTS);
    if (h) U(CertCloseStore)(h, 0);
    ds_end();
}
TEST(dxss_open_name_case_insensitive) {
    SETUP(CertOpenStore); NAME("cs1");
    HCERTSTORE a = ds_open(nm, 0);
    CHECK(a != NULL && ds_add_ok(a, 0));
    if (a) U(CertCloseStore)(a, 0);
    wchar_t up[120]; wcscpy(up, nm); CharUpperW(up);
    CHECK(wcscmp(up, nm) != 0);
    EXPECT_EQ(ds_count_named(up, 0, CERT_STORE_OPEN_EXISTING_FLAG), 1);
    ds_end();
}
TEST(dxss_open_system_a_provider) {
    SETUP(CertOpenStore); NAME("sa1");
    char an[120]; WideCharToMultiByte(CP_ACP, 0, nm, -1, an, 120, NULL, NULL);
    HCERTSTORE a = U(CertOpenStore)(DS_SYS_A, 0, 0, CERT_SYSTEM_STORE_CURRENT_USER, an);
    CHECK(a != NULL);
    CHECK(ds_key_exists(0, nm, NULL));
    if (a) { CHECK(ds_add_ok(a, 1)); U(CertCloseStore)(a, 0); }
    EXPECT_EQ(ds_stored(nm, 0, 1), 1);   /* the wide provider sees what the ansi one wrote */
    ds_end();
}
TEST(dxss_open_system_registry_provider_w) {
    SETUP(CertOpenStore); NAME("sr1");
    if (t_is_wine()) { t_skip("emulator does not persist through the registry-only provider"); return; }
    HCERTSTORE a = U(CertOpenStore)(DS_SYSREG_W, 0, 0, CERT_SYSTEM_STORE_CURRENT_USER, nm);
    CHECK(a != NULL);
    if (a) { CHECK(ds_add_ok(a, 2)); U(CertCloseStore)(a, 0); }
    CHECK(ds_cert_key_exists(0, nm, 2));
    EXPECT_EQ(ds_stored(nm, 0, 2), 1);
    ds_end();
}
TEST(dxss_open_system_registry_provider_a) {
    SETUP(CertOpenStore); NAME("sr2");
    if (t_is_wine()) { t_skip("emulator does not persist through the registry-only provider"); return; }
    char an[120]; WideCharToMultiByte(CP_ACP, 0, nm, -1, an, 120, NULL, NULL);
    HCERTSTORE a = U(CertOpenStore)(DS_SYSREG_A, 0, 0, CERT_SYSTEM_STORE_CURRENT_USER, an);
    CHECK(a != NULL);
    if (a) { CHECK(ds_add_ok(a, 2)); U(CertCloseStore)(a, 0); }
    CHECK(ds_cert_key_exists(0, nm, 2));
    ds_end();
}
TEST(dxss_open_null_name_fails) {
    SETUP(CertOpenStore);
    SET_ERR(0);
    HCERTSTORE h = U(CertOpenStore)(DS_SYS_W, 0, 0, CERT_SYSTEM_STORE_CURRENT_USER, NULL);
    DWORD e = GetLastError();
    CHECK(h == NULL);
    if (t_is_wine()) t_note("emulator: NULL name last error 0x%lx", e); else EXPECT_EQ(e, DS_E_INVALIDARG);   /* ParseSystemStorePara */
    if (h) U(CertCloseStore)(h, 0);
}
TEST(dxss_open_empty_name_fails) {
    SETUP(CertOpenStore);
    SET_ERR(0);
    HCERTSTORE h = U(CertOpenStore)(DS_SYS_W, 0, 0, CERT_SYSTEM_STORE_CURRENT_USER, L"");
    DWORD e = GetLastError();
    CHECK(h == NULL || t_is_wine());
    if (t_is_wine()) t_note("emulator: empty name last error 0x%lx", e); else EXPECT_EQ(e, DS_E_INVALIDARG);
    if (h) U(CertCloseStore)(h, 0);
}
TEST(dxss_open_unregistered_location_fails) {
    SETUP(CertOpenStore); NAME("ul1");
    SET_ERR(0);
    /* location id 0xFE has no registry provider and no registered OID function */
    HCERTSTORE h = U(CertOpenStore)(DS_SYS_W, 0, 0, (DWORD)0xFE << 16, nm);
    CHECK(h == NULL);
    t_note("unknown store location 0xFE: last error 0x%lx", GetLastError());
    if (h) U(CertCloseStore)(h, 0);
    ds_end();
}

/* ---- persistence of added certificates ------------------------------------------------------ */
TEST(dxss_add_persists_registry_key) {
    SETUP(CertOpenStore); NAME("ap1");
    HCERTSTORE h = ds_open(nm, 0);
    CHECK(h != NULL);
    if (!h) return;
    CHECK(!ds_cert_key_exists(0, nm, 0));
    CHECK(ds_add_ok(h, 0));
    CHECK(ds_cert_key_exists(0, nm, 0));   /* written through immediately, before close */
    U(CertCloseStore)(h, 0);
    CHECK(ds_cert_key_exists(0, nm, 0));
    ds_end();
}
TEST(dxss_add_persists_blob_value) {
    SETUP(CertOpenStore); NAME("ap2");
    HCERTSTORE h = ds_open(nm, 0);
    if (!h) { CHECK(h != NULL); return; }
    CHECK(ds_add_ok(h, 1));
    U(CertCloseStore)(h, 0);
    DWORD type = 0, cb = 0, der;
    ds_der(1, &der);
    LONG rc = ds_cert_blob(0, nm, 1, &type, &cb);
    EXPECT_EQ(rc, 0);
    EXPECT_EQ(type, REG_BINARY);
    CHECKF(cb >= der, "Blob %lu bytes, certificate %lu", cb, der);
    ds_end();
}
TEST(dxss_add_reopen_sees_cert) {
    SETUP(CertOpenStore); NAME("ap3");
    HCERTSTORE h = ds_open(nm, 0);
    if (!h) { CHECK(h != NULL); return; }
    CHECK(ds_add_ok(h, 0));
    U(CertCloseStore)(h, 0);
    EXPECT_EQ(ds_stored(nm, 0, 0), 1);
    EXPECT_EQ(ds_count_named(nm, 0, 0), 1);
    ds_end();
}
TEST(dxss_add_reopen_content_is_identical_der) {
    SETUP(CertOpenStore); NAME("ap4");
    HCERTSTORE h = ds_open(nm, 0);
    if (!h) { CHECK(h != NULL); return; }
    CHECK(ds_add_ok(h, 3));
    U(CertCloseStore)(h, 0);
    h = ds_open(nm, CERT_STORE_OPEN_EXISTING_FLAG);
    CHECK(h != NULL);
    PCCERT_CONTEXT c = h ? U(CertEnumCertificatesInStore)(h, NULL) : NULL;
    CHECK(c != NULL);
    if (c) {
        DWORD cb; const BYTE *d = ds_der(3, &cb);
        EXPECT_EQ(c->cbCertEncoded, cb);
        CHECK(c->cbCertEncoded == cb && !memcmp(c->pbCertEncoded, d, cb));
        EXPECT_EQ(c->dwCertEncodingType, X509_ASN_ENCODING);
        EXPECT_EQ(c->hCertStore, h);
        U(CertFreeCertificateContext)(c);
    }
    if (h) U(CertCloseStore)(h, 0);
    ds_end();
}
TEST(dxss_add_all_four_distinct_keys) {
    SETUP(CertOpenStore); NAME("ap5");
    HCERTSTORE h = ds_open(nm, 0);
    if (!h) { CHECK(h != NULL); return; }
    for (int i = 0; i < DS_NCERTS; i++) CHECK(ds_add_ok(h, i));
    EXPECT_EQ(ds_count(h), 4);
    U(CertCloseStore)(h, 0);
    for (int i = 0; i < DS_NCERTS; i++) CHECK(ds_cert_key_exists(0, nm, i));
    EXPECT_EQ(ds_subkey_count(0, nm, L"Certificates"), 4);
    EXPECT_EQ(ds_count_named(nm, 0, 0), 4);
    ds_end();
}
TEST(dxss_add_certificate_key_name_is_uppercase_hex_sha1) {
    SETUP(CertOpenStore); NAME("ap6");
    HCERTSTORE h = ds_open(nm, 0);
    if (!h) { CHECK(h != NULL); return; }
    CHECK(ds_add_ok(h, 0));
    U(CertCloseStore)(h, 0);
    wchar_t p[300]; HKEY k; _snwprintf(p, 300, L"Software\\Microsoft\\SystemCertificates\\%s\\Certificates", nm);
    if (RegOpenKeyExW(HKEY_CURRENT_USER, p, 0, KEY_READ, &k) == 0) {
        wchar_t sub[100] = L""; DWORD n = 100;
        LONG erc = RegEnumKeyExW(k, 0, sub, &n, NULL, NULL, NULL, NULL);
        EXPECT_EQ(erc, 0);
        wchar_t want[100]; _snwprintf(want, 100, L"%hs", ds_sha1(0));
        CHECKF(!wcscmp(sub, want), "subkey %ls want %ls", sub, want);
        RegCloseKey(k);
    } else CHECK(0);
    ds_end();
}
TEST(dxss_add_new_disposition_twice_returns_exists) {
    SETUP(CertOpenStore); NAME("ad1");
    HCERTSTORE h = ds_open(nm, 0);
    if (!h) { CHECK(h != NULL); return; }
    PCCERT_CONTEXT c = ds_add(h, 0, CERT_STORE_ADD_NEW);
    CHECK(c != NULL);
    if (c) U(CertFreeCertificateContext)(c);
    SET_ERR(0);
    DWORD cb; const BYTE *d = ds_der(0, &cb);
    BOOL r = U(CertAddEncodedCertificateToStore)(h, X509_ASN_ENCODING, d, cb, CERT_STORE_ADD_NEW, NULL);
    EXPECT_FAIL(!r, CRYPT_E_EXISTS);
    EXPECT_EQ(ds_count(h), 1);
    U(CertCloseStore)(h, 0);
    ds_end();
}
TEST(dxss_add_replace_existing_keeps_single_key) {
    SETUP(CertOpenStore); NAME("ad2");
    HCERTSTORE h = ds_open(nm, 0);
    if (!h) { CHECK(h != NULL); return; }
    CHECK(ds_add_ok(h, 0));
    CHECK(ds_add_ok(h, 0));
    EXPECT_EQ(ds_count(h), 1);
    ds_sync(h);
    U(CertCloseStore)(h, 0);
    EXPECT_EQ(ds_subkey_count(0, nm, L"Certificates"), 1);
    ds_end();
}
TEST(dxss_add_always_disposition_single_registry_entry) {
    SETUP(CertOpenStore); NAME("ad3");
    HCERTSTORE h = ds_open(nm, 0);
    if (!h) { CHECK(h != NULL); return; }
    PCCERT_CONTEXT a = ds_add(h, 1, CERT_STORE_ADD_ALWAYS), b = ds_add(h, 1, CERT_STORE_ADD_ALWAYS);
    CHECK(a != NULL && b != NULL);
    if (a) U(CertFreeCertificateContext)(a);
    if (b) U(CertFreeCertificateContext)(b);
    U(CertCloseStore)(h, 0);
    EXPECT_EQ(ds_subkey_count(0, nm, L"Certificates"), 1);   /* registry key is the SHA1 hash: duplicates collapse */
    EXPECT_EQ(ds_count_named(nm, 0, 0), 1);
    ds_end();
}
TEST(dxss_add_use_existing_returns_existing_context) {
    SETUP(CertOpenStore); NAME("ad4");
    HCERTSTORE h = ds_open(nm, 0);
    if (!h) { CHECK(h != NULL); return; }
    PCCERT_CONTEXT a = ds_add(h, 2, CERT_STORE_ADD_NEW);
    PCCERT_CONTEXT b = ds_add(h, 2, CERT_STORE_ADD_USE_EXISTING);
    CHECK(a != NULL && b != NULL);
    if (a && b) CHECK(a->cbCertEncoded == b->cbCertEncoded && !memcmp(a->pbCertEncoded, b->pbCertEncoded, a->cbCertEncoded));
    if (a) U(CertFreeCertificateContext)(a);
    if (b) U(CertFreeCertificateContext)(b);
    EXPECT_EQ(ds_count(h), 1);
    U(CertCloseStore)(h, 0);
    ds_end();
}
TEST(dxss_add_newer_disposition_same_cert_is_exists_or_ok) {
    SETUP(CertOpenStore); NAME("ad5");
    HCERTSTORE h = ds_open(nm, 0);
    if (!h) { CHECK(h != NULL); return; }
    CHECK(ds_add_ok(h, 2));
    DWORD cb; const BYTE *d = ds_der(2, &cb);
    SET_ERR(0);
    BOOL r = U(CertAddEncodedCertificateToStore)(h, X509_ASN_ENCODING, d, cb, CERT_STORE_ADD_NEWER, NULL);
    t_note("ADD_NEWER with identical cert: %d, last error 0x%lx", r, GetLastError());
    EXPECT_EQ(ds_count(h), 1);
    U(CertCloseStore)(h, 0);
    ds_end();
}
TEST(dxss_add_garbage_der_fails_and_persists_nothing) {
    SETUP(CertOpenStore); NAME("ag1");
    HCERTSTORE h = ds_open(nm, 0);
    if (!h) { CHECK(h != NULL); return; }
    static const BYTE junk[] = { 0x30, 0x03, 0x02, 0x01, 0x01 };
    SET_ERR(0);
    BOOL r = U(CertAddEncodedCertificateToStore)(h, X509_ASN_ENCODING, junk, sizeof junk, CERT_STORE_ADD_ALWAYS, NULL);
    CHECK(!r);
    CHECK(GetLastError() != 0);
    EXPECT_EQ(ds_count(h), 0);
    U(CertCloseStore)(h, 0);
    EXPECT_EQ(ds_subkey_count(0, nm, L"Certificates") <= 0, 1);
    ds_end();
}
TEST(dxss_add_context_from_memory_store) {
    SETUP(CertOpenStore); NAME("am1");
    HCERTSTORE m = U(CertOpenStore)(CERT_STORE_PROV_MEMORY, 0, 0, 0, NULL);
    HCERTSTORE h = ds_open(nm, 0);
    CHECK(m != NULL && h != NULL);
    if (!m || !h) return;
    PCCERT_CONTEXT c = ds_add(m, 1, CERT_STORE_ADD_NEW);
    CHECK(c != NULL);
    if (c) {
        PCCERT_CONTEXT out = NULL;
        CHECK(U(CertAddCertificateContextToStore)(h, c, CERT_STORE_ADD_NEW, &out));
        CHECK(out != NULL);
        if (out) { EXPECT_EQ(out->hCertStore, h); U(CertFreeCertificateContext)(out); }
        U(CertFreeCertificateContext)(c);
    }
    U(CertCloseStore)(h, 0); U(CertCloseStore)(m, 0);
    CHECK(ds_cert_key_exists(0, nm, 1));
    EXPECT_EQ(ds_stored(nm, 0, 1), 1);
    ds_end();
}
TEST(dxss_add_context_copies_properties_to_system_store) {
    SETUP(CertOpenStore); NAME("am2");
    HCERTSTORE m = U(CertOpenStore)(CERT_STORE_PROV_MEMORY, 0, 0, 0, NULL);
    HCERTSTORE h = ds_open(nm, 0);
    if (!m || !h) { CHECK(m && h); return; }
    PCCERT_CONTEXT c = ds_add(m, 0, CERT_STORE_ADD_NEW);
    if (c) {
        CRYPT_DATA_BLOB b = { 12, (BYTE *)L"memfn" };
        CHECK(U(CertSetCertificateContextProperty)(c, CERT_FRIENDLY_NAME_PROP_ID, 0, &b));
        CHECK(U(CertAddCertificateContextToStore)(h, c, CERT_STORE_ADD_NEW, NULL));
        U(CertFreeCertificateContext)(c);
    } else CHECK(0);
    U(CertCloseStore)(h, 0); U(CertCloseStore)(m, 0);
    h = ds_open(nm, CERT_STORE_OPEN_EXISTING_FLAG);
    PCCERT_CONTEXT r = h ? ds_find(h, 0) : NULL;
    CHECK(r != NULL);
    if (r) {
        WCHAR buf[20] = {0}; DWORD cb = sizeof buf;
        CHECK(U(CertGetCertificateContextProperty)(r, CERT_FRIENDLY_NAME_PROP_ID, buf, &cb));
        CHECK(!wcscmp(buf, L"memfn"));
        U(CertFreeCertificateContext)(r);
    }
    if (h) U(CertCloseStore)(h, 0);
    ds_end();
}

/* ---- deletion ------------------------------------------------------------------------------- */
TEST(dxss_delete_removes_registry_key) {
    SETUP(CertOpenStore); NAME("dl1");
    HCERTSTORE h = ds_open(nm, 0);
    if (!h) { CHECK(h != NULL); return; }
    CHECK(ds_add_ok(h, 0));
    CHECK(ds_cert_key_exists(0, nm, 0));
    PCCERT_CONTEXT c = ds_find(h, 0);
    CHECK(c != NULL);
    if (c) CHECK(ds_del(c));   /* frees the context */
    CHECK(!ds_cert_key_exists(0, nm, 0));
    EXPECT_EQ(ds_count(h), 0);
    U(CertCloseStore)(h, 0);
    EXPECT_EQ(ds_count_named(nm, 0, 0), 0);
    ds_end();
}
TEST(dxss_delete_one_of_two_keeps_other) {
    SETUP(CertOpenStore); NAME("dl2");
    HCERTSTORE h = ds_open(nm, 0);
    if (!h) { CHECK(h != NULL); return; }
    CHECK(ds_add_ok(h, 0)); CHECK(ds_add_ok(h, 1));
    PCCERT_CONTEXT c = ds_find(h, 0);
    if (c) CHECK(ds_del(c));
    U(CertCloseStore)(h, 0);
    EXPECT_EQ(ds_stored(nm, 0, 0), 0);
    EXPECT_EQ(ds_stored(nm, 0, 1), 1);
    ds_end();
}
TEST(dxss_delete_twice_same_context_fails_gracefully) {
    SETUP(CertOpenStore); NAME("dl3");
    HCERTSTORE h = ds_open(nm, 0);
    if (!h) { CHECK(h != NULL); return; }
    CHECK(ds_add_ok(h, 0));
    PCCERT_CONTEXT c = ds_find(h, 0), d = ds_find(h, 0);
    CHECK(c != NULL && d != NULL);
    if (c) CHECK(ds_del(c));
    if (d) {
        SET_ERR(0);
        BOOL r = U(CertDeleteCertificateFromStore)(d);   /* already gone: either outcome is tolerated, store stays consistent */
        t_note("second delete of an already deleted context: %d err 0x%lx", r, GetLastError());
    }
    EXPECT_EQ(ds_count(h), 0);
    U(CertCloseStore)(h, 0);
    ds_end();
}
TEST(dxss_readd_after_delete_has_no_old_properties) {
    SETUP(CertOpenStore); NAME("dl4");
    HCERTSTORE h = ds_open(nm, 0);
    if (!h) { CHECK(h != NULL); return; }
    PCCERT_CONTEXT c = ds_add(h, 0, CERT_STORE_ADD_NEW);
    CHECK(c != NULL);
    if (c) {
        CRYPT_DATA_BLOB b = { 8, (BYTE *)L"old" };
        CHECK(U(CertSetCertificateContextProperty)(c, CERT_FRIENDLY_NAME_PROP_ID, 0, &b));
        CHECK(ds_del(c));
    }
    c = ds_add(h, 0, CERT_STORE_ADD_NEW);
    CHECK(c != NULL);
    if (c) {
        DWORD cb = 0; SET_ERR(0);
        CHECK(!U(CertGetCertificateContextProperty)(c, CERT_FRIENDLY_NAME_PROP_ID, NULL, &cb));
        EXPECT_ERR(CRYPT_E_NOT_FOUND);
        U(CertFreeCertificateContext)(c);
    }
    U(CertCloseStore)(h, 0);
    ds_end();
}

/* ---- CertOpenSystemStore / CertAddEncodedCertificateToSystemStore -------------------------- */
TEST(dxss_opensystemstorew_creates_and_returns_handle) {
    SETUP(CertOpenSystemStoreW); NAME("os1");
    HCERTSTORE h = U(CertOpenSystemStoreW)(0, nm);
    CHECK(h != NULL);
    CHECK(ds_key_exists(0, nm, NULL));
    if (h) U(CertCloseStore)(h, 0);
    ds_end();
}
TEST(dxss_opensystemstorea_creates_and_returns_handle) {
    SETUP(CertOpenSystemStoreA); NAME("os2");
    char an[120]; WideCharToMultiByte(CP_ACP, 0, nm, -1, an, 120, NULL, NULL);
    HCERTSTORE h = U(CertOpenSystemStoreA)(0, an);
    CHECK(h != NULL);
    CHECK(ds_key_exists(0, nm, NULL));
    if (h) U(CertCloseStore)(h, 0);
    ds_end();
}
TEST(dxss_opensystemstore_is_current_user_location) {
    SETUP(CertOpenSystemStoreW); NAME("os3");
    HCERTSTORE h = U(CertOpenSystemStoreW)(0, nm);
    if (h) { CHECK(ds_add_ok(h, 0)); U(CertCloseStore)(h, 0); }
    else CHECK(0);
    CHECK(ds_cert_key_exists(0, nm, 0));
    EXPECT_EQ(ds_stored(nm, CERT_SYSTEM_STORE_CURRENT_USER, 0), 1);
    ds_end();
}
TEST(dxss_opensystemstore_null_name_fails) {
    SETUP(CertOpenSystemStoreW);
    SET_ERR(0);
    HCERTSTORE h = U(CertOpenSystemStoreW)(0, NULL);
    CHECK(h == NULL);
    t_note("CertOpenSystemStoreW(NULL name): last error 0x%lx", GetLastError());
    if (h) U(CertCloseStore)(h, 0);
}
TEST(dxss_add_encoded_to_system_store_w_persists) {
    SETUP(CertAddEncodedCertificateToSystemStoreW); NAME("as1");
    DWORD cb; const BYTE *d = ds_der(0, &cb);
    CHECK(U(CertAddEncodedCertificateToSystemStoreW)(nm, (BYTE *)d, cb));
    CHECK(ds_cert_key_exists(0, nm, 0));
    EXPECT_EQ(ds_stored(nm, 0, 0), 1);
    ds_end();
}
TEST(dxss_add_encoded_to_system_store_a_persists) {
    SETUP(CertAddEncodedCertificateToSystemStoreA); NAME("as2");
    char an[120]; WideCharToMultiByte(CP_ACP, 0, nm, -1, an, 120, NULL, NULL);
    DWORD cb; const BYTE *d = ds_der(1, &cb);
    CHECK(U(CertAddEncodedCertificateToSystemStoreA)(an, (BYTE *)d, cb));
    CHECK(ds_cert_key_exists(0, nm, 1));
    ds_end();
}
TEST(dxss_add_encoded_to_system_store_twice_is_success) {
    SETUP(CertAddEncodedCertificateToSystemStoreW); NAME("as3");
    DWORD cb; const BYTE *d = ds_der(0, &cb);
    CHECK(U(CertAddEncodedCertificateToSystemStoreW)(nm, (BYTE *)d, cb));
    SET_ERR(0);
    BOOL r = U(CertAddEncodedCertificateToSystemStoreW)(nm, (BYTE *)d, cb);   /* CERT_STORE_ADD_ALWAYS-like per decomp: disposition 2 = REPLACE_EXISTING */
    CHECK(r);
    EXPECT_EQ(ds_count_named(nm, 0, 0), 1);
    ds_end();
}
TEST(dxss_add_encoded_to_system_store_garbage_fails) {
    SETUP(CertAddEncodedCertificateToSystemStoreW); NAME("as4");
    static const BYTE junk[] = { 1, 2, 3, 4, 5 };
    SET_ERR(0);
    CHECK(!U(CertAddEncodedCertificateToSystemStoreW)(nm, (BYTE *)junk, sizeof junk));
    CHECK(GetLastError() != 0);
    EXPECT_EQ(ds_count_named(nm, 0, 0), 0);
    ds_end();
}
TEST(dxss_add_encoded_to_system_store_two_certs_one_store) {
    SETUP(CertAddEncodedCertificateToSystemStoreW); NAME("as5");
    for (int i = 0; i < DS_NCERTS; i++) {
        DWORD cb; const BYTE *d = ds_der(i, &cb);
        CHECK(U(CertAddEncodedCertificateToSystemStoreW)(nm, (BYTE *)d, cb));
    }
    EXPECT_EQ(ds_count_named(nm, 0, 0), 4);
    ds_end();
}

/* ---- handles and close ---------------------------------------------------------------------- */
TEST(dxss_close_with_check_flag_and_outstanding_context_pending) {
    SETUP(CertOpenStore); NAME("cl1");
    HCERTSTORE h = ds_open(nm, 0);
    if (!h) { CHECK(h != NULL); return; }
    PCCERT_CONTEXT c = ds_add(h, 0, CERT_STORE_ADD_NEW);
    CHECK(c != NULL);
    BOOL (WINAPI *pClose)(HCERTSTORE, DWORD) = U(CertCloseStore);   /* resolve before SET_ERR */
    DWORD ge;
    BOOL r = T_CALL_ERR(&ge, pClose(h, CERT_CLOSE_STORE_CHECK_FLAG));
    if (t_is_wine()) t_note("emulator CHECK_FLAG close with outstanding context: %d", r);
    else { CHECK(!r); EXPECT_EQ(ge, CRYPT_E_PENDING_CLOSE); }
    if (c) U(CertFreeCertificateContext)(c);   /* the store is released once the last context is freed */
    ds_end();
}
TEST(dxss_close_with_check_flag_no_contexts_ok) {
    SETUP(CertOpenStore); NAME("cl2");
    HCERTSTORE h = ds_open(nm, 0);
    if (!h) { CHECK(h != NULL); return; }
    CHECK(U(CertCloseStore)(h, CERT_CLOSE_STORE_CHECK_FLAG));
    ds_end();
}
TEST(dxss_context_outlives_store_handle_close) {
    SETUP(CertOpenStore); NAME("cl3");
    HCERTSTORE h = ds_open(nm, 0);
    if (!h) { CHECK(h != NULL); return; }
    PCCERT_CONTEXT c = ds_add(h, 3, CERT_STORE_ADD_NEW);
    CHECK(c != NULL);
    CHECK(U(CertCloseStore)(h, 0));
    if (c) {
        DWORD cb; const BYTE *d = ds_der(3, &cb);
        CHECK(c->cbCertEncoded == cb && !memcmp(c->pbCertEncoded, d, cb));
        U(CertFreeCertificateContext)(c);
    }
    ds_end();
}
TEST(dxss_duplicate_store_returns_same_handle_and_needs_two_closes) {
    SETUP(CertDuplicateStore); NAME("du1");
    HCERTSTORE h = ds_open(nm, 0);
    if (!h) { CHECK(h != NULL); return; }
    HCERTSTORE d = U(CertDuplicateStore)(h);
    EXPECT_EQ(d, h);
    CHECK(U(CertCloseStore)(h, 0));
    CHECK(ds_add_ok(d, 0));            /* still usable after the first close */
    CHECK(U(CertCloseStore)(d, 0));
    CHECK(ds_cert_key_exists(0, nm, 0));
    ds_end();
}
TEST(dxss_two_handles_second_sees_first_adds_after_reopen_only) {
    SETUP(CertOpenStore); NAME("th1");
    HCERTSTORE a = ds_open(nm, 0), b = ds_open(nm, 0);
    CHECK(a != NULL && b != NULL);
    if (!a || !b) return;
    CHECK(ds_add_ok(a, 0));
    CHECK(ds_cert_key_exists(0, nm, 0));
    HCERTSTORE c = ds_open(nm, 0);                       /* a fresh handle always reads the registry */
    CHECK(c != NULL);
    if (c) { EXPECT_EQ(ds_count(c), 1); U(CertCloseStore)(c, 0); }
    t_note("second pre-existing handle count before resync: %d", ds_count(b));
    U(CertCloseStore)(a, 0); U(CertCloseStore)(b, 0);
    ds_end();
}
TEST(dxss_same_cert_in_two_stores_independent) {
    SETUP(CertOpenStore); wchar_t n1[120], n2[120]; ds_name(n1, 120, "ix1"); ds_name(n2, 120, "ix2");
    HCERTSTORE a = ds_open(n1, 0), b = ds_open(n2, 0);
    if (!a || !b) { CHECK(a && b); return; }
    CHECK(ds_add_ok(a, 0)); CHECK(ds_add_ok(b, 0));
    PCCERT_CONTEXT c = ds_find(a, 0);
    if (c) CHECK(ds_del(c));
    U(CertCloseStore)(a, 0); U(CertCloseStore)(b, 0);
    EXPECT_EQ(ds_stored(n1, 0, 0), 0);
    EXPECT_EQ(ds_stored(n2, 0, 0), 1);
    ds_end();
}

/* ---- CRL persistence ------------------------------------------------------------------------ */
TEST(dxss_crl_add_persists) {
    SETUP(CertOpenStore); NAME("cr1");
    HCERTSTORE h = ds_open(nm, 0);
    if (!h) { CHECK(h != NULL); return; }
    DWORD cb; const BYTE *d = ds_crl(&cb);
    PCCRL_CONTEXT crl = NULL;
    CHECK(U(CertAddEncodedCRLToStore)(h, X509_ASN_ENCODING, d, cb, CERT_STORE_ADD_NEW, &crl));
    CHECK(crl != NULL);
    if (crl) U(CertFreeCRLContext)(crl);
    ds_sync(h);
    CHECK(ds_subkey_count(0, nm, L"CRLs") == 1);
    U(CertCloseStore)(h, 0);
    h = ds_open(nm, CERT_STORE_OPEN_EXISTING_FLAG);
    CHECK(h != NULL);
    if (h) {
        PCCRL_CONTEXT c = U(CertEnumCRLsInStore)(h, NULL);
        CHECK(c != NULL);
        if (c) { CHECK(c->cbCrlEncoded == cb && !memcmp(c->pbCrlEncoded, d, cb)); U(CertFreeCRLContext)(c); }
        U(CertCloseStore)(h, 0);
    }
    ds_end();
}
TEST(dxss_crl_delete_removes_registry_entry) {
    SETUP(CertOpenStore); NAME("cr2");
    if (t_is_wine()) { t_skip("emulator asserts in CertDeleteCRLFromStore"); return; }
    HCERTSTORE h = ds_open(nm, 0);
    if (!h) { CHECK(h != NULL); return; }
    DWORD cb; const BYTE *d = ds_crl(&cb);
    CHECK(U(CertAddEncodedCRLToStore)(h, X509_ASN_ENCODING, d, cb, CERT_STORE_ADD_NEW, NULL));
    PCCRL_CONTEXT c = U(CertEnumCRLsInStore)(h, NULL);
    CHECK(c != NULL);
    if (c) CHECK(U(CertDeleteCRLFromStore)(c));
    EXPECT_EQ(ds_subkey_count(0, nm, L"CRLs") <= 0, 1);
    U(CertCloseStore)(h, 0);
    ds_end();
}
TEST(dxss_crl_and_cert_live_in_separate_subkeys) {
    SETUP(CertOpenStore); NAME("cr3");
    HCERTSTORE h = ds_open(nm, 0);
    if (!h) { CHECK(h != NULL); return; }
    DWORD cb; const BYTE *d = ds_crl(&cb);
    CHECK(ds_add_ok(h, 0));
    CHECK(U(CertAddEncodedCRLToStore)(h, X509_ASN_ENCODING, d, cb, CERT_STORE_ADD_NEW, NULL));
    EXPECT_EQ(ds_count(h), 1);
    ds_sync(h);
    U(CertCloseStore)(h, 0);
    EXPECT_EQ(ds_subkey_count(0, nm, L"Certificates"), 1);
    EXPECT_EQ(ds_subkey_count(0, nm, L"CRLs"), 1);
    ds_end();
}

/* ---- read-only ------------------------------------------------------------------------------ */
TEST(dxss_readonly_flag_does_not_persist) {
    SETUP(CertOpenStore); NAME("ro1");
    HCERTSTORE w = ds_open(nm, 0);
    CHECK(w != NULL);
    if (w) U(CertCloseStore)(w, 0);
    HCERTSTORE h = ds_open(nm, CERT_STORE_READONLY_FLAG | CERT_STORE_OPEN_EXISTING_FLAG);
    CHECK(h != NULL);
    if (!h) return;
    DWORD cb; const BYTE *d = ds_der(0, &cb);
    SET_ERR(0);
    BOOL r = U(CertAddEncodedCertificateToStore)(h, X509_ASN_ENCODING, d, cb, CERT_STORE_ADD_ALWAYS, NULL);
    t_note("add to READONLY system store: %d, last error 0x%lx", r, GetLastError());
    U(CertCloseStore)(h, 0);
    CHECK(!ds_cert_key_exists(0, nm, 0));
    EXPECT_EQ(ds_count_named(nm, 0, 0), 0);
    ds_end();
}
TEST(dxss_readonly_flag_reads_existing_certs) {
    SETUP(CertOpenStore); NAME("ro2");
    HCERTSTORE w = ds_open(nm, 0);
    if (!w) { CHECK(w != NULL); return; }
    CHECK(ds_add_ok(w, 2));
    U(CertCloseStore)(w, 0);
    HCERTSTORE h = ds_open(nm, CERT_STORE_READONLY_FLAG);
    CHECK(h != NULL);
    if (h) { EXPECT_EQ(ds_count(h), 1); U(CertCloseStore)(h, 0); }
    ds_end();
}
TEST(dxss_readonly_flag_delete_does_not_remove) {
    SETUP(CertOpenStore); NAME("ro3");
    HCERTSTORE w = ds_open(nm, 0);
    if (!w) { CHECK(w != NULL); return; }
    CHECK(ds_add_ok(w, 2));
    U(CertCloseStore)(w, 0);
    HCERTSTORE h = ds_open(nm, CERT_STORE_READONLY_FLAG);
    if (!h) { CHECK(h != NULL); return; }
    PCCERT_CONTEXT c = ds_find(h, 2);
    CHECK(c != NULL);
    if (c) { SET_ERR(0); BOOL r = ds_del(c); t_note("delete from READONLY store: %d err 0x%lx", r, GetLastError()); }
    U(CertCloseStore)(h, 0);
    CHECK(ds_cert_key_exists(0, nm, 2));
    ds_end();
}

/* ---- local machine (elevated only) ---------------------------------------------------------- */
TEST(dxss_lm_open_add_persist_delete) {
    SETUP_LM(CertOpenStore); NAME("lm1");
    if (t_is_wine()) { t_skip("emulator keeps machine stores elsewhere"); return; }
    DWORD L = CERT_SYSTEM_STORE_LOCAL_MACHINE;
    HCERTSTORE h = ds_open_loc(nm, L, 0);
    CHECK(h != NULL);
    if (!h) { ds_end(); return; }
    CHECK(ds_key_exists(L, nm, NULL));
    CHECK(!ds_key_exists(0, nm, NULL));   /* not created in HKCU */
    CHECK(ds_add_ok(h, 0));
    CHECK(ds_cert_key_exists(L, nm, 0));
    U(CertCloseStore)(h, 0);
    EXPECT_EQ(ds_stored(nm, L, 0), 1);
    h = ds_open_loc(nm, L, 0);
    PCCERT_CONTEXT c = h ? ds_find(h, 0) : NULL;
    if (c) CHECK(ds_del(c));
    if (h) U(CertCloseStore)(h, 0);
    CHECK(!ds_cert_key_exists(L, nm, 0));
    ds_end();
}
TEST(dxss_lm_and_cu_same_name_are_independent) {
    SETUP_LM(CertOpenStore); NAME("lm2");
    if (t_is_wine()) { t_skip("emulator keeps machine stores elsewhere"); return; }
    DWORD L = CERT_SYSTEM_STORE_LOCAL_MACHINE;
    HCERTSTORE a = ds_open_loc(nm, L, 0), b = ds_open(nm, 0);
    CHECK(a != NULL && b != NULL);
    if (a && b) { CHECK(ds_add_ok(a, 1)); CHECK(ds_add_ok(b, 2)); }
    if (a) U(CertCloseStore)(a, 0);
    if (b) U(CertCloseStore)(b, 0);
    /* registry content is independent per hive ... */
    CHECK(ds_cert_key_exists(L, nm, 1)); CHECK(!ds_cert_key_exists(L, nm, 2));
    CHECK(ds_cert_key_exists(0, nm, 2)); CHECK(!ds_cert_key_exists(0, nm, 1));
    EXPECT_EQ(ds_stored(nm, L, 1), 1);
    EXPECT_EQ(ds_stored(nm, L, 2), 0);
    EXPECT_EQ(ds_stored(nm, 0, 2), 1);
    EXPECT_EQ(ds_stored(nm, 0, 1), 1);   /* ... but the CU view also layers the machine store's .LocalMachine physical store */
    ds_end();
}

/* ---- CERT_STORE_DELETE_FLAG and misc flag validation (decomp: I_CertDllOpenSystemStoreProvW) ----- */
TEST(dxss_open_delete_flag_removes_store_and_returns_null) {
    SETUP(CertOpenStore); NAME("df1");
    if (t_is_wine()) { t_skip("emulator ignores this flag combination"); return; }
    HCERTSTORE h = ds_open(nm, 0);
    CHECK(h != NULL);
    if (h) { CHECK(ds_add_ok(h, 0)); U(CertCloseStore)(h, 0); }
    CHECK(ds_key_exists(0, nm, NULL));
    SET_ERR(0xdead);
    HCERTSTORE d = ds_open(nm, CERT_STORE_DELETE_FLAG);
    DWORD e = GetLastError();
    CHECK(d == NULL);              /* NULL on both success and failure */
    t_note("DELETE_FLAG open: last error 0x%lx", e);
    CHECK(!ds_key_exists(0, nm, NULL));
    ds_end();
}
TEST(dxss_open_delete_flag_missing_store_fails) {
    SETUP(CertOpenStore); NAME("df2");
    if (t_is_wine()) { t_skip("emulator ignores this flag combination"); return; }
    HCERTSTORE d = ds_open(nm, CERT_STORE_DELETE_FLAG);
    CHECK(d == NULL);
    CHECK(!ds_key_exists(0, nm, NULL));
    ds_end();
}
TEST(dxss_open_delete_flag_then_open_existing_fails) {
    SETUP(CertOpenStore); NAME("df3");
    if (t_is_wine()) { t_skip("emulator ignores this flag combination"); return; }
    HCERTSTORE h = ds_open(nm, 0);
    if (h) U(CertCloseStore)(h, 0);
    ds_open(nm, CERT_STORE_DELETE_FLAG);
    SET_ERR(0);
    HCERTSTORE o = ds_open(nm, CERT_STORE_OPEN_EXISTING_FLAG);
    CHECK(o == NULL);
    EXPECT_ERR(ERROR_FILE_NOT_FOUND);
    if (o) U(CertCloseStore)(o, 0);
    ds_end();
}
