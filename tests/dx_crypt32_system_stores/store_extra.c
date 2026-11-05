#include "ds.h"
/* Additional state-changing coverage: registry element layout, enumeration callbacks that stop early,
 * system store location enumeration, extra CertSaveStore targets, context lifetime across delete. */

#define NAME(tag) wchar_t nm[120]; ds_name(nm, 120, tag)
#define NAME2(tag) wchar_t nm2[120]; ds_name(nm2, 120, tag)
#define WINE_SKIP(why) do { if (t_is_wine()) { t_skip("emulator: " why); return; } } while (0)
#define CU CERT_SYSTEM_STORE_CURRENT_USER
#define SC_ROOT L"Software\\Microsoft\\SystemCertificates"

/* ---- registry element layout ------------------------------------------------------------------------ */
static BYTE *read_blob(const wchar_t *store, int idx, DWORD *cb) {
    DWORD type = 0, n = 0;
    if (ds_cert_blob(0, store, idx, &type, &n) != 0 || type != REG_BINARY || !n) return NULL;
    BYTE *b = (BYTE *)malloc(n);
    wchar_t sub[100]; _snwprintf(sub, 100, L"Certificates\\%hs", ds_sha1(idx));
    if (!b || ds_reg_value(0, store, sub, L"Blob", &type, b, &n) != 0) { free(b); return NULL; }
    *cb = n;
    return b;
}
TEST(dxss_layout_registry_blob_is_serialized_element) {
    SETUP(CertAddSerializedElementToStore); NAME("lo1");
    HCERTSTORE h = ds_open(nm, 0);
    if (!h) { CHECK(h != NULL); return; }
    CHECK(ds_add_ok(h, 1));
    U(CertCloseStore)(h, 0);
    DWORD cb = 0; BYTE *b = read_blob(nm, 1, &cb);
    CHECK(b != NULL);
    if (b) {
        HCERTSTORE m = U(CertOpenStore)(CERT_STORE_PROV_MEMORY, 0, 0, 0, NULL);
        const void *ctx = NULL; DWORD ty = 0;
        BOOL r = m && U(CertAddSerializedElementToStore)(m, b, cb, CERT_STORE_ADD_NEW, 0, CERT_STORE_CERTIFICATE_CONTEXT_FLAG, &ty, &ctx);
        CHECK(r);
        if (r) {
            PCCERT_CONTEXT c = (PCCERT_CONTEXT)ctx; DWORD dl; const BYTE *d = ds_der(1, &dl);
            EXPECT_EQ(ty, CERT_STORE_CERTIFICATE_CONTEXT);
            CHECK(c->cbCertEncoded == dl && !memcmp(c->pbCertEncoded, d, dl));
            U(CertFreeCertificateContext)(c);
        }
        if (m) U(CertCloseStore)(m, 0);
        free(b);
    }
    ds_end();
}
TEST(dxss_layout_registry_blob_carries_friendly_name) {
    SETUP(CertAddSerializedElementToStore); NAME("lo2");
    WINE_SKIP("per-certificate property changes are not written through the registry store");
    HCERTSTORE h = ds_open(nm, 0);
    if (!h) { CHECK(h != NULL); return; }
    PCCERT_CONTEXT c = ds_add(h, 0, CERT_STORE_ADD_NEW);
    CHECK(c != NULL);
    if (c) {
        CRYPT_DATA_BLOB fb = { 14, (BYTE *)L"blobfn" };
        CHECK(U(CertSetCertificateContextProperty)(c, CERT_FRIENDLY_NAME_PROP_ID, 0, &fb));
        U(CertFreeCertificateContext)(c);
    }
    U(CertCloseStore)(h, 0);
    DWORD cb = 0; BYTE *b = read_blob(nm, 0, &cb);
    CHECK(b != NULL);
    if (b) {
        HCERTSTORE m = U(CertOpenStore)(CERT_STORE_PROV_MEMORY, 0, 0, 0, NULL);
        const void *ctx = NULL;
        BOOL r = m && U(CertAddSerializedElementToStore)(m, b, cb, CERT_STORE_ADD_NEW, 0, CERT_STORE_CERTIFICATE_CONTEXT_FLAG, NULL, &ctx);
        CHECK(r);
        if (r) {
            WCHAR w[32] = {0}; DWORD n = sizeof w;
            CHECK(U(CertGetCertificateContextProperty)((PCCERT_CONTEXT)ctx, CERT_FRIENDLY_NAME_PROP_ID, w, &n));
            CHECK(!wcscmp(w, L"blobfn"));
            U(CertFreeCertificateContext)((PCCERT_CONTEXT)ctx);
        }
        if (m) U(CertCloseStore)(m, 0);
        free(b);
    }
    ds_end();
}
TEST(dxss_layout_hand_written_registry_element_is_visible) {
    SETUP(CertSerializeCertificateStoreElement); NAME("lo3");
    HCERTSTORE h = ds_open(nm, 0);          /* creates the store key */
    if (!h) { CHECK(h != NULL); return; }
    U(CertCloseStore)(h, 0);
    /* serialize a memory-store certificate carrying a friendly name and write it under Certificates\<SHA1> ourselves */
    HCERTSTORE m = U(CertOpenStore)(CERT_STORE_PROV_MEMORY, 0, 0, 0, NULL);
    PCCERT_CONTEXT c = m ? ds_add(m, 2, CERT_STORE_ADD_NEW) : NULL;
    CHECK(c != NULL);
    if (c) {
        CRYPT_DATA_BLOB fb = { 18, (BYTE *)L"handmade" };
        CHECK(U(CertSetCertificateContextProperty)(c, CERT_FRIENDLY_NAME_PROP_ID, 0, &fb));
        DWORD cb = 0;
        CHECK(U(CertSerializeCertificateStoreElement)(c, 0, NULL, &cb));
        BYTE *b = (BYTE *)malloc(cb ? cb : 1);
        if (b && U(CertSerializeCertificateStoreElement)(c, 0, b, &cb)) {
            wchar_t p[400]; HKEY k; DWORD disp;
            _snwprintf(p, 400, SC_ROOT L"\\%s\\Certificates\\%hs", nm, ds_sha1(2));
            if (RegCreateKeyExW(HKEY_CURRENT_USER, p, 0, NULL, 0, KEY_WRITE, NULL, &k, &disp) == 0) {
                CHECK(RegSetValueExW(k, L"Blob", 0, REG_BINARY, b, cb) == 0);
                RegCloseKey(k);
            } else CHECK(0);
            EXPECT_EQ(ds_stored(nm, 0, 2), 1);
            HCERTSTORE r = ds_open(nm, CERT_STORE_OPEN_EXISTING_FLAG);
            PCCERT_CONTEXT f = r ? ds_find(r, 2) : NULL;
            if (f) {
                WCHAR w[32] = {0}; DWORD n = sizeof w;
                CHECK(U(CertGetCertificateContextProperty)(f, CERT_FRIENDLY_NAME_PROP_ID, w, &n));
                CHECK(!wcscmp(w, L"handmade"));
                U(CertFreeCertificateContext)(f);
            }
            if (r) U(CertCloseStore)(r, 0);
        } else CHECK(0);
        free(b);
        U(CertFreeCertificateContext)(c);
    }
    if (m) U(CertCloseStore)(m, 0);
    ds_end();
}
TEST(dxss_layout_sha1_property_matches_registry_key_name) {
    SETUP(CertGetCertificateContextProperty); NAME("lo4");
    HCERTSTORE h = ds_open(nm, 0);
    if (!h) { CHECK(h != NULL); return; }
    for (int i = 0; i < DS_NCERTS; i++) {
        PCCERT_CONTEXT c = ds_add(h, i, CERT_STORE_ADD_NEW);
        CHECK(c != NULL);
        if (!c) continue;
        BYTE hash[20]; DWORD n = sizeof hash;
        CHECK(U(CertGetCertificateContextProperty)(c, CERT_SHA1_HASH_PROP_ID, hash, &n));
        EXPECT_EQ(n, 20);
        char hex[41]; for (int k = 0; k < 20; k++) sprintf(hex + 2 * k, "%02X", hash[k]);
        EXPECT_STR(hex, ds_sha1(i));
        U(CertFreeCertificateContext)(c);
    }
    U(CertCloseStore)(h, 0);
    ds_end();
}

/* ---- context lifetime and enumerate-and-delete ------------------------------------------------------ */
TEST(dxss_delete_all_by_enumeration_empties_registry) {
    SETUP(CertOpenStore); NAME("ed1");
    HCERTSTORE h = ds_open(nm, 0);
    if (!h) { CHECK(h != NULL); return; }
    for (int i = 0; i < DS_NCERTS; i++) CHECK(ds_add_ok(h, i));
    int guard = 0; PCCERT_CONTEXT c;
    while ((c = U(CertEnumCertificatesInStore)(h, NULL)) != NULL && guard++ < 10) CHECK(ds_del(c));
    EXPECT_EQ(guard, DS_NCERTS);
    EXPECT_EQ(ds_count(h), 0);
    U(CertCloseStore)(h, 0);
    EXPECT_EQ(ds_subkey_count(0, nm, L"Certificates") <= 0, 1);
    EXPECT_EQ(ds_count_named(nm, 0, 0), 0);
    ds_end();
}
TEST(dxss_duplicate_context_survives_delete) {
    SETUP(CertOpenStore); NAME("ed2");
    HCERTSTORE h = ds_open(nm, 0);
    if (!h) { CHECK(h != NULL); return; }
    PCCERT_CONTEXT c = ds_add(h, 3, CERT_STORE_ADD_NEW);
    CHECK(c != NULL);
    if (c) {
        PCCERT_CONTEXT d = U(CertDuplicateCertificateContext)(c);
        CHECK(d != NULL);
        CHECK(ds_del(c));                      /* frees c */
        CHECK(!ds_cert_key_exists(0, nm, 3));
        if (d) {
            DWORD dl; const BYTE *der = ds_der(3, &dl);
            CHECK(d->cbCertEncoded == dl && !memcmp(d->pbCertEncoded, der, dl));
            U(CertFreeCertificateContext)(d);
        }
    }
    EXPECT_EQ(ds_count(h), 0);
    U(CertCloseStore)(h, 0);
    ds_end();
}
TEST(dxss_enum_loop_order_is_stable_between_passes) {
    SETUP(CertOpenStore); NAME("ed3");
    HCERTSTORE h = ds_open(nm, 0);
    if (!h) { CHECK(h != NULL); return; }
    for (int i = 0; i < DS_NCERTS; i++) CHECK(ds_add_ok(h, i));
    BYTE first[DS_NCERTS][20]; int n1 = 0, n2 = 0, same = 1;
    PCCERT_CONTEXT c = NULL;
    while ((c = U(CertEnumCertificatesInStore)(h, c)) != NULL && n1 < DS_NCERTS) { DWORD n = 20; U(CertGetCertificateContextProperty)(c, CERT_SHA1_HASH_PROP_ID, first[n1++], &n); }
    while ((c = U(CertEnumCertificatesInStore)(h, c)) != NULL && n2 < DS_NCERTS) {
        BYTE hh[20]; DWORD n = 20; U(CertGetCertificateContextProperty)(c, CERT_SHA1_HASH_PROP_ID, hh, &n);
        if (n2 < n1 && memcmp(hh, first[n2], 20)) same = 0;
        n2++;
    }
    EXPECT_EQ(n1, DS_NCERTS); EXPECT_EQ(n2, DS_NCERTS);
    CHECK(same);
    U(CertCloseStore)(h, 0);
    ds_end();
}

/* ---- enumeration callbacks that stop early ------------------------------------------------------------- */
typedef struct { int calls; } stop_t;
static BOOL WINAPI stop_sys_cb(const void *sys, DWORD flags, PCERT_SYSTEM_STORE_INFO info, void *resv, void *arg) {
    ((stop_t *)arg)->calls++;
    return FALSE;
}
static BOOL WINAPI stop_phys_cb(const void *sys, DWORD flags, LPCWSTR name, PCERT_PHYSICAL_STORE_INFO info, void *resv, void *arg) {
    ((stop_t *)arg)->calls++;
    return FALSE;
}
TEST(dxss_enumsys_callback_false_stops_enumeration) {
    SETUP(CertEnumSystemStore); NAME("st1"); NAME2("st1b");
    HCERTSTORE a = ds_open(nm, 0), b = ds_open(nm2, 0);     /* at least two stores now exist in HKCU */
    CHECK(a && b);
    if (a) U(CertCloseStore)(a, 0);
    if (b) U(CertCloseStore)(b, 0);
    stop_t s = { 0 };
    SET_ERR(0);
    BOOL r = U(CertEnumSystemStore)(CU, NULL, &s, stop_sys_cb);
    EXPECT_EQ(s.calls, 1);
    t_note("CertEnumSystemStore with a callback returning FALSE: returned %d err 0x%lx", r, GetLastError());
    ds_end();
}
TEST(dxss_enumphys_callback_false_stops_enumeration) {
    SETUP(CertEnumPhysicalStore); NAME("st2"); NAME2("st2t");
    WINE_SKIP("registration/physical store APIs are stubs");
    CHECK(U(CertRegisterSystemStore)((void *)nm, CU, NULL, NULL));
    for (int i = 0; i < 2; i++) {
        CERT_PHYSICAL_STORE_INFO pi; memset(&pi, 0, sizeof pi); pi.cbSize = sizeof pi;
        pi.pszOpenStoreProvider = (LPSTR)(ULONG_PTR)10; pi.dwOpenFlags = CU;
        pi.OpenParameters.pbData = (BYTE *)nm2; pi.OpenParameters.cbData = (DWORD)((wcslen(nm2) + 1) * 2); pi.dwPriority = 5 + i;
        wchar_t pn[8]; _snwprintf(pn, 8, L"s%d", i);
        CHECK(U(CertRegisterPhysicalStore)((void *)nm, CU, pn, &pi, NULL));
    }
    stop_t s = { 0 };
    U(CertEnumPhysicalStore)((void *)nm, CU, &s, stop_phys_cb);
    EXPECT_EQ(s.calls, 1);
    ds_end();
}

/* ---- CertEnumSystemStoreLocation ---------------------------------------------------------------------- */
typedef struct { int n, cu, lm; DWORD cuflags, lmflags; } loc_t;
static BOOL WINAPI loc_cb(LPCWSTR name, DWORD flags, void *resv, void *arg) {
    loc_t *l = (loc_t *)arg; l->n++;
    if (name && !lstrcmpiW(name, L"CurrentUser")) { l->cu++; l->cuflags = flags; }
    if (name && !lstrcmpiW(name, L"LocalMachine")) { l->lm++; l->lmflags = flags; }
    return TRUE;
}
TEST(dxss_enumlocation_lists_user_and_machine) {
    REQUIRE(U(CertEnumSystemStoreLocation));
    loc_t l; memset(&l, 0, sizeof l);
    SET_ERR(0);
    CHECK(U(CertEnumSystemStoreLocation)(0, &l, loc_cb));
    CHECK(l.n >= 2);
    EXPECT_EQ(l.cu, 1); EXPECT_EQ(l.lm, 1);
    EXPECT_EQ(l.cuflags & CERT_SYSTEM_STORE_LOCATION_MASK, CERT_SYSTEM_STORE_CURRENT_USER);
    EXPECT_EQ(l.lmflags & CERT_SYSTEM_STORE_LOCATION_MASK, CERT_SYSTEM_STORE_LOCAL_MACHINE);
}
TEST(dxss_enumlocation_invalid_flags) {
    REQUIRE(U(CertEnumSystemStoreLocation));
    if (t_is_wine()) { t_skip("emulator: no flag validation"); return; }
    static const DWORD bad[] = { 1, 2, 4, 8, 0x10, 0x20, 0x100, 0x200, 0x400, 0x2000 };   /* mask 0x273f */
    for (unsigned i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        loc_t l; memset(&l, 0, sizeof l); SET_ERR(0);
        BOOL r = U(CertEnumSystemStoreLocation)(bad[i], &l, loc_cb);
        DWORD e = GetLastError();
        CHECKF(!r, "flags 0x%lx accepted", bad[i]);
        CHECKF(e == DS_E_INVALIDARG, "flags 0x%lx error 0x%lx", bad[i], e);
        CHECKF(l.n == 0, "flags 0x%lx invoked callback", bad[i]);
    }
}
static BOOL WINAPI loc_stop_cb(LPCWSTR name, DWORD flags, void *resv, void *arg) { ((int *)arg)[0]++; return FALSE; }
TEST(dxss_enumlocation_callback_false_stops) {
    REQUIRE(U(CertEnumSystemStoreLocation));
    int n = 0; SET_ERR(0);
    BOOL r = U(CertEnumSystemStoreLocation)(0, &n, loc_stop_cb);
    EXPECT_EQ(n, 1);
    CHECK(!r);
}

/* ---- CertEnumSystemStore flag validation ---------------------------------------------------------------- */
TEST(dxss_enumsys_invalid_flags_rejected) {
    SETUP(CertEnumSystemStore);
    if (t_is_wine()) { t_skip("emulator: no flag validation"); return; }
    stop_t s = { 0 };
    SET_ERR(0);
    BOOL r = U(CertEnumSystemStore)(CU | CERT_STORE_CREATE_NEW_FLAG, NULL, &s, stop_sys_cb);
    t_note("CertEnumSystemStore with CREATE_NEW: %d err 0x%lx calls %d", r, GetLastError(), s.calls);
    ds_end();
}

/* ---- more CertSaveStore targets ------------------------------------------------------------------------- */
static HCERTSTORE filled2(const wchar_t *n, int cnt) {
    HCERTSTORE h = ds_open(n, 0);
    for (int i = 0; h && i < cnt; i++) ds_add_ok(h, i);
    if (h) ds_sync(h);
    return h;
}
TEST(dxss_save_to_filename_a_reopens) {
    SETUP(CertSaveStore); NAME("sa1");
    HCERTSTORE h = filled2(nm, 3);
    if (!h) { CHECK(h != NULL); return; }
    char pa[MAX_PATH]; t_tmpfile(pa, sizeof pa, "ss_save_a.sst");
    CHECK(U(CertSaveStore)(h, DS_ENC, CERT_STORE_SAVE_AS_STORE, CERT_STORE_SAVE_TO_FILENAME_A, pa, 0));
    HCERTSTORE m = U(CertOpenStore)(CERT_STORE_PROV_FILENAME_A, DS_ENC, 0, CERT_STORE_READONLY_FLAG, pa);
    CHECK(m != NULL);
    if (m) { EXPECT_EQ(ds_count(m), 3); U(CertCloseStore)(m, 0); }
    DeleteFileA(pa);
    U(CertCloseStore)(h, 0);
    ds_end();
}
TEST(dxss_save_to_file_handle) {
    SETUP(CertSaveStore); NAME("sa2");
    HCERTSTORE h = filled2(nm, 2);
    if (!h) { CHECK(h != NULL); return; }
    char pa[MAX_PATH]; t_tmpfile(pa, sizeof pa, "ss_save_h.p7b");
    HANDLE f = CreateFileA(pa, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    CHECK(f != INVALID_HANDLE_VALUE);
    if (f != INVALID_HANDLE_VALUE) {
        CHECK(U(CertSaveStore)(h, DS_ENC, CERT_STORE_SAVE_AS_PKCS7, CERT_STORE_SAVE_TO_FILE, f, 0));
        CloseHandle(f);
        HCERTSTORE m = U(CertOpenStore)(CERT_STORE_PROV_FILENAME_A, DS_ENC, 0, CERT_STORE_READONLY_FLAG, pa);
        CHECK(m != NULL);
        if (m) { EXPECT_EQ(ds_count(m), 2); U(CertCloseStore)(m, 0); }
    }
    DeleteFileA(pa);
    U(CertCloseStore)(h, 0);
    ds_end();
}
TEST(dxss_save_reload_into_other_system_store_roundtrip) {
    SETUP(CertSaveStore); NAME("sa3"); NAME2("sa3b");
    HCERTSTORE h = filled2(nm, 4);
    if (!h) { CHECK(h != NULL); return; }
    CRYPT_DATA_BLOB b = { 0, NULL };
    CHECK(U(CertSaveStore)(h, DS_ENC, CERT_STORE_SAVE_AS_STORE, CERT_STORE_SAVE_TO_MEMORY, &b, 0));
    b.pbData = (BYTE *)malloc(b.cbData ? b.cbData : 1);
    if (b.pbData && U(CertSaveStore)(h, DS_ENC, CERT_STORE_SAVE_AS_STORE, CERT_STORE_SAVE_TO_MEMORY, &b, 0)) {
        HCERTSTORE m = U(CertOpenStore)(CERT_STORE_PROV_SERIALIZED, DS_ENC, 0, 0, &b);
        HCERTSTORE t = ds_open(nm2, 0);
        CHECK(m != NULL && t != NULL);
        if (m && t) {
            PCCERT_CONTEXT c = NULL; int n = 0;
            while ((c = U(CertEnumCertificatesInStore)(m, c)) != NULL) { CHECK(U(CertAddCertificateContextToStore)(t, c, CERT_STORE_ADD_NEW, NULL)); n++; }
            EXPECT_EQ(n, 4);
        }
        if (m) U(CertCloseStore)(m, 0);
        if (t) U(CertCloseStore)(t, 0);
        EXPECT_EQ(ds_count_named(nm2, 0, 0), 4);
        for (int i = 0; i < 4; i++) EXPECT_EQ(ds_stored(nm2, 0, i), 1);
    } else CHECK(0);
    free(b.pbData);
    U(CertCloseStore)(h, 0);
    ds_end();
}

/* ---- sweeping ------------------------------------------------------------------------------------------- */
TEST(dxss_cleanup_sweep_removes_every_test_store) {
    SETUP(CertOpenStore); NAME("sw1"); NAME2("sw2");
    HCERTSTORE a = ds_open(nm, 0), b = ds_open(nm2, 0);
    if (a) { ds_add_ok(a, 0); U(CertCloseStore)(a, 0); }
    if (b) U(CertCloseStore)(b, 0);
    CHECK(ds_key_exists(0, nm, NULL) && ds_key_exists(0, nm2, NULL));
    ds_sweep();
    CHECK(!ds_key_exists(0, nm, NULL));
    CHECK(!ds_key_exists(0, nm2, NULL));
    EXPECT_EQ(ds_count_named(nm, 0, CERT_STORE_OPEN_EXISTING_FLAG), -1);
    ds_end();
}
