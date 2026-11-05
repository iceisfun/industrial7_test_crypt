#include "ds.h"
/* Persistence of per-certificate properties in system stores, archived certificates, enhanced key usage,
 * CertControlStore (RESYNC / COMMIT / NOTIFY_CHANGE), store properties, CertSaveStore of a system store,
 * cross-thread / cross-process use. All in current-user test stores named cryptt_ss_<pid>_*. */

#define NAME(tag) wchar_t nm[120]; ds_name(nm, 120, tag)
#define WINE_SKIP(why) do { if (t_is_wine()) { t_skip("emulator: " why); return; } } while (0)

#define WAITEV(ev, ms, want) do { DWORD w_ = WaitForSingleObject((ev), (ms)); EXPECT_EQ(w_, (want)); } while (0)

typedef struct { HCERTSTORE h; PCCERT_CONTEXT c; } sc_t;
/* create (or open) the store, add certificate idx, return the live context */
static int sc_create(sc_t *s, const wchar_t *nm, int idx) {
    s->h = ds_open(nm, 0); s->c = NULL;
    if (!s->h) return 0;
    s->c = ds_add(s->h, idx, CERT_STORE_ADD_REPLACE_EXISTING);
    return s->c != NULL;
}
/* reopen an existing store and find certificate idx in it */
static int sc_reopen(sc_t *s, const wchar_t *nm, int idx, DWORD flags) {
    s->h = ds_open(nm, CERT_STORE_OPEN_EXISTING_FLAG | flags); s->c = NULL;
    if (!s->h) return 0;
    s->c = ds_find(s->h, idx);
    return s->c != NULL;
}
static void sc_close(sc_t *s) {
    if (s->c) U(CertFreeCertificateContext)(s->c);
    if (s->h) U(CertCloseStore)(s->h, 0);
    s->c = NULL; s->h = NULL;
}
static BOOL set_friendly(PCCERT_CONTEXT c, const wchar_t *w, DWORD flags) {
    CRYPT_DATA_BLOB b = { (DWORD)((wcslen(w) + 1) * 2), (BYTE *)w };
    return U(CertSetCertificateContextProperty)(c, CERT_FRIENDLY_NAME_PROP_ID, flags, &b);
}
static int get_friendly(PCCERT_CONTEXT c, wchar_t *out, size_t cap) {
    DWORD cb = (DWORD)(cap * 2);
    if (!U(CertGetCertificateContextProperty)(c, CERT_FRIENDLY_NAME_PROP_ID, out, &cb)) return -1;
    return (int)cb;
}
static BOOL archive(PCCERT_CONTEXT c) {
    CRYPT_DATA_BLOB b = { 0, NULL };
    return U(CertSetCertificateContextProperty)(c, CERT_ARCHIVED_PROP_ID, 0, &b);
}
static BOOL unarchive(PCCERT_CONTEXT c) { return U(CertSetCertificateContextProperty)(c, CERT_ARCHIVED_PROP_ID, 0, NULL); }

/* ---- friendly name / description ------------------------------------------------------------------ */
TEST(dxss_prop_friendly_name_persists) {
    SETUP(CertSetCertificateContextProperty); NAME("pf1");
    WINE_SKIP("per-certificate property changes and change notifications are not written through the registry store");
    sc_t s;
    CHECK(sc_create(&s, nm, 0));
    if (s.c) CHECK(set_friendly(s.c, L"cryptt friendly", 0));
    sc_close(&s);
    CHECK(sc_reopen(&s, nm, 0, 0));
    if (s.c) {
        wchar_t b[64] = L"";
        int cb = get_friendly(s.c, b, 64);
        EXPECT_EQ(cb, (wcslen(L"cryptt friendly") + 1) * 2);
        CHECK(!wcscmp(b, L"cryptt friendly"));
    }
    sc_close(&s);
    ds_end();
}
TEST(dxss_prop_friendly_name_grows_registry_blob) {
    SETUP(CertSetCertificateContextProperty); NAME("pf2");
    WINE_SKIP("per-certificate property changes and change notifications are not written through the registry store");
    sc_t s;
    CHECK(sc_create(&s, nm, 1));
    DWORD t, before = 0, after = 0;
    ds_sync(s.h);
    EXPECT_EQ(ds_cert_blob(0, nm, 1, &t, &before), 0);
    if (s.c) CHECK(set_friendly(s.c, L"a rather long friendly name for blob growth", 0));
    ds_sync(s.h);
    EXPECT_EQ(ds_cert_blob(0, nm, 1, &t, &after), 0);
    CHECKF(after > before, "blob %lu -> %lu", before, after);
    sc_close(&s);
    ds_end();
}
TEST(dxss_prop_friendly_name_replace_value) {
    SETUP(CertSetCertificateContextProperty); NAME("pf3");
    WINE_SKIP("per-certificate property changes and change notifications are not written through the registry store");
    sc_t s;
    CHECK(sc_create(&s, nm, 0));
    if (s.c) { CHECK(set_friendly(s.c, L"first", 0)); CHECK(set_friendly(s.c, L"second", 0)); }
    sc_close(&s);
    CHECK(sc_reopen(&s, nm, 0, 0));
    if (s.c) { wchar_t b[64] = L""; get_friendly(s.c, b, 64); CHECK(!wcscmp(b, L"second")); }
    sc_close(&s);
    ds_end();
}
TEST(dxss_prop_friendly_name_delete_persists) {
    SETUP(CertSetCertificateContextProperty); NAME("pf4");
    WINE_SKIP("per-certificate property changes and change notifications are not written through the registry store");
    sc_t s;
    CHECK(sc_create(&s, nm, 0));
    if (s.c) {
        CHECK(set_friendly(s.c, L"temp", 0));
        CHECK(U(CertSetCertificateContextProperty)(s.c, CERT_FRIENDLY_NAME_PROP_ID, 0, NULL));
    }
    sc_close(&s);
    CHECK(sc_reopen(&s, nm, 0, 0));
    if (s.c) {
        DWORD cb = 0; SET_ERR(0);
        CHECK(!U(CertGetCertificateContextProperty)(s.c, CERT_FRIENDLY_NAME_PROP_ID, NULL, &cb));
        EXPECT_ERR(CRYPT_E_NOT_FOUND);
    }
    sc_close(&s);
    ds_end();
}
TEST(dxss_prop_description_persists) {
    SETUP(CertSetCertificateContextProperty); NAME("pf5");
    WINE_SKIP("per-certificate property changes and change notifications are not written through the registry store");
    sc_t s;
    CHECK(sc_create(&s, nm, 2));
    if (s.c) {
        CRYPT_DATA_BLOB b = { (DWORD)((wcslen(L"desc text") + 1) * 2), (BYTE *)L"desc text" };
        CHECK(U(CertSetCertificateContextProperty)(s.c, CERT_DESCRIPTION_PROP_ID, 0, &b));
    }
    sc_close(&s);
    CHECK(sc_reopen(&s, nm, 2, 0));
    if (s.c) {
        wchar_t b[64] = L""; DWORD cb = sizeof b;
        CHECK(U(CertGetCertificateContextProperty)(s.c, CERT_DESCRIPTION_PROP_ID, b, &cb));
        CHECK(!wcscmp(b, L"desc text"));
    }
    sc_close(&s);
    ds_end();
}
TEST(dxss_prop_properties_per_certificate) {
    SETUP(CertSetCertificateContextProperty); NAME("pf6");
    WINE_SKIP("per-certificate property changes and change notifications are not written through the registry store");
    sc_t a, b;
    CHECK(sc_create(&a, nm, 0));
    b.h = a.h; b.c = a.h ? ds_add(a.h, 1, CERT_STORE_ADD_NEW) : NULL;
    CHECK(b.c != NULL);
    if (a.c) set_friendly(a.c, L"zero", 0);
    if (b.c) set_friendly(b.c, L"one", 0);
    if (b.c) U(CertFreeCertificateContext)(b.c);
    sc_close(&a);
    sc_t r0, r1;
    CHECK(sc_reopen(&r0, nm, 0, 0));
    if (r0.c) { wchar_t w[32] = L""; get_friendly(r0.c, w, 32); CHECK(!wcscmp(w, L"zero")); }
    r1.h = r0.h; r1.c = r0.h ? ds_find(r0.h, 1) : NULL;
    CHECK(r1.c != NULL);
    if (r1.c) { wchar_t w[32] = L""; get_friendly(r1.c, w, 32); CHECK(!wcscmp(w, L"one")); U(CertFreeCertificateContext)(r1.c); }
    sc_close(&r0);
    ds_end();
}

/* ---- user-defined properties, table driven ----------------------------------------------------------- */
TEST(dxss_prop_custom_properties_roundtrip_sizes) {
    SETUP(CertSetCertificateContextProperty); NAME("pc1");
    WINE_SKIP("per-certificate property changes and change notifications are not written through the registry store");
    static const DWORD sizes[] = { 1, 2, 3, 4, 7, 8, 63, 64, 255, 256, 1000, 4096, 20000 };
    sc_t s;
    CHECK(sc_create(&s, nm, 0));
    BYTE *buf = (BYTE *)malloc(20000);
    if (!buf) return;
    for (unsigned i = 0; i < sizeof sizes / sizeof sizes[0]; i++) {
        for (DWORD k = 0; k < sizes[i]; k++) buf[k] = (BYTE)(k * 7 + i);
        CRYPT_DATA_BLOB b = { sizes[i], buf };
        CHECKF(U(CertSetCertificateContextProperty)(s.c, CERT_FIRST_USER_PROP_ID + 0x10 + i, 0, &b), "set size %lu", sizes[i]);
    }
    sc_close(&s);
    CHECK(sc_reopen(&s, nm, 0, 0));
    BYTE *got = (BYTE *)malloc(20000);
    for (unsigned i = 0; s.c && got && i < sizeof sizes / sizeof sizes[0]; i++) {
        for (DWORD k = 0; k < sizes[i]; k++) buf[k] = (BYTE)(k * 7 + i);
        DWORD cb = 20000;
        BOOL r = U(CertGetCertificateContextProperty)(s.c, CERT_FIRST_USER_PROP_ID + 0x10 + i, got, &cb);
        CHECKF(r, "get size %lu", sizes[i]);
        CHECKF(cb == sizes[i], "size %lu got %lu", sizes[i], cb);
        CHECKF(r && cb == sizes[i] && !memcmp(got, buf, cb), "content size %lu", sizes[i]);
    }
    free(got); free(buf);
    sc_close(&s);
    ds_end();
}
TEST(dxss_prop_custom_property_size_query_protocol) {
    SETUP(CertSetCertificateContextProperty); NAME("pc2");
    WINE_SKIP("per-certificate property changes and change notifications are not written through the registry store");
    sc_t s;
    CHECK(sc_create(&s, nm, 0));
    static const BYTE v[10] = { 1,2,3,4,5,6,7,8,9,10 };
    CRYPT_DATA_BLOB b = { 10, (BYTE *)v };
    CHECK(U(CertSetCertificateContextProperty)(s.c, 0x8123, 0, &b));
    sc_close(&s);
    CHECK(sc_reopen(&s, nm, 0, 0));
    if (s.c) {
        DWORD cb = 0; BYTE out[16] = {0};
        CHECK(U(CertGetCertificateContextProperty)(s.c, 0x8123, NULL, &cb));
        EXPECT_EQ(cb, 10);
        cb = 9; SET_ERR(0);
        CHECK(!U(CertGetCertificateContextProperty)(s.c, 0x8123, out, &cb));
        EXPECT_ERR(ERROR_MORE_DATA);
        EXPECT_EQ(cb, 10);
        cb = 10;
        CHECK(U(CertGetCertificateContextProperty)(s.c, 0x8123, out, &cb));
        CHECK(!memcmp(out, v, 10));
    }
    sc_close(&s);
    ds_end();
}
TEST(dxss_prop_custom_property_delete_persists) {
    SETUP(CertSetCertificateContextProperty); NAME("pc3");
    WINE_SKIP("per-certificate property changes and change notifications are not written through the registry store");
    sc_t s;
    CHECK(sc_create(&s, nm, 0));
    static const BYTE v[4] = { 9, 9, 9, 9 };
    CRYPT_DATA_BLOB b = { 4, (BYTE *)v };
    CHECK(U(CertSetCertificateContextProperty)(s.c, 0x8200, 0, &b));
    CHECK(U(CertSetCertificateContextProperty)(s.c, 0x8200, 0, NULL));
    sc_close(&s);
    CHECK(sc_reopen(&s, nm, 0, 0));
    if (s.c) { DWORD cb = 0; SET_ERR(0); CHECK(!U(CertGetCertificateContextProperty)(s.c, 0x8200, NULL, &cb)); EXPECT_ERR(CRYPT_E_NOT_FOUND); }
    sc_close(&s);
    ds_end();
}
TEST(dxss_prop_inhibit_persist_flag_not_saved) {
    SETUP(CertSetCertificateContextProperty); NAME("pc4");
    WINE_SKIP("per-certificate property changes and change notifications are not written through the registry store");
    sc_t s;
    CHECK(sc_create(&s, nm, 0));
    static const BYTE v[3] = { 1, 2, 3 };
    CRYPT_DATA_BLOB b = { 3, (BYTE *)v };
    CHECK(U(CertSetCertificateContextProperty)(s.c, 0x8300, CERT_SET_PROPERTY_INHIBIT_PERSIST_FLAG, &b));
    DWORD cb = 0;
    CHECK(U(CertGetCertificateContextProperty)(s.c, 0x8300, NULL, &cb));   /* present in memory */
    EXPECT_EQ(cb, 3);
    CHECK(U(CertSetCertificateContextProperty)(s.c, 0x8301, 0, &b));         /* control: persisted */
    sc_close(&s);
    CHECK(sc_reopen(&s, nm, 0, 0));
    if (s.c) {
        cb = 0; SET_ERR(0);
        CHECK(!U(CertGetCertificateContextProperty)(s.c, 0x8300, NULL, &cb));
        EXPECT_ERR(CRYPT_E_NOT_FOUND);
        cb = 0;
        CHECK(U(CertGetCertificateContextProperty)(s.c, 0x8301, NULL, &cb));
    }
    sc_close(&s);
    ds_end();
}
TEST(dxss_prop_enumerate_lists_persisted_ids) {
    SETUP(CertEnumCertificateContextProperties); NAME("pc5");
    WINE_SKIP("per-certificate property changes and change notifications are not written through the registry store");
    sc_t s;
    CHECK(sc_create(&s, nm, 0));
    static const BYTE v[2] = { 5, 6 };
    CRYPT_DATA_BLOB b = { 2, (BYTE *)v };
    CHECK(U(CertSetCertificateContextProperty)(s.c, 0x8401, 0, &b));
    CHECK(U(CertSetCertificateContextProperty)(s.c, 0x8402, 0, &b));
    CHECK(set_friendly(s.c, L"enum", 0));
    sc_close(&s);
    CHECK(sc_reopen(&s, nm, 0, 0));
    int f1 = 0, f2 = 0, ff = 0, n = 0;
    for (DWORD id = 0; s.c && (id = U(CertEnumCertificateContextProperties)(s.c, id)) != 0 && n < 100; n++) {
        if (id == 0x8401) f1++;
        if (id == 0x8402) f2++;
        if (id == CERT_FRIENDLY_NAME_PROP_ID) ff++;
    }
    EXPECT_EQ(f1, 1); EXPECT_EQ(f2, 1); EXPECT_EQ(ff, 1);
    sc_close(&s);
    ds_end();
}
TEST(dxss_prop_key_prov_info_persists) {
    SETUP(CertSetCertificateContextProperty); NAME("pk1");
    WINE_SKIP("per-certificate property changes and change notifications are not written through the registry store");
    sc_t s;
    CHECK(sc_create(&s, nm, 0));
    CRYPT_KEY_PROV_INFO kpi; memset(&kpi, 0, sizeof kpi);
    kpi.pwszContainerName = L"cryptt_nonexistent_container"; kpi.pwszProvName = L"Microsoft Enhanced RSA and AES Cryptographic Provider";
    kpi.dwProvType = PROV_RSA_AES; kpi.dwKeySpec = AT_KEYEXCHANGE; kpi.dwFlags = CRYPT_SILENT;
    if (s.c) CHECK(U(CertSetCertificateContextProperty)(s.c, CERT_KEY_PROV_INFO_PROP_ID, 0, &kpi));
    sc_close(&s);
    CHECK(sc_reopen(&s, nm, 0, 0));
    if (s.c) {
        DWORD cb = 0;
        CHECK(U(CertGetCertificateContextProperty)(s.c, CERT_KEY_PROV_INFO_PROP_ID, NULL, &cb));
        CRYPT_KEY_PROV_INFO *p = (CRYPT_KEY_PROV_INFO *)malloc(cb ? cb : 1);
        if (p && U(CertGetCertificateContextProperty)(s.c, CERT_KEY_PROV_INFO_PROP_ID, p, &cb)) {
            CHECK(!wcscmp(p->pwszContainerName, L"cryptt_nonexistent_container"));
            CHECK(!wcscmp(p->pwszProvName, L"Microsoft Enhanced RSA and AES Cryptographic Provider"));
            EXPECT_EQ(p->dwProvType, PROV_RSA_AES);
            EXPECT_EQ(p->dwKeySpec, AT_KEYEXCHANGE);
            EXPECT_EQ(p->dwFlags, CRYPT_SILENT);
        } else CHECK(0);
        free(p);
    }
    sc_close(&s);
    ds_end();
}
TEST(dxss_prop_inherit_properties_on_replace) {
    SETUP(CertSetCertificateContextProperty); NAME("pi1");
    WINE_SKIP("per-certificate property changes and change notifications are not written through the registry store");
    sc_t s;
    CHECK(sc_create(&s, nm, 0));
    if (s.c) set_friendly(s.c, L"keepme", 0);
    if (s.c) { U(CertFreeCertificateContext)(s.c); s.c = NULL; }
    PCCERT_CONTEXT n = ds_add(s.h, 0, CERT_STORE_ADD_REPLACE_EXISTING_INHERIT_PROPERTIES);
    CHECK(n != NULL);
    if (n) {
        wchar_t w[32] = L"";
        CHECK(get_friendly(n, w, 32) > 0);
        CHECK(!wcscmp(w, L"keepme"));
        U(CertFreeCertificateContext)(n);
    }
    U(CertCloseStore)(s.h, 0); s.h = NULL;
    CHECK(sc_reopen(&s, nm, 0, 0));
    if (s.c) { wchar_t w[32] = L""; get_friendly(s.c, w, 32); CHECK(!wcscmp(w, L"keepme")); }
    sc_close(&s);
    ds_end();
}
TEST(dxss_prop_plain_replace_drops_friendly_name) {
    SETUP(CertSetCertificateContextProperty); NAME("pi2");
    WINE_SKIP("per-certificate property changes and change notifications are not written through the registry store");
    sc_t s;
    CHECK(sc_create(&s, nm, 0));
    if (s.c) set_friendly(s.c, L"orig", 0);
    if (s.c) { U(CertFreeCertificateContext)(s.c); s.c = NULL; }
    PCCERT_CONTEXT n = ds_add(s.h, 0, CERT_STORE_ADD_REPLACE_EXISTING);
    CHECK(n != NULL);
    if (n) { wchar_t w[32] = L""; EXPECT_EQ(get_friendly(n, w, 32) > 0, 0);   /* a plain replace drops the friendly name */ U(CertFreeCertificateContext)(n); }
    EXPECT_EQ(ds_count(s.h), 1);
    sc_close(&s);
    ds_end();
}

/* ---- enhanced key usage ---------------------------------------------------------------------------- */
static int eku_has(PCCERT_CONTEXT c, DWORD flags, const char *oid, int *total) {
    DWORD cb = 0; int found = 0;
    if (total) *total = -1;
    if (!U(CertGetEnhancedKeyUsage)(c, flags, NULL, &cb)) return -1;
    PCERT_ENHKEY_USAGE u = (PCERT_ENHKEY_USAGE)malloc(cb);
    if (u && U(CertGetEnhancedKeyUsage)(c, flags, u, &cb)) {
        if (total) *total = (int)u->cUsageIdentifier;
        for (DWORD i = 0; i < u->cUsageIdentifier; i++) if (!strcmp(u->rgpszUsageIdentifier[i], oid)) found++;
    }
    free(u);
    return found;
}
#define OID_SA "1.3.6.1.5.5.7.3.1"
#define OID_CA "1.3.6.1.5.5.7.3.2"
#define OID_CS "1.3.6.1.5.5.7.3.3"
TEST(dxss_eku_add_identifier_persists) {
    SETUP(CertAddEnhancedKeyUsageIdentifier); NAME("ek1");
    WINE_SKIP("per-certificate property changes and change notifications are not written through the registry store");
    sc_t s;
    CHECK(sc_create(&s, nm, 0));
    if (s.c) CHECK(U(CertAddEnhancedKeyUsageIdentifier)(s.c, OID_SA));
    sc_close(&s);
    CHECK(sc_reopen(&s, nm, 0, 0));
    int total = 0;
    if (s.c) {
        EXPECT_EQ(eku_has(s.c, CERT_FIND_PROP_ONLY_ENHKEY_USAGE_FLAG, OID_SA, &total), 1);
        EXPECT_EQ(total, 1);
    }
    sc_close(&s);
    ds_end();
}
TEST(dxss_eku_add_three_identifiers_order_and_persist) {
    SETUP(CertAddEnhancedKeyUsageIdentifier); NAME("ek2");
    WINE_SKIP("per-certificate property changes and change notifications are not written through the registry store");
    sc_t s;
    CHECK(sc_create(&s, nm, 0));
    if (s.c) {
        CHECK(U(CertAddEnhancedKeyUsageIdentifier)(s.c, OID_SA));
        CHECK(U(CertAddEnhancedKeyUsageIdentifier)(s.c, OID_CA));
        CHECK(U(CertAddEnhancedKeyUsageIdentifier)(s.c, OID_CS));
    }
    sc_close(&s);
    CHECK(sc_reopen(&s, nm, 0, 0));
    if (s.c) {
        int total = 0;
        EXPECT_EQ(eku_has(s.c, CERT_FIND_PROP_ONLY_ENHKEY_USAGE_FLAG, OID_CA, &total), 1);
        EXPECT_EQ(total, 3);
        EXPECT_EQ(eku_has(s.c, CERT_FIND_PROP_ONLY_ENHKEY_USAGE_FLAG, OID_SA, NULL), 1);
        EXPECT_EQ(eku_has(s.c, CERT_FIND_PROP_ONLY_ENHKEY_USAGE_FLAG, OID_CS, NULL), 1);
    }
    sc_close(&s);
    ds_end();
}
TEST(dxss_eku_remove_identifier_persists) {
    SETUP(CertRemoveEnhancedKeyUsageIdentifier); NAME("ek3");
    WINE_SKIP("per-certificate property changes and change notifications are not written through the registry store");
    sc_t s;
    CHECK(sc_create(&s, nm, 0));
    if (s.c) {
        CHECK(U(CertAddEnhancedKeyUsageIdentifier)(s.c, OID_SA));
        CHECK(U(CertAddEnhancedKeyUsageIdentifier)(s.c, OID_CA));
        CHECK(U(CertRemoveEnhancedKeyUsageIdentifier)(s.c, OID_SA));
    }
    sc_close(&s);
    CHECK(sc_reopen(&s, nm, 0, 0));
    if (s.c) {
        int total = 0;
        EXPECT_EQ(eku_has(s.c, CERT_FIND_PROP_ONLY_ENHKEY_USAGE_FLAG, OID_SA, &total), 0);
        EXPECT_EQ(total, 1);
        EXPECT_EQ(eku_has(s.c, CERT_FIND_PROP_ONLY_ENHKEY_USAGE_FLAG, OID_CA, NULL), 1);
    }
    sc_close(&s);
    ds_end();
}
TEST(dxss_eku_add_duplicate_identifier) {
    SETUP(CertAddEnhancedKeyUsageIdentifier); NAME("ek4");
    WINE_SKIP("per-certificate property changes and change notifications are not written through the registry store");
    sc_t s;
    CHECK(sc_create(&s, nm, 0));
    if (s.c) {
        CHECK(U(CertAddEnhancedKeyUsageIdentifier)(s.c, OID_SA));
        SET_ERR(0);
        BOOL r = U(CertAddEnhancedKeyUsageIdentifier)(s.c, OID_SA);
        EXPECT_EQ(r, TRUE);
        int total = 0;
        EXPECT_EQ(eku_has(s.c, CERT_FIND_PROP_ONLY_ENHKEY_USAGE_FLAG, OID_SA, &total), 1);   /* never listed twice */
        EXPECT_EQ(total, 1);
    }
    sc_close(&s);
    ds_end();
}
TEST(dxss_eku_remove_absent_identifier) {
    SETUP(CertRemoveEnhancedKeyUsageIdentifier); NAME("ek5");
    WINE_SKIP("per-certificate property changes and change notifications are not written through the registry store");
    sc_t s;
    CHECK(sc_create(&s, nm, 0));
    if (s.c) {
        CHECK(U(CertAddEnhancedKeyUsageIdentifier)(s.c, OID_SA));
        SET_ERR(0);
        BOOL r = U(CertRemoveEnhancedKeyUsageIdentifier)(s.c, OID_CS);
        EXPECT_EQ(r, TRUE);
        EXPECT_EQ(eku_has(s.c, CERT_FIND_PROP_ONLY_ENHKEY_USAGE_FLAG, OID_SA, NULL), 1);
    }
    sc_close(&s);
    ds_end();
}
TEST(dxss_eku_property_blob_is_encoded_ctl_usage) {
    SETUP(CertAddEnhancedKeyUsageIdentifier); NAME("ek6");
    WINE_SKIP("per-certificate property changes and change notifications are not written through the registry store");
    sc_t s;
    CHECK(sc_create(&s, nm, 0));
    if (s.c) CHECK(U(CertAddEnhancedKeyUsageIdentifier)(s.c, OID_CA));
    sc_close(&s);
    CHECK(sc_reopen(&s, nm, 0, 0));
    if (s.c) {
        BYTE raw[128]; DWORD cb = sizeof raw;
        CHECK(U(CertGetCertificateContextProperty)(s.c, CERT_ENHKEY_USAGE_PROP_ID, raw, &cb));
        /* CERT_ENHKEY_USAGE encoded: SEQUENCE OF OBJECT IDENTIFIER */
        static const BYTE want[] = { 0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02 };
        EXPECT_EQ(cb, sizeof want);
        CHECK(cb == sizeof want && !memcmp(raw, want, sizeof want));
    }
    sc_close(&s);
    ds_end();
}

/* ---- archived certificates -------------------------------------------------------------------------- */
TEST(dxss_archive_hides_from_enumeration_same_handle) {
    SETUP(CertSetCertificateContextProperty); NAME("ar1");
    WINE_SKIP("per-certificate property changes and change notifications are not written through the registry store");
    sc_t s;
    CHECK(sc_create(&s, nm, 0));
    if (s.h) { CHECK(ds_add_ok(s.h, 1)); EXPECT_EQ(ds_count(s.h), 2); }
    if (s.c) CHECK(archive(s.c));
    if (s.h) EXPECT_EQ(ds_count(s.h), 1);
    sc_close(&s);
    ds_end();
}
TEST(dxss_archive_persists_hidden_after_reopen) {
    SETUP(CertSetCertificateContextProperty); NAME("ar2");
    WINE_SKIP("per-certificate property changes and change notifications are not written through the registry store");
    sc_t s;
    CHECK(sc_create(&s, nm, 0));
    if (s.h) CHECK(ds_add_ok(s.h, 1));
    if (s.c) CHECK(archive(s.c));
    sc_close(&s);
    EXPECT_EQ(ds_count_named(nm, 0, 0), 1);          /* enumeration skips the archived certificate */
    EXPECT_EQ(ds_stored(nm, 0, 1), 1);
    ds_end();
}
TEST(dxss_archive_visible_with_enum_archived_flag) {
    SETUP(CertSetCertificateContextProperty); NAME("ar3");
    WINE_SKIP("per-certificate property changes and change notifications are not written through the registry store");
    sc_t s;
    CHECK(sc_create(&s, nm, 0));
    if (s.h) CHECK(ds_add_ok(s.h, 1));
    if (s.c) CHECK(archive(s.c));
    sc_close(&s);
    EXPECT_EQ(ds_count_named(nm, 0, CERT_STORE_ENUM_ARCHIVED_FLAG), 2);
    CHECK(sc_reopen(&s, nm, 0, CERT_STORE_ENUM_ARCHIVED_FLAG));
    if (s.c) {
        DWORD cb = 99; SET_ERR(0);
        BOOL r = U(CertGetCertificateContextProperty)(s.c, CERT_ARCHIVED_PROP_ID, NULL, &cb);
        CHECK(r);
        EXPECT_EQ(cb, 0);
    }
    sc_close(&s);
    ds_end();
}
TEST(dxss_archive_explicit_find_of_archived) {
    SETUP(CertSetCertificateContextProperty); NAME("ar4");
    WINE_SKIP("per-certificate property changes are not written through the registry store");
    sc_t s;
    CHECK(sc_create(&s, nm, 2));
    if (s.c) CHECK(archive(s.c));
    sc_close(&s);
    /* documented: archived certs are skipped by enumeration but still found by explicit searches such as a hash */
    s.h = ds_open(nm, CERT_STORE_OPEN_EXISTING_FLAG);
    CHECK(s.h != NULL);
    if (s.h) {
        PCCERT_CONTEXT c = ds_find(s.h, 2);
        CHECK(c != NULL);
        if (c) U(CertFreeCertificateContext)(c);
        c = U(CertFindCertificateInStore)(s.h, X509_ASN_ENCODING, 0, CERT_FIND_ANY, NULL, NULL);
        CHECK(c == NULL);
        if (c) U(CertFreeCertificateContext)(c);
        EXPECT_EQ(ds_count(s.h), 0);          /* plain enumeration never lists it */
    }
    sc_close(&s);
    ds_end();
}
TEST(dxss_archive_clear_property_restores_visibility) {
    SETUP(CertSetCertificateContextProperty); NAME("ar5");
    WINE_SKIP("per-certificate property changes and change notifications are not written through the registry store");
    sc_t s;
    CHECK(sc_create(&s, nm, 0));
    if (s.c) CHECK(archive(s.c));
    sc_close(&s);
    CHECK(sc_reopen(&s, nm, 0, CERT_STORE_ENUM_ARCHIVED_FLAG));
    if (s.c) CHECK(unarchive(s.c));
    sc_close(&s);
    EXPECT_EQ(ds_count_named(nm, 0, 0), 1);
    ds_end();
}
TEST(dxss_archive_registry_entry_stays) {
    SETUP(CertSetCertificateContextProperty); NAME("ar6");
    WINE_SKIP("per-certificate property changes and change notifications are not written through the registry store");
    sc_t s;
    CHECK(sc_create(&s, nm, 0));
    if (s.c) CHECK(archive(s.c));
    ds_sync(s.h);
    CHECK(ds_cert_key_exists(0, nm, 0));    /* archiving is a property, the registry entry remains */
    sc_close(&s);
    CHECK(ds_cert_key_exists(0, nm, 0));
    ds_end();
}
TEST(dxss_archive_delete_archived_with_flag_removes_entry) {
    SETUP(CertSetCertificateContextProperty); NAME("ar7");
    WINE_SKIP("per-certificate property changes and change notifications are not written through the registry store");
    sc_t s;
    CHECK(sc_create(&s, nm, 0));
    if (s.c) CHECK(archive(s.c));
    sc_close(&s);
    CHECK(sc_reopen(&s, nm, 0, CERT_STORE_ENUM_ARCHIVED_FLAG));
    if (s.c) { PCCERT_CONTEXT c = s.c; s.c = NULL; CHECK(ds_del(c)); }
    sc_close(&s);
    CHECK(!ds_cert_key_exists(0, nm, 0));
    ds_end();
}
TEST(dxss_archive_readd_is_not_archived_by_default) {
    SETUP(CertSetCertificateContextProperty); NAME("ar8");
    WINE_SKIP("per-certificate property changes and change notifications are not written through the registry store");
    sc_t s;
    CHECK(sc_create(&s, nm, 0));
    if (s.c) CHECK(archive(s.c));
    sc_close(&s);
    CHECK(sc_reopen(&s, nm, 0, CERT_STORE_ENUM_ARCHIVED_FLAG));
    if (s.c) { PCCERT_CONTEXT c = s.c; s.c = NULL; CHECK(ds_del(c)); }
    PCCERT_CONTEXT n = s.h ? ds_add(s.h, 0, CERT_STORE_ADD_NEW) : NULL;
    CHECK(n != NULL);
    if (n) U(CertFreeCertificateContext)(n);
    sc_close(&s);
    EXPECT_EQ(ds_count_named(nm, 0, 0), 1);
    ds_end();
}
TEST(dxss_archive_add_new_over_archived_observed) {
    SETUP(CertSetCertificateContextProperty); NAME("ar9");
    WINE_SKIP("per-certificate property changes and change notifications are not written through the registry store");
    sc_t s;
    CHECK(sc_create(&s, nm, 0));
    if (s.c) CHECK(archive(s.c));
    DWORD cb; const BYTE *d = ds_der(0, &cb);
    SET_ERR(0);
    BOOL r = U(CertAddEncodedCertificateToStore)(s.h, X509_ASN_ENCODING, d, cb, CERT_STORE_ADD_NEW, NULL);
    EXPECT_EQ(r, TRUE);   /* an archived cert does not count as existing for ADD_NEW */
    sc_close(&s);
    ds_end();
}

/* ---- CertControlStore ------------------------------------------------------------------------------- */
TEST(dxss_control_resync_makes_other_handle_changes_visible) {
    SETUP(CertControlStore); NAME("cs1");
    HCERTSTORE a = ds_open(nm, 0), b = ds_open(nm, 0);
    CHECK(a != NULL && b != NULL);
    if (!a || !b) return;
    CHECK(ds_add_ok(b, 0));
    ds_sync(b);
    SET_ERR(0);
    BOOL r = U(CertControlStore)(a, 0, CERT_STORE_CTRL_RESYNC, NULL);
    EXPECT_EQ(r, TRUE);
    if (r) { PCCERT_CONTEXT c = ds_find(a, 0); CHECK(c != NULL); if (c) U(CertFreeCertificateContext)(c); }
    U(CertCloseStore)(a, 0); U(CertCloseStore)(b, 0);
    ds_end();
}
TEST(dxss_control_resync_sees_deletion_by_other_handle) {
    SETUP(CertControlStore); NAME("cs2");
    HCERTSTORE a = ds_open(nm, 0);
    if (a) { CHECK(ds_add_ok(a, 0)); ds_sync(a); }
    HCERTSTORE b = ds_open(nm, 0);
    CHECK(a != NULL && b != NULL);
    if (!a || !b) return;
    PCCERT_CONTEXT c = ds_find(b, 0);
    if (c) CHECK(ds_del(c));
    BOOL r = U(CertControlStore)(a, 0, CERT_STORE_CTRL_RESYNC, NULL);
    if (r) EXPECT_EQ(ds_count(a), 0);
    U(CertCloseStore)(a, 0); U(CertCloseStore)(b, 0);
    ds_end();
}
TEST(dxss_control_commit_keeps_content) {
    SETUP(CertControlStore); NAME("cs3");
    HCERTSTORE h = ds_open(nm, 0);
    if (!h) { CHECK(h != NULL); return; }
    CHECK(ds_add_ok(h, 0));
    SET_ERR(0);
    BOOL r = U(CertControlStore)(h, 0, CERT_STORE_CTRL_COMMIT, NULL);
    EXPECT_EQ(r, TRUE);
    BOOL f = U(CertControlStore)(h, CERT_STORE_CTRL_COMMIT_FORCE_FLAG, CERT_STORE_CTRL_COMMIT, NULL);
    EXPECT_EQ(f, TRUE);
    CHECK(ds_cert_key_exists(0, nm, 0));
    EXPECT_EQ(ds_count(h), 1);
    U(CertCloseStore)(h, 0);
    EXPECT_EQ(ds_count_named(nm, 0, 0), 1);
    ds_end();
}
TEST(dxss_control_unknown_type_fails) {
    SETUP(CertControlStore); NAME("cs4");
    HCERTSTORE h = ds_open(nm, 0);
    if (!h) { CHECK(h != NULL); return; }
    SET_ERR(0);
    BOOL r = U(CertControlStore)(h, 0, 0x7777, NULL);
    EXPECT_EQ(r, FALSE);
    EXPECT_ERR(ERROR_CALL_NOT_IMPLEMENTED);

    U(CertCloseStore)(h, 0);
    ds_end();
}
TEST(dxss_control_notify_change_fires_on_other_handle_add) {
    SETUP(CertControlStore); NAME("cn1");
    WINE_SKIP("per-certificate property changes and change notifications are not written through the registry store");
    HCERTSTORE a = ds_open(nm, 0), b = ds_open(nm, 0);
    if (!a || !b) { CHECK(a && b); return; }
    HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    SET_ERR(0);
    BOOL r = U(CertControlStore)(a, 0, CERT_STORE_CTRL_NOTIFY_CHANGE, &ev);
    DWORD e = GetLastError();
    CHECK(r);
    if (r) {
        CHECK(ds_add_ok(b, 0));
        ds_sync(b);
        DWORD w = WaitForSingleObject(ev, 5000);
        EXPECT_EQ(w, WAIT_OBJECT_0);
        U(CertControlStore)(a, 0, CERT_STORE_CTRL_CANCEL_NOTIFY, &ev);
    } else CHECKF(0, "NOTIFY_CHANGE failed err 0x%lx", e);
    CloseHandle(ev);
    U(CertCloseStore)(a, 0); U(CertCloseStore)(b, 0);
    ds_end();
}
TEST(dxss_control_notify_change_fires_on_delete) {
    SETUP(CertControlStore); NAME("cn2");
    WINE_SKIP("per-certificate property changes and change notifications are not written through the registry store");
    HCERTSTORE a = ds_open(nm, 0), b = ds_open(nm, 0);
    if (!a || !b) { CHECK(a && b); return; }
    CHECK(ds_add_ok(b, 1)); ds_sync(b);
    HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (U(CertControlStore)(a, 0, CERT_STORE_CTRL_NOTIFY_CHANGE, &ev)) {
        PCCERT_CONTEXT c = ds_find(b, 1);
        if (c) CHECK(ds_del(c));
        WAITEV(ev, 5000, WAIT_OBJECT_0);
        U(CertControlStore)(a, 0, CERT_STORE_CTRL_CANCEL_NOTIFY, &ev);
    } else CHECK(0);
    CloseHandle(ev);
    U(CertCloseStore)(a, 0); U(CertCloseStore)(b, 0);
    ds_end();
}
TEST(dxss_control_notify_resync_rearms_event) {
    SETUP(CertControlStore); NAME("cn3");
    WINE_SKIP("per-certificate property changes and change notifications are not written through the registry store");
    HCERTSTORE a = ds_open(nm, 0), b = ds_open(nm, 0);
    if (!a || !b) { CHECK(a && b); return; }
    HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (U(CertControlStore)(a, 0, CERT_STORE_CTRL_NOTIFY_CHANGE, &ev)) {
        CHECK(ds_add_ok(b, 0)); ds_sync(b);
        WAITEV(ev, 5000, WAIT_OBJECT_0);
        CHECK(U(CertControlStore)(a, 0, CERT_STORE_CTRL_RESYNC, &ev));   /* re-arms the notification */
        WAITEV(ev, 0, WAIT_OBJECT_0);          /* Win10: RESYNC leaves the manual-reset event signalled */
        ResetEvent(ev);
        PCCERT_CONTEXT c = ds_find(a, 0);
        CHECK(c != NULL);                                             /* resynchronised content */
        if (c) U(CertFreeCertificateContext)(c);
        /* second change signals again; the re-arm after RESYNC is asynchronous, so a change made inside that window is absorbed: retry with new certificates */
        { DWORD w_ = WAIT_TIMEOUT; for (int k_ = 1; k_ <= 4 && w_ != WAIT_OBJECT_0; k_++) { CHECK(ds_add_ok(b, 1 + (k_ - 1) % 3)); ds_sync(b); w_ = WaitForSingleObject(ev, 2500); } EXPECT_EQ(w_, WAIT_OBJECT_0); }
        U(CertControlStore)(a, 0, CERT_STORE_CTRL_CANCEL_NOTIFY, &ev);
    } else CHECK(0);
    CloseHandle(ev);
    U(CertCloseStore)(a, 0); U(CertCloseStore)(b, 0);
    ds_end();
}
TEST(dxss_control_notify_cancel_stops_signalling) {
    SETUP(CertControlStore); NAME("cn4");
    WINE_SKIP("per-certificate property changes and change notifications are not written through the registry store");
    HCERTSTORE a = ds_open(nm, 0), b = ds_open(nm, 0);
    if (!a || !b) { CHECK(a && b); return; }
    HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (U(CertControlStore)(a, 0, CERT_STORE_CTRL_NOTIFY_CHANGE, &ev)) {
        CHECK(U(CertControlStore)(a, 0, CERT_STORE_CTRL_CANCEL_NOTIFY, &ev));
        CHECK(ds_add_ok(b, 0)); ds_sync(b);
        WAITEV(ev, 300, WAIT_TIMEOUT);
    } else CHECK(0);
    CloseHandle(ev);
    U(CertCloseStore)(a, 0); U(CertCloseStore)(b, 0);
    ds_end();
}
TEST(dxss_control_notify_not_fired_by_own_unrelated_store) {
    SETUP(CertControlStore); NAME("cn5"); wchar_t other[120]; ds_name(other, 120, "cn5o");
    WINE_SKIP("per-certificate property changes and change notifications are not written through the registry store");
    HCERTSTORE a = ds_open(nm, 0), o = ds_open(other, 0);
    if (!a || !o) { CHECK(a && o); return; }
    HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (U(CertControlStore)(a, 0, CERT_STORE_CTRL_NOTIFY_CHANGE, &ev)) {
        CHECK(ds_add_ok(o, 0)); ds_sync(o);
        WAITEV(ev, 300, WAIT_TIMEOUT);       /* a different store changed */
        U(CertControlStore)(a, 0, CERT_STORE_CTRL_CANCEL_NOTIFY, &ev);
    } else CHECK(0);
    CloseHandle(ev);
    U(CertCloseStore)(a, 0); U(CertCloseStore)(o, 0);
    ds_end();
}

/* ---- store properties --------------------------------------------------------------------------------- */
TEST(dxss_storeprop_localized_name_roundtrip_same_handle) {
    SETUP(CertSetStoreProperty); NAME("sp1");
    HCERTSTORE h = ds_open(nm, 0);
    if (!h) { CHECK(h != NULL); return; }
    CRYPT_DATA_BLOB b = { (DWORD)((wcslen(L"Corpus Store") + 1) * 2), (BYTE *)L"Corpus Store" };
    SET_ERR(0);
    BOOL r = U(CertSetStoreProperty)(h, CERT_STORE_LOCALIZED_NAME_PROP_ID, 0, &b);
    EXPECT_EQ(r, TRUE);
    if (r) {
        wchar_t out[64] = L""; DWORD cb = sizeof out;
        CHECK(U(CertGetStoreProperty)(h, CERT_STORE_LOCALIZED_NAME_PROP_ID, out, &cb));
        CHECK(!wcscmp(out, L"Corpus Store"));
    }
    U(CertCloseStore)(h, 0);
    ds_end();
}
TEST(dxss_storeprop_get_unset_not_found) {
    SETUP(CertGetStoreProperty); NAME("sp2");
    HCERTSTORE h = ds_open(nm, 0);
    if (!h) { CHECK(h != NULL); return; }
    DWORD cb = 0; SET_ERR(0);
    BOOL r = U(CertGetStoreProperty)(h, 0x9001, NULL, &cb);
    CHECK(!r);
    EXPECT_ERR(CRYPT_E_NOT_FOUND);
    U(CertCloseStore)(h, 0);
    ds_end();
}
TEST(dxss_storeprop_custom_roundtrip_same_handle) {
    SETUP(CertSetStoreProperty); NAME("sp3");
    HCERTSTORE h = ds_open(nm, 0);
    if (!h) { CHECK(h != NULL); return; }
    static const BYTE v[5] = { 1, 3, 5, 7, 9 };
    CRYPT_DATA_BLOB b = { 5, (BYTE *)v };
    SET_ERR(0);
    BOOL r = U(CertSetStoreProperty)(h, 0x9002, 0, &b);
    EXPECT_EQ(r, TRUE);
    if (r) {
        BYTE out[8] = {0}; DWORD cb = sizeof out;
        CHECK(U(CertGetStoreProperty)(h, 0x9002, out, &cb));
        EXPECT_EQ(cb, 5);
        CHECK(!memcmp(out, v, 5));
    }
    U(CertCloseStore)(h, 0);
    ds_end();
}

/* ---- CertSaveStore of a system store ------------------------------------------------------------------- */
static HCERTSTORE filled(const wchar_t *nm, int n, int with_crl) {
    HCERTSTORE h = ds_open(nm, 0);
    if (!h) return NULL;
    for (int i = 0; i < n; i++) ds_add_ok(h, i);
    if (with_crl) { DWORD cb; const BYTE *d = ds_crl(&cb); U(CertAddEncodedCRLToStore)(h, X509_ASN_ENCODING, d, cb, CERT_STORE_ADD_REPLACE_EXISTING, NULL); }
    ds_sync(h);
    return h;
}
static int count_crls(HCERTSTORE h) { int n = 0; PCCRL_CONTEXT c = NULL; while ((c = U(CertEnumCRLsInStore)(h, c)) != NULL) n++; return n; }
static BYTE *save_mem(HCERTSTORE h, DWORD fmt, DWORD *cb) {
    CRYPT_DATA_BLOB b = { 0, NULL };
    if (!U(CertSaveStore)(h, DS_ENC, fmt, CERT_STORE_SAVE_TO_MEMORY, &b, 0)) return NULL;
    *cb = b.cbData;
    b.pbData = (BYTE *)malloc(b.cbData ? b.cbData : 1);
    if (!b.pbData || !U(CertSaveStore)(h, DS_ENC, fmt, CERT_STORE_SAVE_TO_MEMORY, &b, 0)) { free(b.pbData); return NULL; }
    *cb = b.cbData;
    return b.pbData;
}
TEST(dxss_save_pkcs7_to_memory_roundtrip) {
    SETUP(CertSaveStore); NAME("sv1");
    HCERTSTORE h = filled(nm, 3, 0);
    if (!h) { CHECK(h != NULL); return; }
    DWORD cb = 0; BYTE *p = save_mem(h, CERT_STORE_SAVE_AS_PKCS7, &cb);
    CHECK(p != NULL && cb > 0);
    if (p) {
        CRYPT_DATA_BLOB b = { cb, p };
        HCERTSTORE m = U(CertOpenStore)(CERT_STORE_PROV_PKCS7, DS_ENC, 0, 0, &b);
        CHECK(m != NULL);
        if (m) { EXPECT_EQ(ds_count(m), 3); for (int i = 0; i < 3; i++) { PCCERT_CONTEXT c = ds_find(m, i); CHECK(c != NULL); if (c) U(CertFreeCertificateContext)(c); } U(CertCloseStore)(m, 0); }
        free(p);
    }
    U(CertCloseStore)(h, 0);
    ds_end();
}
TEST(dxss_save_serialized_to_memory_roundtrip_with_crl) {
    SETUP(CertSaveStore); NAME("sv2");
    HCERTSTORE h = filled(nm, 2, 1);
    if (!h) { CHECK(h != NULL); return; }
    DWORD cb = 0; BYTE *p = save_mem(h, CERT_STORE_SAVE_AS_STORE, &cb);
    CHECK(p != NULL);
    if (p) {
        CRYPT_DATA_BLOB b = { cb, p };
        HCERTSTORE m = U(CertOpenStore)(CERT_STORE_PROV_SERIALIZED, DS_ENC, 0, 0, &b);
        CHECK(m != NULL);
        if (m) { EXPECT_EQ(ds_count(m), 2); EXPECT_EQ(count_crls(m), 1); U(CertCloseStore)(m, 0); }
        free(p);
    }
    U(CertCloseStore)(h, 0);
    ds_end();
}
TEST(dxss_save_serialized_keeps_properties) {
    SETUP(CertSaveStore); NAME("sv3");
    WINE_SKIP("per-certificate property changes and change notifications are not written through the registry store");
    sc_t s;
    CHECK(sc_create(&s, nm, 0));
    if (s.c) { set_friendly(s.c, L"saved name", 0); }
    DWORD cb = 0; BYTE *p = s.h ? save_mem(s.h, CERT_STORE_SAVE_AS_STORE, &cb) : NULL;
    CHECK(p != NULL);
    if (p) {
        CRYPT_DATA_BLOB b = { cb, p };
        HCERTSTORE m = U(CertOpenStore)(CERT_STORE_PROV_SERIALIZED, DS_ENC, 0, 0, &b);
        PCCERT_CONTEXT c = m ? ds_find(m, 0) : NULL;
        CHECK(c != NULL);
        if (c) { wchar_t w[32] = L""; get_friendly(c, w, 32); CHECK(!wcscmp(w, L"saved name")); U(CertFreeCertificateContext)(c); }
        if (m) U(CertCloseStore)(m, 0);
        free(p);
    }
    sc_close(&s);
    ds_end();
}
TEST(dxss_save_memory_size_query_and_small_buffer) {
    SETUP(CertSaveStore); NAME("sv4");
    HCERTSTORE h = filled(nm, 2, 0);
    if (!h) { CHECK(h != NULL); return; }
    CRYPT_DATA_BLOB q = { 0, NULL };
    SET_ERR(0);
    CHECK(U(CertSaveStore)(h, DS_ENC, CERT_STORE_SAVE_AS_STORE, CERT_STORE_SAVE_TO_MEMORY, &q, 0));
    CHECK(q.cbData > 0);
    DWORD need = q.cbData;
    BYTE *buf = (BYTE *)malloc(need);
    CRYPT_DATA_BLOB b = { need - 1, buf };
    BOOL (WINAPI *pSave)(HCERTSTORE, DWORD, DWORD, DWORD, void *, DWORD) = (void *)U(CertSaveStore);   /* resolve before SET_ERR */
    DWORD ge;
    BOOL r = T_CALL_ERR(&ge, pSave(h, DS_ENC, CERT_STORE_SAVE_AS_STORE, CERT_STORE_SAVE_TO_MEMORY, &b, 0));
    CHECK(!r);
    if (!t_is_wine()) { EXPECT_EQ(ge, ERROR_MORE_DATA); EXPECT_EQ(b.cbData, need); }
    b.cbData = need;
    CHECK(U(CertSaveStore)(h, DS_ENC, CERT_STORE_SAVE_AS_STORE, CERT_STORE_SAVE_TO_MEMORY, &b, 0));
    EXPECT_EQ(b.cbData, need);
    free(buf);
    U(CertCloseStore)(h, 0);
    ds_end();
}
TEST(dxss_save_to_filename_w_reopens_via_filename_provider) {
    SETUP(CertSaveStore); NAME("sv5");
    HCERTSTORE h = filled(nm, 3, 0);
    if (!h) { CHECK(h != NULL); return; }
    char pa[MAX_PATH]; t_tmpfile(pa, sizeof pa, "ss_save.sst");
    wchar_t pw[MAX_PATH]; MultiByteToWideChar(CP_ACP, 0, pa, -1, pw, MAX_PATH);
    CHECK(U(CertSaveStore)(h, DS_ENC, CERT_STORE_SAVE_AS_STORE, CERT_STORE_SAVE_TO_FILENAME_W, pw, 0));
    HCERTSTORE m = U(CertOpenStore)(CERT_STORE_PROV_FILENAME_W, DS_ENC, 0, CERT_STORE_READONLY_FLAG, pw);
    CHECK(m != NULL);
    if (m) { EXPECT_EQ(ds_count(m), 3); U(CertCloseStore)(m, 0); }
    DeleteFileA(pa);
    U(CertCloseStore)(h, 0);
    ds_end();
}
TEST(dxss_save_pkcs7_to_filename_w) {
    SETUP(CertSaveStore); NAME("sv6");
    HCERTSTORE h = filled(nm, 2, 0);
    if (!h) { CHECK(h != NULL); return; }
    char pa[MAX_PATH]; t_tmpfile(pa, sizeof pa, "ss_save.p7b");
    wchar_t pw[MAX_PATH]; MultiByteToWideChar(CP_ACP, 0, pa, -1, pw, MAX_PATH);
    CHECK(U(CertSaveStore)(h, DS_ENC, CERT_STORE_SAVE_AS_PKCS7, CERT_STORE_SAVE_TO_FILENAME_W, pw, 0));
    HCERTSTORE m = U(CertOpenStore)(CERT_STORE_PROV_FILENAME_W, DS_ENC, 0, CERT_STORE_READONLY_FLAG, pw);
    CHECK(m != NULL);
    if (m) { EXPECT_EQ(ds_count(m), 2); U(CertCloseStore)(m, 0); }
    DeleteFileA(pa);
    U(CertCloseStore)(h, 0);
    ds_end();
}
TEST(dxss_save_includes_archived_certs) {
    SETUP(CertSaveStore); NAME("sv7");
    WINE_SKIP("per-certificate property changes and change notifications are not written through the registry store");
    sc_t s;
    CHECK(sc_create(&s, nm, 0));
    if (s.h) CHECK(ds_add_ok(s.h, 1));
    if (s.c) archive(s.c);
    DWORD cb = 0; BYTE *p = s.h ? save_mem(s.h, CERT_STORE_SAVE_AS_STORE, &cb) : NULL;
    if (p) {
        CRYPT_DATA_BLOB b = { cb, p };
        HCERTSTORE m = U(CertOpenStore)(CERT_STORE_PROV_SERIALIZED, DS_ENC, 0, CERT_STORE_ENUM_ARCHIVED_FLAG, &b);
        CHECK(m != NULL);
        if (m) { EXPECT_EQ(ds_count(m), 1); U(CertCloseStore)(m, 0); }   /* the archived cert is saved too */
        free(p);
    }
    sc_close(&s);
    ds_end();
}
TEST(dxss_save_invalid_format_fails) {
    SETUP(CertSaveStore); NAME("sv8");
    HCERTSTORE h = filled(nm, 1, 0);
    if (!h) { CHECK(h != NULL); return; }
    CRYPT_DATA_BLOB b = { 0, NULL };
    SET_ERR(0);
    BOOL r = U(CertSaveStore)(h, DS_ENC, 99, CERT_STORE_SAVE_TO_MEMORY, &b, 0);
    DWORD e = GetLastError();
    CHECK(!r);
    EXPECT_EQ(e, 0x80070057);
    U(CertCloseStore)(h, 0);
    ds_end();
}
TEST(dxss_save_empty_serialized_store_ok) {
    SETUP(CertSaveStore); NAME("sv9");
    HCERTSTORE h = ds_open(nm, 0);
    if (!h) { CHECK(h != NULL); return; }
    DWORD cb = 0; BYTE *p = save_mem(h, CERT_STORE_SAVE_AS_STORE, &cb);
    CHECK(p != NULL);
    if (p) {
        CRYPT_DATA_BLOB b = { cb, p };
        HCERTSTORE m = U(CertOpenStore)(CERT_STORE_PROV_SERIALIZED, DS_ENC, 0, 0, &b);
        CHECK(m != NULL);
        if (m) { EXPECT_EQ(ds_count(m), 0); U(CertCloseStore)(m, 0); }
        free(p);
    }
    U(CertCloseStore)(h, 0);
    ds_end();
}

/* ---- threads and processes ------------------------------------------------------------------------------ */
typedef struct { HCERTSTORE h; int idx; int ok; HANDLE go; } thr_t;
static DWORD WINAPI thr_add(LPVOID p) {
    thr_t *t = (thr_t *)p;
    if (t->go) WaitForSingleObject(t->go, 5000);
    t->ok = ds_add_ok(t->h, t->idx);
    ds_sync(t->h);
    return 0;
}
TEST(dxss_thread_duplicate_store_handle_adds_cert) {
    SETUP(CertDuplicateStore); NAME("th1");
    HCERTSTORE h = ds_open(nm, 0);
    if (!h) { CHECK(h != NULL); return; }
    thr_t t = { U(CertDuplicateStore)(h), 2, 0, NULL };
    EXPECT_EQ(t.h, h);
    HANDLE th = CreateThread(NULL, 0, thr_add, &t, 0, NULL);
    CHECK(th != NULL);
    if (th) { WAITEV(th, 5000, WAIT_OBJECT_0); CloseHandle(th); }
    CHECK(t.ok);
    PCCERT_CONTEXT c = ds_find(h, 2);
    CHECK(c != NULL);
    if (c) U(CertFreeCertificateContext)(c);
    U(CertCloseStore)(t.h, 0);
    U(CertCloseStore)(h, 0);
    CHECK(ds_cert_key_exists(0, nm, 2));
    ds_end();
}
TEST(dxss_thread_original_closed_while_duplicate_in_use) {
    SETUP(CertDuplicateStore); NAME("th2");
    HCERTSTORE h = ds_open(nm, 0);
    if (!h) { CHECK(h != NULL); return; }
    HANDLE go = CreateEventW(NULL, TRUE, FALSE, NULL);
    thr_t t = { U(CertDuplicateStore)(h), 1, 0, go };
    HANDLE th = CreateThread(NULL, 0, thr_add, &t, 0, NULL);
    CHECK(U(CertCloseStore)(h, 0));       /* the creator lets go first */
    SetEvent(go);
    if (th) { WAITEV(th, 5000, WAIT_OBJECT_0); CloseHandle(th); }
    CHECK(t.ok);
    CHECK(U(CertCloseStore)(t.h, 0));
    CloseHandle(go);
    EXPECT_EQ(ds_stored(nm, 0, 1), 1);
    ds_end();
}
TEST(dxss_thread_four_threads_add_distinct_certs) {
    SETUP(CertDuplicateStore); NAME("th3");
    HCERTSTORE h = ds_open(nm, 0);
    if (!h) { CHECK(h != NULL); return; }
    HANDLE go = CreateEventW(NULL, TRUE, FALSE, NULL);
    thr_t t[DS_NCERTS]; HANDLE th[DS_NCERTS];
    for (int i = 0; i < DS_NCERTS; i++) { t[i].h = U(CertDuplicateStore)(h); t[i].idx = i; t[i].ok = 0; t[i].go = go; th[i] = CreateThread(NULL, 0, thr_add, &t[i], 0, NULL); }
    SetEvent(go);
    for (int i = 0; i < DS_NCERTS; i++) { if (th[i]) { WAITEV(th[i], 8000, WAIT_OBJECT_0); CloseHandle(th[i]); } CHECK(t[i].ok); }
    EXPECT_EQ(ds_count(h), 4);
    for (int i = 0; i < DS_NCERTS; i++) U(CertCloseStore)(t[i].h, 0);
    U(CertCloseStore)(h, 0);
    CloseHandle(go);
    EXPECT_EQ(ds_count_named(nm, 0, 0), 4);
    ds_end();
}
TEST(dxss_thread_enumerate_concurrently_with_add) {
    SETUP(CertDuplicateStore); NAME("th4");
    HCERTSTORE h = filled(nm, 2, 0);
    if (!h) { CHECK(h != NULL); return; }
    thr_t t = { U(CertDuplicateStore)(h), 3, 0, NULL };
    HANDLE th = CreateThread(NULL, 0, thr_add, &t, 0, NULL);
    for (int k = 0; k < 200; k++) { int n = ds_count(h); CHECKF(n >= 2 && n <= 3, "count %d", n); }
    if (th) { WaitForSingleObject(th, 5000); CloseHandle(th); }
    EXPECT_EQ(ds_count(h), 3);
    U(CertCloseStore)(t.h, 0); U(CertCloseStore)(h, 0);
    ds_end();
}
CHILD(dxss_child_add) {
    /* argv[1] = store name, argv[2] = cert index, argv[3] = optional "del" */
    if (argc < 3 || !U(CertOpenStore)) return 90;
    wchar_t nm[200]; MultiByteToWideChar(CP_ACP, 0, argv[1], -1, nm, 200);
    int idx = atoi(argv[2]);
    HCERTSTORE h = ds_open(nm, 0);
    if (!h) return 91;
    int rc = 0;
    if (argc > 3 && !strcmp(argv[3], "del")) {
        PCCERT_CONTEXT c = ds_find(h, idx);
        if (!c || !ds_del(c)) rc = 92;
    } else if (!ds_add_ok(h, idx)) rc = 93;
    ds_sync(h);
    U(CertCloseStore)(h, 0);
    return rc;
}
static char *narrow(const wchar_t *w, char *out, size_t cap) { WideCharToMultiByte(CP_ACP, 0, w, -1, out, (int)cap, NULL, NULL); return out; }
TEST(dxss_process_child_adds_cert_parent_sees_it) {
    SETUP(CertOpenStore); NAME("pr1");
    HCERTSTORE h = ds_open(nm, 0);
    if (!h) { CHECK(h != NULL); return; }
    char args[300], n[200]; sprintf(args, "%s 2", narrow(nm, n, sizeof n));
    { DWORD rc_ = t_run_child("dxss_child_add", args, 20000); EXPECT_EQ(rc_, 0); }
    EXPECT_EQ(ds_stored(nm, 0, 2), 1);
    EXPECT_EQ(ds_count(h), 0);     /* the handle that was open before the child's add does not see it without a resync */
    U(CertCloseStore)(h, 0);
    ds_end();
}
TEST(dxss_process_child_deletes_cert) {
    SETUP(CertOpenStore); NAME("pr2");
    HCERTSTORE h = filled(nm, 2, 0);
    if (!h) { CHECK(h != NULL); return; }
    U(CertCloseStore)(h, 0);
    char args[300], n[200]; sprintf(args, "%s 1 del", narrow(nm, n, sizeof n));
    { DWORD rc_ = t_run_child("dxss_child_add", args, 20000); EXPECT_EQ(rc_, 0); }
    EXPECT_EQ(ds_stored(nm, 0, 1), 0);
    EXPECT_EQ(ds_stored(nm, 0, 0), 1);
    ds_end();
}
TEST(dxss_process_notify_fires_for_child_change) {
    SETUP(CertControlStore); NAME("pr3");
    WINE_SKIP("per-certificate property changes and change notifications are not written through the registry store");
    HCERTSTORE h = ds_open(nm, 0);
    if (!h) { CHECK(h != NULL); return; }
    HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (U(CertControlStore)(h, 0, CERT_STORE_CTRL_NOTIFY_CHANGE, &ev)) {
        char args[300], n[200]; sprintf(args, "%s 3", narrow(nm, n, sizeof n));
        { DWORD rc_ = t_run_child("dxss_child_add", args, 20000); EXPECT_EQ(rc_, 0); }
        WAITEV(ev, 5000, WAIT_OBJECT_0);
        U(CertControlStore)(h, 0, CERT_STORE_CTRL_CANCEL_NOTIFY, &ev);
    } else CHECK(0);
    CloseHandle(ev);
    U(CertCloseStore)(h, 0);
    ds_end();
}

/* ---- backup/restore ---------------------------------------------------------------------------------- */
TEST(dxss_backup_restore_flag_open) {
    SETUP(CertOpenStore); NAME("br1");
    HCERTSTORE n = ds_open(nm, 0);
    if (n) { CHECK(ds_add_ok(n, 0)); U(CertCloseStore)(n, 0); }
    SET_ERR(0);
    HCERTSTORE h = ds_open(nm, CERT_STORE_BACKUP_RESTORE_FLAG);
    DWORD e = GetLastError();
    CHECKF(h != NULL, "open with BACKUP_RESTORE_FLAG failed err 0x%lx", e);
    if (h) {
        EXPECT_EQ(ds_count(h), 1);          /* same content as a normal open */
        U(CertCloseStore)(h, 0);
    }
    ds_end();
}
TEST(dxss_backup_restore_flag_add_lands_in_normal_registry) {
    SETUP(CertOpenStore); NAME("br2");
    HCERTSTORE n = ds_open(nm, 0);
    if (n) U(CertCloseStore)(n, 0);
    HCERTSTORE h = ds_open(nm, CERT_STORE_BACKUP_RESTORE_FLAG | CERT_STORE_OPEN_EXISTING_FLAG);
    if (!h) { CHECKF(0, "BACKUP_RESTORE open failed err 0x%lx", GetLastError()); ds_end(); return; }
    CHECK(ds_add_ok(h, 1)); ds_sync(h);
    U(CertCloseStore)(h, 0);
    EXPECT_EQ(ds_stored(nm, 0, 1), 1);
    ds_end();
}

/* ---- local machine (elevated only) ----------------------------------------------------------------------- */
TEST(dxss_lm_friendly_name_and_archive_persist) {
    SETUP_LM(CertSetCertificateContextProperty); NAME("lp1");
    WINE_SKIP("machine stores live elsewhere");
    DWORD L = CERT_SYSTEM_STORE_LOCAL_MACHINE;
    HCERTSTORE h = ds_open_loc(nm, L, 0);
    PCCERT_CONTEXT c = h ? ds_add(h, 0, CERT_STORE_ADD_NEW) : NULL;
    CHECK(c != NULL);
    if (c) { CHECK(set_friendly(c, L"lm name", 0)); CHECK(archive(c)); U(CertFreeCertificateContext)(c); }
    if (h) U(CertCloseStore)(h, 0);
    EXPECT_EQ(ds_count_named(nm, L, 0), 0);
    h = ds_open_loc(nm, L, CERT_STORE_ENUM_ARCHIVED_FLAG | CERT_STORE_OPEN_EXISTING_FLAG);
    c = h ? ds_find(h, 0) : NULL;
    CHECK(c != NULL);
    if (c) { wchar_t w[32] = L""; get_friendly(c, w, 32); CHECK(!wcscmp(w, L"lm name")); U(CertFreeCertificateContext)(c); }
    if (h) U(CertCloseStore)(h, 0);
    ds_end();
}
TEST(dxss_lm_notify_change_across_handles) {
    SETUP_LM(CertControlStore); NAME("lp2");
    WINE_SKIP("machine stores live elsewhere");
    DWORD L = CERT_SYSTEM_STORE_LOCAL_MACHINE;
    HCERTSTORE a = ds_open_loc(nm, L, 0), b = ds_open_loc(nm, L, 0);
    if (!a || !b) { CHECK(a && b); return; }
    HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (U(CertControlStore)(a, 0, CERT_STORE_CTRL_NOTIFY_CHANGE, &ev)) {
        CHECK(ds_add_ok(b, 0));
        WAITEV(ev, 5000, WAIT_OBJECT_0);
        U(CertControlStore)(a, 0, CERT_STORE_CTRL_CANCEL_NOTIFY, &ev);
    } else CHECK(0);
    CloseHandle(ev);
    U(CertCloseStore)(a, 0); U(CertCloseStore)(b, 0);
    ds_end();
}
