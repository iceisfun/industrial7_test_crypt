/* Enhanced key usage, intended key usage, extension / attribute lookup, key length, strong hash. */
#include "ccp.h"

typedef struct { CERT_ENHKEY_USAGE u; char *p[8]; } USAGE8;
static void usage_of(USAGE8 *x, int n, const char *const *oids) { int i; x->u.cUsageIdentifier = n; x->u.rgpszUsageIdentifier = x->p; for (i = 0; i < n; i++) x->p[i] = (char *)oids[i]; }

/* Fetch usage into a freshly allocated buffer. Returns NULL (and *err) on failure. */
static CERT_ENHKEY_USAGE *get_eku(PCCERT_CONTEXT c, DWORD flags, DWORD *err, BOOL *okp) {
    DWORD cb = 0; CERT_ENHKEY_USAGE *u; BOOL ok;
    SET_ERR(0);
    ok = C32(CertGetEnhancedKeyUsage)(c, flags, NULL, &cb);
    if (!ok) { if (err) *err = GetLastError(); if (okp) *okp = FALSE; return NULL; }
    u = (CERT_ENHKEY_USAGE *)LocalAlloc(LPTR, cb + 16);
    SET_ERR(0);
    ok = C32(CertGetEnhancedKeyUsage)(c, flags, u, &cb);
    if (err) *err = GetLastError();
    if (okp) *okp = ok;
    if (!ok) { LocalFree(u); return NULL; }
    return u;
}
static int has_oid(const CERT_ENHKEY_USAGE *u, const char *oid) {
    DWORD i; for (i = 0; i < u->cUsageIdentifier; i++) if (!strcmp(u->rgpszUsageIdentifier[i], oid)) return 1; return 0;
}

/* ---- CertGetEnhancedKeyUsage: extension ---- */
TEST(ccp_eku_extension_server_and_client) {
    PCCERT_CONTEXT c = ccp_ctx(&fx_leaf); CERT_ENHKEY_USAGE *u; DWORD err; BOOL ok; DWORD fl[] = {0, 6, CERT_FIND_EXT_ONLY_ENHKEY_USAGE_FLAG}; int k;
    REQUIRE(C32(CertGetEnhancedKeyUsage));
    if (!c) { CHECK(0); return; }
    for (k = 0; k < 3; k++) {
        u = get_eku(c, fl[k], &err, &ok);
        CHECKF(u != NULL, "flags %lu", (unsigned long)fl[k]);
        if (u) {
            EXPECT_EQ(u->cUsageIdentifier, 2);
            CHECK(has_oid(u, szOID_PKIX_KP_SERVER_AUTH) && has_oid(u, szOID_PKIX_KP_CLIENT_AUTH));
            LocalFree(u);
        }
    }
    ccp_free(c);
}
TEST(ccp_eku_extension_code_signing_variants) {
    const FX *f[] = {&fx_ec256, &fx_leafi}; int k; REQUIRE(C32(CertGetEnhancedKeyUsage));
    for (k = 0; k < 2; k++) {
        PCCERT_CONTEXT c = ccp_ctx(f[k]); CERT_ENHKEY_USAGE *u;
        if (!c) { CHECK(0); continue; }
        u = get_eku(c, 0, NULL, NULL);
        CHECKF(u != NULL, "%s", f[k]->name);
        if (u) { EXPECT_EQ(u->cUsageIdentifier, 1); CHECK(has_oid(u, szOID_PKIX_KP_CODE_SIGNING)); LocalFree(u); }
        ccp_free(c);
    }
}
TEST(ccp_eku_size_protocol) {
    PCCERT_CONTEXT c = ccp_ctx(&fx_leaf); DWORD cb = 0, need; BYTE *buf;
    REQUIRE(C32(CertGetEnhancedKeyUsage));
    if (!c) { CHECK(0); return; }
    SET_ERR(0);
    CHECK(C32(CertGetEnhancedKeyUsage)(c, 0, NULL, &cb));
    need = cb;
    CHECK(need > sizeof(CERT_ENHKEY_USAGE) + 2 * sizeof(char *) + strlen(szOID_PKIX_KP_SERVER_AUTH));
    buf = (BYTE *)LocalAlloc(LPTR, need + 64);
    cb = need - 1; SET_ERR(0);
    EXPECT_FAIL(!C32(CertGetEnhancedKeyUsage)(c, 0, (CERT_ENHKEY_USAGE *)buf, &cb), ERROR_MORE_DATA);
    EXPECT_EQ(cb, need);
    cb = 0; SET_ERR(0);
    EXPECT_FAIL(!C32(CertGetEnhancedKeyUsage)(c, 0, (CERT_ENHKEY_USAGE *)buf, &cb), ERROR_MORE_DATA);
    cb = need;
    CHECK(C32(CertGetEnhancedKeyUsage)(c, 0, (CERT_ENHKEY_USAGE *)buf, &cb));
    CHECK(cb <= need);
    { CERT_ENHKEY_USAGE *u = (CERT_ENHKEY_USAGE *)buf; DWORD i;     /* the OID strings live inside the caller's buffer */
      for (i = 0; i < u->cUsageIdentifier; i++) CHECK((BYTE *)u->rgpszUsageIdentifier[i] >= buf && (BYTE *)u->rgpszUsageIdentifier[i] < buf + need); }
    cb = need + 64;
    CHECK(C32(CertGetEnhancedKeyUsage)(c, 0, (CERT_ENHKEY_USAGE *)buf, &cb));
    LocalFree(buf); ccp_free(c);
}
TEST(ccp_eku_flag_validation) {
    PCCERT_CONTEXT c = ccp_ctx(&fx_leaf); DWORD cb = 0, bad[] = {1, 8, 0x10, 0x20, 0x40, 0x80000000}; int k;
    REQUIRE(C32(CertGetEnhancedKeyUsage));
    if (!c) { CHECK(0); return; }
    for (k = 0; k < 6; k++) {
        SET_ERR(0);
        CHECKF(!C32(CertGetEnhancedKeyUsage)(c, bad[k], NULL, &cb), "flags 0x%lx", (unsigned long)bad[k]);
        EXPECT_ERR(ERROR_INVALID_PARAMETER);
    }
    SET_ERR(0);
    CHECK(!C32(CertGetEnhancedKeyUsage)(NULL, 0, NULL, &cb));
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0);
    CHECK(!C32(CertGetEnhancedKeyUsage)(c, 0, NULL, NULL));
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
    ccp_free(c);
}
TEST(ccp_eku_none_means_all_purposes) {
    PCCERT_CONTEXT c = ccp_ctx(&fx_root); CERT_ENHKEY_USAGE *u; DWORD err = 0; BOOL ok = FALSE; DWORD fl[] = {0, 6}; int k;
    REQUIRE(C32(CertGetEnhancedKeyUsage));
    if (!c) { CHECK(0); return; }
    for (k = 0; k < 2; k++) {
        u = get_eku(c, fl[k], &err, &ok);
        CHECKF(ok && u != NULL, "flags %lu", (unsigned long)fl[k]);
        if (u) { EXPECT_EQ(u->cUsageIdentifier, 0); EXPECT_EQ(err, CRYPT_E_NOT_FOUND_); LocalFree(u); }
    }
    ccp_free(c);
}
TEST(ccp_eku_ext_only_and_prop_only_absent) {
    PCCERT_CONTEXT c = ccp_ctx(&fx_root); DWORD cb = 0;
    REQUIRE(C32(CertGetEnhancedKeyUsage));
    if (!c) { CHECK(0); return; }
    SET_ERR(0);
    EXPECT_FAIL(!C32(CertGetEnhancedKeyUsage)(c, CERT_FIND_EXT_ONLY_ENHKEY_USAGE_FLAG, NULL, &cb), CRYPT_E_NOT_FOUND_);
    SET_ERR(0);
    EXPECT_FAIL(!C32(CertGetEnhancedKeyUsage)(c, CERT_FIND_PROP_ONLY_ENHKEY_USAGE_FLAG, NULL, &cb), CRYPT_E_NOT_FOUND_);
    ccp_free(c);
}
TEST(ccp_eku_prop_only_ignores_extension) {
    PCCERT_CONTEXT c = ccp_ctx(&fx_leaf); DWORD cb = 0;
    REQUIRE(C32(CertGetEnhancedKeyUsage));
    if (!c) { CHECK(0); return; }
    SET_ERR(0);
    EXPECT_FAIL(!C32(CertGetEnhancedKeyUsage)(c, CERT_FIND_PROP_ONLY_ENHKEY_USAGE_FLAG, NULL, &cb), CRYPT_E_NOT_FOUND_);
    ccp_free(c);
}
TEST(ccp_eku_ext_only_ignores_property) {
    PCCERT_CONTEXT c = ccp_ctx(&fx_root); USAGE8 x; const char *o[] = {szOID_PKIX_KP_EMAIL_PROTECTION}; DWORD cb = 0;
    REQUIRE(C32(CertSetEnhancedKeyUsage));
    if (!c) { CHECK(0); return; }
    usage_of(&x, 1, o);
    CHECK(C32(CertSetEnhancedKeyUsage)(c, &x.u));
    SET_ERR(0);
    EXPECT_FAIL(!C32(CertGetEnhancedKeyUsage)(c, CERT_FIND_EXT_ONLY_ENHKEY_USAGE_FLAG, NULL, &cb), CRYPT_E_NOT_FOUND_);
    ccp_free(c);
}

/* ---- Set / Add / Remove ---- */
TEST(ccp_eku_set_property_roundtrip) {
    PCCERT_CONTEXT c = ccp_ctx(&fx_root); USAGE8 x; const char *o[] = {szOID_PKIX_KP_EMAIL_PROTECTION, szOID_PKIX_KP_TIMESTAMP_SIGNING, "1.2.3.4.5"}; CERT_ENHKEY_USAGE *u;
    REQUIRE(C32(CertSetEnhancedKeyUsage));
    if (!c) { CHECK(0); return; }
    usage_of(&x, 3, o);
    CHECK(C32(CertSetEnhancedKeyUsage)(c, &x.u));
    u = get_eku(c, CERT_FIND_PROP_ONLY_ENHKEY_USAGE_FLAG, NULL, NULL);
    CHECK(u != NULL);
    if (u) { EXPECT_EQ(u->cUsageIdentifier, 3); CHECK(has_oid(u, o[0]) && has_oid(u, o[1]) && has_oid(u, "1.2.3.4.5")); LocalFree(u); }
    u = get_eku(c, 0, NULL, NULL);
    CHECK(u != NULL);
    if (u) { EXPECT_EQ(u->cUsageIdentifier, 3); LocalFree(u); }
    ccp_free(c);
}
TEST(ccp_eku_set_property_visible_as_raw_property) {
    PCCERT_CONTEXT c = ccp_ctx(&fx_root); USAGE8 x; const char *o[] = {szOID_PKIX_KP_SERVER_AUTH}; DWORD cb = 0; BYTE raw[128];
    REQUIRE(C32(CertSetEnhancedKeyUsage));
    if (!c) { CHECK(0); return; }
    usage_of(&x, 1, o);
    CHECK(C32(CertSetEnhancedKeyUsage)(c, &x.u));
    /* the property holds the DER SEQUENCE OF OBJECT IDENTIFIER */
    CHECK(ccp_getprop(c, CERT_ENHKEY_USAGE_PROP_ID, NULL, &cb) && cb == 2 + 2 + 8);
    cb = sizeof raw;
    CHECK(ccp_getprop(c, CERT_ENHKEY_USAGE_PROP_ID, raw, &cb) && cb == 12);
    { static const BYTE want[] = {0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01}; CHECK(cb == 12 && !memcmp(raw, want, 12)); }
    ccp_free(c);
}
TEST(ccp_eku_set_null_removes_property) {
    PCCERT_CONTEXT c = ccp_ctx(&fx_root); USAGE8 x; const char *o[] = {szOID_PKIX_KP_SERVER_AUTH}; DWORD cb = 0;
    REQUIRE(C32(CertSetEnhancedKeyUsage));
    if (!c) { CHECK(0); return; }
    usage_of(&x, 1, o);
    CHECK(C32(CertSetEnhancedKeyUsage)(c, &x.u));
    CHECK(C32(CertSetEnhancedKeyUsage)(c, NULL));
    SET_ERR(0);
    EXPECT_FAIL(!ccp_getprop(c, CERT_ENHKEY_USAGE_PROP_ID, NULL, &cb), CRYPT_E_NOT_FOUND_);
    CHECK(C32(CertSetEnhancedKeyUsage)(c, NULL));       /* removing nothing succeeds */
    ccp_free(c);
}
TEST(ccp_eku_set_empty_usage_means_no_valid_usage) {
    PCCERT_CONTEXT c = ccp_ctx(&fx_root); CERT_ENHKEY_USAGE e, *u; DWORD err = 99; BOOL ok = FALSE;
    REQUIRE(C32(CertSetEnhancedKeyUsage));
    if (!c) { CHECK(0); return; }
    e.cUsageIdentifier = 0; e.rgpszUsageIdentifier = NULL;
    CHECK(C32(CertSetEnhancedKeyUsage)(c, &e));
    u = get_eku(c, CERT_FIND_PROP_ONLY_ENHKEY_USAGE_FLAG, &err, &ok);
    CHECK(ok && u != NULL);
    if (u) { EXPECT_EQ(u->cUsageIdentifier, 0); EXPECT_EQ(err, 0); LocalFree(u); }
    ccp_free(c);
}
TEST(ccp_eku_set_overwrites_not_merges) {
    PCCERT_CONTEXT c = ccp_ctx(&fx_root); USAGE8 x; const char *a[] = {"1.2.3.1", "1.2.3.2"}, *b[] = {"1.2.3.3"}; CERT_ENHKEY_USAGE *u;
    REQUIRE(C32(CertSetEnhancedKeyUsage));
    if (!c) { CHECK(0); return; }
    usage_of(&x, 2, a); CHECK(C32(CertSetEnhancedKeyUsage)(c, &x.u));
    usage_of(&x, 1, b); CHECK(C32(CertSetEnhancedKeyUsage)(c, &x.u));
    u = get_eku(c, CERT_FIND_PROP_ONLY_ENHKEY_USAGE_FLAG, NULL, NULL);
    CHECK(u != NULL);
    if (u) { EXPECT_EQ(u->cUsageIdentifier, 1); CHECK(has_oid(u, "1.2.3.3")); LocalFree(u); }
    ccp_free(c);
}
TEST(ccp_eku_set_invalid_oid_string_fails) {
    PCCERT_CONTEXT c = ccp_ctx(&fx_root); USAGE8 x; const char *bad[] = {"not.an.oid"}; const char *bad2[] = {"1"}; const char *bad3[] = {""};
    REQUIRE(C32(CertSetEnhancedKeyUsage));
    if (!c) { CHECK(0); return; }
    usage_of(&x, 1, bad); SET_ERR(0);
    CHECK(!C32(CertSetEnhancedKeyUsage)(c, &x.u)); CHECK(GetLastError() != 0);
    usage_of(&x, 1, bad2); SET_ERR(0);
    CHECK(!C32(CertSetEnhancedKeyUsage)(c, &x.u)); CHECK(GetLastError() != 0);
    usage_of(&x, 1, bad3); SET_ERR(0);
    CHECK(!C32(CertSetEnhancedKeyUsage)(c, &x.u)); CHECK(GetLastError() != 0);
    { DWORD cb = 0; CHECK(!ccp_getprop(c, CERT_ENHKEY_USAGE_PROP_ID, NULL, &cb)); }      /* nothing was stored */
    ccp_free(c);
}
TEST(ccp_eku_add_identifier_creates_property) {
    PCCERT_CONTEXT c = ccp_ctx(&fx_root); CERT_ENHKEY_USAGE *u;
    REQUIRE(C32(CertAddEnhancedKeyUsageIdentifier));
    if (!c) { CHECK(0); return; }
    CHECK(C32(CertAddEnhancedKeyUsageIdentifier)(c, szOID_PKIX_KP_CODE_SIGNING));
    u = get_eku(c, CERT_FIND_PROP_ONLY_ENHKEY_USAGE_FLAG, NULL, NULL);
    CHECK(u != NULL);
    if (u) { EXPECT_EQ(u->cUsageIdentifier, 1); CHECK(has_oid(u, szOID_PKIX_KP_CODE_SIGNING)); LocalFree(u); }
    ccp_free(c);
}
TEST(ccp_eku_add_identifier_appends_and_dedups) {
    PCCERT_CONTEXT c = ccp_ctx(&fx_root); CERT_ENHKEY_USAGE *u;
    REQUIRE(C32(CertAddEnhancedKeyUsageIdentifier));
    if (!c) { CHECK(0); return; }
    CHECK(C32(CertAddEnhancedKeyUsageIdentifier)(c, "1.2.3.10"));
    CHECK(C32(CertAddEnhancedKeyUsageIdentifier)(c, "1.2.3.11"));
    CHECK(C32(CertAddEnhancedKeyUsageIdentifier)(c, "1.2.3.10"));          /* already present: success, no duplicate */
    u = get_eku(c, CERT_FIND_PROP_ONLY_ENHKEY_USAGE_FLAG, NULL, NULL);
    CHECK(u != NULL);
    if (u) { EXPECT_EQ(u->cUsageIdentifier, 2); CHECK(has_oid(u, "1.2.3.10") && has_oid(u, "1.2.3.11")); LocalFree(u); }
    ccp_free(c);
}
TEST(ccp_eku_add_identifier_leaves_extension_alone) {
    PCCERT_CONTEXT c = ccp_ctx(&fx_leaf); CERT_ENHKEY_USAGE *u;
    REQUIRE(C32(CertAddEnhancedKeyUsageIdentifier));
    if (!c) { CHECK(0); return; }
    CHECK(C32(CertAddEnhancedKeyUsageIdentifier)(c, szOID_PKIX_KP_CODE_SIGNING));
    u = get_eku(c, CERT_FIND_EXT_ONLY_ENHKEY_USAGE_FLAG, NULL, NULL);
    CHECK(u != NULL);
    if (u) { EXPECT_EQ(u->cUsageIdentifier, 2); CHECK(!has_oid(u, szOID_PKIX_KP_CODE_SIGNING)); LocalFree(u); }
    u = get_eku(c, CERT_FIND_PROP_ONLY_ENHKEY_USAGE_FLAG, NULL, NULL);
    CHECK(u != NULL);
    if (u) { EXPECT_EQ(u->cUsageIdentifier, 1); LocalFree(u); }
    ccp_free(c);
}
TEST(ccp_eku_combined_is_intersection_of_extension_and_property) {
    PCCERT_CONTEXT c = ccp_ctx(&fx_leaf); USAGE8 x; const char *o[] = {szOID_PKIX_KP_SERVER_AUTH, szOID_PKIX_KP_CODE_SIGNING}; CERT_ENHKEY_USAGE *u;
    REQUIRE(C32(CertSetEnhancedKeyUsage));
    if (!c) { CHECK(0); return; }
    usage_of(&x, 2, o); CHECK(C32(CertSetEnhancedKeyUsage)(c, &x.u));
    u = get_eku(c, 0, NULL, NULL);
    CHECK(u != NULL);
    if (u) { EXPECT_EQ(u->cUsageIdentifier, 1); CHECK(has_oid(u, szOID_PKIX_KP_SERVER_AUTH)); LocalFree(u); }
    u = get_eku(c, 6, NULL, NULL);
    CHECK(u != NULL);
    if (u) { EXPECT_EQ(u->cUsageIdentifier, 1); LocalFree(u); }
    ccp_free(c);
}
TEST(ccp_eku_combined_disjoint_is_empty) {
    PCCERT_CONTEXT c = ccp_ctx(&fx_leaf); USAGE8 x; const char *o[] = {szOID_PKIX_KP_CODE_SIGNING}; CERT_ENHKEY_USAGE *u; BOOL ok = FALSE;
    REQUIRE(C32(CertSetEnhancedKeyUsage));
    if (!c) { CHECK(0); return; }
    usage_of(&x, 1, o); CHECK(C32(CertSetEnhancedKeyUsage)(c, &x.u));
    u = get_eku(c, 0, NULL, &ok);
    CHECK(ok && u != NULL);
    if (u) { EXPECT_EQ(u->cUsageIdentifier, 0); LocalFree(u); }
    ccp_free(c);
}
TEST(ccp_eku_remove_identifier) {
    PCCERT_CONTEXT c = ccp_ctx(&fx_root); CERT_ENHKEY_USAGE *u;
    REQUIRE(C32(CertRemoveEnhancedKeyUsageIdentifier));
    if (!c) { CHECK(0); return; }
    CHECK(C32(CertAddEnhancedKeyUsageIdentifier)(c, "1.2.3.20"));
    CHECK(C32(CertAddEnhancedKeyUsageIdentifier)(c, "1.2.3.21"));
    CHECK(C32(CertAddEnhancedKeyUsageIdentifier)(c, "1.2.3.22"));
    CHECK(C32(CertRemoveEnhancedKeyUsageIdentifier)(c, "1.2.3.21"));
    u = get_eku(c, CERT_FIND_PROP_ONLY_ENHKEY_USAGE_FLAG, NULL, NULL);
    CHECK(u != NULL);
    if (u) { EXPECT_EQ(u->cUsageIdentifier, 2); CHECK(has_oid(u, "1.2.3.20") && has_oid(u, "1.2.3.22") && !has_oid(u, "1.2.3.21")); LocalFree(u); }
    CHECK(C32(CertRemoveEnhancedKeyUsageIdentifier)(c, "1.9.9.9"));         /* not present: still success */
    u = get_eku(c, CERT_FIND_PROP_ONLY_ENHKEY_USAGE_FLAG, NULL, NULL);
    if (u) { EXPECT_EQ(u->cUsageIdentifier, 2); LocalFree(u); } else CHECK(0);
    ccp_free(c);
}
TEST(ccp_eku_remove_last_identifier_deletes_property) {
    PCCERT_CONTEXT c = ccp_ctx(&fx_root); DWORD cb = 0;
    REQUIRE(C32(CertRemoveEnhancedKeyUsageIdentifier));
    if (!c) { CHECK(0); return; }
    CHECK(C32(CertAddEnhancedKeyUsageIdentifier)(c, "1.2.3.30"));
    CHECK(C32(CertRemoveEnhancedKeyUsageIdentifier)(c, "1.2.3.30"));
    SET_ERR(0);
    EXPECT_FAIL(!ccp_getprop(c, CERT_ENHKEY_USAGE_PROP_ID, NULL, &cb), CRYPT_E_NOT_FOUND_);
    ccp_free(c);
}
TEST(ccp_eku_remove_without_property_not_found) {
    PCCERT_CONTEXT c = ccp_ctx(&fx_leaf);
    REQUIRE(C32(CertRemoveEnhancedKeyUsageIdentifier));
    if (!c) { CHECK(0); return; }
    SET_ERR(0);
    EXPECT_FAIL(!C32(CertRemoveEnhancedKeyUsageIdentifier)(c, szOID_PKIX_KP_SERVER_AUTH), CRYPT_E_NOT_FOUND_);   /* only the extension has it */
    ccp_free(c);
}
TEST(ccp_eku_property_survives_store_add) {
    HCERTSTORE s1 = ccp_mem(), s2 = ccp_mem(); PCCERT_CONTEXT a, b = NULL; CERT_ENHKEY_USAGE *u;
    REQUIRE(C32(CertAddEnhancedKeyUsageIdentifier));
    if (!s1 || !s2) { CHECK(0); return; }
    a = ccp_add(s1, &fx_root);
    if (a) {
        CHECK(C32(CertAddEnhancedKeyUsageIdentifier)(a, "1.2.3.40"));
        CHECK(C32(CertAddCertificateContextToStore)(s2, a, CERT_STORE_ADD_ALWAYS, &b));
        u = b ? get_eku(b, CERT_FIND_PROP_ONLY_ENHKEY_USAGE_FLAG, NULL, NULL) : NULL;
        CHECK(u != NULL);
        if (u) { EXPECT_EQ(u->cUsageIdentifier, 1); LocalFree(u); }
        ccp_free(b); ccp_free(a);
    } else CHECK(0);
    ccp_close(s1); ccp_close(s2);
}

/* ---- CertGetValidUsages ---- */
TEST(ccp_valid_usages_no_eku_is_minus_one) {
    PCCERT_CONTEXT c = ccp_ctx(&fx_root); int n = 0; DWORD cb = 0;
    REQUIRE(C32(CertGetValidUsages));
    if (!c) { CHECK(0); return; }
    CHECK(C32(CertGetValidUsages)(1, &c, &n, NULL, &cb));
    EXPECT_EQ(n, -1);
    ccp_free(c);
}
TEST(ccp_valid_usages_single_cert_list) {
    PCCERT_CONTEXT c = ccp_ctx(&fx_leaf); int n = 0; DWORD cb = 0; LPSTR *oids; BYTE *buf;
    REQUIRE(C32(CertGetValidUsages));
    if (!c) { CHECK(0); return; }
    CHECK(C32(CertGetValidUsages)(1, &c, &n, NULL, &cb));
    EXPECT_EQ(n, 2);
    CHECK(cb >= 2 * sizeof(LPSTR) + strlen(szOID_PKIX_KP_SERVER_AUTH) + strlen(szOID_PKIX_KP_CLIENT_AUTH) + 2);
    buf = (BYTE *)LocalAlloc(LPTR, cb + 8); oids = (LPSTR *)buf;
    { DWORD small = cb - 1; SET_ERR(0); EXPECT_FAIL(!C32(CertGetValidUsages)(1, &c, &n, oids, &small), ERROR_MORE_DATA); EXPECT_EQ(small, cb); }
    n = 0;
    CHECK(C32(CertGetValidUsages)(1, &c, &n, oids, &cb));
    EXPECT_EQ(n, 2);
    if (n == 2) {
        int a = !strcmp(oids[0], szOID_PKIX_KP_SERVER_AUTH) && !strcmp(oids[1], szOID_PKIX_KP_CLIENT_AUTH);
        int b = !strcmp(oids[1], szOID_PKIX_KP_SERVER_AUTH) && !strcmp(oids[0], szOID_PKIX_KP_CLIENT_AUTH);
        CHECK(a || b);
    }
    LocalFree(buf); ccp_free(c);
}
TEST(ccp_valid_usages_multiple_certs_intersect) {
    PCCERT_CONTEXT c[2]; int n = 0; DWORD cb = 0; LPSTR oids[4]; BYTE buf[256]; DWORD cb2 = sizeof buf;
    REQUIRE(C32(CertGetValidUsages));
    c[0] = ccp_ctx(&fx_leaf); c[1] = ccp_ctx(&fx_root);        /* root has no restriction */
    if (!c[0] || !c[1]) { CHECK(0); return; }
    CHECK(C32(CertGetValidUsages)(2, c, &n, NULL, &cb)); EXPECT_EQ(n, 2);
    ccp_free(c[1]); c[1] = ccp_ctx(&fx_ec256);                 /* code signing only: disjoint with the leaf */
    n = 99; cb = 0;
    CHECK(C32(CertGetValidUsages)(2, c, &n, NULL, &cb)); EXPECT_EQ(n, 0);
    ccp_free(c[0]); ccp_free(c[1]);
    c[0] = ccp_ctx(&fx_ec256); c[1] = ccp_ctx(&fx_leafi);      /* both code signing */
    n = 0; cb2 = sizeof buf;
    CHECK(C32(CertGetValidUsages)(2, c, &n, (LPSTR *)buf, &cb2));
    EXPECT_EQ(n, 1);
    if (n == 1) CHECK(!strcmp(((LPSTR *)buf)[0], szOID_PKIX_KP_CODE_SIGNING));
    ccp_free(c[0]); ccp_free(c[1]);
}
TEST(ccp_valid_usages_property_restricts) {
    PCCERT_CONTEXT c = ccp_ctx(&fx_root); int n = 0; DWORD cb = 0;
    REQUIRE(C32(CertGetValidUsages));
    if (!c) { CHECK(0); return; }
    CHECK(C32(CertAddEnhancedKeyUsageIdentifier)(c, "1.2.3.50"));
    CHECK(C32(CertGetValidUsages)(1, &c, &n, NULL, &cb));
    EXPECT_EQ(n, 1);
    ccp_free(c);
}

/* ---- CertGetIntendedKeyUsage ---- */
TEST(ccp_key_usage_values) {
    struct { const FX *f; BYTE ku; } t[] = {{&fx_leaf, 0x80 | 0x20}, {&fx_root, 0x04 | 0x02}, {&fx_inter, 0x04 | 0x02}, {&fx_ec256, 0x80}, {&fx_leafi, 0x80}, {&fx_sha1leaf, 0x80}};
    int i; REQUIRE(C32(CertGetIntendedKeyUsage));
    for (i = 0; i < 6; i++) {
        PCCERT_CONTEXT c = ccp_ctx(t[i].f); BYTE b = 0xAA;
        if (!c) { CHECK(0); continue; }
        CHECKF(C32(CertGetIntendedKeyUsage)(ENC, c->pCertInfo, &b, 1) && b == t[i].ku, "%s got 0x%02x want 0x%02x", t[i].f->name, b, t[i].ku);
        ccp_free(c);
    }
}
TEST(ccp_key_usage_absent_returns_false_without_error) {
    PCCERT_CONTEXT c = ccp_ctx(&fx_utf8); BYTE b[4]; 
    REQUIRE(C32(CertGetIntendedKeyUsage));
    if (!c) { CHECK(0); return; }
    memset(b, 0xAA, 4); SET_ERR(0xDEAD);
    CHECK(!C32(CertGetIntendedKeyUsage)(ENC, c->pCertInfo, b, 4));
    EXPECT_ERR(0);
    CHECK(b[0] == 0 && b[1] == 0 && b[2] == 0 && b[3] == 0);       /* the output buffer is always zero filled */
    ccp_free(c);
}
TEST(ccp_key_usage_buffer_is_zero_extended) {
    PCCERT_CONTEXT c = ccp_ctx(&fx_leaf); BYTE b[4];
    REQUIRE(C32(CertGetIntendedKeyUsage));
    if (!c) { CHECK(0); return; }
    memset(b, 0xAA, 4);
    CHECK(C32(CertGetIntendedKeyUsage)(ENC, c->pCertInfo, b, 4));
    CHECK(b[0] == 0xA0 && b[1] == 0 && b[2] == 0 && b[3] == 0);
    memset(b, 0xAA, 4);
    CHECK(C32(CertGetIntendedKeyUsage)(ENC, c->pCertInfo, b, 1));
    CHECK(b[0] == 0xA0 && b[1] == 0xAA);                            /* never writes past cbKeyUsage */
    ccp_free(c);
}
TEST(ccp_key_usage_zero_size_buffer) {
    PCCERT_CONTEXT c = ccp_ctx(&fx_leaf); BYTE b = 0xAA;
    REQUIRE(C32(CertGetIntendedKeyUsage));
    if (!c) { CHECK(0); return; }
    SET_ERR(0xDEAD);
    CHECK(!C32(CertGetIntendedKeyUsage)(ENC, c->pCertInfo, &b, 0));
    CHECK(b == 0xAA);
    ccp_free(c);
}

/* ---- CertFindExtension / CertFindAttribute / CertFindRDNAttr ---- */
TEST(ccp_find_extension_returns_array_element) {
    PCCERT_CONTEXT c = ccp_ctx(&fx_leaf); PCERT_EXTENSION e; DWORD i; const char *oids[] = {szOID_BASIC_CONSTRAINTS2, szOID_KEY_USAGE, szOID_ENHANCED_KEY_USAGE, szOID_SUBJECT_ALT_NAME2, szOID_SUBJECT_KEY_IDENTIFIER, szOID_AUTHORITY_KEY_IDENTIFIER2};
    REQUIRE(C32(CertFindExtension));
    if (!c) { CHECK(0); return; }
    for (i = 0; i < 6; i++) {
        e = C32(CertFindExtension)(oids[i], c->pCertInfo->cExtension, c->pCertInfo->rgExtension);
        CHECKF(e != NULL, "%s", oids[i]);
        if (e) { CHECK(e >= c->pCertInfo->rgExtension && e < c->pCertInfo->rgExtension + c->pCertInfo->cExtension); CHECK(!strcmp(e->pszObjId, oids[i])); }
    }
    CHECK(C32(CertFindExtension)(szOID_NAME_CONSTRAINTS, c->pCertInfo->cExtension, c->pCertInfo->rgExtension) == NULL);
    CHECK(C32(CertFindExtension)(szOID_KEY_USAGE, 0, c->pCertInfo->rgExtension) == NULL);
    CHECK(C32(CertFindExtension)(szOID_KEY_USAGE, 0, NULL) == NULL);
    ccp_free(c);
}
TEST(ccp_find_extension_oid_compare_is_exact) {
    PCCERT_CONTEXT c = ccp_ctx(&fx_leaf);
    REQUIRE(C32(CertFindExtension));
    if (!c) { CHECK(0); return; }
    CHECK(C32(CertFindExtension)("2.5.29.1", c->pCertInfo->cExtension, c->pCertInfo->rgExtension) == NULL);
    CHECK(C32(CertFindExtension)("2.5.29.151", c->pCertInfo->cExtension, c->pCertInfo->rgExtension) == NULL);
    CHECK(C32(CertFindExtension)("2.5.29.1", c->pCertInfo->cExtension, c->pCertInfo->rgExtension) == NULL);
    CHECK(C32(CertFindExtension)("", c->pCertInfo->cExtension, c->pCertInfo->rgExtension) == NULL);
    ccp_free(c);
}
TEST(ccp_find_extension_first_of_duplicates) {
    CERT_EXTENSION ex[3]; PCERT_EXTENSION e;
    REQUIRE(C32(CertFindExtension));
    memset(ex, 0, sizeof ex);
    ex[0].pszObjId = "1.2.3.4"; ex[1].pszObjId = "1.2.3.5"; ex[2].pszObjId = "1.2.3.5";
    e = C32(CertFindExtension)("1.2.3.5", 3, ex);
    CHECK(e == &ex[1]);
    e = C32(CertFindExtension)("1.2.3.4", 3, ex);
    CHECK(e == &ex[0]);
}
TEST(ccp_find_attribute_basic) {
    CRYPT_ATTRIBUTE at[3]; PCRYPT_ATTRIBUTE a;
    REQUIRE(C32(CertFindAttribute));
    memset(at, 0, sizeof at);
    at[0].pszObjId = (LPSTR)szOID_COMMON_NAME; at[1].pszObjId = (LPSTR)szOID_LOCALITY_NAME; at[2].pszObjId = (LPSTR)szOID_COMMON_NAME;
    a = C32(CertFindAttribute)(szOID_LOCALITY_NAME, 3, at); CHECK(a == &at[1]);
    a = C32(CertFindAttribute)(szOID_COMMON_NAME, 3, at); CHECK(a == &at[0]);
    a = C32(CertFindAttribute)(szOID_ORGANIZATION_NAME, 3, at); CHECK(a == NULL);
    a = C32(CertFindAttribute)(szOID_COMMON_NAME, 0, at); CHECK(a == NULL);
}
TEST(ccp_find_rdn_attr_in_decoded_name) {
    CERT_NAME_INFO *ni = NULL; DWORD cb = 0; PCERT_RDN_ATTR a;
    REQUIRE(C32(CertFindRDNAttr));
    REQUIRE(C32(CryptDecodeObjectEx));
    CHECK(C32(CryptDecodeObjectEx)(ENC, X509_NAME, fx_leaf.subj, fx_leaf.cbSubj, CRYPT_DECODE_ALLOC_FLAG, NULL, &ni, &cb));
    if (!ni) { CHECK(0); return; }
    EXPECT_EQ(ni->cRDN, 3);
    a = C32(CertFindRDNAttr)(szOID_COMMON_NAME, ni);
    CHECK(a != NULL);
    if (a) t_note("CN attr: type %lu cb %lu", (unsigned long)a->dwValueType, (unsigned long)a->Value.cbData);
    if (a) { CHECK(a->Value.cbData == 16 && !memcmp(a->Value.pbData, "leaf.cryptt.test", 16)); EXPECT_EQ(a->dwValueType, CERT_RDN_UTF8_STRING); }
    a = C32(CertFindRDNAttr)(szOID_COUNTRY_NAME, ni);
    CHECK(a != NULL);
    if (a) { CHECK(a->Value.cbData == 2 && !memcmp(a->Value.pbData, "US", 2)); EXPECT_EQ(a->dwValueType, CERT_RDN_PRINTABLE_STRING); }
    a = C32(CertFindRDNAttr)(szOID_ORGANIZATION_NAME, ni);
    CHECK(a != NULL && a->Value.cbData == 6 && !memcmp(a->Value.pbData, "cryptt", 6));
    CHECK(C32(CertFindRDNAttr)(szOID_LOCALITY_NAME, ni) == NULL);
    CHECK(C32(CertFindRDNAttr)(szOID_RSA_emailAddr, ni) == NULL);
    LocalFree(ni);
}
TEST(ccp_find_rdn_attr_email_and_utf8) {
    CERT_NAME_INFO *ni = NULL; DWORD cb = 0; PCERT_RDN_ATTR a;
    REQUIRE(C32(CertFindRDNAttr));
    REQUIRE(C32(CryptDecodeObjectEx));
    CHECK(C32(CryptDecodeObjectEx)(ENC, X509_NAME, fx_utf8.subj, fx_utf8.cbSubj, CRYPT_DECODE_ALLOC_FLAG, NULL, &ni, &cb));
    if (!ni) { CHECK(0); return; }
    a = C32(CertFindRDNAttr)(szOID_RSA_emailAddr, ni);
    CHECK(a != NULL);
    if (a) { CHECK(a->Value.cbData == 13 && !memcmp(a->Value.pbData, "a@cryptt.test", 13)); EXPECT_EQ(a->dwValueType, CERT_RDN_IA5_STRING); }
    a = C32(CertFindRDNAttr)(szOID_COMMON_NAME, ni);
    CHECK(a != NULL);
    if (a) { static const BYTE want[] = {'G', 'r', 0xc3, 0xbc, 0xc3, 0x9f, 'e', ' ', 'c', 'r', 'y', 'p', 't', 't'}; CHECK(a->Value.cbData == sizeof want && !memcmp(a->Value.pbData, want, sizeof want)); EXPECT_EQ(a->dwValueType, CERT_RDN_UTF8_STRING); }
    LocalFree(ni);
}

/* ---- public key length ---- */
TEST(ccp_public_key_length_table) {
    struct { const FX *f; DWORD bits; } t[] = {{&fx_root, 2048}, {&fx_leaf, 2048}, {&fx_rsa1024, 1024}, {&fx_ec256, 256}, {&fx_ec384v1, 384}, {&fx_inter, 2048}};
    int i; REQUIRE(C32(CertGetPublicKeyLength));
    for (i = 0; i < 6; i++) {
        PCCERT_CONTEXT c = ccp_ctx(t[i].f);
        if (!c) { CHECK(0); continue; }
        CHECKF(C32(CertGetPublicKeyLength)(ENC, &c->pCertInfo->SubjectPublicKeyInfo) == t[i].bits, "%s", t[i].f->name);
        ccp_free(c);
    }
}
TEST(ccp_public_key_length_unknown_algorithm) {
    PCCERT_CONTEXT c = ccp_ctx(&fx_root); CERT_PUBLIC_KEY_INFO k; 
    REQUIRE(C32(CertGetPublicKeyLength));
    if (!c) { CHECK(0); return; }
    k = c->pCertInfo->SubjectPublicKeyInfo;
    k.Algorithm.pszObjId = "1.2.3.4.5.6.7";
    SET_ERR(0);
    t_note("unknown public key algorithm: length %lu err 0x%lx", (unsigned long)C32(CertGetPublicKeyLength)(ENC, &k), (unsigned long)GetLastError());
    ccp_free(c);
}
TEST(ccp_public_key_length_property) {
    PCCERT_CONTEXT c = ccp_ctx(&fx_root);
    REQUIRE(C32(CertGetCertificateContextProperty));
    if (!c) { CHECK(0); return; }
    { DWORD v = 0, cb = 4; if (ccp_getprop(c, 92, &v, &cb)) { EXPECT_EQ(cb, 4); EXPECT_EQ(v, 2048); } else t_note("property 92 (public key bit length) unavailable: 0x%lx", (unsigned long)GetLastError()); }
    ccp_free(c);
}

/* ---- strong / weak hash ---- */
TEST(ccp_is_strong_hash_to_sign_sha256_and_md5) {
    CERT_STRONG_SIGN_PARA p; PCCERT_CONTEXT c = ccp_ctx(&fx_root); BOOL r;
    REQUIRE(C32(CertIsStrongHashToSign));
    if (!c) { CHECK(0); return; }
    memset(&p, 0, sizeof p); p.cbSize = sizeof p; p.dwInfoChoice = CERT_STRONG_SIGN_OID_INFO_CHOICE; p.pszOID = (LPSTR)szOID_CERT_STRONG_SIGN_OS_CURRENT;
    r = C32(CertIsStrongHashToSign)(&p, L"SHA256", c);
    CHECK(r);
    SET_ERR(0);
    r = C32(CertIsStrongHashToSign)(&p, L"MD5", c);
    t_note("CertIsStrongHashToSign(MD5) = %d err 0x%lx", r, (unsigned long)GetLastError());
    CHECK(!r);
    ccp_free(c);
}
