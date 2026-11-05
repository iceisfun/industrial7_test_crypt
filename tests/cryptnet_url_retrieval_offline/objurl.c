#include "cnet.h"
/* CryptGetObjectUrl: URL extraction from fixed certificates (AIA / CDP / freshest CRL), size protocol. */

static PCCERT_CONTEXT mk(const unsigned char *p, size_t n) { return U(CertCreateCertificateContext)(X509_ASN_ENCODING, p, (DWORD)n); }
#define MKC(x) mk(x, sizeof(x))

static BYTE g_buf[4096];

static void expect_urls(LPCSTR oid, PCCERT_CONTEXT c, DWORD flags, int n, const WCHAR * const *urls) {
    DWORD cb = 0;
    SET_ERR(0);
    BOOL ok = U(CryptGetObjectUrl)(oid, (LPVOID)c, flags, NULL, &cb, NULL, NULL, NULL);
    CHECKF(ok, "size query oid=%p err=0x%lx", oid, GetLastError());
    if (!ok) return;
    CHECKF(cb == cn_urlarray_size(n, urls), "size %lu want %lu", cb, cn_urlarray_size(n, urls));
    cb = sizeof g_buf;
    memset(g_buf, 0xCC, sizeof g_buf);
    ok = U(CryptGetObjectUrl)(oid, (LPVOID)c, flags, (PCRYPT_URL_ARRAY)g_buf, &cb, NULL, NULL, NULL);
    CHECKF(ok, "fetch err=0x%lx", GetLastError());
    if (ok) cn_check_urlarray((PCRYPT_URL_ARRAY)g_buf, cn_urlarray_size(n, urls), n, urls);
}

static void expect_notfound(LPCSTR oid, LPVOID para, DWORD flags) {
    DWORD cb = 0;
    SET_ERR(0);
    BOOL ok = U(CryptGetObjectUrl)(oid, para, flags, NULL, &cb, NULL, NULL, NULL);
    CHECK(!ok);
    EXPECT_ERR(ERR_CRYPT_NOTFOUND);
}

TEST(cnobj_resolve) {
    REQUIRE(UIN("cryptnet.dll", CryptGetObjectUrl));
    CHECK(UIN("cryptnet.dll", CryptRetrieveObjectByUrlA) != NULL);
    CHECK(UIN("cryptnet.dll", CryptRetrieveObjectByUrlW) != NULL);
    CHECK(UIN("cryptnet.dll", CryptGetTimeValidObject) != NULL);
    CHECK(UIN("cryptnet.dll", CryptFlushTimeValidObject) != NULL);
}

TEST(cnobj_issuer_cert_a) {
    REQUIRE(U(CryptGetObjectUrl));
    PCCERT_CONTEXT c = MKC(v_cert_a); REQUIRE(c);
    expect_urls(URL_OID_CERTIFICATE_ISSUER, c, 0, 2, CN_URLS_A_ISSUER);
    U(CertFreeCertificateContext)(c);
}
TEST(cnobj_issuer_flags_variants) {
    REQUIRE(U(CryptGetObjectUrl));
    PCCERT_CONTEXT c = MKC(v_cert_a); REQUIRE(c);
    /* dwFlags 0 means "all sources"; the extension source alone is equivalent for a cert without properties */
    expect_urls(URL_OID_CERTIFICATE_ISSUER, c, 0xF, 2, CN_URLS_A_ISSUER);
    expect_urls(URL_OID_CERTIFICATE_ISSUER, c, CRYPT_GET_URL_FROM_EXTENSION, 2, CN_URLS_A_ISSUER);
    expect_urls(URL_OID_CERTIFICATE_ISSUER, c, CRYPT_GET_URL_FROM_EXTENSION | CRYPT_GET_URL_FROM_PROPERTY, 2, CN_URLS_A_ISSUER);
    expect_notfound(URL_OID_CERTIFICATE_ISSUER, (LPVOID)c, CRYPT_GET_URL_FROM_PROPERTY);
    U(CertFreeCertificateContext)(c);
}
TEST(cnobj_crl_dp_cert_a) {
    REQUIRE(U(CryptGetObjectUrl));
    PCCERT_CONTEXT c = MKC(v_cert_a); REQUIRE(c);
    expect_urls(URL_OID_CERTIFICATE_CRL_DIST_POINT, c, 0, 3, CN_URLS_A_CDP);
    expect_urls(URL_OID_CERTIFICATE_CRL_DIST_POINT, c, CRYPT_GET_URL_FROM_EXTENSION, 3, CN_URLS_A_CDP);
    /* the CDP extension has no property form */
    expect_notfound(URL_OID_CERTIFICATE_CRL_DIST_POINT, (LPVOID)c, CRYPT_GET_URL_FROM_PROPERTY);
    U(CertFreeCertificateContext)(c);
}
TEST(cnobj_crl_dp_cert_d) {
    REQUIRE(U(CryptGetObjectUrl));
    PCCERT_CONTEXT c = MKC(v_cert_d); REQUIRE(c);
    const WCHAR *u[1] = { L"http://crl.example.test/only.crl" };
    expect_urls(URL_OID_CERTIFICATE_CRL_DIST_POINT, c, 0, 1, u);
    U(CertFreeCertificateContext)(c);
}
TEST(cnobj_freshest_crl_cert_a) {
    REQUIRE(U(CryptGetObjectUrl));
    PCCERT_CONTEXT c = MKC(v_cert_a); REQUIRE(c);
    const WCHAR *u[1] = { L"http://delta.example.test/d.crl" };
    expect_urls(URL_OID_CERTIFICATE_FRESHEST_CRL, c, 0, 1, u);
    U(CertFreeCertificateContext)(c);
}
TEST(cnobj_ocsp_cert_a) {
    REQUIRE(U(CryptGetObjectUrl));
    PCCERT_CONTEXT c = MKC(v_cert_a); REQUIRE(c);
    const WCHAR *u[1] = { L"http://ocsp.example.test/ocsp" };
    DWORD cb = 0;
    SET_ERR(0);
    BOOL ok = U(CryptGetObjectUrl)(URL_OID_CERTIFICATE_OCSP, (LPVOID)c, 0, NULL, &cb, NULL, NULL, NULL);
    CHECKF(ok, "err 0x%lx", GetLastError());
    if (ok) {
        EXPECT_EQ(cb, cn_urlarray_size(1, u));
        cb = sizeof g_buf;
        ok = U(CryptGetObjectUrl)(URL_OID_CERTIFICATE_OCSP, (LPVOID)c, 0, (PCRYPT_URL_ARRAY)g_buf, &cb, NULL, NULL, NULL);
        CHECK(ok);
        if (ok) cn_check_urlarray((PCRYPT_URL_ARRAY)g_buf, cn_urlarray_size(1, u), 1, u);
    }
    U(CertFreeCertificateContext)(c);
}
TEST(cnobj_ocsp_cert_c) {
    REQUIRE(U(CryptGetObjectUrl));
    PCCERT_CONTEXT c = MKC(v_cert_c); REQUIRE(c);
    const WCHAR *u[1] = { L"http://ocsp.example.test/only" };
    DWORD cb = sizeof g_buf;
    BOOL ok = U(CryptGetObjectUrl)(URL_OID_CERTIFICATE_OCSP, (LPVOID)c, 0, (PCRYPT_URL_ARRAY)g_buf, &cb, NULL, NULL, NULL);
    CHECK(ok);
    if (ok) cn_check_urlarray((PCRYPT_URL_ARRAY)g_buf, cn_urlarray_size(1, u), 1, u);
    U(CertFreeCertificateContext)(c);
}
TEST(cnobj_only_ocsp_prefix) {
    REQUIRE(U(CryptGetObjectUrl));
    /* the "only OCSP" and combined variants return OCSP entries tagged with an "ocsp:" scheme prefix */
    PCCERT_CONTEXT c = MKC(v_cert_a); REQUIRE(c);
    const WCHAR *u[1] = { L"ocsp:http://ocsp.example.test/ocsp" };
    expect_urls(URL_OID_CERTIFICATE_ONLY_OCSP, c, 0, 1, u);
    U(CertFreeCertificateContext)(c);
}
TEST(cnobj_ocsp_and_crl_order) {
    REQUIRE(U(CryptGetObjectUrl));
    PCCERT_CONTEXT c = MKC(v_cert_a); REQUIRE(c);
    const WCHAR *ocsp_first[4] = { L"ocsp:http://ocsp.example.test/ocsp", CN_URLS_A_CDP[0], CN_URLS_A_CDP[1], CN_URLS_A_CDP[2] };
    const WCHAR *crl_first[4] = { CN_URLS_A_CDP[0], CN_URLS_A_CDP[1], CN_URLS_A_CDP[2], L"ocsp:http://ocsp.example.test/ocsp" };
    expect_urls(URL_OID_CERTIFICATE_OCSP_AND_CRL_DIST_POINT, c, 0, 4, ocsp_first);
    expect_urls(URL_OID_CERTIFICATE_CRL_DIST_POINT_AND_OCSP, c, 0, 4, crl_first);
    U(CertFreeCertificateContext)(c);
}
TEST(cnobj_ocsp_and_crl_single_source) {
    REQUIRE(U(CryptGetObjectUrl));
    PCCERT_CONTEXT c = MKC(v_cert_c); PCCERT_CONTEXT d = MKC(v_cert_d); REQUIRE(c && d);
    const WCHAR *only_ocsp[1] = { L"ocsp:http://ocsp.example.test/only" };
    const WCHAR *only_crl[1] = { L"http://crl.example.test/only.crl" };
    expect_urls(URL_OID_CERTIFICATE_OCSP_AND_CRL_DIST_POINT, c, 0, 1, only_ocsp);
    expect_urls(URL_OID_CERTIFICATE_CRL_DIST_POINT_AND_OCSP, c, 0, 1, only_ocsp);
    expect_urls(URL_OID_CERTIFICATE_OCSP_AND_CRL_DIST_POINT, d, 0, 1, only_crl);
    expect_urls(URL_OID_CERTIFICATE_CRL_DIST_POINT_AND_OCSP, d, 0, 1, only_crl);
    U(CertFreeCertificateContext)(c); U(CertFreeCertificateContext)(d);
}
TEST(cnobj_issuer_cert_e) {
    REQUIRE(U(CryptGetObjectUrl));
    PCCERT_CONTEXT c = MKC(v_cert_e); REQUIRE(c);
    const WCHAR *u[1] = { L"http://ca.example.test/only.cer" };
    expect_urls(URL_OID_CERTIFICATE_ISSUER, c, 0, 1, u);
    U(CertFreeCertificateContext)(c);
}

typedef struct { const char *what; LPCSTR oid; const unsigned char *p; size_t n; } nf_row;
TEST(cnobj_notfound_table) {
    REQUIRE(U(CryptGetObjectUrl));
    static const nf_row rows[] = {
        { "issuer/B",  URL_OID_CERTIFICATE_ISSUER, v_cert_b, sizeof v_cert_b },
        { "issuer/C",  URL_OID_CERTIFICATE_ISSUER, v_cert_c, sizeof v_cert_c },
        { "issuer/D",  URL_OID_CERTIFICATE_ISSUER, v_cert_d, sizeof v_cert_d },
        { "cdp/B",     URL_OID_CERTIFICATE_CRL_DIST_POINT, v_cert_b, sizeof v_cert_b },
        { "cdp/C",     URL_OID_CERTIFICATE_CRL_DIST_POINT, v_cert_c, sizeof v_cert_c },
        { "cdp/E",     URL_OID_CERTIFICATE_CRL_DIST_POINT, v_cert_e, sizeof v_cert_e },
        { "fresh/B",   URL_OID_CERTIFICATE_FRESHEST_CRL, v_cert_b, sizeof v_cert_b },
        { "fresh/C",   URL_OID_CERTIFICATE_FRESHEST_CRL, v_cert_c, sizeof v_cert_c },
        { "fresh/D",   URL_OID_CERTIFICATE_FRESHEST_CRL, v_cert_d, sizeof v_cert_d },
        { "fresh/E",   URL_OID_CERTIFICATE_FRESHEST_CRL, v_cert_e, sizeof v_cert_e },
        { "cross/A",   URL_OID_CROSS_CERT_DIST_POINT, v_cert_a, sizeof v_cert_a },
        { "cross/B",   URL_OID_CROSS_CERT_DIST_POINT, v_cert_b, sizeof v_cert_b },
        { "sia/A",     URL_OID_CROSS_CERT_SUBJECT_INFO_ACCESS, v_cert_a, sizeof v_cert_a },
        { "sia/B",     URL_OID_CROSS_CERT_SUBJECT_INFO_ACCESS, v_cert_b, sizeof v_cert_b },
    };
    for (size_t i = 0; i < sizeof rows / sizeof *rows; i++) {
        PCCERT_CONTEXT c = mk(rows[i].p, rows[i].n);
        if (!c) { CHECKF(0, "context %s", rows[i].what); continue; }
        DWORD cb = 0;
        SET_ERR(0);
        BOOL ok = U(CryptGetObjectUrl)(rows[i].oid, (LPVOID)c, 0, NULL, &cb, NULL, NULL, NULL);
        CHECKF(!ok, "%s unexpectedly succeeded", rows[i].what);
        DWORD e = GetLastError();
        CHECKF(e == ERR_CRYPT_NOTFOUND, "%s: error 0x%lx", rows[i].what, e);
        U(CertFreeCertificateContext)(c);
    }
}
TEST(cnobj_ocsp_absent) {
    REQUIRE(U(CryptGetObjectUrl));
    static const nf_row rows[] = {
        { "ocsp/B", URL_OID_CERTIFICATE_OCSP, v_cert_b, sizeof v_cert_b },
        { "ocsp/D", URL_OID_CERTIFICATE_OCSP, v_cert_d, sizeof v_cert_d },
        { "ocsp/E", URL_OID_CERTIFICATE_OCSP, v_cert_e, sizeof v_cert_e },
        { "onlyocsp/B", URL_OID_CERTIFICATE_ONLY_OCSP, v_cert_b, sizeof v_cert_b },
        { "onlyocsp/D", URL_OID_CERTIFICATE_ONLY_OCSP, v_cert_d, sizeof v_cert_d },
        { "onlyocsp/E", URL_OID_CERTIFICATE_ONLY_OCSP, v_cert_e, sizeof v_cert_e },
    };
    for (size_t i = 0; i < sizeof rows / sizeof *rows; i++) {
        PCCERT_CONTEXT c = mk(rows[i].p, rows[i].n);
        if (!c) { CHECKF(0, "context %s", rows[i].what); continue; }
        DWORD cb = 0; SET_ERR(0);
        BOOL ok = U(CryptGetObjectUrl)(rows[i].oid, (LPVOID)c, 0, NULL, &cb, NULL, NULL, NULL);
        CHECKF(!ok, "%s unexpectedly succeeded", rows[i].what);
        t_note("%s: error 0x%lx", rows[i].what, GetLastError());
        U(CertFreeCertificateContext)(c);
    }
}
TEST(cnobj_combined_absent) {
    REQUIRE(U(CryptGetObjectUrl));
    PCCERT_CONTEXT c = MKC(v_cert_b); REQUIRE(c);
    DWORD cb = 0; SET_ERR(0);
    CHECK(!U(CryptGetObjectUrl)(URL_OID_CERTIFICATE_OCSP_AND_CRL_DIST_POINT, (LPVOID)c, 0, NULL, &cb, NULL, NULL, NULL));
    t_note("ocsp+cdp on plain cert: error 0x%lx", GetLastError());
    SET_ERR(0);
    CHECK(!U(CryptGetObjectUrl)(URL_OID_CERTIFICATE_CRL_DIST_POINT_AND_OCSP, (LPVOID)c, 0, NULL, &cb, NULL, NULL, NULL));
    t_note("cdp+ocsp on plain cert: error 0x%lx", GetLastError());
    U(CertFreeCertificateContext)(c);
}

TEST(cnobj_size_protocol_issuer) {
    REQUIRE(U(CryptGetObjectUrl));
    PCCERT_CONTEXT c = MKC(v_cert_a); REQUIRE(c);
    DWORD need = cn_urlarray_size(2, CN_URLS_A_ISSUER), cb;
    /* NULL buffer: size is returned and the call succeeds */
    cb = 0; SET_ERR(0);
    CHECK(U(CryptGetObjectUrl)(URL_OID_CERTIFICATE_ISSUER, (LPVOID)c, 0, NULL, &cb, NULL, NULL, NULL));
    EXPECT_EQ(cb, need);
    cb = 0x7777;
    CHECK(U(CryptGetObjectUrl)(URL_OID_CERTIFICATE_ISSUER, (LPVOID)c, 0, NULL, &cb, NULL, NULL, NULL));
    EXPECT_EQ(cb, need);
    /* exact buffer */
    cb = need;
    CHECK(U(CryptGetObjectUrl)(URL_OID_CERTIFICATE_ISSUER, (LPVOID)c, 0, (PCRYPT_URL_ARRAY)g_buf, &cb, NULL, NULL, NULL));
    EXPECT_EQ(cb, need);
    /* one byte short / zero / tiny: E_INVALIDARG (not ERROR_MORE_DATA) and *pcb untouched */
    DWORD shorts[] = { need - 1, 0, 1, 16, need / 2 };
    for (size_t i = 0; i < sizeof shorts / sizeof *shorts; i++) {
        cb = shorts[i]; SET_ERR(0);
        BOOL ok = U(CryptGetObjectUrl)(URL_OID_CERTIFICATE_ISSUER, (LPVOID)c, 0, (PCRYPT_URL_ARRAY)g_buf, &cb, NULL, NULL, NULL);
        CHECKF(!ok, "cap %lu succeeded", shorts[i]);
        EXPECT_ERR(ERR_INVALIDARG);
        EXPECT_EQ(cb, shorts[i]);
    }
    /* larger buffer: *pcb is NOT rewritten to the used size */
    cb = sizeof g_buf;
    CHECK(U(CryptGetObjectUrl)(URL_OID_CERTIFICATE_ISSUER, (LPVOID)c, 0, (PCRYPT_URL_ARRAY)g_buf, &cb, NULL, NULL, NULL));
    EXPECT_EQ(cb, sizeof g_buf);
    U(CertFreeCertificateContext)(c);
}
TEST(cnobj_size_protocol_null_cb) {
    REQUIRE(U(CryptGetObjectUrl));
    PCCERT_CONTEXT c = MKC(v_cert_a); REQUIRE(c);
    static const LPCSTR oids[] = { URL_OID_CERTIFICATE_ISSUER, URL_OID_CERTIFICATE_CRL_DIST_POINT, URL_OID_CERTIFICATE_FRESHEST_CRL,
                                   URL_OID_CERTIFICATE_ONLY_OCSP, URL_OID_CERTIFICATE_OCSP_AND_CRL_DIST_POINT, URL_OID_CERTIFICATE_CRL_DIST_POINT_AND_OCSP };
    for (size_t i = 0; i < sizeof oids / sizeof *oids; i++) {
        SET_ERR(0);
        BOOL ok = U(CryptGetObjectUrl)(oids[i], (LPVOID)c, 0, NULL, NULL, NULL, NULL, NULL);
        CHECKF(!ok, "oid %p: null buffer and null size succeeded", oids[i]);
        EXPECT_ERR(ERR_INVALIDARG);
        SET_ERR(0);
        ok = U(CryptGetObjectUrl)(oids[i], (LPVOID)c, 0, (PCRYPT_URL_ARRAY)g_buf, NULL, NULL, NULL, NULL);
        CHECKF(!ok, "oid %p: buffer with null size succeeded", oids[i]);
        EXPECT_ERR(ERR_INVALIDARG);
    }
    U(CertFreeCertificateContext)(c);
}
TEST(cnobj_size_protocol_combined) {
    REQUIRE(U(CryptGetObjectUrl));
    PCCERT_CONTEXT c = MKC(v_cert_a); REQUIRE(c);
    const WCHAR *u[4] = { L"ocsp:http://ocsp.example.test/ocsp", CN_URLS_A_CDP[0], CN_URLS_A_CDP[1], CN_URLS_A_CDP[2] };
    DWORD need = cn_urlarray_size(4, u), cb;
    cb = 0;
    CHECK(U(CryptGetObjectUrl)(URL_OID_CERTIFICATE_OCSP_AND_CRL_DIST_POINT, (LPVOID)c, 0, NULL, &cb, NULL, NULL, NULL));
    EXPECT_EQ(cb, need);
    cb = need - 1; SET_ERR(0);
    CHECK(!U(CryptGetObjectUrl)(URL_OID_CERTIFICATE_OCSP_AND_CRL_DIST_POINT, (LPVOID)c, 0, (PCRYPT_URL_ARRAY)g_buf, &cb, NULL, NULL, NULL));
    EXPECT_ERR(ERR_INVALIDARG);
    cb = need;
    CHECK(U(CryptGetObjectUrl)(URL_OID_CERTIFICATE_OCSP_AND_CRL_DIST_POINT, (LPVOID)c, 0, (PCRYPT_URL_ARRAY)g_buf, &cb, NULL, NULL, NULL));
    U(CertFreeCertificateContext)(c);
}
TEST(cnobj_urlinfo) {
    REQUIRE(U(CryptGetObjectUrl));
    PCCERT_CONTEXT c = MKC(v_cert_a); REQUIRE(c);
    DWORD cba = 0, cbi = 0;
    /* size query for the info block: sizeof(CRYPT_URL_INFO) == 0x18 */
    CHECK(U(CryptGetObjectUrl)(URL_OID_CERTIFICATE_ISSUER, (LPVOID)c, 0, NULL, &cba, NULL, &cbi, NULL));
    EXPECT_EQ(cbi, sizeof(CRYPT_URL_INFO));
    EXPECT_EQ(cbi, 0x18);
    CRYPT_URL_INFO info; memset(&info, 0x5A, sizeof info);
    cba = sizeof g_buf; cbi = sizeof info;
    CHECK(U(CryptGetObjectUrl)(URL_OID_CERTIFICATE_ISSUER, (LPVOID)c, 0, (PCRYPT_URL_ARRAY)g_buf, &cba, &info, &cbi, NULL));
    EXPECT_EQ(cbi, sizeof info);
    EXPECT_EQ(info.cbSize, sizeof info);
    EXPECT_EQ(info.dwSyncDeltaTime, 0);
    EXPECT_EQ(info.cGroup, 0);
    EXPECT_EQ(info.rgcGroupEntry, NULL);
    /* same for CDP and combined OCSP+CDP */
    memset(&info, 0x5A, sizeof info); cba = sizeof g_buf; cbi = sizeof info;
    CHECK(U(CryptGetObjectUrl)(URL_OID_CERTIFICATE_CRL_DIST_POINT, (LPVOID)c, 0, (PCRYPT_URL_ARRAY)g_buf, &cba, &info, &cbi, NULL));
    EXPECT_EQ(info.cbSize, sizeof info);
    memset(&info, 0x5A, sizeof info); cba = sizeof g_buf; cbi = sizeof info;
    CHECK(U(CryptGetObjectUrl)(URL_OID_CERTIFICATE_OCSP_AND_CRL_DIST_POINT, (LPVOID)c, 0, (PCRYPT_URL_ARRAY)g_buf, &cba, &info, &cbi, NULL));
    EXPECT_EQ(info.cbSize, sizeof info);
    U(CertFreeCertificateContext)(c);
}

/* AIA / CDP URLs carried as a certificate property instead of an extension */
TEST(cnobj_property_source) {
    REQUIRE(U(CryptGetObjectUrl));
    PCCERT_CONTEXT a = MKC(v_cert_a), b = MKC(v_cert_b); REQUIRE(a && b);
    PCERT_EXTENSION e = U(CertFindExtension)(szOID_AUTHORITY_INFO_ACCESS, a->pCertInfo->cExtension, a->pCertInfo->rgExtension);
    CHECK(e != NULL);
    if (e) {
        CRYPT_DATA_BLOB blob = e->Value;
        BOOL ok = U(CertSetCertificateContextProperty)(b, 68 /* CERT_AUTHORITY_INFO_ACCESS_PROP_ID */, 0, &blob);
        if (!ok && t_is_wine()) { t_skip("emulator rejects the AIA property id"); return; }
        CHECKF(ok, "set property err=0x%lx", GetLastError());
        if (ok) {
            expect_urls(URL_OID_CERTIFICATE_ISSUER, b, CRYPT_GET_URL_FROM_PROPERTY, 2, CN_URLS_A_ISSUER);
            expect_urls(URL_OID_CERTIFICATE_ISSUER, b, 0, 2, CN_URLS_A_ISSUER);
            expect_notfound(URL_OID_CERTIFICATE_ISSUER, (LPVOID)b, CRYPT_GET_URL_FROM_EXTENSION);
            const WCHAR *ocsp[1] = { L"http://ocsp.example.test/ocsp" };
            DWORD cb = sizeof g_buf;
            ok = U(CryptGetObjectUrl)(URL_OID_CERTIFICATE_OCSP, (LPVOID)b, CRYPT_GET_URL_FROM_PROPERTY, (PCRYPT_URL_ARRAY)g_buf, &cb, NULL, NULL, NULL);
            CHECKF(ok, "ocsp via property err=0x%lx", GetLastError());
            if (ok) cn_check_urlarray((PCRYPT_URL_ARRAY)g_buf, cn_urlarray_size(1, ocsp), 1, ocsp);
        }
    }
    U(CertFreeCertificateContext)(a); U(CertFreeCertificateContext)(b);
}
TEST(cnobj_property_undecodable) {
    REQUIRE(U(CryptGetObjectUrl));
    PCCERT_CONTEXT b = MKC(v_cert_b); REQUIRE(b);
    BYTE junk[] = { 0x04, 0x02, 0x01, 0x02 };
    CRYPT_DATA_BLOB blob = { sizeof junk, junk };
    if (!U(CertSetCertificateContextProperty)(b, 68, 0, &blob)) { CHECK(t_is_wine()); t_skip("property not settable here"); return; }
    DWORD cb = 0; SET_ERR(0);
    BOOL ok = U(CryptGetObjectUrl)(URL_OID_CERTIFICATE_ISSUER, (LPVOID)b, CRYPT_GET_URL_FROM_PROPERTY, NULL, &cb, NULL, NULL, NULL);
    CHECK(!ok);
    t_note("undecodable AIA property: error 0x%lx", GetLastError());
    U(CertFreeCertificateContext)(b);
}
TEST(cnobj_attribute_flags_on_cert) {
    REQUIRE(U(CryptGetObjectUrl));
    PCCERT_CONTEXT a = MKC(v_cert_a); REQUIRE(a);
    DWORD cb = 0; SET_ERR(0);
    BOOL ok = U(CryptGetObjectUrl)(URL_OID_CERTIFICATE_ISSUER, (LPVOID)a, CRYPT_GET_URL_FROM_UNAUTH_ATTRIBUTE, NULL, &cb, NULL, NULL, NULL);
    CHECK(!ok);
    t_note("unauth-attribute only on cert: error 0x%lx", GetLastError());
    SET_ERR(0);
    ok = U(CryptGetObjectUrl)(URL_OID_CERTIFICATE_ISSUER, (LPVOID)a, CRYPT_GET_URL_FROM_AUTH_ATTRIBUTE, NULL, &cb, NULL, NULL, NULL);
    CHECK(!ok);
    t_note("auth-attribute only on cert: error 0x%lx", GetLastError());
    /* attribute sources do not hide the extension source */
    expect_urls(URL_OID_CERTIFICATE_ISSUER, a, CRYPT_GET_URL_FROM_EXTENSION | CRYPT_GET_URL_FROM_UNAUTH_ATTRIBUTE | CRYPT_GET_URL_FROM_AUTH_ATTRIBUTE, 2, CN_URLS_A_ISSUER);
    U(CertFreeCertificateContext)(a);
}

TEST(cnobj_crl_ctl_issuer_notfound) {
    REQUIRE(U(CryptGetObjectUrl));
    PCCRL_CONTEXT crl = U(CertCreateCRLContext)(X509_ASN_ENCODING, v_crl_a, sizeof v_crl_a);
    PCCERT_CONTEXT a = MKC(v_cert_a);
    REQUIRE_NOTNULL(crl); REQUIRE_NOTNULL(a);
    /* URL_OID_CRL_ISSUER takes the CRL context itself; URL_OID_CRL_FRESHEST_CRL takes a cert/CRL pair.
       Passing the other form faults inside cryptnet on Win10, so each oid gets its own parameter type. */
    expect_notfound(URL_OID_CRL_ISSUER, (LPVOID)crl, 0);
    expect_notfound(URL_OID_CRL_ISSUER, (LPVOID)crl, CRYPT_GET_URL_FROM_EXTENSION);
    expect_notfound(URL_OID_CRL_ISSUER, (LPVOID)crl, CRYPT_GET_URL_FROM_PROPERTY);
    CERT_CRL_CONTEXT_PAIR pair = { a, crl };
    expect_notfound(URL_OID_CRL_FRESHEST_CRL, (LPVOID)&pair, 0);
    expect_notfound(URL_OID_CRL_FRESHEST_CRL, (LPVOID)&pair, CRYPT_GET_URL_FROM_EXTENSION);
    /* URL_OID_CTL_ISSUER / URL_OID_CTL_NEXT_UPDATE are not exercised: on Win10 every parameter form tried
       (CTL context, signer certificate, cert/CRL pair, usage, NULL) raised an access violation. */
    t_note("CTL url oids 3 and 4 fault on Win10 for every tried parameter form; not called");
    U(CertFreeCRLContext)(crl);
    U(CertFreeCertificateContext)(a);
}
TEST(cnobj_unknown_oid) {
    REQUIRE(U(CryptGetObjectUrl));
    PCCERT_CONTEXT a = MKC(v_cert_a); REQUIRE(a);
    static const size_t ids[] = { 14, 15, 99, 0xFFFF };
    for (size_t i = 0; i < sizeof ids / sizeof *ids; i++) {
        DWORD cb = 0; SET_ERR(0);
        BOOL ok = U(CryptGetObjectUrl)((LPCSTR)ids[i], (LPVOID)a, 0, NULL, &cb, NULL, NULL, NULL);
        CHECKF(!ok, "oid %zu succeeded", ids[i]);
        t_note("unknown url oid %zu: error 0x%lx", ids[i], GetLastError());
    }
    DWORD cb = 0; SET_ERR(0);
    CHECK(!U(CryptGetObjectUrl)("1.2.3.4.5.6.7.8.9", (LPVOID)a, 0, NULL, &cb, NULL, NULL, NULL));
    t_note("string oid: error 0x%lx", GetLastError());
    U(CertFreeCertificateContext)(a);
}
TEST(cnobj_lasterror_preserved_on_success) {
    REQUIRE(U(CryptGetObjectUrl));
    PCCERT_CONTEXT a = MKC(v_cert_a); REQUIRE(a);
    DWORD cb = sizeof g_buf;
    SET_ERR(0xDEAD);
    BOOL ok = U(CryptGetObjectUrl)(URL_OID_CERTIFICATE_ISSUER, (LPVOID)a, 0, (PCRYPT_URL_ARRAY)g_buf, &cb, NULL, NULL, NULL);
    CHECK(ok);
    t_note("last error after success: 0x%lx", GetLastError());
    U(CertFreeCertificateContext)(a);
}
TEST(cnobj_repeatable_and_independent) {
    REQUIRE(U(CryptGetObjectUrl));
    PCCERT_CONTEXT a = MKC(v_cert_a); REQUIRE(a);
    PCCERT_CONTEXT dup = U(CertDuplicateCertificateContext)(a);
    for (int i = 0; i < 20; i++) {
        expect_urls(URL_OID_CERTIFICATE_CRL_DIST_POINT, i & 1 ? dup : a, 0, 3, CN_URLS_A_CDP);
    }
    U(CertFreeCertificateContext)(dup); U(CertFreeCertificateContext)(a);
}
