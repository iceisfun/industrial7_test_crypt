/* CertGetNameStringA/W on fixed certificates (RSA-1024 test certs generated with openssl at authoring time). */
#include "sf.h"

typedef PCCERT_CONTEXT (WINAPI *pfn_cc)(DWORD, const BYTE*, DWORD);
typedef BOOL (WINAPI *pfn_fc)(PCCERT_CONTEXT);
typedef DWORD (WINAPI *pfn_gnw)(PCCERT_CONTEXT, DWORD, DWORD, void*, LPWSTR, DWORD);
typedef DWORD (WINAPI *pfn_gna)(PCCERT_CONTEXT, DWORD, DWORD, void*, LPSTR, DWORD);

#define REQ_GN() \
    pfn_cc cc = (pfn_cc)t_proc("CertCreateCertificateContext"); pfn_fc fc = (pfn_fc)t_proc("CertFreeCertificateContext"); \
    pfn_gnw gw = (pfn_gnw)t_proc("CertGetNameStringW"); pfn_gna ga = (pfn_gna)t_proc("CertGetNameStringA"); \
    REQUIRE(cc); REQUIRE(fc); REQUIRE(gw); REQUIRE(ga); (void)ga; (void)gw

#define CTX(var, arr) PCCERT_CONTEXT var = cc(X509_ASN_ENCODING, sf_cert_##arr, sf_cert_##arr##_len); \
    if (!var) { t_skip("CertCreateCertificateContext failed for " #arr " (%lu)", GetLastError()); return; }

/* expected string found: verifies size query, exact fit, truncation and A/W parity.
 * exp == NULL: the name does not exist -> return 1 and an empty string. */
static void chk_gn(const char *file, int line, PCCERT_CONTEXT c, DWORD type, DWORD flags, void *para, const char *exp)
{
    pfn_gnw gw = (pfn_gnw)t_proc("CertGetNameStringW"); pfn_gna ga = (pfn_gna)t_proc("CertGetNameStringA");
    WCHAR wb[512], we[512]; char ab[512]; DWORD n; size_t el = exp ? strlen(exp) : 0;
    if (exp) sf_widen(exp, we); else we[0] = 0;
    n = gw(c, type, flags, para, NULL, 0);
    t_check(n == el + 1, file, line, "W size query", "type %lu flags %#lx got %lu want %zu", type, flags, n, el + 1);
    n = ga(c, type, flags, para, NULL, 0);
    t_check(n == el + 1, file, line, "A size query", "type %lu got %lu want %zu", type, n, el + 1);
    memset(wb, 0xcc, sizeof wb);
    n = gw(c, type, flags, para, wb, 512);
    t_check(n == el + 1 && !lstrcmpW(wb, we), file, line, "W content", "type %lu flags %#lx n=%lu got '%ls'", type, flags, n, wb);
    memset(ab, 0xcc, sizeof ab);
    n = ga(c, type, flags, para, ab, 512);
    t_check(n == el + 1 && !strcmp(ab, exp ? exp : ""), file, line, "A content", "type %lu n=%lu got '%s'", type, n, ab);
    if (exp && el > 1) {
        memset(wb, 0xcc, sizeof wb);
        n = gw(c, type, flags, para, wb, (DWORD)el);
        t_check(n == el && !wcsncmp(wb, we, el - 1) && wb[el - 1] == 0, file, line, "W truncation", "type %lu n=%lu", type, n);
        memset(ab, 0xcc, sizeof ab);
        n = ga(c, type, flags, para, ab, (DWORD)el);
        t_check(n == 1 && ab[0] == 0, file, line, "A truncation (narrowing fails, empty string)", "type %lu n=%lu", type, n);
        memset(wb, 0xcc, sizeof wb);
        n = gw(c, type, flags, para, wb, 1);
        t_check(n == 1 && wb[0] == 0, file, line, "W cch=1", "type %lu n=%lu", type, n);
        memset(wb, 0xcc, sizeof wb);
        n = gw(c, type, flags, para, wb, 0);
        t_check(n == el + 1 && wb[0] == 0xcccc, file, line, "W cch=0 with buffer is a size query", "n=%lu", n);
    }
}
#define GN(c, type, flags, para, exp) chk_gn(__FILE__, __LINE__, (c), (type), (flags), (para), (exp))

/* ---------------- e-mail ---------------- */
TEST(sf_gns_email_prefers_alt_name) {
    REQ_GN(); CTX(c, leaf);
    GN(c, CERT_NAME_EMAIL_TYPE, 0, NULL, "san@example.com");
    fc(c);
}
TEST(sf_gns_email_falls_back_to_subject_attribute) {
    REQ_GN(); CTX(c, em);
    GN(c, CERT_NAME_EMAIL_TYPE, 0, NULL, "only@example.com");
    fc(c);
}
TEST(sf_gns_email_not_found) {
    REQ_GN(); CTX(c, ou); WCHAR w[8]; DWORD n;
    SET_ERR(0);
    n = gw(c, CERT_NAME_EMAIL_TYPE, 0, NULL, w, 8);
    EXPECT_EQ(n, 1); EXPECT_EQ(w[0], 0); EXPECT_LE(CRYPT_E_NOT_FOUND);
    GN(c, CERT_NAME_EMAIL_TYPE, 0, NULL, NULL);
    fc(c);
}
TEST(sf_gns_email_issuer_flag_not_found) {
    REQ_GN(); CTX(c, leaf);
    GN(c, CERT_NAME_EMAIL_TYPE, CERT_NAME_ISSUER_FLAG, NULL, NULL);
    fc(c);
}

/* ---------------- DNS / URL / UPN ---------------- */
TEST(sf_gns_dns_first_alt_name) {
    REQ_GN(); CTX(c, leaf);
    GN(c, CERT_NAME_DNS_TYPE, 0, NULL, "www.example.com");
    fc(c);
}
TEST(sf_gns_dns_falls_back_to_common_name) {
    REQ_GN(); CTX(c, ca);
    GN(c, CERT_NAME_DNS_TYPE, 0, NULL, "Test Root CA");
    fc(c);
}
TEST(sf_gns_dns_not_found) {
    REQ_GN(); CTX(c, ou); WCHAR w[8]; DWORD n;
    SET_ERR(0);
    n = gw(c, CERT_NAME_DNS_TYPE, 0, NULL, w, 8);
    EXPECT_EQ(n, 1); EXPECT_EQ(w[0], 0); EXPECT_LE(CRYPT_E_NOT_FOUND);
    fc(c);
}
TEST(sf_gns_dns_search_all_names_multi_string) {
    REQ_GN(); CTX(c, leaf); WCHAR w[128]; DWORD n;
    n = gw(c, CERT_NAME_DNS_TYPE, CERT_NAME_SEARCH_ALL_NAMES_FLAG, NULL, NULL, 0);
    EXPECT_EQ(n, 33);
    memset(w, 0xcc, sizeof w);
    n = gw(c, CERT_NAME_DNS_TYPE, CERT_NAME_SEARCH_ALL_NAMES_FLAG, NULL, w, 128);
    EXPECT_EQ(n, 33);
    CHECK(!lstrcmpW(w, L"www.example.com"));
    CHECK(!lstrcmpW(w + 16, L"alt.example.org"));
    EXPECT_EQ(w[32], 0);
    char a[128]; memset(a, 0xcc, sizeof a);
    n = ga(c, CERT_NAME_DNS_TYPE, CERT_NAME_SEARCH_ALL_NAMES_FLAG, NULL, a, 128);
    EXPECT_EQ(n, 33); EXPECT_STR(a, "www.example.com"); EXPECT_STR(a + 16, "alt.example.org"); EXPECT_EQ(a[32], 0);
    fc(c);
}
TEST(sf_gns_dns_search_all_names_small_buffers) {
    REQ_GN(); CTX(c, leaf); WCHAR w[128]; DWORD n;
    memset(w, 0xcc, sizeof w);
    n = gw(c, CERT_NAME_DNS_TYPE, CERT_NAME_SEARCH_ALL_NAMES_FLAG, NULL, w, 33);
    EXPECT_EQ(n, 33); EXPECT_EQ(w[32], 0);
    memset(w, 0xcc, sizeof w);
    n = gw(c, CERT_NAME_DNS_TYPE, CERT_NAME_SEARCH_ALL_NAMES_FLAG, NULL, w, 16);
    t_note("SEARCH_ALL_NAMES with 16 char buffer: n=%lu w[14]=%#x w[15]=%#x", n, w[14], w[15]);
    fc(c);
}
TEST(sf_gns_dns_single_alt_name_search_all) {
    REQ_GN(); CTX(c, idn); WCHAR w[64]; DWORD n;
    n = gw(c, CERT_NAME_DNS_TYPE, CERT_NAME_SEARCH_ALL_NAMES_FLAG, NULL, w, 64);
    EXPECT_EQ(n, 23); CHECK(!lstrcmpW(w, L"xn--bcher-kva.example")); EXPECT_EQ(w[22], 0);
    fc(c);
}
TEST(sf_gns_search_all_names_only_valid_for_dns) {
    REQ_GN(); CTX(c, leaf); DWORD t, n; WCHAR w[16];
    for (t = 1; t <= 8; t++) {
        if (t == CERT_NAME_DNS_TYPE) continue;
        w[0] = 0x7777; SET_ERR(0);
        n = gw(c, t, CERT_NAME_SEARCH_ALL_NAMES_FLAG, NULL, w, 16);
        CHECKF(n == 1 && w[0] == 0, "type %lu n=%lu", t, n); EXPECT_LE(SF_E_INVALIDARG);
    }
    fc(c);
}
TEST(sf_gns_url) {
    REQ_GN(); CTX(c, leaf);
    GN(c, CERT_NAME_URL_TYPE, 0, NULL, "http://example.com/path");
    fc(c);
}
TEST(sf_gns_url_not_found) {
    REQ_GN(); CTX(c, ca); WCHAR w[8]; DWORD n;
    SET_ERR(0);
    n = gw(c, CERT_NAME_URL_TYPE, 0, NULL, w, 8);
    EXPECT_EQ(n, 1); EXPECT_EQ(w[0], 0); EXPECT_LE(CRYPT_E_NOT_FOUND);
    fc(c);
}
TEST(sf_gns_upn) {
    REQ_GN(); CTX(c, leaf);
    GN(c, CERT_NAME_UPN_TYPE, 0, NULL, "user@example.com");
    fc(c);
}
TEST(sf_gns_upn_not_found) {
    REQ_GN(); CTX(c, em); WCHAR w[8]; DWORD n;
    SET_ERR(0);
    n = gw(c, CERT_NAME_UPN_TYPE, 0, NULL, w, 8);
    EXPECT_EQ(n, 1); EXPECT_EQ(w[0], 0); EXPECT_LE(CRYPT_E_NOT_FOUND);
    fc(c);
}

/* ---------------- simple / friendly display ---------------- */
TEST(sf_gns_simple_display_common_name) {
    REQ_GN(); CTX(c, leaf);
    GN(c, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, "Leaf Subject");
    GN(c, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, NULL, "Test Root CA");
    fc(c);
}
TEST(sf_gns_simple_display_org_only) {
    REQ_GN(); CTX(c, o);
    GN(c, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, "JustOrg");
    fc(c);
}
TEST(sf_gns_simple_display_ou_vs_o_priority_observed) {
    REQ_GN(); CTX(c, ou); WCHAR w[64]; DWORD n;
    n = gw(c, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, w, 64);
    t_note("subject with only O=OnlyOrg,OU=OnlyUnit -> simple display '%ls' (%lu)", w, n);
    CHECK(!lstrcmpW(w, L"OnlyOrg") || !lstrcmpW(w, L"OnlyUnit"));
    fc(c);
}
TEST(sf_gns_simple_display_email_only_name) {
    REQ_GN(); CTX(c, em);
    GN(c, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, "Email Only");
    fc(c);
}
TEST(sf_gns_friendly_without_property_equals_simple) {
    REQ_GN(); CTX(c, leaf);
    GN(c, CERT_NAME_FRIENDLY_DISPLAY_TYPE, 0, NULL, "Leaf Subject");
    GN(c, CERT_NAME_FRIENDLY_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, NULL, "Test Root CA");
    fc(c);
}
TEST(sf_gns_friendly_name_property_wins) {
    REQ_GN(); CTX(c, leaf);
    BOOL (WINAPI *setp)(PCCERT_CONTEXT, DWORD, DWORD, const void*) = (void*)t_proc("CertSetCertificateContextProperty");
    REQUIRE(setp);
    PCCERT_CONTEXT d = cc(X509_ASN_ENCODING, sf_cert_leaf, sf_cert_leaf_len);
    static const WCHAR fn[] = L"My Friendly";
    CRYPT_DATA_BLOB blob; blob.cbData = sizeof fn; blob.pbData = (BYTE*)fn;
    BOOL r = setp(d, CERT_FRIENDLY_NAME_PROP_ID, 0, &blob);
    if (!r) { t_note("cannot set friendly name on a free-standing context: %lu", GetLastError()); fc(d); fc(c); return; }
    GN(d, CERT_NAME_FRIENDLY_DISPLAY_TYPE, 0, NULL, "My Friendly");
    GN(d, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, "Leaf Subject");
    GN(c, CERT_NAME_FRIENDLY_DISPLAY_TYPE, 0, NULL, "Leaf Subject");
    fc(d); fc(c);
}

/* ---------------- RDN and ATTR ---------------- */
TEST(sf_gns_rdn_with_string_type) {
    REQ_GN(); CTX(c, leaf); DWORD st;
    st = CERT_X500_NAME_STR;
    GN(c, CERT_NAME_RDN_TYPE, 0, &st, "C=US, O=Corp Org, OU=Dept, CN=Leaf Subject, E=leaf@example.com");
    st = CERT_OID_NAME_STR;
    GN(c, CERT_NAME_RDN_TYPE, 0, &st, "2.5.4.6=US, 2.5.4.10=Corp Org, 2.5.4.11=Dept, 2.5.4.3=Leaf Subject, 1.2.840.113549.1.9.1=leaf@example.com");
    st = CERT_SIMPLE_NAME_STR;
    GN(c, CERT_NAME_RDN_TYPE, 0, &st, "US, Corp Org, Dept, Leaf Subject, leaf@example.com");
    st = CERT_X500_NAME_STR | CERT_NAME_STR_REVERSE_FLAG | CERT_NAME_STR_SEMICOLON_FLAG;
    GN(c, CERT_NAME_RDN_TYPE, 0, &st, "E=leaf@example.com; CN=Leaf Subject; OU=Dept; O=Corp Org; C=US");
    fc(c);
}
TEST(sf_gns_rdn_issuer) {
    REQ_GN(); CTX(c, leaf); DWORD st = CERT_X500_NAME_STR;
    GN(c, CERT_NAME_RDN_TYPE, CERT_NAME_ISSUER_FLAG, &st, "C=US, O=Test CA, CN=Test Root CA");
    fc(c);
}
TEST(sf_gns_rdn_null_para_is_simple) {
    REQ_GN(); CTX(c, ca);
    GN(c, CERT_NAME_RDN_TYPE, 0, NULL, "US, Test CA, Test Root CA");
    fc(c);
}
TEST(sf_gns_rdn_crlf_flag) {
    REQ_GN(); CTX(c, ca); DWORD st = CERT_X500_NAME_STR | CERT_NAME_STR_CRLF_FLAG;
    GN(c, CERT_NAME_RDN_TYPE, 0, &st, "C=US\r\nO=Test CA\r\nCN=Test Root CA");
    fc(c);
}
TEST(sf_gns_attr_by_oid) {
    REQ_GN(); CTX(c, leaf);
    GN(c, CERT_NAME_ATTR_TYPE, 0, (void*)"2.5.4.3", "Leaf Subject");
    GN(c, CERT_NAME_ATTR_TYPE, 0, (void*)"2.5.4.10", "Corp Org");
    GN(c, CERT_NAME_ATTR_TYPE, 0, (void*)"2.5.4.11", "Dept");
    GN(c, CERT_NAME_ATTR_TYPE, 0, (void*)"2.5.4.6", "US");
    GN(c, CERT_NAME_ATTR_TYPE, 0, (void*)"1.2.840.113549.1.9.1", "leaf@example.com");
    GN(c, CERT_NAME_ATTR_TYPE, CERT_NAME_ISSUER_FLAG, (void*)"2.5.4.10", "Test CA");
    fc(c);
}
TEST(sf_gns_attr_missing_oid) {
    REQ_GN(); CTX(c, leaf); WCHAR w[8]; DWORD n;
    SET_ERR(0);
    n = gw(c, CERT_NAME_ATTR_TYPE, 0, (void*)"2.5.4.7", w, 8);
    EXPECT_EQ(n, 1); EXPECT_EQ(w[0], 0); EXPECT_LE(CRYPT_E_NOT_FOUND);
    GN(c, CERT_NAME_ATTR_TYPE, 0, (void*)"2.5.4.7", NULL);
    GN(c, CERT_NAME_ATTR_TYPE, CERT_NAME_ISSUER_FLAG, (void*)"2.5.4.11", NULL);
    fc(c);
}

/* ---------------- invalid types and flags ---------------- */
TEST(sf_gns_invalid_type_values) {
    REQ_GN(); CTX(c, leaf); DWORD types[] = { 0, 9, 10, 100, 0xffff }, i; WCHAR w[8]; char a[8]; DWORD n;
    for (i = 0; i < NELEM(types); i++) {
        w[0] = 0x7777; SET_ERR(0);
        n = gw(c, types[i], 0, NULL, w, 8);
        CHECKF(n == 1 && w[0] == 0, "W type %lu n=%lu", types[i], n); EXPECT_LE(SF_E_INVALIDARG);
        a[0] = 0x77; SET_ERR(0);
        n = ga(c, types[i], 0, NULL, a, 8);
        CHECKF(n == 1 && a[0] == 0, "A type %lu n=%lu", types[i], n); EXPECT_LE(SF_E_INVALIDARG);
        SET_ERR(0);
        n = gw(c, types[i], 0, NULL, NULL, 0);
        CHECKF(n == 1, "size query type %lu n=%lu", types[i], n); EXPECT_LE(SF_E_INVALIDARG);
    }
    fc(c);
}
TEST(sf_gns_a_and_w_agree_across_types) {
    REQ_GN(); CTX(c, leaf); DWORD t; char a[256]; WCHAR w[256]; DWORD na, nw; DWORD st = CERT_X500_NAME_STR;
    for (t = 1; t <= 8; t++) {
        void *para = t == CERT_NAME_RDN_TYPE ? (void*)&st : t == CERT_NAME_ATTR_TYPE ? (void*)"2.5.4.3" : NULL;
        na = ga(c, t, 0, para, a, 256); nw = gw(c, t, 0, para, w, 256);
        CHECKF(na == nw, "type %lu: A=%lu W=%lu", t, na, nw);
        if (na == nw && na > 1) { WCHAR e[256]; sf_widen(a, e); CHECKF(!lstrcmpW(e, w), "type %lu strings differ", t); }
    }
    fc(c);
}
TEST(sf_gns_all_types_for_each_cert_do_not_overrun) {
    REQ_GN();
    const BYTE *ders[] = { sf_cert_leaf, sf_cert_ou, sf_cert_o, sf_cert_ca, sf_cert_idn, sf_cert_em };
    const DWORD *lens[] = { &sf_cert_leaf_len, &sf_cert_ou_len, &sf_cert_o_len, &sf_cert_ca_len, &sf_cert_idn_len, &sf_cert_em_len };
    size_t k; DWORD t, f; DWORD st = CERT_X500_NAME_STR;
    for (k = 0; k < NELEM(ders); k++) {
        PCCERT_CONTEXT c = cc(X509_ASN_ENCODING, ders[k], *lens[k]);
        CHECKF(c != NULL, "cert %zu", k); if (!c) continue;
        for (t = 1; t <= 8; t++) for (f = 0; f <= 1; f++) {
            WCHAR guard[300]; DWORD need, n; void *para = t == 2 ? (void*)&st : t == 3 ? (void*)"2.5.4.3" : NULL;
            need = gw(c, t, f, para, NULL, 0);
            if (need > 250) continue;
            memset(guard, 0xcc, sizeof guard);
            n = gw(c, t, f, para, guard, need);
            CHECKF(n == need && guard[need] == 0xcccc, "cert %zu type %lu flag %lu overrun/length n=%lu need=%lu", k, t, f, n, need);
        }
        fc(c);
    }
}

/* ---------------- punycode / UTF-8 flags ---------------- */
TEST(sf_gns_punycode_default_unchanged) {
    REQ_GN(); CTX(c, idn);
    GN(c, CERT_NAME_DNS_TYPE, 0, NULL, "xn--bcher-kva.example");
    GN(c, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, "xn--bcher-kva.example");
    fc(c);
}
TEST(sf_gns_punycode_flag_observed) {
    REQ_GN(); CTX(c, idn); WCHAR w[64]; DWORD n;
    n = gw(c, CERT_NAME_DNS_TYPE, CERT_NAME_STR_ENABLE_PUNYCODE_FLAG, NULL, w, 64);
    t_note("DNS name with ENABLE_PUNYCODE_FLAG: n=%lu '%ls'", n, w);
    n = gw(c, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_STR_ENABLE_PUNYCODE_FLAG, NULL, w, 64);
    t_note("simple display with ENABLE_PUNYCODE_FLAG: n=%lu '%ls'", n, w);
    fc(c);
}
TEST(sf_gns_disable_ie4_utf8_flag_accepted) {
    REQ_GN(); CTX(c, leaf);
    GN(c, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_DISABLE_IE4_UTF8_FLAG, NULL, "Leaf Subject");
    GN(c, CERT_NAME_ATTR_TYPE, CERT_NAME_DISABLE_IE4_UTF8_FLAG, (void*)"2.5.4.3", "Leaf Subject");
    fc(c);
}
TEST(sf_gns_repeated_calls_stable) {
    REQ_GN(); CTX(c, leaf); int i; WCHAR a[64], b[64];
    gw(c, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, a, 64);
    for (i = 0; i < 200; i++) { gw(c, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, b, 64); if (lstrcmpW(a, b)) { CHECK(0); break; } }
    fc(c);
}
