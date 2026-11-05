/* CERT_CHAIN_POLICY_SSL (crypt32's own policy; no schannel involved): server-name matching, fdwChecks, error mapping. */
#include "cp.h"

typedef struct { DWORD cb; DWORD authType; DWORD fdwChecks; DWORD pad; const WCHAR *name; } SSLP;   /* SSL_EXTRA_CERT_CHAIN_POLICY_PARA (x64 layout) */

static PRES ssl_run(PCCERT_CHAIN_CONTEXT c, DWORD auth, DWORD checks, const WCHAR *name, DWORD flags) {
    SSLP e; memset(&e, 0, sizeof e);
    e.cb = sizeof(SSL_EXTRA_CERT_CHAIN_POLICY_PARA); e.authType = auth; e.fdwChecks = checks; e.name = name;
    return cp_run(CERT_CHAIN_POLICY_SSL, c, flags, &e);
}
static void name_case(int leaf, const WCHAR *name, int want_match, const char *what) {
    PCCERT_CHAIN_CONTEXT c = cp_chain(leaf);
    PRES p;
    if (!c) { t_skip("chain build failed"); return; }
    p = ssl_run(c, AUTHTYPE_SERVER, 0, name, 0);
    CHECK(p.ret);
    if (want_match) CHECKF(p.err == 0 && p.ci == -1 && p.ei == -1, "%s: expected match, err=0x%08lx ci=%ld ei=%ld", what, p.err, p.ci, p.ei);
    else CHECKF(p.err == CERR_CN_NO_MATCH && p.ci == 0 && p.ei == 0, "%s: expected CN_NO_MATCH, err=0x%08lx ci=%ld ei=%ld", what, p.err, p.ci, p.ei);
    cp_free(c);
}
#define NAMET(tn, leaf, nm, want) TEST(ssl_name_##tn) { NEED_ENV(); name_case(C_##leaf, nm, want, #tn); }

/* --- DNS SAN exact --- */
NAMET(san_exact_match, SRV, L"www.example.test", 1)
NAMET(san_case_insensitive, SRV, L"WWW.Example.TEST", 1)
NAMET(san_prefix_missing, SRV, L"example.test", 0)
NAMET(san_label_shorter, SRV, L"ww.example.test", 0)
NAMET(san_label_extra_char, SRV, L"xwww.example.test", 0)
NAMET(san_suffix_extra, SRV, L"www.example.test.evil", 0)
NAMET(san_other_host, SRV, L"mail.example.test", 0)
NAMET(san_empty_name_mismatch, SRV, L"", 0)
NAMET(san_extra_leading_label, SRV, L"a.www.example.test", 0)
/* --- wildcards --- */
NAMET(wild_one_label, WILD, L"a.wild.example.test", 1)
NAMET(wild_case_insensitive, WILD, L"A.WILD.EXAMPLE.TEST", 1)
NAMET(wild_apex_not_matched, WILD, L"wild.example.test", 0)
NAMET(wild_two_labels_not_matched, WILD, L"a.b.wild.example.test", 0)
NAMET(wild_other_parent, WILD, L"a.other.example.test", 0)
NAMET(wild_cn_not_used_when_san_has_dns, WILD, L"wild.example.test", 0)
NAMET(pwild_matches_prefix_wildcard, PWILD, L"www.pw.example.test", 1)
NAMET(pwild_matches_other_suffix_chars, PWILD, L"wxyz.pw.example.test", 1)
NAMET(pwild_wrong_first_char, PWILD, L"abc.pw.example.test", 0)
NAMET(pwild_two_labels, PWILD, L"www.x.pw.example.test", 0)
/* --- CN fallback --- */
NAMET(cn_only_match, CNONLY, L"cn.example.test", 1)
NAMET(cn_only_case_insensitive, CNONLY, L"CN.EXAMPLE.TEST", 1)
NAMET(cn_only_mismatch, CNONLY, L"other.example.test", 0)
NAMET(cn_wild_match, CNWILD, L"x.cnwild.example.test", 1)
NAMET(cn_wild_apex_not_matched, CNWILD, L"cnwild.example.test", 0)
NAMET(cn_wild_two_labels, CNWILD, L"x.y.cnwild.example.test", 0)
NAMET(san_present_hides_cn_other_name_matches, SANMISMATCH, L"other.example.test", 1)
NAMET(san_present_hides_cn, SANMISMATCH, L"cn-match.example.test", 0)
NAMET(san_without_dns_falls_back_to_cn, SANNODNS, L"cn-fallback.example.test", 1)
NAMET(san_without_dns_cn_mismatch, SANNODNS, L"example.test", 0)
NAMET(multi_san_first, MULTISAN, L"a.example.test", 1)
NAMET(multi_san_second, MULTISAN, L"b.example.test", 1)
NAMET(multi_san_cn_hidden, MULTISAN, L"multi.example.test", 0)
NAMET(multi_san_third_unlisted, MULTISAN, L"c.example.test", 0)
/* --- IP addresses --- */
NAMET(ip_v4_match, IP, L"192.0.2.7", 1)
NAMET(ip_v4_mismatch, IP, L"192.0.2.8", 0)
NAMET(ip_v6_match, IP, L"2001:db8::1", 1)
NAMET(ip_v6_expanded_form_match, IP, L"2001:0db8:0000:0000:0000:0000:0000:0001", 1)
NAMET(ip_v6_mismatch, IP, L"2001:db8::2", 0)
NAMET(ip_cert_without_dns_san_uses_cn, IP, L"ip-host.example.test", 1)
NAMET(ip_in_san_alongside_dns, MULTISAN, L"198.51.100.9", 1)
NAMET(ip_v4_not_in_cert, SRV, L"192.0.2.7", 0)
NAMET(ip_v4_other_in_multisan, MULTISAN, L"198.51.100.10", 0)
/* --- server name decoration --- */
NAMET(prefix_slash_stripped, SRV, L"https://www.example.test", 1)
NAMET(prefix_single_slash_stripped, SRV, L"x/www.example.test", 1)
NAMET(trailing_path_not_stripped, SRV, L"www.example.test/x", 0)
NAMET(at_sign_truncates_name, SRV, L"www.example.test@junk", 1)
NAMET(at_sign_before_host_truncates_to_user, SRV, L"user@www.example.test", 0)
NAMET(idn_ascii_form, IDN, L"xn--bcher-kva.example.test", 1)

TEST(ssl_name_idn_unicode_form) {
    PCCERT_CHAIN_CONTEXT c; PRES p;
    NEED_ENV();
    c = cp_chain(C_IDN);
    if (!c) { t_skip("chain build failed"); return; }
    p = ssl_run(c, AUTHTYPE_SERVER, 0, L"bücher.example.test", 0);
    CHECK(p.ret);
    if (p.err != 0) t_note("unicode IDN name not matched against punycode SAN: err=0x%08lx", p.err);
    cp_free(c);
}
TEST(ssl_name_ip_with_port_form) {
    PCCERT_CHAIN_CONTEXT c; PRES p;
    NEED_ENV();
    c = cp_chain(C_IP);
    if (!c) { t_skip("chain build failed"); return; }
    p = ssl_run(c, AUTHTYPE_SERVER, 0, L"192.0.2.7:443", 0);
    CHECK(p.ret);
    t_note("name \"192.0.2.7:443\" -> err=0x%08lx", p.err);
    cp_free(c);
}

/* --- authType is not consulted by the policy itself --- */
TEST(ssl_authtype_values_do_not_change_result) {
    static const DWORD at[] = {0, AUTHTYPE_CLIENT, AUTHTYPE_SERVER, 3, 99};
    PCCERT_CHAIN_CONTEXT c;
    NEED_ENV();
    c = cp_chain(C_SRV);
    if (!c) { t_skip("chain build failed"); return; }
    for (unsigned i = 0; i < sizeof at / sizeof at[0]; i++) {
        PRES a = ssl_run(c, at[i], 0, L"www.example.test", 0), b = ssl_run(c, at[i], 0, L"nope.example.test", 0);
        CHECKF(a.ret && a.err == 0, "authType %lu match: 0x%lx", at[i], a.err);
        CHECKF(b.ret && b.err == CERR_CN_NO_MATCH, "authType %lu mismatch: 0x%lx", at[i], b.err);
    }
    cp_free(c);
}
TEST(ssl_client_cert_chain_client_authtype_no_name) {
    PCCERT_CHAIN_CONTEXT c; PRES p;
    NEED_ENV();
    c = cp_chain(C_CLIENT);
    if (!c) { t_skip("chain build failed"); return; }
    p = ssl_run(c, AUTHTYPE_CLIENT, 0, NULL, 0);
    CHECK(p.ret && p.err == 0 && p.ci == -1 && p.ei == -1);
    cp_free(c);
}
TEST(ssl_no_server_name_means_no_name_check) {
    static const int leaves[] = {C_SRV, C_CNONLY, C_IP, C_CLIENT, C_NOEKU};
    NEED_ENV();
    for (unsigned i = 0; i < sizeof leaves / sizeof leaves[0]; i++) {
        PCCERT_CHAIN_CONTEXT c = cp_chain(leaves[i]); PRES p;
        if (!c) { t_skip("chain build failed"); return; }
        p = ssl_run(c, AUTHTYPE_SERVER, 0, NULL, 0);
        CHECKF(p.ret && p.err == 0, "leaf %d: 0x%lx", leaves[i], p.err);
        cp_free(c);
    }
}
TEST(ssl_null_para_means_no_name_check) {
    PCCERT_CHAIN_CONTEXT c; PRES p;
    NEED_ENV();
    c = cp_chain(C_SRV);
    if (!c) { t_skip("chain build failed"); return; }
    p = cp_run(CERT_CHAIN_POLICY_SSL, c, 0, NULL);
    CHECK(p.ret && p.err == 0 && p.ci == -1 && p.ei == -1);
    cp_free(c);
}

/* --- extra para size rules --- */
TEST(ssl_extra_para_too_small_is_invalid_parameter) {
    static const DWORD sz[] = {0, 4, 8, 12, 16};
    PCCERT_CHAIN_CONTEXT c;
    NEED_ENV();
    c = cp_chain(C_SRV);
    if (!c) { t_skip("chain build failed"); return; }
    for (unsigned i = 0; i < sizeof sz / sizeof sz[0]; i++) {
        SSLP e; PRES p;
        memset(&e, 0, sizeof e); e.cb = sz[i]; e.name = L"www.example.test";
        p = cp_run(CERT_CHAIN_POLICY_SSL, c, 0, &e);
        CHECKF(!p.ret, "extra cbSize %lu accepted", sz[i]);
        CHECKF(p.gle == ERROR_INVALID_PARAMETER, "extra cbSize %lu: GetLastError %lu", sz[i], p.gle);
        CHECK(p.err == 0 && p.ci == -1 && p.ei == -1);
    }
    cp_free(c);
}
TEST(ssl_extra_para_minimum_accepted_size) {
    static const DWORD sz[] = {17, 20, 24, 32, 1000};
    PCCERT_CHAIN_CONTEXT c;
    NEED_ENV();
    c = cp_chain(C_SRV);
    if (!c) { t_skip("chain build failed"); return; }
    for (unsigned i = 0; i < sizeof sz / sizeof sz[0]; i++) {
        SSLP e; PRES p;
        memset(&e, 0, sizeof e); e.cb = sz[i]; e.name = L"nope.example.test";
        p = cp_run(CERT_CHAIN_POLICY_SSL, c, 0, &e);
        CHECKF(p.ret && p.err == CERR_CN_NO_MATCH, "extra cbSize %lu: ret=%d err=0x%lx", sz[i], p.ret, p.err);
    }
    cp_free(c);
}
TEST(ssl_policy_para_cbsize_hides_extra) {
    static const DWORD sz[] = {0, 4, 8};
    PCCERT_CHAIN_CONTEXT c;
    NEED_ENV();
    c = cp_chain(C_SRV);
    if (!c) { t_skip("chain build failed"); return; }
    for (unsigned i = 0; i < sizeof sz / sizeof sz[0]; i++) {
        SSLP e; PRES p;
        memset(&e, 0, sizeof e); e.cb = sizeof e; e.name = L"nope.example.test";
        p = cp_run_ex(CERT_CHAIN_POLICY_SSL, c, sz[i], 0, &e, sizeof(CERT_CHAIN_POLICY_STATUS), NULL);
        CHECKF(p.ret && p.err == 0, "para cbSize %lu: err=0x%lx (extra must be ignored)", sz[i], p.err);
    }
    {
        SSLP e; PRES p;
        memset(&e, 0, sizeof e); e.cb = sizeof e; e.name = L"nope.example.test";
        p = cp_run_ex(CERT_CHAIN_POLICY_SSL, c, 9, 0, &e, sizeof(CERT_CHAIN_POLICY_STATUS), NULL);
        CHECK(p.ret && p.err == CERR_CN_NO_MATCH);
    }
    cp_free(c);
}

/* --- fdwChecks --- */
TEST(ssl_fdwchecks_ignore_cn_invalid) {
    PCCERT_CHAIN_CONTEXT c; PRES p;
    NEED_ENV();
    c = cp_chain(C_SRV);
    if (!c) { t_skip("chain build failed"); return; }
    p = ssl_run(c, AUTHTYPE_SERVER, SECURITY_FLAG_IGNORE_CERT_CN_INVALID, L"nope.example.test", 0);
    CHECK(p.ret && p.err == 0 && p.ci == -1 && p.ei == -1);
    p = ssl_run(c, AUTHTYPE_SERVER, 0x1000, NULL, 0);
    CHECK(p.ret && p.err == 0);
    cp_free(c);
}
TEST(ssl_fdwchecks_other_bits_do_not_ignore_cn) {
    static const DWORD f[] = {0x80, 0x100, 0x200, 0x2000, 0x10000, 0xEFFF & ~0x1000u};
    PCCERT_CHAIN_CONTEXT c;
    NEED_ENV();
    c = cp_chain(C_SRV);
    if (!c) { t_skip("chain build failed"); return; }
    for (unsigned i = 0; i < sizeof f / sizeof f[0]; i++) {
        PRES p = ssl_run(c, AUTHTYPE_SERVER, f[i], L"nope.example.test", 0);
        CHECKF(p.ret && p.err == CERR_CN_NO_MATCH, "fdwChecks 0x%lx: err=0x%lx", f[i], p.err);
    }
    cp_free(c);
}
TEST(ssl_fdwchecks_ignore_unknown_ca) {
    PCCERT_CHAIN_CONTEXT c; PRES p;
    NEED_ENV();
    c = cp_chain_ex(cp_engine_empty(), C_SRV, 0, NULL, NULL, 0);
    if (!c) { t_skip("chain build failed"); return; }
    p = ssl_run(c, AUTHTYPE_SERVER, 0, L"www.example.test", 0);
    CHECK(p.ret); EXPECT_EQ(p.err, CERR_UNTRUSTEDROOT); CHECK(p.ci == 0 && p.ei == 2);
    p = ssl_run(c, AUTHTYPE_SERVER, SECURITY_FLAG_IGNORE_UNKNOWN_CA, L"www.example.test", 0);
    CHECK(p.ret && p.err == 0);
    p = ssl_run(c, AUTHTYPE_SERVER, SECURITY_FLAG_IGNORE_UNKNOWN_CA, L"nope.example.test", 0);
    CHECK(p.ret); EXPECT_EQ(p.err, CERR_CN_NO_MATCH);       /* name still checked after the root error is ignored */
    cp_free(c);
}
TEST(ssl_untrusted_root_skips_name_check) {
    PCCERT_CHAIN_CONTEXT c; PRES p;
    NEED_ENV();
    c = cp_chain_ex(cp_engine_empty(), C_SRV, 0, NULL, NULL, 0);
    if (!c) { t_skip("chain build failed"); return; }
    p = ssl_run(c, AUTHTYPE_SERVER, 0, L"nope.example.test", 0);
    CHECK(p.ret); EXPECT_EQ(p.err, CERR_UNTRUSTEDROOT);
    cp_free(c);
}
TEST(ssl_fdwchecks_ignore_wrong_usage) {
    PCCERT_CHAIN_CONTEXT c; PRES p;
    NEED_ENV();
    c = cp_chain_ex(NULL, C_CLIENT, 0, NULL, szOID_PKIX_KP_SERVER_AUTH, 0);
    if (!c) { t_skip("chain build failed"); return; }
    p = ssl_run(c, AUTHTYPE_SERVER, 0, NULL, 0);
    CHECK(p.ret); CHECKF(p.err == CERR_WRONG_USAGE, "got 0x%lx", p.err); CHECK(p.ci == 0 && p.ei == 0);
    p = ssl_run(c, AUTHTYPE_SERVER, SECURITY_FLAG_IGNORE_WRONG_USAGE, NULL, 0);
    CHECK(p.ret && p.err == 0);
    cp_free(c);
}
TEST(ssl_fdwchecks_ignore_date_invalid) {
    PCCERT_CHAIN_CONTEXT c; PRES p;
    NEED_ENV();
    c = cp_chain(C_EXPIRED);
    if (!c) { t_skip("chain build failed"); return; }
    p = ssl_run(c, AUTHTYPE_SERVER, 0, L"www.example.test", 0);
    CHECK(p.ret); CHECKF(p.err == CERR_EXPIRED, "got 0x%lx", p.err); CHECK(p.ci == 0 && p.ei == 0);
    p = ssl_run(c, AUTHTYPE_SERVER, SECURITY_FLAG_IGNORE_CERT_DATE_INVALID, L"www.example.test", 0);
    CHECK(p.ret && p.err == 0);
    p = ssl_run(c, AUTHTYPE_SERVER, SECURITY_FLAG_IGNORE_CERT_DATE_INVALID, L"nope.example.test", 0);
    CHECK(p.ret); EXPECT_EQ(p.err, CERR_CN_NO_MATCH);
    cp_free(c);
}
TEST(ssl_not_yet_valid_leaf) {
    PCCERT_CHAIN_CONTEXT c; PRES p;
    NEED_ENV();
    c = cp_chain(C_NOTYET);
    if (!c) { t_skip("chain build failed"); return; }
    p = ssl_run(c, AUTHTYPE_SERVER, 0, NULL, 0);
    CHECK(p.ret); EXPECT_EQ(p.err, CERR_EXPIRED);
    cp_free(c);
}
TEST(ssl_expired_error_hides_name_mismatch) {
    PCCERT_CHAIN_CONTEXT c; PRES p;
    NEED_ENV();
    c = cp_chain(C_EXPIRED);
    if (!c) { t_skip("chain build failed"); return; }
    p = ssl_run(c, AUTHTYPE_SERVER, 0, L"nope.example.test", 0);
    CHECK(p.ret); EXPECT_EQ(p.err, CERR_EXPIRED);
    cp_free(c);
}
TEST(ssl_policy_flags_are_merged_with_fdwchecks) {
    PCCERT_CHAIN_CONTEXT c; PRES p;
    NEED_ENV();
    c = cp_chain_ex(cp_engine_empty(), C_EXPIRED, 0, NULL, NULL, 0);
    if (!c) { t_skip("chain build failed"); return; }
    p = ssl_run(c, AUTHTYPE_SERVER, SECURITY_FLAG_IGNORE_UNKNOWN_CA, NULL, 0);
    CHECK(p.ret); EXPECT_EQ(p.err, CERR_EXPIRED);
    p = ssl_run(c, AUTHTYPE_SERVER, SECURITY_FLAG_IGNORE_UNKNOWN_CA, NULL, CERT_CHAIN_POLICY_IGNORE_NOT_TIME_VALID_FLAG);
    CHECK(p.ret && p.err == 0);
    p = ssl_run(c, AUTHTYPE_SERVER, 0, NULL, CERT_CHAIN_POLICY_ALLOW_UNKNOWN_CA_FLAG | CERT_CHAIN_POLICY_IGNORE_NOT_TIME_VALID_FLAG);
    CHECK(p.ret && p.err == 0);
    cp_free(c);
}

/* --- error mapping of the underlying base policy (synthetic contexts) --- */
static PRES syn_ssl(DWORD ctxerr, int el, DWORD elerr, int chainlevel, DWORD checks, const WCHAR *name, DWORD flags) {
    SYN s; int n[1] = {3};
    syn_init(&s, 1, n); syn_ctx(&s, ctxerr, 0);
    if (chainlevel) syn_chain(&s, 0, elerr, 0); else if (el >= 0) syn_el(&s, 0, el, elerr, 0);
    return ssl_run(&s.cc, AUTHTYPE_SERVER, checks, name, flags);
}
TEST(ssl_map_basic_constraints_to_role) {
    PRES p; REQUIRE(U(CertVerifyCertificateChainPolicy));
    p = syn_ssl(0x400, 1, 0x400, 0, 0, NULL, 0);
    CHECK(p.ret); EXPECT_EQ(p.err, CERR_ROLE); CHECK(p.ci == 0 && p.ei == 1);
}
TEST(ssl_map_partial_chain_to_untrusted_root) {
    PRES p; REQUIRE(U(CertVerifyCertificateChainPolicy));
    p = syn_ssl(0x10000, -1, 0x10000, 1, 0, NULL, 0);
    CHECK(p.ret); EXPECT_EQ(p.err, CERR_UNTRUSTEDROOT); CHECK(p.ci == 0 && p.ei == -1);
}
TEST(ssl_map_invalid_policy_to_purpose) {
    PRES p; REQUIRE(U(CertVerifyCertificateChainPolicy));
    p = syn_ssl(0x200, 1, 0x200, 0, 0, NULL, 0);
    CHECK(p.ret); EXPECT_EQ(p.err, CERR_PURPOSE); CHECK(p.ci == 0 && p.ei == 1);
    p = syn_ssl(0x2000000, 2, 0x2000000, 0, 0, NULL, 0);
    CHECK(p.ret); EXPECT_EQ(p.err, CERR_PURPOSE); CHECK(p.ci == 0 && p.ei == 2);
}
TEST(ssl_map_invalid_name_to_cn_no_match) {
    static const DWORD bits[] = {0x800, 0x1000, 0x2000, 0x4000, 0x8000};
    REQUIRE(U(CertVerifyCertificateChainPolicy));
    for (unsigned i = 0; i < 5; i++) {
        PRES p = syn_ssl(bits[i], 1, bits[i], 0, 0, NULL, 0);
        CHECKF(p.ret && p.err == CERR_CN_NO_MATCH && p.ci == 0 && p.ei == 1, "bit 0x%lx: err=0x%lx", bits[i], p.err);
    }
}
TEST(ssl_ignore_cn_flag_also_ignores_name_constraint_errors) {
    PRES p; REQUIRE(U(CertVerifyCertificateChainPolicy));
    p = syn_ssl(0x800, 1, 0x800, 0, SECURITY_FLAG_IGNORE_CERT_CN_INVALID, NULL, 0);
    CHECK(p.ret && p.err == 0);
}
TEST(ssl_unmapped_errors_pass_through) {
    static const struct { DWORD bit; DWORD code; } t[] = {
        {0x8, TERR_CERT_SIGNATURE}, {0x4, CRYPTERR_REVOKED}, {0x20, CERR_UNTRUSTEDROOT}, {0x1, CERR_EXPIRED},
        {0x10, CERR_WRONG_USAGE}, {0x8000000, CERR_CRITICAL}, {0x4000000, CRYPTERR_REVOKED}, };
    REQUIRE(U(CertVerifyCertificateChainPolicy));
    for (unsigned i = 0; i < sizeof t / sizeof t[0]; i++) {
        PRES p = syn_ssl(t[i].bit, 1, t[i].bit, 0, 0, NULL, 0);
        CHECKF(p.ret && p.err == t[i].code && p.ci == 0 && p.ei == 1, "bit 0x%lx: err=0x%lx", t[i].bit, p.err);
    }
}
TEST(ssl_nesting_always_ignored) {
    PRES p; REQUIRE(U(CertVerifyCertificateChainPolicy));
    p = syn_ssl(0x2, 0, 0x2, 0, 0, NULL, 0);
    CHECK(p.ret && p.err == 0 && p.ci == -1 && p.ei == -1);
}
TEST(ssl_root_and_ca_revocation_unknown_always_ignored) {
    SYN s; int n[1] = {3}; PRES p;
    REQUIRE(U(CertVerifyCertificateChainPolicy));
    syn_init(&s, 1, n); syn_ctx(&s, 0x40, 0);
    syn_el(&s, 0, 1, 0x40, 0); syn_rev(&s, 0, 1, CRYPTERR_NO_REVOCATION_CHECK);
    syn_el(&s, 0, 2, 0x40, 8); syn_rev(&s, 0, 2, CRYPTERR_REVOCATION_OFFLINE);
    p = ssl_run(&s.cc, AUTHTYPE_SERVER, 0, NULL, 0);
    CHECK(p.ret && p.err == 0 && p.ci == -1 && p.ei == -1);
}
TEST(ssl_end_cert_revocation_unknown_reported) {
    SYN s; int n[1] = {3}; PRES p;
    REQUIRE(U(CertVerifyCertificateChainPolicy));
    syn_init(&s, 1, n); syn_ctx(&s, 0x40, 0);
    syn_el(&s, 0, 0, 0x40, 0); syn_rev(&s, 0, 0, CRYPTERR_NO_REVOCATION_CHECK);
    p = ssl_run(&s.cc, AUTHTYPE_SERVER, 0, NULL, 0);
    CHECK(p.ret); EXPECT_EQ(p.err, CRYPTERR_NO_REVOCATION_CHECK); CHECK(p.ci == 0 && p.ei == 0);
}
TEST(ssl_revocation_unknown_still_checks_name_match) {
    SYN s; int n[1] = {3}; PRES p;
    REQUIRE(U(CertVerifyCertificateChainPolicy));
    syn_init(&s, 1, n); syn_ctx(&s, 0x40, 0);
    syn_el(&s, 0, 0, 0x40, 0); syn_rev(&s, 0, 0, CRYPTERR_NO_REVOCATION_CHECK);
    p = ssl_run(&s.cc, AUTHTYPE_SERVER, 0, L"www.example.test", 0);        /* synthetic leaf is the srv certificate */
    CHECK(p.ret); EXPECT_EQ(p.err, CRYPTERR_NO_REVOCATION_CHECK); CHECK(p.ci == 0 && p.ei == 0);
    p = ssl_run(&s.cc, AUTHTYPE_SERVER, 0, L"nope.example.test", 0);
    CHECK(p.ret); EXPECT_EQ(p.err, CERR_CN_NO_MATCH); CHECK(p.ci == 0 && p.ei == 0);
}
TEST(ssl_revocation_offline_still_checks_name_match) {
    SYN s; int n[1] = {3}; PRES p;
    REQUIRE(U(CertVerifyCertificateChainPolicy));
    syn_init(&s, 1, n); syn_ctx(&s, 0x40, 0);
    syn_el(&s, 0, 0, 0x40, 0); syn_rev(&s, 0, 0, CRYPTERR_REVOCATION_OFFLINE);
    p = ssl_run(&s.cc, AUTHTYPE_SERVER, 0, L"nope.example.test", 0);
    CHECK(p.ret); EXPECT_EQ(p.err, CERR_CN_NO_MATCH);
}
TEST(ssl_fdwchecks_revocation_bit_not_honoured) {
    SYN s; int n[1] = {3}; PRES p;
    REQUIRE(U(CertVerifyCertificateChainPolicy));
    syn_init(&s, 1, n); syn_ctx(&s, 0x40, 0);
    syn_el(&s, 0, 0, 0x40, 0); syn_rev(&s, 0, 0, CRYPTERR_NO_REVOCATION_CHECK);
    p = ssl_run(&s.cc, AUTHTYPE_SERVER, 0x80, NULL, 0);
    CHECK(p.ret); EXPECT_EQ(p.err, CRYPTERR_NO_REVOCATION_CHECK);
    p = ssl_run(&s.cc, AUTHTYPE_SERVER, 0, NULL, CERT_CHAIN_POLICY_IGNORE_END_REV_UNKNOWN_FLAG);
    CHECK(p.ret && p.err == 0);
}

/* --- real chains: role / chaining --- */
TEST(ssl_real_non_ca_issuer_is_role_error) {
    PCCERT_CHAIN_CONTEXT c; PRES p;
    NEED_ENV();
    c = cp_chain(C_UNDER_EE);
    if (!c) { t_skip("chain build failed"); return; }
    p = ssl_run(c, AUTHTYPE_SERVER, 0, NULL, 0);
    CHECK(p.ret); CHECKF(p.err == CERR_ROLE, "got 0x%lx", p.err); CHECK(p.ci == 0 && p.ei == 1);
    cp_free(c);
}
TEST(ssl_real_missing_issuer_reports_untrusted_root) {
    PCCERT_CHAIN_CONTEXT c; PRES p;
    NEED_ENV();
    c = cp_chain(C_ORPHAN);
    if (!c) { t_skip("chain build failed"); return; }
    p = ssl_run(c, AUTHTYPE_SERVER, 0, NULL, 0);
    CHECK(p.ret); CHECKF(p.err == CERR_UNTRUSTEDROOT, "got 0x%lx", p.err);
    cp_free(c);
}
TEST(ssl_real_path_length_exceeded_is_role_error) {
    PCCERT_CHAIN_CONTEXT c; PRES p;
    NEED_ENV();
    c = cp_chain(C_DEEP);
    if (!c) { t_skip("chain build failed"); return; }
    p = ssl_run(c, AUTHTYPE_SERVER, 0, NULL, 0);
    CHECK(p.ret); CHECKF(p.err == CERR_ROLE, "got 0x%lx", p.err);
    cp_free(c);
}
TEST(ssl_real_self_signed_leaf) {
    PCCERT_CHAIN_CONTEXT c; PRES p;
    NEED_ENV();
    c = cp_chain(C_SELFLEAF);
    if (!c) { t_skip("chain build failed"); return; }
    p = ssl_run(c, AUTHTYPE_SERVER, 0, L"x.example.test", 0);
    CHECK(p.ret); EXPECT_EQ(p.err, CERR_UNTRUSTEDROOT);
    p = ssl_run(c, AUTHTYPE_SERVER, SECURITY_FLAG_IGNORE_UNKNOWN_CA, L"x.example.test", 0);
    CHECK(p.ret); EXPECT_EQ(p.err, CERR_CN_NO_MATCH);      /* CN is "CryptT Self Signed Leaf" */
    cp_free(c);
}
TEST(ssl_name_uses_leaf_certificate_only) {
    PCCERT_CHAIN_CONTEXT c; PRES p;
    NEED_ENV();
    c = cp_chain(C_CNONLY);
    if (!c) { t_skip("chain build failed"); return; }
    p = ssl_run(c, AUTHTYPE_SERVER, 0, L"CryptT Policy Intermediate", 0);   /* issuer CN must not match */
    CHECK(p.ret); EXPECT_EQ(p.err, CERR_CN_NO_MATCH);
    cp_free(c);
}
TEST(ssl_name_with_spaces_in_cn_matches_literally) {
    PCCERT_CHAIN_CONTEXT c; PRES p;
    NEED_ENV();
    c = cp_chain(C_CLIENT);                            /* CN = "CryptT Client", no SAN */
    if (!c) { t_skip("chain build failed"); return; }
    p = ssl_run(c, AUTHTYPE_SERVER, 0, L"CryptT Client", 0);
    CHECK(p.ret); EXPECT_EQ(p.err, 0);
    p = ssl_run(c, AUTHTYPE_SERVER, 0, L"cryptt client", 0);
    CHECK(p.ret); EXPECT_EQ(p.err, 0);
    cp_free(c);
}
TEST(ssl_repeated_name_checks_stable) {
    PCCERT_CHAIN_CONTEXT c;
    NEED_ENV();
    c = cp_chain(C_WILD);
    if (!c) { t_skip("chain build failed"); return; }
    for (int i = 0; i < 100; i++) {
        PRES a = ssl_run(c, AUTHTYPE_SERVER, 0, L"q.wild.example.test", 0), b = ssl_run(c, AUTHTYPE_SERVER, 0, L"wild.example.test", 0);
        if (a.err != 0 || b.err != CERR_CN_NO_MATCH) { CHECKF(0, "iteration %d: 0x%lx 0x%lx", i, a.err, b.err); break; }
    }
    cp_free(c);
}
