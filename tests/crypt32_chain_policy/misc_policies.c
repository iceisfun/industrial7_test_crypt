/* BASIC_CONSTRAINTS, NT_AUTH, MICROSOFT_ROOT, THIRD_PARTY_ROOT and EV policies. */
#include "cp.h"

#define BCCA BASIC_CONSTRAINTS_CERT_CHAIN_POLICY_CA_FLAG
#define BCEE BASIC_CONSTRAINTS_CERT_CHAIN_POLICY_END_ENTITY_FLAG

/* ---------- BASIC_CONSTRAINTS ---------- */
static void bc_case(int leaf, DWORD flags, DWORD want, LONG wci, LONG wei, const char *what) {
    PCCERT_CHAIN_CONTEXT c = cp_chain(leaf); PRES p;
    if (!c) { t_skip("chain build failed"); return; }
    p = cp_run(CERT_CHAIN_POLICY_BASIC_CONSTRAINTS, c, flags, NULL);
    CHECKF(p.ret, "%s: FALSE", what);
    CHECKF(p.err == want && p.ci == wci && p.ei == wei, "%s: err=0x%lx ci=%ld ei=%ld want 0x%lx %ld %ld", what, p.err, p.ci, p.ei, want, wci, wei);
    cp_free(c);
}
#define BCT(nm, leaf, flags, want, ci, ei) TEST(bc_##nm) { NEED_ENV(); bc_case(C_##leaf, flags, want, ci, ei, #nm); }
BCT(plain_end_entity_no_flags, SRV, 0, 0, -1, -1)
BCT(ee_flag_on_end_entity, SRV, BCEE, 0, -1, -1)
BCT(ca_flag_on_end_entity_fails, SRV, BCCA, TERR_BASIC_CONSTRAINTS, 0, 0)
BCT(ca_flag_on_ca_leaf, CALEAF, BCCA, 0, -1, -1)
BCT(ee_flag_on_ca_leaf_fails, CALEAF, BCEE, TERR_BASIC_CONSTRAINTS, 0, 0)
BCT(no_flags_ca_leaf, CALEAF, 0, 0, -1, -1)
BCT(both_flags_ignored_end_entity, SRV, BCCA | BCEE, 0, -1, -1)
BCT(both_flags_ignored_ca_leaf, CALEAF, BCCA | BCEE, 0, -1, -1)
BCT(ca_flag_on_cert_without_extension_passes, INTER_NOBC, BCCA, 0, -1, -1)
BCT(ee_flag_on_cert_without_extension_passes, INTER_NOBC, BCEE, 0, -1, -1)
BCT(issuer_not_ca_reported_without_flags, UNDER_EE, 0, TERR_BASIC_CONSTRAINTS, 0, 1)
BCT(path_length_exceeded_reported, DEEP, 0, TERR_BASIC_CONSTRAINTS, 0, 1)
BCT(untrusted_root_not_a_bc_error, ORPHAN, 0, 0, -1, -1)
BCT(expired_not_a_bc_error, EXPIRED, 0, 0, -1, -1)
BCT(ignore_basic_constraints_flag_not_honoured, UNDER_EE, CERT_CHAIN_POLICY_IGNORE_INVALID_BASIC_CONSTRAINTS_FLAG, TERR_BASIC_CONSTRAINTS, 0, 1)
BCT(low_flag_bits_not_interpreted, SRV, 0x3FFFFFFF, 0, -1, -1)
BCT(code_signing_leaf_end_entity_flag, CODE, BCEE, 0, -1, -1)
BCT(client_leaf_ca_flag_fails, CLIENT, BCCA, TERR_BASIC_CONSTRAINTS, 0, 0)

TEST(bc_flag_bits_only_for_first_element) {
    PCCERT_CHAIN_CONTEXT c; PRES p;
    NEED_ENV();
    c = cp_chain(C_SRV);
    if (!c) { t_skip("chain build failed"); return; }
    /* intermediate and root are CAs: CA flag must not be applied to them, END_ENTITY flag must not fail them */
    p = cp_run(CERT_CHAIN_POLICY_BASIC_CONSTRAINTS, c, BCEE, NULL);
    CHECK(p.ret && p.err == 0);
    cp_free(c);
}
TEST(bc_para_cbsize_gates_flags) {
    PCCERT_CHAIN_CONTEXT c;
    NEED_ENV();
    c = cp_chain(C_SRV);
    if (!c) { t_skip("chain build failed"); return; }
    CHECK(cp_run_ex(CERT_CHAIN_POLICY_BASIC_CONSTRAINTS, c, 0, BCCA, NULL, sizeof(CERT_CHAIN_POLICY_STATUS), NULL).err == 0);
    CHECK(cp_run_ex(CERT_CHAIN_POLICY_BASIC_CONSTRAINTS, c, 4, BCCA, NULL, sizeof(CERT_CHAIN_POLICY_STATUS), NULL).err == 0);
    CHECK(cp_run_ex(CERT_CHAIN_POLICY_BASIC_CONSTRAINTS, c, 5, BCCA, NULL, sizeof(CERT_CHAIN_POLICY_STATUS), NULL).err == TERR_BASIC_CONSTRAINTS);
    cp_free(c);
}
TEST(bc_synthetic_error_status_any_element) {
    static const int el[] = {0, 1, 2};
    REQUIRE(U(CertVerifyCertificateChainPolicy));
    for (int i = 0; i < 3; i++) {
        SYN s; int n[1] = {3}; PRES p;
        syn_init(&s, 1, n); syn_el(&s, 0, el[i], 0x400, 0);
        p = cp_run(CERT_CHAIN_POLICY_BASIC_CONSTRAINTS, &s.cc, 0, NULL);
        CHECKF(p.ret && p.err == TERR_BASIC_CONSTRAINTS && p.ci == 0 && p.ei == el[i], "element %d: 0x%lx %ld %ld", el[i], p.err, p.ci, p.ei);
    }
}
TEST(bc_synthetic_error_second_chain) {
    SYN s; int n[2] = {2, 2}; PRES p;
    REQUIRE(U(CertVerifyCertificateChainPolicy));
    syn_init(&s, 2, n); syn_el(&s, 1, 1, 0x400, 0);
    p = cp_run(CERT_CHAIN_POLICY_BASIC_CONSTRAINTS, &s.cc, 0, NULL);
    CHECK(p.ret && p.err == TERR_BASIC_CONSTRAINTS && p.ci == 1 && p.ei == 1);
}
TEST(bc_synthetic_only_basic_constraints_bit_matters) {
    SYN s; int n[1] = {3}; PRES p;
    REQUIRE(U(CertVerifyCertificateChainPolicy));
    syn_init(&s, 1, n); syn_ctx(&s, 0xFFFFFFFF & ~0x400u, 0);
    for (int e = 0; e < 3; e++) syn_el(&s, 0, e, 0xFFFFFFFF & ~0x400u, 0);
    p = cp_run(CERT_CHAIN_POLICY_BASIC_CONSTRAINTS, &s.cc, 0, NULL);
    CHECK(p.ret && p.err == 0 && p.ci == -1 && p.ei == -1);
}

/* ---------- NT_AUTH ---------- */
TEST(ntauth_ca_not_in_ntauth_store) {
    PCCERT_CHAIN_CONTEXT c; PRES p;
    NEED_ENV();
    c = cp_chain(C_SRV);
    if (!c) { t_skip("chain build failed"); return; }
    p = cp_run(CERT_CHAIN_POLICY_NT_AUTH, c, 0, NULL);
    CHECK(p.ret); CHECKF(p.err == CERR_UNTRUSTEDCA, "got 0x%lx", p.err); CHECK(p.ci == 0 && p.ei == 1);
    cp_free(c);
}
TEST(ntauth_direct_from_root_checks_root_as_issuer) {
    PCCERT_CHAIN_CONTEXT c; PRES p;
    NEED_ENV();
    c = cp_chain(C_DIRECT);
    if (!c) { t_skip("chain build failed"); return; }
    p = cp_run(CERT_CHAIN_POLICY_NT_AUTH, c, 0, NULL);
    CHECK(p.ret); CHECKF(p.err == CERR_UNTRUSTEDCA, "got 0x%lx", p.err); CHECK(p.ci == 0 && p.ei == 1);
    cp_free(c);
}
TEST(ntauth_single_element_chain) {
    PCCERT_CHAIN_CONTEXT c; PRES p;
    NEED_ENV();
    c = cp_chain(C_ROOT);
    if (!c) { t_skip("chain build failed"); return; }
    EXPECT_EQ(c->rgpChain[0]->cElement, 1);
    p = cp_run(CERT_CHAIN_POLICY_NT_AUTH, c, 0, NULL);
    CHECK(p.ret); CHECKF(p.err == CERR_UNTRUSTEDCA, "got 0x%lx", p.err);
    CHECK(p.ci == -1 && p.ei == -1);
    cp_free(c);
}
TEST(ntauth_base_errors_pass_through) {
    PCCERT_CHAIN_CONTEXT c; PRES p;
    NEED_ENV();
    c = cp_chain_ex(cp_engine_empty(), C_SRV, 0, NULL, NULL, 0);
    if (!c) { t_skip("chain build failed"); return; }
    p = cp_run(CERT_CHAIN_POLICY_NT_AUTH, c, 0, NULL);
    CHECK(p.ret); CHECKF(p.err == CERR_UNTRUSTEDROOT, "got 0x%lx", p.err); CHECK(p.ci == 0 && p.ei == 2);
    cp_free(c);
}
TEST(ntauth_expired_passes_through) {
    PCCERT_CHAIN_CONTEXT c; PRES p;
    NEED_ENV();
    c = cp_chain(C_EXPIRED);
    if (!c) { t_skip("chain build failed"); return; }
    p = cp_run(CERT_CHAIN_POLICY_NT_AUTH, c, 0, NULL);
    CHECK(p.ret); EXPECT_EQ(p.err, CERR_EXPIRED);
    p = cp_run(CERT_CHAIN_POLICY_NT_AUTH, c, CERT_CHAIN_POLICY_IGNORE_NOT_TIME_VALID_FLAG, NULL);
    CHECK(p.ret); EXPECT_EQ(p.err, CERR_UNTRUSTEDCA);
    cp_free(c);
}
TEST(ntauth_basic_constraints_error_passes_through) {
    PCCERT_CHAIN_CONTEXT c; PRES p;
    NEED_ENV();
    c = cp_chain(C_UNDER_EE);
    if (!c) { t_skip("chain build failed"); return; }
    p = cp_run(CERT_CHAIN_POLICY_NT_AUTH, c, 0, NULL);
    CHECK(p.ret); EXPECT_EQ(p.err, TERR_BASIC_CONSTRAINTS);
    cp_free(c);
}
TEST(ntauth_revoked_passes_through) {
    SYN s; int n[1] = {3}; PRES p;
    REQUIRE(U(CertVerifyCertificateChainPolicy));
    syn_init(&s, 1, n); syn_ctx(&s, 0x4, 0); syn_el(&s, 0, 1, 0x4, 0);
    p = cp_run(CERT_CHAIN_POLICY_NT_AUTH, &s.cc, 0, NULL);
    CHECK(p.ret); EXPECT_EQ(p.err, CRYPTERR_REVOKED); CHECK(p.ci == 0 && p.ei == 1);
}
TEST(ntauth_revocation_unknown_is_replaced_by_untrusted_ca) {
    SYN s; int n[1] = {3}; PRES p;
    REQUIRE(U(CertVerifyCertificateChainPolicy));
    syn_init(&s, 1, n); syn_ctx(&s, 0x40, 0);
    syn_el(&s, 0, 0, 0x40, 0); syn_rev(&s, 0, 0, CRYPTERR_NO_REVOCATION_CHECK);
    p = cp_run(CERT_CHAIN_POLICY_NT_AUTH, &s.cc, 0, NULL);
    CHECK(p.ret); EXPECT_EQ(p.err, CERR_UNTRUSTEDCA); CHECK(p.ci == 0 && p.ei == 1);
}
TEST(ntauth_synthetic_clean_chain_untrusted_ca) {
    SYN s; int n[1] = {3}; PRES p;
    REQUIRE(U(CertVerifyCertificateChainPolicy));
    syn_init(&s, 1, n);
    p = cp_run(CERT_CHAIN_POLICY_NT_AUTH, &s.cc, 0, NULL);
    CHECK(p.ret); EXPECT_EQ(p.err, CERR_UNTRUSTEDCA); CHECK(p.ci == 0 && p.ei == 1);
}

/* ---------- MICROSOFT_ROOT ---------- */
TEST(msroot_private_root_rejected) {
    PCCERT_CHAIN_CONTEXT c; PRES p;
    NEED_ENV();
    c = cp_chain(C_SRV);
    if (!c) { t_skip("chain build failed"); return; }
    p = cp_run(CERT_CHAIN_POLICY_MICROSOFT_ROOT, c, 0, NULL);
    CHECK(p.ret); EXPECT_EQ(p.err, CERR_UNTRUSTEDROOT); CHECK(p.ci == 0 && p.ei == 2);
    cp_free(c);
}
TEST(msroot_reports_last_element_index) {
    PCCERT_CHAIN_CONTEXT c; PRES p;
    NEED_ENV();
    c = cp_chain(C_DIRECT);
    if (!c) { t_skip("chain build failed"); return; }
    p = cp_run(CERT_CHAIN_POLICY_MICROSOFT_ROOT, c, 0, NULL);
    CHECK(p.ret); EXPECT_EQ(p.err, CERR_UNTRUSTEDROOT); CHECK(p.ci == 0 && p.ei == 1);
    cp_free(c);
}
TEST(msroot_single_element_chain) {
    PCCERT_CHAIN_CONTEXT c; PRES p;
    NEED_ENV();
    c = cp_chain(C_ROOT);
    if (!c) { t_skip("chain build failed"); return; }
    p = cp_run(CERT_CHAIN_POLICY_MICROSOFT_ROOT, c, 0, NULL);
    CHECK(p.ret); EXPECT_EQ(p.err, CERR_UNTRUSTEDROOT); CHECK(p.ci == 0 && p.ei == 0);
    cp_free(c);
}
TEST(msroot_ignores_other_chain_errors) {
    PCCERT_CHAIN_CONTEXT c; PRES p;
    NEED_ENV();
    c = cp_chain(C_EXPIRED);
    if (!c) { t_skip("chain build failed"); return; }
    p = cp_run(CERT_CHAIN_POLICY_MICROSOFT_ROOT, c, 0, NULL);
    CHECK(p.ret); EXPECT_EQ(p.err, CERR_UNTRUSTEDROOT);      /* only the root key is examined */
    cp_free(c);
}
TEST(msroot_flag_combinations) {
    static const struct { DWORD flags; DWORD want; LONG ci, ei; } t[] = {
        {0x00010000, CERR_UNTRUSTEDROOT, 0, 2},          /* ENABLE_TEST_ROOT */
        {0x00020000, CERR_UNTRUSTEDROOT, 0, 2},          /* CHECK_APPLICATION_ROOT */
        {0x00040000, CERR_UNTRUSTEDROOT, 0, 2},          /* DISABLE_FLIGHT_ROOT */
        {0x00050000, CERR_UNTRUSTEDROOT, 0, 2},
        {0x00060000, CERR_UNTRUSTEDROOT, 0, 2},
        {0x00030000, EINVALIDARG_HR, 0, 0},              /* test root and application root are mutually exclusive */
        {0x00070000, EINVALIDARG_HR, 0, 0}, };
    PCCERT_CHAIN_CONTEXT c;
    NEED_ENV();
    c = cp_chain(C_SRV);
    if (!c) { t_skip("chain build failed"); return; }
    for (unsigned i = 0; i < sizeof t / sizeof t[0]; i++) {
        PRES p = cp_run(CERT_CHAIN_POLICY_MICROSOFT_ROOT, c, t[i].flags, NULL);
        CHECKF(p.ret && p.err == t[i].want && p.ci == t[i].ci && p.ei == t[i].ei, "flags 0x%lx: ret=%d err=0x%lx %ld %ld", t[i].flags, p.ret, p.err, p.ci, p.ei);
    }
    cp_free(c);
}
TEST(msroot_para_cbsize_gates_flags) {
    PCCERT_CHAIN_CONTEXT c;
    NEED_ENV();
    c = cp_chain(C_SRV);
    if (!c) { t_skip("chain build failed"); return; }
    CHECK(cp_run_ex(CERT_CHAIN_POLICY_MICROSOFT_ROOT, c, 4, 0x30000, NULL, sizeof(CERT_CHAIN_POLICY_STATUS), NULL).err == CERR_UNTRUSTEDROOT);
    CHECK(cp_run_ex(CERT_CHAIN_POLICY_MICROSOFT_ROOT, c, 5, 0x30000, NULL, sizeof(CERT_CHAIN_POLICY_STATUS), NULL).err == EINVALIDARG_HR);
    cp_free(c);
}
TEST(msroot_second_chain_not_examined) {
    PCCERT_CHAIN_CONTEXT c; PRES p;
    NEED_ENV();
    c = cp_chain(C_UNTRUSTED);
    if (!c) { t_skip("chain build failed"); return; }
    p = cp_run(CERT_CHAIN_POLICY_MICROSOFT_ROOT, c, 0, NULL);
    CHECK(p.ret); EXPECT_EQ(p.err, CERR_UNTRUSTEDROOT); CHECK(p.ci == 0 && p.ei == 1);
    cp_free(c);
}

/* ---------- THIRD_PARTY_ROOT ---------- */
TEST(thirdparty_private_root_untrusted) {
    PCCERT_CHAIN_CONTEXT c; PRES p;
    NEED_ENV();
    c = cp_chain(C_SRV);
    if (!c) { t_skip("chain build failed"); return; }
    p = cp_run(CERT_CHAIN_POLICY_THIRD_PARTY_ROOT, c, 0, NULL);
    CHECK(p.ret); CHECKF(p.err == CERR_UNTRUSTEDROOT, "got 0x%lx", p.err);
    CHECK(p.ci == -1 && p.ei == -1);                       /* policy does not report an index */
    cp_free(c);
}
TEST(thirdparty_untrusted_chain_same_result) {
    PCCERT_CHAIN_CONTEXT c; PRES p;
    NEED_ENV();
    c = cp_chain_ex(cp_engine_empty(), C_UNTRUSTED, 0, NULL, NULL, 0);
    if (!c) { t_skip("chain build failed"); return; }
    p = cp_run(CERT_CHAIN_POLICY_THIRD_PARTY_ROOT, c, 0, NULL);
    CHECK(p.ret); EXPECT_EQ(p.err, CERR_UNTRUSTEDROOT);
    cp_free(c);
}

/* ---------- EV ---------- */
TEST(ev_non_ev_chain_wrong_usage) {
    PCCERT_CHAIN_CONTEXT c; PRES p;
    NEED_ENV();
    c = cp_chain(C_SRV);
    if (!c) { t_skip("chain build failed"); return; }
    p = cp_run(CERT_CHAIN_POLICY_EV, c, 0, NULL);
    CHECK(p.ret); EXPECT_EQ(p.err, CERR_WRONG_USAGE); CHECK(p.ci == 0 && p.ei == 0);
    cp_free(c);
}
TEST(ev_untrusted_chain_wrong_usage) {
    PCCERT_CHAIN_CONTEXT c; PRES p;
    NEED_ENV();
    c = cp_chain_ex(cp_engine_empty(), C_SRV, 0, NULL, NULL, 0);
    if (!c) { t_skip("chain build failed"); return; }
    p = cp_run(CERT_CHAIN_POLICY_EV, c, 0, NULL);
    CHECK(p.ret); EXPECT_EQ(p.err, CERR_WRONG_USAGE); CHECK(p.ci == 0 && p.ei == 0);
    cp_free(c);
}
TEST(ev_with_extra_para_and_status) {
    PCCERT_CHAIN_CONTEXT c; EV_EXTRA_CERT_CHAIN_POLICY_PARA ep; EV_EXTRA_CERT_CHAIN_POLICY_STATUS es; PRES p;
    NEED_ENV();
    c = cp_chain(C_SRV);
    if (!c) { t_skip("chain build failed"); return; }
    memset(&ep, 0, sizeof ep); ep.cbSize = sizeof ep; ep.dwRootProgramQualifierFlags = 0x80000000u;
    memset(&es, 0xAA, sizeof es); es.cbSize = sizeof es;
    p = cp_run_ex(CERT_CHAIN_POLICY_EV, c, sizeof(CERT_CHAIN_POLICY_PARA), 0, &ep, sizeof(CERT_CHAIN_POLICY_STATUS), &es);
    CHECK(p.ret); EXPECT_EQ(p.err, CERR_WRONG_USAGE);
    EXPECT_EQ(es.dwQualifiers, 0xAAAAAAAA); EXPECT_EQ(es.dwIssuanceUsageIndex, 0xAAAAAAAA);    /* only written on success */
    cp_free(c);
}
TEST(ev_no_chains_is_chaining_error) {
    SYN s; int n[1] = {0}; PRES p;
    REQUIRE(U(CertVerifyCertificateChainPolicy));
    syn_init(&s, 0, n);
    p = cp_run(CERT_CHAIN_POLICY_EV, &s.cc, 0, NULL);
    CHECK(p.ret); EXPECT_EQ(p.err, CERR_CHAINING); CHECK(p.ci == 0 && p.ei == 0);
}
TEST(ev_empty_chain_is_chaining_error) {
    SYN s; int n[1] = {0}; PRES p;
    REQUIRE(U(CertVerifyCertificateChainPolicy));
    syn_init(&s, 1, n);
    p = cp_run(CERT_CHAIN_POLICY_EV, &s.cc, 0, NULL);
    CHECK(p.ret); EXPECT_EQ(p.err, CERR_CHAINING); CHECK(p.ci == 0 && p.ei == 0);
}
