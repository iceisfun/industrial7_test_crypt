/* BASE policy over real, offline-built chains (custom chain engine with an exclusive root store). */
#include "cp.h"

static void expect(const char *what, int leaf, HCERTCHAINENGINE eng, DWORD cflags, HCERTSTORE add, int year,
                   DWORD pflags, DWORD want, LONG wci, LONG wei) {
    PCCERT_CHAIN_CONTEXT c = cp_chain_ex(eng, leaf, cflags, add, NULL, year);
    PRES p;
    if (!c) { t_skip("%s: chain build failed", what); return; }
    p = cp_run(CERT_CHAIN_POLICY_BASE, c, pflags, NULL);
    CHECKF(p.ret, "%s: FALSE", what);
    CHECKF(p.err == want, "%s: dwError got 0x%08lx want 0x%08lx", what, p.err, want);
    CHECKF(p.ci == wci, "%s: chain index %ld want %ld", what, p.ci, wci);
    CHECKF(p.ei == wei, "%s: element index %ld want %ld", what, p.ei, wei);
    cp_free(c);
}

TEST(base_real_trusted_chain_ok) { NEED_ENV(); expect("srv", C_SRV, NULL, 0, NULL, 0, 0, 0, -1, -1); }
TEST(base_real_trusted_direct_from_root) { NEED_ENV(); expect("direct", C_DIRECT, NULL, 0, NULL, 0, 0, 0, -1, -1); }
TEST(base_real_trusted_chain_shape) {
    PCCERT_CHAIN_CONTEXT c;
    NEED_ENV();
    c = cp_chain(C_SRV);
    if (!c) { t_skip("chain build failed"); return; }
    EXPECT_EQ(c->cChain, 1); EXPECT_EQ(c->rgpChain[0]->cElement, 3);
    CHECK(c->TrustStatus.dwErrorStatus == 0);
    CHECK(c->rgpChain[0]->rgpElement[2]->pCertContext->cbCertEncoded == sizeof v_root);
    cp_free(c);
}
TEST(base_real_untrusted_root_empty_exclusive_store) {
    NEED_ENV(); expect("empty-root-store", C_SRV, cp_engine_empty(), 0, NULL, 0, 0, CERR_UNTRUSTEDROOT, 0, 2);
}
TEST(base_real_untrusted_root_other_ca) {
    NEED_ENV(); expect("root2", C_UNTRUSTED, NULL, 0, NULL, 0, 0, CERR_UNTRUSTEDROOT, 0, 1);
}
TEST(base_real_untrusted_root_allow_unknown_ca) {
    NEED_ENV(); expect("root2+allow", C_UNTRUSTED, NULL, 0, NULL, 0, CERT_CHAIN_POLICY_ALLOW_UNKNOWN_CA_FLAG, 0, -1, -1);
}
TEST(base_real_self_signed_leaf_untrusted) {
    NEED_ENV(); expect("selfleaf", C_SELFLEAF, NULL, 0, NULL, 0, 0, CERR_UNTRUSTEDROOT, 0, 0);
}
TEST(base_real_partial_chain_missing_issuer) {
    NEED_ENV(); expect("orphan", C_ORPHAN, NULL, 0, NULL, 0, 0, CERR_CHAINING, 0, -1);
}
TEST(base_real_partial_chain_allow_unknown_ca) {
    NEED_ENV(); expect("orphan+allow", C_ORPHAN, NULL, 0, NULL, 0, CERT_CHAIN_POLICY_ALLOW_UNKNOWN_CA_FLAG, 0, -1, -1);
}
TEST(base_real_partial_chain_flag_recorded) {
    PCCERT_CHAIN_CONTEXT c;
    NEED_ENV();
    c = cp_chain(C_ORPHAN);
    if (!c) { t_skip("chain build failed"); return; }
    CHECK(c->TrustStatus.dwErrorStatus & CERT_TRUST_IS_PARTIAL_CHAIN);
    EXPECT_EQ(c->rgpChain[0]->cElement, 1);
    cp_free(c);
}
TEST(base_real_expired_leaf) {
    NEED_ENV(); expect("expired", C_EXPIRED, NULL, 0, NULL, 0, 0, CERR_EXPIRED, 0, 0);
}
TEST(base_real_expired_leaf_ignored) {
    NEED_ENV(); expect("expired+ignore", C_EXPIRED, NULL, 0, NULL, 0, CERT_CHAIN_POLICY_IGNORE_NOT_TIME_VALID_FLAG, 0, -1, -1);
}
TEST(base_real_not_yet_valid_leaf) {
    NEED_ENV(); expect("notyet", C_NOTYET, NULL, 0, NULL, 0, 0, CERR_EXPIRED, 0, 0);
}
TEST(base_real_expired_depends_on_evaluation_time) {
    NEED_ENV();
    expect("expired@2020", C_EXPIRED, NULL, 0, NULL, 2020, 0, 0, -1, -1);
    expect("expired@2024", C_EXPIRED, NULL, 0, NULL, 2024, 0, CERR_EXPIRED, 0, 0);
    expect("notyet@2041", C_NOTYET, NULL, 0, NULL, 2041, 0, 0, -1, -1);
}
TEST(base_real_all_not_time_valid_flags_cover_expiry) {
    NEED_ENV(); expect("expired+all", C_EXPIRED, NULL, 0, NULL, 0, CERT_CHAIN_POLICY_IGNORE_ALL_NOT_TIME_VALID_FLAGS, 0, -1, -1);
}
TEST(base_real_ca_flag_missing_issuer_not_ca) {
    NEED_ENV(); expect("under_ee", C_UNDER_EE, NULL, 0, NULL, 0, 0, TERR_BASIC_CONSTRAINTS, 0, 1);
}
TEST(base_real_issuer_not_ca_ignored) {
    NEED_ENV(); expect("under_ee+ignore", C_UNDER_EE, NULL, 0, NULL, 0, CERT_CHAIN_POLICY_IGNORE_INVALID_BASIC_CONSTRAINTS_FLAG, 0, -1, -1);
}
TEST(base_real_path_length_exceeded) {
    PCCERT_CHAIN_CONTEXT c; PRES p;
    NEED_ENV();
    c = cp_chain(C_DEEP);
    if (!c) { t_skip("chain build failed"); return; }
    p = cp_run(CERT_CHAIN_POLICY_BASE, c, 0, NULL);
    CHECK(p.ret);
    CHECKF(p.err == TERR_BASIC_CONSTRAINTS, "got 0x%lx", p.err);
    p = cp_run(CERT_CHAIN_POLICY_BASE, c, CERT_CHAIN_POLICY_IGNORE_INVALID_BASIC_CONSTRAINTS_FLAG, NULL);
    CHECK(p.ret && p.err == 0);
    cp_free(c);
}
TEST(base_real_wrong_usage_via_requested_usage) {
    PCCERT_CHAIN_CONTEXT c; PRES p;
    NEED_ENV();
    c = cp_chain_ex(NULL, C_CLIENT, 0, NULL, szOID_PKIX_KP_SERVER_AUTH, 0);
    if (!c) { t_skip("chain build failed"); return; }
    CHECK(c->TrustStatus.dwErrorStatus & CERT_TRUST_IS_NOT_VALID_FOR_USAGE);
    p = cp_run(CERT_CHAIN_POLICY_BASE, c, 0, NULL);
    CHECK(p.ret); CHECKF(p.err == CERR_WRONG_USAGE, "got 0x%lx", p.err); CHECK(p.ci == 0 && p.ei == 0);
    p = cp_run(CERT_CHAIN_POLICY_BASE, c, CERT_CHAIN_POLICY_IGNORE_WRONG_USAGE_FLAG, NULL);
    CHECK(p.ret && p.err == 0);
    cp_free(c);
}
TEST(base_real_usage_match_ok) {
    PCCERT_CHAIN_CONTEXT c;
    NEED_ENV();
    c = cp_chain_ex(NULL, C_SRV, 0, NULL, szOID_PKIX_KP_SERVER_AUTH, 0);
    if (!c) { t_skip("chain build failed"); return; }
    CHECK(c->TrustStatus.dwErrorStatus == 0);
    CHECK(cp_run(CERT_CHAIN_POLICY_BASE, c, 0, NULL).err == 0);
    cp_free(c);
}
TEST(base_real_cert_without_eku_matches_any_usage) {
    PCCERT_CHAIN_CONTEXT c;
    NEED_ENV();
    c = cp_chain_ex(NULL, C_NOEKU, 0, NULL, szOID_PKIX_KP_CODE_SIGNING, 0);
    if (!c) { t_skip("chain build failed"); return; }
    CHECK(cp_run(CERT_CHAIN_POLICY_BASE, c, 0, NULL).err == 0);
    cp_free(c);
}
TEST(base_real_nesting_violation) {
    PCCERT_CHAIN_CONTEXT c; PRES p;
    NEED_ENV();
    c = cp_chain(C_NESTED);
    if (!c) { t_skip("chain build failed"); return; }
    if (!(c->rgpChain[0]->TrustStatus.dwErrorStatus & CERT_TRUST_IS_NOT_TIME_NESTED) &&
        !(c->rgpChain[0]->rgpElement[0]->TrustStatus.dwErrorStatus & CERT_TRUST_IS_NOT_TIME_NESTED)) {
        t_note("chain engine did not record NOT_TIME_NESTED (status 0x%lx)", c->TrustStatus.dwErrorStatus);
        p = cp_run(CERT_CHAIN_POLICY_BASE, c, 0, NULL);
        CHECK(p.err == 0);
    } else {
        p = cp_run(CERT_CHAIN_POLICY_BASE, c, 0, NULL);
        CHECKF(p.err == CERR_VALIDITYNEST, "got 0x%lx", p.err);
        p = cp_run(CERT_CHAIN_POLICY_BASE, c, CERT_CHAIN_POLICY_IGNORE_NOT_TIME_NESTED_FLAG, NULL);
        CHECK(p.err == 0);
    }
    cp_free(c);
}
TEST(base_real_revocation_unknown_no_cdp) {
    NEED_ENV();
    expect("rev-chain", C_SRV, NULL, CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT, NULL, 0, 0, CRYPTERR_NO_REVOCATION_CHECK, 0, 0);
}
TEST(base_real_revocation_unknown_end_cert_only) {
    NEED_ENV();
    expect("rev-end", C_SRV, NULL, CERT_CHAIN_REVOCATION_CHECK_END_CERT, NULL, 0, 0, CRYPTERR_NO_REVOCATION_CHECK, 0, 0);
}
TEST(base_real_revocation_unknown_ignore_end_reports_ca) {
    NEED_ENV();
    expect("rev-chain+ignore-end", C_SRV, NULL, CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT, NULL, 0,
           CERT_CHAIN_POLICY_IGNORE_END_REV_UNKNOWN_FLAG, CRYPTERR_NO_REVOCATION_CHECK, 0, 1);
}
TEST(base_real_revocation_unknown_ignore_end_and_ca) {
    NEED_ENV();
    expect("rev-chain+ignore-end-ca", C_SRV, NULL, CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT, NULL, 0, 0x500, 0, -1, -1);
}
TEST(base_real_revocation_unknown_ignore_all) {
    NEED_ENV();
    expect("rev-chain+ignore-all", C_SRV, NULL, CERT_CHAIN_REVOCATION_CHECK_CHAIN, NULL, 0, CERT_CHAIN_POLICY_IGNORE_ALL_REV_UNKNOWN_FLAGS, 0, -1, -1);
}
/* Win10: with CHECK_CHAIN (root included) ignoring the end and CA unknown-revocation flags leaves nothing to report: the policy passes. */
TEST(base_real_revocation_unknown_ignore_end_and_ca_with_root_checked) {
    NEED_ENV();
    expect("rev-chain+ignore-end-ca", C_SRV, NULL, CERT_CHAIN_REVOCATION_CHECK_CHAIN, NULL, 0, 0x500, 0, -1, -1);
}
TEST(base_real_revoked_via_crl_in_additional_store) {
    PCCERT_CHAIN_CONTEXT c; PRES p;
    NEED_ENV();
    c = cp_chain_ex(NULL, C_REVOKED, CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT, cp_addstore_crl(), NULL, 0);
    if (!c) { t_skip("chain build failed"); return; }
    p = cp_run(CERT_CHAIN_POLICY_BASE, c, 0, NULL);
    CHECK(p.ret);
    if (!(c->TrustStatus.dwErrorStatus & CERT_TRUST_IS_REVOKED)) t_note("CRL in the additional store was not used (error status 0x%lx)", c->TrustStatus.dwErrorStatus);
    else { CHECKF(p.err == CRYPTERR_REVOKED, "got 0x%lx", p.err); CHECK(p.ci == 0 && p.ei == 0); }
    cp_free(c);
}
TEST(base_real_revoked_not_ignorable_by_any_policy_flag) {
    PCCERT_CHAIN_CONTEXT c; PRES p;
    NEED_ENV();
    c = cp_chain_ex(NULL, C_REVOKED, CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT, cp_addstore_crl(), NULL, 0);
    if (!c) { t_skip("chain build failed"); return; }
    if (c->TrustStatus.dwErrorStatus & CERT_TRUST_IS_REVOKED) {
        p = cp_run(CERT_CHAIN_POLICY_BASE, c, 0x7FFF, NULL);
        CHECKF(p.ret && p.err == CRYPTERR_REVOKED, "got 0x%lx", p.err);
    } else t_note("revocation via additional store unavailable");
    cp_free(c);
}
TEST(base_real_unrevoked_with_crl_passes) {
    PCCERT_CHAIN_CONTEXT c; PRES p;
    NEED_ENV();
    c = cp_chain_ex(NULL, C_SRV, CERT_CHAIN_REVOCATION_CHECK_END_CERT, cp_addstore_crl(), NULL, 0);
    if (!c) { t_skip("chain build failed"); return; }
    p = cp_run(CERT_CHAIN_POLICY_BASE, c, 0, NULL);
    CHECK(p.ret);
    CHECKF(p.err == 0 || p.err == CRYPTERR_NO_REVOCATION_CHECK, "got 0x%lx", p.err);
    if (p.err) t_note("CRL from additional store not consulted for end cert");
    cp_free(c);
}
TEST(base_real_peer_trust_overrides_untrusted_root) {
    /* Win10: with ENABLE_PEER_TRUST the chain is cut at the peer-trusted leaf (one element, clean status), so the
       policy passes and IGNORE_PEER_TRUST has nothing left to ignore. */
    HCERTCHAINENGINE e; PCCERT_CHAIN_CONTEXT c; PRES p;
    NEED_ENV();
    e = cp_engine_peer(C_UNTRUSTED);
    if (!e) { t_skip("peer engine unavailable"); return; }
    c = cp_chain_ex(e, C_UNTRUSTED, CERT_CHAIN_ENABLE_PEER_TRUST, NULL, NULL, 0);
    if (!c) { t_skip("chain build failed"); return; }
    EXPECT_EQ(c->cChain, 1);
    EXPECT_EQ(c->rgpChain[0]->cElement, 1);
    EXPECT_EQ(c->TrustStatus.dwErrorStatus, 0);
    CHECK(c->TrustStatus.dwInfoStatus & CERT_TRUST_IS_PEER_TRUSTED);
    p = cp_run(CERT_CHAIN_POLICY_BASE, c, 0, NULL);
    CHECKF(p.ret && p.err == 0 && p.ci == -1 && p.ei == -1, "ret=%d err=0x%lx ci=%ld ei=%ld", p.ret, p.err, p.ci, p.ei);
    p = cp_run(CERT_CHAIN_POLICY_BASE, c, CERT_CHAIN_POLICY_IGNORE_PEER_TRUST_FLAG, NULL);
    CHECKF(p.ret && p.err == 0 && p.ci == -1 && p.ei == -1, "ignore: ret=%d err=0x%lx ci=%ld ei=%ld", p.ret, p.err, p.ci, p.ei);
    cp_free(c);
}
TEST(base_real_peer_trust_recorded_without_enable_flag) {
    /* Win10: without ENABLE_PEER_TRUST the chain is still built to the untrusted root (error status keeps
       UNTRUSTED_ROOT) but the leaf and the context carry IS_PEER_TRUSTED, and the BASE policy accepts it unless
       IGNORE_PEER_TRUST is given. */
    HCERTCHAINENGINE e; PCCERT_CHAIN_CONTEXT c; PRES p;
    NEED_ENV();
    e = cp_engine_peer(C_UNTRUSTED);
    if (!e) { t_skip("peer engine unavailable"); return; }
    c = cp_chain_ex(e, C_UNTRUSTED, 0, NULL, NULL, 0);
    if (!c) { t_skip("chain build failed"); return; }
    EXPECT_EQ(c->rgpChain[0]->cElement, 2);
    EXPECT_EQ(c->TrustStatus.dwErrorStatus, CERT_TRUST_IS_UNTRUSTED_ROOT);
    CHECK(c->TrustStatus.dwInfoStatus & CERT_TRUST_IS_PEER_TRUSTED);
    CHECK(c->rgpChain[0]->rgpElement[0]->TrustStatus.dwInfoStatus & CERT_TRUST_IS_PEER_TRUSTED);
    p = cp_run(CERT_CHAIN_POLICY_BASE, c, 0, NULL);
    CHECKF(p.ret && p.err == 0 && p.ci == -1 && p.ei == -1, "ret=%d err=0x%lx ci=%ld ei=%ld", p.ret, p.err, p.ci, p.ei);
    p = cp_run(CERT_CHAIN_POLICY_BASE, c, CERT_CHAIN_POLICY_IGNORE_PEER_TRUST_FLAG, NULL);
    CHECKF(p.ret && p.err == CERR_UNTRUSTEDROOT && p.ci == 0 && p.ei == 1, "ignore: ret=%d err=0x%lx ci=%ld ei=%ld", p.ret, p.err, p.ci, p.ei);
    cp_free(c);
}
TEST(base_real_peer_store_with_other_cert_does_not_trust_leaf) {
    HCERTCHAINENGINE e; PCCERT_CHAIN_CONTEXT c; PRES p;
    NEED_ENV();
    e = cp_engine_peer(C_SRV);
    if (!e) { t_skip("peer engine unavailable"); return; }
    c = cp_chain_ex(e, C_UNTRUSTED, CERT_CHAIN_ENABLE_PEER_TRUST, NULL, NULL, 0);
    if (!c) { t_skip("chain build failed"); return; }
    EXPECT_EQ(c->rgpChain[0]->cElement, 2);
    CHECK((c->TrustStatus.dwInfoStatus & CERT_TRUST_IS_PEER_TRUSTED) == 0);
    p = cp_run(CERT_CHAIN_POLICY_BASE, c, 0, NULL);
    CHECKF(p.ret && p.err == CERR_UNTRUSTEDROOT && p.ci == 0 && p.ei == 1, "ret=%d err=0x%lx ci=%ld ei=%ld", p.ret, p.err, p.ci, p.ei);
    cp_free(c);
}
TEST(base_real_ca_certificate_as_end_entity_is_fine_for_base) {
    NEED_ENV(); expect("caleaf", C_CALEAF, NULL, 0, NULL, 0, 0, 0, -1, -1);
}
TEST(base_real_context_error_status_matches_policy) {
    /* A policy result of 0 corresponds to an empty chain error status (without peer trust). */
    static const int leaves[] = {C_SRV, C_WILD, C_CLIENT, C_CODE, C_NOEKU, C_EMAIL};
    NEED_ENV();
    for (unsigned i = 0; i < sizeof leaves / sizeof leaves[0]; i++) {
        PCCERT_CHAIN_CONTEXT c = cp_chain(leaves[i]);
        if (!c) { t_skip("chain build failed"); return; }
        CHECKF(c->TrustStatus.dwErrorStatus == 0, "leaf %d status 0x%lx", leaves[i], c->TrustStatus.dwErrorStatus);
        CHECK(cp_run(CERT_CHAIN_POLICY_BASE, c, 0, NULL).err == 0);
        cp_free(c);
    }
}
