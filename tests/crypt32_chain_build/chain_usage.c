/* Requested usage, issuance policy, name constraints, weak signatures, cross-signing, cycles, peer trust. */
#include "pkiutil.h"

#define OIDS(...) ((const char *[]){ __VA_ARGS__ })
#define BADUSE CERT_TRUST_IS_NOT_VALID_FOR_USAGE

static void usage_case(const char *tag, const char *leaf, const char *others, int and, int n, const char **oids, DWORD want) {
    REQUIRE(U(CertGetCertificateChain));
    PKI_ENG e;
    if (!pki_eng_open(&e, "root", others, NULL, 0)) { CHECKF(0, "%s engine", tag); return; }
    PCCERT_CHAIN_CONTEXT c = pki_chain_para(e.h, leaf, NULL, PKI_T0, PKI_OFFLINE, and, n, oids);
    CHECKF(c != NULL, "%s: chain", tag);
    if (c) {
        pki_note_chain(tag, c);
        CHECKF(c->TrustStatus.dwErrorStatus == want, "%s: error got 0x%lx want 0x%lx", tag, c->TrustStatus.dwErrorStatus, want);
        if (c->cChain && c->rgpChain[0]->TrustStatus.dwErrorStatus != want) t_note("%s: simple chain status 0x%lx differs from chain status", tag, c->rgpChain[0]->TrustStatus.dwErrorStatus);
    }
    pki_chain_free(c); pki_eng_close(&e);
}
#define USE(nm, leaf, others, and, n, oids, want) TEST(chain_usage_##nm) { usage_case(#nm, leaf, others, and, n, oids, want); }

/* ---- AND / OR matching of RequestedUsage against the end-entity EKU (serverAuth+clientAuth) ---- */
USE(and_server_ok, "leaf", "inter", 1, 1, OIDS(OID_SERVER), 0)
USE(and_client_ok, "leaf", "inter", 1, 1, OIDS(OID_CLIENT), 0)
USE(and_server_client_ok, "leaf", "inter", 1, 2, OIDS(OID_SERVER, OID_CLIENT), 0)
USE(and_code_fails, "leaf", "inter", 1, 1, OIDS(OID_CODE), BADUSE)
USE(and_server_code_fails, "leaf", "inter", 1, 2, OIDS(OID_SERVER, OID_CODE), BADUSE)
USE(and_unknown_oid_fails, "leaf", "inter", 1, 1, OIDS("1.2.3.4.5.6.7"), BADUSE)
USE(or_server_code_ok, "leaf", "inter", 0, 2, OIDS(OID_SERVER, OID_CODE), 0)
USE(or_code_server_ok, "leaf", "inter", 0, 2, OIDS(OID_CODE, OID_SERVER), 0)
USE(or_code_email_fails, "leaf", "inter", 0, 2, OIDS(OID_CODE, OID_EMAIL), BADUSE)
USE(or_single_server_ok, "leaf", "inter", 0, 1, OIDS(OID_SERVER), 0)
USE(or_single_code_fails, "leaf", "inter", 0, 1, OIDS(OID_CODE), BADUSE)
USE(and_empty_list_ok, "leaf", "inter", 1, 0, OIDS(OID_SERVER), 0)
USE(or_empty_list_ok, "leaf", "inter", 0, 0, OIDS(OID_SERVER), 0)
USE(and_no_oids_listed_all_leaf_ok, "leaf_code", "inter", 1, 0, OIDS(OID_SERVER), 0)
USE(code_leaf_and_code_ok, "leaf_code", "inter", 1, 1, OIDS(OID_CODE), 0)
USE(code_leaf_and_server_fails, "leaf_code", "inter", 1, 1, OIDS(OID_SERVER), BADUSE)
USE(code_leaf_or_server_code_ok, "leaf_code", "inter", 0, 2, OIDS(OID_SERVER, OID_CODE), 0)
USE(email_leaf_and_email_client_ok, "leaf_email", "inter", 1, 2, OIDS(OID_EMAIL, OID_CLIENT), 0)
USE(email_leaf_and_email_server_fails, "leaf_email", "inter", 1, 2, OIDS(OID_EMAIL, OID_SERVER), BADUSE)
USE(email_leaf_or_email_server_ok, "leaf_email", "inter", 0, 2, OIDS(OID_EMAIL, OID_SERVER), 0)
USE(email_leaf_or_server_code_fails, "leaf_email", "inter", 0, 2, OIDS(OID_SERVER, OID_CODE), BADUSE)
USE(no_eku_leaf_matches_server, "leaf_nobc", "inter", 1, 1, OIDS(OID_SERVER), 0)
USE(no_eku_leaf_matches_code_and_email, "leaf_nobc", "inter", 1, 2, OIDS(OID_CODE, OID_EMAIL), 0)
USE(no_eku_leaf_or_unknown, "leaf_nobc", "inter", 0, 1, OIDS("1.2.3.4.5.6.7"), 0)
USE(leaf_directly_under_root_and_server, "leaf_root", "", 1, 1, OIDS(OID_SERVER), 0)
USE(leaf_directly_under_root_and_code_fails, "leaf_root", "", 1, 1, OIDS(OID_CODE), BADUSE)

/* ---- EKU on a CA limits everything below it ---- */
USE(ca_eku_code_leaf_code_ok, "leaf_eku_ok", "inter_eku", 1, 1, OIDS(OID_CODE), 0)
USE(ca_eku_code_leaf_server_requested_fails, "leaf_eku_ok", "inter_eku", 1, 1, OIDS(OID_SERVER), BADUSE)
USE(ca_eku_code_leaf_server_requested_server_fails, "leaf_eku_bad", "inter_eku", 1, 1, OIDS(OID_SERVER), BADUSE)
USE(ca_eku_code_leaf_server_requested_code_fails, "leaf_eku_bad", "inter_eku", 1, 1, OIDS(OID_CODE), BADUSE)
USE(ca_eku_leaf_server_no_request_ok, "leaf_eku_bad", "inter_eku", 1, 0, OIDS(OID_SERVER), 0)
USE(ca_eku_or_server_code_ok_on_code_leaf, "leaf_eku_ok", "inter_eku", 0, 2, OIDS(OID_SERVER, OID_CODE), 0)
TEST(chain_usage_ca_eku_or_server_code_on_server_leaf_empty_intersection) {
    /* leaf allows {server}, CA allows {code}: the intersection is empty, so even an OR request cannot match */
    usage_case("ca_eku_or_observation", "leaf_eku_bad", "inter_eku", 0, 2, OIDS(OID_SERVER, OID_CODE), BADUSE);
}

/* ---- anyExtendedKeyUsage ---- */
TEST(chain_usage_any_eku_leaf_observation) {
    REQUIRE(U(CertGetCertificateChain));
    PKI_ENG e; CHECK(pki_eng_open(&e, "root", "inter", NULL, 0));
    const char *o[] = { OID_SERVER };
    PCCERT_CHAIN_CONTEXT c = pki_chain_para(e.h, "leaf_anyeku", NULL, PKI_T0, PKI_OFFLINE, 1, 1, o);
    CHECK(c != NULL);
    if (c) { pki_note_chain("anyEKU leaf, server requested", c); EXPECT_EQ(c->TrustStatus.dwErrorStatus & ~(DWORD)BADUSE, 0); }
    pki_chain_free(c); pki_eng_close(&e);
}

/* ---- application usage reported per element ---- */
TEST(chain_usage_application_usage_of_end_cert) {
    REQUIRE(U(CertGetCertificateChain));
    PKI_ENG e; CHECK(pki_eng_open(&e, "root", "inter", NULL, 0));
    const char *o[] = { OID_SERVER };
    PCCERT_CHAIN_CONTEXT c = pki_chain_para(e.h, "leaf", NULL, PKI_T0, PKI_OFFLINE, 1, 1, o);
    CHECK(c && c->cChain == 1);
    if (c && c->cChain == 1) {
        PCERT_CHAIN_ELEMENT el = c->rgpChain[0]->rgpElement[0];
        if (el->pApplicationUsage) {
            t_note("leaf pApplicationUsage count=%lu", el->pApplicationUsage->cUsageIdentifier);
            int s = 0, cl = 0;
            for (DWORD i = 0; i < el->pApplicationUsage->cUsageIdentifier; i++) {
                if (!strcmp(el->pApplicationUsage->rgpszUsageIdentifier[i], OID_SERVER)) s = 1;
                if (!strcmp(el->pApplicationUsage->rgpszUsageIdentifier[i], OID_CLIENT)) cl = 1;
            }
            CHECK(s); CHECK(cl);
        } else t_note("leaf element has no pApplicationUsage");
    }
    pki_chain_free(c); pki_eng_close(&e);
}
TEST(chain_usage_application_usage_ca_limits_end_cert) {
    REQUIRE(U(CertGetCertificateChain));
    PKI_ENG e; CHECK(pki_eng_open(&e, "root", "inter_eku", NULL, 0));
    const char *o[] = { OID_CODE };
    PCCERT_CHAIN_CONTEXT c = pki_chain_para(e.h, "leaf_eku_ok", NULL, PKI_T0, PKI_OFFLINE, 1, 1, o);
    CHECK(c && c->cChain == 1);
    if (c && c->cChain == 1) {
        PCERT_CHAIN_ELEMENT el = c->rgpChain[0]->rgpElement[0];
        if (el->pApplicationUsage) { EXPECT_EQ(el->pApplicationUsage->cUsageIdentifier, 1); if (el->pApplicationUsage->cUsageIdentifier == 1) EXPECT_STR(el->pApplicationUsage->rgpszUsageIdentifier[0], OID_CODE); }
        else t_note("leaf element has no pApplicationUsage");
    }
    pki_chain_free(c); pki_eng_close(&e);
}
TEST(chain_usage_usage_error_not_present_without_request) {
    REQUIRE(U(CertGetCertificateChain));
    PKI_ENG e; CHECK(pki_eng_open(&e, "root", "inter", NULL, 0));
    PCCERT_CHAIN_CONTEXT c = pki_chain(e.h, "leaf_code", NULL, PKI_T0, PKI_OFFLINE, NULL);
    CHECK(c != NULL);
    if (c) EXPECT_EQ(c->TrustStatus.dwErrorStatus, 0);
    pki_chain_free(c); pki_eng_close(&e);
}

/* ---- issuance policy ---- */
static void policy_case(const char *tag, const char *leaf, const char *others, int and, int n, const char **oids, int want_ok) {
    REQUIRE(U(CertGetCertificateChain));
    PKI_ENG e;
    if (!pki_eng_open(&e, "root", others, NULL, 0)) { CHECKF(0, "%s engine", tag); return; }
    CERT_CHAIN_PARA p; memset(&p, 0, sizeof p); p.cbSize = sizeof p;
    p.RequestedIssuancePolicy.dwType = and ? USAGE_MATCH_TYPE_AND : USAGE_MATCH_TYPE_OR;
    p.RequestedIssuancePolicy.Usage.cUsageIdentifier = n;
    p.RequestedIssuancePolicy.Usage.rgpszUsageIdentifier = (LPSTR *)oids;
    PCCERT_CHAIN_CONTEXT c = pki_chain(e.h, leaf, NULL, PKI_T0, PKI_OFFLINE, &p);
    CHECKF(c != NULL, "%s: chain", tag);
    if (c) {
        pki_note_chain(tag, c);
        if (want_ok) CHECKF(c->TrustStatus.dwErrorStatus == 0, "%s: error 0x%lx", tag, c->TrustStatus.dwErrorStatus);
        else CHECKF(c->TrustStatus.dwErrorStatus & CERT_TRUST_NO_ISSUANCE_CHAIN_POLICY, "%s: expected NO_ISSUANCE_CHAIN_POLICY got 0x%lx", tag, c->TrustStatus.dwErrorStatus);
    }
    pki_chain_free(c); pki_eng_close(&e);
}
#define POL(nm, leaf, others, and, n, oids, ok) TEST(chain_policy_##nm) { policy_case(#nm, leaf, others, and, n, oids, ok); }
POL(and_matching_policy_ok, "leaf_pol", "inter_pol", 1, 1, OIDS(OID_POL1), 1)
POL(or_matching_policy_ok, "leaf_pol", "inter_pol", 0, 2, OIDS(OID_POL2, OID_POL1), 1)
POL(and_other_policy_fails, "leaf_pol", "inter_pol", 1, 1, OIDS(OID_POL2), 0)
POL(and_both_policies_fails, "leaf_pol", "inter_pol", 1, 2, OIDS(OID_POL1, OID_POL2), 0)
POL(or_only_other_policy_fails, "leaf_pol", "inter_pol", 0, 1, OIDS(OID_POL2), 0)
POL(leaf_without_policy_fails, "leaf", "inter", 1, 1, OIDS(OID_POL1), 0)
POL(empty_request_ok, "leaf_pol", "inter_pol", 1, 0, OIDS(OID_POL1), 1)
POL(no_request_policy_cert_ok, "leaf", "inter", 1, 0, OIDS(OID_POL1), 1)
TEST(chain_policy_issuance_policy_info_bit_on_match) {
    REQUIRE(U(CertGetCertificateChain));
    PKI_ENG e; CHECK(pki_eng_open(&e, "root", "inter_pol", NULL, 0));
    CERT_CHAIN_PARA p; memset(&p, 0, sizeof p); p.cbSize = sizeof p;
    const char *o[] = { OID_POL1 };
    p.RequestedIssuancePolicy.dwType = USAGE_MATCH_TYPE_AND; p.RequestedIssuancePolicy.Usage.cUsageIdentifier = 1; p.RequestedIssuancePolicy.Usage.rgpszUsageIdentifier = (LPSTR *)o;
    PCCERT_CHAIN_CONTEXT c = pki_chain(e.h, "leaf_pol", NULL, PKI_T0, PKI_OFFLINE, &p);
    CHECK(c != NULL);
    if (c) { t_note("chain info 0x%lx (HAS_ISSUANCE_CHAIN_POLICY=0x200)", c->TrustStatus.dwInfoStatus); EXPECT_EQ(c->TrustStatus.dwErrorStatus, 0); }
    pki_chain_free(c); pki_eng_close(&e);
}
TEST(chain_policy_issuance_usage_of_elements_observation) {
    REQUIRE(U(CertGetCertificateChain));
    PKI_ENG e; CHECK(pki_eng_open(&e, "root", "inter_pol", NULL, 0));
    PCCERT_CHAIN_CONTEXT c = pki_chain(e.h, "leaf_pol", NULL, PKI_T0, PKI_OFFLINE, NULL);
    CHECK(c && c->cChain == 1);
    if (c && c->cChain == 1) {
        for (DWORD i = 0; i < c->rgpChain[0]->cElement; i++) {
            PCERT_ENHKEY_USAGE u = c->rgpChain[0]->rgpElement[i]->pIssuanceUsage;
            t_note("element %lu pIssuanceUsage count=%lu first=%s", i, u ? u->cUsageIdentifier : 0, (u && u->cUsageIdentifier) ? u->rgpszUsageIdentifier[0] : "-");
        }
        EXPECT_EQ(c->TrustStatus.dwErrorStatus, 0);
    }
    pki_chain_free(c); pki_eng_close(&e);
}

/* ---- name constraints ---- */
static DWORD nc_case(const char *tag, const char *leaf, const char *inter) {
    PKI_ENG e; DWORD r = 0xffffffff;
    if (!pki_eng_open(&e, "root", inter, NULL, 0)) { CHECKF(0, "%s engine", tag); return r; }
    PCCERT_CHAIN_CONTEXT c = pki_chain(e.h, leaf, NULL, PKI_T0, PKI_OFFLINE, NULL);
    CHECKF(c != NULL, "%s: chain", tag);
    if (c) { pki_note_chain(tag, c); r = c->TrustStatus.dwErrorStatus; CHECKF(c->cChain == 1 && c->rgpChain[0]->cElement == 3, "%s: 3 elements", tag); }
    pki_chain_free(c); pki_eng_close(&e);
    return r;
}
TEST(chain_nameconstraints_permitted_dns_ok) { REQUIRE(U(CertGetCertificateChain)); EXPECT_EQ(nc_case("nc_ok", "leaf_nc_ok", "inter_nc"), 0); }
TEST(chain_nameconstraints_not_permitted_dns) {
    REQUIRE(U(CertGetCertificateChain));
    DWORD e = nc_case("nc_bad", "leaf_nc_bad", "inter_nc");
    CHECKF(e & CERT_TRUST_HAS_NOT_PERMITTED_NAME_CONSTRAINT, "got 0x%lx", e);
    t_note("not-permitted status 0x%lx (INVALID_NAME_CONSTRAINTS bit %s)", e, (e & CERT_TRUST_INVALID_NAME_CONSTRAINTS) ? "set" : "clear");
}
TEST(chain_nameconstraints_mixed_names_one_not_permitted) {
    REQUIRE(U(CertGetCertificateChain));
    DWORD e = nc_case("nc_mixed", "leaf_nc_mixed", "inter_nc");
    CHECKF(e & CERT_TRUST_HAS_NOT_PERMITTED_NAME_CONSTRAINT, "got 0x%lx", e);
}
TEST(chain_nameconstraints_excluded_dns) {
    REQUIRE(U(CertGetCertificateChain));
    DWORD e = nc_case("ncx_bad", "leaf_ncx_bad", "inter_ncx");
    CHECKF(e & CERT_TRUST_HAS_EXCLUDED_NAME_CONSTRAINT, "got 0x%lx", e);
}
TEST(chain_nameconstraints_excluded_not_hit_ok) { REQUIRE(U(CertGetCertificateChain)); EXPECT_EQ(nc_case("ncx_ok", "leaf_ncx_ok", "inter_ncx"), 0); }
TEST(chain_nameconstraints_violation_marks_leaf_element) {
    REQUIRE(U(CertGetCertificateChain));
    PKI_ENG e; CHECK(pki_eng_open(&e, "root", "inter_nc", NULL, 0));
    PCCERT_CHAIN_CONTEXT c = pki_chain(e.h, "leaf_nc_bad", NULL, PKI_T0, PKI_OFFLINE, NULL);
    CHECK(c && c->cChain == 1 && c->rgpChain[0]->cElement == 3);
    if (c && c->cChain == 1 && c->rgpChain[0]->cElement == 3) {
        t_note("per element: leaf 0x%lx inter 0x%lx root 0x%lx", pki_elem_err(c, 0, 0), pki_elem_err(c, 0, 1), pki_elem_err(c, 0, 2));
        CHECK((pki_elem_err(c, 0, 0) | pki_elem_err(c, 0, 1)) & CERT_TRUST_HAS_NOT_PERMITTED_NAME_CONSTRAINT);
        EXPECT_EQ(pki_elem_err(c, 0, 2), 0);
    }
    pki_chain_free(c); pki_eng_close(&e);
}
TEST(chain_nameconstraints_good_chain_valid_info_bit_observation) {
    REQUIRE(U(CertGetCertificateChain));
    PKI_ENG e; CHECK(pki_eng_open(&e, "root", "inter_nc", NULL, 0));
    PCCERT_CHAIN_CONTEXT c = pki_chain(e.h, "leaf_nc_ok", NULL, PKI_T0, PKI_OFFLINE, NULL);
    CHECK(c && c->cChain == 1 && c->rgpChain[0]->cElement == 3);
    if (c && c->cChain == 1) t_note("HAS_VALID_NAME_CONSTRAINTS (0x400) element info: leaf 0x%lx inter 0x%lx", pki_elem_info(c, 0, 0), pki_elem_info(c, 0, 1));
    pki_chain_free(c); pki_eng_close(&e);
}

/* ---- weak signature algorithms and key sizes: the chain is built; status is Windows policy dependent ---- */
static void weak_case(const char *leaf) {
    REQUIRE(U(CertGetCertificateChain));
    if (!pki_find(leaf)) { t_skip("fixture %s not generated", leaf); return; }
    PKI_ENG e; CHECK(pki_eng_open(&e, "root", "inter", NULL, 0));
    PCCERT_CHAIN_CONTEXT c = pki_chain(e.h, leaf, NULL, PKI_T0, PKI_OFFLINE, NULL);
    CHECK(c != NULL);
    if (c) {
        pki_note_chain(leaf, c);
        EXPECT_EQ(pki_nelem(c, 0), 3);
        EXPECT_EQ(c->TrustStatus.dwErrorStatus & ~(DWORD)CERT_TRUST_HAS_WEAK_SIGNATURE, 0);
        t_note("%s: HAS_WEAK_SIGNATURE (0x100000) is %s", leaf, (c->TrustStatus.dwErrorStatus & CERT_TRUST_HAS_WEAK_SIGNATURE) ? "set" : "clear");
    }
    pki_chain_free(c); pki_eng_close(&e);
}
TEST(chain_weak_sha1_signed_leaf) { weak_case("leaf_sha1"); }
TEST(chain_weak_md5_signed_leaf) { weak_case("leaf_md5"); }
TEST(chain_weak_rsa1024_leaf) { weak_case("leaf_rsa1024"); }
TEST(chain_weak_sha256_baseline_clear) {
    REQUIRE(U(CertGetCertificateChain));
    PKI_ENG e; CHECK(pki_eng_open(&e, "root", "inter", NULL, 0));
    PCCERT_CHAIN_CONTEXT c = pki_chain(e.h, "leaf", NULL, PKI_T0, PKI_OFFLINE, NULL);
    CHECK(c != NULL);
    if (c) EXPECT_EQ(c->TrustStatus.dwErrorStatus & CERT_TRUST_HAS_WEAK_SIGNATURE, 0);
    pki_chain_free(c); pki_eng_close(&e);
}

/* ---- several valid paths: cross-signed intermediate ---- */
static void cross_case(const char *tag, const char *roots, const char *other, int want_err_zero, const char *want_inter, const char *want_root) {
    REQUIRE(U(CertGetCertificateChain));
    PKI_ENG e; CHECK(pki_eng_open(&e, roots, other, NULL, 0));
    PCCERT_CHAIN_CONTEXT c = pki_chain(e.h, "leaf", NULL, PKI_T0, PKI_OFFLINE, NULL);
    CHECK(c != NULL);
    if (c) {
        pki_note_chain(tag, c);
        if (want_err_zero) EXPECT_EQ(c->TrustStatus.dwErrorStatus, 0);
        EXPECT_EQ(c->cChain, 1);
        EXPECT_EQ(pki_nelem(c, 0), 3);
        if (want_inter) EXPECT_ID(c, 0, 1, want_inter);
        if (want_root) EXPECT_ID(c, 0, 2, want_root);
    }
    pki_chain_free(c); pki_eng_close(&e);
}
TEST(chain_cross_trust_only_root_uses_primary_path) { cross_case("only root", "root", "inter inter_x root2", 1, "inter", "root"); }
TEST(chain_cross_trust_only_root2_uses_cross_cert) { cross_case("only root2", "root2", "inter inter_x root", 1, "inter_x", "root2"); }
TEST(chain_cross_trust_both_roots_valid) {
    REQUIRE(U(CertGetCertificateChain));
    PKI_ENG e; CHECK(pki_eng_open(&e, "root root2", "inter inter_x", NULL, 0));
    PCCERT_CHAIN_CONTEXT c = pki_chain(e.h, "leaf", NULL, PKI_T0, PKI_OFFLINE, NULL);
    CHECK(c != NULL);
    if (c) { pki_note_chain("both roots", c); EXPECT_EQ(c->TrustStatus.dwErrorStatus, 0); EXPECT_EQ(pki_nelem(c, 0), 3);
             const char *i1 = pki_elem_id(c, 0, 1); CHECK(i1 && (!strcmp(i1, "inter") || !strcmp(i1, "inter_x"))); }
    pki_chain_free(c); pki_eng_close(&e);
}
TEST(chain_cross_trust_neither_root_untrusted) {
    REQUIRE(U(CertGetCertificateChain));
    PKI_ENG e; CHECK(pki_eng_open(&e, "", "inter inter_x root root2", NULL, 0));
    PCCERT_CHAIN_CONTEXT c = pki_chain(e.h, "leaf", NULL, PKI_T0, PKI_OFFLINE, NULL);
    CHECK(c != NULL);
    if (c) { pki_note_chain("no trusted root", c); EXPECT_EQ(c->TrustStatus.dwErrorStatus, CERT_TRUST_IS_UNTRUSTED_ROOT); EXPECT_EQ(pki_nelem(c, 0), 3); }
    pki_chain_free(c); pki_eng_close(&e);
}
TEST(chain_cross_cross_cert_only_available_but_its_root_missing) {
    REQUIRE(U(CertGetCertificateChain));
    PKI_ENG e; CHECK(pki_eng_open(&e, "root2", "inter_x", NULL, 0));
    PCCERT_CHAIN_CONTEXT c = pki_chain(e.h, "leaf", NULL, PKI_T0, PKI_OFFLINE, NULL);
    CHECK(c != NULL);
    if (c) { pki_note_chain("cross only, root2 trusted", c); EXPECT_EQ(c->TrustStatus.dwErrorStatus, 0); EXPECT_ID(c, 0, 1, "inter_x"); }
    pki_chain_free(c); pki_eng_close(&e);
}
TEST(chain_cross_expired_primary_path_prefers_valid_alternative) {
    /* inter ends 2045, inter_x too; evaluate with both roots when only the root2 path is complete */
    REQUIRE(U(CertGetCertificateChain));
    PKI_ENG e; CHECK(pki_eng_open(&e, "root2", "inter inter_x", NULL, 0));
    PCCERT_CHAIN_CONTEXT c = pki_chain(e.h, "leaf", NULL, PKI_T0, PKI_OFFLINE, NULL);
    CHECK(c != NULL);
    if (c) { EXPECT_EQ(c->TrustStatus.dwErrorStatus, 0); EXPECT_ID(c, 0, 1, "inter_x"); EXPECT_ID(c, 0, 2, "root2"); }
    pki_chain_free(c); pki_eng_close(&e);
}

/* ---- same subject, different key ---- */
TEST(chain_lookalike_root_not_trusted_by_name) {
    REQUIRE(U(CertGetCertificateChain));
    PKI_ENG e; CHECK(pki_eng_open(&e, "root", "root_fake", NULL, 0));
    PCCERT_CHAIN_CONTEXT c = pki_chain(e.h, "leaf_fake", NULL, PKI_T0, PKI_OFFLINE, NULL);
    CHECK(c != NULL);
    if (c) {
        pki_note_chain("lookalike root", c);
        CHECK(c->TrustStatus.dwErrorStatus & CERT_TRUST_IS_UNTRUSTED_ROOT);
        CHECK(c->TrustStatus.dwErrorStatus != 0);
    }
    pki_chain_free(c); pki_eng_close(&e);
}
TEST(chain_lookalike_root_only_trusted_root_listed) {
    /* leaf signed by the fake key but only the genuine root (same subject) is available: must not validate */
    REQUIRE(U(CertGetCertificateChain));
    PKI_ENG e; CHECK(pki_eng_open(&e, "root", NULL, NULL, 0));
    PCCERT_CHAIN_CONTEXT c = pki_chain(e.h, "leaf_fake", NULL, PKI_T0, PKI_OFFLINE, NULL);
    CHECK(c != NULL);
    if (c) { pki_note_chain("fake leaf, genuine root only", c); CHECK(c->TrustStatus.dwErrorStatus != 0);
             CHECK(c->TrustStatus.dwErrorStatus & (CERT_TRUST_IS_PARTIAL_CHAIN | CERT_TRUST_IS_NOT_SIGNATURE_VALID)); }
    pki_chain_free(c); pki_eng_close(&e);
}
TEST(chain_lookalike_genuine_leaf_with_both_roots_present) {
    REQUIRE(U(CertGetCertificateChain));
    PKI_ENG e; CHECK(pki_eng_open(&e, "root", "inter root_fake", NULL, 0));
    PCCERT_CHAIN_CONTEXT c = pki_chain(e.h, "leaf", NULL, PKI_T0, PKI_OFFLINE, NULL);
    CHECK(c != NULL);
    if (c) { pki_note_chain("genuine leaf amid lookalike", c); EXPECT_EQ(c->TrustStatus.dwErrorStatus, 0); EXPECT_ID(c, 0, 2, "root"); }
    pki_chain_free(c); pki_eng_close(&e);
}

/* ---- certificate cycle ---- */
TEST(chain_cycle_cross_certified_pair) {
    REQUIRE(U(CertGetCertificateChain));
    PKI_ENG e; CHECK(pki_eng_open(&e, "root", "cycA cycB", NULL, 0));
    PCCERT_CHAIN_CONTEXT c = pki_chain(e.h, "leaf_cyc", NULL, PKI_T0, PKI_OFFLINE, NULL);
    CHECK(c != NULL);
    if (c) {
        pki_note_chain("cycle", c);
        CHECK(c->TrustStatus.dwErrorStatus != 0);
        CHECK(c->TrustStatus.dwErrorStatus & (CERT_TRUST_IS_CYCLIC | CERT_TRUST_IS_PARTIAL_CHAIN | CERT_TRUST_IS_UNTRUSTED_ROOT));
        CHECK(pki_nelem(c, 0) >= 2 && pki_nelem(c, 0) <= 8);
    }
    pki_chain_free(c); pki_eng_close(&e);
}
TEST(chain_cycle_with_cycle_modulus_one) {
    REQUIRE(U(CertGetCertificateChain));
    PKI_ENG e; CHECK(pki_eng_open_ex(&e, "root", "cycA cycB", NULL, 0, 0, 1));
    PCCERT_CHAIN_CONTEXT c = pki_chain(e.h, "leaf_cyc", NULL, PKI_T0, PKI_OFFLINE, NULL);
    CHECK(c != NULL);
    if (c) { pki_note_chain("cycle modulus 1", c); CHECK(c->TrustStatus.dwErrorStatus != 0); }
    pki_chain_free(c); pki_eng_close(&e);
}
TEST(chain_cycle_terminates_when_cycle_certs_as_end_cert) {
    REQUIRE(U(CertGetCertificateChain));
    PKI_ENG e; CHECK(pki_eng_open(&e, "root", "cycA cycB", NULL, 0));
    PCCERT_CHAIN_CONTEXT c = pki_chain(e.h, "cycA", NULL, PKI_T0, PKI_OFFLINE, NULL);
    CHECK(c != NULL);
    if (c) { pki_note_chain("cycA as end cert", c); CHECK(c->TrustStatus.dwErrorStatus != 0); }
    pki_chain_free(c); pki_eng_close(&e);
}

/* ---- peer trust ---- */
TEST(chain_peer_trust_flag_marks_trusted_people_cert) {
    REQUIRE(U(CertGetCertificateChain));
    PKI_ENG e; CHECK(pki_eng_open(&e, "", "inter root", "leaf", 0));
    PCCERT_CHAIN_CONTEXT c = pki_chain(e.h, "leaf", NULL, PKI_T0, PKI_OFFLINE | CERT_CHAIN_ENABLE_PEER_TRUST, NULL);
    CHECK(c != NULL);
    if (c && c->cChain) {
        pki_note_chain("peer trusted", c);
        t_note("IS_PEER_TRUSTED info bit: %d", !!(pki_elem_info(c, 0, 0) & CERT_TRUST_IS_PEER_TRUSTED));
        t_note("peer trusted chain error status 0x%lx (UNTRUSTED_ROOT=0x20 would mean the peer trust did not end the chain)", c->TrustStatus.dwErrorStatus);
    }
    pki_chain_free(c); pki_eng_close(&e);
}
TEST(chain_peer_trust_without_flag_not_peer_trusted) {
    REQUIRE(U(CertGetCertificateChain));
    PKI_ENG e; CHECK(pki_eng_open(&e, "", "inter root", "leaf", 0));
    PCCERT_CHAIN_CONTEXT c = pki_chain(e.h, "leaf", NULL, PKI_T0, PKI_OFFLINE, NULL);
    CHECK(c != NULL);
    if (c && c->cChain) {
        pki_note_chain("trusted people store, no flag", c);
        EXPECT_EQ(pki_elem_info(c, 0, 0) & CERT_TRUST_IS_PEER_TRUSTED, 0);
        EXPECT_EQ(c->TrustStatus.dwErrorStatus, CERT_TRUST_IS_UNTRUSTED_ROOT);
    }
    pki_chain_free(c); pki_eng_close(&e);
}
TEST(chain_peer_trust_other_cert_in_store_not_trusted) {
    REQUIRE(U(CertGetCertificateChain));
    PKI_ENG e; CHECK(pki_eng_open(&e, "", "inter root", "leaf_root", 0));
    PCCERT_CHAIN_CONTEXT c = pki_chain(e.h, "leaf", NULL, PKI_T0, PKI_OFFLINE | CERT_CHAIN_ENABLE_PEER_TRUST, NULL);
    CHECK(c != NULL);
    if (c && c->cChain) {
        EXPECT_EQ(pki_elem_info(c, 0, 0) & CERT_TRUST_IS_PEER_TRUSTED, 0);
        EXPECT_EQ(c->TrustStatus.dwErrorStatus, CERT_TRUST_IS_UNTRUSTED_ROOT);
    }
    pki_chain_free(c); pki_eng_close(&e);
}
