/* Offline revocation checking through CRLs supplied in the engine / additional stores.  Never touches the wire:
 * every revocation flag used here carries CERT_CHAIN_REVOCATION_CHECK_CACHE_ONLY and the PKI has no distribution points. */
#include "pkiutil.h"

#define E_REV CERT_TRUST_IS_REVOKED
#define E_UNK CERT_TRUST_REVOCATION_STATUS_UNKNOWN

static PCCERT_CHAIN_CONTEXT rev_chain(PKI_ENG *e, const char *leaf, const char *addl, DWORD flags, CERT_CHAIN_PARA *p) {
    return pki_chain(e->h, leaf, addl, PKI_T0, PKI_OFFLINE | flags, p);
}

TEST(chain_revoke_not_checked_without_flags) {
    REQUIRE(U(CertGetCertificateChain));
    PKI_ENG e; CHECK(pki_eng_open(&e, "root", "inter", NULL, 0));
    PCCERT_CHAIN_CONTEXT c = rev_chain(&e, "leaf_rev", "crl_inter", 0, NULL);
    CHECK(c != NULL);
    if (c) { EXPECT_EQ(c->TrustStatus.dwErrorStatus, 0); if (c->cChain) EXPECT_EQ(c->rgpChain[0]->rgpElement[0]->pRevocationInfo, NULL); }
    pki_chain_free(c); pki_eng_close(&e);
}
TEST(chain_revoke_end_cert_revoked_by_crl_in_additional_store) {
    REQUIRE(U(CertGetCertificateChain));
    PKI_ENG e; CHECK(pki_eng_open(&e, "root", "inter", NULL, 0));
    PCCERT_CHAIN_CONTEXT c = rev_chain(&e, "leaf_rev", "crl_inter", REV_END_CACHE, NULL);
    CHECK(c != NULL);
    if (c && c->cChain && c->rgpChain[0]->cElement == 3) {
        pki_note_chain("revoked leaf", c);
        EXPECT_EQ(c->TrustStatus.dwErrorStatus, E_REV);
        EXPECT_EQ(pki_elem_err(c, 0, 0), E_REV);
        EXPECT_EQ(pki_elem_err(c, 0, 1) & E_REV, 0);
        EXPECT_EQ(pki_elem_err(c, 0, 2) & E_REV, 0);
        EXPECT_EQ(c->TrustStatus.dwErrorStatus & CERT_TRUST_IS_UNTRUSTED_ROOT, 0);
    }
    pki_chain_free(c); pki_eng_close(&e);
}
TEST(chain_revoke_end_cert_revoked_crl_in_engine_additional_store) {
    REQUIRE(U(CertGetCertificateChain));
    PKI_ENG e; CHECK(pki_eng_open(&e, "root", "inter crl_inter", NULL, 0));
    PCCERT_CHAIN_CONTEXT c = rev_chain(&e, "leaf_rev", NULL, REV_END_CACHE, NULL);
    CHECK(c != NULL);
    if (c) { pki_note_chain("crl via engine store", c); EXPECT_EQ(c->TrustStatus.dwErrorStatus, E_REV); }
    pki_chain_free(c); pki_eng_close(&e);
}
TEST(chain_revoke_revocation_info_of_revoked_element) {
    REQUIRE(U(CertGetCertificateChain));
    PKI_ENG e; CHECK(pki_eng_open(&e, "root", "inter", NULL, 0));
    PCCERT_CHAIN_CONTEXT c = rev_chain(&e, "leaf_rev", "crl_inter", REV_END_CACHE, NULL);
    CHECK(c && c->cChain == 1);
    if (c && c->cChain == 1) {
        PCERT_REVOCATION_INFO ri = c->rgpChain[0]->rgpElement[0]->pRevocationInfo;
        CHECK(ri != NULL);
        if (ri) {
            CHECK(ri->cbSize >= offsetof(CERT_REVOCATION_INFO, pCrlInfo));
            EXPECT_EQ(ri->dwRevocationResult, CRYPT_E_REVOKED);
            /* the freshness time is the CRL age in seconds and moves with the clock: only its presence is stable */
            EXPECT_EQ(ri->pszRevocationOid, NULL);
            EXPECT_EQ(ri->fHasFreshnessTime, 1);
            CHECK(ri->dwFreshnessTime > 0);
            CHECK(ri->pCrlInfo != NULL);
            if (ri->pCrlInfo) {
                CHECK(ri->pCrlInfo->pBaseCrlContext != NULL);
                CHECK(ri->pCrlInfo->pCrlEntry != NULL);
                if (ri->pCrlInfo->pCrlEntry) {
                    PCERT_REVOCATION_CRL_INFO ci = ri->pCrlInfo; (void)ci;
                    PCRL_ENTRY en = ri->pCrlInfo->pCrlEntry;
                    EXPECT_EQ(en->SerialNumber.cbData, 2);
                    if (en->SerialNumber.cbData == 2) { EXPECT_EQ(en->SerialNumber.pbData[0], 0x01); EXPECT_EQ(en->SerialNumber.pbData[1], 0x06); }
                }
            }
        }
    }
    pki_chain_free(c); pki_eng_close(&e);
}
TEST(chain_revoke_certificate_hold_counts_as_revoked) {
    REQUIRE(U(CertGetCertificateChain));
    PKI_ENG e; CHECK(pki_eng_open(&e, "root", "inter", NULL, 0));
    PCCERT_CHAIN_CONTEXT c = rev_chain(&e, "leaf_hold", "crl_inter", REV_END_CACHE, NULL);
    CHECK(c != NULL);
    if (c) { pki_note_chain("on hold", c); CHECK(c->TrustStatus.dwErrorStatus & E_REV); }
    pki_chain_free(c); pki_eng_close(&e);
}
TEST(chain_revoke_unlisted_serial_not_revoked) {
    REQUIRE(U(CertGetCertificateChain));
    PKI_ENG e; CHECK(pki_eng_open(&e, "root", "inter", NULL, 0));
    PCCERT_CHAIN_CONTEXT c = rev_chain(&e, "leaf_good_crl", "crl_inter", REV_END_CACHE, NULL);
    CHECK(c != NULL);
    if (c && c->cChain) {
        pki_note_chain("good leaf, CRL with other revoked serials", c);
        EXPECT_EQ(c->TrustStatus.dwErrorStatus & E_REV, 0);
        PCERT_REVOCATION_INFO ri = c->rgpChain[0]->rgpElement[0]->pRevocationInfo;
        CHECK(ri != NULL);
        if (ri) EXPECT_EQ(ri->dwRevocationResult, 0);
        EXPECT_EQ(c->TrustStatus.dwErrorStatus, 0);   /* the CRL is accepted as authoritative */
    }
    pki_chain_free(c); pki_eng_close(&e);
}
TEST(chain_revoke_empty_crl_clean) {
    REQUIRE(U(CertGetCertificateChain));
    PKI_ENG e; CHECK(pki_eng_open(&e, "root", "inter", NULL, 0));
    PCCERT_CHAIN_CONTEXT c = rev_chain(&e, "leaf_rev", "crl_inter_clean", REV_END_CACHE, NULL);
    CHECK(c != NULL);
    if (c) { pki_note_chain("empty CRL", c); EXPECT_EQ(c->TrustStatus.dwErrorStatus, 0); }
    pki_chain_free(c); pki_eng_close(&e);
}
TEST(chain_revoke_no_crl_available_status_unknown) {
    REQUIRE(U(CertGetCertificateChain));
    PKI_ENG e; CHECK(pki_eng_open(&e, "root", "inter", NULL, 0));
    DWORD t0 = GetTickCount();
    PCCERT_CHAIN_CONTEXT c = rev_chain(&e, "leaf_good_crl", NULL, REV_END_CACHE, NULL);
    DWORD dt = GetTickCount() - t0;
    CHECK(c != NULL);
    CHECKF(dt < 20000, "cache-only revocation took %lu ms", dt);
    if (c && c->cChain) {
        pki_note_chain("no CRL anywhere", c);
        EXPECT_EQ(c->TrustStatus.dwErrorStatus, E_UNK);          /* UNKNOWN only: not flagged offline, not revoked */
        EXPECT_EQ(pki_elem_err(c, 0, 0), E_UNK);
        PCERT_REVOCATION_INFO ri = c->rgpChain[0]->rgpElement[0]->pRevocationInfo;
        CHECK(ri != NULL);
        if (ri) EXPECT_EQ(ri->dwRevocationResult, 0x80092012);   /* CRYPT_E_NO_REVOCATION_CHECK */
    }
    pki_chain_free(c); pki_eng_close(&e);
}
TEST(chain_revoke_expired_crl_is_not_authoritative) {
    REQUIRE(U(CertGetCertificateChain));
    PKI_ENG e; CHECK(pki_eng_open(&e, "root", "inter", NULL, 0));
    PCCERT_CHAIN_CONTEXT c = rev_chain(&e, "leaf_good_crl", "crl_inter_expired", REV_END_CACHE, NULL);
    CHECK(c != NULL);
    if (c) { pki_note_chain("CRL nextUpdate 2022 at 2025", c); EXPECT_EQ(c->TrustStatus.dwErrorStatus, 0x1000040); /* UNKNOWN | IS_OFFLINE_REVOCATION */ }
    pki_chain_free(c); pki_eng_close(&e);
}
TEST(chain_revoke_crl_not_yet_valid_at_ptime) {
    REQUIRE(U(CertGetCertificateChain));
    PKI_ENG e; CHECK(pki_eng_open(&e, "root", "inter", NULL, 0));
    /* CRL thisUpdate is 2025-01-01; at 2024-03-01 the entry for the revoked leaf is not yet published */
    PCCERT_CHAIN_CONTEXT c = pki_chain(e.h, "leaf_rev", "crl_inter", 2024, 3, 1, 0, 0, 0, PKI_OFFLINE | REV_END_CACHE, NULL);
    CHECK(c != NULL);
    if (c) pki_note_chain("CRL from the future", c);
    pki_chain_free(c); pki_eng_close(&e);
}
TEST(chain_revoke_other_issuers_crl_not_used) {
    REQUIRE(U(CertGetCertificateChain));
    PKI_ENG e; CHECK(pki_eng_open(&e, "root", "inter", NULL, 0));
    /* only the root's CRL is present; it says nothing about leaf certs issued by the intermediate */
    PCCERT_CHAIN_CONTEXT c = rev_chain(&e, "leaf_rev", "crl_root_clean", REV_END_CACHE, NULL);
    CHECK(c != NULL);
    if (c) { pki_note_chain("wrong issuer CRL", c); EXPECT_EQ(c->TrustStatus.dwErrorStatus & E_REV, 0); CHECK(c->TrustStatus.dwErrorStatus & E_UNK); }
    pki_chain_free(c); pki_eng_close(&e);
}

/* ---- whole chain ---- */
TEST(chain_revoke_chain_exclude_root_all_crls_present) {
    REQUIRE(U(CertGetCertificateChain));
    PKI_ENG e; CHECK(pki_eng_open(&e, "root", "inter", NULL, 0));
    PCCERT_CHAIN_CONTEXT c = rev_chain(&e, "leaf_good_crl", "crl_inter_clean crl_root_clean", REV_XROOT_CACHE, NULL);
    CHECK(c != NULL);
    if (c) { pki_note_chain("chain exclude root", c); EXPECT_EQ(c->TrustStatus.dwErrorStatus & E_REV, 0); }
    pki_chain_free(c); pki_eng_close(&e);
}
TEST(chain_revoke_chain_exclude_root_missing_ca_crl) {
    REQUIRE(U(CertGetCertificateChain));
    PKI_ENG e; CHECK(pki_eng_open(&e, "root", "inter", NULL, 0));
    PCCERT_CHAIN_CONTEXT c = rev_chain(&e, "leaf_good_crl", "crl_inter_clean", REV_XROOT_CACHE, NULL);
    CHECK(c != NULL);
    if (c && c->cChain == 1 && c->rgpChain[0]->cElement == 3) {
        pki_note_chain("no CRL for the intermediate", c);
        CHECK(c->TrustStatus.dwErrorStatus & E_UNK);
        EXPECT_EQ(pki_elem_err(c, 0, 0) & E_UNK, 0);
        CHECK(pki_elem_err(c, 0, 1) & E_UNK);
    }
    pki_chain_free(c); pki_eng_close(&e);
}
TEST(chain_revoke_end_cert_only_does_not_query_ca) {
    REQUIRE(U(CertGetCertificateChain));
    PKI_ENG e; CHECK(pki_eng_open(&e, "root", "inter", NULL, 0));
    PCCERT_CHAIN_CONTEXT c = rev_chain(&e, "leaf_good_crl", "crl_inter_clean", REV_END_CACHE, NULL);
    CHECK(c != NULL);
    if (c && c->cChain == 1 && c->rgpChain[0]->cElement == 3) {
        EXPECT_EQ(c->TrustStatus.dwErrorStatus & E_REV, 0);
        EXPECT_EQ(c->rgpChain[0]->rgpElement[1]->pRevocationInfo, NULL);
        EXPECT_EQ(c->rgpChain[0]->rgpElement[2]->pRevocationInfo, NULL);
    }
    pki_chain_free(c); pki_eng_close(&e);
}
TEST(chain_revoke_revoked_intermediate) {
    REQUIRE(U(CertGetCertificateChain));
    PKI_ENG e; CHECK(pki_eng_open(&e, "root", "inter_rev", NULL, 0));
    PCCERT_CHAIN_CONTEXT c = rev_chain(&e, "leaf_under_rev", "crl_root", REV_XROOT_CACHE, NULL);
    CHECK(c != NULL);
    if (c && c->cChain == 1 && c->rgpChain[0]->cElement == 3) {
        pki_note_chain("revoked CA", c);
        EXPECT_EQ(c->TrustStatus.dwErrorStatus, 0x1000044);   /* REVOKED | IS_OFFLINE_REVOCATION: the leaf below has no CRL */
        EXPECT_EQ(pki_elem_err(c, 0, 0), 0x1000040);
        EXPECT_EQ(pki_elem_err(c, 0, 1), E_REV);
        EXPECT_EQ(pki_elem_err(c, 0, 2) & E_REV, 0);
        PCERT_REVOCATION_INFO ri = c->rgpChain[0]->rgpElement[1]->pRevocationInfo;
        CHECK(ri != NULL);
        if (ri) EXPECT_EQ(ri->dwRevocationResult, CRYPT_E_REVOKED);
    }
    pki_chain_free(c); pki_eng_close(&e);
}
TEST(chain_revoke_revoked_intermediate_not_found_by_end_cert_only) {
    REQUIRE(U(CertGetCertificateChain));
    PKI_ENG e; CHECK(pki_eng_open(&e, "root", "inter_rev", NULL, 0));
    PCCERT_CHAIN_CONTEXT c = rev_chain(&e, "leaf_under_rev", "crl_root", REV_END_CACHE, NULL);
    CHECK(c != NULL);
    if (c) { pki_note_chain("END_CERT with revoked CA", c); EXPECT_EQ(c->TrustStatus.dwErrorStatus & E_REV, 0); }
    pki_chain_free(c); pki_eng_close(&e);
}
TEST(chain_revoke_check_chain_includes_root_observation) {
    REQUIRE(U(CertGetCertificateChain));
    PKI_ENG e; CHECK(pki_eng_open(&e, "root", "inter", NULL, 0));
    PCCERT_CHAIN_CONTEXT c = rev_chain(&e, "leaf_good_crl", "crl_inter_clean crl_root_clean", REV_CHAIN_CACHE, NULL);
    CHECK(c != NULL);
    if (c && c->cChain == 1) {
        pki_note_chain("CHECK_CHAIN (root has no issuer to ask)", c);
        EXPECT_EQ(c->TrustStatus.dwErrorStatus & E_REV, 0);
    }
    pki_chain_free(c); pki_eng_close(&e);
}
TEST(chain_revoke_direct_root_issued_leaf_revocation_unknown_without_crl) {
    REQUIRE(U(CertGetCertificateChain));
    PKI_ENG e; CHECK(pki_eng_open(&e, "root", NULL, NULL, 0));
    PCCERT_CHAIN_CONTEXT c = rev_chain(&e, "leaf_root", NULL, REV_END_CACHE, NULL);
    CHECK(c != NULL);
    if (c) { pki_note_chain("no CRL, 2-element chain", c); CHECK(c->TrustStatus.dwErrorStatus & E_UNK); }
    pki_chain_free(c); pki_eng_close(&e);
}
TEST(chain_revoke_revoked_and_expired_combine_flags) {
    REQUIRE(U(CertGetCertificateChain));
    PKI_ENG e; CHECK(pki_eng_open(&e, "root", "inter", NULL, 0));
    /* leaf_rev evaluated in 2046 (after the intermediate expired): both time and revocation problems are reported */
    PCCERT_CHAIN_CONTEXT c = pki_chain(e.h, "leaf_rev", "crl_inter", 2046, 1, 1, 0, 0, 0, PKI_OFFLINE | REV_END_CACHE, NULL);
    CHECK(c != NULL);
    if (c) { pki_note_chain("revoked+expired", c); CHECK(c->TrustStatus.dwErrorStatus & CERT_TRUST_IS_NOT_TIME_VALID); }
    pki_chain_free(c); pki_eng_close(&e);
}

/* ---- CERT_CHAIN_PARA revocation freshness and timeout ---- */
TEST(chain_revoke_para_url_timeout_zero_cache_only) {
    REQUIRE(U(CertGetCertificateChain));
    PKI_ENG e; CHECK(pki_eng_open(&e, "root", "inter", NULL, 0));
    CERT_CHAIN_PARA p; memset(&p, 0, sizeof p); p.cbSize = sizeof p; p.dwUrlRetrievalTimeout = 0;
    PCCERT_CHAIN_CONTEXT c = rev_chain(&e, "leaf_rev", "crl_inter", REV_END_CACHE, &p);
    CHECK(c != NULL);
    if (c) CHECK(c->TrustStatus.dwErrorStatus & E_REV);
    pki_chain_free(c); pki_eng_close(&e);
}
TEST(chain_revoke_para_freshness_time_generous) {
    REQUIRE(U(CertGetCertificateChain));
    PKI_ENG e; CHECK(pki_eng_open(&e, "root", "inter", NULL, 0));
    CERT_CHAIN_PARA p; memset(&p, 0, sizeof p); p.cbSize = sizeof p;
    p.fCheckRevocationFreshnessTime = TRUE; p.dwRevocationFreshnessTime = 10u * 365 * 24 * 3600;
    PCCERT_CHAIN_CONTEXT c = rev_chain(&e, "leaf_good_crl", "crl_inter_clean", REV_END_CACHE, &p);
    CHECK(c != NULL);
    if (c) {
        pki_note_chain("freshness 10y", c);
        EXPECT_EQ(c->TrustStatus.dwErrorStatus & E_REV, 0);
        EXPECT_EQ(c->TrustStatus.dwErrorStatus, 0);
        /* the reported freshness time is the CRL age in seconds (it moves with the clock): only its presence is stable */
        EXPECT_EQ(c->fHasRevocationFreshnessTime, 1);
        CHECK(c->dwRevocationFreshnessTime > 0);
        if (c->cChain) { EXPECT_EQ(c->rgpChain[0]->fHasRevocationFreshnessTime, 1); CHECK(c->rgpChain[0]->dwRevocationFreshnessTime > 0); }
    }
    pki_chain_free(c); pki_eng_close(&e);
}
TEST(chain_revoke_para_freshness_time_one_second_stale) {
    REQUIRE(U(CertGetCertificateChain));
    PKI_ENG e; CHECK(pki_eng_open(&e, "root", "inter", NULL, 0));
    CERT_CHAIN_PARA p; memset(&p, 0, sizeof p); p.cbSize = sizeof p;
    p.fCheckRevocationFreshnessTime = TRUE; p.dwRevocationFreshnessTime = 1;
    PCCERT_CHAIN_CONTEXT c = rev_chain(&e, "leaf_good_crl", "crl_inter_clean", REV_END_CACHE, &p);
    CHECK(c != NULL);
    if (c) { pki_note_chain("freshness 1s vs CRL age of months", c); EXPECT_EQ(c->TrustStatus.dwErrorStatus, 0x1000040); EXPECT_EQ(pki_elem_err(c, 0, 0), 0x1000040); }
    pki_chain_free(c); pki_eng_close(&e);
}
TEST(chain_revoke_para_cache_resync_filetime_accepted) {
    REQUIRE(U(CertGetCertificateChain));
    PKI_ENG e; CHECK(pki_eng_open(&e, "root", "inter", NULL, 0));
    CERT_CHAIN_PARA p; memset(&p, 0, sizeof p); p.cbSize = sizeof p;
    FILETIME rs = pki_ft(2024, 1, 1, 0, 0, 0); p.pftCacheResync = &rs;
    PCCERT_CHAIN_CONTEXT c = rev_chain(&e, "leaf_rev", "crl_inter", REV_END_CACHE, &p);
    CHECK(c != NULL);
    if (c) CHECK(c->TrustStatus.dwErrorStatus & E_REV);
    pki_chain_free(c); pki_eng_close(&e);
}
TEST(chain_revoke_repeated_calls_consistent) {
    REQUIRE(U(CertGetCertificateChain));
    PKI_ENG e; CHECK(pki_eng_open(&e, "root", "inter", NULL, 0));
    for (int i = 0; i < 5; i++) {
        PCCERT_CHAIN_CONTEXT c = rev_chain(&e, i & 1 ? "leaf_rev" : "leaf_good_crl", "crl_inter", REV_END_CACHE, NULL);
        CHECK(c != NULL);
        if (c) { if (i & 1) CHECK(c->TrustStatus.dwErrorStatus & E_REV); else EXPECT_EQ(c->TrustStatus.dwErrorStatus & E_REV, 0); }
        pki_chain_free(c);
    }
    pki_eng_close(&e);
}
