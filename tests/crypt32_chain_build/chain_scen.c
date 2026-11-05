/* CertGetCertificateChain: scenario table over the generated PKI, structure invariants, pTime and flags. */
#include "pkiutil.h"

#define SCEN(nm, leaf, roots, others, addl, tm, flags, err, n) \
    TEST(chain_build_##nm) { REQUIRE(U(CertGetCertificateChain)); pki_scenario(#nm, leaf, roots, others, addl, tm, flags, err, n); }
#define T(...) __VA_ARGS__
#define NOERR 0
#define TIME_OK CERT_TRUST_IS_NOT_TIME_VALID
#define PARTIAL CERT_TRUST_IS_PARTIAL_CHAIN
#define UNTRUSTED CERT_TRUST_IS_UNTRUSTED_ROOT
#define BADBC CERT_TRUST_INVALID_BASIC_CONSTRAINTS

/* ---- topology and trust ---- */
SCEN(good_three_elements, "leaf", "root", "inter", NULL, PKI_T0, 0, NOERR, 3)
SCEN(good_intermediate_from_hAdditionalStore, "leaf", "root", NULL, "inter", PKI_T0, 0, NOERR, 3)
SCEN(good_leaf_issued_by_root, "leaf_root", "root", NULL, NULL, PKI_T0, 0, NOERR, 2)
SCEN(good_leaf_without_extensions, "leaf_nobc", "root", "inter", NULL, PKI_T0, 0, NOERR, 3)
SCEN(good_leaf_claims_ca_bit, "leaf_ca", "root", "inter", NULL, PKI_T0, 0, NOERR, 3)
SCEN(good_unrelated_certs_in_stores, "leaf", "root root2", "inter inter_pl0 sub_ca leaf_code leaf_expired", NULL, PKI_T0, 0, NOERR, 3)
SCEN(good_pathlen1_with_one_sub_ca, "leaf_pl1", "root", "inter_pl1 sub_ca1", NULL, PKI_T0, 0, NOERR, 4)
SCEN(good_self_signed_root_as_end_cert, "root", "root", NULL, NULL, PKI_T0, 0, NOERR, 1)
SCEN(untrusted_self_signed_root_as_end_cert, "root", "", NULL, NULL, PKI_T0, 0, UNTRUSTED, 1)
SCEN(untrusted_empty_root_store, "leaf", "", "inter root", NULL, PKI_T0, 0, UNTRUSTED, 3)
SCEN(untrusted_other_root_listed, "leaf", "root2", "inter root", NULL, PKI_T0, 0, UNTRUSTED, 3)
SCEN(untrusted_root_two_cert_chain, "leaf_root", "root2", "root", NULL, PKI_T0, 0, UNTRUSTED, 2)
SCEN(partial_no_intermediate, "leaf", "root", "", NULL, PKI_T0, 0, PARTIAL, 1)
SCEN(partial_no_issuer_for_leaf_root, "leaf_root", "", "", NULL, PKI_T0, 0, PARTIAL, 1)
SCEN(partial_intermediate_without_root, "leaf", "", "inter", NULL, PKI_T0, 0, PARTIAL, 2)
SCEN(partial_wrong_root_listed, "leaf", "root2", "inter", NULL, PKI_T0, 0, PARTIAL, 2)

/* ---- time validity (evaluation time is pTime) ---- */
SCEN(time_expired_leaf, "leaf_expired", "root", "inter", NULL, PKI_T0, 0, TIME_OK, 3)
SCEN(time_future_leaf, "leaf_future", "root", "inter", NULL, PKI_T0, 0, TIME_OK, 3)
SCEN(time_expired_leaf_valid_in_past, "leaf_expired", "root", "inter", NULL, T(2021,6,1,0,0,0), 0, NOERR, 3)
SCEN(time_future_leaf_valid_in_future, "leaf_future", "root", "inter", NULL, T(2040,6,1,0,0,0), 0, NOERR, 3)
SCEN(time_before_everything, "leaf", "root", "inter", NULL, T(2015,1,1,0,0,0), 0, TIME_OK, 3)
SCEN(time_before_root_valid_after_nothing, "leaf_root", "root", NULL, NULL, T(2019,12,31,23,59,59), 0, TIME_OK, 2)
SCEN(time_after_intermediate_expiry, "leaf", "root", "inter", NULL, T(2046,1,1,0,0,0), 0, TIME_OK, 3)
SCEN(time_leaf_expired_at_notAfter_exact, "leaf_expired", "root", "inter", NULL, T(2022,1,1,0,0,0), 0, NOERR, 3)
SCEN(time_leaf_expired_one_second_after, "leaf_expired", "root", "inter", NULL, T(2022,1,1,0,0,1), 0, TIME_OK, 3)
SCEN(time_leaf_valid_at_notBefore_exact, "leaf_expired", "root", "inter", NULL, T(2021,1,1,0,0,0), 0, NOERR, 3)
SCEN(time_leaf_invalid_one_second_before_notBefore, "leaf_expired", "root", "inter", NULL, T(2020,12,31,23,59,59), 0, TIME_OK, 3)
SCEN(time_short_intermediate_expired, "leaf_short", "root", "inter_short", NULL, PKI_T0, 0, TIME_OK, 3)
SCEN(time_short_intermediate_valid_earlier, "leaf_short", "root", "inter_short", NULL, T(2022,6,1,0,0,0), 0, NOERR, 3)
SCEN(time_short_intermediate_notyet, "leaf_short", "root", "inter_short", NULL, T(2020,12,1,0,0,0), 0, TIME_OK, 3)
SCEN(time_after_root_expiry, "leaf_root", "root", NULL, NULL, T(2049,12,31,12,0,0), 0, TIME_OK, 2)   /* root notAfter is 2049-12-31 00:00:00 */

/* ---- basic constraints ---- */
SCEN(bc_pathlen0_with_subca_violated, "leaf_pl", "root", "inter_pl0 sub_ca", NULL, PKI_T0, 0, BADBC, 4)
SCEN(bc_non_ca_intermediate, "leaf_noca", "root", "inter_noca", NULL, PKI_T0, 0, BADBC, 3)
SCEN(bc_pathlen0_direct_leaf_fine, "leaf", "root", "inter", NULL, PKI_T0, 0, NOERR, 3)

/* ---- chain cache must not change the answer on repetition ---- */
TEST(chain_build_repeat_gives_same_result) {
    REQUIRE(U(CertGetCertificateChain));
    PKI_ENG e; CHECK(pki_eng_open(&e, "root", "inter", NULL, 0));
    for (int i = 0; i < 20; i++) {
        PCCERT_CHAIN_CONTEXT c = pki_chain(e.h, "leaf", NULL, PKI_T0, PKI_OFFLINE, NULL);
        CHECK(c != NULL);
        if (c) { EXPECT_EQ(c->TrustStatus.dwErrorStatus, 0); EXPECT_EQ(pki_nelem(c, 0), 3); }
        pki_chain_free(c);
    }
    pki_eng_close(&e);
}
TEST(chain_build_time_change_is_not_cached) {
    REQUIRE(U(CertGetCertificateChain));
    PKI_ENG e; CHECK(pki_eng_open(&e, "root", "inter", NULL, 0));
    for (int i = 0; i < 4; i++) {
        PCCERT_CHAIN_CONTEXT c = pki_chain(e.h, "leaf_expired", NULL, i & 1 ? 2025 : 2021, 6, 1, 0, 0, 0, PKI_OFFLINE, NULL);
        CHECK(c != NULL);
        if (c) EXPECT_EQ(c->TrustStatus.dwErrorStatus, (i & 1) ? CERT_TRUST_IS_NOT_TIME_VALID : 0);
        pki_chain_free(c);
    }
    pki_eng_close(&e);
}
TEST(chain_build_cache_end_cert_engine_flag_same_answers) {
    REQUIRE(U(CertGetCertificateChain));
    PKI_ENG e; CHECK(pki_eng_open(&e, "root", "inter", NULL, CERT_CHAIN_CACHE_END_CERT));
    for (int i = 0; i < 4; i++) {
        PCCERT_CHAIN_CONTEXT c = pki_chain(e.h, "leaf_expired", NULL, i & 1 ? 2025 : 2021, 6, 1, 0, 0, 0, PKI_OFFLINE, NULL);
        CHECK(c != NULL);
        if (c) EXPECT_EQ(c->TrustStatus.dwErrorStatus, (i & 1) ? CERT_TRUST_IS_NOT_TIME_VALID : 0);
        pki_chain_free(c);
    }
    pki_eng_close(&e);
}

/* ---- pTime NULL means "now" ---- */
TEST(chain_build_null_time_uses_current_time_good) {
    REQUIRE(U(CertGetCertificateChain));
    PKI_ENG e; CHECK(pki_eng_open(&e, "root", "inter", NULL, 0));
    PCCERT_CHAIN_CONTEXT c = pki_chain(e.h, "leaf", NULL, PKI_NOW, PKI_OFFLINE, NULL);
    CHECK(c != NULL);
    if (c) { EXPECT_EQ(c->TrustStatus.dwErrorStatus, 0); }
    pki_chain_free(c); pki_eng_close(&e);
}
TEST(chain_build_null_time_expired_leaf_flagged) {
    REQUIRE(U(CertGetCertificateChain));
    PKI_ENG e; CHECK(pki_eng_open(&e, "root", "inter", NULL, 0));
    PCCERT_CHAIN_CONTEXT c = pki_chain(e.h, "leaf_expired", NULL, PKI_NOW, PKI_OFFLINE, NULL);
    CHECK(c != NULL);
    if (c) { EXPECT_EQ(c->TrustStatus.dwErrorStatus, CERT_TRUST_IS_NOT_TIME_VALID); }
    pki_chain_free(c); pki_eng_close(&e);
}
TEST(chain_build_explicit_current_time_matches_null_time) {
    REQUIRE(U(CertGetCertificateChain));
    PKI_ENG e; CHECK(pki_eng_open(&e, "root", "inter", NULL, 0));
    SYSTEMTIME st; GetSystemTime(&st);
    PCCERT_CHAIN_CONTEXT a = pki_chain(e.h, "leaf", NULL, st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, PKI_OFFLINE, NULL);
    PCCERT_CHAIN_CONTEXT b = pki_chain(e.h, "leaf", NULL, PKI_NOW, PKI_OFFLINE, NULL);
    CHECK(a && b);
    if (a && b) EXPECT_EQ(a->TrustStatus.dwErrorStatus, b->TrustStatus.dwErrorStatus);
    pki_chain_free(a); pki_chain_free(b); pki_eng_close(&e);
}

/* ---- context structure ---- */
TEST(chain_build_context_header_fields) {
    REQUIRE(U(CertGetCertificateChain));
    PKI_ENG e; CHECK(pki_eng_open(&e, "root", "inter", NULL, 0));
    PCCERT_CHAIN_CONTEXT c = pki_chain(e.h, "leaf", NULL, PKI_T0, PKI_OFFLINE, NULL);
    CHECK(c != NULL);
    if (c) {
        EXPECT_EQ(c->cbSize, sizeof(CERT_CHAIN_CONTEXT));   /* 72 on Win10 22H2 x64 */
        EXPECT_EQ(c->cChain, 1);
        CHECK(c->rgpChain != NULL);
        EXPECT_EQ(c->cLowerQualityChainContext, 0);
        EXPECT_EQ(c->rgpLowerQualityChainContext, NULL);
        EXPECT_EQ(c->TrustStatus.dwErrorStatus, 0);
        EXPECT_EQ(c->TrustStatus.dwInfoStatus, 0x2100);     /* HAS_PREFERRED_ISSUER | IS_FROM_EXCLUSIVE... as probed */
        EXPECT_EQ(c->fHasRevocationFreshnessTime, 0);
        EXPECT_EQ(c->dwCreateFlags, PKI_OFFLINE);
        if (c->cbSize >= sizeof(CERT_CHAIN_CONTEXT)) { GUID z = {0}; CHECK(memcmp(&c->ChainId, &z, sizeof z) == 0); /* Win10: ChainId is all zero in this path */ }
    }
    pki_chain_free(c); pki_eng_close(&e);
}
TEST(chain_build_simple_chain_fields) {
    REQUIRE(U(CertGetCertificateChain));
    PKI_ENG e; CHECK(pki_eng_open(&e, "root", "inter", NULL, 0));
    PCCERT_CHAIN_CONTEXT c = pki_chain(e.h, "leaf", NULL, PKI_T0, PKI_OFFLINE, NULL);
    CHECK(c && c->cChain == 1);
    if (c && c->cChain == 1) {
        PCERT_SIMPLE_CHAIN sc = c->rgpChain[0];
        CHECK(sc != NULL);
        CHECK(sc->cbSize >= offsetof(CERT_SIMPLE_CHAIN, fHasRevocationFreshnessTime));
        EXPECT_EQ(sc->cElement, 3);
        CHECK(sc->rgpElement != NULL);
        EXPECT_EQ(sc->pTrustListInfo, NULL);
        EXPECT_EQ(sc->TrustStatus.dwErrorStatus, c->TrustStatus.dwErrorStatus);
        EXPECT_EQ(sc->cbSize, 40);
        EXPECT_EQ(sc->TrustStatus.dwInfoStatus, 0x2100);
    }
    pki_chain_free(c); pki_eng_close(&e);
}
TEST(chain_build_element_fields) {
    REQUIRE(U(CertGetCertificateChain));
    PKI_ENG e; CHECK(pki_eng_open(&e, "root", "inter", NULL, 0));
    PCCERT_CHAIN_CONTEXT c = pki_chain(e.h, "leaf", NULL, PKI_T0, PKI_OFFLINE, NULL);
    CHECK(c && c->cChain == 1 && c->rgpChain[0]->cElement == 3);
    if (c && c->cChain == 1 && c->rgpChain[0]->cElement == 3) {
        const char *want[3] = {"leaf", "inter", "root"};
        for (int i = 0; i < 3; i++) {
            PCERT_CHAIN_ELEMENT el = c->rgpChain[0]->rgpElement[i];
            CHECKF(el != NULL, "element %d", i);
            if (!el) continue;
            CHECKF(el->cbSize >= offsetof(CERT_CHAIN_ELEMENT, pwszExtendedErrorInfo), "element %d cbSize %lu", i, el->cbSize);
            CHECKF(el->pCertContext != NULL, "element %d cert", i);
            EXPECT_ID(c, 0, i, want[i]);
            EXPECT_EQ(el->TrustStatus.dwErrorStatus, 0);
            EXPECT_EQ(el->pRevocationInfo, NULL);        /* no revocation requested */
        }
    }
    pki_chain_free(c); pki_eng_close(&e);
}
TEST(chain_build_root_element_is_self_signed_only) {
    REQUIRE(U(CertGetCertificateChain));
    PKI_ENG e; CHECK(pki_eng_open(&e, "root", "inter", NULL, 0));
    PCCERT_CHAIN_CONTEXT c = pki_chain(e.h, "leaf", NULL, PKI_T0, PKI_OFFLINE, NULL);
    CHECK(c && c->cChain == 1 && c->rgpChain[0]->cElement == 3);
    if (c && c->cChain == 1 && c->rgpChain[0]->cElement == 3) {
        CHECK(pki_elem_info(c, 0, 2) & CERT_TRUST_IS_SELF_SIGNED);
        CHECK(!(pki_elem_info(c, 0, 0) & CERT_TRUST_IS_SELF_SIGNED));
        CHECK(!(pki_elem_info(c, 0, 1) & CERT_TRUST_IS_SELF_SIGNED));
        /* leaf and intermediate: HAS_KEY_MATCH_ISSUER (2) | HAS_NAME_MATCH_ISSUER (0x100); root adds IS_SELF_SIGNED (8), HAS_PREFERRED_ISSUER/TRUSTED bits */
        EXPECT_EQ(pki_elem_info(c, 0, 0), 0x102);
        EXPECT_EQ(pki_elem_info(c, 0, 1), 0x102);
        EXPECT_EQ(pki_elem_info(c, 0, 2), 0x210c);
    }
    pki_chain_free(c); pki_eng_close(&e);
}
TEST(chain_build_issuer_match_info_bits) {
    REQUIRE(U(CertGetCertificateChain));
    PKI_ENG e; CHECK(pki_eng_open(&e, "root", "inter", NULL, 0));
    PCCERT_CHAIN_CONTEXT c = pki_chain(e.h, "leaf", NULL, PKI_T0, PKI_OFFLINE, NULL);
    CHECK(c && c->cChain == 1 && c->rgpChain[0]->cElement == 3);
    if (c && c->cChain == 1 && c->rgpChain[0]->cElement == 3) {
        DWORD m = CERT_TRUST_HAS_EXACT_MATCH_ISSUER | CERT_TRUST_HAS_KEY_MATCH_ISSUER | CERT_TRUST_HAS_NAME_MATCH_ISSUER;
        CHECK(pki_elem_info(c, 0, 0) & m);     /* leaf and intermediate have an issuer in the chain */
        CHECK(pki_elem_info(c, 0, 1) & m);
    }
    pki_chain_free(c); pki_eng_close(&e);
}
TEST(chain_build_partial_chain_has_no_self_signed_top) {
    REQUIRE(U(CertGetCertificateChain));
    PKI_ENG e; CHECK(pki_eng_open(&e, "root", "", NULL, 0));
    PCCERT_CHAIN_CONTEXT c = pki_chain(e.h, "leaf", NULL, PKI_T0, PKI_OFFLINE, NULL);
    CHECK(c && c->cChain == 1);
    if (c && c->cChain == 1) {
        EXPECT_EQ(c->TrustStatus.dwErrorStatus, CERT_TRUST_IS_PARTIAL_CHAIN);
        CHECK(!(pki_elem_info(c, 0, c->rgpChain[0]->cElement - 1) & CERT_TRUST_IS_SELF_SIGNED));
    }
    pki_chain_free(c); pki_eng_close(&e);
}
TEST(chain_build_untrusted_root_error_on_root_element) {
    REQUIRE(U(CertGetCertificateChain));
    PKI_ENG e; CHECK(pki_eng_open(&e, "", "inter root", NULL, 0));
    PCCERT_CHAIN_CONTEXT c = pki_chain(e.h, "leaf", NULL, PKI_T0, PKI_OFFLINE, NULL);
    CHECK(c && c->cChain == 1 && c->rgpChain[0]->cElement == 3);
    if (c && c->cChain == 1 && c->rgpChain[0]->cElement == 3) {
        EXPECT_EQ(pki_elem_err(c, 0, 2), CERT_TRUST_IS_UNTRUSTED_ROOT);
        EXPECT_EQ(pki_elem_err(c, 0, 0), 0);
        EXPECT_EQ(pki_elem_err(c, 0, 1), 0);
        EXPECT_EQ(c->rgpChain[0]->TrustStatus.dwErrorStatus, CERT_TRUST_IS_UNTRUSTED_ROOT);
    }
    pki_chain_free(c); pki_eng_close(&e);
}
TEST(chain_build_time_error_on_expired_element_only) {
    REQUIRE(U(CertGetCertificateChain));
    PKI_ENG e; CHECK(pki_eng_open(&e, "root", "inter_short", NULL, 0));
    PCCERT_CHAIN_CONTEXT c = pki_chain(e.h, "leaf_short", NULL, PKI_T0, PKI_OFFLINE, NULL);
    CHECK(c && c->cChain == 1 && c->rgpChain[0]->cElement == 3);
    if (c && c->cChain == 1 && c->rgpChain[0]->cElement == 3) {
        EXPECT_EQ(pki_elem_err(c, 0, 0), 0);
        EXPECT_EQ(pki_elem_err(c, 0, 1), CERT_TRUST_IS_NOT_TIME_VALID);
        EXPECT_EQ(pki_elem_err(c, 0, 2), 0);
    }
    pki_chain_free(c); pki_eng_close(&e);
}
TEST(chain_build_time_error_on_leaf_element) {
    REQUIRE(U(CertGetCertificateChain));
    PKI_ENG e; CHECK(pki_eng_open(&e, "root", "inter", NULL, 0));
    PCCERT_CHAIN_CONTEXT c = pki_chain(e.h, "leaf_expired", NULL, PKI_T0, PKI_OFFLINE, NULL);
    CHECK(c && c->cChain == 1 && c->rgpChain[0]->cElement == 3);
    if (c && c->cChain == 1 && c->rgpChain[0]->cElement == 3) {
        EXPECT_EQ(pki_elem_err(c, 0, 0), CERT_TRUST_IS_NOT_TIME_VALID);
        EXPECT_EQ(pki_elem_err(c, 0, 1), 0);
        EXPECT_EQ(pki_elem_err(c, 0, 2), 0);
    }
    pki_chain_free(c); pki_eng_close(&e);
}
TEST(chain_build_basic_constraints_error_reported) {
    REQUIRE(U(CertGetCertificateChain));
    PKI_ENG e; CHECK(pki_eng_open(&e, "root", "inter_noca", NULL, 0));
    PCCERT_CHAIN_CONTEXT c = pki_chain(e.h, "leaf_noca", NULL, PKI_T0, PKI_OFFLINE, NULL);
    CHECK(c && c->cChain == 1 && c->rgpChain[0]->cElement == 3);
    if (c && c->cChain == 1 && c->rgpChain[0]->cElement == 3) {
        DWORD any = pki_elem_err(c, 0, 0) | pki_elem_err(c, 0, 1) | pki_elem_err(c, 0, 2);
        CHECK(any & CERT_TRUST_INVALID_BASIC_CONSTRAINTS);
        EXPECT_EQ(pki_elem_err(c, 0, 0), 0);
        EXPECT_EQ(pki_elem_err(c, 0, 1), CERT_TRUST_INVALID_BASIC_CONSTRAINTS);
        EXPECT_EQ(pki_elem_err(c, 0, 2), 0);
    }
    pki_chain_free(c); pki_eng_close(&e);
}
TEST(chain_build_pathlen_error_reported) {
    REQUIRE(U(CertGetCertificateChain));
    PKI_ENG e; CHECK(pki_eng_open(&e, "root", "inter_pl0 sub_ca", NULL, 0));
    PCCERT_CHAIN_CONTEXT c = pki_chain(e.h, "leaf_pl", NULL, PKI_T0, PKI_OFFLINE, NULL);
    CHECK(c && c->cChain == 1 && c->rgpChain[0]->cElement == 4);
    if (c && c->cChain == 1 && c->rgpChain[0]->cElement == 4) {
        DWORD any = 0; for (int i = 0; i < 4; i++) any |= pki_elem_err(c, 0, i);
        CHECK(any & CERT_TRUST_INVALID_BASIC_CONSTRAINTS);
        EXPECT_EQ(pki_elem_err(c, 0, 0), 0);
        EXPECT_EQ(pki_elem_err(c, 0, 1), 0);
        EXPECT_EQ(pki_elem_err(c, 0, 2), CERT_TRUST_INVALID_BASIC_CONSTRAINTS);   /* the pathLen 0 CA that has a sub CA below it */
        EXPECT_EQ(pki_elem_err(c, 0, 3), 0);
    }
    pki_chain_free(c); pki_eng_close(&e);
}
TEST(chain_build_element_certs_are_the_stored_certs) {
    REQUIRE(U(CertGetCertificateChain));
    PKI_ENG e; CHECK(pki_eng_open(&e, "root", "inter", NULL, 0));
    PCCERT_CHAIN_CONTEXT c = pki_chain(e.h, "leaf", NULL, PKI_T0, PKI_OFFLINE, NULL);
    CHECK(c && c->cChain == 1 && c->rgpChain[0]->cElement == 3);
    if (c && c->cChain == 1 && c->rgpChain[0]->cElement == 3) {
        PCCERT_CONTEXT x = c->rgpChain[0]->rgpElement[1]->pCertContext;
        const PKI_ITEM *it = pki_find("inter");
        EXPECT_EQ(x->cbCertEncoded, it->len);
        CHECK(!memcmp(x->pbCertEncoded, it->der, it->len));
        CHECK(x->pCertInfo != NULL && x->pCertInfo->SerialNumber.cbData > 0);
        CHECK((x->dwCertEncodingType & X509_ASN_ENCODING) != 0);
        EXPECT_EQ(x->pCertInfo->SerialNumber.pbData[x->pCertInfo->SerialNumber.cbData - 1], 0x02);   /* serial 0x0201, little endian blob: 01 02 */
    }
    pki_chain_free(c); pki_eng_close(&e);
}
TEST(chain_build_chain_holds_cert_references) {
    /* the input context may be freed right after the call; chain elements stay valid */
    REQUIRE(U(CertGetCertificateChain));
    PKI_ENG e; CHECK(pki_eng_open(&e, "root", "inter", NULL, 0));
    PCCERT_CHAIN_CONTEXT c = pki_chain(e.h, "leaf", NULL, PKI_T0, PKI_OFFLINE, NULL);   /* helper frees leaf + addl store */
    CHECK(c != NULL);
    if (c && c->cChain == 1 && c->rgpChain[0]->cElement == 3) {
        EXPECT_ID(c, 0, 0, "leaf");
        PCCERT_CONTEXT dup = U(CertDuplicateCertificateContext)(c->rgpChain[0]->rgpElement[0]->pCertContext);
        CHECK(dup != NULL);
        pki_chain_free(c); c = NULL;
        if (dup) { CHECK(dup->cbCertEncoded > 0); EXPECT_STR(pki_id_of(dup), "leaf"); U(CertFreeCertificateContext)(dup); }
    }
    pki_chain_free(c); pki_eng_close(&e);
}

/* ---- parameter validation ---- */
TEST(chain_build_null_para_fails_invalidarg) {
    REQUIRE(U(CertGetCertificateChain));
    PCCERT_CONTEXT cert = pki_cert("leaf");
    PCCERT_CHAIN_CONTEXT out = NULL;
    SET_ERR(0);
    BOOL r = U(CertGetCertificateChain)(NULL, cert, NULL, NULL, NULL, PKI_OFFLINE, NULL, &out);
    CHECK(!r); EXPECT_ERR(E_INVALIDARG); EXPECT_EQ(out, NULL);
    U(CertFreeCertificateContext)(cert);
}
TEST(chain_build_reserved_must_be_null) {
    REQUIRE(U(CertGetCertificateChain));
    PCCERT_CONTEXT cert = pki_cert("leaf");
    CERT_CHAIN_PARA p; memset(&p, 0, sizeof p); p.cbSize = sizeof p;
    PCCERT_CHAIN_CONTEXT out = NULL;
    SET_ERR(0);
    BOOL r = U(CertGetCertificateChain)(NULL, cert, NULL, NULL, &p, PKI_OFFLINE, (LPVOID)(ULONG_PTR)1, &out);
    CHECK(!r); EXPECT_ERR(E_INVALIDARG); EXPECT_EQ(out, NULL);
    U(CertFreeCertificateContext)(cert);
}
TEST(chain_build_para_cbsize_variants_accepted) {
    REQUIRE(U(CertGetCertificateChain));
    PKI_ENG e; CHECK(pki_eng_open(&e, "root", "inter", NULL, 0));
    DWORD sizes[] = { 0x20, 0x38, 0x3c, 0x40, 0x48, 0x50, 0x58, 0x60 };
    for (int i = 0; i < 8; i++) {
        CERT_CHAIN_PARA p; memset(&p, 0, sizeof p); p.cbSize = sizes[i];
        PCCERT_CHAIN_CONTEXT c = pki_chain(e.h, "leaf", NULL, PKI_T0, PKI_OFFLINE, &p);
        CHECKF(c != NULL, "CERT_CHAIN_PARA.cbSize 0x%lx", sizes[i]);
        if (c) EXPECT_EQ(c->TrustStatus.dwErrorStatus, 0);
        pki_chain_free(c);
    }
    pki_eng_close(&e);
}
TEST(chain_build_para_cbsize_zero_accepted) {
    REQUIRE(U(CertGetCertificateChain));
    PKI_ENG e; CHECK(pki_eng_open(&e, "root", "inter", NULL, 0));
    CERT_CHAIN_PARA p; memset(&p, 0, sizeof p); p.cbSize = 0;
    SET_ERR(0);
    PCCERT_CHAIN_CONTEXT c = pki_chain(e.h, "leaf", NULL, PKI_T0, PKI_OFFLINE, &p);
    CHECK(c != NULL);   /* a zero cbSize is accepted on Win10 22H2 */
    if (c) EXPECT_EQ(c->TrustStatus.dwErrorStatus, 0);
    pki_chain_free(c); pki_eng_close(&e);
}
TEST(chain_build_input_chain_pointer_cleared_or_set) {
    REQUIRE(U(CertGetCertificateChain));
    PKI_ENG e; CHECK(pki_eng_open(&e, "root", "inter", NULL, 0));
    PCCERT_CONTEXT cert = pki_cert("leaf");
    CERT_CHAIN_PARA p; memset(&p, 0, sizeof p); p.cbSize = sizeof p;
    PCCERT_CHAIN_CONTEXT out = (PCCERT_CHAIN_CONTEXT)(ULONG_PTR)0x1000;
    BOOL r = U(CertGetCertificateChain)(e.h, cert, NULL, NULL, &p, PKI_OFFLINE, NULL, &out);
    CHECK(r); CHECK(out != NULL && out != (PCCERT_CHAIN_CONTEXT)(ULONG_PTR)0x1000);
    if (r && out) pki_chain_free(out);
    U(CertFreeCertificateContext)(cert); pki_eng_close(&e);
}
TEST(chain_build_distinct_chains_for_distinct_calls) {
    REQUIRE(U(CertGetCertificateChain));
    PKI_ENG e; CHECK(pki_eng_open(&e, "root", "inter", NULL, 0));
    PCCERT_CHAIN_CONTEXT a = pki_chain(e.h, "leaf", NULL, PKI_T0, PKI_OFFLINE, NULL);
    PCCERT_CHAIN_CONTEXT b = pki_chain(e.h, "leaf", NULL, PKI_T0, PKI_OFFLINE, NULL);
    CHECK(a && b);
    if (a && b) { CHECK(a != b); }
    pki_chain_free(a); pki_chain_free(b); pki_eng_close(&e);
}

/* ---- chain flags that must be accepted and leave a good chain good ---- */
#define FLAGOK(nm, fl) SCEN(flag_##nm, "leaf", "root", "inter", NULL, PKI_T0, fl, NOERR, 3)
FLAGOK(disable_pass1_quality_filtering, CERT_CHAIN_DISABLE_PASS1_QUALITY_FILTERING)
FLAGOK(return_lower_quality_contexts, CERT_CHAIN_RETURN_LOWER_QUALITY_CONTEXTS)
FLAGOK(disable_auth_root_auto_update, CERT_CHAIN_DISABLE_AUTH_ROOT_AUTO_UPDATE)
FLAGOK(timestamp_time, CERT_CHAIN_TIMESTAMP_TIME)
FLAGOK(enable_peer_trust, CERT_CHAIN_ENABLE_PEER_TRUST)
FLAGOK(disable_my_peer_trust, CERT_CHAIN_DISABLE_MY_PEER_TRUST)
FLAGOK(cache_only_url, CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL)
FLAGOK(all_combined, CERT_CHAIN_DISABLE_PASS1_QUALITY_FILTERING | CERT_CHAIN_RETURN_LOWER_QUALITY_CONTEXTS | CERT_CHAIN_DISABLE_AUTH_ROOT_AUTO_UPDATE | CERT_CHAIN_ENABLE_PEER_TRUST)
SCEN(flag_timestamp_time_expired_leaf_pTime_before_expiry, "leaf_expired", "root", "inter", NULL, T(2021,6,1,0,0,0), CERT_CHAIN_TIMESTAMP_TIME, TIME_OK, 3) /* Win10: the flag does not suppress NOT_TIME_VALID; probed */
SCEN(flag_timestamp_time_expired_leaf_pTime_after_expiry, "leaf_expired", "root", "inter", NULL, T(2025,6,1,0,0,0), CERT_CHAIN_TIMESTAMP_TIME, TIME_OK, 3)

/* ---- lower quality contexts only on request ---- */
TEST(chain_build_lower_quality_empty_without_flag) {
    REQUIRE(U(CertGetCertificateChain));
    PKI_ENG e; CHECK(pki_eng_open(&e, "root root2", "inter inter_x root2", NULL, 0));
    PCCERT_CHAIN_CONTEXT c = pki_chain(e.h, "leaf", NULL, PKI_T0, PKI_OFFLINE, NULL);
    CHECK(c != NULL);
    if (c) { pki_note_chain("two candidate paths", c); EXPECT_EQ(c->cLowerQualityChainContext, 0); EXPECT_EQ(c->rgpLowerQualityChainContext, NULL); EXPECT_EQ(c->TrustStatus.dwErrorStatus, 0); }
    pki_chain_free(c); pki_eng_close(&e);
}
TEST(chain_build_lower_quality_with_flag) {
    REQUIRE(U(CertGetCertificateChain));
    PKI_ENG e; CHECK(pki_eng_open(&e, "root root2", "inter inter_x root2", NULL, 0));
    PCCERT_CHAIN_CONTEXT c = pki_chain(e.h, "leaf", NULL, PKI_T0, PKI_OFFLINE | CERT_CHAIN_RETURN_LOWER_QUALITY_CONTEXTS, NULL);
    CHECK(c != NULL);
    if (c) {
        pki_note_chain("best", c);
        EXPECT_EQ(c->cLowerQualityChainContext, 1);   /* the cross-signed path through root2 */
        EXPECT_EQ(c->TrustStatus.dwErrorStatus, 0);
        for (DWORD i = 0; i < c->cLowerQualityChainContext; i++) {
            PCCERT_CHAIN_CONTEXT lq = c->rgpLowerQualityChainContext[i];
            CHECK(lq != NULL);
            if (lq) { pki_note_chain("lower", lq); EXPECT_EQ(lq->cLowerQualityChainContext, 0); }
        }
    }
    pki_chain_free(c); pki_eng_close(&e);
}
