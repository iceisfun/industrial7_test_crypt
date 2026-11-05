/* Policies, distribution points, AIA, name constraints, CRL reason, times, Microsoft extensions. */
#include "asn.h"

static const WCHAR wurl[] = { 'h','t','t','p',':','/','/','x',0 };
static const WCHAR wurl2[] = { 'h','t','t','p',':','/','/','y',0 };
static const WCHAR wdns[] = { 'a','.','c','o','m',0 };
static const WCHAR wmail[] = { 'x','@','y','.','z',0 };

/* ---- certificate policies ------------------------------------------------ */
TEST(policies_encode_empty_and_simple) {
    REQUIRE(U(CryptEncodeObjectEx));
    CERT_POLICIES_INFO s = { 0, NULL };
    ENC_EQ(X509_CERT_POLICIES, &s, v_pol_none);
    CERT_POLICY_INFO pi = { (LPSTR)"1.2.3", 0, NULL };
    s.cPolicyInfo = 1; s.rgPolicyInfo = &pi;
    ENC_EQ(X509_CERT_POLICIES, &s, v_pol_one);
    ENC_EQ(szOID_CERT_POLICIES, &s, v_pol_one);
}
TEST(policies_encode_cps_qualifier) {
    REQUIRE(U(CryptEncodeObjectEx));
    static const BYTE q[] = { 0x16, 0x08, 'h','t','t','p',':','/','/','x' };
    CERT_POLICY_QUALIFIER_INFO qi = { (LPSTR)szOID_PKIX_POLICY_QUALIFIER_CPS, { sizeof q, (BYTE *)q } };
    CERT_POLICY_INFO pi = { (LPSTR)"1.2.3", 1, &qi };
    CERT_POLICIES_INFO s = { 1, &pi };
    ENC_EQ(X509_CERT_POLICIES, &s, v_pol_cps);
}
TEST(policies_encode_two_policies_two_qualifiers) {
    REQUIRE(U(CryptEncodeObjectEx));
    static const BYTE q1[] = { 0x16, 0x01, 'a' };
    CERT_POLICY_QUALIFIER_INFO qi[2] = { { (LPSTR)szOID_PKIX_POLICY_QUALIFIER_CPS, { sizeof q1, (BYTE *)q1 } }, { (LPSTR)szOID_PKIX_POLICY_QUALIFIER_USERNOTICE, { 0, NULL } } };
    CERT_POLICY_INFO pi[2] = { { (LPSTR)"1.2.3", 2, qi }, { (LPSTR)szOID_ANY_CERT_POLICY, 0, NULL } };
    CERT_POLICIES_INFO s = { 2, pi };
    ENC_EQ(X509_CERT_POLICIES, &s, v_pol_two_q);
}
TEST(policies_decode) {
    REQUIRE(U(CryptDecodeObjectEx));
    CERT_POLICIES_INFO *d = DEC(X509_CERT_POLICIES, v_pol_two_q, 0, NULL);
    if (d) {
        CHECK(d->cPolicyInfo == 2);
        if (d->cPolicyInfo == 2) {
            CHECK(!strcmp(d->rgPolicyInfo[0].pszPolicyIdentifier, "1.2.3"));
            CHECK(d->rgPolicyInfo[0].cPolicyQualifier == 2);
            if (d->rgPolicyInfo[0].cPolicyQualifier == 2) {
                CERT_POLICY_QUALIFIER_INFO *q = d->rgPolicyInfo[0].rgPolicyQualifier;
                CHECK(!strcmp(q[0].pszPolicyQualifierId, szOID_PKIX_POLICY_QUALIFIER_CPS));
                CHECK(q[0].Qualifier.cbData == 3 && !memcmp(q[0].Qualifier.pbData, "\x16\x01" "a", 3));
                CHECK(!strcmp(q[1].pszPolicyQualifierId, szOID_PKIX_POLICY_QUALIFIER_USERNOTICE));
                CHECK(q[1].Qualifier.cbData == 0);
            }
            CHECK(!strcmp(d->rgPolicyInfo[1].pszPolicyIdentifier, "2.5.29.32.0") && d->rgPolicyInfo[1].cPolicyQualifier == 0);
        }
        LocalFree(d);
    }
    d = DEC(X509_CERT_POLICIES, v_pol_none, 0, NULL);
    if (d) { CHECK(d->cPolicyInfo == 0); LocalFree(d); }
    ROUNDTRIP(X509_CERT_POLICIES, v_pol_one);
    ROUNDTRIP(X509_CERT_POLICIES, v_pol_cps);
    ROUNDTRIP(X509_CERT_POLICIES, v_pol_two_q);
    ROUNDTRIP(szOID_CERT_POLICIES, v_pol_none);
}
TEST(policies_decode_nocopy_qualifier) {
    REQUIRE(U(CryptDecodeObjectEx));
    DWORD c1, c2;
    CERT_POLICIES_INFO *a = DEC(X509_CERT_POLICIES, v_pol_cps, 0, &c1), *n = DEC(X509_CERT_POLICIES, v_pol_cps, CRYPT_DECODE_NOCOPY_FLAG, &c2);
    if (n) {
        CERT_POLICY_QUALIFIER_INFO *q = n->rgPolicyInfo[0].rgPolicyQualifier;
        CHECK(q[0].Qualifier.cbData == 10);
        t_note("policy qualifier NOCOPY: %s (size %lu vs %lu)", PTR_IN(q[0].Qualifier.pbData, v_pol_cps, sizeof v_pol_cps) ? "in place" : "copied", c2, c1);
        LocalFree(n);
    }
    if (a) LocalFree(a);
}
TEST(policies_decode_errors) {
    REQUIRE(U(CryptDecodeObjectEx));
    a_dec_fail(__FILE__, __LINE__, X509_CERT_POLICIES, v_bc2_ca, sizeof v_bc2_ca, 0, 0);
    BYTE trunc[sizeof v_pol_one - 1]; memcpy(trunc, v_pol_one, sizeof trunc);
    a_dec_fail(__FILE__, __LINE__, X509_CERT_POLICIES, trunc, sizeof trunc, 0, HR_ASN1_EOD);
}
TEST(policies_encode_invalid_oid) {
    REQUIRE(U(CryptEncodeObjectEx));
    CERT_POLICY_INFO pi = { (LPSTR)"1.2.zz", 0, NULL }; CERT_POLICIES_INFO s = { 1, &pi };
    DWORD cb = 0; SET_ERR(0);
    BOOL r = U(CryptEncodeObjectEx)(ENC, X509_CERT_POLICIES, &s, 0, NULL, NULL, &cb);
    CHECK(!r); t_note("malformed policy OID: err 0x%lx", GetLastError());
}
TEST(application_policies_alias_probe) {
    REQUIRE(U(CryptEncodeObjectEx));
    CERT_POLICY_INFO pi = { (LPSTR)"1.2.3", 0, NULL }; CERT_POLICIES_INFO s = { 1, &pi };
    DWORD cb = 0; BYTE *p = a_enc(szOID_APPLICATION_CERT_POLICIES, &s, 0, &cb);
    if (!p) { t_note("szOID_APPLICATION_CERT_POLICIES encode: err 0x%lx", GetLastError()); return; }
    CHECK(cb == sizeof v_pol_one && !memcmp(p, v_pol_one, cb));
    LocalFree(p);
}

/* ---- policy mappings / constraints ------------------------------------- */
TEST(policy_mappings) {
    REQUIRE(U(CryptEncodeObjectEx));
    CERT_POLICY_MAPPINGS_INFO s = { 0, NULL };
    ENC_EQ(X509_POLICY_MAPPINGS, &s, v_pmap_none);
    CERT_POLICY_MAPPING m = { (LPSTR)"1.2.3", (LPSTR)"1.2.4" };
    s.cPolicyMapping = 1; s.rgPolicyMapping = &m;
    ENC_EQ(X509_POLICY_MAPPINGS, &s, v_pmap_one);
    ENC_EQ(szOID_POLICY_MAPPINGS, &s, v_pmap_one);
    CERT_POLICY_MAPPINGS_INFO *d = DEC(X509_POLICY_MAPPINGS, v_pmap_one, 0, NULL);
    if (d) { CHECK(d->cPolicyMapping == 1 && !strcmp(d->rgPolicyMapping[0].pszIssuerDomainPolicy, "1.2.3") && !strcmp(d->rgPolicyMapping[0].pszSubjectDomainPolicy, "1.2.4")); LocalFree(d); }
    d = DEC(X509_POLICY_MAPPINGS, v_pmap_none, 0, NULL);
    if (d) { CHECK(d->cPolicyMapping == 0); LocalFree(d); }
    ROUNDTRIP(X509_POLICY_MAPPINGS, v_pmap_one);
    a_dec_fail(__FILE__, __LINE__, X509_POLICY_MAPPINGS, v_ku_ds, sizeof v_ku_ds, 0, HR_ASN1_BADTAG);
}
TEST(policy_mappings_application_probe) {
    REQUIRE(U(CryptEncodeObjectEx));
    CERT_POLICY_MAPPING m = { (LPSTR)"1.2.3", (LPSTR)"1.2.4" }; CERT_POLICY_MAPPINGS_INFO s = { 1, &m };
    DWORD cb = 0; BYTE *p = a_enc(szOID_APPLICATION_POLICY_MAPPINGS, &s, 0, &cb);
    if (!p) { t_note("szOID_APPLICATION_POLICY_MAPPINGS: err 0x%lx", GetLastError()); return; }
    CHECK(cb == sizeof v_pmap_one && !memcmp(p, v_pmap_one, cb));
    LocalFree(p);
}
TEST(policy_constraints_encode) {
    REQUIRE(U(CryptEncodeObjectEx));
    CERT_POLICY_CONSTRAINTS_INFO s; memset(&s, 0, sizeof s);
    ENC_EQ(X509_POLICY_CONSTRAINTS, &s, v_pcon_empty);
    ENC_EQ(szOID_POLICY_CONSTRAINTS, &s, v_pcon_empty);
    s.fRequireExplicitPolicy = TRUE; s.dwRequireExplicitPolicySkipCerts = 0;
    ENC_EQ(X509_POLICY_CONSTRAINTS, &s, v_pcon_req0);
    s.dwRequireExplicitPolicySkipCerts = 2; s.fInhibitPolicyMapping = TRUE; s.dwInhibitPolicyMappingSkipCerts = 1;
    ENC_EQ(X509_POLICY_CONSTRAINTS, &s, v_pcon_req2_inh1);
    memset(&s, 0, sizeof s); s.fInhibitPolicyMapping = TRUE; s.dwInhibitPolicyMappingSkipCerts = 5;
    ENC_EQ(X509_POLICY_CONSTRAINTS, &s, v_pcon_inh_only);
}
TEST(policy_constraints_decode) {
    REQUIRE(U(CryptDecodeObjectEx));
    CERT_POLICY_CONSTRAINTS_INFO *d = DEC(X509_POLICY_CONSTRAINTS, v_pcon_req2_inh1, 0, NULL);
    if (d) { CHECK(d->fRequireExplicitPolicy && d->dwRequireExplicitPolicySkipCerts == 2 && d->fInhibitPolicyMapping && d->dwInhibitPolicyMappingSkipCerts == 1); LocalFree(d); }
    d = DEC(X509_POLICY_CONSTRAINTS, v_pcon_req0, 0, NULL);
    if (d) { CHECK(d->fRequireExplicitPolicy && d->dwRequireExplicitPolicySkipCerts == 0 && !d->fInhibitPolicyMapping); LocalFree(d); }
    d = DEC(X509_POLICY_CONSTRAINTS, v_pcon_inh_only, 0, NULL);
    if (d) { CHECK(!d->fRequireExplicitPolicy && d->fInhibitPolicyMapping && d->dwInhibitPolicyMappingSkipCerts == 5); LocalFree(d); }
    d = DEC(X509_POLICY_CONSTRAINTS, v_pcon_empty, 0, NULL);
    if (d) { CHECK(!d->fRequireExplicitPolicy && !d->fInhibitPolicyMapping); LocalFree(d); }
    ROUNDTRIP(X509_POLICY_CONSTRAINTS, v_pcon_req2_inh1);
    ROUNDTRIP(X509_POLICY_CONSTRAINTS, v_pcon_inh_only);
    ROUNDTRIP(X509_POLICY_CONSTRAINTS, v_pcon_req0);
}

/* ---- CRL distribution points ------------------------------------------- */
static void dp_url(CRL_DIST_POINT *dp, CERT_ALT_NAME_ENTRY *e, const WCHAR *u) {
    memset(dp, 0, sizeof *dp); memset(e, 0, sizeof *e);
    e->dwAltNameChoice = CERT_ALT_NAME_URL; e->pwszURL = (LPWSTR)u;
    dp->DistPointName.dwDistPointNameChoice = CRL_DIST_POINT_FULL_NAME;
    dp->DistPointName.FullName.cAltEntry = 1; dp->DistPointName.FullName.rgAltEntry = e;
}
TEST(crldp_encode) {
    REQUIRE(U(CryptEncodeObjectEx));
    CRL_DIST_POINTS_INFO s = { 0, NULL };
    ENC_EQ(X509_CRL_DIST_POINTS, &s, v_cdp_empty);
    CERT_ALT_NAME_ENTRY e; CRL_DIST_POINT dp; dp_url(&dp, &e, wurl);
    s.cDistPoint = 1; s.rgDistPoint = &dp;
    ENC_EQ(X509_CRL_DIST_POINTS, &s, v_cdp_url);
    ENC_EQ(szOID_CRL_DIST_POINTS, &s, v_cdp_url);
    static BYTE rf = 0x80;
    dp.ReasonFlags.cbData = 1; dp.ReasonFlags.pbData = &rf; dp.ReasonFlags.cUnusedBits = 7;
    ENC_EQ(X509_CRL_DIST_POINTS, &s, v_cdp_url_reason);
}
TEST(crldp_encode_issuer_and_multiple) {
    REQUIRE(U(CryptEncodeObjectEx));
    CERT_ALT_NAME_ENTRY ie = { CERT_ALT_NAME_DIRECTORY_NAME };
    ie.DirectoryName.cbData = sizeof v_name_cn_test; ie.DirectoryName.pbData = (BYTE *)v_name_cn_test;
    CRL_DIST_POINT dp; memset(&dp, 0, sizeof dp);
    dp.CRLIssuer.cAltEntry = 1; dp.CRLIssuer.rgAltEntry = &ie;
    CRL_DIST_POINTS_INFO s = { 1, &dp };
    ENC_EQ(X509_CRL_DIST_POINTS, &s, v_cdp_issuer_only);
    CERT_ALT_NAME_ENTRY e[2]; CRL_DIST_POINT d2[2];
    dp_url(&d2[0], &e[0], wurl); dp_url(&d2[1], &e[1], wurl2);
    CRL_DIST_POINTS_INFO m = { 2, d2 };
    ENC_EQ(X509_CRL_DIST_POINTS, &m, v_cdp_two);
    memset(&dp, 0, sizeof dp);
    CRL_DIST_POINTS_INFO n = { 1, &dp };
    ENC_EQ(X509_CRL_DIST_POINTS, &n, v_cdp_noname);
}
TEST(crldp_decode) {
    REQUIRE(U(CryptDecodeObjectEx));
    CRL_DIST_POINTS_INFO *d = DEC(X509_CRL_DIST_POINTS, v_cdp_url_reason, 0, NULL);
    if (d) {
        CHECK(d->cDistPoint == 1);
        if (d->cDistPoint == 1) {
            CRL_DIST_POINT *p = &d->rgDistPoint[0];
            CHECK(p->DistPointName.dwDistPointNameChoice == CRL_DIST_POINT_FULL_NAME);
            CHECK(p->DistPointName.FullName.cAltEntry == 1 && p->DistPointName.FullName.rgAltEntry[0].dwAltNameChoice == CERT_ALT_NAME_URL);
            CHECK(!lstrcmpW(p->DistPointName.FullName.rgAltEntry[0].pwszURL, wurl));
            CHECK(p->ReasonFlags.cbData == 1 && p->ReasonFlags.pbData[0] == 0x80 && p->ReasonFlags.cUnusedBits == 7);
            CHECK(p->CRLIssuer.cAltEntry == 0);
        }
        LocalFree(d);
    }
    d = DEC(X509_CRL_DIST_POINTS, v_cdp_issuer_only, 0, NULL);
    if (d) { CHECK(d->rgDistPoint[0].DistPointName.dwDistPointNameChoice == CRL_DIST_POINT_NO_NAME); CHECK(d->rgDistPoint[0].CRLIssuer.cAltEntry == 1); LocalFree(d); }
    d = DEC(X509_CRL_DIST_POINTS, v_cdp_two, 0, NULL);
    if (d) { CHECK(d->cDistPoint == 2); if (d->cDistPoint == 2) CHECK(!lstrcmpW(d->rgDistPoint[1].DistPointName.FullName.rgAltEntry[0].pwszURL, wurl2)); LocalFree(d); }
    d = DEC(X509_CRL_DIST_POINTS, v_cdp_noname, 0, NULL);
    if (d) { CHECK(d->cDistPoint == 1 && d->rgDistPoint[0].DistPointName.dwDistPointNameChoice == CRL_DIST_POINT_NO_NAME); LocalFree(d); }
    d = DEC(X509_CRL_DIST_POINTS, v_cdp_empty, 0, NULL);
    if (d) { CHECK(d->cDistPoint == 0); LocalFree(d); }
    ROUNDTRIP(X509_CRL_DIST_POINTS, v_cdp_url);
    ROUNDTRIP(X509_CRL_DIST_POINTS, v_cdp_url_reason);
    ROUNDTRIP(X509_CRL_DIST_POINTS, v_cdp_two);
    ROUNDTRIP(X509_CRL_DIST_POINTS, v_cdp_issuer_only);
}
TEST(crldp_decode_issuer_rdn_name_probe) {
    REQUIRE(U(CryptDecodeObjectEx));
    DWORD cb = 0; void *p = NULL; SET_ERR(0);
    BOOL r = U(CryptDecodeObjectEx)(ENC, X509_CRL_DIST_POINTS, v_cdp_rdn, sizeof v_cdp_rdn, CRYPT_DECODE_ALLOC_FLAG, NULL, &p, &cb);
    t_note("distributionPoint nameRelativeToCRLIssuer: ok=%d err=0x%lx", r, GetLastError());
    if (r) LocalFree(p);
}
TEST(crldp_encode_rdn_choice_probe) {
    REQUIRE(U(CryptEncodeObjectEx));
    CRL_DIST_POINT dp; memset(&dp, 0, sizeof dp); dp.DistPointName.dwDistPointNameChoice = CRL_DIST_POINT_ISSUER_RDN_NAME;
    CRL_DIST_POINTS_INFO s = { 1, &dp };
    DWORD cb = 0; SET_ERR(0);
    BOOL r = U(CryptEncodeObjectEx)(ENC, X509_CRL_DIST_POINTS, &s, 0, NULL, NULL, &cb);
    t_note("encode ISSUER_RDN_NAME choice: ok=%d err=0x%lx", r, GetLastError());
    dp.DistPointName.dwDistPointNameChoice = 9; SET_ERR(0);
    r = U(CryptEncodeObjectEx)(ENC, X509_CRL_DIST_POINTS, &s, 0, NULL, NULL, &cb);
    CHECK(!r); t_note("encode bogus choice 9: err=0x%lx", GetLastError());
}
TEST(crldp_decode_truncated) {
    REQUIRE(U(CryptDecodeObjectEx));
    for (DWORD cut = 0; cut + 1 < sizeof v_cdp_url; cut++) {
        DWORD cb = 0; SET_ERR(0);
        BOOL r = U(CryptDecodeObjectEx)(ENC, X509_CRL_DIST_POINTS, v_cdp_url, cut, 0, NULL, NULL, &cb);
        CHECKF(!r, "cut %lu succeeded", cut);
    }
}

/* ---- authority info access --------------------------------------------- */
TEST(aia_encode_decode) {
    REQUIRE(U(CryptEncodeObjectEx));
    CERT_AUTHORITY_INFO_ACCESS s = { 0, NULL };
    ENC_EQ(X509_AUTHORITY_INFO_ACCESS, &s, v_aia_empty);
    static const WCHAR wo[] = { 'h','t','t','p',':','/','/','o',0 };
    CERT_ACCESS_DESCRIPTION ad = { (LPSTR)szOID_PKIX_OCSP, { CERT_ALT_NAME_URL } };
    ad.AccessLocation.pwszURL = (LPWSTR)wo;
    s.cAccDescr = 1; s.rgAccDescr = &ad;
    ENC_EQ(X509_AUTHORITY_INFO_ACCESS, &s, v_aia_ocsp);
    ENC_EQ(szOID_AUTHORITY_INFO_ACCESS, &s, v_aia_ocsp);
    CERT_ACCESS_DESCRIPTION two[2] = { ad, { (LPSTR)szOID_PKIX_CA_ISSUERS, { CERT_ALT_NAME_DNS_NAME } } };
    static const WCHAR wc[] = { 'c','a','.','e','x','a','m','p','l','e',0 };
    two[1].AccessLocation.pwszDNSName = (LPWSTR)wc;
    s.cAccDescr = 2; s.rgAccDescr = two;
    ENC_EQ(X509_AUTHORITY_INFO_ACCESS, &s, v_aia_two);
    CERT_AUTHORITY_INFO_ACCESS *d = DEC(X509_AUTHORITY_INFO_ACCESS, v_aia_two, 0, NULL);
    if (d) {
        CHECK(d->cAccDescr == 2);
        if (d->cAccDescr == 2) {
            CHECK(!strcmp(d->rgAccDescr[0].pszAccessMethod, szOID_PKIX_OCSP) && d->rgAccDescr[0].AccessLocation.dwAltNameChoice == CERT_ALT_NAME_URL);
            CHECK(!lstrcmpW(d->rgAccDescr[0].AccessLocation.pwszURL, wo));
            CHECK(!strcmp(d->rgAccDescr[1].pszAccessMethod, szOID_PKIX_CA_ISSUERS) && !lstrcmpW(d->rgAccDescr[1].AccessLocation.pwszDNSName, wc));
        }
        LocalFree(d);
    }
    d = DEC(X509_AUTHORITY_INFO_ACCESS, v_aia_empty, 0, NULL);
    if (d) { CHECK(d->cAccDescr == 0); LocalFree(d); }
    ROUNDTRIP(X509_AUTHORITY_INFO_ACCESS, v_aia_ocsp);
    ROUNDTRIP(X509_AUTHORITY_INFO_ACCESS, v_aia_two);
    ROUNDTRIP(szOID_AUTHORITY_INFO_ACCESS, v_aia_two);
    DEC_FAIL(X509_AUTHORITY_INFO_ACCESS, v_bc2_ca, 0);
}
TEST(aia_subject_info_access_probe) {
    REQUIRE(U(CryptDecodeObjectEx));
    DWORD cb = 0; void *p = NULL; SET_ERR(0);
    BOOL r = U(CryptDecodeObjectEx)(ENC, szOID_SUBJECT_INFO_ACCESS, v_aia_ocsp, sizeof v_aia_ocsp, CRYPT_DECODE_ALLOC_FLAG, NULL, &p, &cb);
    t_note("szOID_SUBJECT_INFO_ACCESS decode: ok=%d err=0x%lx", r, GetLastError());
    if (r) LocalFree(p);
}

/* ---- issuing distribution point ----------------------------------------- */
TEST(idp_encode) {
    REQUIRE(U(CryptEncodeObjectEx));
    CRL_ISSUING_DIST_POINT s; memset(&s, 0, sizeof s);
    ENC_EQ(X509_ISSUING_DIST_POINT, &s, v_idp_empty);
    ENC_EQ(szOID_ISSUING_DIST_POINT, &s, v_idp_empty);
    s.fOnlyContainsUserCerts = TRUE; ENC_EQ(X509_ISSUING_DIST_POINT, &s, v_idp_user);
    s.fOnlyContainsUserCerts = FALSE; s.fOnlyContainsCACerts = TRUE; ENC_EQ(X509_ISSUING_DIST_POINT, &s, v_idp_ca);
    s.fOnlyContainsCACerts = FALSE; s.fIndirectCRL = TRUE; ENC_EQ(X509_ISSUING_DIST_POINT, &s, v_idp_indirect);
    s.fOnlyContainsUserCerts = TRUE; ENC_EQ(X509_ISSUING_DIST_POINT, &s, v_idp_user_indirect);
    memset(&s, 0, sizeof s);
    CERT_ALT_NAME_ENTRY e; CRL_DIST_POINT dp; dp_url(&dp, &e, wurl);
    s.DistPointName = dp.DistPointName;
    ENC_EQ(X509_ISSUING_DIST_POINT, &s, v_idp_url);
    memset(&s, 0, sizeof s);
    static BYTE rf = 0x80; s.OnlySomeReasonFlags.cbData = 1; s.OnlySomeReasonFlags.pbData = &rf; s.OnlySomeReasonFlags.cUnusedBits = 1;
    static const BYTE exp[] = { 0x30, 0x04, 0x83, 0x02, 0x01, 0x80 };
    ENC_EQ(X509_ISSUING_DIST_POINT, &s, exp);
}
TEST(idp_decode) {
    REQUIRE(U(CryptDecodeObjectEx));
    CRL_ISSUING_DIST_POINT *d = DEC(X509_ISSUING_DIST_POINT, v_idp_user_indirect, 0, NULL);
    if (d) { CHECK(d->fOnlyContainsUserCerts && !d->fOnlyContainsCACerts && d->fIndirectCRL && d->DistPointName.dwDistPointNameChoice == CRL_DIST_POINT_NO_NAME); LocalFree(d); }
    d = DEC(X509_ISSUING_DIST_POINT, v_idp_ca, 0, NULL);
    if (d) { CHECK(!d->fOnlyContainsUserCerts && d->fOnlyContainsCACerts && !d->fIndirectCRL); LocalFree(d); }
    d = DEC(X509_ISSUING_DIST_POINT, v_idp_url, 0, NULL);
    if (d) { CHECK(d->DistPointName.dwDistPointNameChoice == CRL_DIST_POINT_FULL_NAME && d->DistPointName.FullName.cAltEntry == 1 && !lstrcmpW(d->DistPointName.FullName.rgAltEntry[0].pwszURL, wurl)); LocalFree(d); }
    d = DEC(X509_ISSUING_DIST_POINT, v_idp_reasons, 0, NULL);
    if (d) { CHECK(d->OnlySomeReasonFlags.cbData == 1 && d->OnlySomeReasonFlags.pbData[0] == 0x80 && d->OnlySomeReasonFlags.cUnusedBits == 6); LocalFree(d); }
    d = DEC(X509_ISSUING_DIST_POINT, v_idp_empty, 0, NULL);
    if (d) { CHECK(!d->fOnlyContainsUserCerts && !d->fOnlyContainsCACerts && !d->fIndirectCRL && d->OnlySomeReasonFlags.cbData == 0); LocalFree(d); }
    ROUNDTRIP(X509_ISSUING_DIST_POINT, v_idp_user);
    ROUNDTRIP(X509_ISSUING_DIST_POINT, v_idp_indirect);
    ROUNDTRIP(X509_ISSUING_DIST_POINT, v_idp_url);
    ROUNDTRIP(X509_ISSUING_DIST_POINT, v_idp_reasons);
}

/* ---- name constraints ---------------------------------------------------- */
TEST(nameconstraints_encode) {
    REQUIRE(U(CryptEncodeObjectEx));
    CERT_NAME_CONSTRAINTS_INFO s; memset(&s, 0, sizeof s);
    ENC_EQ(X509_NAME_CONSTRAINTS, &s, v_nc_empty);
    ENC_EQ(szOID_NAME_CONSTRAINTS, &s, v_nc_empty);
    CERT_GENERAL_SUBTREE a; memset(&a, 0, sizeof a); a.Base.dwAltNameChoice = CERT_ALT_NAME_DNS_NAME; a.Base.pwszDNSName = (LPWSTR)wdns;
    s.cPermittedSubtree = 1; s.rgPermittedSubtree = &a;
    ENC_EQ(X509_NAME_CONSTRAINTS, &s, v_nc_perm);
    s.cPermittedSubtree = 0; s.cExcludedSubtree = 1; s.rgExcludedSubtree = &a;
    ENC_EQ(X509_NAME_CONSTRAINTS, &s, v_nc_excl);
    CERT_GENERAL_SUBTREE p[2]; memset(p, 0, sizeof p);
    p[0] = a; p[1].Base.dwAltNameChoice = CERT_ALT_NAME_RFC822_NAME; p[1].Base.pwszRfc822Name = (LPWSTR)wmail;
    CERT_GENERAL_SUBTREE x; memset(&x, 0, sizeof x); x.Base.dwAltNameChoice = CERT_ALT_NAME_URL; x.Base.pwszURL = (LPWSTR)wurl;
    s.cPermittedSubtree = 2; s.rgPermittedSubtree = p; s.cExcludedSubtree = 1; s.rgExcludedSubtree = &x;
    ENC_EQ(X509_NAME_CONSTRAINTS, &s, v_nc_both);
}
TEST(nameconstraints_encode_min_max) {
    REQUIRE(U(CryptEncodeObjectEx));
    CERT_NAME_CONSTRAINTS_INFO s; memset(&s, 0, sizeof s);
    CERT_GENERAL_SUBTREE a; memset(&a, 0, sizeof a); a.Base.dwAltNameChoice = CERT_ALT_NAME_DNS_NAME; a.Base.pwszDNSName = (LPWSTR)wdns;
    a.dwMinimum = 1; a.fMaximum = TRUE; a.dwMaximum = 5;
    s.cPermittedSubtree = 1; s.rgPermittedSubtree = &a;
    ENC_EQ(X509_NAME_CONSTRAINTS, &s, v_nc_minmax);
    a.dwMinimum = 0; a.dwMaximum = 0;
    ENC_EQ(X509_NAME_CONSTRAINTS, &s, v_nc_max0);
}
TEST(nameconstraints_decode) {
    REQUIRE(U(CryptDecodeObjectEx));
    CERT_NAME_CONSTRAINTS_INFO *d = DEC(X509_NAME_CONSTRAINTS, v_nc_both, 0, NULL);
    if (d) {
        CHECK(d->cPermittedSubtree == 2 && d->cExcludedSubtree == 1);
        if (d->cPermittedSubtree == 2 && d->cExcludedSubtree == 1) {
            CHECK(d->rgPermittedSubtree[0].Base.dwAltNameChoice == CERT_ALT_NAME_DNS_NAME && !lstrcmpW(d->rgPermittedSubtree[0].Base.pwszDNSName, wdns));
            CHECK(d->rgPermittedSubtree[1].Base.dwAltNameChoice == CERT_ALT_NAME_RFC822_NAME && !lstrcmpW(d->rgPermittedSubtree[1].Base.pwszRfc822Name, wmail));
            CHECK(d->rgExcludedSubtree[0].Base.dwAltNameChoice == CERT_ALT_NAME_URL);
            CHECK(d->rgPermittedSubtree[0].dwMinimum == 0 && !d->rgPermittedSubtree[0].fMaximum);
        }
        LocalFree(d);
    }
    d = DEC(X509_NAME_CONSTRAINTS, v_nc_minmax, 0, NULL);
    if (d) { CERT_GENERAL_SUBTREE *g = d->rgPermittedSubtree; CHECK(g->dwMinimum == 1 && g->fMaximum && g->dwMaximum == 5); LocalFree(d); }
    d = DEC(X509_NAME_CONSTRAINTS, v_nc_max0, 0, NULL);
    if (d) { CERT_GENERAL_SUBTREE *g = d->rgPermittedSubtree; CHECK(g->dwMinimum == 0 && g->fMaximum && g->dwMaximum == 0); LocalFree(d); }
    d = DEC(X509_NAME_CONSTRAINTS, v_nc_empty, 0, NULL);
    if (d) { CHECK(d->cPermittedSubtree == 0 && d->cExcludedSubtree == 0); LocalFree(d); }
    ROUNDTRIP(X509_NAME_CONSTRAINTS, v_nc_both);
    ROUNDTRIP(X509_NAME_CONSTRAINTS, v_nc_minmax);
    ROUNDTRIP(X509_NAME_CONSTRAINTS, v_nc_excl);
    ROUNDTRIP(X509_NAME_CONSTRAINTS, v_nc_max0);
}

/* ---- CRL reason code (ENUMERATED) -------------------------------------- */
TEST(crlreason_encode_decode) {
    REQUIRE(U(CryptEncodeObjectEx));
    int v;
    v = 0; ENC_EQ(X509_CRL_REASON_CODE, &v, v_enum_0);
    v = 1; ENC_EQ(X509_CRL_REASON_CODE, &v, v_enum_1);
    v = 1; ENC_EQ(szOID_CRL_REASON_CODE, &v, v_enum_1);
    v = 5; ENC_EQ(X509_ENUMERATED, &v, v_enum_5);
    v = 10; ENC_EQ(X509_CRL_REASON_CODE, &v, v_enum_10);
    v = 256; ENC_EQ(X509_CRL_REASON_CODE, &v, v_enum_256);
    int *d = DEC(X509_CRL_REASON_CODE, v_enum_5, 0, NULL);
    if (d) { CHECK(*d == 5); LocalFree(d); }
    d = DEC(szOID_CRL_REASON_CODE, v_enum_10, 0, NULL);
    if (d) { CHECK(*d == 10); LocalFree(d); }
    d = DEC(X509_ENUMERATED, v_enum_256, 0, NULL);
    if (d) { CHECK(*d == 256); LocalFree(d); }
    d = DEC(X509_CRL_REASON_CODE, v_enum_0, 0, NULL);
    if (d) { CHECK(*d == 0); LocalFree(d); }
    DEC_FAIL(X509_CRL_REASON_CODE, v_bc2_pl3, HR_ASN1_BADTAG);
}

/* ---- X509_CHOICE_OF_TIME ------------------------------------------------- */
struct tm_row { const char *label; FILETIME ft; const BYTE *der; DWORD n; };
#define TM(l, ft, v) { l, ft, v, sizeof(v) }
TEST(time_encode_table) {
    REQUIRE(U(CryptEncodeObjectEx));
    struct tm_row rows[] = {
        TM("2000", a_ft(2000, 1, 1, 0, 0, 0), v_time_2000), TM("1950", a_ft(1950, 1, 1, 0, 0, 0), v_time_1950),
        TM("2049", a_ft(2049, 12, 31, 23, 59, 59), v_time_2049), TM("2050", a_ft(2050, 1, 1, 0, 0, 0), v_time_2050),
        TM("1949", a_ft(1949, 12, 31, 23, 59, 59), v_time_1949), TM("2007", a_ft(2007, 1, 2, 3, 4, 5), v_time_2007_gen),
    };
    for (unsigned i = 0; i < sizeof rows / sizeof *rows; i++) {
        t_note("row %s", rows[i].label);
        if (!strcmp(rows[i].label, "2007")) {
            /* 2007 is inside UTCTime range: encoded as UTCTime */
            static const BYTE e[] = { 0x17, 0x0d, '0','7','0','1','0','2','0','3','0','4','0','5','Z' };
            a_enc_eq(__FILE__, __LINE__, X509_CHOICE_OF_TIME, &rows[i].ft, 0, e, sizeof e);
            continue;
        }
        a_enc_eq(__FILE__, __LINE__, X509_CHOICE_OF_TIME, &rows[i].ft, 0, rows[i].der, rows[i].n);
    }
}
TEST(time_decode_table) {
    REQUIRE(U(CryptDecodeObjectEx));
    struct tm_row rows[] = {
        TM("2000", a_ft(2000, 1, 1, 0, 0, 0), v_time_2000), TM("1950", a_ft(1950, 1, 1, 0, 0, 0), v_time_1950),
        TM("2049", a_ft(2049, 12, 31, 23, 59, 59), v_time_2049), TM("2050", a_ft(2050, 1, 1, 0, 0, 0), v_time_2050),
        TM("1949", a_ft(1949, 12, 31, 23, 59, 59), v_time_1949), TM("2007gen", a_ft(2007, 1, 2, 3, 4, 5), v_time_2007_gen),
        TM("nosec", a_ft(2000, 1, 1, 0, 0, 0), v_time_nosec),
        TM("plus0100_adds", a_ft(2000, 1, 1, 1, 0, 0), v_time_off_plus),
        TM("minus0130_subtracts", a_ft(1999, 12, 31, 22, 30, 0), v_time_off_minus),
    };
    for (unsigned i = 0; i < sizeof rows / sizeof *rows; i++) {
        DWORD cb; FILETIME *f = a_dec(__FILE__, __LINE__, X509_CHOICE_OF_TIME, rows[i].der, rows[i].n, 0, &cb);
        t_note("row %s", rows[i].label);
        if (f) { CHECK(cb >= sizeof *f); CHECK(a_ft_eq(*f, rows[i].ft)); LocalFree(f); }
    }
}
TEST(time_decode_errors) {
    REQUIRE(U(CryptDecodeObjectEx));
    DEC_FAIL(X509_CHOICE_OF_TIME, v_time_bad_tag, 0);
    DWORD cb = 0; SET_ERR(0);
    BOOL r = U(CryptDecodeObjectEx)(ENC, X509_CHOICE_OF_TIME, v_time_bad_month, sizeof v_time_bad_month, 0, NULL, NULL, &cb);
    t_note("month 13: ok=%d err=0x%lx", r, GetLastError());
    DEC_FAIL(X509_CHOICE_OF_TIME, v_enum_1, 0);
}
TEST(time_decode_fractional_generalized_probe) {
    REQUIRE(U(CryptDecodeObjectEx));
    DWORD cb = 0; FILETIME *f = a_dec(__FILE__, __LINE__, X509_CHOICE_OF_TIME, v_time_gen_frac, sizeof v_time_gen_frac, 0, &cb);
    if (f) { FILETIME w = a_ft(2007, 1, 2, 3, 4, 5); ULONGLONG a = ((ULONGLONG)f->dwHighDateTime << 32) | f->dwLowDateTime, b = ((ULONGLONG)w.dwHighDateTime << 32) | w.dwLowDateTime;
        t_note("fractional seconds .5 decode delta %lld x100ns", (long long)(a - b)); LocalFree(f); }
}
TEST(time_roundtrips_and_pre1601) {
    REQUIRE(U(CryptDecodeObjectEx));
    ROUNDTRIP(X509_CHOICE_OF_TIME, v_time_2000); ROUNDTRIP(X509_CHOICE_OF_TIME, v_time_1950);
    ROUNDTRIP(X509_CHOICE_OF_TIME, v_time_2049); ROUNDTRIP(X509_CHOICE_OF_TIME, v_time_2050);
    ROUNDTRIP(X509_CHOICE_OF_TIME, v_time_1949);
    static const BYTE old[] = { 0x18, 0x0f, '1','5','9','9','0','1','0','1','0','0','0','0','0','0','Z' };
    DWORD cb = 0; SET_ERR(0);
    BOOL r = U(CryptDecodeObjectEx)(ENC, X509_CHOICE_OF_TIME, old, sizeof old, 0, NULL, NULL, &cb);
    t_note("year 1599 (before FILETIME epoch): ok=%d err=0x%lx", r, GetLastError());
}

/* ---- Microsoft extensions ------------------------------------------------ */
TEST(cert_template_encode_decode) {
    REQUIRE(U(CryptEncodeObjectEx));
    CERT_TEMPLATE_EXT s = { (LPSTR)"1.3.6.1.4.1.311.21.8.1.2", 100, FALSE, 0 };
    ENC_EQ(X509_CERTIFICATE_TEMPLATE, &s, v_tmpl_major);
    ENC_EQ(szOID_CERTIFICATE_TEMPLATE, &s, v_tmpl_major);
    s.fMinorVersion = TRUE; s.dwMinorVersion = 5;
    ENC_EQ(X509_CERTIFICATE_TEMPLATE, &s, v_tmpl_minor);
    s.dwMinorVersion = 0;
    ENC_EQ(X509_CERTIFICATE_TEMPLATE, &s, v_tmpl_minor0);
    CERT_TEMPLATE_EXT *d = DEC(X509_CERTIFICATE_TEMPLATE, v_tmpl_minor, 0, NULL);
    if (d) { CHECK(!strcmp(d->pszObjId, "1.3.6.1.4.1.311.21.8.1.2") && d->dwMajorVersion == 100 && d->fMinorVersion && d->dwMinorVersion == 5); LocalFree(d); }
    d = DEC(szOID_CERTIFICATE_TEMPLATE, v_tmpl_major, 0, NULL);
    if (d) { CHECK(d->dwMajorVersion == 100 && !d->fMinorVersion); LocalFree(d); }
    d = DEC(X509_CERTIFICATE_TEMPLATE, v_tmpl_minor0, 0, NULL);
    if (d) { CHECK(d->fMinorVersion && d->dwMinorVersion == 0); LocalFree(d); }
    ROUNDTRIP(X509_CERTIFICATE_TEMPLATE, v_tmpl_minor);
    DEC_FAIL(X509_CERTIFICATE_TEMPLATE, v_ku_ds, HR_ASN1_BADTAG);
}
TEST(enroll_certtype_extension_probe) {
    REQUIRE(U(CryptDecodeObjectEx));
    DWORD cb = 0; CERT_NAME_VALUE *v = NULL; SET_ERR(0);
    BOOL r = U(CryptDecodeObjectEx)(ENC, szOID_ENROLL_CERTTYPE_EXTENSION, v_enroll_certtype, sizeof v_enroll_certtype, CRYPT_DECODE_ALLOC_FLAG, NULL, &v, &cb);
    t_note("szOID_ENROLL_CERTTYPE_EXTENSION decode: ok=%d err=0x%lx", r, GetLastError());
    if (r) { CHECK(v->dwValueType == CERT_RDN_BMP_STRING || v->dwValueType == CERT_RDN_UNICODE_STRING); CHECK(v->Value.cbData == 8); LocalFree(v); }
}
TEST(ca_version_extension_probe) {
    REQUIRE(U(CryptDecodeObjectEx));
    DWORD cb = 0; int *v = NULL; SET_ERR(0);
    BOOL r = U(CryptDecodeObjectEx)(ENC, szOID_CERTSRV_CA_VERSION, v_ca_version, sizeof v_ca_version, CRYPT_DECODE_ALLOC_FLAG, NULL, &v, &cb);
    t_note("szOID_CERTSRV_CA_VERSION decode: ok=%d err=0x%lx", r, GetLastError());
    if (r) { t_note("CA version decoded as 0x%x", *v); LocalFree(v); }
}
TEST(next_ca_and_os_version_probe) {
    REQUIRE(U(CryptDecodeObjectEx));
    static const BYTE osv[] = { 0x16, 0x07, '1','0','.','0','.','1','5' };
    DWORD cb = 0; void *v = NULL; SET_ERR(0);
    BOOL r = U(CryptDecodeObjectEx)(ENC, szOID_OS_VERSION, osv, sizeof osv, CRYPT_DECODE_ALLOC_FLAG, NULL, &v, &cb);
    t_note("szOID_OS_VERSION decode (IA5): ok=%d err=0x%lx", r, GetLastError());
    if (r) LocalFree(v);
    v = NULL; SET_ERR(0);
    r = U(CryptDecodeObjectEx)(ENC, "1.3.6.1.4.1.311.25.2", v_ski_3, sizeof v_ski_3, CRYPT_DECODE_ALLOC_FLAG, NULL, &v, &cb);
    t_note("NTDS_CA_SECURITY_EXT decode: ok=%d err=0x%lx", r, GetLastError());
    if (r) LocalFree(v);
}
