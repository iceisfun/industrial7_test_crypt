/* CRL store operations: add/enum/find/get/delete/link, issuance and revocation checks. */
#include "cc.h"
#define CERTD CERT_DESCRIPTION_PROP_ID

static void rel(PCCRL_CONTEXT c) { if (c) U(CertFreeCRLContext)(c); }
static void relc(PCCERT_CONTEXT c) { if (c) U(CertFreeCertificateContext)(c); }
static BYTE *dup_bytes(const BYTE *p, DWORD n) { BYTE *b = LocalAlloc(LPTR, n); memcpy(b, p, n); return b; }
static HCERTSTORE store_with(const BYTE *a, DWORD an, const BYTE *b, DWORD bn, const BYTE *c, DWORD cn) {
    HCERTSTORE s = cc_store();
    if (!s) return NULL;
    if (a) cc_add_crl(s, a, an, CERT_STORE_ADD_ALWAYS, NULL);
    if (b) cc_add_crl(s, b, bn, CERT_STORE_ADD_ALWAYS, NULL);
    if (c) cc_add_crl(s, c, cn, CERT_STORE_ADD_ALWAYS, NULL);
    return s;
}

/* ---- CertAddEncodedCRLToStore argument handling ---- */
TEST(crlstore_add_encoded_bad_args) {
    REQUIRE(U(CertAddEncodedCRLToStore));
    HCERTSTORE s = cc_store(); REQUIRE(s);
    SET_ERR(0);
    CHECK(!U(CertAddEncodedCRLToStore)(NULL, 0, NULL, 0, 0, NULL)); EXPECT_ERR(CC_E_INVALIDARG);
    SET_ERR(0);
    CHECK(!U(CertAddEncodedCRLToStore)(s, 0, NULL, 0, 0, NULL)); EXPECT_ERR(CC_E_INVALIDARG);
    SET_ERR(0);
    CHECK(!U(CertAddEncodedCRLToStore)(s, 0, VEC(v_crl_basic), CERT_STORE_ADD_ALWAYS, NULL)); EXPECT_ERR(CC_E_INVALIDARG);
    SET_ERR(0);
    CHECK(!U(CertAddEncodedCRLToStore)(NULL, 0, VEC(v_crl_basic), CERT_STORE_ADD_ALWAYS, NULL)); EXPECT_ERR(CC_E_INVALIDARG);
    SET_ERR(0);
    CHECK(!U(CertAddEncodedCRLToStore)(s, CC_X509, NULL, 0, 0, NULL)); EXPECT_ERR(CC_E_EOD);
    SET_ERR(0);
    CHECK(!U(CertAddEncodedCRLToStore)(NULL, CC_X509, NULL, 0, 0, NULL)); EXPECT_ERR(CC_E_EOD);
    EXPECT_EQ(cc_count_crls(s), 0);
    cc_close(s);
}
TEST(crlstore_add_encoded_garbage_not_added) {
    REQUIRE(U(CertAddEncodedCRLToStore));
    HCERTSTORE s = cc_store(); REQUIRE(s);
    CHECK(!cc_add_crl(s, VEC(v_ca1), CERT_STORE_ADD_ALWAYS, NULL));
    CHECK(!cc_add_crl(s, v_crl_basic, sizeof(v_crl_basic) - 1, CERT_STORE_ADD_ALWAYS, NULL));
    EXPECT_EQ(cc_count_crls(s), 0);
    cc_close(s);
}
TEST(crlstore_add_encoded_returns_context) {
    REQUIRE(U(CertAddEncodedCRLToStore));
    HCERTSTORE s = cc_store(); REQUIRE(s);
    PCCRL_CONTEXT c = NULL;
    CHECK(cc_add_crl(s, VEC(v_crl_basic), CERT_STORE_ADD_ALWAYS, &c));
    REQUIRE(c);
    CHECK(c->hCertStore == s);
    EXPECT_EQ(c->cbCrlEncoded, sizeof v_crl_basic);
    EXPECT_EQ(c->pCrlInfo->cCRLEntry, 2);
    EXPECT_EQ(cc_count_crls(s), 1);
    rel(c);
    cc_close(s);
}
TEST(crlstore_add_encoded_null_store_returns_context) {
    REQUIRE(U(CertAddEncodedCRLToStore));
    PCCRL_CONTEXT c = NULL;
    SET_ERR(0);
    BOOL ok = cc_add_crl(NULL, VEC(v_crl_basic), CERT_STORE_ADD_ALWAYS, &c);
    CHECK(ok);
    CHECK(c != NULL);
    rel(c);
}
TEST(crlstore_add_encoded_copies_input) {
    REQUIRE(U(CertAddEncodedCRLToStore));
    HCERTSTORE s = cc_store(); REQUIRE(s);
    BYTE *p = dup_bytes(VEC(v_crl_basic));
    PCCRL_CONTEXT c = NULL;
    CHECK(cc_add_crl(s, p, sizeof v_crl_basic, CERT_STORE_ADD_ALWAYS, &c));
    REQUIRE(c);
    CHECK(c->pbCrlEncoded != p);
    memset(p, 0, sizeof v_crl_basic);
    CHECK(!memcmp(c->pbCrlEncoded, v_crl_basic, sizeof v_crl_basic));
    LocalFree(p);
    rel(c);
    cc_close(s);
}

/* ---- dispositions ---- */
TEST(crlstore_disp_add_always_duplicates) {
    REQUIRE(U(CertAddEncodedCRLToStore));
    HCERTSTORE s = cc_store(); REQUIRE(s);
    PCCRL_CONTEXT a = NULL, b = NULL;
    CHECK(cc_add_crl(s, VEC(v_crl_basic), CERT_STORE_ADD_ALWAYS, &a));
    CHECK(cc_add_crl(s, VEC(v_crl_basic), CERT_STORE_ADD_ALWAYS, &b));
    CHECK(a != NULL && b != NULL && a != b);
    EXPECT_EQ(cc_count_crls(s), 2);
    rel(a); rel(b);
    cc_close(s);
}
TEST(crlstore_disp_add_new_exists) {
    REQUIRE(U(CertAddEncodedCRLToStore));
    HCERTSTORE s = cc_store(); REQUIRE(s);
    CHECK(cc_add_crl(s, VEC(v_crl_basic), CERT_STORE_ADD_NEW, NULL));
    SET_ERR(0);
    PCCRL_CONTEXT c = (PCCRL_CONTEXT)0x1;
    CHECK(!cc_add_crl(s, VEC(v_crl_basic), CERT_STORE_ADD_NEW, &c)); EXPECT_ERR(CC_E_EXISTS);
    t_note("ppStoreContext after ADD_NEW failure = %p", (void *)c);
    SET_ERR(0);
    CHECK(!cc_add_crl(s, VEC(v_crl_basic_newer), CERT_STORE_ADD_NEW, NULL)); EXPECT_ERR(CC_E_EXISTS);
    EXPECT_EQ(cc_count_crls(s), 1);
    cc_close(s);
}
TEST(crlstore_disp_add_new_other_issuer_ok) {
    REQUIRE(U(CertAddEncodedCRLToStore));
    HCERTSTORE s = cc_store(); REQUIRE(s);
    CHECK(cc_add_crl(s, VEC(v_crl_basic), CERT_STORE_ADD_NEW, NULL));
    CHECK(cc_add_crl(s, VEC(v_crl_ca2), CERT_STORE_ADD_NEW, NULL));
    EXPECT_EQ(cc_count_crls(s), 2);
    cc_close(s);
}
TEST(crlstore_disp_use_existing) {
    REQUIRE(U(CertAddEncodedCRLToStore));
    HCERTSTORE s = cc_store(); REQUIRE(s);
    PCCRL_CONTEXT a = NULL, b = NULL;
    CHECK(cc_add_crl(s, VEC(v_crl_basic), CERT_STORE_ADD_ALWAYS, &a));
    CHECK(cc_add_crl(s, VEC(v_crl_basic), CERT_STORE_ADD_USE_EXISTING, &b));
    CHECK(a != NULL && a == b);
    EXPECT_EQ(cc_count_crls(s), 1);
    rel(a); rel(b);
    /* a different CRL from the same issuer is "existing" too and the existing one is returned */
    b = NULL;
    CHECK(cc_add_crl(s, VEC(v_crl_basic_newer), CERT_STORE_ADD_USE_EXISTING, &b));
    REQUIRE(b);
    EXPECT_EQ(b->cbCrlEncoded, sizeof v_crl_basic);
    rel(b);
    EXPECT_EQ(cc_count_crls(s), 1);
    cc_close(s);
}
TEST(crlstore_disp_replace_existing) {
    REQUIRE(U(CertAddEncodedCRLToStore));
    HCERTSTORE s = cc_store(); REQUIRE(s);
    CHECK(cc_add_crl(s, VEC(v_crl_basic), CERT_STORE_ADD_ALWAYS, NULL));
    PCCRL_CONTEXT n = NULL;
    CHECK(cc_add_crl(s, VEC(v_crl_basic_newer), CERT_STORE_ADD_REPLACE_EXISTING, &n));
    REQUIRE(n);
    EXPECT_EQ(n->cbCrlEncoded, sizeof v_crl_basic_newer);
    EXPECT_EQ(cc_count_crls(s), 1);
    PCCRL_CONTEXT e = U(CertEnumCRLsInStore)(s, NULL);
    REQUIRE(e);
    EXPECT_EQ(e->cbCrlEncoded, sizeof v_crl_basic_newer);
    rel(e); rel(n);
    cc_close(s);
}
TEST(crlstore_disp_replace_existing_without_match_adds) {
    REQUIRE(U(CertAddEncodedCRLToStore));
    HCERTSTORE s = cc_store(); REQUIRE(s);
    CHECK(cc_add_crl(s, VEC(v_crl_basic), CERT_STORE_ADD_ALWAYS, NULL));
    CHECK(cc_add_crl(s, VEC(v_crl_ca2), CERT_STORE_ADD_REPLACE_EXISTING, NULL));
    EXPECT_EQ(cc_count_crls(s), 2);
    cc_close(s);
}
TEST(crlstore_disp_newer_replaces_older) {
    REQUIRE(U(CertAddEncodedCRLToStore));
    HCERTSTORE s = cc_store(); REQUIRE(s);
    CHECK(cc_add_crl(s, VEC(v_crl_basic), CERT_STORE_ADD_ALWAYS, NULL));
    CHECK(cc_add_crl(s, VEC(v_crl_basic_newer), CERT_STORE_ADD_NEWER, NULL));
    EXPECT_EQ(cc_count_crls(s), 1);
    PCCRL_CONTEXT e = U(CertEnumCRLsInStore)(s, NULL);
    REQUIRE(e);
    EXPECT_EQ(cc_ft(e->pCrlInfo->ThisUpdate), V_NEWER_THIS_FT);
    rel(e);
    cc_close(s);
}
TEST(crlstore_disp_newer_rejects_older) {
    REQUIRE(U(CertAddEncodedCRLToStore));
    HCERTSTORE s = cc_store(); REQUIRE(s);
    CHECK(cc_add_crl(s, VEC(v_crl_basic_newer), CERT_STORE_ADD_ALWAYS, NULL));
    SET_ERR(0);
    CHECK(!cc_add_crl(s, VEC(v_crl_basic), CERT_STORE_ADD_NEWER, NULL)); EXPECT_ERR(CC_E_EXISTS);
    EXPECT_EQ(cc_count_crls(s), 1);
    PCCRL_CONTEXT e = U(CertEnumCRLsInStore)(s, NULL);
    REQUIRE(e);
    EXPECT_EQ(cc_ft(e->pCrlInfo->ThisUpdate), V_NEWER_THIS_FT);
    rel(e);
    cc_close(s);
}
TEST(crlstore_disp_newer_same_thisupdate) {
    REQUIRE(U(CertAddEncodedCRLToStore));
    HCERTSTORE s = cc_store(); REQUIRE(s);
    CHECK(cc_add_crl(s, VEC(v_crl_basic), CERT_STORE_ADD_ALWAYS, NULL));
    SET_ERR(0);
    BOOL ok = cc_add_crl(s, VEC(v_crl_basic), CERT_STORE_ADD_NEWER, NULL);
    t_note("ADD_NEWER with identical CRL: ret=%d err=0x%lx count=%d", ok, GetLastError(), cc_count_crls(s));
    cc_close(s);
}
TEST(crlstore_disp_newer_inherit_properties) {
    REQUIRE(U(CertAddEncodedCRLToStore));
    HCERTSTORE s = cc_store(); REQUIRE(s);
    PCCRL_CONTEXT old = NULL;
    CHECK(cc_add_crl(s, VEC(v_crl_basic), CERT_STORE_ADD_ALWAYS, &old));
    REQUIRE(old);
    BYTE v[2] = { 8, 9 }; CRYPT_DATA_BLOB b = { 2, v };
    CHECK(U(CertSetCRLContextProperty)(old, CERTD, 0, &b));
    rel(old);
    PCCRL_CONTEXT n = NULL;
    CHECK(cc_add_crl(s, VEC(v_crl_basic_newer), CERT_STORE_ADD_NEWER_INHERIT_PROPERTIES, &n));
    REQUIRE(n);
    BYTE got[4]; DWORD cb = sizeof got;
    CHECK(U(CertGetCRLContextProperty)(n, CERTD, got, &cb));
    EXPECT_EQ(cb, 2);
    EXPECT_EQ(cc_count_crls(s), 1);
    rel(n);
    cc_close(s);
}
TEST(crlstore_disp_invalid_value) {
    REQUIRE(U(CertAddEncodedCRLToStore));
    HCERTSTORE s = cc_store(); REQUIRE(s);
    static const DWORD bad[] = { 8, 99, 0xffff };
    for (unsigned i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        SET_ERR(0);
        BOOL ok = cc_add_crl(s, VEC(v_crl_basic), bad[i], NULL);
        CHECKF(!ok, "disposition %lu", bad[i]);
        if (!ok) t_note("add disposition %lu -> err 0x%lx", bad[i], GetLastError());
    }
    EXPECT_EQ(cc_count_crls(s), 0);
    cc_close(s);
}

/* ---- CertAddCRLContextToStore / link ---- */
TEST(crlstore_add_context_makes_copy) {
    REQUIRE(U(CertAddCRLContextToStore));
    PCCRL_CONTEXT c = cc_crl(VEC(v_crl_basic));
    REQUIRE(c);
    HCERTSTORE s = cc_store(); REQUIRE(s);
    PCCRL_CONTEXT o = NULL;
    CHECK(U(CertAddCRLContextToStore)(s, c, CERT_STORE_ADD_ALWAYS, &o));
    REQUIRE(o);
    CHECK(o != c);
    CHECK(o->pbCrlEncoded != c->pbCrlEncoded);
    CHECK(o->pCrlInfo != c->pCrlInfo);
    EXPECT_EQ(o->cbCrlEncoded, c->cbCrlEncoded);
    CHECK(o->hCertStore == s);
    rel(o); rel(c);
    cc_close(s);
}
TEST(crlstore_add_context_without_out_param) {
    REQUIRE(U(CertAddCRLContextToStore));
    PCCRL_CONTEXT c = cc_crl(VEC(v_crl_basic));
    REQUIRE(c);
    HCERTSTORE s = cc_store(); REQUIRE(s);
    CHECK(U(CertAddCRLContextToStore)(s, c, CERT_STORE_ADD_ALWAYS, NULL));
    EXPECT_EQ(cc_count_crls(s), 1);
    rel(c);
    cc_close(s);
}
TEST(crlstore_add_context_between_stores) {
    REQUIRE(U(CertAddCRLContextToStore));
    HCERTSTORE s1 = cc_store(), s2 = cc_store(); REQUIRE(s1 && s2);
    PCCRL_CONTEXT in1 = NULL;
    CHECK(cc_add_crl(s1, VEC(v_crl_ca2), CERT_STORE_ADD_ALWAYS, &in1));
    REQUIRE(in1);
    CHECK(U(CertAddCRLContextToStore)(s2, in1, CERT_STORE_ADD_ALWAYS, NULL));
    EXPECT_EQ(cc_count_crls(s1), 1);
    EXPECT_EQ(cc_count_crls(s2), 1);
    rel(in1);
    cc_close(s1); cc_close(s2);
}
TEST(crlstore_link_adds_shared_element) {
    REQUIRE(U(CertAddCRLLinkToStore));
    HCERTSTORE s1 = cc_store(), s2 = cc_store(); REQUIRE(s1 && s2);
    PCCRL_CONTEXT orig = NULL;
    CHECK(cc_add_crl(s1, VEC(v_crl_basic), CERT_STORE_ADD_ALWAYS, &orig));
    REQUIRE(orig);
    PCCRL_CONTEXT lnk = NULL;
    SET_ERR(0);
    BOOL ok = U(CertAddCRLLinkToStore)(s2, orig, CERT_STORE_ADD_ALWAYS, &lnk);
    CHECKF(ok, "err 0x%lx", GetLastError());
    if (ok) {
        EXPECT_EQ(cc_count_crls(s2), 1);
        REQUIRE(lnk);
        CHECK(lnk->hCertStore == s2);
        EXPECT_EQ(lnk->cbCrlEncoded, orig->cbCrlEncoded);
        t_note("link shares encoded buffer: %d", lnk->pbCrlEncoded == orig->pbCrlEncoded);
        /* properties set through the link are visible through the original (shared element) */
        BYTE v = 1; CRYPT_DATA_BLOB b = { 1, &v };
        CHECK(U(CertSetCRLContextProperty)(lnk, CERTD, 0, &b));
        DWORD cb = 0;
        BOOL seen = U(CertGetCRLContextProperty)(orig, CERTD, NULL, &cb);
        t_note("property set on link visible on original: %d", seen);
        rel(lnk);
    }
    rel(orig);
    cc_close(s1);
    /* link outlives the original store */
    PCCRL_CONTEXT e = U(CertEnumCRLsInStore)(s2, NULL);
    if (ok) { CHECK(e != NULL); if (e) EXPECT_EQ(e->pCrlInfo->cCRLEntry, 2); }
    rel(e);
    cc_close(s2);
}
TEST(crlstore_link_same_store_dispositions) {
    REQUIRE(U(CertAddCRLLinkToStore));
    HCERTSTORE s1 = cc_store(), s2 = cc_store(); REQUIRE(s1 && s2);
    PCCRL_CONTEXT orig = NULL;
    CHECK(cc_add_crl(s1, VEC(v_crl_basic), CERT_STORE_ADD_ALWAYS, &orig));
    REQUIRE(orig);
    CHECK(U(CertAddCRLLinkToStore)(s2, orig, CERT_STORE_ADD_NEW, NULL));
    SET_ERR(0);
    CHECK(!U(CertAddCRLLinkToStore)(s2, orig, CERT_STORE_ADD_NEW, NULL)); EXPECT_ERR(CC_E_EXISTS);
    EXPECT_EQ(cc_count_crls(s2), 1);
    rel(orig);
    cc_close(s1); cc_close(s2);
}

/* ---- enumeration ---- */
TEST(crlstore_enum_empty) {
    REQUIRE(U(CertEnumCRLsInStore));
    HCERTSTORE s = cc_store(); REQUIRE(s);
    SET_ERR(0);
    CHECK(U(CertEnumCRLsInStore)(s, NULL) == NULL);
    t_note("enum empty store last error 0x%lx", GetLastError());
    EXPECT_ERR(CC_E_NOT_FOUND);
    cc_close(s);
}
TEST(crlstore_enum_visits_each_once) {
    REQUIRE(U(CertEnumCRLsInStore));
    HCERTSTORE s = store_with(VEC(v_crl_basic), VEC(v_crl_ca2), VEC(v_crl_empty));
    REQUIRE(s);
    int seen[3] = { 0 };
    PCCRL_CONTEXT c = NULL;
    int n = 0;
    while ((c = U(CertEnumCRLsInStore)(s, c)) != NULL) {
        n++;
        if (c->cbCrlEncoded == sizeof v_crl_basic && !memcmp(c->pbCrlEncoded, v_crl_basic, c->cbCrlEncoded)) seen[0]++;
        else if (c->cbCrlEncoded == sizeof v_crl_ca2 && !memcmp(c->pbCrlEncoded, v_crl_ca2, c->cbCrlEncoded)) seen[1]++;
        else if (c->cbCrlEncoded == sizeof v_crl_empty && !memcmp(c->pbCrlEncoded, v_crl_empty, c->cbCrlEncoded)) seen[2]++;
    }
    EXPECT_EQ(n, 3);
    EXPECT_EQ(seen[0], 1); EXPECT_EQ(seen[1], 1); EXPECT_EQ(seen[2], 1);
    cc_close(s);
}
TEST(crlstore_enum_ignores_other_context_types) {
    REQUIRE(U(CertEnumCRLsInStore));
    HCERTSTORE s = cc_store(); REQUIRE(s);
    CHECK(U(CertAddEncodedCertificateToStore)(s, CC_X509, VEC(v_ca1), CERT_STORE_ADD_ALWAYS, NULL));
    CHECK(cc_add_ctl(s, VEC(v_ctl_signed), CERT_STORE_ADD_ALWAYS, NULL));
    CHECK(cc_add_crl(s, VEC(v_crl_basic), CERT_STORE_ADD_ALWAYS, NULL));
    EXPECT_EQ(cc_count_crls(s), 1);
    EXPECT_EQ(cc_count_certs(s), 1);
    EXPECT_EQ(cc_count_ctls(s), 1);
    cc_close(s);
}
TEST(crlstore_enum_returned_context_is_refcounted) {
    REQUIRE(U(CertEnumCRLsInStore));
    HCERTSTORE s = store_with(VEC(v_crl_basic), NULL, 0, NULL, 0);
    REQUIRE(s);
    PCCRL_CONTEXT a = U(CertEnumCRLsInStore)(s, NULL);
    PCCRL_CONTEXT b = U(CertEnumCRLsInStore)(s, NULL);
    REQUIRE(a && b);
    CHECK(a == b);
    rel(a); rel(b);
    cc_close(s);
}

/* ---- delete ---- */
TEST(crlstore_delete_removes) {
    REQUIRE(U(CertDeleteCRLFromStore));
    HCERTSTORE s = store_with(VEC(v_crl_basic), VEC(v_crl_ca2), NULL, 0);
    REQUIRE(s);
    PCCRL_CONTEXT c = U(CertEnumCRLsInStore)(s, NULL);
    REQUIRE(c);
    DWORD cb = c->cbCrlEncoded;
    CHECK(U(CertDeleteCRLFromStore)(c));
    EXPECT_EQ(cc_count_crls(s), 1);
    PCCRL_CONTEXT rest = U(CertEnumCRLsInStore)(s, NULL);
    REQUIRE(rest);
    CHECK(rest->cbCrlEncoded != cb);
    rel(rest);
    cc_close(s);
}
TEST(crlstore_delete_while_enumerating) {
    REQUIRE(U(CertDeleteCRLFromStore));
    if (t_is_wine()) { t_skip("emulator faults when the enumeration cursor is deleted"); return; }
    HCERTSTORE s = store_with(VEC(v_crl_basic), VEC(v_crl_ca2), VEC(v_crl_empty));
    REQUIRE(s);
    PCCRL_CONTEXT c = NULL;
    int removed = 0;
    while ((c = U(CertEnumCRLsInStore)(s, c)) != NULL) {
        PCCRL_CONTEXT d = U(CertDuplicateCRLContext)(c);
        CHECK(U(CertDeleteCRLFromStore)(d));
        removed++;
    }
    EXPECT_EQ(removed, 3);
    EXPECT_EQ(cc_count_crls(s), 0);
    cc_close(s);
}
TEST(crlstore_deleted_context_stays_readable) {
    REQUIRE(U(CertDeleteCRLFromStore));
    HCERTSTORE s = store_with(VEC(v_crl_basic), NULL, 0, NULL, 0);
    REQUIRE(s);
    PCCRL_CONTEXT c = U(CertEnumCRLsInStore)(s, NULL);
    PCCRL_CONTEXT held = U(CertDuplicateCRLContext)(c);
    CHECK(U(CertDeleteCRLFromStore)(c));
    EXPECT_EQ(cc_count_crls(s), 0);
    EXPECT_EQ(held->pCrlInfo->cCRLEntry, 2);
    CHECK(!memcmp(held->pbCrlEncoded, v_crl_basic, sizeof v_crl_basic));
    rel(held);
    cc_close(s);
}

/* ---- CertFindCRLInStore ---- */
TEST(crlfind_any) {
    REQUIRE(U(CertFindCRLInStore));
    HCERTSTORE s = store_with(VEC(v_crl_basic), VEC(v_crl_ca2), NULL, 0);
    REQUIRE(s);
    int n = 0; PCCRL_CONTEXT c = NULL;
    while ((c = U(CertFindCRLInStore)(s, 0, 0, CRL_FIND_ANY, NULL, c)) != NULL) n++;
    EXPECT_EQ(n, 2);
    /* flags and encoding type are ignored for ANY */
    c = U(CertFindCRLInStore)(s, 1234, 1234, CRL_FIND_ANY, NULL, NULL);
    CHECK(c != NULL); rel(c);
    cc_close(s);
}
TEST(crlfind_empty_store_not_found) {
    REQUIRE(U(CertFindCRLInStore));
    HCERTSTORE s = cc_store(); REQUIRE(s);
    SET_ERR(0);
    CHECK(U(CertFindCRLInStore)(s, 0, 0, CRL_FIND_ANY, NULL, NULL) == NULL); EXPECT_ERR(CC_E_NOT_FOUND);
    SET_ERR(0);
    CHECK(U(CertFindCRLInStore)(s, 0, 0, CRL_FIND_ISSUED_BY, NULL, NULL) == NULL); EXPECT_ERR(CC_E_NOT_FOUND);
    cc_close(s);
}
TEST(crlfind_issued_by_null_matches_any) {
    REQUIRE(U(CertFindCRLInStore));
    HCERTSTORE s = store_with(VEC(v_crl_basic), VEC(v_crl_ca2), NULL, 0);
    REQUIRE(s);
    int n = 0; PCCRL_CONTEXT c = NULL;
    while ((c = U(CertFindCRLInStore)(s, 0, 0, CRL_FIND_ISSUED_BY, NULL, c)) != NULL) n++;
    EXPECT_EQ(n, 2);
    cc_close(s);
}
TEST(crlfind_issued_by_name) {
    REQUIRE(U(CertFindCRLInStore));
    HCERTSTORE s = store_with(VEC(v_crl_basic), VEC(v_crl_ca2), VEC(v_crl_empty));
    REQUIRE(s);
    PCCERT_CONTEXT ca1 = cc_cert(VEC(v_ca1)), ca2 = cc_cert(VEC(v_ca2));
    REQUIRE(ca1 && ca2);
    int n1 = 0, n2 = 0; PCCRL_CONTEXT c = NULL;
    while ((c = U(CertFindCRLInStore)(s, 0, 0, CRL_FIND_ISSUED_BY, ca1, c)) != NULL) { n1++; CHECK(c->pCrlInfo->Issuer.cbData == sizeof v_ca1_subject); }
    while ((c = U(CertFindCRLInStore)(s, 0, 0, CRL_FIND_ISSUED_BY, ca2, c)) != NULL) { n2++; }
    EXPECT_EQ(n1, 2); EXPECT_EQ(n2, 1);
    /* a leaf's subject is not an issuer of anything here */
    PCCERT_CONTEXT leaf = cc_cert(VEC(v_cert_1001));
    REQUIRE(leaf);
    SET_ERR(0);
    CHECK(U(CertFindCRLInStore)(s, 0, 0, CRL_FIND_ISSUED_BY, leaf, NULL) == NULL); EXPECT_ERR(CC_E_NOT_FOUND);
    relc(leaf); relc(ca1); relc(ca2);
    cc_close(s);
}
TEST(crlfind_issued_by_signature_flag) {
    REQUIRE(U(CertFindCRLInStore));
    BYTE *bad = dup_bytes(VEC(v_crl_basic));
    bad[sizeof v_crl_basic - 5] ^= 0x40; /* corrupt the signature value */
    HCERTSTORE s = cc_store(); REQUIRE(s);
    CHECK(cc_add_crl(s, bad, sizeof v_crl_basic, CERT_STORE_ADD_ALWAYS, NULL));
    PCCERT_CONTEXT ca1 = cc_cert(VEC(v_ca1));
    REQUIRE(ca1);
    PCCRL_CONTEXT c = U(CertFindCRLInStore)(s, 0, 0, CRL_FIND_ISSUED_BY, ca1, NULL);
    CHECK(c != NULL); rel(c);
    c = U(CertFindCRLInStore)(s, 0, CRL_FIND_ISSUED_BY_SIGNATURE_FLAG, CRL_FIND_ISSUED_BY, ca1, NULL);
    CHECK(c == NULL); rel(c);
    CHECK(cc_add_crl(s, VEC(v_crl_basic_newer), CERT_STORE_ADD_ALWAYS, NULL));
    int n = 0;
    while ((c = U(CertFindCRLInStore)(s, 0, CRL_FIND_ISSUED_BY_SIGNATURE_FLAG, CRL_FIND_ISSUED_BY, ca1, c)) != NULL) { n++; EXPECT_EQ(c->cbCrlEncoded, sizeof v_crl_basic_newer); }
    EXPECT_EQ(n, 1);
    relc(ca1); LocalFree(bad);
    cc_close(s);
}
TEST(crlfind_issued_by_signature_flag_wrong_key) {
    REQUIRE(U(CertFindCRLInStore));
    HCERTSTORE s = store_with(VEC(v_crl_basic), NULL, 0, NULL, 0);
    REQUIRE(s);
    /* signature check uses the issuer cert's public key: a cert with CA1's name but another key must not verify */
    PCCERT_CONTEXT ca2 = cc_cert(VEC(v_ca2));
    REQUIRE(ca2);
    PCCRL_CONTEXT c = U(CertFindCRLInStore)(s, 0, CRL_FIND_ISSUED_BY_SIGNATURE_FLAG, CRL_FIND_ISSUED_BY, ca2, NULL);
    CHECK(c == NULL); rel(c);
    relc(ca2);
    cc_close(s);
}
TEST(crlfind_issued_by_aki_flag) {
    REQUIRE(U(CertFindCRLInStore));
    HCERTSTORE s = store_with(VEC(v_crl_basic), VEC(v_crl_ca2), VEC(v_crl_v1_nonext));
    REQUIRE(s);
    PCCERT_CONTEXT ca1 = cc_cert(VEC(v_ca1));
    REQUIRE(ca1);
    int n = 0; PCCRL_CONTEXT c = NULL;
    int sawbasic = 0, sawv1 = 0;
    while ((c = U(CertFindCRLInStore)(s, 0, CRL_FIND_ISSUED_BY_AKI_FLAG, CRL_FIND_ISSUED_BY, ca1, c)) != NULL) {
        n++;
        if (c->cbCrlEncoded == sizeof v_crl_basic) sawbasic++;
        if (c->cbCrlEncoded == sizeof v_crl_v1_nonext) sawv1++;
    }
    EXPECT_EQ(sawbasic, 1);
    /* A CRL without an AKI extension matches any cert with the same issuer name */
    EXPECT_EQ(sawv1, 1);
    EXPECT_EQ(n, 2);
    relc(ca1);
    cc_close(s);
}
TEST(crlfind_issued_by_base_delta_flags) {
    REQUIRE(U(CertFindCRLInStore));
    HCERTSTORE s = store_with(VEC(v_crl_basic), VEC(v_crl_delta), VEC(v_crl_idp));
    REQUIRE(s);
    PCCERT_CONTEXT ca1 = cc_cert(VEC(v_ca1));
    REQUIRE(ca1);
    int nbase = 0, ndelta = 0, nall = 0; PCCRL_CONTEXT c = NULL;
    while ((c = U(CertFindCRLInStore)(s, 0, CRL_FIND_ISSUED_BY_BASE_FLAG, CRL_FIND_ISSUED_BY, ca1, c)) != NULL) {
        nbase++;
        CHECK(U(CertFindExtension)(szOID_DELTA_CRL_INDICATOR, c->pCrlInfo->cExtension, c->pCrlInfo->rgExtension) == NULL);
    }
    while ((c = U(CertFindCRLInStore)(s, 0, CRL_FIND_ISSUED_BY_DELTA_FLAG, CRL_FIND_ISSUED_BY, ca1, c)) != NULL) {
        ndelta++;
        CHECK(U(CertFindExtension)(szOID_DELTA_CRL_INDICATOR, c->pCrlInfo->cExtension, c->pCrlInfo->rgExtension) != NULL);
    }
    while ((c = U(CertFindCRLInStore)(s, 0, 0, CRL_FIND_ISSUED_BY, ca1, c)) != NULL) nall++;
    EXPECT_EQ(nbase, 2); EXPECT_EQ(ndelta, 1); EXPECT_EQ(nall, 3);
    c = U(CertFindCRLInStore)(s, 0, CRL_FIND_ISSUED_BY_BASE_FLAG | CRL_FIND_ISSUED_BY_DELTA_FLAG, CRL_FIND_ISSUED_BY, ca1, NULL);
    t_note("find with BASE|DELTA flags -> %p", (void *)c);
    rel(c);
    relc(ca1);
    cc_close(s);
}
TEST(crlfind_existing) {
    REQUIRE(U(CertFindCRLInStore));
    HCERTSTORE s = store_with(VEC(v_crl_basic), VEC(v_crl_ca2), NULL, 0);
    REQUIRE(s);
    PCCRL_CONTEXT probe = cc_crl(VEC(v_crl_basic_newer));
    REQUIRE(probe);
    PCCRL_CONTEXT c = U(CertFindCRLInStore)(s, 0, 0, CRL_FIND_EXISTING, probe, NULL);
    CHECK(c != NULL);
    if (c) { EXPECT_EQ(c->cbCrlEncoded, sizeof v_crl_basic); CHECK(c->pCrlInfo->Issuer.cbData == sizeof v_ca1_subject); }
    rel(c);
    rel(probe);
    probe = cc_crl(VEC(v_crl_empty));
    c = U(CertFindCRLInStore)(s, 0, 0, CRL_FIND_EXISTING, probe, NULL);
    CHECK(c != NULL); rel(c); rel(probe);
    cc_close(s);
    s = store_with(VEC(v_crl_ca2), NULL, 0, NULL, 0);
    probe = cc_crl(VEC(v_crl_basic));
    SET_ERR(0);
    c = U(CertFindCRLInStore)(s, 0, 0, CRL_FIND_EXISTING, probe, NULL);
    CHECK(c == NULL); EXPECT_ERR(CC_E_NOT_FOUND);
    rel(probe);
    cc_close(s);
}
TEST(crlfind_issued_for) {
    REQUIRE(U(CertFindCRLInStore));
    HCERTSTORE s = store_with(VEC(v_crl_basic), VEC(v_crl_ca2), NULL, 0);
    REQUIRE(s);
    PCCERT_CONTEXT ca1 = cc_cert(VEC(v_ca1)), ca2 = cc_cert(VEC(v_ca2)), l1 = cc_cert(VEC(v_cert_1001)), l2 = cc_cert(VEC(v_cert_c2_1001));
    REQUIRE(ca1 && ca2 && l1 && l2);
    CRL_FIND_ISSUED_FOR_PARA p;
    p.pSubjectCert = l1; p.pIssuerCert = ca1;
    PCCRL_CONTEXT c = U(CertFindCRLInStore)(s, 0, 0, CRL_FIND_ISSUED_FOR, &p, NULL);
    CHECK(c != NULL);
    if (c) { EXPECT_EQ(c->cbCrlEncoded, sizeof v_crl_basic); }
    rel(c);
    p.pSubjectCert = l2; p.pIssuerCert = ca2;
    c = U(CertFindCRLInStore)(s, 0, 0, CRL_FIND_ISSUED_FOR, &p, NULL);
    CHECK(c != NULL);
    if (c) { EXPECT_EQ(c->cbCrlEncoded, sizeof v_crl_ca2); }
    rel(c);
    relc(ca1); relc(ca2); relc(l1); relc(l2);
    cc_close(s);
}
TEST(crlfind_issued_for_no_issuer_crl) {
    REQUIRE(U(CertFindCRLInStore));
    HCERTSTORE s = store_with(VEC(v_crl_ca2), NULL, 0, NULL, 0);
    REQUIRE(s);
    PCCERT_CONTEXT ca1 = cc_cert(VEC(v_ca1)), l1 = cc_cert(VEC(v_cert_1001));
    REQUIRE(ca1 && l1);
    CRL_FIND_ISSUED_FOR_PARA p = { l1, ca1 };
    SET_ERR(0);
    PCCRL_CONTEXT c = U(CertFindCRLInStore)(s, 0, 0, CRL_FIND_ISSUED_FOR, &p, NULL);
    CHECK(c == NULL); EXPECT_ERR(CC_E_NOT_FOUND);
    relc(ca1); relc(l1);
    cc_close(s);
}
TEST(crlfind_continues_from_prev) {
    REQUIRE(U(CertFindCRLInStore));
    HCERTSTORE s = store_with(VEC(v_crl_basic), VEC(v_crl_basic_newer), VEC(v_crl_ca2));
    REQUIRE(s);
    PCCRL_CONTEXT first = U(CertFindCRLInStore)(s, 0, 0, CRL_FIND_ANY, NULL, NULL);
    REQUIRE(first);
    PCCRL_CONTEXT keep = U(CertDuplicateCRLContext)(first);
    PCCRL_CONTEXT second = U(CertFindCRLInStore)(s, 0, 0, CRL_FIND_ANY, NULL, first); /* frees first */
    REQUIRE(second);
    CHECK(second != keep);
    rel(second); rel(keep);
    cc_close(s);
}

/* ---- CertGetCRLFromStore ---- */
TEST(crlget_bad_flags) {
    REQUIRE(U(CertGetCRLFromStore));
    HCERTSTORE s = store_with(VEC(v_crl_basic), NULL, 0, NULL, 0);
    REQUIRE(s);
    static const DWORD bad[] = { 0xffffffff, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80, 0x400, 0x800, 0x1000, 0x80000000 };
    for (unsigned i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        DWORD f = bad[i];
        SET_ERR(0);
        PCCRL_CONTEXT c = U(CertGetCRLFromStore)(s, NULL, NULL, &f);
        CHECKF(c == NULL, "flags 0x%lx", bad[i]);
        EXPECT_ERR(CC_E_INVALIDARG);
        rel(c);
    }
    cc_close(s);
}
TEST(crlget_bad_flags_releases_prev) {
    REQUIRE(U(CertGetCRLFromStore));
    HCERTSTORE s = store_with(VEC(v_crl_basic), NULL, 0, NULL, 0);
    REQUIRE(s);
    PCCRL_CONTEXT prev = U(CertEnumCRLsInStore)(s, NULL);
    DWORD f = 0x4;
    SET_ERR(0);
    CHECK(U(CertGetCRLFromStore)(s, NULL, prev, &f) == NULL); EXPECT_ERR(CC_E_INVALIDARG);
    /* prev was released by the call: only the store holds the context now */
    cc_close(s);
}
TEST(crlget_empty_store) {
    REQUIRE(U(CertGetCRLFromStore));
    HCERTSTORE s = cc_store(); REQUIRE(s);
    DWORD f = 0;
    SET_ERR(0);
    CHECK(U(CertGetCRLFromStore)(s, NULL, NULL, &f) == NULL); EXPECT_ERR(CC_E_NOT_FOUND);
    cc_close(s);
}
TEST(crlget_null_issuer_matches_any) {
    REQUIRE(U(CertGetCRLFromStore));
    HCERTSTORE s = store_with(VEC(v_crl_basic), VEC(v_crl_ca2), NULL, 0);
    REQUIRE(s);
    DWORD f = 0; int n = 0; PCCRL_CONTEXT c = NULL;
    while ((c = U(CertGetCRLFromStore)(s, NULL, c, &f)) != NULL) n++;
    EXPECT_EQ(n, 2);
    cc_close(s);
}
TEST(crlget_by_issuer) {
    REQUIRE(U(CertGetCRLFromStore));
    HCERTSTORE s = store_with(VEC(v_crl_basic), VEC(v_crl_ca2), NULL, 0);
    REQUIRE(s);
    PCCERT_CONTEXT ca1 = cc_cert(VEC(v_ca1)), leaf = cc_cert(VEC(v_cert_1001));
    REQUIRE(ca1 && leaf);
    DWORD f = 0; int n = 0; PCCRL_CONTEXT c = NULL;
    while ((c = U(CertGetCRLFromStore)(s, ca1, c, &f)) != NULL) { n++; EXPECT_EQ(c->cbCrlEncoded, sizeof v_crl_basic); }
    EXPECT_EQ(n, 1);
    f = 0;
    SET_ERR(0);
    CHECK(U(CertGetCRLFromStore)(s, leaf, NULL, &f) == NULL); EXPECT_ERR(CC_E_NOT_FOUND);
    relc(ca1); relc(leaf);
    cc_close(s);
}
TEST(crlget_signature_flag_valid) {
    REQUIRE(U(CertGetCRLFromStore));
    HCERTSTORE s = store_with(VEC(v_crl_basic), NULL, 0, NULL, 0);
    REQUIRE(s);
    PCCERT_CONTEXT ca1 = cc_cert(VEC(v_ca1));
    REQUIRE(ca1);
    DWORD f = CERT_STORE_SIGNATURE_FLAG;
    PCCRL_CONTEXT c = U(CertGetCRLFromStore)(s, ca1, NULL, &f);
    CHECK(c != NULL);
    EXPECT_EQ(f & CERT_STORE_SIGNATURE_FLAG, 0);
    rel(c);
    relc(ca1);
    cc_close(s);
}
TEST(crlget_signature_flag_bad_signature) {
    REQUIRE(U(CertGetCRLFromStore));
    BYTE *bad = dup_bytes(VEC(v_crl_basic));
    bad[sizeof v_crl_basic - 5] ^= 0x40;
    HCERTSTORE s = cc_store(); REQUIRE(s);
    CHECK(cc_add_crl(s, bad, sizeof v_crl_basic, CERT_STORE_ADD_ALWAYS, NULL));
    PCCERT_CONTEXT ca1 = cc_cert(VEC(v_ca1));
    REQUIRE(ca1);
    DWORD f = CERT_STORE_SIGNATURE_FLAG;
    PCCRL_CONTEXT c = U(CertGetCRLFromStore)(s, ca1, NULL, &f);
    CHECK(c != NULL);
    EXPECT_EQ(f & CERT_STORE_SIGNATURE_FLAG, CERT_STORE_SIGNATURE_FLAG);
    rel(c);
    /* not requested: not checked, flag stays clear */
    f = 0;
    c = U(CertGetCRLFromStore)(s, ca1, NULL, &f);
    CHECK(c != NULL);
    EXPECT_EQ(f, 0);
    rel(c);
    relc(ca1); LocalFree(bad);
    cc_close(s);
}
TEST(crlget_time_validity_flag) {
    REQUIRE(U(CertGetCRLFromStore));
    PCCERT_CONTEXT ca1 = cc_cert(VEC(v_ca1));
    REQUIRE(ca1);
    HCERTSTORE s = store_with(VEC(v_crl_expired), NULL, 0, NULL, 0);
    REQUIRE(s);
    DWORD f = CERT_STORE_TIME_VALIDITY_FLAG;
    PCCRL_CONTEXT c = U(CertGetCRLFromStore)(s, ca1, NULL, &f);
    CHECK(c != NULL);
    EXPECT_EQ(f & CERT_STORE_TIME_VALIDITY_FLAG, CERT_STORE_TIME_VALIDITY_FLAG);
    rel(c);
    f = 0;
    c = U(CertGetCRLFromStore)(s, ca1, NULL, &f);
    CHECK(c != NULL); EXPECT_EQ(f, 0); rel(c);
    cc_close(s);
    s = store_with(VEC(v_crl_basic), NULL, 0, NULL, 0);
    f = CERT_STORE_TIME_VALIDITY_FLAG | CERT_STORE_SIGNATURE_FLAG;
    c = U(CertGetCRLFromStore)(s, ca1, NULL, &f);
    CHECK(c != NULL);
    EXPECT_EQ(f, 0);
    rel(c);
    cc_close(s);
    relc(ca1);
}
TEST(crlget_base_delta_flags) {
    REQUIRE(U(CertGetCRLFromStore));
    HCERTSTORE s = store_with(VEC(v_crl_basic), VEC(v_crl_delta), VEC(v_crl_idp));
    REQUIRE(s);
    PCCERT_CONTEXT ca1 = cc_cert(VEC(v_ca1));
    REQUIRE(ca1);
    int nb = 0, nd = 0, na = 0; PCCRL_CONTEXT c = NULL; DWORD f;
    f = CERT_STORE_BASE_CRL_FLAG;
    while ((c = U(CertGetCRLFromStore)(s, ca1, c, &f)) != NULL) { nb++; f = CERT_STORE_BASE_CRL_FLAG; }
    f = CERT_STORE_DELTA_CRL_FLAG;
    while ((c = U(CertGetCRLFromStore)(s, ca1, c, &f)) != NULL) { nd++; f = CERT_STORE_DELTA_CRL_FLAG; }
    f = 0;
    while ((c = U(CertGetCRLFromStore)(s, ca1, c, &f)) != NULL) { na++; f = 0; }
    EXPECT_EQ(nb, 2); EXPECT_EQ(nd, 1); EXPECT_EQ(na, 3);
    relc(ca1);
    cc_close(s);
}

/* ---- CertFindCertificateInCRL ---- */
TEST(crlentry_find_present) {
    REQUIRE(U(CertFindCertificateInCRL));
    PCCRL_CONTEXT crl = cc_crl(VEC(v_crl_basic));
    PCCERT_CONTEXT l1 = cc_cert(VEC(v_cert_1001)), l2 = cc_cert(VEC(v_cert_1002));
    REQUIRE(crl && l1 && l2);
    PCRL_ENTRY e = (PCRL_ENTRY)0x1234;
    CHECK(U(CertFindCertificateInCRL)(l1, crl, 0, NULL, &e));
    CHECK(e == &crl->pCrlInfo->rgCRLEntry[0]);
    e = NULL;
    CHECK(U(CertFindCertificateInCRL)(l2, crl, 0, NULL, &e));
    CHECK(e == &crl->pCrlInfo->rgCRLEntry[1]);
    relc(l1); relc(l2); rel(crl);
}
TEST(crlentry_find_absent_returns_true_null) {
    REQUIRE(U(CertFindCertificateInCRL));
    PCCRL_CONTEXT crl = cc_crl(VEC(v_crl_basic));
    PCCERT_CONTEXT l3 = cc_cert(VEC(v_cert_1003));
    REQUIRE(crl && l3);
    PCRL_ENTRY e = (PCRL_ENTRY)0x1234;
    SET_ERR(0);
    CHECK(U(CertFindCertificateInCRL)(l3, crl, 0, NULL, &e));
    CHECK(e == NULL);
    relc(l3); rel(crl);
}
TEST(crlentry_find_empty_crl) {
    REQUIRE(U(CertFindCertificateInCRL));
    PCCRL_CONTEXT crl = cc_crl(VEC(v_crl_empty));
    PCCERT_CONTEXT l1 = cc_cert(VEC(v_cert_1001));
    REQUIRE(crl && l1);
    PCRL_ENTRY e = (PCRL_ENTRY)0x1234;
    CHECK(U(CertFindCertificateInCRL)(l1, crl, 0, NULL, &e));
    CHECK(e == NULL);
    relc(l1); rel(crl);
}
TEST(crlentry_find_ignores_issuer) {
    /* only the serial number is compared: CA2's leaf with serial 0x1001 is found in CA1's CRL */
    REQUIRE(U(CertFindCertificateInCRL));
    PCCRL_CONTEXT crl = cc_crl(VEC(v_crl_basic));
    PCCERT_CONTEXT l = cc_cert(VEC(v_cert_c2_1001));
    REQUIRE(crl && l);
    PCRL_ENTRY e = NULL;
    CHECK(U(CertFindCertificateInCRL)(l, crl, 0, NULL, &e));
    CHECK(e == &crl->pCrlInfo->rgCRLEntry[0]);
    relc(l); rel(crl);
}
TEST(crlentry_find_flags_ignored) {
    REQUIRE(U(CertFindCertificateInCRL));
    PCCRL_CONTEXT crl = cc_crl(VEC(v_crl_basic));
    PCCERT_CONTEXT l1 = cc_cert(VEC(v_cert_1001));
    REQUIRE(crl && l1);
    PCRL_ENTRY e = NULL;
    CHECK(U(CertFindCertificateInCRL)(l1, crl, 0xffffffff, NULL, &e));
    CHECK(e != NULL);
    relc(l1); rel(crl);
}
TEST(crlentry_find_all_reason_entries) {
    REQUIRE(U(CertFindCertificateInCRL));
    PCCRL_CONTEXT crl = cc_crl(VEC(v_crl_reasons));
    REQUIRE(crl);
    struct { const BYTE *p; DWORD n; int present; } t[] = {
        { VEC(v_cert_r0), 1 }, { VEC(v_cert_r1), 1 }, { VEC(v_cert_r2), 1 }, { VEC(v_cert_r3), 1 }, { VEC(v_cert_r4), 1 },
        { VEC(v_cert_r5), 1 }, { VEC(v_cert_r6), 1 }, { VEC(v_cert_r8), 1 }, { VEC(v_cert_r9), 1 }, { VEC(v_cert_r10), 1 },
        { VEC(v_cert_1001), 0 }, { VEC(v_cert_cdp_match), 0 },
    };
    for (unsigned i = 0; i < sizeof t / sizeof t[0]; i++) {
        PCCERT_CONTEXT c = cc_cert(t[i].p, t[i].n);
        CHECKF(c != NULL, "cert %u", i);
        if (!c) continue;
        PCRL_ENTRY e = (PCRL_ENTRY)0x1;
        CHECKF(U(CertFindCertificateInCRL)(c, crl, 0, NULL, &e), "cert %u", i);
        CHECKF((e != NULL) == t[i].present, "cert %u present=%d", i, t[i].present);
        relc(c);
    }
    rel(crl);
}

/* ---- CertVerifyCRLRevocation ---- */
TEST(crlverify_revocation_basic) {
    REQUIRE(U(CertVerifyCRLRevocation));
    PCCRL_CONTEXT crl = cc_crl(VEC(v_crl_basic));
    PCCERT_CONTEXT l1 = cc_cert(VEC(v_cert_1001)), l2 = cc_cert(VEC(v_cert_1002)), l3 = cc_cert(VEC(v_cert_1003));
    REQUIRE(crl && l1 && l2 && l3);
    PCRL_INFO infos[1] = { crl->pCrlInfo };
    CHECK(!U(CertVerifyCRLRevocation)(CC_X509, l1->pCertInfo, 1, infos));
    CHECK(!U(CertVerifyCRLRevocation)(CC_X509, l2->pCertInfo, 1, infos));
    CHECK(U(CertVerifyCRLRevocation)(CC_X509, l3->pCertInfo, 1, infos));
    CHECK(U(CertVerifyCRLRevocation)(CC_X509, l3->pCertInfo, 0, infos));
    relc(l1); relc(l2); relc(l3); rel(crl);
}
TEST(crlverify_revocation_zero_crls) {
    REQUIRE(U(CertVerifyCRLRevocation));
    PCCERT_CONTEXT l1 = cc_cert(VEC(v_cert_1001));
    REQUIRE(l1);
    CHECK(U(CertVerifyCRLRevocation)(CC_X509, l1->pCertInfo, 0, NULL));
    relc(l1);
}
TEST(crlverify_revocation_encoding_type_ignored) {
    REQUIRE(U(CertVerifyCRLRevocation));
    PCCRL_CONTEXT crl = cc_crl(VEC(v_crl_basic));
    PCCERT_CONTEXT l1 = cc_cert(VEC(v_cert_1001));
    REQUIRE(crl && l1);
    PCRL_INFO infos[1] = { crl->pCrlInfo };
    CHECK(!U(CertVerifyCRLRevocation)(0, l1->pCertInfo, 1, infos));
    CHECK(!U(CertVerifyCRLRevocation)(1234, l1->pCertInfo, 1, infos));
    relc(l1); rel(crl);
}
TEST(crlverify_revocation_ignores_issuer) {
    REQUIRE(U(CertVerifyCRLRevocation));
    PCCRL_CONTEXT crl = cc_crl(VEC(v_crl_basic));
    PCCERT_CONTEXT l = cc_cert(VEC(v_cert_c2_1001));
    REQUIRE(crl && l);
    PCRL_INFO infos[1] = { crl->pCrlInfo };
    CHECK(!U(CertVerifyCRLRevocation)(CC_X509, l->pCertInfo, 1, infos));
    relc(l); rel(crl);
}
TEST(crlverify_revocation_multiple_crls) {
    REQUIRE(U(CertVerifyCRLRevocation));
    PCCRL_CONTEXT a = cc_crl(VEC(v_crl_empty)), b = cc_crl(VEC(v_crl_ca2)), c = cc_crl(VEC(v_crl_basic));
    PCCERT_CONTEXT l1 = cc_cert(VEC(v_cert_1001)), l3 = cc_cert(VEC(v_cert_1003));
    REQUIRE(a && b && c && l1 && l3);
    PCRL_INFO infos[3] = { a->pCrlInfo, b->pCrlInfo, c->pCrlInfo };
    CHECK(!U(CertVerifyCRLRevocation)(CC_X509, l1->pCertInfo, 3, infos));
    CHECK(U(CertVerifyCRLRevocation)(CC_X509, l3->pCertInfo, 3, infos));
    PCRL_INFO only_empty[1] = { a->pCrlInfo };
    CHECK(U(CertVerifyCRLRevocation)(CC_X509, l1->pCertInfo, 1, only_empty));
    relc(l1); relc(l3); rel(a); rel(b); rel(c);
}
TEST(crlverify_revocation_serial_integer_compare) {
    REQUIRE(U(CertVerifyCRLRevocation));
    PCCRL_CONTEXT crl = cc_crl(VEC(v_crl_basic));
    REQUIRE(crl);
    CERT_INFO ci; memset(&ci, 0, sizeof ci);
    BYTE s1[] = { 0x01, 0x10 }, s1pad[] = { 0x01, 0x10, 0x00 }, s2[] = { 0x01, 0x11 }, shi[] = { 0x01, 0x10, 0x01 };
    PCRL_INFO infos[1] = { crl->pCrlInfo };
    ci.SerialNumber.cbData = 2; ci.SerialNumber.pbData = s1;
    CHECK(!U(CertVerifyCRLRevocation)(CC_X509, &ci, 1, infos));
    ci.SerialNumber.cbData = 3; ci.SerialNumber.pbData = s1pad;
    BOOL padded = U(CertVerifyCRLRevocation)(CC_X509, &ci, 1, infos);
    t_note("serial with trailing zero byte (same integer) revoked: %d", !padded);
    ci.SerialNumber.cbData = 2; ci.SerialNumber.pbData = s2;
    CHECK(U(CertVerifyCRLRevocation)(CC_X509, &ci, 1, infos));
    ci.SerialNumber.cbData = 3; ci.SerialNumber.pbData = shi;
    CHECK(U(CertVerifyCRLRevocation)(CC_X509, &ci, 1, infos));
    BYTE one[] = { 0x01 };
    ci.SerialNumber.cbData = 1; ci.SerialNumber.pbData = one;
    CHECK(U(CertVerifyCRLRevocation)(CC_X509, &ci, 1, infos));
    rel(crl);
}

/* ---- CertVerifyCRLTimeValidity ---- */
static FILETIME mkft(ULONGLONG v) { FILETIME f; f.dwLowDateTime = (DWORD)v; f.dwHighDateTime = (DWORD)(v >> 32); return f; }
TEST(crltime_inside) {
    REQUIRE(U(CertVerifyCRLTimeValidity));
    PCCRL_CONTEXT c = cc_crl(VEC(v_crl_basic));
    REQUIRE(c);
    FILETIME t = mkft(V_THIS_FT + 10000000ULL * 86400 * 30);
    EXPECT_EQ(U(CertVerifyCRLTimeValidity)(&t, c->pCrlInfo), 0);
    rel(c);
}
TEST(crltime_before_thisupdate) {
    REQUIRE(U(CertVerifyCRLTimeValidity));
    PCCRL_CONTEXT c = cc_crl(VEC(v_crl_basic));
    REQUIRE(c);
    FILETIME t = mkft(V_THIS_FT - 1);
    EXPECT_EQ(U(CertVerifyCRLTimeValidity)(&t, c->pCrlInfo), (ULONG_PTR)(LONG)-1);
    t = mkft(0);
    EXPECT_EQ(U(CertVerifyCRLTimeValidity)(&t, c->pCrlInfo), (ULONG_PTR)(LONG)-1);
    rel(c);
}
TEST(crltime_after_nextupdate) {
    REQUIRE(U(CertVerifyCRLTimeValidity));
    PCCRL_CONTEXT c = cc_crl(VEC(v_crl_basic));
    REQUIRE(c);
    FILETIME t = mkft(V_NEXT_FT + 1);
    EXPECT_EQ(U(CertVerifyCRLTimeValidity)(&t, c->pCrlInfo), 1);
    rel(c);
}
TEST(crltime_boundaries_inclusive) {
    REQUIRE(U(CertVerifyCRLTimeValidity));
    PCCRL_CONTEXT c = cc_crl(VEC(v_crl_basic));
    REQUIRE(c);
    FILETIME t = mkft(V_THIS_FT);
    EXPECT_EQ(U(CertVerifyCRLTimeValidity)(&t, c->pCrlInfo), 0);
    t = mkft(V_NEXT_FT);
    EXPECT_EQ(U(CertVerifyCRLTimeValidity)(&t, c->pCrlInfo), 0);
    rel(c);
}
TEST(crltime_null_time_uses_now) {
    REQUIRE(U(CertVerifyCRLTimeValidity));
    PCCRL_CONTEXT ok = cc_crl(VEC(v_crl_basic)), exp = cc_crl(VEC(v_crl_expired));
    REQUIRE(ok && exp);
    EXPECT_EQ(U(CertVerifyCRLTimeValidity)(NULL, ok->pCrlInfo), 0);
    EXPECT_EQ(U(CertVerifyCRLTimeValidity)(NULL, exp->pCrlInfo), 1);
    rel(ok); rel(exp);
}
TEST(crltime_no_nextupdate_never_expires) {
    REQUIRE(U(CertVerifyCRLTimeValidity));
    PCCRL_CONTEXT c = cc_crl(VEC(v_crl_v1_nonext));
    REQUIRE(c);
    FILETIME t = mkft(V_THIS_FT + 10000000ULL * 86400 * 365 * 200);
    EXPECT_EQ(U(CertVerifyCRLTimeValidity)(&t, c->pCrlInfo), 0);
    t = mkft(V_THIS_FT - 1);
    EXPECT_EQ(U(CertVerifyCRLTimeValidity)(&t, c->pCrlInfo), (ULONG_PTR)(LONG)-1);
    EXPECT_EQ(U(CertVerifyCRLTimeValidity)(NULL, c->pCrlInfo), 0);
    rel(c);
}
TEST(crltime_expired_crl_window) {
    REQUIRE(U(CertVerifyCRLTimeValidity));
    PCCRL_CONTEXT c = cc_crl(VEC(v_crl_expired));
    REQUIRE(c);
    FILETIME t = mkft(V_EXP_NEXT_FT);
    EXPECT_EQ(U(CertVerifyCRLTimeValidity)(&t, c->pCrlInfo), 0);
    t = mkft(V_EXP_NEXT_FT + 1);
    EXPECT_EQ(U(CertVerifyCRLTimeValidity)(&t, c->pCrlInfo), 1);
    rel(c);
}

/* ---- CertIsValidCRLForCertificate ---- */
TEST(crlvalid_plain_crl_valid_for_any_cert) {
    REQUIRE(U(CertIsValidCRLForCertificate));
    PCCRL_CONTEXT crl = cc_crl(VEC(v_crl_basic));
    PCCERT_CONTEXT l1 = cc_cert(VEC(v_cert_1001)), l2 = cc_cert(VEC(v_cert_c2_1001)), ca = cc_cert(VEC(v_ca1));
    REQUIRE(crl && l1 && l2 && ca);
    CHECK(U(CertIsValidCRLForCertificate)(l1, crl, 0, NULL));
    CHECK(U(CertIsValidCRLForCertificate)(l2, crl, 0, NULL)); /* other issuer: still valid (no IDP) */
    CHECK(U(CertIsValidCRLForCertificate)(ca, crl, 0, NULL));
    CHECK(U(CertIsValidCRLForCertificate)(NULL, crl, 0, NULL));
    CHECK(U(CertIsValidCRLForCertificate)(l1, crl, 0xffffffff, NULL));
    relc(l1); relc(l2); relc(ca); rel(crl);
}
TEST(crlvalid_idp_requires_matching_cdp) {
    REQUIRE(U(CertIsValidCRLForCertificate));
    PCCRL_CONTEXT crl = cc_crl(VEC(v_crl_idp));
    PCCERT_CONTEXT plain = cc_cert(VEC(v_cert_1001)), m = cc_cert(VEC(v_cert_cdp_match)), o = cc_cert(VEC(v_cert_cdp_other));
    REQUIRE(crl && plain && m && o);
    SET_ERR(0);
    CHECK(!U(CertIsValidCRLForCertificate)(plain, crl, 0, NULL)); EXPECT_ERR(CC_E_NO_MATCH);
    SET_ERR(0);
    CHECK(U(CertIsValidCRLForCertificate)(m, crl, 0, NULL));
    SET_ERR(0);
    CHECK(!U(CertIsValidCRLForCertificate)(o, crl, 0, NULL)); EXPECT_ERR(CC_E_NO_MATCH);
    relc(plain); relc(m); relc(o); rel(crl);
}
TEST(crlvalid_delta_crl_is_plain) {
    REQUIRE(U(CertIsValidCRLForCertificate));
    PCCRL_CONTEXT crl = cc_crl(VEC(v_crl_delta));
    PCCERT_CONTEXT l1 = cc_cert(VEC(v_cert_1001));
    REQUIRE(crl && l1);
    CHECK(U(CertIsValidCRLForCertificate)(l1, crl, 0, NULL));
    relc(l1); rel(crl);
}
TEST(crlfind_issued_for_respects_idp) {
    REQUIRE(U(CertFindCRLInStore));
    HCERTSTORE s = store_with(VEC(v_crl_idp), NULL, 0, NULL, 0);
    REQUIRE(s);
    PCCERT_CONTEXT ca1 = cc_cert(VEC(v_ca1)), plain = cc_cert(VEC(v_cert_1001)), m = cc_cert(VEC(v_cert_cdp_match));
    REQUIRE(ca1 && plain && m);
    CRL_FIND_ISSUED_FOR_PARA p = { plain, ca1 };
    PCCRL_CONTEXT c = U(CertFindCRLInStore)(s, 0, 0, CRL_FIND_ISSUED_FOR, &p, NULL);
    t_note("ISSUED_FOR for cert without CDP vs IDP CRL: %s", c ? "found" : "not found");
    rel(c);
    p.pSubjectCert = m;
    c = U(CertFindCRLInStore)(s, 0, 0, CRL_FIND_ISSUED_FOR, &p, NULL);
    CHECK(c != NULL); rel(c);
    relc(ca1); relc(plain); relc(m);
    cc_close(s);
}
