#include "sm.h"
/* CERT_STORE_PROV_COLLECTION: sibling management, priority order, add routing, delete routing. */

#define HR_ACCESSDENIED ((DWORD)0x80070005)
static HCERTSTORE coll(void) { return U(CertOpenStore)(CERT_STORE_PROV_COLLECTION, 0, 0, 0, NULL); }
static BOOL sib(HCERTSTORE c, HCERTSTORE s, DWORD fl, DWORD prio) { return U(CertAddStoreToCollection)(c, s, fl, prio); }
static HCERTSTORE mem1(const BYTE *p, DWORD n) { HCERTSTORE h = sm_mem(); if (h && p) sm_addc(h, p, n, DISP_NEW, NULL); return h; }
static int first_is(HCERTSTORE h, const BYTE *p, DWORD n) {
    PCCERT_CONTEXT c = U(CertEnumCertificatesInStore)(h, NULL); int r = sm_same_enc(c, p, n); sm_freec(c); return r;
}

TEST(csl_open_empty_collection) {
    REQUIRE(U(CertOpenStore));
    HCERTSTORE c = coll();
    CHECK(c != NULL); if (!c) return;
    SET_ERR(0);
    CHECK(U(CertEnumCertificatesInStore)(c, NULL) == NULL); EXPECT_ERR(HR_NOT_FOUND);
    CHECK(U(CertEnumCRLsInStore)(c, NULL) == NULL);
    CHECK(U(CertEnumCTLsInStore)(c, NULL) == NULL);
    CHECK(U(CertCloseStore)(c, 0));
}
TEST(csl_open_collection_string_name) {
    REQUIRE(U(CertOpenStore));
    HCERTSTORE c = U(CertOpenStore)(sz_CERT_STORE_PROV_COLLECTION, 0, 0, 0, NULL);
    CHECK(c != NULL);
    if (c) { HCERTSTORE s = mem1(VEC(v_cert_a)); CHECK(sib(c, s, 0, 0)); EXPECT_EQ(sm_ncerts(c), 1); sm_close(c); sm_close(s); }
}
TEST(csl_add_to_empty_collection_denied) {
    REQUIRE(U(CertAddStoreToCollection));
    HCERTSTORE c = coll(); if (!c) return;
    SET_ERR(0);
    CHECK(!sm_addc(c, VEC(v_cert_a), DISP_NEW, NULL)); EXPECT_ERR(HR_ACCESSDENIED);
    SET_ERR(0);
    CHECK(!sm_addcrl(c, VEC(v_crl_1a), DISP_NEW, NULL)); EXPECT_ERR(HR_ACCESSDENIED);
    SET_ERR(0);
    CHECK(!sm_addctl(c, VEC(v_ctl_1a), DISP_NEW, NULL)); EXPECT_ERR(HR_ACCESSDENIED);
    sm_close(c);
}
TEST(csl_add_without_enable_flag_denied) {
    REQUIRE(U(CertAddStoreToCollection));
    HCERTSTORE c = coll(), s = sm_mem(); if (!c || !s) return;
    CHECK(sib(c, s, 0, 0));
    SET_ERR(0);
    CHECK(!sm_addc(c, VEC(v_cert_a), DISP_NEW, NULL)); EXPECT_ERR(HR_ACCESSDENIED);
    EXPECT_EQ(sm_ncerts(s), 0);
    sm_close(c); sm_close(s);
}
TEST(csl_add_goes_to_enabled_sibling) {
    REQUIRE(U(CertAddStoreToCollection));
    HCERTSTORE c = coll(), s = sm_mem(); if (!c || !s) return;
    CHECK(sib(c, s, CERT_PHYSICAL_STORE_ADD_ENABLE_FLAG, 0));
    PCCERT_CONTEXT ctx = NULL;
    CHECK(sm_addc(c, VEC(v_cert_a), DISP_NEW, &ctx));
    CHECK(sm_same_enc(ctx, VEC(v_cert_a)));
    EXPECT_EQ(sm_ncerts(s), 1); EXPECT_EQ(sm_ncerts(c), 1);
    t_note("context returned by collection add: hCertStore is collection=%d sibling=%d", ctx && ctx->hCertStore == c, ctx && ctx->hCertStore == s);
    sm_freec(ctx); sm_close(c); sm_close(s);
}
TEST(csl_add_all_types_to_enabled_sibling) {
    REQUIRE(U(CertAddStoreToCollection));
    HCERTSTORE c = coll(), s = sm_mem(); if (!c || !s) return;
    sib(c, s, CERT_PHYSICAL_STORE_ADD_ENABLE_FLAG, 0);
    CHECK(sm_addc(c, VEC(v_cert_a), DISP_NEW, NULL));
    CHECK(sm_addcrl(c, VEC(v_crl_1a), DISP_NEW, NULL));
    CHECK(sm_addctl(c, VEC(v_ctl_1a), DISP_NEW, NULL));
    EXPECT_EQ(sm_ncerts(s), 1); EXPECT_EQ(sm_ncrls(s), 1); EXPECT_EQ(sm_nctls(s), 1);
    EXPECT_EQ(sm_ncerts(c), 1); EXPECT_EQ(sm_ncrls(c), 1); EXPECT_EQ(sm_nctls(c), 1);
    sm_close(c); sm_close(s);
}
TEST(csl_enum_spans_siblings) {
    REQUIRE(U(CertAddStoreToCollection));
    HCERTSTORE c = coll(), s1 = mem1(VEC(v_cert_a)), s2 = mem1(VEC(v_cert_b)), s3 = mem1(VEC(v_cert_c));
    sib(c, s1, 0, 0); sib(c, s2, 0, 0); sib(c, s3, 0, 0);
    EXPECT_EQ(sm_ncerts(c), 3);
    sm_close(c); sm_close(s1); sm_close(s2); sm_close(s3);
}
TEST(csl_priority_zero_appends_in_order) {
    REQUIRE(U(CertAddStoreToCollection));
    HCERTSTORE c = coll(), s1 = mem1(VEC(v_cert_a)), s2 = mem1(VEC(v_cert_b)), s3 = mem1(VEC(v_cert_c));
    sib(c, s1, 0, 0); sib(c, s2, 0, 0); sib(c, s3, 0, 0);
    const BYTE *e[3] = { v_cert_a, v_cert_b, v_cert_c }; DWORD n[3] = { sizeof v_cert_a, sizeof v_cert_b, sizeof v_cert_c };
    PCCERT_CONTEXT x = NULL; int i = 0;
    while ((x = U(CertEnumCertificatesInStore)(c, x)) != NULL && i < 3) { CHECKF(sm_same_enc(x, e[i], n[i]), "idx %d", i); i++; }
    EXPECT_EQ(i, 3);
    sm_close(c); sm_close(s1); sm_close(s2); sm_close(s3);
}
TEST(csl_priority_higher_enumerates_first) {
    REQUIRE(U(CertAddStoreToCollection));
    HCERTSTORE c = coll(), s1 = mem1(VEC(v_cert_a)), s2 = mem1(VEC(v_cert_b)), s3 = mem1(VEC(v_cert_c));
    sib(c, s1, 0, 10); sib(c, s2, 0, 30); sib(c, s3, 0, 20);
    const BYTE *e[3] = { v_cert_b, v_cert_c, v_cert_a }; DWORD n[3] = { sizeof v_cert_b, sizeof v_cert_c, sizeof v_cert_a };
    PCCERT_CONTEXT x = NULL; int i = 0;
    while ((x = U(CertEnumCertificatesInStore)(c, x)) != NULL && i < 3) { CHECKF(sm_same_enc(x, e[i], n[i]), "idx %d", i); i++; }
    EXPECT_EQ(i, 3);
    sm_close(c); sm_close(s1); sm_close(s2); sm_close(s3);
}
TEST(csl_priority_zero_goes_after_prioritised) {
    REQUIRE(U(CertAddStoreToCollection));
    HCERTSTORE c = coll(), s1 = mem1(VEC(v_cert_a)), s2 = mem1(VEC(v_cert_b));
    sib(c, s1, 0, 0); sib(c, s2, 0, 5);
    CHECK(first_is(c, VEC(v_cert_b)));               /* priority 5 sorts before the zero-priority append */
    sm_close(c); sm_close(s1); sm_close(s2);
}
TEST(csl_add_routes_to_highest_priority_enabled) {
    REQUIRE(U(CertAddStoreToCollection));
    HCERTSTORE c = coll(), lo = sm_mem(), hi = sm_mem(), off = sm_mem();
    sib(c, lo, CERT_PHYSICAL_STORE_ADD_ENABLE_FLAG, 10);
    sib(c, hi, CERT_PHYSICAL_STORE_ADD_ENABLE_FLAG, 20);
    sib(c, off, 0, 30);                                /* highest priority but not writable */
    CHECK(sm_addc(c, VEC(v_cert_a), DISP_NEW, NULL));
    EXPECT_EQ(sm_ncerts(hi), 1); EXPECT_EQ(sm_ncerts(lo), 0); EXPECT_EQ(sm_ncerts(off), 0);
    sm_close(c); sm_close(lo); sm_close(hi); sm_close(off);
}
TEST(csl_add_routes_first_enabled_in_append_order) {
    REQUIRE(U(CertAddStoreToCollection));
    HCERTSTORE c = coll(), s1 = sm_mem(), s2 = sm_mem();
    sib(c, s1, CERT_PHYSICAL_STORE_ADD_ENABLE_FLAG, 0);
    sib(c, s2, CERT_PHYSICAL_STORE_ADD_ENABLE_FLAG, 0);
    CHECK(sm_addc(c, VEC(v_cert_a), DISP_NEW, NULL));
    EXPECT_EQ(sm_ncerts(s1), 1); EXPECT_EQ(sm_ncerts(s2), 0);
    sm_close(c); sm_close(s1); sm_close(s2);
}
TEST(csl_add_skips_readonly_enabled_sibling) {
    REQUIRE(U(CertAddStoreToCollection));
    HCERTSTORE c = coll(), ro = U(CertOpenStore)(CERT_STORE_PROV_MEMORY, 0, 0, CERT_STORE_READONLY_FLAG, NULL), rw = sm_mem();
    if (!c || !ro || !rw) return;
    sib(c, ro, CERT_PHYSICAL_STORE_ADD_ENABLE_FLAG, 20);
    sib(c, rw, CERT_PHYSICAL_STORE_ADD_ENABLE_FLAG, 10);
    BOOL r = sm_addc(c, VEC(v_cert_a), DISP_NEW, NULL);
    CHECK(r);
    t_note("readonly(prio 20)=%d writable(prio 10)=%d", sm_ncerts(ro), sm_ncerts(rw));
    sm_close(c); sm_close(ro); sm_close(rw);
}
TEST(csl_new_existing_in_unwritable_sibling) {
    REQUIRE(U(CertAddStoreToCollection));
    HCERTSTORE c = coll(), s0 = mem1(VEC(v_cert_a)), w = sm_mem();
    sib(c, s0, 0, 0); sib(c, w, CERT_PHYSICAL_STORE_ADD_ENABLE_FLAG, 0);
    SET_ERR(0);
    CHECK(!sm_addc(c, VEC(v_cert_a), DISP_NEW, NULL)); EXPECT_ERR(HR_EXISTS);
    EXPECT_EQ(sm_ncerts(w), 0);
    sm_close(c); sm_close(s0); sm_close(w);
}
TEST(csl_replace_other_bytes_goes_to_writable_sibling) {
    REQUIRE(U(CertAddStoreToCollection));
    HCERTSTORE c = coll(), s0 = mem1(VEC(v_cert_a)), w = sm_mem();
    sib(c, s0, 0, 0); sib(c, w, CERT_PHYSICAL_STORE_ADD_ENABLE_FLAG, 0);
    CHECK(sm_addc(c, VEC(v_cert_a2), DISP_REPL, NULL));
    /* Win10: a2 does not match a (hash identity), so it is added to the writable sibling; s0 is untouched */
    CHECK(first_is(s0, VEC(v_cert_a)));
    EXPECT_EQ(sm_ncerts(w), 1);
    sm_close(c); sm_close(s0); sm_close(w);
}
TEST(csl_use_existing_does_not_add) {
    REQUIRE(U(CertAddStoreToCollection));
    HCERTSTORE c = coll(), s0 = mem1(VEC(v_cert_a)), w = sm_mem();
    sib(c, s0, 0, 0); sib(c, w, CERT_PHYSICAL_STORE_ADD_ENABLE_FLAG, 0);
    PCCERT_CONTEXT x = NULL;
    CHECK(sm_addc(c, VEC(v_cert_a), DISP_USE, &x));
    CHECK(sm_same_enc(x, VEC(v_cert_a)));
    EXPECT_EQ(sm_ncerts(w), 0); EXPECT_EQ(sm_ncerts(s0), 1);
    sm_freec(x); sm_close(c); sm_close(s0); sm_close(w);
}
TEST(csl_always_adds_to_writable_even_if_exists) {
    REQUIRE(U(CertAddStoreToCollection));
    HCERTSTORE c = coll(), s0 = mem1(VEC(v_cert_a)), w = sm_mem();
    sib(c, s0, 0, 0); sib(c, w, CERT_PHYSICAL_STORE_ADD_ENABLE_FLAG, 0);
    CHECK(sm_addc(c, VEC(v_cert_a), DISP_ALWAYS, NULL));
    EXPECT_EQ(sm_ncerts(w), 1); EXPECT_EQ(sm_ncerts(c), 2);
    sm_close(c); sm_close(s0); sm_close(w);
}
TEST(csl_invalid_disposition) {
    REQUIRE(U(CertAddStoreToCollection));
    HCERTSTORE c = coll(), w = sm_mem();
    sib(c, w, CERT_PHYSICAL_STORE_ADD_ENABLE_FLAG, 0);
    SET_ERR(0);
    CHECK(!sm_addc(c, VEC(v_cert_a), 0, NULL));
    t_note("collection add with disposition 0 gle=0x%lx", GetLastError());
    sm_close(c); sm_close(w);
}
TEST(csl_delete_through_collection_deletes_in_sibling) {
    REQUIRE(U(CertAddStoreToCollection));
    HCERTSTORE c = coll(), s1 = mem1(VEC(v_cert_a)), s2 = mem1(VEC(v_cert_b));
    sib(c, s1, 0, 0); sib(c, s2, 0, 0);
    CRYPT_HASH_BLOB hb = { 20, (BYTE *)v_sha1_b };
    PCCERT_CONTEXT x = U(CertFindCertificateInStore)(c, X509_ASN_ENCODING, 0, CERT_FIND_SHA1_HASH, &hb, NULL);
    CHECK(x != NULL);
    if (x) CHECK(U(CertDeleteCertificateFromStore)(x));
    EXPECT_EQ(sm_ncerts(s2), 0); EXPECT_EQ(sm_ncerts(s1), 1); EXPECT_EQ(sm_ncerts(c), 1);
    sm_close(c); sm_close(s1); sm_close(s2);
}
TEST(csl_delete_all_while_enumerating) {
    REQUIRE(U(CertAddStoreToCollection));
    if (t_is_wine()) { t_skip("emulator loops when enumerating past a deleted element"); return; }
    HCERTSTORE c = coll(), s1 = mem1(VEC(v_cert_a)), s2 = mem1(VEC(v_cert_b));
    sib(c, s1, 0, 0); sib(c, s2, 0, 0);
    PCCERT_CONTEXT x = NULL; int n = 0;
    while ((x = U(CertEnumCertificatesInStore)(c, x)) != NULL && n < 5) { n++; CHECK(U(CertDeleteCertificateFromStore)(U(CertDuplicateCertificateContext)(x))); }
    EXPECT_EQ(n, 2); EXPECT_EQ(sm_ncerts(s1), 0); EXPECT_EQ(sm_ncerts(s2), 0);
    sm_close(c); sm_close(s1); sm_close(s2);
}
TEST(csl_sibling_changes_visible_live) {
    REQUIRE(U(CertAddStoreToCollection));
    HCERTSTORE c = coll(), s = sm_mem();
    sib(c, s, 0, 0);
    EXPECT_EQ(sm_ncerts(c), 0);
    sm_addc(s, VEC(v_cert_a), DISP_NEW, NULL);
    EXPECT_EQ(sm_ncerts(c), 1);
    sm_addc(s, VEC(v_cert_b), DISP_NEW, NULL);
    EXPECT_EQ(sm_ncerts(c), 2);
    sm_close(c); sm_close(s);
}
TEST(csl_sibling_survives_handle_close) {
    REQUIRE(U(CertAddStoreToCollection));
    HCERTSTORE c = coll(), s = mem1(VEC(v_cert_a));
    sib(c, s, 0, 0);
    sm_close(s);                                    /* the collection holds its own reference */
    EXPECT_EQ(sm_ncerts(c), 1);
    sm_close(c);
}
TEST(csl_remove_store_from_collection) {
    REQUIRE(U(CertRemoveStoreFromCollection));
    HCERTSTORE c = coll(), s1 = mem1(VEC(v_cert_a)), s2 = mem1(VEC(v_cert_b));
    sib(c, s1, 0, 0); sib(c, s2, 0, 0);
    EXPECT_EQ(sm_ncerts(c), 2);
    U(CertRemoveStoreFromCollection)(c, s1);
    EXPECT_EQ(sm_ncerts(c), 1);
    EXPECT_EQ(sm_ncerts(s1), 1);                    /* the sibling itself is unchanged */
    CHECK(first_is(c, VEC(v_cert_b)));
    U(CertRemoveStoreFromCollection)(c, s2);
    EXPECT_EQ(sm_ncerts(c), 0);
    sm_close(c); sm_close(s1); sm_close(s2);
}
TEST(csl_remove_store_not_member_is_harmless) {
    REQUIRE(U(CertRemoveStoreFromCollection));
    HCERTSTORE c = coll(), s1 = mem1(VEC(v_cert_a)), s2 = mem1(VEC(v_cert_b));
    sib(c, s1, 0, 0);
    U(CertRemoveStoreFromCollection)(c, s2);
    EXPECT_EQ(sm_ncerts(c), 1);
    sm_close(c); sm_close(s1); sm_close(s2);
}
TEST(csl_remove_then_add_disabled) {
    REQUIRE(U(CertRemoveStoreFromCollection));
    HCERTSTORE c = coll(), s = sm_mem();
    sib(c, s, CERT_PHYSICAL_STORE_ADD_ENABLE_FLAG, 0);
    U(CertRemoveStoreFromCollection)(c, s);
    SET_ERR(0);
    CHECK(!sm_addc(c, VEC(v_cert_a), DISP_NEW, NULL)); EXPECT_ERR(HR_ACCESSDENIED);
    sm_close(c); sm_close(s);
}
TEST(csl_remove_keeps_enumerated_context_valid) {
    REQUIRE(U(CertRemoveStoreFromCollection));
    HCERTSTORE c = coll(), s = mem1(VEC(v_cert_a));
    sib(c, s, 0, 0);
    PCCERT_CONTEXT x = U(CertEnumCertificatesInStore)(c, NULL);
    U(CertRemoveStoreFromCollection)(c, s);
    CHECK(sm_same_enc(x, VEC(v_cert_a)));
    sm_freec(x); sm_close(c); sm_close(s);
}
TEST(csl_same_sibling_twice) {
    REQUIRE(U(CertAddStoreToCollection));
    HCERTSTORE c = coll(), s = mem1(VEC(v_cert_a));
    BOOL r1 = sib(c, s, 0, 0), r2 = sib(c, s, 0, 0);
    CHECK(r1);
    t_note("second add of same sibling -> %d; collection count %d", r2, sm_ncerts(c));
    sm_close(c); sm_close(s);
}
TEST(csl_add_null_sibling) {
    REQUIRE(U(CertAddStoreToCollection));
    HCERTSTORE c = coll();
    SET_ERR(0);
    BOOL r = sib(c, NULL, 0, 0);
    t_note("add NULL sibling -> %d gle=0x%lx", r, GetLastError());
    sm_close(c);
}
TEST(csl_add_to_non_collection_store) {
    REQUIRE(U(CertAddStoreToCollection));
    HCERTSTORE m = sm_mem(), s = sm_mem();
    SET_ERR(0);
    BOOL r = sib(m, s, 0, 0);
    t_note("add sibling to a memory store -> %d gle=0x%lx", r, GetLastError());
    sm_close(m); sm_close(s);
}
TEST(csl_nested_collections) {
    REQUIRE(U(CertAddStoreToCollection));
    HCERTSTORE outer = coll(), inner = coll(), s = mem1(VEC(v_cert_a)), t = sm_mem();
    sib(inner, s, 0, 0);
    sib(outer, inner, 0, 0);
    sib(outer, t, CERT_PHYSICAL_STORE_ADD_ENABLE_FLAG, 0);
    EXPECT_EQ(sm_ncerts(outer), 1);
    CHECK(sm_addc(outer, VEC(v_cert_b), DISP_NEW, NULL));
    EXPECT_EQ(sm_ncerts(outer), 2); EXPECT_EQ(sm_ncerts(t), 1); EXPECT_EQ(sm_ncerts(inner), 1);
    sm_close(outer); sm_close(inner); sm_close(s); sm_close(t);
}
TEST(csl_nested_add_through_inner) {
    REQUIRE(U(CertAddStoreToCollection));
    HCERTSTORE outer = coll(), inner = coll(), s = sm_mem();
    sib(inner, s, CERT_PHYSICAL_STORE_ADD_ENABLE_FLAG, 0);
    sib(outer, inner, CERT_PHYSICAL_STORE_ADD_ENABLE_FLAG, 0);
    CHECK(sm_addc(outer, VEC(v_cert_a), DISP_NEW, NULL));
    EXPECT_EQ(sm_ncerts(s), 1);
    sm_close(outer); sm_close(inner); sm_close(s);
}
TEST(csl_find_across_siblings) {
    REQUIRE(U(CertAddStoreToCollection));
    HCERTSTORE c = coll(), s1 = mem1(VEC(v_cert_a)), s2 = mem1(VEC(v_cert_b));
    sib(c, s1, 0, 0); sib(c, s2, 0, 0);
    PCCERT_CONTEXT x = U(CertFindCertificateInStore)(c, X509_ASN_ENCODING, 0, CERT_FIND_SUBJECT_STR_W, L"Cert B", NULL);
    CHECK(sm_same_enc(x, VEC(v_cert_b)));
    PCCERT_CONTEXT n = U(CertFindCertificateInStore)(c, X509_ASN_ENCODING, 0, CERT_FIND_ISSUER_STR_W, L"Store CA", NULL); int cnt = 0;
    while (n) { cnt++; n = U(CertFindCertificateInStore)(c, X509_ASN_ENCODING, 0, CERT_FIND_ISSUER_STR_W, L"Store CA", n); }
    EXPECT_EQ(cnt, 2);
    sm_freec(x); sm_close(c); sm_close(s1); sm_close(s2);
}
TEST(csl_crls_and_ctls_span_siblings) {
    REQUIRE(U(CertAddStoreToCollection));
    HCERTSTORE c = coll(), s1 = sm_mem(), s2 = sm_mem();
    sm_addcrl(s1, VEC(v_crl_1a), DISP_NEW, NULL); sm_addcrl(s2, VEC(v_crl_2), DISP_NEW, NULL);
    sm_addctl(s1, VEC(v_ctl_1a), DISP_NEW, NULL); sm_addctl(s2, VEC(v_ctl_2), DISP_NEW, NULL);
    sib(c, s1, 0, 0); sib(c, s2, 0, 0);
    EXPECT_EQ(sm_ncrls(c), 2); EXPECT_EQ(sm_nctls(c), 2); EXPECT_EQ(sm_ncerts(c), 0);
    sm_close(c); sm_close(s1); sm_close(s2);
}
TEST(csl_duplicate_cert_in_two_siblings_enumerated_twice) {
    REQUIRE(U(CertAddStoreToCollection));
    HCERTSTORE c = coll(), s1 = mem1(VEC(v_cert_a)), s2 = mem1(VEC(v_cert_a));
    sib(c, s1, 0, 0); sib(c, s2, 0, 0);
    EXPECT_EQ(sm_ncerts(c), 2);
    sm_close(c); sm_close(s1); sm_close(s2);
}
TEST(csl_link_into_collection_rejected) {
    REQUIRE(U(CertAddCertificateLinkToStore));
    HCERTSTORE c = coll(), w = sm_mem(), s = sm_mem();
    sib(c, w, CERT_PHYSICAL_STORE_ADD_ENABLE_FLAG, 0);
    PCCERT_CONTEXT x = NULL;
    sm_addc(s, VEC(v_cert_a), DISP_NEW, &x);
    SET_ERR(0);
    BOOL r = U(CertAddCertificateLinkToStore)(c, x, DISP_NEW, NULL);
    CHECK(!r);                                       /* documented: links cannot be added to a collection */
    t_note("link into collection gle=0x%lx", GetLastError());
    sm_freec(x); sm_close(c); sm_close(w); sm_close(s);
}
TEST(csl_add_context_from_sibling_into_collection) {
    REQUIRE(U(CertAddCertificateContextToStore));
    HCERTSTORE c = coll(), w = sm_mem(), s = sm_mem();
    sib(c, w, CERT_PHYSICAL_STORE_ADD_ENABLE_FLAG, 0);
    PCCERT_CONTEXT x = NULL, y = NULL;
    sm_addc(s, VEC(v_cert_a), DISP_NEW, &x);
    CHECK(U(CertAddCertificateContextToStore)(c, x, DISP_NEW, &y));
    CHECK(sm_same_enc(y, VEC(v_cert_a)));
    EXPECT_EQ(sm_ncerts(w), 1);
    sm_freec(x); sm_freec(y); sm_close(c); sm_close(w); sm_close(s);
}
TEST(csl_properties_visible_via_sibling) {
    REQUIRE(U(CertAddStoreToCollection));
    HCERTSTORE c = coll(), s = mem1(VEC(v_cert_a));
    sib(c, s, 0, 0);
    PCCERT_CONTEXT x = U(CertEnumCertificatesInStore)(c, NULL);
    static const WCHAR fn[] = L"collname";
    CRYPT_DATA_BLOB b = { sizeof fn, (BYTE *)fn };
    CHECK(U(CertSetCertificateContextProperty)(x, CERT_FRIENDLY_NAME_PROP_ID, 0, &b));
    PCCERT_CONTEXT y = U(CertEnumCertificatesInStore)(s, NULL);
    DWORD cb = 0;
    BOOL r = U(CertGetCertificateContextProperty)(y, CERT_FRIENDLY_NAME_PROP_ID, NULL, &cb);
    t_note("property set via collection context visible in sibling: %d", r);
    CHECK(r);
    sm_freec(x); sm_freec(y); sm_close(c); sm_close(s);
}
TEST(csl_force_close_collection_before_siblings) {
    REQUIRE(U(CertAddStoreToCollection));
    HCERTSTORE c = coll(), s1 = sm_abc(), s2 = sm_abc();
    sib(c, s1, 0, 0); sib(c, s2, 0, 0);
    CHECK(U(CertCloseStore)(c, CERT_CLOSE_STORE_FORCE_FLAG));
    CHECK(U(CertCloseStore)(s1, CERT_CLOSE_STORE_FORCE_FLAG));
    CHECK(U(CertCloseStore)(s2, CERT_CLOSE_STORE_FORCE_FLAG));
}
TEST(csl_duplicate_collection_handle) {
    REQUIRE(U(CertDuplicateStore));
    HCERTSTORE c = coll(), s = mem1(VEC(v_cert_a));
    sib(c, s, 0, 0);
    HCERTSTORE d = U(CertDuplicateStore)(c);
    CHECK(d == c);
    sm_close(c);
    EXPECT_EQ(sm_ncerts(d), 1);
    sm_close(d); sm_close(s);
}
TEST(csl_many_siblings) {
    REQUIRE(U(CertAddStoreToCollection));
    HCERTSTORE c = coll(), s[40];
    for (int i = 0; i < 40; i++) { s[i] = sm_mem(); sib(c, s[i], 0, 0); if (i % 2) sm_addc(s[i], VEC(v_cert_a), DISP_ALWAYS, NULL); }
    EXPECT_EQ(sm_ncerts(c), 20);
    for (int i = 0; i < 40; i++) U(CertRemoveStoreFromCollection)(c, s[i]);
    EXPECT_EQ(sm_ncerts(c), 0);
    sm_close(c); for (int i = 0; i < 40; i++) sm_close(s[i]);
}
TEST(csl_newer_other_bytes_through_collection_adds) {
    REQUIRE(U(CertAddStoreToCollection));
    HCERTSTORE c = coll(), s0 = mem1(VEC(v_cert_a2)), w = sm_mem();
    sib(c, s0, 0, 0); sib(c, w, CERT_PHYSICAL_STORE_ADD_ENABLE_FLAG, 0);
    SET_ERR(0);
    CHECK(sm_addc(c, VEC(v_cert_a), DISP_NEWER, NULL));      /* Win10: hash identity, a does not match a2 */
    EXPECT_EQ(sm_ncerts(w), 1);
    sm_close(c); sm_close(s0); sm_close(w);
}
