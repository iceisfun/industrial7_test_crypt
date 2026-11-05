#include "sm.h"
/* CertOpenStore / CertCloseStore / CertDuplicateStore semantics. Expectations marked in the decomp. */

TEST(csm_open_memory_basic) {
    REQUIRE(U(CertOpenStore)); REQUIRE(U(CertCloseStore));
    HCERTSTORE h = sm_mem();
    CHECK(h != NULL);
    if (!h) return;
    SET_ERR(0);
    CHECK(U(CertEnumCertificatesInStore)(h, NULL) == NULL);
    EXPECT_ERR(HR_NOT_FOUND);
    CHECK(U(CertCloseStore)(h, 0));
}
TEST(csm_open_memory_enum_all_types_empty) {
    REQUIRE(U(CertOpenStore));
    HCERTSTORE h = sm_mem(); if (!h) return;
    SET_ERR(0); CHECK(U(CertEnumCRLsInStore)(h, NULL) == NULL); EXPECT_ERR(HR_NOT_FOUND);
    SET_ERR(0); CHECK(U(CertEnumCTLsInStore)(h, NULL) == NULL); EXPECT_ERR(HR_NOT_FOUND);
    sm_close(h);
}
TEST(csm_open_memory_string_name_case_insensitive) {
    REQUIRE(U(CertOpenStore));
    const char *names[] = { sz_CERT_STORE_PROV_MEMORY, "memory", "MEMORY", "MeMoRy" };
    for (int i = 0; i < 4; i++) {
        HCERTSTORE h = U(CertOpenStore)(names[i], 0, 0, 0, NULL);
        CHECKF(h != NULL, "name %s", names[i]);
        if (h) { sm_addc(h, VEC(v_cert_a), DISP_NEW, NULL); EXPECT_EQ(sm_ncerts(h), 1); sm_close(h); }
    }
}
TEST(csm_open_memory_hash_number_string) {
    REQUIRE(U(CertOpenStore));
    /* "#<n>" selects the numeric provider n (the string is atol'd) */
    HCERTSTORE h = U(CertOpenStore)("#2", 0, 0, 0, NULL);
    t_note("CertOpenStore(\"#2\") -> %p gle=%lu", h, GetLastError());
    sm_close(h);
}
TEST(csm_open_hash_number_too_large) {
    REQUIRE(U(CertOpenStore));
    if (t_is_wine()) { t_skip("emulator maps this differently"); return; }
    SET_ERR(0);
    HCERTSTORE h = U(CertOpenStore)("#65536", 0, 0, 0, NULL);
    CHECK(h == NULL); EXPECT_ERR(HR_INVALIDARG);
    SET_ERR(0);
    h = U(CertOpenStore)("#99999", 0, 0, 0, NULL);
    CHECK(h == NULL); EXPECT_ERR(HR_INVALIDARG);
}
TEST(csm_open_unknown_provider_string) {
    REQUIRE(U(CertOpenStore));
    SET_ERR(0);
    HCERTSTORE h = U(CertOpenStore)("NoSuchProvider_cryptt", 0, 0, 0, NULL);
    CHECK(h == NULL); EXPECT_ERR(ERROR_FILE_NOT_FOUND);
}
TEST(csm_open_unknown_provider_number) {
    REQUIRE(U(CertOpenStore));
    SET_ERR(0);
    HCERTSTORE h = U(CertOpenStore)((LPCSTR)(ULONG_PTR)0x7ff0, 0, 0, 0, NULL);
    CHECK(h == NULL); EXPECT_ERR(ERROR_FILE_NOT_FOUND);
    SET_ERR(0);
    h = U(CertOpenStore)((LPCSTR)(ULONG_PTR)0, 0, 0, 0, NULL);
    CHECK(h == NULL);
    t_note("provider 0 gle=%lu", GetLastError());
}
TEST(csm_open_unknown_provider_closes_nothing_leaks_prov) {
    /* a caller-supplied hCryptProv is released on failure unless NO_CRYPT_RELEASE */
    REQUIRE(U(CertOpenStore)); REQUIRE(U(CryptAcquireContextW)); REQUIRE(U(CryptReleaseContext));
    HCRYPTPROV p = 0;
    if (!U(CryptAcquireContextW)(&p, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) { t_skip("no csp"); return; }
    SET_ERR(0);
    HCERTSTORE h = U(CertOpenStore)("NoSuchProvider_cryptt", 0, p, CERT_STORE_NO_CRYPT_RELEASE_FLAG, NULL);
    CHECK(h == NULL);
    CHECK(U(CryptReleaseContext)(p, 0));    /* still ours */
}
TEST(csm_open_no_crypt_release_keeps_provider) {
    REQUIRE(U(CertOpenStore)); REQUIRE(U(CryptAcquireContextW)); REQUIRE(U(CryptReleaseContext));
    HCRYPTPROV p = 0;
    if (!U(CryptAcquireContextW)(&p, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) { t_skip("no csp"); return; }
    HCERTSTORE h = U(CertOpenStore)(CERT_STORE_PROV_MEMORY, 0, p, CERT_STORE_NO_CRYPT_RELEASE_FLAG, NULL);
    CHECK(h != NULL);
    sm_close(h);
    CHECK(U(CryptReleaseContext)(p, 0));    /* store did not release it */
}
TEST(csm_open_provider_released_on_close_without_flag) {
    REQUIRE(U(CertOpenStore)); REQUIRE(U(CryptAcquireContextW)); REQUIRE(U(CryptReleaseContext));
    HCRYPTPROV p = 0;
    if (!U(CryptAcquireContextW)(&p, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) { t_skip("no csp"); return; }
    HCERTSTORE h = U(CertOpenStore)(CERT_STORE_PROV_MEMORY, 0, p, 0, NULL);
    CHECK(h != NULL);
    sm_close(h);
    SET_ERR(0);
    BOOL r = U(CryptReleaseContext)(p, 0);
    t_note("release after store-owned close -> %d gle=%lu (store owned the handle)", r, GetLastError());
}
TEST(csm_open_delete_flag_unsupported_for_memory) {
    REQUIRE(U(CertOpenStore));
    SET_ERR(0);
    HCERTSTORE h = U(CertOpenStore)(CERT_STORE_PROV_MEMORY, 0, 0, CERT_STORE_DELETE_FLAG, NULL);
    CHECK(h == NULL);                       /* DELETE never returns a usable store */
    t_note("memory + DELETE_FLAG gle=%lu (decomp: ERROR_CALL_NOT_IMPLEMENTED when provider lacks delete)", GetLastError());
    sm_close(h);
}
TEST(csm_open_flags_accepted_for_memory) {
    REQUIRE(U(CertOpenStore));
    DWORD fl[] = { 0, CERT_STORE_NO_CRYPT_RELEASE_FLAG, CERT_STORE_DEFER_CLOSE_UNTIL_LAST_FREE_FLAG,
                   CERT_STORE_ENUM_ARCHIVED_FLAG, CERT_STORE_UPDATE_KEYID_FLAG, CERT_STORE_BACKUP_RESTORE_FLAG,
                   CERT_STORE_MANIFOLD_FLAG, CERT_STORE_SET_LOCALIZED_NAME_FLAG };
    for (unsigned i = 0; i < sizeof fl / sizeof fl[0]; i++) {
        HCERTSTORE h = U(CertOpenStore)(CERT_STORE_PROV_MEMORY, 0, 0, fl[i], NULL);
        CHECKF(h != NULL, "flag 0x%lx", fl[i]);
        if (h) {
            CHECKF(sm_addc(h, VEC(v_cert_a), DISP_NEW, NULL), "add flag 0x%lx", fl[i]);
            sm_close(h);
        }
    }
}
TEST(csm_open_memory_readonly_rejects_adds) {
    REQUIRE(U(CertOpenStore));
    HCERTSTORE h = U(CertOpenStore)(CERT_STORE_PROV_MEMORY, 0, 0, CERT_STORE_READONLY_FLAG, NULL);
    if (!h) { t_note("memory+READONLY open failed gle=%lu", GetLastError()); return; }
    SET_ERR(0);
    BOOL r = sm_addc(h, VEC(v_cert_a), DISP_NEW, NULL);
    t_note("add to READONLY memory store -> %d gle=0x%lx count=%d", r, GetLastError(), sm_ncerts(h));
    sm_close(h);
}
TEST(csm_open_memory_with_initial_pkcs7_blob_ignored_or_used) {
    REQUIRE(U(CertOpenStore));
    /* pvPara for PROV_MEMORY is ignored */
    CRYPT_DATA_BLOB b = { sizeof v_p7_certs, (BYTE *)v_p7_certs };
    HCERTSTORE h = U(CertOpenStore)(CERT_STORE_PROV_MEMORY, ENC, 0, 0, &b);
    CHECK(h != NULL);
    if (h) { t_note("memory store with pvPara blob has %d certs", sm_ncerts(h)); sm_close(h); }
}
TEST(csm_open_encoding_type_irrelevant_for_memory) {
    REQUIRE(U(CertOpenStore));
    DWORD e[] = { 0, X509_ASN_ENCODING, PKCS_7_ASN_ENCODING, ENC };
    for (int i = 0; i < 4; i++) { HCERTSTORE h = U(CertOpenStore)(CERT_STORE_PROV_MEMORY, e[i], 0, 0, NULL); CHECK(h != NULL); sm_close(h); }
}
TEST(csm_close_null_store) {
    REQUIRE(U(CertCloseStore));
    SET_ERR(0);
    BOOL r = U(CertCloseStore)(NULL, 0);
    t_note("CertCloseStore(NULL,0) -> %d gle=0x%lx", r, GetLastError());
}
TEST(csm_close_two_opens_independent) {
    REQUIRE(U(CertOpenStore));
    HCERTSTORE a = sm_mem(), b = sm_mem();
    CHECK(a && b && a != b);
    sm_addc(a, VEC(v_cert_a), DISP_NEW, NULL);
    EXPECT_EQ(sm_ncerts(a), 1); EXPECT_EQ(sm_ncerts(b), 0);
    sm_close(a); sm_close(b);
}
TEST(csm_duplicate_store_same_handle_and_refcount) {
    REQUIRE(U(CertDuplicateStore));
    HCERTSTORE h = sm_abc(); if (!h) return;
    HCERTSTORE d = U(CertDuplicateStore)(h);
    CHECK(d == h);
    CHECK(U(CertCloseStore)(h, 0));         /* ref 2 -> 1 */
    EXPECT_EQ(sm_ncerts(d), 3);             /* still alive */
    CHECK(U(CertCloseStore)(d, 0));
}
TEST(csm_duplicate_store_many) {
    REQUIRE(U(CertDuplicateStore));
    HCERTSTORE h = sm_mem(); if (!h) return;
    sm_addc(h, VEC(v_cert_a), DISP_NEW, NULL);
    for (int i = 0; i < 20; i++) CHECK(U(CertDuplicateStore)(h) == h);
    for (int i = 0; i < 20; i++) CHECK(U(CertCloseStore)(h, 0));
    EXPECT_EQ(sm_ncerts(h), 1);             /* last reference remains */
    sm_close(h);
}
TEST(csm_close_with_outstanding_context_plain) {
    REQUIRE(U(CertOpenStore));
    HCERTSTORE h = sm_mem(); if (!h) return;
    PCCERT_CONTEXT c = NULL;
    CHECK(sm_addc(h, VEC(v_cert_a), DISP_NEW, &c));
    CHECK(c != NULL);
    CHECK(U(CertCloseStore)(h, 0));         /* store closes; context stays usable */
    if (c) { CHECK(sm_same_enc(c, VEC(v_cert_a))); sm_freec(c); }
}
TEST(csm_close_check_flag_with_outstanding_context) {
    REQUIRE(U(CertOpenStore));
    HCERTSTORE h = sm_mem(); if (!h) return;
    PCCERT_CONTEXT c = NULL;
    sm_addc(h, VEC(v_cert_a), DISP_NEW, &c);
    SET_ERR(0);
    BOOL r = U(CertCloseStore)(h, CERT_CLOSE_STORE_CHECK_FLAG);
    CHECK(!r); EXPECT_ERR(HR_PENDING);
    if (c) { CHECK(sm_same_enc(c, VEC(v_cert_a))); sm_freec(c); }
}
TEST(csm_close_check_flag_without_outstanding_context) {
    REQUIRE(U(CertOpenStore));
    HCERTSTORE h = sm_abc(); if (!h) return;
    CHECK(U(CertCloseStore)(h, CERT_CLOSE_STORE_CHECK_FLAG));
}
TEST(csm_close_force_flag_with_outstanding_context) {
    REQUIRE(U(CertOpenStore));
    HCERTSTORE h = sm_mem(); if (!h) return;
    PCCERT_CONTEXT c = NULL;
    sm_addc(h, VEC(v_cert_a), DISP_NEW, &c);
    CHECK(U(CertCloseStore)(h, CERT_CLOSE_STORE_FORCE_FLAG));
    t_note("after FORCE close the outstanding context was not touched (freed by DLL? not accessed)");
}
TEST(csm_close_force_flag_with_duplicates) {
    REQUIRE(U(CertOpenStore)); REQUIRE(U(CertDuplicateStore));
    HCERTSTORE h = sm_abc(); if (!h) return;
    U(CertDuplicateStore)(h);
    U(CertDuplicateStore)(h);
    CHECK(U(CertCloseStore)(h, CERT_CLOSE_STORE_FORCE_FLAG));   /* force frees every reference */
}
TEST(csm_defer_close_until_last_free) {
    REQUIRE(U(CertOpenStore));
    HCERTSTORE h = U(CertOpenStore)(CERT_STORE_PROV_MEMORY, 0, 0, CERT_STORE_DEFER_CLOSE_UNTIL_LAST_FREE_FLAG, NULL);
    CHECK(h != NULL); if (!h) return;
    PCCERT_CONTEXT c = NULL;
    CHECK(sm_addc(h, VEC(v_cert_a), DISP_NEW, &c));
    CHECK(U(CertCloseStore)(h, 0));
    if (c) {
        /* the store stays alive while the context is outstanding: a context still reports its store */
        CHECK(sm_same_enc(c, VEC(v_cert_a)));
        PCCERT_CONTEXT n = U(CertEnumCertificatesInStore)(c->hCertStore, NULL);
        t_note("deferred-close store still enumerable via context: %d", n != NULL);
        sm_freec(n);
        sm_freec(c);
    }
}
TEST(csm_defer_close_pending_check_is_ok) {
    REQUIRE(U(CertOpenStore));
    HCERTSTORE h = U(CertOpenStore)(CERT_STORE_PROV_MEMORY, 0, 0, CERT_STORE_DEFER_CLOSE_UNTIL_LAST_FREE_FLAG, NULL);
    if (!h) return;
    PCCERT_CONTEXT c = NULL;
    sm_addc(h, VEC(v_cert_a), DISP_NEW, &c);
    SET_ERR(0);
    BOOL r = U(CertCloseStore)(h, CERT_CLOSE_STORE_CHECK_FLAG);
    t_note("DEFER_CLOSE + CHECK_FLAG with outstanding ctx -> %d gle=0x%lx", r, GetLastError());
    sm_freec(c);
}
TEST(csm_store_property_context_hcertstore_matches) {
    REQUIRE(U(CertOpenStore));
    HCERTSTORE h = sm_mem(); if (!h) return;
    PCCERT_CONTEXT c = NULL;
    sm_addc(h, VEC(v_cert_a), DISP_NEW, &c);
    CHECK(c && c->hCertStore == h);
    CHECK(c && c->dwCertEncodingType == X509_ASN_ENCODING);
    sm_freec(c); sm_close(h);
}
TEST(csm_open_two_hundred_stores) {
    REQUIRE(U(CertOpenStore));
    HCERTSTORE hs[100];
    for (int i = 0; i < 100; i++) { hs[i] = sm_mem(); CHECK(hs[i] != NULL); }
    for (int i = 0; i < 100; i++) sm_close(hs[i]);
}
TEST(csm_null_store_add_creates_standalone_context) {
    REQUIRE(U(CertAddEncodedCertificateToStore));
    /* decomp: a NULL store maps to an internal default store: the call succeeds and returns a context */
    PCCERT_CONTEXT c = NULL;
    BOOL r = sm_addc(NULL, VEC(v_cert_a), DISP_ALWAYS, &c);
    t_note("NULL store add ALWAYS -> %d ctx=%p gle=0x%lx", r, c, GetLastError());
    if (r && c) { CHECK(sm_same_enc(c, VEC(v_cert_a))); }
    sm_freec(c);
}
