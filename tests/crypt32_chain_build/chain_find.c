/* Chain context reference counting, CertFindChainInStore, CertSelectCertificateChains, CertFreeCertificateChainList,
 * I_CertChainEngineIsDisallowedCertificate. */
#include "pkiutil.h"

UDECL(BOOL, I_CertChainEngineIsDisallowedCertificate, (HCERTCHAINENGINE, PCCERT_CONTEXT));

/* ---- reference counting ---- */
static PCCERT_CHAIN_CONTEXT good_chain(PKI_ENG *e) {
    if (!pki_eng_open(e, "root", "inter", NULL, 0)) return NULL;
    return pki_chain(e->h, "leaf", NULL, PKI_T0, PKI_OFFLINE, NULL);
}
TEST(chain_refcount_duplicate_returns_same_pointer) {
    REQUIRE(U(CertDuplicateCertificateChain));
    PKI_ENG e; PCCERT_CHAIN_CONTEXT c = good_chain(&e); CHECK(c != NULL);
    if (c) {
        PCCERT_CHAIN_CONTEXT d = U(CertDuplicateCertificateChain)(c);
        CHECK(d == c);
        pki_chain_free(d); pki_chain_free(c);
    }
    pki_eng_close(&e);
}
TEST(chain_refcount_survives_first_free) {
    REQUIRE(U(CertDuplicateCertificateChain));
    PKI_ENG e; PCCERT_CHAIN_CONTEXT c = good_chain(&e); CHECK(c != NULL);
    if (c) {
        PCCERT_CHAIN_CONTEXT d = U(CertDuplicateCertificateChain)(c);
        pki_chain_free(c);
        EXPECT_EQ(d->cChain, 1);
        EXPECT_EQ(pki_nelem(d, 0), 3);
        EXPECT_ID(d, 0, 0, "leaf");
        pki_chain_free(d);
    }
    pki_eng_close(&e);
}
TEST(chain_refcount_many_duplicates) {
    REQUIRE(U(CertDuplicateCertificateChain));
    PKI_ENG e; PCCERT_CHAIN_CONTEXT c = good_chain(&e); CHECK(c != NULL);
    if (c) {
        for (int i = 0; i < 100; i++) CHECK(U(CertDuplicateCertificateChain)(c) == c);
        for (int i = 0; i < 100; i++) pki_chain_free(c);
        EXPECT_EQ(c->cChain, 1);                    /* the original reference is still held */
        EXPECT_EQ(pki_nelem(c, 0), 3);
        pki_chain_free(c);
    }
    pki_eng_close(&e);
}
TEST(chain_refcount_certs_outlive_chain_when_duplicated) {
    REQUIRE(U(CertDuplicateCertificateChain));
    PKI_ENG e; PCCERT_CHAIN_CONTEXT c = good_chain(&e); CHECK(c != NULL);
    if (c && c->cChain == 1 && c->rgpChain[0]->cElement == 3) {
        PCCERT_CONTEXT x[3];
        for (int i = 0; i < 3; i++) x[i] = U(CertDuplicateCertificateContext)(c->rgpChain[0]->rgpElement[i]->pCertContext);
        pki_chain_free(c);
        EXPECT_STR(pki_id_of(x[0]), "leaf"); EXPECT_STR(pki_id_of(x[1]), "inter"); EXPECT_STR(pki_id_of(x[2]), "root");
        for (int i = 0; i < 3; i++) U(CertFreeCertificateContext)(x[i]);
    } else pki_chain_free(c);
    pki_eng_close(&e);
}
TEST(chain_refcount_two_chains_independent) {
    REQUIRE(U(CertDuplicateCertificateChain));
    PKI_ENG e; PCCERT_CHAIN_CONTEXT a = good_chain(&e);
    PCCERT_CHAIN_CONTEXT b = pki_chain(e.h, "leaf_root", NULL, PKI_T0, PKI_OFFLINE, NULL);
    CHECK(a && b);
    pki_chain_free(a);
    if (b) { EXPECT_EQ(pki_nelem(b, 0), 2); EXPECT_ID(b, 0, 0, "leaf_root"); }
    pki_chain_free(b); pki_eng_close(&e);
}
TEST(chain_refcount_free_list_null_is_noop) {
    REQUIRE(U(CertFreeCertificateChainList));
    U(CertFreeCertificateChainList)(NULL);       /* forwards to LocalFree(NULL), which is a no-op */
    CHECK(1);
}
typedef struct { PCCERT_CHAIN_CONTEXT c; volatile LONG ok; } DUPARG;
static DWORD WINAPI dup_thread(LPVOID p) {
    DUPARG *a = p;
    for (int i = 0; i < 200; i++) {
        PCCERT_CHAIN_CONTEXT d = U(CertDuplicateCertificateChain)(a->c);
        if (d == a->c && d->cChain == 1 && d->rgpChain[0]->cElement == 3) InterlockedIncrement(&a->ok);
        U(CertFreeCertificateChain)(d);
    }
    return 0;
}
TEST(chain_refcount_concurrent_duplicate_free) {
    REQUIRE(U(CertDuplicateCertificateChain));
    PKI_ENG e; PCCERT_CHAIN_CONTEXT c = good_chain(&e); CHECK(c != NULL);
    if (c) {
        DUPARG a = { c, 0 };
        HANDLE th[4];
        for (int i = 0; i < 4; i++) th[i] = CreateThread(NULL, 0, dup_thread, &a, 0, NULL);
        DWORD w = WaitForMultipleObjects(4, th, TRUE, 20000);
        CHECK(w == WAIT_OBJECT_0);
        for (int i = 0; i < 4; i++) CloseHandle(th[i]);
        EXPECT_EQ(a.ok, 800);
        EXPECT_EQ(c->cChain, 1);
        pki_chain_free(c);
    }
    pki_eng_close(&e);
}
typedef struct { HCERTCHAINENGINE eng; volatile LONG good; } BLDARG;
static DWORD WINAPI build_thread(LPVOID p) {
    BLDARG *a = p;
    for (int i = 0; i < 25; i++) {
        PCCERT_CHAIN_CONTEXT c = pki_chain(a->eng, i & 1 ? "leaf_root" : "leaf", NULL, PKI_T0, PKI_OFFLINE, NULL);
        if (c && c->TrustStatus.dwErrorStatus == 0 && c->cChain == 1 && c->rgpChain[0]->cElement == ((i & 1) ? 2u : 3u)) InterlockedIncrement(&a->good);
        pki_chain_free(c);
    }
    return 0;
}
TEST(chain_thread_shared_engine_concurrent_builds) {
    REQUIRE(U(CertGetCertificateChain));
    PKI_ENG e; CHECK(pki_eng_open(&e, "root", "inter", NULL, 0));
    BLDARG a = { e.h, 0 };
    HANDLE th[4];
    for (int i = 0; i < 4; i++) th[i] = CreateThread(NULL, 0, build_thread, &a, 0, NULL);
    DWORD w = WaitForMultipleObjects(4, th, TRUE, 60000);
    CHECK(w == WAIT_OBJECT_0);
    for (int i = 0; i < 4; i++) CloseHandle(th[i]);
    EXPECT_EQ(a.good, 100);
    pki_eng_close(&e);
}
TEST(chain_thread_chain_freed_on_other_thread) {
    REQUIRE(U(CertGetCertificateChain));
    PKI_ENG e; PCCERT_CHAIN_CONTEXT c = good_chain(&e); CHECK(c != NULL);
    if (c) {
        DUPARG a = { c, 0 };
        HANDLE th = CreateThread(NULL, 0, dup_thread, &a, 0, NULL);
        CHECK(WaitForSingleObject(th, 20000) == WAIT_OBJECT_0);
        CloseHandle(th);
        pki_chain_free(c);
    }
    pki_eng_close(&e);
}

/* ---- CertFindChainInStore ---- */
/* The emulator used for validation only stubs CertFindChainInStore (ERROR_CALL_NOT_IMPLEMENTED / 126); Windows implements it. */
static int find_unsupported(void) {
    if (!t_is_wine()) return 0;
    HCERTSTORE st = pki_store(NULL);
    SET_ERR(0);
    PCCERT_CHAIN_CONTEXT c = U(CertFindChainInStore)(st, X509_ASN_ENCODING, 0, CERT_CHAIN_FIND_BY_ISSUER, NULL, NULL);
    DWORD e = GetLastError();
    U(CertCloseStore)(st, 0);
    return c == NULL && e != CRYPT_E_NOT_FOUND;
}
#define FINDREQ() do { REQUIRE(U(CertFindChainInStore)); if (find_unsupported()) { t_skip("emulator stubs CertFindChainInStore"); return; } } while (0)
static CERT_CHAIN_FIND_BY_ISSUER_PARA find_para(void) {
    CERT_CHAIN_FIND_BY_ISSUER_PARA p; memset(&p, 0, sizeof p); p.cbSize = 0x30;
    return p;
}
#define FINDF (CERT_CHAIN_FIND_BY_ISSUER_NO_KEY_FLAG | CERT_CHAIN_FIND_BY_ISSUER_CACHE_ONLY_URL_FLAG)
static int find_all(HCERTSTORE st, DWORD flags, CERT_CHAIN_FIND_BY_ISSUER_PARA *p, const char **ids, int maxids, DWORD *lasterr) {
    int n = 0;
    PCCERT_CHAIN_CONTEXT c = NULL;
    for (;;) {
        SET_ERR(0);
        c = U(CertFindChainInStore)(st, X509_ASN_ENCODING, flags, CERT_CHAIN_FIND_BY_ISSUER, p, c);
        if (!c) { if (lasterr) *lasterr = GetLastError(); break; }
        if (n < maxids && ids) ids[n] = c->cChain && c->rgpChain[0]->cElement ? pki_elem_id(c, 0, 0) : "?";
        n++;
        if (n > 20) { U(CertFreeCertificateChain)(c); break; }
    }
    return n;
}
TEST(chain_find_empty_store_not_found) {
    FINDREQ();
    HCERTSTORE st = pki_store(NULL);
    CERT_CHAIN_FIND_BY_ISSUER_PARA p = find_para();
    SET_ERR(0);
    PCCERT_CHAIN_CONTEXT c = U(CertFindChainInStore)(st, X509_ASN_ENCODING, FINDF, CERT_CHAIN_FIND_BY_ISSUER, &p, NULL);
    CHECK(c == NULL); EXPECT_ERR(CRYPT_E_NOT_FOUND);
    U(CertCloseStore)(st, 0);
}
TEST(chain_find_empty_store_invalid_type_still_not_found) {
    FINDREQ();
    HCERTSTORE st = pki_store(NULL);
    SET_ERR(0);
    PCCERT_CHAIN_CONTEXT c = U(CertFindChainInStore)(st, X509_ASN_ENCODING, 0, 0, NULL, NULL);
    CHECK(c == NULL); EXPECT_ERR(CRYPT_E_NOT_FOUND);       /* the find type is only examined for an enumerated certificate */
    U(CertCloseStore)(st, 0);
}
TEST(chain_find_invalid_find_type_nonempty_store) {
    FINDREQ();
    HCERTSTORE st = pki_store("leaf");
    CERT_CHAIN_FIND_BY_ISSUER_PARA p = find_para();
    DWORD types[] = { 0, 2, 3, 0xffffffff };
    for (int i = 0; i < 4; i++) {
        SET_ERR(0);
        PCCERT_CHAIN_CONTEXT c = U(CertFindChainInStore)(st, X509_ASN_ENCODING, FINDF, types[i], &p, NULL);
        CHECKF(c == NULL, "find type %lu", types[i]); EXPECT_ERR(E_INVALIDARG);
    }
    U(CertCloseStore)(st, 0);
}
TEST(chain_find_null_para_nonempty_store) {
    FINDREQ();
    HCERTSTORE st = pki_store("leaf");
    SET_ERR(0);
    PCCERT_CHAIN_CONTEXT c = U(CertFindChainInStore)(st, X509_ASN_ENCODING, FINDF, CERT_CHAIN_FIND_BY_ISSUER, NULL, NULL);
    CHECK(c == NULL); EXPECT_ERR(E_INVALIDARG);
    U(CertCloseStore)(st, 0);
}
TEST(chain_find_para_cbsize_too_small) {
    FINDREQ();
    HCERTSTORE st = pki_store("leaf");
    DWORD sizes[] = { 0, 4, 0x28, 0x2f };
    for (int i = 0; i < 4; i++) {
        CERT_CHAIN_FIND_BY_ISSUER_PARA p = find_para(); p.cbSize = sizes[i];
        SET_ERR(0);
        PCCERT_CHAIN_CONTEXT c = U(CertFindChainInStore)(st, X509_ASN_ENCODING, FINDF, CERT_CHAIN_FIND_BY_ISSUER, &p, NULL);
        CHECKF(c == NULL, "cbSize 0x%lx", sizes[i]); EXPECT_ERR(E_INVALIDARG);
    }
    U(CertCloseStore)(st, 0);
}
TEST(chain_find_para_cbsize_minimum_accepted) {
    FINDREQ();
    HCERTSTORE st = pki_store("leaf");
    CERT_CHAIN_FIND_BY_ISSUER_PARA p = find_para();
    PCCERT_CHAIN_CONTEXT c = U(CertFindChainInStore)(st, X509_ASN_ENCODING, FINDF, CERT_CHAIN_FIND_BY_ISSUER, &p, NULL);
    CHECK(c != NULL);
    if (c) { EXPECT_ID(c, 0, 0, "leaf"); U(CertFreeCertificateChain)(c); }
    U(CertCloseStore)(st, 0);
}
TEST(chain_find_enumerates_every_certificate) {
    FINDREQ();
    HCERTSTORE st = pki_store("leaf inter root");
    CERT_CHAIN_FIND_BY_ISSUER_PARA p = find_para();
    const char *ids[8] = {0}; DWORD err = 0;
    int n = find_all(st, FINDF, &p, ids, 8, &err);
    EXPECT_EQ(n, 3);
    EXPECT_EQ(err, CRYPT_E_NOT_FOUND);
    int seen_leaf = 0, seen_inter = 0, seen_root = 0;
    for (int i = 0; i < n && i < 8; i++) { if (!strcmp(ids[i], "leaf")) seen_leaf++; if (!strcmp(ids[i], "inter")) seen_inter++; if (!strcmp(ids[i], "root")) seen_root++; }
    EXPECT_EQ(seen_leaf, 1); EXPECT_EQ(seen_inter, 1); EXPECT_EQ(seen_root, 1);
    U(CertCloseStore)(st, 0);
}
TEST(chain_find_encoding_type_zero_means_x509) {
    FINDREQ();
    HCERTSTORE st = pki_store("leaf inter");
    CERT_CHAIN_FIND_BY_ISSUER_PARA p = find_para();
    int n = 0; PCCERT_CHAIN_CONTEXT c = NULL;
    while ((c = U(CertFindChainInStore)(st, 0, FINDF, CERT_CHAIN_FIND_BY_ISSUER, &p, c)) != NULL && n < 10) n++;
    EXPECT_EQ(n, 2);
    U(CertCloseStore)(st, 0);
}
TEST(chain_find_requires_key_info_unless_no_key_flag) {
    FINDREQ();
    HCERTSTORE st = pki_store("leaf inter root");
    CERT_CHAIN_FIND_BY_ISSUER_PARA p = find_para();
    SET_ERR(0);
    PCCERT_CHAIN_CONTEXT c = U(CertFindChainInStore)(st, X509_ASN_ENCODING, CERT_CHAIN_FIND_BY_ISSUER_CACHE_ONLY_URL_FLAG, CERT_CHAIN_FIND_BY_ISSUER, &p, NULL);
    CHECK(c == NULL); EXPECT_ERR(CRYPT_E_NOT_FOUND);       /* certificates without a private key / key identifier property are skipped */
    U(CertCloseStore)(st, 0);
}
TEST(chain_find_key_spec_selects_property_to_test) {
    FINDREQ();
    HCERTSTORE st = pki_store("leaf");
    for (DWORD ks = 0; ks <= 2; ks++) {
        CERT_CHAIN_FIND_BY_ISSUER_PARA p = find_para(); p.dwKeySpec = ks;
        SET_ERR(0);
        PCCERT_CHAIN_CONTEXT c = U(CertFindChainInStore)(st, X509_ASN_ENCODING, CERT_CHAIN_FIND_BY_ISSUER_CACHE_ONLY_URL_FLAG, CERT_CHAIN_FIND_BY_ISSUER, &p, NULL);
        CHECKF(c == NULL, "dwKeySpec %lu without key property", ks);
        EXPECT_ERR(CRYPT_E_NOT_FOUND);
    }
    U(CertCloseStore)(st, 0);
}
TEST(chain_find_key_identifier_property_does_not_satisfy_key_requirement) {
    FINDREQ();
    HCERTSTORE st = pki_store("leaf");
    PCCERT_CONTEXT cc = U(CertEnumCertificatesInStore)(st, NULL);
    CHECK(cc != NULL);
    if (cc) {
        BYTE kid[20] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20};
        CRYPT_DATA_BLOB b = { sizeof kid, kid };
        CHECK(U(CertSetCertificateContextProperty)(cc, CERT_KEY_IDENTIFIER_PROP_ID, 0, &b));
        CERT_CHAIN_FIND_BY_ISSUER_PARA p = find_para();
        PCCERT_CHAIN_CONTEXT c = U(CertFindChainInStore)(st, X509_ASN_ENCODING, CERT_CHAIN_FIND_BY_ISSUER_CACHE_ONLY_URL_FLAG, CERT_CHAIN_FIND_BY_ISSUER, &p, NULL);
        CHECK(c == NULL);   /* the key identifier property does not stand in for a private key on Win10 22H2 */
        if (c) U(CertFreeCertificateChain)(c);
        U(CertFreeCertificateContext)(cc);
    }
    U(CertCloseStore)(st, 0);
}
static int g_cb_calls, g_cb_ret; static void *g_cb_arg_seen;
static BOOL WINAPI find_cb(PCCERT_CONTEXT c, void *arg) { g_cb_calls++; g_cb_arg_seen = arg; return g_cb_ret; }
TEST(chain_find_callback_called_per_candidate) {
    FINDREQ();
    HCERTSTORE st = pki_store("leaf inter root");
    CERT_CHAIN_FIND_BY_ISSUER_PARA p = find_para(); p.pfnFindCallback = find_cb; p.pvFindArg = (void *)(ULONG_PTR)0xABCD;
    g_cb_calls = 0; g_cb_ret = 0; g_cb_arg_seen = NULL;
    DWORD err = 0; int n = find_all(st, FINDF, &p, NULL, 0, &err);
    EXPECT_EQ(n, 0); EXPECT_EQ(err, CRYPT_E_NOT_FOUND);
    EXPECT_EQ(g_cb_calls, 3);
    EXPECT_EQ(g_cb_arg_seen, 0xABCD);
    U(CertCloseStore)(st, 0);
}
TEST(chain_find_callback_true_keeps_all) {
    FINDREQ();
    HCERTSTORE st = pki_store("leaf inter root");
    CERT_CHAIN_FIND_BY_ISSUER_PARA p = find_para(); p.pfnFindCallback = find_cb;
    g_cb_calls = 0; g_cb_ret = 1;
    int n = find_all(st, FINDF, &p, NULL, 0, NULL);
    EXPECT_EQ(n, 3); EXPECT_EQ(g_cb_calls, 3);
    U(CertCloseStore)(st, 0);
}
static BOOL WINAPI find_cb_leaf_only(PCCERT_CONTEXT c, void *arg) { const char *id = pki_id_of(c); return id && !strcmp(id, "leaf"); }
TEST(chain_find_callback_filters_one_certificate) {
    FINDREQ();
    HCERTSTORE st = pki_store("leaf inter root");
    CERT_CHAIN_FIND_BY_ISSUER_PARA p = find_para(); p.pfnFindCallback = find_cb_leaf_only;
    const char *ids[4] = {0}; DWORD err = 0;
    int n = find_all(st, FINDF, &p, ids, 4, &err);
    EXPECT_EQ(n, 1);
    if (n == 1) EXPECT_STR(ids[0], "leaf");
    U(CertCloseStore)(st, 0);
}
TEST(chain_find_usage_identifier_filters_end_certs) {
    FINDREQ();
    HCERTSTORE st = pki_store("leaf leaf_code");
    CERT_CHAIN_FIND_BY_ISSUER_PARA p = find_para(); p.pszUsageIdentifier = OID_SERVER;
    const char *ids[4] = {0}; DWORD err = 0;
    int n = find_all(st, FINDF, &p, ids, 4, &err);
    EXPECT_EQ(n, 1);
    if (n == 1) EXPECT_STR(ids[0], "leaf");
    p.pszUsageIdentifier = OID_CODE;
    n = find_all(st, FINDF, &p, ids, 4, &err);
    EXPECT_EQ(n, 1);
    if (n == 1) EXPECT_STR(ids[0], "leaf_code");
    p.pszUsageIdentifier = "1.2.3.4.5.6.7.8";
    n = find_all(st, FINDF, &p, ids, 4, &err);
    EXPECT_EQ(n, 0); EXPECT_EQ(err, CRYPT_E_NOT_FOUND);
    U(CertCloseStore)(st, 0);
}
TEST(chain_find_issuer_name_filter_matches_ancestor) {
    FINDREQ();
    HCERTSTORE st = pki_store("leaf inter root");
    PCCERT_CONTEXT rc = pki_cert("root");
    CERT_NAME_BLOB nm = rc->pCertInfo->Subject;
    CERT_CHAIN_FIND_BY_ISSUER_PARA p = find_para(); p.cIssuer = 1; p.rgIssuer = &nm;
    const char *ids[8] = {0}; DWORD err = 0;
    int n = find_all(st, FINDF, &p, ids, 8, &err);
    EXPECT_EQ(n, 3);
    U(CertFreeCertificateContext)(rc); U(CertCloseStore)(st, 0);
}
TEST(chain_find_issuer_name_filter_unrelated_name) {
    FINDREQ();
    HCERTSTORE st = pki_store("leaf inter root");
    PCCERT_CONTEXT other = pki_cert("cycA");
    CERT_NAME_BLOB nm = other->pCertInfo->Subject;
    CERT_CHAIN_FIND_BY_ISSUER_PARA p = find_para(); p.cIssuer = 1; p.rgIssuer = &nm;
    DWORD err = 0;
    int n = find_all(st, FINDF, &p, NULL, 0, &err);
    EXPECT_EQ(n, 0); EXPECT_EQ(err, CRYPT_E_NOT_FOUND);
    U(CertFreeCertificateContext)(other); U(CertCloseStore)(st, 0);
}
TEST(chain_find_issuer_name_filter_inter_subject_selects_leaf_chain) {
    FINDREQ();
    HCERTSTORE st = pki_store("leaf inter root leaf_root");
    PCCERT_CONTEXT ic = pki_cert("inter");
    CERT_NAME_BLOB nm = ic->pCertInfo->Subject;
    CERT_CHAIN_FIND_BY_ISSUER_PARA p = find_para(); p.cIssuer = 1; p.rgIssuer = &nm;
    const char *ids[8] = {0}; DWORD err = 0;
    int n = find_all(st, FINDF, &p, ids, 8, &err);
    int leaf = 0, leafroot = 0;
    for (int i = 0; i < n && i < 8; i++) { if (!strcmp(ids[i], "leaf")) leaf++; if (!strcmp(ids[i], "leaf_root")) leafroot++; }
    EXPECT_EQ(n, 1);
    EXPECT_EQ(leaf, 1);
    EXPECT_EQ(leafroot, 0);      /* leaf_root is issued directly by the root: the intermediate is not in its chain */
    U(CertFreeCertificateContext)(ic); U(CertCloseStore)(st, 0);
}
TEST(chain_find_chain_built_from_store_contents) {
    FINDREQ();
    HCERTSTORE st = pki_store("leaf inter root");
    CERT_CHAIN_FIND_BY_ISSUER_PARA p = find_para(); p.pfnFindCallback = find_cb_leaf_only;
    PCCERT_CHAIN_CONTEXT c = U(CertFindChainInStore)(st, X509_ASN_ENCODING, FINDF, CERT_CHAIN_FIND_BY_ISSUER, &p, NULL);
    CHECK(c != NULL);
    if (c) { pki_note_chain("find: leaf chain", c); EXPECT_EQ(pki_nelem(c, 0), 3); EXPECT_ID(c, 0, 1, "inter"); U(CertFreeCertificateChain)(c); }
    U(CertCloseStore)(st, 0);
}
TEST(chain_find_cache_only_flag_ignores_store_intermediates) {
    FINDREQ();
    HCERTSTORE st = pki_store("leaf inter root");
    CERT_CHAIN_FIND_BY_ISSUER_PARA p = find_para(); p.pfnFindCallback = find_cb_leaf_only;
    PCCERT_CHAIN_CONTEXT c = U(CertFindChainInStore)(st, X509_ASN_ENCODING, FINDF | CERT_CHAIN_FIND_BY_ISSUER_CACHE_ONLY_FLAG, CERT_CHAIN_FIND_BY_ISSUER, &p, NULL);
    CHECK(c != NULL);
    if (c) { pki_note_chain("find with CACHE_ONLY_FLAG", c); EXPECT_EQ(pki_nelem(c, 0), 1); CHECK(c->TrustStatus.dwErrorStatus & CERT_TRUST_IS_PARTIAL_CHAIN); U(CertFreeCertificateChain)(c); }
    U(CertCloseStore)(st, 0);
}
TEST(chain_find_prev_chain_is_consumed) {
    /* the previous chain reference is released by the call; a duplicate taken first stays valid */
    FINDREQ();
    HCERTSTORE st = pki_store("leaf inter");
    CERT_CHAIN_FIND_BY_ISSUER_PARA p = find_para();
    PCCERT_CHAIN_CONTEXT a = U(CertFindChainInStore)(st, X509_ASN_ENCODING, FINDF, CERT_CHAIN_FIND_BY_ISSUER, &p, NULL);
    CHECK(a != NULL);
    if (a) {
        PCCERT_CHAIN_CONTEXT keep = U(CertDuplicateCertificateChain)(a);
        PCCERT_CHAIN_CONTEXT b = U(CertFindChainInStore)(st, X509_ASN_ENCODING, FINDF, CERT_CHAIN_FIND_BY_ISSUER, &p, a);
        CHECK(b != NULL && b != keep);
        EXPECT_EQ(keep->cChain, 1);
        if (b) U(CertFreeCertificateChain)(b);
        U(CertFreeCertificateChain)(keep);
    }
    U(CertCloseStore)(st, 0);
}

/* ---- CertSelectCertificateChains ---- */
static BOOL do_select(const GUID *ctx, DWORD flags, PKI_ENG *e, HCERTSTORE addl, HCERTSTORE st, DWORD cCrit, CERT_SELECT_CRITERIA *crit, DWORD *n, PCCERT_CHAIN_CONTEXT **list) {
    CERT_CHAIN_PARA cp; memset(&cp, 0, sizeof cp); cp.cbSize = sizeof cp;
    FILETIME ft = pki_ft(PKI_T0);
    CERT_SELECT_CHAIN_PARA sp; memset(&sp, 0, sizeof sp);
    sp.hChainEngine = e ? e->h : NULL; sp.pTime = &ft; sp.hAdditionalStore = addl; sp.pChainPara = &cp; sp.dwFlags = PKI_OFFLINE;
    *n = 0xdead; *list = NULL;
    return U(CertSelectCertificateChains)(ctx, flags, &sp, cCrit, crit, st, n, list);
}
static void free_selection(DWORD n, PCCERT_CHAIN_CONTEXT *list) {
    for (DWORD i = 0; list && i < n; i++) if (list[i]) U(CertFreeCertificateChain)(list[i]);
    if (list) U(CertFreeCertificateChainList)(list);
}
TEST(chain_select_null_store_invalid_parameter) {
    REQUIRE(U(CertSelectCertificateChains));
    DWORD n; PCCERT_CHAIN_CONTEXT *l;
    SET_ERR(0);
    BOOL r = do_select(NULL, 0, NULL, NULL, NULL, 0, NULL, &n, &l);
    CHECK(!r); EXPECT_ERR(ERROR_INVALID_PARAMETER);
}
TEST(chain_select_too_many_criteria) {
    REQUIRE(U(CertSelectCertificateChains));
    HCERTSTORE st = pki_store("leaf");
    DWORD n; PCCERT_CHAIN_CONTEXT *l;
    SET_ERR(0);
    BOOL r = do_select(NULL, 0, NULL, NULL, st, 34, NULL, &n, &l);
    CHECK(!r); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    U(CertCloseStore)(st, 0);
}
TEST(chain_select_unknown_flag_bits) {
    REQUIRE(U(CertSelectCertificateChains));
    HCERTSTORE st = pki_store("leaf");
    DWORD fl[] = { 0x200, 0x400, 0x80000000u, 0xfffffe00u };
    for (int i = 0; i < 4; i++) {
        DWORD n; PCCERT_CHAIN_CONTEXT *l;
        SET_ERR(0);
        BOOL r = do_select(NULL, fl[i], NULL, NULL, st, 0, NULL, &n, &l);
        CHECKF(!r, "flags 0x%lx", fl[i]); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    }
    U(CertCloseStore)(st, 0);
}
TEST(chain_select_valid_flag_bits_accepted) {
    REQUIRE(U(CertSelectCertificateChains));
    HCERTSTORE st = pki_store("leaf");
    PKI_ENG e; CHECK(pki_eng_open(&e, "root", "inter", NULL, 0));
    for (DWORD f = 1; f <= 0x100; f <<= 1) {
        DWORD n; PCCERT_CHAIN_CONTEXT *l;
        BOOL r = do_select(NULL, f, &e, NULL, st, 0, NULL, &n, &l);
        /* probed: every single flag is accepted; the keyless leaf survives only the flags that do not filter on key/validity/usage */
        static const DWORD cnt[9] = { 1, 1, 1, 0, 0, 0, 0, 1, 1 };
        int bi = 0; while ((1u << bi) != f) bi++;
        EXPECT_EQ(r, 1);
        CHECKF(!r || n == cnt[bi], "flags 0x%lx count %lu", f, n);
        if (r) free_selection(n, l);
    }
    pki_eng_close(&e); U(CertCloseStore)(st, 0);
}
TEST(chain_select_valid_cert_selected_expired_excluded) {
    REQUIRE(U(CertSelectCertificateChains));
    HCERTSTORE st = pki_store("leaf leaf_expired");
    PKI_ENG e; CHECK(pki_eng_open(&e, "root", "inter", NULL, 0));
    DWORD n; PCCERT_CHAIN_CONTEXT *l;
    BOOL r = do_select(NULL, 0, &e, NULL, st, 0, NULL, &n, &l);
    CHECK(r);
    if (r) {
        EXPECT_EQ(n, 1);
        int leaf = 0, exp = 0;
        for (DWORD i = 0; i < n; i++) { const char *id = pki_elem_id(l[i], 0, 0); if (id && !strcmp(id, "leaf")) leaf++; if (id && !strcmp(id, "leaf_expired")) exp++; }
        EXPECT_EQ(leaf, 1); EXPECT_EQ(exp, 0);
        free_selection(n, l);
    }
    pki_eng_close(&e); U(CertCloseStore)(st, 0);
}
TEST(chain_select_allow_expired) {
    REQUIRE(U(CertSelectCertificateChains));
    HCERTSTORE st = pki_store("leaf leaf_expired");
    PKI_ENG e; CHECK(pki_eng_open(&e, "root", "inter", NULL, 0));
    DWORD n; PCCERT_CHAIN_CONTEXT *l;
    BOOL r = do_select(NULL, CERT_SELECT_ALLOW_EXPIRED, &e, NULL, st, 0, NULL, &n, &l);
    CHECK(r);
    if (r) { EXPECT_EQ(n, 2); free_selection(n, l); }
    pki_eng_close(&e); U(CertCloseStore)(st, 0);
}
TEST(chain_select_disallow_selfsigned) {
    REQUIRE(U(CertSelectCertificateChains));
    HCERTSTORE st = pki_store("leaf root");
    PKI_ENG e; CHECK(pki_eng_open(&e, "root", "inter", NULL, 0));
    DWORD n; PCCERT_CHAIN_CONTEXT *l;
    BOOL r = do_select(NULL, CERT_SELECT_DISALLOW_SELFSIGNED, &e, NULL, st, 0, NULL, &n, &l);
    CHECK(r);
    if (r) {
        EXPECT_EQ(n, 1);
        for (DWORD i = 0; i < n; i++) { const char *id = pki_elem_id(l[i], 0, 0); CHECK(id && strcmp(id, "root") != 0); }
        free_selection(n, l);
    }
    pki_eng_close(&e); U(CertCloseStore)(st, 0);
}
TEST(chain_select_selfsigned_allowed_by_default) {
    REQUIRE(U(CertSelectCertificateChains));
    HCERTSTORE st = pki_store("leaf root");
    PKI_ENG e; CHECK(pki_eng_open(&e, "root", "inter", NULL, 0));
    DWORD n; PCCERT_CHAIN_CONTEXT *l;
    BOOL r = do_select(NULL, 0, &e, NULL, st, 0, NULL, &n, &l);
    CHECK(r);
    if (r) { EXPECT_EQ(n, 2); free_selection(n, l); }
    pki_eng_close(&e); U(CertCloseStore)(st, 0);
}
TEST(chain_select_has_private_key_none_available) {
    REQUIRE(U(CertSelectCertificateChains));
    HCERTSTORE st = pki_store("leaf");
    PKI_ENG e; CHECK(pki_eng_open(&e, "root", "inter", NULL, 0));
    DWORD n; PCCERT_CHAIN_CONTEXT *l;
    SET_ERR(0);
    BOOL r = do_select(NULL, CERT_SELECT_HAS_PRIVATE_KEY, &e, NULL, st, 0, NULL, &n, &l);
    EXPECT_EQ(r, 1);
    if (r) { EXPECT_EQ(n, 0); free_selection(n, l); }
    pki_eng_close(&e); U(CertCloseStore)(st, 0);
}
TEST(chain_select_trusted_root_flag_with_trusting_engine) {
    REQUIRE(U(CertSelectCertificateChains));
    HCERTSTORE st = pki_store("leaf");
    PKI_ENG e; CHECK(pki_eng_open(&e, "root", "inter", NULL, 0));
    DWORD n; PCCERT_CHAIN_CONTEXT *l;
    BOOL r = do_select(NULL, CERT_SELECT_TRUSTED_ROOT, &e, NULL, st, 0, NULL, &n, &l);
    CHECK(r);
    if (r) { EXPECT_EQ(n, 1); free_selection(n, l); }
    pki_eng_close(&e); U(CertCloseStore)(st, 0);
}
TEST(chain_select_trusted_root_flag_with_untrusting_engine) {
    REQUIRE(U(CertSelectCertificateChains));
    HCERTSTORE st = pki_store("leaf");
    PKI_ENG e; CHECK(pki_eng_open(&e, "", "inter root", NULL, 0));
    DWORD n; PCCERT_CHAIN_CONTEXT *l;
    SET_ERR(0);
    BOOL r = do_select(NULL, CERT_SELECT_TRUSTED_ROOT, &e, NULL, st, 0, NULL, &n, &l);
    EXPECT_EQ(r, 1);
    if (r) { EXPECT_EQ(n, 0); free_selection(n, l); }
    pki_eng_close(&e); U(CertCloseStore)(st, 0);
}
TEST(chain_select_untrusted_root_selected_without_flag) {
    REQUIRE(U(CertSelectCertificateChains));
    HCERTSTORE st = pki_store("leaf");
    PKI_ENG e; CHECK(pki_eng_open(&e, "", "inter root", NULL, 0));
    DWORD n; PCCERT_CHAIN_CONTEXT *l;
    BOOL r = do_select(NULL, 0, &e, NULL, st, 0, NULL, &n, &l);
    CHECK(r);
    if (r) { EXPECT_EQ(n, 1); free_selection(n, l); }
    pki_eng_close(&e); U(CertCloseStore)(st, 0);
}
TEST(chain_select_criteria_enhanced_key_usage) {
    REQUIRE(U(CertSelectCertificateChains));
    HCERTSTORE st = pki_store("leaf leaf_code");
    PKI_ENG e; CHECK(pki_eng_open(&e, "root", "inter", NULL, 0));
    const char *oid = OID_CODE; void *pp[1] = { (void *)oid };
    CERT_SELECT_CRITERIA crit = { CERT_SELECT_BY_ENHKEY_USAGE, 1, pp };
    DWORD n; PCCERT_CHAIN_CONTEXT *l;
    BOOL r = do_select(NULL, 0, &e, NULL, st, 1, &crit, &n, &l);
    CHECK(r);
    if (r) {
        EXPECT_EQ(n, 1);
        if (n == 1) EXPECT_ID(l[0], 0, 0, "leaf_code");
        free_selection(n, l);
    }
    pki_eng_close(&e); U(CertCloseStore)(st, 0);
}
TEST(chain_select_selection_context_guid_accepted) {
    REQUIRE(U(CertSelectCertificateChains));
    HCERTSTORE st = pki_store("leaf");
    PKI_ENG e; CHECK(pki_eng_open(&e, "root", "inter", NULL, 0));
    GUID g = {0x11111111, 0x2222, 0x3333, {1,2,3,4,5,6,7,8}};
    DWORD n; PCCERT_CHAIN_CONTEXT *l;
    BOOL r = do_select(&g, 0, &e, NULL, st, 0, NULL, &n, &l);
    CHECK(r);
    if (r) { EXPECT_EQ(n, 1); free_selection(n, l); }
    pki_eng_close(&e); U(CertCloseStore)(st, 0);
}
TEST(chain_select_empty_store) {
    REQUIRE(U(CertSelectCertificateChains));
    HCERTSTORE st = pki_store(NULL);
    PKI_ENG e; CHECK(pki_eng_open(&e, "root", "inter", NULL, 0));
    DWORD n; PCCERT_CHAIN_CONTEXT *l;
    SET_ERR(0);
    BOOL r = do_select(NULL, 0, &e, NULL, st, 0, NULL, &n, &l);
    EXPECT_EQ(r, 1);
    if (r) { EXPECT_EQ(n, 0); free_selection(n, l); }
    pki_eng_close(&e); U(CertCloseStore)(st, 0);
}
TEST(chain_select_additional_store_supplies_intermediate) {
    REQUIRE(U(CertSelectCertificateChains));
    HCERTSTORE st = pki_store("leaf"), add = pki_store("inter");
    PKI_ENG e; CHECK(pki_eng_open(&e, "root", NULL, NULL, 0));
    DWORD n; PCCERT_CHAIN_CONTEXT *l;
    BOOL r = do_select(NULL, CERT_SELECT_TRUSTED_ROOT, &e, add, st, 0, NULL, &n, &l);
    CHECK(r);
    if (r) { EXPECT_EQ(n, 1); if (n == 1) EXPECT_EQ(pki_nelem(l[0], 0), 3); free_selection(n, l); }
    pki_eng_close(&e); U(CertCloseStore)(st, 0); U(CertCloseStore)(add, 0);
}

/* ---- I_CertChainEngineIsDisallowedCertificate ---- */
TEST(chain_disallowed_regular_cert_default_engine) {
    REQUIRE(UN(I_CertChainEngineIsDisallowedCertificate));
    const char *ids[] = {"leaf", "inter", "root", "leaf_expired", "root2", "leaf_md5"};
    for (int i = 0; i < 6; i++) {
        PCCERT_CONTEXT c = pki_cert(ids[i]);
        CHECK(c != NULL);
        if (c) { CHECKF(UN(I_CertChainEngineIsDisallowedCertificate)(NULL, c) == 0, "%s", ids[i]); U(CertFreeCertificateContext)(c); }
    }
}
TEST(chain_disallowed_regular_cert_custom_engine) {
    REQUIRE(UN(I_CertChainEngineIsDisallowedCertificate));
    PKI_ENG e; CHECK(pki_eng_open(&e, "root", "inter", NULL, 0));
    PCCERT_CONTEXT c = pki_cert("leaf");
    CHECK(c != NULL);
    if (c) { CHECK(UN(I_CertChainEngineIsDisallowedCertificate)(e.h, c) == 0); U(CertFreeCertificateContext)(c); }
    pki_eng_close(&e);
}
TEST(chain_disallowed_local_machine_default_engine) {
    REQUIRE(UN(I_CertChainEngineIsDisallowedCertificate));
    PCCERT_CONTEXT c = pki_cert("leaf");
    CHECK(c != NULL);
    if (c) { CHECK(UN(I_CertChainEngineIsDisallowedCertificate)(HCCE_LOCAL_MACHINE, c) == 0); U(CertFreeCertificateContext)(c); }
}
TEST(chain_disallowed_engine_still_usable_after_query) {
    REQUIRE(UN(I_CertChainEngineIsDisallowedCertificate));
    PKI_ENG e; CHECK(pki_eng_open(&e, "root", "inter", NULL, 0));
    PCCERT_CONTEXT c = pki_cert("leaf");
    for (int i = 0; i < 10 && c; i++) UN(I_CertChainEngineIsDisallowedCertificate)(e.h, c);
    PCCERT_CHAIN_CONTEXT ch = pki_chain(e.h, "leaf", NULL, PKI_T0, PKI_OFFLINE, NULL);
    CHECK(ch && ch->TrustStatus.dwErrorStatus == 0);
    pki_chain_free(ch);
    if (c) U(CertFreeCertificateContext)(c);
    pki_eng_close(&e);
}
