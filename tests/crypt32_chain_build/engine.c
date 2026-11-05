/* Chain engine lifetime, configuration validation and resync. */
#include "pkiutil.h"

#define ENG_SENTINEL ((HCERTCHAINENGINE)(ULONG_PTR)0x1234)

static void eng_cbsize(DWORD cb, int want_ok) {
    REQUIRE(U(CertCreateCertificateChainEngine)); REQUIRE(U(CertFreeCertificateChainEngine));
    if (t_is_wine() && cb >= 0x51 && cb <= 0x58) { t_skip("emulator only accepts the three documented struct sizes"); return; }
    CERT_CHAIN_ENGINE_CONFIG cfg; memset(&cfg, 0, sizeof cfg);
    cfg.cbSize = cb;
    HCERTCHAINENGINE h = ENG_SENTINEL;
    SET_ERR(0);
    BOOL r = U(CertCreateCertificateChainEngine)(&cfg, &h);
    if (want_ok) {
        CHECKF(r, "cbSize 0x%lx must be accepted", cb);
        CHECK(h != NULL && h != ENG_SENTINEL);
        if (r && h) U(CertFreeCertificateChainEngine)(h);
    } else {
        CHECKF(!r, "cbSize 0x%lx must be rejected", cb);
        EXPECT_ERR(E_INVALIDARG);
        if (!t_is_wine()) EXPECT_EQ(h, NULL);       /* output handle is cleared before validation */
    }
}
#define ENG_CB(nm, cb, ok) TEST(chain_engine_cbsize_##nm) { eng_cbsize(cb, ok); }
ENG_CB(zero, 0, 0)
ENG_CB(one, 1, 0)
ENG_CB(sizeof_dword, 4, 0)
ENG_CB(0x3f, 0x3f, 0)
ENG_CB(0x40, 0x40, 1)
ENG_CB(0x41, 0x41, 0)
ENG_CB(0x44, 0x44, 0)
ENG_CB(0x48, 0x48, 0)
ENG_CB(0x4f, 0x4f, 0)
ENG_CB(0x50, 0x50, 1)
ENG_CB(0x54, 0x54, 1)
ENG_CB(0x58, 0x58, 1)
ENG_CB(0x59, 0x59, 0)
ENG_CB(0x60, 0x60, 0)
ENG_CB(0x100, 0x100, 0)
ENG_CB(max, 0xffffffffu, 0)
TEST(chain_engine_sizeof_config_is_0x58) { EXPECT_EQ(sizeof(CERT_CHAIN_ENGINE_CONFIG), 0x58); }

TEST(chain_engine_default_config_is_empty) {
    REQUIRE(U(CertCreateCertificateChainEngine));
    CERT_CHAIN_ENGINE_CONFIG cfg; memset(&cfg, 0, sizeof cfg); cfg.cbSize = CFG_CB;
    HCERTCHAINENGINE h = NULL;
    CHECK(U(CertCreateCertificateChainEngine)(&cfg, &h)); CHECK(h != NULL);
    if (h) U(CertFreeCertificateChainEngine)(h);
}
TEST(chain_engine_two_engines_differ) {
    REQUIRE(U(CertCreateCertificateChainEngine));
    CERT_CHAIN_ENGINE_CONFIG cfg; memset(&cfg, 0, sizeof cfg); cfg.cbSize = CFG_CB;
    HCERTCHAINENGINE a = NULL, b = NULL;
    CHECK(U(CertCreateCertificateChainEngine)(&cfg, &a));
    CHECK(U(CertCreateCertificateChainEngine)(&cfg, &b));
    CHECK(a != NULL && b != NULL && a != b);
    CHECK((ULONG_PTR)a > 2 && (ULONG_PTR)b > 2);   /* 0,1,2 are the predefined engine pseudo handles */
    if (a) U(CertFreeCertificateChainEngine)(a);
    if (b) U(CertFreeCertificateChainEngine)(b);
}
TEST(chain_engine_create_free_loop) {
    REQUIRE(U(CertCreateCertificateChainEngine));
    CERT_CHAIN_ENGINE_CONFIG cfg; memset(&cfg, 0, sizeof cfg); cfg.cbSize = CFG_CB;
    int okc = 0;
    for (int i = 0; i < 200; i++) {
        HCERTCHAINENGINE h = NULL;
        if (U(CertCreateCertificateChainEngine)(&cfg, &h) && h) { okc++; U(CertFreeCertificateChainEngine)(h); }
    }
    EXPECT_EQ(okc, 200);
}

/* ---- dwFlags accepted by engine creation ---- */
static void eng_flags(DWORD fl) {
    REQUIRE(U(CertCreateCertificateChainEngine));
    PKI_ENG e;
    BOOL ok = pki_eng_open(&e, "root", "inter", NULL, fl);
    CHECKF(ok, "engine flags 0x%lx", fl);
    if (ok) {
        PCCERT_CHAIN_CONTEXT c = pki_chain(e.h, "leaf", NULL, PKI_T0, PKI_OFFLINE, NULL);
        CHECK(c != NULL);
        if (c) { EXPECT_EQ(c->TrustStatus.dwErrorStatus, 0); EXPECT_EQ(pki_nelem(c, 0), 3); pki_chain_free(c); }
    }
    pki_eng_close(&e);
}
#define ENG_FL(nm, fl) TEST(chain_engine_flags_##nm) { eng_flags(fl); }
ENG_FL(none, 0)
ENG_FL(cache_end_cert, CERT_CHAIN_CACHE_END_CERT)
ENG_FL(thread_store_sync, CERT_CHAIN_THREAD_STORE_SYNC)
ENG_FL(cache_only_url, CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL)
ENG_FL(use_local_machine, CERT_CHAIN_USE_LOCAL_MACHINE_STORE)
ENG_FL(cache_auto_update, CERT_CHAIN_ENABLE_CACHE_AUTO_UPDATE)
ENG_FL(share_store, CERT_CHAIN_ENABLE_SHARE_STORE)
ENG_FL(offline_combo, CERT_CHAIN_CACHE_END_CERT | CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL)
ENG_FL(all_documented, CERT_CHAIN_CACHE_END_CERT | CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL | CERT_CHAIN_USE_LOCAL_MACHINE_STORE |
       CERT_CHAIN_ENABLE_CACHE_AUTO_UPDATE | CERT_CHAIN_ENABLE_SHARE_STORE)

TEST(chain_engine_url_timeout_zero_and_cache_params) {
    REQUIRE(U(CertCreateCertificateChainEngine));
    PKI_ENG e; CHECK(pki_eng_open_ex(&e, "root", "inter", NULL, 0, 5, 7));
    PCCERT_CHAIN_CONTEXT c = pki_chain(e.h, "leaf", NULL, PKI_T0, PKI_OFFLINE, NULL);
    CHECK(c && c->TrustStatus.dwErrorStatus == 0);
    pki_chain_free(c); pki_eng_close(&e);
}
TEST(chain_engine_tiny_cache_still_builds) {
    REQUIRE(U(CertCreateCertificateChainEngine));
    PKI_ENG e; CHECK(pki_eng_open_ex(&e, "root", "inter inter_pl0 sub_ca inter_pl1 sub_ca1", NULL, 0, 1, 1));
    const char *ids[] = {"leaf", "leaf_pl1", "leaf_root"};
    for (int i = 0; i < 3; i++) {
        PCCERT_CHAIN_CONTEXT c = pki_chain(e.h, ids[i], NULL, PKI_T0, PKI_OFFLINE, NULL);
        CHECKF(c && c->TrustStatus.dwErrorStatus == 0, "%s", ids[i]);
        pki_chain_free(c);
    }
    pki_eng_close(&e);
}

/* ---- trust anchors: exclusive mode (private roots) ---- */
TEST(chain_engine_exclusive_root_missing_intermediate_is_partial) {
    REQUIRE(U(CertCreateCertificateChainEngine));
    PKI_ENG e; CHECK(pki_eng_open(&e, "root", NULL, NULL, 0));
    PCCERT_CHAIN_CONTEXT c = pki_chain(e.h, "leaf", NULL, PKI_T0, PKI_OFFLINE, NULL);
    CHECK(c != NULL);
    if (c) { EXPECT_EQ(c->TrustStatus.dwErrorStatus, CERT_TRUST_IS_PARTIAL_CHAIN); EXPECT_EQ(pki_nelem(c, 0), 1); }
    pki_chain_free(c); pki_eng_close(&e);
}
TEST(chain_engine_exclusive_additional_store_supplies_intermediate) {
    REQUIRE(U(CertCreateCertificateChainEngine));
    PKI_ENG e; CHECK(pki_eng_open(&e, "root", "inter", NULL, 0));
    PCCERT_CHAIN_CONTEXT c = pki_chain(e.h, "leaf", NULL, PKI_T0, PKI_OFFLINE, NULL);
    CHECK(c != NULL);
    if (c) { pki_note_chain("exclusive+rghAdditionalStore", c); EXPECT_EQ(c->TrustStatus.dwErrorStatus, 0); EXPECT_EQ(pki_nelem(c, 0), 3);
             EXPECT_ID(c, 0, 1, "inter"); EXPECT_ID(c, 0, 2, "root"); }
    pki_chain_free(c); pki_eng_close(&e);
}
TEST(chain_engine_exclusive_hAdditionalStore_param_supplies_intermediate) {
    REQUIRE(U(CertCreateCertificateChainEngine));
    PKI_ENG e; CHECK(pki_eng_open(&e, "root", NULL, NULL, 0));
    PCCERT_CHAIN_CONTEXT c = pki_chain(e.h, "leaf", "inter", PKI_T0, PKI_OFFLINE, NULL);
    CHECK(c != NULL);
    if (c) { EXPECT_EQ(c->TrustStatus.dwErrorStatus, 0); EXPECT_EQ(pki_nelem(c, 0), 3); }
    pki_chain_free(c); pki_eng_close(&e);
}
TEST(chain_engine_config_two_additional_stores) {
    REQUIRE(U(CertCreateCertificateChainEngine));
    if (t_is_wine()) { t_skip("emulator has no exclusive trust mode"); return; }
    HCERTSTORE xr = pki_store("root"), as[2] = { pki_store("inter_pl0"), pki_store("sub_ca") };
    CERT_CHAIN_ENGINE_CONFIG cfg; memset(&cfg, 0, sizeof cfg); cfg.cbSize = sizeof cfg;
    cfg.hExclusiveRoot = xr; cfg.cAdditionalStore = 2; cfg.rghAdditionalStore = as;
    HCERTCHAINENGINE h = NULL;
    CHECK(U(CertCreateCertificateChainEngine)(&cfg, &h));
    if (h) {
        PCCERT_CHAIN_CONTEXT c = pki_chain(h, "leaf_pl", NULL, PKI_T0, PKI_OFFLINE, NULL);
        CHECK(c != NULL);
        if (c) { pki_note_chain("two additional", c); EXPECT_EQ(pki_nelem(c, 0), 4); CHECK(c->TrustStatus.dwErrorStatus & CERT_TRUST_INVALID_BASIC_CONSTRAINTS); }
        pki_chain_free(c); U(CertFreeCertificateChainEngine)(h);
    }
    U(CertCloseStore)(xr, 0); U(CertCloseStore)(as[0], 0); U(CertCloseStore)(as[1], 0);
}
TEST(chain_engine_exclusive_empty_root_store_means_untrusted) {
    REQUIRE(U(CertCreateCertificateChainEngine));
    PKI_ENG e; CHECK(pki_eng_open(&e, "", "inter root", NULL, 0));
    PCCERT_CHAIN_CONTEXT c = pki_chain(e.h, "leaf", NULL, PKI_T0, PKI_OFFLINE, NULL);
    CHECK(c != NULL);
    if (c) { EXPECT_EQ(c->TrustStatus.dwErrorStatus, CERT_TRUST_IS_UNTRUSTED_ROOT); EXPECT_EQ(pki_nelem(c, 0), 3); }
    pki_chain_free(c); pki_eng_close(&e);
}
TEST(chain_engine_exclusive_root_in_additional_store_does_not_confer_trust) {
    REQUIRE(U(CertCreateCertificateChainEngine));
    PKI_ENG e; CHECK(pki_eng_open(&e, "root2", "inter root", NULL, 0));
    PCCERT_CHAIN_CONTEXT c = pki_chain(e.h, "leaf", NULL, PKI_T0, PKI_OFFLINE, NULL);
    CHECK(c != NULL);
    if (c) { EXPECT_EQ(c->TrustStatus.dwErrorStatus, CERT_TRUST_IS_UNTRUSTED_ROOT); EXPECT_EQ(pki_nelem(c, 0), 3); }
    pki_chain_free(c); pki_eng_close(&e);
}
TEST(chain_engine_exclusive_only_other_root_listed) {
    REQUIRE(U(CertCreateCertificateChainEngine));
    PKI_ENG e; CHECK(pki_eng_open(&e, "root2", "inter", NULL, 0));
    PCCERT_CHAIN_CONTEXT c = pki_chain(e.h, "leaf", NULL, PKI_T0, PKI_OFFLINE, NULL);
    CHECK(c != NULL);
    if (c) { pki_note_chain("wrong exclusive root", c);
             EXPECT_EQ(c->TrustStatus.dwErrorStatus, CERT_TRUST_IS_PARTIAL_CHAIN); }   /* issuer root is nowhere to be found */
    pki_chain_free(c); pki_eng_close(&e);
}
TEST(chain_engine_exclusive_caller_may_close_store_handles_after_create) {
    REQUIRE(U(CertCreateCertificateChainEngine));
    if (t_is_wine()) { t_skip("emulator has no exclusive trust mode"); return; }
    HCERTSTORE rs = pki_store("root"), os = pki_store("inter");
    CERT_CHAIN_ENGINE_CONFIG cfg; memset(&cfg, 0, sizeof cfg); cfg.cbSize = sizeof cfg;
    cfg.hExclusiveRoot = rs; cfg.cAdditionalStore = 1; cfg.rghAdditionalStore = &os;
    HCERTCHAINENGINE h = NULL;
    CHECK(U(CertCreateCertificateChainEngine)(&cfg, &h));
    U(CertCloseStore)(rs, 0); U(CertCloseStore)(os, 0);   /* the engine holds its own references */
    if (h) {
        PCCERT_CHAIN_CONTEXT c = pki_chain(h, "leaf", NULL, PKI_T0, PKI_OFFLINE, NULL);
        CHECK(c != NULL);
        if (c) { pki_note_chain("after caller closed stores", c); EXPECT_EQ(c->TrustStatus.dwErrorStatus, 0); }
        pki_chain_free(c); U(CertFreeCertificateChainEngine)(h);
    }
}
TEST(chain_engine_exclusive_root_trusts_listed_root) {
    REQUIRE(U(CertCreateCertificateChainEngine));
    PKI_ENG e; CHECK(pki_eng_open(&e, "root", NULL, NULL, 0));
    PCCERT_CHAIN_CONTEXT c = pki_chain(e.h, "leaf", "inter", PKI_T0, PKI_OFFLINE, NULL);
    CHECK(c != NULL);
    if (c) { pki_note_chain("exclusive root", c); EXPECT_EQ(c->TrustStatus.dwErrorStatus, 0); EXPECT_EQ(pki_nelem(c, 0), 3);
             t_note("root element info bits 0x%lx (IS_FROM_EXCLUSIVE_TRUST_STORE=0x2000, IS_SELF_SIGNED=8)", pki_elem_info(c, 0, 2));
             CHECK(pki_elem_info(c, 0, 2) & CERT_TRUST_IS_SELF_SIGNED); }
    pki_chain_free(c); pki_eng_close(&e);
}
TEST(chain_engine_exclusive_root_rejects_unlisted_root) {
    REQUIRE(U(CertCreateCertificateChainEngine));
    PKI_ENG e; CHECK(pki_eng_open(&e, "root2", NULL, NULL, 0));
    PCCERT_CHAIN_CONTEXT c = pki_chain(e.h, "leaf", "inter root", PKI_T0, PKI_OFFLINE, NULL);
    CHECK(c != NULL);
    if (c) { EXPECT_EQ(c->TrustStatus.dwErrorStatus, CERT_TRUST_IS_UNTRUSTED_ROOT); }
    pki_chain_free(c); pki_eng_close(&e);
}
TEST(chain_engine_exclusive_second_root_selects_cross_signed_path) {
    REQUIRE(U(CertCreateCertificateChainEngine));
    PKI_ENG e; CHECK(pki_eng_open(&e, "root2", "inter inter_x", NULL, 0));
    PCCERT_CHAIN_CONTEXT c = pki_chain(e.h, "leaf", NULL, PKI_T0, PKI_OFFLINE, NULL);
    CHECK(c != NULL);
    if (c) { pki_note_chain("cross-signed via root2", c); EXPECT_EQ(c->TrustStatus.dwErrorStatus, 0); EXPECT_EQ(pki_nelem(c, 0), 3);
             EXPECT_ID(c, 0, 1, "inter_x"); EXPECT_ID(c, 0, 2, "root2"); }
    pki_chain_free(c); pki_eng_close(&e);
}
TEST(chain_engine_exclusive_ca_flag_intermediate_as_anchor) {
    if (t_is_wine()) { t_skip("emulator has no exclusive CA flag"); return; }
    /* CERT_CHAIN_EXCLUSIVE_ENABLE_CA_FLAG: a non-self-signed CA in hExclusiveRoot terminates the chain as trusted */
    REQUIRE(U(CertCreateCertificateChainEngine));
    HCERTSTORE xr = pki_store("inter");
    CERT_CHAIN_ENGINE_CONFIG cfg; memset(&cfg, 0, sizeof cfg); cfg.cbSize = sizeof cfg;
    cfg.hExclusiveRoot = xr; cfg.dwExclusiveFlags = CERT_CHAIN_EXCLUSIVE_ENABLE_CA_FLAG;
    HCERTCHAINENGINE h = NULL;
    CHECK(U(CertCreateCertificateChainEngine)(&cfg, &h));
    if (h) {
        PCCERT_CHAIN_CONTEXT c = pki_chain(h, "leaf", NULL, PKI_T0, PKI_OFFLINE, NULL);
        CHECK(c != NULL);
        if (c) { pki_note_chain("CA as anchor", c); EXPECT_EQ(c->TrustStatus.dwErrorStatus, 0); EXPECT_EQ(pki_nelem(c, 0), 2);
                 t_note("top element info 0x%lx (IS_CA_TRUSTED=0x4000)", pki_elem_info(c, 0, 1)); }
        pki_chain_free(c); U(CertFreeCertificateChainEngine)(h);
    }
    U(CertCloseStore)(xr, 0);
}
TEST(chain_engine_exclusive_without_ca_flag_intermediate_not_anchor) {
    if (t_is_wine()) { t_skip("emulator has no exclusive trust mode"); return; }
    REQUIRE(U(CertCreateCertificateChainEngine));
    PKI_ENG e; CHECK(pki_eng_open(&e, "inter", NULL, NULL, 0));
    PCCERT_CHAIN_CONTEXT c = pki_chain(e.h, "leaf", NULL, PKI_T0, PKI_OFFLINE, NULL);
    CHECK(c != NULL);
    if (c) { pki_note_chain("no CA flag", c); CHECK(c->TrustStatus.dwErrorStatus != 0); }
    pki_chain_free(c); pki_eng_close(&e);
}

/* ---- classic restricted mode: hRestrictedRoot must be a subset of the system Root store ---- */
TEST(chain_engine_restricted_root_with_private_root_rejected) {
    REQUIRE(U(CertCreateCertificateChainEngine));
    PCCERT_CONTEXT rc = pki_cert("root");
    PKI_ENG e;
    SET_ERR(0);
    BOOL ok = pki_eng_open_restricted(&e, rc, 1, NULL, NULL, 0);
    DWORD err = GetLastError();
    CHECK(!ok);                              /* the test root is not in the system Root store */
    EXPECT_EQ(e.h, NULL);
    t_note("restricted root not in system store: GetLastError=0x%lx (decomp suggests CRYPT_E_NOT_FOUND 0x80092004)", err);
    CHECK(err != 0);
    pki_eng_close(&e); U(CertFreeCertificateContext)(rc);
}
TEST(chain_engine_restricted_root_empty_store_accepted) {
    REQUIRE(U(CertCreateCertificateChainEngine));
    PKI_ENG e;
    BOOL ok = pki_eng_open_restricted(&e, NULL, 1, "inter root", NULL, 0);
    CHECK(ok);
    if (ok) {
        PCCERT_CHAIN_CONTEXT c = pki_chain(e.h, "leaf", NULL, PKI_T0, PKI_OFFLINE, NULL);
        CHECK(c != NULL);
        if (c) { pki_note_chain("restricted empty", c); EXPECT_EQ(c->TrustStatus.dwErrorStatus, CERT_TRUST_IS_UNTRUSTED_ROOT); EXPECT_EQ(pki_nelem(c, 0), 3); }
        pki_chain_free(c);
    }
    pki_eng_close(&e);
}
TEST(chain_engine_restricted_root_system_subset_accepted) {
    REQUIRE(U(CertCreateCertificateChainEngine));
    PCCERT_CONTEXT sys = pki_first_system_root();
    if (!sys) { t_skip("no certificate in the current user Root store"); return; }
    PKI_ENG e;
    BOOL ok = pki_eng_open_restricted(&e, sys, 1, "inter root", NULL, 0);
    CHECK(ok);
    if (ok) {
        PCCERT_CHAIN_CONTEXT c = pki_chain(e.h, "leaf", NULL, PKI_T0, PKI_OFFLINE, NULL);
        CHECK(c != NULL);
        if (c) { EXPECT_EQ(c->TrustStatus.dwErrorStatus, CERT_TRUST_IS_UNTRUSTED_ROOT); }   /* the private root is still untrusted */
        pki_chain_free(c);
    }
    pki_eng_close(&e); U(CertFreeCertificateContext)(sys);
}
TEST(chain_engine_restricted_root_system_plus_private_rejected) {
    REQUIRE(U(CertCreateCertificateChainEngine));
    PCCERT_CONTEXT sys = pki_first_system_root();
    if (!sys) { t_skip("no certificate in the current user Root store"); return; }
    PCCERT_CONTEXT rc = pki_cert("root");
    PKI_ENG e; memset(&e, 0, sizeof e);
    HCERTSTORE rs = pki_store(NULL);
    U(CertAddCertificateContextToStore)(rs, sys, CERT_STORE_ADD_ALWAYS, NULL);
    U(CertAddCertificateContextToStore)(rs, rc, CERT_STORE_ADD_ALWAYS, NULL);
    CERT_CHAIN_ENGINE_CONFIG cfg; memset(&cfg, 0, sizeof cfg); cfg.cbSize = CFG_CB; cfg.hRestrictedRoot = rs;
    HCERTCHAINENGINE h = ENG_SENTINEL;
    CHECK(!U(CertCreateCertificateChainEngine)(&cfg, &h));
    EXPECT_EQ(h, NULL);
    U(CertCloseStore)(rs, 0); U(CertFreeCertificateContext)(rc); U(CertFreeCertificateContext)(sys);
}
TEST(chain_engine_restricted_other_and_trust_have_no_subset_rule) {
    REQUIRE(U(CertCreateCertificateChainEngine));
    PKI_ENG e;
    BOOL ok = pki_eng_open_restricted(&e, NULL, 0, "inter root", "leaf", 0);
    CHECK(ok);
    if (ok) {
        PCCERT_CHAIN_CONTEXT c = pki_chain(e.h, "leaf", NULL, PKI_T0, PKI_OFFLINE, NULL);
        CHECK(c != NULL);
        if (c) { pki_note_chain("restricted other/trust", c); EXPECT_EQ(c->TrustStatus.dwErrorStatus, CERT_TRUST_IS_UNTRUSTED_ROOT); EXPECT_EQ(pki_nelem(c, 0), 3); }
        pki_chain_free(c);
    }
    pki_eng_close(&e);
}
TEST(chain_engine_restricted_other_supplies_intermediate) {
    REQUIRE(U(CertCreateCertificateChainEngine));
    PKI_ENG e;
    BOOL ok = pki_eng_open_restricted(&e, NULL, 0, "inter", NULL, 0);
    CHECK(ok);
    if (ok) {
        PCCERT_CHAIN_CONTEXT c = pki_chain(e.h, "leaf_root", NULL, PKI_T0, PKI_OFFLINE, NULL);
        CHECK(c != NULL);
        if (c) { pki_note_chain("restricted other, missing root", c); EXPECT_EQ(c->TrustStatus.dwErrorStatus, CERT_TRUST_IS_PARTIAL_CHAIN); EXPECT_EQ(pki_nelem(c, 0), 1); }
        pki_chain_free(c);
        c = pki_chain(e.h, "leaf", NULL, PKI_T0, PKI_OFFLINE, NULL);
        CHECK(c != NULL);
        if (c) { pki_note_chain("restricted other", c); EXPECT_EQ(c->TrustStatus.dwErrorStatus, CERT_TRUST_IS_PARTIAL_CHAIN); EXPECT_EQ(pki_nelem(c, 0), 2); }
        pki_chain_free(c);
    }
    pki_eng_close(&e);
}

/* ---- validation of mixed restricted / exclusive configuration ---- */
static void eng_mix(int restricted, int exclusive_root, int exclusive_tp, DWORD cb, int want_ok) {
    REQUIRE(U(CertCreateCertificateChainEngine));
    if (t_is_wine()) { t_skip("emulator has no exclusive trust mode"); return; }
    HCERTSTORE s1 = pki_store(NULL), s2 = pki_store("root");
    CERT_CHAIN_ENGINE_CONFIG cfg; memset(&cfg, 0, sizeof cfg); cfg.cbSize = cb;
    if (restricted == 1) cfg.hRestrictedRoot = s1;          /* empty store: passes the subset test */
    if (restricted == 2) cfg.hRestrictedTrust = s1;
    if (restricted == 3) cfg.hRestrictedOther = s1;
    if (exclusive_root) cfg.hExclusiveRoot = s2;
    if (exclusive_tp) cfg.hExclusiveTrustedPeople = s2;
    HCERTCHAINENGINE h = ENG_SENTINEL;
    SET_ERR(0);
    BOOL r = U(CertCreateCertificateChainEngine)(&cfg, &h);
    if (want_ok) { CHECK(r); CHECK(h && h != ENG_SENTINEL); if (r && h) U(CertFreeCertificateChainEngine)(h); }
    else { CHECK(!r); EXPECT_ERR(E_INVALIDARG); EXPECT_EQ(h, NULL); }
    U(CertCloseStore)(s1, 0); U(CertCloseStore)(s2, 0);
}
TEST(chain_engine_exclusive_root_alone_ok) { eng_mix(0, 1, 0, 0x58, 1); }
TEST(chain_engine_exclusive_trusted_people_alone_ok) { eng_mix(0, 0, 1, 0x58, 1); }
TEST(chain_engine_exclusive_both_ok) { eng_mix(0, 1, 1, 0x58, 1); }
TEST(chain_engine_exclusive_with_cb54_ok) { eng_mix(0, 1, 1, 0x54, 1); }
TEST(chain_engine_exclusive_with_cb50_ok) { eng_mix(0, 1, 1, 0x50, 1); }
TEST(chain_engine_restricted_root_plus_exclusive_root_rejected) { eng_mix(1, 1, 0, 0x58, 0); }
TEST(chain_engine_restricted_root_plus_exclusive_tp_rejected) { eng_mix(1, 0, 1, 0x58, 0); }
TEST(chain_engine_restricted_trust_plus_exclusive_root_rejected) { eng_mix(2, 1, 0, 0x58, 0); }
TEST(chain_engine_restricted_other_plus_exclusive_root_rejected) { eng_mix(3, 1, 0, 0x58, 0); }
TEST(chain_engine_restricted_other_plus_exclusive_tp_rejected) { eng_mix(3, 0, 1, 0x58, 0); }
TEST(chain_engine_restricted_other_plus_exclusive_root_cb50_rejected) { eng_mix(3, 1, 0, 0x50, 0); }
TEST(chain_engine_restricted_other_with_cb40_ok) { eng_mix(3, 0, 0, 0x40, 1); }
TEST(chain_engine_restricted_root_empty_with_cb40_ok) { eng_mix(1, 0, 0, 0x40, 1); }
TEST(chain_engine_exclusive_fields_hidden_by_cb40) {
    /* cbSize 0x40 hides the exclusive fields, so the mix is not detected */
    eng_mix(3, 1, 1, 0x40, 1);
}

/* ---- free / lifetime ---- */
TEST(chain_engine_free_null_is_safe) {
    REQUIRE(U(CertFreeCertificateChainEngine));
    U(CertFreeCertificateChainEngine)(NULL);     /* HCCE_CURRENT_USER: flushes the default engine */
    CHECK(1);
}
TEST(chain_engine_free_local_machine_pseudo_handle_is_safe) {
    REQUIRE(U(CertFreeCertificateChainEngine));
    U(CertFreeCertificateChainEngine)(HCCE_LOCAL_MACHINE);
    CHECK(1);
}
TEST(chain_engine_default_engine_usable_after_flush) {
    REQUIRE(U(CertFreeCertificateChainEngine));
    U(CertFreeCertificateChainEngine)(NULL);
    PCCERT_CHAIN_CONTEXT c = pki_chain(NULL, "leaf", "inter root", PKI_T0, PKI_OFFLINE, NULL);
    CHECK(c != NULL);
    pki_chain_free(c);
}
TEST(chain_engine_chain_outlives_engine) {
    REQUIRE(U(CertCreateCertificateChainEngine));
    PKI_ENG e; CHECK(pki_eng_open(&e, "root", "inter", NULL, 0));
    PCCERT_CHAIN_CONTEXT c = pki_chain(e.h, "leaf", NULL, PKI_T0, PKI_OFFLINE, NULL);
    CHECK(c != NULL);
    pki_eng_close(&e);                               /* engine and its stores are gone */
    if (c) {
        EXPECT_EQ(c->cChain, 1);
        EXPECT_EQ(pki_nelem(c, 0), 3);
        EXPECT_ID(c, 0, 0, "leaf");
        EXPECT_ID(c, 0, 2, "root");
        EXPECT_EQ(c->TrustStatus.dwErrorStatus, 0);
    }
    pki_chain_free(c);
}
TEST(chain_engine_chain_after_engine_free_still_dupable) {
    REQUIRE(U(CertCreateCertificateChainEngine));
    PKI_ENG e; CHECK(pki_eng_open(&e, "root", "inter", NULL, 0));
    PCCERT_CHAIN_CONTEXT c = pki_chain(e.h, "leaf", NULL, PKI_T0, PKI_OFFLINE, NULL);
    pki_eng_close(&e);
    if (c) {
        PCCERT_CHAIN_CONTEXT d = U(CertDuplicateCertificateChain)(c);
        CHECK(d == c);
        pki_chain_free(c);
        EXPECT_EQ(d->cChain, 1);
        pki_chain_free(d);
    }
}

/* ---- resync ---- */
TEST(chain_engine_resync_returns_true) {
    REQUIRE(U(CertResyncCertificateChainEngine));
    PKI_ENG e; CHECK(pki_eng_open(&e, "root", "inter", NULL, 0));
    CHECK(U(CertResyncCertificateChainEngine)(e.h));
    CHECK(U(CertResyncCertificateChainEngine)(e.h));
    pki_eng_close(&e);
}
TEST(chain_engine_resync_default_engines) {
    REQUIRE(U(CertResyncCertificateChainEngine));
    CHECK(U(CertResyncCertificateChainEngine)(NULL));
    CHECK(U(CertResyncCertificateChainEngine)(HCCE_LOCAL_MACHINE));
}
TEST(chain_engine_resync_serial_local_machine_pseudo_handle) {
    REQUIRE(U(CertResyncCertificateChainEngine));
    CHECK(U(CertResyncCertificateChainEngine)((HCERTCHAINENGINE)(ULONG_PTR)2));   /* returns TRUE without touching anything */
}
TEST(chain_engine_resync_picks_up_new_root) {
    REQUIRE(U(CertResyncCertificateChainEngine));
    PKI_ENG e; CHECK(pki_eng_open(&e, "", "inter root", NULL, 0));
    PCCERT_CHAIN_CONTEXT c = pki_chain(e.h, "leaf", NULL, PKI_T0, PKI_OFFLINE, NULL);
    CHECK(c && c->TrustStatus.dwErrorStatus == CERT_TRUST_IS_UNTRUSTED_ROOT);
    pki_chain_free(c);
    const PKI_ITEM *r = pki_find("root");
    CHECK(U(CertAddEncodedCertificateToStore)(e.root, ENC, r->der, r->len, CERT_STORE_ADD_ALWAYS, NULL));
    CHECK(U(CertResyncCertificateChainEngine)(e.h));
    c = pki_chain(e.h, "leaf", NULL, PKI_T0, PKI_OFFLINE, NULL);
    CHECK(c != NULL);
    if (c) { pki_note_chain("after resync", c); EXPECT_EQ(c->TrustStatus.dwErrorStatus, 0); }
    pki_chain_free(c); pki_eng_close(&e);
}
TEST(chain_engine_resync_picks_up_removed_root) {
    REQUIRE(U(CertResyncCertificateChainEngine));
    PKI_ENG e; CHECK(pki_eng_open(&e, "root", "inter", NULL, 0));
    PCCERT_CHAIN_CONTEXT c = pki_chain(e.h, "leaf", NULL, PKI_T0, PKI_OFFLINE, NULL);
    CHECK(c && c->TrustStatus.dwErrorStatus == 0);
    pki_chain_free(c);
    PCCERT_CONTEXT rc = U(CertEnumCertificatesInStore)(e.root, NULL);
    CHECK(rc != NULL);
    if (rc) {
        PCCERT_CONTEXT dup = U(CertDuplicateCertificateContext)(rc);
        CHECK(U(CertDeleteCertificateFromStore)(dup));       /* consumes dup */
        U(CertFreeCertificateContext)(rc);
    }
    CHECK(U(CertResyncCertificateChainEngine)(e.h));
    c = pki_chain(e.h, "leaf", NULL, PKI_T0, PKI_OFFLINE, NULL);
    CHECK(c != NULL);
    if (c) { pki_note_chain("root removed + resync", c); CHECK(c->TrustStatus.dwErrorStatus != 0); }
    pki_chain_free(c); pki_eng_close(&e);
}
TEST(chain_engine_resync_picks_up_new_intermediate) {
    REQUIRE(U(CertResyncCertificateChainEngine));
    PKI_ENG e; CHECK(pki_eng_open(&e, "root", "", NULL, 0));
    PCCERT_CHAIN_CONTEXT c = pki_chain(e.h, "leaf", NULL, PKI_T0, PKI_OFFLINE, NULL);
    CHECK(c && c->TrustStatus.dwErrorStatus == CERT_TRUST_IS_PARTIAL_CHAIN);
    pki_chain_free(c);
    const PKI_ITEM *r = pki_find("inter");
    CHECK(U(CertAddEncodedCertificateToStore)(e.other, ENC, r->der, r->len, CERT_STORE_ADD_ALWAYS, NULL));
    CHECK(U(CertResyncCertificateChainEngine)(e.h));
    c = pki_chain(e.h, "leaf", NULL, PKI_T0, PKI_OFFLINE, NULL);
    CHECK(c != NULL);
    if (c) { EXPECT_EQ(c->TrustStatus.dwErrorStatus, 0); EXPECT_EQ(pki_nelem(c, 0), 3); }
    pki_chain_free(c); pki_eng_close(&e);
}
TEST(chain_engine_store_change_without_resync_observation) {
    REQUIRE(U(CertResyncCertificateChainEngine));
    PKI_ENG e; CHECK(pki_eng_open(&e, "", "inter root", NULL, 0));
    PCCERT_CHAIN_CONTEXT c = pki_chain(e.h, "leaf", NULL, PKI_T0, PKI_OFFLINE, NULL);
    pki_chain_free(c);
    const PKI_ITEM *r = pki_find("root");
    U(CertAddEncodedCertificateToStore)(e.root, ENC, r->der, r->len, CERT_STORE_ADD_ALWAYS, NULL);
    c = pki_chain(e.h, "leaf", NULL, PKI_T0, PKI_OFFLINE, NULL);
    if (c) { t_note("trust of a root added without resync: err=0x%lx (0 = engine noticed the store change)", c->TrustStatus.dwErrorStatus); }
    pki_chain_free(c); pki_eng_close(&e);
}

/* ---- default engines ---- */
static void default_engine_untrusted(HCERTCHAINENGINE h, DWORD flags) {
    REQUIRE(U(CertGetCertificateChain));
    PCCERT_CHAIN_CONTEXT c = pki_chain(h, "leaf", "inter root", PKI_T0, flags | PKI_OFFLINE, NULL);
    CHECK(c != NULL);
    if (c) {
        pki_note_chain("default engine", c);
        EXPECT_EQ(c->TrustStatus.dwErrorStatus, CERT_TRUST_IS_UNTRUSTED_ROOT);   /* test root is in no system store */
        EXPECT_EQ(pki_nelem(c, 0), 3);
    }
    pki_chain_free(c);
}
TEST(chain_engine_default_current_user_untrusted_test_root) { default_engine_untrusted(NULL, 0); }
TEST(chain_engine_default_local_machine_untrusted_test_root) { default_engine_untrusted(HCCE_LOCAL_MACHINE, 0); }
TEST(chain_engine_default_missing_intermediate_partial) {
    PCCERT_CHAIN_CONTEXT c = pki_chain(NULL, "leaf", NULL, PKI_T0, PKI_OFFLINE, NULL);
    CHECK(c != NULL);
    if (c) { EXPECT_EQ(c->TrustStatus.dwErrorStatus, CERT_TRUST_IS_PARTIAL_CHAIN); EXPECT_EQ(pki_nelem(c, 0), 1); }
    pki_chain_free(c);
}
