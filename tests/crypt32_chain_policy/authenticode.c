/* CERT_CHAIN_POLICY_AUTHENTICODE and CERT_CHAIN_POLICY_AUTHENTICODE_TS. */
#include "cp.h"

typedef struct { DWORD cb; DWORD reg; const void *signer; } ACPARA;       /* AUTHENTICODE_EXTRA_CERT_CHAIN_POLICY_PARA (x64) */
typedef struct { DWORD cb; DWORD commercial; } ACSTAT;                    /* AUTHENTICODE_EXTRA_CERT_CHAIN_POLICY_STATUS */
typedef struct { DWORD cb; DWORD reg; DWORD commercial; } TSPARA;          /* AUTHENTICODE_TS_EXTRA_CERT_CHAIN_POLICY_PARA */
static const char g_signer_dummy[256];                                     /* zeroed CMSG_SIGNER_INFO stand-in (only tested for non-NULL) */

static PRES ac(PCCERT_CHAIN_CONTEXT c, DWORD flags, DWORD reg, int with_signer, DWORD extra_cb) {
    ACPARA e; memset(&e, 0, sizeof e);
    e.cb = extra_cb ? extra_cb : sizeof e; e.reg = reg; e.signer = with_signer ? g_signer_dummy : NULL;
    return cp_run(CERT_CHAIN_POLICY_AUTHENTICODE, c, flags, &e);
}
static PRES ts(PCCERT_CHAIN_CONTEXT c, DWORD flags, DWORD reg) {
    TSPARA e; memset(&e, 0, sizeof e);
    e.cb = sizeof e; e.reg = reg;
    return cp_run(CERT_CHAIN_POLICY_AUTHENTICODE_TS, c, flags, &e);
}
static PRES syn_ac(DWORD ctxerr, int el, DWORD elerr, DWORD rev, DWORD reg, int ts_variant) {
    SYN s; int n[1] = {3};
    syn_init(&s, 1, n); syn_ctx(&s, ctxerr, 0);
    if (el >= 0) { syn_el(&s, 0, el, elerr, 0); if (rev) syn_rev(&s, 0, el, rev); }
    return ts_variant ? ts(&s.cc, 0, reg) : ac(&s.cc, 0, reg, 0, 0);
}

/* ---------- AUTHENTICODE ---------- */
TEST(authenticode_trusted_chain_null_para) {
    PCCERT_CHAIN_CONTEXT c; PRES p;
    NEED_ENV();
    c = cp_chain(C_CODE);
    if (!c) { t_skip("chain build failed"); return; }
    p = cp_run(CERT_CHAIN_POLICY_AUTHENTICODE, c, 0, NULL);
    CHECK(p.ret && p.err == 0 && p.ci == -1 && p.ei == -1);
    cp_free(c);
}
TEST(authenticode_no_signer_info_skips_purpose_check) {
    static const int leaves[] = {C_SRV, C_CLIENT, C_EMAIL, C_NOEKU, C_CODE};
    NEED_ENV();
    for (unsigned i = 0; i < 5; i++) {
        PCCERT_CHAIN_CONTEXT c = cp_chain(leaves[i]); PRES p;
        if (!c) { t_skip("chain build failed"); return; }
        p = ac(c, 0, 0, 0, 0);
        CHECKF(p.ret && p.err == 0, "leaf %d: 0x%lx", leaves[i], p.err);
        cp_free(c);
    }
}
TEST(authenticode_signer_info_enforces_code_signing_purpose) {
    static const struct { int leaf; DWORD want; } t[] = {
        {C_CODE, 0}, {C_NOEKU, 0}, {C_DIRECT, 0}, {C_SRV, CERR_PURPOSE}, {C_CLIENT, CERR_PURPOSE}, {C_EMAIL, CERR_PURPOSE} };
    NEED_ENV();
    for (unsigned i = 0; i < sizeof t / sizeof t[0]; i++) {
        PCCERT_CHAIN_CONTEXT c = cp_chain(t[i].leaf); PRES p;
        if (!c) { t_skip("chain build failed"); return; }
        p = ac(c, 0, 0, 1, 0);
        CHECKF(p.ret && p.err == t[i].want, "leaf %d: 0x%lx want 0x%lx", t[i].leaf, p.err, t[i].want);
        if (t[i].want) CHECKF(p.ci == 0 && p.ei == 0, "leaf %d indices %ld/%ld", t[i].leaf, p.ci, p.ei);
        else CHECK(p.ci == -1 && p.ei == -1);
        cp_free(c);
    }
}
TEST(authenticode_extra_cbsize_gates_signer_info) {
    static const struct { DWORD cb; DWORD want; } t[] = {{4, 0}, {8, 0}, {9, CERR_PURPOSE}, {16, CERR_PURPOSE}, {24, CERR_PURPOSE}};
    PCCERT_CHAIN_CONTEXT c;
    NEED_ENV();
    c = cp_chain(C_SRV);
    if (!c) { t_skip("chain build failed"); return; }
    for (unsigned i = 0; i < sizeof t / sizeof t[0]; i++) {
        PRES p = ac(c, 0, 0, 1, t[i].cb);
        CHECKF(p.ret && p.err == t[i].want, "extra cbSize %lu: 0x%lx want 0x%lx", t[i].cb, p.err, t[i].want);
    }
    cp_free(c);
}
TEST(authenticode_policy_para_cbsize_gates_extra) {
    static const struct { DWORD cb; DWORD want; } t[] = {{4, 0}, {8, 0}, {9, CERR_PURPOSE}, {24, CERR_PURPOSE}};
    PCCERT_CHAIN_CONTEXT c;
    NEED_ENV();
    c = cp_chain(C_SRV);
    if (!c) { t_skip("chain build failed"); return; }
    for (unsigned i = 0; i < sizeof t / sizeof t[0]; i++) {
        ACPARA e; PRES p;
        memset(&e, 0, sizeof e); e.cb = sizeof e; e.signer = g_signer_dummy;
        p = cp_run_ex(CERT_CHAIN_POLICY_AUTHENTICODE, c, t[i].cb, 0, &e, sizeof(CERT_CHAIN_POLICY_STATUS), NULL);
        CHECKF(p.ret && p.err == t[i].want, "para cbSize %lu: 0x%lx want 0x%lx", t[i].cb, p.err, t[i].want);
    }
    cp_free(c);
}
TEST(authenticode_untrusted_root_reported) {
    PCCERT_CHAIN_CONTEXT c; PRES p;
    NEED_ENV();
    c = cp_chain_ex(cp_engine_empty(), C_CODE, 0, NULL, NULL, 0);
    if (!c) { t_skip("chain build failed"); return; }
    p = ac(c, 0, 0, 0, 0);
    CHECK(p.ret); EXPECT_EQ(p.err, CERR_UNTRUSTEDROOT); CHECK(p.ci == 0 && p.ei == 2);
    cp_free(c);
}
TEST(authenticode_untrusted_root_allowed_by_policy_flag) {
    PCCERT_CHAIN_CONTEXT c; PRES p;
    NEED_ENV();
    c = cp_chain_ex(cp_engine_empty(), C_CODE, 0, NULL, NULL, 0);
    if (!c) { t_skip("chain build failed"); return; }
    p = ac(c, CERT_CHAIN_POLICY_ALLOW_UNKNOWN_CA_FLAG, 0, 0, 0);
    CHECK(p.ret && p.err == 0);
    cp_free(c);
}
TEST(authenticode_expired_signer) {
    PCCERT_CHAIN_CONTEXT c; PRES p;
    NEED_ENV();
    c = cp_chain(C_EXPIRED);
    if (!c) { t_skip("chain build failed"); return; }
    p = ac(c, 0, 0, 0, 0);
    CHECK(p.ret); EXPECT_EQ(p.err, CERR_EXPIRED); CHECK(p.ci == 0 && p.ei == 0);
    cp_free(c);
}
TEST(authenticode_reg_setting_0x100_ignores_time) {
    PCCERT_CHAIN_CONTEXT c;
    NEED_ENV();
    c = cp_chain(C_EXPIRED);
    if (!c) { t_skip("chain build failed"); return; }
    CHECK(ac(c, 0, 0x100, 0, 0).err == 0);
    CHECK(ac(c, 0, 0x2, 0, 0).err == CERR_EXPIRED);
    CHECK(ac(c, 0, 0x10, 0, 0).err == CERR_EXPIRED);
    cp_free(c);
}
TEST(authenticode_policy_flag_ignores_time) {
    PCCERT_CHAIN_CONTEXT c;
    NEED_ENV();
    c = cp_chain(C_EXPIRED);
    if (!c) { t_skip("chain build failed"); return; }
    CHECK(ac(c, CERT_CHAIN_POLICY_IGNORE_NOT_TIME_VALID_FLAG, 0, 0, 0).err == 0);
    cp_free(c);
}
TEST(authenticode_nesting_always_ignored) {
    PRES p; REQUIRE(U(CertVerifyCertificateChainPolicy));
    p = syn_ac(0x2, 0, 0x2, 0, 0, 0);
    CHECK(p.ret && p.err == 0 && p.ci == -1 && p.ei == -1);
}
TEST(authenticode_ca_and_root_revocation_unknown_always_ignored) {
    SYN s; int n[1] = {3}; PRES p;
    REQUIRE(U(CertVerifyCertificateChainPolicy));
    syn_init(&s, 1, n); syn_ctx(&s, 0x40, 0);
    syn_el(&s, 0, 1, 0x40, 0); syn_rev(&s, 0, 1, CRYPTERR_NO_REVOCATION_CHECK);
    syn_el(&s, 0, 2, 0x40, 8); syn_rev(&s, 0, 2, CRYPTERR_REVOCATION_OFFLINE);
    p = ac(&s.cc, 0, 0, 0, 0);
    CHECK(p.ret && p.err == 0);
}
TEST(authenticode_revoked_maps_to_cert_e_revoked) {
    PRES p; REQUIRE(U(CertVerifyCertificateChainPolicy));
    p = syn_ac(0x4, 0, 0x4, 0, 0, 0);
    CHECK(p.ret); EXPECT_EQ(p.err, CERR_REVOKED); CHECK(p.ci == 0 && p.ei == 0);
}
TEST(authenticode_explicit_distrust_maps_to_cert_e_revoked) {
    PRES p; REQUIRE(U(CertVerifyCertificateChainPolicy));
    p = syn_ac(0x4000000, 1, 0x4000000, 0, 0, 0);
    CHECK(p.ret); EXPECT_EQ(p.err, CERR_REVOKED); CHECK(p.ci == 0 && p.ei == 1);
}
TEST(authenticode_revocation_codes_map_to_revocation_failure) {
    static const DWORD rc[] = {CRYPTERR_NO_REVOCATION_CHECK, CRYPTERR_REVOCATION_OFFLINE};
    REQUIRE(U(CertVerifyCertificateChainPolicy));
    for (unsigned i = 0; i < 2; i++) {
        PRES p = syn_ac(0x40, 0, 0x40, rc[i], 0, 0);
        CHECKF(p.ret && p.err == CERR_REVOCATION_FAIL && p.ci == 0 && p.ei == 0, "result 0x%lx -> 0x%lx", rc[i], p.err);
    }
}
TEST(authenticode_end_rev_unknown_ignored_by_reg_settings) {
    static const DWORD reg[] = {0x200, 0x400, 0x800, 0xC00};
    REQUIRE(U(CertVerifyCertificateChainPolicy));
    for (unsigned i = 0; i < 4; i++) {
        PRES p = syn_ac(0x40, 0, 0x40, CRYPTERR_NO_REVOCATION_CHECK, reg[i], 0);
        CHECKF(p.ret && p.err == 0 && p.ci == -1 && p.ei == -1, "reg 0x%lx -> 0x%lx", reg[i], p.err);
    }
    CHECK(syn_ac(0x40, 0, 0x40, CRYPTERR_NO_REVOCATION_CHECK, 0x1, 0).err == CERR_REVOCATION_FAIL);
}
TEST(authenticode_revoked_not_ignorable_by_reg_settings) {
    PRES p; REQUIRE(U(CertVerifyCertificateChainPolicy));
    p = syn_ac(0x4, 0, 0x4, 0, 0xFFFFFFFF, 0);
    CHECK(p.ret); EXPECT_EQ(p.err, CERR_REVOKED);
}
TEST(authenticode_reg_setting_0x100_ignores_ctl_and_nesting_not_chaining) {
    PRES a, b;
    REQUIRE(U(CertVerifyCertificateChainPolicy));
    a = syn_ac(0x1, 0, 0x1, 0, 0x100, 0);
    b = syn_ac(0x10000, -1, 0, 0, 0x100, 0);
    CHECK(a.ret && a.err == 0);
    CHECK(b.ret && b.err == CERR_CHAINING);
}
TEST(authenticode_signature_error_unchanged) {
    PRES p; REQUIRE(U(CertVerifyCertificateChainPolicy));
    p = syn_ac(0x8, 1, 0x8, 0, 0xFFFFFFFF, 0);
    CHECK(p.ret); EXPECT_EQ(p.err, TERR_CERT_SIGNATURE); CHECK(p.ci == 0 && p.ei == 1);
}
TEST(authenticode_basic_constraints_error_unchanged) {
    PRES p; REQUIRE(U(CertVerifyCertificateChainPolicy));
    p = syn_ac(0x400, 1, 0x400, 0, 0, 0);
    CHECK(p.ret); EXPECT_EQ(p.err, TERR_BASIC_CONSTRAINTS); CHECK(p.ci == 0 && p.ei == 1);
}
TEST(authenticode_basic_constraints_error_real_chain) {
    PCCERT_CHAIN_CONTEXT c; PRES p;
    NEED_ENV();
    c = cp_chain(C_UNDER_EE);
    if (!c) { t_skip("chain build failed"); return; }
    p = ac(c, 0, 0, 0, 0);
    CHECK(p.ret); CHECKF(p.err == TERR_BASIC_CONSTRAINTS, "got 0x%lx", p.err);
    cp_free(c);
}
TEST(authenticode_signer_info_requires_end_entity_leaf) {
    PCCERT_CHAIN_CONTEXT c; PRES p;
    NEED_ENV();
    c = cp_chain(C_CALEAF);
    if (!c) { t_skip("chain build failed"); return; }
    p = ac(c, 0, 0, 0, 0);
    CHECK(p.ret && p.err == 0);
    p = ac(c, 0, 0, 1, 0);
    CHECK(p.ret); CHECKF(p.err == TERR_BASIC_CONSTRAINTS, "got 0x%lx", p.err); CHECK(p.ci == 0 && p.ei == 0);
    cp_free(c);
}
TEST(authenticode_synthetic_chain_without_usage_skips_purpose) {
    SYN s; int n[1] = {3}; ACPARA e; PRES p;
    REQUIRE(U(CertVerifyCertificateChainPolicy));
    syn_init(&s, 1, n); syn_ctx(&s, 0x40, 0);
    syn_el(&s, 0, 0, 0x40, 0); syn_rev(&s, 0, 0, CRYPTERR_NO_REVOCATION_CHECK);
    memset(&e, 0, sizeof e); e.cb = sizeof e; e.signer = g_signer_dummy;
    /* synthetic chain elements carry no pApplicationUsage: purpose check passes, revocation failure stays */
    p = cp_run(CERT_CHAIN_POLICY_AUTHENTICODE, &s.cc, 0, &e);
    CHECK(p.ret); EXPECT_EQ(p.err, CERR_REVOCATION_FAIL);
}
TEST(authenticode_trusted_chain_status_fcommercial_reset) {
    PCCERT_CHAIN_CONTEXT c; ACPARA e; ACSTAT st; PRES p;
    NEED_ENV();
    c = cp_chain(C_CODE);
    if (!c) { t_skip("chain build failed"); return; }
    memset(&e, 0, sizeof e); e.cb = sizeof e;
    st.cb = sizeof st; st.commercial = 0x55;
    p = cp_run_ex(CERT_CHAIN_POLICY_AUTHENTICODE, c, sizeof(CERT_CHAIN_POLICY_PARA), 0, &e, sizeof(CERT_CHAIN_POLICY_STATUS), &st);
    CHECK(p.ret && p.err == 0); EXPECT_EQ(st.commercial, 0); EXPECT_EQ(st.cb, sizeof st);
    cp_free(c);
}
TEST(authenticode_status_extra_untouched_when_status_cbsize_small) {
    PCCERT_CHAIN_CONTEXT c; ACPARA e; ACSTAT st; PRES p;
    NEED_ENV();
    c = cp_chain(C_CODE);
    if (!c) { t_skip("chain build failed"); return; }
    memset(&e, 0, sizeof e); e.cb = sizeof e;
    st.cb = sizeof st; st.commercial = 0x55;
    p = cp_run_ex(CERT_CHAIN_POLICY_AUTHENTICODE, c, sizeof(CERT_CHAIN_POLICY_PARA), 0, &e, 0x10, &st);
    CHECK(p.ret && p.err == 0); EXPECT_EQ(st.commercial, 0x55);
    cp_free(c);
}
TEST(authenticode_status_extra_untouched_when_extra_cb_small) {
    PCCERT_CHAIN_CONTEXT c; ACPARA e; ACSTAT st; PRES p;
    NEED_ENV();
    c = cp_chain(C_CODE);
    if (!c) { t_skip("chain build failed"); return; }
    memset(&e, 0, sizeof e); e.cb = sizeof e;
    st.cb = 4; st.commercial = 0x55;
    p = cp_run_ex(CERT_CHAIN_POLICY_AUTHENTICODE, c, sizeof(CERT_CHAIN_POLICY_PARA), 0, &e, sizeof(CERT_CHAIN_POLICY_STATUS), &st);
    CHECK(p.ret && p.err == 0); EXPECT_EQ(st.commercial, 0x55);
    cp_free(c);
}
TEST(authenticode_status_extra_reset_even_on_error) {
    PCCERT_CHAIN_CONTEXT c; ACPARA e; ACSTAT st; PRES p;
    NEED_ENV();
    c = cp_chain(C_EXPIRED);
    if (!c) { t_skip("chain build failed"); return; }
    memset(&e, 0, sizeof e); e.cb = sizeof e;
    st.cb = sizeof st; st.commercial = 0x55;
    p = cp_run_ex(CERT_CHAIN_POLICY_AUTHENTICODE, c, sizeof(CERT_CHAIN_POLICY_PARA), 0, &e, sizeof(CERT_CHAIN_POLICY_STATUS), &st);
    CHECK(p.ret && p.err == CERR_EXPIRED); EXPECT_EQ(st.commercial, 0);
    cp_free(c);
}
TEST(authenticode_repeated_calls_stable) {
    PCCERT_CHAIN_CONTEXT c;
    NEED_ENV();
    c = cp_chain(C_CODE);
    if (!c) { t_skip("chain build failed"); return; }
    for (int i = 0; i < 50; i++) { PRES p = ac(c, 0, 0, 1, 0); if (!p.ret || p.err) { CHECKF(0, "iter %d err 0x%lx", i, p.err); break; } }
    cp_free(c);
}

/* ---------- AUTHENTICODE_TS ---------- */
TEST(authenticode_ts_trusted_chain_ok) {
    static const int leaves[] = {C_CODE, C_SRV, C_EMAIL, C_NOEKU};
    NEED_ENV();
    for (unsigned i = 0; i < 4; i++) {
        PCCERT_CHAIN_CONTEXT c = cp_chain(leaves[i]); PRES p;
        if (!c) { t_skip("chain build failed"); return; }
        p = cp_run(CERT_CHAIN_POLICY_AUTHENTICODE_TS, c, 0, NULL);
        CHECKF(p.ret && p.err == 0 && p.ci == -1 && p.ei == -1, "leaf %d: 0x%lx", leaves[i], p.err);
        cp_free(c);
    }
}
TEST(authenticode_ts_untrusted_root) {
    PCCERT_CHAIN_CONTEXT c; PRES p;
    NEED_ENV();
    c = cp_chain_ex(cp_engine_empty(), C_SRV, 0, NULL, NULL, 0);
    if (!c) { t_skip("chain build failed"); return; }
    p = ts(c, 0, 0);
    CHECK(p.ret); EXPECT_EQ(p.err, CERR_UNTRUSTEDROOT); CHECK(p.ci == 0 && p.ei == 2);
    cp_free(c);
}
TEST(authenticode_ts_expired) {
    PCCERT_CHAIN_CONTEXT c; PRES p;
    NEED_ENV();
    c = cp_chain(C_EXPIRED);
    if (!c) { t_skip("chain build failed"); return; }
    p = ts(c, 0, 0);
    CHECK(p.ret); EXPECT_EQ(p.err, CERR_EXPIRED); CHECK(p.ci == 0 && p.ei == 0);
    CHECK(ts(c, 0, 0x100).err == 0);
    cp_free(c);
}
TEST(authenticode_ts_basic_constraints_not_rechecked_for_leaf) {
    PCCERT_CHAIN_CONTEXT c; PRES p;
    NEED_ENV();
    c = cp_chain(C_CALEAF);
    if (!c) { t_skip("chain build failed"); return; }
    p = ts(c, 0, 0);
    CHECK(p.ret && p.err == 0);
    cp_free(c);
}
TEST(authenticode_ts_revoked_maps_to_cert_e_revoked) {
    PRES p; REQUIRE(U(CertVerifyCertificateChainPolicy));
    p = syn_ac(0x4, 0, 0x4, 0, 0, 1);
    CHECK(p.ret); EXPECT_EQ(p.err, CERR_REVOKED); CHECK(p.ci == 0 && p.ei == 0);
}
TEST(authenticode_ts_revocation_codes_map_to_revocation_failure) {
    static const DWORD rc[] = {CRYPTERR_NO_REVOCATION_CHECK, CRYPTERR_REVOCATION_OFFLINE, 0x80092011u, 0x80092014u};
    REQUIRE(U(CertVerifyCertificateChainPolicy));
    for (unsigned i = 0; i < 4; i++) {
        PRES p = syn_ac(0x40, 0, 0x40, rc[i], 0, 1);
        CHECKF(p.ret && p.err == CERR_REVOCATION_FAIL && p.ci == 0 && p.ei == 0, "result 0x%lx -> 0x%lx", rc[i], p.err);
    }
}
TEST(authenticode_ts_rev_unknown_reg_bits) {
    REQUIRE(U(CertVerifyCertificateChainPolicy));
    CHECK(syn_ac(0x40, 0, 0x40, CRYPTERR_NO_REVOCATION_CHECK, 0x400, 1).err == 0);
    CHECK(syn_ac(0x40, 0, 0x40, CRYPTERR_NO_REVOCATION_CHECK, 0x800, 1).err == 0);
    CHECK(syn_ac(0x40, 0, 0x40, CRYPTERR_NO_REVOCATION_CHECK, 0x20000, 1).err == 0);
    CHECK(syn_ac(0x40, 0, 0x40, CRYPTERR_NO_REVOCATION_CHECK, 0x200, 1).err == CERR_REVOCATION_FAIL);   /* 0x200 is the plain-authenticode bit */
    CHECK(syn_ac(0x40, 0, 0x40, CRYPTERR_NO_REVOCATION_CHECK, 0, 1).err == CERR_REVOCATION_FAIL);
}
TEST(authenticode_ts_all_rev_unknown_bit_differs_from_authenticode) {
    REQUIRE(U(CertVerifyCertificateChainPolicy));
    /* plain: bit 9 means all revocation-unknown ignored; TS: bit 17 does */
    CHECK(syn_ac(0x40, 0, 0x40, CRYPTERR_NO_REVOCATION_CHECK, 0x200, 0).err == 0);
    CHECK(syn_ac(0x40, 0, 0x40, CRYPTERR_NO_REVOCATION_CHECK, 0x20000, 0).err == CERR_REVOCATION_FAIL);
}
TEST(authenticode_ts_extra_cbsize_gates_settings) {
    PCCERT_CHAIN_CONTEXT c;
    NEED_ENV();
    c = cp_chain(C_EXPIRED);
    if (!c) { t_skip("chain build failed"); return; }
    {
        static const struct { DWORD cb; DWORD want; } t[] = {{4, CERR_EXPIRED}, {5, 0}, {8, 0}, {12, 0}};
        for (unsigned i = 0; i < 4; i++) {
            TSPARA e; PRES p;
            memset(&e, 0, sizeof e); e.cb = t[i].cb; e.reg = 0x100;
            p = cp_run(CERT_CHAIN_POLICY_AUTHENTICODE_TS, c, 0, &e);
            CHECKF(p.ret && p.err == t[i].want, "extra cbSize %lu: 0x%lx", t[i].cb, p.err);
        }
    }
    cp_free(c);
}
TEST(authenticode_ts_signature_error_unchanged) {
    PRES p; REQUIRE(U(CertVerifyCertificateChainPolicy));
    p = syn_ac(0x8, 1, 0x8, 0, 0, 1);
    CHECK(p.ret); EXPECT_EQ(p.err, TERR_CERT_SIGNATURE); CHECK(p.ci == 0 && p.ei == 1);
}
TEST(authenticode_ts_does_not_touch_extra_status) {
    PCCERT_CHAIN_CONTEXT c; ACSTAT st; TSPARA e; PRES p;
    NEED_ENV();
    c = cp_chain(C_CODE);
    if (!c) { t_skip("chain build failed"); return; }
    memset(&e, 0, sizeof e); e.cb = sizeof e;
    st.cb = sizeof st; st.commercial = 0x55;
    p = cp_run_ex(CERT_CHAIN_POLICY_AUTHENTICODE_TS, c, sizeof(CERT_CHAIN_POLICY_PARA), 0, &e, sizeof(CERT_CHAIN_POLICY_STATUS), &st);
    CHECK(p.ret && p.err == 0); EXPECT_EQ(st.commercial, 0x55);
    cp_free(c);
}
