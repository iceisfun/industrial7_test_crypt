/* CertVerifyCertificateChainPolicy dispatch: policy OID lookup, status initialisation, cbSize rules. */
#include "cp.h"

static const struct { LPCSTR oid; const char *name; } g_pol[] = {
    {CERT_CHAIN_POLICY_BASE, "BASE"}, {CERT_CHAIN_POLICY_AUTHENTICODE, "AUTHENTICODE"},
    {CERT_CHAIN_POLICY_AUTHENTICODE_TS, "AUTHENTICODE_TS"}, {CERT_CHAIN_POLICY_SSL, "SSL"},
    {CERT_CHAIN_POLICY_BASIC_CONSTRAINTS, "BASIC_CONSTRAINTS"}, {CERT_CHAIN_POLICY_NT_AUTH, "NT_AUTH"},
    {CERT_CHAIN_POLICY_MICROSOFT_ROOT, "MICROSOFT_ROOT"}, {CERT_CHAIN_POLICY_EV, "EV"},
    {CERT_CHAIN_POLICY_THIRD_PARTY_ROOT, "THIRD_PARTY_ROOT"}, };

TEST(dispatch_policy_ids_are_small_integers) {
    CHECK((ULONG_PTR)CERT_CHAIN_POLICY_BASE == 1);
    CHECK((ULONG_PTR)CERT_CHAIN_POLICY_AUTHENTICODE == 2);
    CHECK((ULONG_PTR)CERT_CHAIN_POLICY_AUTHENTICODE_TS == 3);
    CHECK((ULONG_PTR)CERT_CHAIN_POLICY_SSL == 4);
    CHECK((ULONG_PTR)CERT_CHAIN_POLICY_BASIC_CONSTRAINTS == 5);
    CHECK((ULONG_PTR)CERT_CHAIN_POLICY_NT_AUTH == 6);
    CHECK((ULONG_PTR)CERT_CHAIN_POLICY_MICROSOFT_ROOT == 7);
    CHECK((ULONG_PTR)CERT_CHAIN_POLICY_EV == 8);
    CHECK((ULONG_PTR)CERT_CHAIN_POLICY_THIRD_PARTY_ROOT == 11);
}

TEST(dispatch_builtin_policies_return_true) {
    PCCERT_CHAIN_CONTEXT c;
    NEED_ENV();
    c = cp_chain(C_SRV);
    if (!c) { t_skip("chain build failed"); return; }
    for (unsigned i = 0; i < sizeof g_pol / sizeof g_pol[0]; i++) {
        PRES p = cp_run(g_pol[i].oid, c, 0, NULL);
        CHECKF(p.ret, "policy %s returned FALSE (gle=%lu)", g_pol[i].name, p.gle);
    }
    cp_free(c);
}

TEST(dispatch_unsupported_integer_oids_fail) {
    static const ULONG_PTR ids[] = {0, 13, 14, 15, 100, 0x7FFF, 0xFFFF};
    PCCERT_CHAIN_CONTEXT c;
    NEED_ENV();
    c = cp_chain(C_SRV);
    if (!c) { t_skip("chain build failed"); return; }
    for (unsigned i = 0; i < sizeof ids / sizeof ids[0]; i++) {
        PRES p = cp_run((LPCSTR)ids[i], c, 0, NULL);
        CHECKF(!p.ret, "oid %lu unexpectedly supported", (unsigned long)ids[i]);
        CHECKF(p.gle == ERROR_FILE_NOT_FOUND, "oid %lu: GetLastError %lu", (unsigned long)ids[i], p.gle);
        CHECK(p.err == 0 && p.ci == -1 && p.ei == -1);
    }
    cp_free(c);
}

TEST(dispatch_unsupported_string_oids_fail) {
    static const char *s[] = {"", "1.2.3.4.5", "1.3.6.1.5.5.7.3.1", "CERT_CHAIN_POLICY_BASE", "1", "BASE", "2.5.29.15", "#0", "#13", "#abc", "#"};
    PCCERT_CHAIN_CONTEXT c;
    NEED_ENV();
    c = cp_chain(C_SRV);
    if (!c) { t_skip("chain build failed"); return; }
    for (unsigned i = 0; i < sizeof s / sizeof s[0]; i++) {
        PRES p = cp_run(s[i], c, 0, NULL);
        CHECKF(!p.ret, "oid \"%s\" unexpectedly supported", s[i]);
        CHECKF(p.gle == ERROR_FILE_NOT_FOUND, "oid \"%s\": GetLastError %lu", s[i], p.gle);
        CHECK(p.err == 0 && p.ci == -1 && p.ei == -1);
    }
    cp_free(c);
}

TEST(dispatch_hash_prefixed_oids_select_builtin_policies) {
    PCCERT_CHAIN_CONTEXT c;
    NEED_ENV();
    c = cp_chain_ex(cp_engine_empty(), C_SRV, 0, NULL, NULL, 0);     /* untrusted root */
    if (!c) { t_skip("chain build failed"); return; }
    for (int id = 1; id <= 8; id++) {
        char buf[8]; PRES a, b;
        sprintf(buf, "#%d", id);
        a = cp_run((LPCSTR)(ULONG_PTR)id, c, 0, NULL);
        b = cp_run(buf, c, 0, NULL);
        CHECKF(b.ret == a.ret && b.err == a.err && b.ci == a.ci && b.ei == a.ei, "\"%s\" differs from integer oid: %lx/%lx", buf, b.err, a.err);
    }
    cp_free(c);
}

TEST(dispatch_hash_oid_beyond_16_bits_is_invalid_parameter) {
    static const char *s[] = {"#65536", "#65537", "#99999999", "#-1", "#4294967295"};
    PCCERT_CHAIN_CONTEXT c;
    NEED_ENV();
    c = cp_chain(C_SRV);
    if (!c) { t_skip("chain build failed"); return; }
    for (unsigned i = 0; i < sizeof s / sizeof s[0]; i++) {
        PRES p = cp_run(s[i], c, 0, NULL);
        CHECKF(!p.ret, "\"%s\" unexpectedly supported", s[i]);
        CHECKF(p.gle == EINVALIDARG_HR, "\"%s\": GetLastError 0x%lx", s[i], p.gle);
    }
    cp_free(c);
}

TEST(dispatch_status_reset_before_policy_runs) {
    PCCERT_CHAIN_CONTEXT c; PRES p;
    NEED_ENV();
    c = cp_chain(C_SRV);
    if (!c) { t_skip("chain build failed"); return; }
    p = cp_run(CERT_CHAIN_POLICY_BASE, c, 0, NULL);
    CHECK(p.ret); EXPECT_EQ(p.err, 0); CHECK(p.ci == -1); CHECK(p.ei == -1);
    cp_free(c);
}

TEST(dispatch_status_untouched_cbsize) {
    PCCERT_CHAIN_CONTEXT c; PRES p;
    NEED_ENV();
    c = cp_chain(C_SRV);
    if (!c) { t_skip("chain build failed"); return; }
    p = cp_run_ex(CERT_CHAIN_POLICY_BASE, c, sizeof(CERT_CHAIN_POLICY_PARA), 0, NULL, 0x1234, NULL);
    CHECK(p.ret); EXPECT_EQ(p.ssz, 0x1234); EXPECT_EQ(p.err, 0); CHECK(p.ci == -1);
    cp_free(c);
}

TEST(dispatch_status_cbsize_not_validated_for_base) {
    static const DWORD sz[] = {0, 1, 4, 8, 16, 0x18, 0x100};
    PCCERT_CHAIN_CONTEXT c;
    NEED_ENV();
    c = cp_chain_ex(cp_engine_empty(), C_SRV, 0, NULL, NULL, 0);
    if (!c) { t_skip("chain build failed"); return; }
    for (unsigned i = 0; i < sizeof sz / sizeof sz[0]; i++) {
        PRES p = cp_run_ex(CERT_CHAIN_POLICY_BASE, c, sizeof(CERT_CHAIN_POLICY_PARA), 0, NULL, sz[i], NULL);
        CHECKF(p.ret && p.err == CERR_UNTRUSTEDROOT, "status cbSize %lu: ret=%d err=0x%lx", sz[i], p.ret, p.err);
    }
    cp_free(c);
}

TEST(dispatch_null_policy_para_allowed) {
    PCCERT_CHAIN_CONTEXT c;
    CERT_CHAIN_POLICY_STATUS s;
    NEED_ENV();
    c = cp_chain(C_SRV);
    if (!c) { t_skip("chain build failed"); return; }
    for (unsigned i = 0; i < sizeof g_pol / sizeof g_pol[0]; i++) {
        BOOL r;
        memset(&s, 0, sizeof s); s.cbSize = sizeof s;
        r = U(CertVerifyCertificateChainPolicy)(g_pol[i].oid, c, NULL, &s);
        CHECKF(r, "policy %s with NULL para failed", g_pol[i].name);
    }
    cp_free(c);
}

/* policy-para cbSize gates dwFlags: flags are only read when cbSize > 4 */
TEST(dispatch_para_cbsize_gates_flags) {
    PCCERT_CHAIN_CONTEXT c;
    NEED_ENV();
    c = cp_chain_ex(cp_engine_empty(), C_SRV, 0, NULL, NULL, 0);
    if (!c) { t_skip("chain build failed"); return; }
    static const struct { DWORD cb; DWORD want; } t[] = {
        {0, CERR_UNTRUSTEDROOT}, {1, CERR_UNTRUSTEDROOT}, {4, CERR_UNTRUSTEDROOT}, {5, 0}, {8, 0},
        {12, 0}, {16, 0}, {0x100, 0}, };
    for (unsigned i = 0; i < sizeof t / sizeof t[0]; i++) {
        PRES p = cp_run_ex(CERT_CHAIN_POLICY_BASE, c, t[i].cb, CERT_CHAIN_POLICY_ALLOW_UNKNOWN_CA_FLAG, NULL, sizeof(CERT_CHAIN_POLICY_STATUS), NULL);
        CHECKF(p.ret && p.err == t[i].want, "para cbSize %lu: ret=%d err=0x%lx want 0x%lx", t[i].cb, p.ret, p.err, t[i].want);
    }
    cp_free(c);
}

TEST(dispatch_para_cbsize_gates_flags_basic_constraints) {
    PCCERT_CHAIN_CONTEXT c; PRES a, b;
    NEED_ENV();
    c = cp_chain(C_SRV);          /* end entity: CA flag must fail when honoured */
    if (!c) { t_skip("chain build failed"); return; }
    a = cp_run_ex(CERT_CHAIN_POLICY_BASIC_CONSTRAINTS, c, 4, BASIC_CONSTRAINTS_CERT_CHAIN_POLICY_CA_FLAG, NULL, sizeof(CERT_CHAIN_POLICY_STATUS), NULL);
    b = cp_run_ex(CERT_CHAIN_POLICY_BASIC_CONSTRAINTS, c, 5, BASIC_CONSTRAINTS_CERT_CHAIN_POLICY_CA_FLAG, NULL, sizeof(CERT_CHAIN_POLICY_STATUS), NULL);
    CHECK(a.ret && a.err == 0);
    CHECK(b.ret && b.err == TERR_BASIC_CONSTRAINTS);
    cp_free(c);
}

TEST(dispatch_extra_policy_para_ignored_by_base) {
    PCCERT_CHAIN_CONTEXT c; DWORD junk[4] = {16, 0xFFFFFFFF, 0xFFFFFFFF, 0}; PRES a, b;
    NEED_ENV();
    c = cp_chain_ex(cp_engine_empty(), C_SRV, 0, NULL, NULL, 0);
    if (!c) { t_skip("chain build failed"); return; }
    a = cp_run(CERT_CHAIN_POLICY_BASE, c, 0, NULL);
    b = cp_run(CERT_CHAIN_POLICY_BASE, c, 0, junk);
    CHECK(a.ret && b.ret && a.err == b.err && a.ci == b.ci && a.ei == b.ei);
    cp_free(c);
}

TEST(dispatch_nonzero_dwerror_still_returns_true) {
    PCCERT_CHAIN_CONTEXT c; PRES p;
    NEED_ENV();
    c = cp_chain_ex(cp_engine_empty(), C_SRV, 0, NULL, NULL, 0);
    if (!c) { t_skip("chain build failed"); return; }
    p = cp_run(CERT_CHAIN_POLICY_BASE, c, 0, NULL);
    CHECK(p.ret); EXPECT_EQ(p.err, CERR_UNTRUSTEDROOT);
    cp_free(c);
}

TEST(dispatch_repeatable_results) {
    PCCERT_CHAIN_CONTEXT c; PRES f;
    NEED_ENV();
    c = cp_chain_ex(cp_engine_empty(), C_SRV, 0, NULL, NULL, 0);
    if (!c) { t_skip("chain build failed"); return; }
    f = cp_run(CERT_CHAIN_POLICY_BASE, c, 0, NULL);
    for (int i = 0; i < 20; i++) {
        PRES p = cp_run(CERT_CHAIN_POLICY_BASE, c, 0, NULL);
        CHECK(p.ret == f.ret && p.err == f.err && p.ci == f.ci && p.ei == f.ei);
    }
    cp_free(c);
}

TEST(dispatch_chain_context_not_modified) {
    PCCERT_CHAIN_CONTEXT c; DWORD e0, i0, n0;
    NEED_ENV();
    c = cp_chain_ex(cp_engine_empty(), C_SRV, 0, NULL, NULL, 0);
    if (!c) { t_skip("chain build failed"); return; }
    e0 = c->TrustStatus.dwErrorStatus; i0 = c->TrustStatus.dwInfoStatus; n0 = c->cChain;
    for (unsigned i = 0; i < sizeof g_pol / sizeof g_pol[0]; i++) (void)cp_run(g_pol[i].oid, c, 0, NULL);
    CHECK(c->TrustStatus.dwErrorStatus == e0 && c->TrustStatus.dwInfoStatus == i0 && c->cChain == n0);
    cp_free(c);
}

TEST(dispatch_policy_ids_are_distinct_policies) {
    PCCERT_CHAIN_CONTEXT c; PRES base, bc, ms;
    NEED_ENV();
    c = cp_chain_ex(cp_engine_empty(), C_SRV, 0, NULL, NULL, 0);
    if (!c) { t_skip("chain build failed"); return; }
    base = cp_run(CERT_CHAIN_POLICY_BASE, c, 0, NULL);
    bc = cp_run(CERT_CHAIN_POLICY_BASIC_CONSTRAINTS, c, 0, NULL);
    ms = cp_run(CERT_CHAIN_POLICY_MICROSOFT_ROOT, c, 0, NULL);
    CHECK(base.err == CERR_UNTRUSTEDROOT);
    CHECK(bc.err == 0);                       /* BC policy ignores the untrusted root */
    CHECK(ms.err == CERR_UNTRUSTEDROOT);
    cp_free(c);
}

/* ---- concurrent callers on one chain context ---- */
typedef struct { PCCERT_CHAIN_CONTEXT c; volatile LONG bad; } THR;
static DWORD WINAPI thr_main(LPVOID a) {
    THR *t = a;
    for (int i = 0; i < 100; i++) {
        PRES p = cp_run(CERT_CHAIN_POLICY_BASE, t->c, 0, NULL);
        if (!p.ret || p.err != CERR_UNTRUSTEDROOT || p.ci != 0) InterlockedIncrement(&t->bad);
        p = cp_run(CERT_CHAIN_POLICY_BASE, t->c, CERT_CHAIN_POLICY_ALLOW_UNKNOWN_CA_FLAG, NULL);
        if (!p.ret || p.err != 0) InterlockedIncrement(&t->bad);
    }
    return 0;
}
TEST(dispatch_concurrent_calls_same_chain) {
    THR t; HANDLE h[4]; int n = 0;
    NEED_ENV();
    t.c = cp_chain_ex(cp_engine_empty(), C_SRV, 0, NULL, NULL, 0); t.bad = 0;
    if (!t.c) { t_skip("chain build failed"); return; }
    for (int i = 0; i < 4; i++) { h[n] = CreateThread(NULL, 0, thr_main, &t, 0, NULL); if (h[n]) n++; }
    if (n) CHECK(WaitForMultipleObjects(n, h, TRUE, 20000) == WAIT_OBJECT_0);
    for (int i = 0; i < n; i++) CloseHandle(h[i]);
    EXPECT_EQ(t.bad, 0);
    cp_free(t.c);
}

/* ---- chain-flag interplay: policy sees what the chain build recorded ---- */
TEST(dispatch_chain_built_without_revocation_has_no_rev_unknown) {
    PCCERT_CHAIN_CONTEXT c; PRES p;
    NEED_ENV();
    c = cp_chain(C_SRV);
    if (!c) { t_skip("chain build failed"); return; }
    CHECK((c->TrustStatus.dwErrorStatus & CERT_TRUST_REVOCATION_STATUS_UNKNOWN) == 0);
    p = cp_run(CERT_CHAIN_POLICY_BASE, c, 0, NULL);
    CHECK(p.ret && p.err == 0 && p.ci == -1 && p.ei == -1);
    cp_free(c);
}
