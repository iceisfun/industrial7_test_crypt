/* Parameter validation of the SSL_F12 (9), SSL_HPKP_HEADER (10) and SSL_KEY_PIN (12) policies.
 * Only the rejection paths are exercised: they fail before the chain or the network are touched. */
#include "cp.h"

#define POL_F12   ((LPCSTR)(ULONG_PTR)9)
#define POL_HPKP  ((LPCSTR)(ULONG_PTR)10)
#define POL_PIN   ((LPCSTR)(ULONG_PTR)12)

typedef struct { DWORD cb; DWORD rsv; void *p1; void *p2; DWORD pad[4]; } XPARA;      /* 0x30 bytes, fields read at +8 / +16 */
typedef struct { DWORD cb; BYTE body[0x420]; } XSTAT;

static void expect_reject(LPCSTR oid, PCCERT_CHAIN_CONTEXT c, DWORD pcb, void *ep, DWORD scb, void *es, const char *what) {
    PRES p = cp_run_ex(oid, c, pcb, 0, ep, scb, es);
    CHECKF(!p.ret, "%s: returned TRUE", what);
    CHECKF(p.gle == ERROR_INVALID_PARAMETER, "%s: GetLastError %lu", what, p.gle);
    CHECKF(p.err == 0 && p.ci == -1 && p.ei == -1, "%s: status 0x%lx %ld %ld", what, p.err, p.ci, p.ei);
}

TEST(pcheck_f12_without_extra_status_rejected) {
    PCCERT_CHAIN_CONTEXT c;
    NEED_ENV();
    c = cp_chain(C_SRV);
    if (!c) { t_skip("chain build failed"); return; }
    expect_reject(POL_F12, c, sizeof(CERT_CHAIN_POLICY_PARA), NULL, sizeof(CERT_CHAIN_POLICY_STATUS), NULL, "no extra status");
    cp_free(c);
}
TEST(pcheck_f12_extra_status_too_small_rejected) {
    PCCERT_CHAIN_CONTEXT c; XSTAT es;
    NEED_ENV();
    c = cp_chain(C_SRV);
    if (!c) { t_skip("chain build failed"); return; }
    memset(&es, 0, sizeof es);
    es.cb = 0x20F;     /* minimum is sizeof(SSL_F12_EXTRA_CERT_CHAIN_POLICY_STATUS) == 0x210 */
    expect_reject(POL_F12, c, sizeof(CERT_CHAIN_POLICY_PARA), NULL, sizeof(CERT_CHAIN_POLICY_STATUS), &es, "extra cb 0x20f");
    es.cb = 0;
    expect_reject(POL_F12, c, sizeof(CERT_CHAIN_POLICY_PARA), NULL, sizeof(CERT_CHAIN_POLICY_STATUS), &es, "extra cb 0");
    cp_free(c);
}
TEST(pcheck_f12_status_cbsize_must_exceed_16) {
    PCCERT_CHAIN_CONTEXT c; XSTAT es;
    NEED_ENV();
    c = cp_chain(C_SRV);
    if (!c) { t_skip("chain build failed"); return; }
    memset(&es, 0, sizeof es); es.cb = 0x210;
    expect_reject(POL_F12, c, sizeof(CERT_CHAIN_POLICY_PARA), NULL, 16, &es, "status cbSize 16");
    expect_reject(POL_F12, c, sizeof(CERT_CHAIN_POLICY_PARA), NULL, 0, &es, "status cbSize 0");
    cp_free(c);
}
TEST(pcheck_f12_is_a_registered_policy) {
    /* a registered policy reports ERROR_INVALID_PARAMETER, an unknown id reports ERROR_FILE_NOT_FOUND */
    PCCERT_CHAIN_CONTEXT c; PRES a, b;
    NEED_ENV();
    c = cp_chain(C_SRV);
    if (!c) { t_skip("chain build failed"); return; }
    a = cp_run(POL_F12, c, 0, NULL);
    b = cp_run((LPCSTR)(ULONG_PTR)13, c, 0, NULL);
    CHECK(!a.ret && a.gle == ERROR_INVALID_PARAMETER);
    CHECK(!b.ret && b.gle == ERROR_FILE_NOT_FOUND);
    cp_free(c);
}

TEST(pcheck_hpkp_null_para_rejected) {
    PCCERT_CHAIN_CONTEXT c; CERT_CHAIN_POLICY_STATUS s; BOOL r;
    NEED_ENV();
    c = cp_chain(C_SRV);
    if (!c) { t_skip("chain build failed"); return; }
    memset(&s, 0, sizeof s); s.cbSize = sizeof s;
    SetLastError(0);
    r = U(CertVerifyCertificateChainPolicy)(POL_HPKP, c, NULL, &s);
    CHECK(!r); EXPECT_EQ(GetLastError(), ERROR_INVALID_PARAMETER);
    CHECK(s.dwError == 0 && s.lChainIndex == -1 && s.lElementIndex == -1);
    cp_free(c);
}
TEST(pcheck_hpkp_no_extra_para_rejected) {
    PCCERT_CHAIN_CONTEXT c;
    NEED_ENV();
    c = cp_chain(C_SRV);
    if (!c) { t_skip("chain build failed"); return; }
    expect_reject(POL_HPKP, c, sizeof(CERT_CHAIN_POLICY_PARA), NULL, sizeof(CERT_CHAIN_POLICY_STATUS), NULL, "NULL extra");
    cp_free(c);
}
TEST(pcheck_hpkp_extra_para_too_small_rejected) {
    PCCERT_CHAIN_CONTEXT c; XPARA xp;
    NEED_ENV();
    c = cp_chain(C_SRV);
    if (!c) { t_skip("chain build failed"); return; }
    memset(&xp, 0, sizeof xp);
    xp.cb = 0x1F;      /* minimum 0x20 */
    expect_reject(POL_HPKP, c, sizeof(CERT_CHAIN_POLICY_PARA), &xp, sizeof(CERT_CHAIN_POLICY_STATUS), NULL, "extra cb 0x1f");
    xp.cb = 0;
    expect_reject(POL_HPKP, c, sizeof(CERT_CHAIN_POLICY_PARA), &xp, sizeof(CERT_CHAIN_POLICY_STATUS), NULL, "extra cb 0");
    cp_free(c);
}
TEST(pcheck_hpkp_para_cbsize_gates_extra) {
    PCCERT_CHAIN_CONTEXT c; XPARA xp;
    NEED_ENV();
    c = cp_chain(C_SRV);
    if (!c) { t_skip("chain build failed"); return; }
    memset(&xp, 0, sizeof xp); xp.cb = 0x30;
    expect_reject(POL_HPKP, c, 8, &xp, sizeof(CERT_CHAIN_POLICY_STATUS), NULL, "para cbSize 8 hides the extra para");
    expect_reject(POL_HPKP, c, 0, &xp, sizeof(CERT_CHAIN_POLICY_STATUS), NULL, "para cbSize 0");
    cp_free(c);
}

TEST(pcheck_keypin_no_extra_rejected) {
    PCCERT_CHAIN_CONTEXT c;
    NEED_ENV();
    c = cp_chain(C_SRV);
    if (!c) { t_skip("chain build failed"); return; }
    expect_reject(POL_PIN, c, sizeof(CERT_CHAIN_POLICY_PARA), NULL, sizeof(CERT_CHAIN_POLICY_STATUS), NULL, "no extras");
    cp_free(c);
}
TEST(pcheck_keypin_missing_server_name_rejected) {
    PCCERT_CHAIN_CONTEXT c; XPARA xp; XSTAT es; static const WCHAR empty[1] = {0};
    NEED_ENV();
    c = cp_chain(C_SRV);
    if (!c) { t_skip("chain build failed"); return; }
    memset(&xp, 0, sizeof xp); xp.cb = 0x20; xp.p1 = NULL;
    memset(&es, 0, sizeof es); es.cb = 0x408;
    expect_reject(POL_PIN, c, sizeof(CERT_CHAIN_POLICY_PARA), &xp, sizeof(CERT_CHAIN_POLICY_STATUS), &es, "NULL server name");
    xp.p1 = (void *)empty;
    expect_reject(POL_PIN, c, sizeof(CERT_CHAIN_POLICY_PARA), &xp, sizeof(CERT_CHAIN_POLICY_STATUS), &es, "empty server name");
    cp_free(c);
}
TEST(pcheck_keypin_extra_cb_gates_server_name) {
    PCCERT_CHAIN_CONTEXT c; XPARA xp; XSTAT es; static const WCHAR nm[] = L"pin.example.test";
    NEED_ENV();
    c = cp_chain(C_SRV);
    if (!c) { t_skip("chain build failed"); return; }
    memset(&xp, 0, sizeof xp); xp.cb = 8; xp.p1 = (void *)nm;     /* cb must be > 8 */
    memset(&es, 0, sizeof es); es.cb = 0x408;
    expect_reject(POL_PIN, c, sizeof(CERT_CHAIN_POLICY_PARA), &xp, sizeof(CERT_CHAIN_POLICY_STATUS), &es, "extra para cb 8");
    cp_free(c);
}
TEST(pcheck_keypin_status_extra_too_small_rejected) {
    PCCERT_CHAIN_CONTEXT c; XPARA xp; XSTAT es; static const WCHAR nm[] = L"pin.example.test";
    NEED_ENV();
    c = cp_chain(C_SRV);
    if (!c) { t_skip("chain build failed"); return; }
    memset(&xp, 0, sizeof xp); xp.cb = 0x20; xp.p1 = (void *)nm;
    memset(&es, 0, sizeof es); es.cb = 0x407;                      /* minimum 0x408 */
    expect_reject(POL_PIN, c, sizeof(CERT_CHAIN_POLICY_PARA), &xp, sizeof(CERT_CHAIN_POLICY_STATUS), &es, "status extra cb 0x407");
    es.cb = 0x408;
    expect_reject(POL_PIN, c, sizeof(CERT_CHAIN_POLICY_PARA), &xp, 16, &es, "status cbSize 16 hides the extra status");
    cp_free(c);
}
