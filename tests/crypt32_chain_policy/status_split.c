/* Chain TrustStatus (build result) recorded separately from the policy result: a TRUE return from
 * CertVerifyCertificateChainPolicy means the policy ran; the verdict is in dwError/lChainIndex/lElementIndex. */
#include "cp.h"

static void split(PCCERT_CHAIN_CONTEXT c, DWORD cerr, DWORD cinfo, DWORD perr, LONG pci, LONG pei) {
    PRES p;
    CHECKF(c->TrustStatus.dwErrorStatus == cerr, "chain dwErrorStatus 0x%lx want 0x%lx", c->TrustStatus.dwErrorStatus, cerr);
    CHECKF(c->TrustStatus.dwInfoStatus == cinfo, "chain dwInfoStatus 0x%lx want 0x%lx", c->TrustStatus.dwInfoStatus, cinfo);
    p = cp_run(CERT_CHAIN_POLICY_BASE, c, 0, NULL);
    CHECKF(p.ret == TRUE, "policy BOOL %d", p.ret);
    CHECKF(p.err == perr, "policy dwError 0x%lx want 0x%lx", p.err, perr);
    CHECKF(p.ci == pci && p.ei == pei, "policy index %ld/%ld want %ld/%ld", (long)p.ci, (long)p.ei, (long)pci, (long)pei);
}

TEST(status_split_good_chain) {
    PCCERT_CHAIN_CONTEXT c;
    NEED_ENV();
    c = cp_chain(C_SRV);
    REQUIRE_NOTNULL(c);
    split(c, 0, 0x2100, 0, -1, -1);
    cp_free(c);
}
TEST(status_split_expired_leaf) {
    PCCERT_CHAIN_CONTEXT c;
    NEED_ENV();
    c = cp_chain(C_EXPIRED);
    REQUIRE_NOTNULL(c);
    split(c, 0x1, 0x2100, 0x800B0101, 0, 0);
    cp_free(c);
}
TEST(status_split_missing_intermediate_cache_only) {
    PCCERT_CHAIN_CONTEXT c;
    NEED_ENV();
    c = cp_chain(C_ORPHAN);
    REQUIRE_NOTNULL(c);
    split(c, 0x10000, 0, 0x800B010A, 0, -1);
    cp_free(c);
}
TEST(status_split_revocation_requested_without_evidence) {
    PCCERT_CHAIN_CONTEXT c;
    NEED_ENV();
    c = cp_chain_ex(NULL, C_SRV, CERT_CHAIN_REVOCATION_CHECK_CHAIN | CERT_CHAIN_REVOCATION_CHECK_CACHE_ONLY, NULL, NULL, 0);
    REQUIRE_NOTNULL(c);
    split(c, 0x40, 0x2100, 0x80092012, 0, 0);       /* no revocation check possible: distinct from the good verdict */
    cp_free(c);
}
