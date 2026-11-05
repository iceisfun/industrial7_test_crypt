#include "gap0.h"
/* CertIsWeakHash: behaviour depends on policy/OS build, so only structural properties are checked. */

TEST(gap0_weakhash_export) {
    if (t_is_wine()) { t_skip("exports absent in the emulator"); return; }
    CHECK(t_proc_in("crypt32.dll", "CertIsWeakHash") != NULL);
}

TEST(gap0_weakhash_returns_boolean_and_is_stable) {
    REQUIRE(U(CertIsWeakHash));
    static const WCHAR *algs[] = { L"MD2", L"MD4", L"MD5", L"SHA1", L"SHA256", L"SHA384", L"SHA512", L"BOGUSHASH" };
    for (DWORD use = 0; use < 4; use++) {
        for (unsigned i = 0; i < sizeof algs / sizeof *algs; i++) {
            BOOL a = U(CertIsWeakHash)(use, algs[i], 0, NULL, NULL, NULL);
            BOOL b = U(CertIsWeakHash)(use, algs[i], 0, NULL, NULL, NULL);
            CHECKF(a == 0 || a == 1, "use %lu alg %u gave %d", use, i, a);
            CHECKF(a == b, "use %lu alg %u not stable", use, i);
            t_note("CertIsWeakHash(use=%lu, %ls) = %d", use, algs[i], a);
        }
    }
}

TEST(gap0_weakhash_monotonic_md5_sha256) {
    REQUIRE(U(CertIsWeakHash));
    for (DWORD use = 0; use < 4; use++) {
        BOOL md5 = U(CertIsWeakHash)(use, L"MD5", 0, NULL, NULL, NULL);
        BOOL sha256 = U(CertIsWeakHash)(use, L"SHA256", 0, NULL, NULL, NULL);
        /* A stronger hash is never reported weak while a broken one is accepted. */
        CHECKF(!(sha256 && !md5), "use %lu: SHA256 weak but MD5 not", use);
    }
}

TEST(gap0_weakhash_with_chain_context) {
    REQUIRE(U(CertIsWeakHash)); REQUIRE(U(CertGetCertificateChain));
    PCCERT_CHAIN_CONTEXT ch = g0_ss_chain();
    if (!ch) { t_skip("cannot build chain"); return; }
    FILETIME ft; GetSystemTimeAsFileTime(&ft);
    BOOL r1 = U(CertIsWeakHash)(0, L"SHA256", 0, ch, NULL, NULL);
    BOOL r2 = U(CertIsWeakHash)(0, L"SHA256", 0, ch, &ft, NULL);
    BOOL r3 = U(CertIsWeakHash)(0, L"MD5", 0, ch, &ft, NULL);
    CHECK(r1 == 0 || r1 == 1); CHECK(r2 == 0 || r2 == 1); CHECK(r3 == 0 || r3 == 1);
    t_note("with chain: sha256=%d sha256@now=%d md5@now=%d", r1, r2, r3);
    /* The chain's own signature algorithm is SHA-256 on P-256; the chain must not be flagged for a stronger hash than MD5. */
    CHECK(!(r2 && !r3));
    U(CertFreeCertificateChain)(ch);
}

