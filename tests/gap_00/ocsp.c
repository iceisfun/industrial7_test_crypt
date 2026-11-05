#include "gap0.h"
/* Server OCSP response API (crypt32). Only paths that never touch the network are exercised. */

#define OCSP_ASYNC 0x1

static const char *g_ocsp_names[] = {
    "CertOpenServerOcspResponse", "CertAddRefServerOcspResponse", "CertCloseServerOcspResponse",
    "CertGetServerOcspResponseContext", "CertAddRefServerOcspResponseContext", "CertFreeServerOcspResponseContext" };

TEST(gap0_ocsp_exports_in_crypt32) {
    if (t_is_wine()) { t_skip("exports absent in the emulator"); return; }
    for (unsigned i = 0; i < sizeof g_ocsp_names / sizeof *g_ocsp_names; i++) {
        FARPROC p = t_proc_in("crypt32.dll", g_ocsp_names[i]);
        CHECKF(p != NULL, "%s missing from crypt32.dll", g_ocsp_names[i]);
    }
}

TEST(gap0_ocsp_open_null_chain) {
    REQUIRE(U(CertOpenServerOcspResponse));
    DWORD flags[] = { 0, 1, 2, 3, 0x80000000, 0xFFFFFFFF };
    for (unsigned i = 0; i < sizeof flags / sizeof *flags; i++) {
        SET_ERR(0);
        HCERT_SERVER_OCSP_RESPONSE h = U(CertOpenServerOcspResponse)(NULL, flags[i], NULL);
        CHECKF(h == NULL, "flags 0x%lx", flags[i]);
        EXPECT_ERR(ERROR_INVALID_PARAMETER);
    }
}

TEST(gap0_ocsp_open_null_chain_with_para) {
    REQUIRE(U(CertOpenServerOcspResponse));
    CERT_SERVER_OCSP_RESPONSE_OPEN_PARA p; memset(&p, 0, sizeof p); p.cbSize = sizeof p;
    DWORD used = 0xCAFEF00D; p.pcbUsedSize = &used;
    SET_ERR(0);
    HCERT_SERVER_OCSP_RESPONSE h = U(CertOpenServerOcspResponse)(NULL, 0, &p);
    CHECK(h == NULL); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    /* The chain argument is validated before the parameter block is looked at. */
    EXPECT_EQ(used, 0xCAFEF00D);
}

TEST(gap0_ocsp_open_para_cbsize_too_small) {
    REQUIRE(U(CertOpenServerOcspResponse)); REQUIRE(U(CertGetCertificateChain));
    PCCERT_CHAIN_CONTEXT ch = g0_ss_chain();
    if (!ch) { t_skip("cannot build chain"); return; }
    DWORD sizes[] = { 0, 1, 4, 0x20, 0x27 };
    for (unsigned i = 0; i < sizeof sizes / sizeof *sizes; i++) {
        CERT_SERVER_OCSP_RESPONSE_OPEN_PARA p; memset(&p, 0, sizeof p);
        DWORD used = 0xCAFEF00D;
        p.cbSize = sizes[i]; p.pcbUsedSize = &used;
        SET_ERR(0);
        HCERT_SERVER_OCSP_RESPONSE h = U(CertOpenServerOcspResponse)(ch, OCSP_ASYNC, &p);
        CHECKF(h == NULL, "cbSize %lu", sizes[i]);
        EXPECT_ERR(ERROR_INVALID_PARAMETER);
        CHECKF(used == 0xCAFEF00D, "pcbUsedSize touched for cbSize %lu", sizes[i]);
    }
    U(CertFreeCertificateChain)(ch);
}

TEST(gap0_ocsp_open_para_flag_combinations_invalid) {
    REQUIRE(U(CertOpenServerOcspResponse)); REQUIRE(U(CertGetCertificateChain));
    PCCERT_CHAIN_CONTEXT ch = g0_ss_chain();
    if (!ch) { t_skip("cannot build chain"); return; }
    static WCHAR dir[] = L"C:\\cryptt_gap0_nonexistent_dir";
    struct { DWORD pflags; PWSTR dir; } rows[] = {
        { 1, NULL }, { 2, NULL }, { 3, NULL }, { 3, dir }, { 0x7, dir } };
    for (unsigned i = 0; i < sizeof rows / sizeof *rows; i++) {
        CERT_SERVER_OCSP_RESPONSE_OPEN_PARA p; memset(&p, 0, sizeof p);
        DWORD used = 0xCAFEF00D;
        p.cbSize = sizeof p; p.dwFlags = rows[i].pflags; p.pwszOcspDirectory = rows[i].dir; p.pcbUsedSize = &used;
        SET_ERR(0);
        HCERT_SERVER_OCSP_RESPONSE h = U(CertOpenServerOcspResponse)(ch, OCSP_ASYNC, &p);
        CHECKF(h == NULL, "row %u", i);
        EXPECT_ERR(ERROR_INVALID_PARAMETER);
        CHECKF(used == 0xCAFEF00D, "pcbUsedSize touched on row %u", i);
    }
    U(CertFreeCertificateChain)(ch);
}

TEST(gap0_ocsp_open_async_without_ocsp_url) {
    REQUIRE(U(CertOpenServerOcspResponse)); REQUIRE(U(CertGetCertificateChain));
    PCCERT_CHAIN_CONTEXT ch = g0_ss_chain();
    if (!ch) { t_skip("cannot build chain"); return; }
    /* A self-signed leaf without an OCSP AIA URL cannot be served: the async open fails early. */
    SET_ERR(0);
    HCERT_SERVER_OCSP_RESPONSE h = U(CertOpenServerOcspResponse)(ch, OCSP_ASYNC, NULL);
    CHECK(h == NULL); EXPECT_ERR(G0_CRYPT_E_NOT_IN_REVOCATION_DATABASE);
    if (h) U(CertCloseServerOcspResponse)(h, 0);
    U(CertFreeCertificateChain)(ch);
}

TEST(gap0_ocsp_open_async_para_reports_used_size) {
    REQUIRE(U(CertOpenServerOcspResponse)); REQUIRE(U(CertGetCertificateChain));
    PCCERT_CHAIN_CONTEXT ch = g0_ss_chain();
    if (!ch) { t_skip("cannot build chain"); return; }
    DWORD cbs[] = { 0x28, 0x30, 0x100 };
    for (unsigned i = 0; i < sizeof cbs / sizeof *cbs; i++) {
        BYTE buf[0x100]; memset(buf, 0, sizeof buf);
        CERT_SERVER_OCSP_RESPONSE_OPEN_PARA *p = (void *)buf;
        DWORD used = 0xCAFEF00D;
        p->cbSize = cbs[i]; p->pcbUsedSize = &used;
        SET_ERR(0);
        HCERT_SERVER_OCSP_RESPONSE h = U(CertOpenServerOcspResponse)(ch, OCSP_ASYNC, p);
        CHECKF(h == NULL, "cbSize 0x%lx", cbs[i]); EXPECT_ERR(G0_CRYPT_E_NOT_IN_REVOCATION_DATABASE);
        /* The implementation understands a 0x28 byte block and reports exactly that, whatever the caller declared. */
        CHECKF(used == 0x28, "cbSize 0x%lx used=0x%lx", cbs[i], used);
        if (h) U(CertCloseServerOcspResponse)(h, 0);
    }
    U(CertFreeCertificateChain)(ch);
}

TEST(gap0_ocsp_open_async_with_directory_flags) {
    REQUIRE(U(CertOpenServerOcspResponse)); REQUIRE(U(CertGetCertificateChain));
    PCCERT_CHAIN_CONTEXT ch = g0_ss_chain();
    if (!ch) { t_skip("cannot build chain"); return; }
    static WCHAR dir[] = L"C:\\cryptt_gap0_nonexistent_dir";
    DWORD pf[] = { 1, 2 };
    for (unsigned i = 0; i < 2; i++) {
        CERT_SERVER_OCSP_RESPONSE_OPEN_PARA p; memset(&p, 0, sizeof p);
        DWORD used = 0;
        p.cbSize = sizeof p; p.dwFlags = pf[i]; p.pwszOcspDirectory = dir; p.pcbUsedSize = &used;
        SET_ERR(0);
        HCERT_SERVER_OCSP_RESPONSE h = U(CertOpenServerOcspResponse)(ch, OCSP_ASYNC, &p);
        CHECK(h == NULL); EXPECT_ERR(G0_CRYPT_E_NOT_IN_REVOCATION_DATABASE);
        EXPECT_EQ(used, 0x28);
        if (h) U(CertCloseServerOcspResponse)(h, 0);
    }
    U(CertFreeCertificateChain)(ch);
}

TEST(gap0_ocsp_open_sync_without_ocsp_url_observed) {
    REQUIRE(U(CertOpenServerOcspResponse)); REQUIRE(U(CertGetCertificateChain));
    PCCERT_CHAIN_CONTEXT ch = g0_ss_chain();
    if (!ch) { t_skip("cannot build chain"); return; }
    SET_ERR(0);
    HCERT_SERVER_OCSP_RESPONSE h = U(CertOpenServerOcspResponse)(ch, 0, NULL);
    DWORD e = GetLastError();
    t_note("sync open of self-signed cert without AIA: handle=%p err=0x%lx", (void *)h, e);
    if (h) {
        /* A handle may exist without a fetched response; getting the context must then fail cleanly. */
        SET_ERR(0);
        PCCERT_SERVER_OCSP_RESPONSE_CONTEXT c = U(CertGetServerOcspResponseContext)(h, 0, NULL);
        t_note("context=%p err=0x%lx", (const void *)c, GetLastError());
        if (c) U(CertFreeServerOcspResponseContext)(c);
        U(CertCloseServerOcspResponse)(h, 0);
    }
    U(CertFreeCertificateChain)(ch);
}

TEST(gap0_ocsp_open_keeps_chain_usable) {
    REQUIRE(U(CertOpenServerOcspResponse)); REQUIRE(U(CertGetCertificateChain));
    PCCERT_CHAIN_CONTEXT ch = g0_ss_chain();
    if (!ch) { t_skip("cannot build chain"); return; }
    HCERT_SERVER_OCSP_RESPONSE h = U(CertOpenServerOcspResponse)(ch, OCSP_ASYNC, NULL);
    CHECK(h == NULL);
    /* After a failed open the chain must be fully usable and freeable by the caller. */
    CHECK(ch->cChain == 1);
    CHECK(ch->rgpChain[0]->cElement == 1);
    PCCERT_CHAIN_CONTEXT dup = U(CertDuplicateCertificateChain)(ch);
    CHECK(dup != NULL);
    if (dup) U(CertFreeCertificateChain)(dup);
    U(CertFreeCertificateChain)(ch);
}

TEST(gap0_ocsp_get_context_null_handle) {
    REQUIRE(U(CertGetServerOcspResponseContext));
    DWORD flags[] = { 0, 1, 0xFFFFFFFF };
    for (unsigned i = 0; i < 3; i++) {
        SET_ERR(0);
        PCCERT_SERVER_OCSP_RESPONSE_CONTEXT c = U(CertGetServerOcspResponseContext)(NULL, flags[i], NULL);
        CHECKF(c == NULL, "flags 0x%lx", flags[i]);
        EXPECT_ERR(ERROR_INVALID_PARAMETER);
    }
}

TEST(gap0_ocsp_null_handles_are_noops) {
    REQUIRE(U(CertAddRefServerOcspResponse)); REQUIRE(U(CertCloseServerOcspResponse));
    REQUIRE(U(CertAddRefServerOcspResponseContext)); REQUIRE(U(CertFreeServerOcspResponseContext));
    SET_ERR(0x1234);
    U(CertAddRefServerOcspResponse)(NULL);
    U(CertCloseServerOcspResponse)(NULL, 0);
    U(CertCloseServerOcspResponse)(NULL, 0xFFFFFFFF);
    U(CertAddRefServerOcspResponseContext)(NULL);
    U(CertFreeServerOcspResponseContext)(NULL);
    /* No-ops leave the thread's last error alone. */
    EXPECT_EQ(GetLastError(), 0x1234);
}
