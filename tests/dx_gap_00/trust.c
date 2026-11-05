#include "dxgap0.h"
/* CertModifyCertificatesToTrust (cryptdlg.dll) edits the current user's Disallowed and TrustedPeople stores.
 * Every test removes the throw-away certificate again, also at start-up, to sweep earlier aborted runs. */

typedef struct { PCCERT_CONTEXT pccert; DWORD dwOperation; DWORD dwError; } DX_MODREQ;
#define OP_ADD_NOT_TRUSTED 1
#define OP_REMOVE 2
#define OP_ADD_TRUSTED 3
UDECL(LONG, CertModifyCertificatesToTrust, (int, DX_MODREQ *, LPCSTR, HWND, HCERTSTORE));

static const WCHAR *k_stores[] = { L"Disallowed", L"TrustedPeople" };

static PCCERT_CONTEXT dx_cert(void) {
    return U(CertCreateCertificateContext)(DX_ENC, dxgap0_ss_cert, sizeof dxgap0_ss_cert);
}

/* Is the certificate (by exact match) in HKCU\<store>? */
static int dx_in_store(const WCHAR *name, PCCERT_CONTEXT c) {
    HCERTSTORE s = dx_open_hkcu(name);
    if (!s) return -1;
    PCCERT_CONTEXT f = U(CertFindCertificateInStore)(s, DX_ENC, 0, CERT_FIND_EXISTING, c, NULL);
    int r = f != NULL;
    if (f) U(CertFreeCertificateContext)(f);
    U(CertCloseStore)(s, 0);
    return r;
}

static void dx_purge(PCCERT_CONTEXT c) {
    for (int i = 0; i < 2; i++) {
        HCERTSTORE s = dx_open_hkcu(k_stores[i]);
        if (!s) continue;
        PCCERT_CONTEXT f;
        while ((f = U(CertFindCertificateInStore)(s, DX_ENC, 0, CERT_FIND_EXISTING, c, NULL)) != NULL)
            U(CertDeleteCertificateFromStore)(f);   /* frees f */
        U(CertCloseStore)(s, 0);
    }
}

#define SETUP() \
    CertModifyCertificatesToTrust_pfn mod = (CertModifyCertificatesToTrust_pfn)t_proc_in("cryptdlg.dll", "CertModifyCertificatesToTrust"); \
    if (t_is_wine()) { t_skip("stub aborts under the emulator"); return; } \
    REQUIRE(mod); REQUIRE(U(CertOpenStore)); \
    PCCERT_CONTEXT cert = dx_cert(); \
    if (!cert) { t_skip("cert"); return; } \
    dx_purge(cert); \
    do { HCERTSTORE probe_ = dx_open_hkcu(L"TrustedPeople"); if (!probe_) { U(CertFreeCertificateContext)(cert); t_skip("HKCU stores not available"); return; } U(CertCloseStore)(probe_, 0); } while (0)

#define TEARDOWN() do { dx_purge(cert); U(CertFreeCertificateContext)(cert); } while (0)

TEST(dx_gap0_trust_zero_requests) {
    SETUP();
    LONG r = mod(0, NULL, NULL, NULL, NULL);
    CHECKF(r == 0, "r=%ld", r);
    TEARDOWN();
}

TEST(dx_gap0_trust_invalid_operation_codes) {
    SETUP();
    DWORD ops[] = { 0, 4, 5, 0x100, 0xFFFFFFFF };
    for (unsigned i = 0; i < sizeof ops / sizeof *ops; i++) {
        DX_MODREQ rq = { cert, ops[i], 0xDEAD };
        LONG r = mod(1, &rq, NULL, NULL, NULL);
        CHECKF(r != 0, "op %lu accepted", ops[i]);
        CHECKF(rq.dwError == 0x80070057, "op %lu: dwError 0x%lx", ops[i], rq.dwError);
        CHECKF(dx_in_store(L"Disallowed", cert) == 0, "op %lu changed Disallowed", ops[i]);
        CHECKF(dx_in_store(L"TrustedPeople", cert) == 0, "op %lu changed TrustedPeople", ops[i]);
    }
    TEARDOWN();
}

TEST(dx_gap0_trust_add_not_trusted_then_remove) {
    SETUP();
    DX_MODREQ rq = { cert, OP_ADD_NOT_TRUSTED, 0xDEAD };
    LONG r = mod(1, &rq, NULL, NULL, NULL);
    CHECKF(r == 0, "add: r=%ld err=0x%lx", r, rq.dwError);
    EXPECT_EQ(rq.dwError, 0);
    CHECK(dx_in_store(L"Disallowed", cert) == 1);
    /* adding again is idempotent */
    rq.dwError = 0xDEAD;
    r = mod(1, &rq, NULL, NULL, NULL);
    CHECKF(r == 0, "re-add: r=%ld err=0x%lx", r, rq.dwError);
    CHECK(dx_in_store(L"Disallowed", cert) == 1);
    rq.dwOperation = OP_REMOVE; rq.dwError = 0xDEAD;
    r = mod(1, &rq, NULL, NULL, NULL);
    CHECKF(r == 0, "remove: r=%ld err=0x%lx", r, rq.dwError);
    EXPECT_EQ(rq.dwError, 0);
    CHECK(dx_in_store(L"Disallowed", cert) == 0);
    TEARDOWN();
}

TEST(dx_gap0_trust_remove_when_absent) {
    SETUP();
    DX_MODREQ rq = { cert, OP_REMOVE, 0xDEAD };
    LONG r = mod(1, &rq, NULL, NULL, NULL);
    t_note("remove of an unknown certificate: r=%ld dwError=0x%lx", r, rq.dwError);
    CHECK(dx_in_store(L"Disallowed", cert) == 0);
    CHECK(dx_in_store(L"TrustedPeople", cert) == 0);
    TEARDOWN();
}

TEST(dx_gap0_trust_add_trusted_moves_out_of_disallowed) {
    SETUP();
    DX_MODREQ rq = { cert, OP_ADD_NOT_TRUSTED, 0xDEAD };
    CHECK(mod(1, &rq, NULL, NULL, NULL) == 0);
    CHECK(dx_in_store(L"Disallowed", cert) == 1);
    rq.dwOperation = OP_ADD_TRUSTED; rq.dwError = 0xDEAD;
    LONG r = mod(1, &rq, szOID_PKIX_KP_EMAIL_PROTECTION, NULL, NULL);
    t_note("add trusted: r=%ld dwError=0x%lx", r, rq.dwError);
    if (r == 0) {
        EXPECT_EQ(rq.dwError, 0);
        CHECK(dx_in_store(L"Disallowed", cert) == 0);
        CHECK(dx_in_store(L"TrustedPeople", cert) == 1);
        /* trusting removes the certificate from the other list; distrusting does the converse */
        rq.dwOperation = OP_ADD_NOT_TRUSTED; rq.dwError = 0xDEAD;
        r = mod(1, &rq, NULL, NULL, NULL);
        CHECKF(r == 0, "r=%ld err=0x%lx", r, rq.dwError);
        CHECK(dx_in_store(L"Disallowed", cert) == 1);
        t_note("TrustedPeople presence after distrust: %d", dx_in_store(L"TrustedPeople", cert));
    }
    TEARDOWN();
}

TEST(dx_gap0_trust_mixed_batch_reports_per_entry_errors) {
    SETUP();
    DX_MODREQ rq[3] = { { cert, OP_ADD_NOT_TRUSTED, 0xDEAD }, { cert, 0x77, 0xDEAD }, { cert, OP_REMOVE, 0xDEAD } };
    LONG r = mod(3, rq, NULL, NULL, NULL);
    CHECKF(r != 0, "batch with an invalid entry returned %ld", r);
    EXPECT_EQ(rq[0].dwError, 0);
    EXPECT_EQ(rq[1].dwError, 0x80070057);
    EXPECT_EQ(rq[2].dwError, 0);
    /* entries are processed in order: add, (invalid), remove => absent at the end */
    CHECK(dx_in_store(L"Disallowed", cert) == 0);
    TEARDOWN();
}

TEST(dx_gap0_trust_export_lives_in_cryptdlg) {
    if (t_is_wine()) { t_skip("emulator"); return; }
    CHECK(t_proc_in("cryptdlg.dll", "CertModifyCertificatesToTrust") != NULL);
}
