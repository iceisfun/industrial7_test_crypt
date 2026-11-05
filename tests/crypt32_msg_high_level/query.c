/* CryptQueryObject: blob and file objects, content/format masks, outputs, error codes. */
#include "mh.h"
#include <stdlib.h>
#include <wchar.h>

#define CQ U(CryptQueryObject)
#define QC_CERT 0x2u
#define QC_CTL 0x4u
#define QC_CRL 0x8u
#define QC_SSTORE 0x10u
#define QC_SCERT 0x20u
#define QC_SCTL 0x40u
#define QC_SCRL 0x80u
#define QC_P7S 0x100u
#define QC_P7U 0x200u
#define QC_P7E 0x400u
#define QC_P10 0x800u
#define QC_PFX 0x1000u
#define QC_PAIR 0x2000u
#define QC_ALL 0x3ffeu
#define QF_BIN 0x2u
#define QF_B64 0x4u
#define QF_HEX 0x8u
#define QF_ALL 0xeu
enum { T_CERT = 1, T_CTL, T_CRL, T_SSTORE, T_SCERT, T_SCTL, T_SCRL, T_P7S, T_P7U, T_P7E, T_P10, T_PFX, T_PAIR };

typedef struct { DWORD enc, ct, ft; HCERTSTORE st; HCRYPTMSG msg; const void *ctx; DWORD err; } QR;

static BOOL qblob(const BYTE *p, DWORD n, DWORD cmask, DWORD fmask, QR *r) {
    CERT_BLOB b = { n, (BYTE *)p };
    memset(r, 0, sizeof *r); SET_ERR(0);
    BOOL ok = CQ(CERT_QUERY_OBJECT_BLOB, &b, cmask, fmask, 0, &r->enc, &r->ct, &r->ft, &r->st, &r->msg, &r->ctx);
    r->err = GetLastError();
    return ok;
}
static void qfree(QR *r) {
    if (r->ctx) {
        switch (r->ct) {
        case T_CERT: case T_SCERT: U(CertFreeCertificateContext)((PCCERT_CONTEXT)r->ctx); break;
        case T_CRL: case T_SCRL: U(CertFreeCRLContext)((PCCRL_CONTEXT)r->ctx); break;
        case T_CTL: case T_SCTL: U(CertFreeCTLContext)((PCCTL_CONTEXT)r->ctx); break;
        }
    }
    if (r->msg) U(CryptMsgClose)(r->msg);
    if (r->st) U(CertCloseStore)(r->st, 0);
    memset(r, 0, sizeof *r);
}
static BYTE *dup_(const BYTE *p, DWORD n) { BYTE *q = malloc(n); memcpy(q, p, n); return q; }

/* ---- argument validation ---------------------------------------------------------------------- */
TEST(query_null_object_invalid) {
    REQUIRE(CQ);
    DWORD enc = 77, ct = 77, ft = 77; SET_ERR(0);
    BOOL r = CQ(CERT_QUERY_OBJECT_BLOB, NULL, QC_ALL, QF_ALL, 0, &enc, &ct, &ft, NULL, NULL, NULL);
    EXPECT_FAIL(r == FALSE, E_INVALIDARG_);
    r = CQ(CERT_QUERY_OBJECT_FILE, NULL, QC_ALL, QF_ALL, 0, &enc, &ct, &ft, NULL, NULL, NULL);
    EXPECT_FAIL(r == FALSE, E_INVALIDARG_);
}
TEST(query_invalid_object_type) {
    REQUIRE(CQ);
    CERT_BLOB b = { sizeof v_o_cert, (BYTE *)v_o_cert };
    static const DWORD t[] = { 0, 3, 4, 0x80, 0xFFFFFFFF };
    for (int i = 0; i < 5; i++) {
        SET_ERR(0); BOOL r = CQ(t[i], &b, QC_ALL, QF_ALL, 0, NULL, NULL, NULL, NULL, NULL, NULL);
        EXPECT_FAIL(r == FALSE, E_INVALIDARG_);
    }
}
TEST(query_invalid_content_masks) {
    REQUIRE(CQ);
    CERT_BLOB b = { sizeof v_o_cert, (BYTE *)v_o_cert };
    static const DWORD m[] = { 0, 1, 0x8000, 0x8001, 0x10000, 0x80000000u };
    for (int i = 0; i < 6; i++) {
        SET_ERR(0); BOOL r = CQ(CERT_QUERY_OBJECT_BLOB, &b, m[i], QF_ALL, 0, NULL, NULL, NULL, NULL, NULL, NULL);
        EXPECT_FAIL(r == FALSE, E_INVALIDARG_);
    }
}
TEST(query_invalid_format_masks) {
    REQUIRE(CQ);
    CERT_BLOB b = { sizeof v_o_cert, (BYTE *)v_o_cert };
    static const DWORD m[] = { 0, 1, 0x10, 0x11, 0x100, 0x80000000u };
    for (int i = 0; i < 6; i++) {
        SET_ERR(0); BOOL r = CQ(CERT_QUERY_OBJECT_BLOB, &b, QC_ALL, m[i], 0, NULL, NULL, NULL, NULL, NULL, NULL);
        EXPECT_FAIL(r == FALSE, E_INVALIDARG_);
    }
}
TEST(query_empty_blob_invalid) {
    REQUIRE(CQ);
    CERT_BLOB b0 = { 0, (BYTE *)v_o_cert }, b1 = { sizeof v_o_cert, NULL }, b2 = { 0, NULL };
    CERT_BLOB *bs[3] = { &b0, &b1, &b2 };
    for (int i = 0; i < 3; i++) {
        SET_ERR(0); BOOL r = CQ(CERT_QUERY_OBJECT_BLOB, bs[i], QC_ALL, QF_ALL, 0, NULL, NULL, NULL, NULL, NULL, NULL);
        EXPECT_FAIL(r == FALSE, E_INVALIDARG_);
    }
}
TEST(query_invalid_args_leave_outputs_untouched) {
    REQUIRE(CQ);
    DWORD enc = 0x1111, ct = 0x2222, ft = 0x3333; HCERTSTORE st = (HCERTSTORE)0x44; HCRYPTMSG msg = (HCRYPTMSG)0x55; const void *ctx = (void *)0x66;
    SET_ERR(0);
    BOOL r = CQ(CERT_QUERY_OBJECT_BLOB, NULL, QC_ALL, QF_ALL, 0, &enc, &ct, &ft, &st, &msg, &ctx);
    CHECK(r == FALSE);
    EXPECT_EQ(enc, 0x1111); EXPECT_EQ(ct, 0x2222); EXPECT_EQ(ft, 0x3333);
    CHECK(st == (HCERTSTORE)0x44 && msg == (HCRYPTMSG)0x55 && ctx == (void *)0x66);
}
TEST(query_no_match_zeroes_outputs_when_binary_attempted) {
    REQUIRE(CQ);
    static const BYTE g[] = { 0x04, 0x02, 0x41, 0x42 };
    DWORD enc = 0x1111, ct = 0x2222, ft = 0x3333; HCERTSTORE st = (HCERTSTORE)0x44; HCRYPTMSG msg = (HCRYPTMSG)0x55; const void *ctx = (void *)0x66;
    CERT_BLOB b = { sizeof g, (BYTE *)g }; SET_ERR(0);
    BOOL r = CQ(CERT_QUERY_OBJECT_BLOB, &b, QC_ALL, QF_BIN, 0, &enc, &ct, &ft, &st, &msg, &ctx);
    EXPECT_FAIL(r == FALSE, E_CRYPT_E_NO_MATCH);
    EXPECT_EQ(enc, 0); EXPECT_EQ(ct, 0); EXPECT_EQ(ft, 0); CHECK(st == NULL && msg == NULL && ctx == NULL);
}
TEST(query_all_outputs_optional) {
    REQUIRE(CQ);
    CERT_BLOB b = { sizeof v_o_cert, (BYTE *)v_o_cert }; SET_ERR(0);
    CHECK(CQ(CERT_QUERY_OBJECT_BLOB, &b, QC_ALL, QF_ALL, 0, NULL, NULL, NULL, NULL, NULL, NULL));
    CHECK(CQ(CERT_QUERY_OBJECT_BLOB, &b, QC_CERT, QF_BIN, 0, NULL, NULL, NULL, NULL, NULL, NULL));
    SET_ERR(0);
    CHECK(!CQ(CERT_QUERY_OBJECT_BLOB, &b, QC_CRL, QF_BIN, 0, NULL, NULL, NULL, NULL, NULL, NULL)); EXPECT_ERR(E_CRYPT_E_NO_MATCH);
}

/* ---- binary content types ---------------------------------------------------------------------- */
static struct { const char *name; const BYTE *p; DWORD n; DWORD mask; DWORD ct; DWORD enc; } g_bin[] = {
    { "cert",      v_o_cert,   sizeof v_o_cert,   QC_CERT,  T_CERT,  1 },
    { "crl",       v_o_crl,    sizeof v_o_crl,    QC_CRL,   T_CRL,   1 },
    { "ctl",       NULL,       0,                 QC_CTL,   T_CTL,   0x10001 },
    { "p7 certs",  v_m_certs_only, sizeof v_m_certs_only, QC_P7S, T_P7S, 0x10001 },
    { "p7 crl",    v_o_p7_crl, sizeof v_o_p7_crl, QC_P7S,   T_P7S,   0x10001 },
    { "p7 signed", v_m_sig_noattr, sizeof v_m_sig_noattr, QC_P7S, T_P7S, 0x10001 },
    { "pfx",       v_o_pfx,    sizeof v_o_pfx,    QC_PFX,   T_PFX,   1 },
    { "pair",      v_o_pair,   sizeof v_o_pair,   QC_PAIR,  T_PAIR,  1 },
};
#define NBIN ((int)(sizeof g_bin / sizeof g_bin[0]))
static DWORD g_ctl_n; static const BYTE *g_ctl;
static int bin_init(void) {
    if (!g_ctl) { g_ctl = mh_ctl_blob(&g_ctl_n); for (int i = 0; i < NBIN; i++) if (g_bin[i].ct == T_CTL) { g_bin[i].p = g_ctl; g_bin[i].n = g_ctl_n; } }
    if (!g_ctl) { t_skip("cannot build a signed CTL"); return 0; }
    return 1;
}
#define BIN_INIT() do { if (!bin_init()) return; } while (0)

TEST(query_binary_exact_mask_table) {
    REQUIRE(CQ); BIN_INIT();
    for (int i = 0; i < NBIN; i++) {
        QR r; BOOL ok = qblob(g_bin[i].p, g_bin[i].n, g_bin[i].mask, QF_BIN, &r);
        CHECKF(ok, "%s: err 0x%lx", g_bin[i].name, r.err); if (!ok) continue;
        CHECKF(r.ct == g_bin[i].ct, "%s content type %lu", g_bin[i].name, r.ct);
        CHECKF(r.ft == 1, "%s format %lu", g_bin[i].name, r.ft);
        CHECKF(r.enc == g_bin[i].enc, "%s encoding 0x%lx", g_bin[i].name, r.enc);
        qfree(&r);
    }
}
TEST(query_binary_all_masks_table) {
    REQUIRE(CQ); BIN_INIT();
    for (int i = 0; i < NBIN; i++) {
        QR r; BOOL ok = qblob(g_bin[i].p, g_bin[i].n, QC_ALL, QF_ALL, &r);
        CHECKF(ok, "%s: err 0x%lx", g_bin[i].name, r.err); if (!ok) continue;
        CHECKF(r.ct == g_bin[i].ct, "%s content type %lu", g_bin[i].name, r.ct);
        CHECKF(r.ft == 1, "%s format %lu", g_bin[i].name, r.ft);
        qfree(&r);
    }
}
TEST(query_binary_wrong_mask_no_match_table) {
    REQUIRE(CQ); BIN_INIT();
    for (int i = 0; i < NBIN; i++) {
        /* every other single-type mask must fail; types that can legitimately overlap are skipped */
        for (int j = 0; j < NBIN; j++) {
            if (i == j || g_bin[i].mask == g_bin[j].mask) continue;
            DWORD m = g_bin[j].mask;
            QR r; BOOL ok = qblob(g_bin[i].p, g_bin[i].n, m, QF_BIN, &r);
            if (g_bin[i].ct == T_CTL && m == QC_P7S) {   /* a CTL is a signed PKCS#7 message and matches that mask */
                t_label("%s as %s", g_bin[i].name, g_bin[j].name); CHECK(ok); EXPECT_EQ(r.ct, T_P7S); t_label(NULL); qfree(&r); continue; }
            CHECKF(!ok, "%s queried as %s unexpectedly matched (type %lu)", g_bin[i].name, g_bin[j].name, r.ct);
            if (!ok) CHECKF(r.err == E_CRYPT_E_NO_MATCH, "%s as %s: err 0x%lx", g_bin[i].name, g_bin[j].name, r.err);
            qfree(&r);
        }
    }
}
TEST(query_cert_outputs) {
    REQUIRE(CQ);
    QR r; CHECK(qblob(v_o_cert, sizeof v_o_cert, QC_CERT, QF_BIN, &r));
    CHECK(r.st != NULL); CHECK(r.msg == NULL); CHECK(CERT_IS((PCCERT_CONTEXT)r.ctx, v_o_cert));
    EXPECT_EQ(mh_count_certs(r.st), 1);
    PCCERT_CONTEXT c = ((PCCERT_CONTEXT)r.ctx); CHECK(c && c->hCertStore == r.st);
    qfree(&r);
}
TEST(query_cert_context_survives_store_close) {
    REQUIRE(CQ);
    QR r; CHECK(qblob(v_o_cert, sizeof v_o_cert, QC_CERT, QF_BIN, &r));
    PCCERT_CONTEXT c = (PCCERT_CONTEXT)r.ctx; r.ctx = NULL;
    CHECK(U(CertCloseStore)(r.st, 0)); r.st = NULL;
    CHECK(CERT_IS(c, v_o_cert));
    FREE_CERT(c);
}
TEST(query_cert_without_store_output) {
    REQUIRE(CQ);
    CERT_BLOB b = { sizeof v_o_cert, (BYTE *)v_o_cert }; const void *ctx = NULL; DWORD ct = 0;
    CHECK(CQ(CERT_QUERY_OBJECT_BLOB, &b, QC_CERT, QF_BIN, 0, NULL, &ct, NULL, NULL, NULL, &ctx));
    EXPECT_EQ(ct, T_CERT); CHECK(CERT_IS((PCCERT_CONTEXT)ctx, v_o_cert));
    PCCERT_CONTEXT c = (PCCERT_CONTEXT)ctx; FREE_CERT(c);
    HCERTSTORE st = NULL;
    CHECK(CQ(CERT_QUERY_OBJECT_BLOB, &b, QC_CERT, QF_BIN, 0, NULL, NULL, NULL, &st, NULL, NULL));
    CHECK(st != NULL); EXPECT_EQ(mh_count_certs(st), 1); U(CertCloseStore)(st, 0);
}
TEST(query_crl_outputs) {
    REQUIRE(CQ);
    QR r; CHECK(qblob(v_o_crl, sizeof v_o_crl, QC_CRL, QF_BIN, &r)); if (r.ct != T_CRL) { qfree(&r); return; }
    PCCRL_CONTEXT c = (PCCRL_CONTEXT)r.ctx;
    CHECK(c && c->cbCrlEncoded == sizeof v_o_crl && !memcmp(c->pbCrlEncoded, v_o_crl, sizeof v_o_crl));
    CHECK(r.st != NULL); CHECK(U(CertEnumCRLsInStore)(r.st, NULL) != NULL);
    EXPECT_EQ(mh_count_certs(r.st), 0);
    qfree(&r);
}
TEST(query_ctl_outputs) {
    REQUIRE(CQ); BIN_INIT();
    QR r; CHECK(qblob(g_ctl, g_ctl_n, QC_CTL, QF_BIN, &r)); if (r.ct != T_CTL) { qfree(&r); return; }
    PCCTL_CONTEXT c = (PCCTL_CONTEXT)r.ctx;
    CHECK(c != NULL); if (c) { EXPECT_EQ(c->pCtlInfo->cCTLEntry, 2); CHECK(c->cbCtlEncoded == g_ctl_n); }
    CHECK(r.st != NULL);
    qfree(&r);
}
TEST(query_ctl_is_signed_data_when_ctl_not_requested) {
    REQUIRE(CQ); BIN_INIT();
    QR r; BOOL ok = qblob(g_ctl, g_ctl_n, QC_P7S, QF_BIN, &r);
    CHECKF(ok, "err 0x%lx", r.err);
    if (ok) { EXPECT_EQ(r.ct, T_P7S); CHECK(r.msg != NULL); CHECK(r.ctx == NULL); }
    qfree(&r);
    ok = qblob(g_ctl, g_ctl_n, QC_P7S | QC_CTL, QF_BIN, &r);
    CHECK(ok); if (ok) EXPECT_EQ(r.ct, T_CTL);
    qfree(&r);
}
TEST(query_pkcs7_signed_outputs) {
    REQUIRE(CQ);
    QR r; CHECK(qblob(v_m_certs_only, sizeof v_m_certs_only, QC_P7S, QF_BIN, &r)); if (r.ct != T_P7S) { qfree(&r); return; }
    CHECK(r.st != NULL); CHECK(r.msg != NULL); CHECK(r.ctx == NULL);
    EXPECT_EQ(mh_count_certs(r.st), 2);
    DWORD t = 0, n = sizeof t;
    CHECK(U(CryptMsgGetParam)(r.msg, CMSG_TYPE_PARAM, 0, &t, &n)); EXPECT_EQ(t, CMSG_SIGNED);
    n = sizeof t; CHECK(U(CryptMsgGetParam)(r.msg, CMSG_CERT_COUNT_PARAM, 0, &t, &n)); EXPECT_EQ(t, 2);
    qfree(&r);
}
TEST(query_pkcs7_signed_with_content_message_handle) {
    REQUIRE(CQ);
    QR r; CHECK(qblob(v_m_sig_noattr, sizeof v_m_sig_noattr, QC_P7S, QF_BIN, &r)); if (r.ct != T_P7S) { qfree(&r); return; }
    DWORD n = 0; CHECK(U(CryptMsgGetParam)(r.msg, CMSG_CONTENT_PARAM, 0, NULL, &n)); EXPECT_EQ(n, sizeof v_payload);
    n = 0; CHECK(U(CryptMsgGetParam)(r.msg, CMSG_SIGNER_COUNT_PARAM, 0, &n, &(DWORD){ 4 })); EXPECT_EQ(n, 1);
    EXPECT_EQ(mh_count_certs(r.st), 2);   /* signer + CA */
    qfree(&r);
}
TEST(query_pkcs7_unsigned_enveloped_and_hashed) {
    REQUIRE(CQ);
    static const struct { const char *n; const BYTE *p; DWORD l; DWORD type; } t[] = {
        { "enveloped", v_m_env_aes128, sizeof v_m_env_aes128, CMSG_ENVELOPED }, { "hashed", v_m_hashed_sha256, sizeof v_m_hashed_sha256, CMSG_HASHED } };
    for (int i = 0; i < 2; i++) {
        QR r; BOOL ok = qblob(t[i].p, t[i].l, QC_P7U, QF_BIN, &r);
        CHECKF(ok, "%s: err 0x%lx", t[i].n, r.err); if (!ok) continue;
        EXPECT_EQ(r.ct, T_P7U); EXPECT_EQ(r.enc, 0x10001); CHECK(r.msg != NULL); CHECK(r.st == NULL); CHECK(r.ctx == NULL);
        DWORD mt = 0, n = sizeof mt; CHECK(U(CryptMsgGetParam)(r.msg, CMSG_TYPE_PARAM, 0, &mt, &n)); EXPECT_EQ(mt, t[i].type);
        qfree(&r);
    }
}
TEST(query_pkcs7_unsigned_rejects_signed) {
    REQUIRE(CQ);
    QR r; BOOL ok = qblob(v_m_sig_noattr, sizeof v_m_sig_noattr, QC_P7U, QF_BIN, &r);
    EXPECT_EQ(ok, FALSE); EXPECT_EQ(r.err, E_CRYPT_E_NO_MATCH);
    ok = qblob(v_m_certs_only, sizeof v_m_certs_only, QC_P7U, QF_BIN, &r);
    EXPECT_EQ(ok, FALSE); EXPECT_EQ(r.err, E_CRYPT_E_NO_MATCH);
    qfree(&r);
}
TEST(query_pkcs7_signed_rejects_enveloped_and_hashed) {
    REQUIRE(CQ);
    QR r; BOOL ok = qblob(v_m_env_aes128, sizeof v_m_env_aes128, QC_P7S, QF_BIN, &r);
    EXPECT_EQ(ok, FALSE); EXPECT_EQ(r.err, E_CRYPT_E_NO_MATCH);
    ok = qblob(v_m_hashed_sha256, sizeof v_m_hashed_sha256, QC_P7S, QF_BIN, &r);
    EXPECT_EQ(ok, FALSE); EXPECT_EQ(r.err, E_CRYPT_E_NO_MATCH);
}
TEST(query_pkcs7_embedded_flag_on_plain_blob) {
    REQUIRE(CQ);
    QR r; BOOL ok = qblob(v_m_certs_only, sizeof v_m_certs_only, QC_P7E, QF_BIN, &r);
    EXPECT_EQ(ok, FALSE); EXPECT_EQ(r.err, E_CRYPT_E_NO_MATCH);
    ok = qblob(v_m_certs_only, sizeof v_m_certs_only, QC_P7E | QC_P7S, QF_BIN, &r);
    CHECK(ok); if (ok) EXPECT_EQ(r.ct, T_P7S);
    qfree(&r);
}
TEST(query_pkcs10_request) {
    REQUIRE(CQ);
    QR r; BOOL ok = qblob(v_o_p10, sizeof v_o_p10, QC_P10, QF_BIN, &r);
    CHECKF(ok, "err 0x%lx", r.err); /* observed: a PKCS#10 request is recognised */
    if (ok) { EXPECT_EQ(r.ct, T_P10); EXPECT_EQ(r.enc, 1); CHECK(r.st == NULL); CHECK(r.msg == NULL); }
    qfree(&r);
    ok = qblob(v_o_p10, sizeof v_o_p10, QC_CERT | QC_CRL | QC_CTL | QC_P7S | QC_PAIR | QC_PFX, QF_BIN, &r);
    EXPECT_EQ(ok, FALSE); qfree(&r);
}
TEST(query_pfx_outputs) {
    REQUIRE(CQ);
    QR r; CHECK(qblob(v_o_pfx, sizeof v_o_pfx, QC_PFX, QF_BIN, &r));
    EXPECT_EQ(r.ct, T_PFX); CHECK(r.st == NULL); CHECK(r.msg == NULL); CHECK(r.ctx == NULL);
    qfree(&r);
    BYTE *c = dup_(v_o_pfx, sizeof v_o_pfx); c[3] ^= 0x7f; c[4] ^= 0x7f;     /* break the structure */
    BOOL ok = qblob(c, sizeof v_o_pfx, QC_PFX, QF_BIN, &r);
    CHECK(ok == FALSE); free(c);
}
TEST(query_cert_pair_outputs) {
    REQUIRE(CQ);
    QR r; CHECK(qblob(v_o_pair, sizeof v_o_pair, QC_PAIR, QF_BIN, &r));
    EXPECT_EQ(r.ct, T_PAIR); CHECK(r.st != NULL); CHECK(r.msg == NULL);
    if (r.st) { int n = mh_count_certs(r.st); EXPECT_EQ(n, 2); }
    qfree(&r);
    CHECK(qblob(v_o_pair_fwd, sizeof v_o_pair_fwd, QC_PAIR, QF_BIN, &r));
    EXPECT_EQ(r.ct, T_PAIR); if (r.st) EXPECT_EQ(mh_count_certs(r.st), 1);
    qfree(&r);
}
TEST(query_cert_pair_not_a_cert) {
    REQUIRE(CQ);
    QR r; BOOL ok = qblob(v_o_pair, sizeof v_o_pair, QC_CERT, QF_BIN, &r);
    EXPECT_EQ(ok, FALSE); EXPECT_EQ(r.err, E_CRYPT_E_NO_MATCH);
}
TEST(query_priority_cert_before_everything) {
    REQUIRE(CQ); BIN_INIT();
    QR r; CHECK(qblob(v_o_cert, sizeof v_o_cert, QC_ALL & ~QC_CERT, QF_BIN, &r) == FALSE);
    qfree(&r);
    CHECK(qblob(v_o_cert, sizeof v_o_cert, QC_ALL, QF_BIN, &r)); EXPECT_EQ(r.ct, T_CERT); qfree(&r);
}

/* ---- serialized forms ------------------------------------------------------------------------ */
static BYTE *ser_cert(DWORD *pn) {
    PCCERT_CONTEXT c = U(CertCreateCertificateContext)(ENC, v_o_cert, sizeof v_o_cert);
    DWORD n = 0; if (!c) return NULL;
    BYTE *b = NULL;
    if (U(CertSerializeCertificateStoreElement)(c, 0, NULL, &n)) { b = malloc(n); if (!U(CertSerializeCertificateStoreElement)(c, 0, b, &n)) { free(b); b = NULL; } }
    U(CertFreeCertificateContext)(c); *pn = n; return b;
}
static BYTE *ser_crl(DWORD *pn) {
    PCCRL_CONTEXT c = U(CertCreateCRLContext)(ENC, v_o_crl, sizeof v_o_crl); DWORD n = 0; BYTE *b = NULL; if (!c) return NULL;
    if (U(CertSerializeCRLStoreElement)(c, 0, NULL, &n)) { b = malloc(n); if (!U(CertSerializeCRLStoreElement)(c, 0, b, &n)) { free(b); b = NULL; } }
    U(CertFreeCRLContext)(c); *pn = n; return b;
}
static BYTE *ser_ctl(DWORD *pn) {
    PCCTL_CONTEXT c = U(CertCreateCTLContext)(ENC, g_ctl, g_ctl_n); DWORD n = 0; BYTE *b = NULL; if (!c) return NULL;
    if (U(CertSerializeCTLStoreElement)(c, 0, NULL, &n)) { b = malloc(n); if (!U(CertSerializeCTLStoreElement)(c, 0, b, &n)) { free(b); b = NULL; } }
    U(CertFreeCTLContext)(c); *pn = n; return b;
}
static BYTE *ser_store(DWORD *pn) {
    HCERTSTORE s = U(CertOpenStore)(CERT_STORE_PROV_MEMORY, 0, 0, 0, NULL);
    U(CertAddEncodedCertificateToStore)(s, ENC, v_o_cert, sizeof v_o_cert, CERT_STORE_ADD_ALWAYS, NULL);
    U(CertAddEncodedCertificateToStore)(s, ENC, v_s2_cert, sizeof v_s2_cert, CERT_STORE_ADD_ALWAYS, NULL);
    CRYPT_DATA_BLOB b = { 0, NULL };
    BYTE *out = NULL;
    if (U(CertSaveStore)(s, ENC, CERT_STORE_SAVE_AS_STORE, CERT_STORE_SAVE_TO_MEMORY, &b, 0)) {
        b.pbData = malloc(b.cbData);
        if (U(CertSaveStore)(s, ENC, CERT_STORE_SAVE_AS_STORE, CERT_STORE_SAVE_TO_MEMORY, &b, 0)) { out = b.pbData; *pn = b.cbData; } else free(b.pbData);
    }
    U(CertCloseStore)(s, 0); return out;
}
TEST(query_serialized_cert) {
    REQUIRE(CQ); REQUIRE(U(CertSerializeCertificateStoreElement));
    DWORD n = 0; BYTE *b = ser_cert(&n); CHECK(b != NULL); if (!b) return;
    QR r; BOOL ok = qblob(b, n, QC_SCERT, QF_BIN, &r);
    CHECKF(ok, "err 0x%lx", r.err);
    if (ok) { EXPECT_EQ(r.ct, T_SCERT); CHECK(CERT_IS((PCCERT_CONTEXT)r.ctx, v_o_cert)); CHECK(r.st != NULL); CHECK(r.msg == NULL); EXPECT_EQ(r.enc, 1); EXPECT_EQ(r.ft, 1); }
    qfree(&r);
    ok = qblob(b, n, QC_CERT, QF_BIN, &r); EXPECT_EQ(ok, FALSE); EXPECT_EQ(r.err, E_CRYPT_E_NO_MATCH);
    ok = qblob(b, n, QC_ALL, QF_BIN, &r); CHECK(ok); if (ok) EXPECT_EQ(r.ct, T_SCERT);
    qfree(&r); free(b);
}
TEST(query_serialized_crl) {
    REQUIRE(CQ); REQUIRE(U(CertSerializeCRLStoreElement));
    DWORD n = 0; BYTE *b = ser_crl(&n); CHECK(b != NULL); if (!b) return;
    QR r; BOOL ok = qblob(b, n, QC_SCRL, QF_BIN, &r);
    CHECKF(ok, "err 0x%lx", r.err);
    if (ok) { EXPECT_EQ(r.ct, T_SCRL); CHECK(r.ctx != NULL); CHECK(r.st != NULL); }
    qfree(&r);
    ok = qblob(b, n, QC_SCERT | QC_SCTL, QF_BIN, &r); EXPECT_EQ(ok, FALSE); EXPECT_EQ(r.err, E_CRYPT_E_NO_MATCH);
    free(b);
}
TEST(query_serialized_ctl) {
    REQUIRE(CQ); BIN_INIT(); REQUIRE(U(CertSerializeCTLStoreElement));
    DWORD n = 0; BYTE *b = ser_ctl(&n); CHECK(b != NULL); if (!b) return;
    QR r; BOOL ok = qblob(b, n, QC_SCTL, QF_BIN, &r);
    CHECKF(ok, "err 0x%lx", r.err);
    if (ok) { EXPECT_EQ(r.ct, T_SCTL); CHECK(r.ctx != NULL); CHECK(r.st != NULL); EXPECT_EQ(r.enc, 0x10001); /* observed: X509 | PKCS7 */ }
    qfree(&r);
    ok = qblob(b, n, QC_SCERT | QC_SCRL, QF_BIN, &r); EXPECT_EQ(ok, FALSE); EXPECT_EQ(r.err, E_CRYPT_E_NO_MATCH);
    free(b);
}
TEST(query_serialized_store) {
    REQUIRE(CQ); REQUIRE(U(CertSaveStore));
    DWORD n = 0; BYTE *b = ser_store(&n); CHECK(b != NULL); if (!b) return;
    QR r; BOOL ok = qblob(b, n, QC_SSTORE, QF_BIN, &r);
    CHECKF(ok, "err 0x%lx", r.err);
    if (ok) { EXPECT_EQ(r.ct, T_SSTORE); CHECK(r.st != NULL); CHECK(r.msg == NULL); CHECK(r.ctx == NULL); EXPECT_EQ(r.enc, 0x10001); if (r.st) EXPECT_EQ(mh_count_certs(r.st), 2); }
    qfree(&r);
    ok = qblob(b, n, QC_ALL, QF_BIN, &r);
    CHECK(ok); if (ok) EXPECT_EQ(r.ct, T_SSTORE);
    qfree(&r);
    ok = qblob(b, n, QC_CERT | QC_CRL | QC_P7S | QC_SCERT, QF_BIN, &r); EXPECT_EQ(ok, FALSE);
    free(b);
}
TEST(query_serialized_store_empty) {
    REQUIRE(CQ); REQUIRE(U(CertSaveStore));
    HCERTSTORE s = U(CertOpenStore)(CERT_STORE_PROV_MEMORY, 0, 0, 0, NULL);
    CRYPT_DATA_BLOB b = { 0, NULL };
    CHECK(U(CertSaveStore)(s, ENC, CERT_STORE_SAVE_AS_STORE, CERT_STORE_SAVE_TO_MEMORY, &b, 0));
    b.pbData = malloc(b.cbData);
    CHECK(U(CertSaveStore)(s, ENC, CERT_STORE_SAVE_AS_STORE, CERT_STORE_SAVE_TO_MEMORY, &b, 0));
    QR r; BOOL ok = qblob(b.pbData, b.cbData, QC_SSTORE, QF_BIN, &r);
    CHECKF(ok, "err 0x%lx", r.err); /* observed: an empty serialized store (20 bytes) is recognised */
    EXPECT_EQ(b.cbData, 20);
    if (ok) { CHECK(r.st != NULL); EXPECT_EQ(mh_count_certs(r.st), 0); }
    qfree(&r); free(b.pbData); U(CertCloseStore)(s, 0);
}

/* ---- text encodings --------------------------------------------------------------------------- */
TEST(query_base64_without_header) {
    REQUIRE(CQ);
    DWORD n = 0; char *s = mh_to_b64(v_o_cert, sizeof v_o_cert, CRYPT_STRING_BASE64, &n); CHECK(s != NULL); if (!s) return;
    QR r; BOOL ok = qblob((BYTE *)s, n, QC_CERT, QF_B64, &r);
    CHECKF(ok, "err 0x%lx", r.err);
    if (ok) { EXPECT_EQ(r.ct, T_CERT); EXPECT_EQ(r.ft, 2); CHECK(CERT_IS((PCCERT_CONTEXT)r.ctx, v_o_cert)); EXPECT_EQ(r.enc, 1); }
    qfree(&r);
    ok = qblob((BYTE *)s, n, QC_CERT, QF_BIN, &r); EXPECT_EQ(ok, FALSE); EXPECT_EQ(r.err, E_CRYPT_E_NO_MATCH);
    ok = qblob((BYTE *)s, n, QC_CERT, QF_HEX, &r); EXPECT_EQ(ok, FALSE); EXPECT_EQ(r.err, E_CRYPT_E_NO_MATCH);
    ok = qblob((BYTE *)s, n, QC_CERT, QF_BIN | QF_B64, &r); CHECK(ok); if (ok) EXPECT_EQ(r.ft, 2);
    qfree(&r); free(s);
}
TEST(query_base64_with_pem_header) {
    REQUIRE(CQ);
    DWORD n = 0; char *s = mh_to_b64(v_o_cert, sizeof v_o_cert, CRYPT_STRING_BASE64HEADER, &n); CHECK(s != NULL); if (!s) return;
    CHECK(strstr(s, "-----BEGIN CERTIFICATE-----") != NULL);
    QR r; BOOL ok = qblob((BYTE *)s, n, QC_CERT, QF_B64, &r);
    CHECKF(ok, "err 0x%lx", r.err);
    if (ok) { EXPECT_EQ(r.ct, T_CERT); EXPECT_EQ(r.ft, 2); }
    qfree(&r); free(s);
}
TEST(query_base64_crlf_variants) {
    REQUIRE(CQ);
    static const DWORD f[] = { CRYPT_STRING_BASE64, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCR, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF };
    for (int i = 0; i < 3; i++) {
        DWORD n = 0; char *s = mh_to_b64(v_o_crl, sizeof v_o_crl, f[i], &n);
        CHECKF(s != NULL, "CryptBinaryToString flags 0x%lx", f[i]); if (!s) continue;
        QR r; BOOL ok = qblob((BYTE *)s, n, QC_CRL, QF_B64, &r);
        CHECKF(ok, "flags 0x%lx: err 0x%lx", f[i], r.err);
        if (ok) { EXPECT_EQ(r.ct, T_CRL); EXPECT_EQ(r.ft, 2); }
        qfree(&r); free(s);
    }
}
TEST(query_base64_pkcs7_and_crl_and_pair) {
    REQUIRE(CQ); BIN_INIT();
    for (int i = 0; i < NBIN; i++) {
        if (g_bin[i].ct == T_PFX) continue;
        DWORD n = 0; char *s = mh_to_b64(g_bin[i].p, g_bin[i].n, CRYPT_STRING_BASE64HEADER, &n);
        if (!s) continue;
        QR r; BOOL ok = qblob((BYTE *)s, n, g_bin[i].mask, QF_B64, &r);
        CHECKF(ok, "%s: err 0x%lx", g_bin[i].name, r.err);
        if (ok) { EXPECT_EQ(r.ct, g_bin[i].ct); EXPECT_EQ(r.ft, 2); }
        qfree(&r); free(s);
    }
}
TEST(query_base64_pfx_text) {
    REQUIRE(CQ);
    DWORD n = 0; char *s = mh_to_b64(v_o_pfx, sizeof v_o_pfx, CRYPT_STRING_BASE64, &n); CHECK(s != NULL); if (!s) return;
    QR r; BOOL ok = qblob((BYTE *)s, n, QC_PFX, QF_B64, &r);
    CHECKF(ok, "err 0x%lx", r.err); if (ok) { EXPECT_EQ(r.ct, T_PFX); EXPECT_EQ(r.ft, 2); }
    qfree(&r); free(s);
}
TEST(query_base64_garbage) {
    REQUIRE(CQ);
    static const char g[] = "this is not base64 data !!! ###";
    QR r; BOOL ok = qblob((const BYTE *)g, sizeof g - 1, QC_ALL, QF_B64, &r);
    EXPECT_EQ(ok, FALSE); EXPECT_EQ(r.err, E_CRYPT_E_NO_MATCH);
    static const char g2[] = "QUJDRA==";    /* valid base64 of "ABCD": decodes, but is no known object */
    ok = qblob((const BYTE *)g2, sizeof g2 - 1, QC_ALL, QF_B64, &r);
    EXPECT_EQ(ok, FALSE); EXPECT_EQ(r.err, E_CRYPT_E_NO_MATCH);
}
TEST(query_ascii_hex_cert) {
    REQUIRE(CQ);
    DWORD n = 0; char *s = mh_to_asnhex(v_o_cert, sizeof v_o_cert, &n);
    QR r; BOOL ok = qblob((BYTE *)s, n, QC_CERT, QF_HEX, &r);
    CHECKF(ok, "err 0x%lx", r.err);
    if (ok) { EXPECT_EQ(r.ct, T_CERT); EXPECT_EQ(r.ft, 3); CHECK(CERT_IS((PCCERT_CONTEXT)r.ctx, v_o_cert)); }
    qfree(&r);
    ok = qblob((BYTE *)s, n, QC_CERT, QF_BIN | QF_B64, &r); EXPECT_EQ(ok, FALSE);
    ok = qblob((BYTE *)s, n, QC_ALL, QF_ALL, &r); CHECK(ok); if (ok) EXPECT_EQ(r.ft, 3);
    qfree(&r); free(s);
}
TEST(query_ascii_hex_prefix_case_insensitive) {
    REQUIRE(CQ);
    DWORD n = 0; char *s = mh_to_asnhex(v_o_crl, sizeof v_o_crl, &n);
    memcpy(s, "{asn}", 5);
    QR r; BOOL ok = qblob((BYTE *)s, n, QC_CRL, QF_HEX, &r);
    CHECKF(ok, "err 0x%lx", r.err); if (ok) { EXPECT_EQ(r.ct, T_CRL); EXPECT_EQ(r.ft, 3); }
    qfree(&r);
    memcpy(s, "{AsN}", 5);
    ok = qblob((BYTE *)s, n, QC_CRL, QF_HEX, &r); CHECK(ok); qfree(&r);
    memcpy(s, "{ASX}", 5);
    ok = qblob((BYTE *)s, n, QC_CRL, QF_HEX, &r); CHECK(!ok); EXPECT_EQ(r.err, E_CRYPT_E_NO_MATCH);
    free(s);
}
TEST(query_ascii_hex_lowercase_digits) {
    REQUIRE(CQ);
    DWORD n = 0; char *s = mh_to_asnhex(v_o_cert, sizeof v_o_cert, &n);
    for (DWORD i = 5; i < n; i++) if (s[i] >= 'A' && s[i] <= 'F') s[i] += 32;
    QR r; BOOL ok = qblob((BYTE *)s, n, QC_CERT, QF_HEX, &r);
    CHECKF(ok, "err 0x%lx", r.err); if (ok) { EXPECT_EQ(r.ct, T_CERT); EXPECT_EQ(r.ft, 3); }
    qfree(&r); free(s);
}
TEST(query_ascii_hex_invalid_digits_is_invalid_data) {
    REQUIRE(CQ);
    static const char *bad[] = { "{ASN}0", "{ASN}zz", "{ASN}30 82 01", "{ASN}3082\r\n0102", "{ASN}30820g", "{ASN}308" };
    for (int i = 0; i < 6; i++) {
        QR r; BOOL ok = qblob((const BYTE *)bad[i], (DWORD)strlen(bad[i]), QC_ALL, QF_HEX, &r);
        CHECKF(!ok, "'%s'", bad[i]);
        CHECKF(r.err == ERROR_INVALID_DATA, "'%s' -> 0x%lx", bad[i], r.err);
        qfree(&r);
    }
}
TEST(query_ascii_hex_valid_hex_but_not_an_object) {
    REQUIRE(CQ);
    static const char *g[] = { "{ASN}3082", "{ASN}00", "{ASN}41424344", "{ASN}3003020101" };
    for (int i = 0; i < 4; i++) {
        QR r; BOOL ok = qblob((const BYTE *)g[i], (DWORD)strlen(g[i]), QC_ALL, QF_HEX, &r);
        CHECKF(!ok, "'%s'", g[i]); CHECKF(r.err == E_CRYPT_E_NO_MATCH, "'%s' -> 0x%lx", g[i], r.err);
        qfree(&r);
    }
}
TEST(query_ascii_hex_prefix_only_or_short) {
    REQUIRE(CQ);
    QR r; BOOL ok = qblob((const BYTE *)"{ASN}", 5, QC_ALL, QF_HEX, &r);
    EXPECT_EQ(ok, FALSE); EXPECT_EQ(r.err, E_CRYPT_E_NO_MATCH);
    ok = qblob((const BYTE *)"{ASN", 4, QC_ALL, QF_HEX, &r);
    EXPECT_EQ(ok, FALSE); EXPECT_EQ(r.err, E_CRYPT_E_NO_MATCH);
    ok = qblob((const BYTE *)"3082", 4, QC_ALL, QF_HEX, &r);       /* no prefix: not hex text */
    EXPECT_EQ(ok, FALSE); EXPECT_EQ(r.err, E_CRYPT_E_NO_MATCH);
}
TEST(query_ascii_hex_all_types_table) {
    REQUIRE(CQ); BIN_INIT();
    for (int i = 0; i < NBIN; i++) {
        DWORD n = 0; char *s = mh_to_asnhex(g_bin[i].p, g_bin[i].n, &n);
        QR r; BOOL ok = qblob((BYTE *)s, n, g_bin[i].mask, QF_HEX, &r);
        CHECKF(ok, "%s: err 0x%lx", g_bin[i].name, r.err);
        if (ok) { EXPECT_EQ(r.ct, g_bin[i].ct); EXPECT_EQ(r.ft, 3); }
        qfree(&r); free(s);
    }
}
TEST(query_format_precedence_binary_first) {
    REQUIRE(CQ);
    QR r; CHECK(qblob(v_o_cert, sizeof v_o_cert, QC_CERT, QF_ALL, &r)); EXPECT_EQ(r.ft, 1); qfree(&r);
}
TEST(query_utf16_base64_text) {
    REQUIRE(CQ);
    DWORD n = 0; char *s = mh_to_b64(v_o_cert, sizeof v_o_cert, CRYPT_STRING_BASE64, &n); CHECK(s != NULL); if (!s) return;
    WCHAR *w = calloc(n + 2, sizeof(WCHAR)); /* even-aligned heap block */
    for (DWORD i = 0; i < n; i++) w[i] = (unsigned char)s[i];
    QR r; BOOL ok = qblob((BYTE *)w, n * 2, QC_CERT, QF_B64, &r);
    CHECKF(ok, "err 0x%lx", r.err); /* observed: UTF-16 base64 text is recognised */
    if (ok) { EXPECT_EQ(r.ct, T_CERT); EXPECT_EQ(r.ft, 2); }
    qfree(&r); free(w); free(s);
}
TEST(query_truncated_and_corrupted_objects) {
    REQUIRE(CQ); BIN_INIT();
    for (int i = 0; i < NBIN; i++) {
        /* observed: every kind of object, the PFX included, is rejected as NO_MATCH when cut to half or by one byte */
        t_label("%s", g_bin[i].name);
        QR r; BOOL ok = qblob(g_bin[i].p, g_bin[i].n / 2, g_bin[i].mask, QF_BIN, &r);
        CHECK(!ok); EXPECT_EQ(r.err, E_CRYPT_E_NO_MATCH);
        qfree(&r);
        ok = qblob(g_bin[i].p, g_bin[i].n - 1, g_bin[i].mask, QF_BIN, &r);
        CHECK(!ok); EXPECT_EQ(r.err, E_CRYPT_E_NO_MATCH);
        qfree(&r);
    }
}
TEST(query_trailing_data_after_cert) {
    REQUIRE(CQ);
    BYTE *b = malloc(sizeof v_o_cert + 8); memcpy(b, v_o_cert, sizeof v_o_cert); memset(b + sizeof v_o_cert, 0, 8);
    QR r; BOOL ok = qblob(b, sizeof v_o_cert + 8, QC_CERT, QF_BIN, &r);
    CHECKF(ok, "err 0x%lx", r.err); EXPECT_EQ(r.ct, T_CERT); /* observed: trailing bytes are ignored */
    qfree(&r); free(b);
}

/* ---- file objects ---------------------------------------------------------------------------- */
static void write_file(const char *leaf, const void *p, DWORD n, WCHAR *wpath) {
    char path[MAX_PATH]; t_tmpfile(path, sizeof path, leaf);
    HANDLE h = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD w = 0; if (h != INVALID_HANDLE_VALUE) { WriteFile(h, p, n, &w, NULL); CloseHandle(h); }
    MultiByteToWideChar(CP_ACP, 0, path, -1, wpath, MAX_PATH);
}
static BOOL qfile(const WCHAR *path, DWORD cmask, DWORD fmask, QR *r) {
    memset(r, 0, sizeof *r); SET_ERR(0);
    BOOL ok = CQ(CERT_QUERY_OBJECT_FILE, path, cmask, fmask, 0, &r->enc, &r->ct, &r->ft, &r->st, &r->msg, &r->ctx);
    r->err = GetLastError(); return ok;
}
TEST(query_file_binary_table) {
    REQUIRE(CQ); BIN_INIT();
    for (int i = 0; i < NBIN; i++) {
        WCHAR p[MAX_PATH]; char leaf[32]; sprintf(leaf, "qf%d.bin", i);
        write_file(leaf, g_bin[i].p, g_bin[i].n, p);
        QR r; BOOL ok = qfile(p, g_bin[i].mask, QF_BIN, &r);
        CHECKF(ok, "%s: err 0x%lx", g_bin[i].name, r.err);
        if (ok) { EXPECT_EQ(r.ct, g_bin[i].ct); EXPECT_EQ(r.ft, 1); EXPECT_EQ(r.enc, g_bin[i].enc); }
        qfree(&r);
        ok = qfile(p, QC_ALL, QF_ALL, &r);
        CHECKF(ok, "%s (all): err 0x%lx", g_bin[i].name, r.err);
        if (ok) EXPECT_EQ(r.ct, g_bin[i].ct);
        qfree(&r);
    }
}
TEST(query_file_base64_and_hex) {
    REQUIRE(CQ);
    WCHAR p[MAX_PATH]; DWORD n = 0;
    char *s = mh_to_b64(v_o_cert, sizeof v_o_cert, CRYPT_STRING_BASE64HEADER, &n); write_file("qf_pem.cer", s, n, p); free(s);
    QR r; BOOL ok = qfile(p, QC_CERT, QF_B64, &r);
    CHECKF(ok, "pem: err 0x%lx", r.err); if (ok) { EXPECT_EQ(r.ct, T_CERT); EXPECT_EQ(r.ft, 2); } qfree(&r);
    ok = qfile(p, QC_CERT, QF_BIN, &r); EXPECT_EQ(ok, FALSE); EXPECT_EQ(r.err, E_CRYPT_E_NO_MATCH);
    s = mh_to_asnhex(v_o_crl, sizeof v_o_crl, &n); write_file("qf_hex.crl", s, n, p); free(s);
    ok = qfile(p, QC_CRL, QF_HEX, &r);
    CHECKF(ok, "hex: err 0x%lx", r.err); if (ok) { EXPECT_EQ(r.ct, T_CRL); EXPECT_EQ(r.ft, 3); } qfree(&r);
}
TEST(query_file_missing) {
    REQUIRE(CQ);
    WCHAR p[MAX_PATH]; char path[MAX_PATH]; t_tmpfile(path, sizeof path, "no_such_file.cer");
    MultiByteToWideChar(CP_ACP, 0, path, -1, p, MAX_PATH);
    DWORD enc = 9, ct = 9, ft = 9; HCERTSTORE st = (HCERTSTORE)9; SET_ERR(0);
    BOOL r = CQ(CERT_QUERY_OBJECT_FILE, p, QC_ALL, QF_ALL, 0, &enc, &ct, &ft, &st, NULL, NULL);
    EXPECT_FAIL(r == FALSE, 0x80070002u);   /* HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND) */
}
TEST(query_file_missing_directory_component) {
    REQUIRE(CQ);
    SET_ERR(0);
    BOOL r = CQ(CERT_QUERY_OBJECT_FILE, L"Z:\\cryptt_no_such_dir\\x\\y.cer", QC_ALL, QF_ALL, 0, NULL, NULL, NULL, NULL, NULL, NULL);
    CHECK(r == FALSE);
    DWORD e = GetLastError();
    EXPECT_EQ(e, 0x80070003u);   /* HRESULT_FROM_WIN32(ERROR_PATH_NOT_FOUND) */
}
TEST(query_file_empty) {
    REQUIRE(CQ);
    WCHAR p[MAX_PATH]; write_file("qf_empty.cer", "", 0, p);
    QR r; BOOL ok = qfile(p, QC_ALL, QF_ALL, &r);
    EXPECT_EQ(ok, FALSE); EXPECT_EQ(r.err, 0x80004005u); qfree(&r); /* observed: E_FAIL, not NO_MATCH */
}
TEST(query_file_garbage_is_no_match) {
    REQUIRE(CQ);
    WCHAR p[MAX_PATH]; static const char g[] = "hello, this is no certificate\r\n";
    write_file("qf_garbage.dat", g, sizeof g - 1, p);
    QR r; BOOL ok = qfile(p, QC_ALL, QF_ALL, &r);
    EXPECT_EQ(ok, FALSE); EXPECT_EQ(r.err, E_CRYPT_E_NO_MATCH);
}
TEST(query_file_embedded_signature_absent) {
    REQUIRE(CQ);
    WCHAR self[MAX_PATH];
    MultiByteToWideChar(CP_ACP, 0, t_self_path(), -1, self, MAX_PATH);
    QR r; BOOL ok = qfile(self, QC_P7E, QF_BIN, &r);
    EXPECT_EQ(ok, FALSE); EXPECT_EQ(r.err, E_CRYPT_E_NO_MATCH);
    qfree(&r);
}
TEST(query_file_handle_released_after_query) {
    REQUIRE(CQ);
    WCHAR p[MAX_PATH]; write_file("qf_release.cer", v_o_cert, sizeof v_o_cert, p);
    QR r; CHECK(qfile(p, QC_CERT, QF_BIN, &r)); qfree(&r);
    char path[MAX_PATH]; t_tmpfile(path, sizeof path, "qf_release.cer");
    CHECK(DeleteFileA(path));           /* no handle may remain open on the file */
    SET_ERR(0); CHECK(!qfile(p, QC_CERT, QF_BIN, &r)); EXPECT_EQ(r.err, 0x80070002u);
}
TEST(query_file_directory_path) {
    REQUIRE(CQ);
    WCHAR p[MAX_PATH]; MultiByteToWideChar(CP_ACP, 0, t_tmpdir(), -1, p, MAX_PATH);
    QR r; BOOL ok = qfile(p, QC_ALL, QF_ALL, &r);
    EXPECT_EQ(ok, FALSE); EXPECT_EQ(r.err, 0x80004005u); qfree(&r); /* observed: E_FAIL */
}
TEST(query_file_large_nonmatching) {
    REQUIRE(CQ);
    WCHAR p[MAX_PATH]; DWORD sz = 1 << 20; BYTE *d = calloc(1, sz); for (DWORD i = 0; i < sz; i++) d[i] = (BYTE)(i * 13);
    write_file("qf_big.bin", d, sz, p); free(d);
    QR r; BOOL ok = qfile(p, QC_ALL, QF_ALL, &r);
    EXPECT_EQ(ok, FALSE); EXPECT_EQ(r.err, E_CRYPT_E_NO_MATCH);
}

/* ---- store / context interplay ------------------------------------------------------------------ */
TEST(query_returned_store_is_usable) {
    REQUIRE(CQ);
    QR r; CHECK(qblob(v_m_sig_two_noattr, sizeof v_m_sig_two_noattr, QC_P7S, QF_BIN, &r)); if (!r.st) { qfree(&r); return; }
    EXPECT_EQ(mh_count_certs(r.st), 3);
    PCCERT_CONTEXT c = U(CertFindCertificateInStore)(r.st, ENC, 0, CERT_FIND_EXISTING, mh_ids[MH_S2].pub, NULL);
    CHECK(CERT_IS(c, v_s2_cert)); FREE_CERT(c);
    CHECK(U(CertCloseStore)(r.st, CERT_CLOSE_STORE_CHECK_FLAG) || GetLastError() == CRYPT_E_PENDING_CLOSE);
    r.st = NULL; qfree(&r);
}
TEST(query_message_handle_independent_of_store) {
    REQUIRE(CQ);
    QR r; CHECK(qblob(v_m_sig_noattr, sizeof v_m_sig_noattr, QC_P7S, QF_BIN, &r)); if (!r.st || !r.msg) { qfree(&r); return; }
    CHECK(U(CertCloseStore)(r.st, 0)); r.st = NULL;
    DWORD n = 0; CHECK(U(CryptMsgGetParam)(r.msg, CMSG_CONTENT_PARAM, 0, NULL, &n)); EXPECT_EQ(n, sizeof v_payload);
    qfree(&r);
}
TEST(query_source_buffer_may_be_released) {
    REQUIRE(CQ);
    BYTE *b = dup_(v_o_cert, sizeof v_o_cert);
    QR r; CHECK(qblob(b, sizeof v_o_cert, QC_CERT, QF_BIN, &r));
    memset(b, 0, sizeof v_o_cert); free(b);
    CHECK(CERT_IS((PCCERT_CONTEXT)r.ctx, v_o_cert));
    qfree(&r);
    b = dup_(v_m_sig_noattr, sizeof v_m_sig_noattr);
    CHECK(qblob(b, sizeof v_m_sig_noattr, QC_P7S, QF_BIN, &r));
    memset(b, 0, sizeof v_m_sig_noattr); free(b);
    DWORD n = 0; CHECK(U(CryptMsgGetParam)(r.msg, CMSG_CONTENT_PARAM, 0, NULL, &n)); EXPECT_EQ(n, sizeof v_payload);
    qfree(&r);
}
TEST(query_dwflags_zero_vs_unknown) {
    REQUIRE(CQ);
    CERT_BLOB b = { sizeof v_o_cert, (BYTE *)v_o_cert }; DWORD ct = 0;
    SET_ERR(0); BOOL r = CQ(CERT_QUERY_OBJECT_BLOB, &b, QC_CERT, QF_BIN, 0x1234, NULL, &ct, NULL, NULL, NULL, NULL);
    CHECKF(r, "err 0x%lx", GetLastError()); /* observed: unknown flag bits are ignored */
}
