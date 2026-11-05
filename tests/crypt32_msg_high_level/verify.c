/* CryptVerifyMessageSignature, CryptVerifyDetachedMessageSignature, CryptVerifyMessageSignatureWithKey,
 * CryptGetMessageSignerCount, CryptGetMessageCertificates. */
#include "mh.h"
#include <stdlib.h>

#define PL v_payload, (DWORD)sizeof v_payload
#define VMS U(CryptVerifyMessageSignature)

static const struct { const char *name; const BYTE *p; DWORD cb; int signers; } g_ext[] = {
    { "attr",       v_m_sig_attr,       sizeof v_m_sig_attr, 1 },
    { "noattr",     v_m_sig_noattr,     sizeof v_m_sig_noattr, 1 },
    { "two",        v_m_sig_two_noattr, sizeof v_m_sig_two_noattr, 2 },
    { "sha1",       v_m_sig_sha1,       sizeof v_m_sig_sha1, 1 },
    { "sha512",     v_m_sig_sha512,     sizeof v_m_sig_sha512, 1 },
};

TEST(mh_verify_roundtrip_embedded_signer_cert) {
    MH_INIT(); REQUIRE(VMS); REQUIRE(U(CryptSignMessage));
    CRYPT_SIGN_MESSAGE_PARA p; mh_sign_para(&p, MH_S1, OID_SHA256);
    PCCERT_CONTEXT mc[1] = { mh_ids[MH_S1].pub }; p.cMsgCert = 1; p.rgpMsgCert = mc;
    const BYTE *a[1] = { v_payload }; DWORD l[1] = { sizeof v_payload };
    DWORD n = 0; CHECK(U(CryptSignMessage)(&p, FALSE, 1, a, l, NULL, &n));
    BYTE *b = malloc(n); CHECK(U(CryptSignMessage)(&p, FALSE, 1, a, l, b, &n));
    CRYPT_VERIFY_MESSAGE_PARA vp; mh_verify_para(&vp);
    BYTE d[200]; DWORD dn = sizeof d; PCCERT_CONTEXT sc = (PCCERT_CONTEXT)1;
    SET_ERR(0);
    BOOL r = VMS(&vp, 0, b, n, d, &dn, &sc);
    CHECKF(r, "err 0x%lx", GetLastError());
    EXPECT_EQ(dn, sizeof v_payload); CHECK(!memcmp(d, v_payload, sizeof v_payload));
    CHECK(CERT_IS(sc, v_s1_cert));
    FREE_CERT(sc); free(b);
}
TEST(mh_verify_external_messages_table) {
    MH_INIT(); REQUIRE(VMS);
    for (unsigned i = 0; i < sizeof g_ext / sizeof g_ext[0]; i++) {
        CRYPT_VERIFY_MESSAGE_PARA vp; mh_verify_para(&vp);
        BYTE d[200]; DWORD dn = sizeof d; PCCERT_CONTEXT sc = NULL; SET_ERR(0);
        BOOL r = VMS(&vp, 0, (BYTE *)g_ext[i].p, g_ext[i].cb, d, &dn, &sc);
        CHECKF(r, "%s: err 0x%lx", g_ext[i].name, GetLastError());
        if (r) { EXPECT_EQ(dn, sizeof v_payload); CHECK(!memcmp(d, v_payload, dn)); CHECKF(CERT_IS(sc, v_s1_cert), "%s signer cert", g_ext[i].name); }
        FREE_CERT(sc);
    }
}
TEST(mh_verify_external_second_signer_index) {
    MH_INIT(); REQUIRE(VMS);
    CRYPT_VERIFY_MESSAGE_PARA vp; mh_verify_para(&vp);
    for (DWORD idx = 0; idx < 2; idx++) {
        BYTE d[200]; DWORD dn = sizeof d; PCCERT_CONTEXT sc = NULL; SET_ERR(0);
        BOOL r = VMS(&vp, idx, (BYTE *)v_m_sig_two_noattr, sizeof v_m_sig_two_noattr, d, &dn, &sc);
        CHECKF(r, "idx %lu err 0x%lx", idx, GetLastError());
        if (r) { CHECK(idx == 0 ? CERT_IS(sc, v_s1_cert) : CERT_IS(sc, v_s2_cert)); EXPECT_EQ(dn, sizeof v_payload); }
        FREE_CERT(sc);
    }
}
TEST(mh_verify_signer_index_out_of_range) {
    MH_INIT(); REQUIRE(VMS);
    CRYPT_VERIFY_MESSAGE_PARA vp; mh_verify_para(&vp);
    static const DWORD idx[] = { 2, 3, 100, 0xFFFFFFFF };
    for (unsigned i = 0; i < 4; i++) {
        BYTE d[200]; DWORD dn = sizeof d; PCCERT_CONTEXT sc = (PCCERT_CONTEXT)1; SET_ERR(0);
        BOOL r = VMS(&vp, idx[i], (BYTE *)v_m_sig_two_noattr, sizeof v_m_sig_two_noattr, d, &dn, &sc);
        EXPECT_FAIL(r == FALSE, E_CRYPT_E_NO_SIGNER);
        CHECK(sc == NULL);
        EXPECT_EQ(dn, 0);
    }
}
TEST(mh_verify_signer_index_one_on_single_signer) {
    MH_INIT(); REQUIRE(VMS);
    CRYPT_VERIFY_MESSAGE_PARA vp; mh_verify_para(&vp);
    BYTE d[200]; DWORD dn = sizeof d; SET_ERR(0);
    BOOL r = VMS(&vp, 1, (BYTE *)v_m_sig_noattr, sizeof v_m_sig_noattr, d, &dn, NULL);
    EXPECT_FAIL(r == FALSE, E_CRYPT_E_NO_SIGNER);
}
TEST(mh_verify_size_query_null_buffer) {
    MH_INIT(); REQUIRE(VMS);
    CRYPT_VERIFY_MESSAGE_PARA vp; mh_verify_para(&vp);
    DWORD dn = 0xdead; SET_ERR(0);
    BOOL r = VMS(&vp, 0, (BYTE *)v_m_sig_noattr, sizeof v_m_sig_noattr, NULL, &dn, NULL);
    CHECK(r); EXPECT_EQ(dn, sizeof v_payload);
}
TEST(mh_verify_size_query_does_not_verify_signature) {
    MH_INIT(); REQUIRE(VMS);
    BYTE *b = malloc(sizeof v_m_sig_noattr); memcpy(b, v_m_sig_noattr, sizeof v_m_sig_noattr);
    b[sizeof v_m_sig_noattr - 5] ^= 0x55;        /* inside the signature value */
    CRYPT_VERIFY_MESSAGE_PARA vp; mh_verify_para(&vp);
    DWORD dn = 0; SET_ERR(0);
    BOOL r = VMS(&vp, 0, b, sizeof v_m_sig_noattr, NULL, &dn, NULL);
    CHECKF(r, "length-only decode of a corrupt signature, err 0x%lx", GetLastError());
    EXPECT_EQ(dn, sizeof v_payload);
    BYTE d[100]; dn = sizeof d; SET_ERR(0);
    r = VMS(&vp, 0, b, sizeof v_m_sig_noattr, d, &dn, NULL);
    EXPECT_FAIL(r == FALSE, E_STATUS_INVALID_SIGNATURE);
    dn = 0; PCCERT_CONTEXT sc = NULL;
    r = VMS(&vp, 0, b, sizeof v_m_sig_noattr, NULL, &dn, &sc);   /* asking for the signer forces verification */
    CHECK(r == FALSE); CHECK(sc == NULL); FREE_CERT(sc);
    free(b);
}
TEST(mh_verify_only_no_outputs) {
    MH_INIT(); REQUIRE(VMS);
    CRYPT_VERIFY_MESSAGE_PARA vp; mh_verify_para(&vp);
    SET_ERR(0);
    CHECK(VMS(&vp, 0, (BYTE *)v_m_sig_noattr, sizeof v_m_sig_noattr, NULL, NULL, NULL));
    BYTE *b = malloc(sizeof v_m_sig_noattr); memcpy(b, v_m_sig_noattr, sizeof v_m_sig_noattr);
    b[sizeof v_m_sig_noattr - 5] ^= 0x55;
    CHECK(!VMS(&vp, 0, b, sizeof v_m_sig_noattr, NULL, NULL, NULL));
    free(b);
}
TEST(mh_verify_buffer_too_small_more_data) {
    MH_INIT(); REQUIRE(VMS);
    CRYPT_VERIFY_MESSAGE_PARA vp; mh_verify_para(&vp);
    static const DWORD sizes[] = { 0, 1, sizeof v_payload - 1 };
    for (unsigned i = 0; i < 3; i++) {
        BYTE d[200]; memset(d, 0x77, sizeof d); DWORD dn = sizes[i]; PCCERT_CONTEXT sc = (PCCERT_CONTEXT)1; SET_ERR(0);
        BOOL r = VMS(&vp, 0, (BYTE *)v_m_sig_noattr, sizeof v_m_sig_noattr, sizes[i] ? d : d, &dn, &sc);
        if (sizes[i] == 0) { /* non-NULL buffer, zero size: still a failing size report */ }
        EXPECT_FAIL(r == FALSE, ERROR_MORE_DATA);
        EXPECT_EQ(dn, sizeof v_payload);
        CHECK(sc == NULL);
        CHECK(d[0] == 0x77 || sizes[i] > 0);
    }
}
TEST(mh_verify_exact_buffer_and_oversized_buffer) {
    MH_INIT(); REQUIRE(VMS);
    CRYPT_VERIFY_MESSAGE_PARA vp; mh_verify_para(&vp);
    BYTE d[300]; memset(d, 0x77, sizeof d); DWORD dn = sizeof v_payload;
    CHECK(VMS(&vp, 0, (BYTE *)v_m_sig_noattr, sizeof v_m_sig_noattr, d, &dn, NULL));
    EXPECT_EQ(dn, sizeof v_payload); CHECK(d[sizeof v_payload] == 0x77);
    dn = sizeof d;
    CHECK(VMS(&vp, 0, (BYTE *)v_m_sig_noattr, sizeof v_m_sig_noattr, d, &dn, NULL));
    EXPECT_EQ(dn, sizeof v_payload); CHECK(d[sizeof v_payload] == 0x77);
}
TEST(mh_verify_cbsize_too_small) {
    MH_INIT(); REQUIRE(VMS);
    static const DWORD sizes[] = { 0, 4, 0x10, 0x18, 0x1f };
    for (unsigned i = 0; i < 5; i++) {
        CRYPT_VERIFY_MESSAGE_PARA vp; mh_verify_para(&vp); vp.cbSize = sizes[i];
        BYTE d[100]; DWORD dn = sizeof d; PCCERT_CONTEXT sc = (PCCERT_CONTEXT)1; SET_ERR(0);
        BOOL r = VMS(&vp, 0, (BYTE *)v_m_sig_noattr, sizeof v_m_sig_noattr, d, &dn, &sc);
        EXPECT_FAIL(r == FALSE, E_INVALIDARG_);
        EXPECT_EQ(dn, 0); CHECK(sc == NULL);
    }
}
TEST(mh_verify_cbsize_too_small_size_query) {
    MH_INIT(); REQUIRE(VMS);
    CRYPT_VERIFY_MESSAGE_PARA vp; mh_verify_para(&vp); vp.cbSize = 8;
    DWORD dn = 5; SET_ERR(0);
    BOOL r = VMS(&vp, 0, (BYTE *)v_m_sig_noattr, sizeof v_m_sig_noattr, NULL, &dn, NULL);
    EXPECT_FAIL(r == FALSE, E_INVALIDARG_); EXPECT_EQ(dn, 0);
}
TEST(mh_verify_cbsize_larger_is_accepted) {
    MH_INIT(); REQUIRE(VMS);
    BYTE para[128]; memset(para, 0, sizeof para);
    CRYPT_VERIFY_MESSAGE_PARA *vp = (CRYPT_VERIFY_MESSAGE_PARA *)para;
    vp->cbSize = 0x20; vp->dwMsgAndCertEncodingType = ENC;
    DWORD dn = 0; CHECK(VMS(vp, 0, (BYTE *)v_m_sig_noattr, sizeof v_m_sig_noattr, NULL, &dn, NULL));
    vp->cbSize = 0x28;     /* with the strong-sign pointer field, zero */
    dn = 0; CHECK(VMS(vp, 0, (BYTE *)v_m_sig_noattr, sizeof v_m_sig_noattr, NULL, &dn, NULL));
    vp->cbSize = 0x80;
    dn = 0; CHECK(VMS(vp, 0, (BYTE *)v_m_sig_noattr, sizeof v_m_sig_noattr, NULL, &dn, NULL));
}
TEST(mh_verify_signer_cert_missing_not_found) {
    MH_INIT(); REQUIRE(VMS);
    CRYPT_VERIFY_MESSAGE_PARA vp; mh_verify_para(&vp);
    BYTE d[100]; DWORD dn = sizeof d; PCCERT_CONTEXT sc = (PCCERT_CONTEXT)1; SET_ERR(0);
    BOOL r = VMS(&vp, 0, (BYTE *)v_m_sig_nocert, sizeof v_m_sig_nocert, d, &dn, &sc);
    EXPECT_FAIL(r == FALSE, E_CRYPT_E_NOT_FOUND);
    CHECK(sc == NULL); EXPECT_EQ(dn, 0);
}
TEST(mh_verify_callback_supplies_missing_signer) {
    MH_INIT(); REQUIRE(VMS);
    CRYPT_VERIFY_MESSAGE_PARA vp; mh_verify_para_cb(&vp);
    BYTE d[100]; DWORD dn = sizeof d; PCCERT_CONTEXT sc = NULL; mh_cb_calls = 0; SET_ERR(0);
    BOOL r = VMS(&vp, 0, (BYTE *)v_m_sig_nocert, sizeof v_m_sig_nocert, d, &dn, &sc);
    CHECKF(r, "err 0x%lx", GetLastError());
    EXPECT_EQ(mh_cb_calls, 1);
    CHECK(CERT_IS(sc, v_s1_cert)); FREE_CERT(sc);
}
TEST(mh_verify_callback_not_called_for_length_only) {
    MH_INIT(); REQUIRE(VMS);
    CRYPT_VERIFY_MESSAGE_PARA vp; mh_verify_para_cb(&vp);
    DWORD dn = 0; mh_cb_calls = 0;
    CHECK(VMS(&vp, 0, (BYTE *)v_m_sig_nocert, sizeof v_m_sig_nocert, NULL, &dn, NULL));
    EXPECT_EQ(mh_cb_calls, 0); EXPECT_EQ(dn, sizeof v_payload);
}
static DWORD g_cb_enc; static CERT_INFO g_cb_id; static void *g_cb_arg; static HCERTSTORE g_cb_store;
static PCCERT_CONTEXT WINAPI cb_record(void *arg, DWORD enc, PCERT_INFO id, HCERTSTORE msgstore) {
    g_cb_arg = arg; g_cb_enc = enc; g_cb_id = *id; g_cb_store = msgstore;
    return U(CertGetSubjectCertificateFromStore)(mh_pub_store, enc, id);
}
TEST(mh_verify_callback_arguments) {
    MH_INIT(); REQUIRE(VMS);
    CRYPT_VERIFY_MESSAGE_PARA vp; mh_verify_para(&vp); vp.pfnGetSignerCertificate = cb_record; vp.pvGetArg = (void *)0x1234;
    BYTE d[100]; DWORD dn = sizeof d; PCCERT_CONTEXT sc = NULL;
    memset(&g_cb_id, 0, sizeof g_cb_id); g_cb_arg = NULL;
    CHECK(VMS(&vp, 0, (BYTE *)v_m_sig_nocert, sizeof v_m_sig_nocert, d, &dn, &sc));
    CHECK(g_cb_arg == (void *)0x1234); EXPECT_EQ(g_cb_enc, ENC);
    CHECK(sc && g_cb_id.SerialNumber.cbData == sc->pCertInfo->SerialNumber.cbData
          && !memcmp(g_cb_id.SerialNumber.pbData, sc->pCertInfo->SerialNumber.pbData, g_cb_id.SerialNumber.cbData));
    CHECK(g_cb_id.Issuer.cbData == sc->pCertInfo->Issuer.cbData);
    CHECK(g_cb_store != NULL);
    FREE_CERT(sc);
}
static PCCERT_CONTEXT WINAPI cb_null_err(void *arg, DWORD enc, PCERT_INFO id, HCERTSTORE s) { SetLastError(ERROR_FILE_NOT_FOUND); return NULL; }
TEST(mh_verify_callback_failure_error_is_propagated) {
    MH_INIT(); REQUIRE(VMS);
    CRYPT_VERIFY_MESSAGE_PARA vp; mh_verify_para(&vp); vp.pfnGetSignerCertificate = cb_null_err;
    BYTE d[100]; DWORD dn = sizeof d; PCCERT_CONTEXT sc = (PCCERT_CONTEXT)1; SET_ERR(0);
    BOOL r = VMS(&vp, 0, (BYTE *)v_m_sig_nocert, sizeof v_m_sig_nocert, d, &dn, &sc);
    EXPECT_FAIL(r == FALSE, ERROR_FILE_NOT_FOUND);
    CHECK(sc == NULL);
}
static PCCERT_CONTEXT WINAPI cb_wrong(void *arg, DWORD enc, PCERT_INFO id, HCERTSTORE s) { return U(CertDuplicateCertificateContext)(mh_ids[MH_S2].pub); }
TEST(mh_verify_wrong_signer_cert_fails_signature) {
    MH_INIT(); REQUIRE(VMS);
    CRYPT_VERIFY_MESSAGE_PARA vp; mh_verify_para(&vp); vp.pfnGetSignerCertificate = cb_wrong;
    BYTE d[100]; DWORD dn = sizeof d; PCCERT_CONTEXT sc = (PCCERT_CONTEXT)1; SET_ERR(0);
    BOOL r = VMS(&vp, 0, (BYTE *)v_m_sig_nocert, sizeof v_m_sig_nocert, d, &dn, &sc);
    EXPECT_FAIL(r == FALSE, E_STATUS_INVALID_SIGNATURE); CHECK(sc == NULL);
}
TEST(mh_verify_tampered_content_attached) {
    MH_INIT(); REQUIRE(VMS);
    DWORD cb = sizeof v_m_sig_noattr; BYTE *b = malloc(cb); memcpy(b, v_m_sig_noattr, cb);
    BYTE *pos = NULL; for (DWORD i = 0; i + sizeof v_payload <= cb; i++) if (!memcmp(b + i, v_payload, sizeof v_payload)) { pos = b + i; break; }
    CHECK(pos != NULL); if (!pos) { free(b); return; }
    pos[0] ^= 0x20;
    CRYPT_VERIFY_MESSAGE_PARA vp; mh_verify_para(&vp);
    BYTE d[100]; DWORD dn = sizeof d; PCCERT_CONTEXT sc = (PCCERT_CONTEXT)1; SET_ERR(0);
    BOOL r = VMS(&vp, 0, b, cb, d, &dn, &sc);
    EXPECT_FAIL(r == FALSE, E_STATUS_INVALID_SIGNATURE);
    CHECK(sc == NULL); EXPECT_EQ(dn, 0);
    free(b);
}
TEST(mh_verify_tampered_content_with_authenticated_attrs) {
    MH_INIT(); REQUIRE(VMS);
    DWORD cb = sizeof v_m_sig_attr; BYTE *b = malloc(cb); memcpy(b, v_m_sig_attr, cb);
    BYTE *pos = NULL; for (DWORD i = 0; i + sizeof v_payload <= cb; i++) if (!memcmp(b + i, v_payload, sizeof v_payload)) { pos = b + i; break; }
    CHECK(pos != NULL); if (!pos) { free(b); return; }
    pos[10] ^= 0x01;
    CRYPT_VERIFY_MESSAGE_PARA vp; mh_verify_para(&vp);
    BYTE d[100]; DWORD dn = sizeof d; SET_ERR(0);
    BOOL r = VMS(&vp, 0, b, cb, d, &dn, NULL);
    EXPECT_FAIL(r == FALSE, E_CRYPT_E_HASH_VALUE);
    free(b);
}
TEST(mh_verify_wrong_message_type_hashed_and_enveloped) {
    MH_INIT(); REQUIRE(VMS);
    CRYPT_VERIFY_MESSAGE_PARA vp; mh_verify_para(&vp);
    BYTE d[100]; DWORD dn = sizeof d; SET_ERR(0);
    BOOL r = VMS(&vp, 0, (BYTE *)v_m_env_aes128, sizeof v_m_env_aes128, d, &dn, NULL);
    EXPECT_FAIL(r == FALSE, E_CRYPT_E_UNEXPECTED_MSG_TYPE); EXPECT_EQ(dn, 0);
    r = VMS(&vp, 0, (BYTE *)v_m_env_des3, sizeof v_m_env_des3, NULL, &dn, NULL);
    EXPECT_FAIL(r == FALSE, E_CRYPT_E_UNEXPECTED_MSG_TYPE);
    CRYPT_HASH_MESSAGE_PARA hp; mh_hash_para(&hp, OID_SHA256);
    const BYTE *a[1] = { v_payload }; DWORD l[1] = { sizeof v_payload }; DWORD hn = 0;
    CHECK(U(CryptHashMessage)(&hp, FALSE, 1, a, l, NULL, &hn, NULL, NULL));
    BYTE *hb = malloc(hn); CHECK(U(CryptHashMessage)(&hp, FALSE, 1, a, l, hb, &hn, NULL, NULL));
    dn = sizeof d; SET_ERR(0);
    r = VMS(&vp, 0, hb, hn, d, &dn, NULL);
    EXPECT_FAIL(r == FALSE, E_CRYPT_E_UNEXPECTED_MSG_TYPE);
    free(hb);
}
TEST(mh_verify_garbage_input) {
    MH_INIT(); REQUIRE(VMS);
    CRYPT_VERIFY_MESSAGE_PARA vp; mh_verify_para(&vp);
    static const BYTE g1[] = { 0 }, g2[] = { 0x30 }, g3[] = { 0x30, 0x00 }, g4[] = { 0x30, 0x03, 0x02, 0x01, 0x01 },
                      g5[] = { 0x04, 0x02, 0x41, 0x42 }, g6[] = { 0x30, 0x84, 0xff, 0xff, 0xff, 0xff, 0x00 };
    /* observed: end-of-data for input that stops short, bad-tag for a wrong first tag */
    static const struct { const BYTE *p; DWORD n; DWORD err; } g[] = { { g1, 1, 0x8009310B }, { g2, 1, 0x80093102 }, { g3, 2, 0x80093102 },
                                                                       { g4, 5, 0x8009310B }, { g5, 4, 0x8009310B }, { g6, 7, 0x80093102 } };
    for (unsigned i = 0; i < sizeof g / sizeof g[0]; i++) {
        BYTE d[100]; DWORD dn = sizeof d; PCCERT_CONTEXT sc = (PCCERT_CONTEXT)1; SET_ERR(0);
        BOOL r = VMS(&vp, 0, (BYTE *)g[i].p, g[i].n, d, &dn, &sc);
        t_label("garbage %u", i); EXPECT_FAIL(r == FALSE, g[i].err); t_label(NULL);
        CHECK(sc == NULL); EXPECT_EQ(dn, 0);
    }
}
TEST(mh_verify_truncated_message) {
    MH_INIT(); REQUIRE(VMS);
    CRYPT_VERIFY_MESSAGE_PARA vp; mh_verify_para(&vp);
    static const DWORD cut[] = { 1, 2, 20, 300 };
    for (unsigned i = 0; i < 4; i++) {
        BYTE d[100]; DWORD dn = sizeof d; SET_ERR(0);
        BOOL r = VMS(&vp, 0, (BYTE *)v_m_sig_noattr, sizeof v_m_sig_noattr - cut[i], d, &dn, NULL);
        t_label("cut %lu", cut[i]); EXPECT_FAIL(r == FALSE, 0x80093102); t_label(NULL); /* observed: end-of-data */
    }
}
TEST(mh_verify_zero_length_blob) {
    MH_INIT(); REQUIRE(VMS);
    CRYPT_VERIFY_MESSAGE_PARA vp; mh_verify_para(&vp);
    BYTE d[10]; DWORD dn = sizeof d; SET_ERR(0);
    BOOL r = VMS(&vp, 0, d, 0, d, &dn, NULL);
    EXPECT_FAIL(r == FALSE, 0x80093102);
    EXPECT_EQ(dn, 0);
}
TEST(mh_verify_detached_message_as_attached) {
    MH_INIT(); REQUIRE(VMS);
    CRYPT_VERIFY_MESSAGE_PARA vp; mh_verify_para(&vp);
    BYTE d[100]; DWORD dn = sizeof d; SET_ERR(0);
    BOOL r = VMS(&vp, 0, (BYTE *)v_m_sig_det_noattr, sizeof v_m_sig_det_noattr, d, &dn, NULL);
    EXPECT_FAIL(r == FALSE, E_STATUS_INVALID_SIGNATURE); /* observed: no content to hash */
    dn = 0xdead; SET_ERR(0);
    r = VMS(&vp, 0, (BYTE *)v_m_sig_det_noattr, sizeof v_m_sig_det_noattr, NULL, &dn, NULL);
    CHECK(r); EXPECT_EQ(dn, 0); /* observed: the length-only decode succeeds and reports an empty content */
}
TEST(mh_verify_signer_cert_ownership_refcount) {
    MH_INIT(); REQUIRE(VMS);
    CRYPT_VERIFY_MESSAGE_PARA vp; mh_verify_para(&vp);
    PCCERT_CONTEXT a = NULL, b = NULL; BYTE d[100]; DWORD dn = sizeof d;
    CHECK(VMS(&vp, 0, (BYTE *)v_m_sig_noattr, sizeof v_m_sig_noattr, d, &dn, &a));
    dn = sizeof d; CHECK(VMS(&vp, 0, (BYTE *)v_m_sig_noattr, sizeof v_m_sig_noattr, d, &dn, &b));
    CHECK(a && b); CHECK(CERT_IS(a, v_s1_cert) && CERT_IS(b, v_s1_cert));
    CHECK(a->hCertStore != NULL);
    CHECK(U(CertFreeCertificateContext)(a));
    CHECK(b->pCertInfo != NULL); CHECK(b->pCertInfo->SerialNumber.cbData == 2);
    CHECK(U(CertFreeCertificateContext)(b));
}
TEST(mh_verify_signer_cert_name_string) {
    MH_INIT(); REQUIRE(VMS); REQUIRE(U(CertGetNameStringA));
    CRYPT_VERIFY_MESSAGE_PARA vp; mh_verify_para(&vp);
    PCCERT_CONTEXT sc = NULL; BYTE d[100]; DWORD dn = sizeof d;
    CHECK(VMS(&vp, 1, (BYTE *)v_m_sig_two_noattr, sizeof v_m_sig_two_noattr, d, &dn, &sc));
    char nm[64] = ""; if (sc) U(CertGetNameStringA)(sc, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, nm, sizeof nm);
    EXPECT_STR(nm, "CryptT MH Signer 2");
    FREE_CERT(sc);
}
TEST(mh_verify_attr_message_embedded_chain_certs) {
    MH_INIT(); REQUIRE(U(CryptGetMessageCertificates));
    HCERTSTORE s = U(CryptGetMessageCertificates)(ENC, 0, 0, (BYTE *)v_m_sig_attr, sizeof v_m_sig_attr);
    CHECK(s != NULL); if (!s) return;
    EXPECT_EQ(mh_count_certs(s), 2);
    PCCERT_CONTEXT c = NULL; int ca = 0, s1 = 0;
    while ((c = U(CertEnumCertificatesInStore)(s, c)) != NULL) { if (CERT_IS(c, v_ca)) ca++; if (CERT_IS(c, v_s1_cert)) s1++; }
    EXPECT_EQ(ca, 1); EXPECT_EQ(s1, 1);
    CHECK(U(CertCloseStore)(s, CERT_CLOSE_STORE_CHECK_FLAG));
}

/* ---- detached ---------------------------------------------------------------------------- */
#define VDS U(CryptVerifyDetachedMessageSignature)
TEST(mh_detached_verify_external_table) {
    MH_INIT(); REQUIRE(VDS);
    static const struct { const BYTE *p; DWORD n; } m[] = { { v_m_sig_det_attr, sizeof v_m_sig_det_attr }, { v_m_sig_det_noattr, sizeof v_m_sig_det_noattr } };
    for (int i = 0; i < 2; i++) {
        CRYPT_VERIFY_MESSAGE_PARA vp; mh_verify_para(&vp);
        const BYTE *a[1] = { v_payload }; DWORD l[1] = { sizeof v_payload }; PCCERT_CONTEXT sc = NULL; SET_ERR(0);
        BOOL r = VDS(&vp, 0, (BYTE *)m[i].p, m[i].n, 1, a, l, &sc);
        CHECKF(r, "msg %d err 0x%lx", i, GetLastError());
        CHECK(CERT_IS(sc, v_s1_cert)); FREE_CERT(sc);
    }
}
TEST(mh_detached_verify_split_content) {
    MH_INIT(); REQUIRE(VDS);
    CRYPT_VERIFY_MESSAGE_PARA vp; mh_verify_para(&vp);
    const BYTE *a[3] = { v_payload, v_payload + 3, v_payload + 40 }; DWORD l[3] = { 3, 37, (DWORD)sizeof v_payload - 40 };
    SET_ERR(0);
    BOOL r = VDS(&vp, 0, (BYTE *)v_m_sig_det_noattr, sizeof v_m_sig_det_noattr, 3, a, l, NULL);
    CHECKF(r, "err 0x%lx", GetLastError());
}
TEST(mh_detached_verify_modified_content) {
    MH_INIT(); REQUIRE(VDS);
    CRYPT_VERIFY_MESSAGE_PARA vp; mh_verify_para(&vp);
    BYTE c[sizeof v_payload]; memcpy(c, v_payload, sizeof c); c[7] ^= 1;
    const BYTE *a[1] = { c }; DWORD l[1] = { sizeof c }; PCCERT_CONTEXT sc = (PCCERT_CONTEXT)1; SET_ERR(0);
    BOOL r = VDS(&vp, 0, (BYTE *)v_m_sig_det_noattr, sizeof v_m_sig_det_noattr, 1, a, l, &sc);
    EXPECT_FAIL(r == FALSE, E_STATUS_INVALID_SIGNATURE); CHECK(sc == NULL);
    SET_ERR(0);
    r = VDS(&vp, 0, (BYTE *)v_m_sig_det_attr, sizeof v_m_sig_det_attr, 1, a, l, NULL);
    CHECK(r == FALSE); DWORD e = GetLastError();
    EXPECT_EQ(e, E_CRYPT_E_HASH_VALUE);
}
TEST(mh_detached_verify_truncated_or_extended_content) {
    MH_INIT(); REQUIRE(VDS);
    CRYPT_VERIFY_MESSAGE_PARA vp; mh_verify_para(&vp);
    BYTE c[sizeof v_payload + 1]; memcpy(c, v_payload, sizeof v_payload); c[sizeof v_payload] = 0;
    DWORD lens[2] = { sizeof v_payload - 1, sizeof v_payload + 1 };
    for (int i = 0; i < 2; i++) {
        const BYTE *a[1] = { c }; DWORD l[1] = { lens[i] };
        BOOL r = VDS(&vp, 0, (BYTE *)v_m_sig_det_noattr, sizeof v_m_sig_det_noattr, 1, a, l, NULL);
        CHECKF(r == FALSE, "length %lu", lens[i]);
    }
}
TEST(mh_detached_verify_no_content_fails) {
    MH_INIT(); REQUIRE(VDS);
    CRYPT_VERIFY_MESSAGE_PARA vp; mh_verify_para(&vp);
    SET_ERR(0);
    BOOL r = VDS(&vp, 0, (BYTE *)v_m_sig_det_noattr, sizeof v_m_sig_det_noattr, 0, NULL, NULL, NULL);
    EXPECT_FAIL(r == FALSE, E_STATUS_INVALID_SIGNATURE); /* observed: nothing to hash */
}
TEST(mh_detached_verify_signer_index) {
    MH_INIT(); REQUIRE(VDS);
    CRYPT_VERIFY_MESSAGE_PARA vp; mh_verify_para(&vp);
    const BYTE *a[1] = { v_payload }; DWORD l[1] = { sizeof v_payload }; PCCERT_CONTEXT sc = (PCCERT_CONTEXT)1; SET_ERR(0);
    BOOL r = VDS(&vp, 1, (BYTE *)v_m_sig_det_noattr, sizeof v_m_sig_det_noattr, 1, a, l, &sc);
    EXPECT_FAIL(r == FALSE, E_CRYPT_E_NO_SIGNER); CHECK(sc == NULL);
    r = VDS(&vp, 0xFFFFFFFF, (BYTE *)v_m_sig_det_noattr, sizeof v_m_sig_det_noattr, 1, a, l, NULL);
    EXPECT_FAIL(r == FALSE, E_CRYPT_E_NO_SIGNER);
}
TEST(mh_detached_verify_cbsize_and_garbage) {
    MH_INIT(); REQUIRE(VDS);
    CRYPT_VERIFY_MESSAGE_PARA vp; mh_verify_para(&vp); vp.cbSize = 0x1c;
    const BYTE *a[1] = { v_payload }; DWORD l[1] = { sizeof v_payload }; SET_ERR(0);
    BOOL r = VDS(&vp, 0, (BYTE *)v_m_sig_det_noattr, sizeof v_m_sig_det_noattr, 1, a, l, NULL);
    EXPECT_FAIL(r == FALSE, E_INVALIDARG_);
    mh_verify_para(&vp); SET_ERR(0);
    static const BYTE junk[] = { 0x30, 0x03, 0x02, 0x01, 0x01 };
    r = VDS(&vp, 0, (BYTE *)junk, sizeof junk, 1, a, l, NULL);
    EXPECT_FAIL(r == FALSE, 0x8009310B); /* observed: ASN1 bad tag */
}
TEST(mh_detached_verify_wrong_type) {
    MH_INIT(); REQUIRE(VDS);
    CRYPT_VERIFY_MESSAGE_PARA vp; mh_verify_para(&vp);
    const BYTE *a[1] = { v_payload }; DWORD l[1] = { sizeof v_payload }; SET_ERR(0);
    BOOL r = VDS(&vp, 0, (BYTE *)v_m_env_aes128, sizeof v_m_env_aes128, 1, a, l, NULL);
    EXPECT_FAIL(r == FALSE, E_CRYPT_E_MSG_ERROR);   /* an enveloped message is not a detached signature */
}
TEST(mh_detached_verify_own_signature_roundtrip_all_algs) {
    MH_INIT(); REQUIRE(VDS); REQUIRE(U(CryptSignMessage));
    static const char *oids[] = { OID_SHA1, OID_SHA256, OID_SHA384, OID_SHA512, OID_MD5 };
    for (int i = 0; i < 5; i++) {
        DWORD cb = 0; BYTE *b = mh_sign(MH_S2, oids[i], 1, 0, PL, &cb);
        CHECKF(b != NULL, "sign %s", oids[i]); if (!b) continue;
        CRYPT_VERIFY_MESSAGE_PARA vp; mh_verify_para_cb(&vp);
        const BYTE *a[1] = { v_payload }; DWORD l[1] = { sizeof v_payload }; PCCERT_CONTEXT sc = NULL; SET_ERR(0);
        BOOL r = VDS(&vp, 0, b, cb, 1, a, l, &sc);
        CHECKF(r, "%s: err 0x%lx", oids[i], GetLastError());
        CHECK(CERT_IS(sc, v_s2_cert)); FREE_CERT(sc); free(b);
    }
}

/* ---- signer count / certificates ------------------------------------------------------------ */
TEST(mh_signer_count_table) {
    MH_INIT(); REQUIRE(U(CryptGetMessageSignerCount));
    for (unsigned i = 0; i < sizeof g_ext / sizeof g_ext[0]; i++)
        EXPECT_EQ(U(CryptGetMessageSignerCount)(ENC, g_ext[i].p, g_ext[i].cb), g_ext[i].signers);
    EXPECT_EQ(U(CryptGetMessageSignerCount)(ENC, v_m_sig_det_noattr, sizeof v_m_sig_det_noattr), 1);
    EXPECT_EQ(U(CryptGetMessageSignerCount)(ENC, v_m_sig_nocert, sizeof v_m_sig_nocert), 1);
}
TEST(mh_signer_count_certs_only_is_zero) {
    MH_INIT(); REQUIRE(U(CryptGetMessageSignerCount));
    EXPECT_EQ(U(CryptGetMessageSignerCount)(ENC, v_m_certs_only, sizeof v_m_certs_only), 0);
    EXPECT_EQ(U(CryptGetMessageSignerCount)(ENC, v_o_p7_crl, sizeof v_o_p7_crl), 0);
}
TEST(mh_signer_count_non_signed_messages_fail) {
    MH_INIT(); REQUIRE(U(CryptGetMessageSignerCount));
    EXPECT_EQ(U(CryptGetMessageSignerCount)(ENC, v_m_env_aes128, sizeof v_m_env_aes128), -1);
    EXPECT_EQ(U(CryptGetMessageSignerCount)(ENC, v_m_env_des3, sizeof v_m_env_des3), -1);
}
TEST(mh_signer_count_garbage_is_minus_one) {
    MH_INIT(); REQUIRE(U(CryptGetMessageSignerCount));
    static const BYTE g[] = { 0x30, 0x03, 0x02, 0x01, 0x01 };
    EXPECT_EQ(U(CryptGetMessageSignerCount)(ENC, g, sizeof g), -1);
    EXPECT_EQ(U(CryptGetMessageSignerCount)(ENC, g, 0), -1);
    EXPECT_EQ(U(CryptGetMessageSignerCount)(ENC, v_m_sig_noattr, sizeof v_m_sig_noattr - 1), -1);
    EXPECT_EQ(U(CryptGetMessageSignerCount)(ENC, v_o_cert, sizeof v_o_cert), -1);
}
TEST(mh_signer_count_encoding_type_requirements) {
    MH_INIT(); REQUIRE(U(CryptGetMessageSignerCount));
    EXPECT_EQ(U(CryptGetMessageSignerCount)(PKCS_7_ASN_ENCODING, v_m_sig_noattr, sizeof v_m_sig_noattr), 1);
    EXPECT_EQ(U(CryptGetMessageSignerCount)(0, v_m_sig_noattr, sizeof v_m_sig_noattr), -1);
    LONG r = U(CryptGetMessageSignerCount)(X509_ASN_ENCODING, v_m_sig_noattr, sizeof v_m_sig_noattr);
    EXPECT_EQ(r, -1); /* observed: the PKCS7 encoding bit is required */
}
TEST(mh_signer_count_own_messages) {
    MH_INIT(); REQUIRE(U(CryptGetMessageSignerCount));
    DWORD cb = 0; BYTE *b = mh_sign(MH_S1, OID_SHA256, 0, 0, PL, &cb);
    CHECK(b != NULL); if (b) EXPECT_EQ(U(CryptGetMessageSignerCount)(ENC, b, cb), 1);
    free(b);
    b = mh_sign(MH_S1, OID_SHA256, 1, 0, PL, &cb);
    CHECK(b != NULL); if (b) EXPECT_EQ(U(CryptGetMessageSignerCount)(ENC, b, cb), 1);
    free(b);
}
TEST(mh_get_certs_table) {
    MH_INIT(); REQUIRE(U(CryptGetMessageCertificates));
    static const struct { const BYTE *p; DWORD n; int certs; } t[] = {
        { v_m_certs_only, sizeof v_m_certs_only, 2 }, { v_m_sig_attr, sizeof v_m_sig_attr, 2 },
        { v_m_sig_nocert, sizeof v_m_sig_nocert, 1 }, { v_m_sig_two_noattr, sizeof v_m_sig_two_noattr, 3 },
        { v_o_p7_crl, sizeof v_o_p7_crl, 2 } };
    for (unsigned i = 0; i < 5; i++) {
        HCERTSTORE s = U(CryptGetMessageCertificates)(ENC, 0, 0, t[i].p, t[i].n);
        CHECKF(s != NULL, "msg %u err 0x%lx", i, GetLastError()); if (!s) continue;
        EXPECT_EQ(mh_count_certs(s), t[i].certs);
        CHECK(U(CertCloseStore)(s, 0));
    }
}
TEST(mh_get_certs_crl_in_message) {
    MH_INIT(); REQUIRE(U(CryptGetMessageCertificates));
    HCERTSTORE s = U(CryptGetMessageCertificates)(ENC, 0, 0, v_o_p7_crl, sizeof v_o_p7_crl);
    CHECK(s != NULL); if (!s) return;
    PCCRL_CONTEXT crl = U(CertEnumCRLsInStore)(s, NULL);
    CHECK(crl != NULL);
    if (crl) { CHECK(crl->cbCrlEncoded == sizeof v_o_crl && !memcmp(crl->pbCrlEncoded, v_o_crl, sizeof v_o_crl)); U(CertFreeCRLContext)(crl); }
    U(CertCloseStore)(s, 0);
}
TEST(mh_get_certs_failures) {
    MH_INIT(); REQUIRE(U(CryptGetMessageCertificates));
    static const BYTE g[] = { 0x30, 0x03, 0x02, 0x01, 0x01 };
    SET_ERR(0);
    HCERTSTORE s = U(CryptGetMessageCertificates)(ENC, 0, 0, g, sizeof g);
    EXPECT_FAIL(s == NULL, 0x80093102); /* observed: end-of-data */
    /* any PKCS#7 ContentInfo opens; an enveloped message just carries no certificates */
    s = U(CryptGetMessageCertificates)(ENC, 0, 0, v_m_env_aes128, sizeof v_m_env_aes128);
    CHECK(s != NULL); if (s) { EXPECT_EQ(mh_count_certs(s), 0); U(CertCloseStore)(s, 0); }
    SET_ERR(0);
    s = U(CryptGetMessageCertificates)(ENC, 0, 0, v_m_hashed_sha256, sizeof v_m_hashed_sha256);
    EXPECT_FAIL(s == NULL, 0x80091004); /* observed: CRYPT_E_INVALID_MSG_TYPE */
    s = U(CryptGetMessageCertificates)(ENC, 0, 0, v_o_cert, sizeof v_o_cert);
    CHECK(s == NULL);
    s = U(CryptGetMessageCertificates)(0, 0, 0, v_m_certs_only, sizeof v_m_certs_only);
    /* observed: the encoding type is not validated, a store with the message's certificates is returned */
    CHECK(s != NULL);
    if (s) { HCERTSTORE s2 = U(CryptGetMessageCertificates)(ENC, 0, 0, v_m_certs_only, sizeof v_m_certs_only);
             CHECK(s2 != NULL); if (s2) { EXPECT_EQ(mh_count_certs(s), mh_count_certs(s2)); U(CertCloseStore)(s2, 0); }
             U(CertCloseStore)(s, 0); }
}
TEST(mh_get_certs_store_independent_of_buffer) {
    MH_INIT(); REQUIRE(U(CryptGetMessageCertificates));
    BYTE *copy = malloc(sizeof v_m_certs_only); memcpy(copy, v_m_certs_only, sizeof v_m_certs_only);
    HCERTSTORE s = U(CryptGetMessageCertificates)(ENC, 0, 0, copy, sizeof v_m_certs_only);
    CHECK(s != NULL);
    memset(copy, 0, sizeof v_m_certs_only); free(copy);
    if (s) {
        PCCERT_CONTEXT c = U(CertEnumCertificatesInStore)(s, NULL);
        CHECK(c && (CERT_IS(c, v_s1_cert) || CERT_IS(c, v_s2_cert)));
        if (c) U(CertFreeCertificateContext)(c);
        U(CertCloseStore)(s, 0);
    }
}
TEST(mh_get_certs_find_by_issuer_and_serial) {
    MH_INIT(); REQUIRE(U(CryptGetMessageCertificates));
    HCERTSTORE s = U(CryptGetMessageCertificates)(ENC, 0, 0, v_m_sig_two_noattr, sizeof v_m_sig_two_noattr);
    CHECK(s != NULL); if (!s) return;
    CERT_INFO ci; memset(&ci, 0, sizeof ci);
    ci.Issuer = mh_ids[MH_S2].pub->pCertInfo->Issuer; ci.SerialNumber = mh_ids[MH_S2].pub->pCertInfo->SerialNumber;
    PCCERT_CONTEXT c = U(CertGetSubjectCertificateFromStore)(s, ENC, &ci);
    CHECK(CERT_IS(c, v_s2_cert)); FREE_CERT(c);
    ci.SerialNumber = mh_ids[MH_R1].pub->pCertInfo->SerialNumber;
    SET_ERR(0);
    c = U(CertGetSubjectCertificateFromStore)(s, ENC, &ci);
    CHECK(c == NULL); EXPECT_ERR(E_CRYPT_E_NOT_FOUND);
    U(CertCloseStore)(s, 0);
}

/* ---- CryptVerifyMessageSignatureWithKey --------------------------------------------------------- */
#define VWK U(CryptVerifyMessageSignatureWithKey)
TEST(mh_withkey_verify_nocert_message) {
    MH_NOWINE(); MH_INIT(); REQUIRE(VWK);
    CRYPT_KEY_VERIFY_MESSAGE_PARA p; memset(&p, 0, sizeof p); p.cbSize = sizeof p; p.dwMsgEncodingType = ENC;
    BYTE d[100]; DWORD dn = sizeof d; SET_ERR(0);
    BOOL r = VWK(&p, &mh_ids[MH_S1].pub->pCertInfo->SubjectPublicKeyInfo, v_m_sig_nocert, sizeof v_m_sig_nocert, d, &dn);
    CHECKF(r, "err 0x%lx", GetLastError());
    EXPECT_EQ(dn, sizeof v_payload); CHECK(!memcmp(d, v_payload, dn));
}
TEST(mh_withkey_wrong_key_fails) {
    MH_NOWINE(); MH_INIT(); REQUIRE(VWK);
    CRYPT_KEY_VERIFY_MESSAGE_PARA p; memset(&p, 0, sizeof p); p.cbSize = sizeof p; p.dwMsgEncodingType = ENC;
    BYTE d[100]; DWORD dn = sizeof d; SET_ERR(0);
    BOOL r = VWK(&p, &mh_ids[MH_S2].pub->pCertInfo->SubjectPublicKeyInfo, v_m_sig_nocert, sizeof v_m_sig_nocert, d, &dn);
    CHECK(r == FALSE); EXPECT_EQ(dn, 0);
    EXPECT_ERR(E_STATUS_INVALID_SIGNATURE);
}
TEST(mh_withkey_size_only_without_key) {
    MH_NOWINE(); MH_INIT(); REQUIRE(VWK);
    CRYPT_KEY_VERIFY_MESSAGE_PARA p; memset(&p, 0, sizeof p); p.cbSize = sizeof p; p.dwMsgEncodingType = ENC;
    DWORD dn = 99; SET_ERR(0);
    BOOL r = VWK(&p, NULL, v_m_sig_nocert, sizeof v_m_sig_nocert, NULL, &dn);
    CHECK(r); EXPECT_EQ(dn, sizeof v_payload);
}
TEST(mh_withkey_size_with_key_verifies) {
    MH_NOWINE(); MH_INIT(); REQUIRE(VWK);
    CRYPT_KEY_VERIFY_MESSAGE_PARA p; memset(&p, 0, sizeof p); p.cbSize = sizeof p; p.dwMsgEncodingType = ENC;
    DWORD dn = 0; BOOL r = VWK(&p, &mh_ids[MH_S1].pub->pCertInfo->SubjectPublicKeyInfo, v_m_sig_nocert, sizeof v_m_sig_nocert, NULL, &dn);
    CHECK(r); EXPECT_EQ(dn, sizeof v_payload);
    dn = 0; SET_ERR(0);
    r = VWK(&p, &mh_ids[MH_S2].pub->pCertInfo->SubjectPublicKeyInfo, v_m_sig_nocert, sizeof v_m_sig_nocert, NULL, &dn);
    CHECK(r == FALSE); EXPECT_EQ(dn, 0);
}
TEST(mh_withkey_more_data) {
    MH_NOWINE(); MH_INIT(); REQUIRE(VWK);
    CRYPT_KEY_VERIFY_MESSAGE_PARA p; memset(&p, 0, sizeof p); p.cbSize = sizeof p; p.dwMsgEncodingType = ENC;
    BYTE d[100]; DWORD dn = 10; SET_ERR(0);
    BOOL r = VWK(&p, &mh_ids[MH_S1].pub->pCertInfo->SubjectPublicKeyInfo, v_m_sig_nocert, sizeof v_m_sig_nocert, d, &dn);
    EXPECT_FAIL(r == FALSE, ERROR_MORE_DATA);
    EXPECT_EQ(dn, 50); /* observed: the required size is reported */
}
TEST(mh_withkey_cbsize_must_be_exact) {
    MH_NOWINE(); MH_INIT(); REQUIRE(VWK);
    static const DWORD sz[] = { 0, 8, 0x0f, 0x11, 0x18, 0x20 };
    for (unsigned i = 0; i < 6; i++) {
        CRYPT_KEY_VERIFY_MESSAGE_PARA p; memset(&p, 0, sizeof p); p.cbSize = sz[i]; p.dwMsgEncodingType = ENC;
        BYTE d[100]; DWORD dn = sizeof d; SET_ERR(0);
        BOOL r = VWK(&p, &mh_ids[MH_S1].pub->pCertInfo->SubjectPublicKeyInfo, v_m_sig_nocert, sizeof v_m_sig_nocert, d, &dn);
        EXPECT_FAIL(r == FALSE, E_INVALIDARG_); EXPECT_EQ(dn, 0);
    }
}
TEST(mh_withkey_wrong_message_type) {
    MH_NOWINE(); MH_INIT(); REQUIRE(VWK);
    CRYPT_KEY_VERIFY_MESSAGE_PARA p; memset(&p, 0, sizeof p); p.cbSize = sizeof p; p.dwMsgEncodingType = ENC;
    BYTE d[100]; DWORD dn = sizeof d; SET_ERR(0);
    BOOL r = VWK(&p, &mh_ids[MH_S1].pub->pCertInfo->SubjectPublicKeyInfo, v_m_env_aes128, sizeof v_m_env_aes128, d, &dn);
    EXPECT_FAIL(r == FALSE, E_CRYPT_E_UNEXPECTED_MSG_TYPE); EXPECT_EQ(dn, 0);
}
TEST(mh_withkey_attributes_message_and_own_signature) {
    MH_NOWINE(); MH_INIT(); REQUIRE(VWK);
    CRYPT_KEY_VERIFY_MESSAGE_PARA p; memset(&p, 0, sizeof p); p.cbSize = sizeof p; p.dwMsgEncodingType = ENC;
    BYTE d[100]; DWORD dn = sizeof d; SET_ERR(0);
    BOOL r = VWK(&p, &mh_ids[MH_S1].pub->pCertInfo->SubjectPublicKeyInfo, v_m_sig_attr, sizeof v_m_sig_attr, d, &dn);
    CHECKF(r, "external message with attributes: err 0x%lx", GetLastError());
    DWORD cb = 0; BYTE *b = mh_sign(MH_S2, OID_SHA256, 0, 0, PL, &cb);
    CHECK(b != NULL);
    if (b) {
        dn = sizeof d; r = VWK(&p, &mh_ids[MH_S2].pub->pCertInfo->SubjectPublicKeyInfo, b, cb, d, &dn);
        CHECKF(r, "own message: err 0x%lx", GetLastError());
        if (r) { EXPECT_EQ(dn, sizeof v_payload); CHECK(!memcmp(d, v_payload, dn)); }
        free(b);
    }
}
TEST(mh_withkey_garbage) {
    MH_NOWINE(); MH_INIT(); REQUIRE(VWK);
    CRYPT_KEY_VERIFY_MESSAGE_PARA p; memset(&p, 0, sizeof p); p.cbSize = sizeof p; p.dwMsgEncodingType = ENC;
    static const BYTE g[] = { 0x30, 0x03, 0x02, 0x01, 0x01 };
    BYTE d[100]; DWORD dn = sizeof d; SET_ERR(0);
    BOOL r = VWK(&p, &mh_ids[MH_S1].pub->pCertInfo->SubjectPublicKeyInfo, g, sizeof g, d, &dn);
    CHECK(r == FALSE); EXPECT_EQ(dn, 0); CHECK(GetLastError() != 0);
}
