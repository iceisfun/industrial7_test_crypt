/* CryptSignMessage: structure, size protocol, parameters, flags, attributes. */
#include "mh.h"
#include <stdlib.h>

#define PL v_payload, (DWORD)sizeof v_payload

static const struct { const char *oid; const char *enc; DWORD encn; } g_algs[] = {
    { OID_SHA1,   "\x06\x05\x2b\x0e\x03\x02\x1a", 7 },
    { OID_SHA256, "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01", 11 },
    { OID_SHA384, "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02", 11 },
    { OID_SHA512, "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03", 11 },
    { OID_MD5,    "\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x05", 10 },
};

TEST(mh_sign_header_is_signed_data_contentinfo) {
    MH_INIT(); REQUIRE(U(CryptSignMessage));
    DWORD cb = 0; BYTE *b = mh_sign(MH_S1, OID_SHA256, 0, 0, PL, &cb);
    CHECK(b != NULL); if (!b) return;
    CHECK(b[0] == 0x30);
    EXPECT_EQ(mh_der_total(b, cb), cb);                 /* definite length, exactly the returned size */
    DWORD h = mh_der_hdr(b, cb);
    CHECK(h != 0 && h + 11 <= cb && !memcmp(b + h, MH_OID_SIGNED, 11));
    CHECK(MH_HAS(b, cb, "\x02\x01\x01"));                /* version 1 present */
    CHECK(mh_has(b, cb, v_payload, sizeof v_payload));   /* attached content is carried */
    free(b);
}
TEST(mh_sign_is_deterministic_without_attributes) {
    MH_INIT(); REQUIRE(U(CryptSignMessage));
    DWORD c1 = 0, c2 = 0; BYTE *a = mh_sign(MH_S1, OID_SHA256, 0, 0, PL, &c1), *b = mh_sign(MH_S1, OID_SHA256, 0, 0, PL, &c2);
    CHECK(a && b); if (a && b) { EXPECT_EQ(c1, c2); CHECK(c1 == c2 && !memcmp(a, b, c1)); }
    free(a); free(b);
}
TEST(mh_sign_different_signers_differ) {
    MH_INIT(); REQUIRE(U(CryptSignMessage));
    DWORD c1 = 0, c2 = 0; BYTE *a = mh_sign(MH_S1, OID_SHA256, 0, 0, PL, &c1), *b = mh_sign(MH_S2, OID_SHA256, 0, 0, PL, &c2);
    CHECK(a && b); if (a && b) CHECK(c1 != c2 || memcmp(a, b, c1));
    free(a); free(b);
}
TEST(mh_sign_size_query_null_buffer) {
    MH_INIT(); REQUIRE(U(CryptSignMessage));
    CRYPT_SIGN_MESSAGE_PARA p; mh_sign_para(&p, MH_S1, OID_SHA256);
    const BYTE *a[1] = { v_payload }; DWORD l[1] = { sizeof v_payload }; DWORD n = 0x1234;
    SET_ERR(0);
    CHECK(U(CryptSignMessage)(&p, FALSE, 1, a, l, NULL, &n));
    CHECK(n > sizeof v_payload);
    DWORD cb = 0; BYTE *b = mh_sign(MH_S1, OID_SHA256, 0, 0, PL, &cb);
    CHECK(b != NULL); CHECK(n >= cb);
    if (n != cb) t_note("size query %lu vs actual %lu", n, cb);
    free(b);
}
TEST(mh_sign_size_query_ignores_incoming_value) {
    MH_INIT(); REQUIRE(U(CryptSignMessage));
    CRYPT_SIGN_MESSAGE_PARA p; mh_sign_para(&p, MH_S1, OID_SHA256);
    const BYTE *a[1] = { v_payload }; DWORD l[1] = { sizeof v_payload };
    DWORD n1 = 0, n2 = 0xFFFF;
    CHECK(U(CryptSignMessage)(&p, FALSE, 1, a, l, NULL, &n1));
    CHECK(U(CryptSignMessage)(&p, FALSE, 1, a, l, NULL, &n2));
    EXPECT_EQ(n1, n2);
}
TEST(mh_sign_zero_length_with_buffer_is_more_data) {
    MH_INIT(); REQUIRE(U(CryptSignMessage));
    CRYPT_SIGN_MESSAGE_PARA p; mh_sign_para(&p, MH_S1, OID_SHA256);
    const BYTE *a[1] = { v_payload }; DWORD l[1] = { sizeof v_payload };
    BYTE buf[1024]; DWORD n = 0, q = 0;
    CHECK(U(CryptSignMessage)(&p, FALSE, 1, a, l, NULL, &q));
    SET_ERR(0);
    BOOL r = U(CryptSignMessage)(&p, FALSE, 1, a, l, buf, &n);
    EXPECT_FAIL(r == FALSE, ERROR_MORE_DATA);
    EXPECT_EQ(n, q);
}
TEST(mh_sign_exact_buffer_succeeds_and_trailing_untouched) {
    MH_INIT(); REQUIRE(U(CryptSignMessage));
    CRYPT_SIGN_MESSAGE_PARA p; mh_sign_para(&p, MH_S1, OID_SHA256);
    const BYTE *a[1] = { v_payload }; DWORD l[1] = { sizeof v_payload };
    DWORD q = 0; CHECK(U(CryptSignMessage)(&p, FALSE, 1, a, l, NULL, &q));
    BYTE *buf = malloc(q + 16); memset(buf, 0xA5, q + 16);
    DWORD n = q;
    CHECK(U(CryptSignMessage)(&p, FALSE, 1, a, l, buf, &n));
    CHECK(n <= q);
    EXPECT_EQ(mh_der_total(buf, n), n);
    for (DWORD i = n; i < q + 16; i++) if (buf[i] != 0xA5) { CHECKF(0, "byte %lu past output modified", i); break; }
    free(buf);
}
TEST(mh_sign_short_buffer_more_data_reports_size) {
    MH_INIT(); REQUIRE(U(CryptSignMessage));
    CRYPT_SIGN_MESSAGE_PARA p; mh_sign_para(&p, MH_S1, OID_SHA256);
    const BYTE *a[1] = { v_payload }; DWORD l[1] = { sizeof v_payload };
    DWORD cb = 0; BYTE *full = mh_sign(MH_S1, OID_SHA256, 0, 0, PL, &cb);
    CHECK(full != NULL); if (!full) return;
    static const int cut[] = { 1, 2, 10, 100 };
    for (unsigned i = 0; i < sizeof cut / sizeof cut[0]; i++) {
        BYTE *buf = malloc(cb); DWORD n = cb - cut[i];
        SET_ERR(0);
        BOOL r = U(CryptSignMessage)(&p, FALSE, 1, a, l, buf, &n);
        EXPECT_FAIL(r == FALSE, ERROR_MORE_DATA);
        EXPECT_EQ(n, cb);
        free(buf);
    }
    free(full);
}
TEST(mh_sign_buffer_size_one) {
    MH_INIT(); REQUIRE(U(CryptSignMessage));
    CRYPT_SIGN_MESSAGE_PARA p; mh_sign_para(&p, MH_S1, OID_SHA256);
    const BYTE *a[1] = { v_payload }; DWORD l[1] = { sizeof v_payload };
    BYTE one[1]; DWORD n = 1;
    SET_ERR(0);
    BOOL r = U(CryptSignMessage)(&p, FALSE, 1, a, l, one, &n);
    EXPECT_FAIL(r == FALSE, ERROR_MORE_DATA);
    CHECK(n > 1);
}
TEST(mh_sign_cbsize_too_small_is_invalidarg) {
    MH_INIT(); REQUIRE(U(CryptSignMessage));
    static const DWORD sizes[] = { 0, 1, 4, 0x28, 0x4c, 0x4f };
    const BYTE *a[1] = { v_payload }; DWORD l[1] = { sizeof v_payload };
    for (unsigned i = 0; i < sizeof sizes / sizeof sizes[0]; i++) {
        CRYPT_SIGN_MESSAGE_PARA p; mh_sign_para(&p, MH_S1, OID_SHA256); p.cbSize = sizes[i];
        DWORD n = 777; SET_ERR(0);
        BOOL r = U(CryptSignMessage)(&p, FALSE, 1, a, l, NULL, &n);
        EXPECT_FAIL(r == FALSE, E_INVALIDARG_);
        EXPECT_EQ(n, 0);
    }
}
TEST(mh_sign_cbsize_too_small_with_buffer_zeroes_size) {
    MH_INIT(); REQUIRE(U(CryptSignMessage));
    CRYPT_SIGN_MESSAGE_PARA p; mh_sign_para(&p, MH_S1, OID_SHA256); p.cbSize = 0x4f;
    const BYTE *a[1] = { v_payload }; DWORD l[1] = { sizeof v_payload };
    BYTE buf[600]; DWORD n = sizeof buf; SET_ERR(0);
    BOOL r = U(CryptSignMessage)(&p, FALSE, 1, a, l, buf, &n);
    EXPECT_FAIL(r == FALSE, E_INVALIDARG_);
    EXPECT_EQ(n, 0);
}
TEST(mh_sign_cbsize_0x50_is_accepted) {
    MH_INIT(); REQUIRE(U(CryptSignMessage));
    CRYPT_SIGN_MESSAGE_PARA p; mh_sign_para(&p, MH_S1, OID_SHA256); p.cbSize = 0x50;
    const BYTE *a[1] = { v_payload }; DWORD l[1] = { sizeof v_payload }; DWORD n = 0;
    CHECK(U(CryptSignMessage)(&p, FALSE, 1, a, l, NULL, &n)); CHECK(n > 0);
}
TEST(mh_sign_cbsize_gates_attributes_and_flags) {
    MH_INIT(); REQUIRE(U(CryptSignMessage));
    static char oid[] = "1.2.3.4.5.6.7.99"; static BYTE val[] = { 0x04, 0x03, 'a', 'b', 'c' };
    CRYPT_ATTR_BLOB vb = { sizeof val, val }; CRYPT_ATTRIBUTE at = { oid, 1, &vb };
    const BYTE *a[1] = { v_payload }; DWORD l[1] = { sizeof v_payload };
    DWORD sizes[] = { 0x50, 0x6f, 0x70 };
    for (int i = 0; i < 3; i++) {
        CRYPT_SIGN_MESSAGE_PARA p; mh_sign_para(&p, MH_S1, OID_SHA256); p.cbSize = sizes[i];
        p.cAuthAttr = 1; p.rgAuthAttr = &at;
        DWORD n = 0; BYTE *b;
        CHECK(U(CryptSignMessage)(&p, FALSE, 1, a, l, NULL, &n));
        b = malloc(n); CHECK(U(CryptSignMessage)(&p, FALSE, 1, a, l, b, &n));
        int has = MH_HAS(b, n, "\x06\x07\x2a\x03\x04\x05\x06\x07\x63");
        CHECKF(has == (sizes[i] >= 0x70), "cbSize 0x%lx: attribute present=%d", sizes[i], has);
        free(b);
    }
    /* dwFlags is only read when cbSize >= 0x78 */
    CRYPT_SIGN_MESSAGE_PARA p; mh_sign_para(&p, MH_S1, OID_SHA256); p.dwFlags = CRYPT_MESSAGE_BARE_CONTENT_OUT_FLAG; p.cbSize = 0x70;
    DWORD n = 0; BYTE *b; CHECK(U(CryptSignMessage)(&p, FALSE, 1, a, l, NULL, &n));
    b = malloc(n); CHECK(U(CryptSignMessage)(&p, FALSE, 1, a, l, b, &n));
    DWORD h = mh_der_hdr(b, n); CHECK(h + 11 <= n && !memcmp(b + h, MH_OID_SIGNED, 11)); free(b);
}
TEST(mh_sign_hash_algorithm_table) {
    MH_INIT(); REQUIRE(U(CryptSignMessage)); REQUIRE(U(CryptVerifyMessageSignature));
    for (unsigned i = 0; i < sizeof g_algs / sizeof g_algs[0]; i++) {
        DWORD cb = 0; BYTE *b = mh_sign(MH_S1, g_algs[i].oid, 0, 0, PL, &cb);
        CHECKF(b != NULL, "sign with %s: err 0x%lx", g_algs[i].oid, GetLastError());
        if (!b) continue;
        CHECKF(mh_has(b, cb, g_algs[i].enc, g_algs[i].encn), "digest OID %s present", g_algs[i].oid);
        CRYPT_VERIFY_MESSAGE_PARA vp; mh_verify_para_cb(&vp);
        BYTE out[128]; DWORD n = sizeof out; PCCERT_CONTEXT sc = NULL;
        BOOL r = U(CryptVerifyMessageSignature)(&vp, 0, b, cb, out, &n, &sc);
        CHECKF(r, "verify %s err 0x%lx", g_algs[i].oid, GetLastError());
        if (r) { EXPECT_EQ(n, sizeof v_payload); CHECK(!memcmp(out, v_payload, n)); }
        if (sc) U(CertFreeCertificateContext)(sc);
        free(b);
    }
}
TEST(mh_sign_unknown_hash_oid_fails) {
    MH_INIT(); REQUIRE(U(CryptSignMessage));
    static const char *bad[] = { "1.2.3.4.5", "2.16.840.1.101.3.4.2.99", "not.an.oid", "1.3.14.3.2.7" /* DES-CBC, not a hash */ };
    for (unsigned i = 0; i < 4; i++) {
        CRYPT_SIGN_MESSAGE_PARA p; mh_sign_para(&p, MH_S1, bad[i]);
        const BYTE *a[1] = { v_payload }; DWORD l[1] = { sizeof v_payload }; DWORD n = 55; SET_ERR(0);
        BOOL r = U(CryptSignMessage)(&p, FALSE, 1, a, l, NULL, &n);
        if (r) { t_note("hash oid %s accepted on size query", bad[i]); continue; }
        t_note("hash oid %s -> err 0x%lx", bad[i], GetLastError());
        EXPECT_EQ(n, 0);
    }
}
TEST(mh_sign_pubonly_cert_without_key_fails) {
    MH_INIT(); REQUIRE(U(CryptSignMessage));
    CRYPT_SIGN_MESSAGE_PARA p; mh_sign_para(&p, MH_S1, OID_SHA256); p.pSigningCert = mh_ids[MH_S1].pub;
    p.dwFlags = CRYPT_MESSAGE_SILENT_KEYSET_FLAG;
    const BYTE *a[1] = { v_payload }; DWORD l[1] = { sizeof v_payload }; DWORD n = 9; SET_ERR(0);
    BOOL r = U(CryptSignMessage)(&p, FALSE, 1, a, l, NULL, &n);
    CHECK(r == FALSE); EXPECT_EQ(n, 0);
    t_note("signing without private key -> 0x%lx", GetLastError());
    CHECK(GetLastError() != 0);
}
TEST(mh_sign_wrong_encoding_type_fails) {
    MH_INIT(); REQUIRE(U(CryptSignMessage));
    CRYPT_SIGN_MESSAGE_PARA p; mh_sign_para(&p, MH_S1, OID_SHA256); p.dwMsgEncodingType = 0;
    const BYTE *a[1] = { v_payload }; DWORD l[1] = { sizeof v_payload }; DWORD n = 9; SET_ERR(0);
    BOOL r = U(CryptSignMessage)(&p, FALSE, 1, a, l, NULL, &n);
    CHECK(r == FALSE); t_note("encoding type 0 -> 0x%lx", GetLastError());
    p.dwMsgEncodingType = PKCS_7_ASN_ENCODING; n = 0;
    CHECK(U(CryptSignMessage)(&p, FALSE, 1, a, l, NULL, &n));
    p.dwMsgEncodingType = X509_ASN_ENCODING; n = 0; SET_ERR(0);
    r = U(CryptSignMessage)(&p, FALSE, 1, a, l, NULL, &n);
    t_note("X509-only encoding type -> %d err 0x%lx", r, GetLastError());
}
/* Windows 10: an attached signature accepts exactly one content blob. The size query still succeeds (with a size that
 * depends on the blob count) but producing the message fails. Splitting content is only supported detached. */
TEST(mh_sign_attached_multi_blob_fails_on_output) {
    MH_INIT(); REQUIRE(U(CryptSignMessage));
    CRYPT_SIGN_MESSAGE_PARA p; mh_sign_para(&p, MH_S1, OID_SHA256);
    const BYTE *a3[3] = { v_payload, v_payload + 10, v_payload + 33 };
    DWORD l3[3] = { 10, 23, (DWORD)sizeof v_payload - 33 };
    DWORD n3 = 0; SET_ERR(0);
    BOOL rq = U(CryptSignMessage)(&p, FALSE, 3, a3, l3, NULL, &n3);
    CHECKF(rq, "size query err 0x%lx", GetLastError());
    BYTE *b3 = malloc(n3 + 64); DWORD m = n3 + 64; SET_ERR(0);
    BOOL r = U(CryptSignMessage)(&p, FALSE, 3, a3, l3, b3, &m);
    EXPECT_FAIL(r == FALSE, E_CRYPT_E_MSG_ERROR); EXPECT_EQ(m, 0);
    free(b3);
}
TEST(mh_sign_detached_content_split_equals_concatenation) {
    MH_INIT(); REQUIRE(U(CryptSignMessage));
    CRYPT_SIGN_MESSAGE_PARA p; mh_sign_para(&p, MH_S1, OID_SHA256);
    const BYTE *a3[3] = { v_payload, (const BYTE *)"", v_payload + 33 };
    DWORD l3[3] = { 10 + 23, 0, (DWORD)sizeof v_payload - 33 };
    const BYTE *a1[1] = { v_payload }; DWORD l1[1] = { sizeof v_payload };
    DWORD n3 = 0; CHECK(U(CryptSignMessage)(&p, TRUE, 3, a3, l3, NULL, &n3));
    BYTE *b3 = malloc(n3); CHECK(U(CryptSignMessage)(&p, TRUE, 3, a3, l3, b3, &n3));
    DWORD n1 = 0; CHECK(U(CryptSignMessage)(&p, TRUE, 1, a1, l1, NULL, &n1));
    BYTE *b1 = malloc(n1); CHECK(U(CryptSignMessage)(&p, TRUE, 1, a1, l1, b1, &n1));
    EXPECT_EQ(n1, n3); CHECK(n1 == n3 && !memcmp(b1, b3, n1));
    free(b1); free(b3);
}
TEST(mh_sign_zero_blobs) {
    MH_INIT(); REQUIRE(U(CryptSignMessage));
    CRYPT_SIGN_MESSAGE_PARA p; mh_sign_para(&p, MH_S1, OID_SHA256);
    DWORD n = 0; SET_ERR(0);
    BOOL r = U(CryptSignMessage)(&p, FALSE, 0, NULL, NULL, NULL, &n);
    t_note("cToBeSigned=0 size query -> %d n=%lu err 0x%lx", r, n, GetLastError());
    if (r) {
        BYTE *b = malloc(n); n += 0; BOOL r2 = U(CryptSignMessage)(&p, FALSE, 0, NULL, NULL, b, &n);
        CHECK(r2); free(b);
    }
}
TEST(mh_sign_empty_content_roundtrip) {
    MH_INIT(); REQUIRE(U(CryptSignMessage)); REQUIRE(U(CryptVerifyMessageSignature));
    CRYPT_SIGN_MESSAGE_PARA p; mh_sign_para(&p, MH_S1, OID_SHA256);
    p.cMsgCert = 1; PCCERT_CONTEXT mc[1] = { mh_ids[MH_S1].pub }; p.rgpMsgCert = mc;
    const BYTE *a[1] = { (const BYTE *)"" }; DWORD l[1] = { 0 };
    DWORD n = 0; CHECK(U(CryptSignMessage)(&p, FALSE, 1, a, l, NULL, &n));
    BYTE *b = malloc(n); CHECK(U(CryptSignMessage)(&p, FALSE, 1, a, l, b, &n));
    CRYPT_VERIFY_MESSAGE_PARA vp; mh_verify_para(&vp);
    DWORD dn = 5; BYTE d[5]; PCCERT_CONTEXT sc = NULL;
    SET_ERR(0);
    BOOL r = U(CryptVerifyMessageSignature)(&vp, 0, b, n, d, &dn, &sc);
    t_note("verify of empty-content signed message -> %d err 0x%lx n=%lu", r, GetLastError(), dn);
    if (sc) U(CertFreeCertificateContext)(sc);
    free(b);
}
TEST(mh_sign_large_content_roundtrip) {
    MH_INIT(); REQUIRE(U(CryptSignMessage)); REQUIRE(U(CryptVerifyMessageSignature));
    DWORD sz = 300000; BYTE *data = malloc(sz);
    for (DWORD i = 0; i < sz; i++) data[i] = (BYTE)(i * 31 + (i >> 8));
    CRYPT_SIGN_MESSAGE_PARA p; mh_sign_para(&p, MH_S1, OID_SHA256);
    p.cMsgCert = 1; PCCERT_CONTEXT mc[1] = { mh_ids[MH_S1].pub }; p.rgpMsgCert = mc;
    const BYTE *a[1] = { data }; DWORD l[1] = { sz };
    DWORD n = 0; CHECK(U(CryptSignMessage)(&p, FALSE, 1, a, l, NULL, &n));
    CHECK(n > sz);
    BYTE *b = malloc(n); CHECK(U(CryptSignMessage)(&p, FALSE, 1, a, l, b, &n));
    CHECK(mh_der_total(b, n) == n);
    CRYPT_VERIFY_MESSAGE_PARA vp; mh_verify_para(&vp);
    DWORD dn = 0; PCCERT_CONTEXT sc = NULL;
    CHECK(U(CryptVerifyMessageSignature)(&vp, 0, b, n, NULL, &dn, NULL));
    EXPECT_EQ(dn, sz);
    BYTE *d = malloc(dn ? dn : 1);
    CHECK(U(CryptVerifyMessageSignature)(&vp, 0, b, n, d, &dn, &sc));
    CHECK(dn == sz && !memcmp(d, data, sz));
    if (sc) U(CertFreeCertificateContext)(sc);
    free(d); free(b); free(data);
}
TEST(mh_sign_detached_omits_content) {
    MH_INIT(); REQUIRE(U(CryptSignMessage));
    DWORD ca = 0, cd = 0;
    BYTE *at = mh_sign(MH_S1, OID_SHA256, 0, 0, PL, &ca), *de = mh_sign(MH_S1, OID_SHA256, 1, 0, PL, &cd);
    CHECK(at && de); if (!at || !de) return;
    CHECK(!mh_has(de, cd, v_payload, sizeof v_payload));
    CHECK(mh_has(at, ca, v_payload, sizeof v_payload));
    CHECK(cd + sizeof v_payload <= ca + 4);
    EXPECT_EQ(mh_der_total(de, cd), cd);
    DWORD h = mh_der_hdr(de, cd); CHECK(!memcmp(de + h, MH_OID_SIGNED, 11));
    free(at); free(de);
}
TEST(mh_sign_detached_size_protocol) {
    MH_INIT(); REQUIRE(U(CryptSignMessage));
    CRYPT_SIGN_MESSAGE_PARA p; mh_sign_para(&p, MH_S1, OID_SHA256);
    const BYTE *a[1] = { v_payload }; DWORD l[1] = { sizeof v_payload };
    DWORD q = 0; CHECK(U(CryptSignMessage)(&p, TRUE, 1, a, l, NULL, &q));
    BYTE *b = malloc(q); DWORD n = q - 1; SET_ERR(0);
    BOOL r = U(CryptSignMessage)(&p, TRUE, 1, a, l, b, &n);
    EXPECT_FAIL(r == FALSE, ERROR_MORE_DATA); EXPECT_EQ(n, q);
    n = q; CHECK(U(CryptSignMessage)(&p, TRUE, 1, a, l, b, &n));
    free(b);
}
TEST(mh_sign_detached_signature_same_for_split_content) {
    MH_INIT(); REQUIRE(U(CryptSignMessage));
    CRYPT_SIGN_MESSAGE_PARA p; mh_sign_para(&p, MH_S1, OID_SHA256);
    const BYTE *a2[2] = { v_payload, v_payload + 7 }; DWORD l2[2] = { 7, (DWORD)sizeof v_payload - 7 };
    DWORD n2 = 0; CHECK(U(CryptSignMessage)(&p, TRUE, 2, a2, l2, NULL, &n2));
    BYTE *b2 = malloc(n2); CHECK(U(CryptSignMessage)(&p, TRUE, 2, a2, l2, b2, &n2));
    DWORD n1 = 0; BYTE *b1 = mh_sign(MH_S1, OID_SHA256, 1, 0, PL, &n1);
    CHECK(b1 && n1 == n2 && !memcmp(b1, b2, n1));
    free(b1); free(b2);
}
TEST(mh_sign_rgpmsgcert_embedded_in_message) {
    MH_INIT(); REQUIRE(U(CryptSignMessage)); REQUIRE(U(CryptGetMessageCertificates));
    CRYPT_SIGN_MESSAGE_PARA p; mh_sign_para(&p, MH_S1, OID_SHA256);
    PCCERT_CONTEXT mc[2] = { mh_ids[MH_S1].pub, mh_ids[MH_R1].pub };
    p.cMsgCert = 2; p.rgpMsgCert = mc;
    const BYTE *a[1] = { v_payload }; DWORD l[1] = { sizeof v_payload };
    DWORD n = 0; CHECK(U(CryptSignMessage)(&p, FALSE, 1, a, l, NULL, &n));
    BYTE *b = malloc(n); CHECK(U(CryptSignMessage)(&p, FALSE, 1, a, l, b, &n));
    CHECK(mh_has(b, n, v_s1_cert, sizeof v_s1_cert)); CHECK(mh_has(b, n, v_r1_cert, sizeof v_r1_cert));
    CHECK(!mh_has(b, n, v_s2_cert, sizeof v_s2_cert));
    HCERTSTORE s = U(CryptGetMessageCertificates)(ENC, 0, 0, b, n);
    CHECK(s != NULL);
    if (s) { EXPECT_EQ(mh_count_certs(s), 2); U(CertCloseStore)(s, 0); }
    free(b);
}
TEST(mh_sign_signer_cert_not_added_implicitly) {
    MH_INIT(); REQUIRE(U(CryptSignMessage));
    DWORD cb = 0; BYTE *b = mh_sign(MH_S1, OID_SHA256, 0, 0, PL, &cb);
    CHECK(b != NULL); if (!b) return;
    CHECK(!mh_has(b, cb, v_s1_cert, sizeof v_s1_cert));
    free(b);
}
TEST(mh_sign_cert_count_scales_size) {
    MH_INIT(); REQUIRE(U(CryptSignMessage));
    CRYPT_SIGN_MESSAGE_PARA p; mh_sign_para(&p, MH_S1, OID_SHA256);
    const BYTE *a[1] = { v_payload }; DWORD l[1] = { sizeof v_payload };
    PCCERT_CONTEXT mc[4] = { mh_ids[MH_S1].pub, mh_ids[MH_S2].pub, mh_ids[MH_R1].pub, mh_ids[MH_R2].pub };
    DWORD prev = 0;
    for (DWORD k = 0; k <= 4; k++) {
        p.cMsgCert = k; p.rgpMsgCert = k ? mc : NULL;
        DWORD n = 0; CHECK(U(CryptSignMessage)(&p, FALSE, 1, a, l, NULL, &n));
        if (k) CHECKF(n >= prev + sizeof v_s1_cert - 40, "k=%lu n=%lu prev=%lu", k, n, prev);
        prev = n;
    }
}
TEST(mh_sign_rgpmsgcrl_embedded_in_message) {
    MH_INIT(); REQUIRE(U(CryptSignMessage)); REQUIRE(U(CryptGetMessageCertificates));
    PCCRL_CONTEXT crl = U(CertCreateCRLContext)(ENC, v_o_crl, sizeof v_o_crl);
    CHECK(crl != NULL); if (!crl) return;
    CRYPT_SIGN_MESSAGE_PARA p; mh_sign_para(&p, MH_S1, OID_SHA256);
    p.cMsgCrl = 1; p.rgpMsgCrl = &crl;
    const BYTE *a[1] = { v_payload }; DWORD l[1] = { sizeof v_payload };
    DWORD n = 0; CHECK(U(CryptSignMessage)(&p, FALSE, 1, a, l, NULL, &n));
    BYTE *b = malloc(n); CHECK(U(CryptSignMessage)(&p, FALSE, 1, a, l, b, &n));
    CHECK(mh_has(b, n, v_o_crl, sizeof v_o_crl));
    HCERTSTORE s = U(CryptGetMessageCertificates)(ENC, 0, 0, b, n);
    CHECK(s != NULL);
    if (s) {
        PCCRL_CONTEXT c = U(CertEnumCRLsInStore)(s, NULL);
        CHECK(c != NULL);
        if (c) { CHECK(c->cbCrlEncoded == sizeof v_o_crl); U(CertFreeCRLContext)(c); }
        CHECK(mh_count_certs(s) == 0);
        U(CertCloseStore)(s, 0);
    }
    U(CertFreeCRLContext)(crl); free(b);
}
TEST(mh_sign_bare_content_flag_drops_contentinfo) {
    MH_INIT(); REQUIRE(U(CryptSignMessage));
    DWORD cb = 0; BYTE *b = mh_sign(MH_S1, OID_SHA256, 0, CRYPT_MESSAGE_BARE_CONTENT_OUT_FLAG, PL, &cb);
    CHECK(b != NULL); if (!b) return;
    DWORD h = mh_der_hdr(b, cb);
    CHECK(b[0] == 0x30); CHECK(h && h + 3 <= cb && !memcmp(b + h, "\x02\x01\x01", 3));
    CHECK(!MH_HAS(b, cb, MH_OID_SIGNED));
    DWORD cn = 0; BYTE *nb = mh_sign(MH_S1, OID_SHA256, 0, 0, PL, &cn);
    CHECK(nb && cb < cn); free(nb);
    free(b);
}
TEST(mh_sign_bare_content_not_decodable_as_message) {
    MH_INIT(); REQUIRE(U(CryptVerifyMessageSignature));
    DWORD cb = 0; BYTE *b = mh_sign(MH_S1, OID_SHA256, 0, CRYPT_MESSAGE_BARE_CONTENT_OUT_FLAG, PL, &cb);
    CHECK(b != NULL); if (!b) return;
    CRYPT_VERIFY_MESSAGE_PARA vp; mh_verify_para_cb(&vp);
    PCCERT_CONTEXT sc = NULL; BYTE d[100]; DWORD n = sizeof d; SET_ERR(0);
    BOOL r = U(CryptVerifyMessageSignature)(&vp, 0, b, cb, d, &n, &sc);
    CHECK(r == FALSE); CHECK(sc == NULL); if (sc) U(CertFreeCertificateContext)(sc);
    free(b);
}
TEST(mh_sign_encapsulated_content_flag_roundtrip) {
    MH_INIT(); REQUIRE(U(CryptSignMessage)); REQUIRE(U(CryptVerifyMessageSignature));
    DWORD cb = 0; BYTE *b = mh_sign(MH_S1, OID_SHA256, 0, CRYPT_MESSAGE_ENCAPSULATED_CONTENT_OUT_FLAG, PL, &cb);
    CHECKF(b != NULL, "err 0x%lx", GetLastError()); if (!b) return;
    CHECK(mh_has(b, cb, v_payload, sizeof v_payload));
    CRYPT_VERIFY_MESSAGE_PARA vp; mh_verify_para_cb(&vp);
    BYTE d[100]; DWORD n = sizeof d; PCCERT_CONTEXT sc = NULL;
    BOOL r = U(CryptVerifyMessageSignature)(&vp, 0, b, cb, d, &n, &sc);
    CHECKF(r, "err 0x%lx", GetLastError());
    if (r) { EXPECT_EQ(n, sizeof v_payload); CHECK(!memcmp(d, v_payload, n)); }
    if (sc) U(CertFreeCertificateContext)(sc);
    DWORD c0 = 0; BYTE *b0 = mh_sign(MH_S1, OID_SHA256, 0, 0, PL, &c0);
    if (b0) { if (c0 != cb || memcmp(b0, b, cb)) t_note("encapsulated flag changes the encoding (%lu vs %lu bytes)", cb, c0); else t_note("encapsulated flag leaves a data payload encoding unchanged"); free(b0); }
    free(b);
}
TEST(mh_sign_silent_keyset_flag_accepted) {
    MH_INIT(); REQUIRE(U(CryptSignMessage));
    DWORD cb = 0; BYTE *b = mh_sign(MH_S1, OID_SHA256, 0, CRYPT_MESSAGE_SILENT_KEYSET_FLAG, PL, &cb);
    CHECKF(b != NULL, "err 0x%lx", GetLastError());
    DWORD c0 = 0; BYTE *b0 = mh_sign(MH_S1, OID_SHA256, 0, 0, PL, &c0);
    if (b && b0) CHECK(cb == c0 && !memcmp(b, b0, cb));
    free(b); free(b0);
}
TEST(mh_sign_keyid_signer_flag) {
    MH_INIT(); REQUIRE(U(CryptSignMessage)); REQUIRE(U(CryptMsgOpenToDecode));
    DWORD cb = 0; BYTE *b = mh_sign(MH_S1, OID_SHA256, 0, CRYPT_MESSAGE_KEYID_SIGNER_FLAG, PL, &cb);
    CHECKF(b != NULL, "err 0x%lx", GetLastError()); if (!b) return;
    DWORD c0 = 0; BYTE *b0 = mh_sign(MH_S1, OID_SHA256, 0, 0, PL, &c0);
    CHECK(b0 != NULL);
    if (b0) { CHECK(cb != c0 || memcmp(b, b0, cb)); free(b0); }
    HCRYPTMSG m = U(CryptMsgOpenToDecode)(ENC, 0, 0, 0, NULL, NULL);
    CHECK(m != NULL);
    if (m) {
        CHECK(U(CryptMsgUpdate)(m, b, cb, TRUE));
        DWORD type = 0, n = sizeof type;
        CHECK(U(CryptMsgGetParam)(m, CMSG_TYPE_PARAM, 0, &type, &n)); EXPECT_EQ(type, CMSG_SIGNED);
        DWORD ver = 0; n = sizeof ver;
        if (U(CryptMsgGetParam)(m, CMSG_VERSION_PARAM, 0, &ver, &n)) t_note("message version with KEYID signer: %lu", ver);
        U(CryptMsgClose)(m);
    }
    free(b);
}
static int msg_attr_count(const BYTE *b, DWORD cb, DWORD param, const char *want[], int nwant, int *found) {
    HCRYPTMSG m = U(CryptMsgOpenToDecode)(ENC, 0, 0, 0, NULL, NULL);
    int cnt = -1; if (!m) return -1;
    if (U(CryptMsgUpdate)(m, b, cb, TRUE)) {
        DWORD n = 0;
        if (U(CryptMsgGetParam)(m, param, 0, NULL, &n) && n) {
            CRYPT_ATTRIBUTES *as = malloc(n);
            if (U(CryptMsgGetParam)(m, param, 0, as, &n)) {
                cnt = (int)as->cAttr;
                for (int j = 0; j < nwant; j++) found[j] = 0;
                for (DWORD i = 0; i < as->cAttr; i++)
                    for (int j = 0; j < nwant; j++) if (!strcmp(as->rgAttr[i].pszObjId, want[j])) found[j] = 1;
            }
            free(as);
        }
    }
    U(CryptMsgClose)(m);
    return cnt;
}
TEST(mh_sign_auth_attr_adds_contenttype_and_digest) {
    MH_INIT(); REQUIRE(U(CryptSignMessage)); REQUIRE(U(CryptMsgOpenToDecode));
    static char oid[] = "1.2.3.4.5.6.7.99"; static BYTE val[] = { 0x04, 0x03, 'a', 'b', 'c' };
    CRYPT_ATTR_BLOB vb = { sizeof val, val }; CRYPT_ATTRIBUTE at = { oid, 1, &vb };
    CRYPT_SIGN_MESSAGE_PARA p; mh_sign_para(&p, MH_S1, OID_SHA256); p.cAuthAttr = 1; p.rgAuthAttr = &at;
    const BYTE *a[1] = { v_payload }; DWORD l[1] = { sizeof v_payload };
    DWORD n = 0; CHECK(U(CryptSignMessage)(&p, FALSE, 1, a, l, NULL, &n));
    BYTE *b = malloc(n); CHECK(U(CryptSignMessage)(&p, FALSE, 1, a, l, b, &n));
    const char *want[3] = { "1.2.3.4.5.6.7.99", "1.2.840.113549.1.9.3", "1.2.840.113549.1.9.4" };
    int found[3] = { 0, 0, 0 };
    int cnt = msg_attr_count(b, n, CMSG_SIGNER_AUTH_ATTR_PARAM, want, 3, found);
    CHECK(cnt >= 3); CHECK(found[0]); CHECK(found[1]); CHECK(found[2]);
    t_note("authenticated attribute count with one caller attribute: %d", cnt);
    int f1[1] = { 0 }; const char *w1[1] = { "1.2.3.4.5.6.7.99" };
    EXPECT_EQ(msg_attr_count(b, n, CMSG_SIGNER_UNAUTH_ATTR_PARAM, w1, 1, f1) <= 0, 1);
    free(b);
}
TEST(mh_sign_unauth_attr_in_message) {
    MH_INIT(); REQUIRE(U(CryptSignMessage)); REQUIRE(U(CryptMsgOpenToDecode));
    static char oid[] = "1.2.3.4.5.6.7.98"; static BYTE val[] = { 0x0c, 0x02, 'h', 'i' };
    CRYPT_ATTR_BLOB vb = { sizeof val, val }; CRYPT_ATTRIBUTE at = { oid, 1, &vb };
    CRYPT_SIGN_MESSAGE_PARA p; mh_sign_para(&p, MH_S1, OID_SHA256); p.cUnauthAttr = 1; p.rgUnauthAttr = &at;
    const BYTE *a[1] = { v_payload }; DWORD l[1] = { sizeof v_payload };
    DWORD n = 0; CHECK(U(CryptSignMessage)(&p, FALSE, 1, a, l, NULL, &n));
    BYTE *b = malloc(n); CHECK(U(CryptSignMessage)(&p, FALSE, 1, a, l, b, &n));
    const char *want[1] = { "1.2.3.4.5.6.7.98" }; int found[1] = { 0 };
    EXPECT_EQ(msg_attr_count(b, n, CMSG_SIGNER_UNAUTH_ATTR_PARAM, want, 1, found), 1);
    CHECK(found[0]);
    int f2[1] = { 0 };
    CHECK(msg_attr_count(b, n, CMSG_SIGNER_AUTH_ATTR_PARAM, want, 1, f2) <= 0 || !f2[0]);
    /* unauthenticated attributes do not alter the signature: verification still works */
    CRYPT_VERIFY_MESSAGE_PARA vp; mh_verify_para_cb(&vp); PCCERT_CONTEXT sc = NULL;
    CHECK(U(CryptVerifyMessageSignature)(&vp, 0, b, n, NULL, &n, &sc)); if (sc) U(CertFreeCertificateContext)(sc);
    free(b);
}
TEST(mh_sign_auth_attr_changes_signature_semantics) {
    MH_INIT(); REQUIRE(U(CryptSignMessage)); REQUIRE(U(CryptVerifyMessageSignature));
    static char oid[] = "1.2.3.4.5.6.7.99"; static BYTE val[] = { 0x04, 0x01, 'z' };
    CRYPT_ATTR_BLOB vb = { sizeof val, val }; CRYPT_ATTRIBUTE at = { oid, 1, &vb };
    CRYPT_SIGN_MESSAGE_PARA p; mh_sign_para(&p, MH_S1, OID_SHA256); p.cAuthAttr = 1; p.rgAuthAttr = &at;
    const BYTE *a[1] = { v_payload }; DWORD l[1] = { sizeof v_payload };
    DWORD n = 0; CHECK(U(CryptSignMessage)(&p, FALSE, 1, a, l, NULL, &n));
    BYTE *b = malloc(n); CHECK(U(CryptSignMessage)(&p, FALSE, 1, a, l, b, &n));
    CRYPT_VERIFY_MESSAGE_PARA vp; mh_verify_para_cb(&vp); PCCERT_CONTEXT sc = NULL; BYTE d[100]; DWORD dn = sizeof d;
    CHECKF(U(CryptVerifyMessageSignature)(&vp, 0, b, n, d, &dn, &sc), "err 0x%lx", GetLastError());
    if (sc) U(CertFreeCertificateContext)(sc);
    /* flip one content byte: messageDigest attribute no longer matches */
    BYTE *pos = NULL; for (DWORD i = 0; i + sizeof v_payload <= n; i++) if (!memcmp(b + i, v_payload, sizeof v_payload)) { pos = b + i; break; }
    CHECK(pos != NULL);
    if (pos) {
        pos[5] ^= 1; dn = sizeof d; SET_ERR(0); sc = NULL;
        BOOL r = U(CryptVerifyMessageSignature)(&vp, 0, b, n, d, &dn, &sc);
        CHECK(r == FALSE); CHECK(sc == NULL);
        DWORD e = GetLastError(); t_note("tampered content with auth attrs -> 0x%lx", e);
        EXPECT_EQ(e, E_CRYPT_E_HASH_VALUE);
        if (sc) U(CertFreeCertificateContext)(sc);
    }
    free(b);
}
TEST(mh_sign_two_auth_attrs_and_values) {
    MH_INIT(); REQUIRE(U(CryptSignMessage)); REQUIRE(U(CryptMsgOpenToDecode));
    static char o1[] = "1.2.3.4.5.6.7.1", o2[] = "1.2.3.4.5.6.7.2";
    static BYTE v1[] = { 0x04, 0x01, '1' }, v2[] = { 0x04, 0x01, '2' }, v3[] = { 0x04, 0x01, '3' };
    CRYPT_ATTR_BLOB b1[2] = { { 3, v1 }, { 3, v3 } }, b2[1] = { { 3, v2 } };
    CRYPT_ATTRIBUTE at[2] = { { o1, 2, b1 }, { o2, 1, b2 } };
    CRYPT_SIGN_MESSAGE_PARA p; mh_sign_para(&p, MH_S1, OID_SHA256); p.cAuthAttr = 2; p.rgAuthAttr = at;
    const BYTE *a[1] = { v_payload }; DWORD l[1] = { sizeof v_payload };
    DWORD n = 0; CHECK(U(CryptSignMessage)(&p, FALSE, 1, a, l, NULL, &n));
    BYTE *b = malloc(n); CHECK(U(CryptSignMessage)(&p, FALSE, 1, a, l, b, &n));
    const char *want[2] = { o1, o2 }; int found[2] = { 0, 0 };
    int cnt = msg_attr_count(b, n, CMSG_SIGNER_AUTH_ATTR_PARAM, want, 2, found);
    CHECK(cnt >= 4); CHECK(found[0] && found[1]);
    free(b);
}
TEST(mh_sign_inner_content_type_default_is_data) {
    MH_INIT(); REQUIRE(U(CryptSignMessage)); REQUIRE(U(CryptMsgOpenToDecode));
    DWORD cb = 0; BYTE *b = mh_sign(MH_S1, OID_SHA256, 0, 0, PL, &cb);
    CHECK(b != NULL); if (!b) return;
    HCRYPTMSG m = U(CryptMsgOpenToDecode)(ENC, 0, 0, 0, NULL, NULL);
    CHECK(m && U(CryptMsgUpdate)(m, b, cb, TRUE));
    char oid[64]; DWORD n = sizeof oid;
    CHECK(U(CryptMsgGetParam)(m, CMSG_INNER_CONTENT_TYPE_PARAM, 0, oid, &n));
    EXPECT_STR(oid, "1.2.840.113549.1.7.1");
    CHECK(MH_HAS(b, cb, MH_OID_DATA));
    U(CryptMsgClose)(m); free(b);
}
/* With an explicit inner content type (1..6) crypt32 does not wrap the content: it must already be the DER encoding of a
 * value (fill fails with CRYPT_E_UNEXPECTED_ENCODING for raw bytes). An OCTET STRING around the payload is valid for all. */
static BYTE g_der_pl[2 + sizeof v_payload];
static void der_payload(void) { g_der_pl[0] = 0x04; g_der_pl[1] = (BYTE)sizeof v_payload; memcpy(g_der_pl + 2, v_payload, sizeof v_payload); }
TEST(mh_sign_explicit_inner_type_needs_der_content) {
    MH_INIT(); REQUIRE(U(CryptSignMessage));
    CRYPT_SIGN_MESSAGE_PARA p; mh_sign_para(&p, MH_S1, OID_SHA256);
    const BYTE *a[1] = { v_payload }; DWORD l[1] = { sizeof v_payload };
    for (DWORD t = CMSG_DATA; t <= CMSG_ENCRYPTED; t++) {
        p.dwInnerContentType = t; DWORD n = 0; SET_ERR(0);
        BOOL rq = U(CryptSignMessage)(&p, FALSE, 1, a, l, NULL, &n);
        CHECKF(rq, "type %lu: size query err 0x%lx", t, GetLastError());
        BYTE *b = malloc(n + 64); DWORD m = n + 64; SET_ERR(0);
        BOOL r = U(CryptSignMessage)(&p, FALSE, 1, a, l, b, &m);
        t_label("type %lu", t);
        EXPECT_FAIL(r == FALSE, E_CRYPT_E_UNEXPECTED_ENCODING); EXPECT_EQ(m, 0);
        t_label(NULL); free(b);
    }
}
TEST(mh_sign_inner_content_type_field_requires_cbsize_0x78) {
    MH_INIT(); REQUIRE(U(CryptSignMessage)); REQUIRE(U(CryptMsgOpenToDecode)); der_payload();
    CRYPT_SIGN_MESSAGE_PARA p; mh_sign_para(&p, MH_S1, OID_SHA256); p.dwInnerContentType = CMSG_ENVELOPED;
    const BYTE *a[1] = { g_der_pl }; DWORD l[1] = { sizeof g_der_pl };
    for (int pass = 0; pass < 2; pass++) {
        p.cbSize = pass ? sizeof p : 0x70;
        DWORD n = 0; SET_ERR(0);
        BOOL r = U(CryptSignMessage)(&p, FALSE, 1, a, l, NULL, &n);
        CHECKF(r, "pass %d err 0x%lx", pass, GetLastError()); if (!r) continue;
        BYTE *b = malloc(n); CHECK(U(CryptSignMessage)(&p, FALSE, 1, a, l, b, &n));
        int env = MH_HAS(b, n, MH_OID_ENVELOPED), dat = MH_HAS(b, n, MH_OID_DATA);
        CHECKF(env == pass, "pass %d: enveloped OID present=%d", pass, env);
        CHECKF(dat == !pass, "pass %d: data OID present=%d", pass, dat);
        free(b);
    }
}
TEST(mh_sign_inner_content_type_table) {
    MH_NOWINE(); MH_INIT(); der_payload(); REQUIRE(U(CryptSignMessage)); REQUIRE(U(CryptDecodeMessage));
    static const struct { DWORD t; const char *oid; DWORD n; } tb[] = {
        { CMSG_DATA, MH_OID_DATA, 11 }, { CMSG_SIGNED, MH_OID_SIGNED, 11 },
        { CMSG_ENVELOPED, MH_OID_ENVELOPED, 11 }, { CMSG_HASHED, MH_OID_HASHED, 11 } };
    for (unsigned i = 0; i < 4; i++) {
        CRYPT_SIGN_MESSAGE_PARA p; mh_sign_para(&p, MH_S1, OID_SHA256); p.dwInnerContentType = tb[i].t;
        const BYTE *a[1] = { g_der_pl }; DWORD l[1] = { sizeof g_der_pl };
        DWORD n = 0; CHECK(U(CryptSignMessage)(&p, FALSE, 1, a, l, NULL, &n));
        BYTE *b = malloc(n); CHECK(U(CryptSignMessage)(&p, FALSE, 1, a, l, b, &n));
        /* the contentType after the digest algorithms is the inner type: signedData appears twice for CMSG_SIGNED */
        CHECKF(mh_has(b, n, tb[i].oid, tb[i].n), "type %lu", tb[i].t);
        CRYPT_VERIFY_MESSAGE_PARA vp; mh_verify_para_cb(&vp);
        DWORD mt = 99, it = 99, dn = 0;
        BOOL r = U(CryptDecodeMessage)(CMSG_SIGNED_FLAG, NULL, &vp, 0, b, n, 0, &mt, &it, NULL, &dn, NULL, NULL);
        CHECKF(r, "decode type %lu err 0x%lx", tb[i].t, GetLastError());
        if (r) { EXPECT_EQ(mt, CMSG_SIGNED); EXPECT_EQ(it, tb[i].t); }
        free(b);
    }
}
TEST(mh_sign_nonzero_unknown_inner_type_maps_to_no_oid) {
    MH_INIT(); REQUIRE(U(CryptSignMessage));
    CRYPT_SIGN_MESSAGE_PARA p; mh_sign_para(&p, MH_S1, OID_SHA256); p.dwInnerContentType = 0x4242;
    const BYTE *a[1] = { v_payload }; DWORD l[1] = { sizeof v_payload };
    DWORD n = 0; SET_ERR(0);
    BOOL r = U(CryptSignMessage)(&p, FALSE, 1, a, l, NULL, &n);
    CHECK(r);   /* unknown values are not in the table: encoded as plain data */
    if (r) { BYTE *b = malloc(n); CHECK(U(CryptSignMessage)(&p, FALSE, 1, a, l, b, &n)); CHECK(MH_HAS(b, n, MH_OID_DATA)); free(b); }
}
TEST(mh_sign_fdetached_is_any_nonzero) {
    MH_INIT(); REQUIRE(U(CryptSignMessage));
    DWORD c1 = 0, c2 = 0; BYTE *a = mh_sign(MH_S1, OID_SHA256, 1, 0, PL, &c1), *b = mh_sign(MH_S1, OID_SHA256, 0x100, 0, PL, &c2);
    CHECK(a && b && c1 == c2 && !memcmp(a, b, c1)); free(a); free(b);
}
TEST(mh_sign_each_signer_roundtrips) {
    MH_INIT(); REQUIRE(U(CryptSignMessage)); REQUIRE(U(CryptVerifyMessageSignature));
    for (int who = 0; who < MH_N; who++) {
        DWORD cb = 0; BYTE *b = mh_sign(who, OID_SHA1, 0, 0, PL, &cb);
        CHECKF(b != NULL, "signer %d err 0x%lx", who, GetLastError()); if (!b) continue;
        CRYPT_VERIFY_MESSAGE_PARA vp; mh_verify_para_cb(&vp); PCCERT_CONTEXT sc = NULL; DWORD dn = 0;
        CHECK(U(CryptVerifyMessageSignature)(&vp, 0, b, cb, NULL, &dn, &sc));
        CHECKF(sc && sc->cbCertEncoded == (who == 0 ? sizeof v_s1_cert : who == 1 ? sizeof v_s2_cert : who == 2 ? sizeof v_r1_cert : sizeof v_r2_cert), "signer cert %d", who);
        if (sc) U(CertFreeCertificateContext)(sc);
        free(b);
    }
}
TEST(mh_sign_cng_key_via_handle_property) {
    MH_INIT(); REQUIRE(U(CryptSignMessage)); REQUIRE(U(NCryptOpenStorageProvider)); REQUIRE(U(NCryptImportKey));
    NCRYPT_PROV_HANDLE prov = 0; NCRYPT_KEY_HANDLE key = 0;
    if (U(NCryptOpenStorageProvider)(&prov, MS_KEY_STORAGE_PROVIDER, 0) != 0) { t_skip("no KSP"); return; }
    /* RSA private blob in CNG layout: BCRYPT_RSAFULLPRIVATE_MAGIC, built from the CAPI blob */
    const BYTE *k = v_s2_key; DWORD bits = *(const DWORD *)(k + 12), nb = bits / 8, hb = bits / 16;
    DWORD e = *(const DWORD *)(k + 16);
    BYTE be[4] = { (BYTE)(e >> 24), (BYTE)(e >> 16), (BYTE)(e >> 8), (BYTE)e };
    DWORD eoff = 0; while (eoff < 3 && !be[eoff]) eoff++;
    DWORD cbE = 4 - eoff;
    DWORD tot = 24 + cbE + nb + hb + hb + hb + hb + hb + nb;
    BYTE *blob = calloc(1, tot); BCRYPT_RSAKEY_BLOB *h = (BCRYPT_RSAKEY_BLOB *)blob;
    h->Magic = BCRYPT_RSAFULLPRIVATE_MAGIC; h->BitLength = bits; h->cbPublicExp = cbE; h->cbModulus = nb; h->cbPrime1 = hb; h->cbPrime2 = hb;
    BYTE *w = blob + 24; memcpy(w, be + eoff, cbE); w += cbE;
    const BYTE *src = k + 20; const DWORD lens[7] = { nb, hb, hb, hb, hb, hb, nb };
    /* CAPI order: n p q dp dq qinv d ; CNG full order: n p q dp dq qinv d (little to big endian) */
    for (int i = 0; i < 7; i++) { for (DWORD j = 0; j < lens[i]; j++) w[j] = src[lens[i] - 1 - j]; w += lens[i]; src += lens[i]; }
    SECURITY_STATUS st = U(NCryptImportKey)(prov, 0, BCRYPT_RSAFULLPRIVATE_BLOB, NULL, &key, blob, tot, 0);
    free(blob);
    if (st != 0) { t_note("NCryptImportKey failed 0x%lx", (long)st); U(NCryptFreeObject)(prov); return; }
    PCCERT_CONTEXT cc = U(CertDuplicateCertificateContext)(mh_ids[MH_S2].pub);
    PCCERT_CONTEXT own = NULL;
    HCERTSTORE tmp = U(CertOpenStore)(CERT_STORE_PROV_MEMORY, 0, 0, CERT_STORE_NO_CRYPT_RELEASE_FLAG, NULL);
    CHECK(U(CertAddCertificateContextToStore)(tmp, cc, CERT_STORE_ADD_ALWAYS, &own));
    CERT_KEY_CONTEXT kc; memset(&kc, 0, sizeof kc); kc.cbSize = sizeof kc; kc.hNCryptKey = key; kc.dwKeySpec = CERT_NCRYPT_KEY_SPEC;
    if (!U(CertSetCertificateContextProperty)(own, CERT_KEY_CONTEXT_PROP_ID, 0, &kc)) { t_note("set key ctx failed 0x%lx", GetLastError()); }
    else {
        CRYPT_SIGN_MESSAGE_PARA p; mh_sign_para(&p, MH_S2, OID_SHA256); p.pSigningCert = own;
        const BYTE *a[1] = { v_payload }; DWORD l[1] = { sizeof v_payload };
        DWORD n = 0; BOOL r = U(CryptSignMessage)(&p, FALSE, 1, a, l, NULL, &n);
        if (!r && t_is_wine()) t_note("CNG-keyed signer not supported by emulator (0x%lx)", GetLastError());
        else CHECKF(r, "CNG-keyed cert: err 0x%lx", GetLastError());
        if (r) {
            BYTE *b = malloc(n); CHECK(U(CryptSignMessage)(&p, FALSE, 1, a, l, b, &n));
            DWORD c2 = 0; BYTE *b2 = mh_sign(MH_S2, OID_SHA256, 0, 0, PL, &c2);
            CHECK(b2 && c2 == n && !memcmp(b, b2, n));   /* same key, PKCS#1 v1.5: identical bytes */
            free(b); free(b2);
        }
    }
    if (own) U(CertFreeCertificateContext)(own);
    U(CertFreeCertificateContext)(cc); U(CertCloseStore)(tmp, 0);
    U(NCryptFreeObject)(key); U(NCryptFreeObject)(prov);
}
