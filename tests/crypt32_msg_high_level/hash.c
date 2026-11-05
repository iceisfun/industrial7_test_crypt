/* CryptHashMessage, CryptVerifyMessageHash, CryptVerifyDetachedMessageHash. */
#include "mh.h"
#include <stdlib.h>

#define PL v_payload, (DWORD)sizeof v_payload
#define HM U(CryptHashMessage)
#define VMH U(CryptVerifyMessageHash)
#define VDH U(CryptVerifyDetachedMessageHash)

static const struct { const char *oid; const char *name; const BYTE *h, *abc, *empty; DWORD len; } g_h[] = {
    { OID_MD5,    "md5",    v_h_md5,    v_h_md5_abc,    v_h_md5_empty,    16 },
    { OID_SHA1,   "sha1",   v_h_sha1,   v_h_sha1_abc,   v_h_sha1_empty,   20 },
    { OID_SHA256, "sha256", v_h_sha256, v_h_sha256_abc, v_h_sha256_empty, 32 },
    { OID_SHA384, "sha384", v_h_sha384, v_h_sha384_abc, v_h_sha384_empty, 48 },
    { OID_SHA512, "sha512", v_h_sha512, v_h_sha512_abc, v_h_sha512_empty, 64 },
};
#define NH ((int)(sizeof g_h / sizeof g_h[0]))

/* build hashed blob; returns malloc'ed */
static BYTE *hash_blob(const char *oid, int det, const BYTE *data, DWORD cb, DWORD *pn) {
    CRYPT_HASH_MESSAGE_PARA p; mh_hash_para(&p, oid);
    const BYTE *a[1] = { data }; DWORD l[1] = { cb };
    DWORD n = 0;
    if (!HM(&p, det, 1, a, l, NULL, &n, NULL, NULL) || !n) return NULL;
    BYTE *b = malloc(n);
    if (!HM(&p, det, 1, a, l, b, &n, NULL, NULL)) { free(b); return NULL; }
    *pn = n; return b;
}

TEST(mh_hash_computed_hash_known_answers) {
    REQUIRE(HM);
    for (int i = 0; i < NH; i++) {
        CRYPT_HASH_MESSAGE_PARA p; mh_hash_para(&p, g_h[i].oid);
        const BYTE *a[1] = { (const BYTE *)"abc" }; DWORD l[1] = { 3 };
        BYTE h[64]; DWORD hn = sizeof h; SET_ERR(0);
        BOOL r = HM(&p, FALSE, 1, a, l, NULL, NULL, h, &hn);
        CHECKF(r, "%s err 0x%lx", g_h[i].name, GetLastError()); if (!r) continue;
        EXPECT_EQ(hn, g_h[i].len); CHECKF(!memcmp(h, g_h[i].abc, g_h[i].len), "%s digest of abc", g_h[i].name);
    }
}
TEST(mh_hash_computed_hash_of_payload) {
    REQUIRE(HM);
    for (int i = 0; i < NH; i++) {
        CRYPT_HASH_MESSAGE_PARA p; mh_hash_para(&p, g_h[i].oid);
        const BYTE *a[1] = { v_payload }; DWORD l[1] = { sizeof v_payload };
        BYTE h[64]; DWORD hn = sizeof h;
        CHECK(HM(&p, FALSE, 1, a, l, NULL, NULL, h, &hn));
        CHECKF(hn == g_h[i].len && !memcmp(h, g_h[i].h, hn), "%s", g_h[i].name);
    }
}
TEST(mh_hash_empty_content_digest) {
    REQUIRE(HM);
    for (int i = 0; i < NH; i++) {
        CRYPT_HASH_MESSAGE_PARA p; mh_hash_para(&p, g_h[i].oid);
        BYTE h[64]; DWORD hn = sizeof h; SET_ERR(0);
        BOOL r = HM(&p, FALSE, 0, NULL, NULL, NULL, NULL, h, &hn);
        CHECKF(r, "%s cToBeHashed=0 err 0x%lx", g_h[i].name, GetLastError());
        if (r) CHECK(hn == g_h[i].len && !memcmp(h, g_h[i].empty, hn));
        const BYTE *a[1] = { (const BYTE *)"" }; DWORD l[1] = { 0 }; hn = sizeof h;
        r = HM(&p, FALSE, 1, a, l, NULL, NULL, h, &hn);
        CHECKF(r, "%s one empty blob err 0x%lx", g_h[i].name, GetLastError());
        if (r) CHECK(hn == g_h[i].len && !memcmp(h, g_h[i].empty, hn));
    }
}
TEST(mh_hash_multi_blob_equals_concatenation) {
    REQUIRE(HM);
    CRYPT_HASH_MESSAGE_PARA p; mh_hash_para(&p, OID_SHA256);
    const BYTE *a[4] = { v_payload, v_payload + 1, v_payload + 1, v_payload + 30 };
    DWORD l[4] = { 1, 0, 29, (DWORD)sizeof v_payload - 30 };
    BYTE h[32]; DWORD hn = sizeof h; SET_ERR(0);
    /* Windows 10: several blobs are only accepted for a detached hash; an attached hashed message takes exactly one */
    BOOL r = HM(&p, TRUE, 4, a, l, NULL, NULL, h, &hn);
    CHECKF(r, "detached err 0x%lx", GetLastError());
    if (r) CHECK(hn == 32 && !memcmp(h, v_h_sha256, 32));
    for (int cnt = 2; cnt <= 4; cnt++) {
        BYTE *blob = malloc(512); DWORD bn = 512; hn = sizeof h; SET_ERR(0);
        r = HM(&p, FALSE, cnt, a, l, blob, &bn, NULL, NULL);
        t_label("attached, %d blobs", cnt);
        EXPECT_FAIL(r == FALSE, E_CRYPT_E_MSG_ERROR); EXPECT_EQ(bn, 0);
        t_label(NULL); free(blob);
    }
}
TEST(mh_hash_computed_size_query_is_digest_length) {
    REQUIRE(HM);
    for (int i = 0; i < NH; i++) {
        CRYPT_HASH_MESSAGE_PARA p; mh_hash_para(&p, g_h[i].oid);
        const BYTE *a[1] = { v_payload }; DWORD l[1] = { sizeof v_payload };
        DWORD hn = 0xABCD; SET_ERR(0);
        BOOL r = HM(&p, FALSE, 1, a, l, NULL, NULL, NULL, &hn);
        CHECKF(r, "%s err 0x%lx", g_h[i].name, GetLastError());
        EXPECT_EQ(hn, g_h[i].len);
    }
}
TEST(mh_hash_computed_size_query_needs_no_content) {
    REQUIRE(HM);
    CRYPT_HASH_MESSAGE_PARA p; mh_hash_para(&p, OID_SHA256);
    DWORD hn = 0; SET_ERR(0);
    BOOL r = HM(&p, FALSE, 0, NULL, NULL, NULL, NULL, NULL, &hn);
    CHECK(r); EXPECT_EQ(hn, 32);
}
TEST(mh_hash_computed_zero_size_with_buffer_is_more_data) {
    REQUIRE(HM);
    CRYPT_HASH_MESSAGE_PARA p; mh_hash_para(&p, OID_SHA256);
    const BYTE *a[1] = { v_payload }; DWORD l[1] = { sizeof v_payload };
    BYTE h[64]; DWORD hn = 0; SET_ERR(0);
    BOOL r = HM(&p, FALSE, 1, a, l, NULL, NULL, h, &hn);
    EXPECT_FAIL(r == FALSE, ERROR_MORE_DATA); EXPECT_EQ(hn, 32);
}
TEST(mh_hash_computed_short_buffer_more_data) {
    REQUIRE(HM);
    CRYPT_HASH_MESSAGE_PARA p; mh_hash_para(&p, OID_SHA256);
    const BYTE *a[1] = { v_payload }; DWORD l[1] = { sizeof v_payload };
    static const DWORD sizes[] = { 1, 16, 31 };
    for (int i = 0; i < 3; i++) {
        BYTE h[64]; DWORD hn = sizes[i]; SET_ERR(0);
        BOOL r = HM(&p, FALSE, 1, a, l, NULL, NULL, h, &hn);
        EXPECT_FAIL(r == FALSE, ERROR_MORE_DATA); EXPECT_EQ(hn, 32);
    }
}
TEST(mh_hash_computed_oversized_buffer_reports_actual) {
    REQUIRE(HM);
    CRYPT_HASH_MESSAGE_PARA p; mh_hash_para(&p, OID_SHA1);
    const BYTE *a[1] = { v_payload }; DWORD l[1] = { sizeof v_payload };
    BYTE h[64]; memset(h, 0x5a, sizeof h); DWORD hn = sizeof h;
    CHECK(HM(&p, FALSE, 1, a, l, NULL, NULL, h, &hn));
    EXPECT_EQ(hn, 20); CHECK(h[20] == 0x5a);
}
TEST(mh_hash_blob_header_and_structure) {
    REQUIRE(HM);
    DWORD n = 0; BYTE *b = hash_blob(OID_SHA256, FALSE, PL, &n);
    CHECK(b != NULL); if (!b) return;
    EXPECT_EQ(mh_der_total(b, n), n);
    DWORD h = mh_der_hdr(b, n); CHECK(h + 11 <= n && !memcmp(b + h, MH_OID_HASHED, 11));
    CHECK(mh_has(b, n, v_payload, sizeof v_payload));
    CHECK(mh_has(b, n, v_h_sha256, 32));
    CHECK(MH_HAS(b, n, "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01"));
    free(b);
}
TEST(mh_hash_blob_is_deterministic_and_matches_hand_built) {
    REQUIRE(HM);
    DWORD n1 = 0, n2 = 0; BYTE *a = hash_blob(OID_SHA256, FALSE, PL, &n1), *b = hash_blob(OID_SHA256, FALSE, PL, &n2);
    CHECK(a && b && n1 == n2 && !memcmp(a, b, n1));
    free(a); free(b);
}
TEST(mh_hash_detached_blob_omits_content) {
    REQUIRE(HM);
    DWORD na = 0, nd = 0; BYTE *a = hash_blob(OID_SHA256, FALSE, PL, &na), *d = hash_blob(OID_SHA256, TRUE, PL, &nd);
    CHECK(a && d); if (!a || !d) return;
    CHECK(!mh_has(d, nd, v_payload, sizeof v_payload)); CHECK(mh_has(d, nd, v_h_sha256, 32));
    EXPECT_EQ(na, 137); EXPECT_EQ(nd, 82); /* observed: the detached blob omits the 50 byte payload plus 5 bytes of framing */
    BYTE *d2 = NULL; DWORD n2 = 0; d2 = hash_blob(OID_SHA256, 7, PL, &n2);
    CHECK(d2 && n2 == nd && !memcmp(d2, d, nd));   /* any non-zero fDetachedHash */
    free(a); free(d); free(d2);
}
TEST(mh_hash_blob_size_protocol) {
    REQUIRE(HM);
    CRYPT_HASH_MESSAGE_PARA p; mh_hash_para(&p, OID_SHA256);
    const BYTE *a[1] = { v_payload }; DWORD l[1] = { sizeof v_payload };
    DWORD q = 0x1111; SET_ERR(0);
    CHECK(HM(&p, FALSE, 1, a, l, NULL, &q, NULL, NULL)); EXPECT_EQ(q, 137);
    DWORD cb = 0; BYTE *real = hash_blob(OID_SHA256, FALSE, PL, &cb); CHECK(real != NULL);
    EXPECT_EQ(q, cb);
    BYTE *buf = malloc(q + 8); DWORD n = 0; SET_ERR(0);
    BOOL r = HM(&p, FALSE, 1, a, l, buf, &n, NULL, NULL);
    EXPECT_FAIL(r == FALSE, ERROR_MORE_DATA); EXPECT_EQ(n, q);
    n = cb - 1; SET_ERR(0);
    r = HM(&p, FALSE, 1, a, l, buf, &n, NULL, NULL);
    EXPECT_FAIL(r == FALSE, ERROR_MORE_DATA); EXPECT_EQ(n, cb);
    n = q; CHECK(HM(&p, FALSE, 1, a, l, buf, &n, NULL, NULL)); EXPECT_EQ(n, cb);
    free(buf); free(real);
}
TEST(mh_hash_both_outputs_in_one_call) {
    REQUIRE(HM);
    CRYPT_HASH_MESSAGE_PARA p; mh_hash_para(&p, OID_SHA256);
    const BYTE *a[1] = { v_payload }; DWORD l[1] = { sizeof v_payload };
    DWORD q = 0, hq = 0;
    SET_ERR(0);
    CHECK(HM(&p, FALSE, 1, a, l, NULL, &q, NULL, &hq)); EXPECT_EQ(hq, 32); EXPECT_EQ(q, 137);
    BYTE *buf = malloc(q); BYTE h[32]; DWORD n = q, hn = 32;
    CHECK(HM(&p, FALSE, 1, a, l, buf, &n, h, &hn));
    CHECK(hn == 32 && !memcmp(h, v_h_sha256, 32)); CHECK(mh_der_total(buf, n) == n);
    /* blob buffer OK but hash buffer too small: failure, both sizes reported */
    n = q; hn = 8; SET_ERR(0);
    BOOL r = HM(&p, FALSE, 1, a, l, buf, &n, h, &hn);
    EXPECT_FAIL(r == FALSE, ERROR_MORE_DATA); EXPECT_EQ(hn, 32);
    free(buf);
}
TEST(mh_hash_no_outputs_requested_succeeds) {
    REQUIRE(HM);
    CRYPT_HASH_MESSAGE_PARA p; mh_hash_para(&p, OID_SHA256);
    const BYTE *a[1] = { v_payload }; DWORD l[1] = { sizeof v_payload }; SET_ERR(0);
    CHECK(HM(&p, FALSE, 1, a, l, NULL, NULL, NULL, NULL));
}
TEST(mh_hash_cbsize_must_be_exact) {
    REQUIRE(HM);
    static const DWORD sizes[] = { 0, 4, 0x28, 0x2f, 0x31, 0x38, 0x100 };
    for (int i = 0; i < 7; i++) {
        CRYPT_HASH_MESSAGE_PARA p; mh_hash_para(&p, OID_SHA256); p.cbSize = sizes[i];
        const BYTE *a[1] = { v_payload }; DWORD l[1] = { sizeof v_payload };
        DWORD q = 99, hq = 77; BYTE h[32]; DWORD hn = 32; SET_ERR(0);
        BOOL r = HM(&p, FALSE, 1, a, l, NULL, &q, h, &hn);
        EXPECT_FAIL(r == FALSE, E_INVALIDARG_);
        EXPECT_EQ(q, 0); EXPECT_EQ(hn, 0);
        (void)hq;
    }
}
TEST(mh_hash_unknown_algorithm_fails) {
    REQUIRE(HM);
    static const char *bad[] = { "1.2.3.4.5", "2.16.840.1.101.3.4.2.77" };
    for (int i = 0; i < 2; i++) {
        CRYPT_HASH_MESSAGE_PARA p; mh_hash_para(&p, bad[i]);
        const BYTE *a[1] = { v_payload }; DWORD l[1] = { sizeof v_payload };
        BYTE h[64]; DWORD hn = sizeof h; DWORD q = 0; SET_ERR(0);
        BOOL r = HM(&p, FALSE, 1, a, l, NULL, &q, h, &hn);
        t_label("%s", bad[i]); EXPECT_FAIL(r == FALSE, 0x80091002); /* observed: CRYPT_E_UNKNOWN_ALGO */ t_label(NULL);
        r = HM(&p, FALSE, 1, a, l, NULL, NULL, NULL, &hn);
        CHECKF(r == FALSE, "%s size query", bad[i]); EXPECT_EQ(hn, 0);
    }
}
TEST(mh_hash_bad_encoding_type) {
    REQUIRE(HM);
    CRYPT_HASH_MESSAGE_PARA p; mh_hash_para(&p, OID_SHA256); p.dwMsgEncodingType = 0;
    const BYTE *a[1] = { v_payload }; DWORD l[1] = { sizeof v_payload }; BYTE h[32]; DWORD hn = 32; SET_ERR(0);
    BOOL r = HM(&p, FALSE, 1, a, l, NULL, NULL, h, &hn);
    EXPECT_FAIL(r == FALSE, 0x80070057); /* observed */
    p.dwMsgEncodingType = PKCS_7_ASN_ENCODING; hn = 32;
    CHECK(HM(&p, FALSE, 1, a, l, NULL, NULL, h, &hn));
    p.dwMsgEncodingType = ENC; hn = 32;
    CHECK(HM(&p, FALSE, 1, a, l, NULL, NULL, h, &hn));
}
TEST(mh_hash_large_content) {
    REQUIRE(HM);
    DWORD sz = 1 << 20; BYTE *d = malloc(sz); for (DWORD i = 0; i < sz; i++) d[i] = (BYTE)(i ^ (i >> 7));
    CRYPT_HASH_MESSAGE_PARA p; mh_hash_para(&p, OID_SHA1);
    const BYTE *a[1] = { d }; DWORD l[1] = { sz };
    BYTE h1[20], h2[20]; DWORD hn = 20;
    CHECK(HM(&p, FALSE, 1, a, l, NULL, NULL, h1, &hn));
    const BYTE *a2[2] = { d, d + 12345 }; DWORD l2[2] = { 12345, sz - 12345 }; hn = 20;
    CHECK(HM(&p, TRUE, 2, a2, l2, NULL, NULL, h2, &hn));
    CHECK(!memcmp(h1, h2, 20));
    free(d);
}

/* ---- verification ---------------------------------------------------------------------------- */
TEST(mh_hash_verify_roundtrip_table) {
    REQUIRE(HM); REQUIRE(VMH);
    for (int i = 0; i < NH; i++) {
        DWORD n = 0; BYTE *b = hash_blob(g_h[i].oid, FALSE, PL, &n);
        CHECKF(b != NULL, "%s", g_h[i].name); if (!b) continue;
        CRYPT_HASH_MESSAGE_PARA p; mh_hash_para(&p, g_h[i].oid);
        BYTE d[100], h[64]; DWORD dn = sizeof d, hn = sizeof h; SET_ERR(0);
        BOOL r = VMH(&p, b, n, d, &dn, h, &hn);
        CHECKF(r, "%s err 0x%lx", g_h[i].name, GetLastError());
        if (r) { EXPECT_EQ(dn, sizeof v_payload); CHECK(!memcmp(d, v_payload, dn)); CHECK(hn == g_h[i].len && !memcmp(h, g_h[i].h, hn)); }
        free(b);
    }
}
TEST(mh_hash_verify_hand_built_digested_data) {
    REQUIRE(VMH);
    static const struct { const BYTE *p; DWORD n; const BYTE *h; DWORD hl; } m[] = {
        { v_m_hashed_sha256, sizeof v_m_hashed_sha256, v_h_sha256, 32 }, { v_m_hashed_sha1, sizeof v_m_hashed_sha1, v_h_sha1, 20 } };
    for (int i = 0; i < 2; i++) {
        CRYPT_HASH_MESSAGE_PARA p; mh_hash_para(&p, OID_SHA256);
        BYTE d[100], h[64]; DWORD dn = sizeof d, hn = sizeof h; SET_ERR(0);
        BOOL r = VMH(&p, (BYTE *)m[i].p, m[i].n, d, &dn, h, &hn);
        CHECKF(r, "msg %d err 0x%lx", i, GetLastError());
        if (r) { CHECK(dn == sizeof v_payload && !memcmp(d, v_payload, dn)); CHECK(hn == m[i].hl && !memcmp(h, m[i].h, hn)); }
    }
}
TEST(mh_hash_verify_algorithm_in_para_is_ignored) {
    REQUIRE(VMH);
    CRYPT_HASH_MESSAGE_PARA p; mh_hash_para(&p, "1.2.3.4.5.6");
    BYTE d[100]; DWORD dn = sizeof d; SET_ERR(0);
    BOOL r = VMH(&p, (BYTE *)v_m_hashed_sha256, sizeof v_m_hashed_sha256, d, &dn, NULL, NULL);
    CHECKF(r, "err 0x%lx", GetLastError());
}
TEST(mh_hash_verify_tampered_digest) {
    REQUIRE(VMH);
    BYTE *b = malloc(sizeof v_m_hashed_sha256); memcpy(b, v_m_hashed_sha256, sizeof v_m_hashed_sha256);
    b[sizeof v_m_hashed_sha256 - 3] ^= 0x40;     /* inside the stored digest */
    CRYPT_HASH_MESSAGE_PARA p; mh_hash_para(&p, OID_SHA256);
    BYTE d[100]; DWORD dn = sizeof d; SET_ERR(0);
    BOOL r = VMH(&p, b, sizeof v_m_hashed_sha256, d, &dn, NULL, NULL);
    EXPECT_FAIL(r == FALSE, E_CRYPT_E_HASH_VALUE); EXPECT_EQ(dn, 0);
    BYTE h[32]; DWORD hn = sizeof h; dn = sizeof d; SET_ERR(0);
    r = VMH(&p, b, sizeof v_m_hashed_sha256, d, &dn, h, &hn);
    CHECK(r == FALSE);
    free(b);
}
TEST(mh_hash_verify_tampered_content) {
    REQUIRE(VMH);
    BYTE *b = malloc(sizeof v_m_hashed_sha256); memcpy(b, v_m_hashed_sha256, sizeof v_m_hashed_sha256);
    BYTE *pos = NULL; for (DWORD i = 0; i + 50 <= sizeof v_m_hashed_sha256; i++) if (!memcmp(b + i, v_payload, 50)) { pos = b + i; break; }
    CHECK(pos != NULL); if (pos) pos[3] ^= 1;
    CRYPT_HASH_MESSAGE_PARA p; mh_hash_para(&p, OID_SHA256);
    BYTE d[100]; DWORD dn = sizeof d; SET_ERR(0);
    BOOL r = VMH(&p, b, sizeof v_m_hashed_sha256, d, &dn, NULL, NULL);
    EXPECT_FAIL(r == FALSE, E_CRYPT_E_HASH_VALUE);
    free(b);
}
TEST(mh_hash_verify_size_only_does_not_verify) {
    REQUIRE(VMH);
    BYTE *b = malloc(sizeof v_m_hashed_sha256); memcpy(b, v_m_hashed_sha256, sizeof v_m_hashed_sha256);
    b[sizeof v_m_hashed_sha256 - 3] ^= 0x40;
    CRYPT_HASH_MESSAGE_PARA p; mh_hash_para(&p, OID_SHA256);
    DWORD dn = 0xff; SET_ERR(0);
    BOOL r = VMH(&p, b, sizeof v_m_hashed_sha256, NULL, &dn, NULL, NULL);
    CHECKF(r, "err 0x%lx", GetLastError()); EXPECT_EQ(dn, sizeof v_payload);
    DWORD hn = 0;
    r = VMH(&p, b, sizeof v_m_hashed_sha256, NULL, &dn, NULL, &hn);   /* a computed-hash request forces verification */
    CHECK(r == FALSE);
    free(b);
}
TEST(mh_hash_verify_content_size_protocol) {
    REQUIRE(VMH);
    CRYPT_HASH_MESSAGE_PARA p; mh_hash_para(&p, OID_SHA256);
    BYTE d[100];
    DWORD dn = 0; SET_ERR(0);
    BOOL r = VMH(&p, (BYTE *)v_m_hashed_sha256, sizeof v_m_hashed_sha256, d, &dn, NULL, NULL);
    EXPECT_FAIL(r == FALSE, ERROR_MORE_DATA); EXPECT_EQ(dn, sizeof v_payload);
    dn = sizeof v_payload - 1; SET_ERR(0);
    r = VMH(&p, (BYTE *)v_m_hashed_sha256, sizeof v_m_hashed_sha256, d, &dn, NULL, NULL);
    EXPECT_FAIL(r == FALSE, ERROR_MORE_DATA); EXPECT_EQ(dn, sizeof v_payload);
    dn = sizeof v_payload; CHECK(VMH(&p, (BYTE *)v_m_hashed_sha256, sizeof v_m_hashed_sha256, d, &dn, NULL, NULL));
}
TEST(mh_hash_verify_computed_hash_size_protocol) {
    REQUIRE(VMH);
    CRYPT_HASH_MESSAGE_PARA p; mh_hash_para(&p, OID_SHA256);
    BYTE h[64]; DWORD hn = 0; SET_ERR(0);
    BOOL r = VMH(&p, (BYTE *)v_m_hashed_sha256, sizeof v_m_hashed_sha256, NULL, NULL, NULL, &hn);
    CHECK(r); EXPECT_EQ(hn, 32);
    hn = 0; SET_ERR(0);
    r = VMH(&p, (BYTE *)v_m_hashed_sha256, sizeof v_m_hashed_sha256, NULL, NULL, h, &hn);
    EXPECT_FAIL(r == FALSE, ERROR_MORE_DATA); EXPECT_EQ(hn, 32);
    hn = 31; SET_ERR(0);
    r = VMH(&p, (BYTE *)v_m_hashed_sha256, sizeof v_m_hashed_sha256, NULL, NULL, h, &hn);
    EXPECT_FAIL(r == FALSE, ERROR_MORE_DATA); EXPECT_EQ(hn, 32);
    hn = 64; CHECK(VMH(&p, (BYTE *)v_m_hashed_sha256, sizeof v_m_hashed_sha256, NULL, NULL, h, &hn)); EXPECT_EQ(hn, 32);
}
TEST(mh_hash_verify_only_no_outputs) {
    REQUIRE(VMH);
    CRYPT_HASH_MESSAGE_PARA p; mh_hash_para(&p, OID_SHA256);
    CHECK(VMH(&p, (BYTE *)v_m_hashed_sha256, sizeof v_m_hashed_sha256, NULL, NULL, NULL, NULL));
}
TEST(mh_hash_verify_wrong_message_type) {
    REQUIRE(VMH);
    CRYPT_HASH_MESSAGE_PARA p; mh_hash_para(&p, OID_SHA256);
    BYTE d[100]; DWORD dn = sizeof d; SET_ERR(0);
    BOOL r = VMH(&p, (BYTE *)v_m_sig_noattr, sizeof v_m_sig_noattr, d, &dn, NULL, NULL);
    EXPECT_FAIL(r == FALSE, E_CRYPT_E_UNEXPECTED_MSG_TYPE); EXPECT_EQ(dn, 0);
    r = VMH(&p, (BYTE *)v_m_env_aes128, sizeof v_m_env_aes128, NULL, &dn, NULL, NULL);
    EXPECT_FAIL(r == FALSE, E_CRYPT_E_UNEXPECTED_MSG_TYPE);
}
TEST(mh_hash_verify_cbsize_and_garbage) {
    REQUIRE(VMH);
    CRYPT_HASH_MESSAGE_PARA p; mh_hash_para(&p, OID_SHA256); p.cbSize = 0x28;
    BYTE d[100]; DWORD dn = sizeof d; SET_ERR(0);
    BOOL r = VMH(&p, (BYTE *)v_m_hashed_sha256, sizeof v_m_hashed_sha256, d, &dn, NULL, NULL);
    EXPECT_FAIL(r == FALSE, E_INVALIDARG_); EXPECT_EQ(dn, 0);
    mh_hash_para(&p, OID_SHA256);
    static const BYTE g[] = { 0x30, 0x03, 0x02, 0x01, 0x01 };
    dn = sizeof d; SET_ERR(0);
    r = VMH(&p, (BYTE *)g, sizeof g, d, &dn, NULL, NULL);
    EXPECT_FAIL(r == FALSE, 0x8009310B); EXPECT_EQ(dn, 0); /* observed: ASN1 bad tag */
    r = VMH(&p, (BYTE *)g, 0, d, &dn, NULL, NULL); CHECK(r == FALSE);
}
TEST(mh_hash_verify_detached_hash_blob_as_attached) {
    REQUIRE(VMH);
    CRYPT_HASH_MESSAGE_PARA p; mh_hash_para(&p, OID_SHA256);
    BYTE d[100]; DWORD dn = sizeof d; SET_ERR(0);
    BOOL r = VMH(&p, (BYTE *)v_m_hashed_sha256_det, sizeof v_m_hashed_sha256_det, d, &dn, NULL, NULL);
    EXPECT_FAIL(r == FALSE, 0x80091007); /* observed: CRYPT_E_HASH_VALUE */
}

/* ---- detached verify ------------------------------------------------------------------------ */
TEST(mh_hash_detached_verify_roundtrip_table) {
    REQUIRE(HM); REQUIRE(VDH);
    for (int i = 0; i < NH; i++) {
        DWORD n = 0; BYTE *b = hash_blob(g_h[i].oid, TRUE, PL, &n);
        CHECKF(b != NULL, "%s", g_h[i].name); if (!b) continue;
        CRYPT_HASH_MESSAGE_PARA p; mh_hash_para(&p, g_h[i].oid);
        const BYTE *a[1] = { v_payload }; DWORD l[1] = { sizeof v_payload };
        BYTE h[64]; DWORD hn = sizeof h; SET_ERR(0);
        BOOL r = VDH(&p, b, n, 1, a, l, h, &hn);
        CHECKF(r, "%s err 0x%lx", g_h[i].name, GetLastError());
        if (r) CHECK(hn == g_h[i].len && !memcmp(h, g_h[i].h, hn));
        free(b);
    }
}
TEST(mh_hash_detached_verify_hand_built) {
    REQUIRE(VDH);
    CRYPT_HASH_MESSAGE_PARA p; mh_hash_para(&p, OID_SHA256);
    const BYTE *a[2] = { v_payload, v_payload + 17 }; DWORD l[2] = { 17, (DWORD)sizeof v_payload - 17 };
    BYTE h[32]; DWORD hn = sizeof h; SET_ERR(0);
    BOOL r = VDH(&p, (BYTE *)v_m_hashed_sha256_det, sizeof v_m_hashed_sha256_det, 2, a, l, h, &hn);
    CHECKF(r, "err 0x%lx", GetLastError());
    if (r) CHECK(hn == 32 && !memcmp(h, v_h_sha256, 32));
    CHECK(VDH(&p, (BYTE *)v_m_hashed_sha256_det, sizeof v_m_hashed_sha256_det, 2, a, l, NULL, NULL));
}
TEST(mh_hash_detached_verify_modified_content) {
    REQUIRE(VDH);
    CRYPT_HASH_MESSAGE_PARA p; mh_hash_para(&p, OID_SHA256);
    BYTE c[sizeof v_payload]; memcpy(c, v_payload, sizeof c); c[0] ^= 0x80;
    const BYTE *a[1] = { c }; DWORD l[1] = { sizeof c }; SET_ERR(0);
    BOOL r = VDH(&p, (BYTE *)v_m_hashed_sha256_det, sizeof v_m_hashed_sha256_det, 1, a, l, NULL, NULL);
    EXPECT_FAIL(r == FALSE, E_CRYPT_E_HASH_VALUE);
}
TEST(mh_hash_detached_verify_computed_size_protocol) {
    REQUIRE(VDH);
    CRYPT_HASH_MESSAGE_PARA p; mh_hash_para(&p, OID_SHA256);
    const BYTE *a[1] = { v_payload }; DWORD l[1] = { sizeof v_payload };
    BYTE h[64]; DWORD hn = 0; SET_ERR(0);
    BOOL r = VDH(&p, (BYTE *)v_m_hashed_sha256_det, sizeof v_m_hashed_sha256_det, 1, a, l, NULL, &hn);
    CHECK(r); EXPECT_EQ(hn, 32);
    hn = 4; SET_ERR(0);
    r = VDH(&p, (BYTE *)v_m_hashed_sha256_det, sizeof v_m_hashed_sha256_det, 1, a, l, h, &hn);
    EXPECT_FAIL(r == FALSE, ERROR_MORE_DATA); EXPECT_EQ(hn, 32);
}
TEST(mh_hash_detached_verify_no_content_fails) {
    REQUIRE(VDH);
    CRYPT_HASH_MESSAGE_PARA p; mh_hash_para(&p, OID_SHA256); SET_ERR(0);
    BOOL r = VDH(&p, (BYTE *)v_m_hashed_sha256_det, sizeof v_m_hashed_sha256_det, 0, NULL, NULL, NULL, NULL);
    /* with no content arguments and no computed-hash output nothing is hashed, so the call only parses the message */
    EXPECT_EQ(r, TRUE);
    BYTE h[64]; DWORD hn = sizeof h; SET_ERR(0);
    r = VDH(&p, (BYTE *)v_m_hashed_sha256_det, sizeof v_m_hashed_sha256_det, 0, NULL, NULL, h, &hn);
    EXPECT_FAIL(r == FALSE, E_CRYPT_E_HASH_VALUE);
}
TEST(mh_hash_detached_verify_wrong_type_and_cbsize) {
    REQUIRE(VDH);
    CRYPT_HASH_MESSAGE_PARA p; mh_hash_para(&p, OID_SHA256);
    const BYTE *a[1] = { v_payload }; DWORD l[1] = { sizeof v_payload }; SET_ERR(0);
    BOOL r = VDH(&p, (BYTE *)v_m_sig_det_noattr, sizeof v_m_sig_det_noattr, 1, a, l, NULL, NULL);
    EXPECT_FAIL(r == FALSE, E_CRYPT_E_UNEXPECTED_MSG_TYPE);
    p.cbSize = 0x2f; SET_ERR(0);
    r = VDH(&p, (BYTE *)v_m_hashed_sha256_det, sizeof v_m_hashed_sha256_det, 1, a, l, NULL, NULL);
    EXPECT_FAIL(r == FALSE, E_INVALIDARG_);
}
TEST(mh_hash_detached_verify_attached_blob_with_content) {
    REQUIRE(VDH);
    CRYPT_HASH_MESSAGE_PARA p; mh_hash_para(&p, OID_SHA256);
    const BYTE *a[1] = { v_payload }; DWORD l[1] = { sizeof v_payload }; SET_ERR(0);
    BOOL r = VDH(&p, (BYTE *)v_m_hashed_sha256, sizeof v_m_hashed_sha256, 1, a, l, NULL, NULL);
    EXPECT_FAIL(r == FALSE, 0x80091007); /* observed: CRYPT_E_HASH_VALUE */
}
