/* CryptEncryptMessage, CryptDecryptMessage, CryptSignAndEncryptMessage, CryptDecryptAndVerifyMessageSignature. */
#include "mh.h"
#include <stdlib.h>

#define PL v_payload, (DWORD)sizeof v_payload
#define ENCM U(CryptEncryptMessage)
#define DECM U(CryptDecryptMessage)

static BYTE *enc_blob(const char *oid, DWORD flags, int nrcpt, int who1, int who2, DWORD *pn) {
    CRYPT_ENCRYPT_MESSAGE_PARA p; mh_enc_para(&p, oid); p.dwFlags = flags;
    PCCERT_CONTEXT rc[2] = { mh_ids[who1].pub, mh_ids[who2].pub };
    DWORD n = 0;
    if (!ENCM(&p, nrcpt, rc, v_payload, sizeof v_payload, NULL, &n) || !n) return NULL;
    BYTE *b = malloc(n);
    if (!ENCM(&p, nrcpt, rc, v_payload, sizeof v_payload, b, &n)) { free(b); return NULL; }
    *pn = n; return b;
}
static BOOL dec_with(HCERTSTORE s, const BYTE *b, DWORD n, BYTE *out, DWORD *pn, PCCERT_CONTEXT *x) {
    CRYPT_DECRYPT_MESSAGE_PARA dp; mh_dec_para(&dp); HCERTSTORE st[1] = { s }; dp.rghCertStore = st;
    return DECM(&dp, (BYTE *)b, n, out, pn, x);
}

TEST(mh_encrypt_header_is_enveloped_data) {
    MH_INIT(); REQUIRE(ENCM);
    DWORD n = 0; BYTE *b = enc_blob("2.16.840.1.101.3.4.1.2", 0, 1, MH_R1, MH_R1, &n);
    if (!b && t_is_wine()) { t_note("AES content encryption unsupported by the emulator (0x%lx)", GetLastError()); return; }
    CHECKF(b != NULL, "err 0x%lx", GetLastError()); if (!b) return;
    EXPECT_EQ(mh_der_total(b, n), n);
    DWORD h = mh_der_hdr(b, n); CHECK(h + 11 <= n && !memcmp(b + h, MH_OID_ENVELOPED, 11));
    CHECK(!mh_has(b, n, v_payload, 16));                       /* content is encrypted */
    CHECK(MH_HAS(b, n, "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x01\x02"));   /* aes128-CBC identifier */
    free(b);
}
TEST(mh_encrypt_header_3des) {
    MH_INIT(); REQUIRE(ENCM);
    DWORD n = 0; BYTE *b = enc_blob("1.2.840.113549.3.7", 0, 1, MH_R1, MH_R1, &n);
    CHECKF(b != NULL, "err 0x%lx", GetLastError()); if (!b) return;
    EXPECT_EQ(mh_der_total(b, n), n);
    DWORD h = mh_der_hdr(b, n); CHECK(h + 11 <= n && !memcmp(b + h, MH_OID_ENVELOPED, 11));
    CHECK(!mh_has(b, n, v_payload, 16));
    CHECK(MH_HAS(b, n, "\x06\x08\x2a\x86\x48\x86\xf7\x0d\x03\x07"));    /* des-EDE3-CBC identifier */
    CHECK(MH_HAS(b, n, "\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01"));
    free(b);
}
TEST(mh_encrypt_is_randomized) {
    MH_INIT(); REQUIRE(ENCM);
    DWORD n1 = 0, n2 = 0; BYTE *a = enc_blob("1.2.840.113549.3.7", 0, 1, MH_R1, MH_R1, &n1), *b = enc_blob("1.2.840.113549.3.7", 0, 1, MH_R1, MH_R1, &n2);
    CHECK(a && b); if (a && b) { CHECK(n1 == n2); CHECK(n1 != n2 || memcmp(a, b, n1)); }
    free(a); free(b);
}
TEST(mh_encrypt_size_protocol) {
    MH_INIT(); REQUIRE(ENCM);
    CRYPT_ENCRYPT_MESSAGE_PARA p; mh_enc_para(&p, "1.2.840.113549.3.7");
    PCCERT_CONTEXT rc[1] = { mh_ids[MH_R1].pub };
    DWORD q = 0x77; SET_ERR(0);
    CHECK(ENCM(&p, 1, rc, v_payload, sizeof v_payload, NULL, &q)); EXPECT_EQ(q, 322);
    BYTE *buf = malloc(q + 16); DWORD n = 0; SET_ERR(0);
    BOOL r = ENCM(&p, 1, rc, v_payload, sizeof v_payload, buf, &n);
    EXPECT_FAIL(r == FALSE, ERROR_MORE_DATA); EXPECT_EQ(n, q);
    n = q; CHECK(ENCM(&p, 1, rc, v_payload, sizeof v_payload, buf, &n)); EXPECT_EQ(n, q); CHECK(mh_der_total(buf, n) == n);
    DWORD full = n; n = full - 1; SET_ERR(0);
    r = ENCM(&p, 1, rc, v_payload, sizeof v_payload, buf, &n);
    EXPECT_FAIL(r == FALSE, ERROR_MORE_DATA); EXPECT_EQ(n, full);
    free(buf);
}
TEST(mh_encrypt_cbsize_checks) {
    MH_INIT(); REQUIRE(ENCM);
    static const DWORD sz[] = { 0, 4, 0x20, 0x2f };
    PCCERT_CONTEXT rc[1] = { mh_ids[MH_R1].pub };
    for (int i = 0; i < 4; i++) {
        CRYPT_ENCRYPT_MESSAGE_PARA p; mh_enc_para(&p, "1.2.840.113549.3.7"); p.cbSize = sz[i];
        DWORD n = 88; SET_ERR(0);
        BOOL r = ENCM(&p, 1, rc, v_payload, sizeof v_payload, NULL, &n);
        EXPECT_FAIL(r == FALSE, E_INVALIDARG_); EXPECT_EQ(n, 0);
    }
    CRYPT_ENCRYPT_MESSAGE_PARA p; mh_enc_para(&p, "1.2.840.113549.3.7"); p.cbSize = 0x30;
    DWORD n = 0; CHECK(ENCM(&p, 1, rc, v_payload, sizeof v_payload, NULL, &n)); EXPECT_EQ(n, 322);
}
TEST(mh_encrypt_flags_need_cbsize_0x38) {
    MH_INIT(); REQUIRE(ENCM);
    PCCERT_CONTEXT rc[1] = { mh_ids[MH_R1].pub };
    for (int pass = 0; pass < 2; pass++) {
        CRYPT_ENCRYPT_MESSAGE_PARA p; mh_enc_para(&p, "1.2.840.113549.3.7"); p.dwFlags = CRYPT_MESSAGE_BARE_CONTENT_OUT_FLAG; p.cbSize = pass ? sizeof p : 0x30;
        DWORD n = 0; BYTE *b;
        CHECK(ENCM(&p, 1, rc, v_payload, sizeof v_payload, NULL, &n));
        b = malloc(n); CHECK(ENCM(&p, 1, rc, v_payload, sizeof v_payload, b, &n));
        DWORD h = mh_der_hdr(b, n); int has_oid = h + 11 <= n && !memcmp(b + h, MH_OID_ENVELOPED, 11);
        CHECKF(has_oid == !pass, "pass %d: ContentInfo wrapper present=%d", pass, has_oid);
        if (pass) CHECK(b[h] == 0x02);    /* bare EnvelopedData starts with its version INTEGER */
        free(b);
    }
}
TEST(mh_encrypt_algorithm_table_roundtrip) {
    MH_NOWINE(); MH_INIT(); REQUIRE(ENCM); REQUIRE(DECM);
    static const struct { const char *oid; const char *name; int hard; DWORD dec_err; } t[] = {
        { "2.16.840.1.101.3.4.1.2",  "aes128", 1, 0 }, { "2.16.840.1.101.3.4.1.42", "aes256", 1, 0 },
        { "1.2.840.113549.3.7",      "3des",   1, 0 }, { "1.2.840.113549.3.2",      "rc2",    1, 0 },
        { "2.16.840.1.101.3.4.1.22", "aes192", 1, 0 }, { "1.3.14.3.2.7",            "des",    1, 0 },
        { "1.2.840.113549.3.4",      "rc4",    1, ERROR_NOT_SUPPORTED } };   /* rc4 content encrypts but cannot be decrypted */
    for (unsigned i = 0; i < sizeof t / sizeof t[0]; i++) {
        DWORD n = 0; SET_ERR(0); BYTE *b = enc_blob(t[i].oid, 0, 1, MH_R1, MH_R1, &n);
        if (!b) { CHECKF(0, "%s encrypt err 0x%lx", t[i].name, GetLastError()); continue; }
        BYTE d[200]; DWORD dn = sizeof d; PCCERT_CONTEXT x = NULL; SET_ERR(0);
        BOOL r = dec_with(mh_priv_store, b, n, d, &dn, &x);
        t_label("%s", t[i].name);
        if (t[i].dec_err) { EXPECT_FAIL(r == FALSE, t[i].dec_err); t_label(NULL); FREE_CERT(x); free(b); continue; }
        t_label(NULL);
        CHECKF(r, "%s decrypt err 0x%lx", t[i].name, GetLastError());
        if (r) { CHECKF(dn == sizeof v_payload && !memcmp(d, v_payload, dn), "%s plaintext", t[i].name); CHECK(CERT_IS(x, v_r1_cert)); }
        FREE_CERT(x); free(b);
    }
}
TEST(mh_encrypt_key_transport_algorithm_observed) {
    MH_INIT(); REQUIRE(ENCM);
    DWORD n = 0; BYTE *a = enc_blob("2.16.840.1.101.3.4.1.2", 0, 1, MH_R1, MH_R1, &n);
    /* observed: with an AES content key the RSA recipient is wrapped as RSAES-OAEP, with 3DES as plain rsaEncryption */
    CHECK(a != NULL); if (a) { CHECK(MH_HAS(a, n, MH_OID_OAEP)); free(a); }
    BYTE *b = enc_blob("1.2.840.113549.3.7", 0, 1, MH_R1, MH_R1, &n);
    CHECK(b != NULL);
    if (b) { CHECK(!MH_HAS(b, n, MH_OID_OAEP));
             CHECK(MH_HAS(b, n, "\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01")); free(b); }
}
TEST(mh_encrypt_unknown_algorithm) {
    MH_INIT(); REQUIRE(ENCM);
    static const char *bad[] = { "1.2.3.4.5", "1.2.840.113549.1.1.11" };
    PCCERT_CONTEXT rc[1] = { mh_ids[MH_R1].pub };
    for (int i = 0; i < 2; i++) {
        CRYPT_ENCRYPT_MESSAGE_PARA p; mh_enc_para(&p, bad[i]); DWORD n = 55; SET_ERR(0);
        BYTE tmp[8];
        BOOL r = ENCM(&p, 1, rc, v_payload, sizeof v_payload, NULL, &n);
        EXPECT_FAIL(r == FALSE, 0x80091002); /* observed: CRYPT_E_UNKNOWN_ALGO, also for a signature algorithm OID */
        EXPECT_EQ(n, 0);
        (void)tmp;
    }
}
TEST(mh_encrypt_two_recipients_each_can_decrypt) {
    MH_NOWINE(); MH_INIT(); REQUIRE(ENCM); REQUIRE(DECM);
    DWORD n = 0; BYTE *b = enc_blob("2.16.840.1.101.3.4.1.2", 0, 2, MH_R1, MH_R2, &n);
    CHECKF(b != NULL, "err 0x%lx", GetLastError()); if (!b) return;
    for (int who = MH_R1; who <= MH_R2; who++) {
        HCERTSTORE s = mh_make_store(1u << who, 0);
        BYTE d[100]; DWORD dn = sizeof d; PCCERT_CONTEXT x = NULL; SET_ERR(0);
        BOOL r = dec_with(s, b, n, d, &dn, &x);
        CHECKF(r, "recipient %d err 0x%lx", who, GetLastError());
        if (r) { CHECK(dn == sizeof v_payload && !memcmp(d, v_payload, dn)); CHECK(who == MH_R1 ? CERT_IS(x, v_r1_cert) : CERT_IS(x, v_r2_cert)); }
        FREE_CERT(x); U(CertCloseStore)(s, 0);
    }
    free(b);
}
TEST(mh_encrypt_recipient_count_scales_size) {
    MH_INIT(); REQUIRE(ENCM);
    CRYPT_ENCRYPT_MESSAGE_PARA p; mh_enc_para(&p, "1.2.840.113549.3.7");
    PCCERT_CONTEXT rc[3] = { mh_ids[MH_R1].pub, mh_ids[MH_R2].pub, mh_ids[MH_R1].pub };
    DWORD s1 = 0, s2 = 0, s3 = 0;
    CHECK(ENCM(&p, 1, rc, v_payload, sizeof v_payload, NULL, &s1));
    CHECK(ENCM(&p, 2, rc, v_payload, sizeof v_payload, NULL, &s2));
    CHECK(ENCM(&p, 3, rc, v_payload, sizeof v_payload, NULL, &s3));
    EXPECT_EQ(s1, 322); EXPECT_EQ(s2, 523); EXPECT_EQ(s3, 723); /* observed: about 200 bytes per additional recipient */
}
TEST(mh_encrypt_zero_recipients) {
    MH_INIT(); REQUIRE(ENCM);
    CRYPT_ENCRYPT_MESSAGE_PARA p; mh_enc_para(&p, "1.2.840.113549.3.7");
    DWORD n = 33; SET_ERR(0);
    BOOL r = ENCM(&p, 0, NULL, v_payload, sizeof v_payload, NULL, &n);
    CHECK(r); EXPECT_EQ(n, 115); /* observed: accepted, an EnvelopedData without recipients */
}
TEST(mh_encrypt_empty_plaintext_roundtrip) {
    MH_NOWINE(); MH_INIT(); REQUIRE(ENCM); REQUIRE(DECM);
    CRYPT_ENCRYPT_MESSAGE_PARA p; mh_enc_para(&p, "2.16.840.1.101.3.4.1.2");
    PCCERT_CONTEXT rc[1] = { mh_ids[MH_R1].pub };
    DWORD n = 0; SET_ERR(0);
    BOOL r = ENCM(&p, 1, rc, (BYTE *)"", 0, NULL, &n);
    CHECKF(r, "err 0x%lx", GetLastError()); if (!r) return;
    BYTE *b = malloc(n); CHECK(ENCM(&p, 1, rc, (BYTE *)"", 0, b, &n));
    BYTE d[16]; DWORD dn = sizeof d; SET_ERR(0);
    r = dec_with(mh_priv_store, b, n, d, &dn, NULL);
    CHECKF(r, "err 0x%lx", GetLastError()); EXPECT_EQ(dn, 0); /* observed */
    free(b);
}
TEST(mh_encrypt_large_plaintext_roundtrip) {
    MH_NOWINE(); MH_INIT(); REQUIRE(ENCM); REQUIRE(DECM);
    DWORD sz = 200000 + 7; BYTE *pt = malloc(sz); for (DWORD i = 0; i < sz; i++) pt[i] = (BYTE)(i * 7 + (i >> 9));
    CRYPT_ENCRYPT_MESSAGE_PARA p; mh_enc_para(&p, "2.16.840.1.101.3.4.1.42");
    PCCERT_CONTEXT rc[1] = { mh_ids[MH_R2].pub };
    DWORD n = 0; CHECK(ENCM(&p, 1, rc, pt, sz, NULL, &n)); EXPECT_EQ(n, 200300);
    BYTE *b = malloc(n); CHECK(ENCM(&p, 1, rc, pt, sz, b, &n));
    DWORD dn = 0; PCCERT_CONTEXT x = NULL;
    CHECK(dec_with(mh_priv_store, b, n, NULL, &dn, NULL)); EXPECT_EQ(dn, 200022); /* observed: the query over-reports by the padding block (15 bytes beyond the plaintext) */
    BYTE *d = malloc(dn + 1);
    CHECK(dec_with(mh_priv_store, b, n, d, &dn, &x)); CHECK(dn == sz && !memcmp(d, pt, sz)); CHECK(CERT_IS(x, v_r2_cert));
    FREE_CERT(x); free(d); free(b); free(pt);
}

/* ---- decrypt ---------------------------------------------------------------------------------- */
TEST(mh_decrypt_external_messages_table) {
    MH_NOWINE(); MH_INIT(); REQUIRE(DECM);
    static const struct { const char *n; const BYTE *p; DWORD cb; int who; } t[] = {
        { "aes256", v_m_env_aes256, sizeof v_m_env_aes256, MH_R1 }, { "aes128", v_m_env_aes128, sizeof v_m_env_aes128, MH_R1 },
        { "3des", v_m_env_des3, sizeof v_m_env_des3, MH_R1 }, { "two/r1", v_m_env_two, sizeof v_m_env_two, MH_R1 },
        { "two/r2", v_m_env_two, sizeof v_m_env_two, MH_R2 }, { "r2", v_m_env_r2, sizeof v_m_env_r2, MH_R2 } };
    for (unsigned i = 0; i < 6; i++) {
        HCERTSTORE s = mh_make_store(1u << t[i].who, 0);
        BYTE d[100]; DWORD dn = sizeof d; PCCERT_CONTEXT x = NULL; SET_ERR(0);
        BOOL r = dec_with(s, t[i].p, t[i].cb, d, &dn, &x);
        CHECKF(r, "%s err 0x%lx", t[i].n, GetLastError());
        if (r) { CHECKF(dn == sizeof v_payload && !memcmp(d, v_payload, dn), "%s plaintext", t[i].n); CHECK(t[i].who == MH_R1 ? CERT_IS(x, v_r1_cert) : CERT_IS(x, v_r2_cert)); }
        FREE_CERT(x); U(CertCloseStore)(s, 0);
    }
}
TEST(mh_decrypt_no_matching_certificate) {
    MH_NOWINE(); MH_INIT(); REQUIRE(DECM);
    HCERTSTORE s = mh_make_store(1u << MH_R1, 0);
    BYTE d[100]; DWORD dn = sizeof d; PCCERT_CONTEXT x = (PCCERT_CONTEXT)1; SET_ERR(0);
    BOOL r = dec_with(s, v_m_env_r2, sizeof v_m_env_r2, d, &dn, &x);
    EXPECT_FAIL(r == FALSE, E_CRYPT_E_NO_DECRYPT_CERT);
    CHECK(x == NULL); EXPECT_EQ(dn, 0);
    U(CertCloseStore)(s, 0);
}
TEST(mh_decrypt_certificate_without_private_key) {
    MH_NOWINE(); MH_INIT(); REQUIRE(DECM);
    HCERTSTORE s = mh_make_store(0, 1u << MH_R1);
    BYTE d[100]; DWORD dn = sizeof d; PCCERT_CONTEXT x = (PCCERT_CONTEXT)1; SET_ERR(0);
    BOOL r = dec_with(s, v_m_env_aes128, sizeof v_m_env_aes128, d, &dn, &x);
    EXPECT_FAIL(r == FALSE, E_CRYPT_E_NO_DECRYPT_CERT);
    CHECK(x == NULL); U(CertCloseStore)(s, 0);
}
TEST(mh_decrypt_empty_store_list) {
    MH_NOWINE(); MH_INIT(); REQUIRE(DECM);
    CRYPT_DECRYPT_MESSAGE_PARA dp; mh_dec_para(&dp); dp.cCertStore = 0; dp.rghCertStore = NULL;
    BYTE d[100]; DWORD dn = sizeof d; SET_ERR(0);
    BOOL r = DECM(&dp, (BYTE *)v_m_env_aes128, sizeof v_m_env_aes128, d, &dn, NULL);
    EXPECT_FAIL(r == FALSE, E_CRYPT_E_NO_DECRYPT_CERT);
}
TEST(mh_decrypt_searches_all_stores) {
    MH_NOWINE(); MH_INIT(); REQUIRE(DECM);
    HCERTSTORE s1 = mh_make_store(1u << MH_S1, 0), s2 = mh_make_store(1u << MH_R1, 0);
    HCERTSTORE st[2] = { s1, s2 };
    CRYPT_DECRYPT_MESSAGE_PARA dp; mh_dec_para(&dp); dp.cCertStore = 2; dp.rghCertStore = st;
    BYTE d[100]; DWORD dn = sizeof d; PCCERT_CONTEXT x = NULL; SET_ERR(0);
    BOOL r = DECM(&dp, (BYTE *)v_m_env_aes128, sizeof v_m_env_aes128, d, &dn, &x);
    CHECKF(r, "err 0x%lx", GetLastError()); CHECK(CERT_IS(x, v_r1_cert)); FREE_CERT(x);
    U(CertCloseStore)(s1, 0); U(CertCloseStore)(s2, 0);
}
TEST(mh_decrypt_size_query_does_not_need_key) {
    MH_NOWINE(); MH_INIT(); REQUIRE(DECM);
    HCERTSTORE s = mh_make_store(1u << MH_R1, 0);        /* wrong recipient for m_env_r2 */
    DWORD dn = 0; SET_ERR(0);
    BOOL r = dec_with(s, v_m_env_r2, sizeof v_m_env_r2, NULL, &dn, NULL);
    CHECKF(r, "err 0x%lx", GetLastError());
    EXPECT_EQ(dn, 70); /* observed: 50 payload bytes -> 70 (padded ciphertext length) */
    dn = 0; PCCERT_CONTEXT x = (PCCERT_CONTEXT)1;
    r = dec_with(s, v_m_env_r2, sizeof v_m_env_r2, NULL, &dn, &x);   /* asking for the cert forces decryption */
    CHECK(r == FALSE); CHECK(x == NULL);
    U(CertCloseStore)(s, 0);
}
TEST(mh_decrypt_buffer_too_small_reports_plaintext_size) {
    MH_NOWINE(); MH_INIT(); REQUIRE(DECM);
    static const DWORD sz[] = { 0, 1, sizeof v_payload - 1 };
    for (int i = 0; i < 3; i++) {
        BYTE d[100]; DWORD dn = sz[i]; PCCERT_CONTEXT x = (PCCERT_CONTEXT)1; SET_ERR(0);
        BOOL r = dec_with(mh_priv_store, v_m_env_aes128, sizeof v_m_env_aes128, d, &dn, &x);
        EXPECT_FAIL(r == FALSE, ERROR_MORE_DATA);
        EXPECT_EQ(dn, sizeof v_payload); CHECK(x == NULL);
    }
}
TEST(mh_decrypt_no_outputs) {
    MH_NOWINE(); MH_INIT(); REQUIRE(DECM);
    SET_ERR(0);
    CHECK(dec_with(mh_priv_store, v_m_env_aes128, sizeof v_m_env_aes128, NULL, NULL, NULL));
    HCERTSTORE s = mh_make_store(1u << MH_R1, 0);
    CHECK(!dec_with(s, v_m_env_r2, sizeof v_m_env_r2, NULL, NULL, NULL));
    U(CertCloseStore)(s, 0);
}
TEST(mh_decrypt_cbsize_checks) {
    MH_NOWINE(); MH_INIT(); REQUIRE(DECM);
    static const DWORD sz[] = { 0, 4, 0x10, 0x17 };
    for (int i = 0; i < 4; i++) {
        CRYPT_DECRYPT_MESSAGE_PARA dp; mh_dec_para(&dp); dp.cbSize = sz[i];
        BYTE d[100]; DWORD dn = sizeof d; PCCERT_CONTEXT x = (PCCERT_CONTEXT)1; SET_ERR(0);
        BOOL r = DECM(&dp, (BYTE *)v_m_env_aes128, sizeof v_m_env_aes128, d, &dn, &x);
        EXPECT_FAIL(r == FALSE, E_INVALIDARG_); EXPECT_EQ(dn, 0); CHECK(x == NULL);
    }
    CRYPT_DECRYPT_MESSAGE_PARA dp; mh_dec_para(&dp); dp.cbSize = 0x18;
    BYTE d[100]; DWORD dn = sizeof d; CHECK(DECM(&dp, (BYTE *)v_m_env_aes128, sizeof v_m_env_aes128, d, &dn, NULL));
}
TEST(mh_decrypt_wrong_message_type) {
    MH_NOWINE(); MH_INIT(); REQUIRE(DECM);
    CRYPT_DECRYPT_MESSAGE_PARA dp; mh_dec_para(&dp);
    static const struct { const BYTE *p; DWORD n; } m[] = { { v_m_sig_noattr, sizeof v_m_sig_noattr }, { v_m_hashed_sha256, sizeof v_m_hashed_sha256 }, { v_m_certs_only, sizeof v_m_certs_only } };
    for (int i = 0; i < 3; i++) {
        BYTE d[100]; DWORD dn = sizeof d; SET_ERR(0);
        BOOL r = DECM(&dp, (BYTE *)m[i].p, m[i].n, d, &dn, NULL);
        EXPECT_FAIL(r == FALSE, E_CRYPT_E_UNEXPECTED_MSG_TYPE); EXPECT_EQ(dn, 0);
    }
}
TEST(mh_decrypt_garbage_and_truncated) {
    MH_NOWINE(); MH_INIT(); REQUIRE(DECM);
    CRYPT_DECRYPT_MESSAGE_PARA dp; mh_dec_para(&dp);
    static const BYTE g[] = { 0x30, 0x03, 0x02, 0x01, 0x01 };
    BYTE d[100]; DWORD dn = sizeof d; SET_ERR(0);
    CHECK(!DECM(&dp, (BYTE *)g, sizeof g, d, &dn, NULL)); EXPECT_EQ(dn, 0); CHECK(GetLastError() != 0);
    dn = sizeof d; CHECK(!DECM(&dp, (BYTE *)v_m_env_aes128, sizeof v_m_env_aes128 - 7, d, &dn, NULL));
    dn = sizeof d; CHECK(!DECM(&dp, (BYTE *)v_m_env_aes128, 0, d, &dn, NULL));
}
TEST(mh_decrypt_corrupted_ciphertext) {
    MH_NOWINE(); MH_INIT(); REQUIRE(DECM);
    BYTE *b = malloc(sizeof v_m_env_aes128); memcpy(b, v_m_env_aes128, sizeof v_m_env_aes128);
    b[sizeof v_m_env_aes128 - 1] ^= 0xFF;           /* last ciphertext block: padding becomes invalid or the plaintext changes */
    BYTE d[100]; DWORD dn = sizeof d; SET_ERR(0);
    BOOL r = dec_with(mh_priv_store, b, sizeof v_m_env_aes128, d, &dn, NULL);
    EXPECT_FAIL(r == FALSE, 0xC000003E); /* observed: STATUS_DATA_ERROR (invalid padding) */
    free(b);
}
TEST(mh_decrypt_corrupted_wrapped_key) {
    MH_NOWINE(); MH_INIT(); REQUIRE(DECM);
    BYTE *b = malloc(sizeof v_m_env_aes128); memcpy(b, v_m_env_aes128, sizeof v_m_env_aes128);
    DWORD pos = 0;
    for (DWORD i = 0; i + 4 < sizeof v_m_env_aes128; i++) if (b[i] == 0x04 && b[i + 1] == 0x81 && b[i + 2] == 0x80) { pos = i + 3 + 10; break; }
    CHECK(pos != 0);
    if (pos) {
        b[pos] ^= 0x55;
        BYTE d[100]; DWORD dn = sizeof d; SET_ERR(0);
        BOOL r = dec_with(mh_priv_store, b, sizeof v_m_env_aes128, d, &dn, NULL);
        EXPECT_FAIL(r == FALSE, 0x80090027); /* observed: NTE_INVALID_PARAMETER */
    }
    free(b);
}
TEST(mh_decrypt_own_message_not_decryptable_by_sender_key) {
    MH_NOWINE(); MH_INIT(); REQUIRE(ENCM); REQUIRE(DECM);
    DWORD n = 0; BYTE *b = enc_blob("2.16.840.1.101.3.4.1.2", 0, 1, MH_R2, MH_R2, &n);
    CHECK(b != NULL); if (!b) return;
    HCERTSTORE s = mh_make_store((1u << MH_R1) | (1u << MH_S1) | (1u << MH_S2), 0);
    BYTE d[100]; DWORD dn = sizeof d; SET_ERR(0);
    BOOL r = dec_with(s, b, n, d, &dn, NULL);
    EXPECT_FAIL(r == FALSE, E_CRYPT_E_NO_DECRYPT_CERT);
    U(CertCloseStore)(s, 0); free(b);
}

/* ---- sign + encrypt ----------------------------------------------------------------------------- */
static BYTE *sae_blob(DWORD signflags, DWORD *pn) {
    CRYPT_SIGN_MESSAGE_PARA sp; mh_sign_para(&sp, MH_S1, OID_SHA256); sp.dwFlags = signflags;
    PCCERT_CONTEXT mc[1] = { mh_ids[MH_S1].pub }; sp.cMsgCert = 1; sp.rgpMsgCert = mc;
    CRYPT_ENCRYPT_MESSAGE_PARA ep; mh_enc_para(&ep, "2.16.840.1.101.3.4.1.2");
    PCCERT_CONTEXT rc[1] = { mh_ids[MH_R1].pub }; DWORD n = 0;
    if (!U(CryptSignAndEncryptMessage)(&sp, &ep, 1, rc, v_payload, sizeof v_payload, NULL, &n) || !n) return NULL;
    BYTE *b = malloc(n);
    if (!U(CryptSignAndEncryptMessage)(&sp, &ep, 1, rc, v_payload, sizeof v_payload, b, &n)) { free(b); return NULL; }
    *pn = n; return b;
}
TEST(mh_signandencrypt_roundtrip) {
    MH_NOWINE(); MH_INIT(); REQUIRE(U(CryptSignAndEncryptMessage)); REQUIRE(U(CryptDecryptAndVerifyMessageSignature));
    DWORD n = 0; BYTE *b = sae_blob(0, &n);
    CHECKF(b != NULL, "err 0x%lx", GetLastError()); if (!b) return;
    DWORD h = mh_der_hdr(b, n); CHECK(!memcmp(b + h, MH_OID_ENVELOPED, 11));
    CRYPT_DECRYPT_MESSAGE_PARA dp; mh_dec_para(&dp); CRYPT_VERIFY_MESSAGE_PARA vp; mh_verify_para(&vp);
    BYTE d[100]; DWORD dn = sizeof d; PCCERT_CONTEXT x = NULL, sc = NULL; SET_ERR(0);
    BOOL r = U(CryptDecryptAndVerifyMessageSignature)(&dp, &vp, 0, b, n, d, &dn, &x, &sc);
    CHECKF(r, "err 0x%lx", GetLastError());
    if (r) { CHECK(dn == sizeof v_payload && !memcmp(d, v_payload, dn)); CHECK(CERT_IS(x, v_r1_cert)); CHECK(CERT_IS(sc, v_s1_cert)); }
    FREE_CERT(x); FREE_CERT(sc); free(b);
}
TEST(mh_signandencrypt_decrypt_yields_signed_message) {
    MH_NOWINE(); MH_INIT(); REQUIRE(U(CryptSignAndEncryptMessage)); REQUIRE(DECM); REQUIRE(U(CryptVerifyMessageSignature));
    DWORD n = 0; BYTE *b = sae_blob(0, &n); CHECK(b != NULL); if (!b) return;
    BYTE inner[1000]; DWORD in = sizeof inner;
    CHECK(dec_with(mh_priv_store, b, n, inner, &in, NULL));
    EXPECT_EQ(in, 926); CHECK(inner[0] == 0x30);
    DWORD h = mh_der_hdr(inner, in); CHECK(in >= h + 11 && !memcmp(inner + h, MH_OID_SIGNED, 11));
    CRYPT_VERIFY_MESSAGE_PARA vp; mh_verify_para(&vp);
    BYTE d[100]; DWORD dn = sizeof d; PCCERT_CONTEXT sc = NULL;
    CHECK(U(CryptVerifyMessageSignature)(&vp, 0, inner, in, d, &dn, &sc));
    CHECK(dn == sizeof v_payload && !memcmp(d, v_payload, dn)); FREE_CERT(sc); free(b);
}
TEST(mh_signandencrypt_size_protocol) {
    MH_NOWINE(); MH_INIT(); REQUIRE(U(CryptSignAndEncryptMessage));
    CRYPT_SIGN_MESSAGE_PARA sp; mh_sign_para(&sp, MH_S1, OID_SHA256);
    CRYPT_ENCRYPT_MESSAGE_PARA ep; mh_enc_para(&ep, "2.16.840.1.101.3.4.1.2");
    PCCERT_CONTEXT rc[1] = { mh_ids[MH_R1].pub };
    DWORD q = 0x55; SET_ERR(0);
    CHECK(U(CryptSignAndEncryptMessage)(&sp, &ep, 1, rc, v_payload, sizeof v_payload, NULL, &q)); EXPECT_EQ(q, 615);
    BYTE *buf = malloc(q); DWORD n = 0; SET_ERR(0);
    BOOL r = U(CryptSignAndEncryptMessage)(&sp, &ep, 1, rc, v_payload, sizeof v_payload, buf, &n);
    EXPECT_FAIL(r == FALSE, ERROR_MORE_DATA); EXPECT_EQ(n, q); EXPECT_EQ(q, 615);
    n = q; CHECK(U(CryptSignAndEncryptMessage)(&sp, &ep, 1, rc, v_payload, sizeof v_payload, buf, &n)); EXPECT_EQ(n, q);
    free(buf);
}
TEST(mh_signandencrypt_bad_signer_zeroes_size) {
    MH_NOWINE(); MH_INIT(); REQUIRE(U(CryptSignAndEncryptMessage));
    CRYPT_SIGN_MESSAGE_PARA sp; mh_sign_para(&sp, MH_S1, OID_SHA256); sp.pSigningCert = mh_ids[MH_S1].pub;
    CRYPT_ENCRYPT_MESSAGE_PARA ep; mh_enc_para(&ep, "2.16.840.1.101.3.4.1.2");
    PCCERT_CONTEXT rc[1] = { mh_ids[MH_R1].pub };
    DWORD q = 0x55; SET_ERR(0);
    BOOL r = U(CryptSignAndEncryptMessage)(&sp, &ep, 1, rc, v_payload, sizeof v_payload, NULL, &q);
    CHECK(r == FALSE); EXPECT_EQ(q, 0);
    sp.cbSize = 4; sp.pSigningCert = mh_ids[MH_S1].priv; q = 0x55; SET_ERR(0);
    r = U(CryptSignAndEncryptMessage)(&sp, &ep, 1, rc, v_payload, sizeof v_payload, NULL, &q);
    EXPECT_FAIL(r == FALSE, E_INVALIDARG_); EXPECT_EQ(q, 0);
}
TEST(mh_signandencrypt_bad_encrypt_para) {
    MH_NOWINE(); MH_INIT(); REQUIRE(U(CryptSignAndEncryptMessage));
    CRYPT_SIGN_MESSAGE_PARA sp; mh_sign_para(&sp, MH_S1, OID_SHA256);
    CRYPT_ENCRYPT_MESSAGE_PARA ep; mh_enc_para(&ep, "2.16.840.1.101.3.4.1.2"); ep.cbSize = 8;
    PCCERT_CONTEXT rc[1] = { mh_ids[MH_R1].pub };
    DWORD q = 0x55; SET_ERR(0);
    BOOL r = U(CryptSignAndEncryptMessage)(&sp, &ep, 1, rc, v_payload, sizeof v_payload, NULL, &q);
    EXPECT_FAIL(r == FALSE, E_INVALIDARG_); EXPECT_EQ(q, 0);
}
TEST(mh_decryptandverify_wrong_types) {
    MH_NOWINE(); MH_INIT(); REQUIRE(U(CryptDecryptAndVerifyMessageSignature));
    CRYPT_DECRYPT_MESSAGE_PARA dp; mh_dec_para(&dp); CRYPT_VERIFY_MESSAGE_PARA vp; mh_verify_para_cb(&vp);
    BYTE d[100]; DWORD dn = sizeof d; PCCERT_CONTEXT x = (PCCERT_CONTEXT)1, sc = (PCCERT_CONTEXT)1; SET_ERR(0);
    BOOL r = U(CryptDecryptAndVerifyMessageSignature)(&dp, &vp, 0, v_m_sig_noattr, sizeof v_m_sig_noattr, d, &dn, &x, &sc);
    EXPECT_FAIL(r == FALSE, E_CRYPT_E_UNEXPECTED_MSG_TYPE);
    CHECK(x == NULL); CHECK(sc == NULL); EXPECT_EQ(dn, 0);
}
TEST(mh_decryptandverify_plain_envelope_fails_verification) {
    MH_NOWINE(); MH_INIT(); REQUIRE(U(CryptDecryptAndVerifyMessageSignature));
    CRYPT_DECRYPT_MESSAGE_PARA dp; mh_dec_para(&dp); CRYPT_VERIFY_MESSAGE_PARA vp; mh_verify_para_cb(&vp);
    BYTE d[100]; DWORD dn = sizeof d; PCCERT_CONTEXT x = (PCCERT_CONTEXT)1, sc = (PCCERT_CONTEXT)1; SET_ERR(0);
    BOOL r = U(CryptDecryptAndVerifyMessageSignature)(&dp, &vp, 0, v_m_env_aes128, sizeof v_m_env_aes128, d, &dn, &x, &sc);
    EXPECT_FAIL(r == FALSE, 0x8009310B); /* observed: ASN1 bad tag (the payload is not a SignedData) */
    CHECK(x == NULL); CHECK(sc == NULL); EXPECT_EQ(dn, 0);
}
TEST(mh_decryptandverify_signer_index_and_sizes) {
    MH_NOWINE(); MH_INIT(); REQUIRE(U(CryptDecryptAndVerifyMessageSignature));
    DWORD n = 0; BYTE *b = sae_blob(0, &n); CHECK(b != NULL); if (!b) return;
    CRYPT_DECRYPT_MESSAGE_PARA dp; mh_dec_para(&dp); CRYPT_VERIFY_MESSAGE_PARA vp; mh_verify_para(&vp);
    BYTE d[100]; DWORD dn = 0; PCCERT_CONTEXT x = NULL, sc = NULL; SET_ERR(0);
    BOOL r = U(CryptDecryptAndVerifyMessageSignature)(&dp, &vp, 0, b, n, NULL, &dn, NULL, NULL);
    CHECKF(r, "size query err 0x%lx", GetLastError()); EXPECT_EQ(dn, sizeof v_payload);
    dn = 3; SET_ERR(0);
    r = U(CryptDecryptAndVerifyMessageSignature)(&dp, &vp, 0, b, n, d, &dn, &x, &sc);
    EXPECT_FAIL(r == FALSE, ERROR_MORE_DATA); EXPECT_EQ(dn, sizeof v_payload); CHECK(x == NULL && sc == NULL);
    dn = sizeof d; SET_ERR(0);
    r = U(CryptDecryptAndVerifyMessageSignature)(&dp, &vp, 1, b, n, d, &dn, &x, &sc);
    EXPECT_FAIL(r == FALSE, E_CRYPT_E_NO_SIGNER); CHECK(x == NULL && sc == NULL);
    free(b);
}
TEST(mh_decryptandverify_no_key_for_recipient) {
    MH_NOWINE(); MH_INIT(); REQUIRE(U(CryptDecryptAndVerifyMessageSignature));
    DWORD n = 0; BYTE *b = sae_blob(0, &n); CHECK(b != NULL); if (!b) return;
    HCERTSTORE s = mh_make_store(1u << MH_R2, 1u << MH_R1);
    HCERTSTORE st[1] = { s };
    CRYPT_DECRYPT_MESSAGE_PARA dp; mh_dec_para(&dp); dp.rghCertStore = st; CRYPT_VERIFY_MESSAGE_PARA vp; mh_verify_para(&vp);
    BYTE d[100]; DWORD dn = sizeof d; PCCERT_CONTEXT x = (PCCERT_CONTEXT)1, sc = (PCCERT_CONTEXT)1; SET_ERR(0);
    BOOL r = U(CryptDecryptAndVerifyMessageSignature)(&dp, &vp, 0, b, n, d, &dn, &x, &sc);
    EXPECT_FAIL(r == FALSE, E_CRYPT_E_NO_DECRYPT_CERT); CHECK(x == NULL && sc == NULL); EXPECT_EQ(dn, 0);
    U(CertCloseStore)(s, 0); free(b);
}
TEST(mh_decryptandverify_signer_cert_missing) {
    MH_NOWINE(); MH_INIT(); REQUIRE(U(CryptSignAndEncryptMessage)); REQUIRE(U(CryptDecryptAndVerifyMessageSignature));
    CRYPT_SIGN_MESSAGE_PARA sp; mh_sign_para(&sp, MH_S2, OID_SHA256);       /* signer cert not embedded */
    CRYPT_ENCRYPT_MESSAGE_PARA ep; mh_enc_para(&ep, "1.2.840.113549.3.7");
    PCCERT_CONTEXT rc[1] = { mh_ids[MH_R1].pub }; DWORD q = 0;
    CHECK(U(CryptSignAndEncryptMessage)(&sp, &ep, 1, rc, v_payload, sizeof v_payload, NULL, &q));
    BYTE *b = malloc(q); CHECK(U(CryptSignAndEncryptMessage)(&sp, &ep, 1, rc, v_payload, sizeof v_payload, b, &q));
    CRYPT_DECRYPT_MESSAGE_PARA dp; mh_dec_para(&dp); CRYPT_VERIFY_MESSAGE_PARA vp; mh_verify_para(&vp);
    BYTE d[100]; DWORD dn = sizeof d; PCCERT_CONTEXT x = NULL, sc = (PCCERT_CONTEXT)1; SET_ERR(0);
    BOOL r = U(CryptDecryptAndVerifyMessageSignature)(&dp, &vp, 0, b, q, d, &dn, &x, &sc);
    EXPECT_FAIL(r == FALSE, E_CRYPT_E_NOT_FOUND); CHECK(sc == NULL); CHECK(x == NULL);
    mh_verify_para_cb(&vp); dn = sizeof d;
    r = U(CryptDecryptAndVerifyMessageSignature)(&dp, &vp, 0, b, q, d, &dn, &x, &sc);
    CHECKF(r, "with callback: err 0x%lx", GetLastError());
    if (r) { CHECK(CERT_IS(sc, v_s2_cert)); CHECK(dn == sizeof v_payload); }
    FREE_CERT(x); FREE_CERT(sc); free(b);
}
