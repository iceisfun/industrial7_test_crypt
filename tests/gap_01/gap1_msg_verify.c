/* CryptVerifyMessageHash, CryptVerifyDetachedMessageHash, CryptVerifyDetachedMessageSignature,
   CryptVerifyMessageSignatureWithKey, CryptDecryptMessage. */
#include "gap1.h"

typedef struct { const char *name; const char *oid; const BYTE *att; DWORD catt; const BYTE *det; DWORD cdet; const BYTE *hash; DWORD chash; } hm_t;
#define HM(n, o) { #n, o, v_dig_##n, sizeof v_dig_##n, v_digdet_##n, sizeof v_digdet_##n, v_h_##n, sizeof v_h_##n }
static const hm_t hms[] = { HM(sha1, OID_SHA1), HM(sha256, OID_SHA256), HM(sha512, OID_SHA512), HM(md5, OID_MD5) };
#define NHM (sizeof hms / sizeof *hms)

static void hpara(CRYPT_HASH_MESSAGE_PARA *p) {
    memset(p, 0, sizeof *p); p->cbSize = sizeof *p; p->dwMsgEncodingType = ENC;
}

/* ---------------- CryptVerifyMessageHash ---------------- */
TEST(gap1_vmh_attached_all_algorithms) {
    REQUIRE(U(CryptVerifyMessageHash));
    CRYPT_HASH_MESSAGE_PARA p; hpara(&p);
    for (unsigned i = 0; i < NHM; i++) {
        BYTE out[128], hash[64]; DWORD co = sizeof out, ch = sizeof hash;
        BOOL r = U(CryptVerifyMessageHash)(&p, (BYTE *)hms[i].att, hms[i].catt, out, &co, hash, &ch);
        CHECKF(r, "%s: err 0x%08lx", hms[i].name, GetLastError());
        if (r) {
            CHECKF(co == sizeof v_payload && !memcmp(out, v_payload, co), "%s content", hms[i].name);
            CHECKF(ch == hms[i].chash && !memcmp(hash, hms[i].hash, ch), "%s computed hash (len %lu)", hms[i].name, ch);
        }
    }
}
TEST(gap1_vmh_size_queries) {
    REQUIRE(U(CryptVerifyMessageHash));
    CRYPT_HASH_MESSAGE_PARA p; hpara(&p);
    DWORD co = 0xFFFF, ch = 0xFFFF;
    CHECK(U(CryptVerifyMessageHash)(&p, BLOB(v_dig_sha256), NULL, &co, NULL, &ch));
    EXPECT_EQ(co, sizeof v_payload); EXPECT_EQ(ch, 32);
    /* only the content size */
    co = 0xFFFF;
    CHECK(U(CryptVerifyMessageHash)(&p, BLOB(v_dig_sha256), NULL, &co, NULL, NULL));
    EXPECT_EQ(co, sizeof v_payload);
    /* only the computed hash */
    ch = 0xFFFF;
    CHECK(U(CryptVerifyMessageHash)(&p, BLOB(v_dig_sha256), NULL, NULL, NULL, &ch));
    EXPECT_EQ(ch, 32);
    /* neither: plain verification */
    CHECK(U(CryptVerifyMessageHash)(&p, BLOB(v_dig_sha256), NULL, NULL, NULL, NULL));
}
TEST(gap1_vmh_short_buffers_report_required_size) {
    REQUIRE(U(CryptVerifyMessageHash));
    CRYPT_HASH_MESSAGE_PARA p; hpara(&p);
    BYTE out[128], hash[64];
    for (DWORD cap = 1; cap < sizeof v_payload; cap += 9) {
        DWORD co = cap; SET_ERR(0);
        CHECKF(!U(CryptVerifyMessageHash)(&p, BLOB(v_dig_sha256), out, &co, NULL, NULL), "cap %lu", cap);
        EXPECT_ERR(ERROR_MORE_DATA);
        EXPECT_EQ(co, sizeof v_payload);
    }
    for (DWORD cap = 1; cap < 32; cap += 7) {
        DWORD ch = cap; SET_ERR(0);
        CHECKF(!U(CryptVerifyMessageHash)(&p, BLOB(v_dig_sha256), NULL, NULL, hash, &ch), "hash cap %lu", cap);
        EXPECT_ERR(ERROR_MORE_DATA);
        EXPECT_EQ(ch, 32);
    }
    DWORD co = sizeof v_payload, ch = 32;
    CHECK(U(CryptVerifyMessageHash)(&p, BLOB(v_dig_sha256), out, &co, hash, &ch));   /* exact sizes */
}
TEST(gap1_vmh_buffer_larger_than_needed) {
    REQUIRE(U(CryptVerifyMessageHash));
    CRYPT_HASH_MESSAGE_PARA p; hpara(&p);
    BYTE out[256], hash[128]; memset(out, 0x55, sizeof out);
    DWORD co = sizeof out, ch = sizeof hash;
    CHECK(U(CryptVerifyMessageHash)(&p, BLOB(v_dig_sha1), out, &co, hash, &ch));
    EXPECT_EQ(co, sizeof v_payload); EXPECT_EQ(ch, 20);
    CHECK(out[sizeof v_payload] == 0x55);
}
TEST(gap1_vmh_bad_cbsize) {
    REQUIRE(U(CryptVerifyMessageHash));
    CRYPT_HASH_MESSAGE_PARA p; hpara(&p);
    static const DWORD sizes[] = { 0, 1, 40, 47, 49, 56, 0x30000 };
    for (unsigned i = 0; i < sizeof sizes / sizeof *sizes; i++) {
        p.cbSize = sizes[i]; DWORD co = 0x77, ch = 0x77; BYTE out[128], hash[64];
        SET_ERR(0);
        CHECKF(!U(CryptVerifyMessageHash)(&p, BLOB(v_dig_sha256), out, &co, hash, &ch), "cbSize %lu", sizes[i]);
        EXPECT_ERR(E_INVALIDARG_);
        EXPECT_EQ(co, 0); EXPECT_EQ(ch, 0);     /* output sizes are cleared before the parameter check */
    }
}
TEST(gap1_vmh_wrong_message_type) {
    REQUIRE(U(CryptVerifyMessageHash));
    CRYPT_HASH_MESSAGE_PARA p; hpara(&p);
    SET_ERR(0);
    CHECK(!U(CryptVerifyMessageHash)(&p, BLOB(v_sig_att), NULL, NULL, NULL, NULL));
    EXPECT_ERR(CRYPT_E_UNEXPECTED_MSG_TYPE_);
    SET_ERR(0);
    CHECK(!U(CryptVerifyMessageHash)(&p, BLOB(v_env_aes256), NULL, NULL, NULL, NULL));
    EXPECT_ERR(CRYPT_E_UNEXPECTED_MSG_TYPE_);
}
TEST(gap1_vmh_garbage_blobs) {
    REQUIRE(U(CryptVerifyMessageHash));
    CRYPT_HASH_MESSAGE_PARA p; hpara(&p);
    static const BYTE g1[] = { 0x00, 0x01, 0x02, 0x03 }, g2[] = { 0x30, 0x03, 0x02, 0x01, 0x05 }, g3[] = { 0x30, 0x84, 0xff, 0xff, 0xff, 0xff };
    struct { const BYTE *b; DWORD n; } t[] = { { g1, 4 }, { g2, 5 }, { g3, 6 } };
    for (int i = 0; i < 3; i++) {
        SET_ERR(0);
        CHECKF(!U(CryptVerifyMessageHash)(&p, (BYTE *)t[i].b, t[i].n, NULL, NULL, NULL, NULL), "garbage %d", i);
        DWORD e = GetLastError();
        CHECKF(CRYPT_E_ASN1_ANY(e) || e == CRYPT_E_UNEXPECTED_MSG_TYPE_ || e == ERROR_MORE_DATA, "garbage %d: 0x%08lx", i, e);
        t_note("garbage %d -> 0x%08lx", i, e);
    }
    /* truncated valid message */
    SET_ERR(0);
    CHECK(!U(CryptVerifyMessageHash)(&p, (BYTE *)v_dig_sha256, sizeof v_dig_sha256 - 5, NULL, NULL, NULL, NULL));
    t_note("truncated -> 0x%08lx", GetLastError());
    SET_ERR(0);
    CHECK(!U(CryptVerifyMessageHash)(&p, (BYTE *)v_dig_sha256, 0, NULL, NULL, NULL, NULL));
    CHECK(GetLastError() != 0);
}
TEST(gap1_vmh_corrupted_digest) {
    REQUIRE(U(CryptVerifyMessageHash));
    CRYPT_HASH_MESSAGE_PARA p; hpara(&p);
    BYTE out[128], hash[64]; DWORD co = sizeof out, ch = sizeof hash;
    SET_ERR(0);
    CHECK(!U(CryptVerifyMessageHash)(&p, BLOB(v_dig_sha256_bad), out, &co, hash, &ch));
    EXPECT_ERR(CRYPT_E_HASH_VALUE_);
    co = sizeof out; SET_ERR(0);
    CHECK(!U(CryptVerifyMessageHash)(&p, BLOB(v_dig_sha256_bad), out, &co, NULL, NULL));
    EXPECT_ERR(CRYPT_E_HASH_VALUE_);
    ch = sizeof hash; SET_ERR(0);
    CHECK(!U(CryptVerifyMessageHash)(&p, BLOB(v_dig_sha256_bad), NULL, NULL, hash, &ch));
    EXPECT_ERR(CRYPT_E_HASH_VALUE_);
}
TEST(gap1_vmh_corrupted_digest_size_query_skips_check) {
    /* a bare content-size query does not verify the digest (the decode is opened in length-only mode) */
    REQUIRE(U(CryptVerifyMessageHash));
    CRYPT_HASH_MESSAGE_PARA p; hpara(&p);
    DWORD co = 0;
    BOOL r = U(CryptVerifyMessageHash)(&p, BLOB(v_dig_sha256_bad), NULL, &co, NULL, NULL);
    t_note("size query on corrupted digest: ret %d, size %lu, err 0x%08lx", r, co, GetLastError());
    CHECK(r == TRUE);
    CHECK(co == sizeof v_payload);
}
TEST(gap1_vmh_empty_content) {
    REQUIRE(U(CryptVerifyMessageHash));
    CRYPT_HASH_MESSAGE_PARA p; hpara(&p);
    BYTE out[8], hash[32]; DWORD co = sizeof out, ch = sizeof hash;
    BOOL r = U(CryptVerifyMessageHash)(&p, BLOB(v_dig_sha256_empty), out, &co, hash, &ch);
    CHECKF(r, "err 0x%08lx", GetLastError());
    if (r) {
        static const BYTE e[32] = {0xe3,0xb0,0xc4,0x42,0x98,0xfc,0x1c,0x14,0x9a,0xfb,0xf4,0xc8,0x99,0x6f,0xb9,0x24,0x27,0xae,0x41,0xe4,0x64,0x9b,0x93,0x4c,0xa4,0x95,0x99,0x1b,0x78,0x52,0xb8,0x55};
        EXPECT_EQ(co, 0); EXPECT_EQ(ch, 32); CHECK(!memcmp(hash, e, 32));
    }
}
TEST(gap1_vmh_detached_blob_note) {
    REQUIRE(U(CryptVerifyMessageHash));
    CRYPT_HASH_MESSAGE_PARA p; hpara(&p);
    BYTE out[128], hash[32]; DWORD co = sizeof out, ch = sizeof hash;
    SET_ERR(0);
    BOOL r = U(CryptVerifyMessageHash)(&p, BLOB(v_digdet_sha256), out, &co, hash, &ch);
    t_note("detached hash blob through the attached API: ret %d, err 0x%08lx, content %lu", r, GetLastError(), co);
}
TEST(gap1_vmh_param_encoding_type) {
    REQUIRE(U(CryptVerifyMessageHash));
    CRYPT_HASH_MESSAGE_PARA p; hpara(&p);
    p.dwMsgEncodingType = X509_ASN_ENCODING;
    SET_ERR(0);
    BOOL r = U(CryptVerifyMessageHash)(&p, BLOB(v_dig_sha256), NULL, NULL, NULL, NULL);
    t_note("X509-only encoding type: ret %d err 0x%08lx", r, GetLastError());
    CHECK(!r);
    p.dwMsgEncodingType = 0; SET_ERR(0);
    CHECK(!U(CryptVerifyMessageHash)(&p, BLOB(v_dig_sha256), NULL, NULL, NULL, NULL));
    EXPECT_ERR(E_INVALIDARG_);
    p.dwMsgEncodingType = PKCS_7_ASN_ENCODING;
    CHECK(U(CryptVerifyMessageHash)(&p, BLOB(v_dig_sha256), NULL, NULL, NULL, NULL));
}

/* ---------------- CryptVerifyDetachedMessageHash ---------------- */
TEST(gap1_vdh_single_chunk_all_algorithms) {
    REQUIRE(U(CryptVerifyDetachedMessageHash));
    CRYPT_HASH_MESSAGE_PARA p; hpara(&p);
    for (unsigned i = 0; i < NHM; i++) {
        const BYTE *ch[1] = { v_payload }; DWORD cl[1] = { sizeof v_payload };
        BYTE hash[64]; DWORD chs = sizeof hash;
        BOOL r = U(CryptVerifyDetachedMessageHash)(&p, (BYTE *)hms[i].det, hms[i].cdet, 1, (const BYTE **)ch, cl, hash, &chs);
        CHECKF(r, "%s: err 0x%08lx", hms[i].name, GetLastError());
        if (r) CHECKF(chs == hms[i].chash && !memcmp(hash, hms[i].hash, chs), "%s computed", hms[i].name);
    }
}
TEST(gap1_vdh_multiple_chunks_equal_one_chunk) {
    REQUIRE(U(CryptVerifyDetachedMessageHash));
    CRYPT_HASH_MESSAGE_PARA p; hpara(&p);
    DWORD n = sizeof v_payload;
    for (DWORD s1 = 11; s1 < n; s1 += 11) for (DWORD s2 = s1 + 1; s2 < n; s2 += 17) {   /* no empty chunks */
        const BYTE *ch[3] = { v_payload, v_payload + s1, v_payload + s2 }; DWORD cl[3] = { s1, s2 - s1, n - s2 };
        BYTE hash[32]; DWORD chs = sizeof hash;
        BOOL r = U(CryptVerifyDetachedMessageHash)(&p, BLOB(v_digdet_sha256), 3, (const BYTE **)ch, cl, hash, &chs);
        CHECKF(r && chs == 32 && !memcmp(hash, v_h_sha256, 32), "split %lu/%lu err 0x%08lx", s1, s2, GetLastError());
    }
}
TEST(gap1_vdh_many_single_byte_chunks) {
    REQUIRE(U(CryptVerifyDetachedMessageHash));
    CRYPT_HASH_MESSAGE_PARA p; hpara(&p);
    DWORD n = sizeof v_payload; const BYTE *ch[64]; DWORD cl[64];
    for (DWORD i = 0; i < n; i++) { ch[i] = v_payload + i; cl[i] = 1; }
    CHECK(U(CryptVerifyDetachedMessageHash)(&p, BLOB(v_digdet_sha256), n, (const BYTE **)ch, cl, NULL, NULL));
}
TEST(gap1_vdh_wrong_data) {
    REQUIRE(U(CryptVerifyDetachedMessageHash));
    CRYPT_HASH_MESSAGE_PARA p; hpara(&p);
    BYTE bad[sizeof v_payload]; memcpy(bad, v_payload, sizeof bad); bad[7] ^= 1;
    const BYTE *ch[1] = { bad }; DWORD cl[1] = { sizeof bad };
    BYTE hash[32]; DWORD chs = sizeof hash;
    SET_ERR(0);
    CHECK(!U(CryptVerifyDetachedMessageHash)(&p, BLOB(v_digdet_sha256), 1, (const BYTE **)ch, cl, hash, &chs));
    EXPECT_ERR(CRYPT_E_HASH_VALUE_);
    SET_ERR(0);
    CHECK(!U(CryptVerifyDetachedMessageHash)(&p, BLOB(v_digdet_sha256), 1, (const BYTE **)ch, cl, NULL, NULL));
    EXPECT_ERR(CRYPT_E_HASH_VALUE_);
    /* truncated data */
    cl[0] = sizeof v_payload - 1; ch[0] = v_payload;
    SET_ERR(0);
    CHECK(!U(CryptVerifyDetachedMessageHash)(&p, BLOB(v_digdet_sha256), 1, (const BYTE **)ch, cl, NULL, NULL));
    EXPECT_ERR(CRYPT_E_HASH_VALUE_);
    /* corrupted digest in the message */
    cl[0] = sizeof v_payload;
    SET_ERR(0);
    CHECK(!U(CryptVerifyDetachedMessageHash)(&p, BLOB(v_digdet_sha256_bad), 1, (const BYTE **)ch, cl, NULL, NULL));
    EXPECT_ERR(CRYPT_E_HASH_VALUE_);
}
TEST(gap1_vdh_computed_hash_buffer_protocol) {
    REQUIRE(U(CryptVerifyDetachedMessageHash));
    CRYPT_HASH_MESSAGE_PARA p; hpara(&p);
    const BYTE *ch[1] = { v_payload }; DWORD cl[1] = { sizeof v_payload };
    DWORD n = 0;
    CHECK(U(CryptVerifyDetachedMessageHash)(&p, BLOB(v_digdet_sha512), 1, (const BYTE **)ch, cl, NULL, &n));
    EXPECT_EQ(n, 64);
    BYTE hash[64];
    for (DWORD cap = 0; cap < 64; cap += 21) {
        DWORD m = cap; SET_ERR(0);
        CHECKF(!U(CryptVerifyDetachedMessageHash)(&p, BLOB(v_digdet_sha512), 1, (const BYTE **)ch, cl, hash, &m), "cap %lu", cap);
        if (cap) EXPECT_ERR(ERROR_MORE_DATA);
        EXPECT_EQ(m, 64);
    }
    n = 64;
    CHECK(U(CryptVerifyDetachedMessageHash)(&p, BLOB(v_digdet_sha512), 1, (const BYTE **)ch, cl, hash, &n));
    CHECK(!memcmp(hash, v_h_sha512, 64));
}
TEST(gap1_vdh_bad_cbsize_and_type) {
    REQUIRE(U(CryptVerifyDetachedMessageHash));
    CRYPT_HASH_MESSAGE_PARA p; hpara(&p);
    const BYTE *ch[1] = { v_payload }; DWORD cl[1] = { sizeof v_payload };
    p.cbSize = 40; SET_ERR(0);
    CHECK(!U(CryptVerifyDetachedMessageHash)(&p, BLOB(v_digdet_sha256), 1, (const BYTE **)ch, cl, NULL, NULL));
    EXPECT_ERR(E_INVALIDARG_);
    hpara(&p); SET_ERR(0);
    CHECK(!U(CryptVerifyDetachedMessageHash)(&p, BLOB(v_sig_det), 1, (const BYTE **)ch, cl, NULL, NULL));
    EXPECT_ERR(CRYPT_E_UNEXPECTED_MSG_TYPE_);
    DWORD n = 1234; SET_ERR(0);
    p.cbSize = 0;
    CHECK(!U(CryptVerifyDetachedMessageHash)(&p, BLOB(v_digdet_sha256), 1, (const BYTE **)ch, cl, NULL, &n));
    EXPECT_EQ(n, 0);
}
TEST(gap1_vdh_no_chunks_note) {
    REQUIRE(U(CryptVerifyDetachedMessageHash));
    CRYPT_HASH_MESSAGE_PARA p; hpara(&p);
    SET_ERR(0);
    BOOL r = U(CryptVerifyDetachedMessageHash)(&p, BLOB(v_digdet_sha256), 0, NULL, NULL, NULL, NULL);
    t_note("cToBeHashed=0, no hash output: ret %d err 0x%08lx", r, GetLastError());
    DWORD n = 0; SET_ERR(0);
    r = U(CryptVerifyDetachedMessageHash)(&p, BLOB(v_digdet_sha256), 0, NULL, NULL, NULL, &n);
    t_note("cToBeHashed=0, with hash output: ret %d err 0x%08lx len %lu", r, GetLastError(), n);
}
TEST(gap1_vdh_attached_blob_note) {
    REQUIRE(U(CryptVerifyDetachedMessageHash));
    CRYPT_HASH_MESSAGE_PARA p; hpara(&p);
    const BYTE *ch[1] = { v_payload }; DWORD cl[1] = { sizeof v_payload };
    SET_ERR(0);
    BOOL r = U(CryptVerifyDetachedMessageHash)(&p, BLOB(v_dig_sha256), 1, (const BYTE **)ch, cl, NULL, NULL);
    t_note("attached digest blob through the detached API: ret %d err 0x%08lx", r, GetLastError());
}

/* ---------------- CryptVerifyDetachedMessageSignature ---------------- */
static void vpara(CRYPT_VERIFY_MESSAGE_PARA *p) { memset(p, 0, sizeof *p); p->cbSize = sizeof *p; p->dwMsgAndCertEncodingType = ENC; }
static int same_cert(PCCERT_CONTEXT c, PCCERT_CONTEXT ref) {
    return c && c->cbCertEncoded == ref->cbCertEncoded && !memcmp(c->pbCertEncoded, ref->pbCertEncoded, c->cbCertEncoded);
}
TEST(gap1_vds_attrs_and_noattr_variants) {
    REQUIRE(U(CryptVerifyDetachedMessageSignature)); G1_INIT();
    CRYPT_VERIFY_MESSAGE_PARA p; vpara(&p);
    const BYTE *ch[1] = { v_payload }; DWORD cl[1] = { sizeof v_payload };
    struct { const char *w; const BYTE *b; DWORD n; } t[] = { { "attrs", v_sig_det, sizeof v_sig_det }, { "noattr", v_sig_det_noattr, sizeof v_sig_det_noattr } };
    for (int i = 0; i < 2; i++) {
        PCCERT_CONTEXT signer = NULL;
        BOOL r = U(CryptVerifyDetachedMessageSignature)(&p, 0, (BYTE *)t[i].b, t[i].n, 1, (const BYTE **)ch, cl, &signer);
        CHECKF(r, "%s: 0x%08lx", t[i].w, GetLastError());
        if (r) { CHECKF(same_cert(signer, g1_A.cert), "%s signer cert", t[i].w); U(CertFreeCertificateContext)(signer); }
        r = U(CryptVerifyDetachedMessageSignature)(&p, 0, (BYTE *)t[i].b, t[i].n, 1, (const BYTE **)ch, cl, NULL);   /* signer cert not requested */
        CHECKF(r, "%s no ppSignerCert", t[i].w);
    }
}
TEST(gap1_vds_multiple_chunks) {
    REQUIRE(U(CryptVerifyDetachedMessageSignature));
    CRYPT_VERIFY_MESSAGE_PARA p; vpara(&p);
    DWORD n = sizeof v_payload;
    for (DWORD s1 = 13; s1 < n; s1 += 13) {   /* no empty chunks */
        const BYTE *ch[2] = { v_payload, v_payload + s1 }; DWORD cl[2] = { s1, n - s1 };
        CHECKF(U(CryptVerifyDetachedMessageSignature)(&p, 0, BLOB(v_sig_det), 2, (const BYTE **)ch, cl, NULL), "split %lu: 0x%08lx", s1, GetLastError());
    }
}
TEST(gap1_vds_tampered_data) {
    REQUIRE(U(CryptVerifyDetachedMessageSignature));
    CRYPT_VERIFY_MESSAGE_PARA p; vpara(&p);
    BYTE bad[sizeof v_payload]; memcpy(bad, v_payload, sizeof bad); bad[0] ^= 0x20;
    const BYTE *ch[1] = { bad }; DWORD cl[1] = { sizeof bad };
    PCCERT_CONTEXT signer = (PCCERT_CONTEXT)(ULONG_PTR)1;
    SET_ERR(0);
    CHECK(!U(CryptVerifyDetachedMessageSignature)(&p, 0, BLOB(v_sig_det), 1, (const BYTE **)ch, cl, &signer));
    EXPECT_ERR(CRYPT_E_HASH_VALUE_);
    CHECK(signer == NULL);                  /* output cleared on failure */
    SET_ERR(0);
    CHECK(!U(CryptVerifyDetachedMessageSignature)(&p, 0, BLOB(v_sig_det_noattr), 1, (const BYTE **)ch, cl, NULL));
    EXPECT_ERR((DWORD)ST_INVALID_SIGNATURE);
}
TEST(gap1_vds_signer_index_out_of_range) {
    REQUIRE(U(CryptVerifyDetachedMessageSignature));
    CRYPT_VERIFY_MESSAGE_PARA p; vpara(&p);
    const BYTE *ch[1] = { v_payload }; DWORD cl[1] = { sizeof v_payload };
    static const DWORD idx[] = { 1, 2, 100, 0xFFFFFFFF };
    for (unsigned i = 0; i < 4; i++) {
        PCCERT_CONTEXT signer = NULL; SET_ERR(0);
        CHECKF(!U(CryptVerifyDetachedMessageSignature)(&p, idx[i], BLOB(v_sig_det), 1, (const BYTE **)ch, cl, &signer), "index %lu", idx[i]);
        CHECK(signer == NULL);
        t_note("signer index %lu -> 0x%08lx", idx[i], GetLastError());
    }
}
TEST(gap1_vds_parameter_validation) {
    REQUIRE(U(CryptVerifyDetachedMessageSignature));
    CRYPT_VERIFY_MESSAGE_PARA p; vpara(&p);
    const BYTE *ch[1] = { v_payload }; DWORD cl[1] = { sizeof v_payload };
    SET_ERR(0);
    CHECK(!U(CryptVerifyDetachedMessageSignature)(NULL, 0, BLOB(v_sig_det), 1, (const BYTE **)ch, cl, NULL));
    EXPECT_ERR(E_INVALIDARG_);
    static const DWORD sizes[] = { 0, 4, 16, 31 };
    for (unsigned i = 0; i < 4; i++) {
        p.cbSize = sizes[i]; SET_ERR(0);
        CHECKF(!U(CryptVerifyDetachedMessageSignature)(&p, 0, BLOB(v_sig_det), 1, (const BYTE **)ch, cl, NULL), "cbSize %lu", sizes[i]);
        EXPECT_ERR(E_INVALIDARG_);
    }
    vpara(&p); p.dwMsgAndCertEncodingType = 0; SET_ERR(0);
    CHECK(!U(CryptVerifyDetachedMessageSignature)(&p, 0, BLOB(v_sig_det), 1, (const BYTE **)ch, cl, NULL));
    EXPECT_ERR(E_INVALIDARG_);
}
TEST(gap1_vds_wrong_message_types) {
    REQUIRE(U(CryptVerifyDetachedMessageSignature));
    CRYPT_VERIFY_MESSAGE_PARA p; vpara(&p);
    const BYTE *ch[1] = { v_payload }; DWORD cl[1] = { sizeof v_payload };
    SET_ERR(0);
    CHECK(!U(CryptVerifyDetachedMessageSignature)(&p, 0, BLOB(v_digdet_sha256), 1, (const BYTE **)ch, cl, NULL));
    EXPECT_ERR(CRYPT_E_UNEXPECTED_MSG_TYPE_);
    SET_ERR(0);
    CHECK(!U(CryptVerifyDetachedMessageSignature)(&p, 0, BLOB(v_env_aes256), 1, (const BYTE **)ch, cl, NULL));
    EXPECT_ERR(CRYPT_E_MSG_ERROR_);          /* an enveloped message is not a decodable signed message here */
}
TEST(gap1_vds_garbage) {
    REQUIRE(U(CryptVerifyDetachedMessageSignature));
    CRYPT_VERIFY_MESSAGE_PARA p; vpara(&p);
    const BYTE *ch[1] = { v_payload }; DWORD cl[1] = { sizeof v_payload };
    static const BYTE g[] = { 0x04, 0x02, 0xAA, 0xBB };
    SET_ERR(0);
    CHECK(!U(CryptVerifyDetachedMessageSignature)(&p, 0, (BYTE *)g, sizeof g, 1, (const BYTE **)ch, cl, NULL));
    DWORD e = GetLastError();
    CHECKF(CRYPT_E_ASN1_ANY(e) || e == CRYPT_E_UNEXPECTED_MSG_TYPE_, "0x%08lx", e);
    SET_ERR(0);
    CHECK(!U(CryptVerifyDetachedMessageSignature)(&p, 0, (BYTE *)v_sig_det, sizeof v_sig_det / 2, 1, (const BYTE **)ch, cl, NULL));
    t_note("half a signed message -> 0x%08lx", GetLastError());
}
static int g_cb_calls; static PCCERT_CONTEXT g_cb_ret; static CERT_INFO g_cb_id; static BYTE g_cb_serial[32], g_cb_issuer[256]; static DWORD g_cb_enc;
static PCCERT_CONTEXT WINAPI signer_cb(void *arg, DWORD enc, PCERT_INFO id, HCERTSTORE store) {
    g_cb_calls++; g_cb_enc = enc;
    g_cb_id = *id;
    g_cb_id.SerialNumber.cbData = id->SerialNumber.cbData > 32 ? 32 : id->SerialNumber.cbData; memcpy(g_cb_serial, id->SerialNumber.pbData, g_cb_id.SerialNumber.cbData);
    g_cb_id.Issuer.cbData = id->Issuer.cbData > 256 ? 256 : id->Issuer.cbData; memcpy(g_cb_issuer, id->Issuer.pbData, g_cb_id.Issuer.cbData);
    if (g_cb_ret) return U(CertDuplicateCertificateContext)(g_cb_ret);
    return NULL;
}
TEST(gap1_vds_signer_callback_supplies_certificate) {
    REQUIRE(U(CryptVerifyMessageSignature)); REQUIRE(U(CryptVerifyDetachedMessageSignature)); G1_INIT();
    CRYPT_VERIFY_MESSAGE_PARA p; vpara(&p);
    p.pfnGetSignerCertificate = signer_cb;
    const BYTE *ch[1] = { v_payload }; DWORD cl[1] = { sizeof v_payload };
    /* a detached signature without embedded certificates: only attached nocerts available, use it via the attached API */
    g_cb_calls = 0; g_cb_ret = g1_A.cert;
    BYTE out[128]; DWORD co = sizeof out; PCCERT_CONTEXT signer = NULL;
    BOOL r = U(CryptVerifyMessageSignature)(&p, 0, BLOB(v_sig_att_nocerts), out, &co, &signer);
    CHECKF(r, "0x%08lx", GetLastError());
    CHECK(g_cb_calls == 1);
    if (r) {
        CHECK(co == sizeof v_payload && !memcmp(out, v_payload, co));
        CHECK(same_cert(signer, g1_A.cert)); U(CertFreeCertificateContext)(signer);
        CHECK(g_cb_id.SerialNumber.cbData == g1_A.cert->pCertInfo->SerialNumber.cbData);
        CHECK(!memcmp(g_cb_serial, g1_A.cert->pCertInfo->SerialNumber.pbData, g_cb_id.SerialNumber.cbData));
        CHECK(g_cb_id.Issuer.cbData == g1_A.cert->pCertInfo->Issuer.cbData && !memcmp(g_cb_issuer, g1_A.cert->pCertInfo->Issuer.pbData, g_cb_id.Issuer.cbData));
        CHECK(g_cb_enc == ENC);
    }
    /* callback finds nothing */
    g_cb_calls = 0; g_cb_ret = NULL; co = sizeof out; signer = NULL; SET_ERR(0);
    CHECK(!U(CryptVerifyMessageSignature)(&p, 0, BLOB(v_sig_att_nocerts), out, &co, &signer));
    CHECK(g_cb_calls == 1 && signer == NULL);
    t_note("callback returns NULL -> 0x%08lx", GetLastError());
    /* callback returns the wrong certificate */
    g_cb_calls = 0; g_cb_ret = g1_B.cert; co = sizeof out; signer = NULL; SET_ERR(0);
    CHECK(!U(CryptVerifyMessageSignature)(&p, 0, BLOB(v_sig_att_nocerts), out, &co, &signer));
    CHECK(signer == NULL);
    t_note("callback returns a non-signing certificate -> 0x%08lx", GetLastError());
    /* the same through the detached API with an embedded-cert message: the callback is consulted first */
    g_cb_calls = 0; g_cb_ret = g1_A.cert;
    r = U(CryptVerifyDetachedMessageSignature)(&p, 0, BLOB(v_sig_det), 1, (const BYTE **)ch, cl, &signer);
    CHECK(r); CHECK(g_cb_calls == 1);
    if (r) U(CertFreeCertificateContext)(signer);
}
TEST(gap1_vds_no_certificate_available) {
    /* nocerts message, default lookup (no callback, no store) cannot find the signer */
    REQUIRE(U(CryptVerifyMessageSignature));
    CRYPT_VERIFY_MESSAGE_PARA p; vpara(&p);
    BYTE out[128]; DWORD co = sizeof out; PCCERT_CONTEXT signer = NULL;
    SET_ERR(0);
    CHECK(!U(CryptVerifyMessageSignature)(&p, 0, BLOB(v_sig_att_nocerts), out, &co, &signer));
    CHECK(signer == NULL);
    DWORD e = GetLastError();
    t_note("signer not found -> 0x%08lx", e);
    CHECK(e != 0);
}

/* ---------------- CryptVerifyMessageSignatureWithKey ---------------- */
static void kpara(CRYPT_KEY_VERIFY_MESSAGE_PARA *p) { memset(p, 0, sizeof *p); p->cbSize = sizeof *p; p->dwMsgEncodingType = ENC; }
TEST(gap1_vsk_struct_size) { CHECK(sizeof(CRYPT_KEY_VERIFY_MESSAGE_PARA) == 16); }
TEST(gap1_vsk_good_signatures) {
    REQUIRE(U(CryptVerifyMessageSignatureWithKey)); NOWINE_STUB(); REQUIRE(U(CertCreateCertificateContext));
    PCCERT_CONTEXT a = U(CertCreateCertificateContext)(ENC, BLOB(v_certA)); REQUIRE(a);
    CRYPT_KEY_VERIFY_MESSAGE_PARA p; kpara(&p);
    struct { const char *w; const BYTE *b; DWORD n; } t[] = {
        { "sha256+attrs", v_sig_att, sizeof v_sig_att }, { "sha1+attrs", v_sig_att_sha1, sizeof v_sig_att_sha1 },
        { "noattr", v_sig_att_noattr, sizeof v_sig_att_noattr }, { "nocerts", v_sig_att_nocerts, sizeof v_sig_att_nocerts },
    };
    for (int i = 0; i < 4; i++) {
        BYTE out[128]; DWORD co = sizeof out;
        BOOL r = U(CryptVerifyMessageSignatureWithKey)(&p, &a->pCertInfo->SubjectPublicKeyInfo, (BYTE *)t[i].b, t[i].n, out, &co);
        CHECKF(r, "%s: 0x%08lx", t[i].w, GetLastError());
        if (r) CHECKF(co == sizeof v_payload && !memcmp(out, v_payload, co), "%s content", t[i].w);
        /* verify only */
        CHECKF(U(CryptVerifyMessageSignatureWithKey)(&p, &a->pCertInfo->SubjectPublicKeyInfo, (BYTE *)t[i].b, t[i].n, NULL, NULL), "%s verify only", t[i].w);
    }
    U(CertFreeCertificateContext)(a);
}
TEST(gap1_vsk_decoded_buffer_protocol) {
    REQUIRE(U(CryptVerifyMessageSignatureWithKey)); NOWINE_STUB(); REQUIRE(U(CertCreateCertificateContext));
    PCCERT_CONTEXT a = U(CertCreateCertificateContext)(ENC, BLOB(v_certA)); REQUIRE(a);
    CRYPT_KEY_VERIFY_MESSAGE_PARA p; kpara(&p);
    PCERT_PUBLIC_KEY_INFO k = &a->pCertInfo->SubjectPublicKeyInfo;
    DWORD n = 0xFFFF;
    CHECK(U(CryptVerifyMessageSignatureWithKey)(&p, k, BLOB(v_sig_att), NULL, &n));
    EXPECT_EQ(n, sizeof v_payload);
    BYTE out[128];
    for (DWORD cap = 1; cap < sizeof v_payload; cap += 11) {
        n = cap; SET_ERR(0);
        CHECKF(!U(CryptVerifyMessageSignatureWithKey)(&p, k, BLOB(v_sig_att), out, &n), "cap %lu", cap);
        EXPECT_ERR(ERROR_MORE_DATA); EXPECT_EQ(n, sizeof v_payload);
    }
    n = sizeof out; memset(out, 0x66, sizeof out);
    CHECK(U(CryptVerifyMessageSignatureWithKey)(&p, k, BLOB(v_sig_att), out, &n));
    EXPECT_EQ(n, sizeof v_payload); CHECK(out[sizeof v_payload] == 0x66);
    U(CertFreeCertificateContext)(a);
}
TEST(gap1_vsk_wrong_key) {
    REQUIRE(U(CryptVerifyMessageSignatureWithKey)); NOWINE_STUB(); REQUIRE(U(CertCreateCertificateContext));
    PCCERT_CONTEXT b = U(CertCreateCertificateContext)(ENC, BLOB(v_certB)); REQUIRE(b);
    CRYPT_KEY_VERIFY_MESSAGE_PARA p; kpara(&p);
    const BYTE *blobs[3] = { v_sig_att, v_sig_att_noattr, v_sig_att_nocerts }; DWORD lens[3] = { sizeof v_sig_att, sizeof v_sig_att_noattr, sizeof v_sig_att_nocerts };
    for (int i = 0; i < 3; i++) {
        BYTE out[128]; DWORD co = sizeof out; SET_ERR(0);
        CHECKF(!U(CryptVerifyMessageSignatureWithKey)(&p, &b->pCertInfo->SubjectPublicKeyInfo, (BYTE *)blobs[i], lens[i], out, &co), "blob %d", i);
        EXPECT_ERR((DWORD)ST_INVALID_SIGNATURE);
        EXPECT_EQ(co, 0);
    }
    U(CertFreeCertificateContext)(b);
}
static BYTE *dup_flip(const BYTE *b, DWORD n, DWORD off) { BYTE *c = malloc(n); memcpy(c, b, n); c[off] ^= 0x01; return c; }
static DWORD find(const BYTE *h, DWORD n, const BYTE *nd, DWORD m) { for (DWORD i = 0; i + m <= n; i++) if (!memcmp(h + i, nd, m)) return i; return 0xFFFFFFFF; }
TEST(gap1_vsk_tampered_content_and_signature) {
    REQUIRE(U(CryptVerifyMessageSignatureWithKey)); NOWINE_STUB(); REQUIRE(U(CertCreateCertificateContext));
    PCCERT_CONTEXT a = U(CertCreateCertificateContext)(ENC, BLOB(v_certA)); REQUIRE(a);
    PCERT_PUBLIC_KEY_INFO k = &a->pCertInfo->SubjectPublicKeyInfo;
    CRYPT_KEY_VERIFY_MESSAGE_PARA p; kpara(&p);
    DWORD at = find(v_sig_att, sizeof v_sig_att, v_payload, sizeof v_payload);
    DWORD an = find(v_sig_att_noattr, sizeof v_sig_att_noattr, v_payload, sizeof v_payload);
    CHECK(at != 0xFFFFFFFF && an != 0xFFFFFFFF);
    BYTE out[128]; DWORD co;
    /* content tampered: signed attributes carry the digest -> hash value error; without attributes the signature fails */
    BYTE *c = dup_flip(v_sig_att, sizeof v_sig_att, at + 3); co = sizeof out; SET_ERR(0);
    CHECK(!U(CryptVerifyMessageSignatureWithKey)(&p, k, c, sizeof v_sig_att, out, &co)); EXPECT_ERR(CRYPT_E_HASH_VALUE_); free(c);
    c = dup_flip(v_sig_att_noattr, sizeof v_sig_att_noattr, an + 3); co = sizeof out; SET_ERR(0);
    CHECK(!U(CryptVerifyMessageSignatureWithKey)(&p, k, c, sizeof v_sig_att_noattr, out, &co)); EXPECT_ERR((DWORD)ST_INVALID_SIGNATURE); free(c);
    /* signature value is the tail of each message (last OCTET STRING of 128 bytes) */
    c = dup_flip(v_sig_att, sizeof v_sig_att, sizeof v_sig_att - 20); co = sizeof out; SET_ERR(0);
    CHECK(!U(CryptVerifyMessageSignatureWithKey)(&p, k, c, sizeof v_sig_att, out, &co)); EXPECT_ERR((DWORD)ST_INVALID_SIGNATURE); free(c);
    c = dup_flip(v_sig_att_noattr, sizeof v_sig_att_noattr, sizeof v_sig_att_noattr - 20); co = sizeof out; SET_ERR(0);
    CHECK(!U(CryptVerifyMessageSignatureWithKey)(&p, k, c, sizeof v_sig_att_noattr, out, &co)); EXPECT_ERR((DWORD)ST_INVALID_SIGNATURE); free(c);
    U(CertFreeCertificateContext)(a);
}
TEST(gap1_vsk_null_key_skips_verification) {
    REQUIRE(U(CryptVerifyMessageSignatureWithKey)); NOWINE_STUB();
    CRYPT_KEY_VERIFY_MESSAGE_PARA p; kpara(&p);
    BYTE *c = dup_flip(v_sig_att_noattr, sizeof v_sig_att_noattr, sizeof v_sig_att_noattr - 20);
    BYTE out[128]; DWORD co = sizeof out;
    /* with no public key the message is only decoded, the signature is not checked */
    BOOL r = U(CryptVerifyMessageSignatureWithKey)(&p, NULL, c, sizeof v_sig_att_noattr, out, &co);
    CHECKF(r, "0x%08lx", GetLastError());
    if (r) CHECK(co == sizeof v_payload && !memcmp(out, v_payload, co));
    free(c);
    co = 0;
    CHECK(U(CryptVerifyMessageSignatureWithKey)(&p, NULL, BLOB(v_sig_att), NULL, &co));
    EXPECT_EQ(co, sizeof v_payload);
}
TEST(gap1_vsk_bad_cbsize) {
    REQUIRE(U(CryptVerifyMessageSignatureWithKey)); NOWINE_STUB(); REQUIRE(U(CertCreateCertificateContext));
    PCCERT_CONTEXT a = U(CertCreateCertificateContext)(ENC, BLOB(v_certA)); REQUIRE(a);
    CRYPT_KEY_VERIFY_MESSAGE_PARA p; kpara(&p);
    static const DWORD sizes[] = { 0, 4, 8, 12, 15, 17, 24, 32 };
    for (unsigned i = 0; i < 8; i++) {
        p.cbSize = sizes[i]; BYTE out[128]; DWORD co = 77; SET_ERR(0);
        CHECKF(!U(CryptVerifyMessageSignatureWithKey)(&p, &a->pCertInfo->SubjectPublicKeyInfo, BLOB(v_sig_att), out, &co), "cbSize %lu", sizes[i]);
        EXPECT_ERR(E_INVALIDARG_);
        EXPECT_EQ(co, 0);
    }
    U(CertFreeCertificateContext)(a);
}
TEST(gap1_vsk_wrong_message_type) {
    REQUIRE(U(CryptVerifyMessageSignatureWithKey)); NOWINE_STUB(); REQUIRE(U(CertCreateCertificateContext));
    PCCERT_CONTEXT a = U(CertCreateCertificateContext)(ENC, BLOB(v_certA)); REQUIRE(a);
    CRYPT_KEY_VERIFY_MESSAGE_PARA p; kpara(&p);
    BYTE out[128]; DWORD co = sizeof out; SET_ERR(0);
    CHECK(!U(CryptVerifyMessageSignatureWithKey)(&p, &a->pCertInfo->SubjectPublicKeyInfo, BLOB(v_dig_sha256), out, &co));
    EXPECT_ERR(CRYPT_E_UNEXPECTED_MSG_TYPE_); EXPECT_EQ(co, 0);
    co = sizeof out; SET_ERR(0);
    CHECK(!U(CryptVerifyMessageSignatureWithKey)(&p, &a->pCertInfo->SubjectPublicKeyInfo, BLOB(v_env_aes128), out, &co));
    EXPECT_ERR(CRYPT_E_UNEXPECTED_MSG_TYPE_);
    /* with a NULL key the type check is still made */
    co = sizeof out; SET_ERR(0);
    CHECK(!U(CryptVerifyMessageSignatureWithKey)(&p, NULL, BLOB(v_dig_sha256), out, &co));
    EXPECT_ERR(CRYPT_E_UNEXPECTED_MSG_TYPE_);
    U(CertFreeCertificateContext)(a);
}
TEST(gap1_vsk_garbage_and_truncated) {
    REQUIRE(U(CryptVerifyMessageSignatureWithKey)); NOWINE_STUB(); REQUIRE(U(CertCreateCertificateContext));
    PCCERT_CONTEXT a = U(CertCreateCertificateContext)(ENC, BLOB(v_certA)); REQUIRE(a);
    CRYPT_KEY_VERIFY_MESSAGE_PARA p; kpara(&p);
    static const BYTE g[] = { 0xFF, 0xFE, 0xFD, 0xFC, 0xFB };
    BYTE out[128]; DWORD co = sizeof out; SET_ERR(0);
    CHECK(!U(CryptVerifyMessageSignatureWithKey)(&p, &a->pCertInfo->SubjectPublicKeyInfo, (BYTE *)g, sizeof g, out, &co));
    DWORD e = GetLastError(); CHECKF(CRYPT_E_ASN1_ANY(e), "0x%08lx", e); EXPECT_EQ(co, 0);
    co = sizeof out; SET_ERR(0);
    CHECK(!U(CryptVerifyMessageSignatureWithKey)(&p, &a->pCertInfo->SubjectPublicKeyInfo, (BYTE *)v_sig_att, sizeof v_sig_att - 30, out, &co));
    t_note("truncated -> 0x%08lx", GetLastError());
    EXPECT_EQ(co, 0);
    U(CertFreeCertificateContext)(a);
}
TEST(gap1_vsk_detached_blob_note) {
    REQUIRE(U(CryptVerifyMessageSignatureWithKey)); NOWINE_STUB(); REQUIRE(U(CertCreateCertificateContext));
    PCCERT_CONTEXT a = U(CertCreateCertificateContext)(ENC, BLOB(v_certA)); REQUIRE(a);
    CRYPT_KEY_VERIFY_MESSAGE_PARA p; kpara(&p);
    BYTE out[128]; DWORD co = sizeof out; SET_ERR(0);
    BOOL r = U(CryptVerifyMessageSignatureWithKey)(&p, &a->pCertInfo->SubjectPublicKeyInfo, BLOB(v_sig_det), out, &co);
    t_note("detached signed blob through the attached key API: ret %d err 0x%08lx", r, GetLastError());
    CHECK(!r);
    U(CertFreeCertificateContext)(a);
}
TEST(gap1_vsk_algorithm_mismatch_key_note) {
    REQUIRE(U(CryptVerifyMessageSignatureWithKey)); NOWINE_STUB();
    PCCERT_CONTEXT e = U(CertCreateCertificateContext)(ENC, BLOB(v_certE256)); REQUIRE(e);
    CRYPT_KEY_VERIFY_MESSAGE_PARA p; kpara(&p);
    BYTE out[128]; DWORD co = sizeof out; SET_ERR(0);
    BOOL r = U(CryptVerifyMessageSignatureWithKey)(&p, &e->pCertInfo->SubjectPublicKeyInfo, BLOB(v_sig_att), out, &co);
    t_note("RSA-signed message checked with an ECC public key: ret %d err 0x%08lx", r, GetLastError());
    CHECK(!r);
    U(CertFreeCertificateContext)(e);
}

/* ---------------- CryptDecryptMessage ---------------- */
static HCERTSTORE dec_store(const g1_id *id, int with_key) {
    HCERTSTORE s = U(CertOpenStore)(CERT_STORE_PROV_MEMORY, 0, 0, CERT_STORE_NO_CRYPT_RELEASE_FLAG, NULL);
    if (!s) return NULL;
    PCCERT_CONTEXT c = NULL;
    if (!U(CertAddCertificateContextToStore)(s, id->cert, CERT_STORE_ADD_ALWAYS, &c)) { U(CertCloseStore)(s, 0); return NULL; }
    if (with_key) {
        /* AES content needs a CNG key handle: a legacy provider handle only decrypts the 3DES message.  Every store gets its
           own handle because crypt32 releases the handle of a context it has finished with. */
        CERT_KEY_CONTEXT kc; memset(&kc, 0, sizeof kc);
        kc.cbSize = sizeof kc;
        kc.hNCryptKey = g1_cng_key(id == &g1_A ? v_keyA : v_keyB); kc.dwKeySpec = CERT_NCRYPT_KEY_SPEC;
        if (!kc.hNCryptKey) { kc.hCryptProv = id->prov; kc.dwKeySpec = AT_KEYEXCHANGE; }
        U(CertSetCertificateContextProperty)(c, CERT_KEY_CONTEXT_PROP_ID, 0, &kc);
    }
    U(CertFreeCertificateContext)(c);
    return s;
}
static void dpara(CRYPT_DECRYPT_MESSAGE_PARA *p, HCERTSTORE *stores, DWORD n) {
    memset(p, 0, sizeof *p); p->cbSize = sizeof *p; p->dwMsgAndCertEncodingType = ENC; p->cCertStore = n; p->rghCertStore = stores;
}
TEST(gap1_decrypt_all_content_algorithms) {
    REQUIRE(U(CryptDecryptMessage)); NOWINE_STUB(); G1_INIT();
    HCERTSTORE st = dec_store(&g1_A, 1); REQUIRE(st);
    CRYPT_DECRYPT_MESSAGE_PARA p; dpara(&p, &st, 1);
    struct { const char *w; const BYTE *b; DWORD n; } t[] = {
        { "aes256", v_env_aes256, sizeof v_env_aes256 }, { "aes128", v_env_aes128, sizeof v_env_aes128 }, { "3des", v_env_3des, sizeof v_env_3des } };
    for (int i = 0; i < 3; i++) {
        BYTE out[128]; DWORD co = sizeof out; PCCERT_CONTEXT x = NULL;
        BOOL r = U(CryptDecryptMessage)(&p, (BYTE *)t[i].b, t[i].n, out, &co, &x);
        CHECKF(r, "%s: 0x%08lx", t[i].w, GetLastError());
        if (r) {
            CHECKF(co == sizeof v_payload && !memcmp(out, v_payload, co), "%s content", t[i].w);
            CHECKF(x && x->cbCertEncoded == sizeof v_certA && !memcmp(x->pbCertEncoded, v_certA, sizeof v_certA), "%s exchange cert", t[i].w);
            if (x) U(CertFreeCertificateContext)(x);
        }
    }
    U(CertCloseStore)(st, 0);
}
TEST(gap1_decrypt_buffer_protocol) {
    REQUIRE(U(CryptDecryptMessage)); NOWINE_STUB(); G1_INIT();
    HCERTSTORE st = dec_store(&g1_A, 1); REQUIRE(st);
    CRYPT_DECRYPT_MESSAGE_PARA p; dpara(&p, &st, 1);
    DWORD n = 0xFFFF;
    CHECK(U(CryptDecryptMessage)(&p, BLOB(v_env_aes256), NULL, &n, NULL));
    EXPECT_EQ(n, 54);          /* the NULL-buffer query reports an upper bound (54), not the exact 44-byte payload size */
    BYTE out[128];
    for (DWORD cap = 1; cap < sizeof v_payload; cap += 10) {
        n = cap; SET_ERR(0);
        CHECKF(!U(CryptDecryptMessage)(&p, BLOB(v_env_aes256), out, &n, NULL), "cap %lu", cap);
        EXPECT_ERR(ERROR_MORE_DATA); EXPECT_EQ(n, sizeof v_payload);
    }
    /* no output pointers at all: decrypt-and-discard */
    CHECK(U(CryptDecryptMessage)(&p, BLOB(v_env_aes256), NULL, NULL, NULL));
    U(CertCloseStore)(st, 0);
}
TEST(gap1_decrypt_no_matching_certificate) {
    REQUIRE(U(CryptDecryptMessage)); NOWINE_STUB(); G1_INIT();
    HCERTSTORE st = dec_store(&g1_B, 1); REQUIRE(st);       /* recipient B is not the one the message targets */
    CRYPT_DECRYPT_MESSAGE_PARA p; dpara(&p, &st, 1);
    BYTE out[128]; DWORD co = sizeof out; PCCERT_CONTEXT x = (PCCERT_CONTEXT)(ULONG_PTR)1;
    SET_ERR(0);
    CHECK(!U(CryptDecryptMessage)(&p, BLOB(v_env_aes256), out, &co, &x));
    EXPECT_ERR(CRYPT_E_NO_DECRYPT_CERT);
    CHECK(x == NULL); EXPECT_EQ(co, 0);
    U(CertCloseStore)(st, 0);
}
TEST(gap1_decrypt_certificate_without_private_key) {
    REQUIRE(U(CryptDecryptMessage)); NOWINE_STUB(); G1_INIT();
    HCERTSTORE st = dec_store(&g1_A, 0); REQUIRE(st);
    CRYPT_DECRYPT_MESSAGE_PARA p; dpara(&p, &st, 1);
    BYTE out[128]; DWORD co = sizeof out; SET_ERR(0);
    CHECK(!U(CryptDecryptMessage)(&p, BLOB(v_env_aes256), out, &co, NULL));
    DWORD e = GetLastError();
    t_note("recipient certificate without a key -> 0x%08lx", e);
    CHECK(e != 0);
    U(CertCloseStore)(st, 0);
}
TEST(gap1_decrypt_store_list_variants) {
    REQUIRE(U(CryptDecryptMessage)); NOWINE_STUB(); G1_INIT();
    HCERTSTORE sb = dec_store(&g1_B, 1), sa = dec_store(&g1_A, 1); REQUIRE(sa && sb);
    BYTE out[128]; DWORD co;
    HCERTSTORE both[2] = { sb, sa }, both2[2] = { sa, sb };
    CRYPT_DECRYPT_MESSAGE_PARA p;
    dpara(&p, both, 2); co = sizeof out;
    CHECKF(U(CryptDecryptMessage)(&p, BLOB(v_env_aes256), out, &co, NULL), "second store: 0x%08lx", GetLastError());
    dpara(&p, both2, 2); co = sizeof out;
    CHECKF(U(CryptDecryptMessage)(&p, BLOB(v_env_aes256), out, &co, NULL), "first store: 0x%08lx", GetLastError());
    dpara(&p, NULL, 0); co = sizeof out; SET_ERR(0);
    CHECK(!U(CryptDecryptMessage)(&p, BLOB(v_env_aes256), out, &co, NULL));
    t_note("no stores -> 0x%08lx", GetLastError());
    U(CertCloseStore)(sa, 0); U(CertCloseStore)(sb, 0);
}
TEST(gap1_decrypt_parameter_validation) {
    REQUIRE(U(CryptDecryptMessage)); NOWINE_STUB(); G1_INIT();
    HCERTSTORE st = dec_store(&g1_A, 1); REQUIRE(st);
    CRYPT_DECRYPT_MESSAGE_PARA p; dpara(&p, &st, 1);
    BYTE out[128]; DWORD co = sizeof out;
    SET_ERR(0);
    CHECK(!U(CryptDecryptMessage)(NULL, BLOB(v_env_aes256), out, &co, NULL));
    EXPECT_ERR(E_INVALIDARG_); EXPECT_EQ(co, 0);
    static const DWORD sizes[] = { 0, 8, 16, 23 };
    for (unsigned i = 0; i < 4; i++) {
        dpara(&p, &st, 1); p.cbSize = sizes[i]; co = sizeof out; SET_ERR(0);
        CHECKF(!U(CryptDecryptMessage)(&p, BLOB(v_env_aes256), out, &co, NULL), "cbSize %lu", sizes[i]);
        EXPECT_ERR(E_INVALIDARG_);
    }
    dpara(&p, &st, 1); p.cbSize = 24;               /* the pre-dwFlags size is accepted */
    co = sizeof out;
    CHECKF(U(CryptDecryptMessage)(&p, BLOB(v_env_aes256), out, &co, NULL), "cbSize 24: 0x%08lx", GetLastError());
    dpara(&p, &st, 1); p.dwMsgAndCertEncodingType = 0; co = sizeof out; SET_ERR(0);
    CHECK(!U(CryptDecryptMessage)(&p, BLOB(v_env_aes256), out, &co, NULL));
    EXPECT_ERR(E_INVALIDARG_);
    U(CertCloseStore)(st, 0);
}
TEST(gap1_decrypt_wrong_message_types) {
    REQUIRE(U(CryptDecryptMessage)); NOWINE_STUB(); G1_INIT();
    HCERTSTORE st = dec_store(&g1_A, 1); REQUIRE(st);
    CRYPT_DECRYPT_MESSAGE_PARA p; dpara(&p, &st, 1);
    BYTE out[128]; DWORD co = sizeof out;
    SET_ERR(0);
    CHECK(!U(CryptDecryptMessage)(&p, BLOB(v_sig_att), out, &co, NULL)); EXPECT_ERR(CRYPT_E_UNEXPECTED_MSG_TYPE_);
    co = sizeof out; SET_ERR(0);
    CHECK(!U(CryptDecryptMessage)(&p, BLOB(v_dig_sha256), out, &co, NULL)); EXPECT_ERR(CRYPT_E_UNEXPECTED_MSG_TYPE_);
    EXPECT_EQ(co, 0);
    U(CertCloseStore)(st, 0);
}
TEST(gap1_decrypt_garbage_and_corruption) {
    REQUIRE(U(CryptDecryptMessage)); NOWINE_STUB(); G1_INIT();
    HCERTSTORE st = dec_store(&g1_A, 1); REQUIRE(st);
    CRYPT_DECRYPT_MESSAGE_PARA p; dpara(&p, &st, 1);
    static const BYTE g[] = { 0x31, 0x00 };
    BYTE out[128]; DWORD co = sizeof out; SET_ERR(0);
    CHECK(!U(CryptDecryptMessage)(&p, (BYTE *)g, sizeof g, out, &co, NULL));
    DWORD e = GetLastError(); CHECKF(CRYPT_E_ASN1_ANY(e), "0x%08lx", e);
    /* corrupted ciphertext (tail of the message): padding or length error; never success with the original text */
    BYTE *c = dup_flip(v_env_aes256, sizeof v_env_aes256, sizeof v_env_aes256 - 1);
    co = sizeof out; memset(out, 0, sizeof out); SET_ERR(0);
    BOOL r = U(CryptDecryptMessage)(&p, c, sizeof v_env_aes256, out, &co, NULL);
    t_note("last ciphertext byte flipped: ret %d err 0x%08lx", r, GetLastError());
    if (r) CHECK(co != sizeof v_payload || memcmp(out, v_payload, co) != 0);
    free(c);
    U(CertCloseStore)(st, 0);
}
