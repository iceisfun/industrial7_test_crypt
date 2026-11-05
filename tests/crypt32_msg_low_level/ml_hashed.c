/* CMSG_HASHED (digestedData): encode, decode, CMSG_CTRL_VERIFY_HASH. */
#include "ml.h"

static const BYTE T3[3] = {'a','b','c'};

static void hinfo(CMSG_HASHED_ENCODE_INFO *h, const char *oid, HCRYPTPROV prov) {
    memset(h, 0, sizeof *h);
    h->cbSize = sizeof *h;
    h->hCryptProv = prov;
    h->HashAlgorithm.pszObjId = (LPSTR)oid;
}
static BYTE *enc_hashed(const char *oid, DWORD flags, const BYTE *d, DWORD n, DWORD *out) {
    CMSG_HASHED_ENCODE_INFO h; hinfo(&h, oid, 0);
    HCRYPTMSG m = mOpenEnc()(ENC, flags, CMSG_HASHED, &h, NULL, NULL);
    BYTE *r = NULL;
    if (!m) return NULL;
    if (mUpdate()(m, d, n, TRUE)) r = ml_param(m, CMSG_CONTENT_PARAM, 0, out);
    mClose()(m);
    return r;
}

/* ---- open validation ---- */
TEST(mlh_open_null_info) {
    REQ_MSG();
    if (t_is_wine()) { t_skip("emulator dereferences NULL info"); return; }
    SET_ERR(0);
    HCRYPTMSG m = mOpenEnc()(ENC, 0, CMSG_HASHED, NULL, NULL, NULL);
    CHECK(m == NULL);
    EXPECT_ERR(E_INVALIDARG);
    if (m) mClose()(m);
}
TEST(mlh_open_bad_cbsize) {
    REQ_MSG();
    static const DWORD cbs[] = {0, 1, 4, 8};
    for (size_t i = 0; i < sizeof cbs / sizeof *cbs; i++) {
        CMSG_HASHED_ENCODE_INFO h; hinfo(&h, OID_SHA1, 0); h.cbSize = cbs[i];
        SET_ERR(0);
        HCRYPTMSG m = mOpenEnc()(ENC, 0, CMSG_HASHED, &h, NULL, NULL);
        CHECKF(m == NULL, "cbSize %lu", (unsigned long)cbs[i]);
        if (m) mClose()(m); else EXPECT_ERR(E_INVALIDARG);
    }
}
TEST(mlh_open_unknown_hash_oid) {
    REQ_MSG();
    static const char *oids[] = {"1.2.3.4", "1.3.14.3.2.99", "2.16.840.1.101.3.4.2.99"};
    for (size_t i = 0; i < 3; i++) {
        CMSG_HASHED_ENCODE_INFO h; hinfo(&h, oids[i], 0);
        SET_ERR(0);
        HCRYPTMSG m = mOpenEnc()(ENC, 0, CMSG_HASHED, &h, NULL, NULL);
        CHECKF(m == NULL, "oid %s", oids[i]);
        if (m) mClose()(m); else EXPECT_ERR(CRYPT_E_UNKNOWN_ALGO);
    }
}
TEST(mlh_open_null_oid) {
    REQ_MSG();
    CMSG_HASHED_ENCODE_INFO h; hinfo(&h, NULL, 0);
    SET_ERR(0);
    HCRYPTMSG m = mOpenEnc()(ENC, 0, CMSG_HASHED, &h, NULL, NULL);
    t_note("hashed open with NULL hash OID: %s err=0x%lx", m ? "succeeded" : "failed", (unsigned long)GetLastError());
    CHECK(1);
    if (m) mClose()(m);
}
TEST(mlh_open_with_explicit_provider) {
    REQ_MSG();
    HCRYPTPROV p = ml_prov(NULL, 0);
    REQUIRE(p);
    CMSG_HASHED_ENCODE_INFO h; hinfo(&h, OID_SHA1, p);
    HCRYPTMSG m = mOpenEnc()(ENC, 0, CMSG_HASHED, &h, NULL, NULL);
    CHECK(m != NULL);
    if (m) { CHECK(mUpdate()(m, T3, 3, TRUE)); mClose()(m); }
    ml_prov_release(p);
}
TEST(mlh_open_release_context_flag) {
    REQ_MSG();
    HCRYPTPROV p = ml_prov(NULL, 0);
    REQUIRE(p);
    CMSG_HASHED_ENCODE_INFO h; hinfo(&h, OID_SHA1, p);
    HCRYPTMSG m = mOpenEnc()(ENC, CMSG_CRYPT_RELEASE_CONTEXT_FLAG, CMSG_HASHED, &h, NULL, NULL);
    CHECK(m != NULL);
    if (m) { CHECK(mUpdate()(m, T3, 3, TRUE)); CHECK(mClose()(m)); }
    /* ownership of the provider passed to the message; do not release it here */
}

/* ---- encode results ---- */
typedef struct { const char *oid; const BYTE *dig; DWORD cb; const char *name; } halg_t;
static const halg_t HALGS[] = {
    {OID_SHA1, V_SHA1, V_SHA1_LEN, "sha1"}, {OID_SHA256, V_SHA256, V_SHA256_LEN, "sha256"}, {OID_MD5, V_MD5, V_MD5_LEN, "md5"},
};
TEST(mlh_encode_roundtrip_digest_in_message) {
    REQ_MSG();
    for (size_t i = 0; i < 3; i++) {
        DWORD cb = 0; BYTE *b = enc_hashed(HALGS[i].oid, 0, V_CONTENT, V_CONTENT_LEN, &cb);
        CHECKF(b != NULL, "%s", HALGS[i].name);
        if (!b) continue;
        CHECKF(b[0] == 0x30, "%s", HALGS[i].name);
        CHECKF(ml_memmem(b, cb, HALGS[i].dig, HALGS[i].cb) != NULL, "%s digest present", HALGS[i].name);
        CHECKF(ml_memmem(b, cb, V_CONTENT, V_CONTENT_LEN) != NULL, "%s content present", HALGS[i].name);
        ml_free(b);
    }
}
TEST(mlh_encode_content_info_oid_is_digested) {
    REQ_MSG();
    static const BYTE digested[] = {0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x07,0x05};
    DWORD cb = 0; BYTE *b = enc_hashed(OID_SHA1, 0, T3, 3, &cb);
    CHECK(b != NULL);
    if (b) { CHECK(ml_memmem(b, cb, digested, sizeof digested) == b + 2 || ml_memmem(b, cb, digested, sizeof digested) == b + 3 || ml_memmem(b, cb, digested, sizeof digested) == b + 4); ml_free(b); }
}
TEST(mlh_encode_version_param_zero) {
    REQ_MSG();
    CMSG_HASHED_ENCODE_INFO h; hinfo(&h, OID_SHA1, 0);
    HCRYPTMSG m = mOpenEnc()(ENC, 0, CMSG_HASHED, &h, NULL, NULL);
    if (!m) { CHECK(m != NULL); return; }
    CHECK(mUpdate()(m, T3, 3, TRUE));
    DWORD v = 99;
    if (ml_param_dword(m, CMSG_VERSION_PARAM, 0, &v)) EXPECT_EQ(v, 0);
    else t_note("VERSION_PARAM on encode hashed failed: 0x%lx", (unsigned long)GetLastError());
    mClose()(m);
}
TEST(mlh_encode_getparams_after_final) {
    REQ_MSG();
    CMSG_HASHED_ENCODE_INFO h; hinfo(&h, OID_SHA1, 0);
    HCRYPTMSG m = mOpenEnc()(ENC, 0, CMSG_HASHED, &h, NULL, NULL);
    if (!m) { CHECK(m != NULL); return; }
    CHECK(mUpdate()(m, V_CONTENT, V_CONTENT_LEN, TRUE));
    DWORD cb = 0; BYTE *b;
    b = ml_param(m, CMSG_COMPUTED_HASH_PARAM, 0, &cb);
    CHECK(b && cb == V_SHA1_LEN && !memcmp(b, V_SHA1, cb)); ml_free(b);
    DWORD n = 0; SET_ERR(0);
    CHECK(!mGetParam()(m, CMSG_HASH_DATA_PARAM, 0, NULL, &n));   /* not available on an encoded message */
    EXPECT_ERR(CRYPT_E_INVALID_MSG_TYPE);
    DWORD v = 99;
    CHECK(ml_param_dword(m, CMSG_VERSION_PARAM, 0, &v));
    EXPECT_EQ(v, 0);
    n = 0; SET_ERR(0);
    CHECK(!mGetParam()(m, CMSG_TYPE_PARAM, 0, NULL, &n));        /* the type is not available on an encoded message */
    mClose()(m);
}
TEST(mlh_encode_exact_bytes_md5_1234) {
    REQ_MSG();
    static const BYTE d4[4] = {1,2,3,4};
    DWORD cb = 0; BYTE *b = enc_hashed(OID_MD5, 0, d4, 4, &cb);
    CHECK(b && cb == X_HASH_MD5_1234_LEN && !memcmp(b, X_HASH_MD5_1234, cb));
    ml_free(b);
    b = enc_hashed(OID_MD5, CMSG_DETACHED_FLAG, d4, 4, &cb);
    CHECK(b && cb == X_HASH_MD5_1234_DET_LEN && !memcmp(b, X_HASH_MD5_1234_DET, cb));
    ml_free(b);
}
TEST(mlh_encode_exact_bytes_bare_md5_1234) {
    REQ_MSG();
    static const BYTE d4[4] = {1,2,3,4};
    CMSG_HASHED_ENCODE_INFO h; hinfo(&h, OID_MD5, 0);
    HCRYPTMSG m = mOpenEnc()(ENC, 0, CMSG_HASHED, &h, NULL, NULL);
    if (!m) { CHECK(m != NULL); return; }
    CHECK(mUpdate()(m, d4, 4, TRUE));
    DWORD cb = 0; BYTE *b = ml_param(m, CMSG_BARE_CONTENT_PARAM, 0, &cb);
    CHECK(b && cb == X_HASH_MD5_1234_BARE_LEN && !memcmp(b, X_HASH_MD5_1234_BARE, cb));
    ml_free(b);
    mClose()(m);
}
TEST(mlh_encode_exact_bytes_sha1_sha256_content) {
    REQ_MSG();
    DWORD cb = 0; BYTE *b = enc_hashed(OID_SHA1, 0, V_CONTENT, V_CONTENT_LEN, &cb);
    CHECK(b && cb == X_HASH_SHA1_CONTENT_LEN && !memcmp(b, X_HASH_SHA1_CONTENT, cb));
    ml_free(b);
    b = enc_hashed(OID_SHA256, 0, V_CONTENT, V_CONTENT_LEN, &cb);
    CHECK(b && cb == X_HASH_SHA256_CONTENT_LEN && !memcmp(b, X_HASH_SHA256_CONTENT, cb));
    ml_free(b);
}
TEST(mlh_encode_computed_hash_finalizes_hash) {
    REQ_MSG();
    static const BYTE md5_empty[16] = {0xd4,0x1d,0x8c,0xd9,0x8f,0x00,0xb2,0x04,0xe9,0x80,0x09,0x98,0xec,0xf8,0x42,0x7e};
    CMSG_HASHED_ENCODE_INFO h; hinfo(&h, OID_MD5, 0);
    HCRYPTMSG m = mOpenEnc()(ENC, 0, CMSG_HASHED, &h, NULL, NULL);
    if (!m) { CHECK(m != NULL); return; }
    DWORD cb = 0; BYTE *b = ml_param(m, CMSG_COMPUTED_HASH_PARAM, 0, &cb);   /* before any update: hash of nothing */
    CHECK(b && cb == 16 && !memcmp(b, md5_empty, 16));
    ml_free(b);
    SET_ERR(0);
    CHECK(!mUpdate()(m, V_CONTENT, 4, TRUE));
    DWORD e = GetLastError();
    CHECKF(e == (DWORD)NTE_BAD_HASH_STATE || e == (DWORD)CRYPT_E_MSG_ERROR, "err 0x%lx", (unsigned long)e);
    mClose()(m);
}
TEST(mlh_encode_nonfinal_needs_detached) {
    REQ_MSG();
    CMSG_HASHED_ENCODE_INFO h; hinfo(&h, OID_SHA1, 0);
    HCRYPTMSG m = mOpenEnc()(ENC, 0, CMSG_HASHED, &h, NULL, NULL);
    if (!m) { CHECK(m != NULL); return; }
    SET_ERR(0);
    CHECK(!mUpdate()(m, T3, 3, FALSE));
    EXPECT_ERR(CRYPT_E_MSG_ERROR);
    mClose()(m);
}
TEST(mlh_encode_detached_chunks_equal_oneshot_hash) {
    REQ_MSG();
    CMSG_HASHED_ENCODE_INFO h; hinfo(&h, OID_SHA256, 0);
    HCRYPTMSG m = mOpenEnc()(ENC, CMSG_DETACHED_FLAG, CMSG_HASHED, &h, NULL, NULL);
    if (!m) { CHECK(m != NULL); return; }
    DWORD off = 0;
    while (off + 5 < V_CONTENT_LEN) { CHECK(mUpdate()(m, V_CONTENT + off, 5, FALSE)); off += 5; }
    CHECK(mUpdate()(m, V_CONTENT + off, V_CONTENT_LEN - off, TRUE));
    DWORD cb = 0; BYTE *b = ml_param(m, CMSG_COMPUTED_HASH_PARAM, 0, &cb);
    CHECK(b && cb == V_SHA256_LEN && !memcmp(b, V_SHA256, cb)); ml_free(b);
    b = ml_param(m, CMSG_CONTENT_PARAM, 0, &cb);
    CHECK(b != NULL);
    if (b) { CHECK(ml_memmem(b, cb, V_CONTENT, 8) == NULL); CHECK(ml_memmem(b, cb, V_SHA256, V_SHA256_LEN) != NULL); }
    ml_free(b);
    mClose()(m);
}
TEST(mlh_encode_empty_content_hash) {
    REQ_MSG();
    static const BYTE sha1_empty[] = {0xda,0x39,0xa3,0xee,0x5e,0x6b,0x4b,0x0d,0x32,0x55,0xbf,0xef,0x95,0x60,0x18,0x90,0xaf,0xd8,0x07,0x09};
    CMSG_HASHED_ENCODE_INFO h; hinfo(&h, OID_SHA1, 0);
    HCRYPTMSG m = mOpenEnc()(ENC, 0, CMSG_HASHED, &h, NULL, NULL);
    if (!m) { CHECK(m != NULL); return; }
    CHECK(mUpdate()(m, NULL, 0, TRUE));
    DWORD cb = 0; BYTE *b = ml_param(m, CMSG_COMPUTED_HASH_PARAM, 0, &cb);
    CHECK(b && cb == 20 && !memcmp(b, sha1_empty, 20)); ml_free(b);
    mClose()(m);
}
TEST(mlh_encode_update_after_final) {
    REQ_MSG();
    CMSG_HASHED_ENCODE_INFO h; hinfo(&h, OID_SHA1, 0);
    HCRYPTMSG m = mOpenEnc()(ENC, 0, CMSG_HASHED, &h, NULL, NULL);
    if (!m) { CHECK(m != NULL); return; }
    CHECK(mUpdate()(m, T3, 3, TRUE));
    SET_ERR(0);
    CHECK(!mUpdate()(m, T3, 3, TRUE));
    EXPECT_ERR(CRYPT_E_MSG_ERROR);
    mClose()(m);
}
TEST(mlh_encode_inapplicable_params) {
    REQ_MSG();
    CMSG_HASHED_ENCODE_INFO h; hinfo(&h, OID_SHA1, 0);
    HCRYPTMSG m = mOpenEnc()(ENC, 0, CMSG_HASHED, &h, NULL, NULL);
    if (!m) { CHECK(m != NULL); return; }
    CHECK(mUpdate()(m, T3, 3, TRUE));
    static const DWORD p[] = {CMSG_SIGNER_COUNT_PARAM, CMSG_RECIPIENT_COUNT_PARAM, CMSG_ENVELOPE_ALGORITHM_PARAM, CMSG_ENCODED_SIGNER};
    for (size_t i = 0; i < sizeof p / sizeof *p; i++) {
        DWORD n = 0; SET_ERR(0);
        CHECKF(!mGetParam()(m, p[i], 0, NULL, &n), "param %lu", (unsigned long)p[i]);
        EXPECT_ERR(CRYPT_E_INVALID_MSG_TYPE);
    }
    mClose()(m);
}
TEST(mlh_encode_calc_length) {
    REQ_MSG();
    REQUIRE(mCalcLen());
    if (t_is_wine()) { t_skip("CryptMsgCalculateEncodedLength is unimplemented under wine"); return; }
    CMSG_HASHED_ENCODE_INFO h; hinfo(&h, OID_SHA1, 0);
    DWORD cb = 0; BYTE *b = enc_hashed(OID_SHA1, 0, V_CONTENT, V_CONTENT_LEN, &cb);
    DWORD calc = mCalcLen()(ENC, 0, CMSG_HASHED, &h, NULL, V_CONTENT_LEN);
    CHECKF(b && calc >= cb, "calc %lu actual %lu", (unsigned long)calc, (unsigned long)cb);
    t_note("hashed: CalculateEncodedLength=%lu actual=%lu", (unsigned long)calc, (unsigned long)cb);
    ml_free(b);
}

/* ---- decode of externally produced digestedData ---- */
typedef struct { const BYTE *der; DWORD n; const BYTE *dig; DWORD dn; const char *oid; } dvec_t;
static const dvec_t DV[] = {
    {M_DIGESTED_SHA256, M_DIGESTED_SHA256_LEN, V_SHA256, V_SHA256_LEN, OID_SHA256},
    {M_DIGESTED_SHA1, M_DIGESTED_SHA1_LEN, V_SHA1, V_SHA1_LEN, OID_SHA1},
};
TEST(mlh_decode_type_autodetect) {
    REQ_MSG();
    for (size_t i = 0; i < 2; i++) {
        HCRYPTMSG m = ml_decode(DV[i].der, DV[i].n, 0, 0);
        CHECKF(m != NULL, "vec %zu err 0x%lx", i, GetLastError());
        if (!m) continue;
        DWORD t = 0; CHECK(ml_param_dword(m, CMSG_TYPE_PARAM, 0, &t)); EXPECT_EQ(t, CMSG_HASHED);
        mClose()(m);
    }
}
TEST(mlh_decode_explicit_type_takes_bare_content) {
    REQ_MSG();
    /* with an explicit type the update data is the bare content, not a ContentInfo */
    for (size_t i = 0; i < 2; i++) {
        DWORD n = 0; const BYTE *bare = ml_unwrap(DV[i].der, DV[i].n, &n);
        CHECK(bare != NULL);
        if (!bare) continue;
        HCRYPTMSG m = mOpenDec()(ENC, 0, CMSG_HASHED, 0, NULL, NULL);
        CHECK(m != NULL);
        if (!m) continue;
        SET_ERR(0);
        CHECKF(mUpdate()(m, bare, n, TRUE), "vec %zu err 0x%lx", i, GetLastError());
        CHECK(mControl()(m, 0, CMSG_CTRL_VERIFY_HASH, NULL));
        mClose()(m);
    }
}
TEST(mlh_decode_explicit_type_rejects_contentinfo) {
    REQ_MSG();
    HCRYPTMSG m = mOpenDec()(ENC, 0, CMSG_HASHED, 0, NULL, NULL);
    if (!m) { CHECK(m != NULL); return; }
    SET_ERR(0);
    CHECK(!mUpdate()(m, M_DIGESTED_SHA256, M_DIGESTED_SHA256_LEN, TRUE));
    EXPECT_ERR(CRYPT_E_ASN1_BADTAG);
    mClose()(m);
}
TEST(mlh_decode_untyped_rejects_bare_content) {
    REQ_MSG();
    DWORD n = 0; const BYTE *bare = ml_unwrap(M_DIGESTED_SHA256, M_DIGESTED_SHA256_LEN, &n);
    CHECK(bare != NULL);
    if (!bare) return;
    HCRYPTMSG m = mOpenDec()(ENC, 0, 0, 0, NULL, NULL);
    if (!m) { CHECK(m != NULL); return; }
    SET_ERR(0);
    CHECK(!mUpdate()(m, bare, n, TRUE));
    EXPECT_ERR(CRYPT_E_ASN1_BADTAG);
    mClose()(m);
}
TEST(mlh_decode_params) {
    REQ_MSG();
    for (size_t i = 0; i < 2; i++) {
        HCRYPTMSG m = ml_decode(DV[i].der, DV[i].n, 0, 0);
        if (!m) { CHECK(m != NULL); continue; }
        DWORD cb = 0; BYTE *b;
        b = ml_param(m, CMSG_HASH_DATA_PARAM, 0, &cb);       /* the digest stored in the message */
        CHECK(b && cb == DV[i].dn && !memcmp(b, DV[i].dig, cb)); ml_free(b);
        b = ml_param(m, CMSG_CONTENT_PARAM, 0, &cb);
        CHECK(b && cb == V_CONTENT_LEN && !memcmp(b, V_CONTENT, cb)); ml_free(b);
        b = ml_param(m, CMSG_COMPUTED_HASH_PARAM, 0, &cb);
        CHECK(b && cb == DV[i].dn && !memcmp(b, DV[i].dig, cb)); ml_free(b);
        b = ml_param(m, CMSG_HASH_ALGORITHM_PARAM, 0, &cb);
        CHECK(b != NULL);
        if (b) { CRYPT_ALGORITHM_IDENTIFIER *a = (CRYPT_ALGORITHM_IDENTIFIER *)b; CHECK(a->pszObjId && !strcmp(a->pszObjId, DV[i].oid)); }
        ml_free(b);
        DWORD v = 99; if (ml_param_dword(m, CMSG_VERSION_PARAM, 0, &v)) EXPECT_EQ(v, 0);
        b = ml_param(m, CMSG_INNER_CONTENT_TYPE_PARAM, 0, &cb);
        CHECK(b && !strcmp((char *)b, OID_DATA)); ml_free(b);
        mClose()(m);
    }
}
TEST(mlh_decode_verify_hash) {
    REQ_MSG();
    for (size_t i = 0; i < 2; i++) {
        HCRYPTMSG m = ml_decode(DV[i].der, DV[i].n, 0, 0);
        if (!m) { CHECK(m != NULL); continue; }
        SET_ERR(0);
        CHECKF(mControl()(m, 0, CMSG_CTRL_VERIFY_HASH, NULL), "vec %zu err 0x%lx", i, GetLastError());
        mClose()(m);
    }
}
TEST(mlh_decode_tampered_digest_fails_verify) {
    REQ_MSG();
    for (size_t i = 0; i < 2; i++) {
        BYTE *copy = (BYTE *)LocalAlloc(LPTR, DV[i].n);
        memcpy(copy, DV[i].der, DV[i].n);
        const BYTE *p = ml_memmem(copy, DV[i].n, DV[i].dig, DV[i].dn);
        CHECK(p != NULL);
        if (!p) { LocalFree(copy); continue; }
        ((BYTE *)p)[3] ^= 0x01;
        HCRYPTMSG m = ml_decode(copy, DV[i].n, 0, 0);
        CHECK(m != NULL);
        if (m) {
            SET_ERR(0);
            CHECK(!mControl()(m, 0, CMSG_CTRL_VERIFY_HASH, NULL));
            EXPECT_ERR(CRYPT_E_HASH_VALUE);
            mClose()(m);
        }
        LocalFree(copy);
    }
}
TEST(mlh_decode_tampered_content_fails_verify) {
    REQ_MSG();
    BYTE *copy = (BYTE *)LocalAlloc(LPTR, M_DIGESTED_SHA256_LEN);
    memcpy(copy, M_DIGESTED_SHA256, M_DIGESTED_SHA256_LEN);
    const BYTE *p = ml_memmem(copy, M_DIGESTED_SHA256_LEN, V_CONTENT, V_CONTENT_LEN);
    CHECK(p != NULL);
    if (p) {
        ((BYTE *)p)[0] ^= 0x20;
        HCRYPTMSG m = ml_decode(copy, M_DIGESTED_SHA256_LEN, 0, 0);
        CHECK(m != NULL);
        if (m) { SET_ERR(0); CHECK(!mControl()(m, 0, CMSG_CTRL_VERIFY_HASH, NULL)); EXPECT_ERR(CRYPT_E_HASH_VALUE); mClose()(m); }
    }
    LocalFree(copy);
}
TEST(mlh_decode_verify_hash_wrong_type) {
    REQ_MSG();
    HCRYPTMSG m = ml_decode(M_SIGNED_ATTR, M_SIGNED_ATTR_LEN, 0, 0);
    if (!m) { CHECK(m != NULL); return; }
    SET_ERR(0);
    CHECK(!mControl()(m, 0, CMSG_CTRL_VERIFY_HASH, NULL));
    EXPECT_ERR(CRYPT_E_INVALID_MSG_TYPE);
    mClose()(m);
}
TEST(mlh_decode_nonfinal_update_needs_stream_info) {
    REQ_MSG();
    HCRYPTMSG m = mOpenDec()(ENC, 0, 0, 0, NULL, NULL);
    if (!m) { CHECK(m != NULL); return; }
    SET_ERR(0);
    CHECK(!mUpdate()(m, M_DIGESTED_SHA256, 10, FALSE));
    EXPECT_ERR(CRYPT_E_MSG_ERROR);
    /* the failed non-final update does not poison the message: a complete final update still works */
    CHECK(mUpdate()(m, M_DIGESTED_SHA256, M_DIGESTED_SHA256_LEN, TRUE));
    CHECK(mControl()(m, 0, CMSG_CTRL_VERIFY_HASH, NULL));
    mClose()(m);
}
TEST(mlh_decode_truncated_final_fails) {
    REQ_MSG();
    static const DWORD cut[] = {0, 1, 2, 3, 10, 40, 100, 116};
    for (size_t i = 0; i < sizeof cut / sizeof *cut; i++) {
        HCRYPTMSG m = mOpenDec()(ENC, 0, 0, 0, NULL, NULL);
        if (!m) { CHECK(m != NULL); continue; }
        SET_ERR(0);
        BOOL ok = mUpdate()(m, M_DIGESTED_SHA256, cut[i], TRUE);
        CHECKF(!ok, "cut at %lu", (unsigned long)cut[i]);
        if (!ok) t_note("hashed truncated to %lu bytes (final): err 0x%lx", (unsigned long)cut[i], (unsigned long)GetLastError());
        mClose()(m);
    }
}
TEST(mlh_decode_garbage_fails) {
    REQ_MSG();
    static const BYTE g1[] = {0x00,0x01,0x02,0x03,0x04,0x05};
    static const BYTE g2[] = {0x04,0x03,'a','b','c'};
    static const BYTE g3[] = {0x30,0x03,0x02,0x01,0x01};
    const struct { const BYTE *p; DWORD n; } g[] = {{g1, sizeof g1}, {g2, sizeof g2}, {g3, sizeof g3}};
    for (size_t i = 0; i < 3; i++) {
        HCRYPTMSG m = mOpenDec()(ENC, 0, 0, 0, NULL, NULL);
        if (!m) { CHECK(m != NULL); continue; }
        SET_ERR(0);
        CHECKF(!mUpdate()(m, g[i].p, g[i].n, TRUE), "garbage %zu", i);
        mClose()(m);
    }
}
TEST(mlh_decode_hashed_message_from_own_encoder_all_algs) {
    REQ_MSG();
    for (size_t i = 0; i < 3; i++) {
        DWORD cb = 0; BYTE *b = enc_hashed(HALGS[i].oid, 0, V_CONTENT, V_CONTENT_LEN, &cb);
        if (!b) { CHECK(b != NULL); continue; }
        HCRYPTMSG m = ml_decode(b, cb, 0, 0);
        CHECKF(m != NULL, "%s err 0x%lx", HALGS[i].name, GetLastError());
        if (m) {
            CHECK(mControl()(m, 0, CMSG_CTRL_VERIFY_HASH, NULL));
            DWORD n = 0; BYTE *h = ml_param(m, CMSG_COMPUTED_HASH_PARAM, 0, &n);
            CHECK(h && n == HALGS[i].cb && !memcmp(h, HALGS[i].dig, n)); ml_free(h);
            mClose()(m);
        }
        ml_free(b);
    }
}
TEST(mlh_getparam_size_protocol) {
    REQ_MSG();
    HCRYPTMSG m = ml_decode(M_DIGESTED_SHA256, M_DIGESTED_SHA256_LEN, 0, 0);
    if (!m) { CHECK(m != NULL); return; }
    BYTE buf[64]; DWORD n = 0;
    CHECK(mGetParam()(m, CMSG_COMPUTED_HASH_PARAM, 0, NULL, &n));
    EXPECT_EQ(n, V_SHA256_LEN);
    n = V_SHA256_LEN - 1; SET_ERR(0);
    CHECK(!mGetParam()(m, CMSG_COMPUTED_HASH_PARAM, 0, buf, &n));
    EXPECT_ERR(ERROR_MORE_DATA); EXPECT_EQ(n, V_SHA256_LEN);
    n = 0; SET_ERR(0);
    CHECK(!mGetParam()(m, CMSG_COMPUTED_HASH_PARAM, 0, buf, &n));
    EXPECT_ERR(ERROR_MORE_DATA); EXPECT_EQ(n, V_SHA256_LEN);
    n = sizeof buf;
    CHECK(mGetParam()(m, CMSG_COMPUTED_HASH_PARAM, 0, buf, &n));
    EXPECT_EQ(n, V_SHA256_LEN);
    mClose()(m);
}
TEST(mlh_decode_inapplicable_params) {
    REQ_MSG();
    HCRYPTMSG m = ml_decode(M_DIGESTED_SHA256, M_DIGESTED_SHA256_LEN, 0, 0);
    if (!m) { CHECK(m != NULL); return; }
    static const DWORD p[] = {CMSG_SIGNER_COUNT_PARAM, CMSG_SIGNER_INFO_PARAM, CMSG_RECIPIENT_COUNT_PARAM, CMSG_ENVELOPE_ALGORITHM_PARAM};
    for (size_t i = 0; i < sizeof p / sizeof *p; i++) {
        DWORD n = 0; SET_ERR(0);
        CHECKF(!mGetParam()(m, p[i], 0, NULL, &n), "param %lu", (unsigned long)p[i]);
        EXPECT_ERR(CRYPT_E_INVALID_MSG_TYPE);
    }
    mClose()(m);
}
TEST(mlh_decode_before_final_not_ready) {
    REQ_MSG();
    HCRYPTMSG m = mOpenDec()(ENC, 0, 0, 0, NULL, NULL);
    if (!m) { CHECK(m != NULL); return; }
    DWORD n = 0; SET_ERR(0);
    BOOL ok = mGetParam()(m, CMSG_TYPE_PARAM, 0, NULL, &n);
    t_note("GetParam(TYPE) on a decode message with no data: ok=%d err 0x%lx", ok, (unsigned long)GetLastError());
    CHECK(1);
    mClose()(m);
}
