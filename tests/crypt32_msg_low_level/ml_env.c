/* CMSG_ENVELOPED: encode, decode, CMSG_CTRL_DECRYPT / KEY_TRANS_DECRYPT / MAIL_LIST_DECRYPT. */
#include "ml.h"

typedef struct {
    HCRYPTPROV encprov;      /* provider for content encryption (AES capable) */
    HCRYPTPROV decprov;      /* provider holding recipient key 1 */
    PCCERT_CONTEXT cert;
    PCERT_INFO rcpt[2];
    CMSG_ENVELOPED_ENCODE_INFO ei;
} env_t;

static BOOL env_init(env_t *e, const char *alg) {
    memset(e, 0, sizeof *e);
    e->encprov = ml_prov(NULL, 0);
    e->decprov = ml_prov(V_KEY1, V_KEY1_LEN);
    e->cert = ml_cert(V_CERT1, V_CERT1_LEN);
    if (!e->encprov || !e->decprov || !e->cert) return FALSE;
    e->rcpt[0] = e->cert->pCertInfo;
    e->ei.cbSize = sizeof e->ei;
    e->ei.hCryptProv = e->encprov;
    e->ei.ContentEncryptionAlgorithm.pszObjId = (LPSTR)alg;
    e->ei.cRecipients = 1;
    e->ei.rgpRecipients = e->rcpt;
    return TRUE;
}
static void env_done(env_t *e) { ml_cert_free(e->cert); ml_prov_release(e->encprov); ml_prov_release(e->decprov); }
#define REQ_ENV(e, alg) env_t e; do { REQ_MSG(); if (!env_init(&(e), alg)) { env_done(&(e)); t_skip("cannot set up ephemeral recipient"); return; } } while (0)

static BYTE *env_encode(env_t *e, DWORD flags, const BYTE *d, DWORD n, DWORD *cb) {
    HCRYPTMSG m = mOpenEnc()(ENC, flags, CMSG_ENVELOPED, &e->ei, NULL, NULL);
    BYTE *r = NULL;
    if (!m) return NULL;
    if (mUpdate()(m, d, n, TRUE)) r = ml_param(m, CMSG_CONTENT_PARAM, 0, cb);
    mClose()(m);
    return r;
}
static BOOL decrypt(env_t *e, HCRYPTMSG m, DWORD idx) {
    CMSG_CTRL_DECRYPT_PARA p; memset(&p, 0, sizeof p);
    p.cbSize = sizeof p; p.hCryptProv = e->decprov; p.dwKeySpec = AT_KEYEXCHANGE; p.dwRecipientIndex = idx;
    return mControl()(m, 0, CMSG_CTRL_DECRYPT, &p);
}

/* ---------------------------------------------------------------- open validation */
TEST(mle_open_null_info) {
    REQ_MSG();
    if (t_is_wine()) { t_skip("emulator dereferences NULL info"); return; }
    SET_ERR(0);
    HCRYPTMSG m = mOpenEnc()(ENC, 0, CMSG_ENVELOPED, NULL, NULL, NULL);
    CHECK(m == NULL);
    EXPECT_ERR(E_INVALIDARG);
    if (m) mClose()(m);
}
TEST(mle_open_bad_cbsize) {
    REQ_ENV(e, OID_3DES);
    static const DWORD cbs[] = {0, 4, 8};
    for (size_t i = 0; i < 3; i++) {
        e.ei.cbSize = cbs[i]; SET_ERR(0);
        HCRYPTMSG m = mOpenEnc()(ENC, 0, CMSG_ENVELOPED, &e.ei, NULL, NULL);
        CHECKF(m == NULL, "cbSize %lu", (unsigned long)cbs[i]);
        if (m) mClose()(m); else EXPECT_ERR(E_INVALIDARG);
    }
    env_done(&e);
}
TEST(mle_open_unknown_cipher) {
    REQ_ENV(e, "1.2.3.4");
    SET_ERR(0);
    HCRYPTMSG m = mOpenEnc()(ENC, 0, CMSG_ENVELOPED, &e.ei, NULL, NULL);
    CHECK(m == NULL);
    EXPECT_ERR(CRYPT_E_UNKNOWN_ALGO);
    if (m) mClose()(m);
    env_done(&e);
}
TEST(mle_open_zero_recipients) {
    REQ_ENV(e, OID_3DES);
    e.ei.cRecipients = 0; SET_ERR(0);
    HCRYPTMSG m = mOpenEnc()(ENC, 0, CMSG_ENVELOPED, &e.ei, NULL, NULL);
    t_note("enveloped with zero recipients: %s err=0x%lx", m ? "opened" : "rejected", (unsigned long)GetLastError());
    CHECK(1);
    if (m) mClose()(m);
    env_done(&e);
}

/* ---------------------------------------------------------------- encode / decrypt round trips */
typedef struct { const char *oid; const char *name; } calg_t;
static const calg_t CALGS[] = {{OID_AES128, "aes128"}, {OID_AES256, "aes256"}, {OID_3DES, "3des"}, {"1.2.840.113549.3.2", "rc2"}, {"1.2.840.113549.3.4", "rc4"}};

TEST(mle_roundtrip_all_ciphers) {
    REQ_MSG();
    for (size_t i = 0; i < sizeof CALGS / sizeof *CALGS; i++) {
        env_t e;
        if (!env_init(&e, CALGS[i].oid)) { env_done(&e); t_skip("setup"); return; }
        SET_ERR(0);
        DWORD cb = 0; BYTE *b = env_encode(&e, 0, V_CONTENT, V_CONTENT_LEN, &cb);
        CHECKF(b != NULL, "%s encode err 0x%lx", CALGS[i].name, GetLastError());
        if (b) {
            CHECKF(ml_memmem(b, cb, V_CONTENT, 8) == NULL, "%s plaintext leaked", CALGS[i].name);
            HCRYPTMSG d = ml_decode(b, cb, 0, 0);
            CHECKF(d != NULL, "%s decode", CALGS[i].name);
            if (d) {
                DWORD t = 0; CHECK(ml_param_dword(d, CMSG_TYPE_PARAM, 0, &t)); EXPECT_EQ(t, CMSG_ENVELOPED);
                SET_ERR(0);
                CHECKF(decrypt(&e, d, 0), "%s decrypt err 0x%lx", CALGS[i].name, GetLastError());
                DWORD n = 0; BYTE *p = ml_param(d, CMSG_CONTENT_PARAM, 0, &n);
                CHECKF(p && n == V_CONTENT_LEN && !memcmp(p, V_CONTENT, n), "%s content (%lu)", CALGS[i].name, (unsigned long)n);
                ml_free(p);
                mClose()(d);
            }
            ml_free(b);
        }
        env_done(&e);
    }
}
TEST(mle_envelope_algorithm_param) {
    REQ_MSG();
    for (size_t i = 0; i < sizeof CALGS / sizeof *CALGS; i++) {
        env_t e;
        if (!env_init(&e, CALGS[i].oid)) { env_done(&e); t_skip("setup"); return; }
        DWORD cb = 0; BYTE *b = env_encode(&e, 0, V_CONTENT, V_CONTENT_LEN, &cb);
        HCRYPTMSG d = b ? ml_decode(b, cb, 0, 0) : NULL;
        CHECKF(d != NULL, "%s", CALGS[i].name);
        if (d) {
            DWORD n = 0; BYTE *a = ml_param(d, CMSG_ENVELOPE_ALGORITHM_PARAM, 0, &n);
            CHECKF(a && ((CRYPT_ALGORITHM_IDENTIFIER *)a)->pszObjId && !strcmp(((CRYPT_ALGORITHM_IDENTIFIER *)a)->pszObjId, CALGS[i].oid), "%s", CALGS[i].name);
            if (a && i < 2) CHECKF(((CRYPT_ALGORITHM_IDENTIFIER *)a)->Parameters.cbData == 18, "%s IV parameter is an OCTET STRING of the block size (got %lu)", CALGS[i].name, (unsigned long)((CRYPT_ALGORITHM_IDENTIFIER *)a)->Parameters.cbData);
            if (a && i == 2) CHECKF(((CRYPT_ALGORITHM_IDENTIFIER *)a)->Parameters.cbData == 10, "%s IV parameter (got %lu)", CALGS[i].name, (unsigned long)((CRYPT_ALGORITHM_IDENTIFIER *)a)->Parameters.cbData);
            ml_free(a);
            mClose()(d);
        }
        ml_free(b); env_done(&e);
    }
}
TEST(mle_encode_is_randomized) {
    REQ_ENV(e, OID_3DES);
    DWORD c1 = 0, c2 = 0; BYTE *a = env_encode(&e, 0, V_CONTENT, V_CONTENT_LEN, &c1), *b = env_encode(&e, 0, V_CONTENT, V_CONTENT_LEN, &c2);
    CHECK(a && b && c1 == c2 && memcmp(a, b, c1) != 0);   /* fresh session key and IV for every message */
    ml_free(a); ml_free(b); env_done(&e);
}
TEST(mle_encoded_structure) {
    REQ_ENV(e, OID_3DES);
    static const BYTE env_oid[] = {0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x07,0x03};
    static const BYTE data_oid[] = {0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x07,0x01};
    static const BYTE aes_oid[] = {0x06,0x08,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x03,0x07};
    DWORD cb = 0; BYTE *b = env_encode(&e, 0, V_CONTENT, V_CONTENT_LEN, &cb);
    CHECK(b != NULL);
    if (b) {
        CHECK(b[0] == 0x30);
        CHECK(ml_memmem(b, cb, env_oid, sizeof env_oid) != NULL);
        CHECK(ml_memmem(b, cb, data_oid, sizeof data_oid) != NULL);
        CHECK(ml_memmem(b, cb, aes_oid, sizeof aes_oid) != NULL);
        /* the encrypted content is the [0] IMPLICIT OCTET STRING: padded to the 8-byte DES block */
        ml_free(b);
    }
    env_done(&e);
}
TEST(mle_nonfinal_update_rejected) {
    REQ_ENV(e, OID_3DES);
    HCRYPTMSG m = mOpenEnc()(ENC, 0, CMSG_ENVELOPED, &e.ei, NULL, NULL);
    CHECK(m != NULL);
    if (m) {
        SET_ERR(0);
        CHECK(!mUpdate()(m, V_CONTENT, 5, FALSE));
        EXPECT_ERR(CRYPT_E_MSG_ERROR);
        mClose()(m);
    }
    env_done(&e);
}
TEST(mle_detached_nonfinal_chunks) {
    REQ_ENV(e, OID_3DES);
    HCRYPTMSG m = mOpenEnc()(ENC, CMSG_DETACHED_FLAG, CMSG_ENVELOPED, &e.ei, NULL, NULL);
    CHECK(m != NULL);
    if (m) {
        SET_ERR(0);
        BOOL a = mUpdate()(m, V_CONTENT, 5, FALSE);
        t_note("enveloped DETACHED non-final update: ok=%d err=0x%lx", a, (unsigned long)GetLastError());
        mClose()(m);
    }
    env_done(&e);
}
TEST(mle_empty_content_roundtrip) {
    REQ_ENV(e, OID_3DES);
    DWORD cb = 0; BYTE *b = env_encode(&e, 0, NULL, 0, &cb);
    CHECK(b != NULL);
    HCRYPTMSG d = b ? ml_decode(b, cb, 0, 0) : NULL;
    CHECK(d != NULL);
    if (d) {
        CHECK(decrypt(&e, d, 0));
        DWORD n = 77; BYTE *p = ml_param(d, CMSG_CONTENT_PARAM, 0, &n);
        t_note("empty enveloped content decrypts to %s (%lu bytes)", p ? "a buffer" : "failure", (unsigned long)n);
        CHECK(p == NULL || n == 0);
        ml_free(p); mClose()(d);
    }
    ml_free(b); env_done(&e);
}
TEST(mle_block_boundary_sizes) {
    REQ_ENV(e, OID_3DES);
    static const DWORD sz[] = {1, 7, 8, 9, 15, 16, 17, 1000};
    for (size_t i = 0; i < sizeof sz / sizeof *sz; i++) {
        BYTE *in = (BYTE *)LocalAlloc(LPTR, sz[i]);
        for (DWORD k = 0; k < sz[i]; k++) in[k] = (BYTE)(k * 7 + 1);
        DWORD cb = 0; BYTE *b = env_encode(&e, 0, in, sz[i], &cb);
        HCRYPTMSG d = b ? ml_decode(b, cb, 0, 0) : NULL;
        CHECKF(d != NULL, "size %lu", (unsigned long)sz[i]);
        if (d) {
            CHECK(decrypt(&e, d, 0));
            DWORD n = 0; BYTE *p = ml_param(d, CMSG_CONTENT_PARAM, 0, &n);
            CHECKF(p && n == sz[i] && !memcmp(p, in, n), "size %lu got %lu", (unsigned long)sz[i], (unsigned long)n);
            ml_free(p); mClose()(d);
        }
        ml_free(b); LocalFree(in);
    }
    env_done(&e);
}
TEST(mle_recipient_params) {
    REQ_ENV(e, OID_3DES);
    DWORD cb = 0; BYTE *b = env_encode(&e, 0, V_CONTENT, V_CONTENT_LEN, &cb);
    HCRYPTMSG d = b ? ml_decode(b, cb, 0, 0) : NULL;
    CHECK(d != NULL);
    if (d) {
        DWORD v = 99;
        CHECK(ml_param_dword(d, CMSG_RECIPIENT_COUNT_PARAM, 0, &v)); EXPECT_EQ(v, 1);
        CHECK(ml_param_dword(d, CMSG_CMS_RECIPIENT_COUNT_PARAM, 0, &v)); EXPECT_EQ(v, 1);
        CHECK(ml_param_dword(d, CMSG_VERSION_PARAM, 0, &v)); EXPECT_EQ(v, 0);
        DWORD n = 0; BYTE *r = ml_param(d, CMSG_RECIPIENT_INFO_PARAM, 0, &n);
        CHECK(r != NULL);
        if (r) {
            CERT_INFO *ci = (CERT_INFO *)r;
            CHECK(ci->Issuer.cbData == e.cert->pCertInfo->Issuer.cbData && !memcmp(ci->Issuer.pbData, e.cert->pCertInfo->Issuer.pbData, ci->Issuer.cbData));
            CHECK(ci->SerialNumber.cbData == e.cert->pCertInfo->SerialNumber.cbData && !memcmp(ci->SerialNumber.pbData, e.cert->pCertInfo->SerialNumber.pbData, ci->SerialNumber.cbData));
            CHECK(ci->SubjectPublicKeyInfo.Algorithm.pszObjId && !strcmp(ci->SubjectPublicKeyInfo.Algorithm.pszObjId, OID_RSA));
            CHECK(ci->SubjectPublicKeyInfo.PublicKey.cbData == 128);   /* the RSA-encrypted content key */
            ml_free(r);
        }
        r = ml_param(d, CMSG_CMS_RECIPIENT_INFO_PARAM, 0, &n);
        CHECK(r != NULL);
        if (r) {
            CMSG_CMS_RECIPIENT_INFO *ri = (CMSG_CMS_RECIPIENT_INFO *)r;
            EXPECT_EQ(ri->dwRecipientChoice, CMSG_KEY_TRANS_RECIPIENT);
            if (ri->dwRecipientChoice == CMSG_KEY_TRANS_RECIPIENT && ri->pKeyTrans) {
                EXPECT_EQ(ri->pKeyTrans->dwVersion, 0);
                EXPECT_EQ(ri->pKeyTrans->RecipientId.dwIdChoice, CERT_ID_ISSUER_SERIAL_NUMBER);
                CHECK(ri->pKeyTrans->KeyEncryptionAlgorithm.pszObjId && !strcmp(ri->pKeyTrans->KeyEncryptionAlgorithm.pszObjId, OID_RSA));
                CHECK(ri->pKeyTrans->EncryptedKey.cbData == 128);
            }
            ml_free(r);
        }
        SET_ERR(0);
        CHECK(!mGetParam()(d, CMSG_RECIPIENT_INFO_PARAM, 1, NULL, &n));
        EXPECT_ERR(CRYPT_E_INVALID_INDEX);
        SET_ERR(0);
        CHECK(!mGetParam()(d, CMSG_CMS_RECIPIENT_INFO_PARAM, 1, NULL, &n));
        EXPECT_ERR(CRYPT_E_INVALID_INDEX);
        mClose()(d);
    }
    ml_free(b); env_done(&e);
}
TEST(mle_inapplicable_params) {
    REQ_ENV(e, OID_3DES);
    DWORD cb = 0; BYTE *b = env_encode(&e, 0, V_CONTENT, V_CONTENT_LEN, &cb);
    HCRYPTMSG d = b ? ml_decode(b, cb, 0, 0) : NULL;
    CHECK(d != NULL);
    if (d) {
        static const DWORD p[] = {CMSG_SIGNER_COUNT_PARAM, CMSG_SIGNER_INFO_PARAM, CMSG_COMPUTED_HASH_PARAM, CMSG_HASH_DATA_PARAM};
        for (size_t i = 0; i < 4; i++) {
            DWORD n = 0; SET_ERR(0);
            CHECKF(!mGetParam()(d, p[i], 0, NULL, &n), "param %lu", (unsigned long)p[i]);
            EXPECT_ERR(CRYPT_E_INVALID_MSG_TYPE);
        }
        mClose()(d);
    }
    ml_free(b); env_done(&e);
}

/* ---------------------------------------------------------------- decrypt controls */
TEST(mle_decrypt_openssl_vectors) {
    REQ_MSG();
    struct { const char *n; const BYTE *d; DWORD len; const char *alg; } v[] = {
        {"aes128", M_ENV_AES128, M_ENV_AES128_LEN, OID_AES128}, {"aes256", M_ENV_AES256, M_ENV_AES256_LEN, OID_AES256}, {"3des", M_ENV_3DES, M_ENV_3DES_LEN, OID_3DES},
    };
    env_t e;
    if (!env_init(&e, OID_3DES)) { env_done(&e); t_skip("setup"); return; }
    for (size_t i = 0; i < 3; i++) {
        HCRYPTMSG m = ml_decode(v[i].d, v[i].len, 0, 0);
        CHECKF(m != NULL, "%s", v[i].n);
        if (!m) continue;
        DWORD t = 0; CHECK(ml_param_dword(m, CMSG_TYPE_PARAM, 0, &t)); EXPECT_EQ(t, CMSG_ENVELOPED);
        DWORD n = 0; BYTE *a = ml_param(m, CMSG_ENVELOPE_ALGORITHM_PARAM, 0, &n);
        CHECKF(a && !strcmp(((CRYPT_ALGORITHM_IDENTIFIER *)a)->pszObjId, v[i].alg), "%s alg", v[i].n);
        ml_free(a);
        SET_ERR(0);
        CHECKF(decrypt(&e, m, 0), "%s decrypt err 0x%lx", v[i].n, GetLastError());
        BYTE *p = ml_param(m, CMSG_CONTENT_PARAM, 0, &n);
        CHECKF(p && n == V_CONTENT_LEN && !memcmp(p, V_CONTENT, n), "%s content", v[i].n);
        ml_free(p);
        mClose()(m);
    }
    env_done(&e);
}
TEST(mle_decrypt_twice) {
    env_t e; REQ_MSG();
    if (!env_init(&e, OID_3DES)) { env_done(&e); t_skip("setup"); return; }
    HCRYPTMSG m = ml_decode(M_ENV_3DES, M_ENV_3DES_LEN, 0, 0);
    CHECK(m != NULL);
    if (m) {
        CHECK(decrypt(&e, m, 0));
        SET_ERR(0);
        CHECK(!decrypt(&e, m, 0));
        EXPECT_ERR(CRYPT_E_ALREADY_DECRYPTED);
        mClose()(m);
    }
    env_done(&e);
}
TEST(mle_decrypt_bad_parameters) {
    env_t e; REQ_MSG();
    if (!env_init(&e, OID_3DES)) { env_done(&e); t_skip("setup"); return; }
    HCRYPTMSG m = ml_decode(M_ENV_3DES, M_ENV_3DES_LEN, 0, 0);
    CHECK(m != NULL);
    if (m) {
        CMSG_CTRL_DECRYPT_PARA p; memset(&p, 0, sizeof p);
        p.cbSize = 4; p.hCryptProv = e.decprov; p.dwKeySpec = AT_KEYEXCHANGE;
        SET_ERR(0);
        CHECK(!mControl()(m, 0, CMSG_CTRL_DECRYPT, &p));
        EXPECT_ERR(E_INVALIDARG);
        p.cbSize = sizeof p; p.dwRecipientIndex = 5; SET_ERR(0);
        CHECK(!mControl()(m, 0, CMSG_CTRL_DECRYPT, &p));
        EXPECT_ERR(CRYPT_E_INVALID_INDEX);
        /* failed attempts leave the message undecrypted */
        CHECK(decrypt(&e, m, 0));
        mClose()(m);
    }
    env_done(&e);
}
TEST(mle_decrypt_wrong_message_types) {
    env_t e; REQ_MSG();
    if (!env_init(&e, OID_3DES)) { env_done(&e); t_skip("setup"); return; }
    const struct { const char *n; const BYTE *d; DWORD len; } v[] = {{"signed", M_SIGNED_NOATTR, M_SIGNED_NOATTR_LEN}, {"hashed", M_DIGESTED_SHA256, M_DIGESTED_SHA256_LEN}, {"data", M_DATA, M_DATA_LEN}};
    for (size_t i = 0; i < 3; i++) {
        HCRYPTMSG m = ml_decode(v[i].d, v[i].len, 0, 0);
        CHECKF(m != NULL, "%s", v[i].n);
        if (!m) continue;
        SET_ERR(0);
        CHECKF(!decrypt(&e, m, 0), "%s", v[i].n);
        EXPECT_ERR(CRYPT_E_INVALID_MSG_TYPE);
        mClose()(m);
    }
    env_done(&e);
}
TEST(mle_decrypt_without_data) {
    env_t e; REQ_MSG();
    if (!env_init(&e, OID_3DES)) { env_done(&e); t_skip("setup"); return; }
    HCRYPTMSG m = mOpenDec()(ENC, 0, 0, 0, NULL, NULL);
    CHECK(m != NULL);
    if (m) {
        SET_ERR(0);
        CHECK(!decrypt(&e, m, 0));
        EXPECT_ERR(CRYPT_E_INVALID_MSG_TYPE);   /* type still unknown */
        mClose()(m);
    }
    env_done(&e);
}
TEST(mle_decrypt_with_wrong_key) {
    env_t e; REQ_MSG();
    if (!env_init(&e, OID_3DES)) { env_done(&e); t_skip("setup"); return; }
    HCRYPTPROV other = ml_prov(V_KEY2, V_KEY2_LEN);
    HCRYPTMSG m = ml_decode(M_ENV_3DES, M_ENV_3DES_LEN, 0, 0);
    CHECK(m != NULL && other);
    if (m && other) {
        CMSG_CTRL_DECRYPT_PARA p; memset(&p, 0, sizeof p);
        p.cbSize = sizeof p; p.hCryptProv = other; p.dwKeySpec = AT_KEYEXCHANGE;
        SET_ERR(0);
        BOOL ok = mControl()(m, 0, CMSG_CTRL_DECRYPT, &p);
        t_note("decrypt with a different private key: ok=%d err=0x%lx", ok, (unsigned long)GetLastError());
        if (ok) { DWORD n = 0; BYTE *c = ml_param(m, CMSG_CONTENT_PARAM, 0, &n); CHECK(!(c && n == V_CONTENT_LEN && !memcmp(c, V_CONTENT, n))); ml_free(c); }
        else CHECK(1);
    }
    if (m) mClose()(m);
    ml_prov_release(other);
    env_done(&e);
}
TEST(mle_content_before_decrypt) {
    REQ_MSG();
    HCRYPTMSG m = ml_decode(M_ENV_AES128, M_ENV_AES128_LEN, 0, 0);
    CHECK(m != NULL);
    if (m) {
        DWORD n = 0; SET_ERR(0);
        BOOL ok = mGetParam()(m, CMSG_CONTENT_PARAM, 0, NULL, &n);
        t_note("enveloped CONTENT_PARAM before decrypt: ok=%d err=0x%lx", ok, (unsigned long)GetLastError());
        CHECK(1);
        mClose()(m);
    }
}
TEST(mle_key_trans_decrypt) {
    env_t e; REQ_MSG();
    if (!env_init(&e, OID_3DES)) { env_done(&e); t_skip("setup"); return; }
    HCRYPTMSG m = ml_decode(M_ENV_3DES, M_ENV_3DES_LEN, 0, 0);
    CHECK(m != NULL);
    if (m) {
        DWORD n = 0; BYTE *r = ml_param(m, CMSG_CMS_RECIPIENT_INFO_PARAM, 0, &n);
        CHECK(r != NULL);
        if (r) {
            CMSG_CMS_RECIPIENT_INFO *ri = (CMSG_CMS_RECIPIENT_INFO *)r;
            CMSG_CTRL_KEY_TRANS_DECRYPT_PARA p; memset(&p, 0, sizeof p);
            p.cbSize = sizeof p; p.hCryptProv = e.decprov; p.dwKeySpec = AT_KEYEXCHANGE; p.pKeyTrans = ri->pKeyTrans; p.dwRecipientIndex = 0;
            SET_ERR(0);
            CHECKF(mControl()(m, 0, CMSG_CTRL_KEY_TRANS_DECRYPT, &p), "err 0x%lx", GetLastError());
            BYTE *c = ml_param(m, CMSG_CONTENT_PARAM, 0, &n);
            CHECK(c && n == V_CONTENT_LEN && !memcmp(c, V_CONTENT, n));
            ml_free(c);
            SET_ERR(0);
            CHECK(!mControl()(m, 0, CMSG_CTRL_KEY_TRANS_DECRYPT, &p));
            EXPECT_ERR(CRYPT_E_ALREADY_DECRYPTED);
            ml_free(r);
        }
        mClose()(m);
    }
    env_done(&e);
}
TEST(mle_key_trans_decrypt_bad_cbsize) {
    env_t e; REQ_MSG();
    if (!env_init(&e, OID_3DES)) { env_done(&e); t_skip("setup"); return; }
    HCRYPTMSG m = ml_decode(M_ENV_3DES, M_ENV_3DES_LEN, 0, 0);
    CHECK(m != NULL);
    if (m) {
        CMSG_CTRL_KEY_TRANS_DECRYPT_PARA p; memset(&p, 0, sizeof p);
        p.cbSize = 4; p.hCryptProv = e.decprov; p.dwKeySpec = AT_KEYEXCHANGE;
        SET_ERR(0);
        CHECK(!mControl()(m, 0, CMSG_CTRL_KEY_TRANS_DECRYPT, &p));
        EXPECT_ERR(E_INVALIDARG);
        mClose()(m);
    }
    env_done(&e);
}
TEST(mle_key_trans_recipient_by_key_id) {
    env_t e; REQ_MSG();
    if (!env_init(&e, OID_3DES)) { env_done(&e); t_skip("setup"); return; }
    static BYTE kid[20] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20};
    CMSG_KEY_TRANS_RECIPIENT_ENCODE_INFO kt; memset(&kt, 0, sizeof kt);
    kt.cbSize = sizeof kt;
    kt.KeyEncryptionAlgorithm.pszObjId = OID_RSA;
    kt.RecipientPublicKey = e.cert->pCertInfo->SubjectPublicKeyInfo.PublicKey;
    kt.RecipientId.dwIdChoice = CERT_ID_KEY_IDENTIFIER;
    kt.RecipientId.KeyId.cbData = sizeof kid; kt.RecipientId.KeyId.pbData = kid;
    CMSG_RECIPIENT_ENCODE_INFO ri; memset(&ri, 0, sizeof ri);
    ri.dwRecipientChoice = CMSG_KEY_TRANS_RECIPIENT; ri.pKeyTrans = &kt;
    e.ei.rgpRecipients = NULL; e.ei.rgCmsRecipients = &ri; e.ei.cRecipients = 1;
    SET_ERR(0);
    DWORD cb = 0; BYTE *b = env_encode(&e, 0, V_CONTENT, V_CONTENT_LEN, &cb);
    CHECKF(b != NULL, "encode err 0x%lx", GetLastError());
    HCRYPTMSG d = b ? ml_decode(b, cb, 0, 0) : NULL;
    CHECK(d != NULL);
    if (d) {
        DWORD v = 0;
        if (ml_param_dword(d, CMSG_VERSION_PARAM, 0, &v)) t_note("enveloped with SKI recipient: message version %lu", (unsigned long)v);
        DWORD n = 0; BYTE *r = ml_param(d, CMSG_CMS_RECIPIENT_INFO_PARAM, 0, &n);
        CHECK(r != NULL);
        if (r) {
            CMSG_CMS_RECIPIENT_INFO *x = (CMSG_CMS_RECIPIENT_INFO *)r;
            EXPECT_EQ(x->dwRecipientChoice, CMSG_KEY_TRANS_RECIPIENT);
            if (x->pKeyTrans) {
                EXPECT_EQ(x->pKeyTrans->RecipientId.dwIdChoice, CERT_ID_KEY_IDENTIFIER);
                CHECK(x->pKeyTrans->RecipientId.KeyId.cbData == sizeof kid && !memcmp(x->pKeyTrans->RecipientId.KeyId.pbData, kid, sizeof kid));
                EXPECT_EQ(x->pKeyTrans->dwVersion, 2);
                CMSG_CTRL_KEY_TRANS_DECRYPT_PARA p; memset(&p, 0, sizeof p);
                p.cbSize = sizeof p; p.hCryptProv = e.decprov; p.dwKeySpec = AT_KEYEXCHANGE; p.pKeyTrans = x->pKeyTrans;
                SET_ERR(0);
                CHECKF(mControl()(d, 0, CMSG_CTRL_KEY_TRANS_DECRYPT, &p), "err 0x%lx", GetLastError());
                BYTE *c = ml_param(d, CMSG_CONTENT_PARAM, 0, &n);
                CHECK(c && n == V_CONTENT_LEN && !memcmp(c, V_CONTENT, n)); ml_free(c);
            }
            ml_free(r);
        }
        mClose()(d);
    }
    ml_free(b); env_done(&e);
}
TEST(mle_two_recipients_same_cert) {
    env_t e; REQ_MSG();
    if (!env_init(&e, OID_3DES)) { env_done(&e); t_skip("setup"); return; }
    PCCERT_CONTEXT c2 = ml_cert(V_CERT2, V_CERT2_LEN);
    HCRYPTPROV p2 = ml_prov(V_KEY2, V_KEY2_LEN);
    CHECK(c2 && p2);
    if (c2 && p2) {
        e.rcpt[1] = c2->pCertInfo; e.ei.cRecipients = 2;
        DWORD cb = 0; BYTE *b = env_encode(&e, 0, V_CONTENT, V_CONTENT_LEN, &cb);
        HCRYPTMSG d = b ? ml_decode(b, cb, 0, 0) : NULL;
        CHECKF(d != NULL, "err 0x%lx", GetLastError());
        if (d) {
            DWORD v = 0; CHECK(ml_param_dword(d, CMSG_RECIPIENT_COUNT_PARAM, 0, &v)); EXPECT_EQ(v, 2);
            /* recipient 1 is decryptable with key 2 only */
            CMSG_CTRL_DECRYPT_PARA p; memset(&p, 0, sizeof p);
            p.cbSize = sizeof p; p.hCryptProv = p2; p.dwKeySpec = AT_KEYEXCHANGE; p.dwRecipientIndex = 1;
            SET_ERR(0);
            CHECKF(mControl()(d, 0, CMSG_CTRL_DECRYPT, &p), "err 0x%lx", GetLastError());
            DWORD n = 0; BYTE *c = ml_param(d, CMSG_CONTENT_PARAM, 0, &n);
            CHECK(c && n == V_CONTENT_LEN && !memcmp(c, V_CONTENT, n)); ml_free(c);
            mClose()(d);
        }
        ml_free(b);
    }
    ml_cert_free(c2); ml_prov_release(p2);
    env_done(&e);
}
TEST(mle_truncated_final_fails) {
    REQ_MSG();
    static const DWORD cut[] = {0, 1, 20, 100, 200, 329};
    for (size_t i = 0; i < sizeof cut / sizeof *cut; i++) {
        HCRYPTMSG m = mOpenDec()(ENC, 0, 0, 0, NULL, NULL);
        if (!m) { CHECK(m != NULL); continue; }
        SET_ERR(0);
        CHECKF(!mUpdate()(m, M_ENV_AES128, cut[i], TRUE), "cut %lu", (unsigned long)cut[i]);
        mClose()(m);
    }
}

/* ---------------------------------------------------------------- mail-list recipients */
TEST(mle_mail_list_roundtrip) {
    REQ_MSG();
    HCRYPTPROV prov = ml_prov(NULL, 0);
    REQUIRE(prov);
    HCRYPTKEY kek = 0;
    if (!U(CryptGenKey)(prov, CALG_3DES, CRYPT_EXPORTABLE, &kek)) { t_note("cannot create a 3DES key-encryption key: 0x%lx", GetLastError()); ml_prov_release(prov); return; }
    static BYTE kid[4] = {9,8,7,6};
    CMSG_MAIL_LIST_RECIPIENT_ENCODE_INFO ml; memset(&ml, 0, sizeof ml);
    ml.cbSize = sizeof ml; ml.KeyEncryptionAlgorithm.pszObjId = "1.2.840.113549.1.9.16.3.6";
    ml.hCryptProv = prov; ml.dwKeyChoice = CMSG_MAIL_LIST_HANDLE_KEY_CHOICE; ml.hKeyEncryptionKey = kek;
    ml.KeyId.cbData = sizeof kid; ml.KeyId.pbData = kid;
    CMSG_RECIPIENT_ENCODE_INFO ri; memset(&ri, 0, sizeof ri);
    ri.dwRecipientChoice = CMSG_MAIL_LIST_RECIPIENT; ri.pMailList = &ml;
    CMSG_ENVELOPED_ENCODE_INFO ei; memset(&ei, 0, sizeof ei);
    ei.cbSize = sizeof ei; ei.hCryptProv = prov; ei.ContentEncryptionAlgorithm.pszObjId = OID_3DES;
    ei.cRecipients = 1; ei.rgCmsRecipients = &ri;
    SET_ERR(0);
    HCRYPTMSG m = mOpenEnc()(ENC, 0, CMSG_ENVELOPED, &ei, NULL, NULL);
    if (!m) { t_note("mail-list envelope open failed: 0x%lx", GetLastError()); U(CryptDestroyKey)(kek); ml_prov_release(prov); return; }
    CHECK(mUpdate()(m, V_CONTENT, V_CONTENT_LEN, TRUE));
    DWORD cb = 0; BYTE *b = ml_param(m, CMSG_CONTENT_PARAM, 0, &cb);
    CHECK(b != NULL);
    HCRYPTMSG d = b ? ml_decode(b, cb, 0, 0) : NULL;
    CHECK(d != NULL);
    if (d) {
        DWORD n = 0; BYTE *r = ml_param(d, CMSG_CMS_RECIPIENT_INFO_PARAM, 0, &n);
        CHECK(r != NULL);
        if (r) {
            CMSG_CMS_RECIPIENT_INFO *x = (CMSG_CMS_RECIPIENT_INFO *)r;
            EXPECT_EQ(x->dwRecipientChoice, CMSG_MAIL_LIST_RECIPIENT);
            if (x->dwRecipientChoice == CMSG_MAIL_LIST_RECIPIENT && x->pMailList) {
                CHECK(x->pMailList->KeyId.cbData == sizeof kid && !memcmp(x->pMailList->KeyId.pbData, kid, sizeof kid));
                CMSG_CTRL_MAIL_LIST_DECRYPT_PARA p; memset(&p, 0, sizeof p);
                p.cbSize = sizeof p; p.hCryptProv = prov; p.pMailList = x->pMailList; p.dwKeyChoice = CMSG_MAIL_LIST_HANDLE_KEY_CHOICE; p.hKeyEncryptionKey = kek;
                SET_ERR(0);
                BOOL ok = mControl()(d, 0, CMSG_CTRL_MAIL_LIST_DECRYPT, &p);
                CHECKF(ok, "err 0x%lx", GetLastError());
                if (ok) { BYTE *c = ml_param(d, CMSG_CONTENT_PARAM, 0, &n); CHECK(c && n == V_CONTENT_LEN && !memcmp(c, V_CONTENT, n)); ml_free(c); }
            }
            ml_free(r);
        }
        mClose()(d);
    }
    ml_free(b); mClose()(m);
    U(CryptDestroyKey)(kek); ml_prov_release(prov);
}
