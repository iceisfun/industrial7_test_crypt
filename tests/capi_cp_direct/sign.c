#include "cp.h"
#include "rsa_vectors.h"
/* CPSignHash / CPVerifySignature on rsaenh (deterministic PKCS#1 v1.5 vectors) and on dssenh (DSA). */

static int hx(const char *s, BYTE *out) {
    int n = 0;
    while (s[0] && s[1]) { unsigned v; char t[3] = { s[0], s[1], 0 }; sscanf(t, "%x", &v); out[n++] = (BYTE)v; s += 2; }
    return n;
}
static ULONG_PTR priv_ctx(const cpf *f, ULONG_PTR p) {
    ULONG_PTR k = 0;
    if (!f->ImportKey(p, rsa_priv_blob, sizeof rsa_priv_blob, 0, 0, &k)) return 0;
    return k;
}
static ULONG_PTR abc_hash(const cpf *f, ULONG_PTR p, ALG_ID alg) {
    ULONG_PTR h = cp_mkhash(f, p, alg);
    if (h) f->HashData(p, h, cp_abc, 3, 0);
    return h;
}

/* ---- RSA signatures: known answers ------------------------------------------------------ */
TEST(cpd_sign_rsa_sha1_known_answer) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR k = priv_ctx(&R, p); REQUIRE(k);
    ULONG_PTR h = abc_hash(&R, p, CALG_SHA1); REQUIRE(h);
    BYTE sig[128]; DWORD n = sizeof sig;
    OKAY(R.SignHash(p, h, AT_KEYEXCHANGE, NULL, 0, sig, &n));
    EXPECT_EQ(n, 128);
    if (n == 128) SAMEBYTES(sig, rsa_sig_sha1_abc, 128);
    R.DestroyHash(p, h); R.DestroyKey(p, k);
    cp_rel(&R, p);
}
TEST(cpd_sign_rsa_md5_known_answer) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR k = priv_ctx(&R, p); REQUIRE(k);
    ULONG_PTR h = abc_hash(&R, p, CALG_MD5); REQUIRE(h);
    BYTE sig[128]; DWORD n = sizeof sig;
    OKAY(R.SignHash(p, h, AT_KEYEXCHANGE, NULL, 0, sig, &n));
    EXPECT_EQ(n, 128);
    if (n == 128) SAMEBYTES(sig, rsa_sig_md5_abc, 128);
    R.DestroyHash(p, h); R.DestroyKey(p, k);
    cp_rel(&R, p);
}
TEST(cpd_sign_rsa_sha256_known_answer) {
    NEED_RSA(); ULONG_PTR p = rsa_aes(&R); REQUIRE(p);
    ULONG_PTR k = priv_ctx(&R, p); REQUIRE(k);
    ULONG_PTR h = abc_hash(&R, p, CALG_SHA_256); REQUIRE(h);
    BYTE sig[128]; DWORD n = sizeof sig;
    OKAY(R.SignHash(p, h, AT_KEYEXCHANGE, NULL, 0, sig, &n));
    EXPECT_EQ(n, 128);
    if (n == 128) SAMEBYTES(sig, rsa_sig_sha256_abc, 128);
    R.DestroyHash(p, h); R.DestroyKey(p, k);
    cp_rel(&R, p);
}
TEST(cpd_sign_rsa_nohashoid_known_answer) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR k = priv_ctx(&R, p); REQUIRE(k);
    ULONG_PTR h = abc_hash(&R, p, CALG_SHA1); REQUIRE(h);
    BYTE sig[128]; DWORD n = sizeof sig;
    OKAY(R.SignHash(p, h, AT_KEYEXCHANGE, NULL, CRYPT_NOHASHOID, sig, &n));
    EXPECT_EQ(n, 128);
    if (n == 128) SAMEBYTES(sig, rsa_sig_sha1_abc_nooid, 128);
    R.DestroyHash(p, h); R.DestroyKey(p, k);
    cp_rel(&R, p);
}
TEST(cpd_sign_rsa_signature_is_deterministic) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR k = 0;
    OKAY(R.GenKey(p, AT_SIGNATURE, 512u << 16, &k)); REQUIRE(k);
    BYTE s1[64], s2[64]; DWORD n1 = 64, n2 = 64;
    ULONG_PTR h1 = abc_hash(&R, p, CALG_SHA1), h2 = abc_hash(&R, p, CALG_SHA1); REQUIRE(h1 && h2);
    OKAY(R.SignHash(p, h1, AT_SIGNATURE, NULL, 0, s1, &n1));
    OKAY(R.SignHash(p, h2, AT_SIGNATURE, NULL, 0, s2, &n2));
    EXPECT_EQ(n1, 64); EXPECT_EQ(n2, 64);
    SAMEBYTES(s1, s2, 64);
    R.DestroyHash(p, h1); R.DestroyHash(p, h2); R.DestroyKey(p, k);
    cp_rel(&R, p);
}
TEST(cpd_sign_signature_size_is_modulus_size) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    DWORD bits[] = { 384, 512, 768 };
    for (size_t i = 0; i < NELEM(bits); i++) {
        ULONG_PTR k = 0;
        OKAY(R.GenKey(p, AT_SIGNATURE, bits[i] << 16, &k)); if (!k) continue;
        ULONG_PTR h = abc_hash(&R, p, CALG_MD5);
        DWORD n = 0;
        OKAY(R.SignHash(p, h, AT_SIGNATURE, NULL, 0, NULL, &n));
        EXPECT_EQ(n, bits[i] / 8);
        R.DestroyHash(p, h); R.DestroyKey(p, k);
    }
    cp_rel(&R, p);
}

/* ---- sign: protocol and validation ------------------------------------------------------- */
TEST(cpd_sign_buffer_protocol) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR k = priv_ctx(&R, p); REQUIRE(k);
    ULONG_PTR h = abc_hash(&R, p, CALG_SHA1); REQUIRE(h);
    BYTE sig[256]; DWORD n = 0;
    OKAY(R.SignHash(p, h, AT_KEYEXCHANGE, NULL, 0, NULL, &n));
    EXPECT_EQ(n, 128);
    n = 127;
    FAILS(R.SignHash(p, h, AT_KEYEXCHANGE, NULL, 0, sig, &n), ERROR_MORE_DATA);
    EXPECT_EQ(n, 128);
    n = 0;
    FAILS(R.SignHash(p, h, AT_KEYEXCHANGE, NULL, 0, sig, &n), ERROR_MORE_DATA);
    EXPECT_EQ(n, 128);
    /* the failed calls must not have finished the hash */
    OKAY(R.HashData(p, h, (const BYTE *)"", 0, 0));
    n = sizeof sig;
    OKAY(R.SignHash(p, h, AT_KEYEXCHANGE, NULL, 0, sig, &n));
    EXPECT_EQ(n, 128);
    SAMEBYTES(sig, rsa_sig_sha1_abc, 128);
    R.DestroyHash(p, h); R.DestroyKey(p, k);
    cp_rel(&R, p);
}
TEST(cpd_sign_finishes_the_hash) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR k = priv_ctx(&R, p); REQUIRE(k);
    ULONG_PTR h = abc_hash(&R, p, CALG_SHA1); REQUIRE(h);
    BYTE sig[128]; DWORD n = sizeof sig;
    OKAY(R.SignHash(p, h, AT_KEYEXCHANGE, NULL, 0, sig, &n));
    FAILS(R.HashData(p, h, (const BYTE *)"x", 1, 0), CPE_BAD_HASH_STATE);
    n = sizeof sig;
    OKAY(R.SignHash(p, h, AT_KEYEXCHANGE, NULL, 0, sig, &n));
    SAMEBYTES(sig, rsa_sig_sha1_abc, 128);
    R.DestroyHash(p, h); R.DestroyKey(p, k);
    cp_rel(&R, p);
}
TEST(cpd_sign_flags) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR k = priv_ctx(&R, p); REQUIRE(k);
    ULONG_PTR h = abc_hash(&R, p, CALG_SHA1); REQUIRE(h);
    BYTE sig[128]; DWORD n;
    DWORD bad[] = { 0x2, 0x8, 0x10, 0x20, 0x100, 0x8000, 0x80000000, 0x3 };
    for (size_t i = 0; i < NELEM(bad); i++) { n = sizeof sig; FAILS(R.SignHash(p, h, AT_KEYEXCHANGE, NULL, bad[i], sig, &n), CPE_BAD_FLAGS); }
    n = sizeof sig;
    FAILS(R.SignHash(0, 0, AT_KEYEXCHANGE, NULL, 2, sig, &n), CPE_BAD_FLAGS);
    R.DestroyHash(p, h); R.DestroyKey(p, k);
    cp_rel(&R, p);
}
TEST(cpd_sign_no_key_in_context) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR h = abc_hash(&R, p, CALG_SHA1); REQUIRE(h);
    BYTE sig[128]; DWORD n = sizeof sig;
    FAILS(R.SignHash(p, h, AT_KEYEXCHANGE, NULL, 0, sig, &n), CPE_BAD_KEYSET);
    n = sizeof sig;
    FAILS(R.SignHash(p, h, AT_SIGNATURE, NULL, 0, sig, &n), CPE_BAD_KEYSET);
    n = 0;
    FAILS(R.SignHash(p, h, AT_SIGNATURE, NULL, 0, NULL, &n), CPE_BAD_KEYSET);
    R.DestroyHash(p, h);
    cp_rel(&R, p);
}
TEST(cpd_sign_bad_keyspec) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR k = priv_ctx(&R, p); REQUIRE(k);
    ULONG_PTR h = abc_hash(&R, p, CALG_SHA1); REQUIRE(h);
    BYTE sig[128]; DWORD n;
    DWORD bad[] = { 0, 3, 4, 0xa400, 0x2400, 0xffffffff };
    for (size_t i = 0; i < NELEM(bad); i++) { n = sizeof sig; FAILS(R.SignHash(p, h, bad[i], NULL, 0, sig, &n), CPE_BAD_ALGID); }
    R.DestroyHash(p, h); R.DestroyKey(p, k);
    cp_rel(&R, p);
}
TEST(cpd_sign_signature_keyspec_with_only_keyx_key) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR k = priv_ctx(&R, p); REQUIRE(k);   /* AT_KEYEXCHANGE key only */
    ULONG_PTR h = abc_hash(&R, p, CALG_SHA1); REQUIRE(h);
    BYTE sig[128]; DWORD n = sizeof sig;
    FAILS(R.SignHash(p, h, AT_SIGNATURE, NULL, 0, sig, &n), CPE_BAD_KEYSET);
    R.DestroyHash(p, h); R.DestroyKey(p, k);
    cp_rel(&R, p);
}
TEST(cpd_sign_wrong_handle_kinds) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R), p2 = rsa_enh(&R); REQUIRE(p && p2);
    ULONG_PTR k = priv_ctx(&R, p); REQUIRE(k);
    ULONG_PTR h = abc_hash(&R, p, CALG_SHA1); REQUIRE(h);
    BYTE sig[128]; DWORD n = sizeof sig;
    FAILS(R.SignHash(k, h, AT_KEYEXCHANGE, NULL, 0, sig, &n), CPE_BAD_UID);
    n = sizeof sig;
    FAILS(R.SignHash(h, h, AT_KEYEXCHANGE, NULL, 0, sig, &n), CPE_BAD_UID);
    n = sizeof sig;
    SET_ERR(0);
    FAILS(R.SignHash(p, k, AT_KEYEXCHANGE, NULL, 0, sig, &n), CPE_FAIL);
    n = sizeof sig;
    SET_ERR(0);
    FAILS(R.SignHash(p2, h, AT_KEYEXCHANGE, NULL, 0, sig, &n), CPE_BAD_KEYSET);
    R.DestroyHash(p, h); R.DestroyKey(p, k);
    cp_rel(&R, p); cp_rel(&R, p2);
}
TEST(cpd_sign_unsupported_hash_algorithms) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR k = priv_ctx(&R, p); REQUIRE(k);
    BYTE key[16]; memset(key, 3, 16);
    ULONG_PTR hk = cp_hkey(&R, p, key, 16); REQUIRE(hk);
    ULONG_PTR h = 0;
    OKAY(R.CreateHash(p, CALG_HMAC, hk, 0, &h));
    if (h) {
        HMAC_INFO hi; memset(&hi, 0, sizeof hi); hi.HashAlgid = CALG_SHA1;
        R.SetHashParam(p, h, HP_HMAC_INFO, (BYTE *)&hi, 0);
        R.HashData(p, h, cp_abc, 3, 0);
        BYTE sig[128]; DWORD n = sizeof sig;
        FAILS(R.SignHash(p, h, AT_KEYEXCHANGE, NULL, 0, sig, &n), CPE_BAD_ALGID);
        R.DestroyHash(p, h);
    }
    R.DestroyKey(p, hk); R.DestroyKey(p, k);
    cp_rel(&R, p);
}
TEST(cpd_sign_ssl3_shamd5_requires_data) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR k = priv_ctx(&R, p); REQUIRE(k);
    ULONG_PTR h = cp_mkhash(&R, p, CALG_SSL3_SHAMD5); REQUIRE(h);
    BYTE sig[128]; DWORD n = sizeof sig;
    FAILS(R.SignHash(p, h, AT_KEYEXCHANGE, NULL, 0, sig, &n), CPE_BAD_HASH_STATE);
    /* a SHAMD5 hash is not fed through HashData; its 36-byte value is set with HP_HASHVAL */
    FAILS(R.HashData(p, h, cp_abc, 3, 0), ERROR_INVALID_HANDLE);
    n = sizeof sig;
    FAILS(R.SignHash(p, h, AT_KEYEXCHANGE, NULL, 0, sig, &n), CPE_BAD_HASH_STATE);
    BYTE v36[36]; memset(v36, 0x5a, sizeof v36);
    OKAY(R.SetHashParam(p, h, HP_HASHVAL, v36, 0));
    n = sizeof sig;
    OKAY(R.SignHash(p, h, AT_KEYEXCHANGE, NULL, 0, sig, &n));
    EXPECT_EQ(n, 128);
    R.DestroyHash(p, h); R.DestroyKey(p, k);
    cp_rel(&R, p);
}

/* ---- verify ------------------------------------------------------------------------------ */
static ULONG_PTR pub_ctx(const cpf *f, ULONG_PTR p) {
    ULONG_PTR k = 0;
    if (!f->ImportKey(p, rsa_pub_blob, sizeof rsa_pub_blob, 0, 0, &k)) return 0;
    return k;
}
TEST(cpd_verify_rsa_known_answers) {
    NEED_RSA(); ULONG_PTR p = rsa_aes(&R); REQUIRE(p);
    ULONG_PTR pub = pub_ctx(&R, p); REQUIRE(pub);
    struct { ALG_ID a; const BYTE *sig; DWORD flags; } t[] = {
        { CALG_SHA1, rsa_sig_sha1_abc, 0 }, { CALG_MD5, rsa_sig_md5_abc, 0 }, { CALG_SHA_256, rsa_sig_sha256_abc, 0 },
        { CALG_SHA1, rsa_sig_sha1_abc_nooid, CRYPT_NOHASHOID } };
    for (size_t i = 0; i < NELEM(t); i++) {
        ULONG_PTR h = abc_hash(&R, p, t[i].a);
        SET_ERR(0);
        BOOL r = R.VerifySignature(p, h, t[i].sig, 128, pub, NULL, t[i].flags);
        CHECKF(r, "vector %zu err=0x%lx", i, GetLastError());
        R.DestroyHash(p, h);
    }
    R.DestroyKey(p, pub);
    cp_rel(&R, p);
}
TEST(cpd_verify_rsa_rejects_modified_inputs) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR pub = pub_ctx(&R, p); REQUIRE(pub);
    BYTE sig[128];
    for (int pos = 0; pos < 128; pos += 13) {
        memcpy(sig, rsa_sig_sha1_abc, 128); sig[pos] ^= 0x01;
        ULONG_PTR h = abc_hash(&R, p, CALG_SHA1);
        FAILS(R.VerifySignature(p, h, sig, 128, pub, NULL, 0), CPE_BAD_SIGNATURE);
        R.DestroyHash(p, h);
    }
    /* other data */
    ULONG_PTR h = cp_mkhash(&R, p, CALG_SHA1);
    R.HashData(p, h, (const BYTE *)"abd", 3, 0);
    FAILS(R.VerifySignature(p, h, rsa_sig_sha1_abc, 128, pub, NULL, 0), CPE_BAD_SIGNATURE);
    R.DestroyHash(p, h);
    /* different hash algorithm than the one that was signed */
    h = abc_hash(&R, p, CALG_MD5);
    FAILS(R.VerifySignature(p, h, rsa_sig_sha1_abc, 128, pub, NULL, 0), CPE_BAD_SIGNATURE);
    R.DestroyHash(p, h);
    /* signature made with the OID verified without the NOHASHOID flag and vice versa */
    h = abc_hash(&R, p, CALG_SHA1);
    FAILS(R.VerifySignature(p, h, rsa_sig_sha1_abc, 128, pub, NULL, CRYPT_NOHASHOID), CPE_BAD_SIGNATURE);
    R.DestroyHash(p, h);
    h = abc_hash(&R, p, CALG_SHA1);
    OKAY(R.VerifySignature(p, h, rsa_sig_sha1_abc_nooid, 128, pub, NULL, 0));   /* the OID-less form is also accepted without the flag */
    R.DestroyHash(p, h);
    R.DestroyKey(p, pub);
    cp_rel(&R, p);
}
TEST(cpd_verify_rsa_byte_order_matters) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR pub = pub_ctx(&R, p); REQUIRE(pub);
    BYTE rev[128]; for (int i = 0; i < 128; i++) rev[i] = rsa_sig_sha1_abc[127 - i];
    ULONG_PTR h = abc_hash(&R, p, CALG_SHA1);
    FAILS(R.VerifySignature(p, h, rev, 128, pub, NULL, 0), CPE_BAD_SIGNATURE);
    R.DestroyHash(p, h); R.DestroyKey(p, pub);
    cp_rel(&R, p);
}
TEST(cpd_verify_rsa_wrong_signature_length) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR pub = pub_ctx(&R, p); REQUIRE(pub);
    BYTE big[300]; memset(big, 0, sizeof big); memcpy(big, rsa_sig_sha1_abc, 128);
    DWORD lens[] = { 0, 1, 64, 127, 129, 256 };
    for (size_t i = 0; i < NELEM(lens); i++) {
        ULONG_PTR h = abc_hash(&R, p, CALG_SHA1);
        FAILS(R.VerifySignature(p, h, big, lens[i], pub, NULL, 0), CPE_BAD_SIGNATURE);
        R.DestroyHash(p, h);
    }
    cp_rel(&R, p);
}
TEST(cpd_verify_flags_checked_first) {
    NEED_RSA();
    DWORD bad[] = { 0x2, 0x8, 0x10, 0x20, 0x80, 0x100, 0x8000, 0x80000000 };
    for (size_t i = 0; i < NELEM(bad); i++) FAILS(R.VerifySignature(0, 0, rsa_sig_sha1_abc, 128, 0, NULL, bad[i]), CPE_BAD_FLAGS);
}
TEST(cpd_verify_wrong_handle_kinds) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R), p2 = rsa_enh(&R); REQUIRE(p && p2);
    ULONG_PTR pub = pub_ctx(&R, p); REQUIRE(pub);
    ULONG_PTR h = abc_hash(&R, p, CALG_SHA1);
    ULONG_PTR sk = 0; OKAY(R.GenKey(p, CALG_RC4, 0, &sk));
    FAILS(R.VerifySignature(pub, h, rsa_sig_sha1_abc, 128, pub, NULL, 0), CPE_BAD_UID);
    FAILS(R.VerifySignature(p, pub, rsa_sig_sha1_abc, 128, pub, NULL, 0), CPE_BAD_HASH);
    FAILS(R.VerifySignature(p2, h, rsa_sig_sha1_abc, 128, pub, NULL, 0), CPE_BAD_UID);
    if (sk) FAILS(R.VerifySignature(p, h, rsa_sig_sha1_abc, 128, sk, NULL, 0), CPE_BAD_KEY);
    FAILS(R.VerifySignature(p, h, rsa_sig_sha1_abc, 128, h, NULL, 0), CPE_BAD_KEY);
    FAILS(R.VerifySignature(p, h, rsa_sig_sha1_abc, 128, p, NULL, 0), CPE_BAD_KEY);
    if (sk) R.DestroyKey(p, sk);
    R.DestroyHash(p, h); R.DestroyKey(p, pub);
    cp_rel(&R, p); cp_rel(&R, p2);
}
TEST(cpd_verify_does_not_require_the_private_half) {
    NEED_RSA(); ULONG_PTR a = rsa_enh(&R), b = rsa_enh(&R); REQUIRE(a && b);
    ULONG_PTR k = 0; OKAY(R.GenKey(a, AT_SIGNATURE, (512u << 16) | CRYPT_EXPORTABLE, &k)); REQUIRE(k);
    ULONG_PTR h = abc_hash(&R, a, CALG_SHA1);
    BYTE sig[64]; DWORD n = sizeof sig;
    OKAY(R.SignHash(a, h, AT_SIGNATURE, NULL, 0, sig, &n));
    BYTE pubblob[200]; DWORD pn = sizeof pubblob;
    OKAY(R.ExportKey(a, k, 0, PUBLICKEYBLOB, 0, pubblob, &pn));
    ULONG_PTR pub = 0;
    OKAY(R.ImportKey(b, pubblob, pn, 0, 0, &pub)); REQUIRE(pub);
    ULONG_PTR hb = abc_hash(&R, b, CALG_SHA1);
    OKAY(R.VerifySignature(b, hb, sig, n, pub, NULL, 0));
    R.DestroyHash(b, hb);
    hb = cp_mkhash(&R, b, CALG_SHA1); R.HashData(b, hb, (const BYTE *)"abx", 3, 0);
    FAILS(R.VerifySignature(b, hb, sig, n, pub, NULL, 0), CPE_BAD_SIGNATURE);
    R.DestroyHash(b, hb); R.DestroyKey(b, pub);
    R.DestroyHash(a, h); R.DestroyKey(a, k);
    cp_rel(&R, a); cp_rel(&R, b);
}
TEST(cpd_verify_finishes_the_hash) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR pub = pub_ctx(&R, p); REQUIRE(pub);
    ULONG_PTR h = abc_hash(&R, p, CALG_SHA1);
    OKAY(R.VerifySignature(p, h, rsa_sig_sha1_abc, 128, pub, NULL, 0));
    FAILS(R.HashData(p, h, (const BYTE *)"x", 1, 0), CPE_BAD_HASH_STATE);
    R.DestroyHash(p, h); R.DestroyKey(p, pub);
    cp_rel(&R, p);
}
TEST(cpd_verify_description_is_hashed_into_the_digest) {
    NEED_RSA(); ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR k = 0; OKAY(R.GenKey(p, AT_SIGNATURE, (512u << 16), &k)); REQUIRE(k);
    ULONG_PTR pub = 0; OKAY(R.GetUserKey(p, AT_SIGNATURE, &pub)); REQUIRE(pub);
    ULONG_PTR h = abc_hash(&R, p, CALG_SHA1);
    BYTE sig[64]; DWORD n = sizeof sig;
    OKAY(R.SignHash(p, h, AT_SIGNATURE, L"desc", 0, sig, &n));
    ULONG_PTR h2 = abc_hash(&R, p, CALG_SHA1);
    OKAY(R.VerifySignature(p, h2, sig, n, pub, L"desc", 0));
    ULONG_PTR h3 = abc_hash(&R, p, CALG_SHA1);
    FAILS(R.VerifySignature(p, h3, sig, n, pub, NULL, 0), CPE_BAD_SIGNATURE);
    ULONG_PTR h4 = abc_hash(&R, p, CALG_SHA1);
    FAILS(R.VerifySignature(p, h4, sig, n, pub, L"other", 0), CPE_BAD_SIGNATURE);
    R.DestroyHash(p, h); R.DestroyHash(p, h2); R.DestroyHash(p, h3); R.DestroyHash(p, h4);
    R.DestroyKey(p, pub); R.DestroyKey(p, k);
    cp_rel(&R, p);
}
TEST(cpd_sign_verify_roundtrip_each_hash) {
    NEED_RSA(); ULONG_PTR p = rsa_aes(&R); REQUIRE(p);
    ULONG_PTR k = 0; OKAY(R.GenKey(p, AT_SIGNATURE, (1024u << 16), &k)); REQUIRE(k);
    ULONG_PTR pub = 0; OKAY(R.GetUserKey(p, AT_SIGNATURE, &pub)); REQUIRE(pub);
    ALG_ID algs[] = { CALG_MD2, CALG_MD4, CALG_MD5, CALG_SHA1, CALG_SHA_256, CALG_SHA_384, CALG_SHA_512 };
    for (size_t i = 0; i < NELEM(algs); i++) {
        ULONG_PTR h = abc_hash(&R, p, algs[i]), h2 = abc_hash(&R, p, algs[i]);
        BYTE sig[128]; DWORD n = sizeof sig;
        SET_ERR(0);
        BOOL r = R.SignHash(p, h, AT_SIGNATURE, NULL, 0, sig, &n);
        CHECKF(r, "sign alg 0x%x err=0x%lx", algs[i], GetLastError());
        if (r) {
            EXPECT_EQ(n, 128);
            SET_ERR(0);
            CHECKF(R.VerifySignature(p, h2, sig, n, pub, NULL, 0), "verify alg 0x%x err=0x%lx", algs[i], GetLastError());
        }
        R.DestroyHash(p, h); R.DestroyHash(p, h2);
    }
    R.DestroyKey(p, pub); R.DestroyKey(p, k);
    cp_rel(&R, p);
}

/* ---- dssenh ------------------------------------------------------------------------------ */
static ULONG_PTR dss_gen(const cpf *f, ULONG_PTR p, DWORD bits) {
    ULONG_PTR k = 0;
    if (!f->GenKey(p, AT_SIGNATURE, (bits << 16) | CRYPT_EXPORTABLE, &k)) return 0;
    return k;
}
TEST(cpd_dss_genkey_validation_order) {
    NEED_DSS(); ULONG_PTR p = dss_open(&D, PROV_DSS_DH); REQUIRE(p);
    ULONG_PTR k = 0x99;
    /* dssenh does not validate phKey or the context before it writes the result: a NULL phKey faults */
    T_EXPECT_FAULT(D.GenKey(p, AT_SIGNATURE, 0, NULL));
    T_EXPECT_FAULT(D.GenKey(p, AT_SIGNATURE, 0x8, NULL));
    DWORD bad[] = { 0x8, 0x20, 0x80, 0x100, 0x200, 0x800, 0x1000, 0x2000 };
    for (size_t i = 0; i < NELEM(bad); i++) FAILS(D.GenKey(p, AT_SIGNATURE, bad[i], &k), CPE_BAD_FLAGS);
    cp_rel(&D, p);
}
TEST(cpd_dss_genkey_unsupported_algorithms) {
    NEED_DSS(); ULONG_PTR p = dss_open(&D, PROV_DSS_DH); REQUIRE(p);
    ALG_ID bad[] = { CALG_MD5, CALG_SHA1, CALG_RSA_SIGN, CALG_RSA_KEYX, 0x1234, 0 };
    for (size_t i = 0; i < NELEM(bad); i++) { ULONG_PTR k = 0; FAILS(D.GenKey(p, bad[i], 0, &k), CPE_BAD_ALGID); }
    /* the DSS/DH provider also generates RC4, RC2 and DES session keys */
    ALG_ID ok[] = { CALG_RC4, CALG_RC2, CALG_DES };
    for (size_t i = 0; i < NELEM(ok); i++) { ULONG_PTR k = 0; OKAY(D.GenKey(p, ok[i], 0, &k)); if (k) D.DestroyKey(p, k); }
    cp_rel(&D, p);
}
TEST(cpd_dss_genkey_wrong_context_kind) {
    NEED_DSS(); ULONG_PTR p = dss_open(&D, PROV_DSS_DH); REQUIRE(p);
    ULONG_PTR k = dss_gen(&D, p, 512); REQUIRE(k);
    ULONG_PTR k2 = 0;
    FAILS(D.GenKey(k, AT_SIGNATURE, 0, &k2), CPE_BAD_UID);
    D.DestroyKey(p, k);
    cp_rel(&D, p);
}
TEST(cpd_dss_genkey_illegal_length_flags) {
    NEED_DSS(); ULONG_PTR p = dss_open(&D, PROV_DSS_DH); REQUIRE(p);
    DWORD bad[] = { 128, 256, 400, 511, 1025, 2048, 4096 };
    for (size_t i = 0; i < NELEM(bad); i++) {
        ULONG_PTR k = 0;
        SET_ERR(0);
        BOOL r = D.GenKey(p, AT_SIGNATURE, bad[i] << 16, &k);
        CHECKF(!r, "DSS key with %lu bits was generated", bad[i]);
        if (!r) EXPECT_ERR(CPE_BAD_FLAGS);
        else D.DestroyKey(p, k);
    }
    cp_rel(&D, p);
}
TEST(cpd_dss_sign_verify_roundtrip) {
    NEED_DSS(); ULONG_PTR p = dss_open(&D, PROV_DSS_DH); REQUIRE(p);
    ULONG_PTR k = dss_gen(&D, p, 512); REQUIRE(k);
    BOOL ok;
    if (!t_is_wine()) {   /* the emulated dssenh has no CPGetKeyParam and aborts */
        EXPECT_EQ(cp_kp_dw(&D, p, k, KP_ALGID, &ok), CALG_DSS_SIGN); CHECK(ok);
        EXPECT_EQ(cp_kp_dw(&D, p, k, KP_KEYLEN, &ok), 512); CHECK(ok);
    }
    ULONG_PTR h = abc_hash(&D, p, CALG_SHA1); REQUIRE(h);
    BYTE sig[128]; DWORD n = 0;
    OKAY(D.SignHash(p, h, AT_SIGNATURE, NULL, 0, NULL, &n));
    EXPECT_EQ(n, 40);
    n = 39;
    FAILS(D.SignHash(p, h, AT_SIGNATURE, NULL, 0, sig, &n), ERROR_MORE_DATA);
    EXPECT_EQ(n, 40);
    n = sizeof sig;
    OKAY(D.SignHash(p, h, AT_SIGNATURE, NULL, 0, sig, &n));
    EXPECT_EQ(n, 40);
    ULONG_PTR pub = 0; OKAY(D.GetUserKey(p, AT_SIGNATURE, &pub)); REQUIRE(pub);
    ULONG_PTR h2 = abc_hash(&D, p, CALG_SHA1);
    OKAY(D.VerifySignature(p, h2, sig, n, pub, NULL, 0));
    ULONG_PTR h3 = cp_mkhash(&D, p, CALG_SHA1); D.HashData(p, h3, (const BYTE *)"abd", 3, 0);
    FAILS(D.VerifySignature(p, h3, sig, n, pub, NULL, 0), CPE_BAD_SIGNATURE);
    BYTE bad[40]; memcpy(bad, sig, 40); bad[7] ^= 0x10;
    ULONG_PTR h4 = abc_hash(&D, p, CALG_SHA1);
    FAILS(D.VerifySignature(p, h4, bad, 40, pub, NULL, 0), CPE_BAD_SIGNATURE);
    D.DestroyHash(p, h); D.DestroyHash(p, h2); D.DestroyHash(p, h3); D.DestroyHash(p, h4);
    D.DestroyKey(p, pub); D.DestroyKey(p, k);
    cp_rel(&D, p);
}
TEST(cpd_dss_signatures_are_randomised) {
    NEED_DSS(); ULONG_PTR p = dss_open(&D, PROV_DSS_DH); REQUIRE(p);
    ULONG_PTR k = dss_gen(&D, p, 512); REQUIRE(k);
    BYTE s1[40], s2[40]; DWORD n1 = 40, n2 = 40;
    ULONG_PTR h1 = abc_hash(&D, p, CALG_SHA1), h2 = abc_hash(&D, p, CALG_SHA1);
    OKAY(D.SignHash(p, h1, AT_SIGNATURE, NULL, 0, s1, &n1));
    OKAY(D.SignHash(p, h2, AT_SIGNATURE, NULL, 0, s2, &n2));
    CHECK(n1 == 40 && n2 == 40 && memcmp(s1, s2, 40) != 0);
    D.DestroyHash(p, h1); D.DestroyHash(p, h2); D.DestroyKey(p, k);
    cp_rel(&D, p);
}
TEST(cpd_dss_export_public_blob_and_cross_context_verify) {
    NEED_DSS(); ULONG_PTR a = dss_open(&D, PROV_DSS_DH), b = dss_open(&D, PROV_DSS_DH); REQUIRE(a && b);
    ULONG_PTR k = dss_gen(&D, a, 512); REQUIRE(k);
    BYTE blob[600]; DWORD n = sizeof blob;
    OKAY(D.ExportKey(a, k, 0, PUBLICKEYBLOB, 0, blob, &n));
    CHECK(blob[0] == PUBLICKEYBLOB); CHECK(blob[1] == 2);
    EXPECT_EQ(*(ALG_ID *)(blob + 4), CALG_DSS_SIGN);
    EXPECT_EQ(*(DWORD *)(blob + 8), 0x31535344);   /* "DSS1" */
    EXPECT_EQ(*(DWORD *)(blob + 12), 512);
    ULONG_PTR h = abc_hash(&D, a, CALG_SHA1);
    BYTE sig[40]; DWORD sn = 40;
    OKAY(D.SignHash(a, h, AT_SIGNATURE, NULL, 0, sig, &sn));
    ULONG_PTR pub = 0; OKAY(D.ImportKey(b, blob, n, 0, 0, &pub)); REQUIRE(pub);
    ULONG_PTR hb = abc_hash(&D, b, CALG_SHA1);
    OKAY(D.VerifySignature(b, hb, sig, sn, pub, NULL, 0));
    D.DestroyHash(b, hb); D.DestroyKey(b, pub); D.DestroyHash(a, h); D.DestroyKey(a, k);
    cp_rel(&D, a); cp_rel(&D, b);
}
TEST(cpd_dss_sha1_known_answer) {
    NEED_DSS(); ULONG_PTR p = dss_open(&D, PROV_DSS_DH); REQUIRE(p);
    BYTE d[20], want[20];
    EXPECT_EQ(cp_hash(&D, p, CALG_SHA1, "abc", 3, d, 20), 20);
    hx("a9993e364706816aba3e25717850c26c9cd0d89d", want);
    SAMEBYTES(d, want, 20);
    EXPECT_EQ(cp_hash(&D, p, CALG_SHA1, "", 0, d, 20), 20);
    hx("da39a3ee5e6b4b0d3255bfef95601890afd80709", want);
    SAMEBYTES(d, want, 20);
    cp_rel(&D, p);
}
TEST(cpd_dss_md5_hash) {
    NEED_DSS(); ULONG_PTR p = dss_open(&D, PROV_DSS_DH); REQUIRE(p);
    BYTE d[16], want[16];
    DWORD n = cp_hash(&D, p, CALG_MD5, "abc", 3, d, 16);
    EXPECT_EQ(n, 16);
    hx("900150983cd24fb0d6963f7d28e17f72", want); SAMEBYTES(d, want, 16);
    cp_rel(&D, p);
}
TEST(cpd_dss_hashdata_state_rules) {
    NEED_DSS(); ULONG_PTR p = dss_open(&D, PROV_DSS_DH); REQUIRE(p);
    ULONG_PTR h = cp_mkhash(&D, p, CALG_SHA1); REQUIRE(h);
    OKAY(D.HashData(p, h, cp_abc, 3, 0));
    BYTE d[20]; DWORD n = 20;
    OKAY(D.GetHashParam(p, h, HP_HASHVAL, d, &n, 0));
    SET_ERR(0);
    BOOL r = D.HashData(p, h, cp_abc, 1, 0);
    CHECK(!r);
    if (!r) EXPECT_ERR(CPE_BAD_HASH_STATE);
    D.DestroyHash(p, h);
    cp_rel(&D, p);
}
TEST(cpd_dss_hash_size_protocol) {
    NEED_DSS(); ULONG_PTR p = dss_open(&D, PROV_DSS_DH); REQUIRE(p);
    ULONG_PTR h = abc_hash(&D, p, CALG_SHA1); REQUIRE(h);
    DWORD n = 0;
    OKAY(D.GetHashParam(p, h, HP_HASHVAL, NULL, &n, 0));
    EXPECT_EQ(n, 20);
    BYTE b[32]; n = 19;
    FAILS(D.GetHashParam(p, h, HP_HASHVAL, b, &n, 0), ERROR_MORE_DATA);
    EXPECT_EQ(n, 20);
    BOOL ok; EXPECT_EQ(cp_hp_dw(&D, p, h, HP_HASHSIZE, &ok), 20); CHECK(ok);
    EXPECT_EQ(cp_hp_dw(&D, p, h, HP_ALGID, &ok), CALG_SHA1); CHECK(ok);
    D.DestroyHash(p, h);
    cp_rel(&D, p);
}
TEST(cpd_dss_getuserkey_without_key) {
    NEED_DSS(); ULONG_PTR p = dss_open(&D, PROV_DSS_DH); REQUIRE(p);
    ULONG_PTR k = 0;
    SET_ERR(0);
    FAILS(D.GetUserKey(p, AT_SIGNATURE, &k), CPE_NO_KEY);
    cp_rel(&D, p);
}
TEST(cpd_dss_genrandom) {
    NEED_DSS(); ULONG_PTR p = dss_open(&D, PROV_DSS_DH); REQUIRE(p);
    BYTE a[32], b[32];
    OKAY(D.GenRandom(p, 32, a)); OKAY(D.GenRandom(p, 32, b));
    CHECK(memcmp(a, b, 32) != 0);
    BYTE o[24]; memset(o, 0xA5, sizeof o);
    OKAY(D.GenRandom(p, 8, o));
    for (int i = 8; i < 24; i++) CHECK(o[i] == 0xA5);
    cp_rel(&D, p);
}
TEST(cpd_dss_destroy_and_duplicate_key) {
    NEED_DSS(); ULONG_PTR p = dss_open(&D, PROV_DSS_DH); REQUIRE(p);
    ULONG_PTR k = dss_gen(&D, p, 512); REQUIRE(k);
    ULONG_PTR d = 0;
    SET_ERR(0);
    OKAY(D.DuplicateKey(p, k, NULL, 0, &d));  /* probed: succeeds */
    CHECK(d != 0 && d != k);
    if (d) OKAY(D.DestroyKey(p, d));
    OKAY(D.DestroyKey(p, k));
    cp_rel(&D, p);
}
