/* crypt32 encode/decode of algorithm identifiers, public/private key structures and signatures. */
#include "kp.h"
#include "kp_vec.h"

#define REQ_CRYPT32() do { REQUIRE(t_proc_in("crypt32.dll", "CryptEncodeObjectEx")); REQUIRE(t_proc_in("crypt32.dll", "CryptDecodeObjectEx")); \
    REQUIRE(t_proc_in("crypt32.dll", "CryptEncodeObject")); REQUIRE(t_proc_in("crypt32.dll", "CryptDecodeObject")); } while (0)

#define RSA_CSP_PUBLICKEYBLOB_T ((LPCSTR)19)
#define CNG_RSA_PUBLIC_KEY_BLOB_T ((LPCSTR)72)
#define OID_RSA "1.2.840.113549.1.1.1"
static const BYTE rsa_oid_der[] = {6,9,0x2a,0x86,0x48,0x86,0xf7,0x0d,1,1,1};

/* ---------------------------------------------------------------- X509_ALGORITHM_IDENTIFIER */
TEST(kpk_algid_encode_empty_params_emits_null) {
    REQ_TYPE(X509_ALGORITHM_IDENTIFIER);
    /* No parameters in the struct: the encoder still writes an explicit ASN.1 NULL */
    CRYPT_ALGORITHM_IDENTIFIER a = { (LPSTR)OID_RSA, { 0, NULL } };
    ENC_EQ(X509_ALGORITHM_IDENTIFIER, &a, V(0x30,0x0d,6,9,0x2a,0x86,0x48,0x86,0xf7,0x0d,1,1,1,5,0));
}
TEST(kpk_algid_encode_explicit_null_params) {
    REQ_TYPE(X509_ALGORITHM_IDENTIFIER);
    CRYPT_ALGORITHM_IDENTIFIER a = { (LPSTR)OID_RSA, { 2, (BYTE *)"\x05\x00" } };
    ENC_EQ(X509_ALGORITHM_IDENTIFIER, &a, V(0x30,0x0d,6,9,0x2a,0x86,0x48,0x86,0xf7,0x0d,1,1,1,5,0));
}
TEST(kpk_algid_encode_blob_params_verbatim) {
    REQ_TYPE(X509_ALGORITHM_IDENTIFIER);
    CRYPT_ALGORITHM_IDENTIFIER a = { (LPSTR)"1.2.3", { 3, (BYTE *)"\x04\x01\xaa" } };
    ENC_EQ(X509_ALGORITHM_IDENTIFIER, &a, V(0x30,0x07,6,2,0x2a,3,4,1,0xaa));
}
TEST(kpk_algid_encode_oid_forms) {
    REQ_TYPE(X509_ALGORITHM_IDENTIFIER);
    CRYPT_ALGORITHM_IDENTIFIER a = { (LPSTR)"1.2.3", { 0, NULL } };
    ENC_EQ(X509_ALGORITHM_IDENTIFIER, &a, V(0x30,0x06,6,2,0x2a,3,5,0));
    a.pszObjId = (LPSTR)"2.5.8.1.1";
    ENC_EQ(X509_ALGORITHM_IDENTIFIER, &a, V(0x30,0x08,6,4,0x55,8,1,1,5,0));
    a.pszObjId = (LPSTR)szOID_OIWSEC_sha1;
    ENC_EQ(X509_ALGORITHM_IDENTIFIER, &a, V(0x30,0x09,6,5,0x2b,0x0e,3,2,0x1a,5,0));
    a.pszObjId = (LPSTR)szOID_NIST_sha256;
    ENC_EQ(X509_ALGORITHM_IDENTIFIER, &a, V(0x30,0x0d,6,9,0x60,0x86,0x48,1,0x65,3,4,2,1,5,0));
}
TEST(kpk_algid_encode_bad_oid_fails) {
    REQ_TYPE(X509_ALGORITHM_IDENTIFIER);
    CRYPT_ALGORITHM_IDENTIFIER a = { (LPSTR)"no-such-oid", { 0, NULL } };
    ENC_FAIL(X509_ALGORITHM_IDENTIFIER, &a, 0);
    a.pszObjId = (LPSTR)"1";
    ENC_FAIL(X509_ALGORITHM_IDENTIFIER, &a, 0);
    a.pszObjId = (LPSTR)"";
    ENC_FAIL(X509_ALGORITHM_IDENTIFIER, &a, 0);
}
TEST(kpk_algid_encode_failure_zeroes_size_and_alloc_pointer) {
    REQ_TYPE(X509_ALGORITHM_IDENTIFIER);
    CRYPT_ALGORITHM_IDENTIFIER a = { (LPSTR)"no-such-oid", { 0, NULL } };
    BYTE *out = (BYTE *)(ULONG_PTR)1; DWORD cb = 55;
    CHECK(!U(CryptEncodeObjectEx)(KP_ENC, X509_ALGORITHM_IDENTIFIER, &a, CRYPT_ENCODE_ALLOC_FLAG, NULL, &out, &cb));
    CHECK(out == NULL); EXPECT_EQ(cb, 0);
}
TEST(kpk_algid_decode_params_null_vs_absent) {
    REQ_TYPE(X509_ALGORITHM_IDENTIFIER);
    CRYPT_ALGORITHM_IDENTIFIER *r = DEC_OK(X509_ALGORITHM_IDENTIFIER, V(0x30,0x0d,6,9,0x2a,0x86,0x48,0x86,0xf7,0x0d,1,1,1,5,0), 0);
    if (r) { EXPECT_STR(r->pszObjId, OID_RSA); BLOB_IS(r->Parameters, 5, 0); kp_free(r); }
    r = DEC_OK(X509_ALGORITHM_IDENTIFIER, V(0x30,0x0b,6,9,0x2a,0x86,0x48,0x86,0xf7,0x0d,1,1,1), 0);
    if (r) { EXPECT_STR(r->pszObjId, OID_RSA); CHECK(r->Parameters.cbData == 0); kp_free(r); }
}
TEST(kpk_algid_decode_params_blob) {
    REQ_TYPE(X509_ALGORITHM_IDENTIFIER);
    CRYPT_ALGORITHM_IDENTIFIER *r = DEC_OK(X509_ALGORITHM_IDENTIFIER, V(0x30,0x09,6,2,0x2a,3,0x30,3,2,1,7), 0);
    if (r) { EXPECT_STR(r->pszObjId, "1.2.3"); BLOB_IS(r->Parameters, 0x30,3,2,1,7); kp_free(r); }
    r = DEC_OK(X509_ALGORITHM_IDENTIFIER, V(0x30,0x07,6,2,0x2a,3,4,1,0xaa), 0);
    if (r) { BLOB_IS(r->Parameters, 4,1,0xaa); kp_free(r); }
}
TEST(kpk_algid_decode_nocopy_params_alias_input) {
    REQ_TYPE(X509_ALGORITHM_IDENTIFIER);
    static const BYTE der[] = {0x30,0x07,6,2,0x2a,3,4,1,0xaa}; BYTE buf[256]; DWORD cb = sizeof buf;
    CHECK(U(CryptDecodeObjectEx)(KP_ENC, X509_ALGORITHM_IDENTIFIER, der, sizeof der, CRYPT_DECODE_NOCOPY_FLAG, NULL, buf, &cb));
    CRYPT_ALGORITHM_IDENTIFIER *r = (CRYPT_ALGORITHM_IDENTIFIER *)buf;
    CHECK(r->Parameters.cbData == 3);
    t_note("NOCOPY: Parameters.pbData aliases input = %d", r->Parameters.pbData == der + 6);
}
TEST(kpk_algid_decode_errors) {
    REQ_TYPE(X509_ALGORITHM_IDENTIFIER);
    DEC_FAILV(X509_ALGORITHM_IDENTIFIER, KP_E_BADTAG, 0x31, 0);
    DEC_FAILV(X509_ALGORITHM_IDENTIFIER, KP_E_BADTAG, 2, 1, 1);
    DEC_FAILV(X509_ALGORITHM_IDENTIFIER, KP_E_BADTAG, 0x30, 3, 2, 1, 1);
    DEC_FAILV(X509_ALGORITHM_IDENTIFIER, KP_E_TRUNC, 0x30, 9, 6, 2, 0x2a);
    DEC_FAILV(X509_ALGORITHM_IDENTIFIER, KP_E_TRUNC, 0x30);
    DEC_FAILV(X509_ALGORITHM_IDENTIFIER, 0, 0x30, 0);
}
TEST(kpk_algid_roundtrip_oids) {
    REQ_TYPE(X509_ALGORITHM_IDENTIFIER);
    static const char *oids[] = { szOID_RSA_RSA, szOID_OIWSEC_sha1, szOID_NIST_sha256, szOID_X957_DSA, szOID_ECC_PUBLIC_KEY, szOID_RSA_SHA256RSA, "1.3.6.1.4.1.311.2.1.4" };
    for (unsigned i = 0; i < sizeof oids / sizeof oids[0]; i++) {
        CRYPT_ALGORITHM_IDENTIFIER a = { (LPSTR)oids[i], { 0, NULL } }; DWORD cb;
        BYTE *e = kp_enc_alloc(X509_ALGORITHM_IDENTIFIER, &a, 0, &cb);
        CHECKF(e != NULL, "%s", oids[i]);
        if (!e) continue;
        CRYPT_ALGORITHM_IDENTIFIER *r = kp_dec_alloc(X509_ALGORITHM_IDENTIFIER, e, cb, 0, NULL);
        CHECKF(r && !strcmp(r->pszObjId, oids[i]) && r->Parameters.cbData == 2, "%s", oids[i]);
        kp_free(r); kp_free(e);
    }
}

/* ---------------------------------------------------------------- X509_PUBLIC_KEY_INFO */
static const BYTE small_rsa_pub[] = {0x30,6,2,1,0x0b,2,1,3};
TEST(kpk_pubkeyinfo_encode_rsa_null_params) {
    REQ_CRYPT32();
    CERT_PUBLIC_KEY_INFO k; memset(&k, 0, sizeof k);
    k.Algorithm.pszObjId = (LPSTR)OID_RSA;
    k.PublicKey.cbData = sizeof small_rsa_pub; k.PublicKey.pbData = (BYTE *)small_rsa_pub;
    ENC_EQ(X509_PUBLIC_KEY_INFO, &k, V(0x30,0x1a, 0x30,0x0d,6,9,0x2a,0x86,0x48,0x86,0xf7,0x0d,1,1,1,5,0, 3,9,0, 0x30,6,2,1,0x0b,2,1,3));
}
TEST(kpk_pubkeyinfo_encode_unknown_oid_null_params) {
    REQ_CRYPT32();
    CERT_PUBLIC_KEY_INFO k; memset(&k, 0, sizeof k);
    k.Algorithm.pszObjId = (LPSTR)"1.2.3.4.5";
    k.PublicKey.cbData = 2; k.PublicKey.pbData = (BYTE *)"\x01\x02";
    ENC_EQ(X509_PUBLIC_KEY_INFO, &k, V(0x30,0x0f, 0x30,0x08,6,4,0x2a,3,4,5,5,0, 3,3,0,1,2));
}
TEST(kpk_pubkeyinfo_encode_explicit_params) {
    REQ_CRYPT32();
    CERT_PUBLIC_KEY_INFO k; memset(&k, 0, sizeof k);
    k.Algorithm.pszObjId = (LPSTR)"1.2.3.4.5";
    k.Algorithm.Parameters.cbData = 3; k.Algorithm.Parameters.pbData = (BYTE *)"\x04\x01\x55";
    k.PublicKey.cbData = 1; k.PublicKey.pbData = (BYTE *)"\xf0"; k.PublicKey.cUnusedBits = 4;
    ENC_EQ(X509_PUBLIC_KEY_INFO, &k, V(0x30,0x0f, 0x30,0x09,6,4,0x2a,3,4,5,4,1,0x55, 3,2,4,0xf0));
}
TEST(kpk_pubkeyinfo_encode_ecc_no_params_note) {
    REQ_CRYPT32();
    CERT_PUBLIC_KEY_INFO k; memset(&k, 0, sizeof k);
    k.Algorithm.pszObjId = (LPSTR)szOID_ECC_PUBLIC_KEY;
    k.PublicKey.cbData = sizeof kv_ec_pub_point; k.PublicKey.pbData = (BYTE *)kv_ec_pub_point;
    DWORD cb; BYTE *e = kp_enc_alloc(X509_PUBLIC_KEY_INFO, &k, 0, &cb);
    CHECK(e != NULL);
    if (e) {
        /* the OID table flags EC keys as taking no NULL parameters: the algorithm sequence is then just the OID */
        t_note("ECC key info without parameters encodes %lu bytes (OID only would be %lu)", cb, (unsigned long)(sizeof kv_ec_pub_point + 3 + 2 + 2 + 9 + 2));
        kp_free(e);
    }
}
TEST(kpk_pubkeyinfo_encode_empty_key) {
    REQ_CRYPT32();
    CERT_PUBLIC_KEY_INFO k; memset(&k, 0, sizeof k);
    k.Algorithm.pszObjId = (LPSTR)"1.2.3";
    ENC_EQ(X509_PUBLIC_KEY_INFO, &k, V(0x30,0x0b, 0x30,0x06,6,2,0x2a,3,5,0, 3,1,0));
}
TEST(kpk_pubkeyinfo_encode_real_rsa_matches_vector) {
    REQ_CRYPT32();
    CERT_PUBLIC_KEY_INFO k; memset(&k, 0, sizeof k);
    k.Algorithm.pszObjId = (LPSTR)OID_RSA;
    k.PublicKey.cbData = sizeof kv_rsa_pkcs1_pub; k.PublicKey.pbData = (BYTE *)kv_rsa_pkcs1_pub;
    ENC_EQ(X509_PUBLIC_KEY_INFO, &k, kv_rsa_spki, sizeof kv_rsa_spki);
}
TEST(kpk_pubkeyinfo_decode_real_rsa) {
    REQ_CRYPT32();
    CERT_PUBLIC_KEY_INFO *r = DEC_OK(X509_PUBLIC_KEY_INFO, kv_rsa_spki, sizeof kv_rsa_spki, 0);
    if (r) {
        EXPECT_STR(r->Algorithm.pszObjId, OID_RSA);
        BLOB_IS(r->Algorithm.Parameters, 5, 0);
        CHECK(r->PublicKey.cUnusedBits == 0 && r->PublicKey.cbData == sizeof kv_rsa_pkcs1_pub && !memcmp(r->PublicKey.pbData, kv_rsa_pkcs1_pub, sizeof kv_rsa_pkcs1_pub));
        kp_free(r);
    }
}
TEST(kpk_pubkeyinfo_decode_ecc_curve_params) {
    REQ_CRYPT32();
    CERT_PUBLIC_KEY_INFO *r = DEC_OK(X509_PUBLIC_KEY_INFO, kv_ec_spki, sizeof kv_ec_spki, 0);
    if (r) {
        EXPECT_STR(r->Algorithm.pszObjId, szOID_ECC_PUBLIC_KEY);
        BLOB_IS(r->Algorithm.Parameters, 6,8,0x2a,0x86,0x48,0xce,0x3d,3,1,7);
        CHECK(r->PublicKey.cbData == 65 && r->PublicKey.pbData[0] == 4 && !memcmp(r->PublicKey.pbData, kv_ec_pub_point, 65));
        kp_free(r);
    }
}
TEST(kpk_pubkeyinfo_ecc_roundtrip_matches_vector) {
    REQ_CRYPT32();
    CERT_PUBLIC_KEY_INFO k; memset(&k, 0, sizeof k);
    k.Algorithm.pszObjId = (LPSTR)szOID_ECC_PUBLIC_KEY;
    k.Algorithm.Parameters.cbData = 10; k.Algorithm.Parameters.pbData = (BYTE *)"\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07";
    k.PublicKey.cbData = 65; k.PublicKey.pbData = (BYTE *)kv_ec_pub_point;
    ENC_EQ(X509_PUBLIC_KEY_INFO, &k, kv_ec_spki, sizeof kv_ec_spki);
}
TEST(kpk_pubkeyinfo_decode_unused_bits_masked) {
    REQ_CRYPT32();
    CERT_PUBLIC_KEY_INFO *r = DEC_OK(X509_PUBLIC_KEY_INFO, V(0x30,0x0f, 0x30,0x09,6,4,0x2a,3,4,5,4,1,0x55, 3,2,4,0xff), 0);
    if (r) { CHECK(r->PublicKey.cbData == 1 && r->PublicKey.cUnusedBits == 4 && r->PublicKey.pbData[0] == 0xf0); kp_free(r); }
}
TEST(kpk_pubkeyinfo_decode_errors) {
    REQ_CRYPT32();
    DEC_FAILV(X509_PUBLIC_KEY_INFO, KP_E_BADTAG, 2, 1, 1);
    DEC_FAILV(X509_PUBLIC_KEY_INFO, KP_E_BADTAG, 0x30, 0x0a, 0x30,0x06,6,2,0x2a,3,5,0, 4,1,0);   /* key is not a BIT STRING */
    DEC_FAILV(X509_PUBLIC_KEY_INFO, KP_E_TRUNC, 0x30, 0x0a, 0x30,0x06,6,2,0x2a,3,5,0, 3);
    DEC_FAILV(X509_PUBLIC_KEY_INFO, 0, 0x30, 0);
    DEC_FAILV(X509_PUBLIC_KEY_INFO, 0, 0x30, 0x08, 0x30,0x06,6,2,0x2a,3,5,0);                   /* no key at all */
}
TEST(kpk_pubkeyinfo_encode_bad_oid) {
    REQ_CRYPT32();
    CERT_PUBLIC_KEY_INFO k; memset(&k, 0, sizeof k);
    k.Algorithm.pszObjId = (LPSTR)"bogus";
    ENC_FAIL(X509_PUBLIC_KEY_INFO, &k, 0);
}

/* ---------------------------------------------------------------- RSA_CSP_PUBLICKEYBLOB */
TEST(kpk_rsa_csp_pub_encode) {
    REQ_CRYPT32();
    ENC_EQ(RSA_CSP_PUBLICKEYBLOB_T, kv_rsa_csp_pub, kv_rsa_pkcs1_pub, sizeof kv_rsa_pkcs1_pub);
}
TEST(kpk_rsa_csp_pub_decode) {
    REQ_CRYPT32();
    BYTE *r = DEC_OK(RSA_CSP_PUBLICKEYBLOB_T, kv_rsa_pkcs1_pub, sizeof kv_rsa_pkcs1_pub, 0);
    if (r) {
        DWORD cb = 0;
        U(CryptDecodeObjectEx)(KP_ENC, RSA_CSP_PUBLICKEYBLOB_T, kv_rsa_pkcs1_pub, sizeof kv_rsa_pkcs1_pub, 0, NULL, NULL, &cb);
        CHECK(cb >= sizeof kv_rsa_csp_pub);
        CHECK(!memcmp(r, kv_rsa_csp_pub, sizeof kv_rsa_csp_pub));
        CHECK(r[0] == PUBLICKEYBLOB && r[1] == 2 && *(WORD *)(r + 2) == 0 && *(DWORD *)(r + 4) == CALG_RSA_KEYX);
        kp_free(r);
    }
}
TEST(kpk_rsa_csp_pub_decode_header_fields) {
    REQ_CRYPT32();
    BYTE *r = kp_dec_alloc(RSA_CSP_PUBLICKEYBLOB_T, kv_rsa_pkcs1_pub, sizeof kv_rsa_pkcs1_pub, 0, NULL);
    CHECK(r != NULL);
    if (r) {
        CHECK(*(DWORD *)(r + 8) == 0x31415352);          /* 'RSA1' */
        CHECK(*(DWORD *)(r + 12) == 1024);                /* bit length from the modulus */
        CHECK(*(DWORD *)(r + 16) == 65537);               /* public exponent */
        kp_free(r);
    }
}
TEST(kpk_rsa_csp_pub_small_modulus_roundtrip) {
    REQ_CRYPT32();
    /* n = 0xC0A80101C0A80101 (64 bits, top bit set => DER needs a 00 pad), e = 65537 */
    BYTE blob[20 + 8]; memset(blob, 0, sizeof blob);
    blob[0] = 6; blob[1] = 2; *(DWORD *)(blob + 4) = CALG_RSA_KEYX; *(DWORD *)(blob + 8) = 0x31415352; *(DWORD *)(blob + 12) = 64; *(DWORD *)(blob + 16) = 65537;
    static const BYTE nle[8] = {0x01,0x01,0xa8,0xc0,0x01,0x01,0xa8,0xc0};
    memcpy(blob + 20, nle, 8);
    ENC_EQ(RSA_CSP_PUBLICKEYBLOB_T, blob, V(0x30,0x10, 2,9,0,0xc0,0xa8,1,1,0xc0,0xa8,1,1, 2,3,1,0,1));
    BYTE *r = DEC_OK(RSA_CSP_PUBLICKEYBLOB_T, V(0x30,0x10, 2,9,0,0xc0,0xa8,1,1,0xc0,0xa8,1,1, 2,3,1,0,1), 0);
    if (r) { CHECK(!memcmp(r, blob, sizeof blob)); kp_free(r); }
}
TEST(kpk_rsa_csp_pub_small_exponents) {
    REQ_CRYPT32();
    BYTE blob[20 + 8]; memset(blob, 0, sizeof blob);
    blob[0] = 6; blob[1] = 2; *(DWORD *)(blob + 4) = CALG_RSA_KEYX; *(DWORD *)(blob + 8) = 0x31415352; *(DWORD *)(blob + 12) = 64;
    static const BYTE nle[8] = {0x01,0x01,0xa8,0x40,0x01,0x01,0xa8,0x40};
    memcpy(blob + 20, nle, 8);
    *(DWORD *)(blob + 16) = 3;
    ENC_EQ(RSA_CSP_PUBLICKEYBLOB_T, blob, V(0x30,0x0d, 2,8,0x40,0xa8,1,1,0x40,0xa8,1,1, 2,1,3));
    *(DWORD *)(blob + 16) = 0x80000001;
    ENC_EQ(RSA_CSP_PUBLICKEYBLOB_T, blob, V(0x30,0x11, 2,8,0x40,0xa8,1,1,0x40,0xa8,1,1, 2,5,0,0x80,0,0,1));
}
TEST(kpk_rsa_csp_pub_wrong_blob_type_is_invalidarg) {
    REQ_CRYPT32();
    BYTE blob[sizeof kv_rsa_csp_pub]; memcpy(blob, kv_rsa_csp_pub, sizeof blob);
    blob[0] = PRIVATEKEYBLOB;
    ENC_FAIL(RSA_CSP_PUBLICKEYBLOB_T, blob, KP_E_INVALIDARG);
    blob[0] = 0;
    ENC_FAIL(RSA_CSP_PUBLICKEYBLOB_T, blob, KP_E_INVALIDARG);
    blob[0] = SIMPLEBLOB;
    ENC_FAIL(RSA_CSP_PUBLICKEYBLOB_T, blob, KP_E_INVALIDARG);
}
TEST(kpk_rsa_csp_pub_wrong_type_alloc_clears) {
    REQ_CRYPT32();
    BYTE blob[sizeof kv_rsa_csp_pub]; memcpy(blob, kv_rsa_csp_pub, sizeof blob); blob[0] = PRIVATEKEYBLOB;
    BYTE *out = (BYTE *)(ULONG_PTR)1; DWORD cb = 99;
    CHECK(!U(CryptEncodeObjectEx)(KP_ENC, RSA_CSP_PUBLICKEYBLOB_T, blob, CRYPT_ENCODE_ALLOC_FLAG, NULL, &out, &cb));
    CHECK(out == NULL); EXPECT_EQ(cb, 0);
}
TEST(kpk_rsa_csp_pub_magic_and_alg_not_validated_note) {
    REQ_CRYPT32();
    BYTE blob[sizeof kv_rsa_csp_pub]; memcpy(blob, kv_rsa_csp_pub, sizeof blob);
    *(DWORD *)(blob + 8) = 0x41424344;
    DWORD cb = 0; BOOL ok = U(CryptEncodeObjectEx)(KP_ENC, RSA_CSP_PUBLICKEYBLOB_T, blob, 0, NULL, NULL, &cb);
    t_note("bad magic: ok=%d cb=%lu", ok, cb);
    memcpy(blob, kv_rsa_csp_pub, sizeof blob); *(DWORD *)(blob + 4) = CALG_RSA_SIGN;
    cb = 0; ok = U(CryptEncodeObjectEx)(KP_ENC, RSA_CSP_PUBLICKEYBLOB_T, blob, 0, NULL, NULL, &cb);
    t_note("aiKeyAlg RSA_SIGN: ok=%d cb=%lu", ok, cb);
}
TEST(kpk_rsa_csp_pub_decode_errors) {
    REQ_CRYPT32();
    DEC_FAILV(RSA_CSP_PUBLICKEYBLOB_T, KP_E_BADTAG, 2, 1, 1);
    DEC_FAILV(RSA_CSP_PUBLICKEYBLOB_T, KP_E_BADTAG, 0x30, 3, 4, 1, 1);
    DEC_FAILV(RSA_CSP_PUBLICKEYBLOB_T, KP_E_TRUNC, 0x30, 8, 2, 1, 0x0b);
    DEC_FAILV(RSA_CSP_PUBLICKEYBLOB_T, 0, 0x30, 3, 2, 1, 5);                /* exponent missing */
}
TEST(kpk_rsa_csp_pub_alias_of_pkcs_rsa_public) {
    REQ_CRYPT32();
    /* the same struct type is registered under its OID spelling szOID_RSA_RSA? it is not: record the outcome */
    DWORD cb = 0;
    BOOL ok = U(CryptEncodeObjectEx)(KP_ENC, "1.2.840.113549.1.1.1", kv_rsa_csp_pub, 0, NULL, NULL, &cb);
    t_note("encode via OID string rsaEncryption: ok=%d err=0x%lx", ok, ok ? 0 : GetLastError());
}

/* ---------------------------------------------------------------- CNG_RSA_PUBLIC_KEY_BLOB */
static size_t build_cng_pub(BYTE *out) {
    BCRYPT_RSAKEY_BLOB *h = (BCRYPT_RSAKEY_BLOB *)out;
    h->Magic = 0x31415352; h->BitLength = 1024; h->cbPublicExp = 3; h->cbModulus = 128; h->cbPrime1 = 0; h->cbPrime2 = 0;
    out[sizeof *h] = 1; out[sizeof *h + 1] = 0; out[sizeof *h + 2] = 1;
    for (int i = 0; i < 128; i++) out[sizeof *h + 3 + i] = kv_rsa_csp_pub[20 + 127 - i];
    return sizeof *h + 3 + 128;
}
TEST(kpk_cng_rsa_pub_encode) {
    REQ_CRYPT32();
    BYTE blob[256]; size_t n = build_cng_pub(blob);
    ENC_EQ(CNG_RSA_PUBLIC_KEY_BLOB_T, blob, kv_rsa_pkcs1_pub, sizeof kv_rsa_pkcs1_pub);
    (void)n;
}
TEST(kpk_cng_rsa_pub_decode) {
    REQ_CRYPT32();
    BYTE blob[256]; size_t n = build_cng_pub(blob);
    BYTE *r = DEC_OK(CNG_RSA_PUBLIC_KEY_BLOB_T, kv_rsa_pkcs1_pub, sizeof kv_rsa_pkcs1_pub, 0);
    if (r) { CHECK(!memcmp(r, blob, n)); kp_free(r); }
}
TEST(kpk_cng_rsa_pub_wrong_magic) {
    REQ_CRYPT32();
    BYTE blob[256]; build_cng_pub(blob);
    ((BCRYPT_RSAKEY_BLOB *)blob)->Magic = 0x32415352;       /* 'RSA2' is a private-key magic */
    DWORD cb = 0; BOOL ok = U(CryptEncodeObjectEx)(KP_ENC, CNG_RSA_PUBLIC_KEY_BLOB_T, blob, 0, NULL, NULL, &cb);
    t_note("CNG public blob with RSA2 magic: ok=%d err=0x%lx", ok, ok ? 0 : GetLastError());
}

/* ---------------------------------------------------------------- PKCS_RSA_PRIVATE_KEY */
TEST(kpk_rsa_private_encode) {
    REQ_TYPE(PKCS_RSA_PRIVATE_KEY);
    ENC_EQ(PKCS_RSA_PRIVATE_KEY, kv_rsa_csp_priv, kv_rsa_pkcs1_priv, sizeof kv_rsa_pkcs1_priv);
}
TEST(kpk_rsa_private_decode) {
    REQ_TYPE(PKCS_RSA_PRIVATE_KEY);
    BYTE *r = DEC_OK(PKCS_RSA_PRIVATE_KEY, kv_rsa_pkcs1_priv, sizeof kv_rsa_pkcs1_priv, 0);
    if (r) {
        CHECK(!memcmp(r, kv_rsa_csp_priv, sizeof kv_rsa_csp_priv));
        CHECK(r[0] == PRIVATEKEYBLOB && r[1] == 2 && *(DWORD *)(r + 4) == CALG_RSA_KEYX && *(DWORD *)(r + 8) == 0x32415352);
        kp_free(r);
    }
}
TEST(kpk_rsa_private_decode_size_covers_blob) {
    REQ_TYPE(PKCS_RSA_PRIVATE_KEY);
    DWORD cb = 0;
    CHECK(U(CryptDecodeObjectEx)(KP_ENC, PKCS_RSA_PRIVATE_KEY, kv_rsa_pkcs1_priv, sizeof kv_rsa_pkcs1_priv, 0, NULL, NULL, &cb));
    CHECK(cb >= sizeof kv_rsa_csp_priv);
}
TEST(kpk_rsa_private_wrong_blob_type) {
    REQ_TYPE(PKCS_RSA_PRIVATE_KEY);
    BYTE blob[sizeof kv_rsa_csp_priv]; memcpy(blob, kv_rsa_csp_priv, sizeof blob);
    blob[0] = PUBLICKEYBLOB;
    ENC_FAIL(PKCS_RSA_PRIVATE_KEY, blob, KP_E_INVALIDARG);
    blob[0] = 0;
    ENC_FAIL(PKCS_RSA_PRIVATE_KEY, blob, KP_E_INVALIDARG);
}
TEST(kpk_rsa_private_decode_errors) {
    REQ_TYPE(PKCS_RSA_PRIVATE_KEY);
    DEC_FAILV(PKCS_RSA_PRIVATE_KEY, KP_E_BADTAG, 2, 1, 1);
    DEC_FAILV(PKCS_RSA_PRIVATE_KEY, KP_E_TRUNC, 0x30, 9, 2, 1, 0);
    DEC_FAILV(PKCS_RSA_PRIVATE_KEY, 0, 0x30, 3, 2, 1, 0);                   /* only the version */
    DEC_FAILV(PKCS_RSA_PRIVATE_KEY, 0, 0x30, 0);
}
TEST(kpk_rsa_private_decode_public_der_fails) {
    REQ_TYPE(PKCS_RSA_PRIVATE_KEY);
    DEC_FAIL(PKCS_RSA_PRIVATE_KEY, kv_rsa_pkcs1_pub, sizeof kv_rsa_pkcs1_pub, 0);
}
TEST(kpk_rsa_private_roundtrip_via_decode) {
    REQ_TYPE(PKCS_RSA_PRIVATE_KEY);
    DWORD cb; BYTE *e = kp_enc_alloc(PKCS_RSA_PRIVATE_KEY, kv_rsa_csp_priv, 0, &cb);
    CHECK(e && cb == sizeof kv_rsa_pkcs1_priv);
    if (e) {
        BYTE *d = kp_dec_alloc(PKCS_RSA_PRIVATE_KEY, e, cb, 0, NULL);
        CHECK(d && !memcmp(d, kv_rsa_csp_priv, sizeof kv_rsa_csp_priv));
        kp_free(d); kp_free(e);
    }
}

/* ---------------------------------------------------------------- PKCS_PRIVATE_KEY_INFO */
TEST(kpk_pkcs8_encode_matches_vector) {
    REQ_TYPE(PKCS_PRIVATE_KEY_INFO);
    CRYPT_PRIVATE_KEY_INFO p; memset(&p, 0, sizeof p);
    p.Version = 0; p.Algorithm.pszObjId = (LPSTR)OID_RSA;
    p.PrivateKey.cbData = sizeof kv_rsa_pkcs1_priv; p.PrivateKey.pbData = (BYTE *)kv_rsa_pkcs1_priv;
    ENC_EQ(PKCS_PRIVATE_KEY_INFO, &p, kv_rsa_pkcs8, sizeof kv_rsa_pkcs8);
}
TEST(kpk_pkcs8_decode_vector) {
    REQ_TYPE(PKCS_PRIVATE_KEY_INFO);
    CRYPT_PRIVATE_KEY_INFO *r = DEC_OK(PKCS_PRIVATE_KEY_INFO, kv_rsa_pkcs8, sizeof kv_rsa_pkcs8, 0);
    if (r) {
        CHECK(r->Version == 0); EXPECT_STR(r->Algorithm.pszObjId, OID_RSA);
        BLOB_IS(r->Algorithm.Parameters, 5, 0);
        CHECK(r->PrivateKey.cbData == sizeof kv_rsa_pkcs1_priv && !memcmp(r->PrivateKey.pbData, kv_rsa_pkcs1_priv, r->PrivateKey.cbData));
        CHECK(r->pAttributes == NULL);
        kp_free(r);
    }
}
TEST(kpk_pkcs8_small_encode) {
    REQ_TYPE(PKCS_PRIVATE_KEY_INFO);
    CRYPT_PRIVATE_KEY_INFO p; memset(&p, 0, sizeof p);
    p.Version = 0; p.Algorithm.pszObjId = (LPSTR)"1.2.3"; p.PrivateKey.cbData = 2; p.PrivateKey.pbData = (BYTE *)"\xaa\xbb";
    ENC_EQ(PKCS_PRIVATE_KEY_INFO, &p, V(0x30,0x0f, 2,1,0, 0x30,0x06,6,2,0x2a,3,5,0, 4,2,0xaa,0xbb));
    p.Version = 1;
    ENC_EQ(PKCS_PRIVATE_KEY_INFO, &p, V(0x30,0x0f, 2,1,1, 0x30,0x06,6,2,0x2a,3,5,0, 4,2,0xaa,0xbb));
}
TEST(kpk_pkcs8_explicit_params) {
    REQ_TYPE(PKCS_PRIVATE_KEY_INFO);
    CRYPT_PRIVATE_KEY_INFO p; memset(&p, 0, sizeof p);
    p.Algorithm.pszObjId = (LPSTR)"1.2.3"; p.Algorithm.Parameters.cbData = 3; p.Algorithm.Parameters.pbData = (BYTE *)"\x04\x01\x07";
    p.PrivateKey.cbData = 1; p.PrivateKey.pbData = (BYTE *)"\x09";
    ENC_EQ(PKCS_PRIVATE_KEY_INFO, &p, V(0x30,0x0f, 2,1,0, 0x30,0x07,6,2,0x2a,3,4,1,7, 4,1,9));
}
TEST(kpk_pkcs8_with_attributes) {
    REQ_TYPE(PKCS_PRIVATE_KEY_INFO);
    CRYPT_PRIVATE_KEY_INFO p; memset(&p, 0, sizeof p);
    CRYPT_ATTRIBUTE at; CRYPT_ATTR_BLOB v = { 3, (BYTE *)"\x02\x01\x05" };
    at.pszObjId = (LPSTR)"1.2.3"; at.cValue = 1; at.rgValue = &v;
    CRYPT_ATTRIBUTES as = { 1, &at };
    p.Algorithm.pszObjId = (LPSTR)"1.2.3"; p.PrivateKey.cbData = 1; p.PrivateKey.pbData = (BYTE *)"\x09"; p.pAttributes = &as;
    /* attributes are an implicit [0] SET OF Attribute after the key */
    ENC_EQ(PKCS_PRIVATE_KEY_INFO, &p, V(0x30,0x1b, 2,1,0, 0x30,0x06,6,2,0x2a,3,5,0, 4,1,9, 0xa0,0x0b, 0x30,0x09,6,2,0x2a,3,0x31,3,2,1,5));
}
TEST(kpk_pkcs8_decode_errors) {
    REQ_TYPE(PKCS_PRIVATE_KEY_INFO);
    DEC_FAILV(PKCS_PRIVATE_KEY_INFO, KP_E_BADTAG, 2, 1, 0);
    DEC_FAILV(PKCS_PRIVATE_KEY_INFO, KP_E_BADTAG, 0x30, 3, 4, 1, 0);
    DEC_FAILV(PKCS_PRIVATE_KEY_INFO, 0, 0x30, 3, 2, 1, 0);
    DEC_FAILV(PKCS_PRIVATE_KEY_INFO, KP_E_TRUNC, 0x30, 0x0f, 2, 1, 0, 0x30, 6);
}
TEST(kpk_pkcs8_encode_bad_oid) {
    REQ_TYPE(PKCS_PRIVATE_KEY_INFO);
    CRYPT_PRIVATE_KEY_INFO p; memset(&p, 0, sizeof p);
    p.Algorithm.pszObjId = (LPSTR)"bogus"; p.PrivateKey.cbData = 1; p.PrivateKey.pbData = (BYTE *)"\x09";
    ENC_FAIL(PKCS_PRIVATE_KEY_INFO, &p, 0);
}

/* ---------------------------------------------------------------- PKCS_ENCRYPTED_PRIVATE_KEY_INFO */
TEST(kpk_encrypted_pkcs8_encode) {
    REQ_TYPE(PKCS_ENCRYPTED_PRIVATE_KEY_INFO);
    CRYPT_ENCRYPTED_PRIVATE_KEY_INFO e; memset(&e, 0, sizeof e);
    e.EncryptionAlgorithm.pszObjId = (LPSTR)szOID_RSA_DES_EDE3_CBC;
    e.EncryptionAlgorithm.Parameters.cbData = 10; e.EncryptionAlgorithm.Parameters.pbData = (BYTE *)"\x04\x08\x01\x02\x03\x04\x05\x06\x07\x08";
    e.EncryptedPrivateKey.cbData = 4; e.EncryptedPrivateKey.pbData = (BYTE *)"\xde\xad\xbe\xef";
    ENC_EQ(PKCS_ENCRYPTED_PRIVATE_KEY_INFO, &e, V(0x30,0x1c, 0x30,0x14,6,8,0x2a,0x86,0x48,0x86,0xf7,0x0d,3,7, 4,8,1,2,3,4,5,6,7,8, 4,4,0xde,0xad,0xbe,0xef));
}
TEST(kpk_encrypted_pkcs8_encode_no_params_emits_null) {
    REQ_TYPE(PKCS_ENCRYPTED_PRIVATE_KEY_INFO);
    CRYPT_ENCRYPTED_PRIVATE_KEY_INFO e; memset(&e, 0, sizeof e);
    e.EncryptionAlgorithm.pszObjId = (LPSTR)"1.2.3";
    e.EncryptedPrivateKey.cbData = 1; e.EncryptedPrivateKey.pbData = (BYTE *)"\x01";
    ENC_EQ(PKCS_ENCRYPTED_PRIVATE_KEY_INFO, &e, V(0x30,0x0b, 0x30,0x06,6,2,0x2a,3,5,0, 4,1,1));
}
TEST(kpk_encrypted_pkcs8_decode) {
    REQ_TYPE(PKCS_ENCRYPTED_PRIVATE_KEY_INFO);
    CRYPT_ENCRYPTED_PRIVATE_KEY_INFO *r = DEC_OK(PKCS_ENCRYPTED_PRIVATE_KEY_INFO,
        V(0x30,0x1c, 0x30,0x14,6,8,0x2a,0x86,0x48,0x86,0xf7,0x0d,3,7, 4,8,1,2,3,4,5,6,7,8, 4,4,0xde,0xad,0xbe,0xef), 0);
    if (r) {
        EXPECT_STR(r->EncryptionAlgorithm.pszObjId, szOID_RSA_DES_EDE3_CBC);
        BLOB_IS(r->EncryptionAlgorithm.Parameters, 4,8,1,2,3,4,5,6,7,8);
        BLOB_IS(r->EncryptedPrivateKey, 0xde,0xad,0xbe,0xef);
        kp_free(r);
    }
}
TEST(kpk_encrypted_pkcs8_decode_errors) {
    REQ_TYPE(PKCS_ENCRYPTED_PRIVATE_KEY_INFO);
    DEC_FAILV(PKCS_ENCRYPTED_PRIVATE_KEY_INFO, KP_E_BADTAG, 4, 1, 1);
    DEC_FAILV(PKCS_ENCRYPTED_PRIVATE_KEY_INFO, KP_E_BADTAG, 0x30, 0x0b, 0x30,0x06,6,2,0x2a,3,5,0, 3,1,0);
    DEC_FAILV(PKCS_ENCRYPTED_PRIVATE_KEY_INFO, 0, 0x30, 0x08, 0x30,0x06,6,2,0x2a,3,5,0);
}

/* ---------------------------------------------------------------- X509_DSS_PARAMETERS */
TEST(kpk_dss_parameters_encode) {
    REQ_TYPE(X509_DSS_PARAMETERS);
    BYTE p[] = {0x0b}, q[] = {0x05}, g[] = {0x02};
    CERT_DSS_PARAMETERS d = { {1, p}, {1, q}, {1, g} };
    ENC_EQ(X509_DSS_PARAMETERS, &d, V(0x30,9, 2,1,0x0b, 2,1,5, 2,1,2));
}
TEST(kpk_dss_parameters_encode_high_bit_padding) {
    REQ_TYPE(X509_DSS_PARAMETERS);
    BYTE p[] = {0xff,0x80}, q[] = {0x81}, g[] = {0x00,0x00,0x7f};
    CERT_DSS_PARAMETERS d = { {2, p}, {1, q}, {3, g} };
    /* little endian unsigned: 0x80ff -> 00 80 ff, 0x81 -> 00 81, 0x7f0000 -> 7f 00 00 */
    ENC_EQ(X509_DSS_PARAMETERS, &d, V(0x30,0x0e, 2,3,0,0x80,0xff, 2,2,0,0x81, 2,3,0x7f,0,0));
}
TEST(kpk_dss_parameters_decode) {
    REQ_TYPE(X509_DSS_PARAMETERS);
    CERT_DSS_PARAMETERS *r = DEC_OK(X509_DSS_PARAMETERS, V(0x30,0x0e, 2,3,0,0x80,0xff, 2,2,0,0x81, 2,3,0x7f,0,0), 0);
    if (r) { BLOB_IS(r->p, 0xff,0x80); BLOB_IS(r->q, 0x81); BLOB_IS(r->g, 0,0,0x7f); kp_free(r); }
}
TEST(kpk_dss_parameters_roundtrip_160_bit) {
    REQ_TYPE(X509_DSS_PARAMETERS);
    BYTE p[128], q[20], g[128]; for (int i = 0; i < 128; i++) { p[i] = (BYTE)(i * 7 + 3); g[i] = (BYTE)(i * 5 + 1); } for (int i = 0; i < 20; i++) q[i] = (BYTE)(0xf0 - i);
    p[127] |= 0x80; g[127] |= 0x80; q[19] = 0xf0;
    CERT_DSS_PARAMETERS d = { {128, p}, {20, q}, {128, g} }; DWORD cb;
    BYTE *e = kp_enc_alloc(X509_DSS_PARAMETERS, &d, 0, &cb);
    CHECK(e != NULL);
    if (e) {
        CERT_DSS_PARAMETERS *r = kp_dec_alloc(X509_DSS_PARAMETERS, e, cb, 0, NULL);
        CHECK(r && r->p.cbData == 128 && r->q.cbData == 20 && r->g.cbData == 128 && !memcmp(r->p.pbData, p, 128) && !memcmp(r->q.pbData, q, 20) && !memcmp(r->g.pbData, g, 128));
        kp_free(r); kp_free(e);
    }
}
TEST(kpk_dss_parameters_decode_errors) {
    REQ_TYPE(X509_DSS_PARAMETERS);
    DEC_FAILV(X509_DSS_PARAMETERS, KP_E_BADTAG, 2, 1, 1);
    DEC_FAILV(X509_DSS_PARAMETERS, 0, 0x30, 6, 2, 1, 1, 2, 1, 2);        /* g missing */
    DEC_FAILV(X509_DSS_PARAMETERS, KP_E_TRUNC, 0x30, 9, 2, 1, 1, 2, 1, 2);
}

/* ---------------------------------------------------------------- X509_DSS_SIGNATURE */
TEST(kpk_dss_signature_encode_basic) {
    REQ_TYPE(X509_DSS_SIGNATURE);
    BYTE sig[40]; memset(sig, 0, sizeof sig);
    sig[0] = 1; sig[20] = 2;       /* r = 1, s = 2 (each 20 bytes little endian) */
    ENC_EQ(X509_DSS_SIGNATURE, sig, V(0x30,6, 2,1,1, 2,1,2));
}
TEST(kpk_dss_signature_encode_full_width) {
    REQ_TYPE(X509_DSS_SIGNATURE);
    BYTE sig[40]; for (int i = 0; i < 40; i++) sig[i] = (BYTE)(i + 1);
    /* r bytes (LE) 01..14 -> BE 14 13 .. 01 ; top byte 0x14 < 0x80 => 20 bytes; s bytes 15..28 -> BE 28 .. 15 => 0x28 < 0x80 */
    BYTE want[2 + 22 + 22]; int o = 0; want[o++] = 0x30; want[o++] = 44;
    want[o++] = 2; want[o++] = 20; for (int i = 19; i >= 0; i--) want[o++] = sig[i];
    want[o++] = 2; want[o++] = 20; for (int i = 39; i >= 20; i--) want[o++] = sig[i];
    ENC_EQ(X509_DSS_SIGNATURE, sig, want, o);
}
TEST(kpk_dss_signature_encode_high_bit_pads) {
    REQ_TYPE(X509_DSS_SIGNATURE);
    BYTE sig[40]; memset(sig, 0x11, sizeof sig); sig[19] = 0x80; sig[39] = 0xff;
    DWORD cb; BYTE *e = kp_enc_alloc(X509_DSS_SIGNATURE, sig, 0, &cb);
    CHECK(e && cb == 2 + 22 + 22 && e[0] == 0x30 && e[1] == 44 && e[2] == 2 && e[3] == 21 && e[4] == 0 && e[5] == 0x80);
    if (e && cb == 48) CHECK(e[26] == 2 && e[27] == 21 && e[28] == 0 && e[29] == 0xff);
    kp_free(e);
}
TEST(kpk_dss_signature_encode_zero_values) {
    REQ_TYPE(X509_DSS_SIGNATURE);
    BYTE sig[40]; memset(sig, 0, sizeof sig);
    ENC_EQ(X509_DSS_SIGNATURE, sig, V(0x30,6, 2,1,0, 2,1,0));
}
TEST(kpk_dss_signature_decode_basic) {
    REQ_TYPE(X509_DSS_SIGNATURE);
    BYTE *r = DEC_OK(X509_DSS_SIGNATURE, V(0x30,6, 2,1,1, 2,1,2), 0);
    if (r) {
        DWORD cb = 0;
        U(CryptDecodeObjectEx)(KP_ENC, X509_DSS_SIGNATURE, (const BYTE[]){0x30,6,2,1,1,2,1,2}, 8, 0, NULL, NULL, &cb);
        CHECK(cb >= 40);
        CHECK(r[0] == 1 && r[20] == 2);
        int z = 1; for (int i = 0; i < 40; i++) if (i != 0 && i != 20 && r[i]) z = 0;
        CHECK(z);
        kp_free(r);
    }
}
TEST(kpk_dss_signature_roundtrip_random) {
    REQ_TYPE(X509_DSS_SIGNATURE);
    BYTE sig[40]; unsigned x = 12345;
    for (int round = 0; round < 50; round++) {
        for (int i = 0; i < 40; i++) { x = x * 1103515245u + 12345u; sig[i] = (BYTE)(x >> 16); }
        DWORD cb; BYTE *e = kp_enc_alloc(X509_DSS_SIGNATURE, sig, 0, &cb);
        CHECK(e != NULL);
        if (!e) continue;
        BYTE *d = kp_dec_alloc(X509_DSS_SIGNATURE, e, cb, 0, NULL);
        CHECK(d && !memcmp(d, sig, 40));
        kp_free(d); kp_free(e);
    }
}
TEST(kpk_dss_signature_decode_errors) {
    REQ_TYPE(X509_DSS_SIGNATURE);
    DEC_FAILV(X509_DSS_SIGNATURE, KP_E_BADTAG, 2, 1, 1);
    DEC_FAILV(X509_DSS_SIGNATURE, 0, 0x30, 3, 2, 1, 1);
    DEC_FAILV(X509_DSS_SIGNATURE, KP_E_TRUNC, 0x30, 6, 2, 1, 1, 2, 1);
}
TEST(kpk_dss_signature_decode_too_wide_value) {
    REQ_TYPE(X509_DSS_SIGNATURE);
    /* r needs 21 significant bytes: does not fit the fixed 20-byte slot */
    BYTE der[2 + 2 + 21 + 3]; int o = 0; der[o++] = 0x30; der[o++] = 2 + 21 + 3; der[o++] = 2; der[o++] = 21; for (int i = 0; i < 21; i++) der[o++] = 0x7f; der[o++] = 2; der[o++] = 1; der[o++] = 1;
    DWORD cb = 4096; BYTE buf[4096];
    BOOL ok = U(CryptDecodeObjectEx)(KP_ENC, X509_DSS_SIGNATURE, der, o, 0, NULL, buf, &cb);
    t_note("21-byte r in DSS signature: ok=%d err=0x%lx", ok, ok ? 0 : GetLastError());
}

/* ---------------------------------------------------------------- X509_ECC_SIGNATURE / DH params (type 47) */
TEST(kpk_ecc_signature_encode) {
    REQ_TYPE(X509_ECC_SIGNATURE);
    BYTE r[] = {0x02, 0x01}, s[] = {0x80};
    CERT_ECC_SIGNATURE sig = { {2, r}, {1, s} };
    ENC_EQ(X509_ECC_SIGNATURE, &sig, V(0x30,8, 2,2,1,2, 2,2,0,0x80));
}
TEST(kpk_ecc_signature_decode) {
    REQ_TYPE(X509_ECC_SIGNATURE);
    CERT_ECC_SIGNATURE *sig = DEC_OK(X509_ECC_SIGNATURE, V(0x30,8, 2,2,1,2, 2,2,0,0x80), 0);
    if (sig) { BLOB_IS(sig->r, 2, 1); BLOB_IS(sig->s, 0x80); kp_free(sig); }
}
TEST(kpk_ecc_signature_p256_roundtrip) {
    REQ_TYPE(X509_ECC_SIGNATURE);
    BYTE r[32], s[32]; for (int i = 0; i < 32; i++) { r[i] = (BYTE)(0xa0 + i); s[i] = (BYTE)(i * 3); }
    r[31] = 0x90; s[31] = 0x7f;
    CERT_ECC_SIGNATURE sig = { {32, r}, {32, s} }; DWORD cb;
    BYTE *e = kp_enc_alloc(X509_ECC_SIGNATURE, &sig, 0, &cb);
    CHECK(e && cb == 2 + (2 + 33) + (2 + 32));
    if (e) {
        CERT_ECC_SIGNATURE *d = kp_dec_alloc(X509_ECC_SIGNATURE, e, cb, 0, NULL);
        CHECK(d && d->r.cbData == 32 && d->s.cbData == 32 && !memcmp(d->r.pbData, r, 32) && !memcmp(d->s.pbData, s, 32));
        kp_free(d); kp_free(e);
    }
}
TEST(kpk_ecc_signature_leading_zero_values) {
    REQ_TYPE(X509_ECC_SIGNATURE);
    BYTE r[] = {0x05, 0x00, 0x00}, s[] = {0x00};
    CERT_ECC_SIGNATURE sig = { {3, r}, {1, s} };
    ENC_EQ(X509_ECC_SIGNATURE, &sig, V(0x30,6, 2,1,5, 2,1,0));
}
TEST(kpk_ecc_signature_decode_errors) {
    REQ_TYPE(X509_ECC_SIGNATURE);
    DEC_FAILV(X509_ECC_SIGNATURE, KP_E_BADTAG, 2, 1, 1);
    DEC_FAILV(X509_ECC_SIGNATURE, 0, 0x30, 3, 2, 1, 1);
}

/* ---------------------------------------------------------------- X509_ECC_PRIVATE_KEY */
TEST(kpk_ecc_private_encode_matches_vector) {
    REQ_TYPE(X509_ECC_PRIVATE_KEY);
    CRYPT_ECC_PRIVATE_KEY_INFO k; memset(&k, 0, sizeof k);
    k.dwVersion = CRYPT_ECC_PRIVATE_KEY_INFO_v1;
    k.PrivateKey.cbData = 32; k.PrivateKey.pbData = (BYTE *)kv_ec_priv_d;
    k.szCurveOid = (LPSTR)szOID_ECC_CURVE_P256;
    k.PublicKey.cbData = 65; k.PublicKey.pbData = (BYTE *)kv_ec_pub_point;
    ENC_EQ(X509_ECC_PRIVATE_KEY, &k, kv_ec_sec1, sizeof kv_ec_sec1);
}
TEST(kpk_ecc_private_decode_vector) {
    REQ_TYPE(X509_ECC_PRIVATE_KEY);
    CRYPT_ECC_PRIVATE_KEY_INFO *r = DEC_OK(X509_ECC_PRIVATE_KEY, kv_ec_sec1, sizeof kv_ec_sec1, 0);
    if (r) {
        CHECK(r->dwVersion == 1);
        BLOB_IS(r->PrivateKey, 0);   /* replaced below: compare with the vector */
        kp_free(r);
    }
}
TEST(kpk_ecc_private_decode_fields) {
    REQ_TYPE(X509_ECC_PRIVATE_KEY);
    CRYPT_ECC_PRIVATE_KEY_INFO *r = kp_dec_alloc(X509_ECC_PRIVATE_KEY, kv_ec_sec1, sizeof kv_ec_sec1, 0, NULL);
    CHECK(r != NULL);
    if (r) {
        CHECK(r->dwVersion == 1);
        CHECK(r->PrivateKey.cbData == 32 && !memcmp(r->PrivateKey.pbData, kv_ec_priv_d, 32));
        CHECK(r->szCurveOid && !strcmp(r->szCurveOid, szOID_ECC_CURVE_P256));
        CHECK(r->PublicKey.cbData == 65 && r->PublicKey.cUnusedBits == 0 && !memcmp(r->PublicKey.pbData, kv_ec_pub_point, 65));
        kp_free(r);
    }
}
TEST(kpk_ecc_private_optional_parts) {
    REQ_TYPE(X509_ECC_PRIVATE_KEY);
    BYTE d[] = {1,2,3};
    CRYPT_ECC_PRIVATE_KEY_INFO k; memset(&k, 0, sizeof k);
    k.dwVersion = 1; k.PrivateKey.cbData = 3; k.PrivateKey.pbData = d;
    ENC_EQ(X509_ECC_PRIVATE_KEY, &k, V(0x30,8, 2,1,1, 4,3,1,2,3));
    k.szCurveOid = (LPSTR)"";
    ENC_EQ(X509_ECC_PRIVATE_KEY, &k, V(0x30,8, 2,1,1, 4,3,1,2,3));            /* empty curve string means absent */
    k.szCurveOid = (LPSTR)"1.2.3";
    ENC_EQ(X509_ECC_PRIVATE_KEY, &k, V(0x30,0x0e, 2,1,1, 4,3,1,2,3, 0xa0,4,6,2,0x2a,3));
    k.szCurveOid = NULL; k.PublicKey.cbData = 2; k.PublicKey.pbData = (BYTE *)"\x04\x05";
    ENC_EQ(X509_ECC_PRIVATE_KEY, &k, V(0x30,0x0f, 2,1,1, 4,3,1,2,3, 0xa1,5,3,3,0,4,5));
    k.PublicKey.cUnusedBits = 3;
    ENC_EQ(X509_ECC_PRIVATE_KEY, &k, V(0x30,0x0f, 2,1,1, 4,3,1,2,3, 0xa1,5,3,3,3,4,5));
}
TEST(kpk_ecc_private_bad_curve_oid) {
    REQ_TYPE(X509_ECC_PRIVATE_KEY);
    BYTE d[] = {1};
    CRYPT_ECC_PRIVATE_KEY_INFO k; memset(&k, 0, sizeof k);
    k.dwVersion = 1; k.PrivateKey.cbData = 1; k.PrivateKey.pbData = d; k.szCurveOid = (LPSTR)"not-an-oid";
    ENC_FAIL(X509_ECC_PRIVATE_KEY, &k, 0);
}
TEST(kpk_ecc_private_decode_without_optional_parts) {
    REQ_TYPE(X509_ECC_PRIVATE_KEY);
    CRYPT_ECC_PRIVATE_KEY_INFO *r = DEC_OK(X509_ECC_PRIVATE_KEY, V(0x30,8, 2,1,1, 4,3,1,2,3), 0);
    if (r) { CHECK(r->dwVersion == 1); BLOB_IS(r->PrivateKey, 1,2,3); CHECK(r->szCurveOid == NULL || r->szCurveOid[0] == 0); CHECK(r->PublicKey.cbData == 0); kp_free(r); }
}
TEST(kpk_ecc_private_decode_errors) {
    REQ_TYPE(X509_ECC_PRIVATE_KEY);
    DEC_FAILV(X509_ECC_PRIVATE_KEY, KP_E_BADTAG, 4, 1, 1);
    DEC_FAILV(X509_ECC_PRIVATE_KEY, 0, 0x30, 3, 2, 1, 1);
    DEC_FAILV(X509_ECC_PRIVATE_KEY, KP_E_BADTAG, 0x30, 8, 4, 3, 1, 2, 3, 2, 1, 1);
}
TEST(kpk_ecc_private_sec1_rsa_der_mismatch) {
    REQ_TYPE(X509_ECC_PRIVATE_KEY);
    DEC_FAIL(X509_ECC_PRIVATE_KEY, kv_rsa_pkcs1_priv, sizeof kv_rsa_pkcs1_priv, 0);
}
