/* Sign/verify, encrypt/decrypt, secret agreement, KDFs and handle translation on ephemeral keys. */
#include "nc.h"

#define NC_BAD_ALGID 0x80090008u

static NTSTATUS nc_hash(LPCWSTR alg, const BYTE *key, ULONG ck, const BYTE *data, ULONG cd, BYTE *out, ULONG co)
{
    BCRYPT_ALG_HANDLE h = NULL;
    NTSTATUS s = U(BCryptOpenAlgorithmProvider)(&h, alg, NULL, key ? BCRYPT_ALG_HANDLE_HMAC_FLAG : 0);
    if (s) return s;
    s = U(BCryptHash)(h, (PUCHAR)key, ck, (PUCHAR)data, cd, out, co);
    U(BCryptCloseAlgorithmProvider)(h, 0);
    return s;
}

static NCRYPT_KEY_HANDLE g_prov_dummy;
/* imports the fixed RSA-1024 private key used for the known answers */
static NCRYPT_KEY_HANDLE rsa_priv(NCRYPT_PROV_HANDLE p) { return nc_import(p, BCRYPT_RSAFULLPRIVATE_BLOB, NCV(k_rsa_full)); }
static NCRYPT_KEY_HANDLE rsa_pub(NCRYPT_PROV_HANDLE p) { return nc_import(p, BCRYPT_RSAPUBLIC_BLOB, NCV(k_rsa_pub)); }

/* ---------- RSA PKCS#1 v1.5 signatures: known answers ---------- */
typedef struct { LPCWSTR alg; const BYTE *dig; DWORD cd; const BYTE *sig; } pk1row_t;
#define PK1(a, d, s) { a, d, sizeof d, s }
static const pk1row_t PK1S[] = {
    PK1(BCRYPT_SHA1_ALGORITHM, k_dig_sha1, k_rsa_pkcs1_sha1), PK1(BCRYPT_SHA256_ALGORITHM, k_dig_sha256, k_rsa_pkcs1_sha256),
    PK1(BCRYPT_SHA384_ALGORITHM, k_dig_sha384, k_rsa_pkcs1_sha384), PK1(BCRYPT_SHA512_ALGORITHM, k_dig_sha512, k_rsa_pkcs1_sha512),
};
TEST(ncops_rsa_pkcs1_sign_known_answers) {
    REQUIRE(U(NCryptSignHash));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE k = rsa_priv(p); NEED(k, "RSA key");
    for (size_t i = 0; i < 4; i++) {
        BCRYPT_PKCS1_PADDING_INFO pi = { PK1S[i].alg };
        BYTE sig[128]; DWORD cb = 0;
        EXPECT_SS(U(NCryptSignHash)(k, &pi, (PBYTE)PK1S[i].dig, PK1S[i].cd, sig, sizeof sig, &cb, BCRYPT_PAD_PKCS1), 0);
        EXPECT_EQ(cb, 128);
        CHECKF(!memcmp(sig, PK1S[i].sig, 128), "%ls PKCS1 signature differs from known answer", PK1S[i].alg);
    }
    nc_free(k); nc_free(p);
}
TEST(ncops_rsa_pkcs1_verify_known_answers) {
    REQUIRE(U(NCryptVerifySignature));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE k = rsa_pub(p); NEED(k, "RSA public key");
    for (size_t i = 0; i < 4; i++) {
        BCRYPT_PKCS1_PADDING_INFO pi = { PK1S[i].alg };
        EXPECT_SS(U(NCryptVerifySignature)(k, &pi, (PBYTE)PK1S[i].dig, PK1S[i].cd, (PBYTE)PK1S[i].sig, 128, BCRYPT_PAD_PKCS1), 0);
        /* the signature does not verify under another hash id */
        BCRYPT_PKCS1_PADDING_INFO other = { PK1S[(i + 1) % 4].alg };
        SECURITY_STATUS s = U(NCryptVerifySignature)(k, &other, (PBYTE)PK1S[i].dig, PK1S[i].cd, (PBYTE)PK1S[i].sig, 128, BCRYPT_PAD_PKCS1);
        EXPECT_SS_FAIL(s);
    }
    nc_free(k); nc_free(p);
}
TEST(ncops_rsa_pkcs1_verify_tamper) {
    REQUIRE(U(NCryptVerifySignature));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE k = rsa_pub(p); NEED(k, "RSA public key");
    BCRYPT_PKCS1_PADDING_INFO pi = { BCRYPT_SHA256_ALGORITHM };
    BYTE sig[128], dig[32];
    memcpy(sig, k_rsa_pkcs1_sha256, 128); sig[64] ^= 1;
    EXPECT_SS(U(NCryptVerifySignature)(k, &pi, (PBYTE)k_dig_sha256, 32, sig, 128, BCRYPT_PAD_PKCS1), NC_BAD_SIGNATURE);
    memcpy(dig, k_dig_sha256, 32); dig[31] ^= 1;
    EXPECT_SS(U(NCryptVerifySignature)(k, &pi, dig, 32, (PBYTE)k_rsa_pkcs1_sha256, 128, BCRYPT_PAD_PKCS1), NC_BAD_SIGNATURE);
    SECURITY_STATUS s = U(NCryptVerifySignature)(k, &pi, (PBYTE)k_dig_sha256, 32, (PBYTE)k_rsa_pkcs1_sha256, 127, BCRYPT_PAD_PKCS1);
    EXPECT_SS_FAIL(s); t_note("verify with 127-byte signature -> 0x%08lx", (DWORD)s);
    s = U(NCryptVerifySignature)(k, &pi, (PBYTE)k_dig_sha256, 32, (PBYTE)k_rsa_pkcs1_sha256, 0, BCRYPT_PAD_PKCS1);
    EXPECT_SS_FAIL(s); t_note("verify with empty signature -> 0x%08lx", (DWORD)s);
    memset(sig, 0, 128);
    EXPECT_SS(U(NCryptVerifySignature)(k, &pi, (PBYTE)k_dig_sha256, 32, sig, 128, BCRYPT_PAD_PKCS1), NC_BAD_SIGNATURE);
    memset(sig, 0xFF, 128);   /* signature value >= modulus */
    s = U(NCryptVerifySignature)(k, &pi, (PBYTE)k_dig_sha256, 32, sig, 128, BCRYPT_PAD_PKCS1);
    EXPECT_SS_FAIL(s); t_note("verify with signature >= modulus -> 0x%08lx", (DWORD)s);
    nc_free(k); nc_free(p);
}
TEST(ncops_rsa_sign_size_protocol) {
    REQUIRE(U(NCryptSignHash));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE k = rsa_priv(p); NEED(k, "RSA key");
    BCRYPT_PKCS1_PADDING_INFO pi = { BCRYPT_SHA256_ALGORITHM };
    DWORD cb = 0xFFFF; BYTE sig[256];
    EXPECT_SS(U(NCryptSignHash)(k, &pi, (PBYTE)k_dig_sha256, 32, NULL, 0, &cb, BCRYPT_PAD_PKCS1), 0);
    EXPECT_EQ(cb, 128);
    static const DWORD small[] = { 0, 1, 64, 127 };
    for (int i = 0; i < 4; i++) {
        cb = 0xFFFF;
        EXPECT_SS(U(NCryptSignHash)(k, &pi, (PBYTE)k_dig_sha256, 32, sig, small[i], &cb, BCRYPT_PAD_PKCS1), NC_BUFFER_TOO_SMALL);
        EXPECT_EQ(cb, 128);
    }
    cb = 0; EXPECT_SS(U(NCryptSignHash)(k, &pi, (PBYTE)k_dig_sha256, 32, sig, 128, &cb, BCRYPT_PAD_PKCS1), 0); EXPECT_EQ(cb, 128);
    cb = 0; EXPECT_SS(U(NCryptSignHash)(k, &pi, (PBYTE)k_dig_sha256, 32, sig, 256, &cb, BCRYPT_PAD_PKCS1), 0); EXPECT_EQ(cb, 128);
    nc_free(k); nc_free(p);
}
TEST(ncops_rsa_sign_parameter_errors) {
    REQUIRE(U(NCryptSignHash));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE k = rsa_priv(p); NEED(k, "RSA key");
    BYTE sig[128]; DWORD cb = 0; SECURITY_STATUS s;
    BCRYPT_PKCS1_PADDING_INFO pi = { BCRYPT_SHA256_ALGORITHM };
    s = U(NCryptSignHash)(k, NULL, (PBYTE)k_dig_sha256, 32, sig, 128, &cb, BCRYPT_PAD_PKCS1);
    EXPECT_SS_FAIL(s); t_note("PKCS1 flag without padding info -> 0x%08lx", (DWORD)s);
    s = U(NCryptSignHash)(k, NULL, (PBYTE)k_dig_sha256, 32, sig, 128, &cb, 0);
    EXPECT_SS_FAIL(s); t_note("RSA sign with no padding flag -> 0x%08lx", (DWORD)s);
    s = U(NCryptSignHash)(k, &pi, (PBYTE)k_dig_sha1, 20, sig, 128, &cb, BCRYPT_PAD_PKCS1);
    EXPECT_SS_FAIL(s); t_note("SHA256 padding info with a 20-byte hash -> 0x%08lx", (DWORD)s);
    BCRYPT_PKCS1_PADDING_INFO bad = { L"cryptt-no-such-hash" };
    s = U(NCryptSignHash)(k, &bad, (PBYTE)k_dig_sha256, 32, sig, 128, &cb, BCRYPT_PAD_PKCS1);
    EXPECT_SS_FAIL(s); t_note("unknown padding hash id -> 0x%08lx", (DWORD)s);
    s = U(NCryptSignHash)(k, &pi, NULL, 32, sig, 128, &cb, BCRYPT_PAD_PKCS1);
    EXPECT_SS_FAIL(s);
    s = U(NCryptSignHash)(k, &pi, (PBYTE)k_dig_sha256, 0, sig, 128, &cb, BCRYPT_PAD_PKCS1);
    EXPECT_SS_FAIL(s);
    s = U(NCryptSignHash)(k, &pi, (PBYTE)k_dig_sha256, 32, sig, 128, NULL, BCRYPT_PAD_PKCS1);
    EXPECT_SS_FAIL(s); t_note("pcbResult NULL -> 0x%08lx", (DWORD)s);
    s = U(NCryptSignHash)(k, &pi, (PBYTE)k_dig_sha256, 32, sig, 128, &cb, BCRYPT_PAD_PKCS1 | BCRYPT_PAD_PSS);
    EXPECT_SS_FAIL(s);
    s = U(NCryptSignHash)(k, &pi, (PBYTE)k_dig_sha256, 32, sig, 128, &cb, 0x10000000);
    EXPECT_SS_FAIL(s); t_note("unknown sign flag -> 0x%08lx", (DWORD)s);
    nc_free(k); nc_free(p);
}
TEST(ncops_rsa_sign_raw_digestinfo_note) {
    REQUIRE(U(NCryptSignHash));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE k = rsa_priv(p); NEED(k, "RSA key");
    BCRYPT_PKCS1_PADDING_INFO pi = { NULL };   /* no hash id: caller supplies the DigestInfo */
    BYTE sig[128]; DWORD cb = 0;
    SECURITY_STATUS s = U(NCryptSignHash)(k, &pi, (PBYTE)k_dig_sha256, 32, sig, 128, &cb, BCRYPT_PAD_PKCS1);
    t_note("PKCS1 sign with pszAlgId NULL and 32-byte input -> 0x%08lx", (DWORD)s);
    if (s == 0) t_note("   signature %s the SHA256 DigestInfo signature", memcmp(sig, k_rsa_pkcs1_sha256, 128) ? "differs from" : "equals");
    nc_free(k); nc_free(p);
}
TEST(ncops_rsa_pss_known_answers) {
    REQUIRE(U(NCryptVerifySignature));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE pub = rsa_pub(p), prv = rsa_priv(p); NEED(pub && prv, "keys");
    BCRYPT_PSS_PADDING_INFO s32 = { BCRYPT_SHA256_ALGORITHM, 32 }, s0 = { BCRYPT_SHA256_ALGORITHM, 0 };
    EXPECT_SS(U(NCryptVerifySignature)(pub, &s32, (PBYTE)k_dig_sha256, 32, (PBYTE)k_rsa_pss_sha256_salt32, 128, BCRYPT_PAD_PSS), 0);
    EXPECT_SS(U(NCryptVerifySignature)(pub, &s0, (PBYTE)k_dig_sha256, 32, (PBYTE)k_rsa_pss_sha256_salt0, 128, BCRYPT_PAD_PSS), 0);
    SECURITY_STATUS s = U(NCryptVerifySignature)(pub, &s0, (PBYTE)k_dig_sha256, 32, (PBYTE)k_rsa_pss_sha256_salt32, 128, BCRYPT_PAD_PSS);
    t_note("verify salt-32 signature with cbSalt=0 -> 0x%08lx", (DWORD)s);
    s = U(NCryptVerifySignature)(pub, &s32, (PBYTE)k_dig_sha256, 32, (PBYTE)k_rsa_pkcs1_sha256, 128, BCRYPT_PAD_PSS);
    EXPECT_SS_FAIL(s);   /* a PKCS#1 signature is not a PSS signature */
    BYTE sig[128]; DWORD cb = 0;
    /* salt length zero makes PSS deterministic */
    EXPECT_SS(U(NCryptSignHash)(prv, &s0, (PBYTE)k_dig_sha256, 32, sig, 128, &cb, BCRYPT_PAD_PSS), 0);
    CHECK(!memcmp(sig, k_rsa_pss_sha256_salt0, 128));
    nc_free(pub); nc_free(prv); nc_free(p);
}
TEST(ncops_rsa_pss_sign_random_salt) {
    REQUIRE(U(NCryptSignHash));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE pub = rsa_pub(p), prv = rsa_priv(p); NEED(pub && prv, "keys");
    BCRYPT_PSS_PADDING_INFO pi = { BCRYPT_SHA256_ALGORITHM, 32 };
    BYTE a[128], b[128]; DWORD ca = 0, cb = 0;
    EXPECT_SS(U(NCryptSignHash)(prv, &pi, (PBYTE)k_dig_sha256, 32, a, 128, &ca, BCRYPT_PAD_PSS), 0);
    EXPECT_SS(U(NCryptSignHash)(prv, &pi, (PBYTE)k_dig_sha256, 32, b, 128, &cb, BCRYPT_PAD_PSS), 0);
    EXPECT_EQ(ca, 128); CHECK(memcmp(a, b, 128) != 0);
    EXPECT_SS(U(NCryptVerifySignature)(pub, &pi, (PBYTE)k_dig_sha256, 32, a, 128, BCRYPT_PAD_PSS), 0);
    EXPECT_SS(U(NCryptVerifySignature)(pub, &pi, (PBYTE)k_dig_sha256, 32, b, 128, BCRYPT_PAD_PSS), 0);
    a[10] ^= 4;
    EXPECT_SS(U(NCryptVerifySignature)(pub, &pi, (PBYTE)k_dig_sha256, 32, a, 128, BCRYPT_PAD_PSS), NC_BAD_SIGNATURE);
    /* too large a salt for the modulus: 128 - 32 - 2 = 94 is the maximum */
    BCRYPT_PSS_PADDING_INFO big = { BCRYPT_SHA256_ALGORITHM, 95 };
    SECURITY_STATUS s = U(NCryptSignHash)(prv, &big, (PBYTE)k_dig_sha256, 32, a, 128, &ca, BCRYPT_PAD_PSS);
    EXPECT_SS_FAIL(s); t_note("PSS salt 95 with RSA-1024/SHA-256 -> 0x%08lx", (DWORD)s);
    BCRYPT_PSS_PADDING_INFO max = { BCRYPT_SHA256_ALGORITHM, 94 };
    s = U(NCryptSignHash)(prv, &max, (PBYTE)k_dig_sha256, 32, a, 128, &ca, BCRYPT_PAD_PSS);
    t_note("PSS salt 94 (maximum) -> 0x%08lx", (DWORD)s);
    nc_free(pub); nc_free(prv); nc_free(p);
}
TEST(ncops_rsa_generated_key_sign_verify_matrix) {
    REQUIRE(U(NCryptSignHash));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE k = nc_newkey(p, BCRYPT_RSA_ALGORITHM, 1024, 0, TRUE); NEED(k, "RSA key");
    for (size_t i = 0; i < 4; i++) {
        BCRYPT_PKCS1_PADDING_INFO pi = { PK1S[i].alg }; BYTE sig[128]; DWORD cb = 0;
        EXPECT_SS(U(NCryptSignHash)(k, &pi, (PBYTE)PK1S[i].dig, PK1S[i].cd, sig, 128, &cb, BCRYPT_PAD_PKCS1), 0);
        EXPECT_SS(U(NCryptVerifySignature)(k, &pi, (PBYTE)PK1S[i].dig, PK1S[i].cd, sig, cb, BCRYPT_PAD_PKCS1), 0);
        BCRYPT_PSS_PADDING_INFO ps = { PK1S[i].alg, PK1S[i].cd };
        EXPECT_SS(U(NCryptSignHash)(k, &ps, (PBYTE)PK1S[i].dig, PK1S[i].cd, sig, 128, &cb, BCRYPT_PAD_PSS), 0);
        EXPECT_SS(U(NCryptVerifySignature)(k, &ps, (PBYTE)PK1S[i].dig, PK1S[i].cd, sig, cb, BCRYPT_PAD_PSS), 0);
    }
    nc_free(k); nc_free(p);
}

/* ---------- ECDSA ---------- */
static const struct { LPCWSTR alg; DWORD sig; } ECDSA_SIZES[] = { { L"ECDSA_P256", 64 }, { L"ECDSA_P384", 96 }, { L"ECDSA_P521", 132 } };
TEST(ncops_ecdsa_sign_verify_sizes) {
    REQUIRE(U(NCryptSignHash));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    for (int i = 0; i < 3; i++) {
        NCRYPT_KEY_HANDLE k = nc_newkey(p, ECDSA_SIZES[i].alg, 0, 0, TRUE);
        CHECKF(k != 0, "%ls", ECDSA_SIZES[i].alg); if (!k) continue;
        DWORD cb = 0; BYTE sig[160];
        EXPECT_SS(U(NCryptSignHash)(k, NULL, (PBYTE)k_dig_sha256, 32, NULL, 0, &cb, 0), 0);
        EXPECT_EQ(cb, ECDSA_SIZES[i].sig);
        cb = 0xFFFF;
        EXPECT_SS(U(NCryptSignHash)(k, NULL, (PBYTE)k_dig_sha256, 32, sig, ECDSA_SIZES[i].sig - 1, &cb, 0), NC_BUFFER_TOO_SMALL);
        EXPECT_EQ(cb, ECDSA_SIZES[i].sig);
        cb = 0;
        EXPECT_SS(U(NCryptSignHash)(k, NULL, (PBYTE)k_dig_sha256, 32, sig, sizeof sig, &cb, 0), 0);
        EXPECT_EQ(cb, ECDSA_SIZES[i].sig);
        EXPECT_SS(U(NCryptVerifySignature)(k, NULL, (PBYTE)k_dig_sha256, 32, sig, cb, 0), 0);
        nc_free(k);
    }
    nc_free(p);
}
TEST(ncops_ecdsa_verify_known_answer) {
    REQUIRE(U(NCryptVerifySignature));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE k = nc_import(p, BCRYPT_ECCPUBLIC_BLOB, NCV(k_ec256_pub)); NEED(k, "key");
    EXPECT_SS(U(NCryptVerifySignature)(k, NULL, (PBYTE)k_dig_sha256, 32, (PBYTE)k_ec256_sig_sha256, 64, 0), 0);
    BYTE sig[64]; memcpy(sig, k_ec256_sig_sha256, 64);
    sig[5] ^= 0x80;
    EXPECT_SS(U(NCryptVerifySignature)(k, NULL, (PBYTE)k_dig_sha256, 32, sig, 64, 0), NC_BAD_SIGNATURE);
    memcpy(sig, k_ec256_sig_sha256, 64); sig[63] ^= 1;
    EXPECT_SS(U(NCryptVerifySignature)(k, NULL, (PBYTE)k_dig_sha256, 32, sig, 64, 0), NC_BAD_SIGNATURE);
    BYTE dig[32]; memcpy(dig, k_dig_sha256, 32); dig[0] ^= 1;
    EXPECT_SS(U(NCryptVerifySignature)(k, NULL, dig, 32, (PBYTE)k_ec256_sig_sha256, 64, 0), NC_BAD_SIGNATURE);
    memset(sig, 0, 64);   /* r = s = 0 is never valid */
    EXPECT_SS(U(NCryptVerifySignature)(k, NULL, (PBYTE)k_dig_sha256, 32, sig, 64, 0), NC_BAD_SIGNATURE);
    SECURITY_STATUS s = U(NCryptVerifySignature)(k, NULL, (PBYTE)k_dig_sha256, 32, (PBYTE)k_ec256_sig_sha256, 63, 0);
    EXPECT_SS_FAIL(s); t_note("ECDSA verify with 63-byte signature -> 0x%08lx", (DWORD)s);
    s = U(NCryptVerifySignature)(k, NULL, (PBYTE)k_dig_sha256, 32, (PBYTE)k_ec256_sig_sha256, 65, 0);
    EXPECT_SS_FAIL(s); t_note("ECDSA verify with 65-byte signature -> 0x%08lx", (DWORD)s);
    nc_free(k); nc_free(p);
}
TEST(ncops_ecdsa_imported_private_signs) {
    REQUIRE(U(NCryptSignHash));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE prv = nc_import(p, BCRYPT_ECCPRIVATE_BLOB, NCV(k_ec256_priv)), pub = nc_import(p, BCRYPT_ECCPUBLIC_BLOB, NCV(k_ec256_pub));
    NEED(prv && pub, "keys");
    BYTE a[64], b[64]; DWORD ca = 0, cb = 0;
    EXPECT_SS(U(NCryptSignHash)(prv, NULL, (PBYTE)k_dig_sha256, 32, a, 64, &ca, 0), 0);
    EXPECT_SS(U(NCryptSignHash)(prv, NULL, (PBYTE)k_dig_sha256, 32, b, 64, &cb, 0), 0);
    EXPECT_SS(U(NCryptVerifySignature)(pub, NULL, (PBYTE)k_dig_sha256, 32, a, 64, 0), 0);
    EXPECT_SS(U(NCryptVerifySignature)(pub, NULL, (PBYTE)k_dig_sha256, 32, b, 64, 0), 0);
    CHECK(memcmp(a, b, 64) != 0);   /* ECDSA nonces are random */
    nc_free(prv); nc_free(pub); nc_free(p);
}
TEST(ncops_ecdsa_hash_lengths) {
    REQUIRE(U(NCryptSignHash));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE k = nc_newkey(p, BCRYPT_ECDSA_P256_ALGORITHM, 0, 0, TRUE); NEED(k, "key");
    static const DWORD lens[] = { 20, 32, 48, 64 };
    BYTE h[64]; for (int i = 0; i < 64; i++) h[i] = (BYTE)(i + 1);
    for (int i = 0; i < 4; i++) {
        BYTE sig[64]; DWORD cb = 0;
        EXPECT_SS(U(NCryptSignHash)(k, NULL, h, lens[i], sig, 64, &cb, 0), 0);
        EXPECT_SS(U(NCryptVerifySignature)(k, NULL, h, lens[i], sig, cb, 0), 0);
        /* a signature over a different length input must not verify */
        SECURITY_STATUS s = U(NCryptVerifySignature)(k, NULL, h, lens[i] - 1, sig, cb, 0);
        EXPECT_SS(s, NC_BAD_SIGNATURE);
    }
    BYTE sig[64]; DWORD cb = 0;
    SECURITY_STATUS s = U(NCryptSignHash)(k, NULL, h, 0, sig, 64, &cb, 0);
    t_note("ECDSA sign with empty hash -> 0x%08lx", (DWORD)s);
    s = U(NCryptSignHash)(k, NULL, h, 1, sig, 64, &cb, 0);
    t_note("ECDSA sign with 1-byte hash -> 0x%08lx", (DWORD)s);
    nc_free(k); nc_free(p);
}
TEST(ncops_ecdsa_cross_key_verify_fails) {
    REQUIRE(U(NCryptVerifySignature));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE a = nc_newkey(p, BCRYPT_ECDSA_P256_ALGORITHM, 0, 0, TRUE), b = nc_newkey(p, BCRYPT_ECDSA_P256_ALGORITHM, 0, 0, TRUE);
    NEED(a && b, "keys");
    BYTE sig[64]; DWORD cb = 0;
    EXPECT_SS(U(NCryptSignHash)(a, NULL, (PBYTE)k_dig_sha256, 32, sig, 64, &cb, 0), 0);
    EXPECT_SS(U(NCryptVerifySignature)(b, NULL, (PBYTE)k_dig_sha256, 32, sig, 64, 0), NC_BAD_SIGNATURE);
    nc_free(a); nc_free(b); nc_free(p);
}
TEST(ncops_ecdsa_rejects_padding_flags) {
    REQUIRE(U(NCryptSignHash));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE k = nc_newkey(p, BCRYPT_ECDSA_P256_ALGORITHM, 0, 0, TRUE); NEED(k, "key");
    BYTE sig[64]; DWORD cb = 0; BCRYPT_PKCS1_PADDING_INFO pi = { BCRYPT_SHA256_ALGORITHM };
    SECURITY_STATUS s = U(NCryptSignHash)(k, &pi, (PBYTE)k_dig_sha256, 32, sig, 64, &cb, BCRYPT_PAD_PKCS1);
    EXPECT_SS_FAIL(s); t_note("ECDSA sign with PKCS1 flag -> 0x%08lx", (DWORD)s);
    s = U(NCryptSignHash)(k, NULL, (PBYTE)k_dig_sha256, 32, sig, 64, &cb, NCRYPT_SILENT_FLAG);
    t_note("ECDSA sign with SILENT flag -> 0x%08lx", (DWORD)s);
    nc_free(k); nc_free(p);
}
TEST(ncops_ecdh_key_cannot_sign_or_verify) {
    REQUIRE(U(NCryptSignHash));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE k = nc_newkey(p, BCRYPT_ECDH_P256_ALGORITHM, 0, 0, TRUE); NEED(k, "key");
    BYTE sig[64]; DWORD cb = 0;
    SECURITY_STATUS s = U(NCryptSignHash)(k, NULL, (PBYTE)k_dig_sha256, 32, sig, 64, &cb, 0);
    EXPECT_SS_FAIL(s); t_note("sign with ECDH key -> 0x%08lx", (DWORD)s);
    s = U(NCryptVerifySignature)(k, NULL, (PBYTE)k_dig_sha256, 32, (PBYTE)k_ec256_sig_sha256, 64, 0);
    EXPECT_SS_FAIL(s); t_note("verify with ECDH key -> 0x%08lx", (DWORD)s);
    nc_free(k); nc_free(p);
}
TEST(ncops_dsa_sign_verify_note) {
    REQUIRE(U(NCryptSignHash));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE k = nc_newkey(p, BCRYPT_DSA_ALGORITHM, 1024, 0, TRUE);
    t_note("DSA-1024 ephemeral key: %s", k ? "created" : "unavailable");
    if (k) {
        BYTE sig[128]; DWORD cb = 0;
        SECURITY_STATUS s = U(NCryptSignHash)(k, NULL, (PBYTE)k_dig_sha1, 20, sig, sizeof sig, &cb, 0);
        t_note("DSA sign 20-byte hash -> 0x%08lx size %lu", (DWORD)s, cb);
        if (s == 0) { EXPECT_EQ(cb, 40); EXPECT_SS(U(NCryptVerifySignature)(k, NULL, (PBYTE)k_dig_sha1, 20, sig, cb, 0), 0); }
        s = U(NCryptSignHash)(k, NULL, (PBYTE)k_dig_sha256, 32, sig, sizeof sig, &cb, 0);
        t_note("DSA-1024 sign 32-byte hash -> 0x%08lx", (DWORD)s);
        nc_free(k);
    }
    nc_free(p);
}

/* ---------- RSA encryption ---------- */
TEST(ncops_rsa_decrypt_known_answers) {
    REQUIRE(U(NCryptDecrypt));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE k = rsa_priv(p); NEED(k, "RSA key");
    BYTE out[256]; DWORD cb;
    cb = 0; memset(out, 0, sizeof out);
    EXPECT_SS(U(NCryptDecrypt)(k, (PBYTE)k_rsa_enc_pkcs1, 128, NULL, out, sizeof out, &cb, NCRYPT_PAD_PKCS1_FLAG), 0);
    EXPECT_EQ(cb, sizeof k_pt); CHECK(cb == sizeof k_pt && !memcmp(out, k_pt, cb));
    static const struct { LPCWSTR h; const BYTE *c; } oaep[] = { { BCRYPT_SHA1_ALGORITHM, k_rsa_enc_oaep_sha1 }, { BCRYPT_SHA256_ALGORITHM, k_rsa_enc_oaep_sha256 } };
    for (int i = 0; i < 2; i++) {
        BCRYPT_OAEP_PADDING_INFO oi = { oaep[i].h, NULL, 0 };
        cb = 0; memset(out, 0, sizeof out);
        EXPECT_SS(U(NCryptDecrypt)(k, (PBYTE)oaep[i].c, 128, &oi, out, sizeof out, &cb, NCRYPT_PAD_OAEP_FLAG), 0);
        CHECKF(cb == sizeof k_pt && !memcmp(out, k_pt, cb), "OAEP %ls plaintext", oaep[i].h);
        /* the wrong hash fails to unpad */
        BCRYPT_OAEP_PADDING_INFO wrong = { oaep[i].h == BCRYPT_SHA1_ALGORITHM ? BCRYPT_SHA256_ALGORITHM : BCRYPT_SHA1_ALGORITHM, NULL, 0 };
        SECURITY_STATUS s = U(NCryptDecrypt)(k, (PBYTE)oaep[i].c, 128, &wrong, out, sizeof out, &cb, NCRYPT_PAD_OAEP_FLAG);
        EXPECT_SS_FAIL(s); t_note("OAEP decrypt with wrong hash -> 0x%08lx", (DWORD)s);
    }
    cb = 0; memset(out, 0, sizeof out);
    EXPECT_SS(U(NCryptDecrypt)(k, (PBYTE)k_raw_c, 128, NULL, out, sizeof out, &cb, NCRYPT_NO_PADDING_FLAG), 0);
    EXPECT_EQ(cb, 128); CHECK(cb == 128 && !memcmp(out, k_raw_m, 128));
    nc_free(k); nc_free(p);
}
TEST(ncops_rsa_encrypt_raw_known_answer) {
    REQUIRE(U(NCryptEncrypt));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE k = rsa_pub(p); NEED(k, "RSA public key");
    BYTE out[256]; DWORD cb = 0;
    EXPECT_SS(U(NCryptEncrypt)(k, (PBYTE)k_raw_m, 128, NULL, out, sizeof out, &cb, NCRYPT_NO_PADDING_FLAG), 0);
    EXPECT_EQ(cb, 128); CHECK(cb == 128 && !memcmp(out, k_raw_c, 128));
    nc_free(k); nc_free(p);
}
TEST(ncops_rsa_encrypt_size_protocol) {
    REQUIRE(U(NCryptEncrypt));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE k = rsa_pub(p); NEED(k, "RSA public key");
    BYTE out[256]; DWORD cb = 0xFFFF;
    EXPECT_SS(U(NCryptEncrypt)(k, (PBYTE)k_pt, sizeof k_pt, NULL, NULL, 0, &cb, NCRYPT_PAD_PKCS1_FLAG), 0);
    EXPECT_EQ(cb, 128);
    BCRYPT_OAEP_PADDING_INFO oi = { BCRYPT_SHA1_ALGORITHM, NULL, 0 };
    cb = 0xFFFF;
    EXPECT_SS(U(NCryptEncrypt)(k, (PBYTE)k_pt, sizeof k_pt, &oi, NULL, 0, &cb, NCRYPT_PAD_OAEP_FLAG), 0);
    EXPECT_EQ(cb, 128);
    static const DWORD small[] = { 0, 1, 64, 127 };
    for (int i = 0; i < 4; i++) {
        cb = 0xFFFF;
        EXPECT_SS(U(NCryptEncrypt)(k, (PBYTE)k_pt, sizeof k_pt, NULL, out, small[i], &cb, NCRYPT_PAD_PKCS1_FLAG), NC_BUFFER_TOO_SMALL);
        EXPECT_EQ(cb, 128);
    }
    cb = 0; EXPECT_SS(U(NCryptEncrypt)(k, (PBYTE)k_pt, sizeof k_pt, NULL, out, 128, &cb, NCRYPT_PAD_PKCS1_FLAG), 0); EXPECT_EQ(cb, 128);
    nc_free(k); nc_free(p);
}
TEST(ncops_rsa_encrypt_plaintext_limits) {
    REQUIRE(U(NCryptEncrypt));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE k = rsa_pub(p); NEED(k, "RSA public key");
    BYTE in[200]; for (int i = 0; i < 200; i++) in[i] = (BYTE)i;
    BYTE out[256]; DWORD cb = 0;
    BCRYPT_OAEP_PADDING_INFO o1 = { BCRYPT_SHA1_ALGORITHM, NULL, 0 }, o256 = { BCRYPT_SHA256_ALGORITHM, NULL, 0 };
    EXPECT_SS(U(NCryptEncrypt)(k, in, 117, NULL, out, 256, &cb, NCRYPT_PAD_PKCS1_FLAG), 0);        /* 128 - 11 */
    EXPECT_SS_FAIL(U(NCryptEncrypt)(k, in, 118, NULL, out, 256, &cb, NCRYPT_PAD_PKCS1_FLAG));
    EXPECT_SS(U(NCryptEncrypt)(k, in, 86, &o1, out, 256, &cb, NCRYPT_PAD_OAEP_FLAG), 0);           /* 128 - 2*20 - 2 */
    EXPECT_SS_FAIL(U(NCryptEncrypt)(k, in, 87, &o1, out, 256, &cb, NCRYPT_PAD_OAEP_FLAG));
    EXPECT_SS(U(NCryptEncrypt)(k, in, 62, &o256, out, 256, &cb, NCRYPT_PAD_OAEP_FLAG), 0);         /* 128 - 2*32 - 2 */
    EXPECT_SS_FAIL(U(NCryptEncrypt)(k, in, 63, &o256, out, 256, &cb, NCRYPT_PAD_OAEP_FLAG));
    SECURITY_STATUS s = U(NCryptEncrypt)(k, in, 129, NULL, out, 256, &cb, NCRYPT_NO_PADDING_FLAG);
    EXPECT_SS_FAIL(s);
    s = U(NCryptEncrypt)(k, in, 127, NULL, out, 256, &cb, NCRYPT_NO_PADDING_FLAG);
    t_note("raw RSA encrypt of 127 bytes -> 0x%08lx", (DWORD)s);
    nc_free(k); nc_free(p);
}
TEST(ncops_rsa_roundtrip_paddings) {
    REQUIRE(U(NCryptEncrypt)); REQUIRE(U(NCryptDecrypt));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE k = nc_newkey(p, BCRYPT_RSA_ALGORITHM, 1024, 0, TRUE); NEED(k, "RSA key");
    BYTE ct[128], ct2[128], pt[128]; DWORD c1 = 0, c2 = 0, c3 = 0;
    EXPECT_SS(U(NCryptEncrypt)(k, (PBYTE)k_pt, sizeof k_pt, NULL, ct, 128, &c1, NCRYPT_PAD_PKCS1_FLAG), 0);
    EXPECT_SS(U(NCryptEncrypt)(k, (PBYTE)k_pt, sizeof k_pt, NULL, ct2, 128, &c2, NCRYPT_PAD_PKCS1_FLAG), 0);
    CHECK(memcmp(ct, ct2, 128) != 0);   /* PKCS#1 type 2 padding is randomized */
    EXPECT_SS(U(NCryptDecrypt)(k, ct, c1, NULL, pt, 128, &c3, NCRYPT_PAD_PKCS1_FLAG), 0);
    CHECK(c3 == sizeof k_pt && !memcmp(pt, k_pt, c3));
    LPCWSTR hs[] = { BCRYPT_SHA1_ALGORITHM, BCRYPT_SHA256_ALGORITHM, BCRYPT_SHA384_ALGORITHM, BCRYPT_SHA512_ALGORITHM };
    static const BYTE label[] = "cryptt-label";
    for (int i = 0; i < 4; i++) {
        BCRYPT_OAEP_PADDING_INFO oi = { hs[i], (PUCHAR)label, sizeof label };
        BCRYPT_OAEP_PADDING_INFO nol = { hs[i], NULL, 0 };
        SECURITY_STATUS s = U(NCryptEncrypt)(k, (PBYTE)k_pt, sizeof k_pt, &oi, ct, 128, &c1, NCRYPT_PAD_OAEP_FLAG);
        if (i == 3) { t_note("OAEP SHA-512 on RSA-1024 -> 0x%08lx (needs 2*64+2 < 128 bytes: expected failure)", (DWORD)s); EXPECT_SS_FAIL(s); continue; }
        EXPECT_SS(s, 0);
        memset(pt, 0, 128);
        EXPECT_SS(U(NCryptDecrypt)(k, ct, c1, &oi, pt, 128, &c3, NCRYPT_PAD_OAEP_FLAG), 0);
        CHECKF(c3 == sizeof k_pt && !memcmp(pt, k_pt, c3), "OAEP %ls roundtrip", hs[i]);
        s = U(NCryptDecrypt)(k, ct, c1, &nol, pt, 128, &c3, NCRYPT_PAD_OAEP_FLAG);
        EXPECT_SS_FAIL(s);   /* label mismatch */
    }
    nc_free(k); nc_free(p);
}
TEST(ncops_rsa_decrypt_errors) {
    REQUIRE(U(NCryptDecrypt));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE k = rsa_priv(p), pub = rsa_pub(p); NEED(k && pub, "keys");
    BYTE out[256], ct[128]; DWORD cb = 0; SECURITY_STATUS s;
    memcpy(ct, k_rsa_enc_pkcs1, 128); ct[40] ^= 0x10;
    s = U(NCryptDecrypt)(k, ct, 128, NULL, out, sizeof out, &cb, NCRYPT_PAD_PKCS1_FLAG);
    EXPECT_SS_FAIL(s); t_note("decrypt tampered PKCS1 ciphertext -> 0x%08lx", (DWORD)s);
    s = U(NCryptDecrypt)(k, (PBYTE)k_rsa_enc_pkcs1, 127, NULL, out, sizeof out, &cb, NCRYPT_PAD_PKCS1_FLAG);
    EXPECT_SS_FAIL(s); t_note("decrypt 127-byte ciphertext -> 0x%08lx", (DWORD)s);
    s = U(NCryptDecrypt)(k, (PBYTE)k_rsa_enc_pkcs1, 129, NULL, out, sizeof out, &cb, NCRYPT_PAD_PKCS1_FLAG);
    EXPECT_SS_FAIL(s);
    s = U(NCryptDecrypt)(k, (PBYTE)k_rsa_enc_pkcs1, 128, NULL, out, sizeof out, &cb, 0);
    EXPECT_SS_FAIL(s); t_note("decrypt with no padding flag -> 0x%08lx", (DWORD)s);
    s = U(NCryptDecrypt)(k, (PBYTE)k_rsa_enc_oaep_sha1, 128, NULL, out, sizeof out, &cb, NCRYPT_PAD_OAEP_FLAG);
    EXPECT_SS_FAIL(s); t_note("OAEP flag without padding info -> 0x%08lx", (DWORD)s);
    s = U(NCryptDecrypt)(pub, (PBYTE)k_rsa_enc_pkcs1, 128, NULL, out, sizeof out, &cb, NCRYPT_PAD_PKCS1_FLAG);
    EXPECT_SS_FAIL(s); t_note("decrypt with public-only key -> 0x%08lx", (DWORD)s);
    memset(ct, 0xFF, 128);
    s = U(NCryptDecrypt)(k, ct, 128, NULL, out, sizeof out, &cb, NCRYPT_NO_PADDING_FLAG);
    EXPECT_SS_FAIL(s); t_note("raw decrypt of value >= modulus -> 0x%08lx", (DWORD)s);
    s = U(NCryptDecrypt)(k, (PBYTE)k_rsa_enc_pkcs1, 128, NULL, out, 1, &cb, NCRYPT_PAD_PKCS1_FLAG);
    EXPECT_SS_FAIL(s); t_note("decrypt into 1-byte buffer -> 0x%08lx need %lu", (DWORD)s, cb);
    s = U(NCryptDecrypt)(k, (PBYTE)k_rsa_enc_pkcs1, 128, NULL, NULL, 0, &cb, NCRYPT_PAD_PKCS1_FLAG);
    t_note("decrypt size query -> 0x%08lx size %lu (plaintext is %u bytes)", (DWORD)s, cb, (unsigned)sizeof k_pt);
    nc_free(k); nc_free(pub); nc_free(p);
}
TEST(ncops_ecc_key_cannot_encrypt) {
    REQUIRE(U(NCryptEncrypt));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE k = nc_newkey(p, BCRYPT_ECDH_P256_ALGORITHM, 0, 0, TRUE); NEED(k, "key");
    BYTE out[256]; DWORD cb = 0;
    EXPECT_SS(U(NCryptEncrypt)(k, (PBYTE)k_pt, 8, NULL, out, 256, &cb, NCRYPT_PAD_PKCS1_FLAG), NC_NOT_SUPPORTED);
    EXPECT_SS(U(NCryptDecrypt)(k, out, 64, NULL, out, 256, &cb, NCRYPT_PAD_PKCS1_FLAG), NC_NOT_SUPPORTED);
    nc_free(k); nc_free(p);
}
TEST(ncops_rsa_empty_plaintext_note) {
    REQUIRE(U(NCryptEncrypt));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE k = nc_newkey(p, BCRYPT_RSA_ALGORITHM, 1024, 0, TRUE); NEED(k, "key");
    BYTE ct[128], pt[128]; DWORD c1 = 0, c2 = 0;
    SECURITY_STATUS s = U(NCryptEncrypt)(k, (PBYTE)"", 0, NULL, ct, 128, &c1, NCRYPT_PAD_PKCS1_FLAG);
    t_note("PKCS1 encrypt of empty plaintext -> 0x%08lx", (DWORD)s);
    if (s == 0) { s = U(NCryptDecrypt)(k, ct, c1, NULL, pt, 128, &c2, NCRYPT_PAD_PKCS1_FLAG); t_note("   decrypt -> 0x%08lx len %lu", (DWORD)s, c2); if (s == 0) EXPECT_EQ(c2, 0); }
    nc_free(k); nc_free(p);
}

/* ---------- secret agreement and derivation ---------- */
static int sec_pair(NCRYPT_PROV_HANDLE p, NCRYPT_KEY_HANDLE *a_priv, NCRYPT_KEY_HANDLE *a_pub, NCRYPT_KEY_HANDLE *b_priv, NCRYPT_KEY_HANDLE *b_pub,
                    NCRYPT_SECRET_HANDLE *sa, NCRYPT_SECRET_HANDLE *sb)
{
    *a_priv = nc_import(p, BCRYPT_ECCPRIVATE_BLOB, NCV(k_ecdh256_a_priv)); *a_pub = nc_import(p, BCRYPT_ECCPUBLIC_BLOB, NCV(k_ecdh256_a_pub));
    *b_priv = nc_import(p, BCRYPT_ECCPRIVATE_BLOB, NCV(k_ecdh256_b_priv)); *b_pub = nc_import(p, BCRYPT_ECCPUBLIC_BLOB, NCV(k_ecdh256_b_pub));
    *sa = *sb = 0;
    if (!*a_priv || !*a_pub || !*b_priv || !*b_pub) return 0;
    if (U(NCryptSecretAgreement)(*a_priv, *b_pub, sa, 0) != 0) return 0;
    if (U(NCryptSecretAgreement)(*b_priv, *a_pub, sb, 0) != 0) return 0;
    return 1;
}
static void sec_cleanup(NCRYPT_KEY_HANDLE a, NCRYPT_KEY_HANDLE b, NCRYPT_KEY_HANDLE c, NCRYPT_KEY_HANDLE d, NCRYPT_SECRET_HANDLE s1, NCRYPT_SECRET_HANDLE s2, NCRYPT_PROV_HANDLE p)
{ nc_free(s1); nc_free(s2); nc_free(a); nc_free(b); nc_free(c); nc_free(d); nc_free(p); }

TEST(ncops_agreement_rfc5903_p256_raw) {
    REQUIRE(U(NCryptSecretAgreement)); REQUIRE(U(NCryptDeriveKey));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE a, ap, b, bp; NCRYPT_SECRET_HANDLE sa, sb;
    int ok = sec_pair(p, &a, &ap, &b, &bp, &sa, &sb);
    CHECK(ok);
    if (ok) {
        BYTE r1[64], r2[64]; DWORD c1 = 0, c2 = 0;
        EXPECT_SS(U(NCryptDeriveKey)(sa, BCRYPT_KDF_RAW_SECRET, NULL, NULL, 0, &c1, 0), 0);
        EXPECT_EQ(c1, 32);
        EXPECT_SS(U(NCryptDeriveKey)(sa, BCRYPT_KDF_RAW_SECRET, NULL, r1, sizeof r1, &c1, 0), 0);
        EXPECT_SS(U(NCryptDeriveKey)(sb, BCRYPT_KDF_RAW_SECRET, NULL, r2, sizeof r2, &c2, 0), 0);
        EXPECT_EQ(c1, 32); EXPECT_EQ(c2, 32);
        CHECK(!memcmp(r1, r2, 32));
        BYTE rev[32]; for (int i = 0; i < 32; i++) rev[i] = k_ecdh256_secret[31 - i];
        int le = !memcmp(r1, rev, 32), be = !memcmp(r1, k_ecdh256_secret, 32);
        CHECK(le || be);
        t_note("RAW_SECRET byte order: %s (RFC 5903 shared x)", le ? "little-endian" : be ? "big-endian" : "UNEXPECTED");
        CHECKF(le, "RAW_SECRET is documented as little-endian");
    }
    sec_cleanup(a, ap, b, bp, sa, sb, p);
}
TEST(ncops_agreement_hash_kdf) {
    REQUIRE(U(NCryptSecretAgreement)); REQUIRE(U(NCryptDeriveKey));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE a, ap, b, bp; NCRYPT_SECRET_HANDLE sa, sb;
    NEED(sec_pair(p, &a, &ap, &b, &bp, &sa, &sb), "agreement");
    static const struct { LPCWSTR alg; DWORD n; } hs[] = { { BCRYPT_SHA1_ALGORITHM, 20 }, { BCRYPT_SHA256_ALGORITHM, 32 }, { BCRYPT_SHA384_ALGORITHM, 48 }, { BCRYPT_SHA512_ALGORITHM, 64 } };
    BYTE rev[32]; for (int i = 0; i < 32; i++) rev[i] = k_ecdh256_secret[31 - i];
    for (int i = 0; i < 4; i++) {
        NCryptBuffer nb = { (ULONG)((lstrlenW(hs[i].alg) + 1) * 2), KDF_HASH_ALGORITHM, (void *)hs[i].alg };
        NCryptBufferDesc d = { BCRYPTBUFFER_VERSION, 1, &nb };
        BYTE o1[64], o2[64], want_be[64], want_le[64]; DWORD c1 = 0, c2 = 0;
        EXPECT_SS(U(NCryptDeriveKey)(sa, BCRYPT_KDF_HASH, &d, NULL, 0, &c1, 0), 0);
        EXPECT_EQ(c1, hs[i].n);
        EXPECT_SS(U(NCryptDeriveKey)(sa, BCRYPT_KDF_HASH, &d, o1, sizeof o1, &c1, 0), 0);
        EXPECT_SS(U(NCryptDeriveKey)(sb, BCRYPT_KDF_HASH, &d, o2, sizeof o2, &c2, 0), 0);
        EXPECT_EQ(c1, hs[i].n); EXPECT_EQ(c2, hs[i].n);
        CHECK(!memcmp(o1, o2, hs[i].n));
        nc_hash(hs[i].alg, NULL, 0, k_ecdh256_secret, 32, want_be, hs[i].n);
        nc_hash(hs[i].alg, NULL, 0, rev, 32, want_le, hs[i].n);
        int be = !memcmp(o1, want_be, hs[i].n), le = !memcmp(o1, want_le, hs[i].n);
        CHECKF(be || le, "%ls KDF output is the hash of neither byte order", hs[i].alg);
        t_note("KDF_HASH %ls hashes the %s secret", hs[i].alg, be ? "big-endian" : le ? "little-endian" : "?");
    }
    sec_cleanup(a, ap, b, bp, sa, sb, p);
}
TEST(ncops_agreement_hash_prepend_append) {
    REQUIRE(U(NCryptDeriveKey));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE a, ap, b, bp; NCRYPT_SECRET_HANDLE sa, sb;
    NEED(sec_pair(p, &a, &ap, &b, &bp, &sa, &sb), "agreement");
    /* learn the byte order that KDF_HASH uses, then check prepend/append compose around it */
    NCryptBuffer hb = { sizeof(BCRYPT_SHA256_ALGORITHM), KDF_HASH_ALGORITHM, (void *)BCRYPT_SHA256_ALGORITHM };
    NCryptBufferDesc hd = { BCRYPTBUFFER_VERSION, 1, &hb };
    BYTE base[32], rev[32], tmp[32 + 16]; DWORD cb = 0;
    for (int i = 0; i < 32; i++) rev[i] = k_ecdh256_secret[31 - i];
    EXPECT_SS(U(NCryptDeriveKey)(sa, BCRYPT_KDF_HASH, &hd, base, 32, &cb, 0), 0);
    BYTE w[32]; nc_hash(BCRYPT_SHA256_ALGORITHM, NULL, 0, k_ecdh256_secret, 32, w, 32);
    const BYTE *sec = !memcmp(base, w, 32) ? k_ecdh256_secret : rev;
    static const BYTE pre[] = "PRE", app[] = "appendix!";
    NCryptBuffer nb[3] = { hb, { sizeof pre, KDF_SECRET_PREPEND, (void *)pre }, { sizeof app, KDF_SECRET_APPEND, (void *)app } };
    NCryptBufferDesc d = { BCRYPTBUFFER_VERSION, 3, nb };
    BYTE got[32], want[32], cat[3 + 32 + 9];
    EXPECT_SS(U(NCryptDeriveKey)(sa, BCRYPT_KDF_HASH, &d, got, 32, &cb, 0), 0);
    memcpy(cat, pre, 3); memcpy(cat + 3, sec, 32); memcpy(cat + 35, app, 9);
    nc_hash(BCRYPT_SHA256_ALGORITHM, NULL, 0, cat, sizeof cat, want, 32);
    CHECK(!memcmp(got, want, 32));
    d.cBuffers = 2; nb[1] = (NCryptBuffer){ sizeof pre, KDF_SECRET_PREPEND, (void *)pre };
    EXPECT_SS(U(NCryptDeriveKey)(sa, BCRYPT_KDF_HASH, &d, got, 32, &cb, 0), 0);
    memcpy(cat, pre, 3); memcpy(cat + 3, sec, 32);
    nc_hash(BCRYPT_SHA256_ALGORITHM, NULL, 0, cat, 35, want, 32);
    CHECK(!memcmp(got, want, 32));
    sec_cleanup(a, ap, b, bp, sa, sb, p);
}
TEST(ncops_agreement_hmac_kdf) {
    REQUIRE(U(NCryptDeriveKey));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE a, ap, b, bp; NCRYPT_SECRET_HANDLE sa, sb;
    NEED(sec_pair(p, &a, &ap, &b, &bp, &sa, &sb), "agreement");
    static const BYTE key[] = "hmac key for cryptt";
    NCryptBuffer nb[2] = { { sizeof(BCRYPT_SHA256_ALGORITHM), KDF_HASH_ALGORITHM, (void *)BCRYPT_SHA256_ALGORITHM }, { sizeof key - 1, KDF_HMAC_KEY, (void *)key } };
    NCryptBufferDesc d = { BCRYPTBUFFER_VERSION, 2, nb };
    BYTE o1[32], o2[32]; DWORD c1 = 0, c2 = 0;
    EXPECT_SS(U(NCryptDeriveKey)(sa, BCRYPT_KDF_HMAC, &d, o1, 32, &c1, 0), 0);
    EXPECT_SS(U(NCryptDeriveKey)(sb, BCRYPT_KDF_HMAC, &d, o2, 32, &c2, 0), 0);
    EXPECT_EQ(c1, 32); CHECK(!memcmp(o1, o2, 32));
    BYTE rev[32], w1[32], w2[32]; for (int i = 0; i < 32; i++) rev[i] = k_ecdh256_secret[31 - i];
    nc_hash(BCRYPT_SHA256_ALGORITHM, key, sizeof key - 1, k_ecdh256_secret, 32, w1, 32);
    nc_hash(BCRYPT_SHA256_ALGORITHM, key, sizeof key - 1, rev, 32, w2, 32);
    int be = !memcmp(o1, w1, 32), le = !memcmp(o1, w2, 32);
    CHECKF(be || le, "HMAC KDF output matches neither HMAC(key, secret) byte order");
    t_note("KDF_HMAC uses the %s secret", be ? "big-endian" : le ? "little-endian" : "?");
    /* without a key the call must fail or generate a random key; both sides differ in the latter case */
    NCryptBufferDesc d1 = { BCRYPTBUFFER_VERSION, 1, nb };
    SECURITY_STATUS s = U(NCryptDeriveKey)(sa, BCRYPT_KDF_HMAC, &d1, o1, 32, &c1, 0);
    t_note("KDF_HMAC without KDF_HMAC_KEY -> 0x%08lx", (DWORD)s);
    sec_cleanup(a, ap, b, bp, sa, sb, p);
}
TEST(ncops_agreement_tls_prf) {
    REQUIRE(U(NCryptDeriveKey));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE a, ap, b, bp; NCRYPT_SECRET_HANDLE sa, sb;
    NEED(sec_pair(p, &a, &ap, &b, &bp, &sa, &sb), "agreement");
    static const char label[] = "cryptt test label"; BYTE seed[64]; for (int i = 0; i < 64; i++) seed[i] = (BYTE)(255 - i);
    DWORD proto = 0x0303;   /* TLS 1.2 PRF; no handshake or schannel call is involved */
    NCryptBuffer nb[3] = { { sizeof label - 1, KDF_TLS_PRF_LABEL, (void *)label }, { sizeof seed, KDF_TLS_PRF_SEED, seed }, { 4, KDF_TLS_PRF_PROTOCOL, &proto } };
    NCryptBufferDesc d = { BCRYPTBUFFER_VERSION, 3, nb };
    BYTE o1[48], o2[48]; DWORD c1 = 0, c2 = 0;
    SECURITY_STATUS s1 = U(NCryptDeriveKey)(sa, BCRYPT_KDF_TLS_PRF, &d, o1, 48, &c1, 0);
    SECURITY_STATUS s2 = U(NCryptDeriveKey)(sb, BCRYPT_KDF_TLS_PRF, &d, o2, 48, &c2, 0);
    t_note("KDF_TLS_PRF -> 0x%08lx / 0x%08lx", (DWORD)s1, (DWORD)s2);
    EXPECT_EQ((DWORD)s1, (DWORD)s2);
    if (s1 == 0 && s2 == 0) { EXPECT_EQ(c1, 48); CHECK(!memcmp(o1, o2, 48)); }
    sec_cleanup(a, ap, b, bp, sa, sb, p);
}
TEST(ncops_derive_buffer_protocol) {
    REQUIRE(U(NCryptDeriveKey));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE a, ap, b, bp; NCRYPT_SECRET_HANDLE sa, sb;
    NEED(sec_pair(p, &a, &ap, &b, &bp, &sa, &sb), "agreement");
    NCryptBuffer nb = { sizeof(BCRYPT_SHA256_ALGORITHM), KDF_HASH_ALGORITHM, (void *)BCRYPT_SHA256_ALGORITHM };
    NCryptBufferDesc d = { BCRYPTBUFFER_VERSION, 1, &nb };
    BYTE out[64]; DWORD cb;
    static const DWORD small[] = { 0, 1, 31 };
    for (int i = 0; i < 3; i++) {
        cb = 0xFFFF;
        EXPECT_SS(U(NCryptDeriveKey)(sa, BCRYPT_KDF_HASH, &d, out, small[i], &cb, 0), NC_BUFFER_TOO_SMALL);
        EXPECT_EQ(cb, 32);
    }
    cb = 0; EXPECT_SS(U(NCryptDeriveKey)(sa, BCRYPT_KDF_HASH, &d, out, 32, &cb, 0), 0); EXPECT_EQ(cb, 32);
    cb = 0; EXPECT_SS(U(NCryptDeriveKey)(sa, BCRYPT_KDF_HASH, &d, out, 64, &cb, 0), 0); EXPECT_EQ(cb, 32);
    SECURITY_STATUS s = U(NCryptDeriveKey)(sa, BCRYPT_KDF_HASH, NULL, NULL, 0, &cb, 0);
    t_note("KDF_HASH without parameters: size query 0x%08lx size %lu", (DWORD)s, cb);
    sec_cleanup(a, ap, b, bp, sa, sb, p);
}
TEST(ncops_derive_invalid_kdf) {
    REQUIRE(U(NCryptDeriveKey));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE a, ap, b, bp; NCRYPT_SECRET_HANDLE sa, sb;
    NEED(sec_pair(p, &a, &ap, &b, &bp, &sa, &sb), "agreement");
    BYTE out[64]; DWORD cb = 0; SECURITY_STATUS s;
    s = U(NCryptDeriveKey)(sa, L"cryptt-no-such-kdf", NULL, out, sizeof out, &cb, 0);
    EXPECT_SS_FAIL(s); t_note("unknown KDF -> 0x%08lx", (DWORD)s);
    s = U(NCryptDeriveKey)(sa, NULL, NULL, out, sizeof out, &cb, 0);
    EXPECT_SS_FAIL(s); t_note("NULL KDF -> 0x%08lx", (DWORD)s);
    s = U(NCryptDeriveKey)(sa, L"", NULL, out, sizeof out, &cb, 0);
    EXPECT_SS_FAIL(s);
    NCryptBuffer nb = { sizeof(L"cryptt-no-hash"), KDF_HASH_ALGORITHM, (void *)L"cryptt-no-hash" };
    NCryptBufferDesc d = { BCRYPTBUFFER_VERSION, 1, &nb };
    s = U(NCryptDeriveKey)(sa, BCRYPT_KDF_HASH, &d, out, sizeof out, &cb, 0);
    EXPECT_SS_FAIL(s); t_note("KDF_HASH with unknown hash -> 0x%08lx", (DWORD)s);
    s = U(NCryptDeriveKey)(sa, BCRYPT_KDF_RAW_SECRET, NULL, out, sizeof out, &cb, 0x80000000u);
    t_note("DeriveKey with unknown flag -> 0x%08lx", (DWORD)s);
    sec_cleanup(a, ap, b, bp, sa, sb, p);
}
TEST(ncops_agreement_invalid_keys) {
    REQUIRE(U(NCryptSecretAgreement));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE a = nc_import(p, BCRYPT_ECCPRIVATE_BLOB, NCV(k_ecdh256_a_priv)), bpub = nc_import(p, BCRYPT_ECCPUBLIC_BLOB, NCV(k_ecdh256_b_pub));
    NCRYPT_KEY_HANDLE p384 = nc_newkey(p, BCRYPT_ECDH_P384_ALGORITHM, 0, 0, TRUE), ecdsa = nc_newkey(p, BCRYPT_ECDSA_P256_ALGORITHM, 0, 0, TRUE);
    NCRYPT_KEY_HANDLE rsa = nc_newkey(p, BCRYPT_RSA_ALGORITHM, 1024, 0, TRUE);
    NEED(a && bpub && p384 && ecdsa && rsa, "keys");
    NCRYPT_SECRET_HANDLE s = 0; SECURITY_STATUS st;
    st = U(NCryptSecretAgreement)(a, p384, &s, 0);          EXPECT_SS_FAIL(st); EXPECT_EQ(s, 0); t_note("P256 priv with P384 pub -> 0x%08lx", (DWORD)st);
    st = U(NCryptSecretAgreement)(bpub, bpub, &s, 0);       EXPECT_SS_FAIL(st); EXPECT_EQ(s, 0); t_note("public-only key as private -> 0x%08lx", (DWORD)st);
    st = U(NCryptSecretAgreement)(ecdsa, bpub, &s, 0);      EXPECT_SS_FAIL(st); EXPECT_EQ(s, 0); t_note("ECDSA key as private -> 0x%08lx", (DWORD)st);
    st = U(NCryptSecretAgreement)(rsa, bpub, &s, 0);        EXPECT_SS_FAIL(st); EXPECT_EQ(s, 0); t_note("RSA key as private -> 0x%08lx", (DWORD)st);
    st = U(NCryptSecretAgreement)(a, rsa, &s, 0);           EXPECT_SS_FAIL(st); EXPECT_EQ(s, 0);
    st = U(NCryptSecretAgreement)(a, bpub, &s, 0x80000000u); t_note("agreement with unknown flag -> 0x%08lx", (DWORD)st); if (st == 0) nc_free(s);
    nc_free(a); nc_free(bpub); nc_free(p384); nc_free(ecdsa); nc_free(rsa); nc_free(p);
}
TEST(ncops_agreement_self_and_random_keys) {
    REQUIRE(U(NCryptSecretAgreement));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    static const LPCWSTR algs[] = { BCRYPT_ECDH_P256_ALGORITHM, BCRYPT_ECDH_P384_ALGORITHM, BCRYPT_ECDH_P521_ALGORITHM };
    static const DWORD len[] = { 32, 48, 66 };
    for (int i = 0; i < 3; i++) {
        NCRYPT_KEY_HANDLE a = nc_newkey(p, algs[i], 0, NC_EXP_ALL, TRUE), b = nc_newkey(p, algs[i], 0, NC_EXP_ALL, TRUE);
        CHECKF(a && b, "%ls", algs[i]); if (!a || !b) { nc_free(a); nc_free(b); continue; }
        DWORD c1 = 0, c2 = 0, c3 = 0, c4 = 0;
        BYTE *apub = NULL, *bpub = NULL;
        c1 = c2 = 0;
        U(NCryptExportKey)(a, 0, BCRYPT_ECCPUBLIC_BLOB, NULL, NULL, 0, &c1, 0); apub = (BYTE *)HeapAlloc(GetProcessHeap(), 0, c1);
        U(NCryptExportKey)(a, 0, BCRYPT_ECCPUBLIC_BLOB, NULL, apub, c1, &c1, 0);
        U(NCryptExportKey)(b, 0, BCRYPT_ECCPUBLIC_BLOB, NULL, NULL, 0, &c2, 0); bpub = (BYTE *)HeapAlloc(GetProcessHeap(), 0, c2);
        U(NCryptExportKey)(b, 0, BCRYPT_ECCPUBLIC_BLOB, NULL, bpub, c2, &c2, 0);
        NCRYPT_KEY_HANDLE ai = nc_import(p, BCRYPT_ECCPUBLIC_BLOB, apub, c1), bi = nc_import(p, BCRYPT_ECCPUBLIC_BLOB, bpub, c2);
        CHECK(ai && bi);
        NCRYPT_SECRET_HANDLE s1 = 0, s2 = 0;
        EXPECT_SS(U(NCryptSecretAgreement)(a, bi, &s1, 0), 0);
        EXPECT_SS(U(NCryptSecretAgreement)(b, ai, &s2, 0), 0);
        BYTE r1[80], r2[80];
        EXPECT_SS(U(NCryptDeriveKey)(s1, BCRYPT_KDF_RAW_SECRET, NULL, r1, sizeof r1, &c3, 0), 0);
        EXPECT_SS(U(NCryptDeriveKey)(s2, BCRYPT_KDF_RAW_SECRET, NULL, r2, sizeof r2, &c4, 0), 0);
        EXPECT_EQ(c3, len[i]); EXPECT_EQ(c4, len[i]); CHECK(c3 == c4 && !memcmp(r1, r2, c3));
        nc_free(s1); nc_free(s2); nc_free(ai); nc_free(bi); nc_free(a); nc_free(b);
        nc_hfree(apub); nc_hfree(bpub);
    }
    nc_free(p);
}
TEST(ncops_agreement_dh_modp2048) {
    REQUIRE(U(NCryptSecretAgreement));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE k[2] = {0, 0}, imp[2] = {0, 0};
    BYTE blob[sizeof(BCRYPT_DH_PARAMETER_HEADER) + 512];
    BCRYPT_DH_PARAMETER_HEADER *h = (BCRYPT_DH_PARAMETER_HEADER *)blob;
    h->cbLength = sizeof blob; h->dwMagic = BCRYPT_DH_PARAMETERS_MAGIC; h->cbKeyLength = 256;
    memcpy(blob + sizeof *h, k_dh2048_p, 256); memcpy(blob + sizeof *h + 256, k_dh2048_g, 256);
    BYTE *pub[2] = {0, 0}; DWORD cpub[2] = {0, 0};
    for (int i = 0; i < 2; i++) {
        if (U(NCryptCreatePersistedKey)(p, &k[i], BCRYPT_DH_ALGORITHM, NULL, 0, 0) != 0) break;
        if (U(NCryptSetProperty)(k[i], NCRYPT_DH_PARAMETERS_PROPERTY, blob, sizeof blob, 0) != 0) break;
        if (U(NCryptFinalizeKey)(k[i], 0) != 0) break;
        U(NCryptExportKey)(k[i], 0, BCRYPT_DH_PUBLIC_BLOB, NULL, NULL, 0, &cpub[i], 0);
        pub[i] = (BYTE *)HeapAlloc(GetProcessHeap(), 0, cpub[i]);
        U(NCryptExportKey)(k[i], 0, BCRYPT_DH_PUBLIC_BLOB, NULL, pub[i], cpub[i], &cpub[i], 0);
        imp[i] = nc_import(p, BCRYPT_DH_PUBLIC_BLOB, pub[i], cpub[i]);
    }
    CHECKF(k[0] && k[1] && imp[0] && imp[1], "DH key setup");
    if (k[0] && k[1] && imp[0] && imp[1]) {
        NCRYPT_SECRET_HANDLE s1 = 0, s2 = 0; BYTE r1[300], r2[300]; DWORD c1 = 0, c2 = 0;
        EXPECT_SS(U(NCryptSecretAgreement)(k[0], imp[1], &s1, 0), 0);
        EXPECT_SS(U(NCryptSecretAgreement)(k[1], imp[0], &s2, 0), 0);
        EXPECT_SS(U(NCryptDeriveKey)(s1, BCRYPT_KDF_RAW_SECRET, NULL, r1, sizeof r1, &c1, 0), 0);
        EXPECT_SS(U(NCryptDeriveKey)(s2, BCRYPT_KDF_RAW_SECRET, NULL, r2, sizeof r2, &c2, 0), 0);
        EXPECT_EQ(c1, 256); EXPECT_EQ(c2, 256); CHECK(c1 == c2 && !memcmp(r1, r2, c1));
        nc_free(s1); nc_free(s2);
    }
    for (int i = 0; i < 2; i++) { nc_free(imp[i]); nc_free(k[i]); nc_hfree(pub[i]); }
    nc_free(p);
}
TEST(ncops_secret_handle_survives_key_close) {
    REQUIRE(U(NCryptSecretAgreement));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE a, ap, b, bp; NCRYPT_SECRET_HANDLE sa, sb;
    NEED(sec_pair(p, &a, &ap, &b, &bp, &sa, &sb), "agreement");
    nc_free(a); nc_free(ap); nc_free(b); nc_free(bp); nc_free(p);   /* the secret holds its own provider reference */
    BYTE r[32]; DWORD cb = 0;
    EXPECT_SS(U(NCryptDeriveKey)(sa, BCRYPT_KDF_RAW_SECRET, NULL, r, 32, &cb, 0), 0);
    EXPECT_EQ(cb, 32);
    EXPECT_SS(U(NCryptFreeObject)(sa), 0);
    EXPECT_SS(U(NCryptFreeObject)(sb), 0);
}
TEST(ncops_derive_secret_reusable) {
    REQUIRE(U(NCryptDeriveKey));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE a, ap, b, bp; NCRYPT_SECRET_HANDLE sa, sb;
    NEED(sec_pair(p, &a, &ap, &b, &bp, &sa, &sb), "agreement");
    BYTE r1[32], r2[32]; DWORD cb = 0;
    EXPECT_SS(U(NCryptDeriveKey)(sa, BCRYPT_KDF_RAW_SECRET, NULL, r1, 32, &cb, 0), 0);
    EXPECT_SS(U(NCryptDeriveKey)(sa, BCRYPT_KDF_RAW_SECRET, NULL, r2, 32, &cb, 0), 0);   /* a secret can be derived from repeatedly */
    CHECK(!memcmp(r1, r2, 32));
    sec_cleanup(a, ap, b, bp, sa, sb, p);
}
TEST(ncops_key_derivation_needs_kdf_key) {
    REQUIRE(U(NCryptKeyDerivation));
    NCRYPT_PROV_HANDLE p = nc_prov(); NEED(p, "provider");
    NCRYPT_KEY_HANDLE k = nc_newkey(p, BCRYPT_ECDH_P256_ALGORITHM, 0, 0, TRUE); NEED(k, "key");
    BYTE out[32]; DWORD cb = 0;
    SECURITY_STATUS s = U(NCryptKeyDerivation)(k, NULL, out, 32, &cb, 0);
    EXPECT_SS_FAIL(s); t_note("NCryptKeyDerivation on an asymmetric key -> 0x%08lx", (DWORD)s);
    nc_free(k); nc_free(p);
}

/* ---------- NCryptTranslateHandle ---------- */
TEST(ncops_translate_parameter_validation) {
    REQUIRE(U(NCryptTranslateHandle));
    NCRYPT_PROV_HANDLE ph = 0; NCRYPT_KEY_HANDLE kh = 0;
    EXPECT_SS(U(NCryptTranslateHandle)(&ph, NULL, 1, 0, 0, 0), NC_INVALID_PARAMETER);
    EXPECT_SS(U(NCryptTranslateHandle)(&ph, &kh, 0, 0, 0, 0), NC_INVALID_PARAMETER);
    EXPECT_SS(U(NCryptTranslateHandle)(NULL, NULL, 0, 0, 0, 0), NC_INVALID_PARAMETER);
    EXPECT_EQ(ph, 0); EXPECT_EQ(kh, 0);
}
TEST(ncops_translate_capi_ephemeral_note) {
    REQUIRE(U(NCryptTranslateHandle)); REQUIRE(U(CryptAcquireContextW)); REQUIRE(U(CryptGenKey));
    HCRYPTPROV hp = 0; HCRYPTKEY hk = 0;
    if (!U(CryptAcquireContextW)(&hp, NULL, MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) { t_skip("no CAPI provider"); return; }
    if (!U(CryptGenKey)(hp, AT_KEYEXCHANGE, (1024u << 16) | CRYPT_EXPORTABLE, &hk)) { U(CryptReleaseContext)(hp, 0); t_skip("cannot generate CAPI key"); return; }
    NCRYPT_PROV_HANDLE ph = 0; NCRYPT_KEY_HANDLE kh = 0;
    SECURITY_STATUS s = U(NCryptTranslateHandle)(&ph, &kh, hp, hk, AT_KEYEXCHANGE, 0);
    t_note("translate ephemeral (VERIFYCONTEXT) CAPI key -> 0x%08lx", (DWORD)s);
    if (s == 0) {
        CHECK(kh != 0 && U(NCryptIsKeyHandle)(kh));
        DWORD v; if (kh && nc_getdw(kh, NCRYPT_LENGTH_PROPERTY, &v) == 0) EXPECT_EQ(v, 1024);
        nc_free(kh); nc_free(ph);
    } else { EXPECT_EQ(kh, 0); }
    s = U(NCryptTranslateHandle)(NULL, &kh, hp, hk, AT_KEYEXCHANGE, 0x80000000u);
    t_note("translate with unknown flag -> 0x%08lx", (DWORD)s);
    if (s == 0) nc_free(kh);
    U(CryptDestroyKey)(hk); U(CryptReleaseContext)(hp, 0);
}
