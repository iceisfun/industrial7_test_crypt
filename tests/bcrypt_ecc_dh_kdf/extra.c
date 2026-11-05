/* PBKDF2 and generated-key round trips beyond the fixed vectors. */
#include "kc.h"

static const unsigned char XV_S256_1[] = {0x12,0x0f,0xb6,0xcf,0xfc,0xf8,0xb3,0x2c,0x43,0xe7,0x22,0x52,0x56,0xc4,0xf8,0x37,0xa8,0x65,0x48,0xc9,0x2c,0xcc,0x35,0x48,0x08,0x05,0x98,0x7c,0xb7,0x0b,0xe1,0x7b};
static const unsigned char XV_S256_2[] = {0xae,0x4d,0x0c,0x95,0xaf,0x6b,0x46,0xd3,0x2d,0x0a,0xdf,0xf9,0x28,0xf0,0x6d,0xd0,0x2a,0x30,0x3f,0x8e,0xf3,0xc2,0x51,0xdf,0xd6,0xe2,0xd8,0x5a,0x95,0x47,0x4c,0x43};
static const unsigned char XV_S256_4096[] = {0xc5,0xe4,0x78,0xd5,0x92,0x88,0xc8,0x41,0xaa,0x53,0x0d,0xb6,0x84,0x5c,0x4c,0x8d,0x96,0x28,0x93,0xa0,0x01,0xce,0x4e,0x11,0xa4,0x96,0x38,0x73,0xaa,0x98,0x13,0x4a};
static const unsigned char XV_S256_PASSWD[] = {0x55,0xac,0x04,0x6e,0x56,0xe3,0x08,0x9f,0xec,0x16,0x91,0xc2,0x25,0x44,0xb6,0x05,0xf9,0x41,0x85,0x21,0x6d,0xde,0x04,0x65,0xe6,0x8b,0x9d,0x57,0xc2,0x0d,0xac,0xbc,0x49,0xca,0x9c,0xcc,0xf1,0x79,0xb6,0x45,0x99,0x16,0x64,0xb3,0x9d,0x77,0xef,0x31,0x7c,0x71,0xb8,0x45,0xb1,0xe3,0x0b,0xd5,0x09,0x11,0x20,0x41,0xd3,0xa1,0x97,0x83};
static const unsigned char XV_S512_1[] = {0x86,0x7f,0x70,0xcf,0x1a,0xde,0x02,0xcf,0xf3,0x75,0x25,0x99,0xa3,0xa5,0x3d,0xc4,0xaf,0x34,0xc7,0xa6,0x69,0x81,0x5a,0xe5,0xd5,0x13,0x55,0x4e,0x1c,0x8c,0xf2,0x52,0xc0,0x2d,0x47,0x0a,0x28,0x5a,0x05,0x01,0xba,0xd9,0x99,0xbf,0xe9,0x43,0xc0,0x8f,0x05,0x02,0x35,0xd7,0xd6,0x8b,0x1d,0xa5,0x5e,0x63,0xf7,0x3b,0x60,0xa5,0x7f,0xce};

static NTSTATUS xpb(const WCHAR *hash, const void *pw, ULONG pn, const void *salt, ULONG sn, ULONGLONG it, unsigned char *o, ULONG on) {
    BCRYPT_ALG_HANDLE h = kc_open(hash, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (!h) return NS_UNSUCCESSFUL;
    NTSTATUS s = U(BCryptDeriveKeyPBKDF2)(h, (PUCHAR)pw, pn, (PUCHAR)salt, sn, it, o, on, 0);
    kc_close(h);
    return s;
}
#define XNEED() do { NEED_CORE(); if (!U(BCryptDeriveKeyPBKDF2)) { t_skip("no PBKDF2"); return; } } while (0)

TEST(bcx_pbkdf2_sha256_c1) { XNEED(); unsigned char o[32]; CHECK_NS(xpb(L"SHA256", "password", 8, "salt", 4, 1, o, 32), 0); CHECK_MEM(o, XV_S256_1, 32); }
TEST(bcx_pbkdf2_sha256_c2) { XNEED(); unsigned char o[32]; CHECK_NS(xpb(L"SHA256", "password", 8, "salt", 4, 2, o, 32), 0); CHECK_MEM(o, XV_S256_2, 32); }
TEST(bcx_pbkdf2_sha256_c4096) { XNEED(); unsigned char o[32]; CHECK_NS(xpb(L"SHA256", "password", 8, "salt", 4, 4096, o, 32), 0); CHECK_MEM(o, XV_S256_4096, 32); }
TEST(bcx_pbkdf2_sha256_multiblock) { XNEED(); unsigned char o[64]; CHECK_NS(xpb(L"SHA256", "passwd", 6, "salt", 4, 1, o, 64), 0); CHECK_MEM(o, XV_S256_PASSWD, 64); }
TEST(bcx_pbkdf2_sha256_prefix_property) {
    XNEED(); unsigned char o[40];
    CHECK_NS(xpb(L"SHA256", "passwd", 6, "salt", 4, 1, o, 40), 0);
    CHECK_MEM(o, XV_S256_PASSWD, 40);
}
TEST(bcx_pbkdf2_sha512_c1) { XNEED(); unsigned char o[64]; CHECK_NS(xpb(L"SHA512", "password", 8, "salt", 4, 1, o, 64), 0); CHECK_MEM(o, XV_S512_1, 64); }
TEST(bcx_pbkdf2_one_byte_output) {
    XNEED(); unsigned char o[2] = { 0, 0xAA };
    CHECK_NS(xpb(L"SHA256", "password", 8, "salt", 4, 1, o, 1), 0);
    EXPECT_EQ(o[0], XV_S256_1[0]); EXPECT_EQ(o[1], 0xAA);
}

/* Generated keys: sign / verify / agree on every curve. */
CURVE_TESTS(bcx_generated_sign_verify) {
    BCRYPT_ALG_HANDLE a = kc_open(c->dsa, 0);
    BCRYPT_KEY_HANDLE k = kc_gen(a, c->bits, 1);
    if (!k) { CHECK(0 && "keygen"); return; }
    unsigned char sig1[140], sig2[140], pub[300]; ULONG n1 = 0, n2 = 0, pn = 0;
    CHECK_NS(U(BCryptSignHash)(k, NULL, (PUCHAR)c->hash, c->hashlen, sig1, sizeof(sig1), &n1, 0), 0);
    CHECK_NS(U(BCryptSignHash)(k, NULL, (PUCHAR)c->hash, c->hashlen, sig2, sizeof(sig2), &n2, 0), 0);
    EXPECT_EQ(n1, 2 * c->cb); EXPECT_EQ(n2, 2 * c->cb);
    CHECK_NS(U(BCryptVerifySignature)(k, NULL, (PUCHAR)c->hash, c->hashlen, sig1, n1, 0), 0);
    CHECK_NS(U(BCryptVerifySignature)(k, NULL, (PUCHAR)c->hash, c->hashlen, sig2, n2, 0), 0);
    CHECK(memcmp(sig1, sig2, n1) != 0);   /* ECDSA signing is randomized: two signatures over the same hash differ */
    CHECK_NS(kc_export(k, BCRYPT_ECCPUBLIC_BLOB, pub, sizeof(pub), &pn), 0);
    EXPECT_EQ(pn, sizeof(BCRYPT_ECCKEY_BLOB) + 2 * c->cb);
    BCRYPT_KEY_HANDLE pk = NULL;
    CHECK_NS(kc_import(a, BCRYPT_ECCPUBLIC_BLOB, pub, pn, 0, &pk), 0);
    CHECK_NS(U(BCryptVerifySignature)(pk, NULL, (PUCHAR)c->hash, c->hashlen, sig1, n1, 0), 0);
    sig1[0] ^= 1;
    CHECK_NS(U(BCryptVerifySignature)(pk, NULL, (PUCHAR)c->hash, c->hashlen, sig1, n1, 0), NS_INVALID_SIGNATURE);
    kc_destroy(pk); kc_destroy(k); kc_close(a);
}

CURVE_TESTS(bcx_generated_ecdh_agree) {
    BCRYPT_ALG_HANDLE a = kc_open(c->dh, 0);
    BCRYPT_KEY_HANDLE k1 = kc_gen(a, c->bits, 1), k2 = kc_gen(a, c->bits, 1);
    if (!k1 || !k2) { CHECK(0 && "keygen"); return; }
    unsigned char p1[300], p2[300], r1[80], r2[80]; ULONG n1 = 0, n2 = 0, m1 = 0, m2 = 0;
    CHECK_NS(kc_export(k1, BCRYPT_ECCPUBLIC_BLOB, p1, sizeof(p1), &n1), 0);
    CHECK_NS(kc_export(k2, BCRYPT_ECCPUBLIC_BLOB, p2, sizeof(p2), &n2), 0);
    BCRYPT_KEY_HANDLE pub1 = NULL, pub2 = NULL;
    CHECK_NS(kc_import(a, BCRYPT_ECCPUBLIC_BLOB, p1, n1, 0, &pub1), 0);
    CHECK_NS(kc_import(a, BCRYPT_ECCPUBLIC_BLOB, p2, n2, 0, &pub2), 0);
    NTSTATUS s1, s2;
    BCRYPT_SECRET_HANDLE x1 = kc_agree(k1, pub2, &s1), x2 = kc_agree(k2, pub1, &s2);
    CHECK_NS(s1, 0); CHECK_NS(s2, 0);
    if (x1 && x2) {
        CHECK_NS(U(BCryptDeriveKey)(x1, BCRYPT_KDF_RAW_SECRET, NULL, r1, sizeof(r1), &m1, 0), 0);
        CHECK_NS(U(BCryptDeriveKey)(x2, BCRYPT_KDF_RAW_SECRET, NULL, r2, sizeof(r2), &m2, 0), 0);
        EXPECT_EQ(m1, c->cb); EXPECT_EQ(m2, c->cb);
        CHECK_MEM(r1, r2, c->cb);
    }
    if (x1) U(BCryptDestroySecret)(x1);
    if (x2) U(BCryptDestroySecret)(x2);
    kc_destroy(pub1); kc_destroy(pub2); kc_destroy(k1); kc_destroy(k2); kc_close(a);
}
