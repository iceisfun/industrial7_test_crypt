/* Pseudo (constant) algorithm handles, BCRYPT_*_ALG_HANDLE: property queries, read-only, close. */
#include "ap.h"

struct ph {
    ULONG_PTR h;
    const char *tag;
    const WCHAR *name;   /* AlgorithmName; NULL = observe only */
    const WCHAR *mode;   /* ChainingMode for ciphers, NULL otherwise */
    int fam;             /* 1 cipher 2 hash 3 hmac 4 rng 5 rsa 6 rsasign 7 dsa 8 dh 9 ecc 10 kd 11 generic/observe */
    int blk, hlen, kmin, kmax, kinc;
};
#define CBC BCRYPT_CHAIN_MODE_CBC
#define ECB BCRYPT_CHAIN_MODE_ECB
#define CFB BCRYPT_CHAIN_MODE_CFB
#define CCM BCRYPT_CHAIN_MODE_CCM
#define GCM BCRYPT_CHAIN_MODE_GCM
static const struct ph g_ph[] = {
 { 0x001, "md2",      L"MD2",    NULL, 2, 0, 16, -1,-1,-1 },
 { 0x011, "md4",      L"MD4",    NULL, 2, 0, 16, -1,-1,-1 },
 { 0x021, "md5",      L"MD5",    NULL, 2, 0, 16, -1,-1,-1 },
 { 0x031, "sha1",     L"SHA1",   NULL, 2, 0, 20, -1,-1,-1 },
 { 0x041, "sha256",   L"SHA256", NULL, 2, 0, 32, -1,-1,-1 },
 { 0x051, "sha384",   L"SHA384", NULL, 2, 0, 48, -1,-1,-1 },
 { 0x061, "sha512",   L"SHA512", NULL, 2, 0, 64, -1,-1,-1 },
 { 0x071, "rc4",      L"RC4",    NULL, 1, -1, 0, -1,-1,-1 },
 { 0x081, "rng",      L"RNG",    NULL, 4, 0, 0, -1,-1,-1 },
 { 0x091, "hmac_md5", NULL,      NULL, 3, 0, 16, -1,-1,-1 },
 { 0x0a1, "hmac_sha1",NULL,      NULL, 3, 0, 20, -1,-1,-1 },
 { 0x0b1, "hmac_sha256",NULL,    NULL, 3, 0, 32, -1,-1,-1 },
 { 0x0c1, "hmac_sha384",NULL,    NULL, 3, 0, 48, -1,-1,-1 },
 { 0x0d1, "hmac_sha512",NULL,    NULL, 3, 0, 64, -1,-1,-1 },
 { 0x0e1, "rsa",      L"RSA",    NULL, 5, 0, 0, 512, 16384, 8 },
 { 0x0f1, "ecdsa",    NULL,      NULL, 11, 0, 0, -1,-1,-1 },
 { 0x101, "aes_cmac", NULL,      NULL, 11, 0, 0, -1,-1,-1 },
 { 0x111, "aes_gmac", NULL,      NULL, 11, 0, 0, -1,-1,-1 },
 { 0x121, "hmac_md2", NULL,      NULL, 3, 0, 16, -1,-1,-1 },
 { 0x131, "hmac_md4", NULL,      NULL, 3, 0, 16, -1,-1,-1 },
 { 0x141, "3des_cbc", L"3DES",   CBC, 1, 8, 0, 192,192,0 },
 { 0x151, "3des_ecb", L"3DES",   ECB, 1, 8, 0, 192,192,0 },
 { 0x161, "3des_cfb", L"3DES",   CFB, 1, 8, 0, 192,192,0 },
 { 0x171, "3des112_cbc", L"3DES_112", CBC, 1, 8, 0, 128,128,0 },
 { 0x181, "3des112_ecb", L"3DES_112", ECB, 1, 8, 0, 128,128,0 },
 { 0x191, "3des112_cfb", L"3DES_112", CFB, 1, 8, 0, 128,128,0 },
 { 0x1a1, "aes_cbc",  L"AES",    CBC, 1, 16, 0, 128,256,64 },
 { 0x1b1, "aes_ecb",  L"AES",    ECB, 1, 16, 0, 128,256,64 },
 { 0x1c1, "aes_cfb",  L"AES",    CFB, 1, 16, 0, 128,256,64 },
 { 0x1d1, "aes_ccm",  L"AES",    CCM, 1, 16, 0, 128,256,64 },
 { 0x1e1, "aes_gcm",  L"AES",    GCM, 1, 16, 0, 128,256,64 },
 { 0x1f1, "des_cbc",  L"DES",    CBC, 1, 8, 0, 64,64,0 },
 { 0x201, "des_ecb",  L"DES",    ECB, 1, 8, 0, 64,64,0 },
 { 0x211, "des_cfb",  L"DES",    CFB, 1, 8, 0, 64,64,0 },
 { 0x221, "desx_cbc", L"DESX",   CBC, 1, 8, 0, 192,192,0 },
 { 0x231, "desx_ecb", L"DESX",   ECB, 1, 8, 0, 192,192,0 },
 { 0x241, "desx_cfb", L"DESX",   CFB, 1, 8, 0, 192,192,0 },
 { 0x251, "rc2_cbc",  L"RC2",    CBC, 1, 8, 0, -1,-1,-1 },
 { 0x261, "rc2_ecb",  L"RC2",    ECB, 1, 8, 0, -1,-1,-1 },
 { 0x271, "rc2_cfb",  L"RC2",    CFB, 1, 8, 0, -1,-1,-1 },
 { 0x281, "dh",       L"DH",     NULL, 8, 0, 0, 512, 4096, 8 },
 { 0x291, "ecdh",     NULL,      NULL, 11, 0, 0, -1,-1,-1 },
 { 0x2a1, "ecdh256",  NULL,      NULL, 9, 0, 0, 256,256,0 },
 { 0x2b1, "ecdh384",  NULL,      NULL, 9, 0, 0, 384,384,0 },
 { 0x2c1, "ecdh521",  NULL,      NULL, 9, 0, 0, 521,521,0 },
 { 0x2d1, "dsa",      L"DSA",    NULL, 7, 0, 0, 512, 3072, 64 },
 { 0x2e1, "ecdsa256", NULL,      NULL, 9, 0, 0, 256,256,0 },
 { 0x2f1, "ecdsa384", NULL,      NULL, 9, 0, 0, 384,384,0 },
 { 0x301, "ecdsa521", NULL,      NULL, 9, 0, 0, 521,521,0 },
 { 0x311, "rsa_sign", L"RSA_SIGN", NULL, 6, 0, 0, 512, 16384, 8 },
 { 0x321, "capi_kdf", L"CAPI_KDF", NULL, 10, 0, 0, 0,16384,8 },
 { 0x331, "pbkdf2",   L"PBKDF2", NULL, 10, 0, 0, 0,16384,8 },
 { 0x341, "sp800108", L"SP800_108_CTR_HMAC", NULL, 10, 0, 0, 0,16384,8 },
 { 0x351, "sp80056a", L"SP800_56A_CONCAT", NULL, 10, 0, 0, 0,16384,8 },
 { 0x361, "tls11",    L"TLS1_1_KDF", NULL, 10, 0, 0, 0,16384,8 },
 { 0x371, "tls12",    L"TLS1_2_KDF", NULL, 10, 0, 0, 0,16384,8 },
 { 0x381, "xts",      L"XTS-AES", NULL, 11, 0, 0, -1,-1,-1 },
 { 0x391, "hkdf",     L"HKDF",   NULL, 10, 0, 0, 0,16384,8 },
};
#define NPH ((int)(sizeof(g_ph) / sizeof(g_ph[0])))
#define PH(p) ((BCRYPT_ALG_HANDLE)(p)->h)

static int mode_eq(BCRYPT_HANDLE h, const WCHAR *m) {
    UCHAR raw[64]; ULONG res = 0; memset(raw, 0, 64);
    if (U(BCryptGetProperty)(h, BCRYPT_CHAINING_MODE, raw, 64, &res, 0) < 0) return 0;
    raw[62] = raw[63] = 0;
    return !lstrcmpW((WCHAR *)raw, m);
}

static void ph_check(const struct ph *p) {
    NEED_CORE();
    BCRYPT_ALG_HANDLE h = PH(p);
    WCHAR nm[64]; ULONG cb = 0, v = 0;
    NTSTATUS s = ap_getstr(h, BCRYPT_ALGORITHM_NAME, nm, 64, &cb);
    NT_OK(s);
    if (s >= 0 && p->name) { CHECK(!lstrcmpW(nm, p->name)); EXPECT_EQ(cb, (lstrlenW(p->name) + 1) * 2); }
    else if (s >= 0) t_note("%s: AlgorithmName=\"%ls\"", p->tag, nm);
    if (p->fam == 1) {
        if (p->blk > 0) { NT_OK(ap_getdw(h, BCRYPT_BLOCK_LENGTH, &v, &cb)); EXPECT_EQ(v, p->blk); }
        if (p->mode) CHECK(mode_eq(h, p->mode));
        if (p->kmin >= 0) {
            BCRYPT_KEY_LENGTHS_STRUCT kl = { 0 };
            NT_OK(AP_GET(h, BCRYPT_KEY_LENGTHS, &kl, sizeof(kl), &cb));
            EXPECT_EQ(kl.dwMinLength, p->kmin); EXPECT_EQ(kl.dwMaxLength, p->kmax); EXPECT_EQ(kl.dwIncrement, p->kinc);
        }
        NT_OK(ap_getdw(h, BCRYPT_PRIMITIVE_TYPE, &v, &cb)); EXPECT_EQ(v, 1);
        NT_OK(ap_getdw(h, BCRYPT_OBJECT_LENGTH, &v, &cb)); CHECK(v > 0);
    } else if (p->fam == 2 || p->fam == 3) {
        NT_OK(ap_getdw(h, BCRYPT_HASH_LENGTH, &v, &cb)); EXPECT_EQ(v, p->hlen);
        NT_OK(ap_getdw(h, BCRYPT_PRIMITIVE_TYPE, &v, &cb)); EXPECT_EQ(v, 2);
        NT_OK(ap_getdw(h, BCRYPT_IS_KEYED_HASH, &v, &cb)); EXPECT_EQ(v, p->fam == 3 ? 1 : 0);
        NT_OK(ap_getdw(h, BCRYPT_OBJECT_LENGTH, &v, &cb)); CHECK(v > 0);
    } else if (p->fam == 4) {
        NT_OK(ap_getdw(h, BCRYPT_PRIMITIVE_TYPE, &v, &cb)); EXPECT_EQ(v, 6);
        NT_EQ(ap_getdw(h, BCRYPT_OBJECT_LENGTH, &v, &cb), AP_NOT_SUPPORTED);
    } else if (p->fam == 5 || p->fam == 6) {
        NT_OK(ap_getdw(h, BCRYPT_PADDING_SCHEMES, &v, &cb)); EXPECT_EQ(v, p->fam == 5 ? 0x1e : 0x14);
    } else if (p->fam == 10) {
        NT_OK(ap_getdw(h, BCRYPT_PRIMITIVE_TYPE, &v, &cb)); EXPECT_EQ(v, 7);
    }
    if ((p->fam == 5 || p->fam == 6 || p->fam == 7 || p->fam == 8 || p->fam == 9 || p->fam == 10) && p->kmin >= 0) {
        BCRYPT_KEY_LENGTHS_STRUCT kl = { 0 };
        NT_OK(AP_GET(h, BCRYPT_KEY_LENGTHS, &kl, sizeof(kl), &cb));
        EXPECT_EQ(kl.dwMinLength, p->kmin); EXPECT_EQ(kl.dwMaxLength, p->kmax); EXPECT_EQ(kl.dwIncrement, p->kinc);
    }
    if (p->fam == 9) {
        WCHAR cn[40];
        NT_OK(ap_getstr(h, BCRYPT_ECC_CURVE_NAME, cn, 40, &cb));
        const WCHAR *want = p->kmin == 256 ? L"nistP256" : p->kmin == 384 ? L"nistP384" : L"nistP521";
        CHECK(!lstrcmpW(cn, want));
    }
    /* every pseudo handle exposes a provider handle */
    UCHAR b[8] = { 0 }; ULONG_PTR ph1, ph2;
    NT_OK(AP_GET(h, BCRYPT_PROVIDER_HANDLE, b, 8, &cb)); EXPECT_EQ(cb, 8); memcpy(&ph1, b, 8);
    NT_OK(AP_GET(h, BCRYPT_PROVIDER_HANDLE, b, 8, &cb)); memcpy(&ph2, b, 8);
    CHECK(ph1 != 0 && ph1 == ph2);                  /* the backing object is created once and cached */
    /* unknown properties behave as on an opened handle */
    UCHAR junk[16];
    NT_EQ(AP_GET(h, L"NoSuchProperty", junk, 16, &cb), AP_NOT_SUPPORTED);
    NT_EQ(AP_GET(h, BCRYPT_ALGORITHM_NAME, junk, 2, &cb), AP_BUF_TOO_SMALL);
}
static void ph_ro(const struct ph *p) {
    NEED_CORE();
    ULONG v = 1;
    NT_EQ(AP_SET(PH(p), L"NoSuchProperty", &v, 4), AP_ACCESS_DENIED);
    NT_EQ(AP_SET(PH(p), BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC)), AP_ACCESS_DENIED);
    NT_EQ(AP_CLOSE(PH(p)), AP_INVALID_HANDLE);
    /* still usable */
    ULONG cb = 0;
    NT_OK(ap_getdw(PH(p), BCRYPT_PRIMITIVE_TYPE, &v, &cb));
}
#define GEN_PH(i, tag) \
  TEST(ap_pseudo_props_##tag) { ph_check(&g_ph[i]); } \
  TEST(ap_pseudo_readonly_##tag) { ph_ro(&g_ph[i]); }
GEN_PH(0, md2) GEN_PH(1, md4) GEN_PH(2, md5) GEN_PH(3, sha1) GEN_PH(4, sha256) GEN_PH(5, sha384) GEN_PH(6, sha512)
GEN_PH(7, rc4) GEN_PH(8, rng) GEN_PH(9, hmac_md5) GEN_PH(10, hmac_sha1) GEN_PH(11, hmac_sha256) GEN_PH(12, hmac_sha384) GEN_PH(13, hmac_sha512)
GEN_PH(14, rsa) GEN_PH(15, ecdsa) GEN_PH(16, aes_cmac) GEN_PH(17, aes_gmac) GEN_PH(18, hmac_md2) GEN_PH(19, hmac_md4)
GEN_PH(20, des3_cbc) GEN_PH(21, des3_ecb) GEN_PH(22, des3_cfb) GEN_PH(23, des3_112_cbc) GEN_PH(24, des3_112_ecb) GEN_PH(25, des3_112_cfb)
GEN_PH(26, aes_cbc) GEN_PH(27, aes_ecb) GEN_PH(28, aes_cfb) GEN_PH(29, aes_ccm) GEN_PH(30, aes_gcm)
GEN_PH(31, des_cbc) GEN_PH(32, des_ecb) GEN_PH(33, des_cfb) GEN_PH(34, desx_cbc) GEN_PH(35, desx_ecb) GEN_PH(36, desx_cfb)
GEN_PH(37, rc2_cbc) GEN_PH(38, rc2_ecb) GEN_PH(39, rc2_cfb) GEN_PH(40, dh) GEN_PH(41, ecdh) GEN_PH(42, ecdh256) GEN_PH(43, ecdh384) GEN_PH(44, ecdh521)
GEN_PH(45, dsa) GEN_PH(46, ecdsa256) GEN_PH(47, ecdsa384) GEN_PH(48, ecdsa521) GEN_PH(49, rsa_sign) GEN_PH(50, capi_kdf) GEN_PH(51, pbkdf2)
GEN_PH(52, sp800108) GEN_PH(53, sp80056a) GEN_PH(54, tls11) GEN_PH(55, tls12) GEN_PH(56, xts) GEN_PH(57, hkdf)

TEST(ap_pseudo_table_sanity) {
    EXPECT_EQ(NPH, 58);
    for (int i = 0; i < NPH; i++) EXPECT_EQ(g_ph[i].h, (ULONG_PTR)i * 0x10 + 1);   /* contiguous run of handle values */
}

TEST(ap_pseudo_authtag_modes) {
    NEED_CORE();
    UCHAR raw[12]; ULONG cb = 0;
    BCRYPT_AUTH_TAG_LENGTHS_STRUCT t;
    NT_OK(AP_GET((BCRYPT_ALG_HANDLE)(ULONG_PTR)0x1e1, BCRYPT_AUTH_TAG_LENGTH, raw, 12, &cb));
    memcpy(&t, raw, 12); EXPECT_EQ(t.dwMinLength, 12); EXPECT_EQ(t.dwMaxLength, 16); EXPECT_EQ(t.dwIncrement, 1);
    NT_OK(AP_GET((BCRYPT_ALG_HANDLE)(ULONG_PTR)0x1d1, BCRYPT_AUTH_TAG_LENGTH, raw, 12, &cb));
    memcpy(&t, raw, 12); EXPECT_EQ(t.dwMinLength, 4); EXPECT_EQ(t.dwMaxLength, 16); EXPECT_EQ(t.dwIncrement, 2);
    NT_EQ(AP_GET((BCRYPT_ALG_HANDLE)(ULONG_PTR)0x1a1, BCRYPT_AUTH_TAG_LENGTH, raw, 12, &cb), AP_NOT_SUPPORTED);
    NT_EQ(AP_GET((BCRYPT_ALG_HANDLE)(ULONG_PTR)0x1f1, BCRYPT_AUTH_TAG_LENGTH, raw, 12, &cb), AP_NOT_SUPPORTED);
}
TEST(ap_pseudo_matches_real_handle) {
    NEED_CORE();
    static const struct { ULONG_PTR p; const WCHAR *id; } c[] = { { 0x41, L"SHA256" }, { 0x1a1, L"AES" }, { 0x21, L"MD5" }, { 0x31, L"SHA1" }, { 0x61, L"SHA512" }, { 0x1f1, L"DES" }, { 0x141, L"3DES" } };
    for (unsigned i = 0; i < sizeof(c) / sizeof(c[0]); i++) {
        BCRYPT_ALG_HANDLE h = NULL;
        NT_OK(AP_OPEN(&h, c[i].id, NULL, 0));
        if (!h) continue;
        ULONG a = 0, b = 0, cb;
        NT_OK(ap_getdw(h, BCRYPT_OBJECT_LENGTH, &a, &cb));
        NT_OK(ap_getdw((BCRYPT_ALG_HANDLE)c[i].p, BCRYPT_OBJECT_LENGTH, &b, &cb));
        if (a != b) t_note("%ls ObjectLength real=%lu pseudo=%lu", c[i].id, (unsigned long)a, (unsigned long)b);
        EXPECT_EQ(a, b);
        AP_CLOSE(h);
    }
}
TEST(ap_pseudo_unmapped_values_invalid) {
    NEED_CORE();
    static const ULONG_PTR bad[] = { 0x3a1, 0x3b1, 0x401, 0x451, 0x1001, 0xff1, 0x10001 };
    for (unsigned i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        ULONG v = 0, cb = 0;
        NT_EQ(ap_getdw((BCRYPT_ALG_HANDLE)bad[i], BCRYPT_OBJECT_LENGTH, &v, &cb), AP_INVALID_HANDLE);
        NT_EQ(AP_CLOSE((BCRYPT_ALG_HANDLE)bad[i]), AP_INVALID_HANDLE);
    }
}
TEST(ap_pseudo_handle_in_getprop_argument_order) {
    NEED_CORE();
    ULONG v = 0, cb = 0;
    NT_EQ(U(BCryptGetProperty)((BCRYPT_ALG_HANDLE)(ULONG_PTR)0x41, NULL, (PUCHAR)&v, 4, &cb, 0), AP_INVALID_PARAM);
    NT_EQ(U(BCryptGetProperty)((BCRYPT_ALG_HANDLE)(ULONG_PTR)0x41, BCRYPT_HASH_LENGTH, (PUCHAR)&v, 4, NULL, 0), AP_INVALID_PARAM);
    NT_OK(U(BCryptGetProperty)((BCRYPT_ALG_HANDLE)(ULONG_PTR)0x41, BCRYPT_HASH_LENGTH, (PUCHAR)&v, 4, &cb, 0));
    EXPECT_EQ(v, 32);
}
TEST(ap_pseudo_hash_oneshot_works) {
    /* a pseudo handle is a legal algorithm handle for the consumers; spot check SHA-256("abc") from FIPS 180-4 */
    REQUIRE(U(BCryptHash));
    static const UCHAR kat[32] = { 0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
                                   0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad };
    UCHAR out[32] = { 0 };
    NT_OK(U(BCryptHash)((BCRYPT_ALG_HANDLE)(ULONG_PTR)0x41, NULL, 0, (PUCHAR)"abc", 3, out, 32));
    CHECK(!memcmp(out, kat, 32));
}
