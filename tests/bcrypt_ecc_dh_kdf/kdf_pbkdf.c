/* BCryptDeriveKeyPBKDF2, BCryptKeyDerivation (PBKDF2, SP800-108 CTR HMAC, HKDF) and BCryptDeriveKeyCapi. */
#include "kc.h"

static const unsigned char PW[] = "password";
static const unsigned char SALT[] = "salt";

static BCRYPT_ALG_HANDLE hmac_alg(const WCHAR *hash) { return kc_open(hash, BCRYPT_ALG_HANDLE_HMAC_FLAG); }

static NTSTATUS pbk(BCRYPT_ALG_HANDLE h, const void *pw, ULONG pwn, const void *salt, ULONG sn, ULONGLONG it, unsigned char *out, ULONG outn) {
    return U(BCryptDeriveKeyPBKDF2)(h, (PUCHAR)pw, pwn, (PUCHAR)salt, sn, it, out, outn, 0);
}
#define NEED_PB() do { NEED_CORE(); if (!U(BCryptDeriveKeyPBKDF2)) { t_skip("no BCryptDeriveKeyPBKDF2"); return; } } while (0)

/* ---- RFC 6070 and further known answers ----------------------------------------------------------------------------- */
TEST(bckdf_pbkdf2_rfc6070_1) {
    NEED_PB();
    BCRYPT_ALG_HANDLE h = hmac_alg(L"SHA1"); unsigned char o[20];
    CHECK_NS(pbk(h, PW, 8, SALT, 4, 1, o, 20), 0); CHECK_MEM(o, PB_RFC6070_1, 20); kc_close(h);
}
TEST(bckdf_pbkdf2_rfc6070_2) {
    NEED_PB();
    BCRYPT_ALG_HANDLE h = hmac_alg(L"SHA1"); unsigned char o[20];
    CHECK_NS(pbk(h, PW, 8, SALT, 4, 2, o, 20), 0); CHECK_MEM(o, PB_RFC6070_2, 20); kc_close(h);
}
TEST(bckdf_pbkdf2_rfc6070_3) {
    NEED_PB();
    BCRYPT_ALG_HANDLE h = hmac_alg(L"SHA1"); unsigned char o[20];
    CHECK_NS(pbk(h, PW, 8, SALT, 4, 4096, o, 20), 0); CHECK_MEM(o, PB_RFC6070_3, 20); kc_close(h);
}
TEST(bckdf_pbkdf2_rfc6070_4) {
    NEED_PB();
    BCRYPT_ALG_HANDLE h = hmac_alg(L"SHA1"); unsigned char o[25];
    CHECK_NS(pbk(h, "passwordPASSWORDpassword", 24, "saltSALTsaltSALTsaltSALTsaltSALTsalt", 36, 4096, o, 25), 0);
    CHECK_MEM(o, PB_RFC6070_4, 25); kc_close(h);
}
TEST(bckdf_pbkdf2_rfc6070_5_embedded_nul) {
    NEED_PB();
    BCRYPT_ALG_HANDLE h = hmac_alg(L"SHA1"); unsigned char o[16];
    CHECK_NS(pbk(h, "pass\0word", 9, "sa\0lt", 5, 4096, o, 16), 0);
    CHECK_MEM(o, PB_RFC6070_5, 16); kc_close(h);
}
TEST(bckdf_pbkdf2_sha256) {
    NEED_PB();
    BCRYPT_ALG_HANDLE h = hmac_alg(L"SHA256"); unsigned char o[64];
    CHECK_NS(pbk(h, PW, 8, SALT, 4, 1, o, 32), 0); CHECK_MEM(o, PB_256_1, 32);
    CHECK_NS(pbk(h, PW, 8, SALT, 4, 4096, o, 64), 0); CHECK_MEM(o, PB_256_4096_64, 64);
    CHECK_NS(pbk(h, PW, 8, SALT, 4, 10000, o, 32), 0); CHECK_MEM(o, PB_256_DEFAULT10000, 32);
    kc_close(h);
}
TEST(bckdf_pbkdf2_sha384_sha512_md5) {
    NEED_PB();
    unsigned char o[128];
    BCRYPT_ALG_HANDLE h = hmac_alg(L"SHA384");
    CHECK_NS(pbk(h, PW, 8, SALT, 4, 2, o, 48), 0); CHECK_MEM(o, PB_384_2_48, 48); kc_close(h);
    h = hmac_alg(L"SHA512");
    CHECK_NS(pbk(h, PW, 8, SALT, 4, 1, o, 64), 0); CHECK_MEM(o, PB_512_1_64, 64);
    CHECK_NS(pbk(h, PW, 8, SALT, 4, 1000, o, 100), 0); CHECK_MEM(o, PB_512_1000_100, 100); kc_close(h);
    h = hmac_alg(L"MD5");
    CHECK_NS(pbk(h, PW, 8, SALT, 4, 1, o, 16), 0); CHECK_MEM(o, PB_MD5_1, 16); kc_close(h);
}
TEST(bckdf_pbkdf2_output_lengths) {
    NEED_PB();
    BCRYPT_ALG_HANDLE h = hmac_alg(L"SHA256"); unsigned char o[40];
    memset(o, 0xA5, sizeof(o));
    CHECK_NS(pbk(h, PW, 8, SALT, 4, 1, o, 1), 0);
    EXPECT_EQ(o[0], PB_256_1_1[0]);
    EXPECT_EQ(o[1], 0xA5);                                       /* nothing written past the request */
    CHECK_NS(pbk(h, PW, 8, SALT, 4, 1, o, 33), 0);                /* second block is partially used */
    CHECK_MEM(o, PB_256_33, 33);
    EXPECT_EQ(o[33], 0xA5);
    kc_close(h);
}
TEST(bckdf_pbkdf2_prefix_property) {
    NEED_PB();
    BCRYPT_ALG_HANDLE h = hmac_alg(L"SHA256"); unsigned char a[64], b[16];
    CHECK_NS(pbk(h, PW, 8, SALT, 4, 4096, a, 64), 0);
    CHECK_NS(pbk(h, PW, 8, SALT, 4, 4096, b, 16), 0);
    CHECK_MEM(a, b, 16);
    kc_close(h);
}
TEST(bckdf_pbkdf2_empty_inputs) {
    NEED_PB();
    BCRYPT_ALG_HANDLE h = hmac_alg(L"SHA256"); unsigned char o[32];
    CHECK_NS(pbk(h, NULL, 0, SALT, 4, 3, o, 32), 0); CHECK_MEM(o, PB_256_EMPTYPW, 32);
    CHECK_NS(pbk(h, PW, 8, NULL, 0, 3, o, 32), 0); CHECK_MEM(o, PB_256_EMPTYSALT, 32);
    CHECK_NS(pbk(h, NULL, 0, NULL, 0, 1, o, 32), 0); CHECK_MEM(o, PB_256_EMPTYBOTH, 32);
    unsigned char dummy = 1;
    CHECK_NS(pbk(h, &dummy, 0, &dummy, 0, 1, o, 32), 0); CHECK_MEM(o, PB_256_EMPTYBOTH, 32);   /* non-NULL, zero length */
    kc_close(h);
}
TEST(bckdf_pbkdf2_long_password) {
    NEED_PB();
    BCRYPT_ALG_HANDLE h = hmac_alg(L"SHA256"); unsigned char o[32], pw[200];
    memset(pw, 'p', sizeof(pw));
    CHECK_NS(pbk(h, pw, 200, SALT, 4, 2, o, 32), 0); CHECK_MEM(o, PB_256_LONGPW, 32);
    kc_close(h);
}

/* ---- alg handle forms ------------------------------------------------------------------------------------------------ */
TEST(bckdf_pbkdf2_pseudo_handles) {
    NEED_PB();
    unsigned char o[64];
    CHECK_NS(pbk(BCRYPT_HMAC_SHA1_ALG_HANDLE, PW, 8, SALT, 4, 4096, o, 20), 0); CHECK_MEM(o, PB_RFC6070_3, 20);
    CHECK_NS(pbk(BCRYPT_HMAC_SHA256_ALG_HANDLE, PW, 8, SALT, 4, 1, o, 32), 0); CHECK_MEM(o, PB_256_1, 32);
    CHECK_NS(pbk(BCRYPT_HMAC_SHA384_ALG_HANDLE, PW, 8, SALT, 4, 2, o, 48), 0); CHECK_MEM(o, PB_384_2_48, 48);
    CHECK_NS(pbk(BCRYPT_HMAC_SHA512_ALG_HANDLE, PW, 8, SALT, 4, 1, o, 64), 0); CHECK_MEM(o, PB_512_1_64, 64);
    CHECK_NS(pbk(BCRYPT_HMAC_MD5_ALG_HANDLE, PW, 8, SALT, 4, 1, o, 16), 0); CHECK_MEM(o, PB_MD5_1, 16);
}
TEST(bckdf_pbkdf2_requires_keyed_hash) {
    NEED_PB();
    unsigned char o[32];
    BCRYPT_ALG_HANDLE h = kc_open(L"SHA256", 0);                     /* opened without the HMAC flag */
    CHECK_NS(pbk(h, PW, 8, SALT, 4, 1, o, 32), NS_INVALID_HANDLE);
    kc_close(h);
    CHECK_NS(pbk(BCRYPT_SHA256_ALG_HANDLE, PW, 8, SALT, 4, 1, o, 32), NS_INVALID_HANDLE);
    CHECK_NS(pbk(BCRYPT_SHA1_ALG_HANDLE, PW, 8, SALT, 4, 1, o, 20), NS_INVALID_HANDLE);
    h = kc_open(L"AES", 0);
    CHECK_NS(pbk(h, PW, 8, SALT, 4, 1, o, 32), NS_INVALID_HANDLE);
    kc_close(h);
    h = kc_open(L"RNG", 0);
    CHECK_NS(pbk(h, PW, 8, SALT, 4, 1, o, 32), NS_INVALID_HANDLE);
    kc_close(h);
    h = kc_open(L"ECDSA_P256", 0);
    CHECK_NS(pbk(h, PW, 8, SALT, 4, 1, o, 32), NS_INVALID_HANDLE);
    kc_close(h);
}
TEST(bckdf_pbkdf2_invalid_handles) {
    NEED_PB();
    if (t_is_wine()) { t_skip("NULL algorithm handle crashes this emulator"); return; }
    unsigned char o[32];
    CHECK_NS(pbk(NULL, PW, 8, SALT, 4, 1, o, 32), NS_INVALID_HANDLE);
}
TEST(bckdf_pbkdf2_hmac_flag_with_object_buffer_alg) {
    NEED_PB();
    BCRYPT_ALG_HANDLE h = hmac_alg(L"SHA256");
    DWORD v = 0; ULONG r = 0;
    CHECK_NS(U(BCryptGetProperty)(h, BCRYPT_IS_KEYED_HASH, (PUCHAR)&v, 4, &r, 0), 0);
    EXPECT_EQ(v, 1);
    kc_close(h);
}

/* ---- argument validation (checked before the handle) -------------------------------------------------------------------- */
TEST(bckdf_pbkdf2_zero_iterations) {
    NEED_PB();
    unsigned char o[32];
    CHECK_NS(pbk(BCRYPT_HMAC_SHA256_ALG_HANDLE, PW, 8, SALT, 4, 0, o, 32), NS_INVALID_PARAMETER);
    CHECK_NS(pbk(NULL, PW, 8, SALT, 4, 0, o, 32), NS_INVALID_PARAMETER);          /* parameter errors precede the handle check */
}
TEST(bckdf_pbkdf2_bad_flags) {
    NEED_PB();
    unsigned char o[32];
    static const ULONG flags[] = { 1, 2, 8, 0x80000000 };
    for (unsigned i = 0; i < 4; i++)
        CHECK_NS(U(BCryptDeriveKeyPBKDF2)(BCRYPT_HMAC_SHA256_ALG_HANDLE, (PUCHAR)PW, 8, (PUCHAR)SALT, 4, 1, o, 32, flags[i]), NS_INVALID_PARAMETER);
}
TEST(bckdf_pbkdf2_null_buffers) {
    NEED_PB();
    if (t_is_wine()) { t_skip("NULL buffers crash this emulator"); return; }
    unsigned char o[32];
    BCRYPT_ALG_HANDLE h = BCRYPT_HMAC_SHA256_ALG_HANDLE;
    CHECK_NS(pbk(h, NULL, 8, SALT, 4, 1, o, 32), NS_INVALID_PARAMETER);         /* NULL password with a length */
    CHECK_NS(pbk(h, PW, 8, NULL, 4, 1, o, 32), NS_INVALID_PARAMETER);           /* NULL salt with a length */
    CHECK_NS(pbk(h, PW, 8, SALT, 4, 1, NULL, 32), NS_INVALID_PARAMETER);
    CHECK_NS(pbk(h, PW, 8, SALT, 4, 1, o, 0), NS_INVALID_PARAMETER);
    CHECK_NS(pbk(h, PW, 8, SALT, 4, 1, NULL, 0), NS_INVALID_PARAMETER);
}
TEST(bckdf_pbkdf2_large_iteration_count_param) {
    NEED_PB();
    /* the count is 64-bit: values above 2^32 are accepted by the parameter check; use a failing handle so no work is done */
    unsigned char o[32];
    CHECK_NS(pbk(NULL, PW, 8, SALT, 4, 0x100000000ULL, o, 32), NS_INVALID_HANDLE);
    CHECK_NS(pbk(NULL, PW, 8, SALT, 4, 0xFFFFFFFFFFFFFFFFULL, o, 32), NS_INVALID_HANDLE);
}
TEST(bckdf_pbkdf2_different_inputs_differ) {
    NEED_PB();
    BCRYPT_ALG_HANDLE h = hmac_alg(L"SHA256"); unsigned char a[32], b[32], c[32], d[32];
    CHECK_NS(pbk(h, PW, 8, SALT, 4, 5, a, 32), 0);
    CHECK_NS(pbk(h, PW, 7, SALT, 4, 5, b, 32), 0);
    CHECK_NS(pbk(h, PW, 8, SALT, 3, 5, c, 32), 0);
    CHECK_NS(pbk(h, PW, 8, SALT, 4, 6, d, 32), 0);
    CHECK(memcmp(a, b, 32) && memcmp(a, c, 32) && memcmp(a, d, 32) && memcmp(b, c, 32));
    kc_close(h);
}
TEST(bckdf_pbkdf2_alg_handle_reusable) {
    NEED_PB();
    BCRYPT_ALG_HANDLE h = hmac_alg(L"SHA1"); unsigned char a[20], b[20];
    for (int i = 0; i < 3; i++) { CHECK_NS(pbk(h, PW, 8, SALT, 4, 2, a, 20), 0); CHECK_MEM(a, PB_RFC6070_2, 20); }
    (void)b;
    kc_close(h);
}

/* ---- BCryptKeyDerivation: PBKDF2 ----------------------------------------------------------------------------------------- */
static BCRYPT_KEY_HANDLE kd_key(const WCHAR *alg, BCRYPT_ALG_HANDLE *ph, const void *secret, ULONG n) {
    *ph = kc_open(alg, 0);
    if (!*ph) return NULL;
    BCRYPT_KEY_HANDLE k = NULL;
    if (!NT_OK(U(BCryptGenerateSymmetricKey)(*ph, &k, NULL, 0, (PUCHAR)secret, n, 0))) return NULL;
    return k;
}
#define NEED_KD() do { NEED_CORE(); if (!U(BCryptKeyDerivation) || !U(BCryptGenerateSymmetricKey)) { t_skip("no BCryptKeyDerivation"); return; } if (t_is_wine()) { t_skip("BCryptKeyDerivation aborts under this emulator"); return; } } while (0)

static void pb_desc(kc_desc *d, const WCHAR *hash, const void *salt, ULONG sn, const ULONGLONG *it) {
    kc_desc_init(d);
    if (hash) kc_desc_wstr(d, KDF_HASH_ALGORITHM, hash);
    if (salt) kc_desc_add(d, KDF_SALT, salt, sn);
    if (it) kc_desc_add(d, KDF_ITERATION_COUNT, it, 8);
}

TEST(bckdf_keyderivation_pbkdf2_vectors) {
    NEED_KD();
    BCRYPT_ALG_HANDLE a; BCRYPT_KEY_HANDLE k = kd_key(BCRYPT_PBKDF2_ALGORITHM, &a, PW, 8);
    if (!k) { t_skip("PBKDF2 key unavailable"); kc_close(a); return; }
    unsigned char o[100]; ULONG n = 0; kc_desc d; ULONGLONG it;
    it = 1; pb_desc(&d, L"SHA1", SALT, 4, &it);
    CHECK_NS(U(BCryptKeyDerivation)(k, &d.d, o, 20, &n, 0), 0); EXPECT_EQ(n, 20); CHECK_MEM(o, PB_RFC6070_1, 20);
    it = 4096; pb_desc(&d, L"SHA1", SALT, 4, &it);
    CHECK_NS(U(BCryptKeyDerivation)(k, &d.d, o, 20, &n, 0), 0); CHECK_MEM(o, PB_RFC6070_3, 20);
    it = 4096; pb_desc(&d, L"SHA256", SALT, 4, &it);
    CHECK_NS(U(BCryptKeyDerivation)(k, &d.d, o, 64, &n, 0), 0); EXPECT_EQ(n, 64); CHECK_MEM(o, PB_256_4096_64, 64);
    it = 1000; pb_desc(&d, L"SHA512", SALT, 4, &it);
    CHECK_NS(U(BCryptKeyDerivation)(k, &d.d, o, 100, &n, 0), 0); EXPECT_EQ(n, 100); CHECK_MEM(o, PB_512_1000_100, 100);
    kc_destroy(k); kc_close(a);
}
TEST(bckdf_keyderivation_pbkdf2_default_iterations) {
    NEED_KD();
    BCRYPT_ALG_HANDLE a; BCRYPT_KEY_HANDLE k = kd_key(BCRYPT_PBKDF2_ALGORITHM, &a, PW, 8);
    if (!k) { t_skip("PBKDF2 key unavailable"); kc_close(a); return; }
    unsigned char o[32]; ULONG n = 0; kc_desc d;
    pb_desc(&d, L"SHA256", SALT, 4, NULL);
    CHECK_NS(U(BCryptKeyDerivation)(k, &d.d, o, 32, &n, 0), 0);           /* absent count means 10000 */
    CHECK_MEM(o, PB_256_DEFAULT10000, 32);
    kc_destroy(k); kc_close(a);
}
TEST(bckdf_keyderivation_pbkdf2_generic_parameter_as_salt) {
    NEED_KD();
    BCRYPT_ALG_HANDLE a; BCRYPT_KEY_HANDLE k = kd_key(BCRYPT_PBKDF2_ALGORITHM, &a, PW, 8);
    if (!k) { t_skip("PBKDF2 key unavailable"); kc_close(a); return; }
    unsigned char o[20]; ULONG n = 0; kc_desc d; ULONGLONG it = 4096;
    kc_desc_init(&d); kc_desc_wstr(&d, KDF_HASH_ALGORITHM, L"SHA1");
    kc_desc_add(&d, KDF_GENERIC_PARAMETER, SALT, 4); kc_desc_add(&d, KDF_ITERATION_COUNT, &it, 8);
    CHECK_NS(U(BCryptKeyDerivation)(k, &d.d, o, 20, &n, 0), 0);
    CHECK_MEM(o, PB_RFC6070_3, 20);
    kc_destroy(k); kc_close(a);
}
TEST(bckdf_keyderivation_pbkdf2_no_salt) {
    NEED_KD();
    BCRYPT_ALG_HANDLE a; BCRYPT_KEY_HANDLE k = kd_key(BCRYPT_PBKDF2_ALGORITHM, &a, PW, 8);
    if (!k) { t_skip("PBKDF2 key unavailable"); kc_close(a); return; }
    unsigned char o[32]; ULONG n = 0; kc_desc d; ULONGLONG it = 3;
    pb_desc(&d, L"SHA256", NULL, 0, &it);
    NTSTATUS s = U(BCryptKeyDerivation)(k, &d.d, o, 32, &n, 0);
    t_note("PBKDF2 key derivation without salt -> 0x%08lx", (unsigned long)s);
    if (NT_OK(s)) { unsigned char w[32]; CHECK_NS(pbk(BCRYPT_HMAC_SHA256_ALG_HANDLE, PW, 8, NULL, 0, 3, w, 32), 0); CHECK_MEM(o, w, 32); }
    kc_destroy(k); kc_close(a);
}
TEST(bckdf_keyderivation_pbkdf2_requires_hash) {
    NEED_KD();
    BCRYPT_ALG_HANDLE a; BCRYPT_KEY_HANDLE k = kd_key(BCRYPT_PBKDF2_ALGORITHM, &a, PW, 8);
    if (!k) { t_skip("PBKDF2 key unavailable"); kc_close(a); return; }
    unsigned char o[32]; ULONG n = 0; kc_desc d; ULONGLONG it = 3;
    pb_desc(&d, NULL, SALT, 4, &it);
    CHECK_NS(U(BCryptKeyDerivation)(k, &d.d, o, 32, &n, 0), NS_INVALID_PARAMETER);
    pb_desc(&d, L"NOSUCHHASH", SALT, 4, &it);
    CHECK_NS_FAIL(U(BCryptKeyDerivation)(k, &d.d, o, 32, &n, 0));
    pb_desc(&d, L"AES", SALT, 4, &it);
    CHECK_NS_FAIL(U(BCryptKeyDerivation)(k, &d.d, o, 32, &n, 0));
    kc_destroy(k); kc_close(a);
}
TEST(bckdf_keyderivation_pbkdf2_iteration_buffer) {
    NEED_KD();
    BCRYPT_ALG_HANDLE a; BCRYPT_KEY_HANDLE k = kd_key(BCRYPT_PBKDF2_ALGORITHM, &a, PW, 8);
    if (!k) { t_skip("PBKDF2 key unavailable"); kc_close(a); return; }
    unsigned char o[32]; ULONG n = 0; kc_desc d; ULONGLONG it = 0;
    pb_desc(&d, L"SHA256", SALT, 4, &it);                              /* zero iterations */
    CHECK_NS(U(BCryptKeyDerivation)(k, &d.d, o, 32, &n, 0), NS_INVALID_PARAMETER);
    ULONG it32 = 5;
    pb_desc(&d, L"SHA256", SALT, 4, NULL);
    kc_desc_add(&d, KDF_ITERATION_COUNT, &it32, 4);                    /* the count must be a 64-bit value */
    CHECK_NS(U(BCryptKeyDerivation)(k, &d.d, o, 32, &n, 0), NS_INVALID_PARAMETER);
    kc_destroy(k); kc_close(a);
}
TEST(bckdf_keyderivation_arguments) {
    NEED_KD();
    BCRYPT_ALG_HANDLE a; BCRYPT_KEY_HANDLE k = kd_key(BCRYPT_PBKDF2_ALGORITHM, &a, PW, 8);
    if (!k) { t_skip("PBKDF2 key unavailable"); kc_close(a); return; }
    unsigned char o[32]; ULONG n = 0; kc_desc d; ULONGLONG it = 2;
    pb_desc(&d, L"SHA256", SALT, 4, &it);
    CHECK_NS(U(BCryptKeyDerivation)(k, &d.d, o, 32, NULL, 0), NS_INVALID_PARAMETER);
    CHECK_NS(U(BCryptKeyDerivation)(k, &d.d, NULL, 32, &n, 0), NS_INVALID_PARAMETER);       /* no size query mode */
    CHECK_NS(U(BCryptKeyDerivation)(k, &d.d, o, 0, &n, 0), NS_INVALID_PARAMETER);
    CHECK_NS(U(BCryptKeyDerivation)(k, NULL, o, 32, &n, 0), NS_INVALID_PARAMETER);
    CHECK_NS(U(BCryptKeyDerivation)(k, &d.d, o, 32, &n, 1), NS_INVALID_PARAMETER);
    CHECK_NS(U(BCryptKeyDerivation)(k, &d.d, o, 32, &n, 0x40000000), NS_INVALID_PARAMETER);
    CHECK_NS(U(BCryptKeyDerivation)(NULL, &d.d, o, 32, &n, 0), NS_INVALID_HANDLE);
    CHECK_NS(U(BCryptKeyDerivation)((BCRYPT_KEY_HANDLE)a, &d.d, o, 32, &n, 0), NS_INVALID_HANDLE);
    CHECK_NS(U(BCryptKeyDerivation)(k, &d.d, o, 32, &n, 0), 0);
    EXPECT_EQ(n, 32);
    kc_destroy(k); kc_close(a);
}
TEST(bckdf_keyderivation_parameter_checks_precede_handle) {
    NEED_KD();
    unsigned char o[32]; ULONG n = 0;
    CHECK_NS(U(BCryptKeyDerivation)(NULL, NULL, o, 32, NULL, 0), NS_INVALID_PARAMETER);
    CHECK_NS(U(BCryptKeyDerivation)(NULL, NULL, NULL, 32, &n, 0), NS_INVALID_PARAMETER);
    CHECK_NS(U(BCryptKeyDerivation)(NULL, NULL, o, 0, &n, 0), NS_INVALID_PARAMETER);
}
TEST(bckdf_keyderivation_wrong_key_class) {
    NEED_KD();
    BCRYPT_ALG_HANDLE a = NULL; BCRYPT_KEY_HANDLE k = kd_key(L"AES", &a, "0123456789abcdef", 16);
    unsigned char o[32]; ULONG n = 0; kc_desc d; ULONGLONG it = 2;
    pb_desc(&d, L"SHA256", SALT, 4, &it);
    CHECK_NS(U(BCryptKeyDerivation)(k, &d.d, o, 32, &n, 0), NS_NOT_SUPPORTED);
    kc_destroy(k); kc_close(a);
    BCRYPT_ALG_HANDLE e = kc_open(L"ECDH_P256", 0);
    BCRYPT_KEY_HANDLE ek = kc_gen(e, 256, 1);
    CHECK_NS(U(BCryptKeyDerivation)(ek, &d.d, o, 32, &n, 0), NS_NOT_SUPPORTED);
    kc_destroy(ek); kc_close(e);
}
TEST(bckdf_keyderivation_same_key_repeatable) {
    NEED_KD();
    BCRYPT_ALG_HANDLE a; BCRYPT_KEY_HANDLE k = kd_key(BCRYPT_PBKDF2_ALGORITHM, &a, PW, 8);
    if (!k) { t_skip("PBKDF2 key unavailable"); kc_close(a); return; }
    unsigned char o1[32], o2[32]; ULONG n = 0; kc_desc d; ULONGLONG it = 7;
    pb_desc(&d, L"SHA256", SALT, 4, &it);
    CHECK_NS(U(BCryptKeyDerivation)(k, &d.d, o1, 32, &n, 0), 0);
    CHECK_NS(U(BCryptKeyDerivation)(k, &d.d, o2, 32, &n, 0), 0);
    CHECK_MEM(o1, o2, 32);
    kc_destroy(k); kc_close(a);
}
TEST(bckdf_keyderivation_pseudo_alg_handle) {
    NEED_KD();
    BCRYPT_KEY_HANDLE k = NULL;
    NTSTATUS s = U(BCryptGenerateSymmetricKey)(BCRYPT_PBKDF2_ALG_HANDLE, &k, NULL, 0, (PUCHAR)PW, 8, 0);
    if (!NT_OK(s)) { t_note("PBKDF2 pseudo handle key -> 0x%08lx", (unsigned long)s); return; }
    unsigned char o[20]; ULONG n = 0; kc_desc d; ULONGLONG it = 4096;
    pb_desc(&d, L"SHA1", SALT, 4, &it);
    CHECK_NS(U(BCryptKeyDerivation)(k, &d.d, o, 20, &n, 0), 0);
    CHECK_MEM(o, PB_RFC6070_3, 20);
    kc_destroy(k);
}

/* ---- BCryptKeyDerivation: SP800-108 counter mode HMAC ----------------------------------------------------------------------------- */
static void s108_desc(kc_desc *d, const WCHAR *hash) {
    kc_desc_init(d);
    if (hash) kc_desc_wstr(d, KDF_HASH_ALGORITHM, hash);
    kc_desc_add(d, KDF_LABEL, S108_LABEL, S108_LABEL_LEN);
    kc_desc_add(d, KDF_CONTEXT, S108_CTX, S108_CTX_LEN);
}
TEST(bckdf_sp800108_vectors) {
    NEED_KD();
    BCRYPT_ALG_HANDLE a; BCRYPT_KEY_HANDLE k = kd_key(BCRYPT_SP800108_CTR_HMAC_ALGORITHM, &a, S108_KEY, S108_KEY_LEN);
    if (!k) { t_skip("SP800_108 unavailable"); kc_close(a); return; }
    unsigned char o[100]; ULONG n = 0; kc_desc d;
    s108_desc(&d, L"SHA256");
    CHECK_NS(U(BCryptKeyDerivation)(k, &d.d, o, 32, &n, 0), 0); EXPECT_EQ(n, 32); CHECK_MEM(o, S108_256_32, 32);
    CHECK_NS(U(BCryptKeyDerivation)(k, &d.d, o, 80, &n, 0), 0); EXPECT_EQ(n, 80); CHECK_MEM(o, S108_256_80, 80);
    s108_desc(&d, L"SHA512");
    CHECK_NS(U(BCryptKeyDerivation)(k, &d.d, o, 64, &n, 0), 0); CHECK_MEM(o, S108_512_64, 64);
    kc_destroy(k); kc_close(a);
}
TEST(bckdf_sp800108_default_hash_sha256) {
    NEED_KD();
    BCRYPT_ALG_HANDLE a; BCRYPT_KEY_HANDLE k = kd_key(BCRYPT_SP800108_CTR_HMAC_ALGORITHM, &a, S108_KEY, S108_KEY_LEN);
    if (!k) { t_skip("SP800_108 unavailable"); kc_close(a); return; }
    unsigned char o[32]; ULONG n = 0; kc_desc d;
    s108_desc(&d, NULL);
    CHECK_NS(U(BCryptKeyDerivation)(k, &d.d, o, 32, &n, 0), 0);
    CHECK_MEM(o, S108_256_32, 32);
    kc_destroy(k); kc_close(a);
}
TEST(bckdf_sp800108_length_is_part_of_input) {
    NEED_KD();
    BCRYPT_ALG_HANDLE a; BCRYPT_KEY_HANDLE k = kd_key(BCRYPT_SP800108_CTR_HMAC_ALGORITHM, &a, S108_KEY, S108_KEY_LEN);
    if (!k) { t_skip("SP800_108 unavailable"); kc_close(a); return; }
    unsigned char o32[32], o80[80]; ULONG n = 0; kc_desc d;
    s108_desc(&d, L"SHA256");
    CHECK_NS(U(BCryptKeyDerivation)(k, &d.d, o32, 32, &n, 0), 0);
    CHECK_NS(U(BCryptKeyDerivation)(k, &d.d, o80, 80, &n, 0), 0);
    CHECK(memcmp(o32, o80, 32) != 0);                                   /* L (output bits) is hashed, so prefixes differ */
    kc_destroy(k); kc_close(a);
}
TEST(bckdf_sp800108_label_context_rules) {
    NEED_KD();
    BCRYPT_ALG_HANDLE a; BCRYPT_KEY_HANDLE k = kd_key(BCRYPT_SP800108_CTR_HMAC_ALGORITHM, &a, S108_KEY, S108_KEY_LEN);
    if (!k) { t_skip("SP800_108 unavailable"); kc_close(a); return; }
    unsigned char o[32]; ULONG n = 0; kc_desc d;
    /* a generic (pre-formatted) parameter cannot be combined with a label or context */
    kc_desc_init(&d); kc_desc_wstr(&d, KDF_HASH_ALGORITHM, L"SHA256");
    kc_desc_add(&d, KDF_GENERIC_PARAMETER, "fixed", 5); kc_desc_add(&d, KDF_LABEL, S108_LABEL, S108_LABEL_LEN);
    CHECK_NS(U(BCryptKeyDerivation)(k, &d.d, o, 32, &n, 0), NS_INVALID_PARAMETER);
    kc_desc_init(&d); kc_desc_wstr(&d, KDF_HASH_ALGORITHM, L"SHA256");
    kc_desc_add(&d, KDF_GENERIC_PARAMETER, "fixed", 5); kc_desc_add(&d, KDF_CONTEXT, S108_CTX, S108_CTX_LEN);
    CHECK_NS(U(BCryptKeyDerivation)(k, &d.d, o, 32, &n, 0), NS_INVALID_PARAMETER);
    kc_desc_init(&d); kc_desc_wstr(&d, KDF_HASH_ALGORITHM, L"SHA256");
    kc_desc_add(&d, KDF_GENERIC_PARAMETER, "fixed", 5);
    CHECK_NS(U(BCryptKeyDerivation)(k, &d.d, o, 32, &n, 0), 0);
    /* label and context alone, or neither, are fine */
    kc_desc_init(&d); kc_desc_wstr(&d, KDF_HASH_ALGORITHM, L"SHA256");
    NTSTATUS s = U(BCryptKeyDerivation)(k, &d.d, o, 32, &n, 0);
    t_note("SP800-108 without label/context -> 0x%08lx", (unsigned long)s);
    kc_destroy(k); kc_close(a);
}
TEST(bckdf_sp800108_bad_flags_and_args) {
    NEED_KD();
    BCRYPT_ALG_HANDLE a; BCRYPT_KEY_HANDLE k = kd_key(BCRYPT_SP800108_CTR_HMAC_ALGORITHM, &a, S108_KEY, S108_KEY_LEN);
    if (!k) { t_skip("SP800_108 unavailable"); kc_close(a); return; }
    unsigned char o[32]; ULONG n = 0; kc_desc d; s108_desc(&d, L"SHA256");
    CHECK_NS(U(BCryptKeyDerivation)(k, &d.d, o, 32, &n, 1), NS_INVALID_PARAMETER);
    CHECK_NS(U(BCryptKeyDerivation)(k, &d.d, o, 32, &n, 0x80), NS_INVALID_PARAMETER);
    CHECK_NS(U(BCryptKeyDerivation)(k, NULL, o, 32, &n, 0), NS_INVALID_PARAMETER);
    s108_desc(&d, L"NOSUCHHASH");
    CHECK_NS_FAIL(U(BCryptKeyDerivation)(k, &d.d, o, 32, &n, 0));
    kc_destroy(k); kc_close(a);
}

/* ---- BCryptKeyDerivation: HKDF (RFC 5869 test case 1) ----------------------------------------------------------------------------- */
TEST(bckdf_hkdf_rfc5869_case1) {
    NEED_KD();
    BCRYPT_ALG_HANDLE a = kc_open(L"HKDF", 0);
    if (!a) { t_note("HKDF algorithm not available"); return; }
    BCRYPT_KEY_HANDLE k = NULL;
    NTSTATUS s = U(BCryptGenerateSymmetricKey)(a, &k, NULL, 0, (PUCHAR)HK1_IKM, HK1_IKM_LEN, 0);
    CHECK_NS(s, 0);
    if (!k) { kc_close(a); return; }
    CHECK_NS(U(BCryptSetProperty)(k, BCRYPT_HKDF_HASH_ALGORITHM, (PUCHAR)L"SHA256", 14, 0), 0);
    CHECK_NS(U(BCryptSetProperty)(k, BCRYPT_HKDF_SALT_AND_FINALIZE, (PUCHAR)HK1_SALT, HK1_SALT_LEN, 0), 0);
    unsigned char o[100]; ULONG n = 0; kc_desc d;
    kc_desc_init(&d); kc_desc_add(&d, KDF_HKDF_INFO, HK1_INFO, HK1_INFO_LEN);
    CHECK_NS(U(BCryptKeyDerivation)(k, &d.d, o, 42, &n, 0), 0);
    EXPECT_EQ(n, 42);
    CHECK_MEM(o, HK1_OKM, 42);
    CHECK_NS(U(BCryptKeyDerivation)(k, &d.d, o, 80, &n, 0), 0);
    CHECK_MEM(o, HK1_OKM_80, 80);
    kc_destroy(k); kc_close(a);
}
TEST(bckdf_hkdf_prk_path) {
    NEED_KD();
    BCRYPT_ALG_HANDLE a = kc_open(L"HKDF", 0);
    if (!a) { t_note("HKDF algorithm not available"); return; }
    BCRYPT_KEY_HANDLE k = NULL;
    NTSTATUS s = U(BCryptGenerateSymmetricKey)(a, &k, NULL, 0, (PUCHAR)HK1_PRK, HK1_PRK_LEN, 0);
    CHECK_NS(s, 0);
    if (!k) { kc_close(a); return; }
    CHECK_NS(U(BCryptSetProperty)(k, BCRYPT_HKDF_HASH_ALGORITHM, (PUCHAR)L"SHA256", 14, 0), 0);
    CHECK_NS(U(BCryptSetProperty)(k, BCRYPT_HKDF_PRK_AND_FINALIZE, NULL, 0, 0), 0);
    unsigned char o[42]; ULONG n = 0; kc_desc d;
    kc_desc_init(&d); kc_desc_add(&d, KDF_HKDF_INFO, HK1_INFO, HK1_INFO_LEN);
    CHECK_NS(U(BCryptKeyDerivation)(k, &d.d, o, 42, &n, 0), 0);
    CHECK_MEM(o, HK1_OKM, 42);
    kc_destroy(k); kc_close(a);
}
TEST(bckdf_hkdf_sha512_and_misuse) {
    NEED_KD();
    BCRYPT_ALG_HANDLE a = kc_open(L"HKDF", 0);
    if (!a) { t_note("HKDF algorithm not available"); return; }
    BCRYPT_KEY_HANDLE k = NULL;
    CHECK_NS(U(BCryptGenerateSymmetricKey)(a, &k, NULL, 0, (PUCHAR)HK1_IKM, HK1_IKM_LEN, 0), 0);
    unsigned char o[42]; ULONG n = 0; kc_desc d;
    kc_desc_init(&d); kc_desc_add(&d, KDF_HKDF_INFO, HK1_INFO, HK1_INFO_LEN);
    /* deriving before the hash and salt/PRK have been set (key not finalized) must not succeed */
    NTSTATUS s = U(BCryptKeyDerivation)(k, &d.d, o, 42, &n, 0);
    CHECK(!NT_OK(s)); t_note("HKDF derive on an unfinalized key -> 0x%08lx", (unsigned long)s);
    CHECK_NS(U(BCryptSetProperty)(k, BCRYPT_HKDF_HASH_ALGORITHM, (PUCHAR)L"SHA512", 14, 0), 0);
    CHECK_NS(U(BCryptSetProperty)(k, BCRYPT_HKDF_SALT_AND_FINALIZE, (PUCHAR)HK1_SALT, HK1_SALT_LEN, 0), 0);
    CHECK_NS(U(BCryptKeyDerivation)(k, &d.d, o, 32, &n, 0), 0);
    CHECK_MEM(o, HK1_512_OKM_32, 32);
    kc_destroy(k); kc_close(a);
}

/* ---- BCryptDeriveKeyCapi ---------------------------------------------------------------------------------------------------------------- */
static BCRYPT_HASH_HANDLE capi_hash(BCRYPT_ALG_HANDLE *pa, const WCHAR *alg, int data) {
    *pa = kc_open(alg, 0);
    BCRYPT_HASH_HANDLE h = NULL;
    if (!*pa || !NT_OK(U(BCryptCreateHash)(*pa, &h, NULL, 0, NULL, 0, 0))) return NULL;
    if (data) U(BCryptHashData)(h, (PUCHAR)"capi-password", 13, 0);
    return h;
}
#define NEED_CAPI() do { NEED_CORE(); if (!U(BCryptDeriveKeyCapi) || !U(BCryptCreateHash) || !U(BCryptHashData)) { t_skip("no BCryptDeriveKeyCapi"); return; } } while (0)

TEST(bckdf_capi_short_output_is_hash_prefix) {
    NEED_CAPI();
    BCRYPT_ALG_HANDLE a; BCRYPT_HASH_HANDLE h = capi_hash(&a, L"SHA1", 1);
    unsigned char o[20];
    CHECK_NS(U(BCryptDeriveKeyCapi)(h, NULL, o, 20, 0), 0);
    CHECK_MEM(o, CAPI_SHA1_H, 20);
    U(BCryptDestroyHash)(h); kc_close(a);
    h = capi_hash(&a, L"SHA1", 1);
    memset(o, 0xA5, sizeof(o));
    CHECK_NS(U(BCryptDeriveKeyCapi)(h, NULL, o, 7, 0), 0);
    CHECK_MEM(o, CAPI_SHA1_H, 7);
    EXPECT_EQ(o[7], 0xA5);
    U(BCryptDestroyHash)(h); kc_close(a);
}
TEST(bckdf_capi_extended_output_sha1) {
    NEED_CAPI();
    BCRYPT_ALG_HANDLE a; BCRYPT_HASH_HANDLE h = capi_hash(&a, L"SHA1", 1);
    unsigned char o[40];
    CHECK_NS(U(BCryptDeriveKeyCapi)(h, NULL, o, 40, 0), 0);
    CHECK_MEM(o, CAPI_SHA1_40, 40);
    U(BCryptDestroyHash)(h); kc_close(a);
    h = capi_hash(&a, L"SHA1", 1);
    CHECK_NS(U(BCryptDeriveKeyCapi)(h, NULL, o, 21, 0), 0);          /* any size above the digest uses the extension */
    CHECK_MEM(o, CAPI_SHA1_40, 21);
    U(BCryptDestroyHash)(h); kc_close(a);
}
TEST(bckdf_capi_extended_output_sha256_md5) {
    NEED_CAPI();
    BCRYPT_ALG_HANDLE a; BCRYPT_HASH_HANDLE h = capi_hash(&a, L"SHA256", 1);
    unsigned char o[64];
    CHECK_NS(U(BCryptDeriveKeyCapi)(h, NULL, o, 64, 0), 0);
    CHECK_MEM(o, CAPI_SHA256_64, 64);
    U(BCryptDestroyHash)(h); kc_close(a);
    h = capi_hash(&a, L"MD5", 1);
    CHECK_NS(U(BCryptDeriveKeyCapi)(h, NULL, o, 32, 0), 0);
    CHECK_MEM(o, CAPI_MD5_32, 32);
    U(BCryptDestroyHash)(h); kc_close(a);
}
TEST(bckdf_capi_digest_limits) {
    NEED_CAPI();
    BCRYPT_ALG_HANDLE a; BCRYPT_HASH_HANDLE h = capi_hash(&a, L"SHA1", 1);
    unsigned char o[64];
    CHECK_NS(U(BCryptDeriveKeyCapi)(h, NULL, o, 41, 0), NS_INVALID_PARAMETER);       /* more than twice the digest size */
    CHECK_NS(U(BCryptDeriveKeyCapi)(h, NULL, o, 64, 0), NS_INVALID_PARAMETER);
    CHECK_NS(U(BCryptDeriveKeyCapi)(h, NULL, o, 40, 0), 0);
    U(BCryptDestroyHash)(h); kc_close(a);
}
TEST(bckdf_capi_bad_arguments) {
    NEED_CAPI();
    BCRYPT_ALG_HANDLE a; BCRYPT_HASH_HANDLE h = capi_hash(&a, L"SHA1", 1);
    unsigned char o[20];
    CHECK_NS(U(BCryptDeriveKeyCapi)(h, NULL, NULL, 20, 0), NS_INVALID_PARAMETER);
    CHECK_NS(U(BCryptDeriveKeyCapi)(h, NULL, o, 0, 0), NS_INVALID_PARAMETER);
    CHECK_NS(U(BCryptDeriveKeyCapi)(h, NULL, o, 20, 1), NS_INVALID_PARAMETER);
    CHECK_NS(U(BCryptDeriveKeyCapi)(h, NULL, o, 20, 0x80000000), NS_INVALID_PARAMETER);
    NTSTATUS s = U(BCryptDeriveKeyCapi)(NULL, NULL, o, 20, 0);
    CHECK(!NT_OK(s)); t_note("DeriveKeyCapi with NULL hash -> 0x%08lx", (unsigned long)s);
    U(BCryptDestroyHash)(h); kc_close(a);
}
TEST(bckdf_capi_consumes_hash) {
    NEED_CAPI();
    BCRYPT_ALG_HANDLE a; BCRYPT_HASH_HANDLE h = capi_hash(&a, L"SHA1", 1);
    unsigned char o[20];
    CHECK_NS(U(BCryptDeriveKeyCapi)(h, NULL, o, 20, 0), 0);
    NTSTATUS s = U(BCryptDeriveKeyCapi)(h, NULL, o, 20, 0);          /* the hash was finished by the first call */
    CHECK(!NT_OK(s)); t_note("second DeriveKeyCapi on the same hash -> 0x%08lx", (unsigned long)s);
    s = U(BCryptHashData)(h, (PUCHAR)"x", 1, 0);
    CHECK(!NT_OK(s)); t_note("HashData after DeriveKeyCapi -> 0x%08lx", (unsigned long)s);
    U(BCryptDestroyHash)(h); kc_close(a);
}
TEST(bckdf_capi_aes128_target_quirk) {
    NEED_CAPI();
    /* a 16-byte key for AES from a SHA-1 hash uses the extended derivation instead of the raw digest prefix */
    BCRYPT_ALG_HANDLE a; BCRYPT_HASH_HANDLE h = capi_hash(&a, L"SHA1", 1);
    BCRYPT_ALG_HANDLE aes = kc_open(L"AES", 0);
    unsigned char o[16];
    CHECK_NS(U(BCryptDeriveKeyCapi)(h, aes, o, 16, 0), 0);
    CHECK_MEM(o, CAPI_SHA1_H_AES16_EXT, 16);
    CHECK(memcmp(o, CAPI_SHA1_H, 16) != 0);
    U(BCryptDestroyHash)(h); kc_close(a);
    /* any other target, or other key size, keeps the plain prefix */
    BCRYPT_ALG_HANDLE rc4 = kc_open(L"RC4", 0);
    h = capi_hash(&a, L"SHA1", 1);
    CHECK_NS(U(BCryptDeriveKeyCapi)(h, rc4, o, 16, 0), 0);
    CHECK_MEM(o, CAPI_SHA1_H, 16);
    U(BCryptDestroyHash)(h); kc_close(a);
    h = capi_hash(&a, L"SHA1", 1);
    unsigned char o24[24];
    CHECK_NS(U(BCryptDeriveKeyCapi)(h, aes, o24, 24, 0), 0);
    CHECK_MEM(o24, CAPI_SHA1_H, 20);
    U(BCryptDestroyHash)(h); kc_close(a);
    h = capi_hash(&a, L"SHA256", 1);
    CHECK_NS(U(BCryptDeriveKeyCapi)(h, aes, o, 16, 0), 0);
    CHECK_MEM(o, CAPI_SHA256_H, 16);                                   /* digest >= 32 bytes: no quirk */
    U(BCryptDestroyHash)(h); kc_close(a);
    kc_close(aes); kc_close(rc4);
}
TEST(bckdf_capi_hmac_hash_rejected_or_accepted_note) {
    NEED_CAPI();
    BCRYPT_ALG_HANDLE a = kc_open(L"SHA1", BCRYPT_ALG_HANDLE_HMAC_FLAG);
    BCRYPT_HASH_HANDLE h = NULL;
    unsigned char key[4] = {1,2,3,4}, o[20];
    if (a && NT_OK(U(BCryptCreateHash)(a, &h, NULL, 0, key, 4, 0))) {
        U(BCryptHashData)(h, (PUCHAR)"capi-password", 13, 0);
        NTSTATUS s = U(BCryptDeriveKeyCapi)(h, NULL, o, 20, 0);
        t_note("DeriveKeyCapi on an HMAC hash -> 0x%08lx", (unsigned long)s);
        U(BCryptDestroyHash)(h);
    }
    kc_close(a);
}
