/* Legacy CryptoAPI error mapping: advapi32 validates handles/pointers first (87), the CSP reports NTE_* for valid handles
 * with bad values. Each failing call is paired with the successful call on the same objects. */
#include "ew.h"
#define NTE_BAD_ALGID_ 0x80090008
#define NTE_BAD_FLAGS_ 0x80090009
#define NTE_BAD_TYPE_ 0x8009000a
#define NTE_BAD_DATA_ 0x80090005
#define NTE_BAD_VER_ 0x80090007
#define NTE_NO_KEY_ 0x8009000d

TEST(ew_capi_handle_validation_is_87_not_nte) {
    HCRYPTPROV p = 0, bad = 0; HCRYPTHASH h = 0; BYTE b[16];
    REQUIRE(ADV(CryptAcquireContextW));
    EXPECT_CAPI_FAIL(ADV(CryptAcquireContextW)(NULL, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT), ERROR_INVALID_PARAMETER);
    EXPECT_CAPI_OK(ADV(CryptAcquireContextW)(&p, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT));     /* control */
    REQUIRE_NOTNULL((void *)p);
    EXPECT_CAPI_FAIL(ADV(CryptReleaseContext)(0, 0), ERROR_INVALID_PARAMETER);
    EXPECT_CAPI_FAIL(ADV(CryptReleaseContext)(0x1234, 0), ERROR_INVALID_PARAMETER);
    EXPECT_CAPI_FAIL(ADV(CryptCreateHash)(0, CALG_SHA_256, 0, 0, &h), ERROR_INVALID_PARAMETER);
    EXPECT_CAPI_FAIL(ADV(CryptCreateHash)(p, CALG_SHA_256, 0, 0, NULL), ERROR_INVALID_PARAMETER);
    EXPECT_CAPI_FAIL(ADV(CryptHashData)(0, b, 4, 0), ERROR_INVALID_PARAMETER);
    EXPECT_CAPI_FAIL(ADV(CryptGenRandom)(0, 8, b), ERROR_INVALID_PARAMETER);
    EXPECT_CAPI_FAIL(ADV(CryptGenRandom)(p, 8, NULL), ERROR_INVALID_PARAMETER);
    EXPECT_CAPI_OK(ADV(CryptGenRandom)(p, 8, b));                                                        /* control */
    EXPECT_CAPI_FAIL(ADV(CryptDestroyHash)(0), ERROR_INVALID_PARAMETER);
    EXPECT_CAPI_FAIL(ADV(CryptDestroyKey)(0), ERROR_INVALID_PARAMETER);
    EXPECT_CAPI_FAIL(ADV(CryptDestroyKey)(0x1234), ERROR_INVALID_PARAMETER);
    EXPECT_CAPI_FAIL(ADV(CryptContextAddRef)(0, NULL, 0), ERROR_INVALID_PARAMETER);
    EXPECT_CAPI_FAIL(ADV(CryptContextAddRef)(p, NULL, 1), ERROR_INVALID_PARAMETER);
    EXPECT_CAPI_FAIL(ADV(CryptGetProvParam)(p, PP_NAME, NULL, NULL, 0), ERROR_INVALID_PARAMETER);
    EXPECT_CAPI_FAIL(ADV(CryptGetHashParam)(0, HP_HASHVAL, b, (DWORD[]){16}, 0), ERROR_INVALID_PARAMETER);
    (void)bad;
    ADV(CryptReleaseContext)(p, 0);
}
TEST(ew_capi_valid_handle_bad_value_is_nte) {
    HCRYPTPROV p = 0; HCRYPTHASH h = 0; HCRYPTKEY k = 0; BYTE b[64] = {0}; DWORD cb;
    REQUIRE(ADV(CryptAcquireContextW));
    REQUIRE_OK(ADV(CryptAcquireContextW)(&p, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT));
    EXPECT_CAPI_FAIL(ADV(CryptCreateHash)(p, 0, 0, 0, &h), NTE_BAD_ALGID_);
    EXPECT_CAPI_FAIL(ADV(CryptCreateHash)(p, CALG_SHA_256, 0, 1, &h), NTE_BAD_FLAGS_);
    EXPECT_CAPI_OK(ADV(CryptCreateHash)(p, CALG_SHA_256, 0, 0, &h));                                     /* control */
    REQUIRE_OK(h);
    EXPECT_CAPI_FAIL(ADV(CryptHashData)(h, NULL, 4, 0), NTE_BAD_DATA_);
    EXPECT_CAPI_FAIL(ADV(CryptHashData)(h, b, 4, 0x80), NTE_BAD_FLAGS_);
    EXPECT_CAPI_OK(ADV(CryptHashData)(h, b, 4, 0));                                                      /* control */
    cb = 0;
    EXPECT_CAPI_FAIL(ADV(CryptGetHashParam)(h, 0x99, b, &cb, 0), NTE_BAD_TYPE_);
    EXPECT_CAPI_FAIL(ADV(CryptSetHashParam)(h, 0x99, b, 0), NTE_BAD_TYPE_);
    EXPECT_CAPI_FAIL(ADV(CryptDuplicateHash)(h, NULL, 1, &h), NTE_BAD_FLAGS_);
    EXPECT_CAPI_FAIL(ADV(CryptSignHashW)(h, 77, NULL, 0, NULL, &cb), NTE_BAD_ALGID_);
    EXPECT_CAPI_FAIL(ADV(CryptSignHashW)(h, AT_SIGNATURE, NULL, 0, NULL, &cb), ERR_NTE_BAD_KEYSET);   /* verify-context provider has no key container */
    EXPECT_CAPI_FAIL(ADV(CryptGenKey)(p, 0, 0, &k), NTE_BAD_ALGID_);
    EXPECT_CAPI_FAIL(ADV(CryptGenKey)(p, CALG_AES_128, 0x80000000, &k), NTE_BAD_FLAGS_);
    EXPECT_CAPI_FAIL(ADV(CryptGenKey)(p, CALG_AES_128, 0, NULL), ERROR_INVALID_PARAMETER);            /* NULL out pointer is 87 even with a valid provider */
    EXPECT_CAPI_OK(ADV(CryptGenKey)(p, CALG_AES_128, 0, &k));                                            /* control */
    REQUIRE_OK(k);
    EXPECT_CAPI_FAIL(ADV(CryptGetKeyParam)(k, 0x99, NULL, &cb, 0), NTE_BAD_TYPE_);
    EXPECT_CAPI_FAIL(ADV(CryptSetKeyParam)(k, 0x99, b, 0), NTE_BAD_TYPE_);
    cb = 0; EXPECT_CAPI_FAIL(ADV(CryptExportKey)(k, 0, 99, 0, NULL, &cb), ERR_NTE_BAD_KEY_STATE);
    cb = 15; EXPECT_CAPI_FAIL(ADV(CryptDecrypt)(k, 0, TRUE, 0, b, &cb), NTE_BAD_DATA_);
    EXPECT_CAPI_FAIL(ADV(CryptImportKey)(p, b, 16, 0, 0, &k), NTE_BAD_VER_);
    EXPECT_CAPI_FAIL(ADV(CryptGetUserKey)(p, AT_SIGNATURE, &k), NTE_NO_KEY_);
    EXPECT_CAPI_FAIL(ADV(CryptSetProvParam)(p, 0x99, b, 0), NTE_BAD_TYPE_);
    cb = 16; EXPECT_CAPI_FAIL(ADV(CryptGetProvParam)(p, 0x99, b, &cb, 0), NTE_BAD_TYPE_);
    EXPECT_CAPI_FAIL(ADV(CryptReleaseContext)(p, 1), NTE_BAD_FLAGS_);                                    /* nonzero flags reach the CSP only for a valid handle */
    /* the failed release (flags != 0) already dropped the handle: a second release is invalid */
    EXPECT_CAPI_FAIL(ADV(CryptReleaseContext)(p, 0), ERROR_INVALID_PARAMETER);
}
TEST(ew_capi_provider_lookup_codes) {
    HCRYPTPROV p = 0; DWORD cb = 0;
    REQUIRE(ADV(CryptAcquireContextW));
    EXPECT_CAPI_FAIL(ADV(CryptAcquireContextW)(&p, NULL, L"No Such Provider", PROV_RSA_AES, CRYPT_VERIFYCONTEXT), ERR_NTE_KEYSET_NOT_DEF);
    EXPECT_CAPI_FAIL(ADV(CryptAcquireContextW)(&p, NULL, NULL, 999, CRYPT_VERIFYCONTEXT), ERR_NTE_PROV_TYPE_NOT_DEF);
    EXPECT_CAPI_FAIL(ADV(CryptAcquireContextW)(&p, L"i7tNoSuchContainer", NULL, PROV_RSA_AES, 0), ERR_NTE_BAD_KEYSET);
    EXPECT_CAPI_FAIL(ADV(CryptGetDefaultProviderW)(999, NULL, CRYPT_MACHINE_DEFAULT, NULL, &cb), ERROR_INVALID_PARAMETER);
    EXPECT_CAPI_FAIL(ADV(CryptEnumProvidersW)(9999, NULL, 0, NULL, NULL, &cb), ERROR_NO_MORE_ITEMS);
    { DWORD ty = 0; cb = 0; EXPECT_CAPI_OK(ADV(CryptEnumProvidersW)(0, NULL, 0, &ty, NULL, &cb)); }  /* control: index 0 exists */
    CHECK(cb > 0);
}
