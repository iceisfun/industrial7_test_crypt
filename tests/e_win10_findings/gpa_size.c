/* GetProcAddress failure codes and the size-query protocol, pinned per API. */
#include "ew.h"
#include <winternl.h>

TEST(ew_gpa_error_codes) {
    static const char *mods[] = {"kernel32.dll", "bcrypt.dll", "crypt32.dll", "ncrypt.dll", "wintrust.dll", "advapi32.dll"};
    int i;
    for (i = 0; i < 6; i++) {
        HMODULE h = t_module(mods[i]); DWORD e;
        t_label("%s", mods[i]);
        REQUIRE_NOTNULL(h);
        EXPECT_GPA_FAIL(h, "NoSuchExport_xyz");               /* 127 */
        EXPECT_GPA_FAIL(h, "");                               /* 127 */
        EXPECT_GPA_FAIL(h, MAKEINTRESOURCEA(0));              /* 87  */
        EXPECT_GPA_FAIL(h, MAKEINTRESOURCEA(0xFFFF));         /* 182 */
        EXPECT_GPA_FAIL(h, MAKEINTRESOURCEA(60000));          /* 182 */
        SET_ERR(0); CHECK(GetProcAddress(h, "NoSuchExport_xyz") == NULL); e = GetLastError(); EXPECT_EQ(e, 127);
        SET_ERR(0); CHECK(GetProcAddress(h, MAKEINTRESOURCEA(0)) == NULL); e = GetLastError(); EXPECT_EQ(e, 87);
        SET_ERR(0); CHECK(GetProcAddress(h, MAKEINTRESOURCEA(0xFFFF)) == NULL); e = GetLastError(); EXPECT_EQ(e, 182);
        SET_ERR(0); CHECK(GetProcAddress(h, MAKEINTRESOURCEA(60000)) == NULL); e = GetLastError(); EXPECT_EQ(e, 182);
        SET_ERR(0); CHECK(GetProcAddress((HMODULE)0x1234, "x") == NULL); e = GetLastError(); EXPECT_EQ(e, 126);   /* invalid module handle */
        SET_ERR(0); CHECK(GetProcAddress(h, NULL) == NULL); e = GetLastError(); EXPECT_EQ(e, 87);
    }
    /* NULL module is the exe itself: unknown name is 127 */
    SET_ERR(0); CHECK(GetProcAddress(NULL, "NoSuchExport_xyz") == NULL); EXPECT_ERR(127);
    /* control: a real export resolves */
    CHECK(GetProcAddress(t_module("kernel32.dll"), "GetLastError") != NULL);
    CHECK(GetProcAddress(t_module("bcrypt.dll"), "BCryptOpenAlgorithmProvider") != NULL);
}

TEST(ew_size_query_cryptbinarytostring) {
    /* The NULL-output query counts the terminating NUL; the real call reports the length without it (query == final + 1). */
    static const struct { DWORD fl; DWORD final; } rows[] = { {CRYPT_STRING_BASE64, 30}, {CRYPT_STRING_HEX, 63}, {CRYPT_STRING_HEXRAW, 42}, {CRYPT_STRING_BASE64HEADER, 86} };
    BYTE b[20]; char s[500]; int i; DWORD q, f;
    REQUIRE(C32(CryptBinaryToStringA));
    for (i = 0; i < 20; i++) b[i] = (BYTE)(i + 1);
    for (i = 0; i < 4; i++) {
        t_label("row %d", i);
        q = 0; EXPECT_CAPI_OK(C32(CryptBinaryToStringA)(b, 20, rows[i].fl, NULL, &q));
        f = 500; EXPECT_CAPI_OK(C32(CryptBinaryToStringA)(b, 20, rows[i].fl, s, &f));
        EXPECT_SIZE_QUERY(q, f, rows[i].final);
        EXPECT_EQ(q, f + 1);
        EXPECT_EQ(strlen(s), f);
    }
    f = 3; EXPECT_CAPI_FAIL(C32(CryptBinaryToStringA)(b, 20, CRYPT_STRING_HEXRAW, s, &f), ERROR_MORE_DATA);
    EXPECT_EQ(f, 3);                                                                                     /* observed: the count is left unchanged */
}
TEST(ew_size_query_cryptstringtobinary) {
    BYTE out[100]; DWORD q = 0, f = 100;
    const char *b64 = "AQIDBAUGBwgJCgsMDQ4PEBESExQ=";
    REQUIRE(C32(CryptStringToBinaryA));
    EXPECT_CAPI_OK(C32(CryptStringToBinaryA)(b64, 0, CRYPT_STRING_BASE64, NULL, &q, NULL, NULL));
    EXPECT_CAPI_OK(C32(CryptStringToBinaryA)(b64, 0, CRYPT_STRING_BASE64, out, &f, NULL, NULL));
    EXPECT_SIZE_QUERY_EXACT(q, f, 20);
    f = 5; EXPECT_CAPI_FAIL(C32(CryptStringToBinaryA)(b64, 0, CRYPT_STRING_BASE64, out, &f, NULL, NULL), ERROR_INVALID_DATA);   /* too small is not ERROR_MORE_DATA here */
    EXPECT_EQ(f, 5);
}
TEST(ew_size_query_legacy_capi) {
    HCRYPTPROV p = 0; HCRYPTHASH h = 0; HCRYPTKEY k = 0; BYTE b[64] = {0}, big[64]; DWORD cb;
    REQUIRE(ADV(CryptAcquireContextW));
    REQUIRE_OK(ADV(CryptAcquireContextW)(&p, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT));
    REQUIRE_OK(ADV(CryptCreateHash)(p, CALG_SHA_256, 0, 0, &h));
    cb = 0; EXPECT_CAPI_OK(ADV(CryptGetHashParam)(h, HP_HASHVAL, NULL, &cb, 0)); EXPECT_EQ(cb, 32);
    cb = 4; EXPECT_CAPI_FAIL(ADV(CryptGetHashParam)(h, HP_HASHVAL, b, &cb, 0), ERROR_MORE_DATA); EXPECT_EQ(cb, 32);
    cb = 0; EXPECT_CAPI_OK(ADV(CryptGetProvParam)(p, PP_NAME, NULL, &cb, 0)); EXPECT_EQ(cb, 54);
    { DWORD q = cb; cb = 3; EXPECT_CAPI_FAIL(ADV(CryptGetProvParam)(p, PP_NAME, big, &cb, 0), ERROR_MORE_DATA); EXPECT_EQ(cb, q); }
    cb = sizeof big; EXPECT_CAPI_OK(ADV(CryptGetProvParam)(p, PP_NAME, big, &cb, 0)); EXPECT_EQ(cb, 54);
    REQUIRE_OK(ADV(CryptGenKey)(p, CALG_AES_128, 0, &k));
    /* AES-128 CBC with padding: a final block of 0 bytes needs 16, 16 bytes need 32 */
    cb = 0; EXPECT_CAPI_OK(ADV(CryptEncrypt)(k, 0, TRUE, 0, NULL, &cb, 0)); EXPECT_EQ(cb, 16);
    cb = 16; EXPECT_CAPI_OK(ADV(CryptEncrypt)(k, 0, TRUE, 0, b, &cb, 64)); EXPECT_EQ(cb, 32);
    cb = 16; EXPECT_CAPI_FAIL(ADV(CryptEncrypt)(k, 0, TRUE, 0, b, &cb, 16), ERROR_MORE_DATA); EXPECT_EQ(cb, 32);   /* the padded size is reported back */
    ADV(CryptDestroyKey)(k); ADV(CryptDestroyHash)(h); ADV(CryptReleaseContext)(p, 0);
}
TEST(ew_size_query_bcrypt) {
    BCRYPT_ALG_HANDLE ha = 0, hr = 0; BCRYPT_KEY_HANDLE kk = 0; DWORD q = 0, f = 0, len = 0; BYTE big[2000]; NTSTATUS st;
    REQUIRE(BCR(BCryptOpenAlgorithmProvider));
    REQUIRE_EQ(BCR(BCryptOpenAlgorithmProvider)(&ha, BCRYPT_SHA256_ALGORITHM, NULL, 0), 0);
    q = 0; EXPECT_EQ(BCR(BCryptGetProperty)(ha, BCRYPT_HASH_LENGTH, NULL, 0, &q, 0), 0); EXPECT_EQ(q, 4);
    EXPECT_EQ(BCR(BCryptGetProperty)(ha, BCRYPT_HASH_LENGTH, (PUCHAR)&len, 4, &f, 0), 0); EXPECT_EQ(len, 32);
    EXPECT_SIZE_QUERY_EXACT(q, f, 4);
    q = 0; st = BCR(BCryptGetProperty)(ha, BCRYPT_HASH_LENGTH, (PUCHAR)&len, 2, &q, 0); EXPECT_EQ(st, STATUS_BUFFER_TOO_SMALL_); EXPECT_EQ(q, 4);
    q = 0; EXPECT_EQ(BCR(BCryptGetProperty)(ha, BCRYPT_ALGORITHM_NAME, NULL, 0, &q, 0), 0); EXPECT_EQ(q, 14);   /* L"SHA256" + NUL */
    BCR(BCryptCloseAlgorithmProvider)(ha, 0);
    REQUIRE_EQ(BCR(BCryptOpenAlgorithmProvider)(&hr, BCRYPT_RSA_ALGORITHM, NULL, 0), 0);
    REQUIRE_EQ(BCR(BCryptGenerateKeyPair)(hr, &kk, 1024, 0), 0);
    REQUIRE_EQ(BCR(BCryptFinalizeKeyPair)(kk, 0), 0);
    q = 0; EXPECT_EQ(BCR(BCryptExportKey)(kk, NULL, BCRYPT_RSAPUBLIC_BLOB, NULL, 0, &q, 0), 0);
    f = 0; EXPECT_EQ(BCR(BCryptExportKey)(kk, NULL, BCRYPT_RSAPUBLIC_BLOB, big, sizeof big, &f, 0), 0);
    EXPECT_SIZE_QUERY_EXACT(q, f, 155);                                                              /* 24 byte header + 3 byte exponent + 128 byte modulus */
    q = 0; st = BCR(BCryptExportKey)(kk, NULL, BCRYPT_RSAPUBLIC_BLOB, big, 10, &q, 0); EXPECT_EQ(st, STATUS_BUFFER_TOO_SMALL_); EXPECT_EQ(q, 155);
    q = 0; EXPECT_EQ(BCR(BCryptExportKey)(kk, NULL, BCRYPT_RSAFULLPRIVATE_BLOB, NULL, 0, &q, 0), 0); EXPECT_EQ(q, 603);
    BCR(BCryptDestroyKey)(kk); BCR(BCryptCloseAlgorithmProvider)(hr, 0);
}
