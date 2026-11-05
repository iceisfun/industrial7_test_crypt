/* Extra edge cases for the algorithm provider layer. */
#include "ap.h"

TEST(ap_extra_two_opens_distinct_handles) {
    NEED_CORE();
    BCRYPT_ALG_HANDLE a = NULL, b = NULL;
    NT_OK(AP_OPEN(&a, BCRYPT_SHA256_ALGORITHM, NULL, 0));
    NT_OK(AP_OPEN(&b, BCRYPT_SHA256_ALGORITHM, NULL, 0));
    if (a && b) {
        CHECK(a != b);
        NT_OK(AP_CLOSE(a));
        ULONG v = 0, cb = 0;
        NT_OK(ap_getdw(b, BCRYPT_HASH_LENGTH, &v, &cb));   /* other handle unaffected */
        CHECK(v == 32 && cb == 4);
        NT_OK(AP_CLOSE(b));
    }
}
TEST(ap_extra_mode_change_does_not_leak_between_handles) {
    NEED_CORE();
    BCRYPT_ALG_HANDLE a = NULL, b = NULL;
    NT_OK(AP_OPEN(&a, BCRYPT_AES_ALGORITHM, NULL, 0));
    NT_OK(AP_OPEN(&b, BCRYPT_AES_ALGORITHM, NULL, 0));
    if (a && b) {
        NT_OK(AP_SET(a, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_ECB, sizeof(BCRYPT_CHAIN_MODE_ECB)));
        WCHAR m[40]; ULONG cb;
        NT_OK(ap_getstr(b, BCRYPT_CHAINING_MODE, m, 32, &cb));
        CHECK(wcscmp(m, BCRYPT_CHAIN_MODE_CBC) == 0);      /* default is CBC */
        NT_OK(ap_getstr(a, BCRYPT_CHAINING_MODE, m, 32, &cb));
        CHECK(wcscmp(m, BCRYPT_CHAIN_MODE_ECB) == 0);
    }
    if (a) AP_CLOSE(a);
    if (b) AP_CLOSE(b);
}
TEST(ap_extra_getprop_null_property) {
    NEED_CORE();
    BCRYPT_ALG_HANDLE h = NULL;
    NT_OK(AP_OPEN(&h, BCRYPT_AES_ALGORITHM, NULL, 0));
    if (!h) return;
    ULONG v = 0, cb = 0;
    NT_EQ(U(BCryptGetProperty)(h, NULL, (PUCHAR)&v, 4, &cb, 0), AP_INVALID_PARAM);
    AP_CLOSE(h);
}
TEST(ap_extra_getprop_null_result_pointer) {
    NEED_CORE();
    BCRYPT_ALG_HANDLE h = NULL;
    NT_OK(AP_OPEN(&h, BCRYPT_AES_ALGORITHM, NULL, 0));
    if (!h) return;
    ULONG v = 0;
    NT_EQ(U(BCryptGetProperty)(h, BCRYPT_BLOCK_LENGTH, (PUCHAR)&v, 4, NULL, 0), AP_INVALID_PARAM);
    AP_CLOSE(h);
}
TEST(ap_extra_blocklength_buffer_protocol) {
    NEED_CORE();
    BCRYPT_ALG_HANDLE h = NULL;
    NT_OK(AP_OPEN(&h, BCRYPT_AES_ALGORITHM, NULL, 0));
    if (!h) return;
    ULONG v = 0, cb = 0;
    NT_EQ(U(BCryptGetProperty)(h, BCRYPT_BLOCK_LENGTH, (PUCHAR)&v, 3, &cb, 0), AP_BUF_TOO_SMALL);
    CHECK(cb == 4);
    cb = 0; v = 0;
    NT_OK(U(BCryptGetProperty)(h, BCRYPT_BLOCK_LENGTH, (PUCHAR)&v, 4, &cb, 0));
    CHECK(v == 16 && cb == 4);
    AP_CLOSE(h);
}
TEST(ap_extra_algname_matches_request_all_sha) {
    NEED_CORE();
    static const WCHAR *const n[] = { BCRYPT_SHA1_ALGORITHM, BCRYPT_SHA256_ALGORITHM, BCRYPT_SHA384_ALGORITHM, BCRYPT_SHA512_ALGORITHM, BCRYPT_MD5_ALGORITHM };
    for (unsigned i = 0; i < 5; i++) {
        BCRYPT_ALG_HANDLE h = NULL;
        NT_OK(AP_OPEN(&h, n[i], NULL, 0));
        if (!h) continue;
        WCHAR nm[40]; ULONG cb;
        NT_OK(ap_getstr(h, BCRYPT_ALGORITHM_NAME, nm, 32, &cb));
        CHECK(wcscmp(nm, n[i]) == 0);
        CHECK(cb == (wcslen(n[i]) + 1) * sizeof(WCHAR));
        AP_CLOSE(h);
    }
}
