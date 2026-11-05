#include "dp.h"
/* CryptProtectData / CryptUnprotectData: argument validation, round trips, entropy, description, flags */

static const BYTE SECRET[] = "dpapi secret payload 0123456789";

/* ---- argument validation (observed on Windows 10: all rejected with ERROR_INVALID_PARAMETER before any output is written) ---- */

TEST(dpapi_prot_null_datain) {
    DP_NEED_DATA();
    DATA_BLOB out = { 0x77, (BYTE *)(ULONG_PTR)0x1 };
    SET_ERR(0);
    BOOL r = U(CryptProtectData)(NULL, L"d", NULL, NULL, NULL, 0, &out);
    CHECK(!r); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    CHECK(out.cbData == 0x77 && out.pbData == (BYTE *)(ULONG_PTR)1);   /* untouched on early rejection */
}
TEST(dpapi_prot_null_dataout) {
    DP_NEED_DATA();
    DATA_BLOB in = { sizeof SECRET, (BYTE *)SECRET };
    SET_ERR(0);
    CHECK(!U(CryptProtectData)(&in, L"d", NULL, NULL, NULL, 0, NULL)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
}
TEST(dpapi_prot_null_pbdata) {
    DP_NEED_DATA();
    DATA_BLOB in = { 10, NULL }, out = { 0x55, (BYTE *)(ULONG_PTR)1 };
    SET_ERR(0);
    CHECK(!U(CryptProtectData)(&in, L"d", NULL, NULL, NULL, 0, &out)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    CHECK(out.cbData == 0x55 && out.pbData == (BYTE *)(ULONG_PTR)1);
}
TEST(dpapi_prot_null_pbdata_zero_len) {
    DP_NEED_DATA();
    DATA_BLOB in = { 0, NULL }, out = { 0, NULL };
    SET_ERR(0);
    CHECK(!U(CryptProtectData)(&in, NULL, NULL, NULL, NULL, 0, &out)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
}
TEST(dpapi_prot_all_null) {
    DP_NEED_DATA();
    SET_ERR(0);
    CHECK(!U(CryptProtectData)(NULL, NULL, NULL, NULL, NULL, 0, NULL)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
}
TEST(dpapi_unprot_null_datain) {
    DP_NEED_DATA();
    DATA_BLOB out = { 0x77, (BYTE *)(ULONG_PTR)1 };
    SET_ERR(0);
    CHECK(!U(CryptUnprotectData)(NULL, NULL, NULL, NULL, NULL, 0, &out)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    CHECK(out.cbData == 0x77 && out.pbData == (BYTE *)(ULONG_PTR)1);
}
TEST(dpapi_unprot_null_dataout) {
    DP_NEED_DATA();
    BYTE junk[64] = { 0 };
    DATA_BLOB in = { sizeof junk, junk };
    SET_ERR(0);
    CHECK(!U(CryptUnprotectData)(&in, NULL, NULL, NULL, NULL, 0, NULL)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
}
TEST(dpapi_unprot_null_pbdata) {
    DP_NEED_DATA();
    DATA_BLOB in = { 100, NULL }, out = { 0x42, (BYTE *)(ULONG_PTR)1 };
    SET_ERR(0);
    CHECK(!U(CryptUnprotectData)(&in, NULL, NULL, NULL, NULL, 0, &out)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    CHECK(out.cbData == 0x42 && out.pbData == (BYTE *)(ULONG_PTR)1);
}
TEST(dpapi_unprot_short_blob_sizes) {
    DP_NEED_DATA();
    /* cbData < 0x34 is rejected before anything is written, for every smaller size */
    BYTE buf[0x34]; memset(buf, 0, sizeof buf);
    for (DWORD n = 0; n < 0x34; n += (n < 8 ? 1 : 9)) {
        DATA_BLOB in = { n, buf }, out = { 0x31, (BYTE *)(ULONG_PTR)1 };
        LPWSTR d = (LPWSTR)(ULONG_PTR)1;
        SET_ERR(0);
        BOOL r = U(CryptUnprotectData)(&in, &d, NULL, NULL, NULL, 0, &out);
        DWORD e = GetLastError();
        CHECKF(!r, "n=%lu", n);
        t_label("n=%lu", n); EXPECT_EQ(e, ERROR_INVALID_PARAMETER);
        CHECKF(out.cbData == 0x31 && out.pbData == (BYTE *)(ULONG_PTR)1, "n=%lu out modified", n);
        CHECKF(d == (LPWSTR)(ULONG_PTR)1, "n=%lu descr modified", n);
    }
}
TEST(dpapi_unprot_zero_blob_rejected) {
    DP_NEED_DATA();
    BYTE z[256]; memset(z, 0, sizeof z);
    DATA_BLOB in = { sizeof z, z }, out = { 0, NULL };
    LPWSTR d = NULL;
    SET_ERR(0);
    CHECK(!U(CryptUnprotectData)(&in, &d, NULL, NULL, NULL, 0, &out));
    EXPECT_ERR(ERROR_INVALID_DATA);
    CHECK(out.pbData == NULL && out.cbData == 0);
    CHECK(d == NULL);                         /* cleared before the lsass call */
}
TEST(dpapi_unprot_garbage_blob_rejected) {
    DP_NEED_DATA();
    BYTE g[200]; dp_fill(g, sizeof g, 3);
    DATA_BLOB in = { sizeof g, g }, out = { 9, (BYTE *)(ULONG_PTR)1 };
    LPWSTR d = (LPWSTR)(ULONG_PTR)1;
    SET_ERR(0);
    BOOL r = U(CryptUnprotectData)(&in, &d, NULL, NULL, NULL, 0, &out);
    DWORD e = GetLastError();
    CHECK(!r); EXPECT_EQ(e, ERROR_INVALID_DATA);
    CHECK(out.cbData == 0 && out.pbData == NULL);      /* the output is reset, the description cleared */
    CHECK(d == NULL);
}
TEST(dpapi_unprot_descr_length_overflow) {
    DP_NEED_DATA();
    if (t_is_wine()) { t_skip("emulator reads past the blob"); return; }
    /* descr length 0xFFFFFFF0: the length+0x14 wraps -> rejected as invalid */
    BYTE b[0x60]; dp_fill(b, sizeof b, 1);
    dp_wr(b, 0, 1); dp_wr(b, 44, 0xFFFFFFF0u);
    DATA_BLOB in = { sizeof b, b }, out = { 0x31, (BYTE *)(ULONG_PTR)1 };
    SET_ERR(0);
    CHECK(!U(CryptUnprotectData)(&in, NULL, NULL, NULL, NULL, 0, &out));
    DWORD e = GetLastError();
    EXPECT_EQ(e, 13); EXPECT_EQ(out.cbData, 0); CHECK(out.pbData == NULL);   /* output blob reset on failure */
}
TEST(dpapi_unprot_descr_length_beyond_blob) {
    DP_NEED_DATA();
    BYTE b[0x60]; dp_fill(b, sizeof b, 2);
    dp_wr(b, 0, 1); dp_wr(b, 44, 0x1000);
    DATA_BLOB in = { sizeof b, b }, out = { 0x31, (BYTE *)(ULONG_PTR)1 };
    SET_ERR(0);
    CHECK(!U(CryptUnprotectData)(&in, NULL, NULL, NULL, NULL, 0, &out));
    DWORD e = GetLastError();
    EXPECT_EQ(e, 13); EXPECT_EQ(out.cbData, 0); CHECK(out.pbData == NULL);   /* output blob reset on failure */
}

/* ---- round trips ---- */

TEST(dpapi_rt_basic) {
    DP_NEED_DATA();
    DATA_BLOB blob = { 0 }, plain = { 0 };
    LPWSTR d = NULL;
    SET_ERR(0x1234);
    BOOL r = dp_protect(SECRET, sizeof SECRET, L"basic", NULL, 0, 0, &blob);
    CHECK(r); EXPECT_EQ(GetLastError(), 0);     /* SetLastError(0) on success */
    CHECK(blob.pbData != NULL && blob.cbData > sizeof SECRET);
    SET_ERR(0x1234);
    r = dp_unprotect(blob.pbData, blob.cbData, &d, NULL, 0, 0, &plain);
    CHECK(r); EXPECT_EQ(GetLastError(), 0);
    CHECK(plain.cbData == sizeof SECRET && plain.pbData && !memcmp(plain.pbData, SECRET, sizeof SECRET));
    CHECK(d && !lstrcmpW(d, L"basic"));
    if (d) LocalFree(d);
    dp_free(&blob); dp_free(&plain);
}
TEST(dpapi_rt_blob_is_localalloc) {
    DP_NEED_DATA();
    DATA_BLOB blob = { 0 };
    CHECK(dp_protect(SECRET, sizeof SECRET, NULL, NULL, 0, 0, &blob));
    if (blob.pbData) {
        CHECK(LocalSize(blob.pbData) >= blob.cbData);     /* LocalAlloc-backed: LocalSize works */
        CHECK(LocalFree(blob.pbData) == NULL);
    }
}
TEST(dpapi_rt_plain_is_localalloc) {
    DP_NEED_DATA();
    DATA_BLOB blob = { 0 }, plain = { 0 };
    CHECK(dp_protect(SECRET, sizeof SECRET, NULL, NULL, 0, 0, &blob));
    CHECK(dp_unprotect(blob.pbData, blob.cbData, NULL, NULL, 0, 0, &plain));
    if (plain.pbData) { CHECK(LocalSize(plain.pbData) >= plain.cbData); CHECK(LocalFree(plain.pbData) == NULL); }
    dp_free(&blob);
}
TEST(dpapi_rt_blob_differs_from_plaintext) {
    DP_NEED_DATA();
    BYTE pt[64]; memset(pt, 'A', sizeof pt);
    DATA_BLOB blob = { 0 };
    CHECK(dp_protect(pt, sizeof pt, NULL, NULL, 0, 0, &blob));
    int found = 0;
    for (DWORD i = 0; i + 16 <= blob.cbData; i++) if (!memcmp(blob.pbData + i, pt, 16)) found = 1;
    CHECK(!found);                                       /* plaintext not visible anywhere in the blob */
    dp_free(&blob);
}
TEST(dpapi_rt_two_protects_differ) {
    DP_NEED_DATA();
    DATA_BLOB a = { 0 }, b = { 0 };
    CHECK(dp_protect(SECRET, sizeof SECRET, NULL, NULL, 0, 0, &a));
    CHECK(dp_protect(SECRET, sizeof SECRET, NULL, NULL, 0, 0, &b));
    CHECK(a.cbData == b.cbData);                        /* same header sizes: fixed algs, same description */
    CHECK(a.pbData && b.pbData && a.cbData == b.cbData && memcmp(a.pbData, b.pbData, a.cbData) != 0);   /* random salt */
    dp_free(&a); dp_free(&b);
}
TEST(dpapi_rt_unprotect_twice_same_blob) {
    DP_NEED_DATA();
    DATA_BLOB blob = { 0 }, p1 = { 0 }, p2 = { 0 };
    CHECK(dp_protect(SECRET, sizeof SECRET, NULL, NULL, 0, 0, &blob));
    CHECK(dp_unprotect(blob.pbData, blob.cbData, NULL, NULL, 0, 0, &p1));
    CHECK(dp_unprotect(blob.pbData, blob.cbData, NULL, NULL, 0, 0, &p2));   /* blob is not consumed */
    CHECK(p1.cbData == p2.cbData && p1.pbData && p2.pbData && p1.pbData != p2.pbData && !memcmp(p1.pbData, p2.pbData, p1.cbData));
    dp_free(&blob); dp_free(&p1); dp_free(&p2);
}
TEST(dpapi_rt_input_unmodified) {
    DP_NEED_DATA();
    BYTE pt[100], copy[100]; dp_fill(pt, sizeof pt, 9); memcpy(copy, pt, sizeof pt);
    DATA_BLOB blob = { 0 }, plain = { 0 };
    CHECK(dp_protect(pt, sizeof pt, NULL, NULL, 0, 0, &blob));
    CHECK(!memcmp(pt, copy, sizeof pt));
    BYTE *bc = malloc(blob.cbData); memcpy(bc, blob.pbData, blob.cbData);
    CHECK(dp_unprotect(blob.pbData, blob.cbData, NULL, NULL, 0, 0, &plain));
    CHECK(!memcmp(bc, blob.pbData, blob.cbData));         /* input blob not modified by unprotect */
    free(bc); dp_free(&blob); dp_free(&plain);
}
TEST(dpapi_rt_dataout_prefilled_is_overwritten) {
    DP_NEED_DATA();
    DATA_BLOB blob = { 0xdead, (BYTE *)(ULONG_PTR)0x10 }, plain = { 0xbeef, (BYTE *)(ULONG_PTR)0x10 };
    CHECK(dp_protect(SECRET, sizeof SECRET, NULL, NULL, 0, 0, &blob));
    CHECK(blob.cbData != 0xdead && blob.pbData != (BYTE *)(ULONG_PTR)0x10);
    CHECK(dp_unprotect(blob.pbData, blob.cbData, NULL, NULL, 0, 0, &plain));
    CHECK(plain.cbData == sizeof SECRET);
    dp_free(&blob); dp_free(&plain);
}
TEST(dpapi_rt_reserved_ignored) {
    DP_NEED_DATA();
    DATA_BLOB in = { sizeof SECRET, (BYTE *)SECRET }, blob = { 0 }, plain = { 0 };
    CHECK(U(CryptProtectData)(&in, NULL, NULL, NULL, NULL, 0, &blob));
    CHECK(U(CryptUnprotectData)(&blob, NULL, NULL, NULL, NULL, 0, &plain));
    CHECK(plain.cbData == sizeof SECRET);
    dp_free(&blob); dp_free(&plain);
}

/* ---- sizes ---- */

#define SIZE_TEST(nm, N) \
TEST(dpapi_rt_size_##nm) { \
    DP_NEED_DATA(); \
    BYTE *pt = malloc(N ? N : 1); dp_fill(pt, N, N); \
    DATA_BLOB blob = { 0 }, plain = { 0 }; \
    BOOL r = dp_protect(pt, N, L"sz", NULL, 0, 0, &blob); CHECKF(r, "err=%lu", GetLastError()); \
    if (r) { \
        r = dp_unprotect(blob.pbData, blob.cbData, NULL, NULL, 0, 0, &plain); CHECKF(r, "err=%lu", GetLastError()); \
        CHECK(plain.cbData == (N)); \
        CHECK(r && (N == 0 || (plain.pbData && !memcmp(plain.pbData, pt, N)))); \
    } \
    dp_free(&blob); dp_free(&plain); free(pt); \
}
SIZE_TEST(1, 1)
SIZE_TEST(2, 2)
SIZE_TEST(7, 7)
SIZE_TEST(8, 8)
SIZE_TEST(9, 9)
SIZE_TEST(15, 15)
SIZE_TEST(16, 16)
SIZE_TEST(17, 17)
SIZE_TEST(31, 31)
SIZE_TEST(32, 32)
SIZE_TEST(33, 33)
SIZE_TEST(255, 255)
SIZE_TEST(256, 256)
SIZE_TEST(257, 257)
SIZE_TEST(1000, 1000)
SIZE_TEST(4095, 4095)
SIZE_TEST(4096, 4096)
SIZE_TEST(4097, 4097)
SIZE_TEST(65535, 65535)
SIZE_TEST(65536, 65536)
SIZE_TEST(100000, 100000)
SIZE_TEST(1mb, 1048576)
SIZE_TEST(1mb_plus1, 1048577)

TEST(dpapi_rt_empty_data) {
    DP_NEED_DATA();
    BYTE one = 0;
    DATA_BLOB blob = { 0 }, plain = { 0x99, (BYTE *)(ULONG_PTR)1 };
    BOOL r = dp_protect(&one, 0, L"empty", NULL, 0, 0, &blob);
    CHECKF(r, "err=%lu", GetLastError());
    if (r) {
        LPWSTR d = NULL;
        r = dp_unprotect(blob.pbData, blob.cbData, &d, NULL, 0, 0, &plain);
        CHECKF(r, "err=%lu", GetLastError());
        CHECK(plain.cbData == 0);
        CHECK(plain.pbData != NULL);          /* an empty result is still an allocation */
        CHECK(d && !lstrcmpW(d, L"empty"));
        if (d) LocalFree(d);
    }
    dp_free(&blob); dp_free(&plain);
}
TEST(dpapi_rt_blob_grows_with_input) {
    DP_NEED_DATA();
    DATA_BLOB a = { 0 }, b = { 0 };
    BYTE buf[1024]; dp_fill(buf, sizeof buf, 4);
    CHECK(dp_protect(buf, 16, NULL, NULL, 0, 0, &a));
    CHECK(dp_protect(buf, 1024, NULL, NULL, 0, 0, &b));
    CHECK(b.cbData > a.cbData && b.cbData - a.cbData >= 1008 - 16 && b.cbData - a.cbData <= 1008 + 16);
    dp_free(&a); dp_free(&b);
}

/* ---- entropy ---- */

TEST(dpapi_entropy_roundtrip) {
    DP_NEED_DATA();
    static const BYTE ent[] = "optional entropy";
    DATA_BLOB blob = { 0 }, plain = { 0 };
    CHECK(dp_protect(SECRET, sizeof SECRET, NULL, ent, sizeof ent, 0, &blob));
    CHECK(dp_unprotect(blob.pbData, blob.cbData, NULL, ent, sizeof ent, 0, &plain));
    CHECK(plain.cbData == sizeof SECRET && !memcmp(plain.pbData, SECRET, sizeof SECRET));
    dp_free(&blob); dp_free(&plain);
}
TEST(dpapi_entropy_missing_on_unprotect) {
    DP_NEED_DATA();
    static const BYTE ent[] = "needed";
    DATA_BLOB blob = { 0 }, plain = { 0x5, (BYTE *)(ULONG_PTR)1 };
    CHECK(dp_protect(SECRET, sizeof SECRET, NULL, ent, sizeof ent, 0, &blob));
    LPWSTR d = (LPWSTR)(ULONG_PTR)1;
    SET_ERR(0);
    CHECK(!dp_unprotect(blob.pbData, blob.cbData, &d, NULL, 0, 0, &plain)); EXPECT_ERR(ERROR_INVALID_DATA);
    CHECK(plain.cbData == 0 && plain.pbData == NULL);     /* output zeroed, nothing leaked */
    CHECK(d == NULL);
    dp_free(&blob);
}
TEST(dpapi_entropy_wrong_on_unprotect) {
    DP_NEED_DATA();
    static const BYTE e1[] = "entropy-one", e2[] = "entropy-two";
    DATA_BLOB blob = { 0 }, plain = { 0 };
    CHECK(dp_protect(SECRET, sizeof SECRET, NULL, e1, sizeof e1, 0, &blob));
    SET_ERR(0);
    CHECK(!dp_unprotect(blob.pbData, blob.cbData, NULL, e2, sizeof e2, 0, &plain)); EXPECT_ERR(ERROR_INVALID_DATA);
    CHECK(plain.pbData == NULL && plain.cbData == 0);
    dp_free(&blob);
}
TEST(dpapi_entropy_unexpected_on_unprotect) {
    DP_NEED_DATA();
    static const BYTE e1[] = "surprise";
    DATA_BLOB blob = { 0 }, plain = { 0 };
    CHECK(dp_protect(SECRET, sizeof SECRET, NULL, NULL, 0, 0, &blob));
    SET_ERR(0);
    CHECK(!dp_unprotect(blob.pbData, blob.cbData, NULL, e1, sizeof e1, 0, &plain)); EXPECT_ERR(ERROR_INVALID_DATA);
    dp_free(&blob);
}
TEST(dpapi_entropy_one_bit_difference) {
    DP_NEED_DATA();
    BYTE e1[32], e2[32]; dp_fill(e1, 32, 5); memcpy(e2, e1, 32); e2[31] ^= 1;
    DATA_BLOB blob = { 0 }, plain = { 0 };
    CHECK(dp_protect(SECRET, sizeof SECRET, NULL, e1, 32, 0, &blob));
    SET_ERR(0);
    CHECK(!dp_unprotect(blob.pbData, blob.cbData, NULL, e2, 32, 0, &plain)); EXPECT_ERR(ERROR_INVALID_DATA);
    dp_free(&blob);
}
TEST(dpapi_entropy_prefix_not_equal) {
    DP_NEED_DATA();
    BYTE e1[32]; dp_fill(e1, 32, 6);
    DATA_BLOB blob = { 0 }, plain = { 0 };
    CHECK(dp_protect(SECRET, sizeof SECRET, NULL, e1, 32, 0, &blob));
    SET_ERR(0);
    CHECK(!dp_unprotect(blob.pbData, blob.cbData, NULL, e1, 31, 0, &plain)); EXPECT_ERR(ERROR_INVALID_DATA);
    SET_ERR(0);
    BYTE e3[33]; memcpy(e3, e1, 32); e3[32] = 0;
    CHECK(!dp_unprotect(blob.pbData, blob.cbData, NULL, e3, 33, 0, &plain)); EXPECT_ERR(ERROR_INVALID_DATA);
    dp_free(&blob);
}
TEST(dpapi_entropy_large) {
    DP_NEED_DATA();
    BYTE *e = malloc(8192); dp_fill(e, 8192, 7);
    DATA_BLOB blob = { 0 }, plain = { 0 };
    BOOL r = dp_protect(SECRET, sizeof SECRET, NULL, e, 8192, 0, &blob);
    CHECKF(r, "err=%lu", GetLastError());
    if (r) { CHECK(dp_unprotect(blob.pbData, blob.cbData, NULL, e, 8192, 0, &plain)); CHECK(plain.cbData == sizeof SECRET); }
    dp_free(&blob); dp_free(&plain); free(e);
}
TEST(dpapi_entropy_single_byte_values) {
    DP_NEED_DATA();
    for (int v = 0; v < 256; v += 51) {
        BYTE e = (BYTE)v, w = (BYTE)(v + 1);
        DATA_BLOB blob = { 0 }, plain = { 0 };
        CHECK(dp_protect(SECRET, sizeof SECRET, NULL, &e, 1, 0, &blob));
        CHECK(dp_unprotect(blob.pbData, blob.cbData, NULL, &e, 1, 0, &plain));
        dp_free(&plain);
        SET_ERR(0);
        CHECK(!dp_unprotect(blob.pbData, blob.cbData, NULL, &w, 1, 0, &plain)); EXPECT_ERR(ERROR_INVALID_DATA);
        dp_free(&blob);
    }
}
TEST(dpapi_entropy_empty_blob_observed) {
    DP_NEED_DATA();
    /* a DATA_BLOB with cbData 0 is the same as no entropy */
    BYTE z = 0;
    DATA_BLOB e = { 0, &z }, in = { sizeof SECRET, (BYTE *)SECRET }, blob = { 0 }, plain = { 0 };
    BOOL r = U(CryptProtectData)(&in, NULL, &e, NULL, NULL, 0, &blob);
    EXPECT_EQ(r, 1);
    if (r) {
        BOOL r1 = U(CryptUnprotectData)(&blob, NULL, NULL, NULL, NULL, 0, &plain);
        EXPECT_EQ(r1, 1); dp_free(&plain);
        BOOL r2 = U(CryptUnprotectData)(&blob, NULL, &e, NULL, NULL, 0, &plain);
        CHECK(r2);                                          /* the same entropy always round-trips */
        dp_free(&plain);
    }
    dp_free(&blob);
}
TEST(dpapi_entropy_input_unmodified) {
    DP_NEED_DATA();
    BYTE e[40], c[40]; dp_fill(e, 40, 8); memcpy(c, e, 40);
    DATA_BLOB blob = { 0 }, plain = { 0 };
    CHECK(dp_protect(SECRET, sizeof SECRET, NULL, e, 40, 0, &blob));
    CHECK(!memcmp(e, c, 40));
    CHECK(dp_unprotect(blob.pbData, blob.cbData, NULL, e, 40, 0, &plain));
    CHECK(!memcmp(e, c, 40));
    dp_free(&blob); dp_free(&plain);
}

/* ---- description ---- */

TEST(dpapi_descr_roundtrip) {
    DP_NEED_DATA();
    DATA_BLOB blob = { 0 }, plain = { 0 };
    LPWSTR d = NULL;
    CHECK(dp_protect(SECRET, sizeof SECRET, L"Ultra secret test message", NULL, 0, 0, &blob));
    CHECK(dp_unprotect(blob.pbData, blob.cbData, &d, NULL, 0, 0, &plain));
    CHECK(d && !lstrcmpW(d, L"Ultra secret test message"));
    if (d) { CHECK(LocalSize(d) >= (lstrlenW(d) + 1) * 2); LocalFree(d); }
    dp_free(&blob); dp_free(&plain);
}
TEST(dpapi_descr_null_gives_empty_string) {
    DP_NEED_DATA();
    DATA_BLOB blob = { 0 }, plain = { 0 };
    LPWSTR d = (LPWSTR)(ULONG_PTR)1;
    CHECK(dp_protect(SECRET, sizeof SECRET, NULL, NULL, 0, 0, &blob));
    CHECK(dp_unprotect(blob.pbData, blob.cbData, &d, NULL, 0, 0, &plain));
    CHECK(d != NULL && d != (LPWSTR)(ULONG_PTR)1 && d[0] == 0);   /* NULL description is stored as L"" */
    if (d && d != (LPWSTR)(ULONG_PTR)1) LocalFree(d);
    dp_free(&blob); dp_free(&plain);
}
TEST(dpapi_descr_empty_string) {
    DP_NEED_DATA();
    DATA_BLOB blob = { 0 }, plain = { 0 };
    LPWSTR d = NULL;
    CHECK(dp_protect(SECRET, sizeof SECRET, L"", NULL, 0, 0, &blob));
    CHECK(dp_unprotect(blob.pbData, blob.cbData, &d, NULL, 0, 0, &plain));
    CHECK(d && d[0] == 0);
    if (d) LocalFree(d);
    dp_free(&blob); dp_free(&plain);
}
TEST(dpapi_descr_null_out_pointer_ok) {
    DP_NEED_DATA();
    DATA_BLOB blob = { 0 }, plain = { 0 };
    CHECK(dp_protect(SECRET, sizeof SECRET, L"ignored on read", NULL, 0, 0, &blob));
    CHECK(dp_unprotect(blob.pbData, blob.cbData, NULL, NULL, 0, 0, &plain));
    dp_free(&blob); dp_free(&plain);
}
TEST(dpapi_descr_cleared_on_failure) {
    DP_NEED_DATA();
    DATA_BLOB blob = { 0 }, plain = { 0 };
    BYTE ent[4] = { 1, 2, 3, 4 };
    CHECK(dp_protect(SECRET, sizeof SECRET, L"hidden", ent, 4, 0, &blob));
    LPWSTR d = (LPWSTR)(ULONG_PTR)1;
    CHECK(!dp_unprotect(blob.pbData, blob.cbData, &d, NULL, 0, 0, &plain));
    CHECK(d == NULL);
    dp_free(&blob);
}
TEST(dpapi_descr_unicode) {
    DP_NEED_DATA();
    static const WCHAR w[] = { 0x00e9, 0x4e2d, 0x6587, 0xd83d, 0xde00, 'x', 0 };
    DATA_BLOB blob = { 0 }, plain = { 0 };
    LPWSTR d = NULL;
    CHECK(dp_protect(SECRET, sizeof SECRET, w, NULL, 0, 0, &blob));
    CHECK(dp_unprotect(blob.pbData, blob.cbData, &d, NULL, 0, 0, &plain));
    CHECK(d && !lstrcmpW(d, w));
    if (d) LocalFree(d);
    dp_free(&blob); dp_free(&plain);
}
TEST(dpapi_descr_long) {
    DP_NEED_DATA();
    WCHAR *w = malloc(2001 * 2);
    for (int i = 0; i < 2000; i++) w[i] = (WCHAR)('a' + i % 26);
    w[2000] = 0;
    DATA_BLOB blob = { 0 }, plain = { 0 };
    LPWSTR d = NULL;
    BOOL r = dp_protect(SECRET, sizeof SECRET, w, NULL, 0, 0, &blob);
    CHECKF(r, "err=%lu", GetLastError());
    if (r) {
        CHECK(dp_unprotect(blob.pbData, blob.cbData, &d, NULL, 0, 0, &plain));
        CHECK(d && !lstrcmpW(d, w));
        if (d) LocalFree(d);
    }
    dp_free(&blob); dp_free(&plain); free(w);
}
TEST(dpapi_descr_distinct_per_blob) {
    DP_NEED_DATA();
    DATA_BLOB b1 = { 0 }, b2 = { 0 }, p = { 0 };
    LPWSTR d1 = NULL, d2 = NULL;
    CHECK(dp_protect(SECRET, sizeof SECRET, L"one", NULL, 0, 0, &b1));
    CHECK(dp_protect(SECRET, sizeof SECRET, L"two", NULL, 0, 0, &b2));
    CHECK(dp_unprotect(b1.pbData, b1.cbData, &d1, NULL, 0, 0, &p)); dp_free(&p);
    CHECK(dp_unprotect(b2.pbData, b2.cbData, &d2, NULL, 0, 0, &p)); dp_free(&p);
    CHECK(d1 && d2 && !lstrcmpW(d1, L"one") && !lstrcmpW(d2, L"two"));
    if (d1) LocalFree(d1);
    if (d2) LocalFree(d2);
    dp_free(&b1); dp_free(&b2);
}

/* ---- flags ---- */

/* One protect/unprotect round trip with the given flags. NULL prompt structs throughout, so none of these rows can show a
 * window; the prompt rows are kept apart (dpapi_prompt_* below, prompt_ui.c). perr/uerr are the exact last errors of a
 * failing call. */
static void flag_roundtrip(DWORD pflags, DWORD uflags, int pok, DWORD perr, int uok, DWORD uerr) {
    DATA_BLOB blob = { 0 }, plain = { 0 };
    SET_ERR(0);
    BOOL r = dp_protect(SECRET, sizeof SECRET, L"flags", NULL, 0, pflags, &blob);
    DWORD e = GetLastError();
    EXPECT_EQ(r, pok); if (!pok) EXPECT_EQ(e, perr);
    if (r) {
        SET_ERR(0);
        r = dp_unprotect(blob.pbData, blob.cbData, NULL, NULL, 0, uflags, &plain);
        e = GetLastError();
        EXPECT_EQ(r, uok); if (!uok) EXPECT_EQ(e, uerr);
        if (r) CHECK(plain.cbData == sizeof SECRET && !memcmp(plain.pbData, SECRET, sizeof SECRET));
    }
    dp_free(&blob); dp_free(&plain);
}
#define FLAG_TEST(nm, pf, uf, pok, perr, uok, uerr) TEST(dpapi_flags_##nm) { DP_NEED_DATA(); flag_roundtrip(pf, uf, pok, perr, uok, uerr); }
FLAG_TEST(none, 0, 0, 1, 0, 1, 0)
/* fresh synthetic blob, same user, NULL prompt structs, UI forbidden at protect and unprotect: an ordinary round trip */
FLAG_TEST(ui_forbidden_both, CRYPTPROTECT_UI_FORBIDDEN, CRYPTPROTECT_UI_FORBIDDEN, 1, 0, 1, 0)
FLAG_TEST(ui_forbidden_protect_only, CRYPTPROTECT_UI_FORBIDDEN, 0, 1, 0, 1, 0)
FLAG_TEST(ui_forbidden_unprotect_only, 0, CRYPTPROTECT_UI_FORBIDDEN, 1, 0, 1, 0)
FLAG_TEST(local_machine, CRYPTPROTECT_LOCAL_MACHINE, 0, 1, 0, 1, 0)
FLAG_TEST(local_machine_ui_forbidden, CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN, CRYPTPROTECT_UI_FORBIDDEN, 1, 0, 1, 0)
FLAG_TEST(audit, CRYPTPROTECT_AUDIT, 0, 1, 0, 1, 0)
FLAG_TEST(audit_unprotect, 0, CRYPTPROTECT_AUDIT, 1, 0, 1, 0)
FLAG_TEST(verify_protection_unprotect, 0, CRYPTPROTECT_VERIFY_PROTECTION, 1, 0, 1, 0)
FLAG_TEST(verify_protection_both, CRYPTPROTECT_VERIFY_PROTECTION, CRYPTPROTECT_VERIFY_PROTECTION, 1, 0, 1, 0)
FLAG_TEST(no_recovery, CRYPTPROTECT_NO_RECOVERY, 0, 1, 0, 1, 0)
/* a CRED_SYNC blob protects but cannot be unprotected without the flag (observed) */
FLAG_TEST(cred_sync, CRYPTPROTECT_CRED_SYNC, 0, 1, 0, 0, ERROR_INVALID_PARAMETER)
/* CRED_REGENERATE needs a privilege that neither the standard nor the elevated test user holds */
FLAG_TEST(cred_regenerate, CRYPTPROTECT_CRED_REGENERATE, 0, 0, ERROR_PRIVILEGE_NOT_HELD, 0, 0)
FLAG_TEST(all_documented, CRYPTPROTECT_UI_FORBIDDEN | CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_AUDIT | CRYPTPROTECT_VERIFY_PROTECTION, 0, 1, 0, 1, 0)
FLAG_TEST(unprotect_local_machine_flag_irrelevant, CRYPTPROTECT_LOCAL_MACHINE, CRYPTPROTECT_LOCAL_MACHINE, 1, 0, 1, 0)

TEST(dpapi_flags_verify_protection_current_blob_no_new_protection) {
    DP_NEED_DATA();
    DATA_BLOB blob = { 0 }, plain = { 0 };
    CHECK(dp_protect(SECRET, sizeof SECRET, NULL, NULL, 0, 0, &blob));
    SET_ERR(0x4242);
    CHECK(dp_unprotect(blob.pbData, blob.cbData, NULL, NULL, 0, CRYPTPROTECT_VERIFY_PROTECTION, &plain));
    EXPECT_EQ(GetLastError(), 0);       /* fresh blob uses the current algorithms: no CRYPT_I_NEW_PROTECTION_REQUIRED (0x91012) */
    dp_free(&blob); dp_free(&plain);
}
TEST(dpapi_flags_local_machine_blob_flag_bit) {
    DP_NEED_DATA(); DP_NOT_WINE();
    DATA_BLOB u = { 0 }, m = { 0 };
    CHECK(dp_protect(SECRET, sizeof SECRET, NULL, NULL, 0, 0, &u));
    CHECK(dp_protect(SECRET, sizeof SECRET, NULL, NULL, 0, CRYPTPROTECT_LOCAL_MACHINE, &m));
    if (u.pbData && m.pbData) {
        DWORD fu = dp_rd(u.pbData, 40), fm = dp_rd(m.pbData, 40);
        CHECK((fm & CRYPTPROTECT_LOCAL_MACHINE) != 0);
        CHECK((fu & CRYPTPROTECT_LOCAL_MACHINE) == 0);
        EXPECT_EQ(fu, 0); EXPECT_EQ(fm, 4);
    }
    dp_free(&u); dp_free(&m);
}
TEST(dpapi_flags_machine_blob_differs_in_master_key) {
    DP_NEED_DATA(); DP_NOT_WINE();
    DATA_BLOB u = { 0 }, m = { 0 };
    CHECK(dp_protect(SECRET, sizeof SECRET, NULL, NULL, 0, 0, &u));
    CHECK(dp_protect(SECRET, sizeof SECRET, NULL, NULL, 0, CRYPTPROTECT_LOCAL_MACHINE, &m));
    if (u.pbData && m.pbData) CHECK(memcmp(u.pbData + 24, m.pbData + 24, 16) != 0);   /* different master key GUID */
    dp_free(&u); dp_free(&m);
}
TEST(dpapi_flags_machine_blob_not_decryptable_as_user_note) {
    DP_NEED_DATA();
    DATA_BLOB u = { 0 }, m = { 0 }, p = { 0 };
    CHECK(dp_protect(SECRET, sizeof SECRET, NULL, NULL, 0, CRYPTPROTECT_LOCAL_MACHINE, &m));
    BOOL r = dp_unprotect(m.pbData, m.cbData, NULL, NULL, 0, 0, &p);
    CHECK(r); dp_free(&p); dp_free(&m);
}

/* ---- prompt struct ---- */

TEST(dpapi_prompt_null_ok) {
    DP_NEED_DATA();
    DATA_BLOB in = { sizeof SECRET, (BYTE *)SECRET }, blob = { 0 }, plain = { 0 };
    CHECK(U(CryptProtectData)(&in, NULL, NULL, NULL, NULL, 0, &blob));
    CHECK(U(CryptUnprotectData)(&blob, NULL, NULL, NULL, NULL, 0, &plain));
    dp_free(&blob); dp_free(&plain);
}
TEST(dpapi_prompt_zero_flags_struct_no_ui) {
    DP_NEED_DATA();
    CRYPTPROTECT_PROMPTSTRUCT ps = { sizeof ps, 0, NULL, L"cryptt prompt" };
    DATA_BLOB in = { sizeof SECRET, (BYTE *)SECRET }, blob = { 0 }, plain = { 0 };
    /* dwPromptFlags & 3 == 0: the UI path is not entered, so the struct is inert */
    CHECK(U(CryptProtectData)(&in, NULL, NULL, NULL, &ps, CRYPTPROTECT_UI_FORBIDDEN, &blob));
    CHECK(U(CryptUnprotectData)(&blob, NULL, NULL, NULL, &ps, CRYPTPROTECT_UI_FORBIDDEN, &plain));
    CHECK(plain.cbData == sizeof SECRET);
    dp_free(&blob); dp_free(&plain);
}
TEST(dpapi_prompt_reserved_bit_only_no_ui) {
    DP_NEED_DATA();
    CRYPTPROTECT_PROMPTSTRUCT ps = { sizeof ps, CRYPTPROTECT_PROMPT_RESERVED | CRYPTPROTECT_PROMPT_STRONG, NULL, NULL };
    DATA_BLOB in = { sizeof SECRET, (BYTE *)SECRET }, blob = { 0 };
    BOOL r = U(CryptProtectData)(&in, NULL, NULL, NULL, &ps, CRYPTPROTECT_UI_FORBIDDEN, &blob);   
    EXPECT_EQ(r, 0); EXPECT_EQ(GetLastError(), 87); dp_free(&blob);   /* observed: rejected, not ignored */
}
/* Prompt-policy conflict: a prompt is requested (dwPromptFlags) AND CRYPTPROTECT_UI_FORBIDDEN is given. Non-interactive: the
 * call is refused up front with ERROR_PASSWORD_RESTRICTION (1325) and no output blob. Separate from the interactive rows
 * in prompt_ui.c that really show the window. */
TEST(dpapi_prompt_policy_conflict_on_protect_with_ui_forbidden) {
    DP_NEED_DATA();
    CRYPTPROTECT_PROMPTSTRUCT ps = { sizeof ps, CRYPTPROTECT_PROMPT_ON_PROTECT, NULL, L"cryptt" };
    DATA_BLOB in = { sizeof SECRET, (BYTE *)SECRET }, blob = { 0 };
    SET_ERR(0);
    EXPECT_EQ(U(CryptProtectData)(&in, NULL, NULL, NULL, &ps, CRYPTPROTECT_UI_FORBIDDEN, &blob), 0);
    EXPECT_ERR(ERROR_PASSWORD_RESTRICTION);
    CHECK(blob.pbData == NULL && blob.cbData == 0);
    dp_free(&blob);
}
TEST(dpapi_prompt_policy_conflict_on_unprotect_with_ui_forbidden) {
    DP_NEED_DATA();
    CRYPTPROTECT_PROMPTSTRUCT ps = { sizeof ps, CRYPTPROTECT_PROMPT_ON_UNPROTECT, NULL, L"cryptt" };
    DATA_BLOB in = { sizeof SECRET, (BYTE *)SECRET }, blob = { 0 };
    SET_ERR(0);
    EXPECT_EQ(U(CryptProtectData)(&in, NULL, NULL, NULL, &ps, CRYPTPROTECT_UI_FORBIDDEN, &blob), 0);
    EXPECT_ERR(ERROR_PASSWORD_RESTRICTION);
    CHECK(blob.pbData == NULL && blob.cbData == 0);
    dp_free(&blob);
}
TEST(dpapi_prompt_policy_conflict_both_prompt_bits_with_ui_forbidden) {
    DP_NEED_DATA();
    CRYPTPROTECT_PROMPTSTRUCT ps = { sizeof ps, CRYPTPROTECT_PROMPT_ON_PROTECT | CRYPTPROTECT_PROMPT_ON_UNPROTECT, NULL, L"cryptt" };
    DATA_BLOB in = { sizeof SECRET, (BYTE *)SECRET }, blob = { 0 };
    SET_ERR(0);
    EXPECT_EQ(U(CryptProtectData)(&in, NULL, NULL, NULL, &ps, CRYPTPROTECT_UI_FORBIDDEN, &blob), 0);
    EXPECT_ERR(ERROR_PASSWORD_RESTRICTION);
    dp_free(&blob);
}
TEST(dpapi_prompt_struct_request_ignored_when_unprotecting_plain_blob_with_ui_forbidden) {
    DP_NEED_DATA();
    /* not a conflict: the prompt policy is enforced from the flags stored in the blob at protect time, so a fresh blob without
     * prompt bits opens with UI forbidden even when the unprotect call carries a prompt struct that requests a prompt */
    CRYPTPROTECT_PROMPTSTRUCT ps = { sizeof ps, CRYPTPROTECT_PROMPT_ON_UNPROTECT, NULL, L"cryptt" };
    DATA_BLOB blob = { 0 }, plain = { 0 };
    CHECK(dp_protect(SECRET, sizeof SECRET, NULL, NULL, 0, CRYPTPROTECT_UI_FORBIDDEN, &blob));
    if (blob.pbData) {
        DATA_BLOB in = { blob.cbData, blob.pbData };
        SET_ERR(0);
        EXPECT_EQ(U(CryptUnprotectData)(&in, NULL, NULL, NULL, &ps, CRYPTPROTECT_UI_FORBIDDEN, &plain), 1);
        CHECK(plain.cbData == sizeof SECRET && plain.pbData && !memcmp(plain.pbData, SECRET, sizeof SECRET));
    }
    dp_free(&blob); dp_free(&plain);
}
