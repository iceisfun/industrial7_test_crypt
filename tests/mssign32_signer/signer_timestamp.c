/* SignerTimeStamp family, SignerCreateTimeStampRequest, SignerAddTimeStampResponse(Ex): argument handling.
 * No network is used: only argument validation and failures that occur before any URL is contacted. */
#include "mssfix.h"

#define NEED_NOWINE() do { if (t_is_wine()) { t_skip("mssign32 stubs under Wine"); return; } } while (0)
typedef struct { DWORD idx; WCHAR file[MAX_PATH]; SG_FILE fi; SG_SUBJECT sub; } SUB;
static void sub_init(SUB *s) {
    memset(s, 0, sizeof *s);
    _snwprintf(s->file, MAX_PATH - 1, L"C:\\cryptt_nonexistent_dir_%lu\\target.exe", GetCurrentProcessId());
    s->fi.cbSize = sizeof s->fi; s->fi.pwszFileName = s->file;
    s->sub.cbSize = sizeof s->sub; s->sub.pdwIndex = &s->idx; s->sub.dwSubjectChoice = SG_SUBJECT_FILE; s->sub.pInfo = &s->fi;
}
#define URL L"http://127.0.0.1:1/ts"

TEST(mssigner_ts_ex3_flag_combinations_invalid) {
    SignerTimeStampEx3_pfn fn = UN(SignerTimeStampEx3); REQUIRE(fn);
    static const DWORD bad[] = { 0, 3, 5, 6, 7, 8, 0x10, 0x100, 0xFFFFFFFF };   /* not exactly one of 1,2,4 */
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        SUB s; sub_init(&s);
        HRESULT hr = fn(bad[i], 0, &s.sub, URL, NULL, NULL, NULL, NULL, NULL, NULL);
        CHECKF(HR_INVALIDARG == (DWORD)hr, "flags 0x%lx: 0x%08lx", bad[i], (DWORD)hr);
    }
}
TEST(mssigner_ts_ex3_authenticode_requires_index_zero) {
    SignerTimeStampEx3_pfn fn = UN(SignerTimeStampEx3); REQUIRE(fn);
    SUB s; sub_init(&s);
    EXPECT_EQ((DWORD)fn(1, 1, &s.sub, URL, NULL, NULL, NULL, NULL, NULL, NULL), HR_INVALIDARG);
    EXPECT_EQ((DWORD)fn(1, 0xFFFFFFFF, &s.sub, URL, NULL, NULL, NULL, NULL, NULL, NULL), HR_INVALIDARG);
    /* RFC 3161 / sealing accept an index: the missing path is found first */
    EXPECT_EQ((DWORD)fn(2, 1, &s.sub, URL, "2.16.840.1.101.3.4.2.1", NULL, NULL, NULL, NULL, NULL), HR_PATH_NOT_FOUND);
    EXPECT_EQ((DWORD)fn(4, 3, &s.sub, URL, NULL, NULL, NULL, NULL, NULL, NULL), HR_PATH_NOT_FOUND);
}
TEST(mssigner_ts_ex3_reserved_parameter) {
    SignerTimeStampEx3_pfn fn = UN(SignerTimeStampEx3); REQUIRE(fn);
    SUB s; sub_init(&s);
    static const DWORD ok[] = { 1, 2, 4 };
    for (int i = 0; i < 3; i++) {
        HRESULT hr = fn(ok[i], 0, &s.sub, URL, NULL, NULL, NULL, NULL, NULL, (PVOID)1);
        CHECKF(HR_INVALIDARG == (DWORD)hr, "flags %lu: 0x%08lx", ok[i], (DWORD)hr);
    }
}
TEST(mssigner_ts_ex3_missing_path_is_reported_first) {
    SignerTimeStampEx3_pfn fn = UN(SignerTimeStampEx3); REQUIRE(fn);
    static const DWORD ok[] = { 1, 2, 4 };
    for (int i = 0; i < 3; i++) {
        SUB s; sub_init(&s);
        HRESULT hr = fn(ok[i], 0, &s.sub, URL, NULL, NULL, NULL, NULL, NULL, NULL);
        CHECKF(HR_PATH_NOT_FOUND == (DWORD)hr, "flags %lu: 0x%08lx", ok[i], (DWORD)hr);
        hr = fn(ok[i], 0, &s.sub, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
        CHECKF(HR_PATH_NOT_FOUND == (DWORD)hr, "flags %lu no url: 0x%08lx", ok[i], (DWORD)hr);
    }
}
TEST(mssigner_ts_ex3_bad_subject) {
    SignerTimeStampEx3_pfn fn = UN(SignerTimeStampEx3); REQUIRE(fn);
    static const DWORD ok[] = { 1, 2, 4 };
    for (int i = 0; i < 3; i++) {
        SUB s; sub_init(&s);
        CHECKF(HR_INVALIDARG == (DWORD)fn(ok[i], 0, NULL, URL, NULL, NULL, NULL, NULL, NULL, NULL), "NULL subject flags %lu", ok[i]);
        s.sub.cbSize = 0x1f;
        CHECKF(HR_INVALIDARG == (DWORD)fn(ok[i], 0, &s.sub, URL, NULL, NULL, NULL, NULL, NULL, NULL), "cbSize flags %lu", ok[i]);
        sub_init(&s); s.sub.pdwIndex = NULL;
        CHECKF(HR_INVALIDARG == (DWORD)fn(ok[i], 0, &s.sub, URL, NULL, NULL, NULL, NULL, NULL, NULL), "pdwIndex flags %lu", ok[i]);
        sub_init(&s); s.fi.pwszFileName = NULL;
        CHECKF(HR_INVALIDARG == (DWORD)fn(ok[i], 0, &s.sub, URL, NULL, NULL, NULL, NULL, NULL, NULL), "file name flags %lu", ok[i]);
    }
}
TEST(mssigner_ts_wrappers_forward_flags) {
    REQUIRE(UN(SignerTimeStamp)); REQUIRE(UN(SignerTimeStampEx)); REQUIRE(UN(SignerTimeStampEx2));
    SUB s; sub_init(&s);
    /* SignerTimeStamp / SignerTimeStampEx always request Authenticode time stamps; their first Ex argument is ignored */
    EXPECT_EQ((DWORD)UN(SignerTimeStamp)(&s.sub, URL, NULL, NULL), HR_PATH_NOT_FOUND);
    EXPECT_EQ((DWORD)UN(SignerTimeStampEx)(0, &s.sub, URL, NULL, NULL, NULL), HR_PATH_NOT_FOUND);
    EXPECT_EQ((DWORD)UN(SignerTimeStampEx)(0xFFFFFFFF, &s.sub, URL, NULL, NULL, NULL), HR_PATH_NOT_FOUND);
    EXPECT_EQ((DWORD)UN(SignerTimeStamp)(NULL, URL, NULL, NULL), HR_INVALIDARG);
    EXPECT_EQ((DWORD)UN(SignerTimeStampEx)(1, NULL, URL, NULL, NULL, NULL), HR_INVALIDARG);
    /* Ex2 passes its flag word through: it has to select exactly one mode */
    EXPECT_EQ((DWORD)UN(SignerTimeStampEx2)(0, &s.sub, URL, NULL, NULL, NULL, NULL), HR_INVALIDARG);
    EXPECT_EQ((DWORD)UN(SignerTimeStampEx2)(3, &s.sub, URL, NULL, NULL, NULL, NULL), HR_INVALIDARG);
    EXPECT_EQ((DWORD)UN(SignerTimeStampEx2)(1, &s.sub, URL, NULL, NULL, NULL, NULL), HR_PATH_NOT_FOUND);
    EXPECT_EQ((DWORD)UN(SignerTimeStampEx2)(2, &s.sub, URL, "2.16.840.1.101.3.4.2.1", NULL, NULL, NULL), HR_PATH_NOT_FOUND);
}
TEST(mssigner_ts_context_out_pointer_untouched_on_failure) {
    SignerTimeStampEx3_pfn fn = UN(SignerTimeStampEx3); REQUIRE(fn);
    SUB s; sub_init(&s);
    SG_CTX *ctx = (SG_CTX *)(ULONG_PTR)0x1000;
    HRESULT hr = fn(1, 0, &s.sub, URL, NULL, NULL, NULL, &ctx, NULL, NULL);
    CHECK(hr < 0);
    CHECK(ctx == (SG_CTX *)(ULONG_PTR)0x1000 || ctx == NULL);
    t_note("ppSignerContext after failed SignerTimeStampEx3: %p", (void *)ctx);
}

/* ---- request / response helpers ---- */
TEST(mssigner_ts_create_request_arguments) {
    SignerCreateTimeStampRequest_pfn fn = UN(SignerCreateTimeStampRequest); REQUIRE(fn);
    SUB s; sub_init(&s);
    DWORD cb = 0;
    EXPECT_EQ((DWORD)fn(NULL, NULL, NULL, NULL, &cb), HR_INVALIDARG);
    EXPECT_EQ((DWORD)fn(&s.sub, NULL, NULL, NULL, NULL), HR_INVALIDARG);     /* pcbRequest required */
    s.sub.cbSize = 4;
    EXPECT_EQ((DWORD)fn(&s.sub, NULL, NULL, NULL, &cb), HR_INVALIDARG);
    sub_init(&s);
    HRESULT hr = fn(&s.sub, NULL, NULL, NULL, &cb);                           /* nonexistent file */
    CHECK(hr < 0);
    t_note("SignerCreateTimeStampRequest on a missing file: 0x%08lx", (DWORD)hr);
}
TEST(mssigner_ts_add_response_arguments) {
    SignerAddTimeStampResponse_pfn fn = UN(SignerAddTimeStampResponse); REQUIRE(fn);
    SignerAddTimeStampResponseEx_pfn fx = UN(SignerAddTimeStampResponseEx); REQUIRE(fx);
    SUB s; sub_init(&s);
    BYTE resp[16] = { 0x30, 0x03, 0x02, 0x01, 0x00 };
    EXPECT_EQ((DWORD)fn(NULL, resp, sizeof resp, NULL), HR_INVALIDARG);
    EXPECT_EQ((DWORD)fx(0, NULL, resp, sizeof resp, NULL, NULL), HR_INVALIDARG);
    SG_CTX *ctx = (SG_CTX *)(ULONG_PTR)0x1000;
    EXPECT_EQ((DWORD)fx(0, NULL, resp, sizeof resp, NULL, &ctx), HR_INVALIDARG);
    CHECK(ctx == NULL);                       /* cleared before the subject is looked at */
    ctx = (SG_CTX *)(ULONG_PTR)0x1000;
    s.sub.dwSubjectChoice = 7;
    EXPECT_EQ((DWORD)fx(0, &s.sub, resp, sizeof resp, NULL, &ctx), HR_INVALIDARG);
    CHECK(ctx == NULL);
    sub_init(&s);
    HRESULT hr = fn(&s.sub, resp, sizeof resp, NULL);                          /* nonexistent file */
    CHECK(hr < 0);
    t_note("SignerAddTimeStampResponse on a missing file: 0x%08lx", (DWORD)hr);
}
