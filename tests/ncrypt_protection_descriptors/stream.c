#include "npd.h"
/* NCryptStreamOpenToProtect / OpenToUnprotect(Ex) / Update / Close */

static LONG open_protect(void *d, DWORD flags, npd_sink *s, void **hs) {
    NPD_STREAM_INFO si = { npd_cb, s };
    return UN(NCryptStreamOpenToProtect)(d, flags, NULL, &si, hs);
}

/* feed data in chunks; the last chunk carries fFinal */
static LONG feed(void *hs, const BYTE *p, size_t n, size_t chunk, BOOL final_flag) {
    size_t off = 0;
    LONG rc = 0;
    if (n == 0) return UN(NCryptStreamUpdate)(hs, p, 0, final_flag);
    while (off < n) {
        size_t c = n - off < chunk ? n - off : chunk;
        BOOL last = (off + c == n) && final_flag;
        rc = UN(NCryptStreamUpdate)(hs, p + off, c, last);
        if (rc != 0) return rc;
        off += c;
    }
    return rc;
}

/* full stream protect: returns status of the failing step (0 = ok); protected bytes in out */
static LONG stream_protect(void *d, const BYTE *in, size_t n, size_t chunk, DWORD flags, npd_sink *out) {
    void *hs = NULL;
    LONG rc = open_protect(d, flags, out, &hs);
    if (rc != 0) return rc;
    rc = feed(hs, in, n, chunk, TRUE);
    LONG rc2 = UN(NCryptStreamClose)(hs);
    return rc ? rc : rc2;
}

static LONG stream_unprotect(const BYTE *blob, size_t n, size_t chunk, int ex, DWORD flags, npd_sink *out) {
    void *hs = NULL; LONG rc;
    if (ex) {
        NPD_STREAM_INFO_EX si = { npd_cb_ex, out };
        rc = UN(NCryptStreamOpenToUnprotectEx)(&si, flags, NULL, &hs);
    } else {
        NPD_STREAM_INFO si = { npd_cb, out };
        rc = UN(NCryptStreamOpenToUnprotect)(&si, flags, NULL, &hs);
    }
    if (rc != 0) return rc;
    rc = feed(hs, blob, n, chunk, TRUE);
    LONG rc2 = UN(NCryptStreamClose)(hs);
    return rc ? rc : rc2;
}

/* ---- open: argument validation ----------------------------------------------- */

TEST(npd_stream_protect_open_null_args) {
    NREQ(UN(NCryptStreamOpenToProtect));
    void *d = npd_desc(L"LOCAL=user");
    if (!d) { t_skip("no descriptor"); return; }
    npd_sink s; memset(&s, 0, sizeof s);
    NPD_STREAM_INFO si = { npd_cb, &s }, nocb = { NULL, &s };
    void *hs = (void *)(ULONG_PTR)5;
    EXPECT_SS(UN(NCryptStreamOpenToProtect)(d, 0, NULL, NULL, &hs), NPD_NTE_INVALID_PARAM);
    EXPECT_SS(UN(NCryptStreamOpenToProtect)(d, 0, NULL, &si, NULL), NPD_NTE_INVALID_PARAM);
    EXPECT_SS(UN(NCryptStreamOpenToProtect)(d, 0, NULL, &nocb, &hs), NPD_NTE_INVALID_PARAM);
    CHECK(hs == (void *)(ULONG_PTR)5);   /* output untouched on failure */
    CHECK(s.calls == 0);
    npd_desc_close(d);
}

TEST(npd_stream_protect_open_params_before_handle) {
    NREQ(UN(NCryptStreamOpenToProtect));
    npd_sink s; memset(&s, 0, sizeof s);
    NPD_STREAM_INFO si = { npd_cb, &s }, nocb = { NULL, &s };
    void *hs = NULL;
    EXPECT_SS(UN(NCryptStreamOpenToProtect)(NULL, 0, NULL, NULL, &hs), NPD_NTE_INVALID_PARAM);
    EXPECT_SS(UN(NCryptStreamOpenToProtect)(NULL, 0, NULL, &nocb, &hs), NPD_NTE_INVALID_PARAM);
    EXPECT_SS(UN(NCryptStreamOpenToProtect)(NULL, 0, NULL, &si, &hs), NPD_NTE_INVALID_HANDLE);
}

TEST(npd_stream_protect_open_handle_before_flags) {
    NREQ(UN(NCryptStreamOpenToProtect));
    npd_sink s; memset(&s, 0, sizeof s);
    NPD_STREAM_INFO si = { npd_cb, &s };
    void *hs = NULL;
    EXPECT_SS(UN(NCryptStreamOpenToProtect)(NULL, 0x100, NULL, &si, &hs), NPD_NTE_INVALID_HANDLE);
    CHECK(s.calls == 0);
}

TEST(npd_stream_protect_open_bad_flags) {
    NREQ(UN(NCryptStreamOpenToProtect));
    void *d = npd_desc(L"LOCAL=user");
    if (!d) { t_skip("no descriptor"); return; }
    static const DWORD bad[] = { 0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x100, 0x200, 0x1000, 0x10000, 0x80000000u };
    for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) {
        npd_sink s; memset(&s, 0, sizeof s);
        void *hs = (void *)(ULONG_PTR)5;
        LONG rc = open_protect(d, bad[i], &s, &hs);
        CHECKF(SS(rc) == NPD_NTE_BAD_FLAGS, "flags 0x%lx: 0x%lx", (unsigned long)bad[i], (unsigned long)SS(rc));
        CHECKF(hs == (void *)(ULONG_PTR)5 && s.calls == 0, "flags 0x%lx: side effects", (unsigned long)bad[i]);
    }
    npd_desc_close(d);
}

TEST(npd_stream_protect_open_wrong_handle_type) {
    NREQ(UN(NCryptStreamOpenToProtect));
    NREQ(UN(NCryptOpenKeyProtector));
    void *kp = NULL;
    if (UN(NCryptOpenKeyProtector)(&kp, L"LOCAL", 0) != 0) { t_skip("no LOCAL protector"); return; }
    npd_sink s; memset(&s, 0, sizeof s);
    void *hs = NULL;
    EXPECT_SS(open_protect(kp, 0, &s, &hs), NPD_NTE_INVALID_HANDLE);
    UN(NCryptCloseKeyProtector)(kp);
}

TEST(npd_stream_unprotect_open_null_args) {
    NREQ(UN(NCryptStreamOpenToUnprotect));
    npd_sink s; memset(&s, 0, sizeof s);
    NPD_STREAM_INFO si = { npd_cb, &s }, nocb = { NULL, &s };
    void *hs = (void *)(ULONG_PTR)5;
    EXPECT_SS(UN(NCryptStreamOpenToUnprotect)(NULL, 0, NULL, &hs), NPD_NTE_INVALID_PARAM);
    EXPECT_SS(UN(NCryptStreamOpenToUnprotect)(&si, 0, NULL, NULL), NPD_NTE_INVALID_PARAM);
    EXPECT_SS(UN(NCryptStreamOpenToUnprotect)(&nocb, 0, NULL, &hs), NPD_NTE_INVALID_PARAM);
    CHECK(hs == (void *)(ULONG_PTR)5);
}

TEST(npd_stream_unprotect_open_params_before_flags) {
    NREQ(UN(NCryptStreamOpenToUnprotect));
    NREQ(UN(NCryptStreamOpenToUnprotectEx));
    npd_sink s; memset(&s, 0, sizeof s);
    NPD_STREAM_INFO nocb = { NULL, &s };
    NPD_STREAM_INFO_EX nocbx = { NULL, &s };
    void *hs = NULL;
    EXPECT_SS(UN(NCryptStreamOpenToUnprotect)(&nocb, 0x100, NULL, &hs), NPD_NTE_INVALID_PARAM);
    EXPECT_SS(UN(NCryptStreamOpenToUnprotectEx)(&nocbx, 0x100, NULL, &hs), NPD_NTE_INVALID_PARAM);
    EXPECT_SS(UN(NCryptStreamOpenToUnprotectEx)(NULL, 0x100, NULL, &hs), NPD_NTE_INVALID_PARAM);
}

TEST(npd_stream_unprotect_open_bad_flags) {
    NREQ(UN(NCryptStreamOpenToUnprotect));
    static const DWORD bad[] = { 0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x100, 0x200, 0x1000, 0x80000000u };
    for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) {
        npd_sink s; memset(&s, 0, sizeof s);
        NPD_STREAM_INFO si = { npd_cb, &s };
        void *hs = (void *)(ULONG_PTR)5;
        LONG rc = UN(NCryptStreamOpenToUnprotect)(&si, bad[i], NULL, &hs);
        CHECKF(SS(rc) == NPD_NTE_BAD_FLAGS, "flags 0x%lx: 0x%lx", (unsigned long)bad[i], (unsigned long)SS(rc));
        CHECKF(hs == (void *)(ULONG_PTR)5, "flags 0x%lx: handle written", (unsigned long)bad[i]);
    }
}

TEST(npd_stream_unprotect_ex_open_bad_flags) {
    NREQ(UN(NCryptStreamOpenToUnprotectEx));
    static const DWORD bad[] = { 0x2, 0x4, 0x8, 0x10, 0x20, 0x100, 0x200, 0x1000, 0x80000000u };
    for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) {
        npd_sink s; memset(&s, 0, sizeof s);
        NPD_STREAM_INFO_EX si = { npd_cb_ex, &s };
        void *hs = (void *)(ULONG_PTR)5;
        LONG rc = UN(NCryptStreamOpenToUnprotectEx)(&si, bad[i], NULL, &hs);
        CHECKF(SS(rc) == NPD_NTE_BAD_FLAGS, "flags 0x%lx: 0x%lx", (unsigned long)bad[i], (unsigned long)SS(rc));
        CHECKF(hs == (void *)(ULONG_PTR)5, "flags 0x%lx: handle written", (unsigned long)bad[i]);
    }
}

TEST(npd_stream_unprotect_open_accepts_documented_flags) {
    NREQ(UN(NCryptStreamOpenToUnprotect));
    NREQ(UN(NCryptStreamOpenToUnprotectEx));
    static const DWORD ok[] = { 0, NPD_SILENT_FLAG };
    for (size_t i = 0; i < 2; i++) {
        npd_sink s; memset(&s, 0, sizeof s);
        NPD_STREAM_INFO si = { npd_cb, &s };
        void *hs = NULL;
        EXPECT_SS(UN(NCryptStreamOpenToUnprotect)(&si, ok[i], NULL, &hs), 0);
        CHECK(hs != NULL);
        if (hs) EXPECT_SS(UN(NCryptStreamClose)(hs), 0);
        NPD_STREAM_INFO_EX sx = { npd_cb_ex, &s };
        hs = NULL;
        EXPECT_SS(UN(NCryptStreamOpenToUnprotectEx)(&sx, ok[i], NULL, &hs), 0);
        CHECK(hs != NULL);
        if (hs) EXPECT_SS(UN(NCryptStreamClose)(hs), 0);
        CHECK(s.calls == 0);   /* nothing is emitted until data is supplied */
    }
}

TEST(npd_stream_unprotect_open_does_not_invoke_callback) {
    NREQ(UN(NCryptStreamOpenToUnprotect));
    npd_sink s; memset(&s, 0, sizeof s);
    NPD_STREAM_INFO si = { npd_cb, &s };
    void *hs = NULL;
    EXPECT_SS(UN(NCryptStreamOpenToUnprotect)(&si, 0, NULL, &hs), 0);
    CHECK(s.calls == 0);
    if (hs) UN(NCryptStreamClose)(hs);
    npd_sink_free(&s);
}

/* ---- close / update on invalid handles --------------------------------------------- */

TEST(npd_stream_close_null) {
    NREQ(UN(NCryptStreamClose));
    EXPECT_SS(UN(NCryptStreamClose)(NULL), NPD_NTE_INVALID_HANDLE);
}

TEST(npd_stream_update_null) {
    NREQ(UN(NCryptStreamUpdate));
    BYTE b[4] = {1,2,3,4};
    EXPECT_SS(UN(NCryptStreamUpdate)(NULL, b, 4, FALSE), NPD_NTE_INVALID_HANDLE);
    EXPECT_SS(UN(NCryptStreamUpdate)(NULL, b, 4, TRUE), NPD_NTE_INVALID_HANDLE);
    EXPECT_SS(UN(NCryptStreamUpdate)(NULL, NULL, 0, TRUE), NPD_NTE_INVALID_HANDLE);
}

TEST(npd_stream_update_rejects_descriptor_handle) {
    NREQ(UN(NCryptStreamUpdate));
    void *d = npd_desc(L"LOCAL=user");
    if (!d) { t_skip("no descriptor"); return; }
    BYTE b[4] = {1,2,3,4};
    EXPECT_SS(UN(NCryptStreamUpdate)(d, b, 4, FALSE), NPD_NTE_INVALID_HANDLE);
    npd_desc_close(d);
}

TEST(npd_stream_handle_is_not_a_descriptor) {
    NREQ(UN(NCryptStreamOpenToUnprotect));
    npd_sink s; memset(&s, 0, sizeof s);
    NPD_STREAM_INFO si = { npd_cb, &s };
    void *hs = NULL;
    if (UN(NCryptStreamOpenToUnprotect)(&si, 0, NULL, &hs) != 0) { t_skip("open failed"); return; }
    EXPECT_SS(UN(NCryptCloseProtectionDescriptor)(hs), NPD_NTE_INVALID_HANDLE);
    EXPECT_SS(UN(NCryptGetProtectionDescriptorInfo)(hs, NULL, 1, &(void *){NULL}), NPD_NTE_INVALID_HANDLE);
    EXPECT_SS(UN(NCryptStreamClose)(hs), 0);
}

/* ---- protect stream behaviour --------------------------------------------------------- */

TEST(npd_stream_protect_open_emits_header) {
    NREQ(UN(NCryptStreamOpenToProtect));
    REQUIRE_WORKING();
    void *d = npd_desc(L"LOCAL=user");
    npd_sink s; memset(&s, 0, sizeof s);
    void *hs = NULL;
    EXPECT_SS(open_protect(d, NPD_SILENT_FLAG, &s, &hs), 0);
    CHECK(hs != NULL);
    CHECK(s.calls == 1);            /* the encoded message header is delivered at open time */
    CHECK(s.final_calls == 0);
    CHECK(s.len > 0 && s.buf && s.buf[0] == 0x30);
    if (hs) EXPECT_SS(UN(NCryptStreamClose)(hs), 0);
    npd_sink_free(&s);
    npd_desc_close(d);
}

static LONG WINAPI failing_cb(void *ctx, const BYTE *p, SIZE_T cb, BOOL f) { (*(int *)ctx)++; return (LONG)0x80004005; }

TEST(npd_stream_protect_open_callback_failure_propagates) {
    NREQ(UN(NCryptStreamOpenToProtect));
    REQUIRE_WORKING();
    void *d = npd_desc(L"LOCAL=user");
    int calls = 0;
    NPD_STREAM_INFO si = { failing_cb, &calls };
    void *hs = (void *)(ULONG_PTR)5;
    LONG rc = UN(NCryptStreamOpenToProtect)(d, 0, NULL, &si, &hs);
    EXPECT_SS(rc, 0x80004005);     /* callback status is returned verbatim */
    CHECK(calls == 1);
    CHECK(hs == (void *)(ULONG_PTR)5);
    npd_desc_close(d);
}

static LONG WINAPI nt_fail_cb(void *ctx, const BYTE *p, SIZE_T cb, BOOL f) { return 0x00000005; }

TEST(npd_stream_protect_open_callback_nonzero_status_is_failure) {
    NREQ(UN(NCryptStreamOpenToProtect));
    REQUIRE_WORKING();
    void *d = npd_desc(L"LOCAL=user");
    NPD_STREAM_INFO si = { nt_fail_cb, NULL };
    void *hs = (void *)(ULONG_PTR)5;
    LONG rc = UN(NCryptStreamOpenToProtect)(d, 0, NULL, &si, &hs);
    EXPECT_SS(rc, 5);
    CHECK(hs == (void *)(ULONG_PTR)5);
    npd_desc_close(d);
}

TEST(npd_stream_protect_final_callback_semantics) {
    NREQ(UN(NCryptStreamOpenToProtect));
    REQUIRE_WORKING();
    void *d = npd_desc(L"LOCAL=user");
    BYTE in[500]; npd_fill(in, 500, 3);
    npd_sink s; memset(&s, 0, sizeof s);
    EXPECT_SS(stream_protect(d, in, 500, 100, NPD_SILENT_FLAG, &s), 0);
    CHECK(s.calls >= 2);
    CHECK(s.final_calls == 1);
    CHECK(s.last_final == 1);
    CHECK(s.after_final == 0);
    CHECK(s.len > 500);
    npd_sink_free(&s);
    npd_desc_close(d);
}

TEST(npd_stream_protect_update_after_final_is_invalid_handle) {
    NREQ(UN(NCryptStreamOpenToProtect));
    REQUIRE_WORKING();
    void *d = npd_desc(L"LOCAL=user");
    npd_sink s; memset(&s, 0, sizeof s);
    void *hs = NULL;
    EXPECT_SS(open_protect(d, 0, &s, &hs), 0);
    BYTE in[20]; npd_fill(in, 20, 4);
    EXPECT_SS(UN(NCryptStreamUpdate)(hs, in, 20, TRUE), 0);
    int calls = s.calls;
    EXPECT_SS(UN(NCryptStreamUpdate)(hs, in, 20, FALSE), NPD_NTE_INVALID_HANDLE);
    EXPECT_SS(UN(NCryptStreamUpdate)(hs, in, 20, TRUE), NPD_NTE_INVALID_HANDLE);
    EXPECT_SS(UN(NCryptStreamUpdate)(hs, NULL, 0, TRUE), NPD_NTE_INVALID_HANDLE);
    CHECK(s.calls == calls);        /* nothing delivered after the final block */
    EXPECT_SS(UN(NCryptStreamClose)(hs), 0);
    npd_sink_free(&s);
    npd_desc_close(d);
}

TEST(npd_stream_unprotect_update_after_final_is_invalid_handle) {
    NREQ(UN(NCryptStreamOpenToProtect));
    REQUIRE_WORKING();
    void *d = npd_desc(L"LOCAL=user");
    BYTE in[40]; npd_fill(in, 40, 5);
    npd_sink p; memset(&p, 0, sizeof p);
    EXPECT_SS(stream_protect(d, in, 40, 40, 0, &p), 0);
    npd_sink s; memset(&s, 0, sizeof s);
    NPD_STREAM_INFO si = { npd_cb, &s };
    void *hs = NULL;
    EXPECT_SS(UN(NCryptStreamOpenToUnprotect)(&si, 0, NULL, &hs), 0);
    EXPECT_SS(UN(NCryptStreamUpdate)(hs, p.buf, p.len, TRUE), 0);
    EXPECT_SS(UN(NCryptStreamUpdate)(hs, p.buf, 1, FALSE), NPD_NTE_INVALID_HANDLE);
    EXPECT_SS(UN(NCryptStreamClose)(hs), 0);
    CHECK(s.len == 40 && !memcmp(s.buf, in, 40));
    npd_sink_free(&s); npd_sink_free(&p);
    npd_desc_close(d);
}

TEST(npd_stream_protect_close_without_final) {
    /* closing an unfinished stream just releases it */
    NREQ(UN(NCryptStreamOpenToProtect));
    REQUIRE_WORKING();
    void *d = npd_desc(L"LOCAL=user");
    npd_sink s; memset(&s, 0, sizeof s);
    void *hs = NULL;
    EXPECT_SS(open_protect(d, 0, &s, &hs), 0);
    BYTE in[10] = {0};
    EXPECT_SS(UN(NCryptStreamUpdate)(hs, in, 10, FALSE), 0);
    EXPECT_SS(UN(NCryptStreamClose)(hs), 0);
    CHECK(s.final_calls == 0);
    npd_sink_free(&s);
    npd_desc_close(d);
}

TEST(npd_stream_protect_zero_length_update) {
    NREQ(UN(NCryptStreamOpenToProtect));
    REQUIRE_WORKING();
    void *d = npd_desc(L"LOCAL=user");
    npd_sink s; memset(&s, 0, sizeof s);
    void *hs = NULL;
    EXPECT_SS(open_protect(d, 0, &s, &hs), 0);
    BYTE b = 0;
    LONG rc = UN(NCryptStreamUpdate)(hs, &b, 0, FALSE);
    t_note("zero-length non-final update -> 0x%lx", (unsigned long)SS(rc));
    BYTE in[10]; npd_fill(in, 10, 9);
    EXPECT_SS(UN(NCryptStreamUpdate)(hs, in, 10, TRUE), 0);
    UN(NCryptStreamClose)(hs);
    npd_sink_free(&s);
    npd_desc_close(d);
}

TEST(npd_stream_protect_callback_failure_during_update) {
    NREQ(UN(NCryptStreamOpenToProtect));
    REQUIRE_WORKING();
    void *d = npd_desc(L"LOCAL=user");
    npd_sink s; memset(&s, 0, sizeof s);
    s.fail_at = 2; s.fail_ret = (LONG)0x80004005;
    void *hs = NULL;
    EXPECT_SS(open_protect(d, 0, &s, &hs), 0);
    BYTE in[300]; npd_fill(in, 300, 12);
    LONG rc = feed(hs, in, 300, 50, TRUE);
    CHECK(rc != 0);
    t_note("callback failure at call 2 surfaced as 0x%lx", (unsigned long)SS(rc));
    UN(NCryptStreamClose)(hs);
    npd_sink_free(&s);
    npd_desc_close(d);
}

/* ---- stream round trips ----------------------------------------------------------------- */

static void stream_roundtrip(size_t n, size_t pchunk, size_t uchunk, int ex) {
    void *d = npd_desc(L"LOCAL=user");
    BYTE *in = (BYTE *)malloc(n ? n : 1);
    npd_fill(in, n, (unsigned)(n * 7 + pchunk));
    npd_sink p, u; memset(&p, 0, sizeof p); memset(&u, 0, sizeof u);
    LONG rc = stream_protect(d, in, n, pchunk, NPD_SILENT_FLAG, &p);
    CHECKF(rc == 0, "protect n=%lu chunk=%lu -> 0x%lx", (unsigned long)n, (unsigned long)pchunk, (unsigned long)SS(rc));
    if (rc == 0) {
        CHECKF(p.final_calls == 1 && p.last_final == 1, "protect n=%lu: final callback count %d", (unsigned long)n, p.final_calls);
        CHECK(p.len > n);
        rc = stream_unprotect(p.buf, p.len, uchunk, ex, NPD_SILENT_FLAG, &u);
        CHECKF(rc == 0, "unprotect n=%lu chunk=%lu ex=%d -> 0x%lx", (unsigned long)n, (unsigned long)uchunk, ex, (unsigned long)SS(rc));
        if (rc == 0) {
            CHECKF(u.len == n && (n == 0 || !memcmp(u.buf, in, n)), "n=%lu pchunk=%lu uchunk=%lu: plaintext mismatch (got %lu)", (unsigned long)n, (unsigned long)pchunk, (unsigned long)uchunk, (unsigned long)u.len);
            CHECKF(u.final_calls == 1 && u.last_final == 1 && u.after_final == 0, "unprotect callback final accounting calls=%d final=%d", u.calls, u.final_calls);
        }
    }
    npd_sink_free(&p); npd_sink_free(&u); free(in);
    npd_desc_close(d);
}

TEST(npd_stream_roundtrip_chunk_matrix) {
    NREQ(UN(NCryptStreamOpenToProtect));
    REQUIRE_WORKING();
    static const size_t sizes[] = { 1, 15, 16, 17, 100, 1000, 10000 };
    static const size_t chunks[] = { 1, 7, 16, 33, 4096, 1 << 20 };
    for (size_t i = 0; i < sizeof sizes / sizeof *sizes; i++)
        for (size_t j = 0; j < sizeof chunks / sizeof *chunks; j++) {
            if (sizes[i] >= 10000 && chunks[j] == 1) continue;  /* keep the matrix bounded */
            stream_roundtrip(sizes[i], chunks[j], chunks[(j + 2) % 6], 0);
        }
}

TEST(npd_stream_roundtrip_unprotect_ex) {
    NREQ(UN(NCryptStreamOpenToProtect));
    NREQ(UN(NCryptStreamOpenToUnprotectEx));
    REQUIRE_WORKING();
    static const size_t sizes[] = { 1, 100, 5000 };
    static const size_t chunks[] = { 1, 17, 1 << 20 };
    for (size_t i = 0; i < 3; i++) for (size_t j = 0; j < 3; j++) stream_roundtrip(sizes[i], 64, chunks[j], 1);
}

TEST(npd_stream_roundtrip_large_one_meg) {
    NREQ(UN(NCryptStreamOpenToProtect));
    REQUIRE_WORKING();
    stream_roundtrip(1 << 20, 65536, 8192, 0);
}

TEST(npd_stream_roundtrip_byte_at_a_time_unprotect) {
    NREQ(UN(NCryptStreamOpenToProtect));
    REQUIRE_WORKING();
    /* header accumulation must work for 1-byte feeds, including the very first bytes */
    stream_roundtrip(200, 200, 1, 0);
    stream_roundtrip(200, 200, 1, 1);
}

TEST(npd_stream_roundtrip_flags) {
    NREQ(UN(NCryptStreamOpenToProtect));
    REQUIRE_WORKING();
    void *d = npd_desc(L"LOCAL=user");
    static const DWORD f[] = { 0, NPD_SILENT_FLAG };
    BYTE in[64]; npd_fill(in, 64, 77);
    for (int a = 0; a < 2; a++) for (int b = 0; b < 2; b++) {
        npd_sink p, u; memset(&p, 0, sizeof p); memset(&u, 0, sizeof u);
        EXPECT_SS(stream_protect(d, in, 64, 64, f[a], &p), 0);
        EXPECT_SS(stream_unprotect(p.buf, p.len, 64, 0, f[b], &u), 0);
        CHECK(u.len == 64 && !memcmp(u.buf, in, 64));
        npd_sink_free(&p); npd_sink_free(&u);
    }
    npd_desc_close(d);
}

TEST(npd_stream_two_streams_interleaved) {
    NREQ(UN(NCryptStreamOpenToProtect));
    REQUIRE_WORKING();
    void *d = npd_desc(L"LOCAL=user");
    npd_sink s1, s2; memset(&s1, 0, sizeof s1); memset(&s2, 0, sizeof s2);
    void *h1 = NULL, *h2 = NULL;
    EXPECT_SS(open_protect(d, 0, &s1, &h1), 0);
    EXPECT_SS(open_protect(d, 0, &s2, &h2), 0);
    CHECK(h1 && h2 && h1 != h2);
    BYTE a[100], b[100]; npd_fill(a, 100, 1); npd_fill(b, 100, 2);
    for (int i = 0; i < 10; i++) {
        EXPECT_SS(UN(NCryptStreamUpdate)(h1, a + i * 10, 10, i == 9), 0);
        EXPECT_SS(UN(NCryptStreamUpdate)(h2, b + i * 10, 10, i == 9), 0);
    }
    UN(NCryptStreamClose)(h1); UN(NCryptStreamClose)(h2);
    npd_sink u1, u2; memset(&u1, 0, sizeof u1); memset(&u2, 0, sizeof u2);
    EXPECT_SS(stream_unprotect(s1.buf, s1.len, 1000, 0, 0, &u1), 0);
    EXPECT_SS(stream_unprotect(s2.buf, s2.len, 1000, 0, 0, &u2), 0);
    CHECK(u1.len == 100 && !memcmp(u1.buf, a, 100));
    CHECK(u2.len == 100 && !memcmp(u2.buf, b, 100));
    npd_sink_free(&s1); npd_sink_free(&s2); npd_sink_free(&u1); npd_sink_free(&u2);
    npd_desc_close(d);
}

TEST(npd_stream_descriptor_closed_after_open) {
    /* the stream keeps what it needs; the descriptor handle may be closed right after open */
    NREQ(UN(NCryptStreamOpenToProtect));
    REQUIRE_WORKING();
    void *d = npd_desc(L"LOCAL=user");
    npd_sink s; memset(&s, 0, sizeof s);
    void *hs = NULL;
    EXPECT_SS(open_protect(d, 0, &s, &hs), 0);
    npd_desc_close(d);
    BYTE in[30]; npd_fill(in, 30, 8);
    EXPECT_SS(UN(NCryptStreamUpdate)(hs, in, 30, TRUE), 0);
    EXPECT_SS(UN(NCryptStreamClose)(hs), 0);
    npd_sink u; memset(&u, 0, sizeof u);
    EXPECT_SS(stream_unprotect(s.buf, s.len, 1000, 0, 0, &u), 0);
    CHECK(u.len == 30 && !memcmp(u.buf, in, 30));
    npd_sink_free(&s); npd_sink_free(&u);
}

TEST(npd_stream_callback_context_passed_verbatim) {
    NREQ(UN(NCryptStreamOpenToProtect));
    REQUIRE_WORKING();
    void *d = npd_desc(L"LOCAL=user");
    npd_sink s; memset(&s, 0, sizeof s);
    NPD_STREAM_INFO si = { npd_cb, &s };
    void *hs = NULL;
    EXPECT_SS(UN(NCryptStreamOpenToProtect)(d, 0, NULL, &si, &hs), 0);
    CHECK(s.calls == 1);
    /* mutating the caller's info structure after open must not redirect later callbacks */
    si.pfnStreamOutput = nt_fail_cb; si.pvCallbackCtxt = NULL;
    BYTE in[10] = {0};
    EXPECT_SS(UN(NCryptStreamUpdate)(hs, in, 10, TRUE), 0);
    CHECK(s.calls >= 2 && s.final_calls == 1);
    UN(NCryptStreamClose)(hs);
    npd_sink_free(&s);
    npd_desc_close(d);
}

/* ---- unprotect stream on bad content ------------------------------------------------------ */

TEST(npd_stream_unprotect_wrong_outer_tag) {
    NREQ(UN(NCryptStreamOpenToUnprotect));
    npd_sink s; memset(&s, 0, sizeof s);
    NPD_STREAM_INFO si = { npd_cb, &s };
    void *hs = NULL;
    EXPECT_SS(UN(NCryptStreamOpenToUnprotect)(&si, 0, NULL, &hs), 0);
    static const BYTE intg[] = { 0x02, 0x01, 0x05, 0, 0, 0, 0, 0 };   /* valid DER INTEGER, not a SEQUENCE */
    LONG rc = UN(NCryptStreamUpdate)(hs, intg, sizeof intg, TRUE);
    EXPECT_SS(rc, NPD_NTE_BAD_DATA);
    CHECK(s.calls == 0);
    UN(NCryptStreamClose)(hs);
}

TEST(npd_stream_unprotect_garbage_final) {
    NREQ(UN(NCryptStreamOpenToUnprotect));
    npd_sink s; memset(&s, 0, sizeof s);
    NPD_STREAM_INFO si = { npd_cb, &s };
    void *hs = NULL;
    EXPECT_SS(UN(NCryptStreamOpenToUnprotect)(&si, 0, NULL, &hs), 0);
    BYTE g[16]; memset(g, 0xff, 16);
    LONG rc = UN(NCryptStreamUpdate)(hs, g, 16, TRUE);
    CHECK(rc != 0);
    t_note("0xff garbage -> 0x%lx", (unsigned long)SS(rc));
    CHECK(s.calls == 0);
    UN(NCryptStreamClose)(hs);
}

TEST(npd_stream_unprotect_single_byte_final_is_pending) {
    /* fewer than 2 header bytes cannot be judged yet, even with fFinal: accepted without output */
    NREQ(UN(NCryptStreamOpenToUnprotect));
    npd_sink s; memset(&s, 0, sizeof s);
    NPD_STREAM_INFO si = { npd_cb, &s };
    void *hs = NULL;
    EXPECT_SS(UN(NCryptStreamOpenToUnprotect)(&si, 0, NULL, &hs), 0);
    BYTE b = 0x30;
    EXPECT_SS(UN(NCryptStreamUpdate)(hs, &b, 1, FALSE), 0);
    CHECK(s.calls == 0);
    UN(NCryptStreamClose)(hs);
    /* also with fFinal set: still under two header bytes, nothing to judge */
    hs = NULL;
    EXPECT_SS(UN(NCryptStreamOpenToUnprotect)(&si, 0, NULL, &hs), 0);
    EXPECT_SS(UN(NCryptStreamUpdate)(hs, &b, 1, TRUE), 0);
    CHECK(s.calls == 0);
    UN(NCryptStreamClose)(hs);
}

TEST(npd_stream_unprotect_truncated) {
    NREQ(UN(NCryptStreamOpenToProtect));
    REQUIRE_WORKING();
    void *d = npd_desc(L"LOCAL=user");
    BYTE in[100]; npd_fill(in, 100, 14);
    npd_sink p; memset(&p, 0, sizeof p);
    EXPECT_SS(stream_protect(d, in, 100, 100, 0, &p), 0);
    /* a stream may end in framing bytes that a decoder tolerates losing: small cuts are only observed;
       a cut that reaches into the authentication tag must never succeed */
    static const size_t cuts[] = { 1, 2, 10, 24, 40 };
    for (size_t i = 0; i < 5; i++) {
        npd_sink u; memset(&u, 0, sizeof u);
        LONG rc = stream_unprotect(p.buf, p.len - cuts[i], 64, 0, 0, &u);
        if (cuts[i] >= 24) CHECKF(rc != 0, "blob missing %lu trailing bytes accepted", (unsigned long)cuts[i]);
        else t_note("blob missing %lu trailing bytes -> 0x%lx", (unsigned long)cuts[i], (unsigned long)SS(rc));
        npd_sink_free(&u);
    }
    npd_sink_free(&p);
    npd_desc_close(d);
}

TEST(npd_stream_unprotect_tampered_payload) {
    NREQ(UN(NCryptStreamOpenToProtect));
    REQUIRE_WORKING();
    void *d = npd_desc(L"LOCAL=user");
    BYTE in[100]; npd_fill(in, 100, 15);
    npd_sink p, u; memset(&p, 0, sizeof p); memset(&u, 0, sizeof u);
    EXPECT_SS(stream_protect(d, in, 100, 100, 0, &p), 0);
    CHECK(p.first_size > 0 && p.first_size + 20 < p.len);
    if (p.first_size > 0 && p.first_size + 20 < p.len) {
        /* inside the payload that follows the header: framing or ciphertext, either way it must not decode */
        p.buf[p.first_size + 10] ^= 0x40;
        LONG rc = stream_unprotect(p.buf, p.len, 64, 0, 0, &u);
        CHECK(rc != 0);
        t_note("tampered stream: status 0x%lx, plaintext bytes delivered before failure: %lu, final callbacks %d", (unsigned long)SS(rc), (unsigned long)u.len, u.final_calls);
    }
    npd_sink_free(&p); npd_sink_free(&u);
    npd_desc_close(d);
}

TEST(npd_stream_unprotect_callback_failure) {
    NREQ(UN(NCryptStreamOpenToProtect));
    REQUIRE_WORKING();
    void *d = npd_desc(L"LOCAL=user");
    BYTE in[100]; npd_fill(in, 100, 16);
    npd_sink p, u; memset(&p, 0, sizeof p); memset(&u, 0, sizeof u);
    EXPECT_SS(stream_protect(d, in, 100, 100, 0, &p), 0);
    u.fail_at = 1; u.fail_ret = (LONG)0x80004005;
    LONG rc = stream_unprotect(p.buf, p.len, 1000, 0, 0, &u);
    CHECK(rc != 0);
    t_note("callback failure while unprotecting -> 0x%lx", (unsigned long)SS(rc));
    npd_sink_free(&p); npd_sink_free(&u);
    npd_desc_close(d);
}

/* ---- interoperability between the secret and stream forms (observed only) ---------------------- */

TEST(npd_stream_interop_secret_blob_to_stream_observed) {
    NREQ(UN(NCryptStreamOpenToUnprotect));
    REQUIRE_WORKING();
    void *d = npd_desc(L"LOCAL=user");
    BYTE in[64]; npd_fill(in, 64, 18);
    BYTE *blob = NULL; ULONG cb = 0;
    EXPECT_SS(UN(NCryptProtectSecret)(d, 0, in, 64, NULL, NULL, &blob, &cb), 0);
    npd_sink u; memset(&u, 0, sizeof u);
    LONG rc = blob ? stream_unprotect(blob, cb, 100, 0, 0, &u) : -1;
    t_note("ProtectSecret blob through stream unprotect -> 0x%lx, %lu plaintext bytes, match=%d", (unsigned long)SS(rc), (unsigned long)u.len, u.len == 64 && !memcmp(u.buf, in, 64));
    if (blob) LocalFree(blob);
    npd_sink_free(&u);
    npd_desc_close(d);
}

TEST(npd_stream_interop_stream_blob_to_secret_observed) {
    NREQ(UN(NCryptStreamOpenToProtect));
    REQUIRE_WORKING();
    void *d = npd_desc(L"LOCAL=user");
    BYTE in[64]; npd_fill(in, 64, 19);
    npd_sink p; memset(&p, 0, sizeof p);
    EXPECT_SS(stream_protect(d, in, 64, 64, 0, &p), 0);
    BYTE *out = NULL; ULONG co = 0;
    LONG rc = UN(NCryptUnprotectSecret)(NULL, 0, p.buf, (ULONG)p.len, NULL, NULL, &out, &co);
    t_note("stream blob through UnprotectSecret -> 0x%lx, %lu bytes, match=%d", (unsigned long)SS(rc), (unsigned long)co, rc == 0 && co == 64 && !memcmp(out, in, 64));
    if (out) LocalFree(out);
    npd_sink_free(&p);
    npd_desc_close(d);
}
