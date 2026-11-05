#include "npd.h"
/* Additional DPAPI-NG coverage: flag-bit sweeps, parser corner cases, stream state machine, NO_DECRYPT */

/* every flag bit that is not documented/accepted must give NTE_BAD_FLAGS; `skip` bits are valid or feature dependent */
#define BIT_SWEEP_BEGIN(skip) for (int b = 0; b < 32; b++) { DWORD f = 1u << b; if (f & (skip)) continue;
#define BIT_SWEEP_END }

TEST(npd_x_create_flag_bit_sweep) {
    NREQ(UN(NCryptCreateProtectionDescriptor));
    BIT_SWEEP_BEGIN(0x1u | 0x20u)
        void *h = (void *)(ULONG_PTR)1;
        LONG rc = UN(NCryptCreateProtectionDescriptor)(L"LOCAL=user", f, &h);
        CHECKF(SS(rc) == NPD_NTE_BAD_FLAGS, "flag bit %d: 0x%lx", b, (unsigned long)SS(rc));
        CHECKF(h == NULL, "flag bit %d: handle not cleared", b);
    BIT_SWEEP_END
}

TEST(npd_x_protect_secret_flag_bit_sweep) {
    NREQ(UN(NCryptProtectSecret));
    void *d = npd_desc(L"LOCAL=user");
    if (!d) { t_skip("no descriptor"); return; }
    BYTE data[4] = {1,2,3,4};
    BIT_SWEEP_BEGIN(0x40u)
        BYTE *blob = (BYTE *)(ULONG_PTR)1; ULONG cb = 9;
        LONG rc = UN(NCryptProtectSecret)(d, f, data, 4, NULL, NULL, &blob, &cb);
        CHECKF(SS(rc) == NPD_NTE_BAD_FLAGS, "flag bit %d: 0x%lx", b, (unsigned long)SS(rc));
        CHECKF(blob == NULL && cb == 0, "flag bit %d: outputs not cleared", b);
    BIT_SWEEP_END
    npd_desc_close(d);
}

TEST(npd_x_unprotect_secret_flag_bit_sweep) {
    NREQ(UN(NCryptUnprotectSecret));
    BYTE blob[8] = {0x30, 6, 1, 2, 3, 4, 5, 6};
    BIT_SWEEP_BEGIN(0x1u | 0x40u)
        BYTE *out = (BYTE *)(ULONG_PTR)1; ULONG co = 9; void *d = (void *)(ULONG_PTR)1;
        LONG rc = UN(NCryptUnprotectSecret)(&d, f, blob, 8, NULL, NULL, &out, &co);
        CHECKF(SS(rc) == NPD_NTE_BAD_FLAGS, "flag bit %d: 0x%lx", b, (unsigned long)SS(rc));
        CHECKF(out == NULL && co == 0 && d == NULL, "flag bit %d: outputs not cleared", b);
    BIT_SWEEP_END
}

TEST(npd_x_query_register_flag_bit_sweep) {
    NREQ(UN(NCryptQueryProtectionDescriptorName));
    NREQ(UN(NCryptRegisterProtectionDescriptorName));
    BIT_SWEEP_BEGIN(0x20u)
        SIZE_T cch = 9;
        LONG rc = UN(NCryptQueryProtectionDescriptorName)(L"cryptt_npd_x_sweep", NULL, &cch, f);
        CHECKF(SS(rc) == NPD_NTE_BAD_FLAGS, "query flag bit %d: 0x%lx", b, (unsigned long)SS(rc));
        CHECKF(cch == 0, "query flag bit %d: size not zeroed", b);
        /* rejected before any registry access */
        rc = UN(NCryptRegisterProtectionDescriptorName)(L"cryptt_npd_x_sweep", L"LOCAL=user", f);
        CHECKF(SS(rc) == NPD_NTE_BAD_FLAGS, "register flag bit %d: 0x%lx", b, (unsigned long)SS(rc));
    BIT_SWEEP_END
}

TEST(npd_x_stream_open_flag_bit_sweep) {
    NREQ(UN(NCryptStreamOpenToProtect));
    NREQ(UN(NCryptStreamOpenToUnprotect));
    NREQ(UN(NCryptStreamOpenToUnprotectEx));
    void *d = npd_desc(L"LOCAL=user");
    if (!d) { t_skip("no descriptor"); return; }
    npd_sink s; memset(&s, 0, sizeof s);
    NPD_STREAM_INFO si = { npd_cb, &s };
    NPD_STREAM_INFO_EX sx = { npd_cb_ex, &s };
    /* 0x40 and 0x80 pass the mask; 0x20000000 is gated by a servicing feature */
    BIT_SWEEP_BEGIN(0x40u | 0x80u | 0x20000000u)
        void *hs = (void *)(ULONG_PTR)7;
        LONG rc = UN(NCryptStreamOpenToProtect)(d, f, NULL, &si, &hs);
        CHECKF(SS(rc) == NPD_NTE_BAD_FLAGS && hs == (void *)(ULONG_PTR)7, "protect flag bit %d: 0x%lx", b, (unsigned long)SS(rc));
        if (f != 0x1u) {
            hs = (void *)(ULONG_PTR)7;
            rc = UN(NCryptStreamOpenToUnprotect)(&si, f, NULL, &hs);
            CHECKF(SS(rc) == NPD_NTE_BAD_FLAGS && hs == (void *)(ULONG_PTR)7, "unprotect flag bit %d: 0x%lx", b, (unsigned long)SS(rc));
        }
        if (f != 0x1u) {
            hs = (void *)(ULONG_PTR)7;
            rc = UN(NCryptStreamOpenToUnprotectEx)(&sx, f, NULL, &hs);
            CHECKF(SS(rc) == NPD_NTE_BAD_FLAGS && hs == (void *)(ULONG_PTR)7, "unprotect-ex flag bit %d: 0x%lx", b, (unsigned long)SS(rc));
        }
    BIT_SWEEP_END
    CHECK(s.calls == 0);
    npd_desc_close(d);
}

TEST(npd_x_stream_open_flag_0x80_observed) {
    /* 0x80 passes the openers' own flag mask but has no public name: observation only */
    NREQ(UN(NCryptStreamOpenToUnprotect));
    NREQ(UN(NCryptStreamOpenToUnprotectEx));
    npd_sink s; memset(&s, 0, sizeof s);
    NPD_STREAM_INFO si = { npd_cb, &s };
    NPD_STREAM_INFO_EX sx = { npd_cb_ex, &s };
    void *hs = NULL;
    LONG rc = UN(NCryptStreamOpenToUnprotect)(&si, 0x80, NULL, &hs);
    t_note("OpenToUnprotect flags 0x80 -> 0x%lx", (unsigned long)SS(rc));
    if (rc == 0 && hs) UN(NCryptStreamClose)(hs);
    hs = NULL;
    rc = UN(NCryptStreamOpenToUnprotectEx)(&sx, 0x80, NULL, &hs);
    t_note("OpenToUnprotectEx flags 0x80 -> 0x%lx", (unsigned long)SS(rc));
    if (rc == 0 && hs) UN(NCryptStreamClose)(hs);
    hs = NULL;
    rc = UN(NCryptStreamOpenToUnprotectEx)(&sx, 0x1, NULL, &hs);
    t_note("OpenToUnprotectEx flags 0x1 -> 0x%lx", (unsigned long)SS(rc));
    if (rc == 0 && hs) UN(NCryptStreamClose)(hs);
}

/* ---- descriptor string parser corner cases --------------------------------------------------- */

TEST(npd_x_create_certificate_twice_any_case_and_connector) {
    /* the one-CERTIFICATE-per-descriptor rule is evaluated while parsing, case-insensitively, across OR clauses */
    NREQ(UN(NCryptCreateProtectionDescriptor));
    static const wchar_t *const v[] = {
        L"certificate=a OR certificate=b", L"CERTIFICATE=a OR certificate=b", L"Certificate=a AND CERTIFICATE=b",
    };
    for (size_t i = 0; i < sizeof v / sizeof *v; i++) {
        void *h = (void *)(ULONG_PTR)1;
        LONG rc = UN(NCryptCreateProtectionDescriptor)(v[i], 0, &h);
        CHECKF(SS(rc) == NPD_NTE_NOT_SUPPORTED, "\"%ls\": 0x%lx", v[i], (unsigned long)SS(rc));
        CHECKF(h == NULL, "\"%ls\": handle not cleared", v[i]);
    }
}

TEST(npd_x_create_trailing_connector_observed) {
    NREQ(UN(NCryptCreateProtectionDescriptor));
    static const wchar_t *const v[] = { L"LOCAL=user AND", L"LOCAL=user OR", L"LOCAL=user AND  ", L"LOCAL=user  " };
    for (size_t i = 0; i < sizeof v / sizeof *v; i++) {
        void *h = NULL;
        LONG rc = UN(NCryptCreateProtectionDescriptor)(v[i], 0, &h);
        t_note("\"%ls\" -> 0x%lx", v[i], (unsigned long)SS(rc));
        if (rc == 0) npd_desc_close(h);
    }
}

TEST(npd_x_create_connector_case_and_tab) {
    NREQ(UN(NCryptCreateProtectionDescriptor));
    /* only the ASCII space separates tokens, and connectors are exact upper case */
    static const wchar_t *const v[] = { L"LOCAL=user\tAND LOCAL=user", L"LOCAL=user And LOCAL=user", L"LOCAL=user Or LOCAL=user", L"LOCAL=user && LOCAL=user" };
    for (size_t i = 0; i < sizeof v / sizeof *v; i++) {
        void *h = (void *)(ULONG_PTR)1;
        LONG rc = UN(NCryptCreateProtectionDescriptor)(v[i], 0, &h);
        CHECKF(rc != 0, "\"%ls\" accepted", v[i]);
        CHECKF(h == NULL, "\"%ls\": handle not cleared", v[i]);
        t_note("\"%ls\" -> 0x%lx", v[i], (unsigned long)SS(rc));
    }
}

TEST(npd_x_create_rule_counts_exact_boundary) {
    /* nine rules in one AND group or nine OR clauses are over the limit, independent of the rule name */
    NREQ(UN(NCryptCreateProtectionDescriptor));
    wchar_t s[600]; void *h = NULL;
    s[0] = 0;
    for (int i = 0; i < 9; i++) { if (i) lstrcatW(s, L" AND "); lstrcatW(s, L"BOGUS=x"); }
    LONG rc = UN(NCryptCreateProtectionDescriptor)(s, 0, &h);
    EXPECT_SS(rc, NPD_NTE_BAD_DATA);   /* the count is enforced while parsing, before any provider is looked up */
    s[0] = 0;
    for (int i = 0; i < 9; i++) { if (i) lstrcatW(s, L" OR "); lstrcatW(s, L"BOGUS=x"); }
    rc = UN(NCryptCreateProtectionDescriptor)(s, 0, &h);
    EXPECT_SS(rc, NPD_NTE_BAD_DATA);
    CHECK(h == NULL);
}

TEST(npd_x_create_mixed_connectors_count_per_group) {
    /* 8 rules per AND group may be repeated in each OR clause: parser limit is per group */
    NREQ(UN(NCryptCreateProtectionDescriptor));
    wchar_t s[900]; void *h = NULL;
    s[0] = 0;
    for (int i = 0; i < 9; i++) { if (i) lstrcatW(s, L" AND "); lstrcatW(s, L"LOCAL=user"); }
    lstrcatW(s, L" OR LOCAL=user");
    EXPECT_SS(UN(NCryptCreateProtectionDescriptor)(s, 0, &h), NPD_NTE_BAD_DATA);
    CHECK(h == NULL);
}

TEST(npd_x_create_quote_forms) {
    NREQ(UN(NCryptCreateProtectionDescriptor));
    static const wchar_t *const bad[] = { L"LOCAL=us\"er", L"LOCAL=\"user", L"\"LOCAL\"=user", L"LOCAL=\"" };
    for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) {
        void *h = (void *)(ULONG_PTR)1;
        LONG rc = UN(NCryptCreateProtectionDescriptor)(bad[i], 0, &h);
        CHECKF(SS(rc) == NPD_NTE_BAD_DATA, "\"%ls\": 0x%lx", bad[i], (unsigned long)SS(rc));
        CHECKF(h == NULL, "\"%ls\": handle not cleared", bad[i]);
    }
}

TEST(npd_x_create_rule_name_only_spaces_before_equals) {
    NREQ(UN(NCryptCreateProtectionDescriptor));
    void *h = (void *)(ULONG_PTR)1;
    /* "=user": empty rule name */
    LONG rc = UN(NCryptCreateProtectionDescriptor)(L"=user", 0, &h);
    t_note("\"=user\" -> 0x%lx", (unsigned long)SS(rc));
    if (rc == 0) npd_desc_close(h); else CHECK(h == NULL);
}

TEST(npd_x_create_long_value_bounded) {
    /* a long (but sane) value is a parser input, not an environment failure */
    NREQ(UN(NCryptCreateProtectionDescriptor));
    wchar_t s[1100]; int i;
    lstrcpyW(s, L"LOCAL=");
    for (i = 0; i < 1000; i++) s[6 + i] = L'x';
    s[1006] = 0;
    void *h = (void *)(ULONG_PTR)1;
    LONG rc = UN(NCryptCreateProtectionDescriptor)(s, 0, &h);
    t_note("1000-character LOCAL value -> 0x%lx", (unsigned long)SS(rc));
    if (rc == 0) npd_desc_close(h); else CHECK(h == NULL);
}

TEST(npd_x_info_rejects_after_close_type_confusion) {
    /* a LOCAL protector handle is not a descriptor for the info call either */
    NREQ(UN(NCryptGetProtectionDescriptorInfo));
    NREQ(UN(NCryptOpenKeyProtector));
    void *kp = NULL;
    if (UN(NCryptOpenKeyProtector)(&kp, L"LOCAL", 0) != 0) { t_skip("no LOCAL protector"); return; }
    void *out = (void *)(ULONG_PTR)3;
    EXPECT_SS(UN(NCryptGetProtectionDescriptorInfo)(kp, NULL, 1, &out), NPD_NTE_INVALID_HANDLE);
    CHECK(out == (void *)(ULONG_PTR)3);
    UN(NCryptCloseKeyProtector)(kp);
}

TEST(npd_x_info_bad_type_with_allocator_not_called) {
    NREQ(UN(NCryptGetProtectionDescriptorInfo));
    void *d = npd_desc(L"LOCAL=user");
    if (!d) { t_skip("no descriptor"); return; }
    NPD_ALLOC_PARA ap = { sizeof ap, NULL, NULL };   /* never used for an unsupported info type */
    void *out = (void *)(ULONG_PTR)3;
    EXPECT_SS(UN(NCryptGetProtectionDescriptorInfo)(d, &ap, 2, &out), NPD_NTE_NOT_SUPPORTED);
    CHECK(out == NULL);
    npd_desc_close(d);
}

/* ---- NO_DECRYPT: only the header is examined ------------------------------------------------- */

TEST(npd_x_no_decrypt_ignores_ciphertext_damage) {
    NREQ(UN(NCryptUnprotectSecret));
    REQUIRE_WORKING();
    void *d = npd_desc(L"LOCAL=user");
    BYTE in[32]; npd_fill(in, 32, 90);
    BYTE *blob = NULL, *out = NULL; ULONG cb = 0, co = 0;
    EXPECT_SS(UN(NCryptProtectSecret)(d, 0, in, 32, NULL, NULL, &blob, &cb), 0);
    if (blob) {
        blob[cb - 1] ^= 0xff;
        void *dd = NULL;
        EXPECT_SS(UN(NCryptUnprotectSecret)(&dd, NPD_UNPROTECT_NO_DECRYPT, blob, cb, NULL, NULL, &out, &co), 0);
        CHECK(dd != NULL && out == NULL && co == 0);
        if (dd) {
            void *s = NULL;
            EXPECT_SS(UN(NCryptGetProtectionDescriptorInfo)(dd, NULL, 1, &s), 0);
            if (s) { EXPECT_WSTR((wchar_t *)s, L"LOCAL=user"); LocalFree(s); }
            UN(NCryptCloseProtectionDescriptor)(dd);
        }
        /* and a real unprotect of the same blob still fails */
        void *d2 = (void *)(ULONG_PTR)1;
        LONG rc = UN(NCryptUnprotectSecret)(&d2, 0, blob, cb, NULL, NULL, &out, &co);
        CHECK(rc != 0);
        CHECK(d2 == NULL && out == NULL && co == 0);
        LocalFree(blob);
    }
    npd_desc_close(d);
}

TEST(npd_x_no_decrypt_garbage_rejected) {
    NREQ(UN(NCryptUnprotectSecret));
    BYTE junk[16]; memset(junk, 0xff, sizeof junk);
    void *dd = (void *)(ULONG_PTR)1; BYTE *out = (BYTE *)(ULONG_PTR)1; ULONG co = 1;
    LONG rc = UN(NCryptUnprotectSecret)(&dd, NPD_UNPROTECT_NO_DECRYPT, junk, sizeof junk, NULL, NULL, &out, &co);
    CHECK(rc != 0);
    CHECK(dd == NULL && out == NULL && co == 0);
}

TEST(npd_x_no_decrypt_repeatable) {
    NREQ(UN(NCryptUnprotectSecret));
    REQUIRE_WORKING();
    void *d = npd_desc(L"LOCAL=user");
    BYTE in[16]; npd_fill(in, 16, 91);
    BYTE *blob = NULL; ULONG cb = 0;
    EXPECT_SS(UN(NCryptProtectSecret)(d, 0, in, 16, NULL, NULL, &blob, &cb), 0);
    for (int i = 0; blob && i < 3; i++) {
        void *dd = NULL; BYTE *out = NULL; ULONG co = 0;
        EXPECT_SS(UN(NCryptUnprotectSecret)(&dd, NPD_UNPROTECT_NO_DECRYPT, blob, cb, NULL, NULL, &out, &co), 0);
        if (dd) UN(NCryptCloseProtectionDescriptor)(dd);
    }
    /* the blob is untouched by header-only inspection: full unprotect works afterwards */
    BYTE *out = NULL; ULONG co = 0;
    if (blob) EXPECT_SS(UN(NCryptUnprotectSecret)(NULL, 0, blob, cb, NULL, NULL, &out, &co), 0);
    CHECK(co == 16 && out && !memcmp(out, in, 16));
    if (out) LocalFree(out);
    if (blob) LocalFree(blob);
    npd_desc_close(d);
}

/* ---- allocator failures --------------------------------------------------------------------- */

static PVOID WINAPI x_null_alloc(SIZE_T n) { return NULL; }
static void WINAPI x_free(PVOID p) { LocalFree(p); }

TEST(npd_x_unprotect_allocator_failure_leaves_outputs_clear) {
    NREQ(UN(NCryptUnprotectSecret));
    REQUIRE_WORKING();
    void *d = npd_desc(L"LOCAL=user");
    BYTE in[16]; npd_fill(in, 16, 92);
    BYTE *blob = NULL; ULONG cb = 0;
    EXPECT_SS(UN(NCryptProtectSecret)(d, 0, in, 16, NULL, NULL, &blob, &cb), 0);
    NPD_ALLOC_PARA ap = { sizeof ap, x_null_alloc, x_free };
    BYTE *out = (BYTE *)(ULONG_PTR)1; ULONG co = 5; void *dd = (void *)(ULONG_PTR)1;
    LONG rc = blob ? UN(NCryptUnprotectSecret)(&dd, 0, blob, cb, &ap, NULL, &out, &co) : -1;
    CHECK(rc != 0);
    CHECK(out == NULL && co == 0 && dd == NULL);
    t_note("unprotect with failing allocator -> 0x%lx", (unsigned long)SS(rc));
    if (blob) LocalFree(blob);
    npd_desc_close(d);
}

TEST(npd_x_protect_allocator_failure_leaves_outputs_clear) {
    NREQ(UN(NCryptProtectSecret));
    REQUIRE_WORKING();
    void *d = npd_desc(L"LOCAL=user");
    BYTE in[16]; npd_fill(in, 16, 93);
    NPD_ALLOC_PARA ap = { sizeof ap, x_null_alloc, x_free };
    BYTE *blob = (BYTE *)(ULONG_PTR)1; ULONG cb = 5;
    LONG rc = UN(NCryptProtectSecret)(d, 0, in, 16, &ap, NULL, &blob, &cb);
    CHECK(rc != 0);
    CHECK(blob == NULL && cb == 0);
    t_note("protect with failing allocator -> 0x%lx", (unsigned long)SS(rc));
    npd_desc_close(d);
}

static LONG stream_protect_simple(void *d, const BYTE *in, size_t n, npd_sink *out) {
    NPD_STREAM_INFO si = { npd_cb, out };
    void *hs = NULL;
    LONG rc = UN(NCryptStreamOpenToProtect)(d, 0, NULL, &si, &hs);
    if (rc != 0) return rc;
    rc = UN(NCryptStreamUpdate)(hs, in, n, TRUE);
    LONG rc2 = UN(NCryptStreamClose)(hs);
    return rc ? rc : rc2;
}

/* ---- stream state machine ------------------------------------------------------------------- */

TEST(npd_x_stream_failed_final_update_marks_stream_finished) {
    /* fFinal is recorded on entry: even when the final update fails, the stream accepts nothing more */
    NREQ(UN(NCryptStreamOpenToUnprotect));
    npd_sink s; memset(&s, 0, sizeof s);
    NPD_STREAM_INFO si = { npd_cb, &s };
    void *hs = NULL;
    EXPECT_SS(UN(NCryptStreamOpenToUnprotect)(&si, 0, NULL, &hs), 0);
    BYTE g[16]; memset(g, 0xff, 16);
    LONG rc = UN(NCryptStreamUpdate)(hs, g, 16, TRUE);
    CHECK(rc != 0);
    EXPECT_SS(UN(NCryptStreamUpdate)(hs, g, 16, FALSE), NPD_NTE_INVALID_HANDLE);
    EXPECT_SS(UN(NCryptStreamUpdate)(hs, g, 1, TRUE), NPD_NTE_INVALID_HANDLE);
    EXPECT_SS(UN(NCryptStreamClose)(hs), 0);
    CHECK(s.calls == 0);
}

TEST(npd_x_stream_unprotect_wrong_tag_variants) {
    /* the outer element must be a constructed SEQUENCE (0x30) */
    NREQ(UN(NCryptStreamOpenToUnprotect));
    static const BYTE tags[][8] = {
        { 0x04, 0x01, 0x05, 0, 0, 0, 0, 0 },   /* OCTET STRING */
        { 0x31, 0x01, 0x05, 0, 0, 0, 0, 0 },   /* SET */
        { 0x0C, 0x01, 0x41, 0, 0, 0, 0, 0 },   /* UTF8String */
        { 0x05, 0x00, 0, 0, 0, 0, 0, 0 },      /* NULL */
    };
    for (size_t i = 0; i < sizeof tags / sizeof *tags; i++) {
        npd_sink s; memset(&s, 0, sizeof s);
        NPD_STREAM_INFO si = { npd_cb, &s };
        void *hs = NULL;
        EXPECT_SS(UN(NCryptStreamOpenToUnprotect)(&si, 0, NULL, &hs), 0);
        LONG rc = UN(NCryptStreamUpdate)(hs, tags[i], 8, TRUE);
        CHECKF(SS(rc) == NPD_NTE_BAD_DATA, "tag 0x%02x: 0x%lx", tags[i][0], (unsigned long)SS(rc));
        CHECK(s.calls == 0);
        UN(NCryptStreamClose)(hs);
    }
}

TEST(npd_x_stream_unprotect_empty_updates) {
    NREQ(UN(NCryptStreamOpenToUnprotect));
    npd_sink s; memset(&s, 0, sizeof s);
    NPD_STREAM_INFO si = { npd_cb, &s };
    void *hs = NULL;
    EXPECT_SS(UN(NCryptStreamOpenToUnprotect)(&si, 0, NULL, &hs), 0);
    for (int i = 0; i < 5; i++) EXPECT_SS(UN(NCryptStreamUpdate)(hs, NULL, 0, FALSE), 0);
    CHECK(s.calls == 0);
    EXPECT_SS(UN(NCryptStreamClose)(hs), 0);
}

TEST(npd_x_stream_roundtrip_empty_updates_interleaved) {
    /* empty non-final updates interleaved with data do not disturb the encoding */
    NREQ(UN(NCryptStreamOpenToProtect));
    NREQ(UN(NCryptStreamOpenToUnprotect));
    REQUIRE_WORKING();
    void *d = npd_desc(L"LOCAL=user");
    npd_sink s, u; memset(&s, 0, sizeof s); memset(&u, 0, sizeof u);
    NPD_STREAM_INFO si = { npd_cb, &s };
    void *hs = NULL;
    EXPECT_SS(UN(NCryptStreamOpenToProtect)(d, 0, NULL, &si, &hs), 0);
    BYTE in[90]; npd_fill(in, 90, 94);
    for (int i = 0; hs && i < 3; i++) {
        EXPECT_SS(UN(NCryptStreamUpdate)(hs, NULL, 0, FALSE), 0);
        EXPECT_SS(UN(NCryptStreamUpdate)(hs, in + i * 30, 30, i == 2), 0);
    }
    if (hs) EXPECT_SS(UN(NCryptStreamClose)(hs), 0);
    NPD_STREAM_INFO ui = { npd_cb, &u };
    hs = NULL;
    EXPECT_SS(UN(NCryptStreamOpenToUnprotect)(&ui, 0, NULL, &hs), 0);
    if (hs) {
        EXPECT_SS(UN(NCryptStreamUpdate)(hs, s.buf, s.len, TRUE), 0);
        EXPECT_SS(UN(NCryptStreamClose)(hs), 0);
    }
    CHECK(u.len == 90 && !memcmp(u.buf, in, 90));
    npd_sink_free(&s); npd_sink_free(&u);
    npd_desc_close(d);
}

static int g_ex_calls, g_ex_desc_nonnull, g_ex_final;
static LONG WINAPI ex_probe_cb(void *ctx, const BYTE *p, SIZE_T cb, void *hdesc, BOOL fin) {
    g_ex_calls++;
    if (hdesc) g_ex_desc_nonnull++;
    if (fin) g_ex_final++;
    return npd_cb(ctx, p, cb, fin);
}

TEST(npd_x_stream_unprotect_ex_callback_shape) {
    /* the Ex callback has the descriptor handle before fFinal: final must still be reported exactly once */
    NREQ(UN(NCryptStreamOpenToProtect));
    NREQ(UN(NCryptStreamOpenToUnprotectEx));
    REQUIRE_WORKING();
    void *d = npd_desc(L"LOCAL=user");
    BYTE in[200]; npd_fill(in, 200, 95);
    npd_sink p, u; memset(&p, 0, sizeof p); memset(&u, 0, sizeof u);
    EXPECT_SS(stream_protect_simple(d, in, 200, &p), 0);
    NPD_STREAM_INFO_EX sx = { ex_probe_cb, &u };
    void *hs = NULL;
    g_ex_calls = g_ex_desc_nonnull = g_ex_final = 0;
    EXPECT_SS(UN(NCryptStreamOpenToUnprotectEx)(&sx, 0, NULL, &hs), 0);
    if (hs) {
        EXPECT_SS(UN(NCryptStreamUpdate)(hs, p.buf, p.len, TRUE), 0);
        EXPECT_SS(UN(NCryptStreamClose)(hs), 0);
    }
    CHECK(u.len == 200 && !memcmp(u.buf, in, 200));
    CHECK(g_ex_final == 1);
    t_note("Ex callback: %d calls, descriptor handle non-NULL in %d", g_ex_calls, g_ex_desc_nonnull);
    npd_sink_free(&p); npd_sink_free(&u);
    npd_desc_close(d);
}
