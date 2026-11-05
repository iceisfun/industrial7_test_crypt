#include "npd.h"
/* NCryptProtectSecret / NCryptUnprotectSecret with LOCAL descriptors */

static LONG s_alloc_calls, s_free_calls;
static PVOID WINAPI s_alloc(SIZE_T n) { s_alloc_calls++; return LocalAlloc(LPTR, n); }
static void WINAPI s_free(PVOID p) { s_free_calls++; LocalFree(p); }

/* protect then free helper: returns status, *blob/*cb set */
static LONG do_protect(void *d, DWORD fl, const BYTE *data, ULONG cb, BYTE **blob, ULONG *cbBlob) {
    *blob = NULL; *cbBlob = 0;
    return UN(NCryptProtectSecret)(d, fl, data, cb, NULL, NULL, blob, cbBlob);
}
static LONG do_unprotect(const BYTE *blob, ULONG cb, BYTE **out, ULONG *cbOut, void **desc) {
    *out = NULL; *cbOut = 0;
    return UN(NCryptUnprotectSecret)(desc, NPD_SILENT_FLAG, blob, cb, NULL, NULL, out, cbOut);
}

/* ---- Protect: argument validation ----------------------------------------- */

TEST(npd_secret_protect_null_data) {
    NREQ(UN(NCryptProtectSecret));
    void *d = npd_desc(L"LOCAL=user");
    if (!d) { t_skip("no descriptor"); return; }
    BYTE *blob = (BYTE *)(ULONG_PTR)1; ULONG cb = 77;
    LONG rc = UN(NCryptProtectSecret)(d, 0, NULL, 4, NULL, NULL, &blob, &cb);
    EXPECT_SS(rc, NPD_NTE_INVALID_PARAM);
    CHECK(blob == NULL);   /* outputs are cleared on entry */
    CHECK(cb == 0);
    npd_desc_close(d);
}

TEST(npd_secret_protect_zero_length) {
    NREQ(UN(NCryptProtectSecret));
    void *d = npd_desc(L"LOCAL=user");
    if (!d) { t_skip("no descriptor"); return; }
    BYTE one = 1, *blob = (BYTE *)(ULONG_PTR)1; ULONG cb = 77;
    EXPECT_SS(UN(NCryptProtectSecret)(d, 0, &one, 0, NULL, NULL, &blob, &cb), NPD_NTE_INVALID_PARAM);
    CHECK(blob == NULL && cb == 0);
    npd_desc_close(d);
}

TEST(npd_secret_protect_param_check_before_flags_and_handle) {
    NREQ(UN(NCryptProtectSecret));
    BYTE *blob = NULL; ULONG cb = 0;
    EXPECT_SS(UN(NCryptProtectSecret)(NULL, 0x8000, NULL, 0, NULL, NULL, &blob, &cb), NPD_NTE_INVALID_PARAM);
}

TEST(npd_secret_protect_flags_checked_before_handle) {
    NREQ(UN(NCryptProtectSecret));
    BYTE d1[4] = {1,2,3,4}, *blob = NULL; ULONG cb = 0;
    EXPECT_SS(UN(NCryptProtectSecret)(NULL, 0x2, d1, 4, NULL, NULL, &blob, &cb), NPD_NTE_BAD_FLAGS);
}

TEST(npd_secret_protect_bad_flags) {
    NREQ(UN(NCryptProtectSecret));
    void *d = npd_desc(L"LOCAL=user");
    if (!d) { t_skip("no descriptor"); return; }
    static const DWORD bad[] = { 0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x80, 0x100, 0x1000, 0x80000000u, 0xFFFFFFFFu };
    BYTE data[4] = {1,2,3,4};
    for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) {
        BYTE *blob = (BYTE *)(ULONG_PTR)1; ULONG cb = 9;
        LONG rc = UN(NCryptProtectSecret)(d, bad[i], data, 4, NULL, NULL, &blob, &cb);
        CHECKF(SS(rc) == NPD_NTE_BAD_FLAGS, "flags 0x%lx: 0x%lx", (unsigned long)bad[i], (unsigned long)SS(rc));
        CHECKF(blob == NULL && cb == 0, "flags 0x%lx: outputs not cleared", (unsigned long)bad[i]);
    }
    npd_desc_close(d);
}

TEST(npd_secret_protect_null_handle) {
    NREQ(UN(NCryptProtectSecret));
    BYTE data[4] = {1,2,3,4}, *blob = NULL; ULONG cb = 0;
    EXPECT_SS(UN(NCryptProtectSecret)(NULL, 0, data, 4, NULL, NULL, &blob, &cb), NPD_NTE_INVALID_HANDLE);
    EXPECT_SS(UN(NCryptProtectSecret)(NULL, NPD_SILENT_FLAG, data, 4, NULL, NULL, &blob, &cb), NPD_NTE_INVALID_HANDLE);
}

TEST(npd_secret_protect_wrong_handle_type) {
    NREQ(UN(NCryptProtectSecret));
    NREQ(UN(NCryptOpenKeyProtector));
    void *kp = NULL;
    if (UN(NCryptOpenKeyProtector)(&kp, L"LOCAL", 0) != 0) { t_skip("no LOCAL protector"); return; }
    BYTE data[4] = {1,2,3,4}, *blob = NULL; ULONG cb = 0;
    EXPECT_SS(UN(NCryptProtectSecret)(kp, 0, data, 4, NULL, NULL, &blob, &cb), NPD_NTE_INVALID_HANDLE);
    UN(NCryptCloseKeyProtector)(kp);
}

/* ---- Unprotect: argument validation ---------------------------------------- */

TEST(npd_secret_unprotect_null_args) {
    NREQ(UN(NCryptUnprotectSecret));
    BYTE blob[8] = {0x30, 6, 1, 2, 3, 4, 5, 6}, *out; ULONG cbo;
    /* blob, cbBlob, ppbData, pcbData all mandatory; nothing is written before they validate */
    out = (BYTE *)(ULONG_PTR)5; cbo = 5;
    EXPECT_SS(UN(NCryptUnprotectSecret)(NULL, 0, NULL, 8, NULL, NULL, &out, &cbo), NPD_NTE_INVALID_PARAM);
    CHECK(out == (BYTE *)(ULONG_PTR)5 && cbo == 5);
    EXPECT_SS(UN(NCryptUnprotectSecret)(NULL, 0, blob, 0, NULL, NULL, &out, &cbo), NPD_NTE_INVALID_PARAM);
    CHECK(out == (BYTE *)(ULONG_PTR)5 && cbo == 5);
    EXPECT_SS(UN(NCryptUnprotectSecret)(NULL, 0, blob, 8, NULL, NULL, NULL, &cbo), NPD_NTE_INVALID_PARAM);
    CHECK(cbo == 5);
    EXPECT_SS(UN(NCryptUnprotectSecret)(NULL, 0, blob, 8, NULL, NULL, &out, NULL), NPD_NTE_INVALID_PARAM);
    CHECK(out == (BYTE *)(ULONG_PTR)5);
}

TEST(npd_secret_unprotect_bad_flags) {
    NREQ(UN(NCryptUnprotectSecret));
    static const DWORD bad[] = { 0x2, 0x4, 0x8, 0x10, 0x20, 0x80, 0x100, 0x10000, 0x80000000u, 0xFFFFFFFFu };
    BYTE blob[8] = {0x30, 6, 1, 2, 3, 4, 5, 6};
    for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) {
        BYTE *out = (BYTE *)(ULONG_PTR)5; ULONG cbo = 5; void *desc = (void *)(ULONG_PTR)5;
        LONG rc = UN(NCryptUnprotectSecret)(&desc, bad[i], blob, 8, NULL, NULL, &out, &cbo);
        CHECKF(SS(rc) == NPD_NTE_BAD_FLAGS, "flags 0x%lx: 0x%lx", (unsigned long)bad[i], (unsigned long)SS(rc));
        CHECKF(out == NULL && cbo == 0 && desc == NULL, "flags 0x%lx: outputs not cleared", (unsigned long)bad[i]);
    }
}

TEST(npd_secret_unprotect_garbage_blob) {
    NREQ(UN(NCryptUnprotectSecret));
    static const BYTE junk1[] = { 0x00 };
    static const BYTE junk2[] = { 0x30, 0x00 };
    static const BYTE junk3[] = { 0x30, 0x03, 0x02, 0x01, 0x00 };
    static const BYTE junk4[] = { 0x30, 0x84, 0xff, 0xff, 0xff, 0xff, 0x01 };
    static const BYTE junk5[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    static const struct { const BYTE *p; ULONG n; } c[] = {
        { junk1, sizeof junk1 }, { junk2, sizeof junk2 }, { junk3, sizeof junk3 }, { junk4, sizeof junk4 }, { junk5, sizeof junk5 },
    };
    for (size_t i = 0; i < sizeof c / sizeof *c; i++) {
        BYTE *out = (BYTE *)(ULONG_PTR)5; ULONG cbo = 5; void *desc = (void *)(ULONG_PTR)5;
        LONG rc = UN(NCryptUnprotectSecret)(&desc, NPD_SILENT_FLAG, c[i].p, c[i].n, NULL, NULL, &out, &cbo);
        CHECKF(rc != 0, "junk %u unexpectedly succeeded", (unsigned)i);
        CHECKF(out == NULL && cbo == 0 && desc == NULL, "junk %u: outputs not cleared", (unsigned)i);
        t_note("junk blob %u -> 0x%lx", (unsigned)i, (unsigned long)SS(rc));
    }
}

TEST(npd_secret_unprotect_null_desc_pointer_ok) {
    NREQ(UN(NCryptUnprotectSecret));
    REQUIRE_WORKING();
    void *d = npd_desc(L"LOCAL=user");
    BYTE in[5] = {9,8,7,6,5}, *blob, *out; ULONG cb, co;
    EXPECT_SS(do_protect(d, 0, in, 5, &blob, &cb), 0);
    EXPECT_SS(UN(NCryptUnprotectSecret)(NULL, 0, blob, cb, NULL, NULL, &out, &co), 0);
    CHECK(co == 5 && out && !memcmp(out, in, 5));
    if (out) LocalFree(out);
    if (blob) LocalFree(blob);
    npd_desc_close(d);
}

/* ---- round trips ------------------------------------------------------------ */

static void roundtrip(const wchar_t *desc, DWORD pflags, DWORD uflags, ULONG n, unsigned seed, int note_only) {
    void *d = npd_desc(desc);
    if (!d) { t_note("%ls: cannot create", desc); return; }
    BYTE *in = (BYTE *)malloc(n), *blob = NULL, *out = NULL; ULONG cb = 0, co = 0;
    npd_fill(in, n, seed);
    LONG rc = do_protect(d, pflags, in, n, &blob, &cb);
    if (rc != 0) {
        if (note_only) t_note("%ls n=%lu protect -> 0x%lx", desc, (unsigned long)n, (unsigned long)SS(rc));
        else CHECKF(0, "%ls n=%lu protect -> 0x%lx", desc, (unsigned long)n, (unsigned long)SS(rc));
        goto out_;
    }
    CHECKF(blob != NULL && cb > n, "%ls n=%lu: blob=%p cb=%lu", desc, (unsigned long)n, blob, (unsigned long)cb);
    if (blob) {
        CHECKF(blob[0] == 0x30, "%ls: blob does not start with SEQUENCE (0x%02x)", desc, blob[0]);
        CHECKF(LocalSize(blob) >= cb, "%ls: allocation smaller than reported size", desc);
        void *d2 = NULL;
        rc = UN(NCryptUnprotectSecret)(&d2, uflags, blob, cb, NULL, NULL, &out, &co);
        if (rc != 0) {
            if (note_only) t_note("%ls n=%lu unprotect -> 0x%lx", desc, (unsigned long)n, (unsigned long)SS(rc));
            else CHECKF(0, "%ls n=%lu unprotect -> 0x%lx", desc, (unsigned long)n, (unsigned long)SS(rc));
        } else {
            CHECKF(co == n, "%ls: plaintext length %lu want %lu", desc, (unsigned long)co, (unsigned long)n);
            CHECKF(out && co == n && !memcmp(out, in, n), "%ls n=%lu: plaintext mismatch", desc, (unsigned long)n);
            CHECK(d2 != NULL);
            npd_desc_close(d2);
        }
    }
out_:
    if (out) LocalFree(out);
    if (blob) LocalFree(blob);
    free(in);
    npd_desc_close(d);
}

TEST(npd_secret_roundtrip_sizes) {
    NREQ(UN(NCryptProtectSecret));
    REQUIRE_WORKING();
    static const ULONG sizes[] = { 1, 2, 3, 7, 8, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 255, 256, 257, 1000, 4095, 4096, 4097, 65535, 65536 };
    for (size_t i = 0; i < sizeof sizes / sizeof *sizes; i++) roundtrip(L"LOCAL=user", NPD_SILENT_FLAG, NPD_SILENT_FLAG, sizes[i], (unsigned)i + 1, 0);
}

TEST(npd_secret_roundtrip_one_mebibyte) {
    NREQ(UN(NCryptProtectSecret));
    REQUIRE_WORKING();
    roundtrip(L"LOCAL=user", 0, 0, 1 << 20, 99, 0);
}

TEST(npd_secret_roundtrip_flags_combinations) {
    NREQ(UN(NCryptProtectSecret));
    REQUIRE_WORKING();
    static const DWORD f[] = { 0, NPD_SILENT_FLAG };
    for (int p = 0; p < 2; p++) for (int u = 0; u < 2; u++) roundtrip(L"LOCAL=user", f[p], f[u], 100, 7, 0);
}

TEST(npd_secret_roundtrip_all_zero_and_all_ff) {
    NREQ(UN(NCryptProtectSecret));
    REQUIRE_WORKING();
    void *d = npd_desc(L"LOCAL=user");
    BYTE z[64], ff[64]; memset(z, 0, 64); memset(ff, 0xff, 64);
    const BYTE *v[2] = { z, ff };
    for (int i = 0; i < 2; i++) {
        BYTE *blob, *out; ULONG cb, co;
        EXPECT_SS(do_protect(d, 0, v[i], 64, &blob, &cb), 0);
        EXPECT_SS(do_unprotect(blob, cb, &out, &co, NULL), 0);
        CHECK(co == 64 && out && !memcmp(out, v[i], 64));
        if (out) LocalFree(out);
        if (blob) LocalFree(blob);
    }
    npd_desc_close(d);
}

TEST(npd_secret_roundtrip_machine_logon_observed) {
    NREQ(UN(NCryptProtectSecret));
    REQUIRE_WORKING();
    roundtrip(L"LOCAL=machine", NPD_SILENT_FLAG, NPD_SILENT_FLAG, 48, 3, 1);
    roundtrip(L"LOCAL=logon", NPD_SILENT_FLAG, NPD_SILENT_FLAG, 48, 4, 1);
}

TEST(npd_secret_roundtrip_compound_observed) {
    NREQ(UN(NCryptProtectSecret));
    REQUIRE_WORKING();
    roundtrip(L"LOCAL=user OR LOCAL=machine", NPD_SILENT_FLAG, NPD_SILENT_FLAG, 48, 5, 1);
    roundtrip(L"LOCAL=user AND LOCAL=machine", NPD_SILENT_FLAG, NPD_SILENT_FLAG, 48, 6, 1);
}

TEST(npd_secret_roundtrip_via_second_descriptor_handle) {
    /* the protecting descriptor object is not needed to unprotect: the blob carries the rule */
    NREQ(UN(NCryptProtectSecret));
    REQUIRE_WORKING();
    void *d = npd_desc(L"LOCAL=user");
    BYTE in[20]; npd_fill(in, 20, 11);
    BYTE *blob, *out; ULONG cb, co;
    EXPECT_SS(do_protect(d, 0, in, 20, &blob, &cb), 0);
    npd_desc_close(d);   /* closed before unprotect */
    EXPECT_SS(do_unprotect(blob, cb, &out, &co, NULL), 0);
    CHECK(co == 20 && out && !memcmp(out, in, 20));
    if (out) LocalFree(out);
    if (blob) LocalFree(blob);
}

TEST(npd_secret_descriptor_reuse) {
    NREQ(UN(NCryptProtectSecret));
    REQUIRE_WORKING();
    void *d = npd_desc(L"LOCAL=user");
    for (int i = 0; i < 5; i++) {
        BYTE in[10]; npd_fill(in, 10, 100 + i);
        BYTE *blob, *out; ULONG cb, co;
        EXPECT_SS(do_protect(d, 0, in, 10, &blob, &cb), 0);
        EXPECT_SS(do_unprotect(blob, cb, &out, &co, NULL), 0);
        CHECK(co == 10 && out && !memcmp(out, in, 10));
        if (out) LocalFree(out);
        if (blob) LocalFree(blob);
    }
    npd_desc_close(d);
}

/* ---- blob structure ---------------------------------------------------------- */

TEST(npd_secret_blob_is_randomized) {
    NREQ(UN(NCryptProtectSecret));
    REQUIRE_WORKING();
    void *d = npd_desc(L"LOCAL=user");
    BYTE in[32]; npd_fill(in, 32, 5);
    BYTE *a, *b; ULONG ca, cb;
    EXPECT_SS(do_protect(d, 0, in, 32, &a, &ca), 0);
    EXPECT_SS(do_protect(d, 0, in, 32, &b, &cb), 0);
    CHECK(a && b && ca == cb);
    if (a && b && ca == cb) CHECK(memcmp(a, b, ca) != 0);   /* fresh random CEK each time */
    if (a) LocalFree(a);
    if (b) LocalFree(b);
    npd_desc_close(d);
}

TEST(npd_secret_blob_does_not_contain_plaintext) {
    NREQ(UN(NCryptProtectSecret));
    REQUIRE_WORKING();
    void *d = npd_desc(L"LOCAL=user");
    BYTE in[64]; for (int i = 0; i < 64; i++) in[i] = 0xA5;
    BYTE *blob; ULONG cb;
    EXPECT_SS(do_protect(d, 0, in, 64, &blob, &cb), 0);
    int found = 0;
    for (ULONG i = 0; blob && i + 16 <= cb; i++) if (!memcmp(blob + i, in, 16)) found = 1;
    CHECK(!found);
    if (blob) LocalFree(blob);
    npd_desc_close(d);
}

TEST(npd_secret_blob_der_length_observed) {
    NREQ(UN(NCryptProtectSecret));
    REQUIRE_WORKING();
    void *d = npd_desc(L"LOCAL=user");
    BYTE in[50]; npd_fill(in, 50, 8);
    BYTE *blob; ULONG cb;
    EXPECT_SS(do_protect(d, 0, in, 50, &blob, &cb), 0);
    if (blob) {
        CHECK(blob[0] == 0x30);
        long tot = npd_der_total(blob, cb);
        t_note("blob cb=%lu header-declared total=%ld", (unsigned long)cb, tot);
        /* contains the CMS enveloped-data OID 1.2.840.113549.1.7.3 ? */
        static const BYTE oid[] = { 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x03 };
        int has = 0;
        for (ULONG i = 0; i + sizeof oid <= cb; i++) if (!memcmp(blob + i, oid, sizeof oid)) has = 1;
        t_note("blob contains envelopedData OID: %d", has);
        LocalFree(blob);
    }
    npd_desc_close(d);
}

TEST(npd_secret_blob_size_growth_observed) {
    NREQ(UN(NCryptProtectSecret));
    REQUIRE_WORKING();
    void *d = npd_desc(L"LOCAL=user");
    static const ULONG sizes[] = { 1, 16, 100, 255, 256, 1000, 70000 };
    ULONG prev = 0;
    for (size_t i = 0; i < sizeof sizes / sizeof *sizes; i++) {
        BYTE *in = (BYTE *)calloc(1, sizes[i]), *blob; ULONG cb;
        EXPECT_SS(do_protect(d, 0, in, sizes[i], &blob, &cb), 0);
        t_note("plain=%lu protected=%lu overhead=%ld", (unsigned long)sizes[i], (unsigned long)cb, (long)cb - (long)sizes[i]);
        CHECK(cb > sizes[i]);
        CHECK(cb >= prev);
        prev = cb;
        if (blob) LocalFree(blob);
        free(in);
    }
    npd_desc_close(d);
}

/* ---- tamper detection ---------------------------------------------------------- */

TEST(npd_secret_tamper_last_byte) {
    NREQ(UN(NCryptUnprotectSecret));
    REQUIRE_WORKING();
    void *d = npd_desc(L"LOCAL=user");
    BYTE in[40]; npd_fill(in, 40, 21);
    BYTE *blob, *out; ULONG cb, co;
    EXPECT_SS(do_protect(d, 0, in, 40, &blob, &cb), 0);
    if (blob) {
        blob[cb - 1] ^= 0x01;
        LONG rc = do_unprotect(blob, cb, &out, &co, NULL);
        CHECK(rc != 0);
        CHECK(out == NULL && co == 0);
        t_note("flipped last byte -> 0x%lx", (unsigned long)SS(rc));
        if (out) LocalFree(out);
        LocalFree(blob);
    }
    npd_desc_close(d);
}

TEST(npd_secret_tamper_every_tail_byte) {
    NREQ(UN(NCryptUnprotectSecret));
    REQUIRE_WORKING();
    void *d = npd_desc(L"LOCAL=user");
    BYTE in[40]; npd_fill(in, 40, 22);
    BYTE *blob, *out; ULONG cb, co;
    EXPECT_SS(do_protect(d, 0, in, 40, &blob, &cb), 0);
    if (blob) {
        /* the trailing region is ciphertext+tag: no single bit flip may yield the original plaintext */
        for (ULONG k = 1; k <= 56 && k < cb; k++) {
            blob[cb - k] ^= 0x80;
            LONG rc = do_unprotect(blob, cb, &out, &co, NULL);
            CHECKF(!(rc == 0 && out && co == 40 && !memcmp(out, in, 40)), "flip of byte -%lu still yields the original plaintext", (unsigned long)k);
            if (rc != 0) CHECKF(out == NULL && co == 0, "flip of byte -%lu: outputs not cleared", (unsigned long)k);
            if (out) { LocalFree(out); }
            blob[cb - k] ^= 0x80;
        }
        EXPECT_SS(do_unprotect(blob, cb, &out, &co, NULL), 0);   /* restored blob still good */
        if (out) LocalFree(out);
        LocalFree(blob);
    }
    npd_desc_close(d);
}

TEST(npd_secret_truncated_blob) {
    NREQ(UN(NCryptUnprotectSecret));
    REQUIRE_WORKING();
    void *d = npd_desc(L"LOCAL=user");
    BYTE in[40]; npd_fill(in, 40, 23);
    BYTE *blob, *out; ULONG cb, co;
    EXPECT_SS(do_protect(d, 0, in, 40, &blob, &cb), 0);
    if (blob) {
        ULONG cuts[] = { cb - 1, cb - 2, cb - 16, cb / 2, 16, 4, 2, 1 };
        for (size_t i = 0; i < sizeof cuts / sizeof *cuts; i++) {
            void *dd = (void *)(ULONG_PTR)5;
            LONG rc = UN(NCryptUnprotectSecret)(&dd, 0, blob, cuts[i], NULL, NULL, &out, &co);
            CHECKF(rc != 0, "truncation to %lu accepted", (unsigned long)cuts[i]);
            CHECKF(dd == NULL, "truncation to %lu: descriptor not cleared", (unsigned long)cuts[i]);
            if (rc == 0 && out) LocalFree(out);
        }
        LocalFree(blob);
    }
    npd_desc_close(d);
}

TEST(npd_secret_trailing_garbage_observed) {
    NREQ(UN(NCryptUnprotectSecret));
    REQUIRE_WORKING();
    void *d = npd_desc(L"LOCAL=user");
    BYTE in[40]; npd_fill(in, 40, 24);
    BYTE *blob, *out; ULONG cb, co;
    EXPECT_SS(do_protect(d, 0, in, 40, &blob, &cb), 0);
    if (blob) {
        BYTE *big = (BYTE *)malloc(cb + 8);
        memcpy(big, blob, cb); memset(big + cb, 0xEE, 8);
        LONG rc = do_unprotect(big, cb + 8, &out, &co, NULL);
        t_note("blob + 8 trailing bytes -> 0x%lx", (unsigned long)SS(rc));
        if (out) LocalFree(out);
        free(big); LocalFree(blob);
    }
    npd_desc_close(d);
}

/* ---- NCRYPT_UNPROTECT_NO_DECRYPT ------------------------------------------------ */

TEST(npd_secret_unprotect_no_decrypt) {
    NREQ(UN(NCryptUnprotectSecret));
    REQUIRE_WORKING();
    void *d = npd_desc(L"LOCAL=user");
    BYTE in[24]; npd_fill(in, 24, 31);
    BYTE *blob, *out = (BYTE *)(ULONG_PTR)5; ULONG cb, co = 5;
    EXPECT_SS(do_protect(d, 0, in, 24, &blob, &cb), 0);
    void *dd = NULL;
    LONG rc = UN(NCryptUnprotectSecret)(&dd, NPD_UNPROTECT_NO_DECRYPT, blob, cb, NULL, NULL, &out, &co);
    EXPECT_SS(rc, 0);
    CHECK(dd != NULL);
    CHECK(out == NULL && co == 0);   /* nothing decrypted */
    if (dd) {
        void *s = NULL;
        EXPECT_SS(UN(NCryptGetProtectionDescriptorInfo)(dd, NULL, 1, &s), 0);
        if (s) { EXPECT_WSTR((wchar_t *)s, L"LOCAL=user"); LocalFree(s); }
        EXPECT_SS(UN(NCryptCloseProtectionDescriptor)(dd), 0);
    }
    if (blob) LocalFree(blob);
    npd_desc_close(d);
}

TEST(npd_secret_unprotect_returned_descriptor_info) {
    NREQ(UN(NCryptUnprotectSecret));
    REQUIRE_WORKING();
    static const wchar_t *const rules[] = { L"LOCAL=user", L"LOCAL=machine", L"LOCAL=logon" };
    for (size_t i = 0; i < 3; i++) {
        void *d = npd_desc(rules[i]);
        BYTE in[8] = {1,2,3,4,5,6,7,8};
        BYTE *blob, *out; ULONG cb, co;
        if (do_protect(d, NPD_SILENT_FLAG, in, 8, &blob, &cb) != 0) { t_note("%ls: protect failed", rules[i]); npd_desc_close(d); continue; }
        void *dd = NULL;
        if (UN(NCryptUnprotectSecret)(&dd, NPD_UNPROTECT_NO_DECRYPT | NPD_SILENT_FLAG, blob, cb, NULL, NULL, &out, &co) == 0 && dd) {
            void *s = NULL;
            if (UN(NCryptGetProtectionDescriptorInfo)(dd, NULL, 1, &s) == 0 && s) {
                t_note("%ls recovered as \"%ls\"", rules[i], (wchar_t *)s);
                CHECK(!lstrcmpW((wchar_t *)s, rules[i]));
                LocalFree(s);
            }
            UN(NCryptCloseProtectionDescriptor)(dd);
        }
        LocalFree(blob);
        npd_desc_close(d);
    }
}

/* ---- allocator ------------------------------------------------------------------ */

TEST(npd_secret_custom_allocator) {
    NREQ(UN(NCryptProtectSecret));
    REQUIRE_WORKING();
    void *d = npd_desc(L"LOCAL=user");
    NPD_ALLOC_PARA ap = { sizeof ap, s_alloc, s_free };
    BYTE in[30]; npd_fill(in, 30, 41);
    BYTE *blob = NULL, *out = NULL; ULONG cb = 0, co = 0;
    s_alloc_calls = s_free_calls = 0;
    EXPECT_SS(UN(NCryptProtectSecret)(d, 0, in, 30, &ap, NULL, &blob, &cb), 0);
    CHECK(s_alloc_calls >= 1);
    LONG a1 = s_alloc_calls;
    EXPECT_SS(UN(NCryptUnprotectSecret)(NULL, 0, blob, cb, &ap, NULL, &out, &co), 0);
    CHECK(s_alloc_calls > a1);
    CHECK(co == 30 && out && !memcmp(out, in, 30));
    if (out) s_free(out);
    if (blob) s_free(blob);
    npd_desc_close(d);
}

TEST(npd_secret_default_allocator_is_localalloc) {
    NREQ(UN(NCryptProtectSecret));
    REQUIRE_WORKING();
    void *d = npd_desc(L"LOCAL=user");
    BYTE in[30]; npd_fill(in, 30, 42);
    BYTE *blob, *out; ULONG cb, co;
    EXPECT_SS(do_protect(d, 0, in, 30, &blob, &cb), 0);
    EXPECT_SS(do_unprotect(blob, cb, &out, &co, NULL), 0);
    /* LocalSize succeeds only for LocalAlloc'd (movable or fixed) memory */
    CHECK(blob && LocalSize(blob) >= cb);
    CHECK(out && LocalSize(out) >= co);
    CHECK(LocalFree(blob) == NULL);
    CHECK(LocalFree(out) == NULL);
    npd_desc_close(d);
}

/* ---- different process / thread ---------------------------------------------------- */

typedef struct { BYTE *blob; ULONG cb; LONG rc; ULONG co; BYTE out[64]; } thr_arg;
static DWORD WINAPI unprot_thread(void *p) {
    thr_arg *a = (thr_arg *)p; BYTE *o = NULL; ULONG co = 0;
    a->rc = UN(NCryptUnprotectSecret)(NULL, NPD_SILENT_FLAG, a->blob, a->cb, NULL, NULL, &o, &co);
    if (a->rc == 0 && o) { a->co = co; memcpy(a->out, o, co < 64 ? co : 64); LocalFree(o); }
    return 0;
}

TEST(npd_secret_unprotect_on_other_thread) {
    NREQ(UN(NCryptUnprotectSecret));
    REQUIRE_WORKING();
    void *d = npd_desc(L"LOCAL=user");
    BYTE in[40]; npd_fill(in, 40, 51);
    thr_arg a; memset(&a, 0, sizeof a);
    EXPECT_SS(do_protect(d, 0, in, 40, &a.blob, &a.cb), 0);
    HANDLE th = CreateThread(NULL, 0, unprot_thread, &a, 0, NULL);
    CHECK(th != NULL);
    if (th) { CHECK(WaitForSingleObject(th, 20000) == WAIT_OBJECT_0); CloseHandle(th); }
    EXPECT_SS(a.rc, 0);
    CHECK(a.co == 40 && !memcmp(a.out, in, 40));
    if (a.blob) LocalFree(a.blob);
    npd_desc_close(d);
}

CHILD(npd_unprotect_file) {
    /* argv[1] = blob file, argv[2] = expected plaintext file; exit 0 on match */
    if (argc < 3 || !UN(NCryptUnprotectSecret)) return 90;
    HANDLE hb = CreateFileA(argv[1], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    HANDLE hp = CreateFileA(argv[2], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hb == INVALID_HANDLE_VALUE || hp == INVALID_HANDLE_VALUE) return 91;
    BYTE blob[4096], pl[512]; DWORD nb = 0, np = 0;
    ReadFile(hb, blob, sizeof blob, &nb, NULL); ReadFile(hp, pl, sizeof pl, &np, NULL);
    CloseHandle(hb); CloseHandle(hp);
    BYTE *out = NULL; ULONG co = 0;
    LONG rc = UN(NCryptUnprotectSecret)(NULL, NPD_SILENT_FLAG, blob, nb, NULL, NULL, &out, &co);
    if (rc != 0) return 92;
    int ok = (co == np && out && !memcmp(out, pl, np));
    if (out) LocalFree(out);
    return ok ? 0 : 93;
}

static void write_file(const char *path, const BYTE *p, DWORD n) {
    HANDLE h = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (h != INVALID_HANDLE_VALUE) { DWORD w; WriteFile(h, p, n, &w, NULL); CloseHandle(h); }
}

TEST(npd_secret_unprotect_in_other_process) {
    NREQ(UN(NCryptProtectSecret));
    REQUIRE_WORKING();
    void *d = npd_desc(L"LOCAL=user");
    BYTE in[100]; npd_fill(in, 100, 61);
    BYTE *blob; ULONG cb;
    EXPECT_SS(do_protect(d, 0, in, 100, &blob, &cb), 0);
    char fb[MAX_PATH], fp[MAX_PATH], args[2 * MAX_PATH + 8];
    t_tmpfile(fb, sizeof fb, "npd_blob.bin"); t_tmpfile(fp, sizeof fp, "npd_plain.bin");
    write_file(fb, blob, cb); write_file(fp, in, 100);
    snprintf(args, sizeof args, "\"%s\" \"%s\"", fb, fp);
    DWORD rc = t_run_child("npd_unprotect_file", args, 30000);
    EXPECT_EQ(rc, 0);
    DeleteFileA(fb); DeleteFileA(fp);
    if (blob) LocalFree(blob);
    npd_desc_close(d);
}
