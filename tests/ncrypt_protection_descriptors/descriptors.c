#include "npd.h"
/* NCryptCreateProtectionDescriptor / NCryptCloseProtectionDescriptor / NCryptGetProtectionDescriptorInfo */

static void free_info(void *p) { if (p) LocalFree(p); }

TEST(npd_exports_resolve) {
    CHECK(t_proc_in("ncrypt.dll", "NCryptCreateProtectionDescriptor") != NULL);
    CHECK(t_proc_in("ncrypt.dll", "NCryptCloseProtectionDescriptor") != NULL);
    CHECK(t_proc_in("ncrypt.dll", "NCryptGetProtectionDescriptorInfo") != NULL);
    CHECK(t_proc_in("ncrypt.dll", "NCryptRegisterProtectionDescriptorName") != NULL);
    CHECK(t_proc_in("ncrypt.dll", "NCryptQueryProtectionDescriptorName") != NULL);
    CHECK(t_proc_in("ncrypt.dll", "NCryptProtectSecret") != NULL);
    CHECK(t_proc_in("ncrypt.dll", "NCryptUnprotectSecret") != NULL);
    CHECK(t_proc_in("ncrypt.dll", "NCryptStreamOpenToProtect") != NULL);
    CHECK(t_proc_in("ncrypt.dll", "NCryptStreamOpenToUnprotect") != NULL);
    CHECK(t_proc_in("ncrypt.dll", "NCryptStreamOpenToUnprotectEx") != NULL);
    CHECK(t_proc_in("ncrypt.dll", "NCryptStreamUpdate") != NULL);
    CHECK(t_proc_in("ncrypt.dll", "NCryptStreamClose") != NULL);
    CHECK(t_proc_in("ncrypt.dll", "NCryptProtectKey") != NULL);
    CHECK(t_proc_in("ncrypt.dll", "NCryptUnprotectKey") != NULL);
    CHECK(t_proc_in("ncrypt.dll", "NCryptOpenKeyProtector") != NULL);
    CHECK(t_proc_in("ncrypt.dll", "NCryptCloseKeyProtector") != NULL);
    CHECK(t_proc_in("ncrypt.dll", "NCryptDuplicateKeyProtectorHandle") != NULL);
    CHECK(t_proc_in("ncrypt.dll", "NCryptCreateClaim") != NULL);
    CHECK(t_proc_in("ncrypt.dll", "NCryptVerifyClaim") != NULL);
}

/* ---- argument validation ------------------------------------------------ */

TEST(npd_create_null_phandle) {
    NREQ(UN(NCryptCreateProtectionDescriptor));
    LONG rc = UN(NCryptCreateProtectionDescriptor)(L"LOCAL=user", 0, NULL);
    EXPECT_SS(rc, NPD_NTE_INVALID_PARAM);
}

TEST(npd_create_null_phandle_wins_over_flags) {
    NREQ(UN(NCryptCreateProtectionDescriptor));
    LONG rc = UN(NCryptCreateProtectionDescriptor)(NULL, 0x8000, NULL);
    EXPECT_SS(rc, NPD_NTE_INVALID_PARAM);
}

TEST(npd_create_null_string) {
    NREQ(UN(NCryptCreateProtectionDescriptor));
    void *h = (void *)(ULONG_PTR)0x1234;
    LONG rc = UN(NCryptCreateProtectionDescriptor)(NULL, 0, &h);
    EXPECT_SS(rc, NPD_NTE_INVALID_PARAM);
    CHECK(h == NULL);   /* output cleared before the string is validated */
}

TEST(npd_create_empty_string) {
    NREQ(UN(NCryptCreateProtectionDescriptor));
    void *h = (void *)(ULONG_PTR)0x1234;
    LONG rc = UN(NCryptCreateProtectionDescriptor)(L"", 0, &h);
    EXPECT_SS(rc, NPD_NTE_INVALID_PARAM);
    CHECK(h == NULL);
}

TEST(npd_create_string_checked_before_flags) {
    NREQ(UN(NCryptCreateProtectionDescriptor));
    void *h = NULL;
    EXPECT_SS(UN(NCryptCreateProtectionDescriptor)(NULL, 0x100, &h), NPD_NTE_INVALID_PARAM);
    EXPECT_SS(UN(NCryptCreateProtectionDescriptor)(L"", 0x100, &h), NPD_NTE_INVALID_PARAM);
}

TEST(npd_create_bad_flags) {
    NREQ(UN(NCryptCreateProtectionDescriptor));
    static const DWORD bad[] = { 0x2, 0x4, 0x8, 0x10, 0x40, 0x80, 0x100, 0x8000, 0x10000, 0x80000000u, 0xFFFFFFFFu, 0xFFFFFFDEu };
    for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) {
        void *h = (void *)(ULONG_PTR)0x1;
        LONG rc = UN(NCryptCreateProtectionDescriptor)(L"LOCAL=user", bad[i], &h);
        CHECKF(SS(rc) == NPD_NTE_BAD_FLAGS, "flags 0x%lx: got 0x%lx", (unsigned long)bad[i], (unsigned long)SS(rc));
        CHECKF(h == NULL, "flags 0x%lx: handle not cleared", (unsigned long)bad[i]);
    }
}

TEST(npd_create_silent_flag_is_bad_for_create) {
    /* NCRYPT_SILENT_FLAG (0x40) is accepted by the protect/unprotect calls but not here */
    NREQ(UN(NCryptCreateProtectionDescriptor));
    void *h = NULL;
    EXPECT_SS(UN(NCryptCreateProtectionDescriptor)(L"LOCAL=user", NPD_SILENT_FLAG, &h), NPD_NTE_BAD_FLAGS);
}

TEST(npd_create_machine_flag_accepted) {
    NREQ(UN(NCryptCreateProtectionDescriptor));
    void *h = NULL;
    LONG rc = UN(NCryptCreateProtectionDescriptor)(L"LOCAL=user", NPD_MACHINE_FLAG, &h);
    EXPECT_SS(rc, 0);
    CHECK(h != NULL);
    npd_desc_close(h);
}

/* ---- basic creation of the always-available LOCAL rules ------------------- */

static const wchar_t *const local_rules[] = {
    L"LOCAL=user", L"LOCAL=machine", L"LOCAL=logon",
};

TEST(npd_create_local_rules) {
    NREQ(UN(NCryptCreateProtectionDescriptor));
    for (size_t i = 0; i < sizeof local_rules / sizeof *local_rules; i++) {
        void *h = NULL;
        LONG rc = UN(NCryptCreateProtectionDescriptor)(local_rules[i], 0, &h);
        CHECKF(rc == 0, "%ls -> 0x%lx", local_rules[i], (unsigned long)SS(rc));
        CHECKF(h != NULL, "%ls: NULL handle", local_rules[i]);
        npd_desc_close(h);
    }
}

TEST(npd_create_returns_distinct_handles) {
    NREQ(UN(NCryptCreateProtectionDescriptor));
    void *a = NULL, *b = NULL;
    EXPECT_SS(UN(NCryptCreateProtectionDescriptor)(L"LOCAL=user", 0, &a), 0);
    EXPECT_SS(UN(NCryptCreateProtectionDescriptor)(L"LOCAL=user", 0, &b), 0);
    CHECK(a != NULL && b != NULL && a != b);
    npd_desc_close(a); npd_desc_close(b);
}

TEST(npd_create_many_handles_independent) {
    NREQ(UN(NCryptCreateProtectionDescriptor));
    void *h[16] = {0};
    for (int i = 0; i < 16; i++) EXPECT_SS(UN(NCryptCreateProtectionDescriptor)(L"LOCAL=user", 0, &h[i]), 0);
    for (int i = 15; i >= 0; i--) EXPECT_SS(UN(NCryptCloseProtectionDescriptor)(h[i]), 0);
}

TEST(npd_create_whitespace_tolerated_around_tokens) {
    /* parser skips leading spaces before the rule name and value */
    NREQ(UN(NCryptCreateProtectionDescriptor));
    static const wchar_t *const v[] = { L" LOCAL=user", L"  LOCAL=user", L"LOCAL= user", L"LOCAL =user", L"LOCAL = user", L"LOCAL=user " };
    for (size_t i = 0; i < sizeof v / sizeof *v; i++) {
        void *h = NULL;
        LONG rc = UN(NCryptCreateProtectionDescriptor)(v[i], 0, &h);
        CHECKF(rc == 0, "\"%ls\" -> 0x%lx", v[i], (unsigned long)SS(rc));
        npd_desc_close(h);
    }
}

TEST(npd_create_quoted_value) {
    NREQ(UN(NCryptCreateProtectionDescriptor));
    void *h = NULL;
    LONG rc = UN(NCryptCreateProtectionDescriptor)(L"LOCAL=\"user\"", 0, &h);
    if (rc != 0) t_note("quoted value rejected 0x%lx", (unsigned long)SS(rc));
    CHECK(rc == 0);
    npd_desc_close(h);
}

TEST(npd_create_case_of_rule_name) {
    NREQ(UN(NCryptCreateProtectionDescriptor));
    void *h = NULL;
    LONG rc = UN(NCryptCreateProtectionDescriptor)(L"local=user", 0, &h);
    t_note("lower-case rule name -> 0x%lx", (unsigned long)SS(rc));
    npd_desc_close(h);
}

TEST(npd_create_value_not_validated_at_create) {
    /* creation only opens the key-protector provider named by the rule; the value is judged when protecting */
    NREQ(UN(NCryptCreateProtectionDescriptor));
    void *h = NULL;
    LONG rc = UN(NCryptCreateProtectionDescriptor)(L"LOCAL=bogusvalue", 0, &h);
    t_note("LOCAL=bogusvalue -> 0x%lx", (unsigned long)SS(rc));
    if (rc == 0) npd_desc_close(h);
}

/* ---- parser errors (decomp-verified) -------------------------------------- */

typedef struct { const wchar_t *s; DWORD want; } parse_case;

TEST(npd_create_parse_errors_bad_data) {
    NREQ(UN(NCryptCreateProtectionDescriptor));
    static const parse_case c[] = {
        { L"   ", NPD_NTE_BAD_DATA },                        /* only blanks: no rule name */
        { L"LOCAL", NPD_NTE_BAD_DATA },                      /* no '=' and no value */
        { L"LOCAL=", NPD_NTE_BAD_DATA },                     /* empty value */
        { L"LOCAL= ", NPD_NTE_BAD_DATA },
        { L"LOCAL=user BOGUS", NPD_NTE_BAD_DATA },           /* connector is neither AND nor OR */
        { L"LOCAL=user and LOCAL=user", NPD_NTE_BAD_DATA },  /* connector comparison is case sensitive */
        { L"LOCAL=user or LOCAL=user", NPD_NTE_BAD_DATA },
        { L"LOCAL=\"user", NPD_NTE_BAD_DATA },               /* unterminated quote */
        { L"LO\"CAL=user", NPD_NTE_BAD_DATA },               /* quote inside a rule name */
        { L"LOCAL=user LOCAL=user", NPD_NTE_BAD_DATA },      /* missing connector */
    };
    for (size_t i = 0; i < sizeof c / sizeof *c; i++) {
        void *h = (void *)(ULONG_PTR)1;
        LONG rc = UN(NCryptCreateProtectionDescriptor)(c[i].s, 0, &h);
        CHECKF(SS(rc) == c[i].want, "\"%ls\": got 0x%lx want 0x%lx", c[i].s, (unsigned long)SS(rc), (unsigned long)c[i].want);
        if (rc != 0) CHECKF(h == NULL, "\"%ls\": handle not cleared", c[i].s);
        if (rc == 0) npd_desc_close(h);
    }
}

TEST(npd_create_unknown_provider_fails) {
    NREQ(UN(NCryptCreateProtectionDescriptor));
    void *h = (void *)(ULONG_PTR)1;
    LONG rc = UN(NCryptCreateProtectionDescriptor)(L"CRYPTTNOSUCHRULE=x", 0, &h);
    CHECK(rc != 0);
    CHECK(h == NULL);
    t_note("unknown rule name -> 0x%lx", (unsigned long)SS(rc));
}

TEST(npd_create_certificate_twice_not_supported) {
    /* a descriptor may carry CERTIFICATE only once; the check precedes provider loading */
    NREQ(UN(NCryptCreateProtectionDescriptor));
    void *h = NULL;
    LONG rc = UN(NCryptCreateProtectionDescriptor)(L"CERTIFICATE=HashId:0000000000000000000000000000000000000000 AND CERTIFICATE=HashId:0000000000000000000000000000000000000001", 0, &h);
    EXPECT_SS(rc, NPD_NTE_NOT_SUPPORTED);
    CHECK(h == NULL);
    rc = UN(NCryptCreateProtectionDescriptor)(L"certificate=a OR certificate=b", 0, &h);
    t_note("certificate twice across OR -> 0x%lx", (unsigned long)SS(rc));
    if (rc == 0) npd_desc_close(h);
}

static void build_chain(wchar_t *out, size_t cap, int n, const wchar_t *conn) {
    out[0] = 0;
    for (int i = 0; i < n; i++) {
        if (i) { lstrcatW(out, L" "); lstrcatW(out, conn); lstrcatW(out, L" "); }
        lstrcatW(out, L"LOCAL=user");
    }
}

TEST(npd_create_nine_and_rules_rejected) {
    NREQ(UN(NCryptCreateProtectionDescriptor));
    wchar_t s[512]; void *h = NULL;
    build_chain(s, 512, 9, L"AND");
    EXPECT_SS(UN(NCryptCreateProtectionDescriptor)(s, 0, &h), NPD_NTE_BAD_DATA);
    CHECK(h == NULL);
}

TEST(npd_create_eight_and_rules_parse) {
    NREQ(UN(NCryptCreateProtectionDescriptor));
    wchar_t s[512]; void *h = NULL;
    build_chain(s, 512, 8, L"AND");
    LONG rc = UN(NCryptCreateProtectionDescriptor)(s, 0, &h);
    t_note("8 AND-ed rules -> 0x%lx", (unsigned long)SS(rc));
    if (rc == 0) npd_desc_close(h);
}

TEST(npd_create_nine_or_clauses_rejected) {
    NREQ(UN(NCryptCreateProtectionDescriptor));
    wchar_t s[512]; void *h = NULL;
    build_chain(s, 512, 9, L"OR");
    EXPECT_SS(UN(NCryptCreateProtectionDescriptor)(s, 0, &h), NPD_NTE_BAD_DATA);
    CHECK(h == NULL);
}

TEST(npd_create_eight_or_clauses_parse) {
    NREQ(UN(NCryptCreateProtectionDescriptor));
    wchar_t s[512]; void *h = NULL;
    build_chain(s, 512, 8, L"OR");
    LONG rc = UN(NCryptCreateProtectionDescriptor)(s, 0, &h);
    t_note("8 OR-ed clauses -> 0x%lx", (unsigned long)SS(rc));
    if (rc == 0) npd_desc_close(h);
}

/* ---- directory/domain rules: only observed ---------------------------------- */

TEST(npd_create_domain_rules_observed) {
    NREQ(UN(NCryptCreateProtectionDescriptor));
    static const wchar_t *const r[] = {
        L"SID=S-1-5-32-544", L"SDDL=O:SYG:SYD:(A;;FA;;;WD)", L"WEBCREDENTIALS=MyCred", L"WEBCREDENTIALS=MyCred,example.com",
        L"CERTIFICATE=HashId:0000000000000000000000000000000000000000", L"KEY=bogus",
    };
    for (size_t i = 0; i < sizeof r / sizeof *r; i++) {
        void *h = NULL;
        LONG rc = UN(NCryptCreateProtectionDescriptor)(r[i], 0, &h);
        t_note("create \"%ls\" -> 0x%lx", r[i], (unsigned long)SS(rc));
        if (rc == 0) {
            CHECK(h != NULL);
            npd_desc_close(h);
        } else {
            CHECK(h == NULL);
        }
    }
}

/* ---- named descriptors (no registry writes here) ----------------------------- */

TEST(npd_create_named_unregistered) {
    NREQ(UN(NCryptCreateProtectionDescriptor));
    void *h = (void *)(ULONG_PTR)1;
    LONG rc = UN(NCryptCreateProtectionDescriptor)(L"cryptt_npd_never_registered_name", NPD_NAMED_FLAG, &h);
    EXPECT_SS(rc, NPD_HR_FILE_NOT_FOUND);
    CHECK(h == NULL);
}

TEST(npd_create_named_unregistered_machine) {
    NREQ(UN(NCryptCreateProtectionDescriptor));
    void *h = (void *)(ULONG_PTR)1;
    LONG rc = UN(NCryptCreateProtectionDescriptor)(L"cryptt_npd_never_registered_name", NPD_NAMED_FLAG | NPD_MACHINE_FLAG, &h);
    EXPECT_SS(rc, NPD_HR_FILE_NOT_FOUND);
    CHECK(h == NULL);
}

TEST(npd_create_named_bad_flag_combo) {
    NREQ(UN(NCryptCreateProtectionDescriptor));
    void *h = NULL;
    EXPECT_SS(UN(NCryptCreateProtectionDescriptor)(L"cryptt_npd_x", NPD_NAMED_FLAG | 0x2, &h), NPD_NTE_BAD_FLAGS);
}

/* ---- Close -------------------------------------------------------------------- */

TEST(npd_close_null) {
    NREQ(UN(NCryptCloseProtectionDescriptor));
    EXPECT_SS(UN(NCryptCloseProtectionDescriptor)(NULL), NPD_NTE_INVALID_HANDLE);
}

TEST(npd_close_valid_returns_zero) {
    NREQ(UN(NCryptCreateProtectionDescriptor));
    void *h = npd_desc(L"LOCAL=user");
    if (!h) { t_skip("cannot create descriptor"); return; }
    EXPECT_SS(UN(NCryptCloseProtectionDescriptor)(h), 0);
}

TEST(npd_close_does_not_accept_key_protector_handle) {
    /* a key-protector handle (tag 0x48) is not a descriptor handle (tag 0x28) */
    NREQ(UN(NCryptOpenKeyProtector));
    void *kp = NULL;
    if (UN(NCryptOpenKeyProtector)(&kp, L"LOCAL", 0) != 0 || !kp) { t_skip("LOCAL protector unavailable"); return; }
    EXPECT_SS(UN(NCryptCloseProtectionDescriptor)(kp), NPD_NTE_INVALID_HANDLE);
    EXPECT_SS(UN(NCryptCloseKeyProtector)(kp), 0);
}

TEST(npd_close_does_not_accept_stream_handle) {
    NREQ(UN(NCryptStreamClose));
    NREQ(UN(NCryptCloseKeyProtector));
    /* descriptor handle given to the stream close: wrong tag */
    void *h = npd_desc(L"LOCAL=user");
    if (!h) { t_skip("cannot create descriptor"); return; }
    EXPECT_SS(UN(NCryptStreamClose)(h), NPD_NTE_INVALID_HANDLE);
    EXPECT_SS(UN(NCryptCloseKeyProtector)(h), NPD_NTE_INVALID_HANDLE);
    npd_desc_close(h);
}

/* ---- GetProtectionDescriptorInfo ---------------------------------------------- */

TEST(npd_info_null_output) {
    NREQ(UN(NCryptGetProtectionDescriptorInfo));
    void *h = npd_desc(L"LOCAL=user");
    if (!h) { t_skip("cannot create descriptor"); return; }
    EXPECT_SS(UN(NCryptGetProtectionDescriptorInfo)(h, NULL, NPD_INFO_DESCRIPTOR_STRING, NULL), NPD_NTE_INVALID_PARAM);
    npd_desc_close(h);
}

TEST(npd_info_null_output_wins_over_handle) {
    NREQ(UN(NCryptGetProtectionDescriptorInfo));
    EXPECT_SS(UN(NCryptGetProtectionDescriptorInfo)(NULL, NULL, NPD_INFO_DESCRIPTOR_STRING, NULL), NPD_NTE_INVALID_PARAM);
}

TEST(npd_info_null_handle) {
    NREQ(UN(NCryptGetProtectionDescriptorInfo));
    void *out = (void *)(ULONG_PTR)1;
    EXPECT_SS(UN(NCryptGetProtectionDescriptorInfo)(NULL, NULL, NPD_INFO_DESCRIPTOR_STRING, &out), NPD_NTE_INVALID_HANDLE);
    CHECK(out == (void *)(ULONG_PTR)1);   /* untouched when the handle is rejected */
}

TEST(npd_info_bad_type) {
    NREQ(UN(NCryptGetProtectionDescriptorInfo));
    void *h = npd_desc(L"LOCAL=user");
    if (!h) { t_skip("cannot create descriptor"); return; }
    static const DWORD types[] = { 0, 2, 3, 0x100, 0xFFFFFFFFu };
    for (size_t i = 0; i < sizeof types / sizeof *types; i++) {
        void *out = (void *)(ULONG_PTR)1;
        LONG rc = UN(NCryptGetProtectionDescriptorInfo)(h, NULL, types[i], &out);
        CHECKF(SS(rc) == NPD_NTE_NOT_SUPPORTED, "type 0x%lx: 0x%lx", (unsigned long)types[i], (unsigned long)SS(rc));
        CHECKF(out == NULL, "type 0x%lx: output not cleared", (unsigned long)types[i]);
    }
    npd_desc_close(h);
}

TEST(npd_info_string_local_user) {
    NREQ(UN(NCryptGetProtectionDescriptorInfo));
    void *h = npd_desc(L"LOCAL=user");
    if (!h) { t_skip("cannot create descriptor"); return; }
    void *out = NULL;
    LONG rc = UN(NCryptGetProtectionDescriptorInfo)(h, NULL, NPD_INFO_DESCRIPTOR_STRING, &out);
    EXPECT_SS(rc, 0);
    CHECK(out != NULL);
    if (rc == 0 && out) {
        EXPECT_WSTR((const wchar_t *)out, L"LOCAL=user");
        CHECK(LocalSize(out) >= sizeof(L"LOCAL=user"));
    }
    free_info(out);
    npd_desc_close(h);
}

TEST(npd_info_string_each_local_rule) {
    NREQ(UN(NCryptGetProtectionDescriptorInfo));
    for (size_t i = 0; i < sizeof local_rules / sizeof *local_rules; i++) {
        void *h = npd_desc(local_rules[i]);
        if (!h) { t_note("%ls not creatable", local_rules[i]); continue; }
        void *out = NULL;
        EXPECT_SS(UN(NCryptGetProtectionDescriptorInfo)(h, NULL, NPD_INFO_DESCRIPTOR_STRING, &out), 0);
        if (out) { CHECKF(!lstrcmpW((wchar_t *)out, local_rules[i]), "%ls -> %ls", local_rules[i], (wchar_t *)out); }
        free_info(out);
        npd_desc_close(h);
    }
}

TEST(npd_info_string_normalizes_whitespace) {
    NREQ(UN(NCryptGetProtectionDescriptorInfo));
    void *h = npd_desc(L"  LOCAL =  user  ");
    if (!h) { t_skip("cannot create descriptor"); return; }
    void *out = NULL;
    EXPECT_SS(UN(NCryptGetProtectionDescriptorInfo)(h, NULL, NPD_INFO_DESCRIPTOR_STRING, &out), 0);
    if (out) EXPECT_WSTR((wchar_t *)out, L"LOCAL=user");
    free_info(out);
    npd_desc_close(h);
}

TEST(npd_info_string_quotes_dropped) {
    NREQ(UN(NCryptGetProtectionDescriptorInfo));
    void *h = npd_desc(L"LOCAL=\"user\"");
    if (!h) { t_skip("cannot create descriptor"); return; }
    void *out = NULL;
    EXPECT_SS(UN(NCryptGetProtectionDescriptorInfo)(h, NULL, NPD_INFO_DESCRIPTOR_STRING, &out), 0);
    if (out) t_note("quoted descriptor rendered as \"%ls\"", (wchar_t *)out);
    free_info(out);
    npd_desc_close(h);
}

TEST(npd_info_string_compound_observed) {
    NREQ(UN(NCryptGetProtectionDescriptorInfo));
    static const wchar_t *const v[] = { L"LOCAL=user AND LOCAL=machine", L"LOCAL=user OR LOCAL=logon", L"LOCAL=user AND LOCAL=logon OR LOCAL=machine" };
    for (size_t i = 0; i < sizeof v / sizeof *v; i++) {
        void *h = npd_desc(v[i]);
        if (!h) { t_note("\"%ls\" not creatable", v[i]); continue; }
        void *out = NULL;
        LONG rc = UN(NCryptGetProtectionDescriptorInfo)(h, NULL, NPD_INFO_DESCRIPTOR_STRING, &out);
        EXPECT_SS(rc, 0);
        if (out) t_note("\"%ls\" rendered as \"%ls\"", v[i], (wchar_t *)out);
        free_info(out);
        npd_desc_close(h);
    }
}

TEST(npd_info_string_independent_allocations) {
    NREQ(UN(NCryptGetProtectionDescriptorInfo));
    void *h = npd_desc(L"LOCAL=user");
    if (!h) { t_skip("cannot create descriptor"); return; }
    void *a = NULL, *b = NULL;
    EXPECT_SS(UN(NCryptGetProtectionDescriptorInfo)(h, NULL, 1, &a), 0);
    EXPECT_SS(UN(NCryptGetProtectionDescriptorInfo)(h, NULL, 1, &b), 0);
    CHECK(a && b && a != b);
    free_info(a); free_info(b);
    npd_desc_close(h);
}

static LONG g_alloc_calls, g_free_calls; static SIZE_T g_alloc_size;
static PVOID WINAPI my_alloc(SIZE_T n) { g_alloc_calls++; g_alloc_size = n; return LocalAlloc(LPTR, n); }
static void WINAPI my_free(PVOID p) { g_free_calls++; LocalFree(p); }

TEST(npd_info_custom_allocator) {
    NREQ(UN(NCryptGetProtectionDescriptorInfo));
    void *h = npd_desc(L"LOCAL=user");
    if (!h) { t_skip("cannot create descriptor"); return; }
    NPD_ALLOC_PARA ap = { sizeof ap, my_alloc, my_free };
    g_alloc_calls = g_free_calls = 0; g_alloc_size = 0;
    void *out = NULL;
    LONG rc = UN(NCryptGetProtectionDescriptorInfo)(h, &ap, 1, &out);
    EXPECT_SS(rc, 0);
    CHECK(g_alloc_calls == 1);
    CHECK(g_alloc_size >= sizeof(L"LOCAL=user"));
    if (out) EXPECT_WSTR((wchar_t *)out, L"LOCAL=user");
    if (out) my_free(out);
    npd_desc_close(h);
}

static PVOID WINAPI failing_alloc(SIZE_T n) { g_alloc_calls++; return NULL; }

TEST(npd_info_allocator_failure) {
    NREQ(UN(NCryptGetProtectionDescriptorInfo));
    void *h = npd_desc(L"LOCAL=user");
    if (!h) { t_skip("cannot create descriptor"); return; }
    NPD_ALLOC_PARA ap = { sizeof ap, failing_alloc, my_free };
    g_alloc_calls = 0;
    void *out = (void *)(ULONG_PTR)1;
    LONG rc = UN(NCryptGetProtectionDescriptorInfo)(h, &ap, 1, &out);
    EXPECT_SS(rc, NPD_NTE_NO_MEMORY);
    CHECK(out == NULL);
    CHECK(g_alloc_calls == 1);
    npd_desc_close(h);
}

TEST(npd_info_after_machine_flag_create) {
    NREQ(UN(NCryptGetProtectionDescriptorInfo));
    void *h = NULL;
    if (UN(NCryptCreateProtectionDescriptor)(L"LOCAL=machine", NPD_MACHINE_FLAG, &h) != 0) { t_skip("cannot create"); return; }
    void *out = NULL;
    EXPECT_SS(UN(NCryptGetProtectionDescriptorInfo)(h, NULL, 1, &out), 0);
    if (out) EXPECT_WSTR((wchar_t *)out, L"LOCAL=machine");
    free_info(out);
    npd_desc_close(h);
}
