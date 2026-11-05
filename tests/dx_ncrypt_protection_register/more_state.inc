/* Included from register.c: cross-process / multi-name / DPAPI-NG round trips through registered names. */

static void a2w(const char *a, wchar_t *w, int cap) { MultiByteToWideChar(CP_ACP, 0, a, -1, w, cap); }

/* argv[1] = op (query|delete|register), argv[2] = ascii name, argv[3] = expected / new descriptor ascii */
CHILD(dxnpr_child) {
    if (argc < 3 || !UN(NCryptRegisterProtectionDescriptorName) || !UN(NCryptQueryProtectionDescriptorName)) return 90;
    wchar_t n[200], d[200];
    a2w(argv[2], n, 200);
    if (!strcmp(argv[1], "query")) {
        SIZE_T cch = 200; LONG rc = query(n, d, &cch, 0);
        if (rc != 0) return 10 + (int)(SS(rc) == NPD_HR_FILE_NOT_FOUND);
        wchar_t want[200]; a2w(argv[3], want, 200);
        return lstrcmpW(d, want) ? 12 : 0;
    }
    if (!strcmp(argv[1], "delete")) return (int)reg(n, NULL, 0) == 0 ? 0 : 20;
    if (!strcmp(argv[1], "register")) { a2w(argv[3], d, 200); return reg(n, d, 0) == 0 ? 0 : 30; }
    return 91;
}

static void w2a(const wchar_t *w, char *a, int cap) { WideCharToMultiByte(CP_ACP, 0, w, -1, a, cap, NULL, NULL); }

TEST(dxnpr_child_process_sees_registration) {
    NPR_GUARD();
    wchar_t n[128]; npr_name(n, 128, L"xp1");
    EXPECT_SS(reg(n, L"LOCAL=user", 0), 0);
    char an[128], args[300]; w2a(n, an, 128);
    wsprintfA(args, "query %s LOCAL=user", an);
    EXPECT_EQ(t_run_child("dxnpr_child", args, 20000), 0);
    npr_end();
}

TEST(dxnpr_child_process_unknown_name) {
    NPR_GUARD();
    wchar_t n[128]; npr_name(n, 128, L"xp2");
    char an[128], args[300]; w2a(n, an, 128);
    wsprintfA(args, "query %s LOCAL=user", an);
    EXPECT_EQ(t_run_child("dxnpr_child", args, 20000), 11);   /* FILE_NOT_FOUND */
    npr_end();
}

TEST(dxnpr_child_process_deletes_parent_registration) {
    NPR_GUARD();
    wchar_t n[128]; npr_name(n, 128, L"xp3");
    EXPECT_SS(reg(n, L"LOCAL=user", 0), 0);
    char an[128], args[300]; w2a(n, an, 128);
    wsprintfA(args, "delete %s x", an);
    EXPECT_EQ(t_run_child("dxnpr_child", args, 20000), 0);
    SIZE_T cch = 0;
    EXPECT_SS(query(n, NULL, &cch, 0), NPD_HR_FILE_NOT_FOUND);
    npr_end();
}

TEST(dxnpr_child_process_registers_for_parent) {
    NPR_GUARD();
    wchar_t n[128]; npr_name(n, 128, L"xp4");
    char an[128], args[300]; w2a(n, an, 128);
    wsprintfA(args, "register %s LOCAL=logon", an);
    EXPECT_EQ(t_run_child("dxnpr_child", args, 20000), 0);
    wchar_t buf[32]; SIZE_T cch = 32;
    EXPECT_SS(query(n, buf, &cch, 0), 0);
    EXPECT_WSTR(buf, L"LOCAL=logon");
    npr_end();       /* the child registered the name; the sweep removes it */
}

TEST(dxnpr_child_process_overwrite_visible_to_parent) {
    NPR_GUARD();
    wchar_t n[128]; npr_name(n, 128, L"xp5");
    EXPECT_SS(reg(n, L"LOCAL=user", 0), 0);
    char an[128], args[300]; w2a(n, an, 128);
    wsprintfA(args, "register %s LOCAL=logon", an);
    EXPECT_EQ(t_run_child("dxnpr_child", args, 20000), 0);
    wchar_t buf[32]; SIZE_T cch = 32;
    EXPECT_SS(query(n, buf, &cch, 0), 0);
    EXPECT_WSTR(buf, L"LOCAL=logon");
    npr_end();
}

TEST(dxnpr_many_names_roundtrip) {
    NPR_GUARD();
    enum { N = 64 };
    wchar_t n[N][128], d[N][40];
    for (int i = 0; i < N; i++) {
        wchar_t tag[16]; _snwprintf(tag, 16, L"m%02d", i);
        npr_name(n[i], 128, tag);
        _snwprintf(d[i], 40, L"LOCAL=user OR LOCAL=logon%d", i);   /* distinct strings; not parsed at register time */
        EXPECT_SS(reg(n[i], d[i], 0), 0);
    }
    for (int i = 0; i < N; i++) {
        wchar_t buf[64]; SIZE_T cch = 64;
        LONG rc = query(n[i], buf, &cch, 0);
        CHECKF(rc == 0 && !lstrcmpW(buf, d[i]), "name %d rc 0x%lx", i, (unsigned long)SS(rc));
    }
    for (int i = 0; i < N; i += 2) EXPECT_SS(reg(n[i], NULL, 0), 0);
    for (int i = 0; i < N; i++) {
        SIZE_T cch = 0;
        LONG rc = query(n[i], NULL, &cch, 0);
        CHECKF(SS(rc) == (i % 2 ? 0u : NPD_HR_FILE_NOT_FOUND), "name %d after partial delete 0x%lx", i, (unsigned long)SS(rc));
    }
    npr_end();
}

TEST(dxnpr_repeated_overwrite_loop) {
    NPR_GUARD();
    wchar_t n[128]; npr_name(n, 128, L"loop");
    for (int i = 0; i < 200; i++) {
        wchar_t d[48]; _snwprintf(d, 48, L"LOCAL=user /*%d*/", i);
        LONG rc = reg(n, d, 0);
        if (rc) { CHECKF(0, "iteration %d: 0x%lx", i, (unsigned long)SS(rc)); break; }
        wchar_t buf[48]; SIZE_T cch = 48;
        rc = query(n, buf, &cch, 0);
        if (rc || lstrcmpW(buf, d)) { CHECKF(0, "iteration %d readback 0x%lx", i, (unsigned long)SS(rc)); break; }
    }
    EXPECT_SS(reg(n, NULL, 0), 0);
    npr_end();
}

typedef struct { wchar_t name[128]; wchar_t desc[32]; LONG rc; } npr_thr;
static DWORD WINAPI npr_thread(void *p) {
    npr_thr *t = (npr_thr *)p;
    t->rc = reg(t->name, t->desc, 0);
    if (t->rc == 0) {
        wchar_t buf[40]; SIZE_T cch = 40;
        t->rc = query(t->name, buf, &cch, 0);
        if (t->rc == 0 && lstrcmpW(buf, t->desc)) t->rc = 0x7fffffff;
    }
    return 0;
}

TEST(dxnpr_concurrent_registration_distinct_names) {
    NPR_GUARD();
    enum { N = 8 };
    npr_thr t[N]; HANDLE h[N];
    for (int i = 0; i < N; i++) {
        wchar_t tag[16]; _snwprintf(tag, 16, L"th%d", i);
        npr_name(t[i].name, 128, tag);
        _snwprintf(t[i].desc, 32, L"LOCAL=user /*t%d*/", i);
        t[i].rc = -1;
        h[i] = CreateThread(NULL, 0, npr_thread, &t[i], 0, NULL);
    }
    for (int i = 0; i < N; i++) {
        if (!h[i]) { CHECKF(0, "CreateThread %d", i); continue; }
        DWORD w = WaitForSingleObject(h[i], 10000);
        CHECKF(w == WAIT_OBJECT_0, "thread %d wait 0x%lx", i, w);
        CloseHandle(h[i]);
        CHECKF(t[i].rc == 0, "thread %d rc 0x%lx", i, (unsigned long)SS(t[i].rc));
    }
    npr_end();
}

TEST(dxnpr_concurrent_same_name_last_writer_wins) {
    NPR_GUARD();
    enum { N = 6 };
    npr_thr t[N]; HANDLE h[N];
    wchar_t shared[128]; npr_name(shared, 128, L"thsame");
    for (int i = 0; i < N; i++) {
        lstrcpyW(t[i].name, shared);
        _snwprintf(t[i].desc, 32, L"LOCAL=user /*w%d*/", i);
        t[i].rc = -1;
        h[i] = CreateThread(NULL, 0, npr_thread, &t[i], 0, NULL);
    }
    for (int i = 0; i < N; i++) { if (h[i]) { WaitForSingleObject(h[i], 10000); CloseHandle(h[i]); } }
    wchar_t buf[40]; SIZE_T cch = 40;
    EXPECT_SS(query(shared, buf, &cch, 0), 0);
    int match = 0;
    for (int i = 0; i < N; i++) if (!lstrcmpW(buf, t[i].desc)) match = 1;
    CHECK(match);                              /* the stored value is exactly one writer's string */
    npr_end();
}

/* ---- DPAPI-NG through registered names ---- */

static int protect_roundtrip_named(const wchar_t *name, DWORD createflags, const BYTE *in, ULONG cin, int *prot_rc) {
    void *h = NULL; int ok = 0;
    LONG rc = UN(NCryptCreateProtectionDescriptor)(name, createflags, &h);
    *prot_rc = (int)rc;
    if (rc != 0 || !h) return 0;
    BYTE *blob = NULL, *out = NULL; ULONG cb = 0, co = 0;
    rc = UN(NCryptProtectSecret)(h, NPD_SILENT_FLAG, in, cin, NULL, NULL, &blob, &cb);
    *prot_rc = (int)rc;
    if (rc == 0 && blob) {
        rc = UN(NCryptUnprotectSecret)(NULL, NPD_SILENT_FLAG, blob, cb, NULL, NULL, &out, &co);
        *prot_rc = (int)rc;
        ok = (rc == 0 && co == cin && out && !memcmp(out, in, cin));
        if (out) LocalFree(out);
    }
    if (blob) LocalFree(blob);
    npd_desc_close(h);
    return ok;
}

TEST(dxnpr_named_user_roundtrip_sizes) {
    NPR_GUARD();
    REQUIRE_WORKING();
    wchar_t n[128]; npr_name(n, 128, L"sz");
    EXPECT_SS(reg(n, L"LOCAL=user", 0), 0);
    ULONG sizes[] = { 1, 2, 15, 16, 17, 255, 256, 1000, 4096 };
    for (size_t i = 0; i < sizeof sizes / sizeof sizes[0]; i++) {
        BYTE in[4096]; npd_fill(in, sizes[i], (unsigned)i);
        int prc;
        int ok = protect_roundtrip_named(n, NPD_NAMED_FLAG, in, sizes[i], &prc);
        CHECKF(ok, "size %lu rc 0x%lx", sizes[i], (unsigned long)prc);
    }
    npr_end();
}

TEST(dxnpr_named_blob_survives_unregister) {
    NPR_GUARD();
    REQUIRE_WORKING();
    wchar_t n[128]; npr_name(n, 128, L"surv");
    EXPECT_SS(reg(n, L"LOCAL=user", 0), 0);
    void *h = NULL;
    EXPECT_SS(UN(NCryptCreateProtectionDescriptor)(n, NPD_NAMED_FLAG, &h), 0);
    if (!h) { npr_end(); return; }
    BYTE in[40]; npd_fill(in, 40, 9);
    BYTE *blob = NULL, *out = NULL; ULONG cb = 0, co = 0;
    EXPECT_SS(UN(NCryptProtectSecret)(h, NPD_SILENT_FLAG, in, 40, NULL, NULL, &blob, &cb), 0);
    npd_desc_close(h);
    EXPECT_SS(reg(n, NULL, 0), 0);                     /* the blob carries the resolved descriptor, not the name */
    if (blob) {
        EXPECT_SS(UN(NCryptUnprotectSecret)(NULL, NPD_SILENT_FLAG, blob, cb, NULL, NULL, &out, &co), 0);
        CHECK(co == 40 && out && !memcmp(out, in, 40));
        if (out) LocalFree(out);
        LocalFree(blob);
    }
    npr_end();
}

TEST(dxnpr_named_blob_does_not_contain_name) {
    NPR_GUARD();
    REQUIRE_WORKING();
    wchar_t n[128]; npr_name(n, 128, L"noname");
    EXPECT_SS(reg(n, L"LOCAL=user", 0), 0);
    void *h = NULL;
    EXPECT_SS(UN(NCryptCreateProtectionDescriptor)(n, NPD_NAMED_FLAG, &h), 0);
    if (h) {
        BYTE in[16] = { 0 }, *blob = NULL; ULONG cb = 0;
        EXPECT_SS(UN(NCryptProtectSecret)(h, NPD_SILENT_FLAG, in, 16, NULL, NULL, &blob, &cb), 0);
        int found = 0;
        if (blob) {
            size_t nb = lstrlenW(n) * sizeof(wchar_t);
            for (size_t i = 0; i + nb <= cb; i++) if (!memcmp(blob + i, n, nb)) found = 1;
            LocalFree(blob);
        }
        CHECK(!found);
        npd_desc_close(h);
    }
    npr_end();
}

TEST(dxnpr_named_descriptor_logon_and_machine_variants) {
    NPR_GUARD();
    REQUIRE_WORKING();
    const wchar_t *ds[] = { L"LOCAL=logon", L"LOCAL=machine", L"LOCAL=user OR LOCAL=machine" };
    for (int i = 0; i < 3; i++) {
        wchar_t tag[16]; _snwprintf(tag, 16, L"var%d", i);
        wchar_t n[128]; npr_name(n, 128, tag);
        EXPECT_SS(reg(n, ds[i], 0), 0);
        BYTE in[24]; npd_fill(in, 24, 40 + i); int prc;
        int ok = protect_roundtrip_named(n, NPD_NAMED_FLAG, in, 24, &prc);
        CHECKF(ok, "%ls via name: rc 0x%lx", ds[i], (unsigned long)(DWORD)prc);
    }
    npr_end();
}

TEST(dxnpr_named_sid_descriptor_roundtrip) {
    NPR_GUARD();
    REQUIRE_WORKING();
    HANDLE tok; wchar_t *sidstr = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) { t_skip("no token"); return; }
    BYTE tu[256]; DWORD need = 0;
    BOOL ok = GetTokenInformation(tok, TokenUser, tu, sizeof tu, &need);
    CloseHandle(tok);
    typedef BOOL (WINAPI *c2s_t)(PSID, LPWSTR *);
    c2s_t c2s = (c2s_t)GetProcAddress(GetModuleHandleA("advapi32.dll"), "ConvertSidToStringSidW");
    if (!ok || !c2s || !c2s(((TOKEN_USER *)tu)->User.Sid, &sidstr)) { t_skip("no SID string"); return; }
    wchar_t d[200]; _snwprintf(d, 200, L"SID=%ls", sidstr);
    LocalFree(sidstr);
    wchar_t n[128]; npr_name(n, 128, L"sid");
    EXPECT_SS(reg(n, d, 0), 0);
    BYTE in[32]; npd_fill(in, 32, 77); int prc;
    int good = protect_roundtrip_named(n, NPD_NAMED_FLAG, in, 32, &prc);
    /* a SID descriptor needs domain key distribution: on a workgroup machine protecting fails with this status */
    REQUIRE_WORKGROUP();
    CHECK(!good);
    EXPECT_EQ((DWORD)prc, 0x80090034u);
    npr_end();
}

TEST(dxnpr_named_info_reports_resolved_string) {
    NPR_GUARD();
    wchar_t n[128]; npr_name(n, 128, L"info");
    const wchar_t *d = L"LOCAL=user";
    EXPECT_SS(reg(n, d, 0), 0);
    void *h = NULL;
    EXPECT_SS(UN(NCryptCreateProtectionDescriptor)(n, NPD_NAMED_FLAG, &h), 0);
    if (h) {
        void *s = NULL;
        EXPECT_SS(UN(NCryptGetProtectionDescriptorInfo)(h, NULL, NPD_INFO_DESCRIPTOR_STRING, &s), 0);
        if (s) {
            CHECK(!lstrcmpW((wchar_t *)s, d));
            CHECK(lstrcmpW((wchar_t *)s, n) != 0);      /* the registered name is not reported, only its value */
            LocalFree(s);
        }
        npd_desc_close(h);
    }
    npr_end();
}

TEST(dxnpr_second_create_sees_updated_value) {
    NPR_GUARD();
    wchar_t n[128]; npr_name(n, 128, L"upd");
    EXPECT_SS(reg(n, L"LOCAL=user", 0), 0);
    void *h1 = NULL, *h2 = NULL;
    EXPECT_SS(UN(NCryptCreateProtectionDescriptor)(n, NPD_NAMED_FLAG, &h1), 0);
    EXPECT_SS(reg(n, L"LOCAL=logon", 0), 0);
    EXPECT_SS(UN(NCryptCreateProtectionDescriptor)(n, NPD_NAMED_FLAG, &h2), 0);
    void *s1 = NULL, *s2 = NULL;
    if (h1 && h2) {
        EXPECT_SS(UN(NCryptGetProtectionDescriptorInfo)(h1, NULL, 1, &s1), 0);
        EXPECT_SS(UN(NCryptGetProtectionDescriptorInfo)(h2, NULL, 1, &s2), 0);
        if (s1) CHECK(!lstrcmpW((wchar_t *)s1, L"LOCAL=user"));
        if (s2) CHECK(!lstrcmpW((wchar_t *)s2, L"LOCAL=logon"));
    }
    if (s1) LocalFree(s1);
    if (s2) LocalFree(s2);
    npd_desc_close(h1); npd_desc_close(h2);
    npr_end();
}

TEST(dxnpr_named_handle_close_then_reuse_name) {
    NPR_GUARD();
    wchar_t n[128]; npr_name(n, 128, L"reuse");
    EXPECT_SS(reg(n, L"LOCAL=user", 0), 0);
    for (int i = 0; i < 20; i++) {
        void *h = NULL;
        LONG rc = UN(NCryptCreateProtectionDescriptor)(n, NPD_NAMED_FLAG, &h);
        if (rc || !h) { CHECKF(0, "iteration %d rc 0x%lx", i, (unsigned long)SS(rc)); break; }
        EXPECT_SS(UN(NCryptCloseProtectionDescriptor)(h), 0);
    }
    npr_end();
}

TEST(dxnpr_named_flag_variants_on_create) {
    NPR_GUARD();
    wchar_t n[128]; npr_name(n, 128, L"fv2");
    EXPECT_SS(reg(n, L"LOCAL=user", 0), 0);
    void *h = NULL;
    EXPECT_SS(UN(NCryptCreateProtectionDescriptor)(n, NPD_NAMED_FLAG, &h), 0);   /* 0x1 */
    npd_desc_close(h);
    /* flag 0x20 alone: the string is taken as a descriptor, not a name; HKCU registration is not consulted */
    h = (void *)(ULONG_PTR)1;
    LONG rc = UN(NCryptCreateProtectionDescriptor)(n, NPD_MACHINE_FLAG, &h);
    EXPECT_SS(rc, 0x80090005u);   /* NTE_BAD_DATA: the string is parsed as a descriptor and is not one */
    CHECK(h == NULL);
    npr_end();
}

TEST(dxnpr_machine_registration_roundtrip_elevated) {
    NPR_GUARD();
    if (!is_elevated()) { t_skip("needs elevation (HKLM)"); return; }
    REQUIRE_WORKING();
    wchar_t n[128]; npr_name(n, 128, L"mrt");
    EXPECT_SS(reg(n, L"LOCAL=machine", NPD_MACHINE_FLAG), 0);
    DWORD type = 0, cb = 0;
    EXPECT_EQ(raw_get(1, n, &type, NULL, &cb), 0);
    EXPECT_EQ(type, REG_SZ);
    EXPECT_EQ(cb, sizeof(L"LOCAL=machine"));
    BYTE in[20]; npd_fill(in, 20, 5); int prc;
    int ok = protect_roundtrip_named(n, NPD_NAMED_FLAG | NPD_MACHINE_FLAG, in, 20, &prc);
    CHECKF(ok, "machine named roundtrip rc 0x%lx", (unsigned long)(DWORD)prc);
    EXPECT_SS(reg(n, NULL, NPD_MACHINE_FLAG), 0);
    npr_end();
}

TEST(dxnpr_machine_and_user_same_name_independent) {
    NPR_GUARD();
    if (!is_elevated()) { t_skip("needs elevation (HKLM)"); return; }
    wchar_t n[128]; npr_name(n, 128, L"mu");
    EXPECT_SS(reg(n, L"LOCAL=machine", NPD_MACHINE_FLAG), 0);
    EXPECT_SS(reg(n, L"LOCAL=user", 0), 0);
    wchar_t buf[32]; SIZE_T cch = 32;
    EXPECT_SS(query(n, buf, &cch, NPD_MACHINE_FLAG), 0); EXPECT_WSTR(buf, L"LOCAL=machine");
    cch = 32;
    EXPECT_SS(query(n, buf, &cch, 0), 0); EXPECT_WSTR(buf, L"LOCAL=user");
    EXPECT_SS(reg(n, NULL, NPD_MACHINE_FLAG), 0);
    cch = 32;
    EXPECT_SS(query(n, buf, &cch, 0), 0);                              /* user registration untouched */
    cch = 0;
    EXPECT_SS(query(n, NULL, &cch, NPD_MACHINE_FLAG), NPD_HR_FILE_NOT_FOUND);
    npr_end();
}

TEST(dxnpr_machine_delete_unknown_elevated) {
    NPR_GUARD();
    if (!is_elevated()) { t_skip("needs elevation (HKLM)"); return; }
    wchar_t n[128]; npr_name(n, 128, L"mdu");
    EXPECT_SS(reg(n, NULL, NPD_MACHINE_FLAG), NPD_HR_FILE_NOT_FOUND);
    npr_end();
}

TEST(dxnpr_final_cleanup_leaves_no_values) {
    NPR_GUARD();
    wchar_t n[128]; npr_name(n, 128, L"fin");
    EXPECT_SS(reg(n, L"LOCAL=user", 0), 0);
    npr_end();
    SIZE_T cch = 0;
    EXPECT_SS(query(n, NULL, &cch, 0), NPD_HR_FILE_NOT_FOUND);   /* the sweep removed it */
}
