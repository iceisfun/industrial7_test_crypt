/* Included from register.c: argument validation and error mapping of the registration API.
 * Ordering observed on Windows 10: name check (NULL/empty -> NTE_INVALID_PARAMETER) precedes the flag
 * check (flags & ~0x20 -> NTE_BAD_FLAGS); registry errors are mapped to 0x8007xxxx. */

static int key_exists(int machine) {
    HKEY k;
    if (RegOpenKeyExW(root_of(machine), KEYPATH, 0, KEY_QUERY_VALUE, &k) != 0) return 0;
    RegCloseKey(k);
    return 1;
}

/* make the HKCU key absent if (and only if) this run created it and it holds nothing; 1 when absent afterwards */
static int make_key_absent(void) {
    sweep_one(0);
    remove_key_if_ours_and_empty(0);
    return !key_exists(0);
}

static const DWORD bad_flag_values[] = { 0x1, 0x2, 0x4, 0x8, 0x10, 0x40, 0x80, 0x100, 0x10000, 0x80000000u, 0xFFFFFFFFu, 0xFFFFFFDFu, 0x21, 0x3F };

TEST(dxnpr_register_bad_flags_table) {
    NPR_GUARD();
    wchar_t n[128]; npr_name(n, 128, L"bf");
    for (size_t i = 0; i < sizeof bad_flag_values / sizeof bad_flag_values[0]; i++) {
        LONG rc = reg(n, L"LOCAL=user", bad_flag_values[i]);
        CHECKF(SS(rc) == NPD_NTE_BAD_FLAGS, "flags 0x%lx -> 0x%lx", (unsigned long)bad_flag_values[i], (unsigned long)SS(rc));
    }
    SIZE_T cch = 0;
    EXPECT_SS(query(n, NULL, &cch, 0), NPD_HR_FILE_NOT_FOUND);
    npr_end();
}

TEST(dxnpr_register_bad_flags_with_delete) {
    NPR_GUARD();
    wchar_t n[128]; npr_name(n, 128, L"bfd");
    EXPECT_SS(reg(n, L"LOCAL=user", 0), 0);
    EXPECT_SS(reg(n, NULL, 0x2), NPD_NTE_BAD_FLAGS);       /* flag check precedes the delete */
    wchar_t buf[16]; SIZE_T cch = 16;
    EXPECT_SS(query(n, buf, &cch, 0), 0);                  /* still registered */
    npr_end();
}

TEST(dxnpr_query_bad_flags_table) {
    NPR_GUARD();
    wchar_t n[128]; npr_name(n, 128, L"qbf");
    EXPECT_SS(reg(n, L"LOCAL=user", 0), 0);
    for (size_t i = 0; i < sizeof bad_flag_values / sizeof bad_flag_values[0]; i++) {
        SIZE_T cch = 77;
        LONG rc = query(n, NULL, &cch, bad_flag_values[i]);
        CHECKF(SS(rc) == NPD_NTE_BAD_FLAGS, "flags 0x%lx -> 0x%lx", (unsigned long)bad_flag_values[i], (unsigned long)SS(rc));
        CHECKF(cch == 0, "flags 0x%lx: size %lu (written 0 before validation)", (unsigned long)bad_flag_values[i], (unsigned long)cch);
    }
    npr_end();
}

TEST(dxnpr_register_invalid_name_table) {
    NPR_GUARD();
    EXPECT_SS(reg(NULL, L"LOCAL=user", 0), NPD_NTE_INVALID_PARAM);
    EXPECT_SS(reg(L"", L"LOCAL=user", 0), NPD_NTE_INVALID_PARAM);
    EXPECT_SS(reg(NULL, NULL, 0), NPD_NTE_INVALID_PARAM);
    EXPECT_SS(reg(L"", NULL, 0), NPD_NTE_INVALID_PARAM);
    npr_end();
}

TEST(dxnpr_register_name_checked_before_flags) {
    NPR_GUARD();
    EXPECT_SS(reg(NULL, L"LOCAL=user", 0x2), NPD_NTE_INVALID_PARAM);
    EXPECT_SS(reg(L"", L"LOCAL=user", 0xFFFFFFFFu), NPD_NTE_INVALID_PARAM);
    EXPECT_SS(reg(NULL, NULL, NPD_NAMED_FLAG), NPD_NTE_INVALID_PARAM);
    npr_end();
}

TEST(dxnpr_query_invalid_name_table) {
    NPR_GUARD();
    SIZE_T cch = 5;
    EXPECT_SS(query(NULL, NULL, &cch, 0), NPD_NTE_INVALID_PARAM);
    EXPECT_EQ(cch, 0);
    cch = 5;
    EXPECT_SS(query(L"", NULL, &cch, 0), NPD_NTE_INVALID_PARAM);
    EXPECT_EQ(cch, 0);
    wchar_t buf[4] = { 1, 2, 3, 4 };
    cch = 4;
    EXPECT_SS(query(NULL, buf, &cch, 0), NPD_NTE_INVALID_PARAM);
    EXPECT_EQ(buf[0], 1);                                  /* buffer untouched */
    cch = 4;
    EXPECT_SS(query(NULL, buf, &cch, 0x2), NPD_NTE_INVALID_PARAM);   /* name before flags */
    cch = 4;
    EXPECT_SS(query(L"", buf, &cch, 0xFFFFFFFFu), NPD_NTE_INVALID_PARAM);
    npr_end();
}

TEST(dxnpr_query_unknown_name_size_zeroed) {
    NPR_GUARD();
    wchar_t n[128]; npr_name(n, 128, L"unk");
    SIZE_T caps[] = { 0, 1, 99, 4096 };
    for (size_t i = 0; i < 4; i++) {
        wchar_t buf[8]; memset(buf, 0x33, sizeof buf);
        SIZE_T cch = caps[i];
        EXPECT_SS(query(n, i % 2 ? buf : NULL, &cch, 0), NPD_HR_FILE_NOT_FOUND);
        EXPECT_EQ(cch, 0);
        if (i % 2) EXPECT_EQ(buf[0], 0x3333);
    }
    npr_end();
}

TEST(dxnpr_query_unknown_name_machine) {
    NPR_GUARD();
    wchar_t n[128]; npr_name(n, 128, L"unkm");
    SIZE_T cch = 9;
    EXPECT_SS(query(n, NULL, &cch, NPD_MACHINE_FLAG), NPD_HR_FILE_NOT_FOUND);
    EXPECT_EQ(cch, 0);
    npr_end();
}

/* HKLM registration needs elevation. The bodies run in a standard user child (npr_run_unelevated) when this process is
 * elevated (dx mode), in place otherwise. They return 0 or the unexpected status (never create anything). */
static int mden_register_body(void) {
    if (is_elevated()) return 1;
    wchar_t n[128]; npr_name(n, 128, L"mden");
    LONG rc = reg(n, L"LOCAL=machine", NPD_MACHINE_FLAG);
    return SS(rc) == 0x80070005u ? 0 : (SS(rc) ? (int)SS(rc) : 2);   /* ERROR_ACCESS_DENIED as HRESULT */
}
static int mden_delete_body(void) {
    if (is_elevated()) return 1;
    wchar_t n[128]; npr_name(n, 128, L"mdel");
    LONG rc = reg(n, NULL, NPD_MACHINE_FLAG);
    return SS(rc) == 0x80070005u ? 0 : (SS(rc) ? (int)SS(rc) : 2);   /* denied before the missing value is looked at */
}
CHILD(dxnpr_mden_register) { return mden_register_body(); }
CHILD(dxnpr_mden_delete) { return mden_delete_body(); }

TEST(dxnpr_register_machine_flag_not_elevated_denied) {
    NPR_GUARD();
    if (is_elevated()) EXPECT_EQ(npr_run_unelevated("dxnpr_mden_register", 30000), 0);
    else EXPECT_EQ(mden_register_body(), 0);
}

TEST(dxnpr_delete_machine_flag_not_elevated_denied) {
    NPR_GUARD();
    if (is_elevated()) EXPECT_EQ(npr_run_unelevated("dxnpr_mden_delete", 30000), 0);
    else EXPECT_EQ(mden_delete_body(), 0);
}

TEST(dxnpr_user_flag_set_does_not_touch_hklm) {
    NPR_GUARD();
    wchar_t n[128]; npr_name(n, 128, L"hk");
    EXPECT_SS(reg(n, L"LOCAL=user", 0), 0);
    DWORD cb = 0;
    EXPECT_NE(raw_get(1, n, NULL, NULL, &cb), 0);          /* nothing leaked to HKLM */
    EXPECT_EQ(raw_get(0, n, NULL, NULL, &cb), 0);
    npr_end();
}

TEST(dxnpr_value_name_stored_verbatim) {
    NPR_GUARD();
    wchar_t n[128]; npr_name(n, 128, L"Verb_MiXed");
    EXPECT_SS(reg(n, L"LOCAL=user", 0), 0);
    HKEY k;
    EXPECT_EQ(RegOpenKeyExW(HKEY_CURRENT_USER, KEYPATH, 0, KEY_QUERY_VALUE, &k), 0);
    int found = 0;
    for (DWORD i = 0;; i++) {
        wchar_t vn[256]; DWORD len = 256;
        if (RegEnumValueW(k, i, vn, &len, NULL, NULL, NULL, NULL) != 0) break;
        if (!lstrcmpW(vn, n)) found = 1;                   /* exact case preserved */
    }
    RegCloseKey(k);
    CHECK(found);
    npr_end();
}

TEST(dxnpr_register_case_variant_same_value) {
    NPR_GUARD();
    wchar_t n[128], up[128]; npr_name(n, 128, L"cv");
    lstrcpyW(up, n); CharUpperW(up);
    EXPECT_SS(reg(n, L"LOCAL=user", 0), 0);
    EXPECT_SS(reg(up, L"LOCAL=logon", 0), 0);              /* registry value names are case-insensitive: overwrite */
    wchar_t buf[32]; SIZE_T cch = 32;
    EXPECT_SS(query(n, buf, &cch, 0), 0);
    EXPECT_WSTR(buf, L"LOCAL=logon");
    EXPECT_SS(reg(up, NULL, 0), 0);                        /* delete through the other case */
    cch = 0;
    EXPECT_SS(query(n, NULL, &cch, 0), NPD_HR_FILE_NOT_FOUND);
    npr_end();
}

TEST(dxnpr_register_whitespace_names_distinct) {
    NPR_GUARD();
    wchar_t a[128], b[128]; npr_name(a, 128, L"ws");
    lstrcpyW(b, a); lstrcatW(b, L" ");
    EXPECT_SS(reg(a, L"LOCAL=user", 0), 0);
    SIZE_T cch = 0;
    EXPECT_SS(query(b, NULL, &cch, 0), NPD_HR_FILE_NOT_FOUND);   /* no trimming */
    EXPECT_SS(reg(b, L"LOCAL=logon", 0), 0);
    wchar_t buf[32]; cch = 32;
    EXPECT_SS(query(a, buf, &cch, 0), 0); EXPECT_WSTR(buf, L"LOCAL=user");
    cch = 32;
    EXPECT_SS(query(b, buf, &cch, 0), 0); EXPECT_WSTR(buf, L"LOCAL=logon");
    npr_end();
}

TEST(dxnpr_register_descriptor_whitespace_verbatim) {
    NPR_GUARD();
    wchar_t n[128]; npr_name(n, 128, L"dws");
    const wchar_t *d = L"  LOCAL=user  ";
    EXPECT_SS(reg(n, d, 0), 0);
    wchar_t buf[32]; SIZE_T cch = 32;
    EXPECT_SS(query(n, buf, &cch, 0), 0);
    EXPECT_WSTR(buf, d);
    EXPECT_EQ(cch, lstrlenW(d) + 1);
    npr_end();
}

TEST(dxnpr_register_single_char_descriptor) {
    NPR_GUARD();
    wchar_t n[128]; npr_name(n, 128, L"one");
    EXPECT_SS(reg(n, L"x", 0), 0);
    SIZE_T cch = 0;
    EXPECT_SS(query(n, NULL, &cch, 0), 0);
    EXPECT_EQ(cch, 2);
    npr_end();
}

TEST(dxnpr_query_sentinel_after_data_untouched) {
    NPR_GUARD();
    wchar_t n[128]; npr_name(n, 128, L"sen");
    EXPECT_SS(reg(n, L"LOCAL=user", 0), 0);
    wchar_t buf[24]; for (int i = 0; i < 24; i++) buf[i] = 0x5a5a;
    SIZE_T cch = 20;
    EXPECT_SS(query(n, buf, &cch, 0), 0);
    EXPECT_EQ(cch, 11);
    EXPECT_WSTR(buf, L"LOCAL=user");
    for (int i = 11; i < 24; i++) CHECKF(buf[i] == 0x5a5a, "buf[%d] overwritten", i);
    npr_end();
}

TEST(dxnpr_query_capacity_in_characters_not_bytes) {
    NPR_GUARD();
    wchar_t n[128]; npr_name(n, 128, L"chr");
    EXPECT_SS(reg(n, L"abcdef", 0), 0);      /* 7 characters with NUL */
    wchar_t buf[16]; SIZE_T cch = 7;
    EXPECT_SS(query(n, buf, &cch, 0), 0);    /* 7 characters (14 bytes) suffice */
    EXPECT_EQ(cch, 7);
    cch = 6;
    EXPECT_SS(query(n, buf, &cch, 0), NPD_HR_MORE_DATA);
    cch = 14;                                 /* a byte count would also be enough, still 7 returned */
    EXPECT_SS(query(n, buf, &cch, 0), 0);
    EXPECT_EQ(cch, 7);
    npr_end();
}

TEST(dxnpr_query_value_without_terminator_sizes) {
    NPR_GUARD();
    wchar_t n[128]; npr_name(n, 128, L"nt");
    EXPECT_EQ(raw_set(0, n, REG_SZ, L"ABCD", 4 * sizeof(wchar_t)), 0);   /* 4 characters, no NUL */
    SIZE_T cch = 0;
    EXPECT_SS(query(n, NULL, &cch, 0), 0);
    EXPECT_EQ(cch, 5);   /* the size query includes room for the terminator */
    wchar_t buf[8]; memset(buf, 0x44, sizeof buf); cch = 8;
    EXPECT_SS(query(n, buf, &cch, 0), 0);
    EXPECT_EQ(cch, 5);
    CHECK(buf[0] == L'A' && buf[1] == L'B' && buf[2] == L'C');
    if (cch >= 1 && cch <= 8) CHECK(buf[cch - 1] == 0);                   /* last returned slot is always NUL */
    npr_end();
}

TEST(dxnpr_query_zero_length_value) {
    NPR_GUARD();
    wchar_t n[128]; npr_name(n, 128, L"zl");
    EXPECT_EQ(raw_set(0, n, REG_SZ, L"", 0), 0);
    wchar_t buf[4]; memset(buf, 0x66, sizeof buf); SIZE_T cch = 4;
    EXPECT_SS(query(n, buf, &cch, 0), 0);
    EXPECT_EQ(cch, 0);
    EXPECT_EQ(buf[0], 0x6666);               /* nothing written for an empty value */
    void *h = (void *)(ULONG_PTR)1;
    EXPECT_SS(UN(NCryptCreateProtectionDescriptor)(n, NPD_NAMED_FLAG, &h), NPD_NTE_NOT_FOUND);
    CHECK(h == NULL);
    npr_end();
}

TEST(dxnpr_query_odd_byte_count_truncates) {
    NPR_GUARD();
    wchar_t n[128]; npr_name(n, 128, L"odd5");
    BYTE five[5] = { 'A', 0, 'B', 0, 'C' };
    EXPECT_EQ(raw_set(0, n, REG_BINARY, five, 5), 0);
    SIZE_T cch = 0;
    EXPECT_SS(query(n, NULL, &cch, 0), 0);
    EXPECT_EQ(cch, 2);                       /* bytes / 2, rounded down */
    npr_end();
}

TEST(dxnpr_register_deletes_value_raw_check) {
    NPR_GUARD();
    wchar_t n[128]; npr_name(n, 128, L"rawdel");
    EXPECT_SS(reg(n, L"LOCAL=user", 0), 0);
    DWORD cb = 0;
    EXPECT_EQ(raw_get(0, n, NULL, NULL, &cb), 0);
    EXPECT_SS(reg(n, NULL, 0), 0);
    EXPECT_EQ(raw_get(0, n, NULL, NULL, &cb), ERROR_FILE_NOT_FOUND);
    npr_end();
}

TEST(dxnpr_register_does_not_remove_key_on_delete) {
    NPR_GUARD();
    wchar_t a[128], b[128]; npr_name(a, 128, L"kk1"); npr_name(b, 128, L"kk2");
    EXPECT_SS(reg(a, L"LOCAL=user", 0), 0);
    EXPECT_SS(reg(b, L"LOCAL=user", 0), 0);
    EXPECT_SS(reg(a, NULL, 0), 0);
    EXPECT_SS(reg(b, NULL, 0), 0);
    CHECK(key_exists(0));                    /* the NamedDescriptors key stays even when empty */
    npr_end();
}

TEST(dxnpr_register_creates_key_when_missing) {
    NPR_GUARD();
    if (!make_key_absent()) { t_skip("NamedDescriptors key pre-exists on this machine"); return; }
    wchar_t n[128]; npr_name(n, 128, L"mk");
    SIZE_T cch = 3;
    EXPECT_SS(query(n, NULL, &cch, 0), NPD_HR_FILE_NOT_FOUND);   /* a query opens only */
    CHECK(!key_exists(0));
    EXPECT_SS(reg(n, L"LOCAL=user", 0), 0);
    CHECK(key_exists(0));
    EXPECT_SS(reg(n, NULL, 0), 0);
    npr_end();
    make_key_absent();
}

TEST(dxnpr_delete_unknown_creates_key_as_side_effect) {
    NPR_GUARD();
    if (!make_key_absent()) { t_skip("NamedDescriptors key pre-exists on this machine"); return; }
    wchar_t n[128]; npr_name(n, 128, L"dk");
    EXPECT_SS(reg(n, NULL, 0), NPD_HR_FILE_NOT_FOUND);
    CHECK(key_exists(0));                    /* RegCreateKeyEx runs before the delete is attempted */
    npr_end();
    make_key_absent();
}

TEST(dxnpr_failed_validation_does_not_create_key) {
    NPR_GUARD();
    if (!make_key_absent()) { t_skip("NamedDescriptors key pre-exists on this machine"); return; }
    wchar_t n[128]; npr_name(n, 128, L"fv");
    EXPECT_SS(reg(n, L"LOCAL=user", 0x2), NPD_NTE_BAD_FLAGS);
    EXPECT_SS(reg(NULL, L"LOCAL=user", 0), NPD_NTE_INVALID_PARAM);
    CHECK(!key_exists(0));
    npr_end();
}

TEST(dxnpr_query_missing_key_is_file_not_found) {
    NPR_GUARD();
    if (!make_key_absent()) { t_skip("NamedDescriptors key pre-exists on this machine"); return; }
    wchar_t n[128]; npr_name(n, 128, L"mkq");
    SIZE_T cch = 5;
    EXPECT_SS(query(n, NULL, &cch, 0), NPD_HR_FILE_NOT_FOUND);
    EXPECT_EQ(cch, 0);
    CHECK(!key_exists(0));
    npr_end();
}

TEST(dxnpr_create_named_bad_flags_table) {
    NPR_GUARD();
    wchar_t n[128]; npr_name(n, 128, L"cbf");
    EXPECT_SS(reg(n, L"LOCAL=user", 0), 0);
    /* allowed bits are 0x1 and 0x20 only */
    const DWORD bad[] = { 0x2, 0x4, 0x8, 0x10, 0x40, 0x80, 0x100, 0x80000000u, 0xFFFFFFFFu, 0x3 };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        void *h = (void *)(ULONG_PTR)1;
        LONG rc = UN(NCryptCreateProtectionDescriptor)(n, bad[i], &h);
        CHECKF(SS(rc) == NPD_NTE_BAD_FLAGS, "flags 0x%lx -> 0x%lx", (unsigned long)bad[i], (unsigned long)SS(rc));
        CHECKF(h == NULL, "flags 0x%lx: handle not cleared", (unsigned long)bad[i]);
    }
    npr_end();
}

TEST(dxnpr_create_null_out_handle) {
    NPR_GUARD();
    wchar_t n[128]; npr_name(n, 128, L"cnh");
    EXPECT_SS(reg(n, L"LOCAL=user", 0), 0);
    EXPECT_SS(UN(NCryptCreateProtectionDescriptor)(n, NPD_NAMED_FLAG, NULL), NPD_NTE_INVALID_PARAM);
    EXPECT_SS(UN(NCryptCreateProtectionDescriptor)(NULL, NPD_NAMED_FLAG, NULL), NPD_NTE_INVALID_PARAM);
    EXPECT_SS(UN(NCryptCreateProtectionDescriptor)(n, 0x2, NULL), NPD_NTE_INVALID_PARAM);   /* handle first */
    npr_end();
}

TEST(dxnpr_create_named_null_or_empty_name) {
    NPR_GUARD();
    void *h = (void *)(ULONG_PTR)1;
    EXPECT_SS(UN(NCryptCreateProtectionDescriptor)(NULL, NPD_NAMED_FLAG, &h), NPD_NTE_INVALID_PARAM);
    CHECK(h == NULL);
    h = (void *)(ULONG_PTR)1;
    EXPECT_SS(UN(NCryptCreateProtectionDescriptor)(L"", NPD_NAMED_FLAG, &h), NPD_NTE_INVALID_PARAM);
    CHECK(h == NULL);
    h = (void *)(ULONG_PTR)1;
    EXPECT_SS(UN(NCryptCreateProtectionDescriptor)(L"", 0x2, &h), NPD_NTE_INVALID_PARAM);   /* name before flags */
    CHECK(h == NULL);
    npr_end();
}

TEST(dxnpr_create_named_unknown_name) {
    NPR_GUARD();
    wchar_t n[128]; npr_name(n, 128, L"cun");
    void *h = (void *)(ULONG_PTR)1;
    EXPECT_SS(UN(NCryptCreateProtectionDescriptor)(n, NPD_NAMED_FLAG, &h), NPD_HR_FILE_NOT_FOUND);
    CHECK(h == NULL);
    h = (void *)(ULONG_PTR)1;
    EXPECT_SS(UN(NCryptCreateProtectionDescriptor)(n, NPD_NAMED_FLAG | NPD_MACHINE_FLAG, &h), NPD_HR_FILE_NOT_FOUND);
    CHECK(h == NULL);
    npr_end();
}

TEST(dxnpr_create_unnamed_does_not_consult_registry) {
    NPR_GUARD();
    wchar_t n[128]; npr_name(n, 128, L"uc");
    EXPECT_SS(reg(n, L"LOCAL=logon", 0), 0);
    /* without the named flag the string itself is parsed as a descriptor; a registered name is just text */
    void *h = (void *)(ULONG_PTR)1;
    LONG rc = UN(NCryptCreateProtectionDescriptor)(n, 0, &h);
    EXPECT_SS(rc, 0x80090005u);   /* NTE_BAD_DATA from the descriptor parser */
    CHECK(h == NULL);
    npr_end();
}
