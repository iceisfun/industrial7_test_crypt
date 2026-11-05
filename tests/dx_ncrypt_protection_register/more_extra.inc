/* Included from register.c: storage format and re-registration edge cases. */

TEST(dxnpr_stored_size_tracks_length) {
    NPR_GUARD();
    wchar_t n[128]; npr_name(n, 128, L"szlen");
    const wchar_t *ds[] = { L"A", L"LOCAL=user", L"LOCAL=user OR LOCAL=machine" };
    for (int i = 0; i < 3; i++) {
        EXPECT_SS(reg(n, ds[i], 0), 0);
        DWORD type = 0, cb = 0;
        EXPECT_EQ(raw_get(0, n, &type, NULL, &cb), 0);
        EXPECT_EQ(type, REG_SZ);
        CHECKF(cb == (lstrlenW(ds[i]) + 1) * sizeof(wchar_t), "descriptor %d: cb %lu", i, (unsigned long)cb);
    }
    npr_end();
}

TEST(dxnpr_register_stops_at_first_nul) {
    NPR_GUARD();
    wchar_t n[128]; npr_name(n, 128, L"nul");
    EXPECT_SS(reg(n, L"AB\\0CD", 0), 0);       /* only the first string is read */
    wchar_t buf[16]; SIZE_T cch = 16;
    EXPECT_SS(query(n, buf, &cch, 0), 0);
    EXPECT_EQ(cch, 3);
    EXPECT_WSTR(buf, L"AB");
    npr_end();
}

TEST(dxnpr_reregister_after_delete) {
    NPR_GUARD();
    wchar_t n[128]; npr_name(n, 128, L"rr");
    EXPECT_SS(reg(n, L"LOCAL=user", 0), 0);
    EXPECT_SS(reg(n, NULL, 0), 0);
    EXPECT_SS(reg(n, L"LOCAL=logon", 0), 0);
    wchar_t buf[32]; SIZE_T cch = 32;
    EXPECT_SS(query(n, buf, &cch, 0), 0);
    EXPECT_WSTR(buf, L"LOCAL=logon");
    npr_end();
}

TEST(dxnpr_query_other_registry_types_return_raw_bytes) {
    NPR_GUARD();
    wchar_t n[128]; npr_name(n, 128, L"exp");
    EXPECT_EQ(raw_set(0, n, REG_EXPAND_SZ, L"%PATH%", sizeof(L"%PATH%")), 0);
    wchar_t buf[16]; SIZE_T cch = 16;
    EXPECT_SS(query(n, buf, &cch, 0), 0);      /* no type check, no expansion */
    EXPECT_EQ(cch, 7);
    EXPECT_WSTR(buf, L"%PATH%");
    npr_end();
}

TEST(dxnpr_query_failure_leaves_buffer_untouched) {
    NPR_GUARD();
    wchar_t n[128]; npr_name(n, 128, L"keep");
    EXPECT_SS(reg(n, L"LOCAL=user", 0), 0);
    wchar_t buf[16]; memset(buf, 0x21, sizeof buf);
    SIZE_T cch = 4;
    EXPECT_SS(query(n, buf, &cch, 0), NPD_HR_MORE_DATA);
    EXPECT_EQ(cch, 0);
    EXPECT_EQ(buf[0], 0x2121);
    npr_end();
}

TEST(dxnpr_delete_one_of_case_variants_deletes_both) {
    NPR_GUARD();
    wchar_t n[128], up[128]; npr_name(n, 128, L"cv");
    lstrcpyW(up, n); CharUpperW(up);
    EXPECT_SS(reg(n, L"LOCAL=user", 0), 0);
    EXPECT_SS(reg(up, NULL, 0), 0);            /* registry value names are case-insensitive */
    SIZE_T cch = 0;
    EXPECT_SS(query(n, NULL, &cch, 0), NPD_HR_FILE_NOT_FOUND);
    npr_end();
}
