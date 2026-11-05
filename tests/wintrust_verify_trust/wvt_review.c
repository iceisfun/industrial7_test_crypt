/* Additional WinVerifyTrust behaviours: repeatability, hwnd handling, state lifecycle on unsigned subjects. */
#include "wvt.h"

TEST(wvt_rev_unsigned_repeat_stable) {
    WVT_REQUIRE_WVT();
    for (int i = 0; i < 5; i++) {
        DWORD e; LONG r = wvt_verify_bytes(fix_pe_unsigned, sizeof fix_pe_unsigned, 0, "rv1.exe", &e);
        EXPECT_EQ(r, WVT_E_NOSIGNATURE); EXPECT_EQ(e, (DWORD)WVT_E_NOSIGNATURE);
    }
}
TEST(wvt_rev_hwnd_invalid_handle_value_is_no_ui) {
    WVT_REQUIRE_WVT();
    WCHAR p[MAX_PATH]; WVTD w; WINTRUST_FILE_INFO fi;
    wvt_path(p, "rv2.exe"); wvt_write(p, fix_pe_unsigned, sizeof fix_pe_unsigned);
    wvt_init_file(&w, &fi, p);
    LONG r = U(WinVerifyTrust)((HWND)INVALID_HANDLE_VALUE, (GUID *)&WVT_V2, &w.d);
    EXPECT_EQ(r, WVT_E_NOSIGNATURE);
    wvt_del(p);
}
TEST(wvt_rev_ex_and_plain_agree_on_unsigned) {
    WVT_REQUIRE_WVT();
    WCHAR p[MAX_PATH]; WVTD w; WINTRUST_FILE_INFO fi;
    wvt_path(p, "rv3.exe"); wvt_write(p, fix_pe_unsigned, sizeof fix_pe_unsigned);
    wvt_init_file(&w, &fi, p);
    LONG a = U(WinVerifyTrust)(NULL, (GUID *)&WVT_V2, &w.d);
    HRESULT b = U(WinVerifyTrustEx)(NULL, (GUID *)&WVT_V2, &w.d);
    EXPECT_EQ(a, (LONG)b);
    wvt_del(p);
}
TEST(wvt_rev_state_verify_close_cycle_unsigned) {
    WVT_REQUIRE_WVT();
    for (int i = 0; i < 3; i++) {
        WCHAR p[MAX_PATH]; WVTD w; WINTRUST_FILE_INFO fi;
        wvt_path(p, "rv4.exe"); wvt_write(p, fix_pe_unsigned, sizeof fix_pe_unsigned);
        wvt_init_file(&w, &fi, p); w.d.dwStateAction = WTD_STATEACTION_VERIFY;
        DWORD e; LONG r = wvt_call(&WVT_V2, &w, &e);
        EXPECT_EQ(r, WVT_E_NOSIGNATURE);
        CHECK(w.d.hWVTStateData != NULL);
        CRYPT_PROVIDER_DATA *pd = U(WTHelperProvDataFromStateData)(w.d.hWVTStateData);
        CHECK(pd != NULL);
        if (pd) EXPECT_EQ(pd->cbStruct, (DWORD)sizeof(WVT_PD));
        wvt_close(&WVT_V2, &w);
        wvt_del(p);
    }
}
TEST(wvt_rev_ignore_does_not_return_state_for_signed) {
    WVT_REQUIRE_WVT();
    WCHAR p[MAX_PATH]; WVTD w; WINTRUST_FILE_INFO fi;
    wvt_path(p, "rv5.exe"); wvt_write(p, fix_pe_signed, sizeof fix_pe_signed);
    wvt_init_file(&w, &fi, p);
    wvt_call(&WVT_V2, &w, NULL);
    CHECK(w.d.hWVTStateData == NULL);
    wvt_del(p);
}
