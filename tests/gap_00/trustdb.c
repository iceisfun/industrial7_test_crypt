#include "gap0.h"
/* OpenPersonalTrustDBDialog / OpenPersonalTrustDBDialogEx (wintrust). Only the documented no-UI path is run:
 * dwFlags bit 0 makes the call return TRUE immediately without loading the UI module. */

UDECL(BOOL, OpenPersonalTrustDBDialogEx, (HWND, DWORD, PVOID *));
UDECL(BOOL, OpenPersonalTrustDBDialog, (HWND));

TEST(gap0_trustdb_exports_in_wintrust) {
    if (t_is_wine()) { t_skip("exports absent in the emulator"); return; }
    CHECK(t_proc_in("wintrust.dll", "OpenPersonalTrustDBDialog") != NULL);
    CHECK(t_proc_in("wintrust.dll", "OpenPersonalTrustDBDialogEx") != NULL);
}

TEST(gap0_trustdb_flag1_returns_true_without_ui) {
    OpenPersonalTrustDBDialogEx_pfn f = (OpenPersonalTrustDBDialogEx_pfn)t_proc_in("wintrust.dll", "OpenPersonalTrustDBDialogEx");
    REQUIRE(f);
    DWORD flags[] = { 1, 3, 0x81, 0xFFFFFFFF };
    for (unsigned i = 0; i < sizeof flags / sizeof *flags; i++) {
        SET_ERR(0x4242);
        BOOL r = f(NULL, flags[i], NULL);
        CHECKF(r == TRUE, "flags 0x%lx", flags[i]);
        /* the early return does not touch the thread's last error */
        CHECKF(GetLastError() == 0x4242, "flags 0x%lx changed last error to %lu", flags[i], GetLastError());
    }
}

TEST(gap0_trustdb_flag1_ignores_parent_window_and_reserved) {
    OpenPersonalTrustDBDialogEx_pfn f = (OpenPersonalTrustDBDialogEx_pfn)t_proc_in("wintrust.dll", "OpenPersonalTrustDBDialogEx");
    REQUIRE(f);
    PVOID res = NULL;
    SET_ERR(0);
    CHECK(f((HWND)(ULONG_PTR)0xFFFFFFFF, 1, &res) == TRUE);
    CHECK(f(GetDesktopWindow(), 1, NULL) == TRUE);
    CHECK(res == NULL);
    EXPECT_EQ(GetLastError(), 0);
}

TEST(gap0_trustdb_plain_variant_resolves_to_ui_entry) {
    OpenPersonalTrustDBDialog_pfn f = (OpenPersonalTrustDBDialog_pfn)t_proc_in("wintrust.dll", "OpenPersonalTrustDBDialog");
    REQUIRE(f);
    /* OpenPersonalTrustDBDialog(h) is OpenPersonalTrustDBDialogEx(h, 0, NULL), which would show a dialog:
     * only existence and export identity are asserted here (the dialog itself lives in ui_crypto_dialogs). */
    FARPROC ex = t_proc_in("wintrust.dll", "OpenPersonalTrustDBDialogEx");
    CHECK((FARPROC)f != ex);
}
