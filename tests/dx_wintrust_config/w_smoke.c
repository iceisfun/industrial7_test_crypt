#include "wcfg.h"
/* the in-exe providers must be reachable through LoadLibrary/GetProcAddress, which is how wintrust loads them */
TEST(wcfg_smoke_exports_resolve) {
    REQUIRE(U(WintrustAddActionID));
    wchar_t p[MAX_PATH]; wcfg_selfpath(p, MAX_PATH);
    HMODULE h = LoadLibraryW(p);
    CHECK(h != NULL);
    for (int i = 0; i < WP__N; i++) CHECKF(h && GetProcAddress(h, wcfg_names[i]) != NULL, "export %s", wcfg_names[i]);
    for (int i = 0; i < 8; i++) CHECKF(h && GetProcAddress(h, wcfg_sip_names[i]) != NULL, "export %s", wcfg_sip_names[i]);
    if (h) FreeLibrary(h);
}
TEST(wcfg_smoke_test_guid_shape) {
    GUID g; wcfg_guid(&g, 5);
    wchar_t s[48]; wcfg_guid_str(&g, s);
    CHECK(wcslen(s) == 38);
    CHECK(s[0] == L'{' && s[37] == L'}');
    CHECK(!wcscmp(s + 18, L"-6372-797074742121}") || !wcscmp(s + 19, L"-6372-797074742121}"));
}
