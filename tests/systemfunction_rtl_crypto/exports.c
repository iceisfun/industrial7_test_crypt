#include "sf.h"

/* The set of SystemFunction exports per module, from the Windows 10 export tables. */
static const int cryptbase_set[] = {1,2,3,4,5,28,29,34,36,40,41};
static const int cryptsp_set[] = {6,7,8,9,10,11,12,13,14,15,16,18,20,21,22,23,24,25,26,27,30,31,32,33,35};
static const int advapi_set[] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,40,41};
#define N(a) ((int)(sizeof(a) / sizeof((a)[0])))

static int in_set(const int *s, int n, int v) { int i; for (i = 0; i < n; i++) if (s[i] == v) return 1; return 0; }

#define EXPORT_TEST(n) \
TEST(sfrc_export_##n) { \
    if (t_is_wine()) { t_skip("emulator does not forward to cryptbase/cryptsp"); return; } \
    FARPROC a = sf_adv(n), b = sf_in(sf_impl(n), n); \
    CHECK(a != NULL); CHECK(b != NULL); \
    if (n == 35) { \
        FARPROC c = t_proc_in("cryptsp.dll", "CheckSignatureInFile"); \
        CHECK(c != NULL); CHECK(a == c); \
        CHECK(t_proc_in("cryptsp.dll", "SystemFunction035") != NULL); \
    } else CHECK(a == b); \
}
EXPORT_TEST(1) EXPORT_TEST(2) EXPORT_TEST(3) EXPORT_TEST(4) EXPORT_TEST(5)
EXPORT_TEST(6) EXPORT_TEST(7) EXPORT_TEST(8) EXPORT_TEST(9) EXPORT_TEST(10)
EXPORT_TEST(11) EXPORT_TEST(12) EXPORT_TEST(13) EXPORT_TEST(14) EXPORT_TEST(15)
EXPORT_TEST(16) EXPORT_TEST(17) EXPORT_TEST(18) EXPORT_TEST(19) EXPORT_TEST(20)
EXPORT_TEST(21) EXPORT_TEST(22) EXPORT_TEST(23) EXPORT_TEST(24) EXPORT_TEST(25)
EXPORT_TEST(26) EXPORT_TEST(27) EXPORT_TEST(28) EXPORT_TEST(29) EXPORT_TEST(30)
EXPORT_TEST(31) EXPORT_TEST(32) EXPORT_TEST(33) EXPORT_TEST(34) EXPORT_TEST(35)
EXPORT_TEST(36) EXPORT_TEST(40) EXPORT_TEST(41)

TEST(sfrc_export_cryptbase_exact_set)
{
    int n;
    if (t_is_wine()) { t_skip("emulator export layout"); return; }
    if (!t_module("cryptbase.dll")) { t_skip("no cryptbase"); return; }
    for (n = 0; n <= 45; n++) {
        FARPROC p = sf_raw("cryptbase.dll", n);
        int want = in_set(cryptbase_set, N(cryptbase_set), n);
        CHECKF((p != NULL) == want, "SystemFunction%03d in cryptbase: got %d want %d", n, p != NULL, want);
    }
}
TEST(sfrc_export_cryptsp_exact_set)
{
    int n;
    if (t_is_wine()) { t_skip("emulator export layout"); return; }
    if (!t_module("cryptsp.dll")) { t_skip("no cryptsp"); return; }
    for (n = 0; n <= 45; n++) {
        FARPROC p = sf_raw("cryptsp.dll", n);
        int want = in_set(cryptsp_set, N(cryptsp_set), n);
        CHECKF((p != NULL) == want, "SystemFunction%03d in cryptsp: got %d want %d", n, p != NULL, want);
    }
}
TEST(sfrc_export_advapi32_exact_set)
{
    int n;
    for (n = 0; n <= 45; n++) {
        FARPROC p = sf_adv(n);
        int want = in_set(advapi_set, N(advapi_set), n);
        CHECKF((p != NULL) == want, "SystemFunction%03d in advapi32: got %d want %d", n, p != NULL, want);
    }
}
TEST(sfrc_export_missing_gaps_last_error)
{
    static const int gaps[] = {0, 37, 38, 39, 42, 43, 100};
    int i;
    for (i = 0; i < N(gaps); i++) {
        SET_ERR(0);
        FARPROC p = sf_raw("advapi32.dll", gaps[i]);
        CHECK(p == NULL); EXPECT_ERR(ERROR_PROC_NOT_FOUND);
    }
}
TEST(sfrc_export_017_019_local_to_advapi32)
{
    if (t_is_wine()) { t_skip("emulator export layout"); return; }
    CHECK(sf_adv(17) != NULL); CHECK(sf_adv(19) != NULL);
    CHECK(sf_adv(17) != sf_adv(19));
    CHECK(sf_raw("cryptsp.dll", 17) == NULL); CHECK(sf_raw("cryptsp.dll", 19) == NULL);
    CHECK(sf_raw("cryptbase.dll", 17) == NULL); CHECK(sf_raw("cryptbase.dll", 19) == NULL);
}
TEST(sfrc_export_names_case_sensitive)
{
    SET_ERR(0);
    CHECK(GetProcAddress(t_module("advapi32.dll"), "systemfunction036") == NULL);
    EXPECT_ERR(ERROR_PROC_NOT_FOUND);
    CHECK(GetProcAddress(t_module("advapi32.dll"), "SystemFunction36") == NULL);
}
TEST(sfrc_export_rtl_aliases_exist_in_ntdll_or_not)
{
    /* Informational: the documented Rtl names live in ntdll, SystemFunctionNNN are the advapi32 spellings. */
    FARPROC a = t_proc_in("ntdll.dll", "RtlGenRandom");
    t_note("ntdll!RtlGenRandom export present: %d", a != NULL);
    t_note("ntdll!RtlEncryptMemory export present: %d", t_proc_in("ntdll.dll", "RtlEncryptMemory") != NULL);
}
TEST(sfrc_export_ordinals_stable_across_forwarders)
{
    /* Resolving through the forwarder repeatedly must be stable. */
    int i;
    FARPROC first = sf_adv(36);
    REQUIRE(first);
    for (i = 0; i < 50; i++) CHECK(sf_adv(36) == first);
}
