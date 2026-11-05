#include "dxk.h"

TEST(dxpk_machine_key_lifecycle_admin) {
    KP_BEGIN(p); WCHAR n[96]; k_name(n, 96, L"mach"); NCRYPT_KEY_HANDLE k = 0, k2 = 0;
    if (!k_is_admin()) { t_skip("not elevated"); k_free(p); return; }
    EXPECT_S(k_make(p, n, BCRYPT_RSA_ALGORITHM, 1024, 0, NCRYPT_MACHINE_KEY_FLAG, &k), 0);
    CHECK(k_has_name(p, NCRYPT_MACHINE_KEY_FLAG, n, NULL));
    CHECK(!k_has_name(p, 0, n, NULL));
    EXPECT_S(U(NCryptOpenKey)(p, &k2, n, 0, 0), NTE_BAD_KEYSET);
    EXPECT_S(U(NCryptOpenKey)(p, &k2, n, 0, NCRYPT_MACHINE_KEY_FLAG | NCRYPT_SILENT_FLAG), 0);
    if (k2) {
        DWORD v = 0, cb;
        EXPECT_S(U(NCryptGetProperty)(k2, NCRYPT_KEY_TYPE_PROPERTY, (PBYTE)&v, 4, &cb, 0), 0);
        EXPECT_EQ(v & NCRYPT_MACHINE_KEY_FLAG, NCRYPT_MACHINE_KEY_FLAG);
        k_free(k2);
    }
    k_free(k);
    EXPECT_S(k_del(p, n, NCRYPT_MACHINE_KEY_FLAG), 0);
    CHECK(!k_has_name(p, NCRYPT_MACHINE_KEY_FLAG, n, NULL));
    k_free(p);
}
TEST(dxpk_machine_and_user_same_name_independent) {
    KP_BEGIN(p); WCHAR n[96]; k_name(n, 96, L"machuser");
    if (!k_is_admin()) { t_skip("not elevated"); k_free(p); return; }
    EXPECT_S(k_make(p, n, BCRYPT_RSA_ALGORITHM, 1024, 0, 0, NULL), 0);
    EXPECT_S(k_make(p, n, BCRYPT_RSA_ALGORITHM, 1024, 0, NCRYPT_MACHINE_KEY_FLAG, NULL), 0);
    EXPECT_S(k_del(p, n, 0), 0);
    CHECK(k_has_name(p, NCRYPT_MACHINE_KEY_FLAG, n, NULL));
    EXPECT_S(k_del(p, n, NCRYPT_MACHINE_KEY_FLAG), 0);
    k_free(p);
}
TEST(dxpk_machine_key_enumeration_non_admin) {
    KP_BEGIN(p); PVOID st = NULL; NCryptKeyName *kn;
    SECURITY_STATUS s = U(NCryptEnumKeys)(p, NULL, &kn, &st, NCRYPT_MACHINE_KEY_FLAG | NCRYPT_SILENT_FLAG);
    t_note("machine enum (elevated=%d) -> 0x%08lx", k_is_admin(), S(s));
    if (!s) { EXPECT_EQ(kn->dwFlags & NCRYPT_MACHINE_KEY_FLAG, NCRYPT_MACHINE_KEY_FLAG); U(NCryptFreeBuffer)(kn); }
    if (st) U(NCryptFreeBuffer)(st);
    k_free(p);
}
TEST(dxpk_machine_key_create_non_admin) {
    KP_BEGIN(p); WCHAR n[96]; k_name(n, 96, L"machna"); NCRYPT_KEY_HANDLE k = 0;
    if (k_is_admin()) { t_skip("elevated; non-admin path not exercised"); k_free(p); return; }
    SECURITY_STATUS s = k_make(p, n, BCRYPT_RSA_ALGORITHM, 1024, 0, NCRYPT_MACHINE_KEY_FLAG, &k);
    t_note("non-admin machine key create/finalize -> 0x%08lx", S(s));
    if (!s) { k_free(k); k_del(p, n, NCRYPT_MACHINE_KEY_FLAG); }
    k_free(p);
}
TEST(dxpk_machine_open_missing) {
    KP_BEGIN(p); WCHAR n[96]; k_name(n, 96, L"machmiss"); NCRYPT_KEY_HANDLE k = 0;
    SECURITY_STATUS s = U(NCryptOpenKey)(p, &k, n, 0, NCRYPT_MACHINE_KEY_FLAG | NCRYPT_SILENT_FLAG);
    if (k_is_admin()) EXPECT_S(s, NTE_BAD_KEYSET); else t_note("non-elevated machine open of missing key -> 0x%08lx", S(s));
    if (!s) k_free(k);
    k_free(p);
}
