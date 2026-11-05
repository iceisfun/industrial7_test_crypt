#include "dxk.h"

TEST(dxpk_enum_param_validation) {
    K_BEGIN(p); NCryptKeyName *kn = NULL; PVOID st = NULL;
    EXPECT_S(U(NCryptEnumKeys)(p, NULL, NULL, &st, 0), NTE_INVALID_PARAMETER);
    EXPECT_S(U(NCryptEnumKeys)(p, NULL, &kn, NULL, 0), NTE_INVALID_PARAMETER);
    EXPECT_S(U(NCryptEnumKeys)(p, NULL, NULL, NULL, 0), NTE_INVALID_PARAMETER);
    EXPECT_S(U(NCryptEnumKeys)(0, NULL, &kn, &st, 0), NTE_INVALID_HANDLE);
    CHECK(kn == NULL && st == NULL);
    k_free(p);
}
TEST(dxpk_enum_bad_flags_note) {
    K_BEGIN(p); NCryptKeyName *kn = NULL; PVOID st = NULL;
    DWORD fl[] = { 0x10000, NCRYPT_OVERWRITE_KEY_FLAG, 0x01000000 };
    for (int i = 0; i < 3; i++) {
        kn = NULL; st = NULL;
        SECURITY_STATUS s = U(NCryptEnumKeys)(p, NULL, &kn, &st, fl[i]);
        t_note("enum flags 0x%lx -> 0x%08lx", fl[i], S(s));
        if (!s) U(NCryptFreeBuffer)(kn);
        if (st) U(NCryptFreeBuffer)(st);
    }
    k_free(p);
}
TEST(dxpk_enum_walk_finds_created_keys) {
    KP_BEGIN(p); WCHAR n[3][96]; int i;
    const WCHAR *tags[3] = { L"en_a", L"en_b", L"en_c" };
    for (i = 0; i < 3; i++) { k_name(n[i], 96, tags[i]); EXPECT_S(k_make(p, n[i], BCRYPT_RSA_ALGORITHM, 1024, i == 1 ? AT_SIGNATURE : 0, 0, NULL), 0); }
    int seen[3] = {0, 0, 0}; int total = 0; PVOID st = NULL; NCryptKeyName *kn;
    for (;;) {
        SECURITY_STATUS s = U(NCryptEnumKeys)(p, NULL, &kn, &st, NCRYPT_SILENT_FLAG);
        if (s) { EXPECT_S(s, NTE_NO_MORE_ITEMS); break; }
        CHECK(kn != NULL && kn->pszName != NULL && kn->pszAlgid != NULL);
        for (i = 0; i < 3; i++) if (!lstrcmpW(kn->pszName, n[i])) {
            seen[i]++;
            EXPECT_WSTR(kn->pszAlgid, BCRYPT_RSA_ALGORITHM);
            EXPECT_EQ(kn->dwLegacyKeySpec, i == 1 ? AT_SIGNATURE : 0);
            EXPECT_EQ(kn->dwFlags & NCRYPT_MACHINE_KEY_FLAG, 0);
        }
        total++;
        U(NCryptFreeBuffer)(kn);
        if (total > 10000) break;
    }
    if (st) U(NCryptFreeBuffer)(st);
    for (i = 0; i < 3; i++) EXPECT_EQ(seen[i], 1);
    for (i = 0; i < 3; i++) EXPECT_S(k_del(p, n[i], 0), 0);
    k_free(p);
}
TEST(dxpk_enum_end_is_sticky) {
    KP_BEGIN(p); PVOID st = NULL; NCryptKeyName *kn; SECURITY_STATUS s; int n = 0;
    while (!(s = U(NCryptEnumKeys)(p, NULL, &kn, &st, 0)) && n < 10000) { U(NCryptFreeBuffer)(kn); n++; }
    EXPECT_S(s, NTE_NO_MORE_ITEMS);
    kn = (NCryptKeyName *)0; 
    s = U(NCryptEnumKeys)(p, NULL, &kn, &st, 0);
    t_note("enum after end (same state) -> 0x%08lx", S(s));
    if (!s) U(NCryptFreeBuffer)(kn);
    if (st) U(NCryptFreeBuffer)(st);
    k_free(p);
}
TEST(dxpk_enum_restart_with_null_state) {
    KP_BEGIN(p); WCHAR n[96]; k_name(n, 96, L"restart");
    EXPECT_S(k_make(p, n, BCRYPT_RSA_ALGORITHM, 1024, 0, 0, NULL), 0);
    for (int round = 0; round < 3; round++) CHECKF(k_has_name(p, 0, n, NULL), "round %d", round);
    EXPECT_S(k_del(p, n, 0), 0);
    CHECK(!k_has_name(p, 0, n, NULL));
    k_free(p);
}
TEST(dxpk_enum_two_concurrent_walks) {
    KP_BEGIN(p); WCHAR n1[96], n2[96]; k_name(n1, 96, L"cw1"); k_name(n2, 96, L"cw2");
    EXPECT_S(k_make(p, n1, BCRYPT_RSA_ALGORITHM, 1024, 0, 0, NULL), 0);
    EXPECT_S(k_make(p, n2, BCRYPT_RSA_ALGORITHM, 1024, 0, 0, NULL), 0);
    PVOID s1 = NULL, s2 = NULL; NCryptKeyName *a, *b; int c1 = 0, c2 = 0;
    for (;;) {
        SECURITY_STATUS r1 = U(NCryptEnumKeys)(p, NULL, &a, &s1, 0);
        if (!r1) { c1++; U(NCryptFreeBuffer)(a); }
        SECURITY_STATUS r2 = U(NCryptEnumKeys)(p, NULL, &b, &s2, 0);
        if (!r2) { c2++; U(NCryptFreeBuffer)(b); }
        if (r1 && r2) break;
        if (c1 > 10000) break;
    }
    EXPECT_EQ(c1, c2);
    CHECK(c1 >= 2);
    if (s1) U(NCryptFreeBuffer)(s1);
    if (s2) U(NCryptFreeBuffer)(s2);
    k_del(p, n1, 0); k_del(p, n2, 0); k_free(p);
}
TEST(dxpk_enum_deleted_key_disappears) {
    KP_BEGIN(p); WCHAR n[96]; k_name(n, 96, L"enumdel"); NCRYPT_KEY_HANDLE k = 0;
    EXPECT_S(k_make(p, n, BCRYPT_RSA_ALGORITHM, 1024, 0, 0, &k), 0);
    CHECK(k_has_name(p, 0, n, NULL));
    EXPECT_S(U(NCryptDeleteKey)(k, 0), 0);
    CHECK(!k_has_name(p, 0, n, NULL));
    k_free(p);
}
TEST(dxpk_enum_ec_algids) {
    KP_BEGIN(p);
    struct { const WCHAR *alg, *tag; } t[] = { { BCRYPT_ECDSA_P256_ALGORITHM, L"ee_p256" }, { BCRYPT_ECDH_P384_ALGORITHM, L"ee_dh384" } };
    for (int i = 0; i < 2; i++) {
        WCHAR n[96]; k_name(n, 96, t[i].tag);
        if (k_make(p, n, t[i].alg, 0, 0, 0, NULL)) { t_note("no %ls support", t[i].alg); continue; }
        PVOID st = NULL; NCryptKeyName *kn; int found = 0;
        while (!U(NCryptEnumKeys)(p, NULL, &kn, &st, 0)) {
            if (!lstrcmpW(kn->pszName, n)) { found++; EXPECT_WSTR(kn->pszAlgid, t[i].alg); EXPECT_EQ(kn->dwLegacyKeySpec, 0); }
            U(NCryptFreeBuffer)(kn);
        }
        if (st) U(NCryptFreeBuffer)(st);
        EXPECT_EQ(found, 1);
        k_del(p, n, 0);
    }
    k_free(p);
}
TEST(dxpk_enum_scope_note) {
    KP_BEGIN(p); PVOID st = NULL; NCryptKeyName *kn;
    SECURITY_STATUS s = U(NCryptEnumKeys)(p, L"nonsense-scope", &kn, &st, 0);
    t_note("enum with non-NULL scope -> 0x%08lx", S(s));
    if (!s) U(NCryptFreeBuffer)(kn);
    if (st) U(NCryptFreeBuffer)(st);
    k_free(p);
}
TEST(dxpk_enum_keyname_block_layout) {
    /* name and algid strings live inside the single buffer freed by one NCryptFreeBuffer */
    KP_BEGIN(p); WCHAR n[96]; k_name(n, 96, L"layout");
    EXPECT_S(k_make(p, n, BCRYPT_RSA_ALGORITHM, 1024, 0, 0, NULL), 0);
    PVOID st = NULL; NCryptKeyName *kn; int ok = 0;
    while (!U(NCryptEnumKeys)(p, NULL, &kn, &st, 0)) {
        if (!lstrcmpW(kn->pszName, n)) {
            ok = 1;
            CHECK((BYTE *)kn->pszName > (BYTE *)kn && (BYTE *)kn->pszAlgid > (BYTE *)kn);
            CHECK((BYTE *)kn->pszName - (BYTE *)kn < 4096 && (BYTE *)kn->pszAlgid - (BYTE *)kn < 4096);
            EXPECT_EQ(lstrlenW(kn->pszName), lstrlenW(n));
        }
        U(NCryptFreeBuffer)(kn);
    }
    if (st) U(NCryptFreeBuffer)(st);
    CHECK(ok);
    k_del(p, n, 0); k_free(p);
}
TEST(dxpk_free_buffer_null) {
    K_NEEDS();
    SECURITY_STATUS s = U(NCryptFreeBuffer)(NULL);
    t_note("NCryptFreeBuffer(NULL) -> 0x%08lx", S(s));
}

/* ---- delete ---- */
TEST(dxpk_delete_invalid_handle) {
    K_BEGIN(p);
    EXPECT_S(U(NCryptDeleteKey)(0, 0), NTE_INVALID_HANDLE);
    EXPECT_S(U(NCryptDeleteKey)(0, NCRYPT_SILENT_FLAG), NTE_INVALID_HANDLE);
    EXPECT_S(U(NCryptDeleteKey)(p, 0), NTE_INVALID_HANDLE);   /* provider handle is not a key */
    EXPECT_S(U(NCryptFreeObject)(0), NTE_INVALID_HANDLE);
    k_free(p);
}
TEST(dxpk_delete_removes_and_invalidates) {
    KP_BEGIN(p); WCHAR n[96]; k_name(n, 96, L"del1"); NCRYPT_KEY_HANDLE k = 0, k2 = 0;
    EXPECT_S(k_make(p, n, BCRYPT_RSA_ALGORITHM, 1024, 0, 0, &k), 0);
    EXPECT_S(U(NCryptDeleteKey)(k, NCRYPT_SILENT_FLAG), 0);
    EXPECT_S(U(NCryptOpenKey)(p, &k2, n, 0, 0), NTE_BAD_KEYSET);
    CHECK(!k_has_name(p, 0, n, NULL));
    /* name is reusable after delete */
    EXPECT_S(k_make(p, n, BCRYPT_RSA_ALGORITHM, 1024, 0, 0, NULL), 0);
    EXPECT_S(k_del(p, n, 0), 0);
    k_free(p);
}
TEST(dxpk_delete_handle_unusable_afterwards) {
    KP_BEGIN(p); WCHAR n[96]; k_name(n, 96, L"del2"); NCRYPT_KEY_HANDLE k = 0;
    EXPECT_S(k_make(p, n, BCRYPT_RSA_ALGORITHM, 1024, 0, 0, &k), 0);
    EXPECT_S(U(NCryptDeleteKey)(k, 0), 0);
    DWORD v, cb;
    EXPECT_S(U(NCryptGetProperty)(k, NCRYPT_LENGTH_PROPERTY, (PBYTE)&v, 4, &cb, 0), NTE_INVALID_HANDLE);
    EXPECT_S(U(NCryptDeleteKey)(k, 0), NTE_INVALID_HANDLE);
    k_free(p);
}
TEST(dxpk_delete_missing_after_other_delete) {
    KP_BEGIN(p); WCHAR n[96]; k_name(n, 96, L"del3"); NCRYPT_KEY_HANDLE a = 0, b = 0;
    EXPECT_S(k_make(p, n, BCRYPT_RSA_ALGORITHM, 1024, 0, 0, &a), 0);
    EXPECT_S(U(NCryptOpenKey)(p, &b, n, 0, 0), 0);
    EXPECT_S(U(NCryptDeleteKey)(a, 0), 0);
    SECURITY_STATUS s = U(NCryptDeleteKey)(b, 0);
    CHECK(s != 0);
    t_note("delete of second handle after key already deleted -> 0x%08lx", S(s));
    if (s) k_free(b);
    k_free(p);
}
TEST(dxpk_delete_other_key_unaffected) {
    KP_BEGIN(p); WCHAR a[96], b[96]; k_name(a, 96, L"keepa"); k_name(b, 96, L"keepb"); NCRYPT_KEY_HANDLE k = 0;
    EXPECT_S(k_make(p, a, BCRYPT_RSA_ALGORITHM, 1024, 0, 0, NULL), 0);
    EXPECT_S(k_make(p, b, BCRYPT_RSA_ALGORITHM, 1024, 0, 0, NULL), 0);
    EXPECT_S(k_del(p, a, 0), 0);
    EXPECT_S(U(NCryptOpenKey)(p, &k, b, 0, 0), 0); k_free(k);
    EXPECT_S(k_del(p, b, 0), 0);
    k_free(p);
}
TEST(dxpk_delete_bad_flags_note) {
    KP_BEGIN(p); WCHAR n[96]; k_name(n, 96, L"delbf"); NCRYPT_KEY_HANDLE k = 0;
    EXPECT_S(k_make(p, n, BCRYPT_RSA_ALGORITHM, 1024, 0, 0, &k), 0);
    SECURITY_STATUS s = U(NCryptDeleteKey)(k, 0x10000);
    t_note("delete flags 0x10000 -> 0x%08lx", S(s));
    if (s) { EXPECT_S(U(NCryptDeleteKey)(k, 0), 0); }
    k_free(p);
}
TEST(dxpk_delete_key_then_provider_close) {
    KP_BEGIN(p); WCHAR n[96]; k_name(n, 96, L"delprov"); NCRYPT_KEY_HANDLE k = 0;
    EXPECT_S(k_make(p, n, BCRYPT_RSA_ALGORITHM, 1024, 0, 0, &k), 0);
    EXPECT_S(U(NCryptFreeObject)(p), 0);
    /* key handle holds a reference on the provider */
    EXPECT_S(U(NCryptDeleteKey)(k, 0), 0);
    NCRYPT_PROV_HANDLE p2; EXPECT_S(k_prov(&p2), 0);
    CHECK(!k_has_name(p2, 0, n, NULL));
    k_free(p2);
}
TEST(dxpk_key_survives_provider_free) {
    KP_BEGIN(p); WCHAR n[96]; k_name(n, 96, L"provfree"); NCRYPT_KEY_HANDLE k = 0;
    EXPECT_S(k_make(p, n, BCRYPT_RSA_ALGORITHM, 1024, 0, 0, &k), 0);
    EXPECT_S(U(NCryptFreeObject)(p), 0);
    WCHAR nm[96] = {0}; DWORD cb;
    EXPECT_S(U(NCryptGetProperty)(k, NCRYPT_NAME_PROPERTY, (PBYTE)nm, sizeof nm, &cb, 0), 0);
    EXPECT_WSTR(nm, n);
    NCRYPT_PROV_HANDLE p2; EXPECT_S(k_prov(&p2), 0);
    EXPECT_S(U(NCryptDeleteKey)(k, 0), 0);
    k_free(p2);
}
TEST(dxpk_free_object_twice) {
    KP_BEGIN(p);
    EXPECT_S(U(NCryptFreeObject)(p), 0);
    /* second free of a released handle is not exercised (freed memory); only the NULL case is */
    EXPECT_S(U(NCryptFreeObject)(0), NTE_INVALID_HANDLE);
}
