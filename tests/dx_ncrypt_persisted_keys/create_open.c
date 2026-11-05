#include "dxk.h"

TEST(dxpk_create_null_phkey) {
    K_BEGIN(p); WCHAR n[96]; k_name(n, 96, L"nullph");
    EXPECT_S(U(NCryptCreatePersistedKey)(p, NULL, BCRYPT_RSA_ALGORITHM, n, 0, 0), NTE_INVALID_PARAMETER);
    EXPECT_S(U(NCryptOpenKey)(p, NULL, n, 0, 0), NTE_INVALID_PARAMETER);
    CHECK(!k_has_name(p, 0, n, NULL));
    k_free(p);
}
TEST(dxpk_create_open_invalid_provider) {
    K_NEEDS(); NCRYPT_KEY_HANDLE k = 0x1234;
    EXPECT_S(U(NCryptCreatePersistedKey)(0, &k, BCRYPT_RSA_ALGORITHM, L"cryptt_x", 0, 0), NTE_INVALID_HANDLE);
    EXPECT_EQ(k, 0x1234);
    k = 0x1234;
    EXPECT_S(U(NCryptOpenKey)(0, &k, L"cryptt_x", 0, 0), NTE_INVALID_HANDLE);
    EXPECT_EQ(k, 0x1234);
}
TEST(dxpk_provider_check_wrong_object_type) {
    /* a key handle is not a provider handle */
    K_BEGIN(p); NCRYPT_KEY_HANDLE k = 0, k2 = 0;
    CHECK(!U(NCryptCreatePersistedKey)(p, &k, BCRYPT_RSA_ALGORITHM, NULL, 0, 0));
    if (k) {
        EXPECT_S(U(NCryptCreatePersistedKey)(k, &k2, BCRYPT_RSA_ALGORITHM, NULL, 0, 0), NTE_INVALID_HANDLE);
        EXPECT_S(U(NCryptOpenKey)(k, &k2, L"cryptt_none", 0, 0), NTE_INVALID_HANDLE);
        EXPECT_S(U(NCryptEnumKeys)(k, NULL, (NCryptKeyName **)&k2, (PVOID *)&k2, 0), NTE_INVALID_HANDLE);
        k_free(k);
    }
    k_free(p);
}
TEST(dxpk_create_basic_lifecycle) {
    KP_BEGIN(p); WCHAR n[96]; k_name(n, 96, L"basic"); NCRYPT_KEY_HANDLE k = 0, k2 = 0;
    EXPECT_S(U(NCryptCreatePersistedKey)(p, &k, BCRYPT_RSA_ALGORITHM, n, 0, 0), 0);
    CHECK(k != 0);
    /* not persisted before finalize */
    EXPECT_S(U(NCryptOpenKey)(p, &k2, n, 0, 0), NTE_BAD_KEYSET);
    EXPECT_S(U(NCryptFinalizeKey)(k, 0), 0);
    EXPECT_S(U(NCryptOpenKey)(p, &k2, n, 0, 0), 0);
    CHECK(k2 != 0 && k2 != k);
    k_free(k2);
    EXPECT_S(U(NCryptDeleteKey)(k, 0), 0);
    EXPECT_S(U(NCryptOpenKey)(p, &k2, n, 0, 0), NTE_BAD_KEYSET);
    k_free(p);
}
TEST(dxpk_unfinalized_key_not_listed) {
    KP_BEGIN(p); WCHAR n[96]; k_name(n, 96, L"unfin"); NCRYPT_KEY_HANDLE k = 0;
    EXPECT_S(U(NCryptCreatePersistedKey)(p, &k, BCRYPT_RSA_ALGORITHM, n, 0, 0), 0);
    CHECK(!k_has_name(p, 0, n, NULL));
    k_free(k);
    CHECK(!k_has_name(p, 0, n, NULL));
    NCRYPT_KEY_HANDLE k2 = 0;
    EXPECT_S(U(NCryptOpenKey)(p, &k2, n, 0, 0), NTE_BAD_KEYSET);
    k_free(p);
}
TEST(dxpk_create_exists) {
    KP_BEGIN(p); WCHAR n[96]; k_name(n, 96, L"exists"); NCRYPT_KEY_HANDLE k = 0, k2 = 0;
    EXPECT_S(k_make(p, n, BCRYPT_RSA_ALGORITHM, 1024, 0, 0, NULL), 0);
    EXPECT_S(U(NCryptCreatePersistedKey)(p, &k, BCRYPT_RSA_ALGORITHM, n, 0, 0), NTE_EXISTS);
    CHECK(k == 0);
    EXPECT_S(U(NCryptCreatePersistedKey)(p, &k, BCRYPT_ECDSA_P256_ALGORITHM, n, 0, 0), NTE_EXISTS);
    /* same name differing only in case is the same key */
    WCHAR up[96]; lstrcpyW(up, n); CharUpperW(up);
    SECURITY_STATUS s = U(NCryptCreatePersistedKey)(p, &k, BCRYPT_RSA_ALGORITHM, up, 0, 0);
    t_note("create with case-changed name -> 0x%08lx", S(s)); if (!s) k_free(k);
    k_free(p);
}
TEST(dxpk_overwrite_flag) {
    KP_BEGIN(p); WCHAR n[96]; k_name(n, 96, L"overw"); NCRYPT_KEY_HANDLE k = 0, k2 = 0;
    EXPECT_S(k_make(p, n, BCRYPT_RSA_ALGORITHM, 1024, 0, 0, NULL), 0);
    EXPECT_S(U(NCryptCreatePersistedKey)(p, &k, BCRYPT_ECDSA_P256_ALGORITHM, n, 0, NCRYPT_OVERWRITE_KEY_FLAG), 0);
    CHECK(k != 0);
    /* old key remains until the replacement is finalized */
    { SECURITY_STATUS so = U(NCryptOpenKey)(p, &k2, n, 0, 0);
      WCHAR alg[64] = {0}; DWORD cb = 0;
      t_note("pre-finalize open of overwrite target -> 0x%08lx", S(so));
      if (!so) { U(NCryptGetProperty)(k2, NCRYPT_ALGORITHM_PROPERTY, (PBYTE)alg, sizeof alg, &cb, 0);
        t_note("pre-finalize open of overwritten key sees alg %ls", alg); k_free(k2); } }
    EXPECT_S(U(NCryptFinalizeKey)(k, 0), 0);
    k2 = 0;
    EXPECT_S(U(NCryptOpenKey)(p, &k2, n, 0, 0), 0);
    if (k2) {
        WCHAR alg[64] = {0}; DWORD cb = 0;
        EXPECT_S(U(NCryptGetProperty)(k2, NCRYPT_ALGORITHM_PROPERTY, (PBYTE)alg, sizeof alg, &cb, 0), 0);
        EXPECT_WSTR(alg, BCRYPT_ECDSA_P256_ALGORITHM);
        k_free(k2);
    }
    k_free(k);
    k_free(p);
}
TEST(dxpk_overwrite_on_missing_key) {
    KP_BEGIN(p); WCHAR n[96]; k_name(n, 96, L"overwnone"); NCRYPT_KEY_HANDLE k = 0;
    EXPECT_S(U(NCryptCreatePersistedKey)(p, &k, BCRYPT_RSA_ALGORITHM, n, 0, NCRYPT_OVERWRITE_KEY_FLAG), 0);
    EXPECT_S(U(NCryptFinalizeKey)(k, 0), 0);
    CHECK(k_has_name(p, 0, n, NULL));
    k_free(k); k_free(p);
}
TEST(dxpk_open_missing) {
    KP_BEGIN(p); WCHAR n[96]; k_name(n, 96, L"missing"); NCRYPT_KEY_HANDLE k = 0x55;
    DWORD fl[] = { 0, NCRYPT_SILENT_FLAG };
    for (int i = 0; i < 2; i++) {
        k = 0x55;
        EXPECT_S(U(NCryptOpenKey)(p, &k, n, 0, fl[i]), NTE_BAD_KEYSET);
        EXPECT_EQ(k, 0x55);
    }
    DWORD specs[] = { AT_KEYEXCHANGE, AT_SIGNATURE };
    for (int i = 0; i < 2; i++) EXPECT_S(U(NCryptOpenKey)(p, &k, n, specs[i], NCRYPT_SILENT_FLAG), NTE_BAD_KEYSET);
    k_free(p);
}
TEST(dxpk_open_after_provider_reopen) {
    KP_BEGIN(p); WCHAR n[96]; k_name(n, 96, L"reopen"); NCRYPT_KEY_HANDLE k = 0;
    EXPECT_S(k_make(p, n, BCRYPT_RSA_ALGORITHM, 1024, 0, 0, NULL), 0);
    EXPECT_S(U(NCryptFreeObject)(p), 0);
    NCRYPT_PROV_HANDLE p2 = 0;
    EXPECT_S(k_prov(&p2), 0);
    EXPECT_S(U(NCryptOpenKey)(p2, &k, n, 0, 0), 0);
    CHECK(k != 0);
    if (k) {
        WCHAR nm[96] = {0}; DWORD cb = 0;
        EXPECT_S(U(NCryptGetProperty)(k, NCRYPT_NAME_PROPERTY, (PBYTE)nm, sizeof nm, &cb, 0), 0);
        EXPECT_WSTR(nm, n);
        EXPECT_EQ(cb, (lstrlenW(n) + 1) * 2);
        k_free(k);
    }
    EXPECT_S(k_del(p2, n, 0), 0);
    k_free(p2);
}
TEST(dxpk_key_handle_closed_does_not_delete) {
    KP_BEGIN(p); WCHAR n[96]; k_name(n, 96, L"closekeep"); NCRYPT_KEY_HANDLE k = 0, k2 = 0;
    EXPECT_S(k_make(p, n, BCRYPT_RSA_ALGORITHM, 1024, 0, 0, &k), 0);
    EXPECT_S(U(NCryptFreeObject)(k), 0);
    EXPECT_S(U(NCryptOpenKey)(p, &k2, n, 0, 0), 0);
    k_free(k2); k_free(p);
}
TEST(dxpk_two_handles_same_key) {
    KP_BEGIN(p); WCHAR n[96]; k_name(n, 96, L"twohandles"); NCRYPT_KEY_HANDLE a = 0, b = 0;
    EXPECT_S(k_make(p, n, BCRYPT_RSA_ALGORITHM, 1024, 0, 0, &a), 0);
    EXPECT_S(U(NCryptOpenKey)(p, &b, n, 0, 0), 0);
    CHECK(a != b);
    WCHAR u1[128] = {0}, u2[128] = {0}; DWORD c1, c2;
    if (a && b) {
        EXPECT_S(U(NCryptGetProperty)(a, NCRYPT_UNIQUE_NAME_PROPERTY, (PBYTE)u1, sizeof u1, &c1, 0), 0);
        EXPECT_S(U(NCryptGetProperty)(b, NCRYPT_UNIQUE_NAME_PROPERTY, (PBYTE)u2, sizeof u2, &c2, 0), 0);
        EXPECT_WSTR(u1, u2); CHECK(u1[0] != 0);
    }
    k_free(a); k_free(b); k_free(p);
}
TEST(dxpk_legacy_keyspec_roundtrip) {
    KP_BEGIN(p); NCryptKeyName info;
    struct { const WCHAR *tag; DWORD spec; } t[] = { {L"spec0", 0}, {L"specx", AT_KEYEXCHANGE}, {L"specs", AT_SIGNATURE} };
    for (int i = 0; i < 3; i++) {
        WCHAR n[96]; k_name(n, 96, t[i].tag);
        EXPECT_S(k_make(p, n, BCRYPT_RSA_ALGORITHM, 1024, t[i].spec, 0, NULL), 0);
        memset(&info, 0xAA, sizeof info);
        CHECKF(k_has_name(p, 0, n, &info), "spec %lu", t[i].spec);
        if (t[i].spec) EXPECT_EQ(info.dwLegacyKeySpec, t[i].spec);
        else t_note("enumerated legacy spec for key created with spec 0: %lu", info.dwLegacyKeySpec);
        NCRYPT_KEY_HANDLE k = 0;
        EXPECT_S(U(NCryptOpenKey)(p, &k, n, t[i].spec, NCRYPT_SILENT_FLAG), 0);
        k_free(k);
    }
    k_free(p);
}
TEST(dxpk_legacy_keyspec_invalid_note) {
    KP_BEGIN(p); WCHAR n[96]; k_name(n, 96, L"badspec"); NCRYPT_KEY_HANDLE k = 0;
    DWORD specs[] = { 3, 0x10, 0xFFFFFFFF };
    for (int i = 0; i < 3; i++) {
        SECURITY_STATUS s = U(NCryptCreatePersistedKey)(p, &k, BCRYPT_RSA_ALGORITHM, n, specs[i], 0);
        t_note("create keyspec 0x%lx -> 0x%08lx", specs[i], S(s));
        if (!s) k_free(k);
    }
    k_free(p);
}
TEST(dxpk_create_bad_algid) {
    KP_BEGIN(p); WCHAR n[96]; k_name(n, 96, L"badalg"); NCRYPT_KEY_HANDLE k = 0;
    const WCHAR *algs[] = { L"NOT_AN_ALGORITHM", L"", BCRYPT_SHA256_ALGORITHM, BCRYPT_AES_ALGORITHM };
    for (int i = 0; i < 4; i++) {
        k = 0;
        SECURITY_STATUS s = U(NCryptCreatePersistedKey)(p, &k, algs[i], n, 0, 0);
        CHECKF(s != 0, "alg %d accepted", i);
        t_note("create alg[%d] -> 0x%08lx", i, S(s));
        if (!s) k_free(k);
    }
    CHECK(!k_has_name(p, 0, n, NULL));
    k_free(p);
}
TEST(dxpk_create_null_algid) {
    KP_BEGIN(p); WCHAR n[96]; k_name(n, 96, L"nullalg"); NCRYPT_KEY_HANDLE k = 0;
    SECURITY_STATUS s = U(NCryptCreatePersistedKey)(p, &k, NULL, n, 0, 0);
    CHECK(s != 0); t_note("NULL algid -> 0x%08lx", S(s));
    if (!s) k_free(k);
    k_free(p);
}
TEST(dxpk_create_bad_flags) {
    KP_BEGIN(p); WCHAR n[96]; k_name(n, 96, L"badflags"); NCRYPT_KEY_HANDLE k = 0;
    DWORD fl[] = { 0x10000, 0x01000000, 0x08, 0x10 };
    for (int i = 0; i < 4; i++) {
        k = 0; SECURITY_STATUS s = U(NCryptCreatePersistedKey)(p, &k, BCRYPT_RSA_ALGORITHM, n, 0, fl[i]);
        t_note("create flags 0x%lx -> 0x%08lx", fl[i], S(s));
        if (!s) k_free(k);
    }
    k_free(p);
}
TEST(dxpk_open_bad_flags) {
    KP_BEGIN(p); WCHAR n[96]; k_name(n, 96, L"obadf"); NCRYPT_KEY_HANDLE k = 0;
    EXPECT_S(k_make(p, n, BCRYPT_RSA_ALGORITHM, 1024, 0, 0, NULL), 0);
    DWORD fl[] = { 0x10000, 0x01000000, NCRYPT_OVERWRITE_KEY_FLAG };
    for (int i = 0; i < 3; i++) {
        k = 0; SECURITY_STATUS s = U(NCryptOpenKey)(p, &k, n, 0, fl[i]);
        t_note("open flags 0x%lx -> 0x%08lx", fl[i], S(s));
        if (!s) k_free(k);
    }
    k_free(p);
}
TEST(dxpk_name_variants) {
    KP_BEGIN(p);
    const WCHAR *tags[] = { L"a", L"sp ace", L"dot.dot", L"unié中", L"dash-under_x", L"x'y" };
    for (int i = 0; i < 6; i++) {
        WCHAR n[96]; k_name(n, 96, tags[i]); NCRYPT_KEY_HANDLE k = 0;
        SECURITY_STATUS s = k_make(p, n, BCRYPT_RSA_ALGORITHM, 1024, 0, 0, NULL);
        CHECKF(s == 0, "tag %d status 0x%08lx", i, S(s));
        if (!s) {
            NCryptKeyName ki; CHECKF(k_has_name(p, 0, n, &ki), "tag %d not enumerated", i);
            EXPECT_S(U(NCryptOpenKey)(p, &k, n, 0, 0), 0); k_free(k);
            EXPECT_S(k_del(p, n, 0), 0);
        }
    }
    k_free(p);
}
TEST(dxpk_name_case_insensitive_open) {
    KP_BEGIN(p); WCHAR n[96], up[96]; k_name(n, 96, L"CaseKey"); NCRYPT_KEY_HANDLE k = 0;
    EXPECT_S(k_make(p, n, BCRYPT_RSA_ALGORITHM, 1024, 0, 0, NULL), 0);
    lstrcpyW(up, n); CharUpperW(up);
    SECURITY_STATUS s = U(NCryptOpenKey)(p, &k, up, 0, 0);
    t_note("open with upper-cased name -> 0x%08lx", S(s)); if (!s) k_free(k);
    k_free(p);
}
TEST(dxpk_long_name) {
    KP_BEGIN(p); WCHAR n[260]; NCRYPT_KEY_HANDLE k = 0; int i;
    k_name(n, 260, L"");
    int base = lstrlenW(n);
    for (i = base; i < 120; i++) n[i] = L'L';
    n[120] = 0;
    SECURITY_STATUS s = k_make(p, n, BCRYPT_RSA_ALGORITHM, 1024, 0, 0, NULL);
    if (s) t_note("120-char key name create -> 0x%08lx", S(s));
    if (!s) { EXPECT_S(U(NCryptOpenKey)(p, &k, n, 0, 0), 0); k_free(k); CHECK(k_has_name(p, 0, n, NULL)); }
    k_free(p);
}
TEST(dxpk_empty_name_note) {
    KP_BEGIN(p); NCRYPT_KEY_HANDLE k = 0; NCRYPT_KEY_HANDLE k2 = 0;
    SECURITY_STATUS s = U(NCryptOpenKey)(p, &k, L"", 0, 0);
    t_note("open empty name -> 0x%08lx", S(s)); if (!s) k_free(k);
    s = U(NCryptOpenKey)(p, &k, NULL, 0, 0);
    t_note("open NULL name -> 0x%08lx", S(s)); if (!s) k_free(k);
    CHECK(s != 0);
    k_free(p);
}
TEST(dxpk_ephemeral_null_name) {
    KP_BEGIN(p); NCRYPT_KEY_HANDLE k = 0;
    EXPECT_S(U(NCryptCreatePersistedKey)(p, &k, BCRYPT_RSA_ALGORITHM, NULL, 0, 0), 0);
    CHECK(k != 0);
    DWORD bits = 1024;
    EXPECT_S(U(NCryptSetProperty)(k, NCRYPT_LENGTH_PROPERTY, (PBYTE)&bits, 4, 0), 0);
    EXPECT_S(U(NCryptFinalizeKey)(k, 0), 0);
    WCHAR nm[64] = {0}; DWORD cb = 0;
    SECURITY_STATUS s = U(NCryptGetProperty)(k, NCRYPT_NAME_PROPERTY, (PBYTE)nm, sizeof nm, &cb, 0);
    t_note("Name property of ephemeral key -> 0x%08lx", S(s));
    k_free(k); k_free(p);
}
TEST(dxpk_ephemeral_delete_note) {
    KP_BEGIN(p); NCRYPT_KEY_HANDLE k = 0;
    EXPECT_S(U(NCryptCreatePersistedKey)(p, &k, BCRYPT_RSA_ALGORITHM, NULL, 0, 0), 0);
    DWORD bits = 1024; U(NCryptSetProperty)(k, NCRYPT_LENGTH_PROPERTY, (PBYTE)&bits, 4, 0);
    EXPECT_S(U(NCryptFinalizeKey)(k, 0), 0);
    SECURITY_STATUS s = U(NCryptDeleteKey)(k, 0);
    t_note("delete ephemeral key -> 0x%08lx", S(s));
    if (s) k_free(k);
    k_free(p);
}
TEST(dxpk_default_properties) {
    KP_BEGIN(p); WCHAR n[96]; k_name(n, 96, L"props"); NCRYPT_KEY_HANDLE k = 0;
    EXPECT_S(k_make(p, n, BCRYPT_RSA_ALGORITHM, 1024, AT_KEYEXCHANGE, 0, &k), 0);
    DWORD v = 0, cb = 0;
    EXPECT_S(U(NCryptGetProperty)(k, NCRYPT_LENGTH_PROPERTY, (PBYTE)&v, 4, &cb, 0), 0);
    EXPECT_EQ(v, 1024); EXPECT_EQ(cb, 4);
    v = 0; EXPECT_S(U(NCryptGetProperty)(k, NCRYPT_IMPL_TYPE_PROPERTY, (PBYTE)&v, 4, &cb, 0), 0);
    EXPECT_EQ(v, NCRYPT_IMPL_SOFTWARE_FLAG);
    v = 99; EXPECT_S(U(NCryptGetProperty)(k, NCRYPT_KEY_TYPE_PROPERTY, (PBYTE)&v, 4, &cb, 0), 0);
    EXPECT_EQ(v, 0);
    WCHAR g[64] = {0};
    EXPECT_S(U(NCryptGetProperty)(k, NCRYPT_ALGORITHM_GROUP_PROPERTY, (PBYTE)g, sizeof g, &cb, 0), 0);
    EXPECT_WSTR(g, NCRYPT_RSA_ALGORITHM_GROUP);
    WCHAR a[64] = {0};
    EXPECT_S(U(NCryptGetProperty)(k, NCRYPT_ALGORITHM_PROPERTY, (PBYTE)a, sizeof a, &cb, 0), 0);
    EXPECT_WSTR(a, BCRYPT_RSA_ALGORITHM);
    v = 0; SECURITY_STATUS s = U(NCryptGetProperty)(k, NCRYPT_KEY_USAGE_PROPERTY, (PBYTE)&v, 4, &cb, 0);
    t_note("key usage 0x%lx status 0x%08lx", v, S(s));
    v = 0xff; s = U(NCryptGetProperty)(k, NCRYPT_EXPORT_POLICY_PROPERTY, (PBYTE)&v, 4, &cb, 0);
    t_note("default export policy 0x%lx status 0x%08lx", v, S(s));
    k_free(k); k_free(p);
}
TEST(dxpk_name_property_buffer_protocol) {
    KP_BEGIN(p); WCHAR n[96]; k_name(n, 96, L"nameprot"); NCRYPT_KEY_HANDLE k = 0;
    EXPECT_S(k_make(p, n, BCRYPT_RSA_ALGORITHM, 1024, 0, 0, &k), 0);
    DWORD need = (lstrlenW(n) + 1) * 2, cb = 0; WCHAR buf[128];
    EXPECT_S(U(NCryptGetProperty)(k, NCRYPT_NAME_PROPERTY, NULL, 0, &cb, 0), 0);
    EXPECT_EQ(cb, need);
    cb = 0; EXPECT_S(U(NCryptGetProperty)(k, NCRYPT_NAME_PROPERTY, (PBYTE)buf, need - 1, &cb, 0), NTE_BUFFER_TOO_SMALL);
    EXPECT_EQ(cb, need);
    cb = 0; EXPECT_S(U(NCryptGetProperty)(k, NCRYPT_NAME_PROPERTY, (PBYTE)buf, 0, &cb, 0), NTE_BUFFER_TOO_SMALL);
    EXPECT_EQ(cb, need);
    cb = 0; EXPECT_S(U(NCryptGetProperty)(k, NCRYPT_NAME_PROPERTY, (PBYTE)buf, need, &cb, 0), 0);
    EXPECT_EQ(cb, need);
    { SECURITY_STATUS s = U(NCryptGetProperty)(k, NCRYPT_NAME_PROPERTY, (PBYTE)buf, need, NULL, 0); t_note("NULL pcbResult -> 0x%08lx", S(s)); }
    k_free(k); k_free(p);
}
TEST(dxpk_set_length_before_finalize) {
    KP_BEGIN(p); WCHAR n[96]; k_name(n, 96, L"len"); NCRYPT_KEY_HANDLE k = 0;
    DWORD sizes[] = { 512, 1024, 1536 };
    for (int i = 0; i < 3; i++) {
        k_name(n, 96, i == 0 ? L"len0" : i == 1 ? L"len1" : L"len2");
        EXPECT_S(k_make(p, n, BCRYPT_RSA_ALGORITHM, sizes[i], 0, 0, &k), 0);
        DWORD v = 0, cb;
        EXPECT_S(U(NCryptGetProperty)(k, NCRYPT_LENGTH_PROPERTY, (PBYTE)&v, 4, &cb, 0), 0);
        EXPECT_EQ(v, sizes[i]);
        k_free(k);
    }
    k_free(p);
}
TEST(dxpk_set_length_after_finalize) {
    KP_BEGIN(p); WCHAR n[96]; k_name(n, 96, L"lenpost"); NCRYPT_KEY_HANDLE k = 0;
    EXPECT_S(k_make(p, n, BCRYPT_RSA_ALGORITHM, 1024, 0, 0, &k), 0);
    DWORD bits = 2048;
    SECURITY_STATUS s = U(NCryptSetProperty)(k, NCRYPT_LENGTH_PROPERTY, (PBYTE)&bits, 4, 0);
    t_note("set length after finalize -> 0x%08lx", S(s));
    DWORD v = 0, cb; U(NCryptGetProperty)(k, NCRYPT_LENGTH_PROPERTY, (PBYTE)&v, 4, &cb, 0);
    if (s) EXPECT_EQ(v, 1024);
    k_free(k); k_free(p);
}
TEST(dxpk_finalize_twice) {
    KP_BEGIN(p); WCHAR n[96]; k_name(n, 96, L"fin2"); NCRYPT_KEY_HANDLE k = 0;
    EXPECT_S(k_make(p, n, BCRYPT_RSA_ALGORITHM, 1024, 0, 0, &k), 0);
    SECURITY_STATUS s = U(NCryptFinalizeKey)(k, 0);
    t_note("second finalize -> 0x%08lx", S(s));
    EXPECT_S(U(NCryptFinalizeKey)(0, 0), NTE_INVALID_HANDLE);
    k_free(k); k_free(p);
}
TEST(dxpk_persisted_algorithms) {
    KP_BEGIN(p);
    struct { const WCHAR *alg; const WCHAR *tag; DWORD bits; } t[] = {
        { BCRYPT_RSA_ALGORITHM, L"a_rsa", 1024 }, { BCRYPT_ECDSA_P256_ALGORITHM, L"a_ecdsa256", 0 },
        { BCRYPT_ECDSA_P384_ALGORITHM, L"a_ecdsa384", 0 }, { BCRYPT_ECDH_P256_ALGORITHM, L"a_ecdh256", 0 },
        { BCRYPT_ECDH_P384_ALGORITHM, L"a_ecdh384", 0 }, { BCRYPT_ECDSA_P521_ALGORITHM, L"a_ecdsa521", 0 },
        { BCRYPT_DSA_ALGORITHM, L"a_dsa", 1024 }, { BCRYPT_DH_ALGORITHM, L"a_dh", 512 },
    };
    for (int i = 0; i < 8; i++) {
        WCHAR n[96]; k_name(n, 96, t[i].tag); NCRYPT_KEY_HANDLE k = 0;
        SECURITY_STATUS s = k_make(p, n, t[i].alg, t[i].bits, 0, 0, &k);
        if (s) { t_note("%ls persisted creation -> 0x%08lx", t[i].alg, S(s)); continue; }
        WCHAR a[64] = {0}; DWORD cb;
        EXPECT_S(U(NCryptGetProperty)(k, NCRYPT_ALGORITHM_PROPERTY, (PBYTE)a, sizeof a, &cb, 0), 0);
        EXPECT_WSTR(a, t[i].alg);
        k_free(k);
        NCRYPT_KEY_HANDLE k2 = 0;
        EXPECT_S(U(NCryptOpenKey)(p, &k2, n, 0, 0), 0);
        k_free(k2);
        EXPECT_S(k_del(p, n, 0), 0);
    }
    k_free(p);
}

TEST(dxpk_is_key_handle) {
    KP_BEGIN(p); WCHAR n[96]; k_name(n, 96, L"iskey"); NCRYPT_KEY_HANDLE k = 0, e = 0;
    REQUIRE(U(NCryptIsKeyHandle));
    CHECK(!U(NCryptIsKeyHandle)(0));
    CHECK(!U(NCryptIsKeyHandle)(p));            /* provider handle is not a key */
    EXPECT_S(k_make(p, n, BCRYPT_RSA_ALGORITHM, 1024, 0, 0, &k), 0);
    CHECK(U(NCryptIsKeyHandle)(k));
    EXPECT_S(U(NCryptCreatePersistedKey)(p, &e, BCRYPT_ECDSA_P256_ALGORITHM, NULL, 0, 0), 0);
    CHECK(U(NCryptIsKeyHandle)(e));              /* unfinalized ephemeral key is a key handle too */
    k_free(e);
    k_free(k); k_del(p, n, 0); k_free(p);
}
TEST(dxpk_create_null_phkey_before_provider_check) {
    /* phKey is validated before the provider handle (decomp order) */
    K_NEEDS();
    EXPECT_S(U(NCryptCreatePersistedKey)(0, NULL, BCRYPT_RSA_ALGORITHM, L"cryptt_x", 0, 0), NTE_INVALID_PARAMETER);
    EXPECT_S(U(NCryptOpenKey)(0, NULL, L"cryptt_x", 0, 0), NTE_INVALID_PARAMETER);
}
TEST(dxpk_provider_handle_survives_for_open_key) {
    /* a key handle keeps its provider alive: free provider, then still open another handle via a new provider */
    KP_BEGIN(p); WCHAR n[96]; k_name(n, 96, L"provref"); NCRYPT_KEY_HANDLE k = 0, k2 = 0; NCRYPT_PROV_HANDLE p2 = 0;
    EXPECT_S(k_make(p, n, BCRYPT_RSA_ALGORITHM, 1024, 0, 0, &k), 0);
    EXPECT_S(U(NCryptFreeObject)(p), 0);
    EXPECT_S(k_prov(&p2), 0);
    EXPECT_S(U(NCryptOpenKey)(p2, &k2, n, 0, NCRYPT_SILENT_FLAG), 0);
    k_free(k2); k_free(k);
    EXPECT_S(k_del(p2, n, 0), 0);
    k_free(p2);
}
TEST(dxpk_silent_flag_create_open) {
    KP_BEGIN(p); WCHAR n[96]; k_name(n, 96, L"silent"); NCRYPT_KEY_HANDLE k = 0, k2 = 0;
    EXPECT_S(U(NCryptCreatePersistedKey)(p, &k, BCRYPT_RSA_ALGORITHM, n, 0, NCRYPT_SILENT_FLAG), 0);
    DWORD bits = 1024; U(NCryptSetProperty)(k, NCRYPT_LENGTH_PROPERTY, (PBYTE)&bits, 4, 0);
    EXPECT_S(U(NCryptFinalizeKey)(k, NCRYPT_SILENT_FLAG), 0);
    EXPECT_S(U(NCryptOpenKey)(p, &k2, n, 0, NCRYPT_SILENT_FLAG), 0);
    k_free(k2); k_free(k);
    EXPECT_S(k_del(p, n, 0), 0);
    k_free(p);
}
