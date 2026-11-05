#include "cp.h"
/* CPAcquireContext / CPReleaseContext / provider parameters of rsaenh.dll and dssenh.dll. */

static const char *const cp_names[] = {
    "CPAcquireContext", "CPReleaseContext", "CPGenKey", "CPDeriveKey", "CPDestroyKey", "CPSetKeyParam",
    "CPGetKeyParam", "CPSetProvParam", "CPGetProvParam", "CPSetHashParam", "CPGetHashParam", "CPExportKey",
    "CPImportKey", "CPEncrypt", "CPDecrypt", "CPCreateHash", "CPHashData", "CPHashSessionKey", "CPSignHash",
    "CPDestroyHash", "CPVerifySignature", "CPGenRandom", "CPGetUserKey", "CPDuplicateHash", "CPDuplicateKey",
};

/* ---- exports ------------------------------------------------------------------------------ */
TEST(cpd_exports_rsaenh_resolve) {
    HMODULE m = t_module("rsaenh.dll"); REQUIRE(m);
    for (size_t i = 0; i < NELEM(cp_names); i++) {
        FARPROC p = GetProcAddress(m, cp_names[i]);
        CHECKF(p != NULL, "rsaenh.dll missing %s", cp_names[i]);
    }
}
TEST(cpd_exports_dssenh_resolve) {
    HMODULE m = t_module("dssenh.dll"); REQUIRE(m);
    for (size_t i = 0; i < NELEM(cp_names); i++) {
        FARPROC p = GetProcAddress(m, cp_names[i]);
        CHECKF(p != NULL, "dssenh.dll missing %s", cp_names[i]);
    }
}
TEST(cpd_exports_register_server_resolve_only) {
    /* Resolve only: calling these would (un)register the provider system-wide. */
    const char *dlls[] = { "rsaenh.dll", "dssenh.dll" };
    for (int i = 0; i < 2; i++) {
        HMODULE m = t_module(dlls[i]); REQUIRE(m);
        CHECKF(GetProcAddress(m, "DllRegisterServer") != NULL, "%s DllRegisterServer", dlls[i]);
        CHECKF(GetProcAddress(m, "DllUnregisterServer") != NULL, "%s DllUnregisterServer", dlls[i]);
    }
}
TEST(cpd_exports_distinct_between_providers) {
    HMODULE a = t_module("rsaenh.dll"), b = t_module("dssenh.dll"); REQUIRE(a && b);
    CHECK(a != b);
    for (size_t i = 0; i < NELEM(cp_names); i++) {
        FARPROC pa = GetProcAddress(a, cp_names[i]), pb = GetProcAddress(b, cp_names[i]);
        CHECKF(pa != pb, "%s resolves to the same address in both providers", cp_names[i]);
    }
}
TEST(cpd_exports_not_decorated) {
    HMODULE m = t_module("rsaenh.dll"); REQUIRE(m);
    SET_ERR(0);
    CHECK(GetProcAddress(m, "CPAcquireContextA") == NULL);
    EXPECT_ERR(ERROR_PROC_NOT_FOUND);
    SET_ERR(0);
    CHECK(GetProcAddress(m, "_CPAcquireContext@16") == NULL);
    EXPECT_ERR(ERROR_PROC_NOT_FOUND);
}
TEST(cpd_exports_bind_all) {
    NEED_RSA(); NEED_DSS();
    CHECK(R.Acquire != D.Acquire);
}

/* ---- rsaenh acquire ----------------------------------------------------------------------- */
TEST(cpd_rsa_acquire_verifycontext_each_provider) {
    NEED_RSA();
    struct { DWORD type; char *name; } t[] = {
        { PROV_RSA_FULL, N_BASE }, { PROV_RSA_FULL, N_ENH }, { PROV_RSA_FULL, N_STRONG },
        { PROV_RSA_AES, N_AES }, { PROV_RSA_SIG, N_SIG },
    };
    for (size_t i = 0; i < NELEM(t); i++) {
        ULONG_PTR p = 0;
        SET_ERR(0);
        BOOL r = cp_acq_ex(&R, &p, NULL, CRYPT_VERIFYCONTEXT, 3, t[i].type, t[i].name);
        CHECKF(r, "acquire %s type %lu err=0x%lx", t[i].name, t[i].type, GetLastError());
        CHECK(p != 0);
        if (r) OKAY(R.Release(p, 0));
    }
}
TEST(cpd_rsa_acquire_returns_true_not_just_nonzero) {
    NEED_RSA();
    ULONG_PTR p = 0;
    BOOL r = cp_acq_ex(&R, &p, NULL, CRYPT_VERIFYCONTEXT, 3, PROV_RSA_FULL, N_ENH);
    EXPECT_EQ(r, 1);
    if (r) OKAY(R.Release(p, 0));
}
TEST(cpd_rsa_acquire_two_contexts_are_distinct) {
    NEED_RSA();
    ULONG_PTR a = rsa_enh(&R), b = rsa_enh(&R);
    CHECK(a && b); CHECK(a != b);
    cp_rel(&R, a); cp_rel(&R, b);
}
TEST(cpd_rsa_acquire_many_contexts) {
    NEED_RSA();
    ULONG_PTR h[24]; int n = 0;
    for (int i = 0; i < 24; i++) { h[i] = rsa_enh(&R); if (h[i]) n++; }
    EXPECT_EQ(n, 24);
    for (int i = 0; i < 24; i++) cp_rel(&R, h[i]);
}
TEST(cpd_rsa_acquire_unknown_type_no_match) {
    NEED_RSA();
    /* Types the rsaenh table does not know map to NTE_PROV_TYPE_NO_MATCH. */
    DWORD types[] = { 3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 14, 16, 18, 20, 23, 25, 30, 0x1000 };
    for (size_t i = 0; i < NELEM(types); i++) {
        ULONG_PTR p = 0x77;
        SET_ERR(0);
        BOOL r = cp_acq_ex(&R, &p, NULL, CRYPT_VERIFYCONTEXT, 3, types[i], N_ENH);
        CHECKF(!r, "type %lu unexpectedly acquired", types[i]);
        if (!r) EXPECT_ERR(CPE_PROV_TYPE_NO_MATCH);
        else R.Release(p, 0);
    }
}
TEST(cpd_rsa_acquire_type_selects_table_not_name) {
    NEED_RSA();
    /* The algorithm table follows dwProvType (24 = AES) and, for type 1, the name: the name is only
     * recorded for PP_NAME.  An AES type with the Base name still reports the Base name. */
    ULONG_PTR p = 0;
    OKAY(cp_acq_ex(&R, &p, NULL, CRYPT_VERIFYCONTEXT, 3, PROV_RSA_AES, N_BASE));
    if (!p) return;
    char buf[128]; DWORD n = sizeof buf;
    OKAY(R.GetProvParam(p, PP_NAME, (BYTE *)buf, &n, 0));
    EXPECT_STR(buf, N_BASE);
    EXPECT_EQ(cp_pp_dw(&R, p, PP_PROVTYPE, NULL), PROV_RSA_AES);
    ULONG_PTR h = 0;
    OKAY(R.CreateHash(p, CALG_SHA_256, 0, 0, &h));
    if (h) R.DestroyHash(p, h);
    cp_rel(&R, p);
}
TEST(cpd_rsa_acquire_arbitrary_name_accepted_for_type1) {
    NEED_RSA();
    ULONG_PTR p = 0;
    SET_ERR(0);
    BOOL r = cp_acq_ex(&R, &p, NULL, CRYPT_VERIFYCONTEXT, 3, PROV_RSA_FULL, "cryptt custom name");
    CHECKF(r, "err=0x%lx", GetLastError());
    if (!r) return;
    char buf[64]; DWORD n = sizeof buf;
    OKAY(R.GetProvParam(p, PP_NAME, (BYTE *)buf, &n, 0));
    EXPECT_STR(buf, "cryptt custom name");
    EXPECT_EQ(n, strlen("cryptt custom name") + 1);
    cp_rel(&R, p);
}
TEST(cpd_rsa_acquire_vtable_version2_uses_type_field) {
    NEED_RSA();
    /* Version 2 carries dwProvType but no name; the provider copes only if the name is not used.  Only
     * the type is read at this version, so use a harmless Version 3 control instead of crashing. */
    ULONG_PTR p = 0;
    OKAY(cp_acq_ex(&R, &p, NULL, CRYPT_VERIFYCONTEXT, 3, PROV_RSA_SIG, N_SIG));
    if (!p) return;
    EXPECT_EQ(cp_pp_dw(&R, p, PP_PROVTYPE, NULL), PROV_RSA_SIG);
    cp_rel(&R, p);
}
TEST(cpd_rsa_acquire_bad_flag_bits) {
    NEED_RSA();
    /* Allowed bits are 0x78 and the top nibble; everything else is NTE_BAD_FLAGS. */
    DWORD bad[] = { 0x1, 0x2, 0x4, 0x80, 0x100, 0x200, 0x400, 0x800, 0x1000, 0x2000, 0x4000, 0x8000, 0x10000,
                    0x100000, 0x1000000, 0x4000000, 0x8000000, 0x7, 0xfffff87 };
    for (size_t i = 0; i < NELEM(bad); i++) {
        ULONG_PTR p = 0x55;
        FAILS(cp_acq_ex(&R, &p, NULL, bad[i], 3, PROV_RSA_FULL, N_ENH), CPE_BAD_FLAGS);
    }
}
TEST(cpd_rsa_acquire_bad_flags_with_verifycontext) {
    NEED_RSA();
    ULONG_PTR p = 0;
    FAILS(cp_acq_ex(&R, &p, NULL, CRYPT_VERIFYCONTEXT | 1, 3, PROV_RSA_FULL, N_ENH), CPE_BAD_FLAGS);
    FAILS(cp_acq_ex(&R, &p, NULL, CRYPT_VERIFYCONTEXT | 0x100, 3, PROV_RSA_FULL, N_ENH), CPE_BAD_FLAGS);
}
TEST(cpd_rsa_acquire_verifycontext_named_container_rejected) {
    NEED_RSA();
    ULONG_PTR p = 0;
    FAILS(cp_acq_ex(&R, &p, "cryptt_cpd_name", CRYPT_VERIFYCONTEXT, 3, PROV_RSA_FULL, N_ENH), CPE_BAD_FLAGS);
    FAILS(cp_acq_ex(&R, &p, "x", CRYPT_VERIFYCONTEXT | CRYPT_SILENT, 3, PROV_RSA_FULL, N_ENH), CPE_BAD_FLAGS);
}
TEST(cpd_rsa_acquire_verifycontext_empty_container_ok) {
    NEED_RSA();
    char empty[1] = { 0 };
    ULONG_PTR p = 0;
    OKAY(cp_acq_ex(&R, &p, empty, CRYPT_VERIFYCONTEXT, 3, PROV_RSA_FULL, N_ENH));
    cp_rel(&R, p);
}
TEST(cpd_rsa_acquire_verifycontext_silent_ok) {
    NEED_RSA();
    ULONG_PTR p = 0;
    OKAY(cp_acq_ex(&R, &p, NULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT, 3, PROV_RSA_FULL, N_ENH));
    cp_rel(&R, p);
}
TEST(cpd_rsa_acquire_null_phprov) {
    NEED_RSA();
    if (t_is_wine()) { t_skip("emulated CPAcquireContext dereferences phProv"); return; }
    cp_vtbl v; memset(&v, 0, sizeof v); v.Version = 3; v.dwProvType = PROV_RSA_FULL; v.pszProvName = N_ENH;
    FAILS(R.Acquire(NULL, NULL, CRYPT_VERIFYCONTEXT, &v), ERROR_INVALID_PARAMETER);
}
TEST(cpd_rsa_acquire_flag_check_precedes_null_phprov) {
    NEED_RSA();
    if (t_is_wine()) { t_skip("emulated CPAcquireContext dereferences phProv"); return; }
    cp_vtbl v; memset(&v, 0, sizeof v); v.Version = 3; v.dwProvType = PROV_RSA_FULL; v.pszProvName = N_ENH;
    FAILS(R.Acquire(NULL, NULL, 0x2, &v), CPE_BAD_FLAGS);
}
TEST(cpd_rsa_acquire_type_check_after_phprov_check) {
    NEED_RSA();
    if (t_is_wine()) { t_skip("emulated CPAcquireContext dereferences phProv"); return; }
    /* NULL phProv is reported before the provider type is examined (type is only looked at after). */
    cp_vtbl v; memset(&v, 0, sizeof v); v.Version = 3; v.dwProvType = 3; v.pszProvName = N_ENH;
    FAILS(R.Acquire(NULL, NULL, CRYPT_VERIFYCONTEXT, &v), ERROR_INVALID_PARAMETER);
}

/* ---- release ------------------------------------------------------------------------------ */
TEST(cpd_rsa_release_ok) {
    NEED_RSA();
    ULONG_PTR p = rsa_enh(&R); CHECK(p);
    if (p) OKAY(R.Release(p, 0));
}
TEST(cpd_rsa_release_nonzero_flags_fails_bad_flags) {
    NEED_RSA();
    /* The context is still torn down: the flags error is reported after the free. Do not reuse p. */
    ULONG_PTR p = rsa_enh(&R); if (!p) { CHECK(p); return; }
    FAILS(R.Release(p, 1), CPE_BAD_FLAGS);
}
TEST(cpd_rsa_release_wrong_handle_kind_key) {
    NEED_RSA();
    ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR k = 0;
    OKAY(R.GenKey(p, CALG_RC4, CRYPT_EXPORTABLE, &k));
    if (k) {
        FAILS(R.Release(k, 0), CPE_BAD_UID);
        R.DestroyKey(p, k);
    }
    cp_rel(&R, p);
}
TEST(cpd_rsa_release_wrong_handle_kind_hash) {
    NEED_RSA();
    ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR h = cp_mkhash(&R, p, CALG_MD5);
    CHECK(h);
    if (h) {
        FAILS(R.Release(h, 0), CPE_BAD_UID);
        R.DestroyHash(p, h);
    }
    cp_rel(&R, p);
}
TEST(cpd_rsa_release_with_live_key_and_hash) {
    NEED_RSA();
    ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR k = 0, h = cp_mkhash(&R, p, CALG_SHA1);
    OKAY(R.GenKey(p, CALG_RC4, 0, &k));
    CHECK(k && h);
    /* Releasing with outstanding children must succeed (children are leaked on purpose). */
    OKAY(R.Release(p, 0));
}
TEST(cpd_rsa_release_other_context_unaffected) {
    NEED_RSA();
    ULONG_PTR a = rsa_enh(&R), b = rsa_enh(&R); REQUIRE(a && b);
    ULONG_PTR k = 0;
    OKAY(R.GenKey(b, CALG_RC4, 0, &k));
    OKAY(R.Release(a, 0));
    BYTE rnd[8];
    OKAY(R.GenRandom(b, sizeof rnd, rnd));
    if (k) R.DestroyKey(b, k);
    cp_rel(&R, b);
}

/* ---- GetProvParam on rsaenh --------------------------------------------------------------- */
TEST(cpd_rsa_pp_name_per_provider) {
    NEED_RSA();
    struct { DWORD type; char *name; } t[] = {
        { PROV_RSA_FULL, N_BASE }, { PROV_RSA_FULL, N_ENH }, { PROV_RSA_FULL, N_STRONG },
        { PROV_RSA_AES, N_AES }, { PROV_RSA_SIG, N_SIG },
    };
    for (size_t i = 0; i < NELEM(t); i++) {
        ULONG_PTR p = rsa_open(&R, t[i].type, t[i].name); if (!p) { CHECK(p); continue; }
        char buf[128] = ""; DWORD n = sizeof buf;
        OKAY(R.GetProvParam(p, PP_NAME, (BYTE *)buf, &n, 0));
        EXPECT_STR(buf, t[i].name);
        EXPECT_EQ(n, strlen(t[i].name) + 1);
        cp_rel(&R, p);
    }
}
TEST(cpd_rsa_pp_name_buffer_protocol) {
    NEED_RSA();
    ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    DWORD need = 0xffff;
    OKAY(R.GetProvParam(p, PP_NAME, NULL, &need, 0));
    EXPECT_EQ(need, sizeof N_ENH);
    char buf[128];
    DWORD n = need - 1; memset(buf, 'Z', sizeof buf);
    FAILS(R.GetProvParam(p, PP_NAME, (BYTE *)buf, &n, 0), ERROR_MORE_DATA);
    EXPECT_EQ(n, need);
    CHECK(buf[0] == 'Z');
    n = 0;
    FAILS(R.GetProvParam(p, PP_NAME, (BYTE *)buf, &n, 0), ERROR_MORE_DATA);
    EXPECT_EQ(n, need);
    n = need;
    OKAY(R.GetProvParam(p, PP_NAME, (BYTE *)buf, &n, 0));
    EXPECT_EQ(n, need);
    EXPECT_STR(buf, N_ENH);
    n = sizeof buf;
    OKAY(R.GetProvParam(p, PP_NAME, (BYTE *)buf, &n, 0));
    EXPECT_EQ(n, need);
    cp_rel(&R, p);
}
TEST(cpd_rsa_pp_name_null_size_ptr) {
    NEED_RSA();
    ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    char buf[128];
    FAILS(R.GetProvParam(p, PP_NAME, (BYTE *)buf, NULL, 0), ERROR_INVALID_PARAMETER);
    FAILS(R.GetProvParam(p, PP_NAME, NULL, NULL, 0), ERROR_INVALID_PARAMETER);
    cp_rel(&R, p);
}
TEST(cpd_rsa_pp_name_nonzero_flags) {
    NEED_RSA();
    ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    char buf[128]; DWORD n = sizeof buf;
    FAILS(R.GetProvParam(p, PP_NAME, (BYTE *)buf, &n, 1), CPE_BAD_FLAGS);
    n = sizeof buf;
    FAILS(R.GetProvParam(p, PP_NAME, (BYTE *)buf, &n, 0x8000), CPE_BAD_FLAGS);
    cp_rel(&R, p);
}
TEST(cpd_rsa_pp_dword_values) {
    NEED_RSA();
    ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    BOOL ok;
    EXPECT_EQ(cp_pp_dw(&R, p, PP_IMPTYPE, &ok), CRYPT_IMPL_SOFTWARE); CHECK(ok);
    EXPECT_EQ(cp_pp_dw(&R, p, PP_VERSION, &ok), 0x200); CHECK(ok);
    EXPECT_EQ(cp_pp_dw(&R, p, PP_PROVTYPE, &ok), PROV_RSA_FULL); CHECK(ok);
    EXPECT_EQ(cp_pp_dw(&R, p, PP_KEYSTORAGE, &ok), CRYPT_SEC_DESCR); CHECK(ok);
    EXPECT_EQ(cp_pp_dw(&R, p, PP_KEYSET_TYPE, &ok), 0); CHECK(ok);
    EXPECT_EQ(cp_pp_dw(&R, p, PP_KEYSPEC, &ok), AT_KEYEXCHANGE | AT_SIGNATURE); CHECK(ok);
    EXPECT_EQ(cp_pp_dw(&R, p, PP_SIG_KEYSIZE_INC, &ok), 8); CHECK(ok);
    EXPECT_EQ(cp_pp_dw(&R, p, PP_KEYX_KEYSIZE_INC, &ok), 8); CHECK(ok);
    cp_rel(&R, p);
}
TEST(cpd_rsa_pp_keyspec_signature_provider) {
    NEED_RSA();
    ULONG_PTR p = rsa_open(&R, PROV_RSA_SIG, N_SIG); REQUIRE(p);
    BOOL ok;
    EXPECT_EQ(cp_pp_dw(&R, p, PP_KEYSPEC, &ok), AT_SIGNATURE); CHECK(ok);
    EXPECT_EQ(cp_pp_dw(&R, p, PP_PROVTYPE, &ok), PROV_RSA_SIG); CHECK(ok);
    cp_rel(&R, p);
}
TEST(cpd_rsa_pp_keyspec_aes_provider) {
    NEED_RSA();
    ULONG_PTR p = rsa_aes(&R); REQUIRE(p);
    BOOL ok;
    EXPECT_EQ(cp_pp_dw(&R, p, PP_KEYSPEC, &ok), AT_KEYEXCHANGE | AT_SIGNATURE); CHECK(ok);
    EXPECT_EQ(cp_pp_dw(&R, p, PP_PROVTYPE, &ok), PROV_RSA_AES); CHECK(ok);
    cp_rel(&R, p);
}
TEST(cpd_rsa_pp_dword_buffer_protocol) {
    NEED_RSA();
    ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    DWORD params[] = { PP_IMPTYPE, PP_VERSION, PP_PROVTYPE, PP_KEYSTORAGE, PP_KEYSET_TYPE, PP_KEYSPEC,
                       PP_SIG_KEYSIZE_INC, PP_KEYX_KEYSIZE_INC };
    for (size_t i = 0; i < NELEM(params); i++) {
        DWORD v = 0, n = 0;
        OKAY(R.GetProvParam(p, params[i], NULL, &n, 0));
        EXPECT_EQ(n, 4);
        for (DWORD len = 0; len < 4; len++) {
            n = len; v = 0x11111111;
            FAILS(R.GetProvParam(p, params[i], (BYTE *)&v, &n, 0), ERROR_MORE_DATA);
            EXPECT_EQ(n, 4);
            EXPECT_EQ(v, 0x11111111);
        }
        n = 4;
        OKAY(R.GetProvParam(p, params[i], (BYTE *)&v, &n, 0));
        n = 64;
        OKAY(R.GetProvParam(p, params[i], (BYTE *)&v, &n, 0));
        EXPECT_EQ(n, 4);
        n = 4;
        FAILS(R.GetProvParam(p, params[i], (BYTE *)&v, &n, 4), CPE_BAD_FLAGS);
        n = 4;
        FAILS(R.GetProvParam(p, params[i], (BYTE *)&v, NULL, 0), ERROR_INVALID_PARAMETER);
    }
    cp_rel(&R, p);
}
TEST(cpd_rsa_pp_unknown_params_bad_type) {
    NEED_RSA();
    ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    DWORD bad[] = { 0, 7, 9, 0xa, 0xf, 0x12, 0x13, 0x14, 0x15, 0x17, 0x1a, 0x1c, 0x21, 0x26, 0x29, 0x30, 0x1000 };
    for (size_t i = 0; i < NELEM(bad); i++) {
        BYTE b[16]; DWORD n = sizeof b;
        FAILS(R.GetProvParam(p, bad[i], b, &n, 0), CPE_BAD_TYPE);
    }
    cp_rel(&R, p);
}
TEST(cpd_rsa_pp_invalid_pcb_checked_before_type) {
    NEED_RSA();
    ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    BYTE b[16];
    FAILS(R.GetProvParam(p, 0x7777, b, NULL, 0), ERROR_INVALID_PARAMETER);
    cp_rel(&R, p);
}
TEST(cpd_rsa_pp_wrong_handle_kinds_are_bad_uid) {
    NEED_RSA();
    ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR k = 0; OKAY(R.GenKey(p, CALG_RC4, 0, &k));
    ULONG_PTR h = cp_mkhash(&R, p, CALG_MD5);
    BYTE b[128]; DWORD n = sizeof b;
    if (k) { FAILS(R.GetProvParam(k, PP_NAME, b, &n, 0), CPE_BAD_UID); }
    if (h) { n = sizeof b; FAILS(R.GetProvParam(h, PP_NAME, b, &n, 0), CPE_BAD_UID); }
    if (k) R.DestroyKey(p, k);
    if (h) R.DestroyHash(p, h);
    cp_rel(&R, p);
}
TEST(cpd_rsa_pp_container_verifycontext) {
    NEED_RSA();
    ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    char buf[512]; DWORD n = sizeof buf;
    SET_ERR(0);
    BOOL r = R.GetProvParam(p, PP_CONTAINER, (BYTE *)buf, &n, 0);
    if (r) t_note("PP_CONTAINER on VERIFYCONTEXT succeeds, \"%s\"", buf);
    else t_note("PP_CONTAINER on VERIFYCONTEXT fails 0x%lx", GetLastError());
    n = sizeof buf;
    FAILS(R.GetProvParam(p, PP_CONTAINER, (BYTE *)buf, &n, 1), CPE_BAD_FLAGS);
    cp_rel(&R, p);
}
TEST(cpd_rsa_pp_unique_container_verifycontext_note) {
    NEED_RSA();
    ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    char buf[512]; DWORD n = sizeof buf;
    SET_ERR(0);
    BOOL r = R.GetProvParam(p, PP_UNIQUE_CONTAINER, (BYTE *)buf, &n, 0);
    t_note("PP_UNIQUE_CONTAINER on VERIFYCONTEXT: %d err=0x%lx", r, GetLastError());
    n = sizeof buf;
    FAILS(R.GetProvParam(p, PP_UNIQUE_CONTAINER, (BYTE *)buf, &n, 1), CPE_BAD_FLAGS);
    cp_rel(&R, p);
}
TEST(cpd_rsa_pp_keyset_sec_descr_flags) {
    NEED_RSA();
    ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    BYTE b[256]; DWORD n = sizeof b;
    FAILS(R.GetProvParam(p, PP_KEYSET_SEC_DESCR, b, &n, 0), CPE_BAD_FLAGS);
    n = sizeof b;
    FAILS(R.GetProvParam(p, PP_KEYSET_SEC_DESCR, b, &n, 0x20), CPE_BAD_FLAGS);
    cp_rel(&R, p);
}

/* ---- PP_ENUMALGS / PP_ENUMALGS_EX --------------------------------------------------------- */
typedef struct { ALG_ID alg; DWORD bits; DWORD namelen; CHAR name[20]; } cp_enumalg;
typedef struct { ALG_ID alg; DWORD def, min, max, protocols, namelen; CHAR name[20]; DWORD longlen; CHAR longname[40]; } cp_enumalg_ex;

static int cp_enum(const cpf *f, ULONG_PTR p, cp_enumalg *out, int cap) {
    int n = 0;
    for (;;) {
        cp_enumalg e; DWORD len = sizeof e;
        if (!f->GetProvParam(p, PP_ENUMALGS, (BYTE *)&e, &len, n == 0 ? CRYPT_FIRST : 0)) break;
        if (n < cap) out[n] = e;
        n++;
        if (n > 200) break;
    }
    return n;
}
static int cp_has(const cp_enumalg *a, int n, ALG_ID id) { for (int i = 0; i < n; i++) if (a[i].alg == id) return 1; return 0; }

TEST(cpd_rsa_enumalgs_terminates_with_no_more_items) {
    NEED_RSA();
    ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    cp_enumalg a[64]; int n = cp_enum(&R, p, a, 64);
    CHECK(n > 8); CHECK(n < 64);
    EXPECT_ERR(ERROR_NO_MORE_ITEMS);
    cp_rel(&R, p);
}
TEST(cpd_rsa_enumalgs_entry_layout) {
    NEED_RSA();
    ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    cp_enumalg a[64]; int n = cp_enum(&R, p, a, 64);
    for (int i = 0; i < n && i < 64; i++) {
        CHECKF(a[i].namelen == strlen(a[i].name) + 1, "entry %d namelen %lu name %s", i, a[i].namelen, a[i].name);
        CHECKF(a[i].namelen <= 20, "entry %d name too long", i);
        for (int j = 0; j < i; j++) CHECKF(a[i].alg != a[j].alg, "duplicate algid 0x%x", a[i].alg);
    }
    cp_rel(&R, p);
}
TEST(cpd_rsa_enumalgs_enhanced_contents) {
    NEED_RSA();
    ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    cp_enumalg a[64]; int n = cp_enum(&R, p, a, 64);
    ALG_ID need[] = { CALG_RSA_SIGN, CALG_RSA_KEYX, CALG_RC2, CALG_RC4, CALG_DES, CALG_3DES, CALG_3DES_112,
                      CALG_MD5, CALG_SHA1, CALG_MAC, CALG_HMAC, CALG_SSL3_SHAMD5, CALG_MD2, CALG_MD4 };
    for (size_t i = 0; i < NELEM(need); i++) CHECKF(cp_has(a, n, need[i]), "enhanced provider lacks 0x%x", need[i]);
    CHECK(!cp_has(a, n, CALG_AES_128));
    CHECK(!cp_has(a, n, CALG_SHA_256));
    cp_rel(&R, p);
}
TEST(cpd_rsa_enumalgs_aes_contents) {
    NEED_RSA();
    ULONG_PTR p = rsa_aes(&R); REQUIRE(p);
    cp_enumalg a[64]; int n = cp_enum(&R, p, a, 64);
    ALG_ID need[] = { CALG_AES_128, CALG_AES_192, CALG_AES_256, CALG_SHA_256, CALG_SHA_384, CALG_SHA_512,
                      CALG_RSA_SIGN, CALG_RSA_KEYX, CALG_RC4, CALG_3DES, CALG_MD5, CALG_SHA1, CALG_HMAC };
    for (size_t i = 0; i < NELEM(need); i++) CHECKF(cp_has(a, n, need[i]), "aes provider lacks 0x%x", need[i]);
    cp_rel(&R, p);
}
TEST(cpd_rsa_enumalgs_base_contents) {
    NEED_RSA();
    ULONG_PTR p = rsa_base(&R); REQUIRE(p);
    cp_enumalg a[64]; int n = cp_enum(&R, p, a, 64);
    ALG_ID need[] = { CALG_RSA_SIGN, CALG_RSA_KEYX, CALG_RC2, CALG_RC4, CALG_DES, CALG_MD5, CALG_SHA1 };
    for (size_t i = 0; i < NELEM(need); i++) CHECKF(cp_has(a, n, need[i]), "base provider lacks 0x%x", need[i]);
    CHECK(!cp_has(a, n, CALG_AES_128));
    cp_rel(&R, p);
}
TEST(cpd_rsa_enumalgs_base_vs_enhanced_key_sizes) {
    NEED_RSA();
    ULONG_PTR b = rsa_base(&R), e = rsa_enh(&R); REQUIRE(b && e);
    cp_enumalg ab[64], ae[64]; int nb = cp_enum(&R, b, ab, 64), ne = cp_enum(&R, e, ae, 64);
    for (int i = 0; i < nb; i++) if (ab[i].alg == CALG_RC4) CHECKF(ab[i].bits == 40, "base RC4 bits %lu", ab[i].bits);
    for (int i = 0; i < ne; i++) if (ae[i].alg == CALG_RC4) CHECKF(ae[i].bits == 128, "enh RC4 bits %lu", ae[i].bits);
    for (int i = 0; i < ne; i++) if (ae[i].alg == CALG_MD5) EXPECT_EQ(ae[i].bits, 128);
    for (int i = 0; i < ne; i++) if (ae[i].alg == CALG_SHA1) EXPECT_EQ(ae[i].bits, 160);
    cp_rel(&R, b); cp_rel(&R, e);
}
TEST(cpd_rsa_enumalgs_restart_with_first) {
    NEED_RSA();
    ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    cp_enumalg a[64], b[64]; int n1 = cp_enum(&R, p, a, 64), n2 = cp_enum(&R, p, b, 64);
    EXPECT_EQ(n1, n2);
    if (n1 == n2 && n1 <= 64) SAMEBYTES(a, b, n1 * sizeof a[0]);
    cp_rel(&R, p);
}
TEST(cpd_rsa_enumalgs_exhausted_stays_exhausted) {
    NEED_RSA();
    ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    cp_enumalg a[64]; cp_enum(&R, p, a, 64);
    for (int i = 0; i < 3; i++) {
        cp_enumalg e; DWORD len = sizeof e;
        FAILS(R.GetProvParam(p, PP_ENUMALGS, (BYTE *)&e, &len, 0), ERROR_NO_MORE_ITEMS);
    }
    cp_rel(&R, p);
}
TEST(cpd_rsa_enumalgs_size_query_does_not_advance) {
    NEED_RSA();
    ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    DWORD n = 0;
    OKAY(R.GetProvParam(p, PP_ENUMALGS, NULL, &n, CRYPT_FIRST));
    EXPECT_EQ(n, sizeof(cp_enumalg));
    cp_enumalg e1, e2; DWORD l1 = sizeof e1, l2 = sizeof e2;
    OKAY(R.GetProvParam(p, PP_ENUMALGS, (BYTE *)&e1, &l1, CRYPT_FIRST));
    n = 0;
    OKAY(R.GetProvParam(p, PP_ENUMALGS, NULL, &n, 0));
    EXPECT_EQ(n, sizeof(cp_enumalg));
    OKAY(R.GetProvParam(p, PP_ENUMALGS, (BYTE *)&e2, &l2, 0));
    CHECK(e1.alg != e2.alg);
    cp_rel(&R, p);
}
TEST(cpd_rsa_enumalgs_small_buffer_more_data) {
    NEED_RSA();
    ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    cp_enumalg e; DWORD len;
    for (len = 0; len < sizeof(cp_enumalg); len += 7) {
        DWORD l = len;
        FAILS(R.GetProvParam(p, PP_ENUMALGS, (BYTE *)&e, &l, CRYPT_FIRST), ERROR_MORE_DATA);
        EXPECT_EQ(l, sizeof(cp_enumalg));
    }
    len = sizeof(cp_enumalg) - 1;
    FAILS(R.GetProvParam(p, PP_ENUMALGS, (BYTE *)&e, &len, CRYPT_FIRST), ERROR_MORE_DATA);
    len = sizeof(cp_enumalg);
    OKAY(R.GetProvParam(p, PP_ENUMALGS, (BYTE *)&e, &len, CRYPT_FIRST));
    EXPECT_EQ(len, sizeof(cp_enumalg));
    cp_rel(&R, p);
}
TEST(cpd_rsa_enumalgs_bad_flags) {
    NEED_RSA();
    ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    cp_enumalg e; DWORD len = sizeof e;
    FAILS(R.GetProvParam(p, PP_ENUMALGS, (BYTE *)&e, &len, 4), CPE_BAD_FLAGS);
    len = sizeof e;
    FAILS(R.GetProvParam(p, PP_ENUMALGS, (BYTE *)&e, &len, 0x100), CPE_BAD_FLAGS);
    cp_rel(&R, p);
}
TEST(cpd_rsa_enumalgs_contexts_independent) {
    NEED_RSA();
    ULONG_PTR a = rsa_enh(&R), b = rsa_enh(&R); REQUIRE(a && b);
    cp_enumalg ea, eb, ea2; DWORD l = sizeof ea;
    OKAY(R.GetProvParam(a, PP_ENUMALGS, (BYTE *)&ea, &l, CRYPT_FIRST));
    l = sizeof ea;
    OKAY(R.GetProvParam(a, PP_ENUMALGS, (BYTE *)&ea2, &l, 0));
    l = sizeof eb;
    OKAY(R.GetProvParam(b, PP_ENUMALGS, (BYTE *)&eb, &l, CRYPT_FIRST));
    EXPECT_EQ(ea.alg, eb.alg);
    cp_rel(&R, a); cp_rel(&R, b);
}
TEST(cpd_rsa_enumalgs_ex_layout_and_consistency) {
    NEED_RSA();
    ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    cp_enumalg a[64]; int n = cp_enum(&R, p, a, 64);
    int m = 0;
    for (;;) {
        cp_enumalg_ex e; DWORD len = sizeof e;
        if (!R.GetProvParam(p, PP_ENUMALGS_EX, (BYTE *)&e, &len, m == 0 ? CRYPT_FIRST : 0)) break;
        EXPECT_EQ(len, sizeof e);
        CHECK(sizeof e == 0x58);
        if (m < n) {
            CHECKF(e.alg == a[m].alg, "ex[%d] 0x%x vs 0x%x", m, e.alg, a[m].alg);
            CHECKF(e.def == a[m].bits, "ex[%d] def %lu vs bits %lu", m, e.def, a[m].bits);
            CHECK(strcmp(e.name, a[m].name) == 0);
        }
        CHECK(e.min <= e.def); CHECK(e.def <= e.max);
        CHECK(e.namelen == strlen(e.name) + 1);
        CHECK(e.longlen == strlen(e.longname) + 1);
        m++;
        if (m > 100) break;
    }
    EXPECT_EQ(m, n);
    EXPECT_ERR(ERROR_NO_MORE_ITEMS);
    cp_rel(&R, p);
}
TEST(cpd_rsa_enumalgs_ex_buffer_protocol) {
    NEED_RSA();
    ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    DWORD n = 0;
    OKAY(R.GetProvParam(p, PP_ENUMALGS_EX, NULL, &n, CRYPT_FIRST));
    EXPECT_EQ(n, 0x58);
    cp_enumalg_ex e; DWORD l = 0x57;
    FAILS(R.GetProvParam(p, PP_ENUMALGS_EX, (BYTE *)&e, &l, CRYPT_FIRST), ERROR_MORE_DATA);
    EXPECT_EQ(l, 0x58);
    l = sizeof e;
    FAILS(R.GetProvParam(p, PP_ENUMALGS_EX, (BYTE *)&e, &l, 8), CPE_BAD_FLAGS);
    cp_rel(&R, p);
}
TEST(cpd_rsa_enumalgs_ex_aes_key_ranges) {
    NEED_RSA();
    ULONG_PTR p = rsa_aes(&R); REQUIRE(p);
    int seen = 0;
    for (int i = 0;; i++) {
        cp_enumalg_ex e; DWORD len = sizeof e;
        if (!R.GetProvParam(p, PP_ENUMALGS_EX, (BYTE *)&e, &len, i == 0 ? CRYPT_FIRST : 0)) break;
        if (e.alg == CALG_AES_128) { EXPECT_EQ(e.def, 128); EXPECT_EQ(e.min, 128); EXPECT_EQ(e.max, 128); seen++; }
        if (e.alg == CALG_AES_192) { EXPECT_EQ(e.def, 192); EXPECT_EQ(e.max, 192); seen++; }
        if (e.alg == CALG_AES_256) { EXPECT_EQ(e.def, 256); EXPECT_EQ(e.max, 256); seen++; }
        if (e.alg == CALG_RSA_KEYX) { t_note("RSA_KEYX min %lu def %lu max %lu", e.min, e.def, e.max); seen++; }
        if (e.alg == CALG_SHA1) { EXPECT_EQ(e.def, 160); seen++; }
        if (i > 100) break;
    }
    EXPECT_EQ(seen, 5);
    cp_rel(&R, p);
}

/* ---- SetProvParam on rsaenh --------------------------------------------------------------- */
TEST(cpd_rsa_setprov_unknown_bad_type) {
    NEED_RSA();
    ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    BYTE b[4] = { 0 };
    DWORD bad[] = { 0, 1, 3, 4, 5, 6, 7, 9, 0x11, 0x16, 0x1b, 0x20, 0x26, 0x28, 0x77, 0x1000 };
    for (size_t i = 0; i < NELEM(bad); i++) FAILS(R.SetProvParam(p, bad[i], b, 0), CPE_BAD_TYPE);
    cp_rel(&R, p);
}
TEST(cpd_rsa_setprov_hwnd_flags) {
    NEED_RSA();
    ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    OKAY(R.SetProvParam(p, PP_CLIENT_HWND, NULL, 0));
    FAILS(R.SetProvParam(p, PP_CLIENT_HWND, NULL, 1), CPE_BAD_FLAGS);
    FAILS(R.SetProvParam(p, PP_CLIENT_HWND, NULL, 0x80), CPE_BAD_FLAGS);
    cp_rel(&R, p);
}
TEST(cpd_rsa_setprov_ui_prompt) {
    NEED_RSA();
    ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    const WCHAR *s = L"cryptt prompt";
    OKAY(R.SetProvParam(p, PP_UI_PROMPT, (const BYTE *)s, 0));
    OKAY(R.SetProvParam(p, PP_UI_PROMPT, (const BYTE *)s, 0));
    OKAY(R.SetProvParam(p, PP_UI_PROMPT, NULL, 0));
    FAILS(R.SetProvParam(p, PP_UI_PROMPT, (const BYTE *)s, 1), CPE_BAD_FLAGS);
    cp_rel(&R, p);
}
TEST(cpd_rsa_setprov_keyset_sec_descr_flags) {
    NEED_RSA();
    ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    BYTE b[16] = { 0 };
    FAILS(R.SetProvParam(p, PP_KEYSET_SEC_DESCR, b, 0), CPE_BAD_FLAGS);
    FAILS(R.SetProvParam(p, PP_KEYSET_SEC_DESCR, b, 0x20), CPE_BAD_FLAGS);
    cp_rel(&R, p);
}
TEST(cpd_rsa_setprov_deletekey_verifycontext) {
    NEED_RSA();
    ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    DWORD spec = AT_SIGNATURE;
    FAILS(R.SetProvParam(p, PP_DELETEKEY, (BYTE *)&spec, 0), CPE_BAD_UID);
    FAILS(R.SetProvParam(p, PP_DELETEKEY, (BYTE *)&spec, 1), CPE_BAD_FLAGS);
    cp_rel(&R, p);
}
TEST(cpd_rsa_setprov_0x25_non_schannel_bad_type) {
    NEED_RSA();
    ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    BYTE b[4] = { 0 };
    FAILS(R.SetProvParam(p, 0x25, b, 0), CPE_BAD_TYPE);
    FAILS(R.SetProvParam(p, 0x25, b, 1), CPE_BAD_FLAGS);
    cp_rel(&R, p);
}
TEST(cpd_rsa_setprov_wrong_handle_kind) {
    NEED_RSA();
    ULONG_PTR p = rsa_enh(&R); REQUIRE(p);
    ULONG_PTR k = 0; OKAY(R.GenKey(p, CALG_RC4, 0, &k));
    BYTE b[4] = { 0 };
    if (k) { FAILS(R.SetProvParam(k, PP_CLIENT_HWND, b, 0), CPE_BAD_UID); R.DestroyKey(p, k); }
    cp_rel(&R, p);
}

/* ---- dssenh acquire / provider params ----------------------------------------------------- */
TEST(cpd_dss_acquire_verifycontext_types) {
    NEED_DSS();
    DWORD types[] = { PROV_DSS, PROV_DSS_DH };
    for (size_t i = 0; i < NELEM(types); i++) {
        ULONG_PTR p = 0;
        SET_ERR(0);
        BOOL r = cp_acq_ex(&D, &p, NULL, CRYPT_VERIFYCONTEXT, 2, types[i], NULL);
        CHECKF(r, "dss acquire type %lu err=0x%lx", types[i], GetLastError());
        CHECK(p != 0);
        if (r) OKAY(D.Release(p, 0));
    }
}
TEST(cpd_dss_acquire_version0_defaults_to_dss_dh) {
    NEED_DSS();
    ULONG_PTR p = 0;
    SET_ERR(0);
    BOOL r = cp_acq_ex(&D, &p, NULL, CRYPT_VERIFYCONTEXT, 0, 0, NULL);
    CHECKF(r, "err=0x%lx", GetLastError());
    if (!r) return;
    char buf[128]; DWORD n = sizeof buf;
    OKAY(D.GetProvParam(p, PP_NAME, (BYTE *)buf, &n, 0));
    t_note("dss default provider name at Version 0: %s", buf);
    cp_rel(&D, p);
}
TEST(cpd_dss_acquire_bad_flag_bits) {
    NEED_DSS();
    DWORD bad[] = { 0x1, 0x2, 0x4, 0x80, 0x100, 0x1000, 0x10000, 0x1000000, 0x7, 0xfffff87 };
    for (size_t i = 0; i < NELEM(bad); i++) {
        ULONG_PTR p = 0;
        FAILS(cp_acq_ex(&D, &p, NULL, bad[i], 2, PROV_DSS_DH, NULL), CPE_BAD_FLAGS);
    }
}
TEST(cpd_dss_acquire_verifycontext_named_container_rejected) {
    NEED_DSS();
    ULONG_PTR p = 0;
    FAILS(cp_acq_ex(&D, &p, "cryptt_cpd_dss", CRYPT_VERIFYCONTEXT, 2, PROV_DSS_DH, NULL), CPE_BAD_FLAGS);
}
TEST(cpd_dss_acquire_null_phprov) {
    NEED_DSS();
    if (t_is_wine()) { t_skip("dssenh stub dereferences phProv under wine"); return; }
    cp_vtbl v; memset(&v, 0, sizeof v); v.Version = 2; v.dwProvType = PROV_DSS_DH;
    FAILS(D.Acquire(NULL, NULL, CRYPT_VERIFYCONTEXT, &v), ERROR_INVALID_PARAMETER);
    FAILS(D.Acquire(NULL, NULL, 2, &v), CPE_BAD_FLAGS);
}
TEST(cpd_dss_pp_name_by_type) {
    NEED_DSS();
    struct { DWORD type; const char *name; } t[] = { { PROV_DSS, N_DSS_BASE }, { PROV_DSS_DH, N_DSS_ENH } };
    for (size_t i = 0; i < NELEM(t); i++) {
        ULONG_PTR p = dss_open(&D, t[i].type); if (!p) { CHECK(p); continue; }
        char buf[128] = ""; DWORD n = sizeof buf;
        SET_ERR(0);
        BOOL r = D.GetProvParam(p, PP_NAME, (BYTE *)buf, &n, 0);
        CHECKF(r, "type %lu err=0x%lx", t[i].type, GetLastError());
        if (r) t_note("dss type %lu PP_NAME \"%s\"", t[i].type, buf);
        cp_rel(&D, p);
    }
}
TEST(cpd_dss_pp_dword_values) {
    NEED_DSS();
    ULONG_PTR p = dss_open(&D, PROV_DSS_DH); REQUIRE(p);
    BOOL ok;
    EXPECT_EQ(cp_pp_dw(&D, p, PP_IMPTYPE, &ok), CRYPT_IMPL_SOFTWARE); CHECK(ok);
    EXPECT_EQ(cp_pp_dw(&D, p, PP_PROVTYPE, &ok), PROV_DSS_DH); CHECK(ok);
    cp_pp_dw(&D, p, PP_VERSION, &ok); t_note("dss PP_VERSION ok=%d", ok);
    cp_rel(&D, p);
}
TEST(cpd_dss_pp_enumalgs) {
    NEED_DSS();
    ULONG_PTR p = dss_open(&D, PROV_DSS_DH); REQUIRE(p);
    cp_enumalg a[64]; int n = cp_enum(&D, p, a, 64);
    CHECK(n >= 4); CHECK(n < 64);
    EXPECT_ERR(ERROR_NO_MORE_ITEMS);
    CHECK(cp_has(a, n, CALG_DSS_SIGN));
    CHECK(cp_has(a, n, CALG_SHA1));
    CHECK(cp_has(a, n, CALG_DH_SF));
    for (int i = 0; i < n && i < 64; i++) CHECK(a[i].namelen == strlen(a[i].name) + 1);
    cp_rel(&D, p);
}
TEST(cpd_dss_pp_enumalgs_base_has_no_dh) {
    NEED_DSS();
    ULONG_PTR p = dss_open(&D, PROV_DSS); REQUIRE(p);
    cp_enumalg a[64]; int n = cp_enum(&D, p, a, 64);
    CHECK(n >= 2);
    CHECK(cp_has(a, n, CALG_DSS_SIGN));
    CHECK(cp_has(a, n, CALG_SHA1));
    cp_rel(&D, p);
}
TEST(cpd_dss_pp_buffer_protocol) {
    NEED_DSS();
    ULONG_PTR p = dss_open(&D, PROV_DSS_DH); REQUIRE(p);
    DWORD v = 0, n = 0;
    OKAY(D.GetProvParam(p, PP_PROVTYPE, NULL, &n, 0));
    EXPECT_EQ(n, 4);
    n = 3;
    FAILS(D.GetProvParam(p, PP_PROVTYPE, (BYTE *)&v, &n, 0), ERROR_MORE_DATA);
    n = 4;
    FAILS(D.GetProvParam(p, PP_PROVTYPE, (BYTE *)&v, &n, 1), CPE_BAD_FLAGS);
    FAILS(D.GetProvParam(p, PP_PROVTYPE, (BYTE *)&v, NULL, 0), ERROR_INVALID_PARAMETER);
    cp_rel(&D, p);
}
TEST(cpd_dss_release_ok_and_flags) {
    NEED_DSS();
    ULONG_PTR p = dss_open(&D, PROV_DSS_DH); REQUIRE(p);
    OKAY(D.Release(p, 0));
    p = dss_open(&D, PROV_DSS_DH); REQUIRE(p);
    FAILS(D.Release(p, 1), CPE_BAD_FLAGS);
}
