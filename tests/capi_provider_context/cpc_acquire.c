#include "cpc.h"
/* CryptAcquireContextA/W, CryptReleaseContext, CryptContextAddRef with CRYPT_VERIFYCONTEXT only.
 * Behaviour pinned from the cryptsp acquire path (registry lookup of the provider, Type check,
 * LoadLibrary of the CSP, provider CPAcquireContext). */


/* ---------------------------------------------------------------- named providers */
static void acq_a(int i) {
    const cpc_prov *P = &cpc_provs[i];
    REQUIRE(U(CryptAcquireContextA)); REQUIRE(U(CryptReleaseContext));
    HCRYPTPROV h = 0;
    SET_ERR(0);
    BOOL ok = cpc_acq(&h, P->a, P->type, X_VERIFY);
    CHECKF(ok, "%s type %lu err 0x%lx", P->a, P->type, GetLastError());
    if (!ok) return;
    CHECK(h != 0);
    CHECK(U(CryptReleaseContext)(h, 0));
}
PERPROV(cpc_acquire_a, acq_a)

static void acq_w(int i) {
    const cpc_prov *P = &cpc_provs[i];
    REQUIRE(U(CryptAcquireContextW)); REQUIRE(U(CryptReleaseContext));
    HCRYPTPROV h = 0;
    BOOL ok = U(CryptAcquireContextW)(&h, NULL, P->w, P->type, X_VERIFY);
    CHECKF(ok, "type %lu err 0x%lx", P->type, GetLastError());
    if (!ok) return;
    CHECK(h != 0);
    CHECK(U(CryptReleaseContext)(h, 0));
}
PERPROV(cpc_acquire_w, acq_w)


/* A and W contexts report the same provider name (always ANSI through PP_NAME). */
static void acq_aw_name(int i) {
    const cpc_prov *P = &cpc_provs[i];
    REQUIRE(U(CryptAcquireContextW)); REQUIRE(U(CryptGetProvParam));
    HCRYPTPROV ha = 0, hw = 0;
    if (!cpc_acq(&ha, P->a, P->type, X_VERIFY)) { CHECKF(0, "A acquire 0x%lx", GetLastError()); return; }
    if (!U(CryptAcquireContextW)(&hw, NULL, P->w, P->type, X_VERIFY)) { CHECKF(0, "W acquire 0x%lx", GetLastError()); cpc_rel(ha); return; }
    char na[256] = {0}, nw[256] = {0}; DWORD la = sizeof na, lw = sizeof nw;
    CHECK(cpc_gpp(ha, PP_NAME, na, &la, 0));
    CHECK(cpc_gpp(hw, PP_NAME, nw, &lw, 0));
    EXPECT_STR(na, nw);
    EXPECT_STR(na, P->a);
    EXPECT_EQ(la, lw);
    CHECK(ha != hw);
    cpc_rel(ha); cpc_rel(hw);
}
PERPROV(cpc_acquire_aw_name, acq_aw_name)

static void acq_silent(int i) {
    const cpc_prov *P = &cpc_provs[i];
    REQUIRE(U(CryptAcquireContextA));
    HCRYPTPROV h = 0;
    BOOL ok = cpc_acq(&h, P->a, P->type, X_VERIFY | CRYPT_SILENT);
    CHECKF(ok, "err 0x%lx", GetLastError());
    if (ok) { CHECK(h != 0); cpc_rel(h); }
}
PERPROV(cpc_acquire_silent, acq_silent)

static void acq_machine(int i) {
    const cpc_prov *P = &cpc_provs[i];
    REQUIRE(U(CryptAcquireContextA));
    HCRYPTPROV h = 0;
    BOOL ok = cpc_acq(&h, P->a, P->type, X_VERIFY | CRYPT_MACHINE_KEYSET);
    if (!ok) {
        if (GetLastError() == ERROR_ACCESS_DENIED) { t_skip("access denied (app container)"); return; }
        CHECKF(0, "err 0x%lx", GetLastError()); return;
    }
    DWORD v;
    CHECK(cpc_gpp_dw(h, PP_KEYSET_TYPE, &v));
    EXPECT_EQ(v, CRYPT_MACHINE_KEYSET);
    cpc_rel(h);
}
PERPROV(cpc_acquire_machine_keyset_type, acq_machine)

static void acq_user_keyset_type(int i) {
    const cpc_prov *P = &cpc_provs[i];
    REQUIRE(U(CryptAcquireContextA));
    HCRYPTPROV h = 0;
    if (!cpc_acq(&h, P->a, P->type, X_VERIFY)) { CHECKF(0, "err 0x%lx", GetLastError()); return; }
    DWORD v;
    CHECK(cpc_gpp_dw(h, PP_KEYSET_TYPE, &v));
    EXPECT_EQ(v, 0);
    cpc_rel(h);
}
PERPROV(cpc_acquire_user_keyset_type, acq_user_keyset_type)

/* VERIFYCONTEXT and a non-empty container name is rejected by the CSP; cryptsp has already
 * zeroed *phProv before calling it. */
static void acq_container(int i) {
    const cpc_prov *P = &cpc_provs[i];
    REQUIRE(U(CryptAcquireContextA));
    HCRYPTPROV h = 0x1234;
    SET_ERR(0);
    BOOL ok = cpc_acq_c(&h, "cpc_name", P->a, P->type, X_VERIFY);
    CHECK(!ok); EXPECT_ERR(X_NTE_BAD_FLAGS);
    EXPECT_EQ(h, 0);
    if (ok) cpc_rel(h);
    /* the empty string is the same as NULL */
    h = 0;
    ok = cpc_acq_c(&h, "", P->a, P->type, X_VERIFY);
    CHECKF(ok, "err 0x%lx", GetLastError());
    if (ok) { CHECK(h != 0); cpc_rel(h); }
    h = 0;
    ok = cpc_acq_c(&h, NULL, P->a, P->type, X_VERIFY);
    CHECKF(ok, "err 0x%lx", GetLastError());
    if (ok) { CHECK(h != 0); cpc_rel(h); }
}
PERPROV(cpc_acquire_container_rules, acq_container)

/* Flag bits outside the CSP's mask (0x0fffff87 plus the VERIFYCONTEXT nibble). */
static void acq_flagbits(int i) {
    const cpc_prov *P = &cpc_provs[i];
    REQUIRE(U(CryptAcquireContextA));
    DWORD bits[] = { 0x1, 0x2, 0x4, 0x80, 0x100, 0x200, 0x400, 0x800, 0x1000, 0x2000, 0x4000, 0x8000,
                     0x10000, 0x20000, 0x40000, 0x80000, 0x100000, 0x200000, 0x400000, 0x800000,
                     0x1000000, 0x2000000, 0x4000000, 0x8000000 };
    for (unsigned k = 0; k < sizeof bits / sizeof bits[0]; k++) {
        HCRYPTPROV h = 0x77;
        SET_ERR(0);
        BOOL ok = cpc_acq(&h, P->a, P->type, X_VERIFY | bits[k]);
        CHECKF(!ok, "bit 0x%lx accepted", bits[k]);
        if (ok) { cpc_rel(h); continue; }
        t_check(GetLastError() == X_NTE_BAD_FLAGS, __FILE__, __LINE__, "bad flag err", "bit 0x%lx err 0x%lx", bits[k], GetLastError());
    }
}
PERPROV(cpc_acquire_bad_flag_bits, acq_flagbits)

/* A type that is valid but differs from the provider's registered Type -> NTE_PROV_TYPE_NO_MATCH. */
static void acq_nomatch(int i) {
    const cpc_prov *P = &cpc_provs[i];
    REQUIRE(U(CryptAcquireContextA));
    HCRYPTPROV h = 0x55;
    DWORD other = (P->type % 999) + 1;
    SET_ERR(0);
    BOOL ok = cpc_acq(&h, P->a, other, X_VERIFY);
    CHECK(!ok); EXPECT_ERR(X_NTE_PROV_TYPE_NO_MATCH);
    EXPECT_EQ(h, 0x55);   /* failed before the CSP was loaded */
    if (ok) cpc_rel(h);
    /* the always-wrong types 1..24 */
    for (DWORD t = 1; t <= 24; t++) {
        if (t == P->type) continue;
        h = 0x55; SET_ERR(0);
        ok = cpc_acq(&h, P->a, t, X_VERIFY);
        t_check(!ok && GetLastError() == X_NTE_PROV_TYPE_NO_MATCH, __FILE__, __LINE__, "type mismatch", "type %lu ok=%d err 0x%lx", t, ok, GetLastError());
        if (ok) cpc_rel(h);
    }
}
PERPROV(cpc_acquire_type_mismatch, acq_nomatch)

/* Registry key lookup is case-insensitive; the context remembers the name as the caller spelled it. */
static void acq_case(int i) {
    const cpc_prov *P = &cpc_provs[i];
    REQUIRE(U(CryptAcquireContextA));
    char lo[200]; size_t n = strlen(P->a);
    for (size_t k = 0; k <= n; k++) lo[k] = (char)((P->a[k] >= 'A' && P->a[k] <= 'Z') ? P->a[k] + 32 : P->a[k]);
    HCRYPTPROV h = 0;
    BOOL ok = cpc_acq(&h, lo, P->type, X_VERIFY);
    CHECKF(ok, "lowercase name rejected 0x%lx", GetLastError());
    if (!ok) return;
    char nm[256] = {0}; DWORD ln = sizeof nm;
    CHECK(cpc_gpp(h, PP_NAME, nm, &ln, 0));
    EXPECT_STR(nm, lo);
    cpc_rel(h);
}
PERPROV(cpc_acquire_name_case, acq_case)

/* many contexts of the same provider are independent handles */
static void acq_multi(int i) {
    const cpc_prov *P = &cpc_provs[i];
    REQUIRE(U(CryptAcquireContextA));
    HCRYPTPROV h[6] = {0};
    int ok = 0;
    for (int k = 0; k < 6; k++) { if (cpc_acq(&h[k], P->a, P->type, X_VERIFY)) ok++; }
    EXPECT_EQ(ok, 6);
    for (int a = 0; a < 6; a++) for (int b = a + 1; b < 6; b++) if (h[a] && h[b]) CHECK(h[a] != h[b]);
    for (int k = 5; k >= 0; k--) cpc_rel(h[k]);
}
PERPROV(cpc_acquire_multiple, acq_multi)

/* ---------------------------------------------------------------- default provider per type */
static void defprov(DWORD type, BOOL expect_ok) {
    REQUIRE(U(CryptAcquireContextA)); REQUIRE(U(CryptGetDefaultProviderA));
    char def[256] = {0}; DWORD dl = sizeof def;
    BOOL got = U(CryptGetDefaultProviderA)(type, NULL, 0, def, &dl);
    if (!got) { if (expect_ok) CHECKF(0, "no default for type %lu: 0x%lx", type, GetLastError()); return; }
    HCRYPTPROV h = 0;
    BOOL ok = cpc_acq(&h, NULL, type, X_VERIFY);
    CHECKF(ok, "NULL provider type %lu err 0x%lx", type, GetLastError());
    if (!ok) return;
    char nm[256] = {0}; DWORD ln = sizeof nm;
    CHECK(cpc_gpp(h, PP_NAME, nm, &ln, 0));
    EXPECT_STR(nm, def);
    DWORD ty; CHECK(cpc_gpp_dw(h, PP_PROVTYPE, &ty)); EXPECT_EQ(ty, type);
    cpc_rel(h);
    /* empty provider string is identical to NULL */
    h = 0;
    ok = cpc_acq(&h, "", type, X_VERIFY);
    CHECK(ok);
    if (ok) {
        ln = sizeof nm; memset(nm, 0, sizeof nm);
        CHECK(cpc_gpp(h, PP_NAME, nm, &ln, 0)); EXPECT_STR(nm, def);
        cpc_rel(h);
    }
}
TEST(cpc_acquire_default_type1)  { defprov(PROV_RSA_FULL, 1); }
TEST(cpc_acquire_default_type2)  { defprov(PROV_RSA_SIG, 0); }
TEST(cpc_acquire_default_type3)  { defprov(PROV_DSS, 1); }
TEST(cpc_acquire_default_type12) { defprov(PROV_RSA_SCHANNEL, 1); }
TEST(cpc_acquire_default_type13) { defprov(PROV_DSS_DH, 1); }
TEST(cpc_acquire_default_type18) { defprov(PROV_DH_SCHANNEL, 1); }
TEST(cpc_acquire_default_type24) { defprov(PROV_RSA_AES, 1); }

TEST(cpc_acquire_default_w_matches_a) {
    REQUIRE(U(CryptAcquireContextW)); REQUIRE(U(CryptGetProvParam));
    DWORD types[] = { 1, 2, 3, 12, 13, 18, 24 };
    for (unsigned k = 0; k < 7; k++) {
        HCRYPTPROV ha = 0, hw = 0;
        BOOL oa = cpc_acq(&ha, NULL, types[k], X_VERIFY);
        BOOL ow = U(CryptAcquireContextW)(&hw, NULL, NULL, types[k], X_VERIFY);
        CHECK(oa == ow);
        if (oa && ow) {
            char a[256] = {0}, b[256] = {0}; DWORD la = sizeof a, lb = sizeof b;
            CHECK(cpc_gpp(ha, PP_NAME, a, &la, 0)); CHECK(cpc_gpp(hw, PP_NAME, b, &lb, 0));
            EXPECT_STR(a, b);
        }
        cpc_rel(ha); cpc_rel(hw);
    }
}

TEST(cpc_acquire_w_empty_provider_is_default) {
    REQUIRE(U(CryptAcquireContextW));
    HCRYPTPROV h = 0;
    BOOL ok = U(CryptAcquireContextW)(&h, NULL, L"", PROV_RSA_FULL, X_VERIFY);
    CHECKF(ok, "err 0x%lx", GetLastError());
    cpc_rel(h);
}

/* ---------------------------------------------------------------- error codes */
TEST(cpc_acquire_type_zero) {
    REQUIRE(U(CryptAcquireContextA));
    HCRYPTPROV h = 0x99; SET_ERR(0);
    BOOL ok = cpc_acq(&h, NULL, 0, X_VERIFY);
    CHECK(!ok); EXPECT_ERR(X_NTE_BAD_PROV_TYPE); EXPECT_EQ(h, 0x99);
    h = 0x99; SET_ERR(0);
    ok = cpc_acq(&h, MS_DEF_PROV_A, 0, X_VERIFY);
    CHECK(!ok); EXPECT_ERR(X_NTE_BAD_PROV_TYPE); EXPECT_EQ(h, 0x99);
}
TEST(cpc_acquire_type_out_of_range) {
    REQUIRE(U(CryptAcquireContextA));
    DWORD bad[] = { 1000, 1001, 0x7fffffff, 0x80000000, 0xfffffffe, 0xffffffff };
    for (unsigned k = 0; k < 6; k++) {
        HCRYPTPROV h = 0x99; SET_ERR(0);
        BOOL ok = cpc_acq(&h, NULL, bad[k], X_VERIFY);
        t_check(!ok && GetLastError() == X_NTE_BAD_PROV_TYPE, __FILE__, __LINE__, "bad type", "type %lu ok=%d err 0x%lx", bad[k], ok, GetLastError());
        EXPECT_EQ(h, 0x99);
        if (ok) cpc_rel(h);
    }
}
TEST(cpc_acquire_type_out_of_range_w) {
    REQUIRE(U(CryptAcquireContextW));
    DWORD bad[] = { 0, 1000, 0xffffffff };
    for (unsigned k = 0; k < 3; k++) {
        HCRYPTPROV h = 0x99; SET_ERR(0);
        BOOL ok = U(CryptAcquireContextW)(&h, NULL, NULL, bad[k], X_VERIFY);
        CHECK(!ok); EXPECT_ERR(X_NTE_BAD_PROV_TYPE); EXPECT_EQ(h, 0x99);
    }
}
TEST(cpc_acquire_type_999_not_defined) {
    REQUIRE(U(CryptAcquireContextA));
    HCRYPTPROV h = 0x99; SET_ERR(0);
    BOOL ok = cpc_acq(&h, NULL, 999, X_VERIFY);
    CHECK(!ok); EXPECT_ERR(X_NTE_PROV_TYPE_NOT_DEF);
    EXPECT_EQ(h, 0x99);
}
TEST(cpc_acquire_undefined_types_null_provider) {
    REQUIRE(U(CryptAcquireContextA));
    DWORD t[] = { 500, 998, 100, 255 };
    for (unsigned k = 0; k < 4; k++) {
        HCRYPTPROV h = 0; SET_ERR(0);
        BOOL ok = cpc_acq(&h, NULL, t[k], X_VERIFY);
        t_check(!ok && GetLastError() == X_NTE_PROV_TYPE_NOT_DEF, __FILE__, __LINE__, "type not def", "type %lu ok=%d err 0x%lx", t[k], ok, GetLastError());
        if (ok) cpc_rel(h);
    }
}
TEST(cpc_acquire_unknown_provider_name) {
    REQUIRE(U(CryptAcquireContextA));
    const char *names[] = { "cpc no such provider", "Microsoft Base Cryptographic Provider v1.1", " ",
                            "Microsoft Base Cryptographic Provider v1.0 ", "Microsoft", "x\\y" };
    for (unsigned k = 0; k < 6; k++) {
        HCRYPTPROV h = 0x31; SET_ERR(0);
        BOOL ok = cpc_acq(&h, names[k], 1, X_VERIFY);
        t_check(!ok && GetLastError() == X_NTE_KEYSET_NOT_DEF, __FILE__, __LINE__, "unknown provider", "\"%s\" ok=%d err 0x%lx", names[k], ok, GetLastError());
        EXPECT_EQ(h, 0x31);
        if (ok) cpc_rel(h);
    }
}
TEST(cpc_acquire_unknown_provider_name_w) {
    REQUIRE(U(CryptAcquireContextW));
    HCRYPTPROV h = 0x31; SET_ERR(0);
    BOOL ok = U(CryptAcquireContextW)(&h, NULL, L"cpc no such provider", 1, X_VERIFY);
    CHECK(!ok); EXPECT_ERR(X_NTE_KEYSET_NOT_DEF);
    EXPECT_EQ(h, 0x31);
}
TEST(cpc_acquire_unknown_provider_checked_before_type) {
    /* provider lookup happens after the 1..999 type range check, before the type match */
    REQUIRE(U(CryptAcquireContextA));
    HCRYPTPROV h = 0; SET_ERR(0);
    CHECK(!cpc_acq(&h, "cpc no such provider", 0, X_VERIFY)); EXPECT_ERR(X_NTE_BAD_PROV_TYPE);
    SET_ERR(0);
    CHECK(!cpc_acq(&h, "cpc no such provider", 1000, X_VERIFY)); EXPECT_ERR(X_NTE_BAD_PROV_TYPE);
}
TEST(cpc_acquire_type_nomatch_dss_name_rsa_type) {
    REQUIRE(U(CryptAcquireContextA));
    HCRYPTPROV h = 0; SET_ERR(0);
    CHECK(!cpc_acq(&h, MS_DEF_DSS_PROV_A, PROV_RSA_FULL, X_VERIFY)); EXPECT_ERR(X_NTE_PROV_TYPE_NO_MATCH);
    SET_ERR(0);
    CHECK(!cpc_acq(&h, MS_DEF_PROV_A, PROV_DSS, X_VERIFY)); EXPECT_ERR(X_NTE_PROV_TYPE_NO_MATCH);
    SET_ERR(0);
    CHECK(!cpc_acq(&h, MS_DEF_RSA_SIG_PROV_A, PROV_RSA_FULL, X_VERIFY)); EXPECT_ERR(X_NTE_PROV_TYPE_NO_MATCH);
}
TEST(cpc_acquire_xp_aes_name_note) {
    REQUIRE(U(CryptAcquireContextA));
    HCRYPTPROV h = 0;
    BOOL ok = cpc_acq(&h, MS_ENH_RSA_AES_PROV_XP_A, PROV_RSA_AES, X_VERIFY);
    t_note("XP prototype AES provider name \"%s\": %s (0x%lx)", MS_ENH_RSA_AES_PROV_XP_A, ok ? "accepted" : "rejected", ok ? 0 : GetLastError());
    cpc_rel(h);
    h = 0;
    ok = cpc_acq(&h, "Microsoft AES Cryptographic Provider", PROV_RSA_AES, X_VERIFY);
    t_note("\"Microsoft AES Cryptographic Provider\": %s (0x%lx)", ok ? "accepted" : "rejected", ok ? 0 : GetLastError());
    cpc_rel(h);
}
TEST(cpc_acquire_smartcard_provider_note) {
    REQUIRE(U(CryptAcquireContextA));
    HCRYPTPROV h = 0;
    BOOL ok = cpc_acq(&h, MS_SCARD_PROV_A, PROV_RSA_FULL, X_VERIFY);
    t_note("%s VERIFYCONTEXT: %s (0x%lx)", MS_SCARD_PROV_A, ok ? "ok" : "fail", ok ? 0 : GetLastError());
    cpc_rel(h);
}

/* Flag combinations independent of the provider */
TEST(cpc_acquire_flags_verify_with_silent_and_machine) {
    REQUIRE(U(CryptAcquireContextA));
    HCRYPTPROV h = 0;
    BOOL ok = cpc_acq(&h, MS_DEF_PROV_A, 1, X_VERIFY | CRYPT_SILENT);
    CHECK(ok); cpc_rel(h);
    h = 0;
    ok = cpc_acq(&h, MS_DEF_PROV_A, 1, X_VERIFY | CRYPT_SILENT | CRYPT_MACHINE_KEYSET);
    if (ok) cpc_rel(h);
    else CHECKF(GetLastError() == ERROR_ACCESS_DENIED, "err 0x%lx", GetLastError());
}
TEST(cpc_acquire_flags_bit0_without_verify_rejected_early) {
    /* bit 0x1 is outside the CSP mask on its own too; it fails before any container is touched */
    REQUIRE(U(CryptAcquireContextA));
    HCRYPTPROV h = 0; SET_ERR(0);
    BOOL ok = cpc_acq_c(&h, "cpc_unused_name", MS_DEF_PROV_A, 1, 0x1);
    CHECK(!ok); EXPECT_ERR(X_NTE_BAD_FLAGS);
    SET_ERR(0);
    ok = cpc_acq_c(&h, "cpc_unused_name", MS_DEF_PROV_A, 1, 0x80);
    CHECK(!ok); EXPECT_ERR(X_NTE_BAD_FLAGS);
    SET_ERR(0);
    ok = cpc_acq_c(&h, "cpc_unused_name", MS_DEF_DSS_PROV_A, 3, 0x1);
    CHECK(!ok); EXPECT_ERR(X_NTE_BAD_FLAGS);
}
TEST(cpc_acquire_flags_verify_name_long) {
    REQUIRE(U(CryptAcquireContextA));
    char big[400]; memset(big, 'a', sizeof big - 1); big[sizeof big - 1] = 0;
    HCRYPTPROV h = 0; SET_ERR(0);
    BOOL ok = cpc_acq_c(&h, big, MS_DEF_PROV_A, 1, X_VERIFY);
    CHECK(!ok); EXPECT_ERR(X_NTE_BAD_FLAGS);
}

/* ---------------------------------------------------------------- release / addref */
TEST(cpc_release_basic) {
    REQUIRE(U(CryptAcquireContextA)); REQUIRE(U(CryptReleaseContext));
    HCRYPTPROV h = 0;
    CHECK(cpc_acq(&h, MS_DEF_PROV_A, 1, X_VERIFY));
    SET_ERR(0);
    CHECK(U(CryptReleaseContext)(h, 0));
}
TEST(cpc_release_all_providers) {
    REQUIRE(U(CryptAcquireContextA)); REQUIRE(U(CryptReleaseContext));
    for (int i = 0; i < cpc_nprovs; i++) {
        HCRYPTPROV h = 0;
        if (!cpc_acq(&h, cpc_provs[i].a, cpc_provs[i].type, X_VERIFY)) { CHECKF(0, "acquire %s", cpc_provs[i].a); continue; }
        t_check(U(CryptReleaseContext)(h, 0), __FILE__, __LINE__, "release", "%s err 0x%lx", cpc_provs[i].a, GetLastError());
    }
}
TEST(cpc_addref_basic) {
    REQUIRE(U(CryptAcquireContextA)); REQUIRE(U(CryptContextAddRef)); REQUIRE(U(CryptReleaseContext));
    HCRYPTPROV h = 0;
    CHECK(cpc_acq(&h, MS_DEF_PROV_A, 1, X_VERIFY));
    SET_ERR(0);
    CHECK(U(CryptContextAddRef)(h, NULL, 0));
    /* first release only drops the extra reference: handle still usable */
    CHECK(U(CryptReleaseContext)(h, 0));
    char nm[128]; DWORD n = sizeof nm;
    CHECK(cpc_gpp(h, PP_NAME, nm, &n, 0));
    EXPECT_STR(nm, MS_DEF_PROV_A);
    CHECK(U(CryptReleaseContext)(h, 0));
}
TEST(cpc_addref_many) {
    REQUIRE(U(CryptAcquireContextA)); REQUIRE(U(CryptContextAddRef)); REQUIRE(U(CryptReleaseContext));
    HCRYPTPROV h = 0;
    CHECK(cpc_acq(&h, MS_ENHANCED_PROV_A, 1, X_VERIFY));
    for (int k = 0; k < 100; k++) CHECK(U(CryptContextAddRef)(h, NULL, 0));
    for (int k = 0; k < 100; k++) {
        CHECK(U(CryptReleaseContext)(h, 0));
        DWORD v; if (k % 25 == 0) CHECK(cpc_gpp_dw(h, PP_PROVTYPE, &v));
    }
    DWORD v; CHECK(cpc_gpp_dw(h, PP_PROVTYPE, &v)); EXPECT_EQ(v, 1);
    CHECK(U(CryptReleaseContext)(h, 0));
}
static void addref_all(int i) {
    const cpc_prov *P = &cpc_provs[i];
    REQUIRE(U(CryptContextAddRef)); REQUIRE(U(CryptReleaseContext));
    HCRYPTPROV h = 0;
    if (!cpc_acq(&h, P->a, P->type, X_VERIFY)) { CHECK(0); return; }
    CHECK(U(CryptContextAddRef)(h, NULL, 0));
    CHECK(U(CryptReleaseContext)(h, 0));
    DWORD v; CHECK(cpc_gpp_dw(h, PP_PROVTYPE, &v)); EXPECT_EQ(v, P->type);
    CHECK(U(CryptReleaseContext)(h, 0));
}
PERPROV(cpc_addref_provider, addref_all)

TEST(cpc_addref_bad_reserved) {
    REQUIRE(U(CryptAcquireContextA)); REQUIRE(U(CryptContextAddRef)); REQUIRE(U(CryptReleaseContext));
    HCRYPTPROV h = 0;
    CHECK(cpc_acq(&h, MS_DEF_PROV_A, 1, X_VERIFY));
    DWORD reserved = 0;
    SET_ERR(0);
    CHECK(!U(CryptContextAddRef)(h, &reserved, 0)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0);
    CHECK(!U(CryptContextAddRef)(h, NULL, 1)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0);
    CHECK(!U(CryptContextAddRef)(h, NULL, 0x80000000)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    /* a failed AddRef did not take a reference: one release frees the context */
    CHECK(U(CryptReleaseContext)(h, 0));
}
TEST(cpc_addref_independent_contexts) {
    REQUIRE(U(CryptAcquireContextA)); REQUIRE(U(CryptContextAddRef)); REQUIRE(U(CryptReleaseContext));
    HCRYPTPROV a = 0, b = 0;
    CHECK(cpc_acq(&a, MS_DEF_PROV_A, 1, X_VERIFY));
    CHECK(cpc_acq(&b, MS_DEF_PROV_A, 1, X_VERIFY));
    CHECK(U(CryptContextAddRef)(a, NULL, 0));
    CHECK(U(CryptReleaseContext)(b, 0));
    CHECK(U(CryptReleaseContext)(a, 0));
    DWORD v; CHECK(cpc_gpp_dw(a, PP_PROVTYPE, &v));
    CHECK(U(CryptReleaseContext)(a, 0));
}
TEST(cpc_addref_context_survives_other_release) {
    REQUIRE(U(CryptAcquireContextA)); REQUIRE(U(CryptGenRandom));
    HCRYPTPROV a = 0, b = 0;
    CHECK(cpc_acq(&a, MS_DEF_PROV_A, 1, X_VERIFY));
    CHECK(cpc_acq(&b, MS_DEF_PROV_A, 1, X_VERIFY));
    cpc_rel(a);
    BYTE buf[16];
    CHECK(U(CryptGenRandom)(b, sizeof buf, buf));
    cpc_rel(b);
}
typedef struct { HCRYPTPROV h; BOOL ok; BOOL (WINAPI *gr)(HCRYPTPROV, DWORD, BYTE *); BOOL (WINAPI *rel)(HCRYPTPROV, DWORD); } cpc_thr;
static DWORD WINAPI cpc_thr_fn(LPVOID p) {
    cpc_thr *c = p; BYTE b[8];
    c->ok = c->gr(c->h, sizeof b, b) && c->rel(c->h, 0);
    return 0;
}
TEST(cpc_release_from_other_thread) {
    REQUIRE(U(CryptAcquireContextA)); REQUIRE(U(CryptReleaseContext)); REQUIRE(U(CryptGenRandom));
    HCRYPTPROV h = 0;
    CHECK(cpc_acq(&h, MS_DEF_PROV_A, 1, X_VERIFY));
    if (!h) return;
    cpc_thr ctx = { h, 0, U(CryptGenRandom), U(CryptReleaseContext) };
    HANDLE t = CreateThread(NULL, 0, cpc_thr_fn, &ctx, 0, NULL);
    CHECK(t != NULL);
    if (t) {
        DWORD w = WaitForSingleObject(t, 10000);
        CHECK(w == WAIT_OBJECT_0);
        if (w == WAIT_OBJECT_0) CHECK(ctx.ok); else TerminateThread(t, 0);
        CloseHandle(t);
    } else cpc_rel(h);
}
