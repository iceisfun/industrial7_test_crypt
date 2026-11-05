#include "cpc.h"
/* CryptEnumProviders[AW], CryptEnumProviderTypes[AW], CryptGetDefaultProvider[AW] (all read-only).
 * The W variants are wrappers over the A ones; their size arguments are BYTE counts including the NUL. */

#define MAXP 200

typedef struct { char name[256]; DWORD type; } eprov;

static int collect_providers(eprov *out, int max) {
    int n = 0;
    for (DWORD idx = 0; idx < (DWORD)max; idx++) {
        DWORD ty = 0, len = 0;
        if (!U(CryptEnumProvidersA)(idx, NULL, 0, &ty, NULL, &len)) return GetLastError() == ERROR_NO_MORE_ITEMS ? n : -1;
        if (len >= sizeof out[n].name) return -2;
        DWORD l2 = len;
        if (!U(CryptEnumProvidersA)(idx, NULL, 0, &ty, out[n].name, &l2)) return -3;
        if (l2 != len) return -4;
        out[n].type = ty; n++;
    }
    return -5;
}
static int find_prov(const eprov *e, int n, const char *name, DWORD type) {
    for (int k = 0; k < n; k++) if (!strcmp(e[k].name, name) && e[k].type == type) return 1;
    return 0;
}

TEST(cpc_enumprov_full_listing) {
    REQUIRE(U(CryptEnumProvidersA));
    eprov e[MAXP]; int n = collect_providers(e, MAXP);
    CHECKF(n > 0, "n=%d err 0x%lx", n, GetLastError());
    if (n <= 0) return;
    for (int k = 0; k < n; k++) {
        CHECK(e[k].name[0] != 0);
        CHECK(e[k].type >= 1 && e[k].type <= 999);
        for (int j = k + 1; j < n; j++) CHECK(strcmp(e[k].name, e[j].name) != 0);
        t_note("provider %d: type %lu \"%s\"", k, e[k].type, e[k].name);
    }
}
TEST(cpc_enumprov_contains_default_providers) {
    REQUIRE(U(CryptEnumProvidersA));
    eprov e[MAXP]; int n = collect_providers(e, MAXP);
    CHECK(n > 0);
    for (int i = 0; i < cpc_nprovs; i++)
        t_check(find_prov(e, n, cpc_provs[i].a, cpc_provs[i].type), __FILE__, __LINE__, "listed", "missing \"%s\" type %lu", cpc_provs[i].a, cpc_provs[i].type);
}
TEST(cpc_enumprov_each_acquirable_or_explained) {
    /* every registered provider resolves its registry entry: the failure, if any, is never a registry-level one */
    REQUIRE(U(CryptEnumProvidersA)); REQUIRE(U(CryptAcquireContextA));
    eprov e[MAXP]; int n = collect_providers(e, MAXP);
    for (int k = 0; k < n; k++) {
        /* only load the in-box software CSPs: third-party or token-backed providers may block or prompt */
        int known = 0;
        for (int i = 0; i < cpc_nprovs; i++) if (!strcmp(cpc_provs[i].a, e[k].name)) known = 1;
        if (!known) { t_note("not loading \"%s\" (type %lu)", e[k].name, e[k].type); continue; }
        HCRYPTPROV h = 0; SET_ERR(0);
        BOOL ok = cpc_acq(&h, e[k].name, e[k].type, X_VERIFY);
        if (ok) { cpc_rel(h); continue; }
        DWORD err = GetLastError();
        t_note("\"%s\" type %lu VERIFYCONTEXT failed 0x%lx", e[k].name, e[k].type, err);
        t_check(err != X_NTE_KEYSET_NOT_DEF && err != X_NTE_PROV_TYPE_NO_MATCH && err != X_NTE_BAD_PROV_TYPE, __FILE__, __LINE__, "registry level error", "\"%s\" type %lu err 0x%lx", e[k].name, e[k].type, err);
    }
}
TEST(cpc_enumprov_wrong_type_never_matches) {
    REQUIRE(U(CryptEnumProvidersA)); REQUIRE(U(CryptAcquireContextA));
    eprov e[MAXP]; int n = collect_providers(e, MAXP);
    for (int k = 0; k < n; k++) {
        HCRYPTPROV h = 0; SET_ERR(0);
        DWORD other = (e[k].type % 999) + 1;
        BOOL ok = cpc_acq(&h, e[k].name, other, X_VERIFY);
        t_check(!ok && GetLastError() == X_NTE_PROV_TYPE_NO_MATCH, __FILE__, __LINE__, "type no match", "\"%s\" as type %lu ok=%d err 0x%lx", e[k].name, other, ok, GetLastError());
        if (ok) cpc_rel(h);
    }
}
TEST(cpc_enumprov_end_of_list) {
    REQUIRE(U(CryptEnumProvidersA));
    eprov e[MAXP]; int n = collect_providers(e, MAXP);
    CHECK(n > 0);
    DWORD ty = 0x77, len = 300; char name[300];
    DWORD idxs[] = { (DWORD)n, (DWORD)n + 1, 1000, 0x7fffffff, 0xffffffff };
    for (unsigned k = 0; k < 5; k++) {
        SET_ERR(0); ty = 0x77; len = 300;
        BOOL ok = U(CryptEnumProvidersA)(idxs[k], NULL, 0, &ty, name, &len);
        t_check(!ok && GetLastError() == ERROR_NO_MORE_ITEMS, __FILE__, __LINE__, "past end", "idx %lu ok=%d err 0x%lx", idxs[k], ok, GetLastError());
        EXPECT_EQ(ty, 0x77);
    }
}
TEST(cpc_enumprov_size_protocol) {
    REQUIRE(U(CryptEnumProvidersA));
    DWORD ty = 0, len = 0; char buf[300];
    SET_ERR(0);
    CHECK(U(CryptEnumProvidersA)(0, NULL, 0, &ty, NULL, &len));
    CHECK(len > 1 && len < 256); CHECK(ty >= 1 && ty <= 999);
    DWORD need = len, ty0 = ty;
    len = 0; ty = 0;
    CHECK(U(CryptEnumProvidersA)(0, NULL, 0, &ty, NULL, &len)); EXPECT_EQ(len, need); EXPECT_EQ(ty, ty0);
    /* too small: the type is still reported, name is not copied */
    memset(buf, 0x5a, sizeof buf); len = need - 1; ty = 0; SET_ERR(0);
    CHECK(!U(CryptEnumProvidersA)(0, NULL, 0, &ty, buf, &len)); EXPECT_ERR(ERROR_MORE_DATA);
    EXPECT_EQ(len, need); EXPECT_EQ(buf[0], 0x5a); EXPECT_EQ(ty, ty0);
    memset(buf, 0x5a, sizeof buf); len = 0; SET_ERR(0);
    CHECK(!U(CryptEnumProvidersA)(0, NULL, 0, &ty, buf, &len)); EXPECT_ERR(ERROR_MORE_DATA); EXPECT_EQ(len, need);
    /* exact */
    memset(buf, 0x5a, sizeof buf); len = need; SET_ERR(0);
    CHECK(U(CryptEnumProvidersA)(0, NULL, 0, &ty, buf, &len)); EXPECT_EQ(len, need);
    EXPECT_EQ(strlen(buf) + 1, need); EXPECT_EQ((unsigned char)buf[need], 0x5a);
    /* larger */
    len = sizeof buf;
    CHECK(U(CryptEnumProvidersA)(0, NULL, 0, &ty, buf, &len)); EXPECT_EQ(len, need);
}
TEST(cpc_enumprov_bad_args) {
    REQUIRE(U(CryptEnumProvidersA));
    DWORD ty = 0, len = 300, res = 0; char buf[300];
    SET_ERR(0);
    CHECK(!U(CryptEnumProvidersA)(0, &res, 0, &ty, buf, &len)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    DWORD fl[] = { 1, 2, 4, 0x80, 0x10000, 0x80000000, 0xffffffff };
    for (unsigned k = 0; k < 7; k++) {
        len = 300; SET_ERR(0);
        BOOL ok = U(CryptEnumProvidersA)(0, NULL, fl[k], &ty, buf, &len);
        t_check(!ok && GetLastError() == X_NTE_BAD_FLAGS, __FILE__, __LINE__, "flags", "flags 0x%lx ok=%d err 0x%lx", fl[k], ok, GetLastError());
    }
    /* the reserved check comes first */
    len = 300; SET_ERR(0);
    CHECK(!U(CryptEnumProvidersA)(0, &res, 1, &ty, buf, &len)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
}
TEST(cpc_enumprov_w_matches_a) {
    REQUIRE(U(CryptEnumProvidersA)); REQUIRE(U(CryptEnumProvidersW));
    eprov e[MAXP]; int n = collect_providers(e, MAXP);
    CHECK(n > 0);
    for (int k = 0; k < n; k++) {
        DWORD ty = 0, len = 0; WCHAR w[300];
        SET_ERR(0);
        CHECK(U(CryptEnumProvidersW)(k, NULL, 0, &ty, NULL, &len));
        EXPECT_EQ(len, (strlen(e[k].name) + 1) * sizeof(WCHAR));   /* bytes, NUL included */
        EXPECT_EQ(ty, e[k].type);
        memset(w, 0x5a, sizeof w);
        DWORD l2 = len;
        CHECK(U(CryptEnumProvidersW)(k, NULL, 0, &ty, w, &l2)); EXPECT_EQ(l2, len);
        char back[300]; WideCharToMultiByte(CP_ACP, 0, w, -1, back, sizeof back, NULL, NULL);
        EXPECT_STR(back, e[k].name);
        EXPECT_EQ(w[len / 2 - 1], 0);
        /* one byte short, and one WCHAR short */
        memset(w, 0x5a, sizeof w); l2 = len - 1; SET_ERR(0);
        CHECK(!U(CryptEnumProvidersW)(k, NULL, 0, &ty, w, &l2)); EXPECT_ERR(ERROR_MORE_DATA); EXPECT_EQ(l2, len); EXPECT_EQ(w[0], 0x5a5a);
        l2 = len - 2; SET_ERR(0);
        CHECK(!U(CryptEnumProvidersW)(k, NULL, 0, &ty, w, &l2)); EXPECT_ERR(ERROR_MORE_DATA);
    }
}
TEST(cpc_enumprov_w_errors) {
    REQUIRE(U(CryptEnumProvidersW));
    DWORD ty = 0x66, len = 0; WCHAR w[300]; DWORD res = 0;
    SET_ERR(0);
    CHECK(!U(CryptEnumProvidersW)(0xffffffff, NULL, 0, &ty, NULL, &len)); EXPECT_ERR(ERROR_NO_MORE_ITEMS);
    len = 600; SET_ERR(0);
    CHECK(!U(CryptEnumProvidersW)(0, &res, 0, &ty, w, &len)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0);
    CHECK(!U(CryptEnumProvidersW)(0, NULL, 1, &ty, w, &len)); EXPECT_ERR(X_NTE_BAD_FLAGS);
}
TEST(cpc_enumprov_via_advapi32_and_cryptsp) {
    REQUIRE(UIN("advapi32.dll", CryptEnumProvidersA)); REQUIRE(UIN("cryptsp.dll", CryptEnumProvidersA));
    for (DWORD i = 0; i < 4; i++) {
        char a[300] = {0}, b[300] = {0}; DWORD la = sizeof a, lb = sizeof b, ta = 0, tb = 0;
        BOOL oa = UIN("advapi32.dll", CryptEnumProvidersA)(i, NULL, 0, &ta, a, &la);
        BOOL ob = UIN("cryptsp.dll", CryptEnumProvidersA)(i, NULL, 0, &tb, b, &lb);
        CHECK(oa == ob);
        if (oa && ob) { EXPECT_STR(a, b); EXPECT_EQ(ta, tb); EXPECT_EQ(la, lb); }
    }
    SET_ERR(0);
    DWORD ty, len = 0;
    CHECK(!UIN("advapi32.dll", CryptEnumProvidersA)(0x7fffffff, NULL, 0, &ty, NULL, &len)); EXPECT_ERR(ERROR_NO_MORE_ITEMS);
}

/* ------------------------------------------------------------ provider types */
typedef struct { DWORD type; char name[256]; } etype;
static int collect_types(etype *out, int max) {
    int n = 0;
    for (DWORD idx = 0; idx < (DWORD)max; idx++) {
        DWORD ty = 0, len = 0;
        if (!U(CryptEnumProviderTypesA)(idx, NULL, 0, &ty, NULL, &len)) return GetLastError() == ERROR_NO_MORE_ITEMS ? n : -1;
        if (len >= sizeof out[n].name) return -2;
        DWORD l2 = len;
        out[n].name[0] = 0;
        if (!U(CryptEnumProviderTypesA)(idx, NULL, 0, &ty, len ? out[n].name : NULL, &l2)) return -3;
        out[n].type = ty; n++;
    }
    return -5;
}
TEST(cpc_enumtypes_full_listing) {
    REQUIRE(U(CryptEnumProviderTypesA));
    etype t[MAXP]; int n = collect_types(t, MAXP);
    CHECKF(n > 0, "n=%d err 0x%lx", n, GetLastError());
    for (int k = 0; k < n; k++) {
        CHECK(t[k].type >= 1 && t[k].type <= 999);
        for (int j = k + 1; j < n; j++) CHECK(t[k].type != t[j].type);
        t_note("type %lu \"%s\"", t[k].type, t[k].name);
    }
}
TEST(cpc_enumtypes_contains_standard_types) {
    REQUIRE(U(CryptEnumProviderTypesA));
    etype t[MAXP]; int n = collect_types(t, MAXP);
    DWORD want[] = { PROV_RSA_FULL, PROV_DSS, PROV_RSA_SCHANNEL, PROV_DSS_DH, PROV_DH_SCHANNEL, PROV_RSA_AES };
    for (unsigned w = 0; w < 6; w++) {
        int f = 0; for (int k = 0; k < n; k++) if (t[k].type == want[w]) f = 1;
        t_check(f, __FILE__, __LINE__, "type listed", "type %lu missing", want[w]);
    }
    int f2 = 0; for (int k = 0; k < n; k++) if (t[k].type == PROV_RSA_SIG) f2 = 1;
    t_note("PROV_RSA_SIG (type 2) %s in the type list", f2 ? "present" : "absent");
}
TEST(cpc_enumtypes_ordered_note) {
    REQUIRE(U(CryptEnumProviderTypesA));
    etype t[MAXP]; int n = collect_types(t, MAXP);
    int asc = 1; for (int k = 1; k < n; k++) if (t[k].type <= t[k - 1].type) asc = 0;
    t_note("provider types enumerate in ascending order: %s", asc ? "yes" : "no");
}
TEST(cpc_enumtypes_every_provider_type_is_listed) {
    REQUIRE(U(CryptEnumProviderTypesA)); REQUIRE(U(CryptEnumProvidersA));
    etype t[MAXP]; int n = collect_types(t, MAXP);
    eprov e[MAXP]; int m = collect_providers(e, MAXP);
    for (int k = 0; k < m; k++) {
        int f = 0; for (int j = 0; j < n; j++) if (t[j].type == e[k].type) f = 1;
        t_check(f, __FILE__, __LINE__, "provider type registered", "\"%s\" type %lu has no Provider Types entry", e[k].name, e[k].type);
    }
}
TEST(cpc_enumtypes_end_and_args) {
    REQUIRE(U(CryptEnumProviderTypesA));
    etype t[MAXP]; int n = collect_types(t, MAXP);
    DWORD ty = 0x66, len = 300, res = 0; char buf[300];
    DWORD idxs[] = { (DWORD)n, (DWORD)n + 5, 0x7fffffff, 0xffffffff };
    for (unsigned k = 0; k < 4; k++) {
        len = 300; SET_ERR(0);
        BOOL ok = U(CryptEnumProviderTypesA)(idxs[k], NULL, 0, &ty, buf, &len);
        t_check(!ok && GetLastError() == ERROR_NO_MORE_ITEMS, __FILE__, __LINE__, "past end", "idx %lu err 0x%lx", idxs[k], GetLastError());
    }
    len = 300; SET_ERR(0);
    CHECK(!U(CryptEnumProviderTypesA)(0, &res, 0, &ty, buf, &len)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    DWORD fl[] = { 1, 2, 0x80000000, 0xffffffff };
    for (unsigned k = 0; k < 4; k++) {
        len = 300; SET_ERR(0);
        BOOL ok = U(CryptEnumProviderTypesA)(0, NULL, fl[k], &ty, buf, &len);
        t_check(!ok && GetLastError() == X_NTE_BAD_FLAGS, __FILE__, __LINE__, "flags", "flags 0x%lx err 0x%lx", fl[k], GetLastError());
    }
}
TEST(cpc_enumtypes_size_protocol) {
    REQUIRE(U(CryptEnumProviderTypesA));
    DWORD ty = 0, need = 0; char buf[300];
    SET_ERR(0);
    CHECK(U(CryptEnumProviderTypesA)(0, NULL, 0, &ty, NULL, &need));
    if (need < 2) { t_skip("first type has no TypeName value"); return; }
    DWORD len = need - 1; memset(buf, 0x5a, sizeof buf); SET_ERR(0);
    CHECK(!U(CryptEnumProviderTypesA)(0, NULL, 0, &ty, buf, &len)); EXPECT_ERR(ERROR_MORE_DATA); EXPECT_EQ(len, need); EXPECT_EQ(buf[0], 0x5a);
    len = need; CHECK(U(CryptEnumProviderTypesA)(0, NULL, 0, &ty, buf, &len)); EXPECT_EQ(len, need); EXPECT_EQ(strlen(buf) + 1, need);
    len = sizeof buf; CHECK(U(CryptEnumProviderTypesA)(0, NULL, 0, &ty, buf, &len)); EXPECT_EQ(len, need);
}
TEST(cpc_enumtypes_w_matches_a) {
    REQUIRE(U(CryptEnumProviderTypesA)); REQUIRE(U(CryptEnumProviderTypesW));
    etype t[MAXP]; int n = collect_types(t, MAXP);
    CHECK(n > 0);
    for (int k = 0; k < n; k++) {
        DWORD ty = 0, len = 0; WCHAR w[300];
        SET_ERR(0);
        CHECK(U(CryptEnumProviderTypesW)(k, NULL, 0, &ty, NULL, &len));
        EXPECT_EQ(ty, t[k].type);
        if (t[k].name[0] == 0) continue;
        EXPECT_EQ(len, (strlen(t[k].name) + 1) * sizeof(WCHAR));
        memset(w, 0, sizeof w);
        DWORD l2 = len;
        CHECK(U(CryptEnumProviderTypesW)(k, NULL, 0, &ty, w, &l2)); EXPECT_EQ(l2, len);
        char back[300]; WideCharToMultiByte(CP_ACP, 0, w, -1, back, sizeof back, NULL, NULL);
        EXPECT_STR(back, t[k].name);
        l2 = len - 1; SET_ERR(0);
        CHECK(!U(CryptEnumProviderTypesW)(k, NULL, 0, &ty, w, &l2)); EXPECT_ERR(ERROR_MORE_DATA); EXPECT_EQ(l2, len);
    }
}
TEST(cpc_enumtypes_w_errors) {
    REQUIRE(U(CryptEnumProviderTypesW));
    DWORD ty = 0, len = 600, res = 0; WCHAR w[300];
    SET_ERR(0);
    CHECK(!U(CryptEnumProviderTypesW)(0xffffffff, NULL, 0, &ty, w, &len)); EXPECT_ERR(ERROR_NO_MORE_ITEMS);
    SET_ERR(0);
    CHECK(!U(CryptEnumProviderTypesW)(0, &res, 0, &ty, w, &len)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0);
    CHECK(!U(CryptEnumProviderTypesW)(0, NULL, 2, &ty, w, &len)); EXPECT_ERR(X_NTE_BAD_FLAGS);
}
TEST(cpc_enumtypes_via_advapi32_and_cryptsp) {
    REQUIRE(UIN("advapi32.dll", CryptEnumProviderTypesA)); REQUIRE(UIN("cryptsp.dll", CryptEnumProviderTypesA));
    for (DWORD i = 0; i < 4; i++) {
        char a[300] = {0}, b[300] = {0}; DWORD la = sizeof a, lb = sizeof b, ta = 0, tb = 0;
        BOOL oa = UIN("advapi32.dll", CryptEnumProviderTypesA)(i, NULL, 0, &ta, a, &la);
        BOOL ob = UIN("cryptsp.dll", CryptEnumProviderTypesA)(i, NULL, 0, &tb, b, &lb);
        CHECK(oa == ob);
        if (oa && ob) { EXPECT_STR(a, b); EXPECT_EQ(ta, tb); }
    }
}

/* ------------------------------------------------------------ default providers */
static const DWORD deftypes[] = { PROV_RSA_FULL, PROV_DSS, PROV_RSA_SCHANNEL, PROV_DSS_DH, PROV_DH_SCHANNEL, PROV_RSA_AES };

TEST(cpc_defprov_names_are_registered_providers) {
    REQUIRE(U(CryptGetDefaultProviderA)); REQUIRE(U(CryptEnumProvidersA));
    eprov e[MAXP]; int n = collect_providers(e, MAXP);
    for (unsigned k = 0; k < 6; k++) {
        char nm[300]; DWORD len = sizeof nm; SET_ERR(0);
        BOOL ok = U(CryptGetDefaultProviderA)(deftypes[k], NULL, 0, nm, &len);
        t_check(ok, __FILE__, __LINE__, "default exists", "type %lu err 0x%lx", deftypes[k], GetLastError());
        if (!ok) continue;
        EXPECT_EQ(len, strlen(nm) + 1);
        t_check(find_prov(e, n, nm, deftypes[k]), __FILE__, __LINE__, "default listed", "type %lu default \"%s\" not enumerated", deftypes[k], nm);
        t_note("default provider for type %lu: \"%s\"", deftypes[k], nm);
    }
}
TEST(cpc_defprov_flag_variants_agree) {
    REQUIRE(U(CryptGetDefaultProviderA));
    for (unsigned k = 0; k < 6; k++) {
        char n0[300] = {0}, n1[300] = {0}, n2[300] = {0}; DWORD l0 = sizeof n0, l1 = sizeof n1, l2 = sizeof n2;
        BOOL o0 = U(CryptGetDefaultProviderA)(deftypes[k], NULL, 0, n0, &l0);
        BOOL o1 = U(CryptGetDefaultProviderA)(deftypes[k], NULL, CRYPT_MACHINE_DEFAULT, n1, &l1);
        BOOL o2 = U(CryptGetDefaultProviderA)(deftypes[k], NULL, CRYPT_USER_DEFAULT, n2, &l2);
        CHECK(o0); CHECK(o1); CHECK(o2);
        if (o0 && o1) { EXPECT_STR(n0, n1); EXPECT_EQ(l0, l1); }
        if (o0 && o2) EXPECT_STR(n0, n2);   /* the lookup always reads the machine-wide defaults */
    }
}
TEST(cpc_defprov_size_protocol) {
    REQUIRE(U(CryptGetDefaultProviderA));
    DWORD need = 0; char buf[300];
    SET_ERR(0);
    CHECK(U(CryptGetDefaultProviderA)(PROV_RSA_FULL, NULL, 0, NULL, &need));
    CHECK(need > 1 && need < 256);
    DWORD len = 0; CHECK(U(CryptGetDefaultProviderA)(PROV_RSA_FULL, NULL, 0, NULL, &len)); EXPECT_EQ(len, need);
    len = 12345; CHECK(U(CryptGetDefaultProviderA)(PROV_RSA_FULL, NULL, 0, NULL, &len)); EXPECT_EQ(len, need);
    memset(buf, 0x5a, sizeof buf); len = need - 1; SET_ERR(0);
    CHECK(!U(CryptGetDefaultProviderA)(PROV_RSA_FULL, NULL, 0, buf, &len)); EXPECT_ERR(ERROR_MORE_DATA); EXPECT_EQ(len, need); EXPECT_EQ(buf[0], 0x5a);
    memset(buf, 0x5a, sizeof buf); len = 0; SET_ERR(0);
    CHECK(!U(CryptGetDefaultProviderA)(PROV_RSA_FULL, NULL, 0, buf, &len)); EXPECT_ERR(ERROR_MORE_DATA); EXPECT_EQ(len, need);
    memset(buf, 0x5a, sizeof buf); len = need;
    CHECK(U(CryptGetDefaultProviderA)(PROV_RSA_FULL, NULL, 0, buf, &len)); EXPECT_EQ(len, need); EXPECT_EQ(strlen(buf) + 1, need); EXPECT_EQ((unsigned char)buf[need], 0x5a);
    len = sizeof buf;
    CHECK(U(CryptGetDefaultProviderA)(PROV_RSA_FULL, NULL, 0, buf, &len)); EXPECT_EQ(len, need);
}
TEST(cpc_defprov_bad_type) {
    REQUIRE(U(CryptGetDefaultProviderA));
    DWORD bad[] = { 0, 1000, 1001, 0x7fffffff, 0xffffffff };
    for (unsigned k = 0; k < 5; k++) {
        char b[300]; DWORD len = sizeof b; SET_ERR(0);
        BOOL ok = U(CryptGetDefaultProviderA)(bad[k], NULL, 0, b, &len);
        t_check(!ok && GetLastError() == ERROR_INVALID_PARAMETER, __FILE__, __LINE__, "bad type", "type %lu ok=%d err 0x%lx", bad[k], ok, GetLastError());
    }
}
TEST(cpc_defprov_undefined_type) {
    REQUIRE(U(CryptGetDefaultProviderA));
    DWORD t[] = { 999, 500, 255, 100 };
    for (unsigned k = 0; k < 4; k++) {
        char b[300]; DWORD len = sizeof b; SET_ERR(0);
        BOOL ok = U(CryptGetDefaultProviderA)(t[k], NULL, 0, b, &len);
        t_check(!ok && GetLastError() == ERROR_INVALID_PARAMETER, __FILE__, __LINE__, "undefined type", "type %lu ok=%d err 0x%lx", t[k], ok, GetLastError());
    }
}
TEST(cpc_defprov_bad_flags_and_reserved) {
    REQUIRE(U(CryptGetDefaultProviderA));
    char b[300]; DWORD len, res = 0;
    DWORD bad[] = { 3, 4, 5, 8, 0x10, 0x80, 0x100, 0x80000000, 0xffffffff };
    for (unsigned k = 0; k < 9; k++) {
        len = sizeof b; SET_ERR(0);
        BOOL ok = U(CryptGetDefaultProviderA)(PROV_RSA_FULL, NULL, bad[k], b, &len);
        t_check(!ok && GetLastError() == X_NTE_BAD_FLAGS, __FILE__, __LINE__, "flags", "flags 0x%lx ok=%d err 0x%lx", bad[k], ok, GetLastError());
    }
    len = sizeof b; SET_ERR(0);
    CHECK(!U(CryptGetDefaultProviderA)(PROV_RSA_FULL, &res, 0, b, &len)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    /* reserved and type are validated before flags */
    len = sizeof b; SET_ERR(0);
    CHECK(!U(CryptGetDefaultProviderA)(PROV_RSA_FULL, &res, 3, b, &len)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    len = sizeof b; SET_ERR(0);
    CHECK(!U(CryptGetDefaultProviderA)(0, NULL, 3, b, &len)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
}
TEST(cpc_defprov_w_matches_a) {
    REQUIRE(U(CryptGetDefaultProviderA)); REQUIRE(U(CryptGetDefaultProviderW));
    for (unsigned k = 0; k < 6; k++) {
        char a[300]; WCHAR w[300]; DWORD la = sizeof a, lw = 0, lw2;
        if (!U(CryptGetDefaultProviderA)(deftypes[k], NULL, 0, a, &la)) { CHECK(0); continue; }
        SET_ERR(0);
        CHECK(U(CryptGetDefaultProviderW)(deftypes[k], NULL, 0, NULL, &lw));
        EXPECT_EQ(lw, (strlen(a) + 1) * sizeof(WCHAR));
        memset(w, 0x5a, sizeof w); lw2 = lw;
        CHECK(U(CryptGetDefaultProviderW)(deftypes[k], NULL, 0, w, &lw2)); EXPECT_EQ(lw2, lw);
        char back[300]; WideCharToMultiByte(CP_ACP, 0, w, -1, back, sizeof back, NULL, NULL);
        EXPECT_STR(back, a);
        memset(w, 0x5a, sizeof w); lw2 = lw - 1; SET_ERR(0);
        CHECK(!U(CryptGetDefaultProviderW)(deftypes[k], NULL, 0, w, &lw2)); EXPECT_ERR(ERROR_MORE_DATA); EXPECT_EQ(lw2, lw); EXPECT_EQ(w[0], 0x5a5a);
        lw2 = 0; SET_ERR(0);
        CHECK(!U(CryptGetDefaultProviderW)(deftypes[k], NULL, 0, w, &lw2)); EXPECT_ERR(ERROR_MORE_DATA);
    }
}
TEST(cpc_defprov_w_errors) {
    REQUIRE(U(CryptGetDefaultProviderW));
    WCHAR w[300]; DWORD len = sizeof w, res = 0;
    SET_ERR(0);
    CHECK(!U(CryptGetDefaultProviderW)(0, NULL, 0, w, &len)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    len = sizeof w; SET_ERR(0);
    CHECK(!U(CryptGetDefaultProviderW)(1000, NULL, 0, w, &len)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    len = sizeof w; SET_ERR(0);
    CHECK(!U(CryptGetDefaultProviderW)(PROV_RSA_FULL, NULL, 3, w, &len)); EXPECT_ERR(X_NTE_BAD_FLAGS);
    len = sizeof w; SET_ERR(0);
    CHECK(!U(CryptGetDefaultProviderW)(PROV_RSA_FULL, &res, 0, w, &len)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    len = sizeof w; SET_ERR(0);
    CHECK(!U(CryptGetDefaultProviderW)(999, NULL, 0, w, &len)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
}
TEST(cpc_defprov_via_advapi32_and_cryptsp) {
    REQUIRE(UIN("advapi32.dll", CryptGetDefaultProviderA)); REQUIRE(UIN("cryptsp.dll", CryptGetDefaultProviderA));
    for (unsigned k = 0; k < 6; k++) {
        char a[300] = {0}, b[300] = {0}; DWORD la = sizeof a, lb = sizeof b;
        BOOL oa = UIN("advapi32.dll", CryptGetDefaultProviderA)(deftypes[k], NULL, 0, a, &la);
        BOOL ob = UIN("cryptsp.dll", CryptGetDefaultProviderA)(deftypes[k], NULL, 0, b, &lb);
        CHECK(oa && ob);
        EXPECT_STR(a, b); EXPECT_EQ(la, lb);
    }
    SET_ERR(0);
    char b[8]; DWORD len = sizeof b;
    CHECK(!UIN("advapi32.dll", CryptGetDefaultProviderA)(0, NULL, 0, b, &len)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0);
    CHECK(!UIN("advapi32.dll", CryptGetDefaultProviderA)(PROV_RSA_FULL, NULL, 3, b, &len)); EXPECT_ERR(X_NTE_BAD_FLAGS);
    SET_ERR(0);
    CHECK(!UIN("advapi32.dll", CryptGetDefaultProviderW)(0, NULL, 0, (LPWSTR)b, &len)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
}
TEST(cpc_defprov_type_matches_provider_type) {
    /* the default provider of a type is registered as that type */
    REQUIRE(U(CryptGetDefaultProviderA)); REQUIRE(U(CryptAcquireContextA));
    for (unsigned k = 0; k < 6; k++) {
        char nm[300]; DWORD len = sizeof nm;
        if (!U(CryptGetDefaultProviderA)(deftypes[k], NULL, 0, nm, &len)) { CHECK(0); continue; }
        HCRYPTPROV h = 0;
        BOOL ok = cpc_acq(&h, nm, deftypes[k], X_VERIFY);
        t_check(ok, __FILE__, __LINE__, "acquire default by name", "type %lu \"%s\" err 0x%lx", deftypes[k], nm, GetLastError());
        cpc_rel(h);
    }
}
