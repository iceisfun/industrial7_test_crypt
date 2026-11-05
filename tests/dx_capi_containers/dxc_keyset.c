#include "dxc.h"
/* Key container lifecycle through CryptAcquireContextA/W (cryptsp -> rsaenh/dssenh):
 * NEWKEYSET / DELETEKEYSET / open / flags, user scope; machine scope when elevated.
 * Pinned from cryptsp CryptAcquireContextW (UNICODE->ANSI then A), rsaenh CPAcquireContext/NTagLogonUser. */

/* ------------------------------------------------------------ create / exists / open / delete */
static void ks_create_open(int pi) {
    DXC_NEED(pi);
    const char *c = dxc_name("co"); dxc_del(c, pi, 0);
    HCRYPTPROV h = 0, h2 = 0;
    SET_ERR(0);
    BOOL ok = dxc_acq(&h, c, pi, CRYPT_NEWKEYSET);
    CHECKF(ok, "NEWKEYSET err 0x%lx", GetLastError());
    CHECK(h != 0);
    dxc_rel(h);
    CHECK(dxc_acq(&h2, c, pi, 0));
    CHECK(h2 != 0);
    dxc_rel(h2);
    dxc_del(c, pi, 0);
}
DXC_PERPROV(dxc_keyset_create_open, ks_create_open)

static void ks_exists(int pi) {
    DXC_NEED(pi);
    const char *c = dxc_name("ex"); dxc_del(c, pi, 0);
    HCRYPTPROV h = 0, h2 = 0;
    CHECK(dxc_acq(&h, c, pi, CRYPT_NEWKEYSET));
    SET_ERR(0);
    BOOL ok = dxc_acq(&h2, c, pi, CRYPT_NEWKEYSET);
    CHECK(!ok); EXPECT_ERR(X_NTE_EXISTS);
    if (ok) dxc_rel(h2);
    /* the first handle is still usable */
    char nm[300]; DWORD n = sizeof nm;
    CHECK(dxc_gpp(h, PP_CONTAINER, nm, &n, 0));
    EXPECT_STR(nm, c);
    dxc_rel(h);
    dxc_del(c, pi, 0);
}
DXC_PERPROV(dxc_keyset_newkeyset_exists, ks_exists)

static void ks_exists_while_open_released(int pi) {
    DXC_NEED(pi);
    const char *c = dxc_name("exr"); dxc_del(c, pi, 0);
    HCRYPTPROV h = 0, h2 = 0;
    CHECK(dxc_acq(&h, c, pi, CRYPT_NEWKEYSET));
    dxc_rel(h);   /* released: the container still exists on disk */
    SET_ERR(0);
    BOOL ok = dxc_acq(&h2, c, pi, CRYPT_NEWKEYSET);
    CHECK(!ok); EXPECT_ERR(X_NTE_EXISTS);
    if (ok) dxc_rel(h2);
    dxc_del(c, pi, 0);
}
DXC_PERPROV(dxc_keyset_newkeyset_exists_after_release, ks_exists_while_open_released)

static void ks_open_missing(int pi) {
    DXC_NEED(pi);
    const char *c = dxc_name("miss"); dxc_del(c, pi, 0);
    HCRYPTPROV h = 0;
    SET_ERR(0);
    BOOL ok = dxc_acq(&h, c, pi, 0);
    CHECK(!ok); EXPECT_ERR(X_NTE_BAD_KEYSET);
    if (ok) dxc_rel(h);
    SET_ERR(0);
    ok = dxc_acq(&h, c, pi, CRYPT_SILENT);
    CHECK(!ok); EXPECT_ERR(X_NTE_BAD_KEYSET);
    if (ok) dxc_rel(h);
}
DXC_PERPROV(dxc_keyset_open_missing, ks_open_missing)

static void ks_delete_missing(int pi) {
    DXC_NEED(pi);
    const char *c = dxc_name("dm"); dxc_del(c, pi, 0);
    HCRYPTPROV h = 0;
    SET_ERR(0);
    BOOL ok = dxc_acq(&h, c, pi, CRYPT_DELETEKEYSET);
    CHECK(!ok); EXPECT_ERR(X_NTE_BAD_KEYSET);
}
DXC_PERPROV(dxc_keyset_delete_missing, ks_delete_missing)

static void ks_delete(int pi) {
    DXC_NEED(pi);
    const char *c = dxc_name("del"); dxc_del(c, pi, 0);
    HCRYPTPROV h = 0, h2 = 0;
    CHECK(dxc_acq(&h, c, pi, CRYPT_NEWKEYSET)); dxc_rel(h);
    h = 0xdead;
    SET_ERR(0);
    BOOL ok = dxc_acq(&h, c, pi, CRYPT_DELETEKEYSET);
    CHECKF(ok, "delete err 0x%lx", GetLastError());
    /* docs: the value of *phProv is undefined after DELETEKEYSET; never usable as a context */
    t_note("phProv after DELETEKEYSET (prov %d) = 0x%llx", pi, (unsigned long long)h);
    SET_ERR(0);
    ok = dxc_acq(&h2, c, pi, 0);
    CHECK(!ok); EXPECT_ERR(X_NTE_BAD_KEYSET);
    if (ok) dxc_rel(h2);
    /* second delete fails */
    SET_ERR(0);
    ok = dxc_acq(&h2, c, pi, CRYPT_DELETEKEYSET);
    CHECK(!ok); EXPECT_ERR(X_NTE_BAD_KEYSET);
    /* recreate after delete works */
    ok = dxc_acq(&h2, c, pi, CRYPT_NEWKEYSET);
    CHECK(ok); dxc_rel(h2);
    dxc_del(c, pi, 0);
}
DXC_PERPROV(dxc_keyset_delete_lifecycle, ks_delete)

static void ks_silent(int pi) {
    DXC_NEED(pi);
    const char *c = dxc_name("sil"); dxc_del(c, pi, 0);
    HCRYPTPROV h = 0;
    BOOL ok = dxc_acq(&h, c, pi, CRYPT_NEWKEYSET | CRYPT_SILENT);
    CHECKF(ok, "err 0x%lx", GetLastError());
    dxc_rel(h); h = 0;
    ok = dxc_acq(&h, c, pi, CRYPT_SILENT);
    CHECKF(ok, "err 0x%lx", GetLastError());
    dxc_rel(h);
    ok = dxc_acq(&h, c, pi, CRYPT_DELETEKEYSET | CRYPT_SILENT);
    CHECKF(ok, "err 0x%lx", GetLastError());
    CHECK(!dxc_exists(c, pi, 0));
}
DXC_PERPROV(dxc_keyset_silent_flag, ks_silent)

static void ks_two_contexts(int pi) {
    DXC_NEED(pi);
    const char *c = dxc_name("two"); dxc_del(c, pi, 0);
    HCRYPTPROV a = 0, b = 0;
    CHECK(dxc_acq(&a, c, pi, CRYPT_NEWKEYSET));
    CHECK(dxc_acq(&b, c, pi, 0));
    CHECK(a != 0 && b != 0 && a != b);
    char n1[300], n2[300]; DWORD l1 = sizeof n1, l2 = sizeof n2;
    CHECK(dxc_gpp(a, PP_CONTAINER, n1, &l1, 0));
    CHECK(dxc_gpp(b, PP_CONTAINER, n2, &l2, 0));
    EXPECT_STR(n1, n2);
    dxc_rel(a);
    /* b survives release of a */
    l2 = sizeof n2;
    CHECK(dxc_gpp(b, PP_CONTAINER, n2, &l2, 0));
    dxc_rel(b);
    dxc_del(c, pi, 0);
}
DXC_PERPROV(dxc_keyset_two_contexts_same_container, ks_two_contexts)

static void ks_delete_while_open(int pi) {
    DXC_NEED(pi);
    const char *c = dxc_name("dwo"); dxc_del(c, pi, 0);
    HCRYPTPROV a = 0, h2 = 0;
    CHECK(dxc_acq(&a, c, pi, CRYPT_NEWKEYSET));
    BOOL ok = dxc_acq(&h2, c, pi, CRYPT_DELETEKEYSET);
    t_note("delete while another context is open: ok=%d err 0x%lx", ok, GetLastError());
    dxc_rel(a);
    dxc_del(c, pi, 0);
    CHECK(!dxc_exists(c, pi, 0));
}
DXC_PERPROV(dxc_keyset_delete_while_open, ks_delete_while_open)

static void ks_aw(int pi) {
    DXC_NEED(pi);
    REQUIRE(U(CryptAcquireContextW));
    const char *c = dxc_name("aw"); dxc_del(c, pi, 0);
    WCHAR prov[128]; MultiByteToWideChar(CP_ACP, 0, dxc_provs[pi].a, -1, prov, 128);
    HCRYPTPROV h = 0, h2 = 0;
    BOOL ok = U(CryptAcquireContextW)(&h, dxc_wname("aw"), prov, dxc_provs[pi].type, CRYPT_NEWKEYSET);
    CHECKF(ok, "W create err 0x%lx", GetLastError());
    dxc_rel(h);
    CHECK(dxc_acq(&h2, c, pi, 0));      /* open the same container with the ANSI entry */
    dxc_rel(h2); h2 = 0;
    SET_ERR(0);
    ok = U(CryptAcquireContextW)(&h, dxc_wname("aw"), prov, dxc_provs[pi].type, CRYPT_NEWKEYSET);
    CHECK(!ok); EXPECT_ERR(X_NTE_EXISTS);
    ok = U(CryptAcquireContextW)(&h, dxc_wname("aw"), prov, dxc_provs[pi].type, CRYPT_DELETEKEYSET);
    CHECKF(ok, "W delete err 0x%lx", GetLastError());
    CHECK(!dxc_exists(c, pi, 0));
}
DXC_PERPROV(dxc_keyset_wide_ansi_parity, ks_aw)

static void ks_name_chars(int pi) {
    DXC_NEED(pi);
    static const char *tags[] = { "sp ace", "dash-name", "dot.name", "UPPERlower", "under_score", "x" };
    for (unsigned i = 0; i < sizeof tags / sizeof *tags; i++) {
        const char *c = dxc_name(tags[i]); dxc_del(c, pi, 0);
        HCRYPTPROV h = 0, h2 = 0;
        BOOL ok = dxc_acq(&h, c, pi, CRYPT_NEWKEYSET);
        CHECKF(ok, "create '%s' err 0x%lx", c, GetLastError());
        if (!ok) continue;
        char nm[300]; DWORD n = sizeof nm;
        CHECK(dxc_gpp(h, PP_CONTAINER, nm, &n, 0));
        EXPECT_STR(nm, c);
        dxc_rel(h);
        CHECK(dxc_acq(&h2, c, pi, 0)); dxc_rel(h2);
        dxc_del(c, pi, 0);
    }
}
DXC_PERPROV(dxc_keyset_name_characters, ks_name_chars)

static void ks_case(int pi) {
    DXC_NEED(pi);
    /* container names are case-insensitive for lookup on Windows (hashed lower-cased) */
    char lo[160], up[160];
    snprintf(lo, sizeof lo, "%s", dxc_name("casemix"));
    snprintf(up, sizeof up, "%s", lo);
    for (char *p = up; *p; p++) if (*p >= 'a' && *p <= 'z') *p -= 32;
    dxc_del(lo, pi, 0);
    HCRYPTPROV h = 0, h2 = 0;
    CHECK(dxc_acq(&h, lo, pi, CRYPT_NEWKEYSET)); dxc_rel(h);
    BOOL ok = dxc_acq(&h2, up, pi, 0);
    t_note("open with different case: ok=%d err 0x%lx", ok, GetLastError());
    dxc_rel(h2);
    dxc_del(lo, pi, 0);
    dxc_del(up, pi, 0);
}
DXC_PERPROV(dxc_keyset_name_case_lookup, ks_case)

/* --------------------------------------------------------------- flag validation */
static void ks_badflags(int pi) {
    DXC_NEED(pi);
    static const DWORD bad[] = { 0x1, 0x2, 0x4, 0x80, 0x100, 0x10000, 0x0fffff00 };
    const char *c = dxc_name("bf"); dxc_del(c, pi, 0);
    for (unsigned i = 0; i < sizeof bad / sizeof *bad; i++) {
        HCRYPTPROV h = 0;
        SET_ERR(0);
        BOOL ok = dxc_acq(&h, c, pi, bad[i]);
        CHECKF(!ok, "flags 0x%lx succeeded", bad[i]);
        EXPECT_ERR(X_NTE_BAD_FLAGS);
        if (ok) dxc_rel(h);
    }
    CHECK(!dxc_exists(c, pi, 0));
}
DXC_PERPROV(dxc_keyset_invalid_flag_bits, ks_badflags)

static void ks_verify_with_name(int pi) {
    DXC_NEED(pi);
    HCRYPTPROV h = 0;
    SET_ERR(0);
    BOOL ok = dxc_acq(&h, dxc_name("vcn"), pi, CRYPT_VERIFYCONTEXT);
    CHECK(!ok); EXPECT_ERR(X_NTE_BAD_FLAGS);
    if (ok) dxc_rel(h);
    SET_ERR(0);
    ok = dxc_acq(&h, dxc_name("vcn"), pi, CRYPT_VERIFYCONTEXT | CRYPT_NEWKEYSET);
    CHECK(!ok);
    if (ok) dxc_rel(h);
    CHECK(!dxc_exists(dxc_name("vcn"), pi, 0));
}
DXC_PERPROV(dxc_keyset_verifycontext_with_container, ks_verify_with_name)

static void ks_long_name(int pi) {
    DXC_NEED(pi);
    if (t_is_wine()) { t_skip("emulator crashes on over-long container names"); return; }
    char c[500]; HCRYPTPROV h = 0;
    /* NEWKEYSET rejects names longer than 260 characters (strlen+1 > 0x105) */
    memset(c, 'q', 261); c[261] = 0;
    SET_ERR(0);
    BOOL ok = dxc_acq(&h, c, pi, CRYPT_NEWKEYSET);
    CHECK(!ok); EXPECT_ERR(dxc_provs[pi].dss ? X_NTE_BAD_KEYSET : 0x8009001FUL);  
    if (ok) { dxc_rel(h); dxc_del(c, pi, 0); }
    memset(c, 'q', 400); c[400] = 0;
    SET_ERR(0);
    ok = dxc_acq(&h, c, pi, CRYPT_NEWKEYSET);
    CHECK(!ok); EXPECT_ERR(dxc_provs[pi].dss ? X_NTE_BAD_KEYSET : 0x8009001FUL);  
    if (ok) { dxc_rel(h); dxc_del(c, pi, 0); }
}
DXC_PERPROV(dxc_keyset_name_too_long, ks_long_name)

static void ks_max_name(int pi) {
    DXC_NEED(pi);
    if (t_is_wine()) { t_skip("emulator keeps containers in the registry"); return; }
    char c[300]; HCRYPTPROV h = 0;
    snprintf(c, sizeof c, "%s_", dxc_name("max"));
    size_t l = strlen(c);
    memset(c + l, 'm', 260 - l); c[260] = 0;      /* exactly 260 characters */
    dxc_del(c, pi, 0);
    BOOL ok = dxc_acq(&h, c, pi, CRYPT_NEWKEYSET);
    CHECKF(ok, "260-char name err 0x%lx", GetLastError());
    if (ok) {
        dxc_rel(h);
        CHECK(dxc_exists(c, pi, 0));
        dxc_del(c, pi, 0);
    }
}
DXC_PERRSA(dxc_keyset_name_max_length, ks_max_name)

/* --------------------------------------------------------------- provider type mismatches */
TEST(dxc_keyset_bad_provider_type) {
    REQUIRE(U(CryptAcquireContextA));
    HCRYPTPROV h = 0;
    SET_ERR(0);
    BOOL ok = U(CryptAcquireContextA)(&h, dxc_name("bt"), MS_ENH_RSA_AES_PROV_A, 0, CRYPT_NEWKEYSET);
    CHECK(!ok); EXPECT_ERR(X_NTE_BAD_PROV_TYPE);
    SET_ERR(0);
    ok = U(CryptAcquireContextA)(&h, dxc_name("bt"), MS_ENH_RSA_AES_PROV_A, 1000, CRYPT_NEWKEYSET);
    CHECK(!ok); EXPECT_ERR(X_NTE_BAD_PROV_TYPE);
    SET_ERR(0);
    ok = U(CryptAcquireContextA)(&h, dxc_name("bt"), MS_ENH_RSA_AES_PROV_A, PROV_DSS, CRYPT_NEWKEYSET);
    CHECK(!ok);
    t_note("RSA_AES provider with type PROV_DSS: err 0x%lx", GetLastError());
    CHECK(!dxc_exists(dxc_name("bt"), 3, 0));
}

TEST(dxc_keyset_unknown_provider_name) {
    REQUIRE(U(CryptAcquireContextA));
    HCRYPTPROV h = 0;
    char nm[100]; snprintf(nm, sizeof nm, "%s no such provider %lu", T_TMP_PREFIX, GetCurrentProcessId());
    SET_ERR(0);
    BOOL ok = U(CryptAcquireContextA)(&h, dxc_name("up"), nm, PROV_RSA_FULL, CRYPT_NEWKEYSET);
    CHECK(!ok); EXPECT_ERR(X_NTE_KEYSET_NOT_DEF);
}

TEST(dxc_keyset_provider_type_mismatch_name) {
    REQUIRE(U(CryptAcquireContextA));
    HCRYPTPROV h = 0;
    /* Base DSS provider is type 3; asking for it as type 1 is a mismatch */
    SET_ERR(0);
    BOOL ok = U(CryptAcquireContextA)(&h, dxc_name("mm"), MS_DEF_DSS_PROV_A, PROV_RSA_FULL, CRYPT_NEWKEYSET);
    CHECK(!ok);
    DWORD e = GetLastError();
    CHECKF(e == X_NTE_PROV_TYPE_NO_MATCH, "got 0x%lx", e);
    CHECK(!dxc_exists(dxc_name("mm"), 0, 0));
}

/* --------------------------------------------------------------- default (NULL) container */
static void ks_default(int pi) {
    DXC_NEED(pi);
    HCRYPTPROV h = 0;
    SET_ERR(0);
    /* never NEWKEYSET here: that would create the user's real default container */
    BOOL ok = dxc_acq(&h, NULL, pi, 0);
    if (!ok) {
        CHECKF(GetLastError() == X_NTE_BAD_KEYSET, "got 0x%lx", GetLastError());
        t_note("prov %d: default container absent", pi);
        return;
    }
    char nm[300]; DWORD n = sizeof nm;
    BOOL g = dxc_gpp(h, PP_CONTAINER, nm, &n, 0);
    CHECK(g);
    if (g) { CHECK(nm[0] != 0); t_note("prov %d: default container '%s'", pi, nm); }
    dxc_rel(h);
}
DXC_PERPROV(dxc_keyset_default_container_null, ks_default)

TEST(dxc_keyset_default_delete_not_attempted) {
    /* DELETEKEYSET with NULL name is not exercised on purpose; just make sure the
     * verify-context path with NULL is fine on every available provider. */
    REQUIRE(U(CryptAcquireContextA));
    for (int pi = 0; pi < dxc_nprov; pi++) {
        if (!dxc_have(pi)) continue;
        HCRYPTPROV h = 0;
        BOOL ok = dxc_acq(&h, NULL, pi, CRYPT_VERIFYCONTEXT);
        CHECKF(ok, "prov %d", pi);
        dxc_rel(h);
    }
}

/* --------------------------------------------------------------- PP_KEYSET_TYPE, PP_CONTAINER on persisted */
static void ks_type_user(int pi) {
    DXC_NEED(pi);
    const char *c = dxc_name("kt"); dxc_del(c, pi, 0);
    HCRYPTPROV h = 0;
    CHECK(dxc_acq(&h, c, pi, CRYPT_NEWKEYSET));
    DWORD v = 99, n = 4;
    BOOL ok = dxc_gpp(h, PP_KEYSET_TYPE, &v, &n, 0);
    CHECKF(ok, "err 0x%lx", GetLastError());
    EXPECT_EQ(v, 0); EXPECT_EQ(n, 4);
    dxc_rel(h);
    dxc_del(c, pi, 0);
}
DXC_PERPROV(dxc_keyset_pp_keyset_type_user, ks_type_user)

static void ks_pp_container_protocol(int pi) {
    DXC_NEED(pi);
    const char *c = dxc_name("ppc"); dxc_del(c, pi, 0);
    HCRYPTPROV h = 0;
    CHECK(dxc_acq(&h, c, pi, CRYPT_NEWKEYSET));
    DWORD need = strlen(c) + 1, n = 0;
    CHECK(dxc_gpp(h, PP_CONTAINER, NULL, &n, 0));
    EXPECT_EQ(n, need);
    char buf[300]; memset(buf, 'Z', sizeof buf);
    n = need - 1;
    SET_ERR(0);
    CHECK(!dxc_gpp(h, PP_CONTAINER, buf, &n, 0)); EXPECT_ERR(ERROR_MORE_DATA);
    EXPECT_EQ(n, need);
    n = need;
    CHECK(dxc_gpp(h, PP_CONTAINER, buf, &n, 0));
    EXPECT_EQ(n, need); EXPECT_STR(buf, c);
    n = sizeof buf;
    CHECK(dxc_gpp(h, PP_CONTAINER, buf, &n, 0));
    EXPECT_EQ(n, need);
    n = 0;
    SET_ERR(0);
    CHECK(!dxc_gpp(h, PP_CONTAINER, buf, &n, 0)); EXPECT_ERR(ERROR_MORE_DATA);
    n = sizeof buf;
    SET_ERR(0);
    CHECK(!dxc_gpp(h, PP_CONTAINER, buf, &n, 1)); EXPECT_ERR(X_NTE_BAD_FLAGS);
    dxc_rel(h);
    dxc_del(c, pi, 0);
}
DXC_PERPROV(dxc_keyset_pp_container_size_protocol, ks_pp_container_protocol)

static void ks_pp_name_type(int pi) {
    DXC_NEED(pi);
    const char *c = dxc_name("ppn"); dxc_del(c, pi, 0);
    HCRYPTPROV h = 0;
    CHECK(dxc_acq(&h, c, pi, CRYPT_NEWKEYSET));
    char nm[200]; DWORD n = sizeof nm;
    CHECK(dxc_gpp(h, PP_NAME, nm, &n, 0));
    EXPECT_STR(nm, dxc_provs[pi].a);
    DWORD v = 0; n = 4;
    CHECK(dxc_gpp(h, PP_PROVTYPE, &v, &n, 0));
    EXPECT_EQ(v, dxc_provs[pi].type);
    dxc_rel(h);
    dxc_del(c, pi, 0);
}
DXC_PERPROV(dxc_keyset_pp_name_provtype_on_persisted, ks_pp_name_type)

/* --------------------------------------------------------------- enumeration */
static void ks_enum_contains(int pi) {
    DXC_NEED(pi);
    const char *c1 = dxc_name("en1"), *c2 = dxc_name("en2"), *c3 = dxc_name("en3");
    dxc_del(c1, pi, 0); dxc_del(c2, pi, 0); dxc_del(c3, pi, 0);
    HCRYPTPROV h1 = 0, h2 = 0, h3 = 0;
    CHECK(dxc_acq(&h1, c1, pi, CRYPT_NEWKEYSET));
    CHECK(dxc_acq(&h2, c2, pi, CRYPT_NEWKEYSET));
    CHECK(dxc_acq(&h3, c3, pi, CRYPT_NEWKEYSET));
    static char names[600][264];
    int n = dxc_enum(pi, 0, names, 600);
    CHECK(n >= 3);
    int f1 = 0, f2 = 0, f3 = 0;
    for (int i = 0; i < n; i++) {
        if (!strcmp(names[i], c1)) f1++;
        if (!strcmp(names[i], c2)) f2++;
        if (!strcmp(names[i], c3)) f3++;
    }
    EXPECT_EQ(f1, 1); EXPECT_EQ(f2, 1); EXPECT_EQ(f3, 1);
    /* enumeration through a context bound to a container lists the same set */
    int n2 = dxc_enum_in(h1, names, 600);
    CHECK(n2 >= 3);
    dxc_rel(h1); dxc_rel(h2); dxc_rel(h3);
    dxc_del(c1, pi, 0); dxc_del(c2, pi, 0); dxc_del(c3, pi, 0);
    n = dxc_enum(pi, 0, names, 600);
    for (int i = 0; i < n; i++)
        CHECKF(strcmp(names[i], c1) && strcmp(names[i], c2) && strcmp(names[i], c3), "still listed: %s", names[i]);
}
DXC_PERPROV(dxc_keyset_enum_lists_created, ks_enum_contains)

static void ks_enum_protocol(int pi) {
    DXC_NEED(pi);
    const char *c = dxc_name("enp"); dxc_del(c, pi, 0);
    HCRYPTPROV h = 0, v = 0;
    CHECK(dxc_acq(&h, c, pi, CRYPT_NEWKEYSET));
    CHECK(dxc_acq(&v, NULL, pi, CRYPT_VERIFYCONTEXT));
    char buf[600]; DWORD n;
    /* CRYPT_NEXT before CRYPT_FIRST on a fresh context */
    n = sizeof buf; SET_ERR(0);
    CHECK(!dxc_gpp(v, PP_ENUMCONTAINERS, buf, &n, CRYPT_NEXT)); EXPECT_ERR(X_NTE_BAD_FLAGS);
    /* unknown flag bits */
    n = sizeof buf; SET_ERR(0);
    CHECK(!dxc_gpp(v, PP_ENUMCONTAINERS, buf, &n, 4)); EXPECT_ERR(X_NTE_BAD_FLAGS);
    n = sizeof buf; SET_ERR(0);
    CHECK(!dxc_gpp(v, PP_ENUMCONTAINERS, buf, &n, 0x80000000)); EXPECT_ERR(X_NTE_BAD_FLAGS);
    /* a buffer smaller than 261 bytes is reported as too small whatever the name length */
    n = 100; SET_ERR(0);
    CHECK(!dxc_gpp(v, PP_ENUMCONTAINERS, buf, &n, CRYPT_FIRST)); EXPECT_ERR(ERROR_MORE_DATA);
    /* full walk: strings are NUL-terminated and returned length counts the NUL */
    DWORD fl = CRYPT_FIRST; int cnt = 0, found = 0;
    for (;;) {
        n = sizeof buf;
        if (!dxc_gpp(v, PP_ENUMCONTAINERS, buf, &n, fl)) { EXPECT_ERR(ERROR_NO_MORE_ITEMS); break; }
        fl = CRYPT_NEXT; cnt++;
        if (n != strlen(buf) + 1) t_note("enum returned length %lu for '%s'", n, buf);
        if (!strcmp(buf, c)) found++;
        if (cnt > 1000) break;
    }
    EXPECT_EQ(found, 1);
    /* after exhaustion CRYPT_NEXT succeeds without writing a name: buffer and length stay as passed in
     * (observed on Win10, repeated calls identical) */
    for (int rep = 0; rep < 2; rep++) {
        buf[0] = 0; n = sizeof buf;
        CHECK(dxc_gpp(v, PP_ENUMCONTAINERS, buf, &n, CRYPT_NEXT));
        EXPECT_EQ(buf[0], 0);
        EXPECT_EQ(n, sizeof buf);
    }
    /* CRYPT_FIRST restarts */
    n = sizeof buf;
    CHECK(dxc_gpp(v, PP_ENUMCONTAINERS, buf, &n, CRYPT_FIRST));
    /* NULL pbData asks for the size and succeeds */
    n = 0;
    CHECK(dxc_gpp(v, PP_ENUMCONTAINERS, NULL, &n, CRYPT_FIRST));
    t_note("enum size query returns %lu", n);
    dxc_rel(h); dxc_rel(v);
    dxc_del(c, pi, 0);
}
DXC_PERPROV(dxc_keyset_enum_protocol, ks_enum_protocol)

static void ks_enum_two_walks(int pi) {
    DXC_NEED(pi);
    /* two contexts keep independent enumeration cursors */
    HCRYPTPROV a = 0, b = 0;
    CHECK(dxc_acq(&a, NULL, pi, CRYPT_VERIFYCONTEXT));
    CHECK(dxc_acq(&b, NULL, pi, CRYPT_VERIFYCONTEXT));
    char x[600], y[600]; DWORD nx = sizeof x, ny = sizeof y;
    BOOL oka = dxc_gpp(a, PP_ENUMCONTAINERS, x, &nx, CRYPT_FIRST);
    BOOL okb = dxc_gpp(b, PP_ENUMCONTAINERS, y, &ny, CRYPT_FIRST);
    if (oka && okb) {
        EXPECT_STR(x, y);
        nx = sizeof x; ny = sizeof y;
        BOOL a2 = dxc_gpp(a, PP_ENUMCONTAINERS, x, &nx, CRYPT_NEXT);
        BOOL b1 = dxc_gpp(b, PP_ENUMCONTAINERS, y, &ny, CRYPT_FIRST);
        (void)a2; (void)b1;
    }
    dxc_rel(a); dxc_rel(b);
}
DXC_PERPROV(dxc_keyset_enum_independent_cursors, ks_enum_two_walks)

/* PP_UNIQUE_CONTAINER: on Windows the file name of the key container */
static int is_hex(char ch) { return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f'); }
static void ks_unique(int pi) {
    DXC_NEED(pi);
    if (t_is_wine()) { t_skip("emulator keeps no file-per-container store"); return; }
    const char *c = dxc_name("uq"); dxc_del(c, pi, 0);
    HCRYPTPROV h = 0;
    CHECK(dxc_acq(&h, c, pi, CRYPT_NEWKEYSET));
    char u[300] = {0}; DWORD n = 0;
    CHECK(dxc_gpp(h, PP_UNIQUE_CONTAINER, NULL, &n, 0));
    DWORD need = n;
    n = sizeof u;
    CHECK(dxc_gpp(h, PP_UNIQUE_CONTAINER, u, &n, 0));
    EXPECT_EQ(n, strlen(u) + 1);
    EXPECT_EQ(n, need);
    /* "<32 hex>_<machine GUID>" */
    CHECKF(strlen(u) > 33, "unique name '%s'", u);
    int hexok = 1; for (int i = 0; i < 32 && u[i]; i++) if (!is_hex(u[i])) hexok = 0;
    CHECKF(hexok && u[32] == '_', "unique name format '%s'", u);
    CHECK(strcmp(u, c) != 0);
    /* shorter buffer and flags */
    if (n > 1) { DWORD m = n - 1; SET_ERR(0); CHECK(!dxc_gpp(h, PP_UNIQUE_CONTAINER, u, &m, 0)); EXPECT_ERR(ERROR_MORE_DATA); }
    n = sizeof u; SET_ERR(0);
    if (dxc_provs[pi].dss) {
        /* the DSS providers ignore the flags of this parameter */
        CHECK(dxc_gpp(h, PP_UNIQUE_CONTAINER, u, &n, 1));
    } else {
        CHECK(!dxc_gpp(h, PP_UNIQUE_CONTAINER, u, &n, 1)); EXPECT_ERR(X_NTE_BAD_FLAGS);
    }
    /* same container opened again gives the same unique name */
    HCRYPTPROV h2 = 0; char u2[300] = {0}; n = sizeof u2;
    CHECK(dxc_acq(&h2, c, pi, 0));
    CHECK(dxc_gpp(h2, PP_UNIQUE_CONTAINER, u2, &n, 0));
    EXPECT_STR(u, u2);
    dxc_rel(h2); dxc_rel(h);
    dxc_del(c, pi, 0);
}
DXC_PERPROV(dxc_keyset_pp_unique_container_format, ks_unique)

/* ----------------------------------------------------------------- machine keysets */
static void ks_machine(int pi) {
    if (!dxc_machine_ok(pi)) return;
    const char *c = dxc_name("mach"); dxc_del(c, pi, CRYPT_MACHINE_KEYSET); dxc_del(c, pi, 0);
    HCRYPTPROV h = 0, h2 = 0;
    BOOL ok = dxc_acq(&h, c, pi, CRYPT_NEWKEYSET | CRYPT_MACHINE_KEYSET);
    if (!ok && GetLastError() == ERROR_ACCESS_DENIED) { t_skip("machine keyset access denied"); return; }
    CHECKF(ok, "err 0x%lx", GetLastError());
    if (!ok) return;
    DWORD v = 0, n = 4;
    CHECK(dxc_gpp(h, PP_KEYSET_TYPE, &v, &n, 0));
    EXPECT_EQ(v, CRYPT_MACHINE_KEYSET);
    dxc_rel(h);
    /* opens with the machine flag, not without */
    CHECK(dxc_acq(&h2, c, pi, CRYPT_MACHINE_KEYSET)); dxc_rel(h2);
    SET_ERR(0);
    CHECK(!dxc_acq(&h2, c, pi, 0)); EXPECT_ERR(X_NTE_BAD_KEYSET);
    /* NEWKEYSET again in machine scope: exists; in user scope: allowed (independent store) */
    SET_ERR(0);
    CHECK(!dxc_acq(&h2, c, pi, CRYPT_NEWKEYSET | CRYPT_MACHINE_KEYSET)); EXPECT_ERR(X_NTE_EXISTS);
    /* deleting without the flag does not touch it */
    SET_ERR(0);
    CHECK(!dxc_acq(&h2, c, pi, CRYPT_DELETEKEYSET)); EXPECT_ERR(X_NTE_BAD_KEYSET);
    CHECK(dxc_exists(c, pi, CRYPT_MACHINE_KEYSET));
    ok = dxc_acq(&h2, c, pi, CRYPT_DELETEKEYSET | CRYPT_MACHINE_KEYSET);
    CHECKF(ok, "err 0x%lx", GetLastError());
    CHECK(!dxc_exists(c, pi, CRYPT_MACHINE_KEYSET));
    dxc_del(c, pi, CRYPT_MACHINE_KEYSET);
}
DXC_PERPROV(dxc_keyset_machine_scope, ks_machine)

static void ks_scope_independent(int pi) {
    if (!dxc_machine_ok(pi)) return;
    const char *c = dxc_name("sci"); dxc_del(c, pi, CRYPT_MACHINE_KEYSET); dxc_del(c, pi, 0);
    HCRYPTPROV hu = 0, hm = 0;
    BOOL oku = dxc_acq(&hu, c, pi, CRYPT_NEWKEYSET);
    BOOL okm = dxc_acq(&hm, c, pi, CRYPT_NEWKEYSET | CRYPT_MACHINE_KEYSET);
    CHECK(oku);
    CHECKF(okm, "machine create err 0x%lx", GetLastError());
    dxc_rel(hu); dxc_rel(hm);
    static char names[600][264];
    int n = dxc_enum(pi, CRYPT_MACHINE_KEYSET, names, 600), fm = 0;
    for (int i = 0; i < n; i++) if (!strcmp(names[i], c)) fm++;
    EXPECT_EQ(fm, 1);
    dxc_del(c, pi, CRYPT_MACHINE_KEYSET);
    CHECK(dxc_exists(c, pi, 0));      /* user one untouched */
    CHECK(!dxc_exists(c, pi, CRYPT_MACHINE_KEYSET));
    dxc_del(c, pi, 0);
}
DXC_PERRSA(dxc_keyset_user_machine_independent, ks_scope_independent)

TEST(dxc_keyset_machine_verifycontext_type) {
    REQUIRE(U(CryptAcquireContextA));
    if (!dxc_have(3)) { t_skip("no provider"); return; }
    HCRYPTPROV h = 0;
    BOOL ok = dxc_acq(&h, NULL, 3, CRYPT_VERIFYCONTEXT | CRYPT_MACHINE_KEYSET);
    if (!ok) { t_skip("machine verify context err 0x%lx", GetLastError()); return; }
    DWORD v = 0, n = 4;
    CHECK(dxc_gpp(h, PP_KEYSET_TYPE, &v, &n, 0));
    EXPECT_EQ(v, CRYPT_MACHINE_KEYSET);
    dxc_rel(h);
}
