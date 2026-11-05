#include "cpc.h"
/* CryptGetProvParam / CryptSetProvParam on VERIFYCONTEXT contexts of every default provider.
 * Expectations come from the provider (rsaenh / dssenh) PP_* handlers as decompiled on Windows 10. */

static int acqv(int i, HCRYPTPROV *h) {
    *h = 0;
    if (cpc_provs[i].dss && t_is_wine()) { t_skip("dssenh provider entry points are unimplemented in this emulator"); return 0; }
    if (!cpc_acq(h, cpc_provs[i].a, cpc_provs[i].type, X_VERIFY)) {
        t_check(0, __FILE__, __LINE__, "acquire", "%s err 0x%lx", cpc_provs[i].a, GetLastError());
        return 0;
    }
    return 1;
}

/* ------------------------------------------------------------ scalar properties */
static void p_scalars(int i) {
    const cpc_prov *P = &cpc_provs[i];
    REQUIRE(U(CryptGetProvParam));
    HCRYPTPROV h; if (!acqv(i, &h)) return;
    DWORD v;
    CHECK(cpc_gpp_dw(h, PP_IMPTYPE, &v));        EXPECT_EQ(v, CRYPT_IMPL_SOFTWARE);
    CHECK(cpc_gpp_dw(h, PP_VERSION, &v));        EXPECT_EQ(v, P->version);
    CHECK(cpc_gpp_dw(h, PP_PROVTYPE, &v));       EXPECT_EQ(v, P->type);
    CHECK(cpc_gpp_dw(h, PP_KEYSET_TYPE, &v));    EXPECT_EQ(v, 0);
    CHECK(cpc_gpp_dw(h, PP_SIG_KEYSIZE_INC, &v)); EXPECT_EQ(v, P->inc);
    CHECK(cpc_gpp_dw(h, PP_KEYX_KEYSIZE_INC, &v)); EXPECT_EQ(v, P->inc);
    CHECK(cpc_gpp_dw(h, PP_KEYSTORAGE, &v));     EXPECT_EQ(v, CRYPT_SEC_DESCR);
    CHECK(cpc_gpp_dw(h, PP_KEYSPEC, &v));        EXPECT_EQ(v, P->keyspec);
    cpc_rel(h);
}
PERPROV(cpc_gpp_scalars, p_scalars)

static const DWORD dwparams[] = { PP_IMPTYPE, PP_VERSION, PP_PROVTYPE, PP_KEYSET_TYPE, PP_SIG_KEYSIZE_INC,
                                  PP_KEYX_KEYSIZE_INC, PP_KEYSTORAGE, PP_KEYSPEC };

/* size protocol shared by every DWORD-valued property */
static void p_dw_protocol(int i) {
    REQUIRE(U(CryptGetProvParam));
    HCRYPTPROV h; if (!acqv(i, &h)) return;
    for (unsigned k = 0; k < sizeof dwparams / sizeof dwparams[0]; k++) {
        DWORD p = dwparams[k], n, v, want;
        BYTE buf[16];
        if (!cpc_gpp_dw(h, p, &want)) { t_check(0, __FILE__, __LINE__, "baseline", "param %lu", p); continue; }
        /* NULL buffer: success, length = 4 */
        n = 0; SET_ERR(0);
        t_check(cpc_gpp(h, p, NULL, &n, 0) && n == 4, __FILE__, __LINE__, "null buf", "param %lu n=%lu", p, n);
        n = 99;
        t_check(cpc_gpp(h, p, NULL, &n, 0) && n == 4, __FILE__, __LINE__, "null buf big n", "param %lu n=%lu", p, n);
        /* buffer too small: ERROR_MORE_DATA, length updated, buffer untouched */
        for (DWORD sz = 0; sz < 4; sz++) {
            memset(buf, 0x5a, sizeof buf); n = sz; SET_ERR(0);
            BOOL ok = cpc_gpp(h, p, buf, &n, 0);
            t_check(!ok && GetLastError() == ERROR_MORE_DATA && n == 4 && buf[0] == 0x5a, __FILE__, __LINE__, "small buf",
                    "param %lu sz %lu ok=%d err %lu n=%lu b0=%02x", p, sz, ok, GetLastError(), n, buf[0]);
        }
        /* bigger buffer: length is rewritten to 4 */
        memset(buf, 0, sizeof buf); n = 16;
        t_check(cpc_gpp(h, p, buf, &n, 0) && n == 4, __FILE__, __LINE__, "big buf", "param %lu n=%lu", p, n);
        memcpy(&v, buf, 4); EXPECT_EQ(v, want);
        EXPECT_EQ(buf[4], 0);
        /* non-zero flags */
        n = 4; SET_ERR(0);
        t_check(!cpc_gpp(h, p, buf, &n, 1) && GetLastError() == X_NTE_BAD_FLAGS, __FILE__, __LINE__, "flags", "param %lu err 0x%lx", p, GetLastError());
        n = 4; SET_ERR(0);
        t_check(!cpc_gpp(h, p, buf, &n, 0x80000000) && GetLastError() == X_NTE_BAD_FLAGS, __FILE__, __LINE__, "flags hi", "param %lu err 0x%lx", p, GetLastError());
        /* NULL length pointer */
        SET_ERR(0);
        t_check(!cpc_gpp(h, p, buf, NULL, 0) && GetLastError() == ERROR_INVALID_PARAMETER, __FILE__, __LINE__, "null len", "param %lu err 0x%lx", p, GetLastError());
    }
    cpc_rel(h);
}
PERPROV(cpc_gpp_dword_protocol, p_dw_protocol)

/* PP_NAME */
static void p_name(int i) {
    const cpc_prov *P = &cpc_provs[i];
    REQUIRE(U(CryptGetProvParam));
    HCRYPTPROV h; if (!acqv(i, &h)) return;
    DWORD len = (DWORD)strlen(P->a) + 1, n;
    char buf[300];
    n = 0; SET_ERR(0);
    CHECK(cpc_gpp(h, PP_NAME, NULL, &n, 0)); EXPECT_EQ(n, len);
    n = 1000;
    CHECK(cpc_gpp(h, PP_NAME, NULL, &n, 0)); EXPECT_EQ(n, len);
    memset(buf, 0x5a, sizeof buf); n = len - 1; SET_ERR(0);
    CHECK(!cpc_gpp(h, PP_NAME, buf, &n, 0)); EXPECT_ERR(ERROR_MORE_DATA); EXPECT_EQ(n, len); EXPECT_EQ(buf[0], 0x5a);
    memset(buf, 0x5a, sizeof buf); n = 0; SET_ERR(0);
    CHECK(!cpc_gpp(h, PP_NAME, buf, &n, 0)); EXPECT_ERR(ERROR_MORE_DATA); EXPECT_EQ(n, len);
    memset(buf, 0x5a, sizeof buf); n = len;
    CHECK(cpc_gpp(h, PP_NAME, buf, &n, 0)); EXPECT_EQ(n, len); EXPECT_STR(buf, P->a); EXPECT_EQ(buf[len], 0x5a);
    memset(buf, 0x5a, sizeof buf); n = sizeof buf;
    CHECK(cpc_gpp(h, PP_NAME, buf, &n, 0)); EXPECT_EQ(n, len); EXPECT_STR(buf, P->a);
    n = sizeof buf; SET_ERR(0);
    CHECK(!cpc_gpp(h, PP_NAME, buf, &n, 1)); EXPECT_ERR(X_NTE_BAD_FLAGS);
    SET_ERR(0);
    CHECK(!cpc_gpp(h, PP_NAME, buf, NULL, 0)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    cpc_rel(h);
}
PERPROV(cpc_gpp_name, p_name)

/* PP_CONTAINER under VERIFYCONTEXT: provider-specific; log, and enforce the buffer protocol only if it works */
static void p_container(int i) {
    REQUIRE(U(CryptGetProvParam));
    HCRYPTPROV h; if (!acqv(i, &h)) return;
    char buf[300]; DWORD n = 0;
    SET_ERR(0);
    BOOL ok = cpc_gpp(h, PP_CONTAINER, NULL, &n, 0);
    if (!ok) {
        t_note("%s PP_CONTAINER under VERIFYCONTEXT: fails 0x%lx", cpc_provs[i].a, GetLastError());
        DWORD e = GetLastError();
        CHECKF(e == X_NTE_BAD_TYPE || e == ERROR_MORE_DATA || e == X_NTE_BAD_UID, "unexpected error 0x%lx", e);
    } else {
        DWORD len = n;
        n = sizeof buf; memset(buf, 0, sizeof buf);
        CHECK(cpc_gpp(h, PP_CONTAINER, buf, &n, 0));
        t_note("%s PP_CONTAINER under VERIFYCONTEXT: \"%s\" (len %lu)", cpc_provs[i].a, buf, n);
        EXPECT_EQ(n, len);
        n = len - 1; SET_ERR(0);
        CHECK(!cpc_gpp(h, PP_CONTAINER, buf, &n, 0)); EXPECT_ERR(ERROR_MORE_DATA);
    }
    n = sizeof buf; SET_ERR(0);
    CHECK(!cpc_gpp(h, PP_CONTAINER, buf, &n, 1)); EXPECT_ERR(X_NTE_BAD_FLAGS);
    cpc_rel(h);
}
PERPROV(cpc_gpp_container, p_container)

static void p_unique(int i) {
    REQUIRE(U(CryptGetProvParam));
    HCRYPTPROV h; if (!acqv(i, &h)) return;
    char buf[300]; DWORD n = sizeof buf;
    SET_ERR(0);
    BOOL ok = cpc_gpp(h, PP_UNIQUE_CONTAINER, buf, &n, 0);
    t_note("%s PP_UNIQUE_CONTAINER under VERIFYCONTEXT: %s (0x%lx) n=%lu", cpc_provs[i].a, ok ? buf : "fail", ok ? 0 : GetLastError(), n);
    n = sizeof buf; SET_ERR(0);
    /* flag 1 (CRYPT_FIRST): rsaenh rejects it, dssenh ignores it and returns the same empty name */
    ok = cpc_gpp(h, PP_UNIQUE_CONTAINER, buf, &n, 1);
    if (cpc_provs[i].dss) { CHECK(ok); EXPECT_EQ(n, 1); EXPECT_EQ(buf[0], 0); }
    else { CHECK(!ok); EXPECT_ERR(X_NTE_BAD_FLAGS); }
    cpc_rel(h);
}
PERPROV(cpc_gpp_unique_container, p_unique)

/* PP_SGC_INFO / PP_ENUMEX_SIGNING_PROT */
static void p_sgc(int i) {
    const cpc_prov *P = &cpc_provs[i];
    REQUIRE(U(CryptGetProvParam));
    HCRYPTPROV h; if (!acqv(i, &h)) return;
    DWORD v = 7, n = 4;
    SET_ERR(0);
    BOOL ok = cpc_gpp(h, PP_SGC_INFO, &v, &n, 0);
    if (P->type == 12) {
        CHECK(ok); EXPECT_EQ(v, 0); EXPECT_EQ(n, 4);
        n = 0; CHECK(cpc_gpp(h, PP_SGC_INFO, NULL, &n, 0)); EXPECT_EQ(n, 4);
        n = 2; SET_ERR(0); CHECK(!cpc_gpp(h, PP_SGC_INFO, &v, &n, 0)); EXPECT_ERR(ERROR_MORE_DATA); EXPECT_EQ(n, 4);
        n = 4; SET_ERR(0); CHECK(!cpc_gpp(h, PP_SGC_INFO, &v, &n, 1)); EXPECT_ERR(X_NTE_BAD_FLAGS);
    } else {
        CHECK(!ok); EXPECT_ERR(X_NTE_BAD_TYPE);
    }
    /* PP_ENUMEX_SIGNING_PROT: always an empty value */
    BYTE b[8] = {1,1,1,1,1,1,1,1}; n = 8;
    CHECK(cpc_gpp(h, PP_ENUMEX_SIGNING_PROT, b, &n, 0)); EXPECT_EQ(n, 0); EXPECT_EQ(b[0], 1);
    n = 8; CHECK(cpc_gpp(h, PP_ENUMEX_SIGNING_PROT, NULL, &n, 0)); EXPECT_EQ(n, 0);
    n = 0; CHECK(cpc_gpp(h, PP_ENUMEX_SIGNING_PROT, b, &n, 0)); EXPECT_EQ(n, 0);
    cpc_rel(h);
}
PERPROV(cpc_gpp_sgc_and_signing_prot, p_sgc)

/* ------------------------------------------------------------ unknown parameters */
static void p_unknown(int i) {
    REQUIRE(U(CryptGetProvParam));
    HCRYPTPROV h; if (!acqv(i, &h)) return;
    static const DWORD bad[] = { 0, 7, 9, 10, 11, 12, 13, 14, 15, 18, 19, 20, 21, 23, 24, 25, 26, 28, 29, 30,
                                 31, 32, 33, 38, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 100, 0x1000, 0x7fffffff, 0xffffffff };
    for (unsigned k = 0; k < sizeof bad / sizeof bad[0]; k++) {
        BYTE b[64]; DWORD n = sizeof b; SET_ERR(0);
        BOOL ok = cpc_gpp(h, bad[k], b, &n, 0);
        t_check(!ok && GetLastError() == X_NTE_BAD_TYPE, __FILE__, __LINE__, "unknown param", "param %lu ok=%d err 0x%lx", bad[k], ok, GetLastError());
    }
    cpc_rel(h);
}
PERPROV(cpc_gpp_unknown_params, p_unknown)

/* ------------------------------------------------------------ algorithm enumeration */
static int has_alg(const PROV_ENUMALGS *a, int n, ALG_ID id) {
    for (int k = 0; k < n; k++) if (a[k].aiAlgid == id) return 1;
    return 0;
}
static void p_enumalgs(int i) {
    const cpc_prov *P = &cpc_provs[i];
    REQUIRE(U(CryptGetProvParam));
    HCRYPTPROV h; if (!acqv(i, &h)) return;
    PROV_ENUMALGS a[128];
    int n = cpc_enum_algs(h, a, 128);
    CHECKF(n > 0, "enumeration failed (%d), err 0x%lx", n, GetLastError());
    if (n <= 0) { cpc_rel(h); return; }
    for (int k = 0; k < n; k++) {
        for (int j = k + 1; j < n; j++) t_check(a[k].aiAlgid != a[j].aiAlgid, __FILE__, __LINE__, "unique", "dup alg 0x%x", a[k].aiAlgid);
        size_t nl = strnlen(a[k].szName, sizeof a[k].szName);
        t_check(nl < sizeof a[k].szName && nl > 0, __FILE__, __LINE__, "name terminated", "alg 0x%x", a[k].aiAlgid);
        t_check(a[k].dwNameLen == nl + 1, __FILE__, __LINE__, "name len", "alg 0x%x namelen %lu strlen %zu", a[k].aiAlgid, a[k].dwNameLen, nl);
        t_check(GET_ALG_CLASS(a[k].aiAlgid) != 0, __FILE__, __LINE__, "class", "alg 0x%x", a[k].aiAlgid);
    }
    for (int k = 0; k < P->nreq; k++)
        t_check(has_alg(a, n, P->req[k]), __FILE__, __LINE__, "required alg", "%s lacks alg 0x%x", P->a, P->req[k]);
    /* digest sizes are reported as the default bit length */
    for (int k = 0; k < n; k++) {
        DWORD want = 0;
        switch (a[k].aiAlgid) { case CALG_MD5: want = 128; break; case CALG_SHA1: want = 160; break;
            case CALG_SHA_256: want = 256; break; case CALG_SHA_384: want = 384; break; case CALG_SHA_512: want = 512; break; }
        if (want) t_check(a[k].dwBitLen == want, __FILE__, __LINE__, "digest bits", "alg 0x%x bits %lu", a[k].aiAlgid, a[k].dwBitLen);
    }
    t_note("%s: %d algorithms", P->a, n);
    cpc_rel(h);
}
PERPROV(cpc_gpp_enumalgs, p_enumalgs)

static void p_enumalgs_proto(int i) {
    const cpc_prov *P = &cpc_provs[i];
    REQUIRE(U(CryptGetProvParam));
    HCRYPTPROV h; if (!acqv(i, &h)) return;
    PROV_ENUMALGS e, first; DWORD n;
    /* first entry */
    n = sizeof e; CHECK(cpc_gpp(h, PP_ENUMALGS, &e, &n, CRYPT_FIRST)); EXPECT_EQ(n, sizeof e);
    first = e;
    /* NULL buffer reports the size and does not advance */
    n = 0; SET_ERR(0);
    CHECK(cpc_gpp(h, PP_ENUMALGS, NULL, &n, CRYPT_FIRST)); EXPECT_EQ(n, sizeof e);
    n = 0; CHECK(cpc_gpp(h, PP_ENUMALGS, NULL, &n, 0)); EXPECT_EQ(n, sizeof e);
    /* too small */
    for (DWORD sz = 0; sz < sizeof e; sz += 7) {
        n = sz; SET_ERR(0);
        BOOL ok = cpc_gpp(h, PP_ENUMALGS, &e, &n, CRYPT_FIRST);
        t_check(!ok && GetLastError() == ERROR_MORE_DATA && n == sizeof e, __FILE__, __LINE__, "small", "sz %lu ok=%d err %lu n=%lu", sz, ok, GetLastError(), n);
    }
    n = sizeof e - 1; SET_ERR(0);
    CHECK(!cpc_gpp(h, PP_ENUMALGS, &e, &n, CRYPT_FIRST)); EXPECT_ERR(ERROR_MORE_DATA);
    /* the failed/NULL calls did not advance: FIRST restarts at the same entry */
    n = sizeof e; CHECK(cpc_gpp(h, PP_ENUMALGS, &e, &n, CRYPT_FIRST));
    EXPECT_EQ(e.aiAlgid, first.aiAlgid);
    /* a second entry, then restart */
    PROV_ENUMALGS second;
    n = sizeof e; CHECK(cpc_gpp(h, PP_ENUMALGS, &second, &n, 0));
    CHECK(second.aiAlgid != first.aiAlgid);
    n = sizeof e; CHECK(cpc_gpp(h, PP_ENUMALGS, &e, &n, CRYPT_NEXT));
    CHECK(e.aiAlgid != second.aiAlgid);
    n = sizeof e; CHECK(cpc_gpp(h, PP_ENUMALGS, &e, &n, CRYPT_FIRST)); EXPECT_EQ(e.aiAlgid, first.aiAlgid);
    /* larger buffer: size rewritten */
    BYTE big[100]; n = sizeof big;
    CHECK(cpc_gpp(h, PP_ENUMALGS, big, &n, CRYPT_FIRST)); EXPECT_EQ(n, sizeof e);
    /* invalid flags */
    n = sizeof e; SET_ERR(0);
    CHECK(!cpc_gpp(h, PP_ENUMALGS, &e, &n, 8)); EXPECT_ERR(X_NTE_BAD_FLAGS);
    n = sizeof e; SET_ERR(0);
    CHECK(!cpc_gpp(h, PP_ENUMALGS, &e, &n, 0x10)); EXPECT_ERR(X_NTE_BAD_FLAGS);
    n = sizeof e; SET_ERR(0);
    CHECK(!cpc_gpp(h, PP_ENUMALGS, &e, &n, 0x80000001)); EXPECT_ERR(X_NTE_BAD_FLAGS);
    n = sizeof e; SET_ERR(0);
    BOOL ok = cpc_gpp(h, PP_ENUMALGS, &e, &n, CRYPT_FIRST | CRYPT_SGC_ENUM);
    if (P->type == 12) CHECK(ok);   /* SGC enumeration is allowed on the SChannel provider only */
    else { CHECK(!ok); EXPECT_ERR(X_NTE_BAD_FLAGS); }
    cpc_rel(h);
}
PERPROV(cpc_gpp_enumalgs_protocol, p_enumalgs_proto)

static void p_enumalgs_fresh(int i) {
    REQUIRE(U(CryptGetProvParam));
    HCRYPTPROV h; if (!acqv(i, &h)) return;
    PROV_ENUMALGS e0; DWORD n = sizeof e0;
    SET_ERR(0);
    BOOL ok = cpc_gpp(h, PP_ENUMALGS, &e0, &n, 0);
    t_note("%s: first PP_ENUMALGS call without CRYPT_FIRST on a new context: %s (0x%lx)", cpc_provs[i].a, ok ? "ok" : "fail", ok ? 0 : GetLastError());
    cpc_rel(h);
    /* two contexts keep independent enumeration cursors */
    HCRYPTPROV a, b; if (!acqv(i, &a)) return; if (!acqv(i, &b)) { cpc_rel(a); return; }
    PROV_ENUMALGS x, y, z;
    n = sizeof x; CHECK(cpc_gpp(a, PP_ENUMALGS, &x, &n, CRYPT_FIRST));
    n = sizeof y; CHECK(cpc_gpp(a, PP_ENUMALGS, &y, &n, 0));
    n = sizeof z; CHECK(cpc_gpp(b, PP_ENUMALGS, &z, &n, CRYPT_FIRST));
    EXPECT_EQ(z.aiAlgid, x.aiAlgid);
    n = sizeof z; CHECK(cpc_gpp(b, PP_ENUMALGS, &z, &n, 0));
    EXPECT_EQ(z.aiAlgid, y.aiAlgid);   /* b's second entry equals a's second entry */
    cpc_rel(a); cpc_rel(b);
}
PERPROV(cpc_gpp_enumalgs_cursor, p_enumalgs_fresh)

static void p_enumalgs_end(int i) {
    REQUIRE(U(CryptGetProvParam));
    HCRYPTPROV h; if (!acqv(i, &h)) return;
    PROV_ENUMALGS e; DWORD n; int cnt = 0;
    for (;;) {
        n = sizeof e;
        if (!cpc_gpp(h, PP_ENUMALGS, &e, &n, cnt == 0 ? CRYPT_FIRST : 0)) break;
        if (++cnt > 200) break;
    }
    EXPECT_ERR(ERROR_NO_MORE_ITEMS);
    CHECK(cnt > 0 && cnt <= 200);
    /* CRYPT_FIRST after the end restarts */
    n = sizeof e; CHECK(cpc_gpp(h, PP_ENUMALGS, &e, &n, CRYPT_FIRST));
    cpc_rel(h);
}
PERPROV(cpc_gpp_enumalgs_end, p_enumalgs_end)

static void p_enumex(int i) {
    const cpc_prov *P = &cpc_provs[i];
    REQUIRE(U(CryptGetProvParam));
    HCRYPTPROV h; if (!acqv(i, &h)) return;
    PROV_ENUMALGS a[128]; PROV_ENUMALGS_EX x[128];
    int n = cpc_enum_algs(h, a, 128), m = cpc_enum_algs_ex(h, x, 128);
    CHECKF(n > 0 && m > 0, "n=%d m=%d", n, m);
    if (n > 0 && m > 0) {
        EXPECT_EQ(n, m);
        for (int k = 0; k < n && k < m; k++) {
            t_check(a[k].aiAlgid == x[k].aiAlgid, __FILE__, __LINE__, "same order", "k=%d 0x%x vs 0x%x", k, a[k].aiAlgid, x[k].aiAlgid);
            t_check(a[k].dwBitLen == x[k].dwDefaultLen, __FILE__, __LINE__, "bitlen", "alg 0x%x", a[k].aiAlgid);
            t_check(!strcmp(a[k].szName, x[k].szName), __FILE__, __LINE__, "name", "alg 0x%x", a[k].aiAlgid);
            t_check(x[k].dwMinLen <= x[k].dwDefaultLen && x[k].dwDefaultLen <= x[k].dwMaxLen, __FILE__, __LINE__, "min<=def<=max",
                    "alg 0x%x %lu/%lu/%lu", x[k].aiAlgid, x[k].dwMinLen, x[k].dwDefaultLen, x[k].dwMaxLen);
            size_t nl = strnlen(x[k].szName, 20), ll = strnlen(x[k].szLongName, 40);
            t_check(nl < 20 && ll < 40 && nl > 0 && ll > 0, __FILE__, __LINE__, "strings", "alg 0x%x", x[k].aiAlgid);
            t_check(x[k].dwNameLen == nl + 1, __FILE__, __LINE__, "name len", "alg 0x%x", x[k].aiAlgid);
            t_check(x[k].dwLongNameLen == ll + 1, __FILE__, __LINE__, "long name len", "alg 0x%x got %lu want %zu", x[k].aiAlgid, x[k].dwLongNameLen, ll + 1);
        }
        for (int k = 0; k < P->nreq; k++) {
            int f = 0; for (int j = 0; j < m; j++) if (x[j].aiAlgid == P->req[k]) f = 1;
            t_check(f, __FILE__, __LINE__, "required alg (ex)", "%s lacks 0x%x", P->a, P->req[k]);
        }
        for (int k = 0; k < m; k++)
            t_note("%s ex: 0x%04x %-12s def=%lu min=%lu max=%lu prot=0x%lx", P->a, x[k].aiAlgid, x[k].szName, x[k].dwDefaultLen, x[k].dwMinLen, x[k].dwMaxLen, x[k].dwProtocols);
    }
    cpc_rel(h);
}
PERPROV(cpc_gpp_enumalgs_ex_consistency, p_enumex)

static void p_enumex_proto(int i) {
    REQUIRE(U(CryptGetProvParam));
    HCRYPTPROV h; if (!acqv(i, &h)) return;
    PROV_ENUMALGS_EX e, f; DWORD n;
    n = 0; SET_ERR(0);
    CHECK(cpc_gpp(h, PP_ENUMALGS_EX, NULL, &n, CRYPT_FIRST)); EXPECT_EQ(n, sizeof e);
    EXPECT_EQ(sizeof e, 0x58);
    for (DWORD sz = 0; sz < sizeof e; sz += 11) {
        n = sz; SET_ERR(0);
        BOOL ok = cpc_gpp(h, PP_ENUMALGS_EX, &e, &n, CRYPT_FIRST);
        t_check(!ok && GetLastError() == ERROR_MORE_DATA && n == sizeof e, __FILE__, __LINE__, "small", "sz %lu ok=%d err %lu n=%lu", sz, ok, GetLastError(), n);
    }
    n = sizeof e - 1; SET_ERR(0);
    CHECK(!cpc_gpp(h, PP_ENUMALGS_EX, &e, &n, CRYPT_FIRST)); EXPECT_ERR(ERROR_MORE_DATA); EXPECT_EQ(n, sizeof e);
    n = sizeof e; CHECK(cpc_gpp(h, PP_ENUMALGS_EX, &e, &n, CRYPT_FIRST));
    n = sizeof e; CHECK(cpc_gpp(h, PP_ENUMALGS_EX, &f, &n, CRYPT_NEXT));
    CHECK(e.aiAlgid != f.aiAlgid);
    n = sizeof e; SET_ERR(0);
    CHECK(!cpc_gpp(h, PP_ENUMALGS_EX, &e, &n, 8)); EXPECT_ERR(X_NTE_BAD_FLAGS);
    n = sizeof e; SET_ERR(0);
    CHECK(!cpc_gpp(h, PP_ENUMALGS_EX, &e, &n, 0x100)); EXPECT_ERR(X_NTE_BAD_FLAGS);
    cpc_rel(h);
}
PERPROV(cpc_gpp_enumalgs_ex_protocol, p_enumex_proto)

/* ENUMALGS and ENUMALGS_EX keep separate cursors */
static void p_enum_cursors(int i) {
    REQUIRE(U(CryptGetProvParam));
    HCRYPTPROV h; if (!acqv(i, &h)) return;
    PROV_ENUMALGS a0, a1; PROV_ENUMALGS_EX x0, x1; DWORD n;
    n = sizeof a0; CHECK(cpc_gpp(h, PP_ENUMALGS, &a0, &n, CRYPT_FIRST));
    n = sizeof x0; CHECK(cpc_gpp(h, PP_ENUMALGS_EX, &x0, &n, CRYPT_FIRST));
    n = sizeof a1; CHECK(cpc_gpp(h, PP_ENUMALGS, &a1, &n, 0));
    n = sizeof x1; CHECK(cpc_gpp(h, PP_ENUMALGS_EX, &x1, &n, 0));
    EXPECT_EQ(a0.aiAlgid, x0.aiAlgid);
    EXPECT_EQ(a1.aiAlgid, x1.aiAlgid);
    CHECK(a0.aiAlgid != a1.aiAlgid);
    cpc_rel(h);
}
PERPROV(cpc_gpp_enum_separate_cursors, p_enum_cursors)

/* ------------------------------------------------------------ container enumeration under VERIFYCONTEXT */
static void p_enumcont(int i) {
    REQUIRE(U(CryptGetProvParam));
    HCRYPTPROV h; if (!acqv(i, &h)) return;
    char name[0x105 + 8]; DWORD n;
    /* size query */
    n = 0; SET_ERR(0);
    CHECK(cpc_gpp(h, PP_ENUMCONTAINERS, NULL, &n, CRYPT_FIRST)); EXPECT_EQ(n, 0x105);
    n = 0x104; memset(name, 0x5a, sizeof name); SET_ERR(0);
    CHECK(!cpc_gpp(h, PP_ENUMCONTAINERS, name, &n, CRYPT_FIRST)); EXPECT_ERR(ERROR_MORE_DATA); EXPECT_EQ(n, 0x105);
    n = 0; SET_ERR(0);
    CHECK(!cpc_gpp(h, PP_ENUMCONTAINERS, name, &n, CRYPT_FIRST)); EXPECT_ERR(ERROR_MORE_DATA); EXPECT_EQ(n, 0x105);
    /* invalid flags */
    n = sizeof name; SET_ERR(0);
    CHECK(!cpc_gpp(h, PP_ENUMCONTAINERS, name, &n, 4)); EXPECT_ERR(X_NTE_BAD_FLAGS);
    n = sizeof name; SET_ERR(0);
    CHECK(!cpc_gpp(h, PP_ENUMCONTAINERS, name, &n, 8)); EXPECT_ERR(X_NTE_BAD_FLAGS);
    /* walk the (read-only) listing: each call gives a non-empty name, the end is ERROR_NO_MORE_ITEMS */
    int cnt = 0, bad = 0;
    for (;;) {
        n = sizeof name; memset(name, 0, sizeof name);
        BOOL ok = cpc_gpp(h, PP_ENUMCONTAINERS, name, &n, cnt == 0 ? CRYPT_FIRST : CRYPT_NEXT);
        if (!ok) { DWORD e = GetLastError(); t_check(e == ERROR_NO_MORE_ITEMS, __FILE__, __LINE__, "end of containers", "err 0x%lx after %d", e, cnt); break; }
        if (!name[0] || n == 0 || n > 0x105) bad++;
        if (++cnt >= 2000) break;
    }
    CHECK(bad == 0);
    t_note("%s: %d containers visible to the user keyset (sample \"%s\")", cpc_provs[i].a, cnt, name);
    cpc_rel(h);
}
PERPROV(cpc_gpp_enumcontainers_verifyctx, p_enumcont)

static void p_enumcont_next_first(int i) {
    /* CRYPT_NEXT on a context that never started an enumeration */
    REQUIRE(U(CryptGetProvParam));
    HCRYPTPROV h; if (!acqv(i, &h)) return;
    char name[0x110]; DWORD n = sizeof name; SET_ERR(0);
    BOOL ok = cpc_gpp(h, PP_ENUMCONTAINERS, name, &n, CRYPT_NEXT);
    CHECK(!ok); EXPECT_ERR(X_NTE_BAD_FLAGS);
    n = sizeof name; SET_ERR(0);
    ok = cpc_gpp(h, PP_ENUMCONTAINERS, name, &n, 0);
    CHECK(!ok); EXPECT_ERR(X_NTE_BAD_FLAGS);
    cpc_rel(h);
}
PERPROV(cpc_gpp_enumcontainers_next_without_first, p_enumcont_next_first)

/* PP_KEYSET_SEC_DESCR flags rules */
static void p_secdescr(int i) {
    REQUIRE(U(CryptGetProvParam));
    HCRYPTPROV h; if (!acqv(i, &h)) return;
    BYTE b[256]; DWORD n = sizeof b; SET_ERR(0);
    CHECK(!cpc_gpp(h, PP_KEYSET_SEC_DESCR, b, &n, 0)); EXPECT_ERR(X_NTE_BAD_FLAGS);
    n = sizeof b; SET_ERR(0);
    CHECK(!cpc_gpp(h, PP_KEYSET_SEC_DESCR, b, &n, 0x20)); EXPECT_ERR(X_NTE_BAD_FLAGS);
    n = sizeof b; SET_ERR(0);
    CHECK(!cpc_gpp(h, PP_KEYSET_SEC_DESCR, b, &n, 0x80000000)); EXPECT_ERR(X_NTE_BAD_FLAGS);
    n = sizeof b; SET_ERR(0);
    BOOL ok = cpc_gpp(h, PP_KEYSET_SEC_DESCR, b, &n, OWNER_SECURITY_INFORMATION);
    t_note("%s PP_KEYSET_SEC_DESCR(OWNER) under VERIFYCONTEXT: %s (0x%lx) n=%lu", cpc_provs[i].a, ok ? "ok" : "fail", ok ? 0 : GetLastError(), n);
    cpc_rel(h);
}
PERPROV(cpc_gpp_keyset_sec_descr_flags, p_secdescr)

/* ------------------------------------------------------------ SetProvParam */
static void s_misc(int i) {
    const cpc_prov *P = &cpc_provs[i];
    REQUIRE(U(CryptSetProvParam));
    HCRYPTPROV h; if (!acqv(i, &h)) return;
    /* PP_CLIENT_HWND: process-wide, handled in cryptsp; set it back to NULL afterwards */
    HWND none = NULL; SET_ERR(0);
    CHECK(U(CryptSetProvParam)(h, PP_CLIENT_HWND, (BYTE *)&none, 0));
    /* PP_UI_PROMPT (wide string, NULL clears) */
    SET_ERR(0);
    CHECK(U(CryptSetProvParam)(h, PP_UI_PROMPT, (BYTE *)L"cpc prompt", 0));
    CHECK(U(CryptSetProvParam)(h, PP_UI_PROMPT, (BYTE *)L"", 0));
    CHECK(U(CryptSetProvParam)(h, PP_UI_PROMPT, NULL, 0));
    SET_ERR(0);
    CHECK(!U(CryptSetProvParam)(h, PP_UI_PROMPT, (BYTE *)L"x", 1)); EXPECT_ERR(X_NTE_BAD_FLAGS);
    /* PP_KEY_TYPE_SUBTYPE */
    SET_ERR(0);
    BOOL ok = U(CryptSetProvParam)(h, PP_KEY_TYPE_SUBTYPE, NULL, 0);
    if (P->dss) { CHECK(!ok); EXPECT_ERR(X_NTE_BAD_TYPE); } else CHECK(ok);
    SET_ERR(0);
    CHECK(!U(CryptSetProvParam)(h, PP_KEY_TYPE_SUBTYPE, NULL, 1)); EXPECT_ERR(X_NTE_BAD_FLAGS);
    /* PP_DELETEKEY needs a real keyset */
    int spec = AT_KEYEXCHANGE; SET_ERR(0);
    CHECK(!U(CryptSetProvParam)(h, PP_DELETEKEY, (BYTE *)&spec, 0)); EXPECT_ERR(X_NTE_BAD_UID);
    SET_ERR(0);
    CHECK(!U(CryptSetProvParam)(h, PP_DELETEKEY, (BYTE *)&spec, 1)); EXPECT_ERR(X_NTE_BAD_FLAGS);
    /* PP_SGC_INFO */
    SET_ERR(0);
    ok = U(CryptSetProvParam)(h, PP_SGC_INFO, NULL, 0);
    if (P->type == 12) CHECK(ok); else { CHECK(!ok); EXPECT_ERR(X_NTE_BAD_TYPE); }
    SET_ERR(0);
    ok = U(CryptSetProvParam)(h, PP_SGC_INFO, NULL, 1);
    CHECK(!ok);
    if (P->dss) EXPECT_ERR(X_NTE_BAD_TYPE); else EXPECT_ERR(X_NTE_BAD_FLAGS);
    /* PP_KEYSET_SEC_DESCR: flags must be a non-empty SECURITY_INFORMATION subset (low 5 bits) */
    SET_ERR(0);
    CHECK(!U(CryptSetProvParam)(h, PP_KEYSET_SEC_DESCR, NULL, 0)); EXPECT_ERR(X_NTE_BAD_FLAGS);
    SET_ERR(0);
    CHECK(!U(CryptSetProvParam)(h, PP_KEYSET_SEC_DESCR, NULL, 0x20)); EXPECT_ERR(X_NTE_BAD_FLAGS);
    cpc_rel(h);
}
PERPROV(cpc_spp_known_params, s_misc)

static void s_unknown(int i) {
    REQUIRE(U(CryptSetProvParam));
    HCRYPTPROV h; if (!acqv(i, &h)) return;
    static const DWORD bad[] = { 0, 2, 3, 4, 5, 6, 7, 9, 12, 13, 14, 15, 16, 17, 19, 20, 22, 23, 26, 27, 28, 29, 30, 31,
                                 32, 33, 34, 35, 36, 38, 39, 40, 41, 42, 100, 0x7fffffff, 0xffffffff };
    for (unsigned k = 0; k < sizeof bad / sizeof bad[0]; k++) {
        SET_ERR(0);
        BOOL ok = U(CryptSetProvParam)(h, bad[k], NULL, 0);
        t_check(!ok && GetLastError() == X_NTE_BAD_TYPE, __FILE__, __LINE__, "unknown set param", "param %lu ok=%d err 0x%lx", bad[k], ok, GetLastError());
    }
    cpc_rel(h);
}
PERPROV(cpc_spp_unknown_params, s_unknown)

/* a context with an extra reference still accepts parameter calls; contexts are not usable while "busy" is not testable here */
TEST(cpc_spp_client_hwnd_roundtrip) {
    REQUIRE(U(CryptSetProvParam)); REQUIRE(U(CryptAcquireContextA));
    HCRYPTPROV h = 0; CHECK(cpc_acq(&h, MS_DEF_PROV_A, 1, X_VERIFY));
    HWND w = GetDesktopWindow();
    CHECK(U(CryptSetProvParam)(h, PP_CLIENT_HWND, (BYTE *)&w, 0));
    HWND none = NULL;
    CHECK(U(CryptSetProvParam)(h, PP_CLIENT_HWND, (BYTE *)&none, 0));
    cpc_rel(h);
}
