/* cryptxml.dll: the algorithm table - CryptXmlEnumAlgorithmInfo, CryptXmlFindAlgorithmInfo,
 * CryptXmlGetAlgorithmInfo.  The built-in table has 17 entries: 4 hashes (group 1) and
 * 13 signature methods (group 2: RSA x4, DSA, ECDSA x4, HMAC x4). */
#include "xml.h"
#include <stdlib.h>

/* name, hash (CNGAlgid, opened as a BCrypt hash provider), key algorithm (CNGExtraAlgid), group, digest bytes */
typedef struct { const WCHAR *uri; const WCHAR *name; const WCHAR *hash; const WCHAR *key; DWORD group; ULONG hlen; } ROW;
#define ECCP L"CryptOIDInfoECCParameters"
static const ROW ROWS[17] = {
    { U_SHA1,   L"SHA1",   L"SHA1",   NULL, 1, 20 }, { U_SHA256, L"SHA256", L"SHA256", NULL, 1, 32 },
    { U_SHA384, L"SHA384", L"SHA384", NULL, 1, 48 }, { U_SHA512, L"SHA512", L"SHA512", NULL, 1, 64 },
    { U_RSA1,   L"RSA-SHA1",   L"SHA1",   L"RSA", 2, 20 }, { U_RSA256, L"RSA-SHA256", L"SHA256", L"RSA", 2, 32 },
    { U_RSA384, L"RSA-SHA384", L"SHA384", L"RSA", 2, 48 }, { U_RSA512, L"RSA-SHA512", L"SHA512", L"RSA", 2, 64 },
    { U_DSA1,   L"DSA-SHA1",   L"SHA1",   L"DSA", 2, 20 },
    { U_ECDSA1,   L"ECDSA-SHA1",   L"SHA1",   ECCP, 2, 20 }, { U_ECDSA256, L"ECDSA-SHA256", L"SHA256", ECCP, 2, 32 },
    { U_ECDSA384, L"ECDSA-SHA384", L"SHA384", ECCP, 2, 48 },  { U_ECDSA512, L"ECDSA-SHA512", L"SHA512", ECCP, 2, 64 },
    { U_HMAC1,   L"HMAC-SHA1",   L"SHA1",   NULL, 2, 20 }, { U_HMAC256, L"HMAC-SHA256", L"SHA256", NULL, 2, 32 },
    { U_HMAC384, L"HMAC-SHA384", L"SHA384", NULL, 2, 48 }, { U_HMAC512, L"HMAC-SHA512", L"SHA512", NULL, 2, 64 },
};

typedef struct { int n; const XALGINFO *seen[40]; int stop_after; } COLLECT;
static BOOL CALLBACK collect_cb(const XALGINFO *info, void *arg)
{
    COLLECT *c = arg;
    if (c->n < 40) c->seen[c->n] = info;
    c->n++;
    return c->stop_after && c->n >= c->stop_after ? FALSE : TRUE;
}
static int rowof(const WCHAR *uri)
{
    for (int i = 0; i < 17; i++) if (!lstrcmpiW(ROWS[i].uri, uri)) return i;
    return -1;
}

/* ---- enumeration ---------------------------------------------------------------------------------- */
TEST(xmlsig_algs_enum_all_entries)
{
    REQUIRE(XFN(CryptXmlEnumAlgorithmInfo));
    COLLECT c = {0};
    XCHK_HR(XFN(CryptXmlEnumAlgorithmInfo)(0, 0, &c, collect_cb), S_OK);
    EXPECT_EQ(c.n, 17);
    int seen[17] = {0};
    for (int i = 0; i < c.n && i < 40; i++) {
        CHECK(c.seen[i] != NULL);
        if (!c.seen[i]) continue;
        int r = c.seen[i]->wszAlgorithmURI ? rowof(c.seen[i]->wszAlgorithmURI) : -1;
        CHECKF(r >= 0, "unexpected URI %ls", c.seen[i]->wszAlgorithmURI);
        if (r >= 0) { seen[r]++; EXPECT_EQ(c.seen[i]->dwGroupId, ROWS[r].group); }
    }
    for (int i = 0; i < 17; i++) CHECKF(seen[i] == 1, "%ls enumerated %d times", ROWS[i].uri, seen[i]);
}

TEST(xmlsig_algs_enum_groups)
{
    REQUIRE(XFN(CryptXmlEnumAlgorithmInfo));
    DWORD grp[] = { X_GROUP_HASH, X_GROUP_SIGN, 3, 4, 0x100, 0xffffffff };
    int want[] = { 4, 13, 0, 0, 0, 0 };
    for (int i = 0; i < 6; i++) {
        COLLECT c = {0};
        HRESULT hr = XFN(CryptXmlEnumAlgorithmInfo)(grp[i], 0, &c, collect_cb);
        CHECKF(hr == S_OK, "group %lu hr=0x%08lx", grp[i], (unsigned long)hr);
        CHECKF(c.n == want[i], "group %lu: %d entries, want %d", grp[i], c.n, want[i]);
        for (int k = 0; k < c.n && k < 40; k++) if (c.seen[k]) CHECK(c.seen[k]->dwGroupId == grp[i]);
    }
}

TEST(xmlsig_algs_enum_early_stop)
{
    REQUIRE(XFN(CryptXmlEnumAlgorithmInfo));
    for (int stop = 1; stop <= 3; stop++) {
        COLLECT c = {0};
        c.stop_after = stop;
        XCHK_HR(XFN(CryptXmlEnumAlgorithmInfo)(0, 0, &c, collect_cb), S_OK);   /* FALSE from the callback ends the walk, still S_OK */
        EXPECT_EQ(c.n, stop);
    }
    COLLECT c = {0};
    c.stop_after = 5;
    XCHK_HR(XFN(CryptXmlEnumAlgorithmInfo)(X_GROUP_SIGN, 0, &c, collect_cb), S_OK);
    EXPECT_EQ(c.n, 5);
}

TEST(xmlsig_algs_enum_order_is_stable)
{
    REQUIRE(XFN(CryptXmlEnumAlgorithmInfo));
    COLLECT a = {0}, b = {0}, h = {0}, s = {0};
    XCHK_HR(XFN(CryptXmlEnumAlgorithmInfo)(0, 0, &a, collect_cb), S_OK);
    XCHK_HR(XFN(CryptXmlEnumAlgorithmInfo)(0, 0, &b, collect_cb), S_OK);
    XCHK_HR(XFN(CryptXmlEnumAlgorithmInfo)(X_GROUP_HASH, 0, &h, collect_cb), S_OK);
    XCHK_HR(XFN(CryptXmlEnumAlgorithmInfo)(X_GROUP_SIGN, 0, &s, collect_cb), S_OK);
    for (int i = 0; i < 17 && i < a.n; i++) CHECKF(a.seen[i] == b.seen[i], "entry %d moves between calls", i);
    /* the grouped walks visit the same records as the full walk */
    for (int i = 0; i < h.n; i++) { int f = 0; for (int k = 0; k < a.n; k++) f |= a.seen[k] == h.seen[i]; CHECK(f); }
    for (int i = 0; i < s.n; i++) { int f = 0; for (int k = 0; k < a.n; k++) f |= a.seen[k] == s.seen[i]; CHECK(f); }
    t_note("table order: first=%ls last=%ls", a.n ? a.seen[0]->wszAlgorithmURI : L"", a.n ? a.seen[a.n - 1]->wszAlgorithmURI : L"");
}

TEST(xmlsig_algs_enum_disable_extensions_flag)
{
    REQUIRE(XFN(CryptXmlEnumAlgorithmInfo));
    COLLECT c = {0};
    XCHK_HR(XFN(CryptXmlEnumAlgorithmInfo)(0, X_FLAG_DISABLE_EXT, &c, collect_cb), S_OK);
    EXPECT_EQ(c.n, 17);
}

TEST(xmlsig_algs_enum_entries_match_find)
{
    REQUIRE(XFN(CryptXmlEnumAlgorithmInfo)); REQUIRE(XFN(CryptXmlFindAlgorithmInfo));
    COLLECT c = {0};
    XCHK_HR(XFN(CryptXmlEnumAlgorithmInfo)(0, 0, &c, collect_cb), S_OK);
    for (int i = 0; i < c.n && i < 40; i++) {
        const XALGINFO *f = XFN(CryptXmlFindAlgorithmInfo)(X_FIND_URI, c.seen[i]->wszAlgorithmURI, 0, 0);
        CHECKF(f == c.seen[i], "entry %d (%ls): find returns %p, enum gave %p", i, c.seen[i]->wszAlgorithmURI, f, c.seen[i]);
    }
}

/* ---- table content ---------------------------------------------------------------------------------- */
TEST(xmlsig_algs_table_uris_and_groups)
{
    REQUIRE(XFN(CryptXmlFindAlgorithmInfo));
    for (int i = 0; i < 17; i++) {
        const XALGINFO *a = XFN(CryptXmlFindAlgorithmInfo)(X_FIND_URI, ROWS[i].uri, 0, 0);
        CHECKF(a != NULL, "%ls not found", ROWS[i].uri);
        if (!a) continue;
        CHECK(a->wszAlgorithmURI && !lstrcmpW(a->wszAlgorithmURI, ROWS[i].uri));
        EXPECT_EQ(a->dwGroupId, ROWS[i].group);
        CHECK(a->wszName != NULL);
        
        t_note("%ls: name=%ls cng=%ls extra=%ls signFlags=0x%lx verifyFlags=0x%lx cbSize=%lu", ROWS[i].uri, a->wszName ? a->wszName : L"-",
               a->wszCNGAlgid ? a->wszCNGAlgid : L"-", a->wszCNGExtraAlgid ? a->wszCNGExtraAlgid : L"-", a->dwSignFlags, a->dwVerifyFlags, a->cbSize);
    }
}

TEST(xmlsig_algs_table_names_hash_and_key_ids)
{
    REQUIRE(XFN(CryptXmlFindAlgorithmInfo));
    for (int i = 0; i < 17; i++) {
        const XALGINFO *a = XFN(CryptXmlFindAlgorithmInfo)(X_FIND_URI, ROWS[i].uri, 0, 0);
        if (!a) { CHECKF(0, "%ls not found", ROWS[i].uri); continue; }
        CHECKF(a->wszName && !lstrcmpW(a->wszName, ROWS[i].name), "%ls: name %ls", ROWS[i].uri, a->wszName ? a->wszName : L"(null)");
        /* CNGAlgid names the hash used for the digest, CNGExtraAlgid the key algorithm (or the ECC parameter marker) */
        if (i < 13)
            CHECKF(a->wszCNGAlgid && !lstrcmpW(a->wszCNGAlgid, ROWS[i].hash), "%ls: hash id %ls", ROWS[i].uri, a->wszCNGAlgid ? a->wszCNGAlgid : L"(null)");
        else
            t_note("%ls: cng id %ls extra %ls", ROWS[i].uri, a->wszCNGAlgid ? a->wszCNGAlgid : L"(null)", a->wszCNGExtraAlgid ? a->wszCNGExtraAlgid : L"(null)");
        if (ROWS[i].key)
            CHECKF(a->wszCNGExtraAlgid && !lstrcmpW(a->wszCNGExtraAlgid, ROWS[i].key), "%ls: key id %ls", ROWS[i].uri, a->wszCNGExtraAlgid ? a->wszCNGExtraAlgid : L"(null)");
        if (!ROWS[i].key) t_note("%ls: extra algid %ls", ROWS[i].uri, a->wszCNGExtraAlgid ? a->wszCNGExtraAlgid : L"(null)");
    }
}

TEST(xmlsig_algs_cng_hash_ids_are_real_hash_algorithms)
{
    REQUIRE(XFN(CryptXmlFindAlgorithmInfo));
    for (int i = 0; i < 13; i++) {                       /* the HMAC rows are not driven by these fields */
        const XALGINFO *a = XFN(CryptXmlFindAlgorithmInfo)(X_FIND_URI, ROWS[i].uri, 0, 0);
        BYTE out[64]; ULONG ol = 0;
        if (!a || !a->wszCNGAlgid) { CHECKF(0, "%ls", ROWS[i].uri); continue; }
        if (!x_hash(a->wszCNGAlgid, NULL, 0, "abc", 3, out, &ol)) { t_note("bcrypt cannot open %ls", a->wszCNGAlgid); continue; }
        CHECKF(ol == ROWS[i].hlen, "%ls: digest length %lu", ROWS[i].uri, ol);
    }
}

TEST(xmlsig_algs_sign_flags_and_padding)
{
    REQUIRE(XFN(CryptXmlFindAlgorithmInfo));
    for (int i = 4; i < 13; i++) {
        const XALGINFO *a = XFN(CryptXmlFindAlgorithmInfo)(X_FIND_URI, ROWS[i].uri, X_GROUP_SIGN, 0);
        if (!a) { CHECKF(0, "%ls", ROWS[i].uri); continue; }
        if (i <= 7) {
            EXPECT_EQ(a->dwSignFlags, 2);              /* BCRYPT_PAD_PKCS1 */
            EXPECT_EQ(a->dwVerifyFlags, 2);
            CHECK(a->pvPaddingInfo != NULL);
            if (a->pvPaddingInfo) CHECK(*(const WCHAR *const *)a->pvPaddingInfo && !lstrcmpW(*(const WCHAR *const *)a->pvPaddingInfo, ROWS[i].hash));
        } else {
            EXPECT_EQ(a->dwSignFlags, 0);
            EXPECT_EQ(a->dwVerifyFlags, 0);
            EXPECT_EQ(a->pvPaddingInfo, NULL);
        }
    }
}

TEST(xmlsig_algs_hmac_entries_note)
{
    REQUIRE(XFN(CryptXmlFindAlgorithmInfo));
    const WCHAR *uri[] = { U_HMAC1, U_HMAC256, U_HMAC384, U_HMAC512 };
    for (int i = 0; i < 4; i++) {
        const XALGINFO *a = XFN(CryptXmlFindAlgorithmInfo)(X_FIND_URI, uri[i], X_GROUP_SIGN, 0);
        CHECK(a != NULL);
        if (a) t_note("%ls: extra=%ls signFlags=0x%lx pad=%p", uri[i], a->wszCNGExtraAlgid ? a->wszCNGExtraAlgid : L"-", a->dwSignFlags, a->pvPaddingInfo);
    }
}

/* ---- FindAlgorithmInfo -------------------------------------------------------------------------------- */
TEST(xmlsig_algs_find_by_uri_is_case_insensitive)
{
    REQUIRE(XFN(CryptXmlFindAlgorithmInfo));
    const XALGINFO *a = XFN(CryptXmlFindAlgorithmInfo)(X_FIND_URI, U_SHA256, 0, 0);
    const XALGINFO *b = XFN(CryptXmlFindAlgorithmInfo)(X_FIND_URI, L"HTTP://WWW.W3.ORG/2001/04/XMLENC#SHA256", 0, 0);
    const XALGINFO *c = XFN(CryptXmlFindAlgorithmInfo)(X_FIND_URI, L"http://www.w3.org/2001/04/xmlenc#Sha256", 0, 0);
    CHECK(a != NULL);
    EXPECT_EQ(a, b);
    EXPECT_EQ(a, c);
}

TEST(xmlsig_algs_find_by_uri_exact_match_only)
{
    REQUIRE(XFN(CryptXmlFindAlgorithmInfo));
    const WCHAR *no[] = { L"", L"http://www.w3.org/2001/04/xmlenc#sha256 ", L" http://www.w3.org/2001/04/xmlenc#sha256",
                          L"http://www.w3.org/2001/04/xmlenc#sha25", L"http://www.w3.org/2001/04/xmlenc#sha2566", L"sha256",
                          L"http://www.w3.org/2001/04/xmlenc#sha224", U_C14N, U_ENVELOPED, L"urn:cryptt:none" };
    for (int i = 0; i < 10; i++) CHECKF(XFN(CryptXmlFindAlgorithmInfo)(X_FIND_URI, no[i], 0, 0) == NULL, "'%ls' found", no[i]);
}

TEST(xmlsig_algs_find_group_filter)
{
    REQUIRE(XFN(CryptXmlFindAlgorithmInfo));
    CHECK(XFN(CryptXmlFindAlgorithmInfo)(X_FIND_URI, U_SHA256, X_GROUP_HASH, 0) != NULL);
    CHECK(XFN(CryptXmlFindAlgorithmInfo)(X_FIND_URI, U_SHA256, X_GROUP_SIGN, 0) == NULL);
    CHECK(XFN(CryptXmlFindAlgorithmInfo)(X_FIND_URI, U_SHA256, 3, 0) == NULL);
    CHECK(XFN(CryptXmlFindAlgorithmInfo)(X_FIND_URI, U_RSA256, X_GROUP_SIGN, 0) != NULL);
    CHECK(XFN(CryptXmlFindAlgorithmInfo)(X_FIND_URI, U_RSA256, X_GROUP_HASH, 0) == NULL);
    CHECK(XFN(CryptXmlFindAlgorithmInfo)(X_FIND_URI, U_HMAC256, X_GROUP_SIGN, 0) != NULL);
    CHECK(XFN(CryptXmlFindAlgorithmInfo)(X_FIND_URI, U_HMAC256, X_GROUP_HASH, 0) == NULL);
}

TEST(xmlsig_algs_find_invalid_requests)
{
    REQUIRE(XFN(CryptXmlFindAlgorithmInfo));
    CHECK(XFN(CryptXmlFindAlgorithmInfo)(X_FIND_URI, NULL, 0, 0) == NULL);
    CHECK(XFN(CryptXmlFindAlgorithmInfo)(X_FIND_NAME, NULL, 0, 0) == NULL);
    CHECK(XFN(CryptXmlFindAlgorithmInfo)(X_FIND_SIGN_ALGID, NULL, 0, 0) == NULL);
    DWORD bad[] = { 0, 5, 6, 99, 0xffffffff };
    for (int i = 0; i < 5; i++) CHECKF(XFN(CryptXmlFindAlgorithmInfo)(bad[i], U_SHA256, 0, 0) == NULL, "find type %lu matched", bad[i]);
}

TEST(xmlsig_algs_find_by_name)
{
    REQUIRE(XFN(CryptXmlFindAlgorithmInfo));
    const XALGINFO *a = XFN(CryptXmlFindAlgorithmInfo)(X_FIND_NAME, L"RSA-SHA256", 0, 0);
    CHECK(a != NULL);
    if (a) CHECK(!lstrcmpW(a->wszAlgorithmURI, U_RSA256));
    a = XFN(CryptXmlFindAlgorithmInfo)(X_FIND_NAME, L"rsa-sha256", 0, 0);
    CHECK(a != NULL);                                                 /* name comparison ignores case too */
    a = XFN(CryptXmlFindAlgorithmInfo)(X_FIND_NAME, L"SHA384", X_GROUP_HASH, 0);
    CHECK(a != NULL);
    if (a) CHECK(!lstrcmpW(a->wszAlgorithmURI, U_SHA384));
    CHECK(XFN(CryptXmlFindAlgorithmInfo)(X_FIND_NAME, L"SHA384", X_GROUP_SIGN, 0) == NULL);
    a = XFN(CryptXmlFindAlgorithmInfo)(X_FIND_NAME, L"HMAC-SHA512", 0, 0);
    CHECK(a != NULL);
    if (a) CHECK(!lstrcmpW(a->wszAlgorithmURI, U_HMAC512));
    CHECK(XFN(CryptXmlFindAlgorithmInfo)(X_FIND_NAME, L"MD5", 0, 0) == NULL);
}

TEST(xmlsig_algs_find_by_cng_algid)
{
    REQUIRE(XFN(CryptXmlFindAlgorithmInfo));
    /* the CNG id of an entry is its hash algorithm */
    const XALGINFO *a = XFN(CryptXmlFindAlgorithmInfo)(X_FIND_CNG_ALGID, L"SHA256", X_GROUP_HASH, 0);
    CHECK(a != NULL);
    if (a) CHECK(!lstrcmpW(a->wszAlgorithmURI, U_SHA256));
    a = XFN(CryptXmlFindAlgorithmInfo)(X_FIND_CNG_ALGID, L"sha384", X_GROUP_HASH, 0);
    CHECK(a != NULL);
    if (a) CHECK(!lstrcmpW(a->wszAlgorithmURI, U_SHA384));
    a = XFN(CryptXmlFindAlgorithmInfo)(X_FIND_CNG_ALGID, L"SHA256", X_GROUP_SIGN, 0);
    CHECK(a != NULL);
    if (a) { CHECK(a->dwGroupId == 2); CHECK(!lstrcmpW(a->wszCNGAlgid, L"SHA256")); }
    CHECK(XFN(CryptXmlFindAlgorithmInfo)(X_FIND_CNG_ALGID, L"RSA", 0, 0) == NULL);     /* the key algorithm is not the CNG id */
    CHECK(XFN(CryptXmlFindAlgorithmInfo)(X_FIND_CNG_ALGID, L"AES", 0, 0) == NULL);
    CHECK(XFN(CryptXmlFindAlgorithmInfo)(X_FIND_CNG_ALGID, L"SHA256", 3, 0) == NULL);
}

TEST(xmlsig_algs_find_by_sign_algid_pair)
{
    REQUIRE(XFN(CryptXmlFindAlgorithmInfo));
    /* the pair is {hash algorithm, key algorithm} */
    struct { XSIGNALGID p; const WCHAR *uri; } t[] = {
        { { L"SHA1", L"RSA" }, U_RSA1 }, { { L"SHA256", L"RSA" }, U_RSA256 }, { { L"SHA384", L"RSA" }, U_RSA384 },
        { { L"SHA512", L"RSA" }, U_RSA512 }, { { L"SHA1", L"DSA" }, U_DSA1 },
        { { L"SHA1", ECCP }, U_ECDSA1 }, { { L"SHA256", ECCP }, U_ECDSA256 }, { { L"SHA384", ECCP }, U_ECDSA384 }, { { L"SHA512", ECCP }, U_ECDSA512 } };
    for (int i = 0; i < 9; i++) {
        const XALGINFO *a = XFN(CryptXmlFindAlgorithmInfo)(X_FIND_SIGN_ALGID, &t[i].p, 0, 0);
        CHECKF(a != NULL, "pair %ls/%ls", t[i].p.wszCNGAlgid, t[i].p.wszCNGExtraAlgid);
        if (a) CHECK(!lstrcmpW(a->wszAlgorithmURI, t[i].uri));
    }
    XSIGNALGID bad[] = { { L"MD5", L"RSA" }, { L"SHA256", L"DSA" }, { L"RSA", L"SHA256" }, { L"SHA256", L"AES" } };
    for (int i = 0; i < 4; i++) CHECKF(XFN(CryptXmlFindAlgorithmInfo)(X_FIND_SIGN_ALGID, &bad[i], 0, 0) == NULL, "pair %d matched", i);
    XSIGNALGID p5 = { L"SHA256", L"SHA256" };
    t_note("sign-algid lookup of a plain hash pair -> %p", (const void *)XFN(CryptXmlFindAlgorithmInfo)(X_FIND_SIGN_ALGID, &p5, 0, 0));
    XSIGNALGID p6 = { L"SHA256", L"HMAC" };
    t_note("sign-algid lookup of SHA256/HMAC -> %p", (const void *)XFN(CryptXmlFindAlgorithmInfo)(X_FIND_SIGN_ALGID, &p6, 0, 0));
}

TEST(xmlsig_algs_find_returns_stable_table_pointers)
{
    REQUIRE(XFN(CryptXmlFindAlgorithmInfo));
    for (int i = 0; i < 17; i++) {
        const XALGINFO *a = XFN(CryptXmlFindAlgorithmInfo)(X_FIND_URI, ROWS[i].uri, 0, 0);
        const XALGINFO *b = XFN(CryptXmlFindAlgorithmInfo)(X_FIND_URI, ROWS[i].uri, ROWS[i].group, X_FLAG_DISABLE_EXT);
        CHECKF(a != NULL && a == b, "%ls: %p vs %p", ROWS[i].uri, a, b);
    }
}

/* ---- GetAlgorithmInfo ---------------------------------------------------------------------------------- */
TEST(xmlsig_algs_getinfo_null_arguments)
{
    REQUIRE(XFN(CryptXmlGetAlgorithmInfo));
    XALG a = { sizeof a, U_SHA256, {0, 0, NULL} };
    XALGINFO *out = (XALGINFO *)(ULONG_PTR)1;
    XCHK_HR(XFN(CryptXmlGetAlgorithmInfo)(NULL, 0, &out), X_E_INVALIDARG);
    XCHK_HR(XFN(CryptXmlGetAlgorithmInfo)(&a, 0, NULL), X_E_INVALIDARG);
    XCHK_HR(XFN(CryptXmlGetAlgorithmInfo)(NULL, 0, NULL), X_E_INVALIDARG);
}

TEST(xmlsig_algs_getinfo_every_table_entry)
{
    REQUIRE(XFN(CryptXmlGetAlgorithmInfo)); REQUIRE(XFN(CryptXmlFindAlgorithmInfo));
    for (int i = 0; i < 17; i++) {
        XALG a = { sizeof a, ROWS[i].uri, {0, 0, NULL} };
        XALGINFO *out = NULL;
        HRESULT hr = XFN(CryptXmlGetAlgorithmInfo)(&a, 0, &out);
        CHECKF(hr == S_OK, "%ls: hr=0x%08lx", ROWS[i].uri, (unsigned long)hr);
        const XALGINFO *t = XFN(CryptXmlFindAlgorithmInfo)(X_FIND_URI, ROWS[i].uri, 0, 0);
        CHECK(out != NULL);
        if (!out || !t) continue;
        CHECK(out != t);                                   /* a private LocalAlloc copy */
        EXPECT_EQ(out->wszAlgorithmURI, t->wszAlgorithmURI);
        EXPECT_EQ(out->wszName, t->wszName);
        EXPECT_EQ(out->dwGroupId, t->dwGroupId);
        EXPECT_EQ(out->wszCNGAlgid, t->wszCNGAlgid);
        EXPECT_EQ(out->wszCNGExtraAlgid, t->wszCNGExtraAlgid);
        EXPECT_EQ(out->dwSignFlags, t->dwSignFlags);
        EXPECT_EQ(out->dwVerifyFlags, t->dwVerifyFlags);
        EXPECT_EQ(out->pvPaddingInfo, t->pvPaddingInfo);
        EXPECT_EQ(out->pvExtraInfo, t->pvExtraInfo);
        EXPECT_EQ(out->cbSize, t->cbSize);
        CHECK(LocalSize((HLOCAL)out) >= 0x48);            /* allocated with LocalAlloc, 0x48 bytes */
        CHECK(LocalFree((HLOCAL)out) == NULL);
    }
}

TEST(xmlsig_algs_getinfo_unknown_algorithms)
{
    REQUIRE(XFN(CryptXmlGetAlgorithmInfo));
    const WCHAR *no[] = { U_C14N, U_C14N_C, U_EXC, U_ENVELOPED, L"", L"urn:cryptt:none", L"http://www.w3.org/2001/04/xmlenc#sha224",
                          L"http://www.w3.org/2001/04/xmlenc#sha256x" };
    for (int i = 0; i < 8; i++) {
        XALG a = { sizeof a, no[i], {0, 0, NULL} };
        XALGINFO *out = (XALGINFO *)(ULONG_PTR)1;
        HRESULT hr = XFN(CryptXmlGetAlgorithmInfo)(&a, 0, &out);
        CHECKF(hr == X_E_ALGORITHM, "'%ls': hr=0x%08lx", no[i], (unsigned long)hr);
        CHECK(out == NULL);
    }
}

TEST(xmlsig_algs_getinfo_case_insensitive)
{
    REQUIRE(XFN(CryptXmlGetAlgorithmInfo));
    XALG a = { sizeof a, L"HTTP://WWW.W3.ORG/2000/09/XMLDSIG#HMAC-SHA1", {0, 0, NULL} };
    XALGINFO *out = NULL;
    XCHK_HR(XFN(CryptXmlGetAlgorithmInfo)(&a, 0, &out), S_OK);
    if (out) { CHECK(!lstrcmpW(out->wszAlgorithmURI, U_HMAC1)); LocalFree((HLOCAL)out); }
}

TEST(xmlsig_algs_getinfo_ignores_input_size_and_encoded_blob)
{
    REQUIRE(XFN(CryptXmlGetAlgorithmInfo));
    static BYTE junk[4] = { 1, 2, 3, 4 };
    XALG a = { 0, U_SHA1, { 1, 4, junk } };
    XALGINFO *out = NULL;
    XCHK_HR(XFN(CryptXmlGetAlgorithmInfo)(&a, 0, &out), S_OK);
    if (out) LocalFree((HLOCAL)out);
    a.cbSize = 0x7fffffff;
    out = NULL;
    XCHK_HR(XFN(CryptXmlGetAlgorithmInfo)(&a, X_FLAG_DISABLE_EXT, &out), S_OK);
    if (out) LocalFree((HLOCAL)out);
}

TEST(xmlsig_algs_getinfo_each_call_allocates)
{
    REQUIRE(XFN(CryptXmlGetAlgorithmInfo));
    XALG a = { sizeof a, U_RSA256, {0, 0, NULL} };
    XALGINFO *p = NULL, *q = NULL;
    XCHK_HR(XFN(CryptXmlGetAlgorithmInfo)(&a, 0, &p), S_OK);
    XCHK_HR(XFN(CryptXmlGetAlgorithmInfo)(&a, 0, &q), S_OK);
    CHECK(p != NULL && q != NULL && p != q);
    if (p) LocalFree((HLOCAL)p);
    if (q) LocalFree((HLOCAL)q);
}
