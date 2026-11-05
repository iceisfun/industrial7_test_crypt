/* CryptFindOIDInfo / CertAlgIdToOID / CertOIDToAlgId against the shipped Windows 10 OID table. */
#include "fw.h"
#include "oidtab.h"

static int hexval(char c) { return c <= '9' ? c - '0' : (c | 32) - 'a' + 10; }
static unsigned extra_len(const OIDROW *r) { return (unsigned)strlen(r->extra) / 2; }
static unsigned extra_dw0(const OIDROW *r) {
    unsigned v = 0;
    for (int i = 3; i >= 0; i--) v = (v << 8) | (hexval(r->extra[i * 2]) << 4) | hexval(r->extra[i * 2 + 1]);
    return v;
}
static const OIDROW *first_oid(int g, const char *oid) {
    for (size_t i = 0; i < NROWS; i++) if (g_rows[i].grp == g && !strcmp(g_rows[i].oid, oid)) return &g_rows[i];
    return NULL;
}
static const OIDROW *first_name(int g, const wchar_t *nm) {
    for (size_t i = 0; i < NROWS; i++) if (g_rows[i].grp == g && g_rows[i].name && !wcscmp(g_rows[i].name, nm)) return &g_rows[i];
    return NULL;
}
static const OIDROW *first_val(int g, unsigned v) {
    for (size_t i = 0; i < NROWS; i++) if (g_rows[i].grp == g && g_rows[i].val == v) return &g_rows[i];
    return NULL;
}
/* Algids a clean Windows 10 registry (searched before the static table) reports for CNG-only static entries. */
static unsigned alt_algid(const OIDROW *r) {
    static const struct { const wchar_t *n; unsigned v; } m[] = {
        {L"sha256", 0x800c}, {L"sha384", 0x800d}, {L"sha512", 0x800e},
        {L"sha256NoSign", 0x800c}, {L"sha384NoSign", 0x800d}, {L"sha512NoSign", 0x800e},
        {L"sha256RSA", 0x800c}, {L"sha384RSA", 0x800d}, {L"sha512RSA", 0x800e},
        {L"sha1ECDSA", 0x8004}, {L"sha256ECDSA", 0x800c}, {L"sha384ECDSA", 0x800d}, {L"sha512ECDSA", 0x800e},
        {L"aes128", 0x660e}, {L"aes192", 0x660f}, {L"aes256", 0x6610},
        {L"aes128wrap", 0x660e}, {L"aes192wrap", 0x660f}, {L"aes256wrap", 0x6610},
    };
    if (!r->name) return 0;
    for (size_t i = 0; i < sizeof m / sizeof m[0]; i++) if (!wcscmp(r->name, m[i].n)) return m[i].v;
    return 0;
}
static int value_ok(const OIDROW *r, DWORD v) {
    if (r->val < 0xfffffffeu) return v == r->val;
    unsigned a = alt_algid(r);
    if (a && v == a) return 1;
    return v == r->val || a == 0; /* no alternative known: do not judge */
}
/* Full structural comparison of a returned entry against a table row. */
static void check_info(const CRYPT_OID_INFO *p, const OIDROW *r) {
    if (!p) { CHECKF(0, "null info for %s", r->oid); return; }
    EXPECT_EQ(p->cbSize, sizeof(CRYPT_OID_INFO));
    CHECK(p->dwGroupId == (DWORD)r->grp);
    CHECKF(p->pszOID && !strcmp(p->pszOID, r->oid), "oid %s", r->oid);
    if (r->name) CHECKF(p->pwszName && !wcscmp(p->pwszName, r->name), "name of %s", r->oid);
    else CHECKF(p->pwszName && p->pwszName[0] && p->pwszName[0] != L'#', "localized name of %s", r->oid);
    if (r->grp <= 4) CHECKF(value_ok(r, p->dwValue), "value of %s: got 0x%lx static 0x%x", r->oid, p->dwValue, r->val);
    unsigned xl = extra_len(r);
    if (xl >= 4 && (r->grp == OIDG_SIGN || r->grp == OIDG_RDN)) {
        CHECKF(p->ExtraInfo.cbData == xl &&
               p->ExtraInfo.pbData && *(DWORD *)p->ExtraInfo.pbData == extra_dw0(r), "extra of %s", r->oid);
    } else if (xl >= 4 && r->grp <= 3) {
        CHECKF(p->ExtraInfo.cbData >= 4 && p->ExtraInfo.pbData && *(DWORD *)p->ExtraInfo.pbData == extra_dw0(r), "extra dw0 of %s", r->oid);
    }
    if (r->cng && r->cng[0] && p->pwszCNGAlgid) CHECKF(!wcscmp(p->pwszCNGAlgid, r->cng), "cng of %s", r->oid);
    if (r->cngx && r->cngx[0] && p->pwszCNGExtraAlgid) CHECKF(!wcscmp(p->pwszCNGExtraAlgid, r->cngx), "cngx of %s", r->oid);
}

static void by_oid_group(int g) {
    REQUIRE(U(CryptFindOIDInfo));
    int n = 0;
    for (size_t i = 0; i < NROWS; i++) {
        if (g_rows[i].grp != g || first_oid(g, g_rows[i].oid) != &g_rows[i]) continue;
        PCCRYPT_OID_INFO p = U(CryptFindOIDInfo)(CRYPT_OID_INFO_OID_KEY, (void *)g_rows[i].oid, g);
        check_info(p, &g_rows[i]);
        n++;
    }
    CHECK(n > 0);
}
TEST(oidfind_oid_key_hash)    { by_oid_group(OIDG_HASH); }
TEST(oidfind_oid_key_encrypt) { by_oid_group(OIDG_ENCRYPT); }
TEST(oidfind_oid_key_pubkey)  { by_oid_group(OIDG_PUBKEY); }
TEST(oidfind_oid_key_sign)    { by_oid_group(OIDG_SIGN); }
TEST(oidfind_oid_key_rdn)     { by_oid_group(OIDG_RDN); }
TEST(oidfind_oid_key_ext)     { by_oid_group(OIDG_EXT); }
TEST(oidfind_oid_key_enhkey)  { by_oid_group(OIDG_ENHKEY); }
TEST(oidfind_oid_key_policy)  { by_oid_group(OIDG_POLICY); }
TEST(oidfind_oid_key_kdf)     { by_oid_group(OIDG_KDF); }

static void by_name_group(int g) {
    REQUIRE(U(CryptFindOIDInfo));
    int n = 0;
    for (size_t i = 0; i < NROWS; i++) {
        const OIDROW *r = &g_rows[i];
        if (r->grp != g || !r->name || first_name(g, r->name) != r) continue;
        PCCRYPT_OID_INFO p = U(CryptFindOIDInfo)(CRYPT_OID_INFO_NAME_KEY, (void *)r->name, g);
        check_info(p, r);
        n++;
    }
    CHECK(n > 0);
}
TEST(oidfind_name_key_hash)    { by_name_group(OIDG_HASH); }
TEST(oidfind_name_key_encrypt) { by_name_group(OIDG_ENCRYPT); }
TEST(oidfind_name_key_pubkey)  { by_name_group(OIDG_PUBKEY); }
TEST(oidfind_name_key_sign)    { by_name_group(OIDG_SIGN); }
TEST(oidfind_name_key_rdn)     { by_name_group(OIDG_RDN); }
TEST(oidfind_name_key_kdf)     { by_name_group(OIDG_KDF); }

TEST(oidfind_name_key_case_insensitive) {
    REQUIRE(U(CryptFindOIDInfo));
    for (size_t i = 0; i < NROWS; i++) {
        const OIDROW *r = &g_rows[i];
        if (r->grp > 5 && r->grp != 10) continue;
        if (!r->name || first_name(r->grp, r->name) != r) continue;
        wchar_t f[80]; fw_flip_w(f, r->name);
        PCCRYPT_OID_INFO p = U(CryptFindOIDInfo)(CRYPT_OID_INFO_NAME_KEY, f, r->grp);
        CHECKF(p && !strcmp(p->pszOID, r->oid), "case-flipped name %ls", f);
    }
}
TEST(oidfind_oid_key_unknown_returns_null) {
    REQUIRE(U(CryptFindOIDInfo));
    for (int g = 0; g <= 10; g++) {
        PCCRYPT_OID_INFO p = U(CryptFindOIDInfo)(CRYPT_OID_INFO_OID_KEY, (void *)"1.2.3.4.5.6.7.8.9.99999", g | NODS);
        CHECKF(p == NULL, "group %d", g);
    }
}
TEST(oidfind_name_key_unknown_returns_null) {
    REQUIRE(U(CryptFindOIDInfo));
    CHECK(U(CryptFindOIDInfo)(CRYPT_OID_INFO_NAME_KEY, (void *)L"cryptt-no-such-name", 0 | NODS) == NULL);
    CHECK(U(CryptFindOIDInfo)(CRYPT_OID_INFO_NAME_KEY, (void *)L"", OIDG_HASH | NODS) == NULL);
}
TEST(oidfind_oid_key_wrong_group_is_not_found) {
    REQUIRE(U(CryptFindOIDInfo));
    /* a hash OID is not an encryption or RDN OID */
    CHECK(U(CryptFindOIDInfo)(CRYPT_OID_INFO_OID_KEY, (void *)"1.3.14.3.2.26", OIDG_ENCRYPT | NODS) == NULL);
    CHECK(U(CryptFindOIDInfo)(CRYPT_OID_INFO_OID_KEY, (void *)"1.3.14.3.2.26", OIDG_RDN | NODS) == NULL);
    CHECK(U(CryptFindOIDInfo)(CRYPT_OID_INFO_OID_KEY, (void *)"2.5.4.3", OIDG_HASH | NODS) == NULL);
}
TEST(oidfind_group_out_of_range_not_found) {
    REQUIRE(U(CryptFindOIDInfo));
    for (DWORD g = 11; g < 20; g++)
        CHECKF(U(CryptFindOIDInfo)(CRYPT_OID_INFO_OID_KEY, (void *)"1.3.14.3.2.26", g | NODS) == NULL, "group %lu", g);
}
TEST(oidfind_template_group_has_no_builtin) {
    REQUIRE(U(CryptFindOIDInfo));
    CHECK(U(CryptFindOIDInfo)(CRYPT_OID_INFO_OID_KEY, (void *)"1.3.6.1.4.1.311.21.8.1.2.3", CRYPT_TEMPLATE_OID_GROUP_ID | NODS) == NULL);
}

TEST(oidfind_any_group_oid_resolves_to_first_group) {
    REQUIRE(U(CryptFindOIDInfo));
    static const struct { const char *oid; int g; } t[] = {
        {"1.3.14.3.2.26", OIDG_HASH}, {"1.2.840.113549.2.5", OIDG_HASH}, {"1.3.14.3.2.7", OIDG_ENCRYPT},
        {"1.2.840.113549.3.7", OIDG_ENCRYPT}, {"1.2.840.10040.4.1", OIDG_PUBKEY}, {"1.2.840.113549.1.1.5", OIDG_SIGN},
        {"2.5.4.3", OIDG_RDN}, {"1.3.6.1.5.5.7.3.1", OIDG_ENHKEY}, {"2.5.29.19", OIDG_EXT}, {"2.5.29.32.0", OIDG_POLICY},
        {"1.3.132.1.11.1", OIDG_KDF},
    };
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
        PCCRYPT_OID_INFO p = U(CryptFindOIDInfo)(CRYPT_OID_INFO_OID_KEY, (void *)t[i].oid, 0);
        CHECKF(p && p->dwGroupId == (DWORD)t[i].g, "%s", t[i].oid);
    }
}
TEST(oidfind_shared_oid_hash_and_rsa_groups) {
    REQUIRE(U(CryptFindOIDInfo));
    /* the same OID value appears in several groups; the group id selects the entry */
    PCCRYPT_OID_INFO h = U(CryptFindOIDInfo)(CRYPT_OID_INFO_OID_KEY, (void *)"1.3.14.3.2.26", OIDG_HASH);
    PCCRYPT_OID_INFO s = U(CryptFindOIDInfo)(CRYPT_OID_INFO_OID_KEY, (void *)"1.3.14.3.2.26", OIDG_SIGN);
    CHECK(h && s && h != s);
    if (h) { CHECK(!wcscmp(h->pwszName, L"sha1")); CHECK(h->dwGroupId == OIDG_HASH); }
    if (s) { CHECK(!wcscmp(s->pwszName, L"sha1NoSign")); CHECK(s->dwGroupId == OIDG_SIGN); }
    PCCRYPT_OID_INFO a = U(CryptFindOIDInfo)(CRYPT_OID_INFO_OID_KEY, (void *)"1.2.840.113549.1.1.10", OIDG_PUBKEY);
    PCCRYPT_OID_INFO b = U(CryptFindOIDInfo)(CRYPT_OID_INFO_OID_KEY, (void *)"1.2.840.113549.1.1.10", OIDG_SIGN);
    CHECK(a && b);
    if (a) CHECK(a->dwGroupId == OIDG_PUBKEY);
    if (b) CHECK(b->dwGroupId == OIDG_SIGN);
}
TEST(oidfind_returns_stable_pointers) {
    REQUIRE(U(CryptFindOIDInfo));
    PCCRYPT_OID_INFO a = U(CryptFindOIDInfo)(CRYPT_OID_INFO_OID_KEY, (void *)"1.3.14.3.2.26", OIDG_HASH);
    PCCRYPT_OID_INFO b = U(CryptFindOIDInfo)(CRYPT_OID_INFO_NAME_KEY, (void *)L"sha1", OIDG_HASH);
    PCCRYPT_OID_INFO c = U(CryptFindOIDInfo)(CRYPT_OID_INFO_ALGID_KEY, &(ALG_ID){CALG_SHA1}, OIDG_HASH);
    CHECK(a != NULL);
    CHECK(a == b);
    CHECK(a == c);
}

/* ---- ALGID_KEY ---- */
static void by_algid_group(int g) {
    REQUIRE(U(CryptFindOIDInfo));
    int n = 0;
    for (size_t i = 0; i < NROWS; i++) {
        const OIDROW *r = &g_rows[i];
        if (r->grp != g || r->val >= 0xfffffffeu || first_val(g, r->val) != r) continue;
        ALG_ID k = r->val;
        PCCRYPT_OID_INFO p = U(CryptFindOIDInfo)(CRYPT_OID_INFO_ALGID_KEY, &k, g);
        check_info(p, r);
        n++;
    }
    CHECK(n > 0);
}
TEST(oidfind_algid_key_hash)    { by_algid_group(OIDG_HASH); }
TEST(oidfind_algid_key_encrypt) { by_algid_group(OIDG_ENCRYPT); }
TEST(oidfind_algid_key_pubkey)  { by_algid_group(OIDG_PUBKEY); }
TEST(oidfind_algid_key_sign)    { by_algid_group(OIDG_SIGN); }

TEST(oidfind_algid_key_any_group) {
    REQUIRE(U(CryptFindOIDInfo));
    static const struct { ALG_ID a; const char *oid; int g; } t[] = {
        {CALG_SHA1, "1.3.14.3.2.26", 1}, {CALG_MD5, "1.2.840.113549.2.5", 1}, {CALG_MD2, "1.2.840.113549.2.2", 1},
        {CALG_MD4, "1.2.840.113549.2.4", 1}, {CALG_DES, "1.3.14.3.2.7", 2}, {CALG_3DES, "1.2.840.113549.3.7", 2},
        {CALG_RC2, "1.2.840.113549.3.2", 2}, {CALG_RC4, "1.2.840.113549.3.4", 2}, {CALG_RSA_KEYX, "1.2.840.113549.1.1.1", 3},
        {CALG_DSS_SIGN, "1.2.840.10040.4.1", 3}, {CALG_DH_SF, "1.2.840.10046.2.1", 3},
    };
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
        ALG_ID k = t[i].a;
        PCCRYPT_OID_INFO p = U(CryptFindOIDInfo)(CRYPT_OID_INFO_ALGID_KEY, &k, 0);
        CHECKF(p && !strcmp(p->pszOID, t[i].oid) && p->dwGroupId == (DWORD)t[i].g && p->Algid == t[i].a, "algid 0x%x", t[i].a);
    }
}
TEST(oidfind_algid_key_unknown) {
    REQUIRE(U(CryptFindOIDInfo));
    ALG_ID k = 0x0000ABCD;
    for (int g = 0; g <= 4; g++) CHECKF(U(CryptFindOIDInfo)(CRYPT_OID_INFO_ALGID_KEY, &k, g | NODS) == NULL, "group %d", g);
}
TEST(oidfind_algid_key_hash_alg_selects_sign_oid_in_sign_group) {
    REQUIRE(U(CryptFindOIDInfo));
    ALG_ID k = CALG_MD5;
    PCCRYPT_OID_INFO p = U(CryptFindOIDInfo)(CRYPT_OID_INFO_ALGID_KEY, &k, OIDG_SIGN);
    CHECK(p && p->dwGroupId == OIDG_SIGN && p->Algid == CALG_MD5);
    ALG_ID k2 = CALG_SHA1;
    p = U(CryptFindOIDInfo)(CRYPT_OID_INFO_ALGID_KEY, &k2, OIDG_SIGN);
    CHECK(p && p->Algid == CALG_SHA1 && !strcmp(p->pszOID, "1.2.840.113549.1.1.5"));
}

/* ---- SIGN_KEY ---- */
TEST(oidfind_sign_key_pairs) {
    REQUIRE(U(CryptFindOIDInfo));
    static const struct { ALG_ID h, pk; const char *oid; const wchar_t *name; } t[] = {
        {CALG_SHA1, CALG_RSA_SIGN, "1.2.840.113549.1.1.5", L"sha1RSA"},
        {CALG_MD5, CALG_RSA_SIGN, "1.2.840.113549.1.1.4", L"md5RSA"},
        {CALG_MD2, CALG_RSA_SIGN, "1.2.840.113549.1.1.2", L"md2RSA"},
        {CALG_MD4, CALG_RSA_SIGN, "1.2.840.113549.1.1.3", L"md4RSA"},
        {CALG_SHA1, CALG_DSS_SIGN, "1.2.840.10040.4.3", L"sha1DSA"},
    };
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
        ALG_ID k[2] = {t[i].h, t[i].pk};
        PCCRYPT_OID_INFO p = U(CryptFindOIDInfo)(CRYPT_OID_INFO_SIGN_KEY, k, OIDG_SIGN);
        CHECKF(p && !strcmp(p->pszOID, t[i].oid) && !wcscmp(p->pwszName, t[i].name), "pair %zu", i);
        if (p) { CHECK(p->Algid == t[i].h); CHECK(p->ExtraInfo.cbData >= 4 && *(DWORD *)p->ExtraInfo.pbData == t[i].pk); }
    }
}
TEST(oidfind_sign_key_mismatched_pair_not_found) {
    REQUIRE(U(CryptFindOIDInfo));
    ALG_ID k[2] = {CALG_MD5, CALG_DSS_SIGN};
    CHECK(U(CryptFindOIDInfo)(CRYPT_OID_INFO_SIGN_KEY, k, OIDG_SIGN | NODS) == NULL);
    ALG_ID k2[2] = {CALG_SHA1, 0x1234};
    CHECK(U(CryptFindOIDInfo)(CRYPT_OID_INFO_SIGN_KEY, k2, OIDG_SIGN | NODS) == NULL);
}
TEST(oidfind_sign_key_all_static_pairs) {
    REQUIRE(U(CryptFindOIDInfo));
    for (size_t i = 0; i < NROWS; i++) {
        const OIDROW *r = &g_rows[i];
        if (r->grp != OIDG_SIGN || r->val >= 0xfffffffeu || extra_len(r) < 4) continue;
        ALG_ID k[2] = {r->val, extra_dw0(r)};
        PCCRYPT_OID_INFO p = U(CryptFindOIDInfo)(CRYPT_OID_INFO_SIGN_KEY, k, OIDG_SIGN);
        CHECKF(p && p->Algid == k[0] && *(DWORD *)p->ExtraInfo.pbData == k[1], "row %zu %s", i, r->oid);
    }
}

/* ---- CNG keys ---- */
TEST(oidfind_cng_algid_key_hash) {
    REQUIRE(U(CryptFindOIDInfo));
    static const struct { const wchar_t *cng; const char *oid; } t[] = {
        {L"SHA1", "1.3.14.3.2.26"}, {L"MD5", "1.2.840.113549.2.5"}, {L"MD4", "1.2.840.113549.2.4"}, {L"MD2", "1.2.840.113549.2.2"},
        {L"SHA256", "2.16.840.1.101.3.4.2.1"}, {L"SHA384", "2.16.840.1.101.3.4.2.2"}, {L"SHA512", "2.16.840.1.101.3.4.2.3"},
    };
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
        PCCRYPT_OID_INFO p = U(CryptFindOIDInfo)(CRYPT_OID_INFO_CNG_ALGID_KEY, (void *)t[i].cng, OIDG_HASH);
        CHECKF(p && !strcmp(p->pszOID, t[i].oid), "%ls", t[i].cng);
    }
}
TEST(oidfind_cng_algid_key_case_insensitive) {
    REQUIRE(U(CryptFindOIDInfo));
    PCCRYPT_OID_INFO p = U(CryptFindOIDInfo)(CRYPT_OID_INFO_CNG_ALGID_KEY, (void *)L"sha256", OIDG_HASH);
    CHECK(p && !strcmp(p->pszOID, "2.16.840.1.101.3.4.2.1"));
    p = U(CryptFindOIDInfo)(CRYPT_OID_INFO_CNG_ALGID_KEY, (void *)L"Sha512", OIDG_HASH);
    CHECK(p && !strcmp(p->pszOID, "2.16.840.1.101.3.4.2.3"));
}
TEST(oidfind_cng_algid_key_encrypt_and_pubkey) {
    REQUIRE(U(CryptFindOIDInfo));
    PCCRYPT_OID_INFO p = U(CryptFindOIDInfo)(CRYPT_OID_INFO_CNG_ALGID_KEY, (void *)L"3DES", OIDG_ENCRYPT);
    CHECK(p && !strcmp(p->pszOID, "1.2.840.113549.3.7"));
    p = U(CryptFindOIDInfo)(CRYPT_OID_INFO_CNG_ALGID_KEY, (void *)L"RC4", OIDG_ENCRYPT | NODS);
    t_note("CNG algid RC4 in encrypt group: %s", p ? p->pszOID : "(none)");
    p = U(CryptFindOIDInfo)(CRYPT_OID_INFO_CNG_ALGID_KEY, (void *)L"DSA", OIDG_PUBKEY);
    CHECK(p && !strcmp(p->pszOID, "1.2.840.10040.4.1"));
    p = U(CryptFindOIDInfo)(CRYPT_OID_INFO_CNG_ALGID_KEY, (void *)L"RSA", OIDG_PUBKEY);
    CHECK(p && !strcmp(p->pszOID, "1.2.840.113549.1.1.1"));
    p = U(CryptFindOIDInfo)(CRYPT_OID_INFO_CNG_ALGID_KEY, (void *)L"DH", OIDG_PUBKEY);
    CHECK(p && !strcmp(p->pszOID, "1.2.840.10046.2.1"));
}
TEST(oidfind_cng_algid_key_unknown) {
    REQUIRE(U(CryptFindOIDInfo));
    CHECK(U(CryptFindOIDInfo)(CRYPT_OID_INFO_CNG_ALGID_KEY, (void *)L"NOSUCHALG", 0 | NODS) == NULL);
}
TEST(oidfind_cng_sign_key_pairs) {
    REQUIRE(U(CryptFindOIDInfo));
    static const struct { const wchar_t *h, *s; const char *oid; } t[] = {
        {L"SHA256", L"RSA", "1.2.840.113549.1.1.11"}, {L"SHA384", L"RSA", "1.2.840.113549.1.1.12"},
        {L"SHA512", L"RSA", "1.2.840.113549.1.1.13"}, {L"SHA1", L"RSA", "1.2.840.113549.1.1.5"},
        {L"MD5", L"RSA", "1.2.840.113549.1.1.4"}, {L"SHA1", L"DSA", "1.2.840.10040.4.3"},
        {L"SHA1", L"CryptOIDInfoECCParameters", "1.2.840.10045.4.1"},
        {L"SHA256", L"CryptOIDInfoECCParameters", "1.2.840.10045.4.3.2"},
        {L"SHA384", L"CryptOIDInfoECCParameters", "1.2.840.10045.4.3.3"},
        {L"SHA512", L"CryptOIDInfoECCParameters", "1.2.840.10045.4.3.4"},
    };
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
        struct { const wchar_t *a, *b; } k = {t[i].h, t[i].s};
        PCCRYPT_OID_INFO p = U(CryptFindOIDInfo)(CRYPT_OID_INFO_CNG_SIGN_KEY, &k, OIDG_SIGN);
        CHECKF(p && !strcmp(p->pszOID, t[i].oid), "%ls/%ls", t[i].h, t[i].s);
    }
}
TEST(oidfind_cng_sign_key_mismatch) {
    REQUIRE(U(CryptFindOIDInfo));
    struct { const wchar_t *a, *b; } k = {L"SHA256", L"DSA"};
    CHECK(U(CryptFindOIDInfo)(CRYPT_OID_INFO_CNG_SIGN_KEY, &k, OIDG_SIGN | NODS) == NULL);
}

/* ---- pubkey encrypt / sign flags and ECC ---- */
TEST(oidfind_pubkey_sign_flag_picks_ecdsa) {
    REQUIRE(U(CryptFindOIDInfo));
    PCCRYPT_OID_INFO p = U(CryptFindOIDInfo)(CRYPT_OID_INFO_OID_KEY | CRYPT_OID_INFO_PUBKEY_SIGN_KEY_FLAG, (void *)"1.2.840.10045.3.1.7", OIDG_PUBKEY);
    CHECK(p != NULL);
    if (p) { CHECK(p->pwszCNGAlgid && !wcscmp(p->pwszCNGAlgid, L"ECDSA_P256")); CHECK(p->dwGroupId == OIDG_PUBKEY); }
}
TEST(oidfind_pubkey_encrypt_flag_picks_ecdh) {
    REQUIRE(U(CryptFindOIDInfo));
    PCCRYPT_OID_INFO p = U(CryptFindOIDInfo)(CRYPT_OID_INFO_OID_KEY | CRYPT_OID_INFO_PUBKEY_ENCRYPT_KEY_FLAG, (void *)"1.2.840.10045.3.1.7", OIDG_PUBKEY);
    CHECK(p != NULL);
    if (p) CHECK(p->pwszCNGAlgid && !wcscmp(p->pwszCNGAlgid, L"ECDH_P256"));
}
TEST(oidfind_pubkey_flags_p384_p521) {
    REQUIRE(U(CryptFindOIDInfo));
    static const struct { const char *oid; const wchar_t *sig, *enc; } t[] = {
        {"1.3.132.0.34", L"ECDSA_P384", L"ECDH_P384"}, {"1.3.132.0.35", L"ECDSA_P521", L"ECDH_P521"},
    };
    for (size_t i = 0; i < 2; i++) {
        PCCRYPT_OID_INFO s = U(CryptFindOIDInfo)(CRYPT_OID_INFO_OID_KEY | CRYPT_OID_INFO_PUBKEY_SIGN_KEY_FLAG, (void *)t[i].oid, OIDG_PUBKEY);
        PCCRYPT_OID_INFO e = U(CryptFindOIDInfo)(CRYPT_OID_INFO_OID_KEY | CRYPT_OID_INFO_PUBKEY_ENCRYPT_KEY_FLAG, (void *)t[i].oid, OIDG_PUBKEY);
        CHECK(s && s->pwszCNGAlgid && !wcscmp(s->pwszCNGAlgid, t[i].sig));
        CHECK(e && e->pwszCNGAlgid && !wcscmp(e->pwszCNGAlgid, t[i].enc));
        CHECK(s != e);
    }
}
TEST(oidfind_pubkey_cng_key_with_flags) {
    REQUIRE(U(CryptFindOIDInfo));
    PCCRYPT_OID_INFO p = U(CryptFindOIDInfo)(CRYPT_OID_INFO_CNG_ALGID_KEY | CRYPT_OID_INFO_PUBKEY_ENCRYPT_KEY_FLAG, (void *)L"ECDH_P256", OIDG_PUBKEY);
    CHECK(p && !strcmp(p->pszOID, "1.2.840.10045.3.1.7"));
    p = U(CryptFindOIDInfo)(CRYPT_OID_INFO_CNG_ALGID_KEY | CRYPT_OID_INFO_PUBKEY_SIGN_KEY_FLAG, (void *)L"ECDSA_P384", OIDG_PUBKEY);
    CHECK(p && !strcmp(p->pszOID, "1.3.132.0.34"));
}
TEST(oidfind_pubkey_sign_flag_rejects_ecdh_name) {
    REQUIRE(U(CryptFindOIDInfo));
    PCCRYPT_OID_INFO p = U(CryptFindOIDInfo)(CRYPT_OID_INFO_CNG_ALGID_KEY | CRYPT_OID_INFO_PUBKEY_SIGN_KEY_FLAG, (void *)L"ECDH_P256", OIDG_PUBKEY | NODS);
    CHECK(p == NULL);
}
TEST(oidfind_ecc_public_key_oid) {
    REQUIRE(U(CryptFindOIDInfo));
    PCCRYPT_OID_INFO p = U(CryptFindOIDInfo)(CRYPT_OID_INFO_OID_KEY, (void *)"1.2.840.10045.2.1", OIDG_PUBKEY);
    CHECK(p != NULL);
    if (p) { CHECK(p->Algid == CALG_OID_INFO_PARAMETERS); CHECK(!wcscmp(p->pwszName, L"ECC")); }
}
TEST(oidfind_special_algid_constants) {
    REQUIRE(U(CryptFindOIDInfo));
    PCCRYPT_OID_INFO p = U(CryptFindOIDInfo)(CRYPT_OID_INFO_OID_KEY, (void *)"1.2.840.113549.1.1.8", OIDG_HASH);
    CHECK(p && p->Algid == CALG_OID_INFO_PARAMETERS && p->pwszCNGAlgid && !wcscmp(p->pwszCNGAlgid, CRYPT_OID_INFO_MGF1_PARAMETERS_ALGORITHM));
    p = U(CryptFindOIDInfo)(CRYPT_OID_INFO_OID_KEY, (void *)"1.3.6.1.5.5.7.6.2", OIDG_PUBKEY);
    CHECK(p && p->Algid == CALG_NO_SIGN && p->pwszCNGAlgid && !wcscmp(p->pwszCNGAlgid, CRYPT_OID_INFO_NO_SIGN_ALGORITHM));
    p = U(CryptFindOIDInfo)(CRYPT_OID_INFO_OID_KEY, (void *)"1.2.840.113549.1.1.7", OIDG_PUBKEY);
    CHECK(p && p->Algid == CALG_OID_INFO_PARAMETERS && p->pwszCNGAlgid && !wcscmp(p->pwszCNGAlgid, CRYPT_OID_INFO_OAEP_PARAMETERS_ALGORITHM));
}

/* ---- encrypt group bit length filter ---- */
TEST(oidfind_encrypt_bitlength_filter_matches) {
    REQUIRE(U(CryptFindOIDInfo));
    static const struct { const char *oid; DWORD bits; } t[] = {
        {"2.16.840.1.101.3.4.1.2", 128}, {"2.16.840.1.101.3.4.1.22", 192}, {"2.16.840.1.101.3.4.1.42", 256},
    };
    for (size_t i = 0; i < 3; i++) {
        PCCRYPT_OID_INFO p = U(CryptFindOIDInfo)(CRYPT_OID_INFO_OID_KEY, (void *)t[i].oid, OIDG_ENCRYPT | (t[i].bits << 16));
        CHECKF(p && !strcmp(p->pszOID, t[i].oid), "bits %lu", t[i].bits);
        if (p) CHECK(p->ExtraInfo.cbData >= 4 && *(DWORD *)p->ExtraInfo.pbData == t[i].bits);
    }
}
TEST(oidfind_encrypt_bitlength_filter_mismatch) {
    REQUIRE(U(CryptFindOIDInfo));
    CHECK(U(CryptFindOIDInfo)(CRYPT_OID_INFO_OID_KEY, (void *)"2.16.840.1.101.3.4.1.2", OIDG_ENCRYPT | (256u << 16) | NODS) == NULL);
    CHECK(U(CryptFindOIDInfo)(CRYPT_OID_INFO_OID_KEY, (void *)"2.16.840.1.101.3.4.1.42", OIDG_ENCRYPT | (128u << 16) | NODS) == NULL);
    CHECK(U(CryptFindOIDInfo)(CRYPT_OID_INFO_OID_KEY, (void *)"2.16.840.1.101.3.4.1.22", OIDG_ENCRYPT | (1u << 16) | NODS) == NULL);
}
TEST(oidfind_encrypt_bitlength_by_name) {
    REQUIRE(U(CryptFindOIDInfo));
    PCCRYPT_OID_INFO p = U(CryptFindOIDInfo)(CRYPT_OID_INFO_NAME_KEY, (void *)L"aes256", OIDG_ENCRYPT | (256u << 16));
    CHECK(p && !strcmp(p->pszOID, "2.16.840.1.101.3.4.1.42"));
    p = U(CryptFindOIDInfo)(CRYPT_OID_INFO_NAME_KEY, (void *)L"aes256", OIDG_ENCRYPT | (128u << 16) | NODS);
    CHECK(p == NULL);
}

/* ---- CNG preference flag ---- */
TEST(oidfind_prefer_cng_flag_oid_key) {
    REQUIRE(U(CryptFindOIDInfo));
    /* with the flag the first entry that carries a CNG algorithm name is returned */
    for (int g = 1; g <= 4; g++) {
        PCCRYPT_OID_INFO p = U(CryptFindOIDInfo)(CRYPT_OID_INFO_OID_KEY, (void *)"1.3.14.3.2.26", g | CRYPT_OID_PREFER_CNG_ALGID_FLAG | NODS);
        if (g == 1 || g == 4) CHECKF(p && p->pwszCNGAlgid && p->pwszCNGAlgid[0], "group %d", g);
        else CHECKF(p == NULL, "group %d", g);
    }
}
TEST(oidfind_prefer_cng_flag_any_group_sha1) {
    REQUIRE(U(CryptFindOIDInfo));
    PCCRYPT_OID_INFO p = U(CryptFindOIDInfo)(CRYPT_OID_INFO_OID_KEY, (void *)"1.3.14.3.2.26", CRYPT_OID_PREFER_CNG_ALGID_FLAG);
    CHECK(p && p->dwGroupId == OIDG_HASH && p->pwszCNGAlgid && !wcscmp(p->pwszCNGAlgid, L"SHA1"));
}

/* ---- invalid key types ---- */
TEST(oidfind_invalid_key_type_fails) {
    REQUIRE(U(CryptFindOIDInfo));
    static const DWORD bad[] = {0, 7, 8, 0x55, 0xffff};
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        SET_ERR(0);
        PCCRYPT_OID_INFO p = U(CryptFindOIDInfo)(bad[i], (void *)"1.3.14.3.2.26", OIDG_HASH | NODS);
        CHECKF(p == NULL, "key type 0x%lx", bad[i]);
        if (GetLastError() != ERR_INVALIDARG) t_note("key type 0x%lx: last error 0x%lx", bad[i], GetLastError());
    }
}

/* ---- localized resource names for groups 6/7/8 ---- */
TEST(oidfind_localized_groups_have_resolved_names) {
    REQUIRE(U(CryptFindOIDInfo));
    int n = 0, bad = 0;
    for (size_t i = 0; i < NROWS; i++) {
        const OIDROW *r = &g_rows[i];
        if (r->grp < 6 || r->grp > 8 || r->name || first_oid(r->grp, r->oid) != r) continue;
        PCCRYPT_OID_INFO p = U(CryptFindOIDInfo)(CRYPT_OID_INFO_OID_KEY, (void *)r->oid, r->grp);
        CHECKF(p != NULL, "%s", r->oid);
        /* the resource id in the static table is replaced by the loaded string; an individual resource may be absent */
        if (p && (!p->pwszName || !p->pwszName[0] || p->pwszName[0] == L'#')) { bad++; t_note("unresolved name for %s", r->oid); }
        n++;
    }
    CHECK(n > 100);
    CHECKF(bad * 10 < n, "%d of %d names unresolved", bad, n);
}
TEST(oidfind_enhkey_usage_well_known_names_en) {
    REQUIRE(U(CryptFindOIDInfo));
    if ((GetUserDefaultUILanguage() & 0xff) != 9) { t_skip("non-English UI"); return; }
    static const struct { const char *oid; const wchar_t *name; } t[] = {
        {"1.3.6.1.5.5.7.3.1", L"Server Authentication"}, {"1.3.6.1.5.5.7.3.2", L"Client Authentication"},
        {"1.3.6.1.5.5.7.3.3", L"Code Signing"}, {"1.3.6.1.5.5.7.3.4", L"Secure Email"},
    };
    for (size_t i = 0; i < 4; i++) {
        PCCRYPT_OID_INFO p = U(CryptFindOIDInfo)(CRYPT_OID_INFO_OID_KEY, (void *)t[i].oid, OIDG_ENHKEY);
        CHECKF(p && !wcscmp(p->pwszName, t[i].name), "%s", t[i].oid);
        if (p && wcscmp(p->pwszName, t[i].name)) t_note("%s -> %ls", t[i].oid, p->pwszName);
    }
}
TEST(oidfind_ext_group_values_zero) {
    REQUIRE(U(CryptFindOIDInfo));
    PCCRYPT_OID_INFO p = U(CryptFindOIDInfo)(CRYPT_OID_INFO_OID_KEY, (void *)"2.5.29.19", OIDG_EXT);
    CHECK(p && p->dwValue == 0 && p->ExtraInfo.cbData == 0);
    p = U(CryptFindOIDInfo)(CRYPT_OID_INFO_OID_KEY, (void *)"2.5.29.37", OIDG_EXT);
    CHECK(p && p->dwValue == 0);
}
TEST(oidfind_rdn_value_types) {
    REQUIRE(U(CryptFindOIDInfo));
    /* ExtraInfo of an RDN attribute is a zero-terminated DWORD array of acceptable value types */
    PCCRYPT_OID_INFO p = U(CryptFindOIDInfo)(CRYPT_OID_INFO_OID_KEY, (void *)"2.5.4.6", OIDG_RDN);
    CHECK(p && p->ExtraInfo.cbData == 8);
    if (p && p->ExtraInfo.cbData == 8) { DWORD *d = (DWORD *)p->ExtraInfo.pbData; CHECK(d[0] == CERT_RDN_PRINTABLE_STRING && d[1] == 0); }
    p = U(CryptFindOIDInfo)(CRYPT_OID_INFO_OID_KEY, (void *)"1.2.840.113549.1.9.1", OIDG_RDN);
    CHECK(p && p->ExtraInfo.cbData == 8);
    if (p && p->ExtraInfo.cbData == 8) CHECK(*(DWORD *)p->ExtraInfo.pbData == CERT_RDN_IA5_STRING);
    p = U(CryptFindOIDInfo)(CRYPT_OID_INFO_OID_KEY, (void *)"0.9.2342.19200300.100.1.25", OIDG_RDN);
    CHECK(p && p->ExtraInfo.cbData == 12);
    if (p && p->ExtraInfo.cbData == 12) { DWORD *d = (DWORD *)p->ExtraInfo.pbData; CHECK(d[0] == CERT_RDN_IA5_STRING && d[1] == CERT_RDN_UTF8_STRING && d[2] == 0); }
    p = U(CryptFindOIDInfo)(CRYPT_OID_INFO_OID_KEY, (void *)"2.5.4.3", OIDG_RDN);
    CHECK(p && p->ExtraInfo.cbData == 0);
}
TEST(oidfind_rdn_synonym_names) {
    REQUIRE(U(CryptFindOIDInfo));
    static const struct { const wchar_t *n; const char *oid; } t[] = {
        {L"E", "1.2.840.113549.1.9.1"}, {L"Email", "1.2.840.113549.1.9.1"}, {L"S", "2.5.4.8"}, {L"ST", "2.5.4.8"},
        {L"T", "2.5.4.12"}, {L"Title", "2.5.4.12"}, {L"G", "2.5.4.42"}, {L"GN", "2.5.4.42"}, {L"GivenName", "2.5.4.42"},
        {L"I", "2.5.4.43"}, {L"Initials", "2.5.4.43"}, {L"SN", "2.5.4.4"}, {L"DC", "0.9.2342.19200300.100.1.25"},
        {L"CN", "2.5.4.3"}, {L"OU", "2.5.4.11"}, {L"O", "2.5.4.10"}, {L"L", "2.5.4.7"}, {L"C", "2.5.4.6"},
    };
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
        PCCRYPT_OID_INFO p = U(CryptFindOIDInfo)(CRYPT_OID_INFO_NAME_KEY, (void *)t[i].n, OIDG_RDN);
        CHECKF(p && !strcmp(p->pszOID, t[i].oid), "%ls", t[i].n);
    }
}

/* ---- CertAlgIdToOID ---- */
TEST(certalgidtooid_table) {
    REQUIRE(U(CertAlgIdToOID));
    static const struct { DWORD a; const char *oid; } t[] = {
        {CALG_SHA1, "1.3.14.3.2.26"}, {CALG_MD5, "1.2.840.113549.2.5"}, {CALG_MD4, "1.2.840.113549.2.4"},
        {CALG_MD2, "1.2.840.113549.2.2"}, {CALG_DES, "1.3.14.3.2.7"}, {CALG_3DES, "1.2.840.113549.3.7"},
        {CALG_RC2, "1.2.840.113549.3.2"}, {CALG_RC4, "1.2.840.113549.3.4"}, {CALG_RSA_KEYX, "1.2.840.113549.1.1.1"},
        {CALG_DSS_SIGN, "1.2.840.10040.4.1"}, {CALG_DH_SF, "1.2.840.10046.2.1"},
    };
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
        LPCSTR o = U(CertAlgIdToOID)(t[i].a);
        CHECKF(o && !strcmp(o, t[i].oid), "algid 0x%lx", t[i].a);
    }
}
TEST(certalgidtooid_rsa_sign_algid) {
    REQUIRE(U(CertAlgIdToOID));
    LPCSTR o = U(CertAlgIdToOID)(CALG_RSA_SIGN);
    CHECK(o && !strcmp(o, "1.2.840.113549.1.1.1"));
}
TEST(certalgidtooid_sha2_algids) {
    REQUIRE(U(CertAlgIdToOID));
    static const struct { DWORD a; const char *oid; } t[] = {
        {CALG_SHA_256, "2.16.840.1.101.3.4.2.1"}, {CALG_SHA_384, "2.16.840.1.101.3.4.2.2"}, {CALG_SHA_512, "2.16.840.1.101.3.4.2.3"},
    };
    for (size_t i = 0; i < 3; i++) {
        LPCSTR o = U(CertAlgIdToOID)(t[i].a);
        if (!o) t_note("CertAlgIdToOID(0x%lx) returned NULL", t[i].a);
        else CHECKF(!strcmp(o, t[i].oid), "algid 0x%lx -> %s", t[i].a, o);
    }
}
TEST(certalgidtooid_unknown_is_null) {
    REQUIRE(U(CertAlgIdToOID));
    CHECK(U(CertAlgIdToOID)(0) == NULL);
    CHECK(U(CertAlgIdToOID)(0xABCDEF) == NULL);
    CHECK(U(CertAlgIdToOID)(CALG_HMAC) == NULL);
    CHECK(U(CertAlgIdToOID)(CALG_SSL3_SHAMD5) == NULL);
}
TEST(certalgidtooid_returns_pointer_into_table) {
    REQUIRE(U(CertAlgIdToOID)); REQUIRE(U(CryptFindOIDInfo));
    LPCSTR o = U(CertAlgIdToOID)(CALG_SHA1);
    ALG_ID k = CALG_SHA1;
    PCCRYPT_OID_INFO p = U(CryptFindOIDInfo)(CRYPT_OID_INFO_ALGID_KEY, &k, OIDG_HASH);
    CHECK(o && p && o == p->pszOID);
    CHECK(U(CertAlgIdToOID)(CALG_SHA1) == o);
}

/* ---- CertOIDToAlgId ---- */
TEST(certoidtoalgid_table) {
    REQUIRE(U(CertOIDToAlgId));
    static const struct { const char *oid; DWORD a; } t[] = {
        {"1.3.14.3.2.26", CALG_SHA1}, {"1.2.840.113549.2.5", CALG_MD5}, {"1.2.840.113549.2.4", CALG_MD4},
        {"1.2.840.113549.2.2", CALG_MD2}, {"1.3.14.3.2.7", CALG_DES}, {"1.2.840.113549.3.7", CALG_3DES},
        {"1.2.840.113549.3.2", CALG_RC2}, {"1.2.840.113549.3.4", CALG_RC4}, {"1.2.840.113549.1.1.1", CALG_RSA_KEYX},
        {"1.2.840.10040.4.1", CALG_DSS_SIGN}, {"1.2.840.10046.2.1", CALG_DH_SF},
    };
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++)
        CHECKF(U(CertOIDToAlgId)(t[i].oid) == t[i].a, "%s", t[i].oid);
}
TEST(certoidtoalgid_sign_oids_return_hash_algid) {
    REQUIRE(U(CertOIDToAlgId));
    static const struct { const char *oid; DWORD a; } t[] = {
        {"1.2.840.113549.1.1.5", CALG_SHA1}, {"1.2.840.113549.1.1.4", CALG_MD5}, {"1.2.840.113549.1.1.2", CALG_MD2},
        {"1.2.840.113549.1.1.3", CALG_MD4}, {"1.2.840.10040.4.3", CALG_SHA1}, {"1.3.14.3.2.29", CALG_SHA1},
    };
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++)
        CHECKF(U(CertOIDToAlgId)(t[i].oid) == t[i].a, "%s", t[i].oid);
}
TEST(certoidtoalgid_sha2_oids) {
    REQUIRE(U(CertOIDToAlgId));
    static const struct { const char *oid; DWORD a; } t[] = {
        {"2.16.840.1.101.3.4.2.1", CALG_SHA_256}, {"2.16.840.1.101.3.4.2.2", CALG_SHA_384}, {"2.16.840.1.101.3.4.2.3", CALG_SHA_512},
        {"1.2.840.113549.1.1.11", CALG_SHA_256}, {"1.2.840.113549.1.1.12", CALG_SHA_384}, {"1.2.840.113549.1.1.13", CALG_SHA_512},
    };
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
        DWORD a = U(CertOIDToAlgId)(t[i].oid);
        if (a != t[i].a) t_note("CertOIDToAlgId(%s) = 0x%lx (expected CALG 0x%lx)", t[i].oid, a, t[i].a);
        CHECKF(a == t[i].a || a == 0xffffffffu, "%s -> 0x%lx", t[i].oid, a);
    }
}
TEST(certoidtoalgid_unknown_is_zero) {
    REQUIRE(U(CertOIDToAlgId));
    CHECK(U(CertOIDToAlgId)("1.2.3.4.5.99999") == 0);
    CHECK(U(CertOIDToAlgId)("") == 0);
    CHECK(U(CertOIDToAlgId)("sha1") == 0); /* names are not OIDs */
    CHECK(U(CertOIDToAlgId)("2.5.4.3") == 0); /* RDN group is not searched */
    CHECK(U(CertOIDToAlgId)("1.3.6.1.5.5.7.3.1") == 0);
}
TEST(certoidtoalgid_roundtrip_with_algidtooid) {
    REQUIRE(U(CertOIDToAlgId)); REQUIRE(U(CertAlgIdToOID));
    static const DWORD a[] = {CALG_SHA1, CALG_MD5, CALG_MD4, CALG_MD2, CALG_DES, CALG_3DES, CALG_RC2, CALG_RC4, CALG_RSA_KEYX, CALG_DSS_SIGN};
    for (size_t i = 0; i < sizeof a / sizeof a[0]; i++) {
        LPCSTR o = U(CertAlgIdToOID)(a[i]);
        CHECKF(o && U(CertOIDToAlgId)(o) == a[i], "algid 0x%lx", a[i]);
    }
}
