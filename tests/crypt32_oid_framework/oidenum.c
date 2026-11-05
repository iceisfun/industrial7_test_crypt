/* CryptEnumOIDInfo and CryptFindLocalizedName. */
#include "fw.h"
#include "oidtab.h"

#define MAXE 2048
typedef struct {
    int n, stop_at, ret;
    const CRYPT_OID_INFO *p[MAXE];
    void *seen_arg;
} ENUMST;

static BOOL WINAPI cb_collect(PCCRYPT_OID_INFO info, void *arg) {
    ENUMST *s = arg;
    if (s->n < MAXE) s->p[s->n] = info;
    s->n++;
    s->seen_arg = arg;
    if (s->stop_at && s->n >= s->stop_at) return FALSE;
    return TRUE;
}
static int static_count(int g) {
    int c = 0;
    for (size_t i = 0; i < NROWS; i++) if (g == 0 || g_rows[i].grp == g) c++;
    return c;
}

static void enum_group_checks(int g) {
    REQUIRE(U(CryptEnumOIDInfo));
    static ENUMST s;
    memset(&s, 0, sizeof s);
    BOOL r = U(CryptEnumOIDInfo)(g, 0, &s, cb_collect);
    CHECK(r == TRUE);
    CHECKF(s.n >= static_count(g), "enumerated %d, static table has %d", s.n, static_count(g));
    CHECK(s.n <= MAXE);
    CHECK(s.seen_arg == &s);
    for (int i = 0; i < s.n && i < MAXE; i++) {
        CHECK(s.p[i]->cbSize == sizeof(CRYPT_OID_INFO));
        CHECK(s.p[i]->pszOID != NULL);
        if (g) CHECK(s.p[i]->dwGroupId == (DWORD)g);
        else CHECK(s.p[i]->dwGroupId >= 1 && s.p[i]->dwGroupId <= 10);
    }
    /* every static row is delivered, in table order (registry entries, if any, come first) */
    int pos = 0, found = 0;
    for (size_t i = 0; i < NROWS; i++) {
        const OIDROW *r = &g_rows[i];
        if (g && r->grp != g) continue;
        int hit = 0;
        for (; pos < s.n && pos < MAXE; pos++) {
            const CRYPT_OID_INFO *e = s.p[pos];
            if (e->dwGroupId == (DWORD)r->grp && !strcmp(e->pszOID, r->oid) && (!r->name || (e->pwszName && !wcscmp(e->pwszName, r->name)))) { hit = 1; pos++; break; }
        }
        if (hit) found++;
    }
    CHECKF(found == static_count(g), "ordered static rows found: %d of %d", found, static_count(g));
}
TEST(oidenum_group_hash)     { enum_group_checks(OIDG_HASH); }
TEST(oidenum_group_encrypt)  { enum_group_checks(OIDG_ENCRYPT); }
TEST(oidenum_group_pubkey)   { enum_group_checks(OIDG_PUBKEY); }
TEST(oidenum_group_sign)     { enum_group_checks(OIDG_SIGN); }
TEST(oidenum_group_rdn)      { enum_group_checks(OIDG_RDN); }
TEST(oidenum_group_ext)      { enum_group_checks(OIDG_EXT); }
TEST(oidenum_group_enhkey)   { enum_group_checks(OIDG_ENHKEY); }
TEST(oidenum_group_policy)   { enum_group_checks(OIDG_POLICY); }
TEST(oidenum_group_kdf)      { enum_group_checks(OIDG_KDF); }
TEST(oidenum_all_groups)     { enum_group_checks(0); }

TEST(oidenum_template_group_is_callable) {
    REQUIRE(U(CryptEnumOIDInfo));
    static ENUMST s; memset(&s, 0, sizeof s);
    BOOL r = U(CryptEnumOIDInfo)(OIDG_TEMPLATE, 0, &s, cb_collect);
    CHECK(r == TRUE);
    for (int i = 0; i < s.n && i < MAXE; i++) CHECK(s.p[i]->dwGroupId == OIDG_TEMPLATE);
    t_note("template group entries: %d", s.n);
}
TEST(oidenum_all_equals_sum_of_groups) {
    REQUIRE(U(CryptEnumOIDInfo));
    static ENUMST s; memset(&s, 0, sizeof s);
    U(CryptEnumOIDInfo)(0, 0, &s, cb_collect);
    int total = s.n, sum = 0;
    for (int g = 1; g <= 10; g++) { memset(&s, 0, sizeof s); U(CryptEnumOIDInfo)(g, 0, &s, cb_collect); sum += s.n; }
    CHECKF(total == sum, "all=%d sum=%d", total, sum);
}
TEST(oidenum_repeatable) {
    REQUIRE(U(CryptEnumOIDInfo));
    static ENUMST a, b; memset(&a, 0, sizeof a); memset(&b, 0, sizeof b);
    U(CryptEnumOIDInfo)(OIDG_SIGN, 0, &a, cb_collect);
    U(CryptEnumOIDInfo)(OIDG_SIGN, 0, &b, cb_collect);
    CHECK(a.n == b.n);
    for (int i = 0; i < a.n && i < MAXE; i++) CHECK(a.p[i] == b.p[i]);
}
TEST(oidenum_flags_are_ignored) {
    REQUIRE(U(CryptEnumOIDInfo));
    static ENUMST a, b; memset(&a, 0, sizeof a); memset(&b, 0, sizeof b);
    U(CryptEnumOIDInfo)(OIDG_HASH, 0, &a, cb_collect);
    BOOL r = U(CryptEnumOIDInfo)(OIDG_HASH, 0xA5A5A5A5, &b, cb_collect);
    CHECK(r == TRUE);
    CHECK(a.n == b.n);
}
TEST(oidenum_callback_false_stops_group) {
    REQUIRE(U(CryptEnumOIDInfo));
    for (int g = 1; g <= 8; g++) {
        static ENUMST s; memset(&s, 0, sizeof s); s.stop_at = 1;
        BOOL r = U(CryptEnumOIDInfo)(g, 0, &s, cb_collect);
        CHECKF(r == FALSE && s.n == 1, "group %d: ret %d calls %d", g, r, s.n);
    }
}
TEST(oidenum_callback_false_stops_after_n) {
    REQUIRE(U(CryptEnumOIDInfo));
    static ENUMST s; memset(&s, 0, sizeof s); s.stop_at = 5;
    BOOL r = U(CryptEnumOIDInfo)(OIDG_EXT, 0, &s, cb_collect);
    CHECK(r == FALSE);
    CHECK(s.n == 5);
}
TEST(oidenum_callback_false_stops_all_groups) {
    REQUIRE(U(CryptEnumOIDInfo));
    static ENUMST s; memset(&s, 0, sizeof s); s.stop_at = 40;
    BOOL r = U(CryptEnumOIDInfo)(0, 0, &s, cb_collect);
    CHECK(r == FALSE);
    CHECK(s.n == 40);
}
TEST(oidenum_unknown_group_no_callbacks) {
    REQUIRE(U(CryptEnumOIDInfo));
    static const DWORD g[] = {11, 12, 99, 0x1000};
    for (size_t i = 0; i < sizeof g / sizeof g[0]; i++) {
        static ENUMST s; memset(&s, 0, sizeof s);
        BOOL r = U(CryptEnumOIDInfo)(g[i], 0, &s, cb_collect);
        CHECKF(s.n == 0, "group %lu produced %d callbacks", g[i], s.n);
        t_note("CryptEnumOIDInfo(group %lu) returned %d", g[i], r);
    }
}
TEST(oidenum_pointers_match_find) {
    REQUIRE(U(CryptEnumOIDInfo)); REQUIRE(U(CryptFindOIDInfo));
    static ENUMST s; memset(&s, 0, sizeof s);
    U(CryptEnumOIDInfo)(OIDG_HASH, 0, &s, cb_collect);
    for (size_t i = 0; i < NROWS; i++) {
        if (g_rows[i].grp != OIDG_HASH) continue;
        PCCRYPT_OID_INFO f = U(CryptFindOIDInfo)(CRYPT_OID_INFO_OID_KEY, (void *)g_rows[i].oid, OIDG_HASH);
        int in = 0;
        for (int k = 0; k < s.n && k < MAXE; k++) if (s.p[k] == f) in = 1;
        CHECKF(f && in, "%s", g_rows[i].oid);
    }
}
TEST(oidenum_find_by_name_pointer_is_enumerated) {
    REQUIRE(U(CryptEnumOIDInfo)); REQUIRE(U(CryptFindOIDInfo));
    static ENUMST s; memset(&s, 0, sizeof s);
    U(CryptEnumOIDInfo)(OIDG_RDN, 0, &s, cb_collect);
    PCCRYPT_OID_INFO f = U(CryptFindOIDInfo)(CRYPT_OID_INFO_NAME_KEY, (void *)L"CN", OIDG_RDN);
    int in = 0;
    for (int k = 0; k < s.n && k < MAXE; k++) if (s.p[k] == f) in = 1;
    CHECK(f && in);
}

/* reentrancy: the callback may call back into the OID info APIs */
static BOOL WINAPI cb_reenter(PCCRYPT_OID_INFO info, void *arg) {
    int *bad = arg;
    PCCRYPT_OID_INFO p = U(CryptFindOIDInfo)(CRYPT_OID_INFO_OID_KEY, (void *)info->pszOID, info->dwGroupId | NODS);
    if (!p || strcmp(p->pszOID, info->pszOID)) (*bad)++;
    return TRUE;
}
TEST(oidenum_callback_may_call_find) {
    REQUIRE(U(CryptEnumOIDInfo)); REQUIRE(U(CryptFindOIDInfo));
    int bad = 0;
    BOOL r = U(CryptEnumOIDInfo)(OIDG_SIGN, 0, &bad, cb_reenter);
    CHECK(r == TRUE);
    CHECK(bad == 0);
}
static BOOL WINAPI cb_nested(PCCRYPT_OID_INFO info, void *arg) {
    int *n = arg;
    static ENUMST inner;
    memset(&inner, 0, sizeof inner); inner.stop_at = 2;
    BOOL r = U(CryptEnumOIDInfo)(OIDG_HASH, 0, &inner, cb_collect);
    if (r != FALSE || inner.n != 2) (*n)++;
    return TRUE;
}
TEST(oidenum_nested_enumeration) {
    REQUIRE(U(CryptEnumOIDInfo));
    int bad = 0;
    U(CryptEnumOIDInfo)(OIDG_ENCRYPT, 0, &bad, cb_nested);
    CHECK(bad == 0);
}
static DWORD WINAPI enum_thread(void *p) {
    ENUMST *s = p;
    U(CryptEnumOIDInfo)(OIDG_ENHKEY, 0, s, cb_collect);
    return 0;
}
TEST(oidenum_concurrent_threads_agree) {
    REQUIRE(U(CryptEnumOIDInfo));
    static ENUMST s[4]; HANDLE h[4];
    memset(s, 0, sizeof s);
    for (int i = 0; i < 4; i++) h[i] = CreateThread(NULL, 0, enum_thread, &s[i], 0, NULL);
    for (int i = 0; i < 4; i++) { CHECK(WaitForSingleObject(h[i], 20000) == WAIT_OBJECT_0); CloseHandle(h[i]); }
    for (int i = 1; i < 4; i++) {
        CHECK(s[i].n == s[0].n);
        for (int k = 0; k < s[0].n && k < MAXE; k++) CHECK(s[i].p[k] == s[0].p[k]);
    }
}

/* ---- group-specific content ---- */
static int count_name(int g, const wchar_t *nm, ENUMST *s) {
    int c = 0;
    for (int k = 0; k < s->n && k < MAXE; k++)
        if (s->p[k]->dwGroupId == (DWORD)g && s->p[k]->pwszName && !wcscmp(s->p[k]->pwszName, nm)) c++;
    return c;
}
TEST(oidenum_rdn_synonyms_enumerated_separately) {
    REQUIRE(U(CryptEnumOIDInfo));
    static ENUMST s; memset(&s, 0, sizeof s);
    U(CryptEnumOIDInfo)(OIDG_RDN, 0, &s, cb_collect);
    CHECK(count_name(OIDG_RDN, L"S", &s) >= 1);
    CHECK(count_name(OIDG_RDN, L"ST", &s) >= 1);
    CHECK(count_name(OIDG_RDN, L"GN", &s) >= 1);
    CHECK(count_name(OIDG_RDN, L"GivenName", &s) >= 1);
    CHECK(count_name(OIDG_RDN, L"Email", &s) >= 1);
    CHECK(count_name(OIDG_RDN, L"E", &s) >= 1);
}
TEST(oidenum_hash_group_duplicate_oid_entries) {
    REQUIRE(U(CryptEnumOIDInfo));
    static ENUMST s; memset(&s, 0, sizeof s);
    U(CryptEnumOIDInfo)(OIDG_HASH, 0, &s, cb_collect);
    int sha1 = 0;
    for (int k = 0; k < s.n && k < MAXE; k++) if (!strcmp(s.p[k]->pszOID, "1.3.14.3.2.26")) sha1++;
    CHECKF(sha1 >= 2, "sha1 OID enumerated %d times (names sha1 and sha)", sha1);
}
TEST(oidenum_pubkey_group_contains_ecc_curves) {
    REQUIRE(U(CryptEnumOIDInfo));
    static ENUMST s; memset(&s, 0, sizeof s);
    U(CryptEnumOIDInfo)(OIDG_PUBKEY, 0, &s, cb_collect);
    CHECK(count_name(OIDG_PUBKEY, L"ECDSA_P256", &s) >= 1);
    CHECK(count_name(OIDG_PUBKEY, L"ECDH_P384", &s) >= 1);
    CHECK(count_name(OIDG_PUBKEY, L"RSA", &s) >= 1);
}
TEST(oidenum_sign_group_all_have_two_part_cng) {
    REQUIRE(U(CryptEnumOIDInfo));
    static ENUMST s; memset(&s, 0, sizeof s);
    U(CryptEnumOIDInfo)(OIDG_SIGN, 0, &s, cb_collect);
    int with = 0;
    for (int k = 0; k < s.n && k < MAXE; k++)
        if (s.p[k]->pwszCNGAlgid && s.p[k]->pwszCNGAlgid[0] && s.p[k]->pwszCNGExtraAlgid && s.p[k]->pwszCNGExtraAlgid[0]) with++;
    CHECKF(with >= 20, "%d entries carry CNG hash+signature names", with);
}
TEST(oidenum_names_non_empty_in_every_group) {
    REQUIRE(U(CryptEnumOIDInfo));
    static ENUMST s;
    for (int g = 1; g <= 10; g++) {
        memset(&s, 0, sizeof s);
        U(CryptEnumOIDInfo)(g, 0, &s, cb_collect);
        int empty = 0;
        for (int k = 0; k < s.n && k < MAXE; k++) if (!s.p[k]->pwszName || !s.p[k]->pwszName[0]) empty++;
        if (empty) t_note("group %d: %d unnamed entries of %d", g, empty, s.n);
    }
}

/* ---- CryptFindLocalizedName ---- */
/* lvl 2: asserted; lvl 1: reported only (present in the name table of crypt32, text unverified) */
static const struct { const wchar_t *k, *en; int lvl; } g_loc[] = {
    {L"Root", L"Trusted Root Certification Authorities", 2}, {L"My", L"Personal", 2},
    {L"CA", L"Intermediate Certification Authorities", 2}, {L"TrustedPublisher", L"Trusted Publishers", 2},
    {L"TrustedPeople", L"Trusted People", 2}, {L"Disallowed", L"Untrusted Certificates", 2},
    {L"AuthRoot", L"Third-Party Root Certification Authorities", 2}, {L"Trust", L"Enterprise Trust", 2},
    {L"REQUEST", L"Certificate Enrollment Requests", 1}, {L"SmartCardRoot", L"Smart Card Trusted Roots", 1},
    {L"ClientAuthIssuer", L"Client Authentication Issuers", 1},
};
TEST(localizedname_known_stores_resolve) {
    REQUIRE(U(CryptFindLocalizedName));
    for (size_t i = 0; i < sizeof g_loc / sizeof g_loc[0]; i++) {
        LPCWSTR r = U(CryptFindLocalizedName)(g_loc[i].k);
        if (g_loc[i].lvl == 2) CHECKF(r && r[0], "%ls", g_loc[i].k);
        else t_note("%ls -> %ls", g_loc[i].k, r ? r : L"(null)");
    }
}
TEST(localizedname_english_strings) {
    REQUIRE(U(CryptFindLocalizedName));
    if ((GetUserDefaultUILanguage() & 0xff) != 9) { t_skip("non-English UI language"); return; }
    for (size_t i = 0; i < sizeof g_loc / sizeof g_loc[0]; i++) {
        LPCWSTR r = U(CryptFindLocalizedName)(g_loc[i].k);
        if (g_loc[i].lvl == 2) CHECKF(r && !wcscmp(r, g_loc[i].en), "%ls -> %ls", g_loc[i].k, r ? r : L"(null)");
        else if (!r || wcscmp(r, g_loc[i].en)) t_note("%ls -> %ls", g_loc[i].k, r ? r : L"(null)");
    }
}
TEST(localizedname_case_insensitive) {
    REQUIRE(U(CryptFindLocalizedName));
    for (size_t i = 0; i < sizeof g_loc / sizeof g_loc[0]; i++) {
        if (g_loc[i].lvl != 2) continue;
        wchar_t f[64]; fw_flip_w(f, g_loc[i].k);
        LPCWSTR a = U(CryptFindLocalizedName)(g_loc[i].k), b = U(CryptFindLocalizedName)(f);
        CHECKF(a && b && !wcscmp(a, b), "%ls", f);
    }
}
TEST(localizedname_stable_pointer) {
    REQUIRE(U(CryptFindLocalizedName));
    LPCWSTR a = U(CryptFindLocalizedName)(L"Root"), b = U(CryptFindLocalizedName)(L"ROOT");
    CHECK(a && a == b);
    CHECK(U(CryptFindLocalizedName)(L"Root") == a);
}
TEST(localizedname_null_and_empty) {
    REQUIRE(U(CryptFindLocalizedName));
    CHECK(U(CryptFindLocalizedName)(NULL) == NULL);
    CHECK(U(CryptFindLocalizedName)(L"") == NULL);
}
TEST(localizedname_unknown_and_whitespace) {
    REQUIRE(U(CryptFindLocalizedName));
    CHECK(U(CryptFindLocalizedName)(L"cryptt-NoSuchStore") == NULL);
    CHECK(U(CryptFindLocalizedName)(L"Root ") == NULL);
    CHECK(U(CryptFindLocalizedName)(L" Root") == NULL);
    CHECK(U(CryptFindLocalizedName)(L"Roo") == NULL);
    CHECK(U(CryptFindLocalizedName)(L"Rootx") == NULL);
}
TEST(localizedname_translation_is_not_idempotent_key) {
    REQUIRE(U(CryptFindLocalizedName));
    LPCWSTR a = U(CryptFindLocalizedName)(L"My");
    CHECK(a != NULL);
    if (a) CHECK(U(CryptFindLocalizedName)(a) == NULL || wcscmp(a, L"My") != 0);
}
TEST(localizedname_distinct_results) {
    REQUIRE(U(CryptFindLocalizedName));
    for (size_t i = 0; i < sizeof g_loc / sizeof g_loc[0]; i++)
        for (size_t j = i + 1; j < sizeof g_loc / sizeof g_loc[0]; j++) {
            if (g_loc[i].lvl != 2 || g_loc[j].lvl != 2) continue;
            LPCWSTR a = U(CryptFindLocalizedName)(g_loc[i].k), b = U(CryptFindLocalizedName)(g_loc[j].k);
            CHECKF(a && b && wcscmp(a, b) != 0, "%ls vs %ls", g_loc[i].k, g_loc[j].k);
        }
}
static DWORD WINAPI loc_thread(void *p) {
    LPCWSTR *out = p;
    *out = U(CryptFindLocalizedName)(L"CA");
    return 0;
}
TEST(localizedname_thread_safe_same_pointer) {
    REQUIRE(U(CryptFindLocalizedName));
    LPCWSTR r[4] = {0}; HANDLE h[4];
    for (int i = 0; i < 4; i++) h[i] = CreateThread(NULL, 0, loc_thread, &r[i], 0, NULL);
    for (int i = 0; i < 4; i++) { CHECK(WaitForSingleObject(h[i], 20000) == WAIT_OBJECT_0); CloseHandle(h[i]); }
    for (int i = 1; i < 4; i++) CHECK(r[i] && r[i] == r[0]);
}
