#include "wcfg.h"
/* CryptCATAdmin*: add / enumerate by hash / resolve path / remove of a test catalog.
 * The catalog is created with the CryptCAT* APIs from a deterministic member file.  Installing needs elevation
 * (the catalog database lives behind the cryptographic service); everything installed is removed again. */

#define CSETUP(fn) REQUIRE(U(fn)); REQUIRE(U(CryptCATAdminAcquireContext)); REQUIRE(U(CryptCATAdminReleaseContext))

static HCATADMIN acquire(void) {
    HCATADMIN h = NULL;
    if (!U(CryptCATAdminAcquireContext)(&h, NULL, 0)) return NULL;
    return h;
}
static void narrow2wide(const char *a, wchar_t *w, int n) { MultiByteToWideChar(CP_ACP, 0, a, -1, w, n); }

/* ------------------------------------------------------------------ ResolveCatalogPath: pure path construction */
TEST(wcfg_cat_resolve_path_concatenates_catroot_dir_and_name) {
    CSETUP(CryptCATAdminResolveCatalogPath); HCATADMIN a = acquire();
    CHECK(a != NULL); if (!a) return;
    CATALOG_INFO ci; memset(&ci, 0x55, sizeof ci); ci.cbStruct = sizeof ci;
    CHECK(sizeof ci == 0x20c);
    WCHAR name[] = L"cryptt_probe.cat";
    SET_ERR(0);
    BOOL r = U(CryptCATAdminResolveCatalogPath)(a, name, &ci, 0);
    CHECK(r);
    size_t l = wcslen(ci.wszCatalogFile), nl = wcslen(name);
    CHECK(l > nl + 1);
    if (l > nl + 1) {
        CHECK(!wcscmp(ci.wszCatalogFile + l - nl, name));
        CHECK(ci.wszCatalogFile[l - nl - 1] == L'\\');
        wchar_t low[MAX_PATH]; wcscpy(low, ci.wszCatalogFile); _wcslwr(low);
        CHECK(wcsstr(low, L"\\catroot\\") != NULL);
    }
    t_note("catroot path: %ls", ci.wszCatalogFile);
    CHECK(ci.cbStruct == sizeof ci);
    U(CryptCATAdminReleaseContext)(a, 0);
}
TEST(wcfg_cat_resolve_path_does_not_check_existence) {
    CSETUP(CryptCATAdminResolveCatalogPath); HCATADMIN a = acquire(); if (!a) { t_skip("no catalog admin context"); return; }
    CATALOG_INFO ci; ci.cbStruct = sizeof ci;
    WCHAR n1[] = L"cryptt_no_such_catalog.cat", n2[] = L"", n3[] = L"sub\\dir\\x.cat", n4[] = L"..\\up.cat";
    WCHAR *names[] = { n1, n2, n3, n4 };
    for (int i = 0; i < 4; i++) {
        memset(ci.wszCatalogFile, 0, sizeof ci.wszCatalogFile);
        BOOL r = U(CryptCATAdminResolveCatalogPath)(a, names[i], &ci, 0);
        CHECKF(r, "name %d", i);
        size_t l = wcslen(ci.wszCatalogFile), nl = wcslen(names[i]);
        CHECKF(l >= nl && !wcscmp(ci.wszCatalogFile + l - nl, names[i]), "name %d appended verbatim", i);
    }
    U(CryptCATAdminReleaseContext)(a, 0);
}
TEST(wcfg_cat_resolve_path_empty_name_is_directory) {
    CSETUP(CryptCATAdminResolveCatalogPath); HCATADMIN a = acquire(); if (!a) { t_skip("no catalog admin context"); return; }
    CATALOG_INFO ci; ci.cbStruct = sizeof ci; WCHAR e[] = L"", x[] = L"x";
    CHECK(U(CryptCATAdminResolveCatalogPath)(a, e, &ci, 0));
    size_t dl = wcslen(ci.wszCatalogFile);
    CHECK(dl > 3);
    CATALOG_INFO c2; c2.cbStruct = sizeof c2;
    CHECK(U(CryptCATAdminResolveCatalogPath)(a, x, &c2, 0));
    CHECK(wcslen(c2.wszCatalogFile) == dl + 1);
    CHECK(!wcsncmp(c2.wszCatalogFile, ci.wszCatalogFile, dl));
    U(CryptCATAdminReleaseContext)(a, 0);
}
TEST(wcfg_cat_resolve_path_length_boundary) {
    CSETUP(CryptCATAdminResolveCatalogPath); HCATADMIN a = acquire(); if (!a) { t_skip("no catalog admin context"); return; }
    if (t_is_wine()) { t_skip("emulator crashes/differs"); return; }
    CATALOG_INFO ci; ci.cbStruct = sizeof ci; WCHAR e[] = L"";
    CHECK(U(CryptCATAdminResolveCatalogPath)(a, e, &ci, 0));
    size_t dl = wcslen(ci.wszCatalogFile);
    WCHAR big[400];
    size_t fit = 259 - dl;                               /* dir + name + NUL must fit 260 characters */
    for (size_t i = 0; i < 390; i++) { big[i] = L'n'; }
    big[390] = 0;
    big[fit] = 0;
    SET_ERR(0);
    CHECK(U(CryptCATAdminResolveCatalogPath)(a, big, &ci, 0));
    CHECK(wcslen(ci.wszCatalogFile) == 259);
    big[fit] = L'n'; big[fit + 1] = 0;
    SET_ERR(0);
    CHECK(!U(CryptCATAdminResolveCatalogPath)(a, big, &ci, 0)); EXPECT_ERR(ERROR_NOT_ENOUGH_MEMORY);
    U(CryptCATAdminReleaseContext)(a, 0);
}
TEST(wcfg_cat_resolve_path_invalid_arguments) {
    CSETUP(CryptCATAdminResolveCatalogPath); HCATADMIN a = acquire(); if (!a) { t_skip("no catalog admin context"); return; }
    if (t_is_wine()) { t_skip("emulator crashes/differs"); return; }
    CATALOG_INFO ci; WCHAR n[] = L"x.cat";
    ci.cbStruct = sizeof ci;
    SET_ERR(0); CHECK(!U(CryptCATAdminResolveCatalogPath)(NULL, n, &ci, 0)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!U(CryptCATAdminResolveCatalogPath)(a, NULL, &ci, 0)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!U(CryptCATAdminResolveCatalogPath)(a, n, NULL, 0)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!U(CryptCATAdminResolveCatalogPath)(a, n, &ci, 1)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    static const DWORD bad[] = { 0, 4, 0x20b, 0x20d, 0x400 };
    for (unsigned i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        ci.cbStruct = bad[i]; SET_ERR(0);
        CHECKF(!U(CryptCATAdminResolveCatalogPath)(a, n, &ci, 0), "cbStruct 0x%lx", bad[i]); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    }
    U(CryptCATAdminReleaseContext)(a, 0);
}

/* ------------------------------------------------------------------ AddCatalog argument validation (nothing is installed) */
static void write_file(const char *path, const void *data, DWORD n) {
    HANDLE h = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL); DWORD w;
    if (h == INVALID_HANDLE_VALUE) return;
    if (n) WriteFile(h, data, n, &w, NULL);
    CloseHandle(h);
}
TEST(wcfg_cat_add_invalid_arguments) {
    CSETUP(CryptCATAdminAddCatalog); HCATADMIN a = acquire(); if (!a) { t_skip("no catalog admin context"); return; }
    if (t_is_wine()) { t_skip("emulator differs"); U(CryptCATAdminReleaseContext)(a, 0); return; }
    char p[MAX_PATH]; t_tmpfile(p, sizeof p, "wcfg_notcat.txt"); write_file(p, "this is not a catalog\r\n", 23);
    wchar_t wp[MAX_PATH]; narrow2wide(p, wp, MAX_PATH);
    SET_ERR(0); CHECK(U(CryptCATAdminAddCatalog)(NULL, wp, NULL, 0) == NULL); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(U(CryptCATAdminAddCatalog)(a, NULL, NULL, 0) == NULL); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(U(CryptCATAdminAddCatalog)(a, wp, NULL, 2) == NULL); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(U(CryptCATAdminAddCatalog)(a, wp, NULL, 0x80000000) == NULL); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    U(CryptCATAdminReleaseContext)(a, 0);
    DeleteFileA(p);
}
TEST(wcfg_cat_add_missing_file) {
    CSETUP(CryptCATAdminAddCatalog); HCATADMIN a = acquire(); if (!a) { t_skip("no catalog admin context"); return; }
    if (t_is_wine()) { t_skip("emulator differs"); U(CryptCATAdminReleaseContext)(a, 0); return; }
    SET_ERR(0);
    CHECK(U(CryptCATAdminAddCatalog)(a, L"C:\\cryptt_no_such_dir\\none.cat", NULL, 0) == NULL);
    EXPECT_ERR(ERROR_BAD_FORMAT);                          /* missing directory: probed on Win10 */
    SET_ERR(0);
    CHECK(U(CryptCATAdminAddCatalog)(a, L"C:\\Windows\\cryptt_no_such_file.cat", NULL, 0) == NULL);
    EXPECT_ERR(ERROR_FILE_NOT_FOUND);                      /* existing directory, missing file */
    U(CryptCATAdminReleaseContext)(a, 0);
}
TEST(wcfg_cat_add_non_catalog_file_is_bad_format) {
    CSETUP(CryptCATAdminAddCatalog); HCATADMIN a = acquire(); if (!a) { t_skip("no catalog admin context"); return; }
    if (t_is_wine()) { t_skip("emulator differs"); U(CryptCATAdminReleaseContext)(a, 0); return; }
    char p[MAX_PATH]; wchar_t wp[MAX_PATH];
    t_tmpfile(p, sizeof p, "wcfg_text.cat"); write_file(p, "plain text", 10); narrow2wide(p, wp, MAX_PATH);
    SET_ERR(0); CHECK(U(CryptCATAdminAddCatalog)(a, wp, NULL, 0) == NULL); EXPECT_ERR(ERROR_BAD_FORMAT);
    DeleteFileA(p);
    t_tmpfile(p, sizeof p, "wcfg_empty.cat"); write_file(p, NULL, 0); narrow2wide(p, wp, MAX_PATH);
    SET_ERR(0); CHECK(U(CryptCATAdminAddCatalog)(a, wp, NULL, 0) == NULL); EXPECT_ERR(ERROR_BAD_FORMAT);
    DeleteFileA(p);
    t_tmpfile(p, sizeof p, "wcfg_der.cat"); write_file(p, "\x30\x03\x02\x01\x05", 5); narrow2wide(p, wp, MAX_PATH);   /* DER but not a CTL */
    SET_ERR(0); CHECK(U(CryptCATAdminAddCatalog)(a, wp, NULL, 0) == NULL); EXPECT_ERR(ERROR_BAD_FORMAT);
    DeleteFileA(p);
    U(CryptCATAdminReleaseContext)(a, 0);
}

/* ------------------------------------------------------------------ install / enumerate / resolve / remove */
static const char member_data[] = "cryptt catalog member: deterministic content 0123456789abcdef\r\n";

/* builds <tmp>\cryptt_<pid>.cat with one member (the hash of <tmp>\cryptt_member_<pid>.bin) */
typedef struct { char member[MAX_PATH], cat[MAX_PATH]; wchar_t wcat[MAX_PATH]; BYTE hash[64]; DWORD cbHash; wchar_t tag[130]; wchar_t leaf[64]; } catfix_t;
static int build_catalog(catfix_t *f, int tweak) {
    char leaf[64];
    sprintf(leaf, "cryptt_member_%lu_%d.bin", GetCurrentProcessId(), tweak);
    t_tmpfile(f->member, sizeof f->member, leaf);
    char data[200]; int n = sprintf(data, "%s%d\r\n", member_data, tweak);
    write_file(f->member, data, n);
    sprintf(leaf, "cryptt_%lu_%d.cat", GetCurrentProcessId(), tweak);
    t_tmpfile(f->cat, sizeof f->cat, leaf);
    narrow2wide(f->cat, f->wcat, MAX_PATH);
    narrow2wide(leaf, f->leaf, 64);
    DeleteFileA(f->cat);
    HANDLE h = CreateFileA(f->member, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return 0;
    f->cbHash = 0; t_label("calc-hash-size");
    BOOL ok = U(CryptCATAdminCalcHashFromFileHandle)(h, &f->cbHash, NULL, 0);
    if (!ok || !f->cbHash || f->cbHash > sizeof f->hash) { t_note("calc hash size query failed %d err %lu", ok, GetLastError()); CloseHandle(h); return 0; }
    t_label("calc-hash"); ok = U(CryptCATAdminCalcHashFromFileHandle)(h, &f->cbHash, f->hash, 0);
    CloseHandle(h);
    if (!ok) return 0;
    for (DWORD i = 0; i < f->cbHash; i++) swprintf(f->tag + 2 * i, 4, L"%02X", f->hash[i]);
    /* CryptCATPutMemberInfo takes a SIP_INDIRECT_DATA structure (the output of CryptSIPCreateIndirectData), not its encoding */
    static BYTE data_val[2] = { 0x30, 0x00 };
    static BYTE alg_par[2] = { 0x05, 0x00 };
    if (f->cbHash != 20) return 0;
    SIP_INDIRECT_DATA sid; memset(&sid, 0, sizeof sid);
    sid.Data.pszObjId = (LPSTR)"1.3.6.1.4.1.311.2.1.15"; sid.Data.Value.cbData = sizeof data_val; sid.Data.Value.pbData = data_val;
    sid.DigestAlgorithm.pszObjId = (LPSTR)"1.3.14.3.2.26"; sid.DigestAlgorithm.Parameters.cbData = sizeof alg_par; sid.DigestAlgorithm.Parameters.pbData = alg_par;
    sid.Digest.cbData = f->cbHash; sid.Digest.pbData = f->hash;
    t_label("cat-open"); HANDLE cat = U(CryptCATOpen)(f->wcat, CRYPTCAT_OPEN_CREATENEW, 0, CRYPTCAT_VERSION_1, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING);
    if (!cat || cat == INVALID_HANDLE_VALUE) { t_note("CryptCATOpen failed err %lu", GetLastError()); return 0; }
    GUID pe = { 0xC689AAB8, 0x8E78, 0x11D0, { 0x8C, 0x47, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE } };
    wchar_t mem[80]; narrow2wide(strrchr(f->member, '\\') + 1, mem, 80);
    t_label("put-member"); CRYPTCATMEMBER *m = U(CryptCATPutMemberInfo)(cat, mem, f->tag, &pe, 0x200, sizeof sid, (BYTE *)&sid);
    if (!m) t_note("PutMemberInfo failed err %lx", GetLastError());
    t_label("persist"); BOOL pers = m ? U(CryptCATPersistStore)(cat) : FALSE;
    if (m && !pers) t_note("PersistStore failed err %lx", GetLastError());
    t_label("close"); U(CryptCATClose)(cat); t_label(NULL);
    return m != NULL && pers && GetFileAttributesA(f->cat) != INVALID_FILE_ATTRIBUTES;
}
#define FIXSETUP(f, tw) REQUIRE(U(CryptCATAdminAddCatalog)); REQUIRE(U(CryptCATOpen)); REQUIRE(U(CryptCATPutMemberInfo)); \
    REQUIRE(U(CryptCATPersistStore)); REQUIRE(U(CryptCATAdminCalcHashFromFileHandle)); \
    if (!wcfg_begin_trust()) return; \
    catfix_t f; memset(&f, 0, sizeof f); \
    if (!build_catalog(&f, tw)) { t_skip("cannot build test catalog with CryptCAT APIs"); return; }

TEST(wcfg_cat_build_catalog_roundtrip) {
    REQUIRE(U(CryptCATOpen)); REQUIRE(U(CryptCATEnumerateMember)); REQUIRE(U(CryptCATAdminCalcHashFromFileHandle));
    REQUIRE(U(CryptCATPutMemberInfo)); REQUIRE(U(CryptCATPersistStore));
    catfix_t f; memset(&f, 0, sizeof f);
    if (!build_catalog(&f, 90)) { t_skip("cannot build test catalog"); return; }
    HANDLE c = U(CryptCATOpen)(f.wcat, CRYPTCAT_OPEN_EXISTING, 0, 0, 0);
    CHECK(c != NULL && c != INVALID_HANDLE_VALUE);
    if (c && c != INVALID_HANDLE_VALUE) {
        CRYPTCATMEMBER *m = U(CryptCATEnumerateMember)(c, NULL);
        CHECK(m != NULL);
        if (m) CHECK(!wcscmp(m->pwszReferenceTag, f.tag));
        if (m) CHECK(U(CryptCATEnumerateMember)(c, m) == NULL);
        U(CryptCATClose)(c);
    }
    DeleteFileA(f.cat); DeleteFileA(f.member);
}
TEST(wcfg_cat_add_enum_resolve_remove) {
    CSETUP(CryptCATAdminAddCatalog);
    FIXSETUP(f, 1);
    if (t_is_wine()) { t_skip("emulator catalog service differs"); DeleteFileA(f.cat); DeleteFileA(f.member); return; }
    HCATADMIN a = acquire(); if (!a) { t_skip("no catalog admin context"); goto out; }
    SET_ERR(0);
    HCATINFO ci = U(CryptCATAdminAddCatalog)(a, f.wcat, f.leaf, 0);
    if (!ci) {
        t_note("AddCatalog of the unsigned test catalog failed: error %lu (0x%lx)", GetLastError(), GetLastError());
        U(CryptCATAdminReleaseContext)(a, 0); goto out;
    }
    CATALOG_INFO info; memset(&info, 0, sizeof info); info.cbStruct = sizeof info;
    CHECK(U(CryptCATCatalogInfoFromContext)(ci, &info, 0));
    t_note("installed as %ls", info.wszCatalogFile);
    CHECK(info.wszCatalogFile[0] != 0);
    CHECK(GetFileAttributesW(info.wszCatalogFile) != INVALID_FILE_ATTRIBUTES);
    wchar_t *leaf = wcsrchr(info.wszCatalogFile, L'\\'); leaf = leaf ? leaf + 1 : info.wszCatalogFile;
    wchar_t installed_leaf[MAX_PATH]; wcscpy(installed_leaf, leaf);
    /* Resolve builds the same path from the leaf name */
    CATALOG_INFO rp; rp.cbStruct = sizeof rp;
    CHECK(U(CryptCATAdminResolveCatalogPath)(a, installed_leaf, &rp, 0));
    CHECK(!_wcsicmp(rp.wszCatalogFile, info.wszCatalogFile));
    /* the hash of the member finds it */
    HCATINFO e = U(CryptCATAdminEnumCatalogFromHash)(a, f.hash, f.cbHash, 0, NULL);
    CHECK(e != NULL);
    if (e) {
        CATALOG_INFO ei; memset(&ei, 0, sizeof ei); ei.cbStruct = sizeof ei;
        CHECK(U(CryptCATCatalogInfoFromContext)(e, &ei, 0));
        CHECK(!_wcsicmp(ei.wszCatalogFile, info.wszCatalogFile));
        HCATINFO e2 = U(CryptCATAdminEnumCatalogFromHash)(a, f.hash, f.cbHash, 0, &e);
        CHECK(e2 == NULL);
        if (e2) U(CryptCATAdminReleaseCatalogContext)(a, e2, 0);
    }
    /* a different hash is not found */
    BYTE other[20]; memcpy(other, f.hash, 20); other[0] ^= 0xFF;
    HCATINFO none = U(CryptCATAdminEnumCatalogFromHash)(a, other, 20, 0, NULL);
    CHECK(none == NULL);
    if (none) U(CryptCATAdminReleaseCatalogContext)(a, none, 0);
    CHECK(U(CryptCATAdminReleaseCatalogContext)(a, ci, 0));
    /* remove */
    SET_ERR(0);
    CHECK(U(CryptCATAdminRemoveCatalog)(a, installed_leaf, 0));
    /* observed on Win10 (stable across 10 polls over 5 s): the catalog file is deleted, but the hash database still
     * resolves the member hash to the removed catalog's path until the database is rebuilt */
    HCATINFO after = U(CryptCATAdminEnumCatalogFromHash)(a, f.hash, f.cbHash, 0, NULL);
    CHECK(after != NULL);
    if (after) {
        CATALOG_INFO ai; memset(&ai, 0, sizeof ai); ai.cbStruct = sizeof ai;
        CHECK(U(CryptCATCatalogInfoFromContext)(after, &ai, 0));
        CHECK(!_wcsicmp(ai.wszCatalogFile, info.wszCatalogFile));
        U(CryptCATAdminReleaseCatalogContext)(a, after, 0);
    }
    CHECK(GetFileAttributesW(info.wszCatalogFile) == INVALID_FILE_ATTRIBUTES);
    U(CryptCATAdminRemoveCatalog)(a, installed_leaf, 0);      /* belt and braces */
    U(CryptCATAdminReleaseContext)(a, 0);
out:
    DeleteFileA(f.cat); DeleteFileA(f.member);
    wcfg_end();
}
TEST(wcfg_cat_remove_unknown_catalog) {
    CSETUP(CryptCATAdminRemoveCatalog);
    if (!wcfg_begin_trust()) return;
    if (t_is_wine()) { t_skip("emulator differs"); return; }
    HCATADMIN a = acquire(); if (!a) { t_skip("no catalog admin context"); return; }
    char nm[64]; sprintf(nm, "cryptt_missing_%lu.cat", GetCurrentProcessId()); wchar_t w[64]; narrow2wide(nm, w, 64);
    SET_ERR(0);
    BOOL r = U(CryptCATAdminRemoveCatalog)(a, w, 0);
    t_note("RemoveCatalog of a catalog that is not installed: %d, error %lu", r, GetLastError());
    U(CryptCATAdminReleaseContext)(a, 0);
    wcfg_end();
}
TEST(wcfg_cat_add_twice_same_catalog) {
    CSETUP(CryptCATAdminAddCatalog);
    FIXSETUP(f, 2);
    if (t_is_wine()) { t_skip("emulator catalog service differs"); DeleteFileA(f.cat); DeleteFileA(f.member); return; }
    HCATADMIN a = acquire(); if (!a) { t_skip("no catalog admin context"); goto out; }
    HCATINFO c1 = U(CryptCATAdminAddCatalog)(a, f.wcat, f.leaf, 0);
    if (!c1) { t_note("AddCatalog failed: %lu", GetLastError()); U(CryptCATAdminReleaseContext)(a, 0); goto out; }
    CATALOG_INFO i1; memset(&i1, 0, sizeof i1); i1.cbStruct = sizeof i1;
    CHECK(U(CryptCATCatalogInfoFromContext)(c1, &i1, 0));
    HCATINFO c2 = U(CryptCATAdminAddCatalog)(a, f.wcat, f.leaf, 0);
    CHECK(c2 != NULL);
    if (c2) {
        CATALOG_INFO i2; memset(&i2, 0, sizeof i2); i2.cbStruct = sizeof i2;
        CHECK(U(CryptCATCatalogInfoFromContext)(c2, &i2, 0));
        t_note("same catalog added twice: '%ls' then '%ls'", i1.wszCatalogFile, i2.wszCatalogFile);
        wchar_t *l2 = wcsrchr(i2.wszCatalogFile, L'\\');
        if (l2 && _wcsicmp(i1.wszCatalogFile, i2.wszCatalogFile)) U(CryptCATAdminRemoveCatalog)(a, l2 + 1, 0);
        U(CryptCATAdminReleaseCatalogContext)(a, c2, 0);
    }
    wchar_t *l1 = wcsrchr(i1.wszCatalogFile, L'\\');
    if (l1) U(CryptCATAdminRemoveCatalog)(a, l1 + 1, 0);
    U(CryptCATAdminReleaseCatalogContext)(a, c1, 0);
    U(CryptCATAdminReleaseContext)(a, 0);
out:
    DeleteFileA(f.cat); DeleteFileA(f.member);
    wcfg_end();
}
TEST(wcfg_cat_catalog_info_from_context_invalid_arguments) {
    REQUIRE(U(CryptCATCatalogInfoFromContext));
    CATALOG_INFO ci; ci.cbStruct = sizeof ci;
    SET_ERR(0); CHECK(!U(CryptCATCatalogInfoFromContext)(NULL, &ci, 0)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!U(CryptCATCatalogInfoFromContext)((HCATINFO)&ci, NULL, 0)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
}
TEST(wcfg_cat_release_invalid_arguments) {
    CSETUP(CryptCATAdminReleaseCatalogContext); HCATADMIN a = acquire(); if (!a) { t_skip("no catalog admin context"); return; }
    SET_ERR(0); CHECK(!U(CryptCATAdminReleaseCatalogContext)(NULL, (HCATINFO)a, 0)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!U(CryptCATAdminReleaseCatalogContext)(a, NULL, 0)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    U(CryptCATAdminReleaseContext)(a, 0);
}
