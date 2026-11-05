/* CryptCATOpen/Close, CryptCATPut*, Enumerate*, Get* on catalogs held in memory. */
#include "cat_common.h"

#define NEED() do { REQUIRE(U(CryptCATOpen)); REQUIRE(U(CryptCATClose)); } while (0)
/* Wine implements Open/Close but stubs (or aborts on) most of the in-memory catalog object API. */
#define NO_WINE() do { if (t_is_wine()) { t_skip("catalog object API is a stub under Wine"); return; } } while (0)
#define NEED_MEM() do { NO_WINE(); NEED(); } while (0)

/* ---------------------------------------------------------------- open / close */
TEST(wtcat_open_null_filename)
{
    DWORD flags[] = { 0, CRYPTCAT_OPEN_CREATENEW, CRYPTCAT_OPEN_ALWAYS, CRYPTCAT_OPEN_EXISTING, 7,
                      CRYPTCAT_OPEN_SORTED, CRYPTCAT_OPEN_NO_CONTENT_HCRYPTMSG };
    size_t i;
    NEED();
    for (i = 0; i < sizeof flags / sizeof *flags; i++) {
        SET_ERR(0xdeadbeef);
        HANDLE h = U(CryptCATOpen)(NULL, flags[i], 0, 0, 0);
        CHECKF(h == INVH, "flags %#lx: h=%p", flags[i], h);
        EXPECT_ERR(ERROR_INVALID_PARAMETER);
    }
}

TEST(wtcat_open_createnew_makes_empty_file)
{
    WCHAR p[MAX_PATH]; HANDLE h;
    NEED(); wpath(p, "cn_empty.cat");
    DeleteFileW(p);
    SET_ERR(0);
    h = c_open(p, CRYPTCAT_OPEN_CREATENEW, 0, 0);
    CHECK(h != INVH && h != NULL);
    CHECK(fexists(p));
    EXPECT_EQ(fsize(p), 0);
    CHECK(c_close(h));
    /* closing without CryptCATPersistStore never writes anything */
    EXPECT_EQ(fsize(p), 0);
    DeleteFileW(p);
}

TEST(wtcat_open_createnew_truncates_existing)
{
    WCHAR p[MAX_PATH]; HANDLE h; char buf[100];
    NEED(); wpath(p, "cn_trunc.cat");
    memset(buf, 'x', sizeof buf);
    put_file(p, buf, sizeof buf);
    EXPECT_EQ(fsize(p), 100);
    h = c_open(p, CRYPTCAT_OPEN_CREATENEW, 0, 0);
    CHECK(h != INVH);
    EXPECT_EQ(fsize(p), 0);
    if (h != INVH) c_close(h);
    DeleteFileW(p);
}

TEST(wtcat_open_createnew_reopen_cycle)
{
    WCHAR p[MAX_PATH]; int i;
    NEED(); wpath(p, "cn_cycle.cat");
    for (i = 0; i < 5; i++) {
        HANDLE h = c_open(p, CRYPTCAT_OPEN_CREATENEW, 0, 0);
        CHECKF(h != INVH, "iteration %d err %lu", i, GetLastError());
        if (h != INVH) CHECK(c_close(h));
    }
    DeleteFileW(p);
}

TEST(wtcat_open_existing_missing_file)
{
    WCHAR p[MAX_PATH]; HANDLE h;
    NEED(); wpath(p, "ex_missing.cat");
    DeleteFileW(p);
    SET_ERR(0);
    h = c_open(p, CRYPTCAT_OPEN_EXISTING, 0, 0);
    CHECK(h == INVH);
    EXPECT_ERR(ERROR_FILE_NOT_FOUND);
    CHECK(!fexists(p));   /* EXISTING never creates */
}

TEST(wtcat_open_existing_missing_directory)
{
    WCHAR p[MAX_PATH]; HANDLE h;
    NEED(); wpath(p, "no_such_dir\\x.cat");
    SET_ERR(0);
    h = c_open(p, CRYPTCAT_OPEN_EXISTING, 0, 0);
    CHECK(h == INVH);
    EXPECT_ERR(ERROR_PATH_NOT_FOUND);
}

TEST(wtcat_open_createnew_missing_directory)
{
    WCHAR p[MAX_PATH]; HANDLE h;
    NEED(); wpath(p, "no_such_dir\\x.cat");
    SET_ERR(0);
    h = c_open(p, CRYPTCAT_OPEN_CREATENEW, 0, 0);
    CHECK(h == INVH);
    EXPECT_ERR(ERROR_PATH_NOT_FOUND);
}

TEST(wtcat_open_zero_flags_missing_note)
{
    WCHAR p[MAX_PATH]; HANDLE h;
    NEED(); wpath(p, "zero_flags.cat");
    DeleteFileW(p);
    SET_ERR(0);
    h = c_open(p, 0, 0, 0);
    t_note("CryptCATOpen(flags=0) on a missing file: handle %s, GLE %lu, file %s",
           h == INVH ? "INVALID" : "valid", GetLastError(), fexists(p) ? "created" : "not created");
    if (h != INVH) c_close(h);
    DeleteFileW(p);
}

TEST(wtcat_open_always_creates_missing)
{
    WCHAR p[MAX_PATH]; HANDLE h;
    NEED(); wpath(p, "always_new.cat");
    DeleteFileW(p);
    h = c_open(p, CRYPTCAT_OPEN_ALWAYS, 0, 0);
    CHECK(h != INVH);
    CHECK(fexists(p));
    EXPECT_EQ(fsize(p), 0);
    if (h != INVH) c_close(h);
    DeleteFileW(p);
}

TEST(wtcat_open_always_keeps_existing_content)
{
    WCHAR p[MAX_PATH]; HANDLE h;
    NEED(); wpath(p, "always_keep.cat");
    put_text(p, "test text");   /* 9 bytes: shorter than any catalog, treated as an empty store */
    h = c_open(p, CRYPTCAT_OPEN_ALWAYS, 0, 0);
    CHECK(h != INVH);
    if (h != INVH) c_close(h);
    EXPECT_EQ(fsize(p), 9);
    DeleteFileW(p);
}

TEST(wtcat_open_short_file_all_flag_combinations)
{
    DWORD flags[] = { CRYPTCAT_OPEN_CREATENEW, CRYPTCAT_OPEN_ALWAYS, CRYPTCAT_OPEN_EXISTING,
                      CRYPTCAT_OPEN_CREATENEW | CRYPTCAT_OPEN_ALWAYS, 3, 5, 6, 7 };
    size_t i;
    NEED();
    for (i = 0; i < sizeof flags / sizeof *flags; i++) {
        WCHAR p[MAX_PATH]; HANDLE h;
        wpath(p, "short.cat");
        put_text(p, "test text");
        SET_ERR(0);
        h = c_open(p, flags[i], 0, 0);
        CHECKF(h != INVH, "flags %#lx err %lu", flags[i], GetLastError());
        if (h != INVH) c_close(h);
        if (flags[i] & CRYPTCAT_OPEN_CREATENEW) EXPECT_EQ(fsize(p), 0);
        else EXPECT_EQ(fsize(p), 9);
        DeleteFileW(p);
    }
}

TEST(wtcat_open_nonempty_garbage_file_note)
{
    WCHAR p[MAX_PATH]; HANDLE h; char junk[64];
    NEED_MEM(); wpath(p, "garbage.cat");
    memset(junk, 'Z', sizeof junk);
    put_file(p, junk, sizeof junk);
    SET_ERR(0);
    h = c_open(p, CRYPTCAT_OPEN_EXISTING, 0, 0);
    t_note("EXISTING open of a 64-byte non-ASN.1 file: %s GLE %lu", h == INVH ? "INVALID_HANDLE_VALUE" : "handle", GetLastError());
    if (h != INVH) {
        t_note("members=%d catattrs=%d", count_members(h), count_cat_attrs(h));
        c_close(h);
    }
    DeleteFileW(p);
}

TEST(wtcat_open_store_defaults)
{
    WCHAR p[MAX_PATH]; HANDLE h; CATSTORE *s;
    NEED_MEM(); wpath(p, "defaults.cat");
    h = c_open(p, CRYPTCAT_OPEN_CREATENEW, 0, 0);
    REQUIRE(h != INVH);
    s = c_store(h);
    EXPECT_EQ(s->cbStruct, 0x40);
    EXPECT_EQ(s->dwPublicVersion, CRYPTCAT_VERSION_1);
    EXPECT_EQ(s->dwEncodingType, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING);
    EXPECT_EQ(s->fdwStoreFlags, 0);
    CHECK(s->pwszP7File != NULL && s->pwszP7File != p && !wcscmp(s->pwszP7File, p));
    CHECK(s->hProv != 0);   /* a default provider is acquired when none is passed */
    c_close(h); DeleteFileW(p);
}

TEST(wtcat_open_store_explicit_version_encoding)
{
    struct { DWORD ver, enc, wantver, wantenc; } t[] = {
        { CRYPTCAT_VERSION_1, 0, CRYPTCAT_VERSION_1, 0x10001 },
        { CRYPTCAT_VERSION_2, 0, CRYPTCAT_VERSION_2, 0x10001 },
        { 0, PKCS_7_ASN_ENCODING, CRYPTCAT_VERSION_1, PKCS_7_ASN_ENCODING },
        { 0, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, CRYPTCAT_VERSION_1, 0x10001 },
        { 0x300, 0x00020002, 0x300, 0x00020002 },   /* stored verbatim, not validated at open */
    };
    size_t i;
    NEED_MEM();
    for (i = 0; i < sizeof t / sizeof *t; i++) {
        WCHAR p[MAX_PATH]; HANDLE h;
        wpath(p, "verenc.cat");
        h = c_open(p, CRYPTCAT_OPEN_CREATENEW, t[i].ver, t[i].enc);
        CHECKF(h != INVH, "row %zu", i);
        if (h == INVH) continue;
        CHECKF(c_store(h)->dwPublicVersion == t[i].wantver, "row %zu ver %#lx", i, c_store(h)->dwPublicVersion);
        CHECKF(c_store(h)->dwEncodingType == t[i].wantenc, "row %zu enc %#lx", i, c_store(h)->dwEncodingType);
        c_close(h); DeleteFileW(p);
    }
}

TEST(wtcat_open_store_flags_high_word_only)
{
    struct { DWORD flags, want; } t[] = {
        { CRYPTCAT_OPEN_CREATENEW, 0 },
        { CRYPTCAT_OPEN_CREATENEW | CRYPTCAT_OPEN_EXCLUDE_PAGE_HASHES, CRYPTCAT_OPEN_EXCLUDE_PAGE_HASHES },
        { CRYPTCAT_OPEN_CREATENEW | CRYPTCAT_OPEN_INCLUDE_PAGE_HASHES, CRYPTCAT_OPEN_INCLUDE_PAGE_HASHES },
        { CRYPTCAT_OPEN_CREATENEW | CRYPTCAT_OPEN_NO_CONTENT_HCRYPTMSG, CRYPTCAT_OPEN_NO_CONTENT_HCRYPTMSG },
        { CRYPTCAT_OPEN_ALWAYS | CRYPTCAT_OPEN_VERIFYSIGHASH, CRYPTCAT_OPEN_VERIFYSIGHASH },
        { CRYPTCAT_OPEN_CREATENEW | 0x00000f00, 0 },   /* low-word bits other than 1/2/4 are dropped */
        { CRYPTCAT_OPEN_CREATENEW | CRYPTCAT_OPEN_EXCLUDE_PAGE_HASHES | CRYPTCAT_OPEN_INCLUDE_PAGE_HASHES,
          CRYPTCAT_OPEN_EXCLUDE_PAGE_HASHES | CRYPTCAT_OPEN_INCLUDE_PAGE_HASHES },
    };
    size_t i;
    NEED_MEM();
    for (i = 0; i < sizeof t / sizeof *t; i++) {
        WCHAR p[MAX_PATH]; HANDLE h;
        wpath(p, "flags.cat");
        h = c_open(p, t[i].flags, 0, 0);
        CHECKF(h != INVH, "row %zu flags %#lx", i, t[i].flags);
        if (h == INVH) continue;
        CHECKF(c_store(h)->fdwStoreFlags == t[i].want, "row %zu: %#lx", i, c_store(h)->fdwStoreFlags);
        c_close(h); DeleteFileW(p);
    }
}

TEST(wtcat_open_independent_handles)
{
    WCHAR p1[MAX_PATH], p2[MAX_PATH]; HANDLE h1, h2;
    NEED_MEM(); wpath(p1, "ind1.cat"); wpath(p2, "ind2.cat");
    h1 = c_open(p1, CRYPTCAT_OPEN_CREATENEW, 0, 0);
    h2 = c_open(p2, CRYPTCAT_OPEN_CREATENEW, 0, 0);
    REQUIRE(h1 != INVH && h2 != INVH);
    CHECK(h1 != h2);
    CHECK(U(CryptCATPutCatAttrInfo)(h1, L"OnlyInOne", CRYPTCAT_ATTR_DATAASCII | CRYPTCAT_ATTR_NAMEASCII, 2, (BYTE *)L"") != NULL);
    EXPECT_EQ(count_cat_attrs(h1), 1);
    EXPECT_EQ(count_cat_attrs(h2), 0);
    CHECK(c_close(h2)); CHECK(c_close(h1));
    DeleteFileW(p1); DeleteFileW(p2);
}

TEST(wtcat_close_invalid_handles)
{
    NEED();
    SET_ERR(0); CHECK(!U(CryptCATClose)(NULL)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!U(CryptCATClose)(INVH)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
}

TEST(wtcat_close_returns_true_for_populated_store)
{
    WCHAR p[MAX_PATH]; HANDLE h; int i;
    NEED_MEM(); wpath(p, "closepop.cat");
    h = c_open(p, CRYPTCAT_OPEN_CREATENEW, 0, 0);
    REQUIRE(h != INVH);
    for (i = 0; i < 5; i++) {
        WCHAR tag[16]; swprintf(tag, 16, L"T%d", i);
        CHECK(put_member(h, L"f.bin", tag, g_dig_a) != NULL);
        CHECK(U(CryptCATPutCatAttrInfo)(h, tag, CRYPTCAT_ATTR_DATAASCII | CRYPTCAT_ATTR_NAMEASCII, 4, (BYTE *)L"v") != NULL);
    }
    CHECK(c_close(h));
    DeleteFileW(p);
}

/* ---------------------------------------------------------------- handle <-> store */
TEST(wtcat_handle_store_identity)
{
    WCHAR p[MAX_PATH]; HANDLE h;
    NO_WINE(); REQUIRE(UN(CryptCATHandleFromStore)); REQUIRE(UN(CryptCATStoreFromHandle)); NEED();
    wpath(p, "hs.cat");
    h = c_open(p, CRYPTCAT_OPEN_CREATENEW, 0, 0);
    REQUIRE(h != INVH);
    CHECK(UN(CryptCATHandleFromStore)(h) == (void *)h);
    CHECK(UN(CryptCATStoreFromHandle)((void *)h) == h);
    c_close(h); DeleteFileW(p);
}

TEST(wtcat_handle_store_are_plain_casts)
{
    void *vals[] = { NULL, (void *)(ULONG_PTR)0x1000, (void *)(ULONG_PTR)-1, (void *)(ULONG_PTR)0x123456789ULL };
    size_t i;
    NO_WINE(); REQUIRE(UN(CryptCATHandleFromStore)); REQUIRE(UN(CryptCATStoreFromHandle));
    for (i = 0; i < sizeof vals / sizeof *vals; i++) {
        CHECK(UN(CryptCATHandleFromStore)((HANDLE)vals[i]) == vals[i]);
        CHECK(UN(CryptCATStoreFromHandle)(vals[i]) == (HANDLE)vals[i]);
    }
}

TEST(wtcat_handle_store_share_one_function)
{
    FARPROC a, b, c;
    NO_WINE();
    a = t_proc_in("wintrust.dll", "CryptCATHandleFromStore");
    b = t_proc_in("wintrust.dll", "CryptCATStoreFromHandle");
    c = t_proc_in("wintrust.dll", "WTHelperProvDataFromStateData");
    REQUIRE(a); REQUIRE(b);
    CHECK(a == b);
    if (c) t_note("WTHelperProvDataFromStateData %s the same code as CryptCATHandleFromStore", c == a ? "shares" : "does not share");
}

/* ---------------------------------------------------------------- catalog attributes */
#define ATTR_ASCII (CRYPTCAT_ATTR_DATAASCII | CRYPTCAT_ATTR_NAMEASCII)

TEST(wtcat_putcatattr_invalid_parameters)
{
    WCHAR p[MAX_PATH]; HANDLE h; BYTE data[4] = { 1, 2, 3, 4 };
    NEED_MEM(); REQUIRE(U(CryptCATPutCatAttrInfo)); wpath(p, "pca_inv.cat");
    h = c_open(p, CRYPTCAT_OPEN_CREATENEW, 0, 0); REQUIRE(h != INVH);
#define BAD(call) do { SET_ERR(0); CHECK((call) == NULL); EXPECT_ERR(ERROR_INVALID_PARAMETER); } while (0)
    BAD(U(CryptCATPutCatAttrInfo)(NULL, L"t", ATTR_ASCII, 4, data));
    BAD(U(CryptCATPutCatAttrInfo)(INVH, L"t", ATTR_ASCII, 4, data));
    BAD(U(CryptCATPutCatAttrInfo)(h, NULL, ATTR_ASCII, 4, data));
    BAD(U(CryptCATPutCatAttrInfo)(h, L"t", ATTR_ASCII, 4, NULL));          /* size without data */
    BAD(U(CryptCATPutCatAttrInfo)(h, L"t", CRYPTCAT_ATTR_NAMEASCII, 4, data));   /* no data-type bit */
    BAD(U(CryptCATPutCatAttrInfo)(h, L"t", 0, 4, data));
    BAD(U(CryptCATPutCatAttrInfo)(h, L"t", CRYPTCAT_ATTR_AUTHENTICATED, 4, data));
    BAD(U(CryptCATPutCatAttrInfo)(h, L"t", CRYPTCAT_ATTR_NAMEOBJID | CRYPTCAT_ATTR_NO_AUTO_COMPAT_ENTRY, 4, data));
#undef BAD
    EXPECT_EQ(count_cat_attrs(h), 0);
    c_close(h); DeleteFileW(p);
}

TEST(wtcat_putcatattr_ascii_fields)
{
    WCHAR p[MAX_PATH]; HANDLE h; CRYPTCATATTRIBUTE *a; BYTE data[6] = { 'a', 0, 'b', 0, 0, 0 };
    WCHAR tag[] = L"MyTag";
    NEED_MEM(); wpath(p, "pca_f.cat");
    h = c_open(p, CRYPTCAT_OPEN_CREATENEW, 0, 0); REQUIRE(h != INVH);
    a = U(CryptCATPutCatAttrInfo)(h, tag, ATTR_ASCII, sizeof data, data);
    REQUIRE(a != NULL);
    EXPECT_EQ(a->cbStruct, 0x28);
    CHECK(a->pwszReferenceTag != NULL && a->pwszReferenceTag != tag && !wcscmp(a->pwszReferenceTag, L"MyTag"));
    EXPECT_EQ(a->dwAttrTypeAndAction, ATTR_ASCII);
    EXPECT_EQ(a->cbValue, sizeof data);
    CHECK(a->pbValue != NULL && a->pbValue != data && !memcmp(a->pbValue, data, sizeof data));
    tag[0] = L'X'; data[0] = 'Z';   /* the store holds private copies */
    CHECK(!wcscmp(a->pwszReferenceTag, L"MyTag"));
    EXPECT_EQ(a->pbValue[0], 'a');
    c_close(h); DeleteFileW(p);
}

TEST(wtcat_putcatattr_no_data)
{
    WCHAR p[MAX_PATH]; HANDLE h; CRYPTCATATTRIBUTE *a;
    NEED_MEM(); wpath(p, "pca_nd.cat");
    h = c_open(p, CRYPTCAT_OPEN_CREATENEW, 0, 0); REQUIRE(h != INVH);
    a = U(CryptCATPutCatAttrInfo)(h, L"Empty", ATTR_ASCII, 0, NULL);
    REQUIRE(a != NULL);
    EXPECT_EQ(a->cbValue, 0);
    CHECK(a->pbValue == NULL);
    EXPECT_EQ(a->dwAttrTypeAndAction, ATTR_ASCII);
    c_close(h); DeleteFileW(p);
}

TEST(wtcat_putcatattr_flags_stored_verbatim)
{
    DWORD flags[] = {
        CRYPTCAT_ATTR_DATAASCII, CRYPTCAT_ATTR_DATAOBJID | CRYPTCAT_ATTR_NAMEOBJID,
        CRYPTCAT_ATTR_AUTHENTICATED | ATTR_ASCII, CRYPTCAT_ATTR_UNAUTHENTICATED | ATTR_ASCII,
        CRYPTCAT_ATTR_NO_AUTO_COMPAT_ENTRY | ATTR_ASCII, 0x30000 | 1,
    };
    WCHAR p[MAX_PATH]; HANDLE h; size_t i;
    NEED_MEM(); wpath(p, "pca_fl.cat");
    h = c_open(p, CRYPTCAT_OPEN_CREATENEW, 0, 0); REQUIRE(h != INVH);
    for (i = 0; i < sizeof flags / sizeof *flags; i++) {
        WCHAR tag[16]; CRYPTCATATTRIBUTE *a; swprintf(tag, 16, L"F%zu", i);
        a = U(CryptCATPutCatAttrInfo)(h, tag, flags[i], 2, (BYTE *)L"");
        CHECKF(a != NULL, "row %zu flags %#lx err %lu", i, flags[i], GetLastError());
        if (a) CHECKF(a->dwAttrTypeAndAction == flags[i], "row %zu got %#lx", i, a->dwAttrTypeAndAction);
    }
    c_close(h); DeleteFileW(p);
}

TEST(wtcat_putcatattr_dataobjid_decodes_string)
{
    WCHAR p[MAX_PATH]; HANDLE h; CRYPTCATATTRIBUTE *a;
    static const WCHAR b64[] = L"AQID";   /* base64 of 01 02 03 */
    NEED_MEM(); wpath(p, "pca_b64.cat");
    h = c_open(p, CRYPTCAT_OPEN_CREATENEW, 0, 0); REQUIRE(h != INVH);
    a = U(CryptCATPutCatAttrInfo)(h, L"Bin", CRYPTCAT_ATTR_DATAOBJID | CRYPTCAT_ATTR_NAMEASCII, 8, (BYTE *)b64);
    REQUIRE(a != NULL);
    EXPECT_EQ(a->cbValue, 3);
    if (a->pbValue && a->cbValue == 3) { EXPECT_EQ(a->pbValue[0], 1); EXPECT_EQ(a->pbValue[1], 2); EXPECT_EQ(a->pbValue[2], 3); }
    c_close(h); DeleteFileW(p);
}

TEST(wtcat_putcatattr_dataobjid_base64_longer)
{
    WCHAR p[MAX_PATH]; HANDLE h; CRYPTCATATTRIBUTE *a;
    NEED_MEM(); wpath(p, "pca_hex.cat");
    h = c_open(p, CRYPTCAT_OPEN_CREATENEW, 0, 0); REQUIRE(h != INVH);
    a = U(CryptCATPutCatAttrInfo)(h, L"Bin2", CRYPTCAT_ATTR_DATAOBJID | CRYPTCAT_ATTR_NAMEASCII, 16, (BYTE *)L"TWFuTWFu");
    REQUIRE(a != NULL);
    EXPECT_EQ(a->cbValue, 6);   /* "ManMan" */
    if (a->pbValue && a->cbValue == 6) CHECK(!memcmp(a->pbValue, "ManMan", 6));
    c_close(h); DeleteFileW(p);
}

TEST(wtcat_putcatattr_replace_existing)
{
    WCHAR p[MAX_PATH]; HANDLE h; CRYPTCATATTRIBUTE *a, *b; BYTE v1[4] = { 1, 1, 1, 1 }, v2[8] = { 9, 8, 7, 6, 5, 4, 3, 2 };
    NEED_MEM(); wpath(p, "pca_rep.cat");
    h = c_open(p, CRYPTCAT_OPEN_CREATENEW, 0, 0); REQUIRE(h != INVH);
    a = U(CryptCATPutCatAttrInfo)(h, L"Slot", ATTR_ASCII, sizeof v1, v1);
    REQUIRE(a != NULL);
    b = U(CryptCATPutCatAttrInfo)(h, L"Slot", CRYPTCAT_ATTR_DATAREPLACE, sizeof v2, v2);
    CHECK(b == a);   /* the existing attribute object is updated in place */
    if (b) {
        EXPECT_EQ(b->cbValue, sizeof v2);
        CHECK(b->pbValue && !memcmp(b->pbValue, v2, sizeof v2));
        EXPECT_EQ(b->dwAttrTypeAndAction, ATTR_ASCII);   /* flags of the original attribute remain */
    }
    EXPECT_EQ(count_cat_attrs(h), 1);
    c_close(h); DeleteFileW(p);
}

TEST(wtcat_putcatattr_replace_missing_tag)
{
    WCHAR p[MAX_PATH]; HANDLE h; BYTE v[2] = { 1, 2 };
    NEED_MEM(); wpath(p, "pca_repm.cat");
    h = c_open(p, CRYPTCAT_OPEN_CREATENEW, 0, 0); REQUIRE(h != INVH);
    CHECK(U(CryptCATPutCatAttrInfo)(h, L"Nope", CRYPTCAT_ATTR_DATAREPLACE, 2, v) == NULL);   /* empty store */
    CHECK(U(CryptCATPutCatAttrInfo)(h, L"Other", ATTR_ASCII, 2, v) != NULL);
    CHECK(U(CryptCATPutCatAttrInfo)(h, L"Nope", CRYPTCAT_ATTR_DATAREPLACE, 2, v) == NULL);
    EXPECT_EQ(count_cat_attrs(h), 1);
    c_close(h); DeleteFileW(p);
}

TEST(wtcat_putcatattr_replace_is_case_sensitive)
{
    WCHAR p[MAX_PATH]; HANDLE h; BYTE v[2] = { 1, 2 };
    NEED_MEM(); wpath(p, "pca_repc.cat");
    h = c_open(p, CRYPTCAT_OPEN_CREATENEW, 0, 0); REQUIRE(h != INVH);
    CHECK(U(CryptCATPutCatAttrInfo)(h, L"CaseTag", ATTR_ASCII, 2, v) != NULL);
    CHECK(U(CryptCATPutCatAttrInfo)(h, L"casetag", CRYPTCAT_ATTR_DATAREPLACE, 2, v) == NULL);
    CHECK(U(CryptCATPutCatAttrInfo)(h, L"CaseTag", CRYPTCAT_ATTR_DATAREPLACE, 2, v) != NULL);
    c_close(h); DeleteFileW(p);
}

TEST(wtcat_putcatattr_duplicates_allowed_without_replace)
{
    WCHAR p[MAX_PATH]; HANDLE h; CRYPTCATATTRIBUTE *a, *b; BYTE v[2] = { 1, 2 };
    NEED_MEM(); wpath(p, "pca_dup.cat");
    h = c_open(p, CRYPTCAT_OPEN_CREATENEW, 0, 0); REQUIRE(h != INVH);
    a = U(CryptCATPutCatAttrInfo)(h, L"Dup", ATTR_ASCII, 2, v);
    b = U(CryptCATPutCatAttrInfo)(h, L"Dup", ATTR_ASCII, 2, v);
    CHECK(a && b && a != b);
    EXPECT_EQ(count_cat_attrs(h), 2);
    c_close(h); DeleteFileW(p);
}

TEST(wtcat_putcatattr_many_attributes)
{
    WCHAR p[MAX_PATH]; HANDLE h; int i; int seen[200] = { 0 };
    CRYPTCATATTRIBUTE *a = NULL;
    NEED_MEM(); wpath(p, "pca_many.cat");
    h = c_open(p, CRYPTCAT_OPEN_CREATENEW, 0, 0); REQUIRE(h != INVH);
    for (i = 0; i < 150; i++) {
        WCHAR tag[24]; swprintf(tag, 24, L"Attr%03d", i);
        CHECKF(U(CryptCATPutCatAttrInfo)(h, tag, ATTR_ASCII, 2, (BYTE *)L"") != NULL, "i=%d", i);
    }
    while ((a = U(CryptCATEnumerateCatAttr)(h, a)) != NULL) {
        int n = a->pwszReferenceTag ? _wtoi(a->pwszReferenceTag + 4) : -1;
        if (n >= 0 && n < 150) seen[n]++;
    }
    for (i = 0; i < 150; i++) CHECKF(seen[i] == 1, "attr %d seen %d times", i, seen[i]);
    c_close(h); DeleteFileW(p);
}

TEST(wtcat_enumcatattr_empty_store)
{
    WCHAR p[MAX_PATH]; HANDLE h;
    NEED_MEM(); wpath(p, "eca_empty.cat");
    h = c_open(p, CRYPTCAT_OPEN_CREATENEW, 0, 0); REQUIRE(h != INVH);
    SET_ERR(0);
    CHECK(U(CryptCATEnumerateCatAttr)(h, NULL) == NULL);
    EXPECT_ERR(E_CRYPT_NOT_FOUND);
    c_close(h); DeleteFileW(p);
}

TEST(wtcat_enumcatattr_sequence_and_end)
{
    WCHAR p[MAX_PATH]; HANDLE h; CRYPTCATATTRIBUTE *a = NULL, *first = NULL; int i;
    NEED_MEM(); wpath(p, "eca_seq.cat");
    h = c_open(p, CRYPTCAT_OPEN_CREATENEW, 0, 0); REQUIRE(h != INVH);
    for (i = 0; i < 4; i++) {
        WCHAR tag[8]; swprintf(tag, 8, L"E%d", i);
        U(CryptCATPutCatAttrInfo)(h, tag, ATTR_ASCII, 2, (BYTE *)L"");
    }
    for (i = 0; i < 4; i++) {
        a = U(CryptCATEnumerateCatAttr)(h, a);
        CHECKF(a != NULL, "i=%d", i);
        if (!a) break;
        if (i == 0) first = a;
        EXPECT_EQ(a->dwReserved, i);   /* enumeration index is kept in dwReserved */
    }
    SET_ERR(0);
    CHECK(U(CryptCATEnumerateCatAttr)(h, a) == NULL);
    EXPECT_ERR(E_CRYPT_NOT_FOUND);
    /* restarting from NULL gives the same object again */
    CHECK(U(CryptCATEnumerateCatAttr)(h, NULL) == first);
    c_close(h); DeleteFileW(p);
}

TEST(wtcat_enumcatattr_invalid_parameters)
{
    WCHAR p[MAX_PATH]; HANDLE h; CRYPTCATATTRIBUTE fake;
    NEED_MEM(); wpath(p, "eca_inv.cat");
    h = c_open(p, CRYPTCAT_OPEN_CREATENEW, 0, 0); REQUIRE(h != INVH);
    U(CryptCATPutCatAttrInfo)(h, L"A", ATTR_ASCII, 2, (BYTE *)L"");
    SET_ERR(0); CHECK(U(CryptCATEnumerateCatAttr)(NULL, NULL) == NULL); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(U(CryptCATEnumerateCatAttr)(INVH, NULL) == NULL); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    memset(&fake, 0, sizeof fake); fake.cbStruct = 0x20;   /* too small to be an attribute */
    SET_ERR(0); CHECK(U(CryptCATEnumerateCatAttr)(h, &fake) == NULL); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    c_close(h); DeleteFileW(p);
}

TEST(wtcat_getcatattrinfo_lookup)
{
    WCHAR p[MAX_PATH]; HANDLE h; CRYPTCATATTRIBUTE *a, *b;
    NEED_MEM(); REQUIRE(U(CryptCATGetCatAttrInfo)); wpath(p, "gca.cat");
    h = c_open(p, CRYPTCAT_OPEN_CREATENEW, 0, 0); REQUIRE(h != INVH);
    U(CryptCATPutCatAttrInfo)(h, L"First", ATTR_ASCII, 2, (BYTE *)L"");
    a = U(CryptCATPutCatAttrInfo)(h, L"Second", ATTR_ASCII, 2, (BYTE *)L"");
    b = U(CryptCATGetCatAttrInfo)(h, L"Second");
    CHECK(b == a);
    CHECK(U(CryptCATGetCatAttrInfo)(h, L"First") != NULL);
    /* the tag comparison ignores case */
    CHECK(U(CryptCATGetCatAttrInfo)(h, L"SECOND") == a);
    CHECK(U(CryptCATGetCatAttrInfo)(h, L"second") == a);
    SET_ERR(0); CHECK(U(CryptCATGetCatAttrInfo)(h, L"Third") == NULL); EXPECT_ERR(E_CRYPT_NOT_FOUND);
    SET_ERR(0); CHECK(U(CryptCATGetCatAttrInfo)(h, L"Secon") == NULL); EXPECT_ERR(E_CRYPT_NOT_FOUND);
    SET_ERR(0); CHECK(U(CryptCATGetCatAttrInfo)(h, L"") == NULL); EXPECT_ERR(E_CRYPT_NOT_FOUND);
    c_close(h); DeleteFileW(p);
}

TEST(wtcat_getcatattrinfo_invalid_parameters)
{
    WCHAR p[MAX_PATH]; HANDLE h;
    NEED_MEM(); REQUIRE(U(CryptCATGetCatAttrInfo)); wpath(p, "gca_inv.cat");
    h = c_open(p, CRYPTCAT_OPEN_CREATENEW, 0, 0); REQUIRE(h != INVH);
    SET_ERR(0); CHECK(U(CryptCATGetCatAttrInfo)(NULL, L"x") == NULL); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(U(CryptCATGetCatAttrInfo)(INVH, L"x") == NULL); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(U(CryptCATGetCatAttrInfo)(h, NULL) == NULL); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    c_close(h); DeleteFileW(p);
}

TEST(wtcat_getcatattrinfo_duplicate_tag_returns_first)
{
    WCHAR p[MAX_PATH]; HANDLE h; CRYPTCATATTRIBUTE *a, *b;
    NEED_MEM(); REQUIRE(U(CryptCATGetCatAttrInfo)); wpath(p, "gca_dup.cat");
    h = c_open(p, CRYPTCAT_OPEN_CREATENEW, 0, 0); REQUIRE(h != INVH);
    a = U(CryptCATPutCatAttrInfo)(h, L"Dup", ATTR_ASCII, 2, (BYTE *)L"");
    b = U(CryptCATPutCatAttrInfo)(h, L"Dup", ATTR_ASCII, 2, (BYTE *)L"");
    REQUIRE(a && b);
    {
        CRYPTCATATTRIBUTE *f = U(CryptCATEnumerateCatAttr)(h, NULL);
        CHECK(U(CryptCATGetCatAttrInfo)(h, L"Dup") == f);   /* the first in enumeration order */
    }
    c_close(h); DeleteFileW(p);
}

TEST(wtcat_catattr_enumeration_order_note)
{
    WCHAR p[MAX_PATH]; HANDLE h; CRYPTCATATTRIBUTE *a = NULL; char order[64] = ""; int i;
    NEED_MEM(); wpath(p, "ord.cat");
    h = c_open(p, CRYPTCAT_OPEN_CREATENEW, 0, 0); REQUIRE(h != INVH);
    for (i = 0; i < 4; i++) { WCHAR tag[4]; swprintf(tag, 4, L"%c", 'A' + i); U(CryptCATPutCatAttrInfo)(h, tag, ATTR_ASCII, 2, (BYTE *)L""); }
    while ((a = U(CryptCATEnumerateCatAttr)(h, a)) != NULL) { size_t n = strlen(order); order[n] = (char)a->pwszReferenceTag[0]; order[n + 1] = 0; }
    t_note("enumeration order after Put A,B,C,D: %s", order);
    c_close(h); DeleteFileW(p);
}

/* ---------------------------------------------------------------- members */
TEST(wtcat_putmember_invalid_parameters)
{
    WCHAR p[MAX_PATH]; HANDLE h; SIP_INDIRECT_DATA d; GUID g = g_subj;
    NEED_MEM(); wpath(p, "pm_inv.cat");
    h = c_open(p, CRYPTCAT_OPEN_CREATENEW, 0, 0); REQUIRE(h != INVH);
    mk_ind(&d, g_dig_a, 20);
#define BAD(call) do { SET_ERR(0); CHECK((call) == NULL); EXPECT_ERR(ERROR_INVALID_PARAMETER); } while (0)
    BAD(U(CryptCATPutMemberInfo)(NULL, L"f", L"t", &g, 0x200, sizeof d, (BYTE *)&d));
    BAD(U(CryptCATPutMemberInfo)(INVH, L"f", L"t", &g, 0x200, sizeof d, (BYTE *)&d));
    BAD(U(CryptCATPutMemberInfo)(h, L"f", NULL, &g, 0x200, sizeof d, (BYTE *)&d));
    BAD(U(CryptCATPutMemberInfo)(h, L"f", L"t", NULL, 0x200, sizeof d, (BYTE *)&d));
    BAD(U(CryptCATPutMemberInfo)(h, L"f", L"t", &g, 0x200, sizeof d, NULL));
    BAD(U(CryptCATPutMemberInfo)(h, L"f", L"t", &g, 0x200, 0, NULL));
#undef BAD
    EXPECT_EQ(count_members(h), 0);
    c_close(h); DeleteFileW(p);
}

TEST(wtcat_putmember_reference_tag_length_limit)
{
    WCHAR p[MAX_PATH], tag[200]; HANDLE h; SIP_INDIRECT_DATA d; GUID g = g_subj; int i;
    NEED_MEM(); wpath(p, "pm_len.cat");
    h = c_open(p, CRYPTCAT_OPEN_CREATENEW, 0, 0); REQUIRE(h != INVH);
    mk_ind(&d, g_dig_a, 20);
    for (i = 0; i < 199; i++) tag[i] = L'a';
    tag[199] = 0;
    tag[127] = 0;   /* 127 chars */
    CHECK(U(CryptCATPutMemberInfo)(h, L"f", tag, &g, 0x200, sizeof d, (BYTE *)&d) != NULL);
    tag[127] = L'a'; tag[128] = 0;   /* exactly 128 chars */
    CHECK(U(CryptCATPutMemberInfo)(h, L"f", tag, &g, 0x200, sizeof d, (BYTE *)&d) != NULL);
    tag[128] = L'a'; tag[129] = 0;   /* 129 chars */
    SET_ERR(0);
    CHECK(U(CryptCATPutMemberInfo)(h, L"f", tag, &g, 0x200, sizeof d, (BYTE *)&d) == NULL);
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
    tag[0] = 0;   /* the empty tag is accepted */
    CHECK(U(CryptCATPutMemberInfo)(h, L"f", tag, &g, 0x200, sizeof d, (BYTE *)&d) != NULL);
    EXPECT_EQ(count_members(h), 3);
    c_close(h); DeleteFileW(p);
}

TEST(wtcat_putmember_fields)
{
    WCHAR p[MAX_PATH], file[] = L"dir\\file.bin", tag[] = L"TAG1"; HANDLE h; CRYPTCATMEMBER *m; SIP_INDIRECT_DATA d; GUID g = g_subj;
    NEED_MEM(); wpath(p, "pm_f.cat");
    h = c_open(p, CRYPTCAT_OPEN_CREATENEW, 0, 0); REQUIRE(h != INVH);
    mk_ind(&d, g_dig_a, 20);
    m = U(CryptCATPutMemberInfo)(h, file, tag, &g, 0x200, sizeof d, (BYTE *)&d);
    REQUIRE(m != NULL);
    EXPECT_EQ(m->cbStruct, 0x68);
    CHECK(m->pwszReferenceTag && m->pwszReferenceTag != tag && !wcscmp(m->pwszReferenceTag, L"TAG1"));
    CHECK(m->pwszFileName && m->pwszFileName != file && !wcscmp(m->pwszFileName, L"dir\\file.bin"));
    CHECK(!memcmp(&m->gSubjectType, &g_subj, sizeof(GUID)));
    EXPECT_EQ(m->dwCertVersion, 0x200);
    EXPECT_EQ(m->fdwMemberFlags, 0);
    CHECK(m->pIndirectData != NULL);
    file[0] = L'X'; tag[0] = L'X';
    CHECK(!wcscmp(m->pwszFileName, L"dir\\file.bin"));
    CHECK(!wcscmp(m->pwszReferenceTag, L"TAG1"));
    c_close(h); DeleteFileW(p);
}

TEST(wtcat_putmember_null_filename)
{
    WCHAR p[MAX_PATH]; HANDLE h; CRYPTCATMEMBER *m;
    NEED_MEM(); wpath(p, "pm_nf.cat");
    h = c_open(p, CRYPTCAT_OPEN_CREATENEW, 0, 0); REQUIRE(h != INVH);
    m = put_member(h, NULL, L"NoFile", g_dig_a);
    REQUIRE(m != NULL);
    CHECK(m->pwszFileName == NULL);
    CHECK(m->pwszReferenceTag && !wcscmp(m->pwszReferenceTag, L"NoFile"));
    c_close(h); DeleteFileW(p);
}

TEST(wtcat_putmember_deep_copies_indirect_data)
{
    WCHAR p[MAX_PATH]; HANDLE h; CRYPTCATMEMBER *m; SIP_INDIRECT_DATA d; GUID g = g_subj; BYTE dig[20];
    NEED_MEM(); wpath(p, "pm_deep.cat");
    h = c_open(p, CRYPTCAT_OPEN_CREATENEW, 0, 0); REQUIRE(h != INVH);
    memcpy(dig, g_dig_a, 20);
    mk_ind(&d, dig, 20);
    m = U(CryptCATPutMemberInfo)(h, L"f", L"deep", &g, 0x200, sizeof d, (BYTE *)&d);
    REQUIRE(m && m->pIndirectData);
    CHECK((void *)m->pIndirectData != (void *)&d);
    CHECK(m->pIndirectData->Digest.pbData != dig);
    memset(dig, 0xee, 20); g_ind_value[0] = 0x31;
    CHECK(m->pIndirectData->Data.pszObjId && !strcmp(m->pIndirectData->Data.pszObjId, g_ind_oid));
    EXPECT_EQ(m->pIndirectData->Data.Value.cbData, 2);
    CHECK(m->pIndirectData->Data.Value.pbData && m->pIndirectData->Data.Value.pbData[0] == 0x30);
    CHECK(m->pIndirectData->DigestAlgorithm.pszObjId && !strcmp(m->pIndirectData->DigestAlgorithm.pszObjId, g_alg_sha1));
    /* the copy routine carries the object id, value and digest; the algorithm parameters are not duplicated */
    EXPECT_EQ(m->pIndirectData->DigestAlgorithm.Parameters.cbData, 0);
    CHECK(m->pIndirectData->DigestAlgorithm.Parameters.pbData == NULL);
    EXPECT_EQ(m->pIndirectData->Digest.cbData, 20);
    CHECK(m->pIndirectData->Digest.pbData && !memcmp(m->pIndirectData->Digest.pbData, g_dig_a, 20));
    g_ind_value[0] = 0x30;
    c_close(h); DeleteFileW(p);
}

TEST(wtcat_putmember_zero_size_indirect_data)
{
    WCHAR p[MAX_PATH]; HANDLE h; CRYPTCATMEMBER *m; SIP_INDIRECT_DATA d; GUID g = g_subj;
    NEED_MEM(); wpath(p, "pm_zero.cat");
    h = c_open(p, CRYPTCAT_OPEN_CREATENEW, 0, 0); REQUIRE(h != INVH);
    mk_ind(&d, g_dig_a, 20);
    m = U(CryptCATPutMemberInfo)(h, L"f", L"nosip", &g, 0x100, 0, (BYTE *)&d);   /* size 0: nothing is copied */
    REQUIRE(m != NULL);
    CHECK(m->pIndirectData == NULL);
    EXPECT_EQ(m->dwCertVersion, 0x100);
    c_close(h); DeleteFileW(p);
}

TEST(wtcat_putmember_indirect_data_without_value_or_params)
{
    WCHAR p[MAX_PATH]; HANDLE h; CRYPTCATMEMBER *m; SIP_INDIRECT_DATA d; GUID g = g_subj;
    NEED_MEM(); wpath(p, "pm_nov.cat");
    h = c_open(p, CRYPTCAT_OPEN_CREATENEW, 0, 0); REQUIRE(h != INVH);
    mk_ind(&d, g_dig_a, 20);
    d.Data.Value.cbData = 0; d.Data.Value.pbData = NULL;
    d.DigestAlgorithm.Parameters.cbData = 0; d.DigestAlgorithm.Parameters.pbData = NULL;
    m = U(CryptCATPutMemberInfo)(h, L"f", L"bare", &g, 0x200, sizeof d, (BYTE *)&d);
    REQUIRE(m && m->pIndirectData);
    CHECK(m->pIndirectData->Data.Value.pbData == NULL);
    CHECK(m->pIndirectData->DigestAlgorithm.Parameters.pbData == NULL);
    CHECK(m->pIndirectData->Digest.pbData && !memcmp(m->pIndirectData->Digest.pbData, g_dig_a, 20));
    c_close(h); DeleteFileW(p);
}

TEST(wtcat_enummember_empty_store)
{
    WCHAR p[MAX_PATH]; HANDLE h;
    NEED_MEM(); wpath(p, "em_empty.cat");
    h = c_open(p, CRYPTCAT_OPEN_CREATENEW, 0, 0); REQUIRE(h != INVH);
    CHECK(U(CryptCATEnumerateMember)(h, NULL) == NULL);
    c_close(h); DeleteFileW(p);
}

TEST(wtcat_enummember_sequence)
{
    WCHAR p[MAX_PATH]; HANDLE h; CRYPTCATMEMBER *m = NULL, *put[3]; int i;
    NEED_MEM(); wpath(p, "em_seq.cat");
    h = c_open(p, CRYPTCAT_OPEN_CREATENEW, 0, 0); REQUIRE(h != INVH);
    for (i = 0; i < 3; i++) { WCHAR tag[8]; swprintf(tag, 8, L"M%d", i); put[i] = put_member(h, L"f", tag, g_dig_a); REQUIRE(put[i]); }
    for (i = 0; i < 3; i++) {
        m = U(CryptCATEnumerateMember)(h, m);
        CHECKF(m != NULL, "i=%d", i);
        if (!m) break;
        EXPECT_EQ(m->dwReserved, i);
        CHECK(m == put[0] || m == put[1] || m == put[2]);   /* enumeration returns the stored objects */
    }
    CHECK(m && U(CryptCATEnumerateMember)(h, m) == NULL);
    EXPECT_EQ(count_members(h), 3);
    c_close(h); DeleteFileW(p);
}

TEST(wtcat_enummember_invalid_parameters)
{
    WCHAR p[MAX_PATH]; HANDLE h; CRYPTCATMEMBER fake;
    NEED_MEM(); wpath(p, "em_inv.cat");
    h = c_open(p, CRYPTCAT_OPEN_CREATENEW, 0, 0); REQUIRE(h != INVH);
    put_member(h, L"f", L"T", g_dig_a);
    SET_ERR(0); CHECK(U(CryptCATEnumerateMember)(NULL, NULL) == NULL); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(U(CryptCATEnumerateMember)(INVH, NULL) == NULL); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    memset(&fake, 0, sizeof fake); fake.cbStruct = 0x40;
    SET_ERR(0); CHECK(U(CryptCATEnumerateMember)(h, &fake) == NULL); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    c_close(h); DeleteFileW(p);
}

TEST(wtcat_getmemberinfo_lookup)
{
    WCHAR p[MAX_PATH]; HANDLE h; CRYPTCATMEMBER *a, *b;
    NEED_MEM(); REQUIRE(U(CryptCATGetMemberInfo)); wpath(p, "gm.cat");
    h = c_open(p, CRYPTCAT_OPEN_CREATENEW, 0, 0); REQUIRE(h != INVH);
    a = put_member(h, L"a.bin", L"AAAA", g_dig_a);
    b = put_member(h, L"b.bin", L"BBBB", g_dig_b);
    REQUIRE(a && b);
    CHECK(U(CryptCATGetMemberInfo)(h, L"AAAA") == a);
    CHECK(U(CryptCATGetMemberInfo)(h, L"BBBB") == b);
    SET_ERR(0);
    CHECK(U(CryptCATGetMemberInfo)(h, L"CCCC") == NULL);
    t_note("GetMemberInfo of an unknown tag sets GLE %#lx", GetLastError());
    c_close(h); DeleteFileW(p);
}

TEST(wtcat_getmemberinfo_invalid_parameters)
{
    WCHAR p[MAX_PATH]; HANDLE h;
    NEED_MEM(); REQUIRE(U(CryptCATGetMemberInfo)); wpath(p, "gm_inv.cat");
    h = c_open(p, CRYPTCAT_OPEN_CREATENEW, 0, 0); REQUIRE(h != INVH);
    SET_ERR(0); CHECK(U(CryptCATGetMemberInfo)(NULL, L"x") == NULL); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(U(CryptCATGetMemberInfo)(INVH, L"x") == NULL); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(U(CryptCATGetMemberInfo)(h, NULL) == NULL); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    c_close(h); DeleteFileW(p);
}

/* ---------------------------------------------------------------- member attributes */
TEST(wtcat_putattrinfo_invalid_parameters)
{
    WCHAR p[MAX_PATH]; HANDLE h; CRYPTCATMEMBER *m, fake; BYTE data[4] = { 1, 2, 3, 4 };
    NEED_MEM(); REQUIRE(U(CryptCATPutAttrInfo)); wpath(p, "pa_inv.cat");
    h = c_open(p, CRYPTCAT_OPEN_CREATENEW, 0, 0); REQUIRE(h != INVH);
    m = put_member(h, L"f", L"T", g_dig_a); REQUIRE(m);
    memset(&fake, 0, sizeof fake); fake.cbStruct = 0x40;
#define BAD(call) do { SET_ERR(0); CHECK((call) == NULL); EXPECT_ERR(ERROR_INVALID_PARAMETER); } while (0)
    BAD(U(CryptCATPutAttrInfo)(NULL, m, L"t", ATTR_ASCII, 4, data));
    BAD(U(CryptCATPutAttrInfo)(INVH, m, L"t", ATTR_ASCII, 4, data));
    BAD(U(CryptCATPutAttrInfo)(h, NULL, L"t", ATTR_ASCII, 4, data));
    BAD(U(CryptCATPutAttrInfo)(h, &fake, L"t", ATTR_ASCII, 4, data));      /* member struct too small */
    BAD(U(CryptCATPutAttrInfo)(h, m, NULL, ATTR_ASCII, 4, data));
    BAD(U(CryptCATPutAttrInfo)(h, m, L"t", ATTR_ASCII, 4, NULL));
    BAD(U(CryptCATPutAttrInfo)(h, m, L"t", CRYPTCAT_ATTR_NAMEASCII, 4, data));
    BAD(U(CryptCATPutAttrInfo)(h, m, L"t", 0, 4, data));
    BAD(U(CryptCATPutAttrInfo)(h, m, L"t", CRYPTCAT_ATTR_DATAREPLACE, 4, data));   /* replace is not valid for members */
#undef BAD
    EXPECT_EQ(count_attrs(h, m), 0);
    c_close(h); DeleteFileW(p);
}

TEST(wtcat_putattrinfo_fields_and_copy)
{
    WCHAR p[MAX_PATH]; HANDLE h; CRYPTCATMEMBER *m; CRYPTCATATTRIBUTE *a; BYTE data[6] = { 'h', 0, 'i', 0, 0, 0 };
    NEED_MEM(); REQUIRE(U(CryptCATPutAttrInfo)); wpath(p, "pa_f.cat");
    h = c_open(p, CRYPTCAT_OPEN_CREATENEW, 0, 0); REQUIRE(h != INVH);
    m = put_member(h, L"f", L"T", g_dig_a); REQUIRE(m);
    a = U(CryptCATPutAttrInfo)(h, m, L"File", ATTR_ASCII | CRYPTCAT_ATTR_AUTHENTICATED, sizeof data, data);
    REQUIRE(a != NULL);
    EXPECT_EQ(a->cbStruct, 0x28);
    CHECK(a->pwszReferenceTag && !wcscmp(a->pwszReferenceTag, L"File"));
    EXPECT_EQ(a->dwAttrTypeAndAction, ATTR_ASCII | CRYPTCAT_ATTR_AUTHENTICATED);
    EXPECT_EQ(a->cbValue, sizeof data);
    CHECK(a->pbValue && a->pbValue != data && !memcmp(a->pbValue, data, sizeof data));
    EXPECT_EQ(count_attrs(h, m), 1);
    EXPECT_EQ(count_cat_attrs(h), 0);   /* member attributes are not catalog attributes */
    c_close(h); DeleteFileW(p);
}

TEST(wtcat_putattrinfo_no_data)
{
    WCHAR p[MAX_PATH]; HANDLE h; CRYPTCATMEMBER *m; CRYPTCATATTRIBUTE *a;
    NEED_MEM(); REQUIRE(U(CryptCATPutAttrInfo)); wpath(p, "pa_nd.cat");
    h = c_open(p, CRYPTCAT_OPEN_CREATENEW, 0, 0); REQUIRE(h != INVH);
    m = put_member(h, L"f", L"T", g_dig_a); REQUIRE(m);
    a = U(CryptCATPutAttrInfo)(h, m, L"Nothing", ATTR_ASCII, 0, NULL);
    REQUIRE(a != NULL);
    EXPECT_EQ(a->cbValue, 0);
    CHECK(a->pbValue == NULL);
    c_close(h); DeleteFileW(p);
}

TEST(wtcat_putattrinfo_dataobjid_decodes_string)
{
    WCHAR p[MAX_PATH]; HANDLE h; CRYPTCATMEMBER *m; CRYPTCATATTRIBUTE *a;
    NEED_MEM(); REQUIRE(U(CryptCATPutAttrInfo)); wpath(p, "pa_b64.cat");
    h = c_open(p, CRYPTCAT_OPEN_CREATENEW, 0, 0); REQUIRE(h != INVH);
    m = put_member(h, L"f", L"T", g_dig_a); REQUIRE(m);
    a = U(CryptCATPutAttrInfo)(h, m, L"Bin", CRYPTCAT_ATTR_DATAOBJID | CRYPTCAT_ATTR_NAMEASCII, 8, (BYTE *)L"AQID");
    REQUIRE(a != NULL);
    EXPECT_EQ(a->cbValue, 3);
    if (a->pbValue && a->cbValue == 3) CHECK(a->pbValue[0] == 1 && a->pbValue[1] == 2 && a->pbValue[2] == 3);
    c_close(h); DeleteFileW(p);
}

TEST(wtcat_putattrinfo_duplicates_are_kept)
{
    WCHAR p[MAX_PATH]; HANDLE h; CRYPTCATMEMBER *m;
    NEED_MEM(); REQUIRE(U(CryptCATPutAttrInfo)); wpath(p, "pa_dup.cat");
    h = c_open(p, CRYPTCAT_OPEN_CREATENEW, 0, 0); REQUIRE(h != INVH);
    m = put_member(h, L"f", L"T", g_dig_a); REQUIRE(m);
    CHECK(U(CryptCATPutAttrInfo)(h, m, L"D", ATTR_ASCII, 2, (BYTE *)L"") != NULL);
    CHECK(U(CryptCATPutAttrInfo)(h, m, L"D", ATTR_ASCII, 2, (BYTE *)L"") != NULL);
    EXPECT_EQ(count_attrs(h, m), 2);
    c_close(h); DeleteFileW(p);
}

TEST(wtcat_member_attributes_are_per_member)
{
    WCHAR p[MAX_PATH]; HANDLE h; CRYPTCATMEMBER *m1, *m2;
    NEED_MEM(); REQUIRE(U(CryptCATPutAttrInfo)); wpath(p, "pa_per.cat");
    h = c_open(p, CRYPTCAT_OPEN_CREATENEW, 0, 0); REQUIRE(h != INVH);
    m1 = put_member(h, L"1", L"T1", g_dig_a); m2 = put_member(h, L"2", L"T2", g_dig_b);
    REQUIRE(m1 && m2);
    U(CryptCATPutAttrInfo)(h, m1, L"A", ATTR_ASCII, 2, (BYTE *)L"");
    U(CryptCATPutAttrInfo)(h, m1, L"B", ATTR_ASCII, 2, (BYTE *)L"");
    U(CryptCATPutAttrInfo)(h, m2, L"C", ATTR_ASCII, 2, (BYTE *)L"");
    EXPECT_EQ(count_attrs(h, m1), 2);
    EXPECT_EQ(count_attrs(h, m2), 1);
    CHECK(U(CryptCATGetAttrInfo)(h, m1, L"A") != NULL);
    CHECK(U(CryptCATGetAttrInfo)(h, m2, L"A") == NULL);
    CHECK(U(CryptCATGetAttrInfo)(h, m2, L"C") != NULL);
    c_close(h); DeleteFileW(p);
}

TEST(wtcat_enumattr_member_without_attributes)
{
    WCHAR p[MAX_PATH]; HANDLE h; CRYPTCATMEMBER *m;
    NEED_MEM(); wpath(p, "ea_none.cat");
    h = c_open(p, CRYPTCAT_OPEN_CREATENEW, 0, 0); REQUIRE(h != INVH);
    m = put_member(h, L"f", L"T", g_dig_a); REQUIRE(m);
    CHECK(U(CryptCATEnumerateAttr)(h, m, NULL) == NULL);
    c_close(h); DeleteFileW(p);
}

TEST(wtcat_enumattr_sequence_dwreserved)
{
    WCHAR p[MAX_PATH]; HANDLE h; CRYPTCATMEMBER *m; CRYPTCATATTRIBUTE *a = NULL; int i;
    NEED_MEM(); wpath(p, "ea_seq.cat");
    h = c_open(p, CRYPTCAT_OPEN_CREATENEW, 0, 0); REQUIRE(h != INVH);
    m = put_member(h, L"f", L"T", g_dig_a); REQUIRE(m);
    for (i = 0; i < 5; i++) { WCHAR tag[8]; swprintf(tag, 8, L"a%d", i); U(CryptCATPutAttrInfo)(h, m, tag, ATTR_ASCII, 2, (BYTE *)L""); }
    for (i = 0; i < 5; i++) {
        a = U(CryptCATEnumerateAttr)(h, m, a);
        CHECKF(a != NULL, "i=%d", i);
        if (!a) break;
        EXPECT_EQ(a->dwReserved, i);
    }
    CHECK(a && U(CryptCATEnumerateAttr)(h, m, a) == NULL);
    c_close(h); DeleteFileW(p);
}

TEST(wtcat_enumattr_invalid_parameters)
{
    WCHAR p[MAX_PATH]; HANDLE h; CRYPTCATMEMBER *m, fakem; CRYPTCATATTRIBUTE fakea;
    NEED_MEM(); wpath(p, "ea_inv.cat");
    h = c_open(p, CRYPTCAT_OPEN_CREATENEW, 0, 0); REQUIRE(h != INVH);
    m = put_member(h, L"f", L"T", g_dig_a); REQUIRE(m);
    U(CryptCATPutAttrInfo)(h, m, L"a", ATTR_ASCII, 2, (BYTE *)L"");
    memset(&fakem, 0, sizeof fakem); fakem.cbStruct = 0x40;
    memset(&fakea, 0, sizeof fakea); fakea.cbStruct = 0x20;
    SET_ERR(0); CHECK(U(CryptCATEnumerateAttr)(NULL, m, NULL) == NULL); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(U(CryptCATEnumerateAttr)(INVH, m, NULL) == NULL); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(U(CryptCATEnumerateAttr)(h, NULL, NULL) == NULL); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(U(CryptCATEnumerateAttr)(h, &fakem, NULL) == NULL); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(U(CryptCATEnumerateAttr)(h, m, &fakea) == NULL); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    c_close(h); DeleteFileW(p);
}

TEST(wtcat_getattrinfo_lookup)
{
    WCHAR p[MAX_PATH]; HANDLE h; CRYPTCATMEMBER *m; CRYPTCATATTRIBUTE *a;
    NEED_MEM(); REQUIRE(U(CryptCATGetAttrInfo)); wpath(p, "ga.cat");
    h = c_open(p, CRYPTCAT_OPEN_CREATENEW, 0, 0); REQUIRE(h != INVH);
    m = put_member(h, L"f", L"T", g_dig_a); REQUIRE(m);
    U(CryptCATPutAttrInfo)(h, m, L"Alpha", ATTR_ASCII, 2, (BYTE *)L"");
    a = U(CryptCATPutAttrInfo)(h, m, L"Beta", ATTR_ASCII, 2, (BYTE *)L"");
    CHECK(U(CryptCATGetAttrInfo)(h, m, L"Beta") == a);
    CHECK(U(CryptCATGetAttrInfo)(h, m, L"bETA") == a);   /* case-insensitive */
    CHECK(U(CryptCATGetAttrInfo)(h, m, L"Alpha") != NULL);
    SET_ERR(0); CHECK(U(CryptCATGetAttrInfo)(h, m, L"Gamma") == NULL); EXPECT_ERR(E_CRYPT_NOT_FOUND);
    c_close(h); DeleteFileW(p);
}

TEST(wtcat_getattrinfo_invalid_parameters)
{
    WCHAR p[MAX_PATH]; HANDLE h; CRYPTCATMEMBER *m, fake;
    NEED_MEM(); REQUIRE(U(CryptCATGetAttrInfo)); wpath(p, "ga_inv.cat");
    h = c_open(p, CRYPTCAT_OPEN_CREATENEW, 0, 0); REQUIRE(h != INVH);
    m = put_member(h, L"f", L"T", g_dig_a); REQUIRE(m);
    memset(&fake, 0, sizeof fake); fake.cbStruct = 0x40;
    SET_ERR(0); CHECK(U(CryptCATGetAttrInfo)(NULL, m, L"x") == NULL); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(U(CryptCATGetAttrInfo)(INVH, m, L"x") == NULL); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(U(CryptCATGetAttrInfo)(h, NULL, L"x") == NULL); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(U(CryptCATGetAttrInfo)(h, &fake, L"x") == NULL); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(U(CryptCATGetAttrInfo)(h, m, NULL) == NULL); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    c_close(h); DeleteFileW(p);
}

/* ---------------------------------------------------------------- CryptCATVerifyMember */
TEST(wtcat_verifymember_invalid_parameters)
{
    WCHAR p[MAX_PATH]; HANDLE h, f; CRYPTCATMEMBER *m, fake;
    NEED_MEM(); REQUIRE(UN(CryptCATVerifyMember)); wpath(p, "vm.cat");
    h = c_open(p, CRYPTCAT_OPEN_CREATENEW, 0, 0); REQUIRE(h != INVH);
    m = put_member(h, L"f", L"T", g_dig_a); REQUIRE(m);
    f = ropen(p); REQUIRE(f != INVALID_HANDLE_VALUE);
    memset(&fake, 0, sizeof fake); fake.cbStruct = 0x40;
    SET_ERR(0); CHECK(!UN(CryptCATVerifyMember)(NULL, m, f)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!UN(CryptCATVerifyMember)(INVH, m, f)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!UN(CryptCATVerifyMember)(h, NULL, f)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!UN(CryptCATVerifyMember)(h, &fake, f)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!UN(CryptCATVerifyMember)(h, m, NULL)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!UN(CryptCATVerifyMember)(h, m, INVH)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    CloseHandle(f); c_close(h); DeleteFileW(p);
}

TEST(wtcat_verifymember_always_false)
{
    WCHAR p[MAX_PATH]; HANDLE h, f; CRYPTCATMEMBER *m;
    NEED_MEM(); REQUIRE(UN(CryptCATVerifyMember)); wpath(p, "vm2.cat");
    h = c_open(p, CRYPTCAT_OPEN_CREATENEW, 0, 0); REQUIRE(h != INVH);
    m = put_member(h, L"f", L"T", g_dig_a); REQUIRE(m);
    f = ropen(p); REQUIRE(f != INVALID_HANDLE_VALUE);
    CHECK(!UN(CryptCATVerifyMember)(h, m, f));   /* the Windows 10 export is an unconditional FALSE */
    CloseHandle(f); c_close(h); DeleteFileW(p);
}
