/* CryptCATPersistStore and reopening: round trips, SORTED / NO_CONTENT stores, IsCatalogFile,
 * MsCatConstructHashTag. */
#include "cat_common.h"

#define NEED() do { REQUIRE(U(CryptCATOpen)); REQUIRE(U(CryptCATClose)); REQUIRE(U(CryptCATPersistStore)); } while (0)
#define NO_WINE() do { if (t_is_wine()) { t_skip("catalog object API is a stub under Wine"); return; } } while (0)
#define NEED_MEM() do { NO_WINE(); NEED(); } while (0)
#define ATTR_ASCII (CRYPTCAT_ATTR_DATAASCII | CRYPTCAT_ATTR_NAMEASCII)

/* Build and persist a catalog with three members and two catalog attributes. */
static BOOL build_sample(const WCHAR *path)
{
    HANDLE h = c_open(path, CRYPTCAT_OPEN_CREATENEW, 0, 0);
    CRYPTCATMEMBER *m; BOOL ok;
    static const WCHAR v1[] = L"first value", v2[] = L"second";
    if (h == INVH) return FALSE;
    U(CryptCATPutCatAttrInfo)(h, L"CatAttrOne", ATTR_ASCII, sizeof v1, (BYTE *)v1);
    U(CryptCATPutCatAttrInfo)(h, L"CatAttrTwo", ATTR_ASCII, sizeof v2, (BYTE *)v2);
    m = put_member(h, L"zeta.bin", L"ZZZZ", g_dig_a);
    if (m) U(CryptCATPutAttrInfo)(h, m, L"File", ATTR_ASCII, sizeof v1, (BYTE *)v1);
    put_member(h, L"alpha.bin", L"AAAA", g_dig_b);
    m = put_member(h, L"mu.bin", L"MMMM", g_dig_a);
    if (m) {
        U(CryptCATPutAttrInfo)(h, m, L"A1", ATTR_ASCII, sizeof v2, (BYTE *)v2);
        U(CryptCATPutAttrInfo)(h, m, L"A2", ATTR_ASCII, sizeof v2, (BYTE *)v2);
    }
    ok = U(CryptCATPersistStore)(h);
    c_close(h);
    return ok;
}

TEST(wtcat_persist_invalid_handles)
{
    NEED_MEM();
    SET_ERR(0); CHECK(!U(CryptCATPersistStore)(NULL)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!U(CryptCATPersistStore)(INVH)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
}

TEST(wtcat_persist_writes_file)
{
    WCHAR p[MAX_PATH]; HANDLE h;
    NEED_MEM(); wpath(p, "ps_w.cat");
    h = c_open(p, CRYPTCAT_OPEN_CREATENEW, 0, 0); REQUIRE(h != INVH);
    CHECK(put_member(h, L"f.bin", L"TAGW", g_dig_a) != NULL);
    EXPECT_EQ(fsize(p), 0);
    CHECK(U(CryptCATPersistStore)(h));
    EXPECT_EQ(fsize(p), 305);   /* probed on Win10 */
    c_close(h);
    {   /* a DER SEQUENCE */
        HANDLE f = ropen(p); BYTE b = 0; DWORD n = 0;
        if (f != INVALID_HANDLE_VALUE) { ReadFile(f, &b, 1, &n, NULL); CloseHandle(f); }
        EXPECT_EQ(b, 0x30);
    }
    DeleteFileW(p);
}

TEST(wtcat_persist_empty_catalog_note)
{
    WCHAR p[MAX_PATH]; HANDLE h; BOOL ok;
    NEED_MEM(); wpath(p, "ps_e.cat");
    h = c_open(p, CRYPTCAT_OPEN_CREATENEW, 0, 0); REQUIRE(h != INVH);
    SET_ERR(0);
    ok = U(CryptCATPersistStore)(h);
    CHECK(ok);   /* probed on Win10: succeeds and writes a 104 byte file */
    EXPECT_EQ(fsize(p), 104);
    c_close(h); DeleteFileW(p);
}

TEST(wtcat_persist_roundtrip_member_count_and_tags)
{
    WCHAR p[MAX_PATH]; HANDLE h; CRYPTCATMEMBER *m;
    NEED_MEM(); wpath(p, "rt_m.cat");
    CHECK(build_sample(p));
    h = c_open(p, CRYPTCAT_OPEN_EXISTING, 0, 0); REQUIRE(h != INVH);
    EXPECT_EQ(count_members(h), 3);
    m = U(CryptCATGetMemberInfo)(h, L"ZZZZ"); CHECK(m != NULL);
    if (m) {
        CHECK(m->pwszReferenceTag && !wcscmp(m->pwszReferenceTag, L"ZZZZ"));
        CHECK(!memcmp(&m->gSubjectType, &g_subj, sizeof(GUID)));
        EXPECT_EQ(m->dwCertVersion, 0x200);
        CHECK(m->pIndirectData != NULL);
        if (m->pIndirectData) {
            EXPECT_EQ(m->pIndirectData->Digest.cbData, 20);
            CHECK(m->pIndirectData->Digest.pbData && !memcmp(m->pIndirectData->Digest.pbData, g_dig_a, 20));
            CHECK(m->pIndirectData->Data.pszObjId && !strcmp(m->pIndirectData->Data.pszObjId, g_ind_oid));
            CHECK(m->pIndirectData->DigestAlgorithm.pszObjId && !strcmp(m->pIndirectData->DigestAlgorithm.pszObjId, g_alg_sha1));
        }
        CHECK(m->pwszFileName == NULL);   /* probed on Win10: the file name is not persisted */
    }
    m = U(CryptCATGetMemberInfo)(h, L"AAAA"); CHECK(m != NULL);
    if (m && m->pIndirectData) CHECK(m->pIndirectData->Digest.pbData && !memcmp(m->pIndirectData->Digest.pbData, g_dig_b, 20));
    m = U(CryptCATGetMemberInfo)(h, L"MMMM"); CHECK(m != NULL);
    if (m && m->pIndirectData) CHECK(m->pIndirectData->Digest.pbData && !memcmp(m->pIndirectData->Digest.pbData, g_dig_a, 20));
    c_close(h); DeleteFileW(p);
}

TEST(wtcat_persist_roundtrip_enumeration_covers_all_members)
{
    WCHAR p[MAX_PATH]; HANDLE h; CRYPTCATMEMBER *m = NULL; int seen = 0, i = 0;
    NEED_MEM(); wpath(p, "rt_e.cat");
    CHECK(build_sample(p));
    h = c_open(p, CRYPTCAT_OPEN_EXISTING, 0, 0); REQUIRE(h != INVH);
    while ((m = U(CryptCATEnumerateMember)(h, m)) != NULL && i < 10) {
        if (m->pwszReferenceTag && !wcscmp(m->pwszReferenceTag, L"ZZZZ")) seen |= 1;
        if (m->pwszReferenceTag && !wcscmp(m->pwszReferenceTag, L"AAAA")) seen |= 2;
        if (m->pwszReferenceTag && !wcscmp(m->pwszReferenceTag, L"MMMM")) seen |= 4;
        EXPECT_EQ(m->dwReserved, i);
        EXPECT_EQ(m->cbStruct, 0x68);
        i++;
    }
    EXPECT_EQ(i, 3);
    EXPECT_EQ(seen, 7);
    c_close(h); DeleteFileW(p);
}

TEST(wtcat_persist_roundtrip_catalog_attributes)
{
    WCHAR p[MAX_PATH]; HANDLE h; CRYPTCATATTRIBUTE *a;
    NEED_MEM(); wpath(p, "rt_ca.cat");
    CHECK(build_sample(p));
    h = c_open(p, CRYPTCAT_OPEN_EXISTING, 0, 0); REQUIRE(h != INVH);
    a = U(CryptCATGetCatAttrInfo)(h, L"CatAttrOne");
    CHECK(a != NULL);
    if (a) {
        CHECK(a->pwszReferenceTag && !wcscmp(a->pwszReferenceTag, L"CatAttrOne"));
        EXPECT_EQ(a->cbValue, 24);   /* probed on Win10 */
        CHECK(a->pbValue != NULL);
        if (a->pbValue && a->cbValue == 24) CHECK(!wmemcmp((WCHAR *)a->pbValue, L"first value", 12));
        EXPECT_EQ(a->dwAttrTypeAndAction, 0x10001);
    }
    a = U(CryptCATGetCatAttrInfo)(h, L"CatAttrTwo");
    CHECK(a != NULL);
    if (a && a->pbValue && a->cbValue >= 12) CHECK(!wmemcmp((WCHAR *)a->pbValue, L"second", 6));
    EXPECT_EQ(count_cat_attrs(h), 2);
    c_close(h); DeleteFileW(p);
}

TEST(wtcat_persist_roundtrip_member_attributes)
{
    WCHAR p[MAX_PATH]; HANDLE h; CRYPTCATMEMBER *m; CRYPTCATATTRIBUTE *a;
    NEED_MEM(); wpath(p, "rt_ma.cat");
    CHECK(build_sample(p));
    h = c_open(p, CRYPTCAT_OPEN_EXISTING, 0, 0); REQUIRE(h != INVH);
    m = U(CryptCATGetMemberInfo)(h, L"MMMM"); REQUIRE(m);
    a = U(CryptCATGetAttrInfo)(h, m, L"A1");
    CHECK(a != NULL);
    if (a && a->pbValue && a->cbValue >= 12) CHECK(!wmemcmp((WCHAR *)a->pbValue, L"second", 6));
    CHECK(U(CryptCATGetAttrInfo)(h, m, L"A2") != NULL);
    EXPECT_EQ(count_attrs(h, m), 2);
    m = U(CryptCATGetMemberInfo)(h, L"ZZZZ"); REQUIRE(m);
    CHECK(U(CryptCATGetAttrInfo)(h, m, L"File") != NULL);
    CHECK(U(CryptCATGetAttrInfo)(h, m, L"A1") == NULL);
    m = U(CryptCATGetMemberInfo)(h, L"AAAA"); REQUIRE(m);
    EXPECT_EQ(count_attrs(h, m), 0);
    c_close(h); DeleteFileW(p);
}

TEST(wtcat_persist_is_repeatable)
{
    WCHAR p[MAX_PATH]; HANDLE h; LONGLONG s1, s2;
    NEED_MEM(); wpath(p, "ps_rep.cat");
    h = c_open(p, CRYPTCAT_OPEN_CREATENEW, 0, 0); REQUIRE(h != INVH);
    put_member(h, L"f", L"R1", g_dig_a);
    put_member(h, L"g", L"R2", g_dig_b);
    CHECK(U(CryptCATPersistStore)(h)); s1 = fsize(p);
    CHECK(U(CryptCATPersistStore)(h)); s2 = fsize(p);
    CHECK(s1 > 0);
    EXPECT_EQ(s1, 486);   /* probed on Win10; a second persist writes an identical file */
    EXPECT_EQ(s2, s1);
    c_close(h);
    h = c_open(p, CRYPTCAT_OPEN_EXISTING, 0, 0); REQUIRE(h != INVH);
    EXPECT_EQ(count_members(h), 2);
    c_close(h); DeleteFileW(p);
}

TEST(wtcat_persist_reopen_modify_persist)
{
    WCHAR p[MAX_PATH]; HANDLE h;
    NEED_MEM(); wpath(p, "ps_mod.cat");
    CHECK(build_sample(p));
    h = c_open(p, CRYPTCAT_OPEN_EXISTING, 0, 0); REQUIRE(h != INVH);
    CHECK(put_member(h, L"new.bin", L"NEWW", g_dig_b) != NULL);
    CHECK(U(CryptCATPutCatAttrInfo)(h, L"Added", ATTR_ASCII, 4, (BYTE *)L"x") != NULL);
    CHECK(U(CryptCATPersistStore)(h));
    c_close(h);
    h = c_open(p, CRYPTCAT_OPEN_EXISTING, 0, 0); REQUIRE(h != INVH);
    EXPECT_EQ(count_members(h), 4);
    CHECK(U(CryptCATGetMemberInfo)(h, L"NEWW") != NULL);
    CHECK(U(CryptCATGetMemberInfo)(h, L"ZZZZ") != NULL);
    CHECK(U(CryptCATGetCatAttrInfo)(h, L"Added") != NULL);
    CHECK(U(CryptCATGetCatAttrInfo)(h, L"CatAttrOne") != NULL);
    c_close(h); DeleteFileW(p);
}

TEST(wtcat_persist_open_always_keeps_persisted_content)
{
    WCHAR p[MAX_PATH]; HANDLE h;
    NEED_MEM(); wpath(p, "ps_alw.cat");
    CHECK(build_sample(p));
    h = c_open(p, CRYPTCAT_OPEN_ALWAYS, 0, 0); REQUIRE(h != INVH);
    EXPECT_EQ(count_members(h), 3);
    c_close(h);
    h = c_open(p, CRYPTCAT_OPEN_CREATENEW, 0, 0); REQUIRE(h != INVH);   /* CREATENEW discards it */
    EXPECT_EQ(count_members(h), 0);
    c_close(h); DeleteFileW(p);
}

TEST(wtcat_persist_open_zero_flags_reads_persisted)
{
    WCHAR p[MAX_PATH]; HANDLE h;
    NEED_MEM(); wpath(p, "ps_z.cat");
    CHECK(build_sample(p));
    h = c_open(p, 0, 0, 0); REQUIRE(h != INVH);
    EXPECT_EQ(count_members(h), 3);
    c_close(h); DeleteFileW(p);
}

TEST(wtcat_persist_many_members)
{
    WCHAR p[MAX_PATH]; HANDLE h; int i;
    NEED_MEM(); wpath(p, "ps_many.cat");
    h = c_open(p, CRYPTCAT_OPEN_CREATENEW, 0, 0); REQUIRE(h != INVH);
    for (i = 0; i < 120; i++) {
        BYTE d[20]; WCHAR tag[24]; int k;
        for (k = 0; k < 20; k++) d[k] = (BYTE)(i * 3 + k);
        swprintf(tag, 24, L"MEMBER%04d", i);
        CHECKF(put_member(h, L"f", tag, d) != NULL, "i=%d", i);
    }
    CHECK(U(CryptCATPersistStore)(h));
    c_close(h);
    h = c_open(p, CRYPTCAT_OPEN_EXISTING, 0, 0); REQUIRE(h != INVH);
    EXPECT_EQ(count_members(h), 120);
    for (i = 0; i < 120; i += 17) {
        WCHAR tag[24]; CRYPTCATMEMBER *m; swprintf(tag, 24, L"MEMBER%04d", i);
        m = U(CryptCATGetMemberInfo)(h, tag);
        CHECKF(m != NULL, "tag %ls", tag);
        if (m && m->pIndirectData && m->pIndirectData->Digest.pbData) EXPECT_EQ(m->pIndirectData->Digest.pbData[0], (BYTE)(i * 3));
    }
    c_close(h); DeleteFileW(p);
}

TEST(wtcat_persist_long_reference_tag_roundtrip)
{
    WCHAR p[MAX_PATH], tag[129]; HANDLE h; int i;
    NEED_MEM(); wpath(p, "ps_lt.cat");
    for (i = 0; i < 128; i++) tag[i] = L'A' + (i % 26);
    tag[128] = 0;
    h = c_open(p, CRYPTCAT_OPEN_CREATENEW, 0, 0); REQUIRE(h != INVH);
    CHECK(put_member(h, L"f", tag, g_dig_a) != NULL);
    CHECK(U(CryptCATPersistStore)(h));
    c_close(h);
    h = c_open(p, CRYPTCAT_OPEN_EXISTING, 0, 0); REQUIRE(h != INVH);
    CHECK(U(CryptCATGetMemberInfo)(h, tag) != NULL);
    c_close(h); DeleteFileW(p);
}

TEST(wtcat_persist_unicode_attribute_value)
{
    WCHAR p[MAX_PATH]; HANDLE h; CRYPTCATATTRIBUTE *a;
    static const WCHAR v[] = { 0x00e9, 0x4e2d, 0x6587, 0x0041, 0 };
    NEED_MEM(); wpath(p, "ps_u.cat");
    h = c_open(p, CRYPTCAT_OPEN_CREATENEW, 0, 0); REQUIRE(h != INVH);
    CHECK(put_member(h, L"f", L"U", g_dig_a) != NULL);
    CHECK(U(CryptCATPutCatAttrInfo)(h, L"Uni", ATTR_ASCII, sizeof v, (BYTE *)v) != NULL);
    CHECK(U(CryptCATPersistStore)(h));
    c_close(h);
    h = c_open(p, CRYPTCAT_OPEN_EXISTING, 0, 0); REQUIRE(h != INVH);
    a = U(CryptCATGetCatAttrInfo)(h, L"Uni"); CHECK(a != NULL);
    if (a && a->pbValue && a->cbValue >= 8) CHECK(!wmemcmp((WCHAR *)a->pbValue, v, 4));
    c_close(h); DeleteFileW(p);
}

/* ---------------------------------------------------------------- open flags on persisted files */
TEST(wtcat_open_no_content_hcryptmsg)
{
    WCHAR p[MAX_PATH]; HANDLE h;
    NEED_MEM(); wpath(p, "nc.cat");
    CHECK(build_sample(p));
    h = c_open(p, CRYPTCAT_OPEN_EXISTING, 0, 0); REQUIRE(h != INVH);
    CHECK(c_store(h)->hCryptMsg == NULL);
    c_close(h);
    h = c_open(p, CRYPTCAT_OPEN_EXISTING | CRYPTCAT_OPEN_NO_CONTENT_HCRYPTMSG, 0, 0); REQUIRE(h != INVH);
    CHECK(c_store(h)->hCryptMsg != NULL);
    EXPECT_EQ(c_store(h)->fdwStoreFlags, CRYPTCAT_OPEN_NO_CONTENT_HCRYPTMSG);
    EXPECT_EQ(count_members(h), 3);
    CHECK(c_close(h));
    DeleteFileW(p);
}

TEST(wtcat_open_sorted_missing_file)
{
    WCHAR p[MAX_PATH]; HANDLE h;
    NEED_MEM(); wpath(p, "sorted_missing.cat");
    DeleteFileW(p);
    SET_ERR(0);
    h = c_open(p, CRYPTCAT_OPEN_EXISTING | CRYPTCAT_OPEN_SORTED, 0, 0);
    CHECK(h == INVH);
    EXPECT_ERR(ERROR_FILE_NOT_FOUND);   /* probed on Win10: 2 */
}

TEST(wtcat_open_sorted_flag_recorded)
{
    WCHAR p[MAX_PATH]; HANDLE h;
    NEED_MEM(); wpath(p, "sorted_flag.cat");
    CHECK(build_sample(p));
    h = c_open(p, CRYPTCAT_OPEN_EXISTING | CRYPTCAT_OPEN_SORTED, 0, 0); REQUIRE(h != INVH);
    EXPECT_EQ(c_store(h)->fdwStoreFlags, CRYPTCAT_OPEN_SORTED);
    CHECK(c_store(h)->hSorted != NULL);
    CHECK(c_close(h));
    h = c_open(p, CRYPTCAT_OPEN_EXISTING, 0, 0); REQUIRE(h != INVH);
    CHECK(c_store(h)->hSorted == NULL);
    c_close(h); DeleteFileW(p);
}

TEST(wtcat_sorted_alloc_finds_members)
{
    WCHAR p[MAX_PATH]; HANDLE h; CRYPTCATMEMBER *m;
    NEED_MEM(); REQUIRE(UN(CryptCATAllocSortedMemberInfo)); REQUIRE(UN(CryptCATFreeSortedMemberInfo));
    wpath(p, "sorted_alloc.cat");
    CHECK(build_sample(p));
    h = c_open(p, CRYPTCAT_OPEN_EXISTING | CRYPTCAT_OPEN_SORTED, 0, 0); REQUIRE(h != INVH);
    m = UN(CryptCATAllocSortedMemberInfo)(h, L"AAAA");
    CHECK(m != NULL);
    if (m) {
        CHECK(m->pwszReferenceTag && !wcscmp(m->pwszReferenceTag, L"AAAA"));
        CHECK(m->fdwMemberFlags & 0x40000000);
        CHECK(!memcmp(&m->gSubjectType, &g_subj, sizeof(GUID)));
        CHECK(m->pIndirectData && m->pIndirectData->Digest.pbData && !memcmp(m->pIndirectData->Digest.pbData, g_dig_b, 20));
        UN(CryptCATFreeSortedMemberInfo)(h, m);
    }
    m = UN(CryptCATAllocSortedMemberInfo)(h, L"ZZZZ");
    CHECK(m != NULL);
    if (m) {
        CHECK(m->pIndirectData && m->pIndirectData->Digest.pbData && !memcmp(m->pIndirectData->Digest.pbData, g_dig_a, 20));
        UN(CryptCATFreeSortedMemberInfo)(h, m);
    }
    c_close(h); DeleteFileW(p);
}

TEST(wtcat_sorted_alloc_returns_independent_copies)
{
    WCHAR p[MAX_PATH]; HANDLE h; CRYPTCATMEMBER *m1, *m2;
    NEED_MEM(); REQUIRE(UN(CryptCATAllocSortedMemberInfo)); REQUIRE(UN(CryptCATFreeSortedMemberInfo));
    wpath(p, "sorted_copy.cat");
    CHECK(build_sample(p));
    h = c_open(p, CRYPTCAT_OPEN_EXISTING | CRYPTCAT_OPEN_SORTED, 0, 0); REQUIRE(h != INVH);
    m1 = UN(CryptCATAllocSortedMemberInfo)(h, L"MMMM");
    m2 = UN(CryptCATAllocSortedMemberInfo)(h, L"MMMM");
    CHECK(m1 && m2 && m1 != m2);
    if (m1) UN(CryptCATFreeSortedMemberInfo)(h, m1);
    if (m2) {
        CHECK(m2->pwszReferenceTag && !wcscmp(m2->pwszReferenceTag, L"MMMM"));   /* still intact after freeing the other */
        UN(CryptCATFreeSortedMemberInfo)(h, m2);
    }
    c_close(h); DeleteFileW(p);
}

TEST(wtcat_sorted_alloc_unknown_tag)
{
    WCHAR p[MAX_PATH]; HANDLE h;
    NEED_MEM(); REQUIRE(UN(CryptCATAllocSortedMemberInfo));
    wpath(p, "sorted_unk.cat");
    CHECK(build_sample(p));
    h = c_open(p, CRYPTCAT_OPEN_EXISTING | CRYPTCAT_OPEN_SORTED, 0, 0); REQUIRE(h != INVH);
    SET_ERR(0);
    CHECK(UN(CryptCATAllocSortedMemberInfo)(h, L"NOPE") == NULL);
    EXPECT_ERR(CRYPT_E_NOT_FOUND);   /* probed on Win10: 0x80092004 */
    c_close(h); DeleteFileW(p);
}

TEST(wtcat_sorted_alloc_invalid_parameters)
{
    WCHAR p[MAX_PATH]; HANDLE h, hu;
    NEED_MEM(); REQUIRE(UN(CryptCATAllocSortedMemberInfo));
    wpath(p, "sorted_inv.cat");
    CHECK(build_sample(p));
    h = c_open(p, CRYPTCAT_OPEN_EXISTING | CRYPTCAT_OPEN_SORTED, 0, 0); REQUIRE(h != INVH);
    hu = c_open(p, CRYPTCAT_OPEN_EXISTING, 0, 0); REQUIRE(hu != INVH);
    SET_ERR(0); CHECK(UN(CryptCATAllocSortedMemberInfo)(NULL, L"AAAA") == NULL); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(UN(CryptCATAllocSortedMemberInfo)(INVH, L"AAAA") == NULL); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(UN(CryptCATAllocSortedMemberInfo)(h, NULL) == NULL); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(UN(CryptCATAllocSortedMemberInfo)(hu, L"AAAA") == NULL); EXPECT_ERR(ERROR_INVALID_PARAMETER);   /* not opened SORTED */
    c_close(hu); c_close(h); DeleteFileW(p);
}

TEST(wtcat_sorted_free_ignores_unsorted_members)
{
    WCHAR p[MAX_PATH]; HANDLE h; CRYPTCATMEMBER *m;
    NEED_MEM(); REQUIRE(UN(CryptCATFreeSortedMemberInfo));
    wpath(p, "sorted_free.cat");
    CHECK(build_sample(p));
    h = c_open(p, CRYPTCAT_OPEN_EXISTING, 0, 0); REQUIRE(h != INVH);
    m = U(CryptCATEnumerateMember)(h, NULL); REQUIRE(m);
    UN(CryptCATFreeSortedMemberInfo)(h, m);   /* only members flagged as sorted copies are released */
    CHECK(m->pwszReferenceTag != NULL);
    UN(CryptCATFreeSortedMemberInfo)(h, NULL);
    EXPECT_EQ(count_members(h), 3);
    c_close(h); DeleteFileW(p);
}

/* ---------------------------------------------------------------- IsCatalogFile */
TEST(wtcat_iscatalogfile_invalid_parameters)
{
    REQUIRE(UN(IsCatalogFile));
    SET_ERR(0); CHECK(!UN(IsCatalogFile)(NULL, NULL)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    if (!t_is_wine()) { SET_ERR(0); CHECK(!UN(IsCatalogFile)(INVH, NULL)); EXPECT_ERR(ERROR_INVALID_PARAMETER); }
}

TEST(wtcat_iscatalogfile_persisted_catalog_by_name)
{
    WCHAR p[MAX_PATH];
    NEED_MEM(); REQUIRE(UN(IsCatalogFile)); wpath(p, "isc1.cat");
    CHECK(build_sample(p));
    CHECK(UN(IsCatalogFile)(NULL, p));
    CHECK(UN(IsCatalogFile)(INVH, p));
    DeleteFileW(p);
}

TEST(wtcat_iscatalogfile_persisted_catalog_by_handle)
{
    WCHAR p[MAX_PATH]; HANDLE f;
    NEED_MEM(); REQUIRE(UN(IsCatalogFile)); wpath(p, "isc2.cat");
    CHECK(build_sample(p));
    f = ropen(p); REQUIRE(f != INVALID_HANDLE_VALUE);
    CHECK(UN(IsCatalogFile)(f, NULL));
    CHECK(UN(IsCatalogFile)(f, L"ignored-when-a-handle-is-given.cat"));
    /* the handle stays open and usable */
    EXPECT_EQ(GetFileSize(f, NULL), 970);   /* probed on Win10 */
    CloseHandle(f); DeleteFileW(p);
}

TEST(wtcat_iscatalogfile_rejects_non_catalogs)
{
    WCHAR p[MAX_PATH]; char junk[200];
    REQUIRE(UN(IsCatalogFile)); wpath(p, "isc_no.dat");
    put_text(p, "plain text, not a catalog at all");
    CHECK(!UN(IsCatalogFile)(NULL, p));
    memset(junk, '0', sizeof junk);   /* starts with 0x30 but is not DER */
    put_file(p, junk, sizeof junk);
    CHECK(!UN(IsCatalogFile)(NULL, p));
    put_file(p, "", 0);
    CHECK(!UN(IsCatalogFile)(NULL, p));
    DeleteFileW(p);
}

TEST(wtcat_iscatalogfile_missing_file)
{
    WCHAR p[MAX_PATH];
    REQUIRE(UN(IsCatalogFile)); wpath(p, "isc_missing.cat");
    DeleteFileW(p);
    CHECK(!UN(IsCatalogFile)(NULL, p));
}

TEST(wtcat_iscatalogfile_pe_is_not_a_catalog)
{
    WCHAR p[MAX_PATH];
    REQUIRE(UN(IsCatalogFile)); wpath(p, "isc_pe.dat");
    {
        BYTE mz[0x200]; memset(mz, 0, sizeof mz); mz[0] = 'M'; mz[1] = 'Z';
        put_file(p, mz, sizeof mz);
    }
    CHECK(!UN(IsCatalogFile)(NULL, p));
    DeleteFileW(p);
}

/* ---------------------------------------------------------------- MsCatConstructHashTag */
TEST(wtcat_hashtag_known_values)
{
    static const BYTE b1[] = { 0x00, 0xff, 0x10, 0xab, 0xcd, 0xef, 0x01, 0x7f, 0x80 };
    LPWSTR t = NULL;
    NO_WINE(); REQUIRE(UN(MsCatConstructHashTag)); REQUIRE(UN(MsCatFreeHashTag));
    CHECK(UN(MsCatConstructHashTag)(sizeof b1, (BYTE *)b1, &t));
    REQUIRE(t != NULL);
    CHECK(!wcscmp(t, L"00FF10ABCDEF01" L"7F80"));   /* upper-case hex, two digits per byte, no separators */
    CHECK(UN(MsCatFreeHashTag)(t) == NULL);
}

TEST(wtcat_hashtag_all_byte_values)
{
    BYTE all[256]; WCHAR want[513]; LPWSTR t = NULL; int i;
    NO_WINE(); REQUIRE(UN(MsCatConstructHashTag)); REQUIRE(UN(MsCatFreeHashTag));
    for (i = 0; i < 256; i++) all[i] = (BYTE)i;
    hex_upper(want, all, 256);
    CHECK(UN(MsCatConstructHashTag)(256, all, &t));
    REQUIRE(t != NULL);
    CHECK(!wcscmp(t, want));
    EXPECT_EQ(wcslen(t), 512);
    UN(MsCatFreeHashTag)(t);
}

TEST(wtcat_hashtag_lengths)
{
    DWORD lens[] = { 1, 2, 16, 20, 32, 48, 64 };
    size_t i;
    NO_WINE(); REQUIRE(UN(MsCatConstructHashTag)); REQUIRE(UN(MsCatFreeHashTag));
    for (i = 0; i < sizeof lens / sizeof *lens; i++) {
        BYTE b[64]; WCHAR want[130]; LPWSTR t = NULL; DWORD k;
        for (k = 0; k < lens[i]; k++) b[k] = (BYTE)(k * 29 + 7);
        hex_upper(want, b, lens[i]);
        CHECKF(UN(MsCatConstructHashTag)(lens[i], b, &t), "len %lu", lens[i]);
        CHECKF(t && !wcscmp(t, want), "len %lu", lens[i]);
        if (t) UN(MsCatFreeHashTag)(t);
    }
}

TEST(wtcat_hashtag_empty_input)
{
    LPWSTR t = (LPWSTR)(ULONG_PTR)1;
    BYTE dummy = 0;
    NO_WINE(); REQUIRE(UN(MsCatConstructHashTag)); REQUIRE(UN(MsCatFreeHashTag));
    CHECK(UN(MsCatConstructHashTag)(0, &dummy, &t));
    CHECK(t != NULL && t != (LPWSTR)(ULONG_PTR)1);
    if (t && t != (LPWSTR)(ULONG_PTR)1) { EXPECT_EQ(t[0], 0); UN(MsCatFreeHashTag)(t); }
    t = NULL;
    CHECK(UN(MsCatConstructHashTag)(0, NULL, &t));   /* the input pointer is not touched for an empty hash */
    if (t) UN(MsCatFreeHashTag)(t);
}

TEST(wtcat_hashtag_free_null)
{
    NO_WINE(); REQUIRE(UN(MsCatFreeHashTag));
    CHECK(UN(MsCatFreeHashTag)(NULL) == NULL);
}

TEST(wtcat_hashtag_output_is_local_heap_allocation)
{
    static const BYTE b[] = { 1, 2, 3, 4 };
    LPWSTR t = NULL;
    NO_WINE(); REQUIRE(UN(MsCatConstructHashTag));
    CHECK(UN(MsCatConstructHashTag)(sizeof b, (BYTE *)b, &t));
    REQUIRE(t != NULL);
    CHECK(LocalSize(t) >= (sizeof b * 2 + 1) * sizeof(WCHAR));   /* the caller may release it with LocalFree */
    CHECK(LocalFree(t) == NULL);
}
