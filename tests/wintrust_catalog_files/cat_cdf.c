/* Catalog definition files: CryptCATCDFOpen / Close / Enum*.  A CDF is UTF-8 text with a
 * [CatalogHeader] and a [CatalogFiles] section; opening one creates the (empty) catalog file,
 * enumerating members hashes the listed files through the matching SIP and stores the result, and
 * CryptCATCDFClose persists the catalog. */
#include "cat_common.h"
#include "vectors.h"

#define NO_WINE() do { if (t_is_wine()) { t_skip("CDF support needs a module Wine lacks (GLE 126), other exports are stubs"); return; } } while (0)
#define NEED() do { NO_WINE(); REQUIRE(U(CryptCATCDFOpen)); REQUIRE(U(CryptCATCDFClose)); } while (0)
#define ATTR_ASCII (CRYPTCAT_ATTR_DATAASCII | CRYPTCAT_ATTR_NAMEASCII)

static const GUID GUID_FLAT = { 0xDE351A42, 0x8E59, 0x11D0, { 0x8C, 0x47, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE } };
static const GUID GUID_PE = { 0xC689AAB8, 0x8E78, 0x11D0, { 0x8C, 0x47, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE } };
static const char OID_SHA1[] = "1.3.14.3.2.26";
static const char OID_SHA256[] = "2.16.840.1.101.3.4.2.1";

/* ---- parse-error callback recorder ------------------------------------ */
static struct { int n; DWORD area[8], err[8]; WCHAR line[8][300]; } g_cb;
static void WINAPI cb_record(DWORD area, DWORD err, WCHAR *line)
{
    if (g_cb.n < 8) {
        g_cb.area[g_cb.n] = area; g_cb.err[g_cb.n] = err;
        g_cb.line[g_cb.n][0] = 0;
        if (line) { wcsncpy(g_cb.line[g_cb.n], line, 299); g_cb.line[g_cb.n][299] = 0; }
    }
    g_cb.n++;
}
static void cb_reset(void) { memset(&g_cb, 0, sizeof g_cb); }

/* ---- fixtures ---------------------------------------------------------- */
static char g_dir[MAX_PATH];   /* scratch dir, trailing backslash */
static char g_out[MAX_PATH];   /* output dir for catalogs, trailing backslash */
static void fixtures(void)
{
    static BYTE big[70000]; size_t i; char p[MAX_PATH]; WCHAR w[MAX_PATH];
    strcpy(g_dir, t_tmpdir());
    if (g_dir[strlen(g_dir) - 1] != '\\') strcat(g_dir, "\\");
    snprintf(g_out, sizeof g_out, "%sout\\", g_dir);
    CreateDirectoryA(g_out, NULL);
#define FIX(leaf, data, len) do { snprintf(p, sizeof p, "%s%s", g_dir, leaf); wtow(w, MAX_PATH, p); put_file(w, data, (DWORD)(len)); } while (0)
    FIX("fa.dat", flat_a, sizeof flat_a);
    FIX("fc.dat", flat_c, sizeof flat_c);
    for (i = 0; i < sizeof big; i++) big[i] = (BYTE)((i * 7 + 3) & 255);
    FIX("fb.dat", big, sizeof big);
    FIX("p_base.bin", pe_base, sizeof pe_base);
    FIX("p_ts.bin", pe_ts, sizeof pe_ts);
    FIX("p_chk.bin", pe_chk, sizeof pe_chk);
    FIX("p_trail.bin", pe_trail, sizeof pe_trail);
#undef FIX
}
static void write_text(const char *leaf, const char *text)
{
    char p[MAX_PATH]; WCHAR w[MAX_PATH];
    snprintf(p, sizeof p, "%s%s", g_dir, leaf); wtow(w, MAX_PATH, p);
    put_file(w, text, (DWORD)strlen(text));
}
/* header (CRLF) with Name/ResultDir/CatalogVersion/HashAlgorithms, then optional extra header lines, then files */
static void write_cdf(const char *leaf, const char *name, int version, const char *alg, const char *extra_hdr, const char *files)
{
    static char buf[16384];
    snprintf(buf, sizeof buf, "[CatalogHeader]\r\nName=%s\r\nResultDir=%s\r\nPublicVersion=0x0000001\r\nEncodingType=0x00010001\r\n"
             "CatalogVersion=%d\r\nHashAlgorithms=%s\r\n%s[CatalogFiles]\r\n%s", name, g_out, version, alg, extra_hdr ? extra_hdr : "", files ? files : "");
    write_text(leaf, buf);
}
static CRYPTCATCDF *open_cdf(const char *leaf, PFN_CDF_PARSE_ERROR_CALLBACK cb)
{
    char p[MAX_PATH]; WCHAR w[MAX_PATH];
    snprintf(p, sizeof p, "%s%s", g_dir, leaf); wtow(w, MAX_PATH, p);
    return U(CryptCATCDFOpen)(w, cb);
}
static void out_path(WCHAR *w, const char *leaf)
{
    char p[MAX_PATH]; snprintf(p, sizeof p, "%s%s", g_out, leaf); wtow(w, MAX_PATH, p);
}
static HANDLE cdf_store(CRYPTCATCDF *c) { return c->hCATStore; }
static int dig_is(const CRYPTCATMEMBER *m, const char *oid, const BYTE *d, DWORD n)
{
    return m && m->pIndirectData && m->pIndirectData->DigestAlgorithm.pszObjId && !strcmp(m->pIndirectData->DigestAlgorithm.pszObjId, oid) &&
           m->pIndirectData->Digest.cbData == n && m->pIndirectData->Digest.pbData && !memcmp(m->pIndirectData->Digest.pbData, d, n);
}
static void files_v1(char *out, size_t cap, const char *tagpfx)
{
    snprintf(out, cap, "%sfa=%sfa.dat\r\n%sfaATTR1=0x10010001:File:fa.dat\r\n%sfaATTR2=0x10010001:Other:two\r\n%sfc=%sfc.dat\r\n",
             tagpfx, g_dir, tagpfx, tagpfx, tagpfx, g_dir);
}

/* ---------------------------------------------------------------- open / close */
TEST(wtcdf_open_null_path)
{
    NEED();
    cb_reset();
    SET_ERR(0); CHECK(U(CryptCATCDFOpen)(NULL, NULL) == NULL); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(U(CryptCATCDFOpen)(NULL, cb_record) == NULL); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    EXPECT_EQ(g_cb.n, 0);
}

TEST(wtcdf_open_missing_file)
{
    WCHAR w[MAX_PATH];
    NEED(); fixtures(); cb_reset();
    wtow(w, MAX_PATH, "C:\\cryptt_no_such_dir_xyz\\missing.cdf");
    SET_ERR(0); CHECK(U(CryptCATCDFOpen)(w, cb_record) == NULL); EXPECT_ERR(ERROR_PATH_NOT_FOUND);
    CHECK(open_cdf("no_such_file.cdf", cb_record) == NULL);
    EXPECT_EQ(g_cb.n, 0);   /* I/O failures are not parse errors */
}

TEST(wtcdf_open_missing_file_error_code)
{
    NEED(); fixtures();
    SET_ERR(0); CHECK(open_cdf("absent.cdf", NULL) == NULL); EXPECT_ERR(ERROR_FILE_NOT_FOUND);
}

TEST(wtcdf_close_invalid)
{
    CRYPTCATCDF fake;
    NEED();
    SET_ERR(0); CHECK(!U(CryptCATCDFClose)(NULL)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    memset(&fake, 0, sizeof fake); fake.cbStruct = 0x2f;
    SET_ERR(0); CHECK(!U(CryptCATCDFClose)(&fake)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    fake.cbStruct = sizeof fake + 8;
    SET_ERR(0); CHECK(!U(CryptCATCDFClose)(&fake)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
}

TEST(wtcdf_open_without_catalogheader_reports_tag_not_found)
{
    CRYPTCATCDF *c;
    NEED(); fixtures(); cb_reset();
    write_text("nohdr.cdf", "[CatalogFiles]\r\nx=y\r\n");
    c = open_cdf("nohdr.cdf", cb_record);
    CHECK(c == NULL);
    if (c) U(CryptCATCDFClose)(c);
    EXPECT_EQ(g_cb.n, 1);
    if (g_cb.n >= 1) {
        EXPECT_EQ(g_cb.area[0], CRYPTCAT_E_AREA_HEADER);
        EXPECT_EQ(g_cb.err[0], CRYPTCAT_E_CDF_TAGNOTFOUND);
        CHECK(!wcscmp(g_cb.line[0], L"[CatalogHeader]"));
    }
}

TEST(wtcdf_open_without_catalogheader_null_callback)
{
    CRYPTCATCDF *c;
    NEED(); fixtures();
    write_text("nohdr2.cdf", "just some text\r\nwithout sections\r\n");
    c = open_cdf("nohdr2.cdf", NULL);
    CHECK(c == NULL);
    if (c) U(CryptCATCDFClose)(c);
}

TEST(wtcdf_open_empty_file_reports_tag_not_found)
{
    CRYPTCATCDF *c;
    NEED(); fixtures(); cb_reset();
    write_text("empty.cdf", "");
    c = open_cdf("empty.cdf", cb_record);
    CHECK(c == NULL);
    if (c) U(CryptCATCDFClose)(c);
    EXPECT_EQ(g_cb.n, 1);
    if (g_cb.n >= 1) { EXPECT_EQ(g_cb.area[0], 0); EXPECT_EQ(g_cb.err[0], 4); }
}

TEST(wtcdf_open_creates_catalog_file_and_close_persists)
{
    CRYPTCATCDF *c; WCHAR cat[MAX_PATH];
    NEED(); fixtures();
    write_cdf("basic.cdf", "basic.cat", 1, "SHA1", "", "");
    out_path(cat, "basic.cat");
    DeleteFileW(cat);
    c = open_cdf("basic.cdf", NULL);
    REQUIRE(c != NULL);
    EXPECT_EQ(c->cbStruct, 0x30);
    CHECK(c->hFile != NULL && c->hFile != INVH);
    CHECK(c->hCATStore != NULL && c->hCATStore != INVH);
    CHECK(c->pwszResultDir != NULL);
    CHECK(fexists(cat));
    EXPECT_EQ(fsize(cat), 0);   /* created empty, filled when the CDF is closed */
    t_note("CDF close with zero members: %s", U(CryptCATCDFClose)(c) ? "TRUE" : "FALSE");
    t_note("catalog size after closing an empty CDF: %lld", (long long)fsize(cat));
}

TEST(wtcdf_open_result_dir_is_kept_verbatim)
{
    CRYPTCATCDF *c; char d[MAX_PATH]; WCHAR wd[MAX_PATH];
    NEED(); fixtures();
    write_cdf("rd.cdf", "rd.cat", 1, "SHA1", "", "");
    c = open_cdf("rd.cdf", NULL);
    REQUIRE(c != NULL);
    strcpy(d, g_out); wtow(wd, MAX_PATH, d);
    CHECK(c->pwszResultDir && !wcscmp(c->pwszResultDir, wd));
    CHECK(c->pwszResultDir != wd);
    U(CryptCATCDFClose)(c);
}

TEST(wtcdf_open_result_dir_without_trailing_backslash)
{
    CRYPTCATCDF *c; WCHAR cat[MAX_PATH]; char buf[2048];
    NEED(); fixtures();
    snprintf(buf, sizeof buf, "[CatalogHeader]\r\nName=nobs.cat\r\nResultDir=%s\r\n[CatalogFiles]\r\n", g_out);
    {   /* strip the backslash that ends g_out */
        char *p = strstr(buf, "ResultDir=") + 10; char *e = strstr(p, "\r\n"); memmove(e - 1, e, strlen(e) + 1);
    }
    write_text("nobs.cdf", buf);
    out_path(cat, "nobs.cat"); DeleteFileW(cat);
    c = open_cdf("nobs.cdf", NULL);
    REQUIRE(c != NULL);
    CHECK(fexists(cat));   /* a separator is inserted between directory and name */
    U(CryptCATCDFClose)(c);
}

TEST(wtcdf_open_name_without_extension_gets_cat_suffix)
{
    CRYPTCATCDF *c; WCHAR with[MAX_PATH], without[MAX_PATH]; char full[MAX_PATH];
    NEED(); fixtures();
    write_cdf("noext.cdf", "plainname", 1, "SHA1", "", "");
    snprintf(full, sizeof full, "%splainname", g_out);
    out_path(with, "plainname.CAT"); out_path(without, "plainname");
    DeleteFileW(with); DeleteFileW(without);
    c = open_cdf("noext.cdf", NULL);
    REQUIRE(c != NULL);
    /* ".CAT" is appended only when the whole result path contains no '.' */
    if (strchr(full, '.')) { CHECK(fexists(without)); CHECK(!fexists(with)); }
    else { CHECK(fexists(with)); CHECK(!fexists(without)); }
    U(CryptCATCDFClose)(c);
}

TEST(wtcdf_open_name_with_extension_is_used_as_is)
{
    CRYPTCATCDF *c; WCHAR a[MAX_PATH], b[MAX_PATH];
    NEED(); fixtures();
    write_cdf("ext.cdf", "mycatalog.mycat", 1, "SHA1", "", "");
    out_path(a, "mycatalog.mycat"); out_path(b, "mycatalog.mycat.CAT");
    DeleteFileW(a); DeleteFileW(b);
    c = open_cdf("ext.cdf", NULL);
    REQUIRE(c != NULL);
    CHECK(fexists(a)); CHECK(!fexists(b));
    U(CryptCATCDFClose)(c);
}

TEST(wtcdf_open_default_name_is_cdf_leaf)
{
    CRYPTCATCDF *c; WCHAR a[MAX_PATH]; char buf[1024];
    NEED(); fixtures();
    snprintf(buf, sizeof buf, "[CatalogHeader]\r\nResultDir=%s\r\n[CatalogFiles]\r\n", g_out);
    write_text("leafname.cdf", buf);
    out_path(a, "leafname.cdf"); DeleteFileW(a);
    c = open_cdf("leafname.cdf", NULL);
    REQUIRE(c != NULL);
    CHECK(fexists(a));   /* the catalog is named after the CDF itself, extension included */
    U(CryptCATCDFClose)(c);
}

TEST(wtcdf_open_without_result_dir)
{
    CRYPTCATCDF *c; WCHAR a[MAX_PATH]; char buf[1024];
    NEED(); fixtures();
    snprintf(buf, sizeof buf, "[CatalogHeader]\r\nName=%sabsolute.cat\r\n[CatalogFiles]\r\n", g_out);
    write_text("nord.cdf", buf);
    out_path(a, "absolute.cat"); DeleteFileW(a);
    c = open_cdf("nord.cdf", NULL);
    REQUIRE(c != NULL);
    CHECK(c->pwszResultDir == NULL);
    CHECK(fexists(a));
    U(CryptCATCDFClose)(c);
}

TEST(wtcdf_open_missing_result_dir)
{
    CRYPTCATCDF *c; char buf[1024];
    NEED(); fixtures();
    snprintf(buf, sizeof buf, "[CatalogHeader]\r\nName=x.cat\r\nResultDir=%sno_such_subdir\\\r\n[CatalogFiles]\r\n", g_dir);
    write_text("badrd.cdf", buf);
    c = open_cdf("badrd.cdf", NULL);
    CHECK(c == NULL);
    if (c) U(CryptCATCDFClose)(c);
}

TEST(wtcdf_open_hash_algorithm_and_version_matrix)
{
    static const struct { int ver; const char *alg; int ok; DWORD pubver; } t[] = {
        { 1, "SHA1", 1, 0x100 }, { 2, "SHA256", 1, 0x200 }, { 1, "sha1", 1, 0x100 }, { 2, "Sha256", 1, 0x200 },
        { 1, "SHA256", 0, 0 }, { 2, "SHA1", 0, 0 }, { 1, "MD5", 0, 0 }, { 2, "SHA384", 0, 0 }, { 2, "SHA512", 0, 0 },
        { 0, "SHA1", 0, 0 }, { 3, "SHA1", 0, 0 }, { 3, "SHA256", 0, 0 }, { -1, "SHA1", 0, 0 },
    };
    size_t i;
    NEED(); fixtures();
    for (i = 0; i < sizeof t / sizeof *t; i++) {
        CRYPTCATCDF *c; char leaf[40]; WCHAR cat[MAX_PATH]; char name[40];
        snprintf(leaf, sizeof leaf, "mx%zu.cdf", i); snprintf(name, sizeof name, "mx%zu.cat", i);
        write_cdf(leaf, name, t[i].ver, t[i].alg, "", "");
        out_path(cat, name); DeleteFileW(cat);
        SET_ERR(0);
        c = open_cdf(leaf, NULL);
        if (t[i].ok) {
            CHECKF(c != NULL, "row %zu (v%d %s)", i, t[i].ver, t[i].alg);
            if (c) {
                CHECKF(c_store(cdf_store(c))->dwPublicVersion == t[i].pubver, "row %zu pubver %#lx", i, c_store(cdf_store(c))->dwPublicVersion);
                U(CryptCATCDFClose)(c);
            }
        } else {
            CHECKF(c == NULL, "row %zu (v%d %s) must be rejected", i, t[i].ver, t[i].alg);
            if (c) U(CryptCATCDFClose)(c);
            else { EXPECT_ERR(ERROR_INVALID_PARAMETER); CHECKF(!fexists(cat), "row %zu left a catalog behind", i); }
        }
    }
}

TEST(wtcdf_open_default_version_and_algorithm)
{
    CRYPTCATCDF *c; char buf[1024];
    NEED(); fixtures();
    snprintf(buf, sizeof buf, "[CatalogHeader]\r\nName=dflt.cat\r\nResultDir=%s\r\n[CatalogFiles]\r\n", g_out);
    write_text("dflt.cdf", buf);
    c = open_cdf("dflt.cdf", NULL);
    REQUIRE(c != NULL);
    EXPECT_EQ(c_store(cdf_store(c))->dwPublicVersion, CRYPTCAT_VERSION_1);   /* CatalogVersion defaults to 1, hash to SHA1 */
    EXPECT_EQ(c_store(cdf_store(c))->dwEncodingType, 0x10001);
    U(CryptCATCDFClose)(c);
}

TEST(wtcdf_open_non_numeric_catalog_version)
{
    CRYPTCATCDF *c;
    NEED(); fixtures();
    write_cdf("badver.cdf", "badver.cat", 1, "SHA1", "", "");
    write_text("badver2.cdf", "[CatalogHeader]\r\nName=badver2.cat\r\nCatalogVersion=abc\r\n[CatalogFiles]\r\n");
    c = open_cdf("badver2.cdf", NULL);
    CHECK(c == NULL);
    if (c) U(CryptCATCDFClose)(c);
}

TEST(wtcdf_open_encoding_type_parsed_as_hex)
{
    static const struct { const char *txt; DWORD want; } t[] = {
        { "0x00010001", 0x10001 }, { "00010001", 0x10001 }, { "0x10000", 0x10000 }, { "1", 1 }, { "0x00020002", 0x20002 }, { "", 0x10001 },
    };
    size_t i;
    NEED(); fixtures();
    for (i = 0; i < sizeof t / sizeof *t; i++) {
        CRYPTCATCDF *c; char buf[1024], leaf[32];
        snprintf(leaf, sizeof leaf, "enc%zu.cdf", i);
        snprintf(buf, sizeof buf, "[CatalogHeader]\r\nName=enc%zu.cat\r\nResultDir=%s\r\nEncodingType=%s\r\n[CatalogFiles]\r\n", i, g_out, t[i].txt);
        write_text(leaf, buf);
        c = open_cdf(leaf, NULL);
        CHECKF(c != NULL, "row %zu", i);
        if (!c) continue;
        CHECKF(c_store(cdf_store(c))->dwEncodingType == t[i].want, "row %zu: got %#lx want %#lx", i, c_store(cdf_store(c))->dwEncodingType, t[i].want);
        U(CryptCATCDFClose)(c);
    }
}

TEST(wtcdf_parse_comments_case_and_line_endings)
{
    static const char *docs[] = {
        "# leading comment\r\n[catalogheader]\r\n# inside\r\nNAME=ending1.cat\r\nresultdir=%s\r\n[CATALOGFILES]\r\n",
        "[CatalogHeader]\nName=ending2.cat\nResultDir=%s\n[CatalogFiles]\n",
        "[CatalogHeader]\rName=ending3.cat\rResultDir=%s\r[CatalogFiles]\r",
        "[CatalogHeader]\r\nName=ending4.cat\r\nResultDir=%s\r\n[CatalogFiles]",
    };
    size_t i;
    NEED(); fixtures();
    for (i = 0; i < sizeof docs / sizeof *docs; i++) {
        CRYPTCATCDF *c; char buf[2048], leaf[32]; WCHAR cat[MAX_PATH]; char name[32];
        snprintf(buf, sizeof buf, docs[i], g_out);
        snprintf(leaf, sizeof leaf, "style%zu.cdf", i); snprintf(name, sizeof name, "ending%zu.cat", i + 1);
        write_text(leaf, buf);
        out_path(cat, name); DeleteFileW(cat);
        c = open_cdf(leaf, NULL);
        CHECKF(c != NULL, "document %zu", i);
        if (!c) continue;
        CHECKF(fexists(cat), "document %zu: %s not created", i, name);
        U(CryptCATCDFClose)(c);
    }
}

TEST(wtcdf_parse_key_in_wrong_section_is_ignored)
{
    CRYPTCATCDF *c; WCHAR good[MAX_PATH], wrong[MAX_PATH]; char buf[2048];
    NEED(); fixtures();
    snprintf(buf, sizeof buf, "[CatalogHeader]\r\nName=sect.cat\r\nResultDir=%s\r\n[CatalogFiles]\r\nName=other.cat\r\n", g_out);
    write_text("sect.cdf", buf);
    out_path(good, "sect.cat"); out_path(wrong, "other.cat");
    DeleteFileW(good); DeleteFileW(wrong);
    c = open_cdf("sect.cdf", NULL);
    REQUIRE(c != NULL);
    CHECK(fexists(good)); CHECK(!fexists(wrong));
    U(CryptCATCDFClose)(c);
}

/* ---------------------------------------------------------------- catalog attributes */
TEST(wtcdf_catattr_enumeration)
{
    CRYPTCATCDF *c; CRYPTCATATTRIBUTE *a, *a1, *a2;
    NEED(); REQUIRE(U(CryptCATCDFEnumCatAttributes)); fixtures(); cb_reset();
    write_cdf("ca1.cdf", "ca1.cat", 1, "SHA1", "CATATTR1=0x10010001:FirstTag:first value\r\nCATATTR2=0x10010001:SecondTag:second:with:colons\r\n", "");
    c = open_cdf("ca1.cdf", cb_record); REQUIRE(c);
    a1 = a = U(CryptCATCDFEnumCatAttributes)(c, NULL, cb_record);
    REQUIRE(a != NULL);
    CHECK(a->pwszReferenceTag && !wcscmp(a->pwszReferenceTag, L"FirstTag"));
    EXPECT_EQ(a->dwAttrTypeAndAction, 0x10010001);
    EXPECT_EQ(a->cbValue, (12) * sizeof(WCHAR));   /* "first value" plus the terminator, in bytes */
    CHECK(a->pbValue && !wcscmp((WCHAR *)a->pbValue, L"first value"));
    EXPECT_EQ(a->dwReserved, 1);
    a2 = a = U(CryptCATCDFEnumCatAttributes)(c, a, cb_record);
    REQUIRE(a != NULL);
    CHECK(a->pwszReferenceTag && !wcscmp(a->pwszReferenceTag, L"SecondTag"));
    CHECK(a->pbValue && !wcscmp((WCHAR *)a->pbValue, L"second:with:colons"));
    EXPECT_EQ(a->dwReserved, 2);
    CHECK(U(CryptCATCDFEnumCatAttributes)(c, a, cb_record) == NULL);
    EXPECT_EQ(g_cb.n, 0);
    /* the attributes were added to the catalog under construction */
    CHECK(U(CryptCATGetCatAttrInfo)(cdf_store(c), L"FirstTag") == a1);
    CHECK(U(CryptCATGetCatAttrInfo)(cdf_store(c), L"SecondTag") == a2);
    EXPECT_EQ(count_cat_attrs(cdf_store(c)), 2);
    U(CryptCATCDFClose)(c);
}

TEST(wtcdf_catattr_none_present)
{
    CRYPTCATCDF *c;
    NEED(); REQUIRE(U(CryptCATCDFEnumCatAttributes)); fixtures(); cb_reset();
    write_cdf("ca0.cdf", "ca0.cat", 1, "SHA1", "", "");
    c = open_cdf("ca0.cdf", cb_record); REQUIRE(c);
    CHECK(U(CryptCATCDFEnumCatAttributes)(c, NULL, cb_record) == NULL);
    EXPECT_EQ(g_cb.n, 0);
    U(CryptCATCDFClose)(c);
}

TEST(wtcdf_catattr_enumeration_stops_at_gap)
{
    CRYPTCATCDF *c; CRYPTCATATTRIBUTE *a;
    NEED(); REQUIRE(U(CryptCATCDFEnumCatAttributes)); fixtures();
    write_cdf("cag.cdf", "cag.cat", 1, "SHA1", "CATATTR1=0x10010001:One:1\r\nCATATTR3=0x10010001:Three:3\r\n", "");
    c = open_cdf("cag.cdf", NULL); REQUIRE(c);
    a = U(CryptCATCDFEnumCatAttributes)(c, NULL, NULL); CHECK(a != NULL);
    CHECK(a && U(CryptCATCDFEnumCatAttributes)(c, a, NULL) == NULL);   /* CATATTR2 is missing: the numbering is dense */
    U(CryptCATCDFClose)(c);
}

TEST(wtcdf_catattr_invalid_parameters)
{
    CRYPTCATCDF fake;
    NEED(); REQUIRE(U(CryptCATCDFEnumCatAttributes));
    SET_ERR(0); CHECK(U(CryptCATCDFEnumCatAttributes)(NULL, NULL, NULL) == NULL); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    memset(&fake, 0, sizeof fake); fake.cbStruct = 0x20;
    SET_ERR(0); CHECK(U(CryptCATCDFEnumCatAttributes)(&fake, NULL, NULL) == NULL); EXPECT_ERR(ERROR_INVALID_PARAMETER);
}

TEST(wtcdf_catattr_malformed_lines_report_errors)
{
    static const struct { const char *line; DWORD err; } t[] = {
        { "0x10010001:OnlyName", CRYPTCAT_E_CDF_ATTR_TOOFEWVALUES },
        { "0x10010001:Name:", CRYPTCAT_E_CDF_ATTR_TOOFEWVALUES },
        { "justtext", CRYPTCAT_E_CDF_ATTR_TOOFEWVALUES },
        { "0x10000000:Name:value", CRYPTCAT_E_CDF_ATTR_TYPECOMBO },       /* neither name nor data type */
        { "0x10010000:Name:value", CRYPTCAT_E_CDF_ATTR_TYPECOMBO },       /* no name type */
        { "0x10000001:Name:value", CRYPTCAT_E_CDF_ATTR_TYPECOMBO },       /* no data type */
        { "0x20010001:Name:value", CRYPTCAT_E_CDF_UNSUPPORTED },          /* unauthenticated attributes */
    };
    size_t i;
    NEED(); REQUIRE(U(CryptCATCDFEnumCatAttributes)); fixtures();
    for (i = 0; i < sizeof t / sizeof *t; i++) {
        CRYPTCATCDF *c; char hdr[256], leaf[32], name[32]; CRYPTCATATTRIBUTE *a;
        snprintf(hdr, sizeof hdr, "CATATTR1=%s\r\n", t[i].line);
        snprintf(leaf, sizeof leaf, "cab%zu.cdf", i); snprintf(name, sizeof name, "cab%zu.cat", i);
        write_cdf(leaf, name, 1, "SHA1", hdr, "");
        cb_reset();
        c = open_cdf(leaf, NULL); REQUIRE(c);
        a = U(CryptCATCDFEnumCatAttributes)(c, NULL, cb_record);
        CHECKF(a == NULL, "row %zu: %s", i, t[i].line);
        CHECKF(g_cb.n == 1, "row %zu: callback count %d", i, g_cb.n);
        if (g_cb.n >= 1) {
            CHECKF(g_cb.area[0] == CRYPTCAT_E_AREA_ATTRIBUTE, "row %zu area %#lx", i, g_cb.area[0]);
            CHECKF(g_cb.err[0] == t[i].err, "row %zu err %#lx want %#lx", i, g_cb.err[0], t[i].err);
        }
        EXPECT_EQ(count_cat_attrs(cdf_store(c)), 0);
        U(CryptCATCDFClose)(c);
    }
}

TEST(wtcdf_catattr_malformed_line_without_callback)
{
    CRYPTCATCDF *c;
    NEED(); REQUIRE(U(CryptCATCDFEnumCatAttributes)); fixtures();
    write_cdf("cabn.cdf", "cabn.cat", 1, "SHA1", "CATATTR1=bad\r\n", "");
    c = open_cdf("cabn.cdf", NULL); REQUIRE(c);
    CHECK(U(CryptCATCDFEnumCatAttributes)(c, NULL, NULL) == NULL);
    U(CryptCATCDFClose)(c);
}

TEST(wtcdf_catattr_objid_names)
{
    CRYPTCATCDF *c; CRYPTCATATTRIBUTE *a;
    NEED(); REQUIRE(U(CryptCATCDFEnumCatAttributes)); fixtures(); cb_reset();
    write_cdf("cao.cdf", "cao.cat", 1, "SHA1", "CATATTR1=0x10010002:1.3.6.1.4.1.311.12.2.1:oidvalue\r\nCATATTR2=0x10010002:not.an.oid:v\r\n", "");
    c = open_cdf("cao.cdf", NULL); REQUIRE(c);
    a = U(CryptCATCDFEnumCatAttributes)(c, NULL, cb_record);
    CHECK(a != NULL);
    if (a) CHECK(a->pwszReferenceTag && !wcscmp(a->pwszReferenceTag, L"1.3.6.1.4.1.311.12.2.1"));
    CHECK(a && U(CryptCATCDFEnumCatAttributes)(c, a, cb_record) == NULL);   /* the second name is not a dotted-decimal OID */
    EXPECT_EQ(g_cb.n, 1);
    if (g_cb.n >= 1) { EXPECT_EQ(g_cb.area[0], CRYPTCAT_E_AREA_ATTRIBUTE); EXPECT_EQ(g_cb.err[0], CRYPTCAT_E_CDF_ATTR_TYPECOMBO); CHECK(!wcscmp(g_cb.line[0], L"not.an.oid")); }
    U(CryptCATCDFClose)(c);
}

TEST(wtcdf_catattr_flags_without_0x_prefix)
{
    CRYPTCATCDF *c; CRYPTCATATTRIBUTE *a;
    NEED(); REQUIRE(U(CryptCATCDFEnumCatAttributes)); fixtures();
    write_cdf("caf.cdf", "caf.cat", 1, "SHA1", "CATATTR1=10010001:Plain:val\r\n", "");
    c = open_cdf("caf.cdf", NULL); REQUIRE(c);
    a = U(CryptCATCDFEnumCatAttributes)(c, NULL, NULL);
    CHECK(a != NULL);
    if (a) EXPECT_EQ(a->dwAttrTypeAndAction, 0x10010001);
    U(CryptCATCDFClose)(c);
}

TEST(wtcdf_catattr_no_auto_compat_flag_is_removed)
{
    CRYPTCATCDF *c; CRYPTCATATTRIBUTE *a;
    NEED(); REQUIRE(U(CryptCATCDFEnumCatAttributes)); fixtures();
    write_cdf("cac.cdf", "cac.cat", 1, "SHA1", "CATATTR1=0x11010001:Compat:val\r\n", "");
    c = open_cdf("cac.cdf", NULL); REQUIRE(c);
    a = U(CryptCATCDFEnumCatAttributes)(c, NULL, NULL);
    CHECK(a != NULL);
    if (a) EXPECT_EQ(a->dwAttrTypeAndAction, 0x10010001);   /* CRYPTCAT_ATTR_NO_AUTO_COMPAT_ENTRY is consumed by the parser */
    U(CryptCATCDFClose)(c);
}

/* ---------------------------------------------------------------- members */
TEST(wtcdf_members_flat_files_v1)
{
    CRYPTCATCDF *c; CRYPTCATMEMBER *m, *m2; char files[1024]; char wantpath[MAX_PATH]; WCHAR wp[MAX_PATH];
    NO_WINE(); NEED(); REQUIRE(UN(CryptCATCDFEnumMembers)); fixtures(); cb_reset();
    files_v1(files, sizeof files, "");
    write_cdf("mv1.cdf", "mv1.cat", 1, "SHA1", "", files);
    c = open_cdf("mv1.cdf", cb_record); REQUIRE(c);
    m = UN(CryptCATCDFEnumMembers)(c, NULL, cb_record);
    REQUIRE(m != NULL);
    EXPECT_EQ(m->cbStruct, 0x68);
    CHECK(m->pwszReferenceTag && !wcscmp(m->pwszReferenceTag, L"fa"));
    snprintf(wantpath, sizeof wantpath, "%sfa.dat", g_dir); wtow(wp, MAX_PATH, wantpath);
    CHECK(m->pwszFileName && !wcscmp(m->pwszFileName, wp));
    CHECK(!memcmp(&m->gSubjectType, &GUID_FLAT, sizeof(GUID)));
    CHECK(dig_is(m, OID_SHA1, flat_a_sha1, 20));
    t_note("flat member: dwCertVersion=%#lx fdwMemberFlags=%#lx Data.pszObjId=%s", m->dwCertVersion, m->fdwMemberFlags,
           m->pIndirectData && m->pIndirectData->Data.pszObjId ? m->pIndirectData->Data.pszObjId : "(null)");
    m2 = UN(CryptCATCDFEnumMembers)(c, m, cb_record);
    REQUIRE(m2 != NULL);
    CHECK(m2->pwszReferenceTag && !wcscmp(m2->pwszReferenceTag, L"fc"));
    CHECK(dig_is(m2, OID_SHA1, flat_c_sha1, 20));
    SET_ERR(0xdead);
    CHECK(UN(CryptCATCDFEnumMembers)(c, m2, cb_record) == NULL);
    EXPECT_ERR(0);   /* end of the list is not an error */
    EXPECT_EQ(g_cb.n, 0);
    CHECK(U(CryptCATGetMemberInfo)(cdf_store(c), L"fa") == m);
    CHECK(U(CryptCATGetMemberInfo)(cdf_store(c), L"fc") == m2);
    EXPECT_EQ(count_members(cdf_store(c)), 2);
    U(CryptCATCDFClose)(c);
}

TEST(wtcdf_members_large_flat_file_digest)
{
    CRYPTCATCDF *c; CRYPTCATMEMBER *m; char files[512];
    NO_WINE(); NEED(); REQUIRE(UN(CryptCATCDFEnumMembers)); fixtures();
    snprintf(files, sizeof files, "big=%sfb.dat\r\n", g_dir);
    write_cdf("mbig.cdf", "mbig.cat", 1, "SHA1", "", files);
    c = open_cdf("mbig.cdf", NULL); REQUIRE(c);
    m = UN(CryptCATCDFEnumMembers)(c, NULL, NULL); REQUIRE(m);
    CHECK(dig_is(m, OID_SHA1, flat_b_sha1, 20));
    U(CryptCATCDFClose)(c);
}

TEST(wtcdf_members_sha256_catalog)
{
    CRYPTCATCDF *c; CRYPTCATMEMBER *m; char files[512];
    NO_WINE(); NEED(); REQUIRE(UN(CryptCATCDFEnumMembers)); fixtures();
    snprintf(files, sizeof files, "<HASH>fa=%sfa.dat\r\n", g_dir);
    write_cdf("m256.cdf", "m256.cat", 2, "SHA256", "", files);
    c = open_cdf("m256.cdf", NULL); REQUIRE(c);
    m = UN(CryptCATCDFEnumMembers)(c, NULL, NULL); REQUIRE(m);
    CHECK(m->pwszReferenceTag && !wcscmp(m->pwszReferenceTag, L"<HASH>fa"));   /* EnumMembers never substitutes the hash tag */
    CHECK(dig_is(m, OID_SHA256, flat_a_sha256, 32));
    EXPECT_EQ(count_members(cdf_store(c)), 1);
    U(CryptCATCDFClose)(c);
}

TEST(wtcdf_members_pe_images)
{
    CRYPTCATCDF *c; CRYPTCATMEMBER *m = NULL; char files[1024]; int i;
    struct { const char *tag; const BYTE *want; } t[] = { { "pbase", pe_base_sha1 }, { "pts", pe_ts_sha1 }, { "pchk", pe_chk_sha1 }, { "ptrail", pe_trail_sha1 } };
    NO_WINE(); NEED(); REQUIRE(UN(CryptCATCDFEnumMembers)); fixtures();
    snprintf(files, sizeof files, "pbase=%sp_base.bin\r\npts=%sp_ts.bin\r\npchk=%sp_chk.bin\r\nptrail=%sp_trail.bin\r\n", g_dir, g_dir, g_dir, g_dir);
    write_cdf("mpe.cdf", "mpe.cat", 1, "SHA1", "", files);
    c = open_cdf("mpe.cdf", NULL); REQUIRE(c);
    for (i = 0; i < 4; i++) {
        m = UN(CryptCATCDFEnumMembers)(c, m, NULL);
        CHECKF(m != NULL, "member %d", i);
        if (!m) break;
        { WCHAR wt[16]; wtow(wt, 16, t[i].tag); CHECKF(m->pwszReferenceTag && !wcscmp(m->pwszReferenceTag, wt), "member %d tag", i); }
        CHECK(!memcmp(&m->gSubjectType, &GUID_PE, sizeof(GUID)));
        CHECKF(dig_is(m, OID_SHA1, t[i].want, 20), "PE member %d (%s) digest", i, t[i].tag);
    }
    U(CryptCATCDFClose)(c);
}

TEST(wtcdf_members_pe_sha256)
{
    CRYPTCATCDF *c; CRYPTCATMEMBER *m = NULL; char files[512]; int i;
    const BYTE *want[] = { pe_base_sha256, pe_trail_sha256 };
    NO_WINE(); NEED(); REQUIRE(UN(CryptCATCDFEnumMembers)); fixtures();
    snprintf(files, sizeof files, "<HASH>pb=%sp_base.bin\r\n<HASH>pt=%sp_trail.bin\r\n", g_dir, g_dir);
    write_cdf("mpe2.cdf", "mpe2.cat", 2, "SHA256", "", files);
    c = open_cdf("mpe2.cdf", NULL); REQUIRE(c);
    for (i = 0; i < 2; i++) {
        m = UN(CryptCATCDFEnumMembers)(c, m, NULL);
        CHECKF(m != NULL, "member %d", i);
        if (m) CHECKF(dig_is(m, OID_SHA256, want[i], 32), "PE member %d sha256", i);
    }
    U(CryptCATCDFClose)(c);
}

TEST(wtcdf_members_pe_digest_ignores_checksum_not_timestamp)
{
    CHECK(memcmp(pe_base_sha1, pe_chk_sha1, 20) == 0);
    CHECK(memcmp(pe_base_sha1, pe_ts_sha1, 20) != 0);
    CHECK(memcmp(pe_base_sha1, pe_trail_sha1, 20) != 0);
    CHECK(memcmp(pe_base_sha256, pe_chk_sha256, 32) == 0);
}

TEST(wtcdf_members_missing_file)
{
    CRYPTCATCDF *c; CRYPTCATMEMBER *m; char files[512]; char miss[MAX_PATH]; WCHAR wmiss[MAX_PATH];
    NO_WINE(); NEED(); REQUIRE(UN(CryptCATCDFEnumMembers)); fixtures(); cb_reset();
    snprintf(miss, sizeof miss, "%sdoes_not_exist.dat", g_dir); wtow(wmiss, MAX_PATH, miss);
    snprintf(files, sizeof files, "gone=%s\r\n", miss);
    write_cdf("mgone.cdf", "mgone.cat", 1, "SHA1", "", files);
    c = open_cdf("mgone.cdf", cb_record); REQUIRE(c);
    SET_ERR(0);
    m = UN(CryptCATCDFEnumMembers)(c, NULL, cb_record);
    CHECK(m == NULL);
    EXPECT_ERR(ERROR_FILE_NOT_FOUND);
    EXPECT_EQ(g_cb.n, 1);
    if (g_cb.n >= 1) {
        EXPECT_EQ(g_cb.area[0], CRYPTCAT_E_AREA_MEMBER);
        EXPECT_EQ(g_cb.err[0], CRYPTCAT_E_CDF_MEMBER_FILENOTFOUND);
        CHECK(!wcscmp(g_cb.line[0], wmiss));
    }
    EXPECT_EQ(count_members(cdf_store(c)), 0);
    U(CryptCATCDFClose)(c);
}

TEST(wtcdf_members_missing_directory_error_code)
{
    CRYPTCATCDF *c; char files[512];
    NO_WINE(); NEED(); REQUIRE(UN(CryptCATCDFEnumMembers)); fixtures();
    snprintf(files, sizeof files, "gone=%sno_such_dir\\x.dat\r\n", g_dir);
    write_cdf("mgone2.cdf", "mgone2.cat", 1, "SHA1", "", files);
    c = open_cdf("mgone2.cdf", NULL); REQUIRE(c);
    SET_ERR(0);
    CHECK(UN(CryptCATCDFEnumMembers)(c, NULL, NULL) == NULL);
    EXPECT_ERR(ERROR_PATH_NOT_FOUND);
    U(CryptCATCDFClose)(c);
}

TEST(wtcdf_members_no_catalogfiles_section)
{
    CRYPTCATCDF *c;
    NO_WINE(); NEED(); REQUIRE(UN(CryptCATCDFEnumMembers)); fixtures();
    write_text("mnone.cdf", "[CatalogHeader]\r\nName=mnone.cat\r\n");
    {   char b[600]; snprintf(b, sizeof b, "[CatalogHeader]\r\nName=mnone.cat\r\nResultDir=%s\r\n", g_out); write_text("mnone.cdf", b); }
    c = open_cdf("mnone.cdf", NULL); REQUIRE(c);
    SET_ERR(0xdead);
    CHECK(UN(CryptCATCDFEnumMembers)(c, NULL, NULL) == NULL);
    EXPECT_ERR(0);
    U(CryptCATCDFClose)(c);
}

TEST(wtcdf_members_empty_catalogfiles_section)
{
    CRYPTCATCDF *c;
    NO_WINE(); NEED(); REQUIRE(UN(CryptCATCDFEnumMembers)); fixtures();
    write_cdf("mempty.cdf", "mempty.cat", 1, "SHA1", "", "");
    c = open_cdf("mempty.cdf", NULL); REQUIRE(c);
    SET_ERR(0xdead);
    CHECK(UN(CryptCATCDFEnumMembers)(c, NULL, NULL) == NULL);
    EXPECT_ERR(0);
    U(CryptCATCDFClose)(c);
}

TEST(wtcdf_members_invalid_parameters)
{
    CRYPTCATCDF *c; CRYPTCATMEMBER fake; char files[512];
    NO_WINE(); NEED(); REQUIRE(UN(CryptCATCDFEnumMembers)); fixtures();
    SET_ERR(0); CHECK(UN(CryptCATCDFEnumMembers)(NULL, NULL, NULL) == NULL); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    snprintf(files, sizeof files, "fa=%sfa.dat\r\n", g_dir);
    write_cdf("minv.cdf", "minv.cat", 1, "SHA1", "", files);
    c = open_cdf("minv.cdf", NULL); REQUIRE(c);
    memset(&fake, 0, sizeof fake); fake.cbStruct = 0x40;
    SET_ERR(0); CHECK(UN(CryptCATCDFEnumMembers)(c, &fake, NULL) == NULL); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    U(CryptCATCDFClose)(c);
}

TEST(wtcdf_members_tag_prefix_lines_are_skipped)
{
    /* a line whose key begins with the previous tag (attribute lines, PageHashes, ALTSIPID) is not a new member */
    CRYPTCATCDF *c; CRYPTCATMEMBER *m; char files[1024];
    NO_WINE(); NEED(); REQUIRE(UN(CryptCATCDFEnumMembers)); fixtures();
    snprintf(files, sizeof files, "fa=%sfa.dat\r\nfaATTR1=0x10010001:A:1\r\nfaPageHashes=false\r\nfaATTR2=0x10010001:B:2\r\nfc=%sfc.dat\r\n", g_dir, g_dir);
    write_cdf("mskip.cdf", "mskip.cat", 1, "SHA1", "", files);
    c = open_cdf("mskip.cdf", NULL); REQUIRE(c);
    m = UN(CryptCATCDFEnumMembers)(c, NULL, NULL); REQUIRE(m);
    CHECK(!wcscmp(m->pwszReferenceTag, L"fa"));
    m = UN(CryptCATCDFEnumMembers)(c, m, NULL); REQUIRE(m);
    CHECK(!wcscmp(m->pwszReferenceTag, L"fc"));
    CHECK(UN(CryptCATCDFEnumMembers)(c, m, NULL) == NULL);
    U(CryptCATCDFClose)(c);
}

TEST(wtcdf_members_comment_lines_between_members)
{
    CRYPTCATCDF *c; CRYPTCATMEMBER *m; char files[1024];
    NO_WINE(); NEED(); REQUIRE(UN(CryptCATCDFEnumMembers)); fixtures();
    snprintf(files, sizeof files, "# comment\r\nfa=%sfa.dat\r\n# another\r\n\r\nfc=%sfc.dat\r\n", g_dir, g_dir);
    write_cdf("mcom.cdf", "mcom.cat", 1, "SHA1", "", files);
    c = open_cdf("mcom.cdf", NULL); REQUIRE(c);
    m = UN(CryptCATCDFEnumMembers)(c, NULL, NULL); CHECK(m && !wcscmp(m->pwszReferenceTag, L"fa"));
    if (m) m = UN(CryptCATCDFEnumMembers)(c, m, NULL);
    CHECK(m && !wcscmp(m->pwszReferenceTag, L"fc"));
    U(CryptCATCDFClose)(c);
}

TEST(wtcdf_members_section_end_stops_enumeration)
{
    CRYPTCATCDF *c; CRYPTCATMEMBER *m; char files[1024];
    NO_WINE(); NEED(); REQUIRE(UN(CryptCATCDFEnumMembers)); fixtures();
    snprintf(files, sizeof files, "fa=%sfa.dat\r\n[Other]\r\nfc=%sfc.dat\r\n", g_dir, g_dir);
    write_cdf("msec.cdf", "msec.cat", 1, "SHA1", "", files);
    c = open_cdf("msec.cdf", NULL); REQUIRE(c);
    m = UN(CryptCATCDFEnumMembers)(c, NULL, NULL); REQUIRE(m);
    CHECK(UN(CryptCATCDFEnumMembers)(c, m, NULL) == NULL);
    U(CryptCATCDFClose)(c);
}

/* ---------------------------------------------------------------- member attributes */
TEST(wtcdf_member_attributes)
{
    CRYPTCATCDF *c; CRYPTCATMEMBER *m; CRYPTCATATTRIBUTE *a, *a1; char files[1024];
    NO_WINE(); NEED(); REQUIRE(UN(CryptCATCDFEnumMembers)); REQUIRE(UN(CryptCATCDFEnumAttributes)); fixtures(); cb_reset();
    files_v1(files, sizeof files, "");
    write_cdf("mat.cdf", "mat.cat", 1, "SHA1", "", files);
    c = open_cdf("mat.cdf", cb_record); REQUIRE(c);
    m = UN(CryptCATCDFEnumMembers)(c, NULL, cb_record); REQUIRE(m);
    a1 = a = UN(CryptCATCDFEnumAttributes)(c, m, NULL, cb_record);
    REQUIRE(a != NULL);
    CHECK(a->pwszReferenceTag && !wcscmp(a->pwszReferenceTag, L"File"));
    CHECK(a->pbValue && !wcscmp((WCHAR *)a->pbValue, L"fa.dat"));
    EXPECT_EQ(a->dwReserved, 1);
    a = UN(CryptCATCDFEnumAttributes)(c, m, a, cb_record);
    REQUIRE(a != NULL);
    CHECK(a->pwszReferenceTag && !wcscmp(a->pwszReferenceTag, L"Other"));
    EXPECT_EQ(a->dwReserved, 2);
    CHECK(UN(CryptCATCDFEnumAttributes)(c, m, a, cb_record) == NULL);
    EXPECT_EQ(g_cb.n, 0);
    CHECK(U(CryptCATGetAttrInfo)(cdf_store(c), m, L"File") == a1);
    EXPECT_EQ(count_attrs(cdf_store(c), m), 2);
    U(CryptCATCDFClose)(c);
}

TEST(wtcdf_member_attributes_member_without_any)
{
    CRYPTCATCDF *c; CRYPTCATMEMBER *m; char files[1024];
    NO_WINE(); NEED(); REQUIRE(UN(CryptCATCDFEnumMembers)); REQUIRE(UN(CryptCATCDFEnumAttributes)); fixtures();
    files_v1(files, sizeof files, "");
    write_cdf("mat2.cdf", "mat2.cat", 1, "SHA1", "", files);
    c = open_cdf("mat2.cdf", NULL); REQUIRE(c);
    m = UN(CryptCATCDFEnumMembers)(c, NULL, NULL); REQUIRE(m);
    m = UN(CryptCATCDFEnumMembers)(c, m, NULL); REQUIRE(m);   /* "fc" has no attribute lines */
    CHECK(UN(CryptCATCDFEnumAttributes)(c, m, NULL, NULL) == NULL);
    U(CryptCATCDFClose)(c);
}

TEST(wtcdf_member_attributes_must_follow_their_member)
{
    CRYPTCATCDF *c; CRYPTCATMEMBER *m; char files[1024];
    NO_WINE(); NEED(); REQUIRE(UN(CryptCATCDFEnumMembers)); REQUIRE(UN(CryptCATCDFEnumAttributes)); fixtures();
    snprintf(files, sizeof files, "fa=%sfa.dat\r\nfcATTR1=0x10010001:Misplaced:x\r\nfc=%sfc.dat\r\n", g_dir, g_dir);
    write_cdf("mat3.cdf", "mat3.cat", 1, "SHA1", "", files);
    c = open_cdf("mat3.cdf", NULL); REQUIRE(c);
    m = UN(CryptCATCDFEnumMembers)(c, NULL, NULL); REQUIRE(m);
    CHECK(UN(CryptCATCDFEnumAttributes)(c, m, NULL, NULL) == NULL);
    U(CryptCATCDFClose)(c);
}

TEST(wtcdf_member_attributes_invalid_parameters)
{
    CRYPTCATCDF *c, fakec; CRYPTCATMEMBER *m, fakem; char files[512];
    NO_WINE(); NEED(); REQUIRE(UN(CryptCATCDFEnumMembers)); REQUIRE(UN(CryptCATCDFEnumAttributes)); fixtures();
    snprintf(files, sizeof files, "fa=%sfa.dat\r\n", g_dir);
    write_cdf("mat4.cdf", "mat4.cat", 1, "SHA1", "", files);
    c = open_cdf("mat4.cdf", NULL); REQUIRE(c);
    m = UN(CryptCATCDFEnumMembers)(c, NULL, NULL); REQUIRE(m);
    memset(&fakem, 0, sizeof fakem); fakem.cbStruct = 0x40; fakem.pwszReferenceTag = L"fa";
    memset(&fakec, 0, sizeof fakec); fakec.cbStruct = 0x20;
    SET_ERR(0); CHECK(UN(CryptCATCDFEnumAttributes)(NULL, m, NULL, NULL) == NULL); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(UN(CryptCATCDFEnumAttributes)(&fakec, m, NULL, NULL) == NULL); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(UN(CryptCATCDFEnumAttributes)(c, &fakem, NULL, NULL) == NULL); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    U(CryptCATCDFClose)(c);
}

TEST(wtcdf_member_attributes_malformed)
{
    CRYPTCATCDF *c; CRYPTCATMEMBER *m; char files[512];
    NO_WINE(); NEED(); REQUIRE(UN(CryptCATCDFEnumMembers)); REQUIRE(UN(CryptCATCDFEnumAttributes)); fixtures(); cb_reset();
    snprintf(files, sizeof files, "fa=%sfa.dat\r\nfaATTR1=0x10010001:NoValue\r\n", g_dir);
    write_cdf("mat5.cdf", "mat5.cat", 1, "SHA1", "", files);
    c = open_cdf("mat5.cdf", cb_record); REQUIRE(c);
    m = UN(CryptCATCDFEnumMembers)(c, NULL, cb_record); REQUIRE(m);
    CHECK(UN(CryptCATCDFEnumAttributes)(c, m, NULL, cb_record) == NULL);
    EXPECT_EQ(g_cb.n, 1);
    if (g_cb.n >= 1) { EXPECT_EQ(g_cb.area[0], CRYPTCAT_E_AREA_ATTRIBUTE); EXPECT_EQ(g_cb.err[0], CRYPTCAT_E_CDF_ATTR_TOOFEWVALUES); }
    EXPECT_EQ(count_attrs(cdf_store(c), m), 0);
    U(CryptCATCDFClose)(c);
}

/* ---------------------------------------------------------------- EnumMembersByCDFTag(Ex) */
TEST(wtcdf_bytag_v1_plain_tags)
{
    CRYPTCATCDF *c; CRYPTCATMEMBER *m = NULL; LPWSTR t; char files[1024];
    NEED(); REQUIRE(U(CryptCATCDFEnumMembersByCDFTagEx)); fixtures(); cb_reset();
    files_v1(files, sizeof files, "");
    write_cdf("bt1.cdf", "bt1.cat", 1, "SHA1", "", files);
    c = open_cdf("bt1.cdf", cb_record); REQUIRE(c);
    t = U(CryptCATCDFEnumMembersByCDFTagEx)(c, NULL, cb_record, &m, FALSE, NULL);
    REQUIRE(t != NULL && m != NULL);
    CHECK(!wcscmp(t, L"fa"));
    CHECK(m->pwszReferenceTag && !wcscmp(m->pwszReferenceTag, L"fa"));   /* version 1: non-hash tags are stored as written */
    CHECK(dig_is(m, OID_SHA1, flat_a_sha1, 20));
    m = NULL;
    t = U(CryptCATCDFEnumMembersByCDFTagEx)(c, t, cb_record, &m, FALSE, NULL);   /* the previous tag is released by the callee */
    REQUIRE(t != NULL && m != NULL);
    CHECK(!wcscmp(t, L"fc"));
    CHECK(dig_is(m, OID_SHA1, flat_c_sha1, 20));
    m = NULL;
    SET_ERR(0xdead);
    t = U(CryptCATCDFEnumMembersByCDFTagEx)(c, t, cb_record, &m, FALSE, NULL);
    CHECK(t == NULL); CHECK(m == NULL);
    EXPECT_ERR(0);
    EXPECT_EQ(g_cb.n, 0);
    EXPECT_EQ(count_members(cdf_store(c)), 2);
    U(CryptCATCDFClose)(c);
}

TEST(wtcdf_bytag_non_ex_variant)
{
    CRYPTCATCDF *c; CRYPTCATMEMBER *m = NULL; LPWSTR t; char files[1024];
    NO_WINE(); NEED(); REQUIRE(UN(CryptCATCDFEnumMembersByCDFTag)); fixtures();
    files_v1(files, sizeof files, "");
    write_cdf("bt2.cdf", "bt2.cat", 1, "SHA1", "", files);
    c = open_cdf("bt2.cdf", NULL); REQUIRE(c);
    t = UN(CryptCATCDFEnumMembersByCDFTag)(c, NULL, NULL, &m);
    REQUIRE(t != NULL && m != NULL);
    CHECK(!wcscmp(t, L"fa"));
    m = NULL;
    t = UN(CryptCATCDFEnumMembersByCDFTag)(c, t, NULL, &m);
    REQUIRE(t != NULL && m != NULL);
    CHECK(!wcscmp(t, L"fc"));
    m = NULL;
    CHECK(UN(CryptCATCDFEnumMembersByCDFTag)(c, t, NULL, &m) == NULL);
    U(CryptCATCDFClose)(c);
}

TEST(wtcdf_bytag_v2_hash_tags_and_compat_member)
{
    CRYPTCATCDF *c; CRYPTCATMEMBER *m = NULL, *compat; LPWSTR t; char files[512]; WCHAR h256[65], h1[41];
    NEED(); REQUIRE(U(CryptCATCDFEnumMembersByCDFTagEx)); fixtures(); cb_reset();
    snprintf(files, sizeof files, "<HASH>fa=%sfa.dat\r\n", g_dir);
    write_cdf("bt3.cdf", "bt3.cat", 2, "SHA256", "", files);
    hex_upper(h256, flat_a_sha256, 32); hex_upper(h1, flat_a_sha1, 20);
    c = open_cdf("bt3.cdf", cb_record); REQUIRE(c);
    t = U(CryptCATCDFEnumMembersByCDFTagEx)(c, NULL, cb_record, &m, FALSE, NULL);
    REQUIRE(t != NULL && m != NULL);
    CHECK(!wcscmp(t, L"<HASH>fa"));
    CHECK(m->pwszReferenceTag && !wcscmp(m->pwszReferenceTag, h256));   /* reference tag = upper-case hex of the file hash */
    CHECK(dig_is(m, OID_SHA256, flat_a_sha256, 32));
    /* a SHA-1 compatibility member is added next to the SHA-256 one */
    compat = U(CryptCATGetMemberInfo)(cdf_store(c), h1);
    CHECK(compat != NULL);
    if (compat) CHECK(dig_is(compat, OID_SHA1, flat_a_sha1, 20));
    EXPECT_EQ(count_members(cdf_store(c)), 2);
    CHECK(U(CryptCATCDFEnumMembersByCDFTagEx)(c, t, cb_record, &m, FALSE, NULL) == NULL);
    EXPECT_EQ(g_cb.n, 0);
    CHECK(U(CryptCATCDFClose)(c));
}

TEST(wtcdf_bytag_v1_hash_tag_substitution)
{
    CRYPTCATCDF *c; CRYPTCATMEMBER *m = NULL; LPWSTR t; char files[512]; WCHAR h1[41];
    NEED(); REQUIRE(U(CryptCATCDFEnumMembersByCDFTagEx)); fixtures();
    snprintf(files, sizeof files, "<HASH>fa=%sfa.dat\r\n", g_dir);
    write_cdf("bt4.cdf", "bt4.cat", 1, "SHA1", "", files);
    hex_upper(h1, flat_a_sha1, 20);
    c = open_cdf("bt4.cdf", NULL); REQUIRE(c);
    t = U(CryptCATCDFEnumMembersByCDFTagEx)(c, NULL, NULL, &m, FALSE, NULL);
    REQUIRE(t && m);
    CHECK(m->pwszReferenceTag && !wcscmp(m->pwszReferenceTag, h1));
    EXPECT_EQ(count_members(cdf_store(c)), 1);   /* SHA-1 catalogs need no compatibility member */
    LocalFree(t);
    U(CryptCATCDFClose)(c);
}

TEST(wtcdf_bytag_v2_requires_hash_tags)
{
    CRYPTCATCDF *c; CRYPTCATMEMBER *m = NULL; LPWSTR t; char files[512];
    NEED(); REQUIRE(U(CryptCATCDFEnumMembersByCDFTagEx)); fixtures();
    snprintf(files, sizeof files, "plaintag=%sfa.dat\r\n", g_dir);
    write_cdf("bt5.cdf", "bt5.cat", 2, "SHA256", "", files);
    c = open_cdf("bt5.cdf", NULL); REQUIRE(c);
    SET_ERR(0);
    t = U(CryptCATCDFEnumMembersByCDFTagEx)(c, NULL, NULL, &m, TRUE, NULL);
    CHECK(t == NULL); CHECK(m == NULL);
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
    EXPECT_EQ(count_members(cdf_store(c)), 0);
    U(CryptCATCDFClose)(c);
}

TEST(wtcdf_bytag_missing_file_stops_unless_continue)
{
    CRYPTCATCDF *c; CRYPTCATMEMBER *m = NULL; LPWSTR t; char files[1024]; char miss[MAX_PATH]; WCHAR wmiss[MAX_PATH];
    NEED(); REQUIRE(U(CryptCATCDFEnumMembersByCDFTagEx)); fixtures(); cb_reset();
    snprintf(miss, sizeof miss, "%snot_there.dat", g_dir); wtow(wmiss, MAX_PATH, miss);
    snprintf(files, sizeof files, "bad=%s\r\ngood=%sfa.dat\r\n", miss, g_dir);
    write_cdf("bt6.cdf", "bt6.cat", 1, "SHA1", "", files);
    c = open_cdf("bt6.cdf", cb_record); REQUIRE(c);
    SET_ERR(0);
    t = U(CryptCATCDFEnumMembersByCDFTagEx)(c, NULL, cb_record, &m, FALSE, NULL);
    CHECK(t == NULL); CHECK(m == NULL);
    EXPECT_ERR(ERROR_FILE_NOT_FOUND);
    EXPECT_EQ(g_cb.n, 1);
    if (g_cb.n >= 1) { EXPECT_EQ(g_cb.area[0], CRYPTCAT_E_AREA_MEMBER); EXPECT_EQ(g_cb.err[0], CRYPTCAT_E_CDF_MEMBER_FILENOTFOUND); CHECK(!wcscmp(g_cb.line[0], wmiss)); }
    U(CryptCATCDFClose)(c);

    /* with fContinueOnError the caller still gets the tag, so enumeration can go on */
    cb_reset(); m = NULL;
    c = open_cdf("bt6.cdf", cb_record); REQUIRE(c);
    SET_ERR(0);
    t = U(CryptCATCDFEnumMembersByCDFTagEx)(c, NULL, cb_record, &m, TRUE, NULL);
    CHECK(t != NULL); CHECK(m == NULL);
    EXPECT_ERR(ERROR_FILE_NOT_FOUND);
    if (t) {
        CHECK(!wcscmp(t, L"bad"));
        t = U(CryptCATCDFEnumMembersByCDFTagEx)(c, t, cb_record, &m, TRUE, NULL);
        CHECK(t != NULL && m != NULL);
        if (t) { CHECK(!wcscmp(t, L"good")); LocalFree(t); }
        if (m) CHECK(dig_is(m, OID_SHA1, flat_a_sha1, 20));
    }
    U(CryptCATCDFClose)(c);
}

TEST(wtcdf_bytag_invalid_cdf)
{
    CRYPTCATCDF fake; CRYPTCATMEMBER *m = NULL;
    NEED(); REQUIRE(U(CryptCATCDFEnumMembersByCDFTagEx));
    SET_ERR(0); CHECK(U(CryptCATCDFEnumMembersByCDFTagEx)(NULL, NULL, NULL, &m, FALSE, NULL) == NULL); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    memset(&fake, 0, sizeof fake);   /* hFile == NULL */
    SET_ERR(0); CHECK(U(CryptCATCDFEnumMembersByCDFTagEx)(&fake, NULL, NULL, &m, FALSE, NULL) == NULL); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    CHECK(m == NULL);
}

TEST(wtcdf_bytag_member_attributes_with_cdf_tag)
{
    CRYPTCATCDF *c; CRYPTCATMEMBER *m = NULL, *compat; LPWSTR t; CRYPTCATATTRIBUTE *a; char files[1024]; WCHAR h1[41];
    NO_WINE(); NEED(); REQUIRE(U(CryptCATCDFEnumMembersByCDFTagEx)); REQUIRE(UN(CryptCATCDFEnumAttributesWithCDFTag)); fixtures();
    snprintf(files, sizeof files, "<HASH>fa=%sfa.dat\r\n<HASH>faATTR1=0x10010001:File:fa.dat\r\n<HASH>faATTR2=0x11010001:NoCompat:x\r\n", g_dir);
    write_cdf("bt7.cdf", "bt7.cat", 2, "SHA256", "", files);
    hex_upper(h1, flat_a_sha1, 20);
    c = open_cdf("bt7.cdf", NULL); REQUIRE(c);
    t = U(CryptCATCDFEnumMembersByCDFTagEx)(c, NULL, NULL, &m, FALSE, NULL);
    REQUIRE(t && m);
    a = UN(CryptCATCDFEnumAttributesWithCDFTag)(c, t, m, NULL, NULL);
    REQUIRE(a != NULL);
    CHECK(a->pwszReferenceTag && !wcscmp(a->pwszReferenceTag, L"File"));
    EXPECT_EQ(a->dwReserved, 1);
    a = UN(CryptCATCDFEnumAttributesWithCDFTag)(c, t, m, a, NULL);
    REQUIRE(a != NULL);
    CHECK(a->pwszReferenceTag && !wcscmp(a->pwszReferenceTag, L"NoCompat"));
    EXPECT_EQ(a->dwAttrTypeAndAction, 0x10010001);
    CHECK(UN(CryptCATCDFEnumAttributesWithCDFTag)(c, t, m, a, NULL) == NULL);
    EXPECT_EQ(count_attrs(cdf_store(c), m), 2);
    /* the first attribute is mirrored onto the SHA-1 compatibility member, the NO_AUTO_COMPAT one is not */
    compat = U(CryptCATGetMemberInfo)(cdf_store(c), h1);
    CHECK(compat != NULL);
    if (compat) { CHECK(U(CryptCATGetAttrInfo)(cdf_store(c), compat, L"File") != NULL); CHECK(U(CryptCATGetAttrInfo)(cdf_store(c), compat, L"NoCompat") == NULL); }
    LocalFree(t);
    U(CryptCATCDFClose)(c);
}

TEST(wtcdf_attributes_with_cdf_tag_null_tag)
{
    CRYPTCATCDF *c; CRYPTCATMEMBER *m = NULL; LPWSTR t; char files[512];
    NO_WINE(); NEED(); REQUIRE(U(CryptCATCDFEnumMembersByCDFTagEx)); REQUIRE(UN(CryptCATCDFEnumAttributesWithCDFTag)); fixtures();
    snprintf(files, sizeof files, "fa=%sfa.dat\r\n", g_dir);
    write_cdf("bt8.cdf", "bt8.cat", 1, "SHA1", "", files);
    c = open_cdf("bt8.cdf", NULL); REQUIRE(c);
    t = U(CryptCATCDFEnumMembersByCDFTagEx)(c, NULL, NULL, &m, FALSE, NULL);
    REQUIRE(t && m);
    SET_ERR(0); CHECK(UN(CryptCATCDFEnumAttributesWithCDFTag)(c, NULL, m, NULL, NULL) == NULL); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    LocalFree(t);
    U(CryptCATCDFClose)(c);
}

/* ---------------------------------------------------------------- malformed PE handling */
TEST(wtcdf_nonconformant_pe_fallback_flat)
{
    /* Windows keeps the fallback switch process-wide once it was enabled, so the strict case runs first. */
    CRYPTCATCDF *c; CRYPTCATMEMBER *m; char files[512]; BYTE bad[0x300]; WCHAR wbad[MAX_PATH]; char pbad[MAX_PATH]; int strict_failed;
    NO_WINE(); NEED(); REQUIRE(UN(CryptCATCDFEnumMembers)); fixtures(); cb_reset();
    memset(bad, 0x41, sizeof bad); bad[0] = 'M'; bad[1] = 'Z';
    snprintf(pbad, sizeof pbad, "%sbadpe.bin", g_dir); wtow(wbad, MAX_PATH, pbad); put_file(wbad, bad, sizeof bad);
    snprintf(files, sizeof files, "bad=%s\r\n", pbad);
    write_cdf("npe1.cdf", "npe1.cat", 1, "SHA1", "", files);
    c = open_cdf("npe1.cdf", cb_record); REQUIRE(c);
    SET_ERR(0);
    m = UN(CryptCATCDFEnumMembers)(c, NULL, cb_record);
    strict_failed = (m == NULL);
    if (strict_failed) {
        t_note("strict mode rejected the malformed image, GLE %lu", GetLastError());
        EXPECT_EQ(g_cb.n, 1);
        if (g_cb.n >= 1) { EXPECT_EQ(g_cb.area[0], CRYPTCAT_E_AREA_MEMBER); EXPECT_EQ(g_cb.err[0], CRYPTCAT_E_CDF_MEMBER_INDIRECTDATA); CHECK(!wcscmp(g_cb.line[0], wbad)); }
    } else t_note("the malformed image was hashed without the fallback switch (SIP treats it as a flat file)");
    U(CryptCATCDFClose)(c);

    write_cdf("npe2.cdf", "npe2.cat", 1, "SHA1", "NonConformantFilesFallbackFlat=true\r\n", files);
    c = open_cdf("npe2.cdf", NULL); REQUIRE(c);
    m = UN(CryptCATCDFEnumMembers)(c, NULL, NULL);
    CHECK(m != NULL);
    if (m && strict_failed) CHECK(!memcmp(&m->gSubjectType, &GUID_FLAT, sizeof(GUID)));
    U(CryptCATCDFClose)(c);
}

/* ---------------------------------------------------------------- persistence of a CDF catalog */
TEST(wtcdf_close_persists_catalog_v1)
{
    CRYPTCATCDF *c; CRYPTCATMEMBER *m = NULL; char files[1024]; WCHAR cat[MAX_PATH]; HANDLE h; CRYPTCATATTRIBUTE *a = NULL;
    NO_WINE(); NEED(); REQUIRE(UN(CryptCATCDFEnumMembers)); REQUIRE(UN(CryptCATCDFEnumAttributes)); fixtures();
    files_v1(files, sizeof files, "");
    write_cdf("pv1.cdf", "pv1.cat", 1, "SHA1", "CATATTR1=0x10010001:CatTag:cat value\r\n", files);
    out_path(cat, "pv1.cat"); DeleteFileW(cat);
    c = open_cdf("pv1.cdf", NULL); REQUIRE(c);
    a = U(CryptCATCDFEnumCatAttributes)(c, NULL, NULL); CHECK(a != NULL);
    while ((m = UN(CryptCATCDFEnumMembers)(c, m, NULL)) != NULL) {
        CRYPTCATATTRIBUTE *ma = NULL;
        while ((ma = UN(CryptCATCDFEnumAttributes)(c, m, ma, NULL)) != NULL) ;
    }
    CHECK(U(CryptCATCDFClose)(c));
    CHECK(fsize(cat) > 0);
    CHECK(UN(IsCatalogFile)(NULL, cat));
    h = c_open(cat, CRYPTCAT_OPEN_EXISTING, 0, 0); REQUIRE(h != INVH);
    EXPECT_EQ(count_members(h), 2);
    m = U(CryptCATGetMemberInfo)(h, L"fa");
    CHECK(m != NULL);
    if (m) {
        CHECK(!memcmp(&m->gSubjectType, &GUID_FLAT, sizeof(GUID)));
        CHECK(dig_is(m, OID_SHA1, flat_a_sha1, 20));
        CHECK(U(CryptCATGetAttrInfo)(h, m, L"File") != NULL);
        CHECK(U(CryptCATGetAttrInfo)(h, m, L"Other") != NULL);
    }
    m = U(CryptCATGetMemberInfo)(h, L"fc");
    CHECK(m != NULL);
    if (m) CHECK(dig_is(m, OID_SHA1, flat_c_sha1, 20));
    CHECK(U(CryptCATGetCatAttrInfo)(h, L"CatTag") != NULL);
    EXPECT_EQ(c_store(h)->dwEncodingType, 0x10001);
    t_note("reloaded dwPublicVersion of a version-1 CDF catalog: %#lx", c_store(h)->dwPublicVersion);
    c_close(h);
}

TEST(wtcdf_close_persists_catalog_v2)
{
    CRYPTCATCDF *c; CRYPTCATMEMBER *m = NULL; LPWSTR t = NULL; char files[512]; WCHAR cat[MAX_PATH], h256[65], h1[41]; HANDLE h;
    NO_WINE(); NEED(); REQUIRE(U(CryptCATCDFEnumMembersByCDFTagEx)); fixtures();
    snprintf(files, sizeof files, "<HASH>fa=%sfa.dat\r\n<HASH>fc=%sfc.dat\r\n", g_dir, g_dir);
    write_cdf("pv2.cdf", "pv2.cat", 2, "SHA256", "", files);
    out_path(cat, "pv2.cat"); DeleteFileW(cat);
    hex_upper(h256, flat_a_sha256, 32); hex_upper(h1, flat_a_sha1, 20);
    c = open_cdf("pv2.cdf", NULL); REQUIRE(c);
    while (1) {
        m = NULL;
        t = U(CryptCATCDFEnumMembersByCDFTagEx)(c, t, NULL, &m, FALSE, NULL);
        if (!t) break;
    }
    CHECK(U(CryptCATCDFClose)(c));
    h = c_open(cat, CRYPTCAT_OPEN_EXISTING, 0, 0); REQUIRE(h != INVH);
    EXPECT_EQ(count_members(h), 4);   /* a SHA-256 and a SHA-1 entry for each of the two files */
    m = U(CryptCATGetMemberInfo)(h, h256); CHECK(m != NULL);
    if (m) CHECK(dig_is(m, OID_SHA256, flat_a_sha256, 32));
    m = U(CryptCATGetMemberInfo)(h, h1); CHECK(m != NULL);
    if (m) CHECK(dig_is(m, OID_SHA1, flat_a_sha1, 20));
    EXPECT_EQ(c_store(h)->dwEncodingType, 0x10001);
    t_note("reloaded dwPublicVersion of a version-2 CDF catalog: %#lx", c_store(h)->dwPublicVersion);
    c_close(h);
}

TEST(wtcdf_sorted_open_of_cdf_catalog)
{
    CRYPTCATCDF *c; CRYPTCATMEMBER *m = NULL; LPWSTR t = NULL; char files[512]; WCHAR cat[MAX_PATH], h256[65]; HANDLE h;
    NO_WINE(); NEED(); REQUIRE(U(CryptCATCDFEnumMembersByCDFTagEx)); REQUIRE(UN(CryptCATAllocSortedMemberInfo)); REQUIRE(UN(CryptCATFreeSortedMemberInfo)); fixtures();
    snprintf(files, sizeof files, "<HASH>fa=%sfa.dat\r\n", g_dir);
    write_cdf("psort.cdf", "psort.cat", 2, "SHA256", "", files);
    out_path(cat, "psort.cat"); DeleteFileW(cat);
    hex_upper(h256, flat_a_sha256, 32);
    c = open_cdf("psort.cdf", NULL); REQUIRE(c);
    while ((t = U(CryptCATCDFEnumMembersByCDFTagEx)(c, t, NULL, &m, FALSE, NULL)) != NULL) ;
    CHECK(U(CryptCATCDFClose)(c));
    h = c_open(cat, CRYPTCAT_OPEN_EXISTING | CRYPTCAT_OPEN_SORTED, 0, 0); REQUIRE(h != INVH);
    m = UN(CryptCATAllocSortedMemberInfo)(h, h256);
    CHECK(m != NULL);
    if (m) { CHECK(dig_is(m, OID_SHA256, flat_a_sha256, 32)); UN(CryptCATFreeSortedMemberInfo)(h, m); }
    c_close(h);
}

TEST(wtcdf_reopen_cdf_twice_overwrites_catalog)
{
    CRYPTCATCDF *c; char files[512]; WCHAR cat[MAX_PATH]; CRYPTCATMEMBER *m = NULL; HANDLE h;
    NO_WINE(); NEED(); REQUIRE(UN(CryptCATCDFEnumMembers)); fixtures();
    snprintf(files, sizeof files, "fa=%sfa.dat\r\n", g_dir);
    write_cdf("pre.cdf", "pre.cat", 1, "SHA1", "", files);
    out_path(cat, "pre.cat"); DeleteFileW(cat);
    c = open_cdf("pre.cdf", NULL); REQUIRE(c);
    m = UN(CryptCATCDFEnumMembers)(c, NULL, NULL); CHECK(m != NULL);
    CHECK(U(CryptCATCDFClose)(c));
    CHECK(fsize(cat) > 0);
    c = open_cdf("pre.cdf", NULL); REQUIRE(c);
    EXPECT_EQ(fsize(cat), 0);   /* opening the CDF again recreates (truncates) the output catalog */
    U(CryptCATCDFClose)(c);
    h = c_open(cat, CRYPTCAT_OPEN_EXISTING, 0, 0);
    if (h != INVH) { t_note("members in the catalog after closing an unpopulated CDF: %d", count_members(h)); c_close(h); }
}
