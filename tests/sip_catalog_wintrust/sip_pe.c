/* PE subject type (C689AAB8-...): indirect data, digest, verify, embedded signature storage. */
#include "sip_common.h"
#include "kats.h"

#define WCRE UIN("wintrust.dll", CryptSIPCreateIndirectData)
#define WVER UIN("wintrust.dll", CryptSIPVerifyIndirectData)
#define WGET UIN("wintrust.dll", CryptSIPGetSignedDataMsg)
#define WPUT UIN("wintrust.dll", CryptSIPPutSignedDataMsg)
#define WREM UIN("wintrust.dll", CryptSIPRemoveSignedDataMsg)

#define ENC (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING)
#define OID_PE_IMAGE_DATA "1.3.6.1.4.1.311.2.1.15"
#define DEFAULT_FLAGS 0x10          /* SPC_EXC_PE_PAGE_HASHES_FLAG: keeps the encoded SPC data deterministic */

typedef struct { char path[MAX_PATH]; WCHAR w[MAX_PATH]; } PF;

static void mk(PF *f, const char *leaf, unsigned variant)
{
    sipt_mkpe(f->path, sizeof f->path, leaf, variant);
    sipt_wide(f->w, MAX_PATH, f->path);
}

static const struct { const char *oid; const char *name; unsigned len; const u8 *kat[4]; } k_algs[] = {
    { OID_SHA1,   "sha1",   20, { kat_pe0_sha1,   kat_pe1_sha1,   kat_pe2_sha1,   kat_pe3_sha1 } },
    { OID_SHA256, "sha256", 32, { kat_pe0_sha256, kat_pe1_sha256, kat_pe2_sha256, kat_pe3_sha256 } },
    { OID_SHA384, "sha384", 48, { kat_pe0_sha384, kat_pe1_sha384, kat_pe2_sha384, kat_pe3_sha384 } },
    { OID_SHA512, "sha512", 64, { kat_pe0_sha512, kat_pe1_sha512, kat_pe2_sha512, kat_pe3_sha512 } },
    { OID_MD5,    "md5",    16, { kat_pe0_md5,    kat_pe1_md5,    kat_pe2_md5,    kat_pe3_md5 } },
};
#define NALGS (sizeof k_algs / sizeof *k_algs)

/* size-query then fill. Returns malloc'ed buffer (SIP_INDIRECT_DATA followed by its payload) or NULL. */
static SIP_INDIRECT_DATA *create_id(SIP_SUBJECTINFO *si, DWORD *pneed)
{
    DWORD cb = 0; SIP_INDIRECT_DATA *id;
    if (!WCRE(si, &cb, NULL) || cb < sizeof *id) return NULL;
    if (pneed) *pneed = cb;
    id = calloc(1, cb + 16);
    if (!id) return NULL;
    if (!WCRE(si, &cb, id)) { free(id); return NULL; }
    return id;
}

static int file_ok(const char *path, const u8 *want, size_t n)
{
    u8 b[8192]; size_t got = sipt_get(path, b, sizeof b);
    return got == n && !memcmp(b, want, n);
}
static void read_certdir(const char *path, DWORD *off, DWORD *size)
{
    u8 b[8192]; *off = *size = 0xFFFFFFFF;
    if (sipt_get(path, b, sizeof b) >= SIPI_PE_CERTDIR_OFF + 8) {
        *off = *(DWORD *)(b + SIPI_PE_CERTDIR_OFF); *size = *(DWORD *)(b + SIPI_PE_CERTDIR_OFF + 4);
    }
}
static void tamper(const char *path, size_t off, u8 x)
{
    HANDLE h = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    u8 b; DWORD n;
    if (h == INVALID_HANDLE_VALUE) return;
    SetFilePointer(h, (LONG)off, NULL, FILE_BEGIN); ReadFile(h, &b, 1, &n, NULL);
    b ^= x; SetFilePointer(h, (LONG)off, NULL, FILE_BEGIN); WriteFile(h, &b, 1, &n, NULL);
    CloseHandle(h);
}

/* ===================== CreateIndirectData ===================== */
TEST(sip_pe_create_wintrust_parameter_validation) {
    REQUIRE(WCRE);
    PF f; SIP_SUBJECTINFO si; DWORD cb = 0; mk(&f, "v.exe", 0);
    sipt_subject(&si, &G_PE, NULL, f.w, OID_SHA1, DEFAULT_FLAGS);
    SET_ERR(0); CHECK(!WCRE(NULL, &cb, NULL)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!WCRE(&si, NULL, NULL)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    si.cbSize = 0x57;
    SET_ERR(0); CHECK(!WCRE(&si, &cb, NULL)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    si.cbSize = 0;
    SET_ERR(0); CHECK(!WCRE(&si, &cb, NULL)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    si.cbSize = 0x58;                                         /* smallest accepted size */
    CHECK(WCRE(&si, &cb, NULL) == TRUE);
}
TEST(sip_pe_create_unknown_subject_type) {
    REQUIRE(WCRE);
    PF f; SIP_SUBJECTINFO si; DWORD cb = 0x1234; mk(&f, "v.exe", 0);
    sipt_subject(&si, &G_UNKNOWN, NULL, f.w, OID_SHA1, DEFAULT_FLAGS);
    SET_ERR(0); CHECK(!WCRE(&si, &cb, NULL));
    EXPECT_ERR(E_TRUST_SUBJECT_FORM_UNKNOWN);
    CHECK(cb == 0);                                           /* size query result reset on failure */
}
TEST(sip_pe_create_size_query_matches_layout) {
    REQUIRE(WCRE);
    PF f; mk(&f, "v.exe", 0);
    for (unsigned a = 0; a < NALGS; a++) {
        SIP_SUBJECTINFO si; DWORD need = 0xFFFF;
        sipt_subject(&si, &G_PE, NULL, f.w, k_algs[a].oid, DEFAULT_FLAGS);
        SIP_INDIRECT_DATA *id = create_id(&si, &need);
        CHECKF(id != NULL, "%s", k_algs[a].name);
        if (!id) continue;
        /* sizeof(SIP_INDIRECT_DATA) + oid\0 + encoded SPC data + alg oid\0 + digest */
        DWORD want = (DWORD)sizeof(SIP_INDIRECT_DATA) + (DWORD)strlen(OID_PE_IMAGE_DATA) + 1 + id->Data.Value.cbData
                   + (DWORD)strlen(k_algs[a].oid) + 1 + k_algs[a].len;
        CHECKF(need == want, "%s: need %lu want %lu", k_algs[a].name, need, want);
        free(id);
    }
}
TEST(sip_pe_create_buffer_boundaries) {
    REQUIRE(WCRE);
    PF f; SIP_SUBJECTINFO si; DWORD need = 0; mk(&f, "v.exe", 0);
    sipt_subject(&si, &G_PE, NULL, f.w, OID_SHA256, DEFAULT_FLAGS);
    SIP_INDIRECT_DATA *id = create_id(&si, &need);
    CHECK(id != NULL);
    if (!id) return;
    free(id);
    u8 *buf = calloc(1, need + 64);
    DWORD cb = need - 1;
    CHECK(!WCRE(&si, &cb, (SIP_INDIRECT_DATA *)buf));             /* one byte short */
    cb = need;
    CHECK(WCRE(&si, &cb, (SIP_INDIRECT_DATA *)buf) == TRUE);      /* exact fit */
    cb = need + 64;
    CHECK(WCRE(&si, &cb, (SIP_INDIRECT_DATA *)buf) == TRUE);      /* larger is fine */
    cb = 0;
    CHECK(!WCRE(&si, &cb, (SIP_INDIRECT_DATA *)buf));
    free(buf);
}
TEST(sip_pe_create_digest_known_answers) {
    REQUIRE(WCRE);
    for (unsigned v = 0; v < SIPI_PE_NVARIANTS; v++) {
        PF f; mk(&f, "kat.exe", v);
        for (unsigned a = 0; a < NALGS; a++) {
            SIP_SUBJECTINFO si;
            sipt_subject(&si, &G_PE, NULL, f.w, k_algs[a].oid, DEFAULT_FLAGS);
            SIP_INDIRECT_DATA *id = create_id(&si, NULL);
            CHECKF(id != NULL, "variant %u %s", v, k_algs[a].name);
            if (!id) continue;
            CHECKF(id->Digest.cbData == k_algs[a].len, "variant %u %s len %lu", v, k_algs[a].name, id->Digest.cbData);
            CHECKF(id->Digest.cbData == k_algs[a].len && !memcmp(id->Digest.pbData, k_algs[a].kat[v], k_algs[a].len), "variant %u %s digest", v, k_algs[a].name);
            free(id);
        }
    }
}
TEST(sip_pe_create_indirect_data_structure) {
    REQUIRE(WCRE);
    PF f; SIP_SUBJECTINFO si; mk(&f, "v.exe", 0);
    sipt_subject(&si, &G_PE, NULL, f.w, OID_SHA256, DEFAULT_FLAGS);
    DWORD need = 0; SIP_INDIRECT_DATA *id = create_id(&si, &need);
    CHECK(id != NULL);
    if (!id) return;
    u8 *lo = (u8 *)id, *hi = lo + need;
    EXPECT_STR(id->Data.pszObjId, OID_PE_IMAGE_DATA);
    EXPECT_STR(id->DigestAlgorithm.pszObjId, OID_SHA256);
    CHECK(id->DigestAlgorithm.Parameters.cbData == 0 && id->DigestAlgorithm.Parameters.pbData == NULL);
    CHECK(id->Data.Value.cbData > 0);
    CHECK(id->Digest.cbData == 32);
    /* every pointer lives inside the caller's buffer, after the fixed part */
    CHECK((u8 *)id->Data.pszObjId >= lo + sizeof *id && (u8 *)id->Data.pszObjId < hi);
    CHECK(id->Data.Value.pbData >= lo + sizeof *id && id->Data.Value.pbData + id->Data.Value.cbData <= hi);
    CHECK((u8 *)id->DigestAlgorithm.pszObjId >= lo + sizeof *id && (u8 *)id->DigestAlgorithm.pszObjId < hi);
    CHECK(id->Digest.pbData >= lo + sizeof *id && id->Digest.pbData + id->Digest.cbData <= hi);
    CHECK(id->Data.Value.pbData[0] == 0x30);                    /* SEQUENCE */
    CHECK(si.dwIntVersion == 0x200);                            /* the entry point stamps the SIP interface version */
    free(id);
}
TEST(sip_pe_create_value_decodes_as_pe_image_data) {
    REQUIRE(WCRE); REQUIRE(U(CryptDecodeObjectEx));
    typedef struct { DWORD dwLinkChoice; LPWSTR pwszFile; } LINK;
    typedef struct { CRYPT_BIT_BLOB Flags; LINK *pFile; } IMG;
    PF f; SIP_SUBJECTINFO si; mk(&f, "v.exe", 0);
    sipt_subject(&si, &G_PE, NULL, f.w, OID_SHA1, DEFAULT_FLAGS);
    SIP_INDIRECT_DATA *id = create_id(&si, NULL);
    CHECK(id != NULL);
    if (!id) return;
    IMG *img = NULL; DWORD cb = 0;
    BOOL ok = U(CryptDecodeObjectEx)(ENC, OID_PE_IMAGE_DATA, id->Data.Value.pbData, id->Data.Value.cbData, CRYPT_DECODE_ALLOC_FLAG, NULL, &img, &cb);
    if (!ok) { t_note("SPC_PE_IMAGE_DATA decoder not available via crypt32 (err 0x%lx)", GetLastError()); free(id); return; }
    CHECK(img->pFile != NULL);
    if (img->pFile) {
        CHECK(img->pFile->dwLinkChoice == 3);                   /* SPC_FILE_LINK_CHOICE */
        CHECK(img->pFile->pwszFile && img->pFile->pwszFile[0] == 0);   /* empty file name */
    }
    LocalFree(img);
    free(id);
}
TEST(sip_pe_create_page_hash_flag_changes_only_the_spc_data) {
    REQUIRE(WCRE);
    PF f; mk(&f, "v.exe", 0);
    SIP_SUBJECTINFO s1, s2;
    sipt_subject(&s1, &G_PE, NULL, f.w, OID_SHA1, 0x10);
    sipt_subject(&s2, &G_PE, NULL, f.w, OID_SHA1, 0x100);
    SIP_INDIRECT_DATA *a = create_id(&s1, NULL), *b = create_id(&s2, NULL);
    CHECK(a != NULL);
    if (!b) { t_note("page hash creation failed for the hand built image (err 0x%lx)", GetLastError()); free(a); return; }
    if (a) {
        CHECK(b->Data.Value.cbData > a->Data.Value.cbData);       /* page hash attribute is embedded in the SPC link */
        CHECK(a->Digest.cbData == b->Digest.cbData && !memcmp(a->Digest.pbData, b->Digest.pbData, a->Digest.cbData));
        static const u8 v1[] = { 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x03, 0x01 };   /* 1.3.6.1.4.1.311.2.3.1 */
        int found = 0;
        for (DWORD i = 0; i + sizeof v1 <= b->Data.Value.cbData; i++) if (!memcmp(b->Data.Value.pbData + i, v1, sizeof v1)) found = 1;
        CHECK(found);
    }
    free(a); free(b);
}
TEST(sip_pe_create_digest_independent_of_spc_flags) {
    REQUIRE(WCRE);
    static const DWORD flags[] = { 0, 0x10, 0x20, 0x40, 0x80, 0x100, 0x10000 };
    PF f; mk(&f, "v.exe", 0);
    for (unsigned i = 0; i < sizeof flags / sizeof *flags; i++) {
        SIP_SUBJECTINFO si; sipt_subject(&si, &G_PE, NULL, f.w, OID_SHA256, flags[i]);
        SIP_INDIRECT_DATA *id = create_id(&si, NULL);
        CHECKF(id != NULL, "flags 0x%lx", flags[i]);
        if (!id) continue;
        CHECKF(id->Digest.cbData == 32 && !memcmp(id->Digest.pbData, kat_pe0_sha256, 32), "flags 0x%lx", flags[i]);
        free(id);
    }
}
TEST(sip_pe_create_excludes_checksum_and_certificate_table) {
    REQUIRE(WCRE);
    PF f; mk(&f, "v.exe", 0);
    u8 b[4096]; size_t n = sipt_get(f.path, b, sizeof b);
    CHECK(n == 0x400);
    /* point the certificate directory at 0x20 appended bytes: the digest must not change */
    sipi_w32(b + SIPI_PE_CERTDIR_OFF, 0x400); sipi_w32(b + SIPI_PE_CERTDIR_OFF + 4, 0x20);
    sipi_w32(b + SIPI_PE_CHKSUM_OFF, 0xCAFEBABE);
    memset(b + 0x400, 0x5A, 0x20);
    CHECK(sipt_put(f.path, b, 0x420));
    SIP_SUBJECTINFO si; sipt_subject(&si, &G_PE, NULL, f.w, OID_SHA256, DEFAULT_FLAGS);
    SIP_INDIRECT_DATA *id = create_id(&si, NULL);
    CHECK(id != NULL);
    if (id) { CHECK(id->Digest.cbData == 32 && !memcmp(id->Digest.pbData, kat_pe0_sha256, 32)); free(id); }
    /* changing the signature bytes themselves does not matter either */
    memset(b + 0x400, 0xA5, 0x20); sipt_put(f.path, b, 0x420);
    id = create_id(&si, NULL);
    if (id) { CHECK(!memcmp(id->Digest.pbData, kat_pe0_sha256, 32)); free(id); } else CHECK(0);
}
TEST(sip_pe_create_every_other_byte_is_covered) {
    REQUIRE(WCRE);
    /* flipping any single byte outside checksum/cert-dir fields changes the digest */
    static const size_t offs[] = { 0, 2, 0x3c, 0x40, 0x7f, SIPI_PE_LFANEW, SIPI_PE_LFANEW + 8, SIPI_PE_OH, SIPI_PE_OH + 60,
        SIPI_PE_CHKSUM_OFF - 1, SIPI_PE_CHKSUM_OFF + 4, SIPI_PE_CERTDIR_OFF - 1, SIPI_PE_CERTDIR_OFF + 8,
        SIPI_PE_SECT_OFF, 0x1ff, 0x200, 0x201, 0x3ff };
    for (unsigned i = 0; i < sizeof offs / sizeof *offs; i++) {
        PF f; mk(&f, "flip.exe", 0);
        tamper(f.path, offs[i], 0x01);
        SIP_SUBJECTINFO si; sipt_subject(&si, &G_PE, NULL, f.w, OID_SHA256, DEFAULT_FLAGS);
        SIP_INDIRECT_DATA *id = create_id(&si, NULL);
        if (!id) { t_note("offset 0x%x: image rejected (0x%lx)", (unsigned)offs[i], GetLastError()); continue; }
        CHECKF(memcmp(id->Digest.pbData, kat_pe0_sha256, 32) != 0, "offset 0x%x", (unsigned)offs[i]);
        free(id);
    }
    for (size_t o = SIPI_PE_CHKSUM_OFF; o < SIPI_PE_CHKSUM_OFF + 4; o++) {
        PF f; mk(&f, "flipck.exe", 0); tamper(f.path, o, 0xFF);
        SIP_SUBJECTINFO si; sipt_subject(&si, &G_PE, NULL, f.w, OID_SHA256, DEFAULT_FLAGS);
        SIP_INDIRECT_DATA *id = create_id(&si, NULL);
        CHECKF(id && !memcmp(id->Digest.pbData, kat_pe0_sha256, 32), "checksum byte %u excluded", (unsigned)(o - SIPI_PE_CHKSUM_OFF));
        free(id);
    }
}
TEST(sip_pe_create_by_handle_matches_by_name) {
    REQUIRE(WCRE);
    PF f; SIP_SUBJECTINFO si; mk(&f, "h.exe", 2);
    HANDLE h = sipt_open(f.path, GENERIC_READ);
    sipt_subject(&si, &G_PE, h, NULL, OID_SHA384, DEFAULT_FLAGS);
    SIP_INDIRECT_DATA *id = create_id(&si, NULL);
    CHECK(id != NULL);
    if (id) { CHECK(id->Digest.cbData == 48 && !memcmp(id->Digest.pbData, kat_pe2_sha384, 48)); free(id); }
    CHECK(GetFileSize(h, NULL) == 0x600);                      /* the caller's handle is not closed */
    CloseHandle(h);
}
TEST(sip_pe_create_handle_takes_precedence_over_name) {
    REQUIRE(WCRE);
    PF f; SIP_SUBJECTINFO si; mk(&f, "h.exe", 0);
    HANDLE h = sipt_open(f.path, GENERIC_READ);
    WCHAR bogus[] = L"C:\\no\\such\\file.exe";
    sipt_subject(&si, &G_PE, h, bogus, OID_SHA1, DEFAULT_FLAGS);
    SIP_INDIRECT_DATA *id = create_id(&si, NULL);
    CHECK(id && !memcmp(id->Digest.pbData, kat_pe0_sha1, 20));
    free(id);
    CloseHandle(h);
}
TEST(sip_pe_create_extension_not_checked) {
    REQUIRE(WCRE);
    PF f; SIP_SUBJECTINFO si; mk(&f, "x.js", 0);
    sipt_subject(&si, &G_PE, NULL, f.w, OID_SHA1, DEFAULT_FLAGS);
    SIP_INDIRECT_DATA *id = create_id(&si, NULL);
    CHECK(id != NULL);                                         /* blocked extensions only matter for verification */
    free(id);
}
TEST(sip_pe_create_leaves_file_unmodified) {
    REQUIRE(WCRE);
    PF f; SIP_SUBJECTINFO si; u8 img[4096]; size_t n = sipi_pe(1, img, sizeof img); mk(&f, "ro.exe", 1);
    sipt_subject(&si, &G_PE, NULL, f.w, OID_SHA256, 0x100);
    SIP_INDIRECT_DATA *id = create_id(&si, NULL);
    free(id);
    CHECK(file_ok(f.path, img, n));
}
TEST(sip_pe_create_works_on_read_only_file) {
    REQUIRE(WCRE);
    PF f; SIP_SUBJECTINFO si; mk(&f, "ro.exe", 0);
    SetFileAttributesA(f.path, FILE_ATTRIBUTE_READONLY);
    sipt_subject(&si, &G_PE, NULL, f.w, OID_SHA1, DEFAULT_FLAGS);
    SIP_INDIRECT_DATA *id = create_id(&si, NULL);
    CHECK(id != NULL);
    free(id);
    SetFileAttributesA(f.path, FILE_ATTRIBUTE_NORMAL);
}
TEST(sip_pe_create_unknown_digest_algorithm) {
    REQUIRE(WCRE);
    PF f; SIP_SUBJECTINFO si; DWORD cb = 0; mk(&f, "v.exe", 0);
    static const char *bad[] = { "1.2.3.4.5.6", "2.16.840.1.101.3.4.2.99", "not.an.oid" };
    for (unsigned i = 0; i < 3; i++) {
        sipt_subject(&si, &G_PE, NULL, f.w, bad[i], DEFAULT_FLAGS);
        CHECKF(!WCRE(&si, &cb, NULL), "size query %s", bad[i]);
        u8 buf[1024]; cb = sizeof buf;
        SET_ERR(0);
        CHECKF(!WCRE(&si, &cb, (SIP_INDIRECT_DATA *)buf), "%s", bad[i]);
        EXPECT_ERR(E_NTE_BAD_ALGID);
    }
}
TEST(sip_pe_create_missing_file) {
    REQUIRE(WCRE);
    PF f; SIP_SUBJECTINFO si; u8 buf[1024]; DWORD cb = sizeof buf;
    t_tmpfile(f.path, sizeof f.path, "missing.exe"); sipt_wide(f.w, MAX_PATH, f.path);
    sipt_subject(&si, &G_PE, NULL, f.w, OID_SHA1, DEFAULT_FLAGS);
    SET_ERR(0);
    CHECK(!WCRE(&si, &cb, (SIP_INDIRECT_DATA *)buf));
    EXPECT_ERR(ERROR_FILE_NOT_FOUND);
}
TEST(sip_pe_create_non_pe_content) {
    REQUIRE(WCRE);
    PF f; SIP_SUBJECTINFO si; u8 buf[1024]; DWORD cb = sizeof buf;
    t_tmpfile(f.path, sizeof f.path, "text.exe"); sipt_put(f.path, "this is definitely not a PE file........", 40); sipt_wide(f.w, MAX_PATH, f.path);
    sipt_subject(&si, &G_PE, NULL, f.w, OID_SHA1, DEFAULT_FLAGS);
    SET_ERR(0);
    CHECK(!WCRE(&si, &cb, (SIP_INDIRECT_DATA *)buf));
    t_note("PE SIP on text file: error 0x%lx", GetLastError());
    sipt_put(f.path, "", 0);
    cb = sizeof buf;
    CHECK(!WCRE(&si, &cb, (SIP_INDIRECT_DATA *)buf));
}
TEST(sip_pe_create_dispatch_via_crypt32_matches_wintrust) {
    REQUIRE(U(CryptSIPLoad));
    SIP_DISPATCH_INFO d; memset(&d, 0, sizeof d);
    CHECK(U(CryptSIPLoad)(&G_PE, 0, &d));
    if (!d.pfCreate) return;
    PF f; SIP_SUBJECTINFO si; DWORD c1 = 0, c2 = 0; mk(&f, "d.exe", 0);
    sipt_subject(&si, &G_PE, NULL, f.w, OID_SHA256, DEFAULT_FLAGS);
    CHECK(d.pfCreate(&si, &c1, NULL) == TRUE);
    CHECK(WCRE(&si, &c2, NULL) == TRUE);
    CHECK(c1 == c2 && c1 > 0);
    u8 *buf = calloc(1, c1 + 8); DWORD cb = c1;
    CHECK(d.pfCreate(&si, &cb, (SIP_INDIRECT_DATA *)buf) == TRUE);
    SIP_INDIRECT_DATA *id = (SIP_INDIRECT_DATA *)buf;
    CHECK(id->Digest.cbData == 32 && !memcmp(id->Digest.pbData, kat_pe0_sha256, 32));
    free(buf);
}
TEST(sip_pe_crypt32_entry_points_validate_subject_type) {
    REQUIRE(U(CryptSIPCreateIndirectData));
    SIP_SUBJECTINFO si; DWORD cb = 0;
    SET_ERR(0); CHECK(!UIN("crypt32.dll", CryptSIPCreateIndirectData)(NULL, &cb, NULL)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    sipt_subject(&si, NULL, NULL, NULL, OID_SHA1, 0);
    SET_ERR(0); CHECK(!UIN("crypt32.dll", CryptSIPCreateIndirectData)(&si, &cb, NULL)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!UIN("crypt32.dll", CryptSIPVerifyIndirectData)(&si, NULL)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!UIN("crypt32.dll", CryptSIPRemoveSignedDataMsg)(&si, 0)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!UIN("crypt32.dll", CryptSIPGetSignedDataMsg)(&si, &cb, 0, &cb, NULL)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!UIN("crypt32.dll", CryptSIPPutSignedDataMsg)(&si, ENC, &cb, 1, (BYTE *)&cb)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    sipt_subject(&si, &G_UNKNOWN, NULL, NULL, OID_SHA1, 0);
    SET_ERR(0); CHECK(!UIN("crypt32.dll", CryptSIPCreateIndirectData)(&si, &cb, NULL)); EXPECT_ERR(E_TRUST_SUBJECT_FORM_UNKNOWN);
    SET_ERR(0); CHECK(!UIN("crypt32.dll", CryptSIPVerifyIndirectData)(&si, NULL)); EXPECT_ERR(E_TRUST_SUBJECT_FORM_UNKNOWN);
    SET_ERR(0); CHECK(!UIN("crypt32.dll", CryptSIPRemoveSignedDataMsg)(&si, 0)); EXPECT_ERR(E_TRUST_SUBJECT_FORM_UNKNOWN);
    SET_ERR(0); CHECK(!UIN("crypt32.dll", CryptSIPGetSignedDataMsg)(&si, &cb, 0, &cb, NULL)); EXPECT_ERR(E_TRUST_SUBJECT_FORM_UNKNOWN);
    SET_ERR(0); CHECK(!UIN("crypt32.dll", CryptSIPPutSignedDataMsg)(&si, ENC, &cb, 1, (BYTE *)&cb)); EXPECT_ERR(E_TRUST_SUBJECT_FORM_UNKNOWN);
}
TEST(sip_pe_wintrust_entry_points_unknown_subject_type) {
    REQUIRE(WCRE);
    SIP_SUBJECTINFO si; DWORD cb = 8, idx = 0, enc = 0; BYTE blob[8] = {1};
    sipt_subject(&si, &G_UNKNOWN, NULL, NULL, OID_SHA1, 0);
    SET_ERR(0); CHECK(!WVER(&si, NULL)); EXPECT_ERR(E_TRUST_SUBJECT_FORM_UNKNOWN);
    SET_ERR(0); CHECK(!WREM(&si, 0)); EXPECT_ERR(E_TRUST_SUBJECT_FORM_UNKNOWN);
    SET_ERR(0); CHECK(!WPUT(&si, ENC, &idx, 8, blob)); EXPECT_ERR(E_TRUST_SUBJECT_FORM_UNKNOWN);
    SET_ERR(0); cb = 8; CHECK(!WGET(&si, &enc, 0, &cb, NULL)); EXPECT_ERR(E_TRUST_SUBJECT_FORM_UNKNOWN);
    CHECK(cb == 0);                                            /* size-query out parameter zeroed */
}

/* ===================== VerifyIndirectData ===================== */
TEST(sip_pe_verify_roundtrip_all_algorithms) {
    REQUIRE(WCRE); REQUIRE(WVER);
    for (unsigned a = 0; a < NALGS; a++) {
        PF f; SIP_SUBJECTINFO si; mk(&f, "rt.exe", 0);
        sipt_subject(&si, &G_PE, NULL, f.w, k_algs[a].oid, DEFAULT_FLAGS);
        SIP_INDIRECT_DATA *id = create_id(&si, NULL);
        CHECKF(id != NULL, "%s", k_algs[a].name);
        if (!id) continue;
        sipt_subject(&si, &G_PE, NULL, f.w, k_algs[a].oid, 0);
        SET_ERR(0xDEAD);
        CHECKF(WVER(&si, id) == TRUE, "%s", k_algs[a].name);
        free(id);
    }
}
TEST(sip_pe_verify_null_indirect_data) {
    REQUIRE(WVER);
    PF f; SIP_SUBJECTINFO si; mk(&f, "n.exe", 0);
    sipt_subject(&si, &G_PE, NULL, f.w, OID_SHA1, 0);
    SET_ERR(0); CHECK(!WVER(&si, NULL)); EXPECT_ERR(E_E_INVALIDARG);
}
TEST(sip_pe_verify_parameter_validation) {
    REQUIRE(WVER);
    SIP_SUBJECTINFO si;
    SET_ERR(0); CHECK(!WVER(NULL, NULL)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    sipt_subject(&si, &G_PE, NULL, NULL, OID_SHA1, 0); si.cbSize = 0x57;
    SET_ERR(0); CHECK(!WVER(&si, NULL)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
}
TEST(sip_pe_verify_detects_modification) {
    REQUIRE(WCRE); REQUIRE(WVER);
    static const size_t offs[] = { 0, 0x10, 0x50, SIPI_PE_LFANEW + 8, SIPI_PE_OH + 16, SIPI_PE_SECT_OFF, 0x200, 0x3ff };
    for (unsigned i = 0; i < sizeof offs / sizeof *offs; i++) {
        PF f; SIP_SUBJECTINFO si; mk(&f, "mod.exe", 0);
        sipt_subject(&si, &G_PE, NULL, f.w, OID_SHA256, DEFAULT_FLAGS);
        SIP_INDIRECT_DATA *id = create_id(&si, NULL);
        if (!id) { CHECK(0); continue; }
        tamper(f.path, offs[i], 0x80);
        SET_ERR(0);
        CHECKF(!WVER(&si, id), "offset 0x%x", (unsigned)offs[i]);
        EXPECT_ERR(E_TRUST_BAD_DIGEST);
        free(id);
    }
}
TEST(sip_pe_verify_ignores_checksum_changes) {
    REQUIRE(WCRE); REQUIRE(WVER);
    PF f; SIP_SUBJECTINFO si; mk(&f, "ck.exe", 0);
    sipt_subject(&si, &G_PE, NULL, f.w, OID_SHA1, DEFAULT_FLAGS);
    SIP_INDIRECT_DATA *id = create_id(&si, NULL);
    CHECK(id != NULL);
    if (!id) return;
    tamper(f.path, SIPI_PE_CHKSUM_OFF, 0x55);
    CHECK(WVER(&si, id) == TRUE);
    free(id);
}
TEST(sip_pe_verify_wrong_digest_bytes_or_length) {
    REQUIRE(WCRE); REQUIRE(WVER);
    PF f; SIP_SUBJECTINFO si; mk(&f, "w.exe", 0);
    sipt_subject(&si, &G_PE, NULL, f.w, OID_SHA256, DEFAULT_FLAGS);
    SIP_INDIRECT_DATA *id = create_id(&si, NULL);
    CHECK(id != NULL);
    if (!id) return;
    id->Digest.pbData[31] ^= 1;
    SET_ERR(0); CHECK(!WVER(&si, id)); EXPECT_ERR(E_TRUST_BAD_DIGEST);
    id->Digest.pbData[31] ^= 1;
    CHECK(WVER(&si, id) == TRUE);
    id->Digest.cbData = 31;
    SET_ERR(0); CHECK(!WVER(&si, id)); EXPECT_ERR(E_TRUST_BAD_DIGEST);
    id->Digest.cbData = 0;
    SET_ERR(0); CHECK(!WVER(&si, id)); EXPECT_ERR(E_TRUST_BAD_DIGEST);
    free(id);
}
TEST(sip_pe_verify_uses_algorithm_from_indirect_data) {
    REQUIRE(WCRE); REQUIRE(WVER);
    PF f; SIP_SUBJECTINFO si; mk(&f, "alg.exe", 0);
    sipt_subject(&si, &G_PE, NULL, f.w, OID_SHA256, DEFAULT_FLAGS);
    SIP_INDIRECT_DATA *id = create_id(&si, NULL);
    CHECK(id != NULL);
    if (!id) return;
    sipt_subject(&si, &G_PE, NULL, f.w, OID_SHA1, 0);              /* subject algorithm is irrelevant for verification */
    CHECK(WVER(&si, id) == TRUE);
    free(id);
}
TEST(sip_pe_verify_unknown_indirect_algorithm) {
    REQUIRE(WCRE); REQUIRE(WVER);
    PF f; SIP_SUBJECTINFO si; mk(&f, "ua.exe", 0);
    sipt_subject(&si, &G_PE, NULL, f.w, OID_SHA1, DEFAULT_FLAGS);
    SIP_INDIRECT_DATA *id = create_id(&si, NULL);
    CHECK(id != NULL);
    if (!id) return;
    char *saved = id->DigestAlgorithm.pszObjId;
    id->DigestAlgorithm.pszObjId = "1.2.3.4.5.6";
    SET_ERR(0); CHECK(!WVER(&si, id)); EXPECT_ERR(E_NTE_BAD_ALGID);
    id->DigestAlgorithm.pszObjId = saved;
    free(id);
}
TEST(sip_pe_verify_blocked_script_extensions) {
    REQUIRE(WCRE); REQUIRE(WVER);
    static const char *blocked[] = { ".hta", ".jar", ".js", ".jse", ".vbe", ".vbs", ".wsf", ".wsh", ".JS", ".Vbs" };
    static const char *allowed[] = { ".exe", ".dll", ".sys", ".jsx", ".j", ".txt", ".jsonl", "" };
    PF f; SIP_SUBJECTINFO si; mk(&f, "ext.exe", 0);
    sipt_subject(&si, &G_PE, NULL, f.w, OID_SHA1, DEFAULT_FLAGS);
    SIP_INDIRECT_DATA *id = create_id(&si, NULL);
    CHECK(id != NULL);
    if (!id) return;
    HANDLE h = sipt_open(f.path, GENERIC_READ);
    for (unsigned i = 0; i < sizeof blocked / sizeof *blocked; i++) {
        WCHAR name[64]; char tmp[64]; snprintf(tmp, sizeof tmp, "C:\\x\\file%s", blocked[i]); sipt_wide(name, 64, tmp);
        sipt_subject(&si, &G_PE, h, name, OID_SHA1, 0);
        SET_ERR(0);
        CHECKF(!WVER(&si, id), "%s", blocked[i]);
        EXPECT_ERR(ERROR_FILE_INVALID);
    }
    for (unsigned i = 0; i < sizeof allowed / sizeof *allowed; i++) {
        WCHAR name[64]; char tmp[64]; snprintf(tmp, sizeof tmp, "C:\\x\\file%s", allowed[i]); sipt_wide(name, 64, tmp);
        sipt_subject(&si, &G_PE, h, name, OID_SHA1, 0);
        CHECKF(WVER(&si, id) == TRUE, "'%s'", allowed[i]);
    }
    CloseHandle(h);
    free(id);
}
TEST(sip_pe_verify_garbage_spc_data) {
    REQUIRE(WCRE); REQUIRE(WVER);
    PF f; SIP_SUBJECTINFO si; mk(&f, "g.exe", 0);
    sipt_subject(&si, &G_PE, NULL, f.w, OID_SHA1, DEFAULT_FLAGS);
    SIP_INDIRECT_DATA *id = create_id(&si, NULL);
    CHECK(id != NULL);
    if (!id) return;
    DWORD saved = id->Data.Value.cbData;
    id->Data.Value.cbData = 0;                                    /* undecodable SPC_PE_IMAGE_DATA */
    SET_ERR(0); CHECK(!WVER(&si, id));
    id->Data.Value.cbData = saved;
    id->Data.Value.pbData[0] = 0x31;                              /* SET instead of SEQUENCE */
    CHECK(!WVER(&si, id));
    id->Data.Value.pbData[0] = 0x30;
    CHECK(WVER(&si, id) == TRUE);
    free(id);
}
TEST(sip_pe_verify_dispatch_via_crypt32) {
    REQUIRE(U(CryptSIPLoad)); REQUIRE(WCRE);
    SIP_DISPATCH_INFO d; memset(&d, 0, sizeof d);
    CHECK(U(CryptSIPLoad)(&G_PE, 0, &d));
    if (!d.pfVerify) return;
    PF f; SIP_SUBJECTINFO si; mk(&f, "dv.exe", 3);
    sipt_subject(&si, &G_PE, NULL, f.w, OID_SHA256, DEFAULT_FLAGS);
    SIP_INDIRECT_DATA *id = create_id(&si, NULL);
    CHECK(id != NULL);
    if (!id) return;
    CHECK(d.pfVerify(&si, id) == TRUE);
    tamper(f.path, 0x300, 1);
    SET_ERR(0); CHECK(!d.pfVerify(&si, id)); EXPECT_ERR(E_TRUST_BAD_DIGEST);
    free(id);
}

/* ===================== embedded signatures ===================== */
static void pattern(u8 *p, size_t n, u8 seed) { for (size_t i = 0; i < n; i++) p[i] = (u8)(seed + i * 13); }

TEST(sip_pe_put_wintrust_parameter_validation) {
    REQUIRE(WPUT);
    PF f; SIP_SUBJECTINFO si; DWORD idx = 0; u8 blob[16]; mk(&f, "p.exe", 0); pattern(blob, 16, 1);
    sipt_subject(&si, &G_PE, NULL, f.w, OID_SHA1, 0);
    SET_ERR(0); CHECK(!WPUT(NULL, ENC, &idx, 16, blob)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!WPUT(&si, ENC, NULL, 16, blob)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!WPUT(&si, ENC, &idx, 0, blob)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!WPUT(&si, ENC, &idx, 16, NULL)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    si.cbSize = 0x57;
    SET_ERR(0); CHECK(!WPUT(&si, ENC, &idx, 16, blob)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    CHECK(sipt_size(f.path) == 0x400);                             /* nothing was written */
}
TEST(sip_pe_get_remove_wintrust_parameter_validation) {
    REQUIRE(WGET); REQUIRE(WREM);
    PF f; SIP_SUBJECTINFO si; DWORD cb = 0, enc = 0; mk(&f, "p.exe", 0);
    sipt_subject(&si, &G_PE, NULL, f.w, OID_SHA1, 0);
    SET_ERR(0); CHECK(!WGET(NULL, &enc, 0, &cb, NULL)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!WGET(&si, NULL, 0, &cb, NULL)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!WGET(&si, &enc, 0, NULL, NULL)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    si.cbSize = 0x57;
    SET_ERR(0); CHECK(!WGET(&si, &enc, 0, &cb, NULL)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!WREM(&si, 0)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!WREM(NULL, 0)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
}
TEST(sip_pe_get_from_unsigned_image) {
    REQUIRE(WGET);
    PF f; SIP_SUBJECTINFO si; DWORD cb = 0, enc = 0; mk(&f, "u.exe", 0);
    sipt_subject(&si, &G_PE, NULL, f.w, OID_SHA1, 0);
    SET_ERR(0);
    CHECK(!WGET(&si, &enc, 0, &cb, NULL));
    t_note("Get on unsigned PE: error 0x%lx cb=%lu", GetLastError(), cb);
    u8 buf[64]; cb = sizeof buf;
    CHECK(!WGET(&si, &enc, 0, &cb, buf));
}
TEST(sip_pe_put_get_roundtrip_layout) {
    REQUIRE(WPUT); REQUIRE(WGET);
    PF f; SIP_SUBJECTINFO si; DWORD idx = 0xFFFF, cb = 0, enc = 0; u8 blob[24], got[64];
    mk(&f, "s.exe", 0); pattern(blob, sizeof blob, 7);
    sipt_subject(&si, &G_PE, NULL, f.w, OID_SHA1, 0);
    CHECK(WPUT(&si, ENC, &idx, sizeof blob, blob) == TRUE);
    CHECK(idx == 0);
    /* on-disk layout: one WIN_CERTIFICATE {dwLength=8+n, wRevision=0x200, wCertificateType=2} at the old end of file */
    u8 raw[1024]; size_t n = sipt_get(f.path, raw, sizeof raw);
    CHECK(n == 0x400 + 32);
    DWORD coff, csz; read_certdir(f.path, &coff, &csz);
    CHECK(coff == 0x400 && csz == 32);
    if (n == 0x420) {
        CHECK(*(DWORD *)(raw + 0x400) == 32 && *(WORD *)(raw + 0x404) == 0x200 && *(WORD *)(raw + 0x406) == 2);
        CHECK(!memcmp(raw + 0x408, blob, sizeof blob));
    }
    /* size query */
    sipt_subject(&si, &G_PE, NULL, f.w, OID_SHA1, 0);
    cb = 0; enc = 0xFFFF;
    SET_ERR(0);
    CHECK(WGET(&si, &enc, 0, &cb, NULL) == TRUE);
    CHECK(cb == 32);                                               /* includes the 8 byte WIN_CERTIFICATE header */
    /* fetch */
    cb = sizeof got; memset(got, 0xEE, sizeof got); enc = 0xFFFF; si.dwIntVersion = 0;
    CHECK(WGET(&si, &enc, 0, &cb, got) == TRUE);
    CHECK(cb == sizeof blob);
    CHECK(!memcmp(got, blob, sizeof blob));
    CHECK(enc == ENC);
    CHECK(si.dwIntVersion == 0x200);                               /* WIN_CERTIFICATE.wRevision */
}
TEST(sip_pe_get_buffer_too_small) {
    REQUIRE(WPUT); REQUIRE(WGET);
    PF f; SIP_SUBJECTINFO si; DWORD idx, cb, enc; u8 blob[24], got[64]; mk(&f, "s.exe", 0); pattern(blob, sizeof blob, 9);
    sipt_subject(&si, &G_PE, NULL, f.w, OID_SHA1, 0);
    CHECK(WPUT(&si, ENC, &idx, sizeof blob, blob));
    for (cb = 8; cb < 32; cb++) {
        DWORD c = cb;
        SET_ERR(0);
        CHECKF(!WGET(&si, &enc, 0, &c, got), "cb %lu", cb);
        EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER);
    }
    cb = 32; memset(got, 0, sizeof got);
    CHECK(WGET(&si, &enc, 0, &cb, got) == TRUE);                  /* exact: header + payload */
    CHECK(cb == 24 && !memcmp(got, blob, 24));
}
TEST(sip_pe_get_index_out_of_range) {
    REQUIRE(WPUT); REQUIRE(WGET);
    PF f; SIP_SUBJECTINFO si; DWORD idx, cb = 0, enc; u8 blob[16]; mk(&f, "s.exe", 0); pattern(blob, 16, 3);
    sipt_subject(&si, &G_PE, NULL, f.w, OID_SHA1, 0);
    CHECK(WPUT(&si, ENC, &idx, 16, blob));
    SET_ERR(0);
    CHECK(!WGET(&si, &enc, 1, &cb, NULL));
    t_note("Get index 1 of 1 signature: error 0x%lx", GetLastError());
    cb = 0; CHECK(!WGET(&si, &enc, 0xFFFF, &cb, NULL));
}
TEST(sip_pe_put_non_multiple_of_eight_length) {
    REQUIRE(WPUT); REQUIRE(WGET);
    static const DWORD lens[] = { 1, 7, 9, 21, 100, 4001 };
    for (unsigned i = 0; i < sizeof lens / sizeof *lens; i++) {
        PF f; SIP_SUBJECTINFO si; DWORD idx = 9, cb = 0, enc; u8 *blob = malloc(lens[i]), *got = malloc(lens[i] + 64);
        mk(&f, "len.exe", 0); pattern(blob, lens[i], (u8)i);
        sipt_subject(&si, &G_PE, NULL, f.w, OID_SHA1, 0);
        BOOL ok = WPUT(&si, ENC, &idx, lens[i], blob);
        CHECKF(ok, "len %lu", lens[i]);
        if (ok) {
            CHECKF(idx == 0, "len %lu", lens[i]);
            size_t sz = sipt_size(f.path);
            CHECKF(sz % 8 == 0, "len %lu: file size %u keeps the certificate table 8-byte aligned", lens[i], (unsigned)sz);
            cb = 0;
            CHECKF(WGET(&si, &enc, 0, &cb, NULL) == TRUE && cb == lens[i] + 8, "len %lu query cb %lu", lens[i], cb);
            cb = lens[i] + 64; memset(got, 0xEE, cb);
            CHECKF(WGET(&si, &enc, 0, &cb, got) == TRUE, "len %lu", lens[i]);
            CHECKF(cb == lens[i], "len %lu: returned %lu", lens[i], cb);
            CHECKF(!memcmp(got, blob, lens[i]), "len %lu", lens[i]);
        }
        free(blob); free(got);
    }
}
TEST(sip_pe_two_signatures) {
    REQUIRE(WPUT); REQUIRE(WGET);
    PF f; SIP_SUBJECTINFO si; DWORD i0 = 9, i1 = 9, cb, enc; u8 a[24], b[40], got[64];
    mk(&f, "m.exe", 0); pattern(a, sizeof a, 1); pattern(b, sizeof b, 99);
    sipt_subject(&si, &G_PE, NULL, f.w, OID_SHA256, 0);
    CHECK(WPUT(&si, ENC, &i0, sizeof a, a)); CHECK(i0 == 0);
    BOOL ok = WPUT(&si, ENC, &i1, sizeof b, b);
    if (!ok) { t_note("second signature rejected: 0x%lx", GetLastError()); return; }
    CHECK(i1 == 1);
    DWORD coff, csz; read_certdir(f.path, &coff, &csz);
    CHECK(coff == 0x400 && csz == 32 + 48);
    cb = sizeof got; CHECK(WGET(&si, &enc, 0, &cb, got) && cb == sizeof a && !memcmp(got, a, sizeof a));
    cb = sizeof got; CHECK(WGET(&si, &enc, 1, &cb, got) && cb == sizeof b && !memcmp(got, b, sizeof b));
    SET_ERR(0); cb = sizeof got; CHECK(!WGET(&si, &enc, 2, &cb, got));
}
TEST(sip_pe_remove_signature) {
    REQUIRE(WPUT); REQUIRE(WGET); REQUIRE(WREM);
    PF f; SIP_SUBJECTINFO si; DWORD idx, cb, enc; u8 a[24], b[24], got[64];
    mk(&f, "r.exe", 0); pattern(a, sizeof a, 1); pattern(b, sizeof b, 50);
    sipt_subject(&si, &G_PE, NULL, f.w, OID_SHA1, 0);
    CHECK(WPUT(&si, ENC, &idx, sizeof a, a));
    if (!WPUT(&si, ENC, &idx, sizeof b, b)) { t_note("second signature rejected"); return; }
    CHECK(WREM(&si, 0) == TRUE);
    cb = sizeof got; CHECK(WGET(&si, &enc, 0, &cb, got) && cb == sizeof b && !memcmp(got, b, sizeof b));   /* remaining entries shift down */
    CHECK(WREM(&si, 0) == TRUE);
    DWORD coff, csz; read_certdir(f.path, &coff, &csz);
    CHECK(csz == 0);
    cb = 0; SET_ERR(0); CHECK(!WGET(&si, &enc, 0, &cb, NULL));
    t_note("after removing all signatures: file size %u, cert dir offset 0x%lx", (unsigned)sipt_size(f.path), coff);
    SET_ERR(0); CHECK(!WREM(&si, 0));                               /* nothing left to remove */
}
TEST(sip_pe_remove_out_of_range_and_unsigned) {
    REQUIRE(WREM); REQUIRE(WPUT);
    PF f; SIP_SUBJECTINFO si; DWORD idx; u8 a[16]; mk(&f, "r.exe", 0); pattern(a, 16, 4);
    sipt_subject(&si, &G_PE, NULL, f.w, OID_SHA1, 0);
    SET_ERR(0); CHECK(!WREM(&si, 0));
    t_note("Remove on unsigned PE: error 0x%lx", GetLastError());
    CHECK(WPUT(&si, ENC, &idx, 16, a));
    CHECK(!WREM(&si, 1));
    CHECK(!WREM(&si, 0xFFFFFFFF));
    CHECK(WREM(&si, 0) == TRUE);
}
TEST(sip_pe_signing_does_not_change_digest) {
    REQUIRE(WCRE); REQUIRE(WVER); REQUIRE(WPUT);
    PF f; SIP_SUBJECTINFO si; DWORD idx; u8 a[48]; mk(&f, "sg.exe", 0); pattern(a, sizeof a, 77);
    sipt_subject(&si, &G_PE, NULL, f.w, OID_SHA256, DEFAULT_FLAGS);
    SIP_INDIRECT_DATA *before = create_id(&si, NULL);
    CHECK(before != NULL);
    if (!before) return;
    CHECK(WPUT(&si, ENC, &idx, sizeof a, a));
    SIP_INDIRECT_DATA *after = create_id(&si, NULL);
    CHECK(after && after->Digest.cbData == 32 && !memcmp(after->Digest.pbData, kat_pe0_sha256, 32));
    CHECK(WVER(&si, before) == TRUE);                               /* sign-then-verify round trip */
    free(before); free(after);
}
TEST(sip_pe_put_get_through_open_handle) {
    REQUIRE(WPUT); REQUIRE(WGET);
    PF f; SIP_SUBJECTINFO si; DWORD idx = 5, cb, enc; u8 a[32], got[64]; mk(&f, "hd.exe", 0); pattern(a, sizeof a, 21);
    HANDLE h = sipt_open(f.path, GENERIC_READ | GENERIC_WRITE);
    sipt_subject(&si, &G_PE, h, NULL, OID_SHA1, 0);
    CHECK(WPUT(&si, ENC, &idx, sizeof a, a) == TRUE);
    CHECK(idx == 0);
    CHECK(GetFileSize(h, NULL) == 0x400 + 40);                      /* caller's handle observed the write and is still open */
    cb = sizeof got; CHECK(WGET(&si, &enc, 0, &cb, got) && cb == sizeof a && !memcmp(got, a, sizeof a));
    CloseHandle(h);
    CHECK(sipt_size(f.path) == 0x400 + 40);
}
TEST(sip_pe_put_with_read_only_handle) {
    REQUIRE(WPUT);
    PF f; SIP_SUBJECTINFO si; DWORD idx; u8 a[16]; mk(&f, "rh.exe", 0); pattern(a, 16, 2);
    HANDLE h = sipt_open(f.path, GENERIC_READ);
    sipt_subject(&si, &G_PE, h, NULL, OID_SHA1, 0);
    SET_ERR(0);
    CHECK(!WPUT(&si, ENC, &idx, 16, a));
    t_note("Put through read-only handle: error 0x%lx", GetLastError());
    CHECK(sipt_size(f.path) == 0x400);
    CloseHandle(h);
}
TEST(sip_pe_put_read_only_file) {
    REQUIRE(WPUT);
    PF f; SIP_SUBJECTINFO si; DWORD idx; u8 a[16]; mk(&f, "ro.exe", 0); pattern(a, 16, 2);
    SetFileAttributesA(f.path, FILE_ATTRIBUTE_READONLY);
    sipt_subject(&si, &G_PE, NULL, f.w, OID_SHA1, 0);
    SET_ERR(0);
    CHECK(!WPUT(&si, ENC, &idx, 16, a));
    EXPECT_ERR(ERROR_ACCESS_DENIED);
    SET_ERR(0);
    CHECK(!WREM(&si, 0)); EXPECT_ERR(ERROR_ACCESS_DENIED);
    SetFileAttributesA(f.path, FILE_ATTRIBUTE_NORMAL);
    CHECK(sipt_size(f.path) == 0x400);
}
TEST(sip_pe_put_missing_file) {
    REQUIRE(WPUT); REQUIRE(WGET); REQUIRE(WREM);
    PF f; SIP_SUBJECTINFO si; DWORD idx, cb = 0, enc; u8 a[16] = {1};
    t_tmpfile(f.path, sizeof f.path, "nope.exe"); sipt_wide(f.w, MAX_PATH, f.path);
    sipt_subject(&si, &G_PE, NULL, f.w, OID_SHA1, 0);
    SET_ERR(0); CHECK(!WPUT(&si, ENC, &idx, 16, a)); EXPECT_ERR(ERROR_FILE_NOT_FOUND);
    SET_ERR(0); CHECK(!WGET(&si, &enc, 0, &cb, NULL)); EXPECT_ERR(ERROR_FILE_NOT_FOUND);
    SET_ERR(0); CHECK(!WREM(&si, 0)); EXPECT_ERR(ERROR_FILE_NOT_FOUND);
}
TEST(sip_pe_put_into_non_pe_file) {
    REQUIRE(WPUT);
    PF f; SIP_SUBJECTINFO si; DWORD idx; u8 a[16] = {1};
    t_tmpfile(f.path, sizeof f.path, "text.exe"); sipt_put(f.path, "plain text file, not an image at all.....", 40); sipt_wide(f.w, MAX_PATH, f.path);
    sipt_subject(&si, &G_PE, NULL, f.w, OID_SHA1, 0);
    SET_ERR(0);
    CHECK(!WPUT(&si, ENC, &idx, 16, a));
    t_note("Put into non-PE file: error 0x%lx size %u", GetLastError(), (unsigned)sipt_size(f.path));
}
TEST(sip_pe_full_flow_through_crypt32_dispatch) {
    REQUIRE(U(CryptSIPLoad));
    SIP_DISPATCH_INFO d; memset(&d, 0, sizeof d);
    CHECK(U(CryptSIPLoad)(&G_PE, 0, &d));
    if (!d.pfCreate || !d.pfPut || !d.pfGet || !d.pfVerify || !d.pfRemove) return;
    PF f; SIP_SUBJECTINFO si; DWORD cb = 0, idx = 7, enc = 0; u8 blob[40], got[128];
    mk(&f, "flow.exe", 2); pattern(blob, sizeof blob, 31);
    sipt_subject(&si, &G_PE, NULL, f.w, OID_SHA256, DEFAULT_FLAGS);
    CHECK(d.pfCreate(&si, &cb, NULL) && cb > 0);
    u8 *buf = calloc(1, cb); SIP_INDIRECT_DATA *id = (SIP_INDIRECT_DATA *)buf;
    CHECK(d.pfCreate(&si, &cb, id) == TRUE);
    CHECK(id->Digest.cbData == 32 && !memcmp(id->Digest.pbData, kat_pe2_sha256, 32));
    CHECK(d.pfPut(&si, ENC, &idx, sizeof blob, blob) == TRUE); CHECK(idx == 0);
    cb = 0; CHECK(d.pfGet(&si, &enc, 0, &cb, NULL) == TRUE); CHECK(cb == sizeof blob + 8);
    cb = sizeof got; CHECK(d.pfGet(&si, &enc, 0, &cb, got) == TRUE); CHECK(cb == sizeof blob && !memcmp(got, blob, sizeof blob));
    CHECK(d.pfVerify(&si, id) == TRUE);
    CHECK(d.pfRemove(&si, 0) == TRUE);
    CHECK(d.pfVerify(&si, id) == TRUE);
    cb = 0; CHECK(!d.pfGet(&si, &enc, 0, &cb, NULL));
    free(buf);
}

TEST(sip_pe_calls_through_mssip32_forwarders) {
    FARPROC c = t_proc_in("mssip32.dll", "CryptSIPCreateIndirectData"), v = t_proc_in("mssip32.dll", "CryptSIPVerifyIndirectData");
    FARPROC p = t_proc_in("mssip32.dll", "CryptSIPPutSignedDataMsg"), g = t_proc_in("mssip32.dll", "CryptSIPGetSignedDataMsg");
    FARPROC r = t_proc_in("mssip32.dll", "CryptSIPRemoveSignedDataMsg");
    if (!c || !v || !p || !g || !r) { t_skip("mssip32.dll exports not available"); return; }
    PF f; SIP_SUBJECTINFO si; DWORD cb = 0, idx = 5, enc = 0; u8 blob[16], got[32]; mk(&f, "ms.exe", 0); pattern(blob, 16, 8);
    sipt_subject(&si, &G_PE, NULL, f.w, OID_SHA1, DEFAULT_FLAGS);
    CHECK(((pCryptSIPCreateIndirectData)c)(&si, &cb, NULL) == TRUE && cb > 0);
    u8 *buf = calloc(1, cb); SIP_INDIRECT_DATA *id = (SIP_INDIRECT_DATA *)buf;
    CHECK(((pCryptSIPCreateIndirectData)c)(&si, &cb, id) == TRUE);
    CHECK(id->Digest.cbData == 20 && !memcmp(id->Digest.pbData, kat_pe0_sha1, 20));
    CHECK(((pCryptSIPPutSignedDataMsg)p)(&si, ENC, &idx, 16, blob) == TRUE && idx == 0);
    cb = sizeof got; CHECK(((pCryptSIPGetSignedDataMsg)g)(&si, &enc, 0, &cb, got) == TRUE && cb == 16 && !memcmp(got, blob, 16));
    CHECK(((pCryptSIPVerifyIndirectData)v)(&si, id) == TRUE);
    CHECK(((pCryptSIPRemoveSignedDataMsg)r)(&si, 0) == TRUE);
    free(buf);
}
