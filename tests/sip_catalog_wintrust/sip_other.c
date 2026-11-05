/* CAB (C689AABA), flat (DE351A42) and catalog (DE351A43 / 9BA61D3F) subject types. */
#include "sip_common.h"
#include "kats.h"

#define WCRE UIN("wintrust.dll", CryptSIPCreateIndirectData)
#define WVER UIN("wintrust.dll", CryptSIPVerifyIndirectData)
#define WGET UIN("wintrust.dll", CryptSIPGetSignedDataMsg)
#define WPUT UIN("wintrust.dll", CryptSIPPutSignedDataMsg)
#define WREM UIN("wintrust.dll", CryptSIPRemoveSignedDataMsg)
#define ENC (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING)
#define NOPT 0
#define OID_CAB_DATA  "1.3.6.1.4.1.311.2.1.28"
#define OID_FLAT_DATA "1.3.6.1.4.1.311.2.1.25"

typedef struct { char path[MAX_PATH]; WCHAR w[MAX_PATH]; } XF;
static void xf_put(XF *f, const char *leaf, const void *b, size_t n)
{
    t_tmpfile(f->path, sizeof f->path, leaf);
    sipt_put(f->path, b, n);
    sipt_wide(f->w, MAX_PATH, f->path);
}
static void xf_cab(XF *f, const char *leaf) { u8 b[256]; size_t n = sipi_cab(b, sizeof b); xf_put(f, leaf, b, n); }

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
static size_t slurp(const char *p, u8 *b, size_t cap) { return sipt_get(p, b, cap); }
static unsigned rd32(const u8 *b, size_t o) { return b[o] | b[o + 1] << 8 | b[o + 2] << 16 | (unsigned)b[o + 3] << 24; }
static unsigned rd16(const u8 *b, size_t o) { return b[o] | b[o + 1] << 8; }

/* ============================ CAB ============================ */
TEST(sip_cab_create_size_query_leaves_file_alone) {
    REQUIRE(WCRE);
    XF f; SIP_SUBJECTINFO si; DWORD cb = 0; u8 img[256], now[256]; size_t n = sipi_cab(img, sizeof img);
    xf_cab(&f, "q.cab");
    sipt_subject(&si, &G_CAB, NULL, f.w, OID_SHA1, 0);
    CHECK(WCRE(&si, &cb, NULL) == TRUE);
    CHECK(cb > sizeof(SIP_INDIRECT_DATA));
    CHECK(slurp(f.path, now, sizeof now) == n && !memcmp(img, now, n));
}
TEST(sip_cab_create_reserves_signature_area) {
    REQUIRE(WCRE);
    XF f; SIP_SUBJECTINFO si; u8 b[512]; xf_cab(&f, "r.cab");
    sipt_subject(&si, &G_CAB, NULL, f.w, OID_SHA1, 0);
    SIP_INDIRECT_DATA *id = create_id(&si, NULL);
    CHECK(id != NULL);
    free(id);
    size_t n = slurp(f.path, b, sizeof b);
    CHECK(n == SIPI_CAB_SIZE + 24);                       /* 4 bytes of reserve sizes + 20 bytes of reserve data */
    if (n != SIPI_CAB_SIZE + 24) return;
    CHECK(!memcmp(b, "MSCF", 4));
    CHECK(rd32(b, 8) == SIPI_CAB_SIZE + 24);              /* cbCabinet */
    CHECK(rd32(b, 16) == 44 + 24);                        /* coffFiles */
    CHECK(rd16(b, 30) == 4);                              /* flags: cfhdrRESERVE_PRESENT */
    CHECK(rd16(b, 0x24) == 20 && b[0x26] == 0 && b[0x27] == 0);   /* cbCFHeader / cbCFFolder / cbCFData */
    CHECK(rd16(b, 0x28) == 0 && rd16(b, 0x2a) == 0x10);   /* no prefix data; 16 byte signature slot */
    for (int i = 0x2c; i < 0x3c; i++) CHECKF(b[i] == 0, "slot byte 0x%x", i);
    CHECK(rd32(b, 60) == 66 + 24);                        /* the folder entry's data offset moved with the data */
    GUID g;
    CHECK(U(CryptSIPRetrieveSubjectGuid)(f.w, NULL, &g) && !memcmp(&g, &G_CAB, 16));
}
TEST(sip_cab_create_is_idempotent) {
    REQUIRE(WCRE);
    XF f; SIP_SUBJECTINFO si; u8 a[512], b[512]; xf_cab(&f, "i.cab");
    sipt_subject(&si, &G_CAB, NULL, f.w, OID_SHA256, 0);
    SIP_INDIRECT_DATA *i1 = create_id(&si, NULL);
    size_t n1 = slurp(f.path, a, sizeof a);
    SIP_INDIRECT_DATA *i2 = create_id(&si, NULL);
    size_t n2 = slurp(f.path, b, sizeof b);
    CHECK(i1 && i2);
    CHECK(n1 == n2 && !memcmp(a, b, n1));
    if (i1 && i2) CHECK(i1->Digest.cbData == 32 && i2->Digest.cbData == 32 && !memcmp(i1->Digest.pbData, i2->Digest.pbData, 32));
    free(i1); free(i2);
}
TEST(sip_cab_create_structure_and_size_layout) {
    REQUIRE(WCRE);
    static const struct { const char *oid; unsigned len; } t[] = { { OID_SHA1, 20 }, { OID_SHA256, 32 }, { OID_SHA384, 48 }, { OID_SHA512, 64 }, { OID_MD5, 16 } };
    for (unsigned i = 0; i < 5; i++) {
        XF f; SIP_SUBJECTINFO si; DWORD need = 0; xf_cab(&f, "s.cab");
        sipt_subject(&si, &G_CAB, NULL, f.w, t[i].oid, 0);
        SIP_INDIRECT_DATA *id = create_id(&si, &need);
        CHECKF(id != NULL, "%s", t[i].oid);
        if (!id) continue;
        EXPECT_STR(id->Data.pszObjId, OID_CAB_DATA);
        EXPECT_STR(id->DigestAlgorithm.pszObjId, t[i].oid);
        CHECKF(id->Digest.cbData == t[i].len, "%s", t[i].oid);
        /* SPC data value starts with a context tag [1] (0xA1) whose length covers the rest */
        CHECKF(id->Data.Value.cbData > 2 && id->Data.Value.pbData[0] == 0xA1 && id->Data.Value.pbData[1] == id->Data.Value.cbData - 2, "%s", t[i].oid);
        CHECKF(need == sizeof(SIP_INDIRECT_DATA) + strlen(OID_CAB_DATA) + 1 + id->Data.Value.cbData + strlen(t[i].oid) + 1 + t[i].len, "%s need %lu", t[i].oid, need);
        free(id);
    }
}
TEST(sip_cab_create_buffer_boundaries) {
    REQUIRE(WCRE);
    XF f; SIP_SUBJECTINFO si; DWORD need = 0, cb; xf_cab(&f, "b.cab");
    sipt_subject(&si, &G_CAB, NULL, f.w, OID_SHA1, 0);
    free(create_id(&si, &need));
    u8 *buf = calloc(1, need + 32);
    cb = need - 1; CHECK(!WCRE(&si, &cb, (SIP_INDIRECT_DATA *)buf));
    cb = need;     CHECK(WCRE(&si, &cb, (SIP_INDIRECT_DATA *)buf) == TRUE);
    free(buf);
}
TEST(sip_cab_create_digest_is_deterministic_and_content_sensitive) {
    REQUIRE(WCRE);
    XF f1, f2, f3; SIP_SUBJECTINFO si; u8 img[256]; size_t n = sipi_cab(img, sizeof img);
    xf_cab(&f1, "d1.cab"); xf_cab(&f2, "d2.cab");
    img[76] ^= 1; xf_put(&f3, "d3.cab", img, n);                    /* payload byte of the stored file */
    SIP_INDIRECT_DATA *a, *b, *c;
    sipt_subject(&si, &G_CAB, NULL, f1.w, OID_SHA256, 0); a = create_id(&si, NULL);
    sipt_subject(&si, &G_CAB, NULL, f2.w, OID_SHA256, 0); b = create_id(&si, NULL);
    sipt_subject(&si, &G_CAB, NULL, f3.w, OID_SHA256, 0); c = create_id(&si, NULL);
    CHECK(a && b && c);
    if (a && b && c) {
        CHECK(!memcmp(a->Digest.pbData, b->Digest.pbData, 32));
        CHECK(memcmp(a->Digest.pbData, c->Digest.pbData, 32) != 0);
    }
    free(a); free(b); free(c);
}
TEST(sip_cab_create_header_fields_are_digested) {
    REQUIRE(WCRE);
    XF f1, f2; SIP_SUBJECTINFO si; u8 img[256]; size_t n = sipi_cab(img, sizeof img);
    xf_cab(&f1, "h1.cab");
    sipi_w16(img + 32, 0x4321);                                      /* setID */
    xf_put(&f2, "h2.cab", img, n);
    sipt_subject(&si, &G_CAB, NULL, f1.w, OID_SHA1, 0); SIP_INDIRECT_DATA *a = create_id(&si, NULL);
    sipt_subject(&si, &G_CAB, NULL, f2.w, OID_SHA1, 0); SIP_INDIRECT_DATA *b = create_id(&si, NULL);
    CHECK(a && b);
    if (a && b) CHECK(memcmp(a->Digest.pbData, b->Digest.pbData, 20) != 0);
    free(a); free(b);
}
TEST(sip_cab_create_prohibit_resize_flag) {
    REQUIRE(WCRE);
    XF f; SIP_SUBJECTINFO si; u8 img[256], now[512]; size_t n = sipi_cab(img, sizeof img); xf_cab(&f, "p.cab");
    SetFileAttributesA(f.path, FILE_ATTRIBUTE_READONLY);              /* no write access needed with the flag */
    sipt_subject(&si, &G_CAB, NULL, f.w, OID_SHA1, MSSIP_FLAGS_PROHIBIT_RESIZE_ON_CREATE);
    SIP_INDIRECT_DATA *id = create_id(&si, NULL);
    CHECK(id != NULL);
    CHECK(slurp(f.path, now, sizeof now) == n && !memcmp(img, now, n));
    SetFileAttributesA(f.path, FILE_ATTRIBUTE_NORMAL);
    sipt_subject(&si, &G_CAB, NULL, f.w, OID_SHA1, 0);
    SIP_INDIRECT_DATA *id2 = create_id(&si, NULL);
    if (id && id2) CHECK(memcmp(id->Digest.pbData, id2->Digest.pbData, 20) != 0);   /* cbCabinet is part of the digest */
    free(id); free(id2);
}
TEST(sip_cab_create_read_only_file_needs_write_access) {
    REQUIRE(WCRE);
    XF f; SIP_SUBJECTINFO si; u8 buf[1024]; DWORD cb = sizeof buf; xf_cab(&f, "ro.cab");
    SetFileAttributesA(f.path, FILE_ATTRIBUTE_READONLY);
    sipt_subject(&si, &G_CAB, NULL, f.w, OID_SHA1, 0);
    SET_ERR(0);
    CHECK(!WCRE(&si, &cb, (SIP_INDIRECT_DATA *)buf));
    EXPECT_ERR(ERROR_ACCESS_DENIED);
    SetFileAttributesA(f.path, FILE_ATTRIBUTE_NORMAL);
}
TEST(sip_cab_create_malformed_cabinets) {
    REQUIRE(WCRE);
    static const struct { size_t off; unsigned w; unsigned val; const char *what; } m[] = {
        { 8, 4, SIPI_CAB_SIZE + 1, "cbCabinet beyond end of file" },
        { 8, 4, SIPI_CAB_SIZE - 1, "cbCabinet short of the data" },
        { 16, 4, 45, "coffFiles not at end of folder table" },
        { 36, 4, 67, "folder data offset wrong" },
        { 0, 4, 0x46435351, "bad signature" },
        { 26, 2, 3, "cFolders overstated" },
    };
    for (unsigned i = 0; i < sizeof m / sizeof *m; i++) {
        XF f; SIP_SUBJECTINFO si; u8 img[256], buf[1024]; DWORD cb = sizeof buf; size_t n = sipi_cab(img, sizeof img);
        if (m[i].w == 4) sipi_w32(img + m[i].off, m[i].val); else sipi_w16(img + m[i].off, m[i].val);
        xf_put(&f, "bad.cab", img, n);
        sipt_subject(&si, &G_CAB, NULL, f.w, OID_SHA1, MSSIP_FLAGS_PROHIBIT_RESIZE_ON_CREATE);
        SET_ERR(0);
        CHECKF(!WCRE(&si, &cb, (SIP_INDIRECT_DATA *)buf), "%s", m[i].what);
    }
}
TEST(sip_cab_get_from_pristine_cabinet) {
    REQUIRE(WGET);
    XF f; SIP_SUBJECTINFO si; DWORD cb = 0, enc = 0; xf_cab(&f, "g.cab");
    sipt_subject(&si, &G_CAB, NULL, f.w, OID_SHA1, 0);
    SET_ERR(0);
    CHECK(!WGET(&si, &enc, 0, &cb, NULL));
    EXPECT_ERR(E_TRUST_NOSIGNATURE);
    SET_ERR(0); cb = 0;
    CHECK(!WGET(&si, &enc, 1, &cb, NULL));                     /* only index 0 exists for a CAB */
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
}
TEST(sip_cab_put_without_reserved_area_fails) {
    REQUIRE(WPUT);
    XF f; SIP_SUBJECTINFO si; DWORD idx = 0; u8 blob[24] = {1}; u8 img[256]; size_t n = sipi_cab(img, sizeof img); xf_cab(&f, "np.cab");
    sipt_subject(&si, &G_CAB, NULL, f.w, OID_SHA1, 0);
    CHECK(!WPUT(&si, ENC, &idx, sizeof blob, blob));
    u8 now[256]; CHECK(slurp(f.path, now, sizeof now) == n && !memcmp(now, img, n));
}
static void pat(u8 *p, size_t n, u8 s) { for (size_t i = 0; i < n; i++) p[i] = (u8)(s + i * 3); }
TEST(sip_cab_sign_roundtrip) {
    REQUIRE(WCRE); REQUIRE(WPUT); REQUIRE(WGET); REQUIRE(WVER);
    XF f; SIP_SUBJECTINFO si; DWORD idx = 0, cb = 0, enc = 0; u8 blob[24], got[64], raw[512];
    xf_cab(&f, "sg.cab"); pat(blob, sizeof blob, 40);
    sipt_subject(&si, &G_CAB, NULL, f.w, OID_SHA256, 0);
    SIP_INDIRECT_DATA *id = create_id(&si, NULL);
    CHECK(id != NULL);
    CHECK(WPUT(&si, ENC, &idx, sizeof blob, blob) == TRUE);
    size_t n = slurp(f.path, raw, sizeof raw);
    CHECK(n == SIPI_CAB_SIZE + 24 + sizeof blob);                  /* signature appended after the cabinet */
    if (n >= SIPI_CAB_SIZE + 24 + sizeof blob) {
        CHECK(rd32(raw, 8) == SIPI_CAB_SIZE + 24);                 /* cbCabinet does not cover the signature */
        CHECK(rd32(raw, 0x2c) == SIPI_CAB_SIZE + 24 && rd32(raw, 0x30) == sizeof blob);
        CHECK(!memcmp(raw + SIPI_CAB_SIZE + 24, blob, sizeof blob));
    }
    cb = 0; SET_ERR(0);
    CHECK(WGET(&si, &enc, 0, &cb, NULL) == TRUE);
    CHECK(cb == sizeof blob + 8);
    cb = sizeof blob + 8; memset(got, 0xEE, sizeof got);
    CHECK(WGET(&si, &enc, 0, &cb, got) == TRUE);
    CHECK(cb == sizeof blob && !memcmp(got, blob, sizeof blob));
    CHECK(enc == ENC);
    if (id) {
        sipt_subject(&si, &G_CAB, NULL, f.w, OID_SHA256, 0);
        SET_ERR(0);
        CHECK(WVER(&si, id) == TRUE);                              /* digest taken before signing still verifies */
    }
    free(id);
}
TEST(sip_cab_get_buffer_too_small) {
    REQUIRE(WCRE); REQUIRE(WPUT); REQUIRE(WGET);
    XF f; SIP_SUBJECTINFO si; DWORD idx, cb, enc; u8 blob[24], got[64]; xf_cab(&f, "gs.cab"); pat(blob, sizeof blob, 5);
    sipt_subject(&si, &G_CAB, NULL, f.w, OID_SHA1, 0);
    free(create_id(&si, NULL));
    CHECK(WPUT(&si, ENC, &idx, sizeof blob, blob));
    for (cb = 8; cb < sizeof blob + 8; cb++) {
        DWORD c = cb; SET_ERR(0);
        CHECKF(!WGET(&si, &enc, 0, &c, got), "cb %lu", cb);
        EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER);
    }
}
TEST(sip_cab_verify_detects_tampering) {
    REQUIRE(WCRE); REQUIRE(WVER);
    XF f; SIP_SUBJECTINFO si; xf_cab(&f, "vt.cab");
    sipt_subject(&si, &G_CAB, NULL, f.w, OID_SHA1, 0);
    SIP_INDIRECT_DATA *id = create_id(&si, NULL);
    CHECK(id != NULL);
    if (!id) return;
    CHECK(WVER(&si, id) == TRUE);
    HANDLE h = CreateFileA(f.path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    DWORD n; SetFilePointer(h, 76 + 24, NULL, FILE_BEGIN); WriteFile(h, "Z", 1, &n, NULL); CloseHandle(h);   /* "hello" -> "hellZ" */
    SET_ERR(0);
    CHECK(!WVER(&si, id));
    EXPECT_ERR(E_TRUST_BAD_DIGEST);
    free(id);
}
TEST(sip_cab_verify_blocked_extension) {
    REQUIRE(WCRE); REQUIRE(WVER);
    XF f; SIP_SUBJECTINFO si; xf_cab(&f, "x.cab");
    sipt_subject(&si, &G_CAB, NULL, f.w, OID_SHA1, 0);
    SIP_INDIRECT_DATA *id = create_id(&si, NULL);
    CHECK(id != NULL);
    if (!id) return;
    XF g; t_tmpfile(g.path, sizeof g.path, "copy.js");
    CopyFileA(f.path, g.path, FALSE); sipt_wide(g.w, MAX_PATH, g.path);
    sipt_subject(&si, &G_CAB, NULL, g.w, OID_SHA1, 0);
    SET_ERR(0);
    CHECK(!WVER(&si, id)); EXPECT_ERR(ERROR_FILE_INVALID);
    free(id);
}
TEST(sip_cab_remove_is_not_supported) {
    REQUIRE(WREM);
    XF f; SIP_SUBJECTINFO si; xf_cab(&f, "rm.cab");
    sipt_subject(&si, &G_CAB, NULL, f.w, OID_SHA1, 0);
    CHECK(!WREM(&si, 0));
}
TEST(sip_cab_wrong_subject_content) {
    REQUIRE(WCRE);
    XF f; SIP_SUBJECTINFO si; u8 img[4096], buf[1024]; DWORD cb = sizeof buf;
    size_t n = sipi_pe(0, img, sizeof img);
    xf_put(&f, "pe.cab", img, n);
    sipt_subject(&si, &G_CAB, NULL, f.w, OID_SHA1, MSSIP_FLAGS_PROHIBIT_RESIZE_ON_CREATE);
    CHECK(!WCRE(&si, &cb, (SIP_INDIRECT_DATA *)buf));
    CHECK(sipt_size(f.path) == n);                                   /* a PE is left untouched */
}

/* ============================ flat ============================ */
static void flat_data(u8 *b, size_t n) { for (size_t i = 0; i < n; i++) b[i] = (u8)(i * 11 + 5); }

TEST(sip_flat_create_hashes_whole_file) {
    REQUIRE(WCRE);
    u8 d[100]; flat_data(d, sizeof d);
    XF f; SIP_SUBJECTINFO si; xf_put(&f, "flat.bin", d, sizeof d);
    sipt_subject(&si, &G_FLAT, NULL, f.w, OID_SHA1, 0);
    SIP_INDIRECT_DATA *id = create_id(&si, NULL);
    CHECK(id != NULL);
    if (id) { EXPECT_STR(id->Data.pszObjId, OID_FLAT_DATA); CHECK(id->Digest.cbData == 20 && !memcmp(id->Digest.pbData, kat_flat_sha1, 20)); free(id); }
    sipt_subject(&si, &G_FLAT, NULL, f.w, OID_SHA256, 0);
    id = create_id(&si, NULL);
    CHECK(id != NULL);
    if (id) { CHECK(id->Digest.cbData == 32 && !memcmp(id->Digest.pbData, kat_flat_sha256, 32)); free(id); }
}
TEST(sip_flat_digest_of_pe_is_plain_file_hash) {
    REQUIRE(WCRE);
    u8 pe[4096]; size_t n = sipi_pe(0, pe, sizeof pe);
    XF f; SIP_SUBJECTINFO si; xf_put(&f, "pe.bin", pe, n);
    sipt_subject(&si, &G_FLAT, NULL, f.w, OID_SHA256, 0);
    SIP_INDIRECT_DATA *id = create_id(&si, NULL);
    CHECK(id && id->Digest.cbData == 32 && !memcmp(id->Digest.pbData, kat_flatpe0_sha256, 32));
    CHECK(id && memcmp(id->Digest.pbData, kat_pe0_sha256, 32) != 0);       /* not the Authenticode digest */
    free(id);
}
TEST(sip_flat_create_by_handle) {
    REQUIRE(WCRE);
    u8 d[100]; flat_data(d, sizeof d);
    XF f; SIP_SUBJECTINFO si; xf_put(&f, "flat.bin", d, sizeof d);
    HANDLE h = sipt_open(f.path, GENERIC_READ);
    sipt_subject(&si, &G_FLAT, h, NULL, OID_SHA256, 0);
    SIP_INDIRECT_DATA *id = create_id(&si, NULL);
    CHECK(id && !memcmp(id->Digest.pbData, kat_flat_sha256, 32));
    free(id);
    CHECK(GetFileSize(h, NULL) == 100);
    CloseHandle(h);
}
TEST(sip_flat_verify_with_add_info_never_succeeds) {
    /* Win10: with a valid MS_ADDINFO_FLAT the flat SIP verify returns FALSE with last error 0, for an unmodified file,
       a modified file, a corrupted digest, other algorithms and a handle subject alike. */
    REQUIRE(WCRE); REQUIRE(WVER);
    u8 d[100]; flat_data(d, sizeof d);
    XF f; SIP_SUBJECTINFO si; MS_ADDINFO_FLAT ai; xf_put(&f, "flat.bin", d, sizeof d);
    sipt_subject(&si, &G_FLAT, NULL, f.w, OID_SHA1, 0);
    SIP_INDIRECT_DATA *id = create_id(&si, NULL);
    CHECK(id != NULL);
    if (!id) return;
    ai.cbStruct = sizeof ai; ai.pIndirectData = id;
    si.dwUnionChoice = MSSIP_ADDINFO_FLAT; si.psFlat = &ai;
    SET_ERR(0x55);
    CHECK(!WVER(&si, id)); EXPECT_ERR(0);                      /* unmodified file */
    d[50] ^= 1; sipt_put(f.path, d, sizeof d);
    SET_ERR(0x55);
    CHECK(!WVER(&si, id)); EXPECT_ERR(0);                      /* modified file */
    d[50] ^= 1; sipt_put(f.path, d, sizeof d);
    id->Digest.pbData[0] ^= 1;
    SET_ERR(0x55);
    CHECK(!WVER(&si, id)); EXPECT_ERR(0);                      /* corrupted digest */
    id->Digest.pbData[0] ^= 1;
    HANDLE h = sipt_open(f.path, GENERIC_READ);
    SIP_SUBJECTINFO s2; sipt_subject(&s2, &G_FLAT, h, NULL, OID_SHA1, 0);
    s2.dwUnionChoice = MSSIP_ADDINFO_FLAT; s2.psFlat = &ai;
    SET_ERR(0x55);
    CHECK(!WVER(&s2, id)); EXPECT_ERR(0);                      /* handle subject */
    CloseHandle(h);
    ai.cbStruct = 0x1000;
    SET_ERR(0x55);
    CHECK(!WVER(&si, id)); EXPECT_ERR(ERROR_INVALID_PARAMETER);    /* only cbStruct is validated */
    free(id);
}
TEST(sip_flat_verify_without_add_info_is_invalid_argument) {
    REQUIRE(WVER);
    u8 d[100]; flat_data(d, sizeof d);
    XF f; SIP_SUBJECTINFO si; xf_put(&f, "flat.bin", d, sizeof d);
    sipt_subject(&si, &G_FLAT, NULL, f.w, OID_SHA1, 0);
    SET_ERR(0);
    CHECK(!WVER(&si, NULL));
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
    MS_ADDINFO_FLAT ai = { 0x11, NULL };
    si.dwUnionChoice = MSSIP_ADDINFO_FLAT; si.psFlat = &ai;                 /* wrong cbStruct */
    SET_ERR(0);
    CHECK(!WVER(&si, (SIP_INDIRECT_DATA *)&ai));
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
}
TEST(sip_flat_get_reports_no_embedded_signature) {
    REQUIRE(WGET);
    SIP_SUBJECTINFO si; DWORD cb = 0x1234, enc = 0;
    sipt_subject(&si, &G_FLAT, NULL, NULL, OID_SHA1, 0);                   /* no file is even opened */
    CHECK(WGET(&si, &enc, 0, &cb, NULL) == TRUE);
    CHECK(cb == 0 && enc == ENC);
    cb = 99; enc = 0; u8 buf[8];
    CHECK(WGET(&si, &enc, 3, &cb, buf) == TRUE);
    CHECK(cb == 0 && enc == ENC);
}
TEST(sip_flat_put_and_remove_are_unsupported) {
    REQUIRE(WPUT); REQUIRE(WREM);
    SIP_SUBJECTINFO si; DWORD idx = 0x77; u8 blob[16] = {1};
    XF f; xf_put(&f, "flat.bin", "abcdefgh", 8);
    sipt_subject(&si, &G_FLAT, NULL, f.w, OID_SHA1, 0);
    CHECK(!WPUT(&si, ENC, &idx, sizeof blob, blob));
    CHECK(!WREM(&si, 0));
    CHECK(sipt_size(f.path) == 8);
}
TEST(sip_flat_create_unknown_algorithm_and_missing_file) {
    REQUIRE(WCRE);
    XF f; SIP_SUBJECTINFO si; u8 buf[512]; DWORD cb = sizeof buf; xf_put(&f, "flat.bin", "abcdefgh", 8);
    sipt_subject(&si, &G_FLAT, NULL, f.w, "1.2.3.4.5", 0);
    SET_ERR(0); CHECK(!WCRE(&si, &cb, (SIP_INDIRECT_DATA *)buf)); EXPECT_ERR(E_NTE_BAD_ALGID);
    XF g; t_tmpfile(g.path, sizeof g.path, "gone.bin"); sipt_wide(g.w, MAX_PATH, g.path);
    sipt_subject(&si, &G_FLAT, NULL, g.w, OID_SHA1, 0); cb = sizeof buf;
    SET_ERR(0); CHECK(!WCRE(&si, &cb, (SIP_INDIRECT_DATA *)buf)); EXPECT_ERR(ERROR_FILE_NOT_FOUND);
}

/* ============================ catalog (DE351A43 / 9BA61D3F) ============================ */
static const GUID *k_cat[2] = { &G_CAT, &G_CTL };

TEST(sip_cat_create_indirect_data_is_empty) {
    REQUIRE(WCRE);
    for (int i = 0; i < 2; i++) {
        SIP_SUBJECTINFO si; DWORD cb = 0x1234; u8 buf[64];
        sipt_subject(&si, k_cat[i], NULL, NULL, OID_SHA1, 0);                  /* nothing is opened */
        CHECK(WCRE(&si, &cb, NULL) == TRUE); CHECK(cb == 0);
        cb = 0x1234;
        CHECK(WCRE(&si, &cb, (SIP_INDIRECT_DATA *)buf) == TRUE); CHECK(cb == 0);
    }
}
TEST(sip_cat_get_returns_file_contents) {
    REQUIRE(WGET);
    u8 m[1024]; size_t n = sipt_make_ctl(m, sizeof m, OID_CATALOG_LIST);
    if (!n) { t_skip("cannot build CTL message"); return; }
    for (int i = 0; i < 2; i++) {
        XF f; SIP_SUBJECTINFO si; DWORD cb = 0, enc = 0; u8 got[1024];
        xf_put(&f, "c.cat", m, n);
        sipt_subject(&si, k_cat[i], NULL, f.w, OID_SHA1, 0);
        CHECK(WGET(&si, &enc, 0, &cb, NULL) == TRUE);
        CHECKF(cb == n && enc == ENC, "size query: cb %lu", cb);
        cb = sizeof got; enc = 0; memset(got, 0, sizeof got);
        CHECK(WGET(&si, &enc, 0, &cb, got) == TRUE);
        CHECK(enc == ENC);
        CHECK(cb == sizeof got);                              /* *pcb is left as the caller's buffer size on success */
        CHECK(!memcmp(got, m, n));
        cb = (DWORD)n; memset(got, 0, sizeof got);
        CHECK(WGET(&si, &enc, 0, &cb, got) == TRUE);          /* exact fit */
        CHECK(!memcmp(got, m, n));
        cb = (DWORD)n - 1; SET_ERR(0);
        CHECK(!WGET(&si, &enc, 0, &cb, got)); EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER);
        cb = 0; SET_ERR(0);
        CHECK(!WGET(&si, &enc, 1, &cb, NULL)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    }
}
TEST(sip_cat_get_missing_file) {
    REQUIRE(WGET);
    XF f; SIP_SUBJECTINFO si; DWORD cb = 0, enc = 0;
    t_tmpfile(f.path, sizeof f.path, "none.cat"); sipt_wide(f.w, MAX_PATH, f.path);
    sipt_subject(&si, &G_CAT, NULL, f.w, OID_SHA1, 0);
    SET_ERR(0);
    CHECK(!WGET(&si, &enc, 0, &cb, NULL)); EXPECT_ERR(ERROR_FILE_NOT_FOUND);
}
TEST(sip_cat_get_from_memory_blob) {
    REQUIRE(WGET);
    SIP_SUBJECTINFO si; MS_ADDINFO_BLOB bl; DWORD cb = 0, enc = 0; u8 mem[40], got[64];
    pat(mem, sizeof mem, 9);
    memset(&bl, 0, sizeof bl); bl.cbStruct = sizeof bl; bl.cbMemObject = sizeof mem; bl.pbMemObject = mem;
    sipt_subject(&si, &G_CAT, NULL, NULL, OID_SHA1, 0);
    si.dwUnionChoice = MSSIP_ADDINFO_BLOB; si.psBlob = &bl;
    CHECK(WGET(&si, &enc, 0, &cb, NULL) == TRUE); CHECK(cb == sizeof mem);
    cb = sizeof got; memset(got, 0, sizeof got);
    CHECK(WGET(&si, &enc, 0, &cb, got) == TRUE); CHECK(!memcmp(got, mem, sizeof mem));
    cb = sizeof mem - 1; SET_ERR(0);
    CHECK(!WGET(&si, &enc, 0, &cb, got)); EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER);
    bl.cbStruct = 0x18; SET_ERR(0); cb = 0;
    CHECK(!WGET(&si, &enc, 0, &cb, NULL)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    bl.cbStruct = 0x19; cb = 0;
    CHECK(WGET(&si, &enc, 0, &cb, NULL) == TRUE);
    si.psBlob = NULL; SET_ERR(0);
    CHECK(!WGET(&si, &enc, 0, &cb, NULL)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
}
TEST(sip_cat_put_replaces_file_contents) {
    REQUIRE(WPUT);
    for (int i = 0; i < 2; i++) {
        XF f; SIP_SUBJECTINFO si; DWORD idx = 0x5555; u8 blob[100], now[256];
        pat(blob, sizeof blob, 17);
        xf_put(&f, "p.cat", "old content that is longer than nothing at all, 0123456789 0123456789 0123456789 0123456789", 90);
        sipt_subject(&si, k_cat[i], NULL, f.w, OID_SHA1, 0);
        CHECK(WPUT(&si, ENC, &idx, 40, blob) == TRUE);
        CHECK(idx == 0x5555);                                   /* index out parameter is not written */
        CHECK(slurp(f.path, now, sizeof now) == 40 && !memcmp(now, blob, 40));
    }
}
TEST(sip_cat_put_missing_file) {
    REQUIRE(WPUT);
    XF f; SIP_SUBJECTINFO si; DWORD idx = 0; u8 blob[8] = {1};
    t_tmpfile(f.path, sizeof f.path, "none.cat"); sipt_wide(f.w, MAX_PATH, f.path);
    sipt_subject(&si, &G_CAT, NULL, f.w, OID_SHA1, 0);
    SET_ERR(0);
    CHECK(!WPUT(&si, ENC, &idx, sizeof blob, blob)); EXPECT_ERR(ERROR_FILE_NOT_FOUND);
    CHECK(sipt_size(f.path) == (size_t)-1);                      /* and it is not created */
}
TEST(sip_cat_remove_is_not_supported) {
    REQUIRE(WREM);
    XF f; SIP_SUBJECTINFO si; xf_put(&f, "rm.cat", "abcdefgh", 8);
    sipt_subject(&si, &G_CAT, NULL, f.w, OID_SHA1, 0);
    CHECK(!WREM(&si, 0));
    CHECK(sipt_size(f.path) == 8);
}
TEST(sip_cat_verify_checks_file_extension_only) {
    REQUIRE(WVER);
    static const struct { const char *name; int ok; } t[] = {
        { "x.cat", 1 }, { "x.CAT", 1 }, { "x.Ctl", 1 }, { "x.p7s", 1 }, { "x.spc", 1 }, { "x.sst", 1 }, { "x.stl", 1 },
        { "a.b.cat", 1 }, { "x.txt", 0 }, { "x.exe", 0 }, { "x.cab", 0 }, { "x", 0 }, { "x.cat.bak", 0 }, { "x.cats", 0 },
        { "x.js", 0 }, { "x.vbs", 0 }, { "x.", 0 },
    };
    for (int g = 0; g < 2; g++) {
        for (unsigned i = 0; i < sizeof t / sizeof *t; i++) {
            SIP_SUBJECTINFO si; WCHAR w[64];
            sipt_wide(w, 64, t[i].name);
            sipt_subject(&si, k_cat[g], NULL, w, OID_SHA1, 0);
            SET_ERR(0);
            BOOL r = WVER(&si, NULL);
            CHECKF(r == (t[i].ok ? TRUE : FALSE), "%s", t[i].name);
            if (!t[i].ok) EXPECT_ERR(ERROR_FILE_INVALID);
        }
    }
}
TEST(sip_cat_verify_without_name_succeeds) {
    REQUIRE(WVER);
    SIP_SUBJECTINFO si;
    sipt_subject(&si, &G_CAT, NULL, NULL, OID_SHA1, 0);
    CHECK(WVER(&si, NULL) == TRUE);
}
TEST(sip_cat_verify_dispatch_via_crypt32) {
    REQUIRE(U(CryptSIPLoad));
    SIP_DISPATCH_INFO d; memset(&d, 0, sizeof d);
    CHECK(U(CryptSIPLoad)(&G_CAT, 0, &d));
    if (!d.pfVerify || !d.pfCreate) return;
    SIP_SUBJECTINFO si; DWORD cb = 5; WCHAR w[] = L"thing.cat";
    sipt_subject(&si, &G_CAT, NULL, w, OID_SHA1, 0);
    CHECK(d.pfVerify(&si, NULL) == TRUE);
    CHECK(d.pfCreate(&si, &cb, NULL) == TRUE && cb == 0);
}
