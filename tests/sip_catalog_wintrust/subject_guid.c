/* CryptSIPRetrieveSubjectGuid / CryptSIPRetrieveSubjectGuidForCatalogFile: file sniffing rules. */
#include "sip_common.h"

#define PRE() memset(&g, 0xFF, sizeof g)
static int guid_eq(const GUID *a, const GUID *b) { return !memcmp(a, b, sizeof *a); }
static int guid_zero(const GUID *a) { GUID z; memset(&z, 0, sizeof z); return guid_eq(a, &z); }

/* sniff `bytes` stored in a file called `leaf` with the by-name API. */
static BOOL sniff(int catalog, const char *leaf, const void *bytes, size_t n, GUID *g)
{
    char path[MAX_PATH]; WCHAR w[MAX_PATH];
    t_tmpfile(path, sizeof path, leaf);
    sipt_put(path, bytes, n);
    sipt_wide(w, MAX_PATH, path);
    SET_ERR(0xDEAD);
    memset(g, 0xFF, sizeof *g);
    return (catalog ? U(CryptSIPRetrieveSubjectGuidForCatalogFile) : U(CryptSIPRetrieveSubjectGuid))(w, NULL, g);
}

/* A PE-like image with a chosen e_lfanew and file size; "PE\0\0" at e_lfanew when it fits. */
static size_t fake_pe(u8 *b, size_t size, unsigned lfanew, int with_sig)
{
    memset(b, 0, size);
    b[0] = 'M'; b[1] = 'Z';
    sipi_w32(b + 0x3c, lfanew);
    if (with_sig && (size_t)lfanew + 4 <= size) memcpy(b + lfanew, "PE\0\0", 4);
    return size;
}

TEST(sip_guid_null_out_param) {
    REQUIRE(U(CryptSIPRetrieveSubjectGuid));
    char path[MAX_PATH]; WCHAR w[MAX_PATH]; u8 b[4096];
    sipt_mkpe(path, sizeof path, "nullout.exe", 0); sipt_wide(w, MAX_PATH, path);
    SET_ERR(0);
    EXPECT_FAIL(!U(CryptSIPRetrieveSubjectGuid)(w, NULL, NULL), ERROR_INVALID_PARAMETER);
    SET_ERR(0);
    EXPECT_FAIL(!U(CryptSIPRetrieveSubjectGuid)(NULL, NULL, NULL), ERROR_INVALID_PARAMETER);
    (void)b;
}
TEST(sip_guid_null_out_param_catalog_variant) {
    REQUIRE(U(CryptSIPRetrieveSubjectGuidForCatalogFile));
    char path[MAX_PATH]; WCHAR w[MAX_PATH];
    sipt_mkpe(path, sizeof path, "nullout2.exe", 0); sipt_wide(w, MAX_PATH, path);
    SET_ERR(0);
    EXPECT_FAIL(!U(CryptSIPRetrieveSubjectGuidForCatalogFile)(w, NULL, NULL), ERROR_INVALID_PARAMETER);
}
TEST(sip_guid_no_name_no_handle) {
    REQUIRE(U(CryptSIPRetrieveSubjectGuid));
    GUID g; HANDLE bad[2] = { NULL, INVALID_HANDLE_VALUE };
    for (int i = 0; i < 2; i++) {
        PRE(); SET_ERR(0);
        EXPECT_FAIL(!U(CryptSIPRetrieveSubjectGuid)(NULL, bad[i], &g), ERROR_INVALID_PARAMETER);
        CHECK(guid_zero(&g));
    }
}
TEST(sip_guid_no_name_no_handle_catalog_variant) {
    REQUIRE(U(CryptSIPRetrieveSubjectGuidForCatalogFile));
    GUID g; HANDLE bad[2] = { NULL, INVALID_HANDLE_VALUE };
    for (int i = 0; i < 2; i++) {
        PRE(); SET_ERR(0);
        EXPECT_FAIL(!U(CryptSIPRetrieveSubjectGuidForCatalogFile)(NULL, bad[i], &g), ERROR_INVALID_PARAMETER);
        CHECK(guid_zero(&g));
    }
}
TEST(sip_guid_missing_file) {
    REQUIRE(U(CryptSIPRetrieveSubjectGuid));
    char path[MAX_PATH]; WCHAR w[MAX_PATH]; GUID g;
    t_tmpfile(path, sizeof path, "does_not_exist.exe"); sipt_wide(w, MAX_PATH, path);
    PRE(); SET_ERR(0);
    EXPECT_FAIL(!U(CryptSIPRetrieveSubjectGuid)(w, NULL, &g), ERROR_FILE_NOT_FOUND);
    CHECK(guid_zero(&g));
    char dir[MAX_PATH]; snprintf(dir, sizeof dir, "%sno_such_dir\\x.exe", t_tmpdir()); sipt_wide(w, MAX_PATH, dir);
    PRE(); SET_ERR(0);
    EXPECT_FAIL(!U(CryptSIPRetrieveSubjectGuid)(w, NULL, &g), ERROR_PATH_NOT_FOUND);
    CHECK(guid_zero(&g));
}
TEST(sip_guid_missing_file_catalog_variant) {
    REQUIRE(U(CryptSIPRetrieveSubjectGuidForCatalogFile));
    char path[MAX_PATH]; WCHAR w[MAX_PATH]; GUID g;
    t_tmpfile(path, sizeof path, "does_not_exist.cat"); sipt_wide(w, MAX_PATH, path);
    PRE(); SET_ERR(0);
    EXPECT_FAIL(!U(CryptSIPRetrieveSubjectGuidForCatalogFile)(w, NULL, &g), ERROR_FILE_NOT_FOUND);
    CHECK(guid_zero(&g));
}
TEST(sip_guid_directory_is_not_openable) {
    REQUIRE(U(CryptSIPRetrieveSubjectGuid));
    WCHAR w[MAX_PATH]; GUID g;
    sipt_wide(w, MAX_PATH, t_tmpdir());
    PRE(); SET_ERR(0);
    /* CreateFile on a directory without FILE_FLAG_BACKUP_SEMANTICS */
    EXPECT_FAIL(!U(CryptSIPRetrieveSubjectGuid)(w, NULL, &g), ERROR_ACCESS_DENIED);
    CHECK(guid_zero(&g));
}
TEST(sip_guid_sharing_violation_with_writer) {
    REQUIRE(U(CryptSIPRetrieveSubjectGuid)); REQUIRE(U(CryptSIPRetrieveSubjectGuidForCatalogFile));
    char path[MAX_PATH]; WCHAR w[MAX_PATH]; GUID g; u8 b[4096];
    size_t n = sipi_pe(0, b, sizeof b);
    t_tmpfile(path, sizeof path, "locked.exe"); sipt_put(path, b, n); sipt_wide(w, MAX_PATH, path);
    HANDLE hw = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    CHECK(hw != INVALID_HANDLE_VALUE);
    if (hw == INVALID_HANDLE_VALUE) return;
    PRE(); SET_ERR(0);
    EXPECT_FAIL(!U(CryptSIPRetrieveSubjectGuid)(w, NULL, &g), ERROR_SHARING_VIOLATION);
    PRE(); SET_ERR(0);
    EXPECT_FAIL(!U(CryptSIPRetrieveSubjectGuidForCatalogFile)(w, NULL, &g), ERROR_SHARING_VIOLATION);
    CloseHandle(hw);
    PRE();
    CHECK(U(CryptSIPRetrieveSubjectGuid)(w, NULL, &g)); CHECK(guid_eq(&g, &G_PE));
}
TEST(sip_guid_too_small_files) {
    REQUIRE(U(CryptSIPRetrieveSubjectGuid));
    static const u8 data[4] = { 'M', 'S', 'C', 'F' };
    GUID g;
    for (size_t n = 0; n < 4; n++) {
        BOOL r = sniff(0, "small.bin", data, n, &g);
        CHECKF(!r, "size %u", (unsigned)n);
        EXPECT_ERR(ERROR_INVALID_PARAMETER);
        CHECK(guid_zero(&g));
    }
    CHECK(sniff(0, "four.bin", data, 4, &g) == TRUE);
    CHECK(guid_eq(&g, &G_CAB));
}
TEST(sip_guid_four_unknown_bytes) {
    REQUIRE(U(CryptSIPRetrieveSubjectGuid));
    GUID g; static const u8 d[4] = { 'a', 'b', 'c', 'd' };
    CHECK(!sniff(0, "abcd.bin", d, 4, &g));
    EXPECT_ERR(E_TRUST_SUBJECT_FORM_UNKNOWN);
    CHECK(guid_zero(&g));
}
TEST(sip_guid_pe_hand_built_variants) {
    REQUIRE(U(CryptSIPRetrieveSubjectGuid));
    for (unsigned v = 0; v < SIPI_PE_NVARIANTS; v++) {
        char path[MAX_PATH]; WCHAR w[MAX_PATH]; GUID g;
        sipt_mkpe(path, sizeof path, "variant.exe", v); sipt_wide(w, MAX_PATH, path);
        PRE(); SET_ERR(0xDEAD);
        BOOL r = U(CryptSIPRetrieveSubjectGuid)(w, NULL, &g);
        CHECKF(r == TRUE, "variant %u", v);
        CHECKF(guid_eq(&g, &G_PE), "variant %u", v);
    }
}
TEST(sip_guid_pe_extension_is_irrelevant) {
    REQUIRE(U(CryptSIPRetrieveSubjectGuid));
    static const char *leaf[] = { "noext", "image.dll", "image.txt", "image.cat", "image.sys", "image.EXE" };
    u8 b[4096]; size_t n = sipi_pe(0, b, sizeof b); GUID g;
    for (unsigned i = 0; i < sizeof leaf / sizeof *leaf; i++) {
        CHECKF(sniff(0, leaf[i], b, n, &g) == TRUE, "%s", leaf[i]);
        CHECKF(guid_eq(&g, &G_PE), "%s", leaf[i]);
    }
}
TEST(sip_guid_by_handle_keeps_handle_usable) {
    REQUIRE(U(CryptSIPRetrieveSubjectGuid));
    char path[MAX_PATH]; GUID g; u8 b[16];
    sipt_mkpe(path, sizeof path, "byhandle.exe", 0);
    HANDLE h = sipt_open(path, GENERIC_READ);
    CHECK(h != INVALID_HANDLE_VALUE);
    if (h == INVALID_HANDLE_VALUE) return;
    PRE(); SET_ERR(0xDEAD);
    CHECK(U(CryptSIPRetrieveSubjectGuid)(NULL, h, &g) == TRUE);
    CHECK(guid_eq(&g, &G_PE));
    DWORD r = 0;
    CHECK(SetFilePointer(h, 0, NULL, FILE_BEGIN) == 0);
    CHECK(ReadFile(h, b, 2, &r, NULL) && r == 2 && b[0] == 'M' && b[1] == 'Z');   /* handle still open */
    CloseHandle(h);
}
TEST(sip_guid_handle_wins_over_name) {
    REQUIRE(U(CryptSIPRetrieveSubjectGuid));
    char path[MAX_PATH]; GUID g; WCHAR w[MAX_PATH];
    sipt_mkcab(path, sizeof path, "real.cab");
    HANDLE h = sipt_open(path, GENERIC_READ);
    sipt_wide(w, MAX_PATH, "C:\\this\\does\\not\\exist.exe");
    PRE();
    CHECK(U(CryptSIPRetrieveSubjectGuid)(w, h, &g) == TRUE);
    CHECK(guid_eq(&g, &G_CAB));
    CloseHandle(h);
}
TEST(sip_guid_handle_without_read_access_fails_mapping) {
    REQUIRE(U(CryptSIPRetrieveSubjectGuid));
    char path[MAX_PATH]; GUID g;
    sipt_mkpe(path, sizeof path, "wo.exe", 0);
    HANDLE h = sipt_open(path, GENERIC_WRITE);
    if (h == INVALID_HANDLE_VALUE) { t_skip("cannot open write-only"); return; }
    PRE(); SET_ERR(0);
    BOOL r = U(CryptSIPRetrieveSubjectGuid)(NULL, h, &g);
    CHECK(!r);
    if (!r) { CHECK(guid_zero(&g)); t_note("write-only handle last error %lu", GetLastError()); }
    CloseHandle(h);
}
TEST(sip_guid_non_file_handle_fails) {
    REQUIRE(U(CryptSIPRetrieveSubjectGuid));
    GUID g; HANDLE ev = CreateEventA(NULL, TRUE, FALSE, NULL);
    PRE(); SET_ERR(0);
    CHECK(!U(CryptSIPRetrieveSubjectGuid)(NULL, ev, &g));   /* GetFileSizeEx on an event handle */
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
    CHECK(guid_zero(&g));
    CloseHandle(ev);
}
TEST(sip_guid_pe_header_boundaries) {
    REQUIRE(U(CryptSIPRetrieveSubjectGuid));
    /* _DetermineWhichPE: size > 0x3f, e_lfanew+0x40 < size, e_lfanew+0x148 <= size, "PE\0\0" at e_lfanew */
    static const struct { unsigned lfanew; unsigned size; int sig; int is_pe; const char *what; } t[] = {
        { 0x40,  0x40 + 0x148,     1, 1, "exact minimum size, lfanew 0x40" },
        { 0x40,  0x40 + 0x148 - 1, 1, 0, "one byte short" },
        { 0x40,  0x40 + 0x148 + 1, 1, 1, "one byte over" },
        { 0x80,  0x80 + 0x148,     1, 1, "exact, lfanew 0x80" },
        { 0x80,  0x80 + 0x148 - 1, 1, 0, "short, lfanew 0x80" },
        { 0x100, 0x100 + 0x148,    1, 1, "exact, lfanew 0x100" },
        { 0x100, 0x100 + 0x147,    1, 0, "short, lfanew 0x100" },
        { 0x40,  0x400,            0, 0, "no PE signature" },
        { 0x80,  0x400,            0, 0, "no PE signature at 0x80" },
        { 0x3c,  0x400,            1, 1, "lfanew inside the DOS header region" },
        { 0x0,   0x400,            1, 0, "lfanew 0 (MZ is not a PE signature)" },
        { 0xFFFFFFF0u, 0x400,      1, 0, "lfanew huge" },
        { 0x7fffffbfu, 0x400,      1, 0, "lfanew at the limit" },
        { 0x80000000u, 0x400,      1, 0, "lfanew negative as int" },
        { 0x200, 0x300,            1, 0, "lfanew beyond end" },
    };
    for (unsigned i = 0; i < sizeof t / sizeof *t; i++) {
        u8 b[0x800]; GUID g;
        fake_pe(b, t[i].size, t[i].lfanew, t[i].sig);
        BOOL r = sniff(0, "hdr.bin", b, t[i].size, &g);
        if (t[i].is_pe) { CHECKF(r == TRUE && guid_eq(&g, &G_PE), "%s", t[i].what); }
        else { CHECKF(!r, "%s", t[i].what); if (!r) { EXPECT_ERR(E_TRUST_SUBJECT_FORM_UNKNOWN); } }
    }
}
TEST(sip_guid_pe_signature_variants) {
    REQUIRE(U(CryptSIPRetrieveSubjectGuid));
    static const u8 sigs[][4] = { {'P','E',0,1}, {'p','e',0,0}, {'P','E',1,0}, {'N','E',0,0}, {'P','E',0,0} };
    for (unsigned i = 0; i < 5; i++) {
        u8 b[0x400]; GUID g;
        fake_pe(b, 0x400, 0x80, 0);
        memcpy(b + 0x80, sigs[i], 4);
        BOOL r = sniff(0, "sig.bin", b, 0x400, &g);
        if (i == 4) CHECK(r == TRUE && guid_eq(&g, &G_PE)); else CHECKF(!r, "variant %u", i);
    }
}
TEST(sip_guid_mz_stub_only) {
    REQUIRE(U(CryptSIPRetrieveSubjectGuid));
    u8 b[0x40]; GUID g;
    memset(b, 0, sizeof b); b[0] = 'M'; b[1] = 'Z';
    CHECK(!sniff(0, "stub.exe", b, sizeof b, &g));
    EXPECT_ERR(E_TRUST_SUBJECT_FORM_UNKNOWN);
    CHECK(guid_zero(&g));
    CHECK(!sniff(0, "stub2.exe", b, 0x20, &g));
    EXPECT_ERR(E_TRUST_SUBJECT_FORM_UNKNOWN);
}
TEST(sip_guid_cab_signature) {
    REQUIRE(U(CryptSIPRetrieveSubjectGuid));
    GUID g; u8 b[64];
    memset(b, 0xCC, sizeof b);
    memcpy(b, "MSCF", 4);
    CHECK(sniff(0, "any.cab", b, 64, &g) == TRUE); CHECK(guid_eq(&g, &G_CAB));
    CHECK(sniff(0, "any.bin", b, 64, &g) == TRUE); CHECK(guid_eq(&g, &G_CAB));
    memcpy(b, "mscf", 4);
    CHECK(!sniff(0, "lower.cab", b, 64, &g)); EXPECT_ERR(E_TRUST_SUBJECT_FORM_UNKNOWN);
    memcpy(b, "MSCE", 4);
    CHECK(!sniff(0, "near.cab", b, 64, &g)); EXPECT_ERR(E_TRUST_SUBJECT_FORM_UNKNOWN);
    memcpy(b + 1, "MSCF", 4); b[0] = 0;
    CHECK(!sniff(0, "off1.cab", b, 64, &g));
}
TEST(sip_guid_cab_real_fixture) {
    REQUIRE(U(CryptSIPRetrieveSubjectGuid));
    char path[MAX_PATH]; WCHAR w[MAX_PATH]; GUID g;
    sipt_mkcab(path, sizeof path, "real.cab"); sipt_wide(w, MAX_PATH, path);
    PRE();
    CHECK(U(CryptSIPRetrieveSubjectGuid)(w, NULL, &g) == TRUE);
    CHECK(guid_eq(&g, &G_CAB));
}
TEST(sip_guid_mz_beats_cab_when_both_match) {
    REQUIRE(U(CryptSIPRetrieveSubjectGuid));
    u8 b[0x400]; GUID g;
    sipi_pe(0, b, sizeof b);
    CHECK(sniff(0, "pe.cab", b, 0x400, &g) == TRUE); CHECK(guid_eq(&g, &G_PE));
}
TEST(sip_guid_ctl_catalog_and_other_ctl) {
    REQUIRE(U(CryptSIPRetrieveSubjectGuid));
    u8 m[1024]; size_t n; GUID g;
    n = sipt_make_ctl(m, sizeof m, OID_CATALOG_LIST);
    if (!n) { t_skip("cannot build CTL message"); return; }
    CHECK(m[0] == 0x30);
    CHECK(sniff(0, "a.cat", m, n, &g) == TRUE); CHECK(guid_eq(&g, &G_CAT));
    CHECK(sniff(0, "a.bin", m, n, &g) == TRUE); CHECK(guid_eq(&g, &G_CAT));       /* content, not extension */
    n = sipt_make_ctl(m, sizeof m, "1.3.6.1.4.1.311.10.3.1");
    CHECK(sniff(0, "b.ctl", m, n, &g) == TRUE); CHECK(guid_eq(&g, &G_CTL));
    n = sipt_make_ctl(m, sizeof m, NULL);
    if (n) { CHECK(sniff(0, "c.ctl", m, n, &g) == TRUE); CHECK(guid_eq(&g, &G_CTL)); }
}
TEST(sip_guid_ctl_truncated_is_unknown) {
    REQUIRE(U(CryptSIPRetrieveSubjectGuid));
    u8 m[1024]; size_t n = sipt_make_ctl(m, sizeof m, OID_CATALOG_LIST); GUID g;
    if (!n) { t_skip("cannot build CTL message"); return; }
    CHECK(!sniff(0, "trunc.cat", m, n - 3, &g)); EXPECT_ERR(E_TRUST_SUBJECT_FORM_UNKNOWN);
    CHECK(guid_zero(&g));
    CHECK(!sniff(0, "trunc2.cat", m, 12, &g)); EXPECT_ERR(E_TRUST_SUBJECT_FORM_UNKNOWN);
}
TEST(sip_guid_der_sequence_that_is_not_a_ctl) {
    REQUIRE(U(CryptSIPRetrieveSubjectGuid));
    static const u8 seq[] = { 0x30, 0x03, 0x02, 0x01, 0x05 };      /* SEQUENCE { INTEGER 5 } */
    static const u8 text[] = "0 is just a digit here";
    GUID g;
    CHECK(!sniff(0, "seq.bin", seq, sizeof seq, &g)); EXPECT_ERR(E_TRUST_SUBJECT_FORM_UNKNOWN);
    CHECK(!sniff(0, "digit.txt", text, sizeof text - 1, &g)); EXPECT_ERR(E_TRUST_SUBJECT_FORM_UNKNOWN);
}
TEST(sip_guid_plain_text_unknown) {
    REQUIRE(U(CryptSIPRetrieveSubjectGuid));
    static const char *leaf[] = { "a.txt", "a.bin", "a.dat", "noext", "a.cat.bak" };
    static const char text[] = "just some ordinary text, nothing to sign here\r\n";
    GUID g;
    for (unsigned i = 0; i < 5; i++) {
        BOOL r = sniff(0, leaf[i], text, sizeof text - 1, &g);
        CHECKF(!r, "%s", leaf[i]);
        EXPECT_ERR(E_TRUST_SUBJECT_FORM_UNKNOWN);
        CHECKF(guid_zero(&g), "%s", leaf[i]);
    }
}
TEST(sip_guid_powershell_by_extension) {
    REQUIRE(U(CryptSIPRetrieveSubjectGuid));
    static const char script[] = "Write-Host 'hello'\r\n";
    GUID g;
    if (!sipt_sip_is_registered(&G_PS)) { t_skip("PowerShell SIP not registered"); return; }
    BOOL r = sniff(0, "t.ps1", script, sizeof script - 1, &g);
    CHECK(r == TRUE);
    if (r) CHECK(guid_eq(&g, &G_PS));
    r = sniff(0, "t.txt", script, sizeof script - 1, &g);
    CHECK(!r);                                  /* the registered IsMyFileType2 hook keys on the file name */
    if (!r) EXPECT_ERR(E_TRUST_SUBJECT_FORM_UNKNOWN);
}
TEST(sip_guid_script_and_msi_notes) {
    REQUIRE(U(CryptSIPRetrieveSubjectGuid));
    static const char js[] = "WScript.Echo(1);\r\n";
    GUID g;
    BOOL r = sniff(0, "t.js", js, sizeof js - 1, &g);
    t_note("t.js -> %d err 0x%lx guid %08lx (script SIP registered: %d)", r, GetLastError(), (unsigned long)g.Data1, sipt_sip_is_registered(&G_UNKNOWN));
    t_note("MSI SIP %s registered, PowerShell SIP %s registered", sipt_sip_is_registered(&G_MSI) ? "is" : "is not", sipt_sip_is_registered(&G_PS) ? "is" : "is not");
}
TEST(sip_guid_output_pointer_is_fully_overwritten_on_success) {
    REQUIRE(U(CryptSIPRetrieveSubjectGuid));
    u8 b[4096]; size_t n = sipi_pe(0, b, sizeof b); GUID g;
    CHECK(sniff(0, "o.exe", b, n, &g) == TRUE);
    CHECK(g.Data1 == 0xC689AAB8 && g.Data2 == 0x8E78 && g.Data3 == 0x11D0);
    CHECK(g.Data4[0] == 0x8C && g.Data4[1] == 0x47 && g.Data4[2] == 0x00 && g.Data4[3] == 0xC0 && g.Data4[4] == 0x4F && g.Data4[5] == 0xC2 && g.Data4[6] == 0x95 && g.Data4[7] == 0xEE);
}

/* ---- ForCatalogFile: only PE and CAB are recognised, everything else is "flat" ---- */
TEST(sip_guid_catalog_variant_pe_and_cab) {
    REQUIRE(U(CryptSIPRetrieveSubjectGuidForCatalogFile));
    u8 b[4096]; size_t n = sipi_pe(0, b, sizeof b); GUID g;
    CHECK(sniff(1, "pe.bin", b, n, &g) == TRUE); CHECK(guid_eq(&g, &G_PE));
    n = sipi_cab(b, sizeof b);
    CHECK(sniff(1, "c.bin", b, n, &g) == TRUE); CHECK(guid_eq(&g, &G_CAB));
}
TEST(sip_guid_catalog_variant_unknown_is_flat) {
    REQUIRE(U(CryptSIPRetrieveSubjectGuidForCatalogFile));
    static const char text[] = "plain text, no signature\r\n";
    GUID g;
    CHECK(sniff(1, "t.txt", text, sizeof text - 1, &g) == TRUE); CHECK(guid_eq(&g, &G_FLAT));
    CHECK(sniff(1, "t.ps1", text, sizeof text - 1, &g) == TRUE);  CHECK(guid_eq(&g, &G_FLAT));   /* no registry hooks consulted */
}
TEST(sip_guid_catalog_variant_small_files_are_flat) {
    REQUIRE(U(CryptSIPRetrieveSubjectGuidForCatalogFile));
    static const u8 d[4] = { 'M', 'S', 'C', 'F' };
    GUID g;
    for (size_t n = 0; n < 4; n++) {
        CHECKF(sniff(1, "small.bin", d, n, &g) == TRUE, "size %u", (unsigned)n);
        CHECKF(guid_eq(&g, &G_FLAT), "size %u", (unsigned)n);
    }
    CHECK(sniff(1, "four.bin", d, 4, &g) == TRUE); CHECK(guid_eq(&g, &G_CAB));
}
TEST(sip_guid_catalog_variant_does_not_sniff_ctl) {
    REQUIRE(U(CryptSIPRetrieveSubjectGuidForCatalogFile));
    u8 m[1024]; size_t n = sipt_make_ctl(m, sizeof m, OID_CATALOG_LIST); GUID g;
    if (!n) { t_skip("cannot build CTL message"); return; }
    CHECK(sniff(1, "a.cat", m, n, &g) == TRUE);
    CHECK(guid_eq(&g, &G_FLAT));
}
TEST(sip_guid_catalog_variant_pe_boundaries) {
    REQUIRE(U(CryptSIPRetrieveSubjectGuidForCatalogFile));
    u8 b[0x400]; GUID g;
    fake_pe(b, 0x40 + 0x148, 0x40, 1);
    CHECK(sniff(1, "x.bin", b, 0x40 + 0x148, &g) == TRUE); CHECK(guid_eq(&g, &G_PE));
    fake_pe(b, 0x40 + 0x147, 0x40, 1);
    CHECK(sniff(1, "x.bin", b, 0x40 + 0x147, &g) == TRUE); CHECK(guid_eq(&g, &G_FLAT));
}
TEST(sip_guid_catalog_variant_by_handle) {
    REQUIRE(U(CryptSIPRetrieveSubjectGuidForCatalogFile));
    char path[MAX_PATH]; GUID g;
    sipt_mkpe(path, sizeof path, "h.exe", 0);
    HANDLE h = sipt_open(path, GENERIC_READ);
    PRE();
    CHECK(U(CryptSIPRetrieveSubjectGuidForCatalogFile)(NULL, h, &g) == TRUE); CHECK(guid_eq(&g, &G_PE));
    CHECK(GetFileSize(h, NULL) == 0x400);        /* still open */
    CloseHandle(h);
}
TEST(sip_guid_catalog_variant_non_file_handle) {
    REQUIRE(U(CryptSIPRetrieveSubjectGuidForCatalogFile));
    GUID g; HANDLE ev = CreateEventA(NULL, TRUE, FALSE, NULL);
    PRE(); SET_ERR(0);
    CHECK(!U(CryptSIPRetrieveSubjectGuidForCatalogFile)(NULL, ev, &g));
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
    CHECK(guid_zero(&g));
    CloseHandle(ev);
}
