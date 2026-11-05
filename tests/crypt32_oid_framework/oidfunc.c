/* In-process OID function sets: init / install / get / free / default list / enum / registry value reads. */
#include "fw.h"

static int fA(void) { return 0xA1; }
static int fB(void) { return 0xB2; }
static int fC(void) { return 0xC3; }
static int fD(void) { return 0xD4; }
static int fE(void) { return 0xE5; }
#define PA ((void *)fA)
#define PB ((void *)fB)
#define PC ((void *)fC)
#define PD ((void *)fD)
#define PE ((void *)fE)
#define NUMOID(n) ((LPCSTR)(ULONG_PTR)(n))
#define SENT1 ((void *)(ULONG_PTR)0x1111)
#define SENT2 ((HCRYPTOIDFUNCADDR)(ULONG_PTR)0x2222)

static HCRYPTOIDFUNCSET mkset(const char *name) { return U(CryptInitOIDFunctionSet)(name, 0); }
static BOOL inst(HCRYPTOIDFUNCSET set, const char *name, DWORD enc, DWORD flags, const char *oid, void *fn) {
    CRYPT_OID_FUNC_ENTRY e = {oid, fn};
    (void)set;
    return U(CryptInstallOIDFunctionAddress)(NULL, enc, name, 1, &e, flags);
}
static BOOL getf(HCRYPTOIDFUNCSET set, DWORD enc, LPCSTR oid, DWORD flags, void **fn, HCRYPTOIDFUNCADDR *h) {
    return U(CryptGetOIDFunctionAddress)(set, enc, oid, flags, fn, h);
}
static void expect_notfound(HCRYPTOIDFUNCSET set, DWORD enc, LPCSTR oid, DWORD flags, const char *tag) {
    void *fn = SENT1; HCRYPTOIDFUNCADDR h = SENT2;
    SET_ERR(0);
    BOOL r = getf(set, enc, oid, flags, &fn, &h);
    DWORD e = GetLastError();
    CHECKF(r == FALSE, "%s: unexpectedly found", tag);
    CHECKF(e == ERROR_FILE_NOT_FOUND, "%s: error %lu", tag, e);
    CHECKF(fn == NULL && h == NULL, "%s: outputs not cleared (%p,%p)", tag, fn, h);
}
static void expect_found(HCRYPTOIDFUNCSET set, DWORD enc, LPCSTR oid, DWORD flags, void *want, const char *tag) {
    void *fn = NULL; HCRYPTOIDFUNCADDR h = NULL;
    BOOL r = getf(set, enc, oid, flags, &fn, &h);
    CHECKF(r == TRUE, "%s: not found (err %lu)", tag, GetLastError());
    CHECKF(fn == want, "%s: function %p want %p", tag, fn, want);
    CHECKF(h != NULL, "%s: null handle", tag);
    if (r) CHECK(U(CryptFreeOIDFunctionAddress)(h, 0) == TRUE);
}

/* ---- CryptInitOIDFunctionSet ---- */
TEST(fset_init_returns_handle) {
    REQUIRE(U(CryptInitOIDFunctionSet));
    CHECK(mkset("cryptt_fw_init1") != NULL);
}
TEST(fset_init_same_name_same_handle) {
    REQUIRE(U(CryptInitOIDFunctionSet));
    HCRYPTOIDFUNCSET a = mkset("cryptt_fw_init2"), b = mkset("cryptt_fw_init2");
    CHECK(a && a == b);
}
TEST(fset_init_different_names_differ) {
    REQUIRE(U(CryptInitOIDFunctionSet));
    HCRYPTOIDFUNCSET a = mkset("cryptt_fw_init3a"), b = mkset("cryptt_fw_init3b");
    CHECK(a && b && a != b);
}
TEST(fset_init_name_is_case_sensitive) {
    REQUIRE(U(CryptInitOIDFunctionSet));
    HCRYPTOIDFUNCSET a = mkset("cryptt_fw_Case4"), b = mkset("cryptt_fw_case4");
    CHECK(a && b && a != b);
}
TEST(fset_init_prefix_names_differ) {
    REQUIRE(U(CryptInitOIDFunctionSet));
    HCRYPTOIDFUNCSET a = mkset("cryptt_fw_pre5"), b = mkset("cryptt_fw_pre5x"), c = mkset("cryptt_fw_pre");
    CHECK(a && b && c && a != b && a != c && b != c);
}
TEST(fset_init_empty_name_ok) {
    REQUIRE(U(CryptInitOIDFunctionSet));
    HCRYPTOIDFUNCSET a = mkset(""), b = mkset("");
    CHECK(a && a == b);
}
TEST(fset_init_flags_not_validated) {
    REQUIRE(U(CryptInitOIDFunctionSet));
    HCRYPTOIDFUNCSET a = U(CryptInitOIDFunctionSet)("cryptt_fw_flags6", 0xFFFFFFFF), b = mkset("cryptt_fw_flags6");
    CHECK(a && a == b);
}
TEST(fset_init_long_name) {
    REQUIRE(U(CryptInitOIDFunctionSet));
    char n[400]; memset(n, 'x', sizeof n - 1); n[sizeof n - 1] = 0;
    HCRYPTOIDFUNCSET a = mkset(n); n[sizeof n - 2] = 'y';
    HCRYPTOIDFUNCSET b = mkset(n);
    CHECK(a && b && a != b);
}
TEST(fset_init_well_known_names_stable) {
    REQUIRE(U(CryptInitOIDFunctionSet));
    static const char *k[] = {"CryptDllEncodeObject", "CryptDllDecodeObject", "CryptDllEncodeObjectEx", "CryptDllDecodeObjectEx",
                              "CryptDllFindOIDInfo", "CertDllVerifyRevocation", "CryptDllExportPublicKeyInfoEx", "CryptDllImportPublicKeyInfoEx"};
    for (size_t i = 0; i < sizeof k / sizeof k[0]; i++) {
        HCRYPTOIDFUNCSET a = mkset(k[i]), b = mkset(k[i]);
        CHECKF(a && a == b, "%s", k[i]);
    }
}
static DWORD WINAPI init_thread(void *p) { *(HCRYPTOIDFUNCSET *)p = mkset("cryptt_fw_thread7"); return 0; }
TEST(fset_init_threads_share_one_set) {
    REQUIRE(U(CryptInitOIDFunctionSet));
    HCRYPTOIDFUNCSET r[4] = {0}; HANDLE h[4];
    for (int i = 0; i < 4; i++) h[i] = CreateThread(NULL, 0, init_thread, &r[i], 0, NULL);
    for (int i = 0; i < 4; i++) { CHECK(WaitForSingleObject(h[i], 10000) == WAIT_OBJECT_0); CloseHandle(h[i]); }
    for (int i = 1; i < 4; i++) CHECK(r[i] && r[i] == r[0]);
}

/* ---- Install + Get ---- */
TEST(fset_install_zero_entries_succeeds) {
    REQUIRE(U(CryptInstallOIDFunctionAddress));
    BOOL (WINAPI *pinst)(HMODULE, DWORD, LPCSTR, DWORD, const CRYPT_OID_FUNC_ENTRY[], DWORD) = U(CryptInstallOIDFunctionAddress);
    SET_ERR(0xdeadbeef);
    BOOL r = pinst(NULL, 0, "cryptt_fw_zero8", 0, NULL, 0);
    DWORD e = GetLastError();
    CHECK(r == TRUE);
    CHECKF(e == 0xdeadbeef, "last error 0x%lx", e);
}
TEST(fset_install_get_string_oid) {
    REQUIRE(U(CryptInstallOIDFunctionAddress)); REQUIRE(U(CryptGetOIDFunctionAddress));
    const char *fs = "cryptt_fw_str9"; HCRYPTOIDFUNCSET set = mkset(fs);
    CHECK(inst(set, fs, X509_ASN_ENCODING, 0, "1.2.3.4.9", PA));
    expect_found(set, X509_ASN_ENCODING, "1.2.3.4.9", 0, PA, "exact");
}
TEST(fset_get_unknown_oid_fails) {
    REQUIRE(U(CryptInstallOIDFunctionAddress)); REQUIRE(U(CryptGetOIDFunctionAddress));
    const char *fs = "cryptt_fw_unk10"; HCRYPTOIDFUNCSET set = mkset(fs);
    CHECK(inst(set, fs, 1, 0, "1.2.3.4.10", PA));
    expect_notfound(set, 1, "1.2.3.4.11", 0, "other oid");
    expect_notfound(set, 1, "1.2.3.4.1", 0, "prefix oid");
    expect_notfound(set, 1, "1.2.3.4.100", 0, "longer oid");
}
TEST(fset_get_from_empty_set_fails) {
    REQUIRE(U(CryptGetOIDFunctionAddress));
    HCRYPTOIDFUNCSET set = mkset("cryptt_fw_empty11");
    expect_notfound(set, 1, "1.2.3.4", 0, "empty set string");
    expect_notfound(set, 1, NUMOID(5), 0, "empty set numeric");
    expect_notfound(set, 1, CRYPT_DEFAULT_OID, 0, "empty set default");
}
TEST(fset_get_wrong_encoding_fails) {
    REQUIRE(U(CryptInstallOIDFunctionAddress)); REQUIRE(U(CryptGetOIDFunctionAddress));
    const char *fs = "cryptt_fw_enc12"; HCRYPTOIDFUNCSET set = mkset(fs);
    CHECK(inst(set, fs, X509_ASN_ENCODING, 0, "1.2.3.4.12", PA));
    /* 0x10000 has a zero low word, so the high word (1) is the encoding: it matches the x509 install (probed) */
    expect_found(set, PKCS_7_ASN_ENCODING, "1.2.3.4.12", 0, PA, "0x10000 selects encoding 1");
    expect_notfound(set, 3, "1.2.3.4.12", 0, "encoding 3");
    expect_notfound(set, 2, "1.2.3.4.12", 0, "encoding 2");
}
TEST(fset_encoding_uses_low_word_first) {
    REQUIRE(U(CryptInstallOIDFunctionAddress)); REQUIRE(U(CryptGetOIDFunctionAddress));
    const char *fs = "cryptt_fw_enc13"; HCRYPTOIDFUNCSET set = mkset(fs);
    CHECK(inst(set, fs, X509_ASN_ENCODING, 0, "1.2.3.4.13", PA));
    expect_found(set, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, "1.2.3.4.13", 0, PA, "x509|pkcs7 uses low word 0x10001 -> 1");
    expect_found(set, 0x00010001, "1.2.3.4.13", 0, PA, "0x10001");
    expect_found(set, 0xABCD0001, "1.2.3.4.13", 0, PA, "high word ignored when low word set");
    expect_notfound(set, 0x00010002, "1.2.3.4.13", 0, "low word 2 selects encoding 2");
}
TEST(fset_encoding_high_word_used_when_low_zero) {
    REQUIRE(U(CryptInstallOIDFunctionAddress)); REQUIRE(U(CryptGetOIDFunctionAddress));
    const char *fs = "cryptt_fw_enc14"; HCRYPTOIDFUNCSET set = mkset(fs);
    CHECK(inst(set, fs, X509_ASN_ENCODING, 0, "1.2.3.4.14", PA));
    expect_found(set, PKCS_7_ASN_ENCODING /* 0x10000 */, "1.2.3.4.14", 0, PA, "0x10000 -> 1");
    const char *fs2 = "cryptt_fw_enc14b"; HCRYPTOIDFUNCSET set2 = mkset(fs2);
    CHECK(inst(set2, fs2, 0x00020000, 0, "1.2.3.4.14", PB));
    expect_found(set2, 2, "1.2.3.4.14", 0, PB, "install with 0x20000 stores 2");
}
TEST(fset_encoding_zero_matches_zero) {
    REQUIRE(U(CryptInstallOIDFunctionAddress)); REQUIRE(U(CryptGetOIDFunctionAddress));
    const char *fs = "cryptt_fw_enc15"; HCRYPTOIDFUNCSET set = mkset(fs);
    CHECK(inst(set, fs, 0, 0, "1.2.3.4.15", PA));
    expect_found(set, 0, "1.2.3.4.15", 0, PA, "enc 0");
    expect_notfound(set, 1, "1.2.3.4.15", 0, "enc 1 vs installed 0");
}
TEST(fset_same_oid_per_encoding) {
    REQUIRE(U(CryptInstallOIDFunctionAddress)); REQUIRE(U(CryptGetOIDFunctionAddress));
    const char *fs = "cryptt_fw_enc16"; HCRYPTOIDFUNCSET set = mkset(fs);
    CHECK(inst(set, fs, 1, 0, "1.2.3.4.16", PA));
    CHECK(inst(set, fs, 2, 0, "1.2.3.4.16", PB));
    expect_found(set, 1, "1.2.3.4.16", 0, PA, "enc1");
    expect_found(set, 2, "1.2.3.4.16", 0, PB, "enc2");
}
TEST(fset_oid_string_case_insensitive) {
    REQUIRE(U(CryptInstallOIDFunctionAddress)); REQUIRE(U(CryptGetOIDFunctionAddress));
    const char *fs = "cryptt_fw_case17"; HCRYPTOIDFUNCSET set = mkset(fs);
    CHECK(inst(set, fs, 1, 0, "Foo.Bar.17", PA));
    expect_found(set, 1, "foo.bar.17", 0, PA, "lower");
    expect_found(set, 1, "FOO.BAR.17", 0, PA, "upper");
    expect_notfound(set, 1, "foo.bar.18", 0, "different");
}
TEST(fset_install_copies_oid_string) {
    REQUIRE(U(CryptInstallOIDFunctionAddress)); REQUIRE(U(CryptGetOIDFunctionAddress));
    const char *fs = "cryptt_fw_copy18"; HCRYPTOIDFUNCSET set = mkset(fs);
    char buf[32]; strcpy(buf, "copy.oid.18");
    CRYPT_OID_FUNC_ENTRY e = {buf, PA};
    CHECK(U(CryptInstallOIDFunctionAddress)(NULL, 1, fs, 1, &e, 0));
    memset(buf, 'Z', sizeof buf - 1);
    expect_found(set, 1, "copy.oid.18", 0, PA, "string copied at install");
}
TEST(fset_duplicate_install_first_wins) {
    REQUIRE(U(CryptInstallOIDFunctionAddress)); REQUIRE(U(CryptGetOIDFunctionAddress));
    const char *fs = "cryptt_fw_dup19"; HCRYPTOIDFUNCSET set = mkset(fs);
    CHECK(inst(set, fs, 1, 0, "dup.19", PA));
    CHECK(inst(set, fs, 1, 0, "dup.19", PB));
    expect_found(set, 1, "dup.19", 0, PA, "first installed");
}
TEST(fset_before_flag_installs_in_front) {
    REQUIRE(U(CryptInstallOIDFunctionAddress)); REQUIRE(U(CryptGetOIDFunctionAddress));
    const char *fs = "cryptt_fw_before20"; HCRYPTOIDFUNCSET set = mkset(fs);
    CHECK(inst(set, fs, 1, 0, "dup.20", PA));
    CHECK(inst(set, fs, 1, CRYPT_INSTALL_OID_FUNC_BEFORE_FLAG, "dup.20", PB));
    expect_found(set, 1, "dup.20", 0, PB, "BEFORE wins");
    CHECK(inst(set, fs, 1, 0, "dup.20", PC));
    expect_found(set, 1, "dup.20", 0, PB, "append after BEFORE does not displace");
}
TEST(fset_before_flag_numeric) {
    REQUIRE(U(CryptInstallOIDFunctionAddress)); REQUIRE(U(CryptGetOIDFunctionAddress));
    const char *fs = "cryptt_fw_before21"; HCRYPTOIDFUNCSET set = mkset(fs);
    CHECK(inst(set, fs, 1, 0, NUMOID(77), PA));
    CHECK(inst(set, fs, 1, CRYPT_INSTALL_OID_FUNC_BEFORE_FLAG, NUMOID(77), PB));
    expect_found(set, 1, NUMOID(77), 0, PB, "numeric BEFORE");
}
TEST(fset_install_flag_high_bit_masked) {
    REQUIRE(U(CryptInstallOIDFunctionAddress)); REQUIRE(U(CryptGetOIDFunctionAddress));
    const char *fs = "cryptt_fw_hibit22"; HCRYPTOIDFUNCSET set = mkset(fs);
    CHECK(inst(set, fs, 1, 0, "hb.22", PA));
    CHECK(inst(set, fs, 1, 0x80000000u | CRYPT_INSTALL_OID_FUNC_BEFORE_FLAG, "hb.22", PB));
    expect_found(set, 1, "hb.22", 0, PB, "bit 31 masked, BEFORE honored");
}
TEST(fset_install_multiple_entries_one_call) {
    REQUIRE(U(CryptInstallOIDFunctionAddress)); REQUIRE(U(CryptGetOIDFunctionAddress));
    const char *fs = "cryptt_fw_multi23"; HCRYPTOIDFUNCSET set = mkset(fs);
    CRYPT_OID_FUNC_ENTRY e[3] = {{"m.a.23", PA}, {"m.b.23", PB}, {"m.c.23", PC}};
    CHECK(U(CryptInstallOIDFunctionAddress)(NULL, 1, fs, 3, e, 0));
    expect_found(set, 1, "m.a.23", 0, PA, "a"); expect_found(set, 1, "m.b.23", 0, PB, "b"); expect_found(set, 1, "m.c.23", 0, PC, "c");
}
TEST(fset_install_via_set_name_visible_through_set) {
    REQUIRE(U(CryptInstallOIDFunctionAddress)); REQUIRE(U(CryptGetOIDFunctionAddress));
    /* install by name first, create the set handle afterwards */
    const char *fs = "cryptt_fw_late24";
    CRYPT_OID_FUNC_ENTRY e = {"late.24", PA};
    CHECK(U(CryptInstallOIDFunctionAddress)(NULL, 1, fs, 1, &e, 0));
    expect_found(mkset(fs), 1, "late.24", 0, PA, "late set");
}
TEST(fset_sets_are_independent) {
    REQUIRE(U(CryptInstallOIDFunctionAddress)); REQUIRE(U(CryptGetOIDFunctionAddress));
    const char *f1 = "cryptt_fw_ind25a", *f2 = "cryptt_fw_ind25b";
    HCRYPTOIDFUNCSET s1 = mkset(f1), s2 = mkset(f2);
    CHECK(inst(s1, f1, 1, 0, "ind.25", PA));
    CHECK(inst(s2, f2, 1, 0, "ind.25", PB));
    expect_found(s1, 1, "ind.25", 0, PA, "set 1"); expect_found(s2, 1, "ind.25", 0, PB, "set 2");
}
TEST(fset_get_installed_flag_finds_installed) {
    REQUIRE(U(CryptInstallOIDFunctionAddress)); REQUIRE(U(CryptGetOIDFunctionAddress));
    const char *fs = "cryptt_fw_instfl26"; HCRYPTOIDFUNCSET set = mkset(fs);
    CHECK(inst(set, fs, 1, 0, "if.26", PA));
    expect_found(set, 1, "if.26", CRYPT_GET_INSTALLED_OID_FUNC_FLAG, PA, "installed flag");
    expect_notfound(set, 1, "if.27", CRYPT_GET_INSTALLED_OID_FUNC_FLAG, "installed flag, missing");
}
TEST(fset_get_unknown_flags_are_ignored) {
    REQUIRE(U(CryptInstallOIDFunctionAddress)); REQUIRE(U(CryptGetOIDFunctionAddress));
    const char *fs = "cryptt_fw_flg28"; HCRYPTOIDFUNCSET set = mkset(fs);
    CHECK(inst(set, fs, 1, 0, "fl.28", PA));
    expect_found(set, 1, "fl.28", 0xFFFFFFFE, PA, "flags with bit0 clear");
}
TEST(fset_get_handle_stable_per_entry) {
    REQUIRE(U(CryptInstallOIDFunctionAddress)); REQUIRE(U(CryptGetOIDFunctionAddress));
    const char *fs = "cryptt_fw_hdl29"; HCRYPTOIDFUNCSET set = mkset(fs);
    CHECK(inst(set, fs, 1, 0, "h.a.29", PA)); CHECK(inst(set, fs, 1, 0, "h.b.29", PB));
    void *f; HCRYPTOIDFUNCADDR h1, h2, h3;
    CHECK(getf(set, 1, "h.a.29", 0, &f, &h1)); CHECK(getf(set, 1, "h.a.29", 0, &f, &h2)); CHECK(getf(set, 1, "h.b.29", 0, &f, &h3));
    CHECK(h1 && h1 == h2 && h3 && h3 != h1);
}
TEST(fset_many_entries) {
    REQUIRE(U(CryptInstallOIDFunctionAddress)); REQUIRE(U(CryptGetOIDFunctionAddress));
    const char *fs = "cryptt_fw_many30"; HCRYPTOIDFUNCSET set = mkset(fs);
    char oid[32];
    for (int i = 0; i < 200; i++) { sprintf(oid, "many.%d.30", i); CHECK(inst(set, fs, 1, 0, oid, (i & 1) ? PA : PB)); }
    for (int i = 0; i < 200; i++) { sprintf(oid, "many.%d.30", i); expect_found(set, 1, oid, 0, (i & 1) ? PA : PB, oid); }
    expect_notfound(set, 1, "many.200.30", 0, "beyond");
}

/* ---- numeric OIDs ---- */
TEST(fset_numeric_oid_roundtrip) {
    REQUIRE(U(CryptInstallOIDFunctionAddress)); REQUIRE(U(CryptGetOIDFunctionAddress));
    const char *fs = "cryptt_fw_num31"; HCRYPTOIDFUNCSET set = mkset(fs);
    CHECK(inst(set, fs, 1, 0, NUMOID(1234), PA));
    expect_found(set, 1, NUMOID(1234), 0, PA, "1234");
    expect_notfound(set, 1, NUMOID(1235), 0, "1235");
    expect_notfound(set, 1, NUMOID(1233), 0, "1233");
    expect_notfound(set, 2, NUMOID(1234), 0, "other encoding");
}
TEST(fset_numeric_oid_hash_form_equals_integer) {
    REQUIRE(U(CryptInstallOIDFunctionAddress)); REQUIRE(U(CryptGetOIDFunctionAddress));
    const char *fs = "cryptt_fw_num32"; HCRYPTOIDFUNCSET set = mkset(fs);
    CHECK(inst(set, fs, 1, 0, NUMOID(4321), PA));
    expect_found(set, 1, "#4321", 0, PA, "#4321");
    expect_found(set, 1, "#04321", 0, PA, "leading zero");
    expect_notfound(set, 1, "#4322", 0, "#4322");
}
TEST(fset_numeric_oid_hash_form_atol_semantics) {
    REQUIRE(U(CryptInstallOIDFunctionAddress)); REQUIRE(U(CryptGetOIDFunctionAddress));
    const char *fs = "cryptt_fw_num33"; HCRYPTOIDFUNCSET set = mkset(fs);
    CHECK(inst(set, fs, 1, 0, NUMOID(12), PA));
    expect_found(set, 1, "#12abc", 0, PA, "trailing garbage ignored");
    expect_found(set, 1, "#  12", 0, PA, "leading blanks skipped");
    expect_found(set, 1, "#+12", 0, PA, "plus sign");
}
TEST(fset_numeric_oid_hash_out_of_range_invalid_arg) {
    REQUIRE(U(CryptGetOIDFunctionAddress));
    HCRYPTOIDFUNCSET set = mkset("cryptt_fw_num34");
    static const char *bad[] = {"#65536", "#99999", "#4294967295", "#-1", "#-5", "#2147483647"};
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        void *fn = SENT1; HCRYPTOIDFUNCADDR h = SENT2;
        SET_ERR(0);
        BOOL r = getf(set, 1, bad[i], 0, &fn, &h);
        CHECKF(r == FALSE && GetLastError() == ERR_INVALIDARG && fn == NULL && h == NULL, "%s: r=%d err=0x%lx", bad[i], r, GetLastError());
    }
}
TEST(fset_numeric_oid_hash_max_valid_is_not_found) {
    REQUIRE(U(CryptGetOIDFunctionAddress));
    HCRYPTOIDFUNCSET set = mkset("cryptt_fw_num35");
    expect_notfound(set, 1, "#65535", 0, "#65535");
    expect_notfound(set, 1, "#0", 0, "#0");
    expect_notfound(set, 1, "#abc", 0, "#abc (atol 0)");
    expect_notfound(set, 1, "#", 0, "# alone");
}
TEST(fset_hash_string_installed_as_string_is_not_reachable_by_string) {
    REQUIRE(U(CryptInstallOIDFunctionAddress)); REQUIRE(U(CryptGetOIDFunctionAddress));
    const char *fs = "cryptt_fw_num36"; HCRYPTOIDFUNCSET set = mkset(fs);
    CHECK(inst(set, fs, 1, 0, "#36", PA));
    /* '#' strings are always interpreted as numeric OIDs on lookup */
    expect_notfound(set, 1, "#36", 0, "string #36 vs numeric 36");
    CHECK(inst(set, fs, 1, 0, NUMOID(36), PB));
    expect_found(set, 1, "#36", 0, PB, "numeric 36");
}
TEST(fset_numeric_consecutive_range) {
    REQUIRE(U(CryptInstallOIDFunctionAddress)); REQUIRE(U(CryptGetOIDFunctionAddress));
    const char *fs = "cryptt_fw_rng37"; HCRYPTOIDFUNCSET set = mkset(fs);
    void *fns[5] = {PA, PB, PC, PD, PE};
    CRYPT_OID_FUNC_ENTRY e[5];
    for (int i = 0; i < 5; i++) { e[i].pszOID = NUMOID(500 + i); e[i].pvFuncAddr = fns[i]; }
    CHECK(U(CryptInstallOIDFunctionAddress)(NULL, 1, fs, 5, e, 0));
    for (int i = 0; i < 5; i++) expect_found(set, 1, NUMOID(500 + i), 0, fns[i], "range member");
    expect_notfound(set, 1, NUMOID(499), 0, "below"); expect_notfound(set, 1, NUMOID(505), 0, "above");
    void *f; HCRYPTOIDFUNCADDR h1, h2;
    CHECK(getf(set, 1, NUMOID(500), 0, &f, &h1)); CHECK(getf(set, 1, NUMOID(504), 0, &f, &h2));
    CHECK(h1 == h2); /* one element covers the whole consecutive run */
}
TEST(fset_numeric_non_consecutive) {
    REQUIRE(U(CryptInstallOIDFunctionAddress)); REQUIRE(U(CryptGetOIDFunctionAddress));
    const char *fs = "cryptt_fw_rng38"; HCRYPTOIDFUNCSET set = mkset(fs);
    CRYPT_OID_FUNC_ENTRY e[4] = {{NUMOID(600), PA}, {NUMOID(601), PB}, {NUMOID(603), PC}, {NUMOID(604), PD}};
    CHECK(U(CryptInstallOIDFunctionAddress)(NULL, 1, fs, 4, e, 0));
    expect_found(set, 1, NUMOID(600), 0, PA, "600"); expect_found(set, 1, NUMOID(601), 0, PB, "601");
    expect_found(set, 1, NUMOID(603), 0, PC, "603"); expect_found(set, 1, NUMOID(604), 0, PD, "604");
    expect_notfound(set, 1, NUMOID(602), 0, "602 gap");
}
TEST(fset_numeric_mixed_with_strings) {
    REQUIRE(U(CryptInstallOIDFunctionAddress)); REQUIRE(U(CryptGetOIDFunctionAddress));
    const char *fs = "cryptt_fw_mix39"; HCRYPTOIDFUNCSET set = mkset(fs);
    CRYPT_OID_FUNC_ENTRY e[5] = {{NUMOID(10), PA}, {"s.one.39", PB}, {NUMOID(11), PC}, {NUMOID(12), PD}, {"s.two.39", PE}};
    CHECK(U(CryptInstallOIDFunctionAddress)(NULL, 1, fs, 5, e, 0));
    expect_found(set, 1, NUMOID(10), 0, PA, "10"); expect_found(set, 1, NUMOID(11), 0, PC, "11"); expect_found(set, 1, NUMOID(12), 0, PD, "12");
    expect_found(set, 1, "s.one.39", 0, PB, "s1"); expect_found(set, 1, "s.two.39", 0, PE, "s2");
}
TEST(fset_numeric_does_not_match_string_oids) {
    REQUIRE(U(CryptInstallOIDFunctionAddress)); REQUIRE(U(CryptGetOIDFunctionAddress));
    const char *fs = "cryptt_fw_num40"; HCRYPTOIDFUNCSET set = mkset(fs);
    CHECK(inst(set, fs, 1, 0, "40", PA));
    expect_notfound(set, 1, NUMOID(40), 0, "numeric 40 vs string \"40\"");
    expect_found(set, 1, "40", 0, PA, "string 40");
}
/* ---- handles ---- */
TEST(fset_free_handle_returns_true) {
    REQUIRE(U(CryptFreeOIDFunctionAddress));
    CHECK(U(CryptFreeOIDFunctionAddress)(NULL, 0) == TRUE);
    CHECK(U(CryptFreeOIDFunctionAddress)(NULL, 0xFFFFFFFF) == TRUE);
}
TEST(fset_free_installed_handle_repeatedly) {
    REQUIRE(U(CryptInstallOIDFunctionAddress)); REQUIRE(U(CryptGetOIDFunctionAddress));
    const char *fs = "cryptt_fw_free42"; HCRYPTOIDFUNCSET set = mkset(fs);
    CHECK(inst(set, fs, 1, 0, "fr.42", PA));
    void *f; HCRYPTOIDFUNCADDR h;
    CHECK(getf(set, 1, "fr.42", 0, &f, &h));
    for (int i = 0; i < 5; i++) CHECK(U(CryptFreeOIDFunctionAddress)(h, 0) == TRUE);
    expect_found(set, 1, "fr.42", 0, PA, "still installed after frees");
}
TEST(fset_free_preserves_last_error) {
    REQUIRE(U(CryptInstallOIDFunctionAddress)); REQUIRE(U(CryptGetOIDFunctionAddress));
    const char *fs = "cryptt_fw_free43"; HCRYPTOIDFUNCSET set = mkset(fs);
    CHECK(inst(set, fs, 1, 0, "fr.43", PA));
    void *f; HCRYPTOIDFUNCADDR h;
    CHECK(getf(set, 1, "fr.43", 0, &f, &h));
    BOOL (WINAPI *pfree)(HCRYPTOIDFUNCADDR, DWORD) = U(CryptFreeOIDFunctionAddress);
    SET_ERR(0x1234);
    pfree(h, 0);
    DWORD e = GetLastError();
    CHECKF(e == 0x1234, "last error 0x%lx", e);
}
TEST(fset_get_function_callable) {
    REQUIRE(U(CryptInstallOIDFunctionAddress)); REQUIRE(U(CryptGetOIDFunctionAddress));
    const char *fs = "cryptt_fw_call44"; HCRYPTOIDFUNCSET set = mkset(fs);
    CHECK(inst(set, fs, 1, 0, "call.44", PC));
    int (*fn)(void) = NULL; HCRYPTOIDFUNCADDR h = NULL;
    CHECK(getf(set, 1, "call.44", 0, (void **)&fn, &h));
    if (fn) CHECK(fn() == 0xC3);
    U(CryptFreeOIDFunctionAddress)(h, 0);
}

/* ---- DEFAULT entries ---- */
TEST(fset_default_entry_found_by_default_oid) {
    REQUIRE(U(CryptInstallOIDFunctionAddress)); REQUIRE(U(CryptGetOIDFunctionAddress));
    const char *fs = "cryptt_fw_def45"; HCRYPTOIDFUNCSET set = mkset(fs);
    CHECK(inst(set, fs, 1, 0, CRYPT_DEFAULT_OID, PA));
    expect_found(set, 1, CRYPT_DEFAULT_OID, 0, PA, "DEFAULT");
    expect_found(set, 1, "default", 0, PA, "default (case-insensitive)");
}
TEST(fset_default_entry_not_a_fallback_for_other_oids) {
    REQUIRE(U(CryptInstallOIDFunctionAddress)); REQUIRE(U(CryptGetOIDFunctionAddress));
    const char *fs = "cryptt_fw_def46"; HCRYPTOIDFUNCSET set = mkset(fs);
    CHECK(inst(set, fs, 1, 0, CRYPT_DEFAULT_OID, PA));
    expect_notfound(set, 1, "1.2.3.4.46", 0, "string oid");
    expect_notfound(set, 1, NUMOID(46), 0, "numeric oid");
}
TEST(fset_default_func_address_basic) {
    REQUIRE(U(CryptInstallOIDFunctionAddress)); REQUIRE(U(CryptGetDefaultOIDFunctionAddress));
    const char *fs = "cryptt_fw_def47"; HCRYPTOIDFUNCSET set = mkset(fs);
    CHECK(inst(set, fs, 1, 0, CRYPT_DEFAULT_OID, PA));
    void *f = SENT1; HCRYPTOIDFUNCADDR h = NULL;
    BOOL r = U(CryptGetDefaultOIDFunctionAddress)(set, 1, NULL, 0, &f, &h);
    CHECK(r == TRUE && f == PA && h != NULL);
    U(CryptFreeOIDFunctionAddress)(h, 0);
}
TEST(fset_default_func_address_wrong_encoding) {
    REQUIRE(U(CryptInstallOIDFunctionAddress)); REQUIRE(U(CryptGetDefaultOIDFunctionAddress));
    const char *fs = "cryptt_fw_def48"; HCRYPTOIDFUNCSET set = mkset(fs);
    CHECK(inst(set, fs, 1, 0, CRYPT_DEFAULT_OID, PA));
    void *f = SENT1; HCRYPTOIDFUNCADDR h = NULL;
    SET_ERR(0);
    BOOL r = U(CryptGetDefaultOIDFunctionAddress)(set, 2, NULL, 0, &f, &h);
    CHECK(r == FALSE); CHECK(GetLastError() == ERROR_FILE_NOT_FOUND); CHECK(f == NULL && h == NULL);
}
TEST(fset_default_func_address_none_installed) {
    REQUIRE(U(CryptGetDefaultOIDFunctionAddress));
    HCRYPTOIDFUNCSET set = mkset("cryptt_fw_def49");
    void *f = SENT1; HCRYPTOIDFUNCADDR h = NULL;
    SET_ERR(0);
    BOOL r = U(CryptGetDefaultOIDFunctionAddress)(set, 1, NULL, 0, &f, &h);
    CHECK(r == FALSE); CHECK(GetLastError() == ERROR_FILE_NOT_FOUND); CHECK(f == NULL && h == NULL);
}
TEST(fset_default_func_address_ignores_non_default_entries) {
    REQUIRE(U(CryptInstallOIDFunctionAddress)); REQUIRE(U(CryptGetDefaultOIDFunctionAddress));
    const char *fs = "cryptt_fw_def50"; HCRYPTOIDFUNCSET set = mkset(fs);
    CHECK(inst(set, fs, 1, 0, "1.2.3.50", PA));
    CHECK(inst(set, fs, 1, 0, NUMOID(50), PB));
    void *f = SENT1; HCRYPTOIDFUNCADDR h = NULL;
    CHECK(U(CryptGetDefaultOIDFunctionAddress)(set, 1, NULL, 0, &f, &h) == FALSE);
}
TEST(fset_default_func_address_iterates_in_install_order) {
    REQUIRE(U(CryptInstallOIDFunctionAddress)); REQUIRE(U(CryptGetDefaultOIDFunctionAddress));
    const char *fs = "cryptt_fw_def51"; HCRYPTOIDFUNCSET set = mkset(fs);
    CRYPT_OID_FUNC_ENTRY e[3] = {{CRYPT_DEFAULT_OID, PA}, {CRYPT_DEFAULT_OID, PB}, {CRYPT_DEFAULT_OID, PC}};
    CHECK(U(CryptInstallOIDFunctionAddress)(NULL, 1, fs, 3, e, 0));
    void *want[3] = {PA, PB, PC};
    HCRYPTOIDFUNCADDR h = NULL; void *f;
    for (int i = 0; i < 3; i++) {
        f = SENT1;
        BOOL r = U(CryptGetDefaultOIDFunctionAddress)(set, 1, NULL, 0, &f, &h);
        CHECKF(r && f == want[i] && h, "iteration %d: r=%d f=%p", i, r, f);
    }
    f = SENT1; SET_ERR(0);
    BOOL r = U(CryptGetDefaultOIDFunctionAddress)(set, 1, NULL, 0, &f, &h);
    CHECK(r == FALSE); CHECK(GetLastError() == ERROR_FILE_NOT_FOUND); CHECK(f == NULL && h == NULL);
}
TEST(fset_default_before_flag_order) {
    REQUIRE(U(CryptInstallOIDFunctionAddress)); REQUIRE(U(CryptGetDefaultOIDFunctionAddress));
    const char *fs = "cryptt_fw_def52"; HCRYPTOIDFUNCSET set = mkset(fs);
    CHECK(inst(set, fs, 1, 0, CRYPT_DEFAULT_OID, PA));
    CHECK(inst(set, fs, 1, CRYPT_INSTALL_OID_FUNC_BEFORE_FLAG, CRYPT_DEFAULT_OID, PB));
    CHECK(inst(set, fs, 1, 0, CRYPT_DEFAULT_OID, PC));
    CRYPT_OID_FUNC_ENTRY e[2] = {{CRYPT_DEFAULT_OID, PD}, {CRYPT_DEFAULT_OID, PE}};
    CHECK(U(CryptInstallOIDFunctionAddress)(NULL, 1, fs, 2, e, CRYPT_INSTALL_OID_FUNC_BEFORE_FLAG));
    void *want[5] = {PD, PE, PB, PA, PC}; /* a BEFORE batch keeps its internal order */
    HCRYPTOIDFUNCADDR h = NULL; void *f;
    for (int i = 0; i < 5; i++) {
        f = SENT1;
        BOOL r = U(CryptGetDefaultOIDFunctionAddress)(set, 1, NULL, 0, &f, &h);
        CHECKF(r && f == want[i], "position %d: r=%d f=%p", i, r, f);
    }
}
TEST(fset_default_entries_per_encoding) {
    REQUIRE(U(CryptInstallOIDFunctionAddress)); REQUIRE(U(CryptGetDefaultOIDFunctionAddress));
    const char *fs = "cryptt_fw_def53"; HCRYPTOIDFUNCSET set = mkset(fs);
    CHECK(inst(set, fs, 1, 0, CRYPT_DEFAULT_OID, PA));
    CHECK(inst(set, fs, 2, 0, CRYPT_DEFAULT_OID, PB));
    CHECK(inst(set, fs, 1, 0, CRYPT_DEFAULT_OID, PC));
    void *f = NULL; HCRYPTOIDFUNCADDR h = NULL;
    CHECK(U(CryptGetDefaultOIDFunctionAddress)(set, 2, NULL, 0, &f, &h) && f == PB);
    h = NULL;
    CHECK(U(CryptGetDefaultOIDFunctionAddress)(set, 1, NULL, 0, &f, &h) && f == PA);
    CHECK(U(CryptGetDefaultOIDFunctionAddress)(set, 1, NULL, 0, &f, &h) && f == PC);
    CHECK(U(CryptGetDefaultOIDFunctionAddress)(set, 1, NULL, 0, &f, &h) == FALSE);
}
TEST(fset_default_func_address_encoding_word_rules) {
    REQUIRE(U(CryptInstallOIDFunctionAddress)); REQUIRE(U(CryptGetDefaultOIDFunctionAddress));
    const char *fs = "cryptt_fw_def54"; HCRYPTOIDFUNCSET set = mkset(fs);
    CHECK(inst(set, fs, 1, 0, CRYPT_DEFAULT_OID, PA));
    void *f = NULL; HCRYPTOIDFUNCADDR h = NULL;
    CHECK(U(CryptGetDefaultOIDFunctionAddress)(set, 0x00010001, NULL, 0, &f, &h) && f == PA);
    h = NULL;
    CHECK(U(CryptGetDefaultOIDFunctionAddress)(set, 0x00010000, NULL, 0, &f, &h) && f == PA);
}

/* ---- CryptGetDefaultOIDDllList ---- */
TEST(fset_dll_list_unregistered_size_query) {
    REQUIRE(U(CryptGetDefaultOIDDllList));
    HCRYPTOIDFUNCSET set = mkset("cryptt_fw_dll55");
    DWORD cch = 0x77;
    BOOL r = U(CryptGetDefaultOIDDllList)(set, 1, NULL, &cch);
    CHECK(r == TRUE);
    CHECK(cch == 2); /* an empty multi-string: two terminating NULs */
}
TEST(fset_dll_list_unregistered_fill) {
    REQUIRE(U(CryptGetDefaultOIDDllList));
    HCRYPTOIDFUNCSET set = mkset("cryptt_fw_dll56");
    WCHAR buf[8]; for (int i = 0; i < 8; i++) buf[i] = 0x5a5a;
    DWORD cch = 8;
    BOOL r = U(CryptGetDefaultOIDDllList)(set, 1, buf, &cch);
    CHECK(r == TRUE); CHECK(cch == 2); CHECK(buf[0] == 0);
    CHECK(buf[2] == 0x5a5a); /* nothing written beyond the list */
}
TEST(fset_dll_list_exact_size_buffer) {
    REQUIRE(U(CryptGetDefaultOIDDllList));
    HCRYPTOIDFUNCSET set = mkset("cryptt_fw_dll57");
    WCHAR buf[2] = {0x5a5a, 0x5a5a}; DWORD cch = 2;
    CHECK(U(CryptGetDefaultOIDDllList)(set, 1, buf, &cch) == TRUE);
    CHECK(cch == 2 && buf[0] == 0);
}
TEST(fset_dll_list_buffer_too_small) {
    REQUIRE(U(CryptGetDefaultOIDDllList));
    HCRYPTOIDFUNCSET set = mkset("cryptt_fw_dll58");
    WCHAR buf[2] = {0x5a5a, 0x5a5a}; DWORD cch = 1;
    SET_ERR(0);
    BOOL r = U(CryptGetDefaultOIDDllList)(set, 1, buf, &cch);
    CHECK(r == FALSE); CHECK(GetLastError() == ERROR_MORE_DATA); CHECK(cch == 2);
    CHECK(buf[0] == 0x5a5a);
    cch = 0; SET_ERR(0);
    r = U(CryptGetDefaultOIDDllList)(set, 1, buf, &cch);
    CHECK(r == FALSE); CHECK(GetLastError() == ERROR_MORE_DATA); CHECK(cch == 2);
}
TEST(fset_dll_list_any_encoding_is_accepted) {
    REQUIRE(U(CryptGetDefaultOIDDllList));
    HCRYPTOIDFUNCSET set = mkset("cryptt_fw_dll59");
    static const DWORD enc[] = {0, 1, 2, 3, 0x10001, 0x10000, 0xFFFFFFFF};
    for (size_t i = 0; i < sizeof enc / sizeof enc[0]; i++) {
        DWORD cch = 0;
        CHECKF(U(CryptGetDefaultOIDDllList)(set, enc[i], NULL, &cch) && cch == 2, "enc 0x%lx", enc[i]);
    }
}

/* ---- CryptEnumOIDFunction (registry-backed) ---- */
#define REQ_ENUM() do { REQUIRE(U(CryptEnumOIDFunction)); if (t_is_wine()) { t_skip("CryptEnumOIDFunction aborts under wine"); return; } } while (0)
typedef struct { int calls; int bad; int ret; DWORD enc_filter; const char *func_filter; int vals; } EOF_ST;
static BOOL WINAPI enum_cb(DWORD enc, LPCSTR fn, LPCSTR oid, DWORD cValue, const DWORD *types, LPCWSTR const *names, const BYTE *const *data, const DWORD *cbs, void *arg) {
    EOF_ST *s = arg;
    s->calls++;
    if (s->enc_filter != 0xFFFFFFFF && enc != (s->enc_filter & 0xffff ? (s->enc_filter & 0xffff) : (s->enc_filter >> 16))) s->bad++;
    if (!fn || !oid) { s->bad++; return s->ret; }
    if (s->func_filter && lstrcmpiA(fn, s->func_filter)) s->bad++;
    /* every reported value must be readable back with CryptGetOIDFunctionValue */
    if (U(CryptGetOIDFunctionValue)) {
        for (DWORD i = 0; i < cValue; i++) {
            if (!names[i]) { s->bad++; continue; }
            BYTE buf[2048]; DWORD cb = sizeof buf, ty = 0xdead;
            BOOL ok = U(CryptGetOIDFunctionValue)(enc, fn, oid, names[i], &ty, buf, &cb);
            if (cbs[i] > sizeof buf) continue;
            if (!ok || ty != types[i] || cb != cbs[i] || (cb && memcmp(buf, data[i], cb))) s->bad++;
            s->vals++;
        }
    }
    return s->ret;
}
TEST(fsenum_unknown_function_no_callbacks) {
    REQ_ENUM();
    EOF_ST s = {0}; s.ret = TRUE; s.enc_filter = 0xFFFFFFFF;
    BOOL r = U(CryptEnumOIDFunction)(0xFFFFFFFF, "cryptt_fw_nosuchfunc", NULL, 0, &s, enum_cb);
    CHECK(r == TRUE); CHECK(s.calls == 0);
}
TEST(fsenum_unknown_function_x509) {
    REQ_ENUM();
    EOF_ST s = {0}; s.ret = TRUE; s.enc_filter = 1;
    BOOL r = U(CryptEnumOIDFunction)(X509_ASN_ENCODING, "cryptt_fw_nosuchfunc2", NULL, 0, &s, enum_cb);
    CHECK(r == TRUE); CHECK(s.calls == 0);
}
TEST(fsenum_unknown_function_with_oid) {
    REQ_ENUM();
    EOF_ST s = {0}; s.ret = TRUE; s.enc_filter = 1;
    BOOL r = U(CryptEnumOIDFunction)(X509_ASN_ENCODING, "cryptt_fw_nosuchfunc3", "1.2.3.4", 0, &s, enum_cb);
    CHECK(r == TRUE); CHECK(s.calls == 0);
    r = U(CryptEnumOIDFunction)(X509_ASN_ENCODING, "cryptt_fw_nosuchfunc3", NUMOID(7), 0, &s, enum_cb);
    CHECK(r == TRUE); CHECK(s.calls == 0);
}
TEST(fsenum_installed_functions_are_not_enumerated) {
    REQ_ENUM(); REQUIRE(U(CryptInstallOIDFunctionAddress));
    const char *fs = "cryptt_fw_enum60"; HCRYPTOIDFUNCSET set = mkset(fs);
    CHECK(inst(set, fs, 1, 0, "en.60", PA));
    EOF_ST s = {0}; s.ret = TRUE; s.enc_filter = 1;
    CHECK(U(CryptEnumOIDFunction)(1, fs, NULL, 0, &s, enum_cb) == TRUE);
    CHECK(s.calls == 0);
}
static const char *g_known_funcs[] = {"CryptDllEncodeObject", "CryptDllDecodeObject", "CryptDllEncodeObjectEx", "CryptDllDecodeObjectEx",
    "CryptDllFindOIDInfo", "CryptDllFindLocalizedName", "CertDllOpenStoreProv", "CertDllVerifyRevocation", "CryptDllExportPublicKeyInfoEx",
    "CryptDllImportPublicKeyInfoEx", "CryptDllCreateCOMObject", "CertDllVerifyCertificateChainPolicy", "CryptDllProtectData"};
TEST(fsenum_values_match_getvalue_x509) {
    REQ_ENUM(); REQUIRE(U(CryptGetOIDFunctionValue));
    int calls = 0;
    for (size_t i = 0; i < sizeof g_known_funcs / sizeof g_known_funcs[0]; i++) {
        EOF_ST s = {0}; s.ret = TRUE; s.enc_filter = 1; s.func_filter = g_known_funcs[i];
        BOOL r = U(CryptEnumOIDFunction)(X509_ASN_ENCODING, g_known_funcs[i], NULL, 0, &s, enum_cb);
        CHECKF(r == TRUE, "%s", g_known_funcs[i]);
        CHECKF(s.bad == 0, "%s: %d inconsistent reports", g_known_funcs[i], s.bad);
        calls += s.calls;
        if (s.calls) t_note("%s: %d registered OIDs, %d values", g_known_funcs[i], s.calls, s.vals);
    }
    t_note("total registered X509 function entries seen: %d", calls);
}
TEST(fsenum_all_encodings_consistent) {
    REQ_ENUM(); REQUIRE(U(CryptGetOIDFunctionValue));
    for (size_t i = 0; i < sizeof g_known_funcs / sizeof g_known_funcs[0]; i++) {
        EOF_ST s = {0}; s.ret = TRUE; s.enc_filter = 0xFFFFFFFF; s.func_filter = g_known_funcs[i];
        CHECKF(U(CryptEnumOIDFunction)(0xFFFFFFFF, g_known_funcs[i], NULL, 0, &s, enum_cb) == TRUE, "%s", g_known_funcs[i]);
        CHECKF(s.bad == 0, "%s: %d inconsistent", g_known_funcs[i], s.bad);
    }
}
TEST(fsenum_callback_result_is_ignored) {
    REQ_ENUM();
    for (size_t i = 0; i < sizeof g_known_funcs / sizeof g_known_funcs[0]; i++) {
        EOF_ST a = {0}, b = {0}; a.ret = TRUE; b.ret = FALSE; a.enc_filter = b.enc_filter = 0xFFFFFFFF;
        BOOL ra = U(CryptEnumOIDFunction)(0xFFFFFFFF, g_known_funcs[i], NULL, 0, &a, enum_cb);
        BOOL rb = U(CryptEnumOIDFunction)(0xFFFFFFFF, g_known_funcs[i], NULL, 0, &b, enum_cb);
        CHECKF(ra == TRUE && rb == TRUE && a.calls == b.calls, "%s: %d vs %d calls", g_known_funcs[i], a.calls, b.calls);
    }
}
TEST(fsenum_flags_are_ignored) {
    REQ_ENUM();
    EOF_ST a = {0}, b = {0}; a.ret = b.ret = TRUE; a.enc_filter = b.enc_filter = 0xFFFFFFFF;
    U(CryptEnumOIDFunction)(0xFFFFFFFF, "CryptDllEncodeObjectEx", NULL, 0, &a, enum_cb);
    U(CryptEnumOIDFunction)(0xFFFFFFFF, "CryptDllEncodeObjectEx", NULL, 0xF0F0F0F0, &b, enum_cb);
    CHECK(a.calls == b.calls);
}
TEST(fsenum_oid_filter_restricts_to_one_key) {
    REQ_ENUM();
    EOF_ST all = {0}; all.ret = TRUE; all.enc_filter = 0xFFFFFFFF;
    U(CryptEnumOIDFunction)(0xFFFFFFFF, "CryptDllEncodeObjectEx", NULL, 0, &all, enum_cb);
    EOF_ST one = {0}; one.ret = TRUE; one.enc_filter = 0xFFFFFFFF;
    U(CryptEnumOIDFunction)(0xFFFFFFFF, "CryptDllEncodeObjectEx", "cryptt-no-such-oid", 0, &one, enum_cb);
    CHECK(one.calls == 0);
    CHECK(one.bad == 0);
}
TEST(fsenum_encoding_filter_excludes_others) {
    REQ_ENUM();
    EOF_ST s = {0}; s.ret = TRUE; s.enc_filter = 7;
    BOOL r = U(CryptEnumOIDFunction)(7, "CryptDllEncodeObjectEx", NULL, 0, &s, enum_cb);
    CHECK(r == TRUE); CHECK(s.calls == 0);
}

/* ---- CryptGetOIDFunctionValue negative paths ---- */
TEST(fsvalue_missing_key_not_found) {
    REQUIRE(U(CryptGetOIDFunctionValue));
    BYTE buf[16]; DWORD cb = sizeof buf, ty = 0x55;
    SET_ERR(0);
    BOOL r = U(CryptGetOIDFunctionValue)(X509_ASN_ENCODING, "cryptt_fw_nosuchfunc4", "1.2.3.4", L"Dll", &ty, buf, &cb);
    CHECK(r == FALSE); CHECK(GetLastError() == ERROR_FILE_NOT_FOUND);
    CHECK(ty == 0); CHECK(cb == 0);
}
TEST(fsvalue_missing_key_null_out_params) {
    REQUIRE(U(CryptGetOIDFunctionValue));
    SET_ERR(0);
    BOOL r = U(CryptGetOIDFunctionValue)(X509_ASN_ENCODING, "cryptt_fw_nosuchfunc5", "1.2.3.4", L"Dll", NULL, NULL, NULL);
    CHECK(r == FALSE); CHECK(GetLastError() == ERROR_FILE_NOT_FOUND);
}
TEST(fsvalue_numeric_oid_missing) {
    REQUIRE(U(CryptGetOIDFunctionValue));
    BYTE buf[16]; DWORD cb = sizeof buf, ty = 0x55;
    SET_ERR(0);
    BOOL r = U(CryptGetOIDFunctionValue)(X509_ASN_ENCODING, "cryptt_fw_nosuchfunc6", NUMOID(77), L"Dll", &ty, buf, &cb);
    CHECK(r == FALSE); CHECK(GetLastError() == ERROR_FILE_NOT_FOUND); CHECK(ty == 0 && cb == 0);
}
struct pick { char fn[128], oid[128]; DWORD enc; int have; };
static BOOL WINAPI cb_pick(DWORD enc, LPCSTR fn, LPCSTR oid, DWORD cV, const DWORD *t, LPCWSTR const *n, const BYTE *const *d, const DWORD *c, void *arg) {
    struct pick *p = arg;
    if (!p->have) { strncpy(p->fn, fn, 127); strncpy(p->oid, oid, 127); p->enc = enc; p->have = 1; }
    return TRUE;
}
TEST(fsvalue_missing_value_name_in_existing_key_is_not_found) {
    REQUIRE(U(CryptGetOIDFunctionValue)); REQ_ENUM();
    /* find any registered OID key, then ask for a value name that cannot exist */
    struct pick pk = {0};
    static const char *cands[] = {"CryptDllEncodeObjectEx", "CryptDllDecodeObjectEx", "CryptDllEncodeObject", "CryptDllFindOIDInfo"};
    for (size_t i = 0; i < 4 && !pk.have; i++) U(CryptEnumOIDFunction)(0xFFFFFFFF, cands[i], NULL, 0, &pk, cb_pick);
    if (!pk.have) { t_skip("no registered function OIDs to probe"); return; }
    BYTE buf[16]; DWORD cb = sizeof buf, ty = 0x55;
    SET_ERR(0);
    BOOL r = U(CryptGetOIDFunctionValue)(pk.enc, pk.fn, pk.oid, L"cryptt_no_such_value", &ty, buf, &cb);
    CHECK(r == FALSE); CHECK(GetLastError() == ERROR_FILE_NOT_FOUND); CHECK(ty == 0 && cb == 0);
}
