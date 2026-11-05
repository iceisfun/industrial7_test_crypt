/* CryptSIPLoad, capability / info queries, registry-driven policy flags, mssip32 forwards. */
#include "sip_common.h"

static const struct { const GUID *g; const char *name; } k_builtin[] = {
    { &G_PE, "PE" }, { &G_CAB, "CAB" }, { &G_FLAT, "flat" }, { &G_CAT, "catalog" }, { &G_CTL, "ctl" },
};
#define NBUILTIN (sizeof k_builtin / sizeof *k_builtin)

TEST(sip_load_rejects_null_guid) {
    REQUIRE(U(CryptSIPLoad));
    SIP_DISPATCH_INFO d; memset(&d, 0xAA, sizeof d);
    SET_ERR(0);
    EXPECT_FAIL(!U(CryptSIPLoad)(NULL, 0, &d), ERROR_INVALID_PARAMETER);
}
TEST(sip_load_rejects_null_dispatch) {
    REQUIRE(U(CryptSIPLoad));
    SET_ERR(0);
    EXPECT_FAIL(!U(CryptSIPLoad)(&G_PE, 0, NULL), ERROR_INVALID_PARAMETER);
}
TEST(sip_load_rejects_nonzero_flags) {
    REQUIRE(U(CryptSIPLoad));
    static const DWORD flags[] = { 1, 2, 0x10, 0x8000, 0x80000000, 0xFFFFFFFF };
    for (unsigned i = 0; i < sizeof flags / sizeof *flags; i++) {
        SIP_DISPATCH_INFO d; memset(&d, 0xAA, sizeof d);
        SET_ERR(0);
        CHECKF(!U(CryptSIPLoad)(&G_PE, flags[i], &d), "flags 0x%lx", flags[i]);
        EXPECT_ERR(ERROR_INVALID_PARAMETER);
        CHECK(d.hSIP == (HANDLE)0xAAAAAAAAAAAAAAAAULL);
    }
}
TEST(sip_load_flags_checked_before_guid_lookup) {
    REQUIRE(U(CryptSIPLoad));
    SIP_DISPATCH_INFO d; memset(&d, 0, sizeof d);
    SET_ERR(0);
    CHECK(!U(CryptSIPLoad)(&G_UNKNOWN, 1, &d));
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
}
TEST(sip_load_unknown_guid) {
    REQUIRE(U(CryptSIPLoad));
    static const GUID *bad[] = { &G_UNKNOWN };
    GUID zero; memset(&zero, 0, sizeof zero);
    SIP_DISPATCH_INFO d; memset(&d, 0xAA, sizeof d);
    SET_ERR(0);
    CHECK(!U(CryptSIPLoad)(bad[0], 0, &d)); EXPECT_ERR(E_TRUST_SUBJECT_FORM_UNKNOWN);
    SET_ERR(0);
    CHECK(!U(CryptSIPLoad)(&zero, 0, &d)); EXPECT_ERR(E_TRUST_SUBJECT_FORM_UNKNOWN);
    CHECK(d.hSIP == (HANDLE)0xAAAAAAAAAAAAAAAAULL);          /* untouched on failure */
    CHECK(d.pfGet == (pCryptSIPGetSignedDataMsg)0xAAAAAAAAAAAAAAAAULL);
}
TEST(sip_load_builtin_subjects_succeed) {
    REQUIRE(U(CryptSIPLoad));
    for (unsigned i = 0; i < NBUILTIN; i++) {
        SIP_DISPATCH_INFO d; memset(&d, 0xAA, sizeof d);
        d.cbSize = 0x1234;
        SET_ERR(0xDEAD);
        BOOL r = U(CryptSIPLoad)(k_builtin[i].g, 0, &d);
        CHECKF(r == TRUE, "%s", k_builtin[i].name);
        if (!r) continue;
        CHECKF(d.hSIP == NULL, "%s", k_builtin[i].name);
        CHECKF(d.cbSize == 0x1234, "%s: cbSize is not written by CryptSIPLoad", k_builtin[i].name);
    }
}
TEST(sip_load_dispatch_points_into_crypt32) {
    REQUIRE(U(CryptSIPLoad));
    void *get = t_proc_in("crypt32.dll", "CryptSIPGetSignedDataMsg"), *put = t_proc_in("crypt32.dll", "CryptSIPPutSignedDataMsg");
    void *cre = t_proc_in("crypt32.dll", "CryptSIPCreateIndirectData"), *ver = t_proc_in("crypt32.dll", "CryptSIPVerifyIndirectData");
    void *rem = t_proc_in("crypt32.dll", "CryptSIPRemoveSignedDataMsg");
    for (unsigned i = 0; i < NBUILTIN; i++) {
        SIP_DISPATCH_INFO d; memset(&d, 0, sizeof d);
        if (!U(CryptSIPLoad)(k_builtin[i].g, 0, &d)) { CHECKF(0, "%s load", k_builtin[i].name); continue; }
        CHECKF((void *)d.pfGet == get, "%s", k_builtin[i].name);
        CHECKF((void *)d.pfPut == put, "%s", k_builtin[i].name);
        CHECKF((void *)d.pfCreate == cre, "%s", k_builtin[i].name);
        CHECKF((void *)d.pfVerify == ver, "%s", k_builtin[i].name);
        CHECKF((void *)d.pfRemove == rem, "%s", k_builtin[i].name);
    }
}
TEST(sip_load_dispatch_is_not_wintrusts_implementation) {
    REQUIRE(U(CryptSIPLoad));
    SIP_DISPATCH_INFO d; memset(&d, 0, sizeof d);
    CHECK(U(CryptSIPLoad)(&G_PE, 0, &d));
    CHECK((void *)d.pfGet != t_proc_in("wintrust.dll", "CryptSIPGetSignedDataMsg"));
    CHECK((void *)d.pfCreate != t_proc_in("wintrust.dll", "CryptSIPCreateIndirectData"));
}
TEST(sip_load_repeatable_and_independent_structs) {
    REQUIRE(U(CryptSIPLoad));
    SIP_DISPATCH_INFO a, b; memset(&a, 0, sizeof a); memset(&b, 0, sizeof b);
    CHECK(U(CryptSIPLoad)(&G_PE, 0, &a)); CHECK(U(CryptSIPLoad)(&G_CAB, 0, &b));
    CHECK(a.pfGet == b.pfGet && a.pfPut == b.pfPut && a.pfCreate == b.pfCreate);   /* same generic trampolines for every subject type */
    for (int i = 0; i < 50; i++) CHECK(U(CryptSIPLoad)(&G_PE, 0, &a));
}
TEST(sip_load_registered_third_party_sips_are_notes) {
    REQUIRE(U(CryptSIPLoad));
    t_note("registered: MSI=%d PowerShell=%d", sipt_sip_is_registered(&G_MSI), sipt_sip_is_registered(&G_PS));
}

/* ---- CryptSIPGetCaps ---- */
static void caps_init(SIPT_CAPS *c, DWORD cb) { memset(c, 0, sizeof *c); c->cbSize = cb; }

TEST(sip_caps_wintrust_parameter_validation) {
    REQUIRE(WT(CryptSIPGetCaps));
    SIP_SUBJECTINFO si; SIPT_CAPS c;
    sipt_subject(&si, &G_PE, NULL, NULL, OID_SHA1, 0);
    SET_ERR(0); caps_init(&c, 16);
    CHECK(!WT(CryptSIPGetCaps)(&si, NULL)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); caps_init(&c, 15);
    CHECK(!WT(CryptSIPGetCaps)(&si, &c)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); caps_init(&c, 0);
    CHECK(!WT(CryptSIPGetCaps)(&si, &c)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); caps_init(&c, 16); c.dwFlags = 1;                  /* reserved field must be zero on input */
    CHECK(!WT(CryptSIPGetCaps)(&si, &c)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); caps_init(&c, 16); si.cbSize = 0x57;
    CHECK(!WT(CryptSIPGetCaps)(&si, &c)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
}
TEST(sip_caps_pe_reports_sealing_and_multisign) {
    REQUIRE(WT(CryptSIPGetCaps));
    SIP_SUBJECTINFO si; SIPT_CAPS c;
    sipt_subject(&si, &G_PE, NULL, NULL, OID_SHA256, 0);
    caps_init(&c, 16); c.dwVersion = 0xDEAD; c.isMultiSign = 0xDEAD;
    CHECK(WT(CryptSIPGetCaps)(&si, &c) == TRUE);
    CHECK(c.cbSize == 16); CHECK(c.dwVersion == 3); CHECK(c.isMultiSign == 1); CHECK(c.dwFlags == 1);
}
TEST(sip_caps_pe_resets_cbsize_to_16) {
    REQUIRE(WT(CryptSIPGetCaps));
    SIP_SUBJECTINFO si; SIPT_CAPS big[2];
    sipt_subject(&si, &G_PE, NULL, NULL, OID_SHA1, 0);
    memset(big, 0, sizeof big); big[0].cbSize = sizeof big;
    CHECK(WT(CryptSIPGetCaps)(&si, &big[0]) == TRUE);
    CHECK(big[0].cbSize == 16);
}
TEST(sip_caps_other_subjects_use_base_caps) {
    REQUIRE(WT(CryptSIPGetCaps));
    for (unsigned i = 1; i < NBUILTIN; i++) {
        SIP_SUBJECTINFO si; SIPT_CAPS c;
        sipt_subject(&si, k_builtin[i].g, NULL, NULL, OID_SHA1, 0);
        caps_init(&c, 32); c.dwFlags = 0;
        BOOL r = WT(CryptSIPGetCaps)(&si, &c);
        CHECKF(r == TRUE, "%s", k_builtin[i].name);
        CHECKF(c.dwVersion == 3, "%s", k_builtin[i].name);
        CHECKF(c.isMultiSign == 1, "%s", k_builtin[i].name);
        CHECKF(c.dwFlags == 0, "%s: no sealing", k_builtin[i].name);
        CHECKF(c.cbSize == 32, "%s: base implementation leaves cbSize alone", k_builtin[i].name);
    }
}
TEST(sip_caps_wintrust_unknown_subject) {
    REQUIRE(WT(CryptSIPGetCaps));
    SIP_SUBJECTINFO si; SIPT_CAPS c;
    sipt_subject(&si, &G_UNKNOWN, NULL, NULL, OID_SHA1, 0);
    caps_init(&c, 16);
    SET_ERR(0);
    CHECK(!WT(CryptSIPGetCaps)(&si, &c));
    EXPECT_ERR(E_TRUST_SUBJECT_FORM_UNKNOWN);
}
TEST(sip_caps_crypt32_dispatch_validation) {
    REQUIRE(C32(CryptSIPGetCaps));
    SIP_SUBJECTINFO si; SIPT_CAPS c;
    caps_init(&c, 16);
    SET_ERR(0);
    CHECK(!C32(CryptSIPGetCaps)(NULL, &c)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    sipt_subject(&si, NULL, NULL, NULL, OID_SHA1, 0);
    SET_ERR(0);
    CHECK(!C32(CryptSIPGetCaps)(&si, &c)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    sipt_subject(&si, &G_UNKNOWN, NULL, NULL, OID_SHA1, 0);
    SET_ERR(0);
    CHECK(!C32(CryptSIPGetCaps)(&si, &c)); EXPECT_ERR(E_TRUST_SUBJECT_FORM_UNKNOWN);
}
TEST(sip_caps_crypt32_dispatch_matches_wintrust) {
    REQUIRE(C32(CryptSIPGetCaps)); REQUIRE(WT(CryptSIPGetCaps));
    for (unsigned i = 0; i < NBUILTIN; i++) {
        SIP_SUBJECTINFO si; SIPT_CAPS c1, c2;
        sipt_subject(&si, k_builtin[i].g, NULL, NULL, OID_SHA1, 0);
        caps_init(&c1, 16); caps_init(&c2, 16);
        SET_ERR(0);
        BOOL r1 = C32(CryptSIPGetCaps)(&si, &c1), r2 = WT(CryptSIPGetCaps)(&si, &c2);
        if (!r1 && GetLastError() == E_TRUST_SUBJECT_FORM_UNKNOWN) { t_note("%s: no CryptSIPDllGetCaps registration", k_builtin[i].name); continue; }
        CHECKF(r1 == r2, "%s", k_builtin[i].name);
        CHECKF(!memcmp(&c1, &c2, sizeof c1), "%s", k_builtin[i].name);
    }
}

/* ---- CryptSIPGetSealedDigest ---- */
TEST(sip_sealed_digest_parameter_validation) {
    REQUIRE(WT(CryptSIPGetSealedDigest));
    SIP_SUBJECTINFO si; BYTE sig[8] = {0}; BYTE out[64]; DWORD cb = sizeof out;
    sipt_subject(&si, &G_PE, NULL, NULL, OID_SHA256, 0);
    SET_ERR(0);
    CHECK(!WT(CryptSIPGetSealedDigest)(&si, sig, sizeof sig, out, NULL));
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
    (void)cb;
}
TEST(sip_sealed_digest_crypt32_dispatch_validation) {
    REQUIRE(C32(CryptSIPGetSealedDigest));
    SIP_SUBJECTINFO si; BYTE sig[8] = {0}; BYTE out[64]; DWORD cb = sizeof out;
    SET_ERR(0);
    CHECK(!C32(CryptSIPGetSealedDigest)(NULL, sig, sizeof sig, out, &cb)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    sipt_subject(&si, NULL, NULL, NULL, OID_SHA256, 0);
    SET_ERR(0);
    CHECK(!C32(CryptSIPGetSealedDigest)(&si, sig, sizeof sig, out, &cb)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    sipt_subject(&si, &G_UNKNOWN, NULL, NULL, OID_SHA256, 0);
    SET_ERR(0);
    CHECK(!C32(CryptSIPGetSealedDigest)(&si, sig, sizeof sig, out, &cb)); EXPECT_ERR(E_TRUST_SUBJECT_FORM_UNKNOWN);
}
TEST(sip_sealed_digest_garbage_signature_on_unsigned_pe) {
    /* Win10: no parsing of the signature is done; the call succeeds with a 32 byte value that depends on both the
       signature bytes and the file, and is deterministic. The exact value for this input is pinned. */
    REQUIRE(WT(CryptSIPGetSealedDigest));
    static const u8 want[32] = { 0x21,0x96,0xd3,0x91,0xde,0xfb,0xaf,0xe5,0xf6,0xff,0x25,0x69,0x8e,0x34,0x94,0x01,
                                 0x58,0x0d,0x95,0xff,0x5e,0x9a,0xbd,0x92,0xc6,0x9b,0x0f,0xab,0xa3,0x4b,0x24,0xc8 };
    char path[MAX_PATH]; WCHAR w[MAX_PATH]; SIP_SUBJECTINFO si; BYTE sig[32], out[64], out2[64]; DWORD cb = sizeof out, cb2 = sizeof out2;
    sipt_mkpe(path, sizeof path, "sealed.exe", 0); sipt_wide(w, MAX_PATH, path);
    sipt_subject(&si, &G_PE, NULL, w, OID_SHA256, 0);
    memset(sig, 0x11, sizeof sig);
    SET_ERR(0x1234);
    CHECK(WT(CryptSIPGetSealedDigest)(&si, sig, sizeof sig, out, &cb) == TRUE);
    EXPECT_EQ(cb, 32);
    CHECK(!memcmp(out, want, 32));
    CHECK(WT(CryptSIPGetSealedDigest)(&si, sig, sizeof sig, out2, &cb2) == TRUE);
    CHECK(cb2 == 32 && !memcmp(out, out2, 32));
    cb = 0;
    CHECK(WT(CryptSIPGetSealedDigest)(&si, sig, sizeof sig, NULL, &cb) == TRUE);   /* size query */
    EXPECT_EQ(cb, 32);
    sig[0] ^= 1; cb2 = sizeof out2;
    CHECK(WT(CryptSIPGetSealedDigest)(&si, sig, sizeof sig, out2, &cb2) == TRUE);
    CHECK(memcmp(out, out2, 32) != 0);
}

/* ---- CryptSIPGetInfo / GetRegWorkingFlags / mssip32 forwards ---- */
TEST(sip_info_lists_five_builtin_subject_types) {
    REQUIRE(WT(CryptSIPGetInfo));
    if (t_is_wine()) { t_skip("CryptSIPGetInfo is a stub that aborts under wine"); return; }
    SIPT_INFORMATION inf; memset(&inf, 0xAA, sizeof inf);
    CHECK(WT(CryptSIPGetInfo)(&inf) == TRUE);
    CHECK(inf.cbSize == 0x10);
    CHECK(inf.cGuids == 5);
    if (inf.cGuids == 5 && inf.pGuids) {
        CHECK(!memcmp(&inf.pGuids[0], &G_PE, 16));
        CHECK(!memcmp(&inf.pGuids[1], &G_CAB, 16));
        CHECK(!memcmp(&inf.pGuids[2], &G_FLAT, 16));
        CHECK(!memcmp(&inf.pGuids[3], &G_CAT, 16));
        CHECK(!memcmp(&inf.pGuids[4], &G_CTL, 16));
    }
}
TEST(sip_info_is_stable_across_calls) {
    REQUIRE(WT(CryptSIPGetInfo));
    if (t_is_wine()) { t_skip("CryptSIPGetInfo is a stub that aborts under wine"); return; }
    SIPT_INFORMATION a, b; memset(&a, 0, sizeof a); memset(&b, 0, sizeof b);
    CHECK(WT(CryptSIPGetInfo)(&a)); CHECK(WT(CryptSIPGetInfo)(&b));
    CHECK(a.pGuids == b.pGuids && a.cGuids == b.cGuids);
}
TEST(sip_mssip32_exports_forward_to_wintrust) {
    static const char *names[] = { "CryptSIPCreateIndirectData", "CryptSIPGetInfo", "CryptSIPGetRegWorkingFlags",
        "CryptSIPGetSignedDataMsg", "CryptSIPPutSignedDataMsg", "CryptSIPRemoveSignedDataMsg", "CryptSIPVerifyIndirectData" };
    if (!t_module("mssip32.dll")) { t_skip("mssip32.dll not available"); return; }
    for (unsigned i = 0; i < sizeof names / sizeof *names; i++) {
        FARPROC a = t_proc_in("mssip32.dll", names[i]), b = t_proc_in("wintrust.dll", names[i]);
        CHECKF(a != NULL, "mssip32!%s", names[i]);
        CHECKF(a == b, "mssip32!%s must resolve to wintrust!%s", names[i], names[i]);
    }
}
TEST(sip_wintrust_and_crypt32_exports_are_distinct_implementations) {
    static const char *names[] = { "CryptSIPCreateIndirectData", "CryptSIPGetSignedDataMsg", "CryptSIPPutSignedDataMsg",
        "CryptSIPRemoveSignedDataMsg", "CryptSIPVerifyIndirectData", "CryptSIPGetCaps", "CryptSIPGetSealedDigest" };
    for (unsigned i = 0; i < sizeof names / sizeof *names; i++) {
        FARPROC a = t_proc_in("crypt32.dll", names[i]), b = t_proc_in("wintrust.dll", names[i]);
        CHECKF(a && b, "%s present in both", names[i]);
        CHECKF(a != b, "%s", names[i]);
    }
}

/* ---- registry-driven working flags ---- */
static int read_state(DWORD *out)
{
    HKEY k; DWORD type = 0, cb = 4, v = 0; LONG r; int ok = 0;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\WinTrust\\Trust Providers\\Software Publishing", 0, KEY_READ, &k)) return 0;
    r = RegQueryValueExW(k, L"State", NULL, &type, (BYTE *)&v, &cb);
    if (r == ERROR_SUCCESS && (type == REG_DWORD || type == REG_BINARY)) { *out = v; ok = 1; }
    RegCloseKey(k);
    return ok;
}
TEST(sip_policy_flags_default_or_registry) {
    REQUIRE(WT(WintrustGetRegPolicyFlags));
    DWORD f = 0xDEADBEEF, st;
    WT(WintrustGetRegPolicyFlags)(&f);
    DWORD want = read_state(&st) ? st : 0x23c00;
    EXPECT_EQ(f, want);
    t_note("WintrustGetRegPolicyFlags = 0x%lx", f);
}
TEST(sip_policy_flags_overwrites_output_even_without_registry_value) {
    REQUIRE(WT(WintrustGetRegPolicyFlags));
    DWORD a = 0, b = 0xFFFFFFFF;
    WT(WintrustGetRegPolicyFlags)(&a); WT(WintrustGetRegPolicyFlags)(&b);
    EXPECT_EQ(a, b);
}
TEST(sip_working_flags_equal_policy_flags) {
    REQUIRE(WT(WintrustGetRegPolicyFlags)); REQUIRE(WT(CryptSIPGetRegWorkingFlags));
    if (t_is_wine()) { t_skip("CryptSIPGetRegWorkingFlags is a stub that aborts under wine"); return; }
    DWORD a = 1, b = 2;
    WT(WintrustGetRegPolicyFlags)(&a); WT(CryptSIPGetRegWorkingFlags)(&b);
    EXPECT_EQ(a, b);
    FARPROC m = t_proc_in("mssip32.dll", "CryptSIPGetRegWorkingFlags");
    if (m) { DWORD c = 3; ((void (WINAPI *)(DWORD *))m)(&c); EXPECT_EQ(c, a); }
}
TEST(sip_policy_flags_default_bits) {
    DWORD st;
    /* 0x23c00 is the built-in default; document which bits it carries */
    /* Win10 22H2 oracle: the HKCU State value is present and equals the default in both std and adm runs. */
    if (read_state(&st)) EXPECT_EQ(st, 0x23c00);
    REQUIRE(WT(WintrustGetRegPolicyFlags));
    DWORD f = 0; WT(WintrustGetRegPolicyFlags)(&f);
    EXPECT_EQ(f, 0x23c00);
    CHECK((f & 0x10000) == 0);            /* the bit that makes legacy (<2.0) SIP versions fail verification */
}

/* ---- IsCatalogFile ---- */
static void ifile(const char *leaf, const void *b, size_t n, char *path, size_t cap, WCHAR *w)
{
    t_tmpfile(path, cap, leaf);
    sipt_put(path, b, n);
    sipt_wide(w, MAX_PATH, path);
}
TEST(sip_iscatalog_null_name_and_handle) {
    REQUIRE(WT(IsCatalogFile));
    SET_ERR(0);
    CHECK(WT(IsCatalogFile)(NULL, NULL) == FALSE);
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0);
    CHECK(WT(IsCatalogFile)(INVALID_HANDLE_VALUE, NULL) == FALSE);
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
}
TEST(sip_iscatalog_missing_file) {
    REQUIRE(WT(IsCatalogFile));
    WCHAR w[MAX_PATH]; char p[MAX_PATH];
    t_tmpfile(p, sizeof p, "nothing.cat"); sipt_wide(w, MAX_PATH, p);
    SET_ERR(0);
    CHECK(WT(IsCatalogFile)(NULL, w) == FALSE);
    EXPECT_ERR(ERROR_FILE_NOT_FOUND);
}
TEST(sip_iscatalog_real_catalog_by_name_and_handle) {
    REQUIRE(WT(IsCatalogFile));
    u8 m[1024]; size_t n = sipt_make_ctl(m, sizeof m, OID_CATALOG_LIST);
    char p[MAX_PATH]; WCHAR w[MAX_PATH];
    if (!n) { t_skip("cannot build CTL message"); return; }
    ifile("real.cat", m, n, p, sizeof p, w);
    CHECK(WT(IsCatalogFile)(NULL, w) == TRUE);
    CHECK(WT(IsCatalogFile)(INVALID_HANDLE_VALUE, w) == TRUE);
    HANDLE h = sipt_open(p, GENERIC_READ);
    CHECK(WT(IsCatalogFile)(h, NULL) == TRUE);
    CHECK(WT(IsCatalogFile)(h, L"C:\\ignored\\name.txt") == TRUE);       /* handle wins, name ignored */
    CHECK(GetFileSize(h, NULL) == n);                                     /* handle left open */
    CloseHandle(h);
}
TEST(sip_iscatalog_extension_is_irrelevant) {
    REQUIRE(WT(IsCatalogFile));
    u8 m[1024]; size_t n = sipt_make_ctl(m, sizeof m, OID_CATALOG_LIST);
    char p[MAX_PATH]; WCHAR w[MAX_PATH];
    if (!n) { t_skip("cannot build CTL message"); return; }
    static const char *leaf[] = { "x.txt", "x", "x.exe" };
    for (unsigned i = 0; i < 3; i++) { ifile(leaf[i], m, n, p, sizeof p, w); CHECKF(WT(IsCatalogFile)(NULL, w) == TRUE, "%s", leaf[i]); }
}
TEST(sip_iscatalog_other_ctl_usage_is_not_a_catalog) {
    REQUIRE(WT(IsCatalogFile));
    u8 m[1024]; size_t n; char p[MAX_PATH]; WCHAR w[MAX_PATH];
    n = sipt_make_ctl(m, sizeof m, "1.3.6.1.4.1.311.10.3.1");
    if (!n) { t_skip("cannot build CTL message"); return; }
    ifile("other.ctl", m, n, p, sizeof p, w);
    CHECK(WT(IsCatalogFile)(NULL, w) == FALSE);
    n = sipt_make_ctl(m, sizeof m, NULL);
    if (n) { ifile("empty.ctl", m, n, p, sizeof p, w); CHECK(WT(IsCatalogFile)(NULL, w) == FALSE); }
}
TEST(sip_iscatalog_non_catalog_files) {
    REQUIRE(WT(IsCatalogFile));
    u8 b[4096]; char p[MAX_PATH]; WCHAR w[MAX_PATH];
    size_t n = sipi_pe(0, b, sizeof b);
    ifile("pe.exe", b, n, p, sizeof p, w);  CHECK(WT(IsCatalogFile)(NULL, w) == FALSE);
    n = sipi_cab(b, sizeof b);
    ifile("c.cab", b, n, p, sizeof p, w);   CHECK(WT(IsCatalogFile)(NULL, w) == FALSE);
    ifile("t.txt", "plain text", 10, p, sizeof p, w); CHECK(WT(IsCatalogFile)(NULL, w) == FALSE);
    static const u8 seq[] = { 0x30, 0x03, 0x02, 0x01, 0x05 };
    ifile("seq.cat", seq, sizeof seq, p, sizeof p, w); CHECK(WT(IsCatalogFile)(NULL, w) == FALSE);
}
TEST(sip_iscatalog_empty_file) {
    REQUIRE(WT(IsCatalogFile));
    char p[MAX_PATH]; WCHAR w[MAX_PATH];
    ifile("empty.cat", "", 0, p, sizeof p, w);
    CHECK(WT(IsCatalogFile)(NULL, w) == FALSE);              /* cannot map a zero-length file */
}
TEST(sip_iscatalog_truncated_catalog) {
    REQUIRE(WT(IsCatalogFile));
    u8 m[1024]; size_t n = sipt_make_ctl(m, sizeof m, OID_CATALOG_LIST);
    char p[MAX_PATH]; WCHAR w[MAX_PATH];
    if (!n) { t_skip("cannot build CTL message"); return; }
    ifile("trunc.cat", m, n - 1, p, sizeof p, w);
    CHECK(WT(IsCatalogFile)(NULL, w) == FALSE);
}
TEST(sip_iscatalog_sharing_modes) {
    REQUIRE(WT(IsCatalogFile));
    u8 m[1024]; size_t n = sipt_make_ctl(m, sizeof m, OID_CATALOG_LIST);
    char p[MAX_PATH]; WCHAR w[MAX_PATH];
    if (!n) { t_skip("cannot build CTL message"); return; }
    ifile("shared.cat", m, n, p, sizeof p, w);
    /* an existing reader that only shares READ does not conflict with a read-only open */
    HANDLE hr = CreateFileA(p, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    CHECK(WT(IsCatalogFile)(NULL, w) == TRUE);
    CloseHandle(hr);
    /* an existing writer needs FILE_SHARE_WRITE from the opener, which IsCatalogFile (read|delete) does not give */
    HANDLE hw = CreateFileA(p, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
    SET_ERR(0);
    CHECK(WT(IsCatalogFile)(NULL, w) == FALSE);
    EXPECT_ERR(ERROR_SHARING_VIOLATION);
    CloseHandle(hw);
    CHECK(WT(IsCatalogFile)(NULL, w) == TRUE);
}

/* ---- ComputeFirstPageHash ---- */
TEST(sip_firstpage_algorithm_names) {
    REQUIRE(WT(ComputeFirstPageHash));
    char p[MAX_PATH]; WCHAR w[MAX_PATH]; u8 out[64];
    sipt_mkpe(p, sizeof p, "fph.exe", 0); sipt_wide(w, MAX_PATH, p);
    CHECK(WT(ComputeFirstPageHash)(L"SHA1", w, NULL, 0) == 20);
    CHECK(WT(ComputeFirstPageHash)(L"SHA256", w, NULL, 0) == 32);
    CHECK(WT(ComputeFirstPageHash)(L"sha1", w, NULL, 0) == 0);        /* exact, case-sensitive match */
    CHECK(WT(ComputeFirstPageHash)(L"SHA384", w, NULL, 0) == 0);
    CHECK(WT(ComputeFirstPageHash)(L"SHA-256", w, NULL, 0) == 0);
    CHECK(WT(ComputeFirstPageHash)(L"MD5", w, NULL, 0) == 0);
    CHECK(WT(ComputeFirstPageHash)(L"", w, NULL, 0) == 0);
    CHECK(WT(ComputeFirstPageHash)(L"SHA1", w, out, 19) == 20);      /* wrong size: length is returned, nothing written */
    CHECK(WT(ComputeFirstPageHash)(L"SHA256", w, out, 20) == 32);
}
TEST(sip_firstpage_null_arguments) {
    REQUIRE(WT(ComputeFirstPageHash));
    WCHAR w[MAX_PATH]; char p[MAX_PATH]; u8 out[32];
    sipt_mkpe(p, sizeof p, "fph.exe", 0); sipt_wide(w, MAX_PATH, p);
    CHECK(WT(ComputeFirstPageHash)(NULL, w, out, 20) == 0);
    CHECK(WT(ComputeFirstPageHash)(L"SHA1", NULL, out, 20) == 0);
    CHECK(WT(ComputeFirstPageHash)(NULL, NULL, NULL, 0) == 0);
}
TEST(sip_firstpage_query_does_not_touch_file) {
    REQUIRE(WT(ComputeFirstPageHash));
    WCHAR w[MAX_PATH];
    sipt_wide(w, MAX_PATH, "C:\\no\\such\\file.exe");
    CHECK(WT(ComputeFirstPageHash)(L"SHA1", w, NULL, 0) == 20);       /* size query never opens the file */
    CHECK(WT(ComputeFirstPageHash)(L"SHA256", w, NULL, 123) == 32);
}
TEST(sip_firstpage_hash_of_hand_built_pe) {
    REQUIRE(WT(ComputeFirstPageHash));
    char p[MAX_PATH]; WCHAR w[MAX_PATH]; u8 a[32], b[32], c[20];
    sipt_mkpe(p, sizeof p, "fph.exe", 0); sipt_wide(w, MAX_PATH, p);
    memset(a, 0, sizeof a); memset(b, 0xEE, sizeof b);
    int r1 = WT(ComputeFirstPageHash)(L"SHA256", w, a, 32);
    int r2 = WT(ComputeFirstPageHash)(L"SHA256", w, b, 32);
    CHECK(r1 == 32); CHECK(r2 == 32);
    CHECK(!memcmp(a, b, 32));                                         /* deterministic */
    CHECK(WT(ComputeFirstPageHash)(L"SHA1", w, c, 20) == 20);
    t_note("first page hash (sha1 of image, variant 0) starts %02x%02x%02x%02x", c[0], c[1], c[2], c[3]);
}
TEST(sip_firstpage_unchanged_by_section_contents_and_checksum) {
    REQUIRE(WT(ComputeFirstPageHash));
    char p0[MAX_PATH], p3[MAX_PATH]; WCHAR w0[MAX_PATH], w3[MAX_PATH]; u8 a[32], b[32];
    sipt_mkpe(p0, sizeof p0, "f0.exe", 0); sipt_wide(w0, MAX_PATH, p0);
    sipt_mkpe(p3, sizeof p3, "f3.exe", 3); sipt_wide(w3, MAX_PATH, p3);
    CHECK(WT(ComputeFirstPageHash)(L"SHA256", w0, a, 32) == 32);
    CHECK(WT(ComputeFirstPageHash)(L"SHA256", w3, b, 32) == 32);
    CHECK(!memcmp(a, b, 32));           /* differs only by the checksum field, which is excluded */
}
TEST(sip_firstpage_non_pe_file_fails) {
    REQUIRE(WT(ComputeFirstPageHash));
    char p[MAX_PATH]; WCHAR w[MAX_PATH]; u8 out[32];
    ifile("t.txt", "this is not an image at all", 27, p, sizeof p, w);
    CHECK(WT(ComputeFirstPageHash)(L"SHA256", w, out, 32) == 0);
    t_tmpfile(p, sizeof p, "missing.exe"); sipt_wide(w, MAX_PATH, p);
    CHECK(WT(ComputeFirstPageHash)(L"SHA256", w, out, 32) == 0);
}

/* ---- GetAuthenticodeSha256Hash ---- */
#include "kats.h"
TEST(sip_authenticode256_known_answers) {
    REQUIRE(WT(GetAuthenticodeSha256Hash));
    static const u8 *kat[] = { kat_pe0_sha256, kat_pe1_sha256, kat_pe2_sha256, kat_pe3_sha256 };
    for (unsigned v = 0; v < SIPI_PE_NVARIANTS; v++) {
        char p[MAX_PATH]; WCHAR w[MAX_PATH]; u8 out[32];
        sipt_mkpe(p, sizeof p, "ac.exe", v); sipt_wide(w, MAX_PATH, p);
        HANDLE h = sipt_open(p, GENERIC_READ);
        memset(out, 0xEE, sizeof out);
        DWORD r = WT(GetAuthenticodeSha256Hash)(w, h, out);
        CHECKF(r == 0, "variant %u returned 0x%lx", v, r);
        CHECKF(!memcmp(out, kat[v], 32), "variant %u digest", v);
        CloseHandle(h);
    }
}
TEST(sip_authenticode256_handle_survives_and_name_is_informational) {
    REQUIRE(WT(GetAuthenticodeSha256Hash));
    char p[MAX_PATH]; u8 out[32];
    sipt_mkpe(p, sizeof p, "ac.exe", 0);
    HANDLE h = sipt_open(p, GENERIC_READ);
    WCHAR other[] = L"C:\\other\\name.exe";
    DWORD r = WT(GetAuthenticodeSha256Hash)(other, h, out);
    CHECK(r == 0);
    CHECK(!memcmp(out, kat_pe0_sha256, 32));
    DWORD sz = GetFileSize(h, NULL);
    CHECK(sz == 0x400);
    CloseHandle(h);
}
TEST(sip_authenticode256_repeatable) {
    REQUIRE(WT(GetAuthenticodeSha256Hash));
    char p[MAX_PATH]; WCHAR w[MAX_PATH]; u8 a[32], b[32];
    sipt_mkpe(p, sizeof p, "ac.exe", 2); sipt_wide(w, MAX_PATH, p);
    HANDLE h = sipt_open(p, GENERIC_READ);
    CHECK(WT(GetAuthenticodeSha256Hash)(w, h, a) == 0);
    CHECK(WT(GetAuthenticodeSha256Hash)(w, h, b) == 0);
    CHECK(!memcmp(a, b, 32));
    CloseHandle(h);
}
