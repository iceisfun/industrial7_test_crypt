#include "wcfg.h"
/* WintrustSetRegPolicyFlags / WintrustGetRegPolicyFlags: HKCU\Software\Microsoft\Windows\CurrentVersion\WinTrust\
 * Trust Providers\Software Publishing, value "State".  The original value (or its absence) is restored. */

#define DEFAULT_FLAGS 0x23C00u
#define PSETUP(fn) REQUIRE(U(fn)); REQUIRE(U(WintrustGetRegPolicyFlags)); REQUIRE(U(WintrustSetRegPolicyFlags)); wcfg_state_save()

static DWORD getf(void) { DWORD f = 0xCCCCCCCC; U(WintrustGetRegPolicyFlags)(&f); return f; }

TEST(wcfg_policy_default_when_value_absent) {
    PSETUP(WintrustGetRegPolicyFlags);
    wcfg_state_delete();
    EXPECT_EQ(getf(), DEFAULT_FLAGS);
    wcfg_end();
}
TEST(wcfg_policy_get_overwrites_output_even_when_untouched) {
    PSETUP(WintrustGetRegPolicyFlags);
    wcfg_state_delete();
    DWORD f = 0x11111111; U(WintrustGetRegPolicyFlags)(&f);
    EXPECT_EQ(f, DEFAULT_FLAGS);
    wcfg_end();
}
TEST(wcfg_policy_set_get_roundtrip) {
    PSETUP(WintrustSetRegPolicyFlags);
    static const DWORD vals[] = { 0, 1, 2, 0x20, 0x40, 0x80, 0xFF, 0x100, 0x400, 0x800, 0x1000, 0x10000, 0x23C00, 0x7FFFFFFF,
        0x80000000, 0xFFFFFFFF, 0xDEADBEEF, 0x12345678, 0x00020000, 0x00000C00 };
    for (unsigned i = 0; i < sizeof vals / sizeof vals[0]; i++) {
        SET_ERR(0xdead);
        BOOL r = U(WintrustSetRegPolicyFlags)(vals[i]);
        CHECKF(r == TRUE, "set 0x%lx", vals[i]);
        DWORD g = getf();
        CHECKF(g == vals[i], "set 0x%lx get 0x%lx", vals[i], g);
    }
    wcfg_end();
}
TEST(wcfg_policy_set_writes_reg_dword_exact) {
    PSETUP(WintrustSetRegPolicyFlags);
    CHECK(U(WintrustSetRegPolicyFlags)(0xA1B2C3D4));
    DWORD t = 0, cb = 16; BYTE b[16] = { 0 };
    CHECK(wcfg_state_raw(&t, b, &cb));
    EXPECT_EQ(t, REG_DWORD); EXPECT_EQ(cb, 4);
    CHECK(*(DWORD *)b == 0xA1B2C3D4);
    wcfg_end();
}
TEST(wcfg_policy_set_creates_key_when_absent) {
    PSETUP(WintrustSetRegPolicyFlags);
    wcfg_state_delete();
    CHECK(U(WintrustSetRegPolicyFlags)(0x55));
    DWORD t, cb = 8; BYTE b[8];
    CHECK(wcfg_state_raw(&t, b, &cb));
    EXPECT_EQ(getf(), 0x55);
    wcfg_end();
}
TEST(wcfg_policy_set_replaces_other_value_types) {
    PSETUP(WintrustSetRegPolicyFlags);
    wchar_t s[] = L"abc"; wcfg_state_put(REG_SZ, s, sizeof s);
    CHECK(U(WintrustSetRegPolicyFlags)(0x77));
    DWORD t = 0, cb = 8; BYTE b[8];
    CHECK(wcfg_state_raw(&t, b, &cb)); EXPECT_EQ(t, REG_DWORD); EXPECT_EQ(cb, 4);
    wcfg_end();
}
TEST(wcfg_policy_set_zero_is_not_default) {
    PSETUP(WintrustSetRegPolicyFlags);
    CHECK(U(WintrustSetRegPolicyFlags)(0));
    EXPECT_EQ(getf(), 0);
    wcfg_state_delete();
    EXPECT_EQ(getf(), DEFAULT_FLAGS);
    wcfg_end();
}
TEST(wcfg_policy_get_accepts_reg_binary_4) {
    PSETUP(WintrustGetRegPolicyFlags);
    DWORD v = 0x0BADF00D; wcfg_state_put(REG_BINARY, &v, 4);
    EXPECT_EQ(getf(), v);
    wcfg_end();
}
TEST(wcfg_policy_get_short_binary_zero_extends) {
    PSETUP(WintrustGetRegPolicyFlags);
    BYTE v[2] = { 0x34, 0x12 }; wcfg_state_put(REG_BINARY, v, 2);
    EXPECT_EQ(getf(), 0x1234);
    BYTE one = 0x7F; wcfg_state_put(REG_BINARY, &one, 1);
    EXPECT_EQ(getf(), 0x7F);
    wcfg_end();
}
TEST(wcfg_policy_get_empty_binary_gives_zero) {
    PSETUP(WintrustGetRegPolicyFlags);
    wcfg_state_put(REG_BINARY, "", 0);
    EXPECT_EQ(getf(), 0);
    wcfg_end();
}
TEST(wcfg_policy_get_oversized_binary_keeps_default) {
    PSETUP(WintrustGetRegPolicyFlags);
    BYTE v[8] = { 1, 2, 3, 4, 5, 6, 7, 8 }; wcfg_state_put(REG_BINARY, v, 8);
    EXPECT_EQ(getf(), DEFAULT_FLAGS);
    wcfg_end();
}
TEST(wcfg_policy_get_ignores_unsupported_types) {
    PSETUP(WintrustGetRegPolicyFlags);
    DWORD v = 0x4242;
    wchar_t s[] = L"1234";
    wcfg_state_put(REG_SZ, s, sizeof s);          EXPECT_EQ(getf(), DEFAULT_FLAGS);
    wcfg_state_put(REG_EXPAND_SZ, s, sizeof s);   EXPECT_EQ(getf(), DEFAULT_FLAGS);
    if (!t_is_wine()) {
        wcfg_state_put(REG_DWORD_BIG_ENDIAN, &v, 4);  EXPECT_EQ(getf(), DEFAULT_FLAGS);
        wcfg_state_put(REG_NONE, &v, 4);              EXPECT_EQ(getf(), DEFAULT_FLAGS);
    }
    ULONGLONG q = 0x4242; wcfg_state_put(REG_QWORD, &q, 8); EXPECT_EQ(getf(), DEFAULT_FLAGS);
    wcfg_state_put(REG_MULTI_SZ, s, sizeof s);    EXPECT_EQ(getf(), DEFAULT_FLAGS);
    wcfg_state_put(REG_DWORD, &v, 4);             EXPECT_EQ(getf(), v);
    wcfg_end();
}
TEST(wcfg_policy_get_reads_each_time) {
    PSETUP(WintrustGetRegPolicyFlags);
    DWORD a = 0x11, b = 0x22;
    wcfg_state_put(REG_DWORD, &a, 4); EXPECT_EQ(getf(), a);
    wcfg_state_put(REG_DWORD, &b, 4); EXPECT_EQ(getf(), b);
    wcfg_end();
}
TEST(wcfg_policy_set_visible_in_child_process) {
    PSETUP(WintrustSetRegPolicyFlags);
    CHECK(U(WintrustSetRegPolicyFlags)(0x31337));
    EXPECT_EQ(t_run_child("wcfg_policy_child", "", 20000), 0);
    wcfg_end();
}
CHILD(wcfg_policy_child) {
    DWORD f = 0;
    if (!U(WintrustGetRegPolicyFlags)) return 90;
    U(WintrustGetRegPolicyFlags)(&f);
    return f == 0x31337 ? 0 : 1;
}
TEST(wcfg_policy_restore_leaves_original_state) {
    PSETUP(WintrustSetRegPolicyFlags);
    DWORD t0 = 0, cb0 = 16, t1 = 0, cb1 = 16; BYTE b0[16] = { 0 }, b1[16] = { 0 };
    int p0 = wcfg_state_raw(&t0, b0, &cb0);
    CHECK(U(WintrustSetRegPolicyFlags)(0xABCDEF));
    wcfg_state_restore();
    int p1 = wcfg_state_raw(&t1, b1, &cb1);
    CHECK(p0 == p1);
    if (p0 && p1) { CHECK(t0 == t1 && cb0 == cb1 && !memcmp(b0, b1, cb0)); }
    wcfg_end();
}

/* ------------------------------------------------------------------ WintrustSetDefaultIncludePEPageHashes */
/* No getter exists; the flag only influences PE indirect data creation.  The calls must be accepted and be
 * repeatable; the effect is recorded as an observation. */
static DWORD pe_indirect_size(HANDLE hf, const wchar_t *path, DWORD flags) {
    static const GUID pe = { 0xC689AAB8, 0x8E78, 0x11D0, { 0x8C, 0x47, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE } };
    SIP_SUBJECTINFO si; memset(&si, 0, sizeof si);
    GUID g = pe;
    si.cbSize = sizeof si; si.pgSubjectType = &g; si.hFile = hf; si.pwsFileName = path;
    si.DigestAlgorithm.pszObjId = (LPSTR)szOID_OIWSEC_sha1; si.dwFlags = flags;
    si.dwEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
    DWORD cb = 0;
    if (!U(CryptSIPCreateIndirectData)(&si, &cb, NULL)) return 0;
    return cb;
}
TEST(wcfg_policy_pe_page_hashes_calls_accepted) {
    REQUIRE(U(WintrustSetDefaultIncludePEPageHashes));
    U(WintrustSetDefaultIncludePEPageHashes)(TRUE);
    U(WintrustSetDefaultIncludePEPageHashes)(FALSE);
    U(WintrustSetDefaultIncludePEPageHashes)(2);
    U(WintrustSetDefaultIncludePEPageHashes)(0);
    CHECK(1);
}
TEST(wcfg_policy_pe_page_hashes_effect_on_indirect_data) {
    REQUIRE(U(WintrustSetDefaultIncludePEPageHashes)); REQUIRE(U(CryptSIPCreateIndirectData));
    wchar_t p[MAX_PATH]; wcfg_selfpath(p, MAX_PATH);
    HANDLE h = CreateFileW(p, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    CHECK(h != INVALID_HANDLE_VALUE);
    if (h == INVALID_HANDLE_VALUE) return;
    U(WintrustSetDefaultIncludePEPageHashes)(FALSE);
    DWORD off = pe_indirect_size(h, p, 0);
    U(WintrustSetDefaultIncludePEPageHashes)(TRUE);
    DWORD on = pe_indirect_size(h, p, 0);
    DWORD forced = pe_indirect_size(h, p, 0x100 /* SPC_INC_PE_PAGE_HASHES_FLAG */);
    U(WintrustSetDefaultIncludePEPageHashes)(FALSE);
    DWORD off2 = pe_indirect_size(h, p, 0);
    CloseHandle(h);
    CHECK(off != 0); CHECK(on != 0);
    CHECK(off == off2);
    t_note("PE indirect data size: default-off %lu, default-on %lu, flag %lu", off, on, forced);
}
