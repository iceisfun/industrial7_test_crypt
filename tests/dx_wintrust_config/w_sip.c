#include "wcfg.h"
/* CryptSIPAddProvider / CryptSIPRemoveProvider / CryptSIPLoad / dispatch / CryptSIPRetrieveSubjectGuid.
 * A SIP is registered as OID functions (encoding 0) in function sets CryptSIPDll* keyed by the subject GUID.
 * The SIP callbacks are exports of this exe (cryptt_Sip*). */

#define SSETUP(fn) REQUIRE(U(CryptSIPAddProvider)); REQUIRE(U(CryptSIPRemoveProvider)); REQUIRE(U(fn)); \
    if (t_is_wine()) { t_skip("emulator registry layout differs"); return; } \
    if (!wcfg_begin_oid()) return
UDECL(BOOL, CryptSIPGetCaps, (SIP_SUBJECTINFO *, void *));
#define C32CAPS ((CryptSIPGetCaps_pfn)t_proc_in("crypt32.dll", "CryptSIPGetCaps"))
enum { FS_GET, FS_PUT, FS_CREATE, FS_VERIFY, FS_REMOVE, FS_IS, FS_IS2, FS_CAPS };

static BOOL addp(SIP_ADD_NEWPROVIDER_EX *a) { return U(CryptSIPAddProvider)((SIP_ADD_NEWPROVIDER *)a); }
static BOOL remp(const GUID *g) { return U(CryptSIPRemoveProvider)((GUID *)g); }
static int nregistered(const GUID *g) { int n = 0; for (int s = 0; s < 8; s++) n += wcfg_sip_key_present(s, g, NULL, NULL); return n; }

TEST(wcfg_sip_struct_layout) {
    CHECK(sizeof(SIP_ADD_NEWPROVIDER) == 0x58);
    CHECK(offsetof(SIP_ADD_NEWPROVIDER, pwszIsFunctionNameFmt2) == 0x50);
    CHECK(offsetof(SIP_ADD_NEWPROVIDER, pwszRemoveFuncName) == 0x48);
    CHECK(sizeof(SIP_DISPATCH_INFO) == 0x38);
}

/* each function set receives its own function name; Dll is the dll file name */
#define SET_TEST(S, NAME, ID) TEST(wcfg_sip_add_registers_##NAME) { \
    SSETUP(CryptSIPAddProvider); GUID g; wcfg_guid(&g, 400); wchar_t dll[MAX_PATH]; wcfg_selfpath(dll, MAX_PATH); \
    SIP_ADD_NEWPROVIDER_EX a; wcfg_sip_fill(&a, &g, dll); SET_ERR(0); \
    CHECK(addp(&a)); wchar_t d[300], f[300]; \
    CHECK(wcfg_sip_key_present(S, &g, d, f)); CHECK(!wcscmp(d, dll)); CHECK(!wcscmp(f, wcfg_sip_wnames[ID])); \
    CHECK(remp(&g)); CHECK(!wcfg_sip_key_present(S, &g, NULL, NULL)); wcfg_end(); }
SET_TEST(FS_GET, get, SC_GET)
SET_TEST(FS_PUT, put, SC_PUT)
SET_TEST(FS_CREATE, create, SC_CREATE)
SET_TEST(FS_VERIFY, verify, SC_VERIFY)
SET_TEST(FS_REMOVE, remove, SC_REMOVE)
SET_TEST(FS_IS, is_my_file_type, SC_IS)
SET_TEST(FS_IS2, is_my_file_type2, SC_IS2)
SET_TEST(FS_CAPS, get_caps, SC_CAPS)

TEST(wcfg_sip_add_value_types_are_reg_sz) {
    SSETUP(CryptSIPAddProvider); GUID g; wcfg_guid(&g, 401); wchar_t dll[MAX_PATH]; wcfg_selfpath(dll, MAX_PATH);
    SIP_ADD_NEWPROVIDER_EX a; wcfg_sip_fill(&a, &g, dll);
    CHECK(addp(&a));
    wchar_t gs[48], p[400], b[300]; DWORD t, cb; wcfg_guid_str(&g, gs);
    swprintf(p, 400, L"SOFTWARE\\Microsoft\\Cryptography\\OID\\EncodingType 0\\CryptSIPDllPutSignedDataMsg\\%ls", gs);
    EXPECT_EQ(wcfg_get_str(p, L"Dll", b, 300, &t, &cb), 0); EXPECT_EQ(t, REG_SZ);
    EXPECT_EQ(wcfg_get_str(p, L"FuncName", b, 300, &t, &cb), 0); EXPECT_EQ(t, REG_SZ);
    wcfg_end();
}
TEST(wcfg_sip_add_full_struct_registers_eight_sets) {
    SSETUP(CryptSIPAddProvider); GUID g; wcfg_guid(&g, 402); wchar_t dll[MAX_PATH]; wcfg_selfpath(dll, MAX_PATH);
    SIP_ADD_NEWPROVIDER_EX a; wcfg_sip_fill(&a, &g, dll);
    EXPECT_EQ(nregistered(&g), 0);
    CHECK(addp(&a));
    EXPECT_EQ(nregistered(&g), 8);
    wcfg_end();
}
TEST(wcfg_sip_add_base_size_registers_six_sets) {
    SSETUP(CryptSIPAddProvider); GUID g; wcfg_guid(&g, 403); wchar_t dll[MAX_PATH]; wcfg_selfpath(dll, MAX_PATH);
    SIP_ADD_NEWPROVIDER_EX a; wcfg_sip_fill(&a, &g, dll); a.cbStruct = SIP_ADD_BASE_SIZE;
    CHECK(addp(&a));
    EXPECT_EQ(nregistered(&g), 6);                      /* get put create verify remove IsMyFileType */
    CHECK(wcfg_sip_key_present(FS_IS, &g, NULL, NULL));
    CHECK(!wcfg_sip_key_present(FS_IS2, &g, NULL, NULL));
    CHECK(!wcfg_sip_key_present(FS_CAPS, &g, NULL, NULL));
    wcfg_end();
}
TEST(wcfg_sip_add_fmt2_size_registers_is2_not_caps) {
    SSETUP(CryptSIPAddProvider); GUID g; wcfg_guid(&g, 404); wchar_t dll[MAX_PATH]; wcfg_selfpath(dll, MAX_PATH);
    SIP_ADD_NEWPROVIDER_EX a; wcfg_sip_fill(&a, &g, dll); a.cbStruct = SIP_ADD_FMT2_SIZE;
    CHECK(addp(&a));
    CHECK(wcfg_sip_key_present(FS_IS2, &g, NULL, NULL));
    CHECK(!wcfg_sip_key_present(FS_CAPS, &g, NULL, NULL));
    wcfg_end();
}
TEST(wcfg_sip_add_cbstruct_57_skips_fmt2) {
    SSETUP(CryptSIPAddProvider); GUID g; wcfg_guid(&g, 405); wchar_t dll[MAX_PATH]; wcfg_selfpath(dll, MAX_PATH);
    SIP_ADD_NEWPROVIDER_EX a; wcfg_sip_fill(&a, &g, dll); a.cbStruct = 0x57;
    CHECK(addp(&a));
    CHECK(!wcfg_sip_key_present(FS_IS2, &g, NULL, NULL));
    wcfg_end();
}
TEST(wcfg_sip_add_cbstruct_5f_skips_caps) {
    SSETUP(CryptSIPAddProvider); GUID g; wcfg_guid(&g, 406); wchar_t dll[MAX_PATH]; wcfg_selfpath(dll, MAX_PATH);
    SIP_ADD_NEWPROVIDER_EX a; wcfg_sip_fill(&a, &g, dll); a.cbStruct = 0x5F;
    CHECK(addp(&a));
    CHECK(wcfg_sip_key_present(FS_IS2, &g, NULL, NULL));
    CHECK(!wcfg_sip_key_present(FS_CAPS, &g, NULL, NULL));
    wcfg_end();
}
TEST(wcfg_sip_add_optional_names_null_are_skipped) {
    SSETUP(CryptSIPAddProvider); GUID g; wcfg_guid(&g, 407); wchar_t dll[MAX_PATH]; wcfg_selfpath(dll, MAX_PATH);
    SIP_ADD_NEWPROVIDER_EX a; wcfg_sip_fill(&a, &g, dll);
    a.pwszIsFunctionName = NULL; a.pwszIsFunctionNameFmt2 = NULL; a.pwszGetCapFuncName = NULL; a.pwszMagicNumber = NULL;
    CHECK(addp(&a));
    EXPECT_EQ(nregistered(&g), 5);
    wcfg_end();
}
TEST(wcfg_sip_add_cbstruct_below_50_fails) {
    SSETUP(CryptSIPAddProvider); GUID g; wcfg_guid(&g, 408); wchar_t dll[MAX_PATH]; wcfg_selfpath(dll, MAX_PATH);
    SIP_ADD_NEWPROVIDER_EX a; wcfg_sip_fill(&a, &g, dll);
    static const DWORD bad[] = { 0, 4, 0x20, 0x48, 0x4F };
    for (unsigned i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        a.cbStruct = bad[i]; SET_ERR(0);
        CHECKF(!addp(&a), "cbStruct 0x%lx", bad[i]); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    }
    EXPECT_EQ(nregistered(&g), 0);
    wcfg_end();
}
TEST(wcfg_sip_add_null_struct_fails) {
    SSETUP(CryptSIPAddProvider);
    SET_ERR(0); CHECK(!U(CryptSIPAddProvider)(NULL)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    wcfg_end();
}
/* mandatory members: dll, get, put, create, verify, remove */
#define REQ_TEST(FIELD) TEST(wcfg_sip_add_requires_##FIELD) { \
    SSETUP(CryptSIPAddProvider); GUID g; wcfg_guid(&g, 410); wchar_t dll[MAX_PATH]; wcfg_selfpath(dll, MAX_PATH); \
    SIP_ADD_NEWPROVIDER_EX a; wcfg_sip_fill(&a, &g, dll); a.FIELD = NULL; SET_ERR(0); \
    CHECK(!addp(&a)); EXPECT_ERR(ERROR_INVALID_PARAMETER); EXPECT_EQ(nregistered(&g), 0); wcfg_end(); }
REQ_TEST(pwszDLLFileName)
REQ_TEST(pwszGetFuncName)
REQ_TEST(pwszPutFuncName)
REQ_TEST(pwszCreateFuncName)
REQ_TEST(pwszVerifyFuncName)
REQ_TEST(pwszRemoveFuncName)
TEST(wcfg_sip_add_twice_overwrites) {
    SSETUP(CryptSIPAddProvider); GUID g; wcfg_guid(&g, 411); wchar_t dll[MAX_PATH]; wcfg_selfpath(dll, MAX_PATH);
    SIP_ADD_NEWPROVIDER_EX a; wcfg_sip_fill(&a, &g, dll);
    CHECK(addp(&a));
    a.pwszGetFuncName = L"another_get";
    CHECK(addp(&a));
    wchar_t f[300]; CHECK(wcfg_sip_key_present(FS_GET, &g, NULL, f)); CHECK(!wcscmp(f, L"another_get"));
    wcfg_end();
}
TEST(wcfg_sip_add_long_function_name_truncated_to_63) {
    SSETUP(CryptSIPAddProvider); GUID g; wcfg_guid(&g, 412); wchar_t dll[MAX_PATH]; wcfg_selfpath(dll, MAX_PATH);
    SIP_ADD_NEWPROVIDER_EX a; wcfg_sip_fill(&a, &g, dll);
    wchar_t longn[100]; for (int i = 0; i < 90; i++) longn[i] = L'a' + (i % 26); longn[90] = 0;
    a.pwszGetFuncName = longn;
    BOOL r = addp(&a);
    t_note("function name of 90 chars: add=%d err=%lu", r, GetLastError());
    wchar_t f[300] = L"";
    if (r && wcfg_sip_key_present(FS_GET, &g, NULL, f)) t_note("stored length %zu", wcslen(f));
    wcfg_end();
}
TEST(wcfg_sip_add_distinct_subjects_independent) {
    SSETUP(CryptSIPAddProvider); GUID a1, b1; wcfg_guid(&a1, 413); wcfg_guid(&b1, 414); wchar_t dll[MAX_PATH]; wcfg_selfpath(dll, MAX_PATH);
    SIP_ADD_NEWPROVIDER_EX a; wcfg_sip_fill(&a, &a1, dll); CHECK(addp(&a));
    wcfg_sip_fill(&a, &b1, dll); CHECK(addp(&a));
    CHECK(remp(&a1));
    EXPECT_EQ(nregistered(&a1), 0); EXPECT_EQ(nregistered(&b1), 8);
    wcfg_end();
}

/* ---- remove ---- */
TEST(wcfg_sip_remove_full_registration_true) {
    SSETUP(CryptSIPRemoveProvider); GUID g; wcfg_guid(&g, 420); wchar_t dll[MAX_PATH]; wcfg_selfpath(dll, MAX_PATH);
    SIP_ADD_NEWPROVIDER_EX a; wcfg_sip_fill(&a, &g, dll); CHECK(addp(&a));
    SET_ERR(0);
    CHECK(remp(&g) == TRUE);
    EXPECT_EQ(nregistered(&g), 0);
    wcfg_end();
}
TEST(wcfg_sip_remove_partial_registration_false_but_removes_present) {
    SSETUP(CryptSIPRemoveProvider); GUID g; wcfg_guid(&g, 421); wchar_t dll[MAX_PATH]; wcfg_selfpath(dll, MAX_PATH);
    SIP_ADD_NEWPROVIDER_EX a; wcfg_sip_fill(&a, &g, dll); a.cbStruct = SIP_ADD_BASE_SIZE; a.pwszIsFunctionName = NULL;
    CHECK(addp(&a));
    EXPECT_EQ(nregistered(&g), 5);
    SET_ERR(0);
    BOOL r = remp(&g);
    CHECK(r == FALSE); EXPECT_ERR(ERROR_FILE_NOT_FOUND);       /* the optional sets were never registered */
    EXPECT_EQ(nregistered(&g), 0);
    wcfg_end();
}
TEST(wcfg_sip_remove_unregistered_fails_not_found) {
    SSETUP(CryptSIPRemoveProvider); GUID g; wcfg_guid(&g, 422);
    SET_ERR(0); CHECK(!remp(&g)); EXPECT_ERR(ERROR_FILE_NOT_FOUND);
    wcfg_end();
}
TEST(wcfg_sip_remove_twice) {
    SSETUP(CryptSIPRemoveProvider); GUID g; wcfg_guid(&g, 423); wchar_t dll[MAX_PATH]; wcfg_selfpath(dll, MAX_PATH);
    SIP_ADD_NEWPROVIDER_EX a; wcfg_sip_fill(&a, &g, dll); CHECK(addp(&a));
    CHECK(remp(&g));
    SET_ERR(0); CHECK(!remp(&g)); EXPECT_ERR(ERROR_FILE_NOT_FOUND);
    wcfg_end();
}
TEST(wcfg_sip_remove_null_guid_fails) {
    SSETUP(CryptSIPRemoveProvider);
    SET_ERR(0); CHECK(!U(CryptSIPRemoveProvider)(NULL)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    wcfg_end();
}
TEST(wcfg_sip_remove_leaves_function_set_keys) {
    SSETUP(CryptSIPRemoveProvider); GUID g; wcfg_guid(&g, 424); wchar_t dll[MAX_PATH]; wcfg_selfpath(dll, MAX_PATH);
    SIP_ADD_NEWPROVIDER_EX a; wcfg_sip_fill(&a, &g, dll); CHECK(addp(&a)); CHECK(remp(&g));
    for (int s = 0; s < 8; s++) {
        wchar_t p[300]; swprintf(p, 300, L"SOFTWARE\\Microsoft\\Cryptography\\OID\\EncodingType 0\\%hs", wcfg_sip_funcset[s]);
        CHECKF(wcfg_key_exists(p), "set %s still present", wcfg_sip_funcset[s]);
    }
    wcfg_end();
}

/* ---- CryptSIPLoad ---- */
TEST(wcfg_sip_load_registered_subject) {
    SSETUP(CryptSIPLoad); GUID g; wcfg_guid(&g, 430); wchar_t dll[MAX_PATH]; wcfg_selfpath(dll, MAX_PATH);
    SIP_ADD_NEWPROVIDER_EX a; wcfg_sip_fill(&a, &g, dll); CHECK(addp(&a));
    SIP_DISPATCH_INFO d; memset(&d, 0xCC, sizeof d); d.cbSize = sizeof d;
    SET_ERR(0);
    CHECK(U(CryptSIPLoad)(&g, 0, &d));
    CHECK(d.hSIP == NULL);
    HMODULE c32 = GetModuleHandleA("crypt32.dll");
    CHECK(d.pfGet == (void *)GetProcAddress(c32, "CryptSIPGetSignedDataMsg"));
    CHECK(d.pfPut == (void *)GetProcAddress(c32, "CryptSIPPutSignedDataMsg"));
    CHECK(d.pfCreate == (void *)GetProcAddress(c32, "CryptSIPCreateIndirectData"));
    CHECK(d.pfVerify == (void *)GetProcAddress(c32, "CryptSIPVerifyIndirectData"));
    CHECK(d.pfRemove == (void *)GetProcAddress(c32, "CryptSIPRemoveSignedDataMsg"));
    wcfg_end();
}
TEST(wcfg_sip_load_unregistered_subject) {
    SSETUP(CryptSIPLoad); GUID g; wcfg_guid(&g, 431);
    SIP_DISPATCH_INFO d; memset(&d, 0, sizeof d);
    SET_ERR(0); CHECK(!U(CryptSIPLoad)(&g, 0, &d)); EXPECT_ERR(CK_TRUST_E_SUBJECT_FORM_UNKNOWN);
    CHECK(d.pfGet == NULL);
    wcfg_end();
}
TEST(wcfg_sip_load_after_remove_fails) {
    SSETUP(CryptSIPLoad); GUID g; wcfg_guid(&g, 432); wchar_t dll[MAX_PATH]; wcfg_selfpath(dll, MAX_PATH);
    SIP_ADD_NEWPROVIDER_EX a; wcfg_sip_fill(&a, &g, dll); CHECK(addp(&a));
    SIP_DISPATCH_INFO d; memset(&d, 0, sizeof d);
    CHECK(U(CryptSIPLoad)(&g, 0, &d));
    remp(&g);
    SET_ERR(0); CHECK(!U(CryptSIPLoad)(&g, 0, &d)); EXPECT_ERR(CK_TRUST_E_SUBJECT_FORM_UNKNOWN);
    wcfg_end();
}
TEST(wcfg_sip_load_invalid_arguments) {
    SSETUP(CryptSIPLoad); GUID g; wcfg_guid(&g, 433); wchar_t dll[MAX_PATH]; wcfg_selfpath(dll, MAX_PATH);
    SIP_ADD_NEWPROVIDER_EX a; wcfg_sip_fill(&a, &g, dll); CHECK(addp(&a));
    SIP_DISPATCH_INFO d; memset(&d, 0, sizeof d);
    SET_ERR(0); CHECK(!U(CryptSIPLoad)(NULL, 0, &d)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!U(CryptSIPLoad)(&g, 0, NULL)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!U(CryptSIPLoad)(&g, 1, &d)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!U(CryptSIPLoad)(&g, 0x80000000, &d)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    wcfg_end();
}
TEST(wcfg_sip_load_bad_put_function_name_fails) {
    SSETUP(CryptSIPLoad); GUID g; wcfg_guid(&g, 434); wchar_t dll[MAX_PATH]; wcfg_selfpath(dll, MAX_PATH);
    SIP_ADD_NEWPROVIDER_EX a; wcfg_sip_fill(&a, &g, dll); a.pwszPutFuncName = L"cryptt_NoSuchExport";
    CHECK(addp(&a));
    SIP_DISPATCH_INFO d; memset(&d, 0, sizeof d);
    SET_ERR(0); CHECK(!U(CryptSIPLoad)(&g, 0, &d)); EXPECT_ERR(CK_TRUST_E_SUBJECT_FORM_UNKNOWN);
    wcfg_end();
}
TEST(wcfg_sip_load_checks_only_put_function) {
    SSETUP(CryptSIPLoad); GUID g; wcfg_guid(&g, 435); wchar_t dll[MAX_PATH]; wcfg_selfpath(dll, MAX_PATH);
    SIP_ADD_NEWPROVIDER_EX a; wcfg_sip_fill(&a, &g, dll); a.pwszGetFuncName = L"cryptt_NoSuchExport"; a.pwszVerifyFuncName = L"cryptt_NoSuchExport";
    CHECK(addp(&a));
    SIP_DISPATCH_INFO d; memset(&d, 0, sizeof d);
    CHECK(U(CryptSIPLoad)(&g, 0, &d));
    wcfg_end();
}
TEST(wcfg_sip_load_builtin_subjects) {
    REQUIRE(U(CryptSIPLoad));
    static const GUID pe = { 0xC689AAB8, 0x8E78, 0x11D0, { 0x8C, 0x47, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE } };
    static const GUID cat = { 0xDE351A43, 0x8E59, 0x11D0, { 0x8C, 0x47, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE } };
    static const GUID cab = { 0xC689AABA, 0x8E78, 0x11D0, { 0x8C, 0x47, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE } };
    static const GUID ctl = { 0x9BA61D3F, 0xE73A, 0x11D0, { 0x8C, 0xD2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE } };
    const GUID *all[] = { &pe, &cat, &cab, &ctl };
    for (int i = 0; i < 4; i++) {
        SIP_DISPATCH_INFO d; memset(&d, 0, sizeof d);
        BOOL r = U(CryptSIPLoad)((GUID *)all[i], 0, &d);
        if (i < 2) CHECKF(r, "built-in subject %d loads", i);
        else t_note("built-in subject %d loads: %d", i, r);
    }
}

/* ---- dispatch through crypt32 into the registered in-exe SIP ---- */
static void dispatch_setup(GUID *g, unsigned slot) {
    wcfg_guid(g, slot);
    wchar_t dll[MAX_PATH]; wcfg_selfpath(dll, MAX_PATH);
    SIP_ADD_NEWPROVIDER_EX a; wcfg_sip_fill(&a, g, dll);
    CHECK(addp(&a));
    wcfg_sip_reset();
}
static SIP_SUBJECTINFO *mkinfo(SIP_SUBJECTINFO *si, GUID *g) { memset(si, 0, sizeof *si); si->cbSize = sizeof *si; si->pgSubjectType = g; return si; }

TEST(wcfg_sip_dispatch_get_signed_data_msg) {
    SSETUP(CryptSIPGetSignedDataMsg); GUID g; dispatch_setup(&g, 440); SIP_SUBJECTINFO si; mkinfo(&si, &g);
    DWORD enc = 0, cb = 0x55;
    BOOL r = UIN("crypt32.dll", CryptSIPGetSignedDataMsg)(&si, &enc, 7, &cb, NULL);
    CHECK(r == TRUE);
    EXPECT_EQ(wcfg_sipc[SC_GET].n, 1);
    CHECK(wcfg_sipc[SC_GET].info == &si); CHECK(wcfg_sipc[SC_GET].p1 == &enc); EXPECT_EQ(wcfg_sipc[SC_GET].a, 7); CHECK(wcfg_sipc[SC_GET].p2 == &cb);
    wcfg_sipc[SC_GET].ret = FALSE;
    r = UIN("crypt32.dll", CryptSIPGetSignedDataMsg)(&si, &enc, 0, &cb, NULL);
    CHECK(r == FALSE); EXPECT_EQ(wcfg_sipc[SC_GET].n, 2);
    wcfg_end();
}
TEST(wcfg_sip_dispatch_put_signed_data_msg) {
    SSETUP(CryptSIPPutSignedDataMsg); GUID g; dispatch_setup(&g, 441); SIP_SUBJECTINFO si; mkinfo(&si, &g);
    DWORD idx = 3; BYTE msg[4] = { 1, 2, 3, 4 };
    BOOL r = UIN("crypt32.dll", CryptSIPPutSignedDataMsg)(&si, 0x10001, &idx, sizeof msg, msg);
    CHECK(r == TRUE); EXPECT_EQ(wcfg_sipc[SC_PUT].n, 1);
    CHECK(wcfg_sipc[SC_PUT].info == &si); EXPECT_EQ(wcfg_sipc[SC_PUT].a, 0x10001); CHECK(wcfg_sipc[SC_PUT].p1 == &idx); EXPECT_EQ(wcfg_sipc[SC_PUT].b, 4);
    if (wcfg_sipc[SC_PUT].p2 != msg) t_note("fifth argument not forwarded verbatim");
    else CHECK(1);
    wcfg_end();
}
TEST(wcfg_sip_dispatch_create_indirect_data) {
    SSETUP(CryptSIPCreateIndirectData); GUID g; dispatch_setup(&g, 442); SIP_SUBJECTINFO si; mkinfo(&si, &g);
    DWORD cb = 0; SIP_INDIRECT_DATA id;
    BOOL r = UIN("crypt32.dll", CryptSIPCreateIndirectData)(&si, &cb, &id);
    CHECK(r == TRUE); EXPECT_EQ(wcfg_sipc[SC_CREATE].n, 1);
    CHECK(wcfg_sipc[SC_CREATE].info == &si); CHECK(wcfg_sipc[SC_CREATE].p1 == &cb); CHECK(wcfg_sipc[SC_CREATE].p2 == &id);
    wcfg_end();
}
TEST(wcfg_sip_dispatch_verify_indirect_data) {
    SSETUP(CryptSIPVerifyIndirectData); GUID g; dispatch_setup(&g, 443); SIP_SUBJECTINFO si; mkinfo(&si, &g);
    SIP_INDIRECT_DATA id;
    BOOL r = UIN("crypt32.dll", CryptSIPVerifyIndirectData)(&si, &id);
    CHECK(r == TRUE); EXPECT_EQ(wcfg_sipc[SC_VERIFY].n, 1);
    CHECK(wcfg_sipc[SC_VERIFY].info == &si); CHECK(wcfg_sipc[SC_VERIFY].p2 == &id);
    wcfg_sipc[SC_VERIFY].ret = FALSE;
    CHECK(UIN("crypt32.dll", CryptSIPVerifyIndirectData)(&si, &id) == FALSE);
    wcfg_end();
}
TEST(wcfg_sip_dispatch_remove_signed_data_msg) {
    SSETUP(CryptSIPRemoveSignedDataMsg); GUID g; dispatch_setup(&g, 444); SIP_SUBJECTINFO si; mkinfo(&si, &g);
    BOOL r = UIN("crypt32.dll", CryptSIPRemoveSignedDataMsg)(&si, 9);
    CHECK(r == TRUE); EXPECT_EQ(wcfg_sipc[SC_REMOVE].n, 1);
    CHECK(wcfg_sipc[SC_REMOVE].info == &si); EXPECT_EQ(wcfg_sipc[SC_REMOVE].a, 9);
    wcfg_end();
}
TEST(wcfg_sip_dispatch_get_caps) {
    REQUIRE(C32CAPS); SSETUP(CryptSIPAddProvider); GUID g; dispatch_setup(&g, 445); SIP_SUBJECTINFO si; mkinfo(&si, &g);
    BYTE caps[64] = { 0 };
    BOOL r = C32CAPS(&si, caps);
    CHECK(r == TRUE); EXPECT_EQ(wcfg_sipc[SC_CAPS].n, 1);
    CHECK(wcfg_sipc[SC_CAPS].info == &si);
    wcfg_end();
}
TEST(wcfg_sip_dispatch_via_loaded_dispatch_table) {
    SSETUP(CryptSIPLoad); GUID g; dispatch_setup(&g, 446); SIP_SUBJECTINFO si; mkinfo(&si, &g);
    SIP_DISPATCH_INFO d; memset(&d, 0, sizeof d);
    CHECK(U(CryptSIPLoad)(&g, 0, &d));
    DWORD cb = 0; SIP_INDIRECT_DATA id;
    CHECK(d.pfCreate(&si, &cb, &id)); CHECK(d.pfVerify(&si, &id)); CHECK(d.pfRemove(&si, 1));
    EXPECT_EQ(wcfg_sipc[SC_CREATE].n, 1); EXPECT_EQ(wcfg_sipc[SC_VERIFY].n, 1); EXPECT_EQ(wcfg_sipc[SC_REMOVE].n, 1);
    wcfg_end();
}
TEST(wcfg_sip_dispatch_unknown_subject) {
    SSETUP(CryptSIPGetSignedDataMsg); GUID g; wcfg_guid(&g, 447); SIP_SUBJECTINFO si; mkinfo(&si, &g);
    DWORD enc, cb; BYTE caps[64]; SIP_INDIRECT_DATA id; DWORD idx;
    SET_ERR(0); CHECK(!UIN("crypt32.dll", CryptSIPGetSignedDataMsg)(&si, &enc, 0, &cb, NULL)); EXPECT_ERR(CK_TRUST_E_SUBJECT_FORM_UNKNOWN);
    SET_ERR(0); CHECK(!UIN("crypt32.dll", CryptSIPPutSignedDataMsg)(&si, 0x10001, &idx, 1, caps)); EXPECT_ERR(CK_TRUST_E_SUBJECT_FORM_UNKNOWN);
    SET_ERR(0); CHECK(!UIN("crypt32.dll", CryptSIPCreateIndirectData)(&si, &cb, &id)); EXPECT_ERR(CK_TRUST_E_SUBJECT_FORM_UNKNOWN);
    SET_ERR(0); CHECK(!UIN("crypt32.dll", CryptSIPVerifyIndirectData)(&si, &id)); EXPECT_ERR(CK_TRUST_E_SUBJECT_FORM_UNKNOWN);
    SET_ERR(0); CHECK(!UIN("crypt32.dll", CryptSIPRemoveSignedDataMsg)(&si, 0)); EXPECT_ERR(CK_TRUST_E_SUBJECT_FORM_UNKNOWN);
    SET_ERR(0); CHECK(!C32CAPS(&si, caps)); EXPECT_ERR(CK_TRUST_E_SUBJECT_FORM_UNKNOWN);
    wcfg_end();
}
TEST(wcfg_sip_dispatch_null_arguments) {
    SSETUP(CryptSIPGetSignedDataMsg); GUID g; wcfg_guid(&g, 448); SIP_SUBJECTINFO si; mkinfo(&si, &g);
    DWORD enc, cb, idx; BYTE caps[64]; SIP_INDIRECT_DATA id;
    SIP_SUBJECTINFO ng; mkinfo(&ng, NULL);
    SET_ERR(0); CHECK(!UIN("crypt32.dll", CryptSIPGetSignedDataMsg)(NULL, &enc, 0, &cb, NULL)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!UIN("crypt32.dll", CryptSIPGetSignedDataMsg)(&ng, &enc, 0, &cb, NULL)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!UIN("crypt32.dll", CryptSIPPutSignedDataMsg)(NULL, 1, &idx, 1, caps)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!UIN("crypt32.dll", CryptSIPPutSignedDataMsg)(&ng, 1, &idx, 1, caps)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!UIN("crypt32.dll", CryptSIPCreateIndirectData)(NULL, &cb, &id)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!UIN("crypt32.dll", CryptSIPCreateIndirectData)(&ng, &cb, &id)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!UIN("crypt32.dll", CryptSIPVerifyIndirectData)(NULL, &id)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!UIN("crypt32.dll", CryptSIPVerifyIndirectData)(&ng, &id)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!UIN("crypt32.dll", CryptSIPRemoveSignedDataMsg)(NULL, 0)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!UIN("crypt32.dll", CryptSIPRemoveSignedDataMsg)(&ng, 0)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!C32CAPS(NULL, caps)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!C32CAPS(&ng, caps)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    wcfg_end();
}

/* ---- the subject registered with wintrust's own PE implementation names ---- */
TEST(wcfg_sip_register_with_wintrust_export_names) {
    SSETUP(CryptSIPLoad); GUID g; wcfg_guid(&g, 450);
    SIP_ADD_NEWPROVIDER_EX a; memset(&a, 0, sizeof a);
    a.cbStruct = SIP_ADD_BASE_SIZE; a.pgSubject = &g; a.pwszDLLFileName = L"WINTRUST.DLL"; a.pwszMagicNumber = L"MZ";
    a.pwszGetFuncName = L"CryptSIPGetSignedDataMsg"; a.pwszPutFuncName = L"CryptSIPPutSignedDataMsg";
    a.pwszCreateFuncName = L"CryptSIPCreateIndirectData"; a.pwszVerifyFuncName = L"CryptSIPVerifyIndirectData";
    a.pwszRemoveFuncName = L"CryptSIPRemoveSignedDataMsg";
    CHECK(addp(&a));
    wchar_t d[300], f[300];
    CHECK(wcfg_sip_key_present(FS_PUT, &g, d, f)); CHECK(!wcscmp(d, L"WINTRUST.DLL")); CHECK(!wcscmp(f, L"CryptSIPPutSignedDataMsg"));
    CHECK(wcfg_sip_key_present(FS_CREATE, &g, d, f)); CHECK(!wcscmp(f, L"CryptSIPCreateIndirectData"));
    SIP_DISPATCH_INFO di; memset(&di, 0, sizeof di);
    CHECK(U(CryptSIPLoad)(&g, 0, &di));
    /* wintrust's own entry points only know the built-in subject types */
    SIP_SUBJECTINFO si; mkinfo(&si, &g); DWORD cb = 0;
    SET_ERR(0);
    BOOL r = UIN("wintrust.dll", CryptSIPCreateIndirectData)(&si, &cb, NULL);
    t_note("wintrust!CryptSIPCreateIndirectData with an alias subject: %d err 0x%lx", r, GetLastError());
    wcfg_end();
}

/* ---- CryptSIPRetrieveSubjectGuid: runs in fresh child processes (the IsMyFileType list is read once per process) ---- */
static void make_file(const char *path, const char *magic8, int extra) {
    HANDLE h = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    DWORD n; char pad[64]; memset(pad, 'x', sizeof pad);
    if (h == INVALID_HANDLE_VALUE) return;
    if (magic8) WriteFile(h, magic8, (DWORD)strlen(magic8), &n, NULL);
    if (extra) WriteFile(h, pad, extra, &n, NULL);
    CloseHandle(h);
}
static void child_paths(char *dir, size_t cap) { if (!GetEnvironmentVariableA("CRYPTT_WCFG_DIR", dir, (DWORD)cap)) dir[0] = 0; }
static int child_guid_arg(int argc, char **argv, GUID *g, unsigned slot) {
    if (argc < 2) return 0;
    wcfg_guid_for(g, slot, (DWORD)strtoul(argv[1], NULL, 10)); return 1;
}
static int same(const GUID *a, const GUID *b) { return !memcmp(a, b, sizeof(GUID)); }

CHILD(wcfg_sip_retrieve) {
    GUID g1, g2; char dir[MAX_PATH], p[MAX_PATH]; GUID out;
    if (!child_guid_arg(argc, argv, &g1, 460) || !child_guid_arg(argc, argv, &g2, 461)) return 90;
    child_paths(dir, sizeof dir); if (!dir[0]) return 91;
    wcfg_sip_guid_for_is = g1; wcfg_sip_guid_for_is2 = g2;
    wchar_t wp[MAX_PATH];
    /* 1: magic recognised by IsMyFileType (by name) */
    sprintf(p, "%s\\magic1.bin", dir); MultiByteToWideChar(CP_ACP, 0, p, -1, wp, MAX_PATH);
    memset(&out, 0xAA, sizeof out); SetLastError(0);
    if (!U(CryptSIPRetrieveSubjectGuid)(wp, NULL, &out)) return 1;
    if (!same(&out, &g1)) return 2;
    if (wcfg_sipc[SC_IS].n < 1) return 3;
    /* 2: same file by handle */
    HANDLE h = CreateFileA(p, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    memset(&out, 0xAA, sizeof out);
    if (!U(CryptSIPRetrieveSubjectGuid)(NULL, h, &out)) return 4;
    if (!same(&out, &g1)) return 5;
    CloseHandle(h);
    /* 3: magic only the Fmt2 callback knows */
    sprintf(p, "%s\\magic2.bin", dir); MultiByteToWideChar(CP_ACP, 0, p, -1, wp, MAX_PATH);
    memset(&out, 0xAA, sizeof out);
    if (!U(CryptSIPRetrieveSubjectGuid)(wp, NULL, &out)) return 6;
    if (!same(&out, &g2)) return 7;
    if (wcfg_sipc[SC_IS2].n < 1) return 8;
    if (!wcfg_sipc[SC_IS2].p1 || wcscmp((WCHAR *)wcfg_sipc[SC_IS2].p1, wp)) return 9;
    /* 4: unknown content */
    sprintf(p, "%s\\plain.bin", dir); MultiByteToWideChar(CP_ACP, 0, p, -1, wp, MAX_PATH);
    memset(&out, 0xAA, sizeof out); SetLastError(0);
    if (U(CryptSIPRetrieveSubjectGuid)(wp, NULL, &out)) return 10;
    if (GetLastError() != CK_TRUST_E_SUBJECT_FORM_UNKNOWN) return 11;
    { GUID z; memset(&z, 0, sizeof z); if (!same(&out, &z)) return 12; }
    /* 5: shorter than four bytes */
    sprintf(p, "%s\\tiny.bin", dir); MultiByteToWideChar(CP_ACP, 0, p, -1, wp, MAX_PATH);
    SetLastError(0);
    if (U(CryptSIPRetrieveSubjectGuid)(wp, NULL, &out)) return 13;
    if (GetLastError() != ERROR_INVALID_PARAMETER) return 14;
    /* 6: missing file */
    sprintf(p, "%s\\nothere.bin", dir); MultiByteToWideChar(CP_ACP, 0, p, -1, wp, MAX_PATH);
    SetLastError(0);
    if (U(CryptSIPRetrieveSubjectGuid)(wp, NULL, &out)) return 15;
    if (GetLastError() != ERROR_FILE_NOT_FOUND) return 16;
    /* 7: argument validation */
    SetLastError(0);
    if (U(CryptSIPRetrieveSubjectGuid)(NULL, INVALID_HANDLE_VALUE, &out)) return 17;
    if (GetLastError() != ERROR_INVALID_PARAMETER) return 18;
    SetLastError(0);
    if (U(CryptSIPRetrieveSubjectGuid)(wp, NULL, NULL)) return 19;
    if (GetLastError() != ERROR_INVALID_PARAMETER) return 20;
    return 0;
}
CHILD(wcfg_sip_retrieve_cache) {
    GUID g1; char dir[MAX_PATH], p[MAX_PATH]; GUID out; wchar_t wp[MAX_PATH];
    if (!child_guid_arg(argc, argv, &g1, 462)) return 90;
    child_paths(dir, sizeof dir); if (!dir[0]) return 91;
    wcfg_sip_guid_for_is = g1;
    sprintf(p, "%s\\magic1.bin", dir); MultiByteToWideChar(CP_ACP, 0, p, -1, wp, MAX_PATH);
    /* first lookup loads the (empty) list of registered IsMyFileType functions */
    SetLastError(0);
    if (U(CryptSIPRetrieveSubjectGuid)(wp, NULL, &out)) return 1;
    if (GetLastError() != CK_TRUST_E_SUBJECT_FORM_UNKNOWN) return 2;
    wchar_t dll[MAX_PATH]; wcfg_selfpath(dll, MAX_PATH);
    SIP_ADD_NEWPROVIDER_EX a; wcfg_sip_fill(&a, &g1, dll);
    if (!U(CryptSIPAddProvider)((SIP_ADD_NEWPROVIDER *)&a)) return 3;
    wcfg_sip_reset();
    SetLastError(0);
    int r = U(CryptSIPRetrieveSubjectGuid)(wp, NULL, &out);
    DWORD e = GetLastError();
    U(CryptSIPRemoveProvider)(&g1);
    if (r) return 4;                         /* list was cached: the new provider is not consulted */
    if (e != CK_TRUST_E_SUBJECT_FORM_UNKNOWN) return 5;
    if (wcfg_sipc[SC_IS].n != 0 || wcfg_sipc[SC_IS2].n != 0) return 6;
    return 0;
}
static int run_retrieve_child(const char *name, unsigned slot_guid_unused) {
    char dir[MAX_PATH]; strcpy(dir, t_tmpdir()); size_t l = strlen(dir); if (l && dir[l - 1] == '\\') dir[l - 1] = 0;
    char p[MAX_PATH];
    sprintf(p, "%s\\magic1.bin", dir); make_file(p, "CRYPTTST", 40);
    sprintf(p, "%s\\magic2.bin", dir); make_file(p, "CRYPTTS2", 40);
    sprintf(p, "%s\\plain.bin", dir);  make_file(p, "NOMAGIC!", 40);
    sprintf(p, "%s\\tiny.bin", dir);   make_file(p, "ab", 0);
    SetEnvironmentVariableA("CRYPTT_WCFG_DIR", dir);
    char args[32]; sprintf(args, "%lu", GetCurrentProcessId());
    DWORD rc = t_run_child(name, args, 30000);
    SetEnvironmentVariableA("CRYPTT_WCFG_DIR", NULL);
    return (int)rc;
}
TEST(wcfg_sip_retrieve_subject_guid_registered_is_my_file_type) {
    SSETUP(CryptSIPRetrieveSubjectGuid); GUID g1, g2; wcfg_guid(&g1, 460); wcfg_guid(&g2, 461);
    wchar_t dll[MAX_PATH]; wcfg_selfpath(dll, MAX_PATH);
    SIP_ADD_NEWPROVIDER_EX a; wcfg_sip_fill(&a, &g1, dll); CHECK(addp(&a));
    wcfg_sip_fill(&a, &g2, dll); CHECK(addp(&a));
    int rc = run_retrieve_child("wcfg_sip_retrieve", 0);
    CHECKF(rc == 0, "child step %d failed", rc);
    wcfg_end();
}
TEST(wcfg_sip_retrieve_subject_guid_list_cached_per_process) {
    SSETUP(CryptSIPRetrieveSubjectGuid);
    int rc = run_retrieve_child("wcfg_sip_retrieve_cache", 0);
    CHECKF(rc == 0, "child step %d failed", rc);
    wcfg_end();
}
