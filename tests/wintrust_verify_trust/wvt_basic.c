/* WinVerifyTrust / WinVerifyTrustEx: argument handling, unsigned/unknown subjects, action GUIDs, flags. */
#include "wvt.h"

static const char *const g_wintrust_exports[] = {
    "WinVerifyTrust", "WinVerifyTrustEx", "WintrustGetRegPolicyFlags", "WintrustSetRegPolicyFlags",
    "WintrustAddActionID", "WintrustRemoveActionID", "WintrustLoadFunctionPointers", "WintrustAddDefaultForUsage",
    "WintrustGetDefaultForUsage", "WintrustSetDefaultIncludePEPageHashes", "WintrustUserWriteabilityCheck",
    "WTHelperProvDataFromStateData", "WTHelperGetProvSignerFromChain", "WTHelperGetProvCertFromChain",
    "WTHelperGetProvPrivateDataFromChain", "WTHelperCertIsSelfSigned", "WTHelperCertCheckValidSignature",
    "WTHelperCheckCertUsage", "WTHelperGetKnownUsages", "WTHelperGetAgencyInfo", "WTHelperGetFileHandle",
    "WTHelperGetFileName", "WTHelperGetFileHash", "WTHelperOpenKnownStores", "WTHelperIsInRootStore",
    "WTHelperIsChainedToMicrosoft", "WTHelperIsChainedToMicrosoftFromStateData", "WTHelperCertFindIssuerCertificate",
    "WTGetSignatureInfo", "WTConvertCertCtxToChainInfo", "TrustDecode", "TrustFreeDecode", "TrustOpenStores",
    "TrustFindIssuerCertificate", "TrustIsCertificateSelfSigned", "SoftpubInitialize", "SoftpubLoadMessage",
    "SoftpubLoadSignature", "SoftpubCheckCert", "SoftpubCleanup", "SoftpubAuthenticode", "SoftpubDefCertInit",
    "SoftpubFreeDefUsageCallData", "SoftpubLoadDefUsageCallData", "SoftpubDumpStructure", "WintrustCertificateTrust",
    "GenericChainCertificateTrust", "GenericChainFinalProv", "HTTPSCertificateTrust", "HTTPSFinalProv",
    "DriverInitializePolicy", "DriverFinalPolicy", "DriverCleanupPolicy", "OfficeInitializePolicy",
    "OfficeCleanupPolicy", "ConfigCiFinalPolicy", "WVTAsn1SpcLinkEncode", "WVTAsn1SpcLinkDecode",
    "WVTAsn1SpcSpOpusInfoEncode", "WVTAsn1SpcSpOpusInfoDecode", "WVTAsn1SpcPeImageDataEncode",
    "WVTAsn1SpcPeImageDataDecode", "WVTAsn1SpcIndirectDataContentEncode", "WVTAsn1SpcIndirectDataContentDecode",
    "WVTAsn1SpcStatementTypeEncode", "WVTAsn1SpcStatementTypeDecode", "WVTAsn1SpcSigInfoEncode",
    "WVTAsn1SpcSigInfoDecode", "WVTAsn1CatNameValueEncode", "WVTAsn1CatNameValueDecode",
    "WVTAsn1CatMemberInfoEncode", "WVTAsn1CatMemberInfoDecode", "WVTAsn1CatMemberInfo2Encode",
    "WVTAsn1CatMemberInfo2Decode", "WVTAsn1SpcSpAgencyInfoEncode", "WVTAsn1SpcSpAgencyInfoDecode",
    "WVTAsn1SpcMinimalCriteriaInfoEncode", "WVTAsn1SpcMinimalCriteriaInfoDecode",
    "WVTAsn1SpcFinancialCriteriaInfoEncode", "WVTAsn1SpcFinancialCriteriaInfoDecode",
    "WVTAsn1SealingSignatureAttributeEncode", "WVTAsn1SealingSignatureAttributeDecode",
    "WVTAsn1SealingTimestampAttributeEncode", "WVTAsn1SealingTimestampAttributeDecode",
    "WVTAsn1IntentToSealAttributeEncode", "WVTAsn1IntentToSealAttributeDecode", NULL };

TEST(wvt_exports_resolve_by_name) {
    HMODULE m = t_module("wintrust.dll");
    if (!m) { t_skip("wintrust.dll missing"); return; }
    for (int i = 0; g_wintrust_exports[i]; i++) {
        FARPROC p = GetProcAddress(m, g_wintrust_exports[i]);
        CHECKF(p != NULL, "%s", g_wintrust_exports[i]);
    }
}
TEST(wvt_getprocaddress_negative) {
    HMODULE m = t_module("wintrust.dll"); if (!m) return;
    SET_ERR(0); CHECK(GetProcAddress(m, "WinVerifyTrustNoSuchExport") == NULL); EXPECT_ERR(ERROR_PROC_NOT_FOUND);
    SET_ERR(0); CHECK(GetProcAddress(m, "winverifytrust") == NULL); EXPECT_ERR(ERROR_PROC_NOT_FOUND); /* case sensitive */
}
TEST(wvt_wintrustex_same_export_family) {
    HMODULE m = t_module("wintrust.dll"); if (!m) return;
    FARPROC a = GetProcAddress(m, "WinVerifyTrust"), b = GetProcAddress(m, "WinVerifyTrustEx");
    CHECK(a && b); CHECK(a != b);
}

/* ---- unsigned PE ------------------------------------------------------- */
TEST(wvt_unsigned_pe_nosignature) {
    WVT_REQUIRE_WVT();
    DWORD e; LONG r = wvt_verify_bytes(fix_pe_unsigned, sizeof fix_pe_unsigned, 0, "u1.exe", &e);
    EXPECT_EQ(r, WVT_E_NOSIGNATURE); EXPECT_EQ(e, (DWORD)WVT_E_NOSIGNATURE);
}
TEST(wvt_unsigned_pe_ex_matches) {
    WVT_REQUIRE_WVT();
    WCHAR p[MAX_PATH]; WVTD w; WINTRUST_FILE_INFO fi;
    wvt_path(p, "u2.exe"); wvt_write(p, fix_pe_unsigned, sizeof fix_pe_unsigned);
    wvt_init_file(&w, &fi, p);
    SET_ERR(0xdeadbeef);
    HRESULT hr = U(WinVerifyTrustEx)(NULL, (GUID *)&WVT_V2, &w.d);
    EXPECT_EQ(hr, WVT_E_NOSIGNATURE); EXPECT_EQ(GetLastError(), (DWORD)WVT_E_NOSIGNATURE);
    wvt_del(p);
}
TEST(wvt_unsigned_pe_by_handle) {
    WVT_REQUIRE_WVT();
    WCHAR p[MAX_PATH]; WVTD w; WINTRUST_FILE_INFO fi;
    wvt_path(p, "u3.exe"); wvt_write(p, fix_pe_unsigned, sizeof fix_pe_unsigned);
    HANDLE h = CreateFileW(p, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    CHECK(h != INVALID_HANDLE_VALUE);
    wvt_init_file(&w, &fi, p); fi.hFile = h;
    DWORD e; LONG r = wvt_call(&WVT_V2, &w, &e);
    EXPECT_EQ(r, WVT_E_NOSIGNATURE); EXPECT_EQ(e, (DWORD)WVT_E_NOSIGNATURE);
    /* a caller supplied handle is not closed by the verification */
    DWORD sz = GetFileSize(h, NULL); EXPECT_EQ(sz, sizeof fix_pe_unsigned);
    CloseHandle(h); wvt_del(p);
}
TEST(wvt_unsigned_pe_handle_without_path) {
    WVT_REQUIRE_WVT();
    WCHAR p[MAX_PATH]; WVTD w; WINTRUST_FILE_INFO fi;
    wvt_path(p, "u4.exe"); wvt_write(p, fix_pe_unsigned, sizeof fix_pe_unsigned);
    HANDLE h = CreateFileW(p, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    wvt_init_file(&w, &fi, NULL); fi.hFile = h;
    DWORD e; LONG r = wvt_call(&WVT_V2, &w, &e);
    t_note("handle-only unsigned PE: result 0x%08lx", (unsigned long)r);
    CHECK(r != 0);
    CloseHandle(h); wvt_del(p);
}
TEST(wvt_unsigned_pe_cbstruct_variants) {
    WVT_REQUIRE_WVT();
    static const DWORD sizes[] = { sizeof(WVTD), sizeof(WINTRUST_DATA), 0x4c };
    WCHAR p[MAX_PATH]; wvt_path(p, "u5.exe"); wvt_write(p, fix_pe_unsigned, sizeof fix_pe_unsigned);
    for (int i = 0; i < 3; i++) {
        WVTD w; WINTRUST_FILE_INFO fi; wvt_init_file(&w, &fi, p); w.d.cbStruct = sizes[i];
        DWORD e; LONG r = wvt_call(&WVT_V2, &w, &e);
        CHECKF(r == WVT_E_NOSIGNATURE, "cbStruct 0x%lx got 0x%08lx", (unsigned long)sizes[i], (unsigned long)r);
    }
    wvt_del(p);
}
TEST(wvt_cbstruct_small_values_observed) {
    WVT_REQUIRE_WVT();
    static const DWORD sizes[] = { 0, 4, 0x18, 0x20, 0x30, 0x38, 0x40, 0x48 };
    WCHAR p[MAX_PATH]; wvt_path(p, "u6.exe"); wvt_write(p, fix_pe_unsigned, sizeof fix_pe_unsigned);
    for (int i = 0; i < 8; i++) {
        WVTD w; WINTRUST_FILE_INFO fi; wvt_init_file(&w, &fi, p); w.d.cbStruct = sizes[i];
        DWORD e; LONG r = wvt_call(&WVT_V2, &w, &e);
        t_note("cbStruct=0x%lx -> 0x%08lx lasterr 0x%08lx", (unsigned long)sizes[i], (unsigned long)r, (unsigned long)e);
        CHECKF(r != 0, "cbStruct 0x%lx must not succeed on an unsigned image", (unsigned long)sizes[i]);
    }
    wvt_del(p);
}
TEST(wvt_unsigned_pe_provflags_matrix) {
    WVT_REQUIRE_WVT();
    static const DWORD fl[] = { 0, WTD_USE_IE4_TRUST_FLAG, WTD_NO_IE4_CHAIN_FLAG, WTD_NO_POLICY_USAGE_FLAG,
        WTD_REVOCATION_CHECK_NONE, WTD_REVOCATION_CHECK_END_CERT, WTD_REVOCATION_CHECK_CHAIN,
        WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT, WTD_SAFER_FLAG, WTD_HASH_ONLY_FLAG, WTD_USE_DEFAULT_OSVER_CHECK,
        WTD_LIFETIME_SIGNING_FLAG, WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_DISABLE_MD2_MD4, WTD_MOTW_FLAG,
        WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_USE_IE4_TRUST_FLAG | WTD_NO_IE4_CHAIN_FLAG };
    WCHAR p[MAX_PATH]; wvt_path(p, "u7.exe"); wvt_write(p, fix_pe_unsigned, sizeof fix_pe_unsigned);
    for (unsigned i = 0; i < sizeof fl / sizeof fl[0]; i++) {
        WVTD w; WINTRUST_FILE_INFO fi; wvt_init_file(&w, &fi, p); w.d.dwProvFlags = fl[i];
        DWORD e; LONG r = wvt_call(&WVT_V2, &w, &e);
        CHECKF(r == WVT_E_NOSIGNATURE, "flags 0x%lx got 0x%08lx", (unsigned long)fl[i], (unsigned long)r);
        CHECKF(e == (DWORD)WVT_E_NOSIGNATURE, "flags 0x%lx lasterr 0x%08lx", (unsigned long)fl[i], (unsigned long)e);
    }
    wvt_del(p);
}
TEST(wvt_unsigned_pe_revocation_matrix) {
    WVT_REQUIRE_WVT();
    static const DWORD rv[] = { WTD_REVOKE_NONE, WTD_REVOKE_WHOLECHAIN };
    WCHAR p[MAX_PATH]; wvt_path(p, "u8.exe"); wvt_write(p, fix_pe_unsigned, sizeof fix_pe_unsigned);
    for (int i = 0; i < 2; i++) {
        WVTD w; WINTRUST_FILE_INFO fi; wvt_init_file(&w, &fi, p); w.d.fdwRevocationChecks = rv[i];
        w.d.dwProvFlags = WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL; /* never touch the wire */
        DWORD e; LONG r = wvt_call(&WVT_V2, &w, &e);
        EXPECT_EQ(r, WVT_E_NOSIGNATURE);
    }
    wvt_del(p);
}

/* ---- non-PE, empty, missing ---------------------------------------------- */
TEST(wvt_empty_file_subject_form_unknown) {
    WVT_REQUIRE_WVT();
    DWORD e; LONG r = wvt_verify_bytes("", 0, 0, "empty.bin", &e);
    EXPECT_EQ(r, WVT_E_SUBJECT_FORM); EXPECT_EQ(e, (DWORD)WVT_E_SUBJECT_FORM);
}
TEST(wvt_text_file_subject_form_unknown) {
    WVT_REQUIRE_WVT();
    static const char txt[] = "hello, this is not a signable subject\r\n";
    DWORD e; LONG r = wvt_verify_bytes(txt, sizeof txt - 1, 0, "a.txt", &e);
    EXPECT_EQ(r, WVT_E_SUBJECT_FORM); EXPECT_EQ(e, (DWORD)WVT_E_SUBJECT_FORM);
}
TEST(wvt_garbage_binary_subject_form_unknown) {
    WVT_REQUIRE_WVT();
    BYTE b[600]; for (int i = 0; i < 600; i++) b[i] = (BYTE)(i * 7 + 3);
    DWORD e; LONG r = wvt_verify_bytes(b, sizeof b, 0, "g.bin", &e);
    EXPECT_EQ(r, WVT_E_SUBJECT_FORM);
}
TEST(wvt_truncated_pe_dos_header_only) {
    WVT_REQUIRE_WVT();
    DWORD e; LONG r = wvt_verify_bytes(fix_pe_signed, sizeof(IMAGE_DOS_HEADER), 0, "t1.exe", &e);
    EXPECT_EQ(r, WVT_E_SUBJECT_FORM);
    r = wvt_verify_bytes(fix_pe_signed, sizeof(IMAGE_DOS_HEADER), WTD_HASH_ONLY_FLAG, "t2.exe", &e);
    EXPECT_EQ(r, WVT_E_NOSIGNATURE);
}
TEST(wvt_truncated_pe_headers_only) {
    WVT_REQUIRE_WVT();
    DWORD n = sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS64) * 2; DWORD e;
    EXPECT_EQ(wvt_verify_bytes(fix_pe_signed, n, 0, "t3.exe", &e), WVT_E_NOSIGNATURE);
    EXPECT_EQ(wvt_verify_bytes(fix_pe_signed, n, WTD_HASH_ONLY_FLAG, "t4.exe", &e), WVT_E_NOSIGNATURE);
}
TEST(wvt_missing_file_result) {
    WVT_REQUIRE_WVT();
    WCHAR p[MAX_PATH]; WVTD w; WINTRUST_FILE_INFO fi; wvt_path(p, "nonexistent.exe"); wvt_del(p);
    wvt_init_file(&w, &fi, p); DWORD e; LONG r = wvt_call(&WVT_V2, &w, &e);
    CHECKF(r == WVT_E_FILE_ERROR || r == (LONG)HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND) || r == (LONG)ERROR_FILE_NOT_FOUND || r == WVT_E_NOSIGNATURE,
           "got 0x%08lx", (unsigned long)r);
    EXPECT_EQ((DWORD)r, e);
    t_note("missing file: result 0x%08lx", (unsigned long)r);
}
TEST(wvt_missing_directory_result) {
    WVT_REQUIRE_WVT();
    WCHAR p[MAX_PATH]; WVTD w; WINTRUST_FILE_INFO fi; wvt_path(p, "nodir\\nofile.exe");
    wvt_init_file(&w, &fi, p); DWORD e; LONG r = wvt_call(&WVT_V2, &w, &e);
    CHECK(r != 0); EXPECT_EQ((DWORD)r, e);
    t_note("missing directory: result 0x%08lx", (unsigned long)r);
}
TEST(wvt_missing_file_state_returned) {
    /* state data is still produced for a failed verification */
    WVT_REQUIRE_WVT();
    WCHAR p[MAX_PATH]; WVTD w; WINTRUST_FILE_INFO fi; wvt_path(p, "nonexistent2.exe"); wvt_del(p);
    wvt_init_file(&w, &fi, p); w.d.dwStateAction = WTD_STATEACTION_VERIFY;
    DWORD e; LONG r = wvt_call(&WVT_V2, &w, &e);
    CHECK(r != 0); CHECK(w.d.hWVTStateData != NULL);
    EXPECT_EQ(wvt_close(&WVT_V2, &w), 0);
    CHECK(w.d.hWVTStateData == NULL);
}
TEST(wvt_empty_path_string) {
    WVT_REQUIRE_WVT();
    WVTD w; WINTRUST_FILE_INFO fi; wvt_init_file(&w, &fi, L"");
    DWORD e; LONG r = wvt_call(&WVT_V2, &w, &e);
    CHECK(r != 0); EXPECT_EQ((DWORD)r, e);
    t_note("empty path: 0x%08lx", (unsigned long)r);
}

/* ---- action GUIDs ------------------------------------------------------- */
TEST(wvt_unknown_action_guid) {
    WVT_REQUIRE_WVT();
    static const GUID g[] = {
        {0x12345678,0x1234,0x1234,{1,2,3,4,5,6,7,8}}, {0,0,0,{0}},
        {0xFFFFFFFF,0xFFFF,0xFFFF,{0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF}},
        /* near misses of the generic verify GUID */
        {0x00AAC56C,0xCD44,0x11d0,{0x8c,0xc2,0x00,0xc0,0x4f,0xc2,0x95,0xee}},
        {0x00AAC56B,0xCD44,0x11d0,{0x8c,0xc2,0x00,0xc0,0x4f,0xc2,0x95,0xef}} };
    WCHAR p[MAX_PATH]; wvt_path(p, "ug.exe"); wvt_write(p, fix_pe_unsigned, sizeof fix_pe_unsigned);
    for (int i = 0; i < 5; i++) {
        WVTD w; WINTRUST_FILE_INFO fi; wvt_init_file(&w, &fi, p); DWORD e;
        LONG r = wvt_call(&g[i], &w, &e);
        CHECKF(r == WVT_E_PROVIDER_UNKNOWN, "guid %d got 0x%08lx", i, (unsigned long)r);
        CHECKF(e == 0, "guid %d lasterr 0x%08lx", i, (unsigned long)e); /* Win10: the HRESULT is only the return value, last error is cleared */
        CHECK(w.d.hWVTStateData == NULL);
    }
    wvt_del(p);
}
TEST(wvt_unknown_action_guid_ex) {
    WVT_REQUIRE_WVT();
    GUID g = {0x12345678,0x4321,0x1234,{1,2,3,4,5,6,7,9}};
    WCHAR p[MAX_PATH]; WVTD w; WINTRUST_FILE_INFO fi; wvt_path(p, "ug2.exe"); wvt_write(p, fix_pe_unsigned, sizeof fix_pe_unsigned);
    wvt_init_file(&w, &fi, p);
    EXPECT_EQ(U(WinVerifyTrustEx)(NULL, &g, &w.d), WVT_E_PROVIDER_UNKNOWN);
    wvt_del(p);
}
TEST(wvt_unknown_action_guid_with_verify_state) {
    WVT_REQUIRE_WVT();
    GUID g = {0x12345678,0x4321,0x1234,{1,2,3,4,5,6,7,10}};
    WCHAR p[MAX_PATH]; WVTD w; WINTRUST_FILE_INFO fi; wvt_path(p, "ug3.exe"); wvt_write(p, fix_pe_unsigned, sizeof fix_pe_unsigned);
    wvt_init_file(&w, &fi, p); w.d.dwStateAction = WTD_STATEACTION_VERIFY;
    DWORD e; EXPECT_EQ(wvt_call(&g, &w, &e), WVT_E_PROVIDER_UNKNOWN);
    CHECK(w.d.hWVTStateData == NULL);
    wvt_del(p);
}
TEST(wvt_known_actions_unsigned_pe_not_success) {
    WVT_REQUIRE_WVT();
    if (t_is_wine()) { t_skip("provider coverage differs under emulation"); return; }
    struct { const GUID *g; const char *n; } a[] = {
        { &WVT_V2, "GENERIC_VERIFY_V2" }, { &WVT_TPTEST, "TRUSTPROVIDER_TEST" } };
    WCHAR p[MAX_PATH]; wvt_path(p, "ka.exe"); wvt_write(p, fix_pe_unsigned, sizeof fix_pe_unsigned);
    for (int i = 0; i < 2; i++) {
        WVTD w; WINTRUST_FILE_INFO fi; wvt_init_file(&w, &fi, p); DWORD e;
        LONG r = wvt_call(a[i].g, &w, &e);
        t_note("%s on unsigned PE -> 0x%08lx", a[i].n, (unsigned long)r);
        CHECKF(r != 0, "%s", a[i].n);
    }
    wvt_del(p);
}
TEST(wvt_cert_actions_reject_file_choice_observed) {
    WVT_REQUIRE_WVT();
    if (t_is_wine()) { t_skip("provider coverage differs under emulation"); return; }
    WCHAR p[MAX_PATH]; wvt_path(p, "ca.exe"); wvt_write(p, fix_pe_unsigned, sizeof fix_pe_unsigned);
    const GUID *g[] = { &WVT_CERTV, &WVT_CHAINV, &WVT_HTTPS };
    for (int i = 0; i < 3; i++) {
        WVTD w; WINTRUST_FILE_INFO fi; wvt_init_file(&w, &fi, p); DWORD e;
        LONG r = wvt_call(g[i], &w, &e);
        t_note("action %d with CHOICE_FILE on unsigned PE -> 0x%08lx (lasterr 0x%08lx)", i, (unsigned long)r, (unsigned long)e);
        CHECK(r != 0);
    }
    wvt_del(p);
}
TEST(wvt_driver_action_without_policy_data_observed) {
    WVT_REQUIRE_WVT();
    if (t_is_wine()) { t_skip("driver provider not emulated"); return; }
    WCHAR p[MAX_PATH]; WVTD w; WINTRUST_FILE_INFO fi; wvt_path(p, "dr.exe"); wvt_write(p, fix_pe_unsigned, sizeof fix_pe_unsigned);
    wvt_init_file(&w, &fi, p); DWORD e;
    LONG r = wvt_call(&WVT_DRIVER, &w, &e);
    t_note("DRIVER_ACTION_VERIFY w/o DRIVER_VER_INFO -> 0x%08lx lasterr 0x%08lx", (unsigned long)r, (unsigned long)e);
    CHECK(r != 0);
    wvt_del(p);
}

/* ---- WTD_STATEACTION_CLOSE / state --------------------------------------- */
TEST(wvt_close_without_state_is_ok_and_keeps_lasterror) {
    WVT_REQUIRE_WVT();
    WCHAR p[MAX_PATH]; WVTD w; WINTRUST_FILE_INFO fi; wvt_path(p, "cl.exe");
    wvt_init_file(&w, &fi, p); w.d.dwStateAction = WTD_STATEACTION_CLOSE; w.d.hWVTStateData = NULL;
    SetLastError(0xdeadbeef);
    LONG r = U(WinVerifyTrust)(INVALID_HANDLE_VALUE, (GUID *)&WVT_V2, &w);
    EXPECT_EQ(r, 0); EXPECT_EQ(GetLastError(), 0x7f); /* Win10 leaves ERROR_PROC_NOT_FOUND (an internal optional lookup) */
}
TEST(wvt_close_without_state_ex) {
    WVT_REQUIRE_WVT();
    WCHAR p[MAX_PATH]; WVTD w; WINTRUST_FILE_INFO fi; wvt_path(p, "cl2.exe");
    wvt_init_file(&w, &fi, p); w.d.dwStateAction = WTD_STATEACTION_CLOSE;
    SetLastError(0xdeadbeef);
    HRESULT hr = U(WinVerifyTrustEx)(NULL, (GUID *)&WVT_V2, &w.d);
    EXPECT_EQ(hr, 0); EXPECT_EQ(GetLastError(), 0x7f);
}
TEST(wvt_close_does_not_inspect_subject) {
    /* CLOSE with state data is independent of the (now missing) file */
    WVT_REQUIRE_WVT();
    WCHAR p[MAX_PATH]; WVTD w; WINTRUST_FILE_INFO fi; wvt_path(p, "cl3.exe");
    wvt_write(p, fix_pe_unsigned, sizeof fix_pe_unsigned);
    wvt_init_file(&w, &fi, p); w.d.dwStateAction = WTD_STATEACTION_VERIFY;
    DWORD e; EXPECT_EQ(wvt_call(&WVT_V2, &w, &e), WVT_E_NOSIGNATURE);
    CHECK(w.d.hWVTStateData != NULL);
    wvt_del(p);
    SetLastError(0xdeadbeef);
    EXPECT_EQ(wvt_close(&WVT_V2, &w), 0);
    EXPECT_EQ(GetLastError(), 0x7f);
    CHECK(w.d.hWVTStateData == NULL);
}
TEST(wvt_close_twice) {
    WVT_REQUIRE_WVT();
    WCHAR p[MAX_PATH]; WVTD w; WINTRUST_FILE_INFO fi; wvt_path(p, "cl4.exe");
    wvt_write(p, fix_pe_unsigned, sizeof fix_pe_unsigned);
    wvt_init_file(&w, &fi, p); w.d.dwStateAction = WTD_STATEACTION_VERIFY;
    DWORD e; wvt_call(&WVT_V2, &w, &e);
    EXPECT_EQ(wvt_close(&WVT_V2, &w), 0);
    EXPECT_EQ(wvt_close(&WVT_V2, &w), 0); /* state already NULL */
    wvt_del(p);
}
TEST(wvt_state_ignore_returns_no_state) {
    WVT_REQUIRE_WVT();
    WCHAR p[MAX_PATH]; WVTD w; WINTRUST_FILE_INFO fi; wvt_path(p, "ig.exe");
    wvt_write(p, fix_pe_unsigned, sizeof fix_pe_unsigned);
    wvt_init_file(&w, &fi, p); DWORD e;
    EXPECT_EQ(wvt_call(&WVT_V2, &w, &e), WVT_E_NOSIGNATURE);
    CHECK(w.d.hWVTStateData == NULL);
    wvt_del(p);
}
TEST(wvt_state_verify_returns_state_even_on_failure) {
    WVT_REQUIRE_WVT();
    WCHAR p[MAX_PATH]; WVTD w; WINTRUST_FILE_INFO fi; wvt_path(p, "sv.exe");
    wvt_write(p, fix_pe_unsigned, sizeof fix_pe_unsigned);
    wvt_init_file(&w, &fi, p); w.d.dwStateAction = WTD_STATEACTION_VERIFY; DWORD e;
    EXPECT_EQ(wvt_call(&WVT_V2, &w, &e), WVT_E_NOSIGNATURE);
    CHECK(w.d.hWVTStateData != NULL);
    EXPECT_EQ(wvt_close(&WVT_V2, &w), 0);
    wvt_del(p);
}
TEST(wvt_state_independent_handles) {
    WVT_REQUIRE_WVT();
    WCHAR p[MAX_PATH]; WINTRUST_FILE_INFO f1, f2; WVTD a, b; wvt_path(p, "si.exe");
    wvt_write(p, fix_pe_unsigned, sizeof fix_pe_unsigned);
    wvt_init_file(&a, &f1, p); wvt_init_file(&b, &f2, p);
    a.d.dwStateAction = b.d.dwStateAction = WTD_STATEACTION_VERIFY; DWORD e;
    wvt_call(&WVT_V2, &a, &e); wvt_call(&WVT_V2, &b, &e);
    CHECK(a.d.hWVTStateData && b.d.hWVTStateData && a.d.hWVTStateData != b.d.hWVTStateData);
    EXPECT_EQ(wvt_close(&WVT_V2, &a), 0); CHECK(b.d.hWVTStateData != NULL);
    EXPECT_EQ(wvt_close(&WVT_V2, &b), 0);
    wvt_del(p);
}
TEST(wvt_state_data_shape_after_unsigned_verify) {
    WVT_REQUIRE_WVT();
    WCHAR p[MAX_PATH]; WVTD w; WINTRUST_FILE_INFO fi; wvt_path(p, "sd.exe");
    wvt_write(p, fix_pe_unsigned, sizeof fix_pe_unsigned);
    wvt_init_file(&w, &fi, p); w.d.dwStateAction = WTD_STATEACTION_VERIFY; DWORD e;
    wvt_call(&WVT_V2, &w, &e);
    WVT_PD *pd = (WVT_PD *)U(WTHelperProvDataFromStateData)(w.d.hWVTStateData);
    CHECK((void *)pd == w.d.hWVTStateData);
    if (pd) {
        EXPECT_EQ(pd->d.cbStruct, sizeof(WVT_PD));
        EXPECT_EQ(sizeof(WVT_PD), 0xF0);
        CHECK(pd->d.pWintrustData == &w.d);
        CHECK(pd->d.pgActionID != NULL && IsEqualGUID(pd->d.pgActionID, &WVT_V2));
        EXPECT_EQ(pd->d.cdwTrustStepErrors, 38);
        CHECK(pd->d.padwTrustStepErrors != NULL);
        EXPECT_EQ(pd->d.dwEncoding, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING);
        EXPECT_EQ(pd->d.csSigners, 0);
        CHECK(pd->d.psPfns != NULL);
        if (pd->d.psPfns) { EXPECT_EQ(pd->d.psPfns->cbStruct, sizeof(CRYPT_PROVIDER_FUNCTIONS)); EXPECT_EQ(sizeof(CRYPT_PROVIDER_FUNCTIONS), 0x80);
            CHECK(pd->d.psPfns->pfnAlloc != NULL); CHECK(pd->d.psPfns->pfnFree != NULL); }
        if (pd->d.padwTrustStepErrors) {
            EXPECT_EQ(pd->d.padwTrustStepErrors[TRUSTERROR_STEP_FINAL_WVTINIT], 0);
            EXPECT_EQ(pd->d.padwTrustStepErrors[TRUSTERROR_STEP_FINAL_INITPROV], 0);
        }
        CHECK(pd->d.hProv != 0);
        t_note("unsigned: dwError=0x%08lx dwFinalError=0x%08lx fOpenedFile=%d dwSubjectChoice=%lu",
               (unsigned long)pd->d.dwError, (unsigned long)pd->d.dwFinalError, pd->d.fOpenedFile, (unsigned long)pd->d.dwSubjectChoice);
        if (pd->d.padwTrustStepErrors)
            t_note("step FINAL_OBJPROV=0x%08lx FINAL_POLICYPROV=0x%08lx", (unsigned long)pd->d.padwTrustStepErrors[TRUSTERROR_STEP_FINAL_OBJPROV],
                   (unsigned long)pd->d.padwTrustStepErrors[TRUSTERROR_STEP_FINAL_POLICYPROV]);
    }
    wvt_close(&WVT_V2, &w);
    wvt_del(p);
}
TEST(wvt_hwnd_parent_preserved_with_ui_none) {
    WVT_REQUIRE_WVT();
    WCHAR p[MAX_PATH]; wvt_path(p, "hw.exe"); wvt_write(p, fix_pe_unsigned, sizeof fix_pe_unsigned);
    HWND hs[2] = { NULL, INVALID_HANDLE_VALUE };
    for (int i = 0; i < 2; i++) {
        WVTD w; WINTRUST_FILE_INFO fi; wvt_init_file(&w, &fi, p); w.d.dwStateAction = WTD_STATEACTION_VERIFY;
        SetLastError(0xdeadbeef);
        LONG r = U(WinVerifyTrust)(hs[i], (GUID *)&WVT_V2, &w);
        EXPECT_EQ(r, WVT_E_NOSIGNATURE);
        CRYPT_PROVIDER_DATA *pd = U(WTHelperProvDataFromStateData)(w.d.hWVTStateData);
        CHECK(pd != NULL);
        if (pd) CHECK(pd->hWndParent == hs[i]);
        wvt_close(&WVT_V2, &w);
    }
    wvt_del(p);
}
TEST(wvt_provdata_from_null_state) {
    HANDLE h = NULL;
    if (!U(WTHelperProvDataFromStateData)) { t_skip("missing export"); return; }
    CHECK(U(WTHelperProvDataFromStateData)(h) == NULL);
}

/* ---- SAFER fast path (decomp: WinVerifyTrust pre-check) ---------------------- */
TEST(wvt_safer_flag_ignore_unsigned_pe) {
    WVT_REQUIRE_WVT();
    WCHAR p[MAX_PATH]; WVTD w; WINTRUST_FILE_INFO fi; wvt_path(p, "sf.exe");
    wvt_write(p, fix_pe_unsigned, sizeof fix_pe_unsigned);
    wvt_init_file(&w, &fi, p); w.d.dwProvFlags = WTD_SAFER_FLAG; DWORD e;
    EXPECT_EQ(wvt_call(&WVT_V2, &w, &e), WVT_E_NOSIGNATURE); EXPECT_EQ(e, (DWORD)WVT_E_NOSIGNATURE);
    wvt_del(p);
}
TEST(wvt_safer_flag_mz_stub_is_nosignature) {
    /* A file that starts with MZ but has no valid PE headers: the SAFER pre-check treats it as an unsigned PE. */
    WVT_REQUIRE_WVT();
    static const BYTE mz[64] = { 'M', 'Z' };
    DWORD e; LONG r = wvt_verify_bytes(mz, sizeof mz, WTD_SAFER_FLAG, "mz.exe", &e);
    EXPECT_EQ(r, WVT_E_NOSIGNATURE); EXPECT_EQ(e, (DWORD)WVT_E_NOSIGNATURE);
}
TEST(wvt_mz_stub_without_safer_observed) {
    WVT_REQUIRE_WVT();
    static const BYTE mz[64] = { 'M', 'Z' };
    DWORD e; LONG r = wvt_verify_bytes(mz, sizeof mz, 0, "mz2.exe", &e);
    t_note("MZ stub without SAFER flag -> 0x%08lx", (unsigned long)r);
    CHECK(r != 0);
}
TEST(wvt_safer_flag_non_pe_not_shortcut) {
    WVT_REQUIRE_WVT();
    DWORD e; LONG r = wvt_verify_bytes("plain text", 10, WTD_SAFER_FLAG, "sn.txt", &e);
    EXPECT_EQ(r, WVT_E_NOSIGNATURE); /* Win10: a non-PE subject with SAFER is reported as unsigned, not as a bad subject form */
}
TEST(wvt_safer_flag_signed_pe_takes_full_path) {
    WVT_REQUIRE_WVT();
    DWORD e; LONG r = wvt_verify_bytes(fix_pe_signed, sizeof fix_pe_signed, WTD_SAFER_FLAG, "ss.exe", &e);
    EXPECT_EQ(r, WVT_E_UNTRUSTEDROOT);
}
TEST(wvt_safer_flag_requires_ignore_action) {
    /* with a VERIFY state action the pre-check is skipped; the answer is the same but state is returned */
    WVT_REQUIRE_WVT();
    static const BYTE mz[64] = { 'M', 'Z' };
    WCHAR p[MAX_PATH]; WVTD w; WINTRUST_FILE_INFO fi; wvt_path(p, "sv2.exe"); wvt_write(p, mz, sizeof mz);
    wvt_init_file(&w, &fi, p); w.d.dwProvFlags = WTD_SAFER_FLAG; w.d.dwStateAction = WTD_STATEACTION_VERIFY; DWORD e;
    LONG r = wvt_call(&WVT_V2, &w, &e);
    t_note("MZ stub, SAFER+VERIFY -> 0x%08lx state=%p", (unsigned long)r, w.d.hWVTStateData);
    CHECK(r != 0);
    wvt_close(&WVT_V2, &w); wvt_del(p);
}
TEST(wvt_safer_flag_small_cbstruct_no_shortcut) {
    WVT_REQUIRE_WVT();
    static const BYTE mz[64] = { 'M', 'Z' };
    WCHAR p[MAX_PATH]; WVTD w; WINTRUST_FILE_INFO fi; wvt_path(p, "sm.exe"); wvt_write(p, mz, sizeof mz);
    wvt_init_file(&w, &fi, p); w.d.dwProvFlags = WTD_SAFER_FLAG; w.d.cbStruct = 0x48; DWORD e;
    LONG r = wvt_call(&WVT_V2, &w, &e);
    t_note("MZ stub, SAFER, cbStruct 0x48 -> 0x%08lx", (unsigned long)r);
    CHECK(r != 0);
    wvt_del(p);
}
TEST(wvt_safer_flag_ex_same_shortcut) {
    WVT_REQUIRE_WVT();
    static const BYTE mz[64] = { 'M', 'Z' };
    WCHAR p[MAX_PATH]; WVTD w; WINTRUST_FILE_INFO fi; wvt_path(p, "se.exe"); wvt_write(p, mz, sizeof mz);
    wvt_init_file(&w, &fi, p); w.d.dwProvFlags = WTD_SAFER_FLAG;
    SetLastError(0);
    EXPECT_EQ(U(WinVerifyTrustEx)(NULL, (GUID *)&WVT_V2, &w.d), WVT_E_NOSIGNATURE);
    EXPECT_EQ(GetLastError(), (DWORD)WVT_E_NOSIGNATURE);
    wvt_del(p);
}

/* ---- union choice / auto cache ------------------------------------------- */
TEST(wvt_invalid_union_choice_fails) {
    WVT_REQUIRE_WVT();
    static const DWORD ch[] = { 0, 6, 7, 99, 0xffffffff };
    WCHAR p[MAX_PATH]; wvt_path(p, "uc.exe"); wvt_write(p, fix_pe_unsigned, sizeof fix_pe_unsigned);
    for (int i = 0; i < 5; i++) {
        WVTD w; WINTRUST_FILE_INFO fi; wvt_init_file(&w, &fi, p); w.d.dwUnionChoice = ch[i]; DWORD e;
        LONG r = wvt_call(&WVT_V2, &w, &e);
        t_note("dwUnionChoice=%lu -> 0x%08lx", (unsigned long)ch[i], (unsigned long)r);
        CHECKF(r != 0, "choice %lu", (unsigned long)ch[i]);
    }
    wvt_del(p);
}
TEST(wvt_auto_cache_flush_catalog_returns_ok) {
    /* decomp: AUTO_CACHE_FLUSH with the catalog union flushes and returns 0 before looking at the catalog info */
    WVT_REQUIRE_WVT();
    WVTD w; WINTRUST_CATALOG_INFO ci; memset(&w, 0, sizeof w); memset(&ci, 0, sizeof ci);
    ci.cbStruct = sizeof ci; ci.pcwszCatalogFilePath = L"C:\\no\\such\\catalog.cat"; ci.pcwszMemberFilePath = L"C:\\no\\such\\member.exe";
    ci.pcwszMemberTag = L"tag";
    w.d.cbStruct = sizeof w; w.d.dwUIChoice = WTD_UI_NONE; w.d.dwUnionChoice = WTD_CHOICE_CATALOG; w.d.pCatalog = &ci;
    w.d.dwStateAction = WTD_STATEACTION_AUTO_CACHE_FLUSH; w.d.dwProvFlags = WTD_REVOCATION_CHECK_NONE;
    SetLastError(0xdeadbeef);
    EXPECT_EQ(U(WinVerifyTrust)(NULL, (GUID *)&WVT_V2, &w), 0);
    EXPECT_EQ(GetLastError(), 0x7f);
}
TEST(wvt_auto_cache_flush_twice) {
    WVT_REQUIRE_WVT();
    WVTD w; WINTRUST_CATALOG_INFO ci; memset(&w, 0, sizeof w); memset(&ci, 0, sizeof ci);
    ci.cbStruct = sizeof ci; ci.pcwszCatalogFilePath = L"C:\\x.cat";
    w.d.cbStruct = sizeof w; w.d.dwUIChoice = WTD_UI_NONE; w.d.dwUnionChoice = WTD_CHOICE_CATALOG; w.d.pCatalog = &ci;
    w.d.dwStateAction = WTD_STATEACTION_AUTO_CACHE_FLUSH;
    for (int i = 0; i < 3; i++) EXPECT_EQ(U(WinVerifyTrust)(NULL, (GUID *)&WVT_V2, &w), 0);
}
TEST(wvt_exports_wintrustex_hash_only_signed_ok) {
    WVT_REQUIRE_WVT();
    WCHAR p[MAX_PATH]; WVTD w; WINTRUST_FILE_INFO fi; wvt_path(p, "ho.exe"); wvt_write(p, fix_pe_signed, sizeof fix_pe_signed);
    wvt_init_file(&w, &fi, p); w.d.dwProvFlags |= WTD_HASH_ONLY_FLAG;
    EXPECT_EQ(U(WinVerifyTrustEx)(NULL, (GUID *)&WVT_V2, &w.d), 0);
    wvt_del(p);
}
