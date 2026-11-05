/* Provider callbacks, function-pointer loading, signature state and WTGetSignatureInfo. */
#include "wvt.h"

typedef struct { DWORD cbStruct; HCRYPTMSG *rhSecondarySigs; HCRYPTMSG hPrimarySig; BOOL fFirstAttemptMade, fNoMoreSigs;
    DWORD cSecondarySigs, dwCurrentIndex; BOOL fSupportMultiSig; DWORD dwCryptoPolicySupport, iAttemptCount; BOOL fCheckedSealing; void *pSealingSignature; } WVT_SIGSTATE;

/* ---- WintrustLoadFunctionPointers ---------------------------------------------------------- */
typedef BOOL (WINAPI *loadpfn_t)(GUID *, CRYPT_PROVIDER_FUNCTIONS *);
TEST(wvt_load_function_pointers_args) {
    loadpfn_t f = (loadpfn_t)t_proc("WintrustLoadFunctionPointers"); REQUIRE(f);
    CRYPT_PROVIDER_FUNCTIONS p; memset(&p, 0, sizeof p);
    p.cbStruct = sizeof p;
    CHECK(!f((GUID *)&WVT_V2, NULL));
    p.cbStruct = 0x77; CHECK(!f((GUID *)&WVT_V2, &p));
    p.cbStruct = 0; CHECK(!f((GUID *)&WVT_V2, &p));
    CHECK(p.pfnAlloc == NULL && p.pfnInitialize == NULL);                 /* untouched on failure */
}
TEST(wvt_load_function_pointers_unknown_guid) {
    loadpfn_t f = (loadpfn_t)t_proc("WintrustLoadFunctionPointers"); REQUIRE(f);
    CRYPT_PROVIDER_FUNCTIONS p; memset(&p, 0, sizeof p); p.cbStruct = sizeof p;
    GUID g = { 0x1234abcd, 0x1, 0x2, { 3, 4, 5, 6, 7, 8, 9, 10 } };
    CHECK(!f(&g, &p));
    CHECK(p.pfnInitialize == NULL && p.pfnAlloc == NULL);
}
TEST(wvt_load_function_pointers_generic_verify) {
    loadpfn_t f = (loadpfn_t)t_proc("WintrustLoadFunctionPointers"); REQUIRE(f);
    HMODULE m = t_module("wintrust.dll");
    CRYPT_PROVIDER_FUNCTIONS p; memset(&p, 0, sizeof p); p.cbStruct = sizeof p;
    CHECK(f((GUID *)&WVT_V2, &p));
    CHECK(p.pfnAlloc && p.pfnFree && p.pfnAddStore2Chain && p.pfnAddSgnr2Chain && p.pfnAddCert2Chain && p.pfnAddPrivData2Chain);
    CHECK(p.pfnInitialize == (PFN_PROVIDER_INIT_CALL)GetProcAddress(m, "SoftpubInitialize"));
    CHECK(p.pfnObjectTrust == (PFN_PROVIDER_OBJTRUST_CALL)GetProcAddress(m, "SoftpubLoadMessage"));
    CHECK(p.pfnSignatureTrust == (PFN_PROVIDER_SIGTRUST_CALL)GetProcAddress(m, "SoftpubLoadSignature"));
    CHECK(p.pfnCertificateTrust == (PFN_PROVIDER_CERTTRUST_CALL)GetProcAddress(m, "WintrustCertificateTrust"));
    CHECK(p.pfnCertCheckPolicy == (PFN_PROVIDER_CERTCHKPOLICY_CALL)GetProcAddress(m, "SoftpubCheckCert"));
    CHECK(p.pfnFinalPolicy != NULL);
    t_note("V2 final policy=%p ConfigCiFinalPolicy=%p SoftpubAuthenticode=%p cleanup=%p", (void *)p.pfnFinalPolicy,
           (void *)GetProcAddress(m, "ConfigCiFinalPolicy"), (void *)GetProcAddress(m, "SoftpubAuthenticode"), (void *)p.pfnCleanupPolicy);
}
TEST(wvt_load_function_pointers_cleanup_only_for_large_struct) {
    loadpfn_t f = (loadpfn_t)t_proc("WintrustLoadFunctionPointers"); REQUIRE(f);
    CRYPT_PROVIDER_FUNCTIONS p; memset(&p, 0, sizeof p);
    p.cbStruct = 0x78; p.pfnCleanupPolicy = (PFN_PROVIDER_CLEANUP_CALL)(ULONG_PTR)0x1234;
    CHECK(f((GUID *)&WVT_V2, &p));
    CHECK(p.pfnCleanupPolicy == (PFN_PROVIDER_CLEANUP_CALL)(ULONG_PTR)0x1234);   /* cbStruct 0x78 does not reach the cleanup slot */
    CHECK(p.pfnTestFinalPolicy == p.pfnTestFinalPolicy);
    p.cbStruct = 0x80;
    CHECK(f((GUID *)&WVT_V2, &p));
    CHECK(p.pfnCleanupPolicy != (PFN_PROVIDER_CLEANUP_CALL)(ULONG_PTR)0x1234);
}
TEST(wvt_load_function_pointers_alloc_free_work) {
    loadpfn_t f = (loadpfn_t)t_proc("WintrustLoadFunctionPointers"); REQUIRE(f);
    CRYPT_PROVIDER_FUNCTIONS p; memset(&p, 0, sizeof p); p.cbStruct = sizeof p;
    if (!f((GUID *)&WVT_V2, &p)) { CHECK(0); return; }
    for (int i = 1; i < 200; i += 37) { BYTE *b = (BYTE *)p.pfnAlloc(i); CHECK(b != NULL); if (b) { memset(b, 0xa5, i); p.pfnFree(b); } }
}
TEST(wvt_load_function_pointers_other_known_actions) {
    loadpfn_t f = (loadpfn_t)t_proc("WintrustLoadFunctionPointers"); REQUIRE(f);
    const GUID *g[] = { &WVT_CERTV, &WVT_CHAINV, &WVT_HTTPS, &WVT_DRIVER, &WVT_TPTEST };
    for (int i = 0; i < 5; i++) {
        CRYPT_PROVIDER_FUNCTIONS p; memset(&p, 0, sizeof p); p.cbStruct = sizeof p;
        BOOL r = f((GUID *)g[i], &p);
        t_note("action %d: loaded=%d init=%p final=%p", i, r, (void *)p.pfnInitialize, (void *)p.pfnFinalPolicy);
        if (r) CHECK(p.pfnAlloc != NULL && p.pfnInitialize != NULL);
    }
}

/* ---- provider callbacks on synthetic data ----------------------------------------------------- */
TEST(wvt_softpub_check_cert_sets_flag) {
    BOOL (WINAPI *f)(CRYPT_PROVIDER_DATA *, DWORD, BOOL, DWORD) = (void *)t_proc("SoftpubCheckCert"); REQUIRE(f);
    WVT_PD pd; memset(&pd, 0, sizeof pd); pd.d.cbStruct = sizeof pd;
    CHECK(f(&pd.d, 0, FALSE, 0)); EXPECT_EQ(pd.d.dwProvFlags, 0x80000000);
    pd.d.dwProvFlags = 0x1234; CHECK(f(&pd.d, 0, FALSE, 0)); EXPECT_EQ(pd.d.dwProvFlags, 0x80001234);
    CHECK(f(&pd.d, 5, TRUE, 9)); EXPECT_EQ(pd.d.dwProvFlags, 0x80001234);       /* idempotent, indexes ignored */
}
TEST(wvt_softpub_initialize_no_step_errors) {
    HRESULT (WINAPI *f)(CRYPT_PROVIDER_DATA *) = (void *)t_proc("SoftpubInitialize"); REQUIRE(f);
    WVT_PD pd; memset(&pd, 0, sizeof pd); pd.d.cbStruct = sizeof pd;
    CHECK(f(&pd.d) != 0);                                    /* no padwTrustStepErrors */
    DWORD steps[38]; memset(steps, 0, sizeof steps); steps[TRUSTERROR_STEP_FINAL_WVTINIT] = 5;
    pd.d.padwTrustStepErrors = steps; pd.d.cdwTrustStepErrors = 38;
    CHECK(f(&pd.d) != 0);                                    /* a previous WVTINIT error aborts */
}
TEST(wvt_softpub_initialize_cert_choice) {
    HRESULT (WINAPI *f)(CRYPT_PROVIDER_DATA *) = (void *)t_proc("SoftpubInitialize"); REQUIRE(f);
    WVT_PD pd; WVTD w; WINTRUST_CERT_INFO ci; DWORD steps[38]; memset(&pd, 0, sizeof pd); memset(&w, 0, sizeof w); memset(&ci, 0, sizeof ci); memset(steps, 0, sizeof steps);
    w.d.cbStruct = sizeof w; w.d.dwUnionChoice = WTD_CHOICE_CERT; w.d.pCert = &ci;
    pd.d.cbStruct = sizeof pd; pd.d.pWintrustData = &w.d; pd.d.padwTrustStepErrors = steps; pd.d.cdwTrustStepErrors = 38;
    steps[TRUSTERROR_STEP_FINAL_INITPROV] = 0x1111; steps[TRUSTERROR_STEP_FILEIO] = 0x2222;
    EXPECT_EQ(f(&pd.d), 0);
    EXPECT_EQ(steps[TRUSTERROR_STEP_FINAL_INITPROV], 0); EXPECT_EQ(steps[TRUSTERROR_STEP_FILEIO], 0);
    CHECK(pd.d.pszUsageOID != NULL);
    if (pd.d.pszUsageOID) EXPECT_STR(pd.d.pszUsageOID, "1.3.6.1.5.5.7.3.3");
}
TEST(wvt_softpub_initialize_small_provider_struct_keeps_usage) {
    HRESULT (WINAPI *f)(CRYPT_PROVIDER_DATA *) = (void *)t_proc("SoftpubInitialize"); REQUIRE(f);
    WVT_PD pd; WVTD w; WINTRUST_CERT_INFO ci; DWORD steps[38]; memset(&pd, 0, sizeof pd); memset(&w, 0, sizeof w); memset(&ci, 0, sizeof ci); memset(steps, 0, sizeof steps);
    w.d.cbStruct = sizeof w; w.d.dwUnionChoice = WTD_CHOICE_CERT; w.d.pCert = &ci;
    pd.d.cbStruct = 0xa8; pd.d.pWintrustData = &w.d; pd.d.padwTrustStepErrors = steps; pd.d.cdwTrustStepErrors = 38;
    EXPECT_EQ(f(&pd.d), 0);
    CHECK(pd.d.pszUsageOID == NULL);
}
TEST(wvt_softpub_initialize_unknown_choice_ok) {
    HRESULT (WINAPI *f)(CRYPT_PROVIDER_DATA *) = (void *)t_proc("SoftpubInitialize"); REQUIRE(f);
    static const DWORD ch[] = { 0, 4, 5, 6, 77 };
    for (int i = 0; i < 5; i++) {
        WVT_PD pd; WVTD w; DWORD steps[38]; memset(&pd, 0, sizeof pd); memset(&w, 0, sizeof w); memset(steps, 0, sizeof steps);
        w.d.cbStruct = sizeof w; w.d.dwUnionChoice = ch[i];
        pd.d.cbStruct = sizeof pd; pd.d.pWintrustData = &w.d; pd.d.padwTrustStepErrors = steps; pd.d.cdwTrustStepErrors = 38;
        CHECKF(f(&pd.d) == 0, "union choice %lu", (unsigned long)ch[i]);
    }
}
TEST(wvt_certificate_trust_no_signers) {
    HRESULT (WINAPI *f)(CRYPT_PROVIDER_DATA *) = (void *)t_proc("WintrustCertificateTrust"); REQUIRE(f);
    WVT_PD pd; WVT_SIGSTATE ss; DWORD steps[38]; memset(&pd, 0, sizeof pd); memset(&ss, 0, sizeof ss); memset(steps, 0, sizeof steps);
    pd.d.cbStruct = sizeof pd; pd.pSigState = &ss; pd.d.padwTrustStepErrors = steps; pd.d.cdwTrustStepErrors = 38;
    CHECK(f(&pd.d) != 0);
    EXPECT_EQ(steps[TRUSTERROR_STEP_FINAL_CERTPROV], (DWORD)WVT_E_NOSIGNATURE);
    EXPECT_EQ(ss.dwCryptoPolicySupport, 4);                  /* WSS_CERTTRUST_SUPPORT */
}
TEST(wvt_certificate_trust_marks_sigstate_cumulatively) {
    HRESULT (WINAPI *f)(CRYPT_PROVIDER_DATA *) = (void *)t_proc("WintrustCertificateTrust"); REQUIRE(f);
    WVT_PD pd; WVT_SIGSTATE ss; DWORD steps[38]; memset(&pd, 0, sizeof pd); memset(&ss, 0, sizeof ss); memset(steps, 0, sizeof steps);
    pd.d.cbStruct = sizeof pd; pd.pSigState = &ss; pd.d.padwTrustStepErrors = steps; ss.dwCryptoPolicySupport = 3;
    f(&pd.d);
    EXPECT_EQ(ss.dwCryptoPolicySupport, 7);
}

/* ---- signature state after a real verification --------------------------------------------------- */
TEST(wvt_state_signature_state_after_signed_verify) {
    WVT_REQUIRE_WVT();
    WCHAR p[MAX_PATH]; WVTD w; WINTRUST_FILE_INFO fi; DWORD e; wvt_path(p, "sg.exe"); wvt_write(p, fix_pe_signed, sizeof fix_pe_signed);
    wvt_init_file(&w, &fi, p); w.d.dwStateAction = WTD_STATEACTION_VERIFY;
    LONG r = wvt_call(&WVT_V2, &w, &e);
    WVT_PD *pd = (WVT_PD *)U(WTHelperProvDataFromStateData)(w.d.hWVTStateData);
    CHECK(r == WVT_E_UNTRUSTEDROOT && pd != NULL);
    if (pd && pd->d.cbStruct == sizeof *pd) {
        WVT_SIGSTATE *ss = (WVT_SIGSTATE *)pd->pSigState;
        CHECK(ss != NULL);
        if (ss) {
            EXPECT_EQ(ss->cbStruct, sizeof(WVT_SIGSTATE));
            CHECK(ss->fSupportMultiSig);
            EXPECT_EQ(ss->dwCryptoPolicySupport, 7);
            EXPECT_EQ(ss->cSecondarySigs, 0);
            CHECK(ss->hPrimarySig != NULL);
            CHECK(ss->hPrimarySig == pd->d.hMsg);
            t_note("sigstate: fFirstAttemptMade=%d fNoMoreSigs=%d dwCurrentIndex=%lu iAttemptCount=%lu fCheckedSealing=%d",
                   ss->fFirstAttemptMade, ss->fNoMoreSigs, (unsigned long)ss->dwCurrentIndex, (unsigned long)ss->iAttemptCount, ss->fCheckedSealing);
        }
        CHECK(pd->pSigSettings == NULL || pd->pSigSettings == w.pSignatureSettings);
    }
    wvt_close(&WVT_V2, &w); wvt_del(p);
}
TEST(wvt_state_signature_state_unsigned) {
    WVT_REQUIRE_WVT();
    WCHAR p[MAX_PATH]; WVTD w; WINTRUST_FILE_INFO fi; DWORD e; wvt_path(p, "sg2.exe"); wvt_write(p, fix_pe_unsigned, sizeof fix_pe_unsigned);
    wvt_init_file(&w, &fi, p); w.d.dwStateAction = WTD_STATEACTION_VERIFY; wvt_call(&WVT_V2, &w, &e);
    WVT_PD *pd = (WVT_PD *)U(WTHelperProvDataFromStateData)(w.d.hWVTStateData);
    if (pd && pd->d.cbStruct == sizeof *pd && pd->pSigState) {
        WVT_SIGSTATE *ss = (WVT_SIGSTATE *)pd->pSigState;
        CHECK(ss->dwCryptoPolicySupport & 1);                /* the object provider ran */
        EXPECT_EQ(ss->dwCryptoPolicySupport, 7);
        EXPECT_EQ(ss->cSecondarySigs, 0);
    } else CHECK(pd != NULL);
    wvt_close(&WVT_V2, &w); wvt_del(p);
}

/* ---- WTGetSignatureInfo --------------------------------------------------------------------------- */
typedef HRESULT (WINAPI *getsiginfo_t)(const WCHAR *, HANDLE, DWORD, void *, PCCERT_CONTEXT *, HANDLE *);
#define SIF_AUTHENTICODE_SIGNED 0x00000001
#define SIF_CATALOG_SIGNED      0x00000002
#define SIF_VERSION_INFO        0x00000004
#define SIGINFO_CB 0x58
TEST(wvt_getsignatureinfo_invalid_arguments) {
    getsiginfo_t f = (getsiginfo_t)t_proc("WTGetSignatureInfo"); REQUIRE(f);
    BYTE si[SIGINFO_CB]; memset(si, 0, sizeof si); *(DWORD *)si = SIGINFO_CB;
    PCCERT_CONTEXT c = (PCCERT_CONTEXT)(ULONG_PTR)1; HANDLE st = (HANDLE)(ULONG_PTR)1;
    EXPECT_EQ(f(NULL, INVALID_HANDLE_VALUE, SIF_AUTHENTICODE_SIGNED, si, &c, &st), (ULONG_PTR)WVT_E_INVALIDARG);
    CHECK(c == NULL && st == NULL);                           /* out parameters are cleared first */
    c = (PCCERT_CONTEXT)(ULONG_PTR)1; st = (HANDLE)(ULONG_PTR)1;
    EXPECT_EQ(f(L"C:\\x", INVALID_HANDLE_VALUE, SIF_AUTHENTICODE_SIGNED, NULL, &c, &st), (ULONG_PTR)WVT_E_INVALIDARG);
    CHECK(c == NULL && st == NULL);
    *(DWORD *)si = SIGINFO_CB - 1;
    EXPECT_EQ(f(L"C:\\x", INVALID_HANDLE_VALUE, SIF_AUTHENTICODE_SIGNED, si, NULL, NULL), (ULONG_PTR)WVT_E_INVALIDARG);
    *(DWORD *)si = 0;
    EXPECT_EQ(f(L"C:\\x", INVALID_HANDLE_VALUE, SIF_AUTHENTICODE_SIGNED, si, NULL, NULL), (ULONG_PTR)WVT_E_INVALIDARG);
    *(DWORD *)si = SIGINFO_CB;
}
TEST(wvt_getsignatureinfo_invalid_flags) {
    getsiginfo_t f = (getsiginfo_t)t_proc("WTGetSignatureInfo"); REQUIRE(f);
    BYTE si[SIGINFO_CB]; memset(si, 0, sizeof si); *(DWORD *)si = SIGINFO_CB;
    static const DWORD fl[] = { 0, 8, 0x10, 0x10000, 0x20000, 0x40000, 0x80000, 0xfffffff8 };
    for (int i = 0; i < 8; i++) {
        HRESULT hr = f(L"C:\\x", INVALID_HANDLE_VALUE, fl[i], si, NULL, NULL);
        CHECKF(hr == (HRESULT)WVT_E_INVALIDARG, "flags 0x%lx -> 0x%08lx", (unsigned long)fl[i], (unsigned long)hr);
    }
}
TEST(wvt_getsignatureinfo_larger_cbsize_accepted) {
    getsiginfo_t f = (getsiginfo_t)t_proc("WTGetSignatureInfo"); REQUIRE(f);
    BYTE si[SIGINFO_CB + 16]; memset(si, 0, sizeof si); *(DWORD *)si = sizeof si;
    WCHAR p[MAX_PATH]; wvt_path(p, "gs0.exe"); wvt_del(p);
    HRESULT hr = f(p, INVALID_HANDLE_VALUE, SIF_AUTHENTICODE_SIGNED, si, NULL, NULL);
    CHECK(hr != (HRESULT)WVT_E_INVALIDARG);
}
TEST(wvt_getsignatureinfo_missing_file) {
    getsiginfo_t f = (getsiginfo_t)t_proc("WTGetSignatureInfo"); REQUIRE(f);
    BYTE si[SIGINFO_CB]; memset(si, 0xAA, sizeof si); *(DWORD *)si = SIGINFO_CB;
    WCHAR p[MAX_PATH]; wvt_path(p, "gs1.exe"); wvt_del(p);
    PCCERT_CONTEXT c = (PCCERT_CONTEXT)(ULONG_PTR)1; HANDLE st = (HANDLE)(ULONG_PTR)1;
    HRESULT hr = f(p, INVALID_HANDLE_VALUE, SIF_AUTHENTICODE_SIGNED, si, &c, &st);
    EXPECT_EQ(hr, (ULONG_PTR)HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND));
    CHECK(c == NULL && st == NULL);
}
TEST(wvt_getsignatureinfo_unsigned_pe) {
    getsiginfo_t f = (getsiginfo_t)t_proc("WTGetSignatureInfo"); REQUIRE(f);
    BYTE si[SIGINFO_CB]; memset(si, 0xAA, sizeof si); *(DWORD *)si = SIGINFO_CB;
    WCHAR p[MAX_PATH]; wvt_path(p, "gs2.exe"); wvt_write(p, fix_pe_unsigned, sizeof fix_pe_unsigned);
    PCCERT_CONTEXT c = NULL; HANDLE st = NULL;
    HRESULT hr = f(p, INVALID_HANDLE_VALUE, SIF_AUTHENTICODE_SIGNED, si, &c, &st);
    DWORD *d = (DWORD *)si;
    t_note("unsigned PE: hr=0x%08lx state=%lu type=%lu avail=0x%lx avail2=0x%lx cert=%p", (unsigned long)hr, (unsigned long)d[1], (unsigned long)d[2], (unsigned long)d[3], (unsigned long)d[4], c);
    EXPECT_EQ(d[0], SIGINFO_CB);
    CHECK(c == NULL);
    EXPECT_EQ(d[4], d[3]);                                    /* dwInfoAvailability mirrors dwSignatureInfoAvailability */
    wvt_del(p);
}
TEST(wvt_getsignatureinfo_signed_pe) {
    getsiginfo_t f = (getsiginfo_t)t_proc("WTGetSignatureInfo"); REQUIRE(f);
    /* the structure must be zeroed: Win10 dereferences members of the output structure for a signed image */
    BYTE si[SIGINFO_CB]; memset(si, 0, sizeof si); *(DWORD *)si = SIGINFO_CB;
    WCHAR p[MAX_PATH]; wvt_path(p, "gs3.exe"); wvt_write(p, fix_pe_signed, sizeof fix_pe_signed);
    PCCERT_CONTEXT c = NULL; HANDLE st = NULL;
    HRESULT hr = f(p, INVALID_HANDLE_VALUE, SIF_AUTHENTICODE_SIGNED, si, &c, &st);
    DWORD *d = (DWORD *)si;
    t_note("signed PE: hr=0x%08lx state=%lu type=%lu avail=0x%lx avail2=0x%lx cert=%p", (unsigned long)hr, (unsigned long)d[1], (unsigned long)d[2], (unsigned long)d[3], (unsigned long)d[4], c);
    EXPECT_EQ(hr, 0); EXPECT_EQ(d[1], 2); EXPECT_EQ(d[2], 1); EXPECT_EQ(d[3], 0);
    EXPECT_EQ(d[4], d[3]);
    REQUIRE_NOTNULL(c);
    CHECK(c->cbCertEncoded == sizeof fix_cert_self && !memcmp(c->pbCertEncoded, fix_cert_self, sizeof fix_cert_self));
    U(CertFreeCertificateContext)(c);
    wvt_del(p);
}
TEST(wvt_getsignatureinfo_caller_handle) {
    getsiginfo_t f = (getsiginfo_t)t_proc("WTGetSignatureInfo"); REQUIRE(f);
    BYTE si[SIGINFO_CB]; memset(si, 0, sizeof si); *(DWORD *)si = SIGINFO_CB;
    WCHAR p[MAX_PATH]; wvt_path(p, "gs4.exe"); wvt_write(p, fix_pe_unsigned, sizeof fix_pe_unsigned);
    HANDLE h = CreateFileW(p, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    HRESULT hr = f(p, h, SIF_AUTHENTICODE_SIGNED, si, NULL, NULL);
    t_note("caller handle: hr=0x%08lx", (unsigned long)hr);
    DWORD sz = GetFileSize(h, NULL); EXPECT_EQ(sz, sizeof fix_pe_unsigned);    /* handle is not closed */
    CloseHandle(h); wvt_del(p);
}
TEST(wvt_getsignatureinfo_version_info_only_flag) {
    getsiginfo_t f = (getsiginfo_t)t_proc("WTGetSignatureInfo"); REQUIRE(f);
    BYTE si[SIGINFO_CB]; memset(si, 0, sizeof si); *(DWORD *)si = SIGINFO_CB;
    WCHAR p[MAX_PATH]; wvt_path(p, "gs5.exe"); wvt_write(p, fix_pe_unsigned, sizeof fix_pe_unsigned);
    HRESULT hr = f(p, INVALID_HANDLE_VALUE, SIF_VERSION_INFO, si, NULL, NULL);
    t_note("version-info-only on a PE without a version resource: hr=0x%08lx", (unsigned long)hr);
    DWORD *d = (DWORD *)si; EXPECT_EQ(d[1], 0); EXPECT_EQ(d[2], 0);       /* no signature state requested */
    wvt_del(p);
}

/* ---- WTConvertCertCtxToChainInfo ------------------------------------------------------------------------- */
TEST(wvt_convert_cert_ctx_to_chain_info_observed) {
    LONG (WINAPI *f)(void *, PCCERT_CONTEXT, void *) = (void *)t_proc("WTConvertCertCtxToChainInfo"); REQUIRE(f);
    PCCERT_CONTEXT c = U(CertCreateCertificateContext)(X509_ASN_ENCODING, fix_cert_leaf, sizeof fix_cert_leaf); if (!c) { CHECK(0); return; }
    BYTE info[0x38]; memset(info, 0xEE, sizeof info);
    /* Win10 dereferences the first argument unconditionally (read at offset 0xc8 of NULL) */
    T_EXPECT_FAULT(f(NULL, c, info));
    U(CertFreeCertificateContext)(c);
}
