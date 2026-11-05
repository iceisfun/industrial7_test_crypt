/* WinVerifyTrust against an embedded, Authenticode-signed (self-signed, SHA-256) PE32+ image. */
#include "wvt.h"

static LONG verify_signed_state(WVTD *w, WINTRUST_FILE_INFO *fi, const WCHAR *p, DWORD flags, DWORD *err) {
    wvt_init_file(w, fi, p); w->d.dwStateAction = WTD_STATEACTION_VERIFY; w->d.dwProvFlags |= flags;
    return wvt_call(&WVT_V2, w, err);
}
static void put_signed(WCHAR *p, const char *leaf) { wvt_path(p, leaf); wvt_write(p, fix_pe_signed, sizeof fix_pe_signed); }

TEST(wvt_signed_selfsigned_untrusted_root) {
    WVT_REQUIRE_WVT();
    DWORD e; LONG r = wvt_verify_bytes(fix_pe_signed, sizeof fix_pe_signed, 0, "s1.exe", &e);
    EXPECT_EQ(r, WVT_E_UNTRUSTEDROOT); EXPECT_EQ(e, (DWORD)WVT_E_UNTRUSTEDROOT);
}
TEST(wvt_signed_selfsigned_ex) {
    WVT_REQUIRE_WVT();
    WCHAR p[MAX_PATH]; WVTD w; WINTRUST_FILE_INFO fi; put_signed(p, "s2.exe"); wvt_init_file(&w, &fi, p);
    SetLastError(0);
    EXPECT_EQ(U(WinVerifyTrustEx)(NULL, (GUID *)&WVT_V2, &w.d), WVT_E_UNTRUSTEDROOT);
    EXPECT_EQ(GetLastError(), (DWORD)WVT_E_UNTRUSTEDROOT);
    wvt_del(p);
}
TEST(wvt_signed_hash_only_succeeds) {
    WVT_REQUIRE_WVT();
    DWORD e; LONG r = wvt_verify_bytes(fix_pe_signed, sizeof fix_pe_signed, WTD_HASH_ONLY_FLAG, "s3.exe", &e);
    EXPECT_EQ(r, 0); EXPECT_EQ(e, 0);
}
TEST(wvt_signed_cache_only_and_no_revocation_flags) {
    WVT_REQUIRE_WVT();
    static const DWORD fl[] = { WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_REVOCATION_CHECK_NONE, WTD_DISABLE_MD2_MD4,
        WTD_USE_DEFAULT_OSVER_CHECK, WTD_NO_POLICY_USAGE_FLAG, WTD_USE_IE4_TRUST_FLAG | WTD_NO_IE4_CHAIN_FLAG };
    WCHAR p[MAX_PATH]; put_signed(p, "s4.exe");
    for (unsigned i = 0; i < sizeof fl / sizeof fl[0]; i++) {
        WVTD w; WINTRUST_FILE_INFO fi; wvt_init_file(&w, &fi, p); w.d.dwProvFlags = fl[i]; DWORD e;
        LONG r = wvt_call(&WVT_V2, &w, &e);
        t_label("flags 0x%lx", (unsigned long)fl[i]);
        EXPECT_EQ(r, WVT_E_UNTRUSTEDROOT);
    }
    wvt_del(p);
}
TEST(wvt_signed_revocation_whole_chain_cache_only) {
    WVT_REQUIRE_WVT();
    WCHAR p[MAX_PATH]; WVTD w; WINTRUST_FILE_INFO fi; put_signed(p, "s5.exe"); wvt_init_file(&w, &fi, p);
    w.d.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN; w.d.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
    DWORD e; LONG r = wvt_call(&WVT_V2, &w, &e);
    /* the chain is untrusted before revocation matters */
    CHECKF(r == WVT_E_UNTRUSTEDROOT, "got 0x%08lx", (unsigned long)r);
    wvt_del(p);
}

/* ---- tampering ---------------------------------------------------------- */
static LONG verify_modified(DWORD off, BYTE x, DWORD flags, const char *leaf) {
    BYTE *b = (BYTE *)HeapAlloc(GetProcessHeap(), 0, sizeof fix_pe_signed); DWORD e;
    memcpy(b, fix_pe_signed, sizeof fix_pe_signed); b[off] ^= x;
    LONG r = wvt_verify_bytes(b, sizeof fix_pe_signed, flags, leaf, &e);
    HeapFree(GetProcessHeap(), 0, b); return r;
}
TEST(wvt_tamper_code_byte_bad_digest) {
    WVT_REQUIRE_WVT();
    EXPECT_EQ(verify_modified(0x200, 0x01, 0, "m1.exe"), WVT_E_BAD_DIGEST);
    /* Win10: with HASH_ONLY the tampered image is reported as having no signature, not as a bad digest */
    EXPECT_EQ(verify_modified(0x200, 0x01, WTD_HASH_ONLY_FLAG, "m2.exe"), WVT_E_NOSIGNATURE);
}
TEST(wvt_tamper_section_padding_bad_digest) {
    WVT_REQUIRE_WVT();
    EXPECT_EQ(verify_modified(0x3ff, 0x80, 0, "m3.exe"), WVT_E_BAD_DIGEST);
}
TEST(wvt_tamper_header_timestamp_bad_digest) {
    WVT_REQUIRE_WVT();
    EXPECT_EQ(verify_modified(0x48, 0xff, WTD_HASH_ONLY_FLAG, "m4.exe"), WVT_E_NOSIGNATURE); /* TimeDateStamp */
}
TEST(wvt_tamper_dos_stub_bad_digest) {
    WVT_REQUIRE_WVT();
    EXPECT_EQ(verify_modified(0x10, 0x55, WTD_HASH_ONLY_FLAG, "m5.exe"), WVT_E_NOSIGNATURE);
}
TEST(wvt_tamper_section_header_bad_digest) {
    WVT_REQUIRE_WVT();
    EXPECT_EQ(verify_modified(0x148 + 8, 0x01, WTD_HASH_ONLY_FLAG, "m6.exe"), WVT_E_NOSIGNATURE); /* VirtualSize */
}
TEST(wvt_checksum_field_not_hashed) {
    /* Authenticode excludes the optional-header CheckSum from the image digest */
    WVT_REQUIRE_WVT();
    EXPECT_EQ(verify_modified(0x58 + 64, 0xa5, WTD_HASH_ONLY_FLAG, "m7.exe"), 0);
    EXPECT_EQ(verify_modified(0x58 + 67, 0x01, 0, "m8.exe"), WVT_E_UNTRUSTEDROOT);
}
TEST(wvt_tamper_signature_value_fails) {
    WVT_REQUIRE_WVT();
    /* flip a bit inside the RSA signature (last bytes of the PKCS#7 blob, before the 8-byte padding) */
    DWORD off = sizeof fix_pe_signed - 8 - 40;
    LONG r = verify_modified(off, 0x04, 0, "m9.exe");
    EXPECT_EQ(r, WVT_E_NOSIGNATURE);
}
TEST(wvt_tamper_embedded_digest_fails) {
    WVT_REQUIRE_WVT();
    /* flip a byte inside the SpcIndirectData digest (first 0x100 bytes of the blob contain it) */
    BYTE *b = (BYTE *)HeapAlloc(GetProcessHeap(), 0, sizeof fix_pe_signed);
    memcpy(b, fix_pe_signed, sizeof fix_pe_signed);
    DWORD off = 0; for (DWORD i = 0x408; i < 0x700; i++) if (!memcmp(b + i, fix_pe_sha256, 32)) { off = i; break; }
    CHECK(off != 0);
    if (off) { b[off + 3] ^= 1; DWORD e; LONG r = wvt_verify_bytes(b, sizeof fix_pe_signed, 0, "m10.exe", &e);
        EXPECT_EQ(r, WVT_E_BAD_DIGEST); }
    HeapFree(GetProcessHeap(), 0, b);
}
TEST(wvt_unsigned_twin_nosignature) {
    WVT_REQUIRE_WVT();
    DWORD e; EXPECT_EQ(wvt_verify_bytes(fix_pe_unsigned, sizeof fix_pe_unsigned, WTD_HASH_ONLY_FLAG, "m11.exe", &e), WVT_E_NOSIGNATURE);
}
TEST(wvt_signed_trailing_garbage_observed) {
    WVT_REQUIRE_WVT();
    BYTE *b = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof fix_pe_signed + 16); DWORD e;
    memcpy(b, fix_pe_signed, sizeof fix_pe_signed); memset(b + sizeof fix_pe_signed, 0xAB, 16);
    LONG r = wvt_verify_bytes(b, sizeof fix_pe_signed + 16, 0, "m12.exe", &e);
    EXPECT_EQ(r, WVT_E_NOSIGNATURE);
    HeapFree(GetProcessHeap(), 0, b);
}
TEST(wvt_signed_cert_table_truncated) {
    WVT_REQUIRE_WVT();
    DWORD e; LONG r = wvt_verify_bytes(fix_pe_signed, sizeof fix_pe_signed - 100, WTD_HASH_ONLY_FLAG, "m13.exe", &e);
    EXPECT_EQ(r, WVT_E_NOSIGNATURE);
}

/* ---- state, provider data ------------------------------------------------- */
#define SIGNED_STATE_PROLOGUE \
    WVT_REQUIRE_WVT(); \
    WCHAR p[MAX_PATH]; WVTD w; WINTRUST_FILE_INFO fi; DWORD e; put_signed(p, "st.exe"); \
    LONG r = verify_signed_state(&w, &fi, p, 0, &e); \
    WVT_PD *pd = (WVT_PD *)U(WTHelperProvDataFromStateData)(w.d.hWVTStateData); \
    if (r != WVT_E_UNTRUSTEDROOT || !pd) { CHECKF(0, "setup r=0x%08lx pd=%p", (unsigned long)r, pd); wvt_close(&WVT_V2, &w); wvt_del(p); return; }
#define SIGNED_STATE_EPILOGUE wvt_close(&WVT_V2, &w); wvt_del(p);

TEST(wvt_state_signers_and_certs) {
    SIGNED_STATE_PROLOGUE
    EXPECT_EQ(pd->d.csSigners, 1);
    CHECK(pd->d.pasSigners != NULL);
    CRYPT_PROVIDER_SGNR *s0 = U(WTHelperGetProvSignerFromChain)(&pd->d, 0, FALSE, 0);
    CHECK(s0 == pd->d.pasSigners);
    CHECK(U(WTHelperGetProvSignerFromChain)(&pd->d, 1, FALSE, 0) == NULL);
    CHECK(U(WTHelperGetProvSignerFromChain)(&pd->d, 0xffffffff, FALSE, 0) == NULL);
    CHECK(U(WTHelperGetProvSignerFromChain)(&pd->d, 0, TRUE, 0) == NULL);
    CHECK(U(WTHelperGetProvSignerFromChain)(&pd->d, 0, TRUE, 5) == NULL);
    CHECK(U(WTHelperGetProvSignerFromChain)(NULL, 0, FALSE, 0) == NULL);
    if (s0) {
        EXPECT_EQ(s0->csCounterSigners, 0);
        EXPECT_EQ(s0->csCertChain, 1);
        CRYPT_PROVIDER_CERT *c0 = U(WTHelperGetProvCertFromChain)(s0, 0);
        CHECK(c0 == s0->pasCertChain && c0 != NULL);
        CHECK(U(WTHelperGetProvCertFromChain)(s0, 1) == NULL);
        CHECK(U(WTHelperGetProvCertFromChain)(s0, 0xffffffff) == NULL);
        CHECK(U(WTHelperGetProvCertFromChain)(NULL, 0) == NULL);
        CHECK(U(WTHelperGetProvCertFromChain)(NULL, 1) == NULL);
        EXPECT_EQ(s0->cbStruct, 64); EXPECT_EQ(s0->dwError, 0);
        EXPECT_EQ(s0->dwSignerType, 0);
        CHECK(s0->psSigner != NULL);
        CHECK(s0->pChainContext != NULL);
        if (c0) {
            CHECK(c0->pCert != NULL);
            CHECK(c0->fSelfSigned);
            CHECK(!c0->fTrustedRoot);
            CHECK(!c0->fTestCert);
            EXPECT_EQ(c0->dwError, (DWORD)WVT_E_UNTRUSTEDROOT); EXPECT_EQ(c0->dwConfidence, 0x11100000); EXPECT_EQ(c0->dwRevokedReason, 0);
        }
    }
    SIGNED_STATE_EPILOGUE
}
TEST(wvt_state_signer_cert_identity) {
    SIGNED_STATE_PROLOGUE
    CRYPT_PROVIDER_SGNR *s0 = U(WTHelperGetProvSignerFromChain)(&pd->d, 0, FALSE, 0);
    CRYPT_PROVIDER_CERT *c0 = s0 ? U(WTHelperGetProvCertFromChain)(s0, 0) : NULL;
    if (c0 && c0->pCert) {
        CERT_INFO *ci = c0->pCert->pCertInfo;
        static const BYTE ser[2] = { 0x01, 0x10 };
        EXPECT_EQ(ci->SerialNumber.cbData, 2);
        if (ci->SerialNumber.cbData == 2) CHECK(!memcmp(ci->SerialNumber.pbData, ser, 2));
        WCHAR nm[128] = {0};
        DWORD n = U(CertGetNameStringW)(c0->pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, nm, 128);
        CHECK(n > 1); EXPECT_WSTR(nm, L"cryptt WVT self-signed signer");
        CHECK(c0->pCert->cbCertEncoded == sizeof fix_cert_self);
        if (c0->pCert->cbCertEncoded == sizeof fix_cert_self) CHECK(!memcmp(c0->pCert->pbCertEncoded, fix_cert_self, sizeof fix_cert_self));
    } else CHECK(0);
    if (s0 && s0->psSigner) {
        static const BYTE ser[2] = { 0x01, 0x10 };
        EXPECT_EQ(s0->psSigner->SerialNumber.cbData, 2);
        if (s0->psSigner->SerialNumber.cbData == 2) CHECK(!memcmp(s0->psSigner->SerialNumber.pbData, ser, 2));
        EXPECT_STR(s0->psSigner->HashAlgorithm.pszObjId, "2.16.840.1.101.3.4.2.1");
        EXPECT_STR(s0->psSigner->HashEncryptionAlgorithm.pszObjId, "1.2.840.113549.1.1.1");
        EXPECT_EQ(s0->psSigner->dwVersion, 1);
        CHECK(s0->psSigner->AuthAttrs.cAttr >= 2);
    }
    SIGNED_STATE_EPILOGUE
}
TEST(wvt_state_chain_context) {
    SIGNED_STATE_PROLOGUE
    CRYPT_PROVIDER_SGNR *s0 = U(WTHelperGetProvSignerFromChain)(&pd->d, 0, FALSE, 0);
    if (s0 && s0->pChainContext) {
        PCCERT_CHAIN_CONTEXT cc = s0->pChainContext;
        EXPECT_EQ(cc->cChain, 1);
        CHECK(cc->TrustStatus.dwErrorStatus & CERT_TRUST_IS_UNTRUSTED_ROOT);
        EXPECT_EQ(cc->TrustStatus.dwInfoStatus, 0x100);   /* chain level: HAS_PREFERRED_ISSUER only; SELF_SIGNED is on the element */
        if (cc->cChain >= 1) CHECK(cc->rgpChain[0]->rgpElement[0]->TrustStatus.dwInfoStatus & CERT_TRUST_IS_SELF_SIGNED);
        if (cc->cChain >= 1) { EXPECT_EQ(cc->rgpChain[0]->cElement, 1);
            CHECK(cc->rgpChain[0]->rgpElement[0]->pCertContext != NULL); }
    } else CHECK(0);
    SIGNED_STATE_EPILOGUE
}
TEST(wvt_state_message_handle) {
    SIGNED_STATE_PROLOGUE
    CHECK(pd->d.hMsg != NULL);
    if (pd->d.hMsg && U(CryptMsgGetParam)) {
        DWORD type = 0, cb = sizeof type;
        CHECK(U(CryptMsgGetParam)(pd->d.hMsg, CMSG_TYPE_PARAM, 0, &type, &cb)); EXPECT_EQ(type, CMSG_SIGNED);
        DWORD cnt = 0; cb = sizeof cnt;
        CHECK(U(CryptMsgGetParam)(pd->d.hMsg, CMSG_SIGNER_COUNT_PARAM, 0, &cnt, &cb)); EXPECT_EQ(cnt, 1);
        char oid[64] = {0}; cb = sizeof oid;
        CHECK(U(CryptMsgGetParam)(pd->d.hMsg, CMSG_INNER_CONTENT_TYPE_PARAM, 0, oid, &cb));
        EXPECT_STR(oid, "1.3.6.1.4.1.311.2.1.4");
        cnt = 0; cb = sizeof cnt;
        CHECK(U(CryptMsgGetParam)(pd->d.hMsg, CMSG_CERT_COUNT_PARAM, 0, &cnt, &cb)); EXPECT_EQ(cnt, 1);
    }
    SIGNED_STATE_EPILOGUE
}
TEST(wvt_state_provider_data_fields) {
    SIGNED_STATE_PROLOGUE
    EXPECT_EQ(pd->d.cbStruct, 0xF0);
    EXPECT_EQ(pd->d.cdwTrustStepErrors, 38);
    CHECK(pd->d.pWintrustData == &w.d);
    CHECK(pd->d.pgActionID && IsEqualGUID(pd->d.pgActionID, &WVT_V2));
    EXPECT_EQ(pd->d.dwEncoding, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING);
    CHECK(pd->d.hProv != 0);
    CHECK(pd->d.psPfns != NULL);
    CHECK(pd->d.pszUsageOID != NULL);
    if (pd->d.pszUsageOID) EXPECT_STR(pd->d.pszUsageOID, "1.3.6.1.5.5.7.3.3");
    CHECK(pd->d.dwProvFlags & CPD_USE_NT5_CHAIN_FLAG);
    CHECK(pd->d.dwRegSecuritySettings <= 2);
    CHECK((pd->d.dwRegPolicySettings & 0xA0) == 0);
    CHECK(!pd->d.fRecallWithState);
    EXPECT_EQ(pd->d.dwSubjectChoice, CPD_CHOICE_SIP);
    CHECK(pd->d.pPDSip != NULL);
    CHECK(pd->d.chStores >= 1); CHECK(pd->d.pahStores != NULL);
    FILETIME now; GetSystemTimeAsFileTime(&now);
    ULONGLONG a = ((ULONGLONG)now.dwHighDateTime << 32) | now.dwLowDateTime;
    ULONGLONG b = ((ULONGLONG)pd->d.sftSystemTime.dwHighDateTime << 32) | pd->d.sftSystemTime.dwLowDateTime;
    CHECK((a > b ? a - b : b - a) < 10ULL * 60 * 10000000);
    EXPECT_EQ(pd->d.dwProvFlags, 0x80000010); EXPECT_EQ(pd->d.dwRegSecuritySettings, 1); EXPECT_EQ(pd->d.dwRegPolicySettings, 0x00023c00);
    EXPECT_EQ(pd->d.dwError, 0); EXPECT_EQ(pd->d.dwFinalError, (DWORD)WVT_E_UNTRUSTEDROOT);
    EXPECT_EQ(pd->d.dwTrustPubSettings, 0); EXPECT_EQ(pd->d.dwUIStateFlags, 0);
    for (int i = 0; i < 38 && pd->d.padwTrustStepErrors; i++) { t_label("trust step %d", i); EXPECT_EQ(pd->d.padwTrustStepErrors[i], 0); }
    EXPECT_EQ(pd->d.padwTrustStepErrors[TRUSTERROR_STEP_FINAL_WVTINIT], 0);
    EXPECT_EQ(pd->d.padwTrustStepErrors[TRUSTERROR_STEP_FINAL_INITPROV], 0);
    EXPECT_EQ(pd->d.padwTrustStepErrors[TRUSTERROR_STEP_FINAL_OBJPROV], 0);
    EXPECT_EQ(pd->d.padwTrustStepErrors[TRUSTERROR_STEP_FINAL_SIGPROV], 0);
    SIGNED_STATE_EPILOGUE
}
TEST(wvt_state_provider_function_table) {
    SIGNED_STATE_PROLOGUE
    CRYPT_PROVIDER_FUNCTIONS *f = pd->d.psPfns;
    if (f) {
        EXPECT_EQ(f->cbStruct, 0x80);
        HMODULE m = t_module("wintrust.dll");
        CHECK(f->pfnInitialize == (PFN_PROVIDER_INIT_CALL)GetProcAddress(m, "SoftpubInitialize"));
        CHECK(f->pfnObjectTrust == (PFN_PROVIDER_OBJTRUST_CALL)GetProcAddress(m, "SoftpubLoadMessage"));
        CHECK(f->pfnSignatureTrust == (PFN_PROVIDER_SIGTRUST_CALL)GetProcAddress(m, "SoftpubLoadSignature"));
        CHECK(f->pfnCertificateTrust == (PFN_PROVIDER_CERTTRUST_CALL)GetProcAddress(m, "WintrustCertificateTrust"));
        CHECK(f->pfnCertCheckPolicy == (PFN_PROVIDER_CERTCHKPOLICY_CALL)GetProcAddress(m, "SoftpubCheckCert"));
        CHECK((void *)f->pfnFinalPolicy == (void *)GetProcAddress(m, "SoftpubAuthenticode"));
        CHECK(f->pfnAlloc && f->pfnFree && f->pfnAddStore2Chain && f->pfnAddSgnr2Chain && f->pfnAddCert2Chain && f->pfnAddPrivData2Chain);
        void *blk = f->pfnAlloc(48);
        CHECK(blk != NULL);
        if (blk) { memset(blk, 0x5a, 48); f->pfnFree(blk); }
    }
    SIGNED_STATE_EPILOGUE
}
TEST(wvt_state_private_data_lookup) {
    SIGNED_STATE_PROLOGUE
    static const GUID nope = { 0xdeadbeef, 0x1111, 0x2222, { 1, 2, 3, 4, 5, 6, 7, 8 } };
    CHECK(U(WTHelperGetProvPrivateDataFromChain)(&pd->d, (GUID *)&nope) == NULL);
    CHECK(U(WTHelperGetProvPrivateDataFromChain)(&pd->d, NULL) == NULL);
    CHECK(U(WTHelperGetProvPrivateDataFromChain)(NULL, (GUID *)&nope) == NULL);
    CHECK(U(WTHelperGetProvPrivateDataFromChain)(NULL, NULL) == NULL);
    EXPECT_EQ(pd->d.csProvPrivData, 0);   /* Win10 records no provider private data for this verify */
    for (DWORD i = 0; i < pd->d.csProvPrivData && pd->d.pasProvPrivData; i++) {
        CRYPT_PROVIDER_PRIVDATA *pr = U(WTHelperGetProvPrivateDataFromChain)(&pd->d, &pd->d.pasProvPrivData[i].gProviderID);
        CHECKF(pr != NULL && pr->gProviderID.Data1 == pd->d.pasProvPrivData[i].gProviderID.Data1, "private data %lu", (unsigned long)i);
    }
    SIGNED_STATE_EPILOGUE
}
TEST(wvt_state_close_clears_handle) {
    SIGNED_STATE_PROLOGUE
    CHECK(w.d.hWVTStateData != NULL);
    SetLastError(0xdeadbeef);
    EXPECT_EQ(wvt_close(&WVT_V2, &w), 0);
    CHECK(w.d.hWVTStateData == NULL);
    EXPECT_EQ(GetLastError(), 0x7f);
    wvt_del(p);
}
TEST(wvt_state_file_closed_after_close) {
    /* after CLOSE the image file can be deleted: nothing keeps it open */
    WVT_REQUIRE_WVT();
    WCHAR p[MAX_PATH]; WVTD w; WINTRUST_FILE_INFO fi; DWORD e; put_signed(p, "del.exe");
    verify_signed_state(&w, &fi, p, 0, &e);
    wvt_close(&WVT_V2, &w);
    CHECK(DeleteFileW(p));
}
TEST(wvt_ignore_leaves_file_unlocked) {
    WVT_REQUIRE_WVT();
    WCHAR p[MAX_PATH]; WVTD w; WINTRUST_FILE_INFO fi; DWORD e; put_signed(p, "del2.exe");
    wvt_init_file(&w, &fi, p); wvt_call(&WVT_V2, &w, &e);
    CHECK(DeleteFileW(p));
}
TEST(wvt_state_open_file_handle_helper) {
    WVT_REQUIRE_WVT();
    WCHAR p[MAX_PATH]; WVTD w; WINTRUST_FILE_INFO fi; DWORD e; put_signed(p, "fh.exe");
    verify_signed_state(&w, &fi, p, 0, &e);
    CHECK(fi.hFile == INVALID_HANDLE_VALUE);   /* Win10 stores an invalid handle for a path-only subject */
    wvt_close(&WVT_V2, &w); wvt_del(p);
    CHECK(fi.hFile == INVALID_HANDLE_VALUE);
}
TEST(wvt_verify_twice_same_data_independent) {
    WVT_REQUIRE_WVT();
    WCHAR p[MAX_PATH]; put_signed(p, "tw.exe");
    for (int i = 0; i < 3; i++) {
        WVTD w; WINTRUST_FILE_INFO fi; DWORD e;
        EXPECT_EQ(verify_signed_state(&w, &fi, p, 0, &e), WVT_E_UNTRUSTEDROOT);
        wvt_close(&WVT_V2, &w);
    }
    wvt_del(p);
}
TEST(wvt_state_recall_verify_with_existing_state) {
    /* VERIFY again with the state handle of a previous VERIFY: re-runs and keeps a state handle */
    WVT_REQUIRE_WVT();
    WCHAR p[MAX_PATH]; WVTD w; WINTRUST_FILE_INFO fi; DWORD e; put_signed(p, "rc.exe");
    verify_signed_state(&w, &fi, p, 0, &e);
    HANDLE h1 = w.d.hWVTStateData;
    w.d.dwStateAction = WTD_STATEACTION_VERIFY;
    LONG r = wvt_call(&WVT_V2, &w, &e);
    EXPECT_EQ(r, WVT_E_UNTRUSTEDROOT); CHECK(w.d.hWVTStateData == h1);
    wvt_close(&WVT_V2, &w); wvt_del(p);
}

/* ---- signature settings --------------------------------------------------- */
TEST(wvt_sigsettings_count_secondary) {
    WVT_REQUIRE_WVT();
    WCHAR p[MAX_PATH]; WVTD w; WINTRUST_FILE_INFO fi; DWORD e; put_signed(p, "ss.exe");
    wvt_init_file(&w, &fi, p); w.d.dwStateAction = WTD_STATEACTION_VERIFY;
    WVT_SIGSET ss; memset(&ss, 0, sizeof ss); ss.cbStruct = sizeof ss; ss.dwFlags = 2 /* WSS_GET_SECONDARY_SIG_COUNT */;
    ss.cSecondarySigs = 0xcccccccc; ss.dwVerifiedSigIndex = 0xcccccccc;
    w.pSignatureSettings = &ss;
    LONG r = wvt_call(&WVT_V2, &w, &e);
    EXPECT_EQ(r, WVT_E_UNTRUSTEDROOT);
    EXPECT_EQ(ss.dwVerifiedSigIndex, 0xcccccccc);   /* not written for a count-only request */
    EXPECT_EQ(ss.cSecondarySigs, 0);
    wvt_close(&WVT_V2, &w); wvt_del(p);
}
TEST(wvt_sigsettings_verify_specific_index0) {
    WVT_REQUIRE_WVT();
    WCHAR p[MAX_PATH]; WVTD w; WINTRUST_FILE_INFO fi; DWORD e; put_signed(p, "ss2.exe");
    wvt_init_file(&w, &fi, p);
    WVT_SIGSET ss; memset(&ss, 0, sizeof ss); ss.cbStruct = sizeof ss; ss.dwFlags = 1 /* WSS_VERIFY_SPECIFIC */; ss.dwIndex = 0;
    w.pSignatureSettings = &ss;
    EXPECT_EQ(wvt_call(&WVT_V2, &w, &e), WVT_E_UNTRUSTEDROOT);
    wvt_del(p);
}
TEST(wvt_sigsettings_verify_specific_out_of_range) {
    WVT_REQUIRE_WVT();
    WCHAR p[MAX_PATH]; WVTD w; WINTRUST_FILE_INFO fi; DWORD e; put_signed(p, "ss3.exe");
    wvt_init_file(&w, &fi, p);
    WVT_SIGSET ss; memset(&ss, 0, sizeof ss); ss.cbStruct = sizeof ss; ss.dwFlags = 1; ss.dwIndex = 5;
    w.pSignatureSettings = &ss;
    LONG r = wvt_call(&WVT_V2, &w, &e);
    EXPECT_EQ(r, WVT_E_NOSIGNATURE);
    wvt_del(p);
}
TEST(wvt_sigsettings_too_small_cbstruct) {
    WVT_REQUIRE_WVT();
    WCHAR p[MAX_PATH]; WVTD w; WINTRUST_FILE_INFO fi; DWORD e; put_signed(p, "ss4.exe");
    wvt_init_file(&w, &fi, p);
    WVT_SIGSET ss; memset(&ss, 0, sizeof ss); ss.cbStruct = 0x1c;
    w.pSignatureSettings = &ss;
    LONG r = wvt_call(&WVT_V2, &w, &e);
    EXPECT_EQ(r, 0);
    EXPECT_EQ(e, (DWORD)WVT_E_INVALIDARG);
    wvt_del(p);
}
TEST(wvt_sigsettings_ignored_for_old_cbstruct) {
    /* a 0x50-byte WINTRUST_DATA has no pSignatureSettings member, so the (garbage) pointer is never read */
    WVT_REQUIRE_WVT();
    WCHAR p[MAX_PATH]; WVTD w; WINTRUST_FILE_INFO fi; DWORD e; put_signed(p, "ss5.exe");
    wvt_init_file(&w, &fi, p); w.d.cbStruct = sizeof(WINTRUST_DATA);
    WVT_SIGSET ss; memset(&ss, 0, sizeof ss); ss.cbStruct = 4; w.pSignatureSettings = &ss;
    EXPECT_EQ(wvt_call(&WVT_V2, &w, &e), WVT_E_UNTRUSTEDROOT);
    wvt_del(p);
}

/* ---- WTD_CHOICE_CERT ----------------------------------------------------------- */
static PCCERT_CONTEXT mkcert(const BYTE *der, DWORD n) { return U(CertCreateCertificateContext)(X509_ASN_ENCODING, der, n); }
static LONG verify_cert(PCCERT_CONTEXT c, HCERTSTORE st, FILETIME *asof, DWORD *err, const GUID *act, WVTD *wout, WINTRUST_CERT_INFO *cio) {
    WVTD w; WINTRUST_CERT_INFO ci; memset(&w, 0, sizeof w); memset(&ci, 0, sizeof ci);
    ci.cbStruct = sizeof ci; ci.pcwszDisplayName = L"cryptt cert"; ci.psCertContext = (CERT_CONTEXT *)c;
    ci.dwFlags = WTCI_DONT_OPEN_STORES; ci.psftVerifyAsOf = asof;
    if (st) { ci.chStores = 1; ci.pahStores = &st; }
    w.d.cbStruct = sizeof w; w.d.dwUIChoice = WTD_UI_NONE; w.d.fdwRevocationChecks = WTD_REVOKE_NONE;
    w.d.dwUnionChoice = WTD_CHOICE_CERT; w.d.pCert = &ci; w.d.dwStateAction = wout ? WTD_STATEACTION_VERIFY : WTD_STATEACTION_IGNORE;
    w.d.dwProvFlags = WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL;
    LONG r = wvt_call(act, &w, err);
    if (wout) { *wout = w; if (cio) *cio = ci; }
    return r;
}
TEST(wvt_cert_selfsigned_untrusted_root) {
    WVT_REQUIRE_WVT();
    PCCERT_CONTEXT c = mkcert(fix_cert_self, sizeof fix_cert_self); CHECK(c != NULL); if (!c) return;
    DWORD e; LONG r = verify_cert(c, NULL, NULL, &e, &WVT_CERTV, NULL, NULL);
    EXPECT_EQ(r, WVT_E_UNTRUSTEDROOT); EXPECT_EQ(e, (DWORD)WVT_E_UNTRUSTEDROOT);
    U(CertFreeCertificateContext)(c);
}
TEST(wvt_cert_partial_chain) {
    WVT_REQUIRE_WVT();
    PCCERT_CONTEXT c = mkcert(fix_cert_leaf, sizeof fix_cert_leaf); CHECK(c != NULL); if (!c) return;
    DWORD e; LONG r = verify_cert(c, NULL, NULL, &e, &WVT_CERTV, NULL, NULL);
    EXPECT_EQ(r, WVT_E_CHAINING); EXPECT_EQ(e, (DWORD)WVT_E_CHAINING);
    U(CertFreeCertificateContext)(c);
}
TEST(wvt_cert_chain_with_supplied_issuer) {
    WVT_REQUIRE_WVT();
    HCERTSTORE st = U(CertOpenStore)(CERT_STORE_PROV_MEMORY, 0, 0, 0, NULL); CHECK(st != NULL); if (!st) return;
    CHECK(U(CertAddEncodedCertificateToStore)(st, X509_ASN_ENCODING, fix_cert_ca, sizeof fix_cert_ca, CERT_STORE_ADD_ALWAYS, NULL));
    PCCERT_CONTEXT c = mkcert(fix_cert_leaf, sizeof fix_cert_leaf);
    DWORD e; WVTD w; WINTRUST_CERT_INFO ci;
    LONG r = verify_cert(c, st, NULL, &e, &WVT_CERTV, &w, &ci);
    EXPECT_EQ(r, WVT_E_UNTRUSTEDROOT);
    WVT_PD *pd = (WVT_PD *)U(WTHelperProvDataFromStateData)(w.d.hWVTStateData);
    CHECK(pd != NULL);
    if (pd) {
        EXPECT_EQ(pd->d.csSigners, 1);
        CRYPT_PROVIDER_SGNR *s = U(WTHelperGetProvSignerFromChain)(&pd->d, 0, FALSE, 0);
        CHECK(s != NULL);
        if (s) {
            EXPECT_EQ(s->csCertChain, 2);
            CRYPT_PROVIDER_CERT *c0 = U(WTHelperGetProvCertFromChain)(s, 0), *c1 = U(WTHelperGetProvCertFromChain)(s, 1);
            if (c0 && c1) {
                CHECK(!c0->fSelfSigned); CHECK(c1->fSelfSigned); CHECK(!c1->fTrustedRoot);
                CHECK(c0->pCert->cbCertEncoded == sizeof fix_cert_leaf);
                CHECK(c1->pCert->cbCertEncoded == sizeof fix_cert_ca);
            } else CHECK(0);
            CHECK(U(WTHelperGetProvCertFromChain)(s, 2) == NULL);
        }
    }
    wvt_close(&WVT_CERTV, &w);
    U(CertFreeCertificateContext)(c); U(CertCloseStore)(st, 0);
}
TEST(wvt_cert_verify_as_of_before_validity) {
    WVT_REQUIRE_WVT();
    PCCERT_CONTEXT c = mkcert(fix_cert_self, sizeof fix_cert_self); if (!c) { CHECK(0); return; }
    SYSTEMTIME st = { 2010, 6, 0, 1, 12, 0, 0, 0 }; FILETIME ft; SystemTimeToFileTime(&st, &ft);
    DWORD e; LONG r = verify_cert(c, NULL, &ft, &e, &WVT_CERTV, NULL, NULL);
    EXPECT_EQ(r, WVT_E_UNTRUSTEDROOT);   /* Win10 reports the untrusted root for an as-of time before NotBefore */
    U(CertFreeCertificateContext)(c);
}
TEST(wvt_cert_verify_as_of_after_validity) {
    WVT_REQUIRE_WVT();
    PCCERT_CONTEXT c = mkcert(fix_cert_self, sizeof fix_cert_self); if (!c) { CHECK(0); return; }
    SYSTEMTIME st = { 2125, 6, 0, 1, 12, 0, 0, 0 }; FILETIME ft; SystemTimeToFileTime(&st, &ft);
    DWORD e; LONG r = verify_cert(c, NULL, &ft, &e, &WVT_CERTV, NULL, NULL);
    EXPECT_EQ(r, WVT_E_UNTRUSTEDROOT);   /* likewise for an as-of time after NotAfter */
    U(CertFreeCertificateContext)(c);
}
TEST(wvt_cert_verify_as_of_within_validity) {
    WVT_REQUIRE_WVT();
    PCCERT_CONTEXT c = mkcert(fix_cert_self, sizeof fix_cert_self); if (!c) { CHECK(0); return; }
    SYSTEMTIME st = { 2030, 6, 0, 1, 12, 0, 0, 0 }; FILETIME ft; SystemTimeToFileTime(&st, &ft);
    DWORD e; EXPECT_EQ(verify_cert(c, NULL, &ft, &e, &WVT_CERTV, NULL, NULL), WVT_E_UNTRUSTEDROOT);
    U(CertFreeCertificateContext)(c);
}
TEST(wvt_cert_unknown_guid_cert_choice) {
    WVT_REQUIRE_WVT();
    PCCERT_CONTEXT c = mkcert(fix_cert_self, sizeof fix_cert_self); if (!c) { CHECK(0); return; }
    GUID g = { 0x9a9a9a9a, 0x1, 2, { 3, 4, 5, 6, 7, 8, 9, 10 } };
    DWORD e; EXPECT_EQ(verify_cert(c, NULL, NULL, &e, &g, NULL, NULL), WVT_E_PROVIDER_UNKNOWN);
    U(CertFreeCertificateContext)(c);
}
TEST(wvt_cert_chain_action_with_cert_choice_observed) {
    WVT_REQUIRE_WVT();
    if (t_is_wine()) { t_skip("chain provider needs policy callback data"); return; }
    PCCERT_CONTEXT c = mkcert(fix_cert_self, sizeof fix_cert_self); if (!c) { CHECK(0); return; }
    DWORD e; LONG r = verify_cert(c, NULL, NULL, &e, &WVT_CHAINV, NULL, NULL);
    EXPECT_EQ(r, WVT_E_UNTRUSTEDROOT);
    U(CertFreeCertificateContext)(c);
}

/* ---- WTD_CHOICE_BLOB -------------------------------------------------------------- */
TEST(wvt_blob_unknown_subject_guid) {
    /* observed: the object provider loads the SIP for gSubject; an unregistered GUID ends in TRUST_E_PROVIDER_UNKNOWN
       in the FINAL_OBJPROV step and the SIP step records the CryptSIPLoad error */
    WVT_REQUIRE_WVT();
    WVTD w; WINTRUST_BLOB_INFO bi; static const BYTE data[16] = { 1, 2, 3, 4 };
    memset(&w, 0, sizeof w); memset(&bi, 0, sizeof bi);
    bi.cbStruct = sizeof bi; bi.gSubject = (GUID){ 0x77777777, 0x1234, 0x4321, { 9, 8, 7, 6, 5, 4, 3, 2 } };
    bi.pcwszDisplayName = L"blob"; bi.cbMemObject = sizeof data; bi.pbMemObject = (BYTE *)data;
    w.d.cbStruct = sizeof w; w.d.dwUIChoice = WTD_UI_NONE; w.d.dwUnionChoice = WTD_CHOICE_BLOB; w.d.pBlob = &bi;
    w.d.dwProvFlags = WTD_REVOCATION_CHECK_NONE; w.d.dwStateAction = WTD_STATEACTION_VERIFY;
    DWORD e; LONG r = wvt_call(&WVT_V2, &w, &e);
    EXPECT_EQ(r, WVT_E_PROVIDER_UNKNOWN); EXPECT_EQ(e, (DWORD)WVT_E_PROVIDER_UNKNOWN);
    CRYPT_PROVIDER_DATA *pd = U(WTHelperProvDataFromStateData)(w.d.hWVTStateData);
    CHECK(pd != NULL && pd->padwTrustStepErrors != NULL);
    if (pd && pd->padwTrustStepErrors) {
        EXPECT_EQ(pd->padwTrustStepErrors[TRUSTERROR_STEP_FINAL_OBJPROV], (DWORD)WVT_E_PROVIDER_UNKNOWN);
        EXPECT_EQ(pd->padwTrustStepErrors[TRUSTERROR_STEP_SIP], (DWORD)WVT_E_SUBJECT_FORM);
    }
    wvt_close(&WVT_V2, &w);
}
TEST(wvt_blob_pe_subject_unsigned_observed) {
    WVT_REQUIRE_WVT();
    WVTD w; WINTRUST_BLOB_INFO bi; memset(&w, 0, sizeof w); memset(&bi, 0, sizeof bi);
    bi.cbStruct = sizeof bi; bi.gSubject = WVT_PE_SIP; bi.pcwszDisplayName = L"blob.exe";
    bi.cbMemObject = sizeof fix_pe_unsigned; bi.pbMemObject = (BYTE *)fix_pe_unsigned;
    w.d.cbStruct = sizeof w; w.d.dwUIChoice = WTD_UI_NONE; w.d.dwUnionChoice = WTD_CHOICE_BLOB; w.d.pBlob = &bi;
    w.d.dwProvFlags = WTD_REVOCATION_CHECK_NONE;
    DWORD e; LONG r = wvt_call(&WVT_V2, &w, &e);
    EXPECT_EQ(r, WVT_E_NOSIGNATURE);
}
TEST(wvt_blob_pe_subject_signed_observed) {
    WVT_REQUIRE_WVT();
    WVTD w; WINTRUST_BLOB_INFO bi; memset(&w, 0, sizeof w); memset(&bi, 0, sizeof bi);
    bi.cbStruct = sizeof bi; bi.gSubject = WVT_PE_SIP; bi.pcwszDisplayName = L"blob.exe";
    bi.cbMemObject = sizeof fix_pe_signed; bi.pbMemObject = (BYTE *)fix_pe_signed;
    w.d.cbStruct = sizeof w; w.d.dwUIChoice = WTD_UI_NONE; w.d.dwUnionChoice = WTD_CHOICE_BLOB; w.d.pBlob = &bi;
    w.d.dwProvFlags = WTD_REVOCATION_CHECK_NONE;
    DWORD e; LONG r = wvt_call(&WVT_V2, &w, &e);
    EXPECT_EQ(r, WVT_E_NOSIGNATURE);
}
TEST(wvt_blob_with_state_unknown_guid_state_closed) {
    WVT_REQUIRE_WVT();
    WVTD w; WINTRUST_BLOB_INFO bi; static const BYTE data[8] = { 1 };
    memset(&w, 0, sizeof w); memset(&bi, 0, sizeof bi);
    bi.cbStruct = sizeof bi; bi.gSubject = (GUID){ 0x77777778, 0x1234, 0x4321, { 9, 8, 7, 6, 5, 4, 3, 2 } };
    bi.cbMemObject = sizeof data; bi.pbMemObject = (BYTE *)data;
    w.d.cbStruct = sizeof w; w.d.dwUIChoice = WTD_UI_NONE; w.d.dwUnionChoice = WTD_CHOICE_BLOB; w.d.pBlob = &bi;
    w.d.dwStateAction = WTD_STATEACTION_VERIFY;
    DWORD e; EXPECT_EQ(wvt_call(&WVT_V2, &w, &e), WVT_E_PROVIDER_UNKNOWN);
    CHECK(w.d.hWVTStateData != NULL);
    EXPECT_EQ(wvt_close(&WVT_V2, &w), 0);
    CHECK(w.d.hWVTStateData == NULL);
}

/* ---- failure step recorded in the provider data -------------------------------------- */
static DWORD step_after(const void *img, DWORD n, int step, LONG *res) {
    WCHAR p[MAX_PATH]; WVTD w; WINTRUST_FILE_INFO fi; DWORD e, v = 0xdeadbeef;
    wvt_path(p, "step.exe"); wvt_write(p, img, n);
    wvt_init_file(&w, &fi, p); w.d.dwStateAction = WTD_STATEACTION_VERIFY; w.d.dwProvFlags |= WTD_HASH_ONLY_FLAG;
    LONG r = wvt_call(&WVT_V2, &w, &e); if (res) *res = r;
    CRYPT_PROVIDER_DATA *pd = U(WTHelperProvDataFromStateData)(w.d.hWVTStateData);
    if (pd && pd->padwTrustStepErrors) v = pd->padwTrustStepErrors[step];
    wvt_close(&WVT_V2, &w); wvt_del(p); return v;
}
TEST(wvt_step_unsigned_pe_objprov_nosignature) {
    WVT_REQUIRE_WVT(); LONG r;
    EXPECT_EQ(step_after(fix_pe_unsigned, sizeof fix_pe_unsigned, TRUSTERROR_STEP_FINAL_OBJPROV, &r), (DWORD)WVT_E_NOSIGNATURE);
    EXPECT_EQ(r, WVT_E_NOSIGNATURE);
}
TEST(wvt_step_tampered_pe_objprov_bad_digest) {
    WVT_REQUIRE_WVT(); LONG r; BYTE *b = (BYTE *)HeapAlloc(GetProcessHeap(), 0, sizeof fix_pe_signed);
    memcpy(b, fix_pe_signed, sizeof fix_pe_signed); b[0x200] ^= 1;
    EXPECT_EQ(step_after(b, sizeof fix_pe_signed, TRUSTERROR_STEP_FINAL_OBJPROV, &r), (DWORD)WVT_E_BAD_DIGEST);
    EXPECT_EQ(r, WVT_E_NOSIGNATURE); /* the step error keeps the digest failure, the return value is NOSIGNATURE */
    HeapFree(GetProcessHeap(), 0, b);
}
TEST(wvt_step_valid_hash_only_all_zero) {
    WVT_REQUIRE_WVT(); LONG r;
    EXPECT_EQ(step_after(fix_pe_signed, sizeof fix_pe_signed, TRUSTERROR_STEP_FINAL_OBJPROV, &r), 0);
    EXPECT_EQ(r, 0);
}
TEST(wvt_step_invalid_union_choice_objprov_invalid_parameter) {
    /* observed: SoftpubLoadMessage records ERROR_INVALID_PARAMETER for dwUnionChoice 0 and >= 6 */
    WVT_REQUIRE_WVT();
    static const DWORD ch[] = { 0, 6, 99 };
    WCHAR p[MAX_PATH]; wvt_path(p, "uc2.exe"); wvt_write(p, fix_pe_unsigned, sizeof fix_pe_unsigned);
    for (int i = 0; i < 3; i++) {
        WVTD w; WINTRUST_FILE_INFO fi; wvt_init_file(&w, &fi, p); w.d.dwUnionChoice = ch[i];
        w.d.dwStateAction = WTD_STATEACTION_VERIFY; DWORD e;
        LONG r = wvt_call(&WVT_V2, &w, &e);
        CRYPT_PROVIDER_DATA *pd = U(WTHelperProvDataFromStateData)(w.d.hWVTStateData);
        EXPECT_EQ((DWORD)r, 0x57);
        if (pd && pd->padwTrustStepErrors)
            CHECKF(pd->padwTrustStepErrors[TRUSTERROR_STEP_FINAL_OBJPROV] == 0x57, "choice %lu step=0x%08lx", (unsigned long)ch[i], (unsigned long)pd->padwTrustStepErrors[TRUSTERROR_STEP_FINAL_OBJPROV]);
        else CHECK(0);
        wvt_close(&WVT_V2, &w);
    }
    wvt_del(p);
}
