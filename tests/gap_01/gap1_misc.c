/* CertSelectionGetSerializedBlob, crypt32!CryptSIPGetCaps, WTHelperCertCheckValidSignature, Tbsip_Submit_Command,
   and the resolution of the (UI-only) CertSelectCertificate / CertViewProperties exports. */
#include "gap1.h"
#include <softpub.h>
#include <wintrust.h>
#include <mssip.h>

typedef struct { HCERTSTORE hStore; PCCERT_CHAIN_CONTEXT *prgpChain; ULONG cChain; } G1_SELECTUI_INPUT;
UDECL(HRESULT, CertSelectionGetSerializedBlob, (G1_SELECTUI_INPUT *, void **, ULONG *));
#define CSGSB ((CertSelectionGetSerializedBlob_pfn)t_proc_in("cryptui.dll", "CertSelectionGetSerializedBlob"))
#define S_E_INVALIDARG ((HRESULT)0x80070057)
static const BYTE blob_guid[16] = { 0x48,0x96,0x9b,0xab, 0xd2,0x0e,0x0c,0x41, 0xa3,0xf6,0x62,0xe7, 0x47,0x12,0xb6,0x6c };

static HCERTSTORE mem_store(void) { return U(CertOpenStore)(CERT_STORE_PROV_MEMORY, 0, 0, 0, NULL); }

TEST(gap1_csblob_exported_only_by_cryptui) {
    REQUIRE(CSGSB);
    HMODULE d = t_module("cryptdlg.dll");
    if (d) { SET_ERR(0); CHECK(GetProcAddress(d, "CertSelectionGetSerializedBlob") == NULL); EXPECT_ERR(ERROR_PROC_NOT_FOUND); }
}
TEST(gap1_csblob_null_arguments) {
    REQUIRE(CSGSB);
    G1_SELECTUI_INPUT in = { NULL, NULL, 0 }; void *out = (void *)(ULONG_PTR)0x1; ULONG cb = 0x55;
    EXPECT_EQ(CSGSB(NULL, &out, &cb), S_E_INVALIDARG);
    EXPECT_EQ(CSGSB(&in, NULL, &cb), S_E_INVALIDARG);
    EXPECT_EQ(CSGSB(&in, &out, NULL), S_E_INVALIDARG);
    EXPECT_EQ(CSGSB(NULL, NULL, NULL), S_E_INVALIDARG);
    CHECK(out == (void *)(ULONG_PTR)0x1 && cb == 0x55);      /* outputs untouched by the argument check */
}
TEST(gap1_csblob_store_and_chain_are_exclusive) {
    REQUIRE(CSGSB); G1_INIT();
    HCERTSTORE s = mem_store(); REQUIRE(s);
    PCCERT_CHAIN_CONTEXT dummy[1] = { NULL };
    G1_SELECTUI_INPUT in = { s, dummy, 1 }; void *out = (void *)(ULONG_PTR)0x1; ULONG cb = 0x55;
    EXPECT_EQ(CSGSB(&in, &out, &cb), S_E_INVALIDARG);
    CHECK(out == (void *)(ULONG_PTR)0x1 && cb == 0x55);
    U(CertCloseStore)(s, 0);
}
TEST(gap1_csblob_neither_store_nor_chain) {
    REQUIRE(CSGSB);
    G1_SELECTUI_INPUT in = { NULL, NULL, 0 }; void *out = (void *)(ULONG_PTR)0x1; ULONG cb = 0x55;
    EXPECT_EQ(CSGSB(&in, &out, &cb), 0);
    CHECK(out == NULL); EXPECT_EQ(cb, 0);
}
static void check_blob(const void *p, ULONG cb, ULONG flags) {
    const BYTE *b = p;
    CHECK(p != NULL && cb >= 0x18);
    if (!p || cb < 0x18) return;
    CHECK(!memcmp(b, blob_guid, 16));
    DWORD fl, inner; memcpy(&fl, b + 16, 4); memcpy(&inner, b + 20, 4);
    CHECKF(fl == flags, "flags field %lu", fl);
    CHECKF(inner + 0x18 == cb, "inner %lu + 24 != total %lu", inner, cb);
}
TEST(gap1_csblob_empty_store) {
    REQUIRE(CSGSB);
    HCERTSTORE s = mem_store(); REQUIRE(s);
    G1_SELECTUI_INPUT in = { s, NULL, 0 }; void *out = NULL; ULONG cb = 0;
    EXPECT_EQ(CSGSB(&in, &out, &cb), 0);
    check_blob(out, cb, 0);
    if (out) CHECK(LocalFree(out) == NULL);
    U(CertCloseStore)(s, 0);
}
TEST(gap1_csblob_store_contents_and_growth) {
    REQUIRE(CSGSB); G1_INIT();
    HCERTSTORE s = mem_store(); REQUIRE(s);
    void *o0 = NULL, *o1 = NULL, *o2 = NULL; ULONG c0 = 0, c1 = 0, c2 = 0;
    G1_SELECTUI_INPUT in = { s, NULL, 0 };
    EXPECT_EQ(CSGSB(&in, &o0, &c0), 0);
    CHECK(U(CertAddCertificateContextToStore)(s, g1_A.cert, CERT_STORE_ADD_ALWAYS, NULL));
    EXPECT_EQ(CSGSB(&in, &o1, &c1), 0);
    CHECK(U(CertAddCertificateContextToStore)(s, g1_B.cert, CERT_STORE_ADD_ALWAYS, NULL));
    EXPECT_EQ(CSGSB(&in, &o2, &c2), 0);
    check_blob(o0, c0, 0); check_blob(o1, c1, 0); check_blob(o2, c2, 0);
    CHECK(c1 > c0 + sizeof v_certA - 1);
    CHECK(c2 > c1 + sizeof v_certB - 1);
    if (o1) CHECK(g1_has(o1, c1, v_certA, sizeof v_certA));
    if (o1) CHECK(!g1_has(o1, c1, v_certB, sizeof v_certB));
    if (o2) CHECK(g1_has(o2, c2, v_certA, sizeof v_certA) && g1_has(o2, c2, v_certB, sizeof v_certB));
    /* distinct allocations */
    CHECK(o1 != o2);
    if (o0) LocalFree(o0); if (o1) LocalFree(o1); if (o2) LocalFree(o2);
    U(CertCloseStore)(s, 0);
}
TEST(gap1_csblob_properties_are_serialized) {
    REQUIRE(CSGSB); G1_INIT();
    HCERTSTORE s = mem_store(); REQUIRE(s);
    PCCERT_CONTEXT c = NULL;
    CHECK(U(CertAddCertificateContextToStore)(s, g1_A.cert, CERT_STORE_ADD_ALWAYS, &c));
    void *o1 = NULL, *o2 = NULL; ULONG c1 = 0, c2 = 0;
    G1_SELECTUI_INPUT in = { s, NULL, 0 };
    EXPECT_EQ(CSGSB(&in, &o1, &c1), 0);
    static const WCHAR fn[] = L"gap1 friendly name";
    CRYPT_DATA_BLOB b = { sizeof fn, (BYTE *)fn };
    CHECK(U(CertSetCertificateContextProperty)(c, CERT_FRIENDLY_NAME_PROP_ID, 0, &b));
    EXPECT_EQ(CSGSB(&in, &o2, &c2), 0);
    CHECK(c2 >= c1 + sizeof fn);
    if (o2) CHECK(g1_has(o2, c2, fn, sizeof fn));
    if (o1) CHECK(!g1_has(o1, c1, fn, sizeof fn));
    if (o1) LocalFree(o1); if (o2) LocalFree(o2);
    U(CertFreeCertificateContext)(c); U(CertCloseStore)(s, 0);
}
TEST(gap1_csblob_chain_input) {
    REQUIRE(CSGSB); G1_INIT();
    HCERTSTORE s = mem_store(); REQUIRE(s);
    CHECK(U(CertAddCertificateContextToStore)(s, g1_A.cert, CERT_STORE_ADD_ALWAYS, NULL));
    CERT_CHAIN_PARA cp; memset(&cp, 0, sizeof cp); cp.cbSize = sizeof cp;
    PCCERT_CHAIN_CONTEXT chain = NULL;
    BOOL r = U(CertGetCertificateChain)(NULL, g1_A.cert, NULL, s, &cp, CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL, NULL, &chain);
    if (!r || !chain) { U(CertCloseStore)(s, 0); t_skip("cannot build a chain: %lu", GetLastError()); return; }
    G1_SELECTUI_INPUT in = { NULL, &chain, 1 }; void *out = NULL; ULONG cb = 0;
    EXPECT_EQ(CSGSB(&in, &out, &cb), 0);
    check_blob(out, cb, 0);
    if (out) CHECK(g1_has(out, cb, v_certA, sizeof v_certA));
    if (out) LocalFree(out);
    /* zero chains: an empty store is serialized */
    G1_SELECTUI_INPUT in0 = { NULL, &chain, 0 }; out = NULL; cb = 0;
    EXPECT_EQ(CSGSB(&in0, &out, &cb), 0);
    check_blob(out, cb, 0);
    if (out) { CHECK(!g1_has(out, cb, v_certA, sizeof v_certA)); LocalFree(out); }
    U(CertFreeCertificateChain)(chain); U(CertCloseStore)(s, 0);
}
TEST(gap1_csblob_chain_same_cert_twice_deduplicated) {
    REQUIRE(CSGSB); G1_INIT();
    HCERTSTORE s = mem_store(); REQUIRE(s);
    CHECK(U(CertAddCertificateContextToStore)(s, g1_A.cert, CERT_STORE_ADD_ALWAYS, NULL));
    CERT_CHAIN_PARA cp; memset(&cp, 0, sizeof cp); cp.cbSize = sizeof cp;
    PCCERT_CHAIN_CONTEXT chain = NULL;
    if (!U(CertGetCertificateChain)(NULL, g1_A.cert, NULL, s, &cp, CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL, NULL, &chain) || !chain) {
        U(CertCloseStore)(s, 0); t_skip("cannot build a chain"); return; }
    PCCERT_CHAIN_CONTEXT two[2] = { chain, chain };
    G1_SELECTUI_INPUT in1 = { NULL, two, 1 }, in2 = { NULL, two, 2 };
    void *o1 = NULL, *o2 = NULL; ULONG c1 = 0, c2 = 0;
    EXPECT_EQ(CSGSB(&in1, &o1, &c1), 0);
    EXPECT_EQ(CSGSB(&in2, &o2, &c2), 0);
    t_note("one chain %lu bytes, same chain twice %lu bytes (added with CERT_STORE_ADD_USE_EXISTING)", c1, c2);
    CHECK(c1 == c2);      /* the memory store collapses duplicates (add disposition 4 = USE_EXISTING) */
    if (o1) LocalFree(o1); if (o2) LocalFree(o2);
    U(CertFreeCertificateChain)(chain); U(CertCloseStore)(s, 0);
}

/* ---------------- crypt32!CryptSIPGetCaps ---------------- */
UDECL(DWORD, CryptSIPGetCaps_c32, (void *));
TEST(gap1_c32sipcaps_argument_validation) {
    DWORD (WINAPI *f)(void *) = (void *)t_proc_in("crypt32.dll", "CryptSIPGetCaps"); REQUIRE(f);
    SET_ERR(0);
    CHECK(f(NULL) == 0); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    /* a subject-info structure with a NULL subject-type GUID */
    SIP_SUBJECTINFO si; memset(&si, 0, sizeof si); si.cbSize = sizeof si;
    SET_ERR(0);
    CHECK(f(&si) == 0); EXPECT_ERR(ERROR_INVALID_PARAMETER);
}
TEST(gap1_c32sipcaps_unregistered_guid) {
    DWORD (WINAPI *f)(void *) = (void *)t_proc_in("crypt32.dll", "CryptSIPGetCaps"); REQUIRE(f);
    static const GUID unknown = { 0x6a8f5f17, 0x1c2d, 0x4a9e, { 0x91, 0x0b, 0x77, 0xaa, 0xbb, 0xcc, 0xdd, 0xee } };
    SIP_SUBJECTINFO si; memset(&si, 0, sizeof si); si.cbSize = sizeof si; si.pgSubjectType = (GUID *)&unknown;
    SET_ERR(0);
    CHECK(f(&si) == 0);
    EXPECT_ERR(TRUST_E_SUBJECT_FORM_UNKNOWN_);
}
TEST(gap1_c32sipcaps_exports_differ_from_wintrust) {
    FARPROC a = t_proc_in("crypt32.dll", "CryptSIPGetCaps"), b = t_proc_in("wintrust.dll", "CryptSIPGetCaps");
    REQUIRE(a); REQUIRE(b);
    CHECK(a != b);       /* two different implementations: crypt32's one takes the subject info only */
}

/* ---------------- WTHelperCertCheckValidSignature ---------------- */
/* Layout facts used (CRYPT_PROVIDER_DATA): +0x08 pWintrustData, +0x50 padwTrustStepErrors (array of TRUSTERROR_MAX_STEPS = 38 DWORDs) */
TEST(gap1_wthelper_checkvalid_step_error_mapping) {
    REQUIRE(U(WTHelperCertCheckValidSignature));
    if (t_is_wine()) { t_skip("provider data layout is implementation specific"); return; }
    BYTE *buf = calloc(1, 4096);
    CRYPT_PROVIDER_DATA *pd = (CRYPT_PROVIDER_DATA *)buf;
    WINTRUST_DATA wd; memset(&wd, 0, sizeof wd); wd.cbStruct = sizeof wd; wd.dwUnionChoice = WTD_CHOICE_FILE;
    DWORD steps[40]; memset(steps, 0, sizeof steps);
    pd->cbStruct = sizeof *pd; pd->pWintrustData = &wd; pd->padwTrustStepErrors = steps;
    /* no signers and no step errors: success */
    HRESULT hr = U(WTHelperCertCheckValidSignature)(pd);
    CHECKF(hr == 0, "hr 0x%08lx", (unsigned long)hr);
    /* step 2 (TRUSTERROR_STEP_FINAL_WVTINIT/ message) recorded failure -> fixed HRESULT 0x80092003 */
    steps[2] = 5;
    hr = U(WTHelperCertCheckValidSignature)(pd);
    CHECKF((DWORD)hr == 0x80092003, "step2 error -> 0x%08lx", (unsigned long)hr);
    steps[2] = 0;
    steps[6] = 5;
    hr = U(WTHelperCertCheckValidSignature)(pd);
    CHECKF((DWORD)hr == 0x80092003, "step6 error -> 0x%08lx", (unsigned long)hr);
    steps[6] = 0;
    /* a failure in one of the later steps is returned as recorded (here an arbitrary HRESULT) */
    steps[0x1f] = 0x800B0109;
    hr = U(WTHelperCertCheckValidSignature)(pd);
    CHECKF((DWORD)hr == 0x800B0109, "steps[0x1f] negative -> 0x%08lx", (unsigned long)hr);
    steps[0x1f] = 5;                       /* positive (Win32) values are mapped to the 0x8007xxxx form */
    hr = U(WTHelperCertCheckValidSignature)(pd);
    CHECKF((DWORD)hr == 0x80070005, "steps[0x1f] = 5 -> 0x%08lx", (unsigned long)hr);
    steps[0x1f] = 0; steps[0x20] = 0;
    steps[0x24] = 0x80096004;
    hr = U(WTHelperCertCheckValidSignature)(pd);
    CHECKF((DWORD)hr == 0x80096004, "steps[0x24] -> 0x%08lx", (unsigned long)hr);
    steps[0x24] = 0;
    free(buf);
}
/* ---------------- Tbsip_Submit_Command: validation that never reaches the device ---------------- */
UDECL(UINT32, Tbsip_Submit_Command_g1, (void *, UINT32, UINT32, const BYTE *, UINT32, BYTE *, UINT32 *));
#define TBS_SUBMIT ((Tbsip_Submit_Command_g1_pfn)t_proc_in("tbs.dll", "Tbsip_Submit_Command"))
TEST(gap1_tbs_submit_output_untouched_on_early_errors) {
    REQUIRE(TBS_SUBMIT);
    if (t_is_wine()) { t_skip("emulator stub"); return; }
    static const BYTE cmd[12] = { 0x80,0x01, 0,0,0,12, 0,0,0x01,0x7b, 0,8 };
    BYTE out[32]; memset(out, 0xA5, sizeof out); UINT32 cbout = 32;
    EXPECT_EQ(TBS_SUBMIT(NULL, 1, 200, cmd, 12, out, &cbout), 0x80284002);   /* TBS_E_BAD_PARAMETER: locality */
    EXPECT_EQ(cbout, 32);
    EXPECT_EQ(TBS_SUBMIT(NULL, 0, 0x80000001u, cmd, 12, out, &cbout), 0x80284002);
    EXPECT_EQ(cbout, 32);
    cbout = 9;
    EXPECT_EQ(TBS_SUBMIT(NULL, 0, 200, cmd, 12, out, &cbout), 0x80284005);   /* TBS_E_INSUFFICIENT_BUFFER: fewer than 10 bytes */
    EXPECT_EQ(cbout, 9);
    cbout = 10;
    EXPECT_NE(TBS_SUBMIT(NULL, 0, 200, cmd, 12, out, &cbout), 0x80284005);   /* 10 is the minimum accepted */
    BYTE chk[32]; memset(chk, 0xA5, sizeof chk);
    CHECK(!memcmp(out, chk, sizeof out));
}
TEST(gap1_tbs_submit_command_buffer_is_const) {
    REQUIRE(TBS_SUBMIT);
    if (t_is_wine()) { t_skip("emulator stub"); return; }
    BYTE cmd[12] = { 0x80,0x01, 0,0,0,12, 0,0,0x01,0x7b, 0,8 }, orig[12];
    memcpy(orig, cmd, 12);
    BYTE out[32]; UINT32 cbout = 32;
    UINT32 r = TBS_SUBMIT(NULL, 0, 400, cmd, 12, out, &cbout);   /* NULL context: refused after the command copy is prepared */
    EXPECT_EQ(r, 0x80284004);                                    /* TBS_E_INVALID_CONTEXT */
    CHECK(!memcmp(cmd, orig, 12));                               /* the priority byte is patched in a private copy */
}
TEST(gap1_tbs_submit_null_command_with_valid_outputs) {
    REQUIRE(TBS_SUBMIT);
    if (t_is_wine()) { t_skip("emulator stub"); return; }
    BYTE out[32]; UINT32 cbout = 32;
    EXPECT_EQ(TBS_SUBMIT(NULL, 0, 200, NULL, 0, out, &cbout), 0x80284002);
    EXPECT_EQ(TBS_SUBMIT(NULL, 0, 200, NULL, 12, out, &cbout), 0x80284002);
    static const BYTE cmd[12] = {0};
    EXPECT_EQ(TBS_SUBMIT(NULL, 0, 200, cmd, 0, out, &cbout), 0x80284002);
}

/* ---------------- UI entry points: resolution only (calling them shows dialogs) ---------------- */
TEST(gap1_ui_exports_resolve_in_cryptdlg) {
    HMODULE m = t_module("cryptdlg.dll"); REQUIRE(m);
    static const char *n[] = { "CertSelectCertificateA", "CertSelectCertificateW", "CertViewPropertiesA", "CertViewPropertiesW" };
    FARPROC p[4];
    for (int i = 0; i < 4; i++) { p[i] = GetProcAddress(m, n[i]); CHECKF(p[i] != NULL, "%s", n[i]); }
    CHECK(p[0] != p[1]); CHECK(p[2] != p[3]);
    HMODULE ui = t_module("cryptui.dll");
    if (ui) { SET_ERR(0); CHECK(GetProcAddress(ui, "CertSelectCertificateW") == NULL); EXPECT_ERR(ERROR_PROC_NOT_FOUND); }
    t_note("not called here: both pairs open modal dialogs (see ui_crypto_dialogs)");
}
