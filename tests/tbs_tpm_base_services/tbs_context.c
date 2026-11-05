/* Tbsi_Context_Create / Tbsip_Context_Close / Tbsi_GetDeviceInfo and the export surface. */
#include "tbsx.h"

#define SENT ((void *)(ULONG_PTR)0x5a5a5a5a5a5aULL)

/* ---------- export surface ---------- */
static const char *const k_exports[] = {
    "GetDeviceID","GetDeviceIDString","GetDeviceIDWithTimeout","Tbsi_Context_Create",
    "Tbsi_Create_Attestation_From_Log","Tbsi_Create_Windows_Key","Tbsi_FilterLog","Tbsi_GetDeviceInfo",
    "Tbsi_Get_OwnerAuth","Tbsi_Get_TCG_Log","Tbsi_Get_TCG_Log_Ex","Tbsi_Get_TCG_Logs",
    "Tbsi_Physical_Presence_Command","Tbsi_Revoke_Attestation","Tbsi_ShaHash","Tbsip_Cancel_Commands",
    "Tbsip_Context_Close","Tbsip_Submit_Command","Tbsip_Submit_Command_NonBlocking",
    "Tbsip_TestInterruptInformation","Tbsip_TestMorBit" };

TEST(tbs_exports_module_loads) {
    HMODULE h = t_module("tbs.dll");
    CHECK(h != NULL);
}
TEST(tbs_exports_all_resolve_by_name) {
    HMODULE h = t_module("tbs.dll");
    if (!h) { t_skip("tbs.dll not loadable"); return; }
    for (size_t i = 0; i < sizeof k_exports / sizeof *k_exports; i++) {
        FARPROC p = GetProcAddress(h, k_exports[i]);
        CHECKF(p != NULL, "export %s", k_exports[i]);
    }
}
TEST(tbs_exports_ordinals_match_names) {
    HMODULE h = t_module("tbs.dll");
    if (!h) { t_skip("tbs.dll not loadable"); return; }
    if (t_is_wine()) { t_skip("ordinal layout is a Windows property"); return; }
    /* ordinals as shipped in the Windows 10 export table */
    static const struct { const char *n; unsigned o; } tab[] = {
        {"Tbsi_Create_Attestation_From_Log",1},{"Tbsi_Get_TCG_Logs",2},{"GetDeviceID",3},{"GetDeviceIDString",4},
        {"GetDeviceIDWithTimeout",5},{"Tbsi_Context_Create",6},{"Tbsi_Create_Windows_Key",7},{"Tbsi_FilterLog",8},
        {"Tbsi_GetDeviceInfo",9},{"Tbsi_Get_OwnerAuth",10},{"Tbsi_Get_TCG_Log",11},{"Tbsi_Get_TCG_Log_Ex",12},
        {"Tbsi_Physical_Presence_Command",13},{"Tbsi_Revoke_Attestation",14},{"Tbsi_ShaHash",15},
        {"Tbsip_Cancel_Commands",16},{"Tbsip_Context_Close",17},{"Tbsip_Submit_Command",18},
        {"Tbsip_Submit_Command_NonBlocking",19},{"Tbsip_TestInterruptInformation",20},{"Tbsip_TestMorBit",21} };
    for (size_t i = 0; i < sizeof tab / sizeof *tab; i++) {
        FARPROC a = GetProcAddress(h, tab[i].n);
        FARPROC b = GetProcAddress(h, (LPCSTR)(ULONG_PTR)tab[i].o);
        CHECKF(a && a == b, "%s ordinal %u", tab[i].n, tab[i].o);
    }
}
TEST(tbs_exports_unknown_name_fails) {
    HMODULE h = t_module("tbs.dll");
    if (!h) { t_skip("tbs.dll not loadable"); return; }
    SET_ERR(0);
    CHECK(GetProcAddress(h, "Tbsi_NoSuchExport") == NULL); EXPECT_ERR(ERROR_PROC_NOT_FOUND);
    SET_ERR(0);
    CHECK(GetProcAddress(h, "tbsi_context_create") == NULL); EXPECT_ERR(ERROR_PROC_NOT_FOUND); /* case sensitive */
}
TEST(tbs_exports_name_ordinal_out_of_range) {
    HMODULE h = t_module("tbs.dll");
    if (!h) { t_skip("tbs.dll not loadable"); return; }
    /* an ordinal that is not exported gives ERROR_INVALID_ORDINAL (182), not PROC_NOT_FOUND */
    EXPECT_GPA_FAIL(h, MAKEINTRESOURCEA(22));
    EXPECT_GPA_FAIL(h, MAKEINTRESOURCEA(0x7fff));
}
TEST(tbs_exports_not_forwarded) {
    /* tbs.dll implements every export itself; the resolved address lies inside tbs.dll */
    HMODULE h = t_module("tbs.dll");
    if (!h) { t_skip("tbs.dll not loadable"); return; }
    for (size_t i = 0; i < sizeof k_exports / sizeof *k_exports; i++) {
        FARPROC p = GetProcAddress(h, k_exports[i]);
        HMODULE owner = NULL;
        if (!p) continue;
        GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCSTR)p, &owner);
        CHECKF(owner == h, "%s owner module", k_exports[i]);
    }
}
TEST(tbs_exports_is_tpm_present_absent_on_win10) {
    /* Tbsi_Is_Tpm_Present is in the Windows 11 SDK, not in the Win10 x64 export table */
    HMODULE h = t_module("tbs.dll");
    if (!h) { t_skip("tbs.dll not loadable"); return; }
    FARPROC p = GetProcAddress(h, "Tbsi_Is_Tpm_Present");
    t_note("Tbsi_Is_Tpm_Present export %s", p ? "present (newer build)" : "absent");
}

/* ---------- Tbsi_Context_Create : argument validation (before any device access) ---------- */
TEST(tbs_ctx_create_null_params_null_handle) {
    NEED(Tbsi_Context_Create); NOEMU();
    void *h = SENT;
    EXPECT_EQ(P(Tbsi_Context_Create)(NULL, &h), TE_BAD_PARAMETER);
    EXPECT_EQ(h, SENT);
}
TEST(tbs_ctx_create_both_null) {
    NEED(Tbsi_Context_Create); NOEMU();
    /* parameters are validated before the output pointer */
    EXPECT_EQ(P(Tbsi_Context_Create)(NULL, NULL), TE_BAD_PARAMETER);
}
TEST(tbs_ctx_create_null_out_pointer_versions) {
    NEED(Tbsi_Context_Create); NOEMU();
    static const UINT32 vers[] = { 0, 1, 2, 3, 4, 0x7fffffff, 0x80000000u, 0xffffffffu };
    for (size_t i = 0; i < sizeof vers / sizeof *vers; i++) {
        tbsx_params2 p = { vers[i], TBSX_TPM12 | TBSX_TPM20 };
        UINT32 r = P(Tbsi_Context_Create)(&p, NULL);
        CHECKF(r == TE_INVALID_OUTPUT_POINTER, "version %u -> 0x%08x", vers[i], r);
    }
}
TEST(tbs_ctx_create_null_out_pointer_v1) {
    NEED(Tbsi_Context_Create); NOEMU();
    tbsx_params1 p = { 1 };
    EXPECT_EQ(P(Tbsi_Context_Create)(&p, NULL), TE_INVALID_OUTPUT_POINTER);
}
TEST(tbs_ctx_create_fail_leaves_handle_untouched) {
    NEED(Tbsi_Context_Create);
    tbsx_devinfo di;
    if (tbsx_tpm_present(&di)) { t_skip("TPM present"); return; }
    void *h = SENT;
    tbsx_params2 p = { 2, TBSX_TPM12 | TBSX_TPM20 };
    EXPECT_EQ(P(Tbsi_Context_Create)(&p, &h), TE_TPM_NOT_FOUND);
    EXPECT_EQ(h, SENT);
}
TEST(tbs_ctx_create_no_tpm_any_version_is_not_found) {
    NEED(Tbsi_Context_Create);
    tbsx_devinfo di;
    if (tbsx_tpm_present(&di)) { t_skip("TPM present"); return; }
    /* the device probe precedes version validation */
    static const UINT32 vers[] = { 0, 1, 2, 3, 99, 0xffffffffu };
    for (size_t i = 0; i < sizeof vers / sizeof *vers; i++) {
        tbsx_params2 p = { vers[i], 0xffffffffu };
        void *h = SENT;
        UINT32 r = P(Tbsi_Context_Create)(&p, &h);
        CHECKF(r == TE_TPM_NOT_FOUND, "version %u -> 0x%08x", vers[i], r);
        EXPECT_EQ(h, SENT);
    }
}
TEST(tbs_ctx_create_tpm_bad_version) {
    NEED(Tbsi_Context_Create); NEED(Tbsip_Context_Close);
    tbsx_devinfo di;
    if (!tbsx_tpm_present(&di)) { t_skip("no TPM"); return; }
    static const UINT32 vers[] = { 0, 3, 4, 0x100, 0xffffffffu };
    for (size_t i = 0; i < sizeof vers / sizeof *vers; i++) {
        tbsx_params2 p = { vers[i], 0xffffffffu };
        void *h = SENT;
        UINT32 r = P(Tbsi_Context_Create)(&p, &h);
        CHECKF(r == TE_INVALID_CONTEXT_PARAM, "version %u -> 0x%08x", vers[i], r);
        EXPECT_EQ(h, SENT);
    }
}

/* ---------- Tbsi_Context_Create : success paths (TPM only) ---------- */
static UINT32 mk(UINT32 ver, UINT32 flags, void **h) {
    tbsx_params2 p = { ver, flags };
    Tbsi_Context_Create_pfn f = TB(Tbsi_Context_Create);
    return f(&p, h);
}
TEST(tbs_ctx_create_v1_matches_tpm_version) {
    NEED(Tbsi_Context_Create); NEED(Tbsip_Context_Close);
    tbsx_devinfo di;
    if (!tbsx_tpm_present(&di)) { t_skip("no TPM"); return; }
    tbsx_params1 p = { 1 };
    void *h = NULL;
    UINT32 r = P(Tbsi_Context_Create)(&p, &h);
    if (di.tpmVersion == 1) { EXPECT_EQ(r, TE_OK); CHECK(h != NULL); }
    else if (di.tpmVersion == 2) { EXPECT_EQ(r, TE_TPM_NOT_FOUND); } /* v1 contexts only see TPM 1.2 */
    else t_note("tpmVersion %u: v1 create 0x%08x", di.tpmVersion, r);
    if (r == 0 && h) EXPECT_EQ(P(Tbsip_Context_Close)(h), TE_OK);
}
TEST(tbs_ctx_create_v2_flag_matrix) {
    NEED(Tbsi_Context_Create); NEED(Tbsip_Context_Close);
    tbsx_devinfo di;
    if (!tbsx_tpm_present(&di)) { t_skip("no TPM"); return; }
    if (di.tpmVersion != 1 && di.tpmVersion != 2) { t_skip("tpmVersion %u", di.tpmVersion); return; }
    UINT32 want_bit = di.tpmVersion == 1 ? TBSX_TPM12 : TBSX_TPM20;
    for (UINT32 f = 0; f < 8; f++) {
        void *h = NULL;
        UINT32 r = mk(2, f, &h);
        UINT32 expect = (f & want_bit) ? TE_OK : TE_TPM_NOT_FOUND;
        CHECKF(r == expect, "flags 0x%x -> 0x%08x want 0x%08x", f, r, expect);
        if (r == 0) { CHECK(h != NULL); EXPECT_EQ(P(Tbsip_Context_Close)(h), TE_OK); }
    }
}
TEST(tbs_ctx_create_v2_reserved_flag_bits_ignored) {
    NEED(Tbsi_Context_Create); NEED(Tbsip_Context_Close);
    tbsx_devinfo di;
    if (!tbsx_tpm_present(&di)) { t_skip("no TPM"); return; }
    if (di.tpmVersion != 1 && di.tpmVersion != 2) { t_skip("tpmVersion"); return; }
    UINT32 bit = di.tpmVersion == 1 ? TBSX_TPM12 : TBSX_TPM20;
    void *h = NULL;
    EXPECT_EQ(mk(2, bit | 0xfffffff8u, &h), TE_OK);
    if (h) P(Tbsip_Context_Close)(h);
    h = NULL;
    EXPECT_EQ(mk(2, 0xfffffff8u, &h), TE_TPM_NOT_FOUND);
}
TEST(tbs_ctx_create_handle_is_kernel_handle) {
    NEED(Tbsi_Context_Create); NEED(Tbsip_Context_Close);
    tbsx_devinfo di;
    if (!tbsx_tpm_present(&di)) { t_skip("no TPM"); return; }
    void *h = NULL;
    UINT32 r = mk(2, TBSX_TPM12 | TBSX_TPM20, &h);
    if (r != 0) { t_note("create failed 0x%08x", r); return; }
    DWORD fl = 0;
    CHECK(GetHandleInformation((HANDLE)h, &fl) != 0);
    CHECK(GetFileType((HANDLE)h) != FILE_TYPE_UNKNOWN || GetLastError() == NO_ERROR);
    EXPECT_EQ(P(Tbsip_Context_Close)(h), TE_OK);
    SET_ERR(0);
    CHECK(GetHandleInformation((HANDLE)h, &fl) == 0); EXPECT_ERR(ERROR_INVALID_HANDLE);
}
TEST(tbs_ctx_create_handle_not_inheritable) {
    NEED(Tbsi_Context_Create); NEED(Tbsip_Context_Close);
    tbsx_devinfo di;
    if (!tbsx_tpm_present(&di)) { t_skip("no TPM"); return; }
    void *h = NULL;
    if (mk(2, TBSX_TPM12 | TBSX_TPM20, &h) != 0) { t_skip("create failed"); return; }
    DWORD fl = 0;
    CHECK(GetHandleInformation((HANDLE)h, &fl) != 0);
    CHECK((fl & HANDLE_FLAG_INHERIT) == 0);
    P(Tbsip_Context_Close)(h);
}
TEST(tbs_ctx_create_multiple_distinct) {
    NEED(Tbsi_Context_Create); NEED(Tbsip_Context_Close);
    tbsx_devinfo di;
    if (!tbsx_tpm_present(&di)) { t_skip("no TPM"); return; }
    void *h[4] = {0};
    int n = 0;
    for (; n < 4; n++) {
        UINT32 r = mk(2, TBSX_TPM12 | TBSX_TPM20, &h[n]);
        if (r != 0) { t_note("create %d: 0x%08x", n, r); break; }
    }
    for (int i = 0; i < n; i++) for (int j = i + 1; j < n; j++) CHECK(h[i] != h[j]);
    for (int i = 0; i < n; i++) EXPECT_EQ(P(Tbsip_Context_Close)(h[i]), TE_OK);
}
TEST(tbs_ctx_create_loop_close) {
    NEED(Tbsi_Context_Create); NEED(Tbsip_Context_Close);
    tbsx_devinfo di;
    if (!tbsx_tpm_present(&di)) { t_skip("no TPM"); return; }
    for (int i = 0; i < 50; i++) {
        void *h = NULL;
        UINT32 r = mk(2, TBSX_TPM12 | TBSX_TPM20, &h);
        if (r != 0) { CHECKF(0, "iteration %d: 0x%08x", i, r); break; }
        EXPECT_EQ(P(Tbsip_Context_Close)(h), TE_OK);
    }
}
TEST(tbs_ctx_create_context_usable_across_threads) {
    NEED(Tbsi_Context_Create); NEED(Tbsip_Context_Close);
    tbsx_devinfo di;
    if (!tbsx_tpm_present(&di)) { t_skip("no TPM"); return; }
    void *h = NULL;
    if (mk(2, TBSX_TPM12 | TBSX_TPM20, &h) != 0) { t_skip("create failed"); return; }
    /* a context is a plain handle: close from another thread works */
    struct a { void *h; UINT32 r; Tbsip_Context_Close_pfn f; } arg = { h, 0xdead, P(Tbsip_Context_Close) };
    DWORD WINAPI th(LPVOID p) { struct a *x = p; x->r = x->f(x->h); return 0; }
    HANDLE t = CreateThread(NULL, 0, th, &arg, 0, NULL);
    if (!t) { P(Tbsip_Context_Close)(h); t_skip("thread"); return; }
    CHECK(WaitForSingleObject(t, 5000) == WAIT_OBJECT_0);
    CloseHandle(t);
    EXPECT_EQ(arg.r, TE_OK);
}
TEST(tbs_ctx_create_requires_device_access) {
    NEED(Tbsi_Context_Create);
    tbsx_devinfo di;
    if (tbsx_tpm_present(&di)) { t_skip("TPM present: covered by success tests"); return; }
    void *h = SENT;
    tbsx_params1 p1 = { 1 };
    EXPECT_EQ(P(Tbsi_Context_Create)(&p1, &h), TE_TPM_NOT_FOUND);
    tbsx_params2 p2 = { 2, TBSX_TPM20 };
    EXPECT_EQ(P(Tbsi_Context_Create)(&p2, &h), TE_TPM_NOT_FOUND);
    p2.flags = TBSX_TPM12 | TBSX_RAW;
    EXPECT_EQ(P(Tbsi_Context_Create)(&p2, &h), TE_TPM_NOT_FOUND);
}

/* ---------- Tbsip_Context_Close ---------- */
TEST(tbs_close_null_handle) {
    NEED(Tbsip_Context_Close);
    EXPECT_EQ(P(Tbsip_Context_Close)(NULL), TE_INVALID_CONTEXT);
}
TEST(tbs_close_null_handle_twice) {
    NEED(Tbsip_Context_Close);
    EXPECT_EQ(P(Tbsip_Context_Close)(NULL), TE_INVALID_CONTEXT);
    EXPECT_EQ(P(Tbsip_Context_Close)(NULL), TE_INVALID_CONTEXT);
}
TEST(tbs_close_preserves_last_error_not_required) {
    NEED(Tbsip_Context_Close);
    /* result is returned in the return value, not through SetLastError */
    SET_ERR(0x1234);
    UINT32 r = P(Tbsip_Context_Close)(NULL);
    EXPECT_EQ(r, TE_INVALID_CONTEXT);
    t_note("GetLastError after failed close: %lu", GetLastError());
}
TEST(tbs_close_is_plain_handle_close) {
    NEED(Tbsip_Context_Close);
    /* the implementation is a bare NtClose: any open kernel handle is closed and reported as success */
    HANDLE e = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!e) { t_skip("CreateEvent"); return; }
    EXPECT_EQ(P(Tbsip_Context_Close)((void *)e), TE_OK);
    SET_ERR(0);
    CHECK(SetEvent(e) == 0); EXPECT_ERR(ERROR_INVALID_HANDLE);
}
TEST(tbs_close_double_close_reports_invalid_context) {
    NEED(Tbsip_Context_Close);
    HANDLE e = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!e) { t_skip("CreateEvent"); return; }
    EXPECT_EQ(P(Tbsip_Context_Close)((void *)e), TE_OK);
    EXPECT_EQ(P(Tbsip_Context_Close)((void *)e), TE_INVALID_CONTEXT);
}
TEST(tbs_close_double_close_real_context) {
    NEED(Tbsi_Context_Create); NEED(Tbsip_Context_Close);
    tbsx_devinfo di;
    if (!tbsx_tpm_present(&di)) { t_skip("no TPM"); return; }
    void *h = NULL;
    if (mk(2, TBSX_TPM12 | TBSX_TPM20, &h) != 0) { t_skip("create failed"); return; }
    EXPECT_EQ(P(Tbsip_Context_Close)(h), TE_OK);
    EXPECT_EQ(P(Tbsip_Context_Close)(h), TE_INVALID_CONTEXT);
}

/* ---------- Tbsi_GetDeviceInfo ---------- */
TEST(tbs_devinfo_no_tpm_not_found) {
    NEED(Tbsi_GetDeviceInfo);
    tbsx_devinfo di;
    if (tbsx_tpm_present(&di)) { t_skip("TPM present"); return; }
    tbsx_devinfo d; memset(&d, 0xcc, sizeof d);
    EXPECT_EQ(P(Tbsi_GetDeviceInfo)(sizeof d, &d), TE_TPM_NOT_FOUND);
    for (size_t i = 0; i < sizeof d; i++) if (((BYTE *)&d)[i] != 0xcc) { CHECK(0 && "buffer modified"); break; }
}
TEST(tbs_devinfo_no_tpm_sizes) {
    NEED(Tbsi_GetDeviceInfo);
    tbsx_devinfo di;
    if (tbsx_tpm_present(&di)) { t_skip("TPM present"); return; }
    BYTE buf[64];
    static const UINT32 sizes[] = { 0, 1, 4, 8, 15, 16, 17, 32, 64 };
    for (size_t i = 0; i < sizeof sizes / sizeof *sizes; i++) {
        memset(buf, 0, sizeof buf);
        UINT32 r = P(Tbsi_GetDeviceInfo)(sizes[i], buf);
        CHECKF(r == TE_TPM_NOT_FOUND, "size %u -> 0x%08x", sizes[i], r);
    }
}
TEST(tbs_devinfo_no_tpm_null_buffer) {
    NEED(Tbsi_GetDeviceInfo);
    tbsx_devinfo di;
    if (tbsx_tpm_present(&di)) { t_skip("TPM present"); return; }
    /* the device open fails first, so a NULL buffer is never touched */
    EXPECT_EQ(P(Tbsi_GetDeviceInfo)(0, NULL), TE_TPM_NOT_FOUND);
    EXPECT_EQ(P(Tbsi_GetDeviceInfo)(16, NULL), TE_TPM_NOT_FOUND);
}
TEST(tbs_devinfo_fields) {
    NEED(Tbsi_GetDeviceInfo);
    tbsx_devinfo d;
    if (!tbsx_tpm_present(&d)) { t_skip("no TPM"); return; }
    EXPECT_EQ(d.structVersion, 1);
    CHECK(d.tpmVersion == 1 || d.tpmVersion == 2);
    CHECK(d.tpmInterfaceType <= 5);
    t_note("TPM_DEVICE_INFO: structVersion=%u tpmVersion=%u ifType=%u impRevision=%u", d.structVersion, d.tpmVersion, d.tpmInterfaceType, d.tpmImpRevision);
}
TEST(tbs_devinfo_repeatable) {
    NEED(Tbsi_GetDeviceInfo);
    tbsx_devinfo a, b;
    if (!tbsx_tpm_present(&a)) { t_skip("no TPM"); return; }
    memset(&b, 0, sizeof b);
    EXPECT_EQ(P(Tbsi_GetDeviceInfo)(sizeof b, &b), TE_OK);
    CHECK(!memcmp(&a, &b, sizeof a));
}
TEST(tbs_devinfo_oversized_buffer) {
    NEED(Tbsi_GetDeviceInfo);
    tbsx_devinfo d;
    if (!tbsx_tpm_present(&d)) { t_skip("no TPM"); return; }
    BYTE buf[64]; memset(buf, 0xee, sizeof buf);
    UINT32 r = P(Tbsi_GetDeviceInfo)(sizeof buf, buf);
    t_note("size 64 -> 0x%08x", r);
    if (r == 0) CHECK(!memcmp(buf, &d, sizeof d));
}
TEST(tbs_devinfo_undersized_buffer) {
    NEED(Tbsi_GetDeviceInfo);
    tbsx_devinfo d;
    if (!tbsx_tpm_present(&d)) { t_skip("no TPM"); return; }
    static const UINT32 sizes[] = { 0, 4, 8, 12, 15 };
    for (size_t i = 0; i < sizeof sizes / sizeof *sizes; i++) {
        BYTE buf[16]; memset(buf, 0xee, sizeof buf);
        UINT32 r = P(Tbsi_GetDeviceInfo)(sizes[i], buf);
        t_note("size %u -> 0x%08x", sizes[i], r);
        /* nothing beyond the declared size may be written */
        for (UINT32 k = sizes[i]; k < 16; k++) if (buf[k] != 0xee) { CHECKF(0, "byte %u past declared size modified", k); break; }
    }
}
TEST(tbs_devinfo_consistent_with_context_create) {
    NEED(Tbsi_Context_Create); NEED(Tbsip_Context_Close);
    tbsx_devinfo d;
    if (!tbsx_tpm_present(&d)) { t_skip("no TPM"); return; }
    void *h = NULL;
    UINT32 r12 = mk(2, TBSX_TPM12, &h); if (h) P(Tbsip_Context_Close)(h); h = NULL;
    UINT32 r20 = mk(2, TBSX_TPM20, &h); if (h) P(Tbsip_Context_Close)(h);
    EXPECT_EQ(r12 == 0, d.tpmVersion == 1);
    EXPECT_EQ(r20 == 0, d.tpmVersion == 2);
}
