/* TCG event-log retrieval, log filtering, attestation-from-log argument validation. */
#include "tbsx.h"

static int emu_skip(void) { if (tbsx_emulated()) { t_skip("emulator stub"); return 1; } return 0; }

/* ---------- Tbsi_Get_TCG_Log ---------- */
TEST(tbs_log_null_length_pointer) {
    NEED(Tbsi_Get_TCG_Log); if (emu_skip()) return;
    BYTE b[16];
    EXPECT_EQ(P(Tbsi_Get_TCG_Log)(NULL, NULL, NULL), TE_INVALID_OUTPUT_POINTER);
    EXPECT_EQ(P(Tbsi_Get_TCG_Log)(NULL, b, NULL), TE_INVALID_OUTPUT_POINTER);
    EXPECT_EQ(P(Tbsi_Get_TCG_Log)((void *)(ULONG_PTR)0x1234, b, NULL), TE_INVALID_OUTPUT_POINTER);
}
TEST(tbs_log_null_buffer_with_nonzero_length) {
    NEED(Tbsi_Get_TCG_Log); if (emu_skip()) return;
    static const UINT32 sizes[] = { 1, 4, 100, 0x10000, 0xffffffffu };
    for (size_t i = 0; i < sizeof sizes / sizeof *sizes; i++) {
        UINT32 n = sizes[i];
        EXPECT_EQ(P(Tbsi_Get_TCG_Log)(NULL, NULL, &n), TE_BAD_PARAMETER);
        EXPECT_EQ(n, sizes[i]);       /* untouched on parameter errors */
    }
}
TEST(tbs_log_context_argument_is_ignored) {
    NEED(Tbsi_Get_TCG_Log); if (emu_skip()) return;
    UINT32 a = 0, b = 0;
    UINT32 ra = P(Tbsi_Get_TCG_Log)(NULL, NULL, &a);
    UINT32 rb = P(Tbsi_Get_TCG_Log)((void *)(ULONG_PTR)0xdeadbeef0, NULL, &b);
    EXPECT_EQ(ra, rb);
    EXPECT_EQ(a, b);
}
TEST(tbs_log_size_query_result_codes) {
    NEED(Tbsi_Get_TCG_Log); if (emu_skip()) return;
    UINT32 n = 0x1111;
    UINT32 r = P(Tbsi_Get_TCG_Log)(NULL, NULL, &n);
    if (r == 0) { CHECK(n > 0); t_note("TCG log size %u", n); }
    else {
        /* no WBCL value in HKLM\SYSTEM\CurrentControlSet\Control\IntegrityServices */
        EXPECT_EQ(r, TE_INTERNAL_ERROR);
        EXPECT_EQ(n, 0);              /* length is zeroed before the registry is consulted */
    }
}
TEST(tbs_log_size_query_zero_length_with_buffer) {
    NEED(Tbsi_Get_TCG_Log); if (emu_skip()) return;
    BYTE b[8]; memset(b, 0x5c, sizeof b);
    UINT32 n = 0, m = 0;
    UINT32 r1 = P(Tbsi_Get_TCG_Log)(NULL, b, &n);
    UINT32 r2 = P(Tbsi_Get_TCG_Log)(NULL, NULL, &m);
    EXPECT_EQ(r1, r2);
    EXPECT_EQ(n, m);
    for (int i = 0; i < 8; i++) CHECK(b[i] == 0x5c);
}
TEST(tbs_log_fetch_exact_size) {
    NEED(Tbsi_Get_TCG_Log); if (emu_skip()) return;
    UINT32 n = 0;
    if (P(Tbsi_Get_TCG_Log)(NULL, NULL, &n) != 0 || n == 0) { t_skip("no TCG log on this machine"); return; }
    if (n > 16 * 1024 * 1024) { t_skip("log unexpectedly large"); return; }
    BYTE *b = malloc(n + 16);
    if (!b) { t_skip("alloc"); return; }
    memset(b, 0xa5, n + 16);
    UINT32 m = n;
    EXPECT_EQ(P(Tbsi_Get_TCG_Log)(NULL, b, &m), TE_OK);
    EXPECT_EQ(m, n);
    for (int i = 0; i < 16; i++) CHECK(b[n + i] == 0xa5);   /* no overrun */
    if (n >= 8) t_note("first event: pcr=%u type=0x%x", *(UINT32 *)b, *(UINT32 *)(b + 4));
    free(b);
}
TEST(tbs_log_fetch_oversized_buffer_reports_actual_size) {
    NEED(Tbsi_Get_TCG_Log); if (emu_skip()) return;
    UINT32 n = 0;
    if (P(Tbsi_Get_TCG_Log)(NULL, NULL, &n) != 0 || n == 0 || n > 16 * 1024 * 1024) { t_skip("no TCG log"); return; }
    BYTE *b = malloc(n + 1024);
    if (!b) { t_skip("alloc"); return; }
    UINT32 m = n + 1024;
    EXPECT_EQ(P(Tbsi_Get_TCG_Log)(NULL, b, &m), TE_OK);
    EXPECT_EQ(m, n);
    free(b);
}
TEST(tbs_log_fetch_too_small_buffer) {
    NEED(Tbsi_Get_TCG_Log); if (emu_skip()) return;
    UINT32 n = 0;
    if (P(Tbsi_Get_TCG_Log)(NULL, NULL, &n) != 0 || n < 2 || n > 16 * 1024 * 1024) { t_skip("no TCG log"); return; }
    BYTE *b = malloc(n + 16);
    if (!b) { t_skip("alloc"); return; }
    static const int deltas[] = { 1, 2, 16 };
    for (size_t i = 0; i < 3; i++) {
        if ((UINT32)deltas[i] >= n) continue;
        memset(b, 0xa5, n + 16);
        UINT32 m = n - deltas[i];
        UINT32 r = P(Tbsi_Get_TCG_Log)(NULL, b, &m);
        CHECKF(r == TE_INSUFFICIENT_BUFFER, "short by %d -> 0x%08x", deltas[i], r);
        t_note("short by %d: length reported %u (required %u)", deltas[i], m, n);
        for (UINT32 k = n - deltas[i]; k < n + 16; k++) if (b[k] != 0xa5) { CHECK(0 && "wrote past declared size"); break; }
    }
    free(b);
}
TEST(tbs_log_fetch_is_repeatable) {
    NEED(Tbsi_Get_TCG_Log); if (emu_skip()) return;
    UINT32 n = 0;
    if (P(Tbsi_Get_TCG_Log)(NULL, NULL, &n) != 0 || n == 0 || n > 16 * 1024 * 1024) { t_skip("no TCG log"); return; }
    BYTE *a = malloc(n), *b = malloc(n);
    if (a && b) {
        UINT32 m1 = n, m2 = n;
        EXPECT_EQ(P(Tbsi_Get_TCG_Log)(NULL, a, &m1), TE_OK);
        EXPECT_EQ(P(Tbsi_Get_TCG_Log)(NULL, b, &m2), TE_OK);
        CHECK(m1 == m2 && !memcmp(a, b, m1));
    }
    free(a); free(b);
}

/* ---------- Tbsi_Get_TCG_Log_Ex ---------- */
TEST(tbs_logex_null_length_pointer) {
    NEED(Tbsi_Get_TCG_Log_Ex); if (emu_skip()) return;
    BYTE b[8];
    /* NULL length is rejected before the TPM is consulted, with BAD_PARAMETER (not OUTPUT_POINTER) */
    for (UINT32 t = 0; t <= 7; t++) {
        UINT32 r = P(Tbsi_Get_TCG_Log_Ex)(t, b, NULL);
        CHECKF(r == TE_BAD_PARAMETER, "type %u -> 0x%08x", t, r);
    }
    EXPECT_EQ(P(Tbsi_Get_TCG_Log_Ex)(0, NULL, NULL), TE_BAD_PARAMETER);
}
TEST(tbs_logex_no_tpm_all_types) {
    NEED(Tbsi_Get_TCG_Log_Ex); if (emu_skip()) return;
    tbsx_devinfo di;
    if (tbsx_tpm_present(&di)) { t_skip("TPM present"); return; }
    for (UINT32 t = 0; t <= 8; t++) {
        UINT32 n = 0;
        UINT32 r = P(Tbsi_Get_TCG_Log_Ex)(t, NULL, &n);
        CHECKF(r == TE_TPM_NOT_FOUND, "type %u -> 0x%08x", t, r);
    }
    UINT32 n = 0;
    EXPECT_EQ(P(Tbsi_Get_TCG_Log_Ex)(0xffffffffu, NULL, &n), TE_TPM_NOT_FOUND);
}
TEST(tbs_logex_invalid_type_with_tpm) {
    NEED(Tbsi_Get_TCG_Log_Ex); if (emu_skip()) return;
    tbsx_devinfo di;
    if (!tbsx_tpm_present(&di)) { t_skip("no TPM"); return; }
    static const UINT32 types[] = { 6, 7, 100, 0x80000000u, 0xffffffffu };
    for (size_t i = 0; i < sizeof types / sizeof *types; i++) {
        UINT32 n = 0;
        UINT32 r = P(Tbsi_Get_TCG_Log_Ex)(types[i], NULL, &n);
        CHECKF(r == TE_BAD_PARAMETER, "type %u -> 0x%08x", types[i], r);
    }
}
TEST(tbs_logex_srtm_current_matches_legacy_api) {
    NEED(Tbsi_Get_TCG_Log_Ex); NEED(Tbsi_Get_TCG_Log); if (emu_skip()) return;
    tbsx_devinfo di;
    if (!tbsx_tpm_present(&di)) { t_skip("no TPM"); return; }
    UINT32 a = 0, b = 0;
    UINT32 ra = P(Tbsi_Get_TCG_Log)(NULL, NULL, &a);
    UINT32 rb = P(Tbsi_Get_TCG_Log_Ex)(0, NULL, &b);
    if (ra == 0) { EXPECT_EQ(rb, 0); EXPECT_EQ(a, b); }
    else {
        EXPECT_EQ(ra, TE_INTERNAL_ERROR);
        EXPECT_EQ(rb, TE_NO_EVENT_LOG);   /* Ex distinguishes "no log" from "internal error" */
    }
}
TEST(tbs_logex_log_types_result_codes) {
    NEED(Tbsi_Get_TCG_Log_Ex); if (emu_skip()) return;
    tbsx_devinfo di;
    if (!tbsx_tpm_present(&di)) { t_skip("no TPM"); return; }
    for (UINT32 t = 0; t <= 5; t++) {
        UINT32 n = 0;
        UINT32 r = P(Tbsi_Get_TCG_Log_Ex)(t, NULL, &n);
        t_note("log type %u: 0x%08x size=%u", t, r, n);
        CHECKF(r == 0 || (r & 0xffff0000) == 0x80280000, "type %u -> 0x%08x", t, r);
    }
}
TEST(tbs_logex_srtm_boot_size_then_fetch) {
    NEED(Tbsi_Get_TCG_Log_Ex); if (emu_skip()) return;
    tbsx_devinfo di;
    if (!tbsx_tpm_present(&di)) { t_skip("no TPM"); return; }
    UINT32 n = 0;
    UINT32 r = P(Tbsi_Get_TCG_Log_Ex)(2, NULL, &n);
    if (r != 0 || n == 0 || n > 16 * 1024 * 1024) { t_note("SRTM boot log: 0x%08x size=%u", r, n); return; }
    BYTE *b = malloc(n);
    if (!b) return;
    UINT32 m = n;
    EXPECT_EQ(P(Tbsi_Get_TCG_Log_Ex)(2, b, &m), TE_OK);
    EXPECT_EQ(m, n);
    m = n - 1;
    r = P(Tbsi_Get_TCG_Log_Ex)(2, b, &m);
    EXPECT_EQ(r, TE_INSUFFICIENT_BUFFER);
    free(b);
}

/* ---------- Tbsi_Get_TCG_Logs ---------- */
TEST(tbs_logs_null_length_pointer) {
    NEED(Tbsi_Get_TCG_Logs); if (emu_skip()) return;
    BYTE b[8];
    EXPECT_EQ(P(Tbsi_Get_TCG_Logs)(0, NULL, b, sizeof b, NULL, 0), TE_INVALID_OUTPUT_POINTER);
    EXPECT_EQ(P(Tbsi_Get_TCG_Logs)(0, NULL, NULL, 0, NULL, 0), TE_INVALID_OUTPUT_POINTER);
    /* the output pointer is validated before the flags */
    EXPECT_EQ(P(Tbsi_Get_TCG_Logs)(0, NULL, NULL, 0, NULL, 2), TE_INVALID_OUTPUT_POINTER);
}
TEST(tbs_logs_reserved_flag_bits) {
    NEED(Tbsi_Get_TCG_Logs); if (emu_skip()) return;
    static const UINT32 flags[] = { 2, 3, 4, 0x80000000u, 0xfffffffeu, 0xffffffffu };
    for (size_t i = 0; i < sizeof flags / sizeof *flags; i++) {
        UINT32 out = 0x77777777;
        UINT32 r = P(Tbsi_Get_TCG_Logs)(0, NULL, NULL, 0, &out, flags[i]);
        CHECKF(r == TE_BAD_PARAMETER, "flags 0x%x -> 0x%08x", flags[i], r);
        CHECKF(out == 0, "length not zeroed: %u", out);
    }
}
TEST(tbs_logs_length_zeroed_first) {
    NEED(Tbsi_Get_TCG_Logs); if (emu_skip()) return;
    UINT32 out = 0x77777777;
    UINT32 r = P(Tbsi_Get_TCG_Logs)(0, NULL, NULL, 0, &out, 0);
    t_note("size query: 0x%08x len=%u", r, out);
    if (r != 0) CHECKF(r == TE_INTERNAL_ERROR || r == TE_NO_EVENT_LOG || r == TE_INSUFFICIENT_BUFFER, "0x%08x", r);
    CHECK(out != 0x77777777);   /* length is always written once the pointer is valid */
}
TEST(tbs_logs_flag_one_accepted) {
    NEED(Tbsi_Get_TCG_Logs); if (emu_skip()) return;
    UINT32 out = 0x77777777;
    UINT32 r = P(Tbsi_Get_TCG_Logs)(0, NULL, NULL, 0, &out, 1);
    t_note("flags=1 size query: 0x%08x len=%u", r, out);
    CHECK(r != TE_BAD_PARAMETER);
}
TEST(tbs_logs_buffer_too_small) {
    NEED(Tbsi_Get_TCG_Logs); if (emu_skip()) return;
    UINT32 n = 0;
    if (P(Tbsi_Get_TCG_Logs)(0, NULL, NULL, 0, &n, 0) != 0 || n < 2 || n > 16 * 1024 * 1024) { t_skip("no logs"); return; }
    BYTE *b = malloc(n);
    if (!b) return;
    UINT32 m = 1;
    UINT32 r = P(Tbsi_Get_TCG_Logs)(0, NULL, b, 1, &m, 0);
    CHECKF(r == TE_INSUFFICIENT_BUFFER, "0x%08x", r);
    m = 0;
    r = P(Tbsi_Get_TCG_Logs)(0, NULL, b, n, &m, 0);
    t_note("full fetch: 0x%08x len=%u (query %u)", r, m, n);
    free(b);
}

/* ---------- Tbsi_FilterLog ---------- */
TEST(tbs_filterlog_invalid_arguments) {
    NEED(Tbsi_FilterLog); if (emu_skip()) return;
    BYTE log[64] = {0}, out[64]; UINT32 n = 0x1234;
    EXPECT_EQ(P(Tbsi_FilterLog)(NULL, 64, 1, out, 64, &n), NT_INVALID_PARAMETER);
    EXPECT_EQ(P(Tbsi_FilterLog)(log, 0, 1, out, 64, &n), NT_INVALID_PARAMETER);
    EXPECT_EQ(P(Tbsi_FilterLog)(log, 64, 0, out, 64, &n), NT_INVALID_PARAMETER);
    EXPECT_EQ(P(Tbsi_FilterLog)(log, 64, 1, out, 64, NULL), NT_INVALID_PARAMETER);
    EXPECT_EQ(n, 0x1234);       /* untouched on parameter errors */
}
TEST(tbs_filterlog_all_null) {
    NEED(Tbsi_FilterLog); if (emu_skip()) return;
    EXPECT_EQ(P(Tbsi_FilterLog)(NULL, 0, 0, NULL, 0, NULL), NT_INVALID_PARAMETER);
}
TEST(tbs_filterlog_status_is_ntstatus_not_tbs) {
    NEED(Tbsi_FilterLog); if (emu_skip()) return;
    UINT32 n = 0;
    UINT32 r = P(Tbsi_FilterLog)(NULL, 1, 1, NULL, 0, &n);
    CHECK((r & 0xc0000000u) == 0xc0000000u);      /* STATUS_ error severity */
    CHECK((r & 0x0fff0000u) != 0x00280000u);      /* not a TBS HRESULT */
}
TEST(tbs_filterlog_each_missing_argument_table) {
    NEED(Tbsi_FilterLog); if (emu_skip()) return;
    BYTE log[32] = {0};
    struct { const BYTE *l; UINT32 cl, mask; UINT32 *pn; } t[] = {
        { NULL, 32, 1, NULL }, { log, 0, 1, NULL }, { log, 32, 0, NULL }, { log, 32, 1, NULL },
        { NULL, 0, 0, NULL }, { log, 0, 0, NULL },
    };
    for (size_t i = 0; i < sizeof t / sizeof *t; i++) {
        UINT32 r = P(Tbsi_FilterLog)(t[i].l, t[i].cl, t[i].mask, NULL, 0, t[i].pn);
        CHECKF(r == NT_INVALID_PARAMETER, "case %zu -> 0x%08x", i, r);
    }
}

/* ---------- Tbsi_Create_Attestation_From_Log : validation only ---------- */
TEST(tbs_attest_invalid_arguments) {
    NEED(Tbsi_Create_Attestation_From_Log); if (emu_skip()) return;
    BYTE log[64] = {0}; UINT32 n = 0x4321;
    /* (log, cbLog, ?, ?, ?, ?, cbOut, &cbOut, flags) */
    EXPECT_EQ(P(Tbsi_Create_Attestation_From_Log)(NULL, 64, NULL, NULL, NULL, NULL, 0, &n, 0), NT_INVALID_PARAMETER);
    EXPECT_EQ(P(Tbsi_Create_Attestation_From_Log)(log, 0, NULL, NULL, NULL, NULL, 0, &n, 0), NT_INVALID_PARAMETER);
    EXPECT_EQ(P(Tbsi_Create_Attestation_From_Log)(log, 64, NULL, NULL, NULL, NULL, 0, NULL, 0), NT_INVALID_PARAMETER);
    EXPECT_EQ(n, 0x4321);
}
TEST(tbs_attest_reserved_flags) {
    NEED(Tbsi_Create_Attestation_From_Log); if (emu_skip()) return;
    BYTE log[64] = {0}; UINT32 n = 0;
    static const UINT32 flags[] = { 2, 3, 0x100, 0x80000000u, 0xfffffffeu, 0xffffffffu };
    for (size_t i = 0; i < sizeof flags / sizeof *flags; i++) {
        UINT32 r = P(Tbsi_Create_Attestation_From_Log)(log, 64, NULL, NULL, NULL, NULL, 0, &n, flags[i]);
        CHECKF(r == NT_INVALID_PARAMETER, "flags 0x%x -> 0x%08x", flags[i], r);
    }
}
TEST(tbs_attest_all_null) {
    NEED(Tbsi_Create_Attestation_From_Log); if (emu_skip()) return;
    EXPECT_EQ(P(Tbsi_Create_Attestation_From_Log)(NULL, 0, NULL, NULL, NULL, NULL, 0, NULL, 0), NT_INVALID_PARAMETER);
}
