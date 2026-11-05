/* Tbsip_Submit_Command / _NonBlocking / Cancel_Commands / TestInterruptInformation / TestMorBit.
 * Only read-only TPM2 commands (GetRandom, GetCapability) are ever sent. */
#include "tbsx.h"

#define PRIO_LOW 100
#define PRIO_NORMAL 200
#define PRIO_HIGH 300
#define PRIO_SYSTEM 400
#define PRIO_MAX 0x80000000u

static const BYTE k_getrandom8[12] = { 0x80,0x01, 0,0,0,12, 0,0,0x01,0x7b, 0,8 };
/* TPM2_GetCapability(TPM_CAP_TPM_PROPERTIES, TPM_PT_FIXED, 8) */
static const BYTE k_getcap[22] = { 0x80,0x01, 0,0,0,22, 0,0,0x01,0x7a, 0,0,0,6, 0,0,0x01,0x00, 0,0,0,8 };

typedef UINT32 (*submit_t)(void *, UINT32, UINT32, const BYTE *, UINT32, BYTE *, UINT32 *);
static submit_t subs[2];
static const char *subn[2] = { "Tbsip_Submit_Command", "Tbsip_Submit_Command_NonBlocking" };
static int load_subs(void) {
    if (tbsx_emulated()) { t_skip("emulator stub"); return 0; }
    subs[0] = (submit_t)tbsx_proc(subn[0]);
    subs[1] = (submit_t)tbsx_proc(subn[1]);
    if (!subs[0] || !subs[1]) { t_skip("missing export"); return 0; }
    return 1;
}
#define FOR_BOTH for (int v = 0; v < 2; v++)

static UINT32 be32(const BYTE *p) { return ((UINT32)p[0] << 24) | ((UINT32)p[1] << 16) | ((UINT32)p[2] << 8) | p[3]; }
static unsigned be16(const BYTE *p) { return (p[0] << 8) | p[1]; }

/* ----- argument validation that happens before the device is touched; hContext is NULL on purpose ----- */
TEST(tbs_submit_null_result_buffer) {
    if (!load_subs()) return;
    FOR_BOTH {
        UINT32 cb = 100;
        UINT32 r = subs[v](NULL, 0, PRIO_NORMAL, k_getrandom8, sizeof k_getrandom8, NULL, &cb);
        CHECKF(r == TE_INVALID_OUTPUT_POINTER, "%s 0x%08x", subn[v], r);
        EXPECT_EQ(cb, 100);
    }
}
TEST(tbs_submit_null_result_length) {
    if (!load_subs()) return;
    BYTE out[64];
    FOR_BOTH {
        UINT32 r = subs[v](NULL, 0, PRIO_NORMAL, k_getrandom8, sizeof k_getrandom8, out, NULL);
        CHECKF(r == TE_INVALID_OUTPUT_POINTER, "%s 0x%08x", subn[v], r);
    }
}
TEST(tbs_submit_both_outputs_null) {
    if (!load_subs()) return;
    FOR_BOTH {
        UINT32 r = subs[v](NULL, 0, PRIO_NORMAL, k_getrandom8, sizeof k_getrandom8, NULL, NULL);
        CHECKF(r == TE_INVALID_OUTPUT_POINTER, "%s 0x%08x", subn[v], r);
    }
}
TEST(tbs_submit_result_buffer_below_ten_bytes) {
    if (!load_subs()) return;
    BYTE out[64];
    FOR_BOTH for (UINT32 n = 0; n < 10; n++) {
        UINT32 cb = n;
        memset(out, 0xaa, sizeof out);
        UINT32 r = subs[v](NULL, 0, PRIO_NORMAL, k_getrandom8, sizeof k_getrandom8, out, &cb);
        CHECKF(r == TE_INSUFFICIENT_BUFFER, "%s cb=%u -> 0x%08x", subn[v], n, r);
        CHECKF(cb == n, "cb modified: %u", cb);
        CHECK(out[0] == 0xaa);
    }
}
TEST(tbs_submit_insufficient_buffer_precedes_command_checks) {
    if (!load_subs()) return;
    BYTE out[16]; UINT32 cb = 9;
    FOR_BOTH {
        cb = 9;
        EXPECT_EQ(subs[v](NULL, 0, PRIO_NORMAL, NULL, 0, out, &cb), TE_INSUFFICIENT_BUFFER);
    }
}
TEST(tbs_submit_null_command) {
    if (!load_subs()) return;
    BYTE out[64];
    FOR_BOTH {
        UINT32 cb = sizeof out;
        EXPECT_EQ(subs[v](NULL, 0, PRIO_NORMAL, NULL, 12, out, &cb), TE_BAD_PARAMETER);
        EXPECT_EQ(cb, sizeof out);
    }
}
TEST(tbs_submit_zero_length_command) {
    if (!load_subs()) return;
    BYTE out[64];
    FOR_BOTH {
        UINT32 cb = sizeof out;
        EXPECT_EQ(subs[v](NULL, 0, PRIO_NORMAL, k_getrandom8, 0, out, &cb), TE_BAD_PARAMETER);
        cb = sizeof out;
        EXPECT_EQ(subs[v](NULL, 0, PRIO_NORMAL, NULL, 0, out, &cb), TE_BAD_PARAMETER);
    }
}
TEST(tbs_submit_nonzero_locality_rejected) {
    if (!load_subs()) return;
    BYTE out[64];
    /* only locality zero is accepted by this implementation, even for the named localities 1..4 */
    static const UINT32 loc[] = { 1, 2, 3, 4, 5, 255, 0x80000000u, 0xffffffffu };
    FOR_BOTH for (size_t i = 0; i < sizeof loc / sizeof *loc; i++) {
        UINT32 cb = sizeof out;
        UINT32 r = subs[v](NULL, loc[i], PRIO_NORMAL, k_getrandom8, sizeof k_getrandom8, out, &cb);
        CHECKF(r == TE_BAD_PARAMETER, "%s locality %u -> 0x%08x", subn[v], loc[i], r);
    }
}
TEST(tbs_submit_locality_checked_before_output_pointers) {
    if (!load_subs()) return;
    FOR_BOTH {
        EXPECT_EQ(subs[v](NULL, 1, PRIO_NORMAL, k_getrandom8, sizeof k_getrandom8, NULL, NULL), TE_BAD_PARAMETER);
    }
}
TEST(tbs_submit_priority_above_max_rejected) {
    if (!load_subs()) return;
    BYTE out[64];
    static const UINT32 pr[] = { 0x80000001u, 0x80000002u, 0xfffffffeu, 0xffffffffu };
    FOR_BOTH for (size_t i = 0; i < sizeof pr / sizeof *pr; i++) {
        UINT32 cb = sizeof out;
        UINT32 r = subs[v](NULL, 0, pr[i], k_getrandom8, sizeof k_getrandom8, out, &cb);
        CHECKF(r == TE_BAD_PARAMETER, "%s priority 0x%x -> 0x%08x", subn[v], pr[i], r);
    }
}
TEST(tbs_submit_priority_range_reaches_device) {
    if (!load_subs()) return;
    BYTE out[64];
    /* priorities up to TBS_COMMAND_PRIORITY_MAX pass validation; the NULL context is then refused by the device layer */
    static const UINT32 pr[] = { 0, 1, PRIO_LOW, 199, PRIO_NORMAL, 299, PRIO_HIGH, 399, PRIO_SYSTEM, 1000, PRIO_MAX };
    FOR_BOTH for (size_t i = 0; i < sizeof pr / sizeof *pr; i++) {
        UINT32 cb = sizeof out;
        UINT32 r = subs[v](NULL, 0, pr[i], k_getrandom8, sizeof k_getrandom8, out, &cb);
        CHECKF(r == TE_INVALID_CONTEXT, "%s priority %u -> 0x%08x", subn[v], pr[i], r);
        CHECKF(cb == sizeof out, "cb modified on failure");
    }
}
TEST(tbs_submit_null_context) {
    if (!load_subs()) return;
    BYTE out[64];
    FOR_BOTH {
        UINT32 cb = sizeof out; memset(out, 0x77, sizeof out);
        EXPECT_EQ(subs[v](NULL, 0, PRIO_NORMAL, k_getrandom8, sizeof k_getrandom8, out, &cb), TE_INVALID_CONTEXT);
        EXPECT_EQ(cb, sizeof out);
        CHECK(out[0] == 0x77 && out[63] == 0x77);
    }
}
TEST(tbs_submit_not_a_context_handle) {
    if (!load_subs()) return;
    /* a valid kernel handle that is not a TPM context: the ioctl is refused, not crashed */
    HANDLE e = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!e) { t_skip("CreateEvent"); return; }
    BYTE out[64];
    FOR_BOTH {
        UINT32 cb = sizeof out;
        UINT32 r = subs[v]((void *)e, 0, PRIO_NORMAL, k_getrandom8, sizeof k_getrandom8, out, &cb);
        CHECKF(r != 0 && (r & 0xffff0000) == 0x80280000, "%s -> 0x%08x", subn[v], r);
        t_note("%s on event handle: 0x%08x", subn[v], r);
    }
    CloseHandle(e);
}
TEST(tbs_submit_closed_context_handle) {
    if (!load_subs()) return;
    HANDLE e = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!e) { t_skip("CreateEvent"); return; }
    CloseHandle(e);
    BYTE out[64];
    FOR_BOTH {
        UINT32 cb = sizeof out;
        UINT32 r = subs[v]((void *)e, 0, PRIO_NORMAL, k_getrandom8, sizeof k_getrandom8, out, &cb);
        CHECKF(r == TE_INVALID_CONTEXT, "%s -> 0x%08x", subn[v], r);
    }
}
TEST(tbs_submit_commands_larger_than_limit_still_validated_first) {
    if (!load_subs()) return;
    /* TBS_IN_OUT_BUF_SIZE_MAX is 256 KiB; the result-buffer checks run before anything else */
    FOR_BOTH {
        UINT32 cb = 0;
        EXPECT_EQ(subs[v](NULL, 0, PRIO_NORMAL, k_getrandom8, 256 * 1024 + 1, (BYTE *)k_getrandom8, &cb), TE_INSUFFICIENT_BUFFER);
    }
}

/* ----- real TPM2 traffic ----- */
static void *open_ctx(UINT32 flags, tbsx_devinfo *di) {
    Tbsi_Context_Create_pfn cr = TB(Tbsi_Context_Create);
    void *h = NULL;
    if (!cr || tbsx_emulated()) { t_skip("no tbs"); return NULL; }
    if (!tbsx_tpm_present(di)) { t_skip("no TPM (TBS_E_TPM_NOT_FOUND)"); return NULL; }
    if (di->tpmVersion != 2) { t_skip("TPM version %u is not 2.0", di->tpmVersion); return NULL; }
    tbsx_params2 p = { 2, flags };
    UINT32 r = cr(&p, &h);
    if (r != 0) { t_skip("context create failed 0x%08x", r); return NULL; }
    return h;
}
static void close_ctx(void *h) { Tbsip_Context_Close_pfn c = TB(Tbsip_Context_Close); if (c && h) c(h); }

TEST(tbs_tpm2_getrandom_response_header) {
    if (!load_subs()) return;
    tbsx_devinfo di; void *h = open_ctx(TBSX_TPM20, &di); if (!h) return;
    FOR_BOTH {
        BYTE out[4096]; UINT32 cb = sizeof out; memset(out, 0, sizeof out);
        UINT32 r = subs[v](h, 0, PRIO_NORMAL, k_getrandom8, sizeof k_getrandom8, out, &cb);
        if (r != 0) { t_note("%s: 0x%08x", subn[v], r); continue; }
        CHECK(cb >= 10);
        EXPECT_EQ(be16(out), 0x8001);            /* TPM_ST_NO_SESSIONS */
        EXPECT_EQ(be32(out + 2), cb);            /* responseSize == bytes returned */
        EXPECT_EQ(be32(out + 6), 0);             /* TPM_RC_SUCCESS */
        if (cb >= 12) {
            unsigned n = be16(out + 10);
            CHECK(n >= 1 && n <= 8);             /* never more than requested */
            EXPECT_EQ(cb, 12 + n);
        }
    }
    close_ctx(h);
}
TEST(tbs_tpm2_getrandom_two_calls_differ) {
    if (!load_subs()) return;
    tbsx_devinfo di; void *h = open_ctx(TBSX_TPM20, &di); if (!h) return;
    BYTE cmd[12]; memcpy(cmd, k_getrandom8, 12); cmd[11] = 32;
    BYTE a[256], b[256]; UINT32 ca = sizeof a, cbb = sizeof b;
    UINT32 r1 = subs[0](h, 0, PRIO_NORMAL, cmd, 12, a, &ca);
    UINT32 r2 = subs[0](h, 0, PRIO_NORMAL, cmd, 12, b, &cbb);
    if (r1 == 0 && r2 == 0 && ca >= 14 && cbb >= 14 && be32(a + 6) == 0 && be32(b + 6) == 0) {
        unsigned na = be16(a + 10), nb = be16(b + 10);
        if (na >= 16 && na == nb) CHECK(memcmp(a + 12, b + 12, na) != 0); /* 2^-128 false-failure odds */
    } else t_note("r1=0x%08x r2=0x%08x", r1, r2);
    close_ctx(h);
}
TEST(tbs_tpm2_getcapability_properties) {
    if (!load_subs()) return;
    tbsx_devinfo di; void *h = open_ctx(TBSX_TPM20, &di); if (!h) return;
    BYTE out[4096]; UINT32 cb = sizeof out;
    UINT32 r = subs[0](h, 0, PRIO_NORMAL, k_getcap, sizeof k_getcap, out, &cb);
    if (r != 0) { t_note("GetCapability 0x%08x", r); close_ctx(h); return; }
    CHECK(cb >= 10);
    EXPECT_EQ(be16(out), 0x8001);
    EXPECT_EQ(be32(out + 2), cb);
    EXPECT_EQ(be32(out + 6), 0);
    if (cb >= 19) {
        /* moreData(1) capability(4) count(4) then {property(4) value(4)}* */
        EXPECT_EQ(be32(out + 11), 6);
        UINT32 n = be32(out + 15);
        CHECK(n >= 1 && n <= 8);
        EXPECT_EQ(cb, 19 + n * 8);
        if (cb >= 27 && be32(out + 19) == 0x100) EXPECT_EQ(be32(out + 23), 0x322E3000); /* TPM_PT_FAMILY_INDICATOR "2.0\0" */
    }
    close_ctx(h);
}
TEST(tbs_tpm2_getcapability_family_indicator) {
    if (!load_subs()) return;
    tbsx_devinfo di; void *h = open_ctx(TBSX_TPM20, &di); if (!h) return;
    BYTE cmd[22]; memcpy(cmd, k_getcap, 22); cmd[21] = 1; /* one property starting at TPM_PT_FAMILY_INDICATOR */
    BYTE out[256]; UINT32 cb = sizeof out;
    UINT32 r = subs[0](h, 0, PRIO_NORMAL, cmd, 22, out, &cb);
    if (r == 0 && cb == 27 && be32(out + 6) == 0) {
        EXPECT_EQ(be32(out + 15), 1);
        EXPECT_EQ(be32(out + 19), 0x100);
        EXPECT_EQ(be32(out + 23), 0x322E3000);
    } else t_note("r=0x%08x cb=%u", r, cb);
    close_ctx(h);
}
TEST(tbs_tpm2_raw_context_getrandom) {
    if (!load_subs()) return;
    tbsx_devinfo di; void *h = open_ctx(TBSX_TPM20 | TBSX_RAW, &di); if (!h) return;
    BYTE out[256]; UINT32 cb = sizeof out;
    UINT32 r = subs[0](h, 0, PRIO_NORMAL, k_getrandom8, sizeof k_getrandom8, out, &cb);
    t_note("raw context GetRandom: 0x%08x cb=%u", r, cb);
    if (r == 0 && cb >= 10) { EXPECT_EQ(be16(out), 0x8001); EXPECT_EQ(be32(out + 6), 0); }
    close_ctx(h);
}
TEST(tbs_tpm2_priorities_all_work) {
    if (!load_subs()) return;
    tbsx_devinfo di; void *h = open_ctx(TBSX_TPM20, &di); if (!h) return;
    static const UINT32 pr[] = { 0, PRIO_LOW, PRIO_NORMAL, PRIO_HIGH, PRIO_SYSTEM, PRIO_MAX };
    for (size_t i = 0; i < sizeof pr / sizeof *pr; i++) {
        BYTE out[64]; UINT32 cb = sizeof out;
        UINT32 r = subs[0](h, 0, pr[i], k_getrandom8, sizeof k_getrandom8, out, &cb);
        if (r != 0) t_note("priority %u -> 0x%08x", pr[i], r);
        else EXPECT_EQ(be32(out + 6), 0);
    }
    close_ctx(h);
}
TEST(tbs_tpm2_result_buffer_exactly_ten) {
    if (!load_subs()) return;
    tbsx_devinfo di; void *h = open_ctx(TBSX_TPM20, &di); if (!h) return;
    BYTE out[16]; UINT32 cb = 10; memset(out, 0xee, sizeof out);
    UINT32 r = subs[0](h, 0, PRIO_NORMAL, k_getrandom8, sizeof k_getrandom8, out, &cb);
    t_note("10-byte result buffer: 0x%08x cb=%u", r, cb);
    for (int i = 10; i < 16; i++) CHECK(out[i] == 0xee); /* never writes past the declared size */
    close_ctx(h);
}
TEST(tbs_tpm2_truncated_response_buffer) {
    if (!load_subs()) return;
    tbsx_devinfo di; void *h = open_ctx(TBSX_TPM20, &di); if (!h) return;
    BYTE out[64]; UINT32 cb = 12; memset(out, 0xee, sizeof out);
    BYTE cmd[12]; memcpy(cmd, k_getrandom8, 12); cmd[11] = 32;
    UINT32 r = subs[0](h, 0, PRIO_NORMAL, cmd, 12, out, &cb);
    t_note("32 random bytes into 12-byte buffer: 0x%08x cb=%u", r, cb);
    for (int i = 12; i < 64; i++) if (out[i] != 0xee) { CHECK(0 && "wrote past declared buffer"); break; }
    close_ctx(h);
}
TEST(tbs_tpm2_short_command_is_not_fatal) {
    if (!load_subs()) return;
    tbsx_devinfo di; void *h = open_ctx(TBSX_TPM20, &di); if (!h) return;
    static const UINT32 lens[] = { 1, 2, 4, 9 };
    for (size_t i = 0; i < sizeof lens / sizeof *lens; i++) {
        BYTE out[256]; UINT32 cb = sizeof out;
        UINT32 r = subs[0](h, 0, PRIO_NORMAL, k_getrandom8, lens[i], out, &cb);
        t_note("command length %u: 0x%08x cb=%u", lens[i], r, cb);
        if (r == 0 && cb >= 10) CHECK(be32(out + 6) != 0);   /* a TPM error response, never success */
    }
    close_ctx(h);
}
TEST(tbs_tpm2_command_size_field_mismatch) {
    if (!load_subs()) return;
    tbsx_devinfo di; void *h = open_ctx(TBSX_TPM20, &di); if (!h) return;
    BYTE cmd[12]; memcpy(cmd, k_getrandom8, 12); cmd[5] = 20; /* commandSize says 20, 12 sent */
    BYTE out[256]; UINT32 cb = sizeof out;
    UINT32 r = subs[0](h, 0, PRIO_NORMAL, cmd, 12, out, &cb);
    t_note("size-field mismatch: 0x%08x cb=%u", r, cb);
    if (r == 0 && cb >= 10) CHECK(be32(out + 6) != 0);
    close_ctx(h);
}
TEST(tbs_tpm2_command_overwritten_by_priority_byte_is_private) {
    if (!load_subs()) return;
    tbsx_devinfo di; void *h = open_ctx(TBSX_TPM20, &di); if (!h) return;
    /* the implementation copies the command before stamping its priority into byte 0, so the caller's buffer is intact */
    BYTE cmd[12]; memcpy(cmd, k_getrandom8, 12);
    BYTE out[64]; UINT32 cb = sizeof out;
    subs[0](h, 0, PRIO_HIGH, cmd, 12, out, &cb);
    CHECK(!memcmp(cmd, k_getrandom8, 12));
    close_ctx(h);
}
TEST(tbs_tpm2_context_closed_then_submit) {
    if (!load_subs()) return;
    tbsx_devinfo di; void *h = open_ctx(TBSX_TPM20, &di); if (!h) return;
    close_ctx(h);
    BYTE out[64]; UINT32 cb = sizeof out;
    EXPECT_EQ(subs[0](h, 0, PRIO_NORMAL, k_getrandom8, sizeof k_getrandom8, out, &cb), TE_INVALID_CONTEXT);
}
TEST(tbs_tpm2_tpm12_context_rejected_on_tpm2) {
    if (!load_subs()) return;
    tbsx_devinfo di;
    if (tbsx_emulated() || !tbsx_tpm_present(&di) || di.tpmVersion != 2) { t_skip("needs a TPM 2.0"); return; }
    void *h = NULL; tbsx_params2 p = { 2, TBSX_TPM12 };
    EXPECT_EQ(TB(Tbsi_Context_Create)(&p, &h), TE_TPM_NOT_FOUND);
}

/* ----- Tbsip_Cancel_Commands ----- */
TEST(tbs_cancel_null_context) {
    NEED(Tbsip_Cancel_Commands);
    t_note("cancel(NULL) -> 0x%08x (void return assumed; unverified)", (unsigned)P(Tbsip_Cancel_Commands)(NULL));
}
TEST(tbs_cancel_closed_handle) {
    NEED(Tbsip_Cancel_Commands);
    HANDLE e = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!e) { t_skip("CreateEvent"); return; }
    CloseHandle(e);
    t_note("cancel(closed) -> 0x%08x (unverified)", (unsigned)P(Tbsip_Cancel_Commands)((void *)e));
}
TEST(tbs_cancel_idle_context) {
    NEED(Tbsip_Cancel_Commands);
    tbsx_devinfo di; void *h = open_ctx(TBSX_TPM20, &di); if (!h) return;
    UINT32 r = P(Tbsip_Cancel_Commands)(h);
    t_note("cancel on idle context: 0x%08x", r);
    close_ctx(h);
}
TEST(tbs_cancel_after_close) {
    NEED(Tbsip_Cancel_Commands);
    tbsx_devinfo di; void *h = open_ctx(TBSX_TPM20, &di); if (!h) return;
    close_ctx(h);
    t_note("cancel(after close) -> 0x%08x (unverified)", (unsigned)P(Tbsip_Cancel_Commands)(h));
}

/* ----- Tbsip_TestInterruptInformation / Tbsip_TestMorBit ----- */
TEST(tbs_testinterrupt_no_tpm) {
    NEED(Tbsip_TestInterruptInformation);
    tbsx_devinfo di;
    if (tbsx_tpm_present(&di)) { t_skip("TPM present"); return; }
    UINT32 v = 0x55555555;
    EXPECT_EQ(P(Tbsip_TestInterruptInformation)(&v), TE_TPM_NOT_FOUND);
    EXPECT_EQ(v, 0xffffffffu);      /* the out value is set to -1 even though the call failed */
}
TEST(tbs_testmorbit_no_tpm) {
    NEED(Tbsip_TestMorBit);
    tbsx_devinfo di;
    if (tbsx_tpm_present(&di)) { t_skip("TPM present"); return; }
    UINT32 v = 0x55555555;
    EXPECT_EQ(P(Tbsip_TestMorBit)(&v), TE_TPM_NOT_FOUND);
    EXPECT_EQ(v, 0xffffffffu);
}
TEST(tbs_testmorbit_null_out_no_tpm) {
    NEED(Tbsip_TestMorBit);
    tbsx_devinfo di;
    if (tbsx_tpm_present(&di)) { t_skip("TPM present"); return; }
    /* unlike TestInterruptInformation, TestMorBit tolerates a NULL output */
    EXPECT_EQ(P(Tbsip_TestMorBit)(NULL), TE_TPM_NOT_FOUND);
}
TEST(tbs_testinterrupt_with_tpm) {
    NEED(Tbsip_TestInterruptInformation);
    tbsx_devinfo di;
    if (!tbsx_tpm_present(&di)) { t_skip("no TPM"); return; }
    UINT32 v = 0x55555555;
    UINT32 r = P(Tbsip_TestInterruptInformation)(&v);
    t_note("TestInterruptInformation: 0x%08x value=0x%08x", r, v);
    if (r != 0) CHECK((r & 0xffff0000) == 0x80280000);
}
TEST(tbs_testmorbit_with_tpm) {
    NEED(Tbsip_TestMorBit);
    tbsx_devinfo di;
    if (!tbsx_tpm_present(&di)) { t_skip("no TPM"); return; }
    UINT32 v = 0x55555555;
    UINT32 r = P(Tbsip_TestMorBit)(&v);
    t_note("TestMorBit: 0x%08x value=0x%08x", r, v);
    if (r != 0) CHECK((r & 0xffff0000) == 0x80280000);
}
TEST(tbs_testmorbit_leaves_no_context_open) {
    NEED(Tbsip_TestMorBit); NEED(Tbsip_TestInterruptInformation);
    tbsx_devinfo di;
    if (!tbsx_tpm_present(&di)) { t_skip("no TPM"); return; }
    /* the helpers open and close their own internal context: the process handle count must not grow */
    DWORD before = 0, after = 0; UINT32 v;
    GetProcessHandleCount(GetCurrentProcess(), &before);
    for (int i = 0; i < 20; i++) { P(Tbsip_TestMorBit)(&v); P(Tbsip_TestInterruptInformation)(&v); }
    GetProcessHandleCount(GetCurrentProcess(), &after);
    CHECKF(after <= before + 2, "handles %lu -> %lu", before, after);
}
