/* crypt32.dll internal exports: object locator, OSS globals (retired), ASN.1 module TLS slots,
 * diagnostics control, CryptLoadSip argument validation. */
#include "gap2.h"
#include <string.h>
#include <wincrypt.h>

#define E_INVALIDARG_ 0x80070057u
typedef void *(WINAPI *pf_loc_get)(void *loc, DWORD flags, CRYPT_DATA_BLOB *id);
typedef void *(WINAPI *pf_loc_1)(void *loc);
typedef int   (WINAPI *pf_loc_chg)(void *loc);
typedef void  (WINAPI *pf_loc_rel)(DWORD flags, void *loc);
typedef void *(WINAPI *pf_loc_init)(const char *oidfunc, DWORD a, DWORD b, void *c, void *d);

#define NOWINE(why) do { if (t_is_wine()) { t_skip("emulator aborts on stub: " why); return; } } while (0)
static void *c32(const char *n) { return (void *)t_proc_in("crypt32.dll", n); }

TEST(gap2_c32_locator_get_null_args) {
    pf_loc_get f = (pf_loc_get)c32("CryptObjectLocatorGet"); REQUIRE(f);
    CRYPT_DATA_BLOB b = { 4, (BYTE *)"abcd" };
    char fake[64] = {0};
    SET_ERR(0); CHECK(f(NULL, 0, &b) == NULL); EXPECT_ERR(E_INVALIDARG_);
    SET_ERR(0); CHECK(f(fake, 0, NULL) == NULL); EXPECT_ERR(E_INVALIDARG_);
    SET_ERR(0); CHECK(f(NULL, 0, NULL) == NULL); EXPECT_ERR(E_INVALIDARG_);
    SET_ERR(0); CHECK(f(NULL, 0xFFFFFFFF, &b) == NULL); EXPECT_ERR(E_INVALIDARG_);
}
TEST(gap2_c32_locator_getcontent_null) {
    pf_loc_1 f = (pf_loc_1)c32("CryptObjectLocatorGetContent"); REQUIRE(f);
    SET_ERR(0); CHECK(f(NULL) == NULL); EXPECT_ERR(E_INVALIDARG_);
}
TEST(gap2_c32_locator_getcontent_unknown_state) {
    pf_loc_1 f = (pf_loc_1)c32("CryptObjectLocatorGetContent"); REQUIRE(f);
    /* element block whose state word (offset 4) is not 1..3 fails with NTE_BAD_DATA (0x80090005) */
    DWORD blk[16] = {0};
    int states[] = { 0, -1, 4, 5, 0x7fffffff };
    for (unsigned i = 0; i < sizeof states / sizeof *states; i++) {
        blk[1] = (DWORD)states[i];
        SET_ERR(0); CHECK(f(blk) == NULL); EXPECT_ERR(0x80090005u);
    }
}
TEST(gap2_c32_locator_getupdated_null) {
    pf_loc_1 f = (pf_loc_1)c32("CryptObjectLocatorGetUpdated"); REQUIRE(f);
    SET_ERR(0); CHECK(f(NULL) == NULL); EXPECT_ERR(E_INVALIDARG_);
}
TEST(gap2_c32_locator_ischanged_null_is_false) {
    pf_loc_chg f = (pf_loc_chg)c32("CryptObjectLocatorIsChanged"); REQUIRE(f);
    EXPECT_EQ(f(NULL), 0);
}
TEST(gap2_c32_locator_ischanged_compares_generation) {
    pf_loc_chg f = (pf_loc_chg)c32("CryptObjectLocatorIsChanged"); REQUIRE(f);
    /* handle word 0 is the generation snapshot, the owner (offset 0x28) holds the live generation at +0x48 */
    struct { DWORD gen; BYTE pad[0x24]; void *owner; } h = {0};
    BYTE owner[0x60] = {0};
    h.owner = owner;
    DWORD live = 7; memcpy(owner + 0x48, &live, 4);
    h.gen = 7; EXPECT_EQ(f(&h), 0);
    h.gen = 6; EXPECT_EQ(f(&h), 1);
    h.gen = 8; EXPECT_EQ(f(&h), 1);
    live = 0; memcpy(owner + 0x48, &live, 4);
    h.gen = 0; EXPECT_EQ(f(&h), 0);
}
TEST(gap2_c32_locator_release_null_keeps_last_error) {
    pf_loc_rel f = (pf_loc_rel)c32("CryptObjectLocatorRelease"); REQUIRE(f);
    DWORD flags[] = { 0, 1, 2, 4, 0xFFFFFFFF };
    for (unsigned i = 0; i < 5; i++) { SET_ERR(0x1357); f(flags[i], NULL); EXPECT_ERR(0x1357); }
}
TEST(gap2_c32_locator_free_preserves_last_error_on_null_like_args) {
    REQUIRE(c32("CryptObjectLocatorFree"));
    t_note("CryptObjectLocatorFree saves/restores last error; NULL handling not exercised");
}

/* ---- retired OSS global trio: one shared body, always fails with ERROR_INVALID_FUNCTION --------- */
TEST(gap2_c32_oss_globals_fail_invalid_function) {
    NOWINE("emulator differs / aborts");
    typedef void *(WINAPI *pf)(void);
    const char *n[] = { "I_CryptGetOssGlobal", "I_CryptInstallOssGlobal", "I_CryptUninstallOssGlobal" };
    FARPROC first = NULL;
    for (int i = 0; i < 3; i++) {
        pf f = (pf)c32(n[i]); REQUIRE(f);
        SET_ERR(0); CHECKF(f() == NULL, "%s", n[i]); EXPECT_ERR(ERROR_INVALID_FUNCTION);
        SET_ERR(99); CHECK(f() == NULL); EXPECT_ERR(ERROR_INVALID_FUNCTION);
        if (!first) first = (FARPROC)f; else CHECKF((FARPROC)f == first, "%s shares one body", n[i]);
    }
}

/* ---- ASN.1 module slots --------------------------------------------------------------------- */
typedef struct { DWORD length; BYTE *value; } LVs;
typedef void *(WINAPI *pf_mkmod)(DWORD ver, int rule, DWORD flags, DWORD cpdu, const void *e, const void *d, const void *fr, const DWORD *sz, DWORD name);
typedef void  (WINAPI *pf_closemod)(void *);
typedef DWORD (WINAPI *pf_inst_)(void *mod, DWORD fl, void *rs);
typedef void  (WINAPI *pf_uninst)(DWORD h);
typedef void *(WINAPI *pf_getenc)(DWORD h);
typedef void *(WINAPI *pf_getdec)(DWORD h);

static int WINAPI stub_enc(void *e, DWORD t, void *d) { return 1; }
static const void *const g_tab[1] = { (void *)stub_enc };
static const DWORD g_sz[1] = { 8 };

static void *mkmod(void) {
    pf_mkmod f = (pf_mkmod)t_proc_in("msasn1.dll", "ASN1_CreateModule");
    if (!f) return NULL;
    return f(0x10000, 0x400, 0, 1, g_tab, g_tab, g_tab, g_sz, 0x67617032);
}
TEST(gap2_c32_asn1_handle_zero_is_rejected) {
    pf_getenc ge = (pf_getenc)c32("I_CryptGetAsn1Encoder"); REQUIRE(ge);
    pf_getdec gd = (pf_getdec)c32("I_CryptGetAsn1Decoder"); REQUIRE(gd);
    CHECK(ge(0) == NULL);
    CHECK(gd(0) == NULL);
}
TEST(gap2_c32_asn1_install_get_uninstall) {
    NOWINE("emulator differs / aborts");
    pf_inst_ in_ = (pf_inst_)c32("I_CryptInstallAsn1Module"); REQUIRE(in_);
    pf_uninst un = (pf_uninst)c32("I_CryptUninstallAsn1Module"); REQUIRE(un);
    pf_getenc ge = (pf_getenc)c32("I_CryptGetAsn1Encoder"); REQUIRE(ge);
    pf_getdec gd = (pf_getdec)c32("I_CryptGetAsn1Decoder"); REQUIRE(gd);
    pf_closemod cm = (pf_closemod)t_proc_in("msasn1.dll", "ASN1_CloseModule"); REQUIRE(cm);
    void *mod = mkmod(); CHECK(mod != NULL); if (!mod) return;
    DWORD h = in_(mod, 0, NULL);
    CHECK(h != 0);
    if (h) {
        void *e1 = ge(h), *e2 = ge(h), *d1 = gd(h), *d2 = gd(h);
        CHECK(e1 != NULL); CHECK(d1 != NULL);
        CHECK(e1 == e2);      /* cached per thread and module */
        CHECK(d1 == d2);
        CHECK(e1 != d1);
        if (e1) { void *m; memcpy(&m, (BYTE *)e1 + 8, sizeof m); CHECK(m == mod); }  /* encoder -> module */
        if (d1) { void *m; memcpy(&m, (BYTE *)d1 + 8, sizeof m); CHECK(m == mod); }
        un(h);
    }
    cm(mod);
}
TEST(gap2_c32_asn1_two_modules_get_distinct_handles) {
    NOWINE("emulator differs / aborts");
    pf_inst_ in_ = (pf_inst_)c32("I_CryptInstallAsn1Module"); REQUIRE(in_);
    pf_uninst un = (pf_uninst)c32("I_CryptUninstallAsn1Module"); REQUIRE(un);
    pf_getenc ge = (pf_getenc)c32("I_CryptGetAsn1Encoder"); REQUIRE(ge);
    pf_closemod cm = (pf_closemod)t_proc_in("msasn1.dll", "ASN1_CloseModule"); REQUIRE(cm);
    void *a = mkmod(), *b = mkmod(); CHECK(a && b); if (!a || !b) return;
    DWORD ha = in_(a, 0, NULL), hb = in_(b, 0, NULL);
    CHECK(ha != 0 && hb != 0 && ha != hb);
    if (ha && hb) { void *ea = ge(ha), *eb = ge(hb); CHECK(ea && eb && ea != eb); }
    if (ha) un(ha);
    if (hb) un(hb);
    cm(a); cm(b);
}

/* ---- diagnostics control -------------------------------------------------------------------- */
TEST(gap2_c32_certdiagcontrol_unknown_command_noop_keeps_last_error) {
    typedef void (WINAPI *pf)(DWORD cmd, void *a, void *b);
    pf f = (pf)c32("I_CertDiagControl"); REQUIRE(f);
    DWORD cmds[] = { 0, 0x1b, 0x1c, 0x40, 0x100, 0xFFFF, 0xFFFFFFFF };
    for (unsigned i = 0; i < sizeof cmds / sizeof *cmds; i++) {
        int sentinel = 0x5a5a;
        SET_ERR(0x2468); f(cmds[i], NULL, &sentinel); EXPECT_ERR(0x2468);
        CHECKF(sentinel == 0x5a5a, "cmd 0x%lx must not write the result", cmds[i]);
    }
}

/* ---- CryptLoadSip ---------------------------------------------------------------------------- */
TEST(gap2_c32_loadsip_argument_validation) {
    NOWINE("CryptLoadSip");
    typedef BOOL (WINAPI *pf)(const GUID *g, DWORD flags, void *disp);
    pf f = (pf)c32("CryptLoadSip"); REQUIRE(f);
    static const GUID pe = { 0xC689AAB8, 0x8E78, 0x11D0, { 0x8C, 0x47, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE } };
    BYTE disp[128]; memset(disp, 0xEE, sizeof disp);
    SET_ERR(0); CHECK(!f(NULL, 0, disp)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!f(&pe, 1, disp)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!f(&pe, 0x80000000, disp)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!f(&pe, 0, NULL)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    for (unsigned i = 0; i < sizeof disp; i++) if (disp[i] != 0xEE) { CHECK(0); break; }
}
TEST(gap2_c32_loadsip_unregistered_guid) {
    NOWINE("CryptLoadSip");
    typedef BOOL (WINAPI *pf)(const GUID *g, DWORD flags, void *disp);
    pf f = (pf)c32("CryptLoadSip"); REQUIRE(f);
    static const GUID nope = { 0x0badf00d, 0xcafe, 0x4bad, { 1, 2, 3, 4, 5, 6, 7, 8 } };
    BYTE disp[128]; memset(disp, 0xEE, sizeof disp);
    SET_ERR(0); CHECK(!f(&nope, 0, disp)); EXPECT_ERR(0x800b0003u);   /* TRUST_E_SUBJECT_FORM_UNKNOWN */
    for (unsigned i = 0; i < sizeof disp; i++) if (disp[i] != 0xEE) { CHECK(0); break; }
}
TEST(gap2_c32_loadsip_registered_pe_fills_dispatch) {
    NOWINE("CryptLoadSip");
    typedef BOOL (WINAPI *pf)(const GUID *g, DWORD flags, void *disp);
    pf f = (pf)c32("CryptLoadSip"); REQUIRE(f);
    static const GUID pe = { 0xC689AAB8, 0x8E78, 0x11D0, { 0x8C, 0x47, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE } };
    struct { DWORD cb; DWORD pad; void *hSIP; void *fn[5]; } d; memset(&d, 0, sizeof d);
    BOOL ok = f(&pe, 0, &d);
    if (!ok) { t_note("PE SIP GUID not resolvable here, err 0x%lx", GetLastError()); return; }
    CHECK(d.hSIP == NULL);
    for (int i = 0; i < 5; i++) CHECKF(d.fn[i] != NULL, "slot %d", i);
}
TEST(gap2_c32_wnf_enable_flush_cache_is_idempotent) {
    typedef void (WINAPI *pf)(void);
    pf f = (pf)c32("I_CertWnfEnableFlushCache"); REQUIRE(f);
    SET_ERR(0x4321); f(); f();
    t_note("last error after I_CertWnfEnableFlushCache: 0x%lx", GetLastError());
}
