#include "dxc.h"
#include <sddl.h>
/* CryptGetProvParam / CryptSetProvParam on persisted containers: PP_KEYSET_SEC_DESCR,
 * unsupported parameters, fixed-size parameters, PP_CLIENT_HWND (handled in cryptsp itself).
 * Pinned from rsaenh CPGetProvParam/CPSetProvParam and cryptsp CryptSetProvParam. The rsaenh
 * expectations apply to the four RSA providers; dssenh is a separate DLL and is only noted. */

static BOOL sp(HCRYPTPROV h, DWORD p, const void *d, DWORD fl) { return U(CryptSetProvParam)(h, p, (const BYTE *)d, fl); }

static char *user_sid_string(void) {
    static char buf[200]; HANDLE t; buf[0] = 0;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &t)) {
        BYTE tb[300]; DWORD n = 0;
        if (GetTokenInformation(t, TokenUser, tb, sizeof tb, &n)) {
            char *s = NULL;
            if (ConvertSidToStringSidA(((TOKEN_USER *)tb)->User.Sid, &s)) { snprintf(buf, sizeof buf, "%s", s); LocalFree(s); }
        }
        CloseHandle(t);
    }
    return buf;
}

/* ---------------------------------------------------------------- security descriptor */
static void p_sd_get(int pi) {
    DXC_NEED(pi);
    if (t_is_wine()) { t_skip("emulator has no container security descriptors"); return; }
    const char *c = dxc_name("psd"); dxc_del(c, pi, 0);
    HCRYPTPROV h = 0;
    CHECK(dxc_acq(&h, c, pi, CRYPT_NEWKEYSET));
    static BYTE sd[8192]; DWORD n = sizeof sd;
    BOOL ok = dxc_gpp(h, PP_KEYSET_SEC_DESCR, sd, &n, DACL_SECURITY_INFORMATION);
    CHECKF(ok, "err 0x%lx", GetLastError());
    if (ok) {
        CHECK(n >= sizeof(SECURITY_DESCRIPTOR_RELATIVE));
        CHECK(IsValidSecurityDescriptor((PSECURITY_DESCRIPTOR)sd));
        SECURITY_DESCRIPTOR_CONTROL ctl = 0; DWORD rev = 0;
        CHECK(GetSecurityDescriptorControl((PSECURITY_DESCRIPTOR)sd, &ctl, &rev));
        CHECK(ctl & SE_SELF_RELATIVE);
        BOOL present = 0, def = 0; PACL acl = NULL;
        CHECK(GetSecurityDescriptorDacl((PSECURITY_DESCRIPTOR)sd, &present, &acl, &def));
        CHECK(present);
        if (present && acl) CHECK(acl->AceCount >= 1);
    }
    /* size query */
    n = 0; SET_ERR(0);
    ok = dxc_gpp(h, PP_KEYSET_SEC_DESCR, NULL, &n, DACL_SECURITY_INFORMATION);
    t_note("prov %d: SD size query ok=%d len=%lu err 0x%lx", pi, ok, n, GetLastError());
    /* owner */
    n = sizeof sd;
    ok = dxc_gpp(h, PP_KEYSET_SEC_DESCR, sd, &n, OWNER_SECURITY_INFORMATION);
    CHECKF(ok, "owner err 0x%lx", GetLastError());
    if (ok) {
        PSID o = NULL; BOOL def = 0;
        CHECK(GetSecurityDescriptorOwner((PSECURITY_DESCRIPTOR)sd, &o, &def));
        CHECK(o != NULL && IsValidSid(o));
    }
    dxc_rel(h);
    dxc_del(c, pi, 0);
}
DXC_PERRSA(dxc_params_sec_descr_get, p_sd_get)

static void p_sd_flags(int pi) {
    DXC_NEED(pi);
    const char *c = dxc_name("psf"); dxc_del(c, pi, 0);
    HCRYPTPROV h = 0;
    CHECK(dxc_acq(&h, c, pi, CRYPT_NEWKEYSET));
    static const DWORD bad[] = { 0, 0x20, 0x40, 0x100, 0x1000, 0x80000000 };
    BYTE sd[2048];
    SECURITY_DESCRIPTOR local; InitializeSecurityDescriptor(&local, SECURITY_DESCRIPTOR_REVISION);
    for (unsigned i = 0; i < sizeof bad / sizeof *bad; i++) {
        DWORD n = sizeof sd; SET_ERR(0);
        CHECKF(!dxc_gpp(h, PP_KEYSET_SEC_DESCR, sd, &n, bad[i]), "get flags 0x%lx", bad[i]);
        EXPECT_ERR(X_NTE_BAD_FLAGS);
        SET_ERR(0);
        CHECKF(!sp(h, PP_KEYSET_SEC_DESCR, &local, bad[i]), "set flags 0x%lx", bad[i]);
        EXPECT_ERR(X_NTE_BAD_FLAGS);
    }
    dxc_rel(h);
    dxc_del(c, pi, 0);
}
DXC_PERRSA(dxc_params_sec_descr_invalid_flags, p_sd_flags)

static void p_sd_set(int pi) {
    DXC_NEED(pi);
    if (t_is_wine()) { t_skip("emulator has no container security descriptors"); return; }
    const char *c = dxc_name("pss"); dxc_del(c, pi, 0);
    HCRYPTPROV h = 0, h2 = 0;
    CHECK(dxc_acq(&h, c, pi, CRYPT_NEWKEYSET));
    char sddl[400]; snprintf(sddl, sizeof sddl, "D:(A;;GA;;;%s)(A;;GA;;;SY)", user_sid_string());
    PSECURITY_DESCRIPTOR psd = NULL;
    CHECK(ConvertStringSecurityDescriptorToSecurityDescriptorA(sddl, SDDL_REVISION_1, &psd, NULL));
    if (!psd) { dxc_rel(h); dxc_del(c, pi, 0); return; }
    BOOL ok = sp(h, PP_KEYSET_SEC_DESCR, psd, DACL_SECURITY_INFORMATION);
    CHECKF(ok, "set err 0x%lx", GetLastError());
    static BYTE out[8192]; DWORD n = sizeof out;
    ok = dxc_gpp(h, PP_KEYSET_SEC_DESCR, out, &n, DACL_SECURITY_INFORMATION);
    CHECKF(ok, "get err 0x%lx", GetLastError());
    if (ok) {
        BOOL present = 0, def = 0; PACL acl = NULL;
        CHECK(GetSecurityDescriptorDacl((PSECURITY_DESCRIPTOR)out, &present, &acl, &def));
        CHECK(present && acl);
        if (present && acl) {
            EXPECT_EQ(acl->AceCount, 2);
            void *ace = NULL;
            if (acl->AceCount >= 1 && GetAce(acl, 0, &ace)) {
                ACCESS_ALLOWED_ACE *a = ace;
                EXPECT_EQ(a->Header.AceType, ACCESS_ALLOWED_ACE_TYPE);
            }
        }
    }
    LocalFree(psd);
    dxc_rel(h);
    /* the container is still reachable by its owner after the restrictive DACL */
    CHECK(dxc_acq(&h2, c, pi, 0));
    dxc_rel(h2);
    dxc_del(c, pi, 0);
    CHECK(!dxc_exists(c, pi, 0));
}
DXC_PERRSA(dxc_params_sec_descr_set_roundtrip, p_sd_set)

/* ---------------------------------------------------------------- unsupported params */
static void p_set_bad_type(int pi) {
    DXC_NEED(pi);
    const char *c = dxc_name("psb"); dxc_del(c, pi, 0);
    HCRYPTPROV h = 0;
    CHECK(dxc_acq(&h, c, pi, CRYPT_NEWKEYSET));
    /* every ID the rsaenh set handler does not implement */
    static const DWORD bad[] = { 0, 2, 3, 4, 5, 6, 7, 9, 12, 13, 16, 17, 18, 19, 20, 22, 23, 25, 26, 27,
                                 28, 29, 30, PP_ADMIN_PIN, PP_KEYEXCHANGE_PIN, PP_SIGNATURE_PIN, 34, 35, 36,
                                 PP_USE_HARDWARE_RNG, 39, 40, 41, 0x100, 0x10000 };
    DWORD dummy = 0;
    for (unsigned i = 0; i < sizeof bad / sizeof *bad; i++) {
        SET_ERR(0);
        BOOL ok = sp(h, bad[i], &dummy, 0);
        CHECKF(!ok, "param %lu accepted", bad[i]);
        EXPECT_ERR(X_NTE_BAD_TYPE);
    }
    dxc_rel(h);
    dxc_del(c, pi, 0);
}
DXC_PERRSA(dxc_params_set_unsupported_param, p_set_bad_type)

static void p_get_bad_type(int pi) {
    DXC_NEED(pi);
    const char *c = dxc_name("pgb"); dxc_del(c, pi, 0);
    HCRYPTPROV h = 0;
    CHECK(dxc_acq(&h, c, pi, CRYPT_NEWKEYSET));
    static const DWORD bad[] = { 0, 7, 9, 10, 11, 12, 13, 14, 15, 18, 19, 20, 21, 23, 24, 25, 26, 28, 29, 30,
                                 PP_ADMIN_PIN, PP_KEYEXCHANGE_PIN, PP_SIGNATURE_PIN, PP_USE_HARDWARE_RNG,
                                 41, 42, 0x100, 0x10000 };
    for (unsigned i = 0; i < sizeof bad / sizeof *bad; i++) {
        BYTE buf[64]; DWORD n = sizeof buf;
        SET_ERR(0);
        BOOL ok = dxc_gpp(h, bad[i], buf, &n, 0);
        CHECKF(!ok, "param %lu accepted", bad[i]);
        EXPECT_ERR(X_NTE_BAD_TYPE);
    }
    dxc_rel(h);
    dxc_del(c, pi, 0);
}
DXC_PERRSA(dxc_params_get_unsupported_param, p_get_bad_type)

/* ---------------------------------------------------------------- supported set params */
static void p_set_flags(int pi) {
    DXC_NEED(pi);
    const char *c = dxc_name("psfl"); dxc_del(c, pi, 0);
    HCRYPTPROV h = 0;
    CHECK(dxc_acq(&h, c, pi, CRYPT_NEWKEYSET));
    DWORD dummy = 0;
    CHECK(sp(h, 10, &dummy, 0));                       /* PP_KEY_TYPE_SUBTYPE: accepted, ignored */
    SET_ERR(0); CHECK(!sp(h, 10, &dummy, 1)); EXPECT_ERR(X_NTE_BAD_FLAGS);
    static const WCHAR prompt[] = L"cryptt prompt";
    CHECK(sp(h, PP_UI_PROMPT, prompt, 0));
    CHECK(sp(h, PP_UI_PROMPT, NULL, 0));               /* clears */
    SET_ERR(0); CHECK(!sp(h, PP_UI_PROMPT, prompt, 1)); EXPECT_ERR(X_NTE_BAD_FLAGS);
    SET_ERR(0); CHECK(!sp(h, PP_UI_PROMPT, prompt, 0x80)); EXPECT_ERR(X_NTE_BAD_FLAGS);
    dxc_rel(h);
    dxc_del(c, pi, 0);
}
DXC_PERRSA(dxc_params_set_supported_flags, p_set_flags)

static void p_sgc(int pi) {
    DXC_NEED(pi);
    const char *c = dxc_name("psg"); dxc_del(c, pi, 0);
    HCRYPTPROV h = 0; DWORD d = 0;
    CHECK(dxc_acq(&h, c, pi, CRYPT_NEWKEYSET));
    /* PP_SGC_INFO is only meaningful for PROV_RSA_SCHANNEL (12): not on 1/24 */
    SET_ERR(0); CHECK(!sp(h, PP_SGC_INFO, &d, 0)); EXPECT_ERR(X_NTE_BAD_TYPE);
    BYTE buf[16]; DWORD n = sizeof buf;
    SET_ERR(0); CHECK(!dxc_gpp(h, PP_SGC_INFO, buf, &n, 0)); EXPECT_ERR(X_NTE_BAD_TYPE);
    dxc_rel(h);
    dxc_del(c, pi, 0);
}
DXC_PERRSA(dxc_params_sgc_info_not_schannel, p_sgc)

/* ---------------------------------------------------------------- fixed-size gets */
static void p_dword_param(int pi, DWORD id, DWORD expect, const char *tag) {
    const char *c = dxc_name(tag); dxc_del(c, pi, 0);
    HCRYPTPROV h = 0;
    CHECK(dxc_acq(&h, c, pi, CRYPT_NEWKEYSET));
    DWORD v = 0xcccccccc, n = 0;
    CHECK(dxc_gpp(h, id, NULL, &n, 0));
    EXPECT_EQ(n, 4);
    n = 3; SET_ERR(0);
    CHECK(!dxc_gpp(h, id, &v, &n, 0)); EXPECT_ERR(ERROR_MORE_DATA);
    EXPECT_EQ(n, 4);
    n = 4;
    CHECK(dxc_gpp(h, id, &v, &n, 0));
    EXPECT_EQ(n, 4); EXPECT_EQ(v, expect);
    n = 100; v = 0;
    CHECK(dxc_gpp(h, id, &v, &n, 0));
    EXPECT_EQ(n, 4); EXPECT_EQ(v, expect);
    n = 4; SET_ERR(0);
    CHECK(!dxc_gpp(h, id, &v, &n, 1)); EXPECT_ERR(X_NTE_BAD_FLAGS);
    dxc_rel(h);
    dxc_del(c, pi, 0);
}
static void p_keysize_inc_sig(int pi) { DXC_NEED(pi); p_dword_param(pi, PP_SIG_KEYSIZE_INC, 8, "psi1"); }
static void p_keysize_inc_keyx(int pi) { DXC_NEED(pi); p_dword_param(pi, PP_KEYX_KEYSIZE_INC, 8, "psi2"); }
static void p_keyset_type(int pi) { DXC_NEED(pi); p_dword_param(pi, PP_KEYSET_TYPE, 0, "psi3"); }
static void p_keyspec(int pi) { DXC_NEED(pi); p_dword_param(pi, PP_KEYSPEC, 3, "psi4"); }
DXC_PERRSA(dxc_params_sig_keysize_inc, p_keysize_inc_sig)
DXC_PERRSA(dxc_params_keyx_keysize_inc, p_keysize_inc_keyx)
DXC_PERRSA(dxc_params_keyset_type_protocol, p_keyset_type)
DXC_PERRSA(dxc_params_keyspec_rsa_both, p_keyspec)

static void p_signing_prot(int pi) {
    DXC_NEED(pi);
    const char *c = dxc_name("psp"); dxc_del(c, pi, 0);
    HCRYPTPROV h = 0;
    CHECK(dxc_acq(&h, c, pi, CRYPT_NEWKEYSET));
    DWORD n = 77; BYTE buf[8];
    CHECK(dxc_gpp(h, PP_ENUMEX_SIGNING_PROT, buf, &n, 0));
    EXPECT_EQ(n, 0);
    n = 77;
    CHECK(dxc_gpp(h, PP_ENUMEX_SIGNING_PROT, NULL, &n, 0));
    EXPECT_EQ(n, 0);
    n = 77; SET_ERR(0);
    CHECK(!dxc_gpp(h, PP_ENUMEX_SIGNING_PROT, buf, &n, 1)); EXPECT_ERR(X_NTE_BAD_FLAGS);
    dxc_rel(h);
    dxc_del(c, pi, 0);
}
DXC_PERRSA(dxc_params_enumex_signing_prot_empty, p_signing_prot)

/* ---------------------------------------------------------------- PP_CLIENT_HWND */
TEST(dxc_params_client_hwnd_process_global) {
    REQUIRE(U(CryptSetProvParam));
    /* cryptsp keeps the window handle in a module variable and never touches the provider handle */
    HWND w = NULL;
    BOOL ok = U(CryptSetProvParam)(0, PP_CLIENT_HWND, (const BYTE *)&w, 0);
    CHECKF(ok, "err 0x%lx", GetLastError());
    ok = U(CryptSetProvParam)(0, PP_CLIENT_HWND, (const BYTE *)&w, 0x1234);   /* flags ignored */
    CHECK(ok);
}

TEST(dxc_params_client_hwnd_on_container) {
    int pi = 3;
    DXC_NEED(pi);
    const char *c = dxc_name("pcw"); dxc_del(c, pi, 0);
    HCRYPTPROV h = 0; HWND w = NULL;
    CHECK(dxc_acq(&h, c, pi, CRYPT_NEWKEYSET));
    CHECK(U(CryptSetProvParam)(h, PP_CLIENT_HWND, (const BYTE *)&w, 0));
    dxc_rel(h);
    dxc_del(c, pi, 0);
}

/* ---------------------------------------------------------------- misc on persisted contexts */
static void p_context_addref(int pi) {
    DXC_NEED(pi);
    REQUIRE(U(CryptContextAddRef));
    const char *c = dxc_name("pad"); dxc_del(c, pi, 0);
    HCRYPTPROV h = 0; HCRYPTKEY k = 0;
    CHECK(dxc_acq(&h, c, pi, CRYPT_NEWKEYSET));
    CHECK(U(CryptContextAddRef)(h, NULL, 0));
    CHECK(U(CryptReleaseContext)(h, 0));              /* one reference left */
    CHECK(U(CryptGenKey)(h, AT_SIGNATURE, 0, &k));    /* still usable */
    U(CryptDestroyKey)(k);
    CHECK(U(CryptReleaseContext)(h, 0));
    dxc_del(c, pi, 0);
}
DXC_PERPROV(dxc_params_addref_keeps_context, p_context_addref)

static void p_release_flags(int pi) {
    DXC_NEED(pi);
    const char *c = dxc_name("prf"); dxc_del(c, pi, 0);
    HCRYPTPROV h = 0;
    CHECK(dxc_acq(&h, c, pi, CRYPT_NEWKEYSET));
    /* cryptsp ignores dwFlags of CryptReleaseContext (it is never forwarded to the CSP) */
    SET_ERR(0);
    BOOL ok = U(CryptReleaseContext)(h, 0x1234);
    CHECKF(ok, "err 0x%lx", GetLastError());
    CHECK(dxc_exists(c, pi, 0));
    dxc_del(c, pi, 0);
}
DXC_PERPROV(dxc_params_release_ignores_flags, p_release_flags)

static void p_addref_args(int pi) {
    DXC_NEED(pi);
    REQUIRE(U(CryptContextAddRef));
    const char *c = dxc_name("paa"); dxc_del(c, pi, 0);
    HCRYPTPROV h = 0; DWORD res = 0;
    CHECK(dxc_acq(&h, c, pi, CRYPT_NEWKEYSET));
    SET_ERR(0);
    CHECK(!U(CryptContextAddRef)(h, &res, 0)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0);
    CHECK(!U(CryptContextAddRef)(h, NULL, 1)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    /* two extra references need three releases */
    CHECK(U(CryptContextAddRef)(h, NULL, 0));
    CHECK(U(CryptContextAddRef)(h, NULL, 0));
    CHECK(U(CryptReleaseContext)(h, 0));
    CHECK(U(CryptReleaseContext)(h, 0));
    char nm[300]; DWORD n = sizeof nm;
    CHECK(dxc_gpp(h, PP_CONTAINER, nm, &n, 0));
    EXPECT_STR(nm, c);
    CHECK(U(CryptReleaseContext)(h, 0));
    dxc_del(c, pi, 0);
}
DXC_PERPROV(dxc_params_addref_invalid_args, p_addref_args)
