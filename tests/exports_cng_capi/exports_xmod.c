/* Cross-module and documented-public-surface export checks.
 * The public lists below come from the SDK documentation (independent of the authoring snapshot), so a
 * missing documented export is reported even if the snapshot tables were wrong. */
#include "exports_common.h"
#include <bcrypt.h>
#include <ncrypt.h>
#include <wincrypt.h>

static void resolve_list(const char *dll, const char *const *n, int cnt) {
    HMODULE h = t_module(dll);
    if (!h) { t_skip("cannot load %s", dll); return; }
    for (int i = 0; i < cnt; i++) {
        SET_ERR(0);
        FARPROC p = GetProcAddress(h, n[i]);
        CHECKF(p != NULL, "%s!%s", dll, n[i]);
        EXPECT_EQ(p, t_proc_in(dll, n[i]));
    }
}
#define LIST(...) static const char *const l[] = { __VA_ARGS__ }
#define RES(dll) resolve_list(dll, l, (int)(sizeof l / sizeof *l))

TEST(exports_cng_capi_public_bcrypt_algorithm_and_hash) {
    LIST("BCryptOpenAlgorithmProvider","BCryptCloseAlgorithmProvider","BCryptGetProperty","BCryptSetProperty",
         "BCryptCreateHash","BCryptHashData","BCryptFinishHash","BCryptDuplicateHash","BCryptDestroyHash","BCryptHash",
         "BCryptEnumAlgorithms","BCryptEnumRegisteredProviders","BCryptFreeBuffer","BCryptGenRandom","BCryptGetFipsAlgorithmMode");
    RES("bcrypt.dll");
}
TEST(exports_cng_capi_public_bcrypt_keys_and_crypto) {
    LIST("BCryptGenerateSymmetricKey","BCryptGenerateKeyPair","BCryptFinalizeKeyPair","BCryptImportKey","BCryptImportKeyPair",
         "BCryptExportKey","BCryptDuplicateKey","BCryptDestroyKey","BCryptEncrypt","BCryptDecrypt","BCryptSignHash",
         "BCryptVerifySignature","BCryptSecretAgreement","BCryptDeriveKey","BCryptDestroySecret","BCryptKeyDerivation","BCryptDeriveKeyPBKDF2","BCryptDeriveKeyCapi");
    RES("bcrypt.dll");
}
TEST(exports_cng_capi_public_bcrypt_configuration) {
    LIST("BCryptResolveProviders","BCryptQueryProviderRegistration","BCryptRegisterProvider","BCryptUnregisterProvider",
         "BCryptCreateContext","BCryptDeleteContext","BCryptEnumContexts","BCryptConfigureContext","BCryptQueryContextConfiguration",
         "BCryptAddContextFunction","BCryptRemoveContextFunction","BCryptEnumContextFunctions","BCryptConfigureContextFunction",
         "BCryptQueryContextFunctionConfiguration","BCryptEnumContextFunctionProviders","BCryptSetContextFunctionProperty",
         "BCryptQueryContextFunctionProperty","BCryptRegisterConfigChangeNotify","BCryptUnregisterConfigChangeNotify",
         "BCryptAddContextFunctionProvider","BCryptRemoveContextFunctionProvider");
    RES("bcrypt.dll");
}
TEST(exports_cng_capi_public_ncrypt_keys) {
    LIST("NCryptOpenStorageProvider","NCryptEnumStorageProviders","NCryptFreeBuffer","NCryptOpenKey","NCryptCreatePersistedKey",
         "NCryptGetProperty","NCryptSetProperty","NCryptFinalizeKey","NCryptEncrypt","NCryptDecrypt","NCryptImportKey","NCryptExportKey",
         "NCryptSignHash","NCryptVerifySignature","NCryptDeleteKey","NCryptFreeObject","NCryptIsKeyHandle","NCryptTranslateHandle",
         "NCryptNotifyChangeKey","NCryptSecretAgreement","NCryptDeriveKey","NCryptKeyDerivation","NCryptCreateClaim","NCryptVerifyClaim",
         "NCryptEnumKeys","NCryptEnumAlgorithms","NCryptIsAlgSupported");
    RES("ncrypt.dll");
}
TEST(exports_cng_capi_public_ncrypt_protection) {
    LIST("NCryptRegisterProtectionDescriptorName","NCryptQueryProtectionDescriptorName","NCryptCreateProtectionDescriptor",
         "NCryptCloseProtectionDescriptor","NCryptGetProtectionDescriptorInfo","NCryptProtectSecret","NCryptUnprotectSecret",
         "NCryptStreamOpenToProtect","NCryptStreamOpenToUnprotect","NCryptStreamOpenToUnprotectEx","NCryptStreamUpdate","NCryptStreamClose");
    RES("ncrypt.dll");
}
TEST(exports_cng_capi_public_ncrypt_forwarded_bcrypt_surface_is_complete) {
    /* ncrypt re-exports the BCrypt provider-configuration surface so that callers linking ncrypt.lib find it */
    LIST("BCryptOpenAlgorithmProvider","BCryptCloseAlgorithmProvider","BCryptGetProperty","BCryptSetProperty","BCryptHash",
         "BCryptCreateHash","BCryptHashData","BCryptFinishHash","BCryptGenRandom","BCryptEncrypt","BCryptDecrypt","BCryptSignHash",
         "BCryptVerifySignature","BCryptGenerateSymmetricKey","BCryptGenerateKeyPair","BCryptImportKey","BCryptExportKey",
         "BCryptCreateContext","BCryptResolveProviders","BCryptDeriveKeyPBKDF2");
    RES("ncrypt.dll");
}
TEST(exports_cng_capi_public_capi_advapi32) {
    LIST("CryptAcquireContextA","CryptAcquireContextW","CryptReleaseContext","CryptContextAddRef","CryptGenKey","CryptDeriveKey",
         "CryptDestroyKey","CryptDuplicateKey","CryptSetKeyParam","CryptGetKeyParam","CryptSetHashParam","CryptGetHashParam",
         "CryptSetProvParam","CryptGetProvParam","CryptGenRandom","CryptGetUserKey","CryptExportKey","CryptImportKey","CryptEncrypt",
         "CryptDecrypt","CryptCreateHash","CryptHashData","CryptHashSessionKey","CryptDestroyHash","CryptDuplicateHash",
         "CryptSignHashA","CryptSignHashW","CryptVerifySignatureA","CryptVerifySignatureW","CryptSetProviderA","CryptSetProviderW",
         "CryptSetProviderExA","CryptSetProviderExW","CryptGetDefaultProviderA","CryptGetDefaultProviderW",
         "CryptEnumProviderTypesA","CryptEnumProviderTypesW","CryptEnumProvidersA","CryptEnumProvidersW");
    RES("advapi32.dll");
}
TEST(exports_cng_capi_public_capi_cryptsp) {
    LIST("CryptAcquireContextA","CryptAcquireContextW","CryptReleaseContext","CryptContextAddRef","CryptGenKey","CryptDeriveKey",
         "CryptDestroyKey","CryptDuplicateKey","CryptSetKeyParam","CryptGetKeyParam","CryptSetHashParam","CryptGetHashParam",
         "CryptSetProvParam","CryptGetProvParam","CryptGenRandom","CryptGetUserKey","CryptExportKey","CryptImportKey","CryptEncrypt",
         "CryptDecrypt","CryptCreateHash","CryptHashData","CryptHashSessionKey","CryptDestroyHash","CryptDuplicateHash",
         "CryptSignHashA","CryptSignHashW","CryptVerifySignatureA","CryptVerifySignatureW");
    RES("cryptsp.dll");
}
TEST(exports_cng_capi_public_csp_interface_rsaenh) {
    LIST("CPAcquireContext","CPReleaseContext","CPGenKey","CPDeriveKey","CPDestroyKey","CPSetKeyParam","CPGetKeyParam","CPExportKey",
         "CPImportKey","CPEncrypt","CPDecrypt","CPCreateHash","CPHashData","CPHashSessionKey","CPSignHash","CPDestroyHash",
         "CPVerifySignature","CPGenRandom","CPGetUserKey","CPSetProvParam","CPGetProvParam","CPSetHashParam","CPGetHashParam",
         "CPDuplicateKey","CPDuplicateHash","DllRegisterServer","DllUnregisterServer");
    RES("rsaenh.dll");
}
TEST(exports_cng_capi_public_csp_interface_dssenh) {
    LIST("CPAcquireContext","CPReleaseContext","CPGenKey","CPDeriveKey","CPDestroyKey","CPSetKeyParam","CPGetKeyParam","CPExportKey",
         "CPImportKey","CPEncrypt","CPDecrypt","CPCreateHash","CPHashData","CPHashSessionKey","CPSignHash","CPDestroyHash",
         "CPVerifySignature","CPGenRandom","CPGetUserKey","CPSetProvParam","CPGetProvParam","CPSetHashParam","CPGetHashParam",
         "CPDuplicateKey","CPDuplicateHash","DllRegisterServer","DllUnregisterServer");
    RES("dssenh.dll");
}
TEST(exports_cng_capi_public_dpapi_memory) {
    LIST("CryptProtectMemory","CryptUnprotectMemory");
    RES("dpapi.dll");
}
TEST(exports_cng_capi_public_bcryptprimitives_prng) {
    LIST("ProcessPrng");
    RES("bcryptprimitives.dll");
}
TEST(exports_cng_capi_public_cng_provider_entry_points) {
    LIST("GetKeyStorageInterface");
    RES("ncryptprov.dll");
}

/* ---- typed pointers via U() / UIN() --------------------------------------------------------------- */
TEST(exports_cng_capi_u_search_order_prefers_bcrypt) {
    REQUIRE(U(BCryptOpenAlgorithmProvider));
    EXPECT_EQ(U(BCryptOpenAlgorithmProvider), UIN("bcrypt.dll", BCryptOpenAlgorithmProvider));
    EXPECT_EQ(U(BCryptHash), UIN("bcrypt.dll", BCryptHash));
    EXPECT_EQ(U(BCryptGenRandom), UIN("bcrypt.dll", BCryptGenRandom));
    EXPECT_EQ(U(BCryptEncrypt), UIN("bcrypt.dll", BCryptEncrypt));
}
TEST(exports_cng_capi_u_ncrypt_resolves_to_ncrypt) {
    REQUIRE(U(NCryptOpenStorageProvider));
    EXPECT_EQ(U(NCryptOpenStorageProvider), UIN("ncrypt.dll", NCryptOpenStorageProvider));
    EXPECT_EQ(U(NCryptCreatePersistedKey), UIN("ncrypt.dll", NCryptCreatePersistedKey));
    EXPECT_EQ(U(NCryptFreeObject), UIN("ncrypt.dll", NCryptFreeObject));
}
TEST(exports_cng_capi_u_capi_prefers_advapi32_when_cryptsp_not_forwarded) {
    REQUIRE(U(CryptAcquireContextW));
    FARPROC a = (FARPROC)UIN("advapi32.dll", CryptAcquireContextW);
    FARPROC c = (FARPROC)UIN("cryptsp.dll", CryptAcquireContextW);
    CHECK(a != NULL); CHECK(c != NULL);
    /* U() searches cryptsp.dll before advapi32.dll */
    EXPECT_EQ((FARPROC)U(CryptAcquireContextW), c);
    CHECK(a != c);   /* advapi32 has its own implementation and does not forward to cryptsp */
}
TEST(exports_cng_capi_u_ncrypt_bcrypt_forward_is_bcrypt) {
    REQUIRE(UIN("ncrypt.dll", BCryptHash));
    EXPECT_EQ(UIN("ncrypt.dll", BCryptHash), UIN("bcrypt.dll", BCryptHash));
    EXPECT_EQ(UIN("ncrypt.dll", BCryptGenRandom), UIN("bcrypt.dll", BCryptGenRandom));
    EXPECT_EQ(UIN("ncrypt.dll", BCryptCreateHash), UIN("bcrypt.dll", BCryptCreateHash));
    EXPECT_EQ(UIN("ncrypt.dll", BCryptEncrypt), UIN("bcrypt.dll", BCryptEncrypt));
}
TEST(exports_cng_capi_u_unpinned_wrong_module_fails) {
    SET_ERR(0);
    CHECK(t_proc_in("bcrypt.dll", "NCryptOpenStorageProvider") == NULL);
    CHECK(t_proc_in("ncryptprov.dll", "BCryptHash") == NULL);
    CHECK(t_proc_in("dpapi.dll", "CryptAcquireContextA") == NULL);
    CHECK(t_proc_in("cryptbase.dll", "CryptAcquireContextA") == NULL);
}

/* ---- ncrypt -> bcrypt forwarding ------------------------------------------------------------------ */
TEST(exports_cng_capi_xmod_ncrypt_bcrypt_forward_targets_listed_in_bcrypt) {
    const XM *nc = ex_find("ncrypt.dll"), *bc = ex_find("bcrypt.dll");
    int fwd = 0;
    for (int i = 0; i < nc->n; i++) {
        if (!nc->e[i].fwd) continue;
        fwd++;
        char dll[64], sym[128]; ex_target_of(nc->e[i].fwd, dll, sizeof dll, sym, sizeof sym);
        EXPECT_STR(dll, "bcrypt.dll");
        int found = 0;
        for (int j = 0; j < bc->n; j++) if (bc->e[j].name && !strcmp(bc->e[j].name, sym)) found = 1;
        CHECKF(found, "%s not exported by bcrypt", sym);
        EXPECT_STR(sym, nc->e[i].name);   /* same-name forwarders only */
    }
    CHECK(fwd > 0);
    t_note("ncrypt.dll forwards %d BCrypt* names to bcrypt.dll", fwd);
}
TEST(exports_cng_capi_xmod_ncrypt_ncrypt_names_are_own_code) {
    HMODULE h = t_module("ncrypt.dll"); XDIR d;
    if (!h || !ex_dir(h, &d)) { t_skip("ncrypt unavailable"); return; }
    const XM *nc = ex_find("ncrypt.dll");
    for (int i = 0; i < nc->n; i++) {
        if (!nc->e[i].name || strncmp(nc->e[i].name, "NCrypt", 6)) continue;
        const char *f = (const char *)1;
        if (!ex_dir_find(&d, nc->e[i].name, NULL, NULL, &f)) continue;
        CHECKF(f == NULL, "%s should be implemented in ncrypt.dll", nc->e[i].name);
        FARPROC p = GetProcAddress(h, nc->e[i].name);
        CHECK(p && ex_in_image(&d, p));
    }
}
TEST(exports_cng_capi_xmod_bcrypt_has_no_ncrypt_names) {
    HMODULE h = t_module("bcrypt.dll");
    if (!h) { t_skip("no bcrypt"); return; }
    const XM *nc = ex_find("ncrypt.dll");
    for (int i = 0; i < nc->n; i++) {
        if (!nc->e[i].name || strncmp(nc->e[i].name, "NCrypt", 6)) continue;
        SET_ERR(0);
        CHECKF(GetProcAddress(h, nc->e[i].name) == NULL, "bcrypt exports %s", nc->e[i].name);
    }
}
TEST(exports_cng_capi_xmod_ncrypt_has_no_ssl_in_snapshot) {
    /* Ssl* belongs to schannel support and is excluded: assert only that the snapshot tables carry none. */
    const XM *nc = ex_find("ncrypt.dll");
    for (int i = 0; i < nc->n; i++) CHECK(!nc->e[i].name || strncmp(nc->e[i].name, "Ssl", 3));
}

/* ---- advapi32 -> cryptsp / cryptbase / ntdll forwarding -------------------------------------------- */
static void adv_fwd_to(const char *tgt_upper, const char *tgt_dll) {
    const XM *ad = ex_find("advapi32.dll"), *tm = ex_find(tgt_dll);
    HMODULE ha = t_module("advapi32.dll"), ht = t_module(tgt_dll);
    if (!ha || !ht) { t_skip("module missing"); return; }
    int n = 0;
    for (int i = 0; i < ad->n; i++) {
        if (!ad->e[i].fwd || strncmp(ad->e[i].fwd, tgt_upper, strlen(tgt_upper)) || ad->e[i].fwd[strlen(tgt_upper)] != '.') continue;
        n++;
        char dll[64], sym[128]; ex_target_of(ad->e[i].fwd, dll, sizeof dll, sym, sizeof sym);
        int found = 0;
        for (int j = 0; tm && j < tm->n; j++) if (tm->e[j].name && !strcmp(tm->e[j].name, sym)) found = 1;
        CHECKF(found, "%s!%s missing from snapshot of %s", tgt_dll, sym, tgt_dll);
        FARPROC a = GetProcAddress(ha, ad->e[i].name), b = GetProcAddress(ht, sym);
        CHECKF(a && a == b, "advapi32!%s vs %s!%s", ad->e[i].name, tgt_dll, sym);
    }
    CHECKF(n > 0 || t_is_wine(), "no advapi32 forwarders to %s", tgt_dll);
    t_note("advapi32.dll forwards %d names to %s", n, tgt_dll);
}
TEST(exports_cng_capi_xmod_advapi32_forwards_to_cryptbase) { adv_fwd_to("CRYPTBASE", "cryptbase.dll"); }
TEST(exports_cng_capi_xmod_advapi32_forwards_to_cryptsp) { adv_fwd_to("CRYPTSP", "cryptsp.dll"); }
TEST(exports_cng_capi_xmod_advapi32_systemfunction036_is_cryptbase) {
    HMODULE ha = t_module("advapi32.dll"), hb = t_module("cryptbase.dll");
    if (!ha || !hb) { t_skip("module missing"); return; }
    FARPROC a = GetProcAddress(ha, "SystemFunction036");
    CHECK(a != NULL);
    EXPECT_EQ(a, GetProcAddress(hb, "SystemFunction036"));
}
TEST(exports_cng_capi_xmod_advapi32_systemfunction_numbers_all_resolve) {
    HMODULE ha = t_module("advapi32.dll");
    if (!ha) { t_skip("no advapi32"); return; }
    const XM *ad = ex_find("advapi32.dll");
    int n = 0;
    for (int i = 0; i < ad->n; i++) {
        if (!ad->e[i].name || strncmp(ad->e[i].name, "SystemFunction", 14)) continue;
        n++;
        CHECKF(GetProcAddress(ha, ad->e[i].name) != NULL, "%s", ad->e[i].name);
    }
    CHECK(n > 0);
}
TEST(exports_cng_capi_xmod_systemfunction_names_have_three_digits) {
    const XM *ad = ex_find("advapi32.dll"), *cb = ex_find("cryptbase.dll");
    const XM *ms[2] = { ad, cb };
    for (int k = 0; k < 2; k++) for (int i = 0; i < ms[k]->n; i++) {
        const char *n = ms[k]->e[i].name;
        if (!n || strncmp(n, "SystemFunction", 14)) continue;
        CHECKF(strlen(n) == 17 && n[14] >= '0' && n[14] <= '9' && n[15] >= '0' && n[15] <= '9' && n[16] >= '0' && n[16] <= '9', "%s", n);
    }
}
TEST(exports_cng_capi_xmod_cryptdll_md5_forwards_to_ntdll) {
    HMODULE hc = t_module("cryptdll.dll"), hn = t_module("ntdll.dll");
    if (!hc || !hn) { t_skip("module missing"); return; }
    static const char *const n[] = { "MD5Init", "MD5Update", "MD5Final" };
    for (int i = 0; i < 3; i++) {
        FARPROC a = GetProcAddress(hc, n[i]), b = GetProcAddress(hn, n[i]);
        CHECKF(a && a == b, "cryptdll!%s", n[i]);
    }
}
TEST(exports_cng_capi_xmod_cryptdll_other_names_are_own_code) {
    HMODULE hc = t_module("cryptdll.dll"); XDIR d;
    if (!hc || !ex_dir(hc, &d)) { t_skip("no cryptdll"); return; }
    const XM *m = ex_find("cryptdll.dll");
    for (int i = 0; i < m->n; i++) {
        if (m->e[i].fwd || !m->e[i].name) continue;
        FARPROC p = GetProcAddress(hc, m->e[i].name);
        CHECKF(p && ex_in_image(&d, p), "%s", m->e[i].name);
    }
}

/* ---- rsaenh vs dssenh: both implement the same CSP SPI --------------------------------------------- */
TEST(exports_cng_capi_xmod_rsaenh_dssenh_same_name_set) {
    const XM *r = ex_find("rsaenh.dll"), *s = ex_find("dssenh.dll");
    CHECK(r->n == s->n);
    for (int i = 0; i < r->n; i++) {
        int f = 0;
        for (int j = 0; j < s->n; j++) if (!strcmp(r->e[i].name, s->e[j].name)) f = 1;
        CHECKF(f, "%s only in rsaenh", r->e[i].name);
    }
}
TEST(exports_cng_capi_xmod_rsaenh_dssenh_distinct_implementations) {
    HMODULE r = t_module("rsaenh.dll"), s = t_module("dssenh.dll");
    if (!r || !s) { t_skip("module missing"); return; }
    CHECK(r != s);
    const XM *m = ex_find("rsaenh.dll");
    for (int i = 0; i < m->n; i++) {
        FARPROC a = GetProcAddress(r, m->e[i].name), b = GetProcAddress(s, m->e[i].name);
        CHECKF(a && b && a != b, "%s", m->e[i].name);
    }
}
TEST(exports_cng_capi_xmod_csp_spi_not_exported_by_cryptsp) {
    HMODULE c = t_module("cryptsp.dll");
    if (!c) { t_skip("no cryptsp"); return; }
    const XM *m = ex_find("rsaenh.dll");
    for (int i = 0; i < m->n; i++) {
        if (strncmp(m->e[i].name, "CP", 2)) continue;
        SET_ERR(0);
        CHECKF(GetProcAddress(c, m->e[i].name) == NULL, "cryptsp exports %s", m->e[i].name);
    }
}

/* ---- advapi32 Crypt* vs cryptsp Crypt* ------------------------------------------------------------- */
TEST(exports_cng_capi_xmod_cryptsp_names_also_in_advapi32) {
    const XM *cs = ex_find("cryptsp.dll"), *ad = ex_find("advapi32.dll");
    HMODULE h = t_module("advapi32.dll");
    int shared = 0;
    for (int i = 0; i < cs->n; i++) {
        const char *n = cs->e[i].name;
        if (strncmp(n, "Crypt", 5)) continue;
        int f = 0;
        for (int j = 0; j < ad->n; j++) if (ad->e[j].name && !strcmp(ad->e[j].name, n)) f = 1;
        if (f) { shared++; CHECK(h && GetProcAddress(h, n)); }
        else t_note("cryptsp!%s is not exported by advapi32", n);
    }
    CHECK(shared > 0);
}
TEST(exports_cng_capi_xmod_cryptsp_exports_signature_and_check_helpers) {
    HMODULE h = t_module("cryptsp.dll");
    if (!h) { t_skip("no cryptsp"); return; }
    CHECK(GetProcAddress(h, "CheckSignatureInFile") != NULL);
    HMODULE a = t_module("advapi32.dll");
    if (a) {
        /* advapi32 SystemFunction035 forwards to cryptsp!CheckSignatureInFile */
        FARPROC x = GetProcAddress(a, "SystemFunction035");
        if (x) EXPECT_EQ(x, GetProcAddress(h, "CheckSignatureInFile"));
        else t_note("advapi32 has no SystemFunction035");
    }
}

/* ---- bcryptprimitives -------------------------------------------------------------------------------- */
TEST(exports_cng_capi_xmod_bcryptprimitives_interface_getters) {
    HMODULE h = t_module("bcryptprimitives.dll"); XDIR d;
    if (!h || !ex_dir(h, &d)) { t_skip("no bcryptprimitives"); return; }
    static const char *const n[] = { "GetAsymmetricEncryptionInterface","GetCipherInterface","GetHashInterface",
        "GetKeyDerivationInterface","GetRngInterface","GetSecretAgreementInterface","GetSignatureInterface" };
    for (int i = 0; i < 7; i++) {
        FARPROC p = GetProcAddress(h, n[i]);
        CHECKF(p && ex_in_image(&d, p), "%s", n[i]);
    }
    /* these provider-interface getters are not exported by bcrypt.dll itself */
    HMODULE b = t_module("bcrypt.dll");
    for (int i = 0; b && i < 7; i++) { SET_ERR(0); CHECKF(GetProcAddress(b, n[i]) == NULL, "bcrypt exports %s", n[i]); }
}
TEST(exports_cng_capi_xmod_bcryptprimitives_prng_pair) {
    HMODULE h = t_module("bcryptprimitives.dll");
    if (!h) { t_skip("no bcryptprimitives"); return; }
    FARPROC a = GetProcAddress(h, "ProcessPrng"), b = GetProcAddress(h, "ProcessPrngGuid");
    CHECK(a != NULL); CHECK(b != NULL); CHECK(a != b);
}
TEST(exports_cng_capi_xmod_ncryptprov_key_storage_entry) {
    HMODULE h = t_module("ncryptprov.dll"); XDIR d;
    if (!h || !ex_dir(h, &d)) { t_skip("no ncryptprov"); return; }
    FARPROC p = GetProcAddress(h, "GetKeyStorageInterface");
    CHECK(p && ex_in_image(&d, p));
    FARPROC q = GetProcAddress(h, "SetAuditingInterface");
    CHECK(q && ex_in_image(&d, q));
    CHECK(GetProcAddress(h, "SKCacheFlush") != NULL);
}
TEST(exports_cng_capi_xmod_dpapi_no_ui_variants) {
    HMODULE h = t_module("dpapi.dll"); XDIR d;
    if (!h || !ex_dir(h, &d)) { t_skip("no dpapi"); return; }
    static const char *const n[] = { "CryptProtectDataNoUI","CryptUnprotectDataNoUI","CryptProtectMemory","CryptUnprotectMemory",
        "CryptResetMachineCredentials","CryptUpdateProtectedState","iCryptIdentifyProtection" };
    for (int i = 0; i < 7; i++) { FARPROC p = GetProcAddress(h, n[i]); CHECKF(p && ex_in_image(&d, p), "%s", n[i]); }
}

/* ---- additional forwarder / ordinal checks ---------------------------------------------------------- */
TEST(exports_cng_capi_xmod_ncrypt_forwarders_by_ordinal_match_bcrypt) {
    HMODULE n = t_module("ncrypt.dll"), b = t_module("bcrypt.dll"); XDIR d;
    if (!n || !b || !ex_dir(n, &d)) { t_skip("module missing"); return; }
    if (t_is_wine()) { t_skip("wine forwarders differ"); return; }
    const XM *nc = ex_find("ncrypt.dll");
    int k = 0;
    for (int i = 0; i < nc->n && k < 60; i++) {
        DWORD ord;
        if (!nc->e[i].fwd || !ex_dir_find(&d, nc->e[i].name, &ord, NULL, NULL)) continue;
        k++;
        SET_ERR(0);
        FARPROC byord = GetProcAddress(n, MAKEINTRESOURCEA(ord));
        CHECKF(byord != NULL && byord == GetProcAddress(b, nc->e[i].name), "%s", nc->e[i].name);
    }
    CHECK(k > 0);
}
TEST(exports_cng_capi_xmod_forwarder_targets_are_loadable_modules) {
    static const char *const mods[] = { "ncrypt.dll", "advapi32.dll", "cryptdll.dll" };
    if (t_is_wine()) { t_skip("wine lacks forward target modules"); return; }
    for (unsigned k = 0; k < 3; k++) {
        const XM *m = ex_find(mods[k]);
        for (int i = 0; m && i < m->n; i++) {
            if (!m->e[i].fwd) continue;
            char dll[64], sym[128]; ex_target_of(m->e[i].fwd, dll, sizeof dll, sym, sizeof sym);
            CHECKF(t_module(dll) != NULL, "%s forwards %s to unloadable %s", mods[k], m->e[i].name, dll);
            CHECKF(sym[0] && sym[0] != '#', "%s forwarder %s is not by name", m->e[i].name, m->e[i].fwd);
        }
    }
}
TEST(exports_cng_capi_xmod_ncrypt_getprocaddress_forwarder_resolves_to_other_image) {
    HMODULE n = t_module("ncrypt.dll"); XDIR d;
    if (!n || !ex_dir(n, &d)) { t_skip("no ncrypt"); return; }
    static const char *const f[] = { "BCryptHash", "BCryptOpenAlgorithmProvider", "BCryptDecrypt", "BCryptVerifySignature" };
    for (int i = 0; i < 4; i++) {
        FARPROC p = GetProcAddress(n, f[i]);
        if (!p && t_is_wine()) { t_note("wine: ncrypt!%s unresolved", f[i]); continue; }
        CHECKF(p != NULL && !ex_in_image(&d, p), "%s", f[i]);
    }
}
TEST(exports_cng_capi_xmod_getprocaddress_null_module_and_ordinal_zero) {
    HMODULE b = t_module("bcrypt.dll");
    if (!b) { t_skip("no bcrypt"); return; }
    EXPECT_GPA_FAIL(b, MAKEINTRESOURCEA(0));   /* 87 */
    EXPECT_GPA_FAIL(NULL, "BCryptHash");       /* 127: NULL module is the exe itself */
}
