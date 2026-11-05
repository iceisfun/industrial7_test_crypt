/* More user-mode argument validation, taken from the shipped bcrypt.dll: provider registration structure
 * checks (BcpIsValidProviderReg / ImageReg / InterfaceRegArray / StringArray), provider-mode checks of
 * the resolve and registration-query calls, and the change-notify handle check. All of these fail before
 * any call into the configuration driver, so they neither need elevation nor change any state. */
#include "cfg.h"

typedef struct {
    PWSTR fns[2];
    CRYPT_INTERFACE_REG ir;
    PCRYPT_INTERFACE_REG irs[1];
    CRYPT_IMAGE_REG img;
    PWSTR als[2];
    CRYPT_PROVIDER_REG reg;
} VR;

static void vr_init(VR *v) {
    memset(v, 0, sizeof *v);
    v->fns[0] = L"AES"; v->fns[1] = L"SHA256";
    v->ir.dwInterface = BCRYPT_CIPHER_INTERFACE; v->ir.cFunctions = 2; v->ir.rgpszFunctions = v->fns;
    v->irs[0] = &v->ir;
    v->img.pszImage = L"C:\\Windows\\System32\\cryptt_never.dll"; v->img.cInterfaces = 1; v->img.rgpInterfaces = v->irs;
    v->als[0] = L"cryptt_a"; v->als[1] = L"cryptt_b";
    v->reg.pUM = &v->img;
}
#define NEEDV() do { REQUIRE(UN(BCryptRegisterProvider)); if (t_is_wine()) { t_skip("emulator is lenient"); return; } } while (0)
#define REGBAD(v) ST_EQ(UN(BCryptRegisterProvider)(L"cryptt_never_prov", 0, &(v).reg), S_INVALID_PARAMETER)

TEST(dxctx_val2_reg_image_null_path) {
    NEEDV(); VR v; vr_init(&v);
    v.img.pszImage = NULL; REGBAD(v);
    v.img.pszImage = L""; REGBAD(v);
}
TEST(dxctx_val2_reg_image_no_interfaces) {
    NEEDV(); VR v; vr_init(&v);
    v.img.cInterfaces = 0; REGBAD(v);
    vr_init(&v); v.img.rgpInterfaces = NULL; REGBAD(v);
    vr_init(&v); v.irs[0] = NULL; REGBAD(v);
}
TEST(dxctx_val2_reg_interface_ids) {
    NEEDV(); VR v;
    static const ULONG bad[] = {0, 8, 0x10000, 0x10005, 0xFFFFFFFF};
    for (int i = 0; i < 5; i++) { vr_init(&v); v.ir.dwInterface = bad[i]; REGBAD(v); }
}
TEST(dxctx_val2_reg_interface_functions) {
    NEEDV(); VR v;
    vr_init(&v); v.ir.cFunctions = 0; REGBAD(v);
    vr_init(&v); v.ir.rgpszFunctions = NULL; REGBAD(v);
    vr_init(&v); v.fns[1] = NULL; REGBAD(v);
    vr_init(&v); v.fns[0] = L""; REGBAD(v);
}
TEST(dxctx_val2_reg_aliases) {
    NEEDV(); VR v;
    vr_init(&v); v.reg.cAliases = 1; v.reg.rgpszAliases = NULL; REGBAD(v);
    vr_init(&v); v.reg.cAliases = 2; v.reg.rgpszAliases = v.als; v.als[1] = NULL; REGBAD(v);
    vr_init(&v); v.reg.cAliases = 2; v.reg.rgpszAliases = v.als; v.als[0] = L""; REGBAD(v);
    vr_init(&v); v.reg.cAliases = 0; v.reg.rgpszAliases = v.als; REGBAD(v);
}
TEST(dxctx_val2_reg_km_image_validated_too) {
    NEEDV(); VR v; vr_init(&v);
    CRYPT_IMAGE_REG km = {NULL, 1, v.irs};
    v.reg.pKM = &km; REGBAD(v);       /* a valid UM image does not excuse a malformed KM image */
    vr_init(&v); CRYPT_IMAGE_REG km2 = {L"cryptt_never.sys", 0, v.irs};
    v.reg.pKM = &km2; REGBAD(v);
    vr_init(&v); v.reg.pUM = NULL; v.reg.pKM = &km; REGBAD(v);
}
TEST(dxctx_val2_reg_flags_checked_after_name_before_struct) {
    NEEDV(); VR v; vr_init(&v);
    /* both the flags and the structure are bad; either way the answer is the same status */
    CRYPT_PROVIDER_REG none = {0, NULL, NULL, NULL};
    ST_EQ(UN(BCryptRegisterProvider)(L"cryptt_never_prov", 2, &none), S_INVALID_PARAMETER);
    ST_EQ(UN(BCryptRegisterProvider)(NULL, 0, NULL), S_INVALID_PARAMETER);
    ST_EQ(UN(BCryptRegisterProvider)(NULL, 2, NULL), S_INVALID_PARAMETER);
}
TEST(dxctx_val2_resolve_provider_mode) {
    REQUIRE(U(BCryptResolveProviders));
    if (t_is_wine()) { t_skip("emulator stub aborts"); return; }
    /* ValidateProviderMode(mode, 2): 1, 2 and 3 are valid; 0, 4 and above are not */
    static const ULONG bad[] = {0, 4, 5, 0x80000000, 0xFFFFFFFF};
    for (int i = 0; i < 5; i++) {
        ULONG cb = 0; PCRYPT_PROVIDER_REFS p = NULL;
        ST_EQ(U(BCryptResolveProviders)(NULL, 1, NULL, NULL, bad[i], 0, &cb, &p), S_INVALID_PARAMETER);
        CHECK(p == NULL);
    }
}
TEST(dxctx_val2_resolve_flags) {
    REQUIRE(U(BCryptResolveProviders));
    if (t_is_wine()) { t_skip("emulator stub aborts"); return; }
    /* only the two low flag bits are defined */
    static const ULONG bad[] = {4, 8, 0x100, 0x80000000, 0xFFFFFFFC};
    for (int i = 0; i < 5; i++) {
        ULONG cb = 0; PCRYPT_PROVIDER_REFS p = NULL;
        ST_EQ(U(BCryptResolveProviders)(NULL, 1, NULL, NULL, CRYPT_UM, bad[i], &cb, &p), S_INVALID_PARAMETER);
        CHECK(p == NULL);
    }
}
TEST(dxctx_val2_query_registration_mode) {
    REQUIRE(U(BCryptQueryProviderRegistration));
    if (t_is_wine()) { t_skip("emulator stub aborts"); return; }
    /* ValidateProviderMode(mode, 6): 1..4 are valid; 0 and 5 and above are not */
    static const ULONG bad[] = {0, 5, 6, 0x80000000, 0xFFFFFFFF};
    for (int i = 0; i < 5; i++) {
        ULONG cb = 0; PCRYPT_PROVIDER_REG p = NULL;
        ST_EQ(U(BCryptQueryProviderRegistration)(L"cryptt_never_prov", bad[i], 1, &cb, &p), S_INVALID_PARAMETER);
        CHECK(p == NULL);
    }
}
TEST(dxctx_val2_unregister_notify_null_exact) {
    REQUIRE(U(BCryptUnregisterConfigChangeNotify));
    if (t_is_wine()) { t_skip("emulator stub aborts"); return; }
    ST_EQ(U(BCryptUnregisterConfigChangeNotify)(NULL), S_INVALID_PARAMETER);
}
TEST(dxctx_val2_enum_registered_providers_buffer_untouched_on_error) {
    REQUIRE(U(BCryptEnumRegisteredProviders));
    if (t_is_wine()) { t_skip("emulator stub aborts"); return; }
    PCRYPT_PROVIDERS p = NULL;
    ST_EQ(U(BCryptEnumRegisteredProviders)(NULL, &p), S_INVALID_PARAMETER);
    CHECK(p == NULL);
}
TEST(dxctx_val2_free_buffer_null) {
    REQUIRE(U(BCryptFreeBuffer));
    /* freeing a NULL buffer is a documented no-op that must not crash */
    T_TRY(U(BCryptFreeBuffer)(NULL));
}
