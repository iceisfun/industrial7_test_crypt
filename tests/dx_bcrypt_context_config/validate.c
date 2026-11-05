/* Argument validation that happens in user mode, before the configuration driver is called.
 * Every status below is derived from the shipped bcrypt.dll: ValidateTableId accepts 1 and 2 only,
 * ValidateInterfaceId accepts 1..7 and 0x10001..0x10004, empty/NULL names are rejected, and the
 * resulting status is STATUS_INVALID_PARAMETER. None of these reach the registry, so they are safe
 * (and meaningful) with or without elevation. */
#include "cfg.h"

#define BADT_LOOP for (int i_ = 0; i_ < 6; i_++) { ULONG bt = cfg_bad_tables[i_];
#define BADI_LOOP for (int j_ = 0; j_ < 7; j_++) { ULONG bi = cfg_bad_ifaces[j_];
#define END }

TEST(dxctx_val_create_bad_table) {
    REQUIRE(U(BCryptCreateContext));
    if (t_is_wine()) { t_skip("emulator stub aborts"); return; }
    CRYPT_CONTEXT_CONFIG c = {0, 0};
    BADT_LOOP ST_EQ(U(BCryptCreateContext)(bt, L"cryptt_never", &c), S_INVALID_PARAMETER); END
}
TEST(dxctx_val_create_null_name) {
    REQUIRE(U(BCryptCreateContext));
    if (t_is_wine()) { t_skip("emulator stub aborts"); return; }
    CRYPT_CONTEXT_CONFIG c = {0, 0};
    ST_EQ(U(BCryptCreateContext)(CRYPT_LOCAL, NULL, &c), S_INVALID_PARAMETER);
    ST_EQ(U(BCryptCreateContext)(CRYPT_DOMAIN, NULL, &c), S_INVALID_PARAMETER);
}
TEST(dxctx_val_create_empty_name) {
    REQUIRE(U(BCryptCreateContext));
    if (t_is_wine()) { t_skip("emulator stub aborts"); return; }
    CRYPT_CONTEXT_CONFIG c = {0, 0};
    ST_EQ(U(BCryptCreateContext)(CRYPT_LOCAL, L"", &c), S_INVALID_PARAMETER);
    ST_EQ(U(BCryptCreateContext)(CRYPT_DOMAIN, L"", NULL), S_INVALID_PARAMETER);
}
TEST(dxctx_val_delete_bad_table) {
    REQUIRE(U(BCryptDeleteContext));
    if (t_is_wine()) { t_skip("emulator stub aborts"); return; }
    BADT_LOOP ST_EQ(U(BCryptDeleteContext)(bt, L"cryptt_never"), S_INVALID_PARAMETER); END
}
TEST(dxctx_val_delete_null_and_empty) {
    REQUIRE(U(BCryptDeleteContext));
    if (t_is_wine()) { t_skip("emulator stub aborts"); return; }
    ST_EQ(U(BCryptDeleteContext)(CRYPT_LOCAL, NULL), S_INVALID_PARAMETER);
    ST_EQ(U(BCryptDeleteContext)(CRYPT_LOCAL, L""), S_INVALID_PARAMETER);
    ST_EQ(U(BCryptDeleteContext)(CRYPT_DOMAIN, NULL), S_INVALID_PARAMETER);
    ST_EQ(U(BCryptDeleteContext)(CRYPT_DOMAIN, L""), S_INVALID_PARAMETER);
}
TEST(dxctx_val_configure_bad_table) {
    REQUIRE(U(BCryptConfigureContext));
    if (t_is_wine()) { t_skip("emulator stub aborts"); return; }
    CRYPT_CONTEXT_CONFIG c = {0, 0};
    BADT_LOOP ST_EQ(U(BCryptConfigureContext)(bt, L"cryptt_never", &c), S_INVALID_PARAMETER); END
}
TEST(dxctx_val_configure_null_config) {
    REQUIRE(U(BCryptConfigureContext));
    if (t_is_wine()) { t_skip("emulator stub aborts"); return; }
    ST_EQ(U(BCryptConfigureContext)(CRYPT_LOCAL, L"cryptt_never", NULL), S_INVALID_PARAMETER);
    ST_EQ(U(BCryptConfigureContext)(CRYPT_DOMAIN, L"cryptt_never", NULL), S_INVALID_PARAMETER);
}
TEST(dxctx_val_enum_contexts_bad_table) {
    REQUIRE(U(BCryptEnumContexts));
    if (t_is_wine()) { t_skip("emulator stub aborts"); return; }
    ULONG cb = 0; PCRYPT_CONTEXTS p = NULL;
    BADT_LOOP ST_EQ(U(BCryptEnumContexts)(bt, &cb, &p), S_INVALID_PARAMETER); CHECK(p == NULL); END
}
TEST(dxctx_val_enum_contexts_null_size) {
    REQUIRE(U(BCryptEnumContexts));
    if (t_is_wine()) { t_skip("emulator stub aborts"); return; }
    PCRYPT_CONTEXTS p = NULL;
    ST_EQ(U(BCryptEnumContexts)(CRYPT_LOCAL, NULL, &p), S_INVALID_PARAMETER);
}
TEST(dxctx_val_query_config_bad_table) {
    REQUIRE(U(BCryptQueryContextConfiguration));
    if (t_is_wine()) { t_skip("emulator stub aborts"); return; }
    ULONG cb = 0; PCRYPT_CONTEXT_CONFIG p = NULL;
    BADT_LOOP ST_EQ(U(BCryptQueryContextConfiguration)(bt, L"cryptt_never", &cb, &p), S_INVALID_PARAMETER); CHECK(p == NULL); END
}
TEST(dxctx_val_query_config_null_size) {
    REQUIRE(U(BCryptQueryContextConfiguration));
    if (t_is_wine()) { t_skip("emulator stub aborts"); return; }
    PCRYPT_CONTEXT_CONFIG p = NULL;
    ST_EQ(U(BCryptQueryContextConfiguration)(CRYPT_LOCAL, L"cryptt_never", NULL, &p), S_INVALID_PARAMETER);
}
TEST(dxctx_val_add_function_bad_table) {
    REQUIRE(U(BCryptAddContextFunction));
    if (t_is_wine()) { t_skip("emulator does not validate"); return; }
    BADT_LOOP ST_EQ(U(BCryptAddContextFunction)(bt, L"cryptt_never", BCRYPT_CIPHER_INTERFACE, L"fn", CRYPT_PRIORITY_BOTTOM), S_INVALID_PARAMETER); END
}
TEST(dxctx_val_add_function_bad_interface) {
    REQUIRE(U(BCryptAddContextFunction));
    if (t_is_wine()) { t_skip("emulator does not validate"); return; }
    BADI_LOOP ST_EQ(U(BCryptAddContextFunction)(CRYPT_LOCAL, L"cryptt_never", bi, L"fn", CRYPT_PRIORITY_BOTTOM), S_INVALID_PARAMETER); END
}
TEST(dxctx_val_add_function_null_empty_function) {
    REQUIRE(U(BCryptAddContextFunction));
    if (t_is_wine()) { t_skip("emulator does not validate"); return; }
    ST_EQ(U(BCryptAddContextFunction)(CRYPT_LOCAL, L"cryptt_never", BCRYPT_CIPHER_INTERFACE, NULL, 0), S_INVALID_PARAMETER);
    ST_EQ(U(BCryptAddContextFunction)(CRYPT_LOCAL, L"cryptt_never", BCRYPT_CIPHER_INTERFACE, L"", 0), S_INVALID_PARAMETER);
}
TEST(dxctx_val_remove_function_bad_args) {
    REQUIRE(U(BCryptRemoveContextFunction));
    if (t_is_wine()) { t_skip("emulator does not validate"); return; }
    BADT_LOOP ST_EQ(U(BCryptRemoveContextFunction)(bt, L"cryptt_never", 1, L"fn"), S_INVALID_PARAMETER); END
    BADI_LOOP ST_EQ(U(BCryptRemoveContextFunction)(CRYPT_LOCAL, L"cryptt_never", bi, L"fn"), S_INVALID_PARAMETER); END
    ST_EQ(U(BCryptRemoveContextFunction)(CRYPT_LOCAL, L"cryptt_never", 1, NULL), S_INVALID_PARAMETER);
    ST_EQ(U(BCryptRemoveContextFunction)(CRYPT_LOCAL, L"cryptt_never", 1, L""), S_INVALID_PARAMETER);
}
TEST(dxctx_val_enum_functions_bad_args) {
    REQUIRE(U(BCryptEnumContextFunctions));
    if (t_is_wine()) { t_skip("emulator does not validate"); return; }
    ULONG cb = 0; PCRYPT_CONTEXT_FUNCTIONS p = NULL;
    BADT_LOOP ST_EQ(U(BCryptEnumContextFunctions)(bt, L"cryptt_never", 1, &cb, &p), S_INVALID_PARAMETER); END
    BADI_LOOP ST_EQ(U(BCryptEnumContextFunctions)(CRYPT_LOCAL, L"cryptt_never", bi, &cb, &p), S_INVALID_PARAMETER); END
    ST_EQ(U(BCryptEnumContextFunctions)(CRYPT_LOCAL, L"cryptt_never", 1, NULL, &p), S_INVALID_PARAMETER);
    CHECK(p == NULL);
}
TEST(dxctx_val_configure_function_bad_args) {
    REQUIRE(U(BCryptConfigureContextFunction));
    if (t_is_wine()) { t_skip("emulator stub aborts"); return; }
    CRYPT_CONTEXT_FUNCTION_CONFIG c = {0, 0};
    BADT_LOOP ST_EQ(U(BCryptConfigureContextFunction)(bt, L"cryptt_never", 1, L"fn", &c), S_INVALID_PARAMETER); END
    BADI_LOOP ST_EQ(U(BCryptConfigureContextFunction)(CRYPT_LOCAL, L"cryptt_never", bi, L"fn", &c), S_INVALID_PARAMETER); END
    ST_EQ(U(BCryptConfigureContextFunction)(CRYPT_LOCAL, L"cryptt_never", 1, NULL, &c), S_INVALID_PARAMETER);
    ST_EQ(U(BCryptConfigureContextFunction)(CRYPT_LOCAL, L"cryptt_never", 1, L"", &c), S_INVALID_PARAMETER);
}
TEST(dxctx_val_query_function_config_bad_args) {
    REQUIRE(U(BCryptQueryContextFunctionConfiguration));
    if (t_is_wine()) { t_skip("emulator stub aborts"); return; }
    ULONG cb = 0; PCRYPT_CONTEXT_FUNCTION_CONFIG p = NULL;
    BADT_LOOP ST_EQ(U(BCryptQueryContextFunctionConfiguration)(bt, L"cryptt_never", 1, L"fn", &cb, &p), S_INVALID_PARAMETER); END
    BADI_LOOP ST_EQ(U(BCryptQueryContextFunctionConfiguration)(CRYPT_LOCAL, L"cryptt_never", bi, L"fn", &cb, &p), S_INVALID_PARAMETER); END
    ST_EQ(U(BCryptQueryContextFunctionConfiguration)(CRYPT_LOCAL, L"cryptt_never", 1, NULL, &cb, &p), S_INVALID_PARAMETER);
    ST_EQ(U(BCryptQueryContextFunctionConfiguration)(CRYPT_LOCAL, L"cryptt_never", 1, L"", &cb, &p), S_INVALID_PARAMETER);
    ST_EQ(U(BCryptQueryContextFunctionConfiguration)(CRYPT_LOCAL, L"cryptt_never", 1, L"fn", NULL, &p), S_INVALID_PARAMETER);
    CHECK(p == NULL);
}
TEST(dxctx_val_enum_function_providers_bad_args) {
    REQUIRE(U(BCryptEnumContextFunctionProviders));
    if (t_is_wine()) { t_skip("emulator stub aborts"); return; }
    ULONG cb = 0; PCRYPT_CONTEXT_FUNCTION_PROVIDERS p = NULL;
    BADT_LOOP ST_EQ(U(BCryptEnumContextFunctionProviders)(bt, L"cryptt_never", 1, L"fn", &cb, &p), S_INVALID_PARAMETER); END
    BADI_LOOP ST_EQ(U(BCryptEnumContextFunctionProviders)(CRYPT_LOCAL, L"cryptt_never", bi, L"fn", &cb, &p), S_INVALID_PARAMETER); END
    ST_EQ(U(BCryptEnumContextFunctionProviders)(CRYPT_LOCAL, L"cryptt_never", 1, NULL, &cb, &p), S_INVALID_PARAMETER);
    ST_EQ(U(BCryptEnumContextFunctionProviders)(CRYPT_LOCAL, L"cryptt_never", 1, L"", &cb, &p), S_INVALID_PARAMETER);
    ST_EQ(U(BCryptEnumContextFunctionProviders)(CRYPT_LOCAL, L"cryptt_never", 1, L"fn", NULL, &p), S_INVALID_PARAMETER);
    CHECK(p == NULL);
}
TEST(dxctx_val_add_function_provider_bad_args) {
    if (!UN(BCryptAddContextFunctionProvider)) { t_skip("missing export"); return; }
    if (t_is_wine()) { t_skip("emulator does not validate"); return; }
    BCryptAddContextFunctionProvider_pfn f = UN(BCryptAddContextFunctionProvider);
    BADT_LOOP ST_EQ(f(bt, L"cryptt_never", 1, L"fn", L"prov", 0), S_INVALID_PARAMETER); END
    BADI_LOOP ST_EQ(f(CRYPT_LOCAL, L"cryptt_never", bi, L"fn", L"prov", 0), S_INVALID_PARAMETER); END
    ST_EQ(f(CRYPT_LOCAL, L"cryptt_never", 1, NULL, L"prov", 0), S_INVALID_PARAMETER);
    ST_EQ(f(CRYPT_LOCAL, L"cryptt_never", 1, L"", L"prov", 0), S_INVALID_PARAMETER);
    ST_EQ(f(CRYPT_LOCAL, L"cryptt_never", 1, L"fn", NULL, 0), S_INVALID_PARAMETER);
    ST_EQ(f(CRYPT_LOCAL, L"cryptt_never", 1, L"fn", L"", 0), S_INVALID_PARAMETER);
}
TEST(dxctx_val_remove_function_provider_bad_args) {
    if (!UN(BCryptRemoveContextFunctionProvider)) { t_skip("missing export"); return; }
    if (t_is_wine()) { t_skip("emulator does not validate"); return; }
    BCryptRemoveContextFunctionProvider_pfn f = UN(BCryptRemoveContextFunctionProvider);
    BADT_LOOP ST_EQ(f(bt, L"cryptt_never", 1, L"fn", L"prov"), S_INVALID_PARAMETER); END
    BADI_LOOP ST_EQ(f(CRYPT_LOCAL, L"cryptt_never", bi, L"fn", L"prov"), S_INVALID_PARAMETER); END
    ST_EQ(f(CRYPT_LOCAL, L"cryptt_never", 1, NULL, L"prov"), S_INVALID_PARAMETER);
    ST_EQ(f(CRYPT_LOCAL, L"cryptt_never", 1, L"", L"prov"), S_INVALID_PARAMETER);
    ST_EQ(f(CRYPT_LOCAL, L"cryptt_never", 1, L"fn", NULL), S_INVALID_PARAMETER);
    ST_EQ(f(CRYPT_LOCAL, L"cryptt_never", 1, L"fn", L""), S_INVALID_PARAMETER);
}
TEST(dxctx_val_set_property_bad_args) {
    REQUIRE(U(BCryptSetContextFunctionProperty));
    if (t_is_wine()) { t_skip("emulator stub aborts"); return; }
    UCHAR v[4] = {1, 2, 3, 4};
    BADT_LOOP ST_EQ(U(BCryptSetContextFunctionProperty)(bt, L"cryptt_never", 1, L"fn", L"p", 4, v), S_INVALID_PARAMETER); END
    BADI_LOOP ST_EQ(U(BCryptSetContextFunctionProperty)(CRYPT_LOCAL, L"cryptt_never", bi, L"fn", L"p", 4, v), S_INVALID_PARAMETER); END
    ST_EQ(U(BCryptSetContextFunctionProperty)(CRYPT_LOCAL, L"cryptt_never", 1, NULL, L"p", 4, v), S_INVALID_PARAMETER);
    ST_EQ(U(BCryptSetContextFunctionProperty)(CRYPT_LOCAL, L"cryptt_never", 1, L"", L"p", 4, v), S_INVALID_PARAMETER);
    ST_EQ(U(BCryptSetContextFunctionProperty)(CRYPT_LOCAL, L"cryptt_never", 1, L"fn", NULL, 4, v), S_INVALID_PARAMETER);
    ST_EQ(U(BCryptSetContextFunctionProperty)(CRYPT_LOCAL, L"cryptt_never", 1, L"fn", L"", 4, v), S_INVALID_PARAMETER);
}
TEST(dxctx_val_query_property_bad_args) {
    REQUIRE(U(BCryptQueryContextFunctionProperty));
    if (t_is_wine()) { t_skip("emulator stub aborts"); return; }
    ULONG cb = 0; PUCHAR p = NULL;
    BADT_LOOP ST_EQ(U(BCryptQueryContextFunctionProperty)(bt, L"cryptt_never", 1, L"fn", L"p", &cb, &p), S_INVALID_PARAMETER); END
    BADI_LOOP ST_EQ(U(BCryptQueryContextFunctionProperty)(CRYPT_LOCAL, L"cryptt_never", bi, L"fn", L"p", &cb, &p), S_INVALID_PARAMETER); END
    ST_EQ(U(BCryptQueryContextFunctionProperty)(CRYPT_LOCAL, L"cryptt_never", 1, NULL, L"p", &cb, &p), S_INVALID_PARAMETER);
    ST_EQ(U(BCryptQueryContextFunctionProperty)(CRYPT_LOCAL, L"cryptt_never", 1, L"", L"p", &cb, &p), S_INVALID_PARAMETER);
    ST_EQ(U(BCryptQueryContextFunctionProperty)(CRYPT_LOCAL, L"cryptt_never", 1, L"fn", NULL, &cb, &p), S_INVALID_PARAMETER);
    ST_EQ(U(BCryptQueryContextFunctionProperty)(CRYPT_LOCAL, L"cryptt_never", 1, L"fn", L"", &cb, &p), S_INVALID_PARAMETER);
    ST_EQ(U(BCryptQueryContextFunctionProperty)(CRYPT_LOCAL, L"cryptt_never", 1, L"fn", L"p", NULL, &p), S_INVALID_PARAMETER);
    CHECK(p == NULL);
}
TEST(dxctx_val_resolve_providers_bad_args) {
    REQUIRE(U(BCryptResolveProviders));
    if (t_is_wine()) { t_skip("emulator stub aborts"); return; }
    ULONG cb = 0; PCRYPT_PROVIDER_REFS p = NULL;
    /* interface is validated with the "0 allowed" variant; 8 and 0x10000 are never valid */
    ST_EQ(U(BCryptResolveProviders)(NULL, 8, NULL, NULL, CRYPT_UM, 0, &cb, &p), S_INVALID_PARAMETER);
    ST_EQ(U(BCryptResolveProviders)(NULL, 0x10000, NULL, NULL, CRYPT_UM, 0, &cb, &p), S_INVALID_PARAMETER);
    ST_EQ(U(BCryptResolveProviders)(NULL, 0xFFFFFFFF, NULL, NULL, CRYPT_UM, 0, &cb, &p), S_INVALID_PARAMETER);
    ST_EQ(U(BCryptResolveProviders)(NULL, 1, NULL, NULL, CRYPT_UM, 0, NULL, &p), S_INVALID_PARAMETER);
    CHECK(p == NULL);
}
TEST(dxctx_val_register_provider_bad_args) {
    REQUIRE(UN(BCryptRegisterProvider));
    if (t_is_wine()) { t_skip("emulator stub aborts"); return; }
    BCryptRegisterProvider_pfn f = UN(BCryptRegisterProvider);
    WCHAR *fn[1] = {L"AES"};
    CRYPT_INTERFACE_REG ir = {BCRYPT_CIPHER_INTERFACE, 0, 1, fn};
    PCRYPT_INTERFACE_REG irs[1] = {&ir};
    CRYPT_IMAGE_REG img = {L"C:\\Windows\\System32\\cryptt_never.dll", 1, irs};
    CRYPT_PROVIDER_REG reg = {0, NULL, &img, NULL};
    /* provider name */
    ST_EQ(f(NULL, 0, &reg), S_INVALID_PARAMETER);
    ST_EQ(f(L"", 0, &reg), S_INVALID_PARAMETER);
    /* flags: only 0 and CRYPT_OVERWRITE are defined */
    ST_EQ(f(L"cryptt_never_prov", 2, &reg), S_INVALID_PARAMETER);
    ST_EQ(f(L"cryptt_never_prov", 3, &reg), S_INVALID_PARAMETER);
    ST_EQ(f(L"cryptt_never_prov", 0x80000000, &reg), S_INVALID_PARAMETER);
    ST_EQ(f(L"cryptt_never_prov", 0xFFFFFFFF, &reg), S_INVALID_PARAMETER);
    /* registration structure */
    ST_EQ(f(L"cryptt_never_prov", 0, NULL), S_INVALID_PARAMETER);
    CRYPT_PROVIDER_REG none = {0, NULL, NULL, NULL};
    ST_EQ(f(L"cryptt_never_prov", 0, &none), S_INVALID_PARAMETER);   /* neither UM nor KM image */
    PWSTR als[1] = {L"alias"};
    CRYPT_PROVIDER_REG badal = {0, als, &img, NULL};
    ST_EQ(f(L"cryptt_never_prov", 0, &badal), S_INVALID_PARAMETER);  /* zero count but array supplied */
}
TEST(dxctx_val_unregister_provider_bad_args) {
    REQUIRE(UN(BCryptUnregisterProvider));
    if (t_is_wine()) { t_skip("emulator stub aborts"); return; }
    ST_EQ(UN(BCryptUnregisterProvider)(NULL), S_INVALID_PARAMETER);
    ST_EQ(UN(BCryptUnregisterProvider)(L""), S_INVALID_PARAMETER);
}
TEST(dxctx_val_query_provider_registration_bad_args) {
    REQUIRE(U(BCryptQueryProviderRegistration));
    if (t_is_wine()) { t_skip("emulator stub aborts"); return; }
    ULONG cb = 0; PCRYPT_PROVIDER_REG p = NULL;
    BADI_LOOP
        if (bi == 0) continue;  /* 0 is a valid "any interface" value here */
        ST_EQ(U(BCryptQueryProviderRegistration)(L"cryptt_never_prov", CRYPT_UM, bi, &cb, &p), S_INVALID_PARAMETER);
    END
    ST_EQ(U(BCryptQueryProviderRegistration)(L"cryptt_never_prov", CRYPT_UM, 1, NULL, &p), S_INVALID_PARAMETER);
    CHECK(p == NULL);
}
TEST(dxctx_val_enum_registered_providers_null_size) {
    REQUIRE(U(BCryptEnumRegisteredProviders));
    if (t_is_wine()) { t_skip("emulator stub aborts"); return; }
    PCRYPT_PROVIDERS p = NULL;
    ST_EQ(U(BCryptEnumRegisteredProviders)(NULL, &p), S_INVALID_PARAMETER);
    CHECK(p == NULL);
}
TEST(dxctx_val_unregister_notify_null_handle) {
    REQUIRE(U(BCryptUnregisterConfigChangeNotify));
    if (t_is_wine()) { t_skip("emulator stub aborts"); return; }
    ULONG st = (ULONG)U(BCryptUnregisterConfigChangeNotify)(NULL);
    ST_EQ(st, S_INVALID_PARAMETER);
}
TEST(dxctx_val_interface_table_matrix) {
    /* Every valid interface id is accepted by the validators: the call must get past parameter
     * validation, i.e. it must NOT return STATUS_INVALID_PARAMETER for a well-formed request about a
     * context that does not exist: STATUS_NOT_FOUND when elevated, STATUS_ACCESS_DENIED for a standard user. */
    REQUIRE(U(BCryptRemoveContextFunction));
    if (t_is_wine()) { t_skip("emulator does not validate"); return; }
    for (int t = 1; t <= 2; t++)
        for (int i = 0; i < 11; i++) {
            ULONG st = (ULONG)U(BCryptRemoveContextFunction)(t, L"cryptt_never_ctx", cfg_valid_ifaces[i], L"fn");
            t_label("table %d iface 0x%lx", t, cfg_valid_ifaces[i]);
            ST_EQ(st, cfg_is_elevated() ? S_NOT_FOUND : S_ACCESS_DENIED);   /* the access check comes before the lookup */
        }
}
