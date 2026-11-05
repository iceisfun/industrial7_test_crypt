/* Parameter validation of the CNG configuration query APIs.
 * Every failure here is produced in user mode before the configuration store is consulted
 * (ValidateTableId / ValidateInterfaceId / ValidateProviderMode, empty-name checks, string length limit),
 * so the exact NTSTATUS is deterministic: STATUS_INVALID_PARAMETER, or STATUS_BUFFER_TOO_SMALL for over-long names. */
#include "cr.h"

static BYTE cr_sentinel_block[64];

/* ---------------------------------------------------------------- BCryptEnumContexts */
TEST(crpar_enumcontexts_bad_table)
{
    REQUIRE(U(BCryptEnumContexts));
    for (size_t i = 0; i < CR_N_BAD_TABLES; i++) {
        ULONG cb = 0x1234; PCRYPT_CONTEXTS p = NULL;
        NTSTATUS st = U(BCryptEnumContexts)(cr_bad_tables[i], &cb, &p);
        CHECKF(st == CRS_INVALID_PARAMETER, "table 0x%lx: got 0x%lx", cr_bad_tables[i], (ULONG)st);
        EXPECT_EQ(cb, 0x1234);       /* untouched on a parameter error */
        EXPECT_EQ(p, NULL);
    }
}
TEST(crpar_enumcontexts_bad_table_null_buffer_ptr)
{
    REQUIRE(U(BCryptEnumContexts));
    for (size_t i = 0; i < CR_N_BAD_TABLES; i++) {
        ULONG cb = 0x77;
        NTSTATUS st = U(BCryptEnumContexts)(cr_bad_tables[i], &cb, NULL);
        CHECKF(st == CRS_INVALID_PARAMETER, "table 0x%lx: got 0x%lx", cr_bad_tables[i], (ULONG)st);
        EXPECT_EQ(cb, 0x77);
    }
}
TEST(crpar_enumcontexts_null_size_pointer)
{
    REQUIRE(U(BCryptEnumContexts));
    for (ULONG t = 1; t <= 2; t++) {
        PCRYPT_CONTEXTS p = NULL;
        NTSTATUS st = U(BCryptEnumContexts)(t, NULL, &p);
        CHECKF(st == CRS_INVALID_PARAMETER, "table %lu: got 0x%lx", t, (ULONG)st);
        EXPECT_EQ(p, NULL);
        st = U(BCryptEnumContexts)(t, NULL, NULL);
        CHECKF(st == CRS_INVALID_PARAMETER, "table %lu, both null: got 0x%lx", t, (ULONG)st);
    }
}
TEST(crpar_enumcontexts_all_invalid_at_once)
{
    REQUIRE(U(BCryptEnumContexts));
    EXPECT_EQ(U(BCryptEnumContexts)(0, NULL, NULL), CRS_INVALID_PARAMETER);
    EXPECT_EQ(U(BCryptEnumContexts)(0xFFFFFFFF, NULL, NULL), CRS_INVALID_PARAMETER);
}
TEST(crpar_enumcontexts_caller_block_not_freed_on_param_error)
{
    REQUIRE(U(BCryptEnumContexts));
    /* The pointer variable the caller passed in is left alone on a parameter error (nothing was allocated by the call). */
    ULONG cb = sizeof cr_sentinel_block;
    PCRYPT_CONTEXTS p = (PCRYPT_CONTEXTS)cr_sentinel_block;
    NTSTATUS st = U(BCryptEnumContexts)(7, &cb, &p);
    EXPECT_EQ(st, CRS_INVALID_PARAMETER);
    EXPECT_EQ(p, cr_sentinel_block);
    EXPECT_EQ(cb, sizeof cr_sentinel_block);
    st = U(BCryptEnumContexts)(1, NULL, &p);
    EXPECT_EQ(st, CRS_INVALID_PARAMETER);
    EXPECT_EQ(p, cr_sentinel_block);
}

/* ---------------------------------------------------------------- BCryptEnumRegisteredProviders */
TEST(crpar_enumregistered_null_size_pointer)
{
    REQUIRE(U(BCryptEnumRegisteredProviders));
    PCRYPT_PROVIDERS p = NULL;
    EXPECT_EQ(U(BCryptEnumRegisteredProviders)(NULL, &p), CRS_INVALID_PARAMETER);
    EXPECT_EQ(p, NULL);
    EXPECT_EQ(U(BCryptEnumRegisteredProviders)(NULL, NULL), CRS_INVALID_PARAMETER);
}
TEST(crpar_enumregistered_null_ptr_is_size_query)
{
    REQUIRE(U(BCryptEnumRegisteredProviders));
    /* A NULL buffer pointer turns the call into a size query that SUCCEEDS (STATUS_BUFFER_TOO_SMALL is folded to 0). */
    ULONG cb = 0;
    NTSTATUS st = U(BCryptEnumRegisteredProviders)(&cb, NULL);
    EXPECT_EQ(st, CRS_OK);
    CHECKF(cb >= sizeof(CRYPT_PROVIDERS), "required size %lu", cb);
}

/* ---------------------------------------------------------------- BCryptQueryContextConfiguration */
TEST(crpar_querycontextcfg_bad_table)
{
    REQUIRE(U(BCryptQueryContextConfiguration));
    for (size_t i = 0; i < CR_N_BAD_TABLES; i++) {
        ULONG cb = 0x99; PCRYPT_CONTEXT_CONFIG p = NULL;
        NTSTATUS st = U(BCryptQueryContextConfiguration)(cr_bad_tables[i], L"Default", &cb, &p);
        CHECKF(st == CRS_INVALID_PARAMETER, "table 0x%lx: got 0x%lx", cr_bad_tables[i], (ULONG)st);
        EXPECT_EQ(cb, 0x99);
        EXPECT_EQ(p, NULL);
    }
}
TEST(crpar_querycontextcfg_bad_table_null_ptr)
{
    REQUIRE(U(BCryptQueryContextConfiguration));
    for (size_t i = 0; i < CR_N_BAD_TABLES; i++) {
        ULONG cb = 0;
        EXPECT_EQ(U(BCryptQueryContextConfiguration)(cr_bad_tables[i], L"SSL", &cb, NULL), CRS_INVALID_PARAMETER);
    }
}
TEST(crpar_querycontextcfg_null_size_pointer)
{
    REQUIRE(U(BCryptQueryContextConfiguration));
    PCRYPT_CONTEXT_CONFIG p = NULL;
    for (ULONG t = 1; t <= 2; t++) {
        EXPECT_EQ(U(BCryptQueryContextConfiguration)(t, L"Default", NULL, &p), CRS_INVALID_PARAMETER);
        EXPECT_EQ(U(BCryptQueryContextConfiguration)(t, L"Default", NULL, NULL), CRS_INVALID_PARAMETER);
    }
    EXPECT_EQ(p, NULL);
}
TEST(crpar_querycontextcfg_param_error_keeps_caller_pointer)
{
    REQUIRE(U(BCryptQueryContextConfiguration));
    ULONG cb = 5; PCRYPT_CONTEXT_CONFIG p = (PCRYPT_CONTEXT_CONFIG)cr_sentinel_block;
    EXPECT_EQ(U(BCryptQueryContextConfiguration)(0, L"Default", &cb, &p), CRS_INVALID_PARAMETER);
    EXPECT_EQ(p, cr_sentinel_block);
    EXPECT_EQ(cb, 5);
}
TEST(crpar_querycontextcfg_overlong_name_buffer_too_small)
{
    REQUIRE(U(BCryptQueryContextConfiguration));
    /* Names are measured with a 0xFFFF character limit; no terminator inside it gives ERROR_INSUFFICIENT_BUFFER
     * which is reported as STATUS_BUFFER_TOO_SMALL (not as a parameter error). */
    WCHAR *s = cr_longstr(0xFFFF, L'A'); REQUIRE(s);
    ULONG cb = 0; PCRYPT_CONTEXT_CONFIG p = NULL;
    NTSTATUS st = U(BCryptQueryContextConfiguration)(CR_TABLE_LOCAL, s, &cb, &p);
    EXPECT_EQ(st, CRS_BUFFER_TOO_SMALL);
    EXPECT_EQ(p, NULL);
    HeapFree(GetProcessHeap(), 0, s);
}
TEST(crpar_querycontextcfg_overlong_name_size_query_reports_success)
{
    REQUIRE(U(BCryptQueryContextConfiguration));
    /* With a NULL buffer pointer the final STATUS_BUFFER_TOO_SMALL is converted into STATUS_SUCCESS, whatever caused it. */
    WCHAR *s = cr_longstr(0xFFFF, L'B'); REQUIRE(s);
    ULONG cb = 0x5555;
    NTSTATUS st = U(BCryptQueryContextConfiguration)(CR_TABLE_LOCAL, s, &cb, NULL);
    EXPECT_EQ(st, CRS_OK);
    HeapFree(GetProcessHeap(), 0, s);
}
TEST(crpar_querycontextcfg_name_at_limit_is_accepted_by_packer)
{
    REQUIRE(U(BCryptQueryContextConfiguration));
    /* 0xFFFE characters + NUL fit inside the 0xFFFF character window, so the user-mode packer accepts it;
     * the store then simply has no such context. Exact "not found" code is recorded, not required. */
    WCHAR *s = cr_longstr(0xFFFE, L'C'); REQUIRE(s);
    ULONG cb = 0; PCRYPT_CONTEXT_CONFIG p = NULL;
    NTSTATUS st = U(BCryptQueryContextConfiguration)(CR_TABLE_LOCAL, s, &cb, &p);
    CHECKF(st != CRS_OK, "unexpected success for a 65534-character context name");
    CHECKF(st != CRS_INVALID_PARAMETER, "0xFFFE characters must not be rejected as a parameter error (got 0x%lx)", (ULONG)st);
    t_note("QueryContextConfiguration(65534-char name) -> 0x%08lx", (ULONG)st);
    cr_free(p);
    HeapFree(GetProcessHeap(), 0, s);
}

/* ---------------------------------------------------------------- BCryptEnumContextFunctions */
TEST(crpar_enumfuncs_bad_table)
{
    REQUIRE(U(BCryptEnumContextFunctions));
    for (size_t i = 0; i < CR_N_BAD_TABLES; i++) {
        ULONG cb = 0x31; PCRYPT_CONTEXT_FUNCTIONS p = NULL;
        NTSTATUS st = U(BCryptEnumContextFunctions)(cr_bad_tables[i], L"Default", CRI_HASH, &cb, &p);
        CHECKF(st == CRS_INVALID_PARAMETER, "table 0x%lx: got 0x%lx", cr_bad_tables[i], (ULONG)st);
        EXPECT_EQ(cb, 0x31);
        EXPECT_EQ(p, NULL);
    }
}
TEST(crpar_enumfuncs_bad_interface)
{
    REQUIRE(U(BCryptEnumContextFunctions));
    for (size_t i = 0; i < CR_N_BAD_IFACES_NZ; i++) {
        ULONG cb = 0x31; PCRYPT_CONTEXT_FUNCTIONS p = NULL;
        NTSTATUS st = U(BCryptEnumContextFunctions)(CR_TABLE_LOCAL, L"Default", cr_bad_ifaces_nz[i], &cb, &p);
        CHECKF(st == CRS_INVALID_PARAMETER, "interface 0x%lx: got 0x%lx", cr_bad_ifaces_nz[i], (ULONG)st);
        EXPECT_EQ(p, NULL);
        EXPECT_EQ(cb, 0x31);
    }
}
TEST(crpar_enumfuncs_interface_zero_rejected)
{
    REQUIRE(U(BCryptEnumContextFunctions));
    /* Unlike ResolveProviders / QueryProviderRegistration, interface 0 ("any") is not accepted here. */
    ULONG cb = 0; PCRYPT_CONTEXT_FUNCTIONS p = NULL;
    EXPECT_EQ(U(BCryptEnumContextFunctions)(CR_TABLE_LOCAL, L"Default", 0, &cb, &p), CRS_INVALID_PARAMETER);
    EXPECT_EQ(U(BCryptEnumContextFunctions)(CR_TABLE_DOMAIN, L"Default", 0, &cb, &p), CRS_INVALID_PARAMETER);
    EXPECT_EQ(U(BCryptEnumContextFunctions)(CR_TABLE_LOCAL, L"Default", 0, &cb, NULL), CRS_INVALID_PARAMETER);
}
TEST(crpar_enumfuncs_null_size_pointer)
{
    REQUIRE(U(BCryptEnumContextFunctions));
    PCRYPT_CONTEXT_FUNCTIONS p = NULL;
    EXPECT_EQ(U(BCryptEnumContextFunctions)(CR_TABLE_LOCAL, L"Default", CRI_HASH, NULL, &p), CRS_INVALID_PARAMETER);
    EXPECT_EQ(U(BCryptEnumContextFunctions)(CR_TABLE_LOCAL, L"Default", CRI_HASH, NULL, NULL), CRS_INVALID_PARAMETER);
    EXPECT_EQ(p, NULL);
}
TEST(crpar_enumfuncs_bad_table_and_interface_null_ptr)
{
    REQUIRE(U(BCryptEnumContextFunctions));
    ULONG cb = 0;
    EXPECT_EQ(U(BCryptEnumContextFunctions)(0, L"Default", 0, &cb, NULL), CRS_INVALID_PARAMETER);
    EXPECT_EQ(U(BCryptEnumContextFunctions)(9, NULL, 0xFFFFFFFF, &cb, NULL), CRS_INVALID_PARAMETER);
    EXPECT_EQ(U(BCryptEnumContextFunctions)(9, NULL, 0xFFFFFFFF, NULL, NULL), CRS_INVALID_PARAMETER);
}
TEST(crpar_enumfuncs_param_error_keeps_caller_pointer)
{
    REQUIRE(U(BCryptEnumContextFunctions));
    ULONG cb = 8; PCRYPT_CONTEXT_FUNCTIONS p = (PCRYPT_CONTEXT_FUNCTIONS)cr_sentinel_block;
    EXPECT_EQ(U(BCryptEnumContextFunctions)(CR_TABLE_LOCAL, L"Default", 0x10005, &cb, &p), CRS_INVALID_PARAMETER);
    EXPECT_EQ(p, cr_sentinel_block);
    EXPECT_EQ(cb, 8);
}
TEST(crpar_enumfuncs_overlong_context_name)
{
    REQUIRE(U(BCryptEnumContextFunctions));
    WCHAR *s = cr_longstr(0xFFFF, L'D'); REQUIRE(s);
    ULONG cb = 0; PCRYPT_CONTEXT_FUNCTIONS p = NULL;
    EXPECT_EQ(U(BCryptEnumContextFunctions)(CR_TABLE_LOCAL, s, CRI_HASH, &cb, &p), CRS_BUFFER_TOO_SMALL);
    EXPECT_EQ(p, NULL);
    EXPECT_EQ(U(BCryptEnumContextFunctions)(CR_TABLE_LOCAL, s, CRI_HASH, &cb, NULL), CRS_OK);
    HeapFree(GetProcessHeap(), 0, s);
}

/* ---------------------------------------------------------------- BCryptEnumContextFunctionProviders */
TEST(crpar_enumfuncprov_bad_table)
{
    REQUIRE(U(BCryptEnumContextFunctionProviders));
    for (size_t i = 0; i < CR_N_BAD_TABLES; i++) {
        ULONG cb = 0x41; PCRYPT_CONTEXT_FUNCTION_PROVIDERS p = NULL;
        NTSTATUS st = U(BCryptEnumContextFunctionProviders)(cr_bad_tables[i], L"Default", CRI_HASH, L"SHA256", &cb, &p);
        CHECKF(st == CRS_INVALID_PARAMETER, "table 0x%lx: got 0x%lx", cr_bad_tables[i], (ULONG)st);
        EXPECT_EQ(cb, 0x41);
        EXPECT_EQ(p, NULL);
    }
}
TEST(crpar_enumfuncprov_bad_interface)
{
    REQUIRE(U(BCryptEnumContextFunctionProviders));
    ULONG bad0[] = { 0 };
    for (size_t i = 0; i < CR_N_BAD_IFACES_NZ + 1; i++) {
        ULONG iface = i == 0 ? bad0[0] : cr_bad_ifaces_nz[i - 1];
        ULONG cb = 0x41; PCRYPT_CONTEXT_FUNCTION_PROVIDERS p = NULL;
        NTSTATUS st = U(BCryptEnumContextFunctionProviders)(CR_TABLE_LOCAL, L"Default", iface, L"SHA256", &cb, &p);
        CHECKF(st == CRS_INVALID_PARAMETER, "interface 0x%lx: got 0x%lx", iface, (ULONG)st);
        EXPECT_EQ(p, NULL);
    }
}
TEST(crpar_enumfuncprov_function_name_required)
{
    REQUIRE(U(BCryptEnumContextFunctionProviders));
    ULONG cb = 0x41; PCRYPT_CONTEXT_FUNCTION_PROVIDERS p = NULL;
    EXPECT_EQ(U(BCryptEnumContextFunctionProviders)(CR_TABLE_LOCAL, L"Default", CRI_HASH, NULL, &cb, &p), CRS_INVALID_PARAMETER);
    EXPECT_EQ(U(BCryptEnumContextFunctionProviders)(CR_TABLE_LOCAL, L"Default", CRI_HASH, L"", &cb, &p), CRS_INVALID_PARAMETER);
    EXPECT_EQ(U(BCryptEnumContextFunctionProviders)(CR_TABLE_LOCAL, L"Default", CRI_HASH, NULL, &cb, NULL), CRS_INVALID_PARAMETER);
    EXPECT_EQ(U(BCryptEnumContextFunctionProviders)(CR_TABLE_LOCAL, L"Default", CRI_HASH, L"", &cb, NULL), CRS_INVALID_PARAMETER);
    EXPECT_EQ(p, NULL);
    EXPECT_EQ(cb, 0x41);
}
TEST(crpar_enumfuncprov_null_size_pointer)
{
    REQUIRE(U(BCryptEnumContextFunctionProviders));
    PCRYPT_CONTEXT_FUNCTION_PROVIDERS p = NULL;
    EXPECT_EQ(U(BCryptEnumContextFunctionProviders)(CR_TABLE_LOCAL, L"Default", CRI_HASH, L"SHA256", NULL, &p), CRS_INVALID_PARAMETER);
    EXPECT_EQ(U(BCryptEnumContextFunctionProviders)(CR_TABLE_LOCAL, L"Default", CRI_HASH, L"SHA256", NULL, NULL), CRS_INVALID_PARAMETER);
    EXPECT_EQ(p, NULL);
}
TEST(crpar_enumfuncprov_param_error_keeps_caller_pointer)
{
    REQUIRE(U(BCryptEnumContextFunctionProviders));
    ULONG cb = 3; PCRYPT_CONTEXT_FUNCTION_PROVIDERS p = (PCRYPT_CONTEXT_FUNCTION_PROVIDERS)cr_sentinel_block;
    EXPECT_EQ(U(BCryptEnumContextFunctionProviders)(5, L"Default", CRI_HASH, L"SHA256", &cb, &p), CRS_INVALID_PARAMETER);
    EXPECT_EQ(p, cr_sentinel_block);
    EXPECT_EQ(cb, 3);
}
TEST(crpar_enumfuncprov_overlong_function_name)
{
    REQUIRE(U(BCryptEnumContextFunctionProviders));
    WCHAR *s = cr_longstr(0xFFFF, L'E'); REQUIRE(s);
    ULONG cb = 0; PCRYPT_CONTEXT_FUNCTION_PROVIDERS p = NULL;
    EXPECT_EQ(U(BCryptEnumContextFunctionProviders)(CR_TABLE_LOCAL, L"Default", CRI_HASH, s, &cb, &p), CRS_BUFFER_TOO_SMALL);
    EXPECT_EQ(p, NULL);
    EXPECT_EQ(U(BCryptEnumContextFunctionProviders)(CR_TABLE_LOCAL, L"Default", CRI_HASH, s, &cb, NULL), CRS_OK);
    HeapFree(GetProcessHeap(), 0, s);
}

/* ---------------------------------------------------------------- BCryptQueryContextFunctionConfiguration */
TEST(crpar_queryfunccfg_bad_table)
{
    REQUIRE(U(BCryptQueryContextFunctionConfiguration));
    for (size_t i = 0; i < CR_N_BAD_TABLES; i++) {
        ULONG cb = 0x51; PCRYPT_CONTEXT_FUNCTION_CONFIG p = NULL;
        NTSTATUS st = U(BCryptQueryContextFunctionConfiguration)(cr_bad_tables[i], L"Default", CRI_HASH, L"SHA256", &cb, &p);
        CHECKF(st == CRS_INVALID_PARAMETER, "table 0x%lx: got 0x%lx", cr_bad_tables[i], (ULONG)st);
        EXPECT_EQ(cb, 0x51);
        EXPECT_EQ(p, NULL);
    }
}
TEST(crpar_queryfunccfg_bad_interface)
{
    REQUIRE(U(BCryptQueryContextFunctionConfiguration));
    for (size_t i = 0; i < CR_N_BAD_IFACES_NZ + 1; i++) {
        ULONG iface = i == 0 ? 0 : cr_bad_ifaces_nz[i - 1];
        ULONG cb = 0x51; PCRYPT_CONTEXT_FUNCTION_CONFIG p = NULL;
        NTSTATUS st = U(BCryptQueryContextFunctionConfiguration)(CR_TABLE_LOCAL, L"Default", iface, L"SHA256", &cb, &p);
        CHECKF(st == CRS_INVALID_PARAMETER, "interface 0x%lx: got 0x%lx", iface, (ULONG)st);
        EXPECT_EQ(p, NULL);
    }
}
TEST(crpar_queryfunccfg_function_name_required)
{
    REQUIRE(U(BCryptQueryContextFunctionConfiguration));
    ULONG cb = 0x51; PCRYPT_CONTEXT_FUNCTION_CONFIG p = NULL;
    EXPECT_EQ(U(BCryptQueryContextFunctionConfiguration)(CR_TABLE_LOCAL, L"Default", CRI_HASH, NULL, &cb, &p), CRS_INVALID_PARAMETER);
    EXPECT_EQ(U(BCryptQueryContextFunctionConfiguration)(CR_TABLE_LOCAL, L"Default", CRI_HASH, L"", &cb, &p), CRS_INVALID_PARAMETER);
    EXPECT_EQ(U(BCryptQueryContextFunctionConfiguration)(CR_TABLE_LOCAL, L"Default", CRI_HASH, L"", &cb, NULL), CRS_INVALID_PARAMETER);
    EXPECT_EQ(cb, 0x51);
    EXPECT_EQ(p, NULL);
}
TEST(crpar_queryfunccfg_null_size_pointer)
{
    REQUIRE(U(BCryptQueryContextFunctionConfiguration));
    PCRYPT_CONTEXT_FUNCTION_CONFIG p = NULL;
    EXPECT_EQ(U(BCryptQueryContextFunctionConfiguration)(CR_TABLE_LOCAL, L"Default", CRI_HASH, L"SHA256", NULL, &p), CRS_INVALID_PARAMETER);
    EXPECT_EQ(U(BCryptQueryContextFunctionConfiguration)(CR_TABLE_LOCAL, L"Default", CRI_HASH, L"SHA256", NULL, NULL), CRS_INVALID_PARAMETER);
    EXPECT_EQ(p, NULL);
}
TEST(crpar_queryfunccfg_param_error_keeps_caller_pointer)
{
    REQUIRE(U(BCryptQueryContextFunctionConfiguration));
    ULONG cb = 3; PCRYPT_CONTEXT_FUNCTION_CONFIG p = (PCRYPT_CONTEXT_FUNCTION_CONFIG)cr_sentinel_block;
    EXPECT_EQ(U(BCryptQueryContextFunctionConfiguration)(CR_TABLE_LOCAL, L"Default", 99, L"SHA256", &cb, &p), CRS_INVALID_PARAMETER);
    EXPECT_EQ(p, cr_sentinel_block);
    EXPECT_EQ(cb, 3);
}
TEST(crpar_queryfunccfg_overlong_names)
{
    REQUIRE(U(BCryptQueryContextFunctionConfiguration));
    WCHAR *s = cr_longstr(0xFFFF, L'F'); REQUIRE(s);
    ULONG cb = 0; PCRYPT_CONTEXT_FUNCTION_CONFIG p = NULL;
    EXPECT_EQ(U(BCryptQueryContextFunctionConfiguration)(CR_TABLE_LOCAL, L"Default", CRI_HASH, s, &cb, &p), CRS_BUFFER_TOO_SMALL);
    EXPECT_EQ(U(BCryptQueryContextFunctionConfiguration)(CR_TABLE_LOCAL, s, CRI_HASH, L"SHA256", &cb, &p), CRS_BUFFER_TOO_SMALL);
    EXPECT_EQ(p, NULL);
    EXPECT_EQ(U(BCryptQueryContextFunctionConfiguration)(CR_TABLE_LOCAL, L"Default", CRI_HASH, s, &cb, NULL), CRS_OK);
    HeapFree(GetProcessHeap(), 0, s);
}

/* ---------------------------------------------------------------- BCryptQueryContextFunctionProperty */
TEST(crpar_queryfuncprop_bad_table)
{
    REQUIRE(U(BCryptQueryContextFunctionProperty));
    for (size_t i = 0; i < CR_N_BAD_TABLES; i++) {
        ULONG cb = 0x61; PUCHAR p = NULL;
        NTSTATUS st = U(BCryptQueryContextFunctionProperty)(cr_bad_tables[i], L"Default", CRI_HASH, L"SHA256", L"Prop", &cb, &p);
        CHECKF(st == CRS_INVALID_PARAMETER, "table 0x%lx: got 0x%lx", cr_bad_tables[i], (ULONG)st);
        EXPECT_EQ(cb, 0x61);
        EXPECT_EQ(p, NULL);
    }
}
TEST(crpar_queryfuncprop_bad_interface)
{
    REQUIRE(U(BCryptQueryContextFunctionProperty));
    for (size_t i = 0; i < CR_N_BAD_IFACES_NZ + 1; i++) {
        ULONG iface = i == 0 ? 0 : cr_bad_ifaces_nz[i - 1];
        ULONG cb = 0x61; PUCHAR p = NULL;
        NTSTATUS st = U(BCryptQueryContextFunctionProperty)(CR_TABLE_LOCAL, L"Default", iface, L"SHA256", L"Prop", &cb, &p);
        CHECKF(st == CRS_INVALID_PARAMETER, "interface 0x%lx: got 0x%lx", iface, (ULONG)st);
        EXPECT_EQ(p, NULL);
    }
}
TEST(crpar_queryfuncprop_function_and_property_required)
{
    REQUIRE(U(BCryptQueryContextFunctionProperty));
    ULONG cb = 0x61; PUCHAR p = NULL;
    EXPECT_EQ(U(BCryptQueryContextFunctionProperty)(CR_TABLE_LOCAL, L"Default", CRI_HASH, NULL, L"Prop", &cb, &p), CRS_INVALID_PARAMETER);
    EXPECT_EQ(U(BCryptQueryContextFunctionProperty)(CR_TABLE_LOCAL, L"Default", CRI_HASH, L"", L"Prop", &cb, &p), CRS_INVALID_PARAMETER);
    EXPECT_EQ(U(BCryptQueryContextFunctionProperty)(CR_TABLE_LOCAL, L"Default", CRI_HASH, L"SHA256", NULL, &cb, &p), CRS_INVALID_PARAMETER);
    EXPECT_EQ(U(BCryptQueryContextFunctionProperty)(CR_TABLE_LOCAL, L"Default", CRI_HASH, L"SHA256", L"", &cb, &p), CRS_INVALID_PARAMETER);
    EXPECT_EQ(U(BCryptQueryContextFunctionProperty)(CR_TABLE_LOCAL, L"Default", CRI_HASH, L"SHA256", L"", &cb, NULL), CRS_INVALID_PARAMETER);
    EXPECT_EQ(U(BCryptQueryContextFunctionProperty)(CR_TABLE_LOCAL, L"Default", CRI_HASH, NULL, NULL, &cb, NULL), CRS_INVALID_PARAMETER);
    EXPECT_EQ(cb, 0x61);
    EXPECT_EQ(p, NULL);
}
TEST(crpar_queryfuncprop_null_size_pointer)
{
    REQUIRE(U(BCryptQueryContextFunctionProperty));
    PUCHAR p = NULL;
    EXPECT_EQ(U(BCryptQueryContextFunctionProperty)(CR_TABLE_LOCAL, L"Default", CRI_HASH, L"SHA256", L"Prop", NULL, &p), CRS_INVALID_PARAMETER);
    EXPECT_EQ(U(BCryptQueryContextFunctionProperty)(CR_TABLE_LOCAL, L"Default", CRI_HASH, L"SHA256", L"Prop", NULL, NULL), CRS_INVALID_PARAMETER);
    EXPECT_EQ(p, NULL);
}
TEST(crpar_queryfuncprop_param_error_keeps_caller_pointer)
{
    REQUIRE(U(BCryptQueryContextFunctionProperty));
    ULONG cb = 3; PUCHAR p = cr_sentinel_block;
    EXPECT_EQ(U(BCryptQueryContextFunctionProperty)(0, L"Default", CRI_HASH, L"SHA256", L"Prop", &cb, &p), CRS_INVALID_PARAMETER);
    EXPECT_EQ(p, cr_sentinel_block);
    EXPECT_EQ(cb, 3);
}
TEST(crpar_queryfuncprop_overlong_names)
{
    REQUIRE(U(BCryptQueryContextFunctionProperty));
    /* This entry point's status mapper has no case for ERROR_INSUFFICIENT_BUFFER (0x7A), unlike its siblings, so the exact
     * status of an over-long name is recorded rather than required; it must be a failure and must not look like success. */
    WCHAR *s = cr_longstr(0xFFFF, L'G'); REQUIRE(s);
    ULONG cb = 0; PUCHAR p = NULL;
    NTSTATUS st[3];
    st[0] = U(BCryptQueryContextFunctionProperty)(CR_TABLE_LOCAL, L"Default", CRI_HASH, L"SHA256", s, &cb, &p);
    st[1] = U(BCryptQueryContextFunctionProperty)(CR_TABLE_LOCAL, L"Default", CRI_HASH, s, L"Prop", &cb, &p);
    st[2] = U(BCryptQueryContextFunctionProperty)(CR_TABLE_LOCAL, s, CRI_HASH, L"SHA256", L"Prop", &cb, &p);
    for (int i = 0; i < 3; i++) {
        CHECKF(st[i] < 0, "variant %d returned 0x%lx", i, (ULONG)st[i]);
        t_note("QueryContextFunctionProperty overlong name variant %d -> 0x%08lx", i, (ULONG)st[i]);
    }
    EXPECT_EQ(p, NULL);
    HeapFree(GetProcessHeap(), 0, s);
}

/* ---------------------------------------------------------------- BCryptQueryProviderRegistration */
TEST(crpar_queryreg_provider_name_required)
{
    REQUIRE(U(BCryptQueryProviderRegistration));
    ULONG cb = 0x71; PCRYPT_PROVIDER_REG p = NULL;
    EXPECT_EQ(U(BCryptQueryProviderRegistration)(NULL, CRYPT_UM, CRI_HASH, &cb, &p), CRS_INVALID_PARAMETER);
    EXPECT_EQ(U(BCryptQueryProviderRegistration)(L"", CRYPT_UM, CRI_HASH, &cb, &p), CRS_INVALID_PARAMETER);
    EXPECT_EQ(U(BCryptQueryProviderRegistration)(NULL, CRYPT_UM, CRI_HASH, &cb, NULL), CRS_INVALID_PARAMETER);
    EXPECT_EQ(U(BCryptQueryProviderRegistration)(L"", CRYPT_ANY, 0, &cb, NULL), CRS_INVALID_PARAMETER);
    EXPECT_EQ(cb, 0x71);
    EXPECT_EQ(p, NULL);
}
TEST(crpar_queryreg_bad_mode)
{
    REQUIRE(U(BCryptQueryProviderRegistration));
    static const ULONG bad[] = { 0, 5, 6, 7, 8, 0x10, 0x100, 0x80000000u, 0xFFFFFFFEu, 0xFFFFFFFFu };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        ULONG cb = 0x71; PCRYPT_PROVIDER_REG p = NULL;
        NTSTATUS st = U(BCryptQueryProviderRegistration)(CR_PROVIDER_PRIM, bad[i], CRI_HASH, &cb, &p);
        CHECKF(st == CRS_INVALID_PARAMETER, "mode 0x%lx: got 0x%lx", bad[i], (ULONG)st);
        EXPECT_EQ(cb, 0x71);
        EXPECT_EQ(p, NULL);
    }
}
TEST(crpar_queryreg_bad_interface)
{
    REQUIRE(U(BCryptQueryProviderRegistration));
    for (size_t i = 0; i < CR_N_BAD_IFACES_NZ; i++) {
        ULONG cb = 0x71; PCRYPT_PROVIDER_REG p = NULL;
        NTSTATUS st = U(BCryptQueryProviderRegistration)(CR_PROVIDER_PRIM, CRYPT_UM, cr_bad_ifaces_nz[i], &cb, &p);
        CHECKF(st == CRS_INVALID_PARAMETER, "interface 0x%lx: got 0x%lx", cr_bad_ifaces_nz[i], (ULONG)st);
        EXPECT_EQ(p, NULL);
    }
}
TEST(crpar_queryreg_null_size_pointer)
{
    REQUIRE(U(BCryptQueryProviderRegistration));
    PCRYPT_PROVIDER_REG p = NULL;
    EXPECT_EQ(U(BCryptQueryProviderRegistration)(CR_PROVIDER_PRIM, CRYPT_UM, CRI_HASH, NULL, &p), CRS_INVALID_PARAMETER);
    EXPECT_EQ(U(BCryptQueryProviderRegistration)(CR_PROVIDER_PRIM, CRYPT_UM, CRI_HASH, NULL, NULL), CRS_INVALID_PARAMETER);
    EXPECT_EQ(p, NULL);
}
TEST(crpar_queryreg_param_error_keeps_caller_pointer)
{
    REQUIRE(U(BCryptQueryProviderRegistration));
    ULONG cb = 4; PCRYPT_PROVIDER_REG p = (PCRYPT_PROVIDER_REG)cr_sentinel_block;
    EXPECT_EQ(U(BCryptQueryProviderRegistration)(CR_PROVIDER_PRIM, 0, CRI_HASH, &cb, &p), CRS_INVALID_PARAMETER);
    EXPECT_EQ(p, cr_sentinel_block);
    EXPECT_EQ(cb, 4);
}
TEST(crpar_queryreg_overlong_provider_name)
{
    REQUIRE(U(BCryptQueryProviderRegistration));
    WCHAR *s = cr_longstr(0xFFFF, L'I'); REQUIRE(s);
    ULONG cb = 0; PCRYPT_PROVIDER_REG p = NULL;
    EXPECT_EQ(U(BCryptQueryProviderRegistration)(s, CRYPT_UM, CRI_HASH, &cb, &p), CRS_BUFFER_TOO_SMALL);
    EXPECT_EQ(p, NULL);
    EXPECT_EQ(U(BCryptQueryProviderRegistration)(s, CRYPT_UM, CRI_HASH, &cb, NULL), CRS_OK);
    HeapFree(GetProcessHeap(), 0, s);
}

/* ---------------------------------------------------------------- BCryptResolveProviders */
TEST(crpar_resolve_bad_mode)
{
    REQUIRE(U(BCryptResolveProviders));
    /* CRYPT_ANY (4) is not a resolution mode; 0 is not either. */
    static const ULONG bad[] = { 0, 4, 5, 6, 7, 8, 0x10, 0x100, 0x80000000u, 0xFFFFFFFEu, 0xFFFFFFFFu };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        ULONG cb = 0x81; PCRYPT_PROVIDER_REFS p = NULL;
        NTSTATUS st = U(BCryptResolveProviders)(NULL, CRI_HASH, L"SHA256", NULL, bad[i], 0, &cb, &p);
        CHECKF(st == CRS_INVALID_PARAMETER, "mode 0x%lx: got 0x%lx", bad[i], (ULONG)st);
        EXPECT_EQ(cb, 0x81);
        EXPECT_EQ(p, NULL);
    }
}
TEST(crpar_resolve_bad_interface)
{
    REQUIRE(U(BCryptResolveProviders));
    for (size_t i = 0; i < CR_N_BAD_IFACES_NZ; i++) {
        ULONG cb = 0x81; PCRYPT_PROVIDER_REFS p = NULL;
        NTSTATUS st = U(BCryptResolveProviders)(NULL, cr_bad_ifaces_nz[i], L"SHA256", NULL, CRYPT_UM, 0, &cb, &p);
        CHECKF(st == CRS_INVALID_PARAMETER, "interface 0x%lx: got 0x%lx", cr_bad_ifaces_nz[i], (ULONG)st);
        EXPECT_EQ(p, NULL);
    }
}
TEST(crpar_resolve_bad_flags)
{
    REQUIRE(U(BCryptResolveProviders));
    /* Only CRYPT_ALL_FUNCTIONS (1) and CRYPT_ALL_PROVIDERS (2) are defined; any other bit is ERROR_INVALID_FLAGS -> STATUS_INVALID_PARAMETER. */
    static const ULONG bad[] = { 4, 8, 0x10, 0x100, 0x10000, 0x80000000u, 0xFFFFFFFCu, 0xFFFFFFFFu, 5, 7 };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        ULONG cb = 0x81; PCRYPT_PROVIDER_REFS p = NULL;
        NTSTATUS st = U(BCryptResolveProviders)(NULL, CRI_HASH, L"SHA256", NULL, CRYPT_UM, bad[i], &cb, &p);
        CHECKF(st == CRS_INVALID_PARAMETER, "flags 0x%lx: got 0x%lx", bad[i], (ULONG)st);
        EXPECT_EQ(p, NULL);
        EXPECT_EQ(cb, 0x81);
        st = U(BCryptResolveProviders)(NULL, CRI_HASH, L"SHA256", NULL, CRYPT_UM, bad[i], &cb, NULL);
        CHECKF(st == CRS_INVALID_PARAMETER, "flags 0x%lx (size query): got 0x%lx", bad[i], (ULONG)st);
    }
}
TEST(crpar_resolve_null_size_pointer)
{
    REQUIRE(U(BCryptResolveProviders));
    PCRYPT_PROVIDER_REFS p = NULL;
    EXPECT_EQ(U(BCryptResolveProviders)(NULL, CRI_HASH, L"SHA256", NULL, CRYPT_UM, 0, NULL, &p), CRS_INVALID_PARAMETER);
    EXPECT_EQ(U(BCryptResolveProviders)(NULL, CRI_HASH, L"SHA256", NULL, CRYPT_UM, 0, NULL, NULL), CRS_INVALID_PARAMETER);
    EXPECT_EQ(p, NULL);
}
TEST(crpar_resolve_param_error_keeps_caller_pointer)
{
    REQUIRE(U(BCryptResolveProviders));
    ULONG cb = 4; PCRYPT_PROVIDER_REFS p = (PCRYPT_PROVIDER_REFS)cr_sentinel_block;
    EXPECT_EQ(U(BCryptResolveProviders)(NULL, CRI_HASH, L"SHA256", NULL, 0, 0, &cb, &p), CRS_INVALID_PARAMETER);
    EXPECT_EQ(p, cr_sentinel_block);
    EXPECT_EQ(U(BCryptResolveProviders)(NULL, 99, L"SHA256", NULL, CRYPT_UM, 0, &cb, &p), CRS_INVALID_PARAMETER);
    EXPECT_EQ(p, cr_sentinel_block);
    EXPECT_EQ(U(BCryptResolveProviders)(NULL, CRI_HASH, L"SHA256", NULL, CRYPT_UM, 4, &cb, &p), CRS_INVALID_PARAMETER);
    EXPECT_EQ(p, cr_sentinel_block);
    EXPECT_EQ(cb, 4);
}
TEST(crpar_resolve_overlong_names)
{
    REQUIRE(U(BCryptResolveProviders));
    WCHAR *s = cr_longstr(0xFFFF, L'J'); REQUIRE(s);
    ULONG cb = 0; PCRYPT_PROVIDER_REFS p = NULL;
    EXPECT_EQ(U(BCryptResolveProviders)(s, CRI_HASH, L"SHA256", NULL, CRYPT_UM, 0, &cb, &p), CRS_BUFFER_TOO_SMALL);
    EXPECT_EQ(U(BCryptResolveProviders)(NULL, CRI_HASH, s, NULL, CRYPT_UM, 0, &cb, &p), CRS_BUFFER_TOO_SMALL);
    EXPECT_EQ(U(BCryptResolveProviders)(NULL, CRI_HASH, L"SHA256", s, CRYPT_UM, 0, &cb, &p), CRS_BUFFER_TOO_SMALL);
    EXPECT_EQ(p, NULL);
    EXPECT_EQ(U(BCryptResolveProviders)(s, CRI_HASH, L"SHA256", NULL, CRYPT_UM, 0, &cb, NULL), CRS_OK);
    HeapFree(GetProcessHeap(), 0, s);
}

/* ---------------------------------------------------------------- BCryptFreeBuffer */
TEST(crpar_freebuffer_null_is_noop)
{
    REQUIRE(U(BCryptFreeBuffer));
    U(BCryptFreeBuffer)(NULL);
    U(BCryptFreeBuffer)(NULL);
    CHECK(1);
}
TEST(crpar_freebuffer_accepts_block_from_enum)
{
    REQUIRE(U(BCryptFreeBuffer)); REQUIRE(U(BCryptEnumContexts));
    cr_blk b = cr_enum_contexts(CR_TABLE_LOCAL);
    EXPECT_EQ(b.st, CRS_OK);
    CHECK(b.p != NULL);
    /* The block is a single process-heap allocation: HeapValidate on it must succeed before it is freed. */
    if (b.p) CHECK(HeapValidate(GetProcessHeap(), 0, b.p));
    cr_free(b.p);
}
