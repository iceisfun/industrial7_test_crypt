/* Shared helpers for the dx_bcrypt_context_config area (CNG configuration, state changing). */
#ifndef CFG_H
#define CFG_H
#include "t.h"
#include <bcrypt.h>

UDECL(NTSTATUS, BCryptRegisterProvider, (LPCWSTR, ULONG, PCRYPT_PROVIDER_REG));
UDECL(NTSTATUS, BCryptUnregisterProvider, (LPCWSTR));
UDECL(NTSTATUS, BCryptAddContextFunctionProvider, (ULONG, LPCWSTR, ULONG, LPCWSTR, LPCWSTR, ULONG));
UDECL(NTSTATUS, BCryptRemoveContextFunctionProvider, (ULONG, LPCWSTR, ULONG, LPCWSTR, LPCWSTR));

#define ST_EQ(a, b) EXPECT_EQ((ULONG)(a), (ULONG)(b))
#define ST_OK(a)    EXPECT_EQ((ULONG)(a), 0)
#define S_INVALID_PARAMETER 0xC000000DUL
#define S_ACCESS_DENIED     0xC0000022UL
#define S_NAME_COLLISION    0xC0000035UL
#define S_NOT_FOUND         0xC0000225UL
#define S_OBJECT_NAME_NOT_FOUND 0xC0000034UL
#define NT_OK(s) ((LONG)(s) >= 0)

#define NINTERFACES 7
extern const ULONG cfg_valid_ifaces[11];
extern const ULONG cfg_bad_ifaces[7];
extern const ULONG cfg_bad_tables[6];

int  cfg_is_elevated(void);
/* Returns 1 when the test may touch HKLM (elevated, not an emulator). Otherwise t_skip()s. Sweeps leftovers once. */
int  cfg_begin(void);
/* Unique name "cryptt_<tag>_<pid>_<n>"; also remembered for cleanup at exit. kind: 0 context, 1 provider */
void cfg_name(WCHAR *out, size_t cch, const char *tag, int kind);
void cfg_cleanup_all(void);
/* Enumerate: returns count or -1 on failure; names copied to out[i] (max 64 wchars). */
int  cfg_enum_ctx(ULONG table, WCHAR out[][96], int max, NTSTATUS *st);
int  cfg_enum_funcs(ULONG table, const WCHAR *ctx, ULONG iface, WCHAR out[][96], int max, NTSTATUS *st);
int  cfg_enum_fprov(ULONG table, const WCHAR *ctx, ULONG iface, const WCHAR *fn, WCHAR out[][96], int max, NTSTATUS *st);
int  cfg_enum_registered(WCHAR out[][96], int max, NTSTATUS *st);
int  cfg_has_ctx(ULONG table, const WCHAR *ctx);
int  cfg_has_provider(const WCHAR *name);
void cfg_sysdll(WCHAR *out, size_t cch, const WCHAR *leaf);
#endif
