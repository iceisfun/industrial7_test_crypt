/* Zero-argument contract probes: every argument register is 0.  Observed on Win10 22H2, the same in std and adm.
 * ZT: the call returns normally; low 32 bits of the return value and the last error (cleared first) are pinned.
 * ZF: the call dereferences a NULL argument and faults (Win10 does not validate these pointers). */
#ifndef ZC_H
#define ZC_H
#include "t.h"
typedef ULONG_PTR (WINAPI *zc_fn)(ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR);
static zc_fn zc_get(const char *dll, const char *name) {
    zc_fn f = (zc_fn)t_proc_in(dll, name);
    t_check(f != NULL, __FILE__, __LINE__, "export present", "%s!%s", dll, name);
    return f;
}
#define ZT(fn, dll, want_ret, want_err) TEST(zc_##fn) { if (t_is_wine()) { t_skip("ncrypt Ssl* exports are aborting stubs under the emulator"); return; } zc_fn f = zc_get(dll, #fn); DWORD ge = 0; volatile ULONG_PTR r = 0; \
    if (!f) { return; } T_TRY( r = T_CALL_ERR(&ge, f(0,0,0,0,0,0,0,0)) ); \
    EXPECT_EQ((DWORD)r, (DWORD)(want_ret)); EXPECT_EQ(ge, (DWORD)(want_err)); }
#define ZF(fn, dll) TEST(zf_##fn) { if (t_is_wine()) { t_skip("ncrypt Ssl* exports are aborting stubs under the emulator"); return; } zc_fn f = zc_get(dll, #fn); if (!f) return; T_EXPECT_FAULT( f(0,0,0,0,0,0,0,0) ); }
#endif
