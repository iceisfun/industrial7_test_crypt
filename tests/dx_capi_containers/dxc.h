#ifndef DXC_H
#define DXC_H
#include "t.h"
#include <wincrypt.h>

/* NTE_* / status codes spelled out so tests do not depend on header coverage. */
#define X_NTE_BAD_UID          0x80090001UL
#define X_NTE_BAD_KEY          0x80090003UL
#define X_NTE_BAD_FLAGS        0x80090009UL
#define X_NTE_BAD_TYPE         0x8009000AUL
#define X_NTE_BAD_KEY_STATE    0x8009000BUL
#define X_NTE_NO_KEY           0x8009000DUL
#define X_NTE_EXISTS           0x8009000FUL
#define X_NTE_BAD_KEYSET       0x80090016UL
#define X_NTE_BAD_PUBLIC_KEY   0x80090015UL
#define X_NTE_BAD_PROV_TYPE    0x80090014UL
#define X_NTE_PROV_TYPE_NOT_DEF 0x80090017UL
#define X_CRYPT_E_NO_KEY_PROPERTY 0x8009200BUL
#define X_NTE_KEYSET_NOT_DEF   0x80090019UL
#define X_NTE_PROV_TYPE_NO_MATCH 0x8009001BUL

/* Providers exercised by the per-provider tests. */
typedef struct { const char *a; DWORD type; int dss; } dxc_prov;
extern const dxc_prov dxc_provs[];
extern const int dxc_nprov;      /* 7 */

/* container name "cryptt_<pid>_<tag>" (rotating static buffers, ANSI / wide) */
const char *dxc_name(const char *tag);
const WCHAR *dxc_wname(const char *tag);

BOOL dxc_have(int pi);                                   /* provider usable via VERIFYCONTEXT */
BOOL dxc_acq(HCRYPTPROV *h, const char *cont, int pi, DWORD flags);   /* CryptAcquireContextA, resolved at call time */
void dxc_rel(HCRYPTPROV h);
/* delete container ignoring result (flag: 0 or CRYPT_MACHINE_KEYSET). Also sweeps leftovers on first use per provider. */
void dxc_del(const char *cont, int pi, DWORD machine);
void dxc_prepare(int pi, DWORD machine);                 /* sweep stale cryptt_ containers once + delete none */
BOOL dxc_exists(const char *cont, int pi, DWORD machine);/* open existing (no NEWKEYSET) succeeds */
BOOL dxc_gpp(HCRYPTPROV h, DWORD p, void *buf, DWORD *n, DWORD fl);
/* enumerate all containers into names[] (each up to 262 bytes); returns count or -1 */
int  dxc_enum(int pi, DWORD machine, char names[][264], int max);
int  dxc_enum_in(HCRYPTPROV h, char names[][264], int max);
BOOL dxc_is_admin(void);
/* key blob helper: export key with blobtype; returns length or -1; out must be >= cap */
int  dxc_export(HCRYPTKEY k, HCRYPTKEY expkey, DWORD blobtype, DWORD flags, BYTE *out, DWORD cap);
/* returns TRUE if machine keysets can be created here (admin); otherwise sets skip reason */
BOOL dxc_machine_ok(int pi);

/* skip boilerplate */
#define DXC_NEED(pi) do { if (!dxc_have(pi)) { t_skip("provider %s not available", dxc_provs[pi].a); return; } dxc_prepare(pi, 0); } while (0)

#define DXC_PERPROV(tn, fn) \
    TEST(tn##_0) { fn(0); } TEST(tn##_1) { fn(1); } TEST(tn##_2) { fn(2); } TEST(tn##_3) { fn(3); } \
    TEST(tn##_4) { fn(4); } TEST(tn##_5) { fn(5); } TEST(tn##_6) { fn(6); }
/* RSA providers only (0-3) */
#define DXC_PERRSA(tn, fn) \
    TEST(tn##_0) { fn(0); } TEST(tn##_1) { fn(1); } TEST(tn##_2) { fn(2); } TEST(tn##_3) { fn(3); }
#endif
