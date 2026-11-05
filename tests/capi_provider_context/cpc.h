#ifndef CPC_H
#define CPC_H
#include "t.h"
#include <wincrypt.h>

/* SECURITY_STATUS / NTE codes spelled out so the tests do not depend on header coverage. */
#define X_NTE_BAD_UID            0x80090001UL
#define X_NTE_BAD_KEY            0x80090003UL
#define X_NTE_BAD_ALGID          0x80090008UL
#define X_NTE_BAD_FLAGS          0x80090009UL
#define X_NTE_BAD_TYPE           0x8009000AUL
#define X_NTE_NO_KEY             0x8009000DUL
#define X_NTE_BAD_PROV_TYPE      0x80090014UL
#define X_NTE_KEYSET_NOT_DEF     0x80090019UL
#define X_NTE_PROV_TYPE_NOT_DEF  0x80090017UL
#define X_NTE_PROV_TYPE_ENTRY_BAD 0x8009001AUL
#define X_NTE_PROV_TYPE_NO_MATCH 0x8009001BUL
#define X_NTE_FAIL               0x80090020UL
#define X_VERIFY CRYPT_VERIFYCONTEXT

typedef struct {
    const char *a;      /* provider name, ANSI */
    const WCHAR *w;     /* provider name, wide */
    DWORD type;
    int dss;            /* dssenh instead of rsaenh */
    DWORD version;      /* PP_VERSION */
    DWORD inc;          /* PP_SIG/KEYX_KEYSIZE_INC */
    DWORD keyspec;      /* PP_KEYSPEC */
    const ALG_ID *req;  /* algorithms that must be enumerable */
    int nreq;
} cpc_prov;

extern const cpc_prov cpc_provs[];
extern const int cpc_nprovs;   /* 10 */

/* thin wrappers: everything resolved with GetProcAddress at call time */
BOOL cpc_acq(HCRYPTPROV *h, const char *prov, DWORD type, DWORD flags);
BOOL cpc_acq_c(HCRYPTPROV *h, const char *cont, const char *prov, DWORD type, DWORD flags);
BOOL cpc_gpp(HCRYPTPROV h, DWORD p, void *buf, DWORD *n, DWORD fl);
BOOL cpc_gpp_dw(HCRYPTPROV h, DWORD p, DWORD *v);   /* succeeds only if length came back as 4 */
void cpc_rel(HCRYPTPROV h);
/* enumerate PP_ENUMALGS; returns count (or -1 on protocol failure) */
int cpc_enum_algs(HCRYPTPROV h, PROV_ENUMALGS *out, int max);
int cpc_enum_algs_ex(HCRYPTPROV h, PROV_ENUMALGS_EX *out, int max);
#define CPC_SIG_IDX 4   /* Microsoft RSA Signature Cryptographic Provider (type 2) */
/* The type-2 signature provider has no registry entry on Windows 10 22H2; the per-provider
 * tests skip that row with a stated reason (cpc_sig_provider_absent pins the absence). */
int cpc_skip_absent(int i);
int cpc_prov_registered(const char *name);
#define PERPROV(tn, fn) \
    static void tn##_w(int i) { if (cpc_skip_absent(i)) return; fn(i); } \
    TEST(tn##_0) { tn##_w(0); } TEST(tn##_1) { tn##_w(1); } TEST(tn##_2) { tn##_w(2); } TEST(tn##_3) { tn##_w(3); } \
    TEST(tn##_4) { tn##_w(4); } TEST(tn##_5) { tn##_w(5); } TEST(tn##_6) { tn##_w(6); } TEST(tn##_7) { tn##_w(7); } \
    TEST(tn##_8) { tn##_w(8); } TEST(tn##_9) { tn##_w(9); }
#endif
