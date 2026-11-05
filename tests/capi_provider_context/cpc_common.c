#include "cpc.h"

#define A(...) (const ALG_ID[]){__VA_ARGS__}
#define R(...) A(__VA_ARGS__), (int)(sizeof(A(__VA_ARGS__)) / sizeof(ALG_ID))

const cpc_prov cpc_provs[] = {
    /* 0 */ { MS_DEF_PROV_A,            MS_DEF_PROV_W,            1,  0, 0x200, 8,    3,
              R(CALG_MD5, CALG_SHA1, CALG_RSA_SIGN, CALG_RSA_KEYX, CALG_RC2, CALG_RC4) },
    /* 1 */ { MS_ENHANCED_PROV_A,       MS_ENHANCED_PROV_W,       1,  0, 0x200, 8,    3,
              R(CALG_MD5, CALG_SHA1, CALG_RSA_SIGN, CALG_RSA_KEYX, CALG_RC2, CALG_RC4) },
    /* 2 */ { MS_STRONG_PROV_A,         MS_STRONG_PROV_W,         1,  0, 0x200, 8,    3,
              R(CALG_MD5, CALG_SHA1, CALG_RSA_SIGN, CALG_RSA_KEYX, CALG_RC2, CALG_RC4) },
    /* 3 */ { MS_ENH_RSA_AES_PROV_A,    MS_ENH_RSA_AES_PROV_W,    24, 0, 0x200, 8,    3,
              R(CALG_MD5, CALG_SHA1, CALG_RSA_SIGN, CALG_RSA_KEYX, CALG_RC2, CALG_RC4,
                CALG_AES_128, CALG_AES_192, CALG_AES_256, CALG_SHA_256, CALG_SHA_384, CALG_SHA_512) },
    /* 4 */ { MS_DEF_RSA_SIG_PROV_A,    MS_DEF_RSA_SIG_PROV_W,    2,  0, 0x200, 8,    2,
              R(CALG_MD5, CALG_SHA1, CALG_RSA_SIGN) },
    /* 5 */ { MS_DEF_RSA_SCHANNEL_PROV_A, MS_DEF_RSA_SCHANNEL_PROV_W, 12, 0, 0x200, 8, 1,
              R(CALG_MD5, CALG_SHA1, CALG_RSA_KEYX) },   /* no CALG_RSA_SIGN (0x2400) in the SChannel provider on Win10 */
    /* 6 */ { MS_DEF_DSS_PROV_A,        MS_DEF_DSS_PROV_W,        3,  1, 0x100, 0x40, 2,
              R(CALG_SHA1, CALG_DSS_SIGN) },
    /* 7 */ { MS_DEF_DSS_DH_PROV_A,     MS_DEF_DSS_DH_PROV_W,     13, 1, 0x100, 0x40, 3,
              R(CALG_SHA1, CALG_DSS_SIGN, CALG_DH_SF, CALG_DH_EPHEM) },
    /* 8 */ { MS_ENH_DSS_DH_PROV_A,     MS_ENH_DSS_DH_PROV_W,     13, 1, 0x100, 0x40, 3,
              R(CALG_SHA1, CALG_DSS_SIGN, CALG_DH_SF, CALG_DH_EPHEM) },
    /* 9 */ { MS_DEF_DH_SCHANNEL_PROV_A, MS_DEF_DH_SCHANNEL_PROV_W, 18, 1, 0x100, 0x40, 3,
              NULL, 0 },
};
const int cpc_nprovs = 10;

int cpc_prov_registered(const char *name) {
    char key[512]; HKEY k;
    snprintf(key, sizeof key, "SOFTWARE\\Microsoft\\Cryptography\\Defaults\\Provider\\%s", name);
    LONG r = RegOpenKeyExA(HKEY_LOCAL_MACHINE, key, 0, KEY_READ, &k);
    if (r == ERROR_SUCCESS) { RegCloseKey(k); return 1; }
    return 0;
}
int cpc_skip_absent(int i) {
    if (i != CPC_SIG_IDX || cpc_prov_registered(cpc_provs[i].a)) return 0;
    t_skip("provider \"%s\" has no registry entry on this OS", cpc_provs[i].a);
    return 1;
}
BOOL cpc_acq(HCRYPTPROV *h, const char *prov, DWORD type, DWORD flags) {
    return U(CryptAcquireContextA)(h, NULL, prov, type, flags);
}
BOOL cpc_acq_c(HCRYPTPROV *h, const char *cont, const char *prov, DWORD type, DWORD flags) {
    return U(CryptAcquireContextA)(h, cont, prov, type, flags);
}
BOOL cpc_gpp(HCRYPTPROV h, DWORD p, void *buf, DWORD *n, DWORD fl) {
    return U(CryptGetProvParam)(h, p, (BYTE *)buf, n, fl);
}
BOOL cpc_gpp_dw(HCRYPTPROV h, DWORD p, DWORD *v) {
    DWORD n = 4;
    *v = 0xdeadbeef;
    return U(CryptGetProvParam)(h, p, (BYTE *)v, &n, 0) && n == 4;
}
void cpc_rel(HCRYPTPROV h) { if (h) U(CryptReleaseContext)(h, 0); }

int cpc_enum_algs(HCRYPTPROV h, PROV_ENUMALGS *out, int max) {
    int cnt = 0;
    for (;;) {
        PROV_ENUMALGS e; DWORD n = sizeof(e);
        memset(&e, 0xAA, sizeof(e));
        if (!U(CryptGetProvParam)(h, PP_ENUMALGS, (BYTE *)&e, &n, cnt == 0 ? CRYPT_FIRST : 0)) {
            if (GetLastError() == ERROR_NO_MORE_ITEMS) return cnt;
            return -1;
        }
        if (n != sizeof(e) || cnt >= max) return -1;
        out[cnt++] = e;
    }
}
int cpc_enum_algs_ex(HCRYPTPROV h, PROV_ENUMALGS_EX *out, int max) {
    int cnt = 0;
    for (;;) {
        PROV_ENUMALGS_EX e; DWORD n = sizeof(e);
        memset(&e, 0xAA, sizeof(e));
        if (!U(CryptGetProvParam)(h, PP_ENUMALGS_EX, (BYTE *)&e, &n, cnt == 0 ? CRYPT_FIRST : 0)) {
            if (GetLastError() == ERROR_NO_MORE_ITEMS) return cnt;
            return -1;
        }
        if (n != sizeof(e) || cnt >= max) return -1;
        out[cnt++] = e;
    }
}
