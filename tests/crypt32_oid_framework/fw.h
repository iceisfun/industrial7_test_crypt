/* Shared helpers for the crypt32 OID / function-set framework area. */
#ifndef FW_H
#define FW_H
#define CRYPT_OID_INFO_HAS_EXTRA_FIELDS
#include "t.h"
#include <wincrypt.h>
#include <wchar.h>

#define NODS 0x80000000u /* CRYPT_OID_DISABLE_SEARCH_DS_FLAG: never touch a directory */
#define OIDG_HASH 1
#define OIDG_ENCRYPT 2
#define OIDG_PUBKEY 3
#define OIDG_SIGN 4
#define OIDG_RDN 5
#define OIDG_EXT 6
#define OIDG_ENHKEY 7
#define OIDG_POLICY 8
#define OIDG_TEMPLATE 9
#define OIDG_KDF 10

#define ERR_INVALIDARG 0x80070057u
#define ERR_NOTIMPL    120u

/* case-flipped copy of a narrow/wide string into a caller buffer */
static inline void fw_flip_a(char *out, const char *in) {
    for (; *in; in++, out++) {
        char c = *in;
        if (c >= 'a' && c <= 'z') c -= 32; else if (c >= 'A' && c <= 'Z') c += 32;
        *out = c;
    }
    *out = 0;
}
static inline void fw_flip_w(wchar_t *out, const wchar_t *in) {
    for (; *in; in++, out++) {
        wchar_t c = *in;
        if (c >= L'a' && c <= L'z') c -= 32; else if (c >= L'A' && c <= L'Z') c += 32;
        *out = c;
    }
    *out = 0;
}
#endif
