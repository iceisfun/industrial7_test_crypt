#ifndef OIDREG_H
#define OIDREG_H
#include "t.h"
#include <wincrypt.h>
/* Shared helpers for the dx_crypt32_oid_registry area.
 *
 * Everything this area writes lives under
 *   HKLM\Software\Microsoft\Cryptography\OID\EncodingType 777\...        (real-export-named sets)
 *   HKLM\Software\Microsoft\Cryptography\OID\EncodingType {0,1}\cryptt_oidreg_<pid>_*  (unique sets)
 *   HKLM\Software\Microsoft\Cryptography\OID\EncodingType 0\CryptDllFindOIDInfo\2.999.1347.<pid>.<n>!<group>
 * and key identifier elements whose id starts with the ASCII bytes "cryptt".
 * Leftovers are swept at the start of every test and at process exit. */

#define OIDR_ROOT   L"Software\\Microsoft\\Cryptography\\OID"
#define OIDR_ENC777 777            /* private encoding type, used for sets named after real exports */
#define OIDR_FINDINFO "CryptDllFindOIDInfo"

int  oidr_can_write(void);          /* HKLM OID key is writable (administrator) */
int  oidr_begin(void);              /* gate + sweep + atexit; 0 => caller must return (already t_skip'd) */
void oidr_end(void);                /* sweep */
void oidr_sweep(void);

char *oidr_set(char *buf, size_t cap, const char *tag);   /* cryptt_oidreg_<pid>_<tag> */
char *oidr_oid(char *buf, size_t cap, unsigned n);        /* 2.999.1347.<pid>.<n> */
wchar_t *oidr_wide(wchar_t *buf, size_t cap, const char *s);

/* Registry path of  EncodingType <enc>\<func>\<oid>  (enc already the numeric type) */
void oidr_path(wchar_t *buf, size_t cap, unsigned enc, const char *func, const char *oid);
/* Raw registry read through advapi32 (scaffolding for verification). rc = status */
LONG oidr_raw_get(const wchar_t *subkey, const wchar_t *name, DWORD *type, void *buf, DWORD *cb);
int  oidr_key_exists(const wchar_t *subkey);
/* Number of values in key; -1 if absent */
int  oidr_value_count(const wchar_t *subkey);

/* Key identifier helpers */
void oidr_kid(CRYPT_HASH_BLOB *b, BYTE *store20, const char *tag, size_t len);  /* "cryptt" + pid + tag */
void oidr_kid_cleanup(void);
void oidr_kid_track(const BYTE *id, size_t len);   /* remember an identifier for cleanup */
int  oidr_kid_begin(int machine);   /* machine=1 needs elevation; 0 => caller must return */
#endif
