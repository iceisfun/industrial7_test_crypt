#ifndef SIP_COMMON_H
#define SIP_COMMON_H
#include "t.h"
#include <wincrypt.h>
#include <mssip.h>
#include "sip_images.h"

/* ---- GUIDs (SIP subject types) ---- */
static const GUID G_PE   = {0xC689AAB8, 0x8E78, 0x11D0, {0x8C, 0x47, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE}};
static const GUID G_CAB  = {0xC689AABA, 0x8E78, 0x11D0, {0x8C, 0x47, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE}};
static const GUID G_FLAT = {0xDE351A42, 0x8E59, 0x11D0, {0x8C, 0x47, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE}};
static const GUID G_CAT  = {0xDE351A43, 0x8E59, 0x11D0, {0x8C, 0x47, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE}};
static const GUID G_CTL  = {0x9BA61D3F, 0xE73A, 0x11D0, {0x8C, 0xD2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE}};
static const GUID G_PS   = {0x603BCC1F, 0x4B59, 0x4E08, {0xB7, 0x24, 0xD2, 0xC6, 0x29, 0x7E, 0xF3, 0x51}};
static const GUID G_MSI  = {0x000C10F1, 0x0000, 0x0000, {0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}};
static const GUID G_UNKNOWN = {0x7A3B1C55, 0x0F12, 0x4D4E, {0x91, 0xA7, 0x5C, 0x2E, 0x6B, 0x83, 0x10, 0xD9}};

#define OID_SHA1   "1.3.14.3.2.26"
#define OID_SHA256 "2.16.840.1.101.3.4.2.1"
#define OID_SHA384 "2.16.840.1.101.3.4.2.2"
#define OID_SHA512 "2.16.840.1.101.3.4.2.3"
#define OID_MD5    "1.2.840.113549.2.5"
#define OID_CATALOG_LIST "1.3.6.1.4.1.311.12.1.1"

#define E_TRUST_SUBJECT_FORM_UNKNOWN ((DWORD)0x800B0003)
#define E_TRUST_NOSIGNATURE          ((DWORD)0x800B0100)
#define E_TRUST_BAD_DIGEST           ((DWORD)0x80096010)
#define E_NTE_BAD_ALGID              ((DWORD)0x80090008)
#define E_E_INVALIDARG              ((DWORD)0x80070057)

/* SIP_CAP_SET_V3 / SIP_INFORMATION are not in the SDK headers used here. */
typedef struct { DWORD cbSize; DWORD dwVersion; DWORD isMultiSign; DWORD dwFlags; } SIPT_CAPS;
typedef struct { DWORD cbSize; DWORD cGuids; const GUID *pGuids; } SIPT_INFORMATION;
UDECL(BOOL, CryptSIPGetInfo, (SIPT_INFORMATION *));
UDECL(void, CryptSIPGetRegWorkingFlags, (DWORD *));
UDECL(BOOL, CryptSIPGetCaps, (SIP_SUBJECTINFO *, SIPT_CAPS *));
UDECL(BOOL, CryptSIPGetSealedDigest, (SIP_SUBJECTINFO *, const BYTE *, DWORD, BYTE *, DWORD *));
UDECL(int,  ComputeFirstPageHash, (const WCHAR *, const WCHAR *, void *, int));
UDECL(DWORD, GetAuthenticodeSha256Hash, (const WCHAR *, HANDLE, BYTE *));
UDECL(BOOL, IsCatalogFile, (HANDLE, const WCHAR *));
UDECL(void, WintrustGetRegPolicyFlags, (DWORD *));

#define WT(name)  ((name##_pfn)t_proc_in("wintrust.dll", #name))   /* UDECL'd function pinned to wintrust */
#define C32(name) ((name##_pfn)t_proc_in("crypt32.dll", #name))    /* UDECL'd function pinned to crypt32 */

/* ---- helpers (sip_common.c) ---- */
void   sipt_wide(WCHAR *dst, size_t n, const char *src);
int    sipt_put(const char *path, const void *buf, size_t n);          /* create/truncate; 1 = ok */
size_t sipt_get(const char *path, u8 *buf, size_t cap);                /* read whole file; 0 on error */
size_t sipt_size(const char *path);                                    /* (size_t)-1 on error */
void   sipt_mkpe(char *path, size_t cap, const char *leaf, unsigned variant);
void   sipt_mkcab(char *path, size_t cap, const char *leaf);
HANDLE sipt_open(const char *path, DWORD access);                      /* share all; INVALID_HANDLE_VALUE on error */
void   sipt_subject(SIP_SUBJECTINFO *si, const GUID *g, HANDLE h, const WCHAR *wname, const char *alg, DWORD flags);
int    sipt_sip_is_registered(const GUID *g);                          /* via CryptSIPLoad */
/* Unsigned catalog-style message: signedData holding a CTL whose SubjectUsage is `usage` (NULL: empty usage). */
size_t sipt_make_ctl(u8 *out, size_t cap, const char *usage);
#endif
