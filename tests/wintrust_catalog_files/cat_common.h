/* Shared scaffolding for the wintrust_catalog_files area (included by every .c of the area).
 * Everything under test is reached through GetProcAddress via U()/UN(); only trivial kernel32
 * file plumbing is called directly. */
#ifndef CAT_COMMON_H
#define CAT_COMMON_H
#include "t.h"
#include <wincrypt.h>
#include <wintrust.h>
#include <mscat.h>
#include <mssip.h>
#include <stdlib.h>
#include <wchar.h>

#define INVH ((HANDLE)(LONG_PTR)-1)
#define E_CRYPT_NOT_FOUND 0x80092004u   /* CRYPT_E_NOT_FOUND */

/* Undocumented but stable layout of the object CryptCATOpen returns (CryptCATHandleFromStore is the
 * identity function, so a caller can read it). Offsets verified against the x64 build. */
typedef struct {
    DWORD cbStruct; DWORD dwPublicVersion; LPWSTR pwszP7File; ULONG_PTR hProv;
    DWORD dwEncodingType; DWORD fdwStoreFlags; HANDLE hReserved; HANDLE hAttrs;
    HANDLE hCryptMsg; HANDLE hSorted;
} CATSTORE;

UDECL(CRYPTCATMEMBER *, CryptCATAllocSortedMemberInfo, (HANDLE, LPWSTR));
UDECL(void, CryptCATFreeSortedMemberInfo, (HANDLE, CRYPTCATMEMBER *));
UDECL(BOOL, CryptCATVerifyMember, (HANDLE, CRYPTCATMEMBER *, HANDLE));
UDECL(void *, CryptCATHandleFromStore, (HANDLE));
UDECL(HANDLE, CryptCATStoreFromHandle, (void *));
UDECL(BOOL, IsCatalogFile, (HANDLE, WCHAR *));
UDECL(BOOL, MsCatConstructHashTag, (DWORD, BYTE *, LPWSTR *));
UDECL(HLOCAL, MsCatFreeHashTag, (LPWSTR));
UDECL(BOOL, CryptCATAdminCalcHashFromFileHandle3, (HCATADMIN, HANDLE, DWORD *, BYTE *, DWORD));
UDECL(CRYPTCATMEMBER *, CryptCATCDFEnumMembers, (CRYPTCATCDF *, CRYPTCATMEMBER *, PFN_CDF_PARSE_ERROR_CALLBACK));
UDECL(LPWSTR, CryptCATCDFEnumMembersByCDFTag, (CRYPTCATCDF *, LPWSTR, PFN_CDF_PARSE_ERROR_CALLBACK, CRYPTCATMEMBER **));
UDECL(CRYPTCATATTRIBUTE *, CryptCATCDFEnumAttributes, (CRYPTCATCDF *, CRYPTCATMEMBER *, CRYPTCATATTRIBUTE *, PFN_CDF_PARSE_ERROR_CALLBACK));
UDECL(CRYPTCATATTRIBUTE *, CryptCATCDFEnumAttributesWithCDFTag, (CRYPTCATCDF *, LPWSTR, CRYPTCATMEMBER *, CRYPTCATATTRIBUTE *, PFN_CDF_PARSE_ERROR_CALLBACK));

/* ---- file plumbing ---------------------------------------------------- */
static void wpath(WCHAR *out, const char *leaf)
{
    char p[MAX_PATH];
    t_tmpfile(p, sizeof p, leaf);
    MultiByteToWideChar(CP_ACP, 0, p, -1, out, MAX_PATH);
}
static BOOL put_file(const WCHAR *path, const void *d, DWORD n)
{
    DWORD w = 0;
    HANDLE h = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return FALSE;
    BOOL ok = n ? WriteFile(h, d, n, &w, NULL) : TRUE;
    CloseHandle(h);
    return ok && w == n;
}
static void put_text(const WCHAR *path, const char *s) { put_file(path, s, (DWORD)strlen(s)); }
static LONGLONG fsize(const WCHAR *path)
{
    WIN32_FILE_ATTRIBUTE_DATA d;
    if (!GetFileAttributesExW(path, GetFileExInfoStandard, &d)) return -1;
    return ((LONGLONG)d.nFileSizeHigh << 32) | d.nFileSizeLow;
}
static int fexists(const WCHAR *path) { return GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES; }
static HANDLE ropen(const WCHAR *path)
{
    return CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
}
static void wtow(WCHAR *out, size_t cap, const char *s) { MultiByteToWideChar(CP_UTF8, 0, s, -1, out, (int)cap); }

/* ---- thin wrappers: every call still goes through GetProcAddress ------- */
static HANDLE c_open(const WCHAR *p, DWORD flags, DWORD ver, DWORD enc)
{ return U(CryptCATOpen)((LPWSTR)p, flags, 0, ver, enc); }
static BOOL c_close(HANDLE h) { return U(CryptCATClose)(h); }
static CATSTORE *c_store(HANDLE h) { return (CATSTORE *)h; }

static int count_cat_attrs(HANDLE h)
{
    int n = 0; CRYPTCATATTRIBUTE *a = NULL;
    while ((a = U(CryptCATEnumerateCatAttr)(h, a)) != NULL && n < 100000) n++;
    return n;
}
static int count_members(HANDLE h)
{
    int n = 0; CRYPTCATMEMBER *m = NULL;
    while ((m = U(CryptCATEnumerateMember)(h, m)) != NULL && n < 100000) n++;
    return n;
}
static int count_attrs(HANDLE h, CRYPTCATMEMBER *m)
{
    int n = 0; CRYPTCATATTRIBUTE *a = NULL;
    while ((a = U(CryptCATEnumerateAttr)(h, m, a)) != NULL && n < 100000) n++;
    return n;
}
static CRYPTCATMEMBER *member_at(HANDLE h, int idx)
{
    CRYPTCATMEMBER *m = NULL; int i;
    for (i = 0; i <= idx; i++) { m = U(CryptCATEnumerateMember)(h, m); if (!m) return NULL; }
    return m;
}

/* A syntactically complete SIP_INDIRECT_DATA built by hand (value = empty SEQUENCE, SHA-1 algid). */
static BYTE g_ind_value[2] = { 0x30, 0x00 };
static BYTE g_ind_params[2] = { 0x05, 0x00 };
static const char g_ind_oid[] = "1.3.6.1.4.1.311.2.1.15";
static const char g_alg_sha1[] = "1.3.14.3.2.26";
static const GUID g_subj = { 0x1b2c3d4e, 0x5f60, 0x4172, { 0x83, 0x94, 0xa5, 0xb6, 0xc7, 0xd8, 0xe9, 0xf0 } };
static void mk_ind(SIP_INDIRECT_DATA *d, const BYTE *digest, DWORD cb)
{
    memset(d, 0, sizeof *d);
    d->Data.pszObjId = (LPSTR)g_ind_oid;
    d->Data.Value.cbData = sizeof g_ind_value; d->Data.Value.pbData = g_ind_value;
    d->DigestAlgorithm.pszObjId = (LPSTR)g_alg_sha1;
    d->DigestAlgorithm.Parameters.cbData = sizeof g_ind_params; d->DigestAlgorithm.Parameters.pbData = g_ind_params;
    d->Digest.cbData = cb; d->Digest.pbData = (BYTE *)digest;
}
static CRYPTCATMEMBER *put_member(HANDLE h, const WCHAR *file, const WCHAR *tag, const BYTE *digest20)
{
    SIP_INDIRECT_DATA d; GUID g = g_subj;
    mk_ind(&d, digest20, 20);
    return U(CryptCATPutMemberInfo)(h, (WCHAR *)file, (WCHAR *)tag, &g, 0x200, sizeof d, (BYTE *)&d);
}
static const BYTE g_dig_a[20] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20 };
static const BYTE g_dig_b[20] = { 0xa0,0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,0xa8,0xa9,0xaa,0xab,0xac,0xad,0xae,0xaf,0xb0,0xb1,0xb2,0xb3 };

static void hex_upper(WCHAR *out, const BYTE *b, DWORD n)
{
    static const WCHAR d[] = L"0123456789ABCDEF"; DWORD i;
    for (i = 0; i < n; i++) { out[2 * i] = d[b[i] >> 4]; out[2 * i + 1] = d[b[i] & 15]; }
    out[2 * n] = 0;
}
#endif
