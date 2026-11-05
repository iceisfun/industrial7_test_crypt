/* certca.dll / certcli.dll conformance: shared declarations and helpers.
 *
 * Everything is resolved with GetProcAddress. certcli.dll forwards most exports to certca.dll (many by
 * ordinal only), so helper-style exports are always resolved through certcli.dll by name.
 *
 * Directory-service safety: certca.dll talks to Active Directory for every real template / CA lookup.
 * Those calls are only made on machines that are NOT domain joined (so no wire traffic), run in a
 * bounded worker thread (5 s), and tests that need a live template object only run when one can be
 * created (see cct_template()).
 */
#ifndef CCT_H
#define CCT_H
#include "t.h"
#include <stdlib.h>
#include <wincrypt.h>

typedef void *HCT;   /* HCERTTYPE */
typedef void *HCA;   /* HCAINFO   */

#define E_PTR       ((HRESULT)0x80004003)
#define E_NOIMPL    ((HRESULT)0x80004001)
#define E_BADARG    ((HRESULT)0x80070057)
#define E_NOMEM     ((HRESULT)0x8007000E)
#define E_UNEXP     ((HRESULT)0x8000FFFF)
#define HR_NOT_FOUND_FILE ((HRESULT)0x80070002)
#define HR_ERROR_NOT_FOUND ((HRESULT)0x80070490)
#define HR_CRYPT_E_NOT_FOUND ((HRESULT)0x80092004)
#define HR_BAD_SD   ((HRESULT)0x8007053A)

/* ---- certca.dll / certcli.dll exports --------------------------------- */
UDECL(HRESULT, CACreateCertType, (LPCWSTR, void *, DWORD, HCT *));
UDECL(HRESULT, CACloneCertType, (HCT, LPCWSTR, LPCWSTR, void *, DWORD, HCT *));
UDECL(HRESULT, CACloseCertType, (HCT));
UDECL(HRESULT, CASetCertTypeProperty, (HCT, LPCWSTR, LPWSTR *));
UDECL(HRESULT, CAGetCertTypeProperty, (HCT, LPCWSTR, LPWSTR **));
UDECL(HRESULT, CAGetCertTypePropertyEx, (HCT, LPCWSTR, void *));
UDECL(HRESULT, CAFreeCertTypeProperty, (HCT, LPWSTR *));
UDECL(HRESULT, CASetCertTypeFlags, (HCT, DWORD));
UDECL(HRESULT, CAGetCertTypeFlags, (HCT, DWORD *));
UDECL(HRESULT, CASetCertTypeFlagsEx, (HCT, DWORD, DWORD));
UDECL(HRESULT, CAGetCertTypeFlagsEx, (HCT, DWORD, DWORD *));
UDECL(HRESULT, CASetCertTypeKeySpec, (HCT, DWORD));
UDECL(HRESULT, CAGetCertTypeKeySpec, (HCT, DWORD *));
UDECL(HRESULT, CASetCertTypeExpiration, (HCT, FILETIME *, FILETIME *));
UDECL(HRESULT, CAGetCertTypeExpiration, (HCT, FILETIME *, FILETIME *));
UDECL(HRESULT, CASetCertTypeExtension, (HCT, LPCWSTR, DWORD, void *));
UDECL(HRESULT, CAGetCertTypeExtensions, (HCT, CERT_EXTENSIONS **));
UDECL(HRESULT, CAGetCertTypeExtensionsEx, (HCT, DWORD, void *, CERT_EXTENSIONS **));
UDECL(HRESULT, CAFreeCertTypeExtensions, (HCT, CERT_EXTENSIONS *));
UDECL(HRESULT, CACertTypeGetSecurity, (HCT, PSECURITY_DESCRIPTOR *));
UDECL(HRESULT, CACertTypeSetSecurity, (HCT, PSECURITY_DESCRIPTOR));
UDECL(HRESULT, CACertTypeAccessCheck, (HCT, HANDLE));
UDECL(HRESULT, CACertTypeAccessCheckEx, (HCT, HANDLE, DWORD));
UDECL(HRESULT, CACertTypeAuthzAccessCheck, (HCT, void *, DWORD));
UDECL(DWORD,   CACertTypeQuery, (DWORD *, DWORD *));
UDECL(HRESULT, CAEnumCertTypes, (DWORD, HCT *));
UDECL(HRESULT, CAEnumCertTypesEx, (void *, DWORD, HCT *));
UDECL(HRESULT, CAEnumNextCertType, (HCT, HCT *));
UDECL(DWORD,   CACountCertTypes, (HCT));
UDECL(HRESULT, CAFindCertTypeByName, (LPCWSTR, HCA, DWORD, HCT *));
UDECL(HRESULT, CAEnumFirstCA, (LPCWSTR, DWORD, HCA *));
UDECL(HRESULT, CAEnumNextCA, (HCA, HCA *));
UDECL(DWORD,   CACountCAs, (HCA));
UDECL(HRESULT, CACloseCA, (HCA));
UDECL(HRESULT, CAFindByName, (LPCWSTR, LPCWSTR, DWORD, HCA *));
UDECL(HRESULT, CAFindByCertType, (LPCWSTR, LPCWSTR, DWORD, HCA *));
UDECL(HRESULT, CAFindByIssuerDN, (CRYPT_DATA_BLOB *, LPCWSTR, DWORD, HCA *));
UDECL(HRESULT, CAEnumCertTypesForCA, (HCA, DWORD, HCT *));
UDECL(HRESULT, CAEnumCertTypesForCAEx, (HCA, LPCWSTR, DWORD, HCT *));
UDECL(HRESULT, CAGetCAProperty, (HCA, LPCWSTR, LPWSTR **));
UDECL(HRESULT, CASetCAProperty, (HCA, LPCWSTR, LPWSTR *));
UDECL(HRESULT, CAFreeCAProperty, (HCA, LPWSTR *));
UDECL(HRESULT, CAGetCAFlags, (HCA, DWORD *));
UDECL(HRESULT, CASetCAFlags, (HCA, DWORD));
UDECL(HRESULT, CAGetCAExpiration, (HCA, DWORD *, DWORD *));
UDECL(HRESULT, CASetCAExpiration, (HCA, DWORD, DWORD));
UDECL(HRESULT, CAGetCACertificate, (HCA, PCCERT_CONTEXT *));
UDECL(HRESULT, CASetCACertificate, (HCA, PCCERT_CONTEXT));
UDECL(HRESULT, CAGetCASecurity, (HCA, PSECURITY_DESCRIPTOR *));
UDECL(HRESULT, CASetCASecurity, (HCA, PSECURITY_DESCRIPTOR));
UDECL(HRESULT, CAAccessCheck, (HCA, HANDLE));
UDECL(HRESULT, CAAccessCheckEx, (HCA, HANDLE, DWORD));
UDECL(HRESULT, CAUpdateCA, (HCA));
UDECL(HRESULT, CAUpdateCAEx, (void *, DWORD, HCA));
UDECL(HRESULT, CADeleteCA, (HCA));
UDECL(HRESULT, CADeleteCAEx, (void *, DWORD, HCA));
UDECL(HRESULT, CADeleteCertType, (HCT));
UDECL(HRESULT, CADeleteCertTypeEx, (void *, DWORD, HCT));
UDECL(HRESULT, CAUpdateCertType, (HCT));
UDECL(HRESULT, CAUpdateCertTypeEx, (void *, DWORD, HCT));
UDECL(HRESULT, CAInstallDefaultCertType, (DWORD));
UDECL(HRESULT, CAInstallDefaultCertTypeEx, (void *, DWORD));
UDECL(HRESULT, CACreateNewCA, (LPCWSTR, LPCWSTR, DWORD, HCA *));
UDECL(HRESULT, CAOIDCreateNew, (DWORD, DWORD, LPWSTR *));
UDECL(HRESULT, CAOIDCreateNewEx, (DWORD, DWORD, void *, LPWSTR *));
UDECL(HRESULT, CAOIDAdd, (DWORD, DWORD, LPCWSTR));
UDECL(HRESULT, CAOIDAddEx, (DWORD, DWORD, void *, LPCWSTR));
UDECL(HRESULT, CAOIDDelete, (LPCWSTR));
UDECL(HRESULT, CAOIDDeleteEx, (DWORD, void *, LPCWSTR));
UDECL(HRESULT, CAOIDGetProperty, (LPCWSTR, DWORD, void *));
UDECL(HRESULT, CAOIDGetPropertyEx, (DWORD, void *, LPCWSTR, DWORD, void *));
UDECL(HRESULT, CAOIDSetProperty, (LPCWSTR, DWORD, void *));
UDECL(HRESULT, CAOIDSetPropertyEx, (DWORD, void *, LPCWSTR, DWORD, void *));
UDECL(HRESULT, CAOIDFreeProperty, (void *));
UDECL(HRESULT, CAOIDFreeLdapURL, (void *));
UDECL(HRESULT, CAOIDGetLdapURL, (DWORD, DWORD, LPWSTR *));
UDECL(HRESULT, CCFindCertificateBuildFilter, (LPCWSTR, void **));
UDECL(PCCERT_CONTEXT, CCFindCertificateFromFilter, (HCERTSTORE, void *, PCCERT_CONTEXT));
UDECL(void,    CCFindCertificateFreeFilter, (void *));
UDECL(HRESULT, CCGetCertNameList, (PCCERT_CONTEXT, DWORD, DWORD, DWORD *, LPWSTR **));
UDECL(void,    CCFreeStringArray, (LPWSTR *));

/* certcli helper exports (all reached through certcli.dll, mostly ordinal forwards into certca.dll) */
UDECL(HRESULT, myCryptBinaryToString, (const BYTE *, DWORD, DWORD, LPWSTR *));
UDECL(HRESULT, myCryptBinaryToStringA, (const BYTE *, DWORD, DWORD, LPSTR *));
UDECL(HRESULT, myCryptStringToBinary, (LPCWSTR, DWORD, DWORD, BYTE **, DWORD *, DWORD *, DWORD *));
UDECL(HRESULT, myCryptStringToBinaryA, (LPCSTR, DWORD, DWORD, BYTE **, DWORD *, DWORD *, DWORD *));
UDECL(HRESULT, WszToMultiByteInteger, (DWORD, LPCWSTR, DWORD *, BYTE **));
UDECL(HRESULT, WszToMultiByteIntegerBuf, (DWORD, LPCWSTR, DWORD *, BYTE *));
UDECL(HRESULT, mySanitizeName, (LPCWSTR, LPWSTR *));
UDECL(HRESULT, myRevertSanitizeName, (LPCWSTR, LPWSTR *));
UDECL(HRESULT, mySanitizedNameToShortName, (LPCWSTR, int, LPWSTR *));
UDECL(HRESULT, mySanitizedNameToDSName, (LPCWSTR, LPWSTR *));
UDECL(HRESULT, SplitConfigString, (LPCWSTR, LPWSTR *, LPWSTR *));
UDECL(int,     mylstrcmpiL, (LPCWSTR, LPCWSTR));
UDECL(HRESULT, myGenerateGuidString, (LPWSTR *));
UDECL(void,    myGenerateGuidSerialNumber, (GUID *));
UDECL(HRESULT, myOIDHashOIDToString, (LPCWSTR, LPWSTR *));
UDECL(HRESULT, caTranslateFileTimePeriodToPeriodUnits, (LONGLONG *, DWORD, DWORD *, void **));
UDECL(HRESULT, CertcliGetDetailedCertcliVersionString, (LPCWSTR *));
UDECL(LPWSTR,  myGetErrorMessageText, (LONG, BOOL));
UDECL(LPWSTR,  myGetErrorMessageText1, (LONG, BOOL, LPCWSTR));
UDECL(LONG,    myHGetLastError, (void));
UDECL(int,     myIsDelayLoadHResult, (LONG));
UDECL(LONG,    myJetHResult, (LONG));
UDECL(LONG,    myHExceptionCode, (EXCEPTION_POINTERS *));
UDECL(HRESULT, myCAPropGetDisplayName, (LONG, LPCWSTR *));
UDECL(HRESULT, myCAPropInfoLookup, (const void *, LONG, LONG, const void **));
UDECL(HRESULT, DecodeFileW, (LPCWSTR, BYTE **, DWORD *, DWORD));
UDECL(HRESULT, EncodeToFileW, (LPCWSTR, const BYTE *, DWORD, DWORD));

#define CCLI(name) ((name##_pfn)t_proc_in("certcli.dll", #name))
#define CCA(name)  ((name##_pfn)t_proc_in("certca.dll", #name))

/* ---- environment ------------------------------------------------------- */
/* NetGetJoinInformation status: 0 unknown, 1 unjoined, 2 workgroup, 3 domain. */
static inline int cct_join_status(void)
{
    typedef DWORD (WINAPI *gj_t)(LPCWSTR, LPWSTR *, DWORD *);
    typedef DWORD (WINAPI *fr_t)(void *);
    HMODULE m = LoadLibraryA("netapi32.dll");
    if (!m) return 0;
    gj_t gj = (gj_t)GetProcAddress(m, "NetGetJoinInformation");
    fr_t fr = (fr_t)GetProcAddress(m, "NetApiBufferFree");
    if (!gj) return 0;
    LPWSTR nm = NULL; DWORD st = 0;
    if (gj(NULL, &nm, &st) != 0) return 0;
    if (nm && fr) fr(nm);
    return (int)st;
}
static inline int cct_domain_joined(void) { return cct_join_status() == 3; }

/* Skip (and return from the caller) on domain-joined machines: the call would reach a domain controller. */
#define CCT_NEED_NO_DOMAIN() do { if (cct_domain_joined()) { t_skip("domain joined: directory calls could reach the wire"); return; } } while (0)

/* Bounded worker: run fn(arg) on a thread, wait up to ms. Returns 1 if it finished. The argument block
 * must have static storage because an abandoned thread may still use it. */
typedef struct { void (*fn)(void *); void *arg; } cct_job;
static inline DWORD WINAPI cct_job_main(LPVOID p) { cct_job *j = (cct_job *)p; j->fn(j->arg); return 0; }
static inline int cct_bounded(void (*fn)(void *), void *arg, DWORD ms)
{
    static cct_job job;
    job.fn = fn; job.arg = arg;
    HANDLE h = CreateThread(NULL, 0, cct_job_main, &job, 0, NULL);
    if (!h) return 0;
    if (WaitForSingleObject(h, ms) != WAIT_OBJECT_0) { CloseHandle(h); return 0; }
    CloseHandle(h);
    return 1;
}

/* A cleanup-safe fixed template (nullptr when the environment cannot create one). Defined in cct_template.c. */
HCT cct_template(void);
const WCHAR *cct_template_name(void);
#endif
