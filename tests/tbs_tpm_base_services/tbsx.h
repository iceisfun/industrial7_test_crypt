/* Shared declarations for the tbs.dll area. Nothing here links against tbs.dll:
 * every entry point is resolved with GetProcAddress through UN(). */
#ifndef TBSX_H
#define TBSX_H
#include "t.h"

#define TE_OK                      0x00000000u
#define TE_INTERNAL_ERROR        0x80284001u
#define TE_BAD_PARAMETER         0x80284002u
#define TE_INVALID_OUTPUT_POINTER 0x80284003u
#define TE_INVALID_CONTEXT       0x80284004u
#define TE_INSUFFICIENT_BUFFER   0x80284005u
#define TE_INVALID_CONTEXT_PARAM 0x80284007u
#define TE_BUFFER_TOO_LARGE      0x8028400Eu
#define TE_TPM_NOT_FOUND         0x8028400Fu
#define TE_NO_EVENT_LOG          0x80284011u
#define HR_INSUFFICIENT_BUFFER      0x8007007Au
#define NT_INVALID_PARAMETER        0xC000000Du
#define NT_BUFFER_TOO_SMALL         0xC0000023u

typedef struct { UINT32 version; } tbsx_params1;
typedef struct { UINT32 version; UINT32 flags; } tbsx_params2;
#define TBSX_RAW    1u
#define TBSX_TPM12  2u
#define TBSX_TPM20  4u
typedef struct { UINT32 structVersion, tpmVersion, tpmInterfaceType, tpmImpRevision; } tbsx_devinfo;

UDECL(UINT32, Tbsi_Context_Create, (const void *, void **));
UDECL(UINT32, Tbsip_Context_Close, (void *));
UDECL(UINT32, Tbsip_Submit_Command, (void *, UINT32, UINT32, const BYTE *, UINT32, BYTE *, UINT32 *));
UDECL(UINT32, Tbsip_Submit_Command_NonBlocking, (void *, UINT32, UINT32, const BYTE *, UINT32, BYTE *, UINT32 *));
UDECL(UINT32, Tbsip_Cancel_Commands, (void *));
UDECL(UINT32, Tbsip_TestInterruptInformation, (UINT32 *));
UDECL(UINT32, Tbsip_TestMorBit, (UINT32 *));
UDECL(UINT32, Tbsi_GetDeviceInfo, (UINT32, void *));
UDECL(UINT32, Tbsi_Get_TCG_Log, (void *, BYTE *, UINT32 *));
UDECL(UINT32, Tbsi_Get_TCG_Log_Ex, (UINT32, BYTE *, UINT32 *));
UDECL(UINT32, Tbsi_Get_TCG_Logs, (UINT32, UINT32 *, BYTE *, UINT32, UINT32 *, UINT32));
UDECL(UINT32, Tbsi_FilterLog, (const BYTE *, UINT32, UINT32, BYTE *, UINT32, UINT32 *));
UDECL(UINT32, Tbsi_Create_Attestation_From_Log, (const BYTE *, UINT32, USHORT *, USHORT **, BYTE *, BYTE *, UINT32, UINT32 *, UINT32));
UDECL(UINT32, Tbsi_Revoke_Attestation, (void));
UDECL(UINT32, Tbsi_Create_Windows_Key, (UINT32));
UDECL(UINT32, Tbsi_Get_OwnerAuth, (void *, UINT32, BYTE *, UINT32 *));
UDECL(UINT32, Tbsi_Physical_Presence_Command, (void *, const BYTE *, UINT32, BYTE *, UINT32 *));
UDECL(LONG,   Tbsi_ShaHash, (const WCHAR *, const BYTE *, ULONG, const BYTE *, ULONG, BYTE *, UINT32, UINT32 *));
UDECL(LONG,   GetDeviceID, (BYTE *, UINT32, UINT32 *, BOOL *));
UDECL(LONG,   GetDeviceIDString, (WCHAR *, UINT32, UINT32 *, BOOL *));
UDECL(LONG,   GetDeviceIDWithTimeout, (BYTE *, UINT32, UINT32 *, UINT32, BOOL *));

#define TBS_NAMES(X) X(Tbsi_Context_Create) X(Tbsip_Context_Close) X(Tbsip_Submit_Command) \
  X(Tbsip_Submit_Command_NonBlocking) X(Tbsip_Cancel_Commands) X(Tbsip_TestInterruptInformation) \
  X(Tbsip_TestMorBit) X(Tbsi_GetDeviceInfo) X(Tbsi_Get_TCG_Log) X(Tbsi_Get_TCG_Log_Ex) \
  X(Tbsi_Get_TCG_Logs) X(Tbsi_FilterLog) X(Tbsi_Create_Attestation_From_Log) X(Tbsi_Revoke_Attestation) \
  X(Tbsi_Create_Windows_Key) X(Tbsi_Get_OwnerAuth) X(Tbsi_Physical_Presence_Command) X(Tbsi_ShaHash) \
  X(GetDeviceID) X(GetDeviceIDString) X(GetDeviceIDWithTimeout)

/* Resolve an export of tbs.dll specifically. */
static inline FARPROC tbsx_proc(const char *n) { return t_proc_in("tbs.dll", n); }
#define TB(name) ((name##_pfn)tbsx_proc(#name))
static inline int tbsx_emulated(void) {
    HMODULE n = GetModuleHandleA("ntdll.dll");
    HKEY k;
    if (t_is_wine()) return 1;
    if (n && (GetProcAddress(n, "wine_get_host_version") || GetProcAddress(n, "__wine_init_unix_call") || GetProcAddress(n, "wine_unix_to_nt_file_name"))) return 1;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Wine", 0, KEY_READ, &k) == ERROR_SUCCESS) { RegCloseKey(k); return 1; }
    return 0;
}
/* Emulators may export these as aborting stubs: skip there (no-op on Windows). */
static inline int tbsx_stub_on_emulator(const char *n) {
    return tbsx_emulated() && strcmp(n, "Tbsi_Context_Create") && strcmp(n, "Tbsi_GetDeviceInfo") && strcmp(n, "GetDeviceIDString");
}
#define NEED(name) name##_pfn p_##name = TB(name); REQUIRE(p_##name); \
    if (tbsx_stub_on_emulator(#name)) { t_skip("emulator stub: " #name); return; }
#define NOEMU() do { if (tbsx_emulated()) { t_skip("emulator stub does not validate"); return; } } while (0)
#define P(name) p_##name

/* Is a TPM visible to TBS?  (\??\TPM opens and the device-info ioctl succeeds.) */
static inline int tbsx_tpm_present(tbsx_devinfo *out) {
    Tbsi_GetDeviceInfo_pfn f = TB(Tbsi_GetDeviceInfo);
    tbsx_devinfo d; memset(&d, 0, sizeof d);
    if (!f) return 0;
    UINT32 r = f(sizeof d, &d);
    if (r != 0) return 0;
    if (out) *out = d;
    return 1;
}
#endif
