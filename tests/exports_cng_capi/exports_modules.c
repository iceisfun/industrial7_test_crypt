/* exports_cng_capi: export-table sweeps (resolve-only) for the CNG / CAPI core modules:
 * bcrypt, bcryptprimitives, ncrypt (BCrypt and NCrypt names; the Ssl names are excluded), ncryptprov, cryptsp, cryptbase,
 * cryptdll, dpapi, rsaenh, dssenh and advapi32 Crypt and SystemFunction names (plus names forwarded to cryptsp/cryptbase).
 *
 * Every lookup is LoadLibrary (harness) -> GetProcAddress. Nothing exported is ever called.
 * exports_data.c is an authoring-time snapshot of the Windows 10 x64 export directories; checks tied to
 * names and forwarders, ordinals, directory counts and the number of unlisted exports are pinned to the values
 * observed on Windows 10 22H2.
 *
 * Forwarder tables (export -> target), from the Windows 10 x64 export directories.
 * Targets are resolved with GetProcAddress on the forwarding module and must equal the address
 * obtained from the target module itself (tests exports_cng_capi_*_forwarders_*).
 *
 * ncrypt.dll -> BCRYPT (56): BCryptAddContextFunction, BCryptAddContextFunctionProvider,
 *   BCryptCloseAlgorithmProvider, BCryptConfigureContext, BCryptConfigureContextFunction,
 *   BCryptCreateContext, BCryptCreateHash, BCryptDecrypt, BCryptDeleteContext, BCryptDeriveKey,
 *   BCryptDeriveKeyCapi, BCryptDeriveKeyPBKDF2, BCryptDestroyHash, BCryptDestroyKey,
 *   BCryptDestroySecret, BCryptDuplicateHash, BCryptDuplicateKey, BCryptEncrypt,
 *   BCryptEnumAlgorithms, BCryptEnumContextFunctionProviders, BCryptEnumContextFunctions,
 *   BCryptEnumContexts, BCryptEnumProviders, BCryptEnumRegisteredProviders, BCryptExportKey,
 *   BCryptFinalizeKeyPair, BCryptFinishHash, BCryptFreeBuffer, BCryptGenRandom,
 *   BCryptGenerateKeyPair, BCryptGenerateSymmetricKey, BCryptGetFipsAlgorithmMode,
 *   BCryptGetProperty, BCryptHash, BCryptHashData, BCryptImportKey, BCryptImportKeyPair,
 *   BCryptKeyDerivation, BCryptOpenAlgorithmProvider, BCryptQueryContextConfiguration,
 *   BCryptQueryContextFunctionConfiguration, BCryptQueryContextFunctionProperty,
 *   BCryptQueryProviderRegistration, BCryptRegisterConfigChangeNotify, BCryptRegisterProvider,
 *   BCryptRemoveContextFunction, BCryptRemoveContextFunctionProvider, BCryptResolveProviders,
 *   BCryptSecretAgreement, BCryptSetAuditingInterface, BCryptSetContextFunctionProperty,
 *   BCryptSetProperty, BCryptSignHash, BCryptUnregisterConfigChangeNotify,
 *   BCryptUnregisterProvider, BCryptVerifySignature
 * cryptdll.dll -> NTDLL (3): MD5Final, MD5Init, MD5Update
 * advapi32.dll -> CRYPTBASE (11): SystemFunction001, SystemFunction002, SystemFunction003,
 *   SystemFunction004, SystemFunction005, SystemFunction028, SystemFunction029,
 *   SystemFunction034, SystemFunction036, SystemFunction040, SystemFunction041
 * advapi32.dll -> CRYPTSP (25): SystemFunction006, SystemFunction007, SystemFunction008,
 *   SystemFunction009, SystemFunction010, SystemFunction011, SystemFunction012,
 *   SystemFunction013, SystemFunction014, SystemFunction015, SystemFunction016,
 *   SystemFunction018, SystemFunction020, SystemFunction021, SystemFunction022,
 *   SystemFunction023, SystemFunction024, SystemFunction025, SystemFunction026,
 *   SystemFunction027, SystemFunction030, SystemFunction031, SystemFunction032,
 *   SystemFunction033, SystemFunction035->CheckSignatureInFile
 * Not forwarded (own code): bcrypt, bcryptprimitives, ncryptprov, cryptsp, cryptbase, dpapi, rsaenh, dssenh,
 * and every advapi32 Crypt* name (CryptAcquireContext*, CryptCreateHash, ... are advapi32 code).
 */

#include "exports_common.h"

MODTESTS(bcrypt, "bcrypt.dll")
MODTESTS(bcryptprimitives, "bcryptprimitives.dll")
MODTESTS(ncrypt, "ncrypt.dll")
MODTESTS(ncryptprov, "ncryptprov.dll")
MODTESTS(cryptsp, "cryptsp.dll")
MODTESTS(cryptbase, "cryptbase.dll")
MODTESTS(cryptdll, "cryptdll.dll")
MODTESTS(dpapi, "dpapi.dll")
MODTESTS(rsaenh, "rsaenh.dll")
MODTESTS(dssenh, "dssenh.dll")
MODTESTS(advapi32, "advapi32.dll")
