/* Generated: per-family resolve sweeps (names grouped by their first two CamelCase words). */
#include "exports_common.h"

TEST(exports_cng_capi_bcrypt_family_BCrypt) {
    static const char *const n[] = {"BCryptAddContextFunction","BCryptAddContextFunctionProvider","BCryptCloseAlgorithmProvider","BCryptConfigureContext","BCryptConfigureContextFunction","BCryptCreateContext","BCryptCreateHash","BCryptCreateMultiHash","BCryptDecrypt","BCryptDeleteContext","BCryptDeriveKey","BCryptDeriveKeyCapi","BCryptDeriveKeyPBKDF2","BCryptDestroyHash","BCryptDestroyKey","BCryptDestroySecret","BCryptDuplicateHash","BCryptDuplicateKey","BCryptEncrypt","BCryptEnumAlgorithms","BCryptEnumContextFunctionProviders","BCryptEnumContextFunctions","BCryptEnumContexts","BCryptEnumProviders","BCryptEnumRegisteredProviders","BCryptExportKey","BCryptFinalizeKeyPair","BCryptFinishHash","BCryptFreeBuffer","BCryptGenRandom","BCryptGenerateKeyPair","BCryptGenerateSymmetricKey","BCryptGetFipsAlgorithmMode","BCryptGetProperty","BCryptHash","BCryptHashData","BCryptImportKey","BCryptImportKeyPair","BCryptKeyDerivation","BCryptOpenAlgorithmProvider","BCryptProcessMultiOperations","BCryptQueryContextConfiguration","BCryptQueryContextFunctionConfiguration","BCryptQueryContextFunctionProperty","BCryptQueryProviderRegistration","BCryptRegisterConfigChangeNotify","BCryptRegisterProvider","BCryptRemoveContextFunction","BCryptRemoveContextFunctionProvider","BCryptResolveProviders","BCryptSecretAgreement","BCryptSetAuditingInterface","BCryptSetContextFunctionProperty","BCryptSetProperty","BCryptSignHash","BCryptUnregisterConfigChangeNotify","BCryptUnregisterProvider","BCryptVerifySignature"};
    ex_family("bcrypt.dll", n, 58);
}
TEST(exports_cng_capi_bcryptprimitives_family_ProcessPrng) {
    static const char *const n[] = {"ProcessPrng","ProcessPrngGuid"};
    ex_family("bcryptprimitives.dll", n, 2);
}
TEST(exports_cng_capi_bcryptprimitives_family_misc) {
    static const char *const n[] = {"GetAsymmetricEncryptionInterface","GetCipherInterface","GetHashInterface","GetKeyDerivationInterface","GetRngInterface","GetSecretAgreementInterface","GetSignatureInterface","MSCryptConvertRsaPrivateBlobToFullRsaBlob"};
    ex_family("bcryptprimitives.dll", n, 8);
}
TEST(exports_cng_capi_ncrypt_family_BCrypt) {
    static const char *const n[] = {"BCryptAddContextFunction","BCryptAddContextFunctionProvider","BCryptCloseAlgorithmProvider","BCryptConfigureContext","BCryptConfigureContextFunction","BCryptCreateContext","BCryptCreateHash","BCryptDecrypt","BCryptDeleteContext","BCryptDeriveKey","BCryptDeriveKeyCapi","BCryptDeriveKeyPBKDF2","BCryptDestroyHash","BCryptDestroyKey","BCryptDestroySecret","BCryptDuplicateHash","BCryptDuplicateKey","BCryptEncrypt","BCryptEnumAlgorithms","BCryptEnumContextFunctionProviders","BCryptEnumContextFunctions","BCryptEnumContexts","BCryptEnumProviders","BCryptEnumRegisteredProviders","BCryptExportKey","BCryptFinalizeKeyPair","BCryptFinishHash","BCryptFreeBuffer","BCryptGenRandom","BCryptGenerateKeyPair","BCryptGenerateSymmetricKey","BCryptGetFipsAlgorithmMode","BCryptGetProperty","BCryptHash","BCryptHashData","BCryptImportKey","BCryptImportKeyPair","BCryptKeyDerivation","BCryptOpenAlgorithmProvider","BCryptQueryContextConfiguration","BCryptQueryContextFunctionConfiguration","BCryptQueryContextFunctionProperty","BCryptQueryProviderRegistration","BCryptRegisterConfigChangeNotify","BCryptRegisterProvider","BCryptRemoveContextFunction","BCryptRemoveContextFunctionProvider","BCryptResolveProviders","BCryptSecretAgreement","BCryptSetAuditingInterface","BCryptSetContextFunctionProperty","BCryptSetProperty","BCryptSignHash","BCryptUnregisterConfigChangeNotify","BCryptUnregisterProvider","BCryptVerifySignature"};
    ex_family("ncrypt.dll", n, 56);
}
TEST(exports_cng_capi_ncrypt_family_NCrypt) {
    static const char *const n[] = {"NCryptCloseKeyProtector","NCryptCloseProtectionDescriptor","NCryptCreateClaim","NCryptCreatePersistedKey","NCryptCreateProtectionDescriptor","NCryptDecrypt","NCryptDeleteKey","NCryptDeriveKey","NCryptDuplicateKeyProtectorHandle","NCryptEncrypt","NCryptEnumAlgorithms","NCryptEnumKeys","NCryptEnumStorageProviders","NCryptExportKey","NCryptFinalizeKey","NCryptFreeBuffer","NCryptFreeObject","NCryptGetProperty","NCryptGetProtectionDescriptorInfo","NCryptImportKey","NCryptIsAlgSupported","NCryptIsKeyHandle","NCryptKeyDerivation","NCryptNotifyChangeKey","NCryptOpenKey","NCryptOpenKeyProtector","NCryptOpenStorageProvider","NCryptProtectKey","NCryptProtectSecret","NCryptQueryProtectionDescriptorName","NCryptRegisterProtectionDescriptorName","NCryptSecretAgreement","NCryptSetAuditingInterface","NCryptSetProperty","NCryptSignHash","NCryptStreamClose","NCryptStreamOpenToProtect","NCryptStreamOpenToUnprotect","NCryptStreamOpenToUnprotectEx","NCryptStreamUpdate","NCryptTranslateHandle","NCryptUnprotectKey","NCryptUnprotectSecret","NCryptVerifyClaim","NCryptVerifySignature"};
    ex_family("ncrypt.dll", n, 45);
}
TEST(exports_cng_capi_ncrypt_family_misc) {
    static const char *const n[] = {"GetIsolationServerInterface","GetKeyStorageInterface","GetSChannelInterface"};
    ex_family("ncrypt.dll", n, 3);
}
TEST(exports_cng_capi_ncryptprov_family_misc) {
    static const char *const n[] = {"GetKeyStorageInterface","SKCacheFlush","SetAuditingInterface"};
    ex_family("ncryptprov.dll", n, 3);
}
TEST(exports_cng_capi_cryptsp_family_CryptAcquire) {
    static const char *const n[] = {"CryptAcquireContextA","CryptAcquireContextW"};
    ex_family("cryptsp.dll", n, 2);
}
TEST(exports_cng_capi_cryptsp_family_CryptDestroy) {
    static const char *const n[] = {"CryptDestroyHash","CryptDestroyKey"};
    ex_family("cryptsp.dll", n, 2);
}
TEST(exports_cng_capi_cryptsp_family_CryptDuplicate) {
    static const char *const n[] = {"CryptDuplicateHash","CryptDuplicateKey"};
    ex_family("cryptsp.dll", n, 2);
}
TEST(exports_cng_capi_cryptsp_family_CryptEnum) {
    static const char *const n[] = {"CryptEnumProviderTypesA","CryptEnumProviderTypesW","CryptEnumProvidersA","CryptEnumProvidersW"};
    ex_family("cryptsp.dll", n, 4);
}
TEST(exports_cng_capi_cryptsp_family_CryptGen) {
    static const char *const n[] = {"CryptGenKey","CryptGenRandom"};
    ex_family("cryptsp.dll", n, 2);
}
TEST(exports_cng_capi_cryptsp_family_CryptGet) {
    static const char *const n[] = {"CryptGetDefaultProviderA","CryptGetDefaultProviderW","CryptGetHashParam","CryptGetKeyParam","CryptGetProvParam","CryptGetUserKey"};
    ex_family("cryptsp.dll", n, 6);
}
TEST(exports_cng_capi_cryptsp_family_CryptHash) {
    static const char *const n[] = {"CryptHashData","CryptHashSessionKey"};
    ex_family("cryptsp.dll", n, 2);
}
TEST(exports_cng_capi_cryptsp_family_CryptSet) {
    static const char *const n[] = {"CryptSetHashParam","CryptSetKeyParam","CryptSetProvParam","CryptSetProviderA","CryptSetProviderExA","CryptSetProviderExW","CryptSetProviderW"};
    ex_family("cryptsp.dll", n, 7);
}
TEST(exports_cng_capi_cryptsp_family_CryptSign) {
    static const char *const n[] = {"CryptSignHashA","CryptSignHashW"};
    ex_family("cryptsp.dll", n, 2);
}
TEST(exports_cng_capi_cryptsp_family_CryptVerify) {
    static const char *const n[] = {"CryptVerifySignatureA","CryptVerifySignatureW"};
    ex_family("cryptsp.dll", n, 2);
}
TEST(exports_cng_capi_cryptsp_family_misc) {
    static const char *const n[] = {"CheckSignatureInFile","CryptContextAddRef","CryptCreateHash","CryptDecrypt","CryptDeriveKey","CryptEncrypt","CryptExportKey","CryptImportKey","CryptReleaseContext","SystemFunction006","SystemFunction007","SystemFunction008","SystemFunction009","SystemFunction010","SystemFunction011","SystemFunction012","SystemFunction013","SystemFunction014","SystemFunction015","SystemFunction016","SystemFunction018","SystemFunction020","SystemFunction021","SystemFunction022","SystemFunction023","SystemFunction024","SystemFunction025","SystemFunction026","SystemFunction027","SystemFunction030","SystemFunction031","SystemFunction032","SystemFunction033","SystemFunction035"};
    ex_family("cryptsp.dll", n, 34);
}
TEST(exports_cng_capi_cryptbase_family_misc) {
    static const char *const n[] = {"SystemFunction001","SystemFunction002","SystemFunction003","SystemFunction004","SystemFunction005","SystemFunction028","SystemFunction029","SystemFunction034","SystemFunction036","SystemFunction040","SystemFunction041"};
    ex_family("cryptbase.dll", n, 11);
}
TEST(exports_cng_capi_cryptdll_family_CD) {
    static const char *const n[] = {"CDBuildIntegrityVect","CDBuildVect","CDFindCommonCSystem","CDFindCommonCSystemWithKey","CDGenerateRandomBits","CDGetIntegrityVect","CDLocateCSystem","CDLocateCheckSum","CDLocateRng","CDRegisterCSystem","CDRegisterCheckSum","CDRegisterRng"};
    ex_family("cryptdll.dll", n, 12);
}
TEST(exports_cng_capi_cryptdll_family_MD5) {
    static const char *const n[] = {"MD5Final","MD5Init","MD5Update"};
    ex_family("cryptdll.dll", n, 3);
}
TEST(exports_cng_capi_cryptdll_family_CT) {
    static const char *const n[] = {"aesCTSDecryptMsg","aesCTSEncryptMsg"};
    ex_family("cryptdll.dll", n, 2);
}
TEST(exports_cng_capi_cryptdll_family_misc) {
    static const char *const n[] = {"HMACwithSHA","KRBFXCF2","PBKDF2"};
    ex_family("cryptdll.dll", n, 3);
}
TEST(exports_cng_capi_dpapi_family_CryptProtect) {
    static const char *const n[] = {"CryptProtectDataNoUI","CryptProtectMemory"};
    ex_family("dpapi.dll", n, 2);
}
TEST(exports_cng_capi_dpapi_family_CryptUnprotect) {
    static const char *const n[] = {"CryptUnprotectDataNoUI","CryptUnprotectMemory"};
    ex_family("dpapi.dll", n, 2);
}
TEST(exports_cng_capi_dpapi_family_misc) {
    static const char *const n[] = {"CryptResetMachineCredentials","CryptUpdateProtectedState","iCryptIdentifyProtection"};
    ex_family("dpapi.dll", n, 3);
}
TEST(exports_cng_capi_rsaenh_family_CP) {
    static const char *const n[] = {"CPAcquireContext","CPCreateHash","CPDecrypt","CPDeriveKey","CPDestroyHash","CPDestroyKey","CPDuplicateHash","CPDuplicateKey","CPEncrypt","CPExportKey","CPGenKey","CPGenRandom","CPGetHashParam","CPGetKeyParam","CPGetProvParam","CPGetUserKey","CPHashData","CPHashSessionKey","CPImportKey","CPReleaseContext","CPSetHashParam","CPSetKeyParam","CPSetProvParam","CPSignHash","CPVerifySignature"};
    ex_family("rsaenh.dll", n, 25);
}
TEST(exports_cng_capi_rsaenh_family_misc) {
    static const char *const n[] = {"DllRegisterServer","DllUnregisterServer"};
    ex_family("rsaenh.dll", n, 2);
}
TEST(exports_cng_capi_dssenh_family_CP) {
    static const char *const n[] = {"CPAcquireContext","CPCreateHash","CPDecrypt","CPDeriveKey","CPDestroyHash","CPDestroyKey","CPDuplicateHash","CPDuplicateKey","CPEncrypt","CPExportKey","CPGenKey","CPGenRandom","CPGetHashParam","CPGetKeyParam","CPGetProvParam","CPGetUserKey","CPHashData","CPHashSessionKey","CPImportKey","CPReleaseContext","CPSetHashParam","CPSetKeyParam","CPSetProvParam","CPSignHash","CPVerifySignature"};
    ex_family("dssenh.dll", n, 25);
}
TEST(exports_cng_capi_dssenh_family_misc) {
    static const char *const n[] = {"DllRegisterServer","DllUnregisterServer"};
    ex_family("dssenh.dll", n, 2);
}
TEST(exports_cng_capi_advapi32_family_CryptAcquire) {
    static const char *const n[] = {"CryptAcquireContextA","CryptAcquireContextW"};
    ex_family("advapi32.dll", n, 2);
}
TEST(exports_cng_capi_advapi32_family_CryptDestroy) {
    static const char *const n[] = {"CryptDestroyHash","CryptDestroyKey"};
    ex_family("advapi32.dll", n, 2);
}
TEST(exports_cng_capi_advapi32_family_CryptDuplicate) {
    static const char *const n[] = {"CryptDuplicateHash","CryptDuplicateKey"};
    ex_family("advapi32.dll", n, 2);
}
TEST(exports_cng_capi_advapi32_family_CryptEnum) {
    static const char *const n[] = {"CryptEnumProviderTypesA","CryptEnumProviderTypesW","CryptEnumProvidersA","CryptEnumProvidersW"};
    ex_family("advapi32.dll", n, 4);
}
TEST(exports_cng_capi_advapi32_family_CryptGen) {
    static const char *const n[] = {"CryptGenKey","CryptGenRandom"};
    ex_family("advapi32.dll", n, 2);
}
TEST(exports_cng_capi_advapi32_family_CryptGet) {
    static const char *const n[] = {"CryptGetDefaultProviderA","CryptGetDefaultProviderW","CryptGetHashParam","CryptGetKeyParam","CryptGetProvParam","CryptGetUserKey"};
    ex_family("advapi32.dll", n, 6);
}
TEST(exports_cng_capi_advapi32_family_CryptHash) {
    static const char *const n[] = {"CryptHashData","CryptHashSessionKey"};
    ex_family("advapi32.dll", n, 2);
}
TEST(exports_cng_capi_advapi32_family_CryptSet) {
    static const char *const n[] = {"CryptSetHashParam","CryptSetKeyParam","CryptSetProvParam","CryptSetProviderA","CryptSetProviderExA","CryptSetProviderExW","CryptSetProviderW"};
    ex_family("advapi32.dll", n, 7);
}
TEST(exports_cng_capi_advapi32_family_CryptSign) {
    static const char *const n[] = {"CryptSignHashA","CryptSignHashW"};
    ex_family("advapi32.dll", n, 2);
}
TEST(exports_cng_capi_advapi32_family_CryptVerify) {
    static const char *const n[] = {"CryptVerifySignatureA","CryptVerifySignatureW"};
    ex_family("advapi32.dll", n, 2);
}
TEST(exports_cng_capi_advapi32_family_misc) {
    static const char *const n[] = {"CryptContextAddRef","CryptCreateHash","CryptDecrypt","CryptDeriveKey","CryptEncrypt","CryptExportKey","CryptImportKey","CryptReleaseContext","SystemFunction001","SystemFunction002","SystemFunction003","SystemFunction004","SystemFunction005","SystemFunction006","SystemFunction007","SystemFunction008","SystemFunction009","SystemFunction010","SystemFunction011","SystemFunction012","SystemFunction013","SystemFunction014","SystemFunction015","SystemFunction016","SystemFunction017","SystemFunction018","SystemFunction019","SystemFunction020","SystemFunction021","SystemFunction022","SystemFunction023","SystemFunction024","SystemFunction025","SystemFunction026","SystemFunction027","SystemFunction028","SystemFunction029","SystemFunction030","SystemFunction031","SystemFunction032","SystemFunction033","SystemFunction034","SystemFunction035","SystemFunction036","SystemFunction040","SystemFunction041"};
    ex_family("advapi32.dll", n, 46);
}
