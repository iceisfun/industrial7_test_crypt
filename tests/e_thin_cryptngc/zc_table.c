#include "zc.h"

ZT(NgcAddBioProtector, "cryptngc.dll", 0x80090027, 0x0)
ZT(NgcAddCompanionDeviceProtector, "cryptngc.dll", 0x80090027, 0x0)
ZT(NgcAddPrebootProtector, "cryptngc.dll", 0x80090027, 0x0)
ZF(NgcCancelPendingUIRequest, "cryptngc.dll")
ZT(NgcChangePin, "cryptngc.dll", 0x80090027, 0x0)
ZT(NgcChangePinSilent, "cryptngc.dll", 0x80090027, 0x0)
ZT(NgcCreateContainer, "cryptngc.dll", 0x80090027, 0x0)
ZT(NgcCreateContainerSilent, "cryptngc.dll", 0x80090027, 0x0)
ZT(NgcCreateTicketForSmartCardKeyOperation, "cryptngc.dll", 0x80090027, 0x0)
ZT(NgcCreateTicketForSmartCardVpn, "cryptngc.dll", 0x800706f4, 0x0)
ZT(NgcCreateUserIdKey, "cryptngc.dll", 0x80090027, 0x0)
ZT(NgcCreateUserIdKeyEx, "cryptngc.dll", 0x80090027, 0x0)
ZT(NgcCreateUserIdKeyHandle, "cryptngc.dll", 0x80090027, 0x0)
ZT(NgcDecryptWithSymmetricPopKey, "cryptngc.dll", 0x80090027, 0x0)
ZT(NgcDecryptWithUserIdKey, "cryptngc.dll", 0x80090027, 0x0)
ZT(NgcDecryptWithUserIdKeySilent, "cryptngc.dll", 0x80090027, 0x0)
ZT(NgcDeleteContainer, "cryptngc.dll", 0x80090027, 0x0)
ZT(NgcDeleteContainerEx, "cryptngc.dll", 0x80090027, 0x0)
ZT(NgcDeleteSymmetricPopKeyTransportKey, "cryptngc.dll", 0x80090027, 0x0)
ZT(NgcDeleteUserIdKey, "cryptngc.dll", 0x80090027, 0x0)
ZT(NgcEncryptWithAsymmetricKey, "cryptngc.dll", 0x80090027, 0x0)
ZT(NgcEncryptWithSymmetricPopKey, "cryptngc.dll", 0x80090027, 0x0)
ZT(NgcEnumContainers, "cryptngc.dll", 0x80090027, 0x0)
ZT(NgcEnumUserIdKeys, "cryptngc.dll", 0x80090027, 0x0)
ZT(NgcFreeEnumState, "cryptngc.dll", 0x80004003, 0x0)
ZT(NgcGetDefaultDecryptionKeyName, "cryptngc.dll", 0x80090027, 0x0)
ZT(NgcGetKeyAttestationForContainerService, "cryptngc.dll", 0x80090027, 0x0)
ZT(NgcGetKeyAttestationForUserIdKey, "cryptngc.dll", 0x80090027, 0x0)
ZF(NgcGetKeyAttestationForUserIdKey2, "cryptngc.dll")
ZT(NgcGetKeyImplType, "cryptngc.dll", 0x80090027, 0x0)
ZT(NgcGetLogonDecryptionKeyName, "cryptngc.dll", 0x80090027, 0x0)
ZT(NgcGetLogonDecryptionKeyNameForFirstLogonAfterUpgradeFromThreshold, "cryptngc.dll", 0x80090027, 0x0)
ZT(NgcGetPkcs7ChainBlobFromCertificateBlob, "cryptngc.dll", 0x80004003, 0x0)
ZT(NgcGetPolicy, "cryptngc.dll", 0x80090027, 0x0)
ZT(NgcGetPregenKeyState, "cryptngc.dll", 0x80090027, 0x0)
ZT(NgcGetPregenUserKey, "cryptngc.dll", 0x80090027, 0x0)
ZT(NgcGetSymmetricPopKeyTransportKeyName, "cryptngc.dll", 0x80090027, 0x0)
ZT(NgcGetUserIdKeyCertificate, "cryptngc.dll", 0x80090027, 0x0)
ZT(NgcGetUserIdKeyContainerStatus, "cryptngc.dll", 0x80090027, 0x0)
ZF(NgcGetUserIdKeyName, "cryptngc.dll")
ZT(NgcGetUserIdKeyPublicKey, "cryptngc.dll", 0x80090027, 0x0)
ZT(NgcImportSymmetricPopKey, "cryptngc.dll", 0x80090027, 0x0)
ZT(NgcIsAnyContainerInVsm, "cryptngc.dll", 0x800706f4, 0x0)
ZT(NgcIsPinRemovable, "cryptngc.dll", 0x80090027, 0x0)
/* Result depends on whether the container service has registered its RPC endpoint yet (it starts on its own a while after boot):
   probed on Win10 22H2 in std and adm, stopped -> EPT_S_NOT_REGISTERED (0x800706d9), running -> NTE_PERM (0x80090010), last error 0 in both. */
static int zc_ngcctnr_running(void) {
    SC_HANDLE m = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT), s = m ? OpenServiceA(m, "NgcCtnrSvc", SERVICE_QUERY_STATUS) : NULL;
    SERVICE_STATUS st; int run = -1;
    if (s && QueryServiceStatus(s, &st)) run = st.dwCurrentState == SERVICE_RUNNING;
    if (s) CloseServiceHandle(s);
    if (m) CloseServiceHandle(m);
    return run;
}
TEST(zc_NgcNotifyVscProvisioned) {
    zc_fn f = zc_get("cryptngc.dll", "NgcNotifyVscProvisioned"); DWORD ge = 0; volatile ULONG_PTR r = 0; int run = zc_ngcctnr_running();
    if (!f) return;
    REQUIRE_EQ(run == 0 || run == 1, 1);
    T_TRY( r = T_CALL_ERR(&ge, f(0,0,0,0,0,0,0,0)) );
    int run2 = zc_ngcctnr_running();
    if (run == run2) { EXPECT_EQ((DWORD)r, run ? (DWORD)0x80090010 : (DWORD)0x800706d9); EXPECT_EQ(ge, (DWORD)0x0); }
    else t_note("service state changed during the call (%d -> %d): ret 0x%08lx", run, run2, (DWORD)r);
}
ZT(NgcOpenUserIdKey, "cryptngc.dll", 0x80090027, 0x0)
ZF(NgcQueryEffectiveCertPolicy, "cryptngc.dll")
ZF(NgcQueryEnabled, "cryptngc.dll")
ZF(NgcQueryHardwarePolicy, "cryptngc.dll")
ZT(NgcRemoveBioProtector, "cryptngc.dll", 0x80090027, 0x0)
ZT(NgcRemoveCompanionDeviceProtector, "cryptngc.dll", 0x80090027, 0x0)
ZT(NgcRemovePrebootProtector, "cryptngc.dll", 0x80090027, 0x0)
ZT(NgcRenewKeyAttestation, "cryptngc.dll", 0x80090027, 0x0)
ZT(NgcSignWithSymmetricPopKey, "cryptngc.dll", 0x80090027, 0x0)
ZT(NgcSignWithUserIdKey, "cryptngc.dll", 0x80090027, 0x0)
ZT(NgcSignWithUserIdKeyAndPadding, "cryptngc.dll", 0x80090027, 0x0)
ZT(NgcSignWithUserIdKeyEx, "cryptngc.dll", 0x80090027, 0x0)
ZT(NgcSignWithUserIdKeySilent, "cryptngc.dll", 0x80090027, 0x0)
ZT(NgcUnpackPasswordChangeAuthBuffer, "cryptngc.dll", 0x80004003, 0x0)
ZT(NgcVerifyWithSymmetricPopKey, "cryptngc.dll", 0x80090027, 0x0)
