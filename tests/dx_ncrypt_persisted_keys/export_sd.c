#include "dxk.h"

/* export policy */
static SECURITY_STATUS exp_blob(NCRYPT_KEY_HANDLE k, const WCHAR *type, DWORD fl, DWORD *cb)
{ BYTE buf[4096]; *cb = 0; return U(NCryptExportKey)(k, 0, type, NULL, buf, sizeof buf, cb, fl); }

TEST(dxpk_export_public_always_allowed) {
    KP_BEGIN(p); WCHAR n[96]; k_name(n, 96, L"expub"); NCRYPT_KEY_HANDLE k = 0; REQUIRE(U(NCryptExportKey));
    EXPECT_S(k_make(p, n, BCRYPT_RSA_ALGORITHM, 1024, 0, 0, &k), 0);
    DWORD cb = 0;
    EXPECT_S(exp_blob(k, BCRYPT_RSAPUBLIC_BLOB, 0, &cb), 0);
    CHECK(cb > sizeof(BCRYPT_RSAKEY_BLOB));
    BYTE b[4096]; U(NCryptExportKey)(k, 0, BCRYPT_RSAPUBLIC_BLOB, NULL, b, sizeof b, &cb, 0);
    BCRYPT_RSAKEY_BLOB *h = (BCRYPT_RSAKEY_BLOB *)b;
    EXPECT_EQ(h->Magic, BCRYPT_RSAPUBLIC_MAGIC); EXPECT_EQ(h->BitLength, 1024);
    k_del(p, n, 0); k_free(p);
}
TEST(dxpk_export_private_denied_by_default) {
    KP_BEGIN(p); WCHAR n[96]; k_name(n, 96, L"exdeny"); NCRYPT_KEY_HANDLE k = 0; REQUIRE(U(NCryptExportKey));
    EXPECT_S(k_make(p, n, BCRYPT_RSA_ALGORITHM, 1024, 0, 0, &k), 0);
    const WCHAR *types[] = { BCRYPT_RSAFULLPRIVATE_BLOB, BCRYPT_RSAPRIVATE_BLOB, NCRYPT_PKCS8_PRIVATE_KEY_BLOB };
    for (int i = 0; i < 3; i++) {
        DWORD cb = 0xdead; SECURITY_STATUS s = exp_blob(k, types[i], 0, &cb);
        CHECKF(s != 0, "type %d exported without allow flag", i);
        t_note("export %ls from non-exportable key -> 0x%08lx", types[i], S(s));
    }
    /* the PKCS8 export with a password-protected container is private as well */
    k_del(p, n, 0); k_free(p);
}
TEST(dxpk_export_policy_allow_flag_enables_private) {
    KP_BEGIN(p); WCHAR n[96]; k_name(n, 96, L"exallow"); NCRYPT_KEY_HANDLE k = 0; REQUIRE(U(NCryptExportKey));
    EXPECT_S(U(NCryptCreatePersistedKey)(p, &k, BCRYPT_RSA_ALGORITHM, n, 0, 0), 0);
    DWORD bits = 1024, pol = NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG;
    EXPECT_S(U(NCryptSetProperty)(k, NCRYPT_LENGTH_PROPERTY, (PBYTE)&bits, 4, 0), 0);
    EXPECT_S(U(NCryptSetProperty)(k, NCRYPT_EXPORT_POLICY_PROPERTY, (PBYTE)&pol, 4, NCRYPT_PERSIST_FLAG), 0);
    EXPECT_S(U(NCryptFinalizeKey)(k, 0), 0);
    DWORD cb;
    EXPECT_S(exp_blob(k, BCRYPT_RSAFULLPRIVATE_BLOB, 0, &cb), 0);
    CHECK(cb > 200);
    DWORD v = 0, rc; EXPECT_S(U(NCryptGetProperty)(k, NCRYPT_EXPORT_POLICY_PROPERTY, (PBYTE)&v, 4, &rc, 0), 0);
    EXPECT_EQ(v, NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG);
    /* policy survives close/reopen */
    k_free(k); k = 0;
    EXPECT_S(U(NCryptOpenKey)(p, &k, n, 0, 0), 0);
    if (k) { EXPECT_S(exp_blob(k, BCRYPT_RSAFULLPRIVATE_BLOB, 0, &cb), 0); k_free(k); }
    k_del(p, n, 0); k_free(p);
}
TEST(dxpk_export_policy_default_value_note) {
    KP_BEGIN(p); WCHAR n[96]; k_name(n, 96, L"expolnote"); NCRYPT_KEY_HANDLE k = 0;
    EXPECT_S(k_make(p, n, BCRYPT_RSA_ALGORITHM, 1024, 0, 0, &k), 0);
    DWORD v = 0xff, cb; SECURITY_STATUS s = U(NCryptGetProperty)(k, NCRYPT_EXPORT_POLICY_PROPERTY, (PBYTE)&v, 4, &cb, 0);
    EXPECT_S(s, 0); EXPECT_EQ(v & NCRYPT_ALLOW_EXPORT_FLAG, 0);
    t_note("default export policy 0x%lx", v);
    k_del(p, n, 0); k_free(p);
}
TEST(dxpk_export_policy_cannot_be_raised) {
    KP_BEGIN(p); WCHAR n[96]; k_name(n, 96, L"expolraise"); NCRYPT_KEY_HANDLE k = 0;
    EXPECT_S(k_make(p, n, BCRYPT_RSA_ALGORITHM, 1024, 0, 0, &k), 0);
    DWORD pol = NCRYPT_ALLOW_EXPORT_FLAG;
    SECURITY_STATUS s = U(NCryptSetProperty)(k, NCRYPT_EXPORT_POLICY_PROPERTY, (PBYTE)&pol, 4, NCRYPT_PERSIST_FLAG);
    t_note("raise export policy after finalize -> 0x%08lx", S(s));
    k_del(p, n, 0); k_free(p);
}
TEST(dxpk_export_plaintext_flag_note) {
    KP_BEGIN(p); WCHAR n[96]; k_name(n, 96, L"explain"); NCRYPT_KEY_HANDLE k = 0; REQUIRE(U(NCryptExportKey));
    EXPECT_S(U(NCryptCreatePersistedKey)(p, &k, BCRYPT_RSA_ALGORITHM, n, 0, 0), 0);
    DWORD bits = 1024, pol = NCRYPT_ALLOW_EXPORT_FLAG;
    U(NCryptSetProperty)(k, NCRYPT_LENGTH_PROPERTY, (PBYTE)&bits, 4, 0);
    U(NCryptSetProperty)(k, NCRYPT_EXPORT_POLICY_PROPERTY, (PBYTE)&pol, 4, NCRYPT_PERSIST_FLAG);
    EXPECT_S(U(NCryptFinalizeKey)(k, 0), 0);
    /* observed on Win10: with ALLOW_EXPORT only, plaintext private blobs are NTE_NOT_SUPPORTED; only the encrypted opaque transport blob exports */
    DWORD cb; SECURITY_STATUS s = exp_blob(k, BCRYPT_RSAFULLPRIVATE_BLOB, 0, &cb);
    EXPECT_S(s, NTE_NOT_SUPPORTED);
    s = exp_blob(k, NCRYPT_PKCS8_PRIVATE_KEY_BLOB, 0, &cb);
    EXPECT_S(s, NTE_NOT_SUPPORTED);
    s = exp_blob(k, NCRYPT_OPAQUETRANSPORT_BLOB, 0, &cb);
    EXPECT_S(s, 0);
    k_del(p, n, 0); k_free(p);
}
TEST(dxpk_export_size_protocol_public) {
    KP_BEGIN(p); WCHAR n[96]; k_name(n, 96, L"exsize"); NCRYPT_KEY_HANDLE k = 0; REQUIRE(U(NCryptExportKey));
    EXPECT_S(k_make(p, n, BCRYPT_RSA_ALGORITHM, 1024, 0, 0, &k), 0);
    DWORD need = 0, cb = 0; BYTE buf[2048];
    EXPECT_S(U(NCryptExportKey)(k, 0, BCRYPT_RSAPUBLIC_BLOB, NULL, NULL, 0, &need, 0), 0);
    CHECK(need > 0);
    EXPECT_S(U(NCryptExportKey)(k, 0, BCRYPT_RSAPUBLIC_BLOB, NULL, buf, 10, &cb, 0), NTE_BUFFER_TOO_SMALL);
    EXPECT_EQ(cb, need);
    /* observed on Win10: a public-blob buffer one byte short is accepted */
    cb = 0; EXPECT_S(U(NCryptExportKey)(k, 0, BCRYPT_RSAPUBLIC_BLOB, NULL, buf, need - 1, &cb, 0), 0);
    EXPECT_EQ(cb, need);
    EXPECT_S(U(NCryptExportKey)(k, 0, BCRYPT_RSAPUBLIC_BLOB, NULL, buf, need, &cb, 0), 0);
    EXPECT_EQ(cb, need);
    { SECURITY_STATUS sn = U(NCryptExportKey)(k, 0, BCRYPT_RSAPUBLIC_BLOB, NULL, buf, need, NULL, 0); t_note("export NULL pcbResult -> 0x%08lx", S(sn)); }
    k_del(p, n, 0); k_free(p);
}
TEST(dxpk_export_after_reopen_matches) {
    KP_BEGIN(p); WCHAR n[96]; k_name(n, 96, L"exreopen"); NCRYPT_KEY_HANDLE k = 0, k2 = 0; REQUIRE(U(NCryptExportKey));
    EXPECT_S(k_make(p, n, BCRYPT_RSA_ALGORITHM, 1024, 0, 0, &k), 0);
    BYTE a[2048], b[2048]; DWORD ca = 0, cb = 0;
    EXPECT_S(U(NCryptExportKey)(k, 0, BCRYPT_RSAPUBLIC_BLOB, NULL, a, sizeof a, &ca, 0), 0);
    k_free(k);
    EXPECT_S(U(NCryptOpenKey)(p, &k2, n, 0, 0), 0);
    EXPECT_S(U(NCryptExportKey)(k2, 0, BCRYPT_RSAPUBLIC_BLOB, NULL, b, sizeof b, &cb, 0), 0);
    EXPECT_EQ(ca, cb); CHECK(ca == cb && !memcmp(a, b, ca));
    k_free(k2); k_del(p, n, 0); k_free(p);
}

/* sign/verify with persisted key (PKCS1 is deterministic) */
TEST(dxpk_persisted_key_sign_verify_after_reopen) {
    KP_BEGIN(p); WCHAR n[96]; k_name(n, 96, L"sig"); NCRYPT_KEY_HANDLE k = 0, k2 = 0;
    REQUIRE(U(NCryptSignHash)); REQUIRE(U(NCryptVerifySignature));
    EXPECT_S(k_make(p, n, BCRYPT_RSA_ALGORITHM, 1024, AT_SIGNATURE, 0, &k), 0);
    BYTE hash[32]; for (int i = 0; i < 32; i++) hash[i] = (BYTE)(i * 7 + 1);
    BCRYPT_PKCS1_PADDING_INFO pi = { BCRYPT_SHA256_ALGORITHM };
    BYTE s1[256], s2[256]; DWORD c1 = 0, c2 = 0;
    EXPECT_S(U(NCryptSignHash)(k, &pi, hash, 32, NULL, 0, &c1, BCRYPT_PAD_PKCS1), 0);
    EXPECT_EQ(c1, 128);
    EXPECT_S(U(NCryptSignHash)(k, &pi, hash, 32, s1, sizeof s1, &c1, BCRYPT_PAD_PKCS1), 0);
    k_free(k);
    EXPECT_S(U(NCryptOpenKey)(p, &k2, n, AT_SIGNATURE, 0), 0);
    EXPECT_S(U(NCryptSignHash)(k2, &pi, hash, 32, s2, sizeof s2, &c2, BCRYPT_PAD_PKCS1), 0);
    EXPECT_EQ(c1, c2); CHECK(c1 == c2 && !memcmp(s1, s2, c1));
    EXPECT_S(U(NCryptVerifySignature)(k2, &pi, hash, 32, s1, c1, BCRYPT_PAD_PKCS1), 0);
    hash[0] ^= 1;
    EXPECT_S(U(NCryptVerifySignature)(k2, &pi, hash, 32, s1, c1, BCRYPT_PAD_PKCS1), NTE_BAD_SIGNATURE);
    k_free(k2); k_del(p, n, 0); k_free(p);
}
TEST(dxpk_ecdsa_persisted_key_sign_verify) {
    KP_BEGIN(p); WCHAR n[96]; k_name(n, 96, L"ecsig"); NCRYPT_KEY_HANDLE k = 0, k2 = 0;
    REQUIRE(U(NCryptSignHash)); REQUIRE(U(NCryptVerifySignature));
    if (k_make(p, n, BCRYPT_ECDSA_P256_ALGORITHM, 0, 0, 0, &k)) { t_skip("no ECDSA persisted support"); k_free(p); return; }
    BYTE hash[32] = {1,2,3}; BYTE sg[64]; DWORD cb = 0;
    EXPECT_S(U(NCryptSignHash)(k, NULL, hash, 32, sg, sizeof sg, &cb, 0), 0);
    EXPECT_EQ(cb, 64);
    k_free(k);
    EXPECT_S(U(NCryptOpenKey)(p, &k2, n, 0, 0), 0);
    EXPECT_S(U(NCryptVerifySignature)(k2, NULL, hash, 32, sg, cb, 0), 0);
    k_free(k2); k_del(p, n, 0); k_free(p);
}

/* security descriptor property */
static int sd_get(NCRYPT_KEY_HANDLE k, DWORD secinfo, BYTE *buf, DWORD cap, DWORD *cb, SECURITY_STATUS *st)
{ *st = U(NCryptGetProperty)(k, NCRYPT_SECURITY_DESCR_PROPERTY, buf, cap, cb, secinfo); return *st == 0; }

TEST(dxpk_sd_get_dacl) {
    KP_BEGIN(p); WCHAR n[96]; k_name(n, 96, L"sdget"); NCRYPT_KEY_HANDLE k = 0; BYTE buf[2048]; DWORD cb = 0; SECURITY_STATUS s;
    EXPECT_S(k_make(p, n, BCRYPT_RSA_ALGORITHM, 1024, 0, 0, &k), 0);
    s = U(NCryptGetProperty)(k, NCRYPT_SECURITY_DESCR_PROPERTY, NULL, 0, &cb, DACL_SECURITY_INFORMATION);
    EXPECT_S(s, 0); CHECK(cb >= sizeof(SECURITY_DESCRIPTOR_RELATIVE) || cb > 20);
    DWORD need = cb;
    if (need && need < sizeof buf) {
        EXPECT_S(U(NCryptGetProperty)(k, NCRYPT_SECURITY_DESCR_PROPERTY, buf, need - 1, &cb, DACL_SECURITY_INFORMATION), NTE_BUFFER_TOO_SMALL);
        EXPECT_S(U(NCryptGetProperty)(k, NCRYPT_SECURITY_DESCR_PROPERTY, buf, need, &cb, DACL_SECURITY_INFORMATION), 0);
        CHECK(IsValidSecurityDescriptor(buf));
        BOOL present = FALSE, def = FALSE; PACL acl = NULL;
        CHECK(GetSecurityDescriptorDacl(buf, &present, &acl, &def));
        CHECK(present);
    }
    k_del(p, n, 0); k_free(p);
}
TEST(dxpk_sd_get_owner_group) {
    KP_BEGIN(p); WCHAR n[96]; k_name(n, 96, L"sdown"); NCRYPT_KEY_HANDLE k = 0; BYTE buf[2048]; DWORD cb = 0; SECURITY_STATUS s;
    EXPECT_S(k_make(p, n, BCRYPT_RSA_ALGORITHM, 1024, 0, 0, &k), 0);
    if (sd_get(k, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION, buf, sizeof buf, &cb, &s)) {
        PSID o = NULL; BOOL def; CHECK(IsValidSecurityDescriptor(buf));
        CHECK(GetSecurityDescriptorOwner(buf, &o, &def)); CHECK(o != NULL && IsValidSid(o));
    } else t_note("owner/group read -> 0x%08lx", S(s));
    k_del(p, n, 0); k_free(p);
}
TEST(dxpk_sd_get_invalid_secinfo_note) {
    KP_BEGIN(p); WCHAR n[96]; k_name(n, 96, L"sdbad"); NCRYPT_KEY_HANDLE k = 0; BYTE buf[2048]; DWORD cb = 0;
    EXPECT_S(k_make(p, n, BCRYPT_RSA_ALGORITHM, 1024, 0, 0, &k), 0);
    SECURITY_STATUS s = U(NCryptGetProperty)(k, NCRYPT_SECURITY_DESCR_PROPERTY, buf, sizeof buf, &cb, 0);
    t_note("get SD with flags 0 -> 0x%08lx cb=%lu", S(s), cb);
    s = U(NCryptGetProperty)(k, NCRYPT_SECURITY_DESCR_PROPERTY, buf, sizeof buf, &cb, SACL_SECURITY_INFORMATION);
    t_note("get SD with SACL info (unprivileged) -> 0x%08lx", S(s));
    k_del(p, n, 0); k_free(p);
}
TEST(dxpk_sd_roundtrip_set_same) {
    KP_BEGIN(p); WCHAR n[96]; k_name(n, 96, L"sdrt"); NCRYPT_KEY_HANDLE k = 0; BYTE buf[2048]; DWORD cb = 0; SECURITY_STATUS s;
    EXPECT_S(k_make(p, n, BCRYPT_RSA_ALGORITHM, 1024, 0, 0, &k), 0);
    if (!sd_get(k, DACL_SECURITY_INFORMATION, buf, sizeof buf, &cb, &s)) { EXPECT_S(s, 0); }
    else {
        EXPECT_S(U(NCryptSetProperty)(k, NCRYPT_SECURITY_DESCR_PROPERTY, buf, cb, DACL_SECURITY_INFORMATION), 0);
        BYTE b2[2048]; DWORD c2 = 0;
        EXPECT_S(U(NCryptGetProperty)(k, NCRYPT_SECURITY_DESCR_PROPERTY, b2, sizeof b2, &c2, DACL_SECURITY_INFORMATION), 0);
        CHECK(c2 > 0); CHECK(IsValidSecurityDescriptor(b2));
    }
    k_del(p, n, 0); k_free(p);
}
TEST(dxpk_sd_set_deny_then_restore) {
    /* add an explicit deny ACE for a made-up SID on the key, verify it round trips, then restore */
    KP_BEGIN(p); WCHAR n[96]; k_name(n, 96, L"sddeny"); NCRYPT_KEY_HANDLE k = 0; BYTE buf[2048]; DWORD cb = 0; SECURITY_STATUS s;
    EXPECT_S(k_make(p, n, BCRYPT_RSA_ALGORITHM, 1024, 0, 0, &k), 0);
    if (!sd_get(k, DACL_SECURITY_INFORMATION, buf, sizeof buf, &cb, &s)) { t_skip("cannot read SD 0x%08lx", S(s)); k_del(p, n, 0); k_free(p); return; }
    BYTE orig[2048]; DWORD ocb = cb; memcpy(orig, buf, cb);
    BOOL present, def; PACL acl; GetSecurityDescriptorDacl(buf, &present, &acl, &def);
    ACL_SIZE_INFORMATION ai = { 0 };
    CHECK(present && acl && GetAclInformation(acl, &ai, sizeof ai, AclSizeInformation));
    BYTE sid[SECURITY_MAX_SID_SIZE]; DWORD sl = sizeof sid;
    CHECK(CreateWellKnownSid(WinBuiltinGuestsSid, NULL, sid, &sl));
    BYTE nacl[1024]; CHECK(InitializeAcl((PACL)nacl, sizeof nacl, ACL_REVISION));
    CHECK(AddAccessDeniedAce((PACL)nacl, ACL_REVISION, GENERIC_ALL, sid));
    for (DWORD i = 0; i < ai.AceCount; i++) { LPVOID ace; if (GetAce(acl, i, &ace)) AddAce((PACL)nacl, ACL_REVISION, MAXDWORD, ace, ((PACE_HEADER)ace)->AceSize); }
    SECURITY_DESCRIPTOR sd; CHECK(InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION));
    CHECK(SetSecurityDescriptorDacl(&sd, TRUE, (PACL)nacl, FALSE));
    BYTE rel[2048]; DWORD rl = sizeof rel; CHECK(MakeSelfRelativeSD(&sd, rel, &rl));
    s = U(NCryptSetProperty)(k, NCRYPT_SECURITY_DESCR_PROPERTY, rel, rl, DACL_SECURITY_INFORMATION);
    EXPECT_S(s, 0);
    if (!s) {
        BYTE b2[2048]; DWORD c2 = 0;
        EXPECT_S(U(NCryptGetProperty)(k, NCRYPT_SECURITY_DESCR_PROPERTY, b2, sizeof b2, &c2, DACL_SECURITY_INFORMATION), 0);
        PACL a2 = NULL; GetSecurityDescriptorDacl(b2, &present, &a2, &def);
        ACL_SIZE_INFORMATION ai2 = { 0 };
        if (a2 && GetAclInformation(a2, &ai2, sizeof ai2, AclSizeInformation)) EXPECT_EQ(ai2.AceCount, ai.AceCount + 1);
        EXPECT_S(U(NCryptSetProperty)(k, NCRYPT_SECURITY_DESCR_PROPERTY, orig, ocb, DACL_SECURITY_INFORMATION), 0);
    }
    k_del(p, n, 0); k_free(p);
}
TEST(dxpk_sd_set_invalid_descriptor) {
    KP_BEGIN(p); WCHAR n[96]; k_name(n, 96, L"sdinv"); NCRYPT_KEY_HANDLE k = 0;
    EXPECT_S(k_make(p, n, BCRYPT_RSA_ALGORITHM, 1024, 0, 0, &k), 0);
    BYTE zero[4] = { 0 };
    SECURITY_STATUS s = U(NCryptSetProperty)(k, NCRYPT_SECURITY_DESCR_PROPERTY, zero, sizeof zero, DACL_SECURITY_INFORMATION);
    CHECK(s != 0); t_note("set 4-byte garbage SD -> 0x%08lx", S(s));
    s = U(NCryptSetProperty)(k, NCRYPT_SECURITY_DESCR_PROPERTY, NULL, 0, DACL_SECURITY_INFORMATION);
    CHECK(s != 0); t_note("set NULL SD -> 0x%08lx", S(s));
    k_del(p, n, 0); k_free(p);
}
TEST(dxpk_sd_support_property) {
    KP_BEGIN(p); WCHAR n[96]; k_name(n, 96, L"sdsup"); NCRYPT_KEY_HANDLE k = 0;
    EXPECT_S(k_make(p, n, BCRYPT_RSA_ALGORITHM, 1024, 0, 0, &k), 0);
    /* observed on Win10: supported-SD property exists on the provider handle (value 1), not on a key handle */
    DWORD v = 0, cb = 0; SECURITY_STATUS s = U(NCryptGetProperty)(k, NCRYPT_SECURITY_DESCR_SUPPORT_PROPERTY, (PBYTE)&v, 4, &cb, 0);
    EXPECT_S(s, NTE_NOT_SUPPORTED);
    s = U(NCryptGetProperty)(p, NCRYPT_SECURITY_DESCR_SUPPORT_PROPERTY, (PBYTE)&v, 4, &cb, 0);
    EXPECT_S(s, 0);
    if (!s) { EXPECT_EQ(cb, 4); EXPECT_EQ(v, 1); }
    k_del(p, n, 0); k_free(p);
}
TEST(dxpk_property_unknown_name) {
    KP_BEGIN(p); WCHAR n[96]; k_name(n, 96, L"propunk"); NCRYPT_KEY_HANDLE k = 0; BYTE b[16]; DWORD cb;
    EXPECT_S(k_make(p, n, BCRYPT_RSA_ALGORITHM, 1024, 0, 0, &k), 0);
    SECURITY_STATUS s = U(NCryptGetProperty)(k, L"cryptt No Such Property", b, sizeof b, &cb, 0);
    CHECK(s != 0); t_note("unknown property -> 0x%08lx", S(s));
    s = U(NCryptSetProperty)(k, L"cryptt No Such Property", b, 4, 0);
    t_note("set unknown property -> 0x%08lx", S(s));
    k_del(p, n, 0); k_free(p);
}
TEST(dxpk_custom_property_persist_flag) {
    KP_BEGIN(p); WCHAR n[96]; k_name(n, 96, L"custprop"); NCRYPT_KEY_HANDLE k = 0, k2 = 0;
    EXPECT_S(k_make(p, n, BCRYPT_RSA_ALGORITHM, 1024, 0, 0, &k), 0);
    BYTE val[5] = { 9, 8, 7, 6, 5 };
    SECURITY_STATUS s = U(NCryptSetProperty)(k, L"CrypttCustomProp", val, 5, NCRYPT_PERSIST_FLAG);
    t_note("set custom persisted property -> 0x%08lx", S(s));
    if (!s) {
        k_free(k);
        EXPECT_S(U(NCryptOpenKey)(p, &k2, n, 0, 0), 0);
        BYTE out[16] = { 0 }; DWORD cb = 0;
        EXPECT_S(U(NCryptGetProperty)(k2, L"CrypttCustomProp", out, sizeof out, &cb, 0), 0);
        EXPECT_EQ(cb, 5); CHECK(!memcmp(out, val, 5));
        k_free(k2);
    } else k_free(k);
    k_del(p, n, 0); k_free(p);
}

TEST(dxpk_export_invalid_handle) {
    K_NEEDS(); REQUIRE(U(NCryptExportKey)); BYTE b[64]; DWORD cb = 0;
    EXPECT_S(U(NCryptExportKey)(0, 0, BCRYPT_RSAPUBLIC_BLOB, NULL, b, sizeof b, &cb, 0), NTE_INVALID_HANDLE);
}
TEST(dxpk_export_ecc_public_blob) {
    KP_BEGIN(p); WCHAR n[96]; k_name(n, 96, L"exec"); NCRYPT_KEY_HANDLE k = 0; REQUIRE(U(NCryptExportKey));
    if (k_make(p, n, BCRYPT_ECDSA_P256_ALGORITHM, 0, 0, 0, &k)) { t_skip("no ECDSA persisted support"); k_free(p); return; }
    BYTE b[256]; DWORD cb = 0;
    EXPECT_S(U(NCryptExportKey)(k, 0, BCRYPT_ECCPUBLIC_BLOB, NULL, b, sizeof b, &cb, 0), 0);
    EXPECT_EQ(cb, sizeof(BCRYPT_ECCKEY_BLOB) + 64);
    BCRYPT_ECCKEY_BLOB *h = (BCRYPT_ECCKEY_BLOB *)b;
    EXPECT_EQ(h->dwMagic, BCRYPT_ECDSA_PUBLIC_P256_MAGIC); EXPECT_EQ(h->cbKey, 32);
    k_del(p, n, 0); k_free(p);
}
