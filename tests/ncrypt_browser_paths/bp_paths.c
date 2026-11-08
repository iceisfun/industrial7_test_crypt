/* The ncrypt paths a browser takes: provider open/enumerate, ephemeral ECDSA P-256 / RSA 2048 keys, finalize, sign,
 * verify, property get/set, public key blobs, opaque transport export, NTE_* ordering. All values observed on
 * Windows 10 22H2 first; machine dependent facts (TPM provider, enumerated names) are notes. */
#include "bp.h"

/* per-iteration expectations of looped checks (observed on Windows 10) */
static const unsigned long long VT_23[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0x80090029, 0, 0, 0, 0x80090029, 0x80090029, 0x80090029, 0x80090029, 0x80090029, 0x80090029, 0x80090029 };
static const unsigned long long VT_135[] = { 0x48, 0x68, 0x8c };
static const unsigned long long VT_137[] = { 0x48, 0x68, 0x8c };
static const unsigned long long VT_139[] = { 0x20, 0x30, 0x42 };
static const unsigned long long VT_142[] = { 0x40, 0x60, 0x84 };
static const unsigned long long VT_152[] = { 0x48, 0x68, 0x8c };


/* ---- provider open / enumerate --------------------------------------------------------------------------------------- */
TEST(brw_open_provider_matrix) {
    BP_NEED();
    REQUIRE(U(NCryptOpenStorageProvider));
    NCRYPT_PROV_HANDLE h; LONG r; unsigned i;
    static const LPCWSTR names[] = { L"Microsoft Software Key Storage Provider", L"MICROSOFT SOFTWARE KEY STORAGE PROVIDER", L"", L"No Such KSP",
        L"Microsoft Software Key Storage Provider ", L"Microsoft Smart Card Key Storage Provider", L"Microsoft Passport Key Storage Provider" };
    h = 0x1234; OBS(1, U(NCryptOpenStorageProvider)(NULL, BP_KSP, 0), 0x80090027);
    h = 0x1234; r = U(NCryptOpenStorageProvider)(&h, NULL, 0); OBS(2, r, 0); OBS(3, h != 0 && h != 0x1234, 1); bp_free(h);
    for (i = 0; i < sizeof names / sizeof *names; i++) {
        h = 0x1234; t_label("name %u", i);
        r = U(NCryptOpenStorageProvider)(&h, names[i], 0);
        OBSN(4, r);
        if (r == 0) bp_free(h); else OBSN(5, h);
    }
    t_label("");
    h = 0x1234; r = U(NCryptOpenStorageProvider)(&h, L"No Such KSP", 0); OBS(6, r, 0xc0000225); OBS(7, h, 0);
    h = 0x1234; r = U(NCryptOpenStorageProvider)(&h, BP_KSP, 1); OBS(8, r, 0x80090009); OBS(9, h == 0x1234, 0); if (r == 0) bp_free(h);
    h = 0x1234; r = U(NCryptOpenStorageProvider)(&h, BP_KSP, 0x40); OBS(10, r, 0); if (r == 0) bp_free(h);       /* SILENT */
    h = 0x1234; r = U(NCryptOpenStorageProvider)(&h, BP_KSP, 0x80000000); OBS(11, r, 0x80090009); if (r == 0) bp_free(h);
    {   /* name of 4096 characters */
        WCHAR big[4097]; int j; for (j = 0; j < 4096; j++) big[j] = L'A'; big[4096] = 0;
        h = 0x1234; r = U(NCryptOpenStorageProvider)(&h, big, 0); OBS(12, r, 0xc0000225); if (r == 0) bp_free(h);
    }
    /* the platform (TPM) provider: depends on the machine */
    h = 0x1234; r = U(NCryptOpenStorageProvider)(&h, MS_PLATFORM_CRYPTO_PROVIDER, 0);
    t_note("platform crypto provider open -> 0x%08lx", (unsigned long)r); if (r == 0) bp_free(h);
    h = 0x1234; r = U(NCryptOpenStorageProvider)(&h, MS_SMART_CARD_KEY_STORAGE_PROVIDER, 0);
    t_note("smart card KSP open -> 0x%08lx", (unsigned long)r); if (r == 0) bp_free(h);
}

TEST(brw_enum_providers) {
    BP_NEED();
    REQUIRE(U(NCryptEnumStorageProviders));
    DWORD n = 77; NCryptProviderName *l = NULL; LONG r; DWORD i; int found = 0;
    OBS(13, U(NCryptEnumStorageProviders)(NULL, &l, 0), 0x80090027);
    OBS(14, U(NCryptEnumStorageProviders)(&n, NULL, 0), 0x80090027);
    OBS(15, n, 0x4d);
    OBS(16, U(NCryptEnumStorageProviders)(&n, &l, 0x80000000), 0x80090009);
    n = 77; l = NULL;
    r = U(NCryptEnumStorageProviders)(&n, &l, 0);
    OBS(17, r, 0);
    if (r == 0 && l) {
        OBS(18, n >= 1, 1);
        for (i = 0; i < n; i++) {
            if (!lstrcmpiW(l[i].pszName, BP_KSP)) found = 1;
            t_note("provider %lu: %ls", (unsigned long)i, l[i].pszName);
        }
        OBS(19, found, 1);
        OBS(20, U(NCryptFreeBuffer)(l), 0);
    }
    n = 77; l = NULL;
    r = U(NCryptEnumStorageProviders)(&n, &l, NCRYPT_SILENT_FLAG);
    OBS(21, r, 0); if (r == 0 && l) U(NCryptFreeBuffer)(l);
    OBS(22, U(NCryptFreeBuffer)(NULL), 0);
}

TEST(brw_isalgsupported) {
    BP_NEED();
    REQUIRE(U(NCryptIsAlgSupported));
    NCRYPT_PROV_HANDLE p = bp_prov(); unsigned i;
    static const LPCWSTR algs[] = { L"ECDSA_P256", L"ECDSA_P384", L"ECDSA_P521", L"ECDH_P256", L"RSA", L"DH", L"DSA", L"AES", L"SHA256",
        L"ECDSA", L"ECDH", L"3DES", L"HMAC", L"CURVE25519", L"ECDH_P192", L"rsa", L"RSA ", L"", L"No Such Alg" };
    REQUIRE(p);
    for (i = 0; i < sizeof algs / sizeof *algs; i++) { t_label("alg %u", i); OBSV(23, U(NCryptIsAlgSupported)(p, algs[i], 0)); }
    t_label("");
    OBS(24, U(NCryptIsAlgSupported)(p, NULL, 0), 0x800706f4);
    OBS(25, U(NCryptIsAlgSupported)(0, L"RSA", 0), 0x80090026);
    OBS(27, U(NCryptIsAlgSupported)(p, L"RSA", 1), 0x80090009);
    OBS(28, U(NCryptIsAlgSupported)(p, L"RSA", NCRYPT_SILENT_FLAG), 0);
    OBS(29, U(NCryptIsAlgSupported)(p, L"RSA", 0x80000000), 0x80090009);
    bp_free(p);
}

/* ---- ECDSA P-256 ephemeral key ----------------------------------------------------------------------------------------- */
TEST(brw_ecdsa_p256_properties) {
    BP_NEED();
    REQUIRE(U(NCryptCreatePersistedKey));
    NCRYPT_PROV_HANDLE p = bp_prov(); NCRYPT_KEY_HANDLE k = 0; DWORD cb = 0, v = 0; BYTE buf[256]; LONG r;
    REQUIRE(p);
    OBS(30, U(NCryptCreatePersistedKey)(p, &k, L"ECDSA_P256", NULL, 0, 0), 0);
    REQUIRE(k);
    /* before finalize */
    r = U(NCryptGetProperty)(k, L"Length", (PBYTE)&v, 4, &cb, 0); OBS(31, r, 0); OBS(32, v, 0x100); OBS(33, cb, 4);
    r = U(NCryptGetProperty)(k, L"Algorithm Name", buf, sizeof buf, &cb, 0); OBS(34, r, 0); OBS(35, cb, 0x16);
    if (r == 0) t_note("pre-final algorithm name %ls", (WCHAR *)buf);
    r = U(NCryptGetProperty)(k, L"Export Policy", (PBYTE)&v, 4, &cb, 0); OBS(36, r, 0); OBS(37, v, 0);
    r = U(NCryptGetProperty)(k, L"Key Usage", (PBYTE)&v, 4, &cb, 0); OBS(38, r, 0); OBS(39, v, 0xffffff);
    OBS(40, U(NCryptFinalizeKey)(k, 0), 0);
    OBS(41, U(NCryptFinalizeKey)(k, 0), 0x80090026);           /* second finalize */
    /* properties of the finalized key */
    r = U(NCryptGetProperty)(k, L"Algorithm Name", NULL, 0, &cb, 0); OBS(42, r, 0); OBS(43, cb, 0x16);
    memset(buf, 0, sizeof buf); r = U(NCryptGetProperty)(k, L"Algorithm Name", buf, sizeof buf, &cb, 0); OBS(44, r, 0);
    OBS(45, lstrcmpW((WCHAR *)buf, L"ECDSA"), 1);
    memset(buf, 0, sizeof buf); r = U(NCryptGetProperty)(k, L"Algorithm Group", buf, sizeof buf, &cb, 0); OBS(46, r, 0); OBS(47, cb, 0xc);
    OBS(48, lstrcmpW((WCHAR *)buf, L"ECDSA"), 0);
    r = U(NCryptGetProperty)(k, L"Length", (PBYTE)&v, 4, &cb, 0); OBS(49, r, 0); OBS(50, v, 0x100);
    r = U(NCryptGetProperty)(k, L"Export Policy", (PBYTE)&v, 4, &cb, 0); OBS(51, r, 0); OBS(52, v, 0);
    r = U(NCryptGetProperty)(k, L"Key Usage", (PBYTE)&v, 4, &cb, 0); OBS(53, r, 0); OBS(54, v, 0xffffff);
    r = U(NCryptGetProperty)(k, L"Security Descr Support", (PBYTE)&v, 4, &cb, 0); OBS(55, r, 0x80090029); OBS(56, v, 0xffffff);
    r = U(NCryptGetProperty)(k, L"Impl Type", (PBYTE)&v, 4, &cb, 0); OBS(57, r, 0x80090029); OBS(58, v, 0xffffff);
    r = U(NCryptGetProperty)(k, L"Key Type", (PBYTE)&v, 4, &cb, 0); OBS(59, r, 0); OBS(60, v, 0);
    r = U(NCryptGetProperty)(k, L"Name", buf, sizeof buf, &cb, 0); OBS(61, r, 0x80090029);
    r = U(NCryptGetProperty)(k, L"Unique Name", buf, sizeof buf, &cb, 0); OBS(62, r, 0x80090029);
    r = U(NCryptGetProperty)(k, L"ECCCurveName", buf, sizeof buf, &cb, 0); OBS(63, r, 0x80090011); OBS(64, cb, 0);
    r = U(NCryptGetProperty)(k, L"Provider Handle", (PBYTE)&v, 8, &cb, 0); OBS(66, r, 0);
    r = U(NCryptGetProperty)(k, L"UI Policy", buf, sizeof buf, &cb, 0); OBS(68, r, 0x80090011);
    r = U(NCryptGetProperty)(k, L"Lengths", buf, sizeof buf, &cb, 0); OBS(69, r, 0);
    r = U(NCryptGetProperty)(k, L"No Such Property", buf, sizeof buf, &cb, 0); OBS(70, r, 0x80090029);
    r = U(NCryptGetProperty)(k, L"", buf, sizeof buf, &cb, 0); OBS(71, r, 0x80090029);
    /* buffer handling */
    cb = 0; r = U(NCryptGetProperty)(k, L"Length", (PBYTE)&v, 2, &cb, 0); OBS(72, r, 0x80090028); OBS(73, cb, 4);
    cb = 0; r = U(NCryptGetProperty)(k, L"Length", NULL, 0, &cb, 0); OBS(74, r, 0); OBS(75, cb, 4);
    r = U(NCryptGetProperty)(k, L"Length", (PBYTE)&v, 4, NULL, 0); OBS(76, r, 0x80090027);
    r = U(NCryptGetProperty)(k, NULL, (PBYTE)&v, 4, &cb, 0); OBS(77, r, 0x80090027);
    r = U(NCryptGetProperty)(k, L"Length", (PBYTE)&v, 4, &cb, 0x80000000); OBS(78, r, 0x80090009);
    r = U(NCryptGetProperty)(0, L"Length", (PBYTE)&v, 4, &cb, 0); OBS(79, r, 0x80090026);
    /* set property after finalize */
    v = 384; r = U(NCryptSetProperty)(k, L"Length", (PBYTE)&v, 4, 0); OBS(81, r, 0x80090029);
    v = 0; r = U(NCryptSetProperty)(k, L"Export Policy", (PBYTE)&v, 4, 0); OBS(82, r, 0);
    v = 0xFFFF; r = U(NCryptSetProperty)(k, L"Key Usage", (PBYTE)&v, 4, 0); OBS(83, r, 0);
    r = U(NCryptSetProperty)(k, L"No Such Property", (PBYTE)&v, 4, 0); OBS(84, r, 0x80090029);
    r = U(NCryptSetProperty)(k, NULL, (PBYTE)&v, 4, 0); OBS(85, r, 0x80090027);
    r = U(NCryptSetProperty)(k, L"Length", NULL, 4, 0); OBS(86, r, 0x800706f7);
    r = U(NCryptSetProperty)(0, L"Length", (PBYTE)&v, 4, 0); OBS(87, r, 0x80090026);
    bp_free(k); bp_free(p);
}

TEST(brw_ecdsa_p256_sign_verify) {
    BP_NEED();
    REQUIRE(U(NCryptSignHash)); REQUIRE(U(NCryptVerifySignature));
    NCRYPT_PROV_HANDLE p = bp_prov(); NCRYPT_KEY_HANDLE k, k2; BYTE h[32], sig[128], sig2[128]; DWORD cb = 0, cb2 = 0; LONG r;
    REQUIRE(p); k = bp_key(p, L"ECDSA_P256", 0, 0, 0, 1); REQUIRE(k);
    bp_digest(h, 32);
    r = U(NCryptSignHash)(k, NULL, h, 32, NULL, 0, &cb, 0); OBS(88, r, 0); OBS(89, cb, 0x40);
    memset(sig, 0, sizeof sig);
    r = U(NCryptSignHash)(k, NULL, h, 32, sig, sizeof sig, &cb, 0); OBS(90, r, 0); OBS(91, cb, 0x40);
    r = U(NCryptVerifySignature)(k, NULL, h, 32, sig, cb, 0); OBS(92, r, 0);
    /* ECDSA is randomised: two signatures differ, both verify */
    cb2 = sizeof sig2; r = U(NCryptSignHash)(k, NULL, h, 32, sig2, sizeof sig2, &cb2, 0); OBS(93, r, 0);
    OBS(94, memcmp(sig, sig2, 64) != 0, 1);
    OBS(95, U(NCryptVerifySignature)(k, NULL, h, 32, sig2, cb2, 0), 0);
    /* tampering */
    sig[5] ^= 1; OBS(96, U(NCryptVerifySignature)(k, NULL, h, 32, sig, 64, 0), 0x80090006); sig[5] ^= 1;
    h[0] ^= 1; OBS(97, U(NCryptVerifySignature)(k, NULL, h, 32, sig, 64, 0), 0x80090006); h[0] ^= 1;
    OBS(98, U(NCryptVerifySignature)(k, NULL, h, 32, sig, 63, 0), 0x80090027);
    OBS(99, U(NCryptVerifySignature)(k, NULL, h, 32, sig, 65, 0), 0x80090027);
    OBS(100, U(NCryptVerifySignature)(k, NULL, h, 32, sig, 0, 0), 0x80090027);
    OBS(101, U(NCryptVerifySignature)(k, NULL, h, 32, NULL, 64, 0), 0x800706f4);
    OBS(102, U(NCryptVerifySignature)(k, NULL, NULL, 32, sig, 64, 0), 0x800706f4);
    OBS(103, U(NCryptVerifySignature)(k, NULL, h, 0, sig, 64, 0), 0x80090027);
    OBS(104, U(NCryptVerifySignature)(k, NULL, h, 31, sig, 64, 0), 0x80090006);
    OBS(105, U(NCryptVerifySignature)(k, NULL, h, 20, sig, 64, 0), 0x80090006);
    OBS(106, U(NCryptVerifySignature)(k, NULL, h, 64, sig, 64, 0), 0);
    OBS(107, U(NCryptVerifySignature)(k, NULL, h, 32, sig, 64, 0x80000000), 0x80090009);
    OBS(108, U(NCryptVerifySignature)(k, NULL, h, 32, sig, 64, BCRYPT_PAD_PKCS1), 0);
    OBS(109, U(NCryptVerifySignature)(0, NULL, h, 32, sig, 64, 0), 0x80090026);
    OBS(110, U(NCryptVerifySignature)(p, NULL, h, 32, sig, 64, 0), 0x80090026);
    /* another key does not verify */
    k2 = bp_key(p, L"ECDSA_P256", 0, 0, 0, 1);
    if (k2) { OBS(111, U(NCryptVerifySignature)(k2, NULL, h, 32, sig, 64, 0), 0x80090006); bp_free(k2); }
    /* sign argument validation and ordering */
    cb = 99; r = U(NCryptSignHash)(k, NULL, h, 32, sig, 10, &cb, 0); OBS(112, r, 0x80090028); OBS(113, cb, 0x40);
    cb = 99; r = U(NCryptSignHash)(k, NULL, h, 32, sig, 63, &cb, 0); OBS(114, r, 0x80090028); OBS(115, cb, 0x40);
    cb = 99; r = U(NCryptSignHash)(k, NULL, h, 32, sig, 64, &cb, 0); OBS(116, r, 0); OBS(117, cb, 0x40);
    r = U(NCryptSignHash)(k, NULL, h, 32, sig, 64, NULL, 0); OBS(118, r, 0x800706f4);
    r = U(NCryptSignHash)(k, NULL, NULL, 32, sig, 64, &cb, 0); OBS(119, r, 0x800706f4);
    r = U(NCryptSignHash)(k, NULL, h, 0, sig, 64, &cb, 0); OBS(120, r, 0x80090027);
    r = U(NCryptSignHash)(k, NULL, h, 31, sig, 64, &cb, 0); OBS(121, r, 0);
    r = U(NCryptSignHash)(k, NULL, h, 20, sig, 64, &cb, 0); OBS(122, r, 0);
    r = U(NCryptSignHash)(k, NULL, h, 64, sig, 64, &cb, 0); OBS(123, r, 0);
    r = U(NCryptSignHash)(k, NULL, h, 48, sig, 64, &cb, 0); OBS(124, r, 0);
    r = U(NCryptSignHash)(k, NULL, h, 32, sig, 64, &cb, 0x80000000); OBS(125, r, 0x80090009);
    r = U(NCryptSignHash)(k, NULL, h, 32, sig, 64, &cb, BCRYPT_PAD_PKCS1); OBS(126, r, 0);
    r = U(NCryptSignHash)(k, NULL, h, 32, sig, 64, &cb, BCRYPT_PAD_PSS); OBS(127, r, 0);
    r = U(NCryptSignHash)(0, NULL, h, 32, sig, 64, &cb, 0); OBS(128, r, 0x80090026);
    r = U(NCryptSignHash)(p, NULL, h, 32, sig, 64, &cb, 0); OBS(129, r, 0x80090026);
    /* unfinalized key */
    {   NCRYPT_KEY_HANDLE u = bp_key(p, L"ECDSA_P256", 0, 0, 0, 0);
        if (u) {
            cb = 99; r = U(NCryptSignHash)(u, NULL, h, 32, sig, 64, &cb, 0); OBS(131, r, 0x80090027);
            r = U(NCryptVerifySignature)(u, NULL, h, 32, sig, 64, 0); OBS(132, r, 0x80090026);
            bp_free(u);
        }
    }
    /* key usage restricted to key agreement cannot sign */
    {   NCRYPT_KEY_HANDLE u = bp_key(p, L"ECDSA_P256", 0, 0, NCRYPT_ALLOW_KEY_AGREEMENT_FLAG, 1);
        if (u) { cb = 99; r = U(NCryptSignHash)(u, NULL, h, 32, sig, 64, &cb, 0); OBS(133, r, 0x80090010); bp_free(u); }
    }
    bp_free(k); bp_free(p);
}

TEST(brw_ecc_public_blob_layout) {
    BP_NEED();
    REQUIRE(U(NCryptExportKey)); REQUIRE(U(NCryptImportKey));
    static const struct { LPCWSTR alg; DWORD magic; } curves[] = {
        { L"ECDSA_P256", 0x31534345 }, { L"ECDSA_P384", 0x33534345 }, { L"ECDSA_P521", 0x35534345 } };
    NCRYPT_PROV_HANDLE p = bp_prov(); unsigned i; BYTE blob[400]; DWORD cb = 0, cb2; LONG r; NCRYPT_KEY_HANDLE k, k2;
    REQUIRE(p);
    for (i = 0; i < 3; i++) {
        BCRYPT_ECCKEY_BLOB *eb = (BCRYPT_ECCKEY_BLOB *)blob;
        t_label("%ls", curves[i].alg);
        k = bp_key(p, curves[i].alg, 0, 0, 0, 1); if (!k) { CHECKF(0, "key"); continue; }
        cb = 0; r = U(NCryptExportKey)(k, 0, BCRYPT_ECCPUBLIC_BLOB, NULL, NULL, 0, &cb, 0); OBS(134, r, 0); OBSV(135, cb);
        memset(blob, 0, sizeof blob); cb2 = sizeof blob;
        r = U(NCryptExportKey)(k, 0, BCRYPT_ECCPUBLIC_BLOB, NULL, blob, sizeof blob, &cb2, 0); OBS(136, r, 0); OBSV(137, cb2);
        OBS(138, eb->dwMagic == curves[i].magic, 1); OBSV(139, eb->cbKey);
        OBS(140, cb2 == sizeof(BCRYPT_ECCKEY_BLOB) + 2 * eb->cbKey, 1);
        /* import the public blob back and verify a signature made by the original */
        {   BYTE h[64], sig[200]; DWORD cs = sizeof sig, hl = i == 0 ? 32 : i == 1 ? 48 : 64; bp_digest(h, hl);
            r = U(NCryptSignHash)(k, NULL, h, hl, sig, sizeof sig, &cs, 0); OBS(141, r, 0); OBSV(142, cs);
            k2 = 0; r = U(NCryptImportKey)(p, 0, BCRYPT_ECCPUBLIC_BLOB, NULL, &k2, blob, cb2, 0); OBS(143, r, 0);
            if (k2) { OBS(144, U(NCryptVerifySignature)(k2, NULL, h, hl, sig, cs, 0), 0); bp_free(k2); }
        }
        /* private blob is not exportable by default */
        cb = 0; r = U(NCryptExportKey)(k, 0, BCRYPT_ECCPRIVATE_BLOB, NULL, NULL, 0, &cb, 0); OBS(145, r, 0x80090029);
        cb = 0; r = U(NCryptExportKey)(k, 0, NCRYPT_OPAQUETRANSPORT_BLOB, NULL, NULL, 0, &cb, 0); OBS(146, r, 0x8009000b);
        cb = 0; r = U(NCryptExportKey)(k, 0, NCRYPT_PKCS8_PRIVATE_KEY_BLOB, NULL, NULL, 0, &cb, 0); OBS(147, r, 0x80090029);
        cb = 0; r = U(NCryptExportKey)(k, 0, L"No Such Blob", NULL, NULL, 0, &cb, 0); OBS(148, r, 0x80090027);
        cb = 0; r = U(NCryptExportKey)(k, 0, BCRYPT_RSAPUBLIC_BLOB, NULL, NULL, 0, &cb, 0); OBS(149, r, 0x8009000a);
        cb = 0; r = U(NCryptExportKey)(k, 0, BCRYPT_PUBLIC_KEY_BLOB, NULL, NULL, 0, &cb, 0); OBS(150, r, 0);
        cb = 4; r = U(NCryptExportKey)(k, 0, BCRYPT_ECCPUBLIC_BLOB, NULL, blob, 4, &cb, 0); OBS(151, r, 0x80090028); OBSV(152, cb);
        bp_free(k);
    }
    t_label("");
    /* tampered / truncated public blobs on import */
    k = bp_key(p, L"ECDSA_P256", 0, 0, 0, 1);
    if (k) {
        BCRYPT_ECCKEY_BLOB *eb = (BCRYPT_ECCKEY_BLOB *)blob; cb2 = sizeof blob;
        r = U(NCryptExportKey)(k, 0, BCRYPT_ECCPUBLIC_BLOB, NULL, blob, sizeof blob, &cb2, 0);
        if (r == 0) {
            k2 = 0xAB; OBS(153, U(NCryptImportKey)(p, 0, BCRYPT_ECCPUBLIC_BLOB, NULL, &k2, blob, cb2 - 1, 0), 0x80090027); OBS(154, k2, 0xab);
            k2 = 0xAB; OBS(155, U(NCryptImportKey)(p, 0, BCRYPT_ECCPUBLIC_BLOB, NULL, &k2, blob, 4, 0), 0x80090027);
            k2 = 0xAB; OBS(156, U(NCryptImportKey)(p, 0, BCRYPT_ECCPUBLIC_BLOB, NULL, &k2, blob, 0, 0), 0x80090027);
            k2 = 0xAB; OBS(157, U(NCryptImportKey)(p, 0, BCRYPT_ECCPUBLIC_BLOB, NULL, &k2, NULL, cb2, 0), 0x800706f4);
            k2 = 0xAB; OBS(158, U(NCryptImportKey)(p, 0, BCRYPT_ECCPUBLIC_BLOB, NULL, NULL, blob, cb2, 0), 0x80090027);
            k2 = 0xAB; OBS(159, U(NCryptImportKey)(p, 0, NULL, NULL, &k2, blob, cb2, 0), 0x80090027);
            k2 = 0xAB; OBS(160, U(NCryptImportKey)(0, 0, BCRYPT_ECCPUBLIC_BLOB, NULL, &k2, blob, cb2, 0), 0x80090026);
            k2 = 0xAB; OBS(161, U(NCryptImportKey)(p, 0, BCRYPT_ECCPUBLIC_BLOB, NULL, &k2, blob, cb2, 0x80000000), 0x80090009);
            eb->dwMagic = 0x31534346; k2 = 0xAB; OBS(162, U(NCryptImportKey)(p, 0, BCRYPT_ECCPUBLIC_BLOB, NULL, &k2, blob, cb2, 0), 0x80090027);
            eb->dwMagic = 0x31534345; eb->cbKey = 33; k2 = 0xAB; OBS(163, U(NCryptImportKey)(p, 0, BCRYPT_ECCPUBLIC_BLOB, NULL, &k2, blob, cb2, 0), 0x80090027);
            eb->cbKey = 32; blob[sizeof *eb + 40] ^= 1; k2 = 0xAB; r = U(NCryptImportKey)(p, 0, BCRYPT_ECCPUBLIC_BLOB, NULL, &k2, blob, cb2, 0);
            OBS(164, r, 0x80090027);                /* point not on the curve */
            if (r == 0) bp_free(k2);
        }
        bp_free(k);
    }
    bp_free(p);
}

/* ---- RSA 2048 ephemeral key -------------------------------------------------------------------------------------------- */
TEST(brw_rsa2048_properties_and_blob) {
    BP_NEED();
    REQUIRE(U(NCryptCreatePersistedKey));
    NCRYPT_PROV_HANDLE p = bp_prov(); NCRYPT_KEY_HANDLE k = 0, k2; DWORD cb = 0, v = 0; BYTE buf[600]; LONG r;
    REQUIRE(p); t_set_timeout(120);
    OBS(165, U(NCryptCreatePersistedKey)(p, &k, L"RSA", NULL, 0, 0), 0);
    REQUIRE(k);
    r = U(NCryptGetProperty)(k, L"Length", (PBYTE)&v, 4, &cb, 0); OBS(166, r, 0); OBS(167, v, 0x400);       /* default before finalize */
    v = 2048; OBS(168, U(NCryptSetProperty)(k, L"Length", (PBYTE)&v, 4, 0), 0);
    v = 100; OBS(169, U(NCryptSetProperty)(k, L"Length", (PBYTE)&v, 4, 0), 0x80090029);
    v = 511; OBS(170, U(NCryptSetProperty)(k, L"Length", (PBYTE)&v, 4, 0), 0x80090029);
    v = 513; OBS(171, U(NCryptSetProperty)(k, L"Length", (PBYTE)&v, 4, 0), 0x80090029);
    v = 16385; OBS(172, U(NCryptSetProperty)(k, L"Length", (PBYTE)&v, 4, 0), 0x80090029);
    v = 2048; OBS(173, U(NCryptSetProperty)(k, L"Length", (PBYTE)&v, 4, 0), 0);
    OBS(174, U(NCryptSetProperty)(k, L"Length", (PBYTE)&v, 2, 0), 0x80090005);
    OBS(175, U(NCryptFinalizeKey)(k, 0), 0);
    r = U(NCryptGetProperty)(k, L"Length", (PBYTE)&v, 4, &cb, 0); OBS(176, r, 0); OBS(177, v, 0x800);
    memset(buf, 0, sizeof buf); r = U(NCryptGetProperty)(k, L"Algorithm Name", buf, sizeof buf, &cb, 0); OBS(178, r, 0);
    OBS(179, lstrcmpW((WCHAR *)buf, L"RSA"), 0);
    r = U(NCryptGetProperty)(k, L"Export Policy", (PBYTE)&v, 4, &cb, 0); OBS(180, r, 0); OBS(181, v, 0);
    r = U(NCryptGetProperty)(k, L"Key Usage", (PBYTE)&v, 4, &cb, 0); OBS(182, r, 0); OBS(183, v, 0xffffff);
    r = U(NCryptGetProperty)(k, L"Security Descr Support", (PBYTE)&v, 4, &cb, 0); OBS(184, r, 0x80090029); OBS(185, v, 0xffffff);
    r = U(NCryptGetProperty)(k, L"Lengths", buf, sizeof buf, &cb, 0); OBS(186, r, 0); OBS(187, cb, 0x10);
    if (r == 0 && cb == 16) { DWORD *l = (DWORD *)buf; OBS(188, l[0], 0x200); OBS(189, l[1], 0x4000); OBS(190, l[2], 8); OBS(191, l[3], 0x400); }
    v = 4096; OBS(192, U(NCryptSetProperty)(k, L"Length", (PBYTE)&v, 4, 0), 0);
    /* public blob layout: header + exponent + modulus */
    cb = 0; r = U(NCryptExportKey)(k, 0, BCRYPT_RSAPUBLIC_BLOB, NULL, NULL, 0, &cb, 0); OBS(193, r, 0); OBS(194, cb, 0x11b);
    memset(buf, 0, sizeof buf);
    r = U(NCryptExportKey)(k, 0, BCRYPT_RSAPUBLIC_BLOB, NULL, buf, sizeof buf, &cb, 0); OBS(195, r, 0);
    {   BCRYPT_RSAKEY_BLOB *rb = (BCRYPT_RSAKEY_BLOB *)buf;
        OBS(196, rb->Magic, 0x31415352); OBS(197, rb->BitLength, 0x800); OBS(198, rb->cbPublicExp, 3); OBS(199, rb->cbModulus, 0x100);
        OBS(200, rb->cbPrime1, 0); OBS(201, rb->cbPrime2, 0);
        OBS(202, buf[sizeof *rb] == 1 && buf[sizeof *rb + 1] == 0 && buf[sizeof *rb + 2] == 1, 1);   /* 65537 big endian */
        OBS(203, buf[sizeof *rb + rb->cbPublicExp] >= 0x80, 1);                                       /* top bit of modulus set */
    }
    k2 = 0; OBS(204, U(NCryptImportKey)(p, 0, BCRYPT_RSAPUBLIC_BLOB, NULL, &k2, buf, cb, 0), 0);
    if (k2) { r = U(NCryptGetProperty)(k2, L"Length", (PBYTE)&v, 4, &cb, 0); OBS(205, r, 0); OBS(206, v, 0x800); bp_free(k2); }
    /* other blob types */
    cb = 0; r = U(NCryptExportKey)(k, 0, BCRYPT_RSAPRIVATE_BLOB, NULL, NULL, 0, &cb, 0); OBS(207, r, 0x80090029);
    cb = 0; r = U(NCryptExportKey)(k, 0, BCRYPT_RSAFULLPRIVATE_BLOB, NULL, NULL, 0, &cb, 0); OBS(208, r, 0x80090029);
    cb = 0; r = U(NCryptExportKey)(k, 0, NCRYPT_OPAQUETRANSPORT_BLOB, NULL, NULL, 0, &cb, 0); OBS(209, r, 0x8009000b);
    cb = 0; r = U(NCryptExportKey)(k, 0, NCRYPT_PKCS8_PRIVATE_KEY_BLOB, NULL, NULL, 0, &cb, 0); OBS(210, r, 0x80090029);
    cb = 0; r = U(NCryptExportKey)(k, 0, BCRYPT_ECCPUBLIC_BLOB, NULL, NULL, 0, &cb, 0); OBS(211, r, 0x8009000a);
    cb = 0; r = U(NCryptExportKey)(k, 0, L"CAPIPUBLICBLOB", NULL, NULL, 0, &cb, 0); OBS(212, r, 0);
    bp_free(k); bp_free(p);
}

TEST(brw_rsa2048_sign_verify) {
    BP_NEED();
    REQUIRE(U(NCryptSignHash)); REQUIRE(U(NCryptVerifySignature));
    NCRYPT_PROV_HANDLE p = bp_prov(); NCRYPT_KEY_HANDLE k, k2; BYTE h[64], sig[512], sig2[512]; DWORD cb = 0, cb2 = 0; LONG r;
    BCRYPT_PKCS1_PADDING_INFO pi = { BCRYPT_SHA256_ALGORITHM };
    BCRYPT_PKCS1_PADDING_INFO pi1 = { BCRYPT_SHA1_ALGORITHM };
    BCRYPT_PKCS1_PADDING_INFO pin = { NULL };
    BCRYPT_PKCS1_PADDING_INFO pib = { L"NOHASH" };
    BCRYPT_PSS_PADDING_INFO ps = { BCRYPT_SHA256_ALGORITHM, 32 };
    BCRYPT_PSS_PADDING_INFO ps0 = { BCRYPT_SHA256_ALGORITHM, 0 };
    BCRYPT_PSS_PADDING_INFO psbig = { BCRYPT_SHA256_ALGORITHM, 400 };
    REQUIRE(p); t_set_timeout(120);
    k = bp_key(p, L"RSA", 2048, 0, 0, 1); REQUIRE(k);
    bp_digest(h, 64);
    r = U(NCryptSignHash)(k, &pi, h, 32, NULL, 0, &cb, BCRYPT_PAD_PKCS1); OBS(213, r, 0); OBS(214, cb, 0x100);
    memset(sig, 0, sizeof sig);
    r = U(NCryptSignHash)(k, &pi, h, 32, sig, sizeof sig, &cb, BCRYPT_PAD_PKCS1); OBS(215, r, 0); OBS(216, cb, 0x100);
    OBS(217, U(NCryptVerifySignature)(k, &pi, h, 32, sig, 256, BCRYPT_PAD_PKCS1), 0);
    /* deterministic PKCS#1 */
    cb2 = sizeof sig2; U(NCryptSignHash)(k, &pi, h, 32, sig2, sizeof sig2, &cb2, BCRYPT_PAD_PKCS1);
    OBS(218, memcmp(sig, sig2, 256), 0);
    /* mismatches */
    OBS(219, U(NCryptVerifySignature)(k, &pi1, h, 20, sig, 256, BCRYPT_PAD_PKCS1), 0x80090006);
    OBS(220, U(NCryptVerifySignature)(k, &pi1, h, 32, sig, 256, BCRYPT_PAD_PKCS1), 0x80090027);
    OBS(221, U(NCryptVerifySignature)(k, &pi, h, 31, sig, 256, BCRYPT_PAD_PKCS1), 0x80090027);
    OBS(222, U(NCryptVerifySignature)(k, &pi, h, 32, sig, 255, BCRYPT_PAD_PKCS1), 0x80090027);
    OBS(223, U(NCryptVerifySignature)(k, &pi, h, 32, sig, 257, BCRYPT_PAD_PKCS1), 0x80090006);
    OBS(224, U(NCryptVerifySignature)(k, &pi, h, 32, sig, 0, BCRYPT_PAD_PKCS1), 0x80090027);
    sig[100] ^= 1; OBS(225, U(NCryptVerifySignature)(k, &pi, h, 32, sig, 256, BCRYPT_PAD_PKCS1), 0x80090006); sig[100] ^= 1;
    OBS(226, U(NCryptVerifySignature)(k, NULL, h, 32, sig, 256, BCRYPT_PAD_PKCS1), 0x80090027);
    OBS(227, U(NCryptVerifySignature)(k, &pin, h, 32, sig, 256, BCRYPT_PAD_PKCS1), 0x80090006);
    OBS(228, U(NCryptVerifySignature)(k, &pib, h, 32, sig, 256, BCRYPT_PAD_PKCS1), 0x80090029);
    OBS(229, U(NCryptVerifySignature)(k, &pi, h, 32, sig, 256, 0), 0x80090009);
    OBS(230, U(NCryptVerifySignature)(k, &pi, h, 32, sig, 256, BCRYPT_PAD_PSS), 0x80090027);
    OBS(231, U(NCryptVerifySignature)(k, &pi, h, 32, sig, 256, BCRYPT_PAD_PKCS1 | 0x80000000), 0x80090009);
    OBS(232, U(NCryptVerifySignature)(k, &pi, NULL, 32, sig, 256, BCRYPT_PAD_PKCS1), 0x800706f4);
    OBS(233, U(NCryptVerifySignature)(k, &pi, h, 32, NULL, 256, BCRYPT_PAD_PKCS1), 0x800706f4);
    OBS(234, U(NCryptVerifySignature)(0, &pi, h, 32, sig, 256, BCRYPT_PAD_PKCS1), 0x80090026);
    /* PKCS#1 sign argument validation / ordering */
    cb = 99; r = U(NCryptSignHash)(k, &pi, h, 32, sig, 100, &cb, BCRYPT_PAD_PKCS1); OBS(235, r, 0x80090028); OBS(236, cb, 0x100);
    r = U(NCryptSignHash)(k, NULL, h, 32, sig, 256, &cb, BCRYPT_PAD_PKCS1); OBS(237, r, 0x80090027);
    r = U(NCryptSignHash)(k, &pin, h, 32, sig, 256, &cb, BCRYPT_PAD_PKCS1); OBS(238, r, 0);
    r = U(NCryptSignHash)(k, &pib, h, 32, sig, 256, &cb, BCRYPT_PAD_PKCS1); OBS(239, r, 0x80090029);
    r = U(NCryptSignHash)(k, &pi, h, 20, sig, 256, &cb, BCRYPT_PAD_PKCS1); OBS(240, r, 0x80090027);
    r = U(NCryptSignHash)(k, &pi, h, 0, sig, 256, &cb, BCRYPT_PAD_PKCS1); OBS(241, r, 0x80090027);
    r = U(NCryptSignHash)(k, &pi, NULL, 32, sig, 256, &cb, BCRYPT_PAD_PKCS1); OBS(242, r, 0x800706f4);
    r = U(NCryptSignHash)(k, &pi, h, 32, sig, 256, NULL, BCRYPT_PAD_PKCS1); OBS(243, r, 0x800706f4);
    r = U(NCryptSignHash)(k, &pi, h, 32, sig, 256, &cb, 0); OBS(244, r, 0x80090009);
    r = U(NCryptSignHash)(k, &pi, h, 32, sig, 256, &cb, 0x80000000); OBS(245, r, 0x80090009);
    r = U(NCryptSignHash)(k, &pi, h, 32, sig, 256, &cb, BCRYPT_PAD_PKCS1 | BCRYPT_PAD_PSS); OBS(246, r, 0);
    r = U(NCryptSignHash)(k, &pi, h, 32, sig, 256, &cb, BCRYPT_PAD_OAEP); OBS(247, r, 0x80090009);
    r = U(NCryptSignHash)(k, NULL, h, 32, sig, 256, &cb, 0); OBS(248, r, 0x80090027);
    r = U(NCryptSignHash)(p, &pi, h, 32, sig, 256, &cb, BCRYPT_PAD_PKCS1); OBS(249, r, 0x80090026);
    /* PSS (TLS 1.3 / WebCrypto) */
    cb = 0; r = U(NCryptSignHash)(k, &ps, h, 32, NULL, 0, &cb, BCRYPT_PAD_PSS); OBS(250, r, 0); OBS(251, cb, 0x100);
    cb2 = sizeof sig; r = U(NCryptSignHash)(k, &ps, h, 32, sig, sizeof sig, &cb2, BCRYPT_PAD_PSS); OBS(252, r, 0); OBS(253, cb2, 0x100);
    OBS(254, U(NCryptVerifySignature)(k, &ps, h, 32, sig, cb2, BCRYPT_PAD_PSS), 0);
    OBS(255, U(NCryptVerifySignature)(k, &ps0, h, 32, sig, cb2, BCRYPT_PAD_PSS), 0x80090027);      /* salt length mismatch */
    OBS(256, U(NCryptVerifySignature)(k, &ps, h, 32, sig, cb2, BCRYPT_PAD_PKCS1), 0x80090006);
    cb = 99; r = U(NCryptSignHash)(k, &psbig, h, 32, sig2, sizeof sig2, &cb, BCRYPT_PAD_PSS); OBS(257, r, 0x80090027);
    cb = 99; r = U(NCryptSignHash)(k, NULL, h, 32, sig2, sizeof sig2, &cb, BCRYPT_PAD_PSS); OBS(258, r, 0x80090027);
    cb2 = sizeof sig2; r = U(NCryptSignHash)(k, &ps0, h, 32, sig2, sizeof sig2, &cb2, BCRYPT_PAD_PSS); OBS(259, r, 0);
    /* a second key does not verify */
    k2 = bp_key(p, L"RSA", 2048, 0, 0, 1);
    if (k2) {   /* NTE_BAD_SIGNATURE, or NTE_INVALID_PARAMETER when the signature value exceeds the other modulus (random keys) */
        DWORD vr = (DWORD)U(NCryptVerifySignature)(k2, &pi, h, 32, sig, 256, BCRYPT_PAD_PKCS1);
        CHECKF(vr == 0x80090006u || vr == 0x80090027u, "verify with a different RSA key -> 0x%08lx", (unsigned long)vr);
        bp_free(k2);
    }
    /* no key usage for signing */
    k2 = bp_key(p, L"RSA", 2048, 0, NCRYPT_ALLOW_DECRYPT_FLAG, 1);
    if (k2) { cb = 99; r = U(NCryptSignHash)(k2, &pi, h, 32, sig2, sizeof sig2, &cb, BCRYPT_PAD_PKCS1); OBS(261, r, 0x80090010); bp_free(k2); }
    bp_free(k); bp_free(p);
}

/* ---- opaque transport, plaintext export policy, import round trip ---------------------------------------------------- */
TEST(brw_export_policy_and_opaque_transport) {
    BP_NEED();
    REQUIRE(U(NCryptExportKey)); REQUIRE(U(NCryptImportKey));
    NCRYPT_PROV_HANDLE p = bp_prov(); NCRYPT_KEY_HANDLE k, k2; BYTE blob[4096], h[32], sig[128]; DWORD cb = 0, cs, v = 0; LONG r; unsigned i;
    REQUIRE(p);
    k = bp_key(p, L"ECDSA_P256", 0, NCRYPT_ALLOW_EXPORT_FLAG, 0, 1); REQUIRE(k);
    r = U(NCryptGetProperty)(k, L"Export Policy", (PBYTE)&v, 4, &cb, 0); OBS(262, r, 0); OBS(263, v, 1);
    /* only the encrypted (opaque transport / PKCS#8 with password) forms are allowed without the plaintext flag */
    cb = 0; r = U(NCryptExportKey)(k, 0, BCRYPT_ECCPRIVATE_BLOB, NULL, NULL, 0, &cb, 0); OBS(264, r, 0x80090029);
    cb = 0; r = U(NCryptExportKey)(k, 0, NCRYPT_OPAQUETRANSPORT_BLOB, NULL, NULL, 0, &cb, 0); OBS(265, r, 0x8009000b); OBSN(266, cb);
    cb = sizeof blob; r = U(NCryptExportKey)(k, 0, NCRYPT_OPAQUETRANSPORT_BLOB, NULL, blob, sizeof blob, &cb, 0); OBS(267, r, 0x8009000b);
    /* the software KSP does not produce opaque transport blobs; importing garbage of that type fails too */
    {   BYTE junk[96]; memset(junk, 0x5A, sizeof junk);
        k2 = 0xAB; r = U(NCryptImportKey)(p, 0, NCRYPT_OPAQUETRANSPORT_BLOB, NULL, &k2, junk, sizeof junk, 0); OBS(701, r, 0x80090005); OBS(702, k2, 0xab);
        k2 = 0xAB; r = U(NCryptImportKey)(p, 0, NCRYPT_OPAQUETRANSPORT_BLOB, NULL, &k2, junk, 3, 0); OBS(703, r, 0x80090005);
        k2 = 0xAB; r = U(NCryptImportKey)(p, 0, NCRYPT_OPAQUETRANSPORT_BLOB, NULL, &k2, junk, 0, 0); OBS(704, r, 0x80090027);
        k2 = 0xAB; r = U(NCryptImportKey)(p, 0, NCRYPT_PKCS8_PRIVATE_KEY_BLOB, NULL, &k2, junk, sizeof junk, 0); OBS(705, r, 0x80092002);
        k2 = 0xAB; r = U(NCryptImportKey)(p, 0, BCRYPT_ECCPRIVATE_BLOB, NULL, &k2, junk, sizeof junk, 0); OBS(706, r, 0x80090027);
        k2 = 0xAB; r = U(NCryptImportKey)(p, 0, BCRYPT_RSAPRIVATE_BLOB, NULL, &k2, junk, sizeof junk, 0); OBS(707, r, 0x80090029);
        k2 = 0xAB; r = U(NCryptImportKey)(p, 0, L"No Such Blob", NULL, &k2, junk, sizeof junk, 0); OBS(708, r, 0x80090029);
    }
    bp_free(k);
    /* plaintext export needs the plaintext flag on the key */
    k = bp_key(p, L"ECDSA_P256", 0, NCRYPT_ALLOW_EXPORT_FLAG | NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG, 0, 1);
    if (k) {
        cb = 0; r = U(NCryptExportKey)(k, 0, BCRYPT_ECCPRIVATE_BLOB, NULL, NULL, 0, &cb, 0); OBS(277, r, 0); OBS(278, cb, 0x68);
        cb = sizeof blob; r = U(NCryptExportKey)(k, 0, BCRYPT_ECCPRIVATE_BLOB, NULL, blob, sizeof blob, &cb, 0); OBS(279, r, 0);
        OBS(280, ((BCRYPT_ECCKEY_BLOB *)blob)->dwMagic, 0x32534345);
        k2 = 0; r = U(NCryptImportKey)(p, 0, BCRYPT_ECCPRIVATE_BLOB, NULL, &k2, blob, cb, 0); OBS(281, r, 0);
        if (k2) {
            r = U(NCryptGetProperty)(k2, L"Export Policy", (PBYTE)&v, 4, &cb, 0); OBS(282, r, 0); OBS(283, v, 0);
            bp_free(k2);
        }
        bp_free(k);
    }
    /* a key with no export policy */
    k = bp_key(p, L"ECDSA_P256", 0, 0, 0, 1);
    if (k) {
        cb = 0; r = U(NCryptExportKey)(k, 0, NCRYPT_OPAQUETRANSPORT_BLOB, NULL, NULL, 0, &cb, 0); OBS(284, r, 0x8009000b);
        v = NCRYPT_ALLOW_EXPORT_FLAG; r = U(NCryptSetProperty)(k, L"Export Policy", (PBYTE)&v, 4, 0); OBS(285, r, 0);
        bp_free(k);
    }
    bp_free(p);
}

/* ---- create / open / delete argument validation and ordering -------------------------------------------------------- */
TEST(brw_create_open_delete_args) {
    BP_NEED();
    REQUIRE(U(NCryptCreatePersistedKey)); REQUIRE(U(NCryptOpenKey)); REQUIRE(U(NCryptDeleteKey)); REQUIRE(U(NCryptFinalizeKey));
    NCRYPT_PROV_HANDLE p = bp_prov(); NCRYPT_KEY_HANDLE k = 0xAB; LONG r;
    REQUIRE(p);
    OBS(286, U(NCryptCreatePersistedKey)(p, NULL, L"RSA", NULL, 0, 0), 0x80090027);
    k = 0xAB; OBS(287, U(NCryptCreatePersistedKey)(p, &k, NULL, NULL, 0, 0), 0x800706f4); OBS(288, k, 0xab);
    k = 0xAB; OBS(289, U(NCryptCreatePersistedKey)(p, &k, L"", NULL, 0, 0), 0x80090029); OBS(290, k, 0xab);
    k = 0xAB; OBS(291, U(NCryptCreatePersistedKey)(p, &k, L"No Such Alg", NULL, 0, 0), 0x80090029); OBS(292, k, 0xab);
    k = 0xAB; OBS(293, U(NCryptCreatePersistedKey)(p, &k, L"SHA256", NULL, 0, 0), 0x80090029);
    k = 0xAB; OBS(294, U(NCryptCreatePersistedKey)(p, &k, L"AES", NULL, 0, 0), 0);
    k = 0xAB; OBS(295, U(NCryptCreatePersistedKey)(0, &k, L"RSA", NULL, 0, 0), 0x80090026); OBS(296, k, 0xab);
    k = 0xAB; OBS(298, U(NCryptCreatePersistedKey)(p, &k, L"RSA", NULL, 0, 0x80000000), 0x80090009);
    k = 0xAB; r = U(NCryptCreatePersistedKey)(p, &k, L"RSA", NULL, 0, 0x10); OBS(299, r, 0x80090009); if (r == 0) bp_free(k);     /* LEGACY_KEY_SPEC-like bit */
    k = 0xAB; r = U(NCryptCreatePersistedKey)(p, &k, L"RSA", NULL, 1, 0); OBS(300, r, 0); if (r == 0) bp_free(k);        /* dwLegacyKeySpec */
    k = 0xAB; r = U(NCryptCreatePersistedKey)(p, &k, L"RSA", NULL, 2, 0); OBS(301, r, 0); if (r == 0) bp_free(k);
    k = 0xAB; r = U(NCryptCreatePersistedKey)(p, &k, L"RSA", NULL, 3, 0); OBS(302, r, 0); if (r == 0) bp_free(k);
    /* finalize */
    OBS(303, U(NCryptFinalizeKey)(0, 0), 0x80090026);
    OBS(304, U(NCryptFinalizeKey)(p, 0), 0x80090026);
    k = bp_key(p, L"ECDSA_P256", 0, 0, 0, 0);
    if (k) {
        OBS(305, U(NCryptFinalizeKey)(k, 0x80000000), 0x80090009);
        OBS(306, U(NCryptFinalizeKey)(k, NCRYPT_SILENT_FLAG), 0);
        /* delete: ephemeral key (no name) */
        r = U(NCryptDeleteKey)(k, 0); OBS(307, r, 0);
        if (r != 0) bp_free(k);
    }
    OBS(308, U(NCryptDeleteKey)(0, 0), 0x80090026);
    OBS(309, U(NCryptDeleteKey)(p, 0), 0x80090026);
    /* open a name that cannot exist (read only) */
    {   const WCHAR *nm = t_unique_w("nokey"); k = 0xAB;
        r = U(NCryptOpenKey)(p, &k, nm, 0, 0); OBS(311, r, 0x80090016); OBS(312, k, 0xab);
        k = 0xAB; r = U(NCryptOpenKey)(p, &k, nm, 0, NCRYPT_MACHINE_KEY_FLAG); OBS(313, r, 0x80090016);
        k = 0xAB; r = U(NCryptOpenKey)(p, &k, NULL, 0, 0); OBS(314, r, 0x800706f4);
        k = 0xAB; r = U(NCryptOpenKey)(p, &k, L"", 0, 0); OBS(315, r, 0x80090016);
        k = 0xAB; r = U(NCryptOpenKey)(p, NULL, nm, 0, 0); OBS(316, r, 0x80090027);
        k = 0xAB; r = U(NCryptOpenKey)(0, &k, nm, 0, 0); OBS(317, r, 0x80090026);
        k = 0xAB; r = U(NCryptOpenKey)(p, &k, nm, 0, 0x80000000); OBS(318, r, 0x80090009);
    }
    bp_free(p);
}

/* ---- NCryptEnumKeys read only, handle type confusion, free ------------------------------------------------------------ */
TEST(brw_enumkeys_and_handles) {
    BP_NEED();
    REQUIRE(U(NCryptEnumKeys)); REQUIRE(U(NCryptFreeObject));
    NCRYPT_PROV_HANDLE p = bp_prov(); NCryptKeyName *kn = NULL; PVOID st = NULL; LONG r; int n = 0; NCRYPT_KEY_HANDLE k;
    REQUIRE(p);
    OBS(319, U(NCryptEnumKeys)(p, NULL, NULL, &st, 0), 0x80090027);
    OBS(320, U(NCryptEnumKeys)(p, NULL, &kn, NULL, 0), 0x80090027);
    OBS(321, U(NCryptEnumKeys)(0, NULL, &kn, &st, 0), 0x80090026);
    OBS(322, U(NCryptEnumKeys)(p, NULL, &kn, &st, 0x80000000), 0x80090009);
    st = NULL; while (n < 100000 && (r = U(NCryptEnumKeys)(p, NULL, &kn, &st, NCRYPT_SILENT_FLAG)) == 0) { n++; U(NCryptFreeBuffer)(kn); }
    OBS(323, r, 0x8009002a);                    /* NTE_NO_MORE_ITEMS at the end of the list */
    t_note("user keys enumerated through the software KSP: %d", n);
    if (st) U(NCryptFreeBuffer)(st);
    /* handle kinds */
    k = bp_key(p, L"ECDSA_P256", 0, 0, 0, 1);
    if (k) {
        BYTE b[32]; DWORD cb;
        OBS(324, U(NCryptIsKeyHandle)(k), 1);
        OBS(325, U(NCryptIsKeyHandle)(p), 0);
        OBS(326, U(NCryptIsKeyHandle)(0), 0);
        OBS(327, U(NCryptIsAlgSupported)(k, L"RSA", 0), 0x80090026);                  /* key handle as provider */
        OBS(328, U(NCryptEnumKeys)(k, NULL, &kn, &st, 0), 0x80090026);
        OBS(329, U(NCryptGetProperty)(p, L"Name", b, sizeof b, &cb, 0), 0x80090028);
        cb = 0; r = U(NCryptGetProperty)(p, L"Impl Type", b, 4, &cb, 0); OBS(330, r, 0); OBS(331, *(DWORD *)b, 2);
        r = U(NCryptGetProperty)(p, L"Max Name Length", b, 4, &cb, 0); OBS(332, r, 0); OBS(333, *(DWORD *)b, 0x104);
        bp_free(p);                                                          /* provider freed first: key stays usable */
        { BYTE h[32], sig[64]; DWORD cs = sizeof sig; bp_digest(h, 32); OBS(334, U(NCryptSignHash)(k, NULL, h, 32, sig, sizeof sig, &cs, 0), 0); }
        OBS(335, U(NCryptFreeObject)(k), 0);
        OBS(336, U(NCryptFreeObject)(k), 0x80090026);                                 /* double free of the handle value */
    } else bp_free(p);
    OBS(337, U(NCryptFreeObject)(0), 0x80090026);
}

/* ---- ProtectSecret / UnprotectSecret presence --------------------------------------------------------------------------- */
TEST(brw_protect_secret_resolve) {
    BP_NEED();
    OBS(339, t_proc_in("ncrypt.dll", "NCryptProtectSecret") != NULL, 1);
    OBS(340, t_proc_in("ncrypt.dll", "NCryptUnprotectSecret") != NULL, 1);
    OBS(341, t_proc_in("ncrypt.dll", "NCryptCreateProtectionDescriptor") != NULL, 1);
    OBS(342, t_proc_in("ncrypt.dll", "NCryptStreamOpenToProtect") != NULL, 1);
    OBS(343, t_proc_in("ncrypt.dll", "NCryptIsAlgSupported") != NULL, 1);
    OBS(344, t_proc_in("ncrypt.dll", "NCryptSignHash") != NULL, 1);
    OBS(345, t_proc_in("ncrypt.dll", "NCryptVerifySignature") != NULL, 1);
    OBS(346, t_proc_in("ncrypt.dll", "NCryptDeleteKey") != NULL, 1);
    OBS(347, t_proc_in("ncrypt.dll", "NCryptImportKey") != NULL, 1);
    OBS(348, t_proc_in("ncrypt.dll", "NCryptKeyDerivation") != NULL, 1);
    OBS(349, t_proc_in("ncrypt.dll", "NCryptSecretAgreement") != NULL, 1);
    OBS(350, t_proc_in("ncrypt.dll", "NCryptTranslateHandle") != NULL, 1);
    OBS(351, t_proc_in("ncrypt.dll", "NCryptNotifyChangeKey") != NULL, 1);
}

/* ---- unissued handle values: ncrypt dereferences the handle without validating it --------------------------------------- */
TEST(brw_unissued_handles_fault) {
    BP_NEED();
    NCRYPT_PROV_HANDLE p = bp_prov(); BYTE b[16]; DWORD cb = 0, v = 0; NCRYPT_KEY_HANDLE k = 0;
    REQUIRE(p);
    OBSF(352, U(NCryptFreeObject)(0x1234));
    OBSF(353, U(NCryptIsAlgSupported)(0x1234, L"RSA", 0));
    OBSF(354, U(NCryptGetProperty)(0x1234, L"Length", b, 4, &cb, 0));
    OBSF(355, U(NCryptSetProperty)(0x1234, L"Length", (PBYTE)&v, 4, 0));
    OBSF(356, U(NCryptDeleteKey)(0x1234, 0));
    OBSF(357, U(NCryptCreatePersistedKey)(0x1234, &k, L"RSA", NULL, 0, 0));
    OBSF(358, U(NCryptSignHash)(0x1234, NULL, b, 0, NULL, 0, &cb, 0));
    OBSF(359, U(NCryptEnumKeys)(0x1234, NULL, NULL, NULL, 0));
    bp_free(p);
}
