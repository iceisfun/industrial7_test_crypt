/* Argument validation of the ncrypt.dll Ssl* functions that ncrypt_ssl_provider does not cover: master/session key
 * generation and import, key import/export, packet encrypt/decrypt, cipher lookups, EAP key block, handshake hash,
 * provider reference counts, BCryptSetAuditingInterface, GetSChannelInterface.
 * Every expectation was observed on Windows 10 22H2 first. Only calls without side effects outside the process;
 * no handshake, no network. */
#include "sa.h"

/* per-iteration expectations of looped checks (observed on Windows 10) */
static const unsigned long long VT_64[] = { 0, 0x80090029, 0x80090005, 0x80090029, 0x80090029, 0x80090029, 0x80090029 };
static const unsigned long long VT_88[] = { 0, 0x80090027, 0x80090029, 0x80090029, 0x80090029, 0, 0x80090027, 0x80090029, 0x80090029, 0x80090029, 0, 0x80090027, 0x80090029, 0x80090029, 0x80090029, 0, 0x80090027, 0x80090029, 0x80090029, 0x80090029, 0x80090027, 0, 0x80090029, 0x80090029, 0x80090029, 0x80090027, 0, 0x80090029, 0x80090029, 0x80090029, 0, 0x80090027, 0x80090029, 0x80090029, 0x80090029, 0x80090027, 0x80090027, 0x80090029, 0x80090029, 0x80090029, 0x80090027, 0x80090027, 0x80090029, 0x80090029, 0x80090029 };
static const unsigned long long VT_110[] = { 0x80090029, 0x80090026, 0x80090026, 0x80090026, 0x80090026, 0x80090027, 0x80090027, 0x80090027, 0x80090026, 0x80090026, 0x80090026, 0x80090026, 0x80090026, 0x80090026, 0x80090026, 0x80090026, 0x80090026, 0x80090026, 0x80090026, 0x80090027, 0x80090026, 0x80090026, 0x80090027, 0x80090027, 0x80090026, 0x80090026, 0x80090026, 0x80090027, 0x80090026, 0x80090027, 0x80090026, 0x80090026 };
static const unsigned long long VT_111[] = { 0x80090029, 0x80090026, 0x80090026, 0x80090026, 0x80090026, 0x80090026, 0x80090026, 0x80090026, 0x80090026, 0x80090026, 0x80090026, 0x80090026, 0x80090026, 0x80090026, 0x80090026, 0x80090026, 0x80090026, 0x80090026, 0x80090026, 0x80090026, 0x80090026, 0x80090026, 0x80090026, 0x80090026, 0x80090026, 0x80090026, 0x80090026, 0x80090026, 0x80090026, 0x80090026, 0x80090026, 0x80090026 };
static const unsigned long long VT_112[] = { 0x80090029, 0x80090026, 0x80090026, 0x80090026, 0x80090026, 0x80090026, 0x80090026, 0x80090026, 0x80090026, 0x80090026, 0x80090026, 0x80090026, 0x80090026, 0x80090026, 0x80090026, 0x80090026, 0x80090026, 0x80090026, 0x80090026, 0x80090026, 0x80090026, 0x80090026, 0x80090026, 0x80090026, 0x80090026, 0x80090027, 0x80090026, 0x80090026, 0x80090026, 0x80090026, 0x80090026, 0x80090026 };

static DWORD fakep[0x80], fakek[0x80];

/* ---- forged / invalid provider handles ------------------------------------------------------------------------ */
TEST(sslargs_keyfuncs_bad_provider) {
    SA_NEED();
    SF(sa_genmaster_t, SslGenerateMasterKey); SF(sa_gensess_t, SslGenerateSessionKeys); SF(sa_impmaster_t, SslImportMasterKey);
    SF(sa_genpre_t, SslGeneratePreMasterKey); SF(sa_impkey_t, SslImportKey); SF(sa_expkey_t, SslExportKey);
    SF(sa_packet_t, SslEncryptPacket); SF(sa_packet_t, SslDecryptPacket); SF(sa_eap_t, SslComputeEapKeyBlock);
    SF(sa_hashhs_t, SslHashHandshake); SF(sa_mkhash_t, SslCreateHandshakeHash);
    REQUIRE_NOTNULL(SslGenerateMasterKey); REQUIRE_NOTNULL(SslGenerateSessionKeys); REQUIRE_NOTNULL(SslImportMasterKey);
    REQUIRE_NOTNULL(SslGeneratePreMasterKey); REQUIRE_NOTNULL(SslImportKey); REQUIRE_NOTNULL(SslExportKey);
    REQUIRE_NOTNULL(SslEncryptPacket); REQUIRE_NOTNULL(SslDecryptPacket); REQUIRE_NOTNULL(SslComputeEapKeyBlock);
    REQUIRE_NOTNULL(SslHashHandshake); REQUIRE_NOTNULL(SslCreateHandshakeHash);
    ULONG_PTR h1 = 0x1234, h2 = 0x4321; DWORD cb = 0; BYTE buf[64] = {0};
    int v;
    for (v = 0; v < 5; v++) {
        ULONG_PTR p;
        t_label("provider variant %d", v);
        if (v == 0) p = 0;
        else if (v == 1) { p = (ULONG_PTR)fakep; sa_forge(fakep, 0x178, SA_MAGIC_PROV, 0xFFFFFFFF); }
        else {
            p = (ULONG_PTR)fakep;
            if (v == 2) sa_forge(fakep, 0x178, SA_MAGIC_KEY, 0);        /* key magic */
            if (v == 3) sa_forge(fakep, 0x177, SA_MAGIC_PROV, 0);       /* small */
            if (v == 4) sa_forge(fakep, 0x178, SA_MAGIC_PROV, 1);       /* flagged */
        }
        h1 = h2 = 0x1234;
        OBS(1, SslGenerateMasterKey(p, 0, 0, &h1, 0x303, 0x2f, NULL, buf, sizeof buf, &cb, 0), 0x80090026);
        OBS(2, SslGenerateMasterKey(p, 0, 0, NULL, 0, 0, NULL, NULL, 0, NULL, 0), 0x80090026);
        OBS(3, SslGenerateSessionKeys(p, 0, &h1, &h2, NULL, 0), 0x80090026);
        OBS(4, SslGenerateSessionKeys(p, 0, NULL, NULL, NULL, 0), 0x80090026);
        OBS(5, SslImportMasterKey(p, 0, &h1, 0x303, 0x2f, NULL, buf, sizeof buf, 0), 0x80090026);
        OBS(6, SslGeneratePreMasterKey(p, 0, &h1, 0x303, 0x2f, NULL, buf, sizeof buf, &cb, 0), 0x80090026);
        OBS(7, SslImportKey(p, &h1, L"x", buf, sizeof buf, 0), 0x80090026);
        OBS(8, SslExportKey(p, 0, L"x", buf, sizeof buf, &cb, 0), 0x80090026);
        OBS(9, SslEncryptPacket(p, 0, buf, 16, buf, 64, &cb, 0, 0x17, 0), 0x80090026);
        OBS(10, SslDecryptPacket(p, 0, buf, 16, buf, 64, &cb, 0, 0x17, 0), 0x80090026);
        OBS(11, SslComputeEapKeyBlock(p, 0, buf, 64, buf, 64, &cb, 0), 0x80090026);
        OBS(12, SslHashHandshake(p, 0, buf, 16, 0), 0x80090026);
        OBS(13, SslCreateHandshakeHash(p, &h1, 0x303, 0x2f, 0), 0x80090026);
        OBS(14, h1, 0x1234);                 /* output handle left untouched on failure */
    }
}

/* ---- valid provider, invalid (zero / unissued / forged) key handles: order of validation --------------------------- */
TEST(sslargs_keyfuncs_valid_provider_bad_keys) {
    SA_NEED();
    SF(sa_genmaster_t, SslGenerateMasterKey); SF(sa_gensess_t, SslGenerateSessionKeys); SF(sa_impmaster_t, SslImportMasterKey);
    SF(sa_genpre_t, SslGeneratePreMasterKey); SF(sa_expkey_t, SslExportKey);
    SF(sa_packet_t, SslEncryptPacket); SF(sa_packet_t, SslDecryptPacket); SF(sa_eap_t, SslComputeEapKeyBlock);
    REQUIRE_NOTNULL(SslGenerateMasterKey); REQUIRE_NOTNULL(SslGenerateSessionKeys); REQUIRE_NOTNULL(SslImportMasterKey);
    REQUIRE_NOTNULL(SslGeneratePreMasterKey); REQUIRE_NOTNULL(SslExportKey); REQUIRE_NOTNULL(SslEncryptPacket);
    REQUIRE_NOTNULL(SslDecryptPacket); REQUIRE_NOTNULL(SslComputeEapKeyBlock);
    ULONG_PTR h = sa_open(), a = 0x1234, b = 0x1234; DWORD cb = 0; BYTE buf[64] = {0}; int v;
    REQUIRE(h);
    for (v = 0; v < 4; v++) {
        ULONG_PTR k; t_label("key variant %d", v);
        if (v == 0) k = 0;
        else if (v == 1) { k = (ULONG_PTR)fakek; sa_forge(fakek, 0x100, SA_MAGIC_KEY, 0xFFFFFFFF); }
        else { k = (ULONG_PTR)fakek; if (v == 2) sa_forge(fakek, 0x100, SA_MAGIC_PROV, 0); else sa_forge(fakek, 0x10, SA_MAGIC_KEY, 0); }
        a = b = 0x1234;
        OBS(15, SslGenerateMasterKey(h, k, k, &a, 0x303, 0x2f, NULL, buf, sizeof buf, &cb, 0), 0x80090027);
        OBS(16, SslGenerateSessionKeys(h, k, &a, &b, NULL, 0), 0x80090026);
        OBS(17, SslImportMasterKey(h, k, &a, 0x303, 0x2f, NULL, buf, sizeof buf, 0), 0x80090026);
        OBS(18, SslGeneratePreMasterKey(h, k, &a, 0x303, 0x2f, NULL, buf, sizeof buf, &cb, 0), 0x80090027);
        OBS(19, SslExportKey(h, k, L"x", buf, sizeof buf, &cb, 0), 0x80090026);
        OBS(20, SslEncryptPacket(h, k, buf, 16, buf, 64, &cb, 0, 0x17, 0), 0x80090026);
        OBS(21, SslDecryptPacket(h, k, buf, 16, buf, 64, &cb, 0, 0x17, 0), 0x80090026);
        OBS(22, SslComputeEapKeyBlock(h, k, buf, 64, buf, 64, &cb, 0), 0x80090026);
        OBS(23, a, 0x1234);
        OBS(24, b, 0x1234);
    }
    sa_close(h);
}

/* ---- valid provider, NULL / zero / oversized arguments: which parameter error comes first -------------------------- */
TEST(sslargs_keyfuncs_null_args_order) {
    SA_NEED();
    SF(sa_genmaster_t, SslGenerateMasterKey); SF(sa_gensess_t, SslGenerateSessionKeys); SF(sa_impmaster_t, SslImportMasterKey);
    SF(sa_genpre_t, SslGeneratePreMasterKey); SF(sa_impkey_t, SslImportKey); SF(sa_expkey_t, SslExportKey);
    SF(sa_packet_t, SslEncryptPacket); SF(sa_packet_t, SslDecryptPacket); SF(sa_eap_t, SslComputeEapKeyBlock);
    SF(sa_hashhs_t, SslHashHandshake); SF(sa_mkhash_t, SslCreateHandshakeHash);
    REQUIRE_NOTNULL(SslGenerateMasterKey); REQUIRE_NOTNULL(SslGenerateSessionKeys); REQUIRE_NOTNULL(SslImportMasterKey);
    REQUIRE_NOTNULL(SslGeneratePreMasterKey); REQUIRE_NOTNULL(SslImportKey); REQUIRE_NOTNULL(SslExportKey);
    REQUIRE_NOTNULL(SslEncryptPacket); REQUIRE_NOTNULL(SslDecryptPacket); REQUIRE_NOTNULL(SslComputeEapKeyBlock);
    REQUIRE_NOTNULL(SslHashHandshake); REQUIRE_NOTNULL(SslCreateHandshakeHash);
    ULONG_PTR h = sa_open(), a = 0x1234, b = 0x1234; DWORD cb = 99; BYTE buf[64] = {0};
    REQUIRE(h);
    OBS(25, SslGenerateMasterKey(h, 0, 0, NULL, 0x303, 0x2f, NULL, buf, 64, &cb, 0), 0x80090027);
    OBS(26, SslGenerateMasterKey(h, 0, 0, &a, 0, 0, NULL, NULL, 0, NULL, 0), 0x80090029);
    OBS(27, SslGenerateMasterKey(h, 0, 0, &a, 0x303, 0x2f, NULL, buf, 64, &cb, 0x80000000), 0x80090027);
    OBS(28, SslGenerateSessionKeys(h, 0, NULL, &b, NULL, 0), 0x80090026);
    OBS(29, SslGenerateSessionKeys(h, 0, &a, NULL, NULL, 0), 0x80090026);
    OBS(30, SslGenerateSessionKeys(h, 0, &a, &b, NULL, 0x80000000), 0x80090026);
    OBS(31, SslImportMasterKey(h, 0, NULL, 0x303, 0x2f, NULL, buf, 64, 0), 0x80090026);
    OBS(32, SslImportMasterKey(h, 0, &a, 0x303, 0x2f, NULL, NULL, 0, 0), 0x80090026);
    OBS(33, SslImportMasterKey(h, 0, &a, 0x303, 0x2f, NULL, buf, 0, 0), 0x80090026);
    OBS(34, SslImportMasterKey(h, 0, &a, 0, 0, NULL, buf, 64, 0), 0x80090026);
    OBS(35, SslGeneratePreMasterKey(h, 0, NULL, 0x303, 0x2f, NULL, buf, 64, &cb, 0), 0x80090027);
    OBS(36, SslGeneratePreMasterKey(h, 0, &a, 0x303, 0x2f, NULL, NULL, 0, NULL, 0), 0x80090027);
    OBS(37, SslGeneratePreMasterKey(h, 0, &a, 0, 0, NULL, buf, 64, &cb, 0), 0x80090029);
    OBS(38, SslGeneratePreMasterKey(h, 0, &a, 0x303, 0x2f, NULL, buf, 64, &cb, 0xFFFFFFFF), 0x80090027);
    OBS(39, SslImportKey(h, NULL, L"x", buf, 64, 0), 0x80090027);
    OBSF(40, SslImportKey(h, &a, NULL, buf, 64, 0));
    OBS(41, SslImportKey(h, &a, L"", buf, 64, 0), 0x80090029);
    OBS(42, SslImportKey(h, &a, L"x", NULL, 0, 0), 0x80090027);
    OBS(43, SslImportKey(h, &a, L"x", buf, 0, 0), 0x80090029);
    OBS(44, SslImportKey(h, &a, L"x", buf, 64, 0x80000000), 0x80090009);
    OBS(45, SslExportKey(h, 0, NULL, buf, 64, &cb, 0), 0x80090026);
    OBS(46, SslExportKey(h, 0, L"x", buf, 64, NULL, 0), 0x80090026);
    OBS(47, SslExportKey(h, 0, L"x", NULL, 0, &cb, 0), 0x80090026);
    OBS(48, SslEncryptPacket(h, 0, NULL, 0, NULL, 0, NULL, 0, 0, 0), 0x80090026);
    OBS(49, SslEncryptPacket(h, 0, buf, 16, buf, 64, NULL, 0, 0x17, 0), 0x80090026);
    OBS(50, SslEncryptPacket(h, 0, buf, 16, buf, 64, &cb, 0, 0x17, 0x80000000), 0x80090026);
    OBS(51, SslDecryptPacket(h, 0, NULL, 0, NULL, 0, NULL, 0, 0, 0), 0x80090026);
    OBS(52, SslDecryptPacket(h, 0, buf, 16, buf, 64, NULL, 0, 0x17, 0), 0x80090026);
    OBS(53, SslDecryptPacket(h, 0, buf, 16, buf, 64, &cb, 0, 0x17, 0x80000000), 0x80090026);
    OBS(54, SslComputeEapKeyBlock(h, 0, NULL, 0, NULL, 0, NULL, 0), 0x80090026);
    OBS(55, SslComputeEapKeyBlock(h, 0, buf, 64, buf, 64, NULL, 0), 0x80090026);
    OBS(56, SslComputeEapKeyBlock(h, 0, buf, 64, buf, 64, &cb, 0x80000000), 0x80090026);
    OBS(57, SslHashHandshake(h, 0, NULL, 0, 0), 0x80090026);
    OBS(58, SslHashHandshake(h, 0, buf, 16, 0x80000000), 0x80090026);
    OBS(59, SslCreateHandshakeHash(h, NULL, 0x303, 0x2f, 0), 0x80090027);
    OBS(60, SslCreateHandshakeHash(h, &a, 0, 0, 0), 0x80090029);
    OBS(61, SslCreateHandshakeHash(h, &a, 0x303, 0x2f, 0x80000000), 0x80090009);
    OBS(62, cb, 0x63);
    OBS(63, sa_ref(h), 1);          /* failed calls leave the reference count alone */
    sa_close(h);
}

/* ---- import / export / generate with a real RSA public key ---------------------------------------------------------- */
TEST(sslargs_rsa_premaster_flow) {
    SA_NEED();
    SF(sa_impkey_t, SslImportKey); SF(sa_expkey_t, SslExportKey); SF(sa_genpre_t, SslGeneratePreMasterKey);
    SF(sa_freeobj_t, SslFreeObject); SF(sa_freebuf_t, SslFreeBuffer);
    REQUIRE_NOTNULL(SslImportKey); REQUIRE_NOTNULL(SslExportKey); REQUIRE_NOTNULL(SslGeneratePreMasterKey);
    REQUIRE_NOTNULL(SslFreeObject);
    ULONG_PTR h = sa_open(), pub = 0x1234, pm = 0x1234; DWORD cbblob = 0, cb = 0, cb2 = 0; BYTE out[600]; LONG r;
    BYTE *blob = sa_rsa_pub_blob(1024, &cbblob);
    REQUIRE(h); REQUIRE_NOTNULL(blob);
    static const LPCWSTR types[] = { L"RSAPUBLICBLOB", L"CAPIPUBLICBLOB", L"OpaqueKeyBlob", L"KeyDataBlob", L"SSLKeyBlob", L"PublicKeyBlob", L"" };
    int i;
    for (i = 0; i < 7; i++) {
        pub = 0x1234;
        t_label("type %d", i);
        r = SslImportKey(h, &pub, i == 0 ? BCRYPT_RSAPUBLIC_BLOB : types[i], blob, cbblob, 0);
        OBSV(64, r);
        if (r == 0 && pub != 0 && pub != 0x1234) SslFreeObject(pub);
    }
    t_label("");
    pub = 0x1234;
    r = SslImportKey(h, &pub, BCRYPT_RSAPUBLIC_BLOB, blob, cbblob, 0);
    if (r == 0) {
        OBS(65, pub != 0 && pub != 0x1234, 1);
        OBSN(66, ((DWORD *)pub)[0]);       /* key object header word 0 */
        OBS(67, ((DWORD *)pub)[1], 0x44444442);   /* key object magic */
        OBS(68, sa_ref(h), 2);
        /* export round trip */
        cb = 0; r = SslExportKey(h, pub, BCRYPT_RSAPUBLIC_BLOB, NULL, 0, &cb, 0);
        OBS(69, r, 0); OBSN(70, cb);
        cb2 = cb; r = SslExportKey(h, pub, BCRYPT_RSAPUBLIC_BLOB, out, sizeof out, &cb2, 0);
        OBS(71, r, 0); OBS(72, cb2, 0x9b);
        cb = 4; r = SslExportKey(h, pub, BCRYPT_RSAPUBLIC_BLOB, out, 4, &cb, 0);
        OBS(73, r, 0x80090028); OBSN(74, cb);
        cb = 0; r = SslExportKey(h, pub, L"x-no-such-blob", out, sizeof out, &cb, 0);
        OBS(75, r, 0x80090029);
        /* premaster secret: RSA key exchange */
        pm = 0x1234; cb = 0;
        r = SslGeneratePreMasterKey(h, pub, &pm, 0x303, 0x2f, NULL, NULL, 0, &cb, 0);
        OBS(76, r, 0x80090027); OBSN(77, cb);
        memset(out, 0, sizeof out); cb = 0;
        r = SslGeneratePreMasterKey(h, pub, &pm, 0x303, 0x2f, NULL, out, sizeof out, &cb, 0);
        OBS(78, r, 0x80090027); OBS(79, cb, 0);
        OBS(80, pm != 0 && pm != 0x1234, 0);
        if (r == 0 && pm != 0 && pm != 0x1234) SslFreeObject(pm);
        pm = 0x1234; cb = 0;
        r = SslGeneratePreMasterKey(h, pub, &pm, 0x303, 0x2f, NULL, out, 4, &cb, 0);
        OBS(81, r, 0x80090027);
        {   /* parameter lists: empty, highest-version buffer, random buffers (buffer types 20..22 of the SSL provider) */
            NCryptBufferDesc d; NCryptBuffer nb[3]; DWORD ver = 0x0303; BYTE rnd[32] = {1};
            int vv;
            for (vv = 0; vv < 5; vv++) {
                memset(&d, 0, sizeof d); memset(nb, 0, sizeof nb);
                d.ulVersion = 0; d.pBuffers = nb;
                if (vv >= 1) d.cBuffers = 0;
                if (vv == 2) { nb[0].BufferType = 22; nb[0].cbBuffer = 4; nb[0].pvBuffer = &ver; d.cBuffers = 1; }
                if (vv == 3) { nb[0].BufferType = 22; nb[0].cbBuffer = 2; nb[0].pvBuffer = &ver; d.cBuffers = 1; }
                if (vv == 4) { nb[0].BufferType = 20; nb[0].cbBuffer = 32; nb[0].pvBuffer = rnd; nb[1].BufferType = 21; nb[1].cbBuffer = 32; nb[1].pvBuffer = rnd; d.cBuffers = 2; }
                pm = 0x1234; cb = 0; memset(out, 0, sizeof out); t_label("params variant %d", vv);
                r = SslGeneratePreMasterKey(h, pub, &pm, 0x303, 0x2f, vv ? &d : NULL, out, sizeof out, &cb, 0);
                OBS(330, r, vv == 2 ? 0x80090026 : 0x80090027); OBS(340, cb, 0);   /* only the 4 byte version buffer gets past the parameter check */
                if (r == 0 && pm != 0 && pm != 0x1234) SslFreeObject(pm);
            }
            t_label("");
        }
        {   /* an NCrypt public key handle (software KSP) as the exchange key, with the highest-version buffer */
            NCRYPT_PROV_HANDLE kp = 0; NCRYPT_KEY_HANDLE nk = 0; NCryptBufferDesc d; NCryptBuffer nb; DWORD ver = 0x0303;
            memset(&d, 0, sizeof d); nb.BufferType = 22; nb.cbBuffer = 4; nb.pvBuffer = &ver; d.cBuffers = 1; d.pBuffers = &nb;
            if (U(NCryptOpenStorageProvider)(&kp, NULL, 0) == 0 && U(NCryptImportKey)(kp, 0, BCRYPT_RSAPUBLIC_BLOB, NULL, &nk, blob, cbblob, 0) == 0) {
                pm = 0x1234; cb = 0; memset(out, 0, sizeof out);
                r = SslGeneratePreMasterKey(h, nk, &pm, 0x303, 0x2f, &d, out, sizeof out, &cb, 0);
                OBS(360, r, 0); OBS(361, cb, 0x80); OBS(362, pm != 0 && pm != 0x1234, 1);
                if (r == 0 && pm != 0 && pm != 0x1234) SslFreeObject(pm);
                U(NCryptFreeObject)(nk);
            }
            if (kp) U(NCryptFreeObject)(kp);
            /* the SSL provider key with the buffer */
            pm = 0x1234; cb = 0;
            r = SslGeneratePreMasterKey(h, pub, &pm, 0x303, 0x2f, &d, NULL, 0, &cb, 0);
            OBS(363, r, 0x80090026); OBS(364, cb, 0);
            r = SslGeneratePreMasterKey(h, pub, &pm, 0x303, 0x2f, &d, out, 4, &cb, 0);
            OBS(365, r, 0x80090026); OBS(366, cb, 0);
            nb.cbBuffer = 2; ver = 0x0303;
            r = SslGeneratePreMasterKey(h, pub, &pm, 0x303, 0x2f, &d, out, sizeof out, &cb, 0);
            OBS(367, r, 0x80090027); OBS(368, cb, 0);
            nb.cbBuffer = 4; d.ulVersion = 1;
            r = SslGeneratePreMasterKey(h, pub, &pm, 0x303, 0x2f, &d, out, sizeof out, &cb, 0);
            OBS(369, r, 0x80090027);
            d.ulVersion = 0; nb.BufferType = 99;
            r = SslGeneratePreMasterKey(h, pub, &pm, 0x303, 0x2f, &d, out, sizeof out, &cb, 0);
            OBS(370, r, 0x80090027);
        }
        pm = 0x1234; cb = 0;
        r = SslGeneratePreMasterKey(h, pub, &pm, 0x303, 0xFFFF, NULL, out, sizeof out, &cb, 0);
        OBS(82, r, 0x80090029);
        pm = 0x1234; cb = 0;
        r = SslGeneratePreMasterKey(h, pub, &pm, 0x1234, 0x2f, NULL, out, sizeof out, &cb, 0);
        OBS(83, r, 0x80090029);
        if (r == 0 && pm != 0 && pm != 0x1234) SslFreeObject(pm);
        /* provider key is not usable as master key */
        {
            sa_gensess_t SslGenerateSessionKeys = (sa_gensess_t)t_proc_in("ncrypt.dll", "SslGenerateSessionKeys");
            ULONG_PTR rd = 0x1234, wr = 0x1234;
            OBS(84, SslGenerateSessionKeys(h, pub, &rd, &wr, NULL, 0), 0x80090026);
        }
        OBS(85, SslFreeObject(pub), 0);
    } else t_note("SslImportKey RSAPUBLICBLOB -> 0x%08lx", (unsigned long)r);
    OBS(86, sa_ref(h), 1);
    HeapFree(GetProcessHeap(), 0, blob);
    sa_close(h);
}

/* ---- cipher suite lookups -------------------------------------------------------------------------------------------- */
TEST(sslargs_cipher_lookup) {
    SA_NEED();
    SF(sa_lookup_info_t, SslLookupCipherSuiteInfo); SF(sa_lookup_len_t, SslLookupCipherLengths);
    SF(sa_enumcs_t, SslEnumCipherSuites); SF(sa_enumcsex_t, SslEnumCipherSuitesEx); SF(sa_freebuf_t, SslFreeBuffer);
    REQUIRE_NOTNULL(SslLookupCipherSuiteInfo); REQUIRE_NOTNULL(SslLookupCipherLengths);
    REQUIRE_NOTNULL(SslEnumCipherSuites); REQUIRE_NOTNULL(SslFreeBuffer);
    ULONG_PTR h = sa_open(); BYTE o1[0x200], o2[0x200], o3[0x200]; DWORD cs, pr; LONG r; void *a = NULL, *b = NULL;
    REQUIRE(h);
    static const DWORD css[] = { 0x2f, 0x35, 0xc02b, 0xc02f, 0x1301, 0x1302, 0x9c, 0xFFFF, 0 };
    static const DWORD prs[] = { 0x303, 0x304, 0x301, 0x300, 0 };
    /* SslLookupCipherLengths(provider, protocol, cipher suite, key type, out, cb, flags): the order was found by probing */
    for (cs = 0; cs < 9; cs++) for (pr = 0; pr < 5; pr++) {
        memset(o2, 0, sizeof o2);
        t_label("cs=%lx proto=%lx", (unsigned long)css[cs], (unsigned long)prs[pr]);
        r = SslLookupCipherLengths(h, prs[pr], css[cs], 0, o2, 0x20, 0);
        OBSV(88, r);
    }
    t_label("");
    memset(o1, 0xCC, sizeof o1);
    OBS(89, SslLookupCipherLengths(h, 0x303, 0x2f, 0, o1, 0x20, 0), 0);
    { DWORD *d = (DWORD *)o1; OBS(300, d[0], 0x14); OBS(301, d[1], 0x10); OBS(302, d[2], 0x14); OBS(303, d[3], 0x10); OBS(304, d[4], 1); OBS(305, d[5], 0xcccccccc); }
    memset(o1, 0xCC, sizeof o1);
    OBS(306, SslLookupCipherLengths(h, 0x303, 0xc02f, 0, o1, 0x20, 0), 0);
    { DWORD *d = (DWORD *)o1; OBS(307, d[0], 0x14); OBS(308, d[1], 8); OBS(309, d[2], 0x10); OBS(310, d[3], 0); OBS(311, d[4], 0); OBS(312, d[5], 0xcccccccc); }
    memset(o1, 0xCC, sizeof o1);
    OBS(313, SslLookupCipherLengths(h, 0x304, 0x1301, 0, o1, 0x20, 0), 0);
    { DWORD *d = (DWORD *)o1; OBS(314, d[0], 0x14); OBS(315, d[1], 0); OBS(316, d[2], 0x10); OBS(317, d[3], 0); OBS(318, d[4], 0); OBS(319, d[5], 0xcccccccc); }
    memset(o1, 0, sizeof o1);
    OBS(90, SslLookupCipherLengths(h, 0x2f, 0x303, 0, o1, 0x20, 0), 0x80090029);          /* arguments swapped */
    OBS(91, SslLookupCipherLengths(h, 0x303, 0x2f, 0, o1, 0x14, 0), 0);
    OBS(92, SslLookupCipherLengths(h, 0x303, 0x2f, 0, o1, 0x13, 0), 0x80090027);
    OBS(93, SslLookupCipherLengths(h, 0x303, 0x2f, 0, o1, 0, 0), 0x80090027);
    OBS(94, SslLookupCipherLengths(h, 0x303, 0x2f, 0, NULL, 0, 0), 0x80090027);
    OBS(95, SslLookupCipherLengths(h, 0x303, 0x2f, 0, o1, 0x20, 0x80000000), 0x80090009);
    OBS(96, SslLookupCipherLengths(h, 0x303, 0x2f, 1, o1, 0x20, 0), 0);
    OBS(97, SslLookupCipherLengths(h, 0, 0, 0, o1, 0x20, 0), 0x80090029);
    OBS(320, SslLookupCipherLengths(h, 0x303, 0x2f, 0, o1, 0xFFFFFFFF, 0), 0);
    /* SslLookupCipherSuiteInfo: the layout is found by probing; record the statuses of the plausible shapes */
    {
        sa_gen12_t li = (sa_gen12_t)SslLookupCipherSuiteInfo;
        OBS(350, SslLookupCipherSuiteInfo(h, 0x2f, o1, o2, o3, 0), 0x80090027);
        OBS(351, SslLookupCipherSuiteInfo(h, 0x2f, NULL, NULL, NULL, 0), 0x80090027);
        OBS(352, SslLookupCipherSuiteInfo(h, 0x2f, o1, o2, o3, 0x80000000), 0x80090009);
        OBS(353, SslLookupCipherSuiteInfo(h, 0, o1, o2, o3, 0), 0x80090027);
        OBS(354, SslLookupCipherSuiteInfo(h, 0xFFFF, o1, o2, o3, 0), 0x80090027);
        OBS(355, SslLookupCipherSuiteInfo(h, 0x2f, o1, o2, o3, 1), 0x80090009);
        memset(o1, 0xCC, sizeof o1);
        OBS(98, li(h, 0x303, 0x2f, 0, (ULONG_PTR)o1, 0x200, 0, 0, 0, 0, 0, 0), 0x80090009);
        t_note("lookup info proto,cs,0,out,cb,0 first bytes %02x %02x %02x %02x %02x %02x %02x %02x", o1[0], o1[1], o1[2], o1[3], o1[4], o1[5], o1[6], o1[7]);
        memset(o1, 0xCC, sizeof o1);
        OBS(99, li(h, 0x2f, 0x303, 0, (ULONG_PTR)o1, 0x200, 0, 0, 0, 0, 0, 0), 0x80090009);
        memset(o1, 0xCC, sizeof o1);
        OBS(100, li(h, 0x2f, 0, (ULONG_PTR)o1, 0x200, 0, 0, 0, 0, 0, 0, 0), 0x80090027);
        memset(o1, 0xCC, sizeof o1);
        OBS(101, li(h, 0x2f, 0x303, (ULONG_PTR)o1, 0x200, 0, 0, 0, 0, 0, 0, 0), 0x80090027);
        OBS(102, li(h, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0), 0x80090027);
        OBS(321, li(h, 0x303, 0x2f, 0, 0, 0, 0, 0, 0, 0, 0, 0), 0x80090027);
        OBS(322, li(h, 0x303, 0x2f, 0, (ULONG_PTR)o1, 0x200, 0x80000000, 0, 0, 0, 0, 0), 0x80090009);
        OBS(323, li(h, 0x303, 0xFFFF, 0, (ULONG_PTR)o1, 0x200, 0, 0, 0, 0, 0, 0), 0x80090009);
        OBS(324, li(h, 0x303, 0x2f, 0, (ULONG_PTR)o1, 4, 0, 0, 0, 0, 0, 0), 0x80090009);
        OBS(325, li(h, 0x304, 0x1301, 0, (ULONG_PTR)o1, 0x200, 0, 0, 0, 0, 0, 0), 0x80090009);
    }
    /* enumeration argument checks (state pointer, flags) */
    r = SslEnumCipherSuites(h, 0, &a, &b, 0x80000000);
    OBS(103, r, 0x80090009); if (r == 0) { if (a) SslFreeBuffer(a); if (b) SslFreeBuffer(b); }
    a = b = NULL;
    if (SslEnumCipherSuitesEx) {
        a = b = NULL;
        r = SslEnumCipherSuitesEx(h, 0, &a, &b, 0, 0);
        OBS(105, r, 0);
        if (r == 0) { if (a) SslFreeBuffer(a); if (b) SslFreeBuffer(b); }
        OBS(106, SslEnumCipherSuitesEx(h, 0, NULL, &b, 0, 0), 0x80090027);
        OBS(107, SslEnumCipherSuitesEx(h, 0, &a, NULL, 0, 0), 0x80090027);
        OBS(108, SslEnumCipherSuitesEx(0, 0, &a, &b, 0, 0), 0x80090026);
    }
    OBS(109, sa_ref(h), 1);
    sa_close(h);
}

/* ---- remaining Ssl* entry points: valid provider with all other arguments zero ---------------------------------------- */
TEST(sslargs_zero_args_valid_provider) {
    SA_NEED();
    static const char *names[] = {
        "SslChangeNotify", "SslComputeClientAuthHash", "SslComputeEapKeyBlock", "SslComputeFinishedHash", "SslComputeSessionHash",
        "SslCreateClientAuthHash", "SslCreateEphemeralKey", "SslCreateHandshakeHash", "SslDecryptPacket", "SslDuplicateTranscriptHash",
        "SslEncryptPacket", "SslExpandBinderKey", "SslExpandExporterMasterKey", "SslExpandPreSharedKey",
        "SslExpandResumptionMasterKey", "SslExpandTrafficKeys", "SslExpandWriteKey", "SslExportKey", "SslExportKeyingMaterial",
        "SslExtractEarlyKey", "SslExtractHandshakeKey", "SslExtractMasterKey", "SslGenerateMasterKey", "SslGeneratePreMasterKey",
        "SslGenerateSessionKeys", "SslGetKeyProperty", "SslHashHandshake", "SslImportKey", "SslImportMasterKey", "SslOpenPrivateKey",
        "SslSignHash", "SslVerifySignature"
    };
    ULONG_PTR h = sa_open(); unsigned i;
    REQUIRE(h);
    sa_forge(fakep, 0x178, SA_MAGIC_KEY, 0);
    for (i = 0; i < sizeof names / sizeof *names; i++) {
        sa_gen12_t f = (sa_gen12_t)t_proc_in("ncrypt.dll", names[i]);
        t_label("%s", names[i]);
        if (!f) { CHECKF(0, "%s not exported", names[i]); continue; }
        OBSV(110, f(h, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0));
        OBSV(111, f(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0));
        OBSV(112, f((ULONG_PTR)fakep, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0));
    }
    t_label("");
    OBS(113, sa_ref(h), 1);
    sa_close(h);
}

/* ---- provider reference counting through the bare exports ---------------------------------------------------------- */
TEST(sslargs_refcount_extra) {
    SA_NEED();
    SF(sa_incdec_t, SslIncrementProviderReferenceCount); SF(sa_incdec_t, SslDecrementProviderReferenceCount);
    SF(sa_freeobj_t, SslFreeObject);
    REQUIRE_NOTNULL(SslIncrementProviderReferenceCount); REQUIRE_NOTNULL(SslDecrementProviderReferenceCount); REQUIRE_NOTNULL(SslFreeObject);
    ULONG_PTR h = sa_open(); int i;
    REQUIRE(h);
    for (i = 0; i < 100; i++) OBS(114, SslIncrementProviderReferenceCount(h), 0);
    OBS(115, sa_ref(h), 0x65);
    for (i = 0; i < 100; i++) OBS(116, SslDecrementProviderReferenceCount(h), 0);
    OBS(117, sa_ref(h), 1);
    /* a key-object-magic header is not a provider for the refcount functions */
    sa_forge(fakep, 0x178, SA_MAGIC_KEY, 0);
    OBS(118, SslIncrementProviderReferenceCount((ULONG_PTR)fakep), 0xc0000008);
    OBS(119, fakep[4], 0);
    OBS(121, SslFreeObject(0), 0x80090026);
    sa_close(h);
}

/* ---- BCryptSetAuditingInterface, GetSChannelInterface ---------------------------------------------------------------- */
TEST(sslargs_auditing_and_schannel_interface) {
    SA_NEED();
    typedef LONG (WINAPI *p1)(void *);
    typedef LONG (WINAPI *p2)(void *, void *);
    p1 BCryptSetAuditingInterface = (p1)t_proc_in("ncrypt.dll", "BCryptSetAuditingInterface");
    p2 GetSChannelInterface = (p2)t_proc_in("ncrypt.dll", "GetSChannelInterface");
    void *itf = (void *)0x1234;
    REQUIRE_NOTNULL(BCryptSetAuditingInterface); REQUIRE_NOTNULL(GetSChannelInterface);
    /* clearing the auditing interface is the only form that is safe for later bcrypt calls */
    OBS(123, BCryptSetAuditingInterface(NULL), 0xc0000061);
    OBS(124, BCryptSetAuditingInterface(NULL), 0xc0000061);
    {   BCRYPT_ALG_HANDLE a = NULL; ULONG r = U(BCryptOpenAlgorithmProvider)(&a, BCRYPT_SHA256_ALGORITHM, NULL, 0);
        EXPECT_EQ(r, 0); if (a) U(BCryptCloseAlgorithmProvider)(a, 0); }
    OBS(125, GetSChannelInterface(NULL, NULL), 0x8007007f);
    OBS(126, GetSChannelInterface(&itf, NULL), 0x8007007f);
    OBSN(127, itf != (void *)0x1234);
    OBS(128, GetSChannelInterface(NULL, &itf), 0x8007007f);
}

/* ---- export presence of the names the SOW asks about ---------------------------------------------------------------- */
TEST(sslargs_export_table) {
    SA_NEED();
    static const char *absent[] = { "SslDuplicateKey", "SslCloseHandshakeHash", "SslFreeKey", "SslGetKeyInfo" };
    unsigned i;
    t_label("BCryptSetAuditingInterface"); EXPECT_NE(t_proc_in("ncrypt.dll", "BCryptSetAuditingInterface"), NULL);
    t_label("GetSChannelInterface"); EXPECT_NE(t_proc_in("ncrypt.dll", "GetSChannelInterface"), NULL);
    t_label("SslChangeNotify"); EXPECT_NE(t_proc_in("ncrypt.dll", "SslChangeNotify"), NULL);
    t_label("SslComputeClientAuthHash"); EXPECT_NE(t_proc_in("ncrypt.dll", "SslComputeClientAuthHash"), NULL);
    t_label("SslComputeEapKeyBlock"); EXPECT_NE(t_proc_in("ncrypt.dll", "SslComputeEapKeyBlock"), NULL);
    t_label("SslComputeFinishedHash"); EXPECT_NE(t_proc_in("ncrypt.dll", "SslComputeFinishedHash"), NULL);
    t_label("SslComputeSessionHash"); EXPECT_NE(t_proc_in("ncrypt.dll", "SslComputeSessionHash"), NULL);
    t_label("SslCreateClientAuthHash"); EXPECT_NE(t_proc_in("ncrypt.dll", "SslCreateClientAuthHash"), NULL);
    t_label("SslCreateEphemeralKey"); EXPECT_NE(t_proc_in("ncrypt.dll", "SslCreateEphemeralKey"), NULL);
    t_label("SslCreateHandshakeHash"); EXPECT_NE(t_proc_in("ncrypt.dll", "SslCreateHandshakeHash"), NULL);
    t_label("SslDecrementProviderReferenceCount"); EXPECT_NE(t_proc_in("ncrypt.dll", "SslDecrementProviderReferenceCount"), NULL);
    t_label("SslDecryptPacket"); EXPECT_NE(t_proc_in("ncrypt.dll", "SslDecryptPacket"), NULL);
    t_label("SslDuplicateTranscriptHash"); EXPECT_NE(t_proc_in("ncrypt.dll", "SslDuplicateTranscriptHash"), NULL);
    t_label("SslEncryptPacket"); EXPECT_NE(t_proc_in("ncrypt.dll", "SslEncryptPacket"), NULL);
    t_label("SslEnumCipherSuites"); EXPECT_NE(t_proc_in("ncrypt.dll", "SslEnumCipherSuites"), NULL);
    t_label("SslEnumCipherSuitesEx"); EXPECT_NE(t_proc_in("ncrypt.dll", "SslEnumCipherSuitesEx"), NULL);
    t_label("SslEnumEccCurves"); EXPECT_NE(t_proc_in("ncrypt.dll", "SslEnumEccCurves"), NULL);
    t_label("SslEnumProtocolProviders"); EXPECT_NE(t_proc_in("ncrypt.dll", "SslEnumProtocolProviders"), NULL);
    t_label("SslExpandBinderKey"); EXPECT_NE(t_proc_in("ncrypt.dll", "SslExpandBinderKey"), NULL);
    t_label("SslExpandExporterMasterKey"); EXPECT_NE(t_proc_in("ncrypt.dll", "SslExpandExporterMasterKey"), NULL);
    t_label("SslExpandPreSharedKey"); EXPECT_NE(t_proc_in("ncrypt.dll", "SslExpandPreSharedKey"), NULL);
    t_label("SslExpandResumptionMasterKey"); EXPECT_NE(t_proc_in("ncrypt.dll", "SslExpandResumptionMasterKey"), NULL);
    t_label("SslExpandTrafficKeys"); EXPECT_NE(t_proc_in("ncrypt.dll", "SslExpandTrafficKeys"), NULL);
    t_label("SslExpandWriteKey"); EXPECT_NE(t_proc_in("ncrypt.dll", "SslExpandWriteKey"), NULL);
    t_label("SslExportKey"); EXPECT_NE(t_proc_in("ncrypt.dll", "SslExportKey"), NULL);
    t_label("SslExportKeyingMaterial"); EXPECT_NE(t_proc_in("ncrypt.dll", "SslExportKeyingMaterial"), NULL);
    t_label("SslExtractEarlyKey"); EXPECT_NE(t_proc_in("ncrypt.dll", "SslExtractEarlyKey"), NULL);
    t_label("SslExtractHandshakeKey"); EXPECT_NE(t_proc_in("ncrypt.dll", "SslExtractHandshakeKey"), NULL);
    t_label("SslExtractMasterKey"); EXPECT_NE(t_proc_in("ncrypt.dll", "SslExtractMasterKey"), NULL);
    t_label("SslFreeBuffer"); EXPECT_NE(t_proc_in("ncrypt.dll", "SslFreeBuffer"), NULL);
    t_label("SslFreeObject"); EXPECT_NE(t_proc_in("ncrypt.dll", "SslFreeObject"), NULL);
    t_label("SslGenerateMasterKey"); EXPECT_NE(t_proc_in("ncrypt.dll", "SslGenerateMasterKey"), NULL);
    t_label("SslGeneratePreMasterKey"); EXPECT_NE(t_proc_in("ncrypt.dll", "SslGeneratePreMasterKey"), NULL);
    t_label("SslGenerateSessionKeys"); EXPECT_NE(t_proc_in("ncrypt.dll", "SslGenerateSessionKeys"), NULL);
    t_label("SslGetCipherSuitePRFHashAlgorithm"); EXPECT_NE(t_proc_in("ncrypt.dll", "SslGetCipherSuitePRFHashAlgorithm"), NULL);
    t_label("SslGetKeyProperty"); EXPECT_NE(t_proc_in("ncrypt.dll", "SslGetKeyProperty"), NULL);
    t_label("SslGetProviderProperty"); EXPECT_NE(t_proc_in("ncrypt.dll", "SslGetProviderProperty"), NULL);
    t_label("SslHashHandshake"); EXPECT_NE(t_proc_in("ncrypt.dll", "SslHashHandshake"), NULL);
    t_label("SslImportKey"); EXPECT_NE(t_proc_in("ncrypt.dll", "SslImportKey"), NULL);
    t_label("SslImportMasterKey"); EXPECT_NE(t_proc_in("ncrypt.dll", "SslImportMasterKey"), NULL);
    t_label("SslIncrementProviderReferenceCount"); EXPECT_NE(t_proc_in("ncrypt.dll", "SslIncrementProviderReferenceCount"), NULL);
    t_label("SslLookupCipherLengths"); EXPECT_NE(t_proc_in("ncrypt.dll", "SslLookupCipherLengths"), NULL);
    t_label("SslLookupCipherSuiteInfo"); EXPECT_NE(t_proc_in("ncrypt.dll", "SslLookupCipherSuiteInfo"), NULL);
    t_label("SslOpenPrivateKey"); EXPECT_NE(t_proc_in("ncrypt.dll", "SslOpenPrivateKey"), NULL);
    t_label("SslOpenProvider"); EXPECT_NE(t_proc_in("ncrypt.dll", "SslOpenProvider"), NULL);
    t_label("SslSignHash"); EXPECT_NE(t_proc_in("ncrypt.dll", "SslSignHash"), NULL);
    t_label("SslVerifySignature"); EXPECT_NE(t_proc_in("ncrypt.dll", "SslVerifySignature"), NULL);
    for (i = 0; i < sizeof absent / sizeof *absent; i++) { t_label("%s", absent[i]); EXPECT_EQ(t_proc_in("ncrypt.dll", absent[i]), NULL); }
}

/* ---- bogus handle values: the Ssl layer dereferences them without validation ------------------------------------------- */
TEST(sslargs_unmapped_handles_fault) {
    SA_NEED();
    SF(sa_genmaster_t, SslGenerateMasterKey); SF(sa_expkey_t, SslExportKey); SF(sa_packet_t, SslEncryptPacket);
    SF(sa_freeobj_t, SslFreeObject); SF(sa_enumcs_t, SslEnumCipherSuites);
    REQUIRE_NOTNULL(SslGenerateMasterKey); REQUIRE_NOTNULL(SslExportKey); REQUIRE_NOTNULL(SslEncryptPacket);
    REQUIRE_NOTNULL(SslFreeObject); REQUIRE_NOTNULL(SslEnumCipherSuites);
    ULONG_PTR h = sa_open(), a = 0; DWORD cb = 0; BYTE buf[64] = {0}; void *c = NULL, *d = NULL;
    REQUIRE(h);
    OBSF(129, SslGenerateMasterKey(0xFFFFFFFFFFFFFFFFull, 0, 0, &a, 0x303, 0x2f, NULL, buf, 64, &cb, 0));
    OBSF(130, SslExportKey(h, 0x1234, L"x", buf, 64, &cb, 0));
    OBSF(131, SslEncryptPacket(h, 0x1234, buf, 16, buf, 64, &cb, 0, 0x17, 0));
    OBSF(132, SslFreeObject(0x1234));
    sa_forge(fakep, 0x178, SA_MAGIC_KEY, 0);
    OBSF(133, SslFreeObject((ULONG_PTR)fakep));
    OBSF(134, SslEnumCipherSuites(h, 0x1234, &c, &d, 0));
    sa_close(h);
}

/* ---- TLS 1.2 RSA key exchange chain on local keys: premaster -> master -> session keys -> packet protection --------------- */
TEST(sslargs_kdf_chain) {
    SA_NEED();
    SF(sa_genmaster_t, SslGenerateMasterKey); SF(sa_gensess_t, SslGenerateSessionKeys); SF(sa_genpre_t, SslGeneratePreMasterKey);
    SF(sa_packet_t, SslEncryptPacket); SF(sa_packet_t, SslDecryptPacket); SF(sa_freeobj_t, SslFreeObject); SF(sa_expkey_t, SslExportKey);
    REQUIRE_NOTNULL(SslGenerateMasterKey); REQUIRE_NOTNULL(SslGenerateSessionKeys); REQUIRE_NOTNULL(SslGeneratePreMasterKey);
    REQUIRE_NOTNULL(SslEncryptPacket); REQUIRE_NOTNULL(SslDecryptPacket); REQUIRE_NOTNULL(SslFreeObject);
    ULONG_PTR h = sa_open(), pm = 0x1234, mk = 0x1234, rk = 0x1234, wk = 0x1234, rk2 = 0x1234, wk2 = 0x1234;
    NCRYPT_PROV_HANDLE kp = 0; NCRYPT_KEY_HANDLE nk = 0; NCryptBufferDesc dpre, drand; NCryptBuffer nb, rb[2];
    DWORD ver = 0x0303, cbblob = 0, cb = 0, cb2 = 0; BYTE crand[32], srand_[32], out[1024], pt[32], ct[256], back[256]; LONG r; int i;
    BYTE *blob = sa_rsa_pub_blob(1024, &cbblob);
    REQUIRE(h); REQUIRE_NOTNULL(blob);
    for (i = 0; i < 32; i++) { crand[i] = (BYTE)i; srand_[i] = (BYTE)(100 + i); pt[i] = (BYTE)(7 * i); }
    memset(&dpre, 0, sizeof dpre); nb.BufferType = 22; nb.cbBuffer = 4; nb.pvBuffer = &ver; dpre.cBuffers = 1; dpre.pBuffers = &nb;
    memset(&drand, 0, sizeof drand); rb[0].BufferType = 20; rb[0].cbBuffer = 32; rb[0].pvBuffer = crand;
    rb[1].BufferType = 21; rb[1].cbBuffer = 32; rb[1].pvBuffer = srand_; drand.cBuffers = 2; drand.pBuffers = rb;
    REQUIRE_OK(U(NCryptOpenStorageProvider)(&kp, NULL, 0) == 0);
    REQUIRE_OK(U(NCryptImportKey)(kp, 0, BCRYPT_RSAPUBLIC_BLOB, NULL, &nk, blob, cbblob, 0) == 0);
    /* premaster argument checks with the NCrypt key */
    pm = 0x1234; cb = 0; r = SslGeneratePreMasterKey(h, nk, &pm, 0x303, 0x2f, &dpre, NULL, 0, &cb, 0); OBS(401, r, 0); OBS(402, cb, 0x80);
    pm = 0x1234; cb = 0; r = SslGeneratePreMasterKey(h, nk, &pm, 0x303, 0x2f, &dpre, out, 4, &cb, 0); OBS(403, r, 0x80090028); OBS(404, cb, 0x80);
    pm = 0x1234; cb = 0; r = SslGeneratePreMasterKey(h, nk, &pm, 0x303, 0x2f, NULL, out, sizeof out, &cb, 0); OBS(405, r, 0x80090027);
    pm = 0x1234; cb = 0; r = SslGeneratePreMasterKey(h, nk, &pm, 0x301, 0x2f, &dpre, out, sizeof out, &cb, 0); OBS(406, r, 0);
    pm = 0x1234; cb = 0; r = SslGeneratePreMasterKey(h, nk, &pm, 0x303, 0xFFFF, &dpre, out, sizeof out, &cb, 0); OBS(407, r, 0x80090029);
    pm = 0x1234; cb = 0; r = SslGeneratePreMasterKey(h, nk, &pm, 0x303, 0x2f, &dpre, out, sizeof out, &cb, 1); OBS(408, r, 0);
    pm = 0x1234; cb = 0; r = SslGeneratePreMasterKey(h, nk, &pm, 0x303, 0x2f, &dpre, out, sizeof out, &cb, 0); OBS(409, r, 0); OBS(410, cb, 0x80);
    OBSN(411, sa_ref(h));
    if (r == 0) {
        /* master key from the premaster handle: both argument positions */
        static const int pos[2] = { 0, 1 };
        for (i = 0; i < 2; i++) {
            mk = 0x1234; cb = 0; t_label("premaster in slot %d", pos[i]);
            r = SslGenerateMasterKey(h, pos[i] == 0 ? pm : 0, pos[i] == 1 ? pm : 0, &mk, 0x303, 0x2f, &drand, out, sizeof out, &cb, 0);
            OBS(412, r, 0x80090009); OBS(413, cb, 0);
            if (r == 0 && mk != 0x1234) { SslFreeObject(mk); mk = 0x1234; }
        }
        t_label("");
        /* which flag values does the master key generation accept? */
        {   DWORD fl; int ss; unsigned found = 0;
            for (ss = 0; ss < 2; ss++) for (fl = 1; fl <= 0x8000 && !found; fl <<= 1) {
                mk = 0x1234; cb = 0; t_label("slot %d flags 0x%lx", ss, (unsigned long)fl);
                r = SslGenerateMasterKey(h, ss == 0 ? pm : 0, ss == 1 ? pm : 0, &mk, 0x303, 0x2f, &drand, out, sizeof out, &cb, fl);
                OBS(480, r, 0);
                if (r == 0 && mk != 0x1234) { SslFreeObject(mk); mk = 0x1234; found = fl; }
            }
            t_label("");
            t_note("master key generation first accepted flag: 0x%lx", (unsigned long)found);
            for (ss = 0; ss < 2; ss++) {                      /* pm in the output-key slot for completeness, with and without randoms */
                mk = 0x1234; cb = 0;
                r = SslGenerateMasterKey(h, ss == 0 ? pm : 0, ss == 1 ? pm : 0, &mk, 0x303, 0x2f, NULL, out, sizeof out, &cb, 0);
                OBS(490, r, 0x80090027);
            }
        }
        mk = 0x1234; cb = 0; r = SslGenerateMasterKey(h, pm, 0, &mk, 0x303, 0x2f, &drand, NULL, 0, &cb, 1); OBS(502, r, 0); OBS(503, cb, 0);
        if (r == 0 && mk != 0x1234) SslFreeObject(mk);
        mk = 0x1234; cb = 0; r = SslGenerateMasterKey(h, pm, 0, &mk, 0x303, 0x2f, NULL, NULL, 0, NULL, 1); OBS(504, r, 0x80090027);
        mk = 0x1234; cb = 0; r = SslGenerateMasterKey(h, pm, 0, NULL, 0x303, 0x2f, &drand, NULL, 0, NULL, 1); OBS(505, r, 0x80090027);
        mk = 0x1234; cb = 0; r = SslGenerateMasterKey(h, pm, 0, &mk, 0x303, 0xFFFF, &drand, NULL, 0, NULL, 1); OBS(506, r, 0x80090029);
        mk = 0x1234; cb = 0; r = SslGenerateMasterKey(h, pm, 0, &mk, 0x300, 0x2f, &drand, NULL, 0, NULL, 1); OBS(507, r, 0x80090029);
        mk = 0x1234; cb = 0; r = SslGenerateMasterKey(h, pm, 0, &mk, 0x303, 0x2f, &drand, NULL, 0, NULL, 3); OBS(508, r, 0);
        mk = 0x1234; cb = 0; r = SslGenerateMasterKey(h, 0, 0, &mk, 0x303, 0x2f, &drand, NULL, 0, NULL, 1); OBS(509, r, 0x80090027);
        /* the session key flow with the master key from the first position that worked */
        mk = 0x1234; cb = 0;
        r = SslGenerateMasterKey(h, pm, 0, &mk, 0x303, 0x2f, &drand, out, sizeof out, &cb, 1);
        OBS(500, r, 0); OBS(501, cb, 0);
        if (r == 0 && mk != 0x1234) {
            OBS(414, ((DWORD *)mk)[1], 0x44444442);
            rk = wk = rk2 = wk2 = 0x1234;
            r = SslGenerateSessionKeys(h, mk, &rk, &wk, &drand, 0); OBS(601, r, 0);
            OBS(602, SslGenerateSessionKeys(h, mk, &rk2, &wk2, NULL, 0), 0x80090027);
            OBS(603, SslGenerateSessionKeys(h, mk, &rk2, &wk2, &dpre, 0), 0x80090027);
            {   DWORD fl; ULONG_PTR a1, a2;
                for (fl = 1; fl <= 0x8000; fl <<= 1) {
                    a1 = a2 = 0x1234; t_label("session flags 0x%lx", (unsigned long)fl);
                    r = SslGenerateSessionKeys(h, mk, &a1, &a2, &drand, fl); OBS(604, r, 0x80090009);
                    if (r == 0) { if (rk2 == 0x1234) { rk2 = a1; wk2 = a2; t_note("second key pair from flags 0x%lx", (unsigned long)fl); } else { SslFreeObject(a1); SslFreeObject(a2); } }
                }
                t_label("");
            }
            if (rk != 0x1234 && wk != 0x1234) {
                OBS(605, ((DWORD *)wk)[1], 0x44444442);
                cb = 0; r = SslEncryptPacket(h, wk, pt, 16, NULL, 0, &cb, 0, 0x17, 0); OBS(606, r, 0x80090027); OBS(607, cb, 0);
                cb = 0; memset(ct, 0, sizeof ct);
                r = SslEncryptPacket(h, wk, pt, 16, ct, sizeof ct, &cb, 0, 0x17, 0); OBS(608, r, 0); OBS(609, cb, 0x45);
                {   DWORD fl;
                    for (fl = 0; fl <= 0x80; fl = fl ? fl << 1 : 1) {
                        cb2 = 0; t_label("decrypt flags 0x%lx", (unsigned long)fl);
                        r = SslDecryptPacket(h, rk, ct, cb, back, sizeof back, &cb2, 0, 0x17, fl); OBS(610, r, 0x80090009); OBS(611, cb2, 0);
                        if (rk2 != 0x1234) { cb2 = 0; r = SslDecryptPacket(h, rk2, ct, cb, back, sizeof back, &cb2, 0, 0x17, fl); OBSN(612, r); OBSN(613, cb2); }
                    }
                    t_label("");
                }
                cb2 = 0; r = SslEncryptPacket(h, wk, pt, 16, ct, 4, &cb2, 0, 0x17, 0); OBS(614, r, 0x80090028); OBS(615, cb2, 0);
                cb2 = 0; r = SslEncryptPacket(h, wk, pt, 0, ct, sizeof ct, &cb2, 0, 0x17, 0); OBS(616, r, 0); OBS(617, cb2, 0x35);
                cb2 = 0; r = SslEncryptPacket(h, wk, NULL, 16, ct, sizeof ct, &cb2, 0, 0x17, 0); OBS(618, r, 0x80090027);
                cb2 = 0; r = SslEncryptPacket(h, wk, pt, 16, ct, sizeof ct, &cb2, 0, 0, 0); OBS(619, r, 0);
                cb2 = 0; r = SslEncryptPacket(h, wk, pt, 16, ct, sizeof ct, &cb2, 0, 0xFF, 0); OBS(620, r, 0);
                cb2 = 0; r = SslEncryptPacket(h, wk, pt, 16, ct, sizeof ct, &cb2, 0, 0x17, 0xFFFF); OBS(621, r, 0x80090009);
                cb2 = 0; r = SslEncryptPacket(h, wk, pt, 16, ct, sizeof ct, &cb2, 0xFFFFFFFFFFFFFFFFull, 0x17, 0); OBS(622, r, 0);
                cb2 = 0; r = SslEncryptPacket(h, wk, pt, 20000, ct, sizeof ct, &cb2, 0, 0x17, 0); OBS(623, r, 0x80090027);
                SslFreeObject(rk); SslFreeObject(wk);
            }
            if (rk2 != 0x1234) SslFreeObject(rk2);
            if (wk2 != 0x1234) SslFreeObject(wk2);
            SslFreeObject(mk);
        }
        SslFreeObject(pm);
    }
    OBSN(443, sa_ref(h));
    U(NCryptFreeObject)(nk); U(NCryptFreeObject)(kp);
    HeapFree(GetProcessHeap(), 0, blob);
    sa_close(h);
}
