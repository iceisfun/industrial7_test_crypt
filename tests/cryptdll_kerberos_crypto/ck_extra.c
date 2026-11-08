/* Cross-checks against bcrypt.dll (the primitives cryptdll is built on), concurrency, large and unaligned buffers,
 * and odd registration ids. */
#include "ck.h"
#include <bcrypt.h>
#include "bcrypt_handles.h"

static BCRYPT_ALG_HANDLE bc_open(LPCWSTR alg, ULONG flags) {
    BCRYPT_ALG_HANDLE h = NULL;
    if (!U(BCryptOpenAlgorithmProvider) || U(BCryptOpenAlgorithmProvider)(&h, alg, NULL, flags) != 0) return NULL;
    return h;
}
static void bc_close(BCRYPT_ALG_HANDLE h) { if (h && U(BCryptCloseAlgorithmProvider)) U(BCryptCloseAlgorithmProvider)(h, 0); }

TEST(ckx_md5_matches_bcrypt) {
    REQUIRE(U(BCryptHash)); CK_NEED(CDLocateCheckSum);
    if (!CKP(MD5Init)) { t_skip("no MD5"); return; }
    BCRYPT_ALG_HANDLE a = bc_open(BCRYPT_MD5_ALGORITHM, 0);
    CHECK(a != NULL);
    if (!a) return;
    static BYTE msg[1500]; for (int i = 0; i < 1500; i++) msg[i] = (BYTE)(i * 13 + 7);
    for (ULONG n = 0; n <= 300; n += 7) {
        BYTE ref[16], mine[16];
        EXPECT_NS(U(BCryptHash)(a, NULL, 0, msg, n, ref, 16), 0);
        ck_md5(msg, n, mine);
        CHECKF(!memcmp(ref, mine, 16), "MD5 len %lu", (unsigned long)n);
        size_t ol;
        EXPECT_NS(ck_run_checksum(CS_MD5, 0, NULL, 0, 0, msg, n, mine, &ol), 0);
        CHECKF(!memcmp(ref, mine, 16), "checksum MD5 len %lu", (unsigned long)n);
    }
    bc_close(a);
}

TEST(ckx_md4_checksum_matches_bcrypt) {
    REQUIRE(U(BCryptHash)); CK_NEED(CDLocateCheckSum);
    BCRYPT_ALG_HANDLE a = bc_open(BCRYPT_MD4_ALGORITHM, 0);
    if (!a) { t_note("bcrypt MD4 provider unavailable"); return; }
    static BYTE msg[600]; for (int i = 0; i < 600; i++) msg[i] = (BYTE)(i * 3 + 1);
    for (ULONG n = 0; n <= 200; n += 9) {
        BYTE ref[16], mine[16]; size_t ol;
        EXPECT_NS(U(BCryptHash)(a, NULL, 0, msg, n, ref, 16), 0);
        EXPECT_NS(ck_run_checksum(CS_MD4, 0, NULL, 0, 0, msg, n, mine, &ol), 0);
        CHECKF(!memcmp(ref, mine, 16), "MD4 len %lu", (unsigned long)n);
    }
    bc_close(a);
}

TEST(ckx_sha1_checksum_matches_bcrypt) {
    REQUIRE(U(BCryptHash)); CK_NEED(CDLocateCheckSum);
    BCRYPT_ALG_HANDLE a = bc_open(BCRYPT_SHA1_ALGORITHM, 0);
    CHECK(a != NULL);
    if (!a) return;
    static BYTE msg[600]; for (int i = 0; i < 600; i++) msg[i] = (BYTE)(i * 5 + 2);
    for (ULONG n = 0; n <= 300; n += 11) {
        BYTE ref[20], mine[20]; size_t ol;
        EXPECT_NS(U(BCryptHash)(a, NULL, 0, msg, n, ref, 20), 0);
        EXPECT_NS(ck_run_checksum(CS_SHA1, 0, NULL, 0, 0, msg, n, mine, &ol), 0);
        CHECKF(!memcmp(ref, mine, 20), "SHA1 len %lu", (unsigned long)n);
    }
    bc_close(a);
}

TEST(ckx_hmacsha_matches_bcrypt_hmac) {
    REQUIRE(U(BCryptHash)); CK_NEED(HMACwithSHA);
    BCRYPT_ALG_HANDLE a = bc_open(BCRYPT_SHA1_ALGORITHM, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    CHECK(a != NULL);
    if (!a) return;
    static BYTE msg[400]; BYTE key[100];
    for (int i = 0; i < 400; i++) msg[i] = (BYTE)(i * 7);
    for (int i = 0; i < 100; i++) key[i] = (BYTE)(i * 11 + 3);
    static const ULONG kl[] = { 1, 8, 20, 63, 64, 65, 100 };
    for (size_t k = 0; k < sizeof kl / sizeof kl[0]; k++) for (ULONG n = 0; n <= 130; n += 13) {
        BYTE ref[20], mine[20];
        EXPECT_NS(U(BCryptHash)(a, key, kl[k], msg, n, ref, 20), 0);
        EXPECT_NS(CKP(HMACwithSHA)(key, kl[k], msg, n, mine, 20), 0);
        CHECKF(!memcmp(ref, mine, 20), "key %lu data %lu", (unsigned long)kl[k], (unsigned long)n);
    }
    bc_close(a);
}

TEST(ckx_pbkdf2_matches_bcrypt) {
    REQUIRE(U(BCryptDeriveKeyPBKDF2)); CK_NEED(PBKDF2);
    BCRYPT_ALG_HANDLE a = bc_open(BCRYPT_SHA1_ALGORITHM, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    CHECK(a != NULL);
    if (!a) return;
    static const struct { ULONG pl, sl, it, dk; } c[] = { {4, 4, 1, 16}, {8, 20, 100, 20}, {70, 9, 33, 45}, {1, 1, 7, 64}, {20, 64, 2, 21} };
    BYTE pw[80], sa[80]; for (int i = 0; i < 80; i++) { pw[i] = (BYTE)(i + 1); sa[i] = (BYTE)(255 - i); }
    for (size_t i = 0; i < sizeof c / sizeof c[0]; i++) {
        BYTE ref[64], mine[64];
        EXPECT_NS(U(BCryptDeriveKeyPBKDF2)(a, pw, c[i].pl, sa, c[i].sl, c[i].it, ref, c[i].dk, 0), 0);
        EXPECT_NS(CKP(PBKDF2)(pw, c[i].pl, sa, c[i].sl, c[i].it, c[i].dk, mine), 0);
        CHECKF(!memcmp(ref, mine, c[i].dk), "case %zu", i);
    }
    bc_close(a);
}

TEST(ckx_aes_cts_single_block_matches_bcrypt_cbc) {
    REQUIRE(U(BCryptGenerateSymmetricKey)); CK_NEED(aesCTSEncryptMsg);
    BCRYPT_ALG_HANDLE a = bc_open(BCRYPT_AES_ALGORITHM, 0);
    CHECK(a != NULL);
    if (!a) return;
    static const ULONG kls[] = { 16, 24, 32 };
    BYTE key[32]; for (int i = 0; i < 32; i++) key[i] = (BYTE)(i * 9 + 4);
    for (size_t k = 0; k < 3; k++) {
        BCRYPT_KEY_HANDLE h = NULL;
        EXPECT_NS(U(BCryptGenerateSymmetricKey)(a, &h, NULL, 0, key, kls[k], 0), 0);
        if (!h) continue;
        EXPECT_NS(U(BCryptSetProperty)(h, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0), 0);
        BYTE pt[16], ref[16], mine[16], iv[16] = {0}; ULONG got = 0;
        for (int i = 0; i < 16; i++) pt[i] = (BYTE)(i + k);
        EXPECT_NS(U(BCryptEncrypt)(h, pt, 16, NULL, iv, 16, ref, 16, &got, 0), 0);
        memcpy(mine, pt, 16); memset(iv, 0, 16);
        EXPECT_NS(CKP(aesCTSEncryptMsg)(kls[k], key, 16, mine, iv), 0);
        CHECKF(!memcmp(ref, mine, 16), "key %lu", (unsigned long)kls[k]);
        U(BCryptDestroyKey)(h);
    }
    bc_close(a);
}

TEST(ckx_aes_cts_two_blocks_equals_cbc_with_swapped_blocks) {
    REQUIRE(U(BCryptGenerateSymmetricKey)); CK_NEED(aesCTSEncryptMsg);
    BCRYPT_ALG_HANDLE a = bc_open(BCRYPT_AES_ALGORITHM, 0);
    CHECK(a != NULL);
    if (!a) return;
    BYTE key[16]; for (int i = 0; i < 16; i++) key[i] = (BYTE)(i * 3);
    BCRYPT_KEY_HANDLE h = NULL;
    EXPECT_NS(U(BCryptGenerateSymmetricKey)(a, &h, NULL, 0, key, 16, 0), 0);
    if (h) {
        U(BCryptSetProperty)(h, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
        BYTE pt[32], cbc[32], iv[16] = {0}; ULONG got;
        for (int i = 0; i < 32; i++) pt[i] = (BYTE)(i * 5 + 1);
        EXPECT_NS(U(BCryptEncrypt)(h, pt, 32, NULL, iv, 16, cbc, 32, &got, 0), 0);
        BYTE mine[32], iv2[16] = {0};
        memcpy(mine, pt, 32);
        EXPECT_NS(CKP(aesCTSEncryptMsg)(16, key, 32, mine, iv2), 0);
        CHECK(!memcmp(mine, cbc + 16, 16) && !memcmp(mine + 16, cbc, 16));
        U(BCryptDestroyKey)(h);
    }
    bc_close(a);
}

/* ---- large and unaligned buffers -------------------------------------------------------------------------- */
TEST(ckx_large_message_aes_cts_roundtrip_one_megabyte) {
    CK_NEED(aesCTSEncryptMsg); CK_NEED(aesCTSDecryptMsg);
    ULONG n = (1u << 20) + 5;
    BYTE *orig = (BYTE *)malloc(n), *buf = (BYTE *)malloc(n);
    CHECK(orig && buf);
    if (orig && buf) {
        for (ULONG i = 0; i < n; i++) orig[i] = (BYTE)(i * 31 + (i >> 8));
        memcpy(buf, orig, n);
        BYTE key[32] = {5}, iv[16] = {0};
        EXPECT_NS(CKP(aesCTSEncryptMsg)(32, key, n, buf, iv), 0);
        CHECK(memcmp(buf, orig, n) != 0);
        memset(iv, 0, 16);
        EXPECT_NS(CKP(aesCTSDecryptMsg)(32, key, n, buf, iv), 0);
        CHECK(!memcmp(buf, orig, n));
    }
    free(orig); free(buf);
}

TEST(ckx_large_message_hmacsha_and_md5) {
    CK_NEED(HMACwithSHA);
    ULONG n = 3u << 20;
    BYTE *buf = (BYTE *)malloc(n);
    CHECK(buf != NULL);
    if (!buf) return;
    memset(buf, 'a', n);
    BYTE h1[20], h2[20];
    EXPECT_NS(CKP(HMACwithSHA)((PUCHAR)"k", 1, buf, n, h1, 20), 0);
    EXPECT_NS(CKP(HMACwithSHA)((PUCHAR)"k", 1, buf, n, h2, 20), 0);
    CHECK(!memcmp(h1, h2, 20));
    if (CKP(MD5Init)) {
        CK_MD5_CTX c; CKP(MD5Init)(&c); CKP(MD5Update)(&c, buf, n); CKP(MD5Final)(&c);
        CK_MD5_CTX d; CKP(MD5Init)(&d);
        for (ULONG o = 0; o < n; o += 65536) CKP(MD5Update)(&d, buf + o, 65536);
        CKP(MD5Final)(&d);
        CHECK(!memcmp(c.digest, d.digest, 16));
    }
    free(buf);
}

TEST(ckx_unaligned_buffers_everywhere) {
    CK_NEED(HMACwithSHA); CK_NEED(PBKDF2); CK_NEED(aesCTSEncryptMsg); CK_NEED(aesCTSDecryptMsg);
    BYTE raw[600]; BYTE ref_h[20], ref_p[20];
    BYTE base[64]; for (int i = 0; i < 64; i++) base[i] = (BYTE)(i * 3 + 1);
    EXPECT_NS(CKP(HMACwithSHA)(base, 33, base + 3, 29, ref_h, 20), 0);
    EXPECT_NS(CKP(PBKDF2)(base, 20, base + 20, 25, 3, 20, ref_p), 0);
    BYTE key[16]; for (int i = 0; i < 16; i++) key[i] = (BYTE)(i + 77);
    BYTE msg[50]; for (int i = 0; i < 50; i++) msg[i] = (BYTE)(255 - i);
    BYTE ref_c[50]; memcpy(ref_c, msg, 50); BYTE ivz[16] = {0};
    EXPECT_NS(CKP(aesCTSEncryptMsg)(16, key, 50, ref_c, ivz), 0);
    for (int off = 1; off < 8; off++) {
        BYTE *p = raw + off, h[20], q[20];
        memcpy(p, base, 64);
        EXPECT_NS(CKP(HMACwithSHA)(p, 33, p + 3, 29, h, 20), 0);
        CHECKF(!memcmp(h, ref_h, 20), "hmac offset %d", off);
        EXPECT_NS(CKP(PBKDF2)(p, 20, p + 20, 25, 3, 20, q), 0);
        CHECKF(!memcmp(q, ref_p, 20), "pbkdf2 offset %d", off);
        BYTE *k = raw + 100 + off, *d = raw + 200 + off, *iv = raw + 300 + off;
        memcpy(k, key, 16); memcpy(d, msg, 50); memset(iv, 0, 16);
        EXPECT_NS(CKP(aesCTSEncryptMsg)(16, k, 50, d, iv), 0);
        CHECKF(!memcmp(d, ref_c, 50), "cts offset %d", off);
        memset(iv, 0, 16);
        EXPECT_NS(CKP(aesCTSDecryptMsg)(16, k, 50, d, iv), 0);
        CHECKF(!memcmp(d, msg, 50), "cts decrypt offset %d", off);
    }
}

/* ---- concurrency: first use of the CNG-backed routines from many threads at once --------------------------- */
static volatile LONG g_bad;
static DWORD WINAPI worker(LPVOID p) {
    BYTE key[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    for (int i = 0; i < 60; i++) {
        BYTE h[20], pt[40], buf[40], iv[16] = {0};
        if (CKP(HMACwithSHA)((PUCHAR)"Jefe", 4, (PUCHAR)"what do ya want for nothing?", 28, h, 20) != 0 || !ck_eqhex(h, 20, "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79")) InterlockedIncrement(&g_bad);
        for (int j = 0; j < 40; j++) pt[j] = (BYTE)(j + i);
        memcpy(buf, pt, 40);
        if (CKP(aesCTSEncryptMsg)(16, key, 40, buf, iv) != 0) InterlockedIncrement(&g_bad);
        memset(iv, 0, 16);
        if (CKP(aesCTSDecryptMsg)(16, key, 40, buf, iv) != 0 || memcmp(buf, pt, 40)) InterlockedIncrement(&g_bad);
        BYTE dk[20];
        if (CKP(PBKDF2)((PUCHAR)"password", 8, (PUCHAR)"salt", 4, 2, 20, dk) != 0 || !ck_eqhex(dk, 20, "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957")) InterlockedIncrement(&g_bad);
        BYTE ct[96], out[96]; ULONG cl = 96, ol;
        if (ck_cs_encrypt(ET_AES128, key, 16, 3, pt, 40, ct, &cl) != 0) { InterlockedIncrement(&g_bad); continue; }
        ol = cl;
        if (ck_cs_decrypt(ET_AES128, key, 16, 3, ct, cl, out, &ol) != 0 || ol != 40 || memcmp(out, pt, 40)) InterlockedIncrement(&g_bad);
        cl = 96;
        if (ck_cs_encrypt(ET_RC4_HMAC, key, 16, 3, pt, 40, ct, &cl) != 0) { InterlockedIncrement(&g_bad); continue; }
        ol = cl;
        if (ck_cs_decrypt(ET_RC4_HMAC, key, 16, 3, ct, cl, out, &ol) != 0 || ol != 40 || memcmp(out, pt, 40)) InterlockedIncrement(&g_bad);
    }
    return 0;
}
CHILD(ck_threads_first_use) {
    CC(CKP(HMACwithSHA) && CKP(aesCTSEncryptMsg) && CKP(PBKDF2) && CKP(CDLocateCSystem));
    HANDLE th[8];
    for (int i = 0; i < 8; i++) { th[i] = CreateThread(NULL, 0, worker, NULL, 0, NULL); CC(th[i] != NULL); }
    DWORD w = WaitForMultipleObjects(8, th, TRUE, 25000);
    for (int i = 0; i < 8; i++) CloseHandle(th[i]);
    CC(w == WAIT_OBJECT_0);
    CC(g_bad == 0);
    return 0;
}
TEST(ckx_concurrent_first_use_of_cng_backed_routines) {
    CK_NEED(HMACwithSHA);
    DWORD ec = t_run_child("ck_threads_first_use", "", 40000);
    t_check(ec == 0, __FILE__, __LINE__, "child exit 0", "exit code %lu", (unsigned long)ec);
}

TEST(ckx_repeated_state_lifecycle_is_stable) {
    CK_NEED(CDLocateCSystem);
    static const struct { LONG et; ULONG kl; } c[] = { {ET_AES128, 16}, {ET_AES256, 32}, {ET_RC4_HMAC, 16}, {ET_RC4_MD4, 16}, {ET_DES_MD5, 8}, {ET_DES_CRC, 8}, {ET_RC4_HMAC_OLD, 16} };
    BYTE key[32]; for (int i = 0; i < 32; i++) key[i] = (BYTE)(i + 1);
    for (size_t t = 0; t < sizeof c / sizeof c[0]; t++) {
        const CSX *cs = ck_cs(c[t].et);
        CHECK(cs != NULL);
        if (!cs) continue;
        for (int i = 0; i < 400; i++) {
            PVOID st = NULL;
            NTSTATUS r = ((csx_init_fn)cs->Initialize)(key, c[t].kl, (ULONG)i, &st);
            if (r) { CHECKF(0, "etype %ld iteration %d init 0x%08lx", (long)c[t].et, i, (unsigned long)r); break; }
            ((csx_fin_fn)cs->Finish)(&st);
            if (st) { CHECKF(0, "etype %ld iteration %d state not cleared", (long)c[t].et, i); break; }
        }
    }
    for (int i = 0; i < 400; i++) {
        PVOID ctx = NULL; const CKX *ck = ck_ck(CS_SHA1);
        if (!ck) break;
        NTSTATUS r = ((ckx_init_fn)ck->Initialize)(0, &ctx);
        if (r) { CHECKF(0, "sha1 init %d", i); break; }
        ((ckx_finish_fn)ck->Finish)(&ctx);
    }
}

/* ---- odd registration ids (child) --------------------------------------------------------------------------- */
CHILD(ck_reg_odd_ids) {
    CC(CKP(CDRegisterCSystem) && CKP(CDLocateCSystem) && CKP(CDBuildVect) && CKP(CDRegisterCheckSum) && CKP(CDLocateCheckSum));
    CSX z; memset(&z, 0, sizeof z);
    CC(CKP(CDRegisterCSystem)(&z) == 0);                       /* an all-zero entry is accepted verbatim */
    CSX *p; CC(CKP(CDLocateCSystem)(0, &p) == 0 && p->EncryptionType == 0 && p->KeySize == 0);
    CSX n; memset(&n, 0, sizeof n); n.EncryptionType = (ULONG)-5000; n.KeySize = 9;
    CC(CKP(CDRegisterCSystem)(&n) == 0);
    CC(CKP(CDLocateCSystem)(-5000, &p) == 0 && p->KeySize == 9);
    CSX m; memset(&m, 0, sizeof m); m.EncryptionType = 0x7fffffff; m.KeySize = 3;
    CC(CKP(CDRegisterCSystem)(&m) == 0);
    CC(CKP(CDLocateCSystem)(0x7fffffff, &p) == 0 && p->KeySize == 3);
    ULONG cnt = 0; LONG v[40];
    CC(CKP(CDBuildVect)(&cnt, v) == 0 && cnt == 19 && v[16] == 0 && v[17] == -5000 && v[18] == 0x7fffffff);
    CKX ck; memset(&ck, 0, sizeof ck);
    CC(CKP(CDRegisterCheckSum)(&ck) == 0);
    CKX *q; CC(CKP(CDLocateCheckSum)(0, &q) == 0 && q->Size == 0);
    return 0;
}
TEST(ckx_register_zero_negative_and_extreme_ids) { CK_NEED(CDRegisterCSystem); DWORD ec = t_run_child("ck_reg_odd_ids", "", 30000); t_check(ec == 0, __FILE__, __LINE__, "child exit 0", "exit code %lu (source line)", (unsigned long)ec); }

CHILD(ck_reg_isolation_child) {
    CC(CKP(CDRegisterCSystem));
    CSX m; memset(&m, 0, sizeof m); m.EncryptionType = 0x7e57;
    return CKP(CDRegisterCSystem)(&m) == 0 ? 0 : 1;
}
TEST(ckx_registration_is_process_local) {
    CK_NEED(CDRegisterCSystem);
    ULONG before = 0, after = 0;
    EXPECT_NS(CKP(CDBuildVect)(&before, NULL), 0);
    DWORD ec = t_run_child("ck_reg_isolation_child", "", 30000);
    EXPECT_EQ(ec, 0);
    EXPECT_NS(CKP(CDBuildVect)(&after, NULL), 0);
    EXPECT_EQ(before, after);
    CSX *p;
    EXPECT_NS(CKP(CDLocateCSystem)(0x7e57, &p), NS_NO_CSYSTEM);
}
