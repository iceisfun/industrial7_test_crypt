/* Self-tests of the embedded fixtures (keys, certificates, PE image, Authenticode hash helper).
 * These only use crypt32 / rsaenh / wintrust and validate the material every other test relies on. */
#include "mssfix.h"

TEST(mssigner_fixture_certs_parse) {
    for (int w = 0; w < 2; w++) {
        DWORD cb; const BYTE *der = fx_cert_der(w, &cb);
        PCCERT_CONTEXT c = U(CertCreateCertificateContext)(X509_ASN_ENCODING, der, cb);
        REQUIRE(U(CertCreateCertificateContext));
        CHECKF(c != NULL, "cert %d", w);
        if (!c) continue;
        CHECK(U(CertCompareCertificateName)(X509_ASN_ENCODING, &c->pCertInfo->Issuer, &c->pCertInfo->Subject));
        CHECK(U(CertVerifyTimeValidity)(NULL, c->pCertInfo) == 0);
        char name[128] = "";
        U(CertGetNameStringA)(c, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, name, sizeof name);
        EXPECT_STR(name, w == 0 ? "cryptt mssign32 test A" : "cryptt mssign32 test B");
        U(CertFreeCertificateContext)(c);
    }
}
TEST(mssigner_fixture_keys_distinct) {
    REQUIRE(U(CertCreateCertificateContext));
    DWORD ca, cb; const BYTE *a = fx_cert_der(FX_A, &ca), *b = fx_cert_der(FX_B, &cb);
    PCCERT_CONTEXT x = U(CertCreateCertificateContext)(X509_ASN_ENCODING, a, ca);
    PCCERT_CONTEXT y = U(CertCreateCertificateContext)(X509_ASN_ENCODING, b, cb);
    CHECK(x && y);
    if (x && y) {
        CHECK(!U(CertComparePublicKeyInfo)(X509_ASN_ENCODING, &x->pCertInfo->SubjectPublicKeyInfo, &y->pCertInfo->SubjectPublicKeyInfo));
        CHECK(U(CertComparePublicKeyInfo)(X509_ASN_ENCODING, &x->pCertInfo->SubjectPublicKeyInfo, &x->pCertInfo->SubjectPublicKeyInfo));
    }
    if (x) U(CertFreeCertificateContext)(x);
    if (y) U(CertFreeCertificateContext)(y);
}
TEST(mssigner_fixture_key_matches_cert_and_kat) {
    REQUIRE(U(CryptAcquireContextW));
    for (int spec = 1; spec <= 2; spec++) {
        FX f;
        if (!fx_open(&f, FX_A, spec)) { t_skip("cannot open key context"); return; }
        CHECK(fx_cert_attach(&f));
        PCCERT_CONTEXT c = f.cert;
        DWORD cb = 0;
        CHECK(U(CryptExportPublicKeyInfo)(f.hProv, spec, X509_ASN_ENCODING, NULL, &cb));
        CERT_PUBLIC_KEY_INFO *pk = malloc(cb);
        CHECK(U(CryptExportPublicKeyInfo)(f.hProv, spec, X509_ASN_ENCODING, pk, &cb));
        if (c) CHECK(U(CertComparePublicKeyInfo)(X509_ASN_ENCODING, pk, &c->pCertInfo->SubjectPublicKeyInfo));
        free(pk);
        /* RSA PKCS#1 v1.5 signatures are deterministic: compare with the signature produced at authoring time */
        HCRYPTHASH h = 0; BYTE sig[512]; DWORD sl = sizeof sig, kl;
        const BYTE *kat = fx_sig_sha1_abc(&kl);
        CHECK(U(CryptCreateHash)(f.hProv, CALG_SHA1, 0, 0, &h));
        CHECK(U(CryptHashData)(h, (const BYTE *)"abc", 3, 0));
        CHECK(U(CryptSignHashW)(h, spec, NULL, 0, sig, &sl));
        EXPECT_EQ(sl, kl);
        CHECK(sl == kl && !memcmp(sig, kat, kl));
        U(CryptDestroyHash)(h);
        fx_close(&f);
    }
}
TEST(mssigner_fixture_pvk_layout) {
    BYTE pvk[2300];
    DWORD n = fx_pvk(FX_A, 1, 0, 0, pvk, sizeof pvk);
    EXPECT_EQ(n, 24 + 1172);
    DWORD h[6]; memcpy(h, pvk, 24);
    EXPECT_EQ(h[0], 0xB0B5F11E); EXPECT_EQ(h[1], 0); EXPECT_EQ(h[2], 1); EXPECT_EQ(h[3], 0); EXPECT_EQ(h[4], 0); EXPECT_EQ(h[5], 1172);
    EXPECT_EQ(pvk[24], 7); EXPECT_EQ(pvk[25], 2);
    DWORD alg; memcpy(&alg, pvk + 28, 4); EXPECT_EQ(alg, 0xA400);
    n = fx_pvk(FX_A, 2, 0, 0, pvk, sizeof pvk);
    memcpy(&alg, pvk + 28, 4); EXPECT_EQ(alg, 0x2400);
    n = fx_pvk(FX_B, 1, 0, 16, pvk, sizeof pvk);
    EXPECT_EQ(n, 24 + 16 + 20 + 128 + 5 * 64 + 128);
}
TEST(mssigner_fixture_pe_image_wellformed) {
    BYTE b[FX_PE_SIZE]; fx_pe_image(b);
    IMAGE_DOS_HEADER *d = (IMAGE_DOS_HEADER *)b;
    EXPECT_EQ(d->e_magic, 0x5A4D);
    IMAGE_NT_HEADERS64 *nt = (IMAGE_NT_HEADERS64 *)(b + d->e_lfanew);
    EXPECT_EQ(nt->Signature, 0x4550);
    EXPECT_EQ(nt->OptionalHeader.Magic, 0x20B);
    EXPECT_EQ(nt->OptionalHeader.SizeOfHeaders, 0x200);
    DWORD off, size;
    CHECK(fx_pe_secdir(b, sizeof b, &off, &size));
    EXPECT_EQ(off, 0); EXPECT_EQ(size, 0);
    IMAGE_SECTION_HEADER *s = IMAGE_FIRST_SECTION(nt);
    CHECK(s->PointerToRawData + s->SizeOfRawData == FX_PE_SIZE);
}
TEST(mssigner_fixture_pe_unsigned_has_no_signature) {
    char path[MAX_PATH]; fx_pe_new(path, sizeof path, "unsigned.exe");
    REQUIRE(UIN("wintrust.dll", WinVerifyTrust));
    HRESULT hr = fx_verify_trust(path);
    EXPECT_EQ(hr, (HRESULT)0x800B0100);   /* TRUST_E_NOSIGNATURE */
    DeleteFileA(path);
}
TEST(mssigner_fixture_authhash_excludes_checksum_and_secdir) {
    BYTE b[FX_PE_SIZE + 0x100]; memset(b, 0, sizeof b); fx_pe_image(b);
    BYTE h1[64], h2[64], h3[64]; DWORD l1 = 0, l2 = 0, l3 = 0;
    if (!fx_pe_authhash(b, FX_PE_SIZE, BCRYPT_SHA1_ALGORITHM, h1, &l1)) { t_skip("no CNG hash"); return; }
    EXPECT_EQ(l1, 20);
    DWORD nt = ((IMAGE_DOS_HEADER *)b)->e_lfanew;
    DWORD chk = nt + 4 + 20 + 64, sec = nt + 4 + 20 + 0x70 + 32;
    /* "sign" the image by hand: checksum, certificate table entry and appended table all lie outside the digest */
    DWORD v = 0x12345678; memcpy(b + chk, &v, 4);
    v = FX_PE_SIZE; memcpy(b + sec, &v, 4); v = 0x100; memcpy(b + sec + 4, &v, 4);
    memset(b + FX_PE_SIZE, 0xAB, 0x100);
    CHECK(fx_pe_authhash(b, sizeof b, BCRYPT_SHA1_ALGORITHM, h2, &l2));
    EXPECT_EQ(l2, 20);
    EXPECT_EQ(memcmp(h1, h2, 20), 0);
    b[0x201] ^= 1;                                         /* a code byte must change the digest */
    CHECK(fx_pe_authhash(b, sizeof b, BCRYPT_SHA1_ALGORITHM, h3, &l3));
    CHECK(l3 == 20 && memcmp(h1, h3, 20) != 0);
}
TEST(mssigner_fixture_file_helpers_roundtrip) {
    char p[MAX_PATH]; t_tmpfile(p, sizeof p, "rt.bin");
    BYTE d[100]; for (int i = 0; i < 100; i++) d[i] = (BYTE)i;
    CHECK(fx_write_file(p, d, 100));
    DWORD n = 0; BYTE *r = fx_read_file(p, &n);
    CHECK(r && n == 100 && !memcmp(r, d, 100));
    free(r);
    DeleteFileA(p);
}
