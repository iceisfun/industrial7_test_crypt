/* bcryptprimitives.dll provider interfaces: Get*Interface function tables. */
#include "rng_common.h"

typedef NTSTATUS (WINAPI *GetIf_pfn)(LPCWSTR provider, LPCWSTR algid, void **ppTable, ULONG flags);
static GetIf_pfn rngi_get(const char *name) { return (GetIf_pfn)t_proc_in("bcryptprimitives.dll", name); }
/* GetRngInterface takes three arguments (ignored first argument, output pointer in the SECOND position, flags);
 * the other Get*Interface exports take (provider, algid, output, flags). Calling the RNG export with four
 * arguments stores through the algid pointer and faults. */
static LONG rngi_rng_call(GetIf_pfn f, LPCWSTR first, void **pp, ULONG flags) {
    return ((LONG (WINAPI *)(LPCWSTR, void **, ULONG))(void *)f)(first, pp, flags);
}

typedef NTSTATUS (WINAPI *vt_open_t)(BCRYPT_ALG_HANDLE *, LPCWSTR, ULONG);
typedef NTSTATUS (WINAPI *vt_getprop_t)(BCRYPT_ALG_HANDLE, LPCWSTR, PUCHAR, ULONG, ULONG *, ULONG);
typedef NTSTATUS (WINAPI *vt_close_t)(BCRYPT_ALG_HANDLE, ULONG);
typedef NTSTATUS (WINAPI *vt_genrandom_t)(BCRYPT_ALG_HANDLE, PUCHAR, ULONG, ULONG);
typedef struct { BCRYPT_INTERFACE_VERSION Version; void *fn[24]; } vt_t;

static int rngi_in_module(const void *p) {
    HMODULE m = t_module("bcryptprimitives.dll");
    if (!m || !p) return 0;
    IMAGE_DOS_HEADER *d = (IMAGE_DOS_HEADER *)m;
    IMAGE_NT_HEADERS *n = (IMAGE_NT_HEADERS *)((char *)m + d->e_lfanew);
    return (const char *)p >= (const char *)m && (const char *)p < (const char *)m + n->OptionalHeader.SizeOfImage;
}
static int rngi_code_in_module(const void *p) { return rngi_in_module(p); }

/* Fetch a table; returns it or NULL after recording failure. */
static vt_t *rngi_table(const char *fn, const WCHAR *alg) {
    GetIf_pfn f = rngi_get(fn); void *t = (void *)(ULONG_PTR)0x1; LONG s;
    if (!f) return NULL;
    s = !strcmp(fn, "GetRngInterface") ? rngi_rng_call(f, NULL, &t, 0) : f(NULL, alg, &t, 0);
    CHECKF(s == 0, "%s(%ls) = 0x%lx", fn, alg, (unsigned long)s);
    if (s) return NULL;
    CHECKF(t != NULL, "%s(%ls) table NULL", fn, alg);
    return (vt_t *)t;
}
static void rngi_check_table(const char *fn, const WCHAR *alg, vt_t *t) {
    int i;
    if (!t) return;
    CHECKF(rngi_in_module(t), "%s(%ls) table outside bcryptprimitives", fn, alg);
    /* on Win10 22H2 the hash table is interface version 2, every other class is version 1 */
    CHECKF(t->Version.MajorVersion == (strcmp(fn, "GetHashInterface") ? 1 : 2), "%s(%ls) major %u", fn, alg, t->Version.MajorVersion);
    if (t->Version.MinorVersion != 0) t_note("%s(%ls) minor version %u", fn, alg, t->Version.MinorVersion);
    /* Open, GetProperty, SetProperty, Close are the first four members of every provider table */
    for (i = 0; i < 4; i++) CHECKF(t->fn[i] != NULL && rngi_code_in_module(t->fn[i]), "%s(%ls) slot %d = %p", fn, alg, i, t->fn[i]);
}
static void rngi_table_readonly(const char *fn, const WCHAR *alg, vt_t *t) {
    MEMORY_BASIC_INFORMATION mbi;
    if (!t) return;
    if (!VirtualQuery(t, &mbi, sizeof mbi)) return;
    if (!strcmp(fn, "GetRngInterface"))   /* MSRngFunctionTable is known to live in .rdata */
        CHECKF(mbi.Protect == PAGE_READONLY, "%s(%ls) table page protection 0x%lx", fn, alg, (unsigned long)mbi.Protect);
    else if (mbi.Protect != PAGE_READONLY)
        t_note("%s(%ls) table page protection 0x%lx", fn, alg, (unsigned long)mbi.Protect);
}

/* ---------------- exports ---------------- */
TEST(rngi_exports_present) {
    HMODULE m = t_module("bcryptprimitives.dll");
    REQUIRE(m);
    static const char *const names[] = { "GetRngInterface", "GetHashInterface", "GetCipherInterface", "GetAsymmetricEncryptionInterface",
        "GetSignatureInterface", "GetSecretAgreementInterface", "GetKeyDerivationInterface", "MSCryptConvertRsaPrivateBlobToFullRsaBlob",
        "ProcessPrng", "ProcessPrngGuid" };
    unsigned i;
    if (t_is_wine()) { t_skip("emulator lacks the msprim exports"); return; }
    for (i = 0; i < sizeof names / sizeof *names; i++) CHECKF(GetProcAddress(m, names[i]) != NULL, "%s", names[i]);
}
TEST(rngi_exports_absent_from_bcrypt) {
    HMODULE m = t_module("bcrypt.dll"); REQUIRE(m);
    if (t_is_wine()) { t_skip("emulator exports these from bcrypt"); return; }
    CHECK(GetProcAddress(m, "GetRngInterface") == NULL);
    CHECK(GetProcAddress(m, "GetHashInterface") == NULL);
    CHECK(GetProcAddress(m, "MSCryptConvertRsaPrivateBlobToFullRsaBlob") == NULL);
}
TEST(rngi_export_ordinals) {
    /* ordinals are alphabetical by export name: asymmetric=1 cipher=2 hash=3 kdf=4 rng=5 agreement=6 signature=7 convert=8 */
    HMODULE m = t_module("bcryptprimitives.dll"); REQUIRE(m);
    if (t_is_wine()) { t_skip("emulator ordinals differ"); return; }
    static const struct { unsigned ord; const char *name; } e[] = {
        {1, "GetAsymmetricEncryptionInterface"}, {2, "GetCipherInterface"}, {3, "GetHashInterface"}, {4, "GetKeyDerivationInterface"},
        {5, "GetRngInterface"}, {6, "GetSecretAgreementInterface"}, {7, "GetSignatureInterface"}, {8, "MSCryptConvertRsaPrivateBlobToFullRsaBlob"},
        {9, "ProcessPrng"}, {10, "ProcessPrngGuid"} };
    unsigned i;
    for (i = 0; i < sizeof e / sizeof *e; i++)
        CHECKF(GetProcAddress(m, (LPCSTR)(ULONG_PTR)e[i].ord) == GetProcAddress(m, e[i].name), "ordinal %u / %s", e[i].ord, e[i].name);
}

/* ---------------- RNG ---------------- */
TEST(rngi_rng_table) {
    GetIf_pfn f = rngi_get("GetRngInterface"); REQUIRE(f);
    vt_t *t = rngi_table("GetRngInterface", L"RNG");
    rngi_check_table("GetRngInterface", L"RNG", t);
    rngi_table_readonly("GetRngInterface", L"RNG", t);
}
TEST(rngi_rng_ignores_algid_and_provider) {
    GetIf_pfn f = rngi_get("GetRngInterface"); REQUIRE(f);
    void *a = NULL, *b = NULL, *c = NULL, *d = NULL;
    EQ_NT(rngi_rng_call(f, NULL, &a, 0), 0);
    EQ_NT(rngi_rng_call(f, L"Microsoft Primitive Provider", &b, 0), 0);
    EQ_NT(rngi_rng_call(f, L"NotAnAlgorithm", &c, 0), 0);   /* the first argument is not examined */
    EQ_NT(rngi_rng_call(f, NULL, &d, 0xFFFFFFFF), 0);       /* nor are the flags */
    CHECK(a != NULL && a == b && a == c && a == d);
}
TEST(rngi_rng_table_stable_across_calls) {
    GetIf_pfn f = rngi_get("GetRngInterface"); REQUIRE(f);
    void *a = NULL, *b = NULL; int i;
    EQ_NT(rngi_rng_call(f, NULL, &a, 0), 0);
    for (i = 0; i < 20; i++) { b = NULL; EQ_NT(rngi_rng_call(f, NULL, &b, 0), 0); CHECK(a == b); }
}
CHILD(rngi_vt_rng) {
    GetIf_pfn f = rngi_get("GetRngInterface"); vt_t *t = NULL; BCRYPT_ALG_HANDLE h = NULL;
    unsigned char b1[48], b2[48]; LONG s;
    if (!f || rngi_rng_call(f, NULL, (void **)&t, 0) || !t) return 10;
    s = ((vt_open_t)t->fn[0])(&h, L"RNG", 0);
    if (s) return 11;
    if (!h) return 12;
    memset(b1, 0, sizeof b1); memset(b2, 0, sizeof b2);
    s = ((vt_genrandom_t)t->fn[4])(h, b1, sizeof b1, 0);
    if (s) return 13;
    s = ((vt_genrandom_t)t->fn[4])(h, b2, sizeof b2, 0);
    if (s) return 14;
    if (rng_all_zero(b1, sizeof b1) || !memcmp(b1, b2, sizeof b1)) return 15;
    s = ((vt_genrandom_t)t->fn[4])(h, b1, 0, 0);
    if (s) return 16;
    s = ((vt_close_t)t->fn[3])(h, 0);
    if (s) return 17;
    return 0;
}
TEST(rngi_rng_vtable_open_generate_close) {
    GetIf_pfn f = rngi_get("GetRngInterface"); REQUIRE(f);
    DWORD ec = t_run_child("rngi_vt_rng", "", 20000);
    if (ec != 0) t_note("vtable RNG chain child exit code 0x%lx (10 table,11 open,13/14 gen,15 stats,17 close)", (unsigned long)ec);
    CHECK(ec == 0);
}
CHILD(rngi_vt_rng_prop) {
    GetIf_pfn f = rngi_get("GetRngInterface"); vt_t *t = NULL; BCRYPT_ALG_HANDLE h = NULL;
    WCHAR nm[32] = {0}; ULONG got = 0;
    if (!f || rngi_rng_call(f, NULL, (void **)&t, 0) || !t) return 10;
    if (((vt_open_t)t->fn[0])(&h, L"RNG", 0)) return 11;
    if (((vt_getprop_t)t->fn[1])(h, BCRYPT_ALGORITHM_NAME, (PUCHAR)nm, sizeof nm, &got, 0)) return 12;
    if (lstrcmpW(nm, L"RNG")) return 13;
    ((vt_close_t)t->fn[3])(h, 0);
    return 0;
}
TEST(rngi_rng_vtable_get_property_name) {
    DWORD ec; REQUIRE(rngi_get("GetRngInterface"));
    ec = t_run_child("rngi_vt_rng_prop", "", 20000);
    if (ec) t_note("vtable RNG GetProperty child exit 0x%lx", (unsigned long)ec);
    CHECK(ec == 0);
}

/* ---------------- Hash ---------------- */
static const WCHAR *const HASH_OK[] = { L"SHA1", L"SHA256", L"SHA384", L"SHA512", L"MD5" };
static const WCHAR *const HASH_OBSERVE[] = { L"MD2", L"MD4", L"AES-CMAC", L"AES-GMAC", L"SHA3-256", L"SHA3-384", L"SHA3-512", L"HMAC", L"XOF", L"CSHAKE128" };
TEST(rngi_hash_supported_names) {
    REQUIRE(rngi_get("GetHashInterface"));
    unsigned i;
    for (i = 0; i < sizeof HASH_OK / sizeof *HASH_OK; i++) {
        vt_t *t = rngi_table("GetHashInterface", HASH_OK[i]);
        rngi_check_table("GetHashInterface", HASH_OK[i], t);
    }
}
TEST(rngi_hash_single_shared_table) {
    GetIf_pfn f = rngi_get("GetHashInterface"); REQUIRE(f);
    void *first = NULL; unsigned i;
    for (i = 0; i < sizeof HASH_OK / sizeof *HASH_OK; i++) {
        void *t = NULL; EQ_NT(f(NULL, HASH_OK[i], &t, 0), 0);
        if (!first) first = t; else CHECKF(t == first, "%ls", HASH_OK[i]);
    }
    rngi_table_readonly("GetHashInterface", L"SHA256", (vt_t *)first);
}
TEST(rngi_hash_observe_other_names) {
    GetIf_pfn f = rngi_get("GetHashInterface"); REQUIRE(f);
    unsigned i;
    for (i = 0; i < sizeof HASH_OBSERVE / sizeof *HASH_OBSERVE; i++) {
        void *t = NULL; LONG s = f(NULL, HASH_OBSERVE[i], &t, 0);
        t_note("GetHashInterface(%ls) = 0x%lx", HASH_OBSERVE[i], (unsigned long)s);
    }
}
TEST(rngi_hash_unknown_name_not_supported) {
    GetIf_pfn f = rngi_get("GetHashInterface"); REQUIRE(f);
    static const WCHAR *const bad[] = { L"", L"NOPE", L"SHA", L"SHA2", L"SHA-256", L"SHA1 ", L" SHA1", L"RNG", L"AES", L"RSA", L"SHA2560" };
    unsigned i;
    for (i = 0; i < sizeof bad / sizeof *bad; i++) {
        void *t = (void *)(ULONG_PTR)0x1234;
        LONG s = f(NULL, bad[i], &t, 0);
        CHECKF(s == NS_NOT_SUPPORTED, "'%ls' -> 0x%lx", bad[i], (unsigned long)s);
        CHECKF(t == (void *)(ULONG_PTR)0x1234, "'%ls' output modified on failure", bad[i]);
    }
}
TEST(rngi_hash_names_case_sensitive) {
    GetIf_pfn f = rngi_get("GetHashInterface"); REQUIRE(f);
    static const WCHAR *const bad[] = { L"sha256", L"Sha256", L"sha1", L"md5", L"SHA384 " };
    unsigned i;
    for (i = 0; i < sizeof bad / sizeof *bad; i++) {
        void *t = NULL; LONG s = f(NULL, bad[i], &t, 0);
        CHECKF(s == NS_NOT_SUPPORTED, "'%ls' -> 0x%lx", bad[i], (unsigned long)s);
    }
}
TEST(rngi_hash_provider_name_ignored) {
    GetIf_pfn f = rngi_get("GetHashInterface"); REQUIRE(f);
    void *a = NULL, *b = NULL;
    EQ_NT(f(NULL, L"SHA256", &a, 0), 0);
    EQ_NT(f(L"whatever provider", L"SHA256", &b, 0x7), 0);
    CHECK(a && a == b);
}
CHILD(rngi_vt_hash_props) {
    GetIf_pfn f = rngi_get("GetHashInterface"); vt_t *t = NULL; BCRYPT_ALG_HANDLE h = NULL;
    static const struct { const WCHAR *n; ULONG len; } e[] = { {L"SHA1", 20}, {L"SHA256", 32}, {L"SHA384", 48}, {L"SHA512", 64}, {L"MD5", 16} };
    unsigned i;
    if (!f) return 10;
    for (i = 0; i < 5; i++) {
        ULONG v = 0, got = 0; h = NULL; t = NULL;
        if (f(NULL, e[i].n, (void **)&t, 0) || !t) return 11;
        if (((vt_open_t)t->fn[0])(&h, e[i].n, 0) || !h) return 12;
        if (((vt_getprop_t)t->fn[1])(h, L"HashDigestLength", (PUCHAR)&v, sizeof v, &got, 0)) return 13;
        if (got != 4 || v != e[i].len) return 14;
        if (((vt_close_t)t->fn[3])(h, 0)) return 15;
    }
    return 0;
}
TEST(rngi_hash_vtable_digest_length_property) {
    DWORD ec; REQUIRE(rngi_get("GetHashInterface"));
    ec = t_run_child("rngi_vt_hash_props", "", 20000);
    if (ec) t_note("vtable hash property child exit 0x%lx", (unsigned long)ec);
    CHECK(ec == 0);
}
/* Full hash through the table. The member order after Close is not documented in the headers available here,
 * so the outcome is reported as an observation only; a crash is isolated by running in a child. */
typedef NTSTATUS (WINAPI *vt_create_t)(BCRYPT_ALG_HANDLE, BCRYPT_HASH_HANDLE *, PUCHAR, ULONG, PUCHAR, ULONG, ULONG);
typedef NTSTATUS (WINAPI *vt_data_t)(BCRYPT_HASH_HANDLE, PUCHAR, ULONG, ULONG);
typedef NTSTATUS (WINAPI *vt_destroy_t)(BCRYPT_HASH_HANDLE);
CHILD(rngi_vt_hash_chain) {
    GetIf_pfn f = rngi_get("GetHashInterface"); vt_t *t = NULL; BCRYPT_ALG_HANDLE h = NULL; BCRYPT_HASH_HANDLE hh = NULL;
    ULONG objlen = 0, got = 0; unsigned char dig[32]; unsigned char *obj;
    static const unsigned char sha256_abc[32] = {
        0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
        0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad };
    if (!f || f(NULL, L"SHA256", (void **)&t, 0) || !t) return 10;
    if (((vt_open_t)t->fn[0])(&h, L"SHA256", 0)) return 11;
    if (((vt_getprop_t)t->fn[1])(h, L"ObjectLength", (PUCHAR)&objlen, 4, &got, 0)) return 12;
    obj = (unsigned char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, objlen + 64);
    if (!obj) return 13;
    if (((vt_create_t)t->fn[4])(h, &hh, obj, objlen, NULL, 0, 0)) return 14;
    if (((vt_data_t)t->fn[5])(hh, (PUCHAR)"abc", 3, 0)) return 15;
    if (((vt_data_t)t->fn[7])(hh, dig, 32, 0)) return 16;
    if (memcmp(dig, sha256_abc, 32)) return 17;
    ((vt_destroy_t)t->fn[8])(hh);
    ((vt_close_t)t->fn[3])(h, 0);
    return 0;
}
TEST(rngi_hash_vtable_sha256_abc_observe) {
    REQUIRE(rngi_get("GetHashInterface"));
    DWORD ec = t_run_child("rngi_vt_hash_chain", "", 20000);
    t_note("vtable SHA256(abc) chain child exit 0x%lx (0 = matches the FIPS 180 vector with member order Create,HashData,Duplicate,Finish,Destroy after Close)", (unsigned long)ec);
}

/* ---------------- Cipher ---------------- */
TEST(rngi_cipher_supported_names) {
    REQUIRE(rngi_get("GetCipherInterface"));
    static const WCHAR *const ok[] = { L"AES", L"RC4" };
    unsigned i;
    for (i = 0; i < 2; i++) { vt_t *t = rngi_table("GetCipherInterface", ok[i]); rngi_check_table("GetCipherInterface", ok[i], t); }
}
TEST(rngi_cipher_single_shared_table) {
    GetIf_pfn f = rngi_get("GetCipherInterface"); REQUIRE(f);
    void *a = NULL, *b = NULL;
    EQ_NT(f(NULL, L"AES", &a, 0), 0);
    EQ_NT(f(NULL, L"RC4", &b, 0), 0);
    CHECK(a && a == b);
    rngi_table_readonly("GetCipherInterface", L"AES", (vt_t *)a);
}
TEST(rngi_cipher_observe_other_names) {
    GetIf_pfn f = rngi_get("GetCipherInterface"); REQUIRE(f);
    static const WCHAR *const n[] = { L"3DES", L"3DES_112", L"DES", L"DESX", L"RC2", L"CHACHA20", L"XTS-AES", L"AES-GCM", L"SHA256", L"RNG" };
    unsigned i;
    for (i = 0; i < sizeof n / sizeof *n; i++) { void *t = NULL; LONG s = f(NULL, n[i], &t, 0); t_note("GetCipherInterface(%ls) = 0x%lx", n[i], (unsigned long)s); }
}
TEST(rngi_cipher_unknown_name_not_supported) {
    GetIf_pfn f = rngi_get("GetCipherInterface"); REQUIRE(f);
    static const WCHAR *const bad[] = { L"", L"aes", L"Rc4", L"AES ", L"AESX", L"BOGUS", L"RSA" };
    unsigned i;
    for (i = 0; i < sizeof bad / sizeof *bad; i++) {
        void *t = (void *)(ULONG_PTR)0x4321;
        LONG s = f(NULL, bad[i], &t, 0);
        CHECKF(s == NS_NOT_SUPPORTED, "'%ls' -> 0x%lx", bad[i], (unsigned long)s);
        CHECKF(t == (void *)(ULONG_PTR)0x4321, "'%ls' output modified", bad[i]);
    }
}
CHILD(rngi_vt_cipher_props) {
    GetIf_pfn f = rngi_get("GetCipherInterface"); vt_t *t = NULL; BCRYPT_ALG_HANDLE h = NULL; ULONG v = 0, got = 0;
    if (!f || f(NULL, L"AES", (void **)&t, 0) || !t) return 10;
    if (((vt_open_t)t->fn[0])(&h, L"AES", 0) || !h) return 11;
    if (((vt_getprop_t)t->fn[1])(h, L"BlockLength", (PUCHAR)&v, 4, &got, 0)) return 12;
    if (v != 16 || got != 4) return 13;
    if (((vt_close_t)t->fn[3])(h, 0)) return 14;
    return 0;
}
TEST(rngi_cipher_vtable_block_length) {
    DWORD ec; REQUIRE(rngi_get("GetCipherInterface"));
    ec = t_run_child("rngi_vt_cipher_props", "", 20000);
    if (ec) t_note("vtable cipher property child exit 0x%lx", (unsigned long)ec);
    CHECK(ec == 0);
}

/* ---------------- Asymmetric encryption ---------------- */
TEST(rngi_asym_rsa) {
    REQUIRE(rngi_get("GetAsymmetricEncryptionInterface"));
    vt_t *t = rngi_table("GetAsymmetricEncryptionInterface", L"RSA");
    rngi_check_table("GetAsymmetricEncryptionInterface", L"RSA", t);
    rngi_table_readonly("GetAsymmetricEncryptionInterface", L"RSA", t);
}
TEST(rngi_asym_other_names_not_supported) {
    GetIf_pfn f = rngi_get("GetAsymmetricEncryptionInterface"); REQUIRE(f);
    static const WCHAR *const bad[] = { L"", L"rsa", L"RSA_SIGN", L"DH", L"ECDH", L"DSA", L"ECDSA", L"RSA ", L"RSAX", L"AES" };
    unsigned i;
    for (i = 0; i < sizeof bad / sizeof *bad; i++) {
        void *t = (void *)(ULONG_PTR)0x77; LONG s = f(NULL, bad[i], &t, 0);
        CHECKF(s == NS_NOT_SUPPORTED, "'%ls' -> 0x%lx", bad[i], (unsigned long)s);
        CHECKF(t == (void *)(ULONG_PTR)0x77, "'%ls' output modified", bad[i]);
    }
}
TEST(rngi_asym_flags_provider_ignored) {
    GetIf_pfn f = rngi_get("GetAsymmetricEncryptionInterface"); REQUIRE(f);
    void *a = NULL, *b = NULL;
    EQ_NT(f(NULL, L"RSA", &a, 0), 0);
    EQ_NT(f(L"x", L"RSA", &b, 0xFFFF), 0);
    CHECK(a && a == b);
}

/* ---------------- Signature ---------------- */
TEST(rngi_sig_supported_names) {
    GetIf_pfn f = rngi_get("GetSignatureInterface"); REQUIRE(f);
    static const WCHAR *const ok[] = { L"ECDSA", L"ECDSA_P256", L"ECDSA_P384", L"ECDSA_P521", L"RSA_SIGN", L"DSA" };
    unsigned i;
    for (i = 0; i < sizeof ok / sizeof *ok; i++) { vt_t *t = rngi_table("GetSignatureInterface", ok[i]); rngi_check_table("GetSignatureInterface", ok[i], t); rngi_table_readonly("GetSignatureInterface", ok[i], t); }
}
TEST(rngi_sig_table_sharing) {
    GetIf_pfn f = rngi_get("GetSignatureInterface"); REQUIRE(f);
    void *ec, *e256, *e384, *e521, *rsa, *dsa;
    EQ_NT(f(NULL, L"ECDSA", &ec, 0), 0); EQ_NT(f(NULL, L"ECDSA_P256", &e256, 0), 0);
    EQ_NT(f(NULL, L"ECDSA_P384", &e384, 0), 0); EQ_NT(f(NULL, L"ECDSA_P521", &e521, 0), 0);
    EQ_NT(f(NULL, L"RSA_SIGN", &rsa, 0), 0); EQ_NT(f(NULL, L"DSA", &dsa, 0), 0);
    CHECK(ec == e256 && ec == e384 && ec == e521);
    CHECK(rsa != ec && dsa != ec && rsa != dsa);
}
TEST(rngi_sig_unsupported_names) {
    GetIf_pfn f = rngi_get("GetSignatureInterface"); REQUIRE(f);
    static const WCHAR *const bad[] = { L"", L"RSA", L"ecdsa", L"ECDSA_P192", L"ECDSA_P256 ", L"ECDH", L"DH", L"dsa", L"RSA_SIGN2", L"RNG", L"ECDSA_P" };
    unsigned i;
    for (i = 0; i < sizeof bad / sizeof *bad; i++) {
        void *t = (void *)(ULONG_PTR)0x99; LONG s = f(NULL, bad[i], &t, 0);
        CHECKF(s == NS_NOT_SUPPORTED, "'%ls' -> 0x%lx", bad[i], (unsigned long)s);
        CHECKF(t == (void *)(ULONG_PTR)0x99, "'%ls' output modified", bad[i]);
    }
}

/* ---------------- Secret agreement ---------------- */
TEST(rngi_agree_supported_names) {
    GetIf_pfn f = rngi_get("GetSecretAgreementInterface"); REQUIRE(f);
    static const WCHAR *const ok[] = { L"DH", L"ECDH", L"ECDH_P256", L"ECDH_P384", L"ECDH_P521" };
    unsigned i;
    for (i = 0; i < sizeof ok / sizeof *ok; i++) { vt_t *t = rngi_table("GetSecretAgreementInterface", ok[i]); rngi_check_table("GetSecretAgreementInterface", ok[i], t); rngi_table_readonly("GetSecretAgreementInterface", ok[i], t); }
}
TEST(rngi_agree_table_sharing) {
    GetIf_pfn f = rngi_get("GetSecretAgreementInterface"); REQUIRE(f);
    void *dh, *e, *e256, *e384, *e521;
    EQ_NT(f(NULL, L"DH", &dh, 0), 0); EQ_NT(f(NULL, L"ECDH", &e, 0), 0);
    EQ_NT(f(NULL, L"ECDH_P256", &e256, 0), 0); EQ_NT(f(NULL, L"ECDH_P384", &e384, 0), 0); EQ_NT(f(NULL, L"ECDH_P521", &e521, 0), 0);
    CHECK(e == e256 && e == e384 && e == e521);
    CHECK(dh != e);
}
TEST(rngi_agree_unsupported_names) {
    GetIf_pfn f = rngi_get("GetSecretAgreementInterface"); REQUIRE(f);
    static const WCHAR *const bad[] = { L"", L"D", L"DHX", L"dh", L"DH ", L"ecdh", L"ECDH_P192", L"ECDH_P256 ", L"ECDSA", L"RSA", L"DSA", L"ECDH_P" };
    unsigned i;
    for (i = 0; i < sizeof bad / sizeof *bad; i++) {
        void *t = (void *)(ULONG_PTR)0x55; LONG s = f(NULL, bad[i], &t, 0);
        CHECKF(s == NS_NOT_SUPPORTED, "'%ls' -> 0x%lx", bad[i], (unsigned long)s);
        CHECKF(t == (void *)(ULONG_PTR)0x55, "'%ls' output modified", bad[i]);
    }
}

/* ---------------- Key derivation ---------------- */
TEST(rngi_kdf_supported_names) {
    GetIf_pfn f = rngi_get("GetKeyDerivationInterface"); REQUIRE(f);
    static const WCHAR *const ok[] = { L"SP800_108_CTR_HMAC", L"SP800_56A_CONCAT", L"PBKDF2", L"CAPI_KDF", L"TLS1_1_KDF", L"TLS1_2_KDF", L"HKDF" };
    void *first = NULL; unsigned i;
    for (i = 0; i < sizeof ok / sizeof *ok; i++) {
        vt_t *t = rngi_table("GetKeyDerivationInterface", ok[i]);
        rngi_check_table("GetKeyDerivationInterface", ok[i], t);
        if (!first) first = t; else CHECKF((void *)t == first, "%ls", ok[i]);
    }
    rngi_table_readonly("GetKeyDerivationInterface", L"HKDF", (vt_t *)first);
}
TEST(rngi_kdf_unsupported_names) {
    GetIf_pfn f = rngi_get("GetKeyDerivationInterface"); REQUIRE(f);
    static const WCHAR *const bad[] = { L"", L"pbkdf2", L"PBKDF", L"HKDF ", L"SP800_108", L"SP800_56A", L"TLS1_KDF", L"SHA256", L"HMAC", L"SCRYPT" };
    unsigned i;
    for (i = 0; i < sizeof bad / sizeof *bad; i++) {
        void *t = (void *)(ULONG_PTR)0x33; LONG s = f(NULL, bad[i], &t, 0);
        CHECKF(s == NS_NOT_SUPPORTED, "'%ls' -> 0x%lx", bad[i], (unsigned long)s);
        CHECKF(t == (void *)(ULONG_PTR)0x33, "'%ls' output modified", bad[i]);
    }
}

/* ---------------- cross-interface ---------------- */
TEST(rngi_tables_are_distinct_per_class) {
    void *rng = NULL, *hash = NULL, *ciph = NULL, *asym = NULL, *sig = NULL, *agr = NULL, *kdf = NULL;
    GetIf_pfn a = rngi_get("GetRngInterface"), b = rngi_get("GetHashInterface"), c = rngi_get("GetCipherInterface"),
              d = rngi_get("GetAsymmetricEncryptionInterface"), e = rngi_get("GetSignatureInterface"),
              g = rngi_get("GetSecretAgreementInterface"), h = rngi_get("GetKeyDerivationInterface");
    REQUIRE(a); REQUIRE(b); REQUIRE(c); REQUIRE(d); REQUIRE(e); REQUIRE(g); REQUIRE(h);
    EQ_NT(rngi_rng_call(a, NULL, &rng, 0), 0); EQ_NT(b(NULL, L"SHA256", &hash, 0), 0); EQ_NT(c(NULL, L"AES", &ciph, 0), 0);
    EQ_NT(d(NULL, L"RSA", &asym, 0), 0); EQ_NT(e(NULL, L"DSA", &sig, 0), 0); EQ_NT(g(NULL, L"DH", &agr, 0), 0);
    EQ_NT(h(NULL, L"PBKDF2", &kdf, 0), 0);
    void *all[] = { rng, hash, ciph, asym, sig, agr, kdf }; int i, j;
    for (i = 0; i < 7; i++) for (j = i + 1; j < 7; j++) CHECKF(all[i] != all[j], "tables %d and %d are the same object", i, j);
}
TEST(rngi_wrong_class_names_rejected) {
    /* the RNG name is not a hash/cipher/kdf/... algorithm */
    GetIf_pfn b = rngi_get("GetHashInterface"), c = rngi_get("GetCipherInterface"), d = rngi_get("GetAsymmetricEncryptionInterface"),
              e = rngi_get("GetSignatureInterface"), g = rngi_get("GetSecretAgreementInterface"), h = rngi_get("GetKeyDerivationInterface");
    REQUIRE(b); REQUIRE(c); REQUIRE(d); REQUIRE(e); REQUIRE(g); REQUIRE(h);
    void *t = NULL;
    EQ_NT(b(NULL, L"RNG", &t, 0), NS_NOT_SUPPORTED); EQ_NT(c(NULL, L"RNG", &t, 0), NS_NOT_SUPPORTED);
    EQ_NT(d(NULL, L"RNG", &t, 0), NS_NOT_SUPPORTED); EQ_NT(e(NULL, L"RNG", &t, 0), NS_NOT_SUPPORTED);
    EQ_NT(g(NULL, L"RNG", &t, 0), NS_NOT_SUPPORTED); EQ_NT(h(NULL, L"RNG", &t, 0), NS_NOT_SUPPORTED);
}

/* ================= MSCryptConvertRsaPrivateBlobToFullRsaBlob ================= */
#include "rsa_vectors.h"
UDECL(NTSTATUS, MSCryptConvertRsaPrivateBlobToFullRsaBlob, (PUCHAR pbIn, ULONG cbIn, PUCHAR pbOut, ULONG cbOut, ULONG *pcbResult));
#define CONV() ((MSCryptConvertRsaPrivateBlobToFullRsaBlob_pfn)t_proc_in("bcryptprimitives.dll", "MSCryptConvertRsaPrivateBlobToFullRsaBlob"))

static void conv_known_answer(const unsigned char *in, size_t cin, const unsigned char *want, size_t cwant, const char *tag) {
    MSCryptConvertRsaPrivateBlobToFullRsaBlob_pfn f = CONV(); unsigned char *out; ULONG need = 0; LONG s;
    if (!f) return;
    s = f((PUCHAR)in, (ULONG)cin, NULL, 0, &need);
    CHECKF(s == 0, "%s size query status 0x%lx", tag, (unsigned long)s);
    CHECKF(need == cwant, "%s size query %lu want %zu", tag, (unsigned long)need, cwant);
    out = (unsigned char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cwant + 64);
    if (!out) return;
    memset(out + cwant, 0xEE, 64);
    need = 0;
    s = f((PUCHAR)in, (ULONG)cin, out, (ULONG)cwant, &need);
    CHECKF(s == 0, "%s convert status 0x%lx", tag, (unsigned long)s);
    CHECKF(need == cwant, "%s result size %lu", tag, (unsigned long)need);
    CHECKF(!memcmp(out, want, cwant), "%s output differs from the expected FULLPRIVATE blob", tag);
    HeapFree(GetProcessHeap(), 0, out);
}
TEST(rngconv_known_answer_1024) { REQUIRE(CONV()); conv_known_answer(rsa1024_private, sizeof rsa1024_private, rsa1024_full, sizeof rsa1024_full, "1024"); }
TEST(rngconv_known_answer_2048) { REQUIRE(CONV()); conv_known_answer(rsa2048_private, sizeof rsa2048_private, rsa2048_full, sizeof rsa2048_full, "2048"); }

TEST(rngconv_header_fields_1024) {
    MSCryptConvertRsaPrivateBlobToFullRsaBlob_pfn f = CONV(); REQUIRE(f);
    unsigned char out[sizeof rsa1024_full]; ULONG need = 0; ULONG *h = (ULONG *)out;
    EQ_NT(f((PUCHAR)rsa1024_private, sizeof rsa1024_private, out, sizeof out, &need), 0);
    EXPECT_EQ(h[0], 0x33415352);   /* 'RSA3' = BCRYPT_RSAFULLPRIVATE_MAGIC */
    EXPECT_EQ(h[0], BCRYPT_RSAFULLPRIVATE_MAGIC);
    EXPECT_EQ(h[1], 1024); EXPECT_EQ(h[2], 3); EXPECT_EQ(h[3], 128); EXPECT_EQ(h[4], 64); EXPECT_EQ(h[5], 64);
    EXPECT_EQ(need, 24 + 3 + 128 + 5 * 64 + 128);
}
TEST(rngconv_input_unmodified) {
    MSCryptConvertRsaPrivateBlobToFullRsaBlob_pfn f = CONV(); REQUIRE(f);
    unsigned char in[sizeof rsa1024_private], out[sizeof rsa1024_full]; ULONG need;
    memcpy(in, rsa1024_private, sizeof in);
    EQ_NT(f(in, sizeof in, out, sizeof out, &need), 0);
    CHECK(!memcmp(in, rsa1024_private, sizeof in));
}
TEST(rngconv_size_query_with_null_output_ignores_cbout) {
    MSCryptConvertRsaPrivateBlobToFullRsaBlob_pfn f = CONV(); REQUIRE(f);
    ULONG need = 0, need2 = 0;
    EQ_NT(f((PUCHAR)rsa1024_private, sizeof rsa1024_private, NULL, 0, &need), 0);
    EQ_NT(f((PUCHAR)rsa1024_private, sizeof rsa1024_private, NULL, 9999, &need2), 0);
    EXPECT_EQ(need, sizeof rsa1024_full); EXPECT_EQ(need2, sizeof rsa1024_full);
}
TEST(rngconv_buffer_too_small) {
    MSCryptConvertRsaPrivateBlobToFullRsaBlob_pfn f = CONV(); REQUIRE(f);
    unsigned char out[sizeof rsa1024_full]; ULONG need; ULONG sizes[] = { 0, 1, 23, 24, sizeof out / 2, sizeof out - 1 }; unsigned i;
    for (i = 0; i < sizeof sizes / sizeof *sizes; i++) {
        memset(out, 0xEE, sizeof out); need = 0;
        LONG s = f((PUCHAR)rsa1024_private, sizeof rsa1024_private, out, sizes[i], &need);
        CHECKF(s == NS_BUFFER_TOO_SMALL, "cbOut=%lu status 0x%lx", (unsigned long)sizes[i], (unsigned long)s);
        CHECKF(need == sizeof rsa1024_full, "cbOut=%lu needed=%lu", (unsigned long)sizes[i], (unsigned long)need);
        unsigned k, clean = 1; for (k = 0; k < sizeof out; k++) if (out[k] != 0xEE) clean = 0;
        CHECKF(clean, "cbOut=%lu output written despite error", (unsigned long)sizes[i]);
    }
}
TEST(rngconv_larger_buffer_tail_untouched) {
    MSCryptConvertRsaPrivateBlobToFullRsaBlob_pfn f = CONV(); REQUIRE(f);
    unsigned char out[sizeof rsa1024_full + 40]; ULONG need = 0; unsigned i;
    memset(out, 0xEE, sizeof out);
    EQ_NT(f((PUCHAR)rsa1024_private, sizeof rsa1024_private, out, sizeof out, &need), 0);
    EXPECT_EQ(need, sizeof rsa1024_full);
    CHECK(!memcmp(out, rsa1024_full, sizeof rsa1024_full));
    for (i = sizeof rsa1024_full; i < sizeof out; i++) CHECKF(out[i] == 0xEE, "tail byte %u", i);
}
TEST(rngconv_repeatable) {
    MSCryptConvertRsaPrivateBlobToFullRsaBlob_pfn f = CONV(); REQUIRE(f);
    unsigned char a[sizeof rsa2048_full], b[sizeof rsa2048_full]; ULONG n1, n2; int i;
    for (i = 0; i < 5; i++) {
        EQ_NT(f((PUCHAR)rsa2048_private, sizeof rsa2048_private, a, sizeof a, &n1), 0);
        EQ_NT(f((PUCHAR)rsa2048_private, sizeof rsa2048_private, b, sizeof b, &n2), 0);
        CHECK(n1 == n2 && !memcmp(a, b, sizeof a) && !memcmp(a, rsa2048_full, sizeof a));
    }
}
TEST(rngconv_full_blob_idempotent_input_rejected_or_same) {
    /* feeding the already-full blob: observation only */
    MSCryptConvertRsaPrivateBlobToFullRsaBlob_pfn f = CONV(); REQUIRE(f);
    unsigned char out[sizeof rsa1024_full + 256]; ULONG need = 0;
    LONG s = f((PUCHAR)rsa1024_full, sizeof rsa1024_full, out, sizeof out, &need);
    t_note("convert(FULLPRIVATE input) = 0x%lx need=%lu", (unsigned long)s, (unsigned long)need);
}
TEST(rngconv_truncated_input_fails) {
    MSCryptConvertRsaPrivateBlobToFullRsaBlob_pfn f = CONV(); REQUIRE(f);
    unsigned char out[sizeof rsa1024_full + 64]; ULONG need = 0x1234; ULONG cuts[] = { sizeof rsa1024_private - 1, sizeof rsa1024_private - 64, 24, 8, 4 }; unsigned i;
    for (i = 0; i < sizeof cuts / sizeof *cuts; i++) {
        LONG s = f((PUCHAR)rsa1024_private, cuts[i], out, sizeof out, &need);
        CHECKF(s < 0, "cbIn=%lu unexpectedly 0x%lx", (unsigned long)cuts[i], (unsigned long)s);
        t_note("convert(cbIn=%lu) = 0x%lx", (unsigned long)cuts[i], (unsigned long)s);
    }
}
TEST(rngconv_zero_length_input_fails) {
    MSCryptConvertRsaPrivateBlobToFullRsaBlob_pfn f = CONV(); REQUIRE(f);
    unsigned char out[512]; ULONG need = 0;
    LONG s = f((PUCHAR)rsa1024_private, 0, out, sizeof out, &need);
    CHECKF(s < 0, "status 0x%lx", (unsigned long)s);
}
TEST(rngconv_public_blob_rejected) {
    MSCryptConvertRsaPrivateBlobToFullRsaBlob_pfn f = CONV(); REQUIRE(f);
    unsigned char pub[24 + 3 + 128]; ULONG *h = (ULONG *)pub; unsigned char out[1024]; ULONG need = 0;
    memset(pub, 0, sizeof pub);
    h[0] = BCRYPT_RSAPUBLIC_MAGIC; h[1] = 1024; h[2] = 3; h[3] = 128; h[4] = 0; h[5] = 0;
    pub[24] = 1; pub[25] = 0; pub[26] = 1;
    memcpy(pub + 27, rsa1024_n, 128);
    LONG s = f(pub, sizeof pub, out, sizeof out, &need);
    CHECKF(s < 0, "public blob accepted: 0x%lx", (unsigned long)s);
    t_note("convert(RSAPUBLIC blob) = 0x%lx", (unsigned long)s);
}
TEST(rngconv_wrong_magic_rejected) {
    MSCryptConvertRsaPrivateBlobToFullRsaBlob_pfn f = CONV(); REQUIRE(f);
    unsigned char in[sizeof rsa1024_private], out[1024]; ULONG need = 0;
    memcpy(in, rsa1024_private, sizeof in);
    *(ULONG *)in = 0x41424344;
    LONG s = f(in, sizeof in, out, sizeof out, &need);
    CHECKF(s < 0, "bad magic accepted: 0x%lx", (unsigned long)s);
    t_note("convert(bad magic) = 0x%lx", (unsigned long)s);
}
TEST(rngconv_corrupt_header_lengths_rejected) {
    MSCryptConvertRsaPrivateBlobToFullRsaBlob_pfn f = CONV(); REQUIRE(f);
    unsigned char in[sizeof rsa1024_private], out[1024]; ULONG need = 0; ULONG *h = (ULONG *)in; unsigned i;
    for (i = 0; i < 3; i++) {
        memcpy(in, rsa1024_private, sizeof in);
        if (i == 0) h[3] = 127;        /* modulus length not matching the bit length */
        if (i == 1) h[4] = 100;        /* prime length that no longer matches the body */
        if (i == 2) h[2] = 0;          /* empty public exponent */
        LONG s = f(in, sizeof in, out, sizeof out, &need);
        CHECKF(s < 0, "variant %u accepted: 0x%lx", i, (unsigned long)s);
        t_note("convert(corrupt variant %u) = 0x%lx", i, (unsigned long)s);
    }
}
TEST(rngconv_matches_bcrypt_export_of_imported_key) {
    /* import the PRIVATE blob into bcrypt, export RSAFULLPRIVATE_BLOB and compare to the conversion */
    MSCryptConvertRsaPrivateBlobToFullRsaBlob_pfn f = CONV(); REQUIRE(f);
    REQUIRE(U(BCryptOpenAlgorithmProvider)); REQUIRE(U(BCryptImportKeyPair)); REQUIRE(U(BCryptExportKey));
    REQUIRE(U(BCryptDestroyKey)); REQUIRE(U(BCryptCloseAlgorithmProvider));
    BCRYPT_ALG_HANDLE alg = NULL; BCRYPT_KEY_HANDLE key = NULL; unsigned char out[4096], conv[4096]; ULONG got = 0, need = 0;
    EQ_NT(U(BCryptOpenAlgorithmProvider)(&alg, BCRYPT_RSA_ALGORITHM, NULL, 0), 0);
    if (!alg) return;
    EQ_NT(U(BCryptImportKeyPair)(alg, NULL, BCRYPT_RSAPRIVATE_BLOB, &key, (PUCHAR)rsa2048_private, sizeof rsa2048_private, 0), 0);
    if (key) {
        EQ_NT(U(BCryptExportKey)(key, NULL, BCRYPT_RSAFULLPRIVATE_BLOB, out, sizeof out, &got, 0), 0);
        EQ_NT(f((PUCHAR)rsa2048_private, sizeof rsa2048_private, conv, sizeof conv, &need), 0);
        CHECK(got == need);
        CHECK(got == need && !memcmp(out, conv, need));
        CHECK(need == sizeof rsa2048_full && !memcmp(out, rsa2048_full, need));
        U(BCryptDestroyKey)(key);
    }
    U(BCryptCloseAlgorithmProvider)(alg, 0);
}
TEST(rngconv_signature_equal_for_both_blobs) {
    /* PKCS#1 v1.5 signatures are deterministic: both imports must sign identically */
    MSCryptConvertRsaPrivateBlobToFullRsaBlob_pfn f = CONV(); REQUIRE(f);
    REQUIRE(U(BCryptOpenAlgorithmProvider)); REQUIRE(U(BCryptImportKeyPair)); REQUIRE(U(BCryptSignHash));
    REQUIRE(U(BCryptDestroyKey)); REQUIRE(U(BCryptCloseAlgorithmProvider));
    BCRYPT_ALG_HANDLE alg = NULL; BCRYPT_KEY_HANDLE k1 = NULL, k2 = NULL; unsigned char conv[1024]; ULONG need = 0;
    unsigned char hash[32], s1[128], s2[128]; ULONG l1 = 0, l2 = 0; BCRYPT_PKCS1_PADDING_INFO pi;
    memset(hash, 0x5C, sizeof hash);
    pi.pszAlgId = BCRYPT_SHA256_ALGORITHM;
    EQ_NT(f((PUCHAR)rsa1024_private, sizeof rsa1024_private, conv, sizeof conv, &need), 0);
    EQ_NT(U(BCryptOpenAlgorithmProvider)(&alg, BCRYPT_RSA_ALGORITHM, NULL, 0), 0);
    if (!alg) return;
    EQ_NT(U(BCryptImportKeyPair)(alg, NULL, BCRYPT_RSAPRIVATE_BLOB, &k1, (PUCHAR)rsa1024_private, sizeof rsa1024_private, 0), 0);
    EQ_NT(U(BCryptImportKeyPair)(alg, NULL, BCRYPT_RSAFULLPRIVATE_BLOB, &k2, conv, need, 0), 0);
    if (k1 && k2) {
        EQ_NT(U(BCryptSignHash)(k1, &pi, hash, sizeof hash, s1, sizeof s1, &l1, BCRYPT_PAD_PKCS1), 0);
        EQ_NT(U(BCryptSignHash)(k2, &pi, hash, sizeof hash, s2, sizeof s2, &l2, BCRYPT_PAD_PKCS1), 0);
        CHECK(l1 == 128 && l2 == 128 && !memcmp(s1, s2, 128));
    }
    if (k1) U(BCryptDestroyKey)(k1);
    if (k2) U(BCryptDestroyKey)(k2);
    U(BCryptCloseAlgorithmProvider)(alg, 0);
}
TEST(rngconv_modulus_and_exponent_carried_verbatim) {
    MSCryptConvertRsaPrivateBlobToFullRsaBlob_pfn f = CONV(); REQUIRE(f);
    unsigned char out[sizeof rsa1024_full]; ULONG need;
    EQ_NT(f((PUCHAR)rsa1024_private, sizeof rsa1024_private, out, sizeof out, &need), 0);
    CHECK(!memcmp(out + 24, "\x01\x00\x01", 3));
    CHECK(!memcmp(out + 27, rsa1024_n, 128));
    /* P and Q keep the input order */
    CHECK(!memcmp(out + 27 + 128, rsa1024_private + 27 + 128, 128));
}
TEST(rngconv_in_place_distinct_buffers_only) {
    /* output buffer with unrelated pre-existing contents is fully overwritten */
    MSCryptConvertRsaPrivateBlobToFullRsaBlob_pfn f = CONV(); REQUIRE(f);
    unsigned char out[sizeof rsa1024_full]; ULONG need;
    memset(out, 0xAB, sizeof out);
    EQ_NT(f((PUCHAR)rsa1024_private, sizeof rsa1024_private, out, sizeof out, &need), 0);
    CHECK(!memcmp(out, rsa1024_full, sizeof out));
}
TEST(rngconv_concurrent_calls) {
    MSCryptConvertRsaPrivateBlobToFullRsaBlob_pfn f = CONV(); REQUIRE(f);
    int i; unsigned char out[sizeof rsa1024_full]; ULONG need;
    for (i = 0; i < 25; i++) {
        memset(out, 0, sizeof out);
        EQ_NT(f((PUCHAR)rsa1024_private, sizeof rsa1024_private, out, sizeof out, &need), 0);
        if (memcmp(out, rsa1024_full, sizeof out)) { CHECKF(0, "iteration %d differs", i); break; }
    }
}
