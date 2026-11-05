/* SignerSign / SignerSignEx / SignerSignEx2 / SignerSignEx3 argument validation and the failure ladder that
 * precedes any file access, SignerFreeSignerContext and SignError. All expectations come from the decompiled
 * validation helpers (CheckSigncodeParam, CheckSigncodeSubjectInfo) and SignerSignEx3_private.
 * Return values are HRESULTs: HRESULT_FROM_WIN32 for Win32 errors, CRYPT_E_* / NTE_* passed through. */
#include "mssfix.h"

typedef struct {
    DWORD idx;
    WCHAR file[MAX_PATH];
    SG_FILE fi;
    SG_SUBJECT sub;
    GUID guid; BYTE blobdata[16];
    SG_BLOB bi;
    SG_SPCCHAIN spc;
    SG_CERTSTORE cs;
    SG_CERT cert;
    SG_AUTHCODE ac;
    SG_SIGINFO si;
    SG_PROV prov;
    PCCERT_CONTEXT x;
} ARGS;

static void args_init(ARGS *a) {
    memset(a, 0, sizeof *a);
    _snwprintf(a->file, MAX_PATH - 1, L"C:\\cryptt_nonexistent_dir_%lu\\target.exe", GetCurrentProcessId());
    a->fi.cbSize = sizeof a->fi; a->fi.pwszFileName = a->file;
    a->sub.cbSize = sizeof a->sub; a->sub.pdwIndex = &a->idx; a->sub.dwSubjectChoice = SG_SUBJECT_FILE; a->sub.pInfo = &a->fi;
    a->guid.Data1 = 0x000102AA; a->guid.Data4[0] = 0xC0; a->guid.Data4[7] = 0x46;
    a->bi.cbSize = sizeof a->bi; a->bi.pGuidSubject = &a->guid; a->bi.cbBlob = 16; a->bi.pbBlob = a->blobdata;
    a->bi.pwszDisplayName = L"blob";
    a->spc.cbSize = sizeof a->spc; a->spc.pwszSpcFile = L"cryptt_none.spc";
    a->cs.cbSize = sizeof a->cs;
    a->cert.cbSize = sizeof a->cert; a->cert.dwCertChoice = SG_CERT_SPC_FILE; a->cert.pInfo = (void *)L"cryptt_none.spc";
    a->ac.cbSize = sizeof a->ac; a->ac.fCommercial = 1; a->ac.pwszName = L"name"; a->ac.pwszInfo = L"http://127.0.0.1/";
    a->si.cbSize = sizeof a->si; a->si.algId = CALG_SHA1; a->si.dwAttrChoice = SG_NO_ATTR;
    a->prov.cbSize = sizeof a->prov; a->prov.dwProviderType = PROV_RSA_AES; a->prov.dwKeySpec = 1;
    a->prov.dwPvkChoice = SG_PVK_FILE; a->prov.pInfo = (void *)L"C:\\cryptt_nonexistent_dir\\none.pvk";
}
static void args_cert_store(ARGS *a) {
    DWORD cb; const BYTE *der = fx_cert_der(FX_A, &cb);
    a->x = U(CertCreateCertificateContext)(X509_ASN_ENCODING, der, cb);
    a->cs.pSigningCert = a->x;
    a->cert.dwCertChoice = SG_CERT_STORE; a->cert.pInfo = &a->cs;
}
static void args_free(ARGS *a) { if (a->x) U(CertFreeCertificateContext)(a->x); a->x = NULL; }

/* variant 0 SignerSign, 1 SignerSignEx, 2 SignerSignEx2, 3 SignerSignEx3 */
static const char *vname[] = { "SignerSign", "SignerSignEx", "SignerSignEx2", "SignerSignEx3" };
static HRESULT call(int v, DWORD flags, SG_SUBJECT *s, SG_CERT *c, SG_SIGINFO *si, SG_PROV *p, PCWSTR url, SG_CTX **ctx) {
    switch (v) {
    case 0: return UN(SignerSign)(s, c, si, p, url, NULL, NULL);
    case 1: return UN(SignerSignEx)(flags, s, c, si, p, url, NULL, NULL, ctx);
    case 2: return UN(SignerSignEx2)(flags, s, c, si, p, 0, NULL, url, NULL, NULL, ctx, NULL, NULL);
    default: return UN(SignerSignEx3)(flags, s, c, si, p, 0, NULL, url, NULL, NULL, ctx, NULL, NULL, NULL);
    }
}
#define ALLV for (int v = 0; v < 4; v++)
#define NEED_SIGN() do { if (!UN(SignerSign) || !UN(SignerSignEx) || !UN(SignerSignEx2) || !UN(SignerSignEx3)) { t_skip("missing signer exports"); return; } \
    if (t_is_wine()) { t_skip("stubs under Wine"); return; } } while (0)
#define HR(x) ((DWORD)(x))

TEST(mssigner_args_valid_structs_reach_provider_stage) {
    NEED_SIGN();
    ALLV {
        ARGS a; args_init(&a);
        HRESULT hr = call(v, 0, &a.sub, &a.cert, &a.si, NULL, NULL, NULL);
        CHECKF(HR(hr) == HR_NO_PROVIDER, "%s: 0x%08lx", vname[v], HR(hr));
    }
}
TEST(mssigner_args_null_pointers) {
    NEED_SIGN();
    ALLV {
        ARGS a; args_init(&a);
        HRESULT hr;
        hr = call(v, 0, NULL, &a.cert, &a.si, NULL, NULL, NULL);
        CHECKF(HR(hr) == HR_INVALIDARG, "%s subject NULL: 0x%08lx", vname[v], HR(hr));
        hr = call(v, 0, &a.sub, NULL, &a.si, NULL, NULL, NULL);
        CHECKF(HR(hr) == HR_INVALIDARG, "%s cert NULL: 0x%08lx", vname[v], HR(hr));
        hr = call(v, 0, &a.sub, &a.cert, NULL, NULL, NULL, NULL);
        CHECKF(HR(hr) == HR_INVALIDARG, "%s signature NULL: 0x%08lx", vname[v], HR(hr));
        hr = call(v, 0, NULL, NULL, NULL, NULL, NULL, NULL);
        CHECKF(HR(hr) == HR_INVALIDARG, "%s all NULL: 0x%08lx", vname[v], HR(hr));
    }
}

/* table of single-field mutations that must be rejected with E_INVALIDARG */
enum { M_SUB_SIZE, M_SUB_IDXNULL, M_SUB_IDXNZ, M_SUB_CHOICE0, M_SUB_CHOICE3, M_SUB_CHOICEBIG, M_SUB_INFONULL,
       M_FI_SIZE, M_FI_NAMENULL, M_BI_INFONULL, M_BI_SIZE, M_BI_GUIDNULL, M_BI_CB0, M_BI_PBNULL,
       M_SI_SIZE, M_SI_ATTR2, M_SI_ATTR1_NULL, M_SI_ATTR1_ACSIZE, M_SI_ATTRBIG,
       M_C_SIZE, M_C_CHOICE0, M_C_CHOICE4, M_C_SPCFILE_NULL,
       M_C_STORE_NULL, M_C_STORE_SIZE, M_C_STORE_CERTNULL,
       M_C_CHAIN_NULL, M_C_CHAIN_SIZE_SMALL, M_C_CHAIN_SIZE_BIG, M_C_CHAIN_FILENULL,
       M_P_SIZE, M_P_CHOICE0, M_P_CHOICE3, M_P_PTRNULL, M_COUNT };
static const char *mname[] = {
    "subject cbSize 0x1f", "pdwIndex NULL", "*pdwIndex != 0", "subject choice 0", "subject choice 3", "subject choice 0xffffffff", "subject info NULL",
    "file info cbSize 0x17", "file name NULL", "blob info NULL", "blob info cbSize 0x27", "blob guid NULL", "blob cb 0", "blob pb NULL",
    "siginfo cbSize 0x27", "attr choice 2", "attr choice 1 w/o authcode", "authcode cbSize 0x1f", "attr choice ffffffff",
    "cert cbSize 0x17", "cert choice 0", "cert choice 4", "spc file NULL",
    "store info NULL", "store info cbSize 0x1f", "store info cert NULL",
    "chain info NULL", "chain cbSize 0x1f", "chain cbSize 0x21", "chain file NULL",
    "provider cbSize 0x27", "pvk choice 0", "pvk choice 3", "pvk pointer NULL" };

static void apply(int m, ARGS *a, SG_SUBJECT **s, SG_CERT **c, SG_SIGINFO **si, SG_PROV **p) {
    *p = NULL;
    switch (m) {
    case M_SUB_SIZE: a->sub.cbSize = 0x1f; break;
    case M_SUB_IDXNULL: a->sub.pdwIndex = NULL; break;
    case M_SUB_IDXNZ: a->idx = 1; break;
    case M_SUB_CHOICE0: a->sub.dwSubjectChoice = 0; break;
    case M_SUB_CHOICE3: a->sub.dwSubjectChoice = 3; break;
    case M_SUB_CHOICEBIG: a->sub.dwSubjectChoice = 0xFFFFFFFF; break;
    case M_SUB_INFONULL: a->sub.pInfo = NULL; break;
    case M_FI_SIZE: a->fi.cbSize = 0x17; break;
    case M_FI_NAMENULL: a->fi.pwszFileName = NULL; break;
    case M_BI_INFONULL: a->sub.dwSubjectChoice = SG_SUBJECT_BLOB; a->sub.pInfo = NULL; break;
    case M_BI_SIZE: a->sub.dwSubjectChoice = SG_SUBJECT_BLOB; a->sub.pInfo = &a->bi; a->bi.cbSize = 0x27; break;
    case M_BI_GUIDNULL: a->sub.dwSubjectChoice = SG_SUBJECT_BLOB; a->sub.pInfo = &a->bi; a->bi.pGuidSubject = NULL; break;
    case M_BI_CB0: a->sub.dwSubjectChoice = SG_SUBJECT_BLOB; a->sub.pInfo = &a->bi; a->bi.cbBlob = 0; break;
    case M_BI_PBNULL: a->sub.dwSubjectChoice = SG_SUBJECT_BLOB; a->sub.pInfo = &a->bi; a->bi.pbBlob = NULL; break;
    case M_SI_SIZE: a->si.cbSize = 0x27; break;
    case M_SI_ATTR2: a->si.dwAttrChoice = 2; break;
    case M_SI_ATTR1_NULL: a->si.dwAttrChoice = SG_AUTHCODE_ATTR; a->si.pAttrAuthcode = NULL; break;
    case M_SI_ATTR1_ACSIZE: a->si.dwAttrChoice = SG_AUTHCODE_ATTR; a->si.pAttrAuthcode = &a->ac; a->ac.cbSize = 0x1f; break;
    case M_SI_ATTRBIG: a->si.dwAttrChoice = 0xFFFFFFFF; break;
    case M_C_SIZE: a->cert.cbSize = 0x17; break;
    case M_C_CHOICE0: a->cert.dwCertChoice = 0; break;
    case M_C_CHOICE4: a->cert.dwCertChoice = 4; break;
    case M_C_SPCFILE_NULL: a->cert.pInfo = NULL; break;
    case M_C_STORE_NULL: a->cert.dwCertChoice = SG_CERT_STORE; a->cert.pInfo = NULL; break;
    case M_C_STORE_SIZE: args_cert_store(a); a->cs.cbSize = 0x1f; break;
    case M_C_STORE_CERTNULL: a->cert.dwCertChoice = SG_CERT_STORE; a->cert.pInfo = &a->cs; a->cs.pSigningCert = NULL; break;
    case M_C_CHAIN_NULL: a->cert.dwCertChoice = SG_CERT_SPC_CHAIN; a->cert.pInfo = NULL; break;
    case M_C_CHAIN_SIZE_SMALL: a->cert.dwCertChoice = SG_CERT_SPC_CHAIN; a->cert.pInfo = &a->spc; a->spc.cbSize = 0x1f; break;
    case M_C_CHAIN_SIZE_BIG: a->cert.dwCertChoice = SG_CERT_SPC_CHAIN; a->cert.pInfo = &a->spc; a->spc.cbSize = 0x21; break;
    case M_C_CHAIN_FILENULL: a->cert.dwCertChoice = SG_CERT_SPC_CHAIN; a->cert.pInfo = &a->spc; a->spc.pwszSpcFile = NULL; break;
    case M_P_SIZE: a->prov.cbSize = 0x27; *p = &a->prov; break;
    case M_P_CHOICE0: a->prov.dwPvkChoice = 0; *p = &a->prov; break;
    case M_P_CHOICE3: a->prov.dwPvkChoice = 3; *p = &a->prov; break;
    case M_P_PTRNULL: a->prov.pInfo = NULL; *p = &a->prov; break;
    }
    *s = &a->sub; *c = &a->cert; *si = &a->si;
}
TEST(mssigner_args_invalid_field_table) {
    NEED_SIGN();
    for (int m = 0; m < M_COUNT; m++) {
        for (int v = 0; v < 4; v++) {
            ARGS a; args_init(&a);
            SG_SUBJECT *s; SG_CERT *c; SG_SIGINFO *si; SG_PROV *p;
            apply(m, &a, &s, &c, &si, &p);
            HRESULT hr = call(v, 0, s, c, si, p, NULL, NULL);
            CHECKF(HR(hr) == HR_INVALIDARG, "[%s] %s: 0x%08lx", mname[m], vname[v], HR(hr));
            args_free(&a);
        }
    }
}
TEST(mssigner_args_oversized_structs_accepted) {
    /* cbSize is a minimum: larger structures pass validation (the extra bytes are ignored) */
    NEED_SIGN();
    ALLV {
        ARGS a; args_init(&a);
        a.sub.cbSize = 0x100; a.fi.cbSize = 0x100; a.cert.cbSize = 0x100; a.si.cbSize = 0x100;
        HRESULT hr = call(v, 0, &a.sub, &a.cert, &a.si, NULL, NULL, NULL);
        CHECKF(HR(hr) == HR_NO_PROVIDER, "%s: 0x%08lx", vname[v], HR(hr));
    }
}
TEST(mssigner_args_minimal_struct_sizes_accepted) {
    NEED_SIGN();
    ALLV {
        ARGS a; args_init(&a);
        a.sub.cbSize = 0x20; a.fi.cbSize = 0x18; a.cert.cbSize = 0x18; a.si.cbSize = 0x28;
        HRESULT hr = call(v, 0, &a.sub, &a.cert, &a.si, NULL, NULL, NULL);
        CHECKF(HR(hr) == HR_NO_PROVIDER, "%s: 0x%08lx", vname[v], HR(hr));
    }
}
TEST(mssigner_args_blob_subject_valid) {
    NEED_SIGN();
    ALLV {
        ARGS a; args_init(&a);
        a.sub.dwSubjectChoice = SG_SUBJECT_BLOB; a.sub.pInfo = &a.bi;
        HRESULT hr = call(v, 0, &a.sub, &a.cert, &a.si, NULL, NULL, NULL);
        CHECKF(HR(hr) == HR_NO_PROVIDER, "%s: 0x%08lx", vname[v], HR(hr));
    }
}
TEST(mssigner_args_authcode_attr_valid) {
    NEED_SIGN();
    ALLV {
        ARGS a; args_init(&a);
        a.si.dwAttrChoice = SG_AUTHCODE_ATTR; a.si.pAttrAuthcode = &a.ac;
        HRESULT hr = call(v, 0, &a.sub, &a.cert, &a.si, NULL, NULL, NULL);
        CHECKF(HR(hr) == HR_NO_PROVIDER, "%s: 0x%08lx", vname[v], HR(hr));
        a.ac.cbSize = 0x20; a.ac.fCommercial = 0; a.ac.fIndividual = 1; a.ac.pwszName = NULL; a.ac.pwszInfo = NULL;
        hr = call(v, 0, &a.sub, &a.cert, &a.si, NULL, NULL, NULL);
        CHECKF(HR(hr) == HR_NO_PROVIDER, "%s individual: 0x%08lx", vname[v], HR(hr));
    }
}
TEST(mssigner_args_cert_choices_without_key) {
    /* Without a usable private key / provider the signer reports CRYPT_E_NO_PROVIDER for every cert choice */
    NEED_SIGN();
    ALLV {
        ARGS a; args_init(&a);
        a.cert.dwCertChoice = SG_CERT_SPC_CHAIN; a.cert.pInfo = &a.spc;
        HRESULT hr = call(v, 0, &a.sub, &a.cert, &a.si, NULL, NULL, NULL);
        CHECKF(HR(hr) == HR_NO_PROVIDER, "%s chain: 0x%08lx", vname[v], HR(hr));
        ARGS b; args_init(&b); args_cert_store(&b);
        CHECK(b.x != NULL);
        hr = call(v, 0, &b.sub, &b.cert, &b.si, NULL, NULL, NULL);
        CHECKF(HR(hr) == HR_NO_PROVIDER, "%s store (cert without key): 0x%08lx", vname[v], HR(hr));
        args_free(&b);
    }
}
TEST(mssigner_args_provider_failures_map_to_no_provider) {
    NEED_SIGN();
    ALLV {
        ARGS a; args_init(&a);
        /* missing PVK file */
        HRESULT hr = call(v, 0, &a.sub, &a.cert, &a.si, &a.prov, NULL, NULL);
        CHECKF(HR(hr) == HR_NO_PROVIDER, "%s missing pvk: 0x%08lx", vname[v], HR(hr));
        /* nonexistent key container */
        WCHAR cont[64]; _snwprintf(cont, 63, L"cryptt_nosuch_%lu", GetCurrentProcessId());
        a.prov.dwPvkChoice = SG_PVK_CONTAINER; a.prov.pInfo = cont;
        hr = call(v, 0, &a.sub, &a.cert, &a.si, &a.prov, NULL, NULL);
        CHECKF(HR(hr) == HR_NO_PROVIDER, "%s missing container: 0x%08lx", vname[v], HR(hr));
        /* empty PVK file */
        char p[MAX_PATH]; t_tmpfile(p, sizeof p, "emptyprov.pvk");
        fx_write_file(p, "", 0);
        LPWSTR wp = fx_w(p);
        a.prov.dwPvkChoice = SG_PVK_FILE; a.prov.pInfo = wp;
        hr = call(v, 0, &a.sub, &a.cert, &a.si, &a.prov, NULL, NULL);
        CHECKF(HR(hr) == HR_NO_PROVIDER, "%s empty pvk: 0x%08lx", vname[v], HR(hr));
        free(wp); DeleteFileA(p);
    }
}
TEST(mssigner_args_signer_context_out_pointer) {
    NEED_SIGN();
    ARGS a; args_init(&a);
    SG_CTX *sentinel = (SG_CTX *)(ULONG_PTR)0x1000, *ctx;
    /* rejected arguments leave the out pointer alone ... */
    ctx = sentinel;
    HRESULT hr = UN(SignerSignEx)(0, NULL, &a.cert, &a.si, NULL, NULL, NULL, NULL, &ctx);
    EXPECT_EQ(HR(hr), HR_INVALIDARG);
    CHECK(ctx == sentinel);
    ctx = sentinel;
    hr = UN(SignerSignEx3)(0, &a.sub, &a.cert, NULL, NULL, 0, NULL, NULL, NULL, NULL, &ctx, NULL, NULL, NULL);
    EXPECT_EQ(HR(hr), HR_INVALIDARG);
    CHECK(ctx == sentinel);
    /* ... accepted arguments that fail later clear it */
    ctx = sentinel;
    hr = UN(SignerSignEx)(0, &a.sub, &a.cert, &a.si, NULL, NULL, NULL, NULL, &ctx);
    EXPECT_EQ(HR(hr), HR_NO_PROVIDER);
    CHECK(ctx == NULL);
    ctx = sentinel;
    hr = UN(SignerSignEx3)(0, &a.sub, &a.cert, &a.si, NULL, 0, NULL, NULL, NULL, NULL, &ctx, NULL, NULL, NULL);
    EXPECT_EQ(HR(hr), HR_NO_PROVIDER);
    CHECK(ctx == NULL);
}

/* ---- flag combinations rejected up front ---- */
TEST(mssigner_args_flag_combinations) {
    NEED_SIGN();
    ARGS a; args_init(&a);
    HRESULT hr;
    /* SignerSignEx always passes timestamp flags = 1: a flag value 0x1000 together with it is invalid */
    hr = UN(SignerSignEx)(0x1000, &a.sub, &a.cert, &a.si, NULL, NULL, NULL, NULL, NULL);
    EXPECT_EQ(HR(hr), HR_INVALIDARG);
    hr = UN(SignerSignEx2)(0x1000, &a.sub, &a.cert, &a.si, NULL, 1, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    EXPECT_EQ(HR(hr), HR_INVALIDARG);
    hr = UN(SignerSignEx3)(0x1000, &a.sub, &a.cert, &a.si, NULL, 1, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    EXPECT_EQ(HR(hr), HR_INVALIDARG);
    /* a time stamp URL conflicts with flag 0x200 */
    hr = UN(SignerSignEx3)(0x200, &a.sub, &a.cert, &a.si, NULL, 0, NULL, L"http://127.0.0.1:1/", NULL, NULL, NULL, NULL, NULL, NULL);
    EXPECT_EQ(HR(hr), HR_INVALIDARG);
    /* 0x400 / 0x4000 need a digest sign info with exactly the matching callback pointer */
    hr = UN(SignerSignEx3)(0x400, &a.sub, &a.cert, &a.si, NULL, 0, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    EXPECT_EQ(HR(hr), HR_INVALIDARG);
    hr = UN(SignerSignEx3)(0x4000, &a.sub, &a.cert, &a.si, NULL, 0, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    EXPECT_EQ(HR(hr), HR_INVALIDARG);
    /* without 0x4000 a NULL certificate is rejected ... */
    hr = UN(SignerSignEx3)(0, &a.sub, NULL, &a.si, NULL, 0, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    EXPECT_EQ(HR(hr), HR_INVALIDARG);
}
TEST(mssigner_args_reserved_parameters_must_be_null) {
    NEED_SIGN();
    ARGS a; args_init(&a);
    HRESULT hr = UN(SignerSignEx3)(0, &a.sub, &a.cert, &a.si, NULL, 0, NULL, NULL, NULL, NULL, NULL, NULL, NULL, (PVOID)1);
    EXPECT_EQ(HR(hr), HR_INVALIDARG);
    hr = UN(SignerSignEx2)(0, &a.sub, &a.cert, &a.si, NULL, 0, NULL, NULL, NULL, NULL, NULL, NULL, (PVOID)1);
    EXPECT_EQ(HR(hr), HR_INVALIDARG);
    hr = UN(SignerSignEx3)(0, &a.sub, &a.cert, &a.si, NULL, 0, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    EXPECT_EQ(HR(hr), HR_NO_PROVIDER);
}

/* ---- SignerFreeSignerContext / SignError ---- */
TEST(mssigner_free_signer_context_null) {
    SignerFreeSignerContext_pfn fn = UN(SignerFreeSignerContext); REQUIRE(fn);
    SET_ERR(0x1234);
    EXPECT_EQ(fn(NULL), 0);
}
TEST(mssigner_signerror_maps_last_error) {
    SignError_pfn fn = UN(SignError); REQUIRE(fn);
    static const struct { DWORD in, out; } tab[] = {
        { 0, 0x8000FFFF },                   /* no error recorded -> E_FAIL */
        { 1, 0x80070001 }, { 2, 0x80070002 }, { 5, 0x80070005 }, { 87, 0x80070057 }, { 183, 0x800700B7 },
        { 0x7FFF, 0x80077FFF }, { 0xFFFF, 0x8007FFFF },
        { 0x10000, 0x8000FFFF },            /* positive and >= 0x10000 -> E_FAIL */
        { 0x12345, 0x8000FFFF }, { 0x7FFFFFFF, 0x8000FFFF },
        { 0x80000000, 0x80000000 },          /* already negative: unchanged */
        { 0x80090016, 0x80090016 }, { 0x8009200B, 0x8009200B }, { 0x800B0100, 0x800B0100 },
        { 0x80070057, 0x80070057 }, { 0xC0000005, 0xC0000005 }, { 0xFFFFFFFF, 0xFFFFFFFF },
    };
    for (size_t i = 0; i < sizeof tab / sizeof tab[0]; i++) {
        SET_ERR(tab[i].in);
        DWORD r = fn();
        CHECKF(r == tab[i].out, "SignError(%08lx) = %08lx want %08lx", tab[i].in, r, tab[i].out);
    }
}
TEST(mssigner_signerror_preserves_last_error) {
    SignError_pfn fn = UN(SignError); REQUIRE(fn);
    SET_ERR(1234);
    fn();
    EXPECT_ERR(1234);
}
TEST(mssigner_signerror_never_success) {
    SignError_pfn fn = UN(SignError); REQUIRE(fn);
    static const DWORD in[] = { 0, 1, 0xFFFE, 0x10001, 0x20000, 0x7FFFFFFE, 0x80000001, 0xFFFFFFFE };
    for (size_t i = 0; i < sizeof in / sizeof in[0]; i++) {
        SET_ERR(in[i]);
        DWORD r = fn();
        CHECKF((LONG)r < 0, "SignError(%08lx) = %08lx is not a failure HRESULT", in[i], r);
    }
}
