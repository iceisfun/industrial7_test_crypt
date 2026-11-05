#include "mssfix.h"
#include "modules.h"
#include "fixture_data.h"

const BYTE *fx_cert_der(int which, DWORD *cb) {
    if (which == FX_A) { *cb = sizeof(FX_A_CERT); return FX_A_CERT; }
    *cb = sizeof(FX_B_CERT); return FX_B_CERT;
}
const BYTE *fx_sig_sha1_abc(DWORD *cb) { *cb = sizeof(FX_A_SIG_SHA1_ABC); return FX_A_SIG_SHA1_ABC; }

DWORD fx_keyblob(int which, int keyspec, BYTE *out, DWORD cap) {
    const BYTE *src = which == FX_A ? FX_A_KEYBLOB : FX_B_KEYBLOB;
    DWORD n = which == FX_A ? sizeof(FX_A_KEYBLOB) : sizeof(FX_B_KEYBLOB);
    if (n > cap) return 0;
    memcpy(out, src, n);
    DWORD alg = keyspec == 2 ? 0x2400 : 0xA400;
    memcpy(out + 4, &alg, 4);
    return n;
}
void fx_pvk_hdr(BYTE *out, DWORD magic, DWORD reserved, DWORD keytype, DWORD encrypt, DWORD saltlen, DWORD keylen) {
    DWORD h[6] = { magic, reserved, keytype, encrypt, saltlen, keylen };
    memcpy(out, h, 24);
}
DWORD fx_pvk(int which, int keyspec, DWORD encrypt, DWORD saltlen, BYTE *out, DWORD cap) {
    BYTE blob[2048];
    DWORD n = fx_keyblob(which, keyspec, blob, sizeof blob);
    if (!n || 24 + saltlen + n > cap) return 0;
    fx_pvk_hdr(out, 0xB0B5F11E, 0, keyspec, encrypt, saltlen, n);
    memset(out + 24, 0x5a, saltlen);
    memcpy(out + 24 + saltlen, blob, n);
    return 24 + saltlen + n;
}

/* ---- contexts ---- */
static int g_fxseq;
static int import_ok(HCRYPTPROV h, int which, int keyspec) {
    BYTE blob[2048]; DWORD n = fx_keyblob(which, keyspec, blob, sizeof blob);
    HCRYPTKEY k = 0;
    if (!U(CryptImportKey)(h, blob, n, 0, 0, &k)) return 0;
    U(CryptDestroyKey)(k);
    k = 0;
    if (!U(CryptGetUserKey)(h, keyspec, &k)) return 0;
    U(CryptDestroyKey)(k);
    return 1;
}
static int open_ctx(FX *f, int which, int keyspec, int withkey) {
    memset(f, 0, sizeof *f);
    f->which = which; f->keyspec = keyspec;
    HCRYPTPROV h = 0;
    if (U(CryptAcquireContextW)(&h, NULL, MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        if (!withkey || import_ok(h, which, keyspec)) { f->hProv = h; return 1; }
        U(CryptReleaseContext)(h, 0);
    }
    /* fallback: unique named container, removed by fx_close */
    _snwprintf(f->name, 63, L"cryptt_fx_%lu_%d", GetCurrentProcessId(), ++g_fxseq);
    U(CryptAcquireContextW)(&h, f->name, MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, CRYPT_DELETEKEYSET);
    h = 0;
    if (!U(CryptAcquireContextW)(&h, f->name, MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, CRYPT_NEWKEYSET)) return 0;
    f->persisted = 1;
    if (withkey && !import_ok(h, which, keyspec)) {
        U(CryptReleaseContext)(h, 0);
        U(CryptAcquireContextW)(&h, f->name, MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, CRYPT_DELETEKEYSET);
        f->persisted = 0;
        return 0;
    }
    f->hProv = h;
    return 1;
}
int fx_open(FX *f, int which, int keyspec) { return open_ctx(f, which, keyspec, 1); }
int fx_open_empty(FX *f) { return open_ctx(f, FX_A, 1, 0); }

int fx_cert_attach(FX *f) {
    DWORD cb; const BYTE *der = fx_cert_der(f->which, &cb);
    f->cert = U(CertCreateCertificateContext)(X509_ASN_ENCODING, der, cb);
    if (!f->cert) return 0;
    CERT_KEY_CONTEXT kc; memset(&kc, 0, sizeof kc);
    kc.cbSize = sizeof kc; kc.hCryptProv = f->hProv; kc.dwKeySpec = f->keyspec;
    if (!U(CertSetCertificateContextProperty)(f->cert, CERT_KEY_CONTEXT_PROP_ID, CERT_STORE_NO_CRYPT_RELEASE_FLAG, &kc)) {
        U(CertFreeCertificateContext)(f->cert); f->cert = NULL; return 0;
    }
    return 1;
}
void fx_close(FX *f) {
    if (f->cert) { U(CertFreeCertificateContext)(f->cert); f->cert = NULL; }
    if (f->hProv) { U(CryptReleaseContext)(f->hProv, 0); f->hProv = 0; }
    if (f->persisted) {
        HCRYPTPROV h = 0;
        U(CryptAcquireContextW)(&h, f->name, MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, CRYPT_DELETEKEYSET);
        f->persisted = 0;
    }
}

/* ---- PE image ---- */
void fx_pe_image(BYTE *b) {
    memset(b, 0, FX_PE_SIZE);
    IMAGE_DOS_HEADER *d = (IMAGE_DOS_HEADER *)b;
    d->e_magic = IMAGE_DOS_SIGNATURE; d->e_lfanew = 0x40;
    IMAGE_NT_HEADERS64 *nt = (IMAGE_NT_HEADERS64 *)(b + 0x40);
    nt->Signature = IMAGE_NT_SIGNATURE;
    nt->FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
    nt->FileHeader.NumberOfSections = 1;
    nt->FileHeader.TimeDateStamp = 0x5F000000;
    nt->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
    nt->FileHeader.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE;
    IMAGE_OPTIONAL_HEADER64 *o = &nt->OptionalHeader;
    o->Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    o->MajorLinkerVersion = 14;
    o->SizeOfCode = 0x200; o->AddressOfEntryPoint = 0x1000; o->BaseOfCode = 0x1000;
    o->ImageBase = 0x140000000ull; o->SectionAlignment = 0x1000; o->FileAlignment = 0x200;
    o->MajorOperatingSystemVersion = 6; o->MajorSubsystemVersion = 6;
    o->SizeOfImage = 0x2000; o->SizeOfHeaders = 0x200;
    o->Subsystem = IMAGE_SUBSYSTEM_WINDOWS_CUI;
    o->SizeOfStackReserve = 0x100000; o->SizeOfStackCommit = 0x1000;
    o->SizeOfHeapReserve = 0x100000; o->SizeOfHeapCommit = 0x1000;
    o->NumberOfRvaAndSizes = 16;
    IMAGE_SECTION_HEADER *s = (IMAGE_SECTION_HEADER *)((BYTE *)o + sizeof *o);
    memcpy(s->Name, ".text", 5);
    s->Misc.VirtualSize = 3; s->VirtualAddress = 0x1000; s->SizeOfRawData = 0x200; s->PointerToRawData = 0x200;
    s->Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
    b[0x200] = 0x31; b[0x201] = 0xC0; b[0x202] = 0xC3;
}
int fx_write_file(const char *path, const void *p, DWORD n) {
    HANDLE h = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return 0;
    DWORD w = 0; BOOL ok = WriteFile(h, p, n, &w, NULL);
    CloseHandle(h);
    return ok && w == n;
}
BYTE *fx_read_file(const char *path, DWORD *n) {
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return NULL;
    DWORD sz = GetFileSize(h, NULL), r = 0;
    BYTE *p = malloc(sz ? sz : 1);
    if (!p || !ReadFile(h, p, sz, &r, NULL) || r != sz) { free(p); CloseHandle(h); return NULL; }
    CloseHandle(h); *n = sz; return p;
}
LPWSTR fx_w(const char *s) {
    int n = MultiByteToWideChar(CP_ACP, 0, s, -1, NULL, 0);
    LPWSTR w = malloc(n * sizeof(WCHAR));
    MultiByteToWideChar(CP_ACP, 0, s, -1, w, n);
    return w;
}
int fx_pe_secdir(const BYTE *b, DWORD n, DWORD *off, DWORD *size) {
    if (n < 0x200 || b[0] != 'M') return 0;
    const IMAGE_NT_HEADERS64 *nt = (const IMAGE_NT_HEADERS64 *)(b + ((const IMAGE_DOS_HEADER *)b)->e_lfanew);
    *off = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress;
    *size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size;
    return 1;
}
void fx_pe_new(char *path, size_t cap, const char *leaf) {
    BYTE img[FX_PE_SIZE];
    t_tmpfile(path, cap, leaf);
    fx_pe_image(img);
    fx_write_file(path, img, sizeof img);
}
int fx_pe_authhash(const BYTE *b, DWORD n, LPCWSTR alg, BYTE *out, DWORD *cbout) {
    typeof(&BCryptOpenAlgorithmProvider) pO = U(BCryptOpenAlgorithmProvider);
    typeof(&BCryptCloseAlgorithmProvider) pC = U(BCryptCloseAlgorithmProvider);
    typeof(&BCryptCreateHash) pCH = U(BCryptCreateHash);
    typeof(&BCryptHashData) pHD = U(BCryptHashData);
    typeof(&BCryptFinishHash) pF = U(BCryptFinishHash);
    typeof(&BCryptDestroyHash) pD = U(BCryptDestroyHash);
    typeof(&BCryptGetProperty) pG = U(BCryptGetProperty);
    if (!pO || !pCH || !pHD || !pF || !pD || !pG || !pC) return 0;
    DWORD nt = ((const IMAGE_DOS_HEADER *)b)->e_lfanew;
    DWORD chk = nt + 4 + 20 + 64;
    DWORD sec = nt + 4 + 20 + 0x70 + 8 * IMAGE_DIRECTORY_ENTRY_SECURITY;
    DWORD so, ss;
    if (!fx_pe_secdir(b, n, &so, &ss)) return 0;
    DWORD end = so ? so : n;   /* signed: image ends where the certificate table starts */
    BCRYPT_ALG_HANDLE ha = NULL; BCRYPT_HASH_HANDLE hh = NULL; int ok = 0; PUCHAR obj = NULL;
    DWORD got = 0, len = 0;
    if (pO(&ha, alg, NULL, 0) != 0) return 0;
    if (pG(ha, BCRYPT_HASH_LENGTH, (PUCHAR)&len, 4, &got, 0) != 0) goto out;
    DWORD olen = 0;
    if (pG(ha, BCRYPT_OBJECT_LENGTH, (PUCHAR)&olen, 4, &got, 0) != 0) goto out;
    obj = malloc(olen ? olen : 1);
    if (pCH(ha, &hh, obj, olen, NULL, 0, 0) != 0) goto out;
    if (pHD(hh, (PUCHAR)b, chk, 0) || pHD(hh, (PUCHAR)b + chk + 4, sec - chk - 4, 0) ||
        pHD(hh, (PUCHAR)b + sec + 8, end - sec - 8, 0) || pF(hh, out, len, 0)) goto out;
    *cbout = len; ok = 1;
out:
    if (hh) pD(hh);
    pC(ha, 0);
    free(obj);
    return ok;
}

/* ---- signing / verification ---- */
HRESULT fx_sign(FX *f, const char *path, DWORD algid, DWORD flags, SG_CTX **ctx) {
    LPWSTR wp = fx_w(path);
    DWORD idx = 0;
    SG_FILE fi = { sizeof fi, wp, NULL };
    SG_SUBJECT sub = { sizeof sub, &idx, SG_SUBJECT_FILE, &fi };
    SG_CERTSTORE cs = { sizeof cs, f->cert, 0, NULL };
    SG_CERT cert = { sizeof cert, SG_CERT_STORE, &cs, NULL };
    SG_SIGINFO si = { sizeof si, algid, SG_NO_ATTR, NULL, NULL, NULL };
    SignerSignEx_pfn fn = UN(SignerSignEx);
    HRESULT hr = fn(flags, &sub, &cert, &si, NULL, NULL, NULL, NULL, ctx);
    free(wp);
    return hr;
}
HCRYPTMSG fx_query_pe(const char *path, HCERTSTORE *store) {
    LPWSTR wp = fx_w(path);
    DWORD enc = 0, ct = 0, fmt = 0; HCERTSTORE st = NULL; HCRYPTMSG msg = NULL;
    BOOL ok = U(CryptQueryObject)(CERT_QUERY_OBJECT_FILE, wp, CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                                  CERT_QUERY_FORMAT_FLAG_BINARY, 0, &enc, &ct, &fmt, &st, &msg, NULL);
    free(wp);
    if (!ok) return NULL;
    if (store) *store = st; else if (st) U(CertCloseStore)(st, 0);
    return msg;
}
DWORD fx_signer_count(HCRYPTMSG m) {
    DWORD n = 0, cb = sizeof n;
    if (!U(CryptMsgGetParam)(m, CMSG_SIGNER_COUNT_PARAM, 0, &n, &cb)) return 0xFFFFFFFF;
    return n;
}
char *fx_signer_digest_oid(HCRYPTMSG m) {
    DWORD cb = 0;
    if (!U(CryptMsgGetParam)(m, CMSG_SIGNER_INFO_PARAM, 0, NULL, &cb)) return NULL;
    CMSG_SIGNER_INFO *si = malloc(cb);
    if (!U(CryptMsgGetParam)(m, CMSG_SIGNER_INFO_PARAM, 0, si, &cb)) { free(si); return NULL; }
    char *r = _strdup(si->HashAlgorithm.pszObjId ? si->HashAlgorithm.pszObjId : "");
    free(si);
    return r;
}
HRESULT fx_verify_trust(const char *path) {
    LPWSTR wp = fx_w(path);
    WINTRUST_FILE_INFO fi; memset(&fi, 0, sizeof fi);
    fi.cbStruct = sizeof fi; fi.pcwszFilePath = wp;
    WINTRUST_DATA wd; memset(&wd, 0, sizeof wd);
    wd.cbStruct = sizeof wd; wd.dwUIChoice = WTD_UI_NONE; wd.fdwRevocationChecks = WTD_REVOKE_NONE;
    wd.dwUnionChoice = WTD_CHOICE_FILE; wd.pFile = &fi; wd.dwStateAction = WTD_STATEACTION_VERIFY;
    wd.dwProvFlags = WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL;
    GUID act = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    HRESULT hr = UIN("wintrust.dll", WinVerifyTrust)(INVALID_HANDLE_VALUE, &act, &wd);
    wd.dwStateAction = WTD_STATEACTION_CLOSE;
    UIN("wintrust.dll", WinVerifyTrust)(INVALID_HANDLE_VALUE, &act, &wd);
    free(wp);
    return hr;
}
