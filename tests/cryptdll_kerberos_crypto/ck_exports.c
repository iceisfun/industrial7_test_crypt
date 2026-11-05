/* cryptdll.dll export surface: names, ordinals, forwarders. */
#include "ck.h"

static const struct { const char *name; unsigned ord; int fwd; } ck_exp[] = {
    {"CDBuildIntegrityVect", 1, 0}, {"CDBuildVect", 2, 0}, {"CDFindCommonCSystem", 3, 0},
    {"CDFindCommonCSystemWithKey", 4, 0}, {"CDGenerateRandomBits", 5, 0}, {"CDGetIntegrityVect", 6, 0},
    {"CDLocateCSystem", 7, 0}, {"CDLocateCheckSum", 8, 0}, {"CDLocateRng", 9, 0},
    {"CDRegisterCSystem", 10, 0}, {"CDRegisterCheckSum", 11, 0}, {"CDRegisterRng", 12, 0},
    {"HMACwithSHA", 13, 0}, {"KRBFXCF2", 14, 0}, {"MD5Final", 15, 1}, {"MD5Init", 16, 1},
    {"MD5Update", 17, 1}, {"PBKDF2", 18, 0}, {"aesCTSDecryptMsg", 19, 0}, {"aesCTSEncryptMsg", 20, 0},
};
#define CK_NEXP (sizeof ck_exp / sizeof ck_exp[0])

TEST(ckexp_module_loads) {
    HMODULE h = t_module(CK_DLL);
    CHECK(h != NULL);
    if (!h) return;
    char path[MAX_PATH] = {0};
    CHECK(GetModuleFileNameA(h, path, sizeof path) > 0);
    CHECK(strstr(path, "cryptdll") != NULL || strstr(path, "CRYPTDLL") != NULL);
}

TEST(ckexp_all_names_resolve) {
    CK_NOWINE();
    HMODULE h = t_module(CK_DLL);
    if (!h) { t_skip("no cryptdll"); return; }
    for (size_t i = 0; i < CK_NEXP; i++) {
        SET_ERR(0);
        FARPROC p = GetProcAddress(h, ck_exp[i].name);
        CHECKF(p != NULL, "%s", ck_exp[i].name);
    }
}

TEST(ckexp_ordinals_match_names) {
    CK_NOWINE();
    HMODULE h = t_module(CK_DLL);
    if (!h) { t_skip("no cryptdll"); return; }
    for (size_t i = 0; i < CK_NEXP; i++) {
        FARPROC byname = GetProcAddress(h, ck_exp[i].name);
        FARPROC byord = GetProcAddress(h, MAKEINTRESOURCEA(ck_exp[i].ord));
        CHECKF(byname != NULL && byord == byname, "%s ordinal %u", ck_exp[i].name, ck_exp[i].ord);
    }
}

TEST(ckexp_ordinals_are_contiguous_1_to_20) {
    CK_NOWINE();
    HMODULE h = t_module(CK_DLL);
    if (!h) { t_skip("no cryptdll"); return; }
    for (unsigned o = 1; o <= 20; o++) CHECKF(GetProcAddress(h, MAKEINTRESOURCEA(o)) != NULL, "ordinal %u", o);
    EXPECT_GPA_FAIL(h, MAKEINTRESOURCEA(21));
    EXPECT_GPA_FAIL(h, MAKEINTRESOURCEA(0xFFFF));
}

TEST(ckexp_md5_exports_forward_to_ntdll) {
    CK_NOWINE();
    HMODULE h = t_module(CK_DLL), nt = t_module("ntdll.dll");
    if (!h || !nt) { t_skip("module"); return; }
    static const char *n[] = { "MD5Init", "MD5Update", "MD5Final" };
    for (int i = 0; i < 3; i++) {
        FARPROC a = GetProcAddress(h, n[i]), b = GetProcAddress(nt, n[i]);
        CHECKF(a != NULL && a == b, "%s must resolve to the ntdll implementation", n[i]);
    }
}

TEST(ckexp_forwarder_entries_live_in_export_directory) {
    CK_NOWINE();
    /* the three MD5 exports are forwarder strings ("NTDLL.MD5Init"): the export RVA points inside the export directory */
    HMODULE h = t_module(CK_DLL);
    if (!h) { t_skip("no cryptdll"); return; }
    BYTE *base = (BYTE *)h;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    IMAGE_NT_HEADERS64 *nt = (IMAGE_NT_HEADERS64 *)(base + dos->e_lfanew);
    IMAGE_DATA_DIRECTORY dd = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    CHECK(dd.VirtualAddress != 0);
    IMAGE_EXPORT_DIRECTORY *ed = (IMAGE_EXPORT_DIRECTORY *)(base + dd.VirtualAddress);
    DWORD *fn = (DWORD *)(base + ed->AddressOfFunctions);
    DWORD *nm = (DWORD *)(base + ed->AddressOfNames);
    WORD *od = (WORD *)(base + ed->AddressOfNameOrdinals);
    EXPECT_EQ(ed->NumberOfFunctions, 20);
    int fwd = 0;
    for (DWORD i = 0; i < ed->NumberOfNames; i++) {
        const char *name = (const char *)(base + nm[i]);
        DWORD rva = fn[od[i]];
        int is_fwd = rva >= dd.VirtualAddress && rva < dd.VirtualAddress + dd.Size;
        int want = 0;
        for (size_t k = 0; k < CK_NEXP; k++) if (!strcmp(name, ck_exp[k].name)) want = ck_exp[k].fwd;
        CHECKF(is_fwd == want, "%s forwarder=%d want %d", name, is_fwd, want);
        fwd += is_fwd;
        if (is_fwd) CHECKF(!strncmp((const char *)(base + rva), "NTDLL.", 6), "%s -> %s", name, (const char *)(base + rva));
    }
    EXPECT_EQ(fwd, 3);
}

TEST(ckexp_no_unregister_exports) {
    HMODULE h = t_module(CK_DLL);
    if (!h) { t_skip("no cryptdll"); return; }
    static const char *absent[] = { "CDUnregisterCSystem", "CDUnRegisterCSystem", "CDDeregisterCSystem",
        "CDUnregisterCheckSum", "CDUnregisterRng", "CDLocateCSystemByName", "MD5", "aesCTSEncrypt", "aesCTSDecrypt",
        "CheckCNG", "LoadCNG", "aesDR", "CDRegister", "DefaultRngFn", "md5Hmac" };
    for (size_t i = 0; i < sizeof absent / sizeof absent[0]; i++) {
        SET_ERR(0);
        CHECKF(GetProcAddress(h, absent[i]) == NULL, "%s should not be exported", absent[i]);
        EXPECT_ERR(ERROR_PROC_NOT_FOUND);
    }
}

TEST(ckexp_case_sensitive_names) {
    CK_NOWINE();
    HMODULE h = t_module(CK_DLL);
    if (!h) { t_skip("no cryptdll"); return; }
    SET_ERR(0);
    CHECK(GetProcAddress(h, "cdlocatecsystem") == NULL);
    EXPECT_ERR(ERROR_PROC_NOT_FOUND);
    SET_ERR(0);
    CHECK(GetProcAddress(h, "hmacwithsha") == NULL);
    EXPECT_ERR(ERROR_PROC_NOT_FOUND);
    CHECK(GetProcAddress(h, "HMACwithSHA") != NULL);
}

TEST(ckexp_same_module_through_loadlibrary_twice) {
    HMODULE a = LoadLibraryA(CK_DLL), b = LoadLibraryA("CRYPTDLL.DLL");
    CHECK(a != NULL);
    CHECK(a == b);
    if (a) FreeLibrary(a);
    if (b) FreeLibrary(b);
}

TEST(ckexp_exports_not_shared_with_cryptbase_or_advapi) {
    CK_NOWINE();
    /* these exports exist only in cryptdll */
    static const char *only[] = { "CDLocateCSystem", "KRBFXCF2", "HMACwithSHA", "PBKDF2", "aesCTSEncryptMsg" };
    static const char *others[] = { "advapi32.dll", "cryptsp.dll", "cryptbase.dll", "bcrypt.dll", "crypt32.dll" };
    for (size_t i = 0; i < 5; i++) for (size_t j = 0; j < 5; j++) {
        HMODULE m = t_module(others[j]);
        if (!m) continue;
        CHECKF(GetProcAddress(m, only[i]) == NULL, "%s!%s", others[j], only[i]);
    }
}
