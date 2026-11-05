/* The chain engine surface resolves by name in crypt32.dll (no forwarders) and by the harness search order. */
#include "pkiutil.h"

#define EXPORT_PRESENT(fn) \
    TEST(chain_exports_crypt32_has_##fn) { \
        FARPROC p = t_proc_in("crypt32.dll", #fn); \
        if (!p && t_is_wine()) { t_skip("not exported by the emulator"); return; } \
        CHECK(p != NULL); \
        FARPROC q = t_proc(#fn); \
        CHECK(q == p); \
    }
EXPORT_PRESENT(CertCreateCertificateChainEngine)
EXPORT_PRESENT(CertFreeCertificateChainEngine)
EXPORT_PRESENT(CertResyncCertificateChainEngine)
EXPORT_PRESENT(CertGetCertificateChain)
EXPORT_PRESENT(CertDuplicateCertificateChain)
EXPORT_PRESENT(CertFreeCertificateChain)
EXPORT_PRESENT(CertFindChainInStore)
EXPORT_PRESENT(CertFreeCertificateChainList)
EXPORT_PRESENT(CertSelectCertificateChains)
EXPORT_PRESENT(I_CertChainEngineIsDisallowedCertificate)

TEST(chain_exports_missing_name_not_resolved) {
    SET_ERR(0);
    FARPROC p = GetProcAddress(t_module("crypt32.dll"), "CertCreateCertificateChainEngineXX");
    CHECK(p == NULL); EXPECT_ERR(ERROR_PROC_NOT_FOUND);
}
TEST(chain_exports_getprocaddress_null_name_fails) {
    FARPROC p = GetProcAddress(t_module("crypt32.dll"), NULL);
    CHECK(p == NULL);
}
TEST(chain_exports_no_ansi_wide_variants) {
    /* the chain engine API is not A/W split */
    CHECK(t_proc_in("crypt32.dll", "CertGetCertificateChainA") == NULL);
    CHECK(t_proc_in("crypt32.dll", "CertGetCertificateChainW") == NULL);
    CHECK(t_proc_in("crypt32.dll", "CertCreateCertificateChainEngineW") == NULL);
}
TEST(chain_exports_ordinal_lookup_matches_name) {
    HMODULE m = t_module("crypt32.dll");
    CHECK(m != NULL);
    /* resolve the name through the export directory and check the ordinal path yields the same address */
    BYTE *base = (BYTE *)m;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    IMAGE_DATA_DIRECTORY dd = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dd.VirtualAddress) { t_skip("no export directory"); return; }
    IMAGE_EXPORT_DIRECTORY *ed = (IMAGE_EXPORT_DIRECTORY *)(base + dd.VirtualAddress);
    DWORD *names = (DWORD *)(base + ed->AddressOfNames); WORD *ords = (WORD *)(base + ed->AddressOfNameOrdinals);
    for (DWORD i = 0; i < ed->NumberOfNames; i++) {
        if (strcmp((char *)(base + names[i]), "CertGetCertificateChain")) continue;
        FARPROC byname = GetProcAddress(m, "CertGetCertificateChain");
        FARPROC byord = GetProcAddress(m, (LPCSTR)(ULONG_PTR)(ed->Base + ords[i]));
        CHECK(byname != NULL && byname == byord);
        return;
    }
    t_skip("CertGetCertificateChain not in the export name table");
}
