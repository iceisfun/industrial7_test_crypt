#include "exports_common.h"
#include <ctype.h>

const XM *ex_find(const char *dll) {
    for (const XM *m = ex_mods; m->dll; m++) if (!lstrcmpiA(m->dll, dll)) return m;
    return NULL;
}
HMODULE ex_mod(const char *dll) { return t_module(dll); }

int ex_dir(HMODULE h, XDIR *d) {
    memset(d, 0, sizeof *d);
    if (!h) return 0;
    const BYTE *b = (const BYTE *)h;
    const IMAGE_DOS_HEADER *dos = (const IMAGE_DOS_HEADER *)b;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    const IMAGE_NT_HEADERS64 *nt = (const IMAGE_NT_HEADERS64 *)(b + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    d->base = h; d->size_of_image = nt->OptionalHeader.SizeOfImage;
    d->machine = nt->FileHeader.Machine; d->file_chars = nt->FileHeader.Characteristics;
    const IMAGE_DATA_DIRECTORY *dd = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    d->dir_rva = dd->VirtualAddress; d->dir_size = dd->Size;
    if (!dd->VirtualAddress) return 0;
    d->dir = (const IMAGE_EXPORT_DIRECTORY *)(b + dd->VirtualAddress);
    return 1;
}
int ex_in_image(const XDIR *d, const void *p) {
    return (const BYTE *)p >= (const BYTE *)d->base && (const BYTE *)p < (const BYTE *)d->base + d->size_of_image;
}
int ex_dir_find(const XDIR *d, const char *name, DWORD *ord, DWORD *rva, const char **fwd) {
    const BYTE *b = (const BYTE *)d->base;
    const DWORD *nm = (const DWORD *)(b + d->dir->AddressOfNames);
    const WORD *no = (const WORD *)(b + d->dir->AddressOfNameOrdinals);
    const DWORD *fn = (const DWORD *)(b + d->dir->AddressOfFunctions);
    for (DWORD i = 0; i < d->dir->NumberOfNames; i++) {
        if (strcmp((const char *)(b + nm[i]), name)) continue;
        DWORD r = fn[no[i]];
        if (ord) *ord = no[i] + d->dir->Base;
        if (rva) *rva = r;
        if (fwd) *fwd = (r >= d->dir_rva && r < d->dir_rva + d->dir_size) ? (const char *)(b + r) : NULL;
        return 1;
    }
    return 0;
}
void ex_target_of(const char *fwd, char *dll, size_t cap, char *sym, size_t scap) {
    const char *dot = strchr(fwd, '.');
    size_t n = dot ? (size_t)(dot - fwd) : strlen(fwd);
    if (n + 5 > cap) n = cap - 5;
    for (size_t i = 0; i < n; i++) dll[i] = (char)tolower((unsigned char)fwd[i]);
    strcpy(dll + n, ".dll");
    lstrcpynA(sym, dot ? dot + 1 : "", (int)scap);
}
void ex_family(const char *dll, const char *const *names, int n) {
    HMODULE h = t_module(dll);
    if (!h) { t_skip("cannot load %s", dll); return; }
    int bad = 0;
    for (int i = 0; i < n; i++) {
        SET_ERR(0);
        FARPROC p = GetProcAddress(h, names[i]);
        if (!p) { bad++; if (bad <= FAIL_BUDGET) CHECKF(p != NULL, "%s!%s missing", dll, names[i]); }
        else CHECK(p != NULL);
        FARPROC q = t_proc_in(dll, names[i]);
        EXPECT_EQ(q, p);
    }
}
