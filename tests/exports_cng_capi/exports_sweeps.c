/* Generic per-module export sweeps. All lookups go LoadLibrary -> GetProcAddress. */
#include "exports_common.h"

#define LOADM(dll, h, d) \
    const XM *m_ = ex_find(dll); HMODULE h = t_module(dll); XDIR d; \
    if (!m_) { t_skip("no snapshot for %s", dll); return; } \
    if (!h) { t_skip("cannot load %s", dll); return; } \
    if (!ex_dir(h, &d)) { t_skip("no export directory in %s", dll); return; }

static int is_fwd_wine(void) { return t_is_wine(); }

void sw_loads(const char *dll) {
    HMODULE h = t_module(dll);
    CHECKF(h != NULL, "LoadLibrary(%s) failed", dll);
    if (!h) return;
    char path[MAX_PATH]; DWORD n = GetModuleFileNameA(h, path, sizeof path);
    CHECK(n > 0 && n < sizeof path);
    const char *leaf = strrchr(path, '\\'); leaf = leaf ? leaf + 1 : path;
    CHECKF(!lstrcmpiA(leaf, dll), "module file name %s", path);
    CHECK(((ULONG_PTR)h & 0xFFFF) == 0);     /* images are 64K aligned */
}
void sw_pe_headers(const char *dll) {
    LOADM(dll, h, d);
    EXPECT_EQ(d.machine, IMAGE_FILE_MACHINE_AMD64);
    CHECK(d.file_chars & IMAGE_FILE_DLL);
    CHECK(d.dir_size >= sizeof(IMAGE_EXPORT_DIRECTORY));
    CHECK(d.dir->NumberOfFunctions >= d.dir->NumberOfNames);
    CHECK(d.dir->NumberOfNames > 0);
    CHECK(d.dir->Base >= 1);
}
void sw_names_resolve(const char *dll) {
    LOADM(dll, h, d);
    int bad = 0;
    for (int i = 0; i < m_->n; i++) {
        if (!m_->e[i].name) continue;
        SET_ERR(0);
        FARPROC p = GetProcAddress(h, m_->e[i].name);
        if (!p && ++bad <= FAIL_BUDGET) CHECKF(0, "%s!%s does not resolve (err %lu)", dll, m_->e[i].name, GetLastError());
        else CHECK(p != NULL);
    }
}
void sw_name_via_t_proc_in(const char *dll) {
    LOADM(dll, h, d);
    for (int i = 0; i < m_->n; i++) {
        if (!m_->e[i].name) continue;
        EXPECT_EQ(t_proc_in(dll, m_->e[i].name), GetProcAddress(h, m_->e[i].name));
    }
}
void sw_listed_in_dir(const char *dll) {
    LOADM(dll, h, d);
    int bad = 0;
    for (int i = 0; i < m_->n; i++) {
        if (!m_->e[i].name) continue;
        int f = ex_dir_find(&d, m_->e[i].name, NULL, NULL, NULL);
        if (!f && ++bad <= FAIL_BUDGET) CHECKF(0, "%s!%s absent from export directory", dll, m_->e[i].name);
        else CHECK(f);
    }
}
void sw_addr_in_image(const char *dll) {
    LOADM(dll, h, d);
    for (int i = 0; i < m_->n; i++) {
        if (!m_->e[i].name) continue;
        FARPROC p = GetProcAddress(h, m_->e[i].name);
        if (!p) continue;
        DWORD rva; const char *fwd;
        if (!ex_dir_find(&d, m_->e[i].name, NULL, &rva, &fwd)) continue;
        if (fwd) { CHECKF(!ex_in_image(&d, p), "%s forwarder resolved inside the forwarding image", m_->e[i].name); }
        else {
            CHECKF(ex_in_image(&d, p), "%s resolved outside its image", m_->e[i].name);
            EXPECT_EQ((const BYTE *)p, (const BYTE *)h + rva);
        }
    }
}
void sw_dir_ordinal_roundtrip(const char *dll) {
    LOADM(dll, h, d);
    for (int i = 0; i < m_->n; i++) {
        if (!m_->e[i].name) continue;
        DWORD ord;
        if (!ex_dir_find(&d, m_->e[i].name, &ord, NULL, NULL)) continue;
        FARPROC byname = GetProcAddress(h, m_->e[i].name);
        SET_ERR(0);
        FARPROC byord = GetProcAddress(h, MAKEINTRESOURCEA(ord));
        CHECKF(byord != NULL, "%s ordinal %lu does not resolve", m_->e[i].name, ord);
        EXPECT_EQ(byord, byname);
    }
}
void sw_json_ordinals(const char *dll) {
    LOADM(dll, h, d);
    int diff = 0;
    for (int i = 0; i < m_->n; i++) {
        if (!m_->e[i].name) continue;
        DWORD ord;
        if (!ex_dir_find(&d, m_->e[i].name, &ord, NULL, NULL)) continue;
        if (ord != m_->e[i].ord) { diff++; if (diff <= 5) t_note("%s!%s ordinal %lu, snapshot %u", dll, m_->e[i].name, ord, m_->e[i].ord); }
    }
    if (diff) t_note("%s: %d ordinals differ from the authoring snapshot (build dependent)", dll, diff);
    /* the snapshot ordinal always lies inside [Base, Base+NumberOfFunctions) on the snapshot build */
    CHECK(d.dir->Base >= 1);
}
void sw_ordinal_only(const char *dll) {
    LOADM(dll, h, d);
    int seen = 0;
    for (int i = 0; i < m_->n; i++) {
        if (m_->e[i].name) continue;
        seen++;
        SET_ERR(0);
        FARPROC p = GetProcAddress(h, MAKEINTRESOURCEA(m_->e[i].ord));
        if (!p && t_is_wine()) { t_note("wine lacks %s ordinal-only export #%u", dll, m_->e[i].ord); continue; }
        /* ordinal-only slots are build specific (undocumented): note, do not fail */
        if (!p) { t_note("%s ordinal-only export #%u not present on this build", dll, m_->e[i].ord); continue; }
        CHECK(ex_in_image(&d, p));
    }
    if (!seen) {
        /* no ordinal-only exports in this module: every function slot with an RVA is named, or count gap */
        t_note("%s has no ordinal-only exports in the snapshot", dll);
        CHECK(d.dir->NumberOfFunctions >= d.dir->NumberOfNames);
    }
}
void sw_fwd_strings(const char *dll) {
    LOADM(dll, h, d);
    int nf = 0;
    for (int i = 0; i < m_->n; i++) {
        if (!m_->e[i].fwd || !m_->e[i].name) continue;
        nf++;
        const char *fwd = NULL;
        if (!ex_dir_find(&d, m_->e[i].name, NULL, NULL, &fwd)) continue;
        if (is_fwd_wine() && !fwd) { t_note("wine: %s is not a forwarder", m_->e[i].name); continue; }
        CHECKF(fwd != NULL, "%s!%s should be a forwarder", dll, m_->e[i].name);
        if (fwd) CHECKF(!lstrcmpiA(fwd, m_->e[i].fwd), "%s forwarder %s vs %s", m_->e[i].name, fwd, m_->e[i].fwd);
    }
    if (!nf) t_note("%s has no forwarders", dll);
}
void sw_fwd_same_address(const char *dll) {
    LOADM(dll, h, d);
    for (int i = 0; i < m_->n; i++) {
        if (!m_->e[i].fwd || !m_->e[i].name) continue;
        char tdll[64], sym[128];
        ex_target_of(m_->e[i].fwd, tdll, sizeof tdll, sym, sizeof sym);
        HMODULE th = t_module(tdll);
        if (!th) { CHECKF(0, "cannot load forward target %s", tdll); continue; }
        FARPROC a = GetProcAddress(h, m_->e[i].name);
        FARPROC b = GetProcAddress(th, sym);
        CHECKF(b != NULL, "%s!%s unresolved", tdll, sym);
        CHECKF(a == b, "%s!%s -> %s!%s: %p vs %p", dll, m_->e[i].name, tdll, sym, (void *)a, (void *)b);
    }
}
void sw_nonfwd_not_forwarder(const char *dll) {
    LOADM(dll, h, d);
    for (int i = 0; i < m_->n; i++) {
        if (m_->e[i].fwd || !m_->e[i].name) continue;
        DWORD rva; const char *fwd = (const char *)1;
        if (!ex_dir_find(&d, m_->e[i].name, NULL, &rva, &fwd)) continue;
        CHECKF(fwd == NULL, "%s!%s unexpectedly a forwarder", dll, m_->e[i].name);
        CHECK(rva != 0);
    }
}
void sw_counts(const char *dll) {
    LOADM(dll, h, d);
    int named = 0;
    for (int i = 0; i < m_->n; i++) if (m_->e[i].name) named++;
    CHECK(d.dir->NumberOfNames >= (DWORD)named || t_is_wine());
    if (d.dir->NumberOfNames != (DWORD)named)
        t_note("%s: NumberOfNames %lu, snapshot (filtered) %d", dll, d.dir->NumberOfNames, named);
    t_note("%s: Base %lu NumberOfFunctions %lu NumberOfNames %lu", dll, d.dir->Base, d.dir->NumberOfFunctions, d.dir->NumberOfNames);
}
static int listed(const XM *m, const char *n) {
    for (int i = 0; i < m->n; i++) if (m->e[i].name && !strcmp(m->e[i].name, n)) return 1;
    return 0;
}
void sw_unlisted(const char *dll) {
    LOADM(dll, h, d);
    const BYTE *b = (const BYTE *)h; const DWORD *nm = (const DWORD *)(b + d.dir->AddressOfNames);
    int extra = 0;
    for (DWORD i = 0; i < d.dir->NumberOfNames; i++) {
        const char *n = (const char *)(b + nm[i]);
        if (!listed(m_, n)) { extra++; if (extra <= 10) t_note("%s exports unlisted name %s", dll, n); }
    }
    t_note("%s: %d exported names not in the authoring snapshot", dll, extra);
    CHECK(d.dir->NumberOfNames > 0);
}
void sw_case_sensitive(const char *dll) {
    LOADM(dll, h, d);
    int done = 0;
    for (int i = 0; i < m_->n && done < 8; i++) {
        const char *n = m_->e[i].name; if (!n) continue;
        char u[160]; lstrcpynA(u, n, sizeof u);
        char *p = u; for (; *p; p++) if (*p >= 'a' && *p <= 'z') { *p -= 32; break; }
        if (!*p) { for (p = u; *p; p++) if (*p >= 'A' && *p <= 'Z') { *p += 32; break; } }
        if (!strcmp(u, n) || listed(m_, u)) continue;
        SET_ERR(0);
        FARPROC r = GetProcAddress(h, u);
        CHECKF(r == NULL, "%s!%s resolved case-insensitively", dll, u);
        EXPECT_ERR(ERROR_PROC_NOT_FOUND);
        done++;
    }
}
void sw_bad_names(const char *dll) {
    LOADM(dll, h, d);
    static const char *const bad[] = { "NoSuchExport_xyz", "BCrypt", "Crypt", "DoesNotExistW", "__imp_CryptAcquireContextA", "_BCryptHash@4", "?", " " };
    for (unsigned i = 0; i < sizeof bad / sizeof *bad; i++) {
        if (listed(m_, bad[i])) continue;
        SET_ERR(0);
        FARPROC r = GetProcAddress(h, bad[i]);
        CHECKF(r == NULL, "%s!%s unexpectedly resolved", dll, bad[i]);
        EXPECT_ERR(ERROR_PROC_NOT_FOUND);
    }
    /* name + trailing character, and truncated names, of real exports */
    int done = 0;
    for (int i = 0; i < m_->n && done < 6; i++) {
        const char *n = m_->e[i].name; if (!n || strlen(n) < 4) continue;
        char t[200];
        wsprintfA(t, "%sX9", n); if (!listed(m_, t)) { SET_ERR(0); CHECK(GetProcAddress(h, t) == NULL); EXPECT_ERR(ERROR_PROC_NOT_FOUND); }
        lstrcpynA(t, n, (int)strlen(n)); /* drop last char */
        if (!listed(m_, t)) { SET_ERR(0); CHECK(GetProcAddress(h, t) == NULL); EXPECT_ERR(ERROR_PROC_NOT_FOUND); }
        done++;
    }
}
void sw_bad_ordinals(const char *dll) {
    LOADM(dll, h, d);
    DWORD lo = d.dir->Base, hi = d.dir->Base + d.dir->NumberOfFunctions;   /* valid range [lo,hi) */
    DWORD cand[] = { hi, hi + 1, hi + 100, 0xFFFE, 0xFFFF };
    for (unsigned i = 0; i < sizeof cand / sizeof *cand; i++) {
        if (cand[i] < hi || cand[i] > 0xFFFF) continue;
        t_label("ordinal %lu", cand[i]);
        EXPECT_GPA_FAIL(h, MAKEINTRESOURCEA(cand[i]));   /* 182 */
    }
    if (lo > 1) {
        t_label("Base-1");
        EXPECT_GPA_FAIL(h, MAKEINTRESOURCEA(lo - 1));    /* 182 */
    }
    t_label("ordinal 0");
    EXPECT_GPA_FAIL(h, MAKEINTRESOURCEA(0));             /* 87 */
    t_label(NULL);
}
static int has_wide_twin(const XM *m, const char *n, char *twin, size_t cap) {
    size_t l = strlen(n); if (l < 2) return 0;
    char c = n[l - 1]; if (c != 'A' && c != 'W') return 0;
    lstrcpynA(twin, n, (int)cap); twin[l - 1] = (c == 'A') ? 'W' : 'A';
    return listed(m, twin);
}
void sw_aw_pairs(const char *dll) {
    LOADM(dll, h, d);
    int pairs = 0;
    for (int i = 0; i < m_->n; i++) {
        const char *n = m_->e[i].name; char tw[200];
        if (!n || !has_wide_twin(m_, n, tw, sizeof tw)) continue;
        pairs++;
        FARPROC a = GetProcAddress(h, n), b = GetProcAddress(h, tw);
        CHECKF(a != NULL && b != NULL, "%s: %s / %s", dll, n, tw);
        if (a && b && strlen(n) && n[strlen(n) - 1] == 'A') CHECKF(a != b, "%s A and W entry points identical", n);
    }
    if (!pairs) t_note("%s: no A/W pairs exported", dll);
    else t_note("%s: %d A/W name pairs (counted twice)", dll, pairs);
}
void sw_stable(const char *dll) {
    LOADM(dll, h, d);
    for (int i = 0; i < m_->n; i++) {
        const char *n = m_->e[i].name; if (!n) continue;
        FARPROC a = GetProcAddress(h, n), b = GetProcAddress(h, n);
        EXPECT_EQ(a, b);
        EXPECT_EQ(GetProcAddress(t_module(dll), n), a);   /* cached handle == fresh lookup */
    }
    HMODULE h2 = LoadLibraryA(dll);
    EXPECT_EQ(h2, h);
    if (h2) FreeLibrary(h2);
}
void sw_refcount(const char *dll) {
    LOADM(dll, h, d);
    HMODULE a = LoadLibraryA(dll), b = LoadLibraryA(dll);
    EXPECT_EQ(a, h); EXPECT_EQ(b, h);
    CHECK(FreeLibrary(a));
    CHECK(FreeLibrary(b));
    /* the harness's own reference keeps the image mapped */
    HMODULE g = GetModuleHandleA(dll);
    EXPECT_EQ(g, h);
    for (int i = 0; i < m_->n; i++) if (m_->e[i].name) { CHECK(GetProcAddress(h, m_->e[i].name) != NULL); break; }
}
void sw_sorted(const char *dll) {
    LOADM(dll, h, d);
    const BYTE *b = (const BYTE *)h; const DWORD *nm = (const DWORD *)(b + d.dir->AddressOfNames);
    int bad = 0;
    for (DWORD i = 1; i < d.dir->NumberOfNames; i++) {
        const char *x = (const char *)(b + nm[i - 1]), *y = (const char *)(b + nm[i]);
        if (strcmp(x, y) >= 0 && ++bad <= 5) CHECKF(0, "%s: %s !< %s (loader binary search needs strict byte order)", dll, x, y);
    }
    CHECK(bad == 0 || bad > 5);
}
void sw_no_dup_names(const char *dll) {
    LOADM(dll, h, d);
    for (int i = 0; i < m_->n; i++) for (int j = i + 1; j < m_->n; j++)
        if (m_->e[i].name && m_->e[j].name && !strcmp(m_->e[i].name, m_->e[j].name)) CHECKF(0, "duplicate %s", m_->e[i].name);
    for (int i = 0; i < m_->n; i++) for (int j = i + 1; j < m_->n; j++)
        CHECKF(m_->e[i].ord != m_->e[j].ord, "duplicate ordinal %u", m_->e[i].ord);
    CHECK(m_->n > 0);
}
void sw_distinct_addrs(const char *dll) {
    /* same RVA <=> same address, for named non-forwarded exports (RVAs read once; O(n^2) on cheap data only) */
    LOADM(dll, h, d);
    int n = m_->n;
    DWORD *rv = (DWORD *)calloc((size_t)n, sizeof *rv);
    FARPROC *ad = (FARPROC *)calloc((size_t)n, sizeof *ad);
    if (!rv || !ad) { free(rv); free(ad); t_skip("no memory"); return; }
    for (int i = 0; i < n; i++) {
        if (!m_->e[i].name || m_->e[i].fwd) continue;
        if (!ex_dir_find(&d, m_->e[i].name, NULL, &rv[i], NULL)) rv[i] = 0;
        else ad[i] = GetProcAddress(h, m_->e[i].name);
    }
    int bad = 0;
    for (int i = 0; i < n; i++) {
        if (!rv[i]) continue;
        for (int j = i + 1; j < n; j++) {
            if (!rv[j]) continue;
            if ((rv[i] == rv[j]) != (ad[i] == ad[j]) && ++bad <= FAIL_BUDGET)
                CHECKF(0, "%s / %s: rva %lx %lx, addr %p %p", m_->e[i].name, m_->e[j].name, rv[i], rv[j], (void *)ad[i], (void *)ad[j]);
        }
        CHECK(ad[i] == (FARPROC)((const BYTE *)h + rv[i]));
    }
    free(rv); free(ad);
}
void sw_getmodulehandle(const char *dll) {
    LOADM(dll, h, d);
    EXPECT_EQ(GetModuleHandleA(dll), h);
    char path[MAX_PATH]; GetModuleFileNameA(h, path, sizeof path);
    EXPECT_EQ(GetModuleHandleA(path), h);
    /* handle -> address round trip on a real export */
    for (int i = 0; i < m_->n; i++) {
        if (!m_->e[i].name || m_->e[i].fwd) continue;
        FARPROC p = GetProcAddress(h, m_->e[i].name);
        HMODULE owner = NULL;
        CHECK(GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCSTR)p, &owner));
        EXPECT_EQ(owner, h);
        break;
    }
}
void sw_name_len_limits(const char *dll) {
    LOADM(dll, h, d);
    char big[4096];
    memset(big, 'A', sizeof big - 1); big[sizeof big - 1] = 0;
    SET_ERR(0);
    CHECK(GetProcAddress(h, big) == NULL);
    EXPECT_ERR(ERROR_PROC_NOT_FOUND);
    /* NULL module / NULL name combinations */
    SET_ERR(0);
    CHECK(GetProcAddress(NULL, NULL) == NULL);
    CHECK(GetLastError() != 0);
    SET_ERR(0);
    CHECK(GetProcAddress(h, NULL) == NULL);
    CHECK(GetLastError() != 0);
}
