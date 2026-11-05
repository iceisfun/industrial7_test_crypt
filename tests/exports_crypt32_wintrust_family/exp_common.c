/* Shared engine for the table-driven export sweeps (exp.h / exp_data*.c).
 * Everything here is resolve-only: LoadLibrary (t_module) + GetProcAddress, never a call into the DLL.
 *
 * Tables are Windows 10 x64 export tables. Existence checks are hard on Windows; under an emulator
 * (t_is_wine) a missing export is only noted, because stub coverage is not what this corpus defines.
 */
#include "exp.h"
#include <ctype.h>

static int g_wine;
#define XCHK(c, ...) do { int ok_ = !!(c); \
    if (!ok_ && g_wine) t_note("[emulator gap] " __VA_ARGS__); \
    else t_check(ok_, __FILE__, __LINE__, #c, __VA_ARGS__); } while (0)

#undef CHECKF
#define CHECKF(c, ...) XCHK(c, __VA_ARGS__)
#undef CHECK
#define CHECK(c) XCHK(c, "%s", "")
#undef EXPECT_ERR
#define EXPECT_ERR(err) do { DWORD e_ = GetLastError(); XCHK(e_ == (DWORD)(err), "GetLastError got %lu want %lu", e_, (DWORD)(err)); } while (0)

static FARPROC by_name(HMODULE m, const char *n) { return GetProcAddress(m, n); }
static FARPROC by_ord(HMODULE m, unsigned o) { return GetProcAddress(m, (LPCSTR)(ULONG_PTR)o); }

static int in_image(HMODULE m, FARPROC p) {
    MEMORY_BASIC_INFORMATION mbi;
    if (!p) return 0;
    if (!VirtualQuery((void *)p, &mbi, sizeof mbi)) return 0;
    return mbi.AllocationBase == (void *)m;
}

static int tab_has_name(const exp_ent *t, int n, const char *name) {
    for (int i = 0; i < n; i++) if (t[i].name && !strcmp(t[i].name, name)) return 1;
    return 0;
}

/* Split "MOD.Name" / "MOD.#123" into a ".dll" name and a symbol. */
static int split_fwd(const char *f, char *dll, size_t cap, const char **sym) {
    const char *dot = strchr(f, '.');
    if (!dot || (size_t)(dot - f) + 5 > cap) return 0;
    memcpy(dll, f, dot - f); strcpy(dll + (dot - f), ".dll");
    *sym = dot + 1;
    return 1;
}

void exp_run(const char *dll, const char *w, const exp_ent *t, int n) {
    g_wine = t_is_wine();
    HMODULE m = strcmp(w, "sanity") ? t_module(dll) : NULL;
    if (!strcmp(w, "sanity")) {
        CHECK(n > 0);
        for (int i = 0; i < n; i++) {
            if (i) CHECKF(t[i].ord > t[i - 1].ord, "ordinals not strictly ascending at %u", t[i].ord);
            if (t[i].name) for (int j = i + 1; j < n; j++)
                if (t[j].name && !strcmp(t[i].name, t[j].name)) CHECKF(0, "duplicate export name %s", t[i].name);
        }
        return;
    }
    if (!strcmp(w, "load")) {
        if (!m && g_wine) { t_skip("%s not present in emulator", dll); return; }
        if (!m) {
            DWORD le = GetLastError();
            if (le == ERROR_MOD_NOT_FOUND || le == ERROR_BAD_EXE_FORMAT) { t_note("%s not loadable here (error %lu): SKU/feature dependent", dll, le); t_skip("%s absent", dll); return; }
        }
        CHECKF(m != NULL, "LoadLibrary(%s) failed, error %lu", dll, GetLastError());
        return;
    }
    if (!m) { t_skip("%s not loadable", dll); return; }

    if (!strcmp(w, "names")) {
        int cnt = 0;
        for (int i = 0; i < n; i++) if (t[i].name) {
            cnt++;
            XCHK(by_name(m, t[i].name) != NULL, "%s!%s does not resolve by name", dll, t[i].name);
        }
        if (!cnt) t_skip("%s has no named exports", dll);
    } else if (!strcmp(w, "ords")) {
        for (int i = 0; i < n; i++)
            XCHK(by_ord(m, t[i].ord) != NULL, "%s!#%u (%s) does not resolve by ordinal", dll, t[i].ord, t[i].name ? t[i].name : "unnamed");
    } else if (!strcmp(w, "nameord")) {
        int cnt = 0;
        for (int i = 0; i < n; i++) if (t[i].name) {
            FARPROC a = by_name(m, t[i].name), b = by_ord(m, t[i].ord);
            cnt++;
            if (!a || !b) { XCHK(a && b, "%s!%s/#%u: name %p ordinal %p", dll, t[i].name, t[i].ord, (void *)a, (void *)b); continue; }
            CHECKF(a == b, "%s!%s and ordinal %u resolve to different addresses %p %p", dll, t[i].name, t[i].ord, (void *)a, (void *)b);
        }
        if (!cnt) t_skip("%s has no named exports", dll);
    } else if (!strcmp(w, "inimg")) {
        int cnt = 0;
        for (int i = 0; i < n; i++) if (!t[i].fwd) {
            FARPROC p = by_ord(m, t[i].ord);
            if (!p) { XCHK(p != NULL, "%s!#%u missing", dll, t[i].ord); continue; }
            cnt++;
            CHECKF(in_image(m, p), "%s!#%u (%s) is not inside the module image", dll, t[i].ord, t[i].name ? t[i].name : "unnamed");
        }
        if (!cnt) t_skip("%s has no local exports", dll);
    } else if (!strcmp(w, "fwd")) {
        int cnt = 0;
        for (int i = 0; i < n; i++) if (t[i].fwd) {
            char tdll[64]; const char *sym; FARPROC p = by_ord(m, t[i].ord), q;
            cnt++;
            if (!split_fwd(t[i].fwd, tdll, sizeof tdll, &sym)) { CHECKF(0, "bad forwarder string %s", t[i].fwd); continue; }
            HMODULE tm = t_module(tdll);
            if (!tm) { XCHK(tm != NULL, "forwarder target %s for %s!#%u not loadable", tdll, dll, t[i].ord); continue; }
            q = sym[0] == '#' ? by_ord(tm, (unsigned)atoi(sym + 1)) : by_name(tm, sym);
            if (!p || !q) { XCHK(p && q, "%s!#%u -> %s: forwarded %p target %p", dll, t[i].ord, t[i].fwd, (void *)p, (void *)q); continue; }
            CHECKF(p == q, "%s!#%u (%s) forwards to %s but resolves to %p, target is %p", dll, t[i].ord, t[i].name ? t[i].name : "unnamed", t[i].fwd, (void *)p, (void *)q);
            CHECKF(!in_image(m, p), "%s!#%u forwarder resolved inside its own image", dll, t[i].ord);
            if (t[i].name) {
                FARPROC pn = by_name(m, t[i].name);
                CHECKF(pn == p, "%s!%s by name differs from ordinal %u", dll, t[i].name, t[i].ord);
            }
        }
        if (!cnt) t_skip("%s exports no forwarders", dll);
    } else if (!strcmp(w, "bogusname")) {
        static const char *bogus[] = { "cryptt_NoSuchExport_xyz", "NoSuchExport", "_", "CryptT32NoSuch@4" };
        for (int i = 0; i < 4; i++) {
            SET_ERR(0);
            FARPROC p = by_name(m, bogus[i]);
            CHECKF(p == NULL, "%s unexpectedly exports %s", dll, bogus[i]);
            if (!p) EXPECT_ERR(ERROR_PROC_NOT_FOUND);
        }
    } else if (!strcmp(w, "bogusord")) {
        unsigned mx = 0, mn = 0xFFFF;
        for (int i = 0; i < n; i++) { if (t[i].ord > mx) mx = t[i].ord; if (t[i].ord < mn) mn = t[i].ord; }
        unsigned cand[] = { 0xFFFE, 0xFFFF, mx + 4000, mx + 1000 };
        for (int i = 0; i < 4; i++) {
            if (cand[i] > 0xFFFF || cand[i] <= mx + 500) continue;
            SET_ERR(0);
            FARPROC p = by_ord(m, cand[i]);
            CHECKF(p == NULL, "%s unexpectedly exports ordinal %u", dll, cand[i]);
            if (!p) EXPECT_ERR(ERROR_PROC_NOT_FOUND);
        }
        if (mn > 1) {
            SET_ERR(0);
            FARPROC p = by_ord(m, 1);
            CHECKF(p == NULL, "%s unexpectedly exports ordinal 1", dll);
            if (!p) EXPECT_ERR(ERROR_PROC_NOT_FOUND);
        }
    } else if (!strcmp(w, "case")) {
        int done = 0;
        for (int i = 0; i < n && done < 3; i++) {
            if (!t[i].name || !isalpha((unsigned char)t[i].name[0])) continue;
            char buf[160]; int clash = 0;
            strncpy(buf, t[i].name, sizeof buf - 1); buf[sizeof buf - 1] = 0;
            buf[0] = isupper((unsigned char)buf[0]) ? tolower((unsigned char)buf[0]) : toupper((unsigned char)buf[0]);
            for (int j = 0; j < n; j++) if (t[j].name && !_stricmp(t[j].name, buf)) clash = 1;
            if (clash) continue;
            SET_ERR(0);
            FARPROC p = by_name(m, buf);
            CHECKF(p == NULL, "%s resolved case-flipped name %s", dll, buf);
            if (!p) EXPECT_ERR(ERROR_PROC_NOT_FOUND);
            done++;
            i += 7;
        }
        if (!done) t_skip("%s: no suitable names for the case test", dll);
    } else if (!strcmp(w, "awpairs")) {
        int cnt = 0;
        for (int i = 0; i < n; i++) {
            if (!t[i].name) continue;
            size_t l = strlen(t[i].name);
            if (l < 2 || t[i].name[l - 1] != 'W') continue;
            char a[160]; if (l >= sizeof a) continue;
            memcpy(a, t[i].name, l); a[l - 1] = 'A'; a[l] = 0;
            if (!tab_has_name(t, n, a)) continue;
            cnt++;
            FARPROC pw = by_name(m, t[i].name), pa = by_name(m, a);
            if (!pw || !pa) { XCHK(pw && pa, "%s: pair %s/%s: W %p A %p", dll, t[i].name, a, (void *)pw, (void *)pa); continue; }
            CHECKF(pw != pa, "%s: %s and %s share one address", dll, t[i].name, a);
        }
        if (!cnt) t_skip("%s has no A/W pairs", dll);
    } else if (!strcmp(w, "dllentry")) {
        static const char *e[] = { "DllGetClassObject", "DllCanUnloadNow", "DllRegisterServer", "DllUnregisterServer", "DllInstall", "DllGetActivationFactory" };
        for (int i = 0; i < 6; i++) {
            int listed = tab_has_name(t, n, e[i]);
            FARPROC p = by_name(m, e[i]);
            if (listed) XCHK(p != NULL, "%s should export %s", dll, e[i]);
            else if (p) t_note("%s exports %s which the reference Windows 10 table lacks", dll, e[i]);
            else { SET_ERR(0); CHECK(by_name(m, e[i]) == NULL); EXPECT_ERR(ERROR_PROC_NOT_FOUND); }
        }
    } else if (!strcmp(w, "extras")) {
        unsigned mx = 0; int extra = 0;
        for (int i = 0; i < n; i++) if (t[i].ord > mx) mx = t[i].ord;
        for (unsigned o = 1; o <= mx + 64 && o <= 20000; o++) {
            int listed = 0;
            for (int i = 0; i < n; i++) if (t[i].ord == o) { listed = 1; break; }
            if (!listed && by_ord(m, o)) { extra++; t_note("%s exports unlisted ordinal %u", dll, o); }
        }
        CHECKF(1, "scan done, %d unlisted", extra);
    } else if (!strcmp(w, "nullname")) {
        SET_ERR(0);
        CHECK(GetProcAddress(m, NULL) == NULL);
        DWORD e = GetLastError(); t_note("GetProcAddress(%s,NULL) last error %lu", dll, e);
        SET_ERR(0);
        CHECK(GetProcAddress(NULL, NULL) == NULL);
        SET_ERR(0);
        CHECK(GetProcAddress(NULL, "CertOpenStore") == NULL);
    }
}
