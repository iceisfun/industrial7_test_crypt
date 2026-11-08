#!/usr/bin/env python3
"""Static coverage: which exports are exercised by a real call?
usage: coverage.py <corpus_dir> [--table] [exports.txt ...]   (default: <corpus_dir>/tools/*_exports.txt)

An export counts as *called* when the tests resolve it for use, in any of these forms (comments are ignored):
  - U(Name) UIN("dll", Name) UN(Name) and the other single-name resolver macros (UA US UC UK UB UNT UINN)
  - t_proc("Name") t_proc_in("dll", "Name") GetProcAddress(h, "Name") and any helper whose name contains "proc"
    taking the name as a string literal
  - any resolver macro defined in the tests, found automatically: a #define whose body stringifies one of its
    parameters (#param) and passes it to a resolver (t_proc*, GetProcAddress, *proc*) -- e.g. the
    F(type, Name) macro of ncrypt_ssl_provider -- or that pastes it into U()/UIN()/UN() (U(name##x)).
    The scan then looks at every invocation of such a macro and takes the argument at the stringified position.
It is *mentioned* when the name appears anywhere in tests/ (export tables count as mentions only).
Still invisible: names assembled at run time and wrapper tables that resolve whole name lists in a loop; spot-check
before declaring a name uncovered.

Writes tools/uncovered.txt (union of all lists, sorted). --table prints the per-module markdown table used in COVERAGE.md."""
import re, sys, glob, os

args = [a for a in sys.argv[1:] if not a.startswith("--")]
root = args[0]
table = "--table" in sys.argv
lists = args[1:] or sorted(glob.glob(os.path.join(root, "tools", "*_exports.txt")))


def strip_comments(s):
    out, i, n = [], 0, len(s)
    while i < n:
        c = s[i]
        if c == '"' or c == "'":
            j = i + 1
            while j < n and s[j] != c:
                j += 2 if s[j] == "\\" else 1
            out.append(s[i:j + 1]); i = j + 1
        elif s.startswith("/*", i):
            j = s.find("*/", i + 2); j = n if j < 0 else j + 2
            out.append(" "); i = j
        elif s.startswith("//", i):
            j = s.find("\n", i); j = n if j < 0 else j
            i = j
        else:
            out.append(c); i += 1
    return "".join(out)


areas = {}
for f in glob.glob(os.path.join(root, "tests", "**", "*.[ch]"), recursive=True):
    areas.setdefault(os.path.dirname(f), []).append(strip_comments(open(f, errors="replace").read()))
areas = {k: "\n".join(v) for k, v in areas.items()}
src = "\n".join(areas.values())

called = set()      # resolved and called with real arguments
called_zero = set() # reached only through zero-argument contract probes (macros whose body calls f(0,0,0,...))
IDENT = r"[A-Za-z_]\w*"
RESOLVER_CALL = r"\w*(?:[Pp]roc|GetProcAddress|_get|[Rr]esolve)\w*\s*\("
# direct single-name resolver macros
for m in re.finditer(r"\b(?:U|UIN|UN|UA|US|UC|UK|UB|UNT|UINN)\s*\(\s*(?:\"[^\"]*\"\s*,\s*)?(" + IDENT + r")\s*\)", src):
    called.add(m.group(1))
# string-literal forms: t_proc("N"), t_proc_in("dll","N"), GetProcAddress(h,"N"), any *proc* helper
for m in re.finditer(r"\b\w*(?:[Pp]roc|GetProcAddress)\w*\s*\(\s*(?:[^\"()]*?,\s*)?(?:\"[^\"]*\"\s*,\s*)?\"(" + IDENT + r")\"", src):
    called.add(m.group(1))


def split_args(text, start):
    """text[start] is just after '('; return (list of top-level args, index after ')')."""
    depth, cur, res, i, n = 0, [], [], start, len(text)
    while i < n:
        c = text[i]
        if c in "\"'":
            j = i + 1
            while j < n and text[j] != c:
                j += 2 if text[j] == "\\" else 1
            cur.append(text[i:j + 1]); i = j + 1; continue
        if c in "([{": depth += 1
        elif c in ")]}":
            if depth == 0:
                res.append("".join(cur).strip()); return res, i + 1
            depth -= 1
        elif c == "," and depth == 0:
            res.append("".join(cur).strip()); cur = []; i += 1; continue
        cur.append(c); i += 1
    return res, n


# Resolver macros are discovered per area (tests/<area>/): a #define whose body stringifies a parameter and passes it
# to a resolver. A macro defined more than once in an area is an X-macro list (a table that resolves or declares
# every entry at load time, not a call), and is skipped and reported.
macros, xlists = {}, set()
DEF = re.compile(r"^[ \t]*#[ \t]*define[ \t]+(" + IDENT + r")\(([^)]*)\)[ \t]*((?:[^\n]|\\\n)*)", re.M)
for area, text in areas.items():
    defs = {}
    for m in DEF.finditer(text):
        defs.setdefault(m.group(1), []).append(m)
    for name, ms in defs.items():
        if name in ("U", "UIN", "UN", "UA", "US", "UC", "UK", "UB", "UNT", "UINN"):
            continue
        if len(ms) > 1:
            if any(re.search(r"[Pp]roc", x.group(3)) for x in ms):
                xlists.add(os.path.basename(area) + ":" + name)
            continue
        m = ms[0]
        params, body = [p.strip() for p in m.group(2).split(",")], m.group(3).replace("\\\n", " ")
        if not re.search(RESOLVER_CALL + r"|\b(?:U|UIN|UN)\s*\(", body):
            continue
        # the name must reach the resolver whole: "CP" #n style prefixes do not name an export
        idxs = set()
        for idx, p in enumerate(params):
            if p and (re.search(r"(?<!\")\s#\s*" + re.escape(p) + r"\b", " " + body.replace("##", "  ")) or
                      re.search(r"\b(?:U|UIN|UN)\s*\(\s*(?:[^,()]*,\s*)?" + re.escape(p) + r"\s*\)", body)):
                idxs.add(idx)
        if not idxs:
            continue
        macros[(area, name)] = idxs
        for mm in re.finditer(r"(?<![\w#])" + re.escape(name) + r"\s*\(", text):
            ls = text.rfind("\n", 0, mm.start()) + 1
            if re.match(r"[ \t]*#[ \t]*define\b", text[ls:mm.start()]):
                continue
            a, _ = split_args(text, mm.end())
            for i in idxs:
                if i < len(a) and re.fullmatch(IDENT, a[i]):
                    (called_zero if re.search(r"\(\s*0\s*,\s*0\s*,\s*0\s*,\s*0\s*,", m.group(3)) else called).add(a[i])

called_zero -= called
word_cache = set(re.findall(r"\b" + IDENT + r"\b", src))
per = {}
for p in lists:
    mod = os.path.basename(p).replace("_exports.txt", "")
    per[mod] = [l.strip() for l in open(p) if l.strip()]
names = sorted({n for v in per.values() for n in v})
unc = [n for n in names if n not in called and n not in called_zero]
zonly = [n for n in names if n in called_zero]
ment = [n for n in unc if n not in word_cache]
print(f"{len(names)} unique exports; {len(names) - len(unc) - len(zonly)} called with real arguments; {len(zonly)} reached only by zero-argument probes; {len(unc)} not called; {len(ment)} never mentioned")
print("resolver macros found:", ", ".join(sorted({os.path.basename(a) + ":" + n for a, n in macros})) or "-")
print("X-macro lists skipped (table resolution, not a call):", ", ".join(sorted(xlists)) or "-")
open(os.path.join(root, "tools", "uncovered.txt"), "w").write("\n".join(unc) + "\n")
print("never mentioned:", ", ".join(ment[:80]), "..." if len(ment) > 80 else "")
print("wrote tools/uncovered.txt")
if table:
    print("\n| Module | Named exports | Called | Zero-argument probes only |\n|---|---:|---:|---:|")
    te = tc = tz = 0
    for mod in sorted(per):
        n = len(per[mod]); c = sum(1 for x in per[mod] if x in called); z = sum(1 for x in per[mod] if x in called_zero); te += n; tc += c; tz += z
        print(f"| {mod}.dll | {n} | {c} | {z} |")
    print(f"| total (rows summed; a name listed by several modules counts in each) | {te} | {tc} | {tz} |")
    print(f"| unique names | {len(names)} | {len(names) - len(unc) - len(zonly)} | {len(zonly)} |")
