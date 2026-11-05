# bcrypt.dll conformance corpus

Black-box tests for Windows 10 x64 `bcrypt.dll`. The DLL is never linked: each test loads it with `LoadLibrary`,
resolves entry points with `GetProcAddress` (`U(Name)` gives a pointer typed from the SDK header;
`UIN("module.dll", Name)` pins one module, which matters for forwarders) and calls through the pointer.

Modules searched by `U()`: bcrypt.dll bcryptprimitives.dll ncrypt.dll ncryptprov.dll crypt32.dll cryptsp.dll cryptbase.dll cryptdll.dll cryptnet.dll cryptui.dll cryptxml.dll cryptdlg.dll cryptext.dll cryptngc.dll cryptowinrt.dll cryptcatsvc.dll dpapi.dll rsaenh.dll dssenh.dll msasn1.dll ntasn1.dll wintrust.dll mssign32.dll mssip32.dll capisp.dll tbs.dll keyiso.dll certca.dll certcli.dll certenc.dll certprop.dll advapi32.dll ntdll.dll kernel32.dll.

    make                         # cross-compile build/<area>.exe (mingw-w64)
    build\<area>.exe [substr]    # on Windows; optional test-name filter
    tools\run_all.bat            # everything, results\<area>.txt (add /destructive for dx_* areas)
    python tools\summarize.py results [--failures]

Output: `RUN/OK/FAIL/SKIP` per test, `  FAIL file:line expr (detail)` per failed check, `SUMMARY` last;
exit code 1 if any test failed. `NOTE` lines record observed, version-dependent behaviour.

Tests that need a second process re-launch the exe (`--child <name>`). Scratch files live in
`%TEMP%\cryptt_<pid>\` and are removed on exit. `tools/*_exports.txt` list the named exports.

See `HANDOFF.md` (when present) for how to run and triage the Windows passes.
