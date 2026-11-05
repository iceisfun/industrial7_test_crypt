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

## Areas

Every directory under `tests/` builds to `build/<area>.exe`. Names group by surface:

| Prefix | Surface |
|---|---|
| `bcrypt_*` | CNG primitives: providers, hash/HMAC, symmetric ciphers, RSA/DSA, ECC/DH/KDF, RNG, context registry |
| `ncrypt_*` | key storage provider with ephemeral keys, protection descriptors |
| `capi_*`, `systemfunction_rtl_crypto`, `dpapi_*` | legacy CryptoAPI (rsaenh/dssenh/cryptsp), RtlEncrypt family, DPAPI |
| `crypt32_*` | ASN.1 encode/decode, stores (memory and read-only system), certificate contexts, chains and policy, CRL/CTL, messages, OID framework, PFX/PKCS8, string formats |
| `cryptnet_*`, `cryptxml_*`, `cryptdll_*`, `msasn1_*`, `certca_*`, `tbs_*`, `mssign32_*` | the remaining crypto modules |
| `wintrust_*`, `sip_catalog_wintrust` | Authenticode, catalogs, SIP |
| `winrt_cryptography`, `misc_crypto_modules_resolve`, `exports_*`, `gap_*` | WinRT crypto, module/export resolution, export tables, gap fill |
| `ui_crypto_dialogs` | the only area allowed to touch dialogs (all with silent/no-UI variants where possible) |
| `dx_*` | state-changing areas (registry, key containers, system stores, OID registry, config) |

Excluded on purpose: schannel.dll, SSPI/Schannel credentials, the `Ssl*` exports of ncrypt.dll (resolved by name at most, never called), TLS.

## Safety rules the code follows

- No network. Revocation and URL retrieval use file:// URLs, cache-only flags (`CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL`, `CRYPT_CACHE_ONLY_RETRIEVAL`, `WTD_REVOCATION_CHECK_NONE`) and timeout 0.
- No UI outside `ui_crypto_dialogs`.
- Non-`dx_` areas use ephemeral keys and memory stores; system stores are opened read-only.
- `dx_*` areas gate on privilege (`t_skip` otherwise), use names containing `cryptt` and the pid, sweep leftovers at start, and restore state at the end. They never touch the ROOT store trust, FIPS policy, TPM, or machine keys.
- Windows 10 behaviour is the authority; expectations are based on values observed on Windows 10 and on the public documentation. Anything version/locale/SKU dependent is a `t_note`.

## Running on Windows

    make                              # on the Linux build host (mingw-w64), copy build\ to the VM
    tools\run_all.bat                 # non-destructive areas, results in build\results\
    tools\run_all.bat /destructive    # also dx_* areas (disposable VM, elevated)
    python tools\summarize.py build\results --failures

See `HANDOFF.md` for the full procedure and `COVERAGE.md` for what is covered.
Headless validation on Linux: `tools/wine_run.sh build/<area>.exe [filter]` (throw-away prefix, no X).
