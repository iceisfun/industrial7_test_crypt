# HANDOFF: Windows 10 pass for the crypto corpus

For the lane that runs the corpus on a real Windows 10 x64 machine.

## Purpose
This corpus asserts the behaviour of the Windows 10 x64 crypto stack (bcrypt.dll and the other crypto
modules listed in README.md; schannel is out of scope) as seen through LoadLibrary / GetProcAddress /
call. It is meant to be read by someone implementing bcrypt.dll, so every hard CHECK should hold on a
genuine Windows 10. So far it was only run under an emulator, headless, as a smoke check. Windows 10
results are the authority: expect some wrong expectations on the first real run and treat them as test bugs.

## Prerequisites
- Disposable Windows 10 SP1/22H2 x64 VM with a snapshot, no domain, no network needed (nothing contacts any host).
- A standard user account and an elevated administrator account. Both passes matter, several areas skip when unprivileged.
- Build host: Linux with mingw-w64 (`x86_64-w64-mingw32-gcc`) and make. Or copy a prebuilt `build\` folder.
- Python 3 on the VM is optional (only for `tools\summarize.py`).
- A TPM is not required; `tbs_*` records absence with t_skip/t_note.

## Build
    make clean && make -j8        # build/<area>.exe, static, DLL under test never linked

## Run (revert the snapshot between passes)
1. Standard user:                 `tools\run_all.bat`
2. Elevated admin:                `tools\run_all.bat`
3. Elevated admin, destructive:   `tools\run_all.bat /destructive`   (adds the dx_* areas)
4. Optional standard user, destructive: same command without elevation (dx_* areas skip what needs admin).
Single area or test: `build\<area>.exe <name-substring>`. Each exe has a 600 s limit in run_all.bat.
Exit code is 1 when any test failed; the last line is `SUMMARY tests= failed= skipped= checks_pass= checks_fail=`.

## Result collection
Output goes to `build\results\<area>.txt`. Zip the folder, then
`python tools\summarize.py build\results --failures` for totals and the failing checks.
`NOTE` lines are observations of version dependent behaviour; collect them too, they document the
real machine (build number, locale, SKU).

## Triage
Classify every failing check:
1. Wrong expectation: Windows differs from the test. Check the decompilation
   (http://docker1.dev.moonlightcompanies.com:8765/api/function/<module>/<Name>/decomp) and the docs, fix the test.
2. Environment/SKU: locale, privilege, filesystem, hardware, policy. Turn the check into t_note or t_skip.
3. Real divergence: only meaningful once a test is known to be right; record it as a finding.
Fix, rebuild, rerun only that test, commit with a short message (area prefix, no co-author lines).
Do not weaken a check just to get green without evidence from the decomp or the machine.

## Expected skips
- Standard user: dx_bcrypt_context_config (HKLM CNG config), dx_capi_containers machine keysets,
  dx_crypt32_system_stores (LOCAL_MACHINE writes), dx_ncrypt_protection_register, dx_wintrust_config (HKLM) mostly skip.
- Elevated: tests that need an unelevated token skip ("process is elevated").
- No TPM: tbs_tpm_base_services device/command tests skip.
- Emulator-only guards (`t_is_wine`) never trigger on Windows.
- ui_crypto_dialogs: runs silent variants only; it must not leave a window open. Run it on an interactive session.
- Non-domain machines skip group policy store cases that need a GPO.

## Known weak spots
- Under the emulator these areas had many failures, which mostly show the emulator's gaps, but they are the most
  likely to contain real wrong expectations as well: bcrypt_algorithm_providers, bcrypt_rsa_dsa, bcrypt_ecc_dh_kdf,
  capi_cp_direct, bcrypt_hash_hmac (see COVERAGE.md for the per-area table of the last emulator run).
- Areas whose expectations depend on the certificate trust store of the machine: crypt32_system_stores_readonly,
  crypt32_chain_build, crypt32_chain_policy, wintrust_verify_trust.
- Anything involving locale text (string formats, FormatMessage-like output).

## Cleanup of leftovers (after a crashed destructive run)
All names contain `cryptt` and the pid. Scratch files: `%TEMP%\cryptt_*`. Remove with
`rmdir /s /q %TEMP%\cryptt_*` (run per folder) or `for /d %d in (%TEMP%\cryptt_*) do rmdir /s /q "%d"`.
Registry (elevated): look for values/keys containing `cryptt` under
`HKCU\Software\Microsoft\SystemCertificates`, `HKLM\SOFTWARE\Microsoft\Cryptography\OID`,
`HKLM\SOFTWARE\Microsoft\Cryptography\NProtect`, `HKLM\SOFTWARE\Microsoft\Cryptography\Providers`,
`HKLM\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration`,
`HKLM\SOFTWARE\Microsoft\Cryptography\Providers\Trust`. Key containers named `cryptt*`:
`certutil -user -delkey cryptt...` / `certutil -csp "Microsoft Enhanced Cryptographic Provider v1.0" -key`.
The simplest full cleanup is reverting the VM snapshot. Each dx_ area also sweeps stale names at start.

## Report back
Totals per area (tests, failed, skipped), the list of wrong expectations fixed (commit ids), the list of real
divergences with the exact value Windows returned, the areas that could not run and why, the OS build number,
locale, elevation level and whether a TPM was present.
