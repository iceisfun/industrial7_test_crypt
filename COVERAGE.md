# Coverage

Static scan with `python tools/coverage.py .` (an export counts as called when a test resolves it with U/UIN/UN/t_proc and the call can be reached). Names that are only listed in export tables count as uncalled. Uncalled names are in `tools/uncovered.txt`.

| Module | Named exports | Called |
|---|---:|---:|
| advapi32.dll | 77 | 43 |
| bcrypt.dll | 58 | 57 |
| bcryptprimitives.dll | 10 | 4 |
| capisp.dll | 5 | 0 |
| certca.dll | 97 | 3 |
| certcli.dll | 164 | 7 |
| certenc.dll | 4 | 4 |
| certprop.dll | 3 | 3 |
| crypt32.dll | 295 | 242 |
| cryptbase.dll | 11 | 3 |
| cryptcatsvc.dll | 4 | 0 |
| cryptdlg.dll | 21 | 18 |
| cryptdll.dll | 20 | 0 |
| cryptext.dll | 35 | 4 |
| cryptnet.dll | 23 | 17 |
| cryptngc.dll | 69 | 4 |
| cryptowinrt.dll | 3 | 3 |
| cryptsp.dll | 65 | 41 |
| cryptui.dll | 56 | 31 |
| cryptxml.dll | 19 | 0 |
| dpapi.dll | 7 | 7 |
| dssenh.dll | 27 | 2 |
| keyiso.dll | 2 | 1 |
| msasn1.dll | 152 | 2 |
| mssign32.dll | 36 | 34 |
| mssip32.dll | 9 | 8 |
| ncrypt.dll | 149 | 102 |
| ncryptprov.dll | 3 | 3 |
| ntasn1.dll | 0 | 0 |
| rsaenh.dll | 27 | 2 |
| tbs.dll | 21 | 1 |
| wintrust.dll | 159 | 91 |
| total | 1631 | 737 |

The scan cannot see calls made through helper macros or wrapper tables (cryptxml `XFN`, msasn1/cryptdll wrappers,
tbs, capisp, cryptcatsvc, rsaenh/dssenh reached through CryptAcquireContext, certca/certcli templates), so those rows
understate real coverage; the areas below do exercise them. Remaining known gaps: cryptngc.dll (NGC/hello, hardware bound),
certca/certcli enrollment surface (needs a CA), most cryptext/cryptui wizard entry points (UI), msasn1 low-level encoder entry points.

## Tests per area and last emulator run

Columns: tests, failed, skipped (counts from the headless emulator run, which does not implement much of CNG/CAPI;
failures there are not proof of a wrong expectation, Windows 10 is the authority).

| Area | Tests | Failed | Skipped | Checks pass | Checks fail |
|---|---:|---:|---:|---:|---:|
| bcrypt_algorithm_providers | 768 | 601 | 17 | 2859 | 2848 |
| bcrypt_context_registry | 178 | 0 | 178 | 0 | 0 |
| bcrypt_ecc_dh_kdf | 353 | 79 | 163 | 736 | 286 |
| bcrypt_hash_hmac | 423 | 28 | 64 | 60440 | 683 |
| bcrypt_rng_primitives | 163 | 0 | 81 | 11960 | 0 |
| bcrypt_rsa_dsa | 187 | 71 | 0 | 936 | 241 |
| bcrypt_symmetric_ciphers | 319 | 0 | 131 | 1319 | 0 |
| capi_asymmetric_blobs | 173 | 19 | 50 | 1562 | 100 |
| capi_cp_direct | 310 | 106 | 7 | 5946 | 420 |
| capi_hash_mac | 198 | 18 | 1 | 45471 | 145 |
| capi_provider_context | 500 | 194 | 129 | 4998 | 1103 |
| capi_symmetric_keys | 173 | 29 | 4 | 2140 | 189 |
| certca_certcli_templates | 263 | 0 | 263 | 0 | 0 |
| core_smoke | 3 | 0 | 0 | 4 | 0 |
| crypt32_asn_keys_pkcs_misc | 345 | 42 | 90 | 2237 | 99 |
| crypt32_asn_names_extensions | 190 | 45 | 0 | 8408 | 339 |
| crypt32_cert_context_props | 306 | 84 | 15 | 2685 | 302 |
| crypt32_cert_store_memory | 287 | 26 | 12 | 904 | 51 |
| crypt32_chain_build | 311 | 7 | 79 | 1045 | 9 |
| crypt32_chain_policy | 345 | 159 | 0 | 845 | 577 |
| crypt32_crl_ctl_revocation | 256 | 28 | 41 | 1132 | 85 |
| crypt32_msg_high_level | 268 | 72 | 58 | 1166 | 212 |
| crypt32_msg_low_level | 263 | 51 | 25 | 1582 | 119 |
| crypt32_oid_framework | 305 | 114 | 104 | 4675 | 770 |
| crypt32_pfx_pkcs8 | 156 | 0 | 136 | 50 | 0 |
| crypt32_string_formats | 356 | 144 | 0 | 20889 | 10218 |
| crypt32_system_stores_readonly | 129 | 0 | 37 | 1644 | 0 |
| cryptdll_kerberos_crypto | 249 | 0 | 228 | 338 | 0 |
| cryptnet_url_retrieval_offline | 126 | 32 | 45 | 834 | 170 |
| cryptxml_signatures | 219 | 0 | 217 | 22 | 0 |
| dpapi_protect_data | 248 | 4 | 132 | 526 | 4 |
| dx_bcrypt_context_config | 117 | 0 | 116 | 1 | 0 |
| dx_capi_containers | 475 | 87 | 196 | 2152 | 541 |
| dx_crypt32_oid_registry | 203 | 0 | 74 | 790 | 0 |
| dx_crypt32_pfx_persisted | 143 | 0 | 142 | 3 | 0 |
| dx_crypt32_system_stores | 205 | 0 | 110 | 562 | 0 |
| dx_gap_00 | 12 | 0 | 12 | 0 | 0 |
| dx_gap_01 | 9 | 1 | 0 | 31 | 2 |
| dx_ncrypt_persisted_keys | 97 | 0 | 96 | 1 | 0 |
| dx_ncrypt_protection_register | 82 | 0 | 82 | 0 | 0 |
| dx_wintrust_config | 209 | 0 | 126 | 752 | 0 |
| exports_cng_capi | 358 | 26 | 85 | 20161 | 164 |
| exports_crypt32_wintrust_family | 313 | 0 | 164 | 3420 | 0 |
| gap_00 | 40 | 0 | 39 | 1 | 0 |
| gap_01 | 185 | 26 | 85 | 894 | 98 |
| gap_02 | 57 | 0 | 45 | 26 | 0 |
| misc_crypto_modules_resolve | 164 | 3 | 147 | 554 | 26 |
| msasn1_ber_encoder_decoder | 412 | 0 | 397 | 115 | 0 |
| mssign32_signer | 135 | 0 | 131 | 28 | 0 |
| ncrypt_protection_descriptors | 170 | 0 | 169 | 19 | 0 |
| ncrypt_provider_ephemeral_keys | 194 | 53 | 84 | 408 | 159 |
| sip_catalog_wintrust | 169 | 97 | 24 | 519 | 363 |
| systemfunction_rtl_crypto | 201 | 32 | 64 | 5971 | 335 |
| tbs_tpm_base_services | 137 | 0 | 124 | 150 | 0 |
| ui_crypto_dialogs | 194 | 0 | 158 | 134 | 0 |
| winrt_cryptography | 301 | 0 | 286 | 36 | 0 |
| wintrust_catalog_files | 201 | 0 | 166 | 204 | 0 |
| wintrust_verify_trust | 223 | 63 | 49 | 1688 | 130 |

Total tests (including generated table-driven cases): 13376.
