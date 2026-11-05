# Harness helpers (common/t.h)

Rules of the road
- Win10 22H2 is the authority. Pin an exact observed value; never widen with `||`. Probe first with `PROBE_CALL(call)`
  (prints `PROBE ... ret=0x.. err=0x.. (NAME)` and never fails), run on the oracle, then replace by the exact expectation.
- Tests run in REVERSE order of declaration (constructor order). Do not depend on order between tests.
- Last error is meaningful only after a call that FAILED. Order: `SET_ERR(0)` -> call -> check the return value -> check the error.

Assertions (all evaluate each argument once)
- `EXPECT_EQ/NE(a,b)`: both operands <= 4 bytes compare as 32 bit (HRESULT vs `0x80090005` literal is fine); pointers/64 bit exact.
- `EXPECT_STR/WSTR`, `EXPECT_ERR(code)` (reads GetLastError first), `EXPECT_FAIL(is_failure_expr, code)`.
- `EXPECT_FAILS(call, code)` call must return 0/FALSE/NULL and set code; `EXPECT_FAILS_RET(call, sentinel, code)`;
  `EXPECT_SUCCEEDS(call)`; `T_CALL_ERR(&e, call)`; `T_LASTERR_AFTER(call)`.
- `EXPECT_CAPI_FAIL(call, code)` / `EXPECT_CAPI_OK(call)` for legacy CryptoAPI BOOL calls; failures print `0x%08lx NAME`.
  Rule observed on Win10: bad/zero handle, NULL out pointer -> ERROR_INVALID_PARAMETER (87) from advapi32 before the CSP is
  called; NTE_* only for a valid handle with a bad value (see the comment block in t.h). Pin per call.
- `EXPECT_GPA_FAIL(hmod, "name" | MAKEINTRESOURCEA(ord))`: name -> 127, ordinal 0 -> 87, any other bad ordinal -> 182, bad module -> 126.
- `EXPECT_SIZE_QUERY(query, final, want_final)` (query >= final and final == want, checked separately), `..._EXACT`.
- `t_label("stage %d", n)` appends `[stage n]` to every FAIL/NOTE of the test (cleared per test): use it in table driven
  loops and in a_enc_eq style helpers so failures sharing a file:line stay distinguishable.

Aborting
- `REQUIRE_OK(expr)`, `REQUIRE_NOTNULL(p)`, `REQUIRE_EQ(a,b)`, `REQUIRE_SANE_SIZE(cb)`: count a FAIL and `return` from the TEST.
  In helpers returning a value use `if (!t_require(cond, __FILE__, __LINE__, "text")) return X;`.
- `REQUIRE(ptr)` is unchanged: skip when an export is missing.

Faults and hangs
- Every run is supervised (worker process in a job): a test over its budget (default 60 s, env `T_TIMEOUT_S`, per test
  `t_set_timeout(s)`) prints `TIMEOUT <test>` + `FAIL <test>`, the worker tree is killed and the run resumes with the next test;
  a dying worker is reported as `FAIL worker process died` and resumed. SUMMARY gets `timeouts=` / `crashes=` when non-zero.
- An unhandled fault in a test is `FAIL exception ...` for that test only. Faults that the code under test handles itself
  are not failures. `T_TRY(stmt)` / `T_TRY_BEGIN ... T_TRY_END("what")` contain a fault to one statement (still a FAIL);
  `T_EXPECT_FAULT(stmt)` passes only if stmt faults. No `return`/`break` out of a T_TRY block; locals read after a fault must be volatile.
- `T_INPROC=1` runs without the supervisor (debugger / wine).

Environment (all cached; each REQUIRE_* skips with a reason)
- `t_is_elevated()`, `t_is_destructive()` (ORACLE_DESTRUCTIVE=1), `t_join_status()`/`t_is_domain_joined()`, `t_has_tpm()`/`t_tpm_status()`.
- `REQUIRE_ELEVATED()`, `REQUIRE_NOT_ELEVATED()`, `REQUIRE_DESTRUCTIVE()`, `REQUIRE_WORKGROUP()`, `REQUIRE_DOMAIN()`, `REQUIRE_TPM()`, `REQUIRE_NO_TPM()`.
- The supervisor prints one `ENV area=.. elevated=.. destructive=.. join=.. tpm=0x.. wine=..` line first.

Registrations and cleanup (dx_* areas)
- Names: `t_unique("tag")` / `t_unique_w("tag")` -> `I7T_<area>_<tag>_<pid>_<n>`; everything an area registers must start with `t_area_prefix()`.
- `T_SWEEPER(name) { ... }` body sees `phase` (`T_SWEEP_START` before the first test, `T_SWEEP_END` after the last) and `prefix`;
  use `t_reg_sweep_subkeys(root, path, prefix)` / `t_reg_sweep_values(...)` plus your own provider/store/descriptor removal.
  A worker that is restarted after a TIMEOUT/crash does not repeat the start sweep.
- `t_defer(fn, arg)` runs fn at the end of the current test (even after fail/skip/fault/REQUIRE return), LIFO.

Self-test: `make selftest` builds build/selftest.exe. Default run must be all OK on std and adm (13 fault-only tests skip);
with `SELFTEST_FAULTS=1 T_TIMEOUT_S=5` it must show the contained failures described next to each stf_* test.
