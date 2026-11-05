/* BASE policy (CERT_CHAIN_POLICY_BASE) driven with hand-built chain contexts: maps TrustStatus bits to the
 * documented dwError values, the first-error element/chain index, and the CERT_CHAIN_POLICY_*_FLAG overrides. */
#include "cp.h"

typedef struct { int kind; int c, e; DWORD err, info; DWORD rev; } MARK;   /* kind: 'E' element, 'C' chain-level, 'X' context-level only */
typedef struct {
    int nchain; int nel[SYN_MAXC];
    DWORD ctxerr, ctxinfo;
    MARK m[4];
    DWORD flags;
    DWORD want; LONG wci, wei;
    int soft;       /* lower-confidence (inferred multi-element revocation logic): mismatch is only noted */
} ROW;

static void run_row(const char *name, const ROW *r) {
    SYN s; PRES p;
    if (!U(CertVerifyCertificateChainPolicy)) { t_skip("missing export"); return; }
    syn_init(&s, r->nchain ? r->nchain : 1, r->nchain ? r->nel : (int[]){3});
    syn_ctx(&s, r->ctxerr, r->ctxinfo);
    for (int i = 0; i < 4; i++) {
        const MARK *m = &r->m[i];
        if (!m->kind) continue;
        if (m->kind == 'E') { syn_el(&s, m->c, m->e, m->err, m->info); if (m->rev) syn_rev(&s, m->c, m->e, m->rev); }
        else if (m->kind == 'C') syn_chain(&s, m->c, m->err, m->info);
    }
    p = cp_run(CERT_CHAIN_POLICY_BASE, &s.cc, r->flags, NULL);
    CHECKF(p.ret, "%s: call returned FALSE", name);
    if (r->soft) {
        if (p.err != r->want || p.ci != r->wci || p.ei != r->wei)
            t_note("%s: got err=0x%08lx ci=%ld ei=%ld, expected err=0x%08lx ci=%ld ei=%ld", name, p.err, p.ci, p.ei, r->want, r->wci, r->wei);
        return;
    }
    CHECKF(p.err == r->want, "%s: dwError got 0x%08lx want 0x%08lx", name, p.err, r->want);
    CHECKF(p.ci == r->wci, "%s: lChainIndex got %ld want %ld", name, p.ci, r->wci);
    CHECKF(p.ei == r->wei, "%s: lElementIndex got %ld want %ld", name, p.ei, r->wei);
}

#define EL(c_, e_, err_, info_) {'E', c_, e_, err_, info_, 0}
#define ELR(c_, e_, err_, info_, rev_) {'E', c_, e_, err_, info_, rev_}
#define CH(c_, err_) {'C', c_, 0, err_, 0, 0}
#define ROWT(nm, ...) TEST(base_synth_##nm) { static const ROW r = { __VA_ARGS__ }; run_row(#nm, &r); }
/* ROW fields: nchain,{nel},ctxerr,ctxinfo,{marks},flags,want,wci,wei,soft */

ROWT(no_errors, 0,{0}, 0,0, {{0}}, 0, 0, -1, -1)
ROWT(no_errors_all_flags, 0,{0}, 0,0, {{0}}, 0xFFFFFFFF, 0, -1, -1)
ROWT(sig_invalid, 0,{0}, 0x8,0, {EL(0,1,0x8,0)}, 0, TERR_CERT_SIGNATURE, 0, 1)
ROWT(sig_invalid_leaf, 0,{0}, 0x8,0, {EL(0,0,0x8,0)}, 0, TERR_CERT_SIGNATURE, 0, 0)
ROWT(sig_invalid_first_element_wins, 0,{0}, 0x8,0, {EL(0,2,0x8,0), EL(0,1,0x8,0)}, 0, TERR_CERT_SIGNATURE, 0, 1)
ROWT(sig_invalid_second_chain, 2,{2,2}, 0x8,0, {EL(1,1,0x8,0)}, 0, TERR_CERT_SIGNATURE, 1, 1)
ROWT(sig_invalid_not_ignorable, 0,{0}, 0x8,0, {EL(0,1,0x8,0)}, 0x7FFF, TERR_CERT_SIGNATURE, 0, 1)
ROWT(ctl_sig_invalid, 0,{0}, 0x40000,0, {EL(0,0,0x40000,0)}, 0, TERR_CERT_SIGNATURE, 0, 0)
ROWT(explicit_distrust, 0,{0}, 0x4000000,0, {EL(0,1,0x4000000,0)}, 0, CRYPTERR_REVOKED, 0, 1)
ROWT(explicit_distrust_not_ignorable, 0,{0}, 0x4000000,0, {EL(0,2,0x4000000,0)}, 0x7FFF, CRYPTERR_REVOKED, 0, 2)
ROWT(untrusted_root, 0,{0}, 0x20,0, {EL(0,2,0x20,0)}, 0, CERR_UNTRUSTEDROOT, 0, 2)
ROWT(untrusted_root_allow_unknown_ca, 0,{0}, 0x20,0, {EL(0,2,0x20,0)}, CERT_CHAIN_POLICY_ALLOW_UNKNOWN_CA_FLAG, 0, -1, -1)
ROWT(untrusted_root_allow_testroot_nomatch, 0,{0}, 0x20,0, {EL(0,2,0x20,0)}, CERT_CHAIN_POLICY_ALLOW_TESTROOT_FLAG, CERR_UNTRUSTEDROOT, 0, 2)
ROWT(untrusted_root_trust_testroot_alone, 0,{0}, 0x20,0, {EL(0,2,0x20,0)}, CERT_CHAIN_POLICY_TRUST_TESTROOT_FLAG, CERR_UNTRUSTEDROOT, 0, 2)
ROWT(untrusted_root_both_testroot_flags_nomatch, 0,{0}, 0x20,0, {EL(0,2,0x20,0)}, 0xC000, CERR_UNTRUSTEDROOT, 0, 2)
ROWT(untrusted_root_single_element, 1,{1}, 0x20,0, {EL(0,0,0x20,8)}, 0, CERR_UNTRUSTEDROOT, 0, 0)
ROWT(untrusted_root_context_only_no_element, 0,{0}, 0x20,0, {{0}}, 0, CERR_UNTRUSTEDROOT, -1, -1)
ROWT(partial_chain, 0,{0}, 0x10000,0, {CH(0,0x10000)}, 0, CERR_CHAINING, 0, -1)
ROWT(partial_chain_second_chain, 2,{2,2}, 0x10000,0, {CH(1,0x10000)}, 0, CERR_CHAINING, 1, -1)
ROWT(partial_chain_first_flagged_chain_wins, 3,{2,2,2}, 0x10000,0, {CH(2,0x10000), CH(1,0x10000)}, 0, CERR_CHAINING, 1, -1)
ROWT(partial_chain_allow_unknown_ca, 0,{0}, 0x10000,0, {CH(0,0x10000)}, CERT_CHAIN_POLICY_ALLOW_UNKNOWN_CA_FLAG, 0, -1, -1)
ROWT(partial_chain_other_flags_irrelevant, 0,{0}, 0x10000,0, {CH(0,0x10000)}, 0x7FEF, CERR_CHAINING, 0, -1)
ROWT(untrusted_beats_partial, 0,{0}, 0x20|0x10000,0, {EL(0,2,0x20,0), CH(0,0x10000)}, 0, CERR_UNTRUSTEDROOT, 0, 2)
ROWT(allow_unknown_ca_clears_both, 0,{0}, 0x20|0x10000,0, {EL(0,2,0x20,0), CH(0,0x10000)}, 0x10, 0, -1, -1)
ROWT(revoked, 0,{0}, 0x4,0, {EL(0,1,0x4,0)}, 0, CRYPTERR_REVOKED, 0, 1)
ROWT(revoked_leaf, 0,{0}, 0x4,0, {EL(0,0,0x4,0)}, 0, CRYPTERR_REVOKED, 0, 0)
ROWT(revoked_not_ignorable, 0,{0}, 0x4,0, {EL(0,0,0x4,0)}, 0x7FFB, CRYPTERR_REVOKED, 0, 0)
ROWT(wrong_usage_element, 0,{0}, 0x10,0, {EL(0,0,0x10,0)}, 0, CERR_WRONG_USAGE, 0, 0)
ROWT(wrong_usage_ignored, 0,{0}, 0x10,0, {EL(0,0,0x10,0)}, CERT_CHAIN_POLICY_IGNORE_WRONG_USAGE_FLAG, 0, -1, -1)
ROWT(wrong_usage_ctl_chain_level, 0,{0}, 0x80000,0, {CH(0,0x80000)}, 0, CERR_WRONG_USAGE, 0, -1)
ROWT(wrong_usage_ctl_ignored, 0,{0}, 0x80000,0, {CH(0,0x80000)}, 0x20, 0, -1, -1)
ROWT(wrong_usage_ctl_second_chain, 2,{2,2}, 0x80000,0, {CH(1,0x80000)}, 0, CERR_WRONG_USAGE, 1, -1)
ROWT(expired_leaf, 0,{0}, 0x1,0, {EL(0,0,0x1,0)}, 0, CERR_EXPIRED, 0, 0)
ROWT(expired_ca, 0,{0}, 0x1,0, {EL(0,1,0x1,0)}, 0, CERR_EXPIRED, 0, 1)
ROWT(expired_ignored, 0,{0}, 0x1,0, {EL(0,1,0x1,0)}, CERT_CHAIN_POLICY_IGNORE_NOT_TIME_VALID_FLAG, 0, -1, -1)
ROWT(expired_not_ignored_by_ctl_flag, 0,{0}, 0x1,0, {EL(0,1,0x1,0)}, CERT_CHAIN_POLICY_IGNORE_CTL_NOT_TIME_VALID_FLAG, CERR_EXPIRED, 0, 1)
ROWT(ctl_time_invalid, 0,{0}, 0x20000,0, {CH(0,0x20000)}, 0, CERR_EXPIRED, 0, -1)
ROWT(ctl_time_invalid_ignored, 0,{0}, 0x20000,0, {CH(0,0x20000)}, CERT_CHAIN_POLICY_IGNORE_CTL_NOT_TIME_VALID_FLAG, 0, -1, -1)
ROWT(ctl_time_invalid_not_ignored_by_cert_flag, 0,{0}, 0x20000,0, {CH(0,0x20000)}, CERT_CHAIN_POLICY_IGNORE_NOT_TIME_VALID_FLAG, CERR_EXPIRED, 0, -1)
ROWT(name_constraint_invalid, 0,{0}, 0x800,0, {EL(0,0,0x800,0)}, 0, CERR_INVALID_NAME, 0, 0)
ROWT(name_constraint_unsupported, 0,{0}, 0x1000,0, {EL(0,1,0x1000,0)}, 0, CERR_INVALID_NAME, 0, 1)
ROWT(name_constraint_undefined, 0,{0}, 0x2000,0, {EL(0,1,0x2000,0)}, 0, CERR_INVALID_NAME, 0, 1)
ROWT(name_constraint_not_permitted, 0,{0}, 0x4000,0, {EL(0,1,0x4000,0)}, 0, CERR_INVALID_NAME, 0, 1)
ROWT(name_constraint_excluded, 0,{0}, 0x8000,0, {EL(0,1,0x8000,0)}, 0, CERR_INVALID_NAME, 0, 1)
ROWT(name_constraint_ignored, 0,{0}, 0xF800,0, {EL(0,1,0xF800,0)}, CERT_CHAIN_POLICY_IGNORE_INVALID_NAME_FLAG, 0, -1, -1)
ROWT(policy_constraints_invalid, 0,{0}, 0x200,0, {EL(0,1,0x200,0)}, 0, CERR_INVALID_POLICY, 0, 1)
ROWT(no_issuance_chain_policy, 0,{0}, 0x2000000,0, {EL(0,1,0x2000000,0)}, 0, CERR_INVALID_POLICY, 0, 1)
ROWT(policy_ignored, 0,{0}, 0x2000200,0, {EL(0,1,0x2000200,0)}, CERT_CHAIN_POLICY_IGNORE_INVALID_POLICY_FLAG, 0, -1, -1)
ROWT(basic_constraints_invalid, 0,{0}, 0x400,0, {EL(0,1,0x400,0)}, 0, TERR_BASIC_CONSTRAINTS, 0, 1)
ROWT(basic_constraints_ignored, 0,{0}, 0x400,0, {EL(0,1,0x400,0)}, CERT_CHAIN_POLICY_IGNORE_INVALID_BASIC_CONSTRAINTS_FLAG, 0, -1, -1)
ROWT(critical_ext_unsupported, 0,{0}, 0x8000000,0, {EL(0,0,0x8000000,0)}, 0, CERR_CRITICAL, 0, 0)
ROWT(critical_ext_ignored, 0,{0}, 0x8000000,0, {EL(0,0,0x8000000,0)}, CERT_CHAIN_POLICY_IGNORE_NOT_SUPPORTED_CRITICAL_EXT_FLAG, 0, -1, -1)
ROWT(time_nesting, 0,{0}, 0x2,0, {EL(0,0,0x2,0)}, 0, CERR_VALIDITYNEST, 0, 0)
ROWT(time_nesting_ignored, 0,{0}, 0x2,0, {EL(0,0,0x2,0)}, CERT_CHAIN_POLICY_IGNORE_NOT_TIME_NESTED_FLAG, 0, -1, -1)
ROWT(time_nesting_ignored_by_all_not_time_valid, 0,{0}, 0x2,0, {EL(0,0,0x2,0)}, CERT_CHAIN_POLICY_IGNORE_ALL_NOT_TIME_VALID_FLAGS, 0, -1, -1)
ROWT(time_nesting_not_ignored_by_not_time_valid, 0,{0}, 0x2,0, {EL(0,0,0x2,0)}, 0x1, CERR_VALIDITYNEST, 0, 0)
ROWT(unmapped_invalid_extension, 0,{0}, 0x100,0, {EL(0,0,0x100,0)}, 0, 0, -1, -1)
ROWT(unmapped_cyclic, 0,{0}, 0x80,0, {EL(0,0,0x80,0)}, 0, 0, -1, -1)
ROWT(unmapped_offline_revocation, 0,{0}, 0x1000000,0, {EL(0,0,0x1000000,0)}, 0, 0, -1, -1)
ROWT(unmapped_weak_signature, 0,{0}, 0x100000,0, {EL(0,1,0x100000,0)}, 0, 0, -1, -1)
ROWT(peer_trusted_overrides_errors, 0,{0}, 0x20,0x800, {EL(0,2,0x20,0)}, 0, 0, -1, -1)
ROWT(peer_trusted_ignore_peer_flag, 0,{0}, 0x20,0x800, {EL(0,2,0x20,0)}, CERT_CHAIN_POLICY_IGNORE_PEER_TRUST_FLAG, CERR_UNTRUSTEDROOT, 0, 2)
ROWT(peer_trusted_but_leaf_expired, 0,{0}, 0x20|0x1,0x800, {EL(0,0,0x1,0), EL(0,2,0x20,0)}, 0, CERR_EXPIRED, 0, 0)
ROWT(no_peer_trust_expired_and_untrusted, 0,{0}, 0x20|0x1,0, {EL(0,0,0x1,0), EL(0,2,0x20,0)}, 0, CERR_UNTRUSTEDROOT, 0, 2)
ROWT(multiple_chains_first_error_element, 3,{2,2,2}, 0x1,0, {EL(2,0,0x1,0), EL(1,1,0x1,0)}, 0, CERR_EXPIRED, 1, 1)

/* ---- revocation unknown (0x40) ---- */
ROWT(revunk_no_check_leaf, 0,{0}, 0x40,0, {ELR(0,0,0x40,0,CRYPTERR_NO_REVOCATION_CHECK)}, 0, CRYPTERR_NO_REVOCATION_CHECK, 0, 0)
ROWT(revunk_no_check_ca, 0,{0}, 0x40,0, {ELR(0,1,0x40,0,CRYPTERR_NO_REVOCATION_CHECK)}, 0, CRYPTERR_NO_REVOCATION_CHECK, 0, 1)
ROWT(revunk_offline_leaf, 0,{0}, 0x40,0, {ELR(0,0,0x40,0,CRYPTERR_REVOCATION_OFFLINE)}, 0, CRYPTERR_REVOCATION_OFFLINE, 0, 0)
ROWT(revunk_other_result_maps_to_offline, 0,{0}, 0x40,0, {ELR(0,0,0x40,0,0x80092011u)}, 0, CRYPTERR_REVOCATION_OFFLINE, 0, 0)
ROWT(revunk_not_found_in_db_maps_to_offline, 0,{0}, 0x40,0, {ELR(0,0,0x40,0,0x80092014u)}, 0, CRYPTERR_REVOCATION_OFFLINE, 0, 0)
ROWT(revunk_ignore_end, 0,{0}, 0x40,0, {ELR(0,0,0x40,0,CRYPTERR_NO_REVOCATION_CHECK)}, CERT_CHAIN_POLICY_IGNORE_END_REV_UNKNOWN_FLAG, 0, -1, -1)
ROWT(revunk_ignore_end_but_ca_flagged, 0,{0}, 0x40,0, {ELR(0,0,0x40,0,CRYPTERR_NO_REVOCATION_CHECK), ELR(0,1,0x40,0,CRYPTERR_NO_REVOCATION_CHECK)}, 0x100, CRYPTERR_NO_REVOCATION_CHECK, 0, 1)
ROWT(revunk_ignore_ca, 0,{0}, 0x40,0, {ELR(0,1,0x40,0,CRYPTERR_NO_REVOCATION_CHECK)}, CERT_CHAIN_POLICY_IGNORE_CA_REV_UNKNOWN_FLAG, 0, -1, -1)
ROWT(revunk_ignore_ca_does_not_cover_end, 0,{0}, 0x40,0, {ELR(0,0,0x40,0,CRYPTERR_NO_REVOCATION_CHECK)}, 0x400, CRYPTERR_NO_REVOCATION_CHECK, 0, 0)
ROWT(revunk_ignore_all, 0,{0}, 0x40,0, {ELR(0,0,0x40,0,CRYPTERR_NO_REVOCATION_CHECK), ELR(0,1,0x40,0,CRYPTERR_REVOCATION_OFFLINE)}, CERT_CHAIN_POLICY_IGNORE_ALL_REV_UNKNOWN_FLAGS, 0, -1, -1)
ROWT(revunk_ignore_root, 0,{0}, 0x40,0, {ELR(0,2,0x40,8,CRYPTERR_NO_REVOCATION_CHECK)}, CERT_CHAIN_POLICY_IGNORE_ROOT_REV_UNKNOWN_FLAG, 0, -1, -1)
ROWT(revunk_root_not_covered_by_ca_flag, 0,{0}, 0x40,0, {ELR(0,2,0x40,8,CRYPTERR_NO_REVOCATION_CHECK)}, 0x400, CRYPTERR_NO_REVOCATION_CHECK, 0, 2, .soft=1)
ROWT(revunk_selfsigned_single_element_needs_root_flag, 1,{1}, 0x40,0, {ELR(0,0,0x40,8,CRYPTERR_NO_REVOCATION_CHECK)}, 0x100, CRYPTERR_NO_REVOCATION_CHECK, 0, 0, .soft=1)
ROWT(revunk_selfsigned_single_element_root_flag, 1,{1}, 0x40,0, {ELR(0,0,0x40,8,CRYPTERR_NO_REVOCATION_CHECK)}, 0x800, 0, -1, -1, .soft=1)
ROWT(revunk_offline_beats_earlier_no_check, 0,{0}, 0x40,0, {ELR(0,0,0x40,0,CRYPTERR_NO_REVOCATION_CHECK), ELR(0,1,0x40,0,CRYPTERR_REVOCATION_OFFLINE)}, 0, CRYPTERR_REVOCATION_OFFLINE, 0, 1, .soft=1)
ROWT(revunk_offline_first_stays, 0,{0}, 0x40,0, {ELR(0,0,0x40,0,CRYPTERR_REVOCATION_OFFLINE), ELR(0,1,0x40,0,CRYPTERR_NO_REVOCATION_CHECK)}, 0, CRYPTERR_REVOCATION_OFFLINE, 0, 0, .soft=1)
ROWT(revunk_first_no_check_wins, 0,{0}, 0x40,0, {ELR(0,0,0x40,0,CRYPTERR_NO_REVOCATION_CHECK), ELR(0,1,0x40,0,CRYPTERR_NO_REVOCATION_CHECK)}, 0, CRYPTERR_NO_REVOCATION_CHECK, 0, 0, .soft=1)
ROWT(revunk_ctl_signer_first_element_second_chain, 2,{2,2}, 0x40,0, {ELR(1,0,0x40,0,CRYPTERR_NO_REVOCATION_CHECK)}, 0, CRYPTERR_NO_REVOCATION_CHECK, 1, 0, .soft=1)
ROWT(revunk_ctl_signer_ignored, 2,{2,2}, 0x40,0, {ELR(1,0,0x40,0,CRYPTERR_NO_REVOCATION_CHECK)}, CERT_CHAIN_POLICY_IGNORE_CTL_SIGNER_REV_UNKNOWN_FLAG, 0, -1, -1, .soft=1)
ROWT(revunk_other_error_wins, 0,{0}, 0x40|0x1,0, {ELR(0,0,0x40,0,CRYPTERR_NO_REVOCATION_CHECK), EL(0,1,0x1,0)}, 0, CERR_EXPIRED, 0, 1)

/* ---- cChain == 0 ---- */
TEST(base_synth_zero_chains_with_error) {
    SYN s; PRES p; int n[1] = {0};
    REQUIRE(U(CertVerifyCertificateChainPolicy));
    syn_init(&s, 0, n); syn_ctx(&s, 0x20, 0);
    p = cp_run(CERT_CHAIN_POLICY_BASE, &s.cc, 0, NULL);
    CHECK(p.ret); EXPECT_EQ(p.err, CERR_UNTRUSTEDROOT); CHECK(p.ci == -1); CHECK(p.ei == -1);
}
TEST(base_synth_zero_chains_no_error) {
    SYN s; PRES p; int n[1] = {0};
    REQUIRE(U(CertVerifyCertificateChainPolicy));
    syn_init(&s, 0, n);
    p = cp_run(CERT_CHAIN_POLICY_BASE, &s.cc, 0, NULL);
    CHECK(p.ret); EXPECT_EQ(p.err, 0); CHECK(p.ci == -1); CHECK(p.ei == -1);
}

/* ---- priority order: each step removes the highest-priority bit and expects the next code ---- */
TEST(base_synth_error_priority_order) {
    static const struct { DWORD bit; DWORD code; } o[] = {
        {0x8, TERR_CERT_SIGNATURE}, {0x4000000, CRYPTERR_REVOKED}, {0x20, CERR_UNTRUSTEDROOT},
        {0x10000, CERR_CHAINING}, {0x4, CRYPTERR_REVOKED}, {0x10, CERR_WRONG_USAGE},
        {0x1, CERR_EXPIRED}, {0x800, CERR_INVALID_NAME}, {0x200, CERR_INVALID_POLICY},
        {0x400, TERR_BASIC_CONSTRAINTS}, {0x8000000, CERR_CRITICAL}, {0x2, CERR_VALIDITYNEST}, };
    int n = sizeof o / sizeof o[0];
    REQUIRE(U(CertVerifyCertificateChainPolicy));
    for (int i = 0; i < n; i++) {
        DWORD mask = 0; SYN s; PRES p; int nel[1] = {3};
        for (int j = i; j < n; j++) mask |= o[j].bit;
        syn_init(&s, 1, nel); syn_ctx(&s, mask, 0); syn_el(&s, 0, 1, mask, 0); syn_chain(&s, 0, mask, 0);
        p = cp_run(CERT_CHAIN_POLICY_BASE, &s.cc, 0, NULL);
        CHECKF(p.ret && p.err == o[i].code, "step %d mask 0x%08lx: got 0x%08lx want 0x%08lx", i, mask, p.err, o[i].code);
    }
}

/* ---- flag matrix: a rule is cleared by exactly its ignore flags and by no other flag ---- */
static const DWORD g_allflags[] = {0x1,0x2,0x4,0x8,0x10,0x20,0x40,0x80,0x100,0x200,0x400,0x800,0x2000,0x08000000};
typedef struct { DWORD bit; int chain_level; DWORD code; DWORD ign; } RULE;
static void run_rule(const RULE *r) {
    int nel[1] = {3};
    REQUIRE(U(CertVerifyCertificateChainPolicy));
    for (unsigned i = 0; i < sizeof g_allflags / sizeof g_allflags[0]; i++) {
        DWORD f = g_allflags[i]; SYN s; PRES p;
        syn_init(&s, 1, nel); syn_ctx(&s, r->bit, 0);
        if (r->chain_level) syn_chain(&s, 0, r->bit, 0); else syn_el(&s, 0, 1, r->bit, 0);
        p = cp_run(CERT_CHAIN_POLICY_BASE, &s.cc, f, NULL);
        if (f & r->ign) CHECKF(p.ret && p.err == 0 && p.ci == -1 && p.ei == -1, "bit 0x%lx flag 0x%lx should clear: err=0x%lx", r->bit, f, p.err);
        else CHECKF(p.ret && p.err == r->code, "bit 0x%lx flag 0x%lx must not clear: err=0x%lx want 0x%lx", r->bit, f, p.err, r->code);
    }
}
#define RULET(nm, ...) TEST(base_synth_flagmatrix_##nm) { static const RULE r = { __VA_ARGS__ }; run_rule(&r); }
RULET(sig, 0x8, 0, TERR_CERT_SIGNATURE, 0)
RULET(ctl_sig, 0x40000, 0, TERR_CERT_SIGNATURE, 0)
RULET(distrust, 0x4000000, 0, CRYPTERR_REVOKED, 0)
RULET(untrusted, 0x20, 0, CERR_UNTRUSTEDROOT, 0x10)
RULET(partial, 0x10000, 1, CERR_CHAINING, 0x10)
RULET(revoked, 0x4, 0, CRYPTERR_REVOKED, 0)
RULET(usage, 0x10, 0, CERR_WRONG_USAGE, 0x20)
RULET(ctl_usage, 0x80000, 1, CERR_WRONG_USAGE, 0x20)
RULET(time, 0x1, 0, CERR_EXPIRED, 0x1)
RULET(ctl_time, 0x20000, 1, CERR_EXPIRED, 0x2)
RULET(name_800, 0x800, 0, CERR_INVALID_NAME, 0x40)
RULET(name_1000, 0x1000, 0, CERR_INVALID_NAME, 0x40)
RULET(name_2000, 0x2000, 0, CERR_INVALID_NAME, 0x40)
RULET(name_4000, 0x4000, 0, CERR_INVALID_NAME, 0x40)
RULET(name_8000, 0x8000, 0, CERR_INVALID_NAME, 0x40)
RULET(policy_200, 0x200, 0, CERR_INVALID_POLICY, 0x80)
RULET(policy_2000000, 0x2000000, 0, CERR_INVALID_POLICY, 0x80)
RULET(basic_constraints, 0x400, 0, TERR_BASIC_CONSTRAINTS, 0x8)
RULET(critical_ext, 0x8000000, 0, CERR_CRITICAL, 0x2000)
RULET(nesting, 0x2, 0, CERR_VALIDITYNEST, 0x4)

/* The policy only reads the context: it must not modify it. */
TEST(base_synth_context_not_modified) {
    SYN s, copy; int nel[1] = {3};
    REQUIRE(U(CertVerifyCertificateChainPolicy));
    syn_init(&s, 1, nel); syn_ctx(&s, 0x21, 0); syn_el(&s, 0, 2, 0x20, 0); syn_el(&s, 0, 0, 0x1, 0);
    memcpy(&copy, &s, sizeof s);
    (void)cp_run(CERT_CHAIN_POLICY_BASE, &s.cc, 0, NULL);
    CHECK(!memcmp(&copy, &s, sizeof s));
}
