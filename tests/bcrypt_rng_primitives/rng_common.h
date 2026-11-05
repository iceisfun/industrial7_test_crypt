/* Shared helpers for the bcrypt_rng_primitives area. */
#ifndef RNG_COMMON_H
#define RNG_COMMON_H
#include "t.h"
#include <bcrypt.h>
#include <wincrypt.h>

#define NS_SUCCESS            ((LONG)0x00000000)
#define NS_INVALID_HANDLE     ((LONG)0xC0000008)
#define NS_INVALID_PARAMETER  ((LONG)0xC000000D)
#define NS_BUFFER_TOO_SMALL   ((LONG)0xC0000023)
#define NS_NOT_SUPPORTED      ((LONG)0xC00000BB)

/* evaluate the call exactly once (EXPECT_EQ evaluates its arguments twice) */
#define EQ_NT(call, want) do { LONG nt_ = (LONG)(call); EXPECT_EQ(nt_, want); } while (0)
#define ST_OK(s) ((LONG)(s) >= 0)

static int rng_all_zero(const unsigned char *p, size_t n) {
    size_t i; for (i = 0; i < n; i++) if (p[i]) return 0; return 1;
}
static size_t rng_popcount(const unsigned char *p, size_t n) {
    size_t i, c = 0; for (i = 0; i < n; i++) { unsigned v = p[i]; while (v) { c += v & 1; v >>= 1; } } return c;
}
/* Wide sanity band for the number of one bits in n random bytes (about 11 sigma). */
static int rng_popcount_plausible(const unsigned char *p, size_t n) {
    double mean = n * 4.0, sigma = __builtin_sqrt(n * 2.0);
    double c = (double)rng_popcount(p, n);
    return c > mean - 11 * sigma && c < mean + 11 * sigma;
}
/* Every byte value must occur at least once and none may dominate in a large sample. */
static int rng_histogram_plausible(const unsigned char *p, size_t n) {
    unsigned h[256]; size_t i; unsigned mx = 0, mn = 0xffffffff, v;
    memset(h, 0, sizeof h);
    for (i = 0; i < n; i++) h[p[i]]++;
    for (v = 0; v < 256; v++) { if (h[v] > mx) mx = h[v]; if (h[v] < mn) mn = h[v]; }
    return mn > 0 && mx < (unsigned)(n / 256 * 3);
}
#endif
