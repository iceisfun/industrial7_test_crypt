#ifndef GAP2_H
#define GAP2_H
#include "t.h"
typedef struct { const char *dll, *name; unsigned ord; } g2_ord;
typedef struct { const char *dll, *name, *tdll, *tname; unsigned tord; } g2_fwd;
extern const g2_ord g2_ordtab[];
extern const g2_fwd g2_fwdtab[];
#endif
