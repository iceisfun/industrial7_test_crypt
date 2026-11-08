/* Negative control for the zero-argument tables: lookups of names that do not exist fail with the documented codes,
 * so a table row cannot pass by resolving something unrelated. */
#include "zc.h"

TEST(gpa_negative_control) {
    HMODULE h = t_module("cryptngc.dll");
    REQUIRE_NOTNULL(h);
    EXPECT_GPA_FAIL(h, "NoSuchExportName");
    EXPECT_GPA_FAIL(h, MAKEINTRESOURCEA(0));
    EXPECT_GPA_FAIL(h, MAKEINTRESOURCEA(60000));
    EXPECT_EQ(t_proc_in("cryptngc.dll", "NoSuchExportName"), NULL);
}
