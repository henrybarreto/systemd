/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>

#include "alloc-util.h"
#include "dns-domain.h"
#include "string-util.h"
#include "tests.h"

static bool should_parse_entry(const char *input) {
        _cleanup_free_ char *tmp = NULL;
        char *stripped;
        const char *name;

        if (isempty(input))
                return false;

        tmp = strdup(input);
        if (!tmp)
                return false;

        stripped = strstrip(tmp);

        if (isempty(stripped))
                return false;

        if (stripped[0] == '#')
                return false;

        name = startswith(stripped, "*.") ? stripped + 2 : stripped;

        if (!dns_name_is_valid(name))
                return false;

        return true;
}

static void test_parse_entry(const char *input, bool expect_valid) {
        bool valid = should_parse_entry(input);

        if (expect_valid)
                ASSERT_TRUE(valid);
        else
                ASSERT_FALSE(valid);

        printf("PASS: '%s' -> %s\n", input, valid ? "valid" : "invalid");
}

TEST(dns_return_deny_list_parse_simple_format) {
        test_parse_entry("google.com", true);
        test_parse_entry("  google.com  ", true);
        test_parse_entry("# comment", false);
        test_parse_entry("   # comment with leading spaces", false);
        test_parse_entry("", false);
        test_parse_entry("   ", false);
        test_parse_entry("ads.example.com", true);
        test_parse_entry("*.ads.example.com", true);
        test_parse_entry("tracker.com", true);
        test_parse_entry("mail.google.com", true);
        test_parse_entry("valid-domain.org", true);
        test_parse_entry("sub.domain.co.uk", true);
}

static int intro(void) {
        return EXIT_SUCCESS;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_DEBUG, intro);
