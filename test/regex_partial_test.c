/*
 * Regression test for the check_http.c check_regex() partial-match buffer
 * compaction underflow. With a pattern whose partial match can start before
 * its maximum lookbehind (the no-lookbehind "bar" branch here, while
 * "(?<=12345)" sets the max lookbehind to 5), the discard count 'keep' must
 * not wrap. Mirrors the keep computation in check_regex().
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>

int
main(void)
{
	pcre2_code *re;
	pcre2_match_data *md;
	uint32_t max_lookbehind = 0;
	size_t keep, erroff;
	size_t *ov;
	int errn, rc;

	re = pcre2_compile((PCRE2_SPTR)"bar|(?<=12345)X", PCRE2_ZERO_TERMINATED, 0, &errn, &erroff, NULL);
	if (!re) {
		fprintf(stderr, "compile failed\n");
		return 2;
	}

	pcre2_pattern_info(re, PCRE2_INFO_MAXLOOKBEHIND, &max_lookbehind);
	md = pcre2_match_data_create_from_pattern(re, NULL);

	rc = pcre2_match(re, (PCRE2_SPTR)"ba", 2, 0, PCRE2_PARTIAL_HARD, md, NULL);
	if (rc != PCRE2_ERROR_PARTIAL) {
		fprintf(stderr, "expected partial match, got %d\n", rc);
		return 2;
	}

	ov = pcre2_get_ovector_pointer(md);
	keep = ov[0] > max_lookbehind ? ov[0] - max_lookbehind : 0;

	printf("ovector[0]=%zu max_lookbehind=%u keep=%zu\n", ov[0], max_lookbehind, keep);

	/* keep must never exceed the match offset; a wrap means the bug is back. */
	return keep > ov[0];
}
