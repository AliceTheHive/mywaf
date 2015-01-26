
#include <ctype.h>
#include <string.h>

int containsWord (const char *target, size_t target_len, const char* match, size_t match_len)
{
    int i;
    /* scan for first character, then compare from there until we
     * have a match or there is no room left in the target
     */
    int i_max = target_len - match_len;
    for (i = 0; i <= i_max; i++) {

        /* Previous char must have been a start or non-word */
        if ((i > 0) && target[i-1] != ' ')
            continue;

        /* First character matched - avoid func call */
        if (target[i] == match[0]) {
            /* See if remaining matches */
            if (   (match_len == 1)
                   || (memcmp((match + 1), (target + i + 1), (match_len - 1)) == 0)) {
                /* check boundaries */
                if (i == i_max) {
                    /* exact/end word match */
                    return 1;
                }
                else if (target[i + match_len] == ' ') {
                    /* start/mid word match */
                    return 1;
                }
            }
        }
    }
    return 0;
}
#if 0
int within(const char *target, int target_length, const char *match, int match_length)
{
    /* The empty string always matches */
    if (target_length == 0) {
        return 1;
    }

    /* This is impossible to match */
    if (target_length > match_length) {
        /* No match. */
        return 0;
    }

    /* scan for first character, then compare from there until we
     * have a match or there is no room left in the target
     */
    i_max = match_length - target_length;
    for (i = 0; i <= i_max; i++) {
        if (match[i] == target[0]) {
            if (memcmp((target + 1), (match + i + 1), (target_length - 1)) == 0) {
                return 1;
            }
        }
    }

    /* No match. */
    return 0;
}

int contains(const char *target, int target_length, const char *match, int match_length)
{
    /* The empty string always matches */
    if (match_length == 0) {
        return 1;
    }

    if (match_length > target_length) {
        return 0;
    }

    i_max = target_length - match_length;
    for (i = 0; i <= i_max; i++) {
        if (target[i] == match[0]) {
            if (   (match_length == 1)
                   || (memcmp((match + 1), (target + i + 1), (match_length - 1)) == 0))
            {
                return 1;
            }
        }
    }

    return 0;
}
#endif
