#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include "acmp.h"

#define UNICODE_ERROR_CHARACTERS_MISSING    -10
#define UNICODE_ERROR_INVALID_ENCODING      -11
#define UNICODE_ERROR_OVERLONG_CHARACTER    -12
#define UNICODE_ERROR_RESTRICTED_CHARACTER  -13
#define UNICODE_ERROR_DECODING_ERROR        -14

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

ACMP *pm_compile(const char *phrase)
{
    ACMP *p;
    const char *next;

    if (NULL == phrase || '\0' == *phrase) {
        return NULL;
    }

    p = acmp_create(0, NULL);
    if (p == NULL) return NULL;

    for (;;) {
        while((isspace(*phrase) != 0) && (*phrase != '\0')) phrase++;
        if (*phrase == '\0') break;
        next = phrase;
        while((isspace(*next) == 0) && (*next != 0)) next++;
        acmp_add_pattern(p, phrase, NULL, NULL, next - phrase);
        phrase = next;
    }

    acmp_prepare(p);
    return p;
}

int is_pm_compile_ok(ACMP *acmp)
{
    return (acmp != NULL);
}

int pm_match(ACMP *parser, const char *value, int value_len, char *out, int out_len)
{
    const char *match = NULL;
    apr_status_t rc = 0;
    ACMPT pt;

    if (value == NULL || value_len == 0) return 0;
    pt.parser = parser;
    pt.ptr = NULL;

    rc = acmp_process_quick(&pt, &match, value, value_len);
    if (rc) {
        if (NULL != out && 0 != out_len) {
            int len = strlen(match) + 1;
            len = (len > out_len)? out_len : len;
            memcpy(out, match, len);
        }
        return 1;
    }
    return 0;
}
#define HUGE_STRING_LEN 2048
ACMP *pmFromFile_compile(const char *filenames, const char *base_path)
{
    char buf[HUGE_STRING_LEN + 1];
    char *fname = NULL;
    char *next = NULL;
    char *start = NULL;
    char *end = NULL;

    ACMP *p;

    p = acmp_create(0, NULL);
    if (p == NULL) return NULL;
    
    fname = strdup(filenames);
    for (;;) {

        while((isspace(*fname) != 0) && (*fname != '\0')) fname++;
        if (*fname == '\0') break;
        next = fname;
        while((isspace(*next) == 0) && (*next != '\0')) next++;
        while((isspace(*next) != 0) && (*next != '\0')) *(next++) = '\0';
        snprintf(buf, sizeof(buf), "%s/%s", base_path, fname);

        FILE* fp = fopen(buf, "r");
        if (NULL == fp) {
            break;
        }

        for(;;) {
            // Assume one line's size is smaller than HUGE_STRING_LEN, keep it simple.
            if (fgets(buf, HUGE_STRING_LEN, fp) == NULL) {
                break;
            }

            start = buf;
            while ((isspace(*start) != 0) && (*start != '\0')) start++;
            /* Ignore empty lines and comments */
            if ((start == end) || (*start == '#')) continue;
            
            end = buf + strlen(buf);
            if (end > start) end--;
            while ((end > start) && (isspace(*end) != 0)) end--;
            if (end > start) {
                *(++end) = '\0';
            }

            acmp_add_pattern(p, start, NULL, NULL, (end - start));
        }
        fname = next;
        fclose(fp);
        fp = NULL;
    }

    acmp_prepare(p);
    free(fname);
    return p;
}

int within(const char *target, int target_length, const char *match, int match_length)
{
    int i;
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
    int i_max = match_length - target_length;
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
    int i;
    /* The empty string always matches */
    if (match_length == 0) {
        return 1;
    }

    if (match_length > target_length) {
        return 0;
    }

    int i_max = target_length - match_length;
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


int validateUrlEncoding(const char *input, long int input_length)
{
    int i;

    if ((input == NULL)||(input_length < 0)) return -1;

    i = 0;
    while (i < input_length) {
        if (input[i] == '%') {
            if (i + 2 >= input_length) {
                /* Not enough bytes. */
                return -3;
            }
            else {
                /* Here we only decode a %xx combination if it is valid,
                 * leaving it as is otherwise.
                 */
                char c1 = input[i + 1];
                char c2 = input[i + 2];

                if ( (((c1 >= '0')&&(c1 <= '9')) || ((c1 >= 'a')&&(c1 <= 'f')) || ((c1 >= 'A')&&(c1 <= 'F')))
                     && (((c2 >= '0')&&(c2 <= '9')) || ((c2 >= 'a')&&(c2 <= 'f')) || ((c2 >= 'A')&&(c2 <= 'F'))) )
                {
                    i += 3;
                } else {
                    /* Non-hexadecimal characters used in encoding. */
                    return -2;
                }
            }
        } else {
            i++;
        }
    }

    return 0;
}

static int detect_utf8_character(const unsigned char *p_read, unsigned int length)
{
    int unicode_len = 0;
    unsigned int d = 0;
    unsigned char c;

    if (p_read == NULL) return UNICODE_ERROR_DECODING_ERROR;
    c = *p_read;

    /* If first byte begins with binary 0 it is single byte encoding */
    if ((c & 0x80) == 0) {
        /* single byte unicode (7 bit ASCII equivilent) has no validation */
        return 1;
    }
    /* If first byte begins with binary 110 it is two byte encoding*/
    else if ((c & 0xE0) == 0xC0) {
        /* check we have at least two bytes */
        if (length < 2) unicode_len = UNICODE_ERROR_CHARACTERS_MISSING;
        /* check second byte starts with binary 10 */
        else if (((*(p_read + 1)) & 0xC0) != 0x80) unicode_len = UNICODE_ERROR_INVALID_ENCODING;
        else {
            unicode_len = 2;
            /* compute character number */
            d = ((c & 0x1F) << 6) | (*(p_read + 1) & 0x3F);
        }
    }
    /* If first byte begins with binary 1110 it is three byte encoding */
    else if ((c & 0xF0) == 0xE0) {
        /* check we have at least three bytes */
        if (length < 3) unicode_len = UNICODE_ERROR_CHARACTERS_MISSING;
        /* check second byte starts with binary 10 */
        else if (((*(p_read + 1)) & 0xC0) != 0x80) unicode_len = UNICODE_ERROR_INVALID_ENCODING;
        /* check third byte starts with binary 10 */
        else if (((*(p_read + 2)) & 0xC0) != 0x80) unicode_len = UNICODE_ERROR_INVALID_ENCODING;
        else {
            unicode_len = 3;
            /* compute character number */
            d = ((c & 0x0F) << 12) | ((*(p_read + 1) & 0x3F) << 6) | (*(p_read + 2) & 0x3F);
        }
    }
    /* If first byte begins with binary 11110 it is four byte encoding */
    else if ((c & 0xF8) == 0xF0) {
        /* restrict characters to UTF-8 range (U+0000 - U+10FFFF)*/
        if (c >= 0xF5) {
            return UNICODE_ERROR_RESTRICTED_CHARACTER;
        }
        /* check we have at least four bytes */
        if (length < 4) unicode_len = UNICODE_ERROR_CHARACTERS_MISSING;
        /* check second byte starts with binary 10 */
        else if (((*(p_read + 1)) & 0xC0) != 0x80) unicode_len = UNICODE_ERROR_INVALID_ENCODING;
        /* check third byte starts with binary 10 */
        else if (((*(p_read + 2)) & 0xC0) != 0x80) unicode_len = UNICODE_ERROR_INVALID_ENCODING;
        /* check forth byte starts with binary 10 */
        else if (((*(p_read + 3)) & 0xC0) != 0x80) unicode_len = UNICODE_ERROR_INVALID_ENCODING;
        else {
            unicode_len = 4;
            /* compute character number */
            d = ((c & 0x07) << 18) | ((*(p_read + 1) & 0x3F) << 12) | ((*(p_read + 2) & 0x3F) < 6) | (*(p_read + 3) & 0x3F);
        }
    }
    /* any other first byte is invalid (RFC 3629) */
    else {
        return UNICODE_ERROR_INVALID_ENCODING;
    }

    /* invalid UTF-8 character number range (RFC 3629) */
    if ((d >= 0xD800) && (d <= 0xDFFF)) {
        return UNICODE_ERROR_RESTRICTED_CHARACTER;
    }

    /* check for overlong */
    if ((unicode_len == 4) && (d < 0x010000)) {
        /* four byte could be represented with less bytes */
        return UNICODE_ERROR_OVERLONG_CHARACTER;
    }
    else if ((unicode_len == 3) && (d < 0x0800)) {
        /* three byte could be represented with less bytes */
        return UNICODE_ERROR_OVERLONG_CHARACTER;
    }
    else if ((unicode_len == 2) && (d < 0x80)) {
        /* two byte could be represented with less bytes */
        return UNICODE_ERROR_OVERLONG_CHARACTER;
    }

    return unicode_len;
}

int validateUtf8Encoding(const char *value, int value_len)
{
    unsigned int i, bytes_left;

    bytes_left = value_len;

    for(i = 0; i < value_len;) {
        int rc = detect_utf8_character((const unsigned char *)(value+i), bytes_left);
        if (rc <= 0) {
            if (rc == 0) rc = -1;
            return rc;
        }

        i += rc;
        bytes_left -= rc;
    }

    return 1;
}

int endsWith(const char *target, int target_length, const char *match, int match_length)
{
    if (match_length == 0) {
        return 1;
    }

    /* This is impossible to match */
    if (match_length > target_length) {
        /* No match. */
        return 0;
    }

    if (memcmp(match, (target + (target_length - match_length)), match_length) == 0) {
        /* Match. */
        return 1;
    }
    /* No match. */
    return 0;
}

int beginsWith(const char *target, int target_length, const char *match, int match_length)
{
    /* The empty string always matches */
    if (match_length == 0) {
        /* Match. */
        return 1;
    }

    /* This is impossible to match */
    if (match_length > target_length) {
        /* No match. */
        return 0;
    }

    if (memcmp(match, target, match_length) == 0) {
        /* Match. */
        return 1;
    }

    /* No match. */
    return 0;
}
