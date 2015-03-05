#include <ctype.h>
#include <string.h>

int removeNulls(const unsigned char *input, long int input_len,
                char *output, int output_len)
{
    long int i, j;

    if (output_len < input_len) return 0;

    i = j = 0;
    while(i < input_len) {
        if (input[i] == '\0') {
            // pass
        } else {
            output[j] = input[i];
            j++;
        }
        i++;
    }

    return j;
}

int trimLeft(const unsigned char *input, long int input_len, char **rval)
{
    long int i;
    int len;

    *rval = (char *)input;
    for (i = 0; i < input_len; i++) {
        if (isspace(**rval) == 0) {
            break;
        }
        (*rval)++;
    }

    len = input_len - i;

    return len;
}

int trimRight(const unsigned char *input, long int input_len, char **rval)
{
    long int i;
    int len;

    *rval = (char *)input;
    for (i = input_len - 1; i >= 0; i--) {
        if (isspace((*rval)[i]) == 0) {
            break;
        }
        (*rval)[i] = '\0';
    }

    len = i + 1;

    return len;
}

int trim(const unsigned char *input, long int input_len, char **rval)
{
    int len = 0;
    char *out;

    len = trimLeft(input, input_len, rval);
    len = trimRight((const unsigned char *)*rval, len, &out);  

    return len;
}

/**
 * Converts a series of bytes into its hexadecimal
 * representation.
 */
static char *bytes2hex(const unsigned char *data, int len, char *hex, int hex_len) {
    static const unsigned char b2hex[] = "0123456789abcdef";
    int i, j;

    if (hex_len < (len * 2) + 1) {
        return NULL;
    }

    j = 0;
    for(i = 0; i < len; i++) {
        hex[j++] = b2hex[data[i] >> 4];
        hex[j++] = b2hex[data[i] & 0x0f];
    }
    hex[j] = 0;

    return hex;
}

/**
 ** output_len = 2*input_len + 1
 ** TODO: rewrite api
 **/
int hexEncode(const unsigned char *input,
              long int input_len, char *output, long int output_len)
{
    char *p = bytes2hex(input, input_len, output, output_len);
    if(NULL == p) {
        return 0;
    }
    return 1;
}

/**
 * Converts a byte given as its hexadecimal representation
 * into a proper byte. Handles uppercase and lowercase letters
 * but does not check for overflows.
 */
static unsigned char x2c(const unsigned char *what) {
    register unsigned char digit;

    digit = (what[0] >= 'A' ? ((what[0] & 0xdf) - 'A') + 10 : (what[0] - '0'));
    digit *= 16;
    digit += (what[1] >= 'A' ? ((what[1] & 0xdf) - 'A') + 10 : (what[1] - '0'));

    return digit;
}

static int hex2bytes_inplace(unsigned char *data, int len) {
    unsigned char *d = data;
    int i, count = 0;

    if ((data == NULL)||(len == 0)) return 0;

    for(i = 0; i <= len - 2; i += 2) {
        *d++ = x2c(&data[i]);
        count++;
    }
    *d = '\0';

    return count;
}

int hexDecode(unsigned char *input, long int input_len)
{
    int len = hex2bytes_inplace(input, input_len);
    return len;
}

int normalize_path_inplace(unsigned char *input, int input_len, int win, int *changed) {
    unsigned char *src;
    unsigned char *dst;
    unsigned char *end;
    int ldst = 0;
    int hitroot = 0;
    int done = 0;
    int relative;
    int trailing;

    *changed = 0;

    /* Need at least one byte to normalize */
    if (input_len <= 0) return 0;

    /*
     * ENH: Deal with UNC and drive letters?
     */

    src = dst = input;
    end = input + (input_len - 1);
    ldst = 1;

    relative = ((*input == '/') || (win && (*input == '\\'))) ? 0 : 1;
    trailing = ((*end == '/') || (win && (*end == '\\'))) ? 1 : 0;


    while (!done && (src <= end) && (dst <= end)) {
        /* Convert backslash to forward slash on Windows only. */
        if (win) {
            if (*src == '\\') {
                *src = '/';
                *changed = 1;
            }
            if ((src < end) && (*(src + 1) == '\\')) {
                *(src + 1) = '/';
                *changed = 1;
            }
        }

        /* Always normalize at the end of the input. */
        if (src == end) {
            done = 1;
        }

        /* Skip normalization if this is NOT the end of the path segment. */
        else if (*(src + 1) != '/') {
            goto copy; /* Skip normalization. */
        }

        /*** Normalize the path segment. ***/

        /* Could it be an empty path segment? */
        if ((src != end) && *src == '/') {
            /* Ignore */
            *changed = 1;
            goto copy; /* Copy will take care of this. */
        }

        /* Could it be a back or self reference? */
        else if (*src == '.') {

            /* Back-reference? */
            if ((dst > input) && (*(dst - 1) == '.')) {
                /* If a relative path and either our normalization has
                 * already hit the rootdir, or this is a backref with no
                 * previous path segment, then mark that the rootdir was hit
                 * and just copy the backref as no normilization is possible.
                 */
                if (relative && (hitroot || ((dst - 2) <= input))) {
                    hitroot = 1;

                    goto copy; /* Skip normalization. */
                }

                /* Remove backreference and the previous path segment. */
                dst -= 3;
                while ((dst > input) && (*dst != '/')) {
                    dst--;
                }

                /* But do not allow going above rootdir. */
                if (dst <= input) {
                    hitroot = 1;
                    dst = input;

                    /* Need to leave the root slash if this
                     * is not a relative path and the end was reached
                     * on a backreference.
                     */
                    if (!relative && (src == end)) {
                        dst++;
                    }
                }

                if (done) goto length; /* Skip the copy. */
                src++;

                *changed = 1;
            }

            /* Relative Self-reference? */
            else if (dst == input) {
                *changed = 1;

                /* Ignore. */

                if (done) goto length; /* Skip the copy. */
                src++;
            }

            /* Self-reference? */
            else if (*(dst - 1) == '/') {
                *changed = 1;

                /* Ignore. */

                if (done) goto length; /* Skip the copy. */
                dst--;
                src++;
            }
        }

        /* Found a regular path segment. */
        else if (dst > input) {
            hitroot = 0;
        }

copy:
        /*** Copy the byte if required. ***/

        /* Skip to the last forward slash when multiple are used. */
        if (*src == '/') {
            unsigned char *oldsrc = src;

            while (   (src < end)
                    && ((*(src + 1) == '/') || (win && (*(src + 1) == '\\'))) )
            {
                src++;
            }
            if (oldsrc != src) *changed = 1;

            /* Do not copy the forward slash to the root
             * if it is not a relative path.  Instead
             * move over the slash to the next segment.
             */
            if (relative && (dst == input)) {
                src++;
                goto length; /* Skip the copy */
            }
        }

        *(dst++) = *(src++);

length:
        ldst = (dst - input);
    }

    /* Make sure that there is not a trailing slash in the
     * normalized form if there was not one in the original form.
     */
    if (!trailing && (dst > input) && *(dst - 1) == '/') {
        ldst--;
        dst--;
    }

    /* Always NUL terminate */
    *dst = '\0';

    return ldst;
}

int normalizePath(unsigned char *input, long int input_len)
{
    int changed;

    int len = normalize_path_inplace(input, input_len, 0, &changed);

    return len;
}

int replaceNulls(unsigned char *input, long int input_len)
{
    long int i;
    int len;

    i = 0;
    while(i < input_len) {
        if (input[i] == '\0') {
            input[i] = ' ';
        }
        i++;
    }

    len = input_len;

    return len;
}
