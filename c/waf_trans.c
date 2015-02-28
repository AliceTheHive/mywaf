#include <ctype.h>
#include <string.h>

int removeNulls(unsigned char *input, long int input_len,
                char **rval, long int *rval_len)
{
    long int i, j;
    int changed = 0;

    i = j = 0;
    while(i < input_len) {
        if (input[i] == '\0') {
            changed = 1;
        } else {
            input[j] = input[i];
            j++;
        }
        i++;
    }

    *rval = (char *)input;
    *rval_len = j;

    return changed;
}

int trimLeft(unsigned char *input, long int input_len, char **rval, long int *rval_len)
{
    long int i;

    *rval = (char *)input;
    for (i = 0; i < input_len; i++) {
        if (isspace(**rval) == 0) {
            break;
        }
        (*rval)++;
    }

    *rval_len = input_len - i;

    return (*rval_len == input_len ? 0 : 1);
}
