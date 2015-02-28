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
