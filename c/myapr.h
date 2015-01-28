#ifndef _MY_APR_H_
#define _MY_APR_H_

#include <stdlib.h>
#include <string.h>
#define apr_pool_t void
typedef int apr_status_t;
#define APR_SUCCESS 0
#define APR_EGENERAL -1
/** @see apr_array_header_t */
typedef struct apr_array_header_t apr_array_header_t;
/** An opaque array type */
struct apr_array_header_t {
    /** The pool the array is allocated out of */
    apr_pool_t *pool;
    /** The amount of memory allocated for each element of the array */
    int elt_size;
    /** The number of active elements in the array */
    int nelts;
    /** The number of elements allocated in the array */
    int nalloc;
    /** The elements in the array */
    char *elts;
};

#define APR_DECLARE(x) x
#define apr_tolower(x) tolower(x)
#define apr_size_t size_t


void *apr_pcalloc(apr_pool_t *p, int size);
void *apr_palloc(apr_pool_t *p, int size);
int apr_is_empty_array(const apr_array_header_t *a);
apr_array_header_t * apr_array_make(apr_pool_t *p,
                                    int nelts, int elt_size);
void * apr_array_pop(apr_array_header_t *arr);
void * apr_array_push(apr_array_header_t *arr);
#endif
