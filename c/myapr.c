#include "myapr.h"

int apr_pool_create(void **p, void *q)
{
   return APR_SUCCESS;
}

void *apr_palloc(apr_pool_t *p, int size)
{
    return malloc(size);
}

void *apr_pcalloc(apr_pool_t *p, int size)
{
    return calloc(1,size);
}

static void make_array_core(apr_array_header_t *res, apr_pool_t *p,
			    int nelts, int elt_size, int clear)
{
    /*
     * Assure sanity if someone asks for
     * array of zero elts.
     */
    if (nelts < 1) {
        nelts = 1;
    }

    if (clear) {
        //res->elts = apr_pcalloc(p, nelts * elt_size);
    }
    else {
        res->elts = apr_palloc(p, nelts * elt_size);
    }

    res->pool = p;
    res->elt_size = elt_size;
    res->nelts = 0;		/* No active elements yet... */
    res->nalloc = nelts;	/* ...but this many allocated */
}

int apr_is_empty_array(const apr_array_header_t *a)
{
    return ((a == NULL) || (a->nelts == 0));
}

apr_array_header_t * apr_array_make(apr_pool_t *p,
						int nelts, int elt_size)
{
    apr_array_header_t *res;

    res = (apr_array_header_t *) apr_palloc(p, sizeof(apr_array_header_t));
    make_array_core(res, p, nelts, elt_size, 1);
    return res;
}

void apr_array_clear(apr_array_header_t *arr)
{
    arr->nelts = 0;
}

void * apr_array_pop(apr_array_header_t *arr)
{
    if (apr_is_empty_array(arr)) {
        return NULL;
    }
   
    return arr->elts + (arr->elt_size * (--arr->nelts));
}

void * apr_array_push(apr_array_header_t *arr)
{
    if (arr->nelts == arr->nalloc) {
        int new_size = (arr->nalloc <= 0) ? 1 : arr->nalloc * 2;
        char *new_data;

        new_data = apr_palloc(arr->pool, arr->elt_size * new_size);

        memcpy(new_data, arr->elts, arr->nalloc * arr->elt_size);
        memset(new_data + arr->nalloc * arr->elt_size, 0,
               arr->elt_size * (new_size - arr->nalloc));
        arr->elts = new_data;
        arr->nalloc = new_size;
    }

    ++arr->nelts;
    return arr->elts + (arr->elt_size * (arr->nelts - 1));
}

static void *apr_array_push_noclear(apr_array_header_t *arr)
{
    if (arr->nelts == arr->nalloc) {
        int new_size = (arr->nalloc <= 0) ? 1 : arr->nalloc * 2;
        char *new_data;

        new_data = apr_palloc(arr->pool, arr->elt_size * new_size);

        memcpy(new_data, arr->elts, arr->nalloc * arr->elt_size);
        arr->elts = new_data;
        arr->nalloc = new_size;
    }

    ++arr->nelts;
    return arr->elts + (arr->elt_size * (arr->nelts - 1));
}

void apr_array_cat(apr_array_header_t *dst,
			       const apr_array_header_t *src)
{
    int elt_size = dst->elt_size;

    if (dst->nelts + src->nelts > dst->nalloc) {
	int new_size = (dst->nalloc <= 0) ? 1 : dst->nalloc * 2;
	char *new_data;

	while (dst->nelts + src->nelts > new_size) {
	    new_size *= 2;
	}

	new_data = apr_pcalloc(dst->pool, elt_size * new_size);
	memcpy(new_data, dst->elts, dst->nalloc * elt_size);

	dst->elts = new_data;
	dst->nalloc = new_size;
    }

    memcpy(dst->elts + dst->nelts * elt_size, src->elts,
	   elt_size * src->nelts);
    dst->nelts += src->nelts;
}

apr_array_header_t * apr_array_copy(apr_pool_t *p,
						const apr_array_header_t *arr)
{
    apr_array_header_t *res =
        (apr_array_header_t *) apr_palloc(p, sizeof(apr_array_header_t));
    make_array_core(res, p, arr->nalloc, arr->elt_size, 0);

    memcpy(res->elts, arr->elts, arr->elt_size * arr->nelts);
    res->nelts = arr->nelts;
    memset(res->elts + res->elt_size * res->nelts, 0,
           res->elt_size * (res->nalloc - res->nelts));
    return res;
}

/* This cute function copies the array header *only*, but arranges
 * for the data section to be copied on the first push or arraycat.
 * It's useful when the elements of the array being copied are
 * read only, but new stuff *might* get added on the end; we have the
 * overhead of the full copy only where it is really needed.
 */

static void copy_array_hdr_core(apr_array_header_t *res,
					   const apr_array_header_t *arr)
{
    res->elts = arr->elts;
    res->elt_size = arr->elt_size;
    res->nelts = arr->nelts;
    res->nalloc = arr->nelts;	/* Force overflow on push */
}

apr_array_header_t *
    apr_array_copy_hdr(apr_pool_t *p,
		       const apr_array_header_t *arr)
{
    apr_array_header_t *res;

    res = (apr_array_header_t *) apr_palloc(p, sizeof(apr_array_header_t));
    res->pool = p;
    copy_array_hdr_core(res, arr);
    return res;
}

/* The above is used here to avoid consing multiple new array bodies... */

apr_array_header_t *
    apr_array_append(apr_pool_t *p,
		      const apr_array_header_t *first,
		      const apr_array_header_t *second)
{
    apr_array_header_t *res = apr_array_copy_hdr(p, first);

    apr_array_cat(res, second);
    return res;
}

/* apr_array_pstrcat generates a new string from the apr_pool_t containing
 * the concatenated sequence of substrings referenced as elements within
 * the array.  The string will be empty if all substrings are empty or null,
 * or if there are no elements in the array.
 * If sep is non-NUL, it will be inserted between elements as a separator.
 */
char * apr_array_pstrcat(apr_pool_t *p,
				     const apr_array_header_t *arr,
				     const char sep)
{
    char *cp, *res, **strpp;
    apr_size_t len;
    int i;

    if (arr->nelts <= 0 || arr->elts == NULL) {    /* Empty table? */
        return (char *) apr_pcalloc(p, 1);
    }

    /* Pass one --- find length of required string */

    len = 0;
    for (i = 0, strpp = (char **) arr->elts; ; ++strpp) {
        if (strpp && *strpp != NULL) {
            len += strlen(*strpp);
        }
        if (++i >= arr->nelts) {
            break;
	}
        if (sep) {
            ++len;
	}
    }

    /* Allocate the required string */

    res = (char *) apr_palloc(p, len + 1);
    cp = res;

    /* Pass two --- copy the argument strings into the result space */

    for (i = 0, strpp = (char **) arr->elts; ; ++strpp) {
        if (strpp && *strpp != NULL) {
            len = strlen(*strpp);
            memcpy(cp, *strpp, len);
            cp += len;
        }
        if (++i >= arr->nelts) {
            break;
	}
        if (sep) {
            *cp++ = sep;
	}
    }

    *cp = '\0';

    /* Return the result string */

    return res;
}
