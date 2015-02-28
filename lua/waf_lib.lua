local ffi = require 'ffi'

ffi.cdef[[
int containsWord (const char *target, size_t target_len, const char* match, size_t match_len);
typedef struct ACMP ACMP;
typedef struct {
    ACMP *parser;
    void *ptr;
} ACMPT;
ACMP *acmp_create(int flags);
typedef void (*acmp_callback_t)(ACMP *, void *, size_t, size_t);
int acmp_add_pattern(ACMP *parser, const char *pattern,
acmp_callback_t callback, void *data, size_t len);
]]
waf_lib = ffi.load("/usr/local/openresty/lualib/libwaf.so")


