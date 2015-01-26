local ffi = require 'ffi'

ffi.cdef[[
int containsWord (const char *target, size_t target_len, const char* match, size_t match_len);
]]
waf_lib = ffi.load("/usr/local/openresty/lualib/libwaf.so")


