local ffi = require 'ffi'

ffi.cdef[[
typedef struct ACMP ACMP;
ACMP *pm_compile(const char *phrase);
int pm_match(ACMP *parser, const char *value, int value_len, char *out, int out_len);
int is_pm_compile_ok(ACMP *acmp);

int containsWord (const char *target, size_t target_len, const char* match, size_t match_len);
int contains(const char *target, int target_length, const char *match, int match_length);
int within(const char *target, int target_length, const char *match, int match_length);
int validateUrlEncoding(const char *input, long int input_length);
int validateUtf8Encoding(const char *value, int value_len);
int endsWith(const char *target, int target_length, const char *match, int match_length);
int beginsWith(const char *target, int target_length, const char *match, int match_length);
int hexEncode(const unsigned char *input, long int input_len, char *output, long int output_len);
int hexDecode(unsigned char *input, long int input_len);
int normalizePath(unsigned char *input, long int input_len);
int trimLeft(const unsigned char *input, long int input_len, char **rval);
int trimRight(const unsigned char *input, long int input_len, char **rval);
int trim(const unsigned char *input, long int input_len, char **rval);
int removeNulls(const unsigned char *input, long int input_len, char *output, int output_len);
int replaceNulls(unsigned char *input, long int input_len);
]]
waf_lib = ffi.load("/usr/local/openresty/lualib/libwaf.so")


