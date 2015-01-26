local M = {}

local ngx_req_get_method = ngx.req.get_method
local ngx_req_get_uri_args = ngx.req.get_uri_args
local ngx_req_get_post_args = ngx.req.get_post_args
local ngx_req_get_body_data = ngx.req.get_body_data
local ngx_req_start_time = ngx.req.start_time
local ngx_req_http_version = ngx.req.http_version
local ngx_req_get_headers = ngx.req.get_headers
local ngx_req_raw_header = ngx.req.raw_header
local ngx_req_get_body_file = ngx.req.get_body_file
local ngx_req_read_body = ngx.req.read_body
local ngx_req_raw_header = ngx.req.raw_header

function M.hash_to_array(hash)
   local keys = {}
   local vals = {}
   for k,v in pairs(hash) do
      keys[#keys + 1] = k
      vals[#vals + 1] = v
   end
   local res = {}
   res[0] = keys
   res[1] = vals
   return res
end

local function get_keys(hash)
   local keys = {}
   for k, v in pairs(hash) do
      keys[#keys + 1] = k
   end
   return keys
end

-- ARGS_GET
function M.get_args_get()
   return ngx_req_get_uri_args()
end

-- ARGS_POST
function M.get_args_post()
   ngx_req_read_body()
   return ngx_req_get_post_args()
end

-- ARGS
function M.get_args()
   local args = ngx_req_get_uri_args()
   local args_post = ngx_req_get_post_args()
   for k, v in pairs(args_post) do
      args[k] = v
   end
   return args
end

-- ARGS_GET_NAMES
function M.get_args_get_names()
   local args = ngx_req_get_uri_args()
   return get_keys(args)
end

-- ARGS_POST_NAMES
function M.get_args_post_names()
   local args = ngx_req_get_post_args()
   return get_keys(args)
end

-- QUERY_STRING
function M.get_query_string()
   return ngx.var.query_string
end

-- REMOTE_ADDR
function M.get_remote_addr()
   return ngx.var.remote_addr
end

-- REMOTE_PORT
function M.get_remote_port()
   return ngx.var.remote_port
end
-- MATCHED_VAR

-- MATCHED_VAR_NAME

-- REQUEST_BASENAME
function M.get_request_basename()
   local base = string.match(ngx.var.request_filename, ".*([^\\]+$)")
   return base
end

-- REQUEST_BODY
-- need: lua_need_request_body on;
function M.get_request_body()
   return ngx.var.request_body
end

-- REQUEST_COOKIES
function M.get_request_cookies()
   local cookies = {}
   for word in string.gmatch(raw_header, "Cookie: ([^\r\n]+)") do
      for k, v in string.gmatch(str_cookies, "(%S+)=(%S+)") do
         if v:sub(v:len())==";" then
            cookies[k]=v:sub(1,v:len()-1)
         else
            cookies[k]=v
         end
      end
   end
   return cookies
end

-- REQUEST_COOKIES_NAMES
function M.get_request_cookies_names()
   local cookies = M.get_request_cookies()
   return get_keys(cookies)
end

-- REQUEST_FILENAME
function M.get_request_filename()
   return ngx.var.request_filename
end

-- REQUEST_HEADERS
function M.get_request_headers()
   return ngx_req_get_headers()
end

-- REQUEST_HEADERS_NAMES
function M.get_request_headers_names()
   local headers = ngx_req_get_headers()
   return get_keys(headers)
end

-- REQUEST_LINE
function M.get_request_line()
   local header = ngx_req_raw_header()
   local idx = string.find(header, "\r\n")
   if idx ~= -1 then
      return string.sub(header, 1, idx)
   end
end
-- REQUEST_METHOD
function M.get_request_method()
   return ngx.req.get_method()
end

-- REQUEST_PROTOCOL
function M.get_request_protocol()
   local line = M.get_request_line()
   local proto = string.match(line, "HTTP/%d+\\.%d+")
   return proto
end

-- REQUEST_URI
function M.get_request_uri()
   return ngx.var.request_uri
end

-- REQUEST_URI_RAW
function M.get_request_uri_raw()
   return ngx.var.request_uri
end

-- RESPONSE_BODY
-- only in body_filter_by_lua
function M.get_response_body()
   return ngx.args[1]
end

-- RESPONSE_CONTENT_TYPE
function M.get_response_content_type()
   local body = M.get_reponse_body()
   local ctype = string.match(body, "Content-Type:%s*(%S+)")
   return ctype
end

-- RESPONSE_HEADERS
function M.get_response_headers()
   local body = M.get_reponse_body()
   local headers = {}
   for k, v in string.gmatch(str_cookies, "([a-zA-Z-]+):(%S+)") do
      headers[k]=v
   end
   return headers
end

-- RESPONSE_HEADERS_NAMES
function M.get_response_headers_names()
   local body = M.get_reponse_body()
   local names = {}
   for k, v in string.gmatch(body, "([a-zA-Z-]+):(%S+)") do
      names[k]=v
   end
   return names
end

-- RESPONSE_PROTOCOL
function M.get_response_protocol()
   local body = M.get_reponse_body()
   local proto = string.match(body, "^HTTP/%d+\\.%d+")
   return proto
end

-- RESPONSE_STATUS
function M.get_response_protocol()
   local body = M.get_reponse_body()
   local status = string.match(body, "^HTTP/%d+\\.%d+%s+(%d)")
   return status
end

return M
