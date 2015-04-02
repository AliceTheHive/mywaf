local M = {}
local waf_exclude = require "waf_exclude"
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
local fast_match = ngx.re.fast_match
local cjson = require "cjson.safe"
local luaxml = require "LuaXML_lib"
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

function M.exclude_args(args)
   local r = waf_exclude.args[ngx.var.uri]
   if r ~= nil then
      for _, a in ipairs(r) do
         for n, v in pairs(args) do
            if a == n then args[n] = nil end
         end
      end
   end
   return args
end

local function deepcopy(orig)
   local orig_type = type(orig)
   local copy
   if orig_type == 'table' then
      copy = {}
      for orig_key, orig_value in next, orig, nil do
         copy[deepcopy(orig_key)] = deepcopy(orig_value)
      end
      setmetatable(copy, deepcopy(getmetatable(orig)))
   else -- number, string, boolean, etc
      copy = orig
   end
   return copy
end

function M.copy(orig)
   return deepcopy(orig)
end

function M.shallowcopy(orig)
    local orig_type = type(orig)
    local copy
    if orig_type == 'table' then
        copy = {}
        for orig_key, orig_value in pairs(orig) do
            copy[orig_key] = orig_value
        end
    else -- number, string, boolean, etc
        copy = orig
    end
    return copy
end

function M.remove_by_rx_key(hash, key_rx)
   for k, v in pairs(hash) do
      if fast_match(k, key_rx, "jo", key_rx) then
         hash[k] = nil
      end
   end
end

function M.remove_by_key(hash, key)
   hash[key] = nil
end

function M.filter_by_rx_key(hash, key_rx)
   local result = {}
   for k, v in pairs(hash) do
      if fast_match(k, key_rx, "jo", key_rx) then
         result[k] = v
      end
   end
   return result
end

local function get_keys(hash)
   local keys = {}
   for k, v in pairs(hash) do
      keys[#keys + 1] = k
   end
   return keys
end

local function get_json(args, name, t)
   if t == nil then return end
   for k, v in pairs(t) do
       if type(v) ~= 'table' then
          args[name .. "." .. k] = v
       else
          get_json(args, name .. "." .. k, v)
       end
   end
end

local function normlise_args(args)
   --  Arguments without the =<value> parts are treated as boolean arguments. GET /test?foo&bar will yield:
   --  foo: true
   --  bar: true
   for k, v in pairs(args) do
      if (v == true) then
         args[k] = nil
         v = nil
      elseif (type(v) == 'table') then
         local str = ""
         for _, s in ipairs(v) do
            if "string" == type(s) then
               str = str .. s;
            end
         end
         args[k] = str
         v = str
      end
      -- remove chinese characters
      local from, to, err = v and ngx.re.find(v, "[\x80-\xFF]{2,}", "jo")
      if from then
         local new_str = ngx.re.gsub(v, "[\x80-\xFF]{2,}", "cc", "jo")
         args[k] = new_str
      end
      -- 123 => '{'
      if v and string.byte(v,1) == 123 then
         local json = cjson.decode(v)
         if json then
            get_json(args, k, json)
            args[k] = nil
         end
      elseif v and string.byte(v,1) == 60 then
         local xml = luaxml.eval(v)
         if xml then
            get_json(args, k, json)
            args[k] = nil
         end
      end
   end
   args = M.exclude_args(args)
   return args
end

-- ARGS_GET
function M.get_args_get()
   local args = ngx_req_get_uri_args()
   return normlise_args(args)
end

-- ARGS_POST
function M.get_args_post()
   ngx_req_read_body()
   local args = ngx_req_get_post_args()
   return normlise_args(args)
end

-- ARGS
function M.get_args()
   local args = M.get_args_get()
   local args_post = M.get_args_post()
   for k, v in pairs(args_post) do
      args[k] = v
   end
   return args
end

-- do not check args
-- ARGS_GET_NAMES
function M.get_args_get_names()
   local r = {}
   return r
end

-- ARGS_POST_NAMES
function M.get_args_post_names()
   local r = {}
   return r
end

-- ARGS_NAMES
function M.get_args_names()
   return {}
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
   local raw_header = ngx_req_raw_header()
   for str_cookies in string.gmatch(raw_header, "Cookie: ([^\r\n]+)") do
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
   -- TODO:
   --return get_keys(cookies)
   return cookies
end

-- REQUEST_FILENAME
function M.get_request_filename()
   return ngx.var.request_filename
end

-- REQUEST_HEADERS
function M.get_request_headers()
   local headers = ngx_req_get_headers()
   for k, v in pairs(headers) do
      if type(v) == 'table' then
         headers[k] = table.concat(v, ",")
      end
   end
   return headers
end

-- REQUEST_HEADERS_NAMES
function M.get_request_headers_names()
   local headers = ngx_req_get_headers()
   -- TODO:
   --return get_keys(headers)
   return headers
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
   -- TODO: real array
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
