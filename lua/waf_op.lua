local ffi = require("ffi")
local ffi_new = ffi.new
local ffi_string = ffi.string
local base = require "resty.core.base"
local new_tab = base.new_tab
local M = {}

local lib_containsWord = waf_lib.containsWord
local lib_contains = waf_lib.contains
local lib_beginsWith = waf_lib.beginsWith
local lib_endsWith = waf_lib.endsWith
local lib_within = waf_lib.within
local lib_pm_match = waf_lib.pm_match
local lib_pm_compile = waf_lib.pm_compile
local lib_pm_compile_ok = waf_lib.is_pm_compile_ok
local fast_match = ngx.re.fast_match
local next = next

local function rx_hash(hash, regex)
   for k, v in pairs(hash) do
      local match = fast_match(v, regex, "jo")
      if match ~= nil and next(match) ~= nil then
         return match, k
      end
   end
end

function M.rx(list, regex)
   for _, h in pairs(list) do   
      local m, n = rx_hash(h, regex)
      if m then
         return m, n
      end
   end
end

local function do_list(func, list, word)
   for _, h in pairs(list) do
      local v, n = func(h, word)
      if v then
         if type(v) ~= 'table' then
            local t = {}
            t[0] = v
            return t, n
         else
            return v, n
         end
      end
   end
end
-- Don't Repeat Yourself? oh

local function contains_hash(hash, word)
   local word_len = #word
   for k, v in pairs(hash) do
      if lib_contain(v, #v, word, word_len) ~= 0 then
         return v, k
      end
   end
   return false
end

function M.contains(list, word)
   return do_list(contains_hash, list, word)
end

local function containsWord_hash(hash, word)
   local word_len = #word
   for k, v in pairs(hash) do
      if lib_containsWord(v, #v, word, word_len) ~= 0 then
         return v, k
      end
   end
   return false
end

function M.containsWord(list, word)
   return do_list(containsWord_hash, list, word)
end

local function beginsWith_hash(hash, word)
   local word_len = #word
   for k, v in pairs(hash) do
      if lib_beginsWith(v, #v, word, word_len) ~= 0 then
         return v, k
      end
   end
   return false
end

function M.beginsWith(list, word)
   return do_list(beginsWith_hash, list, word)
end

local function endsWith_hash(hash, word)
   local word_len = #word
   for k, v in pairs(hash) do
      if lib_endsWith(v, #v, word, word_len) ~= 0 then
         return v, k
      end
   end
   return false
end

function M.endsWith(list, word)
   return do_list(endsWith_hash, list, word)
end

local function within_hash(hash, word)
   local word_len = #word
   for k, v in pairs(hash) do
      if lib_within(v, #v, word, word_len) ~= 0 then
         return v, k
      end
   end
   return false
end

function M.within(list, word)
   return do_list(within_hash, list, word)
end

local function contains_hash(hash, word)
   local word_len = #word
   for k, v in pairs(hash) do
      if lib_contains(v, #v, word, word_len) ~= 0 then
         return v, k
      end
   end
   return false
end

function M.contains(list, word)
   return do_list(contains_hash, list, word)
end

local acmp_cache = new_tab(4, 4)

local function pm_hash(hash, word)
   local out =ffi_new("char[?]", 256)
   local out_len = 256
   local acmp = acmp_cache[word]
   if not acmp then
      ngx.log(ngx.ERR, "acmp is null: ", word)
      return false
   end
   for k, v in pairs(hash) do
      if lib_pm_match(acmp, v, #v, out, out_len) ~= 0 then
         ngx.log(ngx.ERR, "pm result: ", ffi_string(out, out_len))
         return ffi_string(out, out_len), k
      end
   end
   return false
end

function M.pm(list, word)
   if word == '' or word == nil then
      ngx.log(ngx.ERR, "pm word is null", debug.traceback("Stack trace"))
      return false
   end
   if not acmp_cache[word] then
      acmp = lib_pm_compile(word)
      if lib_pm_compile_ok(acmp) ~= 0 then
         acmp_cache[word] = acmp
      else
         ngx.log(ngx.ERR, "pm compile failed: ", word)
         return false
      end
   end
   return do_list(pm_hash, list, word)
end

return M
