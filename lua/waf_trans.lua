--require "string_utils"
local ffi = require("ffi")
local ffi_new = ffi.new
local ffi_string = ffi.string
local waf_var = require 'waf_var'
local copy = waf_var.copy
local lib_hexEncode = waf_lib.hexEncode
local lib_hexDecode = waf_lib.hexDecode
local lib_normalizePath = waf_lib.normalizePath
local lib_trim = waf_lib.trim
local lib_trimLeft = waf_lib.trimLeft
local lib_trimRight = waf_lib.trimRight
local lib_removeNulls = waf_lib.removeNulls
local lib_replaceNulls = waf_lib.replaceNulls

local M = {}
-- todo: dummy function

local function do_list(func, list)
   local result = {}
   for _, h in ipairs(list) do
      local hash = copy(h)
      table.insert(result, hash)
      for k, v in pairs(hash) do
         local nv = func(v)
         hash[k] = nv
      end
   end
   return result
end

function normlize_path(str)
   local input = ffi_new("char[?]", #str, str)
   local len = lib_normalizePath(input, #str)
   return ffi_string(input, len)
end

function M.normalisePath(list)
   return do_list(normlize_path, list)
end

function M.normalizePath(list)
   return do_list(normlize_path, list)
end

function M.normalisePathWindows(list)
   return list
end

function M.htmlEntityDecode(list)
   return list
end

function M.lowercase(list)
   return do_list(string.lower, list)
end

function M.compressWhiteSpace(list)
   return list
end

function M.cmdLine(list)
   return list
end

function M.replaceComments(list)
   return list
end

function remove_nulls(str)
   local out = ffi_new("char[?]", #str)
   local len = lib_removeNulls(str, #str, out, #str)
   return ffi_string(out, len)
end

function M.removeNulls(list)
   return do_list(remove_nulls, list)
end

local function trim_left(str)
   local out = ffi_new("char*[1]")
   local len = lib_trimLeft(str, #str, out)
   if len == #str then
      return str
   else
      return ffi_string(out[0], len)
   end
end

function M.trimLeft(list)
   return do_list(trim_left, list)
end

local function trim_right(str)
   local out = ffi_new("char*[1]")
   local len = lib_trimRight(str, #str, out)
   if len == #str then
      return str
   else
      return ffi_string(out[0], len)
   end
end

function M.trimRight(list)
   return do_list(trim_right, list)
end

local function trim(str)
   local s = trim_left(str)
   return trim_right(s)
end

function M.trim(list)
   return do_list(trim, list)
end

function M.replaceComments(list)
   return list
end

local function replace_nulls(str)
   local out = ffi_new('char[?]', #str, str)
   local len = lib_replaceNulls(out, #str)
   return ffi_string(out, len)
end

function M.replaceNulls(list)
   return do_list(replace_nulls, list)
end

function M.removeWhitespace(list)
   return list
end

local function hexEncode_single(str)
   local out_len = 2 * #str + 1;
   local out = ffi_new("char[?]", out_len)
   lib_hexEncode(str, #str, out, out_len)
   return ffi_string(out, out_len - 1)
end

function M.hexEncode(list)
   return do_list(hexEncode_single, list)
end

local function hexDecode_single(str)
   local out = ffi_new('char[?]', #str, str)
   local len = lib_hexDecode(out, #str)
   if len <= 0 then
      return ""
   else
      return ffi_string(out, len)
   end
end

function M.hexDecode(list)
   return do_list(hexDecode_single, list)
end

function M.base64Encode(list)
   return list
end

return M
