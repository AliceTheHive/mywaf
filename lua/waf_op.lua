local M = {}

local lib_containsWord = waf_lib.containsWord
local lib_contains = waf_lib.contains
local lib_beginsWith = waf_lib.beginsWith
local lib_endsWith = waf_lib.endsWith
local lib_within = waf_lib.within
local lib_acmp_match = waf_lib.acmp_match
local lib_acmp_compile = waf_lib.acmp_compile
local fast_match = ngx.re.fast_match
local next = next

local function rx_hash(hash, regex, key)
   local keys = hash[0]
   local vals = hash[1]
   for i, k in ipairs(keys) do
      local v = vals[i]
      local match = fast_match(v, regex, "jo", key)
      if match ~= nil and next(match) ~= nil then
         return match, keys[i]
      end
   end
end

function M.rx(list, regex, key)
   for _, h in ipairs(list) do   
      local m, n = rx_hash(h, regex, key)
      if m then
         return m, n
      end
   end
end

function M.remove_key_by_rx(hash, key_rx)
   for k, v in ipairs(hash) do
      if fast_match(k, key_rx, "jo", key_rx) then
         hash[k] = nil
      end
   end
end

local function do_list(func, list, word)
   for _, h in ipairs(list) do   
      local v, n = func(h, word)
      if v then
         if type(v) ~= 'table' then
            local t = {v}
            return t, n
         else
            return v, n
         end
      end
   end
end

local function containsWord_hash(hash, word)
   local keys = hash[0]
   local vals = hash[1]
   local word_len = #word
   for i, v in ipairs(vals) do
      if lib_containsWord(v, #v, word, word_len) ~= 0 then
         return v, keys[i]
      end
   end
   return false
end

function M.containsWord(list, word)
   return do_list(containsWord_hash, h, word)
end

local function beginsWith_hash(hash, word)
   local keys = hash[0]
   local vals = hash[1]
   local word_len = #word
   for i, v in ipairs(vals) do
      if lib_beginsWith(v, #v, word, word_len) ~= 0 then
         return v, keys[i]
      end
   end
   return false
end

function M.beginsWith(list, word)
   return do_list(beginsWith_hash, list, word)
end

local function endsWith_hash(hash, word)
   local keys = hash[0]
   local vals = hash[1]
   local word_len = #word
   for i, v in ipairs(vals) do
      if lib_endsWith(v, #v, word, word_len) ~= 0 then
         return v, keys[i]
      end
   end
   return false
end

function M.endsWith(list, word)
   return do_list(endsWith_hash, list, word)
end

local function within_hash(hash, word)
   local keys = hash[0]
   local vals = hash[1]
   local word_len = #word
   for i, v in ipairs(vals) do
      if lib_within(v, #v, word, word_len) ~= 0 then
         return v, keys[i]
      end
   end
   return false
end

function M.within(list, word)
   return do_list(within_hash, list, word)
end

local function contains_hash(hash, word)
   local keys = hash[0]
   local vals = hash[1]
   local word_len = #word
   for i, v in ipairs(vals) do
      if lib_contains(v, #v, word, word_len) ~= 0 then
         return v, keys[i]
      end
   end
   return false
end

function M.contains(list, word)
   return do_list(contains_hash, list, word)
end

local function pm_hash(hash, word)
   local keys = hash[0]
   local vals = hash[1]
   local out =ffi_new("char[?]", 256)
   local out_len = #word
   local acmp = acmp_cache[word]
   for i, v in ipairs(vals) do
      if lib_acmp_match(acmp, v, #v, out, out_len) ~= 0 then
         return ffi_string(out, out_len), keys[i]
      end
   end
   return false
end

local acmp_cache = new_tab(4, 4)

function M.pm(list, word)
   if acmp_cache[word] then
      local pattern = {}
      for s in string.gmatch(word, "%S+") do
         table.insert(pattern, s)
      end
      acmp = lib_acmp_compile(patten, #pattern)
      acmp_cache[word] = acmp
   end
   return do_list(pm_hash, list, word)
end

return M
