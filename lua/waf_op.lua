local M = {}

local lib_containsWord = waf_lib.containsWord
local lib_contains = waf_lib.contains
local lib_beginsWith = waf_lib.beginsWith
local lib_endsWith = waf_lib.endsWith
local lib_within = waf_lib.within
local lib_pm = waf_lib.pm_match
local fast_match = ngx.re.fast_match

local function rx_hash(hash, regex, key)
   local keys = hash[0]
   local vals = hash[1]
   for i, k in ipairs(keys) do
      local v = vals[i]
      if fast_match(v, regex, "jo", key) then
         return v, keys[i]
      end
   end
end

function M.rx(list, regex, key)
   for _, h in ipairs(list) do   
      local v, n = rx_hash(h, regex, key)
      if v then
         return v, n
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
         return v, n
      end
   end
end

local function containsWord_hash(hash, word)
   local keys = hash[0]
   local vals = hash[1]
   local word_len = #word
   for i, v in ipairs(vals) do
      if lib_containsWord(v, #v, word, word_len) ~= 0 then
         return keys[i], v
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
         return keys[i], v
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
         return keys[i], v
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
         return keys[i], v
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
         return keys[i], v
      end
   end
   return false
end

function M.contains(list, word)
   return do_list(contains_hash, list, word)
end

return M
