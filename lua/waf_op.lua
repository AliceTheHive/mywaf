local M = {}

local lib_containsWord = waf_lib.containsWord
local lib_contains = waf_lib.contains
local lib_beginsWith = waf_lib.beginsWith
local lib_endsWith = waf_lib.endsWith
local lib_within = waf_lib.within
local lib_pm = waf_lib.pm_match
local fast_match = ngx.re.fast_match

function M.rx(data, regex, key)
   if fast_match(data, regex, "jo", key) then
      return data
   end
end

function M.rx_hash(hash, regex, key)
   local keys = hash[0]
   local vals = hash[1]
   for i, k in ipairs(keys) do
      local v = vals[i]
      if fast_match(v, regex, "jo", key) then
         return v, keys[i]
      end
   end
end

function M.rx_hash_list(list, regex, key)
   for _, h in ipairs(list) do   
      local v, n = M.rx_hash(h, regex, key)
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

function M.containsWord(str, word)
   if lib_containsWord(str, #str, word, #word) ~= 0 then
      return true
   end
   return false
end

function M.containsWord_hash(hash, word)
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

-- duplicate! again and again, just for speed
--  
function M.beginsWith(str, word)
   if lib_beginsWith(str, #str, word, #word) ~= 0 then
      return true
   end
   return false
end

function M.beginsWith_hash(hash, word)
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

function M.endsWith(str, word)
   if lib_endsWith(str, #str, word, #word) ~= 0 then
      return true
   end
   return false
end

function M.endsWith_hash(hash, word)
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

function M.within(str, word)
   if lib_within(str, #str, word, #word) ~= 0 then
      return true
   end
   return false
end

function M.within_hash(hash, word)
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

function M.contains(str, word)
   if lib_contains(str, #str, word, #word) ~= 0 then
      return true
   end
   return false
end

function M.contains_hash(hash, word)
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

return M
