local M = {}

local lib_containsWord = waf_lib.containsWord
local fast_match = ngx.re.fast_match

function M.rx(data, regex, key)
   return fast_match(data, regex, "jo", key)
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
         return true
      end
   end
   return false
end

function M.rx_hash(hash, regex, key)
   local keys = hash[0]
   local vals = hash[1]
   for i, k in ipairs(keys) do
      local v = vals[i]
      if fast_match(v, regex, "jo", key) then
         return v
      end
   end
end

return M
