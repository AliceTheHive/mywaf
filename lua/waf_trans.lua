require "string_utils"

local M = {}
-- todo: dummy function

local function do_list(func, list)
   for _, h in ipairs(list) do
      for k, v in pairs(h) do
         local nv = func(v)
         h[k] = nv
      end
   end
end

function M.normalisePath(list)
   return list
end

function M.normalisePathWindows(list)
   return list
end

function M.htmlEntityDecode(list)
   return list
end

function M.lowercase(list)
   do_list(string.lowercase, list)
   return list
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

function M.removeNulls(list)
   return list
end

function M.trim(list)
   --do_list(string_utils.trim, list)
   return list
end

function M.trimLeft(list)
   --do_list(string_utils.trimLeft, list)
   return list
end

function M.trimRight(list)
   --do_list(string_utils.trimRight, list)
   return list
end

function M.replaceComments(list)
   return list
end

function M.replaceNulls(list)
   return list
end

function M.removeWhitespace(list)
   return list
end

function M.hexEncode(list)
   return list
end

function M.hexDecode(list)
   return list
end

function M.base64Encode(list)
   return list
end

return M
