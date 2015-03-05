local M = {}

local ngx_log = ngx.log
local LOG_ERR = ngx.ERR
local LOG_INFO = ngx.INFO

function M.block(v)
   ngx.exit(404)
end

function M.logdata(v,msg)
   local prefix = ''
   if v['RULE:ID'] ~= nil then
      prefix = 'id:' .. v['RULE:ID'] .. ' '
   end
   if v['RULE:MSG'] ~= nil then
      prefix = v['RULE:MSG'] .. ' ' .. prefix .. ' '
   end
   ngx_log(LOG_ERR, "WAF ", prefix .. msg)
end

function M.msg(msg)
   ngx_log(LOG_ERR, "WAF ", msg)
end

return M
