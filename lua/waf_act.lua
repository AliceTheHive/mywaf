local M = {}

local ngx_log = ngx.log
local LOG_ERR = ngx.ERR
local LOG_INFO = ngx.INFO

function M.block(v)
end

function M.logdata(v)
   ngx_log(LOG_ERR, "WAF ", v)
end

function M.msg(msg)
   ngx_log(LOG_ERR, "WAF ", msg)
end
