local M = {}
local resty_string = require "resty.string"
local cjson = require "cjson"
local ngx_re_find = ngx.re.find
local ngx_log = ngx.log
local LOG_ERR = ngx.ERR
local LOG_INFO = ngx.INFO
local LOG_WARN = ngx.WARN

local function purify_args(args)
   if type(args) ~= "table" then
      return
   end
   for _, tab in ipairs(args) do
      if type(tab) == 'table' then
         for k, v in pairs(tab) do
            if ngx_re_find(v, "[\x80-\xFF]", "jo") then
               args[k] = resty_string.to_hex(v)
            end
         end
      end
   end
end

function M.block(args, v)
   if v["TX:ANOMALY_SCORE_BLOCKING"] then
      if v["TX:ANOMALY_SCORE"] >= v["TX:INBOUND_ANOMALY_SCORE_LEVEL"] then
         --purify_args(args)
         ngx_log(LOG_ERR, "block!" .. cjson.encode(args))
         ngx.exit(404)
      end
   else
      --purify_args(args)
      ngx_log(LOG_ERR, "block!" .. cjson.encode(args))
      ngx.exit(404)
   end
end

function M.logdata(v,msg)
   local prefix = ''
   if v['RULE:ID'] ~= nil then
      prefix = 'id:' .. v['RULE:ID'] .. ' '
   end
   if v['RULE:MSG'] ~= nil then
      prefix = v['RULE:MSG'] .. ' ' .. prefix .. ' '
   end
   local from, to = ngx_re_find(msg, "[\x80-\xFF]", "jo")
   if from then
      msg = "HEX:" .. resty_string.to_hex(msg)
   end
   ngx_log(LOG_ERR, "WAF ", prefix .. msg)
end

function M.msg(msg)
   ngx_log(LOG_ERR, "WAF ", msg)
end

return M
