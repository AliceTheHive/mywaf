local waf_exclude = require "waf_exclude"
local rules = assert(loadfile("/usr/local/fountain/3rdparty/nginx/waf_rules.lua"))
if waf_exclude.is_url_excluded(ngx.var.uri) then
   return
else
   rules()
end

