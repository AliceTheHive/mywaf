local M = {}

M.args = { ["/cgi-bin/epg_index.fcgi"]={'picinfo','channelidinfo'},
           ['/cgi-bin/chcaportal_index.fcgi']={'picinfo','channelidinfo'},
           ["/api/file/upload_meta"]={"metaData"},
           ["/aaa/signon"]={"loginName"}
         }
local reg = "^/sdkproxy/sendsms|^/log/report_terminal|^/log/report_exception"

function M.is_url_excluded(url)
   local v = ngx.re.match(url, reg, 'jo')
   return v ~= nil
end

return M
