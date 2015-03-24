local M = {}

M.args = { ["/cgi-bin/epg_index.fcgi"]={'picinfo','channelidinfo'},
           ['/cgi-bin/chcaportal_index.fcgi']={'picinfo','channelidinfo'},
           ["/api/file/upload_meta"]={"metaData"},
           ["/aaa/signon"]={"loginName"}
           ['/sdkproxy/sendsms'] = {},
           ['/log/report_terminal'] = {},
           ['/api/dir/content'] = {},
           ['/log/report_exception'] = {},
           ['/log/report_terminal'] = {},
           ['/sdkproxy/sendsms.action'] = {},
           ['/api/dir/mkdir'] = {},
           ['/api/weibo/mark'] = {},
           ['/api/weibo/so'] = {},
           ['/api/dir/content_count'] = {},
           ['/ss/spSearch/getProgrames'] = {}
         }

local excluded_urls = {}

for k, v in ipairs(M.args) do
   if #v == 0 then
      excluded_urls[k] = 1
      M.args[k] = nil
   end
end

function M.is_url_excluded(url)
   return excluded_urls[url] ~= nil
end

return M
