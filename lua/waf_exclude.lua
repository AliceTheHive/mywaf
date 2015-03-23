local M = {}

M.args = { ["/cgi-bin/epg_index.fcgi"]={'picinfo','channelidinfo'},
           ['/cgi-bin/chcaportal_index.fcgi']={'picinfo','channelidinfo'},
           ["/api/file/upload_meta"]={"metaData"},
           ["/aaa/signon"]={"loginName"}
         }

M.urls = {
   ['/sdkproxy/sendsms'] = 1,
   ['/log/report_terminal'] = 1,
   ['/api/dir/content'] = 1,
   ['/log/report_exception'] = 1,
   ['/log/report_terminal'] = 1,
   ['/sdkproxy/sendsms.action'] = 1,
   ['/api/dir/mkdir'] = 1,
   ['/api/weibo/mark'] = 1,
   ['/api/weibo/so'] = 1,
   ['/api/dir/content_count'] = 1,
   ['/ss/spSearch/getProgrames'] = 1
}

return M
