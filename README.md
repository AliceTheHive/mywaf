# mywaf

Usage:
generate rules of WAF:
#perl parse.pl rules/*.conf > waf_rules.lua

copy rules into nginx:
#cp waf_rules.lua /usr/local/openresty/nginx/

copy nginx.conf into nginx:
#cp nginx.conf /usr/local/openresty/nginx/conf

Now, WAF is done.
Faster and Simpler than mod_security in apache or nginx.