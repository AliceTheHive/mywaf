require "regex_cache" 
require 'waf_lib'
local unit = require('luaunit')
local waf_op = require 'waf_op'

function test_waf_rx()
   local list = {}
   local hash = { name='123' }
   list = { hash }
   matched, name = waf_op.rx(list, "\\d+")
   assertEquals(matched[0],'123')
   assertEquals(name, 'name')
end


unit.run()
