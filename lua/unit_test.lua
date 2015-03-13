require "regex_cache" 
require 'waf_lib'
local unit = require('luaunit')
local assertEquals = unit.assertEquals
local waf_op = require 'waf_op'
local waf_trans = require 'waf_trans'
function g(v)
   local list = {}
   local hash = { name=v }
   list = { hash }
   return list
end

TestOp = {}

function TestOp:test_waf_rx()
   matched, name = waf_op.rx(g('123abc'), "(\\d+).+")
   assertEquals(matched[0],'123abc')
   assertEquals(matched[1],'123')   
   assertEquals(name, 'name')
end

function TestOp:test_waf_contains()
   matched, name = waf_op.contains(g('abc good'), "good")
   assertEquals(matched[0], 'abc good')
   assertEquals(name, 'name')
end

function TestOp:test_waf_containsWord()
   matched, name = waf_op.containsWord(g('abc good'), "good")
   assertEquals(matched[0], 'abc good')
   assertEquals(name, 'name')
end

function TestOp:test_waf_beginsWith()
   matched, name = waf_op.beginsWith(g('goodbad'), "good")
   assertEquals(matched[0], 'goodbad')
   assertEquals(name, 'name')
end

function TestOp:test_waf_endsWith()
   matched, name = waf_op.endsWith(g('goodbad'), "bad")
   assertEquals(matched[0], 'goodbad')
   assertEquals(name, 'name')
end

function TestOp:test_waf_pm()
   matched, name = waf_op.pm(g('the good bad ugly god'), "ugly")
   assertEquals(matched[0], 'the good bad ugly god')
   assertEquals(matched[1], 'ugly')
   assertEquals(name, 'name')
end

function TestOp:test_waf_pmFromFile()
   matched, name = waf_op.pm(g('the good bad ugly god'), "test_pm.data")
   assertEquals(matched[0], 'the good bad ugly god')
   assertEquals(matched[1], 'ugly')
   assertEquals(name, 'name')
end

TestTrans = {}

function TestTrans:test_waf_lowercase()
   local list = g('ABCD')
   local val = waf_trans.lowercase(list)
   assertEquals(val[1]['name'], 'abcd')
   assertEquals(list[1]['name'], 'ABCD')
end

function TestTrans:test_waf_hexEncode()
   local list = g('hexEncode')
   local val = waf_trans.hexEncode(list)
   assertEquals(val[1]['name'], '686578456e636f6465')

end

function TestTrans:test_waf_hexDecode()
   local list = g('686578456e636f6465')
   local val = waf_trans.hexDecode(list)
   assertEquals(val[1]['name'], 'hexEncode')
end

function TestTrans:test_waf_normalisePath()
   local list = g('/usr////test///')
   local val = waf_trans.normalisePath(list)
   assertEquals(val[1]['name'], '/usr/test/')
end

function TestTrans:test_waf_trim()
   local list = g(' test trim ')
   local val = waf_trans.trim(list)
   assertEquals(val[1]['name'], 'test trim')
end

function TestTrans:test_waf_trimLeft()
   local list = g(' test')
   local val = waf_trans.trimLeft(list)
   assertEquals(val[1]['name'], 'test')
end

function TestTrans:test_waf_trimRight()
   local list = g('test ')
   local val = waf_trans.trimRight(list)
   assertEquals(val[1]['name'], 'test')
end

function TestTrans:test_waf_removeNulls()
   local list = g("remove\0Nulls")
   local val = waf_trans.removeNulls(list)
   assertEquals(val[1]['name'], 'removeNulls')
end

function TestTrans:test_waf_replaceNulls()
   local list = g("replace\0Nulls")
   local val = waf_trans.replaceNulls(list)
   assertEquals(val[1]['name'], 'replace Nulls')
end

unit.LuaUnit.run()
