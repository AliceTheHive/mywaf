#include <stddef.h>
#include <ctype.h>
#include <lua.h>
#include <lauxlib.h>

// gcc -shared -fpic -O -I/usr/local/include/luajit-2.1 string_utils.c -o string_utils.so

int trim(lua_State *L)
{
    const char *front;
    const char *end;
    size_t      size;

    front = luaL_checklstring(L,1,&size);
    end   = &front[size - 1];

    for ( ; size && isspace(*front) ; size-- , front++)
        ;
    for ( ; size && isspace(*end) ; size-- , end--)
        ;

    lua_pushlstring(L,front,(size_t)(end - front) + 1);
    return 1;
}

int trimLeft(lua_State *L)
{
    const char *front;
    const char *end;
    size_t      size;

    front = luaL_checklstring(L,1,&size);
    end   = &front[size - 1];

    for ( ; size && isspace(*front) ; size-- , front++)
        ;

    lua_pushlstring(L,front,(size_t)(end - front) + 1);
    return 1;
}

int trimRight(lua_State *L)
{
    const char *front;
    const char *end;
    size_t      size;

    front = luaL_checklstring(L,1,&size);
    end   = &front[size - 1];

    for ( ; size && isspace(*end) ; size-- , end--)
        ;

    lua_pushlstring(L,front,(size_t)(end - front) + 1);
    return 1;
}

int luaopen_trim(lua_State *L)
{
    lua_register(L,"string_utils",trim);
    lua_register(L,"string_utils",trimLeft);
    lua_register(L,"string_utils",trimRight);
    return 0;
}
