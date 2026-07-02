-- Source: https://github.com/O-X-L/haproxy-ja4h
-- Copyright (C) 2025 Rath Pascal
-- License: MIT
-- Algorithm License: FoxIO License (https://github.com/FoxIO-LLC/ja4/blob/main/LICENSE)

-- JA4H
-- see: https://github.com/FoxIO-LLC/ja4
-- config:
--   register: lua-load /etc/haproxy/lua/ja4h.lua (in global)
--   run: http-request lua.fingerprint_ja4h
--   log: http-request capture var(txn.fingerprint_ja4h) len 51
--   acl: var(txn.fingerprint_ja4h) -m str ge11cn21enus_9022c49255fb_ac95b44401d9_8df6a44f726c

local function split_string(str, delimiter)
    local result = {}
    local from = 1
    local delim_from, delim_to = string.find(str, delimiter, from)
    while delim_from do
        table.insert(result, string.sub(str, from, delim_from-1))
        from = delim_to + 1
        delim_from, delim_to = string.find(str, delimiter, from)
    end
    table.insert(result, string.sub(str, from))
    return result
end

function starts_with(value, start)
    return type(value) == 'string' and type(start) == 'string' and string.sub(value, 1, 1) == start
end

local function http_version(txn)
    local v = txn.f:req_ver()
    if (v == '3.0') then
        return '30'
    elseif (v == '2.0') then
        return '20'
    else
        return '11'
    end
end

local function method_code(txn)
    return string.sub(string.lower(txn.f:method()), 1, 2)
end

-- TODO: 'connection' header missing for some reason?
local function header_count(txn)
    local c = 0;
    for _,h in pairs(split_string(txn.f:req_hdr_names(), ',')) do
        if (not starts_with(h, 'cookie') and h ~= 'referer') then
            c = c + 1
        end
    end
    return c
end

local function header_order(txn)
    -- HAProxy returns header names lowercase, comma-separated in request order
    return txn.f:req_hdr_names() or ''
end

local function referer_is_set(txn)
    local r = txn.f:req_hdr('referer')
    if (not r) then
        return 'n'
    end
    return 'r'
end

local function cookie_is_set(txn)
    local c = txn.f:req_hdr('cookie')
    if (not c) then
        return 'n'
    end
    return 'c'
end

-- https://github.com/FoxIO-LLC/ja4/blob/main/python/ja4h.py#L12
local function accept_lang_beg(txn)
    local al = txn.f:req_fhdr('accept-language')
    if (not al) then
        return '0000'
    end
    al = string.lower(al:gsub('%W',''))
    if (#al < 4) then
        return string.rep('0', 4 - #al) .. al
    end
    return string.sub(al, 1, 4)
end

-- https://github.com/FoxIO-LLC/ja4/blob/main/python/ja4h.py#L27
local function header_names_sorted(txn)
    local h = split_string(txn.f:req_hdr_names(), ',')
    table.sort(h)
    if (not h) then
        return ''
    end
    return table.concat(h, ',')
end

-- https://github.com/FoxIO-LLC/ja4/blob/main/python/ja4h.py#L37
local function cookie_names_sorted(txn)
    local c = txn.f:req_cook_names()
    if (not c) then
        return ''
    end
    local cl = split_string(c, ',')
    table.sort(cl)
    if (not cl) then
        return ''
    end
    return table.concat(cl, ',')
end

local function cookie_names_and_values_sorted(txn)
    local cl = {}
    local c = txn.f:req_cook_names()
    if (not c or c == '') then
        return ''
    end
    for i,k in pairs(split_string(c, ',')) do
        local v = txn.f:req_cook(k)
        if (not v) then
            v = ''
        end
        table.insert(cl, k .. '=' .. v)
    end
    table.sort(cl)
    if (not cl) then
        return ''
    end
    return table.concat(cl, ',')
end

local function truncated_sha256(txn, value)
    if (#value == 0) then
        return '000000000000'
    else
        return string.sub(string.lower(txn.c:hex(txn.c:digest(value, 'sha256'))), 1, 12)
    end
end

function fingerprint_ja4h(txn)
    local p1 = method_code(txn)
    local p2 = http_version(txn)
    local p3 = cookie_is_set(txn)
    local p4 = referer_is_set(txn)
    local p5 = header_count(txn)
    local p6 = accept_lang_beg(txn)

    local p7_pretty = header_names_sorted(txn)
    local p7 = truncated_sha256(txn, p7_pretty)

    local p8_pretty = cookie_names_sorted(txn)
    local p8 = truncated_sha256(txn, p8_pretty)

    local p9_pretty = cookie_names_and_values_sorted(txn)
    local p9 = truncated_sha256(txn, p9_pretty)

    txn:set_var('txn.fingerprint_ja4h_raw', p1 .. '_' .. p2 .. '_' .. p3 .. '_' .. p4 .. '_' .. p5 .. '_' .. p6 .. '_' .. p7_pretty .. '_' .. p8_pretty .. '_' .. p9_pretty)
    txn:set_var('txn.fingerprint_ja4h', p1 .. p2 .. p3 .. p4 .. p5 .. p6 .. '_' .. p7 .. '_' .. p8 .. '_' .. p9)
    txn:set_var('txn.header_order', header_order(txn))
end

core.register_action('fingerprint_ja4h', {'http-req'}, fingerprint_ja4h)
