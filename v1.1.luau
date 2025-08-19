local HttpService = game:GetService("HttpService")
local Players = game:GetService("Players")

local sus_patterns = {
    "discord%.com/api/webhooks",
    "grabify",
    "iplogger",
    "stealer",
    "keylogger",
    "doxbin",
    "robux%-generator",
    "free%-robux",
    "pastebin",
    "hastebin",
    "controlc",
    "sendip",
    "ps3cfw",
    "xss%.is",
    "webhook"
}

local sus_functions = {
    "syn%.request",
    "request",
    "http_request",
    "game%.HttpGet",
    "HttpService%:RequestAsync"
}

local sus_data_collection = {
    "Players%.LocalPlayer%.UserId",
    "Players%.LocalPlayer%.Name",
    "Players%.LocalPlayer%.DisplayName",
    "game:HttpGet%(.*ident%.me.*%)",
    "game:HttpGet%(.*ip%-api%.com.*%)",
    "identifyexecutor"
}

-- Normalize strings for scanning
local function normalize(str)
    return str:lower():gsub("%s+", ""):gsub("\"", ""):gsub("'", "")
end

-- Decode base64 safely
local function try_base64_decode(str)
    local success, decoded = pcall(function() return HttpService:Base64Decode(str) end)
    return success and decoded or str
end

-- Convert string.char sequences to string
local function decode_string_char(str)
    local result = str:gsub("string.char%(([%d,]+)%)", function(nums)
        local chars = {}
        for n in nums:gmatch("%d+") do table.insert(chars, string.char(tonumber(n))) end
        return table.concat(chars)
    end)
    return result
end

-- Convert hex-encoded string to normal string
local function decode_hex(str)
    local decoded = str:gsub("\\x(%x%x)", function(h) return string.char(tonumber(h,16)) end)
    return decoded
end

-- Multi-layer decode
local function multilayer_decode(str, max_layers)
    max_layers = max_layers or 3
    local prev
    for i = 1, max_layers do
        prev = str
        str = decode_string_char(str)
        str = decode_hex(str)
        str = try_base64_decode(str)
        if str == prev then break end
    end
    return str
end

-- Core detection
local function detect_suspicious(str, source)
    str = normalize(str)
    str = multilayer_decode(str)

    local matched = {}
    for _, pattern in ipairs(sus_patterns) do if str:find(pattern) then table.insert(matched, pattern) end end
    for _, pattern in ipairs(sus_functions) do if str:find(pattern) then table.insert(matched, pattern) end end
    for _, pattern in ipairs(sus_data_collection) do if str:find(pattern) then table.insert(matched, pattern) end end

    if #matched > 0 then
        warn(("[BLOCKED] Suspicious code detected in %s! Patterns: %s"):format(source, table.concat(matched, ", ")))
        return true
    end
    return false
end

-- Hook loadstring
local old_loadstring = loadstring
loadstring = function(code, chunkName)
    if detect_suspicious(code, "loadstring") then return function() end end
    return old_loadstring(code, chunkName)
end

-- Hook game.HttpGet
local old_http_get = game.HttpGet
game.HttpGet = function(self, url, ...)
    if detect_suspicious(url, "HttpGet") then return "" end
    return old_http_get(self, url, ...)
end

-- Hook HttpService:RequestAsync
local old_request_async = HttpService.RequestAsync
function HttpService:RequestAsync(options)
    if detect_suspicious(options.Url or options.url or "", "RequestAsync") or
       detect_suspicious(options.Body or "", "RequestAsync") then
        return { Success = false, StatusCode = 403, Body = "Request blocked." }
    end
    return old_request_async(self, options)
end

if syn and syn.request then
    local old_syn_request = syn.request
    syn.request = function(opts)
        if detect_suspicious(opts.Url or opts.url or "", "syn.request") or
           detect_suspicious(opts.Body or "", "syn.request") then
            return { StatusCode = 403, Body = "Request blocked." }
        end
        return old_syn_request(opts)
    end
end
