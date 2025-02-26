local sus_patterns = {
    "https://discord.com/api/webhooks/",
    "discordapp.com/api/webhooks/",
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
    "xss.is",
    "webhook"
-- add more if you want or remove
}

-- List of network-related functions to detect in a loadstring
-- just detecting if something is sending requests using these functions
local sus_functions = {
    "syn%.request",
    "request",
    "http_request",
    "game%.HttpGet",
    "HttpService%:RequestAsync"
}
-- some of these data are not bad but i just added it anyways, like the accountAge, or Name or displayname but i just added it anyways.
local sus_data_collection = {
    "game:GetService%('RbxAnalyticsService'%)",
    "Players.LocalPlayer.UserId",
    "Players.LocalPlayer.DisplayName",
    "Players.LocalPlayer.Name",
    "Players.LocalPlayer.MembershipType",
    "Players.LocalPlayer.AccountAge",
    "game.PlaceId",
    "game.JobId",
    "identifyexecutor",
    "game:HttpGet%(%\"https://v4.ident.me/%\"%)",
    "game:HttpGet%(%\"http://ip-api.com/json%\"%)"
}

local function is_suspicious_str(str, patterns)
    local lowerStr = str:lower()
    local matchedPatterns = {}
    for _, pattern in ipairs(patterns) do
        if string.find(lowerStr, pattern) then
            table.insert(matchedPatterns, pattern)
        end
    end
    return #matchedPatterns > 0, matchedPatterns
end

----------------------
--  HOOK LOADSTRING --
----------------------

local original_loadstring = loadstring

loadstring = function(code, chunkName)
    -- Check for suspicious URL
    local url_suspicious, url_matches = is_suspicious_str(code, sus_patterns)

    -- Check for suspicious network functions
    local http_suspicious, http_matches = is_suspicious_str(code, sus_functions)

    -- Check if script tries to collect user data
    local data_suspicious, data_matches = is_suspicious_str(code, sus_data_collection)

    if url_suspicious or http_suspicious or data_suspicious then
        local detected_issues = {}
        if url_suspicious then
            table.insert(detected_issues, "Suspicious URLs: " .. table.concat(url_matches, ", "))
        end
        if http_suspicious then
            table.insert(detected_issues, "Network requests detected: " .. table.concat(http_matches, ", "))
        end
        if data_suspicious then
            table.insert(detected_issues, "User data collection detected: " .. table.concat(data_matches, ", "))
        end
        warn("[BLOCKED] Malicious script detected! " .. table.concat(detected_issues, " | "))
        return function() end -- Block execution
    end

    -- Execute script normally if it's safe
    return original_loadstring(code, chunkName)
end

-------------------------
--  HOOK HTTP REQUESTS --
-------------------------

-- Hook syn.request
if syn and syn.request then
    local original_syn_request = syn.request
    syn.request = function(options)
        local url = (options.Url or options.url or "")
        local body = options.Body or ""

        local url_suspicious, url_matches = is_suspicious_str(url, sus_patterns)
        local body_suspicious, body_matches = is_suspicious_str(body, sus_patterns)

        if url_suspicious or body_suspicious then
            local detected_issues = {}
            if url_suspicious then
                table.insert(detected_issues, "Suspicious URL: " .. table.concat(url_matches, ", "))
            end
            if body_suspicious then
                table.insert(detected_issues, "Suspicious Data Sent: " .. table.concat(body_matches, ", "))
            end
            warn("[BLOCKED] Suspicious syn.request detected! " .. table.concat(detected_issues, " | "))
            return { StatusCode = 403, Body = "Request blocked by security script." }
        end
        return original_syn_request(options)
    end
end

-- Hook game:HttpGet
do
    local original_http_get = game.HttpGet
    game.HttpGet = function(self, url, ...)
        local suspicious, matched = is_suspicious_str(url, sus_patterns)
        if suspicious then
            warn("[BLOCKED] Suspicious HttpGet detected! Patterns: " .. table.concat(matched, ", "))
            return "" -- Block response
        end
        return original_http_get(self, url, ...)
    end
end

-- Hook HttpService:RequestAsync
local http_service = game:GetService("HttpService")
local original_request_async = http_service.RequestAsync

function http_service:RequestAsync(request_options)
    local url = request_options.Url or request_options.url or ""
    local body = request_options.Body or ""

    local url_suspicious, url_matches = is_suspicious_str(url, sus_patterns)
    local body_suspicious, body_matches = is_suspicious_str(body, sus_patterns)

    if url_suspicious or body_suspicious then
        local detected_issues = {}
        if url_suspicious then
            table.insert(detected_issues, "Suspicious URL: " .. table.concat(url_matches, ", "))
        end
        if body_suspicious then
            table.insert(detected_issues, "Suspicious Data Sent: " .. table.concat(body_matches, ", "))
        end
        warn("[BLOCKED] Suspicious RequestAsync detected! " .. table.concat(detected_issues, " | "))
        return { Success = false, StatusCode = 403, Body = "Request blocked by security script." }
    end
    return original_request_async(http_service, request_options)
end
