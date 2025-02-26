local sus_patterns = {
    "https://discord.com/api/webhooks/",
    "discordapp.com/api/webhooks/",
    "grabify",
    "iplogger",
    "stealer",
    "keylogger",
    "doxbin",
    "robux%-generator",
    "free%-robux"
  -- add more if you want
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

-- Helper function: checks if a string contains suspicious content
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

local originalLoadString = loadstring

loadstring = function(code, chunkName)
    -- Check for suspicious URL
    local url_suspicious, urlMatches = is_suspicious_str(code, sus_patterns)
    
    -- Check if script tries to send requests
    local http_suspicious, httpMatches = is_suspicious_str(code, sus_functions)

    if url_suspicious or http_suspicious then
        local detectedIssues = {}
        if url_suspicious then
            table.insert(detectedIssues, "Suspicious URLs: " .. table.concat(urlMatches, ", "))
        end
        if http_suspicious then
            table.insert(detectedIssues, "Network requests detected: " .. table.concat(httpMatches, ", "))
        end
        warn("[BLOCKED] Malicious script detected! " .. table.concat(detectedIssues, " | "))
        return function() end  -- Return a blank function, preventing execution
    end

    -- If it's safe it will execute the script normally
    return originalLoadString(code, chunkName)
end

-------------------------
--  HOOK HTTP REQUESTS --
-------------------------

-- Hooking syn.request 
if syn and syn.request then
    local originalSynRequest = syn.request
    syn.request = function(options)
        local url = (options.Url or options.url or "")
        local suspicious, matched = is_suspicious_str(url, sus_patterns)
        if suspicious then
            warn("[BLOCKED] Suspicious HTTP request detected! Patterns: " .. table.concat(matched, ", "))
            return { StatusCode = 403, Body = "Request blocked by anti-malware script." }
        end
        return originalSynRequest(options)
    end
end

-- Hook game:HttpGet
do
    local originalHttpGet = game.HttpGet
    game.HttpGet = function(self, url, ...)
        local suspicious, matched = is_suspicious_str(url, sus_patterns)
        if suspicious then
            warn("[BLOCKED] Suspicious HttpGet detected! Patterns: " .. table.concat(matched, ", "))
            return "" -- Block response
        end
        return originalHttpGet(self, url, ...)
    end
end

-- Hook HttpService:RequestAsync
local httpService = game:GetService("HttpService")
local originalRequestAsync = httpService.RequestAsync

function httpService:RequestAsync(requestOptions)
    local url = requestOptions.Url or requestOptions.url or ""
    local suspicious, matched = is_suspicious_str(url, sus_patterns)
    if suspicious then
        warn("[BLOCKED] Suspicious RequestAsync detected! Patterns: " .. table.concat(matched, ", "))
        return { Success = false, StatusCode = 403, Body = "Request blocked by anti-malware script." }
    end
    return originalRequestAsync(self, requestOptions)
end
