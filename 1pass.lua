JSON = (loadfile "JSON.lua")()
dofile("dumptable.lua")

local basedir = "1Password/1Password.agilekeychain/data/default"  -- !!! FIXME
local password = argv[2]
local items = nil
local faveitems = nil
local keyhookRunning = false

local passwordTypeNameMap = {
    ["webforms.WebForm"] = "Logins",
    ["wallet.financial.CreditCard"] = "Credit cards",
    ["passwords.Password"] = "Passwords",
    ["wallet.financial.BankAccountUS"] = "Bank accounts",
    ["wallet.membership.Membership"] = "Memberships",
    ["wallet.government.DriversLicense"] = "Drivers licenses",
    ["system.Tombstone"] = "Dead items",
    ["securenotes.SecureNote"] = "Secure notes",
    -- !!! FIXME: more!
}

local passwordTypeOrdering = {
    "webforms.WebForm",
    "wallet.financial.CreditCard",
    "passwords.Password",
    "wallet.financial.BankAccountUS",
    "wallet.membership.Membership",
    "wallet.government.DriversLicense",
    "securenotes.SecureNote",
    -- never show "system.Tombstone",
    -- !!! FIXME: more!
}

local function load_json_str(str, desc)
    local retval = JSON:decode(str)
    return retval
end

local function load_json(fname)
    local f = io.open(fname, "rb")
    if (f == nil) then
        return nil
    end

    local str = f:read("*all")
    f:close()

    return load_json_str(str, fname)
end


local keys = {}
local function loadKey(level, password)
    if keys[level] ~= nil then
        return keys[level]
    end

    local keysjson = load_json(basedir .. "/encryptionKeys.js")
    if (keysjson == nil) or (keysjson[level] == nil) then
        return nil
    end

    local identifier = keysjson[level]
    for i,v in ipairs(keysjson.list) do
        if v.identifier == identifier then
			local iterations = v.iterations
            if (iterations == nil) or (iterations < 1000) then
			    iterations = 1000
            end

			local decrypted = decryptUsingPBKDF2(v.data, password, iterations)
			if decrypted == nil then
                return nil
            end

			local validate = decryptBase64UsingKey(v.validation, decrypted)
			if validate ~= decrypted then
                return nil
            end

            keys[level] = decrypted
            return decrypted
        end
    end

    return nil
end

local function getHint()
    local f = io.open(basedir .. "/.password.hint", "r")
    if (f == nil) then
        return
    end

    local str = "(hint is '" .. f:read("*all") .. "')."
    f:close()
    --print(str)
    return str
end


local function loadContents()
    return load_json(basedir .. "/contents.js")
end

local function build_secret_menuitem(menu, type, str, hidden)
    if str == nil then
        return nil
    end

    local valuestr = str
    if hidden == true then
        valuestr = "*****"
    end
    local text = type .. " " .. valuestr

    local callback = function()
        copyToClipboard(str)
        --print("Copied data [" .. str .. "] to clipboard.")
        keyhookRunning = false
    end
    return appendGuiMenuItem(menu, text, callback)
end


local secret_menuitem_builders = {}

local function build_secret_menuitem_webform(menu, info, secure)
    local addthis = false
    local username = nil
    local password = nil
    local designated_password = nil
    local designated_username = nil
    local email = nil

    if secure.fields == nil then
      print("no secure fields, don't know how to handle this item") 
      return
    end

    for i,v in ipairs(secure.fields) do
        --print(info.name .. ": " .. v.type .. ", " .. v.value)
        local ignored = false
        if (v.value == nil) or (v.value == "") then
            ignored = true
        elseif (v.designation ~= nil) and (v.designation == "password") then
            designated_password = v.value
        elseif (v.designation ~= nil) and (v.designation == "username") then
            designated_username = v.value
        elseif (v.type == "P") then
            password = v.value
        elseif (v.type == "T") then
            username = v.value
        elseif (v.type == "E") then
            email = v.value
        else
            ignored = true
        end

        if not ignored then
            addthis = true
        end
    end

    if addthis then
        -- designated fields always win out.
        if (designated_username ~= nil) then
            username = designated_username
        end

        if (designated_password ~= nil) then
            password = designated_password
        end

        if (username ~= nil) and (email ~= nil) and (email == username) then
            email = nil
        end

        build_secret_menuitem(menu, "username", username)
        build_secret_menuitem(menu, "email", email)
        build_secret_menuitem(menu, "password", password, true)
    end
end
secret_menuitem_builders["webforms.WebForm"] = build_secret_menuitem_webform


local function build_secret_menuitem_password(menu, info, secure)
    build_secret_menuitem(menu, "password", secure.password, true)
end
secret_menuitem_builders["passwords.Password"] = build_secret_menuitem_password


local function build_secret_menuitem_bankacctus(menu, info, secure)
    -- !!! FIXME: there's more data than this in a generic dictionary.
    build_secret_menuitem(menu, "Account type", secure.accountType)
    build_secret_menuitem(menu, "Routing number", secure.routingNo)
    build_secret_menuitem(menu, "Account number", secure.accountNo)
    build_secret_menuitem(menu, "Bank name", secure.bankName)
    build_secret_menuitem(menu, "Owner", secure.owner)
end
secret_menuitem_builders["wallet.financial.BankAccountUS"] = build_secret_menuitem_bankacctus


local function build_secret_menuitem_driverslic(menu, info, secure)
    -- !!! FIXME: there's more data than this in a generic dictionary.
    local birthdate = secure.birthdate_yy .. "/" .. string.sub("00" .. secure.birthdate_mm, -2) .. "/" .. string.sub("00" .. secure.birthdate_dd, -2)
    local expiredate = secure.expiry_date_yy .. "/" .. string.sub("00" .. secure.expiry_date_mm, -2)
    build_secret_menuitem(menu, "License number", secure.number)
    build_secret_menuitem(menu, "Class", secure.class)
    build_secret_menuitem(menu, "Expires", expiredate)
    build_secret_menuitem(menu, "State", secure.state)
    build_secret_menuitem(menu, "Country", secure.country)
    build_secret_menuitem(menu, "Conditions", secure.conditions)
    build_secret_menuitem(menu, "Full name", secure.fullname)
    build_secret_menuitem(menu, "Address", secure.address)
    build_secret_menuitem(menu, "Gender", secure.sex)
    build_secret_menuitem(menu, "Birthdate", birthdate)
    build_secret_menuitem(menu, "Height", secure.height)
end
secret_menuitem_builders["wallet.government.DriversLicense"] = build_secret_menuitem_driverslic


local function build_secret_menuitem_membership(menu, info, secure)
    -- !!! FIXME: there's more data than this in a generic dictionary.
    build_secret_menuitem(menu, "Membership number", secure.membership_no)
end
secret_menuitem_builders["wallet.membership.Membership"] = build_secret_menuitem_membership


local function build_secret_menuitem_creditcard(menu, info, secure)
    -- !!! FIXME: there's more data than this in a generic dictionary.
    local expiredate = secure.expiry_yy .. "/" .. string.sub("00" .. secure.expiry_mm, -2)
    build_secret_menuitem(menu, "Type", secure.type)
    build_secret_menuitem(menu, "CC number", secure.ccnum, true)
    build_secret_menuitem(menu, "CVV", secure.cvv, true)
    build_secret_menuitem(menu, "Expires", secure.expirydate)
    build_secret_menuitem(menu, "Card holder", secure.cardholder)
    build_secret_menuitem(menu, "Bank", secure.bank)
end
secret_menuitem_builders["wallet.financial.CreditCard"] = build_secret_menuitem_creditcard

local function build_secret_menuitem_securenote(menu, info, secure)
    build_secret_menuitem(menu, "Notes", secure.notesPlain, true)
end
secret_menuitem_builders["securenotes.SecureNote"] = build_secret_menuitem_securenote

local function build_secret_menuitems(info, menu)
    local metadata = load_json(basedir .. "/" .. info.uuid .. ".1password")
    if metadata == nil then
        return
    end

    local securityLevel = metadata.securityLevel
    if securityLevel == nil then
        securityLevel = metadata.openContents.securityLevel
    end
    --print("title: " .. metadata.title)
    if securityLevel == nil then
        --print("can't find security level, assuming SL5" .. metadata.title)
        securityLevel = "SL5"
    end

    local plaintext = decryptBase64UsingKey(metadata.encrypted, loadKey(securityLevel, password))
    if plaintext == nil then
        return
    end

    local secure = load_json_str(plaintext, info.uuid)
    if secure == nil then
        return
    end
    --dumptable("secure " .. info.name, secure)

    local menuitem = appendGuiMenuItem(menu, info.name)

    if secret_menuitem_builders[info.type] == nil then
        print("WARNING: don't know how to handle items of type " .. info.type)
        dumptable("secure " .. info.type .. " (" .. info.name .. ")", secure)
        return
    end

    if metadata.faveIndex ~= nil then
        --dumptable("fave metadata " .. info.name, metadata)
        faveitems[metadata.faveIndex] = { info=info, secure=secure }
    end

    local submenu = makeGuiMenu()
    secret_menuitem_builders[info.type](submenu, info, secure)
    setGuiMenuItemSubmenu(menuitem, submenu)
end

local function prepItems()
    items = {}
    local contents = loadContents()
    for i,v in ipairs(contents) do
        local t = v[2]
        if items[t] == nil then
            items[t] = {}
        end
        local bucket = items[t]
        bucket[#bucket+1] = { uuid=v[1], type=t, name=v[3], url=v[4] }  -- !!! FIXME: there are more fields, don't know what they mean yet.
    end
end

local passwordUnlockTime = nil

local function lockKeychain()
    -- lose the existing password and key, prompt user again.
    password = argv[2]  -- might be nil, don't reset if on command line.
    keys["SL5"] = nil
    passwordUnlockTime = nil
    keyhookRunning = false
    setPowermateLED(false)
    collectgarbage()
end

function pumpLua()  -- not local! Called from C!
    -- !!! FIXME: this should lose the key in RAM and turn off the Powermate
    -- !!! FIXME:  LED when the time expires instead of if the time has
    -- !!! FIXME:  expired when the user is trying to get at the keychain.
    if passwordUnlockTime ~= nil then
        local now = os.time()
        local maxTime = (15 * 60)  -- !!! FIXME: don't hardcode.
        if os.difftime(now, passwordUnlockTime) > maxTime then
            lockKeychain()
        end
    end
end


function keyhookPressed()  -- not local! Called from C!
--print("keyhookPressed: running==" .. tostring(keyhookRunning))
--    if keyhookRunning then
--        return
--    end

    keyhookRunning = true

    while password == nil do
        password = runGuiPasswordPrompt(getHint())
        if password == nil then
            keyhookRunning = false
            return
        end
        if loadKey("SL5", password) == nil then
            password = nil  -- wrong password
            local start = os.time()  -- cook the CPU for three seconds.
            local now = start
            while os.difftime(now, start) < 3 do
                now = os.time()
            end
        else
            passwordUnlockTime = os.time()
            setPowermateLED(true)
        end
    end

    prepItems()

    local topmenu = makeGuiMenu()
    local favesmenu = makeGuiMenu()
    faveitems = {}

    setGuiMenuItemSubmenu(appendGuiMenuItem(topmenu, "Favorites"), favesmenu)

    appendGuiMenuItem(topmenu, "Lock keychain", function() lockKeychain() end)

    for orderi,type in ipairs(passwordTypeOrdering) do
        local bucket = items[type]
        if bucket ~= nil then
            local realname = passwordTypeNameMap[type]
            if realname == nil then
                realname = type
            end
            local menuitem = appendGuiMenuItem(topmenu, realname)
            local submenu = makeGuiMenu()
            table.sort(bucket, function(a, b) return a.name < b.name end)
            for i,v in pairs(bucket) do
                build_secret_menuitems(v, submenu)
            end
            setGuiMenuItemSubmenu(menuitem, submenu)
        else
            --print("no bucket found for item type '" .. type .. "'")
        end
    end
    
    -- This favepairs stuff is obnoxious.
    local function favepairs(t)
        local a = {}
        for n in pairs(t) do table.insert(a, n) end
        table.sort(a)
        local i = 0
        local iter = function()
            i = i + 1
            if a[i] == nil then
                return nil
            else
                return a[i], t[a[i]]
            end
        end
        return iter
    end

    for i,v in favepairs(faveitems) do
        --dumptable("fave " .. i, v)
        local menuitem = appendGuiMenuItem(favesmenu, v.info.name)
        local submenu = makeGuiMenu()
        secret_menuitem_builders[v.info.type](submenu, v.info, v.secure)
        setGuiMenuItemSubmenu(menuitem, submenu)
    end

    favepairs = nil
    faveitems = nil

    popupGuiMenu(topmenu)
end


-- Mainline!

--for i,v in ipairs(argv) do
--    print("argv[" .. i .. "] = " .. v)
--end

-- !!! FIXME: message box, exit if basedir is wack.
-- !!! FIXME: this can probably happen in C now (the Lua mainline is basically gone now).
setPowermateLED(false)  -- off by default
print("Now waiting for the magic key combo (probably Alt-Meta-\\) ...")
giveControlToGui()

-- end of 1pass.lua ...

