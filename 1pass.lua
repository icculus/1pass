JSON = (loadfile "JSON.lua")()
dofile("dumptable.lua")

local basedir = "1Password/1Password.agilekeychain/data/default"  -- !!! FIXME
local password = argv[2]
local items = nil
local faveitems = nil
local keyhookRunning = false
local keyhookGuiMenus = nil


local function runGarbageCollector()
    --local memused = math.floor(collectgarbage("count") * 1024.0)
    --print("Collecting garbage (currently using " .. memused .. " bytes).")
    collectgarbage()
    --local newmemused = math.floor(collectgarbage("count") * 1024.0)
    --print("Now using " .. newmemused .. " bytes (" .. memused - newmemused .. " bytes savings).")
end

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

    local str = f:read("*a")
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

    local str = "(hint is '" .. f:read("*a") .. "')."
    f:close()
    --print(str)
    return str
end


local function loadContents()
    return load_json(basedir .. "/contents.js")
end

local function makeMenu()
    return {}
end

local function appendMenuItem(menu, text, callback)
    local item = {}
    item["text"] = text
    if callback ~= nil then
        item["callback"] = callback
    end
    menu[#menu+1] = item
    return item
end

local function setMenuItemSubmenu(menuitem, submenu)
    menuitem["submenu"] = submenu
end

local function setMenuItemChecked(menuitem, ischecked)
    menuitem["checked"] = ischecked
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
        guiDestroyMenu(keyhookGuiMenus[1])
    end
    return appendMenuItem(menu, text, callback)
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
    build_secret_menuitem(menu, "SWIFT code", secure.swift)
    build_secret_menuitem(menu, "PIN", secure.telephonePin)
end
secret_menuitem_builders["wallet.financial.BankAccountUS"] = build_secret_menuitem_bankacctus


local function build_secret_menuitem_driverslic(menu, info, secure)
    -- !!! FIXME: there's more data for this menuitem than this, in a generic dictionary.

    local birthdate = nil
    if secure.birthdate_yy ~= nil then
        birthdate = secure.birthdate_yy
        if secure.birthdate_mm ~= nil then
            birthdate = birthdate .. "/" .. string.sub("00" .. secure.birthdate_mm, -2)
            if secure.birthdate_dd ~= nil then
                birthdate = birthdate .. "/" .. string.sub("00" .. secure.birthdate_dd, -2)
            end
        end
    end

    local expiredate = nil
    if secure.expiry_date_yy ~= nil then
        expiredate = secure.expiry_date_yy
        if secure.expiry_date_mm ~= nil then
            expiredate = expiredate .. "/" .. string.sub("00" .. secure.expiry_date_mm, -2)
            if secure.expiry_date_dd ~= nil then
                expiredate = expiredate .. "/" .. string.sub("00" .. secure.expiry_date_dd, -2)
            end
        end
    end

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
    build_secret_menuitem(menu, "Expires", expiredate)
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
    if (metadata == nil) or (next(metadata) == nil) then  -- the "next" trick tests if table is empty.
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

    local menuitem = appendMenuItem(menu, info.name)

    if secret_menuitem_builders[info.type] == nil then
        print("WARNING: don't know how to handle items of type " .. info.type)
        dumptable("secure " .. info.type .. " (" .. info.name .. ")", secure)
        return
    end

    if metadata.faveIndex ~= nil then
        --dumptable("fave metadata " .. info.name, metadata)
        faveitems[metadata.faveIndex] = { info=info, secure=secure }
    end

    local submenu = makeMenu()
    secret_menuitem_builders[info.type](submenu, info, secure)
    setMenuItemSubmenu(menuitem, submenu)
end

local function prepItems()
    items = {}
    local contents = loadContents()
    if contents == nil then
        return false
    end
    for i,v in ipairs(contents) do
        local t = v[2]
        if items[t] == nil then
            items[t] = {}
        end
        local bucket = items[t]
        bucket[#bucket+1] = { uuid=v[1], type=t, name=v[3], url=v[4] }  -- !!! FIXME: there are more fields, don't know what they mean yet.
    end
    return true
end

local passwordUnlockTime = nil

local function lockKeychain()
    -- lose the existing password and key, prompt user again.
    password = argv[2]  -- might be nil, don't reset if on command line.
    keys["SL5"] = nil
    passwordUnlockTime = nil
    setPowermateLED(false)

    -- kill the popup if it exists.
    if (keyhookGuiMenus ~= nil) and (keyhookGuiMenus[1] ~= nil) then
        guiDestroyMenu(keyhookGuiMenus[1])
    end
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

function escapePressed()  -- not local! Called from C!
    if keyhookGuiMenus[1] then
        guiDestroyMenu(keyhookGuiMenus[1])
    end
end


local buildGuiMenuList

local function spawnSubMenu(button, submenu, depth)
    local guimenu = guiCreateSubMenu(button)

    for i = #keyhookGuiMenus, depth, -1 do
        if keyhookGuiMenus[i] then
            --print("Destroying conflicting submenu at depth " .. i)
            guiDestroyMenu(keyhookGuiMenus[i])
            keyhookGuiMenus[i] = nil
        end
    end

    --print("New submenu at depth " .. depth)
    keyhookGuiMenus[depth] = guimenu

    buildGuiMenuList(guimenu, submenu)
    guiShowWindow(guimenu)
end

local function buildGuiMenuItem(guimenu, item)
    local cb = item["callback"]
    if cb == nil then
        local submenu = item["submenu"]
        local depth = #keyhookGuiMenus+1
        cb = function (button)
            return spawnSubMenu(button, submenu, depth)
        end
    end
    guiAddMenuItem(guimenu, item["text"], item["checked"], cb)
end

buildGuiMenuList = function(guimenu, list)
    for i,v in ipairs(list) do
        buildGuiMenuItem(guimenu, v)
    end
end

local function buildSearchResultsMenuCategory(guimenu, menu, str)
    local submenu = menu["submenu"]
    if not submenu then return end

    local name = menu["text"]
    -- !!! FIXME: hacky. We should really list favorites first anyhow.
    if name == "Favorites" then return end

    for i,v in ipairs(submenu) do
        if string.find(string.lower(v["text"]), str, 1, true) ~= nil then
            buildGuiMenuItem(guimenu, v)
        end
    end
end

local function buildSearchResultsMenuList(guimenu, topmenu, str)
    for i,v in ipairs(topmenu) do
        buildSearchResultsMenuCategory(guimenu, v, str)
    end
end

local function searchEntryChanged(guimenu, str, topmenu)
    --print("search changed to '" .. str .. "' ...")
    guiRemoveAllMenuItems(guimenu)
    if str == "" then
        buildGuiMenuList(guimenu, topmenu)
    else
        buildSearchResultsMenuList(guimenu, topmenu, string.lower(str))
    end
    guiShowWindow(guimenu)
end

local function handleMenuDestroyed()
    --print("Destroying main menu...")
    for i,v in ipairs(keyhookGuiMenus) do
        if i > 1 then
            guiDestroyMenu(v)
        end
    end
    keyhookGuiMenus = nil
    keyhookRunning = false

    runGarbageCollector()
end

local function launchGuiMenu(topmenu)
    local guimenu = guiCreateTopLevelMenu("1pass",

        function(guimenu, str) -- search text changed callback
            return searchEntryChanged(guimenu, str, topmenu)
        end,

        function()  -- window destroyed callback
            handleMenuDestroyed()
        end
    )
    keyhookGuiMenus = {}
    keyhookGuiMenus[#keyhookGuiMenus+1] = guimenu
    buildGuiMenuList(guimenu, topmenu)
    guiShowWindow(guimenu)
end

local trustedDisks = {}

local function getTrustedDiskChecksumPath(mntpoint)
    return mntpoint .. "/1pass.dat"
end

local function getTrustedDiskChecksum(mntpoint)
    local f = io.open(getTrustedDiskChecksumPath(mntpoint), "rb")
    if f == nil then
        return nil
    end

    local str = f:read("*a")
    f:close()
    return calcSha256(str)
end

local function choseTrustedDisk(mntpoint)
    if trustedDisks[mntpoint] ~= nil then
        trustedDisks[mntpoint] = nil  -- no longer check existing trusted disk.
    else
        -- !!! FIXME: probably needs a message box if this fails.
        local checksum = getTrustedDiskChecksum(mntpoint)
        -- No checksum file yet? Generate and write out a random string.
        if checksum == nil then
            local f = io.open("/dev/urandom", "rb")
            if f ~= nil then
                local str = f:read(4096)
                f:close()
                if (str ~= nil) and (#str == 4096) then
                    f = io.open(getTrustedDiskChecksumPath(mntpoint), "wb")
                    if f ~= nil then
                        if f:write(str) and f:flush() then
                            checksum = calcSha256(str)
                        end
                        f:close()
                    end
                end
            end
        end
        trustedDisks[mntpoint] = checksum
    end

    -- kill the popup if it exists.
    -- !!! FIXME: put this in its own function, this is a copy/paste from elsewhere.
    if (keyhookGuiMenus ~= nil) and (keyhookGuiMenus[1] ~= nil) then
        guiDestroyMenu(keyhookGuiMenus[1])
    end
end

local function buildTrustedDeviceMenu()
    local menu = makeMenu()
    local disks = getMountedDisks()  -- this is a C function.

    table.sort(disks, function(a, b) return a < b end)
    for i,v in ipairs(disks) do
        local item = appendMenuItem(menu, v, function() choseTrustedDisk(v) end)
        if trustedDisks[v] ~= nil then
            setMenuItemChecked(item, true)
        end
    end

    return menu
end

function keyhookPressed()  -- not local! Called from C!
    --print("keyhookPressed: running==" .. tostring(keyhookRunning))
    if keyhookRunning then
        return
    end

    keyhookRunning = true

    local allowaccess = true;
    for mntpoint,checksum in pairs(trustedDisks) do
        if getTrustedDiskChecksum(mntpoint) ~= checksum then
            allowaccess = false
            break
        end
    end

    if not allowaccess then
        -- !!! FIXME: probably needs a message box if this happens.
        keyhookRunning = false
        return
    end

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

    if not prepItems() then
        keyhookRunning = false
        return
    end

    local topmenu = makeMenu()
    local favesmenu = makeMenu()
    local securitymenu = makeMenu()
    faveitems = {}

    setMenuItemSubmenu(appendMenuItem(topmenu, "Favorites"), favesmenu)
    setMenuItemSubmenu(appendMenuItem(topmenu, "Security"), securitymenu)

    appendMenuItem(securitymenu, "Lock keychain now", function() lockKeychain() end)
    setMenuItemSubmenu(appendMenuItem(securitymenu, "Require trusted device"), buildTrustedDeviceMenu())

    for orderi,type in ipairs(passwordTypeOrdering) do
        local bucket = items[type]
        if bucket ~= nil then
            local realname = passwordTypeNameMap[type]
            if realname == nil then
                realname = type
            end
            local menuitem = appendMenuItem(topmenu, realname)
            local submenu = makeMenu()
            table.sort(bucket, function(a, b) return a.name < b.name end)
            for i,v in pairs(bucket) do
                build_secret_menuitems(v, submenu)
            end
            setMenuItemSubmenu(menuitem, submenu)
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
        local menuitem = appendMenuItem(favesmenu, v.info.name)
        local submenu = makeMenu()
        secret_menuitem_builders[v.info.type](submenu, v.info, v.secure)
        setMenuItemSubmenu(menuitem, submenu)
    end

    favepairs = nil
    faveitems = nil

    launchGuiMenu(topmenu)
end


-- Mainline!

--for i,v in ipairs(argv) do
--    print("argv[" .. i .. "] = " .. v)
--end

-- !!! FIXME: message box, exit if basedir is wack.
local f = io.open(basedir .. "/contents.js", "rb")
if f == nil then
    print("ERROR: Couldn't read your 1Password keychain in '" .. basedir .. "'.")
    print("ERROR: Please make sure it exists and you have permission to access it.")
    print("ERROR: (maybe you need to run 'ln -s ~/Dropbox/1Password' here?")
    print("ERROR: Giving up for now.")
    os.exit(1)
end
f:close()

-- !!! FIXME: this can probably happen in C now (the Lua mainline is basically gone now).
setPowermateLED(false)  -- off by default
print("Now waiting for the magic key combo (probably Alt-Meta-\\) ...")
giveControlToGui()

-- end of 1pass.lua ...

