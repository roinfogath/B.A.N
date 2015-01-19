local bin = require "bin"
local http = require "http"
local table = require "table"
local url = require "url"

---
-- http-default-accounts-fingerprints.lua
-- This file contains fingerprint data for http-default-accounts.nse
--
-- STRUCTURE:
-- * <code>name</code> - Descriptive name
-- * <code>category</code> - Category
-- * <code>login_combos</code>
---- * <code>username</code> - Default username
---- * <code>password</code> - Default password
-- * <code>paths</code> - Paths table containing the possible location of the target
-- * <code>target_check</code> - Validation function of the target (optional)
-- * <code>login_check</code> - Login function of the target
--
-- TODO: Update the functionality of <code>target_check</code> to differentiate
--       between valid HTTP/200 and a custom error page.
---

---
-- Requests given path using basic authentication.
-- @param host Host table
-- @param port Port table
-- @param path Path to request
-- @param user Username for Basic Auth
-- @param pass Password for Basic Auth
-- @param digest_auth Digest Authentication
-- @return True if login in was successful
---
local function try_http_basic_login(host, port, path, user, pass, digest_auth)
  local credentials = {username = user, password = pass, digest = digest_auth}
  local req = http.get(host, port, path, {no_cache=true, auth=credentials, redirect_ok = false})
  if req.status and req.status ~= 401 and req.status ~= 403 then
    return true
  end
  return false
end

---
-- Tries to login with a http post, if the FAIL string is not found
-- we assume login in was successful
-- @param host Host table
-- @param port Port table
-- @param target Target file
-- @param failstr String shown when login in fails
-- @param params Post parameters
-- @param follow_redirects True if you want redirects to be followed
-- @return True if login in was successful
---
local function try_http_post_login(host, port, path, target, failstr, params, follow_redirects)
  local req = http.post(host, port, url.absolute(path, target), {no_cache=true}, nil, params)

  if not req.status then return false end
  local status = tonumber(req.status) or 0
  if follow_redirects and ( status > 300 and status < 400 ) then
    req = http.get(host, port, url.absolute(path, req.header.location), { no_cache = true, redirect_ok = false })
  end
  if req.status and req.status ~= 404 and not(http.response_contains(req, failstr)) then
    return true
  end
  return false
end

---
-- Returns authentication realm advertised in an HTTP response
-- @param response HTTP response object, such as a result from http.get()
-- @return realm found in response header WWW-Authenticate
--               (or nil if not present)
---
local function http_auth_realm(response)
  local auth = response.header["www-authenticate"] or ""
  return auth:match('%srealm="([^"]*)')
end

fingerprints = {}

---
--WEB
---
table.insert(fingerprints, {
  name = "Cacti",
  category = "web",
  paths = {
    {path = "/cacti/"}
  },
  target_check = function (host, port, path, response)
    -- true if the response is HTTP/200 and sets cookie "Cacti"
    if response.status == 200 then
      for _, ck in ipairs(response.cookies or {}) do
        if ck.name:lower() == "cacti" then return true end
      end
    end
    return false
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_post_login(host, port, path, "index.php", "Invalid User Name/Password", {action="login", login_username=user, login_password=pass}, false)
  end
})

table.insert(fingerprints, {
  name = "Xplico",
  category = "web",
  paths = {
    {path = "/users/login"}
  },
  target_check = function (host, port, path, response)
    -- true if the response is HTTP/200 and sets cookie "Xplico"
    if response.status == 200 then
      for _, ck in ipairs(response.cookies or {}) do
        if ck.name:lower() == "xplico" then return true end
      end
    end
    return false
  end,
  login_combos = {
    {username = "admin", password = "xplico"},
    {username = "xplico", password = "xplico"}
  },
  login_check = function (host, port, path, user, pass)
    -- harvest all hidden fields from the login form
    local req1 = http.get(host, port, path, {no_cache=true, redirect_ok = false})
    if req1.status ~= 200 then return false end
    local html = req1.body and req1.body:match('<form%s+action%s*=%s*"/users/login".->(.-)</form>')
    if not html then return false end
    local form = {}
    for n, v in html:gmatch('<input%s+type%s*=%s*"hidden"%s+name%s*=%s*"(.-)"%s+value%s*=%s*"(.-)"') do
      form[n] = v
    end
    -- add username and password to the form and submit it
    form["data[User][username]"] = user
    form["data[User][password]"] = pass
    local req2 = http.post(host, port, path, {no_cache=true, cookies=req1.cookies}, nil, form)
    if req2.status ~= 302 then return false end
    local loc = req2.header["location"]
    return loc and (loc:match("/admins$") or loc:match("/pols/index$"))
  end
})

table.insert(fingerprints, {
  name = "Apache Tomcat",
  category = "web",
  paths = {
    {path = "/manager/html/"},
    {path = "/tomcat/manager/html/"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "Tomcat Manager Application"
  end,
  login_combos = {
    {username = "tomcat", password = "tomcat"},
    {username = "admin", password = "admin"},
    -- http://cve.mitre.org/cgi-bin/cvename.cgi?name=2009-4189
    {username = "ovwebusr", password = "OvW*busr1"},
    -- http://cve.mitre.org/cgi-bin/cvename.cgi?name=2009-4188
    {username = "j2deployer", password = "j2deployer"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_basic_login(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "Apache Axis2",
  category = "web",
  paths = {
    {path = "/axis2/axis2-admin/"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
  end,
  login_combos = {
    {username = "admin", password = "axis2"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_post_login(host, port, path, "login", "Invalid auth credentials!", {submit="+Login+", userName=user, password=pass})
  end
})
---
--ROUTERS
---
table.insert(fingerprints, {
  name = "Arris 2307",
  category = "routers",
  paths = {
    {path = "/logo_t.gif"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
  end,
  login_combos = {
    {username = "", password = ""}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_post_login(host, port, path, "login.cgi", "Login Error !!", {action="submit", page="", logout="", pws=pass})
  end
})

table.insert(fingerprints, {
  name = "Cisco IOS",
  category = "routers",
  paths = {
    {path = "/exec/show/log/CR"},
    {path = "/level/15/exec/-/configure/http"},
    {path = "/level/15/exec/-"},
    {path = "/level/15/"}
  },
  target_check = function (host, port, path, response)
    local realm = http_auth_realm(response) or ""
    -- Exact PCRE: "^level 15?( or view)? access$"
    return realm:gsub("_"," "):find("^level 15? .*access$")
  end,
  login_combos = {
    {username = "", password = ""},
    {username = "cisco", password = "cisco"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_basic_login(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "Cisco WAP200",
  category = "routers",
  paths = {
    {path = "/StatusLan.htm"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "Linksys WAP200"
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_basic_login(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "Cisco WAP55AG",
  category = "routers",
  paths = {
    {path = "/WPA_Preshared.asp"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "Linksys WAP55AG"
  end,
  login_combos = {
    {username = "", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_basic_login(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "Cisco Lynksys WRT54GCv3",
  category = "routers",
  paths = {
    {path = "/WSecurity.htm"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "WRT54GCv3"
  end,
  login_combos = {
    {username = "admin", password = "admin"},
    {username = "admin", password = "123456"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_basic_login(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "Cisco Lynksys E900",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "E900"
  end,
  login_combos = {
    {username = "admin", password = "admin"},
    {username = "admin", password = "1234"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_basic_login(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "ASUS RT-N10U",
  category = "routers",
  paths = {
    {path = "/as.asp"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "RT-N10U"
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_basic_login(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "Motorola RF Switch",
  category = "routers",
  paths = {
    {path = "/getfwversion.cgi"}
  },
  target_check = function (host, port, path, response)
    -- true if the response is HTTP/200 and returns a firmware version
    return response.status == 200
           and not response.header["server"]
           and response.header["content-type"] == "text/plain"
           and response.body
           and response.body:find("\n%d+%.%d+%.%d+%.%d+%-%w+\n")
  end,
  login_combos = {
    {username = "admin", password = "superuser"}
  },
  login_check = function (host, port, path, user, pass)
    local tohex = function (str)
                    local _, hex = bin.unpack("H" .. str:len(), str)
                    return hex:lower()
                  end
    local login = string.format("J20K34NMMT89XPIJ34S login %s %s", tohex(user), tohex(pass))
    local lpath = url.absolute(path, "usmCgi.cgi/?" .. url.escape(login))
    local req = http.get(host, port, lpath, {no_cache=true, redirect_ok = false})
    return req
           and req.status == 200
           and req.body
           and req.body:match("^login 0 ")
  end
})

table.insert(fingerprints, {
  name = "Nortel VPN Router",
  category = "routers",
  paths = {
    {path = "/manage/bdy_sys.htm"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "Management(1)"
  end,
  login_combos = {
    {username = "admin", password = "setup"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_basic_login(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "Netgear CG3300CMR  CEIFS",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "CG3300CMR-1CEIFS"
  end,
  login_combos = {
    {username = "MSO", password = "0n0Adm1Ni$tRaT0r"},
    {username = "admin", password = "password"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_basic_login(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "ip camera-DVR WEB unknown vendor",
  category = "ip camera",
  paths = {
    {path = "/m.html"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "."
  end,
  login_combos = {
    {username = "admin", password = "123456"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_basic_login(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "ip camera-DVR WEB unknown vendor",
  category = "ip camera",
  paths = {
    {path = "/m.html"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "DVR"
  end,
  login_combos = {
    {username = "admin", password = "123456"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_basic_login(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "ip camera-DVR WEB unknown vendor",
  category = "ip camera",
  paths = {
    {path = "/m.html"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "DVR manager"
  end,
  login_combos = {
    {username = "admin", password = "123456"},
    {username = "admin", password = "admin"},
    {username = "", password = ""}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_basic_login(host, port, path, user, pass, true)
  end
})

table.insert(fingerprints, {
  name = "ZyXel router P-870HW",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "DSL Router"
  end,
  login_combos = {
    {username = "1234", password = "1234"},
    {username = "user", password = "user"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_basic_login(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "ZyXel router P-660HW-D1",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "P-660HW-D1"
  end,
  login_combos = {
    {username = "1234", password = "1234"},
    {username = "user", password = "user"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_basic_login(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "Net-Lynx adsl router",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "ADSL Modem"
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_basic_login(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "HUAWEI  SmartAX MT882",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "SmartAX"
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_basic_login(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "ASUS RT-G32",
  category = "routers",
  paths = {
    {path = "/auto_detect_lang.asp"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "RT-G32"
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_basic_login(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "ASUS RT-N10",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "RT-N10"
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_basic_login(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "ASUS RT-N56U",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "RT-N56U"
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_basic_login(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "ASUS RT-N10.B1",
  category = "routers",
  paths = {
    {path = "/device-map/clients.asp"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "RT-N10.B1"
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_basic_login(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "ASUS RT-N12E",
  category = "routers",
  paths = {
    {path = "/device-map/clients.asp"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "RT-N12E"
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_basic_login(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "ASUS RT-N10E",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "RT-N10E"
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_basic_login(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "ASUS RT-N12C1",
  category = "routers",
  paths = {
    {path = "/as.asp"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "RT-N12C1"
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_basic_login(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "ASUS Wireless Router WL530g-V2 ",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "WL530g-V2 "
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_basic_login(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "ASUS Wireless Router WL500gP ",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "WL500g.Premium"
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_basic_login(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "ASUS Wireless Router RT-N10",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "RT-N10"
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_basic_login(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "ASUS Wireless RT-AC68U",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "RT-AC68U"
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_basic_login(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "ASUS Wireless Router WL520gc",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "WL520gc"
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_basic_login(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "ASUS Wireless Router WL520g",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "WL520g"
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_basic_login(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "ASUS Wireless Router WL500gpv2",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "WL500gpv2"
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_basic_login(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "ASUS Wireless Router RT-N11",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "RT-N11"
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_basic_login(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "ASUS Wireless Router RT-N10LX",
  category = "routers",
  paths = {
    {path = "/wlbasic.asp"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "RT-N10LX"
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_basic_login(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "ASUS Wireless Router WL-500gP V2",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "WL-500gP V2"
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_basic_login(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "ASUS Wireless Router RT-N66U",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "RT-N66U"
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_basic_login(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "ASUS Wireless Router RT-N12+",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "RT-N12+"
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_basic_login(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "ASUS Wireless Router RT-AC56U",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "RT-AC56U"
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_basic_login(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "ASUS Wireless Router RT-N12D1",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "RT-N12D1"
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_basic_login(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "ASUS Wireless Router RT-N12LX",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "RT-N12LX"
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_basic_login(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "ASUS Wireless Router RT-AC66U",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "RT-AC66U"
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_basic_login(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "D-Link Router DI-524",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "DI-524"
  end,
  login_combos = {
    {username = "user", password = ""}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_basic_login(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "D-Link Router DI-524UP",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "DI-524UP"
  end,
  login_combos = {
    {username = "user", password = ""}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_basic_login(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "D-Link Broadband VPN  DI-804HV",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "DI-804HV"
  end,
  login_combos = {
    {username = "user", password = ""}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_basic_login(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "Netgear Router WGR614",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "WGR614v7"
  end,
  login_combos = {
    {username = "admin", password = "password"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_basic_login(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "TP-LINK Wireless Lite N Router WR740N",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "TP-LINK Wireless Lite N Router WR740N"
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_basic_login(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "TP-LINK Wireless N Gigabit Router WR1043ND",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "TP-LINK Wireless N Gigabit Router WR1043ND"
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_basic_login(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "TP-LINK Wireless N Router WR841N",
  category = "routers",
  paths = {
    {path = "/images/blue.jpg"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "TP-LINK Wireless N Router WR841N"
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_basic_login(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "TP-LINK Wireless Router  WA5210G",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "TP-LINK Wireless AP WA5210G"
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_basic_login(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "TP-LINK Wireless Router  WDR3600",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "TP-LINK Wireless Dual Band Gigabit Router WDR3600"
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_basic_login(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "TP-LINK Wireless Router  TL-WR720N",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "150Mbps Wireless N Router TL-WR720N"
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_basic_login(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "TP-LINK Wireless Router  TD-W8951ND",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "TD-W8951ND"
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_basic_login(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "TP-LINK Wireless Router TL-WR841HP ",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "TP-LINK 300Mbps High Power Wireless N Router TL-WR841HP"
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_basic_login(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "TP-LINK IP camera TL-SC3171G",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "Wireless Day/Night IP Camera"
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_basic_login(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "TRENDNET TEW-432BRP",
  category = "routers",
  paths = {
    {path = "/lan.asp"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "TRENDnet"
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_basic_login(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "HUAWEI SmartAX MT882",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "SmartAX"
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_basic_login(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "HUAWEI EchoLife HG520b",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "EchoLife Home Gateway"
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_basic_login(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "SERIOUX SRX-WR150WH",
  category = "routers",
  paths = {
    {path = "/wireless_basic.htm"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "SRX"
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_basic_login(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "LevelOne WBR-6003",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "WBR-6005"
  end,
  login_combos = {
    {username = "admin", password = "password"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_basic_login(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "UMTS router UR5i",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "Router"
  end,
  login_combos = {
    {username = "root", password = "1234"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_basic_login(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "Broadband Router ",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "Broadband Router"
  end,
  login_combos = {
    {username = "1234", password = "1234"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_basic_login(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "U.S. Robotics Wireless",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "U.S. Robotics Wireless MAXg Router"
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_basic_login(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "EVOLVE Router Wireless",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "."
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_basic_login(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "TRENDnet IP Camera TV-IP551WI",
  category = "routers",
  paths = {
    {path = "/"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "TV-IP551WI"
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_basic_login(host, port, path, user, pass, false)
  end
})

table.insert(fingerprints, {
  name = "F5 BIG-IP",
  category = "routers",
  paths = {
    {path = "/tmui/login.jsp"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.header["f5-login-page"] == "true"
           and response.body
           and response.body:find("logmein.html",1,true)
  end,
  login_combos = {
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_post_login(host, port, path, "logmein.html", "login%.jsp%?msgcode=1", {username=user, passwd=pass})
  end
})

---
--Digital recorders
---
table.insert(fingerprints, {
  name = "Digital Sprite 2",
  category = "security",
  paths = {
    {path = "/frmpages/index.html"}
  },
  target_check = function (host, port, path, response)
    return http_auth_realm(response) == "WebPage Configuration"
  end,
  login_combos = {
    {username = "dm", password = "web"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_basic_login(host, port, path, user, pass, true)
  end
})

---
--Remote consoles
---
table.insert(fingerprints, {
  name = "Lantronix SLC",
  category = "console",
  paths = {
    {path = "/scsnetwork.htm"}
  },
  target_check = function (host, port, path, response)
    return response.status == 200
           and response.header["server"]
           and response.header["server"]:find("^mini_httpd")
           and response.body
           and response.body:find("<title>Lantronix SLC",1,true)
  end,
  login_combos = {
    {username = "sysadmin", password = "PASS"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_post_login(host, port, path, "./", "%sname%s*=%s*(['\"]?)slcpassword%1[%s>]", {slclogin=user, slcpassword=pass})
  end
})
