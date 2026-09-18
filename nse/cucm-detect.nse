local nmap      = require "nmap"
local shortport = require "shortport"
local stdnse    = require "stdnse"
local string    = require "string"

-- vim: set filetype=lua :

description = [[
Detects Cisco Unified Communications Manager (CUCM) TFTP servers on TCP/6970.

CUCM exposes an HTTP interface on port 6970 that mirrors its TFTP root directory.
Two canonical CUCM files are probed to confirm the service:

  /ConfigFileCacheList.txt  — present on all CUCM TFTP servers; lists every phone
                              configuration file available for unauthenticated download.
  /XMLDefault.cnf.xml       — fallback; the default phone provisioning XML.

If either file is accessible the host is a CUCM TFTP server. Phone config files
often contain plaintext SIP/SCCP credentials and directory passwords.

References:
* https://github.com/trustedsec/SeeYouCM-Thief
* https://www.trustedsec.com/blog/seeyoucm-thief-exploiting-common-misconfigurations-in-cisco-phone-systems
]]
---
-- @usage
-- nmap -p 6970 --script cucm-detect <host>
--
-- @output
-- 6970/tcp open  cucm-tftp
-- | cucm-detect:
-- |   Product: Cisco Unified Communications Manager (CUCM) TFTP
-- |   ConfigFileCacheList: Accessible — 842 entries (phone configs exposed)
-- |_  Reference: https://github.com/trustedsec/SeeYouCM-Thief

author = "spoonmap"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe", "version"}

portrule = shortport.port_or_service(6970, {"http", "unknown"}, "tcp",
                                     {"open", "open|filtered"})

-- Default sent when no --script-args http.useragent override is given: a
-- generic browser string, not nmap's own default UA, which is itself a
-- distinctive scanner signature to any WAF or IDS.
local DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"

-- Send a raw HTTP/1.0 GET and return the full response string, or nil on error.
local function http_get(host, port, path)
  local TIMEOUT_MS = 8000
  local socket = nmap.new_socket()
  socket:set_timeout(TIMEOUT_MS)
  local ok, err = socket:connect(host, port, "tcp")
  if not ok then
    stdnse.debug1("Connect failed: %s", err)
    socket:close()
    return nil
  end
  local user_agent = stdnse.get_script_args("http.useragent") or DEFAULT_USER_AGENT
  local req = table.concat({
    "GET " .. path .. " HTTP/1.0\r\n",
    "Host: " .. (host.targetname or host.ip) .. "\r\n",
    "User-Agent: " .. user_agent .. "\r\n",
    "Connection: close\r\n",
    "\r\n",
  })
  ok, err = socket:send(req)
  if not ok then
    stdnse.debug1("Send failed: %s", err)
    socket:close()
    return nil
  end
  local response = ""
  while true do
    local chunk
    ok, chunk = socket:receive()
    if not ok then break end
    response = response .. chunk
  end
  socket:close()
  return response
end

-- Return true if the raw HTTP response has a 2xx status line.
local function is_ok(response)
  return response and response:match("^HTTP/%d+%.%d+ 2%d%d") ~= nil
end

-- Split response into headers + body at the first blank line.
local function body_of(response)
  local _, _, body = response:find("\r\n\r\n(.*)", 1)
  if not body then
    _, _, body = response:find("\n\n(.*)", 1)
  end
  return body or ""
end

action = function(host, port)
  -- ── Primary probe: ConfigFileCacheList.txt ──────────────────────────────
  local resp = http_get(host, port, "/ConfigFileCacheList.txt")
  if is_ok(resp) then
    local body = body_of(resp)
    if #body > 0 then
      -- Count non-empty lines (each is one phone-config filename)
      local count = 0
      for _ in body:gmatch("[^\n]+") do count = count + 1 end

      port.version.name    = "cucm-tftp"
      port.version.product = "Cisco Unified Communications Manager TFTP"
      nmap.set_port_version(host, port)

      local out = stdnse.output_table()
      out["Product"]             = "Cisco Unified Communications Manager (CUCM) TFTP"
      out["ConfigFileCacheList"] = string.format(
        "Accessible \xe2\x80\x94 %d entries (phone configs exposed)", count)
      out["Reference"]           = "https://github.com/trustedsec/SeeYouCM-Thief"
      return out
    end
  end

  -- ── Fallback probe: XMLDefault.cnf.xml ─────────────────────────────────
  resp = http_get(host, port, "/XMLDefault.cnf.xml")
  if is_ok(resp) then
    local body = body_of(resp)
    -- <device> is a required root element in every CUCM default config XML
    if body:find("<device>", 1, true) or body:find("<device ", 1, true) then
      port.version.name    = "cucm-tftp"
      port.version.product = "Cisco Unified Communications Manager TFTP"
      nmap.set_port_version(host, port)

      local out = stdnse.output_table()
      out["Product"]            = "Cisco Unified Communications Manager (CUCM) TFTP"
      out["XMLDefault.cnf.xml"] = "Accessible"
      out["Reference"]          = "https://github.com/trustedsec/SeeYouCM-Thief"
      return out
    end
  end

  return nil
end
