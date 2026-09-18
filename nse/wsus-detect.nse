local nmap   = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table  = require "table"

-- vim: set filetype=lua :

description = [[
Identifies Microsoft Windows Server Update Services (WSUS) on its default ports
(8530/HTTP, 8531/HTTPS) by probing the well-known WSUS web-service endpoints.

Detection only: the script issues plain HTTP GET requests to the WSUS ASMX
endpoints and confirms WSUS from WSUS-specific markers in the response. It does
NOT send the CVE-2025-59287 deserialization payload and does NOT attempt
exploitation or any build/patch-level check.

WSUS is a management/update plane and should not be exposed to untrusted networks.
If WSUS is found, verify the October 2025 out-of-band patch for CVE-2025-59287
(unauthenticated RCE, CVSS 9.8, CISA KEV) has been applied.

References:
* https://nvd.nist.gov/vuln/detail/CVE-2025-59287
]]
---
-- @usage
-- nmap -p 8530,8531 --script wsus-detect <host>
--
-- @output
-- 8530/tcp open  wsus
-- | wsus-detect:
-- |_  Microsoft WSUS detected (/ClientWebService/client.asmx)

author = "spoonmap"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe", "version"}

-- Match only the WSUS default ports (8530 HTTP, 8531 HTTPS).
portrule = function(host, port)
  return (port.number == 8530 or port.number == 8531)
     and port.protocol == "tcp"
     and (port.state == "open" or port.state == "open|filtered")
end

local TIMEOUT_MS = 5000

-- WSUS web-service endpoints to probe (first WSUS hit wins).
local WSUS_ENDPOINTS = {
  "/ClientWebService/client.asmx",
  "/ApiRemoting30/WebService.asmx",
  "/ServerSyncWebService/ServerSyncWebService.asmx",
  "/SimpleAuthWebService/SimpleAuth.asmx",
}

-- Distinctive WSUS SOAP method / product markers (case-insensitive). These are
-- not part of the requested URL, so a 404 that echoes the path won't match.
local WSUS_MARKERS = {
  "windows server update services",
  "getauthorizationcookie",
  "reporteventbatch",
  "syncupdates",
  "getextendedupdateinfo",
}

-- Fetch an endpoint over the given transport ("ssl" or "tcp"); return the raw
-- HTTP response string, or nil on any failure (socket always closed).
local function http_get(host, port, proto, path)
  local socket = nmap.new_socket()
  socket:set_timeout(TIMEOUT_MS)
  local ok, err = socket:connect(host, port, proto)
  if not ok then
    stdnse.debug1("connect (%s) failed: %s", proto, err)
    socket:close()
    return nil
  end
  local user_agent = stdnse.get_script_args("http.useragent") or "Windows-Update-Agent"
  local req = table.concat({
    "GET " .. path .. " HTTP/1.0\r\n",
    "Host: " .. (host.targetname or host.ip) .. "\r\n",
    "User-Agent: " .. user_agent .. "\r\n",
    "Connection: close\r\n",
    "\r\n",
  })
  ok, err = socket:send(req)
  if not ok then
    stdnse.debug1("send failed: %s", err)
    socket:close()
    return nil
  end
  local resp = {}
  local total = 0
  while true do
    local status, chunk = socket:receive()
    if not status then break end
    resp[#resp + 1] = chunk
    total = total + #chunk
    if total > 65536 then break end   -- bound response size
  end
  socket:close()
  if #resp == 0 then return nil end
  return table.concat(resp)
end

local function looks_like_wsus(resp)
  if not resp then return false end
  local hay = resp:lower()
  for _, marker in ipairs(WSUS_MARKERS) do
    if hay:find(marker, 1, true) then return true end
  end
  return false
end

action = function(host, port)
  -- 8531 is HTTPS by convention, 8530 is HTTP; try the likely transport first
  -- and fall back to the other only if the first yields no response at all.
  local protos = (port.number == 8531) and {"ssl", "tcp"} or {"tcp", "ssl"}
  for _, proto in ipairs(protos) do
    local any_response = false
    for _, path in ipairs(WSUS_ENDPOINTS) do
      local resp = http_get(host, port, proto, path)
      if resp then
        any_response = true
        if looks_like_wsus(resp) then
          port.version.name    = "wsus"
          port.version.product = "Microsoft WSUS"
          nmap.set_port_version(host, port)
          return "Microsoft WSUS detected (" .. path .. ")"
        end
      end
    end
    if any_response then break end   -- transport works; other endpoints/proto pointless
  end
  return nil
end
