local nmap      = require "nmap"
local shortport = require "shortport"
local stdnse    = require "stdnse"
local string    = require "string"

-- vim: set filetype=lua :

description = [[
Detects a Kibana (or OpenSearch Dashboards) instance accessible without
authentication on TCP/5601.

Sends GET /api/status. A positive match requires HTTP 200 and a JSON body
carrying Kibana's status shape: a "version" object with a "number" field and
a "status" object. An instance with security enabled answers 401 and is not
reported, so output means the UI and its API are reachable by any client.
]]
---
-- @usage
-- nmap -p 5601 --script kibana-detect <host>
--
-- @output
-- 5601/tcp open  kibana
-- | kibana-detect:
-- |_  Kibana accessible without authentication — version: 8.11.0

author = "spoonmap"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe", "version"}

portrule = shortport.port_or_service(5601, {"http", "unknown"}, "tcp",
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
  local resp = http_get(host, port, "/api/status")
  if not is_ok(resp) then return nil end
  local body = body_of(resp)

  -- Kibana's shape: "version" is an object holding "number", alongside a
  -- "status" object. A bare "version":"1.0" string (generic health endpoint)
  -- must not match.
  local version = body:match('"version"%s*:%s*{[^}]-"number"%s*:%s*"([^"]+)"')
  if not version or not body:find('"status"%s*:%s*{') then return nil end

  port.version.name    = "kibana"
  port.version.product = "Kibana"
  port.version.version = version
  nmap.set_port_version(host, port)

  return string.format(
    "Kibana accessible without authentication \xe2\x80\x94 version: %s", version)
end
