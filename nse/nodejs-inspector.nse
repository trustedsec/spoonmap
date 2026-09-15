local nmap      = require "nmap"
local shortport = require "shortport"
local stdnse    = require "stdnse"
local string    = require "string"

-- vim: set filetype=lua :

description = [[
Detects an exposed Node.js Inspector (Chrome DevTools Protocol) on TCP port 9229.

Connects to the port and sends an HTTP GET /json/version request.  If the
response body contains both "Browser" and "node" the service is confirmed as a
live Node.js Inspector endpoint.  Any host that can reach this port can execute
arbitrary JavaScript inside the Node.js process — no authentication is required.
]]
---
-- @usage
-- nmap -p 9229 --script nodejs-inspector <host>
--
-- @output
-- 9229/tcp open  cdp
-- | nodejs-inspector:
-- |_  Node.js Inspector accessible — version: node.js/v18.17.0

author = "spoonmap"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe", "version"}

portrule = shortport.port_or_service(9229, {"cdp", "unknown"}, "tcp",
                                     {"open", "open|filtered"})

-- Default sent when no --script-args http.useragent override is given: a
-- generic browser string, not nmap's own default UA, which is itself a
-- distinctive scanner signature to any WAF or IDS.
local DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"

action = function(host, port)
  local TIMEOUT_MS = 5000

  local socket = nmap.new_socket()
  socket:set_timeout(TIMEOUT_MS)

  local status, err = socket:connect(host, port, "tcp")
  if not status then
    stdnse.debug1("Connect failed: %s", err)
    socket:close()
    return nil
  end

  local user_agent = stdnse.get_script_args("http.useragent") or DEFAULT_USER_AGENT
  local probe = table.concat({
    "GET /json/version HTTP/1.0\r\n",
    "Host: " .. (host.targetname or host.ip) .. "\r\n",
    "User-Agent: " .. user_agent .. "\r\n",
    "Connection: close\r\n",
    "\r\n",
  })

  status, err = socket:send(probe)
  if not status then
    stdnse.debug1("Send failed: %s", err)
    socket:close()
    return nil
  end

  local response
  status, response = socket:receive_bytes(4096)
  socket:close()

  if not status or not response then
    stdnse.debug1("No response received")
    return nil
  end

  -- Must contain both "Browser" and "node" (case-insensitive) to confirm service
  local lower = response:lower()
  if not (lower:find("browser") and lower:find("node")) then
    stdnse.debug1("Response does not match Node.js Inspector fingerprint")
    return nil
  end

  -- Extract version from "Browser": "node.js/vX.Y.Z"
  local version = "unknown"
  local m = response:match('"Browser"%s*:%s*"([^"]+)"')
  if m then
    version = m
  end

  port.version.name    = "cdp"
  port.version.product = "Node.js Inspector"
  nmap.set_port_version(host, port)

  return "Node.js Inspector accessible — version: " .. version
end
