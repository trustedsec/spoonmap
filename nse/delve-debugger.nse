local nmap      = require "nmap"
local shortport = require "shortport"
local stdnse    = require "stdnse"
local string    = require "string"

-- vim: set filetype=lua :

description = [[
Detects an exposed Delve Go debugger using the Debug Adapter Protocol (DAP)
on TCP port 2345.

Sends a minimal DAP initialize request and checks whether the response contains
JSON fields indicating an active DAP server.  Any host that can reach this port
can execute arbitrary code in the target Go process — no authentication is required.
]]
---
-- @usage
-- nmap -p 2345 --script delve-debugger <host>
--
-- @output
-- 2345/tcp open  unknown
-- | delve-debugger:
-- |_  Delve debugger responding to DAP requests

author = "spoonmap"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe", "version"}

portrule = shortport.port_or_service(2345, {"unknown"}, "tcp",
                                     {"open", "open|filtered"})

action = function(host, port)
  local TIMEOUT_MS = 5000

  local socket = nmap.new_socket()
  socket:set_timeout(TIMEOUT_MS)

  local status, err = socket:connect(host, port, "tcp")
  if not status then
    stdnse.debug1("Connect failed: %s", err)
    return nil
  end

  -- Minimal DAP initialize request. clientID is a real VS Code client id
  -- rather than this tool's name: it is echoed back into the target's own
  -- Delve session log verbatim, and naming the scanner there buys nothing.
  local probe = '{"seq":1,"type":"request","command":"initialize","arguments":{"clientID":"vscode"}}\n'

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

  -- Confirm DAP: response must contain "type" and either "response" or "event"
  if not response:find('"type"') then
    stdnse.debug1("Response missing 'type' field — not a DAP server")
    return nil
  end
  if not (response:find('"response"') or response:find('"event"')) then
    stdnse.debug1("Response missing 'response'/'event' — not a DAP server")
    return nil
  end

  port.version.name    = "delve-dap"
  port.version.product = "Delve Go Debugger"
  nmap.set_port_version(host, port)

  return "Delve debugger responding to DAP requests"
end
