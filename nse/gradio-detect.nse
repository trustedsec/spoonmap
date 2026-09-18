local nmap      = require "nmap"
local shortport = require "shortport"
local stdnse    = require "stdnse"
local string    = require "string"

-- vim: set filetype=lua :

description = [[
Detects a Gradio web UI (text-generation-webui and similar) accessible without
authentication on TCP/7860.

Primary probe: GET /info. A positive match requires HTTP 200 AND the response
body to contain both "version" and "gradio" (case-insensitive).

Fallback probe: GET /. If /info returns non-200 or fails the fingerprint, a
second request checks whether "gradio" appears anywhere in the HTML response.
This covers older Gradio versions that do not expose /info.
]]
---
-- @usage
-- nmap -p 7860 --script gradio-detect <host>
--
-- @output
-- 7860/tcp open  gradio
-- | gradio-detect:
-- |_  Gradio web UI accessible — version: 3.50.2

author = "spoonmap"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe", "version"}

portrule = shortport.port_or_service(7860, {"http", "unknown"}, "tcp",
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
  local version = "unknown"
  local matched = false

  -- ── Primary probe: /info ──────────────────────────────────────────────────
  local resp = http_get(host, port, "/info")
  if is_ok(resp) then
    local body  = body_of(resp)
    local lower = body:lower()
    if lower:find('"version"', 1, true) and lower:find("gradio", 1, true) then
      matched = true
      local m = body:match('"version"%s*:%s*"([^"]+)"')
      if m then version = m end
    end
  end

  -- ── Fallback probe: / (HTML check) ───────────────────────────────────────
  if not matched then
    local fresp = http_get(host, port, "/")
    if is_ok(fresp) then
      local fbody = body_of(fresp)
      if fbody:lower():find("gradio", 1, true) then
        matched = true
        -- version stays "unknown" — HTML probe cannot reliably extract it
      end
    end
  end

  if not matched then return nil end

  port.version.name    = "gradio"
  port.version.product = "Gradio (text-generation-webui)"
  nmap.set_port_version(host, port)

  return string.format(
    "Gradio web UI accessible \xe2\x80\x94 version: %s",
    version
  )
end
