local nmap      = require "nmap"
local shortport = require "shortport"
local stdnse    = require "stdnse"
local string    = require "string"

-- vim: set filetype=lua :

description = [[
Detects an Ollama LLM runtime accessible without authentication on TCP/11434.

Sends GET /api/tags (model list endpoint) and GET /api/version. A positive
match requires HTTP 200 and a response body containing "models". Any Ollama
instance responding to /api/tags without authentication exposes the full model
inventory and inference API to any reachable client.
]]
---
-- @usage
-- nmap -p 11434 --script ollama-detect <host>
--
-- @output
-- 11434/tcp open  ollama
-- | ollama-detect:
-- |_  Ollama API accessible without authentication — models: llama2, mistral (version: 0.1.33)

author = "spoonmap"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe", "version"}

portrule = shortport.port_or_service(11434, {"http", "unknown"}, "tcp",
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
  -- ── Primary probe: /api/tags ──────────────────────────────────────────────
  local resp = http_get(host, port, "/api/tags")
  if not is_ok(resp) then return nil end
  local body = body_of(resp)
  if not body:find('"models"', 1, true) then return nil end

  -- Extract model names from "name":"<model>" patterns
  local models = {}
  for name in body:gmatch('"name"%s*:%s*"([^"]+)"') do
    table.insert(models, name)
  end

  -- ── Version probe: /api/version ───────────────────────────────────────────
  local version = "unknown"
  local vresp = http_get(host, port, "/api/version")
  if is_ok(vresp) then
    local vbody = body_of(vresp)
    local m = vbody:match('"version"%s*:%s*"([^"]+)"')
    if m then version = m end
  end

  port.version.name    = "ollama"
  port.version.product = "Ollama LLM Runtime"
  nmap.set_port_version(host, port)

  local model_str = #models > 0 and table.concat(models, ", ") or "none"
  return string.format(
    "Ollama API accessible without authentication \xe2\x80\x94 models: %s (version: %s)",
    model_str, version
  )
end
