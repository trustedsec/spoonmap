local nmap      = require "nmap"
local shortport = require "shortport"
local stdnse    = require "stdnse"
local string    = require "string"

-- vim: set filetype=lua :

description = [[
Detects OpenAI-compatible LLM APIs (LM Studio, llama.cpp server, Jan, etc.)
accessible without authentication on TCP 1234, 1337, 3000, or 8000.

Sends GET /v1/models. A positive match requires HTTP 200 AND the response body
to contain all three strings: "object", "data", and "model". The three-string
fingerprint avoids false positives on generic web apps that often listen on
ports 3000 and 8000.

Product identification: if model IDs contain "lmstudio" the product is
reported as "LM Studio"; otherwise "OpenAI-compatible LLM API".
]]
---
-- @usage
-- nmap -p 1234 --script openai-api-detect <host>
--
-- @output
-- 1234/tcp open  openai-api
-- | openai-api-detect:
-- |_  OpenAI-compatible LLM API accessible without authentication — product: LM Studio, models: TheBloke/Mistral-7B

author = "spoonmap"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe", "version"}

portrule = shortport.port_or_service({1234, 1337, 3000, 8000},
                                     {"http", "unknown"}, "tcp",
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
  local resp = http_get(host, port, "/v1/models")
  if not is_ok(resp) then return nil end
  local body = body_of(resp)

  -- Three-string fingerprint: must contain "object", "data", and "model"
  local lower = body:lower()
  if not (lower:find('"object"', 1, true) and
          lower:find('"data"',   1, true) and
          lower:find('"model"',  1, true)) then
    return nil
  end

  -- Extract model IDs from "id":"<model>" patterns
  local models = {}
  for id in body:gmatch('"id"%s*:%s*"([^"]+)"') do
    table.insert(models, id)
  end

  -- Identify product from model IDs
  local product = "OpenAI-compatible LLM API"
  if lower:find("lmstudio", 1, true) or lower:find("lm studio", 1, true) then
    product = "LM Studio"
  end

  port.version.name    = "openai-api"
  port.version.product = product
  nmap.set_port_version(host, port)

  local model_str = #models > 0 and table.concat(models, ", ") or "none"
  return string.format(
    "OpenAI-compatible LLM API accessible without authentication \xe2\x80\x94 product: %s, models: %s",
    product, model_str
  )
end
