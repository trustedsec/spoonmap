local nmap      = require "nmap"
local rand      = require "rand"
local stdnse    = require "stdnse"
local string    = require "string"
local table     = require "table"

-- vim: set filetype=lua :

description = [[
Confirms an OpenVPN server on UDP or TCP port 1194 by completing the first
step of the control-channel handshake.

Sends a P_CONTROL_HARD_RESET_CLIENT_V2 packet — the same first packet a real
OpenVPN client sends — and checks whether the reply is a matching
P_CONTROL_HARD_RESET_SERVER_V2 (or the older _V1) opcode. This confirms the
OpenVPN protocol without any credentials.

This pre-TLS handshake carries no version string — OpenVPN only exchanges
IV_VER/IV_PLAT peer-info after the TLS control channel is established, which
requires valid --tls-auth/--tls-crypt keys. Servers hardened with tls-auth or
tls-crypt silently drop this unauthenticated probe and will not respond
(reads as no match, not a false negative).
]]
---
-- @usage nmap -sU -p 1194 --script openvpn-detect.nse <host>
-- @usage nmap -p 1194 --script openvpn-detect.nse <host>
-- @output
-- 1194/udp open  openvpn
-- | openvpn-detect:
-- |   OpenVPN server confirmed via control-channel handshake
-- |   Handshake: P_CONTROL_HARD_RESET_SERVER_V2
-- |   Transport: udp
-- |_  Version  : not disclosed pre-authentication (requires the TLS control channel)

author = "spoonmap"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe", "version"}

portrule = function(host, port)
  return port.number == 1194
     and (port.protocol == "tcp" or port.protocol == "udp")
     and (port.state == "open" or port.state == "open|filtered")
end

-- Builds a P_CONTROL_HARD_RESET_CLIENT_V2 packet: opcode 7 (key_id 0), an
-- 8-byte random session id, a zero-length ack array, and a zero packet id.
-- No payload — it only initiates the handshake.
local function build_probe()
  local session_id = rand.random_string(8)
  return "\x38" .. session_id .. "\x00" .. "\x00\x00\x00\x00"
end

-- Returns the opcode (top 5 bits of the first byte) of an OpenVPN packet.
local function opcode_of(reply)
  return math.floor(string.byte(reply, 1) / 8)
end

local function probe_udp(host, port)
  local socket = nmap.new_socket()
  socket:set_timeout(3000)
  local ok, err = socket:connect(host, port, "udp")
  if not ok then
    stdnse.debug1("udp connect failed: %s", err)
    return nil
  end

  ok, err = socket:send(build_probe())
  if not ok then
    stdnse.debug1("udp send failed: %s", err)
    socket:close()
    return nil
  end

  local status, reply = socket:receive()
  socket:close()
  if not status then
    return nil
  end
  return reply
end

local function probe_tcp(host, port)
  local socket = nmap.new_socket()
  socket:set_timeout(5000)
  local ok, err = socket:connect(host, port, "tcp")
  if not ok then
    stdnse.debug1("tcp connect failed: %s", err)
    return nil
  end

  local payload = build_probe()
  -- OpenVPN-over-TCP frames every packet with a 2-byte big-endian length
  -- prefix that does not include itself.
  local framed = string.char(0, #payload) .. payload
  ok, err = socket:send(framed)
  if not ok then
    stdnse.debug1("tcp send failed: %s", err)
    socket:close()
    return nil
  end

  -- Reply is a short control packet behind its own 2-byte length prefix;
  -- receive_bytes blocks until at least this many bytes have arrived.
  local status, buf = socket:receive_bytes(3)
  socket:close()
  if not status or not buf or #buf < 3 then
    return nil
  end
  return buf:sub(3)
end

action = function(host, port)
  local reply
  if port.protocol == "udp" then
    reply = probe_udp(host, port)
  else
    reply = probe_tcp(host, port)
  end

  if not reply or #reply < 1 then
    return nil
  end

  local opcode = opcode_of(reply)
  -- 8 = P_CONTROL_HARD_RESET_SERVER_V2, 2 = the older _V1 variant
  if opcode ~= 8 and opcode ~= 2 then
    stdnse.debug1("unexpected opcode %d in reply", opcode)
    return nil
  end

  port.version.name    = "openvpn"
  port.version.product = "OpenVPN"
  nmap.set_port_version(host, port)

  local variant = (opcode == 8) and "P_CONTROL_HARD_RESET_SERVER_V2"
                                  or "P_CONTROL_HARD_RESET_SERVER_V1"

  -- Multi-line, screenshot-friendly layout: a plain-English headline followed
  -- by indented evidence lines, mirroring azure-sql-detect.nse's convention.
  local lines = {
    "OpenVPN server confirmed via control-channel handshake",
    "  Handshake: " .. variant,
    "  Transport: " .. port.protocol,
    "  Version  : not disclosed pre-authentication (requires the TLS control channel)",
  }
  return table.concat(lines, "\n")
end
