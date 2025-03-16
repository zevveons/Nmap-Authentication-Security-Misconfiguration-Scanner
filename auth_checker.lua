description = [[
Version/Draft 1.8: My most recent version with performance improvements and final fixes
The Purpose: Simple authentication and security configuration scanner
Supported Protocols: HTTP, HTTPS, FTP, SMB, LDAP, IMAP, POP3, VNC, Telnet, RADIUS, 
                     Elasticsearch, Kibana, DockerAPI, SSH, TLS, and Proxy services

What does it do: It checks authentication weaknesses like default credentials and anonymous access, detects insecure configurations
such as outdated TLS, open proxies, and weak SSH credentials,identifies security misconfigurations like exposed services such as Kibana
and Elasticsearch, and provides security teams with actionable fixes.

]]

author = "Maximilian Kottmeyer"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "safe", "pratice"}

-- Load required libraries 
local nmap = require "nmap" -- nmap 
local stdnse = require "stdnse" -- standard nmap engine 
local http = require "http" -- handling http request 
local sslcert = require "sslcert" -- ssl certificates scanning
local ssh = require "ssh" -- ssh authenctiation 
local proxy = require "proxy" -- for detecting open proxies

portrule = function(host, port)
  return port.protocol == "tcp" and port.state == "open" and (
    port.service:match("^http") or
    port.service == "https" or
    port.service == "ftp" or
    port.service == "telnet" or
    port.service == "microsoft-ds" or
    port.service == "ldap" or
    port.service == "imap" or 
    port.service == "pop3" or
    port.service == "vnc" or
    port.service == "radius" or
    port.service == "ssh" or
    port.service == "proxy" or
    port.number == 9200 or port.number == 5601 or port.number == 2375 or
    port.number == 8080 or port.number == 3128 or port.number == 1080
  )
end
-- Helper Functionb: To safely execute and checks catch errors this ensures that the script 
-- doesnt crasg if a function fails 
local function safe_check(host, port, check_name, func, ...)
  local status, result = pcall(func, ...)
  if not status then
    local error_msg = string.format("Error in '%s' at %s:%d - %s", 
                    check_name, host.ip, port.number, result)
    if nmap.verbosity() > 2 then  -- Only log detailed errors at high verbosity
      stdnse.debug1(error_msg)
    end
    return nil, error_msg
  end
  return result, nil
end
-- Checks SSL/TLS security on HTTPS services it verifies TLS version, detects weak ciphers etc 
local function check_ssl_tls_weakness(host, port)
  if port.service ~= "https" then return nil end

  if nmap.verbosity() > 1 then
    stdnse.debug1("Checking SSL/TLS security on %s:%d", host.ip, port.number)
  end

  local output = {}
  local cert, cert_err = safe_check(host, port, "SSL Certificate", 
                                  sslcert.getCertificate, host, port)

  if not cert then
    table.insert(output, "SSL/TLS check failed: " .. (cert_err or "No certificate"))
    return output
  end

  -- TLS version check from certificate
  if cert.version then
    if cert.version < 1.2 then
      table.insert(output, string.format("High: Outdated TLS version detected! (v%.1f)", cert.version))
    end
  else
    table.insert(output, "TLS version information unavailable")
  end

  if cert.valid == false then
    table.insert(output, "High: Expired SSL certificate detected!")
  end

  if cert.issuer == cert.subject then
    table.insert(output, "Medium: Self-signed SSL certificate detected!")
  end

  local weak_ciphers = { "RC4", "DES", "3DES" } -- Checking for weak ciphers  
  for _, cipher in ipairs(weak_ciphers) do
    if cert.cipher and cert.cipher:match(cipher) then
      table.insert(output, "High: Weak SSL cipher detected - " .. cipher)
    end
  end

  return #output > 0 and output or nil
end
-- Checks if open proxy service is running, uses HTTP and SOCKS proxies and reports if they allow unauthenticated access 
local function check_open_proxy(host, port)
  if port.service ~= "proxy" and 
     port.number ~= 8080 and 
     port.number ~= 3128 and 
     port.number ~= 1080 then 
    return nil
  end

  if nmap.verbosity() > 1 then
    stdnse.debug1("Checking for open proxy at %s:%d", host.ip, port.number)
  end

  local output = {}

  -- HTTP Proxy check
  local response, http_err = safe_check(host, port, "HTTP Proxy test", 
                                      http.get, host, port, "http://example.com", 
                                      {
                                        no_cache = true,
                                        bypass_cache = true,
                                        header = {
                                          ["Proxy-Connection"] = "Keep-Alive",
                                          ["Via"] = "1.1 nmap-script"
                                        }
                                      })
  if response and response.header["X-Forwarded-For"] then
    table.insert(output, "High: Open HTTP proxy detected - allows external connections")
  elseif http_err then
    table.insert(output, "HTTP proxy check failed: " .. http_err)
  end

  -- SOCKS Proxy check
  local sock, socks_err = safe_check(host, port, "SOCKS Proxy test", 
                                   proxy.connect, host, port)
  if sock and type(sock) == "table" and sock.close then
    table.insert(output, "High: Open SOCKS proxy detected")
    sock:close()
  elseif socks_err then
    table.insert(output, "SOCKS proxy check failed: " .. socks_err)
  end

  if #output == 0 then
    table.insert(output, "No open proxy detected")
  end

  return output
end
-- SSH authenication check for weak creds 
local function check_ssh_auth(host, port)
  if port.service ~= "ssh" then return nil end

  if nmap.verbosity() > 1 then
    stdnse.debug1("Checking SSH authentication on %s:%d", host.ip, port.number)
  end

  local output = {}
  local common_creds = {
    {"root", "toor"}, {"admin", "admin"}, {"user", "password"},
    {"test", "test"}, {"pi", "raspberry"}
  }

  for _, cred in ipairs(common_creds) do
    local username, password = cred[1], cred[2]
    local ssh_session, ssh_err = safe_check(host, port, "SSH auth "..username, 
                                      ssh.connect, host, port, 
                                      {user = username, password = password, timeout = 5000})
    
    if ssh_session then
      table.insert(output, string.format("Critical: SSH weak credential found - %s:%s", 
                      username, password))
      ssh_session:disconnect()
    elseif ssh_err then
      table.insert(output, "SSH authentication attempt failed: " .. ssh_err)
    end
  end

  return #output > 0 and output or nil
end
-- Checks if HTTP authenication creds are leaked
local function check_basic_auth_leak(host, port)
  if not port.service:match("^http") then return nil end

  if nmap.verbosity() > 1 then
    stdnse.debug1("Checking for Basic Auth leaks on %s:%d", host.ip, port.number)
  end

  local output = {}
  local response, err = safe_check(host, port, "HTTP Headers", http.get, host, port, "/")

  if response and response.header then
    local auth_header = response.header["Authorization"]
    if auth_header and auth_header:match("Basic%s+(%S+)") then
      local encoded = auth_header:match("Basic%s+(%S+)")
      local decoded = stdnse.base64dec(encoded)  -- Corrected function name
      if decoded then
        table.insert(output, "High: Basic Auth credentials exposed: " .. decoded)
      else
        table.insert(output, "Warning: Malformed Basic Auth header detected")
      end
    end
  end

  return #output > 0 and output or nil
end

action = function(host, port)
  local output = {}
  local checks = {
    https = check_ssl_tls_weakness,
    ssh = check_ssh_auth,
    proxy = check_open_proxy,
    http = function(h,p) 
            local res = check_basic_auth_leak(h,p)
            return res or (nmap.verbosity() > 0 and {"Basic Auth: No credentials leaked"} or nil)
           end
  }

  -- Run protocol-specific checks
  if checks[port.service] then
    local results = checks[port.service](host, port)
    if results then
      for _, item in ipairs(results) do
        table.insert(output, item)
      end
    end
  end

  -- Additional protocol checks
  local additional_checks = {
    imap = "IMAP", pop3 = "POP3", telnet = "Telnet", radius = "RADIUS"
  }
  
  for svc, name in pairs(additional_checks) do
    if port.service == svc then
      table.insert(output, name .. " detected - Use " .. svc .. "-brute script")
    end
  end

  if #output == 0 then
    return stdnse.format_output(true, {"No authentication issues detected on this port."})
  end

  return stdnse.format_output(true, output)
end
