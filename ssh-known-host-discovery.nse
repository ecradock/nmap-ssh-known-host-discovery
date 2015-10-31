local stdnse = require "stdnse"
local shortport = require "shortport"
local base64 = require "base64"
local os = require "os"
local ssh1 = require "ssh1"
local ssh2 = require "ssh2"

description = [[
Matches SSH's known_hosts against scanned hosts and checks for matching fingerprints.
]]

portrule = shortport.port_or_service(22,"ssh")

author = "Ed Cradock"
license = "GPL 2.0"
categories = {"discovery"}

--
--@output
-- Post-scan script results:
-- | ssh-known-host-discovery:
-- |   my.hostname:
-- |     fingerprint: SHA256[q7StLmS/+YYwF42lL4HQJdMQGcAPpkKgzVlxORTisGE=]
-- |_    address: 127.0.0.1

--
--@usage
-- nmap -p 22 --script=ssh-known-host-discovery.nse 192.168.0.0/24
-- nmap -p 22 --script=ssh-known-host-discovery.nse --script-args ssh-known-host-discovery.known_hosts_path=/path/to/known_hosts 192.168.0.0/24
--
-- Without specifying known_hosts_path, path will automatically be assumed: $HOME/.ssh/known_hosts

get_known_hosts_path = function()
  local known_hosts_path = stdnse.get_script_args('ssh-known-host-discovery.known_hosts_path')

  if not known_hosts_path then
    local home_env = os.getenv('HOME')
    known_hosts_path = home_env .. '/.ssh/known_hosts'
    local is_readable = io.open(known_hosts_path, 'r')

    if is_readable then
      io.close(is_readable)
    end

    if not home_env or not is_readable then
      return nil
    end
  end

  return known_hosts_path
end

fetch_keys = function(host, port)
  local keys = {}
  local key
  local ssh2_key_algos = {"ssh-dss", "ssh-rsa","ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521"}

  key = ssh1.fetch_host_key( host, port )
  if key then table.insert( keys, key ) end

  for i, algo in ipairs(ssh2_key_algos) do
    key = ssh2.fetch_host_key(host, port, algo)

    if key then table.insert(keys, key) end
  end

  if #keys < 0 then
    return nil
  end

  return keys
end

sha256_fingerprint = function(key)
  return base64.enc(openssl.digest("sha256", base64.dec(key)))
end

action = function(host, port)
  local out = {}
  local known_hosts_path = get_known_hosts_path()
  stdnse.print_debug('known_hosts path used %s', known_hosts_path)

  if not known_hosts_path then
    return 'No valid known_hosts file could be found.'
  end

  local parsed_hosts = ssh1.parse_known_hosts_file(known_hosts_path)

  if #parsed_hosts == 0 then
    return 'Host file contains no valid hosts. ' .. get_known_hosts_path()
  end

  stdnse.print_debug('%d hosts found in known_hosts', #parsed_hosts)

  local keys = fetch_keys(host, port)
  local computed_fingerprints = {}

  for _, entry in ipairs(parsed_hosts) do
    local local_computed_fingerprint = sha256_fingerprint(entry.entry[3])
    table.insert(computed_fingerprints, {name=entry.entry[1], fingerprint=local_computed_fingerprint})
  end

  for _, key in ipairs( keys ) do
    local remote_computed_fingerprint = sha256_fingerprint(key.key)

    for __, fingerprint in ipairs(computed_fingerprints) do
      if remote_computed_fingerprint == fingerprint.fingerprint then
        out[fingerprint.name] = {address=host.ip, fingerprint='SHA256[' .. fingerprint.fingerprint .. ']'}
      end
    end
  end

  if next(out) == nil then
    return 'No hosts were found matching known_hosts'
  end

  return out
end
