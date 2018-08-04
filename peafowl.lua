#!/usr/bin/luajit

-- peafowl lua binding
-- Usage: luajit peafowl.lua /path/to/file.pcap

local arg = ...
local pfile = ""

if arg==nil then
   pfile = "./pcap/http.pcap"
else
   pfile = arg
end

print("Loading " .. pfile )

local ffi = require('ffi')
local C = ffi.C

ffi.include = function(fname)
  local f
  if type(fname) == "string" then
    print("Including " .. fname)
    f = io.popen("echo '#include <" .. fname .. ">' | gcc -E -")
  elseif type(fname) == "table" then
    f = io.popen("cat " .. fname[1] .. " | gcc -E -")
  else
    assert(nil, "Need either string or array[1] as argument")
  end
  local t = {}
  while true do
    local line = f:read()
    if line then
      if not line:match("^#") then
        table.insert(t, line)
      end
    else
      break
    end
  end
  -- print(table.concat(t, "\n"))
  ffi.cdef(table.concat(t, "\n"))
  f:close()
end

local peafowl = ffi.load("./include/libdpi.so")
local pcap = ffi.load("pcap")

-- ffi.include("./include/api.h")

ffi.cdef([[
/* Pcap */
typedef struct pcap pcap_t;
struct pcap_pkthdr {
  uint64_t ts_sec;         /* timestamp seconds */
  uint64_t ts_usec;        /* timestamp microseconds */
  uint32_t incl_len;       /* number of octets of packet saved in file */
  uint32_t orig_len;       /* actual length of packet */
};
int printf(const char *format, ...);
pcap_t *pcap_open_offline(const char *fname, char *errbuf);
void pcap_close(pcap_t *p);
const uint8_t *pcap_next(pcap_t *p, struct pcap_pkthdr *h);

/* Peafowl */

typedef void (*callback)(int, const uint8_t *packet);
void dpi_init_stateful(int, int, int, int);
void dpi_stateful_identify_application_protocol(struct , const uint8_t *packet, int, int);
void dpi_terminate();
]])

local L7PROTO = {"DNS","MDNS","DHCP","DHCPv6","NTP","SIP","RTP","SKYPE","HTTP","BGP","SMTP","POP3","SSL"}

local pcap = ffi.load("pcap")

local filename = pfile
local fname = ffi.new("char[?]", #filename, filename)
local errbuf = ffi.new("char[512]")

-- Read pcap file
local handle = pcap.pcap_open_offline(fname, errbuf)
if handle == nil then
   C.printf(errbuf)
end

local state = peafowl.dpi_init_stateful(32767,32767,500000,500000)


local header = ffi.new("struct pcap_pkthdr")
-- Inspect each packet
local total_packets = 0
while (1) do
   local packet = pcap.pcap_next(handle, header)
   if packet == nil then break end
   local proto = peafowl.dpi_stateful_identify_application_protocol(state, packet, header, os.time()*1000)
   total_packets = total_packets + 1
end
pcap.pcap_close(handle)

-- Print results
peafowl.dpi_terminate(state)

print("Total packets: "..total_packets)
