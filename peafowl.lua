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

local peafowl = ffi.load("./include/libdpi.so")
local pcap = ffi.load("pcap")

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
void init();
void processPacket(const uint8_t *packet, const struct pcap_pkthdr *header);
void finish();
]])

local L7PROTO = {"DNS","MDNS","DHCP","DHCPv6","NTP","SIP","RTP","SKYPE","HTTP","BGP","SMTP","POP3","SSL"}

/*
function onProtocol(id, packet)
   if id >= 2 then
	   io.write("Proto: ")
	   print(  ffi.string(packet), "ID:", id)
   end
end

-- Register protocol handler
peafowl.addProtocolHandler(onProtocol)

*/


local pcap = ffi.load("pcap")

local filename = pfile
local fname = ffi.new("char[?]", #filename, filename)
local errbuf = ffi.new("char[512]")
local protoId = -1

-- Read pcap file
local handle = pcap.pcap_open_offline(fname, errbuf)
if handle == nil then
   C.printf(errbuf)
end

peafowl.init()


local header = ffi.new("struct pcap_pkthdr")
-- Inspect each packet
local total_packets = 0
while (1) do
   local packet = pcap.pcap_next(handle, header)
   if packet == nil then break end
   peafowl.processPacket(packet, header)
   total_packets = total_packets + 1
end
pcap.pcap_close(handle)

-- Print results
peafowl.finish()

print("Total packets: "..total_packets)
