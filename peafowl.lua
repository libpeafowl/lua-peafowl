#!/usr/bin/luajit

-- peafowl lua binding
-- Usage: luajit peafowl.lua /path/to/file.pcap

local arg = ...
local pfile = ""

if arg == nil then
   pfile = "./pcap/http.pcap"
else
   pfile = arg
end

print("Loading " ..pfile)

--*** Import the FFI lib
local ffi = require('ffi')
--*** Import the external library and assign it to a Lua variable
local lpeafowl = ffi.load("./include/peafowl_lib/lib/libdpi.so")
local lpcap = ffi.load("pcap")

--*** Declaration of functions to use inside ffi.cdef ***
ffi.cdef([[
 typedef struct pcap pcap_t;

 struct pcap_pkthdr {
  uint64_t ts_sec;         /* timestamp seconds */
  uint64_t ts_usec;        /* timestamp microseconds */
  uint32_t incl_len;       /* number of octets of packet saved in file */
  uint32_t orig_len;       /* actual length of packet */
};

pcap_t *pcap_open_offline(const char *fname, char *errbuf);

void pcap_close(pcap_t *p);

const uint8_t *pcap_next(pcap_t *p, struct pcap_pkthdr *h);

dpi_library_state_t* dpi_init_stateful(u_int32_t size_v4,
		                               u_int32_t size_v6,
		                               u_int32_t max_active_v4_flows,
		                               u_int32_t max_active_v6_flows);

dpi_identification_result_t dpi_stateful_identify_application_protocol(
		         dpi_library_state_t* state, const unsigned char* pkt,
		         u_int32_t length, u_int32_t current_time);

void dpi_terminate(dpi_library_state_t *state);
]])

-- Protocol names
local L7PROTO = {"DNS","MDNS","DHCP","DHCPv6","NTP","SIP","RTP","SKYPE","HTTP","BGP","SMTP","POP3","SSL"}

-- var for pcap read
local filename = pfile
local fname = ffi.new("char[?]", #filename, filename)
local errbuf = ffi.new("char[512]")

-- Read pcap file
local lhandle = pcap.pcap_open_offline(fname, errbuf)
if handle == nil then
   C.printf(errbuf)
end

-- var for Peafowl init and inspection
local lstate = peafowl.dpi_init_stateful(32767,32767,500000,500000) -- state = (typedef struct library_state ) dpi_library_state_t
local lheader = ffi.new("struct pcap_pkthdr") -- header = struct pcap_pkthdr

-- Inspect each packet
local total_packets = 0
while (1) do
   -- next pkt
   local lpacket = lpcap.pcap_next(lhandle, lheader)
   if lpacket == nil then break end
   -- convert to const unsigned char* (packet)
   -- convert header !!!!
   -- init from Peafowl
   local lproto = peafowl.dpi_stateful_identify_application_protocol(lstate, lpacket, lheader, os.time()*1000)
   print("PKT !")
   total_packets = total_packets + 1
end
pcap.pcap_close(lhandle)

-- Print results
peafowl.dpi_terminate(lstate)

print("Total packets: "..total_packets)
