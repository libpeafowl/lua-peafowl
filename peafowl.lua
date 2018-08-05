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

print("Loading "..pfile)

--*** Import the FFI lib
local ffi = require('ffi')
--*** Import the external library and assign it to a Lua variable
local lpeafowl = ffi.load("./include/peafowl_lib/lib/libdpi.so")
local lpcap = ffi.load("pcap")

--*** Utils
function ternary ( cond , T , F )
    if cond then return T else return F end
end

--*** Declaration of functions to use inside ffi.cdef ***
ffi.cdef([[
 typedef struct pcap pcap_t;

 struct pcap_pkthdr {
    uint64_t ts_sec;
    uint64_t ts_usec; 
    uint32_t caplen; 
    uint32_t len;    
};

pcap_t *pcap_open_offline(const char *fname, char *errbuf);
void pcap_close(pcap_t *p);
const uint8_t *pcap_next(pcap_t *p, struct pcap_pkthdr *h);


typedef void(dpi_flow_cleaner_callback)(void* flow_specific_user_data);

typedef struct dpi_protocol{
	uint8_t l4prot;
	uint8_t l7prot;
} dpi_protocol_t;

struct library_state{
  void *db4;
  void *db6;

  char udp_protocols_to_inspect[1];
  char tcp_protocols_to_inspect[1];

  char udp_active_callbacks[1];
  char tcp_active_callbacks[1];

  uint8_t udp_active_protocols;
  uint8_t tcp_active_protocols;

  uint16_t max_trials;

  dpi_flow_cleaner_callback* flow_cleaner_callback;

  void* http_callbacks;
  void* http_callbacks_user_data;
  void *ssl_callbacks;
  void *ssl_callbacks_user_data;

  uint8_t tcp_reordering_enabled:1;

  void* ipv4_frag_state;
  void* ipv6_frag_state;
};
typedef struct library_state dpi_library_state_t;

typedef struct dpi_identification_result{
	int8_t status;
	dpi_protocol_t protocol;
	void* user_flow_data;
} dpi_identification_result_t;

dpi_library_state_t* dpi_init_stateful(uint32_t size_v4,
		                               uint32_t size_v6,
		                               uint32_t max_active_v4_flows,
		                               uint32_t max_active_v6_flows);

dpi_identification_result_t dpi_stateful_identify_application_protocol(
		         dpi_library_state_t* state, const unsigned char* pkt,
		         uint32_t length, uint32_t current_time);

void dpi_terminate(dpi_library_state_t *state);
]])

-- Protocol names
local L7PROTO = {"DNS","MDNS","DHCP","DHCPv6","NTP","SIP","RTP","SKYPE","HTTP","BGP","SMTP","POP3","SSL"}
local DPI_NUM_UDP_PROTOCOLS = 8

-- var for pcap read
local filename = pfile
local fname = ffi.new("char[?]", #filename, filename)
local errbuf = ffi.new("char[512]")

-- Read pcap file
local lhandle = lpcap.pcap_open_offline(fname, errbuf)
if lhandle == nil then
   print("error buffer")
   return
end

-- var for Peafowl init and inspection
local lstate = lpeafowl.dpi_init_stateful(32767,32767,500000,500000) -- state = (typedef struct library_state ) dpi_library_state_t
local lheader = ffi.new("struct pcap_pkthdr") -- header = struct pcap_pkthdr

local leth_offset = 14

-- Inspect each packet
local total_packets = 0
while (1) do
   -- next pkt
   local lpacket = lpcap.pcap_next(lhandle, lheader)
   if lpacket == nil then
      break
   end
   -- init from Peafowl
   local lproto = lpeafowl.dpi_stateful_identify_application_protocol(lstate, lpacket+leth_offset, lheader.len-leth_offset, os.time()*1000)
   print("PKT Received", "L4", lproto.protocol.l4prot, "L7", L7PROTO[ternary( lproto.protocol.l4prot == 6, lproto.protocol.l7prot+DPI_NUM_UDP_PROTOCOLS, lproto.protocol.l7prot)+1] )
   total_packets = total_packets + 1
end
lpcap.pcap_close(lhandle)

-- Print results
lpeafowl.dpi_terminate(lstate)

print("Total packets: "..total_packets)
