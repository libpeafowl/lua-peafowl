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
ffi.include "./include//peafowl_lib/build/src/libpeafowl.so"
local lpeafowl = ffi.load("./include/peafowl_lib/build/src/libpeafowl.so")
local lpcap = ffi.load("pcap")

--*** Utils
function ternary ( cond , T , F )
    if cond then return T else return F end
end

--*** Declaration of functions to use inside ffi.cdef
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

static pfwl_state_t* state;                  
static pfwl_dissection_info_t dissection_info; 
struct pcap_pkthdr* header;                

int b_init()
{
  state = pfwl_init();
  if(state == NULL) {
      fprintf(stderr, "peafowl init ERROR\n");
      return -1; // ERROR
  }
  return 0;
}


pfwl_protocol_l2_t _convert_pcap_dlt(int link_type)
{
    return pfwl_convert_pcap_dlt(link_type);
}


pfwl_status_t _dissect_from_L2(char* packet, uint32_t length,
                               uint32_t timestamp, pfwl_protocol_l2_t datalink_type)
{
    return pfwl_dissect_from_L2(state, (const u_char*) packet,
                                length, time(NULL),
                                datalink_type, &dissection_info);
}


pfwl_status_t _dissect_from_L3(char* packet_fromL3, uint32_t length_fromL3,
                               uint32_t timestamp)
{
    return pfwl_dissect_from_L3(state, (const u_char*) packet_fromL3,
                                length_fromL3, time(NULL), &dissection_info);
}


pfwl_status_t _dissect_from_L4(char* packet_fromL4, uint32_t length_fromL4,
                               uint32_t timestamp)
{
    return pfwl_dissect_from_L3(state, (const u_char*) packet_fromL4,
                                length_fromL4, time(NULL), &dissection_info);
}


uint8_t _protocol_L7_enable(pfwl_protocol_l7_t protocol)
{
    return pfwl_protocol_l7_enable(state, protocol);
}


uint8_t _protocol_L7_disable(pfwl_protocol_l7_t protocol)
{
    return pfwl_protocol_l7_disable(state, protocol);
}


pfwl_protocol_l7_t _guess_protocol()
{
    return pfwl_guess_protocol(dissection_info);
}


char* _get_L7_protocol_name(pfwl_protocol_l7_t protocol)
{
    return pfwl_get_L7_protocol_name(protocol);
}


pfwl_protocol_l7_t _get_L7_protocol_id(char* string)
{
    return pfwl_get_L7_protocol_id(string);
}


char* _get_L7_from_L2(char* packet, struct pcap_pkthdr* header, int link_type)
{
    char* name = NULL;
    pfwl_protocol_l2_t dlt = pfwl_convert_pcap_dlt(link_type);
    pfwl_status_t status = pfwl_dissect_from_L2(state, (const u_char*) packet,
                                                header->caplen, time(NULL), dlt, &dissection_info);

    if(status >= PFWL_STATUS_OK) {
        name = pfwl_get_L7_protocol_name(dissection_info.l7.protocol);
        return name;
    }
    else return "ERROR";
}


uint8_t _field_add_L7(char* field)
{
    pfwl_field_id_t f = pfwl_get_L7_field_id(field);
    return pfwl_field_add_L7(state, f);
}


uint8_t _field_remove_L7(char* field)
{
    pfwl_field_id_t f = pfwl_get_L7_field_id(field);
    return pfwl_field_remove_L7(state, f);
}


uint8_t _set_protocol_accuracy_L7(pfwl_protocol_l7_t protocol,
                                  pfwl_dissector_accuracy_t accuracy)
{
    return pfwl_set_protocol_accuracy_L7(state, protocol, accuracy);
}


int _field_present(char* field)
{
    pfwl_field_id_t f = pfwl_get_L7_field_id(field);
    return dissection_info.l7.protocol_fields[f].present;
}


char* _field_string_get(char* field)
{
    pfwl_string_t string;
    pfwl_field_id_t f = pfwl_get_L7_field_id(field);
    pfwl_field_string_get(dissection_info.l7.protocol_fields, f, &string);
    return string.value;
}


int _field_number_get(char* field)
{
    int64_t num;
    pfwl_field_id_t f = pfwl_get_L7_field_id(field);
    pfwl_field_number_get(dissection_info.l7.protocol_fields, f, &num);
    return num;
}

void _terminate()
{
  pfwl_terminate(state);
}

]])

-- Protocol names
local L4PROTO = {TCP = 6, UDP = 17}
local DPI_NUM_UDP_PROTOCOLS = 8

-- var for pcap read
local filename = pfile
local fname = ffi.new("char[?]", #filename, filename)
local errbuf = ffi.new("char[512]")

-- counters for IP - TCP UDP
local ip_counter = 0
local tcp_counter = 0
local udp_counter = 0

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

   -- increment counters of pkts
   total_packets = total_packets + 1
   
   -- increment ip pkt count
   ip_counter = ip_counter + 1
   
   -- inspection from Peafowl
   local lproto = lpeafowl.dpi_get_protocol(lstate, lpacket+leth_offset, lheader.len-leth_offset, os.time()*1000)

   -- increment tcp or udp pkt count
   if lproto.protocol.l4prot == L4PROTO.TCP then -- TCP
      tcp_counter = tcp_counter + 1
      l4 = "TCP"
   else
      if lproto.protocol.l4prot == L4PROTO.UDP then -- UDP
	 udp_counter = udp_counter + 1
	 l4 = "UDP"
      else
	 l4 = "Unknown"
      end
   end
   
   -- "create" the l7_ID as a C type
   local l7_ID = ffi.new("dpi_l7_prot_id")
   l7_ID = lproto.protocol.l7prot
   
   -- call function to get protocol name
   local L7 = ffi.string(lpeafowl.dpi_get_protocol_string(l7_ID))
   
   -- Print results
   print(string.format("Protocol: %s %s %d", l4, L7, total_packets))
   
end
lpcap.pcap_close(lhandle)

-- terminate status
lpeafowl.dpi_terminate(lstate)

-- Print results
print("Total number of packets in the pcap file: "..total_packets)
print("Total number of ip packets: "..ip_counter)
print("Total number of tcp packets: "..tcp_counter)
print("Total number of udp packets: "..udp_counter)
