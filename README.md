<img src="https://i.imgur.com/jrQX0Of.gif" width=250> 

# lua-peafowl
LUA Native Bindings for the Peafowl DPI Library

## About
Peafowl is a flexible and extensible DPI framework which can be used to identify the application protocols carried by IP (IPv4 and IPv6) packets and to extract and process data and metadata carried by those protocols.

### Build
```
git clone https://github.com/libpeafowl/lua-peafowl && cd lua peafowl
make
```

### Usage
```
luajit peafowl.lua pcap/http.pcap
```


-------------

If you use Peafowl or Node-Peafowl for scientific purposes, please cite the following paper:

```"Deep Packet Inspection on Commodity Hardware using FastFlow", M. Danelutto, L. Deri, D. De Sensi, M. Torquati```

###### This Project is sponsored by [QXIP BV](http://qxip.net)


