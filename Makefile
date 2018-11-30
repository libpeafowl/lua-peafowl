#!bin/bash

lib:
	@ if [ ! -d "./include/peafowl_lib" ]; then git clone https://github.com/DanieleDeSensi/Peafowl.git ./include/peafowl_lib; fi;
	@ if [ ! -f  ./include/peafowl_lib/build/src/libpeafowl.so ]; then cd ./include/peafowl_lib && mkdir build && cd build && cmake ../ && make; fi;

.PHONY: clean
clean:
	rm -fr ./include/peafowl_lib
