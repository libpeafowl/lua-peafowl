#!bin/bash

lib:
	@ if [ ! -d "./include/peafowl_lib" ]; then git clone https://github.com/DanieleDeSensi/Peafowl.git ./include/peafowl_lib; fi;
	@ if [ ! -f ./include/peafowl_lib/lib/libdpi.a ]; then make -C ./include/peafowl_lib; fi;

.PHONY: clean
clean:
	rm -fr ./include/peafowl_lib
