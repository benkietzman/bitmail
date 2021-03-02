###########################################
# BitMail
# -------------------------------------
# file       : Makefile
# author     : Ben Kietzman
# begin      : 2013-08-19
# copyright  : kietzman.org
# email      : ben@kietzman.org
###########################################

all: bin/bitmail

bin/bitmail: ../common/libcommon.a obj/bitmail.o
	-if [ ! -d bin ]; then mkdir bin; fi;
	g++ -ggdb -o bin/bitmail obj/bitmail.o -L../common -lbz2 -lcommon -lcrypto -lexpat -lmjson -lnsl -lpthread -lrt -lssl -ltar -lxmlrpc -lxmlrpc_client -lxmlrpc_util -lz

../common/libcommon.a: ../common/Makefile
	cd ../common; make;

../common/Makefile: ../common/configure
	cd ../common; ./configure;

../common/configure:
	cd ../; git clone https://github.com/benkietzman/common.git

obj/bitmail.o: bitmail.cpp ../common/Makefile
	-if [ ! -d obj ]; then mkdir obj; fi;
	g++ -Wall -ggdb -std=c++14 -c bitmail.cpp -o obj/bitmail.o -I../common

install: bin/bitmail
	install bin/bitmail /usr/local/bin/
	-if [ ! -d /etc/bitmail ]; then mkdir /etc/bitmail; fi;
	-if [ ! -f /etc/bitmail/bitmail.conf ]; then install etc/bitmail.conf /etc/bitmail/; fi;
	-if [ ! -f /etc/bitmail/bitmail.key ]; then openssl genrsa -out /etc/bitmail/bitmail.key 1024; fi;
	-if [ ! -f /etc/bitmail/bitmail.csr ]; then openssl req -new -key /etc/bitmail/bitmail.key -out /etc/bitmail/bitmail.csr; fi;
	-if [ ! -f /etc/bitmail/bitmail.crt ]; then openssl x509 -req -days 365 -in /etc/bitmail/bitmail.csr -signkey /etc/bitmail/bitmail.key -out /etc/bitmail/bitmail.crt; fi;
	-if [ ! -f /etc/init/bitmail.service ]; then install init/bitmail.service /lib/systemd/system/; fi;

clean:
	-rm -fr obj bin

uninstall:
	-rm -f /etc/init/bitmail.conf
	-rm -f /lib/systemd/system/bitmail.service
	-rm -fr /etc/bitmail
	-rm -f /usr/local/bin/bitmail
