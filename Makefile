all: client server dummy_client dummy_server postprocess
CFLAGS = -g -Wall -Wformat-overflow=0 -O3 -lsqlite3 -ftrapv

sqlinit.c: sqlinit.txt
	xxd -i $^ | sed 's/\([0-9a-f]\)$$/\0, 0x00/' > $@

dummy_main.o: main.c
	cc -c -o $@ $^ -DDUMMY $(CFLAGS)

dummy_client: dummy_client.o crypto.o test.o iomt.o sqlinit.o
	cc -o $@ $^ -lcrypto $(CFLAGS)
dummy_server: dummy_service.o dummy_main.o sqlinit.o crypto.o
	cc -o $@ $^ -lcrypto $(CFLAGS)
client: client.o crypto.o test.o iomt.o
	cc -o $@ $^ -lcrypto $(CFLAGS)
server: service_provider.o crypto.o helper.o trusted_module.o main.o test.o iomt.o sqlinit.o
	cc -o $@ $^ -lcrypto $(CFLAGS)
postprocess: postprocess.cpp
	c++ -o $@ $^
clean:
	rm -f *.o a.out client server dummy_client dummy_server postprocess
