all: client server Makefile
CFLAGS = -g -Wall -O3 -lsqlite3

client: client.o crypto.o test.o iomt.o
	cc -o $@ $^ -lcrypto $(CFLAGS)
server: service_provider.o crypto.o helper.o trusted_module.o main.o test.o iomt.o
	cc -o $@ $^ -lcrypto $(CFLAGS)
clean:
	rm -f *.o a.out client server
