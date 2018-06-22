all: client server Makefile
CFLAGS = -g -Wall

client: client.o crypto.o test.o
	cc -o $@ $^ -lcrypto $(CFLAGS)
server: service_provider.o crypto.o helper.o trusted_module.o main.o test.o
	cc -o $@ $^ -lcrypto $(CFLAGS)
clean:
	rm -f *.o a.out client server
