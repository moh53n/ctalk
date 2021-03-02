CC = gcc
CFLAGS += -lpthread -I./src/include

all: client server

server: src/server/server.o src/net/socket.o
	$(CC) -o $@ $^ $(CFLAGS)

client: src/client/client.o src/client/base64.o src/net/socket.o
	$(CC) -o $@ $^ $(CFLAGS)

clean:
	find . -type f -name '*.o' -delete
	rm -f server client
