CC = gcc
CFLAGS += -lpthread

all: client server

server: server.o
	$(CC) -o $@ $^ $(CFLAGS)

client: client.o
	$(CC) -o $@ $^ $(CFLAGS)

clean:
	rm -rf server.o server client.o client
