CC = gcc

CFLAGS = -c -Wall -std=c99

LDFLAGS= -lpcap

all: sniff

sniff: main.o packet.o
	$(CC) main.o packet.o $(LDFLAGS) -o sniff

main.o: main.c
	$(CC) $(CFLAGS) main.c

packet.o: packet.c
	$(CC) $(CFLAGS) packet.c

clean:
	rm -rf *o sniff



