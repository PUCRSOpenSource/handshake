CC = gcc
CFLAGS = -Wall -g -I.

all: send recv

send: send_raw.c
	$(CC) -o $@ $^ $(CFLAGS)

recv: recv_raw.c
	$(CC) -o $@ $^ $(CFLAGS)

.PHONY: clean server client

clean:
	rm -f send
	rm -f recv

server: recv
	sudo ./recv enp2s0 192.168.25.2

client: send
	sudo ./send enp2s0
