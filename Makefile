CC = gcc
CFLAGS = -Wall -g -I.

all: send recv

send: send_raw.c
	$(CC) -o $@ $^ $(CFLAGS)

recv: recv_raw.c
	$(CC) -o $@ $^ $(CFLAGS)

.PHONY: clean

clean:
	rm -f send
	rm -f recv
