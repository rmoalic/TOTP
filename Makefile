CC=gcc
WARNINGS=-Wall -Wextra -Wshadow -Wno-unused-parameter
CFLAGS=-O2 -pedantic $(WARNINGS)
LINKER=-lcrypto

.PHONY: all clean test

all: lib bin

bin: main

lib: totp.so

main: main.c
	$(CC) $(CFLAGS) $< $(LINKER) -o $@

totp.so: totp.o
	$(CC) -shared $^ $(LINKER) -o $@
	strip $@

totp.o: totp.c
	$(CC) $(CFLAGS) -c -fPIC -D TOTP_IMPLEMENTATION  $< -o $@

test:
	$(CC) $(CFLAGS) -DTOTP_IMPLEMENTATION -DTOTP_TEST totp.c $(LINKER) -o totp_test && ./totp_test

clean:
	rm -f *.o *.so
	rm -f totp_test
	rm -f main
