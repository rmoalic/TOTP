
export PKG_CONFIG_PATH := /opt/tcl/lib/pkgconfig
all: bin lib

temp: lib main

lib: libsecret_store_libsecret.so libsecret_store_plain.so

bin: libtotp_ext.so main

libtotp_ext.so: totp_ext.c ../totp.c
	gcc -ggdb -fPIC -shared -o $@ -DUSE_TCL_STUBS $< `pkg-config --cflags --libs "tcl > 9.0"` -lcrypto

main: secret_store.c main.c
	gcc -ggdb -rdynamic secret_store.c main.c -o $@

libsecret_store_libsecret.so: secret_store_libsecret.c
	gcc -ggdb --shared -fPIC secret_store_libsecret.c `pkg-config --cflags --libs libsecret-1` -o $@

libsecret_store_plain.so: secret_store_plain.c
	gcc -ggdb --shared -fPIC secret_store_plain.c `pkg-config --cflags --libs libzip` -o $@
