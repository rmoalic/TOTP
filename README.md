# TOTP implementation

> WARNING: sha1 is the only protocol implemented

Build and run the demo program

```shell
$ make # gcc -lcrypto main.c -o main
$ ./main
```


Run tests with

```shell
$ make test
```

## References

* [RFC4226](https://www.ietf.org/rfc/rfc4226.txt) HOTP Algorithm
* [RFC6238](https://www.ietf.org/rfc/rfc6238.txt) TOTP: Time-Based One-Time Password Algorithm
