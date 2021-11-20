#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define TOTP_IMPLEMENTATION 1
#include "totp.c"

int main() {
    BYTE secret[] = {0x45, 0x2f, 0x52, 0x45, 0xd7, 0x49, 0x0e, 0x32, 0xda, 0xf1};
    int secret_size = sizeof(secret);
    uint32_t totp;

    totp = TOTP(secret, secret_size, 8, TOTP_SHA1, 0, 30, time(NULL));

    printf("TOTP: %08u\n", totp);

    return EXIT_SUCCESS;
}
