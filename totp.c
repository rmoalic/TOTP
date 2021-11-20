#ifndef TOTP_HEADER
#define TOTP_HEADER 1

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <assert.h>

#include <openssl/sha.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef unsigned char BYTE;

enum TOTP_Algo {
    TOTP_SHA1 = 0, // ONLY SHA1 is implemented !!!
    TOTP_SHA256,
    TOTP_SHA512
};

void print_digest(BYTE* digest, uint64_t size);
uint32_t HOTP(BYTE* secret, uint64_t secret_lenght, uint64_t digits, uint64_t cycle);
uint32_t TOTP(BYTE* secret, uint64_t secret_lenght, uint64_t digits, enum TOTP_Algo algo, time_t t0, time_t tx, time_t t);

#ifdef __cplusplus
};
#endif

#endif

#ifdef TOTP_IMPLEMENTATION
#define SHS_DATASIZE 64

static int ipow(int base, int exp)
{// https://stackoverflow.com/a/101613
    int result = 1;
    for (;;)
    {
        if (exp & 1)
            result *= base;
        exp >>= 1;
        if (!exp)
            break;
        base *= base;
    }

    return result;
}

static bool digest_cmp(const BYTE a[SHA_DIGEST_LENGTH], const BYTE b[SHA_DIGEST_LENGTH]) {
    for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
        if (a[i] != b[i]) {
            return false;
        }
    }
    return true;
}

static void sha1_c(BYTE* value, uint64_t lenght, BYTE* digest) {
    SHA_CTX sha;

    SHA1_Init(&sha);
    SHA1_Update(&sha, value, lenght);
    SHA1_Final(digest, &sha);
}

static void hmac_sha1(BYTE* key, uint64_t key_lenght, BYTE* message, uint64_t message_lenght, BYTE* digest) {
    SHA_CTX sha;
    BYTE digest1[SHA_DIGEST_LENGTH];
    BYTE* used_key = NULL;
    BYTE ckey[SHS_DATASIZE] = {0};
    BYTE ipad[SHS_DATASIZE];
    BYTE opad[SHS_DATASIZE];

    if (key_lenght > SHS_DATASIZE) {
        //printf("shortening key\n");
        sha1_c(key, key_lenght, ckey);
        used_key = ckey;
    } else if (key_lenght < SHS_DATASIZE) {
        //printf("padding key\n");
        memcpy(ckey, key, key_lenght);
        used_key = ckey;
    } else {
        used_key = key;
    }

    for (int i = 0; i < SHS_DATASIZE; i++) {
        ipad[i] = used_key[i] ^ 0x36;
        opad[i] = used_key[i] ^ 0x5c;
    }

    SHA1_Init(&sha);
    SHA1_Update(&sha, ipad, SHS_DATASIZE);
    SHA1_Update(&sha, message, message_lenght);
    SHA1_Final(digest1, &sha);

    SHA1_Init(&sha);
    SHA1_Update(&sha, opad, SHS_DATASIZE);
    SHA1_Update(&sha, digest1, SHA_DIGEST_LENGTH);
    SHA1_Final(digest, &sha);
}


static void hmac_trucate(const BYTE digest[SHA_DIGEST_LENGTH], BYTE out[4]) {
    BYTE offset = digest[SHA_DIGEST_LENGTH - 1] & 0x0f;

    for (int i = 0; i < 4; i++) {
        out[i] = digest[offset + i];
    }
    out[0] &= 0x7f;
}

void print_digest(BYTE* digest, uint64_t size) {
    for (uint64_t i =0; i < size; i++) {
        printf("%02hx", digest[i]);
    }
    printf("\n");
}

//TODO: Endianness
static void uint64_to_byte(uint64_t val, BYTE out[8]) {
    for (int i = 7; i >= 0; i--) {
        out[i] = val & 0xff;
        val = val >> 8;
    }
}

//TODO: Endianness
static uint32_t trunc_to_uint32(const BYTE in[4], int n) {
    uint32_t ret = (in[0] << 24) |
                   (in[1] << 16) |
                   (in[2] <<  8) |
                   (in[3]);
    return ret % ipow(10, n);
}

static uint32_t HOTP_select_algo(BYTE* secret, uint64_t secret_lenght, uint64_t digits, enum TOTP_Algo algo, uint64_t cycle) {
    assert(algo == 0 && "SHA1 only");
    assert(digits >=6 && digits < 9);
    BYTE digest[SHA_DIGEST_LENGTH] = {0};
    BYTE txt[8] = {0};
    BYTE trunc[4] = {0};

    uint64_to_byte(cycle, txt);
    hmac_sha1(secret, secret_lenght, txt, 8, digest);
    hmac_trucate(digest, trunc);
    /*
    printf("HMAC-SHA1(secret, %lu): ", i);
    print_digest(digest, SHA_DIGEST_LENGTH);
    printf("Truncate: ");
    print_digest(trunc, 4);
    */
    return trunc_to_uint32(trunc, digits);
}

uint32_t HOTP(BYTE* secret, uint64_t secret_lenght, uint64_t digits, uint64_t cycle) {
    return HOTP_select_algo(secret, secret_lenght, digits, TOTP_SHA1, cycle);
}

static uint64_t calculate_counter_value(time_t t0, time_t tx, time_t t) {
    return (difftime(t, t0) / (double)tx);
}

uint32_t TOTP(BYTE* secret, uint64_t secret_lenght, uint64_t digits, enum TOTP_Algo algo, time_t t0, time_t tx, time_t t) {
    assert(algo == 0 && "SHA1 only");
    uint64_t counter_value = calculate_counter_value(t0, tx, t);
    return HOTP_select_algo(secret, secret_lenght, digits, algo,  counter_value);
}

#ifdef TOTP_TEST

#define m_char(t) #t
#define m_assert(test) if(! (test)){printf("%s:%d: %s(): Assertion '%s' failled\n", __FILE__, __LINE__, __func__, m_char(test)); return false;}

bool test_sha1() {
    BYTE digest[SHA_DIGEST_LENGTH] = {0};
    BYTE ret[SHA_DIGEST_LENGTH] = {0xa9, 0x4a, 0x8f, 0xe5, 0xcc, 0xb1, 0x9b, 0xa6, 0x1c, 0x4c, 0x08, 0x73, 0xd3, 0x91, 0xe9, 0x87, 0x98, 0x2f, 0xbb, 0xd3};
    BYTE testval[] = "test";

    sha1_c(testval, 4, digest);
    m_assert(digest_cmp(digest, ret));
    return true;
}

bool test_trunc() {
    BYTE in[] = {0x4c,0x93, 0xcf, 0x18};
    uint32_t out;

    out = trunc_to_uint32(in, 0);
    m_assert(out == 0);

    out = trunc_to_uint32(in, 1);
    m_assert(out == 4);

    out = trunc_to_uint32(in, 8);
    m_assert(out == 84755224);

    out = trunc_to_uint32(in, 20);
    m_assert(out == 1284755224);

    return true;
}

bool test_HOTP() {
    const uint32_t results[] = {755224 ,287082,359152, 969429, 338314, 254676, 287922, 162583, 399871, 520489};
    BYTE secret[] = "12345678901234567890";
    int secret_size = sizeof(secret) - 1;

    //test rfc4226
    for (uint64_t i = 0; i <= 9; i++) {
        uint32_t hotp = HOTP(secret, secret_size, 6, i);

        //printf("HOTP(%lu): %06u\n", i, hotp);
        m_assert(hotp == results[i]);
    }

    return true;
}

bool test_TOTP() {
    BYTE secret[] = "12345678901234567890";
    int secret_size = sizeof(secret) - 1;

    uint32_t totp;
    // test sha1 rfc6238
    totp = TOTP(secret, secret_size, 8, TOTP_SHA1, 0, 30, 59);
    m_assert(totp == 94287082);

    totp = TOTP(secret, secret_size, 8, TOTP_SHA1, 0, 30, 1111111109);
    m_assert(totp == 7081804);

    totp = TOTP(secret, secret_size, 8, TOTP_SHA1, 0, 30, 1111111111);
    m_assert(totp == 14050471);

    totp = TOTP(secret, secret_size, 8, TOTP_SHA1, 0, 30, 1234567890);
    m_assert(totp == 89005924);

    totp = TOTP(secret, secret_size, 8, TOTP_SHA1, 0, 30, 2000000000);
    m_assert(totp == 69279037);

    // fails on 32-bit compilers because 20000000000 does not fit in time_t(long). time_t is (long long) on 64-bit.
    totp = TOTP(secret, secret_size, 8, TOTP_SHA1, 0, 30, 20000000000);
    m_assert(totp == 65353130);
    // end test sha1

    //printf("TOTP: %08u\n", totp);
    return true;
}

void test() {
    bool res = true;
    res &= test_sha1();
    res &= test_trunc();
    res &= test_HOTP();
    res &= test_TOTP();
    if (res) {
        printf("Tests Passed\n");
    } else {
        printf("Tests Failled\n");
        abort();
    }
}

int main() {
    test();
    return EXIT_SUCCESS;
}
#endif
#endif
