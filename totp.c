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

typedef unsigned char byte;

enum TOTP_Algo {
    TOTP_SHA1 = 0, // ONLY SHA1 is implemented !!!
    TOTP_SHA256,
    TOTP_SHA512
};

uint32_t HOTP(byte* secret, size_t secret_lenght, uint digits, uint32_t cycle);
uint32_t TOTP(byte* secret, size_t secret_lenght, uint digits, enum TOTP_Algo algo, time_t t0, time_t tx, time_t t);

#ifdef __cplusplus
};
#endif

#endif

#ifdef TOTP_IMPLEMENTATION
// TODO: find a source for the SHA1 block size(bytes) in openssl
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

static bool digest_cmp(const byte a[SHA_DIGEST_LENGTH], const byte b[SHA_DIGEST_LENGTH]) {
    for (size_t i = 0; i < SHA_DIGEST_LENGTH; i++) {
        if (a[i] != b[i]) {
            return false;
        }
    }
    return true;
}

static void sha1_c(byte* value, size_t lenght, byte* digest) {
    SHA_CTX sha;

    SHA1_Init(&sha);
    SHA1_Update(&sha, value, lenght);
    SHA1_Final(digest, &sha);
}

static void hmac_sha1(byte* key, size_t key_lenght, byte* message, size_t message_lenght, byte* digest) {
    SHA_CTX sha;
    byte digest1[SHA_DIGEST_LENGTH];
    byte* used_key = NULL;
    byte ckey[SHS_DATASIZE] = {0};
    byte ipad[SHS_DATASIZE];
    byte opad[SHS_DATASIZE];

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

    for (size_t i = 0; i < SHS_DATASIZE; i++) {
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


static void hmac_trucate(const byte digest[SHA_DIGEST_LENGTH], byte out[4]) {
    byte offset = digest[SHA_DIGEST_LENGTH - 1] & 0x0f;

    for (int i = 0; i < 4; i++) {
        out[i] = digest[offset + i];
    }
    out[0] &= 0x7f;
}

void print_digest(byte* digest, size_t size) {
    for (size_t i =0; i < size; i++) {
        printf("%02x", digest[i]);
    }
    printf("\n");
}

static void uint32_to_bytes_be(uint32_t val, byte out[8]) {
    for (int i = 7; i >= 0; i--) {
        out[i] = val & 0xff;
        val = val >> 8;
    }
}

static uint32_t bytes_to_uint32_be(const byte in[4]) {
    uint32_t ret = (in[0] << 24) |
        (in[1] << 16) |
        (in[2] <<  8) |
        (in[3]);
    return ret;
}

static uint32_t truncate_uint(uint32_t val, int digits) {
    return val % ipow(10, digits);
}

static uint32_t HOTP_select_algo(byte* secret, size_t secret_lenght, uint digits, enum TOTP_Algo algo, uint32_t cycle) {
    assert(algo == 0 && "SHA1 only");
    assert(digits >=6 && digits < 9);
    byte digest[SHA_DIGEST_LENGTH] = {0};
    byte txt[8] = {0};
    byte trunc[4] = {0};
    uint32_t res;

    uint32_to_bytes_be(cycle, txt);
    hmac_sha1(secret, secret_lenght, txt, 8, digest);
    hmac_trucate(digest, trunc);

    res = bytes_to_uint32_be(trunc);

    return truncate_uint(res, digits);
}

uint32_t HOTP(byte* secret, size_t secret_lenght, uint digits, uint32_t cycle) {
    return HOTP_select_algo(secret, secret_lenght, digits, TOTP_SHA1, cycle);
}

static uint32_t calculate_counter_value(time_t t0, time_t tx, time_t t) {
    return (difftime(t, t0) / (double)tx);
}

uint32_t TOTP(byte* secret, size_t secret_lenght, uint digits, enum TOTP_Algo algo, time_t t0, time_t tx, time_t t) {
    assert(algo == 0 && "SHA1 only");
    uint32_t counter_value = calculate_counter_value(t0, tx, t);
    return HOTP_select_algo(secret, secret_lenght, digits, algo, counter_value);
}

#ifdef TOTP_TEST

#define m_char(t) #t
#define m_assert(test) if(! (test)){printf("%s:%d: %s(): Assertion '%s' failled\n", __FILE__, __LINE__, __func__, m_char(test)); return false;}

bool test_sha1() {
    byte digest[SHA_DIGEST_LENGTH] = {0};
    byte ret[SHA_DIGEST_LENGTH] = {0xa9, 0x4a, 0x8f, 0xe5, 0xcc, 0xb1, 0x9b, 0xa6, 0x1c, 0x4c, 0x08, 0x73, 0xd3, 0x91, 0xe9, 0x87, 0x98, 0x2f, 0xbb, 0xd3};
    byte testval[] = "test";

    sha1_c(testval, 4, digest);
    m_assert(digest_cmp(digest, ret));
    return true;
}

bool test_bytes_to_uint_be() {
    byte in[] = {0x4c,0x93, 0xcf, 0x18};
    uint32_t out;

    out = bytes_to_uint32_be(in);
    m_assert(out == 1284755224);

    return true;
}


bool test_truncate_uint() {
    uint32_t in = 1284755224;
    uint32_t out;

    out = truncate_uint(in, 0);
    m_assert(out == 0);

    out = truncate_uint(in, 1);
    m_assert(out == 4);

    out = truncate_uint(in, 8);
    m_assert(out == 84755224);

    out = truncate_uint(in, 20);
    m_assert(out == 1284755224);

    return true;
}

bool test_HOTP() {
    const uint32_t results[] = {755224 ,287082,359152, 969429, 338314, 254676, 287922, 162583, 399871, 520489};
    byte secret[] = "12345678901234567890";
    int secret_size = sizeof(secret) - 1;

    //test rfc4226
    for (uint i = 0; i <= 9; i++) {
        uint32_t hotp = HOTP(secret, secret_size, 6, i);

        //printf("HOTP(%lu): %06u\n", i, hotp);
        m_assert(hotp == results[i]);
    }

    return true;
}

bool test_TOTP() {
    byte secret[] = "12345678901234567890";
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
    res &= test_bytes_to_uint_be();
    res &= test_truncate_uint();
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
