#include <stdio.h>
#include <stdint.h>

#ifndef WOLFSSL_USER_SETTINGS
#include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/aes.h>


#define MAX_PRINT_STRING_LEN 1024
static char bit_string[MAX_PRINT_STRING_LEN + 1];

char nibble_to_hex_char(uint8_t nibble)
{
    char buf[16] = { '0', '1', '2', '3', '4', '5', '6', '7',
                     '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

    return buf[nibble & 0xF];
}

const char *octet_string_hex_string(const uint8_t *str, size_t length)
{
    size_t i;

    /* double length, since one octet takes two hex characters */
    length *= 2;

    /* truncate string if it would be too long */
    if (length > MAX_PRINT_STRING_LEN) {
        length = MAX_PRINT_STRING_LEN;
    }

    for (i = 0; i < length; i += 2) {
        bit_string[i] = nibble_to_hex_char(*str >> 4);
        bit_string[i + 1] = nibble_to_hex_char(*str++ & 0xF);
    }
    bit_string[i] = 0; /* null terminate string */
    return bit_string;
}



static int test()
{
    Aes aes;
    int err = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (err < 0) {
        printf("init failed wolfSSL error code: %d\n", err);
        return 1;
    }

    uint8_t key[16] = {
        0xc6, 0x1e, 0x7a, 0x93, 0x74, 0x4f, 0x39, 0xee,
        0x10, 0x73, 0x4a, 0xfe, 0x3f, 0xf7, 0xa0, 0x87
    };

    uint8_t iv_0[16] = {
        0x30, 0xcb, 0xbc, 0x08, 0x4c, 0xc3, 0x36, 0x3b,
        0xd4, 0x9d, 0xb3, 0x4a, 0x88, 0xd4, 0x00, 0x00
    };
    uint8_t src_0[] = {
        0x51, 0x00, 0x02, 0x00, 0xab, 0xab, 0xab, 0xab,
        0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
        0xab, 0xab, 0xab, 0xab
    };
    uint8_t ref_0[] = {
        0xeb, 0x92, 0x36, 0x52, 0x51, 0xc3, 0xe0, 0x36,
        0xf8, 0xde, 0x27, 0xe9, 0xc2, 0x7e, 0xe3, 0xe0,
        0xb4, 0x65, 0x1d, 0x9f
    };

    uint8_t iv_1[16] = {
        0x30, 0xcb, 0xbc, 0x08, 0x4c, 0xc3, 0x36, 0x3b,
        0xd4, 0x9d, 0xb3, 0x4a, 0x88, 0xd7, 0x00, 0x00
    };
    uint8_t src_1[] = {
        0x05, 0x02, 0x00, 0x02, 0xab, 0xab, 0xab, 0xab,
        0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
        0xab, 0xab, 0xab, 0xab
    };
    uint8_t ref_1[] = {
        0x4e, 0xd9, 0xcc, 0x4e, 0x6a, 0x71, 0x2b, 0x30,
        0x96, 0xc5, 0xca, 0x77, 0x33, 0x9d, 0x42, 0x04,
        0xce, 0x0d, 0x77, 0x39
    };

    printf("key: %s\n", octet_string_hex_string(key, sizeof(key)));

    err = wc_AesSetKey(&aes, key, sizeof(key), NULL, AES_ENCRYPTION);
    if (err < 0) {
        printf("set key, wolfSSL error code: %d", err);
        return 1;
    }

    uint8_t alt_key[16] = {
        0x4c, 0x1a, 0xa4, 0x5a, 0x81, 0xf7, 0x3d, 0x61,
        0xc8, 0x00, 0xbb, 0xb0, 0x0f, 0xbb, 0x1e, 0xaa
    };

    Aes alt_aes;
    err = wc_AesInit(&alt_aes, NULL, INVALID_DEVID);
    if (err < 0) {
        printf("alt init failed wolfSSL error code: %d\n", err);
        return 1;
    }

    printf("alt_key: %s\n", octet_string_hex_string(alt_key, sizeof(alt_key)));

    err = wc_AesSetKey(&alt_aes, alt_key, sizeof(alt_key), NULL, AES_ENCRYPTION);
    if (err < 0) {
        printf("alt set key, wolfSSL error code: %d", err);
        return 1;
    }

    printf("iv_0: %s\n", octet_string_hex_string(iv_0, sizeof(iv_0)));

    err = wc_AesSetIV(&aes, iv_0);
    if (err < 0) {
        printf("set IV 0, wolfSSL error code: %d", err);
        return 1;
    }

    printf("src_0: %s\n", octet_string_hex_string(src_0, sizeof(src_0)));

    err = wc_AesCtrEncrypt(&aes, src_0, src_0, sizeof(src_0));
    if (err < 0) {
        printf("encrypt 0, wolfSSL encrypt error: %d", err);
        return 1;
    }

    printf("enc_0: %s\n", octet_string_hex_string(src_0, sizeof(src_0)));

    if (memcmp(src_0, ref_0, sizeof(src_0)) != 0) {
        printf("encrypt 0 failed, not equal\n");
        printf("ref_0: %s\n", octet_string_hex_string(ref_0, sizeof(ref_0)));
        return 1;
    }

    printf("key: %s\n", octet_string_hex_string(key, sizeof(key)));

    err = wc_AesSetKey(&aes, key, sizeof(key), NULL, AES_ENCRYPTION);
    if (err < 0) {
        printf("set key, wolfSSL error code: %d", err);
        return 1;
    }

    printf("iv_1 : %s\n", octet_string_hex_string(iv_1, sizeof(iv_1)));

    err = wc_AesSetIV(&aes, iv_1);
    if (err < 0) {
        printf("set IV 1, wolfSSL error code: %d", err);
        return 1;
    }

    printf("src_1: %s\n", octet_string_hex_string(src_1, sizeof(src_1)));

    err = wc_AesCtrEncrypt(&aes, src_1, src_1, sizeof(src_1));
    if (err < 0) {
        printf("encrypt 1, wolfSSL encrypt error: %d", err);
        return 1;
    }

    printf("enc_1: %s\n", octet_string_hex_string(src_1, sizeof(src_1)));

    if (memcmp(src_1, ref_1, sizeof(src_1)) != 0) {
        printf("encrypt 1 failed, not equal\n");
        printf("ref_1: %s\n", octet_string_hex_string(ref_1, sizeof(ref_1)));
        return 1;
    }

    wc_AesFree(&aes);
    wc_AesFree(&alt_aes);

    return 0;
}

int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;
    printf("Wolfssl Test\n");
    if (test() != 0) {
        return 1;
    }
    printf("Passed\n");
    return 0;
}