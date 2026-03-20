#include <stdio.h>
#include "aes.h"

#ifndef AES_AS_LIB

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "nist_vectors.h"

static int hex2bin(const char *hex, uint8_t *bin, size_t bin_max_len) {
    if (!hex || !bin) return -1;
    size_t len = strlen(hex);
    if (len % 2 != 0 || len / 2 > bin_max_len) return -1;
    for (size_t i = 0; i < len / 2; i++) {
        unsigned int val;
        sscanf(hex + 2 * i, "%2x", &val);
        bin[i] = (uint8_t)val;
    }
    return (int)(len / 2);
}

int main(void)
{
    printf("Running NIST AES Test Vectors...\n");
    int failed = 0;
    int skipped = 0;
    int passed = 0;

    for (int i = 0; i < num_nist_test_vectors; i++) {
        const TestVector *vec = nist_test_vectors[i];

        uint8_t key[32] = {0};
        uint8_t iv[16] = {0};
        uint8_t pt[1024] = {0};
        uint8_t ct[1024] = {0};
        uint8_t out[1024] = {0};

        int pt_len = hex2bin(vec->plaintext, pt, sizeof(pt));
        int ct_len = hex2bin(vec->ciphertext, ct, sizeof(ct));
        hex2bin(vec->key, key, sizeof(key));

        if (vec->iv) {
            hex2bin(vec->iv, iv, sizeof(iv));
        }

        AesCtx ctx;
        AesKeyLen keylen;
        if (vec->key_len == 128) keylen = AES_KEYLEN_128;
        else if (vec->key_len == 192) keylen = AES_KEYLEN_192;
        else if (vec->key_len == 256) keylen = AES_KEYLEN_256;
        else {
            printf("FAIL: Unknown key length %d (Vector %d)\n", vec->key_len, i + 1);
            failed++;
            continue;
        }

        if (aes_init(&ctx, key, keylen) != 0) {
            printf("FAIL: aes_init failed (Vector %d)\n", i + 1);
            failed++;
            continue;
        }

        if (strcmp(vec->mode, "ECB") == 0) {
            aes_ecb_encrypt(&ctx, out, pt, pt_len);
            if (memcmp(out, ct, ct_len) != 0) {
                printf("FAIL: ECB Encrypt (Vector %d)\n", i + 1);
                failed++;
                continue;
            }

            uint8_t dec[1024] = {0};
            aes_ecb_decrypt(&ctx, dec, ct, ct_len);
            if (memcmp(dec, pt, pt_len) != 0) {
                printf("FAIL: ECB Decrypt (Vector %d)\n", i + 1);
                failed++;
                continue;
            }
            passed++;
        }
        else if (strcmp(vec->mode, "CBC") == 0) {
            aes_cbc_encrypt(&ctx, out, pt, pt_len, iv);
            if (memcmp(out, ct, ct_len) != 0) {
                printf("FAIL: CBC Encrypt (Vector %d)\n", i + 1);
                failed++;
                continue;
            }

            if (vec->iv) hex2bin(vec->iv, iv, 16); // reset IV for decrypt
            uint8_t dec[1024] = {0};
            aes_cbc_decrypt(&ctx, dec, ct, ct_len, iv);
            if (memcmp(dec, pt, pt_len) != 0) {
                printf("FAIL: CBC Decrypt (Vector %d)\n", i + 1);
                failed++;
                continue;
            }
            passed++;
        }
        else if (strcmp(vec->mode, "CFB128") == 0 || strcmp(vec->mode, "CFB") == 0) {
            aes_cfb128_encrypt(&ctx, out, pt, pt_len, iv);
            if (memcmp(out, ct, ct_len) != 0) {
                printf("FAIL: CFB Encrypt (Vector %d)\n", i + 1);
                failed++;
                continue;
            }

            if (vec->iv) hex2bin(vec->iv, iv, 16); // reset IV for decrypt
            uint8_t dec[1024] = {0};
            aes_cfb128_decrypt(&ctx, dec, ct, ct_len, iv);
            if (memcmp(dec, pt, pt_len) != 0) {
                printf("FAIL: CFB Decrypt (Vector %d)\n", i + 1);
                failed++;
                continue;
            }
            passed++;
        }
        else {
            skipped++;
        }
    }

    printf("\nTest Summary:\n");
    printf("Passed:  %d\n", passed);
    printf("Skipped: %d\n", skipped);
    printf("Failed:  %d\n", failed);

    return (failed == 0) ? 0 : 1;
}
#endif

