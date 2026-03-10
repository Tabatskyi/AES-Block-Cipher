/* Key (128-bit):
 *   2b 7e 15 16  28 ae d2 a6  ab f7 15 88  09 cf 4f 3c
 * Plaintext:
 *   32 43 f6 a8  88 5a 30 8d  31 31 98 a2  e0 37 07 34
 * Expected ciphertext:
 *   39 25 84 1d  02 dc 09 fb  dc 11 85 97  19 6a 0b 32
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "aes.h"
#include "rng.h"

static void print_hex(const char *label, const uint8_t *buf, size_t len)
{
    printf("%-14s", label);
    for (size_t i = 0; i < len; ++i)
        printf("%02x%s", buf[i], (i + 1) % 4 == 0 && i + 1 < len ? "  " : " ");
    putchar('\n');
}

static bool bytes_eq(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint8_t diff = 0;
    for (size_t i = 0; i < n; ++i)
        diff |= a[i] ^ b[i];
    return diff == 0;
}

int main(void)
{
    // FIPS 197 Appendix B vector
    static const uint8_t key128[AES_KEY128] = {
        0x2b,0x7e,0x15,0x16, 0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88, 0x09,0xcf,0x4f,0x3c,
    };
    static const uint8_t plaintext[AES_BLOCK_SIZE] = {
        0x32,0x43,0xf6,0xa8, 0x88,0x5a,0x30,0x8d,
        0x31,0x31,0x98,0xa2, 0xe0,0x37,0x07,0x34,
    };
    static const uint8_t expected_ct[AES_BLOCK_SIZE] = {
        0x39,0x25,0x84,0x1d, 0x02,0xdc,0x09,0xfb,
        0xdc,0x11,0x85,0x97, 0x19,0x6a,0x0b,0x32,
    };

    puts("AES-128 FIPS 197 Appendix B vector");
    print_hex("Key:", key128, AES_KEY128);
    print_hex("Plaintext:", plaintext, AES_BLOCK_SIZE);

    AesCtx ctx;
    if (aes_init(&ctx, key128, AES_KEYLEN_128) != 0) {
        fputs("aes_init failed\n", stderr);
        return 1;
    }

    uint8_t ct[AES_BLOCK_SIZE];
    aes_encrypt_block(&ctx, ct, plaintext);
    print_hex("Ciphertext:", ct, AES_BLOCK_SIZE);
    print_hex("Expected:", expected_ct, AES_BLOCK_SIZE);
    printf("Encrypt: %s\n\n", bytes_eq(ct, expected_ct, AES_BLOCK_SIZE) ? "PASS" : "FAIL");

    uint8_t recovered[AES_BLOCK_SIZE];
    aes_decrypt_block(&ctx, recovered, ct);
    print_hex("Decrypted:", recovered, AES_BLOCK_SIZE);
    printf("Decrypt: %s\n\n", bytes_eq(recovered, plaintext, AES_BLOCK_SIZE) ? "PASS" : "FAIL");

    aes_clear(&ctx);

    puts("AES-256 random-key round-trip");
    uint8_t rnd_key[AES_KEY256];
    uint8_t rnd_pt[AES_BLOCK_SIZE];
    if (rng_fill(rnd_key, sizeof rnd_key) != 0 ||
        rng_fill(rnd_pt, sizeof rnd_pt ) != 0) {
        fputs("rng_fill failed\n", stderr);
        return 1;
    }
    print_hex("Key:", rnd_key, AES_KEY256);
    print_hex("Plaintext:", rnd_pt, AES_BLOCK_SIZE);

    AesCtx ctx256;
    aes_init(&ctx256, rnd_key, AES_KEYLEN_256);

    uint8_t rnd_ct[AES_BLOCK_SIZE], rnd_rec[AES_BLOCK_SIZE];
    aes_encrypt_block(&ctx256, rnd_ct, rnd_pt);
    aes_decrypt_block(&ctx256, rnd_rec, rnd_ct);
    print_hex("Ciphertext:", rnd_ct, AES_BLOCK_SIZE);
    print_hex("Recovered:", rnd_rec, AES_BLOCK_SIZE);
    printf("Round-trip: %s\n", bytes_eq(rnd_rec, rnd_pt, AES_BLOCK_SIZE) ? "PASS" : "FAIL");

    aes_clear(&ctx256);
    return 0;
}
