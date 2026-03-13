#pragma once

#include <stddef.h>
#include <stdint.h>

#define AES_BLOCK_SIZE 16u
/* Nr_max + 1 = 15 round keys, each with 4 words. */
#define AES_MAX_ROUND_KEY_WORDS 60u

#define AES_KEY128 16u
#define AES_KEY192 24u
#define AES_KEY256 32u

typedef enum {
    AES_KEYLEN_128 = AES_KEY128,
    AES_KEYLEN_192 = AES_KEY192,
    AES_KEYLEN_256 = AES_KEY256,
} AesKeyLen;

typedef struct {
    uint32_t round_key[AES_MAX_ROUND_KEY_WORDS];
    uint8_t round_count;
} AesCtx;

/* Returns 0 on success, -1 on invalid key length. */
int aes_init(AesCtx *ctx, const uint8_t *key, AesKeyLen keylen);

/* Single-block AES (16 bytes). In-place operation is supported. */
void aes_encrypt_block(const AesCtx *ctx, uint8_t out[AES_BLOCK_SIZE], const uint8_t in[AES_BLOCK_SIZE]);
void aes_decrypt_block(const AesCtx *ctx, uint8_t out[AES_BLOCK_SIZE], const uint8_t in[AES_BLOCK_SIZE]);

/* 'len' must be a multiple of AES_BLOCK_SIZE. */
int aes_ecb_encrypt(const AesCtx *ctx, uint8_t *out, const uint8_t *in, size_t len);
int aes_ecb_decrypt(const AesCtx *ctx, uint8_t *out, const uint8_t *in, size_t len);

/* 'len' must be a multiple of AES_BLOCK_SIZE. */
int aes_cbc_encrypt(const AesCtx *ctx, uint8_t *out, const uint8_t *in, size_t len, const uint8_t iv[AES_BLOCK_SIZE]);
int aes_cbc_decrypt(const AesCtx *ctx, uint8_t *out, const uint8_t *in, size_t len, const uint8_t iv[AES_BLOCK_SIZE]);

/* 'len' may be any value. */
int aes_cfb128_encrypt(const AesCtx *ctx, uint8_t *out, const uint8_t *in, size_t len, const uint8_t iv[AES_BLOCK_SIZE]);
int aes_cfb128_decrypt(const AesCtx *ctx, uint8_t *out, const uint8_t *in, size_t len, const uint8_t iv[AES_BLOCK_SIZE]);

/* Clears expanded key material from memory. */
void aes_clear(AesCtx *ctx);
