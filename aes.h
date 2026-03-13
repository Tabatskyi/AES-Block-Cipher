#pragma once

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#define AES_BLOCK_SIZE 16u
#define AES_MAX_ROUND_KEY_WORDS 60u // Maximum number of round-key words: Nr_max + 1 = 15 rounds * 4 words.

#define AES_KEY128 16u
#define AES_KEY192 24u
#define AES_KEY256 32u

typedef enum : uint8_t {
    AES_KEYLEN_128 = AES_KEY128,
    AES_KEYLEN_192 = AES_KEY192,
    AES_KEYLEN_256 = AES_KEY256,
} AesKeyLen;

// Expanded key schedule. 
typedef struct {
    uint32_t roundKey[AES_MAX_ROUND_KEY_WORDS]; // round-key words after KeyExpansion 
    uint8_t numRounds; // number of rounds: 10 / 12 / 14    
} AesCtx;

// Initialise context from a raw key of length "keylen". Returns 0 on success, -1 if keylen is invalid.                          
int aes_init(AesCtx *ctx, const uint8_t *key, AesKeyLen keylen);

// Encrypt / decrypt / clear a single 128-bit block.         
void aes_encrypt_block(const AesCtx *ctx, uint8_t out[AES_BLOCK_SIZE], const uint8_t in [AES_BLOCK_SIZE]);
void aes_decrypt_block(const AesCtx *ctx, uint8_t out[AES_BLOCK_SIZE], const uint8_t in [AES_BLOCK_SIZE]);

// ECB mode: "len" must be a multiple of AES_BLOCK_SIZE. 
int aes_ecb_encrypt(const AesCtx *ctx, uint8_t *out, const uint8_t *in, size_t len);
int aes_ecb_decrypt(const AesCtx *ctx, uint8_t *out, const uint8_t *in, size_t len);

// CBC mode: "len" must be a multiple of AES_BLOCK_SIZE. "iv" is the initial IV for the operation and is not modified.
int aes_cbc_encrypt(const AesCtx *ctx, uint8_t *out, const uint8_t *in, size_t len, const uint8_t iv[AES_BLOCK_SIZE]);
int aes_cbc_decrypt(const AesCtx *ctx, uint8_t *out, const uint8_t *in, size_t len, const uint8_t iv[AES_BLOCK_SIZE]);

// CFB128 mode: "len" may be any value >= 0. "iv" is the initial shift-register value and is not modified.
int aes_cfb128_encrypt(const AesCtx *ctx, uint8_t *out, const uint8_t *in, size_t len, const uint8_t iv[AES_BLOCK_SIZE]);
int aes_cfb128_decrypt(const AesCtx *ctx, uint8_t *out, const uint8_t *in, size_t len, const uint8_t iv[AES_BLOCK_SIZE]);

// clear the context
void aes_clear(AesCtx *ctx);
