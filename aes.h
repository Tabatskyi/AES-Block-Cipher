#pragma once

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#define AES_BLOCK_SIZE 16u
#define AES_MAX_ROUND_KEY_WORDS 60u // Maximum number of round-key words: Nr_max + 1 = 15 rounds × 4 words.

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

// Initialise context from a raw key of length `keylen`. Returns 0 on success, -1 if keylen is invalid.                          
int aes_init(AesCtx *ctx, const uint8_t *key, AesKeyLen keylen);

// Encrypt / decrypt / clear a single 128-bit block (in-place is allowed).         
void aes_encrypt_block(const AesCtx *ctx, uint8_t out[AES_BLOCK_SIZE], const uint8_t in [AES_BLOCK_SIZE]);
void aes_decrypt_block(const AesCtx *ctx, uint8_t out[AES_BLOCK_SIZE], const uint8_t in [AES_BLOCK_SIZE]);
void aes_clear(AesCtx *ctx);
