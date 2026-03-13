#include "aes.h"

#include <string.h>

static inline uint32_t load_be32(const uint8_t bytes[static 4])
{
    return ((uint32_t)bytes[0] << 24)
         | ((uint32_t)bytes[1] << 16)
         | ((uint32_t)bytes[2] << 8)
         | (uint32_t)bytes[3];
}

static inline void store_be32(uint8_t bytes[static 4], uint32_t word)
{
    bytes[0] = (uint8_t)(word >> 24);
    bytes[1] = (uint8_t)(word >> 16);
    bytes[2] = (uint8_t)(word >> 8);
    bytes[3] = (uint8_t)word;
}

static const uint8_t SBOX[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
};

static const uint8_t SBOX_INV[256] = {
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d,
};

static inline uint8_t xtime(uint8_t value)
{
    return (uint8_t)((value << 1) ^ ((value >> 7) ? 0x1bu : 0x00u));
}

static inline uint8_t gmul(uint8_t lhs, uint8_t rhs)
{
    uint8_t result = 0;
    for (int bit_idx = 0; bit_idx < 8; ++bit_idx) {
        if (rhs & 1u) {
            result ^= lhs;
        }

        bool high_bit = (lhs >> 7) != 0u;
        lhs = (uint8_t)(lhs << 1);
        if (high_bit) {
            lhs ^= 0x1bu;
        }
        rhs >>= 1;
    }
    return result;
}

static const uint8_t RCON[11] = {
    0x00,
    0x01, 0x02, 0x04, 0x08, 0x10,
    0x20, 0x40, 0x80, 0x1b, 0x36,
};

static inline uint32_t sub_word(uint32_t word)
{
    return ((uint32_t)SBOX[(word >> 24) & 0xffu] << 24)
         | ((uint32_t)SBOX[(word >> 16) & 0xffu] << 16)
         | ((uint32_t)SBOX[(word >> 8) & 0xffu] << 8)
         | (uint32_t)SBOX[word & 0xffu];
}

static inline uint32_t rot_word(uint32_t word)
{
    return (word << 8) | (word >> 24);
}

int aes_init(AesCtx *ctx, const uint8_t *key, AesKeyLen keylen)
{
    uint8_t key_words = 0;

    switch (keylen) {
        case AES_KEYLEN_128:
            key_words = 4;
            ctx->round_count = 10;
            break;
        case AES_KEYLEN_192:
            key_words = 6;
            ctx->round_count = 12;
            break;
        case AES_KEYLEN_256:
            key_words = 8;
            ctx->round_count = 14;
            break;
        default:
            return -1;
    }

    const uint8_t total_words = (uint8_t)(4u * (ctx->round_count + 1u));

    for (uint8_t word_idx = 0; word_idx < key_words; ++word_idx) {
        ctx->round_key[word_idx] = load_be32(key + 4u * word_idx);
    }

    for (uint8_t word_idx = key_words; word_idx < total_words; ++word_idx) {
        uint32_t prev_word = ctx->round_key[word_idx - 1u];

        if ((word_idx % key_words) == 0u) {
            prev_word = sub_word(rot_word(prev_word))
                ^ ((uint32_t)RCON[word_idx / key_words] << 24);
        } else if ((key_words > 6u) && ((word_idx % key_words) == 4u)) {
            prev_word = sub_word(prev_word);
        }

        ctx->round_key[word_idx] = ctx->round_key[word_idx - key_words] ^ prev_word;
    }

    return 0;
}

void aes_clear(AesCtx *ctx)
{
    volatile uint8_t *clear_ptr = (volatile uint8_t *)ctx;
    for (size_t byte_idx = 0; byte_idx < sizeof(*ctx); ++byte_idx) {
        clear_ptr[byte_idx] = 0;
    }
}

typedef uint32_t AesState[4];

static inline void bytes_to_state(AesState state, const uint8_t input[AES_BLOCK_SIZE])
{
    for (int col_idx = 0; col_idx < 4; ++col_idx) {
        state[col_idx] = load_be32(input + (size_t)(4 * col_idx));
    }
}

static inline void state_to_bytes(uint8_t output[AES_BLOCK_SIZE], const AesState state)
{
    for (int col_idx = 0; col_idx < 4; ++col_idx) {
        store_be32(output + (size_t)(4 * col_idx), state[col_idx]);
    }
}

static inline uint8_t state_get_byte(const AesState state, int row_idx, int col_idx)
{
    return (uint8_t)(state[col_idx] >> (24 - 8 * row_idx));
}

static void sub_bytes(AesState state)
{
    for (int col_idx = 0; col_idx < 4; ++col_idx) {
        state[col_idx] = ((uint32_t)SBOX[(state[col_idx] >> 24) & 0xffu] << 24)
                       | ((uint32_t)SBOX[(state[col_idx] >> 16) & 0xffu] << 16)
                       | ((uint32_t)SBOX[(state[col_idx] >> 8) & 0xffu] << 8)
                       | (uint32_t)SBOX[state[col_idx] & 0xffu];
    }
}

static void shift_rows(AesState state)
{
    uint32_t row0 = ((uint32_t)state_get_byte(state, 0, 0) << 24)
                  | ((uint32_t)state_get_byte(state, 0, 1) << 16)
                  | ((uint32_t)state_get_byte(state, 0, 2) << 8)
                  | (uint32_t)state_get_byte(state, 0, 3);
    uint32_t row1 = ((uint32_t)state_get_byte(state, 1, 1) << 24)
                  | ((uint32_t)state_get_byte(state, 1, 2) << 16)
                  | ((uint32_t)state_get_byte(state, 1, 3) << 8)
                  | (uint32_t)state_get_byte(state, 1, 0);
    uint32_t row2 = ((uint32_t)state_get_byte(state, 2, 2) << 24)
                  | ((uint32_t)state_get_byte(state, 2, 3) << 16)
                  | ((uint32_t)state_get_byte(state, 2, 0) << 8)
                  | (uint32_t)state_get_byte(state, 2, 1);
    uint32_t row3 = ((uint32_t)state_get_byte(state, 3, 3) << 24)
                  | ((uint32_t)state_get_byte(state, 3, 0) << 16)
                  | ((uint32_t)state_get_byte(state, 3, 1) << 8)
                  | (uint32_t)state_get_byte(state, 3, 2);

    for (int col_idx = 0; col_idx < 4; ++col_idx) {
        state[col_idx] = (((row0 >> (24 - 8 * col_idx)) & 0xffu) << 24)
                       | (((row1 >> (24 - 8 * col_idx)) & 0xffu) << 16)
                       | (((row2 >> (24 - 8 * col_idx)) & 0xffu) << 8)
                       | ((row3 >> (24 - 8 * col_idx)) & 0xffu);
    }
}

static void mix_columns(AesState state)
{
    for (int col_idx = 0; col_idx < 4; ++col_idx) {
        uint8_t byte0 = (uint8_t)(state[col_idx] >> 24);
        uint8_t byte1 = (uint8_t)(state[col_idx] >> 16);
        uint8_t byte2 = (uint8_t)(state[col_idx] >> 8);
        uint8_t byte3 = (uint8_t)state[col_idx];

        uint8_t mix0 = (uint8_t)(xtime(byte0) ^ gmul(3u, byte1) ^ byte2 ^ byte3);
        uint8_t mix1 = (uint8_t)(byte0 ^ xtime(byte1) ^ gmul(3u, byte2) ^ byte3);
        uint8_t mix2 = (uint8_t)(byte0 ^ byte1 ^ xtime(byte2) ^ gmul(3u, byte3));
        uint8_t mix3 = (uint8_t)(gmul(3u, byte0) ^ byte1 ^ byte2 ^ xtime(byte3));

        state[col_idx] = ((uint32_t)mix0 << 24)
                       | ((uint32_t)mix1 << 16)
                       | ((uint32_t)mix2 << 8)
                       | (uint32_t)mix3;
    }
}

static void add_round_key(AesState state, const uint32_t *round_key)
{
    for (int col_idx = 0; col_idx < 4; ++col_idx) {
        state[col_idx] ^= round_key[col_idx];
    }
}

static void inv_sub_bytes(AesState state)
{
    for (int col_idx = 0; col_idx < 4; ++col_idx) {
        state[col_idx] = ((uint32_t)SBOX_INV[(state[col_idx] >> 24) & 0xffu] << 24)
                       | ((uint32_t)SBOX_INV[(state[col_idx] >> 16) & 0xffu] << 16)
                       | ((uint32_t)SBOX_INV[(state[col_idx] >> 8) & 0xffu] << 8)
                       | (uint32_t)SBOX_INV[state[col_idx] & 0xffu];
    }
}

static void inv_shift_rows(AesState state)
{
    uint32_t row0 = ((uint32_t)state_get_byte(state, 0, 0) << 24)
                  | ((uint32_t)state_get_byte(state, 0, 1) << 16)
                  | ((uint32_t)state_get_byte(state, 0, 2) << 8)
                  | (uint32_t)state_get_byte(state, 0, 3);
    uint32_t row1 = ((uint32_t)state_get_byte(state, 1, 3) << 24)
                  | ((uint32_t)state_get_byte(state, 1, 0) << 16)
                  | ((uint32_t)state_get_byte(state, 1, 1) << 8)
                  | (uint32_t)state_get_byte(state, 1, 2);
    uint32_t row2 = ((uint32_t)state_get_byte(state, 2, 2) << 24)
                  | ((uint32_t)state_get_byte(state, 2, 3) << 16)
                  | ((uint32_t)state_get_byte(state, 2, 0) << 8)
                  | (uint32_t)state_get_byte(state, 2, 1);
    uint32_t row3 = ((uint32_t)state_get_byte(state, 3, 1) << 24)
                  | ((uint32_t)state_get_byte(state, 3, 2) << 16)
                  | ((uint32_t)state_get_byte(state, 3, 3) << 8)
                  | (uint32_t)state_get_byte(state, 3, 0);

    for (int col_idx = 0; col_idx < 4; ++col_idx) {
        state[col_idx] = (((row0 >> (24 - 8 * col_idx)) & 0xffu) << 24)
                       | (((row1 >> (24 - 8 * col_idx)) & 0xffu) << 16)
                       | (((row2 >> (24 - 8 * col_idx)) & 0xffu) << 8)
                       | ((row3 >> (24 - 8 * col_idx)) & 0xffu);
    }
}

static void inv_mix_columns(AesState state)
{
    for (int col_idx = 0; col_idx < 4; ++col_idx) {
        uint8_t byte0 = (uint8_t)(state[col_idx] >> 24);
        uint8_t byte1 = (uint8_t)(state[col_idx] >> 16);
        uint8_t byte2 = (uint8_t)(state[col_idx] >> 8);
        uint8_t byte3 = (uint8_t)state[col_idx];

        uint8_t mix0 = (uint8_t)(gmul(0x0eu, byte0) ^ gmul(0x0bu, byte1) ^ gmul(0x0du, byte2) ^ gmul(0x09u, byte3));
        uint8_t mix1 = (uint8_t)(gmul(0x09u, byte0) ^ gmul(0x0eu, byte1) ^ gmul(0x0bu, byte2) ^ gmul(0x0du, byte3));
        uint8_t mix2 = (uint8_t)(gmul(0x0du, byte0) ^ gmul(0x09u, byte1) ^ gmul(0x0eu, byte2) ^ gmul(0x0bu, byte3));
        uint8_t mix3 = (uint8_t)(gmul(0x0bu, byte0) ^ gmul(0x0du, byte1) ^ gmul(0x09u, byte2) ^ gmul(0x0eu, byte3));

        state[col_idx] = ((uint32_t)mix0 << 24)
                       | ((uint32_t)mix1 << 16)
                       | ((uint32_t)mix2 << 8)
                       | (uint32_t)mix3;
    }
}

void aes_encrypt_block(const AesCtx *ctx, uint8_t out[AES_BLOCK_SIZE], const uint8_t in[AES_BLOCK_SIZE])
{
    AesState state;
    bytes_to_state(state, in);

    add_round_key(state, ctx->round_key);

    for (uint8_t round_idx = 1; round_idx < ctx->round_count; ++round_idx) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, ctx->round_key + 4u * round_idx);
    }

    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, ctx->round_key + 4u * ctx->round_count);

    state_to_bytes(out, state);
}

void aes_decrypt_block(const AesCtx *ctx, uint8_t out[AES_BLOCK_SIZE], const uint8_t in[AES_BLOCK_SIZE])
{
    AesState state;
    bytes_to_state(state, in);

    add_round_key(state, ctx->round_key + 4u * ctx->round_count);

    for (uint8_t round_idx = (uint8_t)(ctx->round_count - 1u); round_idx >= 1u; --round_idx) {
        inv_shift_rows(state);
        inv_sub_bytes(state);
        add_round_key(state, ctx->round_key + 4u * round_idx);
        inv_mix_columns(state);
    }

    inv_shift_rows(state);
    inv_sub_bytes(state);
    add_round_key(state, ctx->round_key);

    state_to_bytes(out, state);
}

int aes_ecb_encrypt(const AesCtx *ctx, uint8_t *out, const uint8_t *in, size_t len)
{
    if ((len % AES_BLOCK_SIZE) != 0u) {
        return -1;
    }

    for (size_t block_off = 0; block_off < len; block_off += AES_BLOCK_SIZE) {
        aes_encrypt_block(ctx, out + block_off, in + block_off);
    }
    return 0;
}

int aes_ecb_decrypt(const AesCtx *ctx, uint8_t *out, const uint8_t *in, size_t len)
{
    if ((len % AES_BLOCK_SIZE) != 0u) {
        return -1;
    }

    for (size_t block_off = 0; block_off < len; block_off += AES_BLOCK_SIZE) {
        aes_decrypt_block(ctx, out + block_off, in + block_off);
    }
    return 0;
}

int aes_cbc_encrypt(const AesCtx *ctx, uint8_t *out, const uint8_t *in, size_t len, const uint8_t iv[AES_BLOCK_SIZE])
{
    if ((len % AES_BLOCK_SIZE) != 0u) {
        return -1;
    }

    uint8_t prev_block[AES_BLOCK_SIZE];
    memcpy(prev_block, iv, AES_BLOCK_SIZE);

    for (size_t block_off = 0; block_off < len; block_off += AES_BLOCK_SIZE) {
        uint8_t xor_block[AES_BLOCK_SIZE];
        for (size_t byte_idx = 0; byte_idx < AES_BLOCK_SIZE; ++byte_idx) {
            xor_block[byte_idx] = (uint8_t)(in[block_off + byte_idx] ^ prev_block[byte_idx]);
        }
        aes_encrypt_block(ctx, out + block_off, xor_block);
        memcpy(prev_block, out + block_off, AES_BLOCK_SIZE);
    }
    return 0;
}

int aes_cbc_decrypt(const AesCtx *ctx, uint8_t *out, const uint8_t *in, size_t len, const uint8_t iv[AES_BLOCK_SIZE])
{
    if ((len % AES_BLOCK_SIZE) != 0u) {
        return -1;
    }

    uint8_t prev_block[AES_BLOCK_SIZE];
    memcpy(prev_block, iv, AES_BLOCK_SIZE);

    for (size_t block_off = 0; block_off < len; block_off += AES_BLOCK_SIZE) {
        uint8_t dec_block[AES_BLOCK_SIZE];
        aes_decrypt_block(ctx, dec_block, in + block_off);
        for (size_t byte_idx = 0; byte_idx < AES_BLOCK_SIZE; ++byte_idx) {
            out[block_off + byte_idx] = (uint8_t)(dec_block[byte_idx] ^ prev_block[byte_idx]);
        }
        memcpy(prev_block, in + block_off, AES_BLOCK_SIZE);
    }
    return 0;
}

int aes_cfb128_encrypt(const AesCtx *ctx, uint8_t *out, const uint8_t *in, size_t len, const uint8_t iv[AES_BLOCK_SIZE])
{
    uint8_t shift_reg[AES_BLOCK_SIZE];
    memcpy(shift_reg, iv, AES_BLOCK_SIZE);

    size_t data_off = 0;
    while (data_off < len) {
        uint8_t key_stream[AES_BLOCK_SIZE];
        aes_encrypt_block(ctx, key_stream, shift_reg);

        size_t chunk_len = len - data_off;
        if (chunk_len > AES_BLOCK_SIZE) {
            chunk_len = AES_BLOCK_SIZE;
        }

        for (size_t byte_idx = 0; byte_idx < chunk_len; ++byte_idx) {
            out[data_off + byte_idx] = (uint8_t)(in[data_off + byte_idx] ^ key_stream[byte_idx]);
        }

        if (chunk_len == AES_BLOCK_SIZE) {
            memcpy(shift_reg, out + data_off, AES_BLOCK_SIZE);
        } else {
            memmove(shift_reg, shift_reg + chunk_len, AES_BLOCK_SIZE - chunk_len);
            memcpy(shift_reg + (AES_BLOCK_SIZE - chunk_len), out + data_off, chunk_len);
        }

        data_off += chunk_len;
    }
    return 0;
}

int aes_cfb128_decrypt(const AesCtx *ctx, uint8_t *out, const uint8_t *in, size_t len, const uint8_t iv[AES_BLOCK_SIZE])
{
    uint8_t shift_reg[AES_BLOCK_SIZE];
    memcpy(shift_reg, iv, AES_BLOCK_SIZE);

    size_t data_off = 0;
    while (data_off < len) {
        uint8_t key_stream[AES_BLOCK_SIZE];
        aes_encrypt_block(ctx, key_stream, shift_reg);

        size_t chunk_len = len - data_off;
        if (chunk_len > AES_BLOCK_SIZE) {
            chunk_len = AES_BLOCK_SIZE;
        }

        for (size_t byte_idx = 0; byte_idx < chunk_len; ++byte_idx) {
            out[data_off + byte_idx] = (uint8_t)(in[data_off + byte_idx] ^ key_stream[byte_idx]);
        }

        if (chunk_len == AES_BLOCK_SIZE) {
            memcpy(shift_reg, in + data_off, AES_BLOCK_SIZE);
        } else {
            memmove(shift_reg, shift_reg + chunk_len, AES_BLOCK_SIZE - chunk_len);
            memcpy(shift_reg + (AES_BLOCK_SIZE - chunk_len), in + data_off, chunk_len);
        }

        data_off += chunk_len;
    }
    return 0;
}
