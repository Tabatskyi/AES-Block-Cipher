#include "aes.h"

// Load/store 32-bit big-endian word (state column). 
static inline uint32_t load_be32(const uint8_t b[static 4])
{
    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) | ((uint32_t)b[2] << 8) | (uint32_t)b[3];
}

static inline void store_be32(uint8_t b[static 4], uint32_t w)
{
    b[0] = (uint8_t)(w >> 24);
    b[1] = (uint8_t)(w >> 16);
    b[2] = (uint8_t)(w >> 8);
    b[3] = (uint8_t)(w);
}

// AES S-box and inverse S-box (FIPS 197 &5.1.1, Table 4 / &5.3.2, Table 6)
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

static inline uint8_t xtime(uint8_t a)
{
    return (uint8_t)((a << 1) ^ ((a >> 7) ? 0x1bu : 0x00u));
}

static inline uint8_t gmul(uint8_t a, uint8_t b)
{
    uint8_t p = 0;
    for (int i = 0; i < 8; ++i) {
        if (b & 1u) 
            p ^= a;

        bool hi = (a >> 7) & 1u;
        a = (uint8_t)(a << 1);
        
        if (hi) 
            a ^= 0x1bu;

        b >>= 1;
    }
    return p;
}

static const uint8_t RCON[11] = {
    0x00, // unused index 0 
    0x01, 0x02, 0x04, 0x08, 0x10,
    0x20, 0x40, 0x80, 0x1b, 0x36,
};

static inline uint32_t sub_word(uint32_t w)
{
    return ((uint32_t)SBOX[(w >> 24) & 0xffu] << 24) | ((uint32_t)SBOX[(w >> 16) & 0xffu] << 16) | ((uint32_t)SBOX[(w >> 8) & 0xffu] << 8) |  (uint32_t)SBOX[(w) & 0xffu];
}

static inline uint32_t rot_word(uint32_t w)
{
    return (w << 8) | (w >> 24);
}

// Key Expansion (FIPS 197 &5.2)

int aes_init(AesCtx *ctx, const uint8_t *key, AesKeyLen keylen)
{
    uint8_t nk; // number of 32-bit words in original key 

    switch (keylen) {
    case AES_KEYLEN_128: nk = 4; ctx->numRounds = 10; break;
    case AES_KEYLEN_192: nk = 6; ctx->numRounds = 12; break;
    case AES_KEYLEN_256: nk = 8; ctx->numRounds = 14; break;
    default: return -1;
    }

    const uint8_t total_words = (uint8_t)(4u * (ctx->numRounds + 1u));

    // Load original key words. 
    for (uint8_t i = 0; i < nk; ++i)
        ctx->roundKey[i] = load_be32(key + 4u * i);

    // Expand. 
    for (uint8_t i = nk; i < total_words; ++i) {
        uint32_t tmp = ctx->roundKey[i - 1];
        if (i % nk == 0) {
            tmp = sub_word(rot_word(tmp)) ^ ((uint32_t)RCON[i / nk] << 24);
        } else if (nk > 6 && i % nk == 4) {
            tmp = sub_word(tmp);
        }
        ctx->roundKey[i] = ctx->roundKey[i - nk] ^ tmp;
    }
    return 0;
}

void aes_clear(AesCtx *ctx)
{
    // Use volatile to prevent the compiler from optimising the wipe away. 
    volatile uint8_t *p = (volatile uint8_t *)ctx;
    for (size_t i = 0; i < sizeof *ctx; ++i) p[i] = 0;
}

// State helpers — the 4×4 byte matrix is stored column-major in four uint32_t words (s[col]), matching FIPS 197 &3.4.

typedef uint32_t State[4]; // s[c] = word for column c 

static inline void bytes_to_state(State s, const uint8_t in[static AES_BLOCK_SIZE])
{
    for (int c = 0; c < 4; ++c)
        s[c] = load_be32(in + 4 * c);
}

static inline void state_to_bytes(uint8_t out[static AES_BLOCK_SIZE], const State s)
{
    for (int c = 0; c < 4; ++c)
        store_be32(out + 4 * c, s[c]);
}

// Byte at row r, column c. 
static inline uint8_t sb(const State s, int r, int c)
{
    return (uint8_t)(s[c] >> (24 - 8 * r));
}

// Forward transformations (FIPS 197 &5.1)

// SubBytes &5.1.1 
static void sub_bytes(State s)
{
    for (int c = 0; c < 4; ++c) {
        s[c] = ((uint32_t)SBOX[(s[c] >> 24)] << 24) | ((uint32_t)SBOX[(s[c] >> 16) & 0xffu] << 16) | ((uint32_t)SBOX[(s[c] >> 8) & 0xffu] << 8) | (uint32_t)SBOX[(s[c]) & 0xffu];
    }
}

// ShiftRows &5.1.2 
static void shift_rows(State s)
{
    uint8_t t;

    // Row 1 
    t = sb(s,1,0);
    uint32_t r1 = ((uint32_t)sb(s,1,1) << 24)
                | ((uint32_t)sb(s,1,2) << 16)
                | ((uint32_t)sb(s,1,3) <<  8)
                |  (uint32_t)t;
    // Row 2 
    uint32_t r2 = ((uint32_t)sb(s,2,2) << 24)
                | ((uint32_t)sb(s,2,3) << 16)
                | ((uint32_t)sb(s,2,0) <<  8)
                |  (uint32_t)sb(s,2,1);
    // Row 3 
    uint32_t r3 = ((uint32_t)sb(s,3,3) << 24)
                | ((uint32_t)sb(s,3,0) << 16)
                | ((uint32_t)sb(s,3,1) <<  8)
                |  (uint32_t)sb(s,3,2);
    // Row 0 
    uint32_t r0 = ((uint32_t)sb(s,0,0) << 24)
                | ((uint32_t)sb(s,0,1) << 16)
                | ((uint32_t)sb(s,0,2) <<  8)
                |  (uint32_t)sb(s,0,3);

    for (int c = 0; c < 4; ++c) {
        s[c] = ((r0 >> (24 - 8*c)) & 0xffu) << 24
             | ((r1 >> (24 - 8*c)) & 0xffu) << 16
             | ((r2 >> (24 - 8*c)) & 0xffu) <<  8
             | ((r3 >> (24 - 8*c)) & 0xffu);
    }
}

// MixColumns &5.1.3 
static void mix_columns(State s)
{
    for (int c = 0; c < 4; ++c) {
        uint8_t s0 = (uint8_t)(s[c] >> 24);
        uint8_t s1 = (uint8_t)(s[c] >> 16);
        uint8_t s2 = (uint8_t)(s[c] >>  8);
        uint8_t s3 = (uint8_t)(s[c]);

        uint8_t n0 = (uint8_t)(xtime(s0)  ^ gmul(3,s1) ^ s2         ^ s3       );
        uint8_t n1 = (uint8_t)(s0         ^ xtime(s1)  ^ gmul(3,s2) ^ s3      );
        uint8_t n2 = (uint8_t)(s0         ^ s1         ^ xtime(s2)  ^ gmul(3,s3));
        uint8_t n3 = (uint8_t)(gmul(3,s0) ^ s1         ^ s2         ^ xtime(s3));

        s[c] = ((uint32_t)n0 << 24)
             | ((uint32_t)n1 << 16)
             | ((uint32_t)n2 << 8)
             |  (uint32_t)n3;
    }
}

// AddRoundKey &5.1.4 
static void add_round_key(State s, const uint32_t *roundKey)
{
    for (int c = 0; c < 4; ++c)
        s[c] ^= roundKey[c];
}

// InvSubBytes &5.3.2 
static void inv_sub_bytes(State s)
{
    for (int c = 0; c < 4; ++c) {
        s[c] = ((uint32_t)SBOX_INV[(s[c] >> 24)] << 24)
             | ((uint32_t)SBOX_INV[(s[c] >> 16) & 0xffu] << 16)
             | ((uint32_t)SBOX_INV[(s[c] >> 8) & 0xffu] <<  8)
             |  (uint32_t)SBOX_INV[(s[c]) & 0xffu];
    }
}

// InvShiftRows &5.3.1 — shift right instead of left 
static void inv_shift_rows(State s)
{
    uint32_t r0 = ((uint32_t)sb(s,0,0) << 24)
                | ((uint32_t)sb(s,0,1) << 16)
                | ((uint32_t)sb(s,0,2) << 8)
                |  (uint32_t)sb(s,0,3);
    uint32_t r1 = ((uint32_t)sb(s,1,3) << 24)
                | ((uint32_t)sb(s,1,0) << 16)
                | ((uint32_t)sb(s,1,1) << 8)
                |  (uint32_t)sb(s,1,2);
    uint32_t r2 = ((uint32_t)sb(s,2,2) << 24)
                | ((uint32_t)sb(s,2,3) << 16)
                | ((uint32_t)sb(s,2,0) << 8)
                |  (uint32_t)sb(s,2,1);
    uint32_t r3 = ((uint32_t)sb(s,3,1) << 24)
                | ((uint32_t)sb(s,3,2) << 16)
                | ((uint32_t)sb(s,3,3) << 8)
                |  (uint32_t)sb(s,3,0);

    for (int c = 0; c < 4; ++c) {
        s[c] = ((r0 >> (24 - 8*c)) & 0xffu) << 24
             | ((r1 >> (24 - 8*c)) & 0xffu) << 16
             | ((r2 >> (24 - 8*c)) & 0xffu) << 8
             | ((r3 >> (24 - 8*c)) & 0xffu);
    }
}

// InvMixColumns &5.3.3 
static void inv_mix_columns(State s)
{
    for (int c = 0; c < 4; ++c) {
        uint8_t s0 = (uint8_t)(s[c] >> 24);
        uint8_t s1 = (uint8_t)(s[c] >> 16);
        uint8_t s2 = (uint8_t)(s[c] >> 8);
        uint8_t s3 = (uint8_t)(s[c]);

        uint8_t n0 = (uint8_t)(gmul(0x0e,s0) ^ gmul(0x0b,s1) ^ gmul(0x0d,s2) ^ gmul(0x09,s3));
        uint8_t n1 = (uint8_t)(gmul(0x09,s0) ^ gmul(0x0e,s1) ^ gmul(0x0b,s2) ^ gmul(0x0d,s3));
        uint8_t n2 = (uint8_t)(gmul(0x0d,s0) ^ gmul(0x09,s1) ^ gmul(0x0e,s2) ^ gmul(0x0b,s3));
        uint8_t n3 = (uint8_t)(gmul(0x0b,s0) ^ gmul(0x0d,s1) ^ gmul(0x09,s2) ^ gmul(0x0e,s3));

        s[c] = ((uint32_t)n0 << 24)
             | ((uint32_t)n1 << 16)
             | ((uint32_t)n2 << 8)
             |  (uint32_t)n3;
    }
}

// Cipher (FIPS 197 &5.1) and Inverse Cipher (&5.3)
void aes_encrypt_block(const AesCtx *ctx, uint8_t out[AES_BLOCK_SIZE], const uint8_t in [AES_BLOCK_SIZE])
{
    State s;
    bytes_to_state(s, in);

    add_round_key(s, ctx->roundKey);

    for (uint8_t round = 1; round < ctx->numRounds; ++round) {
        sub_bytes(s);
        shift_rows(s);
        mix_columns(s);
        add_round_key(s, ctx->roundKey + 4u * round);
    }

    // Final round — no MixColumns. 
    sub_bytes(s);
    shift_rows(s);
    add_round_key(s, ctx->roundKey + 4u * ctx->numRounds);

    state_to_bytes(out, s);
}

void aes_decrypt_block(const AesCtx *ctx, uint8_t out[AES_BLOCK_SIZE], const uint8_t in [AES_BLOCK_SIZE])
{
    State s;
    bytes_to_state(s, in);

    add_round_key(s, ctx->roundKey + 4u * ctx->numRounds);

    for (uint8_t round = ctx->numRounds - 1u; round >= 1u; --round) {
        inv_shift_rows(s);
        inv_sub_bytes(s);
        add_round_key(s, ctx->roundKey + 4u * round);
        inv_mix_columns(s);
    }

    // Final round — no InvMixColumns. 
    inv_shift_rows(s);
    inv_sub_bytes(s);
    add_round_key(s, ctx->roundKey);

    state_to_bytes(out, s);
}
