#include "rng.h"

/* Windows: BCryptGenRandom */
#if defined(_WIN32)

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>

int rng_fill(void *buf, size_t len)
{
    uint8_t *out_ptr = buf;
    while (len > 0) {
        ULONG chunk_len = (len > 0xffffffffu) ? 0xffffffffu : (ULONG)len;
        if (!BCRYPT_SUCCESS(BCryptGenRandom(nullptr, out_ptr, chunk_len, BCRYPT_USE_SYSTEM_PREFERRED_RNG))) {
            return -1;
        }
        out_ptr += chunk_len;
        len -= chunk_len;
    }
    return 0;
}

/* Linux: getrandom */
#elif defined(__linux__)

#include <sys/random.h>
#include <errno.h>

int rng_fill(void *buf, size_t len)
{
    uint8_t *out_ptr = buf;
    while (len > 0) {
        size_t chunk_len = (len > 256u) ? 256u : len;
        ssize_t read_len;
        do {
            read_len = getrandom(out_ptr, chunk_len, 0);
        } while (read_len == -1 && errno == EINTR);
        if (read_len <= 0) {
            return -1;
        }
        out_ptr += (size_t)read_len;
        len -= (size_t)read_len;
    }
    return 0;
}

/* macOS / FreeBSD / OpenBSD: getentropy */
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__)

#include <unistd.h> 

int rng_fill(void *buf, size_t len)
{
    uint8_t *out_ptr = buf;
    while (len > 0) {
        size_t chunk_len = (len > 256u) ? 256u : len;
        if (getentropy(out_ptr, chunk_len) != 0) {
            return -1;
        }
        out_ptr += chunk_len;
        len -= chunk_len;
    }
    return 0;
}

#else
#error "Unsupported platform: no secure RNG backend available."
#endif
