#include "rng.h"

// Windows - BCryptGenRandom
#if defined(_WIN32)

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>

int rng_fill(void *buf, size_t len)
{
    // BCryptGenRandom accepts ULONG; call in 4 GiB-sized chunks to be safe.
    uint8_t *p = buf;
    while (len > 0) {
        ULONG chunk = (len > 0xffffffffu) ? 0xffffffffu : (ULONG)len;
        if (!BCRYPT_SUCCESS(BCryptGenRandom(nullptr, p, chunk, BCRYPT_USE_SYSTEM_PREFERRED_RNG)))
            return -1;
        p += chunk;
        len -= chunk;
    }
    return 0;
}

// Linux - getrandom(2)
#elif defined(__linux__)

#include <sys/random.h>
#include <errno.h>

int rng_fill(void *buf, size_t len)
{
    uint8_t *p = buf;
    while (len > 0) {
        size_t chunk = (len > 256u) ? 256u : len; // limited to 256 to match document
        ssize_t n;
        do {
            n = getrandom(p, chunk, 0);
        } while (n == -1 && errno == EINTR);
        if (n <= 0) return -1;
        p += (size_t)n;
        len -= (size_t)n;
    }
    return 0;
}

// macOS / FreeBSD / OpenBSD - getentropy(2)
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__)

#include <unistd.h> 

int rng_fill(void *buf, size_t len)
{
    uint8_t *p = buf;
    while (len > 0) {
        size_t chunk = (len > 256u) ? 256u : len; // limited to 256 to match document
        if (getentropy(p, chunk) != 0) return -1;
        p += chunk;
        len -= chunk;
    }
    return 0;
}

#else
#error "Unsupported platform: no secure RNG backend available."
#endif
