#ifndef UTIL_H
#define UTIL_H

#include <arpa/inet.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#define RSA_PUBLIC_EXP 65537u /* fixed public exponent used by all parties */

/* Fast modular exponentiation for RSA-style operations. */
static inline unsigned long powmod(unsigned long base, unsigned long exp, unsigned long mod) {
    unsigned long result = 1 % mod;
    base %= mod;
    while (exp) {
        if (exp & 1) result = (result * base) % mod;
        base = (base * base) % mod;
        exp >>= 1;
    }
    return result;
}

/* RSA-like sign: sig = m^d mod n; we reduce message to fit modulus. */
static inline unsigned long rsa_sign(unsigned long message, unsigned long privExp, unsigned long modulus) {
    if (modulus == 0) return 0;
    return powmod(message % modulus, privExp, modulus);
}

/* RSA-like verify: check sig^e mod n == (message mod n). */
static inline int rsa_verify(unsigned long signature, unsigned long message, unsigned long pubExp, unsigned long modulus) {
    if (modulus == 0) return 0;
    unsigned long recovered = powmod(signature, pubExp, modulus);
    return recovered == (message % modulus);
}

/* Helpers for deterministic RSA-like key derivation from a password. */
static inline unsigned long gcd(unsigned long a, unsigned long b) {
    while (b) {
        unsigned long t = b;
        b = a % b;
        a = t;
    }
    return a;
}

static inline unsigned long modinv(unsigned long a, unsigned long m) {
    long t = 0, newt = 1;
    long r = (long)m, newr = (long)a;
    while (newr != 0) {
        long q = r / newr;
        long tmp = newt;
        newt = t - q * newt;
        t = tmp;
        tmp = newr;
        newr = r - q * newr;
        r = tmp;
    }
    if (r > 1) return 0;
    if (t < 0) t += m;
    return (unsigned long)t;
}

static inline int is_prime(unsigned long n) {
    if (n < 2) return 0;
    for (unsigned long i = 2; i * i <= n; ++i) {
        if (n % i == 0) return 0;
    }
    return 1;
}

static inline unsigned long next_prime(unsigned long start) {
    unsigned long p = (start < 2) ? 2 : start;
    while (!is_prime(p)) ++p;
    return p;
}

static inline unsigned long hash_password(const char *pw) {
    unsigned long h = 5381;
    int c;
    while ((c = *pw++)) {
        h = ((h << 5) + h) + (unsigned long)c;
    }
    return h;
}

/* Derive public/private key from a password (classroom stub, not secure). */
static inline void derive_keys_from_password(const char *password, unsigned int *pubKey, unsigned int *privKey) {
    unsigned long h = hash_password(password);
    unsigned long p = next_prime((h % 50000ul) + 1000ul);
    unsigned long q = next_prime(((h / 7ul) % 50000ul) + 2000ul);
    if (p == q) q = next_prime(q + 1);
    unsigned long n = p * q;
    unsigned long phi = (p - 1) * (q - 1);
    unsigned long e = RSA_PUBLIC_EXP;
    while (gcd(e, phi) != 1) {
        phi = next_prime(phi + 1);
    }
    unsigned long d = modinv(e, phi);
    if (d == 0) d = 3;
    *pubKey = (unsigned int)n;
    *privKey = (unsigned int)d;
}

/* Logging helper to print IP:port in a single buffer. */
static inline void fmt_addr(const struct sockaddr_in *addr, char *buf, size_t buflen) {
    snprintf(buf, buflen, "%s:%u", inet_ntoa(addr->sin_addr), ntohs(addr->sin_port));
}

#endif /* UTIL_H */
