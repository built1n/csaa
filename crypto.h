#ifndef CSAA_CRYPTO_H
#define CSAA_CRYPTO_H

/* we use SHA256 for h() */
typedef struct hash_t {
    /* a hash of all zeros is given a special meaning */
    unsigned char hash[32];
} hash_t;

#endif
