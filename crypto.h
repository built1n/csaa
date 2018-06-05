#ifndef CSAA_CRYPTO_H
#define CSAA_CRYPTO_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Various useful cryptographic functions; shared between TM and SP. */

/* we use SHA256 for h() */
typedef struct hash_t {
    /* a hash of all zeros is given a special meaning */
    unsigned char hash[32];
} hash_t;

struct iomt_node {
    int idx, next_idx; /* idx cannot be zero */
    hash_t val; /* all zero indicates placeholder */
};
bool encloses(int b, int bprime, int a);
bool hash_equals(hash_t a, hash_t b);
bool is_zero(hash_t u);

hash_t hash_node(const struct iomt_node *node);
hash_t hash_xor(hash_t a, hash_t b);

hash_t sha256(const void *data, size_t datalen);
hash_t hmac_sha256(const void *data, size_t datalen, const void *key, size_t keylen);

hash_t merkle_compute(hash_t node, const hash_t *comp, const int *orders, size_t n);
hash_t merkle_parent(hash_t u, hash_t v, int order);

uint64_t hash_to_u64(hash_t h); 
void dump_hash(hash_t u);

#endif
