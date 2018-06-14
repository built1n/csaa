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

/* guaranteed to be zero */
static const struct hash_t hash_null = { { 0 } };

bool encloses(int b, int bprime, int a);
bool hash_equals(hash_t a, hash_t b);
bool is_zero(hash_t u);

hash_t hash_node(const struct iomt_node *node);
hash_t hash_xor(hash_t a, hash_t b);
void hash_zero(hash_t *h);

hash_t sha256(const void *data, size_t datalen);
hash_t hmac_sha256(const void *data, size_t datalen, const void *key, size_t keylen);

hash_t merkle_compute(hash_t node, const hash_t *comp, const int *orders, size_t n);
hash_t merkle_parent(hash_t u, hash_t v, int order);

/* Calculate the indicies of the complementary nodes to a
 * leaf. `leafidx' is 0 for the rightmost leaf node. This function
 * will return an array with a length equal to the number of levels in
 * the tree minus one (the root is not a complentary node). The 0th
 * element of the returned array will be the index of the immediate
 * sibling, while the 1st element will be the index of the
 * complementary node one level above the leaf node, and so on. Note
 * that logleaves = log2(nleaves). If `orders' is not NULL, the
 * function will additionally allocate an array of `logleaves' *
 * sizeof(int) with each element representing whether each
 * complementary node is a left or right child. */
int *merkle_complement(int leafidx, int logleaves, int **orders);
int *merkle_complement_orders(int leafidx, int logleaves);

/* Return an array of indices of tree nodes that are dependent on a
 * given leaf node. Will be ordered from nearest relative to root. */
int *merkle_dependents(int leafidx, int logleaves);

int bintree_parent(int idx);
int bintree_sibling(int idx);

uint64_t hash_to_u64(hash_t h);
void dump_hash(hash_t u);

#endif
