#include "crypto.h"

#include <string.h>

#include <openssl/hmac.h>
#include <openssl/sha.h>

/* return true iff [b, bprime] encloses a */
bool encloses(int b, int bprime, int a)
{
    return (b < a && a < bprime) || (bprime <= b && b < a) || (a < bprime && bprime <= b);
}

hash_t hash_node(const struct iomt_node *node)
{
    return sha256(node, sizeof(*node));
}

hash_t hmac_sha256(const void *data, size_t datalen, const void *key, size_t keylen)
{
    hash_t h;
    HMAC(EVP_sha256(), key, keylen, data, datalen, h.hash, NULL);
    return h;
}

hash_t sha256(const void *data, size_t datalen)
{
    hash_t h;
    SHA256(data, datalen, h.hash);
    return h;
}

bool is_zero(hash_t u)
{
    /* constant-time comparison */
    volatile char c = 0;
    for(int i = 0; i < 32; ++i)
        c |= u.hash[i];

    return c == 0;
}

void dump_hash(hash_t u)
{
    for(int i = 0; i < 32; ++i)
        printf("%02x", u.hash[i]);
    printf("\n");
}

bool hash_equals(hash_t a, hash_t b)
{
    return !memcmp(a.hash, b.hash, 32);
}

hash_t hash_xor(hash_t a, hash_t b)
{
    for(int i = 0; i < 32; ++i)
        a.hash[i] ^= b.hash[i];
    return a;
}

void hash_zero(hash_t *h)
{
    for(int i = 0; i < 32; ++i)
        h->hash[i] = 0;
}

/* NOTE: we fail to distinguish between intermediate and leaf
 * nodes, making a second-preimage attack possible */
/* order: 0: u is left, v is right, 1: u is right, v is left */
hash_t merkle_parent(hash_t u, hash_t v, int order)
{
    if(is_zero(u))
        return v;
    if(is_zero(v))
        return u;

    /* append and hash */
    SHA256_CTX ctx;
    hash_t h;

    SHA256_Init(&ctx);

    if(order != 0)
        SHA256_Update(&ctx, v.hash, 32);

    SHA256_Update(&ctx, u.hash, 32);

    if(order == 0)
        SHA256_Update(&ctx, v.hash, 32);

    SHA256_Final(h.hash, &ctx);

    return h;
}

/* Calculate the root of a Merkle tree given the leaf node v, and n
 * complementary nodes, ordered from the closest node (the sibling
 * leaf node at the bottom of the tree) to most distant (the opposite
 * half of the tree). orders[i] represents whether each complementarty
 * node is a left or right child, which is necessary to compute the
 * proper hash value at each stage. This is the f_bt() algorithm
 * described in Mohanty et al. */

/* orders: 0 indiciates that the complementary node is LEFT child, 1:
 * node is RIGHT child */
hash_t merkle_compute(hash_t node, const hash_t *comp, const int *orders, size_t n)
{
    hash_t parent = node;
    for(size_t i = 0; i < n; ++i)
        parent = merkle_parent(comp[i], parent, orders[i]);

    return parent;
}

/* Given a node's index, return the index of the parent in an array
 * representation of a binary tree. */
int bintree_parent(int idx)
{
    return (idx - ((idx & 1) ? 1 : 2)) / 2;
}

int bintree_sibling(int idx)
{
    return idx + ((idx & 1) ? 1 : -1);
}

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
int *merkle_complement(int leafidx, int logleaves, int **orders)
{
    int *comp = calloc(logleaves, sizeof(int));
    if(orders)
        *orders = calloc(logleaves, sizeof(int));

    /* true index of leaf */
    int idx = (1 << logleaves) - 1 + leafidx;

    /* progress up the tree */
    for(int i = 0; i < logleaves; ++i)
    {
        /* output index of sibling node */
        comp[i] = bintree_sibling(idx);

        /* we really don't need the orders array */
        if(orders)
            (*orders)[i] = idx & 1;

        /* find parent index and loop */
        idx = bintree_parent(idx);
    }

    return comp;
}

int *merkle_dependents(int leafidx, int logleaves)
{
    int *dep = calloc(logleaves, sizeof(int));

    int idx = (1 << logleaves) - 1 + leafidx;
    for(int i = 0; i < logleaves; ++i)
    {
        idx = bintree_parent(idx);
        dep[i] = idx;
    }

    return dep;
}

/* Shim to get only the orders */
int *merkle_complement_orders(int leafidx, int logleaves)
{
    int *orders;
    free(merkle_complement(leafidx, logleaves, &orders));
    return orders;
}

/* convert the first 8 bytes (little endian) to a 64-bit int */
uint64_t hash_to_u64(hash_t h)
{
    uint64_t ret = 0;
    for(int i = 0; i < 8; ++i)
        ret |= h.hash[i] << (i * 8);
    return ret;
}
