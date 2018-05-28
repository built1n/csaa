/* An implementation of the trusted module T as described in Mohanty
 * et al. As this code is to execute on a general-purpose computer, no
 * guarantees can be made as to the tamper-resistance of the module,
 * but instead this serves as a proof-of-concept. */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include "crypto.h"
#include "trusted_module.h"

struct trusted_module {
    hash_t root; /* root of IOMT */

    /* shared secret with user */
    const char *key;
    size_t keylen;

    /* secret for signing self-certificates */
    char secret[32];
};

static hash_t hmac_sha256(const char *data, size_t datalen, const char *key, size_t keylen)
{
    hash_t h;
    HMAC(EVP_sha256(), key, keylen, data, datalen, h.hash, NULL);
    return h;
}

static hash_t sha256(const char *data, size_t datalen)
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

struct trusted_module *tm_new(const char *key, size_t keylen)
{
    struct trusted_module *tm = calloc(1, sizeof(struct trusted_module));

    if(!RAND_bytes(tm->secret, 32))
    {
        free(tm);
        return NULL;
    }

    tm->key = key;
    tm->keylen = keylen;

    memset(tm->secret, 0, sizeof(tm->secret));
    memset(tm->root.hash, 0, sizeof(tm->root.hash));

    return tm;
}

/* NOTE: we fail to distinguish between intermediate and leaf
 * nodes, making a second-preimage attack possible */
/* order: 0: u is left, v is right, 1: u is right, v is left */
static hash_t merkle_parent(hash_t u, hash_t v, int order)
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
static hash_t merkle_compute(hash_t node, hash_t *comp, int *orders, size_t n)
{
    hash_t parent = node;
    for(size_t i = 0; i < n; ++i)
        parent = merkle_parent(comp[i], parent, orders[i]);

    return parent;
}

void check(int condition)
{
    printf(condition ? "PASS\n" : "FAIL\n");
}

/* self-test */
void tm_test(void)
{
    /* test merkle tree with zeros */
    hash_t zero1, zero2;
    memset(zero1.hash, 0, sizeof(zero1.hash));
    memset(zero2.hash, 0, sizeof(zero2.hash));
    int orders[] = { 0 };

    /* this should return zero */
    hash_t res1 = merkle_compute(zero1, &zero2, orders, 1);
    printf("is_zero(res1) = %d\n", is_zero(res1));
    check(is_zero(res1));

    hash_t a = sha256("a", 1);
    hash_t b = sha256("b", 1);
    hash_t c = sha256("c", 1);
    hash_t d = sha256("d", 1);
    hash_t cd = merkle_parent(c, d, 0);
    dump_hash(cd);
    char buf[64];
    memcpy(buf, c.hash, 32);
    memcpy(buf + 32, d.hash, 32);
    dump_hash(sha256(buf, 64));
    check(hash_equals(sha256(buf, 64), cd));

    hash_t a_comp[] = { b, cd };
    int a_orders[] = { 1, 1 };
    hash_t root1 = merkle_compute(a, a_comp, a_orders, 2);

    hash_t ab = merkle_parent(a, b, 0);
    hash_t root2 = merkle_parent(ab, cd, 0);
    dump_hash(root1);
    dump_hash(root2);
    check(hash_equals(root1, root2));
}
