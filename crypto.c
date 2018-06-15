#include "crypto.h"
#include "test.h"

#include <string.h>

#include <openssl/hmac.h>
#include <openssl/sha.h>

/* return true iff [b, bprime] encloses a */
bool encloses(uint64_t b, uint64_t bprime, uint64_t a)
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
int *merkle_complement_ordersonly(int leafidx, int logleaves)
{
    int *orders;
    free(merkle_complement(leafidx, logleaves, &orders));
    return orders;
}

/* Index-Ordered Merkle Tree routines: */
/* Calculate the value of all the nodes of the tree, given the IOMT
 * leaves in mt_leaves. Leaf count *must* be an integer power of two,
 * otherwise bad things will happen. This function should only need to
 * be called once, namely when the service provider is created. */
void iomt_fill(struct iomt *tree)
{
    for(int i = 0; i < tree->mt_leafcount; ++i)
    {
        uint64_t mt_idx = (1 << tree->mt_logleaves) - 1 + i;
        tree->mt_nodes[mt_idx] = hash_node(tree->mt_leaves + i);
    }
    /* now loop up from the bottom level, calculating the parent of
     * each pair of nodes */
    for(int i = tree->mt_logleaves - 1; i >= 0; --i)
    {
        uint64_t baseidx = (1 << i) - 1;
        for(int j = 0; j < (1 << i); ++j)
        {
            uint64_t mt_idx = baseidx + j;
            tree->mt_nodes[mt_idx] = merkle_parent(tree->mt_nodes[2 * mt_idx + 1],
                                                 tree->mt_nodes[2 * mt_idx + 2],
                                                 0);
        }
    }
}

/* A bit of a hack: our complement calculation returns the *indices*
 * complementary nodes, which is good because the indices are much
 * smaller than the actual nodes (which are 32 bytes each with
 * SHA-256). However, the trusted module requires an array of the
 * actual hash values of the complementary nodes. It would be optimal
 * to modify each function to take the array of all nodes in the tree
 * in addition to the complement indices, but this function will serve
 * as a shim in the meantime. */
hash_t *lookup_nodes(const hash_t *nodes, const int *indices, int n)
{
    hash_t *ret = calloc(n, sizeof(hash_t));
    for(int i = 0; i < n; ++i)
        ret[i] = nodes[indices[i]];
    return ret;
}

void restore_nodes(hash_t *nodes, const int *indices, const hash_t *values, int n)
{
    for(int i = 0; i < n; ++i)
        nodes[indices[i]] = values[i];
}

/* Update mt_nodes to reflect a change to a leaf node's
 * value. Optionally, if old_dep is not NULL, *old_dep will be made to
 * point to an array of length mt_logleaves that contains the old node
 * values (whose indices are returned by merkle_dependents()). */
void merkle_update(struct iomt *tree, uint64_t leafidx, hash_t newval, hash_t **old_dep)
{
    if(old_dep)
        *old_dep = calloc(tree->mt_logleaves, sizeof(hash_t));

    uint64_t idx = (1 << tree->mt_logleaves) - 1 + leafidx;

    tree->mt_nodes[idx] = newval;
    for(int i = 0; i < tree->mt_logleaves; ++i)
    {
        /* find the merkle parent of the two children first */
        hash_t parent = merkle_parent(tree->mt_nodes[idx],
                                      tree->mt_nodes[bintree_sibling(idx)],
                                      (idx + 1) & 1);

        idx = bintree_parent(idx);

        /* save old value */
        if(old_dep)
            (*old_dep)[i] = tree->mt_nodes[idx];

        tree->mt_nodes[idx] = parent;
    }
}

/* find a node with given idx */
struct iomt_node *lookup_leaf(struct iomt *tree, int idx)
{
    for(int i = 0; i < tree->mt_leafcount; ++i)
        if(idx == tree->mt_leaves[i].idx)
            return tree->mt_leaves + i;
    return NULL;
}

void iomt_update(struct iomt *tree, uint64_t idx, hash_t newval)
{
    /* update the leaf first, then use merkle_update */
    struct iomt_node *leaf = lookup_leaf(tree, idx);
    leaf->val = newval;

    merkle_update(tree, idx, hash_node(leaf), NULL);
}

/* Create a merkle tree with 2^logleaves leaves, each initialized to a
 * zero leaf (not a placeholder!) */
struct iomt *iomt_new(int logleaves)
{
    struct iomt *tree = calloc(1, sizeof(struct iomt));
    tree->mt_leafcount = 1 << logleaves;
    tree->mt_logleaves = logleaves;
    tree->mt_leaves = calloc(tree->mt_leafcount, sizeof(struct iomt_node));

    tree->mt_nodes = calloc(2 * tree->mt_leafcount - 1, sizeof(hash_t));

    return tree;
}

void iomt_free(struct iomt *tree)
{
    /* TODO */
    if(tree)
    {
    }
}

struct hashstring hash_format(hash_t h, int n)
{
    struct hashstring ret;
    for(int i = 0; i < n; ++i)
    {
        sprintf(ret.str + 2 * i, "%02x", h.hash[i]);
    }
    return ret;
}

void iomt_dump(struct iomt *tree)
{
    for(int i = 0; i < tree->mt_leafcount; ++i)
    {
        printf("(%d, %s, %d)%s",
               tree->mt_leaves[i].idx,
               hash_format(tree->mt_leaves[i].val, 4).str,
               tree->mt_leaves[i].next_idx,
               (i == tree->mt_leafcount - 1) ? "\n" : ", ");
    }
}

/* convert the first 8 bytes (little endian) to a 64-bit int */
uint64_t hash_to_u64(hash_t h)
{
    uint64_t ret = 0;
    for(int i = 0; i < 8; ++i)
        ret |= h.hash[i] << (i * 8);
    return ret;
}

hash_t u64_to_hash(uint64_t n)
{
    hash_t ret = hash_null;
    for(int i = 0; i < 8; ++i)
    {
        ret.hash[i] = n & 0xff;
        n >>= 8;
    }
    return ret;
}

void crypto_test(void)
{
    int *orders;
    int *comp = merkle_complement(6, 4, &orders);
    int correct[] = { 22, 9, 3, 2 };
    int correct_orders[] = { 1, 0, 0, 1 };
    check("Complement calculation", !memcmp(comp, correct, 4 * sizeof(int)) && !memcmp(orders, correct_orders, 4 * sizeof(int)));
    free(orders);
    free(comp);

    int *dep = merkle_dependents(6, 4);
    int correct_dep[] = { 10, 4, 1, 0 };
    check("Dependency calculation", !memcmp(dep, correct_dep, 4 * sizeof(int)));
    free(dep);
}
