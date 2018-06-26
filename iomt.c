#include "iomt.h"
#include "crypto.h"

#include <string.h>

#include <openssl/hmac.h>
#include <openssl/sha.h>

hash_t hash_node(const struct iomt_node *node)
{
    return sha256(node, sizeof(*node));
}

/* internal nodes only */
hash_t iomt_getnode(const struct iomt *tree, int idx)
{
    if(tree->in_memory)
        return tree->mt_nodes[idx];
}

void iomt_setnode(const struct iomt *tree, int idx, hash_t val)
{
    if(tree->in_memory)
        tree->mt_nodes[idx] = val;
}

struct iomt_node iomt_getleaf(const struct iomt *tree, uint64_t leafidx)
{
    if(tree->in_memory)
        return tree->mt_leaves[leafidx];
}

void iomt_setleaf(struct iomt *tree, uint64_t leafidx, struct iomt_node val)
{
    if(tree->in_memory)
        tree->mt_leaves[leafidx] = val;
}

hash_t *merkle_complement(const struct iomt *tree, int leafidx, int **orders)
{
    int *compidx = bintree_complement(leafidx, tree->mt_logleaves, orders);
    hash_t *comp = lookup_nodes(tree->mt_nodes, compidx, tree->mt_logleaves);
    free(compidx);
    return comp;
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
        iomt_setnode(tree, mt_idx, hash_node(tree->mt_leaves + i));
    }
    /* now loop up from the bottom level, calculating the parent of
     * each pair of nodes */
    for(int i = tree->mt_logleaves - 1; i >= 0; --i)
    {
        uint64_t baseidx = (1 << i) - 1;
        for(int j = 0; j < (1 << i); ++j)
        {
            uint64_t mt_idx = baseidx + j;
            iomt_setnode(tree, mt_idx, merkle_parent(iomt_getnode(tree, 2 * mt_idx + 1),
                                                     iomt_getnode(tree, 2 * mt_idx + 2),
                                                     0));
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
 * values (whose indices are returned by bintree_ancestors()). NOTE:
 * this function will NOT set the corresponding IOMT leaf; use
 * iomt_update_leaf_full for that. */
void merkle_update(struct iomt *tree, uint64_t leafidx, hash_t newval, hash_t **old_dep)
{
    if(old_dep)
        *old_dep = calloc(tree->mt_logleaves, sizeof(hash_t));

    uint64_t idx = (1 << tree->mt_logleaves) - 1 + leafidx;

    iomt_setnode(tree, idx, newval);
    for(int i = 0; i < tree->mt_logleaves; ++i)
    {
        /* find the merkle parent of the two children first */
        hash_t parent = merkle_parent(iomt_getnode(tree, idx),
                                      iomt_getnode(tree, bintree_sibling(idx)),
                                      (idx + 1) & 1);

        idx = bintree_parent(idx);

        /* save old value */
        if(old_dep)
            (*old_dep)[i] = iomt_getnode(tree, mt_nodes[idx]);

        tree->mt_nodes[idx] = parent;
    }
}

hash_t iomt_getroot(const struct iomt *tree)
{
    return tree->mt_nodes[0];
}

/* find a node with given idx */
struct iomt_node *iomt_find_leaf(const struct iomt *tree, uint64_t idx, uint64_t *leafidx)
{
    for(int i = 0; i < tree->mt_leafcount; ++i)
        if(idx == tree->mt_leaves[i].idx)
        {
            if(leafidx)
                *leafidx = i;
            return tree->mt_leaves + i;
        }
    return NULL;
}

struct iomt_node *iomt_find_encloser(const struct iomt *tree, uint64_t idx, uint64_t *leafidx)
{
    for(int i = 0; i < tree->mt_leafcount; ++i)
        if(encloses(tree->mt_leaves[i].idx, tree->mt_leaves[i].next_idx, idx))
        {
            if(leafidx)
                *leafidx = i;
            return tree->mt_leaves + i;
        }
    return NULL;
}

struct iomt_node *iomt_find_leaf_or_encloser(const struct iomt *tree, uint64_t idx, uint64_t *leafidx)
{
    for(int i = 0; i < tree->mt_leafcount; ++i)
    {
        if(tree->mt_leaves[i].idx == idx ||
           encloses(tree->mt_leaves[i].idx, tree->mt_leaves[i].next_idx, idx))
        {
            if(leafidx)
                *leafidx = i;
            return tree->mt_leaves + i;
        }
    }
    return NULL;
}

void iomt_update(struct iomt *tree, uint64_t idx, hash_t newval)
{
    /* update the leaf first, then use merkle_update */
    uint64_t leafidx;
    struct iomt_node *leaf = iomt_find_leaf(tree, idx, &leafidx);
    leaf->val = newval;

    merkle_update(tree, leafidx, hash_node(leaf), NULL);
}

void iomt_update_leaf_full(struct iomt *tree, uint64_t leafidx,
                           uint64_t new_idx, uint64_t new_next_idx, hash_t new_val)
{
    struct iomt_node *leaf = tree->mt_leaves + leafidx;
    leaf->idx = new_idx;
    leaf->next_idx = new_next_idx;
    leaf->val = new_val;

    merkle_update(tree, leafidx, hash_node(leaf), NULL);
}

void iomt_update_leaf_idx(struct iomt *tree, uint64_t leafidx,
                          uint64_t new_idx)
{
    struct iomt_node *leaf = tree->mt_leaves + leafidx;
    leaf->idx = new_idx;

    merkle_update(tree, leafidx, hash_node(leaf), NULL);
}

void iomt_update_leaf_nextidx(struct iomt *tree, uint64_t leafidx,
                              uint64_t new_next_idx)
{
    struct iomt_node *leaf = tree->mt_leaves + leafidx;
    leaf->next_idx = new_next_idx;

    merkle_update(tree, leafidx, hash_node(leaf), NULL);
}

void iomt_update_leaf_hash(struct iomt *tree, uint64_t leafidx,
                           hash_t new_val)
{
    struct iomt_node *leaf = tree->mt_leaves + leafidx;
    leaf->val = new_val;

    merkle_update(tree, leafidx, hash_node(leaf), NULL);
}

/* Create a merkle tree with 2^logleaves leaves, each initialized to a
 * zero leaf (not a placeholder!) */
struct iomt *iomt_new(int logleaves)
{
    struct iomt *tree = calloc(1, sizeof(struct iomt));

    tree->in_memory = true;

    tree->mt_leafcount = 1 << logleaves;
    tree->mt_logleaves = logleaves;
    tree->mt_leaves = calloc(tree->mt_leafcount, sizeof(struct iomt_node));

    tree->mt_nodes = calloc(2 * tree->mt_leafcount - 1, sizeof(hash_t));

    return tree;
}

struct iomt *iomt_dup(const struct iomt *tree)
{
    if(!tree)
        return NULL;
    struct iomt *newtree = calloc(1, sizeof(struct iomt));
    newtree->mt_leafcount = tree->mt_leafcount;
    newtree->mt_logleaves = tree->mt_logleaves;

    newtree->mt_leaves = calloc(tree->mt_leafcount, sizeof(struct iomt_node));
    memcpy(newtree->mt_leaves, tree->mt_leaves, tree->mt_leafcount * sizeof(struct iomt_node));

    newtree->mt_nodes = calloc(2 * tree->mt_leafcount - 1, sizeof(hash_t));
    memcpy(newtree->mt_nodes, tree->mt_nodes, (2 * tree->mt_leafcount - 1) * sizeof(hash_t));

    return newtree;
}

/* TODO: error checking */
uint64_t read_u64(int (*read_fn)(void *userdata, void *buf, size_t len), void *userdata)
{
    uint64_t n;
    if(read_fn(userdata, &n, sizeof(n)) != sizeof(n))
    {
        printf("short read\n");
        return 0;
    }
    return n;
}

void write_u64(void (*write_fn)(void *userdata, const void *data, size_t len),
               void *userdata, uint64_t n)
{
    write_fn(userdata, &n, sizeof(n));
}

#define IOMT_EMPTY (uint64_t)0xFFFFFFFFFFFFFFFFUL

void iomt_serialize(const struct iomt *tree,
                    void (*write_fn)(void *userdata, const void *data, size_t len),
                    void *userdata)
{
    /* leafcount isn't needed */
    if(tree)
    {
        write_u64(write_fn, userdata, tree->mt_logleaves);

        write_fn(userdata, tree->mt_nodes, sizeof(hash_t) * (2 * tree->mt_leafcount - 1));
        write_fn(userdata, tree->mt_leaves, sizeof(struct iomt_node) * tree->mt_leafcount);
    }
    else
        write_u64(write_fn, userdata, IOMT_EMPTY);
}

struct iomt *iomt_deserialize(int (*read_fn)(void *userdata, void *buf, size_t len),
                              void *userdata)
{
    uint64_t logleaves = read_u64(read_fn, userdata);

    if(logleaves == IOMT_EMPTY)
        return NULL;

    struct iomt *tree = iomt_new(logleaves);

    read_fn(userdata, tree->mt_nodes, sizeof(hash_t) * (2 * tree->mt_leafcount - 1));
    read_fn(userdata, tree->mt_leaves, sizeof(struct iomt_node) * tree->mt_leafcount);

    return tree;
}

void iomt_free(struct iomt *tree)
{
    if(tree)
    {
        free(tree->mt_nodes);
        free(tree->mt_leaves);
        free(tree);
    }
}

/* arbitrary */
#define FILELINES_LOGLEAVES 10

struct iomt *iomt_from_lines(const char *filename)
{
    if(!filename)
        return NULL;

    struct iomt *tree = iomt_new(FILELINES_LOGLEAVES);

    FILE *f = fopen(filename, "r");

    SHA256_CTX ctx;
    SHA256_Init(&ctx);

    int c;
    uint64_t line = 0;

    do
    {
        c = fgetc(f);

        char ch = c;

        if(c != EOF)
            SHA256_Update(&ctx, &ch, sizeof(ch));

        if(ch == '\n' || c == EOF)
        {
            hash_t linehash;
            SHA256_Final(linehash.hash, &ctx);

            /* set this leaf to loop around */
            iomt_update_leaf_full(tree, line, line + 1, 1, linehash);

            if(line > 0)
            {
                /* make previously inserted leaf point to this leaf */
                iomt_update_leaf_nextidx(tree, line - 1, line + 1);
            }

            line++;

            /* re-initialize for next line */
            SHA256_Init(&ctx);
        }
    } while(c != EOF);

    fclose(f);

    return tree;
}

void iomt_dump(const struct iomt *tree)
{
    if(tree)
    {
        for(int i = 0; i < tree->mt_leafcount; ++i)
        {
            printf("(%lu, %s, %lu)%s",
                   tree->mt_leaves[i].idx,
                   hash_format(tree->mt_leaves[i].val, 4).str,
                   tree->mt_leaves[i].next_idx,
                   (i == tree->mt_leafcount - 1) ? "\n" : ", ");
        }
    }
    else
        printf("(empty IOMT)\n");
}
