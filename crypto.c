#include "crypto.h"
#include "trusted_module.h"
#include "test.h"

#include <assert.h>
#include <unistd.h>
#include <string.h>

#include <sys/socket.h>

#include <openssl/aes.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

/* return true iff [b, bprime] encloses a */
bool encloses(uint64_t b, uint64_t bprime, uint64_t a)
{
    /* zero is not allowed as an index */
    if(a == 0)
        return false;
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
int *bintree_complement(int leafidx, int logleaves, int **orders)
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

hash_t *merkle_complement(const struct iomt *tree, int leafidx, int **orders)
{
    int *compidx = bintree_complement(leafidx, tree->mt_logleaves, orders);
    hash_t *comp = lookup_nodes(tree->mt_nodes, compidx, tree->mt_logleaves);
    free(compidx);
    return comp;
}

int *bintree_ancestors(int leafidx, int logleaves)
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
int *bintree_complement_ordersonly(int leafidx, int logleaves)
{
    int *orders;
    free(bintree_complement(leafidx, logleaves, &orders));
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
 * values (whose indices are returned by bintree_ancestors()). NOTE:
 * this function will NOT set the corresponding IOMT leaf; use
 * iomt_update_leaf_full for that. */
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
struct iomt_node *iomt_find_leaf(const struct iomt *tree, uint64_t idx)
{
    for(int i = 0; i < tree->mt_leafcount; ++i)
        if(idx == tree->mt_leaves[i].idx)
            return tree->mt_leaves + i;
    return NULL;
}

struct iomt_node *iomt_find_encloser(const struct iomt *tree, uint64_t idx)
{
    for(int i = 0; i < tree->mt_leafcount; ++i)
        if(encloses(tree->mt_leaves[i].idx, tree->mt_leaves[i].next_idx, idx))
            return tree->mt_leaves + i;
    return NULL;
}

struct iomt_node *iomt_find_leaf_or_encloser(const struct iomt *tree, uint64_t idx)
{
    for(int i = 0; i < tree->mt_leafcount; ++i)
    {
        if(tree->mt_leaves[i].idx == idx ||
           encloses(tree->mt_leaves[i].idx, tree->mt_leaves[i].next_idx, idx))
            return tree->mt_leaves + i;
    }
    return NULL;
}

void iomt_update(struct iomt *tree, uint64_t idx, hash_t newval)
{
    /* update the leaf first, then use merkle_update */
    struct iomt_node *leaf = iomt_find_leaf(tree, idx);
    leaf->val = newval;

    merkle_update(tree, leaf - tree->mt_leaves, hash_node(leaf), NULL);
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

struct hashstring hash_format(hash_t h, int n)
{
    struct hashstring ret;
    for(int i = 0; i < n; ++i)
    {
        sprintf(ret.str + 2 * i, "%02x", h.hash[i]);
    }
    return ret;
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

hash_t hash_increment(hash_t h)
{
    /* incredibly inefficient... FIXME! */
    return u64_to_hash(hash_to_u64(h) + 1);
}

/* simple XOR cipher, so encryption and decryption are symmetric */
hash_t crypt_secret(hash_t encrypted_secret,
                    uint64_t file_idx, uint64_t file_version,
                    const void *key, size_t keylen)
{
    hash_t pad; /* key = encrypted_secret ^ pad */
    HMAC_CTX *ctx = HMAC_CTX_new();
    HMAC_Init_ex(ctx,
                 key, keylen,
                 EVP_sha256(), NULL);

    /* potential endianness issue */
    HMAC_Update(ctx, (const unsigned char*)&file_idx, sizeof(file_idx));
    HMAC_Update(ctx, (const unsigned char*)&file_version, sizeof(file_version));

    HMAC_Final(ctx, pad.hash, NULL);
    HMAC_CTX_free(ctx);

    return hash_xor(encrypted_secret, pad);
}

/* These are all fixed-length fields, so we can safely append them and
 * forgo any HMAC. */
hash_t calc_lambda(hash_t gamma, const struct iomt *buildcode, const struct iomt *composefile, hash_t kf)
{
    hash_t buildcode_root = hash_null, composefile_root = hash_null;
    if(buildcode)
        buildcode_root = buildcode->mt_nodes[0];
    if(composefile)
        composefile_root = composefile->mt_nodes[0];

    SHA256_CTX ctx;
    hash_t h;

    SHA256_Init(&ctx);

    SHA256_Update(&ctx, gamma.hash, sizeof(gamma.hash));
    SHA256_Update(&ctx, buildcode_root.hash, sizeof(buildcode_root.hash));
    SHA256_Update(&ctx, composefile_root.hash, sizeof(composefile_root.hash));
    SHA256_Update(&ctx, kf.hash, sizeof(kf.hash));

    SHA256_Final(h.hash, &ctx);

    printf("calc_lambda: gamma = %s, kf = %s, lambda = %s\n",
           hash_format(gamma, 4).str, hash_format(kf, 4).str,
           hash_format(h, 4).str);
    return h;
}

hash_t generate_nonce(void)
{
    hash_t ret;
    if(!RAND_bytes(ret.hash, sizeof(ret.hash)))
    {
        assert(!"Failed to generate nonce");
    }
    return ret;
}

/* Derive a fixed-length key from an arbitrary-length
 * passphrase. TODO: replace with a real KDF (PBKDF2?) */
hash_t derive_key(const char *passphrase, hash_t nonce)
{
    if(!passphrase || strlen(passphrase) == 0)
        return hash_null;
    return hmac_sha256(passphrase, strlen(passphrase),
                       &nonce, sizeof(nonce));
}

hash_t calc_kf(hash_t encryption_key, uint64_t file_idx)
{
    if(is_zero(encryption_key))
        return hash_null;
    return hmac_sha256(&encryption_key, sizeof(encryption_key),
                       &file_idx, sizeof(file_idx));
}

void memxor(unsigned char *dest, const unsigned char *b, size_t len)
{
    while(len--)
        *dest++ ^= *b++;
}

/* symmetric: decryption and encryption are the same operation */
void crypt_bytes(unsigned char *data, size_t len, hash_t key)
{
    /* We use AES256 in CTR mode with a hard-coded IV. We never reuse
     * keys, as they are generated with a combination of the passphrase
     * and a nonce. Therefore, it should be reasonably safe to
     * hard-code the IV: */
    AES_KEY aes;

    AES_set_encrypt_key((void*)&key, 256, &aes);
    unsigned char block[16];

    /* We only use the first 16 bytes of the counter. */
    hash_t counter = u64_to_hash(0);

    size_t i;
    for(i = 0; i < len; i += 16, data += 16)
    {
        AES_ecb_encrypt((void*)&counter, block, &aes, AES_ENCRYPT);
        memxor(data, block, 16);
        counter = hash_increment(counter);
    }

    /* finish up */
    AES_ecb_encrypt((void*)&counter, block, &aes, AES_ENCRYPT);
    memxor(data, block, len - i);
}

/* Generate a signed acknowledgement for successful completion of a
 * request. We append a zero byte to the user request and take the
 * HMAC. */
hash_t ack_sign(const struct tm_request *req, int nzeros, const void *key, size_t keylen)
{
    HMAC_CTX *ctx = HMAC_CTX_new();
    HMAC_Init_ex(ctx,
                 key, keylen,
                 EVP_sha256(), NULL);

    HMAC_Update(ctx, (const unsigned char*)req, sizeof(*req));

    unsigned char zero = 0;
    for(int i = 0; i < nzeros; ++i)
        HMAC_Update(ctx, &zero, 1);

    hash_t hmac;
    HMAC_Final(ctx, hmac.hash, NULL);
    HMAC_CTX_free(ctx);

    return hmac;
}

bool ack_verify(const struct tm_request *req,
                const void *secret, size_t secret_len,
                hash_t hmac)
{
    hash_t correct = ack_sign(req, 1, secret, secret_len);
    return hash_equals(hmac, correct);
}

void write_to_fd(void *userdata, const void *data, size_t len)
{
    int *fdptr = userdata;
    write(*fdptr, data, len);
}


int read_from_fd(void *userdata, void *buf, size_t len)
{
    int *fdptr = userdata;
    int rc = recv(*fdptr, buf, len, MSG_WAITALL);
    if(rc != len)
    {
        printf("short read");
    }
    return rc;
}

void dump_versioninfo(const struct version_info *verinfo)
{
    printf("idx = %lu, ctr = %lu, ver = %lu, max_ver = %lu, acl = %s, lambda = %s\n",
           verinfo->idx, verinfo->counter, verinfo->version, verinfo->max_version,
           hash_format(verinfo->current_acl, 4).str,
           hash_format(verinfo->lambda, 4).str);
}

void crypto_test(void)
{
#if 1
    int *orders;
    int *comp = bintree_complement(6, 4, &orders);
    int correct[] = { 22, 9, 3, 2 };
    int correct_orders[] = { 1, 0, 0, 1 };
    check("Complement calculation", !memcmp(comp, correct, 4 * sizeof(int)) && !memcmp(orders, correct_orders, 4 * sizeof(int)));
    free(orders);
    free(comp);

    int *dep = bintree_ancestors(6, 4);
    int correct_dep[] = { 10, 4, 1, 0 };
    check("Dependency calculation", !memcmp(dep, correct_dep, 4 * sizeof(int)));
    free(dep);

    {
        /* test merkle tree with zeros */
        hash_t zero1, zero2;
        memset(zero1.hash, 0, sizeof(zero1.hash));
        memset(zero2.hash, 0, sizeof(zero2.hash));
        int orders[] = { 0 };

        /* this should return zero */
        hash_t res1 = merkle_compute(zero1, &zero2, orders, 1);
        check("Merkle parent with zeros", is_zero(res1));

        hash_t a = sha256("a", 1);
        hash_t b = sha256("b", 1);
        hash_t c = sha256("c", 1);
        hash_t d = sha256("d", 1);
        hash_t cd = merkle_parent(c, d, 0);
        //dump_hash(cd);
        char buf[64];
        memcpy(buf, c.hash, 32);
        memcpy(buf + 32, d.hash, 32);
        //dump_hash(sha256(buf, 64));
        check("Merkle parent", hash_equals(sha256(buf, 64), cd));

        hash_t a_comp[] = { b, cd };
        int a_orders[] = { 1, 1 };
        hash_t root1 = merkle_compute(a, a_comp, a_orders, 2);

        hash_t ab = merkle_parent(a, b, 0);
        hash_t root2 = merkle_parent(ab, cd, 0);
        //dump_hash(root1);
        //dump_hash(root2);
        check("Merkle compute", hash_equals(root1, root2));
    }
#endif
}
