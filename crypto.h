#ifndef CSAA_CRYPTO_H
#define CSAA_CRYPTO_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct tm_request;
struct version_info;

/* Various useful cryptographic functions; shared between TM and SP. */

/* we use SHA256 for h() */
typedef struct hash_t {
    /* a hash of all zeros is given a special meaning */
    unsigned char hash[32];
} hash_t;

struct iomt_node {
    uint64_t idx, next_idx; /* idx cannot be zero */
    hash_t val; /* all zero indicates placeholder */
};

struct iomt {
    int mt_leafcount, mt_logleaves; /* mt_logleaves must equal 2^mt_leafcount */

    /* Each level of the IOMT is stored sequentially from left to
     * right, top to bottom, as follows:
     *
     *  [0]: root
     *  [1]: root left child
     *  [2]: root right child
     *  [3]: left child of [1]
     *  [4]: right child of [1]
     *  [5]: left child of [2]
     *  [6]: right child of [2],
     *
     * and so on.
     */
    hash_t *mt_nodes; /* this has 2 * mt_leafcount - 1 elements. Note
                       * that the bottom level consists of hashes of
                       * the leaf nodes. */

    struct iomt_node *mt_leaves;
};

/* guaranteed to be zero */
static const struct hash_t hash_null = { { 0 } };

bool encloses(uint64_t b, uint64_t bprime, uint64_t a);
bool hash_equals(hash_t a, hash_t b);
bool is_zero(hash_t u);

hash_t hash_node(const struct iomt_node *node);
hash_t hash_xor(hash_t a, hash_t b);

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
int *bintree_complement(int leafidx, int logleaves, int **orders);
int *bintree_complement_ordersonly(int leafidx, int logleaves);

/* Return an array of indices of tree nodes that are dependent on a
 * given leaf node. Will be ordered from nearest relative to root. */
int *bintree_ancestors(int leafidx, int logleaves);

hash_t *merkle_complement(const struct iomt *tree, int leafidx, int **orders);

hash_t *lookup_nodes(const hash_t *nodes, const int *indices, int n);
void restore_nodes(hash_t *nodes, const int *indices, const hash_t *values, int n);

/* This function is prefixed merkle_ because it does not know about
 * any IOMT-specific properties (though it is still passed an iomt
 * struct) */
void merkle_update(struct iomt *tree, uint64_t leafidx, hash_t newval, hash_t **old_dep);

struct iomt *iomt_new(int logleaves);
struct iomt *iomt_dup(const struct iomt *tree);
void iomt_free(struct iomt *tree);

/* Find a leaf with IOMT index `idx' and change its value, propagating
 * up the tree. */
void iomt_update(struct iomt *tree, uint64_t idx, hash_t newval);

/* Set all the fields of a leaf node (not an IOMT index!) */
void iomt_update_leaf_full(struct iomt *tree, uint64_t leafidx,
                           uint64_t new_idx, uint64_t new_next_idx, hash_t new_val);
void iomt_update_leaf_idx(struct iomt *tree, uint64_t leafidx,
                          uint64_t new_idx);
void iomt_update_leaf_nextidx(struct iomt *tree, uint64_t leafidx,
                              uint64_t new_next_idx);
void iomt_update_leaf_hash(struct iomt *tree, uint64_t leafidx,
                           hash_t new_val);

/* Create an IOMT where the leaves are the hash of file lines */
struct iomt *iomt_from_lines(const char *filename);

void iomt_serialize(const struct iomt *tree,
                    void (*write_fn)(void *userdata, const void *data, size_t len),
                    void *userdata);

struct iomt *iomt_deserialize(int (*read_fn)(void *userdata, void *buf, size_t len),
                              void *userdata);

void iomt_fill(struct iomt *tree);
void iomt_dump(const struct iomt *tree);

hash_t iomt_getroot(const struct iomt *tree);
struct iomt_node *iomt_get_leaf_by_idx(const struct iomt *tree, uint64_t leafidx);

/* All linear searches... slow! */
struct iomt_node *iomt_find_leaf(const struct iomt *tree, uint64_t idx, uint64_t *leafidx);
struct iomt_node *iomt_find_encloser(const struct iomt *tree, uint64_t idx, uint64_t *leafidx);
struct iomt_node *iomt_find_leaf_or_encloser(const struct iomt *tree, uint64_t idx, uint64_t *leafidx);

int bintree_parent(int idx);
int bintree_sibling(int idx);

uint64_t hash_to_u64(hash_t h);
hash_t u64_to_hash(uint64_t n);
void dump_hash(hash_t u);

struct hashstring {
    char str[32 * 2 + 1];
};

struct hashstring hash_format(hash_t h, int n);

hash_t crypt_secret(hash_t encrypted_secret,
                    uint64_t file_idx, uint64_t file_version,
                    const void *key, size_t keylen);

hash_t calc_lambda(hash_t gamma, const struct iomt *buildcode, const struct iomt *composefile, hash_t kf);

/* Generate a signed acknowledgement for successful completion of a
 * request. We append a zero byte to the user request and take the
 * HMAC. */
hash_t ack_sign(const struct tm_request *req, int nzeros, const void *key, size_t keylen);
bool ack_verify(const struct tm_request *req,
                const void *secret, size_t secret_len,
                hash_t hmac);

void write_to_fd(void *userdata, const void *data, size_t len);
int read_from_fd(void *userdata, void *buf, size_t len);

void dump_versioninfo(const struct version_info *verinfo);

void crypt_bytes(unsigned char *data, size_t len, hash_t key);
hash_t generate_nonce(void);
hash_t derive_key(const char *passphrase, hash_t nonce);
hash_t calc_kf(hash_t encryption_key, uint64_t file_idx);

/* self-test */
void crypto_test(void);
#endif
