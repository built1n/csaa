#ifndef CSAA_IOMT_H
#define CSAA_IOMT_H
#include "crypto.h"
#include <sqlite3.h>

struct iomt_node {
    uint64_t idx, next_idx; /* idx cannot be zero */
    hash_t val; /* all zero indicates placeholder */
};

/* indices cannot be zero */
static const struct iomt_node node_null = { 0, 0, { { 0 } } };

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
struct iomt {
    uint64_t mt_leafcount, mt_logleaves; /* mt_logleaves must equal 2^mt_leafcount */

    bool in_memory;

    union {
        struct {
            void *db;
            const char *nodes_table, *leaves_table;

            /* the IOMT code will use nodes with key1_name = key1_val and (if
             * not NULL) key2_name = key2_val */
            const char *key1_name, *key2_name;
            int key1_val, key2_val;

            sqlite3_stmt *getnode, *updatenode, *insertnode;
            sqlite3_stmt *getleaf, *updateleaf, *insertleaf;
            sqlite3_stmt *findleaf, *findencloser, *findleaf_or_encloser;
        } db;
        struct {
            hash_t *mt_nodes; /* this has 2 * mt_leafcount - 1 elements. Note
                               * that the bottom level consists of hashes of
                               * the leaf nodes. */

            struct iomt_node *mt_leaves;
        } mem;
    };
};

hash_t hash_node(struct iomt_node node);

hash_t *lookup_nodes(const struct iomt *tree, const uint64_t *indices, int n);
void restore_nodes(struct iomt *tree, const uint64_t *indices, const hash_t *values, int n);

hash_t *merkle_complement(const struct iomt *tree, uint64_t leafidx, int **orders);

/* This function is prefixed merkle_ because it does not know about
 * any IOMT-specific properties (though it is still passed an iomt
 * struct) */
void merkle_update(struct iomt *tree, uint64_t leafidx, hash_t newval, hash_t **old_dep);

struct iomt *iomt_new(int logleaves);
struct iomt *iomt_new_from_db(void *db,
                              const char *nodes_table, const char *leaves_table,
                              const char *key1_name, int key1_val,
                              const char *key2_name, int key2_val,
                              int logleaves);

struct iomt *iomt_dup(const struct iomt *tree);
struct iomt *iomt_dup_in_db(void *db,
                            const char *nodes_table, const char *leaves_table,
                            const char *key1_name, int key1_val,
                            const char *key2_name, int key2_val,
                            const struct iomt *oldtree);

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

void print_leaf(struct iomt_node node);
void iomt_dump(const struct iomt *tree);

hash_t iomt_getroot(const struct iomt *tree);

hash_t iomt_getnode(const struct iomt *tree, uint64_t idx);
void iomt_setnode(const struct iomt *tree, uint64_t idx, hash_t val);

struct iomt_node iomt_getleaf(const struct iomt *tree, uint64_t leafidx);

/* All linear searches... slow! */
struct iomt_node iomt_find_leaf(const struct iomt *tree, uint64_t idx, uint64_t *leafidx);
struct iomt_node iomt_find_encloser(const struct iomt *tree, uint64_t idx, uint64_t *leafidx);
struct iomt_node iomt_find_leaf_or_encloser(const struct iomt *tree, uint64_t idx, uint64_t *leafidx);
#endif
