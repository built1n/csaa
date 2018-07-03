#include "iomt.h"
#include "crypto.h"

#include <assert.h>
#include <string.h>

#include <openssl/hmac.h>
#include <openssl/sha.h>

#include <sqlite3.h>

hash_t hash_node(const struct iomt_node node)
{
    return sha256(&node, sizeof(node));
}

static void reset_and_bind(const struct iomt *tree, sqlite3_stmt *st)
{
    sqlite3_reset(st);
    if(tree->db.key1_name)
    {
        sqlite3_bind_int(st, 1, tree->db.key1_val);
    }
    if(tree->db.key2_name)
    {
        sqlite3_bind_int(st, 2, tree->db.key2_val);
    }
}

/* internal nodes only */
hash_t iomt_getnode(const struct iomt *tree, uint64_t idx)
{
    if(tree->in_memory)
        return tree->mem.mt_nodes[idx];
    else
    {
        sqlite3_stmt *st = tree->db.getnode;

        reset_and_bind(tree, st);

        sqlite3_bind_int64(st, 3, idx);

        int rc = sqlite3_step(st);
        if(rc == SQLITE_ROW)
        {
            hash_t ret;
            memcpy(&ret, sqlite3_column_blob(st, 0), sizeof(ret));

            return ret;
        }
        else
        {
            return hash_null;
        }
    }
}

void iomt_setnode(const struct iomt *tree, uint64_t idx, hash_t val)
{
    if(tree->in_memory)
        tree->mem.mt_nodes[idx] = val;
    else
    {
        //printf("Setting node idx = %d in %s\n", idx, tree->db.nodes_table);

        sqlite3 *handle = tree->db.db;

        sqlite3_stmt *st = tree->db.updatenode;
        reset_and_bind(tree, st);

        sqlite3_bind_blob(st, 3, &val, sizeof(val), SQLITE_TRANSIENT);

        sqlite3_bind_int64(st, 4, idx);

        int rc = sqlite3_step(st);

        int changes = sqlite3_changes(handle);

        /* Failure, likely because node doesn't exist */
        if(rc != SQLITE_DONE || !changes)
        {
            st = tree->db.insertnode;
            reset_and_bind(tree, st);

            sqlite3_bind_int64(st, 3, idx);
            sqlite3_bind_blob(st, 4, &val, sizeof(val), SQLITE_TRANSIENT);

            if(sqlite3_step(st) != SQLITE_DONE)
            {
                //printf("Failed 1: %s\n", sqlite3_errmsg(tree->db.db));
            }
        }
        else
        {
            //printf("Successfully updated node %d\n", idx);
        }
    }
}

struct iomt_node iomt_getleaf(const struct iomt *tree, uint64_t leafidx)
{
    if(tree->in_memory)
        return tree->mem.mt_leaves[leafidx];
    else
    {
        sqlite3_stmt *st = tree->db.getleaf;
        reset_and_bind(tree, st);

        sqlite3_bind_int64(st, 3, leafidx);

        int rc = sqlite3_step(st);
        if(rc == SQLITE_ROW)
        {
            struct iomt_node ret;

            ret.idx = sqlite3_column_int64(st, 0);
            ret.next_idx = sqlite3_column_int64(st, 1);
            memcpy(&ret.val, sqlite3_column_blob(st, 2), sizeof(ret.val));

            return ret;
        }
        else
        {
            //printf("Failed 2: %s\n", sqlite3_errmsg(tree->db.db));
            //printf("Failed to look up leaf %lu in %s\n", leafidx, tree->db.leaves_table);
            return node_null;
        }
    }
}

void iomt_setleaf(struct iomt *tree, uint64_t leafidx, struct iomt_node val)
{
    if(tree->in_memory)
        tree->mem.mt_leaves[leafidx] = val;
    else
    {
        //printf("Setting leaf idx = %lu in %s\n", leafidx, tree->db.leaves_table);

        sqlite3 *handle = tree->db.db;

        sqlite3_stmt *st = tree->db.updateleaf;
        reset_and_bind(tree, st);

        sqlite3_bind_int64(st, 3, val.idx);
        sqlite3_bind_int64(st, 4, val.next_idx);
        sqlite3_bind_blob(st, 5, &val.val, sizeof(val.val), SQLITE_TRANSIENT);

        sqlite3_bind_int64(st, 6, leafidx);

        int rc = sqlite3_step(st);

        int changes = sqlite3_changes(handle);

        /* Failure, likely because node doesn't exist */
        if(rc != SQLITE_DONE || !changes)
        {
            st = tree->db.insertleaf;
            reset_and_bind(tree, st);

            sqlite3_bind_int64(st, 3, leafidx);
            sqlite3_bind_int64(st, 4, val.idx);
            sqlite3_bind_int64(st, 5, val.next_idx);
            sqlite3_bind_blob(st, 6, &val.val, sizeof(val.val), SQLITE_TRANSIENT);

            if(sqlite3_step(st) != SQLITE_DONE)
            {
                printf("Failed 3: %s\n", sqlite3_errmsg(handle));
            }

            //printf("Successfully inserted (%s)\n", sqlite3_errmsg(handle));
        }
    }
}

hash_t *merkle_complement(const struct iomt *tree, uint64_t leafidx, int **orders)
{
    uint64_t *compidx = bintree_complement(leafidx, tree->mt_logleaves, orders);
    hash_t *comp = lookup_nodes(tree, compidx, tree->mt_logleaves);
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
    for(uint64_t i = 0; i < tree->mt_leafcount; ++i)
    {
        uint64_t mt_idx = ((uint64_t)1 << tree->mt_logleaves) - 1 + i;
        iomt_setnode(tree, mt_idx, hash_node(iomt_getleaf(tree, i)));
    }
    /* now loop up from the bottom level, calculating the parent of
     * each pair of nodes */
    for(int i = tree->mt_logleaves - 1; i >= 0; --i)
    {
        uint64_t baseidx = ((uint64_t)1 << i) - 1;
        for(uint64_t j = 0; j < ((uint64_t)1 << i); ++j)
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
hash_t *lookup_nodes(const struct iomt *tree, const uint64_t *indices, int n)
{
    hash_t *ret = calloc(n, sizeof(hash_t));
    for(int i = 0; i < n; ++i)
        ret[i] = iomt_getnode(tree, indices[i]);
    return ret;
}

void restore_nodes(struct iomt *tree, const uint64_t *indices, const hash_t *values, int n)
{
    for(int i = 0; i < n; ++i)
        iomt_setnode(tree, indices[i], values[i]);
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

    uint64_t idx = ((uint64_t)1 << tree->mt_logleaves) - 1 + leafidx;

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
            (*old_dep)[i] = iomt_getnode(tree, idx);

        iomt_setnode(tree, idx, parent);
    }
}

hash_t iomt_getroot(const struct iomt *tree)
{
    if(tree)
        return iomt_getnode(tree, 0);
    return hash_null;
}

/* find a node with given idx */
/* TODO: replace with database update */
struct iomt_node iomt_find_leaf(const struct iomt *tree, uint64_t idx, uint64_t *leafidx)
{
    if(tree->in_memory)
    {
        for(uint64_t i = 0; i < tree->mt_leafcount; ++i)
            if(idx == iomt_getleaf(tree, i).idx)
            {
                if(leafidx)
                    *leafidx = i;
                return iomt_getleaf(tree, i);
            }
        return node_null;
    }
    else
    {
        sqlite3_stmt *st = tree->db.findleaf;
        reset_and_bind(tree, st);

        sqlite3_bind_int64(st, 3, idx);

        if(sqlite3_step(st) == SQLITE_ROW)
        {
            if(leafidx)
                *leafidx = sqlite3_column_int64(st, 0);
            struct iomt_node ret;
            ret.idx = idx;
            ret.next_idx = sqlite3_column_int64(st, 1);
            memcpy(&ret.val, sqlite3_column_blob(st, 2), sizeof(ret.val));

            return ret;
        }
        return node_null;
    }
}

struct iomt_node iomt_find_encloser(const struct iomt *tree, uint64_t idx, uint64_t *leafidx)
{
    if(tree->in_memory)
    {
        for(uint64_t i = 0; i < tree->mt_leafcount; ++i)
            if(encloses(iomt_getleaf(tree, i).idx, iomt_getleaf(tree, i).next_idx, idx))
            {
                if(leafidx)
                    *leafidx = i;
                return iomt_getleaf(tree, i);
            }
        return node_null;
    }
    else
    {
        sqlite3_stmt *st = tree->db.findencloser;
        reset_and_bind(tree, st);

        sqlite3_bind_int64(st, 3, idx);

        if(sqlite3_step(st) == SQLITE_ROW)
        {
            if(leafidx)
                *leafidx = sqlite3_column_int64(st, 0);
            struct iomt_node ret;
            ret.idx = sqlite3_column_int64(st, 1);
            ret.next_idx = sqlite3_column_int64(st, 2);
            memcpy(&ret.val, sqlite3_column_blob(st, 3), sizeof(ret.val));

            return ret;
        }
        return node_null;
    }
}

struct iomt_node iomt_find_leaf_or_encloser(const struct iomt *tree, uint64_t idx, uint64_t *leafidx)
{
    if(tree->in_memory)
    {
        for(uint64_t i = 0; i < tree->mt_leafcount; ++i)
        {
            if(iomt_getleaf(tree, i).idx == idx ||
               encloses(iomt_getleaf(tree, i).idx, iomt_getleaf(tree, i).next_idx, idx))
            {
                if(leafidx)
                    *leafidx = i;
                return iomt_getleaf(tree, i);
            }
        }
        return node_null;
    }
    else
    {
        sqlite3_stmt *st = tree->db.findleaf_or_encloser;
        reset_and_bind(tree, st);

        sqlite3_bind_int64(st, 3, idx);

        if(sqlite3_step(st) == SQLITE_ROW)
        {
            if(leafidx)
                *leafidx = sqlite3_column_int64(st, 0);
            struct iomt_node ret;
            ret.idx = sqlite3_column_int64(st, 1);
            ret.next_idx = sqlite3_column_int64(st, 2);
            memcpy(&ret.val, sqlite3_column_blob(st, 3), sizeof(ret.val));

            return ret;
        }
        return node_null;
    }
}

void iomt_update(struct iomt *tree, uint64_t idx, hash_t newval)
{
    /* update the leaf first, then use merkle_update */
    uint64_t leafidx = 0;
    struct iomt_node leaf = iomt_find_leaf(tree, idx, &leafidx);
    leaf.val = newval;
    iomt_setleaf(tree, leafidx, leaf);

    merkle_update(tree, leafidx, hash_node(leaf), NULL);
}

void iomt_update_leaf_full(struct iomt *tree, uint64_t leafidx,
                           uint64_t new_idx, uint64_t new_next_idx, hash_t new_val)
{
    struct iomt_node leaf = (struct iomt_node) { new_idx, new_next_idx, new_val };
    iomt_setleaf(tree, leafidx, leaf);

    merkle_update(tree, leafidx, hash_node(leaf), NULL);
}

void iomt_update_leaf_idx(struct iomt *tree, uint64_t leafidx,
                          uint64_t new_idx)
{
    struct iomt_node leaf = iomt_getleaf(tree, leafidx);
    leaf.idx = new_idx;

    iomt_setleaf(tree, leafidx, leaf);

    merkle_update(tree, leafidx, hash_node(leaf), NULL);
}

void iomt_update_leaf_nextidx(struct iomt *tree, uint64_t leafidx,
                              uint64_t new_next_idx)
{
    struct iomt_node leaf = iomt_getleaf(tree, leafidx);
    leaf.next_idx = new_next_idx;

    iomt_setleaf(tree, leafidx, leaf);

    merkle_update(tree, leafidx, hash_node(leaf), NULL);
}

void iomt_update_leaf_hash(struct iomt *tree, uint64_t leafidx,
                           hash_t new_val)
{
    struct iomt_node leaf = iomt_getleaf(tree, leafidx);
    leaf.val = new_val;

    iomt_setleaf(tree, leafidx, leaf);

    merkle_update(tree, leafidx, hash_node(leaf), NULL);
}

/* Create a merkle tree with 2^logleaves leaves, each initialized to a
 * zero leaf (not a placeholder!) */
struct iomt *iomt_new(int logleaves)
{
    struct iomt *tree = calloc(1, sizeof(struct iomt));

    tree->in_memory = true;

    tree->mt_leafcount = (uint64_t)1 << logleaves;
    tree->mt_logleaves = logleaves;
    tree->mem.mt_leaves = calloc(tree->mt_leafcount, sizeof(struct iomt_node));

    tree->mem.mt_nodes = calloc(2 * tree->mt_leafcount - 1, sizeof(hash_t));

    return tree;
}

/* Assumes `buf' is large enough */
static void generate_and_clauses(const struct iomt *tree, char *buf)
{
    buf[0] = '\0';

    if(tree->db.key1_name)
        buf += sprintf(buf, " AND %s = ?1", tree->db.key1_name);
    if(tree->db.key2_name)
        buf += sprintf(buf, " AND %s = ?2", tree->db.key2_name);
}

/* returns one of the following:
   "" - no keys
   ", key1" - key1 only
   ", key2" - key2 only
   ", key1, key2" - both
*/
static void generate_key_list(const struct iomt *tree, char *buf)
{
    buf[0] = '\0';

    if(tree->db.key1_name)
        buf += sprintf(buf, ", %s", tree->db.key1_name);
    if(tree->db.key2_name)
        buf += sprintf(buf, ", %s", tree->db.key2_name);
}

/* returns one of the following:
   "" - no keys
   ", key1" - key1 only
   ", key2" - key2 only
   ", key1, key2" - both
*/
static void generate_placeholder_list(const struct iomt *tree, char *buf)
{
    buf[0] = '\0';

    if(tree->db.key1_name)
        buf += sprintf(buf, ", ?1");
    if(tree->db.key2_name)
        buf += sprintf(buf, ", ?2");
}

struct iomt *iomt_new_from_db(void *db,
                              const char *nodes_table, const char *leaves_table,
                              const char *key1_name, int key1_val,
                              const char *key2_name, int key2_val,
                              int logleaves)
{
    struct iomt *tree = calloc(1, sizeof(struct iomt));

    tree->in_memory = false;

    tree->mt_leafcount = (uint64_t)1 << logleaves;
    tree->mt_logleaves = logleaves;

    tree->db.db = db;
    tree->db.nodes_table = nodes_table;
    tree->db.leaves_table = leaves_table;
    tree->db.key1_name = key1_name;
    tree->db.key1_val = key1_val;
    tree->db.key2_name = key2_name;
    tree->db.key2_val = key2_val;

    /* compile statements now to save time */
    char sql[1000];
    char and_clauses[1000], key_list[1000], placeholder_list[1000];

    generate_and_clauses(tree, and_clauses);
    generate_key_list(tree, key_list);
    generate_placeholder_list(tree, placeholder_list);

    sprintf(sql, "SELECT Val FROM %s WHERE NodeIdx = ?3%s;",
             tree->db.nodes_table,
             and_clauses);
    sqlite3_prepare_v2(db, sql, -1, &tree->db.getnode, 0);

    sprintf(sql, "UPDATE %s SET Val = ?3 WHERE NodeIdx = ?4%s;",
             tree->db.nodes_table,
             and_clauses);
    sqlite3_prepare_v2(db, sql, -1, &tree->db.updatenode, 0);

    sprintf(sql, "INSERT INTO %s ( NodeIdx, Val%s ) VALUES ( ?3, ?4%s );",
             tree->db.nodes_table,
             key_list,
             placeholder_list);
    sqlite3_prepare_v2(db, sql, -1, &tree->db.insertnode, 0);

    sprintf(sql, "SELECT Idx, NextIdx, Val FROM %s WHERE LeafIdx = ?3%s;",
             tree->db.leaves_table,
             and_clauses);
    sqlite3_prepare_v2(db, sql, -1, &tree->db.getleaf, 0);

    sprintf(sql, "UPDATE %s SET Idx = ?3, NextIdx = ?4, Val = ?5 WHERE LeafIdx = ?6%s;",
             tree->db.leaves_table,
             and_clauses);
    sqlite3_prepare_v2(db, sql, -1, &tree->db.updateleaf, 0);

    sprintf(sql, "INSERT INTO %s ( LeafIdx, Idx, NextIdx, Val%s ) VALUES ( ?3, ?4, ?5, ?6%s );",
             tree->db.leaves_table,
             key_list,
             placeholder_list);
    sqlite3_prepare_v2(db, sql, -1, &tree->db.insertleaf, 0);

    sprintf(sql, "SELECT LeafIdx, NextIdx, Val FROM %s WHERE Idx = ?3%s;",
             tree->db.leaves_table,
             and_clauses);
    sqlite3_prepare_v2(db, sql, -1, &tree->db.findleaf, 0);

    sprintf(sql, "SELECT LeafIdx, Idx, NextIdx, Val FROM %s WHERE ( ( Idx < ?3 AND ?3 < NextIdx ) OR ( NextIdx < Idx AND Idx < ?3 ) OR ( ?3 < NextIdx AND NextIdx < Idx ) )%s;",
             tree->db.leaves_table,
             and_clauses);
    sqlite3_prepare_v2(db, sql, -1, &tree->db.findencloser, 0);

    sprintf(sql, "SELECT LeafIdx, Idx, NextIdx, Val FROM %s WHERE ( ( Idx < ?3 AND ?3 < NextIdx ) OR ( NextIdx < Idx AND Idx < ?3 ) OR ( ?3 < NextIdx AND NextIdx < Idx ) OR ( Idx = ?3 ) )%s;",
             tree->db.leaves_table,
             and_clauses);
    sqlite3_prepare_v2(db, sql, -1, &tree->db.findleaf_or_encloser, 0);

    return tree;
}

/* make a copy of the IOMT with database backing (there will be no
 * pointer semantics between the two trees when this function
 * returns) */
struct iomt *iomt_dup_in_db(void *db,
                            const char *nodes_table, const char *leaves_table,
                            const char *key1_name, int key1_val,
                            const char *key2_name, int key2_val,
                            const struct iomt *oldtree)
{
    struct iomt *newtree = iomt_new_from_db(db, nodes_table, leaves_table,
                                            key1_name, key1_val,
                                            key2_name, key2_val,
                                            oldtree->mt_logleaves);

    /* copy nodes, leaves (we do not recalculate the tree) */
    for(uint64_t i = 0; i < newtree->mt_leafcount; ++i)
        iomt_setleaf(newtree, i, iomt_getleaf(oldtree, i));

    for(uint64_t i = 0; i < 2 * newtree->mt_leafcount - 1; ++i)
        iomt_setnode(newtree, i, iomt_getnode(oldtree, i));

    return newtree;
}

/* produces a new IOMT with no relation with the old one (no pointer
 * semantics) */
struct iomt *iomt_dup(const struct iomt *oldtree)
{
    if(!oldtree)
        return NULL;

    struct iomt *newtree = calloc(1, sizeof(struct iomt));
    newtree->mt_leafcount = oldtree->mt_leafcount;
    newtree->mt_logleaves = oldtree->mt_logleaves;

    newtree->in_memory = true;
    newtree->mem.mt_leaves = calloc(oldtree->mt_leafcount, sizeof(struct iomt_node));
    newtree->mem.mt_nodes = calloc(2 * oldtree->mt_leafcount - 1, sizeof(hash_t));

    if(oldtree->in_memory)
    {
        memcpy(newtree->mem.mt_leaves, oldtree->mem.mt_leaves, oldtree->mt_leafcount * sizeof(struct iomt_node));
        memcpy(newtree->mem.mt_nodes, oldtree->mem.mt_nodes, (2 * oldtree->mt_leafcount - 1) * sizeof(hash_t));
    }
    else
    {
        /* copy nodes, leaves (we do not recalculate the tree) */
        for(uint64_t i = 0; i < newtree->mt_leafcount; ++i)
            iomt_setleaf(newtree, i, iomt_getleaf(oldtree, i));

        for(uint64_t i = 0; i < 2 * newtree->mt_leafcount - 1; ++i)
            iomt_setnode(newtree, i, iomt_getnode(oldtree, i));
    }

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

        if(tree->in_memory)
            write_fn(userdata, tree->mem.mt_leaves, sizeof(struct iomt_node) * tree->mt_leafcount);
        else
        {
            for(uint64_t i = 0; i < tree->mt_leafcount; ++i)
            {
                struct iomt_node node = iomt_getleaf(tree, i);
                write_fn(userdata, &node, sizeof(node));
            }
        }
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

    read_fn(userdata, tree->mem.mt_leaves, sizeof(struct iomt_node) * tree->mt_leafcount);

    iomt_fill(tree);

    return tree;
}

void iomt_free(struct iomt *tree)
{
    if(tree)
    {
        if(tree->in_memory)
        {
            free(tree->mem.mt_nodes);
            free(tree->mem.mt_leaves);
        }
        else
        {
            sqlite3_finalize(tree->db.getnode);
            sqlite3_finalize(tree->db.updatenode);
            sqlite3_finalize(tree->db.insertnode);
            sqlite3_finalize(tree->db.getleaf);
            sqlite3_finalize(tree->db.updateleaf);
            sqlite3_finalize(tree->db.insertleaf);
            sqlite3_finalize(tree->db.findleaf);
            sqlite3_finalize(tree->db.findencloser);
            sqlite3_finalize(tree->db.findleaf_or_encloser);
        }
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
        for(uint64_t i = 0; i < tree->mt_leafcount; ++i)
        {
            struct iomt_node node = iomt_getleaf(tree, i);
            printf("(%lu, %s, %lu)%s",
                   node.idx,
                   hash_format(node.val, 4).str,
                   node.next_idx,
                   (i == tree->mt_leafcount - 1) ? "\n" : ", ");
        }
    }
    else
        printf("(null IOMT)\n");
}
