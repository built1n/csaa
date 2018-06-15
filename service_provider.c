/* implementation of a basic service provider for use with the trusted
 * module */

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "crypto.h"
#include "helper.h"
#include "service_provider.h"
#include "trusted_module.h"

struct file_version {
    hash_t kf; /* HMAC(key, file_idx) */
    hash_t l; /* HMAC(h(encrypted contents), kf) */
    hash_t encrypted_secret; /* XOR'd with HMAC(kf, module secret) */

    struct tm_cert vr_cert; /* VR certificate */
    hash_t vr_hmac;

    void *contents;
    size_t len;
};

struct file_record {
    uint64_t idx;
    uint64_t version;
    uint64_t counter;

    struct iomt_node *acl_leaves;
    int acl_nleaves;

    struct tm_cert fr_cert; /* issued by module */
    hash_t fr_hmac;

    struct file_version *versions;
    int nversions;
};

struct service_provider {
    struct trusted_module *tm;

    /* stored in sorted order; eventually a hash table would be
     * wise */
    struct file_record *records;
    size_t nrecords;

    struct iomt_node *mt_leaves; /* leaves of CDI-IOMT, value is counter */
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
};

/* A bit of a hack: our complement calculation returns the *indices*
 * complementary nodes, which is good because the indices are much
 * smaller than the actual nodes (which are 32 bytes each with
 * SHA-256). However, the trusted module requires an array of the
 * actual hash values of the complementary nodes. It would be optimal
 * to modify each function to take the array of all nodes in the tree
 * in addition to the complement indices, but this function will serve
 * as a shim in the meantime. */
static hash_t *lookup_nodes(const hash_t *nodes, const int *indices, int n)
{
    hash_t *ret = calloc(n, sizeof(hash_t));
    for(int i = 0; i < n; ++i)
        ret[i] = nodes[indices[i]];
    return ret;
}

static void restore_nodes(hash_t *nodes, const int *indices, const hash_t *values, int n)
{
    for(int i = 0; i < n; ++i)
        nodes[indices[i]] = values[i];
}

/* Update mt_nodes to reflect a change to a leaf node's
 * value. Optionally, if old_dep is not NULL, *old_dep will be made to
 * point to an array of length mt_logleaves that contains the old node
 * values (whose indices are returned by merkle_dependents()). Untested. */
static void update_tree(struct service_provider *sp, uint64_t leafidx, hash_t newval,
                        hash_t **old_dep)
{
    if(old_dep)
        *old_dep = calloc(sp->mt_logleaves, sizeof(hash_t));

    uint64_t idx = (1 << sp->mt_logleaves) - 1 + leafidx;

    sp->mt_nodes[idx] = newval;
    for(int i = 0; i < sp->mt_logleaves; ++i)
    {
        /* find the merkle parent of the two children first */
        hash_t parent = merkle_parent(sp->mt_nodes[idx],
                                      sp->mt_nodes[bintree_sibling(idx)],
                                      (idx + 1) & 1);

        idx = bintree_parent(idx);

        /* save old value */
        if(old_dep)
            (*old_dep)[i] = sp->mt_nodes[idx];

        sp->mt_nodes[idx] = parent;
    }
}

/* Generate an EQ certificate for inserting a placeholder with index
 * placeholder_idx, given an encloser (which must actually enclose
 * a). Note: this function will modify the *mt_nodes array to reflect
 * the modification of the encloser node. However, it will restore the
 * original values before returning. This function belongs in here
 * service_provider.c and not helper.c since it directly accesses
 * service-provider specific functionality. */

/* NOTE: encloser_leafidx is *NOT* the index in the merkle tree leaf
 * node. It is the 0-based index of the POSITION of the leaf node,
 * counting from the leftmost leaf. */
struct tm_cert cert_eq(struct service_provider *sp,
                       const struct iomt_node *encloser,
                       uint64_t encloser_leafidx,
                       uint64_t placeholder_leafidx, uint64_t placeholder_nodeidx,
                       hash_t *hmac_out)
{
    assert(encloses(encloser->idx, encloser->next_idx, placeholder_nodeidx));

    struct iomt_node encloser_mod = *encloser;
    encloser_mod.next_idx = placeholder_nodeidx;

    struct iomt_node insert;
    insert.idx = placeholder_nodeidx;
    insert.next_idx = encloser->next_idx;
    insert.val = hash_null;

    hash_t h_enc    = hash_node(encloser);
    hash_t h_encmod = hash_node(&encloser_mod);

    hash_t h_ins = hash_node(&insert);

    int *orders_enc, *orders_ins;
    int *compidx_enc = merkle_complement(encloser_leafidx, sp->mt_logleaves, &orders_enc);
    int *compidx_ins = merkle_complement(placeholder_leafidx, sp->mt_logleaves, &orders_ins);

    hash_t *comp_enc = lookup_nodes(sp->mt_nodes, compidx_enc, sp->mt_logleaves);

    /* we need two NU certificates */
    hash_t nu1_hmac, nu2_hmac;

    struct tm_cert nu1 = tm_cert_node_update(sp->tm,
                                             h_enc, h_encmod,
                                             comp_enc, orders_enc, sp->mt_logleaves,
                                             &nu1_hmac);

    /* We now update the ancestors of the encloser node. */
    hash_t *old_depvalues;
    update_tree(sp, encloser_leafidx, h_encmod, &old_depvalues);

    hash_t *comp_ins = lookup_nodes(sp->mt_nodes, compidx_ins, sp->mt_logleaves);

    struct tm_cert nu2 = tm_cert_node_update(sp->tm,
                                             hash_null, h_ins,
                                             comp_ins, orders_ins, sp->mt_logleaves,
                                             &nu2_hmac);

    /* restore the tree */
    int *dep_indices = merkle_dependents(encloser_leafidx, sp->mt_logleaves);
    restore_nodes(sp->mt_nodes,  dep_indices, old_depvalues, sp->mt_logleaves);

    return tm_cert_equiv(sp->tm, &nu1, nu1_hmac, &nu2, nu2_hmac, encloser, placeholder_nodeidx, hmac_out);
}

/* Calculate the value of all the nodes of the tree, given the IOMT
 * leaves in mt_leaves. Leaf count *must* be an integer power of two,
 * otherwise bad things will happen. This function should only need to
 * be called once, namely when the service provider is created. */
static void fill_tree(struct service_provider *sp)
{
    for(int i = 0; i < sp->mt_leafcount; ++i)
    {
        uint64_t mt_idx = (1 << sp->mt_logleaves) - 1 + i;
        sp->mt_nodes[mt_idx] = hash_node(sp->mt_leaves + i);
    }
    /* now loop up from the bottom level, calculating the parent of
     * each pair of nodes */
    for(int i = sp->mt_logleaves - 1; i >= 0; --i)
    {
        uint64_t baseidx = (1 << i) - 1;
        for(int j = 0; j < (1 << i); ++j)
        {
            uint64_t mt_idx = baseidx + j;
            sp->mt_nodes[mt_idx] = merkle_parent(sp->mt_nodes[2 * mt_idx + 1],
                                                 sp->mt_nodes[2 * mt_idx + 2],
                                                 0);
        }
    }
}

/* in trusted_module.c */
void check(int condition);

/* leaf count will be 2^logleaves */
struct service_provider *sp_new(const void *key, size_t keylen, int logleaves)
{
    assert(logleaves > 0);
    struct service_provider *sp = calloc(1, sizeof(*sp));

    sp->tm = tm_new(key, keylen);

    sp->mt_leafcount = 1 << logleaves;
    sp->mt_logleaves = logleaves;
    sp->mt_leaves = calloc(sp->mt_leafcount, sizeof(struct iomt_node));

    sp->mt_nodes = calloc(2 * sp->mt_leafcount - 1, sizeof(hash_t));

    /* The trusted module initializes itself with a single placeholder
     * node (1,0,1). We first update our list of IOMT leaves. Then we
     * insert our desired number of nodes by using EQ certificates to
     * update the internal IOMT root. Note that leaf indices are
     * 1-indexed. */
    sp->mt_leaves[0] = (struct iomt_node) { 1, 1, hash_null };
    update_tree(sp, 0, hash_node(sp->mt_leaves + 0), NULL);

    for(int i = 1; i < sp->mt_leafcount; ++i)
    {
        /* generate EQ certificate */
        hash_t hmac;
        struct tm_cert eq = cert_eq(sp, sp->mt_leaves + i - 1,
                                    i - 1,
                                    i, i + 1,
                                    &hmac);
        assert(eq.type == EQ);

        /* update previous leaf's index */
        sp->mt_leaves[i - 1].next_idx = i + 1;
        update_tree(sp, i - 1, hash_node(sp->mt_leaves + i - 1), NULL);

        sp->mt_leaves[i] = (struct iomt_node) { i + 1, 1, hash_null };
        update_tree(sp, i, hash_node(sp->mt_leaves + i), NULL);

        assert(tm_set_equiv_root(sp->tm, &eq, hmac));
    }

    /* loop around */
#if 0
    hash_t hmac;
    struct tm_cert eq = cert_eq(sp, sp->mt_leaves + sp->mt_leafcount - 2,
                                sp->mt_leafcount - 2,
                                sp->mt_leafcount - 1, sp->mt_leafcount,
                                &hmac);
    assert(eq.type == EQ);

    tm_set_equiv_root(sp->tm, &eq, hmac);

    sp->mt_leaves[sp->mt_leafcount - 1] = (struct iomt_node) { sp->mt_leafcount, 1, hash_null };
    update_tree(sp, sp->mt_leafcount - 1, hash_node(sp->mt_leaves + sp->mt_leafcount - 1), NULL);
#endif

    /* We shouldn't need this; the incremental update_tree() calls
     * should give the same result. */
    //fill_tree(sp);

    /* everything else is already zeroed by calloc */
    return sp;
}

/* linear search for record given idx */
static struct file_record *lookup_record(struct service_provider *sp, int idx)
{
    for(int i = 0; i < sp->nrecords; ++i)
        if(idx == sp->records[i].idx)
            return sp->records + i;
    return NULL;
}

/* Should we insert sorted (for O(logn) lookup), or just at the end to
 * avoid copying (O(n) lookup, O(1) insertion)? Probably better to use a hash
 * table. */

/* We do not check to ensure that there are no duplicate file indices;
 * this is up to the caller */
static void append_record(struct service_provider *sp, const struct file_record *rec)
{
    sp->records = realloc(sp->records, sizeof(struct file_record) * ++sp->nrecords);
    sp->records[sp->nrecords - 1] = *rec;
}

static void append_version(struct file_record *rec, const struct file_version *ver)
{
    rec->versions = realloc(rec->versions, sizeof(struct file_version) * ++rec->nversions);
    rec->versions[rec->nversions - 1] = *ver;
}

/* This does the majority of the work that actually modifies or
 * creates a file. It expects a filled and signed user_request
 * structure, req, and will return the resulting FR certificate and
 * its signature in *hmac_out. Additionally, the module's
 * authenticated acknowledgement (equal to HMAC(req | 0), where |
 * indicates concatenation) is output in *ack_hmac_out.
 *
 * If the request is to modify the file, the parameters
 * encrypted_secret, kf, encrypted_contents, and contents_len are used
 * (otherwise they are ignored). `encrypted_secret' should be the file
 * encryption key XOR'd with HMAC(file index | file counter,
 * user_key). kf should be HMAC(encryption secret, file index).
 */
struct tm_cert sp_request(struct service_provider *sp,
                          const struct user_request *req, hash_t req_hmac,
                          hash_t *hmac_out,
                          struct tm_cert *vr_out, hash_t *vr_hmac_out,
                          hash_t *ack_hmac_out,
                          hash_t encrypted_secret, hash_t kf,
                          const void *encrypted_contents,
                          size_t contents_len)
{
    struct tm_cert vr = cert_null;
    hash_t vr_hmac, ack_hmac, fr_hmac;
    vr_hmac = ack_hmac = fr_hmac = hash_null;

    /* execute the request */
    struct tm_cert fr = tm_request(sp->tm, req, req_hmac, &fr_hmac, &vr, &vr_hmac, &ack_hmac);

    /* now update our databases based on the result */
    if(fr.type == FR)
    {
        /* update the corresponding file record */
        struct file_record *rec = lookup_record(sp, fr.fr.idx);
        bool need_insert = false;
        if(!rec)
        {
            rec = calloc(1, sizeof(struct file_record));
            need_insert = true;
        }

        rec->counter = fr.fr.counter;
        rec->fr_cert = fr;
        rec->fr_hmac = fr_hmac;

        if(rec->version != fr.fr.version)
        {
            rec->version = fr.fr.version;

            struct file_version ver;
            hash_t gamma = sha256(encrypted_contents, contents_len);
            ver.l = hmac_sha256(&gamma, sizeof(gamma),
                                &kf, sizeof(kf));

            if(!is_zero(encrypted_secret) && !is_zero(kf))
            {
                /* File is encrypted */
                ver.encrypted_secret = tm_verify_and_encrypt_secret(sp->tm,
                                                                    rec->idx, rec->counter,
                                                                    req->user_id,
                                                                    encrypted_secret, kf);
                assert(!is_zero(ver.encrypted_secret));

                /* We have no way of verifying that kf=HMAC(encryption
                 * secret, file index) ourselves; instead we rely on the
                 * module to do so for us. */
                ver.kf = kf;
            }
            else
            {
                ver.encrypted_secret = hash_null;
            }

            ver.vr_cert = vr;
            ver.vr_hmac = vr_hmac;

            append_version(rec, &ver);
        }

        if(need_insert)
        {
            append_record(sp, rec);

            /* append_record will make a copy */
            free(rec);
        }

        /* update our tree */
        sp->mt_leaves[req->idx - 1].val = u64_to_hash(fr.fr.counter);
    }

    /* return values to caller */
    if(hmac_out)
        *hmac_out = fr_hmac;
    if(vr_out)
        *vr_out = vr;
    if(vr_hmac_out)
        *vr_hmac_out = vr_hmac;
    if(ack_hmac_out)
        *ack_hmac_out = ack_hmac;

    return fr;
}

void sp_test(void)
{
    /* 2^10 = 1024 leaves ought to be enough for anybody */
    int logleaves = 4;
    struct service_provider *sp = sp_new("a", 1, logleaves);

    /* construct a request to create a file */
    printf("File creation: ");
    int *file_compidx, *file_orders;
    file_compidx = merkle_complement(0, sp->mt_logleaves, &file_orders);

    hash_t *file_comp = lookup_nodes(sp->mt_nodes, file_compidx, sp->mt_logleaves);

    struct user_request req = req_filecreate(sp->tm, 1,
                                             sp->mt_leaves + 0,
                                             file_comp, file_orders, sp->mt_logleaves);

    hash_t req_hmac = hmac_sha256(&req, sizeof(req), "a", 1);
    hash_t fr_hmac;
    hash_t ack_hmac;

    struct tm_cert fr_cert = sp_request(sp, &req, req_hmac, &fr_hmac, NULL, NULL, &ack_hmac,
                                        hash_null, hash_null, NULL, 0);

    check(fr_cert.type == FR &&
          fr_cert.fr.counter == 1 &&
          fr_cert.fr.version == 0);

    struct iomt_node acl_node = (struct iomt_node) { 1, 1, u64_to_hash(3) };

    //sp->mt_leaves[0].val = u64_to_hash(1);
    /* modification */
    struct user_request mod = req_filemodify(sp->tm,
                                             &fr_cert, fr_hmac,
                                             sp->mt_leaves + 0,
                                             file_comp, file_orders, sp->mt_logleaves,
                                             &acl_node,
                                             NULL, NULL, 0,
                                             hash_null);

    req_hmac = hmac_sha256(&mod, sizeof(mod), "a", 1);

    struct tm_cert vr;
    hash_t vr_hmac;

    struct tm_cert new_fr = sp_request(sp, &mod, req_hmac, &fr_hmac, &vr, &vr_hmac, &ack_hmac,
                                       hash_null, hash_null, "contents", 8);
    printf("File modification: ");
    check(new_fr.type == FR);

    printf("Complement calculation: ");
    int *orders;
    int *comp = merkle_complement(6, 4, &orders);
    int correct[] = { 22, 9, 3, 2 };
    int correct_orders[] = { 1, 0, 0, 1 };
    check(!memcmp(comp, correct, 4 * sizeof(int)) && !memcmp(orders, correct_orders, 4 * sizeof(int)));
    free(orders);
    free(comp);

    printf("Dependency calculation: ");
    int *dep = merkle_dependents(6, 4);
    int correct_dep[] = { 10, 4, 1, 0 };
    check(!memcmp(dep, correct_dep, 4 * sizeof(int)));
    free(dep);

    /* test tree initilization (only simple case) */
    if(logleaves == 1)
    {
        struct iomt_node a = { 1, 2, hash_null };
        struct iomt_node b = { 2, 1, hash_null };
        printf("Merkle tree initialization: ");
        check(hash_equals(sp->mt_nodes[0], merkle_parent(hash_node(&a), hash_node(&b), 0)));
    }
}
