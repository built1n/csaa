/* implementation of a basic service provider for use with the trusted
 * module */

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "crypto.h"
#include "helper.h"
#include "service_provider.h"
#include "test.h"
#include "trusted_module.h"

#define ACL_LOGLEAVES 4

struct file_version {
    hash_t kf; /* HMAC(key, file_idx) */
    hash_t encrypted_secret; /* XOR'd with HMAC(kf, module secret) */

    struct tm_cert vr_cert; /* VR certificate */
    hash_t vr_hmac;

    /* lines of Dockerfile */
    struct iomt *buildcode;

    /* lines of docker-compose.yml */
    struct iomt *composefile;

    /* image .tar file */
    void *contents;
    size_t contents_len;
};

struct file_record {
    uint64_t idx;
    uint64_t version;
    uint64_t counter;

    struct iomt *acl;

    struct tm_cert fr_cert; /* issued by module */
    hash_t fr_hmac;

    /* Version numbers start at 1 and are not stored
     * explicitly. versions[0] refers to version 1. */
    struct file_version *versions;
    int nversions;
};

struct service_provider {
    struct trusted_module *tm;

    struct file_record *records;
    size_t nrecords;

    struct iomt *iomt;
};

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
    int *compidx_enc = bintree_complement(encloser_leafidx, sp->iomt->mt_logleaves, &orders_enc);
    int *compidx_ins = bintree_complement(placeholder_leafidx, sp->iomt->mt_logleaves, &orders_ins);

    hash_t *comp_enc = lookup_nodes(sp->iomt->mt_nodes, compidx_enc, sp->iomt->mt_logleaves);

    /* we need two NU certificates */
    hash_t nu1_hmac, nu2_hmac;

    struct tm_cert nu1 = tm_cert_node_update(sp->tm,
                                             h_enc, h_encmod,
                                             comp_enc, orders_enc, sp->iomt->mt_logleaves,
                                             &nu1_hmac);

    /* We now update the ancestors of the encloser node. */
    hash_t *old_depvalues;
    merkle_update(sp->iomt, encloser_leafidx, h_encmod, &old_depvalues);

    hash_t *comp_ins = lookup_nodes(sp->iomt->mt_nodes, compidx_ins, sp->iomt->mt_logleaves);

    struct tm_cert nu2 = tm_cert_node_update(sp->tm,
                                             hash_null, h_ins,
                                             comp_ins, orders_ins, sp->iomt->mt_logleaves,
                                             &nu2_hmac);

    /* restore the tree */
    int *dep_indices = bintree_ancestors(encloser_leafidx, sp->iomt->mt_logleaves);
    restore_nodes(sp->iomt->mt_nodes, dep_indices, old_depvalues, sp->iomt->mt_logleaves);
    free(dep_indices);
    free(old_depvalues);

    free(compidx_enc);
    free(compidx_ins);
    free(comp_enc);
    free(comp_ins);
    free(orders_enc);
    free(orders_ins);

    return tm_cert_equiv(sp->tm, &nu1, nu1_hmac, &nu2, nu2_hmac, encloser, placeholder_nodeidx, hmac_out);
}

/* leaf count will be 2^logleaves */
struct service_provider *sp_new(const void *key, size_t keylen, int logleaves)
{
    assert(logleaves > 0);
    struct service_provider *sp = calloc(1, sizeof(*sp));

    sp->tm = tm_new(key, keylen);

    sp->iomt = iomt_new(logleaves);

    /* The trusted module initializes itself with a single placeholder
     * node (1,0,1). We first update our list of IOMT leaves. Then we
     * insert our desired number of nodes by using EQ certificates to
     * update the internal IOMT root. Note that leaf indices are
     * 1-indexed. */
    sp->iomt->mt_leaves[0] = (struct iomt_node) { 1, 1, hash_null };
    merkle_update(sp->iomt, 0, hash_node(sp->iomt->mt_leaves + 0), NULL);

    for(int i = 1; i < sp->iomt->mt_leafcount; ++i)
    {
        /* generate EQ certificate */
        hash_t hmac;
        struct tm_cert eq = cert_eq(sp, sp->iomt->mt_leaves + i - 1,
                                    i - 1,
                                    i, i + 1,
                                    &hmac);
        assert(eq.type == EQ);

        /* update previous leaf's index */
        sp->iomt->mt_leaves[i - 1].next_idx = i + 1;
        merkle_update(sp->iomt, i - 1, hash_node(sp->iomt->mt_leaves + i - 1), NULL);

        /* next_idx is set to 1 to keep everything circularly linked;
         * in the next iteration it will be updated to point to the
         * next node, if any */
        sp->iomt->mt_leaves[i] = (struct iomt_node) { i + 1, 1, hash_null };
        merkle_update(sp->iomt, i, hash_node(sp->iomt->mt_leaves + i), NULL);

        assert(tm_set_equiv_root(sp->tm, &eq, hmac));
    }

    /* We shouldn't need this; the incremental update_tree() calls
     * should give the same result. */
    //fill_tree(sp);

    /* everything else is already zeroed by calloc */
    return sp;
}

static void free_version(struct file_version *ver)
{
    free(ver->contents);
}

static void free_record(struct file_record *rec)
{
    for(int i = 0; i < rec->nversions; ++i)
        free_version(rec->versions + i);
    free(rec->versions);
    iomt_free(rec->acl);
}

void sp_free(struct service_provider *sp)
{
    for(int i = 0; i < sp->nrecords; ++i)
        free_record(sp->records + i);
    free(sp->records);

    tm_free(sp->tm);
    iomt_free(sp->iomt);
    free(sp);
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
 * encrypted_secret, kf, buildcode, composefile, encrypted_contents,
 * and contents_len are used (otherwise they are
 * ignored). `encrypted_secret' should be the file encryption key
 * XOR'd with HMAC(file index | file counter, user_key). kf should be
 * HMAC(encryption secret, file index).
 *
 * If the request is to either modify the ACL or create a file (which
 * is essentially an ACL update), the ACL will be set to
 * new_acl. `new_acl' must be in persistent storage.
 */
struct tm_cert sp_request(struct service_provider *sp,
                          const struct user_request *req, hash_t req_hmac,
                          hash_t *hmac_out,
                          struct tm_cert *vr_out, hash_t *vr_hmac_out,
                          hash_t *ack_hmac_out,
                          hash_t encrypted_secret, hash_t kf,
                          const struct iomt *buildcode, const struct iomt *composefile,
                          const void *encrypted_contents, size_t contents_len,
                          const struct iomt *new_acl)
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

        rec->idx = fr.fr.idx;
        rec->counter = fr.fr.counter;
        rec->fr_cert = fr;
        rec->fr_hmac = fr_hmac;

        if(req->type == ACL_UPDATE)
        {
            /* check that the passed value matches the calculated root */
            assert(hash_equals(req->val, new_acl->mt_nodes[0]));

            /* update our ACL */
            iomt_free(rec->acl);
            rec->acl = iomt_dup(new_acl);
        }

        if(rec->version != fr.fr.version)
        {
            rec->version = fr.fr.version;

            struct file_version ver;
            memset(&ver, 0, sizeof(ver));

            hash_t gamma = sha256(encrypted_contents, contents_len);

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
                 * module to do so for us, as done above. */
                ver.kf = kf;
            }
            else
            {
                ver.encrypted_secret = hash_null;
            }

            ver.vr_cert = vr;
            ver.vr_hmac = vr_hmac;

            if(buildcode)
                ver.buildcode = iomt_dup(buildcode);

            if(composefile)
                ver.composefile = iomt_dup(composefile);

            if(encrypted_contents)
            {
                /* duplicate */
                ver.contents = malloc(contents_len);
                memcpy(ver.contents, encrypted_contents, contents_len);
                ver.contents_len = contents_len;
            }

            append_version(rec, &ver);
        }

        if(need_insert)
        {
            append_record(sp, rec);

            /* append_record will make a copy */
            free(rec);
        }

        /* update our tree */
        sp->iomt->mt_leaves[req->idx - 1].val = u64_to_hash(fr.fr.counter);

        merkle_update(sp->iomt, req->idx - 1, hash_node(sp->iomt->mt_leaves + req->idx - 1), NULL);
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

struct user_request sp_createfile(struct service_provider *sp,
                             uint64_t user_id, const void *key, size_t keylen,
                             hash_t *ack_hmac)
{
    int i;

    /* Find an empty leaf node */
    for(i = 0; i < sp->iomt->mt_leafcount; ++i)
    {
        if(is_zero(sp->iomt->mt_leaves[i].val))
            break;
    }

    /* fail */
    if(i == sp->iomt->mt_leafcount)
    {
        return req_null;
    }

    int *file_compidx, *file_orders;
    file_compidx = bintree_complement(i, sp->iomt->mt_logleaves, &file_orders);

    hash_t *file_comp = lookup_nodes(sp->iomt->mt_nodes, file_compidx, sp->iomt->mt_logleaves);

    struct iomt *acl = iomt_new(ACL_LOGLEAVES);
    acl->mt_leaves[0] = (struct iomt_node) { user_id, user_id, u64_to_hash(3) };
    merkle_update(acl, 0, hash_node(acl->mt_leaves + 0), NULL);

    struct user_request req = req_filecreate(sp->tm,
                                             i + 1,
                                             sp->iomt->mt_leaves + i,
                                             file_comp, file_orders, sp->iomt->mt_logleaves);

    hash_t req_hmac = hmac_sha256(&req, sizeof(req), key, keylen);
    hash_t fr_hmac;

    struct tm_cert fr_cert = sp_request(sp,
                                        &req, req_hmac,
                                        &fr_hmac,
                                        NULL, NULL,
                                        ack_hmac,
                                        hash_null, hash_null,
                                        NULL, NULL,
                                        NULL, 0,
                                        acl);

    iomt_free(acl);

    free(file_compidx);
    free(file_comp);
    free(file_orders);

    if(fr_cert.type == FR)
        return req;
    return req_null;
}

/* Expects ACL root to already be calculated */
struct user_request sp_modifyacl(struct service_provider *sp,
                                 uint64_t user_id, const void *key, size_t keylen,
                                 uint64_t file_idx,
                                 struct iomt *new_acl,
                                 hash_t *ack_hmac)
{
    /* modification */
    struct file_record *rec = lookup_record(sp, file_idx);
    if(!rec)
        return req_null;

    int *file_orders, *acl_orders;
    struct iomt_node *file_node = iomt_find_leaf(sp->iomt, file_idx);

    hash_t *file_comp = merkle_complement(sp->iomt,
                                          file_node - sp->iomt->mt_leaves,
                                          &file_orders);

    struct iomt_node *acl_node = iomt_find_leaf(rec->acl, user_id);
    hash_t *acl_comp = merkle_complement(rec->acl,
                                         acl_node - rec->acl->mt_leaves,
                                         &acl_orders);

    struct user_request req = req_aclmodify(sp->tm,
                                            &rec->fr_cert, rec->fr_hmac,
                                            file_node,
                                            file_comp, file_orders, sp->iomt->mt_logleaves,
                                            acl_node,
                                            acl_comp, acl_orders, rec->acl->mt_logleaves,
                                            new_acl->mt_nodes[0]);

    free(file_comp);
    free(file_orders);
    free(acl_comp);
    free(acl_orders);

    hash_t req_hmac = hmac_sha256(&req, sizeof(req), key, keylen);

    struct tm_cert new_fr = sp_request(sp,
                                       &req, req_hmac,
                                       NULL,
                                       NULL, NULL,
                                       ack_hmac,
                                       hash_null, hash_null,
                                       NULL, NULL,
                                       NULL, 0,
                                       new_acl);

    if(new_fr.type == FR)
        return req;
    return req_null;
}

struct user_request sp_modifyfile(struct service_provider *sp,
                                  uint64_t user_id, const void *key, size_t keylen,
                                  uint64_t file_idx,
                                  hash_t encrypted_secret, hash_t kf,
                                  const struct iomt *buildcode, const struct iomt *composefile,
                                  const void *encrypted_file, size_t filelen,
                                  hash_t *ack_hmac)
{
    /* modification */
    struct file_record *rec = lookup_record(sp, file_idx);
    if(!rec)
        return req_null;

    int *file_orders, *acl_orders;
    struct iomt_node *file_node = iomt_find_leaf(sp->iomt, file_idx);

    hash_t *file_comp = merkle_complement(sp->iomt,
                                          file_node - sp->iomt->mt_leaves,
                                          &file_orders);

    struct iomt_node *acl_node = iomt_find_leaf(rec->acl, user_id);
    hash_t *acl_comp = merkle_complement(rec->acl,
                                         acl_node - rec->acl->mt_leaves,
                                         &acl_orders);

    hash_t gamma = sha256(encrypted_file, filelen);
    hash_t lambda = calc_lambda(gamma, buildcode, composefile, kf);

    struct user_request req = req_filemodify(sp->tm,
                                             &rec->fr_cert, rec->fr_hmac,
                                             file_node,
                                             file_comp, file_orders, sp->iomt->mt_logleaves,
                                             acl_node,
                                             acl_comp, acl_orders, rec->acl->mt_logleaves,
                                             lambda);
    free(file_comp);
    free(acl_comp);
    free(file_orders);
    free(acl_orders);

    hash_t req_hmac = hmac_sha256(&req, sizeof(req), key, keylen);

    struct tm_cert vr;
    hash_t vr_hmac, fr_hmac;

    struct tm_cert new_fr = sp_request(sp,
                                       &req, req_hmac,
                                       &fr_hmac,
                                       &vr, &vr_hmac,
                                       ack_hmac,
                                       encrypted_secret, kf,
                                       buildcode, composefile,
                                       encrypted_file, filelen,
                                       NULL);

    /* We return the request because that is how the module's
     * authentication is done. */
    if(new_fr.type == FR)
        return req;
    return req_null;
}

static bool ack_verify(const struct user_request *req,
                       const void *secret, size_t secret_len,
                       hash_t hmac)
{
    hash_t correct = ack_sign(req, 1, secret, secret_len);
    return hash_equals(hmac, correct);
}

/* Retrieve authenticated information (using the user's secret as the
 * key) on a version of a file; if version is zero, default to the
 * latest version. If the file does not exist, the function will still
 * succeed, returning an authenticated structure indicating
 * failure. */
struct version_info sp_fileinfo(struct service_provider *sp,
                                uint64_t user_id,
                                uint64_t file_idx,
                                uint64_t version,
                                hash_t *hmac)
{
    struct file_record *rec = lookup_record(sp, file_idx);

    /* Produce an authenticated denial proving that no file exists
     * with the given index. */
    if(!rec)
    {
        /* In theory, we would have to perform a linear search now to
         * either find a placeholder node for this file index, or an
         * enclosing node, both of which would prove that no file with
         * the given index exists. However, we can cheat since we know
         * that our IOMT is initialized with all the node indices
         * falling densely into the range [1,2^logleaves]. If the
         * index falls into this range, we can generate a RV
         * certificate indicating that it has a zero counter value
         * (and hence no associated file), or if it falls outside this
         * range, by generating an RV certificate indicating the
         * nonexistence of this node index. */
        struct tm_cert rv1;
        hash_t rv1_hmac;

        if(1 <= file_idx && file_idx <= sp->iomt->mt_leafcount)
        {
            int *orders, *compidx;
            compidx = bintree_complement(file_idx - 1, sp->iomt->mt_logleaves, &orders);
            hash_t *comp = lookup_nodes(sp->iomt->mt_nodes, compidx, sp->iomt->mt_logleaves);

            /* Placeholder exists. */
            rv1 = cert_rv(sp->tm,
                          sp->iomt->mt_leaves + file_idx - 1,
                          comp, orders, sp->iomt->mt_logleaves,
                          &rv1_hmac,
                          0, NULL, NULL);
            free(comp);
            free(compidx);
            free(orders);
        }
        else
        {
            /* Use last node as encloser */
            int *orders, *compidx;
            compidx = bintree_complement(sp->iomt->mt_leafcount - 1, sp->iomt->mt_logleaves, &orders);
            hash_t *comp = lookup_nodes(sp->iomt->mt_nodes, compidx, sp->iomt->mt_logleaves);

            cert_rv(sp->tm,
                    sp->iomt->mt_leaves + sp->iomt->mt_leafcount - 1,
                    comp, orders, sp->iomt->mt_logleaves,
                    NULL,
                    file_idx, &rv1, &rv1_hmac);

            free(comp);
            free(compidx);
            free(orders);
        }

        return tm_verify_file(sp->tm,
                              user_id,
                              &rv1, rv1_hmac,
                              NULL, hash_null,
                              NULL, hash_null,
                              NULL, hash_null,
                              hmac);
    }

    /* RV1 indicates counter */
    hash_t rv1_hmac;
    struct tm_cert rv1 = cert_rv_by_idx(sp->tm,
                                        sp->iomt,
                                        file_idx,
                                        &rv1_hmac);

    /* RV2 indicates access rights */
    hash_t rv2_hmac;
    struct tm_cert rv2 = cert_rv_by_idx(sp->tm,
                                        rec->acl,
                                        user_id,
                                        &rv2_hmac);

    struct file_version *ver = &rec->versions[version ? version - 1 : rec->nversions - 1];

    return tm_verify_file(sp->tm,
                          user_id,
                          &rv1, rv1_hmac,
                          &rv2, rv2_hmac,
                          &rec->fr_cert, rec->fr_hmac,
                          &ver->vr_cert, ver->vr_hmac,
                          hmac);
}

/* This file retrieves the file given by file_idx for a given
 * user. *encrypted_secret will be set to the encryption key XOR'd
 * with HMAC(f | c_f, K). The returned value is dynamically allocated
 * and must be freed by the caller. This function returns NULL upon
 * failure. An authenticated proof that the request cannot be
 * satisfied can be obtained by calling sp_fileinfo. */
void *sp_retrieve_file(struct service_provider *sp,
                       uint64_t user_id,
                       uint64_t file_idx,
                       uint64_t version,
                       hash_t *encrypted_secret,
                       size_t *len)
{
    struct file_record *rec = lookup_record(sp, file_idx);

    if(!rec->nversions)
    {
        /* Newly created file, no contents. We don't bother to set
         * *encrypted_secret or *len. */
        return NULL;
    }

    struct file_version *ver = &rec->versions[version ? version - 1 : rec->nversions - 1];

    hash_t rv1_hmac, rv2_hmac;
    struct tm_cert rv1 = cert_rv_by_idx(sp->tm, sp->iomt, file_idx, &rv1_hmac);
    struct tm_cert rv2 = cert_rv_by_idx(sp->tm, rec->acl, user_id, &rv2_hmac);

    if(hash_to_u64(rv2.rv.val) < 1)
    {
        /* no permissions; don't return file contents */
        return NULL;
    }

    if(encrypted_secret)
    {
        *encrypted_secret = is_zero(ver->encrypted_secret) ?
            hash_null                                      :
            tm_retrieve_secret(sp->tm,
                               &rv1, rv1_hmac,
                               &rv2, rv2_hmac,
                               &rec->fr_cert, rec->fr_hmac,
                               ver->encrypted_secret, ver->kf);
    }

    if(len)
        *len = ver->contents_len;

    /* duplicate */
    void *ret = malloc(ver->contents_len);
    memcpy(ret, ver->contents, ver->contents_len);

    return ret;
}

#include <time.h>

void sp_test(void)
{
    int logleaves = 5;
    printf("Initializing IOMT with %llu nodes.\n", 1ULL << logleaves);

    clock_t start = clock();
    struct service_provider *sp = sp_new("a", 1, logleaves);
    clock_t stop = clock();
    printf("%.1f placeholder insertions per second\n", (double)(1ULL << logleaves) * CLOCKS_PER_SEC / (stop - start));

    check("Tree initialization", sp != NULL);

    {
        hash_t ack_hmac;
        struct user_request req = sp_createfile(sp, 1, "a", 1, &ack_hmac);

        check("File creation", ack_verify(&req, "a", 1, ack_hmac));

#define N_MODIFY 100
        start = clock();
        for(int i = 0; i < N_MODIFY; ++i)
            req = sp_modifyfile(sp, 1, "a", 1, 1, hash_null, hash_null, NULL, NULL, "contents", 8, &ack_hmac);

        stop = clock();
        printf("%.1f modifications per second\n", (double)N_MODIFY * CLOCKS_PER_SEC / (stop - start));

        check("File modification", ack_verify(&req, "a", 1, ack_hmac));
    }

    /* file info retrieval */
    {
        hash_t hmac;
        /* check inside range, but empty slot */
        struct version_info vi = sp_fileinfo(sp, 1, 12, 1, &hmac);
        check("Authenticated denial 1", hash_equals(hmac, hmac_sha256(&vi, sizeof(vi), "a", 1)));

        /* check outside range */
        vi = sp_fileinfo(sp, 1, (1 << sp->iomt->mt_logleaves) + 1, 1, &hmac);
        check("Authenticated denial 2", hash_equals(hmac, hmac_sha256(&vi, sizeof(vi), "a", 1)));

        /* check in range */
        vi = sp_fileinfo(sp,
                         1, /* user */
                         1, /* file */
                         1, /* version */
                         &hmac);
        check("File info retrieval 1", hash_equals(hmac, hmac_sha256(&vi, sizeof(vi), "a", 1)));

        hash_t gamma = sha256("contents", 8);
        hash_t kf = hash_null;
        hash_t lambda = calc_lambda(gamma, NULL, NULL, kf);

        struct version_info correct = { 1, N_MODIFY + 1, 1, N_MODIFY, lambda };
        check("File info retrieval 2", !memcmp(&correct, &vi, sizeof(vi)));
    }

    /* retrieve contents */
    {
        hash_t key;
        size_t len;
        void *contents = sp_retrieve_file(sp,
                                          1,
                                          1,
                                          1,
                                          &key,
                                          &len);
        check("File retrieval 1", !memcmp(contents, "contents", 8) && len == 8);
        free(contents);
    }

    {
        /* ACL modify */
        struct iomt *newacl = iomt_new(ACL_LOGLEAVES);
        iomt_update_by_leafidx(newacl, 0, 1, 2, u64_to_hash(3));
        iomt_update_by_leafidx(newacl, 1, 2, 1, u64_to_hash(1));

        hash_t ack;
        bool success = true;

#define N_ACLMODIFY 100
        for(int i = 0; i < 100; ++i)
        {
            struct user_request req = sp_modifyacl(sp,
                                                   1, "a", 1,
                                                   1,
                                                   newacl,
                                                   &ack);

            success &= ack_verify(&req, "a", 1, ack);
        }

        iomt_free(newacl);

        check("ACL modification 1", success);
    }

    if(logleaves < 5)
    {
        printf("CDI-IOMT contents: ");
        iomt_dump(sp->iomt);
    }

    /* test tree initialization (only simple case) */
    if(logleaves == 1)
    {
        struct iomt_node a = { 1, 2, u64_to_hash(2) };
        struct iomt_node b = { 2, 1, hash_null };
        check("Merkle tree initialization", hash_equals(sp->iomt->mt_nodes[0], merkle_parent(hash_node(&a), hash_node(&b), 0)));
    }

    sp_free(sp);
}
