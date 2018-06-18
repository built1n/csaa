/* Functions to help with certificate generation (untrusted). */

/* Some of the certificate generation routines require multiple other
 * certificates to function. This file provides various helper
 * functions to handle the generation of these needed certificates. */

#include <assert.h>
#include <stdlib.h>

#include "crypto.h"
#include "trusted_module.h"

struct tm_cert cert_ru(const struct trusted_module *tm,
                       const struct iomt_node *node, hash_t new_val,
                       const hash_t *comp, const int *orders, size_t n,
                       hash_t *hmac_out)
{
    struct iomt_node new_node = *node;
    new_node.val = new_val;
    hash_t nu_hmac;
    struct tm_cert nu = tm_cert_node_update(tm,
                                            hash_node(node),
                                            hash_node(&new_node),
                                            comp, orders, n,
                                            &nu_hmac);

    return tm_cert_record_update(tm, &nu, nu_hmac, node, new_val, hmac_out);
}

struct tm_cert cert_rv(const struct trusted_module *tm,
                       const struct iomt_node *node,
                       const hash_t *comp, const int *orders, size_t n,
                       hash_t *hmac_out,
                       uint64_t b,
                       struct tm_cert *nonexist, hash_t *hmac_nonexist)
{
    hash_t nu_hmac;
    struct tm_cert nu = tm_cert_node_update(tm,
                                            hash_node(node),
                                            hash_node(node),
                                            comp, orders, n,
                                            &nu_hmac);

    return tm_cert_record_verify(tm,
                                 &nu, nu_hmac,
                                 node,
                                 hmac_out,
                                 b, nonexist, hmac_nonexist);
}

struct tm_cert cert_rv_by_idx(const struct trusted_module *tm,
                              const struct iomt *tree,
                              uint64_t idx,
                              hash_t *hmac_out)
{
    struct iomt_node *node = iomt_find_leaf_or_encloser(tree, idx);

    if(!node)
        return cert_null;

    /* find the complement */
    int *orders;
    hash_t *comp = merkle_complement(tree, node - tree->mt_leaves, &orders);

    struct tm_cert cert;

    if(idx == node->idx)
    {
        /* node exists */
        cert = cert_rv(tm,
                       node,
                       comp, orders, tree->mt_logleaves,
                       hmac_out,
                       0, NULL, NULL);
    }
    else
    {
        /* node does not exist */
        cert_rv(tm,
                node,
                comp, orders, tree->mt_logleaves,
                NULL,
                idx,
                &cert, hmac_out);
    }

    free(comp);
    free(orders);

    return cert;
}

/* Fill out a user_request struct to create a file with the index
 * given in file_node->idx with the user added with level 3 access in
 * the ACL. */
struct user_request req_filecreate(const struct trusted_module *tm,
                                   uint64_t user_id,
                                   const struct iomt_node *file_node,
                                   const hash_t *file_comp, const int *file_orders, size_t file_n)
{
    /* construct a request to create a file */
    struct user_request req = req_null;
    req.idx = file_node->idx;
    req.user_id = user_id;
    req.type = ACL_UPDATE;
    req.counter = 0;

    /* construct ACL with a single element (the user, with full access) */
    struct iomt_node acl_node = (struct iomt_node) { 1, 1, u64_to_hash(3) };
    req.val = merkle_compute(hash_node(&acl_node), NULL, NULL, 0);

    hash_t one = u64_to_hash(1);

    hash_t ru_hmac;

    /* we need a RU certificate of the form [f, 0, root, 1, new root],
     * which requires a NU certificate of the form [v, root, v', new
     * root], where v=h(original IOMT node) and v'=h(new IOMT node) */
    struct tm_cert ru = cert_ru(tm,
                                file_node, one,
                                file_comp, file_orders, file_n,
                                &ru_hmac);

    req.create.ru_cert = ru;
    req.create.ru_hmac = ru_hmac;

    return req;
}

/* Fill out a user_request struct to modify an existing file's
 * contents, given the previously generated FR certificate, and the
 * ACL node giving the user's access rights. */
struct user_request req_filemodify(const struct trusted_module *tm,
                                   const struct tm_cert *fr_cert, hash_t fr_hmac,
                                   const struct iomt_node *file_node,
                                   const hash_t *file_comp, const int *file_orders, size_t file_n,
                                   const struct iomt_node *acl_node,
                                   const hash_t *acl_comp, const int *acl_orders, size_t acl_n,
                                   hash_t fileval)
{
    /* modification */
    struct user_request req = req_null;
    req.type = FILE_UPDATE;

    req.idx = file_node->idx;
    req.counter = hash_to_u64(file_node->val);

    req.user_id = acl_node->idx;

    req.modify.fr_cert = *fr_cert;
    req.modify.fr_hmac = fr_hmac;

    req.modify.rv_cert = cert_rv(tm,
                                 acl_node,
                                 acl_comp, acl_orders, acl_n,
                                 &req.modify.rv_hmac,
                                 0, NULL, NULL);

    hash_t next_counter = u64_to_hash(req.counter + 1);

    req.modify.ru_cert = cert_ru(tm, file_node, next_counter,
                                 file_comp, file_orders, file_n,
                                 &req.modify.ru_hmac);
    req.val = fileval;

    return req;
}

/* Fill out a user_request struct to modify a file's ACL. Same
 * parameters as req_filemodify(), except the hash is the root of the
 * new ACL. */
struct user_request req_aclmodify(const struct trusted_module *tm,
                                  const struct tm_cert *fr_cert, hash_t fr_hmac,
                                  const struct iomt_node *file_node,
                                  const hash_t *file_comp, const int *file_orders, size_t file_n,
                                  const struct iomt_node *oldacl_node,
                                  const hash_t *oldacl_comp, const int *oldacl_orders, size_t oldacl_n,
                                  hash_t newacl_root)
{
    struct user_request req;
    req.type = ACL_UPDATE;

    req.idx = file_node->idx;
    req.counter = hash_to_u64(file_node->val);

    req.user_id = oldacl_node->idx;

    req.modify.fr_cert = *fr_cert;
    req.modify.fr_hmac = fr_hmac;

    req.modify.rv_cert = cert_rv(tm,
                                 oldacl_node,
                                 oldacl_comp, oldacl_orders, oldacl_n,
                                 &req.modify.rv_hmac,
                                 0, NULL, NULL);

    hash_t next_counter = u64_to_hash(req.counter + 1);

    req.modify.ru_cert = cert_ru(tm, file_node, next_counter,
                                 file_comp, file_orders, file_n,
                                 &req.modify.ru_hmac);
    req.val = newacl_root;

    return req;
}
