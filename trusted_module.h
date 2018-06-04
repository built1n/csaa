/* interface to the trusted module */
#ifndef CSAA_TRUSTED_MODULE_H
#define CSAA_TRUSTED_MODULE_H

#include <stdbool.h>
#include <stddef.h>

#include "crypto.h"

struct trusted_module;
struct user_request;

struct tm_cert {
    enum { NONE = 0, NU, EQ, RV, RU, FR, VR } type;
    union {
        struct {
            hash_t orig_node, new_node;
            hash_t orig_root, new_root;
        } nu; /* node update */
        struct {
            /* new_root has an additional placeholder */
            hash_t orig_root, new_root;
        } eq; /* equivalence */
        struct {
            /* proof that there is a node with given idx,val that is a
             * child of root; if val=0, proof that there is no such
             * node */
            hash_t root;
            int idx;
            hash_t val;
        } rv; /* record verify */
        struct {
            int idx;
            hash_t orig_val, new_val;
            hash_t orig_root, new_root;
        } ru; /* record update */
        struct {
            int idx;
            int counter;
            int version;
            hash_t acl; /* root of ACL IOMT */
        } fr; /* file record */
        struct {
            int idx;
            int version;
            hash_t hash; /* commitment to contents, key, and index */
        } vr; /* version record (of a file) */
    };
};

/* creates 1 user with given shared secret */
struct trusted_module *tm_new(const void *key, size_t keylen);
void tm_free(struct trusted_module *tm);
void tm_test(void);

/* certificate generation routines */
/* generate a symmetric certificate indicating that the module has
 * verified that updating the node `orig' to `new' changes the root
 * from `orig_root' to `new_root' (neither of these can be
 * NULL). Passing the [return, orig, new, orig_root, new_root] to the
 * module in the future will serve to verify this check. */
/* complementary nodes and order are passed as usual */
struct tm_cert tm_cert_node_update(struct trusted_module *tm, hash_t orig, hash_t new, const hash_t *comp, const int *orders, size_t n, hash_t *hmac);

/* takes two NU certificates, one stating [a is child of x]->[b is
 * child of y], and one stating [b is child of y]->[c is child of z],
 * and generate a certificate stating [a is child of x]->[c is child
 * of z] */
struct tm_cert tm_cert_combine(struct trusted_module *tm, const struct tm_cert *nu1, hash_t hmac1, const struct tm_cert *nu2, hash_t hmac2, hash_t *hmac_out);

struct tm_cert tm_cert_equiv(struct trusted_module *tm,
                             const struct tm_cert *nu_encl, hash_t hmac_encl,
                             const struct tm_cert *nu_ins,  hash_t hmac_ins,
                             const struct iomt_node *encloser,
                             int a, hash_t *hmac_out);

/* nu must be of the form [x,y,x,y] to indicate that x is a child of y */
/* also, if b > 0 and nonexist != NULL, this function will generate a
 * certificate indicating that no node with index b exists with root
 * y*/
struct tm_cert tm_cert_record_verify(struct trusted_module *tm,
                                     const struct tm_cert *nu, hash_t hmac,
                                     const struct iomt_node *node,
                                     hash_t *hmac_out,
                                     int b,
                                     struct tm_cert *nonexist,
                                     hash_t *hmac_nonexist);

struct tm_cert tm_cert_record_update(struct trusted_module *tm,
                                     const struct tm_cert *nu, hash_t nu_hmac,
                                     const struct iomt_node *node,
                                     hash_t new_val,
                                     hash_t *hmac_out);

/* transformation procedures (return true on success) */

/* change internal IOMT root to equivalent root */
bool tm_set_equiv_root(struct trusted_module *tm,
                       const struct tm_cert *cert_eq, hash_t hmac);

struct tm_cert tm_request(struct trusted_module *tm,
                          const struct user_request *req, hash_t req_hmac,
                          hash_t *hmac_out,
                          struct tm_cert *vr_out, hash_t *vr_hmac,
                          hash_t *ack_hmac);

#endif
