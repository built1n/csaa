/* interface to the trusted module */
#ifndef CSAA_TRUSTED_MODULE_H
#define CSAA_TRUSTED_MODULE_H

#include <stdbool.h>
#include <stddef.h>

#include "crypto.h"
#include "iomt.h"

struct trusted_module;
struct tm_request;

struct tm_cert {
    enum { CERT_NONE = 0, NU, EQ, RV, RU, FR, VR } type;
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
            uint64_t idx;
            hash_t val;
            hash_t root;
        } rv; /* record verify */
        struct {
            uint64_t idx;
            hash_t orig_val, new_val;
            hash_t orig_root, new_root;
        } ru; /* record update */
        struct {
            uint64_t idx;
            uint64_t counter;
            uint64_t version;
            hash_t acl; /* root of ACL IOMT */
        } fr; /* file record */
        struct {
            uint64_t idx;
            uint64_t version;
            hash_t hash; /* lambda value: the commitment to build code
                          * ACL root, stack file ACL root, container
                          * image, key, and index */
        } vr; /* version record (of a file) */
    };
};

struct tm_request {
    uint64_t idx; /* file index */
    uint64_t user_id; /* user id */
    enum { REQ_NONE = 0, ACL_UPDATE, FILE_UPDATE } type;
    uint64_t counter; /* current counter value, 0 for creation */
    hash_t val; /* for ACL update, val=[root of ACL IOMT], for file
                 * update, val is a commitment to the contents, key,
                 * and index of the file (specifically this is the
                 * value represented by lambda in Mohanty et al.,
                 * equal to HMAC(h(encrypted contents), kf). Note that
                 * kf=HMAC(key, file_idx) */
    union {
        /* if counter = 0 and type = ACL_UPDATE, create a new file with given ACL */
        struct {
            struct tm_cert ru_cert;
            hash_t ru_hmac;
        } create;

        /* otherwise the request is to modify either the file or
         * ACL */
        struct {
            /* FR certificate verifying file ACL and counter */
            struct tm_cert fr_cert;
            hash_t fr_hmac;

            /* RV certificate verifying that user is in the ACL */
            struct tm_cert rv_cert;
            hash_t rv_hmac;

            /* RU certificate indicating updated counter value in
             * IOMT */
            struct tm_cert ru_cert;
            hash_t ru_hmac;
        } modify;
    };
};

struct version_info {
    uint64_t idx;
    uint64_t counter;
    uint64_t version, max_version;
    hash_t current_acl; /* not version ACL */
    hash_t lambda; /* equal to HMAC(h(encrypted_contents), key=HMAC(key, file_idx)) */
};

static const struct tm_request req_null = { REQ_NONE };
static const struct tm_cert cert_null = { CERT_NONE };
static const struct version_info verinfo_null = { 0 };

#ifndef CLIENT

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
struct tm_cert tm_cert_node_update(const struct trusted_module *tm,
                                   hash_t orig, hash_t new,
                                   const hash_t *comp, const int *orders, size_t n,
                                   hash_t *hmac);

/* takes two NU certificates, one stating [a is child of x]->[b is
 * child of y], and one stating [b is child of y]->[c is child of z],
 * and generate a certificate stating [a is child of x]->[c is child
 * of z] */
struct tm_cert tm_cert_combine(const struct trusted_module *tm,
                               const struct tm_cert *nu1, hash_t hmac1,
                               const struct tm_cert *nu2, hash_t hmac2,
                               hash_t *hmac_out);

/* Let ve = h(b, b', wb). */
/* Let ve' = h(b, a, wb). */
/* Let vi' = h(a, b', 0). */
/* nu_encl should certify that given [ve is child of y], then [ve' is child of y'] */
/* nu_ins should certify that given [0 is child of y'], then [vi' is child of y''] */
/* this function will then issue a certificate verifying that y and
 * y'' are equivalent roots, indicating that they differ only in y''
 * having an additional placeholder node with index a */
struct tm_cert tm_cert_equiv(const struct trusted_module *tm,
                             const struct tm_cert *nu_encl, hash_t hmac_encl,
                             const struct tm_cert *nu_ins,  hash_t hmac_ins,
                             struct iomt_node encloser,
                             uint64_t a, hash_t *hmac_out);

/* nu must be of the form [x,y,x,y] to indicate that x is a child of y */
/* also, if b > 0 and nonexist != NULL, this function will generate a
 * certificate indicating that no node with index b exists with root
 * y*/
struct tm_cert tm_cert_record_verify(const struct trusted_module *tm,
                                     const struct tm_cert *nu, hash_t hmac,
                                     struct iomt_node node,
                                     hash_t *hmac_out,
                                     uint64_t b,
                                     struct tm_cert *nonexist,
                                     hash_t *hmac_nonexist);

struct tm_cert tm_cert_record_update(const struct trusted_module *tm,
                                     const struct tm_cert *nu, hash_t nu_hmac,
                                     struct iomt_node node,
                                     hash_t new_val,
                                     hash_t *hmac_out);

/* transformation procedures (return true on success) */

/* change internal IOMT root to equivalent root */
bool tm_set_equiv_root(struct trusted_module *tm,
                       const struct tm_cert *cert_eq, hash_t hmac);

/* process a user's request to transform the IOMT in some way */
struct tm_cert tm_request(struct trusted_module *tm,
                          const struct tm_request *req, hash_t req_hmac,
                          hash_t *hmac_out,
                          struct tm_cert *vr_out, hash_t *vr_hmac,
                          hash_t *ack_hmac);

/* enc_secret is encrypted by the user by XOR'ing the file encryption
 * key with h(f + q + K), where + denotes concatenation. The purpose
 * of this function is to decrypt the secret passed by the user,
 * verify its integrity against kf=HMAC(secret, key=f_idx), and then
 * re-encrypt the secret with the module's secret key. This is the
 * F_rs() function described by Mohanty et al. */
/* Untested. */
hash_t tm_verify_and_encrypt_secret(const struct trusted_module *tm,
                                    uint64_t file_idx,
                                    uint64_t file_version,
                                    uint64_t user_id,
                                    hash_t encrypted_secret, hash_t kf);

/* Decrypt a previously encrypted secret, and then encrypt for receipt
 * by a user. rv1 should bind the file index and counter to the
 * current root. rv2 should verify the user's access level in the
 * ACL. The index (which is a user id) given in rv2 will select the
 * key used to encrypt the secret. As with
 * tm_verify_and_encrypt_secret(), kf=HMAC(secret, key=f_idx). */
/* Untested. */
hash_t tm_retrieve_secret(const struct trusted_module *tm,
                          const struct tm_cert *rv1, hash_t rv1_hmac,
                          const struct tm_cert *rv2, hash_t rv2_hmac,
                          const struct tm_cert *fr, hash_t fr_hmac,
                          hash_t encrypted_secret, hash_t kf);

struct version_info tm_verify_fileinfo(const struct trusted_module *tm,
                                       uint64_t user_id,
                                       const struct tm_cert *rv1, hash_t rv1_hmac,
                                       const struct tm_cert *rv2, hash_t rv2_hmac,
                                       const struct tm_cert *fr, hash_t fr_hmac,
                                       const struct tm_cert *vr, hash_t vr_hmac,
                                       hash_t *response_hmac);

const char *tm_geterror(void);

void tm_seterror(const char *error);

#endif

#endif
