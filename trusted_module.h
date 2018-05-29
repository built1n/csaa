/* interface to the trusted module */

#include <stddef.h>
#include "crypto.h"
#include "service_provider.h"

struct trusted_module;

struct tm_cert {
    enum { NONE = 0, NU, EQ, RV, RU } type;
    union {
        struct {
            hash_t orig_node, new_node;
            hash_t orig_root, new_root;
        } nu; /* node update */
        struct {
            /* new_root has an additional placeholder */
            hash_t orig_root, new_root;
            char zero[2 * 32];
        } eq; /* equivalence */
        struct {
            /* proof that there is a node with given idx,val that is a
             * child of root; if val=0, proof that there is no such
             * node */
            int idx;
            hash_t val;
            hash_t root;
            } rv; /* record verify */
    };
};

/* dynamically allocated */
struct trusted_module *tm_new(const char *key, size_t keylen);
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
