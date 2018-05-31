/* implementation of a basic service provider for use with the trusted
 * module */

#include <stdlib.h>

#include "crypto.h"
#include "service_provider.h"
#include "trusted_module.h"

struct file_version {
    hash_t k; /* h(key, f_idx) */
    hash_t l; /* h(encrypted contents, k) */
    hash_t enc_key; /* XOR'd with h(k, module secret) */

    struct tm_cert cert; /* VR certificate */
    hash_t cert_hmac;

    void *contents;
    size_t len;
};

struct file_record {
    int version;
    int counter;

    struct iomt_node *acl;
    int acl_nodes;

    struct tm_cert cert; /* FR cert */
    hash_t cert_hmac;

    struct file_version *versions;
    int n_versions;
};

struct service_provider {
    struct trusted_module *tm;

    struct file_record *records;
    int n_records;

    struct iomt_node *mt; /* leaves of CDI-IOMT, value is counter */
    int mt_nodes;
};

struct service_provider *sp_new(const void *key, size_t keylen)
{
    struct service_provider *sp = calloc(1, sizeof(*sp));

    sp->tm = tm_new(key, keylen);

    /* everything else is already zeroed by calloc */
    return sp;
}

void sp_request(struct service_provider *sp, const struct user_request *req, hmac_t hmac)
{

}
