/* Functions to help with certificate generation (untrusted). */

/* Some of the certificate generation routines require multiple other
 * certificates to function. This file provides various helper
 * functions to handle the generation of these needed certificates. */

#include "crypto.h"
#include "trusted_module.h"

struct tm_cert cert_ru(struct trusted_module *tm,
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

struct tm_cert cert_rv(struct trusted_module *tm,
		       const struct iomt_node *node,
		       const hash_t *comp, const int *orders, size_t n,
		       hash_t *hmac_out)
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
				 0, NULL, NULL);
}
