/* Functions to help with certificate generation (untrusted). */

/* Some of the certificate generation routines require multiple other
 * certificates to function. This file provides various helper
 * functions to handle the generation of these needed certificates. */

#include <assert.h>

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

/* generate an EQ certificate for inserting a placeholder with index
 * a, given an encloser (which must actually enclose a) */
struct tm_cert cert_eq(struct trusted_module *tm,
                       const struct iomt_node *encloser,
                       int a,
                       const hash_t *enc_comp, const int *enc_orders, size_t enc_n,
                       const hash_t *ins_comp, const int *ins_orders, size_t ins_n,
                       hash_t *hmac_out)
{
    assert(encloses(encloser->idx, encloser->next_idx, a));

    struct iomt_node encloser_mod = *encloser;
    encloser_mod.next_idx = a;

    struct iomt_node insert;
    insert.idx = a;
    insert.next_idx = encloser->next_idx;
    insert.val = hash_null;

    hash_t h_enc    = hash_node(encloser);
    hash_t h_encmod = hash_node(&encloser_mod);

    hash_t h_ins = hash_node(&insert);

    /* we need two NU certificates */
    hash_t nu1_hmac, nu2_hmac;

    struct tm_cert nu1 = tm_cert_node_update(tm,
                                             h_enc, h_encmod,
                                             enc_comp, enc_orders, enc_n,
                                             &nu1_hmac);
    /* FIXME: the complement will change upon changing this node, so
     * cert_equiv() will fail. */
    struct tm_cert nu2 = tm_cert_node_update(tm,
                                             hash_null, h_ins,
                                             ins_comp, ins_orders, ins_n,
                                             &nu2_hmac);
    return tm_cert_equiv(tm, &nu1, nu1_hmac, &nu2, nu2_hmac, encloser, a, hmac_out);
}
