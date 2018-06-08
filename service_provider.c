/* implementation of a basic service provider for use with the trusted
 * module */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "crypto.h"
#include "helper.h"
#include "service_provider.h"
#include "trusted_module.h"

struct file_version {
    hash_t kf; /* h(key, file_idx) */
    hash_t l; /* h(h(file contents), kf) */
    hash_t enc_key; /* XOR'd with h(kf, module secret) */

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

    struct tm_cert fr_cert; /* issued by module */
    hash_t fr_hmac;

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

struct tm_cert sp_request(struct service_provider *sp,
                          const struct user_request *req, hash_t req_hmac,
                          hash_t *hmac_out,
                          struct tm_cert *vr_out, hash_t *vr_hmac,
                          hash_t *ack_hmac)
{
    /* see if module succeeds; if so, update the databases */
    return tm_request(sp->tm, req, req_hmac, hmac_out, vr_out, vr_hmac, ack_hmac);
}

/* in trusted_module.c */
void check(int condition);

void sp_test(void)
{
    struct service_provider *sp = sp_new("a", 1);
    /* construct a request to create a file */
    struct user_request req;
    req.idx = 1;
    req.user_id = 1;
    req.type = ACL_UPDATE;
    req.counter = 0;

    struct iomt_node acl_node;
    acl_node.idx = 1;
    memset(&acl_node.val, 0, sizeof(acl_node.val));
    acl_node.val.hash[0] = 3; /* full access */
    acl_node.next_idx = 1;
    req.val = merkle_compute(hash_node(&acl_node), NULL, NULL, 0);
    
    struct iomt_node node;
    node.idx = 1;
    memset(node.val.hash, 0, 32);
    node.next_idx = 1;

    hash_t one;
    memset(one.hash, 0, 32);
    one.hash[0] = 1;

    hash_t ru_hmac;
    
    /* we need a RU certificate of the form [f, 0, root, 1, new root],
     * which requires a NU certificate of the form [v, root, v', new
     * root], where v=h(original IOMT node) and v'=h(new IOMT node) */
    struct tm_cert ru = cert_ru(sp->tm, &node, one,
                                NULL, NULL, 0,
                                &ru_hmac,
                                0, NULL, NULL);
    printf("RU generation: ");
    check(ru.type == RU &&
          ru.ru.idx == 1 &&
          hash_equals(ru.ru.orig_val, node.val) &&
          hash_equals(ru.ru.new_val, one));

    /* now create a request */
    req.create.ru_cert = ru;
    req.create.ru_hmac = ru_hmac;
    hash_t req_hmac = hmac_sha256(&req, sizeof(req), "a", 1);
    hash_t fr_hmac;
    hash_t ack_hmac;
    
    struct tm_cert fr_cert = sp_request(sp, &req, req_hmac, &fr_hmac, NULL, NULL, &ack_hmac);

    printf("File creation: ");
    check(fr_cert.type == FR &&
          fr_cert.fr.counter == 1 &&
          fr_cert.fr.version == 0);

    /* modification */
    struct user_request mod;
    mod.type = FILE_UPDATE;
    mod.idx = 1;
    mod.user_id = 1;
    mod.counter = 1;
    mod.modify.fr_cert = fr_cert;
    mod.modify.fr_hmac = fr_hmac;

    mod.modify.rv_cert = cert_rv(sp->tm,
				 &acl_node,
				 NULL, NULL, 0,
				 &mod.modify.rv_hmac);

    struct iomt_node node2;
    node2.idx = 1;
    node2.val = one;
    node2.next_idx = 1;
        
    hash_t two;
    memset(&two, 0, sizeof(two));
    two.hash[0] = 2;
    mod.modify.ru_cert = cert_ru(sp->tm, &node2, two,
                                NULL, NULL, 0,
                                &mod.modify.ru_hmac,
                                0, NULL, NULL);

    req_hmac = hmac_sha256(&mod, sizeof(mod), "a", 1);

    struct tm_cert vr;
    hash_t vr_hmac;
    
    struct tm_cert new_fr = sp_request(sp, &mod, req_hmac, &fr_hmac, &vr, &vr_hmac, &ack_hmac);
    printf("File modification: ");
    check(new_fr.type == FR);
}
