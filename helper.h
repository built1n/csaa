#include "trusted_module.h"
#include "crypto.h"

struct tm_cert cert_ru(struct trusted_module *tm,
                       const struct iomt_node *node, hash_t new_val,
                       const hash_t *comp, const int *orders, size_t n,
                       hash_t *hmac_out,
                       int b,
                       struct tm_cert *nonexist, hash_t *hmac_nonexist);

struct tm_cert cert_rv(struct trusted_module *tm,
                       const struct iomt_node *node,
                       const hash_t *comp, const int *orders, size_t n,
                       hash_t *hmac_out);

struct tm_cert cert_eq(struct trusted_module *tm,
                       const struct iomt_node *encloser,
                       int a,
                       const hash_t *enc_comp, const int *enc_orders, size_t enc_n,
                       const hash_t *ins_comp, const int *ins_orders, size_t ins_n,
                       hash_t *hmac_out);
