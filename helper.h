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
