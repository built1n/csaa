/* implementation of a basic service provider for use with the trusted
 * module */

#ifndef CSAA_SERVICE_PROVIDER_H
#define CSAA_SERVICE_PROVIDER_H

#include "crypto.h"
#include "trusted_module.h"

struct service_provider;

struct service_provider *sp_new(const void *key, size_t keylen, int logleaves);
struct tm_cert sp_request(struct service_provider *sp,
                          const struct user_request *req, hash_t req_hmac,
                          hash_t *hmac_out,
                          struct tm_cert *vr_out, hash_t *vr_hmac,
                          hash_t *ack_hmac);

void sp_test(void);

#endif
