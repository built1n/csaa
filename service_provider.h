/* implementation of a basic service provider for use with the trusted
 * module */

#ifndef CSAA_SERVICE_PROVIDER_H
#define CSAA_SERVICE_PROVIDER_H

#include "crypto.h"
#include "trusted_module.h"

struct service_provider;

struct user_request {
    int idx;
    int id; /* user id */
    enum { ACL_UPDATE, FILE_UPDATE } type;
    int counter;
    hash_t val; /* for ACL update, val=[root of ACL IOMT], for file
                 * update, val is a commitment to the contents, key,
                 * and index of the file */
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

struct service_provider *sp_new(const void *key, size_t keylen);
void sp_request(struct service_provider *sp, const struct user_request *req, hash_t hmac);

#endif
