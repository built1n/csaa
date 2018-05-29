/* implementation of a basic service provider for use with the trusted
 * module */

#ifndef CSAA_SERVICE_PROVIDER_H
#define CSAA_SERVICE_PROVIDER_H

#include "crypto.h"

struct iomt_node {
    int idx, next_idx; /* idx cannot be zero */
    hash_t value; /* all zero indicates placeholder */
};

struct service_provider;

#endif
