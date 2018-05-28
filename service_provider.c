/* implementation of a basic service provider for use with the trusted
 * module */

#include "service_provider.h"
#include "trusted_module.h"
#include "crypto.h"

struct iomt_node {
    int idx, next_idx; /* idx cannot be zero */
    hash_t value; /* all zero indicates placeholder */
};

struct service_provider {
    struct trusted_module *tm;


};
