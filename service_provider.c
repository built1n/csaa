/* implementation of a basic service provider for use with the trusted
 * module */

#include "service_provider.h"
#include "trusted_module.h"
#include "crypto.h"

struct service_provider {
    struct trusted_module *tm;
};
