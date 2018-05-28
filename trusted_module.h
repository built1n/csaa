/* interface to the trusted module */

#include <stddef.h>

struct trusted_module;

/* dynamically allocated */
struct trusted_module *tm_new(const char *key, size_t keylen);
void tm_free(struct trusted_module *tm);
void tm_test(void);
