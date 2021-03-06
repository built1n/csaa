#include <stdio.h>

#include "crypto.h"
#include "service_provider.h"
#include "trusted_module.h"

void check(const char *name, int condition)
{
    printf("%s: %s", name, condition ? "\033[32;1mPASS\033[0m\n" : "\033[31;1mFAIL\033[0m\n");
#if 0
    if(!condition)
    {
        printf("%s\n", tm_geterror());
        tm_seterror(NULL);
    }
#endif
}
