#include <stdio.h>

__attribute__((constructor))
void payload_init(void)
{
    puts("[payload] constructor called");
}

int payload_run(const char *msg, unsigned int len)
{
    printf("[payload] run: \"%s\" (%u)\n", msg, len);
    return 42;
}
