#include <unistd.h>

int run(const char *msg, unsigned int len)
{
    write(1, "[payload] ", 10);
    write(1, msg, len);
    write(1, "\n", 1);
    return 0;
}
