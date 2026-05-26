#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

static char g_buf[256];

__attribute__((constructor))
void advanced_init(void)
{
    memset(g_buf, 0, sizeof(g_buf));
    snprintf(g_buf, sizeof(g_buf), "[advanced] initialized pid=%d", getpid());
    puts(g_buf);
}

int advanced_entry(const char *msg, unsigned int len)
{
    char *copy = malloc(len + 1);
    if (!copy) return -1;
    memcpy(copy, msg, len);
    copy[len] = '\0';

    printf("[advanced] entry: \"%s\" (len=%u, getpid=%d)\n", copy, len, getpid());
    printf("[advanced] g_buf = \"%s\"\n", g_buf);

    free(copy);
    return 42;
}
