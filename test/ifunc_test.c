#include <string.h>
#include <stdio.h>

__attribute__((constructor))
void ifunc_test_init(void) {
    printf("[ifunc_test] constructor\n");
}

void ifunc_test_run(const void *msg, int len) {
    volatile char buf[512];
    memset((void *)buf, 0, 512);
    memcpy((void *)buf, msg, (size_t)len);
    volatile size_t slen = strlen((const char *)buf);
    printf("[ifunc_test] run: \"%s\" (%zu/%d)\n",
           (const char *)buf, (size_t)slen, len);
}
