#include <stdio.h>
#include <string.h>
#include <zlib.h>

__attribute__((constructor))
void zlib_test_init(void)
{
    puts("[zlib_test] constructor called");
}

int zlib_test_run(const char *msg, unsigned int msg_len)
{
    unsigned char buf[256];
    unsigned char out[256];
    uLongf dest_len = sizeof(buf);
    uLong src_len = (uLong)msg_len;

    printf("[zlib_test] input: \"%s\" (%u bytes)\n", msg, msg_len);

    if (compress(buf, &dest_len, (const Bytef *)msg, src_len) != Z_OK) {
        printf("[zlib_test] compress failed\n");
        return -1;
    }
    printf("[zlib_test] compressed: %lu bytes\n", (unsigned long)dest_len);

    uLongf out_len = sizeof(out);
    if (uncompress(out, &out_len, buf, dest_len) != Z_OK) {
        printf("[zlib_test] uncompress failed\n");
        return -2;
    }
    out[out_len] = '\0';
    printf("[zlib_test] decompressed: \"%s\" (%lu bytes)\n", out, (unsigned long)out_len);

    if (out_len == src_len && memcmp(out, msg, src_len) == 0) {
        printf("[zlib_test] PASS — roundtrip OK\n");
        return 0;
    }
    printf("[zlib_test] FAIL — data mismatch\n");
    return -3;
}
