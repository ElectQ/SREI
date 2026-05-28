#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef void CURL;
typedef int CURLcode;
typedef int CURLINFO;

extern CURL *curl_easy_init(void);
extern CURLcode curl_easy_setopt(CURL *, int, ...);
extern CURLcode curl_easy_perform(CURL *);
extern CURLcode curl_easy_getinfo(CURL *, CURLINFO, void *);
extern const char *curl_easy_strerror(CURLcode);
extern void curl_easy_cleanup(CURL *);
extern CURLcode curl_global_init(int);
extern void curl_global_cleanup(void);
extern const char *curl_version(void);

static int g_ok = 0;
static int g_fail = 0;
static size_t g_downloaded;

__attribute__((constructor))
static void curl_ctor(void) { g_ok = 0; g_fail = 0; g_downloaded = 0; }

static size_t write_cb(void *ptr, size_t size, size_t nmemb, void *data) {
    (void)data;
    g_downloaded += size * nmemb;
    return size * nmemb;
}

static int test_version(void) {
    const char *ver = curl_version();
    if (!ver) {
        printf("[curl] curl_version returned NULL\n");
        return 0;
    }
    printf("[curl] version: %s\n", ver);
    return 1;
}

static int test_http_get(void) {
    CURL *curl = curl_easy_init();
    if (!curl) {
        printf("[curl] curl_easy_init failed\n");
        return 0;
    }

    CURLcode rc;

    /* CURLOPT_URL = 10002 */
    rc = curl_easy_setopt(curl, 10002, "http://example.com");

    /* CURLOPT_WRITEFUNCTION = 20011 */
    typedef size_t (*write_fn)(void *, size_t, size_t, void *);
    rc = curl_easy_setopt(curl, 20011, (write_fn)write_cb);

    /* CURLOPT_TIMEOUT = 13 */
    rc = curl_easy_setopt(curl, 13, (long)10);

    /* CURLOPT_NOSIGNAL = 99 */
    rc = curl_easy_setopt(curl, 99, (long)1);

    (void)rc;

    g_downloaded = 0;
    printf("[curl] fetching http://example.com ...\n");
    rc = curl_easy_perform(curl);
    if (rc != 0) {
        printf("[curl] curl_easy_perform failed (%d): %s\n",
               rc, curl_easy_strerror(rc));
        curl_easy_cleanup(curl);
        return 0;
    }

    long http_code = 0;
    curl_easy_getinfo(curl, 0x200002, &http_code);
    printf("[curl] HTTP %ld, downloaded %zu bytes\n", http_code, g_downloaded);

    curl_easy_cleanup(curl);

    if (http_code != 200 && http_code != 301 && http_code != 302) {
        printf("[curl] unexpected HTTP code\n");
        return 0;
    }

    return 1;
}

void curl_run(const void *user_data, unsigned int user_data_len) {
    printf("[curl] === libcurl real-world test ===\n");
    if (user_data && user_data_len > 0)
        printf("[curl] user_data: %.*s\n", user_data_len, (const char *)user_data);

    curl_global_init(3);

    if (test_version()) g_ok++; else g_fail++;
    if (test_http_get()) g_ok++; else g_fail++;

    curl_global_cleanup();

    printf("[curl] results: %d passed, %d failed\n", g_ok, g_fail);
}
