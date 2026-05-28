#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/md5.h>

static int g_tests_passed = 0;
static int g_tests_failed = 0;

__attribute__((constructor))
static void crypto_ctor(void) {
    g_tests_passed = 0;
    g_tests_failed = 0;
}

static int test_sha256(void) {
    const unsigned char msg[] = "hello SREI crypto test";
    unsigned char hash[SHA256_DIGEST_LENGTH];
    unsigned int hash_len = 0;

    EVP_MD_CTX *ctx = EVP_MD_CTX_create();
    if (!ctx) return 0;

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_destroy(ctx);
        return 0;
    }
    if (EVP_DigestUpdate(ctx, msg, strlen((const char *)msg)) != 1) {
        EVP_MD_CTX_destroy(ctx);
        return 0;
    }
    if (EVP_DigestFinal_ex(ctx, hash, &hash_len) != 1) {
        EVP_MD_CTX_destroy(ctx);
        return 0;
    }
    EVP_MD_CTX_destroy(ctx);

    if (hash_len != 32) return 0;

    printf("[crypto] SHA256(%s) = ", msg);
    for (unsigned int i = 0; i < hash_len; i++)
        printf("%02x", hash[i]);
    printf("\n");

    return 1;
}

static int test_aes(void) {
    unsigned char key[AES_BLOCK_SIZE * 2];
    unsigned char iv[AES_BLOCK_SIZE];
    unsigned char plaintext[] = "SREI reflective loading with AES-256-CBC encryption test!";
    unsigned char ciphertext[256];
    unsigned char decrypted[256];
    int ct_len = 0, pt_len = 0;

    memset(key, 0x42, sizeof(key));
    memset(iv, 0x13, sizeof(iv));

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    if (EVP_EncryptUpdate(ctx, ciphertext, &ct_len, plaintext,
                          (int)strlen((const char *)plaintext)) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    int final_len = 0;
    if (EVP_EncryptFinal_ex(ctx, ciphertext + ct_len, &final_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    ct_len += final_len;
    EVP_CIPHER_CTX_free(ctx);

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    if (EVP_DecryptUpdate(ctx, decrypted, &pt_len, ciphertext, ct_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    if (EVP_DecryptFinal_ex(ctx, decrypted + pt_len, &final_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    pt_len += final_len;
    EVP_CIPHER_CTX_free(ctx);

    decrypted[pt_len] = '\0';
    if (strcmp((const char *)plaintext, (const char *)decrypted) != 0) {
        printf("[crypto] AES roundtrip FAILED\n");
        printf("  expected: %s\n", plaintext);
        printf("  got:      %s\n", decrypted);
        return 0;
    }

    printf("[crypto] AES-256-CBC encrypt(%d bytes) -> decrypt(%d bytes) OK\n",
           (int)strlen((const char *)plaintext), pt_len);
    return 1;
}

static int test_md5(void) {
    unsigned char digest[16];
    const char *msg = "reflective crypto";
    unsigned int dlen = 0;

    EVP_MD_CTX *ctx = EVP_MD_CTX_create();
    if (!ctx) return 0;

    EVP_DigestInit_ex(ctx, EVP_md5(), NULL);
    EVP_DigestUpdate(ctx, msg, strlen(msg));
    EVP_DigestFinal_ex(ctx, digest, &dlen);
    EVP_MD_CTX_destroy(ctx);

    if (dlen != 16) return 0;

    printf("[crypto] MD5(%s) = ", msg);
    for (unsigned int i = 0; i < dlen; i++)
        printf("%02x", digest[i]);
    printf("\n");

    return 1;
}

void crypto_run(const void *user_data, unsigned int user_data_len) {
    printf("[crypto] === libcrypto real-world test ===\n");
    if (user_data && user_data_len > 0)
        printf("[crypto] user_data: %.*s\n", user_data_len, (const char *)user_data);

    if (test_sha256()) g_tests_passed++; else g_tests_failed++;
    if (test_aes())    g_tests_passed++; else g_tests_failed++;
    if (test_md5())    g_tests_passed++; else g_tests_failed++;

    printf("[crypto] results: %d passed, %d failed\n",
           g_tests_passed, g_tests_failed);
}
