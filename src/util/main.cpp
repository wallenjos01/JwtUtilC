#include <openssl/bio.h>
#include <openssl/core.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include "../lib/util.hpp"

int main(int argc, char** argv) { 

    const char* keyData = 
        "-----BEGIN EC PRIVATE KEY-----\n"
        "MHcCAQEEICi+/J2GdB++ZgI8Y+gbvK8OnAfWluznoXbwFzjOUzlAoAoGCCqGSM49\n"
        "AwEHoUQDQgAErrwq+1lwloY2pjJQE/oapmXKOEMkDSu59hU3ROE/1vojUy6ykGni\n"
        "itba4iEXdYZxKEavbFPxHn1quBS/hRvAsQ==\n"
        "-----END EC PRIVATE KEY-----";

    const char* input = "Hello, World";

    BIO* mem;
    mem = BIO_new_mem_buf(keyData, -1);

    EVP_PKEY* pkey;
    pkey = PEM_read_bio_PrivateKey(mem, nullptr, nullptr, 0);

    OSSL_PARAM* params;
    EVP_PKEY_todata(pkey, EVP_PKEY_KEYPAIR, &params);

    printOsslParams(params);

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        perror("EVP_MD_CTX_new");
        EVP_PKEY_free(pkey);
        return 1;
    }

    // Initialize the signing operation (using SHA256)
    if (EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, pkey) <= 0) {
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return 1;
    }

    // Add data to sign
    if (EVP_DigestSignUpdate(ctx, input, strlen(input)) <= 0) {
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return 1;
    }

    // Determine required buffer length
    size_t siglen = 0;
    if (EVP_DigestSignFinal(ctx, NULL, &siglen) <= 0) {
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return 1;
    }

    unsigned char *sig = static_cast<unsigned char*>(OPENSSL_malloc(siglen));
    if (!sig) {
        perror("OPENSSL_malloc");
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return 1;
    }

    // Obtain the actual signature
    if (EVP_DigestSignFinal(ctx, sig, &siglen) <= 0) {
        ERR_print_errors_fp(stderr);
        OPENSSL_free(sig);
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return 1;
    }

    printf("Signature (%zu bytes):\n", siglen);
    for (size_t i = 0; i < siglen; i++)
        printf("%02x", sig[i]);
    printf("\n");

    // Cleanup
    OPENSSL_free(sig);
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    return 0; 
}
