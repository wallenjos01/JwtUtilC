#include "util.hpp"

#include <jwt/key.h>
#include <jwt/result.h>
#include <jwt/stream.h>

#include <openssl/core.h>
#include <openssl/evp.h>


namespace jwt::crypt {

class HmacContext {

public:

    HmacContext() = default;

    ~HmacContext() {
        if(_ctx) {
            EVP_MAC_CTX_free(_ctx);
            _ctx = nullptr;
        }
        if(_mac) {
            EVP_MAC_free(_mac);
            _mac = nullptr;
        }
    }

    JwtResult update(Span<uint8_t> input);
    JwtResult final(Span<uint8_t>* output);

    static JwtResult init(HmacContext* out, Span<uint8_t> key, const char* digest);

private:

    EVP_MAC_CTX* _ctx;
    EVP_MAC* _mac;

};

enum class CipherMode {
    DECRYPT = 0,
    ENCRYPT = 1
};

class AesContext {
public:

    AesContext() = default; 

    ~AesContext() {
        if(_ctx) {
            EVP_CIPHER_CTX_free(_ctx);
            _ctx = nullptr;
        }
    }

    JwtResult cipher(Span<uint8_t> input, Span<uint8_t> key, 
                     Span<uint8_t> iv, Span<uint8_t>* output, CipherMode mode);

    JwtResult cipherGcm(Span<uint8_t> input, Span<uint8_t> aad,
                        Span<uint8_t> key, Span<uint8_t> iv, Span<uint8_t>* output, 
                        Span<uint8_t>* tag, CipherMode mode);

    static JwtResult create(AesContext* out, const EVP_CIPHER* cipher);

private:

    EVP_CIPHER_CTX* _ctx;
    const EVP_CIPHER* _cipher;
};

class RsaContext {
public:

    RsaContext() = default;

    JwtResult sign(Span<uint8_t> data, const char* digest, Span<uint8_t>* signature, int32_t padding);
    JwtResult verify(Span<uint8_t> data, const char* digest, Span<uint8_t> signature, int32_t padding);

    JwtResult encrypt(Span<uint8_t> data, Span<uint8_t>* output, const OSSL_PARAM* params);
    JwtResult decrypt(Span<uint8_t> data, Span<uint8_t>* output, const OSSL_PARAM* params);
 
    static JwtResult init(RsaContext* out, EVP_PKEY* pkey);

private:
    EVP_PKEY* _pkey;

};

class EcContext {
public:

    JwtResult sign(Span<uint8_t> data, const char* digest, Span<uint8_t>* signature);
    JwtResult verify(Span<uint8_t> data, const char* digest, Span<uint8_t> signature);

    JwtResult diffieHelman(EVP_PKEY* peer, size_t keyLen, Span<uint8_t>* key);

    static JwtResult init(EcContext* out, EVP_PKEY* pkey);

private:
    EVP_PKEY* _pkey;

};


JwtResult getContextForCryptAlgorithm(JwtCryptAlgorithm alg, AesContext* ctx);



}
