#ifndef CRYPTO_MANAGER_H
#define CRYPTO_MANAGER_H

#include <stddef.h>
#include <stdint.h>
#include <mbedtls/gcm.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

class CryptoManager {
public:
    CryptoManager();
    ~CryptoManager();

    // Initializes mbedTLS AES-GCM and random generator contexts
    bool Initialize();

    // Generates an ephemeral ECDH key pair and exports the raw public key bytes (65 bytes uncompressed)
    bool GenerateEcdhKeyPair(uint8_t* publicKeyOutput, size_t* publicKeyLength);

    // Computes the shared secret using peer's public key and derives our AES session key
    bool ComputeSharedSecret(const uint8_t* peerPublicKey, size_t peerPublicKeyLength);

    // Encrypts plaintext and generates an authentication tag using AES-128-GCM
    bool Encrypt(const uint8_t* plaintext, size_t plaintextLength,
                 const uint8_t* nonce, size_t nonceLength,
                 uint8_t* ciphertext, uint8_t* tagOutput);

    // Decrypts ciphertext and verifies the authentication tag using AES-128-GCM
    bool Decrypt(const uint8_t* ciphertext, size_t ciphertextLength,
                 const uint8_t* nonce, size_t nonceLength,
                 const uint8_t* tag, size_t tagLength,
                 uint8_t* plaintextOutput);

private:
    mbedtls_gcm_context gcmContext_;
    mbedtls_ecdh_context ecdhContext_;
    mbedtls_entropy_context entropyContext_;
    mbedtls_ctr_drbg_context ctrDrbgContext_;
    
    uint8_t aesKey_[16]; // 128-bit AES session key derived from ECDH
    bool isKeyInitialized_;
    bool isInitialized_;
};

#endif // CRYPTO_MANAGER_H