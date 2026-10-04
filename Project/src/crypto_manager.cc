#include "crypto_manager.h"
#include <string.h>

CryptoManager::CryptoManager() : isKeyInitialized_(false), isInitialized_(false) {
    mbedtls_gcm_init(&gcmContext_);
    mbedtls_ecdh_init(&ecdhContext_);
    mbedtls_entropy_init(&entropyContext_);
    mbedtls_ctr_drbg_init(&ctrDrbgContext_);
    memset(aesKey_, 0, sizeof(aesKey_));
}

CryptoManager::~CryptoManager() {
    mbedtls_gcm_free(&gcmContext_);
    mbedtls_ecdh_free(&ecdhContext_);
    mbedtls_ctr_drbg_free(&ctrDrbgContext_);
    mbedtls_entropy_free(&entropyContext_);
}

bool CryptoManager::Initialize() {
    const char* personalization = "IoT_Secure_P2P_ESP32";
    
    // Seed the random number generator
    int ret = mbedtls_ctr_drbg_seed(&ctrDrbgContext_, mbedtls_entropy_func, &entropyContext_,
                                    reinterpret_cast<const unsigned char*>(personalization),
                                    strlen(personalization));
    if (ret != 0) {
        return false;
    }

    // Initialize ECDH context with standard NIST P-256 (secp256r1)
    ret = mbedtls_ecp_group_load(&ecdhContext_.grp, MBEDTLS_ECP_DP_SECP256R1);
    if (ret != 0) {
        return false;
    }

    isInitialized_ = true;
    return true;
}

bool CryptoManager::GenerateEcdhKeyPair(uint8_t* publicKeyOutput, size_t* publicKeyLength) {
    if (!isInitialized_ || publicKeyOutput == nullptr || publicKeyLength == nullptr) {
        return false;
    }

    // Generate local ECDH private/public key pair
    if (mbedtls_ecdh_gen_public(&ecdhContext_.grp, &ecdhContext_.d, &ecdhContext_.Q,
                                mbedtls_ctr_drbg_random, &ctrDrbgContext_) != 0) {
        return false;
    }

    // Export public key point Q to binary format
    size_t olen = 0;
    if (mbedtls_ecp_point_write_binary(&ecdhContext_.grp, &ecdhContext_.Q,
                                       MBEDTLS_ECP_PF_UNCOMPRESSED,
                                       &olen, publicKeyOutput, 65) != 0) {
        return false;
    }

    *publicKeyLength = olen;
    return true;
}

bool CryptoManager::ComputeSharedSecret(const uint8_t* peerPublicKey, size_t peerPublicKeyLength) {
    if (!isInitialized_ || peerPublicKey == nullptr || peerPublicKeyLength == 0) {
        return false;
    }

    // Read peer's public key point into our ECDH context
    if (mbedtls_ecp_point_read_binary(&ecdhContext_.grp, &ecdhContext_.Qp,
                                       peerPublicKey, peerPublicKeyLength) != 0) {
        return false;
    }

    // Calculate raw shared secret z
    size_t secretLen = 0;
    unsigned char rawSecret[32];
    if (mbedtls_ecdh_calc_secret(&ecdhContext_, &secretLen, rawSecret, sizeof(rawSecret),
                                 mbedtls_ctr_drbg_random, &ctrDrbgContext_) != 0) {
        return false;
    }

    // Derive 128-bit AES session key using the first 16 bytes of the shared secret (or SHA-256 truncation)
    memcpy(aesKey_, rawSecret, 16);

    // Initialize AES-GCM context with our newly derived session key
    if (mbedtls_gcm_setkey(&gcmContext_, MBEDTLS_CIPHER_ID_AES, aesKey_, 128) != 0) {
        return false;
    }

    isKeyInitialized_ = true;
    return true;
}

bool CryptoManager::Encrypt(const uint8_t* plaintext, size_t plaintextLength,
                            const uint8_t* nonce, size_t nonceLength,
                            uint8_t* ciphertext, uint8_t* tagOutput) {
    // Fallback to static pre-shared key if ECDH hasn't been negotiated yet (for initial testing compatibility)
    if (!isKeyInitialized_) {
        const uint8_t defaultKey[16] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F};
        mbedtls_gcm_setkey(&gcmContext_, MBEDTLS_CIPHER_ID_AES, defaultKey, 128);
        isKeyInitialized_ = true;
    }

    int result = mbedtls_gcm_crypt_and_tag(&gcmContext_, MBEDTLS_GCM_ENCRYPT, plaintextLength,
                                           nonce, nonceLength, nullptr, 0,
                                           plaintext, ciphertext, 16, tagOutput);
    return (result == 0);
}

bool CryptoManager::Decrypt(const uint8_t* ciphertext, size_t ciphertextLength,
                            const uint8_t* nonce, size_t nonceLength,
                            const uint8_t* tag, size_t tagLength,
                            uint8_t* plaintextOutput) {
    if (!isKeyInitialized_) {
        const uint8_t defaultKey[16] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F};
        mbedtls_gcm_setkey(&gcmContext_, MBEDTLS_CIPHER_ID_AES, defaultKey, 128);
        isKeyInitialized_ = true;
    }

    int result = mbedtls_gcm_auth_decrypt(&gcmContext_, ciphertextLength,
                                          nonce, nonceLength, nullptr, 0,
                                          tag, tagLength,
                                          ciphertext, plaintextOutput);
    return (result == 0);
}