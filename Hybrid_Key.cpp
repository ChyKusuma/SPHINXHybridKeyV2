/*
 *  Copyright (c) (2023) SPHINX_ORG
 *  Authors:
 *    - (C kusuma) <thekoesoemo@gmail.com>
 *      GitHub: (https://github.com/chykusuma)
 *  Contributors:
 *    - (Contributor 1) <email1@example.com>
 *      Github: (https://github.com/yourgit)
 *    - (Contributor 2) <email2@example.com>
 *      Github: (https://github.com/yourgit)
 */



/////////////////////////////////////////////////////////////////////////////////////////////////////////
// The code provided belongs to the SPHINXHybridKey namespace and contains various functions and a structure related to hybrid key operations using different cryptographic algorithms. Let's go through each part of the code to understand its functionality:

// performX448KeyExchange:
    // This function performs the X448 key exchange by utilizing the curve448_keypair and curve448_scalarmult functions. It takes private and public keys as input and computes the shared key.

// HybridKeypair structure:
    // This structure holds the merged keypair information.
    // It has the following members:
        // merged_key: A nested structure that stores the Kyber1024 keypair (kyber_public_key and kyber_private_key).
        // x448_key: A pair of vectors (first and second) to store the Curve448 keypair.
        // public_key_pke: A vector to hold the public key for PKE (Public Key Encryption).
        // secret_key_pke: A vector to hold the secret key for PKE.
        // prng: An instance of the kyber1024_pke::RandomNumberGenerator for key generation.

// generate_hybrid_keypair:
    // This function generates a hybrid keypair.
    // It generates the Kyber1024 keypair using the keygen function and stores it in merged_key.kyber_public_key and merged_key.kyber_private_key.
    // It generates the Curve448 keypair using the curve448_keypair function and stores it in x448_key.
    // It resizes the PKE keypair vectors (public_key_pke and secret_key_pke) and generates the PKE keypair using the keygen function.

// deriveMasterKeyAndChainCode:
    // This function derives the master private key and chain code from a given seed.
    // It uses the deriveKeyHMAC_SWIFFTX function to derive the master private key and chain code based on the seed.
    // It returns the derived master private key and chain code as a pair of strings.

// deriveKeyHMAC_SHA512:
    // This function derives a key using HMAC-SHA512.
    // It takes a key and data as input and performs HMAC-SHA512 hashing using the provided key and data.
    // It returns the derived key as a string.
    // hashSWIFFTX512:
        // This function calculates the SWIFFTX-512 hash of a string.
        // It initializes the hash state, updates it with the input data, and finalizes the hash.
        // It returns the hashed data as a string.

// generateRandomNonce:
    // This function generates a random nonce using the SPHINXUtils::generateRandomNonce function.
    // It returns the generated nonce as a string.

// deriveKeyHKDF:
    // This function derives a key using the HKDF (HMAC-based Key Derivation Function) algorithm.
    // It takes the input key material, salt, info, and key length as input.
    // It uses the EVP_PKEY functions to perform HKDF with SHA256.
    // It returns the derived key as a compressed key (SPHINX-256 hash) in a string.
    // hash:
        // This function calculates the SWIFFTX-256 hash of a string.
        // It uses the SPHINXHash::SPHINX_256 function to compute the hash.
        // It returns the hashed data as a string.

// generateKeyPair:
    // This function generates a key pair.
    // It generates a random private key and computes the public key by hashing the private key.
    // It returns the key pair as a pair of strings (private key and public key).

// generateAddress:
    // This function generates an address from a given public key.
    // It computes the hash of the public key and returns the first 20 characters of the hash as the address.

// requestDigitalSignature:
    // This function requests a digital signature for a given data using the hybrid keypair.
    // It uses the SPHINXSign::verify_data function to generate the signature.
    // It returns the signature as a string.

// encryptMessage:
    // This function encrypts a message using Kyber1024 KEM (Key Encapsulation Mechanism).
    // It takes a message and a public key for PKE as input.
    // It generates a random nonce and uses the cpapke::encrypt function to encrypt the message.
    // It returns the encrypted message as a string.

// decryptMessage:
    // This function decrypts an encrypted message using Kyber1024 KEM.
    // It takes the encrypted message and the secret key for PKE as input.
    // It uses the cpapke::decrypt function to decrypt the message.
    // It returns the decrypted message as a string.

// encapsulateHybridSharedSecret:
    // This function encapsulates a shared secret using the hybrid KEM (Key Encapsulation Mechanism).
    // It takes the hybrid keypair and a vector to store the encapsulated key as input.
    // It performs the X448 key exchange and the Kyber1024 encapsulation to derive the shared secret and encapsulated key.
    // It returns the shared secret as a string.

// decapsulateHybridSharedSecret:
    // This function decapsulates a shared secret using the hybrid KEM.
    // It takes the hybrid keypair and the encapsulated key as input.
    // It performs the X448 key exchange and the Kyber1024 decapsulation to derive the shared secret.
    // It checks if the derived shared secret matches the provided shared secret and throws an error if they don't match.
    // It returns the shared secret as a string.

// This code provides functions for generating and manipulating hybrid keypairs using Curve448 and Kyber1024 algorithms. It also includes functions for key derivation, hashing, encryption, decryption, and digital signatures.
////////////////////////////////////////////////////////////////////////////////////////////////////////



#include <utility>
#include <array>
#include <iostream>
#include <algorithm>
#include <random>
#include <string>
#include <vector>
#include <cstdint>

#include "lib/Openssl/evp.h"
#include "lib/Openssl/hkdf.h" 
#include "lib/Openssl/hmac.h"
#include "lib/Openssl/curve448/point_448.h"
#include "lib/Openssl/sha.h"
#include "lib/Swifftx/SHA3.h"
#include "lib/Kyber/include/kyber1024_kem.hpp"
#include "lib/Kyber/include/kyber1024_pke.hpp"
#include "lib/Kyber/include/encapsulation.hpp"
#include "lib/Kyber/include/decapsulation.hpp"
#include "lib/Kyber/include/encryption.hpp"
#include "lib/Kyber/include/compression.hpp"


#include "Hash.hpp"
#include "Key.hpp"


namespace SPHINXHybridKey {

    // Function to perform the X448 key exchange
    void performX448KeyExchange(unsigned char shared_key[56], const unsigned char private_key[56], const unsigned char public_key[56]) {
        curve448_keypair(shared_key, private_key);
        curve448_scalarmult(shared_key, shared_key, public_key);
    }

    // Structure to hold the merged keypair
    struct HybridKeypair {
        struct {
            // Kyber1024 keypair
            kyber1024_kem::PublicKey kyber_public_key;
            kyber1024_kem::PrivateKey kyber_private_key;
        } merged_key;

        // X448 keypair
        std::pair<std::vector<unsigned char>, std::vector<unsigned char>> x448_key;

        // PKE keypair
        std::vector<uint8_t> public_key_pke;
        std::vector<uint8_t> secret_key_pke;

        // PRNG for key generation
        kyber1024_pke::RandomNumberGenerator prng;
    };

    // Function to generate the hybrid keypair
    HybridKeypair generate_hybrid_keypair() {
        HybridKeypair hybrid_keypair;

        // Generate Kyber1024 keypair for KEM
        hybrid_keypair.merged_key.kyber_public_key = kyber1024_kem::keygen(hybrid_keypair.merged_key.kyber_private_key);

        // Generate X448 keypair
        hybrid_keypair.x448_key.first.resize(56);
        hybrid_keypair.x448_key.second.resize(56);
        curve448_keypair(hybrid_keypair.x448_key.first.data(), hybrid_keypair.x448_key.second.data());

        // Resize PKE keypair vectors
        hybrid_keypair.public_key_pke.resize(kyber1024_pke::pub_key_len());
        hybrid_keypair.secret_key_pke.resize(kyber1024_pke::sec_key_len());

        // Generate PKE keypair
        kyber1024_pke::keygen(hybrid_keypair.prng, hybrid_keypair.public_key_pke.data(), hybrid_keypair.secret_key_pke.data());

        return hybrid_keypair;
    }

    // Function to derive the master private key and chain code
    std::pair<std::string, std::string> deriveMasterKeyAndChainCode(const std::string& seed) {
        std::string masterPrivateKey = deriveKeyHMAC_SWIFFTX("Sphinx seed", seed);
        std::string chainCode = deriveKeyHMAC_SWIFFTX("Sphinx chain code", seed);

        return std::make_pair(masterPrivateKey, chainCode);
    }

    // Function to derive a key using HMAC-SHA512
    std::string deriveKeyHMAC_SHA512(const std::string& key, const std::string& data) {
        HMAC_SHA512_CTX ctx;
        HMAC_SHA512_Init(&ctx);
        HMAC_SHA512_Update(&ctx, reinterpret_cast<const unsigned char*>(key.data()), key.length());
        HMAC_SHA512_Update(&ctx, reinterpret_cast<const unsigned char*>(data.data()), data.length());

        unsigned char hmacResult[HMAC_SHA512_DIGEST_LENGTH];
        HMAC_SHA512_Final(hmacResult, &ctx);

        std::string derivedKey;
        for (size_t i = 0; i < HMAC_SHA512_DIGEST_LENGTH; i++) {
            derivedKey += static_cast<char>(hmacResult[i]);
        }

        return derivedKey;
    }

    // Function to calculate the SWIFFTX-512 hash of a string
    std::string hashSWIFFTX512(const std::string& data) {
        hashState state;
        SWIFFTX512_Init(&state);
        SWIFFTX512_Update(&state, reinterpret_cast<const BitSequence*>(data.data()), data.length() * 8);
        BitSequence hashResult[SWIFFTX_OUTPUT_BLOCK_SIZE];
        SWIFFTX512_Final(&state, hashResult);

        std::string hashedData;
        for (size_t i = 0; i < SWIFFTX_OUTPUT_BLOCK_SIZE; i++) {
            hashedData += static_cast<char>(hashResult[i]);
        }

        return hashedData;
    }

    // Function to generate a random nonce
    std::string generateRandomNonce() {
        return SPHINXUtils::generateRandomNonce();
    }

    // Function to derive a key using HKDF
    std::string deriveKeyHKDF(const std::string& inputKeyMaterial, const std::string& salt, const std::string& info, size_t keyLength) {
        std::string derivedKey(keyLength, 0);

        EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
        EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256());
        EVP_PKEY_CTX_set1_hkdf_salt(pctx, reinterpret_cast<const uint8_t*>(salt.data()), salt.length());
        EVP_PKEY_CTX_set1_hkdf_key(pctx, reinterpret_cast<const uint8_t*>(inputKeyMaterial.data()), inputKeyMaterial.length());
        EVP_PKEY_CTX_add1_hkdf_info(pctx, reinterpret_cast<const uint8_t*>(info.data()), info.length());
        EVP_PKEY_CTX_set1_hkdf_size(pctx, keyLength);
        EVP_PKEY_derive(pctx, reinterpret_cast<uint8_t*>(derivedKey.data()), &keyLength);
        EVP_PKEY_CTX_free(pctx);

        std::string compressedKey = SPHINXHash::SPHINX_256(derivedKey);

        return compressedKey;
    }

    // Function to calculate the SWIFFTX-256 hash of a string
    std::string hash(const std::string& input) {
        return SPHINXHash::SPHINX_256(input);
    }

    // Function to generate a key pair
    std::pair<std::string, std::string> generateKeyPair() {
        std::string privateKey = generateRandomNonce();
        std::string publicKey = hash(privateKey);

        return {privateKey, publicKey};
    }

    // Function to generate an address from a public key
    std::string generateAddress(const std::string& publicKey) {
        std::string hash = hash(publicKey);
        std::string address = hash.substr(0, 20);

        return address;
    }

    // Function to request a digital signature
    std::string requestDigitalSignature(const std::string& data, const HybridKeypair& hybrid_keypair) {
        std::string signature = SPHINXSign::verify_data(data, hybrid_keypair.secret_key_pke.data());

        return signature;
    }

    // Function to encrypt a message using Kyber1024 KEM
    std::string encryptMessage(const std::string& message, const std::vector<uint8_t>& public_key_pke) {
        constexpr size_t tagLength = 16;

        std::string encrypted_message(kyber1024_pke::cipher_text_len() + tagLength, 0);

        std::string nonce = generateRandomNonce();

        cpapke::encrypt<1, kyber1024_kem::eta1, kyber1024_kem::eta2, kyber1024_kem::du, kyber1024_kem::dv>(
            public_key_pke.data(),
            reinterpret_cast<const uint8_t*>(message.data()),
            reinterpret_cast<const uint8_t*>(nonce.data()),
            reinterpret_cast<uint8_t*>(encrypted_message.data()),
            reinterpret_cast<uint8_t*>(encrypted_message.data()) + kyber1024_pke::cipher_text_len(),
            tagLength
        );

        return encrypted_message;
    }

    // Function to decrypt a message using Kyber1024 KEM
    std::string decryptMessage(const std::string& encrypted_message, const std::vector<uint8_t>& secret_key_pke) {
        constexpr size_t tagLength = 16;

        std::string decrypted_message(kyber1024_pke::cipher_text_len(), 0);

        cpapke::decrypt<1, kyber1024_kem::du, kyber1024_kem::dv>(
            secret_key_pke.data(),
            reinterpret_cast<const uint8_t*>(encrypted_message.data()),
            reinterpret_cast<const uint8_t*>(encrypted_message.data()) + kyber1024_pke::cipher_text_len(),
            tagLength,
            reinterpret_cast<uint8_t*>(decrypted_message.data())
        );

        return decrypted_message;
    }

    // Function to encapsulate a shared secret using the hybrid KEM
    std::string encapsulateHybridSharedSecret(const HybridKeypair& hybrid_keypair, std::vector<uint8_t>& encapsulated_key) {
        unsigned char x448_private_key[56];
        curve448_keypair(hybrid_keypair.x448_key.first.data(), x448_private_key);

        unsigned char shared_secret[56];
        performX448KeyExchange(shared_secret, x448_private_key, hybrid_keypair.merged_key.kyber_public_key.data());

        kyber1024_kem::encapsulate(encapsulated_key.data(), hybrid_keypair.x448_key.first.data(), hybrid_keypair.merged_key.kyber_public_key.data(), hybrid_keypair.merged_key.kyber_private_key.data());

        return std::string(shared_secret, shared_secret + sizeof(shared_secret));
    }

    // Function to decapsulate a shared secret using the hybrid KEM
    std::string decapsulateHybridSharedSecret(const HybridKeypair& hybrid_keypair, const std::vector<uint8_t>& encapsulated_key) {
        unsigned char x448_public_key[56];
        unsigned char shared_secret[56];
        kyber1024_kem::decapsulate(x448_public_key, shared_secret, encapsulated_key.data(), hybrid_keypair.merged_key.kyber_private_key.data());

        unsigned char derived_shared_secret[56];
        performX448KeyExchange(derived_shared_secret, hybrid_keypair.x448_key.second.data(), x448_public_key);

        if (std::memcmp(shared_secret, derived_shared_secret, sizeof(shared_secret)) != 0) {
            throw std::runtime_error("Shared secret mismatch");
        }

        return std::string(shared_secret, shared_secret + sizeof(shared_secret));
    }

}  // namespace SPHINXHybridKey