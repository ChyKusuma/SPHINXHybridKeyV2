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


#ifndef SPHINX_HYBRID_KEY_HPP
#define SPHINX_HYBRID_KEY_HPP

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
    void performX448KeyExchange(unsigned char shared_key[56], const unsigned char private_key[56], const unsigned char public_key[56]);

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
    HybridKeypair generate_hybrid_keypair();

    // Function to derive the master private key and chain code
    std::pair<std::string, std::string> deriveMasterKeyAndChainCode(const std::string& seed);

    // Function to derive a key using HMAC-SHA512
    std::string deriveKeyHMAC_SHA512(const std::string& key, const std::string& data);

    // Function to calculate the SWIFFTX-512 hash of a string
    std::string hashSWIFFTX512(const std::string& data);

    // Function to generate a random nonce
    std::string generateRandomNonce();

    // Function to derive a key using HKDF
    std::string deriveKeyHKDF(const std::string& inputKeyMaterial, const std::string& salt, const std::string& info, size_t keyLength);

    // Function to calculate the SWIFFTX-256 hash of a string
    std::string hash(const std::string& input);

    // Function to generate a key pair
    std::pair<std::string, std::string> generateKeyPair();

    // Function to generate an address from a public key
    std::string generateAddress(const std::string& publicKey);

    // Function to request a digital signature
    std::string requestDigitalSignature(const std::string& data, const HybridKeypair& hybrid_keypair);

    // Function to encrypt a message using Kyber1024 KEM
    std::string encryptMessage(const std::string& message, const std::vector<uint8_t>& public_key_pke);

    // Function to decrypt a message using Kyber1024 KEM
    std::string decryptMessage(const std::string& encrypted_message, const std::vector<uint8_t>& secret_key_pke);

    // Function to encapsulate a shared secret using the hybrid KEM
    std::string encapsulateHybridSharedSecret(const HybridKeypair& hybrid_keypair, std::vector<uint8_t>& encapsulated_key);

    // Function to decapsulate a shared secret using the hybrid KEM
    std::string decapsulateHybridSharedSecret(const HybridKeypair& hybrid_keypair, const std::vector<uint8_t>& encapsulated_key);

}  // namespace SPHINXHybridKey

#endif  // SPHINX_HYBRID_KEY_HPP