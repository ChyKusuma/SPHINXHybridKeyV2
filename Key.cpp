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
// The provided code belongs to the SPHINXKey namespace and contains functions related to generating hybrid keypairs, performing key exchanges, generating addresses, calculating public keys, and printing key pair information. Let's go through each part of the code to understand its functionality:

// generate_hybrid_keypair:
    // This function generates a hybrid keypair.
    // It creates an instance of HybridKeypair struct and initializes it.
    // It generates the Kyber1024 key pair by calling the generate_kyber1024_key_pair function and assigns it to merged_key.kyber_private_key.
    // It generates the Kyber1024 public key from the private key by calling the kyber1024_kem::keygen function and assigns it to merged_key.kyber_public_key.
    // It generates the Curve448 key pair by calling the generate_curve448_key_pair function and assigns it to curve448_key.
    // It returns the generated hybrid keypair.

// generate_curve448_key_pair:
    // This function generates a Curve448 key pair.
    // It creates a pair of vectors (curve448_key) to hold the key pair.
    // It calls the curve448_generate_keypair function to generate the Curve448 key pair and stores the result in curve448_key.
    // It returns the generated Curve448 key pair.

// generate_kyber1024_key_pair:
    // This function generates a Kyber1024 key pair.
    // It creates a kyber1024_kem::PrivateKey object (private_key).
    // It calls the kyber1024_kem::keygen function to generate the Kyber1024 private key and assigns it to private_key.
    // It returns the generated Kyber1024 private key.

// merge_key_pair:
    // This function merges the Curve448 and Kyber1024 key pairs into a single hybrid keypair.
    // It takes the Curve448 key pair (curve448_key) and Kyber1024 private key (kyber_key) as input.
    // It creates an instance of HybridKeypair struct (hybrid_keypair).
    // It assigns the Curve448 key pair to hybrid_keypair.curve448_key.
    // It assigns the Kyber1024 private key to hybrid_keypair.merged_key.kyber_private_key.
    // It generates the Kyber1024 public key from the Kyber1024 private key by calling the kyber1024_kem::keygen function and assigns it to hybrid_keypair.merged_key.kyber_public_key.
    // It returns the merged hybrid keypair.

// performCurve448KeyExchange:
    // This function performs the Curve448 key exchange between a private key and a public key.
    // It takes the shared key array (shared_key), private key array (private_key), and public key array (public_key) as input.
    // It calls the curve448_keypair function to generate the shared key using the private key.
    // It then calls the curve448_scalarmult function to perform the scalar multiplication between the shared key and the public key, storing the result in the shared key array (shared_key).

// performHybridKeyExchange:
    // This function performs the hybrid key exchange combining Curve448 and Kyber1024.
    // It takes the shared key array (shared_key), Curve448 key pair (curve448_key), and Kyber1024 private key (kyber_key) as input.
    // It performs the Curve448 key exchange by calling the performCurve448KeyExchange function, passing the shared key array, Curve448 private key from curve448_key, and Kyber1024 private key (kyber_key.data()).
    // It performs the Kyber1024 KEM encapsulation by generating the Kyber1024 public key from the Kyber1024 private key using kyber1024_kem::keygen function, and calling the kyber1024_kem::encapsulate function, passing the shared key array, Curve448 public key from curve448_key, and Kyber1024 public key.
    // The resulting shared key is stored in the shared key array (shared_key).

// generate_and_perform_key_exchange:
    // This function generates a hybrid keypair and performs the key exchange.
    // It calls the generate_hybrid_keypair function to generate a hybrid keypair.
    // It then calls the performHybridKeyExchange function, passing the shared key array from the hybrid keypair, Curve448 key pair from the hybrid keypair, and Kyber1024 private key from the hybrid keypair.
    // Finally, it returns the generated hybrid keypair.

// generateAddress:
    // This function generates a smart contract address based on the public key and contract name.
    // It takes the public key and contract name as input.
    // It calculates the SPHINX-256 hash of the public key by calling the SPHINXHash::SPHINX_256 function.
    // It generates a unique identifier for the smart contract based on the contract name and public key hash.
    // It uses the contract identifier as the smart contract address and returns it.

// calculatePublicKey:
    // This function calculates the public key from the private key.
    // It takes the private key as input.
    // It converts the private key to bytes.
    // It generates the hybrid keypair by calling the generate_curve448_key_pair, generate_kyber1024_key_pair, and kyber1024_kem::keygen functions.
    // It merges the Curve448 and Kyber1024 key pairs into the hybrid keypair.
    // It gets the Curve448 public key from the hybrid keypair and calculates the SPHINX-256 hash of the Curve448 public key.
    // It returns the calculated public key.

// printKeyPair:
    // This function prints the key pair information.
    // It takes a hybrid keypair from the SPHINXHybridKey namespace as input.
    // It extracts the Kyber1024 public key from the merged key pair and prints it.
    // It generates the address using the extracted public key and the contract name "MyContract" by calling the generateAddress function.
    // It extracts the Kyber1024 public key and the Curve448 public key from the merged key pair and prints the merged public key (Kyber1024-Curve448).

// This code provides functions for generating and manipulating hybrid keypairs, performing key exchanges, generating addresses, calculating public keys, and printing key pair information.
////////////////////////////////////////////////////////////////////////////////////////////////////////


#include <string>
#include <vector>
#include <cstring>
#include <utility>
#include <iostream>

#include "Hybrid_key.hpp"
#include "Hash.hpp"


namespace SPHINXKey {

    // Function to generate the hybrid keypair
    HybridKeypair generate_hybrid_keypair() {
        HybridKeypair hybrid_keypair;

        // Generate the Kyber1024 key pair
        hybrid_keypair.merged_key.kyber_private_key = generate_kyber1024_key_pair();

        // Generate the Kyber1024 public key from the private key
        hybrid_keypair.merged_key.kyber_public_key = kyber1024_kem::keygen(hybrid_keypair.merged_key.kyber_private_key);

        // Generate the Curve448 key pair
        hybrid_keypair.curve448_key = generate_curve448_key_pair();

        return hybrid_keypair;
    }

    // Function to generate the Curve448 key pair
    std::pair<std::vector<unsigned char>, std::vector<unsigned char>> generate_curve448_key_pair() {
        std::pair<std::vector<unsigned char>, std::vector<unsigned char>> curve448_key;

        // Generate the Curve448 key pair using curve448_generate_keypair function
        curve448_generate_keypair(curve448_key.first.data(), curve448_key.second.data());
        
        return curve448_key;
    }

    // Function to generate the Kyber1024 key pair
    kyber1024_kem::PrivateKey generate_kyber1024_key_pair() {
        kyber1024_kem::PrivateKey private_key;

        // Generate the Kyber1024 private key using keygen function
        kyber1024_kem::keygen(private_key);
        
        return private_key;
    }

    // Function to merge the Curve448 and Kyber1024 key pairs
    HybridKeypair merge_key_pair(const std::pair<std::vector<unsigned char>, std::vector<unsigned char>>& curve448_key,
                                const kyber1024_kem::PrivateKey& kyber_key) {
        HybridKeypair hybrid_keypair;

        // Assign the Curve448 key pair to hybrid_keypair
        hybrid_keypair.curve448_key = curve448_key;

        // Assign the Kyber1024 private key to hybrid_keypair
        hybrid_keypair.merged_key.kyber_private_key = kyber_key;

        // Generate the Kyber1024 public key from the Kyber1024 private key
        hybrid_keypair.merged_key.kyber_public_key = kyber1024_kem::keygen(hybrid_keypair.merged_key.kyber_private_key);

        return hybrid_keypair;
    }

    // Function to perform the Curve448 key exchange
    void performCurve448KeyExchange(unsigned char shared_key[56], const unsigned char private_key[56], const unsigned char public_key[56]) {
        curve448_keypair(shared_key, private_key);
        curve448_scalarmult(shared_key, shared_key, public_key);
    }

    // Function to perform the hybrid key exchange combining Curve448 and Kyber1024
    void performHybridKeyExchange(unsigned char shared_key[32], const std::pair<std::vector<unsigned char>, std::vector<unsigned char>>& curve448_key,
                                 const kyber1024_kem::PrivateKey& kyber_key) {
        // Perform the Curve448 key exchange
        unsigned char curve448_shared_key[56];
        performCurve448KeyExchange(curve448_shared_key, curve448_key.first.data(), kyber_key.data());

        // Perform the Kyber1024 KEM encapsulation using kyber1024_kem::encapsulate function
        kyber1024_kem::PublicKey kyber_public_key = kyber1024_kem::keygen(kyber_key);
        kyber1024_kem::encapsulate(shared_key, curve448_key.second.data(), kyber_public_key.data());
    }

    // Function to generate the hybrid keypair and perform the key exchange
    HybridKeypair generate_and_perform_key_exchange() {
        HybridKeypair hybrid_keypair = generate_hybrid_keypair();

        // Perform the hybrid key exchange using the generated key pair
        performHybridKeyExchange(hybrid_keypair.merged_key.shared_key.data(), hybrid_keypair.curve448_key, hybrid_keypair.merged_key.kyber_private_key);

        return hybrid_keypair;
    }

    // Function to generate the smart contract address based on the public key and contract name
    std::string generateAddress(const std::string& publicKey, const std::string& contractName) {
        // Calculate the SPHINX-256 hash of the public key using SPHINXHash::SPHINX_256 function
        std::string hash = SPHINXHash::SPHINX_256(publicKey);

        // Generate a unique identifier for the smart contract based on the contract name and public key hash
        std::string contractIdentifier = contractName + "_" + hash;

        // Use the contract identifier as the smart contract address
        std::string address = contractIdentifier;

        return address;
    }

    // Function to calculate the public key from the private key
    std::string calculatePublicKey(const std::string& privateKey) {
        // Convert the private key to bytes
        std::vector<unsigned char> privateKeyBytes(privateKey.begin(), privateKey.end());

        // Generate the hybrid key pair
        HybridKeypair hybridKeyPair;
        hybridKeyPair.curve448_key = generate_curve448_key_pair();
        hybridKeyPair.merged_key.kyber_private_key = generate_kyber1024_key_pair();
        hybridKeyPair.merged_key.kyber_public_key = kyber1024_kem::keygen(hybridKeyPair.merged_key.kyber_private_key);

        // Merge the Curve448 and Kyber1024 key pairs
        hybridKeyPair.merged_key = merge_key_pair(hybridKeyPair.curve448_key, hybridKeyPair.merged_key.kyber_private_key);

        // Get the Curve448 public key from the hybrid key pair
        std::string curve448PublicKey(reinterpret_cast<const char*>(hybridKeyPair.curve448_key.first.data()), 56);

        // Calculate the SPHINX-256 hash of the Curve448 public key
        std::string calculatedPublicKey = SPHINXHash::SPHINX_256(curve448PublicKey);

        return calculatedPublicKey;
    }

    // Function to print the key pair information
    void printKeyPair(const SPHINXHybridKey::HybridKeypair& hybridKeyPair) {
        // Extract the public key from the merged key pair
        std::string mergedPublicKey(reinterpret_cast<const char*>(hybridKeyPair.merged_key.kyber_public_key.data()), kyber1024_kem::public_key_length);

        // Print the merged public key and address
        std::cout << "Merged Public key: " << mergedPublicKey << std::endl;
        std::cout << "Address: " << SPHINXHybridKey::generateAddress(mergedPublicKey, "MyContract") << std::endl;

        // Extract the Kyber1024 public key from the merged key pair
        std::string kyberPublicKey(reinterpret_cast<const char*>(hybridKeyPair.merged_key.kyber_public_key.k.data()), kyber1024_kem::public_key_length);

        // Extract the Curve448 public key from the merged key pair
        std::string curve448PublicKey(reinterpret_cast<const char*>(hybridKeyPair.curve448_key.first.data()), 56);

        // Print the merged public key (Kyber1024-Curve448)
        std::cout << "Merged Public key (Kyber1024-Curve448): " << kyberPublicKey + curve448PublicKey << std::endl;
    }
} // namespace SPHINXKey
