# SPHINXHybridKeyV2


## Introduction

This project is dedicated to the world community as an Open-source Post-quantum blockchain layer 1 project, means anyone can join and contribute based on his/ her passion and skills. SPHINX is a blockchain protocol designed to provide secure and scalable solutions in the post-quantum era.

This repository contains code for the SPHINXKey project, which is a `Generating Key, Master key, and Address` module for the SPHINX blockchain framework.

## Components

In the thrilling era of quantum computers, where we find ourselves in a `Super Position` between classical and quantum realms, the choice of a hybrid key exchange scheme combining curve448 and Kyber1024 holds immense significance. Let's explore why this combination is the perfect fit.

1. Embracing the Best of Both Worlds: `curve448`, a battle-tested and widely adopted algorithm, provides a solid foundation of proven security and efficient key generation. On the other hand, `Kyber1024` represents the cutting-edge of post-quantum cryptography, designed to resist attacks from powerful quantum computers. By combining these two exceptional algorithms, we enter a "Super Position" where we benefit from the strengths of both classical and quantum-resistant cryptography.

2. Inspiration from Tech Giants: The widespread adoption of `curve448` and `Kyber1024` by the larger tech community serves as our guiding light and inspiration. These algorithms have garnered trust and confidence from experts and industry leaders, paving the way for their integration into our hybrid scheme. By following in the footsteps of these role models, we embrace a solution that is not only innovative but also aligns with industry best practices.

In this era of immense technological possibilities, the combination of `curve448` and `Kyber1024` in a hybrid key exchange scheme symbolizes our readiness to face the challenges presented by quantum computing. It demonstrates our commitment to leverage the proven track record of `curve448` and the promising resilience of `Kyber1024`. Together, these algorithms empower us to navigate the quantum landscape with confidence, ensuring the security and longevity of our cryptographic systems.

### The Purpose 

This code is alternative for [SPHINXHybridKey](https://github.com/SPHINX-HUB-ORG/SPHINXHybridKey) as further consideration.

The combination of Curve448 and Kyber1024 in a hybrid key exchange is designed to harness the unique strengths of each algorithm, resulting in a more robust and versatile cryptographic solution.

`Curve448` is an elliptic curve cryptography (ECC) algorithm based on the Curve448 curve. It provides efficient and secure key exchange operations, offering advantages such as strong security guarantees, resistance against various attacks, and compact key sizes. Curve448 is well-suited for scenarios where efficient key generation and secure key exchange are essential.

`Kyber1024`, on the other hand, is a post-quantum key encapsulation mechanism (KEM) based on the Learning With Errors (LWE) problem. It addresses the security challenges posed by quantum computers by providing resistance against attacks by quantum adversaries. Kyber1024 offers a high level of security in a post-quantum computing era when traditional cryptographic schemes may be vulnerable.

By combining `Curve448` and `Kyber1024` in a hybrid key exchange, we can leverage the efficiency and security benefits of `Curve448` while also incorporating the post-quantum resistance of `Kyber1024`. This hybrid approach allows us to strike a balance between immediate performance needs and long-term security considerations. It is particularly advantageous in scenarios where both efficient key exchange and protection against future quantum threats are crucial.

### Description and logic;
- Curve given 224-bit security level
- Kyber-768 given (equal AES-256) mean 256-bit security level
  
If we `merged` them it means we will achieve security level nearly `480-bytes`, this not lightweight but more secured.


### SPHINXKey Namespace

The `SPHINXKey` namespace provides functions for generating key pairs, calculating addresses, and printing key information. It relies on functionality from other included headers such as `Hybrid_key.hpp` and `Hash.hpp`.

### Functions

- The code defines a function called performX448KeyExchange that performs the `curve448` key exchange given a private key, public key, and a buffer to store the shared key.

- It defines a structure called HybridKeypair, which holds the merged key pair consisting of a `Kyber1024` key pair and and `curve448` key pair, as well as PKE key pair, and a random number generator.

- The function `generate_hybrid_keypair` generates a hybrid key pair by generating a `Kyber1024` key pair, an `curve448` key pair, and a PKE key pair using appropriate functions. It returns the generated hybrid key pair.

- The function deriveMasterKeyAndChainCode is used to derive a master private key and chain code from a given seed using the `HMAC-SHA512` function. It returns the `derived master private key` and `chain code` as a pair.

- There are several utility functions defined, such as `deriveKeyHMAC_SHA512` to derive a key using `HMAC-SHA512`, `hashSWIFFTX512` to calculate the `SWIFFTX-512` hash of data, and `generateRandomNonce` to generate a random nonce.

- The function `deriveKeyHKDF` derives a key using the `HKDF` (HMAC-based Key Derivation Function) algorithm with `SHA256` as the default hash function.

- The function hash calculates the `SWIFFTX-256` hash of a given input.

- The function generateKeyPair generates a random private key and calculates the corresponding public key by hashing the private key.

- The function generateAddress generates an address from a given public key by hashing the public key and taking the first 20 bytes of the hash.

- The function `requestDigitalSignatur`e requests a digital signature for a given data using the provided hybrid key pair.

- The functions encryptMessage and decryptMessage are used to encrypt and decrypt a message, respectively, using the `Kyber1024` KEM (Key Encapsulation Mechanism).

- The functions `encapsulateHybridSharedSecret` and `decapsulateHybridSharedSecret` are used to encapsulate and decapsulate a shared secret using the `hybrid KEM`, which combines `curve448` and `Kyber1024`.

This code provides a set of functions and structures to support hybrid key generation, key exchange, encryption, decryption, and other cryptographic operations.


#### The interaction and collaboration between Hybrid_Key.hpp and [SPHINXKey](https://github.com/ChyKusuma/SPHINXHybridKey) can be summarized as follows:

- In Key.cpp, the `generate_hybrid_keypair()` function is defined, which is responsible for generating a hybrid key pair. It internally calls functions from Hybrid_key.hpp to generate the Kyber768 key pair `(generate_kyber768_key_pair())` and the `curve448` key pair `(generate_x448_key_pair())`. It also generates the PKE key pair and initializes the `PRNG` for key generation. Finally, it returns the hybrid key pair.

- The `performX448KeyExchange()` function in Key.cpp is used to perform the `curve448` key exchange. It takes the private and public keys as inputs and uses the `performX448KeyExchange()` function from Hybrid_key.hpp to perform the actual key exchange.

- The `performHybridKeyExchange()` function in Key.cpp combines the X25519 and Kyber768 key pairs to perform a hybrid key exchange. It calls the `performX448KeyExchange()` function and also uses the `Kyber1024` KEM `(kyber1024_kem::encapsulate)` to encapsulate the shared key. The encapsulated key is stored in the shared_key parameter.

- The `merge_key_pair()` function in Key.cpp merges the X25519 and Kyber768 key pairs into a single hybrid key pair. It combines the `X448 public key` and the `Kyber1024 private key`, and generates the Kyber768 public key from the private key. The merged key pair is returned.

- The `generate_and_perform_key_exchange()` function in Key.cpp demonstrates the complete process of generating a hybrid key pair and performing the hybrid key exchange. It calls `generate_hybrid_keypair()` to generate the key pair and then calls `performHybridKeyExchange()` to perform the key exchange using the generated key pair.

- The `generateAddress()` function in Hybrid_key.hpp is used to generate a smart contract address based on a public key and contract name. It is called from the `printKeyPair()` function in Key.cpp to generate the address for a given public key.

- The `calculatePublicKey()` function in Key.cpp calculates the public key from a given private key. It internally uses functions from Hybrid_key.hpp to generate the hybrid key pair, merge the key pairs, and extract the `curve448` public key.

The interaction between Key.cpp and Hybrid_key.hpp involves calling functions defined in Hybrid_key.hpp from Key.cpp to perform various operations related to hybrid key generation, key exchange, address generation, and public key calculation. Hybrid_key.hpp provides the necessary functions and data structures to support these operations, and Key.cpp utilizes them to implement the desired functionality.


### Note

Every code in the repository is a part of the SPHINX blockchain algorithm, which is currently in development and not fully integrated or extensively tested for functionality. The purpose of this repository is to provide a framework and algorithm for the digital signature scheme in the SPHINX blockchain project.

As the project progresses, further updates and enhancements will be made to ensure the code's stability and reliability. We encourage contributors to participate in improving and refining the SPHINXBlock algorithm by submitting pull requests and providing valuable insights.

We appreciate your understanding and look forward to collaborative efforts in shaping the future of the SPHINX blockchain project.


## Getting Started
To get started with the SPHINX blockchain project, follow the instructions below:

1. Clone the repository: `git clone https://github.com/ChyKusuma/SPHINXHybridKeyV2.git`
2. Install the necessary dependencies (List the dependencies or provide a link to the installation guide).
3. Explore the codebase to understand the project structure and components.
4. Run the project or make modifications as needed.


## Contributing
We welcome contributions from the developer community to enhance the SPHINX blockchain project. If you are interested in contributing, please follow the guidelines below:

1. Fork the repository on GitHub.
2. Create a new branch for your feature or bug fix: `git checkout -b feature/your-feature-name` or `git checkout -b bugfix/your-bug-fix`.
3. Make your modifications and ensure the code remains clean and readable.
4. Write tests to cover the changes you've made, if applicable.
5. Commit your changes: `git commit -m "Description of your changes"`.
6. Push the branch to your forked repository: `git push origin your-branch-name`.
7. Open a pull request against the main repository, describing your changes and the problem it solves.
8. Insert your information (i.e name, email) in the authors space.

## License
Specify the license under which the project is distributed (MIT License).

## Contact
If you have any questions, suggestions, or feedback regarding the SPHINX blockchain project, feel free to reach out to us at [sphinxfounders@gmail.com](mailto:sphinxfounders@gmail.com).
