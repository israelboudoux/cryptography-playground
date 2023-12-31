# cryptography-playground

In this playground I'll try to add some resources related to Cryptography. Mostly written in Java, however other times it 
might be written in other languages like Typescript, Golang or Rust (if I have disposition for this :)).

## Resources
# Data Encryption Standard (DES)
This is an implementation of the Data Encryption Standard (DES). It isn't fully validated yet, since the Validation Test
is still failing. Anyway, even after the Validation Test passes, this code isn't recommended for production use and this
algorithm is not considered safe because its short key length isn't enough to prevent brute-force attacks.

The implementation of this algorithm was followed using the instructions from the book "Understanding Cryptography - by Christof Paarjan Pelzl"

This is still a Work in Progress!

The code for DES can be found under 'main/java/src/edu/boudoux/des'.

# Message Digest (MD)
...
The code for one of the MD algorithms (SHA-1) can be found under 'main/java/src/edu/boudoux/messageDigest'.

# Schoolbook RSA
Basically a Schoolbook RSA is an implementation that follows the steps to encrypt/decrypt data, but suffers from some vulnerabilities. Without applying padding, the algorithm may fall short against some attacks, like the following:
If public exponents (_e_) and Plain Texts are small, raising the Plain Text by _e_ might not hit the modulo operation, which would allow an attacker to recover the Plain Text by applying the _e_-th root on the Ciphertext.
Yet, even using padding, RSA may still suffer from [Chosen-Ciphertext Attacks (CCA)](https://en.wikipedia.org/wiki/Chosen-ciphertext_attack). There are two kinds of CCA attacks:
_CCA1_ - passive chosen ciphertext attack; _CCA2_ - adaptative Chosen Ciphertext. For example, the PKCS#1v1.5 (Public Key Cryptography Standard) specifies a padding that may not withstand against
CC2 attacks.

The resources related to this topic are under: 'main/java/src/edu/boudoux/rsa'
Tests for the resources related to this topic are under: 'test/java/src/edu/boudoux/rsa'

One can play with RSA by running the class 'main/java/src/edu/boudoux/rsa/SchoolBookRsa.java'. 

Probably bugs are around. Let me know by raising an issue!

# Diffie-Hellman Key Exchange (DHKE)
This is one of the most used protocol for exchanging keys...

The sample code can be found under 'main/java/src/edu/boudoux/dhke'.

# Elliptic Curve Cryptography (ECC + ECDSA)
...
The sample code can be found under 'main/java/src/edu/boudoux/ecc'.

# Elgamal
...
The sample code can be found under 'main/java/src/edu/boudoux/elgamal'.

# Digital Signature Algorithm (DSA)
...
The sample code can be found under 'main/java/src/edu/boudoux/dsa'.

# Proof of Work (Hashcash)
Hashcash is an algorithm created for preventing mail spam and Denial of Service. Today a variation of it is used in one of the most popular cryptocurrencies, Bitcoin,
where it is used as the engine of the Proof of Work.
The paper about Hashcash can be found at http://www.hashcash.org/papers/hashcash.pdf

The sample code can be found under 'main/java/src/edu/boudoux/proofOfWork'.

# Merkle Tree
...
The sample code can be found under 'main/java/src/edu/boudoux/merkleTree'.

# Message Authentication Code (MAC)
...
The sample code can be found under 'main/java/src/edu/boudoux/mac'.

# Shamir Secret Sharing

# Multiparty Computation (MPC)

# Lattice

# Homomorphic Encryption

# Oblivious Encryption

# Pairing-based Encryption

# Zero-knowledge Proofs (ZKP)

# Advanced Encryption System (AES)
