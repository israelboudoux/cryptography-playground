# cryptography-playground

In this playground I'll try to add some resources related to Cryptography. Mostly written in Java, however other times it 
might be written in other languages like Typescript, Golang or Rust (if I have disposition for this :)).

## Resources
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
