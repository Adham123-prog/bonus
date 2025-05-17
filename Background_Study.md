# Message Authentication Code (MAC) and Length Extension Attacks

## What is a MAC and its Purpose?
A Message Authentication Code (MAC) is a cryptographic checksum that provides:
- Data integrity verification
- Authentication of message origin
- Protection against message tampering

## Length Extension Attack Mechanics
Length extension attacks exploit vulnerabilities in hash functions that use the Merkle-Damgård construction (like MD5 and SHA-1). The attack works because:
- The hash function processes data in fixed-size blocks
- The internal state after processing each block becomes the initial state for the next block
- An attacker can continue hashing from a known hash value without knowing the original input

## Why hash(secret || message) is Insecure
The naive construction MAC = hash(secret || message) is vulnerable because:
1. It allows attackers to extend the message without knowing the secret
2. The hash function's internal state after processing (secret || message) can be derived from the MAC
3. This state can be used as a starting point to hash additional data

