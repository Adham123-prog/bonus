# HMAC Security Analysis

## Why HMAC is Secure Against Length Extension

HMAC uses a nested hash construction:
HMAC(K,m) = hash(K ⊕ opad || hash(K ⊕ ipad || m))

This construction is secure because:
1. The key is used in both inner and outer hashes
2. The nested structure prevents length extension attacks
3. The use of padding constants (ipad/opad) ensures separation between inner and outer hash operations

## Key Security Properties
- The inner hash result is not exposed to attackers
- Length extension is impossible without knowing K ⊕ ipad
- The double hashing provides domain separation

