# MAC Forgery Attack Demonstration

This project demonstrates a Message Authentication Code (MAC) forgery attack using length extension and shows how to mitigate it using HMAC.

## Project Structure

- `server.py`: Vulnerable implementation using hash(secret || message)
- `client.py`: Attacker script demonstrating the length extension attack
- `secure_server.py`: Secure implementation using HMAC

## Background

### What is a MAC?
A Message Authentication Code (MAC) is a cryptographic tool used to ensure data integrity and authenticity. It provides a way to verify that a message hasn't been tampered with and comes from a legitimate source.

### The Vulnerability
The vulnerable implementation uses the construction `MAC = hash(secret || message)`, which is susceptible to length extension attacks. This attack allows an attacker to append data to a message and generate a valid MAC without knowing the secret key.

### Why HMAC is Secure
HMAC (Hash-based Message Authentication Code) is a secure MAC construction that prevents length extension attacks by using a nested hash structure: `HMAC(K, m) = H((K' ⊕ opad) || H((K' ⊕ ipad) || m))`.

## Running the Demonstration

1. First, run the vulnerable server:
```bash
python server.py
```

2. Run the attack demonstration:
```bash
python client.py
```

3. Run the secure implementation:
```bash
python secure_server.py
```

## Attack Explanation

The length extension attack works because:
1. The attacker intercepts a valid (message, MAC) pair
2. The MAC reveals the internal state of the hash function
3. The attacker can use this state to continue hashing from that point
4. By appending data and computing a new MAC, the attacker can forge valid messages

## Mitigation

The secure implementation uses HMAC, which:
1. Uses a nested hash structure
2. Prevents length extension attacks
3. Provides better security guarantees
4. Is the recommended way to implement MACs

## Requirements

- Python 3.6+
- No additional packages required (uses standard library)

## Security Note

This is a demonstration project. In real-world applications:
1. Use established cryptographic libraries
2. Never implement your own cryptographic primitives
3. Always use HMAC or other secure MAC constructions
4. Keep secret keys secure and rotate them regularly 