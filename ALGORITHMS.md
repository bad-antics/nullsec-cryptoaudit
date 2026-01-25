# Cryptographic Algorithm Audit Guide

## Overview
Auditing cryptographic implementations for security weaknesses.

## Algorithm Categories

### Symmetric Encryption
- AES (128/192/256)
- ChaCha20-Poly1305
- Deprecated: DES, 3DES, RC4

### Asymmetric Encryption
- RSA (2048+ bits)
- ECDSA/ECDH
- Ed25519/X25519
- Deprecated: RSA-1024

### Hash Functions
- SHA-256/SHA-512
- SHA-3/SHAKE
- BLAKE2/BLAKE3
- Deprecated: MD5, SHA-1

## Audit Checklist

### Key Management
- Key generation
- Key storage
- Key rotation
- Key destruction

### Implementation Review
- Mode of operation
- IV/nonce handling
- Padding schemes
- Error handling

### Protocol Analysis
- Handshake security
- Session keys
- Forward secrecy
- Replay protection

## Common Vulnerabilities

### Implementation Flaws
- Weak RNG
- Timing attacks
- Side channels
- Padding oracles

### Configuration Issues
- Deprecated algorithms
- Short key lengths
- Missing authentication
- Insecure defaults

## Tools
- OpenSSL analysis
- Cryptographic testing
- Compliance checking

## Legal Notice
For authorized security audits.
