"""
SHA-256 Hash

Use Cases:
- Data Integrity: Verifying file or data integrity.
- Digital Signatures: Used in cryptographic signatures.
- Blockchain: Hashing blocks in blockchain technology.
- Certificate Authorities: Verifying SSL/TLS certificates.
- Password Hashing: Secure password storage (with salt).

Avoid:
- High-security applications without additional protections
"""

import hashlib


def hash_sha(password):
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    return hashed_password, "SHA-256"


def verify_sha(password, stored_hash):
    return hash_sha(password) == stored_hash
