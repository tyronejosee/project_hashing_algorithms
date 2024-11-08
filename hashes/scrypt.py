"""
Scrypt Hash

Use Cases:
- Password Hashing: Secure password storage, especially for high-security envs.
- Web Authentication: Protect user logins with strong hashing.
- Multi-Factor Authentication: Securely hash passwords as part of MFA.
- Sensitive Data Storage: Hash sensitive data (e.g., PII).
- API/Access Token Storage: Securely store tokens with high computational cost.
- Token Generation: Use for securely hashing tokens (e.g., password reset).
- Brute-Force Protection: High memory usage increases resistance to attacks.
- Regulatory Compliance: Meets high-security standards for sensitive data.
"""

import os
import hashlib


def hash_scrypt(password):
    # Generate a salt (random value) for Scrypt
    salt = os.urandom(16)

    # Scrypt parameters: N, r, p
    N = 16384  # CPU/memory cost
    r = 8  # Block size
    p = 1  # Parallelization factor

    # Hash the password using Scrypt
    hashed_password = hashlib.scrypt(
        password.encode(), salt=salt, n=N, r=r, p=p, dklen=64
    )
    new_hash = salt.hex() + hashed_password.hex()

    return new_hash, "Scrypt"


def verify_scrypt(password, hashed_password):
    # Extract salt and hash from stored password
    salt = bytes.fromhex(
        hashed_password[:32],  # The first 32 characters are the salt
    )

    stored_hash = bytes.fromhex(
        hashed_password[32:],  # The rest is the password hash
    )

    # Scrypt parameters (must match those used when hashing)
    N = 16384
    r = 8
    p = 1

    # Hash the entered password using the same salt and parameters
    new_hash = hashlib.scrypt(
        password.encode(),
        salt=salt,
        n=N,
        r=r,
        p=p,
        dklen=64,
    )
    return new_hash == stored_hash
