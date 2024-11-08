"""
MD5 Hash

Use Cases:
- Checksum and Data Integrity: Quick hash for verifying file integrity.
- File Deduplication: Identifying duplicate files.
- Basic Hashing: Simple, low-security use cases.

Avoid:
- Password hashing (insecure).
- Sensitive data storage (easily cracked).
- Cryptographic applications (vulnerable to collisions).
"""

import hashlib


def hash_md5(password):
    hashed_password = hashlib.md5(password.encode()).hexdigest()
    return hashed_password, "MD5"


def verify_md5(password, stored_hash):
    return hash_md5(password) == stored_hash
