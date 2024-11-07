"""
Bcrypt Hash

Use Cases:
- Password Hashing: Secure password storage.
- Web Authentication: Protect user logins.
- Multi-Factor Authentication: Secure password hashing.
- Sensitive Data Storage: Hash PII and sensitive data.
- API/Access Token Storage: Secure API keys and tokens.
- Token Generation: Hash secure tokens (e.g., password reset).
- Brute-Force Protection: Slow hashing prevents brute-force attacks.
- Regulatory Compliance: Meets security standards (e.g., PCI-DSS, HIPAA).
"""

import bcrypt


def hash_bcrypt(password):
    # Generate a salt for bcrypt
    salt = bcrypt.gensalt()

    # Hash the password with the generated salt
    hashed_password = bcrypt.hashpw(password.encode(), salt)

    return hashed_password.decode(), "bcrypt"
