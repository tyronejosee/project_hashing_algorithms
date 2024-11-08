# Project Hashing Algorithms

## MD5

**MD5 (Message Digest Algorithm 5)** is a widely used cryptographic hash function that produces a 128-bit (16-byte) hash value, typically rendered as a 32-character hexadecimal number. It was originally designed for integrity checks, where it can help verify that data (like files or messages) hasn’t been tampered with.

Characteristics:

- **Output**: 128-bit hash value, usually represented as a 32-character hex string.
- **Common Uses**: Verifying file integrity, checksums, and identifying duplicate files.
- **Security**: Considered *insecure* for password hashing or sensitive data due to vulnerabilities, including susceptibility to collision attacks (two different inputs producing the same hash).

## SHA-256

**SHA-256 (Secure Hash Algorithm 256-bit)** is a cryptographic hash function in the SHA-2 family that produces a 256-bit (32-byte) hash value, typically represented as a 64-character hexadecimal string. It was developed by the NSA and is widely used in security applications due to its resistance to collisions and its higher security compared to algorithms like MD5 or SHA-1.

Characteristics:

- **Output**: 256-bit hash value, usually shown as a 64-character hexadecimal string.
- **Common Uses**: Secure password hashing, data integrity verification, digital signatures, and blockchain technology (e.g., in Bitcoin).
- **Security**: Considered one of the most secure and robust hashing options in use today, with high resistance to collision and brute-force attacks.

## Scrypt

**Scrypt** is a cryptographic key derivation function designed to securely hash passwords. It is specifically created to be computationally intensive and memory-hard, making brute-force attacks slower and more difficult. Unlike other hashing algorithms, such as MD5 or SHA-256, Scrypt requires significant memory, which increases the cost of parallel processing in attacks.

Characteristics:

- **Memory Hard**: Requires large amounts of memory to compute, making it resistant to attacks using specialized hardware (e.g., GPUs, ASICs).
- **Adjustable Parameters**: Allows control over memory cost, CPU usage, and parallelization, providing flexibility for different security needs.
- **Common Uses**: Password hashing, secure storage of sensitive data, and cryptographic applications requiring high security.

## Bcrypt

**Bcrypt** is a cryptographic password hashing function designed to be slow and resistant to brute-force attacks. It uses a salt to ensure that even identical passwords produce different hash values. Additionally, it incorporates a work factor, which makes the algorithm slower as computational power increases, thereby improving security over time.

Characteristics:

- **Adaptive**: Allows you to increase the work factor (cost) over time as hardware improves, ensuring it remains resistant to attacks.
- **Salted**: Includes a unique salt for each password, protecting against rainbow table attacks.
- **Common Uses**: Secure password hashing, authentication systems, and protecting sensitive user data.
