"""
Main App
"""

from hashes.md5 import hash_md5, verify_md5
from hashes.sha import hash_sha, verify_sha
from hashes.scrypt import hash_scrypt, verify_scrypt
from hashes.bcrypt import hash_bcrypt, verify_bcrypt


def display_hash(hash_result, hash_type: str):
    """Displays the hash of the password."""
    print(f"{hash_type} hash: {hash_result}")


def main():
    """Main function"""
    password = str(input("Enter your password: "))

    # Calling the functions
    md5_hash_result, md5_hash_type = hash_md5(password)
    sha_hash_result, sha_hash_type = hash_sha(password)
    scrypt_hash_result, scrypt_hash_type = hash_scrypt(password)
    bcrypt_hash_result, bcrypt_hash_type = hash_bcrypt(password)

    # Printed to the console
    display_hash(md5_hash_result, md5_hash_type)
    display_hash(sha_hash_result, sha_hash_type)
    display_hash(scrypt_hash_result, scrypt_hash_type)
    display_hash(bcrypt_hash_result, bcrypt_hash_type)

    print(verify_md5("jose", md5_hash_result))
    print(verify_sha("jose", sha_hash_result))
    print(verify_scrypt("jose", scrypt_hash_result))
    print(verify_bcrypt("jose", bcrypt_hash_result))


if __name__ == "__main__":
    main()
