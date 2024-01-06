# Password Generation and Hashing Utility

## Overview
This Python script is designed to facilitate the generation of strong passwords and their subsequent hashing using various hashing algorithms available in the hashlib library. The script aims to provide a simple interface for generating random passwords and securely hashing them using different algorithms for enhanced security.

## Functionality
- `generate_password(length=12)`: Generates a random password of specified length (default length is 12 characters) using a combination of alphanumeric characters and special symbols.
- `hash_password(password, algorithm='sha256')`: Hashes a provided password using the specified hashing algorithm (default is SHA-256) along with a unique token for each password.
- `generate_and_hash_password()`: Orchestrates the generation of a password, followed by hashing it using multiple hashing algorithms supported by hashlib.

## Usage
1. Run the Python script.
2. The `generate_and_hash_password()` function generates a random password and then hashes it using different hashing algorithms: SHA-256, SHA-512, BLAKE2b, and SHA3-256.
3. The hashed passwords, along with the corresponding salts used, are displayed in the console output.
