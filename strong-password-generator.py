import hashlib
import secrets

def generate_password(length=12):
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_-+=~"
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def hash_password(password, algorithm='sha256'):
    if algorithm not in hashlib.algorithms_available:
        raise ValueError(f"Unsupported hashing algorithm '{algorithm}'")
    
    token = secrets.token_hex(16)
    tokenized_password = password + token
    hashed_password = hashlib.new(algorithm, tokenized_password.encode()).hexdigest()
    
    return hashed_password, token

def generate_and_hash_password():
    password = generate_password()
    print(f"Generated Password: {password}\n")

    hash_algorithms = ['sha256', 'sha512', 'blake2b', 'sha3_256']

    for algorithm in hash_algorithms:
        hashed_password, token = hash_password(password, algorithm)
        print(f"Hashed Password ({algorithm}): {hashed_password}")

generate_and_hash_password()
