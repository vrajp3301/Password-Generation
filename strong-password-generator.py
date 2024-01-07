import hashlib
import secrets

def generate_password(length=12):
    lowercase_letters = string.ascii_lowercase
    uppercase_letters = string.ascii_uppercase
    numbers = string.digits
    special_characters = "!@#$%^&*()_-+=~"

    # Ensure at least one lowercase, one uppercase, one number, and one special character
    password = (
        secrets.choice(lowercase_letters) +
        secrets.choice(uppercase_letters) +
        secrets.choice(numbers) +
        secrets.choice(special_characters) +
        ''.join(secrets.choice(string.ascii_letters + string.digits + special_characters) for _ in range(length - 4))
    )
    password = ''.join(secrets.sample(password, len(password)))
    return password

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
