#!/usr/bin/env python3
"""A module for encrypting passwords.
"""


import bcrypt

def hash_password(password: str) -> bytes:
    """
    Hash a password with bcrypt and return the salted, hashed password as a byte string.

    Args:
    password (str): The plain text password to hash.

    Returns:
    bytes: The salted, hashed password.
    """
    salt = bcrypt.gensalt()  # Generate a salt
    hashed = bcrypt.hashpw(password.encode(), salt)  # Hash the password with the salt
    return hashed

def is_valid(hashed_password: bytes, password: str) -> bool:
    """
    Check if a given password matches the hashed password.
    """
    return bcrypt.checkpw(password.encode(), hashed_password)
