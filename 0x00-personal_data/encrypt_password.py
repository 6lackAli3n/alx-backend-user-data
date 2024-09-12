#!/usr/bin/env python3
"""A module for encrypting passwords.
"""


import bcrypt


def hash_password(password: str) -> bytes:
    """
    Hash a password with bcrypt and return the salted.
    Args:return bcrypt.checkpw(password.encode(), hashed_password)
    password (str): The plain text password to hash.

    Returns:
    bytes: The salted, hashed password.
    """
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def is_valid(hashed_password: bytes, password: str) -> bool:
    """
    Check if a given password matches the hashed password.
    """
    return bcrypt.checkpw(password.encode(), hashed_password)
