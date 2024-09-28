#!/usr/bin/env python3
"""A module for authentication-related routines.
"""


import bcrypt


def _hash_password(password: str) -> bytes:
    """Hashes a password using bcrypt's hashing algorithm.
    """
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password
