#!/usr/bin/env python3
"""
hashing password
"""
import bcrypt

def hash_password(password: str) -> bytes:
    """ Returns a salted, hashed password which is a byte string """
    salt = bcrypt.gensalt();
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)

    return hashed


def is_valid(hashed_password: bytes, password: str) -> bool:
    """ validating that the provided password matches the hashed password """
    encoded = password.encode('utf-8')
    if bcrypt.checkpw(encoded, hashed_password):
        return True
    else:
        return False
