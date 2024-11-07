#!/usr/bin/env python3
"""
A script to encrypt passwords for users
"""
import bcrypt


def hash_password(password: str) -> bytes:
    """
    Usser password is harshed using salt.
    """
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def is_valid(hashed_password: bytes, password: str) -> bool:
    """
    Determines whether a hashed password was generated from the provided password.
    """
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
