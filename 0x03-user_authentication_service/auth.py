#!/usr/bin/env python3
"""Defining Password Hash"""

import bcrypt


def _hash_password(password: str) -> bytes:
    """
    Takes in a password string arguments and returns bytes.

    Args:
        password (str): Password string

    Returns:
        bytes: Hashed string
    """
    pw = password.encode('utf-8')
    return bcrypt.hashpw(pw, bcrypt.gensalt())
