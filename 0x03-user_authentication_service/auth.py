#!/usr/bin/env python3
"""Defining Password Hash"""

import bcrypt
from db import DB
from user import User
from sqlalchemy.orm.exc import NoResultFound
from uuid import uuid4
from typing import Union


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


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """_summary_

        Args:
            email (str): _description_
            password (str): _description_

        Returns:
            User: User object
        """
        try:
            self._db.find_user_by(email=email)
        except NoResultFound:
            hashed = _hash_password(password)
            user = self._db.add_user(email, hashed)
            return user
        raise ValueError(f"User {email} already exists")

    def valid_login(self, email: str, password: str) -> bool:
        """_summary_

        Args:
            email (str): _description_
            password (str): _description_

        Returns:
            bool: _description_
        """
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            return False

        user_pw = user.hashed_password
        pw = password.encode("utf-8")
        return bcrypt.checkpw(pw, user_pw)

    def create_session(self, email: str) -> Union[None, str]:
        """
        Create a session_id for an existing user and update the user's
        session_id attribute
        Args:
            email (str): user's email address
        """
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            return None

        session_id = _generate_uuid()
        self._db.update_user(user.id, session_id=session_id)
        return session_id


def _generate_uuid() -> str:
    """
    Generate a uuid and return its string representation
    """
    return str(uuid4())
