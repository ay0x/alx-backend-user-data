#!/usr/bin/env python3
"""Defining Password Hash"""

import bcrypt
from db import DB
from user import User
from sqlalchemy.orm.exc import NoResultFound
from uuid import uuid4
from typing import Union, TypeVar
from db import DB
from user import User

U = TypeVar(User)


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

    def get_user_from_session_id(self, session_id: str) -> Union[None, U]:
        """
        Takes a session_id and returns the corresponding user, if one exists,
        else returns None
        Args:
            session_id (str): session id for user
        Return:
            user object if found, else None
        """
        if session_id is None:
            return None

        try:
            user = self._db.find_user_by(session_id=session_id)
        except NoResultFound:
            return None
        return user

    def destroy_session(self, user_id: int) -> None:
        """
        Take a user_id and destroy that user's session and update their
        session_id attribute to None
        Args:
            user_id (int): user's id
        Return:
            None
        """
        try:
            self._db.update_user(user_id, session_id=None)
        except ValueError:
            return None
        return None

    def get_reset_password_token(self, email: str) -> str:
        """
        Generates a reset_token uuid for a user identified by the given email
        Args:
            email (str): user's email address
        Return:
            newly generated reset_token for the relevant user
        """
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            raise ValueError

        reset_token = _generate_uuid()
        self._db.update_user(user.id, reset_token=reset_token)
        return reset_token

    def update_password(self, reset_token: str, password: str) -> None:
        """
        Updates a user's password
        Args:
            reset_token (str): reset_token issued to reset the password
            password (str): user's new password
        Return:
            None
        """
        try:
            user = self._db.find_user_by(reset_token=reset_token)
        except NoResultFound:
            raise ValueError()

        hashed = _hash_password(password)
        self._db.update_user(user.id, hashed_password=hashed, reset_token=None)


def _generate_uuid() -> str:
    """
    Generate a uuid and return its string representation
    """
    return str(uuid4())
