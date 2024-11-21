#!/usr/bin/env python3
"""Authentication Module"""
from db import DB
from sqlalchemy.orm.exc import NoResultFound
from user import User
import bcrypt
import uuid
from typing import Optional


def _hash_password(password: str) -> bytes:
    """Hashes a password
    """
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        """Initialize an Auth Instance"""
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """"Registers a user."""
        try:
            self._db.find_user_by(email=email)
            raise ValueError(f"User {email} already exists")
        except NoResultFound:
            hashed_password = _hash_password(password).decode('utf-8')
            user = self._db.add_user(email, hashed_password)
            return user

    def valid_login(self, email: str, password: str) -> bool:
        """Confirms if a user is valid"""
        try:
            user = self._db.find_user_by(email=email)
            return bcrypt.checkpw(password.encode('utf-8'),
                                  user.hashed_password.encode('utf-8'))
        except NoResultFound:
            return False

    def _generate_uuid(self) -> str:
        """Generates a uuid"""
        return uuid.uuid4().__str__()

    def create_session(self, email: str) -> str:
        """Creates a session id"""
        try:
            user = self._db.find_user_by(email=email)
            session_id = self._generate_uuid()
            self._db.update_user(user.id, session_id=session_id)
            return session_id
        except NoResultFound:
            return None

    def get_user_from_session_id(self, session_id: str) -> Optional[User]:
        """Finds user object from session id"""
        if session_id is None:
            return None
        try:
            user = self._db.find_user_by(session_id=session_id)
            return user
        except NoResultFound:
            return None

    def destroy_session(self, user_id: int) -> None:
        """Destroys a session using user id"""
        user = self._db.find_user_by(id=user_id)
        self._db.update_user(user.id, session_id=None)

    def get_reset_password_token(self, email: str) -> str:
        """Gets a password reset token"""
        try:
            user = self._db.find_user_by(email=email)
            token = self._generate_uuid()
            self._db.update_user(user.id, reset_token=token)
            return token
        except NoResultFound:
            raise ValueError("Cannot get token as user does not exist")

    def update_password(self, reset_token: str, password: str) -> None:
        """Updates password based on reset token"""
        try:
            user = self._db.find_user_by(reset_token=reset_token)
            hashed_password = _hash_password(password).decode('utf-8')
            self._db.update_user(user.id,
                                 hashed_password=hashed_password,
                                 reset_token=None)
        except NoResultFound:
            raise ValueError("Cannot update password as user does not exist")
