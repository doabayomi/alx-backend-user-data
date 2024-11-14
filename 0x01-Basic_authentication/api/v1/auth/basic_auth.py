#!/usr/bin/env python3
"""Basic authentication class
"""
from api.v1.auth.auth import Auth
from models.user import User
from typing import Tuple, TypeVar
import base64
import binascii


class BasicAuth(Auth):
    """Basic Authentication object

    Args:
        Auth: Base Authentication object.
    """
    def extract_base64_authorization_header(self,
                                            authorization_header: str) -> str:
        """Extracts the base64 part of the Authorization header
        """
        header_starts_with_basic = authorization_header.startswith('Basic ')

        if authorization_header is None or \
                type(authorization_header) is not str:
            return None
        if not header_starts_with_basic:
            return None
        return authorization_header[6:]

    def decode_base64_authorization_header(self,
                                           base64_authorization_header: str
                                           ) -> str:
        """Returns the decoded value of base64 string in authorization header
        """
        if base64_authorization_header is None:
            return None
        if type(base64_authorization_header) != str:
            return None

        try:
            data = base64.b64decode(base64_authorization_header)
            return data.decode('utf-8')
        except binascii.Error:
            return None

    def extract_user_credentials(self,
                                 decoded_base64_authorization_header: str
                                 ) -> Tuple[str, str]:
        """Gets user credentials from authorization headers
        """
        if decoded_base64_authorization_header is None:
            return (None, None)
        if type(decoded_base64_authorization_header) != str:
            return (None, None)
        if ':' not in decoded_base64_authorization_header:
            return (None, None)

        details = decoded_base64_authorization_header.split(':')
        user_email = details[0]
        user_password = details[1]
        return (user_email, user_password)

    def user_object_from_credentials(self, user_email: str,
                                     user_pwd: str) -> TypeVar('User'):
        """Gets user object from user credentials
        """
        invalid_email = user_email is None or type(user_email) != str
        invalid_pwd = user_pwd is None or type(user_pwd) != str
        if invalid_email or invalid_pwd:
            return None

        user_search_list = User.search({'email': user_email})
        if len(user_search_list) <= 0:
            return None

        user: User = user_search_list[0]
        if not user.is_valid_password(user_pwd):
            return None

        return user

    def current_user(self, request=None) -> TypeVar('User'):
        """Gets current user object
        """
        auth_header = self.authorization_header(request)
        base64_header = self.extract_base64_authorization_header(auth_header)
        decoded_header = self.decode_base64_authorization_header(base64_header)
        email, pwd = self.extract_user_credentials(decoded_header)
        user: User | None = self.user_object_from_credentials(email, pwd)
        return user
