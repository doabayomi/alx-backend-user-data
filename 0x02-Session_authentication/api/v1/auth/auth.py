#!/usr/bin/env python3
"""Base Authentication Class
"""
import os
from flask import request
from typing import List, TypeVar


class Auth():
    """Base Authentication object
    """
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """Confirms if route needs authentication
        """
        if path is None:
            return True
        if excluded_paths is None or not excluded_paths:
            return True

        slashed_path = (path + '/') if path[-1] != '/' else path
        if path in excluded_paths or slashed_path in excluded_paths:
            return False
        return True

    def authorization_header(self, request=None) -> str:
        """Validate all requestss"""
        if request is None or request.headers.get('Authorization') is None:
            return None
        return request.headers.get('Authorization')

    def current_user(self, request=None) -> TypeVar('User'):
        """Returns current user object
        """
        return None

    def session_cookie(self, request=None):
        """Gets a cookie value from a request
        """
        if request is None:
            return None
        session_id = os.getenv('SESSION_NAME', '_my_session_id')
        cookie_value = request.cookies.get(session_id)
        return cookie_value
