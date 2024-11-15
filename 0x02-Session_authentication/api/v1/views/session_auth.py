#!/usr/bin/env python3
from flask import request, jsonify, Response, abort
from api.v1.views import app_views
from api.v1.auth import auth, session_auth
from models.user import User
import os


@app_views.route('/auth_session/login/', methods=['POST'],
                 strict_slashes=False)
def login():
    """POST api/v1/auth_session/login

    Returns:
        JSON representation of User instance
    """
    email = request.form.get('email')
    password = request.form.get('password')

    if not email:
        return jsonify({"error": "email missing"}), 400
    if not password:
        return jsonify({"error": "password missing"}), 400

    user_search_result = User.search({'email': email})
    if not user_search_result or len(user_search_result) == 0:
        return jsonify({"error": "no user found for this email"}), 404

    user: User = user_search_result[0]
    if not user.is_valid_password(password):
        return jsonify({"error": "wrong password"}), 401

    app_module = __import__('api.v1.app', fromlist=['auth'])
    auth: auth.Auth | session_auth.SessionAuth = app_module.auth

    session_id = auth.create_session(user.id)
    response: Response = jsonify(user.to_json())
    response.set_cookie(os.getenv('SESSION_NAME'), session_id)

    return response


@app_views.route('/auth_session/logout/', methods=['DELETE'],
                 strict_slashes=False)
def logout():
    """DELETE api/v1/auth_session/logout

    Returns:
        An empty JSON object or 404 error
    """
    app_module = __import__('api.v1.app', fromlist=['auth'])
    auth: auth.Auth | session_auth.SessionAuth = app_module.auth

    confirmed = auth.destroy_session(request)
    if not confirmed:
        abort(404)
    return jsonify({}), 200
