#!/usr/bin/env python3
"""Flask app routes"""
from flask import (
    Flask,
    jsonify,
    request,
    abort,
    Response,
    redirect,
    url_for)
from auth import Auth

AUTH = Auth()
app = Flask(__name__)


@app.route('/')
def index() -> Response:
    """Main page
    """
    return jsonify({"message": "Bienvenue"})


@app.route("/users", methods=['POST'], strictslashes=False)
def users() -> Response:
    """POST /users
    """
    email = request.form.get("email")
    password = request.form.get("password")
    try:
        AUTH.register_user(email, password)
        return jsonify({"email": email, "message": "user created"}), 400
    except ValueError:
        return jsonify({"message": "email already registered"}), 400


@app.route('/sessions', methods=['POST'], strictslashes=False)
def login() -> Response:
    """POST /sessions
    """
    email = request.form.get("email")
    password = request.form.get("password")
    valid_login = AUTH.valid_login(email, password)
    if not valid_login:
        abort(401)
    payload: Response = jsonify({"email": email, "message": "logged in"})
    session_id = AUTH.create_session(email)
    payload.set_cookie("session_id", session_id)
    return payload


@app.route('/sessions', methods=['DELETE'], strictslashes=False)
def logout() -> Response:
    """DELETE /sessions
    """
    session_id = request.cookies.get('session_id')
    user = AUTH.get_user_from_session_id(session_id)
    if user:
        AUTH.destroy_session(user.id)
        return redirect(url_for('index'))
    abort(403)


@app.route('/profile', methods=['GET'], strictslashes=False)
def profile() -> Response:
    """GET /profile
    """
    session_id = request.cookies.get('session_id')
    user = AUTH.get_user_from_session_id(session_id)
    if user:
        return jsonify({"email": user.email}), 200
    abort(403)


@app.route('/reset_password', methods=['POST'], strictslashes=False)
def get_reset_password_token() -> Response:
    """POST /reset_password
    """
    email = request.form.get("email")
    try:
        token = AUTH.get_reset_password_token(email)
        return jsonify({"email": email, "reset_token": token}), 200
    except ValueError:
        abort(403)


@app.route('/reset_password', methods=['PUT'], strictslashes=False)
def update_password() -> Response:
    """PUT /reset_password
    """
    email = request.form.get("email")
    reset_token = request.form.get("reset_token")
    new_password = request.form.get("new_password")

    try:
        AUTH.update_password(reset_token, new_password)
        return jsonify({"email": email, "message": "Password updated"}), 200
    except ValueError:
        abort(403)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
