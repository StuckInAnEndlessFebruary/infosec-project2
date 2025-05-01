import crypto
from models import db, User
import hashlib
import os
import binascii
from datetime import datetime, timedelta
from flask_jwt_extended import create_access_token

PEPPER = os.getenv('PEPPER')
MAX_LOGIN_ATTEMPTS = 5
LOCK_TIME = timedelta(minutes=30)

def register_user(username, password):
    if User.query.filter_by(username=username).first():
        raise ValueError("Username already exists")

    salt = binascii.hexlify(os.urandom(32)).decode()
    pw_hash = hashlib.sha512((password + salt + PEPPER).encode()).hexdigest()

    user = User(
        username=username,
        password_hash=pw_hash,
        salt=salt,
        failed_login_attempts=0
    )

    db.session.add(user)
    db.session.commit()
    crypto.generate_user_key(user.id)
    return user

def login_user(username, password):
    user = User.query.filter_by(username=username).first()
    if not user:
        raise ValueError("Invalid credentials")

    if user.is_locked and user.lock_expiry > datetime.utcnow():
        remaining_time = (user.lock_expiry - datetime.utcnow()).seconds // 60
        raise ValueError(f"Account locked. Try again in {remaining_time} minutes")

    hashed_input = hashlib.sha512((password + user.salt + PEPPER).encode()).hexdigest()

    if hashed_input != user.password_hash:
        user.failed_login_attempts += 1
        if user.failed_login_attempts >= MAX_LOGIN_ATTEMPTS:
            user.is_locked = True
            user.lock_expiry = datetime.utcnow() + LOCK_TIME
        db.session.commit()
        raise ValueError("Invalid credentials")

    user.failed_login_attempts = 0
    user.is_locked = False
    db.session.commit()

    expires = timedelta(hours=1)
    return create_access_token(identity=user.id, expires_delta=expires)
