from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(512), nullable=False)
    salt = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    failed_login_attempts = db.Column(db.Integer, default=0)
    is_locked = db.Column(db.Boolean, default=False)
    lock_expiry = db.Column(db.DateTime)
    
    encryption_key = db.relationship('EncryptionKey', backref='user', uselist=False)
    sensitive_data = db.relationship('SensitiveData', backref='user')

class EncryptionKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    key_encrypted = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class SensitiveData(db.Model):
    __tablename__ = 'sensitive_data'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    data_type = db.Column(db.String(50), nullable=False)
    data_encrypted = db.Column(db.Text, nullable=False)
    iv = db.Column(db.Text, nullable=False)  # Add this line
    created_at = db.Column(db.DateTime, default=datetime.utcnow)