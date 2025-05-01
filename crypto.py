from cryptography.fernet import Fernet
import os
import base64
from models import db, EncryptionKey

def generate_user_key(user_id):
    key = Fernet.generate_key()
    # ذخیره کلید به صورت امن (ساده‌شده)
    enc_key = EncryptionKey(user_id=user_id, key_encrypted=key.decode())
    db.session.add(enc_key)
    db.session.commit()
    return key

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import base64

def encrypt_data(user_id, plaintext):
    key = EncryptionKey.query.filter_by(user_id=user_id).first()
    if not key:
        raise ValueError("Encryption key not found")
    
    # Generate a random IV
    iv = os.urandom(16)
    cipher = Fernet(key.key_encrypted.encode())
    
    # Encrypt the data
    encrypted = cipher.encrypt(plaintext.encode())
    
    # Return both encrypted data and IV (as base64 strings)
    return encrypted.decode(), base64.b64encode(iv).decode()

def decrypt_data(user_id, ciphertext, iv):
    key = EncryptionKey.query.filter_by(user_id=user_id).first()
    if not key:
        raise ValueError("Encryption key not found")
    
    cipher = Fernet(key.key_encrypted.encode())
    
    # Decode the IV from base64
    iv_decoded = base64.b64decode(iv.encode())
    
    # Decrypt the data
    return cipher.decrypt(ciphertext.encode()).decode()