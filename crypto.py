from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os, base64
from models import db, EncryptionKey
from dotenv import load_dotenv

load_dotenv()
MASTER_KEY = os.getenv("MASTER_KEY").encode()

def derive_key(master_key, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt.encode(),
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(master_key))

def generate_user_key(user_id):
    user_key = Fernet.generate_key()
    salt = base64.b64encode(os.urandom(16)).decode()
    derived_key = derive_key(MASTER_KEY, salt)
    fernet = Fernet(derived_key)
    encrypted_user_key = fernet.encrypt(user_key)
    
    enc_key = EncryptionKey(
        user_id=user_id,
        key_encrypted=encrypted_user_key.decode(),
        salt=salt
    )
    db.session.add(enc_key)
    db.session.commit()
    return user_key

def get_user_key(user_id):
    entry = EncryptionKey.query.filter_by(user_id=user_id).first()
    if not entry:
        raise ValueError("User key not found")
    derived_key = derive_key(MASTER_KEY, entry.salt)
    fernet = Fernet(derived_key)
    return fernet.decrypt(entry.key_encrypted.encode())

def encrypt_data(user_id, plaintext):
    key = get_user_key(user_id)
    fernet = Fernet(key)
    iv = base64.b64encode(os.urandom(16)).decode()
    encrypted = fernet.encrypt(plaintext.encode())
    return encrypted.decode(), iv

def decrypt_data(user_id, ciphertext, iv):
    key = get_user_key(user_id)
    fernet = Fernet(key)
    return fernet.decrypt(ciphertext.encode()).decode()
