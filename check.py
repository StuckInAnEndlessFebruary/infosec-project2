# فایل check.py
from app import app
from models import db, SensitiveData

with app.app_context():
    print("All sensitive data records:")
    for record in SensitiveData.query.all():
        print(f"""
        ID: {record.id}
        User ID: {record.user_id}
        Type: {record.data_type}
        Encrypted Data: {record.data_encrypted[:50]}...
        Created At: {record.created_at}
        """)

