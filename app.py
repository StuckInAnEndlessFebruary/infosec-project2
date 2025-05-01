from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import models
import auth
import crypto
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

jwt = JWTManager(app)
models.db.init_app(app)

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    try:
        user = auth.register_user(data['username'], data['password'])
        return jsonify({"message": "User created", "user_id": user.id}), 201
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    try:
        token = auth.login_user(data['username'], data['password'])
        return jsonify({"access_token": token}), 200
    except ValueError as e:
        return jsonify({"error": str(e)}), 401

@app.route('/secure-data', methods=['POST'])
@jwt_required()
def store_data():
    current_user = get_jwt_identity()
    data = request.get_json()

    encrypted, iv = crypto.encrypt_data(current_user, data['data'])
    new_data = models.SensitiveData(
        user_id=current_user,
        data_type=data['data_type'],
        data_encrypted=encrypted,
        iv=iv
    )
    models.db.session.add(new_data)
    models.db.session.commit()
    return jsonify({"message": "Data stored securely"}), 201

@app.route('/secure-data/<data_type>', methods=['GET'])
@jwt_required()
def get_secure_data(data_type):
    current_user = get_jwt_identity()
    data_record = models.SensitiveData.query.filter_by(
        user_id=current_user,
        data_type=data_type
    ).first()
    if not data_record:
        return jsonify({"error": "Data not found"}), 404

    try:
        decrypted_data = crypto.decrypt_data(
            current_user, data_record.data_encrypted, data_record.iv
        )
        return jsonify({
            data_type: decrypted_data,
            "created_at": data_record.created_at.isoformat()
        })
    except Exception as e:
        return jsonify({"error": "Decryption failed", "details": str(e)}), 500

if __name__ == '__main__':
    with app.app_context():
        models.db.create_all()
    app.run(debug=True)
