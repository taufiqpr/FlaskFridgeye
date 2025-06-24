from flask import Flask, request, jsonify
from flask_jwt_extended import create_access_token, JWTManager, jwt_required, get_jwt_identity
from flask_cors import CORS
from datetime import datetime, timedelta
from flask import request, jsonify
from google.oauth2 import id_token
from google.auth.transport import requests as grequests
import bcrypt
import secrets
import requests
import smtplib
import random
from pymongo import MongoClient
import os
from dotenv import load_dotenv
from email.message import EmailMessage 
from base64 import b64decode
from zoneinfo import ZoneInfo

otp_storage = {}

app = Flask(__name__)
CORS(app)

BASE_URL = ""
API_KEY = ""

EMAIL_ADDRESS = ''
EMAIL_PASSWORD = '' 


load_dotenv()

username = os.getenv("MONGODB_USERNAME")
password = os.getenv("MONGODB_PASSWORD")

uri = f""

client = MongoClient(uri)

db = client['fridgeye']
users_collection = db['users']
login_history_collection = db['login_history']

app.config['JWT_SECRET_KEY'] = 'fridgeeye'
jwt = JWTManager(app)

def send_otp(email, otp_code):
    msg = EmailMessage()
    msg.set_content(f'Kode OTP Anda: {otp_code}')
    msg['Subject'] = 'Kode OTP Registrasi FridgeEye'
    msg['From'] = EMAIL_ADDRESS
    msg['To'] = email

    with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
        smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        smtp.send_message(msg)

@app.route("/google_auth", methods=["POST"])
def google_auth():
    data = request.get_json()
    token = data.get("id_token")

    try:
        CLIENT_ID = ""
        idinfo = id_token.verify_oauth2_token(token, grequests.Request(), CLIENT_ID)

        email = idinfo["email"]
        username = idinfo.get("name", "No Name")

        user = users_collection.find_one({"email": email})
        if not user:
            users_collection.insert_one({
                "email": email,
                "username": username,
                "is_verified": True  
            })

        # Tambahkan login history di sini
        user_agent = request.headers.get('User-Agent')
        timestamp = datetime.now(ZoneInfo("Asia/Jakarta")).strftime('%Y-%m-%d %H:%M:%S')

        login_history_collection.insert_one({
            'user_email': email,
            'timestamp': timestamp,
            'device': user_agent,
            'status': 'success'
        })

        access_token = create_access_token(identity=email)

        return jsonify({
            "status": "success",
            "token": access_token,
            "user": {
                "email": email,
                "username": username
            }
        }), 200

    except ValueError as e:
        return jsonify({"message": "Token Google tidak valid", "error": str(e)}), 400


@app.route('/get_recipes', methods=['GET'])
def get_recipes():
    query = request.args.get('query', '')
    if not query:
        return jsonify({"error": "Query is required"}), 400

    try:
        url = f"{BASE_URL}/recipes/complexSearch?query={query}&number=10&addRecipeInformation=true&apiKey={API_KEY}"
        response = requests.get(url)

        if response.status_code != 200:
            return jsonify({"error": "Gagal mengambil data resep"}), 500

        data = response.json()
        results = data.get("results", [])

        for item in results:
            if not item.get("image"):
                item["image"] = f"https://spoonacular.com/recipeImages/{item['id']}-556x370.jpg"

        return jsonify(results)
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/get_recipe_detail', methods=['GET'])
def get_recipe_detail():
    recipe_id = request.args.get('id')
    if not recipe_id:
        return jsonify({"error": "Recipe ID is required"}), 400

    try:
        url = f"{BASE_URL}/recipes/{recipe_id}/information?apiKey={API_KEY}"
        response = requests.get(url)

        if response.status_code != 200:
            return jsonify({"error": "Gagal mengambil detail resep"}), 500

        data = response.json()
        return jsonify(data)
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    email = data.get('email')
    username = data.get('username')
    password = data.get('password')

    if not all([email, username, password]):
        return jsonify({'message': 'Semua data harus diisi'}), 400

    if users_collection.find_one({'email': email}):
        return jsonify({'message': 'Email sudah terdaftar'}), 400

    otp = str(random.randint(100000, 999999))
    expires_at = datetime.utcnow() + timedelta(minutes=3)

    otp_storage[email] = {
        'otp': otp,
        'expires': expires_at,
        'username': username,
        'password': password  
    }

    try:
        send_otp(email, otp)
        return jsonify({'message': 'OTP dikirim ke email'}), 200
    except Exception as e:
        return jsonify({'message': 'Gagal mengirim OTP', 'error': str(e)}), 500


@app.route('/verify_otp_register', methods=['POST'])
def verify_otp_register():
    data = request.get_json()
    email = data.get('email')
    otp = data.get('otp')

    if not email or not otp:
        return jsonify({'message': 'Email dan OTP harus diisi'}), 400

    otp_data = otp_storage.get(email)
    if not otp_data:
        return jsonify({'message': 'OTP tidak ditemukan, silakan daftar ulang'}), 400

    if otp_data['otp'] != otp:
        return jsonify({'message': 'OTP tidak valid'}), 400

    if datetime.utcnow() > otp_data['expires']:
        return jsonify({'message': 'OTP sudah kedaluwarsa'}), 400

    username = otp_data['username']
    password_plain = otp_data['password']
    hashed_password = bcrypt.hashpw(password_plain.encode('utf-8'), bcrypt.gensalt())

    user_data = {
        'username': username,
        'email': email,
        'password': hashed_password,
        'is_verified': True 
    }
    users_collection.insert_one(user_data)
    del otp_storage[email]

    access_token = create_access_token(identity=email)
    return jsonify({'message': 'Registrasi berhasil', 'token': access_token}), 201

@app.route('/resend_otp', methods=['POST'])
def resend_otp_register():
    data = request.get_json()
    email = data.get('email')

    if not email:
        return jsonify({'message': 'Email harus diisi'}), 400

    otp_data = otp_storage.get(email)
    if not otp_data:
        return jsonify({'message': 'Data registrasi tidak ditemukan, silakan daftar ulang'}), 400

    new_otp = str(random.randint(100000, 999999))
    expires_at = datetime.utcnow() + timedelta(minutes=3)

    otp_data['otp'] = new_otp
    otp_data['expires'] = expires_at

    try:
        send_otp(email, new_otp)
        return jsonify({'message': 'OTP baru telah dikirim ke email'}), 200
    except Exception as e:
        return jsonify({'message': 'Gagal mengirim OTP', 'error': str(e)}), 500


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    password = data.get('password')

    user_agent = request.headers.get('User-Agent')
    timestamp = datetime.now(ZoneInfo("Asia/Jakarta")).strftime('%Y-%m-%d %H:%M:%S')

    if not email or not password:
        return jsonify({'message': 'Email dan password harus diisi'}), 400

    user = users_collection.find_one({'email': email})
    if not user:
        return jsonify({'message': 'Akun tidak ditemukan'}), 404

    if not user.get('is_verified', False):
        return jsonify({'message': 'Akun belum diverifikasi. Silakan cek email Anda untuk OTP.'}), 403

    if not bcrypt.checkpw(password.encode('utf-8'), user['password']):
        return jsonify({'message': 'Password salah'}), 401

    login_history_collection.insert_one({
        'user_email': email,
        'timestamp': timestamp,
        'device': user_agent,
        'status': 'success'
    })

    access_token = create_access_token(identity=email, expires_delta=timedelta(minutes=30))

    return jsonify({'message': 'Login berhasil', 'token': access_token}), 200


@app.route('/login-history', methods=['GET'])
@jwt_required()
def get_login_history():
    current_user_email = get_jwt_identity()

    history_cursor = login_history_collection.find(
        {'user_email': current_user_email},
        {'_id': 0}  
    ).sort('timestamp', -1)

    history_list = list(history_cursor)
    return jsonify(history_list), 200

@app.route('/users', methods=['GET'])
@jwt_required()
def get_all_users():
    users = users_collection.find({}, {'_id': 1, 'password': 0})  
    users_list = list(users)

    for user in users_list:
        user['id'] = str(user['_id'])  
        del user['_id']  

    return jsonify(users_list), 200

from bson import ObjectId

@app.route('/profile', methods=['GET'])
@jwt_required()
def get_profile():
    current_user_email = get_jwt_identity()
    user = users_collection.find_one({'email': current_user_email})
    if not user:
        return jsonify({'message': 'User tidak ditemukan'}), 404

    user['_id'] = str(user['_id'])  
    return jsonify({
        '_id': user['_id'],
        'username': user['username'],
        'email': user['email']
    }), 200


@app.route('/profile/<user_id>', methods=['PUT'])
@jwt_required()
def update_profile(user_id):
    current_user_email = get_jwt_identity()
    
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')

    if not username and not email:
        return jsonify({'message': 'Tidak ada data yang ingin diperbarui'}), 400

    try:
        user = users_collection.find_one({'_id': ObjectId(user_id)})
    except Exception:
        return jsonify({'message': 'ID tidak valid'}), 400

    if not user:
        return jsonify({'message': 'User tidak ditemukan'}), 404

    if user['email'] != current_user_email:
        return jsonify({'message': 'Akses ditolak'}), 403

    update_fields = {}
    if username:
        update_fields['username'] = username
    if email:
        update_fields['email'] = email

    users_collection.update_one({'_id': ObjectId(user_id)}, {'$set': update_fields})

    return jsonify({'message': 'Profil berhasil diperbarui'}), 200


@app.route('/profile/<user_id>', methods=['DELETE'])
@jwt_required()
def delete_account(user_id):
    current_user_email = get_jwt_identity()

    try:
        user = users_collection.find_one({'_id': ObjectId(user_id)})
    except Exception:
        return jsonify({'message': 'ID tidak valid'}), 400

    if not user:
        return jsonify({'message': 'User tidak ditemukan'}), 404

    if user['email'] != current_user_email:
        return jsonify({'message': 'Akses ditolak'}), 403

    users_collection.delete_one({'_id': ObjectId(user_id)})

    login_history_collection.delete_many({'user_email': current_user_email})

    return jsonify({'message': 'Akun berhasil dihapus'}), 200


@app.route('/', methods=['GET'])
def hallo():
    return jsonify({
        "msg": "API IS READYYY MANNNNN"
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
