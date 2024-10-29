from flask import Flask, request, jsonify, session
from flask_cors import CORS
from flask_session import Session
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
import cloudinary
import cloudinary.uploader
import os

# Initialize Flask app
app = Flask(__name__)
CORS(app, supports_credentials=True)  # Allow cookies in CORS

# Configure session management
app.config["SECRET_KEY"] = os.urandom(24)  # Use a secure, random secret key
app.config["SESSION_TYPE"] = "filesystem"
app.config["SESSION_COOKIE_HTTPONLY"] = True  # Prevent JavaScript access to session cookie
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"  # Protect against CSRF in modern browsers
Session(app)

# MongoDB Atlas connection
mongo_uri = "mongodb+srv://contactzcsco:Z3r0c0575k1ll%4066202@zcsproduction.zld0i.mongodb.net/?retryWrites=true&w=majority&appName=ZCSProduction"
client = MongoClient(mongo_uri)
db = client["NCCDatabase"]
cadet_collection = db["cadets"]
profile_collection = db["profiles"]

# Cloudinary configuration
cloudinary.config(
    cloud_name="dxevrrj4j",
    api_key="853367529692421",
    api_secret="qmkkPh2MEoQCSJ2OLfHeQbaYVFk",
    secure=True
)

# Error handler for unauthorized access
@app.errorhandler(401)
def unauthorized_error(e):
    return jsonify({"error": "Unauthorized access. Please log in."}), 401

# Error handler for resource not found
@app.errorhandler(404)
def not_found_error(e):
    return jsonify({"error": "Resource not found"}), 404

# Route to register a new user with enhanced error handling
@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.json
        username = data.get("username")
        password = data.get("password")
        name = data.get("name")
        email = data.get("email")
        is_admin = data.get("is_admin", False)

        if profile_collection.find_one({"username": username}):
            return jsonify({"error": "Username already exists"}), 400

        hashed_password = generate_password_hash(password)
        user_profile = {
            "username": username,
            "password": hashed_password,
            "name": name,
            "email": email,
            "is_admin": is_admin,
            "permissions": {
                "can_edit_blog": False,
                "can_post_blog": False,
                "can_view_cadets": True
            }
        }
        profile_collection.insert_one(user_profile)
        return jsonify({"message": "User registered successfully!"}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Route to login and set up session
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    user = profile_collection.find_one({"username": username})
    if not user or not check_password_hash(user["password"], password):
        return jsonify({"error": "Invalid credentials"}), 401

    session["user_id"] = str(user["_id"])
    session["username"] = username
    session["is_admin"] = user.get("is_admin", False)
    response = jsonify({"message": "Logged in successfully", "is_admin": user.get("is_admin", False)})
    response.headers["Access-Control-Allow-Credentials"] = "true"  # Allow credentials to support cookie storage
    return response

# Route to check if the session is active
@app.route('/check-session', methods=['GET'])
def check_session():
    if "user_id" in session:
        return jsonify({"message": "Session active", "username": session.get("username"), "is_admin": session.get("is_admin")})
    return jsonify({"error": "No active session"}), 401

# Route to logout and clear session
@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    response = jsonify({"message": "Logged out successfully"})
    response.headers["Access-Control-Allow-Credentials"] = "true"
    return response, 200

# Route to get user profile
@app.route('/user_profile', methods=['GET'])
def user_profile():
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    user = profile_collection.find_one({"username": session["username"]})
    if user:
        user["_id"] = str(user["_id"])  # Convert ObjectId to string
        return jsonify(user), 200
    else:
        return jsonify({"error": "User not found"}), 404

# Route for admin actions with enhanced error handling and validation
@app.route('/admin/permissions', methods=['POST'])
def admin_permissions():
    if not session.get("is_admin"):
        return jsonify({"error": "Admin access required"}), 403

    data = request.json
    username = data.get("username")
    permissions = data.get("permissions", {})

    result = profile_collection.update_one(
        {"username": username},
        {"$set": {"permissions": permissions}}
    )
    if result.matched_count == 0:
        return jsonify({"error": "User not found"}), 404
    return jsonify({"message": "Permissions updated successfully"}), 200

# Route to view cadet profiles with proper permissions
@app.route('/cadet_profiles', methods=['GET'])
def view_cadet_profiles():
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    user = profile_collection.find_one({"username": session["username"]})
    if user and (user.get("is_admin") or user["permissions"].get("can_view_cadets")):
        cadets = list(cadet_collection.find({}))
        for cadet in cadets:
            cadet["_id"] = str(cadet["_id"])  # Convert ObjectId to string
        return jsonify(cadets), 200
    else:
        return jsonify({"error": "Permission denied"}), 403

if __name__ == '__main__':
    app.run(debug=True)
