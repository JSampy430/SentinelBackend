from flask import Flask, request, jsonify
from flask_cors import CORS
import json
import os
import bcrypt

app = Flask(__name__)
CORS(app)

# Path for persistent disk (Render will mount to /data)
DATA_DIR = os.environ.get("DATA_DIR", "./data")
USERS_FILE = os.path.join(DATA_DIR, "users.json")

# ---------- Utility Functions ----------

def load_users():
    if not os.path.exists(USERS_FILE):
        return {}
    try:
        with open(USERS_FILE, "r") as file:
            return json.load(file)
    except json.JSONDecodeError:
        return {}

def save_users(users):
    os.makedirs(os.path.dirname(USERS_FILE), exist_ok=True)
    with open(USERS_FILE, "w") as file:
        json.dump(users, file, indent=2)
    print(f"[SAVE] Users saved to: {USERS_FILE}")

# ---------- Routes ----------

@app.route("/signup", methods=["POST"])
def signup():
    try:
        data = request.get_json(force=True)
        print("[DEBUG] Data received:", data)
    except Exception as e:
        print("[ERROR] Failed to parse JSON:", e)
        return jsonify({"error": "Invalid JSON"}), 400

    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"error": "Email and password are required."}), 400

    users = load_users()
    if email in users:
        return jsonify({"error": "Email already registered."}), 400

    hashed_pw = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    users[email] = {"password": hashed_pw}
    save_users(users)

    print(f"[SIGNUP] New user registered: {email}")
    return jsonify({"message": "Signup successful."}), 200

@app.route("/login", methods=["POST"])
def login():
    try:
        data = request.get_json()
        email = data.get("email")
        password = data.get("password")

        users = load_users()
        user = users.get(email)

        if user and bcrypt.checkpw(password.encode("utf-8"), user["password"].encode("utf-8")):
            print(f"[LOGIN] Success for user: {email}")
            return jsonify({"message": "Login successful."}), 200
        else:
            print(f"[LOGIN] Failed login for: {email}")
            return jsonify({"error": "Invalid email or password."}), 401
    except Exception as e:
        print("[ERROR] During login:", str(e))
        return jsonify({"error": "Server error during login"}), 500

# ---------- Start App ----------

if __name__ == "__main__":
    app.run(debug=True, port=5000)
