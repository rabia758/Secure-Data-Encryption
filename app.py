import streamlit as st
import hashlib
import json
import os
import base64
import time
from cryptography.fernet import Fernet

# --- Constants ---
DATA_FILE = "users_data.json"
KEY = Fernet.generate_key()
cipher = Fernet(KEY)

MAX_ATTEMPTS = 3
LOCKOUT_DURATION = 300  # 5 minutes

# --- Session Initialization ---
if "user" not in st.session_state:
    st.session_state.user = None
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = None

# --- Load and Save ---
if os.path.exists(DATA_FILE):
    with open(DATA_FILE, "r") as f:
        users = json.load(f)
else:
    users = {"users": {}}

def save_users():
    with open(DATA_FILE, "w") as f:
        json.dump(users, f)

# --- Secure Hashing ---
def hash_password(password, salt=None):
    if not salt:
        salt = os.urandom(16)
    hashed = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100000)
    return base64.b64encode(salt + hashed).decode()

def verify_password(stored_hash, password):
    decoded = base64.b64decode(stored_hash.encode())
    salt = decoded[:16]
    stored_hashed = decoded[16:]
    test_hashed = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100000)
    return test_hashed == stored_hashed

# --- Encryption / Decryption ---
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text, passkey):
    if st.session_state.lockout_time and time.time() < st.session_state.lockout_time:
        return "LOCKED"

    user_data = users["users"][st.session_state.user]["data"]
    for item in user_data:
        if item["encrypted_text"] == encrypted_text and verify_password(item["passkey"], passkey):
            st.session_state.failed_attempts = 0
            return cipher.decrypt(encrypted_text.encode()).decode()

    st.session_state.failed_attempts += 1
    if st.session_state.failed_attempts >= MAX_ATTEMPTS:
        st.session_state.lockout_time = time.time() + LOCKOUT_DURATION
    return None

# --- UI ---
st.title("🔐 Multi-User Secure Data Vault")

menu = ["Home", "Register", "Login", "Store Data", "Retrieve Data", "Logout"]
choice = st.sidebar.selectbox("Navigation", menu)

if choice == "Home":
    st.subheader("🏠 Welcome")
    st.write("A secure system for storing and retrieving encrypted user data.")

# --- User Registration ---
elif choice == "Register":
    st.subheader("🧾 Register New User")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Register"):
        if username in users["users"]:
            st.error("❌ Username already exists.")
        elif username and password:
            hashed = hash_password(password)
            users["users"][username] = {"password": hashed, "data": []}
            save_users()
            st.success("✅ Registered successfully. Please login.")
        else:
            st.error("⚠️ All fields are required.")

# --- User Login ---
elif choice == "Login":
    st.subheader("🔑 Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if username in users["users"] and verify_password(users["users"][username]["password"], password):
            st.session_state.user = username
            st.session_state.failed_attempts = 0
            st.session_state.lockout_time = None
            st.success(f"✅ Welcome back, {username}!")
        else:
            st.error("❌ Invalid username or password.")

# --- Logout ---
elif choice == "Logout":
    st.session_state.user = None
    st.success("👋 Logged out successfully.")

# --- Store Data (only if logged in) ---
elif choice == "Store Data":
    if not st.session_state.user:
        st.warning("🔒 Please log in first.")
    else:
        st.subheader("📦 Store Your Data")
        user_data = st.text_area("Enter data to encrypt:")
        passkey = st.text_input("Enter passkey:", type="password")

        if st.button("Encrypt & Store"):
            if user_data and passkey:
                hashed_passkey = hash_password(passkey)
                encrypted = encrypt_data(user_data)
                users["users"][st.session_state.user]["data"].append({
                    "encrypted_text": encrypted,
                    "passkey": hashed_passkey
                })
                save_users()
                st.success("✅ Data encrypted and stored!")
                st.code(encrypted, language="text")
            else:
                st.error("⚠️ Both fields are required.")

# --- Retrieve Data (only if logged in) ---
elif choice == "Retrieve Data":
    if not st.session_state.user:
        st.warning("🔒 Please log in first.")
    else:
        st.subheader("🔍 Retrieve Encrypted Data")
        encrypted_text = st.text_area("Enter Encrypted Data:")
        passkey = st.text_input("Enter Passkey:", type="password")

        if st.button("Decrypt"):
            if encrypted_text and passkey:
                decrypted = decrypt_data(encrypted_text, passkey)
                if decrypted == "LOCKED":
                    remaining = int(st.session_state.lockout_time - time.time())
                    st.warning(f"⏳ Locked out. Try again in {remaining} seconds.")
                elif decrypted:
                    st.success(f"✅ Decrypted: {decrypted}")
                else:
                    remaining = MAX_ATTEMPTS - st.session_state.failed_attempts
                    st.error(f"❌ Incorrect passkey. Attempts remaining: {remaining}")
            else:
                st.error("⚠️ Both fields are required.")
