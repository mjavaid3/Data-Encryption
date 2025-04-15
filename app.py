import streamlit as st
import hashlib
import json
import os
import time
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode
from hashlib import pbkdf2_hmac

# === Security Parameters ===
USER_DATA_FILE = "protected_data.json"
SECURITY_SALT = b"fixed_salt_value"  # In production, this should be stored securely
ACCOUNT_LOCK_TIME = 60  # in seconds

# === User Session Management ===
if "current_user" not in st.session_state:
    st.session_state.current_user = None
if "login_attempts" not in st.session_state:
    st.session_state.login_attempts = 0
if "account_locked_until" not in st.session_state:
    st.session_state.account_locked_until = 0

# === Core Functions ===

def get_user_data():
    if os.path.exists(USER_DATA_FILE):
        with open(USER_DATA_FILE, "r") as file:
            return json.load(file)
    return {}

def update_user_data(user_info):
    with open(USER_DATA_FILE, "w") as file:
        json.dump(user_info, file)

def create_encryption_key(secret_phrase):
    # Generate key using PBKDF2
    derived_key = pbkdf2_hmac('sha256', secret_phrase.encode(), SECURITY_SALT, 100000)
    return urlsafe_b64encode(derived_key)

def secure_hash(input_password):
    return hashlib.pbkdf2_hmac('sha256', input_password.encode(), SECURITY_SALT, 100000).hex()

def lock_content(content, lock_key):
    cipher = Fernet(create_encryption_key(lock_key))
    return cipher.encrypt(content.encode()).decode()

def unlock_content(locked_content, unlock_key):
    try:
        cipher = Fernet(create_encryption_key(unlock_key))
        return cipher.decrypt(locked_content.encode()).decode()
    except:
        return None

# === Load existing user data ===
user_database = get_user_data()

# === Application Navigation ===
st.title("🛡️ Protected Data Vault System")
app_pages = ["Main Page", "Create Account", "User Login", "Save Information", "Access Information"]
selected_page = st.sidebar.selectbox("Menu", app_pages)

# === Main Page ===
if selected_page == "Main Page":
    st.subheader("🌟 Secure Data Management Portal")
    st.markdown("Protect and manage your confidential information with military-grade encryption.")
    st.info("Quick Start Guide:")
    st.markdown("""
    1. Create a new user profile
    2. Sign in with your credentials
    3. Securely store your private content
    4. Access your information when required
    """)

# === Create Account ===
elif selected_page == "Create Account":
    st.subheader("📋 New User Registration")
    user_id = st.text_input("Select Username")
    user_pass = st.text_input("Create Password", type="password")

    if st.button("Complete Registration"):
        if user_id and user_pass:
            if user_id in user_database:
                st.warning("⚠️ This username is already taken.")
            else:
                user_database[user_id] = {
                    "password": secure_hash(user_pass),
                    "encrypted_content": []
                }
                update_user_data(user_database)
                st.success("✅ Account created successfully!")
        else:
            st.error("Username and password are mandatory fields.")

# === User Login ===
elif selected_page == "User Login":
    st.subheader("🔐 Access Your Account")
    
    # Account lock verification
    if time.time() < st.session_state.account_locked_until:
        wait_time = int(st.session_state.account_locked_until - time.time())
        st.error(f"⏳ Account temporarily locked. Please wait {wait_time} seconds.")
        st.stop()

    login_id = st.text_input("Your Username")
    login_pass = st.text_input("Your Password", type="password")

    if st.button("Sign In"):
        if login_id in user_database and user_database[login_id]["password"] == secure_hash(login_pass):
            st.session_state.current_user = login_id
            st.session_state.login_attempts = 0
            st.success(f"✅ Welcome back {login_id}!")
        else:
            st.session_state.login_attempts += 1
            attempts_left = 3 - st.session_state.login_attempts
            st.error(f"❌ Authentication failed! Remaining attempts: {attempts_left}")

            if st.session_state.login_attempts >= 3:
                st.session_state.account_locked_until = time.time() + ACCOUNT_LOCK_TIME
                st.error("🔒 Account locked for security. Please try again after 60 seconds.")
                st.stop()

# === Save Information ===
elif selected_page == "Save Information":
    if not st.session_state.current_user:
        st.warning("🔒 Authentication required. Please sign in.")
    else:
        st.subheader("💾 Store Protected Content")
        user_content = st.text_area("Enter your confidential data")
        encryption_phrase = st.text_input("Security Phrase (for encryption)", type="password")
        
        if st.button("Secure & Store"):
            if user_content and encryption_phrase:
                protected_data = lock_content(user_content, encryption_phrase)
                user_database[st.session_state.current_user]["encrypted_content"].append(protected_data)
                update_user_data(user_database)
                st.success("✅ Data secured and stored successfully!")
            else:
                st.error("Please complete all required fields.")

# === Access Information ===
elif selected_page == "Access Information":
    if not st.session_state.current_user:
        st.warning("🔒 Please authenticate to continue.")
    else:
        st.subheader("🔓 Retrieve Your Protected Data")
        user_entries = user_database.get(st.session_state.current_user, {}).get("encrypted_content", [])

        if not user_entries:
            st.info("ℹ️ No secured content available.")
        else:
            st.write(f"🔒 You have {len(user_entries)} protected data items:")
            
            # Display all entries with selection capability
            for idx, entry in enumerate(user_entries):
                st.text(f"Item #{idx+1}")
                st.code(entry[:50] + "..." if len(entry) > 50 else entry, language="text")
                st.write("")

            # User selection for decryption
            selected_item = st.number_input("Choose item number to access", 
                                          min_value=1, 
                                          max_value=len(user_entries), 
                                          value=1)
            
            chosen_data = user_entries[selected_item-1]
            st.text_area("Selected protected content", value=chosen_data, height=100, disabled=True)
            
            decryption_key = st.text_input("Enter Security Phrase to Decrypt", type="password")

            if st.button("Unlock Content"):
                decrypted_result = unlock_content(chosen_data, decryption_key)
                if decrypted_result:
                    st.success("✅ Content successfully unlocked!")
                    st.text_area("Decrypted information", value=decrypted_result, height=150)
                else:
                    st.error("❌ Incorrect security phrase or damaged data.")