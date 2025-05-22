import streamlit as st
import hashlib
from cryptography.fernet import Fernet

KEY = Fernet.generate_key()
cipher = Fernet(KEY)

if "stored_data" not in st.session_state:
    st.session_state.stored_data = {}  
    

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

if "authenticated" not in st.session_state:
    st.session_state.authenticated = True  

def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text, passkey):
    hashed_passkey = hash_passkey(passkey)

    data_entry = st.session_state.stored_data.get(encrypted_text)
    if data_entry and data_entry["passkey"] == hashed_passkey:
        st.session_state.failed_attempts = 0
        return cipher.decrypt(encrypted_text.encode()).decode()
    else:
        st.session_state.failed_attempts += 1
        return None

st.set_page_config(page_title=" Secure Data Storage", layout="centered")
st.title(" Secure Data Encryption System")

menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)

if choice == "Home":
    st.subheader(" Welcome")
    st.write("Store and retrieve encrypted data using unique passkeys.")
    st.write("All data is kept securely in memory for this session only.")

elif choice == "Store Data":
    st.subheader(" Store Data Securely")
    user_data = st.text_area("Enter Data to Store:")
    passkey = st.text_input("Enter a Secure Passkey:", type="password")

    if st.button("Encrypt & Store"):
        if user_data and passkey:
            encrypted_text = encrypt_data(user_data)
            st.session_state.stored_data[encrypted_text] = {
                "encrypted_text": encrypted_text,
                "passkey": hash_passkey(passkey)
            }
            st.success("Data encrypted and stored successfully!")
            st.code(encrypted_text, language="text")
        else:
            st.error(" Please enter both data and passkey.")

elif choice == "Retrieve Data":
    if not st.session_state.authenticated:
        st.warning(" You must reauthorize before accessing this page.")
        st.experimental_rerun()
    st.subheader("🔍 Retrieve Your Data")
    encrypted_text = st.text_area("Enter Encrypted Data:")
    passkey = st.text_input("Enter Your Passkey:", type="password")

    if st.button("Decrypt"):
        if encrypted_text and passkey:
            decrypted_text = decrypt_data(encrypted_text, passkey)

            if decrypted_text:
                st.success(" Decryption successful!")
                st.text_area("Decrypted Data:", decrypted_text, height=150)
            else:
                remaining = 3 - st.session_state.failed_attempts
                if remaining > 0:
                    st.error(f" Incorrect passkey! Attempts remaining: {remaining}")
                if st.session_state.failed_attempts >= 3:
                    st.session_state.authenticated = False
                    st.warning(" Too many failed attempts. Redirecting to login.")
                    st.experimental_rerun()
        else:
            st.error(" Both fields are required.")

elif choice == "Login":
    st.subheader(" Reauthorization Required")
    login_password = st.text_input("Enter Master Password:", type="password")

    if st.button("Login"):
        if login_password == "V3ryS3cu4eP@$$w0rd": 
            st.session_state.authenticated = True
            st.session_state.failed_attempts = 0
            st.success("Logged in successfully.")
            st.experimental_rerun()
        else:
            st.error("Incorrect master password.")