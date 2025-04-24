import streamlit as st
from cryptography.fernet import Fernet
import hashlib

# Generate a single encryption key on session start
if 'fernet_key' not in st.session_state:
    st.session_state.fernet_key = Fernet.generate_key()
    st.session_state.fernet = Fernet(st.session_state.fernet_key)

# In-memory data store
if 'stored_data' not in st.session_state:
    st.session_state.stored_data = {}

# Track failed attempts
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0

# Logged in state
if 'authenticated' not in st.session_state:
    st.session_state.authenticated = True  # Assume authenticated at start

# Simple login password
LOGIN_PASSWORD = "admin123"

# Helper: Hash a passkey
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Insert encrypted data
def insert_data(identifier, text, passkey):
    encrypted_text = st.session_state.fernet.encrypt(text.encode()).decode()
    hashed_pass = hash_passkey(passkey)
    st.session_state.stored_data[identifier] = {
        "encrypted_text": encrypted_text,
        "passkey": hashed_pass
    }

# Retrieve and decrypt data
def retrieve_data(identifier, passkey):
    data_entry = st.session_state.stored_data.get(identifier)
    if not data_entry:
        return None, "No data found for this identifier."

    hashed_input = hash_passkey(passkey)
    if hashed_input == data_entry["passkey"]:
        decrypted = st.session_state.fernet.decrypt(data_entry["encrypted_text"].encode()).decode()
        st.session_state.failed_attempts = 0  # Reset on success
        return decrypted, None
    else:
        st.session_state.failed_attempts += 1
        return None, "Incorrect passkey."

# Login form
def login_page():
    st.title("🔐 Reauthorization Required")
    password = st.text_input("Enter admin password to continue", type="password")
    if st.button("Login"):
        if password == LOGIN_PASSWORD:
            st.success("Login successful!")
            st.session_state.authenticated = True
            st.session_state.failed_attempts = 0
        else:
            st.error("Incorrect password.")

# Navigation
st.sidebar.title("🔐 Secure Data System")
page = st.sidebar.radio("Navigate", ["Home", "Insert Data", "Retrieve Data"])

# Redirect if failed attempts >= 3
if st.session_state.failed_attempts >= 3:
    st.session_state.authenticated = False

if not st.session_state.authenticated:
    login_page()
else:
    if page == "Home":
        st.title("🏠 Welcome to Secure Data System")
        st.write("Choose an action from the sidebar.")
        st.markdown("- 🔐 Insert new encrypted data")
        st.markdown("- 🔓 Retrieve data with a passkey")

    elif page == "Insert Data":
        st.title("🔐 Insert Encrypted Data")
        identifier = st.text_input("Enter unique data identifier (e.g., user1_data)")
        text = st.text_area("Enter text to encrypt")
        passkey = st.text_input("Enter your passkey", type="password")

        if st.button("Store Data"):
            if identifier and text and passkey:
                insert_data(identifier, text, passkey)
                st.success("✅ Data encrypted and stored successfully!")
            else:
                st.warning("Please fill all fields.")

    elif page == "Retrieve Data":
        st.title("🔓 Retrieve Encrypted Data")
        identifier = st.text_input("Enter data identifier")
        passkey = st.text_input("Enter your passkey", type="password")

        if st.button("Decrypt Data"):
            if identifier and passkey:
                decrypted, error = retrieve_data(identifier, passkey)
                if decrypted:
                    st.success("✅ Decryption Successful!")
                    st.code(decrypted)
                else:
                    st.error(error)
                    st.warning(f"❗ Failed Attempts: {st.session_state.failed_attempts}/3")
            else:
                st.warning("Please fill all fields.")
