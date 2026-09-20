import hashlib
import pickle
import os
from datetime import datetime

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Util.Padding import pad, unpad

# ============================ USER ACCOUNTS ============================
USERS = {
    "doctor1": ("123", "doctor"),
    "nurse1": ("123", "nurse"),
    "admin1": ("123", "admin"),
}

ROLE_NAMES = {
    "doctor": "Doctor",
    "nurse": "Nurse",
    "admin": "Admin",
}

# ========================== FIXED SETTINGS ==========================
CIPHER_KEY = b"0123456789ABCDEF"
DATA_FILE = "healthsecure_rsa_records.pkl"
RECORDS = []
USER_KEYS = {}

# ========================= CRYPTO FUNCTIONS =========================
def encrypt_data(data, key=CIPHER_KEY):
    return AES.new(key, AES.MODE_ECB).encrypt(pad(data.encode(), 16))


def decrypt_data(encrypted_data, key=CIPHER_KEY):
    return unpad(AES.new(key, AES.MODE_ECB).decrypt(encrypted_data), 16).decode()


def data_bytes(data):
    if isinstance(data, bytes):
        return data
    if isinstance(data, str):
        return data.encode()
    return pickle.dumps(data)


def hash_data(data):
    return hashlib.sha256(data_bytes(data)).hexdigest()


def generate_keys():
    private_key = RSA.generate(2048)
    return private_key.publickey(), private_key


def sign_data(data, private_key):
    return pkcs1_15.new(private_key).sign(
        SHA256.new(data_bytes(data))
    )


def verify_signature(data, signature, public_key):
    try:
        pkcs1_15.new(public_key).verify(
            SHA256.new(data_bytes(data)), signature
        )
        return True
    except (ValueError, TypeError):
        return False


def export_public_key(public_key):
    return public_key.export_key()


def import_public_key(saved_key):
    return RSA.import_key(saved_key)


def get_user_keys(username):
    if username not in USER_KEYS:
        USER_KEYS[username] = generate_keys()
    return USER_KEYS[username]


# ========================== STORAGE HELPERS ==========================
def load_records():
    global RECORDS
    try:
        with open(DATA_FILE, "rb") as file:
            RECORDS = pickle.load(file)
    except (FileNotFoundError, EOFError):
        RECORDS = []


def save_records():
    with open(DATA_FILE, "wb") as file:
        pickle.dump(RECORDS, file)


def get_input_data():
    print("\n1. Enter patient information")
    print("2. Read patient information from file")
    choice = input("Choice: ")

    if choice == "1":
        print("\nEnter patient information:")
        name = input("Name: ")
        age = input("Age: ")
        gender = input("Gender: ")
        blood = input("Blood Group: ")
        diagnosis = input("Diagnosis: ")
        details = input("Medical Details: ")

        return (
            f"Name: {name}\n"
            f"Age: {age}\n"
            f"Gender: {gender}\n"
            f"Blood Group: {blood}\n"
            f"Diagnosis: {diagnosis}\n"
            f"Medical Details: {details}"
        ), "Keyboard Entry"

    if choice == "2":
        filename = input("Enter file path: ").strip().strip('"')
        try:
            with open(filename, "r", encoding="utf-8") as file:
                return file.read(), os.path.basename(filename)
        except Exception as e:
            print("Error:", e)
            return None, None

    print("Invalid choice")
    return None, None


def select_record(records):
    if not records:
        print("No records found")
        return None

    for index, record in enumerate(records):
        print(index + 1, record["record_id"], record["timestamp"])

    try:
        index = int(input("Select record: ")) - 1
        if 0 <= index < len(records):
            return records[index]
    except ValueError:
        pass

    print("Invalid record")
    return None


# ============================ DOCTOR ACTIONS ==========================
def upload_record(username):
    data, filename = get_input_data()

    if data is None:
        return

    encrypted = encrypt_data(data)
    public_key, private_key = get_user_keys(username)

    record_id = "P" + str(len(RECORDS) + 1).zfill(3)

    RECORDS.append({
        "record_id": record_id,
        "patient_name": data.split("\n")[0].replace("Name: ", ""),
        "filename": filename,
        "encrypted": encrypted,
        "encrypted_hash": hash_data(encrypted),
        "signature": sign_data(encrypted, private_key),
        "public_key": export_public_key(public_key),
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    })

    save_records()

    print("\nPatient record stored successfully.")
    print("Record ID:", record_id)
    print("SHA-256 hash generated.")
    print("RSA digital signature generated.")


def view_doctor_records():
    if not RECORDS:
        print("No records found")
        return

    for record in RECORDS:
        print("\nRecord ID:", record["record_id"])
        print("Patient Name:", record["patient_name"])
        print("Filename:", record["filename"])
        print("Encrypted Data:", record["encrypted"].hex())
        print("SHA-256:", record["encrypted_hash"])
        print("Signature:", record["signature"])
        print("Timestamp:", record["timestamp"])


def doctor_decrypt_verify(username):
    record = select_record(RECORDS)

    if record is None:
        return

    public_key, private_key = get_user_keys(username)

    # Recompute hash of encrypted data
    hash_ok = hash_data(record["encrypted"]) == record["encrypted_hash"]

    # Verify RSA signature
    signature_ok = verify_signature(
        record["encrypted"],
        record["signature"],
        public_key
    )

    print("\nIntegrity Verification:",
          "VALID" if hash_ok else "INVALID")
    print("Signature Verification:",
          "VALID" if signature_ok else "INVALID")

    if hash_ok and signature_ok:
        data = decrypt_data(record["encrypted"])

        print("\nBoth checks successful.")
        print("\nDecrypted Patient Information:")
        print(data)
    else:
        print("\nAccess denied.")
        print("Patient information will NOT be displayed.")


# ============================= NURSE ================================
def nurse_view_records():
    if not RECORDS:
        print("No records found")
        return

    for record in RECORDS:
        public_key = import_public_key(record["public_key"])

        hash_ok = hash_data(record["encrypted"]) == record["encrypted_hash"]
        signature_ok = verify_signature(
            record["encrypted"],
            record["signature"],
            public_key
        )

        print("\nRecord ID:", record["record_id"])
        print("Filename:", record["filename"])
        print("Encrypted Data:", record["encrypted"].hex())
        print("SHA-256:", record["encrypted_hash"])
        print("Signature:", record["signature"])
        print("Timestamp:", record["timestamp"])
        print("Integrity:", "VALID" if hash_ok else "INVALID")
        print("Signature:", "VALID" if signature_ok else "INVALID")
        print("Plaintext: ACCESS DENIED")


# ============================= ADMIN ================================
def admin_view_records():
    if not RECORDS:
        print("No records found")
        return

    for record in RECORDS:
        public_key = import_public_key(record["public_key"])

        signature_ok = verify_signature(
            record["encrypted"],
            record["signature"],
            public_key
        )

        print("\nRecord ID:", record["record_id"])
        print("Patient Name:", record["patient_name"])
        print("SHA-256:", record["encrypted_hash"])
        print("Timestamp:", record["timestamp"])
        print(
            "Digital Signature:",
            "VALID" if signature_ok else "INVALID"
        )


# ============================== MENUS ===============================
def doctor_menu(username):
    while True:
        print("\n========== HealthSecure ==========")
        print("Logged in as: Doctor")
        print("----------------------------------")
        print("1. Enter patient information")
        print("2. Read patient information from file")
        print("3. View patient records")
        print("4. Decrypt and verify patient record")
        print("0. Logout")

        choice = input("Choice: ")

        if choice == "1":
            upload_record(username)
        elif choice == "2":
            upload_record(username)
        elif choice == "3":
            view_doctor_records()
        elif choice == "4":
            doctor_decrypt_verify(username)
        elif choice == "0":
            return


def nurse_menu():
    while True:
        print("\n========== HealthSecure ==========")
        print("Logged in as: Nurse")
        print("----------------------------------")
        print("1. View encrypted patient records")
        print("0. Logout")

        choice = input("Choice: ")

        if choice == "1":
            nurse_view_records()
        elif choice == "0":
            return


def admin_menu():
    while True:
        print("\n========== HealthSecure ==========")
        print("Logged in as: Admin")
        print("----------------------------------")
        print("1. View patient record information")
        print("0. Logout")

        choice = input("Choice: ")

        if choice == "1":
            admin_view_records()
        elif choice == "0":
            return


# ================================ MAIN ===============================
def main():
    load_records()

    while True:
        print("\n======================================")
        print("          HEALTHSECURE")
        print(" Secure Patient Information System")
        print("======================================")
        print("1. Login")
        print("0. Exit")

        choice = input("Choice: ")

        if choice == "0":
            break

        if choice != "1":
            print("Invalid choice")
            continue

        username = input("Username: ")
        password = input("Password: ")

        user = USERS.get(username)

        if user and user[0] == password:
            role = user[1]

            if role == "doctor":
                doctor_menu(username)
            elif role == "nurse":
                nurse_menu()
            elif role == "admin":
                admin_menu()
        else:
            print("Invalid login")


if __name__ == "__main__":
    main()
