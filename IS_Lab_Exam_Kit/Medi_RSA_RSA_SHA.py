'''
HealthSecure

A hospital wants to develop a secure patient-information management system called HealthSecure. The system has three roles: Doctor, Nurse, and Admin.

The system must ensure the confidentiality, integrity, and authenticity of patient information such as name, age, gender, blood group, diagnosis, and other medical details.

Doctor:

The Doctor should be able to:

Enter patient information such as Name, Age, Gender, Blood Group, Diagnosis, etc.
Store the patient information in a suitable data structure such as a list, array, dictionary, or file.

Generate an RSA key pair consisting of a public key and private key.
Encrypt the patient information using RSA encryption and the Doctor's RSA public key.
Compute the SHA-256 hash of the encrypted patient information.
Digitally sign the SHA-256 hash using the Doctor's RSA private key.
Store the encrypted patient data, SHA-256 hash, digital signature, and timestamp.

View previously stored patient records.
Decrypt an encrypted patient record using the corresponding RSA private key.
Recompute the SHA-256 hash of the encrypted data and compare it with the stored hash to verify integrity.
Verify the RSA digital signature using the Doctor's public key to verify authenticity.
Display the decrypted patient information only when the integrity and signature verification are successful.


Nurse:

The Nurse should be able to:

View the available encrypted patient records.

View the filename/record ID, encrypted data, hash, signature, and timestamp as permitted.

Must not be allowed to decrypt or view the plaintext patient information.

Recompute the SHA-256 hash of the encrypted data and compare it with the stored hash to verify data integrity.

Verify the Doctor's RSA digital signature using the Doctor's public key to verify authenticity.

Display the verification result along with a timestamp.

The Nurse must not have access to the Doctor's private key.


Admin:

The Admin should be able to:

View only the patient record ID/name, SHA-256 hash, and timestamp.

Verify the Doctor's RSA digital signature using the Doctor's public key.

Display whether the digital signature is VALID or INVALID.

The Admin must not be allowed to decrypt or view the plaintext patient information.

The Admin must not have access to the Doctor's private key.


Task:

Develop a menu-driven Python program implementing the above requirements using:

RSA asymmetric encryption and decryption

RSA public and private keys

SHA-256 hashing

RSA digital signatures

Role-Based Access Control (RBAC)

Patient data handling using lists, dictionaries, arrays, or files

Timestamps

Secure storage of encrypted records, hashes, signatures, and other required information
Appropriate access restrictions for Doctor, Nurse, and Admin
The program should ensure that each role can perform only its authorized operations and that patient information remains confidential while its integrity and authenticity can be verified.
'''
import hashlib
import pickle
import os
from datetime import datetime

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15


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

DATA_FILE = "healthsecure_rsa_records.pkl"
KEY_FILE = "healthsecure_rsa_keys.pkl"

RECORDS = []
USER_KEYS = {}


# ========================= CRYPTO FUNCTIONS =========================

def generate_keys():
    private_key = RSA.generate(2048)
    return private_key.publickey(), private_key


def load_keys():
    global USER_KEYS

    try:
        with open(KEY_FILE, "rb") as file:
            saved_keys = pickle.load(file)

        for username, keys in saved_keys.items():
            public_key = RSA.import_key(keys[0])
            private_key = RSA.import_key(keys[1])
            USER_KEYS[username] = (public_key, private_key)

    except (FileNotFoundError, EOFError):
        USER_KEYS = {}


def save_keys():
    saved_keys = {}

    for username, keys in USER_KEYS.items():
        public_key, private_key = keys

        saved_keys[username] = (
            public_key.export_key(),
            private_key.export_key()
        )

    with open(KEY_FILE, "wb") as file:
        pickle.dump(saved_keys, file)


def get_user_keys(username):

    if username not in USER_KEYS:
        USER_KEYS[username] = generate_keys()
        save_keys()

    return USER_KEYS[username]


# ========================= RSA ENCRYPTION =========================

def encrypt_data(data, public_key):

    data = data.encode()

    # RSA-2048 with SHA-256 OAEP can encrypt
    # maximum 190 bytes in one block.
    block_size = 190

    encrypted_data = b""

    for i in range(0, len(data), block_size):
        block = data[i:i + block_size]

        cipher = PKCS1_OAEP.new(public_key)
        encrypted_data += cipher.encrypt(block)

    return encrypted_data


def decrypt_data(encrypted_data, private_key):

    # RSA-2048 ciphertext block size = 256 bytes
    block_size = 256

    decrypted_data = b""

    for i in range(0, len(encrypted_data), block_size):
        block = encrypted_data[i:i + block_size]

        cipher = PKCS1_OAEP.new(private_key)
        decrypted_data += cipher.decrypt(block)

    return decrypted_data.decode()


# ========================= HASH FUNCTIONS =========================

def data_bytes(data):

    if isinstance(data, bytes):
        return data

    if isinstance(data, str):
        return data.encode()

    return pickle.dumps(data)


def hash_data(data):

    return hashlib.sha256(data_bytes(data)).hexdigest()


# ========================= DIGITAL SIGNATURE =========================

def sign_data(data, private_key):

    return pkcs1_15.new(private_key).sign(
        SHA256.new(data_bytes(data))
    )


def verify_signature(data, signature, public_key):

    try:
        pkcs1_15.new(public_key).verify(
            SHA256.new(data_bytes(data)),
            signature
        )

        return True

    except (ValueError, TypeError):
        return False


def export_public_key(public_key):

    return public_key.export_key()


def import_public_key(saved_key):

    return RSA.import_key(saved_key)


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


# ========================== INPUT FUNCTIONS ==========================

def get_keyboard_data():

    print("\nEnter patient information:")

    name = input("Name: ")
    age = input("Age: ")
    gender = input("Gender: ")
    blood = input("Blood Group: ")
    diagnosis = input("Diagnosis: ")
    details = input("Medical Details: ")

    data = (
        f"Name: {name}\n"
        f"Age: {age}\n"
        f"Gender: {gender}\n"
        f"Blood Group: {blood}\n"
        f"Diagnosis: {diagnosis}\n"
        f"Medical Details: {details}"
    )

    return data, "Keyboard Entry"


def get_file_data():

    filename = input("Enter file path: ").strip().strip('"')

    try:

        with open(filename, "r", encoding="utf-8") as file:
            data = file.read()

        return data, os.path.basename(filename)

    except Exception as e:

        print("Error:", e)

        return None, None


# ========================== RECORD SELECTION ==========================

def select_record(records):

    if not records:

        print("No records found")
        return None

    for index, record in enumerate(records):

        print(
            index + 1,
            record["record_id"],
            record["timestamp"]
        )

    try:

        index = int(input("Select record: ")) - 1

        if 0 <= index < len(records):

            return records[index]

    except ValueError:

        pass

    print("Invalid record")

    return None


# ============================ DOCTOR ACTIONS ==========================

def upload_record(username, data, filename):

    if data is None:
        return

    # Get Doctor RSA keys
    public_key, private_key = get_user_keys(username)

    # Encrypt patient information using
    # Doctor's RSA PUBLIC KEY
    encrypted = encrypt_data(data, public_key)

    # SHA-256 hash of encrypted patient information
    encrypted_hash = hash_data(encrypted)

    # Digital signature using Doctor's RSA PRIVATE KEY
    signature = sign_data(encrypted, private_key)

    record_id = "P" + str(len(RECORDS) + 1).zfill(3)

    RECORDS.append({

        "record_id": record_id,

        "patient_name":
            data.split("\n")[0].replace("Name: ", ""),

        "filename": filename,

        "encrypted": encrypted,

        "encrypted_hash": encrypted_hash,

        "signature": signature,

        "public_key":
            export_public_key(public_key),

        "timestamp":
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })

    save_records()

    print("\nPatient record stored successfully.")
    print("Record ID:", record_id)
    print("RSA encryption completed.")
    print("SHA-256 hash generated.")
    print("RSA digital signature generated.")


def enter_patient_information(username):

    data, filename = get_keyboard_data()

    upload_record(username, data, filename)


def read_patient_information_file(username):

    data, filename = get_file_data()

    if data is not None:

        upload_record(username, data, filename)


def view_doctor_records():

    if not RECORDS:

        print("No records found")
        return

    for record in RECORDS:

        print("\nRecord ID:", record["record_id"])
        print("Patient Name:", record["patient_name"])
        print("Filename:", record["filename"])

        print(
            "Encrypted Data:",
            record["encrypted"].hex()
        )

        print(
            "SHA-256:",
            record["encrypted_hash"]
        )

        print(
            "Signature:",
            record["signature"].hex()
        )

        print(
            "Timestamp:",
            record["timestamp"]
        )


def doctor_decrypt_verify(username):

    record = select_record(RECORDS)

    if record is None:
        return

    public_key, private_key = get_user_keys(username)

    # Recompute SHA-256 hash
    hash_ok = (
        hash_data(record["encrypted"])
        == record["encrypted_hash"]
    )

    # Verify Doctor's RSA signature
    signature_ok = verify_signature(
        record["encrypted"],
        record["signature"],
        public_key
    )

    print(
        "\nIntegrity Verification:",
        "VALID" if hash_ok else "INVALID"
    )

    print(
        "Signature Verification:",
        "VALID" if signature_ok else "INVALID"
    )

    # Decrypt ONLY when both checks pass
    if hash_ok and signature_ok:

        try:

            data = decrypt_data(
                record["encrypted"],
                private_key
            )

            print("\nBoth checks successful.")

            print("\nDecrypted Patient Information:")
            print(data)

        except Exception:

            print("\nDecryption failed.")

    else:

        print("\nAccess denied.")
        print("Patient information will NOT be displayed.")


# ============================= NURSE ================================

def nurse_view_records():

    if not RECORDS:

        print("No records found")
        return

    for record in RECORDS:

        public_key = import_public_key(
            record["public_key"]
        )

        # Recompute SHA-256
        hash_ok = (
            hash_data(record["encrypted"])
            == record["encrypted_hash"]
        )

        # Verify Doctor's RSA signature
        signature_ok = verify_signature(
            record["encrypted"],
            record["signature"],
            public_key
        )

        print("\nRecord ID:", record["record_id"])
        print("Filename:", record["filename"])

        print(
            "Encrypted Data:",
            record["encrypted"].hex()
        )

        print(
            "SHA-256:",
            record["encrypted_hash"]
        )

        print(
            "Signature:",
            record["signature"].hex()
        )

        print(
            "Timestamp:",
            record["timestamp"]
        )

        print(
            "Integrity:",
            "VALID" if hash_ok else "INVALID"
        )

        print(
            "Digital Signature:",
            "VALID" if signature_ok else "INVALID"
        )

        print("Plaintext: ACCESS DENIED")


# ============================= ADMIN ================================

def admin_view_records():

    if not RECORDS:

        print("No records found")
        return

    for record in RECORDS:

        public_key = import_public_key(
            record["public_key"]
        )

        signature_ok = verify_signature(
            record["encrypted"],
            record["signature"],
            public_key
        )

        print("\nRecord ID:", record["record_id"])
        print("Patient Name:", record["patient_name"])

        print(
            "SHA-256:",
            record["encrypted_hash"]
        )

        print(
            "Timestamp:",
            record["timestamp"]
        )

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

            enter_patient_information(username)

        elif choice == "2":

            read_patient_information_file(username)

        elif choice == "3":

            view_doctor_records()

        elif choice == "4":

            doctor_decrypt_verify(username)

        elif choice == "0":

            return

        else:

            print("Invalid choice")


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

        else:

            print("Invalid choice")


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

        else:

            print("Invalid choice")


# ================================ MAIN ===============================

def main():

    load_records()
    load_keys()

    while True:

        print("\n======================================")
        print("             HEALTHSECURE")
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