"""
HealthSecure
------------
Menu-driven hospital patient-information security system.

Algorithms:
- RSA-2048 public/private key pair
- RSA-OAEP + SHA-256 for patient-data encryption
- SHA-256 for encrypted-record integrity
- RSA PKCS#1 v1.5 + SHA-256 for digital signatures
- RBAC: Doctor, Nurse, Admin

Educational/lab implementation.
"""

import base64
import hashlib
import json
import os
import pickle
from datetime import datetime

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15


# ============================ USER ACCOUNTS ============================

USERS = {
    "doctor1": ("123", "Doctor"),
    "nurse1": ("123", "Nurse"),
    "admin1": ("123", "Admin"),
}


# ========================== FIXED SETTINGS ============================

DATA_FILE = "healthsecure_records.pkl"
PRIVATE_KEY_FILE = "healthsecure_doctor_private.pem"
RECORDS = []


# =========================== BASIC HELPERS ============================

def timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def save_records():
    with open(DATA_FILE, "wb") as file:
        pickle.dump(RECORDS, file)


def load_records():
    global RECORDS

    try:
        with open(DATA_FILE, "rb") as file:
            RECORDS = pickle.load(file)
    except (FileNotFoundError, EOFError, pickle.UnpicklingError):
        RECORDS = []


def bytes_hash(data):
    return hashlib.sha256(data).hexdigest()


def get_next_record_id():
    if not RECORDS:
        return 1
    return max(record["record_id"] for record in RECORDS) + 1


def encode_bytes(data):
    return base64.b64encode(data).decode()


def decode_bytes(data):
    return base64.b64decode(data.encode())


# =========================== RSA KEY FUNCTIONS =========================

def generate_doctor_keys():
    """
    Generate one RSA-2048 key pair for the Doctor.
    The private key is kept in the Doctor-only key file.
    """
    if os.path.exists(PRIVATE_KEY_FILE):
        return

    private_key = RSA.generate(2048)

    with open(PRIVATE_KEY_FILE, "wb") as file:
        file.write(
            private_key.export_key(
                format="PEM",
                passphrase=None
            )
        )

    print("Doctor RSA-2048 key pair generated.")


def load_doctor_private_key():
    if not os.path.exists(PRIVATE_KEY_FILE):
        generate_doctor_keys()

    with open(PRIVATE_KEY_FILE, "rb") as file:
        return RSA.import_key(file.read())


def get_doctor_public_key():
    private_key = load_doctor_private_key()
    return private_key.publickey()


# ============================ RSA ENCRYPTION ===========================

def rsa_encrypt(data, public_key):
    """
    Encrypt arbitrary-size data using RSA-OAEP in multiple blocks.

    A 2048-bit RSA key cannot encrypt an arbitrarily large message in
    one operation, so the plaintext is divided into OAEP-sized blocks.
    """
    cipher = PKCS1_OAEP.new(public_key, hashAlgo=SHA256)

    block_size = public_key.size_in_bytes() - 2 * SHA256.digest_size - 2

    encrypted_blocks = []

    for i in range(0, len(data), block_size):
        block = data[i:i + block_size]
        encrypted_blocks.append(cipher.encrypt(block))

    return b"".join(encrypted_blocks)


def rsa_decrypt(encrypted_data, private_key):
    """
    Decrypt the RSA-OAEP blocks created by rsa_encrypt().
    """
    cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)

    block_size = private_key.size_in_bytes()
    decrypted = bytearray()

    for i in range(0, len(encrypted_data), block_size):
        block = encrypted_data[i:i + block_size]
        decrypted.extend(cipher.decrypt(block))

    return bytes(decrypted)


# ========================== HASHING FUNCTIONS ==========================

def calculate_hash(encrypted_data):
    return bytes_hash(encrypted_data)


# ========================= DIGITAL SIGNATURE ==========================

def sign_encrypted_data(encrypted_data, private_key):
    """
    SHA-256 is computed over the encrypted data and the resulting
    digest is authenticated using the Doctor's RSA private key.
    """
    digest = SHA256.new(encrypted_data)
    return pkcs1_15.new(private_key).sign(digest)


def verify_signature(encrypted_data, signature, public_key):
    try:
        digest = SHA256.new(encrypted_data)
        pkcs1_15.new(public_key).verify(digest, signature)
        return True
    except (ValueError, TypeError):
        return False


# ========================= PATIENT DATA INPUT =========================

def enter_patient_information():
    print("\n=== Enter Patient Information ===")

    patient = {
        "name": input("Name: ").strip(),
        "age": input("Age: ").strip(),
        "gender": input("Gender: ").strip(),
        "blood_group": input("Blood Group: ").strip(),
        "diagnosis": input("Diagnosis: ").strip(),
        "medical_details": input("Other Medical Details: ").strip(),
    }

    return patient


def read_patient_information_from_file():
    print("\n=== Read Patient Information From File ===")

    filename = input("Enter file path: ").strip().strip('"')

    try:
        with open(filename, "r", encoding="utf-8") as file:
            data = file.read()

        # If the file contains JSON, preserve the fields.
        try:
            patient = json.loads(data)

            if isinstance(patient, dict):
                return patient
        except json.JSONDecodeError:
            pass

        # Otherwise store the complete file contents as medical details.
        return {
            "name": input("Patient Name: ").strip(),
            "age": "",
            "gender": "",
            "blood_group": "",
            "diagnosis": "",
            "medical_details": data,
        }

    except FileNotFoundError:
        print("File not found.")
        return None
    except OSError as error:
        print("Unable to read file:", error)
        return None


def patient_to_bytes(patient):
    """
    Convert patient dictionary into deterministic JSON bytes so that
    encryption/decryption always reproduces the same information.
    """
    data = json.dumps(
        patient,
        sort_keys=True,
        separators=(",", ":")
    )

    return data.encode("utf-8")


def bytes_to_patient(data):
    return json.loads(data.decode("utf-8"))


# ============================ RECORD HELPERS ===========================

def select_record():
    if not RECORDS:
        print("No patient records found.")
        return None

    print("\n=== Available Records ===")

    for index, record in enumerate(RECORDS):
        print(
            f"{index + 1}. "
            f"Record ID: {record['record_id']} | "
            f"Patient: {record['patient_name']} | "
            f"Timestamp: {record['timestamp']}"
        )

    try:
        choice = int(input("Select record: ")) - 1

        if 0 <= choice < len(RECORDS):
            return RECORDS[choice]

    except ValueError:
        pass

    print("Invalid record selection.")
    return None


def create_patient_record(patient):
    private_key = load_doctor_private_key()
    public_key = private_key.publickey()

    plaintext = patient_to_bytes(patient)

    encrypted_data = rsa_encrypt(plaintext, public_key)

    encrypted_hash = calculate_hash(encrypted_data)

    signature = sign_encrypted_data(encrypted_data, private_key)

    record = {
        "record_id": get_next_record_id(),

        # Patient name is kept as permitted metadata.
        "patient_name": patient.get("name", "Unknown"),

        # Source/filename can be displayed by Nurse.
        "filename": "Keyboard Entry",

        # Base64 makes the encrypted binary data safe for storage.
        "encrypted_data": encode_bytes(encrypted_data),

        "sha256_hash": encrypted_hash,

        "signature": encode_bytes(signature),

        "public_key": public_key.export_key(),

        "timestamp": timestamp(),
    }

    RECORDS.append(record)
    save_records()

    return record


# ============================= DOCTOR =================================

def doctor_add_patient():
    print("\n1. Enter patient information")
    print("2. Read patient information from file")

    choice = input("Choice: ")

    if choice == "1":
        patient = enter_patient_information()
        filename = "Keyboard Entry"

    elif choice == "2":
        filename = input("Enter file path: ").strip().strip('"')

        try:
            with open(filename, "r", encoding="utf-8") as file:
                data = file.read()

            try:
                patient = json.loads(data)

                if not isinstance(patient, dict):
                    raise ValueError

            except (json.JSONDecodeError, ValueError):
                patient = {
                    "name": input("Patient Name: ").strip(),
                    "age": "",
                    "gender": "",
                    "blood_group": "",
                    "diagnosis": "",
                    "medical_details": data,
                }

        except FileNotFoundError:
            print("File not found.")
            return
        except OSError as error:
            print("Unable to read file:", error)
            return

    else:
        print("Invalid choice.")
        return

    if not patient.get("name"):
        print("Patient name is required.")
        return

    record = create_patient_record(patient)

    record["filename"] = filename
    save_records()

    print("\nPatient information encrypted successfully.")
    print("SHA-256 hash generated.")
    print("RSA digital signature generated.")
    print("Patient record stored successfully.")
    print("Record ID:", record["record_id"])
    print("Timestamp:", record["timestamp"])


def doctor_view_records():
    if not RECORDS:
        print("No patient records found.")
        return

    print("\n=== Doctor: Patient Records ===")

    for record in RECORDS:
        print("\nRecord ID:", record["record_id"])
        print("Patient Name:", record["patient_name"])
        print("Filename:", record["filename"])
        print("Encrypted Data:", record["encrypted_data"])
        print("SHA-256 Hash:", record["sha256_hash"])
        print("Digital Signature:", record["signature"])
        print("Timestamp:", record["timestamp"])


def doctor_decrypt_and_verify():
    record = select_record()

    if record is None:
        return

    print("\n=== Doctor: Decrypt and Verify ===")

    encrypted_data = decode_bytes(record["encrypted_data"])
    signature = decode_bytes(record["signature"])

    public_key = RSA.import_key(record["public_key"])
    private_key = load_doctor_private_key()

    # 1. Recompute SHA-256 over encrypted data.
    new_hash = calculate_hash(encrypted_data)
    integrity_ok = new_hash == record["sha256_hash"]

    # 2. Verify Doctor's RSA digital signature.
    signature_ok = verify_signature(
        encrypted_data,
        signature,
        public_key
    )

    print("Integrity Verification:", "VALID" if integrity_ok else "INVALID")
    print("Signature Verification:", "VALID" if signature_ok else "INVALID")

    # Do not decrypt/display patient data unless BOTH checks pass.
    if not (integrity_ok and signature_ok):
        print("\nAccess denied.")
        print("Patient information will NOT be displayed.")
        return

    try:
        plaintext = rsa_decrypt(encrypted_data, private_key)
        patient = bytes_to_patient(plaintext)
    except Exception:
        print("\nDecryption failed.")
        print("Patient information will NOT be displayed.")
        return

    print("\nBoth verification checks successful.")
    print("\n=== Decrypted Patient Information ===")

    for key, value in patient.items():
        print(f"{key.replace('_', ' ').title()}: {value}")


# ============================== NURSE =================================

def nurse_view_encrypted_records():
    if not RECORDS:
        print("No patient records found.")
        return

    print("\n=== Nurse: Encrypted Patient Records ===")

    for record in RECORDS:
        print("\nRecord ID:", record["record_id"])
        print("Filename:", record["filename"])
        print("Encrypted Data:", record["encrypted_data"])
        print("SHA-256 Hash:", record["sha256_hash"])
        print("Digital Signature:", record["signature"])
        print("Timestamp:", record["timestamp"])

        print("Plaintext: ACCESS DENIED")


def nurse_verify_record():
    record = select_record()

    if record is None:
        return

    print("\n=== Nurse: Verify Record ===")

    encrypted_data = decode_bytes(record["encrypted_data"])
    signature = decode_bytes(record["signature"])
    public_key = RSA.import_key(record["public_key"])

    # Nurse can recompute the hash without decrypting.
    new_hash = calculate_hash(encrypted_data)
    integrity_ok = new_hash == record["sha256_hash"]

    # Nurse only needs the public key for signature verification.
    signature_ok = verify_signature(
        encrypted_data,
        signature,
        public_key
    )

    print("Record ID:", record["record_id"])
    print("Timestamp:", timestamp())
    print("Integrity Verification:",
          "VALID" if integrity_ok else "INVALID")
    print("Signature Verification:",
          "VALID" if signature_ok else "INVALID")

    print("\nPlaintext: ACCESS DENIED")
    print("Doctor private key: ACCESS DENIED")


# ============================== ADMIN =================================

def admin_view_records():
    if not RECORDS:
        print("No patient records found.")
        return

    print("\n=== Admin: Record Metadata ===")

    for record in RECORDS:
        encrypted_data = decode_bytes(record["encrypted_data"])
        signature = decode_bytes(record["signature"])
        public_key = RSA.import_key(record["public_key"])

        signature_ok = verify_signature(
            encrypted_data,
            signature,
            public_key
        )

        print("\nRecord ID:", record["record_id"])
        print("Patient Name:", record["patient_name"])
        print("SHA-256 Hash:", record["sha256_hash"])
        print("Timestamp:", record["timestamp"])

        print(
            "Digital Signature:",
            "VALID" if signature_ok else "INVALID"
        )

        print("Encrypted Data: NOT SHOWN")
        print("Plaintext: ACCESS DENIED")


# ============================== RBAC ==================================

def doctor_menu():
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
            patient = enter_patient_information()

            if patient.get("name"):
                record = create_patient_record(patient)

                print("\nPatient information encrypted successfully.")
                print("SHA-256 hash generated.")
                print("RSA digital signature generated.")
                print("Record ID:", record["record_id"])
                print("Timestamp:", record["timestamp"])

        elif choice == "2":
            patient = read_patient_information_from_file()

            if patient and patient.get("name"):
                record = create_patient_record(patient)
                record["filename"] = os.path.basename(filename)
                save_records()

                print("\nPatient information encrypted successfully.")
                print("SHA-256 hash generated.")
                print("RSA digital signature generated.")
                print("Record ID:", record["record_id"])
                print("Timestamp:", record["timestamp"])

        elif choice == "3":
            doctor_view_records()

        elif choice == "4":
            doctor_decrypt_and_verify()

        elif choice == "0":
            return

        else:
            print("Invalid choice.")


def nurse_menu():
    while True:
        print("\n========== HealthSecure ==========")
        print("Logged in as: Nurse")
        print("----------------------------------")
        print("1. View encrypted patient records")
        print("2. Verify record integrity and signature")
        print("0. Logout")

        choice = input("Choice: ")

        if choice == "1":
            nurse_view_encrypted_records()

        elif choice == "2":
            nurse_verify_record()

        elif choice == "0":
            return

        else:
            print("Invalid choice.")


def admin_menu():
    while True:
        print("\n========== HealthSecure ==========")
        print("Logged in as: Admin")
        print("----------------------------------")
        print("1. View patient record metadata")
        print("0. Logout")

        choice = input("Choice: ")

        if choice == "1":
            admin_view_records()

        elif choice == "0":
            return

        else:
            print("Invalid choice.")


# ============================== LOGIN =================================

def login():
    username = input("Username: ").strip()
    password = input("Password: ").strip()

    user = USERS.get(username)

    if user and user[0] == password:
        return user[1]

    print("Invalid username or password.")
    return None


# =============================== MAIN =================================

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
            print("Exiting HealthSecure.")
            break

        if choice != "1":
            print("Invalid choice.")
            continue

        role = login()

        if role == "Doctor":
            # Only the Doctor flow loads/uses the private key.
            generate_doctor_keys()
            doctor_menu()

        elif role == "Nurse":
            nurse_menu()

        elif role == "Admin":
            admin_menu()


if __name__ == "__main__":
    main()
