"""HealthSecure: RBAC-based healthcare record protection lab program."""

from datetime import datetime

from crypto_functions import (
    b64,
    decrypt_data,
    encrypt_data,
    encrypted_bytes,
    hash_data,
    sign_data,
    verify_signature,
)
from record_manager import add_record, get_record, load_records, record_exists


# ========================= INPUT FUNCTIONS =========================

def get_patient_data():
    print("\n1. Enter text")
    print("2. Read from file")
    choice = input("Choice: ").strip()

    if choice == "1":
        return input("Enter patient record: ")
    if choice == "2":
        filename = input("Enter file path: ").strip().strip('"')
        try:
            with open(filename, "r", encoding="utf-8") as file:
                return file.read()
        except OSError as error:
            print("File error:", error)
            return None

    print("Invalid input choice.")
    return None


def choose_encryption():
    print("\n========== ENCRYPTION ==========")
    print("1. AES-128")
    print("2. AES-192")
    print("3. AES-256")
    print("4. DES")
    print("5. 2DES")
    print("6. 3DES")
    print("7. RSA")
    print("8. ElGamal")
    algorithms = {
        "1": "AES-128", "2": "AES-192", "3": "AES-256", "4": "DES",
        "5": "2DES", "6": "3DES", "7": "RSA", "8": "ElGamal",
    }
    algorithm = algorithms.get(input("Choice: ").strip())
    if algorithm is None:
        print("Invalid encryption choice.")
        return None, None

    if algorithm in ("RSA", "ElGamal"):
        print("Mode: N/A for", algorithm)
        return algorithm, "N/A"

    print("1. ECB")
    print("2. CBC")
    mode = {"1": "ECB", "2": "CBC"}.get(input("Mode: ").strip())
    if mode is None:
        print("Invalid mode choice.")
        return None, None
    return algorithm, mode


def choose_hash():
    print("\n1. MD5")
    print("2. SHA-256")
    return {"1": "MD5", "2": "SHA-256"}.get(input("Hash choice: ").strip())


def choose_signature():
    print("\n1. RSA")
    print("2. ElGamal")
    return {"1": "RSA", "2": "ElGamal"}.get(input("Signature choice: ").strip())


def find_record():
    record_id = input("Enter record ID: ").strip()
    record = get_record(record_id)
    if record is None:
        print("Record not found.")
    return record


def show_encrypted_record(record):
    encryption = record["encryption"]
    print("\nRecord ID:", record["record_id"])
    print("Patient:", record["patient_name"])
    print("Encryption:", encryption["algorithm"])
    print("Mode:", encryption["mode"])
    print("Hash type:", record["hash_type"])
    print("Hash:", record["hash_value"])
    print("Signature:", record["signature"]["type"])
    print("Timestamp:", record["timestamp"])

    if isinstance(encryption["ciphertext"], bytes):
        print("Encrypted data (Base64):", b64(encryption["ciphertext"]))
    elif encryption["algorithm"] == "RSA":
        print("Encrypted RSA blocks:", len(encryption["ciphertext"]))
    else:
        print("Encrypted ElGamal pairs:", len(encryption["ciphertext"]))

    if encryption.get("iv"):
        print("IV (Base64):", b64(encryption["iv"]))


# ========================= DOCTOR FUNCTIONS =========================

def create_record():
    print("\n========== CREATE PATIENT RECORD ==========")
    record_id = input("Record ID: ").strip()
    if not record_id:
        print("Record ID cannot be empty.")
        return
    if record_exists(record_id):
        print("This record ID already exists.")
        return

    patient_name = input("Patient name: ").strip()
    pt = get_patient_data()
    if pt is None:
        return

    algorithm, mode = choose_encryption()
    if algorithm is None:
        return
    hash_type = choose_hash()
    if hash_type is None:
        print("Invalid hash choice.")
        return
    signature_type = choose_signature()
    if signature_type is None:
        print("Invalid signature choice.")
        return

    encryption = encrypt_data(pt, algorithm, mode)
    protected_data = encrypted_bytes(encryption)
    hash_value = hash_data(protected_data, hash_type)
    signature = sign_data(protected_data, signature_type)

    record = {
        "record_id": record_id,
        "patient_name": patient_name,
        "encryption": encryption,
        "hash_type": hash_type,
        "hash_value": hash_value,
        "signature": signature,
        "timestamp": datetime.now().strftime("%d-%m-%Y %H:%M:%S"),
    }
    add_record(record)
    print("\nRecord encrypted, hashed, signed and stored successfully.")


def doctor_view_records():
    records = load_records()
    if not records:
        print("No records available.")
        return
    for record in records:
        show_encrypted_record(record)


def decrypt_and_verify():
    record = find_record()
    if record is None:
        return

    protected_data = encrypted_bytes(record["encryption"])
    hash_ok = hash_data(protected_data, record["hash_type"]) == record["hash_value"]
    signature_ok = verify_signature(protected_data, record["signature"])

    print("Hash verification:", "VALID" if hash_ok else "INVALID")
    print("Signature verification:", "VALID" if signature_ok else "INVALID")
    if not (hash_ok and signature_ok):
        print("Record integrity failed. Decryption stopped.")
        return

    try:
        print("\nDecrypted patient record:\n", decrypt_data(record["encryption"]))
    except (ValueError, UnicodeDecodeError) as error:
        print("Decryption error:", error)


def doctor_menu():
    while True:
        print("\n========== HealthSecure: Doctor ==========")
        print("1. Enter text/file and protect record")
        print("2. View encrypted records")
        print("3. Decrypt and verify record")
        print("0. Logout")
        choice = input("Choice: ").strip()

        if choice == "1":
            create_record()
        elif choice == "2":
            doctor_view_records()
        elif choice == "3":
            decrypt_and_verify()
        elif choice == "0":
            return
        else:
            print("Invalid choice.")


# ========================= NURSE FUNCTIONS =========================

def nurse_verify_hash():
    record = find_record()
    if record is None:
        return
    current_hash = hash_data(encrypted_bytes(record["encryption"]), record["hash_type"])
    print("Hash verification:", "VALID" if current_hash == record["hash_value"] else "INVALID")


def nurse_verify_signature():
    record = find_record()
    if record is None:
        return
    valid = verify_signature(encrypted_bytes(record["encryption"]), record["signature"])
    print("Signature verification:", "VALID" if valid else "INVALID")


def nurse_menu():
    while True:
        print("\n========== HealthSecure: Nurse ==========")
        print("1. View encrypted record")
        print("2. Verify hash")
        print("3. Verify digital signature")
        print("0. Logout")
        choice = input("Choice: ").strip()

        if choice == "1":
            record = find_record()
            if record:
                show_encrypted_record(record)
        elif choice == "2":
            nurse_verify_hash()
        elif choice == "3":
            nurse_verify_signature()
        elif choice == "0":
            return
        else:
            print("Invalid choice.")


# ========================= ADMIN FUNCTIONS =========================

def admin_view_records():
    records = load_records()
    if not records:
        print("No records available.")
        return

    print("\n========== ADMIN RECORD DETAILS ==========")
    for record in records:
        valid = verify_signature(encrypted_bytes(record["encryption"]), record["signature"])
        print("\nRecord ID:", record["record_id"])
        print("Patient name:", record["patient_name"])
        print("Hash:", record["hash_value"])
        print("Timestamp:", record["timestamp"])
        print("Signature verification:", "VALID" if valid else "INVALID")


def admin_menu():
    while True:
        print("\n========== HealthSecure: Admin ==========")
        print("1. View record details")
        print("0. Logout")
        choice = input("Choice: ").strip()
        if choice == "1":
            admin_view_records()
        elif choice == "0":
            return
        else:
            print("Invalid choice.")


# ========================= MAIN RBAC MENU =========================

def main():
    while True:
        print("\n========== HealthSecure ==========")
        print("1. Doctor")
        print("2. Nurse")
        print("3. Admin")
        print("0. Exit")
        choice = input("Choice: ").strip()

        if choice == "1":
            doctor_menu()
        elif choice == "2":
            nurse_menu()
        elif choice == "3":
            admin_menu()
        elif choice == "0":
            print("HealthSecure closed.")
            return
        else:
            print("Invalid choice.")


if __name__ == "__main__":
    main()
