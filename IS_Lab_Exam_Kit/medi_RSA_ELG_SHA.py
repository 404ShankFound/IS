import hashlib
import pickle
import os
from datetime import datetime
from math import gcd
import secrets

from Crypto.Hash import SHA256


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

DATA_FILE = "healthsecure_elgamal_records.pkl"
KEY_FILE = "healthsecure_elgamal_keys.pkl"

# Simple ElGamal parameters for lab use
P = 7919
G = 2

RECORDS = []
USER_KEYS = {}


# ========================= CRYPTO FUNCTIONS =========================

def generate_keys():

    private = secrets.randbelow(P - 3) + 2

    public = pow(G, private, P)

    return (P, G, public), (P, G, private)


# ========================= ELGAMAL ENCRYPTION =========================

def encrypt_data(data, public_key):

    p, g, public = public_key

    data = data.encode()

    encrypted = []

    for byte in data:

        # Random session key
        k = secrets.randbelow(p - 2) + 1

        # c1 = g^k mod p
        c1 = pow(g, k, p)

        # c2 = byte * public^k mod p
        c2 = (byte * pow(public, k, p)) % p

        encrypted.append((c1, c2))

    return encrypted


def decrypt_data(encrypted_data, private_key):

    p, g, private = private_key

    decrypted = []

    for c1, c2 in encrypted_data:

        # Shared secret = c1^private mod p
        shared = pow(c1, private, p)

        # Inverse of shared secret
        inverse = pow(shared, -1, p)

        # Original byte
        byte = (c2 * inverse) % p

        decrypted.append(byte)

    return bytes(decrypted).decode()


# ========================= HASH FUNCTIONS =========================

def data_bytes(data):

    if isinstance(data, bytes):
        return data

    if isinstance(data, str):
        return data.encode()

    return pickle.dumps(data)


def hash_data(data):

    return hashlib.sha256(
        data_bytes(data)
    ).hexdigest()


# ========================= ELGAMAL SIGNATURE =========================

def sign_data(data, private_key):

    p, g, private = private_key

    # Choose k such that gcd(k,p-1)=1
    k = secrets.randbelow(p - 2) + 1

    while gcd(k, p - 1) != 1:

        k = secrets.randbelow(p - 2) + 1

    # SHA-256 hash
    h = int.from_bytes(
        SHA256.new(
            data_bytes(data)
        ).digest(),
        "big"
    )

    # r = g^k mod p
    r = pow(g, k, p)

    # s = (h - private*r) * k^-1 mod (p-1)
    s = (
        (h - private * r)
        * pow(k, -1, p - 1)
    ) % (p - 1)

    return r, s


def verify_signature(data, signature, public_key):

    p, g, public = public_key

    r, s = signature

    h = int.from_bytes(
        SHA256.new(
            data_bytes(data)
        ).digest(),
        "big"
    )

    return (
        pow(g, h, p)
        ==
        (
            pow(public, r, p)
            *
            pow(r, s, p)
        ) % p
    )


def export_public_key(public_key):

    return public_key


def import_public_key(saved_key):

    return saved_key


# ========================= KEY STORAGE =========================

def load_keys():

    global USER_KEYS

    try:

        with open(KEY_FILE, "rb") as file:
            saved_keys = pickle.load(file)

        USER_KEYS = saved_keys

    except (FileNotFoundError, EOFError):

        USER_KEYS = {}


def save_keys():

    with open(KEY_FILE, "wb") as file:
        pickle.dump(USER_KEYS, file)


def get_user_keys(username):

    if username not in USER_KEYS:

        USER_KEYS[username] = generate_keys()

        save_keys()

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

        pickle.dump(
            RECORDS,
            file
        )


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

    filename = input(
        "Enter file path: "
    ).strip().strip('"')

    try:

        with open(
            filename,
            "r",
            encoding="utf-8"
        ) as file:

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

        index = int(
            input("Select record: ")
        ) - 1

        if 0 <= index < len(records):

            return records[index]

    except ValueError:

        pass

    print("Invalid record")

    return None


# ============================ DOCTOR ACTIONS ==========================

def store_record(username, data, filename):

    public_key, private_key = get_user_keys(username)

    # ElGamal encryption using Doctor's public key
    encrypted = encrypt_data(
        data,
        public_key
    )

    # SHA-256 hash of encrypted data
    encrypted_hash = hash_data(
        encrypted
    )

    # ElGamal digital signature
    signature = sign_data(
        encrypted,
        private_key
    )

    record_id = (
        "P" +
        str(len(RECORDS) + 1).zfill(3)
    )

    RECORDS.append({

        "record_id": record_id,

        "patient_name":
            data.split("\n")[0]
            .replace("Name: ", ""),

        "filename": filename,

        "encrypted": encrypted,

        "encrypted_hash": encrypted_hash,

        "signature": signature,

        "public_key":
            export_public_key(public_key),

        "timestamp":
            datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )
    })

    save_records()

    print("\nPatient record stored successfully.")
    print("Record ID:", record_id)
    print("ElGamal encryption completed.")
    print("SHA-256 hash generated.")
    print("ElGamal digital signature generated.")


def upload_record_keyboard(username):

    data, filename = get_keyboard_data()

    store_record(
        username,
        data,
        filename
    )


def upload_record_file(username):

    data, filename = get_file_data()

    if data is not None:

        store_record(
            username,
            data,
            filename
        )


def view_doctor_records():

    if not RECORDS:

        print("No records found")

        return

    for record in RECORDS:

        print(
            "\nRecord ID:",
            record["record_id"]
        )

        print(
            "Patient Name:",
            record["patient_name"]
        )

        print(
            "Filename:",
            record["filename"]
        )

        print(
            "Encrypted Data:",
            record["encrypted"]
        )

        print(
            "SHA-256:",
            record["encrypted_hash"]
        )

        print(
            "ElGamal Signature:",
            record["signature"]
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

    # Recalculate SHA-256
    hash_ok = (
        hash_data(record["encrypted"])
        ==
        record["encrypted_hash"]
    )

    # Verify ElGamal signature
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

    # Decrypt only if both checks pass
    if hash_ok and signature_ok:

        try:

            data = decrypt_data(
                record["encrypted"],
                private_key
            )

            print("\nBoth checks successful.")

            print(
                "\nDecrypted Patient Information:"
            )

            print(data)

        except Exception as e:

            print(
                "\nDecryption failed:",
                e
            )

    else:

        print("\nAccess denied.")

        print(
            "Patient information will NOT be displayed."
        )


# ============================= NURSE ================================

def nurse_view_records():

    if not RECORDS:

        print("No records found")

        return

    for record in RECORDS:

        public_key = import_public_key(
            record["public_key"]
        )

        # Recalculate SHA-256
        hash_ok = (
            hash_data(record["encrypted"])
            ==
            record["encrypted_hash"]
        )

        # Verify ElGamal signature
        signature_ok = verify_signature(
            record["encrypted"],
            record["signature"],
            public_key
        )

        print(
            "\nRecord ID:",
            record["record_id"]
        )

        print(
            "Filename:",
            record["filename"]
        )

        print(
            "Encrypted Data:",
            record["encrypted"]
        )

        print(
            "SHA-256:",
            record["encrypted_hash"]
        )

        print(
            "ElGamal Signature:",
            record["signature"]
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
            "VALID"
            if signature_ok
            else "INVALID"
        )

        print(
            "Plaintext: ACCESS DENIED"
        )


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

        print(
            "\nRecord ID:",
            record["record_id"]
        )

        print(
            "Patient Name:",
            record["patient_name"]
        )

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
            "VALID"
            if signature_ok
            else "INVALID"
        )


# ============================== MENUS ===============================

def doctor_menu(username):

    while True:

        print(
            "\n========== HealthSecure =========="
        )

        print("Logged in as: Doctor")
        print("----------------------------------")

        print(
            "1. Enter patient information"
        )

        print(
            "2. Read patient information from file"
        )

        print(
            "3. View patient records"
        )

        print(
            "4. Decrypt and verify patient record"
        )

        print("0. Logout")

        choice = input("Choice: ")

        if choice == "1":

            upload_record_keyboard(
                username
            )

        elif choice == "2":

            upload_record_file(
                username
            )

        elif choice == "3":

            view_doctor_records()

        elif choice == "4":

            doctor_decrypt_verify(
                username
            )

        elif choice == "0":

            return

        else:

            print("Invalid choice")


def nurse_menu():

    while True:

        print(
            "\n========== HealthSecure =========="
        )

        print("Logged in as: Nurse")
        print("----------------------------------")

        print(
            "1. View encrypted patient records"
        )

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

        print(
            "\n========== HealthSecure =========="
        )

        print("Logged in as: Admin")
        print("----------------------------------")

        print(
            "1. View patient record information"
        )

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

        print(
            "\n======================================"
        )

        print(
            "             HEALTHSECURE"
        )

        print(
            " Secure Patient Information System"
        )

        print(
            "======================================"
        )

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