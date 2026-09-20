'''
SecureVault – Secure Record Management System

Design and implement an application named "SecureVault" for securely storing, authenticating, accessing, and auditing confidential client records. The application must have three roles: Client, Lawyer, and Compliance Officer.

The application must use:
1. DES in CBC mode for encryption and decryption.
2. SHA-256 for data integrity verification.
3. ElGamal Digital Signature for authentication and verification.

CLIENT:

The Client should:
1. Enter/provide a confidential record.
2. Encrypt the record using DES in CBC mode.
3. Generate an IV and use it during encryption.
4. Calculate the SHA-256 hash of the encrypted data.
5. Generate an ElGamal digital signature using the client's private key.
6. Display the following:
   - Ciphertext
   - IV
   - SHA-256 hash value
   - ElGamal signature
   - Timestamp
7. Store the ciphertext, IV, hash value, signature, and timestamp in a file for future verification and access.

LAWYER:

The Lawyer should:
1. Read the stored ciphertext, IV, hash value, signature, and timestamp from the file.
2. Recalculate the SHA-256 hash and compare it with the stored hash value.
3. Verify the ElGamal digital signature using the client's public key.
4. Display the hash verification and signature verification status.
5. Only if the hash and signature verification are successful, decrypt the ciphertext using DES in CBC mode.
6. Display the recovered plaintext record.
7. Store the verification/access status along with a timestamp.

If the integrity or signature verification fails, the Lawyer must not decrypt or access the plaintext.

COMPLIANCE OFFICER:

The Compliance Officer should:
1. Access the stored encrypted record and its associated security metadata.
2. Verify the SHA-256 hash to check whether the stored data has been modified.
3. Verify the ElGamal digital signature using the client's public key.
4. Display the hash verification and signature verification status.
5. Record the verification results along with a timestamp.
6. Generate a Compliance Report containing the verification status and relevant metadata.
7. The Compliance Officer must NOT decrypt the ciphertext or access the client's plaintext record.

The application should maintain proper role-based access, ensuring that:
- The Client can create and securely store records.
- The Lawyer can verify and decrypt records after successful authentication.
- The Compliance Officer can independently audit the record's integrity and authenticity without accessing the plaintext.

The system should clearly display all relevant security information and verification results.
'''

# ================= EXACT ALGORITHMS USED =================
# Primary digital-signature algorithm: ElGamal signature with SHA-256.
# Auxiliary encryption: AES-128 ECB.
# Record hashing: SHA-256.
# =========================================================

"""Ready-to-run role template tailored specifically for ELGAMAL SIGNATURE."""

import hashlib
import pickle
from datetime import datetime

from Crypto.Cipher import DES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
from math import gcd
import secrets

# ============================ USER ACCOUNTS ============================
USERS = {
    "user1": ("123", "uploader"),
    "user2": ("123", "reviewer"),
    "user3": ("123", "auditor"),
}

ROLE_NAMES = {
    "uploader": "Student",
    "reviewer": "Faculty",
    "auditor": "HoD",
}


# ========================== FIXED SETTINGS ==========================
CIPHER_KEY = b"12345678"
DATA_FILE = "role_des_records.pkl"
RECORDS = []
USER_KEYS = {}


# ========================= CRYPTO FUNCTIONS =========================
def encrypt_data(data, key=CIPHER_KEY):
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(pad(data.encode(), DES.block_size))


def decrypt_data(encrypted_data, key=CIPHER_KEY):
    cipher = DES.new(key, DES.MODE_ECB)
    return unpad(cipher.decrypt(encrypted_data), DES.block_size).decode()

def data_bytes(data):
    if isinstance(data, bytes):
        return data
    if isinstance(data, str):
        return data.encode()
    return pickle.dumps(data)


def hash_data(data):
    return hashlib.sha256(data_bytes(data)).hexdigest()


def generate_keys():
    p, g = 7919, 2
    private = secrets.randbelow(p - 3) + 2
    return (p, g, pow(g, private, p)), (p, g, private)


def sign_data(data, private_key):
    p, g, private = private_key
    k = secrets.randbelow(p - 2) + 1
    while gcd(k, p - 1) != 1:
        k = secrets.randbelow(p - 2) + 1
    h = int.from_bytes(SHA256.new(data_bytes(data)).digest(), "big")
    r = pow(g, k, p)
    return r, ((h - private * r) * pow(k, -1, p - 1)) % (p - 1)


def verify_signature(data, signature, public_key):
    p, g, public = public_key
    r, s = signature
    h = int.from_bytes(SHA256.new(data_bytes(data)).digest(), "big")
    return pow(g, h, p) == (pow(public, r, p) * pow(r, s, p)) % p


def export_public_key(public_key):
    return public_key


def import_public_key(saved_key):
    return saved_key


def get_user_keys(username):
    if username not in USER_KEYS:
        USER_KEYS[username] = generate_keys()
    return USER_KEYS[username]


# ========================== STORAGE HELPERS =========================
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
    print("1. Enter data using keyboard")
    print("2. Read data from file")
    choice = input("Choice: ")
    if choice == "1":
        return input("Enter data: ")
    if choice == "2":
        filename = input("Enter file path: ").strip('"')
        with open(filename, "r") as file:
            return file.read()
    print("Invalid choice")
    return None


def select_record(records):
    if not records:
        print("No records found")
        return None
    for index, record in enumerate(records):
        print(index + 1, record["owner"], record["time"])
    try:
        index = int(input("Select record: ")) - 1
        if 0 <= index < len(records):
            return records[index]
    except ValueError:
        pass
    print("Invalid record")
    return None


# ============================ ROLE ACTIONS ===========================
def upload_record(username):
    data = get_input_data()
    if data is None:
        return

    encrypted = encrypt_data(data)
    public_key, private_key = get_user_keys(username)
    RECORDS.append({
        "owner": username,
        "encrypted": encrypted,
        "encrypted_hash": hash_data(encrypted),
        "plain_hash": hash_data(data),
        "signature": sign_data(encrypted, private_key),
        "public_key": export_public_key(public_key),
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "verification": "Not verified",
    })
    save_records()
    print("Data encrypted, signed and uploaded")


def view_own_records(username):
    own_records = [record for record in RECORDS if record["owner"] == username]
    if not own_records:
        print("No records found")
    for record in own_records:
        print("\nTime:", record["time"])
        encrypted = record["encrypted"]
        print("Encrypted:", encrypted.hex() if isinstance(encrypted, bytes) else encrypted)
        print("Encrypted hash:", record["encrypted_hash"])
        print("Plain hash:", record["plain_hash"])


def review_record(username):
    record = select_record(RECORDS)
    if record is None:
        return

    public_key = import_public_key(record["public_key"])
    signature_ok = verify_signature(record["encrypted"], record["signature"], public_key)
    encrypted_hash_ok = hash_data(record["encrypted"]) == record["encrypted_hash"]
    data = decrypt_data(record["encrypted"])
    plain_hash_ok = hash_data(data) == record["plain_hash"]

    print("Decrypted data:", data)
    print("Signature valid:", signature_ok)
    print("Encrypted hash valid:", encrypted_hash_ok)
    print("Plain hash valid:", plain_hash_ok)

    valid = signature_ok and encrypted_hash_ok and plain_hash_ok
    record["verification"] = "Valid" if valid else "Invalid"
    record["verified_by"] = username
    record["verified_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    save_records()


def audit_records():
    if not RECORDS:
        print("No records found")
    for record in RECORDS:
        public_key = import_public_key(record["public_key"])
        signature_ok = verify_signature(record["encrypted"], record["signature"], public_key)
        print("\nOwner:", record["owner"])
        print("Time:", record["time"])
        print("Encrypted hash:", record["encrypted_hash"])
        print("Plain hash:", record["plain_hash"])
        print("Signature valid:", signature_ok)
        print("Verification:", record["verification"])


# ============================== MENUS ================================
# Only edit the PRINTED role/action names if the story changes.
def user_menu(username, role):
    while True:
        if role == "uploader":
            print("\n1. Upload record\n2. View my records\n0. Logout")
            choice = input("Choice: ")
            if choice == "1":
                upload_record(username)
            elif choice == "2":
                view_own_records(username)
            elif choice == "0":
                return

        elif role == "reviewer":
            print("\n1. Decrypt and verify record\n0. Logout")
            choice = input("Choice: ")
            if choice == "1":
                review_record(username)
            elif choice == "0":
                return

        else:
            print("\n1. View hashes and verify signatures\n0. Logout")
            choice = input("Choice: ")
            if choice == "1":
                audit_records()
            elif choice == "0":
                return


def main():
    load_records()
    while True:
        print("\n=== Secure Record System ===")
        print("1. Login\n0. Exit")
        if input("Choice: ") == "0":
            break

        username = input("Username: ")
        password = input("Password: ")
        user = USERS.get(username)
        if user and user[0] == password:
            print("Logged in as", ROLE_NAMES[user[1]])
            user_menu(username, user[1])
        else:
            print("Invalid login")


if __name__ == "__main__":
    main()
