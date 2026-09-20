import hashlib
import pickle
import secrets
from datetime import datetime

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad

# ============================ SETTINGS ============================

ORIGINAL_FILE = "hospital_record.txt"
AES_FILE = "hospital_record.aes"
RSA_KEY_FILE = "rsa_aes_key.bin"
HASH_FILE = "hospital_record_hash.txt"
ELGAMAL_FILE = "authorization_elgamal.pkl"

P = 7919
G = 2

AES_KEY = None
RSA_PRIVATE_KEY = None
RSA_PUBLIC_KEY = None


def timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# ========================= FILE FUNCTIONS =========================

def create_file():
    print("\nEnter hospital record content:")

    name = input("Patient Name: ")
    age = input("Age: ")
    gender = input("Gender: ")
    blood = input("Blood Group: ")
    diagnosis = input("Diagnosis: ")
    details = input("Medical Details: ")

    data = (
        f"Patient Name: {name}\n"
        f"Age: {age}\n"
        f"Gender: {gender}\n"
        f"Blood Group: {blood}\n"
        f"Diagnosis: {diagnosis}\n"
        f"Medical Details: {details}"
    )

    with open(ORIGINAL_FILE, "w", encoding="utf-8") as file:
        file.write(data)

    print("\nOriginal hospital file created:", ORIGINAL_FILE)
    print("Generation Time:", timestamp())


def read_file():
    try:
        with open(ORIGINAL_FILE, "r", encoding="utf-8") as file:
            return file.read()
    except FileNotFoundError:
        print("\nOriginal file not found.")
        return None


# ========================= AES FUNCTIONS =========================

def generate_aes_key():
    global AES_KEY
    AES_KEY = secrets.token_bytes(16)
    return AES_KEY


def encrypt_file_aes():
    global AES_KEY

    data = read_file()

    if data is None:
        return

    key_time = timestamp()
    AES_KEY = generate_aes_key()
    iv = secrets.token_bytes(16)

    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(data.encode(), 16))

    # IV + ciphertext are stored in the AES file.
    with open(AES_FILE, "wb") as file:
        file.write(iv)
        file.write(encrypted)

    print("\nAES-128 encryption completed.")
    print("Encryption Time:", timestamp())
    print("AES Key Generation Time:", key_time)
    print("AES Key:", AES_KEY.hex())
    print("Encrypted message stored in:", AES_FILE)


def decrypt_file_aes():
    if AES_KEY is None:
        print("\nAES key is not available.")
        return None

    try:
        with open(AES_FILE, "rb") as file:
            iv = file.read(16)
            encrypted = file.read()

        cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(encrypted), 16).decode()

    except Exception:
        return None


# ========================= RSA FUNCTIONS =========================

def generate_rsa_keys():
    global RSA_PRIVATE_KEY, RSA_PUBLIC_KEY

    key_time = timestamp()
    RSA_PRIVATE_KEY = RSA.generate(2048)
    RSA_PUBLIC_KEY = RSA_PRIVATE_KEY.publickey()

    print("\nRSA-2048 key pair generated.")
    print("Key Generation Time:", key_time)
    print("Public Key:")
    print("n =", RSA_PUBLIC_KEY.n)
    print("e =", RSA_PUBLIC_KEY.e)


def rsa_encrypt_aes_key():
    if AES_KEY is None:
        print("\nEncrypt the file using AES first.")
        return

    if RSA_PUBLIC_KEY is None:
        generate_rsa_keys()

    encryption_time = timestamp()
    cipher = PKCS1_OAEP.new(RSA_PUBLIC_KEY)
    encrypted_key = cipher.encrypt(AES_KEY)

    with open(RSA_KEY_FILE, "wb") as file:
        file.write(encrypted_key)

    print("\nAES key encrypted using RSA.")
    print("RSA Encryption Time:", encryption_time)
    print("Encrypted AES key stored in:", RSA_KEY_FILE)


def rsa_decrypt_aes_key():
    if RSA_PRIVATE_KEY is None:
        print("\nRSA private key is not available.")
        return None

    try:
        with open(RSA_KEY_FILE, "rb") as file:
            encrypted_key = file.read()

        cipher = PKCS1_OAEP.new(RSA_PRIVATE_KEY)
        return cipher.decrypt(encrypted_key)

    except Exception:
        return None


# ========================= HASH FUNCTIONS =========================

def hash_data(data):
    if isinstance(data, str):
        data = data.encode()

    return hashlib.sha256(data).hexdigest()


def generate_sender_hash():
    try:
        with open(AES_FILE, "rb") as file:
            encrypted = file.read()

        hash_time = timestamp()
        h = hash_data(encrypted)

        with open(HASH_FILE, "w") as file:
            file.write(h)

        print("\nSender SHA-256 Hash:")
        print(h)
        print("Hash Generation Time:", hash_time)
        print("Stored in:", HASH_FILE)

    except FileNotFoundError:
        print("\nAES encrypted file not found.")


def verify_hash():
    try:
        with open(AES_FILE, "rb") as file:
            encrypted = file.read()

        with open(HASH_FILE, "r") as file:
            sender_hash = file.read().strip()

        receiver_hash = hash_data(encrypted)
        verification_time = timestamp()

        print("\nSender Hash:")
        print(sender_hash)

        print("\nReceiver Hash:")
        print(receiver_hash)
        print("Verification Time:", verification_time)

        if sender_hash == receiver_hash:
            print("\nIntegrity Verification: VALID")
            return True

        print("\nIntegrity Verification: FAILED")
        return False

    except FileNotFoundError:
        print("\nRequired file not found.")
        return False


# ========================= ELGAMAL FUNCTIONS =========================

def generate_elgamal_keys():
    key_time = timestamp()
    private = secrets.randbelow(P - 3) + 2
    public = pow(G, private, P)
    return private, public, key_time


def elgamal_encrypt(code, public):
    encrypted = []

    for byte in code.encode():
        k = secrets.randbelow(P - 2) + 1
        c1 = pow(G, k, P)
        c2 = (byte * pow(public, k, P)) % P
        encrypted.append((c1, c2))

    return encrypted


def elgamal_decrypt(encrypted, private):
    decrypted = []

    for c1, c2 in encrypted:
        shared = pow(c1, private, P)
        inverse = pow(shared, -1, P)
        byte = (c2 * inverse) % P
        decrypted.append(byte)

    return bytes(decrypted).decode()


def encrypt_authorization_code():
    code = input("\nEnter authorization code: ")

    private, public, key_time = generate_elgamal_keys()
    encryption_time = timestamp()
    encrypted = elgamal_encrypt(code, public)

    with open(ELGAMAL_FILE, "wb") as file:
        pickle.dump({
            "p": P,
            "g": G,
            "private": private,
            "public": public,
            "encrypted": encrypted
        }, file)

    print("\nElGamal encryption completed.")
    print("p =", P)
    print("g =", G)
    print("Public Key y =", public)
    print("Key Generation Time:", key_time)
    print("Encryption Time:", encryption_time)
    print("Encrypted Authorization:", encrypted)


def decrypt_authorization_code():
    try:
        with open(ELGAMAL_FILE, "rb") as file:
            data = pickle.load(file)

        decrypted = elgamal_decrypt(
            data["encrypted"],
            data["private"]
        )

        print("\nDecrypted Authorization Code:")
        print(decrypted)
        print("Decryption Time:", timestamp())

    except FileNotFoundError:
        print("\nAuthorization code not found.")


# ========================= DISPLAY FUNCTIONS =========================

def display_encrypted_message():
    try:
        with open(AES_FILE, "rb") as file:
            encrypted = file.read()

        print("\nEncrypted AES Message:")
        print(encrypted.hex())
        print("Display Time:", timestamp())

    except FileNotFoundError:
        print("\nEncrypted file not found.")


def display_rsa_values():
    if RSA_PUBLIC_KEY is None:
        print("\nRSA keys have not been generated.")
        return

    print("\n========== RSA VALUES ==========")
    print("Display Time:", timestamp())
    print("Public Key:")
    print("n =", RSA_PUBLIC_KEY.n)
    print("e =", RSA_PUBLIC_KEY.e)

    print("\nPrivate Key:")
    print("d =", RSA_PRIVATE_KEY.d)

    try:
        with open(RSA_KEY_FILE, "rb") as file:
            encrypted_key = file.read()

        print("\nEncrypted AES Key:")
        print(encrypted_key.hex())

    except FileNotFoundError:
        print("\nEncrypted AES key not generated yet.")


def display_all():
    display_encrypted_message()
    display_rsa_values()

    try:
        with open(ELGAMAL_FILE, "rb") as file:
            data = pickle.load(file)

        print("\n========== ELGAMAL VALUES ==========")
        print("p =", data["p"])
        print("g =", data["g"])
        print("Public Key y =", data["public"])
        print("Encrypted Authorization:")
        print(data["encrypted"])

    except FileNotFoundError:
        print("\nElGamal authorization not generated.")


# ========================= DECRYPTION PROCESS =========================

def verify_and_decrypt():
    print("\n========== INTEGRITY CHECK ==========")

    if not verify_hash():
        print("\nERROR: Integrity failed.")
        print("Integrity Failure Time:", timestamp())
        print("The encrypted AES file has been modified.")
        print("Decryption will NOT be performed.")
        return

    print("\nIntegrity verified successfully.")
    print("Verification Passed Time:", timestamp())

    decrypted_key = rsa_decrypt_aes_key()

    if decrypted_key is None:
        print("\nERROR: RSA decryption failed.")
        return

    print("\nDecrypted AES Key:")
    print(decrypted_key.hex())
    print("AES Key Decryption Time:", timestamp())

    global AES_KEY
    AES_KEY = decrypted_key

    decrypted_text = decrypt_file_aes()

    if decrypted_text is None:
        print("\nERROR: AES decryption failed.")
        return

    print("\n========== DECRYPTED TEXT ==========")
    print("AES File Decryption Time:", timestamp())
    print(decrypted_text)
    print("\nOriginal file content recovered successfully.")


# ========================= TAMPERING TEST =========================

def tamper_ciphertext():
    try:
        with open(AES_FILE, "rb") as file:
            data = bytearray(file.read())
    except FileNotFoundError:
        print("\nAES encrypted file not found.")
        return

    if len(data) <= 16:
        print("\nInvalid encrypted file.")
        return

    # First 16 bytes are IV. Modify one byte of ciphertext.
    data[16] ^= 1

    with open(AES_FILE, "wb") as file:
        file.write(data)

    print("\nOne byte of AES ciphertext was modified.")
    print("Tampering Time:", timestamp())
    print("Tampering completed.")

    print("\nNow checking integrity...")
    verify_hash()


# ============================== MENUS ===============================

def encryption_menu():
    while True:
        print("\n========== ENCRYPTION ==========")
        print("1. Create hospital file")
        print("2. Encrypt file using AES-128")
        print("3. Generate RSA keys")
        print("4. Encrypt AES key using RSA")
        print("5. Encrypt authorization code using ElGamal")
        print("6. Display encrypted message and keys")
        print("0. Back")

        choice = input("Choice: ")

        if choice == "1":
            create_file()
        elif choice == "2":
            encrypt_file_aes()
        elif choice == "3":
            generate_rsa_keys()
        elif choice == "4":
            rsa_encrypt_aes_key()
        elif choice == "5":
            encrypt_authorization_code()
        elif choice == "6":
            display_all()
        elif choice == "0":
            return
        else:
            print("Invalid choice")


def verification_menu():
    while True:
        print("\n========== VERIFICATION ==========")
        print("1. Generate sender SHA-256 hash")
        print("2. Check sender and receiver hash")
        print("3. Tamper with AES ciphertext")
        print("4. Verify and decrypt")
        print("5. Decrypt authorization code")
        print("0. Back")

        choice = input("Choice: ")

        if choice == "1":
            generate_sender_hash()
        elif choice == "2":
            verify_hash()
        elif choice == "3":
            tamper_ciphertext()
        elif choice == "4":
            verify_and_decrypt()
        elif choice == "5":
            decrypt_authorization_code()
        elif choice == "0":
            return
        else:
            print("Invalid choice")


# ================================ MAIN ===============================

def main():
    while True:
        print("\n==========================================")
        print("        HOSPITAL MANAGEMENT SYSTEM")
        print("       AES + RSA + ELGAMAL SECURITY")
        print("==========================================")
        print("1. Encryption and Key Management")
        print("2. Hashing, Verification and Decryption")
        print("3. Display RSA Values")
        print("4. Display Encrypted Message")
        print("0. Exit")

        choice = input("Choice: ")

        if choice == "1":
            encryption_menu()
        elif choice == "2":
            verification_menu()
        elif choice == "3":
            display_rsa_values()
        elif choice == "4":
            display_encrypted_message()
        elif choice == "0":
            print("\nExiting Hospital Management System.")
            break
        else:
            print("Invalid choice")


if __name__ == "__main__":
    main()
