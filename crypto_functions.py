"""Simple cryptography helpers used by the HealthSecure lab program."""

import base64
import hashlib
import pickle
import secrets
from math import gcd

from Crypto.Cipher import AES, DES, DES3, PKCS1_OAEP
from Crypto.Hash import MD5, SHA1, SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Util.Padding import pad, unpad


# ========================= COMMON FUNCTIONS =========================

def data_bytes(data):
    if isinstance(data, bytes):
        return data
    if isinstance(data, str):
        return data.encode()
    return pickle.dumps(data)


def hash_data(data, hash_type):
    data = data_bytes(data)

    if hash_type == "MD5":
        return hashlib.md5(data).hexdigest()
    return hashlib.sha256(data).hexdigest()


def b64(data):
    return base64.b64encode(data).decode()


def b64_decode(data):
    return base64.b64decode(data.encode())


# ========================= SYMMETRIC ENCRYPTION =========================

def get_symmetric_key(algorithm):
    if algorithm == "AES-128":
        return secrets.token_bytes(16)
    if algorithm == "AES-192":
        return secrets.token_bytes(24)
    if algorithm == "AES-256":
        return secrets.token_bytes(32)
    if algorithm == "DES":
        return secrets.token_bytes(8)

    # DES3 rejects weak / degenerate keys, so generate until a valid key is made.
    key_size = 16 if algorithm == "2DES" else 24
    while True:
        try:
            return DES3.adjust_key_parity(secrets.token_bytes(key_size))
        except ValueError:
            pass


def symmetric_cipher(algorithm, key, mode, iv=None):
    cipher_mode = AES.MODE_ECB if mode == "ECB" else AES.MODE_CBC
    args = () if mode == "ECB" else (iv,)

    if algorithm.startswith("AES"):
        return AES.new(key, cipher_mode, *args), AES.block_size
    if algorithm == "DES":
        cipher_mode = DES.MODE_ECB if mode == "ECB" else DES.MODE_CBC
        return DES.new(key, cipher_mode, *args), DES.block_size

    cipher_mode = DES3.MODE_ECB if mode == "ECB" else DES3.MODE_CBC
    return DES3.new(key, cipher_mode, *args), DES3.block_size


def encrypt_symmetric(pt, algorithm, mode):
    key = get_symmetric_key(algorithm)
    block_size = AES.block_size if algorithm.startswith("AES") else DES.block_size
    iv = b"" if mode == "ECB" else secrets.token_bytes(block_size)
    cipher, block_size = symmetric_cipher(algorithm, key, mode, iv)
    encrypted = cipher.encrypt(pad(data_bytes(pt), block_size))

    return {
        "algorithm": algorithm,
        "mode": mode,
        "key": key,
        "iv": iv,
        "ciphertext": encrypted,
    }


def decrypt_symmetric(info):
    cipher, block_size = symmetric_cipher(
        info["algorithm"], info["key"], info["mode"], info["iv"]
    )
    return unpad(cipher.decrypt(info["ciphertext"]), block_size).decode()


# ========================= RSA ENCRYPTION =========================

def encrypt_rsa(pt):
    private_key = RSA.generate(2048)
    public_key = private_key.publickey()
    cipher = PKCS1_OAEP.new(public_key, hashAlgo=SHA1)
    max_size = public_key.size_in_bytes() - (2 * SHA1.digest_size) - 2
    data = data_bytes(pt)
    encrypted = [cipher.encrypt(data[i:i + max_size]) for i in range(0, len(data), max_size)]

    return {
        "algorithm": "RSA",
        "mode": "N/A",
        "private_key": private_key.export_key(),
        "public_key": public_key.export_key(),
        "ciphertext": encrypted,
    }


def decrypt_rsa(info):
    private_key = RSA.import_key(info["private_key"])
    cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA1)
    return b"".join(cipher.decrypt(block) for block in info["ciphertext"]).decode()


# ========================= SIMPLE ELGAMAL ENCRYPTION =========================

def encrypt_elgamal(pt):
    # Fixed lab parameters: suitable for demonstration, not real deployments.
    p = 7919
    g = 2
    private = secrets.randbelow(p - 3) + 2
    public = pow(g, private, p)
    encrypted = []

    for value in data_bytes(pt):
        k = secrets.randbelow(p - 3) + 2
        c1 = pow(g, k, p)
        c2 = (value * pow(public, k, p)) % p
        encrypted.append((c1, c2))

    return {
        "algorithm": "ElGamal",
        "mode": "N/A",
        "p": p,
        "g": g,
        "private": private,
        "public": public,
        "ciphertext": encrypted,
    }


def decrypt_elgamal(info):
    pt = []
    for c1, c2 in info["ciphertext"]:
        shared = pow(c1, info["private"], info["p"])
        value = (c2 * pow(shared, -1, info["p"])) % info["p"]
        pt.append(value)
    return bytes(pt).decode()


def encrypt_data(pt, algorithm, mode="N/A"):
    if algorithm in ("AES-128", "AES-192", "AES-256", "DES", "2DES", "3DES"):
        return encrypt_symmetric(pt, algorithm, mode)
    if algorithm == "RSA":
        return encrypt_rsa(pt)
    return encrypt_elgamal(pt)


def decrypt_data(info):
    if info["algorithm"] in ("AES-128", "AES-192", "AES-256", "DES", "2DES", "3DES"):
        return decrypt_symmetric(info)
    if info["algorithm"] == "RSA":
        return decrypt_rsa(info)
    return decrypt_elgamal(info)


def encrypted_bytes(info):
    """Return one stable byte value for hashing/signing the encrypted record."""
    return data_bytes(info["ciphertext"])


# ========================= DIGITAL SIGNATURE =========================

def sign_rsa(data):
    private_key = RSA.generate(2048)
    public_key = private_key.publickey()
    signature = pkcs1_15.new(private_key).sign(SHA256.new(data_bytes(data)))
    return {
        "type": "RSA",
        "signature": signature,
        "public_key": public_key.export_key(),
    }


def verify_rsa(data, signature_info):
    try:
        public_key = RSA.import_key(signature_info["public_key"])
        pkcs1_15.new(public_key).verify(SHA256.new(data_bytes(data)), signature_info["signature"])
        return True
    except (ValueError, TypeError):
        return False


def sign_elgamal(data):
    # Fixed lab parameters: simple textbook ElGamal signature.
    p = 7919
    g = 2
    private = secrets.randbelow(p - 3) + 2
    public = pow(g, private, p)
    h = int.from_bytes(hashlib.sha256(data_bytes(data)).digest(), "big") % (p - 1)

    while True:
        k = secrets.randbelow(p - 3) + 2
        if gcd(k, p - 1) == 1:
            break

    r = pow(g, k, p)
    s = ((h - private * r) * pow(k, -1, p - 1)) % (p - 1)
    return {"type": "ElGamal", "p": p, "g": g, "public": public, "r": r, "s": s}


def verify_elgamal(data, signature_info):
    p = signature_info["p"]
    g = signature_info["g"]
    public = signature_info["public"]
    r = signature_info["r"]
    s = signature_info["s"]
    h = int.from_bytes(hashlib.sha256(data_bytes(data)).digest(), "big") % (p - 1)
    return pow(g, h, p) == (pow(public, r, p) * pow(r, s, p)) % p


def sign_data(data, signature_type):
    if signature_type == "RSA":
        return sign_rsa(data)
    return sign_elgamal(data)


def verify_signature(data, signature_info):
    if signature_info["type"] == "RSA":
        return verify_rsa(data, signature_info)
    return verify_elgamal(data, signature_info)
