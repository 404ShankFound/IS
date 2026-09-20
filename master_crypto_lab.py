# MASTER CRYPTO LAB TOOLKIT
# Install once:
# pip install pycryptodome cryptography numpy pandas matplotlib seaborn
#
# Generic roles used everywhere:
# Role A = create/authorized user
# Role B = verifier/authorized accessor
# Role C = auditor/compliance
#
# IMPORTANT:
# - AES block size is always 16 bytes; key sizes can be 128/192/256 bits.
# - DES/3DES block size is 8 bytes.
# - ECB/CBC may use PKCS#7 padding; CFB/OFB/CTR/GCM do not use PKCS#7 padding.
# - AES block size is fixed at 16 bytes even when the key is 192 or 256 bits.
# - DES/3DES block size is 8 bytes.
# - Textbook RSA/ElGamal/Rabin are kept separate from modern RSA-OAEP/signature schemes.
# - For block-mode chunking, chunks are processed through ONE cipher object so CBC state
#   is preserved; chunks are not independently encrypted.
# - This is an exam/lab toolkit, not a production security system.

import os
import ast
import time
import socket
import hashlib
import secrets
from math import gcd
from datetime import datetime

from Crypto.Cipher import AES, DES, DES3, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15, pss
from Crypto.Hash import SHA256

# Optional analysis/plotting libraries
try:
    import numpy as np
    import pandas as pd
    import matplotlib.pyplot as plt
except ImportError:
    np = pd = plt = None


# ============================================================
# GENERAL HELPERS
# ============================================================

def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def ask_int(msg, default=None):
    while True:
        s = input(msg).strip()
        if s == "" and default is not None:
            return default
        try:
            return int(s)
        except ValueError:
            print("Enter a valid integer.")


def ask_yes_no(msg, default=True):
    suffix = " [Y/n]: " if default else " [y/N]: "
    s = input(msg + suffix).strip().lower()
    if not s:
        return default
    return s in ("y", "yes")


def read_text():
    return input("Enter message: ")


def read_file_bytes():
    filename = input("Enter filename: ").strip()
    with open(filename, "rb") as f:
        return filename, f.read()


def write_bytes(filename, data):
    with open(filename, "wb") as f:
        f.write(data)


def read_bytes(filename):
    with open(filename, "rb") as f:
        return f.read()


def show_hex(label, data, limit=256):
    if isinstance(data, str):
        data = data.encode()
    h = data.hex()
    if len(h) > limit:
        h = h[:limit] + "..."
    print(f"{label}: {h}")


def log_event(event):
    with open("audit.log", "a", encoding="utf-8") as f:
        f.write(f"{now()} : {event}\n")


def save_record(filename, record):
    with open(filename, "w", encoding="utf-8") as f:
        f.write(repr(record))


def load_record(filename):
    with open(filename, "r", encoding="utf-8") as f:
        return ast.literal_eval(f.read())


# ============================================================
# KEY + PADDING HELPERS
# ============================================================

def get_des_key():
    return os.urandom(8)


def get_key_hex(prompt, valid_lengths):
    s = input(prompt).strip().replace(" ", "")
    try:
        key = bytes.fromhex(s)
    except ValueError:
        print("Enter hexadecimal bytes only.")
        return None

    if len(key) not in valid_lengths:
        print("Invalid key length.")
        return None

    return key


def choose_key_aes():
    print("1. Generate random key")
    print("2. Enter key as hexadecimal")

    choice = ask_int("Choose: ", 1)
    bits = ask_int("AES key size (128/192/256): ", 128)

    if bits not in (128, 192, 256):
        print("Invalid AES key size.")
        return None, None

    size = bits // 8

    if choice == 1:
        return os.urandom(size), bits

    if choice == 2:
        key = get_key_hex(
            f"Enter {bits}-bit key in hex ({size} bytes): ",
            [size]
        )
        return key, bits

    print("Invalid choice.")
    return None, None


def choose_des_key():
    print("1. Generate random DES key")
    print("2. Enter DES key as hexadecimal (8 bytes)")

    choice = ask_int("Choose: ", 1)

    if choice == 1:
        return os.urandom(8)

    if choice == 2:
        return get_key_hex("Enter 16 hex characters: ", [8])

    print("Invalid choice.")
    return None


def choose_3des_key():
    print("1. Generate random 3DES key")
    print("2. Enter 3DES key as hexadecimal")

    choice = ask_int("Choose: ", 1)

    if choice == 1:
        while True:
            key = DES3.adjust_key_parity(os.urandom(24))
            try:
                DES3.new(key, DES3.MODE_ECB)
                return key
            except ValueError:
                pass

    if choice == 2:
        return get_key_hex(
            "Enter 16 or 24-byte 3DES key in hex: ",
            [16, 24]
        )

    print("Invalid choice.")
    return None


def choose_padding():
    c = ask_int("Padding: 1. PKCS7  2. None : ", 1)
    return c == 1


def prepare_data(data, block_size, use_padding):
    if use_padding:
        return pad(data, block_size)

    if len(data) % block_size != 0:
        raise ValueError(
            f"Without padding, data length must be a multiple of "
            f"{block_size} bytes."
        )

    return data


def finish_data(data, block_size, use_padding):
    if use_padding:
        return unpad(data, block_size)

    return data


# ============================================================
# AES
# ============================================================

def aes_encrypt(data, key, mode, iv=None, nonce=None, use_padding=True):
    if mode == "ECB":
        cipher = AES.new(key, AES.MODE_ECB)
        data = prepare_data(data, AES.block_size, use_padding)
        return cipher.encrypt(data), None, None

    if mode == "CBC":
        if iv is None:
            iv = os.urandom(AES.block_size)

        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        data = prepare_data(data, AES.block_size, use_padding)

        return cipher.encrypt(data), iv, None

    if mode == "CFB":
        if iv is None:
            iv = os.urandom(AES.block_size)

        cipher = AES.new(
            key,
            AES.MODE_CFB,
            iv=iv
        )

        return cipher.encrypt(data), iv, None

    if mode == "OFB":
        if iv is None:
            iv = os.urandom(AES.block_size)

        cipher = AES.new(
            key,
            AES.MODE_OFB,
            iv=iv
        )

        return cipher.encrypt(data), iv, None

    if mode == "CTR":
        if nonce is None:
            nonce = os.urandom(8)

        cipher = AES.new(
            key,
            AES.MODE_CTR,
            nonce=nonce
        )

        return cipher.encrypt(data), None, nonce

    raise ValueError("Unsupported AES mode.")


def aes_decrypt(ciphertext, key, mode, iv=None, nonce=None, use_padding=True):
    if mode == "ECB":
        cipher = AES.new(key, AES.MODE_ECB)
        return finish_data(
            cipher.decrypt(ciphertext),
            AES.block_size,
            use_padding
        )

    if mode == "CBC":
        if iv is None:
            raise ValueError("CBC requires IV.")

        cipher = AES.new(key, AES.MODE_CBC, iv=iv)

        return finish_data(
            cipher.decrypt(ciphertext),
            AES.block_size,
            use_padding
        )

    if mode == "CFB":
        if iv is None:
            raise ValueError("CFB requires IV.")

        cipher = AES.new(
            key,
            AES.MODE_CFB,
            iv=iv
        )

        return cipher.decrypt(ciphertext)

    if mode == "OFB":
        if iv is None:
            raise ValueError("OFB requires IV.")

        cipher = AES.new(
            key,
            AES.MODE_OFB,
            iv=iv
        )

        return cipher.decrypt(ciphertext)

    if mode == "CTR":
        if nonce is None:
            raise ValueError("CTR requires nonce.")

        cipher = AES.new(
            key,
            AES.MODE_CTR,
            nonce=nonce
        )

        return cipher.decrypt(ciphertext)

    raise ValueError("Unsupported AES mode.")


def aes_encrypt_stream(
    data, key, mode, iv=None, nonce=None,
    use_padding=True, chunk_size=4096
):
    if mode in ("CFB", "OFB"):
        if iv is None:
            iv = os.urandom(AES.block_size)

        cipher_mode = (
            AES.MODE_CFB
            if mode == "CFB"
            else AES.MODE_OFB
        )

        cipher = AES.new(
            key,
            cipher_mode,
            iv=iv
        )

        out = bytearray()

        for i in range(0, len(data), chunk_size):
            out.extend(
                cipher.encrypt(
                    data[i:i + chunk_size]
                )
            )

        return bytes(out), iv, None

    if mode == "CTR":
        if nonce is None:
            nonce = os.urandom(8)

        cipher = AES.new(
            key,
            AES.MODE_CTR,
            nonce=nonce
        )

        out = bytearray()

        for i in range(0, len(data), chunk_size):
            out.extend(
                cipher.encrypt(
                    data[i:i + chunk_size]
                )
            )

        return bytes(out), None, nonce

    if mode == "ECB":
        cipher = AES.new(key, AES.MODE_ECB)

    elif mode == "CBC":
        if iv is None:
            iv = os.urandom(AES.block_size)

        cipher = AES.new(key, AES.MODE_CBC, iv=iv)

    else:
        raise ValueError("Unsupported AES mode.")

    block = AES.block_size
    out = bytearray()
    buffer = b""

    for i in range(0, len(data), chunk_size):
        buffer += data[i:i + chunk_size]

        full = (len(buffer) // block) * block

        if full:
            out.extend(cipher.encrypt(buffer[:full]))
            buffer = buffer[full:]

    if use_padding:
        out.extend(cipher.encrypt(pad(buffer, block)))

    elif buffer:
        raise ValueError(
            "Final data is not block-aligned and padding is off."
        )

    return bytes(out), iv if mode == "CBC" else None, None


def aes_decrypt_stream(
    ciphertext, key, mode, iv=None, nonce=None,
    use_padding=True, chunk_size=4096
):
    if mode in ("CFB", "OFB"):
        if iv is None:
            raise ValueError(
                f"{mode} requires IV."
            )

        cipher_mode = (
            AES.MODE_CFB
            if mode == "CFB"
            else AES.MODE_OFB
        )

        cipher = AES.new(
            key,
            cipher_mode,
            iv=iv
        )

        out = bytearray()

        for i in range(0, len(ciphertext), chunk_size):
            out.extend(
                cipher.decrypt(
                    ciphertext[i:i + chunk_size]
                )
            )

        return bytes(out)

    if mode == "CTR":
        if nonce is None:
            raise ValueError("CTR requires nonce.")

        cipher = AES.new(
            key,
            AES.MODE_CTR,
            nonce=nonce
        )

        out = bytearray()

        for i in range(0, len(ciphertext), chunk_size):
            out.extend(
                cipher.decrypt(
                    ciphertext[i:i + chunk_size]
                )
            )

        return bytes(out)

    if len(ciphertext) % AES.block_size != 0:
        raise ValueError(
            "Ciphertext length is not a multiple of AES block size."
        )

    if mode == "ECB":
        cipher = AES.new(key, AES.MODE_ECB)

    elif mode == "CBC":
        if iv is None:
            raise ValueError("CBC requires IV.")

        cipher = AES.new(key, AES.MODE_CBC, iv=iv)

    else:
        raise ValueError("Unsupported AES mode.")

    out = bytearray()
    block = AES.block_size

    for i in range(0, len(ciphertext), chunk_size):
        end = i + chunk_size
        out.extend(cipher.decrypt(ciphertext[i:end]))

    return finish_data(
        bytes(out),
        block,
        use_padding
    )


# ============================================================
# DES
# ============================================================

def des_encrypt(data, key, mode, iv=None, use_padding=True):
    if mode == "ECB":
        cipher = DES.new(key, DES.MODE_ECB)
        data = prepare_data(data, DES.block_size, use_padding)

        return cipher.encrypt(data), None

    if mode == "CBC":
        if iv is None:
            iv = os.urandom(DES.block_size)

        cipher = DES.new(key, DES.MODE_CBC, iv=iv)
        data = prepare_data(data, DES.block_size, use_padding)

        return cipher.encrypt(data), iv

    raise ValueError("Unsupported DES mode.")


def des_decrypt(ciphertext, key, mode, iv=None, use_padding=True):
    if mode == "ECB":
        cipher = DES.new(key, DES.MODE_ECB)

    elif mode == "CBC":
        if iv is None:
            raise ValueError("CBC requires IV.")

        cipher = DES.new(key, DES.MODE_CBC, iv=iv)

    else:
        raise ValueError("Unsupported DES mode.")

    if len(ciphertext) % DES.block_size != 0:
        raise ValueError(
            "Ciphertext length is not a multiple of DES block size."
        )

    return finish_data(
        cipher.decrypt(ciphertext),
        DES.block_size,
        use_padding
    )


def des_encrypt_stream(
    data, key, mode, iv=None,
    use_padding=True, chunk_size=4096
):
    if mode == "ECB":
        cipher = DES.new(key, DES.MODE_ECB)

    elif mode == "CBC":
        if iv is None:
            iv = os.urandom(DES.block_size)

        cipher = DES.new(key, DES.MODE_CBC, iv=iv)

    else:
        raise ValueError("Unsupported DES mode.")

    block = DES.block_size
    out = bytearray()
    buffer = b""

    for i in range(0, len(data), chunk_size):
        buffer += data[i:i + chunk_size]

        full = (len(buffer) // block) * block

        if full:
            out.extend(cipher.encrypt(buffer[:full]))
            buffer = buffer[full:]

    if use_padding:
        out.extend(cipher.encrypt(pad(buffer, block)))

    elif buffer:
        raise ValueError(
            "Final data is not block-aligned and padding is off."
        )

    return bytes(out), iv if mode == "CBC" else None


def des_decrypt_stream(
    ciphertext, key, mode, iv=None,
    use_padding=True, chunk_size=4096
):
    if len(ciphertext) % DES.block_size != 0:
        raise ValueError(
            "Ciphertext length is not a multiple of DES block size."
        )

    if mode == "ECB":
        cipher = DES.new(key, DES.MODE_ECB)

    elif mode == "CBC":
        if iv is None:
            raise ValueError("CBC requires IV.")

        cipher = DES.new(key, DES.MODE_CBC, iv=iv)

    else:
        raise ValueError("Unsupported DES mode.")

    out = bytearray()

    for i in range(0, len(ciphertext), chunk_size):
        out.extend(cipher.decrypt(
            ciphertext[i:i + chunk_size]
        ))

    return finish_data(
        bytes(out),
        DES.block_size,
        use_padding
    )


# ============================================================
# TRIPLE DES
# ============================================================

def des3_encrypt(data, key, mode, iv=None, use_padding=True):
    if mode == "ECB":
        cipher = DES3.new(key, DES3.MODE_ECB)
        data = prepare_data(data, DES3.block_size, use_padding)

        return cipher.encrypt(data), None

    if mode == "CBC":
        if iv is None:
            iv = os.urandom(DES3.block_size)

        cipher = DES3.new(key, DES3.MODE_CBC, iv=iv)
        data = prepare_data(data, DES3.block_size, use_padding)

        return cipher.encrypt(data), iv

    raise ValueError("Unsupported 3DES mode.")


def des3_decrypt(ciphertext, key, mode, iv=None, use_padding=True):
    if mode == "ECB":
        cipher = DES3.new(key, DES3.MODE_ECB)

    elif mode == "CBC":
        if iv is None:
            raise ValueError("CBC requires IV.")

        cipher = DES3.new(key, DES3.MODE_CBC, iv=iv)

    else:
        raise ValueError("Unsupported 3DES mode.")

    if len(ciphertext) % DES3.block_size != 0:
        raise ValueError(
            "Ciphertext length is not a multiple of 8 bytes."
        )

    return finish_data(
        cipher.decrypt(ciphertext),
        DES3.block_size,
        use_padding
    )


# ============================================================
# HASHING
# ============================================================

def custom_hash(data):
    if isinstance(data, str):
        data = data.encode()

    h = 5381

    for b in data:
        h = h * 33 + b
        h ^= (h >> 16)
        h &= 0xFFFFFFFF

    return h


def hash_data(data, algorithm):
    if isinstance(data, str):
        data = data.encode()

    algorithm = algorithm.lower()

    if algorithm == "custom":
        return f"{custom_hash(data):08x}"

    if algorithm == "whirlpool":
        try:
            h = hashlib.new("whirlpool")
        except ValueError:
            raise ValueError(
                "Whirlpool is not available in this Python/OpenSSL build."
            )

    else:
        h = hashlib.new(algorithm)

    h.update(data)

    return h.hexdigest()


def hash_parameters(data, algorithm):
    if isinstance(data, str):
        data = data.encode()

    algorithm = algorithm.lower()

    if algorithm == "custom":
        start = time.perf_counter()

        digest = hash_data(data, "custom")

        elapsed = time.perf_counter() - start

        print("Algorithm: Custom 5381")
        print("Digest:", digest)
        print("Digest Size: 4 bytes")
        print("Hex Length:", len(digest))
        print(f"Time: {elapsed:.10f} seconds")

        return

    h = hashlib.new(algorithm)

    start = time.perf_counter()
    h.update(data)
    elapsed = time.perf_counter() - start

    print("Algorithm:", algorithm)
    print("Digest:", h.hexdigest())
    print("Digest Size:", h.digest_size, "bytes")
    print("Block Size:", h.block_size, "bytes")
    print("Hex Length:", len(h.hexdigest()), "characters")
    print(f"Time: {elapsed:.10f} seconds")


def compare_hashes(data):
    for alg in ("md5", "sha1", "sha256"):
        hash_parameters(data, alg)


def collision_check(strings, algorithm):
    seen = {}
    collisions = 0

    for text in strings:
        digest = hash_data(text, algorithm)

        if digest in seen and seen[digest] != text:
            collisions += 1

            print(
                "Collision:",
                repr(seen[digest]),
                "<->",
                repr(text)
            )

        else:
            seen[digest] = text

    print("Strings checked:", len(strings))
    print("Collisions:", collisions)


# ============================================================
# TEXTBOOK RSA
# ============================================================

def rsa_parameters(p, q):
    n = p * q
    phi = (p - 1) * (q - 1)

    e = None

    for x in range(2, phi):
        if gcd(x, phi) == 1:
            e = x
            break

    if e is None:
        raise ValueError("Could not choose e.")

    d = pow(e, -1, phi)

    return n, phi, e, d


def rsa_textbook_encrypt(text, e, n):
    return [
        pow(ord(ch), e, n)
        for ch in text
    ]


def rsa_textbook_decrypt(values, d, n):
    return "".join(
        chr(pow(c, d, n))
        for c in values
    )


# ============================================================
# RSA MODERN ENCRYPTION + SIGNATURE
# ============================================================

def generate_rsa_keys(bits=2048):
    private_key = RSA.generate(bits)
    return private_key, private_key.publickey()


def rsa_oaep_encrypt(data, public_key):
    return PKCS1_OAEP.new(public_key).encrypt(data)


def rsa_oaep_decrypt(data, private_key):
    return PKCS1_OAEP.new(private_key).decrypt(data)


def rsa_sign(data, private_key, scheme="PKCS1v1.5"):
    h = SHA256.new(data)

    if scheme == "PSS":
        return pss.new(private_key).sign(h)

    return pkcs1_15.new(private_key).sign(h)


def rsa_verify(
    data,
    signature,
    public_key,
    scheme="PKCS1v1.5"
):
    h = SHA256.new(data)

    try:
        if scheme == "PSS":
            pss.new(public_key).verify(h, signature)
        else:
            pkcs1_15.new(public_key).verify(h, signature)

        return True

    except (ValueError, TypeError):
        return False


# ============================================================
# ELGAMAL ENCRYPTION + SIGNATURE
# ============================================================

def elgamal_encrypt_int(m, p, g, y, k):
    if not (0 < m < p):
        raise ValueError(
            "Message integer must satisfy 0 < m < p."
        )

    if not (1 <= k < p - 1):
        raise ValueError("Invalid k.")

    if gcd(k, p - 1) != 1:
        raise ValueError(
            "k must be coprime to p-1."
        )

    c1 = pow(g, k, p)
    s = pow(y, k, p)
    c2 = (m * s) % p

    return c1, c2


def elgamal_decrypt_int(c1, c2, p, x):
    s = pow(c1, x, p)

    return (
        c2 * pow(s, -1, p)
    ) % p


def elgamal_encrypt_text(text, p, g, x, k):
    y = pow(g, x, p)

    return [
        elgamal_encrypt_int(
            ord(ch),
            p,
            g,
            y,
            k
        )
        for ch in text
    ]


def elgamal_decrypt_text(ciphertext, p, x):
    return "".join(
        chr(
            elgamal_decrypt_int(
                c1,
                c2,
                p,
                x
            )
        )
        for c1, c2 in ciphertext
    )


def elgamal_hash_int(data, p):
    digest = int.from_bytes(
        hashlib.sha256(data).digest(),
        "big"
    )

    return digest % (p - 1)


def elgamal_sign(data, p, g, x, k):
    if not (1 <= x < p - 1):
        raise ValueError("Invalid private key x.")

    if gcd(k, p - 1) != 1:
        raise ValueError(
            "Signature k must be coprime to p-1."
        )

    h = elgamal_hash_int(data, p)

    r = pow(g, k, p)

    s = (
        (h - x * r)
        * pow(k, -1, p - 1)
    ) % (p - 1)

    return r, s


def elgamal_verify(data, signature, p, g, y):
    r, s = signature

    if not (0 < r < p):
        return False

    if not (0 <= s < p - 1):
        return False

    h = elgamal_hash_int(data, p)

    left = (
        pow(y, r, p)
        * pow(r, s, p)
    ) % p

    right = pow(g, h, p)

    return left == right


# ============================================================
# DIFFIE-HELLMAN
# ============================================================

def dh_exchange(p, g, a, b):
    A = pow(g, a, p)
    B = pow(g, b, p)

    key_a = pow(B, a, p)
    key_b = pow(A, b, p)

    return A, B, key_a, key_b


# ============================================================
# ECDH
# ============================================================

def ecdh_exchange():
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes

    a_private = ec.generate_private_key(
        ec.SECP256R1()
    )

    b_private = ec.generate_private_key(
        ec.SECP256R1()
    )

    a_public = a_private.public_key()
    b_public = b_private.public_key()

    a_secret = a_private.exchange(
        ec.ECDH(),
        b_public
    )

    b_secret = b_private.exchange(
        ec.ECDH(),
        a_public
    )

    a_key = HKDF(
        algorithm=hashes.SHA256(),
        length=16,
        salt=None,
        info=b"MASTER-SESSION"
    ).derive(a_secret)

    b_key = HKDF(
        algorithm=hashes.SHA256(),
        length=16,
        salt=None,
        info=b"MASTER-SESSION"
    ).derive(b_secret)

    return a_key, b_key


# ============================================================
# RABIN
# ============================================================

def rabin_encrypt(m, n):
    if not (0 <= m < n):
        raise ValueError(
            "m must satisfy 0 <= m < n."
        )

    return pow(m, 2, n)


def rabin_decrypt(c, p, q):
    n = p * q

    if p % 4 != 3 or q % 4 != 3:
        raise ValueError(
            "For this simple decryption, p and q "
            "must be 3 mod 4."
        )

    mp = pow(
        c,
        (p + 1) // 4,
        p
    )

    mq = pow(
        c,
        (q + 1) // 4,
        q
    )

    def crt(a, b):
        return (
            a * q * pow(q, -1, p)
            + b * p * pow(p, -1, q)
        ) % n

    return [
        crt(mp, mq),
        crt(mp, -mq % q),
        crt(-mp % p, mq),
        crt(-mp % p, -mq % q)
    ]


# ============================================================
# RBAC / KEY MANAGEMENT / AUDIT
# ============================================================

ROLES = {
    "Role A": {
        "create",
        "view",
        "verify",
        "decrypt"
    },

    "Role B": {
        "view",
        "verify"
    },

    "Role C": {
        "view",
        "verify",
        "report"
    },
}


def allowed(role, action):
    if action in ROLES.get(role, set()):
        return True

    print(
        f"Access denied: {role} cannot {action}."
    )

    log_event(
        f"DENIED {role} {action}"
    )

    return False


KEYS = {}


def generate_managed_key(name):
    KEYS[name] = {
        "key": secrets.token_hex(16),
        "status": "ACTIVE",
        "created": now(),
        "updated": now(),
    }

    log_event(
        f"KEY GENERATED {name}"
    )


def revoke_key(name):
    if name in KEYS:
        KEYS[name]["status"] = "REVOKED"
        KEYS[name]["updated"] = now()

        log_event(
            f"KEY REVOKED {name}"
        )

        return True

    return False


def renew_key(name):
    if name not in KEYS:
        generate_managed_key(name)

    else:
        KEYS[name]["key"] = secrets.token_hex(16)
        KEYS[name]["status"] = "ACTIVE"
        KEYS[name]["updated"] = now()

        log_event(
            f"KEY RENEWED {name}"
        )

    return True


def key_active(name):
    return (
        name in KEYS
        and KEYS[name]["status"] == "ACTIVE"
    )


# ============================================================
# TAMPERING
# ============================================================

def tamper_bytes(data):
    if not data:
        return b"X"

    out = bytearray(data)

    out[0] ^= 1

    return bytes(out)


# ============================================================
# SOCKET HASH DEMO
# ============================================================

def socket_server_hash(
    host="127.0.0.1",
    port=9999
):
    server = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    server.setsockopt(
        socket.SOL_SOCKET,
        socket.SO_REUSEADDR,
        1
    )

    server.bind((host, port))
    server.listen(1)

    print(
        f"Server listening on {host}:{port}"
    )

    conn, addr = server.accept()

    data = bytearray()

    while True:
        part = conn.recv(4096)

        if not part:
            break

        data.extend(part)

    digest = hashlib.sha256(
        data
    ).hexdigest()

    conn.sendall(
        digest.encode()
    )

    conn.close()
    server.close()

    print("Received bytes:", len(data))
    print("Server SHA-256:", digest)


def socket_client_hash(
    host="127.0.0.1",
    port=9999
):
    text = input(
        "Message to send: "
    ).encode()

    digest = hashlib.sha256(
        text
    ).hexdigest()

    client = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    client.connect(
        (host, port)
    )

    for i in range(0, len(text), 16):
        client.sendall(
            text[i:i + 16]
        )

    client.shutdown(
        socket.SHUT_WR
    )

    server_digest = client.recv(
        4096
    ).decode()

    client.close()

    print(
        "Client SHA-256:",
        digest
    )

    print(
        "Server SHA-256:",
        server_digest
    )

    print(
        "Integrity:",
        "VERIFIED"
        if digest == server_digest
        else "FAILED"
    )


# ============================================================
# SYMMETRIC MENU
# ============================================================

def symmetric_menu():
    print("\n=== SYMMETRIC ENCRYPTION ===")
    print("1. AES")
    print("2. DES")
    print("3. Triple DES")
    print("AES modes: ECB / CBC / CFB / OFB / CTR / GCM")
    print("DES/3DES modes: ECB / CBC / CFB / OFB")

    choice = input(
        "Choose: "
    ).strip()

    data_choice = input(
        "1. Text  2. File  3. Hex block : "
    ).strip()

    if data_choice == "2":
        filename, data = read_file_bytes()

    elif data_choice == "3":
        filename = None

        try:
            data = bytes.fromhex(
                input(
                    "Enter data in hex: "
                ).strip()
            )

        except ValueError:
            print("Invalid hex.")
            return

    else:
        filename = None
        data = read_text().encode()

    chunked = ask_yes_no(
        "Process in chunks?",
        False
    )

    chunk_size = 4096

    if chunked:
        chunk_size = ask_int(
            "Chunk size in bytes: ",
            4096
        )

        if chunk_size <= 0:
            print("Invalid chunk size.")
            return

    # ---------------- AES ----------------
    if choice == "1":
        key, bits = choose_key_aes()

        if key is None:
            return

        print(
            "Key size:",
            bits,
            "bits"
        )

        show_hex(
            "Key",
            key
        )

        print(
            "Mode: 1. ECB  2. CBC  3. CFB  4. OFB  5. CTR  6. GCM"
        )

        mode_no = ask_int(
            "Choose: ",
            1
        )

        modes = {
            1: "ECB",
            2: "CBC",
            3: "CFB",
            4: "OFB",
            5: "CTR",
            6: "GCM"
        }

        if mode_no not in modes:
            print("Invalid mode.")
            return

        mode = modes[mode_no]

        # GCM is authenticated encryption; no PKCS#7 padding.
        if mode == "GCM":
            nonce = os.urandom(12)

            start = time.perf_counter()

            cipher = AES.new(
                key,
                AES.MODE_GCM,
                nonce=nonce
            )

            ciphertext, tag = (
                cipher.encrypt_and_digest(data)
            )

            elapsed = (
                time.perf_counter()
                - start
            )

            print("Mode: GCM")

            show_hex(
                "Nonce",
                nonce
            )

            show_hex(
                "Ciphertext",
                ciphertext
            )

            show_hex(
                "Tag",
                tag
            )

            print(
                f"Encryption time: "
                f"{elapsed:.10f} seconds"
            )

            if ask_yes_no(
                "Decrypt now?",
                True
            ):
                dec = AES.new(
                    key,
                    AES.MODE_GCM,
                    nonce=nonce
                )

                plain = (
                    dec.decrypt_and_verify(
                        ciphertext,
                        tag
                    )
                )

                print(
                    "Recovered:",
                    plain.decode(
                        errors="replace"
                    )
                )

            return

        use_padding = (
            choose_padding()
            if mode in ("ECB", "CBC")
            else False
        )

        if (
            chunked
            and mode in ("ECB", "CBC")
            and chunk_size % AES.block_size != 0
        ):
            print(
                "For AES ECB/CBC chunking, "
                "chunk size must be a multiple of 16."
            )

            return

        start = time.perf_counter()

        if chunked:
            ciphertext, iv, nonce = (
                aes_encrypt_stream(
                    data,
                    key,
                    mode,
                    use_padding=use_padding,
                    chunk_size=chunk_size
                )
            )

        else:
            ciphertext, iv, nonce = (
                aes_encrypt(
                    data,
                    key,
                    mode,
                    use_padding=use_padding
                )
            )

        elapsed = (
            time.perf_counter()
            - start
        )

        print(
            "Mode:",
            mode
        )

        print(
            "Padding:",
            "ON"
            if use_padding
            else "OFF"
        )

        print(
            "Block size:",
            AES.block_size,
            "bytes"
        )

        if iv:
            show_hex(
                "IV",
                iv
            )

        if nonce:
            show_hex(
                "Nonce",
                nonce
            )

        show_hex(
            "Ciphertext",
            ciphertext
        )

        print(
            f"Encryption time: "
            f"{elapsed:.10f} seconds"
        )

        if ask_yes_no(
            "Decrypt now?",
            True
        ):
            if chunked:
                plain = aes_decrypt_stream(
                    ciphertext,
                    key,
                    mode,
                    iv,
                    nonce,
                    use_padding,
                    chunk_size
                )

            else:
                plain = aes_decrypt(
                    ciphertext,
                    key,
                    mode,
                    iv,
                    nonce,
                    use_padding
                )

            print(
                "Recovered:",
                plain.decode(
                    errors="replace"
                )
            )

    # ---------------- DES ----------------
    elif choice == "2":
        key = choose_des_key()

        if key is None:
            return

        show_hex(
            "DES Key",
            key
        )

        print(
            "Mode: 1. ECB  2. CBC"
        )

        mode_no = ask_int(
            "Choose: ",
            1
        )

        modes = {
            1: "ECB",
            2: "CBC"
        }

        if mode_no not in modes:
            print("Invalid mode.")
            return

        mode = modes[mode_no]
        use_padding = choose_padding()

        if (
            chunked
            and chunk_size % DES.block_size != 0
        ):
            print(
                "For DES ECB/CBC chunking, "
                "chunk size must be a multiple of 8."
            )

            return

        start = time.perf_counter()

        if chunked:
            ciphertext, iv = (
                des_encrypt_stream(
                    data,
                    key,
                    mode,
                    use_padding=use_padding,
                    chunk_size=chunk_size
                )
            )

        else:
            ciphertext, iv = (
                des_encrypt(
                    data,
                    key,
                    mode,
                    None,
                    use_padding
                )
            )

        elapsed = (
            time.perf_counter()
            - start
        )

        print(
            "Mode:",
            mode
        )

        print(
            "Padding:",
            "ON"
            if use_padding
            else "OFF"
        )

        print(
            "Block size:",
            DES.block_size,
            "bytes"
        )

        if iv:
            show_hex(
                "IV",
                iv
            )

        show_hex(
            "Ciphertext",
            ciphertext
        )

        print(
            f"Encryption time: "
            f"{elapsed:.10f} seconds"
        )

        if ask_yes_no(
            "Decrypt now?",
            True
        ):
            if chunked:
                plain = des_decrypt_stream(
                    ciphertext,
                    key,
                    mode,
                    iv,
                    use_padding,
                    chunk_size
                )

            else:
                plain = des_decrypt(
                    ciphertext,
                    key,
                    mode,
                    iv,
                    use_padding
                )

            print(
                "Recovered:",
                plain.decode(
                    errors="replace"
                )
            )

    # ---------------- 3DES ----------------
    elif choice == "3":
        key = choose_3des_key()

        if key is None:
            return

        show_hex(
            "3DES Key",
            key
        )

        print(
            "Mode: 1. ECB  2. CBC"
        )

        mode_no = ask_int(
            "Choose: ",
            1
        )

        modes = {
            1: "ECB",
            2: "CBC"
        }

        if mode_no not in modes:
            print("Invalid mode.")
            return

        mode = modes[mode_no]
        use_padding = choose_padding()

        ciphertext, iv = des3_encrypt(
            data,
            key,
            mode,
            None,
            use_padding
        )

        print(
            "Mode:",
            mode
        )

        print(
            "Padding:",
            "ON"
            if use_padding
            else "OFF"
        )

        print(
            "Block size:",
            DES3.block_size,
            "bytes"
        )

        if iv:
            show_hex(
                "IV",
                iv
            )

        show_hex(
            "Ciphertext",
            ciphertext
        )

        if ask_yes_no(
            "Decrypt now?",
            True
        ):
            plain = des3_decrypt(
                ciphertext,
                key,
                mode,
                iv,
                use_padding
            )

            print(
                "Recovered:",
                plain.decode(
                    errors="replace"
                )
            )

    else:
        print("Invalid choice.")


# ============================================================
# HASHING MENU
# ============================================================

def hashing_menu():
    print("\n=== HASHING ===")
    print("1. Custom 5381")
    print("2. MD5")
    print("3. SHA-1")
    print("4. SHA-256")
    print("5. Whirlpool")
    print("6. Compare MD5/SHA-1/SHA-256")
    print("7. Collision check")
    print("8. Hash data/ciphertext for integrity")

    choice = ask_int(
        "Choose: "
    )

    if choice == 6:
        data = read_text().encode()
        compare_hashes(data)
        return

    if choice == 7:
        n = ask_int(
            "Number of strings: ",
            20
        )

        strings = [
            f"message-{i}-{secrets.token_hex(4)}"
            for i in range(n)
        ]

        alg = input(
            "Algorithm (md5/sha1/sha256): "
        ).strip().lower()

        collision_check(
            strings,
            alg
        )

        return

    if choice == 8:
        text = read_text().encode()

        digest = hashlib.sha256(
            text
        ).hexdigest()

        print(
            "SHA-256 of data/ciphertext:",
            digest
        )

        return

    algorithms = {
        1: "custom",
        2: "md5",
        3: "sha1",
        4: "sha256",
        5: "whirlpool",
    }

    alg = algorithms.get(choice)

    if not alg:
        print("Invalid choice.")
        return

    data = read_text().encode()

    try:
        hash_parameters(
            data,
            alg
        )

    except ValueError as e:
        print(e)


# ============================================================
# RSA MENU
# ============================================================

def rsa_menu():
    print("\n=== RSA ===")
    print("1. Textbook RSA encrypt/decrypt")
    print("2. RSA-OAEP encrypt/decrypt")
    print("3. RSA digital signature")
    print("4. RSA + AES hybrid key protection")

    choice = ask_int(
        "Choose: "
    )

    if choice == 1:
        p = ask_int("p: ")
        q = ask_int("q: ")

        n, phi, e, d = rsa_parameters(
            p,
            q
        )

        text = read_text()

        c = rsa_textbook_encrypt(
            text,
            e,
            n
        )

        print("n =", n)
        print("phi =", phi)
        print("e =", e)
        print("d =", d)
        print("Ciphertext:", c)

        print(
            "Recovered:",
            rsa_textbook_decrypt(
                c,
                d,
                n
            )
        )

    elif choice == 2:
        private_key, public_key = (
            generate_rsa_keys(2048)
        )

        data = read_text().encode()

        if len(data) > 190:
            print(
                "Message is too large for direct "
                "2048-bit RSA-OAEP."
            )

            print(
                "Use the AES + RSA hybrid option "
                "for files/large data."
            )

            return

        start = time.perf_counter()

        c = rsa_oaep_encrypt(
            data,
            public_key
        )

        enc_time = (
            time.perf_counter()
            - start
        )

        p = rsa_oaep_decrypt(
            c,
            private_key
        )

        print(
            "RSA key size: 2048 bits"
        )

        show_hex(
            "Ciphertext",
            c
        )

        print(
            "Recovered:",
            p.decode(
                errors="replace"
            )
        )

        print(
            f"Encryption time: "
            f"{enc_time:.10f} seconds"
        )

    elif choice == 3:
        private_key, public_key = (
            generate_rsa_keys(2048)
        )

        data = read_text().encode()

        scheme = input(
            "Signature scheme "
            "(PKCS1v1.5/PSS): "
        ).strip()

        if scheme not in (
            "PKCS1v1.5",
            "PSS"
        ):
            scheme = "PKCS1v1.5"

        sig = rsa_sign(
            data,
            private_key,
            scheme
        )

        ok = rsa_verify(
            data,
            sig,
            public_key,
            scheme
        )

        tampered = tamper_bytes(
            data
        )

        bad = rsa_verify(
            tampered,
            sig,
            public_key,
            scheme
        )

        print("Signature:")

        show_hex(
            "Signature",
            sig
        )

        print(
            "Original verification:",
            "VALID" if ok else "INVALID"
        )

        print(
            "Tampered verification:",
            "VALID" if bad else "INVALID"
        )

    elif choice == 4:
        data = read_text().encode()

        aes_key = os.urandom(16)

        private_key, public_key = (
            generate_rsa_keys(2048)
        )

        ciphertext, iv, _ = aes_encrypt(
            data,
            aes_key,
            "CBC",
            use_padding=True
        )

        encrypted_key = (
            rsa_oaep_encrypt(
                aes_key,
                public_key
            )
        )

        print("AES key is protected by RSA-OAEP.")

        show_hex(
            "AES ciphertext",
            ciphertext
        )

        show_hex(
            "IV",
            iv
        )

        show_hex(
            "Encrypted AES key",
            encrypted_key
        )

        recovered_key = (
            rsa_oaep_decrypt(
                encrypted_key,
                private_key
            )
        )

        plain = aes_decrypt(
            ciphertext,
            recovered_key,
            "CBC",
            iv,
            None,
            True
        )

        print(
            "Recovered:",
            plain.decode(
                errors="replace"
            )
        )

    else:
        print("Invalid choice.")


# ============================================================
# ELGAMAL MENU
# ============================================================

def elgamal_menu():
    print("\n=== ELGAMAL ===")
    print("1. Encryption/decryption")
    print("2. Digital signature")

    choice = ask_int(
        "Choose: "
    )

    # Exam-friendly default values.
    # Replace them when the question gives p, g, x or k.
    p = 2147483647
    g = 2
    x = 127
    y = pow(g, x, p)

    if choice == 1:
        text = read_text()

        k = ask_int(
            "k (coprime to p-1): ",
            53
        )

        try:
            c = elgamal_encrypt_text(
                text,
                p,
                g,
                x,
                k
            )

            print("p =", p)
            print("g =", g)
            print("Private x =", x)
            print("Public y =", y)
            print("Ciphertext:", c)

            print(
                "Recovered:",
                elgamal_decrypt_text(
                    c,
                    p,
                    x
                )
            )

        except ValueError as e:
            print(e)

    elif choice == 2:
        data = read_text().encode()

        k = ask_int(
            "k (coprime to p-1): ",
            53
        )

        try:
            sig = elgamal_sign(
                data,
                p,
                g,
                x,
                k
            )

            ok = elgamal_verify(
                data,
                sig,
                p,
                g,
                y
            )

            bad = elgamal_verify(
                tamper_bytes(data),
                sig,
                p,
                g,
                y
            )

            print(
                "Public y =",
                y
            )

            print(
                "Signature:",
                sig
            )

            print(
                "Original verification:",
                "VALID" if ok else "INVALID"
            )

            print(
                "Tampered verification:",
                "VALID" if bad else "INVALID"
            )

        except ValueError as e:
            print(e)

    else:
        print("Invalid choice.")


# ============================================================
# DH MENU
# ============================================================

def dh_menu():
    print("\n=== DIFFIE-HELLMAN ===")

    p = ask_int(
        "p: ",
        23
    )

    g = ask_int(
        "g: ",
        5
    )

    a = ask_int(
        "Private A: ",
        6
    )

    b = ask_int(
        "Private B: ",
        15
    )

    start = time.perf_counter()

    A, B, key_a, key_b = dh_exchange(
        p,
        g,
        a,
        b
    )

    elapsed = (
        time.perf_counter()
        - start
    )

    print(
        "Public A:",
        A
    )

    print(
        "Public B:",
        B
    )

    print(
        "Shared key A:",
        key_a
    )

    print(
        "Shared key B:",
        key_b
    )

    print(
        "Keys match:",
        key_a == key_b
    )

    print(
        f"Key exchange time: "
        f"{elapsed:.10f} seconds"
    )


# ============================================================
# ECDH MENU
# ============================================================

def ecdh_menu():
    print("\n=== ECDH ===")

    try:
        start = time.perf_counter()

        a_key, b_key = (
            ecdh_exchange()
        )

        elapsed = (
            time.perf_counter()
            - start
        )

        show_hex(
            "Derived key A",
            a_key
        )

        show_hex(
            "Derived key B",
            b_key
        )

        print(
            "Keys match:",
            a_key == b_key
        )

        print(
            f"Key exchange time: "
            f"{elapsed:.10f} seconds"
        )

    except ImportError:
        print(
            "Install cryptography: "
            "pip install cryptography"
        )


# ============================================================
# RABIN MENU
# ============================================================

def rabin_menu():
    print("\n=== RABIN ===")

    p = ask_int(
        "p (3 mod 4 prime): ",
        7
    )

    q = ask_int(
        "q (3 mod 4 prime): ",
        11
    )

    m = ask_int(
        "Message integer m: ",
        5
    )

    n = p * q

    c = rabin_encrypt(
        m,
        n
    )

    print(
        "n =",
        n
    )

    print(
        "Ciphertext =",
        c
    )

    print(
        "Possible roots:",
        rabin_decrypt(
            c,
            p,
            q
        )
    )

    print(
        "Original m:",
        m
    )


# ============================================================
# RBAC MENU
# ============================================================

def rbac_menu():
    print("\n=== GENERIC RBAC ===")
    print(
        "Roles: Role A, Role B, Role C"
    )

    role = input(
        "Choose role: "
    ).strip()

    print(
        "Actions: "
        "create, view, verify, decrypt, report"
    )

    action = input(
        "Action: "
    ).strip()

    if allowed(
        role,
        action
    ):
        print(
            "Access GRANTED"
        )

        log_event(
            f"GRANTED {role} {action}"
        )

    else:
        print(
            "Access DENIED"
        )


# ============================================================
# KEY MANAGEMENT MENU
# ============================================================

def key_menu():
    print("\n=== KEY MANAGEMENT ===")
    print("1. Generate")
    print("2. View")
    print("3. Distribute / Export")
    print("4. Revoke")
    print("5. Renew")

    choice = ask_int(
        "Choose: "
    )

    name = input(
        "Entity/Role name: "
    ).strip()

    if choice == 1:
        generate_managed_key(
            name
        )

        print(
            "Key generated."
        )

        print(
            KEYS[name]
        )

    elif choice == 2:
        print(
            KEYS.get(
                name,
                "No key found."
            )
        )

    elif choice == 3:
        if (
            name in KEYS
            and KEYS[name]["status"]
            == "ACTIVE"
        ):
            print(
                "Key distribution result:",
                KEYS[name]["key"]
            )

            log_event(
                f"KEY DISTRIBUTED {name}"
            )

        else:
            print(
                "No active key to distribute."
            )

    elif choice == 4:
        print(
            "Revoked."
            if revoke_key(name)
            else "No key found."
        )

    elif choice == 5:
        renew_key(name)

        print(
            "Renewed."
        )

        print(
            KEYS[name]
        )

    else:
        print(
            "Invalid choice."
        )


# ============================================================
# FILE MENU
# ============================================================

def file_menu():
    print("\n=== FILE I/O ===")
    print("1. Create/write text file")
    print("2. Read file")
    print("3. Copy file")
    print("4. Hash file")
    print("5. Tamper file")
    print("6. Show block split")

    choice = ask_int(
        "Choose: "
    )

    if choice == 1:
        name = input(
            "Filename: "
        ).strip()

        text = read_text()

        with open(
            name,
            "w",
            encoding="utf-8"
        ) as f:
            f.write(text)

        print(
            "File created."
        )

    elif choice == 2:
        name = input(
            "Filename: "
        ).strip()

        data = read_bytes(
            name
        )

        print(
            data.decode(
                errors="replace"
            )
        )

    elif choice == 3:
        src = input(
            "Source: "
        ).strip()

        dst = input(
            "Destination: "
        ).strip()

        write_bytes(
            dst,
            read_bytes(src)
        )

        print(
            "Copied."
        )

    elif choice == 4:
        name = input(
            "Filename: "
        ).strip()

        data = read_bytes(
            name
        )

        alg = input(
            "Algorithm "
            "(md5/sha1/sha256/custom): "
        ).strip().lower()

        print(
            "Hash:",
            hash_data(
                data,
                alg
            )
        )

    elif choice == 5:
        name = input(
            "Filename: "
        ).strip()

        data = read_bytes(
            name
        )

        write_bytes(
            name,
            tamper_bytes(data)
        )

        print(
            "One byte modified."
        )

    elif choice == 6:
        try:
            raw = input(
                "Enter hex data: "
            ).strip()

            data = bytes.fromhex(raw)

        except ValueError:
            print("Invalid hex.")
            return

        block_size = ask_int(
            "Block size (8 for DES / 16 for AES): ",
            16
        )

        if block_size <= 0:
            print("Invalid block size.")
            return

        print(
            "Total bytes:",
            len(data)
        )

        for i in range(
            0,
            len(data),
            block_size
        ):
            block = data[i:i + block_size]

            print(
                f"Block {i // block_size + 1}: "
                f"{block.hex()}"
            )

    else:
        print(
            "Invalid choice."
        )


# ============================================================
# CIA DEMO
# ============================================================

def cia_demo():
    print("\n=== GENERIC CIA DEMO ===")

    data = read_text().encode()

    private_key, public_key = (
        generate_rsa_keys(2048)
    )

    if len(data) > 190:
        print(
            "RSA-OAEP demo accepts only "
            "a short message."
        )

        print(
            "Use AES + RSA hybrid for a file."
        )

        return

    # Confidentiality
    ciphertext = rsa_oaep_encrypt(
        data,
        public_key
    )

    # Integrity
    digest = hashlib.sha256(
        ciphertext
    ).hexdigest()

    # Authenticity
    signature = rsa_sign(
        ciphertext,
        private_key
    )

    print(
        "Ciphertext:"
    )

    show_hex(
        "Ciphertext",
        ciphertext
    )

    print(
        "SHA-256:",
        digest
    )

    show_hex(
        "Signature",
        signature
    )

    received_digest = hashlib.sha256(
        ciphertext
    ).hexdigest()

    if received_digest != digest:
        print(
            "Integrity FAILED"
        )

        return

    print(
        "Integrity VERIFIED"
    )

    if not rsa_verify(
        ciphertext,
        signature,
        public_key
    ):
        print(
            "Authenticity FAILED"
        )

        return

    print(
        "Authenticity VERIFIED"
    )

    recovered = rsa_oaep_decrypt(
        ciphertext,
        private_key
    )

    print(
        "Confidentiality: "
        "decryption successful"
    )

    print(
        "Recovered:",
        recovered.decode(
            errors="replace"
        )
    )

    tampered = tamper_bytes(
        ciphertext
    )

    print(
        "Tampered signature verification:",
        "VALID"
        if rsa_verify(
            tampered,
            signature,
            public_key
        )
        else "INVALID"
    )


# ============================================================
# AES + RSA HYBRID FILE DEMO
# ============================================================

def hybrid_file_demo():
    print("\n=== AES + RSA HYBRID FILE DEMO ===")

    filename, data = (
        read_file_bytes()
    )

    bits = ask_int(
        "AES key size (128/192/256): ",
        128
    )

    if bits not in (
        128,
        192,
        256
    ):
        print(
            "Invalid AES key size."
        )

        return

    aes_key = os.urandom(
        bits // 8
    )

    private_key, public_key = (
        generate_rsa_keys(2048)
    )

    ciphertext, iv, _ = aes_encrypt(
        data,
        aes_key,
        "CBC",
        use_padding=True
    )

    encrypted_key = (
        rsa_oaep_encrypt(
            aes_key,
            public_key
        )
    )

    digest = hashlib.sha256(
        ciphertext
    ).hexdigest()

    record = {
        "filename": filename,
        "ciphertext": ciphertext.hex(),
        "iv": iv.hex(),
        "encrypted_key": encrypted_key.hex(),
        "hash": digest,
        "timestamp": now(),
    }

    save_record(
        "secure_record.txt",
        record
    )

    print(
        "Record saved to secure_record.txt"
    )

    print(
        "AES key size:",
        bits
    )

    show_hex(
        "IV",
        iv
    )

    show_hex(
        "Encrypted AES key",
        encrypted_key
    )

    print(
        "SHA-256:",
        digest
    )

    stored = load_record(
        "secure_record.txt"
    )

    ct = bytes.fromhex(
        stored["ciphertext"]
    )

    if (
        hashlib.sha256(ct).hexdigest()
        != stored["hash"]
    ):
        print(
            "Integrity FAILED. "
            "No decryption."
        )

        return

    key = rsa_oaep_decrypt(
        bytes.fromhex(
            stored["encrypted_key"]
        ),
        private_key
    )

    plain = aes_decrypt(
        ct,
        key,
        "CBC",
        bytes.fromhex(
            stored["iv"]
        ),
        None,
        True
    )

    print(
        "Integrity VERIFIED"
    )

    print(
        "Recovered file content:"
    )

    print(
        plain.decode(
            errors="replace"
        )
    )

    if ask_yes_no(
        "Demonstrate tampering?",
        True
    ):
        tampered = tamper_bytes(
            ct
        )

        if (
            hashlib.sha256(
                tampered
            ).hexdigest()
            != stored["hash"]
        ):
            print(
                "Tampering detected: "
                "decryption blocked."
            )

        else:
            print(
                "Unexpected: "
                "hash did not change."
            )


# ============================================================
# SOCKET MENU
# ============================================================

def socket_menu():
    print("\n=== SOCKET HASHING ===")

    print(
        "Run SERVER in one terminal "
        "and CLIENT in another."
    )

    print("1. Server")
    print("2. Client")

    choice = ask_int(
        "Choose: "
    )

    if choice == 1:
        socket_server_hash()

    elif choice == 2:
        socket_client_hash()

    else:
        print(
            "Invalid choice."
        )


# ============================================================
# PERFORMANCE / PLOT
# ============================================================

def performance_menu():
    print("\n=== PERFORMANCE ===")

    print(
        "1. Compare AES-128/192/256"
    )

    print(
        "2. Compare DES vs AES-256"
    )

    print(
        "3. Compare AES modes"
    )

    choice = ask_int(
        "Choose: ",
        1
    )

    data = input(
        "Enter test message: "
    ).encode()

    runs = ask_int(
        "Runs per test: ",
        10
    )

    if runs <= 0:
        print(
            "Runs must be positive."
        )

        return

    rows = []

    if choice == 1:
        for bits in (
            128,
            192,
            256
        ):
            key = os.urandom(
                bits // 8
            )

            times = []

            for _ in range(runs):
                t0 = time.perf_counter()

                aes_encrypt(
                    data,
                    key,
                    "ECB",
                    use_padding=True
                )

                times.append(
                    time.perf_counter()
                    - t0
                )

            avg = (
                float(np.mean(times))
                if np
                else sum(times)
                / len(times)
            )

            rows.append({
                "Algorithm":
                    f"AES-{bits}",
                "Time":
                    avg
            })

    elif choice == 2:
        des_key = os.urandom(8)
        aes_key = os.urandom(32)

        for name, fn, key in (
            (
                "DES",
                des_encrypt,
                des_key
            ),
            (
                "AES-256",
                aes_encrypt,
                aes_key
            ),
        ):
            times = []

            for _ in range(runs):
                t0 = time.perf_counter()

                fn(
                    data,
                    key,
                    "ECB",
                    use_padding=True
                )

                times.append(
                    time.perf_counter()
                    - t0
                )

            avg = (
                float(np.mean(times))
                if np
                else sum(times)
                / len(times)
            )

            rows.append({
                "Algorithm": name,
                "Time": avg
            })

    elif choice == 3:
        key = os.urandom(16)

        for mode in (
            "ECB",
            "CBC",
            "CFB",
            "OFB",
            "CTR"
        ):
            times = []

            for _ in range(runs):
                t0 = time.perf_counter()

                aes_encrypt(
                    data,
                    key,
                    mode,
                    use_padding=(
                        mode in ("ECB", "CBC")
                    )
                )

                times.append(
                    time.perf_counter()
                    - t0
                )

            avg = (
                float(np.mean(times))
                if np
                else sum(times)
                / len(times)
            )

            rows.append({
                "Algorithm":
                    f"AES-{mode}",
                "Time":
                    avg
            })

    else:
        print(
            "Invalid choice."
        )

        return

    for row in rows:
        print(
            f"{row['Algorithm']}: "
            f"{row['Time']:.10f} seconds"
        )

    if (
        pd is not None
        and plt is not None
    ):
        df = pd.DataFrame(
            rows
        )

        print(df)

        df.plot(
            x="Algorithm",
            y="Time",
            kind="bar",
            legend=False
        )

        plt.ylabel(
            "Average time (seconds)"
        )

        plt.title(
            "Encryption Performance"
        )

        plt.tight_layout()
        plt.show()

    else:
        print(
            "Install numpy pandas "
            "matplotlib for plotting."
        )


# ============================================================
# SCENARIO TEMPLATES
# ============================================================

def scenario_secure_marks():
    print("\n=== SECURE MARKS FILE ===")

    data = read_text().encode()

    key = os.urandom(16)

    ct, iv, _ = aes_encrypt(
        data,
        key,
        "CBC",
        use_padding=True
    )

    digest = hashlib.sha256(
        ct
    ).hexdigest()

    print(
        "AES-128 CBC"
    )

    show_hex(
        "Ciphertext",
        ct
    )

    show_hex(
        "IV",
        iv
    )

    print(
        "SHA-256:",
        digest
    )

    received = hashlib.sha256(
        ct
    ).hexdigest()

    if received != digest:
        print(
            "Integrity FAILED. "
            "No decryption."
        )

        return

    print(
        "Integrity VERIFIED"
    )

    plain = aes_decrypt(
        ct,
        key,
        "CBC",
        iv,
        None,
        True
    )

    print(
        "Recovered:",
        plain.decode(
            errors="replace"
        )
    )

    tampered = tamper_bytes(
        ct
    )

    bad_digest = hashlib.sha256(
        tampered
    ).hexdigest()

    print(
        "Tampered verification:",
        "FAILED"
        if bad_digest != digest
        else "UNEXPECTED PASS"
    )


def scenario_authenticated_message():
    print("\n=== AUTHENTICATED MESSAGE ===")

    data = read_text().encode()

    private_key, public_key = (
        generate_rsa_keys(2048)
    )

    digest = hashlib.sha256(
        data
    ).hexdigest()

    signature = rsa_sign(
        data,
        private_key
    )

    print(
        "SHA-256:",
        digest
    )

    show_hex(
        "RSA Signature",
        signature
    )

    print(
        "Original verification:",
        "VALID"
        if rsa_verify(
            data,
            signature,
            public_key
        )
        else "INVALID"
    )

    tampered = tamper_bytes(
        data
    )

    print(
        "Tampered verification:",
        "VALID"
        if rsa_verify(
            tampered,
            signature,
            public_key
        )
        else "INVALID"
    )


def scenario_hospital_session():
    print("\n=== HOSPITAL SESSION SETUP ===")

    print("1. DH")
    print("2. ECDH")

    choice = ask_int(
        "Choose: ",
        1
    )

    message = read_text().encode()

    if choice == 1:
        p = ask_int(
            "p: ",
            23
        )

        g = ask_int(
            "g: ",
            5
        )

        a = ask_int(
            "Private A: ",
            6
        )

        b = ask_int(
            "Private B: ",
            15
        )

        t0 = time.perf_counter()

        A, B, key_a, key_b = (
            dh_exchange(
                p,
                g,
                a,
                b
            )
        )

        elapsed = (
            time.perf_counter()
            - t0
        )

        print(
            "Shared key:",
            key_a
        )

        print(
            "Keys match:",
            key_a == key_b
        )

        key = hashlib.sha256(
            str(key_a).encode()
        ).digest()[:16]

    elif choice == 2:
        t0 = time.perf_counter()

        key_a, key_b = (
            ecdh_exchange()
        )

        elapsed = (
            time.perf_counter()
            - t0
        )

        print(
            "Shared keys match:",
            key_a == key_b
        )

        key = key_a

    else:
        print(
            "Invalid choice."
        )

        return

    print(
        f"Key exchange time: "
        f"{elapsed:.10f} seconds"
    )

    ct, iv, _ = aes_encrypt(
        message,
        key,
        "CBC",
        use_padding=True
    )

    print(
        "AES session encryption successful"
    )

    show_hex(
        "IV",
        iv
    )

    show_hex(
        "Ciphertext",
        ct
    )

    print(
        "Recovered:",
        aes_decrypt(
            ct,
            key,
            "CBC",
            iv,
            None,
            True
        ).decode(
            errors="replace"
        )
    )


def scenario_revocable_record():
    print("\n=== REVOCABLE SECURE RECORD ===")

    print(
        "Role names are generic: "
        "Role A / Role B / Role C"
    )

    roles = {
        "Role A": {
            "create",
            "view",
            "verify",
            "decrypt"
        },

        "Role B": {
            "view",
            "verify",
            "decrypt"
        },

        "Role C": {
            "view",
            "verify",
            "report"
        },
    }

    role = input(
        "Enter role: "
    ).strip()

    data = read_text().encode()

    if (
        "create"
        not in roles.get(
            role,
            set()
        )
    ):
        print(
            "Access denied: "
            "only Role A creates the record."
        )

        return

    key_name = "record-key"

    generate_managed_key(
        key_name
    )

    aes_key = os.urandom(16)

    ct, iv, _ = aes_encrypt(
        data,
        aes_key,
        "CBC",
        use_padding=True
    )

    digest = hashlib.sha256(
        ct
    ).hexdigest()

    record = {
        "ciphertext":
            ct.hex(),

        "iv":
            iv.hex(),

        "hash":
            digest,

        "timestamp":
            now(),

        "status":
            "ACTIVE",
    }

    save_record(
        "role_record.txt",
        record
    )

    print(
        "Record stored."
    )

    action = input(
        "Enter role to access record: "
    ).strip()

    if not allowed(
        action,
        "decrypt"
    ):
        return

    if not key_active(
        key_name
    ):
        print(
            "Key revoked. "
            "Access denied."
        )

        return

    stored = load_record(
        "role_record.txt"
    )

    ct = bytes.fromhex(
        stored["ciphertext"]
    )

    if (
        hashlib.sha256(
            ct
        ).hexdigest()
        != stored["hash"]
    ):
        print(
            "Integrity failed."
        )

        return

    print(
        "Integrity verified."
    )

    print(
        "Recovered:",
        aes_decrypt(
            ct,
            aes_key,
            "CBC",
            bytes.fromhex(
                stored["iv"]
            ),
            None,
            True
        ).decode(
            errors="replace"
        )
    )

    revoke_key(
        key_name
    )

    print(
        "Key revoked."
    )

    if not key_active(
        key_name
    ):
        print(
            "Future access: DENIED"
        )


def scenario_three_role_record():
    print("\n=== THREE-ROLE SECURE RECORD ===")

    print(
        "1. Role A - create"
    )

    print(
        "2. Role B - verify/decrypt"
    )

    print(
        "3. Role C - verify/report"
    )

    role_no = ask_int(
        "Choose role: ",
        1
    )

    role = {
        1: "Role A",
        2: "Role B",
        3: "Role C"
    }.get(
        role_no
    )

    if not role:
        print(
            "Invalid role."
        )

        return

    data = read_text().encode()

    aes_key = os.urandom(16)

    private_key, public_key = (
        generate_rsa_keys(2048)
    )

    ct, iv, _ = aes_encrypt(
        data,
        aes_key,
        "CBC",
        use_padding=True
    )

    digest = hashlib.sha256(
        ct
    ).hexdigest()

    signature = rsa_sign(
        ct,
        private_key
    )

    print(
        "Record created."
    )

    print(
        "Ciphertext:",
        ct.hex()
    )

    print(
        "SHA-256:",
        digest
    )

    print(
        "Timestamp:",
        now()
    )

    new_digest = hashlib.sha256(
        ct
    ).hexdigest()

    integrity = (
        new_digest == digest
    )

    authenticity = rsa_verify(
        ct,
        signature,
        public_key
    )

    print(
        "Integrity:",
        "VALID"
        if integrity
        else "INVALID"
    )

    print(
        "Authenticity:",
        "VALID"
        if authenticity
        else "INVALID"
    )

    if role == "Role A":
        print(
            "Role A can create/view/decrypt."
        )

        if integrity and authenticity:
            print(
                "Recovered:",
                aes_decrypt(
                    ct,
                    aes_key,
                    "CBC",
                    iv,
                    None,
                    True
                ).decode(
                    errors="replace"
                )
            )

    elif role == "Role B":
        print(
            "Role B can verify/decrypt."
        )

        if integrity and authenticity:
            print(
                "Recovered:",
                aes_decrypt(
                    ct,
                    aes_key,
                    "CBC",
                    iv,
                    None,
                    True
                ).decode(
                    errors="replace"
                )
            )

    else:
        print(
            "Role C can verify/report only."
        )

        print(
            "Plaintext is NOT displayed."
        )


def scenarios_menu():
    print("\n=== SCENARIO TEMPLATES ===")

    print(
        "1. Secure Marks File"
    )

    print(
        "2. Authenticated Department Message"
    )

    print(
        "3. Hospital Session Setup"
    )

    print(
        "4. Revocable Secure Document"
    )

    print(
        "5. Generic 3-Role Secure Record"
    )

    choice = ask_int(
        "Choose: "
    )

    if choice == 1:
        scenario_secure_marks()

    elif choice == 2:
        scenario_authenticated_message()

    elif choice == 3:
        scenario_hospital_session()

    elif choice == 4:
        scenario_revocable_record()

    elif choice == 5:
        scenario_three_role_record()

    else:
        print(
            "Invalid choice."
        )


# ============================================================
# MAIN MENU
# ============================================================

def main():
    print(
        "================================================"
    )

    print(
        "        MASTER CRYPTO LAB TOOLKIT"
    )

    print(
        "================================================"
    )

    print(
        "Generic roles: Role A / Role B / Role C"
    )

    print(
        "Pick only the modules required by the question."
    )

    while True:
        print("\n================ MAIN MENU ================")

        print(
            "1. AES / DES / 3DES Encryption"
        )

        print(
            "2. Hashing"
        )

        print(
            "3. RSA"
        )

        print(
            "4. ElGamal"
        )

        print(
            "5. Diffie-Hellman"
        )

        print(
            "6. ECDH"
        )

        print(
            "7. Rabin"
        )

        print(
            "8. RBAC"
        )

        print(
            "9. Key Management"
        )

        print(
            "10. File I/O / Tampering"
        )

        print(
            "11. CIA Demo"
        )

        print(
            "12. AES + RSA Hybrid File"
        )

        print(
            "13. Socket Hashing"
        )

        print(
            "14. Performance / Plot"
        )

        print(
            "15. Scenario Templates"
        )

        print(
            "16. Audit Log"
        )

        print(
            "0. Exit"
        )

        choice = input(
            "Choose: "
        ).strip()

        try:
            if choice == "1":
                symmetric_menu()

            elif choice == "2":
                hashing_menu()

            elif choice == "3":
                rsa_menu()

            elif choice == "4":
                elgamal_menu()

            elif choice == "5":
                dh_menu()

            elif choice == "6":
                ecdh_menu()

            elif choice == "7":
                rabin_menu()

            elif choice == "8":
                rbac_menu()

            elif choice == "9":
                key_menu()

            elif choice == "10":
                file_menu()

            elif choice == "11":
                cia_demo()

            elif choice == "12":
                hybrid_file_demo()

            elif choice == "13":
                socket_menu()

            elif choice == "14":
                performance_menu()

            elif choice == "15":
                scenarios_menu()

            elif choice == "16":
                if os.path.exists(
                    "audit.log"
                ):
                    with open(
                        "audit.log",
                        encoding="utf-8"
                    ) as f:
                        print(
                            f.read()
                        )

                else:
                    print(
                        "No audit log yet."
                    )

            elif choice == "0":
                print(
                    "Exiting."
                )

                break

            else:
                print(
                    "Invalid choice."
                )

        except (
            ValueError,
            OSError,
            EOFError
        ) as e:
            print(
                "Error:",
                e
            )


if __name__ == "__main__":
    main()
