import os
import hashlib
from hmac import compare_digest
from config import get_db_connection
from Crypto.PublicKey import RSA  # ⬅️ pastikan ini sudah ada
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
import traceback

# Scrypt params (jangan ubah-ubah antar register & verify)
SCRYPT_PARAMS = dict(n=16384, r=8, p=1, dklen=64)

def generate_rsa_keys():
    """Buat sepasang kunci RSA (private & public)."""
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def encrypt_private_key(private_pem, password):
    salt = os.urandom(16)
    key = scrypt(password.encode(), salt, 32, N=2**14, r=8, p=1)
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(private_pem)
    return cipher.nonce + ciphertext + tag, salt

def decrypt_private_key(enc_private, salt, password):
    try:
        print("=== DEBUG decrypt_private_key ===", flush=True)
        print("Password:", password, flush=True)
        print("Salt:", salt.hex() if salt else None, flush=True)
        print("Encrypted len:", len(enc_private), flush=True)
        print("[DEBUG] Password:", password, flush=True)
        print("[DEBUG] Salt len:", len(salt) if salt else None, flush=True)
        key = scrypt(password.encode(), salt, 32, N=2**14, r=8, p=1)
        cipher = AES.new(key, AES.MODE_GCM, nonce=enc_private[:16])
        decrypted = cipher.decrypt_and_verify(enc_private[16:-16], enc_private[-16:])
        return decrypted
    except Exception as e:
        print("[decrypt_private_key] ERROR:", e, flush=True)
        return None


def hash_password(password: str):
    """Return tuple (key_bytes, salt_bytes)."""
    salt = os.urandom(16)
    key = hashlib.scrypt(password.encode('utf-8'), salt=salt, **SCRYPT_PARAMS)
    return key, salt


def verify_password(stored_key, stored_salt, entered_password: str) -> bool:
    """Bandingkan hash password dengan hasil scrypt baru."""
    if isinstance(stored_key, bytearray):
        stored_key = bytes(stored_key)
    if isinstance(stored_salt, bytearray):
        stored_salt = bytes(stored_salt)
    if isinstance(stored_key, str):
        stored_key = bytes.fromhex(stored_key)
    if isinstance(stored_salt, str):
        stored_salt = bytes.fromhex(stored_salt)

    try:
        new_key = hashlib.scrypt(
            entered_password.encode("utf-8"),
            salt=stored_salt,
            **SCRYPT_PARAMS
        )
        return compare_digest(new_key, stored_key)
    except Exception as e:
        print("[verify_password] ERROR:", e)
        return False


# --- REGISTER USER ---
def register_user(username, email, password):
    key, salt = hash_password(password)
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # cek apakah email sudah terdaftar
        cursor.execute("SELECT user_id FROM users WHERE email=%s", (email,))
        if cursor.fetchone():
            return False  # email already registered

        # simpan data user
        cursor.execute("""
            INSERT INTO users (username, email, password_hash, salt, role, status)
            VALUES (%s, %s, %s, %s, 'user', 'active')
        """, (username, email, key, salt))
        conn.commit()
        user_id = cursor.lastrowid
        print(f"[REGISTER] User {username} berhasil ditambahkan (ID={user_id})")

        # buat RSA keypair dan simpan di tabel user_keys
        try:
            private_key, public_key = generate_rsa_keys()

            # Enkripsi private key pakai password user
            enc_private, rsa_salt = encrypt_private_key(private_key, password)

            cursor.execute("""
                INSERT INTO user_keys (user_id, rsa_public_pem, rsa_private_pem_enc, rsa_salt)
                VALUES (%s, %s, %s, %s)
            """, (user_id, public_key, enc_private, rsa_salt))
            conn.commit()
            print(f"[RSA] RSA keypair dibuat untuk user_id={user_id}")
        except Exception as e:
            print("[RSA_INIT] ERROR saat membuat RSA key:", e)
            traceback.print_exc()

        return True

    except Exception as e:
        print("[register_user] ERROR:", e)
        traceback.print_exc()
        return False

    finally:
        cursor.close()
        conn.close()


# --- LOGIN USER ---
def login_user(email, password):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT * FROM users WHERE email = %s AND status = 'active'", (email,))
        user = cursor.fetchone()
        if not user:
            print(f"❌ Email {email} tidak ditemukan")
            return None

        ok = verify_password(user["password_hash"], user["salt"], password)
        if ok:
            print(f"✅ Login sukses: {user['username']}")
            return user
        else:
            print("❌ Password salah")
            return None

    except Exception as e:
        print("[login_user] ERROR:", e)
        traceback.print_exc()
        return None

    finally:
        cursor.close()
        conn.close()


