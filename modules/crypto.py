from Crypto.Cipher import AES
from Crypto.Hash import SHA3_256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from config import get_db_connection
import base64
import hashlib
import os

def generate_rsa_keys():
    """Buat sepasang kunci RSA (private & public)."""
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

# ========== Util Hash ==========
def generate_sha3(data: bytes) -> str:
    h = SHA3_256.new()
    h.update(data)
    return h.hexdigest()

def derive_key_sha3(password: str) -> bytes:
    h = SHA3_256.new()
    h.update(password.encode("utf-8"))
    return h.digest()  # 32 bytes

# ========== AES TEXT ==========
def aes_encrypt_text(plain_text: str, password: str) -> str:
    key = derive_key_sha3(password)
    iv  = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(plain_text.encode("utf-8"), AES.block_size))
    # kembalikan dalam base64 agar aman ditampilkan
    import base64
    return base64.b64encode(iv + ct).decode("utf-8")

def aes_decrypt_text(enc_text_b64: str, password: str) -> str:
    import base64
    try:
        raw = base64.b64decode(enc_text_b64)
        iv, ct = raw[:16], raw[16:]
        key = derive_key_sha3(password)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        return pt.decode("utf-8")
    except Exception as e:
        return f"[Decryption Error] {e}"

# ========== AES FILE (symmetric, menyimpan ekstensi) ==========
# Format: [ext_len:1][ext...][iv:16][ciphertext...]
def aes_encrypt(file_data: bytes, key: bytes, original_ext: str):
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(file_data, AES.block_size))
    ext_bytes = original_ext.encode()
    header = len(ext_bytes).to_bytes(1, "big") + ext_bytes
    file_hash = generate_sha3(file_data)
    return header + iv + ct, file_hash

def aes_decrypt(encrypted_data: bytes, key: bytes):
    ext_len = encrypted_data[0]
    ext = encrypted_data[1:1+ext_len].decode()
    iv = encrypted_data[1+ext_len:1+ext_len+16]
    ct = encrypted_data[1+ext_len+16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt, ext

# ========== HYBRID RSA + AES (per-user binding via fingerprint) ==========
# Format file:
# [fingerprint(32)][rsa_len(2)][rsa(aes_key) ...][iv(16)][aes_ciphertext...]
# fingerprint = sha256(public_key_pem)
def rsa_encrypt_file(data: bytes, public_key_pem: bytes):
    """
    Enkripsi file menggunakan hybrid RSA+AES dengan fingerprint public key (32 byte)
    agar hanya pemilik key tersebut yang bisa mendekripsi.
    """
    # 1️⃣ AES acak untuk data utama
    aes_key = get_random_bytes(32)  # AES-256
    iv = get_random_bytes(16)
    aes_cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    ciphertext = aes_cipher.encrypt(pad(data, AES.block_size))

    # 2️⃣ Enkripsi AES key pakai RSA-OAEP
    rsa_key = RSA.import_key(public_key_pem)
    rsa_cipher = PKCS1_OAEP.new(rsa_key)
    enc_aes_key = rsa_cipher.encrypt(aes_key)

    # 3️⃣ Fingerprint unik public key (32 bytes)
    fingerprint = hashlib.sha256(public_key_pem).digest()

    # 4️⃣ Kemas blob: [fingerprint(32)] [len_RSA(2)] [RSA_AES_key] [IV(16)] [Ciphertext]
    rsa_len = len(enc_aes_key).to_bytes(2, "big")
    blob = fingerprint + rsa_len + enc_aes_key + iv + ciphertext

    return blob, fingerprint.hex()

def rsa_decrypt_file(encrypted_blob: bytes, private_key_pem: bytes):
    try:
        priv = RSA.import_key(private_key_pem)
        rsa_cipher = PKCS1_OAEP.new(priv)

        # ambil panjang RSA-encrypted AES key (2 byte setelah fingerprint)
        enc_len = int.from_bytes(encrypted_blob[32:34], "big")
        p = 34
        q = 34 + enc_len
        enc_aes_key = encrypted_blob[p:q]

        # decrypt AES key
        aes_key = rsa_cipher.decrypt(enc_aes_key)

        # ambil IV & ciphertext
        iv = encrypted_blob[q:q+16]
        ciphertext = encrypted_blob[q+16:]

        aes_cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        decrypted = unpad(aes_cipher.decrypt(ciphertext), AES.block_size)

        # Debug info
        print("=== DEBUG DECRYPT ===", flush=True)
        print("Expected fingerprint:", hashlib.sha256(priv.publickey().export_key()).hexdigest(), flush=True)
        print("Stored fingerprint  :", hashlib.sha256(encrypted_blob[:32]).hexdigest(), flush=True)

        return decrypted

    except Exception as e:
        print("[rsa_decrypt_file] ERROR:", e, flush=True)
        return None


# ========= VIDEO STEGANOGRAPHY (LSB ON BLUE CHANNEL) =========
import cv2
import numpy as np
import os
import subprocess

def _bytes_to_bits(data: bytes) -> np.ndarray:
    return np.unpackbits(np.frombuffer(data, dtype=np.uint8))

def _bits_to_bytes(bits: np.ndarray) -> bytes:
    if len(bits) % 8 != 0:
        bits = np.pad(bits, (0, 8 - len(bits) % 8), constant_values=0)
    return np.packbits(bits).tobytes()

def convert_to_avi(input_path: str) -> str:
    """
    Konversi video apapun (mp4, mkv, mov) ke AVI (FFV1 lossless).
    """
    base = os.path.splitext(input_path)[0]
    avi_path = f"{base}_converted.avi"
    cmd = [
        "ffmpeg", "-y", "-i", input_path,
        "-c:v", "ffv1", "-level", "3", "-pix_fmt", "yuv420p",
        "-an", avi_path
    ]
    subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return avi_path

def hide_message_in_video(input_path, message, output_path=None):
    cap = cv2.VideoCapture(input_path)
    if not cap.isOpened():
        raise Exception("Tidak bisa membuka video input.")

    fourcc = cv2.VideoWriter_fourcc(*'FFV1')
    fps = int(cap.get(cv2.CAP_PROP_FPS))
    width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
    height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
    output_path = os.path.splitext(input_path)[0] + "_stego.avi"

    out = cv2.VideoWriter(output_path, fourcc, fps, (width, height))

    # Encode message
    msg_bytes = message.encode('utf-8')
    msg_len = len(msg_bytes)
    header = msg_len.to_bytes(4, 'big')  # 32-bit header
    payload = header + msg_bytes
    bits = ''.join(format(byte, '08b') for byte in payload)

    bit_index = 0
    total_bits = len(bits)

    while True:
        ret, frame = cap.read()
        if not ret:
            break

        for row in range(height):
            for col in range(width):
                for channel in range(3):
                    if bit_index < total_bits:
                        frame[row, col, channel] &= 0b11111110
                        frame[row, col, channel] |= int(bits[bit_index])
                        bit_index += 1
                    else:
                        break
                if bit_index >= total_bits:
                    break
            if bit_index >= total_bits:
                break

        out.write(frame)
        if bit_index >= total_bits:
            break

    cap.release()
    out.release()
    print(f"[DEBUG] Embedded {bit_index} bits into {output_path}")
    return {"embedded_bits": bit_index, "output": output_path}


def _bits_to_text(bits: str) -> str:
    """Ubah bit menjadi string teks (dengan terminator 00000000)."""
    chars = []
    for i in range(0, len(bits), 8):
        byte = bits[i:i+8]
        if byte == '00000000':
            break
        chars.append(chr(int(byte, 2)))
    return ''.join(chars)

def extract_message_from_video(input_path):
    cap = cv2.VideoCapture(input_path)
    if not cap.isOpened():
        raise Exception("Tidak bisa membuka video input.")

    bits = ""
    while True:
        ret, frame = cap.read()
        if not ret:
            break
        height, width, _ = frame.shape
        for row in range(height):
            for col in range(width):
                for channel in range(3):
                    bits += str(frame[row, col, channel] & 1)

    cap.release()

    # Ambil header panjang pesan
    header_bits = bits[:32]
    msg_len = int(header_bits, 2)
    msg_bits = bits[32:32 + msg_len * 8]

    chars = [chr(int(msg_bits[i:i+8], 2)) for i in range(0, len(msg_bits), 8)]
    message = ''.join(chars)
    return message








