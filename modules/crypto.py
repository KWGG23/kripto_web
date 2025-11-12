# modules/crypto.py
import os
import base64
import hashlib
import cv2
import numpy as np

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


# =========================
#  Utilities / Hash helpers
# =========================

def generate_sha3(data: bytes) -> str:
    """SHA3-256 hex digest of data (utility)."""
    from Crypto.Hash import SHA3_256
    h = SHA3_256.new()
    h.update(data)
    return h.hexdigest()

def compute_fp32(public_key_pem: bytes) -> bytes:
    """32-byte fingerprint dari public key PEM (SHA-256)."""
    if isinstance(public_key_pem, str):
        public_key_pem = public_key_pem.encode('utf-8')
    return hashlib.sha256(public_key_pem).digest()


# =========================
#  TEXT ENCRYPTION (AES-CBC)
#  Key derivation: SHA3-256(password)
# =========================

def _derive_key_sha3(password: str) -> bytes:
    """Derive 256-bit AES key dari password dengan SHA3-256."""
    from Crypto.Hash import SHA3_256
    h = SHA3_256.new()
    h.update(password.encode('utf-8'))
    return h.digest()  # 32 bytes

def aes_encrypt_text(plain_text: str, password: str) -> str:
    """Enkripsi teks -> base64(iv|ciphertext)."""
    key = _derive_key_sha3(password)
    iv  = get_random_bytes(16)
    c   = AES.new(key, AES.MODE_CBC, iv)
    ct  = c.encrypt(pad(plain_text.encode('utf-8'), AES.block_size))
    return base64.b64encode(iv + ct).decode('utf-8')

def aes_decrypt_text(enc_text_b64: str, password: str) -> str:
    """Dekripsi base64(iv|ciphertext) -> plaintext str."""
    try:
        raw = base64.b64decode(enc_text_b64)
        iv, ct = raw[:16], raw[16:]
        key = _derive_key_sha3(password)
        c   = AES.new(key, AES.MODE_CBC, iv)
        pt  = unpad(c.decrypt(ct), AES.block_size)
        return pt.decode('utf-8')
    except Exception as e:
        return f"[Decryption Error] {e}"


# ============================================
#  (Opsional) FILE ENCRYPTION (AES-CBC Header)
#  Menyimpan ekstensi asli dalam header
#  Format: [ext_len 1B][ext][iv 16B][ciphertext]
#  (Tidak dipakai route RSA hybrid, tapi disediakan)
# ============================================

def aes_encrypt(file_data: bytes, key: bytes, original_ext: str = ".bin"):
    iv = get_random_bytes(16)
    c  = AES.new(key, AES.MODE_CBC, iv)
    ct = c.encrypt(pad(file_data, AES.block_size))
    ext_bytes = original_ext.encode()
    header = len(ext_bytes).to_bytes(1, 'big') + ext_bytes
    file_hash = generate_sha3(file_data)
    return header + iv + ct, file_hash

def aes_decrypt(encrypted_data: bytes, key: bytes):
    ext_len = encrypted_data[0]
    ext     = encrypted_data[1:1+ext_len].decode()
    p       = 1 + ext_len
    iv      = encrypted_data[p:p+16]
    ct      = encrypted_data[p+16:]
    c       = AES.new(key, AES.MODE_CBC, iv)
    pt      = unpad(c.decrypt(ct), AES.block_size)
    return pt, ext


# =====================================
#  RSA HYBRID (AES-256-CBC + RSA-OAEP)
#  Hanya pemilik private key yang cocok
#  yang bisa mendekripsi (fingerprint check)
#  Blob format:
#    [fp32][len(encAES) 2B][encAES][iv16][ct...]
# =====================================

def rsa_hybrid_encrypt(data: bytes, public_key_pem: bytes):
    """
    Enkripsi hybrid:
      - Data dienkripsi AES-256-CBC (key acak)
      - AES key dibungkus RSA-OAEP
      - Disisipkan fingerprint publik 32B untuk validasi saat decrypt
    return: (blob_bytes, fp_hex)
    """
    if isinstance(public_key_pem, str):
        public_key_pem = public_key_pem.encode('utf-8')

    # 1) AES untuk data
    aes_key = get_random_bytes(32)  # AES-256
    iv      = get_random_bytes(16)
    c_aes   = AES.new(aes_key, AES.MODE_CBC, iv)
    ct      = c_aes.encrypt(pad(data, AES.block_size))

    # 2) Bungkus AES key pakai RSA-OAEP
    rsa_key = RSA.import_key(public_key_pem)
    c_rsa   = PKCS1_OAEP.new(rsa_key)
    enc_aes = c_rsa.encrypt(aes_key)

    # 3) Fingerprint public key (32B)
    fp = compute_fp32(public_key_pem)  # bytes (32)

    # 4) Kemas blob
    enc_len = len(enc_aes).to_bytes(2, "big")  # cukup untuk 2048/3072-bit key
    blob = fp + enc_len + enc_aes + iv + ct

    return blob, fp.hex()

def rsa_hybrid_decrypt(encrypted_blob: bytes, private_key_pem: bytes) -> bytes:
    """
    Dekripsi hybrid:
      - Validasi fingerprint (private key harus cocok dengan fp yang tertanam)
      - Dekripsi AES key dengan RSA-OAEP
      - Dekripsi data AES-256-CBC
    raise ValueError jika fingerprint mismatch / format tidak valid
    """
    if isinstance(private_key_pem, str):
        private_key_pem = private_key_pem.encode('utf-8')

    priv = RSA.import_key(private_key_pem)
    pub  = priv.publickey().export_key()

    expected_fp = compute_fp32(pub)            # 32B
    stored_fp   = encrypted_blob[:32]
    if stored_fp != expected_fp:
        raise ValueError("Private key tidak cocok (fingerprint mismatch).")

    enc_len = int.from_bytes(encrypted_blob[32:34], "big")
    p = 34
    q = 34 + enc_len
    enc_aes = encrypted_blob[p:q]

    c_rsa   = PKCS1_OAEP.new(priv)
    aes_key = c_rsa.decrypt(enc_aes)

    iv = encrypted_blob[q:q+16]
    ct = encrypted_blob[q+16:]
    c_aes = AES.new(aes_key, AES.MODE_CBC, iv)
    data  = unpad(c_aes.decrypt(ct), AES.block_size)
    return data


# ==========================================
#  STEGANOGRAFI VIDEO (Lossless FFV1 → .avi)
#  Robust vs recompression (hindari mp4 lossy)
# ==========================================

def _text_to_bits(text: str) -> str:
    # 8-bit per char + 00000000 terminator
    bits = ''.join(format(ord(c), '08b') for c in text)
    return bits + '00000000'

def _bits_to_text(bits: str) -> str:
    chars = []
    for i in range(0, len(bits), 8):
        byte = bits[i:i+8]
        if byte == '00000000':
            break
        chars.append(chr(int(byte, 2)))
    return ''.join(chars)

def hide_message_in_video(input_path: str, message: str):
    """Sembunyikan pesan via LSB semua channel dalam konten FFV1 (lossless) AVI."""
    cap = cv2.VideoCapture(input_path)
    if not cap.isOpened():
        raise Exception("Tidak bisa membuka video input.")

    fps    = cap.get(cv2.CAP_PROP_FPS) or 25
    width  = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
    height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))

    # Paksa output ke .avi FFV1 (lossless)
    base, _ = os.path.splitext(input_path)
    output_path = f"{base}_stego.avi"
    fourcc = cv2.VideoWriter_fourcc(*'FFV1')
    out    = cv2.VideoWriter(output_path, fourcc, fps, (width, height))

    msg_bits = _text_to_bits(message)
    bit_idx  = 0
    total    = 0

    while True:
        ret, frame = cap.read()
        if not ret:
            break

        if bit_idx < len(msg_bits):
            # embed LSB semua channel BGR
            for r in range(height):
                for c in range(width):
                    for ch in range(3):
                        if bit_idx >= len(msg_bits):
                            break
                        frame[r, c, ch] &= 0b11111110
                        frame[r, c, ch] |= int(msg_bits[bit_idx])
                        bit_idx += 1
                        total   += 1
                    if bit_idx >= len(msg_bits):
                        break
                if bit_idx >= len(msg_bits):
                    break

        out.write(frame)

    cap.release()
    out.release()
    return {"embedded_bits": total, "output": output_path}

def extract_message_from_video(input_path: str) -> str:
    """Ekstrak pesan hingga terminator 00000000."""
    cap = cv2.VideoCapture(input_path)
    if not cap.isOpened():
        raise Exception("Tidak bisa membuka video input.")

    bits = ""
    done = False
    while True:
        ret, frame = cap.read()
        if not ret:
            break

        h, w, _ = frame.shape
        for r in range(h):
            for c in range(w):
                for ch in range(3):
                    bits += str(frame[r, c, ch] & 1)
                    if bits.endswith("00000000"):
                        done = True
                        break
                if done: break
            if done: break
        if done: break

    cap.release()
    return _bits_to_text(bits)
