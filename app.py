from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory
from modules.auth import register_user, login_user, decrypt_private_key
from modules.crypto import (
    aes_encrypt, aes_decrypt, aes_encrypt_text, aes_decrypt_text,
    rsa_hybrid_encrypt, rsa_hybrid_decrypt, compute_fp32,
    hide_message_in_video, extract_message_from_video
)
from config import get_db_connection
import os

app = Flask(__name__)
app.secret_key = "super_secret_key"
UPLOAD_FOLDER = 'static/uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


# --- Helper functions ---
def get_current_user_id():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT user_id FROM users WHERE username = %s", (session['user'],))
    user = cursor.fetchone()
    cursor.close()
    conn.close()
    return user['user_id'] if user else None


def get_user_keys(user_id):
    """Ambil RSA public & private key milik user dari DB."""
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT rsa_public_pem, rsa_private_pem_enc, rsa_salt FROM user_keys WHERE user_id = %s", (user_id,))
    keys = cursor.fetchone()
    cursor.close()
    conn.close()
    return keys


def save_file_record(user_id, original_name, enc_name, fingerprint):
    """Simpan metadata file terenkripsi ke DB."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO files (user_id, original_filename, encrypted_filename, file_sha256, owner_fp)
        VALUES (%s, %s, %s, %s, %s)
    """, (user_id, original_name, enc_name, fingerprint, fingerprint))
    conn.commit()
    cursor.close()
    conn.close()


def user_owns_encrypted_file(user_id, filename, file_data):
    """Periksa apakah file yang akan didekripsi benar milik user."""
    fingerprint = file_data[:32].hex()
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT owner_fp FROM files WHERE encrypted_filename = %s AND user_id = %s", (filename, user_id))
    record = cursor.fetchone()
    cursor.close()
    conn.close()
    return record and record['owner_fp'] == fingerprint


# --- Routes ---
@app.route('/')
def index():
    if 'user' in session:
        return render_template('dashboard.html', user=session['user'])
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        if register_user(username, email, password):
            flash("✅ Registration successful! Please login.", "success")
            return redirect(url_for('login'))
        else:
            flash("❌ Email already registered or database error.", "danger")

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = login_user(email, password)
        if user:
            session['user'] = user['username']
            session['user_password'] = password  # disimpan sementara untuk decrypt private key
            flash(f"✅ Welcome back, {user['username']}!", "success")
            return redirect(url_for('encrypt_file'))
        else:
            flash("❌ Invalid email or password.", "danger")

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.pop('user', None)
    session.pop('user_password', None)
    flash("🔒 Logged out successfully.", "info")
    return redirect(url_for('index'))


@app.route('/encrypt', methods=['GET', 'POST'])
def encrypt_file():
    """Halaman utama untuk semua jenis enkripsi"""
    if 'user' not in session:
        flash("⚠️ Please login first!", "warning")
        return redirect(url_for('login'))

    active_tab = request.args.get('t', 'text')
    download_name = session.pop('download_file', None)
    return render_template('encrypt_form.html',
                           user=session.get('user'),
                           active_tab=active_tab,
                           download_name=download_name)

@app.route('/text_encrypt', methods=['POST'])
def text_encrypt():
    if 'user' not in session:
        flash("⚠️ Please login first!", "warning")
        return redirect(url_for('login'))

    text = request.form.get('text')
    key = request.form.get('key')
    action = request.form.get('action')

    if not text or not key:
        flash("❌ Text and key are required.", "danger")
        return redirect(url_for('encrypt_file'))

    if action == "encrypt":
        result = aes_encrypt_text(text, key)
        flash("✅ Text encrypted successfully!", "success")
    else:
        result = aes_decrypt_text(text, key)
        flash("🔓 Text decrypted successfully!", "info")

    return render_template("encrypt_form.html", 
                           user=session['user'], 
                           text_result=result,
                           active_tab="text")


@app.route('/file_encrypt', methods=['POST'])
def file_encrypt():
    """RSA Hybrid Encryption: file hanya bisa didekripsi oleh pemiliknya"""
    if 'user' not in session:
        flash("⚠️ Please login first!", "warning")
        return redirect(url_for('login'))

    file = request.files.get('file')
    action = request.form.get('action')
    if not file:
        flash("❌ Please upload a file.", "danger")
        return redirect(url_for('encrypt_file', t='file'))

    user_id = get_current_user_id()
    if not user_id:
        flash("❌ User tidak ditemukan.", "danger")
        return redirect(url_for('encrypt_file', t='file'))

    keys = get_user_keys(user_id)
    if not keys:
        flash("❌ RSA key untuk user ini belum tersedia.", "danger")
        return redirect(url_for('encrypt_file', t='file'))

    data = file.read()

    try:
        if action == 'encrypt':
            print(f"[DEBUG] 🔒 Encrypting file for user {user_id}")
            blob, fp_hex = rsa_hybrid_encrypt(data, keys['rsa_public_pem'])
            out_name = f"{file.filename}_encrypted.bin"
            save_path = os.path.join(UPLOAD_FOLDER, out_name)
            with open(save_path, "wb") as f:
                f.write(blob)

            save_file_record(user_id, file.filename, out_name, fp_hex)
            session['download_file'] = out_name
            flash(f"✅ File terenkripsi dengan fingerprint: {fp_hex[:16]}...", "success")

        elif action == 'decrypt':
            print(f"[DEBUG] 🔓 Attempting decryption for user {user_id}")
            enc_name = file.filename
            if not user_owns_encrypted_file(user_id, enc_name, data):
                flash("⛔ Kamu tidak berhak mendekripsi file ini.", "danger")
                print(f"[SECURITY] Unauthorized decrypt attempt by user {user_id}")
                return redirect(url_for('encrypt_file', t='file'))

            password = session.get('user_password')
            private_enc = keys['rsa_private_pem_enc']
            salt = keys['rsa_salt']
            private_pem = decrypt_private_key(private_enc, salt, password)
            if private_pem is None:
                flash("❌ Gagal mendekripsi private key. Password salah atau data kunci korup.", "danger")
                return redirect(url_for('encrypt_file', t='file'))
            plain = rsa_hybrid_decrypt(data, private_pem)

            out_name = enc_name.replace("_encrypted.bin", "")
            save_path = os.path.join(UPLOAD_FOLDER, out_name)
            with open(save_path, "wb") as f:
                f.write(plain)

            session['download_file'] = out_name
            flash(f"🔓 File berhasil didekripsi: {out_name}", "info")

        else:
            flash("❌ Invalid action.", "danger")

    except Exception as e:
        flash(f"❌ Error: {e}", "danger")
        print(f"[ERROR] file_encrypt: {e}")

    return redirect(url_for('encrypt_file', t='file'))


# === Steganografi ===
@app.route('/stegano', methods=['POST'])
def stegano_process():
    if 'user' not in session:
        flash("⚠️ Please login first!", "warning")
        return redirect(url_for('login'))

    action = request.form.get('action')
    video = request.files.get('video')
    message = request.form.get('message', '')

    print("==== STEGANO ====")
    print("Action:", action)
    print("Video:", video.filename if video else None)

    if action == 'hide':
        if not video or not message.strip():
            flash("❌ Upload video dan isi pesan yang ingin disembunyikan.", "danger")
            return redirect(url_for('encrypt_file', t='stegano'))

        ext = os.path.splitext(video.filename)[1]
        in_name = f"vid_in_{os.path.splitext(video.filename)[0]}{ext}"
        in_path = os.path.join(UPLOAD_FOLDER, in_name)
        video.save(in_path)

        info = hide_message_in_video(in_path, message.strip())
        out_name = os.path.basename(info['output'])
        session['download_file'] = out_name
        flash(f"✅ Pesan disisipkan ({info['embedded_bits']} bit) • Ready: {out_name}", "success")

        return redirect(url_for('encrypt_file', t='stegano'))

    elif action == 'extract':
        if not video:
            flash("❌ Upload video yang mengandung pesan tersembunyi.", "danger")
            return redirect(url_for('encrypt_file', t='stegano'))

        in_path = os.path.join(UPLOAD_FOLDER, f"vid_ext_{video.filename}")
        video.save(in_path)
        secret = extract_message_from_video(in_path)
        flash("🔎 Pesan berhasil diekstrak.", "info")
        return render_template('encrypt_form.html',
                               user=session.get('user'),
                               active_tab='stegano',
                               extracted_message=secret)

    flash("❌ Aksi tidak dikenal.", "danger")
    return redirect(url_for('encrypt_file', t='stegano'))


@app.route('/download/<path:filename>')
def download_file(filename):
    return send_from_directory(UPLOAD_FOLDER, filename, as_attachment=True)


if __name__ == '__main__':
    app.run(debug=True, use_reloader=False)
