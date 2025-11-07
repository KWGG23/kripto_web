from flask import Flask, render_template, request, redirect, url_for, flash, session
from modules.auth import register_user, login_user, decrypt_private_key
from modules.crypto import aes_encrypt, aes_decrypt, aes_encrypt_text, aes_decrypt_text, rsa_encrypt_file, rsa_decrypt_file, generate_rsa_keys, hide_message_in_video, extract_message_from_video
from flask import send_from_directory
from config import get_db_connection
import hashlib
import sys
import os


sys.stdout.reconfigure(line_buffering=True)
app = Flask(__name__)
app.secret_key = "super_secret_key"

UPLOAD_FOLDER = 'static/uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def get_current_user_id():
    conn = get_db_connection()
    cur  = conn.cursor(dictionary=True)
    cur.execute("SELECT user_id FROM users WHERE username=%s", (session['user'],))
    row = cur.fetchone()
    cur.close(); conn.close()
    return row['user_id'] if row else None

def get_user_keys(user_id: int):
    conn = get_db_connection()
    cur  = conn.cursor(dictionary=True)
    cur.execute("""
        SELECT rsa_public_pem, rsa_private_pem_enc, rsa_salt
        FROM user_keys WHERE user_id = %s LIMIT 1
    """, (user_id,))
    row = cur.fetchone()
    cur.close(); conn.close()
    return row

def save_file_record(user_id: int, original_name: str, encrypted_name: str, fingerprint_hex: str, encrypted_data: bytes):
    """Catat metadata untuk kontrol kepemilikan: pakai fingerprint & hash isi file."""
    file_hash = hashlib.sha256(encrypted_data).hexdigest()
    conn = get_db_connection()
    cur  = conn.cursor()
    cur.execute("""
        INSERT INTO files (user_id, original_filename, encrypted_filename, fingerprint, file_hash)
        VALUES (%s, %s, %s, %s, %s)
    """, (user_id, original_name, encrypted_name, fingerprint_hex, file_hash))
    conn.commit()
    cur.close(); conn.close()

def user_owns_encrypted_file(user_id: int, enc_name: str, encrypted_data: bytes) -> bool:
    """
    Validasi kepemilikan:
      1) Baca fingerprint file (32 byte pertama → hexdigest)
      2) Hash isi file (untuk cegah rename attack)
      3) Cocokkan dengan record di DB untuk user_id & nama file
    """
    # fingerprint di HEADER file (32 bytes) → samakan format dengan kolom DB (hexdigest)
    header_fp_hex = encrypted_data[:32].hex()
    file_hash = hashlib.sha256(encrypted_data).hexdigest()

    conn = get_db_connection()
    cur  = conn.cursor()
    cur.execute("""
        SELECT 1 FROM files
        WHERE user_id=%s AND encrypted_filename=%s AND fingerprint=%s AND file_hash=%s
        LIMIT 1
    """, (user_id, enc_name, header_fp_hex, file_hash))
    ok = cur.fetchone() is not None
    cur.close(); conn.close()
    return ok

@app.route('/')
def index():
    if 'user' in session:
        return render_template('dashboard.html', user=session['user'])
    return render_template('index.html')

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        email    = request.form['email'].strip()
        password = request.form['password']
        if register_user(username, email, password):
            flash("✅ Registration successful! Please login.", "success")
            return redirect(url_for('login'))
        else:
            flash("❌ Email already registered or database error.", "danger")
    return render_template('register.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        email    = request.form['email']
        password = request.form['password']
        user = login_user(email, password)
        if user:
            session['user'] = user['username']
            # simpan password plaintext hanya di session ( diperlukan utk decrypt private key )
            session['user_password'] = password
            flash(f"✅ Welcome back, {user['username']}!", "success")
            return redirect(url_for('encrypt_file'))
        flash("❌ Invalid email or password.", "danger")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    session.pop('user_password', None)
    flash("🔒 Logged out successfully.", "info")
    return redirect(url_for('index'))


@app.route('/encrypt', methods=['GET','POST'])
def encrypt_file():
    if 'user' not in session:
        flash("⚠️ Please login first!", "warning")
        return redirect(url_for('login'))

    active_tab    = request.args.get('t', 'text')
    download_name = session.pop('download_file', None)

    if request.method == 'POST':
        file = request.files.get('file')
        key  = request.form.get('key', '').encode()
        if not file or not key:
            flash("❌ Please provide both a file and a key.", "danger")
            return redirect(url_for('encrypt_file', t='file'))

        try:
            raw = file.read()
            ext = os.path.splitext(file.filename)[1]
            enc, fhash = aes_encrypt(raw, key, ext)

            out_name = f"{os.path.splitext(file.filename)[0]}_encrypted.bin"
            save_path = os.path.join(UPLOAD_FOLDER, out_name)
            with open(save_path, "wb") as f:
                f.write(enc)

            session['download_file'] = out_name
            flash(f"✅ File encrypted successfully! Hash: {fhash[:16]}...", "success")
            return redirect(url_for('encrypt_file', t='file'))
        except Exception as e:
            flash(f"❌ Encryption failed: {e}", "danger")
            return redirect(url_for('encrypt_file', t='file'))

    return render_template('encrypt_form.html',
                           user=session.get('user'),
                           active_tab=active_tab,
                           download_name=download_name)

@app.route('/decrypt', methods=['POST'])
def decrypt_file():
    if 'user' not in session:
        flash("⚠️ Please login first!", "warning")
        return redirect(url_for('login'))

    file = request.files.get('file')
    key  = request.form.get('key', '').encode()
    if not file or not key:
        flash("❌ Please provide both a file and a key.", "danger")
        return redirect(url_for('encrypt_file', t='file'))

    try:
        enc = file.read()
        dec, ext = aes_decrypt(enc, key)

        base = os.path.splitext(file.filename)[0]
        if base.endswith("_encrypted"):
            base = base.replace("_encrypted", "")
        out_name = f"{base}_decrypted{ext}"
        save_path = os.path.join(UPLOAD_FOLDER, out_name)
        with open(save_path, "wb") as f:
            f.write(dec)

        session['download_file'] = out_name
        flash(f"✅ File berhasil didekripsi: {out_name}", "success")
        return redirect(url_for('encrypt_file', t='file'))
    except Exception as e:
        flash(f"❌ Error during decryption: {e}", "danger")
        return redirect(url_for('encrypt_file', t='file'))



@app.route('/text_encrypt', methods=['POST'])
def text_encrypt():
    if 'user' not in session:
        flash("⚠️ Please login first!", "warning")
        return redirect(url_for('login'))

    text   = request.form.get('text')
    key    = request.form.get('key')
    action = request.form.get('action')
    if not text or not key:
        flash("❌ Text and key are required.", "danger")
        return redirect(url_for('encrypt_file', t='text'))

    if action == 'encrypt':
        result = aes_encrypt_text(text, key)
        flash("✅ Text encrypted successfully!", "success")
    else:
        result = aes_decrypt_text(text, key)
        flash("🔓 Text decrypted successfully!", "info")

    return render_template("encrypt_form.html",
                           user=session['user'],
                           text_result=result,
                           active_tab="text")

@app.route('/download/<path:filename>')
def download_file(filename):
    return send_from_directory(UPLOAD_FOLDER, filename, as_attachment=True)



@app.route('/file_encrypt', methods=['POST'], endpoint='file_encrypt')
def file_encrypt_rsa():
    """Enkripsi/Dekripsi file berbasis RSA+AES Hybrid (terikat user lewat fingerprint)."""
    if 'user' not in session:
        flash("⚠️ Please login first!", "warning")
        return redirect(url_for('login'))

    file   = request.files.get('file')
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
            # Enkripsi pakai public key user + dapatkan fingerprint
            public_pem = keys['rsa_public_pem']
            enc_blob, fp_hex = rsa_encrypt_file(data, public_pem)

            out_name  = f"{file.filename}_encrypted.bin"
            save_path = os.path.join(UPLOAD_FOLDER, out_name)
            with open(save_path, "wb") as f:
                f.write(enc_blob)

            # Simpan metadata ownership
            save_file_record(user_id, file.filename, out_name, fp_hex, enc_blob)

            session['download_file'] = out_name
            flash(f"✅ File terenkripsi: {out_name}", "success")
            return redirect(url_for('encrypt_file', t='file'))

        elif action == 'decrypt':
            # Validasi kepemilikan (DB vs header fingerprint + hash isi)
            enc_name = file.filename
            if not user_owns_encrypted_file(user_id, enc_name, data):
                flash("⛔ Kamu tidak berhak mendekripsi file ini.", "danger")
                return redirect(url_for('encrypt_file', t='file'))

            # Dekripsi private key milik user dari DB
            password = session.get('user_password')
            if not password:
                flash("⚠️ Silakan login ulang untuk mendekripsi private key.", "warning")
                return redirect(url_for('login'))

            private_enc = keys['rsa_private_pem_enc']
            salt        = keys['rsa_salt']
            private_pem = decrypt_private_key(private_enc, salt, password)
            if private_pem is None:
                flash("❌ Gagal mendekripsi private key user.", "danger")
                return redirect(url_for('encrypt_file', t='file'))

            # Dekripsi file
            dec_bytes = rsa_decrypt_file(data, private_pem)

            out_name  = enc_name.replace("_encrypted.bin", "_decrypted.bin")
            save_path = os.path.join(UPLOAD_FOLDER, out_name)
            with open(save_path, "wb") as f:
                f.write(dec_bytes)

            session['download_file'] = out_name
            flash(f"🔓 File berhasil didekripsi: {out_name}", "info")
            return redirect(url_for('encrypt_file', t='file'))

        else:
            flash("❌ Invalid action.", "danger")
            return redirect(url_for('encrypt_file', t='file'))

    except ValueError as ve:
        flash(f"❌ Key tidak cocok: {ve}", "danger")
        return redirect(url_for('encrypt_file', t='file'))
    except Exception as e:
        flash(f"❌ Terjadi kesalahan: {e}", "danger")
        return redirect(url_for('encrypt_file', t='file'))


@app.route('/stegano', methods=['POST'])
def stegano_process():
    if 'user' not in session:
        flash("⚠️ Please login first!", "warning")
        return redirect(url_for('login'))

    action = request.form.get('action')
    video = request.files.get('video')
    message = request.form.get('message', '')

    # Debug awal
    print("==== STEGANO REQUEST ====")
    print("Action:", action)
    print("Video:", video.filename if video else None)
    print("Message:", message.strip()[:50])
    print("=========================")

    if action == 'hide':
        if not video or not message.strip():
            flash("❌ Upload video dan isi pesan yang ingin disembunyikan.", "danger")
            return redirect(url_for('encrypt_file', t='stegano'))

        # Simpan video input
        ext = os.path.splitext(video.filename)[1]
        in_name = f"vid_in_{os.path.splitext(video.filename)[0]}{ext}"
        in_path = os.path.join(UPLOAD_FOLDER, in_name)
        video.save(in_path)

        try:
            info = hide_message_in_video(in_path, message.strip())

            # Debug terminal
            print("=== DEBUG STEGANO ===")
            print("Input video :", in_path)
            print("Output video:", info.get("output"))
            print("Embedded bits:", info.get("embedded_bits"))
            print("=====================")

            # Ambil nama file hasil output
            out_name = os.path.basename(info['output'])
            session['download_file'] = out_name

            flash(f"✅ Pesan disisipkan ({info['embedded_bits']} bit) • Ready: {out_name}", "success")

        except Exception as e:
            print("❌ ERROR hide_message_in_video:", str(e))
            flash(f"❌ Gagal menyisipkan pesan: {e}", "danger")

        return redirect(url_for('encrypt_file', t='stegano'))

    elif action == 'extract':
        if not video:
            flash("❌ Upload video yang mengandung pesan tersembunyi.", "danger")
            return redirect(url_for('encrypt_file', t='stegano'))

        in_name = f"vid_ext_{video.filename}"
        in_path = os.path.join(UPLOAD_FOLDER, in_name)
        video.save(in_path)

        try:
            secret = extract_message_from_video(in_path)
            flash("🔎 Pesan berhasil diekstrak.", "info")
            return render_template(
                'encrypt_form.html',
                user=session.get('user'),
                active_tab='stegano',
                extracted_message=secret
            )
        except Exception as e:
            print("❌ ERROR extract_message_from_video:", str(e))
            flash(f"❌ Gagal mengekstrak pesan: {e}", "danger")
            return redirect(url_for('encrypt_file', t='stegano'))

    else:
        flash("❌ Aksi tidak dikenal.", "danger")
        return redirect(url_for('encrypt_file', t='stegano'))

if __name__ == '__main__':
    app.run(debug=True, use_reloader=False)
