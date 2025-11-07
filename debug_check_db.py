from config import get_db_connection

conn = get_db_connection()
cur = conn.cursor(dictionary=True)
cur.execute("SELECT user_id, email, password_hash, salt FROM users LIMIT 5")
rows = cur.fetchall()
for r in rows:
    print("user_id:", r['user_id'], "email:", r['email'])
    print(" password_hash type:", type(r['password_hash']), " len:", len(r['password_hash']) if r['password_hash'] else None)
    print(" salt type:", type(r['salt']), " len:", len(r['salt']) if r['salt'] else None)
    print("----")
cur.close()
conn.close()

