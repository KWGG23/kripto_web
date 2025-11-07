# config.py
import mysql.connector

def get_db_connection():
    return mysql.connector.connect(
        host='localhost',
        user='root',
        password='',  # isi kalau ada password MySQL kamu
        database='website_kripto'
    )
