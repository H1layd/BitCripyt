import sqlite3
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

def encrypt_aes(plaintext, key):
    iv = os.urandom(16)
    key = base64.b64decode(key)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_plaintext = plaintext + (16 - len(plaintext) % 16) * chr(16 - len(plaintext) % 16)
    encrypted_data = iv + encryptor.update(padded_plaintext.encode()) + encryptor.finalize()
    return base64.b64encode(encrypted_data).decode('utf-8')

def create_encrypted_database(db_name, key):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS your_table (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            encrypted_column TEXT NOT NULL
        )
    ''')
    data_to_encrypt = ["password1", "password2", "password3"]
    for data in data_to_encrypt:
        encrypted_data = encrypt_aes(data, key)
        cursor.execute("INSERT INTO your_table (encrypted_column) VALUES (?)", (encrypted_data,))
    conn.commit()
    conn.close()
    print(f"База данных '{db_name}' успешно создана с зашифрованными данными.")

if __name__ == "__main__":
    key = base64.b64encode(os.urandom(32)).decode('utf-8')
    print(f"Используемый ключ: {key}")
    create_encrypted_database("encrypted_database.db", key)
