from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from urllib.parse import urlparse
import base64
import json
import sqlite3
import os
import time #time implementation
import uuid
from argon2 import PasswordHasher  

# Initialize the password hasher
ph = PasswordHasher()

# Global Variables
AES_KEY = os.environ.get('NOT_MY_KEY')  # Set your environment variable before running
if AES_KEY is None:
    raise ValueError("Environment variable NOT_MY_KEY is not set.")

DATABASE_FILE = "totally_not_my_privateKeys.db"

# Simple rate limiter
rate_limit = {
    'last_request_time': 0,
    'request_count': 0
}
def rate_limiter():
    """Limit to 10 requests per second."""
    current_time = int(time.time())
    if current_time - rate_limit['last_request_time'] >= 1:
        rate_limit['last_request_time'] = current_time
        rate_limit['request_count'] = 0

    rate_limit['request_count'] += 1
    if rate_limit['request_count'] > 10:
        return False
    return True


def generate_password():
    """Generate a secure random UUID as a password."""
    return str(uuid.uuid4())


def hash_password(password):
    """Hash the password using Argon2."""
    return ph.hash(password)


def encrypt_data(plaintext: bytes, key: str) -> str:
    """Encrypts plaintext using AES and returns the base64."""
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(key.encode('utf-8')), modes.GCM(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return base64.b64encode(iv + encryptor.tag + ciphertext).decode('utf-8')


def decrypt_data(encrypted_data: str, key: str) -> bytes:
    """Decrypts encrypted base64-encoded text and returns the original plaintext."""
    encrypted_bytes = base64.b64decode(encrypted_data)
    iv = encrypted_bytes[:12]
    tag = encrypted_bytes[12:28]
    ciphertext = encrypted_bytes[28:]
    cipher = Cipher(algorithms.AES(key.encode('utf-8')), modes.GCM(iv, tag))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def initialize_database():
    """Creates the necessary tables for the application."""
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    try:
        # Create users table
        cursor.execute('''
           CREATE TABLE IF NOT EXISTS users(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                email TEXT UNIQUE,
                date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP  
            )
        ''')
        # Create auth_logs table
        cursor.execute('''
               CREATE TABLE IF NOT EXISTS auth_logs(
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   request_ip TEXT NOT NULL,
                   request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                   user_id INTEGER,
                   FOREIGN KEY(user_id) REFERENCES users(id)
               )
        ''')
        # Create keys table
        cursor.execute('''
          CREATE TABLE IF NOT EXISTS keys(
    kid TEXT PRIMARY KEY,
    key TEXT NOT NULL,
    exp INTEGER NOT NULL
);
        ''')
        conn.commit()
        print("Database tables initialized successfully.")
    except sqlite3.Error as e:
        print(f"Error initializing database: {e}")
    finally:
        conn.close()


def insert_private_key(kid, pem_key, exp_time):
    """Encrypt and insert a new private key into the database."""
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    encrypted_key = encrypt_data(pem_key, AES_KEY)  # Encrypt the key
    cursor.execute('''
        INSERT INTO keys (kid, key, exp) VALUES (?, ?, ?)
    ''', (int(kid), encrypted_key, int(exp_time.timestamp())))
    conn.commit()
    conn.close()


class MyServer(BaseHTTPRequestHandler):
    def do_POST(self):
        global conn
        parsed_path = urlparse(self.path)
        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length).decode("utf-8")
        data = json.loads(post_data)

        if parsed_path.path == "/register":
            username = data.get("username") #username data
            email = data.get("email")# email data

            # Check for missing required fields
            if not username or not email:
                self.send_response(400)  # Bad Request
                self.end_headers() #end
                self.wfile.write(b"Missing required fields (username, email)") #missing required fields
                return

            # Generate password and hash it
            password = generate_password()
            password_hash = hash_password(password)
            try:
                # Connect to the database
                conn = sqlite3.connect(DATABASE_FILE)
                cursor = conn.cursor()

                # Insert the new user into the users table
                cursor.execute('''
                    INSERT INTO users (username, password_hash, email)
                    VALUES (?, ?, ?)
                ''', (username, password_hash, email))
                conn.commit()

            except sqlite3.IntegrityError:
                # Handle duplicate username or email
                self.send_response(409)  # Conflict
                self.end_headers()
                self.wfile.write(b"Username or email already exists")
                return

            except sqlite3.Error as e:
                # Handle general database errors
                self.send_response(500)  # Internal Server Error
                self.end_headers()
                self.wfile.write(f"Database error: {str(e)}".encode("utf-8"))
                return

            finally:
                # Ensure the connection is always closed
                if conn:
                    conn.close()

            # Send success response with the generated password
            self.send_response(201)  # Created
            self.send_header("Content-Type", "application/json") #send this header
            self.end_headers()#end headers
            self.wfile.write(json.dumps({"password": password}).encode("utf-8"))#dumps
        else:
            # Handle unsupported paths
            self.send_response(200)#Not Found
            self.end_headers()
            self.wfile.write(b"Endpoint not found")#if endpoint is not found send this response
    def do_GET(self):
        if self.path == "/.well-known/jwks.json":#path
            self.send_response(200)#reponse
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(json.dumps({"keys": []}), "utf-8"))
        else:
            self.send_response(405)#response
            self.end_headers()

if __name__ == "__main__":
    initialize_database()  # Ensures tables are created
    webServer = HTTPServer(("localhost", 8080), MyServer)
    try:
        print("Server started at http://localhost:8080")
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass
    webServer.server_close()
    print("Server stopped.")
