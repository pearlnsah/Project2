from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime
import sqlite3

hostName = "localhost"
serverPort = 8080

# Function to initialize the SQLite database
def init_db():
    conn = sqlite3.connect('totally_not_my_privateKeys.db')
    c = conn.cursor()
    c.execute('''
    CREATE TABLE IF NOT EXISTS keys (
        kid INTEGER PRIMARY KEY AUTOINCREMENT,
        key BLOB NOT NULL,
        exp INTEGER NOT NULL
    )
    ''')
    conn.commit()
    conn.close()

# Function to save a key into the SQLite database
def save_key(pem, exp):
    conn = sqlite3.connect('totally_not_my_privateKeys.db')
    c = conn.cursor()
    c.execute('INSERT INTO keys (key, exp) VALUES (?, ?)', (pem, exp))
    conn.commit()
    conn.close()

# Generate RSA keys
def generate_rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    expired_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    expired_pem = expired_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    now = int(datetime.datetime.now().timestamp())
    # Save keys with expiration times
    save_key(pem, now + 3600)  # Valid for 1 hour
    save_key(expired_pem, now - 3600)  # Expired 1 hour ago

# Utility function to convert integers to Base64URL
def int_to_base64(value):
    value_hex = format(value, 'x')
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')

class MyServer(BaseHTTPRequestHandler):
    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)
        if parsed_path.path == "/auth":
            conn = sqlite3.connect('totally_not_my_privateKeys.db')
            c = conn.cursor()
            now = int(datetime.datetime.now().timestamp())
            if 'expired' in params:
                c.execute('SELECT key FROM keys WHERE exp <= ? ORDER BY exp DESC LIMIT 1', (now,))
            else:
                c.execute('SELECT key FROM keys WHERE exp > ? ORDER BY exp ASC LIMIT 1', (now,))
            key_row = c.fetchone()
            conn.close()

            if key_row:
                key_pem = key_row[0]
                headers = {"kid": "expiredKID" if 'expired' in params else "goodKID"}
                token_payload = {
                    "user": "username",
                    "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=-1 if 'expired' in params else 1)
                }
                encoded_jwt = jwt.encode(token_payload, key_pem, algorithm="RS256", headers=headers)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(bytes(encoded_jwt, "utf-8"))
            else:
                self.send_response(404, "Key not found")
                self.end_headers()
            return

        self.send_response(405)
        self.end_headers()

    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            conn = sqlite3.connect('totally_not_my_privateKeys.db')
            c = conn.cursor()
            now = int(datetime.datetime.now().timestamp())
            c.execute('SELECT key, kid FROM keys WHERE exp > ?', (now,))
            keys_info = c.fetchall()
            conn.close()

            jwks = {"keys": []}
            for key_pem, kid in keys_info:
                private_key = serialization.load_pem_private_key(key_pem, password=None)
                numbers = private_key.private_numbers()
                jwks["keys"].append({
                    "alg": "RS256",
                    "kty": "RSA",
                    "use": "sig",
                    "kid": str(kid),
                    "n": int_to_base64(numbers.public_numbers.n),
                    "e": int_to_base64(numbers.public_numbers.e),
                })

            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(json.dumps(jwks), "utf-8"))
            return

        self.send_response(405)
        self.end_headers()

# Main setup and server start
if __name__ == "__main__":
    init_db()  # Initialize the database and create the table
    generate_rsa_keys()  # Generate and save RSA keys

    webServer = HTTPServer((hostName, serverPort), MyServer)
    print(f"Server started http://{hostName}:{serverPort}")

    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        webServer.server_close()
        print("Server stopped.")
