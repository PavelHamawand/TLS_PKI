import os
import ssl
import socket
import tempfile
import threading
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates

# Konfiguration
SERVER_ADDRESS = 'localhost'
SERVER_PORT = 8043
PKCS12_PATH = 'PKI/server_certs/server2.p12'  # Uppdatera sökvägen
PKCS12_PASSWORD = 'server'


def start_tls_server(address, port, pkcs12_path, pkcs12_password):
    cert_path, key_path, ca_path = None, None, None
    try:
        p12_password_bytes = pkcs12_password.encode('utf-8')
        with open(pkcs12_path, 'rb') as f:
            private_key, certificate, additional_certificates = load_key_and_certificates(f.read(), p12_password_bytes)
        
        # Extract the private key and certificate in PEM format
        server_key = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        server_cert = certificate.public_bytes(serialization.Encoding.PEM)
        ca_cert = additional_certificates[0].public_bytes(serialization.Encoding.PEM) if additional_certificates else None
        
        # Create a temporary file for the server certificate and key
        with (tempfile.NamedTemporaryFile(delete=False) as cert_file,
              tempfile.NamedTemporaryFile(delete=False) as key_file,
              tempfile.NamedTemporaryFile(delete=False) as ca_file):
            cert_file.write(server_cert)
            cert_path = cert_file.name
            key_file.write(server_key)
            key_path = key_file.name
            # Load the CA certificate for client authentication, when needed
            if ca_cert:
                ca_file.write(ca_cert)
                ca_path = ca_file.name

        # Create an SSL context
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile=cert_path, keyfile=key_path)
        if ca_cert:
            context.load_verify_locations(cafile=ca_path)
        else:
            raise RuntimeError("CA certificate not found")
        
        
        context.verify_mode = ssl.CERT_NONE
        
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
            sock.bind((address, port))
            sock.listen(1)
            print(f"Server listening on {address}:{port}")
            with context.wrap_socket(sock, server_side=True) as ssock:
                conn, addr = ssock.accept()
                with conn:
                    print(f"Connected by {addr}")
                    while True:
                        data = conn.recv(1024)
                        if not data:
                            break
                        message = data.decode()
                        print(f"Received message: {message}")
                        conn.sendall(data)  # Echoing back the received message
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        # Clean up the temporary files
        for path in [cert_path, key_path, ca_path]:
            if path and os.path.exists(path):
                try:
                    os.remove(path)
                except Exception as e:
                    print(f"Error deleting temporary file {path}: {e}")

def run_server():
    start_tls_server(SERVER_ADDRESS, SERVER_PORT, PKCS12_PATH, PKCS12_PASSWORD)

# Run the server in a background thread
thread = threading.Thread(target=run_server, daemon=True)
thread.start()
thread.join()