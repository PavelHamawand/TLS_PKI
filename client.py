import os
import ssl
import socket
import tempfile
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates

# Konfiguration
SERVER_ADDRESS = 'localhost'
SERVER_PORT = 8043
PKCS12_PATH = 'PKI/client_certs/client2.p12'  # Uppdatera sökvägen
PKCS12_PASSWORD = 'client'

def start_tls_client(server_address, port, pkcs12_path, pkcs12_password):
    cert_path, key_path, ca_path = None, None, None
    try:
        p12_password_bytes = pkcs12_password.encode('utf-8')
        with open(pkcs12_path, 'rb') as f:
            private_key, certificate, additional_certificates = load_key_and_certificates(f.read(), p12_password_bytes)

        # Extrahera klientens certifikat i PEM-format
        client_cert = certificate.public_bytes(serialization.Encoding.PEM)
        ca_cert = additional_certificates[0].public_bytes(serialization.Encoding.PEM) if additional_certificates else None

        # Skapa temporära filer för certifikat och nycklar
        with (tempfile.NamedTemporaryFile(delete=False) as cert_file,
              tempfile.NamedTemporaryFile(delete=False) as key_file,
              tempfile.NamedTemporaryFile(delete=False) as ca_file):
            cert_file.write(client_cert)
            cert_path = cert_file.name
            key_file.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
            key_path = key_file.name
            if ca_cert:
                ca_file.write(ca_cert)
                ca_path = ca_file.name

        # Skapa en SSL-kontext för klienten
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        
        context.load_cert_chain(certfile=cert_path, keyfile=key_path)
        if ca_cert:
            context.load_verify_locations(cafile=ca_path)
        else:
            raise RuntimeError("CA-certifikat saknas")
        
        
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True
        received_messages = []

        with socket.create_connection((server_address, port)) as sock:
            with context.wrap_socket(sock, server_hostname=server_address) as ssock:
                print("Klienten ansluten till servern")
                while True:
                    message = input("Ange meddelande att skicka (eller 'exit' för att avsluta): ")
                    if message.lower() == 'exit':
                        break
                    ssock.sendall(message.encode())
                    response = ssock.recv(1024)
                    received_messages.append(response.decode())

        print("Mottagna meddelanden under sessionen:")
        for msg in received_messages:
            print(msg)

    except Exception as e:
        print(f"Ett fel uppstod: {e}")

    finally:
        for path in [cert_path, key_path, ca_path]:
            if path and os.path.exists(path):
                try:
                    os.remove(path)
                except Exception as e:
                    print(f"Fel vid borttagning av temporär fil {path}: {e}")

start_tls_client(SERVER_ADDRESS, SERVER_PORT, PKCS12_PATH, PKCS12_PASSWORD)