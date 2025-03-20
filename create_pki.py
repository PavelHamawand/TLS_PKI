import os
import subprocess
import stat


# Define new base directory and subdirectories for the second setup
BASE_DIR = os.path.abspath("PKI")
CA_DIR = os.path.join(BASE_DIR, "ca_certs")
SERVER_DIR = os.path.join(BASE_DIR, "server_certs")
CLIENT_DIR = os.path.join(BASE_DIR, "client_certs")

# Create directories if they do not already exist
os.makedirs(CA_DIR, exist_ok=True)
os.makedirs(SERVER_DIR, exist_ok=True)
os.makedirs(CLIENT_DIR, exist_ok=True)

def generate_root_ca():
    # Generate the RSA key for the CA with AES-128 encryption
    subprocess.run(["openssl", "genrsa", "-aes128", "-out", os.path.join(CA_DIR, "rootCA.key"), "2048"], check=True)
    
    # Create the CSR (Certificate Signing Request) for the CA
    subprocess.run([
        "openssl", "req", "-new", "-key", os.path.join(CA_DIR, "rootCA.key"),
        "-out", os.path.join(CA_DIR, "rootCA.csr"),
        "-subj", "/C=SE/ST=Scania/L=Lund/O=LU/OU=Education/CN=Demo CA 2/emailAddress=ca2@demoland.se"
    ], check=True)
    
    # Create an extension file for the CA certificate
    ext_file = os.path.join(CA_DIR, "rootCA.ext")
    with open(ext_file, "w") as f:
        f.write("""
basicConstraints = critical,CA:TRUE
keyUsage = critical, digitalSignature, keyCertSign, cRLSign
subjectKeyIdentifier = hash
""")
    
    # Self-sign the CSR to create the CA certificate
    subprocess.run([
        "openssl", "x509", "-req", "-in", os.path.join(CA_DIR, "rootCA.csr"),
        "-signkey", os.path.join(CA_DIR, "rootCA.key"),
        "-days", "3650",
        "-out", os.path.join(CA_DIR, "rootCA.pem"),
        "-extfile", ext_file,
        "-sha256"
    ], check=True)
    
    print("Root CA (2) created successfully!")

def generate_server_cert():
    # Generate the server's RSA key
    subprocess.run([
        "openssl", "genpkey", "-aes128", "-algorithm", "RSA", 
        "-out", os.path.join(SERVER_DIR, "server_key.pem"),
        "-pkeyopt", "rsa_keygen_bits:2048"
    ], check=True)
    
    # Create the server's CSR
    subprocess.run([
        "openssl", "req", "-new", "-key", os.path.join(SERVER_DIR, "server_key.pem"),
        "-out", os.path.join(SERVER_DIR, "server_csr.pem"),
        "-subj", "/C=SE/ST=Scania/L=Lund/O=LU/OU=Education/CN=server2.demoland.se/emailAddress=server2@demoland.se"
    ], check=True)
    
    # Create an extension file for the server certificate
    ext_file = os.path.join(SERVER_DIR, "server_v3.txt")
    with open(ext_file, "w") as f:
        f.write("""
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = keyAgreement, keyEncipherment, digitalSignature
subjectAltName = @alt_names
[alt_names]
DNS.1 = localhost
""")
    
    # Sign the server CSR using the new CA to generate the server certificate
    subprocess.run([
        "openssl", "x509", "-req", "-CA", os.path.join(CA_DIR, "rootCA.pem"),
        "-CAkey", os.path.join(CA_DIR, "rootCA.key"), "-in", os.path.join(SERVER_DIR, "server_csr.pem"),
        "-out", os.path.join(SERVER_DIR, "server_cert.pem"),
        "-days", "365", "-extfile", ext_file, "-set_serial", "1"
    ], check=True)
    
    # Create a new PKCS12 file for the server that does NOT include the CA certificate.
    subprocess.run([
    "openssl", "pkcs12", "-export", "-out", os.path.join(SERVER_DIR, "server2.p12"),
    "-inkey", os.path.join(SERVER_DIR, "server_key.pem"),
    "-in", os.path.join(SERVER_DIR, "server_cert.pem"),
    "-certfile", os.path.join(CA_DIR, "rootCA.pem")  # Lägg till CA-certifikatet
    ], check=True)
    
    print("Server certificate and PKCS12 (without CA cert) generated successfully!")

def generate_client_cert():
    # Generate the client's RSA key
    subprocess.run([
        "openssl", "genpkey", "-aes128", "-algorithm", "RSA", 
        "-out", os.path.join(CLIENT_DIR, "client_key.pem"),
        "-pkeyopt", "rsa_keygen_bits:2048"
    ], check=True)
    
    # Create the client's CSR
    subprocess.run([
        "openssl", "req", "-new", "-key", os.path.join(CLIENT_DIR, "client_key.pem"),
        "-out", os.path.join(CLIENT_DIR, "client_csr.pem"),
        "-subj", "/C=SE/ST=Scania/L=Lund/O=LU/OU=Education/CN=client2.demoland.se/emailAddress=client2@demoland.se"
    ], check=True)
    
    # Create an extension file for the client certificate
    ext_file = os.path.join(CLIENT_DIR, "client_v3.txt")
    with open(ext_file, "w") as f:
        f.write("""
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, dataEncipherment
subjectAltName = @alt_names
[alt_names]
DNS.1 = localhost
""")
    
    # Sign the client CSR using the new CA to generate the client certificate
    subprocess.run([
        "openssl", "x509", "-req", "-CA", os.path.join(CA_DIR, "rootCA.pem"),
        "-CAkey", os.path.join(CA_DIR, "rootCA.key"), "-in", os.path.join(CLIENT_DIR, "client_csr.pem"),
        "-out", os.path.join(CLIENT_DIR, "client_cert.pem"),
        "-days", "365", "-extfile", ext_file, "-set_serial", "2"
    ], check=True)
    
    # Create a PKCS12 file for the client (includes the CA certificate as before)
    subprocess.run([
        "openssl", "pkcs12", "-export", "-out", os.path.join(CLIENT_DIR, "client2.p12"),
        "-inkey", os.path.join(CLIENT_DIR, "client_key.pem"),
        "-in", os.path.join(CLIENT_DIR, "client_cert.pem"),
        "-certfile", os.path.join(CA_DIR, "rootCA.pem")
    ], check=True)
    
    print("Client certificate and PKCS12 generated successfully!")

def set_permissions():
    # Set directory permissions
    os.chmod(CA_DIR, stat.S_IRWXU)
    os.chmod(SERVER_DIR, stat.S_IRWXU)
    os.chmod(CLIENT_DIR, stat.S_IRWXU)
    
    # Set file permissions for the CA
    os.chmod(os.path.join(CA_DIR, "rootCA.key"), stat.S_IRUSR | stat.S_IWUSR)
    os.chmod(os.path.join(CA_DIR, "rootCA.pem"), stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
    
    # Set file permissions for the server
    os.chmod(os.path.join(SERVER_DIR, "server_key.pem"), stat.S_IRUSR | stat.S_IWUSR)
    os.chmod(os.path.join(SERVER_DIR, "server_cert.pem"), stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
    
    # Set file permissions for the client
    os.chmod(os.path.join(CLIENT_DIR, "client_key.pem"), stat.S_IRUSR | stat.S_IWUSR)
    os.chmod(os.path.join(CLIENT_DIR, "client_cert.pem"), stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)

if __name__ == "__main__":
    generate_root_ca()
    generate_server_cert()
    generate_client_cert()
    set_permissions()
    print("All new certificates and keys generated in 'pki_setup2' successfully!")