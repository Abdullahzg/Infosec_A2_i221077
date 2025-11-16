"""
Certificate Issuance Script
Issues CA-signed X.509 certificates for entities (server or client) in the Secure Chat System.

This script:
- Accepts entity name as command-line argument (e.g., "server" or "client")
- Loads CA private key and certificate from certs/
- Generates a 2048-bit RSA keypair for the entity
- Creates an X.509 certificate signing request (CSR)
- Signs the CSR with the CA private key
- Saves entity private key and certificate to certs/

Usage:
    python scripts/gen_cert.py server
    python scripts/gen_cert.py client
"""

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import datetime
import sys
import os


def load_ca_key(ca_key_path):
    """
    Load CA private key from PEM file.
    
    Args:
        ca_key_path: Path to CA private key file
        
    Returns:
        RSA private key object
    """
    with open(ca_key_path, 'rb') as f:
        ca_private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )
    return ca_private_key


def load_ca_cert(ca_cert_path):
    """
    Load CA certificate from PEM file.
    
    Args:
        ca_cert_path: Path to CA certificate file
        
    Returns:
        X.509 certificate object
    """
    with open(ca_cert_path, 'rb') as f:
        ca_cert = x509.load_pem_x509_certificate(
            f.read(),
            backend=default_backend()
        )
    return ca_cert


def generate_entity_certificate(entity_name, ca_private_key, ca_cert):
    """
    Generate an RSA keypair and CA-signed certificate for an entity.
    
    Args:
        entity_name: Name of the entity (e.g., "server" or "client")
        ca_private_key: CA's RSA private key
        ca_cert: CA's X.509 certificate
        
    Returns:
        Tuple of (entity_private_key, entity_certificate)
    """
    print(f"Generating {entity_name} private key...")
    
    # Generate 2048-bit RSA keypair for entity
    entity_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    print(f"Creating certificate signing request (CSR) for {entity_name}...")
    
    # Create subject for the entity
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"SecureChat"),
        x509.NameAttribute(NameOID.COMMON_NAME, f"SecureChat {entity_name.capitalize()}"),
    ])
    
    # Get issuer from CA certificate
    issuer = ca_cert.subject
    
    print(f"Signing {entity_name} certificate with CA private key...")
    
    # Create certificate signed by CA
    entity_cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        entity_private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        # Valid for 1 year
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).add_extension(
        # Not a CA certificate
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    ).add_extension(
        # Entity key usage
        x509.KeyUsage(
            digital_signature=True,
            key_encipherment=True,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    ).sign(
        ca_private_key,
        hashes.SHA256(),
        backend=default_backend()
    )
    
    return entity_private_key, entity_cert


def save_entity_credentials(entity_name, entity_private_key, entity_cert):
    """
    Save entity private key and certificate to PEM files.
    
    Args:
        entity_name: Name of the entity (e.g., "server" or "client")
        entity_private_key: Entity's RSA private key
        entity_cert: Entity's X.509 certificate
    """
    # Create certs directory if it doesn't exist
    if not os.path.exists('certs'):
        os.makedirs('certs')
        print("Created certs/ directory")
    
    # Save entity private key to certs/{entity}_key.pem
    entity_key_path = f'certs/{entity_name}_key.pem'
    with open(entity_key_path, 'wb') as f:
        f.write(entity_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    print(f"Saved {entity_name} private key to {entity_key_path}")
    
    # Save entity certificate to certs/{entity}_cert.pem
    entity_cert_path = f'certs/{entity_name}_cert.pem'
    with open(entity_cert_path, 'wb') as f:
        f.write(entity_cert.public_bytes(serialization.Encoding.PEM))
    print(f"Saved {entity_name} certificate to {entity_cert_path}")
    
    print(f"\n{entity_name.capitalize()} certificate generation complete!")
    print(f"{entity_name.capitalize()} private key: {entity_key_path}")
    print(f"{entity_name.capitalize()} certificate: {entity_cert_path}")
    print("\nYou can inspect the certificate with:")
    print(f"  openssl x509 -in {entity_cert_path} -text -noout")


def main():
    """
    Main function to run the certificate issuance script.
    """
    print("=" * 60)
    print("SecureChat Certificate Issuance Script")
    print("=" * 60)
    print()
    
    # Check command-line arguments
    if len(sys.argv) != 2:
        print("Error: Entity name required")
        print("Usage: python scripts/gen_cert.py <entity_name>")
        print("Example: python scripts/gen_cert.py server")
        print("Example: python scripts/gen_cert.py client")
        sys.exit(1)
    
    entity_name = sys.argv[1].lower()
    
    # Validate entity name
    if entity_name not in ['server', 'client']:
        print(f"Error: Invalid entity name '{entity_name}'")
        print("Entity name must be 'server' or 'client'")
        sys.exit(1)
    
    # Check if CA files exist
    ca_key_path = 'certs/ca_key.pem'
    ca_cert_path = 'certs/ca_cert.pem'
    
    if not os.path.exists(ca_key_path):
        print(f"Error: CA private key not found at {ca_key_path}")
        print("Please run 'python scripts/gen_ca.py' first to generate the CA")
        sys.exit(1)
    
    if not os.path.exists(ca_cert_path):
        print(f"Error: CA certificate not found at {ca_cert_path}")
        print("Please run 'python scripts/gen_ca.py' first to generate the CA")
        sys.exit(1)
    
    print(f"Loading CA credentials from certs/...")
    
    # Load CA private key and certificate
    ca_private_key = load_ca_key(ca_key_path)
    ca_cert = load_ca_cert(ca_cert_path)
    
    print(f"CA loaded successfully")
    print()
    
    # Generate entity certificate
    entity_private_key, entity_cert = generate_entity_certificate(
        entity_name,
        ca_private_key,
        ca_cert
    )
    
    # Save entity credentials
    save_entity_credentials(entity_name, entity_private_key, entity_cert)
    
    print()
    print("=" * 60)


if __name__ == "__main__":
    main()
