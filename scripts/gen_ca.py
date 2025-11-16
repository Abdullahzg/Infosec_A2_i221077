"""
CA Generation Script
Generates a self-signed root Certificate Authority (CA) for the Secure Chat System.

This script creates:
- A 2048-bit RSA private key for the CA
- A self-signed X.509 certificate with CA extensions
- Saves both to the certs/ directory

Usage:
    python scripts/gen_ca.py
"""

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import datetime
import os


def generate_ca():
    """
    Generate a root Certificate Authority (CA) with a self-signed certificate.
    
    Creates:
    - 2048-bit RSA private key
    - Self-signed X.509 certificate valid for 10 years
    - CA extensions (basicConstraints, keyUsage)
    
    Saves:
    - certs/ca_key.pem (private key)
    - certs/ca_cert.pem (certificate)
    """
    print("Generating CA private key...")
    
    # Generate 2048-bit RSA private key for CA
    ca_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    print("Creating self-signed CA certificate...")
    
    # Create subject and issuer (same for self-signed)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"SecureChat"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"SecureChat Root CA"),
    ])
    
    # Create self-signed certificate
    ca_cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        ca_private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        # Valid for 10 years
        datetime.datetime.utcnow() + datetime.timedelta(days=3650)
    ).add_extension(
        # Mark as CA certificate
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True,
    ).add_extension(
        # CA key usage
        x509.KeyUsage(
            digital_signature=True,
            key_cert_sign=True,
            crl_sign=True,
            key_encipherment=False,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    ).sign(
        ca_private_key, 
        hashes.SHA256(),
        backend=default_backend()
    )
    
    # Create certs directory if it doesn't exist
    if not os.path.exists('certs'):
        os.makedirs('certs')
        print("Created certs/ directory")
    
    # Save CA private key to certs/ca_key.pem
    ca_key_path = 'certs/ca_key.pem'
    with open(ca_key_path, 'wb') as f:
        f.write(ca_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    print(f"Saved CA private key to {ca_key_path}")
    
    # Save CA certificate to certs/ca_cert.pem
    ca_cert_path = 'certs/ca_cert.pem'
    with open(ca_cert_path, 'wb') as f:
        f.write(ca_cert.public_bytes(serialization.Encoding.PEM))
    print(f"Saved CA certificate to {ca_cert_path}")
    
    print("\nCA generation complete!")
    print(f"CA private key: {ca_key_path}")
    print(f"CA certificate: {ca_cert_path}")
    print("\nYou can inspect the certificate with:")
    print(f"  openssl x509 -in {ca_cert_path} -text -noout")


def main():
    """
    Main function to run the CA generation script.
    """
    print("=" * 60)
    print("SecureChat CA Generation Script")
    print("=" * 60)
    print()
    
    generate_ca()
    
    print()
    print("=" * 60)


if __name__ == "__main__":
    main()
