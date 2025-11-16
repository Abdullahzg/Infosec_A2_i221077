"""
Cryptographic utilities for the Secure Chat System.

This module provides functions for:
- Loading and parsing X.509 certificates and RSA private keys
- Validating certificates against a trusted CA
- Extracting public keys and computing certificate fingerprints

Design: Uses simple if-else logic with clear error codes.
Libraries: cryptography library for all cryptographic operations.
"""

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timezone
import secrets
import hashlib


# Error codes for certificate validation
BAD_CERT_EXPIRED = "BAD_CERT_EXPIRED"
BAD_CERT_SELF_SIGNED = "BAD_CERT_SELF_SIGNED"
BAD_CERT_UNTRUSTED = "BAD_CERT_UNTRUSTED"
BAD_CERT_INVALID_SIG = "BAD_CERT_INVALID_SIG"


def load_certificate(cert_path):
    """
    Load and parse an X.509 certificate from a PEM file.
    
    Parameters:
        cert_path (str): Path to the PEM certificate file
        
    Returns:
        Certificate object or None if loading fails
    """
    try:
        # Read the PEM file
        with open(cert_path, 'rb') as f:
            cert_data = f.read()
        
        # Parse the X.509 certificate
        cert = x509.load_pem_x509_certificate(cert_data, default_backend())
        
        return cert
    except Exception as e:
        print(f"Error loading certificate from {cert_path}: {e}")
        return None


def load_private_key(key_path):
    """
    Load and parse an RSA private key from a PEM file.
    
    Parameters:
        key_path (str): Path to the PEM private key file
        
    Returns:
        RSAPrivateKey object or None if loading fails
    """
    try:
        # Read the PEM file
        with open(key_path, 'rb') as f:
            key_data = f.read()
        
        # Parse the RSA private key (no password)
        private_key = serialization.load_pem_private_key(
            key_data,
            password=None,
            backend=default_backend()
        )
        
        return private_key
    except Exception as e:
        print(f"Error loading private key from {key_path}: {e}")
        return None


def validate_certificate(cert, ca_cert):
    """
    Validate a certificate against a trusted CA certificate.
    
    Checks performed:
    1. Certificate is not self-signed
    2. Certificate is within validity period
    3. Certificate is signed by the trusted CA
    
    Parameters:
        cert: X.509 certificate to validate
        ca_cert: Trusted CA certificate
        
    Returns:
        Tuple (is_valid, error_code)
        - is_valid (bool): True if certificate is valid, False otherwise
        - error_code (str): Error code if invalid, None if valid
    """
    # Check 1: Verify certificate is not self-signed
    # Self-signed means issuer equals subject
    if cert.issuer == cert.subject:
        return False, BAD_CERT_SELF_SIGNED
    
    # Check 2: Verify validity period
    # Get current time in UTC
    now = datetime.now(timezone.utc)
    
    # Check if certificate is expired or not yet valid
    # Make not_valid_before and not_valid_after timezone-aware
    not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
    not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)
    
    if now < not_before:
        return False, BAD_CERT_EXPIRED
    
    if now > not_after:
        return False, BAD_CERT_EXPIRED
    
    # Check 3: Verify certificate is signed by the CA
    # First check if the issuer matches the CA subject
    if cert.issuer != ca_cert.subject:
        return False, BAD_CERT_UNTRUSTED
    
    # Verify the signature using the CA's public key
    try:
        from cryptography.hazmat.primitives.asymmetric import padding
        
        ca_public_key = ca_cert.public_key()
        
        # Verify the certificate signature
        # Use the signature hash algorithm from the certificate
        ca_public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm
        )
        
        # If verification succeeds, certificate is valid
        return True, None
        
    except Exception as e:
        # Signature verification failed
        return False, BAD_CERT_INVALID_SIG


def get_public_key_from_cert(cert):
    """
    Extract the RSA public key from an X.509 certificate.
    
    Parameters:
        cert: X.509 certificate
        
    Returns:
        RSAPublicKey object
    """
    public_key = cert.public_key()
    return public_key


def get_cert_fingerprint(cert):
    """
    Compute the SHA-256 fingerprint of a certificate.
    
    The fingerprint is computed over the DER encoding of the certificate.
    
    Parameters:
        cert: X.509 certificate
        
    Returns:
        str: Hex-encoded SHA-256 fingerprint
    """
    # Get the DER encoding of the certificate
    cert_der = cert.public_bytes(serialization.Encoding.DER)
    
    # Compute SHA-256 hash
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(cert_der)
    fingerprint_bytes = digest.finalize()
    
    # Convert to hex string
    fingerprint_hex = fingerprint_bytes.hex()
    
    return fingerprint_hex


# ============================================================================
# Diffie-Hellman Key Exchange Functions
# ============================================================================

def generate_dh_parameters():
    """
    Generate standard Diffie-Hellman parameters.
    
    Uses a standard 2048-bit prime (p) and generator (g = 2).
    This is a well-known safe prime from RFC 3526.
    
    Returns:
        Tuple (p, g):
        - p (int): 2048-bit prime modulus
        - g (int): Generator (2)
    """
    # Standard 2048-bit prime from RFC 3526 (Group 14)
    # This is a safe prime: p = 2q + 1 where q is also prime
    p = int(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
        "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
        "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
        "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
        "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
        "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
        "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
        "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16
    )
    
    # Generator
    g = 2
    
    return p, g


def generate_dh_keypair(p, g):
    """
    Generate a Diffie-Hellman keypair.
    
    Generates a random private key and computes the corresponding public key.
    
    Parameters:
        p (int): Prime modulus
        g (int): Generator
        
    Returns:
        Tuple (private_key, public_key):
        - private_key (int): Random private value (a or b)
        - public_key (int): Computed public value (g^private mod p)
    """
    # Generate random private key
    # Private key should be in range [2, p-2]
    # Use secrets module for cryptographically secure random number
    private_key = secrets.randbelow(p - 2) + 2
    
    # Compute public key: public = g^private mod p
    public_key = pow(g, private_key, p)
    
    return private_key, public_key


def compute_shared_secret(peer_public, my_private, p):
    """
    Compute the Diffie-Hellman shared secret.
    
    Computes Ks = peer_public^my_private mod p
    
    Parameters:
        peer_public (int): Peer's public key (A or B)
        my_private (int): My private key (a or b)
        p (int): Prime modulus
        
    Returns:
        int: Shared secret Ks
    """
    # Compute shared secret: Ks = peer_public^my_private mod p
    shared_secret = pow(peer_public, my_private, p)
    
    return shared_secret


def derive_aes_key(shared_secret):
    """
    Derive an AES-128 key from the Diffie-Hellman shared secret.
    
    Process:
    1. Convert shared secret to big-endian bytes
    2. Compute SHA-256 hash
    3. Truncate to first 16 bytes for AES-128
    
    Parameters:
        shared_secret (int): Diffie-Hellman shared secret Ks
        
    Returns:
        bytes: 16-byte AES-128 key
    """
    # Convert shared secret to big-endian bytes
    # Calculate the number of bytes needed
    byte_length = (shared_secret.bit_length() + 7) // 8
    shared_secret_bytes = shared_secret.to_bytes(byte_length, byteorder='big')
    
    # Compute SHA-256 hash
    hash_digest = hashlib.sha256(shared_secret_bytes).digest()
    
    # Truncate to first 16 bytes for AES-128
    aes_key = hash_digest[:16]
    
    return aes_key


# ============================================================================
# AES Encryption and Decryption Functions
# ============================================================================

def pkcs7_pad(data, block_size=16):
    """
    Add PKCS7 padding to data.
    
    PKCS7 padding adds N bytes, each with value N, where N is the number
    of bytes needed to reach a multiple of block_size.
    
    Parameters:
        data (bytes): Data to pad
        block_size (int): Block size in bytes (default 16 for AES)
        
    Returns:
        bytes: Padded data
    """
    # Calculate how many bytes of padding are needed
    padding_length = block_size - (len(data) % block_size)
    
    # Create padding bytes (each byte has value equal to padding_length)
    padding = bytes([padding_length] * padding_length)
    
    # Append padding to data
    padded_data = data + padding
    
    return padded_data


def pkcs7_unpad(padded_data):
    """
    Remove PKCS7 padding from data.
    
    Reads the last byte to determine padding length, then removes that
    many bytes from the end.
    
    Parameters:
        padded_data (bytes): Padded data
        
    Returns:
        bytes: Unpadded data
    """
    # Read the last byte to get padding length
    padding_length = padded_data[-1]
    
    # Verify padding is valid (all padding bytes should have same value)
    for i in range(padding_length):
        if padded_data[-(i+1)] != padding_length:
            raise ValueError("Invalid PKCS7 padding")
    
    # Remove padding bytes
    unpadded_data = padded_data[:-padding_length]
    
    return unpadded_data


def aes_encrypt(plaintext, key):
    """
    Encrypt plaintext using AES-128 in CBC mode.
    
    Process:
    1. Apply PKCS7 padding to plaintext
    2. Generate random IV (16 bytes)
    3. Encrypt using AES-128 CBC mode
    4. Return IV concatenated with ciphertext
    
    Parameters:
        plaintext (bytes): Data to encrypt
        key (bytes): 16-byte AES-128 key
        
    Returns:
        bytes: IV + ciphertext (IV is first 16 bytes)
    """
    from Crypto.Cipher import AES
    
    # Step 1: Apply PKCS7 padding
    padded_plaintext = pkcs7_pad(plaintext, block_size=16)
    
    # Step 2: Generate random IV (16 bytes for AES)
    iv = secrets.token_bytes(16)
    
    # Step 3: Create AES cipher in CBC mode
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Step 4: Encrypt the padded plaintext
    ciphertext = cipher.encrypt(padded_plaintext)
    
    # Step 5: Concatenate IV and ciphertext
    iv_and_ciphertext = iv + ciphertext
    
    return iv_and_ciphertext


def aes_decrypt(ciphertext_with_iv, key):
    """
    Decrypt ciphertext using AES-128 in CBC mode.
    
    Process:
    1. Extract IV (first 16 bytes)
    2. Extract ciphertext (remaining bytes)
    3. Decrypt using AES-128 CBC mode
    4. Remove PKCS7 padding
    5. Return plaintext
    
    Parameters:
        ciphertext_with_iv (bytes): IV + ciphertext
        key (bytes): 16-byte AES-128 key
        
    Returns:
        bytes: Decrypted plaintext
    """
    from Crypto.Cipher import AES
    
    # Step 1: Extract IV (first 16 bytes)
    iv = ciphertext_with_iv[:16]
    
    # Step 2: Extract ciphertext (remaining bytes after IV)
    ciphertext = ciphertext_with_iv[16:]
    
    # Step 3: Create AES cipher in CBC mode with extracted IV
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Step 4: Decrypt the ciphertext
    padded_plaintext = cipher.decrypt(ciphertext)
    
    # Step 5: Remove PKCS7 padding
    plaintext = pkcs7_unpad(padded_plaintext)
    
    return plaintext


# ============================================================================
# RSA Signature Functions
# ============================================================================

def sign_data(data, private_key):
    """
    Sign data using RSA private key with PSS padding.
    
    Process:
    1. Compute SHA-256 hash of data
    2. Sign the hash using RSA private key with PSS padding
    3. Return signature bytes
    
    Parameters:
        data (bytes): Data to sign
        private_key: RSA private key object
        
    Returns:
        bytes: RSA signature
    """
    from cryptography.hazmat.primitives.asymmetric import padding
    
    # Sign the data using RSA private key
    # Use PSS padding with SHA-256 hash
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
    return signature


def verify_signature(data, signature, public_key):
    """
    Verify RSA signature using public key.
    
    Process:
    1. Recompute SHA-256 hash of data
    2. Verify signature using RSA public key with PSS padding
    3. Return True if valid, False if invalid
    
    Parameters:
        data (bytes): Original data that was signed
        signature (bytes): RSA signature to verify
        public_key: RSA public key object
        
    Returns:
        bool: True if signature is valid, False otherwise
    """
    from cryptography.hazmat.primitives.asymmetric import padding
    
    try:
        # Verify the signature
        # Use PSS padding with SHA-256 hash
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        # If verification succeeds, return True
        return True
        
    except Exception as e:
        # Signature verification failed
        return False
