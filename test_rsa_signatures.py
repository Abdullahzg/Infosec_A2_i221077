"""
Test script for RSA signature functions.

Tests:
1. Sign data with private key
2. Verify signature with public key
3. Verify that tampered data fails verification
"""

import crypto_utils

def test_rsa_signatures():
    """Test RSA signing and verification."""
    
    print("=" * 60)
    print("Testing RSA Signature Functions")
    print("=" * 60)
    
    # Load server private key and certificate
    print("\n1. Loading server private key and certificate...")
    private_key = crypto_utils.load_private_key('certs/server_key.pem')
    cert = crypto_utils.load_certificate('certs/server_cert.pem')
    
    if private_key is None:
        print("   ERROR: Failed to load private key")
        return False
    
    if cert is None:
        print("   ERROR: Failed to load certificate")
        return False
    
    print("   SUCCESS: Loaded private key and certificate")
    
    # Extract public key from certificate
    print("\n2. Extracting public key from certificate...")
    public_key = crypto_utils.get_public_key_from_cert(cert)
    print("   SUCCESS: Extracted public key")
    
    # Test data
    test_data = b"Hello, this is a test message for RSA signing!"
    print(f"\n3. Test data: {test_data.decode()}")
    
    # Sign the data
    print("\n4. Signing data with private key...")
    signature = crypto_utils.sign_data(test_data, private_key)
    print(f"   SUCCESS: Generated signature ({len(signature)} bytes)")
    print(f"   Signature (hex): {signature.hex()[:64]}...")
    
    # Verify the signature
    print("\n5. Verifying signature with public key...")
    is_valid = crypto_utils.verify_signature(test_data, signature, public_key)
    
    if is_valid:
        print("   SUCCESS: Signature verification passed!")
    else:
        print("   ERROR: Signature verification failed!")
        return False
    
    # Test with tampered data
    print("\n6. Testing with tampered data...")
    tampered_data = b"Hello, this is a TAMPERED message for RSA signing!"
    is_valid_tampered = crypto_utils.verify_signature(tampered_data, signature, public_key)
    
    if not is_valid_tampered:
        print("   SUCCESS: Tampered data correctly rejected!")
    else:
        print("   ERROR: Tampered data was incorrectly accepted!")
        return False
    
    # Test with tampered signature
    print("\n7. Testing with tampered signature...")
    tampered_signature = bytearray(signature)
    tampered_signature[0] = (tampered_signature[0] + 1) % 256  # Flip one byte
    tampered_signature = bytes(tampered_signature)
    
    is_valid_tampered_sig = crypto_utils.verify_signature(test_data, tampered_signature, public_key)
    
    if not is_valid_tampered_sig:
        print("   SUCCESS: Tampered signature correctly rejected!")
    else:
        print("   ERROR: Tampered signature was incorrectly accepted!")
        return False
    
    print("\n" + "=" * 60)
    print("All RSA signature tests passed!")
    print("=" * 60)
    
    return True


if __name__ == "__main__":
    success = test_rsa_signatures()
    
    if not success:
        print("\nSome tests failed!")
        exit(1)
    else:
        print("\nAll tests completed successfully!")
        exit(0)
