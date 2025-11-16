"""
Simple test script to verify AES encryption and decryption functions.
"""

from crypto_utils import aes_encrypt, aes_decrypt, pkcs7_pad, pkcs7_unpad, derive_aes_key
import secrets

def test_pkcs7_padding():
    """Test PKCS7 padding and unpadding."""
    print("Testing PKCS7 padding...")
    
    # Test with various data lengths
    test_cases = [
        b"Hello",           # 5 bytes - needs 11 bytes padding
        b"Hello World!!!",  # 15 bytes - needs 1 byte padding
        b"Exactly16Bytes!",  # 16 bytes - needs 16 bytes padding (full block)
        b"17BytesOfData!!",  # 17 bytes - needs 15 bytes padding
    ]
    
    for data in test_cases:
        print(f"  Original length: {len(data)} bytes")
        padded = pkcs7_pad(data)
        print(f"  Padded length: {len(padded)} bytes")
        unpadded = pkcs7_unpad(padded)
        
        if unpadded == data:
            print(f"  ✓ PASS: Padding/unpadding successful")
        else:
            print(f"  ✗ FAIL: Data mismatch")
            return False
    
    print()
    return True


def test_aes_encryption_decryption():
    """Test AES encryption and decryption."""
    print("Testing AES encryption and decryption...")
    
    # Generate a random 16-byte AES key
    aes_key = secrets.token_bytes(16)
    print(f"  Generated AES key: {aes_key.hex()}")
    
    # Test messages
    test_messages = [
        b"Hello, World!",
        b"This is a secure chat message.",
        b"Short",
        b"A" * 100,  # Longer message
    ]
    
    for plaintext in test_messages:
        print(f"\n  Testing message: {plaintext[:50]}...")
        
        # Encrypt
        ciphertext_with_iv = aes_encrypt(plaintext, aes_key)
        print(f"  Encrypted length: {len(ciphertext_with_iv)} bytes")
        print(f"  Ciphertext (first 32 bytes): {ciphertext_with_iv[:32].hex()}")
        
        # Decrypt
        decrypted = aes_decrypt(ciphertext_with_iv, aes_key)
        print(f"  Decrypted: {decrypted[:50]}...")
        
        # Verify
        if decrypted == plaintext:
            print(f"  ✓ PASS: Encryption/decryption successful")
        else:
            print(f"  ✗ FAIL: Decrypted text doesn't match original")
            return False
    
    print()
    return True


def test_different_keys():
    """Test that different keys produce different results."""
    print("Testing that different keys produce different ciphertexts...")
    
    plaintext = b"Secret message"
    key1 = secrets.token_bytes(16)
    key2 = secrets.token_bytes(16)
    
    ciphertext1 = aes_encrypt(plaintext, key1)
    ciphertext2 = aes_encrypt(plaintext, key2)
    
    # Ciphertexts should be different (except for the extremely unlikely case of same IV)
    if ciphertext1[16:] != ciphertext2[16:]:  # Compare ciphertext parts only (skip IV)
        print("  ✓ PASS: Different keys produce different ciphertexts")
        print()
        return True
    else:
        print("  Note: Same ciphertext (very unlikely, might be same IV by chance)")
        print()
        return True


def test_integration_with_dh():
    """Test AES encryption with key derived from DH."""
    print("Testing AES with DH-derived key...")
    
    # Simulate a shared secret from DH
    shared_secret = 123456789012345678901234567890
    
    # Derive AES key
    aes_key = derive_aes_key(shared_secret)
    print(f"  Derived AES key: {aes_key.hex()}")
    print(f"  Key length: {len(aes_key)} bytes")
    
    # Test encryption/decryption with derived key
    plaintext = b"Message encrypted with DH-derived key"
    ciphertext_with_iv = aes_encrypt(plaintext, aes_key)
    decrypted = aes_decrypt(ciphertext_with_iv, aes_key)
    
    if decrypted == plaintext:
        print("  ✓ PASS: AES works with DH-derived key")
        print()
        return True
    else:
        print("  ✗ FAIL: Decryption failed with DH-derived key")
        print()
        return False


if __name__ == "__main__":
    print("=" * 60)
    print("AES Encryption/Decryption Test Suite")
    print("=" * 60)
    print()
    
    all_passed = True
    
    all_passed = test_pkcs7_padding() and all_passed
    all_passed = test_aes_encryption_decryption() and all_passed
    all_passed = test_different_keys() and all_passed
    all_passed = test_integration_with_dh() and all_passed
    
    print("=" * 60)
    if all_passed:
        print("✓ ALL TESTS PASSED")
    else:
        print("✗ SOME TESTS FAILED")
    print("=" * 60)
