"""
Certificate Validation Test Script

This script tests the certificate validation functionality of the Secure Chat System.

Test Cases:
1. Valid certificate (should succeed)
2. Expired certificate (should log BAD_CERT_EXPIRED)
3. Self-signed certificate (should log BAD_CERT_SELF_SIGNED)
4. Certificate from different CA (should log BAD_CERT_UNTRUSTED)

Assignment Reference: Section 3 - Testing & Evidence, invalid certificate test
Requirements: 2.5, 14.1
"""

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import datetime
import os
import sys

# Import the crypto_utils module
import crypto_utils


def create_test_ca(name_suffix=""):
    """
    Create a test CA for testing purposes.
    
    Args:
        name_suffix: Optional suffix to add to CA name for uniqueness
        
    Returns:
        Tuple of (ca_private_key, ca_cert)
    """
    print(f"  Creating test CA{name_suffix}...")
    
    # Generate CA private key
    ca_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Create subject and issuer (same for self-signed)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Test"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Test City"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Test Org"),
        x509.NameAttribute(NameOID.COMMON_NAME, f"Test CA{name_suffix}"),
    ])
    
    # Create self-signed CA certificate
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
        datetime.datetime.utcnow() + datetime.timedelta(days=3650)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True,
    ).add_extension(
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
    
    return ca_private_key, ca_cert


def create_valid_certificate(ca_private_key, ca_cert, entity_name="test_entity"):
    """
    Create a valid certificate signed by the CA.
    
    Args:
        ca_private_key: CA's private key
        ca_cert: CA's certificate
        entity_name: Name for the entity
        
    Returns:
        Tuple of (entity_private_key, entity_cert)
    """
    print(f"  Creating valid certificate for {entity_name}...")
    
    # Generate entity private key
    entity_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Create subject
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Test"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Test City"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Test Org"),
        x509.NameAttribute(NameOID.COMMON_NAME, entity_name),
    ])
    
    # Get issuer from CA
    issuer = ca_cert.subject
    
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
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    ).add_extension(
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


def create_expired_certificate(ca_private_key, ca_cert, entity_name="expired_entity"):
    """
    Create an expired certificate (validity period in the past).
    
    Args:
        ca_private_key: CA's private key
        ca_cert: CA's certificate
        entity_name: Name for the entity
        
    Returns:
        Tuple of (entity_private_key, entity_cert)
    """
    print(f"  Creating expired certificate for {entity_name}...")
    
    # Generate entity private key
    entity_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Create subject
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Test"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Test City"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Test Org"),
        x509.NameAttribute(NameOID.COMMON_NAME, entity_name),
    ])
    
    # Get issuer from CA
    issuer = ca_cert.subject
    
    # Create certificate with expired validity period
    # Valid from 2 years ago to 1 year ago (already expired)
    entity_cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        entity_private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow() - datetime.timedelta(days=730)  # 2 years ago
    ).not_valid_after(
        datetime.datetime.utcnow() - datetime.timedelta(days=365)  # 1 year ago (expired)
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    ).add_extension(
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


def create_self_signed_certificate(entity_name="self_signed_entity"):
    """
    Create a self-signed certificate (not signed by CA).
    
    Args:
        entity_name: Name for the entity
        
    Returns:
        Tuple of (entity_private_key, entity_cert)
    """
    print(f"  Creating self-signed certificate for {entity_name}...")
    
    # Generate entity private key
    entity_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Create subject and issuer (same for self-signed)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Test"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Test City"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Test Org"),
        x509.NameAttribute(NameOID.COMMON_NAME, entity_name),
    ])
    
    # Create self-signed certificate
    entity_cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer  # Same as subject (self-signed)
    ).public_key(
        entity_private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    ).add_extension(
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
        entity_private_key,  # Signed with own key (self-signed)
        hashes.SHA256(),
        backend=default_backend()
    )
    
    return entity_private_key, entity_cert


def test_valid_certificate():
    """
    Test Case 1: Valid certificate should succeed.
    
    Expected: validate_certificate returns (True, None)
    """
    print("\n" + "=" * 70)
    print("TEST CASE 1: Valid Certificate")
    print("=" * 70)
    
    # Create test CA
    ca_private_key, ca_cert = create_test_ca()
    
    # Create valid certificate signed by CA
    entity_private_key, entity_cert = create_valid_certificate(ca_private_key, ca_cert)
    
    # Validate the certificate
    print("\n  Validating certificate...")
    is_valid, error_code = crypto_utils.validate_certificate(entity_cert, ca_cert)
    
    # Check result
    print(f"\n  Result: is_valid={is_valid}, error_code={error_code}")
    
    if is_valid and error_code is None:
        print("  ✓ TEST PASSED: Valid certificate accepted")
        return True
    else:
        print(f"  ✗ TEST FAILED: Valid certificate rejected with error: {error_code}")
        return False


def test_expired_certificate():
    """
    Test Case 2: Expired certificate should log BAD_CERT_EXPIRED.
    
    Expected: validate_certificate returns (False, BAD_CERT_EXPIRED)
    """
    print("\n" + "=" * 70)
    print("TEST CASE 2: Expired Certificate")
    print("=" * 70)
    
    # Create test CA
    ca_private_key, ca_cert = create_test_ca()
    
    # Create expired certificate
    entity_private_key, entity_cert = create_expired_certificate(ca_private_key, ca_cert)
    
    # Validate the certificate
    print("\n  Validating certificate...")
    is_valid, error_code = crypto_utils.validate_certificate(entity_cert, ca_cert)
    
    # Check result
    print(f"\n  Result: is_valid={is_valid}, error_code={error_code}")
    
    if not is_valid and error_code == crypto_utils.BAD_CERT_EXPIRED:
        print("  ✓ TEST PASSED: Expired certificate rejected with BAD_CERT_EXPIRED")
        return True
    else:
        print(f"  ✗ TEST FAILED: Expected BAD_CERT_EXPIRED, got {error_code}")
        return False


def test_self_signed_certificate():
    """
    Test Case 3: Self-signed certificate should log BAD_CERT_SELF_SIGNED.
    
    Expected: validate_certificate returns (False, BAD_CERT_SELF_SIGNED)
    """
    print("\n" + "=" * 70)
    print("TEST CASE 3: Self-Signed Certificate")
    print("=" * 70)
    
    # Create test CA (for validation)
    ca_private_key, ca_cert = create_test_ca()
    
    # Create self-signed certificate (not signed by CA)
    entity_private_key, entity_cert = create_self_signed_certificate()
    
    # Validate the certificate against CA
    print("\n  Validating certificate...")
    is_valid, error_code = crypto_utils.validate_certificate(entity_cert, ca_cert)
    
    # Check result
    print(f"\n  Result: is_valid={is_valid}, error_code={error_code}")
    
    if not is_valid and error_code == crypto_utils.BAD_CERT_SELF_SIGNED:
        print("  ✓ TEST PASSED: Self-signed certificate rejected with BAD_CERT_SELF_SIGNED")
        return True
    else:
        print(f"  ✗ TEST FAILED: Expected BAD_CERT_SELF_SIGNED, got {error_code}")
        return False


def test_untrusted_ca_certificate():
    """
    Test Case 4: Certificate from different CA should log BAD_CERT_UNTRUSTED.
    
    Expected: validate_certificate returns (False, BAD_CERT_UNTRUSTED)
    """
    print("\n" + "=" * 70)
    print("TEST CASE 4: Certificate from Different CA")
    print("=" * 70)
    
    # Create first CA (trusted)
    ca1_private_key, ca1_cert = create_test_ca(" 1")
    
    # Create second CA (untrusted)
    ca2_private_key, ca2_cert = create_test_ca(" 2")
    
    # Create certificate signed by CA2
    entity_private_key, entity_cert = create_valid_certificate(
        ca2_private_key, 
        ca2_cert, 
        "entity_from_different_ca"
    )
    
    # Try to validate certificate signed by CA2 against CA1
    print("\n  Validating certificate signed by CA2 against CA1...")
    is_valid, error_code = crypto_utils.validate_certificate(entity_cert, ca1_cert)
    
    # Check result
    print(f"\n  Result: is_valid={is_valid}, error_code={error_code}")
    
    if not is_valid and error_code == crypto_utils.BAD_CERT_UNTRUSTED:
        print("  ✓ TEST PASSED: Certificate from different CA rejected with BAD_CERT_UNTRUSTED")
        return True
    else:
        print(f"  ✗ TEST FAILED: Expected BAD_CERT_UNTRUSTED, got {error_code}")
        return False


def main():
    """
    Run all certificate validation tests.
    """
    print("\n" + "=" * 70)
    print("CERTIFICATE VALIDATION TEST SUITE")
    print("=" * 70)
    print("\nThis test suite validates the certificate validation functionality")
    print("of the Secure Chat System.")
    print("\nAssignment Reference: Section 3 - Testing & Evidence")
    print("Requirements: 2.5, 14.1")
    
    # Run all tests
    results = []
    
    results.append(("Valid Certificate", test_valid_certificate()))
    results.append(("Expired Certificate", test_expired_certificate()))
    results.append(("Self-Signed Certificate", test_self_signed_certificate()))
    results.append(("Certificate from Different CA", test_untrusted_ca_certificate()))
    
    # Print summary
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    
    passed = 0
    failed = 0
    
    for test_name, result in results:
        status = "PASSED" if result else "FAILED"
        symbol = "✓" if result else "✗"
        print(f"{symbol} {test_name}: {status}")
        
        if result:
            passed += 1
        else:
            failed += 1
    
    print("\n" + "-" * 70)
    print(f"Total: {len(results)} tests")
    print(f"Passed: {passed}")
    print(f"Failed: {failed}")
    print("-" * 70)
    
    if failed == 0:
        print("\n✓ ALL TESTS PASSED")
        return 0
    else:
        print(f"\n✗ {failed} TEST(S) FAILED")
        return 1


if __name__ == "__main__":
    sys.exit(main())
