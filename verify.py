"""
Offline Verification Tool for Secure Chat System

This tool verifies the authenticity and integrity of chat transcripts
and session receipts. It performs the following checks:
1. Verifies each message signature in the transcript
2. Verifies the transcript hash matches the receipt
3. Verifies the receipt signature

Usage:
    python verify.py --transcript <transcript_file> --receipt <receipt_file> --cert <peer_cert_file>

Example:
    python verify.py --transcript transcripts/session_123.txt --receipt receipts/session_123_client_receipt.json --cert certs/client_cert.pem

Assignment Reference: Section 3 - Testing & Evidence, offline verification
Requirements: 10.7, 11.1, 11.2, 11.3, 11.4, 11.5, 11.6, 11.7, 11.8, 11.9, 11.10
"""

import argparse
import json
import base64
import hashlib
from crypto_utils import load_certificate, get_public_key_from_cert, verify_signature


def parse_transcript_line(line):
    """
    Parse a single line from the transcript file.
    
    Format: seqno|ts|ct|sig|fingerprint
    
    Parameters:
        line (str): Line from transcript file
        
    Returns:
        dict: Parsed message components or None if parsing fails
    """
    # Remove trailing newline
    line = line.strip()
    
    # Skip empty lines
    if not line:
        return None
    
    # Split by pipe delimiter
    parts = line.split('|')
    
    # Verify we have exactly 5 parts
    if len(parts) != 5:
        print(f"ERROR: Invalid transcript line format (expected 5 fields, got {len(parts)})")
        return None
    
    # Extract components
    try:
        seqno = int(parts[0])
        ts = int(parts[1])
        ct = parts[2]
        sig = parts[3]
        fingerprint = parts[4]
        
        return {
            'seqno': seqno,
            'ts': ts,
            'ct': ct,
            'sig': sig,
            'fingerprint': fingerprint
        }
    except ValueError as e:
        print(f"ERROR: Failed to parse transcript line: {e}")
        return None


def verify_message_signature(seqno, ts, ct, sig_base64, public_key):
    """
    Verify the signature of a single message.
    
    Process:
    1. Recompute digest: SHA-256(seqno || ts || ct)
    2. Verify signature using peer's public key
    
    Parameters:
        seqno (int): Message sequence number
        ts (int): Unix timestamp in milliseconds
        ct (str): Base64-encoded ciphertext
        sig_base64 (str): Base64-encoded signature
        public_key: RSA public key object
        
    Returns:
        bool: True if signature is valid, False otherwise
    """
    # Step 1: Recompute digest
    # Concatenate seqno, timestamp, and ciphertext
    # Convert to bytes for hashing
    seqno_bytes = str(seqno).encode('utf-8')
    ts_bytes = str(ts).encode('utf-8')
    ct_bytes = ct.encode('utf-8')
    
    # Concatenate all components
    data_to_hash = seqno_bytes + ts_bytes + ct_bytes
    
    # Compute SHA-256 digest
    digest = hashlib.sha256(data_to_hash).digest()
    
    # Step 2: Decode signature from base64
    try:
        signature = base64.b64decode(sig_base64)
    except Exception as e:
        print(f"ERROR: Failed to decode signature: {e}")
        return False
    
    # Step 3: Verify signature
    is_valid = verify_signature(digest, signature, public_key)
    
    return is_valid


def verify_transcript_messages(transcript_path, peer_cert):
    """
    Verify all message signatures in the transcript.
    
    Parameters:
        transcript_path (str): Path to transcript file
        peer_cert: X.509 certificate of the peer
        
    Returns:
        tuple: (success, transcript_lines)
        - success (bool): True if all signatures valid, False otherwise
        - transcript_lines (list): List of transcript lines for hash computation
    """
    # Get peer's public key from certificate
    peer_public_key = get_public_key_from_cert(peer_cert)
    
    # Read transcript file
    try:
        with open(transcript_path, 'r') as f:
            transcript_lines = f.readlines()
    except Exception as e:
        print(f"ERROR: Failed to read transcript file: {e}")
        return False, []
    
    # Verify each message
    line_number = 0
    for line in transcript_lines:
        line_number = line_number + 1
        
        # Parse the line
        message = parse_transcript_line(line)
        
        # Skip empty lines
        if message is None:
            if line.strip():  # Only report error if line is not empty
                print(f"ERROR: Failed to parse line {line_number}")
                return False, []
            continue
        
        # Verify message signature
        is_valid = verify_message_signature(
            message['seqno'],
            message['ts'],
            message['ct'],
            message['sig'],
            peer_public_key
        )
        
        if not is_valid:
            print(f"ERROR: Message signature verification failed at line {line_number}")
            print(f"       seqno={message['seqno']}, ts={message['ts']}")
            return False, []
    
    print(f"✓ All {line_number} message signatures verified successfully")
    
    return True, transcript_lines


def compute_transcript_hash_from_lines(transcript_lines):
    """
    Compute SHA-256 hash of transcript lines.
    
    Parameters:
        transcript_lines (list): List of transcript lines
        
    Returns:
        str: Hex-encoded SHA-256 hash
    """
    # Concatenate all lines
    transcript_content = ''.join(transcript_lines)
    
    # Convert to bytes
    transcript_bytes = transcript_content.encode('utf-8')
    
    # Compute SHA-256 hash
    hash_digest = hashlib.sha256(transcript_bytes).digest()
    
    # Convert to hex string
    transcript_hash = hash_digest.hex()
    
    return transcript_hash


def verify_receipt_signature(receipt, peer_cert):
    """
    Verify the receipt signature.
    
    Parameters:
        receipt (dict): Session receipt dictionary
        peer_cert: X.509 certificate of the peer
        
    Returns:
        bool: True if signature is valid, False otherwise
    """
    # Get peer's public key from certificate
    peer_public_key = get_public_key_from_cert(peer_cert)
    
    # Get transcript hash from receipt (hex-encoded)
    transcript_hash_hex = receipt['transcript_sha256']
    
    # Convert hex hash to bytes
    transcript_hash_bytes = bytes.fromhex(transcript_hash_hex)
    
    # Get signature from receipt (base64-encoded)
    sig_base64 = receipt['sig']
    
    # Decode signature from base64
    try:
        signature = base64.b64decode(sig_base64)
    except Exception as e:
        print(f"ERROR: Failed to decode receipt signature: {e}")
        return False
    
    # Verify signature
    is_valid = verify_signature(transcript_hash_bytes, signature, peer_public_key)
    
    return is_valid


def main():
    """
    Main function for offline verification tool.
    """
    # Parse command-line arguments
    parser = argparse.ArgumentParser(
        description='Verify chat transcript and session receipt',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Example:
  python verify.py --transcript transcripts/session_123.txt --receipt receipts/session_123_client_receipt.json --cert certs/client_cert.pem
        """
    )
    
    parser.add_argument('--transcript', required=True, help='Path to transcript file')
    parser.add_argument('--receipt', required=True, help='Path to receipt JSON file')
    parser.add_argument('--cert', required=True, help='Path to peer certificate PEM file')
    
    args = parser.parse_args()
    
    print("=" * 70)
    print("Secure Chat System - Offline Verification Tool")
    print("=" * 70)
    print()
    
    # Step 1: Load peer certificate
    print(f"Loading peer certificate: {args.cert}")
    peer_cert = load_certificate(args.cert)
    
    if peer_cert is None:
        print("ERROR: Failed to load peer certificate")
        print()
        print("VERIFICATION FAILED: Cannot load peer certificate")
        return 1
    
    print("✓ Peer certificate loaded successfully")
    print()
    
    # Step 2: Load receipt
    print(f"Loading receipt: {args.receipt}")
    try:
        with open(args.receipt, 'r') as f:
            receipt = json.load(f)
    except Exception as e:
        print(f"ERROR: Failed to load receipt: {e}")
        print()
        print("VERIFICATION FAILED: Cannot load receipt")
        return 1
    
    print("✓ Receipt loaded successfully")
    print(f"  Peer: {receipt.get('peer', 'unknown')}")
    print(f"  Sequence range: {receipt.get('first_seq', '?')} - {receipt.get('last_seq', '?')}")
    print(f"  Transcript hash: {receipt.get('transcript_sha256', 'unknown')[:32]}...")
    print()
    
    # Step 3: Verify all message signatures in transcript
    print(f"Verifying message signatures in transcript: {args.transcript}")
    success, transcript_lines = verify_transcript_messages(args.transcript, peer_cert)
    
    if not success:
        print()
        print("VERIFICATION FAILED: Message signature verification failed")
        return 1
    
    print()
    
    # Step 4: Compute transcript hash and compare with receipt
    print("Computing transcript hash...")
    computed_hash = compute_transcript_hash_from_lines(transcript_lines)
    receipt_hash = receipt['transcript_sha256']
    
    print(f"  Computed hash:  {computed_hash}")
    print(f"  Receipt hash:   {receipt_hash}")
    
    if computed_hash != receipt_hash:
        print("✗ Transcript hash mismatch!")
        print()
        print("VERIFICATION FAILED: Transcript has been modified")
        return 1
    
    print("✓ Transcript hash matches receipt")
    print()
    
    # Step 5: Verify receipt signature
    print("Verifying receipt signature...")
    receipt_valid = verify_receipt_signature(receipt, peer_cert)
    
    if not receipt_valid:
        print("✗ Receipt signature verification failed!")
        print()
        print("VERIFICATION FAILED: Receipt signature is invalid")
        return 1
    
    print("✓ Receipt signature verified successfully")
    print()
    
    # All checks passed
    print("=" * 70)
    print("VERIFICATION SUCCESS")
    print("=" * 70)
    print()
    print("All checks passed:")
    print("  ✓ All message signatures are valid")
    print("  ✓ Transcript hash matches receipt")
    print("  ✓ Receipt signature is valid")
    print()
    print("The transcript is authentic and has not been tampered with.")
    
    return 0


if __name__ == '__main__':
    exit(main())
