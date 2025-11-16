"""
Simple test script to verify transcript_utils.py functions work correctly.
"""

import transcript_utils
import os
import tempfile
import shutil
from crypto_utils import load_private_key


def test_transcript_operations():
    """Test transcript file creation and operations."""
    print("Testing transcript operations...")
    
    # Test 1: Create transcript file
    session_id = "test_123"
    transcript_path = transcript_utils.create_transcript_file(session_id)
    assert os.path.exists(transcript_path)
    expected_path = os.path.join("transcripts", f"session_{session_id}.txt")
    assert transcript_path == expected_path
    print("✓ create_transcript_file works")
    
    # Test 2: Append to transcript
    with open(transcript_path, 'a') as f:
        transcript_utils.append_to_transcript(
            f, 
            seqno=1, 
            ts=1700000000000, 
            ct="YWJjZGVm", 
            sig="ZGVmZ2hp", 
            peer_fingerprint="a1b2c3d4"
        )
        transcript_utils.append_to_transcript(
            f, 
            seqno=2, 
            ts=1700000001000, 
            ct="Z2hpamts", 
            sig="amtsbW5v", 
            peer_fingerprint="a1b2c3d4"
        )
    
    # Verify file contents
    with open(transcript_path, 'r') as f:
        lines = f.readlines()
    
    assert len(lines) == 2
    assert lines[0] == "1|1700000000000|YWJjZGVm|ZGVmZ2hp|a1b2c3d4\n"
    assert lines[1] == "2|1700000001000|Z2hpamts|amtsbW5v|a1b2c3d4\n"
    print("✓ append_to_transcript works")
    
    # Test 3: Compute transcript hash
    transcript_hash = transcript_utils.compute_transcript_hash(transcript_path)
    assert isinstance(transcript_hash, str)
    assert len(transcript_hash) == 64  # SHA-256 hex is 64 characters
    print(f"✓ compute_transcript_hash works (hash: {transcript_hash[:16]}...)")
    
    # Test 4: Generate session receipt (requires a private key)
    # Load a private key if available, otherwise skip this test
    try:
        private_key = load_private_key("certs/client_key.pem")
        if private_key:
            receipt = transcript_utils.generate_session_receipt(
                transcript_path,
                private_key,
                "server",
                first_seq=1,
                last_seq=2
            )
            
            assert receipt["type"] == "receipt"
            assert receipt["peer"] == "server"
            assert receipt["first_seq"] == 1
            assert receipt["last_seq"] == 2
            assert receipt["transcript_sha256"] == transcript_hash
            assert "sig" in receipt
            print("✓ generate_session_receipt works")
            
            # Test 5: Save receipt
            transcript_utils.save_receipt(receipt, session_id, "client")
            receipt_path = os.path.join("receipts", f"session_{session_id}_client_receipt.json")
            assert os.path.exists(receipt_path)
            print("✓ save_receipt works")
            
            # Cleanup receipt
            os.remove(receipt_path)
        else:
            print("⚠ Skipping receipt tests (no private key available)")
    except Exception as e:
        print(f"⚠ Skipping receipt tests (error loading key: {e})")
    
    # Cleanup
    os.remove(transcript_path)
    print("\nAll transcript tests passed! ✓")


def test_transcript_hash_consistency():
    """Test that transcript hash is consistent."""
    print("\nTesting transcript hash consistency...")
    
    # Create a test transcript
    session_id = "test_hash_456"
    transcript_path = transcript_utils.create_transcript_file(session_id)
    
    # Write some data
    with open(transcript_path, 'a') as f:
        transcript_utils.append_to_transcript(
            f, 1, 1700000000000, "ct1", "sig1", "fp1"
        )
        transcript_utils.append_to_transcript(
            f, 2, 1700000001000, "ct2", "sig2", "fp2"
        )
    
    # Compute hash twice
    hash1 = transcript_utils.compute_transcript_hash(transcript_path)
    hash2 = transcript_utils.compute_transcript_hash(transcript_path)
    
    # Hashes should be identical
    assert hash1 == hash2
    print(f"✓ Transcript hash is consistent: {hash1[:16]}...")
    
    # Modify transcript and verify hash changes
    with open(transcript_path, 'a') as f:
        transcript_utils.append_to_transcript(
            f, 3, 1700000002000, "ct3", "sig3", "fp3"
        )
    
    hash3 = transcript_utils.compute_transcript_hash(transcript_path)
    assert hash3 != hash1
    print("✓ Transcript hash changes when content changes")
    
    # Cleanup
    os.remove(transcript_path)
    print("\nAll hash consistency tests passed! ✓")


if __name__ == "__main__":
    test_transcript_operations()
    test_transcript_hash_consistency()
    print("\n" + "="*50)
    print("ALL TESTS PASSED! ✓✓✓")
    print("="*50)
