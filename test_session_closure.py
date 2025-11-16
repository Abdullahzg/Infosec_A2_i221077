"""
Test script to verify session closure and receipt generation functionality.

This script simulates the session closure process that happens in the server
when a chat session ends.
"""

import os
import time
import transcript_utils
import crypto_utils


def test_session_closure():
    """Test the complete session closure workflow."""
    print("="*60)
    print("Testing Session Closure and Receipt Generation")
    print("="*60)
    
    # Step 1: Create a mock transcript file
    print("\n[Step 1] Creating mock transcript file...")
    session_id = f"test_{int(time.time())}"
    transcript_path = transcript_utils.create_transcript_file(session_id)
    print(f"✓ Transcript created: {transcript_path}")
    
    # Step 2: Add some mock messages to the transcript
    print("\n[Step 2] Adding mock messages to transcript...")
    with open(transcript_path, 'a') as f:
        transcript_utils.append_to_transcript(
            f, 
            seqno=1, 
            ts=1700000000000, 
            ct="YWJjZGVmZ2hpamtsbW5vcA==", 
            sig="c2lnbmF0dXJlMTIzNDU2Nzg5MA==", 
            peer_fingerprint="a1b2c3d4e5f6"
        )
        transcript_utils.append_to_transcript(
            f, 
            seqno=2, 
            ts=1700000001000, 
            ct="cXJzdHV2d3h5ejEyMzQ1Njc4OTA=", 
            sig="c2lnbmF0dXJlOTg3NjU0MzIxMA==", 
            peer_fingerprint="a1b2c3d4e5f6"
        )
        transcript_utils.append_to_transcript(
            f, 
            seqno=3, 
            ts=1700000002000, 
            ct="MTIzNDU2Nzg5MGFiY2RlZmdoaWo=", 
            sig="c2lnbmF0dXJlYWJjZGVmZ2hpag==", 
            peer_fingerprint="a1b2c3d4e5f6"
        )
    print("✓ Added 3 mock messages to transcript")
    
    # Step 3: Close transcript file (simulating end of chat)
    print("\n[Step 3] Closing transcript file...")
    print("✓ Transcript file closed")
    
    # Step 4: Compute transcript hash
    print("\n[Step 4] Computing transcript hash...")
    transcript_hash = transcript_utils.compute_transcript_hash(transcript_path)
    print(f"✓ Transcript hash computed: {transcript_hash[:32]}...")
    
    # Step 5: Load server private key for signing
    print("\n[Step 5] Loading server private key...")
    try:
        server_private_key = crypto_utils.load_private_key("certs/server_key.pem")
        if server_private_key is None:
            print("⚠ Server private key not found. Skipping receipt generation.")
            print("  (Run 'python scripts/gen_ca.py' and 'python scripts/gen_cert.py server' first)")
            cleanup(transcript_path)
            return
        print("✓ Server private key loaded")
    except Exception as e:
        print(f"⚠ Error loading server private key: {e}")
        print("  (Run 'python scripts/gen_ca.py' and 'python scripts/gen_cert.py server' first)")
        cleanup(transcript_path)
        return
    
    # Step 6: Generate session receipt
    print("\n[Step 6] Generating session receipt...")
    first_seq = 1
    last_seq = 3
    receipt = transcript_utils.generate_session_receipt(
        transcript_path,
        server_private_key,
        "client",  # peer name
        first_seq,
        last_seq
    )
    print("✓ Session receipt generated")
    print(f"  - Type: {receipt['type']}")
    print(f"  - Peer: {receipt['peer']}")
    print(f"  - First seq: {receipt['first_seq']}")
    print(f"  - Last seq: {receipt['last_seq']}")
    print(f"  - Transcript hash: {receipt['transcript_sha256'][:32]}...")
    print(f"  - Signature: {receipt['sig'][:32]}...")
    
    # Step 7: Save receipt to file
    print("\n[Step 7] Saving session receipt to file...")
    transcript_utils.save_receipt(receipt, session_id, "server")
    receipt_path = os.path.join("receipts", f"session_{session_id}_server_receipt.json")
    print(f"✓ Receipt saved to: {receipt_path}")
    
    # Step 8: Verify files exist
    print("\n[Step 8] Verifying files exist...")
    assert os.path.exists(transcript_path), "Transcript file not found!"
    assert os.path.exists(receipt_path), "Receipt file not found!"
    print("✓ Both transcript and receipt files exist")
    
    # Cleanup
    print("\n[Cleanup] Removing test files...")
    cleanup(transcript_path, receipt_path)
    
    print("\n" + "="*60)
    print("✓✓✓ ALL SESSION CLOSURE TESTS PASSED! ✓✓✓")
    print("="*60)


def cleanup(*paths):
    """Remove test files."""
    for path in paths:
        if os.path.exists(path):
            os.remove(path)
            print(f"  Removed: {path}")


if __name__ == "__main__":
    test_session_closure()
