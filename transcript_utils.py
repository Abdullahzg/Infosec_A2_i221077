"""
Transcript logging utilities for the Secure Chat System.

This module provides functions for:
- Creating and managing transcript files
- Appending messages to transcripts
- Computing transcript hashes
- Generating session receipts for non-repudiation

Design: Uses simple file I/O operations with explicit open/close or with statements.
Libraries: Standard library for file operations, hashlib for SHA-256, crypto_utils for signatures.
"""

import os
import hashlib
import json
from crypto_utils import sign_data


def create_transcript_file(session_id):
    """
    Create a transcript file for a chat session.
    
    Creates a file in the transcripts/ directory with the format:
    transcripts/session_{session_id}.txt
    
    Parameters:
        session_id (str): Unique identifier for the session
        
    Returns:
        str: Path to the created transcript file
    """
    # Ensure transcripts directory exists
    transcripts_dir = "transcripts"
    if not os.path.exists(transcripts_dir):
        os.makedirs(transcripts_dir)
    
    # Create transcript file path
    transcript_path = os.path.join(transcripts_dir, f"session_{session_id}.txt")
    
    # Create empty file (will be appended to later)
    with open(transcript_path, 'w') as f:
        pass
    
    return transcript_path


def append_to_transcript(file_handle, seqno, ts, ct, sig, peer_fingerprint):
    """
    Append a message to the transcript file.
    
    Format: seqno|ts|ct|sig|fingerprint
    Uses pipe delimiter for easy parsing.
    
    Parameters:
        file_handle: Open file handle for the transcript file
        seqno (int): Message sequence number
        ts (int): Unix timestamp in milliseconds
        ct (str): Base64-encoded ciphertext
        sig (str): Base64-encoded signature
        peer_fingerprint (str): Hex-encoded SHA-256 fingerprint of peer certificate
    """
    # Format the line with pipe delimiters
    line = f"{seqno}|{ts}|{ct}|{sig}|{peer_fingerprint}\n"
    
    # Write the line to the file
    file_handle.write(line)
    
    # Flush to ensure data is written to disk immediately
    file_handle.flush()


def compute_transcript_hash(transcript_path):
    """
    Compute SHA-256 hash of the entire transcript.
    
    Process:
    1. Read all lines from the transcript file
    2. Concatenate all lines (including newlines)
    3. Compute SHA-256 hash of the concatenated data
    4. Return hex-encoded hash
    
    Parameters:
        transcript_path (str): Path to the transcript file
        
    Returns:
        str: Hex-encoded SHA-256 hash of the transcript
    """
    # Read all lines from the transcript file
    with open(transcript_path, 'r') as f:
        transcript_content = f.read()
    
    # Convert to bytes for hashing
    transcript_bytes = transcript_content.encode('utf-8')
    
    # Compute SHA-256 hash
    hash_digest = hashlib.sha256(transcript_bytes).digest()
    
    # Convert to hex string
    transcript_hash = hash_digest.hex()
    
    return transcript_hash


def generate_session_receipt(transcript_path, private_key, peer_name, first_seq, last_seq):
    """
    Generate a session receipt for non-repudiation.
    
    Process:
    1. Compute transcript hash
    2. Sign the transcript hash with private key
    3. Create receipt JSON object
    4. Return receipt dictionary
    
    Receipt format:
    {
        "type": "receipt",
        "peer": "client" or "server",
        "first_seq": first_sequence_number,
        "last_seq": last_sequence_number,
        "transcript_sha256": hex_encoded_hash,
        "sig": base64_encoded_signature
    }
    
    Parameters:
        transcript_path (str): Path to the transcript file
        private_key: RSA private key object for signing
        peer_name (str): Name of the peer ("client" or "server")
        first_seq (int): First sequence number in the session
        last_seq (int): Last sequence number in the session
        
    Returns:
        dict: Session receipt dictionary
    """
    import base64
    
    # Step 1: Compute transcript hash
    transcript_hash = compute_transcript_hash(transcript_path)
    
    # Step 2: Sign the transcript hash
    # Convert hex hash to bytes for signing
    transcript_hash_bytes = bytes.fromhex(transcript_hash)
    
    # Sign the hash with private key
    signature = sign_data(transcript_hash_bytes, private_key)
    
    # Encode signature in base64 for JSON
    signature_base64 = base64.b64encode(signature).decode('utf-8')
    
    # Step 3: Create receipt dictionary
    receipt = {
        "type": "receipt",
        "peer": peer_name,
        "first_seq": first_seq,
        "last_seq": last_seq,
        "transcript_sha256": transcript_hash,
        "sig": signature_base64
    }
    
    return receipt


def save_receipt(receipt, session_id, entity_name):
    """
    Save a session receipt to a JSON file.
    
    Creates a file in the receipts/ directory with the format:
    receipts/session_{session_id}_{entity_name}_receipt.json
    
    Parameters:
        receipt (dict): Session receipt dictionary
        session_id (str): Unique identifier for the session
        entity_name (str): Name of the entity ("client" or "server")
    """
    # Ensure receipts directory exists
    receipts_dir = "receipts"
    if not os.path.exists(receipts_dir):
        os.makedirs(receipts_dir)
    
    # Create receipt file path
    receipt_path = os.path.join(receipts_dir, f"session_{session_id}_{entity_name}_receipt.json")
    
    # Write receipt to JSON file
    with open(receipt_path, 'w') as f:
        json.dump(receipt, f, indent=2)
    
    print(f"Session receipt saved to {receipt_path}")
