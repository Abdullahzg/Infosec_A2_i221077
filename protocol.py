"""
Message Protocol Module

This module provides functions to create and format all message types
used in the Secure Chat System protocol. All functions return Python
dictionaries that will be JSON-encoded for transmission.

Assignment Reference: Section 1 - Secure Chat Protocol
"""

import json
import struct


# ============================================================================
# Message Formatting Functions
# ============================================================================

def create_hello_msg(cert_pem, nonce):
    """
    Create a hello message for client certificate exchange.
    
    Args:
        cert_pem (str): Client certificate in PEM format
        nonce (str): Base64-encoded random nonce
    
    Returns:
        dict: Hello message dictionary
    
    Assignment Reference: Section 1.1 - Control Plane
    Requirements: 2.1
    """
    msg = {
        "type": "hello",
        "client_cert": cert_pem,
        "nonce": nonce
    }
    return msg


def create_server_hello_msg(cert_pem, nonce):
    """
    Create a server hello message for server certificate exchange.
    
    Args:
        cert_pem (str): Server certificate in PEM format
        nonce (str): Base64-encoded random nonce
    
    Returns:
        dict: Server hello message dictionary
    
    Assignment Reference: Section 1.1 - Control Plane
    Requirements: 2.2
    """
    msg = {
        "type": "server_hello",
        "server_cert": cert_pem,
        "nonce": nonce
    }
    return msg


def create_register_msg(email, username, pwd_hash, salt):
    """
    Create a registration message with user credentials.
    
    Args:
        email (str): User email address
        username (str): User username
        pwd_hash (str): Base64-encoded salted password hash
        salt (str): Base64-encoded salt
    
    Returns:
        dict: Registration message dictionary
    
    Assignment Reference: Section 1.1 - Control Plane
    Requirements: 3.4
    """
    msg = {
        "type": "register",
        "email": email,
        "username": username,
        "pwd": pwd_hash,
        "salt": salt
    }
    return msg


def create_login_msg(email, pwd_hash, nonce):
    """
    Create a login message with user credentials.
    
    Args:
        email (str): User email address
        pwd_hash (str): Base64-encoded salted password hash
        nonce (str): Base64-encoded random nonce
    
    Returns:
        dict: Login message dictionary
    
    Assignment Reference: Section 1.1 - Control Plane
    Requirements: 4.4
    """
    msg = {
        "type": "login",
        "email": email,
        "pwd": pwd_hash,
        "nonce": nonce
    }
    return msg


def create_dh_client_msg(g, p, A):
    """
    Create a Diffie-Hellman client message with DH parameters.
    
    Args:
        g (int): DH generator
        p (int): DH prime modulus
        A (int): Client's DH public value (g^a mod p)
    
    Returns:
        dict: DH client message dictionary
    
    Assignment Reference: Section 1.2 - Key Agreement
    Requirements: 5.2
    """
    msg = {
        "type": "dh_client",
        "g": g,
        "p": p,
        "A": A
    }
    return msg


def create_dh_server_msg(B):
    """
    Create a Diffie-Hellman server message with server's public value.
    
    Args:
        B (int): Server's DH public value (g^b mod p)
    
    Returns:
        dict: DH server message dictionary
    
    Assignment Reference: Section 1.2 - Key Agreement
    Requirements: 5.4
    """
    msg = {
        "type": "dh_server",
        "B": B
    }
    return msg


def create_chat_msg(seqno, timestamp, ciphertext, signature):
    """
    Create a chat message with encrypted content and signature.
    
    Args:
        seqno (int): Message sequence number
        timestamp (int): Unix timestamp in milliseconds
        ciphertext (str): Base64-encoded encrypted message
        signature (str): Base64-encoded RSA signature
    
    Returns:
        dict: Chat message dictionary
    
    Assignment Reference: Section 1.3 - Data Plane
    Requirements: 6.7
    """
    msg = {
        "type": "msg",
        "seqno": seqno,
        "ts": timestamp,
        "ct": ciphertext,
        "sig": signature
    }
    return msg


def create_receipt_msg(peer, first_seq, last_seq, transcript_hash, signature):
    """
    Create a session receipt message for non-repudiation.
    
    Args:
        peer (str): Peer identifier ("client" or "server")
        first_seq (int): First sequence number in session
        last_seq (int): Last sequence number in session
        transcript_hash (str): Hex-encoded SHA-256 hash of transcript
        signature (str): Base64-encoded RSA signature of transcript hash
    
    Returns:
        dict: Receipt message dictionary
    
    Assignment Reference: Section 1.4 - Non-Repudiation
    Requirements: 10.5
    """
    msg = {
        "type": "receipt",
        "peer": peer,
        "first_seq": first_seq,
        "last_seq": last_seq,
        "transcript_sha256": transcript_hash,
        "sig": signature
    }
    return msg


# ============================================================================
# Message Transmission Functions
# ============================================================================

def send_message(socket, msg_dict):
    """
    Send a message over a socket with length prefix.
    
    Converts the message dictionary to JSON, encodes to bytes,
    and sends with a 4-byte length prefix.
    
    Args:
        socket: Socket object to send message through
        msg_dict (dict): Message dictionary to send
    
    Returns:
        None
    
    Assignment Reference: Section 1 - Secure Chat Protocol
    Requirements: 6.7
    """
    # Convert dictionary to JSON string
    json_string = json.dumps(msg_dict)
    
    # Encode JSON string to bytes
    message_bytes = json_string.encode('utf-8')
    
    # Get message length
    message_length = len(message_bytes)
    
    # Create 4-byte length prefix (big-endian unsigned int)
    length_prefix = struct.pack('>I', message_length)
    
    # Send length prefix
    socket.sendall(length_prefix)
    
    # Send message bytes
    socket.sendall(message_bytes)


def receive_message(socket):
    """
    Receive a message from a socket with length prefix.
    
    Receives a 4-byte length prefix, then receives the message bytes,
    decodes JSON, and returns the message dictionary.
    
    Args:
        socket: Socket object to receive message from
    
    Returns:
        dict: Received message dictionary
    
    Assignment Reference: Section 1 - Secure Chat Protocol
    Requirements: 6.7
    """
    # Receive 4-byte length prefix
    length_prefix = receive_exact(socket, 4)
    
    # Unpack length (big-endian unsigned int)
    message_length = struct.unpack('>I', length_prefix)[0]
    
    # Receive message bytes
    message_bytes = receive_exact(socket, message_length)
    
    # Decode bytes to JSON string
    json_string = message_bytes.decode('utf-8')
    
    # Parse JSON string to dictionary
    msg_dict = json.loads(json_string)
    
    return msg_dict


def receive_exact(socket, num_bytes):
    """
    Receive exactly num_bytes from socket, handling partial receives.
    
    This helper function ensures we receive the exact number of bytes
    requested, even if socket.recv() returns fewer bytes.
    
    Args:
        socket: Socket object to receive from
        num_bytes (int): Exact number of bytes to receive
    
    Returns:
        bytes: Received bytes
    """
    data = b''
    bytes_received = 0
    
    while bytes_received < num_bytes:
        # Receive remaining bytes
        chunk = socket.recv(num_bytes - bytes_received)
        
        # Check if connection closed
        if len(chunk) == 0:
            raise ConnectionError("Socket connection closed")
        
        # Append chunk to data
        data = data + chunk
        
        # Update bytes received count
        bytes_received = bytes_received + len(chunk)
    
    return data
