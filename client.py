"""
Secure Chat System - Client Application

This is the client-side console application that:
1. Connects to the server via TCP socket
2. Exchanges and validates certificates (Control Plane)
3. Performs temporary DH for credential encryption
4. Handles user registration or login
5. Establishes session key via DH (Key Agreement)
6. Sends and receives encrypted, signed messages (Data Plane)
7. Generates session receipts (Non-Repudiation)

Assignment Reference: Section 2 - System Requirements, client application
Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 3.1-3.8, 4.1-4.9
"""

import socket
import os
import sys
import base64
import hashlib
import secrets
import time
import threading
import json
from dotenv import load_dotenv

# Import utility modules
import crypto_utils
import protocol
import transcript_utils


def perform_session_closure(transcript_path, session_id, client_key, state):
    """
    Perform session closure and generate session receipt for non-repudiation.
    
    Process:
    1. Compute transcript hash using compute_transcript_hash()
    2. Generate session receipt using generate_session_receipt()
    3. Sign transcript hash with client private key
    4. Save receipt to receipts/session_{id}_client_receipt.json
    
    Args:
        transcript_path: Path to the transcript file
        session_id: Unique session identifier
        client_key: Client's RSA private key for signing
        state: Session state object containing sequence numbers
    
    Assignment Reference: Section 1.4 - Non-Repudiation, Section 2.5 - Session Closure
    Requirements: 10.1, 10.2, 10.3, 10.4, 10.5, 10.6
    """
    print("Computing transcript hash...")
    
    # Step 1: Compute transcript hash
    try:
        transcript_hash = transcript_utils.compute_transcript_hash(transcript_path)
        print(f"[INFO] Transcript hash: {transcript_hash[:32]}...")
    except Exception as e:
        print(f"[ERROR] Failed to compute transcript hash: {e}")
        return
    
    # Step 2: Generate session receipt
    print("Generating session receipt...")
    
    # Determine first and last sequence numbers
    # For client, we track both sent and received messages
    # The last_seq should be the maximum of send_seqno - 1 (last sent) or recv_seqno (last received)
    with state.lock:
        first_seq = state.first_seq
        last_seq = max(state.send_seqno - 1, state.recv_seqno)
    
    try:
        receipt = transcript_utils.generate_session_receipt(
            transcript_path,
            client_key,
            "server",  # peer name from client's perspective
            first_seq,
            last_seq
        )
        
        print(f"[INFO] Session receipt generated")
        print(f"[INFO] First sequence: {first_seq}, Last sequence: {last_seq}")
        
    except Exception as e:
        print(f"[ERROR] Failed to generate session receipt: {e}")
        return
    
    # Step 3: Save receipt to file
    print("Saving session receipt...")
    
    try:
        transcript_utils.save_receipt(receipt, session_id, "client")
        print(f"[SUCCESS] Session receipt saved")
        
    except Exception as e:
        print(f"[ERROR] Failed to save session receipt: {e}")
        return
    
    print("Session closure complete")


def main():
    """
    Main client application entry point.
    
    Handles:
    - Loading certificates and keys
    - Connecting to server
    - Certificate exchange and validation
    - User authentication (register or login)
    """
    print("=== Secure Chat System - Client ===\n")
    
    # Load environment variables
    load_dotenv()
    
    # Get server connection details from environment
    server_host = os.getenv('SERVER_HOST', '127.0.0.1')
    server_port = int(os.getenv('SERVER_PORT', '8443'))
    
    # Load client certificate and private key
    print("Loading client certificate and private key...")
    client_cert = crypto_utils.load_certificate('certs/client_cert.pem')
    client_key = crypto_utils.load_private_key('certs/client_key.pem')
    
    if client_cert is None or client_key is None:
        print("ERROR: Failed to load client certificate or private key")
        print("ERROR: Please run: python scripts/gen_cert.py client")
        sys.exit(1)
    
    # Load CA certificate
    print("Loading CA certificate...")
    ca_cert = crypto_utils.load_certificate('certs/ca_cert.pem')
    
    if ca_cert is None:
        print("ERROR: Failed to load CA certificate")
        print("ERROR: Please run: python scripts/gen_ca.py")
        sys.exit(1)
    
    print("Certificates loaded successfully\n")
    
    # Connect to server via TCP socket
    print(f"[INFO] Connecting to server at {server_host}:{server_port}...")
    
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((server_host, server_port))
        print("Connected to server\n")
    except Exception as e:
        print(f"[ERROR] Failed to connect to server: {e}")
        sys.exit(1)
    
    # Phase 1: Control Plane - Certificate Exchange
    print("=== Phase 1: Certificate Exchange ===")
    
    try:
        # Perform certificate exchange and validation
        server_cert = exchange_certificates(client_socket, client_cert, ca_cert)
        
        if server_cert is None:
            print("ERROR: Certificate exchange failed")
            client_socket.close()
            sys.exit(1)
        
        print("Certificate exchange successful\n")
        
        # Phase 1: Control Plane - Temporary DH for Credential Encryption
        print("=== Phase 1: Temporary DH Key Exchange ===")
        
        # Perform temporary DH exchange for credential encryption
        temp_aes_key = perform_temporary_dh(client_socket)
        
        if temp_aes_key is None:
            print("ERROR: Temporary DH key exchange failed")
            client_socket.close()
            sys.exit(1)
        
        print("Temporary session key established\n")
        
        # Phase 1: Control Plane - Authentication (Register or Login)
        print("=== Phase 1: Authentication ===")
        
        # Prompt user for authentication choice
        auth_success = handle_authentication(client_socket, temp_aes_key)
        
        if not auth_success:
            print("ERROR: Authentication failed")
            client_socket.close()
            sys.exit(1)
        
        print("Authentication successful\n")
        print("=== Control Plane Complete ===\n")
        
        # Phase 2: Key Agreement - Session DH Exchange
        print("=== Phase 2: Session Key Agreement ===")
        
        # Perform session DH exchange for chat encryption
        session_aes_key = perform_session_dh(client_socket)
        
        if session_aes_key is None:
            print("ERROR: Session DH key exchange failed")
            client_socket.close()
            sys.exit(1)
        
        print("Session encryption key established\n")
        print("=== Key Agreement Complete ===\n")
        
        # Phase 3: Data Plane - Message Exchange
        print("=== Phase 3: Encrypted Chat ===")
        print("Starting encrypted chat session...")
        print("Type your messages and press Enter to send")
        print("Type 'exit' to end the chat session\n")
        
        # Start encrypted chat session
        chat_session(client_socket, session_aes_key, client_key, server_cert)
        
        # Close connection
        client_socket.close()
        print("\n[INFO] Connection closed")
        
    except Exception as e:
        print(f"[ERROR] Unexpected error: {e}")
        client_socket.close()
        sys.exit(1)


def exchange_certificates(client_socket, client_cert, ca_cert):
    """
    Exchange certificates with server and validate server certificate.
    
    Process:
    1. Generate random nonce
    2. Send hello message with client certificate and nonce
    3. Receive server_hello message with server certificate and nonce
    4. Validate server certificate using CA
    
    Args:
        client_socket: Connected socket to server
        client_cert: Client's X.509 certificate
        ca_cert: Trusted CA certificate
    
    Returns:
        Certificate: Server's validated certificate, or None if validation fails
    
    Assignment Reference: Section 1.1 - Control Plane, certificate exchange
    Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 14.1
    """
    # Step 1: Generate random nonce (16 bytes)
    nonce_bytes = secrets.token_bytes(16)
    nonce_base64 = base64.b64encode(nonce_bytes).decode('utf-8')
    
    print(f"[INFO] Generated client nonce: {nonce_base64[:16]}...")
    
    # Step 2: Get client certificate in PEM format
    from cryptography.hazmat.primitives import serialization
    
    client_cert_pem = client_cert.public_bytes(
        encoding=serialization.Encoding.PEM
    ).decode('utf-8')
    
    # Step 3: Create and send hello message
    hello_msg = protocol.create_hello_msg(client_cert_pem, nonce_base64)
    
    print("Sending hello message with client certificate...")
    protocol.send_message(client_socket, hello_msg)
    
    # Step 4: Receive server_hello message
    print("Waiting for server hello message...")
    server_hello_msg = protocol.receive_message(client_socket)
    
    if server_hello_msg.get('type') != 'server_hello':
        print(f"[ERROR] Expected server_hello, got: {server_hello_msg.get('type')}")
        return None
    
    print("Received server hello message")
    
    # Step 5: Parse server certificate from PEM
    server_cert_pem = server_hello_msg.get('server_cert')
    server_nonce = server_hello_msg.get('nonce')
    
    if server_cert_pem is None or server_nonce is None:
        print("ERROR: Invalid server_hello message format")
        return None
    
    print(f"[INFO] Server nonce: {server_nonce[:16]}...")
    
    # Load server certificate
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    
    try:
        server_cert = x509.load_pem_x509_certificate(
            server_cert_pem.encode('utf-8'),
            default_backend()
        )
    except Exception as e:
        print(f"[ERROR] Failed to parse server certificate: {e}")
        return None
    
    # Step 6: Validate server certificate
    print("Validating server certificate...")
    
    is_valid, error_code = crypto_utils.validate_certificate(server_cert, ca_cert)
    
    if not is_valid:
        print(f"[ERROR] Server certificate validation failed: {error_code}")
        return None
    
    print("Server certificate is valid")
    
    return server_cert


def perform_temporary_dh(client_socket):
    """
    Perform temporary Diffie-Hellman key exchange for credential encryption.
    
    Process:
    1. Generate DH parameters (p, g)
    2. Generate client DH keypair (a, A)
    3. Send dh_client message with g, p, A
    4. Receive dh_server message with B
    5. Compute shared secret Ks and derive temporary AES key
    
    Args:
        client_socket: Connected socket to server
    
    Returns:
        bytes: 16-byte temporary AES key, or None if exchange fails
    
    Assignment Reference: Section 2.2 - Registration and Login, temporary DH
    Requirements: 3.1, 4.1
    """
    # Step 1: Generate DH parameters
    print("Generating DH parameters...")
    p, g = crypto_utils.generate_dh_parameters()
    
    print(f"[INFO] DH parameters: g={g}, p={p.bit_length()} bits")
    
    # Step 2: Generate client DH keypair
    print("Generating client DH keypair...")
    client_private, client_public = crypto_utils.generate_dh_keypair(p, g)
    
    print(f"[INFO] Client public key (A): {str(client_public)[:32]}...")
    
    # Step 3: Send dh_client message
    dh_client_msg = protocol.create_dh_client_msg(g, p, client_public)
    
    print("Sending DH client message...")
    protocol.send_message(client_socket, dh_client_msg)
    
    # Step 4: Receive dh_server message
    print("Waiting for DH server message...")
    dh_server_msg = protocol.receive_message(client_socket)
    
    if dh_server_msg.get('type') != 'dh_server':
        print(f"[ERROR] Expected dh_server, got: {dh_server_msg.get('type')}")
        return None
    
    server_public = dh_server_msg.get('B')
    
    if server_public is None:
        print("ERROR: Invalid dh_server message format")
        return None
    
    print(f"[INFO] Server public key (B): {str(server_public)[:32]}...")
    
    # Step 5: Compute shared secret
    print("Computing shared secret...")
    shared_secret = crypto_utils.compute_shared_secret(server_public, client_private, p)
    
    # Step 6: Derive AES key
    print("Deriving temporary AES key...")
    temp_aes_key = crypto_utils.derive_aes_key(shared_secret)
    
    print(f"[INFO] Temporary AES key derived: {temp_aes_key.hex()[:32]}...")
    
    return temp_aes_key


def perform_session_dh(client_socket):
    """
    Perform session Diffie-Hellman key exchange for chat encryption.
    
    This is a NEW DH exchange performed after successful login to establish
    a session key for encrypting chat messages. This is separate from the
    temporary DH used for credential encryption.
    
    Process:
    1. Generate new DH parameters (p, g)
    2. Generate client DH keypair (a, A)
    3. Send dh_client message with g, p, A
    4. Receive dh_server message with B
    5. Compute shared secret Ks and derive session AES key
    6. Store session key for chat encryption
    
    Args:
        client_socket: Connected socket to server
    
    Returns:
        bytes: 16-byte session AES key, or None if exchange fails
    
    Assignment Reference: Section 1.2 - Key Agreement, Section 2.3 - Session Key Establishment
    Requirements: 5.1, 5.2, 5.5, 5.7, 5.8, 5.9
    """
    # Step 1: Generate new DH parameters
    print("Generating DH parameters for session key...")
    p, g = crypto_utils.generate_dh_parameters()
    
    print(f"[INFO] DH parameters: g={g}, p={p.bit_length()} bits")
    
    # Step 2: Generate client DH keypair
    print("Generating client DH keypair for session...")
    client_private, client_public = crypto_utils.generate_dh_keypair(p, g)
    
    print(f"[INFO] Client public key (A): {str(client_public)[:32]}...")
    
    # Step 3: Send dh_client message
    dh_client_msg = protocol.create_dh_client_msg(g, p, client_public)
    
    print("Sending DH client message for session key...")
    protocol.send_message(client_socket, dh_client_msg)
    
    # Step 4: Receive dh_server message
    print("Waiting for DH server message...")
    dh_server_msg = protocol.receive_message(client_socket)
    
    if dh_server_msg.get('type') != 'dh_server':
        print(f"[ERROR] Expected dh_server, got: {dh_server_msg.get('type')}")
        return None
    
    server_public = dh_server_msg.get('B')
    
    if server_public is None:
        print("ERROR: Invalid dh_server message format")
        return None
    
    print(f"[INFO] Server public key (B): {str(server_public)[:32]}...")
    
    # Step 5: Compute shared secret
    print("Computing shared secret for session...")
    shared_secret = crypto_utils.compute_shared_secret(server_public, client_private, p)
    
    # Step 6: Derive session AES key
    print("Deriving session AES key...")
    session_aes_key = crypto_utils.derive_aes_key(shared_secret)
    
    print(f"[INFO] Session AES key derived: {session_aes_key.hex()[:32]}...")
    
    return session_aes_key


def handle_authentication(client_socket, temp_aes_key):
    """
    Handle user authentication (register or login).
    
    Prompts user to choose between registration and login,
    then performs the selected authentication flow.
    
    Args:
        client_socket: Connected socket to server
        temp_aes_key: 16-byte temporary AES key for encrypting credentials
    
    Returns:
        bool: True if authentication successful, False otherwise
    
    Assignment Reference: Section 2.2 - Registration and Login
    Requirements: 3.2-3.8, 4.2-4.9
    """
    # Prompt user for authentication choice
    print("Choose authentication method:")
    print("1. Register (new user)")
    print("2. Login (existing user)")
    
    choice = input("Enter choice (1 or 2): ").strip()
    
    if choice == '1':
        return handle_registration(client_socket, temp_aes_key)
    elif choice == '2':
        return handle_login(client_socket, temp_aes_key)
    else:
        print("ERROR: Invalid choice")
        return False


def handle_registration(client_socket, temp_aes_key):
    """
    Handle user registration flow.
    
    Process:
    1. Prompt user for email, username, password
    2. Generate random 16-byte salt
    3. Compute salted password hash: SHA-256(salt || password)
    4. Encode salt and pwd_hash in base64
    5. Create register message
    6. Encrypt message with temporary AES key
    7. Send encrypted message to server
    8. Receive and display response
    
    Args:
        client_socket: Connected socket to server
        temp_aes_key: 16-byte temporary AES key for encrypting credentials
    
    Returns:
        bool: True if registration successful, False otherwise
    
    Assignment Reference: Section 2.2 - Registration
    Requirements: 3.2, 3.3, 3.4, 12.1
    """
    print("\n=== User Registration ===")
    
    # Step 1: Prompt user for registration data
    email = input("Enter email: ").strip()
    username = input("Enter username: ").strip()
    password = input("Enter password: ").strip()
    
    if not email or not username or not password:
        print("ERROR: All fields are required")
        return False
    
    # Step 2: Generate random 16-byte salt
    salt_bytes = secrets.token_bytes(16)
    
    print(f"[INFO] Generated salt: {salt_bytes.hex()[:32]}...")
    
    # Step 3: Compute salted password hash: SHA-256(salt || password)
    password_bytes = password.encode('utf-8')
    salted_input = salt_bytes + password_bytes
    pwd_hash_bytes = hashlib.sha256(salted_input).digest()
    
    print(f"[INFO] Computed password hash: {pwd_hash_bytes.hex()[:32]}...")
    
    # Step 4: Encode salt and pwd_hash in base64
    salt_base64 = base64.b64encode(salt_bytes).decode('utf-8')
    pwd_hash_base64 = base64.b64encode(pwd_hash_bytes).decode('utf-8')
    
    # Step 5: Create register message
    register_msg = protocol.create_register_msg(email, username, pwd_hash_base64, salt_base64)
    
    # Step 6: Encrypt message with temporary AES key
    print("Encrypting registration data...")
    
    # Convert message to JSON bytes
    import json
    register_json = json.dumps(register_msg)
    register_bytes = register_json.encode('utf-8')
    
    # Encrypt with temporary AES key
    encrypted_register = crypto_utils.aes_encrypt(register_bytes, temp_aes_key)
    
    # Encode encrypted data in base64
    encrypted_register_base64 = base64.b64encode(encrypted_register).decode('utf-8')
    
    # Step 7: Send encrypted message to server
    encrypted_msg = {
        "type": "encrypted_auth",
        "payload": encrypted_register_base64
    }
    
    print("Sending encrypted registration data to server...")
    protocol.send_message(client_socket, encrypted_msg)
    
    # Step 8: Receive and display response
    print("Waiting for server response...")
    response = protocol.receive_message(client_socket)
    
    response_type = response.get('type')
    response_status = response.get('status')
    response_message = response.get('message', '')
    
    if response_status == 'success':
        print(f"[SUCCESS] Registration successful: {response_message}")
        return True
    else:
        print(f"[ERROR] Registration failed: {response_message}")
        return False


def handle_login(client_socket, temp_aes_key):
    """
    Handle user login flow.
    
    Process:
    1. Prompt user for email and password
    2. Request salt from server for the email
    3. Compute salted password hash: SHA-256(salt || password)
    4. Encode pwd_hash in base64
    5. Create login message with nonce
    6. Encrypt message with temporary AES key
    7. Send encrypted message to server
    8. Receive and display response
    
    Args:
        client_socket: Connected socket to server
        temp_aes_key: 16-byte temporary AES key for encrypting credentials
    
    Returns:
        bool: True if login successful, False otherwise
    
    Assignment Reference: Section 2.2 - Login
    Requirements: 4.2, 4.3, 4.4, 12.2
    """
    print("\n=== User Login ===")
    
    # Step 1: Prompt user for login credentials
    email = input("Enter email: ").strip()
    password = input("Enter password: ").strip()
    
    if not email or not password:
        print("ERROR: Email and password are required")
        return False
    
    # Step 2: Request salt from server
    print("Requesting salt from server...")
    
    salt_request_msg = {
        "type": "get_salt",
        "email": email
    }
    
    protocol.send_message(client_socket, salt_request_msg)
    
    # Receive salt response
    salt_response = protocol.receive_message(client_socket)
    
    if salt_response.get('status') != 'success':
        print(f"[ERROR] Failed to retrieve salt: {salt_response.get('message', 'Unknown error')}")
        return False
    
    salt_base64 = salt_response.get('salt')
    
    if salt_base64 is None:
        print("ERROR: Invalid salt response")
        return False
    
    # Decode salt from base64
    salt_bytes = base64.b64decode(salt_base64)
    
    print(f"[INFO] Received salt: {salt_bytes.hex()[:32]}...")
    
    # Step 3: Compute salted password hash: SHA-256(salt || password)
    password_bytes = password.encode('utf-8')
    salted_input = salt_bytes + password_bytes
    pwd_hash_bytes = hashlib.sha256(salted_input).digest()
    
    print(f"[INFO] Computed password hash: {pwd_hash_bytes.hex()[:32]}...")
    
    # Step 4: Encode pwd_hash in base64
    pwd_hash_base64 = base64.b64encode(pwd_hash_bytes).decode('utf-8')
    
    # Generate nonce for login
    nonce_bytes = secrets.token_bytes(16)
    nonce_base64 = base64.b64encode(nonce_bytes).decode('utf-8')
    
    # Step 5: Create login message
    login_msg = protocol.create_login_msg(email, pwd_hash_base64, nonce_base64)
    
    # Step 6: Encrypt message with temporary AES key
    print("Encrypting login data...")
    
    # Convert message to JSON bytes
    import json
    login_json = json.dumps(login_msg)
    login_bytes = login_json.encode('utf-8')
    
    # Encrypt with temporary AES key
    encrypted_login = crypto_utils.aes_encrypt(login_bytes, temp_aes_key)
    
    # Encode encrypted data in base64
    encrypted_login_base64 = base64.b64encode(encrypted_login).decode('utf-8')
    
    # Step 7: Send encrypted message to server
    encrypted_msg = {
        "type": "encrypted_auth",
        "payload": encrypted_login_base64
    }
    
    print("Sending encrypted login data to server...")
    protocol.send_message(client_socket, encrypted_msg)
    
    # Step 8: Receive and display response
    print("Waiting for server response...")
    response = protocol.receive_message(client_socket)
    
    response_type = response.get('type')
    response_status = response.get('status')
    response_message = response.get('message', '')
    
    if response_status == 'success':
        print(f"[SUCCESS] Login successful: {response_message}")
        return True
    else:
        print(f"[ERROR] Login failed: {response_message}")
        return False


def chat_session(client_socket, session_aes_key, client_key, server_cert):
    """
    Handle encrypted chat session with message exchange.
    
    Uses threading to handle sending and receiving messages simultaneously.
    
    Process:
    1. Create transcript file for session
    2. Start receiving thread
    3. Start sending loop (main thread)
    4. Handle graceful shutdown
    5. Generate session receipt for non-repudiation
    
    Args:
        client_socket: Connected socket to server
        session_aes_key: 16-byte session AES key for encryption
        client_key: Client's RSA private key for signing
        server_cert: Server's X.509 certificate for verification
    
    Assignment Reference: Section 2.4 - Encrypted Chat, Section 2.5 - Session Closure
    Requirements: 6.1-6.14, 10.1-10.6
    """
    # Generate unique session ID
    session_id = secrets.token_hex(8)
    
    # Create transcript file
    transcript_path = transcript_utils.create_transcript_file(session_id)
    transcript_file = open(transcript_path, 'a')
    
    print(f"[INFO] Transcript file created: {transcript_path}")
    
    # Get server certificate fingerprint
    server_fingerprint = crypto_utils.get_cert_fingerprint(server_cert)
    
    # Shared state for threading
    class SessionState:
        def __init__(self):
            self.send_seqno = 1
            self.recv_seqno = 1
            self.running = True
            self.lock = threading.Lock()
            self.first_seq = 1
            self.last_seq = 1
    
    state = SessionState()
    
    # Start receiving thread
    receive_thread = threading.Thread(
        target=receive_messages,
        args=(client_socket, session_aes_key, server_cert, transcript_file, server_fingerprint, state)
    )
    receive_thread.daemon = True
    receive_thread.start()
    
    # Sending loop (main thread)
    try:
        while state.running:
            # Get user input
            message = input()
            
            # Check for exit command
            if message.lower() == 'exit':
                print("Ending chat session...")
                state.running = False
                break
            
            # Skip empty messages
            if not message.strip():
                continue
            
            # Send the message
            send_message(
                client_socket,
                message,
                session_aes_key,
                client_key,
                transcript_file,
                server_fingerprint,
                state
            )
    
    except KeyboardInterrupt:
        print("\n[INFO] Chat interrupted by user")
        state.running = False
    
    except Exception as e:
        print(f"[ERROR] Chat error: {e}")
        state.running = False
    
    finally:
        # Wait for receive thread to finish
        time.sleep(0.5)
        
        # Close transcript file
        transcript_file.close()
        
        print(f"[INFO] Chat session ended")
        print(f"[INFO] Transcript saved to: {transcript_path}")
        
        # Phase 4: Teardown - Non-Repudiation
        print("\n=== Phase 4: Session Closure ===")
        
        # Perform session closure and generate receipt
        perform_session_closure(transcript_path, session_id, client_key, state)


def send_message(client_socket, plaintext, session_aes_key, client_key, transcript_file, server_fingerprint, state):
    """
    Send an encrypted and signed message to the server.
    
    Process:
    1. Get current sequence number
    2. Apply PKCS7 padding to plaintext
    3. Encrypt with session AES key
    4. Get current timestamp in Unix milliseconds
    5. Compute digest: SHA-256(seqno || timestamp || ciphertext)
    6. Sign digest with client private key
    7. Encode ciphertext and signature in base64
    8. Create chat message with seqno, timestamp, ct, sig
    9. Send message to server
    10. Append to transcript: seqno|ts|ct|sig|server_cert_fingerprint
    11. Increment send_seqno
    
    Args:
        client_socket: Connected socket to server
        plaintext: Message text to send
        session_aes_key: 16-byte session AES key
        client_key: Client's RSA private key for signing
        transcript_file: Open file handle for transcript
        server_fingerprint: Server certificate fingerprint
        state: Shared session state object
    
    Assignment Reference: Section 1.3 - Data Plane, Section 2.4 - Encrypted Chat
    Requirements: 6.1, 6.2, 6.3, 6.4, 6.5, 6.6, 6.7, 9.2
    """
    with state.lock:
        # Step 1: Get current sequence number
        seqno = state.send_seqno
        
        # Step 2: Convert plaintext to bytes
        plaintext_bytes = plaintext.encode('utf-8')
        
        # Step 3: Encrypt with session AES key (includes PKCS7 padding)
        ciphertext_bytes = crypto_utils.aes_encrypt(plaintext_bytes, session_aes_key)
        
        # Step 4: Get current timestamp in Unix milliseconds
        timestamp = int(time.time() * 1000)
        
        # Step 5: Encode ciphertext in base64
        ciphertext_base64 = base64.b64encode(ciphertext_bytes).decode('utf-8')
        
        # Step 6: Compute digest: SHA-256(seqno || timestamp || ciphertext)
        # Convert seqno and timestamp to bytes
        seqno_bytes = str(seqno).encode('utf-8')
        timestamp_bytes = str(timestamp).encode('utf-8')
        
        # Concatenate for digest
        digest_input = seqno_bytes + timestamp_bytes + ciphertext_bytes
        
        # Compute SHA-256 hash
        digest = hashlib.sha256(digest_input).digest()
        
        # Step 7: Sign digest with client private key
        signature = crypto_utils.sign_data(digest, client_key)
        
        # Step 8: Encode signature in base64
        signature_base64 = base64.b64encode(signature).decode('utf-8')
        
        # Step 9: Create chat message
        chat_msg = protocol.create_chat_msg(seqno, timestamp, ciphertext_base64, signature_base64)
        
        # Step 10: Send message to server
        protocol.send_message(client_socket, chat_msg)
        
        # Step 11: Append to transcript
        transcript_utils.append_to_transcript(
            transcript_file,
            seqno,
            timestamp,
            ciphertext_base64,
            signature_base64,
            server_fingerprint
        )
        
        # Step 12: Update last_seq and increment send_seqno
        state.last_seq = seqno
        state.send_seqno += 1
        
        print(f"You: {plaintext}")


def receive_messages(client_socket, session_aes_key, server_cert, transcript_file, server_fingerprint, state):
    """
    Receive and process encrypted messages from the server.
    
    Runs in a separate thread to handle incoming messages.
    
    Process:
    1. Receive chat message from server
    2. Extract seqno, timestamp, ciphertext, signature
    3. Check seqno is strictly greater than last received (replay protection)
    4. If seqno <= last, log REPLAY and reject message
    5. Recompute digest: SHA-256(seqno || timestamp || ciphertext)
    6. Verify signature using server public key
    7. If signature invalid, log SIG_FAIL and reject message
    8. Decrypt ciphertext with session AES key
    9. Remove PKCS7 padding
    10. Display plaintext message
    11. Append to transcript: seqno|ts|ct|sig|server_cert_fingerprint
    12. Update recv_seqno
    
    Args:
        client_socket: Connected socket to server
        session_aes_key: 16-byte session AES key
        server_cert: Server's X.509 certificate
        transcript_file: Open file handle for transcript
        server_fingerprint: Server certificate fingerprint
        state: Shared session state object
    
    Assignment Reference: Section 1.3 - Data Plane, Section 2.4 - Message Integrity
    Requirements: 6.8, 6.9, 6.10, 6.11, 6.12, 6.13, 6.14, 7.3, 7.4, 7.5, 8.1, 8.2, 8.3, 8.4, 8.5, 9.2, 14.2, 14.3
    """
    # Get server public key for signature verification
    server_public_key = crypto_utils.get_public_key_from_cert(server_cert)
    
    while state.running:
        try:
            # Step 1: Receive chat message from server
            msg = protocol.receive_message(client_socket)
            
            # Check message type
            if msg.get('type') != 'msg':
                # Handle other message types or errors
                if msg.get('type') == 'error':
                    print(f"[ERROR] Server error: {msg.get('message', 'Unknown error')}")
                continue
            
            # Step 2: Extract message fields
            seqno = msg.get('seqno')
            timestamp = msg.get('ts')
            ciphertext_base64 = msg.get('ct')
            signature_base64 = msg.get('sig')
            
            if seqno is None or timestamp is None or ciphertext_base64 is None or signature_base64 is None:
                print("ERROR: Invalid message format")
                continue
            
            with state.lock:
                # Step 3: Check sequence number (replay protection)
                if seqno <= state.recv_seqno:
                    print(f"[REPLAY] Received seqno={seqno}, expected seqno>{state.recv_seqno}")
                    continue
                
                # Step 4: Decode ciphertext and signature from base64
                ciphertext_bytes = base64.b64decode(ciphertext_base64)
                signature_bytes = base64.b64decode(signature_base64)
                
                # Step 5: Recompute digest: SHA-256(seqno || timestamp || ciphertext)
                seqno_bytes = str(seqno).encode('utf-8')
                timestamp_bytes = str(timestamp).encode('utf-8')
                
                digest_input = seqno_bytes + timestamp_bytes + ciphertext_bytes
                digest = hashlib.sha256(digest_input).digest()
                
                # Step 6: Verify signature using server public key
                is_valid = crypto_utils.verify_signature(digest, signature_bytes, server_public_key)
                
                if not is_valid:
                    print(f"[SIG_FAIL] Message seqno={seqno} signature verification failed")
                    continue
                
                # Step 7: Decrypt ciphertext with session AES key
                try:
                    plaintext_bytes = crypto_utils.aes_decrypt(ciphertext_bytes, session_aes_key)
                    plaintext = plaintext_bytes.decode('utf-8')
                except Exception as e:
                    print(f"[ERROR] Decryption failed for seqno={seqno}: {e}")
                    continue
                
                # Step 8: Display plaintext message
                print(f"Server: {plaintext}")
                
                # Step 9: Append to transcript
                transcript_utils.append_to_transcript(
                    transcript_file,
                    seqno,
                    timestamp,
                    ciphertext_base64,
                    signature_base64,
                    server_fingerprint
                )
                
                # Step 10: Update recv_seqno and last_seq
                state.recv_seqno = seqno
                state.last_seq = max(state.last_seq, seqno)
        
        except Exception as e:
            if state.running:
                print(f"[ERROR] Receive error: {e}")
            break


if __name__ == "__main__":
    main()
