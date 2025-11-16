"""
Secure Chat System - Server Application

This is the server-side console application that:
- Accepts client connections
- Validates client certificates
- Handles user registration and login
- Manages encrypted chat sessions
- Generates session receipts for non-repudiation

Assignment Reference: Section 2 - System Requirements, server application
Requirements: 2.1, 2.2
"""

import socket
import os
import base64
import secrets
import hashlib
import json
from datetime import datetime
from dotenv import load_dotenv

# Import utility modules
import crypto_utils
import db_utils
import protocol
import transcript_utils


def main():
    """
    Main server function.
    
    Process:
    1. Load server certificate, private key, and CA certificate
    2. Connect to MySQL database
    3. Create TCP socket and bind to SERVER_HOST:SERVER_PORT
    4. Listen for connections
    5. Accept client connections and handle each
    """
    print("=== Secure Chat Server ===")
    print("Starting server...")
    
    # Load environment variables
    load_dotenv()
    server_host = os.getenv('SERVER_HOST', '127.0.0.1')
    server_port = int(os.getenv('SERVER_PORT', '8443'))
    
    # Step 1: Load server certificate and private key
    print("Loading server certificate and private key...")
    server_cert = crypto_utils.load_certificate('certs/server_cert.pem')
    server_private_key = crypto_utils.load_private_key('certs/server_key.pem')
    
    if server_cert is None or server_private_key is None:
        print("ERROR: Failed to load server certificate or private key")
        return
    
    # Load CA certificate for validating client certificates
    print("Loading CA certificate...")
    ca_cert = crypto_utils.load_certificate('certs/ca_cert.pem')
    
    if ca_cert is None:
        print("ERROR: Failed to load CA certificate")
        return
    
    print("Certificates loaded successfully")
    
    # Step 2: Connect to MySQL database
    print("Connecting to database...")
    db_connection = db_utils.connect_database()
    
    if db_connection is None:
        print("ERROR: Failed to connect to database")
        return
    
    # Ensure users table exists
    db_utils.create_users_table(db_connection)
    
    # Step 3: Create TCP socket
    print("Creating TCP socket...")
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Allow socket reuse
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    # Step 4: Bind to address and port
    try:
        server_socket.bind((server_host, server_port))
        print(f"Server bound to {server_host}:{server_port}")
    except Exception as e:
        print(f"ERROR: Failed to bind socket: {e}")
        db_connection.close()
        return
    
    # Step 5: Listen for connections
    server_socket.listen(5)
    print("Server listening for connections...")
    
    try:
        while True:
            # Accept client connection
            print("\nWaiting for client connection...")
            client_socket, client_address = server_socket.accept()
            print(f"Client connected from {client_address}")
            
            # Handle client (single-threaded for now)
            handle_client(client_socket, server_cert, server_private_key, ca_cert, db_connection)
            
    except KeyboardInterrupt:
        print("\nServer shutting down...")
    finally:
        server_socket.close()
        db_connection.close()
        print("Server stopped")


def handle_client(client_socket, server_cert, server_private_key, ca_cert, db_connection):
    """
    Handle a client connection through all phases.
    
    Phase 1: Control Plane
        - Certificate exchange and validation
        - Temporary DH for credential encryption
        - Registration or login
    
    Args:
        client_socket: Socket connection to client
        server_cert: Server's X.509 certificate
        server_private_key: Server's RSA private key
        ca_cert: CA certificate for validation
        db_connection: MySQL database connection
    """
    try:
        # Phase 1: Control Plane
        print("=== Phase 1: Control Plane ===")
        
        # Step 1: Certificate exchange
        client_cert = exchange_certificates(client_socket, server_cert, ca_cert)
        if client_cert is None:
            print("ERROR: Certificate exchange failed")
            client_socket.close()
            return
        
        # Step 2: Temporary DH for credential encryption
        temp_aes_key = perform_temporary_dh(client_socket)
        if temp_aes_key is None:
            print("ERROR: Temporary DH exchange failed")
            client_socket.close()
            return
        
        # Step 3: Handle registration or login
        auth_success = handle_authentication(client_socket, temp_aes_key, db_connection)
        if not auth_success:
            print("ERROR: Authentication failed")
            client_socket.close()
            return
        
        print("Client authenticated successfully")
        
        # Phase 2: Session Key Agreement
        print("=== Phase 2: Session Key Agreement ===")
        
        session_aes_key = perform_session_dh(client_socket)
        if session_aes_key is None:
            print("ERROR: Session DH exchange failed")
            client_socket.close()
            return
        
        print("Session key established successfully")
        
        # Phase 3: Data Plane (Message Exchange)
        print("=== Phase 3: Data Plane (Message Exchange) ===")
        
        chat_session(client_socket, session_aes_key, server_private_key, client_cert)
        
        # TODO: Phase 4 will be implemented in later tasks
        
    except Exception as e:
        print(f"ERROR: Exception handling client: {e}")
    finally:
        client_socket.close()
        print("Client connection closed")


def exchange_certificates(client_socket, server_cert, ca_cert):
    """
    Exchange and validate certificates with the client.
    
    Process:
    1. Receive hello message from client with client certificate
    2. Validate client certificate
    3. Send server_hello message with server certificate
    
    Args:
        client_socket: Socket connection to client
        server_cert: Server's X.509 certificate
        ca_cert: CA certificate for validation
    
    Returns:
        Certificate object if validation succeeds, None otherwise
    
    Assignment Reference: Section 1.1 - Control Plane, certificate exchange
    Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 14.1
    """
    print("Exchanging certificates...")
    
    try:
        # Step 1: Receive hello message from client
        hello_msg = protocol.receive_message(client_socket)
        
        if hello_msg['type'] != 'hello':
            print(f"ERROR: Expected hello message, got {hello_msg['type']}")
            return None
        
        # Extract client certificate from message
        client_cert_pem = hello_msg['client_cert']
        client_nonce = hello_msg['nonce']
        
        print("Received hello message from client")
        
        # Parse client certificate
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        client_cert = x509.load_pem_x509_certificate(
            client_cert_pem.encode('utf-8'),
            default_backend()
        )
        
        # Step 2: Validate client certificate
        is_valid, error_code = crypto_utils.validate_certificate(client_cert, ca_cert)
        
        if not is_valid:
            # Log error and close connection
            print(f"[{error_code}] Client certificate validation failed")
            return None
        
        print("Client certificate validated successfully")
        
        # Step 3: Send server_hello message
        # Convert server certificate to PEM format
        from cryptography.hazmat.primitives import serialization
        server_cert_pem = server_cert.public_bytes(
            encoding=serialization.Encoding.PEM
        ).decode('utf-8')
        
        # Generate server nonce
        server_nonce = base64.b64encode(secrets.token_bytes(16)).decode('utf-8')
        
        # Create and send server_hello message
        server_hello_msg = protocol.create_server_hello_msg(server_cert_pem, server_nonce)
        protocol.send_message(client_socket, server_hello_msg)
        
        print("Sent server_hello message")
        
        return client_cert
        
    except Exception as e:
        print(f"ERROR: Certificate exchange failed: {e}")
        return None


def perform_temporary_dh(client_socket):
    """
    Perform temporary Diffie-Hellman key exchange for credential encryption.
    
    Process:
    1. Receive dh_client message with g, p, A
    2. Generate server DH keypair (b, B)
    3. Send dh_server message with B
    4. Compute shared secret and derive AES key
    
    Args:
        client_socket: Socket connection to client
    
    Returns:
        bytes: 16-byte AES key if successful, None otherwise
    
    Assignment Reference: Section 2.2 - Registration and Login, temporary DH
    Requirements: 3.1, 4.1
    """
    print("Performing temporary DH key exchange...")
    
    try:
        # Step 1: Receive dh_client message
        dh_client_msg = protocol.receive_message(client_socket)
        
        if dh_client_msg['type'] != 'dh_client':
            print(f"ERROR: Expected dh_client message, got {dh_client_msg['type']}")
            return None
        
        # Extract DH parameters
        g = dh_client_msg['g']
        p = dh_client_msg['p']
        A = dh_client_msg['A']
        
        print("Received DH parameters from client")
        
        # Step 2: Generate server DH keypair
        b, B = crypto_utils.generate_dh_keypair(p, g)
        
        # Step 3: Send dh_server message
        dh_server_msg = protocol.create_dh_server_msg(B)
        protocol.send_message(client_socket, dh_server_msg)
        
        print("Sent DH server response")
        
        # Step 4: Compute shared secret and derive AES key
        shared_secret = crypto_utils.compute_shared_secret(A, b, p)
        temp_aes_key = crypto_utils.derive_aes_key(shared_secret)
        
        print("Temporary AES key derived")
        
        return temp_aes_key
        
    except Exception as e:
        print(f"ERROR: Temporary DH exchange failed: {e}")
        return None


def handle_authentication(client_socket, temp_aes_key, db_connection):
    """
    Handle user registration or login.
    
    Process:
    1. Receive authentication message (could be get_salt or encrypted_auth)
    2. If get_salt, send salt and wait for encrypted_auth
    3. Decrypt using temporary AES key
    4. Handle registration or login based on message type
    5. Send response
    
    Args:
        client_socket: Socket connection to client
        temp_aes_key: Temporary AES key for credential encryption
        db_connection: MySQL database connection
    
    Returns:
        bool: True if authentication succeeds, False otherwise
    
    Assignment Reference: Section 2.2 - Registration and Login
    Requirements: 3.2-3.8, 4.2-4.9, 14.3, 14.4
    """
    print("Handling authentication...")
    
    try:
        # Step 1: Receive first message (could be get_salt or encrypted_auth)
        first_msg = protocol.receive_message(client_socket)
        
        # Handle get_salt request for login
        if first_msg['type'] == 'get_salt':
            email = first_msg['email']
            print(f"Received salt request for email: {email}")
            
            # Retrieve salt from database
            salt_bytes = db_utils.get_user_salt(db_connection, email)
            
            if salt_bytes is None:
                # User not found
                response = {
                    "type": "salt_response",
                    "status": "error",
                    "message": "USER_NOT_FOUND"
                }
                protocol.send_message(client_socket, response)
                return False
            
            # Send salt to client
            salt_base64 = base64.b64encode(salt_bytes).decode('utf-8')
            response = {
                "type": "salt_response",
                "status": "success",
                "salt": salt_base64
            }
            protocol.send_message(client_socket, response)
            print("Sent salt to client")
            
            # Now receive the encrypted authentication message
            encrypted_msg = protocol.receive_message(client_socket)
        else:
            encrypted_msg = first_msg
        
        if encrypted_msg['type'] != 'encrypted_auth':
            print(f"ERROR: Expected encrypted_auth message, got {encrypted_msg['type']}")
            return False
        
        # Extract encrypted payload
        encrypted_payload_b64 = encrypted_msg['payload']
        encrypted_payload = base64.b64decode(encrypted_payload_b64)
        
        # Step 2: Decrypt using temporary AES key
        decrypted_payload = crypto_utils.aes_decrypt(encrypted_payload, temp_aes_key)
        
        # Parse decrypted JSON
        auth_msg = json.loads(decrypted_payload.decode('utf-8'))
        
        # Step 3: Handle based on message type
        if auth_msg['type'] == 'register':
            return handle_registration(client_socket, auth_msg, db_connection)
        elif auth_msg['type'] == 'login':
            return handle_login(client_socket, auth_msg, db_connection)
        else:
            print(f"ERROR: Unknown auth message type: {auth_msg['type']}")
            return False
        
    except Exception as e:
        print(f"ERROR: Authentication handling failed: {e}")
        return False


def handle_registration(client_socket, register_msg, db_connection):
    """
    Handle user registration.
    
    Process:
    1. Extract email, username, pwd_hash, salt
    2. Call register_user() from db_utils
    3. Send success or error response
    
    Args:
        client_socket: Socket connection to client
        register_msg: Decrypted registration message
        db_connection: MySQL database connection
    
    Returns:
        bool: True if registration succeeds, False otherwise
    
    Assignment Reference: Section 2.2 - Registration
    Requirements: 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 3.8, 14.3
    """
    print("Processing registration...")
    
    try:
        # Step 1: Extract registration data
        email = register_msg['email']
        username = register_msg['username']
        pwd_hash_b64 = register_msg['pwd']
        salt_b64 = register_msg['salt']
        
        # Decode base64 values
        pwd_hash = base64.b64decode(pwd_hash_b64).hex()
        salt = base64.b64decode(salt_b64)
        
        print(f"Registration request for email: {email}, username: {username}")
        
        # Step 2: Register user in database
        success, message = db_utils.register_user(db_connection, email, username, salt, pwd_hash)
        
        # Step 3: Send response
        if success:
            response = {
                "type": "register_response",
                "status": "success",
                "message": message
            }
            protocol.send_message(client_socket, response)
            print("Registration successful")
            return True
        else:
            response = {
                "type": "register_response",
                "status": "error",
                "message": message
            }
            protocol.send_message(client_socket, response)
            print(f"Registration failed: {message}")
            return False
        
    except Exception as e:
        print(f"ERROR: Registration handling failed: {e}")
        response = {
            "type": "register_response",
            "status": "error",
            "message": str(e)
        }
        protocol.send_message(client_socket, response)
        return False


def handle_login(client_socket, login_msg, db_connection):
    """
    Handle user login.
    
    Process:
    1. Extract email, pwd_hash
    2. Call verify_login() from db_utils
    3. Send success or error response
    
    Args:
        client_socket: Socket connection to client
        login_msg: Decrypted login message
        db_connection: MySQL database connection
    
    Returns:
        bool: True if login succeeds, False otherwise
    
    Assignment Reference: Section 2.2 - Login
    Requirements: 4.2, 4.3, 4.4, 4.5, 4.6, 4.7, 4.8, 4.9, 14.3, 14.4
    """
    print("Processing login...")
    
    try:
        # Step 1: Extract login data
        email = login_msg['email']
        pwd_hash_b64 = login_msg['pwd']
        
        # Decode base64 password hash
        pwd_hash = base64.b64decode(pwd_hash_b64).hex()
        
        print(f"Login request for email: {email}")
        
        # Step 2: Verify login credentials
        success, message = db_utils.verify_login(db_connection, email, pwd_hash)
        
        # Step 3: Send response
        if success:
            response = {
                "type": "login_response",
                "status": "success",
                "message": message
            }
            protocol.send_message(client_socket, response)
            print("Login successful")
            return True
        else:
            response = {
                "type": "login_response",
                "status": "error",
                "message": message
            }
            protocol.send_message(client_socket, response)
            print(f"Login failed: {message}")
            return False
        
    except Exception as e:
        print(f"ERROR: Login handling failed: {e}")
        response = {
            "type": "login_response",
            "status": "error",
            "message": str(e)
        }
        protocol.send_message(client_socket, response)
        return False


def perform_session_dh(client_socket):
    """
    Perform session Diffie-Hellman key exchange for chat encryption.
    
    This is a NEW DH exchange performed after successful login.
    It establishes the session key used for encrypting chat messages.
    
    Process:
    1. Receive dh_client message with g, p, A
    2. Generate server DH keypair (b, B) using received p, g
    3. Send dh_server message with B
    4. Compute shared secret Ks and derive session AES key
    5. Store session key for chat encryption
    
    Args:
        client_socket: Socket connection to client
    
    Returns:
        bytes: 16-byte session AES key if successful, None otherwise
    
    Assignment Reference: Section 1.2 - Key Agreement, Section 2.3 - Session Key Establishment
    Requirements: 5.3, 5.4, 5.6, 5.7, 5.8, 5.9
    """
    print("Performing session DH key exchange...")
    
    try:
        # Step 1: Receive dh_client message from client (new DH exchange)
        dh_client_msg = protocol.receive_message(client_socket)
        
        if dh_client_msg['type'] != 'dh_client':
            print(f"ERROR: Expected dh_client message, got {dh_client_msg['type']}")
            return None
        
        # Extract DH parameters
        g = dh_client_msg['g']
        p = dh_client_msg['p']
        A = dh_client_msg['A']
        
        print("Received session DH parameters from client")
        
        # Step 2: Generate server DH keypair (b, B) using received p, g
        b, B = crypto_utils.generate_dh_keypair(p, g)
        
        print("Generated server DH keypair")
        
        # Step 3: Send dh_server message with B
        dh_server_msg = protocol.create_dh_server_msg(B)
        protocol.send_message(client_socket, dh_server_msg)
        
        print("Sent session DH server response")
        
        # Step 4: Compute shared secret Ks and derive session AES key
        shared_secret = crypto_utils.compute_shared_secret(A, b, p)
        session_aes_key = crypto_utils.derive_aes_key(shared_secret)
        
        print("Session AES key derived successfully")
        
        # Step 5: Store session key for chat encryption (returned to caller)
        return session_aes_key
        
    except Exception as e:
        print(f"ERROR: Session DH exchange failed: {e}")
        return None


def chat_session(client_socket, session_aes_key, server_private_key, client_cert):
    """
    Handle the chat session with encrypted message exchange.
    
    Phase 3: Data Plane
    - Initialize sequence numbers
    - Create transcript file
    - Handle sending and receiving encrypted messages
    - Detect replay attacks and tampering
    - Log all messages to transcript
    
    Phase 4: Teardown (Non-Repudiation)
    - Close transcript file
    - Compute transcript hash
    - Generate session receipt
    - Save receipt to file
    
    Args:
        client_socket: Socket connection to client
        session_aes_key: 16-byte AES key for message encryption
        server_private_key: Server's RSA private key for signing
        client_cert: Client's X.509 certificate for verification
    
    Assignment Reference: Section 1.3 - Data Plane, Section 2.4 - Encrypted Chat, Section 1.4 - Non-Repudiation, Section 2.5 - Session Closure
    Requirements: 6.1-6.14, 7.3-7.5, 8.1-8.5, 9.2, 10.1-10.6, 14.2, 14.3
    """
    import time
    import threading
    
    print("Starting chat session...")
    
    # Initialize sequence numbers
    send_seqno = 1
    recv_seqno = 1
    
    # Create transcript file for session
    session_id = f"{int(time.time())}"
    transcript_path = transcript_utils.create_transcript_file(session_id)
    transcript_file = open(transcript_path, 'a')
    
    print(f"Transcript file created: {transcript_path}")
    
    # Get client certificate fingerprint for transcript
    client_fingerprint = crypto_utils.get_cert_fingerprint(client_cert)
    
    # Shared state for threading
    session_state = {
        'send_seqno': send_seqno,
        'recv_seqno': recv_seqno,
        'running': True,
        'transcript_file': transcript_file,
        'client_fingerprint': client_fingerprint
    }
    
    # Start receive thread
    receive_thread = threading.Thread(
        target=receive_messages,
        args=(client_socket, session_aes_key, client_cert, session_state)
    )
    receive_thread.daemon = True
    receive_thread.start()
    
    print("Chat session ready. Type messages to send (or 'exit' to quit):")
    
    # Send messages loop
    try:
        while session_state['running']:
            # Prompt for message input
            message_input = input()
            
            # Check for exit command
            if message_input.lower() == 'exit':
                print("Closing chat session...")
                session_state['running'] = False
                break
            
            # Send the message
            send_message_to_client(
                client_socket,
                message_input,
                session_aes_key,
                server_private_key,
                session_state
            )
            
    except KeyboardInterrupt:
        print("\nChat session interrupted")
        session_state['running'] = False
    finally:
        # Phase 4: Teardown (Non-Repudiation)
        print("=== Phase 4: Teardown (Non-Repudiation) ===")
        
        # Step 1: Close transcript file
        transcript_file.close()
        print("Transcript file closed")
        
        # Step 2: Compute transcript hash using compute_transcript_hash()
        print("Computing transcript hash...")
        transcript_hash = transcript_utils.compute_transcript_hash(transcript_path)
        print(f"Transcript hash: {transcript_hash}")
        
        # Step 3: Generate session receipt using generate_session_receipt()
        # Determine first and last sequence numbers
        first_seq = 1
        last_seq = session_state['send_seqno'] - 1  # Last sent sequence number
        
        print("Generating session receipt...")
        receipt = transcript_utils.generate_session_receipt(
            transcript_path,
            server_private_key,
            "client",  # peer name
            first_seq,
            last_seq
        )
        
        # Step 4: Save receipt to receipts/session_{id}_server_receipt.json
        print("Saving session receipt...")
        transcript_utils.save_receipt(receipt, session_id, "server")
        
        # Step 5: Optionally send receipt to client
        # For now, we'll just save it locally
        # In a full implementation, we could send it via the socket
        
        print("Chat session ended")


def send_message_to_client(client_socket, plaintext, session_aes_key, server_private_key, session_state):
    """
    Send an encrypted and signed message to the client.
    
    Process:
    1. Apply PKCS7 padding to plaintext
    2. Encrypt with session AES key
    3. Get current timestamp in Unix milliseconds
    4. Compute digest: SHA-256(seqno || timestamp || ciphertext)
    5. Sign digest with server private key
    6. Encode ciphertext and signature in base64
    7. Create chat message with seqno, timestamp, ct, sig
    8. Send message to client
    9. Append to transcript: seqno|ts|ct|sig|client_cert_fingerprint
    10. Increment send_seqno
    
    Args:
        client_socket: Socket connection to client
        plaintext (str): Message to send
        session_aes_key: 16-byte AES key
        server_private_key: Server's RSA private key
        session_state (dict): Shared session state
    
    Assignment Reference: Section 1.3 - Data Plane, Section 2.4 - Encrypted Chat
    Requirements: 6.1, 6.2, 6.3, 6.4, 6.5, 6.6, 6.7, 9.2
    """
    import time
    import base64
    
    try:
        # Get current sequence number
        seqno = session_state['send_seqno']
        
        # Step 1: Convert plaintext to bytes
        plaintext_bytes = plaintext.encode('utf-8')
        
        # Step 2: Encrypt with session AES key (includes PKCS7 padding)
        ciphertext_with_iv = crypto_utils.aes_encrypt(plaintext_bytes, session_aes_key)
        
        # Step 3: Get current timestamp in Unix milliseconds
        timestamp = int(time.time() * 1000)
        
        # Step 4: Compute digest: SHA-256(seqno || timestamp || ciphertext)
        # Concatenate seqno, timestamp, and ciphertext as bytes
        seqno_bytes = str(seqno).encode('utf-8')
        timestamp_bytes = str(timestamp).encode('utf-8')
        
        digest_input = seqno_bytes + timestamp_bytes + ciphertext_with_iv
        digest = hashlib.sha256(digest_input).digest()
        
        # Step 5: Sign digest with server private key
        signature = crypto_utils.sign_data(digest, server_private_key)
        
        # Step 6: Encode ciphertext and signature in base64
        ciphertext_base64 = base64.b64encode(ciphertext_with_iv).decode('utf-8')
        signature_base64 = base64.b64encode(signature).decode('utf-8')
        
        # Step 7: Create chat message
        chat_msg = protocol.create_chat_msg(seqno, timestamp, ciphertext_base64, signature_base64)
        
        # Step 8: Send message to client
        protocol.send_message(client_socket, chat_msg)
        
        print(f"Sent message (seqno={seqno}): {plaintext}")
        
        # Step 9: Append to transcript
        transcript_utils.append_to_transcript(
            session_state['transcript_file'],
            seqno,
            timestamp,
            ciphertext_base64,
            signature_base64,
            session_state['client_fingerprint']
        )
        
        # Step 10: Increment send_seqno
        session_state['send_seqno'] = seqno + 1
        
    except Exception as e:
        print(f"ERROR: Failed to send message: {e}")


def receive_messages(client_socket, session_aes_key, client_cert, session_state):
    """
    Receive and process encrypted messages from the client.
    
    This function runs in a separate thread to handle incoming messages.
    
    Process:
    1. Receive chat message from client
    2. Extract seqno, timestamp, ciphertext, signature
    3. Check seqno is strictly greater than last received (replay protection)
    4. If seqno <= last, log REPLAY and reject message
    5. Recompute digest: SHA-256(seqno || timestamp || ciphertext)
    6. Verify signature using client public key
    7. If signature invalid, log SIG_FAIL and reject message
    8. Decrypt ciphertext with session AES key
    9. Remove PKCS7 padding
    10. Display plaintext message
    11. Append to transcript: seqno|ts|ct|sig|client_cert_fingerprint
    12. Update recv_seqno
    
    Args:
        client_socket: Socket connection to client
        session_aes_key: 16-byte AES key
        client_cert: Client's X.509 certificate
        session_state (dict): Shared session state
    
    Assignment Reference: Section 1.3 - Data Plane, Section 2.4 - Message Integrity
    Requirements: 6.8, 6.9, 6.10, 6.11, 6.12, 6.13, 6.14, 7.3, 7.4, 7.5, 8.1, 8.2, 8.3, 8.4, 8.5, 9.2, 14.2, 14.3
    """
    import base64
    
    # Get client public key for signature verification
    client_public_key = crypto_utils.get_public_key_from_cert(client_cert)
    
    try:
        while session_state['running']:
            # Step 1: Receive chat message from client
            try:
                chat_msg = protocol.receive_message(client_socket)
            except Exception as e:
                # Connection closed or error
                print("\nConnection closed by client")
                session_state['running'] = False
                break
            
            # Check message type
            if chat_msg['type'] != 'msg':
                print(f"ERROR: Expected msg, got {chat_msg['type']}")
                continue
            
            # Step 2: Extract seqno, timestamp, ciphertext, signature
            seqno = chat_msg['seqno']
            timestamp = chat_msg['ts']
            ciphertext_base64 = chat_msg['ct']
            signature_base64 = chat_msg['sig']
            
            # Decode base64 values
            ciphertext_with_iv = base64.b64decode(ciphertext_base64)
            signature = base64.b64decode(signature_base64)
            
            # Step 3: Check seqno is strictly greater than last received (replay protection)
            expected_seqno = session_state['recv_seqno']
            
            if seqno <= expected_seqno - 1:
                # Step 4: If seqno <= last, log REPLAY and reject message
                print(f"REPLAY: Received seqno={seqno}, expected seqno>={expected_seqno}")
                continue
            
            # Step 5: Recompute digest: SHA-256(seqno || timestamp || ciphertext)
            seqno_bytes = str(seqno).encode('utf-8')
            timestamp_bytes = str(timestamp).encode('utf-8')
            
            digest_input = seqno_bytes + timestamp_bytes + ciphertext_with_iv
            recomputed_digest = hashlib.sha256(digest_input).digest()
            
            # Step 6: Verify signature using client public key
            signature_valid = crypto_utils.verify_signature(
                recomputed_digest,
                signature,
                client_public_key
            )
            
            if not signature_valid:
                # Step 7: If signature invalid, log SIG_FAIL and reject message
                print(f"SIG_FAIL: Message seqno={seqno} signature verification failed")
                continue
            
            # Step 8: Decrypt ciphertext with session AES key
            try:
                plaintext_bytes = crypto_utils.aes_decrypt(ciphertext_with_iv, session_aes_key)
            except Exception as e:
                print(f"ERROR: Decryption failed for seqno={seqno}: {e}")
                continue
            
            # Step 9: Remove PKCS7 padding (already done in aes_decrypt)
            # Step 10: Display plaintext message
            plaintext = plaintext_bytes.decode('utf-8')
            print(f"\nClient: {plaintext}")
            
            # Step 11: Append to transcript
            transcript_utils.append_to_transcript(
                session_state['transcript_file'],
                seqno,
                timestamp,
                ciphertext_base64,
                signature_base64,
                session_state['client_fingerprint']
            )
            
            # Step 12: Update recv_seqno
            session_state['recv_seqno'] = seqno + 1
            
    except Exception as e:
        print(f"\nERROR: Receive thread error: {e}")
        session_state['running'] = False


if __name__ == "__main__":
    main()
