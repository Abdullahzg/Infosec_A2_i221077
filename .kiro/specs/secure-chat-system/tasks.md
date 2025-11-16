# Implementation Plan

This task list provides step-by-step prompts for implementing the Secure Chat System. Each task builds incrementally on previous tasks, with all code integrated and functional at each step.

**Important Notes**:
- Tasks marked with * are optional (e.g., unit tests, documentation)
- Focus on core functionality first
- Test each task before moving to the next
- All assignment references are included for traceability

---

## Prerequisites (User Setup Required)

Before starting implementation, you must:

1. **Install Python 3.8+** on your system
2. **Install MySQL 8.0+** and start the MySQL service
3. **Create MySQL database**:
   ```sql
   CREATE DATABASE securechat_db;
   CREATE USER 'securechat_user'@'localhost' IDENTIFIED BY 'your_password';
   GRANT ALL PRIVILEGES ON securechat_db.* TO 'securechat_user'@'localhost';
   FLUSH PRIVILEGES;
   ```
4. **Fork the skeleton repository**: https://github.com/maadilrehman/securechat-skeleton
5. **Clone your fork** to your local machine
6. **Create virtual environment** (recommended):
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

---

## Task List

- [x] 1. Set up project structure and dependencies





  - Create directory structure: certs/, scripts/, transcripts/, receipts/
  - Create requirements.txt with cryptography, pycryptodome, mysql-connector-python, python-dotenv
  - Create .gitignore to exclude certs/*.pem, transcripts/, receipts/, .env, __pycache__/
  - Create .env.example with placeholder database and server configuration
  - Create README.md with basic project description and setup instructions
  - _Assignment Reference: Section 2 - System Requirements & Implementation, Section 4 - Submission Instructions_
  - _Requirements: 15.3, 15.4, 15.5, 15.6, 15.7_


- [x] 2. Implement CA generation script





  - [x] 2.1 Create scripts/gen_ca.py


    - Import cryptography libraries for RSA key generation and X.509 certificate creation
    - Generate 2048-bit RSA private key for CA
    - Create self-signed X.509 certificate with CA extensions
    - Set validity period (e.g., 10 years)
    - Save CA private key to certs/ca_key.pem
    - Save CA certificate to certs/ca_cert.pem
    - Add simple main() function to run the script
    - _Assignment Reference: Section 2.1 - PKI Setup, scripts/gen_ca.py_
    - _Requirements: 1.1_

- [x] 3. Implement certificate issuance script





  - [x] 3.1 Create scripts/gen_cert.py

    - Accept entity name as command-line argument (e.g., "server" or "client")
    - Load CA private key and certificate from certs/
    - Generate 2048-bit RSA keypair for entity
    - Create X.509 certificate signing request (CSR)
    - Sign CSR with CA private key
    - Set validity period (e.g., 1 year)
    - Save entity private key to certs/{entity}_key.pem
    - Save entity certificate to certs/{entity}_cert.pem
    - _Assignment Reference: Section 2.1 - PKI Setup, scripts/gen_cert.py_
    - _Requirements: 1.2, 1.3_

---

**After Task 3, you can:**
- Generate CA: `python scripts/gen_ca.py`
- Generate server certificate: `python scripts/gen_cert.py server`
- Generate client certificate: `python scripts/gen_cert.py client`
- Inspect certificates: `openssl x509 -in certs/server_cert.pem -text -noout`

---

- [x] 4. Implement certificate validation utilities




  - [x] 4.1 Create crypto_utils.py with certificate functions


    - Implement load_certificate(cert_path) to read and parse PEM certificate
    - Implement load_private_key(key_path) to read and parse PEM private key
    - Implement validate_certificate(cert, ca_cert) to verify signature chain and validity dates
    - Implement get_public_key_from_cert(cert) to extract RSA public key
    - Implement get_cert_fingerprint(cert) to compute SHA-256 fingerprint
    - Return clear error codes: BAD_CERT_EXPIRED, BAD_CERT_SELF_SIGNED, BAD_CERT_UNTRUSTED, BAD_CERT_INVALID_SIG
    - Use simple if-else logic, no complex exception handling
    - _Assignment Reference: Section 2.1 - PKI Setup, certificate validation_
    - _Requirements: 2.3, 2.4, 2.5, 1.5_


- [x] 5. Implement Diffie-Hellman key exchange utilities






  - [x] 5.1 Add DH functions to crypto_utils.py

    - Implement generate_dh_parameters() to return standard p (2048-bit prime) and g (2)
    - Implement generate_dh_keypair(p, g) to generate random private key and compute public key
    - Implement compute_shared_secret(peer_public, my_private, p) to compute Ks
    - Implement derive_aes_key(shared_secret) to convert Ks to big-endian bytes, hash with SHA-256, and truncate to 16 bytes
    - Use simple arithmetic operations, no complex math libraries beyond pow()
    - _Assignment Reference: Section 1.2 - Key Agreement, Section 2.3 - Session Key Establishment_
    - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.7, 5.8, 5.9_
- [x] 6. Implement AES encryption and decryption utilities




- [ ] 6. Implement AES encryption and decryption utilities


  - [x] 6.1 Add AES functions to crypto_utils.py

    - Implement pkcs7_pad(data, block_size=16) to add PKCS7 padding
    - Implement pkcs7_unpad(padded_data) to remove PKCS7 padding
    - Implement aes_encrypt(plaintext, key) using AES-128 CBC mode with random IV
    - Return IV concatenated with ciphertext
    - Implement aes_decrypt(ciphertext_with_iv, key) to extract IV, decrypt, and unpad
    - Use Crypto.Cipher.AES from pycryptodome
    - Use simple byte operations, no slicing shortcuts
    - _Assignment Reference: Section 2.4 - Encrypted Chat, AES-128 with PKCS#7 padding_
    - _Requirements: 6.1, 6.2, 6.13, 6.14_


- [x] 7. Implement RSA signature utilities




  - [x] 7.1 Add RSA signature functions to crypto_utils.py


    - Implement sign_data(data, private_key) to compute SHA-256 hash and sign with RSA
    - Use PSS padding for signatures
    - Implement verify_signature(data, signature, public_key) to verify RSA signature
    - Return True/False for verification result
    - Use cryptography library's RSA and hashing modules
    - _Assignment Reference: Section 1.3 - Data Plane, Section 2.4 - Message Integrity_
    - _Requirements: 6.5, 6.6, 6.11, 6.12_

---

**After Task 7, you can:**
- Test certificate validation with valid and invalid certificates
- Test DH key exchange by computing shared secrets on both sides
- Test AES encryption/decryption with sample messages
- Test RSA signing and verification with sample data

---


- [x] 8. Implement database utilities





  - [x] 8.1 Create db_utils.py with database functions


    - Implement connect_database() to read .env and connect to MySQL
    - Implement create_users_table() to create users table with schema: id, email, username, salt, pwd_hash, created_at
    - Implement register_user(email, username, salt, pwd_hash) to insert new user
    - Check for duplicate email/username before inserting
    - Implement get_user_salt(email) to retrieve salt for given email
    - Implement verify_login(email, pwd_hash) to check credentials
    - Implement constant_time_compare(a, b) to compare strings safely
    - Use mysql-connector-python library
    - Use simple SQL queries with parameterized statements (no ORM)
    - _Assignment Reference: Section 2.2 - Registration and Login, MySQL database_
    - _Requirements: 3.6, 3.7, 4.6, 4.7, 13.1, 13.2, 13.3, 13.4, 13.5, 13.6_

- [x] 9. Implement message protocol utilities





  - [x] 9.1 Create protocol.py with message formatting functions


    - Implement create_hello_msg(cert_pem, nonce) to format hello message
    - Implement create_server_hello_msg(cert_pem, nonce) to format server hello
    - Implement create_register_msg(email, username, pwd_hash, salt) to format registration
    - Implement create_login_msg(email, pwd_hash, nonce) to format login
    - Implement create_dh_client_msg(g, p, A) to format DH client message
    - Implement create_dh_server_msg(B) to format DH server message
    - Implement create_chat_msg(seqno, timestamp, ciphertext, signature) to format chat message
    - Implement create_receipt_msg(peer, first_seq, last_seq, transcript_hash, signature) to format receipt
    - All functions return Python dictionaries (will be JSON-encoded for transmission)
    - _Assignment Reference: Section 1.1 - Control Plane, Section 1.2 - Key Agreement, Section 1.3 - Data Plane, Section 1.4 - Non-Repudiation_
    - _Requirements: 2.1, 2.2, 3.4, 4.4, 5.2, 5.4, 6.7, 10.5_

  - [x] 9.2 Add message transmission functions to protocol.py

    - Implement send_message(socket, msg_dict) to convert dict to JSON, encode to bytes, send length prefix (4 bytes) + message
    - Implement receive_message(socket) to receive length prefix, receive message bytes, decode JSON, return dict
    - Use simple socket.send() and socket.recv() operations
    - Handle partial receives with loops
    - _Assignment Reference: Section 1 - Secure Chat Protocol, JSON message exchange_
    - _Requirements: 6.7_

---

**After Task 9, you can:**
- Create and format all message types
- Test message serialization and deserialization
- Test socket message transmission (requires basic socket setup)

---


- [x] 10. Implement transcript logging utilities




  - [x] 10.1 Create transcript_utils.py with transcript functions


    - Implement create_transcript_file(session_id) to create file in transcripts/ directory
    - Implement append_to_transcript(file_handle, seqno, ts, ct, sig, peer_fingerprint) to append formatted line
    - Use pipe delimiter: seqno|ts|ct|sig|fingerprint
    - Implement compute_transcript_hash(transcript_path) to read file, concatenate lines, compute SHA-256
    - Implement generate_session_receipt(transcript_path, private_key, peer_name, first_seq, last_seq) to create receipt
    - Use simple file I/O operations with explicit open/close or with statements
    - _Assignment Reference: Section 1.4 - Non-Repudiation, Section 2.5 - Session Closure_
    - _Requirements: 9.1, 9.2, 9.3, 9.4, 9.5, 10.1, 10.2, 10.3, 10.4, 10.5, 10.6_

- [x] 11. Implement server application - Phase 1 (Control Plane)




  - [x] 11.1 Create server.py with basic structure


    - Import all utility modules (crypto_utils, db_utils, protocol, transcript_utils)
    - Load server certificate, private key, and CA certificate
    - Connect to MySQL database
    - Create TCP socket, bind to SERVER_HOST:SERVER_PORT from .env
    - Listen for connections
    - Accept client connections and handle each in main thread (single client for now)
    - _Assignment Reference: Section 2 - System Requirements, server application_
    - _Requirements: 2.1, 2.2_

  - [x] 11.2 Implement certificate exchange in server.py

    - Receive hello message from client with client certificate and nonce
    - Validate client certificate using validate_certificate()
    - If validation fails, log error code (BAD_CERT_*), close connection
    - Send server_hello message with server certificate and nonce
    - _Assignment Reference: Section 1.1 - Control Plane, certificate exchange_
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 14.1_

  - [x] 11.3 Implement temporary DH for credential encryption in server.py

    - Receive dh_client message with g, p, A from client
    - Generate server DH keypair (b, B) using same p, g
    - Send dh_server message with B
    - Compute shared secret Ks and derive temporary AES key
    - _Assignment Reference: Section 2.2 - Registration and Login, temporary DH_
    - _Requirements: 3.1, 4.1_

  - [x] 11.4 Implement registration handling in server.py

    - Receive encrypted register message
    - Decrypt using temporary AES key
    - Extract email, username, pwd_hash, salt
    - Call register_user() from db_utils
    - Send success or error response (USER_EXISTS if duplicate)
    - _Assignment Reference: Section 2.2 - Registration_
    - _Requirements: 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 3.8, 14.3_

  - [x] 11.5 Implement login handling in server.py

    - Receive encrypted login message
    - Decrypt using temporary AES key
    - Extract email, pwd_hash
    - Call verify_login() from db_utils
    - Send success or error response (AUTH_FAILED or USER_NOT_FOUND)
    - _Assignment Reference: Section 2.2 - Login_
    - _Requirements: 4.2, 4.3, 4.4, 4.5, 4.6, 4.7, 4.8, 4.9, 14.3, 14.4_

---

**After Task 11, you can:**
- Start server: `python server.py`
- Server listens for connections
- Server validates client certificates
- Server handles registration and login (need client to test)

---


- [x] 12. Implement client application - Phase 1 (Control Plane)






  - [x] 12.1 Create client.py with basic structure

    - Import all utility modules
    - Load client certificate, private key, and CA certificate
    - Connect to server via TCP socket using SERVER_HOST:SERVER_PORT from .env
    - _Assignment Reference: Section 2 - System Requirements, client application_
    - _Requirements: 2.1_


  - [x] 12.2 Implement certificate exchange in client.py

    - Generate random nonce
    - Send hello message with client certificate and nonce
    - Receive server_hello message with server certificate and nonce
    - Validate server certificate using validate_certificate()
    - If validation fails, log error code (BAD_CERT_*), close connection
    - _Assignment Reference: Section 1.1 - Control Plane, certificate exchange_
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 14.1_


  - [x] 12.3 Implement temporary DH for credential encryption in client.py

    - Generate DH parameters (p, g)
    - Generate client DH keypair (a, A)
    - Send dh_client message with g, p, A
    - Receive dh_server message with B
    - Compute shared secret Ks and derive temporary AES key
    - _Assignment Reference: Section 2.2 - Registration and Login, temporary DH_
    - _Requirements: 3.1, 4.1_

  - [x] 12.4 Implement registration flow in client.py


    - Prompt user for email, username, password
    - Generate random 16-byte salt
    - Compute salted password hash: SHA-256(salt || password)
    - Encode salt and pwd_hash in base64
    - Create register message
    - Encrypt message with temporary AES key
    - Send encrypted message to server
    - Receive and display response
    - _Assignment Reference: Section 2.2 - Registration_
    - _Requirements: 3.2, 3.3, 3.4, 12.1_

  - [x] 12.5 Implement login flow in client.py


    - Prompt user for email and password
    - Request salt from server for the email (or include in protocol)
    - Compute salted password hash: SHA-256(salt || password)
    - Encode pwd_hash in base64
    - Create login message with nonce
    - Encrypt message with temporary AES key
    - Send encrypted message to server
    - Receive and display response
    - _Assignment Reference: Section 2.2 - Login_
    - _Requirements: 4.2, 4.3, 4.4, 12.2_

---

**After Task 12, you can:**
- Start server: `python server.py`
- Start client: `python client.py`
- Register a new user with email, username, password
- Login with existing credentials
- See authentication success/failure messages

---


- [x] 13. Implement server application - Phase 2 (Session Key Agreement)




  - [x] 13.1 Add session DH exchange to server.py


    - After successful login, receive dh_client message from client (new DH exchange)
    - Generate server DH keypair (b, B) using received p, g
    - Send dh_server message with B
    - Compute shared secret Ks and derive session AES key
    - Store session key for chat encryption
    - _Assignment Reference: Section 1.2 - Key Agreement, Section 2.3 - Session Key Establishment_
    - _Requirements: 5.3, 5.4, 5.6, 5.7, 5.8, 5.9_


- [x] 14. Implement client application - Phase 2 (Session Key Agreement)



  - [x] 14.1 Add session DH exchange to client.py

    - After successful login, generate new DH parameters (p, g)
    - Generate client DH keypair (a, A)
    - Send dh_client message with g, p, A
    - Receive dh_server message with B
    - Compute shared secret Ks and derive session AES key
    - Store session key for chat encryption
    - _Assignment Reference: Section 1.2 - Key Agreement, Section 2.3 - Session Key Establishment_
    - _Requirements: 5.1, 5.2, 5.5, 5.7, 5.8, 5.9_

---

**After Task 14, you can:**
- Complete full authentication flow
- Establish session encryption key
- Ready to send encrypted messages

---
-

- [x] 15. Implement server application - Phase 3 (Data Plane - Message Exchange)




  - [x] 15.1 Add message sending to server.py


    - Initialize send_seqno = 1
    - Create transcript file for session
    - Prompt for message input from console
    - Apply PKCS7 padding to plaintext
    - Encrypt with session AES key
    - Get current timestamp in Unix milliseconds
    - Compute digest: SHA-256(seqno || timestamp || ciphertext)
    - Sign digest with server private key
    - Encode ciphertext and signature in base64
    - Create chat message with seqno, timestamp, ct, sig
    - Send message to client
    - Append to transcript: seqno|ts|ct|sig|client_cert_fingerprint
    - Increment send_seqno
    - _Assignment Reference: Section 1.3 - Data Plane, Section 2.4 - Encrypted Chat_
    - _Requirements: 6.1, 6.2, 6.3, 6.4, 6.5, 6.6, 6.7, 9.2_

  - [x] 15.2 Add message receiving to server.py

    - Initialize recv_seqno = 1
    - Receive chat message from client
    - Extract seqno, timestamp, ciphertext, signature
    - Check seqno is strictly greater than last received (replay protection)
    - If seqno <= last, log REPLAY and reject message
    - Recompute digest: SHA-256(seqno || timestamp || ciphertext)
    - Verify signature using client public key
    - If signature invalid, log SIG_FAIL and reject message
    - Decrypt ciphertext with session AES key
    - Remove PKCS7 padding
    - Display plaintext message
    - Append to transcript: seqno|ts|ct|sig|client_cert_fingerprint
    - Update recv_seqno
    - _Assignment Reference: Section 1.3 - Data Plane, Section 2.4 - Message Integrity_
    - _Requirements: 6.8, 6.9, 6.10, 6.11, 6.12, 6.13, 6.14, 7.3, 7.4, 7.5, 8.1, 8.2, 8.3, 8.4, 8.5, 9.2, 14.2, 14.3_

  - [x] 15.3 Add message loop to server.py

    - Use simple loop or threading to handle send and receive simultaneously
    - For simplicity, use alternating send/receive or basic threading
    - Handle connection close gracefully
    - _Assignment Reference: Section 2.4 - Encrypted Chat_
    - _Requirements: 6.1-6.14_

---

**After Task 15, you can:**
- Server can send encrypted and signed messages
- Server can receive and verify messages
- Server detects replay attacks and tampering
- Server logs all messages to transcript

---

-

- [x] 16. Implement client application - Phase 3 (Data Plane - Message Exchange)




  - [x] 16.1 Add message sending to client.py


    - Initialize send_seqno = 1
    - Create transcript file for session
    - Prompt for message input from console
    - Apply PKCS7 padding to plaintext
    - Encrypt with session AES key
    - Get current timestamp in Unix milliseconds
    - Compute digest: SHA-256(seqno || timestamp || ciphertext)
    - Sign digest with client private key
    - Encode ciphertext and signature in base64
    - Create chat message with seqno, timestamp, ct, sig
    - Send message to server
    - Append to transcript: seqno|ts|ct|sig|server_cert_fingerprint
    - Increment send_seqno
    - _Assignment Reference: Section 1.3 - Data Plane, Section 2.4 - Encrypted Chat_
    - _Requirements: 6.1, 6.2, 6.3, 6.4, 6.5, 6.6, 6.7, 9.2_

  - [x] 16.2 Add message receiving to client.py

    - Initialize recv_seqno = 1
    - Receive chat message from server
    - Extract seqno, timestamp, ciphertext, signature
    - Check seqno is strictly greater than last received (replay protection)
    - If seqno <= last, log REPLAY and reject message
    - Recompute digest: SHA-256(seqno || timestamp || ciphertext)
    - Verify signature using server public key
    - If signature invalid, log SIG_FAIL and reject message
    - Decrypt ciphertext with session AES key
    - Remove PKCS7 padding
    - Display plaintext message
    - Append to transcript: seqno|ts|ct|sig|server_cert_fingerprint
    - Update recv_seqno
    - _Assignment Reference: Section 1.3 - Data Plane, Section 2.4 - Message Integrity_
    - _Requirements: 6.8, 6.9, 6.10, 6.11, 6.12, 6.13, 6.14, 7.3, 7.4, 7.5, 8.1, 8.2, 8.3, 8.4, 8.5, 9.2, 14.2, 14.3_

  - [x] 16.3 Add message loop to client.py

    - Use threading: one thread for sending, one for receiving
    - Sending thread: loop to get user input and send messages
    - Receiving thread: loop to receive and display messages
    - Handle connection close gracefully
    - _Assignment Reference: Section 2.4 - Encrypted Chat_
    - _Requirements: 6.1-6.14_

---

**After Task 16, you can:**
- Client can send encrypted and signed messages
- Client can receive and verify messages
- Client detects replay attacks and tampering
- Client logs all messages to transcript
- Full bidirectional encrypted chat works!

---

-

- [x] 17. Implement server application - Phase 4 (Teardown - Non-Repudiation)



  - [x] 17.1 Add session closure to server.py


    - When chat ends (user types "exit" or connection closes), close transcript file
    - Compute transcript hash using compute_transcript_hash()
    - Generate session receipt using generate_session_receipt()
    - Sign transcript hash with server private key
    - Save receipt to receipts/session_{id}_server_receipt.json
    - Optionally send receipt to client
    - _Assignment Reference: Section 1.4 - Non-Repudiation, Section 2.5 - Session Closure_
    - _Requirements: 10.1, 10.2, 10.3, 10.4, 10.5, 10.6_

-

- [x] 18. Implement client application - Phase 4 (Teardown - Non-Repudiation)


  - [x] 18.1 Add session closure to client.py


    - When chat ends (user types "exit" or connection closes), close transcript file
    - Compute transcript hash using compute_transcript_hash()
    - Generate session receipt using generate_session_receipt()
    - Sign transcript hash with client private key
    - Save receipt to receipts/session_{id}_client_receipt.json
    - Optionally send receipt to server
    - _Assignment Reference: Section 1.4 - Non-Repudiation, Section 2.5 - Session Closure_
    - _Requirements: 10.1, 10.2, 10.3, 10.4, 10.5, 10.6_

---

**After Task 18, you can:**
- Complete chat sessions generate transcript files
- Session receipts are created and saved
- Both client and server have cryptographic proof of conversation


---

- [x] 19. Implement offline verification tool



  - [x] 19.1 Create verify.py


    - Accept command-line arguments: --transcript, --receipt, --cert
    - Load transcript file, receipt JSON, and peer certificate
    - Parse each line of transcript: seqno|ts|ct|sig|fingerprint
    - For each message, recompute digest SHA-256(seqno || ts || ct)
    - Verify message signature using peer public key
    - If any message signature fails, report failure with line number
    - Concatenate all transcript lines
    - Compute transcript hash SHA-256(concatenated lines)
    - Compare computed hash with receipt's transcript_sha256
    - Verify receipt signature using peer public key
    - Report VERIFICATION SUCCESS or VERIFICATION FAILED with reason
    - _Assignment Reference: Section 3 - Testing & Evidence, offline verification_
    - _Requirements: 10.7, 11.1, 11.2, 11.3, 11.4, 11.5, 11.6, 11.7, 11.8, 11.9, 11.10_

---

**After Task 19, you can:**
- Verify any transcript and receipt offline
- Detect any tampering with transcripts
- Prove authenticity of conversations
- Usage: `python verify.py --transcript transcripts/session_123.txt --receipt receipts/session_123_client_receipt.json --cert certs/client_cert.pem`

---


- [ ] 20. Testing and evidence collection
-

  - [x] 20.1 Test certificate validation


    - Test with valid certificates (should succeed)
    - Test with expired certificate (should log BAD_CERT_EXPIRED)
    - Test with self-signed certificate (should log BAD_CERT_SELF_SIGNED)
    - Test with certificate from different CA (should log BAD_CERT_UNTRUSTED)
    - Document results with screenshots
    - _Assignment Reference: Section 3 - Testing & Evidence, invalid certificate test_
    - _Requirements: 2.5, 14.1_

  - [ ] 20.2 Test message tampering detection
    - Establish chat session
    - Manually modify ciphertext in a message before sending (flip one bit)
    - Verify server/client logs SIG_FAIL
    - Document results with screenshots
    - _Assignment Reference: Section 3 - Testing & Evidence, tampering test_
    - _Requirements: 8.4, 8.5, 14.2_

  - [ ] 20.3 Test replay attack detection
    - Establish chat session
    - Send message with seqno=3
    - Resend same message after seqno=4
    - Verify server/client logs REPLAY
    - Document results with screenshots
    - _Assignment Reference: Section 3 - Testing & Evidence, replay test_
    - _Requirements: 7.4, 14.3_

  - [ ] 20.4 Test Wireshark traffic capture
    - Start Wireshark on loopback interface (127.0.0.1)
    - Apply display filter: tcp.port == 8443 (or your server port)
    - Start server and client
    - Perform registration with email, username, password
    - Send several chat messages
    - Stop capture
    - Verify no plaintext credentials or messages visible
    - Verify only base64-encoded ciphertext visible
    - Save PCAP file
    - Document with screenshots showing encrypted payloads
    - _Assignment Reference: Section 3 - Testing & Evidence, Wireshark test_
    - _Requirements: 12.1, 12.2, 12.3, 12.4_

  - [ ] 20.5 Test offline verification
    - Complete a chat session
    - Verify transcript and receipt with verify.py (should succeed)
    - Modify one character in transcript file
    - Verify again (should fail with hash mismatch)
    - Restore transcript, modify receipt signature
    - Verify again (should fail with signature verification failed)
    - Document results with screenshots
    - _Assignment Reference: Section 3 - Testing & Evidence, non-repudiation test_
    - _Requirements: 11.5, 11.9, 11.10_

---

**After Task 20, you have:**
- Complete test evidence for all security features
- Screenshots and PCAP files for submission
- Documented proof of CIANR properties

---


- [x] 21. Documentation and submission preparation





  - [x] 21.1 Complete README.md


    - Add project overview and features
    - Add prerequisites (Python, MySQL, libraries)
    - Add setup instructions (database creation, .env configuration, certificate generation)
    - Add usage instructions (start server, start client, register, login, chat)
    - Add testing instructions (Wireshark, verification tool)
    - Add sample input/output formats for all message types
    - Add troubleshooting section
    - Add link to GitHub repository
    - _Assignment Reference: Section 4 - Submission Instructions, README.md_
    - _Requirements: 15.3, 15.7_

  - [x] 21.2 Create database schema dump


    - Export MySQL schema: `mysqldump -u securechat_user -p --no-data securechat_db > schema.sql`
    - Export sample records: `mysqldump -u securechat_user -p securechat_db users > sample_data.sql`
    - Include in submission
    - _Assignment Reference: Section 4 - Submission Instructions, MySQL schema dump_

  - [x] 21.3 Verify .gitignore


    - Ensure certs/*.pem excluded (except .gitkeep)
    - Ensure transcripts/ excluded
    - Ensure receipts/ excluded
    - Ensure .env excluded
    - Ensure __pycache__/ excluded
    - Ensure no secrets committed
    - _Assignment Reference: Section 7 - Academic Integrity, do not commit secrets_
    - _Requirements: 15.4_

  - [x] 21.4 Verify commit history


    - Check at least 10 meaningful commits
    - Each commit should represent a feature or module
    - Commit messages should be clear and descriptive
    - _Assignment Reference: Section 4 - Submission Instructions, at least 10 commits_
    - _Requirements: 15.2_

  - [ ]* 21.5 Create test report document
    - Document all test cases from Task 20
    - Include screenshots for each test
    - Include Wireshark PCAP analysis
    - Include verification tool output
    - Format as RollNumber-FullName-TestReport-A02.docx
    - _Assignment Reference: Section 4 - Submission Instructions, Test Report_

  - [ ]* 21.6 Create main report document
    - Include project overview
    - Include architecture diagram
    - Include certificate inspection results (openssl x509 output)
    - Include protocol flow descriptions
    - Include security analysis (CIANR properties)
    - Include test results summary
    - Include references and citations
    - Format as RollNumber-FullName-Report-A02.docx
    - _Assignment Reference: Section 4 - Submission Instructions, Report_

---

**After Task 21, you have:**
- Complete documentation
- All submission materials ready
- GitHub repository ready for submission

---

## Final Submission Checklist

Before submitting, verify:

1. ✓ GitHub repository has at least 10 meaningful commits
2. ✓ README.md is complete with setup and usage instructions
3. ✓ .gitignore excludes all secrets and sensitive files
4. ✓ .env.example provided (no actual credentials)
5. ✓ All scripts work: gen_ca.py, gen_cert.py, server.py, client.py, verify.py
6. ✓ Database schema dump included
7. ✓ Test evidence collected (screenshots, PCAP)
8. ✓ Reports completed (main report and test report)
9. ✓ Repository ZIP downloaded for GCR submission
10. ✓ All assignment requirements met (check grading rubric)

**Submission on GCR**:
- Downloaded ZIP of GitHub repository
- MySQL schema dump and sample records
- README.md with GitHub link
- RollNumber-FullName-Report-A02.docx
- RollNumber-FullName-TestReport-A02.docx

