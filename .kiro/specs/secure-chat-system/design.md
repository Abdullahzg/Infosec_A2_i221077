# Design Document

## Overview
**Assignment Reference:** Introduction, Section 1 - Secure Chat Protocol

The Secure Chat System is a console-based client-server application that implements cryptographic protocols to achieve Confidentiality, Integrity, Authenticity, and Non-Repudiation (CIANR). The system uses industry-standard cryptographic primitives through Python libraries rather than implementing them from scratch.

### Design Principles

1. **Simplicity First**: Use the simplest possible code structure with minimal abstractions
2. **Library-Based**: Leverage Python's cryptography libraries (cryptography, pycryptodome) for all cryptographic operations
3. **Baby Code Style**: Avoid complex Python features like list comprehensions, dictionary comprehensions, or advanced slicing
4. **Explicit Over Implicit**: Use clear for loops and explicit variable names
5. **No Custom Crypto**: Never implement AES, RSA, DH, or SHA-256 manually

### Technology Stack

- **Language**: Python 3.8+
- **Cryptography**: `cryptography` library for X.509, RSA, and general crypto operations
- **Database**: MySQL with `mysql-connector-python`
- **Networking**: Standard `socket` library (no TLS/SSL wrappers)
- **Data Format**: JSON for all message exchanges

## Architecture
**Assignment Reference:** Section 1 - Secure Chat Protocol (4 phases)

### System Components

```
┌─────────────────┐                    ┌─────────────────┐
│   Client App    │◄──────────────────►│   Server App    │
│                 │   TCP Socket       │                 │
│  - Certificate  │   (No TLS)         │  - Certificate  │
│  - Private Key  │                    │  - Private Key  │
│  - Transcript   │                    │  - Transcript   │
└─────────────────┘                    └────────┬────────┘
                                                │
                                                ▼
                                        ┌───────────────┐
                                        │  MySQL DB     │
                                        │  - users      │
                                        └───────────────┘
```

### Communication Phases

The protocol operates in four sequential phases:


**Phase 1: Control Plane (Negotiation and Authentication)**
- Certificate exchange and validation
- User registration or login
- Temporary DH key exchange for credential encryption

**Phase 2: Key Agreement**
- Post-authentication DH exchange
- Session key derivation for chat encryption

**Phase 3: Data Plane (Message Exchange)**
- Encrypted and signed message transmission
- Replay and tampering detection

**Phase 4: Teardown (Non-Repudiation)**
- Transcript hash computation
- Session receipt generation and exchange

## Components and Interfaces
**Assignment Reference:** Section 2 - System Requirements & Implementation

### 1. Certificate Authority (CA) Module

**Purpose**: Generate root CA and issue certificates

**Files**:
- `scripts/gen_ca.py` - Creates root CA
- `scripts/gen_cert.py` - Issues entity certificates

**Key Functions**:

```python
def generate_ca():
    # Generate RSA private key for CA
    # Create self-signed X.509 certificate
    # Save to certs/ca_key.pem and certs/ca_cert.pem
    pass

def generate_certificate(entity_name, ca_key, ca_cert):
    # Generate RSA keypair for entity
    # Create certificate signing request (CSR)
    # Sign CSR with CA key
    # Save entity key and cert to certs/
    pass
```

**Libraries Used**:
- `cryptography.hazmat.primitives.asymmetric.rsa` for RSA key generation
- `cryptography.x509` for certificate creation and signing

**Design Decision**: Use 2048-bit RSA keys and SHA-256 for signatures (industry standard, assignment compliant)


### 2. Certificate Validation Module

**Purpose**: Verify certificates against trusted CA

**Key Functions**:

```python
def load_certificate(cert_path):
    # Read PEM file
    # Parse X.509 certificate
    # Return certificate object
    pass

def validate_certificate(cert, ca_cert):
    # Check signature chain (verify cert signed by CA)
    # Check validity dates (not_valid_before, not_valid_after)
    # Check if self-signed (reject)
    # Return True/False and error reason
    pass

def get_public_key_from_cert(cert):
    # Extract RSA public key from certificate
    # Return public key object
    pass
```

**Validation Checks**:
1. Signature verification using CA public key
2. Validity period check against current time
3. Self-signed detection (issuer == subject)
4. CA issuer match

**Error Codes**:
- `BAD_CERT_EXPIRED` - Certificate past validity period
- `BAD_CERT_SELF_SIGNED` - Certificate is self-signed
- `BAD_CERT_UNTRUSTED` - Certificate not signed by trusted CA
- `BAD_CERT_INVALID_SIG` - Signature verification failed


### 3. Diffie-Hellman Key Exchange Module

**Purpose**: Establish shared secrets for encryption

**Key Functions**:

```python
def generate_dh_parameters():
    # Use standard DH parameters (p, g)
    # p = large prime, g = generator
    # Return p, g
    pass

def generate_dh_keypair(p, g):
    # Generate random private key 'a' or 'b'
    # Compute public key A = g^a mod p or B = g^b mod p
    # Return private_key, public_key
    pass

def compute_shared_secret(peer_public, my_private, p):
    # Compute Ks = peer_public^my_private mod p
    # Return Ks as integer
    pass

def derive_aes_key(shared_secret):
    # Convert Ks to big-endian bytes
    # Compute SHA-256(Ks_bytes)
    # Truncate to first 16 bytes
    # Return 16-byte AES key
    pass
```

**Design Decisions**:
- Use 2048-bit prime for DH (standard security level)
- Generator g = 2 (common choice)
- Big-endian byte conversion for consistent hashing
- SHA-256 truncation to 16 bytes for AES-128

**Two DH Exchanges**:
1. **Temporary DH** (Control Plane): For encrypting registration/login credentials
2. **Session DH** (Key Agreement): For encrypting chat messages


### 4. AES Encryption Module

**Purpose**: Encrypt and decrypt messages using AES-128

**Key Functions**:

```python
def aes_encrypt(plaintext, key):
    # Apply PKCS7 padding to plaintext
    # Create AES cipher in CBC mode with random IV
    # Encrypt padded plaintext
    # Return IV + ciphertext (concatenated)
    pass

def aes_decrypt(ciphertext_with_iv, key):
    # Extract IV (first 16 bytes)
    # Extract ciphertext (remaining bytes)
    # Create AES cipher in CBC mode with extracted IV
    # Decrypt ciphertext
    # Remove PKCS7 padding
    # Return plaintext
    pass

def pkcs7_pad(data, block_size=16):
    # Calculate padding length
    # Append padding bytes (each byte = padding length)
    # Return padded data
    pass

def pkcs7_unpad(padded_data):
    # Read last byte to get padding length
    # Verify padding is valid
    # Remove padding bytes
    # Return unpadded data
    pass
```

**Design Decisions**:
- Use AES-128 in CBC mode (assignment specifies block cipher)
- Random IV for each encryption (prepended to ciphertext)
- PKCS7 padding for block alignment
- Key size: 16 bytes (128 bits)

**Libraries Used**:
- `Crypto.Cipher.AES` from pycryptodome


### 5. RSA Signature Module

**Purpose**: Sign and verify message digests

**Key Functions**:

```python
def load_private_key(key_path):
    # Read PEM file
    # Parse RSA private key
    # Return private key object
    pass

def sign_data(data, private_key):
    # Compute SHA-256 hash of data
    # Sign hash with RSA private key using PSS padding
    # Return signature bytes
    pass

def verify_signature(data, signature, public_key):
    # Compute SHA-256 hash of data
    # Verify signature using RSA public key
    # Return True if valid, False otherwise
    pass
```

**Signature Process**:
1. Compute digest: `h = SHA-256(seqno || timestamp || ciphertext)`
2. Sign digest: `sig = RSA_SIGN(h, private_key)`
3. Encode signature in base64 for JSON transmission

**Verification Process**:
1. Decode base64 signature
2. Recompute digest: `h = SHA-256(seqno || timestamp || ciphertext)`
3. Verify: `RSA_VERIFY(h, sig, public_key)`

**Libraries Used**:
- `cryptography.hazmat.primitives.asymmetric.rsa` for RSA operations
- `cryptography.hazmat.primitives.hashes` for SHA-256
- `cryptography.hazmat.primitives.asymmetric.padding` for PSS padding


### 6. Database Module

**Purpose**: Store and retrieve user credentials securely

**Schema**:

```sql
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    username VARCHAR(255) UNIQUE NOT NULL,
    salt VARBINARY(16) NOT NULL,
    pwd_hash CHAR(64) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

**Key Functions**:

```python
def connect_database():
    # Read DB credentials from environment variables
    # Connect to MySQL
    # Return connection object
    pass

def register_user(email, username, salt, pwd_hash):
    # Check if email or username exists
    # Insert new user record
    # Return success/failure
    pass

def get_user_salt(email):
    # Query salt for given email
    # Return salt bytes or None
    pass

def verify_login(email, pwd_hash):
    # Query stored pwd_hash for email
    # Compare using constant-time comparison
    # Return True/False
    pass

def constant_time_compare(a, b):
    # Compare two strings byte-by-byte
    # Always check all bytes (prevent timing attacks)
    # Return True if equal
    pass
```

**Design Decisions**:
- Store salt as binary (16 bytes)
- Store pwd_hash as hex string (64 characters for SHA-256)
- Use environment variables for DB credentials (.env file)
- Never store plaintext passwords
- Never store chat messages in database


### 7. Message Protocol Module

**Purpose**: Format and parse JSON messages

**Message Types and Formats**:

```python
# Control Plane Messages
hello_msg = {
    "type": "hello",
    "client_cert": "...PEM...",
    "nonce": "base64_encoded_random_bytes"
}

server_hello_msg = {
    "type": "server_hello",
    "server_cert": "...PEM...",
    "nonce": "base64_encoded_random_bytes"
}

register_msg = {
    "type": "register",
    "email": "user@example.com",
    "username": "username",
    "pwd": "base64_encoded_salted_hash",
    "salt": "base64_encoded_salt"
}

login_msg = {
    "type": "login",
    "email": "user@example.com",
    "pwd": "base64_encoded_salted_hash",
    "nonce": "base64_encoded_random_bytes"
}

# Key Agreement Messages
dh_client_msg = {
    "type": "dh_client",
    "g": 2,
    "p": 123456789...,
    "A": 987654321...
}

dh_server_msg = {
    "type": "dh_server",
    "B": 456789123...
}

# Data Plane Messages
chat_msg = {
    "type": "msg",
    "seqno": 1,
    "ts": 1700000000000,
    "ct": "base64_encoded_ciphertext",
    "sig": "base64_encoded_signature"
}

# Non-Repudiation Messages
receipt_msg = {
    "type": "receipt",
    "peer": "client",
    "first_seq": 1,
    "last_seq": 10,
    "transcript_sha256": "hex_encoded_hash",
    "sig": "base64_encoded_signature"
}
```

**Key Functions**:

```python
def send_message(socket, msg_dict):
    # Convert dict to JSON string
    # Encode to bytes
    # Send length prefix (4 bytes) + message
    pass

def receive_message(socket):
    # Receive length prefix (4 bytes)
    # Receive message bytes
    # Decode and parse JSON
    # Return dict
    pass
```


### 8. Transcript Module

**Purpose**: Log messages for non-repudiation

**Transcript Format**:
```
seqno|timestamp|ciphertext_base64|signature_base64|peer_cert_fingerprint
1|1700000000000|YWJjZGVm...|ZGVmZ2hp...|a1b2c3d4...
2|1700000001000|Z2hpamts...|amtsbW5v...|a1b2c3d4...
```

**Key Functions**:

```python
def create_transcript_file(session_id):
    # Create file: transcripts/session_{id}.txt
    # Return file handle
    pass

def append_to_transcript(file_handle, seqno, ts, ct, sig, peer_fingerprint):
    # Format line: seqno|ts|ct|sig|fingerprint
    # Append to file
    # Flush to disk
    pass

def compute_transcript_hash(transcript_path):
    # Read all lines from file
    # Concatenate lines
    # Compute SHA-256 hash
    # Return hex-encoded hash
    pass

def generate_session_receipt(transcript_path, private_key, peer_name):
    # Compute transcript hash
    # Sign hash with private key
    # Create receipt dict
    # Return receipt
    pass

def get_cert_fingerprint(cert):
    # Compute SHA-256 hash of certificate DER encoding
    # Return hex-encoded fingerprint
    pass
```

**Design Decisions**:
- Use pipe delimiter (|) for easy parsing
- Store in transcripts/ directory
- One file per session
- Append-only (never modify existing lines)


### 9. Server Application

**Purpose**: Accept client connections and handle chat sessions

**Main Flow**:

```python
def main():
    # Load server certificate and private key
    # Load CA certificate
    # Connect to MySQL database
    # Create TCP socket and bind to port
    # Listen for connections
    # For each client connection:
        # Handle client in separate thread
    pass

def handle_client(client_socket):
    # Phase 1: Control Plane
        # Exchange certificates
        # Validate client certificate
        # Perform temporary DH for credential encryption
        # Handle register or login
    
    # Phase 2: Key Agreement
        # Perform session DH exchange
        # Derive session AES key
    
    # Phase 3: Data Plane
        # Initialize sequence number = 1
        # Create transcript file
        # Loop:
            # Receive message
            # Verify sequence number (replay check)
            # Verify signature (tampering check)
            # Decrypt message
            # Display message
            # Log to transcript
            # Get user input for reply
            # Encrypt and sign reply
            # Send reply
            # Log to transcript
    
    # Phase 4: Teardown
        # Compute transcript hash
        # Generate session receipt
        # Exchange receipts
        # Close connection
    pass
```

**Threading**: Each client connection runs in a separate thread to allow multiple concurrent sessions


### 10. Client Application

**Purpose**: Connect to server and participate in chat

**Main Flow**:

```python
def main():
    # Load client certificate and private key
    # Load CA certificate
    # Connect to server via TCP socket
    
    # Phase 1: Control Plane
        # Exchange certificates
        # Validate server certificate
        # Perform temporary DH for credential encryption
        # Prompt user: register or login
        # Send encrypted credentials
    
    # Phase 2: Key Agreement
        # Perform session DH exchange
        # Derive session AES key
    
    # Phase 3: Data Plane
        # Initialize sequence number = 1
        # Create transcript file
        # Start receive thread
        # Loop:
            # Get user input
            # Encrypt and sign message
            # Send message
            # Log to transcript
    
    # Phase 4: Teardown
        # Compute transcript hash
        # Generate session receipt
        # Exchange receipts
        # Close connection
    pass

def receive_messages(socket, aes_key, peer_cert):
    # Loop:
        # Receive message
        # Verify sequence number
        # Verify signature
        # Decrypt message
        # Display message
        # Log to transcript
    pass
```

**Threading**: Separate thread for receiving messages to allow simultaneous send/receive


### 11. Verification Tool

**Purpose**: Offline verification of transcripts and receipts

**Main Flow**:

```python
def verify_transcript(transcript_path, receipt_path, peer_cert_path):
    # Load peer certificate
    # Load receipt JSON
    
    # Step 1: Verify each message signature
    # For each line in transcript:
        # Parse: seqno, ts, ct, sig, fingerprint
        # Recompute digest: SHA-256(seqno || ts || ct)
        # Verify signature using peer public key
        # If any fails: report failure and line number
    
    # Step 2: Verify transcript hash
    # Concatenate all transcript lines
    # Compute SHA-256 hash
    # Compare with receipt's transcript_sha256
    
    # Step 3: Verify receipt signature
    # Verify receipt signature using peer public key
    
    # Report: VERIFICATION SUCCESS or VERIFICATION FAILED
    pass
```

**Usage**:
```bash
python verify.py --transcript transcripts/session_123.txt --receipt receipts/session_123_receipt.json --cert certs/peer_cert.pem
```

## Data Models
**Assignment Reference:** Section 2.2 - Registration and Login

### User Model (Database)

```python
class User:
    id: int
    email: str
    username: str
    salt: bytes  # 16 bytes
    pwd_hash: str  # 64 hex characters (SHA-256)
    created_at: datetime
```

### Certificate Model

```python
class Certificate:
    subject: str  # Common Name
    issuer: str  # CA Common Name
    not_valid_before: datetime
    not_valid_after: datetime
    public_key: RSAPublicKey
    signature: bytes
```


### Session State Model

```python
class SessionState:
    # Certificates
    my_cert: Certificate
    my_private_key: RSAPrivateKey
    peer_cert: Certificate
    ca_cert: Certificate
    
    # Keys
    session_aes_key: bytes  # 16 bytes
    
    # Sequence tracking
    send_seqno: int  # Starts at 1
    recv_seqno: int  # Starts at 1
    
    # Transcript
    transcript_file: FileHandle
    transcript_path: str
```

### Message Model

```python
class ChatMessage:
    type: str  # "msg"
    seqno: int
    timestamp: int  # Unix milliseconds
    ciphertext: str  # base64
    signature: str  # base64
```

### Receipt Model

```python
class SessionReceipt:
    type: str  # "receipt"
    peer: str  # "client" or "server"
    first_seq: int
    last_seq: int
    transcript_sha256: str  # hex
    signature: str  # base64
```

## Error Handling
**Assignment Reference:** Section 2.1 - PKI Setup, Section 3 - Testing & Evidence

### Error Categories

**1. Certificate Errors**
- `BAD_CERT_EXPIRED`: Certificate validity period does not include current time
- `BAD_CERT_SELF_SIGNED`: Certificate issuer equals subject
- `BAD_CERT_UNTRUSTED`: Certificate not signed by trusted CA
- `BAD_CERT_INVALID_SIG`: Signature verification failed

**Action**: Log error, close connection, exit


**2. Message Integrity Errors**
- `SIG_FAIL`: Signature verification failed (message tampered)
- `REPLAY`: Sequence number not strictly increasing (replay attack)

**Action**: Log error, reject message, continue session

**3. Authentication Errors**
- `AUTH_FAILED`: Login credentials incorrect
- `USER_EXISTS`: Registration failed, username/email already exists
- `USER_NOT_FOUND`: Login failed, email not found

**Action**: Send error response, allow retry or close connection

**4. Network Errors**
- `CONNECTION_LOST`: Socket closed unexpectedly
- `TIMEOUT`: No response within timeout period

**Action**: Log error, close connection, cleanup resources

### Error Logging

All errors logged to console with format:
```
[TIMESTAMP] [ERROR_CODE] Details
```

Example:
```
[2024-11-16 10:30:45] [BAD_CERT_EXPIRED] Certificate expired on 2024-10-01
[2024-11-16 10:31:12] [SIG_FAIL] Message seqno=5 signature verification failed
[2024-11-16 10:32:00] [REPLAY] Received seqno=3, expected seqno=6
```

## Testing Strategy
**Assignment Reference:** Section 3 - Testing & Evidence

### 1. Certificate Validation Tests

**Test Case 1.1: Valid Certificate**
- Setup: Generate valid CA and entity certificates
- Action: Exchange certificates
- Expected: Connection proceeds, no errors

**Test Case 1.2: Expired Certificate**
- Setup: Generate certificate with past validity period
- Action: Attempt connection
- Expected: `BAD_CERT_EXPIRED` logged, connection rejected

**Test Case 1.3: Self-Signed Certificate**
- Setup: Generate self-signed certificate (not CA-signed)
- Action: Attempt connection
- Expected: `BAD_CERT_SELF_SIGNED` logged, connection rejected

**Test Case 1.4: Untrusted CA**
- Setup: Generate certificate signed by different CA
- Action: Attempt connection
- Expected: `BAD_CERT_UNTRUSTED` logged, connection rejected


### 2. Registration and Login Tests

**Test Case 2.1: Successful Registration**
- Setup: Fresh database
- Action: Register new user with email, username, password
- Expected: User record created with salt and pwd_hash, success response

**Test Case 2.2: Duplicate Registration**
- Setup: User already exists
- Action: Attempt to register with same email or username
- Expected: `USER_EXISTS` error, no new record created

**Test Case 2.3: Successful Login**
- Setup: User registered
- Action: Login with correct email and password
- Expected: Authentication succeeds, session key established

**Test Case 2.4: Failed Login - Wrong Password**
- Setup: User registered
- Action: Login with incorrect password
- Expected: `AUTH_FAILED` error, connection rejected

**Test Case 2.5: Failed Login - User Not Found**
- Setup: User not registered
- Action: Login with non-existent email
- Expected: `USER_NOT_FOUND` error, connection rejected

### 3. Encryption and Decryption Tests

**Test Case 3.1: AES Encryption/Decryption**
- Setup: Generate random AES key
- Action: Encrypt plaintext, then decrypt ciphertext
- Expected: Decrypted text matches original plaintext

**Test Case 3.2: PKCS7 Padding**
- Setup: Various plaintext lengths (15, 16, 17, 32 bytes)
- Action: Apply padding, then remove padding
- Expected: Unpadded text matches original

### 4. Message Integrity Tests

**Test Case 4.1: Valid Message**
- Setup: Establish session
- Action: Send properly encrypted and signed message
- Expected: Message received, decrypted, and displayed

**Test Case 4.2: Tampered Ciphertext**
- Setup: Establish session
- Action: Flip one bit in ciphertext before sending
- Expected: `SIG_FAIL` logged, message rejected

**Test Case 4.3: Tampered Sequence Number**
- Setup: Establish session
- Action: Modify seqno in message
- Expected: `SIG_FAIL` logged, message rejected

**Test Case 4.4: Tampered Timestamp**
- Setup: Establish session
- Action: Modify timestamp in message
- Expected: `SIG_FAIL` logged, message rejected


### 5. Replay Attack Tests

**Test Case 5.1: Replay Old Message**
- Setup: Establish session, send message with seqno=3
- Action: Resend same message (seqno=3) after seqno=4 has been sent
- Expected: `REPLAY` logged, message rejected

**Test Case 5.2: Out-of-Order Messages**
- Setup: Establish session, send messages 1, 2, 3
- Action: Send message with seqno=2 again
- Expected: `REPLAY` logged, message rejected

### 6. Non-Repudiation Tests

**Test Case 6.1: Transcript Generation**
- Setup: Complete chat session with 5 messages
- Action: Check transcript file
- Expected: File contains 5 lines with correct format

**Test Case 6.2: Session Receipt Generation**
- Setup: Complete chat session
- Action: Generate session receipt
- Expected: Receipt contains correct transcript hash and valid signature

**Test Case 6.3: Offline Verification - Valid Transcript**
- Setup: Transcript and receipt from completed session
- Action: Run verification tool
- Expected: `VERIFICATION SUCCESS` reported

**Test Case 6.4: Offline Verification - Tampered Transcript**
- Setup: Modify one character in transcript file
- Action: Run verification tool
- Expected: `VERIFICATION FAILED` reported, transcript hash mismatch

**Test Case 6.5: Offline Verification - Tampered Receipt**
- Setup: Modify signature in receipt
- Action: Run verification tool
- Expected: `VERIFICATION FAILED` reported, signature verification failed

### 7. Network Traffic Tests (Wireshark)

**Test Case 7.1: Encrypted Credentials**
- Setup: Start Wireshark capture
- Action: Register or login
- Expected: No plaintext email, username, or password visible in packets

**Test Case 7.2: Encrypted Messages**
- Setup: Start Wireshark capture
- Action: Send chat messages
- Expected: Only base64-encoded ciphertext visible, no plaintext messages

**Test Case 7.3: Certificate Exchange**
- Setup: Start Wireshark capture
- Action: Establish connection
- Expected: PEM-encoded certificates visible (expected), but no private keys


## Security Considerations

### 1. Key Management
- Private keys stored in PEM files with restricted permissions (chmod 600)
- Keys never transmitted over network
- Session keys derived fresh for each session
- Keys cleared from memory after session ends

### 2. Password Security
- Passwords never stored in plaintext
- Unique random salt per user (16 bytes)
- SHA-256 hashing with salt
- Constant-time comparison to prevent timing attacks
- Passwords never logged

### 3. Replay Protection
- Strictly increasing sequence numbers
- Sequence number included in signature
- Old messages rejected immediately

### 4. Tampering Protection
- All messages signed with RSA
- Signature covers seqno, timestamp, and ciphertext
- Any modification invalidates signature

### 5. Forward Secrecy Limitation
- Basic DH provides session separation but not forward secrecy
- If private keys compromised, past sessions can be decrypted
- Note: Assignment uses basic DH, not ephemeral DH with key deletion

## File Structure

```
securechat/
├── certs/
│   ├── ca_key.pem          # CA private key (gitignored)
│   ├── ca_cert.pem         # CA certificate (gitignored)
│   ├── server_key.pem      # Server private key (gitignored)
│   ├── server_cert.pem     # Server certificate
│   ├── client_key.pem      # Client private key (gitignored)
│   └── client_cert.pem     # Client certificate
├── scripts/
│   ├── gen_ca.py           # Generate CA
│   └── gen_cert.py         # Generate entity certificates
├── transcripts/            # Session transcripts (gitignored)
│   └── session_*.txt
├── receipts/               # Session receipts (gitignored)
│   └── session_*_receipt.json
├── server.py               # Server application
├── client.py               # Client application
├── verify.py               # Offline verification tool
├── crypto_utils.py         # Cryptography helper functions
├── db_utils.py             # Database helper functions
├── protocol.py             # Message protocol functions
├── requirements.txt        # Python dependencies
├── .env.example            # Example environment variables
├── .gitignore              # Git ignore rules
└── README.md               # Setup and usage instructions
```


## Dependencies

**Python Libraries** (requirements.txt):
```
cryptography>=41.0.0      # X.509, RSA, DH, signatures
pycryptodome>=3.19.0      # AES encryption
mysql-connector-python>=8.2.0  # MySQL database
python-dotenv>=1.0.0      # Environment variables
```

**System Requirements**:
- Python 3.8 or higher
- MySQL 8.0 or higher
- OpenSSL (for certificate inspection)
- Wireshark (for network traffic testing)

## Environment Variables

**.env file** (not committed to git):
```
DB_HOST=localhost
DB_PORT=3306
DB_USER=securechat_user
DB_PASSWORD=your_secure_password
DB_NAME=securechat_db

SERVER_HOST=127.0.0.1
SERVER_PORT=8443
```

**.env.example file** (committed to git):
```
DB_HOST=localhost
DB_PORT=3306
DB_USER=your_db_user
DB_PASSWORD=your_db_password
DB_NAME=securechat_db

SERVER_HOST=127.0.0.1
SERVER_PORT=8443
```

## Setup Instructions Summary

**Prerequisites**:
1. Install Python 3.8+
2. Install MySQL 8.0+
3. Install pip packages: `pip install -r requirements.txt`

**Database Setup**:
1. Create MySQL database: `CREATE DATABASE securechat_db;`
2. Create user and grant privileges
3. Run schema creation script
4. Configure .env file with database credentials

**Certificate Setup**:
1. Run `python scripts/gen_ca.py` to create CA
2. Run `python scripts/gen_cert.py server` to create server certificate
3. Run `python scripts/gen_cert.py client` to create client certificate
4. Verify certificates: `openssl x509 -in certs/server_cert.pem -text -noout`

**Running the System**:
1. Start server: `python server.py`
2. Start client: `python client.py`
3. Choose register or login
4. Start chatting

**Testing**:
1. Start Wireshark capture on loopback interface
2. Run test scenarios (valid cert, expired cert, tampered message, replay)
3. Verify offline: `python verify.py --transcript transcripts/session_123.txt --receipt receipts/session_123_receipt.json --cert certs/peer_cert.pem`


## Design Rationale

### Why Simple "Baby Code"?

This design prioritizes simplicity and readability for exam preparation:

1. **Explicit loops instead of comprehensions**: Easier to debug and understand
2. **No advanced Python features**: Avoid decorators, context managers (except basic file operations), metaclasses
3. **Clear variable names**: `plaintext_bytes` instead of `pt`, `ciphertext_with_iv` instead of `ct`
4. **One operation per line**: Avoid chaining multiple operations
5. **Extensive comments**: Every function has a clear docstring explaining purpose and parameters

### Why Library-Based Crypto?

1. **Assignment allows it**: Section 6 explicitly states "You are not required to implement the internal mathematics"
2. **Security**: Using vetted libraries prevents implementation errors
3. **Time efficiency**: Focus on protocol logic, not crypto math
4. **Industry practice**: Real systems use libraries, not custom crypto

### Why No TLS/SSL?

1. **Assignment requirement**: Section 6 states "Do not use TLS/SSL or any secure-channel abstraction"
2. **Educational purpose**: Demonstrates how TLS-like protocols work at application layer
3. **Explicit control**: Full visibility into certificate validation, key exchange, encryption, and signatures

### Why MySQL for Credentials Only?

1. **Assignment requirement**: Section 2.2 states "chat messages and transcripts must never be written to the database"
2. **Non-repudiation**: Transcripts must be in files for offline verification
3. **Simplicity**: Avoid complex database queries for message retrieval

### Why Two DH Exchanges?

1. **Separation of concerns**: 
   - Temporary DH protects credentials during authentication
   - Session DH protects chat messages after authentication
2. **Security**: Even if session key compromised, credentials remain protected
3. **Assignment compliance**: Section 2.2 describes temporary DH for credentials, Section 2.3 describes session DH

