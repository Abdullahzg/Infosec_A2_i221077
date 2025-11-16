# Secure Chat System

A console-based secure chat application implementing cryptographic protocols to achieve Confidentiality, Integrity, Authenticity, and Non-Repudiation (CIANR).

## Overview

This system demonstrates practical cryptographic implementations using:
- **AES-128** for message encryption
- **RSA with X.509 certificates** for authentication and digital signatures
- **Diffie-Hellman key exchange** for session key establishment
- **SHA-256** for hashing and integrity verification

The system protects against:
- Passive eavesdropping
- Active Man-in-the-Middle attacks
- Replay attacks
- Unauthorized access attempts

## Features

- **PKI Infrastructure**: Self-built Certificate Authority for issuing and validating certificates
- **Mutual Authentication**: Both client and server verify each other's certificates
- **Secure Registration/Login**: Credentials encrypted with temporary DH-derived keys
- **Encrypted Chat**: Messages encrypted with session-specific AES keys
- **Message Integrity**: RSA signatures prevent tampering
- **Replay Protection**: Sequence numbers prevent message replay
- **Non-Repudiation**: Session transcripts and cryptographic receipts provide proof of communication

## Prerequisites

Before setting up the system, ensure you have:

1. **Python 3.8+** installed on your system
2. **MySQL 8.0+** installed and running
3. **pip** package manager

## Installation

### 1. Clone the Repository

```bash
git clone <your-github-repo-url>
cd securechat
```

### 2. Create Virtual Environment (Recommended)

```bash
python -m venv venv

# On Windows
venv\Scripts\activate

# On Linux/Mac
source venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Database Setup

Create the MySQL database and user:

```sql
CREATE DATABASE securechat_db;
CREATE USER 'securechat_user'@'localhost' IDENTIFIED BY 'your_password';
GRANT ALL PRIVILEGES ON securechat_db.* TO 'securechat_user'@'localhost';
FLUSH PRIVILEGES;
```

### 5. Configure Environment Variables

Copy the example environment file and update with your credentials:

```bash
# On Windows
copy .env.example .env

# On Linux/Mac
cp .env.example .env
```

Edit `.env` and update the database password and other settings as needed.

### 6. Generate Certificates

Generate the Certificate Authority:

```bash
python scripts/gen_ca.py
```

Generate server certificate:

```bash
python scripts/gen_cert.py server
```

Generate client certificate:

```bash
python scripts/gen_cert.py client
```

Verify certificates (optional):

```bash
openssl x509 -in certs/server_cert.pem -text -noout
```

## Usage

### Starting the Server

```bash
python server.py
```

The server will start listening on the configured host and port (default: 127.0.0.1:8443).

### Starting the Client

In a separate terminal:

```bash
python client.py
```

### Registration

1. When prompted, choose to register
2. Enter your email address
3. Enter a username
4. Enter a password
5. Wait for confirmation

### Login

1. When prompted, choose to login
2. Enter your registered email
3. Enter your password
4. Upon successful authentication, you can start chatting

### Chatting

- Type your message and press Enter to send
- Messages from the other party will appear automatically
- Type "exit" to end the session

### Session Closure

When you exit:
- A transcript file is saved in `transcripts/`
- A session receipt is generated in `receipts/`
- These can be used for offline verification

## Offline Verification

To verify a chat transcript:

```bash
python verify.py --transcript transcripts/session_123.txt --receipt receipts/session_123_client_receipt.json --cert certs/server_cert.pem
```

This will verify:
- Each message signature
- The transcript hash
- The receipt signature

## Testing

### Certificate Validation Test

Test with expired, self-signed, or untrusted certificates to verify proper rejection and error logging.

### Tampering Test

Modify a message ciphertext to verify signature verification fails with `SIG_FAIL` error.

### Replay Test

Resend an old message to verify replay detection with `REPLAY` error.

### Wireshark Test

1. Start Wireshark on loopback interface (127.0.0.1)
2. Apply display filter: `tcp.port == 8443` (or your configured SERVER_PORT)
3. Start capture
4. Run registration and chat session
5. Stop capture
6. Verify no plaintext credentials or messages are visible
7. Confirm only base64-encoded ciphertext is transmitted
8. Save PCAP file for documentation

## Project Structure

```
securechat/
├── certs/                  # Certificate files (gitignored)
├── scripts/                # Certificate generation scripts
│   ├── gen_ca.py
│   └── gen_cert.py
├── transcripts/            # Session transcripts (gitignored)
├── receipts/               # Session receipts (gitignored)
├── server.py               # Server application
├── client.py               # Client application
├── verify.py               # Offline verification tool
├── crypto_utils.py         # Cryptography utilities
├── db_utils.py             # Database utilities
├── protocol.py             # Message protocol
├── transcript_utils.py     # Transcript logging
├── requirements.txt        # Python dependencies
├── .env.example            # Example environment variables
├── .gitignore              # Git ignore rules
└── README.md               # This file
```

## Message Formats

### Control Plane Messages

**Hello Message:**
```json
{
  "type": "hello",
  "client_cert": "...PEM...",
  "nonce": "base64_encoded_nonce"
}
```

**Registration Message:**
```json
{
  "type": "register",
  "email": "user@example.com",
  "username": "username",
  "pwd": "base64_encoded_salted_hash",
  "salt": "base64_encoded_salt"
}
```

**Login Message:**
```json
{
  "type": "login",
  "email": "user@example.com",
  "pwd": "base64_encoded_salted_hash",
  "nonce": "base64_encoded_nonce"
}
```

### Key Agreement Messages

**DH Client Message:**
```json
{
  "type": "dh_client",
  "g": 2,
  "p": 123456789,
  "A": 987654321
}
```

### Data Plane Messages

**Chat Message:**
```json
{
  "type": "msg",
  "seqno": 1,
  "ts": 1700000000000,
  "ct": "base64_encoded_ciphertext",
  "sig": "base64_encoded_signature"
}
```

### Non-Repudiation Messages

**Session Receipt:**
```json
{
  "type": "receipt",
  "peer": "client",
  "first_seq": 1,
  "last_seq": 10,
  "transcript_sha256": "hex_encoded_hash",
  "sig": "base64_encoded_signature"
}
```

## Security Properties

### Confidentiality
- All credentials encrypted with temporary DH-derived AES key
- All messages encrypted with session-specific AES key
- No plaintext transmitted over network

### Integrity
- All messages signed with RSA private key
- SHA-256 digest covers sequence number, timestamp, and ciphertext
- Any modification invalidates signature

### Authenticity
- Mutual certificate validation using CA
- RSA signatures prove message origin
- Certificate fingerprints in transcript

### Non-Repudiation
- Append-only transcripts log all messages
- Session receipts signed with private key
- Offline verification proves conversation occurred

### Replay Protection
- Strictly increasing sequence numbers
- Sequence number included in signature
- Old messages rejected immediately

## Troubleshooting

### Database Connection Error
- Verify MySQL is running
- Check credentials in `.env` file
- Ensure database and user exist

### Certificate Validation Error
- Regenerate certificates if expired
- Ensure CA certificate is present
- Check certificate file permissions

### Connection Refused
- Verify server is running
- Check SERVER_HOST and SERVER_PORT in `.env`
- Ensure firewall allows connection

### Import Errors
- Activate virtual environment
- Reinstall dependencies: `pip install -r requirements.txt`

### Message Signature Verification Fails (SIG_FAIL)
- Ensure both client and server have correct certificates
- Verify system clocks are synchronized
- Check that certificates haven't expired

### Replay Detection Triggering Incorrectly
- Ensure messages are sent in order
- Don't resend messages manually
- Restart session if sequence numbers become desynchronized

### Transcript Verification Fails
- Ensure transcript file hasn't been modified
- Use the correct peer certificate for verification
- Verify receipt file matches the transcript

## GitHub Repository

**Repository URL:** https://github.com/Abdullahzg/Infosec_A2_i221077

This project is developed with incremental commits showing the development process. Check the commit history to see the implementation progress.

## License

This project is for educational purposes as part of an Information Security course assignment.

## Acknowledgments

- Assignment template: https://github.com/maadilrehman/securechat-skeleton
- Python cryptography library documentation
- MySQL connector documentation
