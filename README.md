# Secure Chat System

A console chat application with encryption and security features.

## What This Is

This is chat system for two people. It uses encryption to keep messages safe. Nobody can read the messages except sender and receiver.

## Main Features

- Certificate authentication for both sides
- Password encryption with random salt
- AES-128 encryption for all messages
- Digital signatures to prevent tampering
- Protection against replay attacks
- Message logs with cryptographic receipts

## What You Need

Before you start, you need these things:

1. Python 3.8 or newer version
2. MySQL 8.0 or newer version
3. pip package manager

## How to Install

### Step 1: Get the Code

```bash
git clone https://github.com/Abdullahzg/Infosec_A2_i221077.git
cd Infosec_A2_i221077
```

### Step 2: Make Virtual Environment

This step is optional but recommended.

```bash
python -m venv venv

# On Windows
venv\Scripts\activate

# On Linux or Mac
source venv/bin/activate
```

### Step 3: Install Required Packages

```bash
pip install -r requirements.txt
```

### Step 4: Setup Database

Open MySQL and run these commands:

```sql
CREATE DATABASE securechat_db;
CREATE USER 'securechat_user'@'localhost' IDENTIFIED BY 'your_password';
GRANT ALL PRIVILEGES ON securechat_db.* TO 'securechat_user'@'localhost';
FLUSH PRIVILEGES;
```

### Step 5: Configure Settings

Copy the example file and edit it:

```bash
# On Windows
copy .env.example .env

# On Linux or Mac
cp .env.example .env
```

Open .env file and change the password to match what you used in Step 4.

### Step 6: Create Certificates

Run these commands to make certificates:

```bash
python scripts/gen_ca.py
python scripts/gen_cert.py server
python scripts/gen_cert.py client
```

## How to Use

### Start the Server

Open one terminal window and run:

```bash
python server.py
```

Server will start and wait for connections.

### Start the Client

Open another terminal window and run:

```bash
python client.py
```

### Register New User

When client starts, you see two options:
1. Register (new user)
2. Login (existing user)

For first time, choose option 1.

Enter these details:
- Email address
- Username
- Password

System will create your account.

### Login

If you already have account, choose option 2.

Enter your email and password.

### Send Messages

After login, you can type messages.
- Type your message
- Press Enter to send
- Type "exit" to quit

### End Session

When you type "exit", system will:
- Save all messages to transcript file
- Create cryptographic receipt
- Close connection

## Verify Messages Later

You can check if messages are real using this command:

```bash
python verify.py --transcript transcripts/session_xxx.txt --receipt receipts/session_xxx_client_receipt.json --cert certs/server_cert.pem
```

Replace "session_xxx" with your actual session ID.

## Test the System

### Test Certificates

Try these tests to see certificate validation:
- Use expired certificate (should fail)
- Use self-signed certificate (should fail)
- Use certificate from different CA (should fail)

### Test Message Security

Try these tests:
- Change message content (should fail)
- Send old message again (should fail)
- Change sequence number (should fail)

### Test with Wireshark

1. Open Wireshark
2. Start capture on loopback (127.0.0.1)
3. Use filter: tcp.port == 8443
4. Run registration and chat
5. Check that no passwords or messages are visible

## Project Files

```
securechat/
├── certs/                  # Certificate files
├── scripts/                # Certificate creation scripts
│   ├── gen_ca.py
│   └── gen_cert.py
├── transcripts/            # Message logs
├── receipts/               # Cryptographic receipts
├── server.py               # Server program
├── client.py               # Client program
├── verify.py               # Verification tool
├── crypto_utils.py         # Encryption functions
├── db_utils.py             # Database functions
├── protocol.py             # Message format
├── transcript_utils.py     # Logging functions
├── requirements.txt        # Required packages
├── .env.example            # Example settings
├── .gitignore              # Git ignore rules
└── README.md               # This file
```

## Message Format Examples

### Registration Message

```json
{
  "type": "register",
  "email": "user@example.com",
  "username": "username",
  "pwd": "base64_encoded_hash",
  "salt": "base64_encoded_salt"
}
```

### Chat Message

```json
{
  "type": "msg",
  "seqno": 1,
  "ts": 1700000000123,
  "ct": "base64_encoded_ciphertext",
  "sig": "base64_encoded_signature"
}
```

### Session Receipt

```json
{
  "type": "receipt",
  "peer": "server",
  "first_seq": 1,
  "last_seq": 10,
  "transcript_sha256": "hex_hash",
  "sig": "base64_signature"
}
```

## Security Features

### Confidentiality
All messages encrypted with AES-128. Nobody can read messages except sender and receiver.

### Integrity
Every message has digital signature. Any change to message will be detected.

### Authenticity
Certificates prove identity. You know who you are talking to.

### Non-Repudiation
All messages saved in transcript. Cryptographic receipt proves conversation happened.

### Replay Protection
Sequence numbers prevent old messages from being sent again.

## Common Problems

### Cannot Connect to Database
- Check MySQL is running
- Check username and password in .env file
- Check database exists

### Certificate Error
- Run certificate generation scripts again
- Check certificate files exist in certs folder
- Check certificates not expired

### Connection Refused
- Check server is running
- Check SERVER_HOST and SERVER_PORT in .env file
- Check firewall settings

### Import Error
- Activate virtual environment
- Run: pip install -r requirements.txt

## GitHub Repository

Repository URL: https://github.com/Abdullahzg/Infosec_A2_i221077

This project has multiple commits showing development progress. Check commit history to see implementation steps.

## Database Schema

The users table stores account information:

```sql
CREATE TABLE users (
  id int NOT NULL AUTO_INCREMENT,
  email varchar(255) NOT NULL,
  username varchar(255) NOT NULL,
  salt varbinary(16) NOT NULL,
  pwd_hash char(64) NOT NULL,
  created_at timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY (email),
  UNIQUE KEY (username)
);
```

Important notes:
- Passwords are never stored in plain text
- Each user has unique random salt
- Password hash is SHA-256 of salt plus password

## License

This project is for educational purposes. Made for Information Security course assignment.

## Credits

- Assignment template from: https://github.com/maadilrehman/securechat-skeleton
- Python cryptography library
- MySQL connector library
