# Requirements Document

## Introduction

This document specifies the requirements for a Console-Based Secure Chat System that demonstrates practical cryptographic implementations. The system implements a client-server architecture using AES-128, RSA with X.509 certificates, Diffie-Hellman key exchange, and SHA-256 to achieve Confidentiality, Integrity, Authenticity, and Non-Repudiation (CIANR). The system protects against passive eavesdropping, active Man-in-the-Middle attacks, replay attacks, and unauthorized access attempts.

## Glossary

- **SecureChatSystem**: The complete client-server application implementing cryptographic protocols
- **CA**: Certificate Authority - a self-built root authority that issues and signs certificates
- **ClientApp**: The client-side console application that initiates connections and sends messages
- **ServerApp**: The server-side console application that accepts connections and responds to messages
- **ControlPlane**: The initial phase handling certificate exchange and authentication
- **DataPlane**: The phase handling encrypted message exchange during active chat
- **SessionReceipt**: A digitally signed proof of the complete chat session for non-repudiation
- **TranscriptHash**: SHA-256 hash computed over all messages in a session
- **DH**: Diffie-Hellman key exchange protocol
- **CIANR**: Confidentiality, Integrity, Authenticity, and Non-Repudiation

## Requirements

### Requirement 1: PKI Infrastructure Setup
**Assignment Reference:** Section 2.1 - PKI Setup and Certificate Validation

**User Story:** As a system administrator, I want to create a root Certificate Authority and issue certificates to both client and server, so that mutual authentication can be established before any communication.

#### Acceptance Criteria

1. WHEN the gen_ca.py script is executed, THE SecureChatSystem SHALL generate a root CA private key and a self-signed X.509 certificate stored in the certs/ directory
   - _Assignment Reference: Section 2.1 - "Implement two scripts: scripts/gen_ca.py: creates a root CA"_

2. WHEN the gen_cert.py script is executed with entity parameters, THE SecureChatSystem SHALL generate an RSA keypair and issue a CA-signed X.509 certificate for the specified entity
   - _Assignment Reference: Section 2.1 - "scripts/gen_cert.py: issues RSA X.509 certificates for both server and client"_

3. THE SecureChatSystem SHALL store the server certificate, server private key, client certificate, and client private key in separate PEM files within the certs/ directory
   - _Assignment Reference: Section 2.1 - "Each entity (client and server) must possess: Its own RSA keypair, A signed certificate"_

4. THE SecureChatSystem SHALL ensure that private keys and CA certificates are excluded from version control through .gitignore configuration
   - _Assignment Reference: Section 2.1 - "The root CA's private key and certificate should be stored locally (never committed to GitHub)"_

5. WHEN a certificate is inspected, THE SecureChatSystem SHALL display the issuer, subject, validity period, and signature algorithm information
   - _Assignment Reference: Section 2.1 - "Your report must include certificate inspection results (either through a script or using openssl x509 -text)"_

### Requirement 2: Certificate Validation and Mutual Authentication
**Assignment Reference:** Section 1.1 - Control Plane (Negotiation and Authentication), Section 2.1 - PKI Setup and Certificate Validation

**User Story:** As a security-conscious user, I want both client and server to validate each other's certificates before exchanging any data, so that I can trust the identity of my communication partner.

#### Acceptance Criteria

1. WHEN the ClientApp connects to the ServerApp, THE ClientApp SHALL send its X.509 certificate in PEM format along with a random nonce
   - _Assignment Reference: Section 1.1 - Control Plane Message Format: {"type":"hello", "client_cert":"...PEM...", "nonce": base64}_

2. WHEN the ServerApp receives a client certificate, THE ServerApp SHALL send its own X.509 certificate in PEM format along with a random nonce
   - _Assignment Reference: Section 1.1 - Control Plane Message Format: {"type":"server_hello", "server_cert":"...PEM...", "nonce": base64}_

3. WHEN either party receives a certificate, THE SecureChatSystem SHALL verify the certificate signature chain against the trusted root CA
   - _Assignment Reference: Section 2.1 - "Both verify the received certificate by checking: Signature chain validity (trusted CA)"_

4. WHEN either party receives a certificate, THE SecureChatSystem SHALL verify that the certificate validity period includes the current date and time
   - _Assignment Reference: Section 2.1 - "Both verify the received certificate by checking: Expiry date and validity period"_

5. IF a received certificate is self-signed, expired, or not signed by the trusted CA, THEN THE SecureChatSystem SHALL reject the connection and log "BAD_CERT" with the reason
   - _Assignment Reference: Section 2.1 - "The server must reject and log any self-signed, expired, or untrusted certificate with a clear error (e.g., BAD_CERT)"_

6. WHEN certificate validation succeeds on both sides, THE SecureChatSystem SHALL proceed to the authentication phase
   - _Assignment Reference: Section 1.1 - "The control plane ensures that: Each participant is authenticated through their CA-issued certificate"_

### Requirement 3: Secure User Registration
**Assignment Reference:** Section 2.2 - Registration and Login

**User Story:** As a new user, I want to register my credentials securely without transmitting my password in plaintext, so that my account cannot be compromised by network eavesdropping.

#### Acceptance Criteria

1. WHEN the ClientApp initiates registration, THE ClientApp SHALL perform a temporary Diffie-Hellman key exchange with the ServerApp to derive an ephemeral AES-128 key
   - _Assignment Reference: Section 2.2 - "A temporary Diffie–Hellman (DH) exchange is performed to generate a shared secret Ks"_

2. WHEN the user provides registration data, THE ClientApp SHALL generate a random 16-byte salt for the user
   - _Assignment Reference: Section 2.2 - "Generates a 16-byte random salt for the user"_

3. WHEN the user provides a password, THE ClientApp SHALL compute the salted hash as SHA-256(salt || password) and encode it in base64
   - _Assignment Reference: Section 1.1 - Control Plane Message Format: {"type":"register", "pwd":base64(sha256(salt||pwd)), "salt": base64}_

4. WHEN registration data is ready, THE ClientApp SHALL encrypt the email, username, salted password hash, and salt using AES-128 with PKCS7 padding
   - _Assignment Reference: Section 2.2 - "The client then encrypts the registration data (email, username, password) using AES-128 (block cipher + PKCS#7 padding)"_

5. WHEN the ServerApp receives encrypted registration data, THE ServerApp SHALL decrypt it using the ephemeral AES-128 key
   - _Assignment Reference: Section 2.2 - "The server decrypts this payload"_

6. WHEN the ServerApp processes registration, THE ServerApp SHALL verify that the username and email are not already registered in the MySQL database
   - _Assignment Reference: Section 2.2 - "verifies that the username or email is not already registered"_

7. WHEN registration validation passes, THE ServerApp SHALL store the email, username, salt, and salted password hash in the users table
   - _Assignment Reference: Section 2.2 - "Stores this in a MySQL table as: users(email VARCHAR, username VARCHAR UNIQUE, salt VARBINARY(16), pwd_hash CHAR(64))"_

8. THE ServerApp SHALL NOT store plaintext passwords in any file, database, or log
   - _Assignment Reference: Section 2.2 - "No plaintext passwords in files/logs" (Grading Rubric)_

### Requirement 4: Secure User Login
**Assignment Reference:** Section 2.2 - Registration and Login

**User Story:** As a returning user, I want to log in securely using my credentials without exposing my password on the network, so that only I can access my account.

#### Acceptance Criteria

1. WHEN the ClientApp initiates login, THE ClientApp SHALL perform a new temporary Diffie-Hellman key exchange to derive a fresh ephemeral AES-128 key
   - _Assignment Reference: Section 2.2 - "During login, a new DH exchange and AES key are used"_

2. WHEN the user provides login credentials, THE ClientApp SHALL retrieve the salt from the ServerApp for the given email
   - _Assignment Reference: Section 2.2 - "The client sends encrypted credentials" (implies salt retrieval for hash computation)_

3. WHEN the salt is received, THE ClientApp SHALL compute the salted password hash as SHA-256(salt || password) and encode it in base64
   - _Assignment Reference: Section 1.1 - Control Plane Message Format: {"type":"login", "pwd": base64(sha256(salt||pwd))}_

4. WHEN login data is ready, THE ClientApp SHALL encrypt the email, salted password hash, and a fresh nonce using AES-128 with PKCS7 padding
   - _Assignment Reference: Section 2.2 - "The client sends encrypted credentials"_

5. WHEN the ServerApp receives encrypted login data, THE ServerApp SHALL decrypt it using the ephemeral AES-128 key
   - _Assignment Reference: Section 2.2 - "the server recomputes the salted hash to verify them"_

6. WHEN the ServerApp validates login, THE ServerApp SHALL retrieve the stored salted password hash for the provided email from the MySQL database
   - _Assignment Reference: Section 2.2 - "the server recomputes the salted hash to verify them"_

7. WHEN comparing password hashes, THE ServerApp SHALL use constant-time comparison to prevent timing attacks
   - _Assignment Reference: Grading Rubric - "constant-time compare"_

8. IF the computed hash matches the stored hash and the certificate is valid, THEN THE ServerApp SHALL grant access and proceed to session key establishment
   - _Assignment Reference: Section 2.2 - "Login succeeds only if: The client certificate is valid and trusted, and The salted hash matches the stored pwd_hash"_

9. IF the computed hash does not match or the certificate is invalid, THEN THE ServerApp SHALL reject the login attempt and log the failure
   - _Assignment Reference: Section 2.2 - "Login succeeds only if..." (implies rejection otherwise)_

### Requirement 5: Session Key Establishment via Diffie-Hellman
**Assignment Reference:** Section 1.2 - Key Agreement (Post-Authentication), Section 2.3 - Session Key Establishment (Basic Diffie–Hellman)

**User Story:** As a chat participant, I want a unique session key to be established for each chat session, so that my messages are encrypted with a key that cannot be derived from previous sessions.

#### Acceptance Criteria

1. WHEN login succeeds, THE ClientApp SHALL generate a random private value 'a' and compute the public value A = g^a mod p using agreed-upon DH parameters
   - _Assignment Reference: Section 2.3 - "Each side chooses a private key (a or b) and computes A = g^a mod p"_

2. WHEN the ClientApp sends DH parameters, THE ClientApp SHALL transmit the public parameters g, p, and the computed public value A to the ServerApp
   - _Assignment Reference: Section 1.2 - Key Agreement Message Format: {"type":"dh_client", "g": int, "p": int, "A": int}_

3. WHEN the ServerApp receives DH parameters, THE ServerApp SHALL generate a random private value 'b' and compute the public value B = g^b mod p
   - _Assignment Reference: Section 2.3 - "Each side chooses a private key (a or b) and computes B = g^b mod p"_

4. WHEN the ServerApp computes its public value, THE ServerApp SHALL send B to the ClientApp
   - _Assignment Reference: Section 1.2 - Key Agreement Message Format: {"type":"dh_server", "B": int}_

5. WHEN both parties have exchanged public values, THE ClientApp SHALL compute the shared secret Ks = B^a mod p
   - _Assignment Reference: Section 1.2 - "Both compute the shared secret Ks = A^b mod p = B^a mod p"_

6. WHEN both parties have exchanged public values, THE ServerApp SHALL compute the shared secret Ks = A^b mod p
   - _Assignment Reference: Section 1.2 - "Both compute the shared secret Ks = A^b mod p = B^a mod p"_

7. WHEN the shared secret is computed, THE SecureChatSystem SHALL convert Ks to big-endian byte representation and compute SHA-256(Ks)
   - _Assignment Reference: Section 1.2 - "K = Trunc16(SHA256(big-endian(Ks)))"_

8. WHEN the hash is computed, THE SecureChatSystem SHALL truncate the SHA-256 output to the first 16 bytes to derive the session key K
   - _Assignment Reference: Section 1.2 - "K = Trunc16(SHA256(big-endian(Ks)))"_

9. THE SecureChatSystem SHALL use the derived key K as the AES-128 encryption key for all subsequent chat messages in the session
   - _Assignment Reference: Section 1.2 - "This 16-byte key (K) is used for AES-128 encryption and decryption during the data exchange phase"_

### Requirement 6: Encrypted and Authenticated Message Exchange
**Assignment Reference:** Section 1.3 - Data Plane (Encrypted Message Exchange), Section 2.4 - Encrypted Chat and Message Integrity

**User Story:** As a chat participant, I want my messages to be encrypted and digitally signed, so that only my intended recipient can read them and verify they came from me without modification.

#### Acceptance Criteria

1. WHEN a user types a message, THE SecureChatSystem SHALL apply PKCS7 padding to the plaintext message
   - _Assignment Reference: Section 2.4 - "The plaintext is padded using PKCS#7"_

2. WHEN the message is padded, THE SecureChatSystem SHALL encrypt it using AES-128 in CBC or ECB mode with the session key K
   - _Assignment Reference: Section 2.4 - "encrypted using AES-128 (block cipher) with the session key K"_

3. WHEN the ciphertext is generated, THE SecureChatSystem SHALL assign a strictly increasing sequence number to the message
   - _Assignment Reference: Section 1.3 - Data Plane Message Format: {"type":"msg", "seqno": n}_

4. WHEN the ciphertext is generated, THE SecureChatSystem SHALL record the current Unix timestamp in milliseconds
   - _Assignment Reference: Section 1.3 - Data Plane Message Format: {"type":"msg", "ts": unix_ms}_

5. WHEN metadata is ready, THE SecureChatSystem SHALL compute the digest h = SHA-256(seqno || timestamp || ciphertext)
   - _Assignment Reference: Section 2.4 - "The sender computes: h = SHA256(seqno || timestamp || ciphertext)"_

6. WHEN the digest is computed, THE SecureChatSystem SHALL sign the digest using the sender's RSA private key to produce a digital signature
   - _Assignment Reference: Section 2.4 - "The hash h is signed with the sender's RSA private key: sig = RSA_SIGN(h)"_

7. WHEN the signature is created, THE SecureChatSystem SHALL encode the ciphertext and signature in base64 and transmit them as a JSON message with type "msg"
   - _Assignment Reference: Section 1.3 - Data Plane Message Format: {"type":"msg", "ct": base64, "sig": base64(RSA_SIGN(SHA256(seqno||ts||ct)))}_

8. WHEN the recipient receives a message, THE SecureChatSystem SHALL verify that the sequence number is strictly greater than the previous message sequence number
   - _Assignment Reference: Section 1.3 - "seqno – ensures messages are processed in order and prevents replays"_

9. IF the sequence number is not strictly increasing, THEN THE SecureChatSystem SHALL reject the message and log "REPLAY"
   - _Assignment Reference: Section 3 - Testing & Evidence: "Replay test: resend old seqno → REPLAY"_

10. WHEN the recipient validates the message, THE SecureChatSystem SHALL recompute the digest h = SHA-256(seqno || timestamp || ciphertext)
   - _Assignment Reference: Section 2.4 - "Verifies the signature using the sender's certificate and recomputed hash"_

11. WHEN the digest is recomputed, THE SecureChatSystem SHALL verify the RSA signature using the sender's public key from their certificate
   - _Assignment Reference: Section 2.4 - "Verifies the signature using the sender's certificate and recomputed hash"_

12. IF the signature verification fails, THEN THE SecureChatSystem SHALL reject the message and log "SIG_FAIL"
   - _Assignment Reference: Section 3 - Testing & Evidence: "Tampering test: flip a bit in ct → recomputed digest/signature fails → SIG_FAIL"_

13. WHEN signature verification succeeds, THE SecureChatSystem SHALL decrypt the ciphertext using AES-128 with the session key K
   - _Assignment Reference: Section 2.4 - "Decrypts the ciphertext using AES-128 and removes PKCS#7 padding"_

14. WHEN decryption completes, THE SecureChatSystem SHALL remove PKCS7 padding and display the plaintext message to the user
   - _Assignment Reference: Section 2.4 - "Decrypts the ciphertext using AES-128 and removes PKCS#7 padding"_

### Requirement 7: Replay Attack Prevention
**Assignment Reference:** Section 1.3 - Data Plane (Encrypted Message Exchange), Section 3 - Testing & Evidence

**User Story:** As a chat participant, I want the system to detect and reject replayed messages, so that an attacker cannot resend old messages to confuse or deceive me.

#### Acceptance Criteria

1. WHEN a chat session begins, THE SecureChatSystem SHALL initialize the expected sequence number to 1 for both sending and receiving
   - _Assignment Reference: Section 1.3 - "seqno – ensures messages are processed in order and prevents replays"_

2. WHEN sending a message, THE SecureChatSystem SHALL increment the outgoing sequence number by 1
   - _Assignment Reference: Section 1.3 - "seqno – ensures messages are processed in order and prevents replays"_

3. WHEN receiving a message, THE SecureChatSystem SHALL verify that the received sequence number equals the expected incoming sequence number
   - _Assignment Reference: Section 1.3 - "Freshness (sequence + timestamp enforcement)"_

4. IF the received sequence number is less than or equal to the last accepted sequence number, THEN THE SecureChatSystem SHALL reject the message and log "REPLAY"
   - _Assignment Reference: Section 3 - Testing & Evidence: "Replay test: resend old seqno → REPLAY"_

5. WHEN a message passes sequence number validation, THE SecureChatSystem SHALL update the expected incoming sequence number to the next value
   - _Assignment Reference: Section 1.3 - "seqno – ensures messages are processed in order and prevents replays"_

### Requirement 8: Message Tampering Detection
**Assignment Reference:** Section 1.3 - Data Plane (Encrypted Message Exchange), Section 3 - Testing & Evidence

**User Story:** As a chat participant, I want the system to detect any modification to messages in transit, so that I can trust the integrity of received messages.

#### Acceptance Criteria

1. WHEN a message is received, THE SecureChatSystem SHALL extract the ciphertext, sequence number, and timestamp from the JSON payload
   - _Assignment Reference: Section 1.3 - Data Plane Message Format: {"type":"msg", "seqno": n, "ts": unix_ms, "ct": base64}_

2. WHEN the message components are extracted, THE SecureChatSystem SHALL recompute the digest h = SHA-256(seqno || timestamp || ciphertext) using the received values
   - _Assignment Reference: Section 2.4 - "Upon receiving, the recipient: Verifies the signature using the sender's certificate and recomputed hash"_

3. WHEN the digest is recomputed, THE SecureChatSystem SHALL verify the RSA signature against the recomputed digest using the sender's public key
   - _Assignment Reference: Section 1.3 - "Integrity (SHA-256 digest), Authenticity (RSA signature validation)"_

4. IF any bit in the ciphertext, sequence number, or timestamp has been modified, THEN THE digest will not match and signature verification SHALL fail
   - _Assignment Reference: Section 1.3 - "This structure ensures that even a single-bit change in ciphertext or metadata will invalidate the signature"_

5. IF signature verification fails, THEN THE SecureChatSystem SHALL reject the message, log "SIG_FAIL", and SHALL NOT decrypt or display the message
   - _Assignment Reference: Section 3 - Testing & Evidence: "Tampering test: flip a bit in ct → recomputed digest/signature fails → SIG_FAIL"_

### Requirement 9: Session Transcript Logging
**Assignment Reference:** Section 1.4 - Non-Repudiation (Session Evidence)

**User Story:** As a chat participant, I want a complete record of all messages exchanged in a session, so that I can later prove what was communicated.

#### Acceptance Criteria

1. WHEN a chat session begins, THE SecureChatSystem SHALL create an append-only transcript file for the session
   - _Assignment Reference: Section 1.4 - "Both client and server maintain an append-only transcript"_

2. WHEN a message is sent or received, THE SecureChatSystem SHALL append a line to the transcript containing the sequence number, timestamp, ciphertext, signature, and peer certificate fingerprint
   - _Assignment Reference: Section 1.4 - "seqno | ts | ct | sig | peer-cert-fingerprint"_

3. THE SecureChatSystem SHALL separate transcript fields using the pipe character "|" as a delimiter
   - _Assignment Reference: Section 1.4 - "seqno | ts | ct | sig | peer-cert-fingerprint"_

4. THE SecureChatSystem SHALL NOT allow modification or deletion of transcript entries during an active session
   - _Assignment Reference: Section 1.4 - "append-only transcript"_

5. WHEN the session ends, THE SecureChatSystem SHALL preserve the complete transcript file for non-repudiation verification
   - _Assignment Reference: Section 2.5 - "Each side maintains a local append-only transcript file"_

### Requirement 10: Non-Repudiation via Session Receipt
**Assignment Reference:** Section 1.4 - Non-Repudiation (Session Evidence), Section 2.5 - Non-Repudiation and Session Closure

**User Story:** As a chat participant, I want to generate cryptographic proof of the entire conversation, so that neither party can later deny their participation or the content of messages exchanged.

#### Acceptance Criteria

1. WHEN a chat session ends, THE SecureChatSystem SHALL read the complete transcript file
   - _Assignment Reference: Section 2.5 - "Each side maintains a local append-only transcript file"_

2. WHEN the transcript is read, THE SecureChatSystem SHALL concatenate all transcript lines in order
   - _Assignment Reference: Section 1.4 - "TranscriptHash = SHA256(concatenation of transcript lines)"_

3. WHEN the concatenation is complete, THE SecureChatSystem SHALL compute the TranscriptHash = SHA-256(concatenated transcript)
   - _Assignment Reference: Section 1.4 - "TranscriptHash = SHA256(concatenation of transcript lines)"_

4. WHEN the TranscriptHash is computed, THE SecureChatSystem SHALL sign the TranscriptHash using the participant's RSA private key
   - _Assignment Reference: Section 1.4 - "This hash is digitally signed with the sender's RSA private key"_

5. WHEN the signature is created, THE SecureChatSystem SHALL generate a SessionReceipt JSON object containing the peer identifier, first sequence number, last sequence number, TranscriptHash in hexadecimal, and the signature in base64
   - _Assignment Reference: Section 1.4 - SessionReceipt Format: {"type":"receipt", "peer":"client|server", "first_seq":..., "last_seq":..., "transcript_sha256":hex, "sig":base64(RSA_SIGN(transcript_sha256))}_

6. WHEN the SessionReceipt is generated, THE SecureChatSystem SHALL save it to a file or exchange it with the peer
   - _Assignment Reference: Section 2.5 - "The SessionReceipt is exchanged or stored locally"_

7. THE SecureChatSystem SHALL provide a mechanism to verify a SessionReceipt offline by recomputing the TranscriptHash and verifying the RSA signature
   - _Assignment Reference: Section 2.5 - "Offline verification must confirm that any transcript modification invalidates the receipt signature"_

### Requirement 11: Offline Transcript Verification
**Assignment Reference:** Section 3 - Testing & Evidence (Non-repudiation test)

**User Story:** As an auditor or third party, I want to verify the authenticity and integrity of a chat transcript, so that I can confirm the conversation occurred as recorded without tampering.

#### Acceptance Criteria

1. WHEN an offline verification is requested, THE SecureChatSystem SHALL accept a transcript file and a SessionReceipt as inputs
   - _Assignment Reference: Section 3 - "Non-repudiation: export transcript & SessionReceipt; show offline verification"_

2. WHEN verification begins, THE SecureChatSystem SHALL parse each line of the transcript to extract sequence number, timestamp, ciphertext, signature, and peer certificate fingerprint
   - _Assignment Reference: Section 1.4 - "seqno | ts | ct | sig | peer-cert-fingerprint"_

3. WHEN each message is parsed, THE SecureChatSystem SHALL recompute the digest h = SHA-256(seqno || timestamp || ciphertext)
   - _Assignment Reference: Section 3 - "Verify each message: recompute SHA-256 digest"_

4. WHEN the digest is recomputed, THE SecureChatSystem SHALL verify the message signature using the peer's public key from their certificate
   - _Assignment Reference: Section 3 - "Verify each message: verify RSA signature"_

5. IF any message signature fails verification, THEN THE SecureChatSystem SHALL report which message failed and halt verification
   - _Assignment Reference: Section 3 - "Show that any edit breaks verification"_

6. WHEN all message signatures are verified, THE SecureChatSystem SHALL concatenate all transcript lines and compute the TranscriptHash = SHA-256(concatenated transcript)
   - _Assignment Reference: Section 3 - "Verify receipt: verify RSA signature over TranscriptHash"_

7. WHEN the TranscriptHash is computed, THE SecureChatSystem SHALL compare it to the TranscriptHash in the SessionReceipt
   - _Assignment Reference: Section 1.4 - "The SessionReceipt acts as a digital evidence artifact"_

8. WHEN the hashes are compared, THE SecureChatSystem SHALL verify the SessionReceipt signature using the participant's public key from their certificate
   - _Assignment Reference: Section 3 - "Verify receipt: verify RSA signature over TranscriptHash"_

9. IF the TranscriptHash matches and the SessionReceipt signature is valid, THEN THE SecureChatSystem SHALL report "VERIFICATION SUCCESS"
   - _Assignment Reference: Section 3 - "Show that any edit breaks verification" (implies success when no edits)_

10. IF the TranscriptHash does not match or the SessionReceipt signature is invalid, THEN THE SecureChatSystem SHALL report "VERIFICATION FAILED" with the reason
   - _Assignment Reference: Section 3 - "Show that any edit breaks verification"_

### Requirement 12: Network Traffic Confidentiality
**Assignment Reference:** Section 3 - Testing & Evidence (Wireshark test)

**User Story:** As a security analyst, I want to verify that no plaintext credentials or messages are transmitted over the network, so that I can confirm the system protects against eavesdropping.

#### Acceptance Criteria

1. WHEN network traffic is captured using Wireshark or similar tools, THE SecureChatSystem SHALL transmit only encrypted ciphertext for all credential and message payloads
   - _Assignment Reference: Section 3 - "Wireshark: show encrypted payloads (no plaintext)"_

2. WHEN examining captured packets, THE observer SHALL NOT be able to identify plaintext passwords, usernames, emails, or chat message content
   - _Assignment Reference: Section 3 - "Wireshark: show encrypted payloads (no plaintext)"_

3. WHEN examining captured packets, THE observer SHALL be able to identify only base64-encoded ciphertext, certificates in PEM format, and JSON structure metadata
   - _Assignment Reference: Section 3 - "Wireshark: show encrypted payloads (no plaintext). Add display filter(s) used"_

4. THE SecureChatSystem SHALL NOT log plaintext passwords or sensitive credentials in any server or client log files
   - _Assignment Reference: Grading Rubric - "No plaintext passwords in files/logs"_

### Requirement 13: Database Security
**Assignment Reference:** Section 2.2 - Registration and Login, Grading Rubric - Registration & Login Security

**User Story:** As a database administrator, I want user credentials to be stored securely with proper salting and hashing, so that a database breach does not expose user passwords.

#### Acceptance Criteria

1. WHEN a user registers, THE ServerApp SHALL generate a unique random 16-byte salt for that user
   - _Assignment Reference: Section 2.2 - "Generates a 16-byte random salt for the user"_

2. WHEN storing credentials, THE ServerApp SHALL store only the email, username, salt, and the salted password hash in the MySQL users table
   - _Assignment Reference: Section 2.2 - "users(email VARCHAR, username VARCHAR UNIQUE, salt VARBINARY(16), pwd_hash CHAR(64))"_

3. THE ServerApp SHALL compute the salted password hash as hex(SHA-256(salt || password))
   - _Assignment Reference: Section 2.2 - "pwd_hash = hex(SHA256(salt || password))"_

4. THE ServerApp SHALL NOT store plaintext passwords in the database
   - _Assignment Reference: Grading Rubric - "Plain/unsalted storage" (negative criterion)_

5. WHEN comparing passwords during login, THE ServerApp SHALL retrieve the user's salt, recompute the salted hash, and compare using constant-time comparison
   - _Assignment Reference: Grading Rubric - "constant-time compare"_

6. THE ServerApp SHALL NOT store chat messages or transcripts in the MySQL database
   - _Assignment Reference: Section 2.2 - "This database will only store user credentials; chat messages and transcripts must never be written to the database"_

### Requirement 14: Error Handling and Logging
**Assignment Reference:** Section 2.1 - PKI Setup, Section 3 - Testing & Evidence

**User Story:** As a system operator, I want clear error messages and logs for security events, so that I can diagnose issues and detect potential attacks.

#### Acceptance Criteria

1. WHEN a certificate validation fails, THE SecureChatSystem SHALL log "BAD_CERT" with the specific reason such as expired, self-signed, or untrusted issuer
   - _Assignment Reference: Section 2.1 - "The server must reject and log any self-signed, expired, or untrusted certificate with a clear error (e.g., BAD_CERT)"_

2. WHEN a signature verification fails, THE SecureChatSystem SHALL log "SIG_FAIL" with the message sequence number
   - _Assignment Reference: Section 3 - "Tampering test: flip a bit in ct → recomputed digest/signature fails → SIG_FAIL"_

3. WHEN a replay attack is detected, THE SecureChatSystem SHALL log "REPLAY" with the received and expected sequence numbers
   - _Assignment Reference: Section 3 - "Replay test: resend old seqno → REPLAY"_

4. WHEN a login attempt fails, THE ServerApp SHALL log the failed attempt with the email and timestamp
   - _Assignment Reference: Threat Model - "untrusted client attempting login/password guessing" (implies logging)_

5. THE SecureChatSystem SHALL NOT log plaintext passwords, private keys, or session keys in any log file
   - _Assignment Reference: Grading Rubric - "No plaintext passwords in files/logs"_

### Requirement 15: GitHub Repository and Documentation
**Assignment Reference:** Section 2 - System Requirements & Implementation, Section 4 - Submission Instructions, Grading Rubric - GitHub Workflow

**User Story:** As a grader or collaborator, I want a well-organized GitHub repository with clear commit history and documentation, so that I can understand the development process and reproduce the system.

#### Acceptance Criteria

1. THE SecureChatSystem SHALL be developed in a forked GitHub repository based on the securechat-skeleton template
   - _Assignment Reference: Section 2 - "All students must fork and work in their own GitHub copy of: https://github.com/maadilrehman/securechat-skeleton"_

2. THE repository SHALL contain at least 10 meaningful commits showing incremental development progress
   - _Assignment Reference: Section 4 - "At least 10 meaningful commits showing progress"_

3. THE repository SHALL include a README.md file with execution steps, configuration requirements, sample input and output formats, and a link to the GitHub repository
   - _Assignment Reference: Section 4 - "GitHub readme.md file, clearly stating, execution steps, configurations required (if any), sample input/output formats and also link to your github repo"_

4. THE repository SHALL include a .gitignore file that excludes private keys, CA certificates, database credentials, and other secrets
   - _Assignment Reference: Grading Rubric - "proper .gitignore; no secrets"_

5. THE repository SHALL include a .env.example file showing required environment variables without actual secret values
   - _Assignment Reference: Section 7 - "Provide a .env.example"_

6. THE repository SHALL include scripts in a scripts/ directory for CA generation (gen_ca.py) and certificate issuance (gen_cert.py)
   - _Assignment Reference: Section 2.1 - "Implement two scripts: scripts/gen_ca.py, scripts/gen_cert.py"_

7. THE repository SHALL include clear instructions for setting up the MySQL database, installing dependencies, and running the client and server applications
   - _Assignment Reference: Section 7 - "Scripts must be reproducible (CA, certs, start server/client, replicate screenshots)"_
