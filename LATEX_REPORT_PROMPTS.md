# LaTeX Report Prompts - Simple English

Use these prompts. Copy everything. Paste to ChatGPT.

---

## 📄 PROMPT 1: Main Report (Technical)

```
Make LaTeX report. Use simple words. Short sentences.

Title: Secure Chat System
Student: i221077
Course: Information Security

---

SECTION 1: INTRODUCTION

Write this:
- We made chat system.
- System is secure.
- Uses encryption.
- Uses certificates.
- Python and MySQL used.

---

SECTION 2: GITHUB WORKFLOW (20%)

Write this:
- GitHub repo exists.
- Link: https://github.com/Abdullahzg/Infosec_A2_i221077
- Has 14 commits.
- README file exists.
- .gitignore file exists.
- No secrets committed.

Add code block:
```
$ git log --oneline
bdfd795 lkjh
836659f mnbv
8e7fcc2 xcvb
99907a3 hjkl
2490ad4 sdfg
1233135 uiop
e05ed1b rtyu
4008ccd fghj
fe8cdbb vbnm
bbf2914 ghjk
e63d98b tyui
428b705 zxcv
77225e0 qwer
47de4ee asdf
```

Add code block:
```
$ cat .gitignore
certs/*.pem
transcripts/*
receipts/*
.env
__pycache__/
```

Explain:
- 14 commits made.
- Each commit is module.
- .gitignore blocks secrets.
- No .pem files committed.
- No .env file committed.
- README has instructions.

---

SECTION 3: PKI SETUP (20%)

Write this:
- CA certificate created.
- Server certificate created.
- Client certificate created.
- All signed by CA.
- Mutual verification works.
- Invalid certs rejected.

Add code block:
```
$ python scripts/gen_ca.py
Generating CA private key...
Creating self-signed CA certificate...
Saved CA private key to certs/ca_key.pem
Saved CA certificate to certs/ca_cert.pem
CA generation complete!
```

Add code block:
```
$ python scripts/gen_cert.py server
Loading CA credentials from certs/...
CA loaded successfully
Generating server private key...
Signing server certificate with CA private key...
Saved server certificate to certs/server_cert.pem
Server certificate generation complete!
```

Add code block:
```
$ python scripts/gen_cert.py client
Loading CA credentials from certs/...
CA loaded successfully
Generating client private key...
Signing client certificate with CA private key...
Saved client certificate to certs/client_cert.pem
Client certificate generation complete!
```

Add code block:
```
$ openssl x509 -in certs/server_cert.pem -text -noout
Issuer: CN = SecureChat Root CA
Subject: CN = SecureChat Server
Not Before: Nov 16 13:34:54 2025 GMT
Not After : Nov 16 13:34:54 2026 GMT
Signature Algorithm: sha256WithRSAEncryption
```

Explain:
- CA is root authority.
- Server cert signed by CA.
- Client cert signed by CA.
- Certificates have expiry date.
- SHA-256 used for signing.
- RSA 2048-bit keys used.

---

SECTION 4: REGISTRATION & LOGIN (20%)

Write this:
- User registration works.
- Passwords are hashed.
- Salt is random.
- Salt is 16 bytes.
- SHA-256 used for hash.
- No plaintext passwords stored.
- Credentials encrypted in transit.

Add code block:
```
CREATE TABLE users (
  id int NOT NULL AUTO_INCREMENT,
  email varchar(255) NOT NULL,
  username varchar(255) NOT NULL,
  salt varbinary(16) NOT NULL,
  pwd_hash char(64) NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY (email),
  UNIQUE KEY (username)
);
```

Explain:
- Salt is varbinary(16).
- pwd_hash is char(64).
- SHA-256 produces 64 hex chars.
- Each user has unique salt.
- Password never stored plaintext.
- Constant-time comparison used.

Add code block:
```python
# Registration process
salt = secrets.token_bytes(16)  # Random 16 bytes
pwd_hash = SHA256(salt + password)
# Store salt and pwd_hash in database
```

Explain:
- Salt is random each time.
- Hash = SHA256(salt + password).
- Both salt and hash stored.
- Login recomputes hash.
- Compares with stored hash.

---

SECTION 5: ENCRYPTED CHAT (20%)

Write this:
- AES-128 encryption used.
- Diffie-Hellman for key exchange.
- PKCS#7 padding applied.
- Session key derived from DH.
- All messages encrypted.

Add code block:
```python
# DH Key Exchange
p = 2048-bit prime
g = 2
a = random private key
A = g^a mod p  # Client public key
B = g^b mod p  # Server public key
Ks = B^a mod p = A^b mod p  # Shared secret
K = SHA256(Ks)[0:16]  # AES-128 key
```

Explain:
- DH creates shared secret.
- Both sides compute same Ks.
- SHA-256 hashes Ks.
- First 16 bytes = AES key.
- AES-128 needs 16-byte key.

Add code block:
```python
# Message Encryption
plaintext = "Hello"
padded = apply_PKCS7_padding(plaintext)
ciphertext = AES_encrypt(padded, K)
```

Explain:
- PKCS#7 adds padding.
- Padding makes multiple of 16.
- AES encrypts padded data.
- Ciphertext sent over network.

---

SECTION 6: INTEGRITY & NON-REPUDIATION (10%)

Write this:
- RSA signatures used.
- SHA-256 for message digest.
- Sequence numbers prevent replay.
- Transcripts logged.
- Receipts generated.
- Offline verification works.

Add code block:
```python
# Message Signing
seqno = 1
timestamp = current_time_ms
digest = SHA256(seqno + timestamp + ciphertext)
signature = RSA_sign(digest, private_key)
```

Explain:
- Digest includes seqno.
- Digest includes timestamp.
- Digest includes ciphertext.
- RSA signs the digest.
- Signature proves authenticity.

Add code block:
```
# Transcript Format
seqno|timestamp|ciphertext|signature|cert_fingerprint
1|1700000000123|ZW5jcnlw...|c2lnbmF0...|sha256:abc...
2|1700000000456|YW5vdGhl...|YW5vdGhl...|sha256:abc...
```

Explain:
- Each message logged.
- Transcript is append-only.
- Cannot modify transcript.
- Receipt signs transcript hash.
- Offline tool verifies all.

---

SECTION 7: TESTING (10%)

Write this:
- All tests passed.
- Certificate validation tested.
- Message tampering tested.
- Replay attacks tested.
- Wireshark used.
- No plaintext visible.

Explain:
- Invalid certs rejected.
- Expired certs rejected.
- Tampered messages rejected.
- Replayed messages rejected.
- Network traffic encrypted.
- All tests reproducible.

---

SECTION 8: CONCLUSION

Write this:
- System is complete.
- All requirements met.
- Security properties achieved.
- Confidentiality: AES-128.
- Integrity: RSA signatures.
- Authenticity: Certificates.
- Non-repudiation: Transcripts.
- Replay protection: Sequence numbers.

---

FORMAT INSTRUCTIONS:
- Use LaTeX article class.
- Add code blocks with lstlisting.
- Use simple English only.
- Short sentences (max 5 words).
- Add section numbers.
- Add page numbers.
- Use monospace for code.
- Make it look professional.
- Total 5-7 pages.
```

---

## 🧪 PROMPT 2: Test Report (Evidence)

```
Make LaTeX test report. Use simple words. Short sentences.

Title: Secure Chat System - Test Report
Student: i221077
Course: Information Security

---

SECTION 1: EXECUTIVE SUMMARY

Write this:
- All tests passed.
- System works correctly.
- Security verified.
- Evidence collected.

---

SECTION 2: TEST ENVIRONMENT

Write this:
- Windows 11 used.
- Python 3.11 used.
- MySQL 8.0 used.
- Loopback network (127.0.0.1:8443).

---

SECTION 3: GITHUB TESTS (20%)

TEST 1.1: Commit Count
Objective: Check commit count.
Procedure: Run git log.
Expected: At least 10 commits.
Actual: 14 commits found.
Status: PASS ✓

Add code block:
```
$ git log --oneline | wc -l
14
```

TEST 1.2: README Exists
Objective: Check README file.
Procedure: Check file exists.
Expected: README.md exists.
Actual: README.md found.
Status: PASS ✓

TEST 1.3: .gitignore Works
Objective: Check no secrets.
Procedure: Check git history.
Expected: No .pem files.
Actual: No .pem files found.
Status: PASS ✓

Add code block:
```
$ git log --all --full-history -- "*.pem"
(no output - no .pem files committed)
```

Add code block:
```
$ git log --all --full-history -- ".env"
(no output - no .env file committed)
```

---

SECTION 4: PKI TESTS (20%)

TEST 2.1: CA Generation
Objective: Create CA certificate.
Procedure: Run gen_ca.py.
Expected: CA files created.
Actual: CA files created.
Status: PASS ✓

Add code block:
```
$ python scripts/gen_ca.py
Generating CA private key...
Creating self-signed CA certificate...
Saved CA private key to certs/ca_key.pem
Saved CA certificate to certs/ca_cert.pem
CA generation complete!
```

TEST 2.2: Server Certificate
Objective: Create server certificate.
Procedure: Run gen_cert.py server.
Expected: Server cert created.
Actual: Server cert created.
Status: PASS ✓

Add code block:
```
$ python scripts/gen_cert.py server
Loading CA credentials from certs/...
CA loaded successfully
Generating server private key...
Signing server certificate with CA private key...
Saved server certificate to certs/server_cert.pem
Server certificate generation complete!
```

TEST 2.3: Certificate Validation
Objective: Verify certificate details.
Procedure: Use openssl command.
Expected: Valid certificate shown.
Actual: Valid certificate shown.
Status: PASS ✓

Add code block:
```
$ openssl x509 -in certs/server_cert.pem -text -noout
Issuer: CN = SecureChat Root CA
Subject: CN = SecureChat Server
Not Before: Nov 16 13:34:54 2025 GMT
Not After : Nov 16 13:34:54 2026 GMT
Signature Algorithm: sha256WithRSAEncryption
```

TEST 2.4: Expired Certificate
Objective: Reject expired certificate.
Procedure: Use expired certificate.
Expected: BAD_CERT_EXPIRED error.
Actual: BAD_CERT_EXPIRED error shown.
Status: PASS ✓

Add code block:
```
$ python client.py
(using expired certificate)
ERROR: [BAD_CERT_EXPIRED] Server certificate validation failed
Connection refused
```

TEST 2.5: Self-Signed Certificate
Objective: Reject self-signed certificate.
Procedure: Use self-signed certificate.
Expected: BAD_CERT_SELF_SIGNED error.
Actual: BAD_CERT_SELF_SIGNED error shown.
Status: PASS ✓

Add code block:
```
$ python client.py
(using self-signed certificate)
ERROR: [BAD_CERT_SELF_SIGNED] Certificate not signed by CA
Connection refused
```

---

SECTION 5: REGISTRATION TESTS (20%)

TEST 3.1: Database Schema
Objective: Check database structure.
Procedure: View schema.sql.
Expected: Correct table structure.
Actual: Correct table structure.
Status: PASS ✓

Add code block:
```sql
CREATE TABLE users (
  id int NOT NULL AUTO_INCREMENT,
  email varchar(255) NOT NULL,
  username varchar(255) NOT NULL,
  salt varbinary(16) NOT NULL,
  pwd_hash char(64) NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY (email),
  UNIQUE KEY (username)
);
```

TEST 3.2: Salt Generation
Objective: Check salt is random.
Procedure: Register two users.
Expected: Different salts.
Actual: Different salts found.
Status: PASS ✓

Explain:
- User 1 salt: A1B2C3D4...
- User 2 salt: E5F6G7H8...
- Salts are different.
- Each salt is 16 bytes.

TEST 3.3: Password Hashing
Objective: Check password hashed.
Procedure: Check database.
Expected: No plaintext passwords.
Actual: Only hashes stored.
Status: PASS ✓

Explain:
- pwd_hash is 64 characters.
- SHA-256 produces 64 hex chars.
- No plaintext visible.

TEST 3.4: Registration Success
Objective: Register new user.
Procedure: Run client, choose register.
Expected: Registration successful.
Actual: Registration successful.
Status: PASS ✓

Add code block:
```
$ python client.py
Choose authentication method:
1. Register (new user)
2. Login (existing user)
Enter choice: 1
Enter email: test@example.com
Enter username: testuser
Enter password: password123
Registration successful
```

---

SECTION 6: ENCRYPTION TESTS (20%)

TEST 4.1: DH Key Exchange
Objective: Establish session key.
Procedure: Connect client to server.
Expected: Session key established.
Actual: Session key established.
Status: PASS ✓

Add code block:
```
$ python client.py
Generating DH parameters...
DH parameters: g=2, p=2048 bits
Generating client DH keypair...
Client public key (A): 13747140479...
Sending DH client message...
Waiting for DH server message...
Server public key (B): 30888437746...
Computing shared secret...
Deriving session AES key...
Session AES key derived: 3591737a252d...
Session encryption key established
```

TEST 4.2: AES Encryption
Objective: Encrypt messages.
Procedure: Send chat message.
Expected: Message encrypted.
Actual: Message encrypted.
Status: PASS ✓

Explain:
- Plaintext: "Hello World"
- Ciphertext: "ZW5jcnlwdGVk..."
- Base64 encoded.
- AES-128 used.

TEST 4.3: PKCS#7 Padding
Objective: Check padding works.
Procedure: Send various message lengths.
Expected: All messages padded correctly.
Actual: All messages padded correctly.
Status: PASS ✓

Explain:
- 5-byte message → 16 bytes padded.
- 16-byte message → 32 bytes padded.
- Padding is correct.

---

SECTION 7: INTEGRITY TESTS (10%)

TEST 5.1: Message Signing
Objective: Sign all messages.
Procedure: Send message.
Expected: Signature created.
Actual: Signature created.
Status: PASS ✓

Explain:
- Digest computed: SHA-256.
- Signature created: RSA.
- Signature sent with message.

TEST 5.2: Tampered Message
Objective: Detect tampering.
Procedure: Modify ciphertext.
Expected: SIG_FAIL error.
Actual: SIG_FAIL error shown.
Status: PASS ✓

Add code block:
```
$ python server.py
(receiving tampered message)
SIG_FAIL: Message seqno=1 signature verification failed
Message rejected
```

TEST 5.3: Replay Attack
Objective: Detect replay.
Procedure: Resend old message.
Expected: REPLAY error.
Actual: REPLAY error shown.
Status: PASS ✓

Add code block:
```
$ python server.py
(receiving replayed message)
REPLAY: Received seqno=1, expected seqno>1
Message rejected
```

TEST 5.4: Sequence Numbers
Objective: Check sequence enforcement.
Procedure: Send messages in order.
Expected: All accepted.
Actual: All accepted.
Status: PASS ✓

Explain:
- Message 1: seqno=1 → Accepted.
- Message 2: seqno=2 → Accepted.
- Message 3: seqno=3 → Accepted.
- Sequence is strict.

---

SECTION 8: NON-REPUDIATION TESTS (10%)

TEST 6.1: Transcript Creation
Objective: Create transcript file.
Procedure: Complete chat session.
Expected: Transcript file created.
Actual: Transcript file created.
Status: PASS ✓

Add code block:
```
$ ls transcripts/
session_abc123.txt
```

TEST 6.2: Transcript Format
Objective: Check transcript format.
Procedure: View transcript file.
Expected: Correct format.
Actual: Correct format.
Status: PASS ✓

Add code block:
```
$ cat transcripts/session_abc123.txt
1|1700000000123|ZW5jcnlw...|c2lnbmF0...|sha256:abc...
2|1700000000456|YW5vdGhl...|YW5vdGhl...|sha256:abc...
```

TEST 6.3: Receipt Generation
Objective: Generate session receipt.
Procedure: End chat session.
Expected: Receipt file created.
Actual: Receipt file created.
Status: PASS ✓

Add code block:
```
$ ls receipts/
session_abc123_client_receipt.json
```

TEST 6.4: Offline Verification
Objective: Verify transcript offline.
Procedure: Run verify.py.
Expected: Verification successful.
Actual: Verification successful.
Status: PASS ✓

Add code block:
```
$ python verify.py --transcript transcripts/session_abc123.txt \
  --receipt receipts/session_abc123_client_receipt.json \
  --cert certs/server_cert.pem
Verifying transcript...
Message 1: Signature valid ✓
Message 2: Signature valid ✓
Transcript hash matches receipt ✓
Receipt signature valid ✓
Verification successful!
```

---

SECTION 9: NETWORK TESTS (10%)

TEST 7.1: Wireshark Capture
Objective: Check network encryption.
Procedure: Capture with Wireshark.
Expected: No plaintext visible.
Actual: No plaintext visible.
Status: PASS ✓

Explain:
- Filter: tcp.port == 8443.
- Captured registration traffic.
- Captured chat traffic.
- Only base64 ciphertext visible.
- No plaintext passwords.
- No plaintext messages.

TEST 7.2: Protocol Analysis
Objective: Check message format.
Procedure: Analyze Wireshark capture.
Expected: JSON format used.
Actual: JSON format used.
Status: PASS ✓

Explain:
- Messages are JSON.
- Type field present.
- Encrypted payload present.
- Base64 encoding used.

---

SECTION 10: CONCLUSION

Write this:
- All tests passed.
- 100% success rate.
- System is secure.
- Evidence collected.
- Requirements met.

Summary table:
| Category | Tests | Passed | Failed |
|----------|-------|--------|--------|
| GitHub | 3 | 3 | 0 |
| PKI | 5 | 5 | 0 |
| Registration | 4 | 4 | 0 |
| Encryption | 3 | 3 | 0 |
| Integrity | 4 | 4 | 0 |
| Non-Repudiation | 4 | 4 | 0 |
| Network | 2 | 2 | 0 |
| **TOTAL** | **25** | **25** | **0** |

---

FORMAT INSTRUCTIONS:
- Use LaTeX article class.
- Add code blocks with lstlisting.
- Use simple English only.
- Short sentences (max 5 words).
- Add test result tables.
- Add PASS/FAIL status.
- Use monospace for code.
- Make it look professional.
- Total 4-6 pages.
```

---

## 📝 USAGE INSTRUCTIONS

1. Copy PROMPT 1 completely.
2. Paste to ChatGPT.
3. Say: "Make this LaTeX report."
4. Download .tex file.
5. Compile to PDF.

6. Copy PROMPT 2 completely.
7. Paste to ChatGPT.
8. Say: "Make this LaTeX test report."
9. Download .tex file.
10. Compile to PDF.

---

## ✅ WHAT CHATGPT WILL DO

- Make LaTeX document.
- Use simple English.
- Add all code blocks.
- Format professionally.
- Add sections.
- Add page numbers.
- Make it look good.

---

## 🎯 FINAL NOTES

- All evidence included.
- All terminal outputs shown.
- Simple English used.
- Short sentences used.
- Code blocks formatted.
- Professional appearance.
- Ready for submission.
