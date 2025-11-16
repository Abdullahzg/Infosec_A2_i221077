"""
Simple test script to verify protocol.py functions work correctly.
"""

import protocol
import json


def test_message_formatting():
    """Test all message formatting functions."""
    print("Testing message formatting functions...")
    
    # Test hello message
    hello = protocol.create_hello_msg("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----", "abc123")
    assert hello["type"] == "hello"
    assert hello["client_cert"] == "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"
    assert hello["nonce"] == "abc123"
    print("✓ create_hello_msg works")
    
    # Test server hello message
    server_hello = protocol.create_server_hello_msg("-----BEGIN CERTIFICATE-----\nserver\n-----END CERTIFICATE-----", "def456")
    assert server_hello["type"] == "server_hello"
    assert server_hello["server_cert"] == "-----BEGIN CERTIFICATE-----\nserver\n-----END CERTIFICATE-----"
    assert server_hello["nonce"] == "def456"
    print("✓ create_server_hello_msg works")
    
    # Test register message
    register = protocol.create_register_msg("user@example.com", "testuser", "hashhash", "saltsalt")
    assert register["type"] == "register"
    assert register["email"] == "user@example.com"
    assert register["username"] == "testuser"
    assert register["pwd"] == "hashhash"
    assert register["salt"] == "saltsalt"
    print("✓ create_register_msg works")
    
    # Test login message
    login = protocol.create_login_msg("user@example.com", "hashhash", "nonce123")
    assert login["type"] == "login"
    assert login["email"] == "user@example.com"
    assert login["pwd"] == "hashhash"
    assert login["nonce"] == "nonce123"
    print("✓ create_login_msg works")
    
    # Test DH client message
    dh_client = protocol.create_dh_client_msg(2, 12345, 67890)
    assert dh_client["type"] == "dh_client"
    assert dh_client["g"] == 2
    assert dh_client["p"] == 12345
    assert dh_client["A"] == 67890
    print("✓ create_dh_client_msg works")
    
    # Test DH server message
    dh_server = protocol.create_dh_server_msg(11111)
    assert dh_server["type"] == "dh_server"
    assert dh_server["B"] == 11111
    print("✓ create_dh_server_msg works")
    
    # Test chat message
    chat = protocol.create_chat_msg(1, 1700000000000, "ciphertext123", "signature456")
    assert chat["type"] == "msg"
    assert chat["seqno"] == 1
    assert chat["ts"] == 1700000000000
    assert chat["ct"] == "ciphertext123"
    assert chat["sig"] == "signature456"
    print("✓ create_chat_msg works")
    
    # Test receipt message
    receipt = protocol.create_receipt_msg("client", 1, 10, "abcdef123456", "sig789")
    assert receipt["type"] == "receipt"
    assert receipt["peer"] == "client"
    assert receipt["first_seq"] == 1
    assert receipt["last_seq"] == 10
    assert receipt["transcript_sha256"] == "abcdef123456"
    assert receipt["sig"] == "sig789"
    print("✓ create_receipt_msg works")
    
    print("\nAll message formatting tests passed! ✓")


def test_json_serialization():
    """Test that all messages can be JSON serialized."""
    print("\nTesting JSON serialization...")
    
    # Create various messages
    messages = [
        protocol.create_hello_msg("cert", "nonce"),
        protocol.create_server_hello_msg("cert", "nonce"),
        protocol.create_register_msg("email", "user", "pwd", "salt"),
        protocol.create_login_msg("email", "pwd", "nonce"),
        protocol.create_dh_client_msg(2, 12345, 67890),
        protocol.create_dh_server_msg(11111),
        protocol.create_chat_msg(1, 1700000000000, "ct", "sig"),
        protocol.create_receipt_msg("client", 1, 10, "hash", "sig")
    ]
    
    # Try to serialize each message
    for msg in messages:
        json_str = json.dumps(msg)
        decoded = json.loads(json_str)
        assert decoded == msg
    
    print("✓ All messages can be JSON serialized and deserialized")
    print("\nAll JSON serialization tests passed! ✓")


if __name__ == "__main__":
    test_message_formatting()
    test_json_serialization()
    print("\n" + "="*50)
    print("ALL TESTS PASSED! ✓✓✓")
    print("="*50)
