"""
Test script to verify protocol transmission functions work correctly.
Uses socket pair for testing send/receive functionality.
"""

import protocol
import socket
import threading
import time


def test_socket_transmission():
    """Test send_message and receive_message with real sockets."""
    print("Testing socket transmission functions...")
    
    # Create a socket pair for testing
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('127.0.0.1', 0))  # Bind to any available port
    server_socket.listen(1)
    
    # Get the port number
    port = server_socket.getsockname()[1]
    
    # Variable to store received message
    received_msg = [None]
    
    def server_thread():
        """Server thread to receive message."""
        conn, addr = server_socket.accept()
        received_msg[0] = protocol.receive_message(conn)
        conn.close()
    
    # Start server thread
    server = threading.Thread(target=server_thread)
    server.start()
    
    # Give server time to start
    time.sleep(0.1)
    
    # Create client socket and connect
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('127.0.0.1', port))
    
    # Create a test message
    test_msg = protocol.create_hello_msg("test_cert", "test_nonce")
    
    # Send message
    protocol.send_message(client_socket, test_msg)
    
    # Close client socket
    client_socket.close()
    
    # Wait for server thread to finish
    server.join()
    
    # Close server socket
    server_socket.close()
    
    # Verify received message matches sent message
    assert received_msg[0] is not None
    assert received_msg[0]["type"] == "hello"
    assert received_msg[0]["client_cert"] == "test_cert"
    assert received_msg[0]["nonce"] == "test_nonce"
    
    print("✓ send_message and receive_message work correctly")


def test_multiple_messages():
    """Test sending and receiving multiple messages in sequence."""
    print("\nTesting multiple message transmission...")
    
    # Create a socket pair for testing
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('127.0.0.1', 0))
    server_socket.listen(1)
    
    port = server_socket.getsockname()[1]
    
    # List to store received messages
    received_msgs = []
    
    def server_thread():
        """Server thread to receive multiple messages."""
        conn, addr = server_socket.accept()
        for i in range(3):
            msg = protocol.receive_message(conn)
            received_msgs.append(msg)
        conn.close()
    
    # Start server thread
    server = threading.Thread(target=server_thread)
    server.start()
    
    # Give server time to start
    time.sleep(0.1)
    
    # Create client socket and connect
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('127.0.0.1', port))
    
    # Create and send multiple test messages
    msg1 = protocol.create_dh_client_msg(2, 12345, 67890)
    msg2 = protocol.create_dh_server_msg(11111)
    msg3 = protocol.create_chat_msg(1, 1700000000000, "test_ct", "test_sig")
    
    protocol.send_message(client_socket, msg1)
    protocol.send_message(client_socket, msg2)
    protocol.send_message(client_socket, msg3)
    
    # Close client socket
    client_socket.close()
    
    # Wait for server thread to finish
    server.join()
    
    # Close server socket
    server_socket.close()
    
    # Verify all messages received correctly
    assert len(received_msgs) == 3
    assert received_msgs[0]["type"] == "dh_client"
    assert received_msgs[0]["g"] == 2
    assert received_msgs[1]["type"] == "dh_server"
    assert received_msgs[1]["B"] == 11111
    assert received_msgs[2]["type"] == "msg"
    assert received_msgs[2]["seqno"] == 1
    
    print("✓ Multiple messages transmitted correctly")


def test_large_message():
    """Test sending and receiving a large message."""
    print("\nTesting large message transmission...")
    
    # Create a socket pair for testing
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('127.0.0.1', 0))
    server_socket.listen(1)
    
    port = server_socket.getsockname()[1]
    
    received_msg = [None]
    
    def server_thread():
        """Server thread to receive message."""
        conn, addr = server_socket.accept()
        received_msg[0] = protocol.receive_message(conn)
        conn.close()
    
    # Start server thread
    server = threading.Thread(target=server_thread)
    server.start()
    
    # Give server time to start
    time.sleep(0.1)
    
    # Create client socket and connect
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('127.0.0.1', port))
    
    # Create a large message (simulate large certificate)
    large_cert = "A" * 10000  # 10KB certificate
    test_msg = protocol.create_hello_msg(large_cert, "nonce")
    
    # Send message
    protocol.send_message(client_socket, test_msg)
    
    # Close client socket
    client_socket.close()
    
    # Wait for server thread to finish
    server.join()
    
    # Close server socket
    server_socket.close()
    
    # Verify received message matches sent message
    assert received_msg[0] is not None
    assert received_msg[0]["type"] == "hello"
    assert len(received_msg[0]["client_cert"]) == 10000
    assert received_msg[0]["client_cert"] == large_cert
    
    print("✓ Large message transmitted correctly")


if __name__ == "__main__":
    test_socket_transmission()
    test_multiple_messages()
    test_large_message()
    print("\n" + "="*50)
    print("ALL TRANSMISSION TESTS PASSED! ✓✓✓")
    print("="*50)
