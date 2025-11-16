"""
Database utilities for Secure Chat System.

This module provides functions for:
- Connecting to MySQL database
- Creating users table
- Registering new users
- Retrieving user salt
- Verifying login credentials
- Constant-time string comparison

Assignment Reference: Section 2.2 - Registration and Login, MySQL database
Requirements: 3.6, 3.7, 4.6, 4.7, 13.1, 13.2, 13.3, 13.4, 13.5, 13.6
"""

import os
import mysql.connector
from mysql.connector import Error
from dotenv import load_dotenv


def connect_database():
    """
    Connect to MySQL database using credentials from .env file.
    
    Returns:
        mysql.connector.connection.MySQLConnection: Database connection object
        None: If connection fails
    
    Environment Variables Required:
        DB_HOST: Database host (e.g., localhost)
        DB_PORT: Database port (e.g., 3306)
        DB_USER: Database username
        DB_PASSWORD: Database password
        DB_NAME: Database name
    """
    # Load environment variables from .env file
    load_dotenv()
    
    # Read database credentials from environment
    db_host = os.getenv('DB_HOST')
    db_port = os.getenv('DB_PORT')
    db_user = os.getenv('DB_USER')
    db_password = os.getenv('DB_PASSWORD')
    db_name = os.getenv('DB_NAME')
    
    # Check if all required environment variables are set
    if not all([db_host, db_port, db_user, db_password, db_name]):
        print("[ERROR] Missing database configuration in .env file")
        return None
    
    try:
        # Create connection to MySQL database
        connection = mysql.connector.connect(
            host=db_host,
            port=int(db_port),
            user=db_user,
            password=db_password,
            database=db_name
        )
        
        if connection.is_connected():
            print(f"[INFO] Connected to MySQL database: {db_name}")
            return connection
        else:
            print("[ERROR] Failed to connect to database")
            return None
            
    except Error as e:
        print(f"[ERROR] Database connection error: {e}")
        return None


def create_users_table(connection):
    """
    Create users table with schema for storing user credentials.
    
    Table Schema:
        id: INT AUTO_INCREMENT PRIMARY KEY
        email: VARCHAR(255) UNIQUE NOT NULL
        username: VARCHAR(255) UNIQUE NOT NULL
        salt: VARBINARY(16) NOT NULL
        pwd_hash: CHAR(64) NOT NULL
        created_at: TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    
    Args:
        connection: MySQL database connection object
    
    Returns:
        bool: True if table created successfully, False otherwise
    
    Assignment Reference: Section 2.2 - users table schema
    Requirements: 13.2
    """
    if connection is None or not connection.is_connected():
        print("[ERROR] No database connection")
        return False
    
    try:
        cursor = connection.cursor()
        
        # SQL query to create users table
        create_table_query = """
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            email VARCHAR(255) UNIQUE NOT NULL,
            username VARCHAR(255) UNIQUE NOT NULL,
            salt VARBINARY(16) NOT NULL,
            pwd_hash CHAR(64) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
        
        # Execute the query
        cursor.execute(create_table_query)
        connection.commit()
        
        print("[INFO] Users table created successfully")
        cursor.close()
        return True
        
    except Error as e:
        print(f"[ERROR] Failed to create users table: {e}")
        return False


def register_user(connection, email, username, salt, pwd_hash):
    """
    Register a new user by inserting credentials into users table.
    Checks for duplicate email or username before inserting.
    
    Args:
        connection: MySQL database connection object
        email (str): User email address
        username (str): User username
        salt (bytes): 16-byte random salt
        pwd_hash (str): Hex-encoded SHA-256 salted password hash (64 characters)
    
    Returns:
        tuple: (success: bool, message: str)
            - (True, "Registration successful") if user registered
            - (False, "USER_EXISTS") if email or username already exists
            - (False, error_message) if other error occurs
    
    Assignment Reference: Section 2.2 - Registration
    Requirements: 3.6, 3.7, 13.1, 13.2
    """
    if connection is None or not connection.is_connected():
        print("[ERROR] No database connection")
        return False, "Database connection error"
    
    try:
        cursor = connection.cursor()
        
        # Check if email already exists
        check_email_query = "SELECT id FROM users WHERE email = %s"
        cursor.execute(check_email_query, (email,))
        email_result = cursor.fetchone()
        
        if email_result is not None:
            print(f"[ERROR] Email already registered: {email}")
            cursor.close()
            return False, "USER_EXISTS"
        
        # Check if username already exists
        check_username_query = "SELECT id FROM users WHERE username = %s"
        cursor.execute(check_username_query, (username,))
        username_result = cursor.fetchone()
        
        if username_result is not None:
            print(f"[ERROR] Username already registered: {username}")
            cursor.close()
            return False, "USER_EXISTS"
        
        # Insert new user record
        insert_query = """
        INSERT INTO users (email, username, salt, pwd_hash)
        VALUES (%s, %s, %s, %s)
        """
        cursor.execute(insert_query, (email, username, salt, pwd_hash))
        connection.commit()
        
        print(f"[INFO] User registered successfully: {email}")
        cursor.close()
        return True, "Registration successful"
        
    except Error as e:
        print(f"[ERROR] Failed to register user: {e}")
        return False, str(e)


def get_user_salt(connection, email):
    """
    Retrieve the salt for a given email address.
    
    Args:
        connection: MySQL database connection object
        email (str): User email address
    
    Returns:
        bytes: 16-byte salt if user exists
        None: If user not found or error occurs
    
    Assignment Reference: Section 2.2 - Login (salt retrieval)
    Requirements: 4.2, 13.5
    """
    if connection is None or not connection.is_connected():
        print("[ERROR] No database connection")
        return None
    
    try:
        cursor = connection.cursor()
        
        # Query to retrieve salt for given email
        query = "SELECT salt FROM users WHERE email = %s"
        cursor.execute(query, (email,))
        result = cursor.fetchone()
        
        cursor.close()
        
        if result is not None:
            salt = result[0]
            return salt
        else:
            print(f"[ERROR] User not found: {email}")
            return None
            
    except Error as e:
        print(f"[ERROR] Failed to retrieve salt: {e}")
        return None


def verify_login(connection, email, pwd_hash):
    """
    Verify login credentials by comparing provided password hash with stored hash.
    Uses constant-time comparison to prevent timing attacks.
    
    Args:
        connection: MySQL database connection object
        email (str): User email address
        pwd_hash (str): Hex-encoded SHA-256 salted password hash (64 characters)
    
    Returns:
        tuple: (success: bool, message: str)
            - (True, "Login successful") if credentials match
            - (False, "USER_NOT_FOUND") if email not found
            - (False, "AUTH_FAILED") if password hash does not match
            - (False, error_message) if other error occurs
    
    Assignment Reference: Section 2.2 - Login verification
    Requirements: 4.6, 4.7, 13.5
    """
    if connection is None or not connection.is_connected():
        print("[ERROR] No database connection")
        return False, "Database connection error"
    
    try:
        cursor = connection.cursor()
        
        # Query to retrieve stored password hash for given email
        query = "SELECT pwd_hash FROM users WHERE email = %s"
        cursor.execute(query, (email,))
        result = cursor.fetchone()
        
        cursor.close()
        
        if result is None:
            print(f"[ERROR] User not found: {email}")
            return False, "USER_NOT_FOUND"
        
        stored_pwd_hash = result[0]
        
        # Compare password hashes using constant-time comparison
        if constant_time_compare(pwd_hash, stored_pwd_hash):
            print(f"[INFO] Login successful: {email}")
            return True, "Login successful"
        else:
            print(f"[ERROR] Authentication failed: {email}")
            return False, "AUTH_FAILED"
            
    except Error as e:
        print(f"[ERROR] Failed to verify login: {e}")
        return False, str(e)


def constant_time_compare(a, b):
    """
    Compare two strings in constant time to prevent timing attacks.
    
    This function always compares all bytes even if a mismatch is found early,
    preventing attackers from using timing information to guess passwords.
    
    Args:
        a (str): First string to compare
        b (str): Second string to compare
    
    Returns:
        bool: True if strings are equal, False otherwise
    
    Assignment Reference: Grading Rubric - constant-time compare
    Requirements: 4.7, 13.5
    """
    # If lengths differ, strings cannot be equal
    # But still compare to maintain constant time
    if len(a) != len(b):
        # Compare with dummy value to maintain constant time
        result = 1
        for i in range(len(a)):
            result |= ord(a[i]) ^ ord(a[i])
        return False
    
    # Compare byte by byte
    result = 0
    for i in range(len(a)):
        result |= ord(a[i]) ^ ord(b[i])
    
    # Return True only if all bytes matched (result == 0)
    return result == 0


# Example usage and testing
if __name__ == "__main__":
    print("=== Database Utilities Test ===")
    
    # Test connection
    conn = connect_database()
    
    if conn is not None:
        # Test table creation
        create_users_table(conn)
        
        # Test constant-time comparison
        print("\n=== Testing constant_time_compare ===")
        print(f"'hello' == 'hello': {constant_time_compare('hello', 'hello')}")
        print(f"'hello' == 'world': {constant_time_compare('hello', 'world')}")
        print(f"'test' == 'test1': {constant_time_compare('test', 'test1')}")
        
        # Close connection
        conn.close()
        print("\n[INFO] Database connection closed")
