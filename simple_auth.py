"""
Simplified authentication system for deployment
"""

import sqlite3
import hashlib
import secrets
import os
from datetime import datetime, timedelta
from typing import Optional, Dict, Any

class SimpleAuth:
    def __init__(self, db_path: str = "cvss_evaluations.db"):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize the database with users table."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Create users table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    full_name TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Create sessions table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS user_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    session_token TEXT UNIQUE NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP NOT NULL
                )
            ''')
            
            # Add user_id to evaluations if it doesn't exist
            try:
                cursor.execute('ALTER TABLE evaluations ADD COLUMN user_id INTEGER')
            except sqlite3.OperationalError:
                pass  # Column already exists
            
            conn.commit()
    
    def hash_password(self, password: str) -> str:
        """Simple password hashing using SHA256."""
        salt = secrets.token_hex(16)
        return f"{salt}:{hashlib.sha256((password + salt).encode()).hexdigest()}"
    
    def verify_password(self, password: str, password_hash: str) -> bool:
        """Verify a password against its hash."""
        try:
            salt, hash_part = password_hash.split(':')
            return hashlib.sha256((password + salt).encode()).hexdigest() == hash_part
        except:
            return False
    
    def register_user(self, email: str, password: str, full_name: str) -> Dict[str, Any]:
        """Register a new user."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Check if user exists
                cursor.execute('SELECT id FROM users WHERE email = ?', (email.lower(),))
                if cursor.fetchone():
                    return {"success": False, "error": "User already exists"}
                
                # Create user
                password_hash = self.hash_password(password)
                cursor.execute('''
                    INSERT INTO users (email, password_hash, full_name)
                    VALUES (?, ?, ?)
                ''', (email.lower(), password_hash, full_name))
                
                user_id = cursor.lastrowid
                conn.commit()
                
                return {"success": True, "user_id": user_id}
                
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def authenticate_user(self, email: str, password: str) -> Dict[str, Any]:
        """Authenticate a user and create a session."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Get user
                cursor.execute('''
                    SELECT id, email, password_hash, full_name
                    FROM users WHERE email = ?
                ''', (email.lower(),))
                
                user = cursor.fetchone()
                if not user:
                    return {"success": False, "error": "Invalid credentials"}
                
                user_id, user_email, password_hash, full_name = user
                
                # Verify password
                if not self.verify_password(password, password_hash):
                    return {"success": False, "error": "Invalid credentials"}
                
                # Create session
                session_token = secrets.token_urlsafe(32)
                expires_at = datetime.now() + timedelta(days=7)
                
                cursor.execute('''
                    INSERT INTO user_sessions (user_id, session_token, expires_at)
                    VALUES (?, ?, ?)
                ''', (user_id, session_token, expires_at.isoformat()))
                
                conn.commit()
                
                return {
                    "success": True,
                    "user_id": user_id,
                    "email": user_email,
                    "full_name": full_name,
                    "session_token": session_token
                }
                
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def validate_session(self, session_token: str) -> Optional[Dict[str, Any]]:
        """Validate a session token."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT u.id, u.email, u.full_name, s.expires_at
                    FROM users u
                    JOIN user_sessions s ON u.id = s.user_id
                    WHERE s.session_token = ?
                ''', (session_token,))
                
                result = cursor.fetchone()
                if not result:
                    return None
                
                user_id, email, full_name, expires_at = result
                
                # Check expiration
                if datetime.now() > datetime.fromisoformat(expires_at):
                    # Clean up expired session
                    cursor.execute('DELETE FROM user_sessions WHERE session_token = ?', (session_token,))
                    conn.commit()
                    return None
                
                return {
                    "user_id": user_id,
                    "email": email,
                    "full_name": full_name
                }
                
        except Exception as e:
            print(f"Session validation error: {e}")
            return None
