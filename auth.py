"""
Authentication module for CVSS Server
Handles user registration, login, session management, and password hashing
"""

import sqlite3
import bcrypt
import secrets
import hashlib
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
import os

class AuthManager:
    def __init__(self, db_path: str = "cvss_evaluations.db"):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize the database with users table if it doesn't exist."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Create users table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    full_name TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP,
                    is_active BOOLEAN DEFAULT 1
                )
            ''')
            
            # Create sessions table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS user_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    session_token TEXT UNIQUE NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            ''')
            
            # Add user_id column to evaluations table if it doesn't exist
            try:
                cursor.execute('ALTER TABLE evaluations ADD COLUMN user_id INTEGER')
                cursor.execute('ALTER TABLE evaluations ADD COLUMN FOREIGN KEY (user_id) REFERENCES users (id)')
            except sqlite3.OperationalError:
                # Column already exists or table doesn't exist yet
                pass
            
            conn.commit()
    
    def hash_password(self, password: str) -> str:
        """Hash a password using bcrypt."""
        salt = bcrypt.gensalt()
        return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
    
    def verify_password(self, password: str, password_hash: str) -> bool:
        """Verify a password against its hash."""
        return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
    
    def generate_session_token(self) -> str:
        """Generate a secure session token."""
        return secrets.token_urlsafe(32)
    
    def register_user(self, email: str, password: str, full_name: str) -> Dict[str, Any]:
        """Register a new user."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Check if user already exists
                cursor.execute('SELECT id FROM users WHERE email = ?', (email.lower(),))
                if cursor.fetchone():
                    return {"success": False, "error": "User already exists"}
                
                # Hash password and create user
                password_hash = self.hash_password(password)
                cursor.execute('''
                    INSERT INTO users (email, password_hash, full_name)
                    VALUES (?, ?, ?)
                ''', (email.lower(), password_hash, full_name))
                
                user_id = cursor.lastrowid
                conn.commit()
                
                return {
                    "success": True, 
                    "user_id": user_id,
                    "message": "User registered successfully"
                }
                
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def authenticate_user(self, email: str, password: str) -> Dict[str, Any]:
        """Authenticate a user and create a session."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Get user by email
                cursor.execute('''
                    SELECT id, email, password_hash, full_name, is_active
                    FROM users WHERE email = ?
                ''', (email.lower(),))
                
                user = cursor.fetchone()
                if not user:
                    return {"success": False, "error": "Invalid credentials"}
                
                user_id, user_email, password_hash, full_name, is_active = user
                
                if not is_active:
                    return {"success": False, "error": "Account is deactivated"}
                
                # Verify password
                if not self.verify_password(password, password_hash):
                    return {"success": False, "error": "Invalid credentials"}
                
                # Create session
                session_token = self.generate_session_token()
                expires_at = datetime.now() + timedelta(days=7)  # 7 days session
                
                cursor.execute('''
                    INSERT INTO user_sessions (user_id, session_token, expires_at)
                    VALUES (?, ?, ?)
                ''', (user_id, session_token, expires_at))
                
                # Update last login
                cursor.execute('''
                    UPDATE users SET last_login = CURRENT_TIMESTAMP
                    WHERE id = ?
                ''', (user_id,))
                
                conn.commit()
                
                return {
                    "success": True,
                    "user_id": user_id,
                    "email": user_email,
                    "full_name": full_name,
                    "session_token": session_token,
                    "expires_at": expires_at
                }
                
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def validate_session(self, session_token: str) -> Optional[Dict[str, Any]]:
        """Validate a session token and return user info."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Get session and user info
                cursor.execute('''
                    SELECT u.id, u.email, u.full_name, s.expires_at
                    FROM users u
                    JOIN user_sessions s ON u.id = s.user_id
                    WHERE s.session_token = ? AND u.is_active = 1
                ''', (session_token,))
                
                result = cursor.fetchone()
                if not result:
                    return None
                
                user_id, email, full_name, expires_at = result
                
                # Check if session is expired
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
    
    def logout_user(self, session_token: str) -> bool:
        """Logout a user by removing their session."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('DELETE FROM user_sessions WHERE session_token = ?', (session_token,))
                conn.commit()
                return True
        except Exception as e:
            print(f"Logout error: {e}")
            return False
    
    def cleanup_expired_sessions(self):
        """Clean up expired sessions."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('DELETE FROM user_sessions WHERE expires_at < CURRENT_TIMESTAMP')
                conn.commit()
        except Exception as e:
            print(f"Session cleanup error: {e}")
    
    def get_user_evaluations(self, user_id: int) -> list:
        """Get all evaluations for a specific user."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT * FROM evaluations 
                    WHERE user_id = ? 
                    ORDER BY created_at DESC
                ''', (user_id,))
                return cursor.fetchall()
        except Exception as e:
            print(f"Error getting user evaluations: {e}")
            return []
