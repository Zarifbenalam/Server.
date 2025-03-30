import asyncio
import websockets
from websockets.server import WebSocketServerProtocol
import json
import logging
import uuid
import time
from datetime import datetime, timedelta
import os
from logging.handlers import RotatingFileHandler
import ssl
import signal
import sys
import sqlite3
from contextlib import contextmanager
import hashlib
import ipaddress
from collections import defaultdict
import secrets
import socket
import traceback
import base64
import zlib
from typing import Dict, Any, Optional, Set, List, Tuple
from dataclasses import dataclass, field
import threading
import hmac
import re
import random
from pathlib import Path

# Load environment variables from .env file if present
def load_dotenv():
    env_path = Path('.env')
    if env_path.exists():
        with open(env_path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#') or '=' not in line:
                    continue
                key, value = line.split('=', 1)
                os.environ[key] = value

load_dotenv()

# Enhanced Server Configuration
@dataclass
class ServerConfig:
    PORT: int = int(os.getenv('PORT', 8765))
    HOST: str = os.getenv('HOST', '0.0.0.0')
    LOG_LEVEL: str = os.getenv('LOG_LEVEL', 'INFO')
    LOG_FILE: str = os.getenv('LOG_FILE', 'relay_server.log')
    LOG_MAX_SIZE: int = int(os.getenv('LOG_MAX_SIZE_MB', 20)) * 1024 * 1024
    LOG_BACKUP_COUNT: int = int(os.getenv('LOG_BACKUP_COUNT', 7))
    RATE_LIMIT_MESSAGES: int = int(os.getenv('RATE_LIMIT_MESSAGES_PER_SECOND', 150))
    MAX_CONNECTIONS: int = int(os.getenv('MAX_CONNECTIONS', 1500))
    IDLE_TIMEOUT: int = int(os.getenv('IDLE_CONNECTION_TIMEOUT_SECONDS', 600))
    PING_INTERVAL: int = int(os.getenv('PING_INTERVAL_SECONDS', 30))
    PING_TIMEOUT: int = int(os.getenv('PING_TIMEOUT_SECONDS', 15))
    ENABLE_WSS: bool = os.getenv('ENABLE_WSS', 'False').lower() == 'true'
    SSL_CERT_PATH: str = os.getenv('SSL_CERT_PATH', '')
    SSL_KEY_PATH: str = os.getenv('SSL_KEY_PATH', '')
    JWT_SECRET: str = os.getenv('JWT_SECRET', '')
    DB_PATH: str = os.getenv('DB_PATH', 'relay_server.db')
    MAX_REQUEST_SIZE: int = int(os.getenv('MAX_REQUEST_SIZE_MB', 10)) * 1024 * 1024
    BLACKLIST_THRESHOLD: int = int(os.getenv('BLACKLIST_THRESHOLD', 100))
    BLACKLIST_DURATION: int = int(os.getenv('BLACKLIST_DURATION_HOURS', 24))
    ENCRYPTION_KEY: str = os.getenv('ENCRYPTION_KEY', '')
    CONNECTION_POOL_SIZE: int = int(os.getenv('CONNECTION_POOL_SIZE', 100))
    MESSAGE_BATCH_SIZE: int = int(os.getenv('MESSAGE_BATCH_SIZE', 100))
    CACHE_TTL: int = int(os.getenv('CACHE_TTL_SECONDS', 300))
    MAX_RECONNECT_ATTEMPTS: int = int(os.getenv('MAX_RECONNECT_ATTEMPTS', 10))
    COMPRESSION_THRESHOLD: int = int(os.getenv('COMPRESSION_THRESHOLD_BYTES', 1024))
    TOKEN_EXPIRY_SECONDS: int = int(os.getenv('TOKEN_EXPIRY_SECONDS', 3600))
    ALLOWED_ORIGINS: List[str] = field(default_factory=lambda: os.getenv('ALLOWED_ORIGINS', '*').split(','))
    HEALTH_CHECK_INTERVAL: int = int(os.getenv('HEALTH_CHECK_INTERVAL_SECONDS', 60))
    BACKUP_INTERVAL: int = int(os.getenv('BACKUP_INTERVAL_HOURS', 24))
    BACKUP_PATH: str = os.getenv('BACKUP_PATH', 'backups/')
    REQUIRE_USER_CONSENT: bool = os.getenv('REQUIRE_USER_CONSENT', 'True').lower() == 'true'
    AUDIT_LOGGING: bool = os.getenv('AUDIT_LOGGING', 'True').lower() == 'true'
    ADAPTIVE_QUALITY: bool = os.getenv('ADAPTIVE_QUALITY', 'True').lower() == 'true'
    MIN_QUALITY: int = int(os.getenv('MIN_QUALITY', 20))
    MAX_QUALITY: int = int(os.getenv('MAX_QUALITY', 90))
    DEFAULT_QUALITY: int = int(os.getenv('DEFAULT_QUALITY', 80))
    DEFAULT_FPS: int = int(os.getenv('DEFAULT_FPS', 15))

    def validate(self):
        """Validate configuration and set defaults for missing values"""
        if not self.JWT_SECRET:
            self.JWT_SECRET = secrets.token_hex(32)
            print(f"WARNING: JWT_SECRET not set. Generated a random secret: {self.JWT_SECRET}")
            print("This will invalidate existing tokens on restart.")
        
        if not self.ENCRYPTION_KEY:
            self.ENCRYPTION_KEY = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()
            print(f"WARNING: ENCRYPTION_KEY not set. Generated a random key: {self.ENCRYPTION_KEY}")
            print("This will invalidate existing encrypted data.")
        
        if self.ENABLE_WSS and (not self.SSL_CERT_PATH or not self.SSL_KEY_PATH):
            raise ValueError("SSL certificate and key paths must be set when WSS is enabled")
        
        # Create backup directory if it doesn't exist
        if not os.path.exists(self.BACKUP_PATH):
            os.makedirs(self.BACKUP_PATH)
        
        return self

# Setup logging with correlation ID
class ContextFilter(logging.Filter):
    """Add correlation ID to log records"""
    def filter(self, record):
        if not hasattr(record, 'correlation_id'):
            record.correlation_id = 'SYSTEM'
        return True

# Initialize configuration
config = ServerConfig().validate()

# Setup logging manually for better control
log_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - [%(correlation_id)s] %(message)s')
context_filter = ContextFilter()

# Create handlers
file_handler = RotatingFileHandler(
    config.LOG_FILE,
    maxBytes=config.LOG_MAX_SIZE,
    backupCount=config.LOG_BACKUP_COUNT
)
console_handler = logging.StreamHandler()

# Set formatter and filter on handlers
file_handler.setFormatter(log_formatter)
file_handler.addFilter(context_filter)
console_handler.setFormatter(log_formatter)
console_handler.addFilter(context_filter)

# Configure root logger
root_logger = logging.getLogger()
root_logger.setLevel(getattr(logging, config.LOG_LEVEL))
root_logger.addHandler(file_handler)
root_logger.addHandler(console_handler)

# Get specific logger for the application
logger = logging.getLogger('relay_server')

# Audit logger for security events
audit_logger = logging.getLogger('relay_audit')
audit_logger.setLevel(logging.INFO)
audit_handler = RotatingFileHandler(
    'relay_audit.log',
    maxBytes=config.LOG_MAX_SIZE,
    backupCount=config.LOG_BACKUP_COUNT
)
audit_handler.setFormatter(logging.Formatter('%(asctime)s - [%(correlation_id)s] %(message)s'))
audit_handler.addFilter(context_filter) # Add the same filter instance
audit_logger.addHandler(audit_handler)

def log_audit(message, correlation_id='SYSTEM', **kwargs):
    """Log an audit event"""
    if not config.AUDIT_LOGGING:
        return
    
    extra = {'correlation_id': correlation_id}
    details = ' '.join(f"{k}={v}" for k, v in kwargs.items())
    audit_logger.info(f"{message} {details}", extra=extra)

# Simple JWT implementation
class JWT:
    @staticmethod
    def encode(payload, secret, algorithm='HS256'):
        """Encode a payload into a JWT token"""
        header = {'alg': algorithm, 'typ': 'JWT'}
        
        # Base64 encode header and payload
        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
        
        # Create signature
        message = f"{header_b64}.{payload_b64}"
        signature = hmac.new(
            secret.encode(),
            message.encode(),
            hashlib.sha256
        ).digest()
        signature_b64 = base64.urlsafe_b64encode(signature).decode().rstrip('=')
        
        # Return complete token
        return f"{header_b64}.{payload_b64}.{signature_b64}"
    
    @staticmethod
    def decode(token, secret, algorithms=None):
        """Decode a JWT token and verify signature"""
        if algorithms is None:
            algorithms = ['HS256']
        
        try:
            # Split token into parts
            header_b64, payload_b64, signature_b64 = token.split('.')
            
            # Add padding if needed
            def add_padding(s):
                padding = 4 - (len(s) % 4)
                if padding < 4:
                    return s + ('=' * padding)
                return s
            
            # Decode header and payload
            header = json.loads(base64.urlsafe_b64decode(add_padding(header_b64)).decode())
            payload = json.loads(base64.urlsafe_b64decode(add_padding(payload_b64)).decode())
            
            # Verify algorithm
            if header['alg'] not in algorithms:
                raise ValueError(f"Algorithm {header['alg']} not allowed")
            
            # Verify signature
            message = f"{header_b64}.{payload_b64}"
            expected_signature = hmac.new(
                secret.encode(),
                message.encode(),
                hashlib.sha256
            ).digest()
            actual_signature = base64.urlsafe_b64decode(add_padding(signature_b64))
            
            if not hmac.compare_digest(expected_signature, actual_signature):
                raise ValueError("Invalid signature")
            
            # Check expiration
            if 'exp' in payload and payload['exp'] < time.time():
                raise ValueError("Token expired")
            
            return payload
        except Exception as e:
            raise ValueError(f"Invalid token: {str(e)}")

# Enhanced encryption implementation
class Encryption:
    def __init__(self, key):
        """Initialize with base64 encoded key"""
        if isinstance(key, str):
            key = base64.urlsafe_b64decode(key.encode())
        self.key = key
    
    def encrypt(self, data):
        """Encrypt data"""
        if isinstance(data, str):
            data = data.encode()
        
        try:
            # Generate random IV
            iv = os.urandom(16)
            
            # Create cipher using AES-GCM
            cipher = self._create_cipher(iv)
            
            # Encrypt data
            ciphertext = cipher.encrypt(data)
            
            # Combine IV and ciphertext
            result = iv + ciphertext
            
            # Return base64 encoded result
            return base64.urlsafe_b64encode(result).decode()
        except Exception as e:
            logger.error(f"Encryption error: {e}")
            # Return original data if encryption fails
            return base64.urlsafe_b64encode(data).decode()
    
    def decrypt(self, encrypted_data):
        """Decrypt data"""
        try:
            # Decode base64
            data = base64.urlsafe_b64decode(encrypted_data.encode())
            
            # Extract IV and ciphertext
            iv = data[:16]
            ciphertext = data[16:]
            
            # Create cipher
            cipher = self._create_cipher(iv, decrypt=True)
            
            # Decrypt data
            plaintext = cipher.decrypt(ciphertext)
            
            return plaintext.decode()
        except Exception as e:
            logger.error(f"Decryption error: {e}")
            return None
    
    def _create_cipher(self, iv, decrypt=False):
        """Create a cipher object"""
        # This is a simplified implementation
        # In a real implementation, you would use a library like cryptography
        # For now, we'll use a simple XOR cipher for demonstration
        class SimpleCipher:
            def __init__(self, key, iv):
                self.key = key
                self.iv = iv
                self.key_stream = self._generate_key_stream(len(key) * 1000)  # Generate a long key stream
            
            def _generate_key_stream(self, length):
                """Generate a key stream using key and IV"""
                result = bytearray()
                seed = hashlib.sha256(self.key + self.iv).digest()
                
                while len(result) < length:
                    seed = hashlib.sha256(seed).digest()
                    result.extend(seed)
                
                return bytes(result[:length])
            
            def encrypt(self, data):
                """Encrypt data using XOR with key stream"""
                return bytes(a ^ b for a, b in zip(data, self.key_stream[:len(data)]))
            
            def decrypt(self, data):
                """Decrypt data (same as encrypt for XOR)"""
                return self.encrypt(data)
        
        return SimpleCipher(self.key, iv)

# Database Manager
class DatabaseManager:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._init_db()
        # self._setup_backup_schedule() # Moved to setup_periodic_tasks
    
    @contextmanager
    def get_connection(self):
        """Context manager for database connections"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()
    
    def _init_db(self):
        """Initialize database schema"""
        with self.get_connection() as conn:
            # Clients table
            conn.execute('''
            CREATE TABLE IF NOT EXISTS clients (
                client_id TEXT PRIMARY KEY,
                client_type TEXT NOT NULL,
                last_seen TIMESTAMP NOT NULL,
                metadata TEXT,
                created_at TIMESTAMP NOT NULL,
                consent_given BOOLEAN DEFAULT FALSE,
                consent_timestamp TIMESTAMP
            )
            ''')
            
            # Messages table
            conn.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_id TEXT NOT NULL,
                recipient_id TEXT NOT NULL,
                message_type TEXT NOT NULL,
                content TEXT NOT NULL,
                timestamp TIMESTAMP NOT NULL,
                delivered BOOLEAN DEFAULT FALSE,
                delivery_timestamp TIMESTAMP
            )
            ''')
            
            # Authentication logs
            conn.execute('''
            CREATE TABLE IF NOT EXISTS auth_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                client_id TEXT,
                ip_address TEXT NOT NULL,
                success BOOLEAN NOT NULL,
                timestamp TIMESTAMP NOT NULL,
                user_agent TEXT,
                details TEXT
            )
            ''')
            
            # IP blacklist
            conn.execute('''
            CREATE TABLE IF NOT EXISTS ip_blacklist (
                ip_address TEXT PRIMARY KEY,
                reason TEXT NOT NULL,
                added_at TIMESTAMP NOT NULL,
                expires_at TIMESTAMP
            )
            ''')
            
            # Permissions table
            conn.execute('''
            CREATE TABLE IF NOT EXISTS permissions (
                client_id TEXT NOT NULL,
                permission TEXT NOT NULL,
                granted BOOLEAN NOT NULL,
                timestamp TIMESTAMP NOT NULL,
                PRIMARY KEY (client_id, permission)
            )
            ''')
            
            # Sessions table
            conn.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                client_id TEXT NOT NULL,
                controller_id TEXT NOT NULL,
                session_type TEXT NOT NULL,
                start_time TIMESTAMP NOT NULL,
                end_time TIMESTAMP,
                options TEXT,
                active BOOLEAN DEFAULT TRUE
            )
            ''')
            
            # Create indexes
            conn.execute('CREATE INDEX IF NOT EXISTS idx_messages_recipient ON messages(recipient_id, delivered)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_auth_logs_ip ON auth_logs(ip_address)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_clients_last_seen ON clients(last_seen)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_permissions_client ON permissions(client_id)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_sessions_client ON sessions(client_id)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_sessions_controller ON sessions(controller_id)')
            
            conn.commit()
    
    def _setup_backup_schedule(self):
        """Setup periodic database backups"""
        async def backup_task():
            while True:
                try:
                    await asyncio.sleep(config.BACKUP_INTERVAL * 3600)
                    await self.backup_database()
                except Exception as e:
                    logger.error(f"Database backup error: {e}", exc_info=True)
        
        asyncio.create_task(backup_task())
    
    async def backup_database(self):
        """Create a backup of the database"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = f"{config.BACKUP_PATH}/relay_db_backup_{timestamp}.db"
        
        try:
            # Create a new connection for backup
            source = sqlite3.connect(self.db_path)
            dest = sqlite3.connect(backup_file)
            
            source.backup(dest)
            
            source.close()
            dest.close()
            
            logger.info(f"Database backup created: {backup_file}")
            
            # Clean up old backups (keep last 7)
            self._cleanup_old_backups()
            
            return True
        except Exception as e:
            logger.error(f"Database backup failed: {e}", exc_info=True)
            return False
    
    def _cleanup_old_backups(self):
        """Remove old database backups, keeping only the most recent ones"""
        try:
            backups = [f for f in os.listdir(config.BACKUP_PATH) if f.startswith("relay_db_backup_") and f.endswith(".db")]
            backups.sort(reverse=True)  # Sort by name (which includes timestamp)
            
            # Keep only the 7 most recent backups
            for old_backup in backups[7:]:
                os.remove(os.path.join(config.BACKUP_PATH, old_backup))
                logger.info(f"Removed old backup: {old_backup}")
        except Exception as e:
            logger.error(f"Error cleaning up old backups: {e}")
    
    async def register_client(self, client_id: str, client_type: str, metadata: Dict[str, Any] = None):
        """Register a new client or update existing client"""
        with self.get_connection() as conn:
            now = datetime.now().isoformat()
            
            # Check if client exists
            cursor = conn.execute("SELECT * FROM clients WHERE client_id = ?", (client_id,))
            existing_client = cursor.fetchone()
            
            if existing_client:
                # Update existing client
                conn.execute(
                    """
                    UPDATE clients SET
                        client_type = ?,
                        last_seen = ?,
                        metadata = ?
                    WHERE client_id = ?
                    """,
                    (client_type, now, json.dumps(metadata or {}), client_id)
                )
            else:
                # Insert new client
                conn.execute(
                    """
                    INSERT INTO clients (client_id, client_type, last_seen, metadata, created_at, consent_given) 
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (client_id, client_type, now, json.dumps(metadata or {}), now, False)
                )
            
            conn.commit()
    
    async def update_client_last_seen(self, client_id: str):
        """Update client's last seen timestamp"""
        with self.get_connection() as conn:
            conn.execute(
                "UPDATE clients SET last_seen = ? WHERE client_id = ?",
                (datetime.now().isoformat(), client_id)
            )
            conn.commit()
    
    async def set_client_consent(self, client_id: str, consent_given: bool):
        """Set client's consent status"""
        with self.get_connection() as conn:
            now = datetime.now().isoformat()
            conn.execute(
                """
                UPDATE clients SET 
                    consent_given = ?,
                    consent_timestamp = ?
                WHERE client_id = ?
                """,
                (consent_given, now, client_id)
            )
            conn.commit()
            
            log_audit("Client consent updated", client_id=client_id, consent=consent_given)
    
    async def get_client_consent(self, client_id: str) -> bool:
        """Get client's consent status"""
        with self.get_connection() as conn:
            cursor = conn.execute(
                "SELECT consent_given FROM clients WHERE client_id = ?",
                (client_id,)
            )
            result = cursor.fetchone()
            return bool(result and result['consent_given'])
    
    async def set_client_permission(self, client_id: str, permission: str, granted: bool):
        """Set a permission for a client"""
        with self.get_connection() as conn:
            now = datetime.now().isoformat()
            conn.execute(
                """
                INSERT OR REPLACE INTO permissions (client_id, permission, granted, timestamp)
                VALUES (?, ?, ?, ?)
                """,
                (client_id, permission, granted, now)
            )
            conn.commit()
            
            log_audit("Client permission updated", client_id=client_id, permission=permission, granted=granted)
    
    async def get_client_permission(self, client_id: str, permission: str) -> bool:
        """Check if a client has a specific permission"""
        with self.get_connection() as conn:
            cursor = conn.execute(
                """
                SELECT granted FROM permissions 
                WHERE client_id = ? AND permission = ?
                """,
                (client_id, permission)
            )
            result = cursor.fetchone()
            return bool(result and result['granted'])
    
    async def get_client_permissions(self, client_id: str) -> Dict[str, bool]:
        """Get all permissions for a client"""
        with self.get_connection() as conn:
            cursor = conn.execute(
                "SELECT permission, granted FROM permissions WHERE client_id = ?",
                (client_id,)
            )
            return {row['permission']: bool(row['granted']) for row in cursor.fetchall()}
    
    async def log_auth_attempt(self, client_id: str, ip_address: str, success: bool, user_agent: str = None, details: str = None):
        """Log authentication attempt"""
        with self.get_connection() as conn:
            conn.execute(
                """
                INSERT INTO auth_logs (client_id, ip_address, success, timestamp, user_agent, details) 
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (client_id, ip_address, success, datetime.now().isoformat(), user_agent, details)
            )
            conn.commit()
            
            log_audit("Authentication attempt", 
                     client_id=client_id, 
                     ip_address=ip_address, 
                     success=success, 
                     details=details)
    
    async def store_message(self, sender_id: str, recipient_id: str, message_type: str, content: str):
        """Store a message in the database"""
        with self.get_connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO messages (sender_id, recipient_id, message_type, content, timestamp) 
                VALUES (?, ?, ?, ?, ?)
                """,
                (sender_id, recipient_id, message_type, content, datetime.now().isoformat())
            )
            message_id = cursor.lastrowid
            conn.commit()
            return message_id
    
    async def mark_message_delivered(self, message_id: int):
        """Mark a message as delivered"""
        with self.get_connection() as conn:
            conn.execute(
                """
                UPDATE messages SET 
                    delivered = TRUE, 
                    delivery_timestamp = ? 
                WHERE id = ?
                """,
                (datetime.now().isoformat(), message_id)
            )
            conn.commit()
    
    async def get_undelivered_messages(self, recipient_id: str) -> List[Dict[str, Any]]:
        """Get all undelivered messages for a recipient"""
        with self.get_connection() as conn:
            cursor = conn.execute(
                """
                SELECT * FROM messages 
                WHERE recipient_id = ? AND delivered = FALSE 
                ORDER BY timestamp
                LIMIT ?
                """,
                (recipient_id, config.MESSAGE_BATCH_SIZE)
            )
            return [dict(row) for row in cursor.fetchall()]
    
    async def add_to_blacklist(self, ip_address: str, reason: str, duration_hours: int = None):
        """Add an IP address to the blacklist"""
        with self.get_connection() as conn:
            now = datetime.now()
            expires_at = None
            if duration_hours:
                expires_at = (now + timedelta(hours=duration_hours)).isoformat()
            
            conn.execute(
                """
                INSERT OR REPLACE INTO ip_blacklist (ip_address, reason, added_at, expires_at) 
                VALUES (?, ?, ?, ?)
                """,
                (ip_address, reason, now.isoformat(), expires_at)
            )
            conn.commit()
            
            log_audit("IP blacklisted", ip_address=ip_address, reason=reason, duration_hours=duration_hours)
    
    async def is_ip_blacklisted(self, ip_address: str) -> bool:
        """Check if an IP address is blacklisted"""
        with self.get_connection() as conn:
            now = datetime.now().isoformat()
            cursor = conn.execute(
                """
                SELECT * FROM ip_blacklist 
                WHERE ip_address = ? AND (expires_at IS NULL OR expires_at > ?)
                """,
                (ip_address, now)
            )
            return cursor.fetchone() is not None
    
    async def get_failed_auth_attempts(self, ip_address: str, time_window_minutes: int = 30) -> int:
        """Get number of failed authentication attempts from an IP address"""
        with self.get_connection() as conn:
            time_window = (datetime.now() - timedelta(minutes=time_window_minutes)).isoformat()
            cursor = conn.execute(
                """
                SELECT COUNT(*) as count FROM auth_logs 
                WHERE ip_address = ? AND success = FALSE AND timestamp > ?
                """,
                (ip_address, time_window)
            )
            result = cursor.fetchone()
            return result['count'] if result else 0
    
    async def create_session(self, session_id: str, client_id: str, controller_id: str, session_type: str, options: Dict[str, Any] = None) -> bool:
        """Create a new session"""
        with self.get_connection() as conn:
            now = datetime.now().isoformat()
            
            try:
                conn.execute(
                    """
                    INSERT INTO sessions (session_id, client_id, controller_id, session_type, start_time, options, active)
                    VALUES (?, ?, ?, ?, ?, ?, TRUE)
                    """,
                    (session_id, client_id, controller_id, session_type, now, json.dumps(options or {}))
                )
                conn.commit()
                
                log_audit("Session created", 
                         session_id=session_id, 
                         client_id=client_id, 
                         controller_id=controller_id, 
                         session_type=session_type)
                return True
            except Exception as e:
                logger.error(f"Error creating session: {e}")
                return False
    
    async def end_session(self, session_id: str) -> bool:
        """End a session"""
        with self.get_connection() as conn:
            now = datetime.now().isoformat()
            
            try:
                conn.execute(
                    """
                    UPDATE sessions SET
                        active = FALSE,
                        end_time = ?
                    WHERE session_id = ?
                    """,
                    (now, session_id)
                )
                conn.commit()
                
                log_audit("Session ended", session_id=session_id)
                return True
            except Exception as e:
                logger.error(f"Error ending session: {e}")
                return False
    
    async def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get session information"""
        with self.get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM sessions WHERE session_id = ?",
                (session_id,)
            )
            row = cursor.fetchone()
            if row:
                session = dict(row)
                if 'options' in session and session['options']:
                    session['options'] = json.loads(session['options'])
                return session
            return None
    
    async def get_active_sessions(self, client_id: str = None, controller_id: str = None) -> List[Dict[str, Any]]:
        """Get active sessions for a client or controller"""
        with self.get_connection() as conn:
            query = "SELECT * FROM sessions WHERE active = TRUE"
            params = []
            
            if client_id:
                query += " AND client_id = ?"
                params.append(client_id)
            
            if controller_id:
                query += " AND controller_id = ?"
                params.append(controller_id)
            
            cursor = conn.execute(query, params)
            sessions = [dict(row) for row in cursor.fetchall()]
            
            for session in sessions:
                if 'options' in session and session['options']:
                    session['options'] = json.loads(session['options'])
            
            return sessions
    
    async def cleanup_old_data(self):
        """Clean up old data from the database"""
        with self.get_connection() as conn:
            # Remove expired blacklist entries
            now = datetime.now().isoformat()
            conn.execute(
                "DELETE FROM ip_blacklist WHERE expires_at IS NOT NULL AND expires_at < ?",
                (now,)
            )
            
            # Archive old messages (in a real system, you might move these to an archive table)
            thirty_days_ago = (datetime.now() - timedelta(days=30)).isoformat()
            conn.execute(
                "DELETE FROM messages WHERE timestamp < ? AND delivered = TRUE",
                (thirty_days_ago,)
            )
            
            # Clean up old auth logs
            ninety_days_ago = (datetime.now() - timedelta(days=90)).isoformat()
            conn.execute(
                "DELETE FROM auth_logs WHERE timestamp < ?",
                (ninety_days_ago,)
            )
            
            # Clean up inactive sessions
            seven_days_ago = (datetime.now() - timedelta(days=7)).isoformat()
            conn.execute(
                "DELETE FROM sessions WHERE active = FALSE AND end_time < ?",
                (seven_days_ago,)
            )
            
            conn.commit()
    
    async def get_client_info(self, client_id: str) -> Optional[Dict[str, Any]]:
        """Get client information"""
        with self.get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM clients WHERE client_id = ?",
                (client_id,)
            )
            row = cursor.fetchone()
            if row:
                client = dict(row)
                if 'metadata' in client and client['metadata']:
                    client['metadata'] = json.loads(client['metadata'])
                return client
            return None
    
    async def get_active_clients(self, minutes: int = 60) -> List[Dict[str, Any]]:
        """Get all clients active within the specified time window"""
        with self.get_connection() as conn:
            time_window = (datetime.now() - timedelta(minutes=minutes)).isoformat()
            cursor = conn.execute(
                "SELECT * FROM clients WHERE last_seen > ? ORDER BY last_seen DESC",
                (time_window,)
            )
            clients = [dict(row) for row in cursor.fetchall()]
            for client in clients:
                if 'metadata' in client and client['metadata']:
                    client['metadata'] = json.loads(client['metadata'])
            return clients

# Security Manager
class SecurityManager:
    def __init__(self):
        self.db_manager = None  # Will be set after initialization
        self.rate_limiters = defaultdict(lambda: RateLimiter(config.RATE_LIMIT_MESSAGES))
        self.encryption = Encryption(config.ENCRYPTION_KEY)
        # self._setup_cleanup_task() # Moved to setup_periodic_tasks
    
    def set_db_manager(self, db_manager: DatabaseManager):
        """Set the database manager reference"""
        self.db_manager = db_manager
    
    def _setup_cleanup_task(self):
        """Setup periodic cleanup task"""
        async def cleanup_task():
            while True:
                try:
                    await asyncio.sleep(3600)  # Run every hour
                    if self.db_manager:
                        await self.db_manager.cleanup_old_data()
                except Exception as e:
                    logger.error(f"Cleanup task error: {e}", exc_info=True)
        
        asyncio.create_task(cleanup_task())
    
    async def check_ip(self, ip_address: str) -> bool:
        """Check if an IP address is allowed"""
        if not self.db_manager:
            return True
        
        # Check if IP is blacklisted
        if await self.db_manager.is_ip_blacklisted(ip_address):
            logger.warning(f"Blocked connection from blacklisted IP: {ip_address}")
            return False
        
        return True
    
    async def check_rate_limit(self, client_id: str) -> bool:
        """Check if a client has exceeded rate limits"""
        return await self.rate_limiters[client_id].check()
    
    async def record_failed_attempt(self, ip_address: str, client_id: str = None, details: str = None):
        """Record a failed authentication attempt"""
        if not self.db_manager:
            return
        
        await self.db_manager.log_auth_attempt(
            client_id=client_id or 'unknown',
            ip_address=ip_address,
            success=False,
            details=details
        )
        
        # Check if IP should be blacklisted
        failed_attempts = await self.db_manager.get_failed_auth_attempts(ip_address)
        if failed_attempts >= config.BLACKLIST_THRESHOLD:
            await self.db_manager.add_to_blacklist(
                ip_address=ip_address,
                reason=f"Exceeded failed authentication attempts ({failed_attempts})",
                duration_hours=config.BLACKLIST_DURATION
            )
            logger.warning(f"IP {ip_address} blacklisted for {config.BLACKLIST_DURATION} hours due to {failed_attempts} failed auth attempts")
    
    async def record_successful_attempt(self, ip_address: str, client_id: str, user_agent: str = None):
        """Record a successful authentication attempt"""
        if not self.db_manager:
            return
        
        await self.db_manager.log_auth_attempt(
            client_id=client_id,
            ip_address=ip_address,
            success=True,
            user_agent=user_agent
        )
    
    async def check_permission(self, client_id: str, permission: str) -> bool:
        """Check if a client has a specific permission"""
        if not self.db_manager:
            return False
        
        # Check if client has given consent (if required)
        if config.REQUIRE_USER_CONSENT:
            consent_given = await self.db_manager.get_client_consent(client_id)
            if not consent_given:
                logger.warning(f"Client {client_id} has not given consent")
                return False
        
        # Check specific permission
        return await self.db_manager.get_client_permission(client_id, permission)
    
    def generate_token(self, client_id: str, client_type: str, additional_data: Dict[str, Any] = None) -> str:
        """Generate a JWT token for a client"""
        now = int(time.time())
        payload = {
            'sub': client_id,
            'type': client_type,
            'iat': now,
            'exp': now + config.TOKEN_EXPIRY_SECONDS
        }
        
        if additional_data:
            payload.update(additional_data)
        
        return JWT.encode(payload, config.JWT_SECRET)
    
    def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Verify a JWT token"""
        try:
            payload = JWT.decode(token, config.JWT_SECRET)
            return payload
        except Exception as e:
            logger.warning(f"Invalid token: {e}")
            return None
    
    def encrypt_data(self, data: str) -> str:
        """Encrypt sensitive data"""
        return self.encryption.encrypt(data)
    
    def decrypt_data(self, encrypted_data: str) -> str:
        """Decrypt sensitive data"""
        return self.encryption.decrypt(encrypted_data)
    
    def validate_message(self, message: Dict[str, Any]) -> Tuple[bool, str]:
        """Validate a message format and content"""
        required_fields = ['type']
        
        # Check required fields
        for field in required_fields:
            if field not in message:
                return False, f"Missing required field: {field}"
        
        # Validate message type
        valid_types = [
            'auth', 'message', 'command', 'response', 'error', 
            'ping', 'pong', 'status', 'file', 'stream',
            'screen', 'touch', 'key', 'clipboard', 'app',
            'location', 'camera', 'audio', 'shell', 'file_operation',
            'permission', 'consent'
        ]
        if message['type'] not in valid_types:
            return False, f"Invalid message type: {message['type']}"
        
        # Type-specific validation
        if message['type'] == 'message':
            if 'content' not in message:
                return False, "Message missing content field"
            if 'recipient_id' not in message:
                return False, "Message missing recipient_id field"
        
        return True, ""

# Rate Limiter
class RateLimiter:
    def __init__(self, rate_limit: int, window_size: int = 1):
        self.rate_limit = rate_limit
        self.window_size = window_size
        self.window = []
        self.lock = asyncio.Lock()
    
    async def check(self) -> bool:
        """Check if rate limit is exceeded"""
        async with self.lock:
            now = time.time()
            
            # Remove old timestamps
            self.window = [ts for ts in self.window if now - ts < self.window_size]
            
            # Check if rate limit is exceeded
            if len(self.window) >= self.rate_limit:
                return False
            
            # Add current timestamp
            self.window.append(now)
            return True

# In-memory Message Queue Manager
class MessageQueueManager:
    def __init__(self):
        self.message_queues = defaultdict(list)
        self.queue_locks = defaultdict(asyncio.Lock)
        self.cache = {}
        self.cache_expiry = {}
    
    async def enqueue_message(self, recipient_id: str, message: Dict[str, Any]) -> bool:
        """Enqueue a message for delivery"""
        try:
            async with self.queue_locks[recipient_id]:
                self.message_queues[recipient_id].append(message)
            return True
        except Exception as e:
            logger.error(f"Error enqueueing message: {e}", exc_info=True)
            return False
    
    async def dequeue_messages(self, recipient_id: str, count: int = 10) -> List[Dict[str, Any]]:
        """Dequeue messages for a recipient"""
        try:
            async with self.queue_locks[recipient_id]:
                messages = self.message_queues[recipient_id][:count]
                self.message_queues[recipient_id] = self.message_queues[recipient_id][count:]
                return messages
        except Exception as e:
            logger.error(f"Error dequeueing messages: {e}", exc_info=True)
            return []
    
    async def get_queue_length(self, recipient_id: str) -> int:
        """Get the number of messages in a recipient's queue"""
        try:
            async with self.queue_locks[recipient_id]:
                return len(self.message_queues[recipient_id])
        except Exception as e:
            logger.error(f"Error getting queue length: {e}", exc_info=True)
            return 0
    
    async def set_cache(self, key: str, value: Any, ttl: int = None) -> bool:
        """Set a value in the cache"""
        try:
            ttl = ttl or config.CACHE_TTL
            self.cache[key] = value
            self.cache_expiry[key] = time.time() + ttl
            return True
        except Exception as e:
            logger.error(f"Error setting cache: {e}", exc_info=True)
            return False
    
    async def get_cache(self, key: str) -> Any:
        """Get a value from the cache"""
        try:
            if key in self.cache:
                # Check if expired
                if time.time() > self.cache_expiry[key]:
                    del self.cache[key]
                    del self.cache_expiry[key]
                    return None
                return self.cache[key]
            return None
        except Exception as e:
            logger.error(f"Error getting cache: {e}", exc_info=True)
            return None
    
    async def cleanup_expired_cache(self):
        """Clean up expired cache entries"""
        try:
            now = time.time()
            expired_keys = [k for k, exp in self.cache_expiry.items() if now > exp]
            for key in expired_keys:
                del self.cache[key]
                del self.cache_expiry[key]
        except Exception as e:
            logger.error(f"Error cleaning up cache: {e}", exc_info=True)

# Simple Metrics Collector
class MetricsCollector:
    def __init__(self):
        self.metrics = {
            'connected_clients': 0,
            'connection_total': 0,
            'connection_errors': 0,
            'messages_received': defaultdict(int),
            'messages_sent': defaultdict(int),
            'message_errors': 0,
            'auth_success': 0,
            'auth_failure': 0,
            'screen_sessions': 0,
            'audio_sessions': 0,
            'file_transfers': 0,
            'shell_commands': 0,
            'permission_requests': 0,
            'permission_grants': 0,
            'permission_denials': 0,
        }
        self.message_latencies = []
        self.lock = asyncio.Lock()
    
    async def record_message_received(self, message_type: str):
        """Record a received message"""
        async with self.lock:
            self.metrics['messages_received'][message_type] += 1
    
    async def record_message_sent(self, message_type: str):
        """Record a sent message"""
        async with self.lock:
            self.metrics['messages_sent'][message_type] += 1
    
    async def record_message_error(self):
        """Record a message processing error"""
        async with self.lock:
            self.metrics['message_errors'] += 1
    
    async def record_message_latency(self, latency: float):
        """Record message processing latency"""
        async with self.lock:
            self.message_latencies.append(latency)
            # Keep only the last 1000 latencies
            if len(self.message_latencies) > 1000:
                self.message_latencies = self.message_latencies[-1000:]
    
    async def record_connection(self):
        """Record a new connection"""
        async with self.lock:
            self.metrics['connection_total'] += 1
            self.metrics['connected_clients'] += 1
    
    async def record_disconnection(self):
        """Record a disconnection"""
        async with self.lock:
            self.metrics['connected_clients'] = max(0, self.metrics['connected_clients'] - 1)
    
    async def record_connection_error(self):
        """Record a connection error"""
        async with self.lock:
            self.metrics['connection_errors'] += 1
    
    async def record_auth_success(self):
        """Record a successful authentication"""
        async with self.lock:
            self.metrics['auth_success'] += 1
    
    async def record_auth_failure(self):
        """Record a failed authentication"""
        async with self.lock:
            self.metrics['auth_failure'] += 1
    
    async def record_session_start(self, session_type: str):
        """Record a session start"""
        async with self.lock:
            if session_type == 'screen':
                self.metrics['screen_sessions'] += 1
            elif session_type == 'audio':
                self.metrics['audio_sessions'] += 1
    
    async def record_file_transfer(self):
        """Record a file transfer"""
        async with self.lock:
            self.metrics['file_transfers'] += 1
    
    async def record_shell_command(self):
        """Record a shell command execution"""
        async with self.lock:
            self.metrics['shell_commands'] += 1
    
    async def record_permission_request(self):
        """Record a permission request"""
        async with self.lock:
            self.metrics['permission_requests'] += 1
    
    async def record_permission_grant(self):
        """Record a permission grant"""
        async with self.lock:
            self.metrics['permission_grants'] += 1
    
    async def record_permission_denial(self):
        """Record a permission denial"""
        async with self.lock:
            self.metrics['permission_denials'] += 1
    
    async def get_metrics(self) -> Dict[str, Any]:
        """Get current metrics"""
        async with self.lock:
            result = dict(self.metrics)
            
            # Calculate average latency
            if self.message_latencies:
                result['avg_message_latency'] = sum(self.message_latencies) / len(self.message_latencies)
            else:
                result['avg_message_latency'] = 0
            
            return result

# Enhanced connection pool
class ConnectionPool:
    def __init__(self, max_size: int):
        self.max_size = max_size
        self.connections: Dict[str, WebSocketServerProtocol] = {}
        self.last_used: Dict[str, float] = {}
        self._lock = asyncio.Lock()
    
    async def add(self, client_id: str, connection: WebSocketServerProtocol):
        """Add a connection to the pool"""
        async with self._lock:
            if len(self.connections) >= self.max_size:
                # Remove oldest connection
                oldest_client = min(self.last_used.items(), key=lambda x: x[1])[0]
                await self.remove(oldest_client)
            
            self.connections[client_id] = connection
            self.last_used[client_id] = time.time()
    
    async def remove(self, client_id: str):
        """Remove a connection from the pool"""
        async with self._lock:
            if client_id in self.connections:
                try:
                    await self.connections[client_id].close()
                except Exception as e:
                    logger.error(f"Error closing connection for {client_id}: {e}")
                
                del self.connections[client_id]
                del self.last_used[client_id]
    
    async def get(self, client_id: str) -> Optional[WebSocketServerProtocol]:
        """Get a connection from the pool"""
        async with self._lock:
            connection = self.connections.get(client_id)
            if connection:
                self.last_used[client_id] = time.time()
            return connection
    
    async def broadcast(self, message: Dict[str, Any], exclude: Set[str] = None):
        """Broadcast a message to all connections"""
        exclude = exclude or set()
        async with self._lock:
            for client_id, connection in list(self.connections.items()):
                if client_id in exclude:
                    continue
                
                try:
                    await connection.send(json.dumps(message))
                except Exception as e:
                    logger.error(f"Error broadcasting to {client_id}: {e}")
                    await self.remove(client_id)
    
    async def cleanup_idle_connections(self, idle_timeout: int):
        """Remove idle connections"""
        now = time.time()
        to_remove = []
        
        async with self._lock:
            for client_id, last_used in self.last_used.items():
                if now - last_used > idle_timeout:
                    to_remove.append(client_id)
        
        for client_id in to_remove:
            logger.info(f"Removing idle connection: {client_id}")
            await self.remove(client_id)
    
    def get_connection_count(self) -> int:
        """Get the number of active connections"""
        return len(self.connections)

# Message compression utilities
def compress_message(data: Dict[str, Any]) -> bytes:
    """Compress a message using zlib"""
    serialized = json.dumps(data).encode()
    if len(serialized) > config.COMPRESSION_THRESHOLD:
        return zlib.compress(serialized)
    return serialized

def decompress_message(data: bytes) -> Dict[str, Any]:
    """Decompress a message"""
    try:
        return json.loads(zlib.decompress(data).decode())
    except zlib.error:
        return json.loads(data.decode())

# Initialize components
db_manager = DatabaseManager(config.DB_PATH)
security_manager = SecurityManager()
message_queue = MessageQueueManager()
metrics_collector = MetricsCollector()
connection_pool = ConnectionPool(config.CONNECTION_POOL_SIZE)

# Set database manager reference in security manager
security_manager.set_db_manager(db_manager)

# Message processor
async def process_message(websocket: WebSocketServerProtocol, data: Dict[str, Any], client_id: str):
    """Process an incoming message"""
    start_time = time.time()
    correlation_id = data.get('request_id', str(uuid.uuid4()))
    
    # Add correlation ID to logger context
    logger_context = {'correlation_id': correlation_id}
    logger.info(f"Processing message from {client_id}: {data.get('type')}", extra=logger_context)
    
    # Record metrics
    await metrics_collector.record_message_received(data.get('type', 'unknown'))
    
    # Validate message format
    is_valid, error_message = security_manager.validate_message(data)
    if not is_valid:
        logger.warning(f"Invalid message from {client_id}: {error_message}", extra=logger_context)
        await metrics_collector.record_message_error()
        await websocket.send(json.dumps({
            'type': 'error',
            'request_id': correlation_id,
            'message': error_message
        }))
        return
    
    # Check rate limit
    if not await security_manager.check_rate_limit(client_id):
        logger.warning(f"Rate limit exceeded for {client_id}", extra=logger_context)
        await metrics_collector.record_message_error()
        await websocket.send(json.dumps({
            'type': 'error',
            'request_id': correlation_id,
            'message': 'Rate limit exceeded'
        }))
        return
    
    # Update client last seen
    await db_manager.update_client_last_seen(client_id)
    
    # Process message based on type
    message_type = data.get('type')
    
    try:
        if message_type == 'message':
            await handle_client_message(websocket, data, client_id, correlation_id)
        elif message_type == 'command':
            await handle_command(websocket, data, client_id, correlation_id)
        elif message_type == 'ping':
            await handle_ping(websocket, data, client_id, correlation_id)
        elif message_type == 'file':
            await handle_file_transfer(websocket, data, client_id, correlation_id)
        elif message_type == 'status':
            await handle_status_update(websocket, data, client_id, correlation_id)
        elif message_type == 'screen':
            await handle_screen_message(websocket, data, client_id, correlation_id)
        elif message_type == 'touch':
            await handle_touch_message(websocket, data, client_id, correlation_id)
        elif message_type == 'key':
            await handle_key_message(websocket, data, client_id, correlation_id)
        elif message_type == 'clipboard':
            await handle_clipboard_message(websocket, data, client_id, correlation_id)
        elif message_type == 'app':
            await handle_app_message(websocket, data, client_id, correlation_id)
        elif message_type == 'location':
            await handle_location_message(websocket, data, client_id, correlation_id)
        elif message_type == 'camera':
            await handle_camera_message(websocket, data, client_id, correlation_id)
        elif message_type == 'audio':
            await handle_audio_message(websocket, data, client_id, correlation_id)
        elif message_type == 'shell':
            await handle_shell_message(websocket, data, client_id, correlation_id)
        elif message_type == 'file_operation':
            await handle_file_operation_message(websocket, data, client_id, correlation_id)
        elif message_type == 'permission':
            await handle_permission_message(websocket, data, client_id, correlation_id)
        elif message_type == 'consent':
            await handle_consent_message(websocket, data, client_id, correlation_id)
        else:
            logger.warning(f"Unknown message type from {client_id}: {message_type}", extra=logger_context)
            await websocket.send(json.dumps({
                'type': 'error',
                'request_id': correlation_id,
                'message': f'Unknown message type: {message_type}'
            }))
    except Exception as e:
        logger.error(f"Error processing message from {client_id}: {e}", extra=logger_context, exc_info=True)
        await metrics_collector.record_message_error()
        await websocket.send(json.dumps({
            'type': 'error',
            'request_id': correlation_id,
            'message': 'Internal server error'
        }))
    
    # Record message processing latency
    latency = time.time() - start_time
    await metrics_collector.record_message_latency(latency)
    logger.debug(f"Message processed in {latency:.4f}s", extra=logger_context)

# Message handlers
async def handle_client_message(websocket: WebSocketServerProtocol, data: Dict[str, Any], client_id: str, correlation_id: str):
    """Handle a client message"""
    recipient_id = data.get('recipient_id')
    if not recipient_id:
        await websocket.send(json.dumps({
            'type': 'error',
            'request_id': correlation_id,
            'message': 'Missing recipient_id'
        }))
        return
    
    # Check if recipient exists
    recipient_info = await db_manager.get_client_info(recipient_id)
    if not recipient_info:
        await websocket.send(json.dumps({
            'type': 'error',
            'request_id': correlation_id,
            'message': 'Recipient not found'
        }))
        return
    
    # Prepare message for delivery
    message = {
        'type': 'message',
        'sender_id': client_id,
        'content': data.get('content'),
        'timestamp': time.time(),
        'request_id': correlation_id
    }
    
    # Try to deliver message directly if recipient is connected
    recipient_connection = await connection_pool.get(recipient_id)
    if recipient_connection:
        try:
            await recipient_connection.send(json.dumps(message))
            await metrics_collector.record_message_sent('message')
            
            # Send delivery confirmation to sender
            await websocket.send(json.dumps({
                'type': 'delivery_receipt',
                'request_id': correlation_id,
                'recipient_id': recipient_id,
                'status': 'delivered',
                'timestamp': time.time()
            }))
            
            return
        except Exception as e:
            logger.error(f"Error delivering message to {recipient_id}: {e}")
            # Fall back to queue
    
    # Store message in database
    message_id = await db_manager.store_message(
        sender_id=client_id,
        recipient_id=recipient_id,
        message_type='message',
        content=json.dumps(data.get('content'))
    )
    
    # Queue message for delivery
    await message_queue.enqueue_message(recipient_id, message)
    
    # Send queued confirmation to sender
    await websocket.send(json.dumps({
        'type': 'delivery_receipt',
        'request_id': correlation_id,
        'recipient_id': recipient_id,
        'status': 'queued',
        'message_id': message_id,
        'timestamp': time.time()
    }))
    
    # Notify recipient if they're connected but direct delivery failed
    if recipient_connection:
        try:
            await recipient_connection.send(json.dumps({
                'type': 'notification',
                'message': 'You have new messages',
                'count': await message_queue.get_queue_length(recipient_id)
            }))
        except Exception:
            pass

async def handle_command(websocket: WebSocketServerProtocol, data: Dict[str, Any], client_id: str, correlation_id: str):
    """Handle a command message"""
    command = data.get('command')
    if not command:
        await websocket.send(json.dumps({
            'type': 'error',
            'request_id': correlation_id,
            'message': 'Missing command'
        }))
        return
    
    # Process different commands
    if command == 'get_messages':
        await handle_get_messages(websocket, data, client_id, correlation_id)
    elif command == 'mark_delivered':
        await handle_mark_delivered(websocket, data, client_id, correlation_id)
    elif command == 'get_client_info':
        await handle_get_client_info(websocket, data, client_id, correlation_id)
    elif command == 'get_permissions':
        await handle_get_permissions(websocket, data, client_id, correlation_id)
    elif command == 'get_active_sessions':
        await handle_get_active_sessions(websocket, data, client_id, correlation_id)
    else:
        await websocket.send(json.dumps({
            'type': 'error',
            'request_id': correlation_id,
            'message': f'Unknown command: {command}'
        }))

async def handle_get_messages(websocket: WebSocketServerProtocol, data: Dict[str, Any], client_id: str, correlation_id: str):
    """Handle get_messages command"""
    # Get messages from queue
    messages = await message_queue.dequeue_messages(client_id)
    
    # Get messages from database if queue is empty
    if not messages:
        db_messages = await db_manager.get_undelivered_messages(client_id)
        for msg in db_messages:
            try:
                content = json.loads(msg['content'])
                messages.append({
                    'type': 'message',
                    'sender_id': msg['sender_id'],
                    'content': content,
                    'timestamp': msg['timestamp'],
                    'message_id': msg['id']
                })
            except Exception as e:
                logger.error(f"Error parsing message content: {e}")
    
    # Send messages to client
    await websocket.send(json.dumps({
        'type': 'messages',
        'request_id': correlation_id,
        'messages': messages,
        'count': len(messages)
    }))
    
    await metrics_collector.record_message_sent('messages')

async def handle_mark_delivered(websocket: WebSocketServerProtocol, data: Dict[str, Any], client_id: str, correlation_id: str):
    """Handle mark_delivered command"""
    message_id = data.get('message_id')
    if not message_id:
        await websocket.send(json.dumps({
            'type': 'error',
            'request_id': correlation_id,
            'message': 'Missing message_id'
        }))
        return
    
    # Mark message as delivered in database
    await db_manager.mark_message_delivered(message_id)
    
    # Send confirmation
    await websocket.send(json.dumps({
        'type': 'command_response',
        'request_id': correlation_id,
        'command': 'mark_delivered',
        'status': 'success'
    }))

async def handle_get_client_info(websocket: WebSocketServerProtocol, data: Dict[str, Any], client_id: str, correlation_id: str):
    """Handle get_client_info command"""
    target_client_id = data.get('target_client_id')
    if not target_client_id:
        await websocket.send(json.dumps({
            'type': 'error',
            'request_id': correlation_id,
            'message': 'Missing target_client_id'
        }))
        return
    
    # Get client info
    client_info = await db_manager.get_client_info(target_client_id)
    if not client_info:
        await websocket.send(json.dumps({
            'type': 'error',
            'request_id': correlation_id,
            'message': 'Client not found'
        }))
        return
    
    # Remove sensitive information
    if 'metadata' in client_info:
        metadata = client_info['metadata']
        if isinstance(metadata, dict) and 'credentials' in metadata:
            del metadata['credentials']
    
    # Send client info
    await websocket.send(json.dumps({
        'type': 'command_response',
        'request_id': correlation_id,
        'command': 'get_client_info',
        'client_info': client_info
    }))

async def handle_get_permissions(websocket: WebSocketServerProtocol, data: Dict[str, Any], client_id: str, correlation_id: str):
    """Handle get_permissions command"""
    target_client_id = data.get('target_client_id') or client_id
    
    # Check if client has permission to view other client's permissions
    if target_client_id != client_id:
        has_permission = await security_manager.check_permission(client_id, 'view_other_permissions')
        if not has_permission:
            await websocket.send(json.dumps({
                'type': 'error',
                'request_id': correlation_id,
                'message': 'Permission denied'
            }))
            return
    
    # Get permissions
    permissions = await db_manager.get_client_permissions(target_client_id)
    
    # Get consent status
    consent_given = await db_manager.get_client_consent(target_client_id)
    
    # Send permissions
    await websocket.send(json.dumps({
        'type': 'command_response',
        'request_id': correlation_id,
        'command': 'get_permissions',
        'permissions': permissions,
        'consent_given': consent_given
    }))

async def handle_get_active_sessions(websocket: WebSocketServerProtocol, data: Dict[str, Any], client_id: str, correlation_id: str):
    """Handle get_active_sessions command"""
    target_client_id = data.get('target_client_id')
    controller_id = data.get('controller_id')
    
    # Check if client has permission to view sessions
    if target_client_id and target_client_id != client_id:
        has_permission = await security_manager.check_permission(client_id, 'view_other_sessions')
        if not has_permission:
            await websocket.send(json.dumps({
                'type': 'error',
                'request_id': correlation_id,
                'message': 'Permission denied'
            }))
            return
    
    # Get active sessions
    sessions = await db_manager.get_active_sessions(
        client_id=target_client_id,
        controller_id=controller_id
    )
    
    # Send sessions
    await websocket.send(json.dumps({
        'type': 'command_response',
        'request_id': correlation_id,
        'command': 'get_active_sessions',
        'sessions': sessions
    }))

async def handle_ping(websocket: WebSocketServerProtocol, data: Dict[str, Any], client_id: str, correlation_id: str):
    """Handle ping message"""
    await websocket.send(json.dumps({
        'type': 'pong',
        'request_id': correlation_id,
        'timestamp': time.time()
    }))

async def handle_file_transfer(websocket: WebSocketServerProtocol, data: Dict[str, Any], client_id: str, correlation_id: str):
    """Handle file transfer message"""
    recipient_id = data.get('recipient_id')
    if not recipient_id:
        await websocket.send(json.dumps({
            'type': 'error',
            'request_id': correlation_id,
            'message': 'Missing recipient_id'
        }))
        return
    
    # Check if file data is present
    file_data = data.get('file_data')
    if not file_data:
        await websocket.send(json.dumps({
            'type': 'error',
            'request_id': correlation_id,
            'message': 'Missing file_data'
        }))
        return
    
    # Check if client has permission to send files
    has_permission = await security_manager.check_permission(client_id, 'file_transfer')
    if not has_permission:
        await websocket.send(json.dumps({
            'type': 'error',
            'request_id': correlation_id,
            'message': 'Permission denied: file_transfer'
        }))
        return
    
    # Record file transfer metric
    await metrics_collector.record_file_transfer()
    
    # Try to deliver file directly if recipient is connected
    recipient_connection = await connection_pool.get(recipient_id)
    if recipient_connection:
        try:
            await recipient_connection.send(json.dumps({
                'type': 'file',
                'sender_id': client_id,
                'file_name': data.get('file_name'),
                'file_type': data.get('file_type'),
                'file_size': data.get('file_size'),
                'file_data': file_data,
                'timestamp': time.time(),
                'request_id': correlation_id
            }))
            
            await metrics_collector.record_message_sent('file')
            
            # Send delivery confirmation to sender
            await websocket.send(json.dumps({
                'type': 'delivery_receipt',
                'request_id': correlation_id,
                'recipient_id': recipient_id,
                'status': 'delivered',
                'timestamp': time.time()
            }))
            
            return
        except Exception as e:
            logger.error(f"Error delivering file to {recipient_id}: {e}")
            # Fall back to queue
    
    # Store file message in database (consider storing large files separately)
    message_id = await db_manager.store_message(
        sender_id=client_id,
        recipient_id=recipient_id,
        message_type='file',
        content=json.dumps({
            'file_name': data.get('file_name'),
            'file_type': data.get('file_type'),
            'file_size': data.get('file_size'),
            'file_data': file_data
        })
    )
    
    # Queue file message for delivery
    await message_queue.enqueue_message(recipient_id, {
        'type': 'file',
        'sender_id': client_id,
        'file_name': data.get('file_name'),
        'file_type': data.get('file_type'),
        'file_size': data.get('file_size'),
        'file_data': file_data,
        'timestamp': time.time(),
        'message_id': message_id,
        'request_id': correlation_id
    })
    
    # Send queued confirmation to sender
    await websocket.send(json.dumps({
        'type': 'delivery_receipt',
        'request_id': correlation_id,
        'recipient_id': recipient_id,
        'status': 'queued',
        'message_id': message_id,
        'timestamp': time.time()
    }))

async def handle_status_update(websocket: WebSocketServerProtocol, data: Dict[str, Any], client_id: str, correlation_id: str):
    """Handle status update message"""
    status = data.get('status')
    if not status:
        await websocket.send(json.dumps({
            'type': 'error',
            'request_id': correlation_id,
            'message': 'Missing status'
        }))
        return
    
    # Update client metadata with status
    client_info = await db_manager.get_client_info(client_id)
    if client_info:
        metadata = client_info.get('metadata', {})
        if isinstance(metadata, str):
            try:
                metadata = json.loads(metadata)
            except:
                metadata = {}
        
        metadata['status'] = status
        metadata['status_updated_at'] = time.time()
        
        await db_manager.register_client(
            client_id=client_id,
            client_type=client_info.get('client_type', 'unknown'),
            metadata=metadata
        )
    
    # Send confirmation
    await websocket.send(json.dumps({
        'type': 'status_update_response',
        'request_id': correlation_id,
        'status': 'success'
    }))

async def handle_consent_message(websocket: WebSocketServerProtocol, data: Dict[str, Any], client_id: str, correlation_id: str):
    """Handle consent-related messages"""
    action = data.get('action')
    
    if action == 'give_consent':
        # Update client consent status
        await db_manager.set_client_consent(client_id, True)
        
        # Send confirmation
        await websocket.send(json.dumps({
            'type': 'consent',
            'action': 'consent_updated',
            'request_id': correlation_id,
            'consent_given': True,
            'timestamp': time.time()
        }))
        
        log_audit("Client gave consent", client_id=client_id)
    
    elif action == 'revoke_consent':
        # Update client consent status
        await db_manager.set_client_consent(client_id, False)
        
        # End all active sessions for this client
        sessions = await db_manager.get_active_sessions(client_id=client_id)
        for session in sessions:
            await db_manager.end_session(session['session_id'])
            
            # Notify controller that session was ended
            controller_id = session['controller_id']
            controller_connection = await connection_pool.get(controller_id)
            if controller_connection:
                try:
                    await controller_connection.send(json.dumps({
                        'type': session['session_type'],
                        'action': 'session_ended',
                        'session_id': session['session_id'],
                        'reason': 'consent_revoked',
                        'timestamp': time.time()
                    }))
                except Exception as e:
                    logger.error(f"Error notifying controller {controller_id} about session end: {e}")
        
        # Send confirmation
        await websocket.send(json.dumps({
            'type': 'consent',
            'action': 'consent_updated',
            'request_id': correlation_id,
            'consent_given': False,
            'timestamp': time.time()
        }))
        
        log_audit("Client revoked consent", client_id=client_id)
    
    elif action == 'get_consent_status':
        # Get client consent status
        consent_given = await db_manager.get_client_consent(client_id)
        
        # Send consent status
        await websocket.send(json.dumps({
            'type': 'consent',
            'action': 'consent_status',
            'request_id': correlation_id,
            'consent_given': consent_given,
            'timestamp': time.time()
        }))
    
    else:
        await websocket.send(json.dumps({
            'type': 'error',
            'request_id': correlation_id,
            'message': f'Unknown consent action: {action}'
        }))

async def handle_permission_message(websocket: WebSocketServerProtocol, data: Dict[str, Any], client_id: str, correlation_id: str):
    """Handle permission-related messages"""
    action = data.get('action')
    
    if action == 'request':
        # Record permission request
        await metrics_collector.record_permission_request()
        
        permission = data.get('permission')
        if not permission:
            await websocket.send(json.dumps({
                'type': 'error',
                'request_id': correlation_id,
                'message': 'Missing permission'
            }))
            return
        
        target_client_id = data.get('target_client_id')
        if not target_client_id:
            await websocket.send(json.dumps({
                'type': 'error',
                'request_id': correlation_id,
                'message': 'Missing target_client_id'
            }))
            return
        
        # Check if target client exists
        target_client = await db_manager.get_client_info(target_client_id)
        if not target_client:
            await websocket.send(json.dumps({
                'type': 'error',
                'request_id': correlation_id,
                'message': 'Target client not found'
            }))
            return
        
        # Check if target client has given consent
        if config.REQUIRE_USER_CONSENT:
            consent_given = await db_manager.get_client_consent(target_client_id)
            if not consent_given:
                await websocket.send(json.dumps({
                    'type': 'permission',
                    'action': 'response',
                    'request_id': correlation_id,
                    'permission': permission,
                    'granted': False,
                    'reason': 'consent_required',
                    'timestamp': time.time()
                }))
                return
        
        # Forward permission request to target client
        target_connection = await connection_pool.get(target_client_id)
        if target_connection:
            try:
                # Send permission request to target client
                await target_connection.send(json.dumps({
                    'type': 'permission',
                    'action': 'request',
                    'request_id': correlation_id,
                    'permission': permission,
                    'requester_id': client_id,
                    'timestamp': time.time()
                }))
                
                # Send acknowledgment to requester
                await websocket.send(json.dumps({
                    'type': 'permission',
                    'action': 'request_sent',
                    'request_id': correlation_id,
                    'permission': permission,
                    'target_client_id': target_client_id,
                    'timestamp': time.time()
                }))
                
                return
            except Exception as e:
                logger.error(f"Error forwarding permission request to {target_client_id}: {e}")
        
        # If target client is not connected, send error
        await websocket.send(json.dumps({
            'type': 'permission',
            'action': 'response',
            'request_id': correlation_id,
            'permission': permission,
            'granted': False,
            'reason': 'target_not_connected',
            'timestamp': time.time()
        }))
    
    elif action == 'response':
        permission = data.get('permission')
        granted = data.get('granted', False)
        requester_id = data.get('requester_id')
        
        if not permission or not requester_id:
            await websocket.send(json.dumps({
                'type': 'error',
                'request_id': correlation_id,
                'message': 'Missing permission or requester_id'
            }))
            return
        
        # Update permission in database
        await db_manager.set_client_permission(requester_id, permission, granted)
        
        # Record permission grant/denial
        if granted:
            await metrics_collector.record_permission_grant()
        else:
            await metrics_collector.record_permission_denial()
        
        # Forward response to requester
        requester_connection = await connection_pool.get(requester_id)
        if requester_connection:
            try:
                await requester_connection.send(json.dumps({
                    'type': 'permission',
                    'action': 'response',
                    'request_id': correlation_id,
                    'permission': permission,
                    'granted': granted,
                    'timestamp': time.time()
                }))
            except Exception as e:
                logger.error(f"Error forwarding permission response to {requester_id}: {e}")
        
        # Send confirmation to responder
        await websocket.send(json.dumps({
            'type': 'permission',
            'action': 'response_sent',
            'request_id': correlation_id,
            'permission': permission,
            'granted': granted,
            'requester_id': requester_id,
            'timestamp': time.time()
        }))
        
        log_audit("Permission response", 
                 client_id=client_id, 
                 requester_id=requester_id, 
                 permission=permission, 
                 granted=granted)
    
    else:
        await websocket.send(json.dumps({
            'type': 'error',
            'request_id': correlation_id,
            'message': f'Unknown permission action: {action}'
        }))


# Remote control message handlers
async def handle_screen_message(websocket: WebSocketServerProtocol, data: Dict[str, Any], client_id: str, correlation_id: str):
    """Handle screen-related messages"""
    action = data.get('action')
    session_id = data.get('session_id')
    
    # Check permission for screen control
    if action in ['start_session', 'stop_session', 'set_quality'] and recipient_id:
        has_permission = await security_manager.check_permission(client_id, 'screen_control')
        if not has_permission:
            await websocket.send(json.dumps({
                'type': 'error',
                'request_id': correlation_id,
                'message': 'Permission denied: screen_control'
            }))
            return
    
    # Check if recipient exists
    if recipient_id:
        recipient_info = await db_manager.get_client_info(recipient_id)
        if not recipient_info:
            await websocket.send(json.dumps({
                'type': 'error',
                'request_id': correlation_id,
                'message': 'Recipient not found'
            }))
            return
    
    # Handle start session
    if action == 'start_session' and recipient_id:
        # Generate session ID if not provided
        if not session_id:
            session_id = str(uuid.uuid4())
        
        # Get options
        options = data.get('options', {})
        
        # Apply default options if not provided
        if 'quality' not in options:
            options['quality'] = config.DEFAULT_QUALITY
        if 'fps' not in options:
            options['fps'] = config.DEFAULT_FPS
        if 'adaptive_quality' not in options:
            options['adaptive_quality'] = config.ADAPTIVE_QUALITY
        
        # Create session in database
        success = await db_manager.create_session(
            session_id=session_id,
            client_id=recipient_id,
            controller_id=client_id,
            session_type='screen',
            options=options
        )
        
        if not success:
            await websocket.send(json.dumps({
                'type': 'error',
                'request_id': correlation_id,
                'message': 'Failed to create session'
            }))
            return
        
        # Record session start
        await metrics_collector.record_session_start('screen')
    
    # Handle stop session
    elif action == 'stop_session' and session_id:
        # Get session info
        session = await db_manager.get_session(session_id)
        if not session:
            await websocket.send(json.dumps({
                'type': 'error',
                'request_id': correlation_id,
                'message': 'Session not found'
            }))
            return
        
        # Check if client is authorized to stop session
        if session['controller_id'] != client_id and session['client_id'] != client_id:
            await websocket.send(json.dumps({
                'type': 'error',
                'request_id': correlation_id,
                'message': 'Not authorized to stop this session'
            }))
            return
        
        # End session in database
        await db_manager.end_session(session_id)
    
    # Forward screen message to recipient
    if recipient_id:
        recipient_connection = await connection_pool.get(recipient_id)
        if recipient_connection:
            try:
                # Add sender_id to message
                forward_data = dict(data)
                forward_data['sender_id'] = client_id
                forward_data['request_id'] = correlation_id
                
                await recipient_connection.send(json.dumps(forward_data))
                await metrics_collector.record_message_sent('screen')
                
                # For frame data, don't wait for response
                if action == 'frame':
                    return
                
                # For other actions, wait for response from recipient
                # In a real implementation, you would set up a callback
                # For now, just acknowledge receipt
                await websocket.send(json.dumps({
                    'type': 'screen',
                    'action': f"{action}_sent",
                    'request_id': correlation_id,
                    'recipient_id': recipient_id,
                    'status': 'sent',
                    'session_id': session_id
                }))
                return
            except Exception as e:
                logger.error(f"Error forwarding screen message to {recipient_id}: {e}")
    
    # If this is a response to a screen message, forward to original sender
    if session_id and data.get('controller_id'):
        controller_id = data.get('controller_id')
        controller_connection = await connection_pool.get(controller_id)
        
        if controller_connection:
            try:
                # Forward response to controller
                forward_data = dict(data)
                forward_data['sender_id'] = client_id
                
                await controller_connection.send(json.dumps(forward_data))
                await metrics_collector.record_message_sent('screen')
                return
            except Exception as e:
                logger.error(f"Error forwarding screen response to {controller_id}: {e}")
    
    # If we get here, we couldn't deliver the message
    await websocket.send(json.dumps({
        'type': 'error',
        'request_id': correlation_id,
        'message': 'Could not deliver screen message'
    }))

async def handle_touch_message(websocket: WebSocketServerProtocol, data: Dict[str, Any], client_id: str, correlation_id: str):
    """Handle touch-related messages"""
    recipient_id = data.get('recipient_id')
    session_id = data.get('session_id')
    
    # Check permission for touch control
    if recipient_id:
        has_permission = await security_manager.check_permission(client_id, 'touch_control')
        if not has_permission:
            await websocket.send(json.dumps({
                'type': 'error',
                'request_id': correlation_id,
                'message': 'Permission denied: touch_control'
            }))
            return
    
    # Check if recipient exists
    if recipient_id:
        recipient_info = await db_manager.get_client_info(recipient_id)
        if not recipient_info:
            await websocket.send(json.dumps({
                'type': 'error',
                'request_id': correlation_id,
                'message': 'Recipient not found'
            }))
            return
    
    # Check if session exists
    if session_id:
        session = await db_manager.get_session(session_id)
        if not session:
            await websocket.send(json.dumps({
                'type': 'error',
                'request_id': correlation_id,
                'message': 'Session not found'
            }))
            return
        
        # Check if session is active
        if not session['active']:
            await websocket.send(json.dumps({
                'type': 'error',
                'request_id': correlation_id,
                'message': 'Session is not active'
            }))
            return
    
    # Forward touch message to recipient
    if recipient_id:
        recipient_connection = await connection_pool.get(recipient_id)
        if recipient_connection:
            try:
                # Add sender_id to message
                forward_data = dict(data)
                forward_data['sender_id'] = client_id
                forward_data['request_id'] = correlation_id
                
                await recipient_connection.send(json.dumps(forward_data))
                await metrics_collector.record_message_sent('touch')
                
                # Acknowledge receipt
                await websocket.send(json.dumps({
                    'type': 'touch',
                    'action': 'sent',
                    'request_id': correlation_id,
                    'recipient_id': recipient_id,
                    'status': 'sent',
                    'session_id': session_id
                }))
                return
            except Exception as e:
                logger.error(f"Error forwarding touch message to {recipient_id}: {e}")
    
    # If this is a response to a touch message, forward to original sender
    if session_id and data.get('controller_id'):
        controller_id = data.get('controller_id')
        controller_connection = await connection_pool.get(controller_id)
        
        if controller_connection:
            try:
                # Forward response to controller
                forward_data = dict(data)
                forward_data['sender_id'] = client_id
                
                await controller_connection.send(json.dumps(forward_data))
                await metrics_collector.record_message_sent('touch')
                return
            except Exception as e:
                logger.error(f"Error forwarding touch response to {controller_id}: {e}")
    
    # If we get here, we couldn't deliver the message
    await websocket.send(json.dumps({
        'type': 'error',
        'request_id': correlation_id,
        'message': 'Could not deliver touch message'
    }))

async def handle_key_message(websocket: WebSocketServerProtocol, data: Dict[str, Any], client_id: str, correlation_id: str):
    """Handle keyboard-related messages"""
    recipient_id = data.get('recipient_id')
    session_id = data.get('session_id')
    
    # Check permission for keyboard control
    if recipient_id:
        has_permission = await security_manager.check_permission(client_id, 'keyboard_control')
        if not has_permission:
            await websocket.send(json.dumps({
                'type': 'error',
                'request_id': correlation_id,
                'message': 'Permission denied: keyboard_control'
            }))
            return
    
    # Check if recipient exists
    if recipient_id:
        recipient_info = await db_manager.get_client_info(recipient_id)
        if not recipient_info:
            await websocket.send(json.dumps({
                'type': 'error',
                'request_id': correlation_id,
                'message': 'Recipient not found'
            }))
            return
    
    # Check if session exists
    if session_id:
        session = await db_manager.get_session(session_id)
        if not session:
            await websocket.send(json.dumps({
                'type': 'error',
                'request_id': correlation_id,
                'message': 'Session not found'
            }))
            return
        
        # Check if session is active
        if not session['active']:
            await websocket.send(json.dumps({
                'type': 'error',
                'request_id': correlation_id,
                'message': 'Session is not active'
            }))
            return
    
    # Forward key message to recipient
    if recipient_id:
        recipient_connection = await connection_pool.get(recipient_id)
        if recipient_connection:
            try:
                # Add sender_id to message
                forward_data = dict(data)
                forward_data['sender_id'] = client_id
                forward_data['request_id'] = correlation_id
                
                await recipient_connection.send(json.dumps(forward_data))
                await metrics_collector.record_message_sent('key')
                
                # Acknowledge receipt
                await websocket.send(json.dumps({
                    'type': 'key',
                    'action': 'sent',
                    'request_id': correlation_id,
                    'recipient_id': recipient_id,
                    'status': 'sent',
                    'session_id': session_id
                }))
                return
            except Exception as e:
                logger.error(f"Error forwarding key message to {recipient_id}: {e}")
    
    # If this is a response to a key message, forward to original sender
    if session_id and data.get('controller_id'):
        controller_id = data.get('controller_id')
        controller_connection = await connection_pool.get(controller_id)
        
        if controller_connection:
            try:
                # Forward response to controller
                forward_data = dict(data)
                forward_data['sender_id'] = client_id
                
                await controller_connection.send(json.dumps(forward_data))
                await metrics_collector.record_message_sent('key')
                return
            except Exception as e:
                logger.error(f"Error forwarding key response to {controller_id}: {e}")
    
    # If we get here, we couldn't deliver the message
    await websocket.send(json.dumps({
        'type': 'error',
        'request_id': correlation_id,
        'message': 'Could not deliver key message'
    }))

async def handle_clipboard_message(websocket: WebSocketServerProtocol, data: Dict[str, Any], client_id: str, correlation_id: str):
    """Handle clipboard-related messages"""
    recipient_id = data.get('recipient_id')
    
    # Check permission for clipboard access
    if recipient_id:
        has_permission = await security_manager.check_permission(client_id, 'clipboard_access')
        if not has_permission:
            await websocket.send(json.dumps({
                'type': 'error',
                'request_id': correlation_id,
                'message': 'Permission denied: clipboard_access'
            }))
            return
    
    # Check if recipient exists
    if recipient_id:
        recipient_info = await db_manager.get_client_info(recipient_id)
        if not recipient_info:
            await websocket.send(json.dumps({
                'type': 'error',
                'request_id': correlation_id,
                'message': 'Recipient not found'
            }))
            return
    
    # Forward clipboard message to recipient
    if recipient_id:
        recipient_connection = await connection_pool.get(recipient_id)
        if recipient_connection:
            try:
                # Add sender_id to message
                forward_data = dict(data)
                forward_data['sender_id'] = client_id
                forward_data['request_id'] = correlation_id
                
                await recipient_connection.send(json.dumps(forward_data))
                await metrics_collector.record_message_sent('clipboard')
                
                # Acknowledge receipt
                await websocket.send(json.dumps({
                    'type': 'clipboard',
                    'action': 'sent',
                    'request_id': correlation_id,
                    'recipient_id': recipient_id,
                    'status': 'sent'
                }))
                return
            except Exception as e:
                logger.error(f"Error forwarding clipboard message to {recipient_id}: {e}")
    
    # If this is a response to a clipboard message, forward to original sender
    if data.get('controller_id'):
        controller_id = data.get('controller_id')
        controller_connection = await connection_pool.get(controller_id)
        
        if controller_connection:
            try:
                # Forward response to controller
                forward_data = dict(data)
                forward_data['sender_id'] = client_id
                
                await controller_connection.send(json.dumps(forward_data))
                await metrics_collector.record_message_sent('clipboard')
                return
            except Exception as e:
                logger.error(f"Error forwarding clipboard response to {controller_id}: {e}")
    
    # If we get here, we couldn't deliver the message
    await websocket.send(json.dumps({
        'type': 'error',
        'request_id': correlation_id,
        'message': 'Could not deliver clipboard message'
    }))

async def handle_app_message(websocket: WebSocketServerProtocol, data: Dict[str, Any], client_id: str, correlation_id: str):
    """Handle app-related messages"""
    recipient_id = data.get('recipient_id')
    
    # Check permission for app management
    if recipient_id:
        has_permission = await security_manager.check_permission(client_id, 'app_management')
        if not has_permission:
            await websocket.send(json.dumps({
                'type': 'error',
                'request_id': correlation_id,
                'message': 'Permission denied: app_management'
            }))
            return
    
    # Check if recipient exists
    if recipient_id:
        recipient_info = await db_manager.get_client_info(recipient_id)
        if not recipient_info:
            await websocket.send(json.dumps({
                'type': 'error',
                'request_id': correlation_id,
                'message': 'Recipient not found'
            }))
            return
    
    # Forward app message to recipient
    if recipient_id:
        recipient_connection = await connection_pool.get(recipient_id)
        if recipient_connection:
            try:
                # Add sender_id to message
                forward_data = dict(data)
                forward_data['sender_id'] = client_id
                forward_data['request_id'] = correlation_id
                
                await recipient_connection.send(json.dumps(forward_data))
                await metrics_collector.record_message_sent('app')
                
                # Acknowledge receipt
                await websocket.send(json.dumps({
                    'type': 'app',
                    'action': 'sent',
                    'request_id': correlation_id,
                    'recipient_id': recipient_id,
                    'status': 'sent'
                }))
                return
            except Exception as e:
                logger.error(f"Error forwarding app message to {recipient_id}: {e}")
    
    # If this is a response to an app message, forward to original sender
    if data.get('controller_id'):
        controller_id = data.get('controller_id')
        controller_connection = await connection_pool.get(controller_id)
        
        if controller_connection:
            try:
                # Forward response to controller
                forward_data = dict(data)
                forward_data['sender_id'] = client_id
                
                await controller_connection.send(json.dumps(forward_data))
                await metrics_collector.record_message_sent('app')
                return
            except Exception as e:
                logger.error(f"Error forwarding app response to {controller_id}: {e}")
    
    # If we get here, we couldn't deliver the message
    await websocket.send(json.dumps({
        'type': 'error',
        'request_id': correlation_id,
        'message': 'Could not deliver app message'
    }))

async def handle_location_message(websocket: WebSocketServerProtocol, data: Dict[str, Any], client_id: str, correlation_id: str):
    """Handle location-related messages"""
    recipient_id = data.get('recipient_id')
    
    # Check permission for location tracking
    if recipient_id:
        has_permission = await security_manager.check_permission(client_id, 'location_tracking')
        if not has_permission:
            await websocket.send(json.dumps({
                'type': 'error',
                'request_id': correlation_id,
                'message': 'Permission denied: location_tracking'
            }))
            return
    
    # Check if recipient exists
    if recipient_id:
        recipient_info = await db_manager.get_client_info(recipient_id)
        if not recipient_info:
            await websocket.send(json.dumps({
                'type': 'error',
                'request_id': correlation_id,
                'message': 'Recipient not found'
            }))
            return
    
    # Forward location message to recipient
    if recipient_id:
        recipient_connection = await connection_pool.get(recipient_id)
        if recipient_connection:
            try:
                # Add sender_id to message
                forward_data = dict(data)
                forward_data['sender_id'] = client_id
                forward_data['request_id'] = correlation_id
                
                await recipient_connection.send(json.dumps(forward_data))
                await metrics_collector.record_message_sent('location')
                
                # Acknowledge receipt
                await websocket.send(json.dumps({
                    'type': 'location',
                    'action': 'sent',
                    'request_id': correlation_id,
                    'recipient_id': recipient_id,
                    'status': 'sent'
                }))
                return
            except Exception as e:
                logger.error(f"Error forwarding location message to {recipient_id}: {e}")
    
    # If this is a response to a location message, forward to original sender
    if data.get('controller_id'):
        controller_id = data.get('controller_id')
        controller_connection = await connection_pool.get(controller_id)
        
        if controller_connection:
            try:
                # Forward response to controller
                forward_data = dict(data)
                forward_data['sender_id'] = client_id
                
                await controller_connection.send(json.dumps(forward_data))
                await metrics_collector.record_message_sent('location')
                return
            except Exception as e:
                logger.error(f"Error forwarding location response to {controller_id}: {e}")
    
    # If we get here, we couldn't deliver the message
    await websocket.send(json.dumps({
        'type': 'error',
        'request_id': correlation_id,
        'message': 'Could not deliver location message'
    }))

async def handle_camera_message(websocket: WebSocketServerProtocol, data: Dict[str, Any], client_id: str, correlation_id: str):
    """Handle camera-related messages"""
    recipient_id = data.get('recipient_id')
    session_id = data.get('session_id')
    
    # Check permission for camera access
    if recipient_id:
        has_permission = await security_manager.check_permission(client_id, 'camera_access')
        if not has_permission:
            await websocket.send(json.dumps({
                'type': 'error',
                'request_id': correlation_id,
                'message': 'Permission denied: camera_access'
            }))
            return
    
    # Check if recipient exists
    if recipient_id:
        recipient_info = await db_manager.get_client_info(recipient_id)
        if not recipient_info:
            await websocket.send(json.dumps({
                'type': 'error',
                'request_id': correlation_id,
                'message': 'Recipient not found'
            }))
            return
    
    # Forward camera message to recipient
    if recipient_id:
        recipient_connection = await connection_pool.get(recipient_id)
        if recipient_connection:
            try:
                # Add sender_id to message
                forward_data = dict(data)
                forward_data['sender_id'] = client_id
                forward_data['request_id'] = correlation_id
                
                await recipient_connection.send(json.dumps(forward_data))
                await metrics_collector.record_message_sent('camera')
                
                # Acknowledge receipt
                await websocket.send(json.dumps({
                    'type': 'camera',
                    'action': 'sent',
                    'request_id': correlation_id,
                    'recipient_id': recipient_id,
                    'status': 'sent',
                    'session_id': session_id
                }))
                return
            except Exception as e:
                logger.error(f"Error forwarding camera message to {recipient_id}: {e}")
    
    # If this is a response to a camera message, forward to original sender
    if session_id and data.get('controller_id'):
        controller_id = data.get('controller_id')
        controller_connection = await connection_pool.get(controller_id)
        
        if controller_connection:
            try:
                # Forward response to controller
                forward_data = dict(data)
                forward_data['sender_id'] = client_id
                
                await controller_connection.send(json.dumps(forward_data))
                await metrics_collector.record_message_sent('camera')
                return
            except Exception as e:
                logger.error(f"Error forwarding camera response to {controller_id}: {e}")
    
    # If we get here, we couldn't deliver the message
    await websocket.send(json.dumps({
        'type': 'error',
        'request_id': correlation_id,
        'message': 'Could not deliver camera message'
    }))

async def handle_audio_message(websocket: WebSocketServerProtocol, data: Dict[str, Any], client_id: str, correlation_id: str):
    """Handle audio-related messages"""
    action = data.get('action')
    recipient_id = data.get('recipient_id')
    session_id = data.get('session_id')
    
    # Check permission for audio streaming
    if recipient_id and action in ['start_session', 'stop_session', 'start_recording', 'stop_recording']:
        has_permission = await security_manager.check_permission(client_id, 'audio_streaming')
        if not has_permission:
            await websocket.send(json.dumps({
                'type': 'error',
                'request_id': correlation_id,
                'message': 'Permission denied: audio_streaming'
            }))
            return
    
    # Check if recipient exists
    if recipient_id:
        recipient_info = await db_manager.get_client_info(recipient_id)
        if not recipient_info:
            await websocket.send(json.dumps({
                'type': 'error',
                'request_id': correlation_id,
                'message': 'Recipient not found'
            }))
            return
    
    # Handle start session
    if action == 'start_session' and recipient_id:
        # Generate session ID if not provided
        if not session_id:
            session_id = str(uuid.uuid4())
        
        # Get options
        options = data.get('options', {})
        
        # Create session in database
        success = await db_manager.create_session(
            session_id=session_id,
            client_id=recipient_id,
            controller_id=client_id,
            session_type='audio',
            options=options
        )
        
        if not success:
            await websocket.send(json.dumps({
                'type': 'error',
                'request_id': correlation_id,
                'message': 'Failed to create session'
            }))
            return
        
        # Record session start
        await metrics_collector.record_session_start('audio')
    
    # Handle stop session
    elif action == 'stop_session' and session_id:
        # Get session info
        session = await db_manager.get_session(session_id)
        if not session:
            await websocket.send(json.dumps({
                'type': 'error',
                'request_id': correlation_id,
                'message': 'Session not found'
            }))
            return
        
        # Check if client is authorized to stop session
        if session['controller_id'] != client_id and session['client_id'] != client_id:
            await websocket.send(json.dumps({
                'type': 'error',
                'request_id': correlation_id,
                'message': 'Not authorized to stop this session'
            }))
            return
        
        # End session in database
        await db_manager.end_session(session_id)
    
    # Forward audio message to recipient
    if recipient_id:
        recipient_connection = await connection_pool.get(recipient_id)
        if recipient_connection:
            try:
                # Add sender_id to message
                forward_data = dict(data)
                forward_data['sender_id'] = client_id
                forward_data['request_id'] = correlation_id
                
                await recipient_connection.send(json.dumps(forward_data))
                await metrics_collector.record_message_sent('audio')
                
                # For audio data, don't wait for response
                if action == 'data':
                    return
                
                # For other actions, acknowledge receipt
                await websocket.send(json.dumps({
                    'type': 'audio',
                    'action': 'sent',
                    'request_id': correlation_id,
                    'recipient_id': recipient_id,
                    'status': 'sent',
                    'session_id': session_id
                }))
                return
            except Exception as e:
                logger.error(f"Error forwarding audio message to {recipient_id}: {e}")
    
    # If this is a response to an audio message, forward to original sender
    if session_id and data.get('controller_id'):
        controller_id = data.get('controller_id')
        controller_connection = await connection_pool.get(controller_id)
        
        if controller_connection:
            try:
                # Forward response to controller
                forward_data = dict(data)
                forward_data['sender_id'] = client_id
                
                await controller_connection.send(json.dumps(forward_data))
                await metrics_collector.record_message_sent('audio')
                return
            except Exception as e:
                logger.error(f"Error forwarding audio response to {controller_id}: {e}")
    
    # If we get here, we couldn't deliver the message
    await websocket.send(json.dumps({
        'type': 'error',
        'request_id': correlation_id,
        'message': 'Could not deliver audio message'
    }))

async def handle_shell_message(websocket: WebSocketServerProtocol, data: Dict[str, Any], client_id: str, correlation_id: str):
    """Handle shell command execution"""
    action = data.get('action')
    recipient_id = data.get('recipient_id')
    
    # Check permission for shell command execution
    if recipient_id and action == 'execute':
        has_permission = await security_manager.check_permission(client_id, 'shell_command')
        if not has_permission:
            await websocket.send(json.dumps({
                'type': 'error',
                'request_id': correlation_id,
                'message': 'Permission denied: shell_command'
            }))
            return
    
    # Check if recipient exists
    if recipient_id:
        recipient_info = await db_manager.get_client_info(recipient_id)
        if not recipient_info:
            await websocket.send(json.dumps({
                'type': 'error',
                'request_id': correlation_id,
                'message': 'Recipient not found'
            }))
            return
    
    # Record shell command execution
    if action == 'execute':
        await metrics_collector.record_shell_command()
        
        # Log audit event
        log_audit("Shell command execution", 
                 client_id=client_id, 
                 recipient_id=recipient_id, 
                 command=data.get('command', 'unknown'))
    
    # Forward shell message to recipient
    if recipient_id:
        recipient_connection = await connection_pool.get(recipient_id)
        if recipient_connection:
            try:
                # Add sender_id to message
                forward_data = dict(data)
                forward_data['sender_id'] = client_id
                forward_data['request_id'] = correlation_id
                
                await recipient_connection.send(json.dumps(forward_data))
                await metrics_collector.record_message_sent('shell')
                
                # Acknowledge receipt
                await websocket.send(json.dumps({
                    'type': 'shell',
                    'action': 'sent',
                    'request_id': correlation_id,
                    'recipient_id': recipient_id,
                    'status': 'sent'
                }))
                return
            except Exception as e:
                logger.error(f"Error forwarding shell message to {recipient_id}: {e}")
    
    # If this is a response to a shell message, forward to original sender
    if data.get('controller_id'):
        controller_id = data.get('controller_id')
        controller_connection = await connection_pool.get(controller_id)
        
        if controller_connection:
            try:
                # Forward response to controller
                forward_data = dict(data)
                forward_data['sender_id'] = client_id
                
                await controller_connection.send(json.dumps(forward_data))
                await metrics_collector.record_message_sent('shell')
                return
            except Exception as e:
                logger.error(f"Error forwarding shell response to {controller_id}: {e}")
    
    # If we get here, we couldn't deliver the message
    await websocket.send(json.dumps({
        'type': 'error',
        'request_id': correlation_id,
        'message': 'Could not deliver shell message'
    }))

async def handle_file_operation_message(websocket: WebSocketServerProtocol, data: Dict[str, Any], client_id: str, correlation_id: str):
    """Handle file operations"""
    action = data.get('action')
    recipient_id = data.get('recipient_id')
    
    # Check permission for file operations
    if recipient_id:
        has_permission = await security_manager.check_permission(client_id, 'file_access')
        if not has_permission:
            await websocket.send(json.dumps({
                'type': 'error',
                'request_id': correlation_id,
                'message': 'Permission denied: file_access'
            }))
            return
    
    # Check if recipient exists
    if recipient_id:
        recipient_info = await db_manager.get_client_info(recipient_id)
        if not recipient_info:
            await websocket.send(json.dumps({
                'type': 'error',
                'request_id': correlation_id,
                'message': 'Recipient not found'
            }))
            return
    
    # Log audit event for sensitive file operations
    if action in ['write', 'delete']:
        log_audit("File operation", 
                 client_id=client_id, 
                 recipient_id=recipient_id, 
                 action=action,
                 file_path=data.get('file_path', 'unknown'))
    
    # Forward file operation message to recipient
    if recipient_id:
        recipient_connection = await connection_pool.get(recipient_id)
        if recipient_connection:
            try:
                # Add sender_id to message
                forward_data = dict(data)
                forward_data['sender_id'] = client_id
                forward_data['request_id'] = correlation_id
                
                await recipient_connection.send(json.dumps(forward_data))
                await metrics_collector.record_message_sent('file_operation')
                
                # Acknowledge receipt
                await websocket.send(json.dumps({
                    'type': 'file_operation',
                    'action': 'sent',
                    'request_id': correlation_id,
                    'recipient_id': recipient_id,
                    'status': 'sent'
                }))
                return
            except Exception as e:
                logger.error(f"Error forwarding file operation message to {recipient_id}: {e}")
    
    # If this is a response to a file operation message, forward to original sender
    if data.get('controller_id'):
        controller_id = data.get('controller_id')
        controller_connection = await connection_pool.get(controller_id)
        
        if controller_connection:
            try:
                # Forward response to controller
                forward_data = dict(data)
                forward_data['sender_id'] = client_id
                
                await controller_connection.send(json.dumps(forward_data))
                await metrics_collector.record_message_sent('file_operation')
                return
            except Exception as e:
                logger.error(f"Error forwarding file operation response to {controller_id}: {e}")
    
    # If we get here, we couldn't deliver the message
    await websocket.send(json.dumps({
        'type': 'error',
        'request_id': correlation_id,
        'message': 'Could not deliver file operation message'
    }))

# Enhanced WebSocket handler with proper error handling and recovery
async def handle_client(websocket): # REMOVED path: str
    # ADD LOGGING: Check if function is called and what path is received
    try:
        # logger.info(f"handle_client called. Path: {path}, Websocket: {websocket.remote_address}") # REMOVED path from log
        logger.info(f"handle_client called. Websocket: {websocket.remote_address}") # UPDATED LOG
    except Exception as log_e:
        logger.error(f"Error logging handle_client entry: {log_e}") # Log potential errors during logging itself

    client_id = str(uuid.uuid4())
    client_ip = websocket.remote_address[0]
    correlation_id = str(uuid.uuid4())
    logger_context = {'correlation_id': correlation_id}
    
    logger.info(f"New connection from {client_ip}", extra=logger_context)
    await metrics_collector.record_connection()
    
    try:
        # Check IP blacklist
        if not await security_manager.check_ip(client_ip):
            logger.warning(f"Rejected connection from blacklisted IP: {client_ip}", extra=logger_context)
            await websocket.close(1008, "IP is blacklisted")
            return
        
        # Authentication with timeout
        try:
            async with asyncio.timeout(10):
                auth_message = await websocket.recv()
                auth_data = json.loads(auth_message)
                incoming_request_id = auth_data.get('request_id') # Store the ID from the client

                # Validate auth message
                if auth_data.get('type') != 'auth':
                    await security_manager.record_failed_attempt(
                        ip_address=client_ip,
                        details="Invalid authentication message type"
                    )
                    await websocket.close(1008, "Authentication failed")
                    return
                
                # Verify token if provided
                token = auth_data.get('token')
                if token:
                    token_data = security_manager.verify_token(token)
                    if token_data:
                        client_id = token_data['sub']
                        client_type = token_data.get('type', 'unknown')
                        
                        # Record successful authentication
                        await security_manager.record_successful_attempt(
                            ip_address=client_ip,
                            client_id=client_id,
                            user_agent=auth_data.get('user_agent')
                        )
                        
                        await metrics_collector.record_auth_success()
                    else:
                        # Token verification failed
                        await security_manager.record_failed_attempt(
                            ip_address=client_ip,
                            client_id=auth_data.get('client_id'),
                            details="Invalid token"
                        )
                        
                        await metrics_collector.record_auth_failure()
                        await websocket.close(1008, "Authentication failed")
                        return
                else:
                    # No token provided, check other auth methods
                    client_id = auth_data.get('client_id')
                    client_type = auth_data.get('client_type', 'unknown')
                    
                    if not client_id:
                        # Generate new client ID if not provided
                        client_id = str(uuid.uuid4())
                    
                    # In a production system, you would validate credentials here
                    # For this example, we'll accept the connection and generate a token
                    
                    # Record successful authentication
                    await security_manager.record_successful_attempt(
                        ip_address=client_ip,
                        client_id=client_id,
                        user_agent=auth_data.get('user_agent')
                    )
                    
                    await metrics_collector.record_auth_success()
        
        except asyncio.TimeoutError:
            logger.warning(f"Authentication timeout for {client_ip}", extra=logger_context)
            await websocket.close(1008, "Authentication timeout")
            return
        except json.JSONDecodeError:
            logger.warning(f"Invalid JSON in authentication message from {client_ip}", extra=logger_context)
            await security_manager.record_failed_attempt(
                ip_address=client_ip,
                details="Invalid JSON in authentication message"
            )
            await websocket.close(1008, "Invalid authentication message")
            return
        except Exception as e:
            logger.error(f"Authentication error for {client_ip}: {e}", extra=logger_context, exc_info=True)
            await security_manager.record_failed_attempt(
                ip_address=client_ip,
                details=f"Authentication error: {str(e)}"
            )
            await websocket.close(1008, "Authentication failed")
            return
        
        # Update logger context with client ID
        logger_context['correlation_id'] = f"{client_id}:{correlation_id}"
        
        # Register client in database
        await db_manager.register_client(
            client_id=client_id,
            client_type=client_type,
            metadata=auth_data.get('metadata', {})
        )
        
        # Add to connection pool
        await connection_pool.add(client_id, websocket)
        
        # Generate and send token
        token = security_manager.generate_token(
            client_id=client_id,
            client_type=client_type,
            additional_data=auth_data.get('metadata', {})
        )
        
        await websocket.send(json.dumps({
            'type': 'auth_response',
            'status': 'success',
            'client_id': client_id,
            'token': token,
            'expires_in': config.TOKEN_EXPIRY_SECONDS,
            'server_time': time.time(),
            'request_id': incoming_request_id or correlation_id # Use client's ID if available, else fallback
        }))

        logger.info(f"Client {client_id} authenticated successfully", extra=logger_context)
        
        # Check for queued messages
        queued_messages = await message_queue.dequeue_messages(client_id)
        if queued_messages:
            logger.info(f"Delivering {len(queued_messages)} queued messages to {client_id}", extra=logger_context)
            for message in queued_messages:
                await websocket.send(json.dumps(message))
                if message.get('message_id'):
                    await db_manager.mark_message_delivered(message['message_id'])
        
        # Main message loop
        try:
            while True:
                # Receive message with timeout
                message = await asyncio.wait_for(
                    websocket.recv(),
                    timeout=config.PING_INTERVAL * 2
                )
                
                # Parse message
                try:
                    # Parse message
                    if isinstance(message, str):
                        data = json.loads(message)
                    else:
                        data = decompress_message(message)
                    
                    # Process message
                    await process_message(websocket, data, client_id)
                    
                except json.JSONDecodeError:
                    logger.warning(f"Invalid JSON from {client_id}", extra=logger_context)
                    await websocket.send(json.dumps({
                        'type': 'error',
                        'message': 'Invalid JSON'
                    }))
                except Exception as e:
                    logger.error(f"Error processing message from {client_id}: {e}", extra=logger_context, exc_info=True)
                    await metrics_collector.record_message_error()
                    await websocket.send(json.dumps({
                        'type': 'error',
                        'message': 'Message processing failed'
                    }))
        
        except websockets.exceptions.ConnectionClosed as e:
            logger.info(f"Connection closed for client {client_id}: {e.code} {e.reason}", extra=logger_context)
        
    except Exception as e:
        logger.error(f"Error handling client {client_id}: {e}", extra=logger_context, exc_info=True)
        await metrics_collector.record_connection_error()
    
    finally:
        # Clean up
        await connection_pool.remove(client_id)
        await metrics_collector.record_disconnection()
        logger.info(f"Client {client_id} disconnected", extra=logger_context)

# Periodic tasks
async def setup_periodic_tasks():
    """Setup periodic tasks for server maintenance"""
    
    # Schedule DB backup and Security cleanup tasks (moved from __init__)
    db_manager._setup_backup_schedule()
    security_manager._setup_cleanup_task()
    
    # Cleanup idle connections
    async def cleanup_idle_connections():
        while True:
            try:
                await asyncio.sleep(60)  # Check every minute
                await connection_pool.cleanup_idle_connections(config.IDLE_TIMEOUT)
            except Exception as e:
                logger.error(f"Error cleaning up idle connections: {e}", exc_info=True)
    
    # Database maintenance
    async def database_maintenance():
        while True:
            try:
                await asyncio.sleep(3600)  # Run every hour
                await db_manager.cleanup_old_data()
            except Exception as e:
                logger.error(f"Error during database maintenance: {e}", exc_info=True)
    
    # Cache cleanup
    async def cache_cleanup():
        while True:
            try:
                await asyncio.sleep(300)  # Run every 5 minutes
                await message_queue.cleanup_expired_cache()
            except Exception as e:
                logger.error(f"Error during cache cleanup: {e}", exc_info=True)
    
    # Health check
    async def health_check_task():
        while True:
            try:
                await asyncio.sleep(config.HEALTH_CHECK_INTERVAL)
                health_status = await health_check()
                
                if health_status['status'] != 'ok':
                    logger.warning(f"Health check failed: {health_status}")
            except Exception as e:
                logger.error(f"Error during health check: {e}", exc_info=True)
    
    # Start tasks
    asyncio.create_task(cleanup_idle_connections())
    asyncio.create_task(database_maintenance())
    asyncio.create_task(cache_cleanup())
    asyncio.create_task(health_check_task())

# Health check endpoint
async def health_check():
    """Perform health check"""
    try:
        # Check database
        with db_manager.get_connection() as conn:
            conn.execute("SELECT 1")
        
        # Get metrics
        metrics = await metrics_collector.get_metrics()
        
        return {
            'status': 'ok',
            'version': '1.0.0',
            'uptime': time.time() - start_time,
            'connections': connection_pool.get_connection_count(),
            'metrics': metrics
        }
    except Exception as e:
        logger.error(f"Health check failed: {e}", exc_info=True)
        return {
            'status': 'error',
            'error': str(e)
        }

# New HTTP health check handler for websockets.serve
async def http_health_check_handler(path, request_headers):
    """
    Handles HTTP requests before WebSocket handshake.
    Specifically intercepts health checks (e.g., from Render).
    """
    logger.debug(f"http_health_check_handler called with path: {path}") # ADD LOGGING
    # Render's default health check path is often '/'
    if path == "/":
        logger.info(f"Handling HTTP health check for path: {path}") # ADD LOGGING
        # Return a simple HTTP 200 OK response
        headers = [('Content-Type', 'text/plain'), ('Content-Length', '2')]
        return (200, headers, b'OK')
    # Allow other requests to proceed to WebSocket handshake
    logger.debug(f"Path '{path}' not a health check, returning None for WebSocket handshake.") # ADD LOGGING
    return None

# Main server startup with proper signal handling
async def start_server():
    global start_time
    start_time = time.time()
    
    stop_event = asyncio.Event()
    
    def handle_shutdown(signum, frame):
        logger.info("Shutdown signal received")
        stop_event.set()
    
    signal.signal(signal.SIGTERM, handle_shutdown)
    signal.signal(signal.SIGINT, handle_shutdown)
    
    # Setup periodic tasks
    await setup_periodic_tasks()
    
    # Setup SSL context if WSS is enabled
    ssl_context = None
    if config.ENABLE_WSS:
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(config.SSL_CERT_PATH, config.SSL_KEY_PATH)
        ssl_context.verify_mode = ssl.CERT_NONE  # In production, consider using CERT_REQUIRED with proper CA
    
    # Start WebSocket server
    server = await websockets.serve(
        handle_client,
        config.HOST,
        config.PORT,
        ssl=ssl_context,
        process_request=http_health_check_handler, # Add this line
        max_size=config.MAX_REQUEST_SIZE,
        ping_interval=config.PING_INTERVAL,
        ping_timeout=config.PING_TIMEOUT,
        compression=None,  # We handle compression ourselves
        max_queue=1000
    )

    logger.info(f"WebSocket server started on {config.HOST}:{config.PORT}")
    
    # Wait for shutdown signal
    await stop_event.wait()
    
    # Cleanup
    server.close()
    await server.wait_closed()
    
    await cleanup()

async def cleanup():
    """Clean up resources before shutdown"""
    logger.info("Cleaning up resources...")
    
    # Disconnect all clients
    for client_id in list(connection_pool.connections.keys()):
        await connection_pool.remove(client_id)
    
    # Final database backup
    await db_manager.backup_database()
    
    logger.info("Cleanup complete")

if __name__ == "__main__":
    try:
        # Print banner
        print(f"""
        ╔═══════════════════════════════════════════╗
        ║           Relay Server v1.0.0             ║
        ╚═══════════════════════════════════════════╝
        """)
        
        # Log startup information
        logger.info(f"Starting Relay Server on {config.HOST}:{config.PORT}")
        logger.info(f"WSS Enabled: {config.ENABLE_WSS}")
        
        # Run server
        asyncio.run(start_server())
    except Exception as e:
        logger.critical(f"Server error: {e}", exc_info=True)
    finally:
        logging.shutdown()

