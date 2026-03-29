from pathlib import Path
import sqlite3
from typing import Any, List, Optional, Dict


# ==============================
# Database Wrapper
# ==============================

class Database:

    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.conn: Optional[sqlite3.Connection] = None

    # ==============================
    # Connection
    # ==============================

    def connect(self) -> None:
        self.conn = sqlite3.connect(
            self.db_path,
            check_same_thread=False
        )
        self.conn.row_factory = sqlite3.Row

        # PRAGMAs
        self.conn.execute("PRAGMA journal_mode=WAL;")
        self.conn.execute("PRAGMA foreign_keys=ON;")

    # ==============================
    # Schema Initialization
    # ==============================

    def initialize_schema(self) -> None:
        with self as conn:

            # Schema versioning
            conn.execute("""
                CREATE TABLE IF NOT EXISTS schema_version (
                    version INTEGER PRIMARY KEY
                )
            """)

            # Contacts
            conn.execute("""
                CREATE TABLE IF NOT EXISTS contacts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    pubkey TEXT UNIQUE,
                    nickname TEXT,
                    local_ip TEXT,
                    public_ip TEXT,
                    port INTEGER,
                    last_seen INTEGER,
                    created_at INTEGER
                )
            """)

            # Sessions
            conn.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    peer_pubkey TEXT PRIMARY KEY,
                    ratchet_state_blob BLOB,
                    updated_at INTEGER
                )
            """)

            # Messages
            conn.execute("""
                CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    peer_pubkey TEXT,
                    direction TEXT,
                    plaintext TEXT,
                    timestamp INTEGER,
                    msg_id TEXT,
                    ttl_expires_at INTEGER,
                    is_one_time INTEGER,
                    opened INTEGER
                )
            """)

            # Prekeys
            conn.execute("""
                CREATE TABLE IF NOT EXISTS prekeys (
                    pubkey_hex TEXT PRIMARY KEY,
                    private_key_blob BLOB,
                    used INTEGER,
                    created_at INTEGER
                )
            """)

            # Signed Prekey
            conn.execute("""
                CREATE TABLE IF NOT EXISTS signed_prekey (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    pubkey_hex TEXT,
                    private_key_blob BLOB,
                    signature BLOB,
                    created_at INTEGER
                )
            """)

            # Initialize schema version if empty
            row = conn.execute("SELECT COUNT(*) as count FROM schema_version").fetchone()
            if row["count"] == 0:
                conn.execute("INSERT INTO schema_version (version) VALUES (1)")

    # ==============================
    # Query Helpers
    # ==============================

    def execute(self, sql: str, params: tuple = ()) -> sqlite3.Cursor:
        return self.conn.execute(sql, params)

    def fetchone(self, sql: str, params: tuple = ()) -> Optional[Dict[str, Any]]:
        cursor = self.conn.execute(sql, params)
        row = cursor.fetchone()
        return dict(row) if row else None

    def fetchall(self, sql: str, params: tuple = ()) -> List[Dict[str, Any]]:
        cursor = self.conn.execute(sql, params)
        rows = cursor.fetchall()
        return [dict(r) for r in rows]

    # ==============================
    # Context Manager (Transactions)
    # ==============================

    def __enter__(self):
        if self.conn is None:
            raise RuntimeError("Database not connected")

        self.conn.execute("BEGIN")
        return self.conn

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is None:
            self.conn.commit()
        else:
            self.conn.rollback()

    # ==============================
    # Close
    # ==============================

    def close(self) -> None:
        if self.conn:
            self.conn.close()
            self.conn = None