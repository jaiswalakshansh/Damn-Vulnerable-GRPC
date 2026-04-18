"""
Database initialization and helpers for DVGRPC.
Uses SQLite for portability.
"""

import os
import sqlite3

import bcrypt

from server.config import ADMIN_EMAIL, ADMIN_PASSWORD, ADMIN_USERNAME, DB_PATH, FLAGS


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db() -> None:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = get_db()
    _create_schema(conn)
    _seed_data(conn)
    conn.close()


def _create_schema(conn: sqlite3.Connection) -> None:
    cursor = conn.cursor()

    cursor.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT    UNIQUE NOT NULL,
            password TEXT    NOT NULL,
            email    TEXT,
            role     TEXT    DEFAULT 'user',
            bio      TEXT    DEFAULT '',
            secret   TEXT    DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS products (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT    NOT NULL,
            description TEXT,
            price       REAL,
            category    TEXT
        );

        CREATE TABLE IF NOT EXISTS notes (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            title      TEXT    NOT NULL,
            content    TEXT,
            owner_id   INTEGER,
            is_private INTEGER DEFAULT 1
        );

        -- VULNERABILITY [VULN-3]: This table is discoverable via SQL injection
        CREATE TABLE IF NOT EXISTS flags (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            challenge TEXT    UNIQUE,
            flag      TEXT,
            hint      TEXT
        );

        -- Internal secrets — also discoverable via SQLi
        CREATE TABLE IF NOT EXISTS secrets (
            id    INTEGER PRIMARY KEY AUTOINCREMENT,
            key   TEXT    UNIQUE,
            value TEXT
        );
    """)
    conn.commit()


def _seed_data(conn: sqlite3.Connection) -> None:
    cursor = conn.cursor()

    # ---- Admin user ----
    admin_hash = bcrypt.hashpw(ADMIN_PASSWORD.encode(), bcrypt.gensalt()).decode()
    cursor.execute(
        "INSERT OR IGNORE INTO users (username, password, email, role, bio, secret) "
        "VALUES (?,?,?,'admin','I am the system administrator.',?)",
        (ADMIN_USERNAME, admin_hash, ADMIN_EMAIL, FLAGS["idor"]),
    )

    # ---- Regular users ----
    regular_users = [
        ("alice", "alice123", "alice@dvgrpc.local", "user", "Hello, I'm Alice!"),
        ("bob", "b0bpassw0rd", "bob@dvgrpc.local", "user", "Just a regular user."),
        ("charlie", "charlie_pass", "charlie@dvgrpc.local", "user", "Nothing to see here."),
        ("dave", "dave1234", "dave@dvgrpc.local", "moderator", "I help moderate things."),
    ]
    for uname, pwd, email, role, bio in regular_users:
        pw_hash = bcrypt.hashpw(pwd.encode(), bcrypt.gensalt()).decode()
        cursor.execute(
            "INSERT OR IGNORE INTO users (username, password, email, role, bio) " "VALUES (?,?,?,?,?)",
            (uname, pw_hash, email, role, bio),
        )

    # ---- Products ----
    products = [
        ("gRPC Security Handbook", "Complete guide to gRPC penetration testing", 29.99, "books"),
        ("Protocol Buffers Deep Dive", "Master protobuf serialization and attacks", 24.99, "books"),
        ("Microservices Attack Patterns", "Real-world microservices exploitation", 34.99, "books"),
        ("DVGRPC Challenge USB", "USB drive preloaded with CTF tooling", 49.99, "hardware"),
        ("gRPC Fuzzer Pro", "Automated gRPC security fuzzing toolkit", 99.99, "software"),
        ("Hack gRPC T-Shirt", "Show your love for vulnerable gRPC apps", 19.99, "clothing"),
        # VULNERABILITY [VULN-13]: hidden "premium" item, only reachable by
        # abusing PaginatedSearch with a negative per_page.
        ("[PREMIUM] Dev kit", f"Gated product — {FLAGS['integer_overflow']}", 999.0, "premium"),
    ]
    for name, desc, price, cat in products:
        cursor.execute(
            "INSERT OR IGNORE INTO products (name, description, price, category) " "VALUES (?,?,?,?)",
            (name, desc, price, cat),
        )

    # ---- Notes (IDOR targets) ----
    cursor.execute("SELECT id FROM users WHERE username=?", (ADMIN_USERNAME,))
    admin = cursor.fetchone()
    if admin:
        cursor.execute(
            "INSERT OR IGNORE INTO notes (id, title, content, owner_id, is_private) " "VALUES (1,?,?,?,1)",
            ("Admin Secret Note", f"IDOR Flag: {FLAGS['idor']}", admin["id"]),
        )
        cursor.execute(
            "INSERT OR IGNORE INTO notes (title, content, owner_id, is_private) " "VALUES (?,?,?,0)",
            ("Public Announcement", "Server maintenance scheduled for Sunday.", admin["id"]),
        )

    cursor.execute("SELECT id FROM users WHERE username='alice'")
    alice = cursor.fetchone()
    if alice:
        cursor.execute(
            "INSERT OR IGNORE INTO notes (title, content, owner_id, is_private) " "VALUES (?,?,?,1)",
            ("Alice's Diary", "Dear diary, today I learned about gRPC vulnerabilities...", alice["id"]),
        )

    cursor.execute("SELECT id FROM users WHERE username='bob'")
    bob = cursor.fetchone()
    if bob:
        cursor.execute(
            "INSERT OR IGNORE INTO notes (title, content, owner_id, is_private) " "VALUES (?,?,?,1)",
            ("Bob's TODO", "1. Learn gRPC  2. Find all flags  3. ???  4. Profit", bob["id"]),
        )

    # ---- Flags table (discoverable via SQL injection) ----
    for challenge, flag in FLAGS.items():
        hint_map = {
            "reflection": "Have you tried grpcurl --plaintext localhost:50051 list?",
            "unauthenticated_admin": "Some services skip authentication entirely.",
            "sql_injection": "Try a UNION SELECT in the product search query.",
            "jwt_confusion": "What happens if you sign an RS256 JWT with HS256 + the public key?",
            "idor": "What's in user_id=1's secret field?",
            "path_traversal": "The uploads folder is not your boundary.",
            "command_injection": "Semicolons are powerful in shell commands.",
            "mass_assignment": "Read the proto carefully — are all fields validated?",
            "metadata_bypass": "Check the server interceptor source for special headers.",
            "hardcoded_creds": "Read config.py — developers love shortcuts.",
            "crypto_ecb": "Encrypt the same block twice and compare.",
            "crypto_forge": "HMAC with a known prefix is weaker than you think.",
        }
        cursor.execute(
            "INSERT OR IGNORE INTO flags (challenge, flag, hint) VALUES (?,?,?)",
            (challenge, flag, hint_map.get(challenge, "No hint.")),
        )

    # ---- Internal secrets (extra SQLi loot) ----
    from server.config import INTERNAL_SERVICE_VALUE, JWT_SECRET

    secrets = [
        ("jwt_secret", JWT_SECRET),
        ("bypass_header", INTERNAL_SERVICE_VALUE),
        ("db_admin_note", "Remember to rotate these secrets before going to prod!"),
    ]
    for key, value in secrets:
        cursor.execute("INSERT OR IGNORE INTO secrets (key, value) VALUES (?,?)", (key, value))

    conn.commit()
