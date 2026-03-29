from pathlib import Path
import time

from db.store import Database


# ==============================
# Setup Paths
# ==============================

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "data" / "messages.db"


# ==============================
# Test Function
# ==============================

def run_db_test():
    print("DB PATH:", DB_PATH)
    print("EXISTS DIR:", DB_PATH.parent.exists())

    db = Database(DB_PATH)
    db.connect()
    db.initialize_schema()

    print("✅ Database initialized")

    # ==============================
    # Test INSERT (contacts)
    # ==============================

    with db as conn:
        conn.execute(
            """
            INSERT INTO contacts (pubkey, nickname, created_at)
            VALUES (?, ?, ?)
            """,
            ("test_pubkey_123", "Alice", int(time.time()))
        )

    print("✅ Inserted contact")

    # ==============================
    # Test FETCH ONE
    # ==============================

    row = db.fetchone(
        "SELECT * FROM contacts WHERE pubkey=?",
        ("test_pubkey_123",)
    )

    assert row is not None, "❌ Fetchone failed"
    print("✅ Fetchone works:", row["nickname"])

    # ==============================
    # Test FETCH ALL
    # ==============================

    rows = db.fetchall("SELECT * FROM contacts")

    assert len(rows) > 0, "❌ Fetchall failed"
    print(f"✅ Fetchall works: {len(rows)} rows")

    # ==============================
    # Test TRANSACTION ROLLBACK
    # ==============================

    try:
        with db as conn:
            conn.execute(
                "INSERT INTO contacts (pubkey) VALUES (?)",
                ("duplicate_test",)
            )
            conn.execute(
                "INSERT INTO contacts (pubkey) VALUES (?)",
                ("duplicate_test",)  # duplicate → should fail
            )
    except Exception:
        print("✅ Rollback triggered correctly")

    # Verify rollback
    row = db.fetchone(
        "SELECT * FROM contacts WHERE pubkey=?",
        ("duplicate_test",)
    )

    assert row is None, "❌ Rollback failed"
    print("✅ Rollback verified")

    db.close()
    print("🎉 ALL DB TESTS PASSED")


# ==============================
# Entry Point
# ==============================

if __name__ == "__main__":
    run_db_test()