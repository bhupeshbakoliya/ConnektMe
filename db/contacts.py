class ContactsRepository:

    def __init__(self, db):
        self.db = db

    def add_contact(self, pubkey, nickname, ip, port):
        ip = ip.strip()

        if ip == "0.0.0.0":
            raise ValueError("Cannot store 0.0.0.0 as contact IP")

        try:
            port = int(port)
        except ValueError:
            raise ValueError("Port must be integer")

        if not (1 <= port <= 65535):
            raise ValueError("Invalid port range")

        with self.db as conn:
            conn.execute("""
                         INSERT OR IGNORE INTO contacts
                             (pubkey, nickname, local_ip, port, created_at)
                         VALUES (?, ?, ?, ?, strftime('%s', 'now'))
                         """, (pubkey.strip(), nickname.strip(), ip, port))


    def list_contacts(self):
        return self.db.fetchall("SELECT * FROM contacts")

    def get_contact(self, pubkey):
        return self.db.fetchone(
            "SELECT * FROM contacts WHERE pubkey=?",
            (pubkey,)
        )