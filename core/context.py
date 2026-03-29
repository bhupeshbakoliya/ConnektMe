class AppContext:
    def __init__(self, keystore, client, server, session_manager, db):
        self.keystore = keystore
        self.client = client
        self.server = server
        self.session_manager = session_manager
        self.db = db

        self.contacts_repo = None
        self.current_peer = None