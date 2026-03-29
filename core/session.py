class InMemorySessionManager:
    def __init__(self, prekey_store):
        self.prekey_store = prekey_store
        self._sessions = {}

    def save_session(self, peer_id, ratchet):
        self._sessions[peer_id] = ratchet

    def load_session(self, peer_id):
        return self._sessions.get(peer_id)