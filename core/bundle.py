class LocalBundleProvider:
    def __init__(self):
        self._bundles = {}

    def register(self, peer_id, bundle):
        self._bundles[peer_id] = bundle

    def get_peer_bundle(self, peer_id):
        if peer_id not in self._bundles:
            raise KeyError("Bundle not found")
        return self._bundles[peer_id]