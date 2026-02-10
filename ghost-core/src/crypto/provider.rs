use openmls_rust_crypto::OpenMlsRustCrypto;

/// Holds the OpenMLS crypto backend and in-memory key storage.
pub struct GhostProvider {
    inner: OpenMlsRustCrypto,
}

impl GhostProvider {
    pub fn new() -> Self {
        Self {
            inner: OpenMlsRustCrypto::default(),
        }
    }

    pub fn inner(&self) -> &OpenMlsRustCrypto {
        &self.inner
    }
}

impl Default for GhostProvider {
    fn default() -> Self {
        Self::new()
    }
}
