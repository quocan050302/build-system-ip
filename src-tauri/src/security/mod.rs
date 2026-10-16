pub mod dpapi;
pub mod keychain;
pub mod redaction;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SecurityError {
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),
    #[error("Invalid base64 payload")]
    Base64Error(#[from] base64::DecodeError),
    #[error("Unsupported security provider: {0}")]
    UnsupportedProvider(String),
}

pub trait SecretStore: Send + Sync {
    fn store_secret(&self, key: &str, secret: &str) -> Result<String, SecurityError>;
    fn retrieve_secret(&self, reference: &str) -> Result<String, SecurityError>;
    fn delete_secret(&self, reference: &str) -> Result<(), SecurityError>;
    fn test_vault(&self) -> Result<bool, SecurityError>;
    fn provider_name(&self) -> &'static str;
}

pub struct MockSecretStore {
    storage: Mutex<HashMap<String, String>>,
}

impl MockSecretStore {
    pub fn new() -> Self {
        Self {
            storage: Mutex::new(HashMap::new()),
        }
    }
}

impl SecretStore for MockSecretStore {
    fn store_secret(&self, key: &str, secret: &str) -> Result<String, SecurityError> {
        let id = if key.is_empty() {
            format!("mock-sec-{}", uuid::Uuid::new_v4())
        } else {
            key.to_string()
        };
        let mut map = self.storage.lock().unwrap();
        map.insert(id.clone(), secret.to_string());
        Ok(format!("mock:{}", id))
    }

    fn retrieve_secret(&self, reference: &str) -> Result<String, SecurityError> {
        let id = reference.strip_prefix("mock:").unwrap_or(reference);
        let map = self.storage.lock().unwrap();
        map.get(id)
            .cloned()
            .ok_or_else(|| SecurityError::DecryptionFailed(format!("Mock secret not found: {}", id)))
    }

    fn delete_secret(&self, reference: &str) -> Result<(), SecurityError> {
        let id = reference.strip_prefix("mock:").unwrap_or(reference);
        let mut map = self.storage.lock().unwrap();
        map.remove(id);
        Ok(())
    }

    fn test_vault(&self) -> Result<bool, SecurityError> {
        Ok(true)
    }

    fn provider_name(&self) -> &'static str {
        "Mock Secret Store"
    }
}

pub fn get_secret_store() -> Arc<dyn SecretStore> {
    #[cfg(target_os = "macos")]
    {
        Arc::new(keychain::MacOsKeychainSecretStore::new())
    }

    #[cfg(windows)]
    {
        Arc::new(dpapi::WindowsDpapiSecretStore::new())
    }

    #[cfg(not(any(target_os = "macos", windows)))]
    {
        Arc::new(MockSecretStore::new())
    }
}
