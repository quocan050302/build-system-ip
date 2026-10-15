use super::SecurityError;
use std::process::Command;

pub struct MacOsKeychainSecretStore {
    service_name: String,
}

impl MacOsKeychainSecretStore {
    pub fn new() -> Self {
        Self {
            service_name: "YouTubeIsolationManager".to_string(),
        }
    }

    pub fn with_service(service_name: &str) -> Self {
        Self {
            service_name: service_name.to_string(),
        }
    }

    pub fn store_secret(&self, key: &str, secret: &str) -> Result<String, SecurityError> {
        let clean_key = if key.is_empty() {
            format!("ep-secret-{}", uuid::Uuid::new_v4())
        } else {
            key.to_string()
        };

        // Invoke /usr/bin/security add-generic-password -a <account> -s <service> -w <password> -U
        let output = Command::new("/usr/bin/security")
            .args([
                "add-generic-password",
                "-a",
                &clean_key,
                "-s",
                &self.service_name,
                "-w",
                secret,
                "-U",
            ])
            .output()
            .map_err(|e| SecurityError::EncryptionFailed(format!("Failed to execute security CLI: {}", e)))?;

        if !output.status.success() {
            let err = String::from_utf8_lossy(&output.stderr);
            return Err(SecurityError::EncryptionFailed(format!(
                "macOS Keychain store failed: {}",
                err.trim()
            )));
        }

        Ok(format!("keychain:{}", clean_key))
    }

    pub fn retrieve_secret(&self, reference: &str) -> Result<String, SecurityError> {
        let key = if let Some(stripped) = reference.strip_prefix("keychain:") {
            stripped
        } else {
            reference
        };

        let output = Command::new("/usr/bin/security")
            .args([
                "find-generic-password",
                "-a",
                key,
                "-s",
                &self.service_name,
                "-w",
            ])
            .output()
            .map_err(|e| SecurityError::DecryptionFailed(format!("Failed to query macOS Keychain: {}", e)))?;

        if !output.status.success() {
            let err = String::from_utf8_lossy(&output.stderr);
            return Err(SecurityError::DecryptionFailed(format!(
                "macOS Keychain secret retrieval failed for key '{}': {}",
                key,
                err.trim()
            )));
        }

        let pass = String::from_utf8_lossy(&output.stdout).trim_end_matches(['\r', '\n']).to_string();
        Ok(pass)
    }

    pub fn delete_secret(&self, reference: &str) -> Result<(), SecurityError> {
        let key = if let Some(stripped) = reference.strip_prefix("keychain:") {
            stripped
        } else {
            reference
        };

        let output = Command::new("/usr/bin/security")
            .args([
                "delete-generic-password",
                "-a",
                key,
                "-s",
                &self.service_name,
            ])
            .output()
            .map_err(|e| SecurityError::DecryptionFailed(format!("Failed to delete Keychain item: {}", e)))?;

        if !output.status.success() {
            let err = String::from_utf8_lossy(&output.stderr);
            // Ignore item not found
            if !err.contains("could not be found") {
                return Err(SecurityError::DecryptionFailed(format!(
                    "Keychain delete failed: {}",
                    err.trim()
                )));
            }
        }

        Ok(())
    }

    pub fn test_vault(&self) -> Result<bool, SecurityError> {
        let test_key = "test-vault-probe-key";
        let test_val = "test-token-keychain-2026";

        self.store_secret(test_key, test_val)?;
        let retrieved = self.retrieve_secret(&format!("keychain:{}", test_key))?;
        let _ = self.delete_secret(test_key);

        Ok(retrieved == test_val)
    }
}

impl super::SecretStore for MacOsKeychainSecretStore {
    fn store_secret(&self, key: &str, secret: &str) -> Result<String, SecurityError> {
        self.store_secret(key, secret)
    }

    fn retrieve_secret(&self, reference: &str) -> Result<String, SecurityError> {
        self.retrieve_secret(reference)
    }

    fn delete_secret(&self, reference: &str) -> Result<(), SecurityError> {
        self.delete_secret(reference)
    }

    fn test_vault(&self) -> Result<bool, SecurityError> {
        self.test_vault()
    }

    fn provider_name(&self) -> &'static str {
        "macOS Keychain"
    }
}
