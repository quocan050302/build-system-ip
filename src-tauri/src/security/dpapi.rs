use super::{SecretStore, SecurityError};
#[allow(unused_imports)]
use base64::prelude::*;

#[cfg(windows)]
mod win_dpapi {
    use super::*;
    use std::ptr::null_mut;
    use windows::Win32::Foundation::LocalFree;
    use windows::Win32::Security::Cryptography::{
        CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    pub fn encrypt_bytes(data: &[u8]) -> Result<Vec<u8>, SecurityError> {
        unsafe {
            let mut input_blob = CRYPT_INTEGER_BLOB {
                cbData: data.len() as u32,
                pbData: data.as_ptr() as *mut u8,
            };
            let mut output_blob = CRYPT_INTEGER_BLOB {
                cbData: 0,
                pbData: null_mut(),
            };

            CryptProtectData(
                &mut input_blob,
                None,
                None,
                None,
                None,
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output_blob,
            )
            .map_err(|e| SecurityError::EncryptionFailed(format!("CryptProtectData failed: {}", e)))?;

            let result = std::slice::from_raw_parts(output_blob.pbData, output_blob.cbData as usize)
                .to_vec();

            let _ = LocalFree(windows::Win32::Foundation::HLOCAL(output_blob.pbData as _));

            Ok(result)
        }
    }

    pub fn decrypt_bytes(encrypted: &[u8]) -> Result<Vec<u8>, SecurityError> {
        unsafe {
            let mut input_blob = CRYPT_INTEGER_BLOB {
                cbData: encrypted.len() as u32,
                pbData: encrypted.as_ptr() as *mut u8,
            };
            let mut output_blob = CRYPT_INTEGER_BLOB {
                cbData: 0,
                pbData: null_mut(),
            };

            CryptUnprotectData(
                &mut input_blob,
                None,
                None,
                None,
                None,
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output_blob,
            )
            .map_err(|e| SecurityError::DecryptionFailed(format!("CryptUnprotectData failed: {}", e)))?;

            let result = std::slice::from_raw_parts(output_blob.pbData, output_blob.cbData as usize)
                .to_vec();

            let _ = LocalFree(windows::Win32::Foundation::HLOCAL(output_blob.pbData as _));

            Ok(result)
        }
    }
}

pub struct WindowsDpapiSecretStore;

impl WindowsDpapiSecretStore {
    pub fn new() -> Self {
        Self
    }
}

impl SecretStore for WindowsDpapiSecretStore {
    fn store_secret(&self, _key: &str, secret: &str) -> Result<String, SecurityError> {
        #[cfg(windows)]
        {
            let encrypted = win_dpapi::encrypt_bytes(secret.as_bytes())?;
            Ok(BASE64_STANDARD.encode(encrypted))
        }

        #[cfg(not(windows))]
        {
            let _ = secret;
            Err(SecurityError::EncryptionFailed(
                "Windows DPAPI is only supported on Windows hosts".to_string(),
            ))
        }
    }

    fn retrieve_secret(&self, reference: &str) -> Result<String, SecurityError> {
        #[cfg(windows)]
        {
            let decoded = BASE64_STANDARD.decode(reference)?;
            let decrypted = win_dpapi::decrypt_bytes(&decoded)?;
            String::from_utf8(decrypted)
                .map_err(|e| SecurityError::DecryptionFailed(e.to_string()))
        }

        #[cfg(not(windows))]
        {
            let _ = reference;
            Err(SecurityError::DecryptionFailed(
                "Windows DPAPI is only supported on Windows hosts".to_string(),
            ))
        }
    }

    fn delete_secret(&self, _reference: &str) -> Result<(), SecurityError> {
        // DPAPI ciphertexts are self-contained; deletion from DB removes the ciphertext
        Ok(())
    }

    fn test_vault(&self) -> Result<bool, SecurityError> {
        #[cfg(windows)]
        {
            let test_val = "test-secret-youtube-isolation-2026";
            let enc = self.store_secret("probe", test_val)?;
            let dec = self.retrieve_secret(&enc)?;
            Ok(dec == test_val)
        }

        #[cfg(not(windows))]
        {
            Ok(false)
        }
    }

    fn provider_name(&self) -> &'static str {
        "Windows DPAPI"
    }
}

/// Backward-compatible vault facade that delegates to the active cross-platform SecretStore
pub struct DpapiVault;

impl DpapiVault {
    pub fn encrypt_secret(plaintext: &str) -> Result<String, SecurityError> {
        let store = super::get_secret_store();
        store.store_secret("", plaintext)
    }

    pub fn decrypt_secret(ciphertext: &str) -> Result<String, SecurityError> {
        let store = super::get_secret_store();
        store.retrieve_secret(ciphertext)
    }

    pub fn test_vault() -> Result<bool, SecurityError> {
        let store = super::get_secret_store();
        store.test_vault()
    }
}
