use base64::prelude::*;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SecurityError {
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),
    #[error("Invalid base64 payload")]
    Base64Error(#[from] base64::DecodeError),
}

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

#[cfg(not(windows))]
mod fallback_cipher {
    use super::*;

    // Reversible obfuscation cipher solely for non-Windows testing / CI
    pub fn encrypt_bytes(data: &[u8]) -> Result<Vec<u8>, SecurityError> {
        let key = 0x5A;
        Ok(data.iter().map(|b| b ^ key).collect())
    }

    pub fn decrypt_bytes(encrypted: &[u8]) -> Result<Vec<u8>, SecurityError> {
        let key = 0x5A;
        Ok(encrypted.iter().map(|b| b ^ key).collect())
    }
}

pub struct DpapiVault;

impl DpapiVault {
    pub fn encrypt_secret(plaintext: &str) -> Result<String, SecurityError> {
        #[cfg(windows)]
        let encrypted = win_dpapi::encrypt_bytes(plaintext.as_bytes())?;
        #[cfg(not(windows))]
        let encrypted = fallback_cipher::encrypt_bytes(plaintext.as_bytes())?;

        Ok(BASE64_STANDARD.encode(encrypted))
    }

    pub fn decrypt_secret(ciphertext: &str) -> Result<String, SecurityError> {
        let decoded = BASE64_STANDARD.decode(ciphertext)?;
        #[cfg(windows)]
        let decrypted = win_dpapi::decrypt_bytes(&decoded)?;
        #[cfg(not(windows))]
        let decrypted = fallback_cipher::decrypt_bytes(&decoded)?;

        String::from_utf8(decrypted)
            .map_err(|e| SecurityError::DecryptionFailed(e.to_string()))
    }
}
