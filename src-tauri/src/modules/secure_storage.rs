// Cyber Security Prime - Secure Storage Module
// Uses OS keychain/credential manager for secure API key storage
// Windows: Credential Manager
// macOS: Keychain
// Linux: Secret Service API (libsecret)

use keyring::Entry;
use thiserror::Error;

const SERVICE_NAME: &str = "com.cybersecurityprime.app";
const OLLAMA_API_KEY: &str = "ollama_api_key";
const MISTRAL_API_KEY: &str = "mistral_api_key";

#[derive(Debug, Error)]
pub enum SecureStorageError {
    #[error("Failed to create keyring entry: {0}")]
    KeyringError(String),
    #[error("API key not found")]
    NotFound,
    #[error("Failed to delete API key: {0}")]
    DeleteError(String),
}

/// Store an API key securely in the OS keychain
pub fn store_api_key(key_name: &str, api_key: &str) -> Result<(), SecureStorageError> {
    let entry = Entry::new(SERVICE_NAME, key_name)
        .map_err(|e| SecureStorageError::KeyringError(format!("Failed to create entry: {}", e)))?;
    
    entry.set_password(api_key)
        .map_err(|e| SecureStorageError::KeyringError(format!("Failed to store key: {}", e)))?;
    
    Ok(())
}

/// Retrieve an API key from the OS keychain
pub fn get_api_key(key_name: &str) -> Result<String, SecureStorageError> {
    let entry = Entry::new(SERVICE_NAME, key_name)
        .map_err(|e: keyring::Error| SecureStorageError::KeyringError(format!("Failed to create entry: {}", e)))?;
    
    entry.get_password()
        .map_err(|e: keyring::Error| {
            // Check if it's a "not found" error
            let error_str = e.to_string().to_lowercase();
            if error_str.contains("not found") || error_str.contains("no such") {
                SecureStorageError::NotFound
            } else {
                SecureStorageError::KeyringError(format!("Failed to retrieve key: {}", e))
            }
        })
}

/// Delete an API key from the OS keychain
pub fn delete_api_key(key_name: &str) -> Result<(), SecureStorageError> {
    let entry = Entry::new(SERVICE_NAME, key_name)
        .map_err(|e| SecureStorageError::KeyringError(format!("Failed to create entry: {}", e)))?;
    
    entry.delete_password()
        .map_err(|e| SecureStorageError::DeleteError(format!("Failed to delete key: {}", e)))?;
    
    Ok(())
}

/// Check if an API key exists in the OS keychain
pub fn api_key_exists(key_name: &str) -> bool {
    get_api_key(key_name).is_ok()
}

// Convenience functions for Ollama API key
pub fn store_ollama_api_key(api_key: &str) -> Result<(), SecureStorageError> {
    store_api_key(OLLAMA_API_KEY, api_key)
}

pub fn get_ollama_api_key() -> Result<String, SecureStorageError> {
    get_api_key(OLLAMA_API_KEY)
}

pub fn delete_ollama_api_key() -> Result<(), SecureStorageError> {
    delete_api_key(OLLAMA_API_KEY)
}

pub fn ollama_api_key_exists() -> bool {
    api_key_exists(OLLAMA_API_KEY)
}

// Convenience functions for Mistral API key (direct api.mistral.ai)
pub fn store_mistral_api_key(api_key: &str) -> Result<(), SecureStorageError> {
    store_api_key(MISTRAL_API_KEY, api_key)
}

pub fn get_mistral_api_key() -> Result<String, SecureStorageError> {
    get_api_key(MISTRAL_API_KEY)
}

pub fn delete_mistral_api_key() -> Result<(), SecureStorageError> {
    delete_api_key(MISTRAL_API_KEY)
}

pub fn mistral_api_key_exists() -> bool {
    api_key_exists(MISTRAL_API_KEY)
}
