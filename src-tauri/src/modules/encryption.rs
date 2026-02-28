// Cyber Security Prime - Encryption Module
// Provides file and folder encryption capabilities using AES-256-GCM

use crate::utils::generate_id;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use chrono::{DateTime, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::fs;
use std::path::{Path, PathBuf};

const MAGIC: &[u8; 8] = b"SPRIME01";
const SALT_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;
const PBKDF2_ITERATIONS: u32 = 100_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionResult {
    pub success: bool,
    pub file_path: String,
    pub encrypted_path: String,
    pub original_size: u64,
    pub encrypted_size: u64,
    pub algorithm: String,
    pub encrypted_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptionResult {
    pub success: bool,
    pub encrypted_path: String,
    pub decrypted_path: String,
    pub decrypted_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedFile {
    pub id: String,
    pub original_name: String,
    pub encrypted_path: String,
    pub original_size: u64,
    pub encrypted_size: u64,
    pub algorithm: String,
    pub encrypted_at: DateTime<Utc>,
    pub last_accessed: Option<DateTime<Utc>>,
}

// ============================================================================
// Internal: Key derivation & metadata persistence
// ============================================================================

fn derive_key(password: &str, salt: &[u8]) -> [u8; KEY_LEN] {
    let mut key = [0u8; KEY_LEN];
    pbkdf2::pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, PBKDF2_ITERATIONS, &mut key);
    key
}

fn metadata_dir() -> PathBuf {
    let base = if cfg!(windows) {
        std::env::var("APPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("."))
    } else {
        std::env::var("HOME")
            .map(|h| PathBuf::from(h).join(".config"))
            .unwrap_or_else(|_| PathBuf::from("."))
    };
    base.join("CyberSecurityPrime")
}

fn metadata_file() -> PathBuf {
    metadata_dir().join("encrypted_files.json")
}

#[derive(Serialize, Deserialize, Default)]
struct EncryptionMetadata {
    files: Vec<EncryptedFile>,
}

fn load_metadata() -> EncryptionMetadata {
    let path = metadata_file();
    if path.exists() {
        fs::read_to_string(&path)
            .ok()
            .and_then(|data| serde_json::from_str(&data).ok())
            .unwrap_or_default()
    } else {
        EncryptionMetadata::default()
    }
}

fn save_metadata(metadata: &EncryptionMetadata) -> Result<(), String> {
    let dir = metadata_dir();
    fs::create_dir_all(&dir)
        .map_err(|e| format!("Failed to create metadata directory: {}", e))?;
    let json = serde_json::to_string_pretty(metadata)
        .map_err(|e| format!("Failed to serialize metadata: {}", e))?;
    fs::write(metadata_file(), json)
        .map_err(|e| format!("Failed to write metadata: {}", e))
}

// ============================================================================
// Core: Encrypt / Decrypt / List / Remove
// ============================================================================

/// Encrypt a file with AES-256-GCM.
///
/// File format: [magic 8B][salt 32B][nonce 12B][ciphertext+tag ...]
pub fn encrypt_file(file_path: &str, password: &str) -> Result<EncryptionResult, String> {
    let src = Path::new(file_path);
    if !src.exists() {
        return Err(format!("File not found: {}", file_path));
    }

    let plaintext =
        fs::read(src).map_err(|e| format!("Failed to read source file: {}", e))?;
    let original_size = plaintext.len() as u64;

    let mut salt = [0u8; SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    let key = derive_key(password, &salt);

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| format!("Cipher init failed: {}", e))?;
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|e| format!("Encryption failed: {}", e))?;

    let mut output =
        Vec::with_capacity(MAGIC.len() + SALT_LEN + NONCE_LEN + ciphertext.len());
    output.extend_from_slice(MAGIC);
    output.extend_from_slice(&salt);
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);

    let encrypted_path = format!("{}.enc", file_path);
    let encrypted_size = output.len() as u64;

    fs::write(&encrypted_path, &output)
        .map_err(|e| format!("Failed to write encrypted file: {}", e))?;

    let original_name = src
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| file_path.to_string());

    let now = Utc::now();
    let mut metadata = load_metadata();
    metadata.files.push(EncryptedFile {
        id: generate_id(),
        original_name,
        encrypted_path: encrypted_path.clone(),
        original_size,
        encrypted_size,
        algorithm: "AES-256-GCM".to_string(),
        encrypted_at: now,
        last_accessed: None,
    });
    save_metadata(&metadata)?;

    Ok(EncryptionResult {
        success: true,
        file_path: file_path.to_string(),
        encrypted_path,
        original_size,
        encrypted_size,
        algorithm: "AES-256-GCM".to_string(),
        encrypted_at: now,
    })
}

/// Decrypt a `.enc` file previously created by `encrypt_file`.
pub fn decrypt_file(file_path: &str, password: &str) -> Result<DecryptionResult, String> {
    let src = Path::new(file_path);
    if !src.exists() {
        return Err(format!("Encrypted file not found: {}", file_path));
    }

    let data =
        fs::read(src).map_err(|e| format!("Failed to read encrypted file: {}", e))?;

    let header_len = MAGIC.len() + SALT_LEN + NONCE_LEN;
    if data.len() < header_len + 16 {
        return Err("Invalid encrypted file: too short".to_string());
    }

    if &data[..MAGIC.len()] != MAGIC {
        return Err("Not a SecurityPrime encrypted file".to_string());
    }

    let salt = &data[MAGIC.len()..MAGIC.len() + SALT_LEN];
    let nonce_bytes = &data[MAGIC.len() + SALT_LEN..header_len];
    let ciphertext = &data[header_len..];

    let key = derive_key(password, salt);
    let nonce = Nonce::from_slice(nonce_bytes);

    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| format!("Cipher init failed: {}", e))?;
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "Decryption failed: wrong password or corrupted file".to_string())?;

    let decrypted_path = if file_path.ends_with(".enc") {
        file_path[..file_path.len() - 4].to_string()
    } else {
        format!("{}.decrypted", file_path)
    };

    fs::write(&decrypted_path, &plaintext)
        .map_err(|e| format!("Failed to write decrypted file: {}", e))?;

    let mut metadata = load_metadata();
    metadata.files.retain(|f| f.encrypted_path != file_path);
    save_metadata(&metadata)?;

    Ok(DecryptionResult {
        success: true,
        encrypted_path: file_path.to_string(),
        decrypted_path,
        decrypted_at: Utc::now(),
    })
}

/// Return tracked encrypted files that still exist on disk.
pub fn get_encrypted_files() -> Result<Vec<EncryptedFile>, String> {
    let metadata = load_metadata();
    let files = metadata
        .files
        .into_iter()
        .filter(|f| Path::new(&f.encrypted_path).exists())
        .collect();
    Ok(files)
}

/// Remove an encrypted file entry (and optionally the .enc file on disk).
pub fn remove_encrypted_file(file_id: &str, delete_file: bool) -> Result<(), String> {
    let mut metadata = load_metadata();

    let entry = metadata
        .files
        .iter()
        .find(|f| f.id == file_id)
        .ok_or_else(|| "File not found in records".to_string())?;

    if delete_file {
        let p = Path::new(&entry.encrypted_path);
        if p.exists() {
            fs::remove_file(p)
                .map_err(|e| format!("Failed to delete encrypted file: {}", e))?;
        }
    }

    metadata.files.retain(|f| f.id != file_id);
    save_metadata(&metadata)
}

// ============================================================================
// Key Export / Import
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyExport {
    pub version: String,
    pub exported_at: String,
    pub key_id: String,
    pub encrypted_key: String,
    pub algorithm: String,
    pub salt: String,
    pub iterations: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyImportResult {
    pub success: bool,
    pub key_id: String,
    pub message: String,
}

/// Export a randomly-generated master key, wrapped (encrypted) with a
/// password-derived key, to a JSON file.
#[tauri::command]
pub fn export_encryption_keys(
    file_path: String,
    export_password: String,
) -> Result<KeyExport, String> {
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};

    let mut salt = [0u8; SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);

    let wrapping_key = derive_key(&export_password, &salt);

    let mut master_key = [0u8; KEY_LEN];
    rand::thread_rng().fill_bytes(&mut master_key);

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let cipher = Aes256Gcm::new_from_slice(&wrapping_key)
        .map_err(|e| format!("Cipher init failed: {}", e))?;
    let encrypted_master = cipher
        .encrypt(nonce, master_key.as_ref())
        .map_err(|e| format!("Key wrapping failed: {}", e))?;

    let key_id = generate_id();
    let export = KeyExport {
        version: "1.0".to_string(),
        exported_at: Utc::now().to_rfc3339(),
        key_id: key_id.clone(),
        encrypted_key: format!("{}:{}", B64.encode(nonce_bytes), B64.encode(&encrypted_master)),
        algorithm: "AES-256-GCM".to_string(),
        salt: B64.encode(salt),
        iterations: PBKDF2_ITERATIONS,
    };

    let json = serde_json::to_string_pretty(&export)
        .map_err(|e| format!("Failed to serialize key export: {}", e))?;
    fs::write(&file_path, &json)
        .map_err(|e| format!("Failed to write key file: {}", e))?;

    println!("Exported encryption key {} to {}", key_id, file_path);
    Ok(export)
}

/// Import (and verify) an encryption key file using a password.
#[tauri::command]
pub fn import_encryption_keys(
    file_path: String,
    import_password: String,
) -> Result<KeyImportResult, String> {
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};

    let json = fs::read_to_string(&file_path)
        .map_err(|e| format!("Failed to read file: {}", e))?;

    let import: KeyExport = serde_json::from_str(&json)
        .map_err(|e| format!("Invalid key file format: {}", e))?;

    let salt = B64
        .decode(&import.salt)
        .map_err(|e| format!("Invalid salt encoding: {}", e))?;

    let wrapping_key = derive_key(&import_password, &salt);

    let parts: Vec<&str> = import.encrypted_key.splitn(2, ':').collect();
    if parts.len() != 2 {
        return Err("Malformed encrypted_key field".to_string());
    }

    let nonce_bytes = B64
        .decode(parts[0])
        .map_err(|e| format!("Invalid nonce encoding: {}", e))?;
    let encrypted_bytes = B64
        .decode(parts[1])
        .map_err(|e| format!("Invalid ciphertext encoding: {}", e))?;

    let nonce = Nonce::from_slice(&nonce_bytes);
    let cipher = Aes256Gcm::new_from_slice(&wrapping_key)
        .map_err(|e| format!("Cipher init failed: {}", e))?;

    cipher
        .decrypt(nonce, encrypted_bytes.as_ref())
        .map_err(|_| "Invalid password. Cannot decrypt key.".to_string())?;

    println!(
        "Imported encryption key {} from {}",
        import.key_id, file_path
    );

    Ok(KeyImportResult {
        success: true,
        key_id: import.key_id,
        message: "Successfully imported encryption key".to_string(),
    })
}
