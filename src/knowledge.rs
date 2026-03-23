use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit};
use rand::RngCore;
use sha2::{Sha256, Digest};
use serde::{Serialize, Deserialize};
use chrono::Utc;
use uuid::Uuid;
use anyhow::Result;

// ========================= KnowledgeItem =========================
#[derive(Serialize, Deserialize, Clone)]
pub struct KnowledgeItem {
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub keywords: Vec<String>,
    pub embedding: Vec<f32>,
    pub source: String,
    pub importance: u8,
    pub timestamp: i64,
    pub session_id: String,
    pub ethical_flags: Vec<String>,
    pub device_id: String,
    pub location_context: Vec<u8>,
    pub checksum: Vec<u8>,
}

// ========================= Encryption / Decryption =========================
pub fn encrypt_data(key_bytes: &[u8], data: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let key = Key::<Aes256Gcm>::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key);
    let mut nonce_bytes = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, data).expect("encryption failed");
    (ciphertext, nonce_bytes.to_vec())
}

pub fn decrypt_data(key_bytes: &[u8], ciphertext: &[u8], nonce_bytes: &[u8]) -> Option<Vec<u8>> {
    let key = Key::<Aes256Gcm>::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher.decrypt(nonce, ciphertext).ok()
}

// ========================= Checksum =========================
pub fn generate_item_checksum(ciphertext: &[u8], nonce: &[u8], device_id: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(ciphertext);
    hasher.update(nonce);
    hasher.update(device_id.as_bytes());
    hasher.finalize().to_vec()
}

// ========================= Build KnowledgeItem =========================
pub fn build_knowledge_item(key: &[u8], content: &str, device_id: String) -> KnowledgeItem {
    let (ciphertext, nonce) = encrypt_data(key, content.as_bytes());
    let checksum = generate_item_checksum(&ciphertext, &nonce, &device_id);

    KnowledgeItem {
        ciphertext,
        nonce,
        keywords: vec![],
        embedding: vec![],
        source: "chat".into(),
        importance: 5,
        timestamp: Utc::now().timestamp(),
        session_id: Uuid::new_v4().to_string(),
        ethical_flags: vec![],
        device_id,
        location_context: vec![],
        checksum,
    }
}

// ========================= Verify Integrity =========================
pub fn verify_integrity(item: &KnowledgeItem) -> bool {
    let expected = generate_item_checksum(&item.ciphertext, &item.nonce, &item.device_id);
    expected == item.checksum
}

// ========================= Security Check =========================
pub fn security_check(item: &KnowledgeItem, current_device: &str) -> Result<()> {
    if !verify_integrity(item) {
        anyhow::bail!("🚨 Tampering detected");
    }
    if item.device_id != current_device {
        anyhow::bail!("🚨 Device mismatch");
    }
    Ok(())
}

// ========================= Tokenizer Wrapper =========================
use tokenizers::Tokenizer;

pub struct TextTokenizer {
    tokenizer: Tokenizer,
}

impl TextTokenizer {
    pub fn new(tokenizer_path: &str) -> Result<Self> {
        let tokenizer = Tokenizer::from_file(tokenizer_path)
            .map_err(|e| anyhow::anyhow!("Tokenizer load error: {}", e))?;
        Ok(Self { tokenizer })
    }

    pub fn encode(&self, text: &str) -> Vec<u32> {
        match self.tokenizer.encode(text, false) {
            Ok(encoding) => encoding.get_ids().to_vec(),
            Err(_) => vec![], // لو حصلت مشكلة في التوكنايز، ارجع Vec فاضي بدل ما تقفل السيرفر
        }
    }
}
