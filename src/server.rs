use std::sync::Arc;
use tokio::sync::Mutex;
use sled::Db;
use crate::knowledge::{KnowledgeItem, build_knowledge_item, security_check, decrypt_data, TextTokenizer};
use chrono::Utc;
use uuid::Uuid;
use bincode;
use hnsw_rs::prelude::*; // للبحث بالـ vectors

// ========================= UserProfile =========================
#[derive(Debug)]
pub struct UserProfile {
    pub total_points: u32,
    pub daily_messages_left: u32,
    pub photos_count: u32,
    pub videos_count: u32,
    pub last_sync_timestamp: i64,
}

// ========================= NexusServer =========================
pub struct NexusServer {
    pub db: Arc<Db>,
    pub tokenizer: Arc<TextTokenizer>,
    pub user_profile: Mutex<UserProfile>,
    pub aes_key: Vec<u8>,
    pub hnsw_index: Mutex<Hnsw<f32, DistL2>>, // البحث بالـ vectors
}

impl NexusServer {
    pub fn new(db_path: &str, tokenizer_path: &str, aes_key: Vec<u8>, embedding_dim: usize) -> anyhow::Result<Self> {
        Ok(Self {
            db: Arc::new(sled::open(db_path)?),
            tokenizer: Arc::new(TextTokenizer::new(tokenizer_path)?),
            user_profile: Mutex::new(UserProfile {
                total_points: 100,
                daily_messages_left: 200,
                photos_count: 0,
                videos_count: 0,
                last_sync_timestamp: Utc::now().timestamp(),
            }),
            aes_key,
            hnsw_index: Mutex::new(Hnsw::new(embedding_dim, 200, DistL2)), // dim ثابت حسب الموديل
        })
    }

    // ========================= Add Knowledge =========================
    pub async fn add_knowledge(&self, content: String, device_id: String) -> anyhow::Result<()> {
        let item = build_knowledge_item(&self.aes_key, &content, device_id.clone());
        security_check(&item, &device_id)?;
        let key = Uuid::new_v4().to_string();
        let serialized = bincode::serialize(&item)?;
        self.db.insert(key.clone(), serialized)?;
        self.db.flush()?;

        // إضافة embedding للـ HNSW إذا موجود
        if !item.embedding.is_empty() {
            let mut hnsw = self.hnsw_index.lock().await;
            hnsw.insert((&item.embedding, &key))?;
        }

        Ok(())
    }

    // ========================= Retrieve Knowledge =========================
    pub async fn retrieve(&self, query: &str) -> Vec<String> {
        let mut results = Vec::new();
        for kv in self.db.iter() {
            if let Ok((_, val)) = kv {
                if let Ok(item) = bincode::deserialize::<KnowledgeItem>(&val) {
                    if let Some(text) = decrypt_data(&self.aes_key, &item.ciphertext, &item.nonce) {
                        if let Ok(string) = String::from_utf8(text) {
                            results.push(string);
                        }
                    }
                }
            }
        }
        results
    }

    // ========================= نقاط وقيود الموارد =========================
    pub fn check_and_deduct_points(&self, user: &mut UserProfile, action_type: &str) -> Result<(), String> {
        match action_type {
            "create_image" => if user.total_points >= 5 { user.total_points -= 5; Ok(()) } else { Err("🚨 رصيدك غير كافٍ!".into()) },
            "chat" => if user.daily_messages_left > 0 { user.daily_messages_left -= 1; Ok(()) } else { Err("🚨 انتهت رسائلك اليومية.".into()) },
            _ => Ok(()),
        }
    }

    pub fn earn_points_from_video(&self, user: &mut UserProfile) {
        user.total_points += 50;
        println!("✅ حصلت على 50 نقطة!");
    }
}

// ========================= قيود الموارد =========================
pub fn validate_resource_limits(user: &UserProfile, resource_type: &str) -> Result<(), String> {
    match resource_type {
        "photo" if user.photos_count >= 7 => Err("🚨 وصلت للحد الأقصى للصور (7).".into()),
        "video" if user.videos_count >= 4 => Err("🚨 وصلت للحد الأقصى للفيديوهات (4).".into()),
        "file" if user.photos_count >= 4 => Err("🚨 وصلت للحد الأقصى للملفات (4).".into()),
        _ => Ok(()),
    }
}

pub fn check_offline_validity(last_sync_timestamp: i64) -> bool {
    let three_hours_in_seconds = 3 * 60 * 60;
    (Utc::now().timestamp() - last_sync_timestamp) <= three_hours_in_seconds
}
