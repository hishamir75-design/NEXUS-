use std::{sync::Arc, fs};
use tokio::sync::Mutex;
use axum::{Router, routing::{post, get}, Json, extract::Extension};
use sled::Db;
use crate::knowledge::{KnowledgeItem, build_knowledge_item, security_check, decrypt_data, TextTokenizer};
use serde::Deserialize;
use uuid::Uuid;
use chrono::Utc;
use rand::RngCore;

// ========================= UserProfile =========================
#[derive(Debug)]
pub struct UserProfile {
    pub total_points: u32,
    pub daily_messages_left: u32,
    pub photos_count: u32,
    pub videos_count: u32,
    pub last_sync_timestamp: i64,
}

// ========================= AppState =========================
pub struct AppState {
    pub db: Arc<Db>,
    pub tokenizer: Arc<TextTokenizer>,
    pub user_profile: Mutex<UserProfile>,
    pub aes_key: Vec<u8>, // المفتاح العشوائي
}

// ========================= Payload Structs =========================
#[derive(Deserialize)]
struct AddRequest {
    content: String,
    device_id: String,
}

#[derive(Deserialize)]
struct RetrieveRequest {
    query: String,
}

// ========================= AppState Methods =========================
impl AppState {

    pub async fn add_knowledge(&self, content: String, device_id: String) -> anyhow::Result<()> {
        let item = build_knowledge_item(&self.aes_key, &content, device_id.clone());
        security_check(&item, &device_id)?;

        let key = Uuid::new_v4().to_string();
        let serialized = bincode::serialize(&item)?;
        self.db.insert(key, serialized)?;
        self.db.flush()?;
        Ok(())
    }

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
            "create_image" => {
                if user.total_points >= 5 {
                    user.total_points -= 5;
                    Ok(())
                } else { Err("🚨 رصيدك غير كافٍ! شاهد فيديو للحصول على نقاط.".into()) }
            },
            "chat" => {
                if user.daily_messages_left > 0 {
                    user.daily_messages_left -= 1;
                    Ok(())
                } else { Err("🚨 انتهت رسائلك اليومية.".into()) }
            },
            _ => Ok(())
        }
    }

    pub fn earn_points_from_video(&self, user: &mut UserProfile) {
        user.total_points += 50;
        println!("✅ حصلت على 50 نقطة!");
    }
}

// ========================= القيود اليومية =========================
pub fn validate_resource_limits(user: &UserProfile, resource_type: &str) -> Result<(), String> {
    match resource_type {
        "photo" if user.photos_count >= 7 => Err("🚨 وصلت للحد الأقصى للصور (7).".into()),
        "video" if user.videos_count >= 4 => Err("🚨 وصلت للحد الأقصى للفيديوهات (4).".into()),
        "file" if user.photos_count >= 4 => Err("🚨 وصلت للحد الأقصى للملفات (4).".into()),
        _ => Ok(())
    }
}

pub fn check_offline_validity(last_sync_timestamp: i64) -> bool {
    let three_hours_in_seconds = 3 * 60 * 60;
    let current_time = Utc::now().timestamp();
    (current_time - last_sync_timestamp) <= three_hours_in_seconds
}

// ========================= Axum Handlers =========================
async fn add_handler(
    Json(payload): Json<AddRequest>,
    Extension(state): Extension<Arc<AppState>>,
) -> Json<serde_json::Value> {
    let mut user = state.user_profile.lock().await;
    if user.daily_messages_left == 0 {
        return Json(serde_json::json!({"status": "error", "message": "انتهت رسائلك الـ 200 لليوم"}));
    }
    match state.add_knowledge(payload.content, payload.device_id).await {
        Ok(_) => {
            user.daily_messages_left -= 1;
            Json(serde_json::json!({"status": "ok", "remaining": user.daily_messages_left}))
        },
        Err(e) => Json(serde_json::json!({"status": "error", "message": e.to_string()})),
    }
}

async fn retrieve_handler(
    Json(payload): Json<RetrieveRequest>,
    Extension(state): Extension<Arc<AppState>>,
) -> Json<serde_json::Value> {
    let items = state.retrieve(&payload.query).await;
    Json(serde_json::json!({"results": items}))
}

async fn earn_points_handler(
    Extension(state): Extension<Arc<AppState>>,
) -> Json<serde_json::Value> {
    let mut user = state.user_profile.lock().await;
    state.earn_points_from_video(&mut user);
    Json(serde_json::json!({"status": "success", "new_balance": user.total_points}))
}

// ========================= Main Function =========================
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 🔑 تحقق من وجود tokenizer.json
    if !fs::metadata("tokenizer.json").is_ok() {
        panic!("🚨 خطأ: ملف tokenizer.json غير موجود! ضع الملف في مجلد المشروع.");
    }

    // توليد AES-256 Key عشوائي
    let mut aes_key = vec![0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut aes_key);

    let state = Arc::new(AppState {
        db: Arc::new(sled::open("nexus_db")?),
        tokenizer: Arc::new(TextTokenizer::new("tokenizer.json")?),
        user_profile: Mutex::new(UserProfile {
            total_points: 100,
            daily_messages_left: 200,
            photos_count: 0,
            videos_count: 0,
            last_sync_timestamp: Utc::now().timestamp(),
        }),
        aes_key,
    });

    let app = Router::new()
        .route("/add", post(add_handler))
        .route("/retrieve", post(retrieve_handler))
        .route("/earn_points", post(earn_points_handler))
        .route("/", get(|| async { "🚀 Nexus AI Server Running" }))
        .layer(Extension(state.clone()));

    println!("🔥 Server running on http://0.0.0.0:3000");
    axum::Server::bind(&"0.0.0.0:3000".parse()?)
        .serve(app.into_make_service())
        .await?;

    Ok(())
}
