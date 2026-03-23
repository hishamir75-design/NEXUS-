use axum::{Json, extract::Extension};
use std::sync::Arc;
use crate::server::{NexusServer, UserProfile};
use crate::knowledge::{AddRequest, RetrieveRequest};

pub async fn add_handler(
    Json(payload): Json<AddRequest>,
    Extension(server): Extension<Arc<NexusServer>>,
) -> Json<serde_json::Value> {
    let mut user = server.user_profile.lock().await;
    if user.daily_messages_left == 0 {
        return Json(serde_json::json!({"status":"error","message":"انتهت رسائلك الـ 200 لليوم"}));
    }
    match server.add_knowledge(payload.content, payload.device_id).await {
        Ok(_) => {
            user.daily_messages_left -= 1;
            Json(serde_json::json!({"status":"ok","remaining":user.daily_messages_left}))
        },
        Err(e) => Json(serde_json::json!({"status":"error","message": e.to_string()})),
    }
}

pub async fn retrieve_handler(
    Json(payload): Json<RetrieveRequest>,
    Extension(server): Extension<Arc<NexusServer>>,
) -> Json<serde_json::Value> {
    let items = server.retrieve(&payload.query).await;
    Json(serde_json::json!({"results": items}))
}

pub async fn earn_points_handler(
    Extension(server): Extension<Arc<NexusServer>>,
) -> Json<serde_json::Value> {
    let mut user = server.user_profile.lock().await;
    server.earn_points_from_video(&mut user);
    Json(serde_json::json!({"status":"success","new_balance":user.total_points}))
}
