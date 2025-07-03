use axum::{async_trait, extract::{FromRequest, Request}, http::StatusCode, response::IntoResponse, Json, body::to_bytes};
use serde::de::DeserializeOwned;
use std::ops::Deref;
use crate::models::ApiResponse;

pub struct CustomJson<T>(pub T);

#[async_trait]
impl<S, T> FromRequest<S> for CustomJson<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = (StatusCode, Json<ApiResponse<()>>);

    async fn from_request(req: Request, _state: &S) -> Result<Self, Self::Rejection> {
        let bytes = match to_bytes(req.into_body(), usize::MAX).await {
            Ok(b) => b,
            Err(_) => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(ApiResponse {
                        success: false,
                        data: None,
                        error: Some("Missing required fields".to_string()),
                    }),
                ))
            }
        };
        match serde_json::from_slice::<T>(&bytes) {
            Ok(value) => Ok(CustomJson(value)),
            Err(_) => Err((
                StatusCode::BAD_REQUEST,
                Json(ApiResponse {
                    success: false,
                    data: None,
                    error: Some("Missing required fields".to_string()),
                }),
            )),
        }
    }
}

impl<T> Deref for CustomJson<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
} 