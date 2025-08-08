//! Error handling for the orchestrator module

use prost::DecodeError;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[allow(non_snake_case)] // used for json parsing
#[derive(Serialize, Deserialize)]
struct RawError {
    name: String,
    message: String,
    httpCode: u16,
}

#[derive(Debug, Error)]
pub enum OrchestratorError {
    /// Failed to decode a Protobuf message from the server
    #[error("Decoding error: {0}")]
    Decode(#[from] DecodeError),

    /// Reqwest error, typically related to network issues or request failures.
    #[error("Reqwest error: {0}")]
    Reqwest(#[from] reqwest::Error),

    /// An error occurred while processing the request.
    #[error("HTTP error with status {status}: {message}")]
    Http { status: u16, message: String, headers: Vec<(String, String)> },
}

impl OrchestratorError {
    pub async fn from_response(response: reqwest::Response) -> OrchestratorError {
        let status = response.status().as_u16();
        let headers: Vec<(String, String)> = response
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();
        let message = response
            .text()
            .await
            .unwrap_or_else(|_| "Failed to read response text".to_string());

        OrchestratorError::Http { status, message, headers }
    }

    pub fn to_pretty(&self) -> Option<String> {
        match self {
            Self::Http { status: _, message: msg, .. } => {
                if let Ok(parsed) = serde_json::from_str::<RawError>(msg) {
                    if let Ok(stringified) = serde_json::to_string_pretty(&parsed) {
                        return Some(stringified);
                    }
                }

                None
            }
            _ => None,
        }
    }

    /// Try parse Retry-After header (seconds)
    pub fn get_retry_after_seconds(&self) -> Option<u32> {
        if let Self::Http { headers, .. } = self {
            for (k, v) in headers {
                if k.eq_ignore_ascii_case("retry-after") {
                    if let Ok(secs) = v.trim().parse::<u32>() {
                        return Some(secs);
                    }
                }
            }
        }
        None
    }
}
