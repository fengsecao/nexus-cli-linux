use serde::{Serialize, Deserialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct JobSubmitRequest {
    pub task_id: String,
    pub program_id: String,
    pub task_type: i32,
    pub public_inputs_list: Vec<Vec<u8>>, // raw bytes per input
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct JobSubmitResponse {
    pub job_id: String,
    pub accepted: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct JobStatusResponse {
    pub job_id: String,
    pub state: String, // queued|running|succeeded|failed|canceled
    pub phase: Option<String>, // received|computing|returning
    pub elapsed_secs: u64,
    pub error: Option<String>,
    pub proof: Option<Vec<u8>>, // postcard-serialized proof bytes
    pub proof_hash: Option<String>,
}


