use crate::task::Task;
use crate::remote::types::{JobSubmitRequest, JobSubmitResponse, JobStatusResponse};
use nexus_sdk::stwo::seq::Proof;
use reqwest::Client;
use sha3::{Digest, Keccak256};

pub struct RemoteProverClient {
    http: Client,
    base_url: String,
    auth_token: Option<String>,
    poll_interval_ms: u64,
    total_timeout_secs: u64,
}

impl RemoteProverClient {
    pub fn new(base_url: String, auth_token: Option<String>, poll_interval_ms: u64, total_timeout_secs: u64) -> Self {
        Self {
            http: Client::new(),
            base_url,
            auth_token,
            poll_interval_ms,
            total_timeout_secs,
        }
    }

    fn auth_header(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        if let Some(tok) = &self.auth_token {
            req.header("Authorization", format!("Bearer {}", tok))
        } else { req }
    }

    pub async fn cancel_job(&self, job_id: &str) -> Result<(), String> {
        let url = format!("{}/v1/jobs/{}", self.base_url, job_id);
        let mut req = self.http.delete(url);
        req = self.auth_header(req);
        let resp = req.send().await.map_err(|e| e.to_string())?;
        if !resp.status().is_success() { return Err(format!("cancel failed: {}", resp.status())); }
        Ok(())
    }

    pub async fn request_proof(&self, task: &Task) -> Result<(Proof, String), String> {
        // 1) submit job
        let submit = JobSubmitRequest {
            task_id: task.task_id.clone(),
            program_id: task.program_id.clone(),
            task_type: task.task_type as i32,
            public_inputs_list: task.public_inputs_list.clone(),
        };

        let url = format!("{}/v1/jobs", self.base_url);
        let mut req = self.http.post(url).json(&submit);
        req = self.auth_header(req);
        let resp = req.send().await.map_err(|e| e.to_string())?;
        if !resp.status().is_success() { return Err(format!("submit failed: {}", resp.status())); }
        let JobSubmitResponse { job_id, accepted } = resp.json().await.map_err(|e| e.to_string())?;
        if !accepted { return Err("job not accepted".into()); }

        // 2) poll status
        let mut waited: u64 = 0;
        loop {
            let url = format!("{}/v1/jobs/{}", self.base_url, job_id);
            let mut req = self.http.get(url);
            req = self.auth_header(req);
            let resp = req.send().await.map_err(|e| e.to_string())?;
            if !resp.status().is_success() { return Err(format!("poll failed: {}", resp.status())); }
            let status: JobStatusResponse = resp.json().await.map_err(|e| e.to_string())?;
            // 更新节点状态（如果能解析出节点ID）
            if let Some(node_id) = task.task_id.split('-').next().and_then(|s| s.parse::<u64>().ok()) {
                if let Some(phase) = &status.phase {
                    let label = match phase.as_str() {
                        "received" => "已接收",
                        "computing" => "计算中",
                        "returning" => "回传中",
                        _ => "处理中",
                    };
                    crate::prover_runtime::set_node_state(node_id, &format!("远程作业{}... ({}s)", label, status.elapsed_secs));
                } else {
                    crate::prover_runtime::set_node_state(node_id, &format!("远程作业处理中... ({}s)", status.elapsed_secs));
                }
            }
            match status.state.as_str() {
                "succeeded" => {
                    let proof_bytes = status.proof.ok_or_else(|| "missing proof".to_string())?;
                    let proof: Proof = postcard::from_bytes(&proof_bytes).map_err(|e| e.to_string())?;
                    let proof_hash = status.proof_hash.unwrap_or_else(|| {
                        let h = Keccak256::digest(&proof_bytes);
                        format!("{:x}", h)
                    });
                    return Ok((proof, proof_hash));
                }
                "failed" => return Err(status.error.unwrap_or_else(|| "job failed".into())),
                _ => {}
            }
            if waited >= self.total_timeout_secs { return Err("job timeout".into()); }
            tokio::time::sleep(std::time::Duration::from_millis(self.poll_interval_ms)).await;
            waited += self.poll_interval_ms / 1000;
        }
    }
}


