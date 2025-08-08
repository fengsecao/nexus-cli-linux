//! Prover Task
//!
//! This abstracts over the two "task" types used in the Nexus Orchestrator:
//! * Task (Returned by GetTasks)
//! * GetProofTaskResponse.

use sha3::{Digest, Keccak256};
use std::fmt::Display;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum TaskType {
    /// Full proof must be submitted
    ProofRequired,
    /// Only proof hash is used for scoring (server may ignore proof bytes)
    ProofHash,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Task {
    /// Orchestrator task ID
    pub task_id: String,

    /// ID of the program to be executed
    pub program_id: String,

    /// Public inputs for the task (legacy field for backward compatibility)
    pub public_inputs: Vec<u8>,

    /// Multiple public inputs for the task (new field)
    pub public_inputs_list: Vec<Vec<u8>>,

    /// The type of task (proof required or only hash)
    pub task_type: TaskType,
}

impl Task {
    /// Creates a new task with the given parameters.
    #[allow(unused)]
    pub fn new(
        task_id: String,
        program_id: String,
        public_inputs: Vec<u8>,
        task_type: TaskType,
    ) -> Self {
        Task {
            task_id,
            program_id,
            public_inputs: public_inputs.clone(),
            public_inputs_list: vec![public_inputs],
            task_type,
        }
    }

    /// Combines multiple proof hashes into a single hash using Keccak-256
    pub fn combine_proof_hashes(hashes: &[String]) -> String {
        if hashes.is_empty() {
            return String::new();
        }
        let combined = hashes.join("");
        let hash = Keccak256::digest(combined.as_bytes());
        format!("{:x}", hash)
    }

    /// Get all inputs for the task
    pub fn all_inputs(&self) -> &[Vec<u8>] {
        &self.public_inputs_list
    }
}

// Display
impl Display for Task {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Task ID: {}, Program ID: {}, Inputs: {}",
            self.task_id,
            self.program_id,
            self.public_inputs_list.len()
        )
    }
}

// From Task (older proto with single input only)
impl From<&crate::nexus_orchestrator::Task> for Task {
    fn from(task: &crate::nexus_orchestrator::Task) -> Self {
        Task {
            task_id: task.task_id.clone(),
            program_id: task.program_id.clone(),
            public_inputs: task.public_inputs.clone(),
            public_inputs_list: vec![task.public_inputs.clone()],
            // Older proto does not provide task type; default to ProofRequired
            task_type: TaskType::ProofRequired,
        }
    }
}

// From GetProofTaskResponse (older proto with single input only)
impl From<&crate::nexus_orchestrator::GetProofTaskResponse> for Task {
    fn from(response: &crate::nexus_orchestrator::GetProofTaskResponse) -> Self {
        Task {
            task_id: response.task_id.clone(),
            program_id: response.program_id.clone(),
            public_inputs: response.public_inputs.clone(),
            public_inputs_list: vec![response.public_inputs.clone()],
            // Older proto does not provide task type; default to ProofRequired
            task_type: TaskType::ProofRequired,
        }
    }
}
