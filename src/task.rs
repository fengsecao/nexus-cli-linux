//! Prover Task
//!
//! This abstracts over the two "task" types used in the Nexus Orchestrator:
//! * Task (Returned by GetTasks)
//! * GetProofTaskResponse.

use sha3::{Digest, Keccak256};
use std::fmt::Display;

/// Back-compat alias so callers referencing `crate::task::TaskType` keep working
pub type TaskType = crate::nexus_orchestrator::TaskType;

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
    #[allow(dead_code)]
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
#[allow(deprecated)]
impl From<&crate::nexus_orchestrator::Task> for Task {
    fn from(task: &crate::nexus_orchestrator::Task) -> Self {
        // Use new fields if present; fall back to deprecated single input
        let public_inputs_list = if !task.public_inputs_list.is_empty() {
            task.public_inputs_list.clone()
        } else {
            vec![task.public_inputs.clone()]
        };
        let public_inputs = public_inputs_list.first().cloned().unwrap_or_default();
        let task_type = <crate::nexus_orchestrator::TaskType as core::convert::TryFrom<i32>>::try_from(task.task_type)
            .unwrap_or(crate::nexus_orchestrator::TaskType::ProofRequired);
        Task {
            task_id: task.task_id.clone(),
            program_id: task.program_id.clone(),
            public_inputs,
            public_inputs_list,
            task_type,
        }
    }
}

// From GetProofTaskResponse (older proto with single input only)
#[allow(deprecated)]
impl From<&crate::nexus_orchestrator::GetProofTaskResponse> for Task {
    fn from(response: &crate::nexus_orchestrator::GetProofTaskResponse) -> Self {
        // Prefer embedded Task in response if available
        if let Some(task) = response.task.as_ref() {
            return Task::from(task);
        }
        // Fallback for older fields
        Task {
            task_id: response.task_id.clone(),
            program_id: response.program_id.clone(),
            public_inputs: response.public_inputs.clone(),
            public_inputs_list: vec![response.public_inputs.clone()],
            task_type: crate::nexus_orchestrator::TaskType::ProofRequired,
        }
    }
}
