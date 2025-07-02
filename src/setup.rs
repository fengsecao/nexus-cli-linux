use crate::config::Config;
// 删除colored依赖
use crate::orchestrator::OrchestratorClient;
use crate::environment::Environment;
use std::error::Error;
use std::path::PathBuf;

/// 提示用户输入节点ID或创建新节点
pub async fn setup_node_id(
    config_path: &PathBuf,
    config: &mut Config,
    orchestrator: &OrchestratorClient,
) -> Result<String, Box<dyn Error>> {
    println!("Would you like to:");
    println!("1. Enter an existing node ID");
    println!("2. Create a new node");
    print!("> ");
    std::io::Write::flush(&mut std::io::stdout())?;

    let mut choice = String::new();
    std::io::stdin().read_line(&mut choice)?;
    let choice = choice.trim();

    match choice {
        "1" => {
            println!("Please enter your node ID:");
            print!("> ");
            std::io::Write::flush(&mut std::io::stdout())?;
            
            let mut node_id = String::new();
            std::io::stdin().read_line(&mut node_id)?;
            let node_id = node_id.trim().to_string();
            
            // Verify the node ID exists
            // (In a real implementation, this should make an API call to check)
            println!("Adding your node ID to the CLI");
            
            Ok(node_id)
        }
        "2" => {
            // Register a new node with the orchestrator
            let user_id = &config.user_id;
            if user_id.is_empty() {
                return Err("No user ID found in config. Please register a user first.".into());
            }
            
            println!("Creating a new node ID...");
            let node_id = orchestrator.register_node(user_id).await?;
            println!("Successfully registered node with ID: {}", node_id);
            
            Ok(node_id)
        }
        _ => Err("Invalid choice".into()),
    }
} 