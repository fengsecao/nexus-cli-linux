//! 节点列表管理模块
//!
//! 用于读取、解析和管理节点ID列表

use std::fs::{self, File};
use std::io::{self, Write};
use std::path::Path;
use std::collections::HashSet;

#[derive(Debug)]
pub struct NodeList {
    node_ids: Vec<u64>,
}

impl NodeList {
    /// 创建一个新的空节点列表
    pub fn new() -> Self {
        Self {
            node_ids: Vec::new(),
        }
    }

    /// 从文件加载节点列表
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let content = fs::read_to_string(path)?;
        let mut node_ids = Vec::new();
        let mut unique_nodes = HashSet::new();

        // 解析每一行
        for line in content.lines() {
            let line = line.trim();
            // 跳过空行和注释
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            
            // 尝试解析为u64
            if let Ok(node_id) = line.parse::<u64>() {
                // 确保没有重复
                if unique_nodes.insert(node_id) {
                    node_ids.push(node_id);
                }
            }
        }
        
        Ok(Self { node_ids })
    }

    /// 保存节点列表到文件
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> io::Result<()> {
        let mut file = File::create(path)?;
        
        // 写入文件头
        writeln!(file, "# Nexus Node ID List")?;
        writeln!(file, "# 每行一个节点ID")?;
        writeln!(file, "")?;
        
        // 写入节点ID
        for node_id in &self.node_ids {
            writeln!(file, "{}", node_id)?;
        }
        
        Ok(())
    }

    /// 创建示例节点列表文件
    pub fn create_example_files<P: AsRef<Path>>(dir: P) -> io::Result<()> {
        let dir_path = dir.as_ref();
        
        // 确保目录存在
        fs::create_dir_all(dir_path)?;
        
        // 创建示例文件
        let example_path = dir_path.join("example_nodes.txt");
        let mut file = File::create(example_path)?;
        
        writeln!(file, "# Nexus Node ID List - 示例")?;
        writeln!(file, "# 将此文件替换为你的实际节点ID")?;
        writeln!(file, "# 每行一个节点ID，跳过空行和以#开头的行")?;
        writeln!(file, "")?;
        writeln!(file, "# 节点ID示例:")?;
        writeln!(file, "123456789")?;
        writeln!(file, "987654321")?;
        writeln!(file, "# 112233445566")?;
        
        Ok(())
    }

    /// 获取节点ID列表的引用
    pub fn node_ids(&self) -> &[u64] {
        &self.node_ids
    }

    /// 获取节点数量
    pub fn len(&self) -> usize {
        self.node_ids.len()
    }

    /// 检查节点列表是否为空
    pub fn is_empty(&self) -> bool {
        self.node_ids.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_load_from_file() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test_nodes.txt");
        
        // 创建测试文件
        {
            let mut file = File::create(&file_path).unwrap();
            writeln!(file, "# 测试节点").unwrap();
            writeln!(file, "123456").unwrap();
            writeln!(file, "789012").unwrap();
            writeln!(file, "# 被注释的节点").unwrap();
            writeln!(file, "").unwrap();
            writeln!(file, "345678").unwrap();
        }
        
        // 读取节点列表
        let node_list = NodeList::load_from_file(&file_path).unwrap();
        
        // 验证结果
        assert_eq!(node_list.len(), 3);
        assert_eq!(node_list.node_ids(), &[123456, 789012, 345678]);
    }

    #[test]
    fn test_save_to_file() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("output_nodes.txt");
        
        // 创建节点列表
        let mut node_list = NodeList::new();
        node_list.node_ids.push(111111);
        node_list.node_ids.push(222222);
        node_list.node_ids.push(333333);
        
        // 保存到文件
        node_list.save_to_file(&file_path).unwrap();
        
        // 重新加载并验证
        let loaded_list = NodeList::load_from_file(&file_path).unwrap();
        assert_eq!(loaded_list.len(), 3);
        assert_eq!(loaded_list.node_ids(), &[111111, 222222, 333333]);
    }
} 