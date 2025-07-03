//! 节点列表管理模块
//!
//! 用于读取、解析和管理节点ID列表

use std::fs::{self, File};
use std::io::{self, Write, BufReader, BufWriter};
use std::path::Path;
use std::collections::HashSet;

#[derive(Debug)]
pub struct NodeList {
    node_ids: Vec<u64>,
}

impl NodeList {
    /// 创建一个新的空节点列表
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self {
            node_ids: Vec::new(),
        }
    }

    /// 从文件加载节点列表
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        
        let mut node_ids = Vec::new();
        
        for line in reader.lines() {
            let line = line?;
            let line = line.trim();
            
            // 跳过空行和注释
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            
            // 尝试解析为u64
            if let Ok(node_id) = line.parse::<u64>() {
                node_ids.push(node_id);
            } else {
                eprintln!("警告: 无法解析节点ID: {}", line);
            }
        }
        
        Ok(Self { node_ids })
    }
    
    /// 将节点列表保存到文件
    #[allow(dead_code)]
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> io::Result<()> {
        let file = File::create(path)?;
        let mut writer = BufWriter::new(file);
        
        writeln!(writer, "# Nexus 节点ID列表")?;
        writeln!(writer, "# 格式: 每行一个节点ID")?;
        writeln!(writer, "# 生成时间: {}", chrono::Local::now().format("%Y-%m-%d %H:%M:%S"))?;
        writeln!(writer)?;
        
        for node_id in &self.node_ids {
            writeln!(writer, "{}", node_id)?;
        }
        
        Ok(())
    }
    
    /// 创建示例节点列表文件
    #[allow(dead_code)]
    pub fn create_example_files<P: AsRef<Path>>(dir: P) -> io::Result<()> {
        let dir = dir.as_ref();
        
        // 创建目录（如果不存在）
        if !dir.exists() {
            fs::create_dir_all(dir)?;
        }
        
        // 创建小型示例文件
        let small_list = Self {
            node_ids: vec![12345678, 23456789, 34567890, 45678901, 56789012],
        };
        small_list.save_to_file(dir.join("nodes_small.txt"))?;
        
        // 创建中型示例文件
        let mut medium_list = Self::new();
        for i in 0..20 {
            medium_list.node_ids.push(10000000 + i);
        }
        medium_list.save_to_file(dir.join("nodes_medium.txt"))?;
        
        // 创建大型示例文件
        let mut large_list = Self::new();
        for i in 0..100 {
            large_list.node_ids.push(20000000 + i);
        }
        large_list.save_to_file(dir.join("nodes_large.txt"))?;
        
        Ok(())
    }
    
    /// 获取节点ID列表
    pub fn node_ids(&self) -> &[u64] {
        &self.node_ids
    }
    
    /// 检查节点列表是否为空
    pub fn is_empty(&self) -> bool {
        self.node_ids.is_empty()
    }
    
    /// 获取节点列表长度
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.node_ids.len()
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