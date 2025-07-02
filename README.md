# Nexus Network 0.8.17 多节点内存优化版
参考@hua_web3的代码修改:https://github.com/huahua1220/nexus-cli-linux

基于 Nexus Network CLI 0.8.17 版本的多节点内存优化实现，解决高内存占用和多节点管理问题。

## 主要特性

- **内存优化**：单节点比官方版节省 30%-50% 内存占用
- **多节点管理**：支持从文件批量启动多个节点ID
- **自动内存碎片整理**：智能监控和处理内存碎片问题
- **高级错误处理**：特别针对 429 限流错误进行优化处理
- **无限重试机制**：节点失败后会自动重试，保障稳定运行
- **实时状态监控**：固定行显示各节点状态和内存使用情况

## 安装

### 1. 安装Rust环境（如已安装可跳过）
```bash
# 安装Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.bashrc
```

### 2. 克隆并编译
```bash
# 克隆代码库
git clone https://github.com/zjw0231/nexus-cli-linux
cd nexus-cli-linux

# 编译发布版本
cargo build --release
```

## 使用方法

### 单节点模式
```bash
# 运行单个节点（自动读取或创建密钥）
./target/release/nexus-network start --node-id <节点ID>
```

### 批量节点模式（推荐）
```bash
# 创建节点列表示例文件
mkdir -p nodes
./target/release/nexus-network batch-file --file nodes/nodes.txt --max-concurrent 10 --proof-interval 5 --workers-per-node 1
```

### 节点列表文件格式
在节点列表文件中，每行放置一个节点ID，例如：
```
# 节点列表示例
123456789
987654321
# 被注释的节点ID（不会启动）
```

## 参数说明

- `--file`：节点列表文件路径
- `--max-concurrent`：最大并发节点数（根据服务器配置调整）
- `--proof-interval`：每个节点提交证明后的等待时间（秒）
- `--workers-per-node`：每个节点的工作线程数（建议保持为1）
- `--verbose`：启用详细日志输出

## 内存优化原理

1. **全局证明器实例共享**：避免每个节点重复创建证明器实例
2. **智能内存碎片整理**：监控内存使用并自动优化碎片
3. **资源池复用**：使用对象池模式减少内存分配和释放
4. **网络请求优化**：减少429错误和优化重试策略

## 适用环境

- Linux（Ubuntu 24.04）

## 改进计划

- [ ] 添加监控API和Web界面
- [ ] 支持动态调整并发节点数
- [ ] 增加节点失败自动替换功能
- [ ] 更精细的内存使用控制
