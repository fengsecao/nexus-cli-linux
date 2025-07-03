# Nexus Network 0.8.18 多节点内存优化版

> 参考@hua_web3的代码修改: https://github.com/huahua1220/nexus-cli-linux

基于 Nexus Network CLI 0.8.18 版本的多节点内存优化实现，解决高内存占用和多节点管理问题。

## 📋 主要特性

- ✅ **内存优化**：单节点比官方版节省 30%-50% 内存占用
- ✅ **多节点管理**：支持从文件批量启动多个节点ID
- ✅ **自动内存碎片整理**：智能监控和处理内存碎片问题
- ✅ **高级错误处理**：特别针对 429 限流错误进行优化处理（最多重试12次）
- ✅ **无限重试机制**：节点失败后会自动重试，保障稳定运行
- ✅ **实时状态监控**：固定行显示各节点状态和内存使用情况

## 🚀 安装指南

### Linux环境

#### 1. 安装Rust环境（如已安装可跳过）
```bash
# 安装Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.bashrc
```

#### 2. 克隆并编译
```bash
# 克隆代码库
git clone https://github.com/zjw0231/nexus-cli-linux
cd nexus-cli-linux

# 编译发布版本
cargo build --release
```

### Windows环境

#### 1. 安装Rust环境
- 访问 [rustup.rs](https://rustup.rs/) 下载并运行安装程序
- 按照向导完成安装

#### 2. 克隆并编译
```powershell
# 克隆代码库
git clone https://github.com/zjw0231/nexus-cli-linux
cd nexus-cli-linux

# 编译发布版本
cargo build --release
```

## 💻 使用方法

### 单节点模式
```bash
# 运行单个节点（自动读取或创建密钥）
./target/release/nexus-network start --node-id <节点ID>

# Windows下使用
.\target\release\nexus-network.exe start --node-id <节点ID>
```

### 批量节点模式（推荐）
```bash
# 创建节点列表示例文件
mkdir -p nodes

# 运行批量节点模式
./target/release/nexus-network batch-file --file nodes/nodes.txt --max-concurrent 10 --proof-interval 5 --workers-per-node 1

# Windows下使用
.\target\release\nexus-network.exe batch-file --file nodes\nodes.txt --max-concurrent 10 --proof-interval 5 --workers-per-node 1
```

### 节点列表文件格式
在nodes.txt中，每行放置一个节点ID，例如：
```
123456789
987654321
456789
```

## ⚙️ 参数说明

| 参数 | 说明 | 默认值 | 建议值 |
|------|------|--------|--------|
| `--file` | 节点列表文件路径 | - | - |
| `--max-concurrent` | 最大并发节点数 | 10 | 根据服务器配置调整 |
| `--proof-interval` | 每个节点提交证明后的等待时间（秒） | 1 | 3-5 |
| `--workers-per-node` | 每个节点的工作线程数 | 1 | 保持为1 |
| `--start-delay` | 节点启动间隔时间（秒） | 0.5 | 0.5-1.0 |
| `--verbose` | 启用详细日志输出 | false | 调试时启用 |
| `--env` | 连接环境 | production | production |

## 🔧 内存优化原理

1. **全局证明器实例共享**：避免每个节点重复创建证明器实例
2. **智能内存碎片整理**：监控内存使用并自动优化碎片
3. **资源池复用**：使用对象池模式减少内存分配和释放
4. **网络请求优化**：减少429错误和优化重试策略
   - 最多重试12次429错误
   - 使用30-60秒随机等待时间
   - 智能退避策略

## 📊 性能对比

| 指标 | 官方版本 | 优化版本 | 提升 |
|------|---------|---------|------|
| 单节点内存占用 | 约150MB | 约80MB | 降低约47% |
| 10节点内存占用 | 约1.5GB | 约700MB | 降低约53% |
| 429错误重试 | 简单重试 | 智能策略 | 更高成功率 |
| 多节点管理 | 不支持 | 支持 | 大幅提升 |

## 🖥️ 适用环境

- ✅ Linux（Ubuntu 20.04+, Debian 10+, CentOS 8+）
- ✅ Windows 10/11
- ⚠️ macOS（需要自行测试）

## 🔄 常见问题

1. **问题**: 遇到"内存不足"错误
   **解决方案**: 减少 `--max-concurrent` 参数值

2. **问题**: 429错误过多
   **解决方案**: 增加 `--proof-interval` 值到5-10秒

3. **问题**: 节点状态显示异常
   **解决方案**: 使用 `--headless` 模式运行，查看详细日志

## 📝 改进计划

- [ ] 添加监控API和Web界面
- [ ] 支持动态调整并发节点数
- [ ] 增加节点失败自动替换功能
- [ ] 更精细的内存使用控制
- [ ] 添加Docker支持

## 📜 许可证

MIT License

## 🙏 致谢

特别感谢@hua_web3的代码贡献和Nexus Network社区的支持。
