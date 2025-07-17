# Nexus Network 0.8.18 多节点内存优化版

基于 Nexus Network CLI 0.8.18 版本的多节点内存优化实现，解决高内存占用和多节点管理问题。

## 主要特性

- **内存优化**：单节点比官方版节省 30%-50% 内存占用
- **多节点管理**：支持从文件批量启动多个节点ID
- **高级错误处理**：针对429限流错误进行优化处理
- **节点轮转功能**：支持节点ID自动轮转，提高成功率
- **代理轮换功能**：支持动态代理池，每次请求使用不同IP

## 安装指南

### 安装Rust环境（如已安装可跳过）
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.bashrc
```

### 克隆并编译
```bash
git clone https://github.com/zjw0231/nexus-cli-linux
cd nexus-cli-linux
cargo build --release
```

## 使用方法

### 批量节点模式（推荐）
```bash
# 基本使用
./target/release/nexus-network batch-file --file nodes/nodes.txt --max-concurrent 10 --proof-interval 5

# 使用代理文件
./target/release/nexus-network batch-file --file nodes/nodes.txt --proxy-file proxy.txt

# 启用节点轮转功能
./target/release/nexus-network batch-file --file nodes/nodes.txt --rotation
```

### 节点列表文件格式
在nodes.txt中，每行放置一个节点ID，例如：
```
123456789
987654321
456789
```

### 代理列表文件格式
在proxy.txt中，每行放置一个代理，格式为`host:port:username:password`，例如：
```
proxy-as.packetstream.vip:31112:13413241:Cazq45dd6jbmZ_country-CHINA
123.45.67.89:8080:user:pass
```

## 参数说明

| 参数 | 说明 | 默认值 | 建议值 |
|------|------|--------|--------|
| `--file` | 节点列表文件路径 | - | - |
| `--max-concurrent` | 最大并发节点数 | 10 | 根据服务器配置调整 |
| `--proof-interval` | 每个节点提交证明后的等待时间（秒） | 1 | 3-5 |
| `--workers-per-node` | 每个节点的工作线程数 | 1 | 保持为1 |
| `--proxy-file` | 代理列表文件路径 | - | proxy.txt |
| `--rotation` | 启用节点轮转功能 | false | 建议启用 |
| `--refresh-interval` | 显示刷新间隔（秒） | 1 | 1-3 |

## 内存优化技巧

- 减少 `--max-concurrent` 参数值可显著降低内存占用
- 增加 `--proof-interval` 值到5-10秒可减少429错误
- 使用 `--proxy-file` 参数指定代理文件，实现IP轮换
- 启用 `--rotation` 参数可在节点成功或遇到429错误时自动切换节点

## 性能对比

| 指标 | 官方版本 | 优化版本 | 提升 |
|------|---------|---------|------|
| 单节点内存占用 | 约150MB | 约80MB | 降低约47% |
| 10节点内存占用 | 约1.5GB | 约700MB | 降低约53% |

## 常见问题

1. **内存不足错误**：减少 `--max-concurrent` 参数值
2. **429错误过多**：增加 `--proof-interval` 值，使用代理文件和节点轮转功能
3. **节点状态显示异常**：使用 `--verbose` 参数查看详细日志

## 致谢

特别感谢@hua_web3的代码贡献和Nexus Network社区的支持。