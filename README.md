# Nexus Network 0.8.18 多节点内存优化版 (Ubuntu 24.04专用)

> 参考@hua_web3的代码修改: https://github.com/huahua1220/nexus-cli-linux

基于 Nexus Network CLI 0.8.18 版本的多节点内存优化实现，专为Ubuntu 24.04环境优化，解决高内存占用和多节点管理问题。其他操作系统未经完整测试，不保证兼容性。

## 📋 主要特性

- ✅ **Ubuntu 24.04专用**：针对Ubuntu 24.04环境进行完整测试和优化
- ✅ **内存优化**：单节点比官方版节省 30%-50% 内存占用
- ✅ **多节点管理**：支持从文件批量启动多个节点ID
- ✅ **自动内存碎片整理**：智能监控和处理内存碎片问题
- ✅ **高级错误处理**：特别针对 429 限流错误进行优化处理（最多重试12次）
- ✅ **无限重试机制**：节点失败后会自动重试，保障稳定运行
- ✅ **实时状态监控**：固定行显示各节点状态和内存使用情况
- ✅ **节点轮转功能**：支持节点ID自动轮转，提高成功率并降低429错误
  - 当节点成功提交证明或连续遇到429错误时自动切换
  - 智能管理节点队列，确保资源高效利用
  - 实时显示每个节点的成功次数和429错误次数
- ✅ **代理轮换功能**：支持动态代理池，每次请求使用不同IP，有效避免429限流错误
  - 支持多种代理格式，包含带国家标识的代理
  - 无需预先测试，自动跳过不可用代理
  - 代理失败时自动回退到直连模式

## 🚀 安装指南

### Ubuntu 24.04环境（推荐）

> **注意**：本工具仅在Ubuntu 24.04环境下进行了完整测试，强烈建议使用此环境。

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

### 其他操作系统（未经完整测试）

> **警告**：以下环境未经完整测试，可能存在兼容性问题。

#### 其他Linux发行版
按照Ubuntu的安装步骤尝试，但可能需要安装额外依赖。

#### Windows环境
不建议在生产环境使用Windows版本，仅供测试：

```powershell
# 安装Rust环境
# 访问 https://rustup.rs/ 下载并运行安装程序

# 克隆代码库
git clone https://github.com/zjw0231/nexus-cli-linux
cd nexus-cli-linux

# 编译发布版本（可能需要额外配置）
cargo build --release
```

#### macOS环境
未经测试，不建议使用。如需尝试，请参考Linux安装步骤。

## 💻 使用方法

### 单节点模式
```bash
# 运行单个节点（自动读取或创建密钥）
./target/release/nexus-network start --node-id <节点ID>

# 使用代理文件
./target/release/nexus-network start --node-id <节点ID> --proxy-file proxy.txt

# Windows下使用
.\target\release\nexus-network.exe start --node-id <节点ID>
```

### 批量节点模式（推荐）
```bash
# 创建节点列表示例文件
mkdir -p nodes

# 运行批量节点模式
./target/release/nexus-network batch-file --file nodes/nodes.txt --max-concurrent 10 --proof-interval 5 --workers-per-node 1

# 使用代理文件
./target/release/nexus-network batch-file --file nodes/nodes.txt --max-concurrent 10 --proof-interval 5 --workers-per-node 1 --proxy-file proxy.txt

# 启用节点轮转功能
./target/release/nexus-network batch-file --file nodes/nodes.txt --max-concurrent 10 --proof-interval 5 --workers-per-node 1 --rotation

# Windows下使用
.\target\release\nexus-network.exe batch-file --file nodes\nodes.txt --max-concurrent 10 --proof-interval 5 --workers-per-node 1
```

### 代理功能使用说明

代理功能可以有效避免429限流错误，提高节点稳定性：

1. **准备代理文件**：创建一个文本文件（默认为`proxy.txt`），每行一个代理
2. **启动时指定代理文件**：使用`--proxy-file`参数指定代理文件路径
3. **工作原理**：
   - 系统会为每个HTTP请求随机选择一个代理
   - 如果代理连接失败，会自动尝试下一个代理
   - 所有代理均不可用时，会回退到直连模式
   - 代理轮换完全自动化，无需手动干预

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

系统会自动从密码中提取国家信息（如果存在`_country-`标记），但这仅用于显示，不影响代理功能。每次请求会随机选择一个代理，有效避免429限流错误。

### 节点轮转功能使用说明

节点轮转功能可以提高节点成功率并有效避免429限流错误：

1. **启用方法**：使用`--rotation`参数启用节点轮转功能
2. **工作原理**：
   - 系统会为每个线程维护一个活动节点队列
   - 当节点成功提交证明或连续遇到429错误两次时，自动切换到下一个节点
   - 实时显示每个节点的成功次数和429错误次数
   - 轮转完全自动化，无需手动干预
3. **最佳实践**：
   - 建议在批量模式下使用节点轮转功能
   - 节点列表文件中建议包含300个以上的节点ID，以确保充分轮转
   - 可与代理轮换功能结合使用，进一步提高成功率

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
| `--proxy-file` | 代理列表文件路径 | - | proxy.txt |
| `--rotation` | 启用节点轮转功能 | false | 建议启用 |

## 🔧 内存优化原理

1. **全局证明器实例共享**：避免每个节点重复创建证明器实例
2. **智能内存碎片整理**：监控内存使用并自动优化碎片
3. **资源池复用**：使用对象池模式减少内存分配和释放
4. **网络请求优化**：减少429错误和优化重试策略
   - 最多重试12次429错误
   - 使用30-60秒随机等待时间
   - 智能退避策略
   - 代理轮换功能，每次请求自动随机选择不同IP

## 📊 性能对比

| 指标 | 官方版本 | 优化版本 | 提升 |
|------|---------|---------|------|
| 单节点内存占用 | 约150MB | 约80MB | 降低约47% |
| 10节点内存占用 | 约1.5GB | 约700MB | 降低约53% |
| 429错误重试 | 简单重试 | 智能策略+代理轮换 | 大幅提高成功率 |
| 多节点管理 | 不支持 | 支持 | 大幅提升 |

## 🖥️ 适用环境

- ✅ **Ubuntu 24.04+**（推荐，经过完整测试）
- ⚠️ 其他Linux发行版（未经完整测试，可能需要调整）
- ⚠️ Windows（未经测试，不保证兼容性）
- ⚠️ macOS（未经测试，不保证兼容性）

> **重要提示**：本工具仅在Ubuntu 24.04环境下进行了完整测试。其他操作系统可能存在兼容性问题，使用前请自行测试。

## 🔄 常见问题

1. **问题**: 遇到"内存不足"错误
   **解决方案**: 减少 `--max-concurrent` 参数值

2. **问题**: 429错误过多
   **解决方案**: 
   - 增加 `--proof-interval` 值到5-10秒
   - 使用 `--proxy-file` 参数指定代理文件，实现IP轮换
   - 确保代理文件中有足够多的可用代理

3. **问题**: 节点状态显示异常
   **解决方案**: 使用 `--headless` 模式运行，查看详细日志

4. **问题**: 代理连接失败
   **解决方案**: 
   - 检查代理格式是否正确，确保使用正确的格式：`host:port:username:password`
   - 确保代理服务器可用且能正常连接
   - 如果代理需要认证，确保用户名和密码正确

5. **问题**: 在非Ubuntu 24.04系统上编译或运行失败
   **解决方案**:
   - 本工具仅在Ubuntu 24.04上经过完整测试
   - 在其他Linux系统上，尝试安装必要的依赖：`build-essential`、`libssl-dev`、`pkg-config`
   - 在Windows上，确保安装了最新版本的Visual Studio Build Tools和C++开发工具
   - 考虑使用Docker容器运行Ubuntu 24.04环境

## 📝 改进计划

- [ ] 添加监控API和Web界面
- [ ] 支持动态调整并发节点数
- [ ] 增加节点失败自动替换功能
- [x] 添加代理轮换功能，避免429错误
- [x] 添加节点轮转功能，提高成功率
- [ ] 支持SOCKS5代理协议
- [ ] 添加代理自动测试和评分机制
- [ ] 更精细的内存使用控制
- [ ] 添加Docker支持

## 📜 许可证

MIT License

## 🙏 致谢

特别感谢@hua_web3的代码贡献和Nexus Network社区的支持。