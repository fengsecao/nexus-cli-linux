# Nexus Network 0.10.10 多节点内存优化版

基于 Nexus Network CLI 0.10.10 版本的多节点内存优化实现，解决高内存占用和多节点管理问题。

## 主要特性

- **多节点管理**：支持从文件批量启动多个节点ID
- **高级错误处理**：针对429限流错误进行优化处理
- **节点轮转功能**：支持节点ID自动轮转，提高成功率
- **代理轮换功能**：支持动态代理池，每次请求使用不同IP

## 安装指南

### 环境要求
- Ubuntu 24.04 或更高版本（编译需要）
- 至少36GB内存空间

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

# 高级配置（推荐生产环境使用）
./target/release/nexus-network batch-file --file nodes/nodes.txt --max-concurrent 8 --proof-interval 5 --rate 1.0 --min-rate 0.2 --max-rate 3.0 --proxy-file proxy.txt --rotation --disable-logs

### 远程计算模式（client/server/normal）
支持将“取任务/提交证明”与“生成证明”分离，低配机器负责取任务并把任务发到强机计算。

- 运行模式通过 `--mode` 指定（默认 `normal`）：
  - `normal`: 本机取任务+本机计算（兼容原有行为）
  - `client`: 本机只取任务，转发到远端计算，拿到证明后本机提交
  - `server`: 本机作为远程计算服务，接收作业并生成证明

示例：

1) 强机（远程计算服务端）
```bash
./target/release/nexus-network --mode server \
  --listen-addr 0.0.0.0:9090 \
  --server-max-concurrency 8 \
  --server-job-timeout-secs 3600 \
  --server-auth-token abc123
```

2) 任务机（客户端）
```bash
./target/release/nexus-network start --mode client \
  --remote-url http://强机IP:9090 \
  --remote-auth-token abc123 \
  --remote-poll-ms 1000 \
  --remote-timeout-secs 3600
```

说明：
- 服务端端口可自定义，使用 `--listen-addr 0.0.0.0:PORT`。
- 客户端指向服务端地址 `--remote-url http://host:PORT`。
- 服务端监视器会打印：排队/运行/成功/失败、并发上限、近5分钟吞吐、最近错误与运行中前10作业。
- 客户端监视器在 client 模式会显示远程阶段：`已接收/计算中/回传中`，并追加统计 `远程: 收/完/败`。
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
| `--rate` | 设置API请求速率（每秒请求数） | 1.0 | 0.5-2.0 |
| `--min-rate` | 最小API请求速率（每秒请求数） | 0.2 | 0.2-0.5 |
| `--max-rate` | 最大API请求速率（每秒请求数） | 5.0 | 2.0-5.0 |
| `--verbose` | 启用详细日志输出 | false | 调试时启用 |
| `--disable-logs` | 禁用所有日志输出 | false | 生产环境可启用 |
| `--env` | 设置运行环境（prod/staging） | prod | prod |

### 新增参数（远程模式 & 调度）

| 参数 | 说明 | 默认值 | 建议值 |
|------|------|--------|--------|
| `--mode` | 运行模式：normal/client/server | normal | 依场景选择 |
| `--listen-addr` | 服务端监听地址（server） | 0.0.0.0:8088 | 自定义端口 |
| `--server-max-concurrency` | 服务端并发作业上限（server） | 1 | CPU核数或核数/2起步 |
| `--server-job-timeout-secs` | 服务端作业超时（server） | 0(不超时) | 1800-7200 |
| `--server-auth-token` | 服务端鉴权令牌（server） | - | 必要时启用 |
| `--remote-url` | 远程计算服务地址（client） | http://127.0.0.1:8088 | 指向强机地址 |
| `--remote-auth-token` | 客户端鉴权令牌（client） | - | 与服务端一致 |
| `--remote-poll-ms` | 客户端轮询间隔（client） | 1000 | 1000-2000 |
| `--remote-timeout-secs` | 客户端总超时（client） | 3600 | 1800-7200 |
| `--fetch-concurrency` | 全局“取任务”并发许可数 | 10 | 1-5(保守) |

说明：`--fetch-concurrency` 不设置时默认 10，亦可通过环境变量 `NEXUS_FETCH_CONCURRENCY` 设置。

## 内存优化技巧

- 减少 `--max-concurrent` 参数值可显著降低内存占用
- 增加 `--proof-interval` 值到5-10秒可减少429错误
- 使用 `--proxy-file` 参数指定代理文件，实现IP轮换
- 启用 `--rotation` 参数可在节点成功或遇到429错误时自动切换节点
- 设置合理的 `--rate` 值可平衡请求频率和成功率
- 使用 `--min-rate` 和 `--max-rate` 参数可动态调整请求速率
- 在大规模部署时开启 `--disable-logs` 可减少I/O开销

### 远程模式优化

- 服务端的 `--server-max-concurrency` 建议从 CPU 物理核数或核数/2 起步，观察内存/吞吐后再提升。
- 客户端机器多时可适当增大 `--remote-poll-ms`，降低服务端 HTTP 负载。
- 监视器可根据“远程: 收/完/败”判断吞吐与失败情况；服务端监视器可根据吞吐与拥堵提示扩容。

## 常见问题

1. **内存不足错误**：减少 `--max-concurrent` 参数值
2. **429错误过多**：增加 `--proof-interval` 值，使用代理文件和节点轮转功能
3. **节点状态显示异常**：使用 `--verbose` 参数查看详细日志
4. **请求速度过慢**：适当增加 `--rate` 参数值，但注意不要超过限制
5. **编译错误**：确保使用Ubuntu 24.04或更高版本系统

6. **端口更改**：服务端用 `--listen-addr 0.0.0.0:PORT`，客户端用 `--remote-url http://host:PORT`。
7. **取任务排队**：通过 `--fetch-concurrency` 控制全局取任务并发（默认10），队列/退避倒计时会在监视器提示。
8. **远程作业阶段**：client 模式会显示 `已接收/计算中/回传中... (Xs)`，并统计 `远程: 收/完/败`。




## 致谢

特别感谢@hua_web3的代码贡献和Nexus Network社区的支持。

## 联系方式

- 推特：[@zjw023](https://x.com/zjw023)