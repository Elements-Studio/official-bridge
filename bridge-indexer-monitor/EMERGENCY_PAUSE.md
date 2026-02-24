# Emergency Pause 紧急暂停功能

## 概述

当检测到可能的密钥泄露（例如在跨链过程中只收到 mint 事件而没有对应的 deposit 事件）时，系统会触发紧急暂停警报，并提供执行指令。

## 检测场景

假设 ETH → Starcoin 跨链:
- **正常情况**: Indexer 先收到 ETH 侧的 `TokenDepositEvent`，然后收到 Starcoin 侧的 `MintEvent`
- **异常情况**: Indexer 只收到 Starcoin 侧的 `MintEvent`，没有对应的 deposit
- **结论**: 这代表可能密钥泄露了，需要紧急暂停整个桥

## 配置方式

### 方式一: 使用预签名 (推荐)

这种方式最安全，因为私钥不需要存储在服务器上。

1. 创建配置文件 `emergency-signatures.yaml`:

```yaml
# ETH 链暂停的预签名
eth_pause_signatures:
  - signature: "0x1234567890abcdef..."  # 委员会成员1的签名
    voting_power: 2500
    signer: "0xAbCdEf1234567890..."
  - signature: "0xfedcba0987654321..."  # 委员会成员2的签名
    voting_power: 2500
    signer: "0x9876543210FeDcBa..."

# Starcoin 链暂停的预签名
starcoin_pause_signatures:
  - signature: "0xabcdef1234567890..."
    voting_power: 2500
    signer: "0x1234567890abcdef..."
  - signature: "0x0987654321fedcba..."
    voting_power: 2500
    signer: "0xfedcba0987654321..."
```

2. 在监控配置中引用:

```yaml
emergency_pause:
  enabled: true
  detection_window_seconds: 300  # 5分钟检测窗口
  auto_pause_enabled: false      # 不自动执行，只提供指令
  pause_signatures:
    path: "emergency-signatures.yaml"
```

### 方式二: 使用私钥文件 (不推荐)

这种方式风险较高，私钥会存储在服务器上。

1. 创建配置文件 `emergency-keys.yaml`:

```yaml
# 委员会成员
members:
  - voting_power: 5000
    eth_private_key: "0x1234567890abcdef..."
    starcoin_private_key: "0xabcdef1234567890..."

# ETH 合约配置
eth:
  chain_id: 1  # Mainnet
  rpc_url: "https://eth-mainnet.alchemyapi.io/v2/YOUR_KEY"
  bridge_proxy_address: "0x..."

# Starcoin 合约配置
starcoin:
  chain_id: 251  # Barnard
  rpc_url: "https://barnard-seed.starcoin.org"
  bridge_address: "0x..."
```

2. 在监控配置中引用:

```yaml
emergency_pause:
  enabled: true
  detection_window_seconds: 300
  auto_pause_enabled: false
  keys_file: "emergency-keys.yaml"
```

## 工作流程

1. **检测阶段**: 
   - Monitor 持续跟踪所有 deposit 和 mint 事件
   - 维护 pending 状态队列

2. **异常判定**:
   - 当某个 mint 事件在检测窗口时间后仍找不到对应 deposit
   - 系统判定为异常情况

3. **告警通知**:
   - 发送紧急警报到 Telegram (带 @everyone 提醒)
   - 记录详细的异常信息

4. **手动执行**:
   - 系统提供完整的 bridge-cli 命令
   - 运维人员检查后手动执行暂停命令

## 执行示例

当检测到异常时，系统会输出类似以下的指令:

```bash
# ETH 链暂停
bridge-cli governance-execute \
  --config-path bridge-cli-config.yaml \
  --eth-chain-id 1 \
  --signatures 0x1234...,0xabcd... \
  emergency-button \
  --nonce 0 \
  --action-type Pause

# Starcoin 链暂停
bridge-cli governance-execute \
  --config-path bridge-cli-config.yaml \
  --starcoin-chain-id 251 \
  --signatures 0x5678...,0xef01... \
  emergency-button \
  --nonce 0 \
  --action-type Pause
```

## 投票权阈值

- **紧急暂停**: 450/10000 (4.5%) - 低阈值，快速响应
- **恢复运行**: 5001/10000 (50.01%) - 高阈值，谨慎决策

参考: `starcoin-bridge-vm-types/src/bridge/bridge.rs`
- `APPROVAL_THRESHOLD_EMERGENCY_PAUSE = 450`
- `APPROVAL_THRESHOLD_UNPAUSE = 5001`

## 安全考虑

1. **为什么不自动执行?**
   - 紧急暂停是重大操作，影响整个桥的运行
   - 可能存在误判情况
   - 需要人工验证后再执行

2. **预签名方式的优势**:
   - 私钥离线存储，降低泄露风险
   - 签名提前准备好，紧急时可快速执行
   - 符合冷钱包最佳实践

3. **检测窗口的意义**:
   - 考虑到区块确认延迟
   - 避免网络抖动导致误报
   - 默认 5 分钟，可根据实际情况调整

## 测试建议

1. **单元测试**: 验证检测逻辑
2. **集成测试**: 使用测试网验证完整流程
3. **演练**: 定期进行紧急响应演练

## 恢复流程

暂停后如需恢复:

```bash
# 需要 >50% 投票权
bridge-cli governance-execute \
  emergency-button \
  --action-type Unpause
```

## 相关代码

- 检测逻辑: `bridge-indexer-monitor/src/monitor/emergency_pause.rs`
- 配置结构: `bridge-indexer-monitor/src/monitor/config.rs`
- 通知功能: `bridge-indexer-monitor/src/monitor/telegram.rs`
- 执行工具: `bridge-cli/src/lib.rs` (governance 相关函数)
