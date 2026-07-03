# Lore Server 服务端功能分析

> 仓库：`EpicGames/lore`（MIT 协议，v0.8.5-nightly）  
> 分析范围：`lore-server` crate（`D:\WorkBuddySpace\lore\lore-server\`）

## 1. 项目定位

Lore 是 Epic Games 开源的下一代集中式版本控制系统，定位为 **UEFN（Unreal Editor for Fortnite）内置 VCS 的开源对等版本**。核心模型是 **内容寻址的 Merkle Tree + 不可变 revision 链**，专门为代码 + 大体量二进制资产（如游戏资源）优化。

服务端 (`lore-server`) 是中央化、有状态的存储与协调服务，采用 **Tokio + Tonic (gRPC) + Quinn (QUIC) + Axum (HTTP)** 的多协议架构。

---

## 2. 网络协议面（3 层接入）

服务端同时暴露 **3 种网络协议 × 2 类端点（公共/内部）**。

| 协议 | 默认端口 | 实现 crate | 端点类型 | 用途 |
|------|---------|------------|---------|------|
| **gRPC** | 41337（公共）<br>41340（内部） | `tonic` 0.14 | 客户端 API、内部节点通信 | 主要业务接口 |
| **QUIC** | 41337（公共）<br>41340（内部） | `quinn` 0.11 | 大文件/分片传输、内部节点复制 | 高吞吐数据面 |
| **HTTP** | 41339 | `axum` 0.8 | 健康检查、Pre-signed URL | 运维 + 直传场景 |

> 内部端口（41340）默认 `enabled = false`，需 mTLS 启用，专用于跨节点 `ReplicationService` 流式分片复制。

### 2.1 gRPC 公共服务矩阵

服务定义在 `lore-proto/proto/`，实现分两层：
- **v1 基础服务层**（`src/grpc/{repository,revision,storage,environment}/v1/`）：稳定的最小 API 表面
- **复合服务层**（`src/grpc/handlers/`）：在 v1 之上编排，集成 hook、auth、telemetry

| Service | Proto 路径 | 主要 RPC |
|---------|-----------|----------|
| `RepositoryService` | `lore/repository/v1/repository.proto` | `RepositoryCreate / Delete / Get / List / MetadataGet / MetadataSet` |
| `RevisionService` | `lore/revision/v1/revision.proto` | `BranchCreate / Delete / Get / List / Push / MetadataGet / MetadataSet / RevisionList` |
| `ForwardedRevisionService` | `lore/revision/v1/revision.proto` | 跨节点转发 Branch 操作（`BranchCreate / Get / Delete`） |
| `StorageService` | `lore/storage/v1/storage.proto` | `Get / GetMetadata / Put / Query / Verify / Copy / MutableLoad / MutableStore / MutableCompareAndSwap` |
| `LockService` | `lock.proto` | `Lock / Unlock / Query / Status / AdminLock` |
| `EnvironmentService` | `environment.proto` | `Get` |
| `ThinClientService` | `lore/thin_client/v1/thin_client.proto` | `RevisionInfo / RevisionTree / RevisionDiff / ContentDiff`（瘦客户端辅助） |
| `AdminService` | `admin.proto` | `ServerInfo / Obliterate` |
| `LoreAdminService` | `src/grpc/admin_service.rs` | 服务端管理面 |
| `NotificationService` | `lore_notification.proto` | 流式事件通知 |
| `UrcAuthApi` | `auth_api.proto` | 对外认证（仅作 gRPC 客户端调用 Epic 认证服务） |
| `RebacApi` | `rebac_api.proto` | 关系型权限客户端（CreateResource / DeleteResource） |

### 2.2 gRPC 内部服务（节点间）

`src/grpc/grpc_internal_server.rs`：
- `ReplicationService.Put(stream)` — 流式分片数据复制

### 2.3 QUIC 服务

- `QuinnServer`（`src/quic/quinn/quinn_server.rs`）
  - 自动从证书解析过期时间并打 metrics
  - 传输参数：BBR 拥塞控制、可配带宽/RTT 估算窗口（单流最大 25% 接收窗口）
  - 多 listener 并发接受（默认 10 个）
- 协议分派：`ServiceStore` + `ALPN` 协议协商
  - `StorageService`（`src/quic/storage_service.rs` + `storage_service_v4.rs`）— v3/v4 双版本并存的高性能分片读写
  - `ReplicationStoreService`（`src/quic/replication_store_service/`）— Get / Put / Query / ExistsBatch / Obliterate
- `client_monitor` — QUIC 客户端连接健康监控

### 2.4 HTTP 服务（Axum）

`src/http/server.rs`：
- 路由：`/health`、`/{repository_id}/...`（仓储级 API）、Pre-signed URL 兑换
- Pre-signed URL：HMAC-SHA256 签名 token（`presign_token.rs`），可绕过 JWT 鉴权直传对象存储
- 中间件链：JWT 验证 → correlation ID → tracing

---

## 3. 核心能力

### 3.1 内容寻址分片存储（Content-Addressed Fragment Store）

- 不可变、分块、按内容 hash 寻址
- 4 种 store 模式（`store_mode`）：
  - `local` — 本地磁盘
  - `remote` — 跨节点 QUIC
  - `composite` — 多子 store 聚合（`CompositeStoreBuilder`）
  - `replicated` — 跨节点复制（`ReplicatedStore`）
- 关键操作：Get / Put / Query / Verify / Copy / MutableLoad / MutableStore / MutableCompareAndSwap
- 修复能力：`Verify(heal=true)` — 自愈校验（`HealResult` 枚举）
- 跨仓库复制：`Copy` 支持指定 `target_context`，把分片复制到目标仓库命名空间

### 3.2 修订图（Revision Graph）

- **分支生命周期**：Create / Get（by id 或 name） / List / Delete（tombstone，幂等）/ Push
- **元数据 CAS**：乐观并发，`MetadataSet` 用 in-band CAS（成功时 `response.metadata == request.updated`，失败时返回当前值），**不抛 gRPC 错误**
- **修订历史**：`RevisionList` 流式分页，支持 identifier 锚点（`number == 0` 自动解析为 branch tip）或 signature cursor，新旧双向前进
- **快进合并**：`BranchPush` 支持 `force` 和 `fast_forward_merge` 两种语义

### 3.3 分布式锁（Lock Service）

`lock.proto` 定义 5 个 RPC：
- `Lock` / `Unlock`：用户级锁
- `Query` / `Status`：查询（按 branch / owner / description 过滤）
- `AdminLock`：管理员代他人加锁（需 `migrate` 权限）
- 资源结构：`Resource { branch, hash, description }`，按 `(branch, hash)` 唯一定位
- 锁后端：可插拔（local / DynamoDB 插件），通过 `lock_store.plugin` 配置

### 3.4 权限与鉴权

- **JWT 鉴权**（`src/auth/`）：JWK 远程拉取 + 本地缓存 + RS256 签名验证 + Axum 中间件 + gRPC 拦截器
  - `AuthorizationToken` 携带 `ResourcePermission[]`（含通配符 `urc-*`）
- **外部认证客户端**（`src/authnz/auth.rs`）：调用 Epic `UrcAuthApi` 验证用户身份、查询权限
- **关系型权限**（`src/authnz/rebac.rs`）：`RebacApiClient` — CreateResource / DeleteResource
- **授权粒度**：
  - `is_owner_or_admin`
  - `can_obliterate`（需 `obliterate` 权限）
  - `can_admin_lock`（需 `migrate` 权限）
  - 通配符 `urc-*` token 可对所有仓库生效

### 3.5 钩子系统（Hooks）

`src/hooks/` — 5 个钩子点：

| HookPoint | 触发时机 |
|-----------|----------|
| `BranchPush` | 分支 push 提交前 |
| `BranchCreate` | 新建分支前 |
| `BranchDelete` | 删除分支前 |
| `RepositoryCreate` | 新建仓库前 |
| `Obliterate` | 数据销毁前 |

**两阶段执行模型**：
- **Pre-handler**（同步）：可修改 context、可 veto、200ms 超时、panic 隔离
- **Post-handler**（异步）：tokio 任务中执行，不阻塞响应，错误只记录

钩子状态码映射：veto 时可指定 `StatusCode`（`PermissionDenied` / `FailedPrecondition` / `ResourceExhausted` / `InvalidArgument` / `Aborted` / `Internal`），自动转 gRPC `Status`。

**自动发现**：`build.rs` 扫描 `src/hooks/*.rs` 自动注册。

### 3.6 插件系统（Plugins）

`src/plugins/` — 4 种插件类型 + 注册表：

| 插件类型 | 现有实现 | 用途 |
|----------|---------|------|
| `Immutable Store` | `aws`, `local` | 分片存储后端 |
| `Mutable Store` | `aws`, `local` | 分支/引用存储 |
| `Lock Store` | `dynamodb` | 分布式锁 |
| `Topology` | `consul`（hashicorp）, `fixed`, `rotating_id_fixed`, `composite` | 节点发现 |

`build.rs` 自动扫描 `src/plugins/*.rs` 生成 `mod.rs`，新插件只需实现 trait + `register()` 函数。

### 3.7 节点拓扑与复制

- **拓扑策略**（`src/topology/`）：
  - `fixed`：静态配置 peer 列表
  - `rotating_id_fixed`：带 rotation id 的固定拓扑（滚动升级用）
  - `composite`：组合多种拓扑源
- **节点间复制**（`src/quic/replication_store_service/`）：
  - 服务端：`ReplicationStoreService`（流式分片读写）
  - 客户端：`ClientContainer` 多连接池 + 健康监控 + 故障转移
- **GRPC 转发**（`src/grpc/forwarded_requests/`）：把客户端请求代理到其他 peer 节点

### 3.8 缓存层

- `src/cache/revision.rs` — 修订页缓存（在 v1 RevisionList 流程中按段对齐）
- 存储层 `Fragment` 缓存命中通过 CAS 内容寻址天然去重

### 3.9 通知

- `src/notification/`：基于 gRPC 流的事件订阅
- `lore_proto/lore_notification.proto` + `src/grpc/notification_service.rs`
- 写入侧：所有写 handler 在 commit 后通知 `NotificationSender`

### 3.10 Pre-signed URL（直传）

`src/http/presign_token.rs` + `src/http/presigned/`：
- 客户端拿到 HMAC 签名的 token，绕过 JWT 直接 GET/PUT 远端对象
- 适用场景：CI 上传产物、CI/CD 拉取构建依赖、第三方集成
- 关键字段：`repository` + `address`（CAS hash）+ `expires_at` + 可选 content-type/encoding/disposition
- `key_id` 派生自 BLAKE3(raw_key) 前 16 hex 字符，支持多 key 轮换

---

## 4. 横切关注点

### 4.1 遥测（`src/telemetry/`）

- **链路追踪**：`tracing` + `tracing-opentelemetry` + `tracing-ecs`（ECS 格式日志）
- **OpenTelemetry**：OTLP gRPC 导出 + `ResourceDetector` 自动填充
- **Tokio 指标**：`tokio-metrics` 集成 `OtelTokioRuntimeMetrics`
- **QUIC 连接指标**：`track_connection_stats`
- **证书过期监控**：`parse_certificate_info` + 定时 gauge
- **User-Agent 过滤**：`UserAgentFilter` 避免高基数污染 metrics
- **Correlation ID**：跨 gRPC / HTTP 的请求级追踪（`CORRELATION_ID_HEADER`）

### 4.2 配置（`src/settings.rs` + `config/default.toml`）

6 层覆盖（**后写者赢**）：
1. 编译内置 `default.toml`（`include_str!` 烧进二进制）
2. 磁盘 `default.toml`（`LORE_CONFIG_PATH` 目录）
3. 环境配置 `{LORE_ENV}.toml`
4. 区域覆盖 `{LORE_ENV}_{LORE_PLATFORM_REGION}.toml`
5. 本地覆盖 `local.toml`
6. 环境变量 `LORE__*`（`__` 作分隔符）

### 4.3 TLS（`src/tls.rs`）

- 客户端 mTLS 证书加载
- 支持 SNI 和证书链
- QUIC 端使用 `rustls` + `ring` 加密库（避免 aws-lc-sys 在 Windows 上的构建问题）

### 4.4 执行上下文（`src/execution_state.rs`）

`ServerExecutionState` 维护服务端运行时状态（启动时间、版本、配置哈希），通过 `gRPC ServerInfo` 暴露。

### 4.5 协议层（`src/protocol/`）

- `AttributeMap`：每个请求携带的上下文（repository_id、auth token）
- `replication_store.rs`：节点间复制消息编解码
- `storage.rs`：存储消息
- `attribute_map.rs`：跨层传递的元数据载体

### 4.6 遗留兼容（`src/legacy/`）

保留旧版 gRPC proto（`legacy/proto/`）和生成代码，用于向前兼容。

---

## 5. 关键设计模式

| 模式 | 应用 |
|------|------|
| **CAS 一致性** | RepositoryMetadataSet / BranchMetadataSet — 失败用 in-band 返回而非错误码 |
| **乐观重试幂等** | 所有 Create RPC 要求调用方预生成 UUID（`id`），重试时返回 ALREADY_EXISTS |
| **分片 + 复制** | 任何 `Put` 触发跨节点复制到 topology 中的 peer |
| **插件 + 钩子双轨扩展** | 存储/拓扑用 plugin（编译期注册），业务事件用 hook（运行期订阅） |
| **读写路径分离** | gRPC 走 Axum-style Handler 链，QUIC 走流式 StreamHandler |
| **传输多样性 + 统一抽象** | gRPC / QUIC / HTTP 三种接入都最终落到 `ImmutableStore` / `MutableStore` 抽象 |
| **多副本 mTLS 隔离** | 公共端口 41337 + 内部端口 41340 物理隔离，mTLS 强制 |

---

## 6. 端到端数据流（一次 client 写操作）

```
Client (gRPC / QUIC)
    │
    ▼
[axum middleware / tonic interceptor]
    │  → JWT 验证、Correlation ID 注入
    ▼
gRPC Handler (e.g. branch_create.rs)
    │  → Pre-hook 触发（HookDispatcher.dispatch）
    │  → 失败则 hook_error_to_status 映射 gRPC 状态码
    ▼
Revision 核心逻辑 (lore-revision crate)
    │  → 调 ImmutableStore.put / MutableStore.CAS
    ▼
Store 层 (lore-storage)
    │  → 本地落盘 / S3 / 转发到 remote
    │  → 触发 replication (QUIC 内部端口)
    ▼
Post-hook (异步, 不阻塞响应)
    ▼
Notification → 订阅者
    ▼
Response 回 Client
```

---

## 7. 部署形态

- **本地 demo 模式**：`LORE_DEMO=1` 一行安装
- **单机生产**：local store + fixed topology（单节点）
- **集群生产**：S3 + DynamoDB（immutable/mutable/lock） + Consul（topology） + 内部 mTLS
- **systemd**：`init/lore.service` unit
- **Docker**：`Dockerfile` 镜像

---

## 8. 总结：服务端"做了什么"的一句话版本

> **`lore-server` 是一个基于 gRPC（API）+ QUIC（大文件传输）+ HTTP（运维/pre-signed）的多协议中央化 VCS 后端，提供内容寻址分片存储、修订图与分支管理、分布式锁、节点间复制、JWT/ReBAC 鉴权、插件化存储/拓扑、事件钩子与 OpenTelemetry 遥测的完整能力栈。**
