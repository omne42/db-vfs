# 系统边界

## 目标

`db-vfs` 是一个带硬安全边界的 DB-backed virtual filesystem。它不是通用数据库抽象层，也不是通用配置框架。

## 本仓负责什么

- `read`、`write`、`patch`、`delete`、`glob`、`grep` 的 VFS 语义
- `db-vfs-core::policy::VfsPolicy` 及其校验
- 路径合法性、traversal、secrets redaction、scan budgets
  - `max_io_ms` 约束非 scan 请求、DB pool wait/connect，以及 service 启动 migration 的 connect/lock 预算。
  - `max_walk_ms` 负责 `glob` / `grep` 的 scan runtime 预算；配置缺字段时默认是 `Some(2000)`。
  - scan 侧 DB pool wait/connect 仍受 `max_io_ms` 约束；SQLite `busy_timeout` / Postgres `statement_timeout` / `lock_timeout` 跟随当前请求预算。启动 migration 也必须复用有界预算，不能无限挂死在锁竞争上。
  - `max_walk_ms = None` 只表示 scan runtime 不设上限；不会把 DB pool wait/connect 也放成无界。
  - 公开 scan diagnostics 不暴露 secret-denied 路径计数；这类细节只留在内部审计语义里。
  - 无 redaction 规则的 ranged `read` 必须优先走 store chunk 读取，避免为了几行内容整文件 materialize。
  - crate 公开构造器里的 `SecretRedactor` / `TraversalSkipper` 必须与同一份 `VfsPolicy` 同源；不允许用外部自定义 matcher 绕过 policy 边界。
  - `secrets.replacement` 不允许控制字符；多行 secret redaction 必须保住 `read` / `grep` 的行语义。
  - redaction 路径的原始输入和中间结果都必须受 `max_read_bytes` 约束；当 ranged `read`
    或 `grep` 需要 whole-file redaction 时，raw content 和 redacted whole-file intermediate
    任何一侧超出预算都必须显式失败/跳过，而不是继续无界分配。
  - scan 内存预算要按 redaction 放大系数计入；启用 `secrets.redact_regexes` 时，service
    需要按每个 in-flight scan 最多同时持有一份原文和一份有界 redacted copy 来估算容量，
    不能只按单 buffer 估算。
- SQLite / Postgres 存储适配和 migrations
- HTTP service 的 auth、rate limit、audit、request-id、trust mode
  - service `Router` 可以带或不带 `ConnectInfo<SocketAddr>` 运行；缺失时只影响 `peer_ip`
    与 per-IP rate-limit 归桶，不应让 handler 在运行时失败。
  - service 启动会先完成 policy/auth/audit/matcher 组合校验，再触发 DB pool 建立与 migration；
    坏配置不应先对后端产生副作用。
  - `max_concurrency_io` / `max_concurrency_scan` 的 permit 必须在 JSON body buffering / decode
    之前获取；慢或恶意的请求体不应绕过 service 的并发边界。
  - auth 明文 token 与 HTTP `Authorization: Bearer <token>` 走同一套 token68 语义；
    不可能通过 Bearer header 发送的 env token 必须在启动时直接拒绝。
  - `auth.tokens[*].token_env_var` 只承载明文 bearer token；预哈希输入只允许放在
    `auth.tokens[*].token`。把字面 `sha256:<hex>` 放进 `token_env_var` 必须在启动时直接拒绝，
    不能被当成预哈希 token 接受。
  - `workspace_id` 是字面命名空间，不是 glob；`*` 保留给 auth `allowed_workspaces`
    模式语法，避免授权边界出现“字面 workspace 名”和“通配规则”混淆。
  - `audit.required = true` 是运行期 fail-closed 语义：请求必须等到对应 audit 记录
    append+flush 成功才返回；对应的 `max_concurrency_*` permit 会一直持有到 audit wait
    结束，避免请求在“已执行但未完成审计”时提前把并发槽位还回去。
  - required audit append+flush 会消费同一条请求的剩余运行期预算；超出剩余预算、worker
    丢失或写失败都会转成稳定 `503 audit_unavailable` 故障，而不是静默丢日志或
    panic/连接级失败。
  - `ValidatedVfsPolicy` 必须包含“policy-derived matcher 可构建”这个不变量，这样
    `DbVfs::new_with_matchers_validated` 这类兼容构造器就不会在 matcher fallback 路径上
    panic，也不需要把这类状态延后到运行期才暴露。
  - 审计 redaction 对 malformed secret-ish path 必须保守遮蔽；即使请求最终会因为
    traversal/control-char 等原因被拒绝，也不能把原始 secret 片段直接写进 JSONL。
- 面向运维和集成者的 API / policy / security 文档

## 当前仍在本仓本地实现的通用能力

- `service/src/policy_io.rs`
  - 自己做配置文件读取、大小限制、env interpolation，以及 JSON/TOML 识别与解析。
  - 当前这里没有接入 YAML。
- `service/src/server/auth.rs`
  - 自己做 bearer token 的 `sha256:<hex>` 解析、token68 校验、摘要匹配和 workspace allowlist 约束。
- `src/store/mod.rs`
  - 仍保留 legacy `list_metas_by_prefix_page` compatibility fallback，但它只保证正确性，
    不保证大前缀 scan budget / 性能语义；fallback 命中时现在会显式告警，不再静默退化。

这些能力已经表现出复用性，但当前仍然直接服务于 `VfsPolicy` 与 `db-vfs` 的服务边界；在真正抽离之前，不要把它们包装成假通用 abstraction。

## 候选复用点

- 如果多个仓库都需要“严格格式识别 + 大小限制 + env interpolation + typed schema parse”，应优先收敛到 `omne_foundation` 的 config 领域，而不是每个服务各写一份 `policy_io`。
- 如果多个仓库都需要一致的 hash / digest / audit chain primitives，应优先沉到 `omne-runtime`，而不是继续在服务层手写。

## 不负责什么

- 通用 config 领域基建
- 跨产品共享的 policy 元模型或治理规范
- agent runtime / gateway / orchestration 语义
- 业务系统自己的授权模型与组织策略

## 迁移原则

- 只抽离真正跨仓复用且不携带 VFS 语义的能力。
- `VfsPolicy` 字段、workspace 授权约束和具体文件操作语义继续留在本仓。
