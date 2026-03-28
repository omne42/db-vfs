# 系统边界

## 目标

`db-vfs` 是一个带硬安全边界的 DB-backed virtual filesystem。它不是通用数据库抽象层，也不是通用配置框架。

## 本仓负责什么

- `read`、`write`、`patch`、`delete`、`glob`、`grep` 的 VFS 语义
- `db-vfs-core::policy::VfsPolicy` 及其校验
- 路径合法性、traversal、secrets redaction、scan budgets
  - `max_io_ms` 只约束非 scan 请求与对应的 DB 等待预算。
  - `max_walk_ms` 负责 `glob` / `grep` 的 scan runtime 预算。
  - scan 侧 DB pool wait/connect 仍受 `max_io_ms` 约束；SQLite `busy_timeout` / Postgres `statement_timeout` 跟随 scan runtime 预算。
  - `max_walk_ms = None` 只表示 scan runtime 不设上限；不会把 DB pool wait/connect 也放成无界。
  - 公开 scan diagnostics 不暴露 secret-denied 路径计数；这类细节只留在内部审计语义里。
  - crate 公开构造器里的 `SecretRedactor` / `TraversalSkipper` 必须与同一份 `VfsPolicy` 同源；不允许用外部自定义 matcher 绕过 policy 边界。
  - `secrets.replacement` 不允许控制字符；多行 secret redaction 必须保住 `read` / `grep` 的行语义。
- SQLite / Postgres 存储适配和 migrations
- HTTP service 的 auth、rate limit、audit、request-id、trust mode
- 面向运维和集成者的 API / policy / security 文档

## 当前仍在本仓本地实现的通用能力

- `service/src/policy_io.rs`
  - 自己做配置文件读取、大小限制、env interpolation，以及 JSON/TOML 识别与解析。
  - 当前这里没有接入 YAML。
- `service/src/server/auth.rs`
  - 自己做 bearer token 的 `sha256:<hex>` 解析、摘要匹配和 workspace allowlist 约束。

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
