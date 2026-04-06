# Source Layout

## Workspace Core

- `core/src/policy.rs`
  - core `VfsPolicy` 及其验证规则；只保留 VFS 领域语义。
- `core/src/path.rs`
  - 路径合法性与规范化规则。
- `core/src/traversal.rs` / `core/src/glob_utils.rs`
  - 扫描与匹配的低层规则。
- `core/src/redaction.rs`
  - secrets redaction 相关能力，以及 audit path/glob 字段的保守遮蔽辅助。
- `core/src/error.rs`
  - core 领域错误。

## Storage And VFS

- `src/vfs/`
  - 六个操作的实现与共享辅助逻辑。
- `src/store/sqlite.rs` / `src/store/postgres.rs`
  - 存储后端实现。
- `src/migrations.rs`
  - migration 装配与校验辅助。

## Service Layer

- `service/src/main.rs`
  - 服务入口与 CLI。
- `service/src/policy.rs`
  - service `ServicePolicy`、auth/audit/runtime limits 以及对 core `VfsPolicy` 的投影。
- `service/src/policy_io.rs`
  - 从文件加载并验证 policy。
- `service/src/server/auth.rs`
  - bearer token 校验与 workspace 授权。
- `service/src/server/rate_limiter.rs`
  - per-IP 限流。
- `service/src/server/audit.rs`
  - 审计事件落盘与 required-audit ack 协调。
- `service/src/server/handlers.rs` / `layers.rs` / `runner.rs` / `mod.rs`
  - HTTP handlers、middleware、请求预算/permit 生命周期和服务装配。
  - handlers 只负责把审计字段映射到 `core::redaction` 的窄 API，不再本地重写 deny-glob/path probe 语义。

## Data And Migrations

- `migrations/sqlite/` / `migrations/postgres/`
  - 后端专属 SQL migrations。

## Documentation

- `docs/src/`
  - `mdBook` 源文档，是运维与集成手册的事实来源。
- `docs/architecture/`
  - 本仓边界与源码布局记录。

## Layout Constraint

- VFS 语义和 policy 规则应留在 `core/` 与 `src/vfs/`，不要泄漏进 HTTP handlers。
- `service/` 只承载 transport、auth、audit、rate limit 和装配逻辑。
- `docs/src/` 是手册源文件；如果后续生成站点产物，不应手工维护生成物。
