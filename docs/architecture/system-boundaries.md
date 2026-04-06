# 系统边界

## 目标

`db-vfs` 是一个带硬安全边界的 DB-backed virtual filesystem。它不是通用数据库抽象层，也不是通用配置框架。

## 本仓负责什么

- `read`、`write`、`patch`、`delete`、`glob`、`grep` 的 VFS 语义
- `db-vfs-core::policy::VfsPolicy` 及其校验
  - 这里只保留 VFS 领域语义：permissions、core limits、secrets、traversal。
  - service-only 的 auth、audit、DB pool / rate-limit 运行期配置归到 `db_vfs_service::policy::ServicePolicy`。
- 路径合法性、traversal、secrets redaction、scan budgets
  - `max_io_ms` 约束非 scan 请求、DB pool wait/connect，以及 service 启动 migration 的 connect/lock 预算。
  - `max_walk_ms` 负责 `glob` / `grep` 的 scan runtime 预算；配置缺字段时默认是 `Some(2000)`。
  - scan 侧 DB pool wait/connect 仍受 `max_io_ms` 约束；SQLite `busy_timeout` / Postgres `statement_timeout` / `lock_timeout` 跟随当前请求预算。启动 migration 也必须复用有界预算，不能无限挂死在锁竞争上。
  - `max_walk_ms = None` 只表示 scan runtime 不设上限；不会把 DB pool wait/connect 也放成无界。
  - 公开 scan diagnostics 不暴露 secret-denied 路径计数；这类细节只留在内部审计语义里。
  - 无 redaction 规则的 ranged `read` 必须优先走 store chunk 读取，避免为了几行内容整文件 materialize。
  - 这个 chunked ranged-read 路径的进度推导必须按字节预算保守前进，不能把
    `max_read_bytes` 直接当成同尺寸字符预算，避免 UTF-8 多字节内容把 traversal work 放大。
  - `read` / `grep` 的 line-oriented 契约必须一致：`\n`、`\r\n`、lone `\r` 都是等价行边界，混合换行文件也不能改变 line range / line number 语义。
  - crate 公开构造器里的 `SecretRedactor` / `TraversalSkipper` 必须与同一份 `VfsPolicy` 同源；不允许用外部自定义 matcher 绕过 policy 边界。
  - `secrets.replacement` 不允许控制字符；多行 secret redaction 必须保住 `read` / `grep` 的行语义。
  - 开启 `secrets.redact_regexes` 时，`patch` 不能再对 raw backing text 做 unified diff apply；
    service/vfs 必须显式拒绝这类请求，避免通过 patch context match/no-match 把被遮蔽的 secret
    再次暴露成 oracle。
  - 启用 redaction 规则时，`grep` 的 literal/regex 匹配必须基于 redacted line view，而不是
    hidden raw content；被遮蔽的 secret 不能继续通过 match/no-match 语义泄漏存在性。
  - redaction 路径的原始输入和中间结果都必须受 `max_read_bytes` 约束；当 ranged `read`
    或 `grep` 需要 whole-file redaction 时，raw content 和 redacted whole-file intermediate
    任何一侧超出预算都必须显式失败/跳过，而不是继续无界分配。
  - scan 内存预算要按 redaction 放大系数计入；启用 `secrets.redact_regexes` 时，service
    需要按每个 in-flight scan 最多同时持有一份原文和一份有界 redacted copy 来估算容量，
    不能只按单 buffer 估算。
- SQLite / Postgres 存储适配和 migrations
- HTTP service 的 auth、rate limit、audit、request-id、trust mode
  - service 启动和 policy 文件解析的 canonical 类型是 `db_vfs_service::policy::ServicePolicy`；
    service 会把其中的 core 子集投影成 `db_vfs_core::policy::VfsPolicy` 再交给
    `ValidatedVfsPolicy` 和 VFS 构造链路。
  - service `Router` 可以带或不带 `ConnectInfo<SocketAddr>` 运行；缺失时只影响 `peer_ip`
    与 per-IP rate-limit 归桶，不应让 handler 在运行时失败。
  - service 启动会先完成 policy/auth/audit/matcher 组合校验，再触发 DB pool 建立与 migration；
    坏配置不应先对后端产生副作用。
  - `max_concurrency_io` / `max_concurrency_scan` 的 permit 必须在 JSON body buffering / decode
    之前获取；慢或恶意的请求体不应绕过 service 的并发边界。
  - JSON body buffering / decode 本身也必须吃掉 frontdoor `max_io_ms` 预算；scan 端点即使
    `max_walk_ms = None`，也不能把 body parse 变成无界等待。
  - body 缓冲完成后，service 应先对 top-level `workspace_id` 做字面校验和 allowlist 预检，
    再进入完整 request schema 反序列化；合法 token 打到未授权 workspace 的大请求不应继续
    materialize `content` / `patch` 这类大字段。
  - auth 明文 token 与 HTTP `Authorization: Bearer <token>` 走同一套 token68 语义；
    不可能通过 Bearer header 发送的 env token 必须在启动时直接拒绝。
  - `auth.tokens[*].token_env_var` 只承载明文 bearer token；预哈希输入只允许放在
    `auth.tokens[*].token`。把字面 `sha256:<hex>` 放进 `token_env_var` 必须在启动时直接拒绝，
    不能被当成预哈希 token 接受。
  - `workspace_id` 是字面命名空间，不是 glob；`*` 保留给 auth `allowed_workspaces`
    模式语法，避免授权边界出现“字面 workspace 名”和“通配规则”混淆。
  - `allowed_workspaces = ["team-*"]` 这类 trailing `-*` 前缀只匹配带非空后缀的 workspace；
    它不能顺带放行字面 `team-`，避免授权边界比策略作者肉眼看到的更宽。
  - token 已通过但 workspace 未授权的请求，service 必须在 buffered JSON 的轻量
    preflight 阶段尽早拒绝，而不是先构造完整 `write` / `patch` 大请求再发现
    workspace scope 不匹配。
  - `audit.required = true` 是运行期 fail-closed 语义：请求必须等到对应 audit 记录
    append+flush 成功才返回；对应的 `max_concurrency_*` permit 会一直持有到 audit wait
    结束，避免请求在“已执行但未完成审计”时提前把并发槽位还回去。
  - 这个 required-audit permit 保持语义同样适用于已经拿到并发槽位的 early-reject 分支，
    包括 JSON/content-type/schema 校验失败、非法 `workspace_id` 以及 token 已通过但
    workspace 仍未授权的请求。
  - 同样地，落在 VFS 路径上的 `401 unauthorized` 与 `429 rate_limited` 这种 frontdoor
    拒绝，只要 `audit.required = true` 且服务还能判定对应 request class，就必须先拿到
    对应 `max_concurrency_*` permit，再等待 audit append+flush 成功后返回，不能在
    “已拒绝但未完成审计”时提前释放并发槽位。
  - required audit append+flush 会消费同一条请求的剩余运行期预算；超出剩余预算、worker
    丢失或写失败都会转成稳定 `503 audit_unavailable` 故障，而不是静默丢日志或
    panic/连接级失败。
  - `audit.required = false` 仍然允许 fail-open，但 optional audit sink 一次写失败后不能把
    后续整个进程永久打成“有请求、无审计”的状态；至少要 rotate 掉可能损坏的 JSONL 并恢复
    worker，让后续事件重新可写。
  - required audit channel 满也必须立即 fail-closed 成 `503 audit_unavailable`；不能因为
    阻塞 `send()` 把 request permit 或后台线程无限悬挂。
  - scan 请求即使配置 `max_walk_ms = None`，backend DB pool wait/connect 和 frontdoor
    reject/audit wait 仍必须保持 `max_io_ms` 有界；只有 scan runtime 本身可以不设上限。
  - `ValidatedVfsPolicy` 必须包含“policy-derived matcher 可构建”这个不变量，这样
    `DbVfs::new_validated`、`DbVfs::new_with_matchers_validated` 这类 validated 构造器都能
    在创建时直接暴露 policy/matcher 不一致，而不是把状态推迟到运行期或做静默“自动修复”。
  - 审计 redaction 对 malformed secret-ish path 必须保守遮蔽；即使请求最终会因为
    traversal/control-char 等原因被拒绝，也不能把原始 secret 片段直接写进 JSONL。
    glob/pattern 审计字段也必须按真实 deny-glob 语义保守遮蔽，不能靠一套会漂移的本地猜测规则。
  - `service` 层只能调用 `core::redaction` 暴露的 audit redaction helper；secret-ish
    path/glob 的 probe 与遮蔽语义属于 policy-derived matcher 边界，不能在 handlers 里复制一套。
- 面向运维和集成者的 API / policy / security 文档

## 当前仍在本仓本地实现的通用能力

- `service/src/policy_io.rs`
  - 自己做配置文件读取、大小限制、env interpolation，以及 JSON/TOML 识别与解析。
  - loader 先做 no-follow 风格的路径探测：只接受 direct regular file，拒绝 symlink、
    FIFO、目录和其他非常规文件，避免在特殊文件或意外链接目标上阻塞/漂移。
  - policy loader 只接受 regular file；env interpolation 只作用于解析后的字符串值，
    不把注释或非字符串字段当模板系统处理。
  - 当前这里没有接入 YAML。
- `service/src/server/auth.rs`
  - 自己做 bearer token 的 `sha256:<hex>` 解析、token68 校验、摘要匹配和 workspace allowlist 约束。
- `src/store/mod.rs`
  - 内置 SQLite/Postgres store 会在公开入口维持 `workspace_id` / `path` / `path_prefix`
    的 VFS 不变量，避免 direct store 调用写出 VFS 无法一致访问的脏 key。
  - 仍保留 legacy `list_metas_by_prefix_page` / `get_content_chunk` compatibility fallback，
    但它们只保证正确性，不保证大前缀 scan budget 或 ranged-read 性能语义；fallback
    命中时会显式告警，提示 store 实现方补齐 cursor pagination / chunked line-range 边界。

这些能力已经表现出复用性，但当前仍然直接服务于 `ServicePolicy` 与 `db-vfs` 的服务边界；在真正抽离之前，不要把它们包装成假通用 abstraction。

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
- core `VfsPolicy` 字段、workspace 授权约束和具体文件操作语义继续留在本仓。
