# db-vfs Docs System

## 入口分工

- `README.md`
  - 对外概览、快速开始和最低安全提醒。
- `AGENTS.md`
  - 给执行者的短地图。
- `docs/`
  - 版本化事实来源。

## 目录职责

- `docs/architecture/`
  - `system-boundaries.md`：本仓负责什么、候选复用点是什么、不负责什么。
  - `source-layout.md`：workspace 目录与模块职责。
- `docs/src/`
  - `mdBook` 源文档，是运维和集成手册的事实来源。
  - 关键页面包括 `index.md`、`policy.md`、`http-api.md`、`security.md`、`storage.md`、`observability.md`、`troubleshooting.md`。
- `docs/llms.txt`
  - 面向 LLM 的聚合入口，不是主事实来源。

## 新鲜度规则

- `VfsPolicy`、`trust_mode`、auth 规则、scan budget 变化时，同时更新 `system-boundaries.md` 和相关 `docs/src/*.md`。
- HTTP surface 变化时，更新 `docs/src/http-api.md`。
- 入口文件或目录职责变化时，更新 `source-layout.md`。
- `mdBook` 导航变化时，更新 `docs/src/SUMMARY.md`。
- 不把长期事实留在聊天记录里，也不要把 `llms.txt` 当成唯一文档源。
- `tests/docs_system.rs` 机械检查根入口和关键手册入口是否仍然存在。
