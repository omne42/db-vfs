# db-vfs AGENTS Map

这个文件只做导航。稳定事实写在 `README.md` 和 `docs/`。

## 先看哪里

- 外部概览：`README.md`
- 文档入口：`docs/README.md`
- 文档系统地图：`docs/docs-system-map.md`
- 系统边界：`docs/architecture/system-boundaries.md`
- 源码布局：`docs/architecture/source-layout.md`
- 运维与集成手册：`docs/src/index.md`
- 策略语义：`docs/src/policy.md`
- HTTP 接口：`docs/src/http-api.md`

## 修改规则

- `AGENTS.md` 保持短小，不把领域细节堆进来。
- policy、auth、trust mode、scan budget 变化时，同时更新 `docs/architecture/system-boundaries.md` 与相关 `docs/src/*.md`。
- 目录职责变化时，更新 `docs/architecture/source-layout.md`。
- 不把“未来可能迁移到 foundation/runtime”的设想写成已实现事实。

## 验证

- `cargo fmt --all`
- `cargo test --workspace`
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`
