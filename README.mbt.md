# hnlyxiaobing/dex

> 整改复核（2026-11-07）：本包数据结构、错误模型、表解析、`code_item`、指令解码与 smali 输出**均为真实实现**（无 `declare`）。`moon check --deny-warn`：0 error / 0 warning；`moon test` 84/84（当时值；现行 96/96 见 `README.md`）。
> 真实 DEX 解析的 P0 缺陷（`method_idx_diff` 未在 direct/virtual 分段复位）**已修复**，解析侧黄金差分**已启用并全通**，见 `docs/DESIGN.md` §13、`docs/DECISIONS.md` D3 与 `tests/ASSETS.md`。

DEX 容器表、class_def、code_item、指令与调用点索引访问接口。

完整文档见项目根目录与 `docs/` 目录：`README.md`、`docs/DESIGN.md`、`docs/API.md`、`docs/DECISIONS.md`（设计决策记录）与 `tests/ASSETS.md`（测试样本清单）。
