# dex · 变更记录（CHANGELOG.md）

> 本文件登记影响公开面 / 行为 / 证据链的变更。加法性 API 变更必须在此留一条，且与
> `pkg.generated.mbti` 快照在同一次提交。条目按时间倒序。

## 2026-11-19 · 文档基线建立（W1）与工具链漂移修复

**五门禁基线（本机实测）**：`moon check --deny-warn` / `moon build` / `moon test` /
`moon fmt --check` / `moon info` 后快照 diff 全绿。`moon test`：**96 passed / 0 failed**；
另有 3 个 `#skip` 用例（不计入通过数）。

- 新增 `tests/ASSETS.md`：登记 6 个文件类样本与 1 个内嵌样本的来源、SHA-256、字节数、
  生成命令与 `dexdump` 规范化口径（`encoded_value` 全 18 种）。
- 新增 `docs/DECISIONS.md`：迁移 D3（`class_data_item` 索引分段复位缺陷，2026-11-07）。
- 消除文档漂移：`xref.mbt` / `semval.mbt` / `cmd/main/main.mbt` / `cmd/main/zipmin.mbt` /
  `tools/bench-dex.ps1` / `fixtures_malformed_test.mbt` 的过期能力描述与跨仓库引用；
  `FIXTURE-*` 标记与示例路径统一为仓库内相对路径，`GOLDEN-*` 标记去掉历史模块前缀。
- `README.md` 公开 API 索引补齐 `pub suberror DexError`、`to_repr`、`pub type MethodHandle`、
  `pub trait Disassembler`、`pub struct AnnotationsIndex` / `XrefIndex`，与
  `pkg.generated.mbti` 逐条一致。
- CI 文案修正：Gate 5 的 API 变更提示指向 `docs/CHANGELOG.md`；删除已不存在的
  `pkg.generated.mbti.r1` 表述。
- 工具链漂移修复（不改变行为，公开 API 快照 0 行增删）：`Bytes::new(0)` →
  `Bytes::make(0, b'\x00')`（`parse.mbt` 两处）；`@flate.inflate_exact(max_output=)` →
  `max_output_bytes=`（`cmd/main/zipmin.mbt`）。
