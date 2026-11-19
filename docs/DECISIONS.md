# dex · 设计决策记录（DECISIONS.md）

> 本文件记录 `dex` 的关键设计决策（背景 → 决策 → 理由 → 后果），供源码注释与文档引用。
> 时间跨度较久的既有决策以原日期与结论原样保留；后续里程碑的裁决（W7 / W9 / W10 等）也落此文件，
> 记录选项、理由与日期。仓库内文档与注释只引用仓库内文件；外部规范以 URL 注明。

## D3. 真实 DEX 黄金差分曾发现并修复 `method_idx_diff` 分段复位 P0 缺陷（2026-11-07，防回归记录）

**背景**：解析器先由程序化 fixture（手工拼装的六表/code_item 字节）驱动开发，全部通过后接入
真实 DEX 样本做黄金差分（工具侧 `dexdump` 规范化输出 ↔ 解析侧渲染）。首跑即发现 `parse` 对
**真实** DEX 抛 `DexError::InvalidIndex(MethodId, 49)`（tvshell-debug 样本，`method_ids_size`
只有 43）。

**缺陷与根因**：`parse.mbt::parse_class_data` 把 `class_data_item` 的 `method_idx_diff` 在
`direct_methods` 与 `virtual_methods` 两个分段之间**连续累加**，而 AOSP libdex / `dexdump`
在每个分段各自从 0 累加（`static_fields` / `instance_fields` 同理）。实测（tvshell-debug）：
dexdump 报方法索引 24,25,26 / 27,28 / 29,33,34,35；连续累加得 24,49,50 / 27,55 / 29,62,63,64 ——
越界即抛 `InvalidIndex(MethodId, 49)`。

**决策 / 修复**：进入 instance/virtual 分段时索引**复位**（`parse.mbt::parse_class_data`，
与 AOSP libdex 行为一致）；修复后真实样本解析侧黄金差分全通（tvshell-debug、motionshell 与后续
fx-multidex 多 dex 样本），并把该缺陷从"已知缺陷钉死用例"改为真实黄金差分常驻回归。

**理由（为什么留记录）**：

1. **防回归**：该缺陷的触发条件是"真实布局中 direct+virtual 分段且 diff 跨段"，程序化 fixture
   从未覆盖这种布局；一旦回归，只有真实样本黄金差分能抓住。
2. **方法论教训**：程序化 fixture 与实现会**互相印证同一错误假设**（"连续累加"的实现配"连续累加"
   的期望），真实工具产出的黄金差分是唯一可靠对照。这与后续在容器层发现的签名块布局缺陷同型。

**后果**：黄金期望值现内嵌于 `fixtures_test.mbt`（`GOLDEN-BEGIN/END` 标记的黄金常量），`moon test`
即回归；任何人改动 `class_data` 解析都必须过真实样本黄金差分。开发期"工具侧↔黄金↔解析侧"三方
差分方法保留描述见 `tests/ASSETS.md`。
