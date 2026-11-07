# hnlyxiaobing/dex

**DEX 解析与 Dalvik 反汇编基础库 —— 容器、表、code_item 与指令解码，纯 MoonBit 实现。**

> 状态：**已实现并门禁全绿**（R2 冻结前整改 2026-11-07 复核）。`moon check --deny-warn` 0 error / 0 warning（原 6 条 `0068` 已消失）；`moon test` 43/43。**真实样本解析存在已见缺陷**（见「测试与验收」）。

## 定位与为什么存在

路线图「拼图一」复核（2026-11-06）：`dex` 唯一命中仍是 `IvanAXu/BioSeqs@0.1.13` 的生物序列 `dexseq_demo`（误报），DEX 解析在 MoonBit 生态完全空白。DEX 是 Android 应用的实际代码载体，没有它就无法在 MoonBit 侧做逆向分析、方法引用图与协议线索提取。规范来自 AOSP `dalvik-bytecode`（8-bit opcode `00`–`ff`，实际定义至 `0xE2`，约 218 条），公开稳定。判定为**纯 MoonBit 自研**（`docs/capability-matrix.md` #03/#04）。

`iceBear67/classfile@0.2.0` 证明纯 MoonBit 可写字节码解析器，但该包 `build_status=legacy`、仍带 `moon.pkg.json`，v0.10.19 下**只作设计参照，不作依赖**（ADR-0010）。

## 能力范围 / 非目标

- **做**：单 DEX 的 header / string / type / proto / field / method / class_def 六表；`code_item`、try/catch 表、`debug_info` 原始字节；约 218 条 Dalvik 指令解码；smali 风格文本输出。
- **不做**：控制流图、Java 反编译、多 dex 合并（交上层）、符号解析（配 `dwarfscope`）、DEX 写入/回编、oat/odex/vdex。
- **与 axml、apk 互不知晓**（架构原则 P1、ADR-0003）；可被单独依赖。

## 公开接口（速览）

`parse(Bytes) -> DexFile raise DexError`、`DexFile::{classes, methods, code, strings}`、`disasm(DexFile, MethodHandle) -> String`。完整签名见 `API.md`。

## 依赖

- **本轮零依赖**；独立 `moon.mod`，`moon check` 独立通过。
- 后续轮：无第三方依赖计划；`dexdump` 只作差分基准，不链接。

## 平台与许可风险

- 平台：全后端（`preferred_target = "wasm"`，未改动）；桌面即可测试。
- 许可：本仓库 Apache-2.0；AOSP 字节码文档 CC-BY-4.0、源码片段 Apache-2.0。无外部二进制。
- 风险：指令表大而细；try/catch 与 `debug_info` 偏移；DEX v039/v040/v041 差异；厂商加密或畸形 DEX（apktool 3.0.0 起默认 `--only-main-classes` 正是为此）。策略为带 `TableKind`/索引的显式错误 + 跳过未知结构。

## 测试与验收

- **测试策略（现状）**：L0 程序化 fixture 37 例（六表 / class_def / code_item / magic·checksum 错误路径）；L1 真实样本内嵌（tvshell-debug 4368 B、motionshell 3148 B）+ L2 `dexdump` 规范化黄金 `fixtures/golden/dex/*.norm.txt` 逐字段差分；畸形派生 5 例（截断 / magic / 错误 checksum / 表偏移 / 未知 opcode，均断言报 `DexError` 而非 panic）。均由 `fixtures/golden/golden-diff.ps1` 驱动。
- **验收状态**：工具侧 `dexdump ↔ 黄金` **全通**；解析侧 `@dex.parse ↔ 黄金` **已启用并全通** —— WP-G 首跑发现的真实 DEX 缺陷 `InvalidIndex(MethodId, 49)`（`method_idx_diff` 未在 direct/virtual 分段复位）**已由 R2 主控修复**（`parse_class_data` 分段复位，AOSP libdex 行为），tvshell-debug 与 motionshell 解析侧差分均 exit 0，见 `DESIGN.md` §13。
- 依赖资产：真实 APK 位于工作区外 `D:\MoonBit\motion_sensing_game\`（受控自建与 AOSP 来源已入库提取样本；目标游戏 APK 许可不明仅登记哈希），清单见 `../fixtures/golden/ASSETS.md` 与 `../docs/open-questions.md` §2.1。

## 当前状态 / 本轮产物

| 项 | 状态 |
|---|---|
| `dex.mbt` 数据结构 + 文档注释 | ✅ |
| `pkg.generated.mbti` API 快照 | ✅ |
| 表解析 / 指令解码 / smali 输出 | ✅ 真实实现（无 `declare`） |
| L1 真实样本 + L2 `dexdump` 黄金 + 差分脚本 | ✅ R2 WP-G |
| 真实 DEX 解析（解析侧差分） | ✅ **全通**（P0 缺陷已修复，DESIGN §13） |
| `moon check --deny-warn` / `moon build` / `moon test` / `moon fmt --check` | ✅ 全绿（43/43） |

## 本轮顺序说明

按 `docs/dependency-graph.md`，DEX 表解析从原报告 M2 **提前到 W0**（任务表原标 P0 却在 M2，冲突 C1）；完整 218 条指令解码（原 DEX-03）延后到 W3，因为 MVL-R 只需要表与方法名。

## 文档索引

`DESIGN.md` · `API.md` · `../docs/architecture.md` · `../docs/adr/ADR-0001`、`ADR-0002`、`ADR-0005` · `../docs/moon-check-report.md`
