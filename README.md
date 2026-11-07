# hnlyxiaobing/dex

**DEX 解析与 Dalvik 反汇编基础库 —— 容器、表、code_item 与指令解码，纯 MoonBit 实现。**

> 状态：**Round-1 架构与声明可评审**。已写入数据结构与 `declare` 签名，`moon check` 0 error（6 条预期 `0068` 告警）。**无业务逻辑**。

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

- **测试策略**：两个真实 APK 的全部 dex 解析无崩溃；`dexdump` 抽样反汇编一致；小型 fixture + smali→dex→smali 往返思路；畸形 magic / 表偏移 / 非法 opcode 注入；`moon test --enable-coverage`。
- **验收标准**（实现轮）：解析本机两个 APK 全部 dex 无崩溃；反汇编抽样与 dexdump 一致；黄金样本纳入 `moon test`。
- 依赖资产：真实 APK 不在本工作区（`docs/open-questions.md` Q1）。

## 当前状态 / 本轮产物

| 项 | 状态 |
|---|---|
| `dex.mbt` 数据结构 + `declare` 签名 + 文档注释 | ✅ |
| `pkg.generated.mbti` API 快照 | ✅ |
| 表解析 / 指令解码 / smali 输出 | ❌ 后续轮，`TODO(实现轮)` |
| `moon check` | ✅ 0 error（6 × `0068`，预期） |

## 本轮顺序说明

按 `docs/dependency-graph.md`，DEX 表解析从原报告 M2 **提前到 W0**（任务表原标 P0 却在 M2，冲突 C1）；完整 218 条指令解码（原 DEX-03）延后到 W3，因为 MVL-R 只需要表与方法名。

## 文档索引

`DESIGN.md` · `API.md` · `../docs/architecture.md` · `../docs/adr/ADR-0001`、`ADR-0002`、`ADR-0005` · `../docs/moon-check-report.md`
