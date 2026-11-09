# hnlyxiaobing/dex

**DEX 解析与 Dalvik 反汇编基础库 —— 容器、表、code_item 与指令解码，纯 MoonBit 实现。**

> 状态：**已实现并门禁全绿**（2026-11-07 语义补全、其后 xref 索引）。`moon check --deny-warn` 0 error / 0 warning；`moon test` 84/84。真实样本（tvshell/motionshell/自建 AnnoSample）解析、注解语义与静态初值均经 `dexdump -d -a` 逐值核对。

## 定位与为什么存在

生态调研（2026-11-06）：`dex` 唯一命中仍是 `IvanAXu/BioSeqs@0.1.13` 的生物序列 `dexseq_demo`（误报），DEX 解析在 MoonBit 生态完全空白。DEX 是 Android 应用的实际代码载体，没有它就无法在 MoonBit 侧做逆向分析、方法引用图与协议线索提取。规范来自 AOSP `dalvik-bytecode`（8-bit opcode `00`–`ff`，实际定义至 `0xE2`，约 218 条），公开稳定。据此判定为**纯 MoonBit 自研**（选型背景与理由见 `DECISIONS.md` D2）。

`iceBear67/classfile@0.2.0` 证明纯 MoonBit 可写字节码解析器，但该包 `build_status=legacy`、仍带 `moon.pkg.json`，v0.10.19 下**只作设计参照，不作依赖**（理由见 `DECISIONS.md` D2）。

## 能力范围 / 非目标

- **做**：单 DEX 的 header / string / type / proto / field / method / class_def 六表；`code_item`、try/catch 表、`debug_info` 原始字节；约 218 条 Dalvik 指令解码；smali 风格文本输出。
- **做（语义补全）**：注解语义——annotation_directory_item（class/field/method/parameter 四类）、annotation_set_item、annotation_item、encoded_annotation 与 encoded_value 全 16 类型解码（数组/枚举/嵌套注解/NULL）；static_values 静态字段初值与 encoded_array（**加密字符串入口**）；指令结构化操作数视图（regs/literal/branch/index）与按表解析名字 helper（invoke→`Lcls;->name(sig)ret`、const-string→字符串池项、字段→`Lcls;->name:type`、类型→类名）。
- **做**：调用点 / 字段访问点索引（xref）——`build_xref` 产出 `XrefIndex`，按方法/字段/调用方/被调方查询 `XrefSite`（kind + code 偏移 + 目标引用名）。
- **不做**：控制流图、Java 反编译、多 dex 合并（交上层；组合模式 = 逐 dex `parse` + 调用方编排，`MultiDexNotMerged` 语义维持）、符号解析、DEX 写入/回编、oat/odex/vdex。
- **与 axml、apk 互不知晓**（模块边界决策见 `DECISIONS.md` D1）；可被单独依赖。

## 公开接口（速览）

`parse(Bytes) -> DexFile raise DexError`、`DexFile::{classes, methods, code, strings}`、`disasm(DexFile, MethodHandle) -> String`；注解/常量值：`class_annotations(Bytes, Int) -> AnnotationsDirectory?`、`static_values(Bytes, Int) -> Array[EncodedValue]`（加密字符串入口）、`annotation_set` / `annotation_item` / `encoded_array`；操作数：`instruction_operands(Instruction) -> InsnOperands`、`string_ref_name` / `type_ref_name` / `field_ref_name` / `method_ref_name` / `resolve_ref_name` / `instruction_ref_name`；xref：`build_xref(DexFile) -> XrefIndex`、`XrefIndex::{sites, sites_in, callers, callees, method_sites, field_sites}`、`method_ref_of`。完整签名见 `API.md`（全部加法性新增，冻结面零改动）。

## 依赖

- **零依赖**；独立 `moon.mod`，`moon check` 独立通过。
- 无第三方依赖计划；`dexdump`（Android build-tools）只作开发期差分基准，不链接、不入库。

## 平台与许可风险

- 平台：全后端（`preferred_target = "wasm"`，未改动）；桌面即可测试。
- 许可：本仓库 Apache-2.0；AOSP 字节码文档 CC-BY-4.0、源码片段 Apache-2.0。无外部二进制。
- 风险：指令表大而细；try/catch 与 `debug_info` 偏移；DEX v039/v040/v041 差异；厂商加密或畸形 DEX（apktool 3.0.0 起默认 `--only-main-classes` 正是为此）。策略为带 `TableKind`/索引的显式错误 + 跳过未知结构（错误模型见 `DECISIONS.md` D4）。

## 测试与验收

- **测试策略（现状）**：程序化 fixture 与白盒 37 例（六表 / class_def / code_item / 方法名 / magic·checksum 错误路径 / 索引边界 / try/catch）；真实样本内嵌（tvshell-debug 4368 B、motionshell 3148 B、fx-multidex 多 dex 2116 B + 1640 B）+ 黄金期望值差分 12 例——**黄金期望值内嵌于测试代码**（`fixtures_test.mbt` 黄金常量），`moon test` 即回归；畸形派生 7 例；注解/常量值/操作数语义 20 例（程序化 fixture 覆盖 VALUE_FIELD/METHOD/窄宽编码 + 自建 AnnoSample 样本（javac 21 + d8 自建，4264 B，SHA-256 `16dbf2d6…52d0d`）与 tvshell（VALUE_METHOD/VALUE_NULL/静态字符串初值）经 `dexdump -d -a` 逐值核对）；xref 索引 8 例。合计 **84/84**（另 3 例 `#skip` 明示不执行：第三方样本未提取、真机测试、DEX 无 chunk 概念）。
- **验收状态**：开发期"工具侧 `dexdump` ↔ 黄金 ↔ 解析侧 `@dex.parse`"三方差分（工具侧↔黄金↔解析侧）全通；黄金值已内嵌测试代码，`moon test` 即回归 —— 三方差分首跑发现的真实 DEX 缺陷 `InvalidIndex(MethodId, 49)`（`method_idx_diff` 未在 direct/virtual 分段复位）**已修复**（`parse_class_data` 分段复位，AOSP libdex 行为），tvshell-debug 与 motionshell 解析侧差分均 exit 0，见 `DESIGN.md` §13 与 `DECISIONS.md` D3。
- 测试样本：来源、生成方式（javac/d8 自建）、SHA-256 与 `dexdump` 规范化口径见 `tests/ASSETS.md`；许可不明的第三方 APK 未入库（开发期差分复核）。

## 当前状态

| 项 | 状态 |
|---|---|
| `dex.mbt` 数据结构 + 文档注释 | ✅ |
| `pkg.generated.mbti` API 快照 | ✅ |
| 表解析 / 指令解码 / smali 输出 | ✅ 真实实现（无 `declare`） |
| 真实样本内嵌 + 黄金差分（期望值内嵌测试） | ✅ |
| 真实 DEX 解析（解析侧差分） | ✅ **全通**（P0 缺陷已修复，DESIGN §13 / DECISIONS D3） |
| 注解语义 / 静态初值 / 结构化操作数（`semval.mbt` `annot.mbt` `operand.mbt`） | ✅（加法性新增） |
| xref 调用点 / 字段访问点索引（`xref.mbt`） | ✅ |
| `moon check --deny-warn` / `moon build` / `moon test` / `moon fmt --check` | ✅ 全绿（84/84） |

## 开发顺序说明

表解析先行（上层的方法引用图与协议线索提取只需要 header + 六表 + 方法名），完整 218 条指令解码与注解/静态初值/操作数语义层随后补齐，语义层全部以加法性新增落地（顺序考量见 `DECISIONS.md` D5）。

## 文档索引

`DESIGN.md`（设计契约）· `API.md`（公开签名）· `DECISIONS.md`（设计决策记录）· `tests/ASSETS.md`（测试样本清单）· `README.mbt.md`（包说明）
