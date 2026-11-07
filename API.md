# dex · 公开 API（API.md）

> 与 `pkg.generated.mbti` 逐项对账（R2 冻结前整改，2026-11-07）。**全部函数为真实实现**，
> 包内**没有 `declare` 存根**；`moon check --deny-warn` 0 error / 0 warning（原 `0068` 已消失）。
> 错误传播统一 `raise DexError`；无外部句柄。
>
> ⚠ **真实样本 P0 缺陷已修复（R2 主控，2026-11-07）**：WP-G 黄金差分首跑发现 `parse` 对真实 DEX 抛
> `InvalidIndex(MethodId, 49)`——`class_data_item` 的 `method_idx_diff` 未在 direct/virtual
> 分段处复位（AOSP libdex/dexdump 两段各自从 0 累加）。**本轮已修复**（`parse_class_data` 分段复位，
> `static_fields`/`instance_fields` 同理），`dexdump ↔ @dex.parse` 黄金差分**解析侧已启用并全通**
> （tvshell-debug 与 motionshell 均 exit 0）。修复记录见 `fixtures_test.mbt` 顶部注释、
> `fixtures/golden/ASSETS.md` §6、`docs/open-questions.md` §2.1。

## 类型

| 类型 | 种类 | 说明 |
|---|---|---|
| `DexFile` | `pub(all) struct` | version / checksum / signature / 六表 / map_list |
| `ClassDef` / `MethodDef` / `FieldDef` / `ProtoId` | `pub(all) struct` | 结构化表项 |
| `CodeItem` / `Instruction` / `TryItem` | `pub(all) struct` | 代码与指令 |
| `DexVersion` | `pub(all) enum` | Dex035..Dex041 + `Unknown(Int)` |
| `TableKind` | `pub(all) enum` (#derive Debug) | 用于错误定位的六表类别 |
| `DexError` | `pub suberror` | 9 个带偏移/索引的错误构造 |
| `MethodHandle` | `pub type` | `Int` 别名 |
| `Disassembler` | `pub trait` | `disasm` 只读契约 |

## 函数签名

| 签名 | 参数与所有权 | 返回 / 错误 | 资源与线程约束 | TODO |
|---|---|---|---|---|
| `parse(data : Bytes) -> DexFile raise DexError` | `data` 只读、调用方持有 | `DexFile` 纯值 / `DexError` | 无句柄；纯函数可并发；返回值只读 | 六表 + code_item + 指令表 |
| `DexFile::classes(self) -> Array[ClassDef]` | `self` 只读 | class_def 顺序列表 | 无状态 | — |
| `DexFile::methods(self, class_index : Int) -> Array[MethodDef] raise DexError` | `class_index` 为表索引 | direct+virtual 方法 / `InvalidIndex` | 无状态 | 索引校验 |
| `DexFile::code(self, method_ref : MethodHandle) -> CodeItem? raise DexError` | `method_ref` 定位方法 | `None` = abstract/native；失败 `DexError` | 无状态 | try/catch、debug_info 偏移 |
| `DexFile::strings(self) -> Array[String]` | `self` 只读 | string_id 顺序表 | 无状态 | — |
| `disasm(dex : DexFile, method_ref : MethodHandle) -> String raise DexError` | 只读 | smali 风格文本 / `InvalidInstruction` | 无状态；不做 CFG/类型推断 | 218 条指令表（W3） |

## 错误构造速查

`UnexpectedEof` · `BadMagic` · `UnsupportedVersion` · `BadTableOffset(TableKind, Int)` · `InvalidIndex(TableKind, Int)` · `InvalidInstruction(offset, opcode)` · `BadCodeItem` · `BadDebugInfo` · `MultiDexNotMerged`

## 非目标

CFG、Java 反编译、多 dex 合并、符号解析、DEX 写入/回编、oat/odex。

## 状态

| 门禁 | 结果 |
|---|---|
| `moon check --deny-warn` | ✅ 0 error / 0 warning（无 `0068`） |
| `moon build` | ✅ |
| `moon test` | ✅ 47 / 47（含真实样本黄金/smoke/畸形派生；另有 3 个 `#skip` 用例不计入：第三方样本未提取、L3 真机、DEX 无 chunk 概念） |
| `moon fmt --check` | ✅ |

黄金差分（`fixtures/golden/golden-diff.ps1`）：工具侧 `dexdump ↔ fixtures/golden/dex/*.norm.txt` **全通**；
解析侧 `@dex.parse ↔ 黄金` **已启用并全通**（tvshell-debug、motionshell 均 exit 0，P0 缺陷已修复）。
API 快照：`pkg.generated.mbti`（`moon info` 由主控统一执行）。

实现：✅ `parse` / 访问器 / `disasm` 均为真实实现；唯一保留的 TODO 是 `res0`/`data` 语义解释（见上表）。
