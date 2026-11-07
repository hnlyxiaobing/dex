# dex · 公开 API（API.md）

> 与 `pkg.generated.mbti` 一致。全部函数为 `declare`（**无实现**，预期 `0068` 告警）。
> 错误传播统一 `raise DexError`；无外部句柄。

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

`moon check`：✅ 0 error，6 × `0068`。API 快照：`pkg.generated.mbti`。实现：❌ 后续轮。
