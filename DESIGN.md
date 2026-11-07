# dex · 设计契约（DESIGN.md）

> Round-1 / 2026-11-06 ｜ 状态：架构与声明可评审，无业务逻辑

## 1. 分层位置与职责

L1 逆向输入层，纯 MoonBit 叶子库。职责：**单个 DEX 文件 → 结构化表 + code_item + 指令流**。`apk` 只给 `DexEntry.bytes`，由组合根调用本库（ADR-0003）。

## 2. 模块边界 / 依赖方向 / 数据流

```
组合根 ──(DexEntry.bytes)──► dex::parse ──► DexFile ──► disasm ──► String(smali)
```

零跨模块 import；与 `axml`、`apk` 互不知晓；多 dex 合并在组合根，不在本库。

## 3. 核心数据结构

| 类型 | 作用 |
|---|---|
| `DexFile` | header + 六表 + `map_list` 原始字节；纯值 |
| `ClassDef` / `MethodDef` / `FieldDef` / `ProtoId` | class_def / method / field / proto 结构化表示 |
| `CodeItem` | registers / ins / outs / tries / `insns` / `debug_info` |
| `Instruction` | `offset` / `opcode` / `mnemonic` / `operands` / `raw` |
| `TryItem` | try/catch 异常处理项 |
| `DexVersion` / `TableKind` | magic 版本与表类别（用于错误定位） |
| `MethodHandle` | 方法定位句柄（`Int` 别名） |
| `Disassembler` trait | 只读反汇编契约，便于替换文本后端 |

## 4. 错误模型

`DexError`：`UnexpectedEof(Int)`、`BadMagic(String)`、`UnsupportedVersion(String)`、`BadTableOffset(TableKind, Int)`、`InvalidIndex(TableKind, Int)`、`InvalidInstruction(Int, Int)`、`BadCodeItem(Int, String)`、`BadDebugInfo(Int, String)`、`MultiDexNotMerged(String)`。

全部 `raise DexError`；禁止 panic；带 `TableKind` / 索引 / 偏移便于黄金样本差分定位。`TableKind` 已 `#derive(Debug)` 以满足错误类型的 `Debug` 派生约束。

## 5. 资源生命周期

全部纯值；无外部句柄、无释放函数。`parse` 不缓存输入 `Bytes` 之外的状态；返回值只读。

## 6. 线程 / 并发边界

无可变全局状态；`parse` 可并发解析不同 DEX；`DexFile` 只读可跨线程共享；`disasm` 为纯函数。

## 7. 平台约束与外部依赖

- `preferred_target = "wasm"`（未改动），全后端。
- 外部依赖：无。规范 AOSP；`classfile@0.2.0` 仅设计参照（legacy，不可直接依赖）。
- 分阶段：MVL-R 只需 header + 六表 + 方法名；`code_item` 与 218 条指令解码属 W3。

## 8. 输入输出类型与错误传播（纯 MoonBit 库）

| 输入 | 输出 | 错误传播 |
|---|---|---|
| `Bytes`（完整单 DEX） | `DexFile` | `DexError`（magic/版本/表偏移） |
| `DexFile + class_index` | `Array[MethodDef]` | `InvalidIndex` |
| `DexFile + MethodHandle` | `CodeItem?`（abstract/native 为 `None`） | `DexError` |
| `DexFile + MethodHandle` | `String`（smali 文本） | `InvalidInstruction` 等 |

`Option` 表达"正常无结果"，`raise` 表达"失败"，二者不混用。

## 9. 可替换性与实现细节不泄漏

上层只看到 `DexFile` / `ClassDef` / `Instruction` 等中性值类型；看不到 map_list 偏移计算、指令表实现、字符串池解码策略。后续可替换 smali 文本后端而不改上层。

## 10. 测试策略

| 层次 | 内容 |
|---|---|
| 黑盒 | 两个真实 APK 全部 dex 解析；与 `dexdump` 抽样反汇编一致 |
| 白盒 | 六表索引边界、`code_item` 偏移、try/catch、`debug_info` |
| 畸形输入 | 截断、非法 magic、非法 opcode、越界索引、多 dex 误喂 |
| 门禁 | `moon fmt --check` / `moon check` / `moon test --enable-coverage` / `moon info` |

## 11. 验收标准（实现轮）

1. 两个 APK 全部 dex 解析无崩溃；2. 反汇编抽样与 dexdump 一致；3. 黄金样本进 `moon test`；4. R4 `moon check --deny-warn` 转绿。

## 12. 未解决问题 / 待验证假设

- DEX v041 / 厂商加固 DEX 的实际分布未验证（Q1 需真实 APK）。
- `aapt2`/`dexdump` 官方差分套件是否存在未证实（Q6）。
- ARM64 指令边界判断若未来给 `ptrace_lite` 用，需要额外反汇编支持。

## 13. 当前状态与 TODO

`dex.mbt` 已写入全部类型与 6 个 `declare` 函数，公开 API 有 `///` 文档注释与 `TODO(实现轮)`。**未实现任何解析逻辑**。字段名避开保留字 `method`（改用 `method_ref`），使 `moon check` 告警只剩 `0068`。

## References

`../docs/research-and-verification.md` §2.1 · `../docs/adr/ADR-0001`、`ADR-0002`、`ADR-0005` · `https://source.android.com/docs/core/dalvik/dalvik-bytecode` · `https://github.com/JesusFreke/smali`
