# dex · 设计契约（DESIGN.md）

> 初版 2026-11-06 ｜ 更新 2026-11-07 ｜ 状态：**已实现**（表解析 / code_item / 指令解码 / smali 输出均为真实实现），门禁全绿（`moon test` 84/84）；真实样本 P0 缺陷已修复（见 §13）

## 1. 分层位置与职责

L1 逆向输入层，纯 MoonBit 叶子库。职责：**单个 DEX 文件 → 结构化表 + code_item + 指令流**。`apk` 只给 `DexEntry.bytes`，由组合根调用本库（模块边界决策见 `DECISIONS.md` D1）。

## 2. 模块边界 / 依赖方向 / 数据流

```
组合根 ──(DexEntry.bytes)──► dex::parse ──► DexFile ──► disasm ──► String(smali)
```

零跨模块 import；与 `axml`、`apk` 互不知晓；多 dex 合并在组合根，不在本库
（组合模式：**逐 dex `parse` + 调用方编排**——对 `classes.dex`/`classes2.dex`… 每个
`DexEntry.bytes` 独立调用 `parse`/`class_annotations`/`static_values`；
`MultiDexNotMerged` 语义维持：ZIP/拼接输入明确报错，不隐式合并）。

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
| `AnnotationVisibility` / `EncodedValue` / `EncodedAnnotation` / `AnnotationElement` / `Annotation` / `AnnotationSet` | annotation_item / encoded_annotation / encoded_value 全类型结构化解码 |
| `AnnotationsDirectory` / `FieldAnnotations` / `MethodAnnotations` / `ParameterAnnotations` | annotation_directory_item 四类注解目录 |
| `InsnOperands` / `IndexKind` | 指令结构化操作数视图（加法性；`Instruction` 未动） |
| `XrefSite` / `XrefKind` / `XrefIndex` | 调用点 / 字段访问点索引（加法性；`build_xref` 产出） |

## 4. 错误模型

`DexError`：`UnexpectedEof(Int)`、`BadMagic(String)`、`UnsupportedVersion(String)`、`BadTableOffset(TableKind, Int)`、`InvalidIndex(TableKind, Int)`、`InvalidInstruction(Int, Int)`、`BadCodeItem(Int, String)`、`BadDebugInfo(Int, String)`、`MultiDexNotMerged(String)`。

全部 `raise DexError`；禁止 panic；带 `TableKind` / 索引 / 偏移便于黄金样本差分定位。`TableKind` 已 `#derive(Debug)` 以满足错误类型的 `Debug` 派生约束。（口径依据见 `DECISIONS.md` D4。）

## 5. 资源生命周期

全部纯值；无外部句柄、无释放函数。`parse` 不缓存输入 `Bytes` 之外的状态；返回值只读。
**本模块没有 `close` / `detach`**：纯值无句柄，不存在释放或“二次释放”问题；同一 `DexFile` 可被任意多次
访问/反汇编，重复调用不产生副作用（若未来引入句柄，必须满足“不会二次释放，重复调用返回明确错误”）。

## 6. 线程 / 并发边界

无可变全局状态；`parse` 可并发解析不同 DEX；`DexFile` 只读可跨线程共享；`disasm` 为纯函数。

## 7. 平台约束与外部依赖

- `preferred_target = "wasm"`（未改动），全后端。
- 外部依赖：无。规范 AOSP；`classfile@0.2.0` 仅设计参照（legacy，不可直接依赖，见 `DECISIONS.md` D2）。
- 分阶段：上层早期只需 header + 六表 + 方法名；`code_item` 与 218 条指令解码随后补齐（顺序见 `DECISIONS.md` D5）。

## 8. 输入输出类型与错误传播（纯 MoonBit 库）

| 输入 | 输出 | 错误传播 |
|---|---|---|
| `Bytes`（完整单 DEX） | `DexFile` | `DexError`（magic/版本/表偏移） |
| `DexFile + class_index` | `Array[MethodDef]` | `InvalidIndex` |
| `DexFile + MethodHandle` | `CodeItem?`（abstract/native 为 `None`） | `DexError` |
| `DexFile + MethodHandle` | `String`（smali 文本） | `InvalidInstruction` 等 |
| `Bytes + class_index` | `AnnotationsDirectory?` / `Array[EncodedValue]` | `DexError`（截断 `UnexpectedEof`、索引 `InvalidIndex`、结构 `BadTableOffset`） |
| `Instruction` | `InsnOperands` | `InvalidInstruction` |
| `DexFile + Int` | `String`（引用名字解析） | `InvalidIndex` |
| `DexFile` | `XrefIndex`（调用点/字段访问点） | `DexError`（`InvalidIndex` 等） |

`Option` 表达"正常无结果"，`raise` 表达"失败"，二者不混用。
注解/静态初值入口**自含**（传原始 `Bytes` + class_defs 位置，内部共享 `read_ctx`
头部校验 + 六表读取；不解析 class_def/code_item，比 `parse` 轻量）；
批量扫描由调用方按类循环编排（性能非本层目标）。

## 9. 可替换性与实现细节不泄漏

上层只看到 `DexFile` / `ClassDef` / `Instruction` 等中性值类型；看不到 map_list 偏移计算、指令表实现、字符串池解码策略。后续可替换 smali 文本后端而不改上层。

## 10. 测试策略

| 层次 | 内容 | 实跑状态（2026-11-07 起） |
|---|---|---|
| 黑盒（程序化 fixture，`dex_test.mbt`） | 六表、class_def、code_item、方法名、magic/checksum 错误路径 | ✅ 26 例 |
| 白盒（`dex_wbtest.mbt`） | 六表索引边界、`code_item` 偏移、try/catch、`debug_info`、opcode 表边界 | ✅ 11 例 |
| 黑盒（真实样本，`fixtures_test.mbt`） | 内嵌真实 `classes.dex`（tvshell-debug 4368 B、motionshell 3148 B、fx-multidex 2116 B + 1640 B）；**内嵌黄金期望值**（`fixtures_test.mbt` 黄金常量，`dexdump` 规范化口径）与解析输出逐字段 diff + 冒烟 | ✅ 12 例（工具侧 + **解析侧全通**，P0 缺陷已修复，§13） |
| 畸形派生（`fixtures_malformed_test.mbt`） | 从真实 dex 派生：截断 / magic 污染 / 错误 checksum / 表偏移污染 / `map_off` 越界 / 未知 opcode / 多 dex 截断与污染（重算 adler32 后直达结构错误）；断言报 `DexError` 而非 panic | ✅ 7 例 |
| 注解/常量值语义（`dex_sem_annotations_test.mbt` 9 + `dex_sem_consts_test.mbt` 5） | 四类注解目录、encoded_value 全 16 类型（含 VALUE_FIELD/METHOD/ENUM/NULL/窄宽/左对齐浮点）、嵌套注解、static_values 前缀语义、错误路径；真实样本 = javac 21 + d8 自建 AnnoSample.dex（4264 B，SHA-256 `16dbf2d6…52d0d`，见 `tests/ASSETS.md`）+ tvshell（VALUE_METHOD/VALUE_NULL/加密字符串入口），`dexdump -d -a` 逐值核对 | ✅ 14 例 |
| 结构化操作数（`dex_sem_operand_test.mbt`） | 十种操作数格式的 regs/literal/branch/index 视图、payload 空视图、名字解析 helper、真实样本 main/Kind.\<clinit\> 与 dexdump `// method@00xx` 等对照 | ✅ 6 例 |
| xref 索引（`xref_test.mbt`） | 计数恒等式与 kind/opcode 族一致、invoke 五族与字段四类分类、abstract/native/外部方法口径、越界 `InvalidIndex`、payload 不产 site、排序稳定、`method_ref_of` 反查 | ✅ 8 例 |
| 门禁 | `moon fmt --check` / `moon check --deny-warn` / `moon build` / `moon test` | ✅ 全绿（84/84） |

skip 机制：MoonBit 原生 `#skip` 属性（默认不计入 `Total tests`；`moon test --include-skipped` 才执行）。
所有未跑通/未内嵌的用例都用 `#skip` 显式标注（3 例：第三方样本未提取、L3 真机、DEX 无 chunk 概念），**绝不冒充通过**。

## 11. 验收标准（实现阶段）

1. 真实 APK 的全部 dex 解析无崩溃 —— ✅ **达成**（P0 缺陷修复后真实 DEX 解析通过）；
2. 反汇编与 dexdump 一致 —— ✅ 解析侧差分已启用并全通；
3. 黄金样本进 `moon test` —— ✅ 样本与黄金期望值已内嵌测试（`moon test` 即回归），工具侧 + 解析侧差分全通；
4. `moon check --deny-warn` 转绿 —— ✅。

## 12. 未解决问题 / 待验证假设

- DEX v041 / 厂商加固 DEX 的实际分布未验证（候选真实 APK 许可不明、未入库，仅开发期差分复核，
  见 `tests/ASSETS.md`）。
- `aapt2`/`dexdump` 官方 fuzz / 差分测试套件是否存在未证实；已以自建黄金差分替代（黄金期望值
  内嵌测试代码，`moon test` 即回归，见 `tests/ASSETS.md` §2）。
- ARM64 指令边界判断若未来给 `ptrace_lite` 用，需要额外反汇编支持。

## 13. 当前状态与 TODO

`dex.mbt` / `parse.mbt` / `instr.mbt` / `disasm.mbt` / `xref.mbt` 已全部实现（**无 `declare`、无 `0068`**），
公开 API 有 `///` 文档注释；字段名避开保留字 `method`（改用 `method_ref`）。

**真实样本与黄金差分（2026-11-07）**：L1 真实样本（`tests/fixtures/*.classes.dex`）+ 黄金
期望值内嵌（`fixtures_test.mbt` 黄金常量）+ 畸形派生用例 + 三方差分（开发期脚本驱动
"工具侧 ↔ 黄金 ↔ 解析侧"，方法与结论见 `tests/ASSETS.md` §2；黄金值已内嵌，`moon test` 即回归）。

**⚠ P0 缺陷（黄金差分首跑发现，2026-11-07 已修复）**：`parse_class_data` 曾把 `method_idx_diff`
在 direct/virtual 两段**连续累加**，而 AOSP libdex/dexdump 在每段各自从 0 累加（`static_fields`/
`instance_fields` 同理）。实测（tvshell-debug，`method_ids_size=43`）：dexdump 报 24,25,26 / 27,28 /
29,33,34,35；连续累加得 24,49,50 / 27,55 / 29,62,63,64 —— 越界抛 `InvalidIndex(MethodId, 49)`。
**修复**：进入 instance/virtual 分段时索引复位（`parse.mbt::parse_class_data`）；修复后真实样本
解析侧差分启用并全通 exit 0。防回归记录见 `DECISIONS.md` D3。

**语义补全（2026-11-07）**：新增注解语义（annotation_directory_item 四类 /
annotation_set_item / annotation_item / encoded_annotation / encoded_value 全 16 类型，
`semval.mbt` + `annot.mbt`）、静态初值/encoded_array（加密字符串入口）、指令结构化操作数
视图与名字解析 helper（`operand.mbt`）。**全部加法性**（mbti 快照 106 行插入 / 0 删除，
冻结面零改动；`DexError` 构造集合未扩）。内部重构：`parse_dex` 的头部校验与五表读取
以纯代码搬移抽出 `validate_header` / `read_ctx` 供新入口共享（行为等价，基线用例 + 黄金差分全保）。
编码布局实证钉死：format=(arg<<5)|type、type 码表（byte=0x00…boolean=0x1f）、
整型右对齐符号扩展、**float/double 左对齐低位补零**（dexdump 对照：3.5f 存 `60 40`）；
AnnotationDefault.value 实证为 **VALUE_ANNOTATION 嵌套注解**（非数组）；
tvshell 实证 VALUE_METHOD（EnclosingMethod）与 VALUE_NULL（InnerClass.name）。

**xref 索引（2026-11-08）**：新增 `xref.mbt`（`build_xref` / `XrefIndex` / `XrefSite` /
`XrefKind`，加法性），把每条 `invoke-*`/`iget-*`/`iput-*`/`sget-*`/`sput-*` 指令解码为一个
访问点；与 `dexdump -d` 指令行抽取口径三方一致（见 `tests/ASSETS.md` §2）。

## References

`DECISIONS.md`（设计决策：模块边界 / 选型 / P0 缺陷记录 / 错误模型 / 开发顺序）· `tests/ASSETS.md`（样本来源与黄金口径）· `https://source.android.com/docs/core/dalvik/dalvik-bytecode` · `https://github.com/JesusFreke/smali`
