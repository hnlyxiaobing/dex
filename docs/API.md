# dex · 公开 API（API.md）

> 与 `../pkg.generated.mbti` 逐项对账（2026-11-07 整改）。**全部函数为真实实现**，
> 包内**没有 `declare` 存根**；`moon check --deny-warn` 0 error / 0 warning。
> 错误传播统一 `raise DexError`；无外部句柄。
>
> ⚠ **真实样本 P0 缺陷已修复（2026-11-07）**：黄金差分首跑发现 `parse` 对真实 DEX 抛
> `InvalidIndex(MethodId, 49)`——`class_data_item` 的 `method_idx_diff` 未在 direct/virtual
> 分段处复位（AOSP libdex/dexdump 两段各自从 0 累加）。**已修复**（`parse_class_data` 分段复位，
> `static_fields`/`instance_fields` 同理），`dexdump ↔ @dex.parse` 黄金差分**解析侧已启用并全通**
> （tvshell-debug 与 motionshell 均 exit 0）。修复记录见 `../fixtures_test.mbt` 顶部注释、
> `DECISIONS.md` D3 与 `../tests/ASSETS.md`。

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
| `AnnotationVisibility` | `pub(all) enum` | VisibilityBuild/Runtime/System（annotation_item.visibility） |
| `EncodedValue` | `pub(all) enum` | encoded_value 全 16 种 value_type 解码（含数组/枚举/嵌套注解/NULL/BOOL） |
| `EncodedAnnotation` / `AnnotationElement` / `Annotation` / `AnnotationSet` | `pub(all) struct` | annotation_item / encoded_annotation / 注解集 |
| `AnnotationsDirectory` + `FieldAnnotations` / `MethodAnnotations` / `ParameterAnnotations` | `pub(all) struct` | annotation_directory_item 四类目录 |
| `InsnOperands` / `IndexKind` | `pub(all) struct` / `enum` | 指令结构化操作数视图（加法性，不动 `Instruction`） |
| `XrefSite` / `XrefKind` / `XrefIndex` | `pub(all) struct` / `enum` / `struct` | 调用点 / 字段访问点索引（加法性新增） |

## 函数签名

| 签名 | 参数与所有权 | 返回 / 错误 | 资源与线程约束 | TODO |
|---|---|---|---|---|
| `parse(data : Bytes) -> DexFile raise DexError` | `data` 只读、调用方持有 | `DexFile` 纯值 / `DexError` | 无句柄；纯函数可并发；返回值只读 | 六表 + code_item + 指令表 |
| `DexFile::classes(self) -> Array[ClassDef]` | `self` 只读 | class_def 顺序列表 | 无状态 | — |
| `DexFile::methods(self, class_index : Int) -> Array[MethodDef] raise DexError` | `class_index` 为表索引 | direct+virtual 方法 / `InvalidIndex` | 无状态 | 索引校验 |
| `DexFile::code(self, method_ref : MethodHandle) -> CodeItem? raise DexError` | `method_ref` 定位方法 | `None` = abstract/native；失败 `DexError` | 无状态 | try/catch、debug_info 偏移 |
| `DexFile::strings(self) -> Array[String]` | `self` 只读 | string_id 顺序表 | 无状态 | — |
| `disasm(dex : DexFile, method_ref : MethodHandle) -> String raise DexError` | 只读 | smali 风格文本 / `InvalidInstruction` | 无状态；不做 CFG/类型推断 | 218 条指令表 |

## 注解 / 静态初值（加法性新增）

> ⚠ **接线注意**：入口自含，第一个参数是**原始 DEX `Bytes`**（不是 `DexFile`）。
> `class_index` 为 **class_defs 表位置**（与 `DexFile::methods` 的 `class_index` 同义）。

| 签名 | 参数与所有权 | 返回 / 错误 | 说明 |
|---|---|---|---|
| `class_annotations(data : Bytes, class_index : Int32) -> AnnotationsDirectory? raise DexError` | `data` 只读、调用方持有 | 四类注解目录；`annotations_off==0` → `None` | annotation_directory_item 全解码 |
| `static_values(data : Bytes, class_index : Int32) -> Array[EncodedValue] raise DexError` | 同上 | 常量值数组（**加密字符串入口**） | static_values_off → encoded_array；前缀省略语义（返回长度 ≤ static_fields 数） |
| `annotation_set(data : Bytes, off : Int32) -> AnnotationSet raise DexError` | `off` 为文件内偏移（≥0x70） | 注解集 | annotation_set_item |
| `annotation_item(data : Bytes, off : Int32) -> Annotation raise DexError` | 同上 | 可见性 + encoded_annotation | annotation_item |
| `encoded_array(data : Bytes, off : Int32) -> Array[EncodedValue] raise DexError` | 同上 | 常量值数组 | encoded_array（AnnotationDefault 等通用） |

### 批量索引（P0 可用性修复轮，加法性新增）

> 单次入口每次调用都会重建六张索引表；逐类遍历 N 个类即 O(N × 表规模)。
> 批量场景（本仓库 CLI 的 `summary` / `--json`）请用索引：每个 DEX 段只建一次，
> 再按 class_defs 位置逐类查询，复杂度降为 O(表规模 + 各类注解数据量)。
> **既有单次入口签名与错误语义逐字未动**（内部委托索引）。

| 签名 | 说明 |
|---|---|
| `annotations_index(data : Bytes) -> AnnotationsIndex raise DexError` | 一次头部校验 + 六表读取；逐 dex 使用，不跨 dex 合并（`MultiDexNotMerged` 口径维持） |
| `AnnotationsIndex::class_annotations(self, class_index : Int32) -> AnnotationsDirectory? raise DexError` | 与全局 `class_annotations` 等价；`annotations_off==0` → `None` |
| `AnnotationsIndex::static_values(self, class_index : Int32) -> Array[EncodedValue] raise DexError` | 与全局 `static_values` 等价；`static_values_off==0` → `[]` |

`AnnotationsIndex` 为不透明 `pub struct`（包外不可访问字段），构建后只读、无全局状态、可并发；
包内私有类型 `Ctx` 仍保持私有——索引平铺保存其公开类型的表字段，查询时在包内重组 `Ctx`
（只搬表引用，不复制表内容）。错误构造集合未扩，越界仍为 `InvalidIndex(ClassDef, ...)`。

`EncodedValue` 解码规则（已用真实样本钉死）：format 字节 = `(value_arg << 5) | value_type`，
value_type 码表 byte=0x00 short=0x02 char=0x03 int=0x04 long=0x06 float=0x10 double=0x11
string=0x17 type=0x18 field=0x19 method=0x1a enum=0x1b array=0x1c annotation=0x1d
null=0x1e boolean=0x1f；整型右对齐符号/零扩展（最小宽度），**float/double 左对齐、低位补零**
（dex 格式 "zero-extended to the right"，实证 3.5f 存 `60 40` 两字节）。
引用类值解码时按表解析为名字：字符串池项原文、类型描述符、字段/枚举 `Lcls;->name:type`、
方法 `Lcls;->name(params)ret`。注解结构错误复用既有错误构造（`DexError` 冻结未动）：
截断 → `UnexpectedEof`、索引越界 → `InvalidIndex(StringId/TypeId/FieldId/MethodId, idx)`、
未定义 value_type/visibility/结构损坏 → `BadTableOffset(ClassDef, 偏移)`。

## 结构化指令操作数 / 名字解析（加法性新增）

> `Instruction` 冻结结构**未改动**；`InsnOperands` 为新增视图（从 `Instruction::raw` 重解码），
> 文本 `operands`（smali 风格）行为不变。名字格式与 `disasm` 一致（smali `->`；
> dexdump 显示为 `.` 分隔，语义相同）。

| 签名 | 说明 |
|---|---|
| `instruction_operands(insn : Instruction) -> InsnOperands raise DexError` | `regs`（invoke 列表/range 已展开）/ `literal : Int64?` / `branch : Int32?` / `index_kind` / `index`；switch·数组 payload 伪指令返回空视图 |
| `string_ref_name(dex : DexFile, index : Int32) -> String raise DexError` | const-string → 字符串池项 |
| `type_ref_name(dex : DexFile, index : Int32) -> String raise DexError` | 类型引用 → 类名（描述符） |
| `field_ref_name(dex : DexFile, index : Int32) -> String raise DexError` | 字段引用 → `Lcls;->name:type` |
| `method_ref_name(dex : DexFile, index : Int32) -> String raise DexError` | invoke → `Lcls;->name(params)ret` |
| `resolve_ref_name(dex : DexFile, kind : IndexKind, index : Int32) -> String raise DexError` | 按 `IndexKind` 综合解析（`IndexNone` 抛 `InvalidIndex`） |
| `instruction_ref_name(dex : DexFile, insn : Instruction) -> String? raise DexError` | 一步解析指令引用；无引用操作数返回 `None` |

## 调用点 / 字段访问点索引（xref，加法性新增）

> 每条 `invoke-*` / `iget-*` / `iput-*` / `sget-*` / `sput-*` 指令解码为一条 `XrefSite`
> （caller 方法引用 + code 偏移 + kind + 目标引用），四元组与 `dexdump -d` 指令行抽取
> 口径一致（见 `../tests/ASSETS.md` §2 三方一致口径）。

| 签名 | 说明 |
|---|---|
| `build_xref(dex : DexFile) -> XrefIndex raise DexError` | 全量扫描 `class_def` 产出索引 |
| `method_ref_of(dex : DexFile, m : MethodDef) -> Int32?` | 方法定义 → method_ids 引用（`None` = 无对应引用） |
| `XrefIndex::sites(self) -> Array[XrefSite]` | 全量访问点（副本，method_ref 升序 × offset 升序） |
| `XrefIndex::sites_in(self, method_ref : Int32) -> Array[XrefSite] raise DexError` | 某方法体内的访问点（offset 升序） |
| `XrefIndex::callers(self, target : Int32) -> Array[XrefSite] raise DexError` | 调用某方法/引用某字段的站点 |
| `XrefIndex::callees(self, method_ref : Int32) -> Array[XrefSite] raise DexError` | 某方法调用的目标 |
| `XrefIndex::method_sites(self, method_ref : Int32) -> Array[XrefSite] raise DexError` | 以某方法为目标的调用点 |
| `XrefIndex::field_sites(self, field_ref : Int32) -> Array[XrefSite] raise DexError` | 以某字段为目标的访问点 |

`XrefSite { method_ref : Int32, offset : Int32, target_ref : Int32, kind : XrefKind }`；
`XrefKind` 九值：`XrefCallVirtual` / `XrefCallSuper` / `XrefCallDirect` / `XrefCallStatic` /
`XrefCallInterface` / `XrefFieldReadStatic` / `XrefFieldWriteStatic` / `XrefFieldReadInstance` /
`XrefFieldWriteInstance`（构造顺序即固定标签映射表顺序）。

## 错误构造速查

`UnexpectedEof` · `BadMagic` · `UnsupportedVersion` · `BadTableOffset(TableKind, Int)` · `InvalidIndex(TableKind, Int)` · `InvalidInstruction(offset, opcode)` · `BadCodeItem` · `BadDebugInfo` · `MultiDexNotMerged`

## 非目标

CFG、Java 反编译、多 dex 合并、符号解析、DEX 写入/回编、oat/odex。

**多 dex 组合模式（维持 `MultiDexNotMerged` 语义）**：本库只处理**单个 DEX 字节流**；
`classes.dex` / `classes2.dex` … 由调用方（组合根）**逐 dex `parse` + 编排**——
对每个 `DexEntry.bytes` 独立调用 `parse` / `class_annotations` / `static_values`，
跨 dex 的类/引用解析由上层负责。喂入 ZIP/APK 容器或多 dex 拼接字节时入口明确报
`MultiDexNotMerged`，不做隐式合并（模块边界决策见 `DECISIONS.md` D1）。

## 冻结标注（语义补全批次）

该批次全部为**加法性新增**（`../pkg.generated.mbti` 快照 diff 106 行插入 / 0 行删除）：
既有公开签名（`parse` / `disasm` / 访问器 / `Instruction` / `ClassDef` / `DexFile` /
`DexError` 等）**零改动**；结构化操作数以新增 `InsnOperands` 视图实现（保旧文本接口）；
注解/常量值为新增类型与函数；`DexError` 构造集合未扩（注解结构错误复用既有构造）。
其后新增的 xref 索引（`XrefIndex` / `XrefSite` / `XrefKind` / `build_xref` / `method_ref_of`）
同为加法性新增。

## 状态

| 门禁 | 结果 |
|---|---|
| `moon check --deny-warn` | ✅ 0 error / 0 warning |
| `moon build` | ✅ |
| `moon test` | ✅ 96 / 96（程序化/白盒 37 + 真实样本黄金与冒烟 12 + 畸形派生 7 + 注解/常量值/操作数语义 20 + xref 8 + R4 038+ 指令组 10 + P0 索引化回归 2；另有 3 个 `#skip` 用例不计入：第三方样本未提取、L3 真机、DEX 无 chunk 概念；分类明细见 `../README.md` §测试与验收） |
| `moon fmt --check` | ✅ |

黄金差分：**黄金期望值内嵌于测试代码**（`../fixtures_test.mbt` 黄金常量/内嵌黄金），`moon test`
即回归。开发期曾以独立差分脚本做"工具侧 `dexdump` ↔ 黄金 ↔ 解析侧 `@dex.parse`"三方差分
（tvshell-debug、motionshell、fx-multidex、fx-multidex2 全通过，方法与结论见 `../tests/ASSETS.md` §2）。
API 快照：`../pkg.generated.mbti`（`moon info` 生成）。

实现：✅ `parse` / 访问器 / `disasm` 均为真实实现；唯一保留的 TODO 是 `res0`/`data` 语义解释（见上表）。
