# dex · DEX 解析与反汇编

> 独立发布单元 ｜ L1 逆向输入 ｜ `preferred_target = wasm` ｜ Apache-2.0
> 状态：`moon test` **109/109** 通过（2026-11-19 本机复验，另有 3 个 `#skip` 用例不计入）；本文件是本仓库**唯一**说明文档。
> 公开 API 以 `pkg.generated.mbti` 为准（由 `moon info` 生成，禁手工编辑）；加法性变更须登记簿记 + 快照审阅 + 快照门禁。

## 1. 定位与边界

把 DEX 字节解析成六表结构、指令序列、注解与交叉引用，输出可读清单与 smali 风格反汇编。

**能力**

- header / string / type / proto / field / method / class_def 六表解析与索引校验
- `code_item` 指令解码（含 DEX 038+ 指令组）、结构化操作数与全方法 opcode 序列
- 注解目录、静态字段初值、方法句柄 / 调用点
- `build_xref` 九种 kind 的调用点与字段访问点索引
- `dex-cli dump --view summary|norm|xref` 与 `disasm`（`--method` / `--json`）

**非目标**

- 不做 Java 反编译、CFG、跨 dex 合并或虚分派展开
- 不覆盖反射、MethodHandle 运行时目标、JNI RegisterNatives、动态代理与运行时织入
- 不 import 任何其他工作区模块
- **access_flags 以原始 `Int32` 输出**；高 16 位含 ART hiddenapi 内部标记（blocked/greylist/max-target-* 等），这些位**不属于 DEX 格式规范**而是 Android 运行时在构建过程注入的约定——本库不解释、不映射、不声明枚举
- **不实施 Multi-DEX 合并**：`DexFile` 是单 DEX 文件的完整、自洽解析单元，索引空间封闭于自身。`MultiDexNotMerged` 显式拒绝多 dex 拼接/容器输入。跨 DEX 编排（合并、去重、索引重映射）属下游工具职责，本库仅保证单 DEX 结构事实忠实可依赖

## 2. 关键设计决策（本仓库自足记录）

- 以 `Bytes` 为输入契约，自研解析而不移植 `classfile@0.2.0`（legacy 格式，仅作参照）。
- P0 防回归：`class_data_item` 的 `method_idx_diff` 必须在 direct / virtual 分段处复位；该缺陷曾由黄金差分抓出。
- 性能门禁：7.26 MB `classes.dex` 的 `summary` 由 >540 s 优化到 1,014 ms，做法是每类缓存六表而非重建。
- 全方法 opcode 序列差分取代抽样差分，以保持黄金证据链的捕获能力。

## 3. 公开 API 索引（自动抽取 `pkg.generated.mbti` 的 `pub` 声明行；完整字段见快照）

```text
pub fn annotation_item(Bytes, Int32) -> Annotation raise DexError
pub fn annotation_set(Bytes, Int32) -> AnnotationSet raise DexError
pub fn annotations_index(Bytes) -> AnnotationsIndex raise DexError
pub fn build_xref(DexFile) -> XrefIndex raise DexError
pub fn call_site_name(DexFile, Int32) -> String raise DexError
pub fn call_site_ref_name(Bytes, Int32) -> String raise DexError
pub fn call_sites(Bytes) -> Array[CallSiteItem] raise DexError
pub fn class_annotations(Bytes, Int32) -> AnnotationsDirectory? raise DexError
pub fn disasm(DexFile, Int32) -> String raise DexError
pub fn encoded_array(Bytes, Int32) -> Array[EncodedValue] raise DexError
pub fn field_ref_name(DexFile, Int32) -> String raise DexError
pub fn instruction_operands(Instruction) -> InsnOperands raise DexError
pub fn instruction_ref_name(DexFile, Instruction) -> String? raise DexError
pub fn method_handle_name(DexFile, Int32) -> String raise DexError
pub fn method_handle_ref_name(Bytes, Int32) -> String raise DexError
pub fn method_handles(Bytes) -> Array[MethodHandleItem] raise DexError
pub fn method_ref_name(DexFile, Int32) -> String raise DexError
pub fn method_ref_of(DexFile, MethodDef) -> Int32?
pub fn parse(Bytes) -> DexFile raise DexError
pub fn proto_name(DexFile, Int32) -> String raise DexError
pub fn resolve_ref_name(DexFile, IndexKind, Int32) -> String raise DexError
pub fn signature_ok(Bytes) -> Bool raise DexError
pub fn static_values(Bytes, Int32) -> Array[EncodedValue] raise DexError
pub fn string_ref_name(DexFile, Int32) -> String raise DexError
pub fn type_ref_name(DexFile, Int32) -> String raise DexError
pub(all) struct Annotation {
pub(all) struct AnnotationElement {
pub(all) struct AnnotationSet {
pub(all) enum AnnotationVisibility {
pub(all) struct AnnotationsDirectory {
pub struct AnnotationsIndex {
pub fn AnnotationsIndex::class_annotations(Self, Int32) -> AnnotationsDirectory? raise DexError
pub fn AnnotationsIndex::static_values(Self, Int32) -> Array[EncodedValue] raise DexError
pub(all) struct CallSiteItem {
pub(all) struct ClassDef {
pub(all) struct CodeItem {
pub suberror DexError {
pub fn DexError::to_repr(Self) -> @debug.Repr
pub(all) struct DexFile {
pub fn DexFile::classes(Self) -> Array[ClassDef]
pub fn DexFile::code(Self, Int32) -> CodeItem? raise DexError
pub fn DexFile::methods(Self, Int32) -> Array[MethodDef] raise DexError
pub fn DexFile::strings(Self) -> Array[String]
pub(all) enum DexVersion {
pub trait Disassembler {
pub(all) struct EncodedAnnotation {
pub(all) enum EncodedValue {
pub(all) struct FieldAnnotations {
pub(all) struct FieldDef {
pub(all) enum IndexKind {
pub(all) struct InsnOperands {
pub(all) struct Instruction {
pub(all) struct MethodAnnotations {
pub(all) struct MethodDef {
pub type MethodHandle = Int32
pub(all) struct MethodHandleItem {
pub fn MethodHandleItem::is_field_ref(Self) -> Bool
pub fn MethodHandleItem::is_method_ref(Self) -> Bool
pub(all) enum MethodHandleKind {
pub(all) struct ParameterAnnotations {
pub(all) struct ProtoId {
pub(all) enum TableKind {
pub fn TableKind::to_repr(Self) -> @debug.Repr
pub(all) struct TryItem {
pub struct XrefIndex {
pub fn XrefIndex::callees(Self, Int32) -> Array[XrefSite] raise DexError
pub fn XrefIndex::callers(Self, Int32) -> Array[XrefSite] raise DexError
pub fn XrefIndex::field_sites(Self, Int32) -> Array[XrefSite] raise DexError
pub fn XrefIndex::method_sites(Self, Int32) -> Array[XrefSite] raise DexError
pub fn XrefIndex::sites(Self) -> Array[XrefSite]
pub fn XrefIndex::sites_in(Self, Int32) -> Array[XrefSite] raise DexError
pub(all) enum XrefKind {
pub(all) struct XrefSite {
```

## 4. 依赖、平台与许可

零第三方依赖；`preferred_target = wasm`；Apache-2.0。

## 5. 命令行与验证

- `moon run cmd/main --target native -- dump <apk|dex> [--view ...] [--json]` / `disasm <apk|dex> [--method <ref>]`；`--json` 同步输出 `annotations` / `static_values`。
- APK 输入：条目 CRC-32 不符（或解压失败）时**整体拒绝**，无部分输出，退出码 1（见 `cmd/main/zipmin.mbt`）。
- 复验：`moon clean` → `moon check --deny-warn` → `moon build` → `moon test` → `moon fmt --check` → `moon info` 后检查 `pkg.generated.mbti` 无意外 diff。
- 本仓库为独立 Git 仓库，文档与 CI 均自包含，不依赖工作区其他目录。

## 6. 风险与未决

- xref 盲区：反射、运行时目标解析、JNI RegisterNatives、跨 dex 合并、注解/encoded_array 引用。
- 资源表与 DEX 的关联由组合根完成，本库不感知 APK 容器。

