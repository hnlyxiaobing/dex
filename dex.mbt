///|
/// DEX 解析与 Dalvik 反汇编基础库的类型与公开接口。
///
/// 本文件为数据结构定义与公开 API 入口；解析实现见 `parse.mbt`、
/// 指令解码见 `instr.mbt`、smali 文本输出见 `disasm.mbt`。
/// 规范依据：AOSP dalvik-bytecode 文档与 dex 格式（Apache-2.0 / CC-BY-4.0 文档）。
/// 边界：单 DEX 容器 + 表 + code_item + 指令解码；不做 CFG、不做 Java 反编译。

///|
/// DEX 版本 / magic 前缀。多 dex（classes2.dex…）由上层合并，本库只管单个 DEX。
pub(all) enum DexVersion {
  Dex035
  Dex037
  Dex038
  Dex039
  Dex040
  Dex041
  Unknown(Int32)
}

///|
/// 六张索引表之一的类别标识，用于错误定位与诊断输出。
#derive(Debug)
pub(all) enum TableKind {
  StringId
  TypeId
  ProtoId
  FieldId
  MethodId
  ClassDef
  CallSiteId
  MethodHandle
  MapList
}

///|
pub extend TableKind with Debug::{to_repr}

///|
/// 单条 Dalvik 指令解码结果。`opcode` 为 0x00–0xFF 原值，`operands` 为已解码的字面量。
pub(all) struct Instruction {
  offset : Int32
  opcode : Int32
  mnemonic : String
  operands : Array[String]
  raw : Bytes
}

///|
/// try/catch 异常处理项；`handler_pc` 为 code_item 内以 code unit 计的偏移。
pub(all) struct TryItem {
  start_addr : Int32
  insn_count : Int32
  handler_off : Int32
  catch_type_index : Int32?
}

///|
/// code_item 的结构化表示；`debug_info` 保留原始字节，暂不展开。
pub(all) struct CodeItem {
  registers_size : Int32
  ins_size : Int32
  outs_size : Int32
  tries_size : Int32
  debug_info_off : Int32
  insns : Array[Instruction]
  tries : Array[TryItem]
  debug_info : Bytes
}

///|
/// 方法定义。`code` 为 `None` 表示 abstract / native 方法。
pub(all) struct MethodDef {
  class_index : Int32
  name_index : Int32
  proto_index : Int32
  access_flags : UInt32
  code_off : Int32
  code : CodeItem?
}

///|
/// 字段定义。
pub(all) struct FieldDef {
  class_index : Int32
  type_index : Int32
  name_index : Int32
  access_flags : UInt32
}

///|
/// 原型（proto_id）的结构化表示。
pub(all) struct ProtoId {
  shorty : String
  return_type : String
  parameters : Array[String]
}

///|
/// class_def 的结构化表示；`class_data_off = 0` 表示无 class_data。
pub(all) struct ClassDef {
  class_index : Int32
  type_descriptor : String
  superclass_index : Int32?
  interfaces : Array[Int32]
  source_file : String?
  access_flags : UInt32
  class_data_off : Int32
  static_fields : Array[FieldDef]
  instance_fields : Array[FieldDef]
  direct_methods : Array[MethodDef]
  virtual_methods : Array[MethodDef]
}

///|
/// 单 DEX 文件的解析结果（纯值，无句柄）。
pub(all) struct DexFile {
  version : DexVersion
  checksum : UInt32
  signature : Bytes
  file_size : Int32
  header_size : Int32
  endian_tag : UInt32
  strings : Array[String]
  type_descriptors : Array[String]
  protos : Array[ProtoId]
  fields : Array[FieldDef]
  methods : Array[MethodDef]
  classes : Array[ClassDef]
  /// DEX 038+：method_handles_item 表（无该表时为空）。
  handles : Array[MethodHandleItem]
  /// DEX 038+：call_site_id_item 表（无该表时为空）。
  call_sites : Array[CallSiteItem]
  map_list : Bytes
}

///|
/// DEX 错误模型：全部带偏移或索引，便于黄金样本差分定位。
#derive(Debug)
pub suberror DexError {
  UnexpectedEof(Int32)
  BadMagic(String)
  UnsupportedVersion(String)
  BadTableOffset(TableKind, Int32)
  InvalidIndex(TableKind, Int32)
  InvalidInstruction(Int32, Int32)
  BadCodeItem(Int32, String)
  BadDebugInfo(Int32, String)
  MultiDexNotMerged(String)
}

///|
pub extend DexError with Debug::{to_repr}

///|
/// 方法句柄：在 `DexFile` 内定位一个方法，作为 `code` / `disasm` 的输入。
pub type MethodHandle = Int32

///|
/// 只读反汇编输出契约，便于后续替换为不同文本后端。
pub trait Disassembler {
  fn disasm(Self, MethodHandle) -> String raise DexError
}

///|
/// 解析单个 DEX 字节流。
///
/// - 参数：`data` 为完整 DEX 文件字节；调用方保留所有权，本函数不缓存。
/// - 返回：`DexFile` 纯值，包含六张表、class_def 与已解码的 code_item/指令流。
/// - 错误：magic、版本、表偏移、索引越界、非法指令均以 `DexError` 传播。
/// - 线程：无全局可变状态，可并发解析不同 DEX；返回值为只读。
/// - 非目标：不做控制流图、不做 Java 反编译、不合并多 dex、不做符号解析。
pub fn parse(data : Bytes) -> DexFile raise DexError {
  parse_dex(data)
}

///|
/// 返回全部 class_def（保持文件内顺序）。
pub fn DexFile::classes(self : DexFile) -> Array[ClassDef] {
  self.classes
}

///|
/// 返回指定类（class_defs 表索引）下的全部方法（direct + virtual）。
/// `class_index` 越界抛 `InvalidIndex(ClassDef, class_index)`。
pub fn DexFile::methods(
  self : DexFile,
  class_index : Int32,
) -> Array[MethodDef] raise DexError {
  if class_index < 0 || class_index >= self.classes.length() {
    raise DexError::InvalidIndex(TableKind::ClassDef, class_index)
  }
  let c = self.classes[class_index]
  let out : Array[MethodDef] = []
  for m in c.direct_methods {
    out.push(m)
  }
  for m in c.virtual_methods {
    out.push(m)
  }
  out
}

///|
/// 返回指定方法（method_ids 表索引）的 code_item；abstract / native 方法返回 `None`。
/// `method_ref` 越界抛 `InvalidIndex(MethodId, method_ref)`。
pub fn DexFile::code(
  self : DexFile,
  method_ref : MethodHandle,
) -> CodeItem? raise DexError {
  if method_ref < 0 || method_ref >= self.methods.length() {
    raise DexError::InvalidIndex(TableKind::MethodId, method_ref)
  }
  self.methods[method_ref].code
}

///|
/// 返回字符串表（string_id 顺序）。
pub fn DexFile::strings(self : DexFile) -> Array[String] {
  self.strings
}

///|
/// 输出 smali 风格反汇编文本；不做 CFG、不做类型推断。
/// `method_ref` 为 method_ids 表索引；越界抛 `InvalidIndex(MethodId, ...)`。
pub fn disasm(
  dex : DexFile,
  method_ref : MethodHandle,
) -> String raise DexError {
  disasm_impl(dex, method_ref)
}
