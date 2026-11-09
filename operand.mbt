///|
/// 结构化指令操作数视图与按表解析名字的 helper。
/// 对既有文本 `Instruction::operands`（smali 风格）的**加法性增强**：
/// 不改动 `Instruction` 冻结结构，新增 `InsnOperands` 视图（寄存器/字面量/
/// 跳转/常量池索引）与名字解析函数；文本 disasm 行为不变。
/// 解码布局与 `instr.mbt` 的文本解码一致（同一指令表、同一操作数格式）。

///|
/// 操作数中常量池引用的类别（结构化视图用）。
pub(all) enum IndexKind {
  IndexNone
  IndexString
  IndexType
  IndexField
  IndexMethod
  IndexCallSite
  IndexMethodHandle
  IndexProto
}

///|
/// 单条指令的结构化操作数视图。
/// - `regs`：寄存器序列（invoke 列表 / range 形式已展开为连续寄存器）。
/// - `literal`：整型字面量（const/4…const-wide、lit8/lit16；`None` 表示无）。
/// - `branch`：相对跳转偏移（以指令起始 code unit 计；`None` 表示无）。
/// - `index_kind` / `index`：常量池引用类别与索引（`IndexNone` 时索引无意义）。
/// switch / 数组 payload 伪指令返回空视图（其摘要保留在文本 `operands` 中）。
pub(all) struct InsnOperands {
  regs : Array[Int32]
  literal : Int64?
  branch : Int32?
  index_kind : IndexKind
  index : Int32
}

///|
/// RefKind（instr.mbt 内部表）→ IndexKind（公开视图）。
fn index_kind_of(k : RefKind) -> IndexKind {
  match k {
    KNone => IndexNone
    KString => IndexString
    KType => IndexType
    KField => IndexField
    KMethod => IndexMethod
    KCallSite => IndexCallSite
    KMethodHandle => IndexMethodHandle
    KProto => IndexProto
  }
}

///|
/// 构造空视图。
fn empty_operands() -> InsnOperands {
  InsnOperands::{
    regs: [],
    literal: None,
    branch: None,
    index_kind: IndexNone,
    index: 0,
  }
}

///|
/// 按指令格式解码结构化操作数（与 `decode_operands` 的文本布局镜像）。
fn decode_operands_struct(
  op : Int32,
  fmt : InstrFormat,
  kind : RefKind,
  word : Int32,
  raw : Bytes,
) -> InsnOperands {
  let u1 = if raw.length() >= 4 { read_u16(raw, 2) } else { 0 }
  let u2 = if raw.length() >= 6 { read_u16(raw, 4) } else { 0 }
  let a = (word >> 8) & 0xf
  let b = (word >> 12) & 0xf
  let aa = (word >> 8) & 0xff
  let base = empty_operands()
  match fmt {
    F10x => base
    F12x =>
      InsnOperands::{
        regs: [a, b],
        literal: None,
        branch: None,
        index_kind: IndexNone,
        index: 0,
      }
    F11n =>
      InsnOperands::{
        regs: [a],
        literal: Some(s4(b).to_int64()),
        branch: None,
        index_kind: IndexNone,
        index: 0,
      }
    F11x =>
      InsnOperands::{
        regs: [aa],
        literal: None,
        branch: None,
        index_kind: IndexNone,
        index: 0,
      }
    F10t =>
      InsnOperands::{
        regs: [],
        literal: None,
        branch: Some(s8(aa)),
        index_kind: IndexNone,
        index: 0,
      }
    F20t =>
      InsnOperands::{
        regs: [],
        literal: None,
        branch: Some(s16(u1)),
        index_kind: IndexNone,
        index: 0,
      }
    F22x =>
      InsnOperands::{
        regs: [aa, u1],
        literal: None,
        branch: None,
        index_kind: IndexNone,
        index: 0,
      }
    F21t =>
      InsnOperands::{
        regs: [aa],
        literal: None,
        branch: Some(s16(u1)),
        index_kind: IndexNone,
        index: 0,
      }
    F21s =>
      InsnOperands::{
        regs: [aa],
        literal: Some(s16(u1).to_int64()),
        branch: None,
        index_kind: IndexNone,
        index: 0,
      }
    F21h =>
      if op == 0x15 {
        // const/high16：低 16 位补零后的 32 位有符号常量
        InsnOperands::{
          regs: [aa],
          literal: Some((u1 << 16).to_int64()),
          branch: None,
          index_kind: IndexNone,
          index: 0,
        }
      } else {
        // const-wide/high16：高 16 位的 64 位有符号常量
        InsnOperands::{
          regs: [aa],
          literal: Some(s16(u1).to_int64() << 48),
          branch: None,
          index_kind: IndexNone,
          index: 0,
        }
      }
    F21c =>
      InsnOperands::{
        regs: [aa],
        literal: None,
        branch: None,
        index_kind: index_kind_of(kind),
        index: u1,
      }
    F23x =>
      InsnOperands::{
        regs: [aa, u1 & 0xff, (u1 >> 8) & 0xff],
        literal: None,
        branch: None,
        index_kind: IndexNone,
        index: 0,
      }
    F22b =>
      InsnOperands::{
        regs: [aa, u1 & 0xff],
        literal: Some(s8((u1 >> 8) & 0xff).to_int64()),
        branch: None,
        index_kind: IndexNone,
        index: 0,
      }
    F22t =>
      InsnOperands::{
        regs: [a, b],
        literal: None,
        branch: Some(s16(u1)),
        index_kind: IndexNone,
        index: 0,
      }
    F22s =>
      InsnOperands::{
        regs: [a, b],
        literal: Some(s16(u1).to_int64()),
        branch: None,
        index_kind: IndexNone,
        index: 0,
      }
    F22c =>
      InsnOperands::{
        regs: [a, b],
        literal: None,
        branch: None,
        index_kind: index_kind_of(kind),
        index: u1,
      }
    F30t =>
      InsnOperands::{
        regs: [],
        literal: None,
        branch: Some(read_u32(raw, 2)),
        index_kind: IndexNone,
        index: 0,
      }
    F32x =>
      InsnOperands::{
        regs: [u1, u2],
        literal: None,
        branch: None,
        index_kind: IndexNone,
        index: 0,
      }
    F31i =>
      InsnOperands::{
        regs: [aa],
        literal: Some(read_u32(raw, 2).to_int64()),
        branch: None,
        index_kind: IndexNone,
        index: 0,
      }
    F31t =>
      InsnOperands::{
        regs: [aa],
        literal: None,
        branch: Some(read_u32(raw, 2)),
        index_kind: IndexNone,
        index: 0,
      }
    F31c =>
      InsnOperands::{
        regs: [aa],
        literal: None,
        branch: None,
        index_kind: index_kind_of(kind),
        index: read_u32(raw, 2),
      }
    F35c | F45cc => {
      let count = b
      let g = a
      let c = u2 & 0xf
      let d = (u2 >> 4) & 0xf
      let e = (u2 >> 8) & 0xf
      let f = (u2 >> 12) & 0xf
      let all = [c, d, e, f, g]
      let regs : Array[Int32] = []
      for i in 0..<count {
        regs.push(all[i])
      }
      InsnOperands::{
        regs,
        literal: None,
        branch: None,
        index_kind: index_kind_of(kind),
        index: u1,
      }
    }
    F3rc | F4rcc => {
      let regs : Array[Int32] = []
      if aa > 0 {
        for i in 0..<aa {
          regs.push(u2 + i)
        }
      }
      InsnOperands::{
        regs,
        literal: None,
        branch: None,
        index_kind: index_kind_of(kind),
        index: u1,
      }
    }
    F51l => {
      let w1 = read_u16(raw, 2)
      let w2 = read_u16(raw, 4)
      let w3 = read_u16(raw, 6)
      let w4 = read_u16(raw, 8)
      let lit = (w1.to_int64() & 0xffffL) |
        ((w2.to_int64() & 0xffffL) << 16) |
        ((w3.to_int64() & 0xffffL) << 32) |
        ((w4.to_int64() & 0xffffL) << 48)
      InsnOperands::{
        regs: [aa],
        literal: Some(lit),
        branch: None,
        index_kind: IndexNone,
        index: 0,
      }
    }
  }
}

///|
/// 计算单条指令的结构化操作数视图（从 `Instruction::raw` 重解码，纯函数）。
///
/// - 参数：`insn` 为已解析指令（`parse` / `DexFile::code` 输出）。
/// - 返回：`InsnOperands`；switch / 数组 payload 伪指令返回空视图。
/// - 错误：未定义 opcode 抛 `InvalidInstruction(offset, opcode)`。
pub fn instruction_operands(insn : Instruction) -> InsnOperands raise DexError {
  let raw = insn.raw
  if raw.length() < 2 {
    return empty_operands()
  }
  let word = read_u16(raw, 0)
  let op = word & 0xff
  if op == 0x00 && word != 0 {
    // payload 伪指令（packed/sparse-switch、fill-array-data）
    return empty_operands()
  }
  match opcode_info(op) {
    None => raise DexError::InvalidInstruction(insn.offset, op)
    Some((_, fmt, kind)) => decode_operands_struct(op, fmt, kind, word, raw)
  }
}

///|
/// 按表解析字符串池项（const-string 的字符串池引用）。
pub fn string_ref_name(dex : DexFile, index : Int32) -> String raise DexError {
  if index < 0 || index >= dex.strings.length() {
    raise DexError::InvalidIndex(TableKind::StringId, index)
  }
  dex.strings[index]
}

///|
/// 按表解析类型引用为类名（类型描述符，如 `Lcom/foo/Bar;`）。
pub fn type_ref_name(dex : DexFile, index : Int32) -> String raise DexError {
  if index < 0 || index >= dex.type_descriptors.length() {
    raise DexError::InvalidIndex(TableKind::TypeId, index)
  }
  dex.type_descriptors[index]
}

///|
/// 按表解析字段引用为 `Lcls;->name:type`（与 disasm 文本一致）。
pub fn field_ref_name(dex : DexFile, index : Int32) -> String raise DexError {
  if index < 0 || index >= dex.fields.length() {
    raise DexError::InvalidIndex(TableKind::FieldId, index)
  }
  let f = dex.fields[index]
  if f.class_index < 0 || f.class_index >= dex.type_descriptors.length() {
    raise DexError::InvalidIndex(TableKind::TypeId, f.class_index)
  }
  if f.name_index < 0 || f.name_index >= dex.strings.length() {
    raise DexError::InvalidIndex(TableKind::StringId, f.name_index)
  }
  if f.type_index < 0 || f.type_index >= dex.type_descriptors.length() {
    raise DexError::InvalidIndex(TableKind::TypeId, f.type_index)
  }
  dex.type_descriptors[f.class_index] +
  "->" +
  dex.strings[f.name_index] +
  ":" +
  dex.type_descriptors[f.type_index]
}

///|
/// 按表解析方法引用（invoke-*）为 `Lcls;->name(params)ret`（与 disasm 文本一致）。
pub fn method_ref_name(dex : DexFile, index : Int32) -> String raise DexError {
  if index < 0 || index >= dex.methods.length() {
    raise DexError::InvalidIndex(TableKind::MethodId, index)
  }
  let m = dex.methods[index]
  if m.class_index < 0 || m.class_index >= dex.type_descriptors.length() {
    raise DexError::InvalidIndex(TableKind::TypeId, m.class_index)
  }
  if m.name_index < 0 || m.name_index >= dex.strings.length() {
    raise DexError::InvalidIndex(TableKind::StringId, m.name_index)
  }
  if m.proto_index < 0 || m.proto_index >= dex.protos.length() {
    raise DexError::InvalidIndex(TableKind::ProtoId, m.proto_index)
  }
  let p = dex.protos[m.proto_index]
  dex.type_descriptors[m.class_index] +
  "->" +
  dex.strings[m.name_index] +
  "(" +
  join_str(p.parameters, "") +
  ")" +
  p.return_type
}

///|
/// 按 `IndexKind` 综合解析常量池引用名字。
/// `IndexNone` 视为调用方错误，抛 `InvalidIndex(ClassDef, index)`。
pub fn resolve_ref_name(
  dex : DexFile,
  kind : IndexKind,
  index : Int32,
) -> String raise DexError {
  match kind {
    IndexNone => raise DexError::InvalidIndex(TableKind::ClassDef, index)
    IndexString => string_ref_name(dex, index)
    IndexType => type_ref_name(dex, index)
    IndexField => field_ref_name(dex, index)
    IndexMethod => method_ref_name(dex, index)
    IndexCallSite => call_site_name(dex, index)
    IndexMethodHandle => method_handle_name(dex, index)
    IndexProto => proto_name(dex, index)
  }
}

///|
/// 一步解析指令的常量池引用名字：invoke→`Lcls;->name(params)ret`、
/// const-string→字符串池项、字段引用→`Lcls;->name:type`、类型引用→类名。
/// 无引用操作数（如算术/跳转指令）返回 `None`。
pub fn instruction_ref_name(
  dex : DexFile,
  insn : Instruction,
) -> String? raise DexError {
  let ops = instruction_operands(insn)
  match ops.index_kind {
    IndexNone => None
    _ => Some(resolve_ref_name(dex, ops.index_kind, ops.index))
  }
}
