///|
/// smali 风格文本输出：`.class` / `.method` 头、`.registers` 与逐条指令行。
/// 不做 CFG、不做类型推断；输出格式确定、便于黄金样本断言。

///|
/// 访问标志位 → smali 风格名称列表（method / class 公共子集）。
fn flags_parts(flags : UInt32) -> Array[String] {
  let parts : Array[String] = []
  if flags.land(0x1U) != 0U {
    parts.push("public")
  }
  if flags.land(0x2U) != 0U {
    parts.push("private")
  }
  if flags.land(0x4U) != 0U {
    parts.push("protected")
  }
  if flags.land(0x8U) != 0U {
    parts.push("static")
  }
  if flags.land(0x10U) != 0U {
    parts.push("final")
  }
  if flags.land(0x20U) != 0U {
    parts.push("synchronized")
  }
  if flags.land(0x40U) != 0U {
    parts.push("bridge")
  }
  if flags.land(0x80U) != 0U {
    parts.push("varargs")
  }
  if flags.land(0x100U) != 0U {
    parts.push("native")
  }
  if flags.land(0x200U) != 0U {
    parts.push("interface")
  }
  if flags.land(0x400U) != 0U {
    parts.push("abstract")
  }
  if flags.land(0x800U) != 0U {
    parts.push("strictfp")
  }
  if flags.land(0x1000U) != 0U {
    parts.push("synthetic")
  }
  if flags.land(0x2000U) != 0U {
    parts.push("constructor")
  }
  if flags.land(0x4000U) != 0U {
    parts.push("declared-synchronized")
  }
  parts
}

///|
/// 单条指令的文本行（不含缩进）。
fn insn_line(insn : Instruction) -> String {
  if insn.operands.is_empty() {
    insn.mnemonic
  } else {
    insn.mnemonic + " " + join_str(insn.operands, ", ")
  }
}

///|
/// `disasm` 的实现主体：方法头 + 指令流的 smali 风格文本。
fn disasm_impl(dex : DexFile, method_ref : Int32) -> String raise DexError {
  if method_ref < 0 || method_ref >= dex.methods.length() {
    raise DexError::InvalidIndex(TableKind::MethodId, method_ref)
  }
  let m = dex.methods[method_ref]
  if m.class_index < 0 || m.class_index >= dex.type_descriptors.length() {
    raise DexError::InvalidIndex(TableKind::TypeId, m.class_index)
  }
  if m.name_index < 0 || m.name_index >= dex.strings.length() {
    raise DexError::InvalidIndex(TableKind::StringId, m.name_index)
  }
  if m.proto_index < 0 || m.proto_index >= dex.protos.length() {
    raise DexError::InvalidIndex(TableKind::ProtoId, m.proto_index)
  }
  let descriptor = dex.type_descriptors[m.class_index]
  // .class 行：优先取 class_def 的访问标志
  let mut class_flags = 0U
  for c in dex.classes {
    if c.class_index == m.class_index {
      class_flags = c.access_flags
    }
  }
  let class_parts = flags_parts(class_flags)
  class_parts.push(descriptor)
  let p = dex.protos[m.proto_index]
  let sig = "(" + join_str(p.parameters, "") + ")" + p.return_type
  let method_parts = flags_parts(m.access_flags)
  method_parts.push(dex.strings[m.name_index] + sig)
  let lines : Array[String] = []
  lines.push(".class " + join_str(class_parts, " "))
  lines.push(".method " + join_str(method_parts, " "))
  match m.code {
    None => ()
    Some(code) => {
      lines.push("    .registers " + code.registers_size.to_string())
      for insn in code.insns {
        lines.push("    " + insn_line(insn))
      }
    }
  }
  lines.push(".end method")
  join_str(lines, "\n")
}
