///|
/// Dalvik 指令解码：opcode → (助记符, 指令格式, 引用类型) 表与操作数格式化。
/// 范围：AOSP dalvik-bytecode 中 0x00–0xE2 的 218 条已定义指令；
/// 0x3E–0x43 / 0x73 / 0x79 / 0x7A 为未定义，0xE3–0xFF 超出本库范围
/// （含 DEX 038+ 的 0xFA–0xFE，属 API.md 标注的 W3 延后项），解码到它们抛 `InvalidInstruction`。

///|
/// 指令格式（决定宽度与操作数布局），对应 AOSP 十种基础格式。
priv enum InstrFormat {
  F10x
  F12x
  F11n
  F11x
  F10t
  F20t
  F22x
  F21t
  F21s
  F21h
  F21c
  F23x
  F22b
  F22t
  F22s
  F22c
  F30t
  F32x
  F31i
  F31t
  F31c
  F35c
  F3rc
  F51l
}

///|
/// 操作数中常量池引用的类别。
priv enum RefKind {
  KNone
  KString
  KType
  KField
  KMethod
}

///|
/// 指令宽度（16 位 code unit 数）。
fn fmt_width(f : InstrFormat) -> Int32 {
  match f {
    F10x => 1
    F12x => 1
    F11n => 1
    F11x => 1
    F10t => 1
    F20t => 2
    F22x => 2
    F21t => 2
    F21s => 2
    F21h => 2
    F21c => 2
    F23x => 2
    F22b => 2
    F22t => 2
    F22s => 2
    F22c => 2
    F30t => 3
    F32x => 3
    F31i => 3
    F31t => 3
    F31c => 3
    F35c => 3
    F3rc => 3
    F51l => 5
  }
}

///|
/// opcode 查询：返回 (助记符, 格式, 引用类别)；未定义 / 超范围 opcode 返回 `None`。
fn opcode_info(op : Int32) -> (String, InstrFormat, RefKind)? {
  match op {
    0x00 => Some(("nop", F10x, KNone))
    0x01 => Some(("move", F12x, KNone))
    0x02 => Some(("move/from16", F22x, KNone))
    0x03 => Some(("move/16", F32x, KNone))
    0x04 => Some(("move-wide", F12x, KNone))
    0x05 => Some(("move-wide/from16", F22x, KNone))
    0x06 => Some(("move-wide/16", F32x, KNone))
    0x07 => Some(("move-object", F12x, KNone))
    0x08 => Some(("move-object/from16", F22x, KNone))
    0x09 => Some(("move-object/16", F32x, KNone))
    0x0a => Some(("move-result", F11x, KNone))
    0x0b => Some(("move-result-wide", F11x, KNone))
    0x0c => Some(("move-result-object", F11x, KNone))
    0x0d => Some(("move-exception", F11x, KNone))
    0x0e => Some(("return-void", F10x, KNone))
    0x0f => Some(("return", F11x, KNone))
    0x10 => Some(("return-wide", F11x, KNone))
    0x11 => Some(("return-object", F11x, KNone))
    0x12 => Some(("const/4", F11n, KNone))
    0x13 => Some(("const/16", F21s, KNone))
    0x14 => Some(("const", F31i, KNone))
    0x15 => Some(("const/high16", F21h, KNone))
    0x16 => Some(("const-wide/16", F21s, KNone))
    0x17 => Some(("const-wide/32", F31i, KNone))
    0x18 => Some(("const-wide", F51l, KNone))
    0x19 => Some(("const-wide/high16", F21h, KNone))
    0x1a => Some(("const-string", F21c, KString))
    0x1b => Some(("const-string/jumbo", F31c, KString))
    0x1c => Some(("const-class", F21c, KType))
    0x1d => Some(("monitor-enter", F11x, KNone))
    0x1e => Some(("monitor-exit", F11x, KNone))
    0x1f => Some(("check-cast", F21c, KType))
    0x20 => Some(("instance-of", F22c, KType))
    0x21 => Some(("array-length", F12x, KNone))
    0x22 => Some(("new-instance", F21c, KType))
    0x23 => Some(("new-array", F22c, KType))
    0x24 => Some(("filled-new-array", F35c, KType))
    0x25 => Some(("filled-new-array/range", F3rc, KType))
    0x26 => Some(("fill-array-data", F31t, KNone))
    0x27 => Some(("throw", F11x, KNone))
    0x28 => Some(("goto", F10t, KNone))
    0x29 => Some(("goto/16", F20t, KNone))
    0x2a => Some(("goto/32", F30t, KNone))
    0x2b => Some(("packed-switch", F31t, KNone))
    0x2c => Some(("sparse-switch", F31t, KNone))
    0x2d => Some(("cmpl-float", F23x, KNone))
    0x2e => Some(("cmpg-float", F23x, KNone))
    0x2f => Some(("cmpl-double", F23x, KNone))
    0x30 => Some(("cmpg-double", F23x, KNone))
    0x31 => Some(("cmp-long", F23x, KNone))
    0x32 => Some(("if-eq", F22t, KNone))
    0x33 => Some(("if-ne", F22t, KNone))
    0x34 => Some(("if-lt", F22t, KNone))
    0x35 => Some(("if-ge", F22t, KNone))
    0x36 => Some(("if-gt", F22t, KNone))
    0x37 => Some(("if-le", F22t, KNone))
    0x38 => Some(("if-eqz", F21t, KNone))
    0x39 => Some(("if-nez", F21t, KNone))
    0x3a => Some(("if-ltz", F21t, KNone))
    0x3b => Some(("if-gez", F21t, KNone))
    0x3c => Some(("if-gtz", F21t, KNone))
    0x3d => Some(("if-lez", F21t, KNone))
    0x44 => Some(("aget", F23x, KNone))
    0x45 => Some(("aget-wide", F23x, KNone))
    0x46 => Some(("aget-object", F23x, KNone))
    0x47 => Some(("aget-boolean", F23x, KNone))
    0x48 => Some(("aget-byte", F23x, KNone))
    0x49 => Some(("aget-char", F23x, KNone))
    0x4a => Some(("aget-short", F23x, KNone))
    0x4b => Some(("aput", F23x, KNone))
    0x4c => Some(("aput-wide", F23x, KNone))
    0x4d => Some(("aput-object", F23x, KNone))
    0x4e => Some(("aput-boolean", F23x, KNone))
    0x4f => Some(("aput-byte", F23x, KNone))
    0x50 => Some(("aput-char", F23x, KNone))
    0x51 => Some(("aput-short", F23x, KNone))
    0x52 => Some(("iget", F22c, KField))
    0x53 => Some(("iget-wide", F22c, KField))
    0x54 => Some(("iget-object", F22c, KField))
    0x55 => Some(("iget-boolean", F22c, KField))
    0x56 => Some(("iget-byte", F22c, KField))
    0x57 => Some(("iget-char", F22c, KField))
    0x58 => Some(("iget-short", F22c, KField))
    0x59 => Some(("iput", F22c, KField))
    0x5a => Some(("iput-wide", F22c, KField))
    0x5b => Some(("iput-object", F22c, KField))
    0x5c => Some(("iput-boolean", F22c, KField))
    0x5d => Some(("iput-byte", F22c, KField))
    0x5e => Some(("iput-char", F22c, KField))
    0x5f => Some(("iput-short", F22c, KField))
    0x60 => Some(("sget", F21c, KField))
    0x61 => Some(("sget-wide", F21c, KField))
    0x62 => Some(("sget-object", F21c, KField))
    0x63 => Some(("sget-boolean", F21c, KField))
    0x64 => Some(("sget-byte", F21c, KField))
    0x65 => Some(("sget-char", F21c, KField))
    0x66 => Some(("sget-short", F21c, KField))
    0x67 => Some(("sput", F21c, KField))
    0x68 => Some(("sput-wide", F21c, KField))
    0x69 => Some(("sput-object", F21c, KField))
    0x6a => Some(("sput-boolean", F21c, KField))
    0x6b => Some(("sput-byte", F21c, KField))
    0x6c => Some(("sput-char", F21c, KField))
    0x6d => Some(("sput-short", F21c, KField))
    0x6e => Some(("invoke-virtual", F35c, KMethod))
    0x6f => Some(("invoke-super", F35c, KMethod))
    0x70 => Some(("invoke-direct", F35c, KMethod))
    0x71 => Some(("invoke-static", F35c, KMethod))
    0x72 => Some(("invoke-interface", F35c, KMethod))
    0x74 => Some(("invoke-virtual/range", F3rc, KMethod))
    0x75 => Some(("invoke-super/range", F3rc, KMethod))
    0x76 => Some(("invoke-direct/range", F3rc, KMethod))
    0x77 => Some(("invoke-static/range", F3rc, KMethod))
    0x78 => Some(("invoke-interface/range", F3rc, KMethod))
    0x7b => Some(("neg-int", F12x, KNone))
    0x7c => Some(("not-int", F12x, KNone))
    0x7d => Some(("neg-long", F12x, KNone))
    0x7e => Some(("not-long", F12x, KNone))
    0x7f => Some(("neg-float", F12x, KNone))
    0x80 => Some(("neg-double", F12x, KNone))
    0x81 => Some(("int-to-long", F12x, KNone))
    0x82 => Some(("int-to-float", F12x, KNone))
    0x83 => Some(("int-to-double", F12x, KNone))
    0x84 => Some(("long-to-int", F12x, KNone))
    0x85 => Some(("long-to-float", F12x, KNone))
    0x86 => Some(("long-to-double", F12x, KNone))
    0x87 => Some(("float-to-int", F12x, KNone))
    0x88 => Some(("float-to-long", F12x, KNone))
    0x89 => Some(("float-to-double", F12x, KNone))
    0x8a => Some(("double-to-int", F12x, KNone))
    0x8b => Some(("double-to-long", F12x, KNone))
    0x8c => Some(("double-to-float", F12x, KNone))
    0x8d => Some(("int-to-byte", F12x, KNone))
    0x8e => Some(("int-to-char", F12x, KNone))
    0x8f => Some(("int-to-short", F12x, KNone))
    0x90 => Some(("add-int", F23x, KNone))
    0x91 => Some(("sub-int", F23x, KNone))
    0x92 => Some(("mul-int", F23x, KNone))
    0x93 => Some(("div-int", F23x, KNone))
    0x94 => Some(("rem-int", F23x, KNone))
    0x95 => Some(("and-int", F23x, KNone))
    0x96 => Some(("or-int", F23x, KNone))
    0x97 => Some(("xor-int", F23x, KNone))
    0x98 => Some(("shl-int", F23x, KNone))
    0x99 => Some(("shr-int", F23x, KNone))
    0x9a => Some(("ushr-int", F23x, KNone))
    0x9b => Some(("add-long", F23x, KNone))
    0x9c => Some(("sub-long", F23x, KNone))
    0x9d => Some(("mul-long", F23x, KNone))
    0x9e => Some(("div-long", F23x, KNone))
    0x9f => Some(("rem-long", F23x, KNone))
    0xa0 => Some(("and-long", F23x, KNone))
    0xa1 => Some(("or-long", F23x, KNone))
    0xa2 => Some(("xor-long", F23x, KNone))
    0xa3 => Some(("shl-long", F23x, KNone))
    0xa4 => Some(("shr-long", F23x, KNone))
    0xa5 => Some(("ushr-long", F23x, KNone))
    0xa6 => Some(("add-float", F23x, KNone))
    0xa7 => Some(("sub-float", F23x, KNone))
    0xa8 => Some(("mul-float", F23x, KNone))
    0xa9 => Some(("div-float", F23x, KNone))
    0xaa => Some(("rem-float", F23x, KNone))
    0xab => Some(("add-double", F23x, KNone))
    0xac => Some(("sub-double", F23x, KNone))
    0xad => Some(("mul-double", F23x, KNone))
    0xae => Some(("div-double", F23x, KNone))
    0xaf => Some(("rem-double", F23x, KNone))
    0xb0 => Some(("add-int/2addr", F12x, KNone))
    0xb1 => Some(("sub-int/2addr", F12x, KNone))
    0xb2 => Some(("mul-int/2addr", F12x, KNone))
    0xb3 => Some(("div-int/2addr", F12x, KNone))
    0xb4 => Some(("rem-int/2addr", F12x, KNone))
    0xb5 => Some(("and-int/2addr", F12x, KNone))
    0xb6 => Some(("or-int/2addr", F12x, KNone))
    0xb7 => Some(("xor-int/2addr", F12x, KNone))
    0xb8 => Some(("shl-int/2addr", F12x, KNone))
    0xb9 => Some(("shr-int/2addr", F12x, KNone))
    0xba => Some(("ushr-int/2addr", F12x, KNone))
    0xbb => Some(("add-long/2addr", F12x, KNone))
    0xbc => Some(("sub-long/2addr", F12x, KNone))
    0xbd => Some(("mul-long/2addr", F12x, KNone))
    0xbe => Some(("div-long/2addr", F12x, KNone))
    0xbf => Some(("rem-long/2addr", F12x, KNone))
    0xc0 => Some(("and-long/2addr", F12x, KNone))
    0xc1 => Some(("or-long/2addr", F12x, KNone))
    0xc2 => Some(("xor-long/2addr", F12x, KNone))
    0xc3 => Some(("shl-long/2addr", F12x, KNone))
    0xc4 => Some(("shr-long/2addr", F12x, KNone))
    0xc5 => Some(("ushr-long/2addr", F12x, KNone))
    0xc6 => Some(("add-float/2addr", F12x, KNone))
    0xc7 => Some(("sub-float/2addr", F12x, KNone))
    0xc8 => Some(("mul-float/2addr", F12x, KNone))
    0xc9 => Some(("div-float/2addr", F12x, KNone))
    0xca => Some(("rem-float/2addr", F12x, KNone))
    0xcb => Some(("add-double/2addr", F12x, KNone))
    0xcc => Some(("sub-double/2addr", F12x, KNone))
    0xcd => Some(("mul-double/2addr", F12x, KNone))
    0xce => Some(("div-double/2addr", F12x, KNone))
    0xcf => Some(("rem-double/2addr", F12x, KNone))
    0xd0 => Some(("add-int/lit16", F22s, KNone))
    0xd1 => Some(("rsub-int", F22s, KNone))
    0xd2 => Some(("mul-int/lit16", F22s, KNone))
    0xd3 => Some(("div-int/lit16", F22s, KNone))
    0xd4 => Some(("rem-int/lit16", F22s, KNone))
    0xd5 => Some(("and-int/lit16", F22s, KNone))
    0xd6 => Some(("or-int/lit16", F22s, KNone))
    0xd7 => Some(("xor-int/lit16", F22s, KNone))
    0xd8 => Some(("add-int/lit8", F22b, KNone))
    0xd9 => Some(("rsub-int/lit8", F22b, KNone))
    0xda => Some(("mul-int/lit8", F22b, KNone))
    0xdb => Some(("div-int/lit8", F22b, KNone))
    0xdc => Some(("rem-int/lit8", F22b, KNone))
    0xdd => Some(("and-int/lit8", F22b, KNone))
    0xde => Some(("or-int/lit8", F22b, KNone))
    0xdf => Some(("xor-int/lit8", F22b, KNone))
    0xe0 => Some(("shl-int/lit8", F22b, KNone))
    0xe1 => Some(("shr-int/lit8", F22b, KNone))
    0xe2 => Some(("ushr-int/lit8", F22b, KNone))
    _ => None
  }
}

///|
/// 解析 string@ 引用为带引号转义的字面量。
fn fmt_string_ref(ctx : Ctx, idx : Int32) -> String raise DexError {
  if idx < 0 || idx >= ctx.strings.length() {
    raise DexError::InvalidIndex(TableKind::StringId, idx)
  }
  ctx.strings[idx].escape(quote=true)
}

///|
/// 解析 type@ 引用为类型描述符。
fn fmt_type_ref(ctx : Ctx, idx : Int32) -> String raise DexError {
  if idx < 0 || idx >= ctx.types.length() {
    raise DexError::InvalidIndex(TableKind::TypeId, idx)
  }
  ctx.types[idx]
}

///|
/// 解析 field@ 引用为 `Lcls;->name:type`。
fn fmt_field_ref(ctx : Ctx, idx : Int32) -> String raise DexError {
  if idx < 0 || idx >= ctx.fields.length() {
    raise DexError::InvalidIndex(TableKind::FieldId, idx)
  }
  let f = ctx.fields[idx]
  if f.class_index < 0 || f.class_index >= ctx.types.length() {
    raise DexError::InvalidIndex(TableKind::TypeId, f.class_index)
  }
  if f.name_index < 0 || f.name_index >= ctx.strings.length() {
    raise DexError::InvalidIndex(TableKind::StringId, f.name_index)
  }
  if f.type_index < 0 || f.type_index >= ctx.types.length() {
    raise DexError::InvalidIndex(TableKind::TypeId, f.type_index)
  }
  ctx.types[f.class_index] +
  "->" +
  ctx.strings[f.name_index] +
  ":" +
  ctx.types[f.type_index]
}

///|
/// 解析 method@ 引用为 `Lcls;->name(params)ret`。
fn fmt_method_ref(ctx : Ctx, idx : Int32) -> String raise DexError {
  if idx < 0 || idx >= ctx.methods.length() {
    raise DexError::InvalidIndex(TableKind::MethodId, idx)
  }
  let m = ctx.methods[idx]
  if m.class_index < 0 || m.class_index >= ctx.types.length() {
    raise DexError::InvalidIndex(TableKind::TypeId, m.class_index)
  }
  if m.name_index < 0 || m.name_index >= ctx.strings.length() {
    raise DexError::InvalidIndex(TableKind::StringId, m.name_index)
  }
  if m.proto_index < 0 || m.proto_index >= ctx.protos.length() {
    raise DexError::InvalidIndex(TableKind::ProtoId, m.proto_index)
  }
  let p = ctx.protos[m.proto_index]
  ctx.types[m.class_index] +
  "->" +
  ctx.strings[m.name_index] +
  "(" +
  join_str(p.parameters, "") +
  ")" +
  p.return_type
}

///|
/// 按引用类别格式化常量池引用。
fn fmt_ref(ctx : Ctx, kind : RefKind, idx : Int32) -> String raise DexError {
  match kind {
    KNone => ""
    KString => fmt_string_ref(ctx, idx)
    KType => fmt_type_ref(ctx, idx)
    KField => fmt_field_ref(ctx, idx)
    KMethod => fmt_method_ref(ctx, idx)
  }
}

///|
/// 4 位有符号立即数。
fn s4(v : Int32) -> Int32 {
  if v >= 8 {
    v - 16
  } else {
    v
  }
}

///|
/// 8 位有符号立即数。
fn s8(v : Int32) -> Int32 {
  if v >= 128 {
    v - 256
  } else {
    v
  }
}

///|
/// 16 位有符号立即数。
fn s16(v : Int32) -> Int32 {
  if v >= 0x8000 {
    v - 0x10000
  } else {
    v
  }
}

///|
/// 寄存器列表文本：`{v0, v1}` 或区间 `{v2 .. v5}`。
fn fmt_reg_list(regs : Array[Int32], range~ : Bool = false) -> String {
  if range {
    if regs.length() == 1 {
      "{" + fmt_reg(regs[0]) + "}"
    } else {
      "{" + fmt_reg(regs[0]) + " .. " + fmt_reg(regs[regs.length() - 1]) + "}"
    }
  } else {
    let parts : Array[String] = []
    for r in regs {
      parts.push(fmt_reg(r))
    }
    "{" + join_str(parts, ", ") + "}"
  }
}

///|
/// 按格式解码操作数为 smali 风格文本。
fn decode_operands(
  ctx : Ctx,
  op : Int32,
  fmt : InstrFormat,
  kind : RefKind,
  word : Int32,
  foff : Int32,
  data : Bytes,
) -> Array[String] raise DexError {
  let u1 = if foff + 4 <= data.length() { read_u16(data, foff + 2) } else { 0 }
  let u2 = if foff + 6 <= data.length() { read_u16(data, foff + 4) } else { 0 }
  let a = (word >> 8) & 0xf
  let b = (word >> 12) & 0xf
  let aa = (word >> 8) & 0xff
  match fmt {
    F10x => []
    F12x => [fmt_reg(a), fmt_reg(b)]
    F11n => [fmt_reg(a), fmt_sint(s4(b))]
    F11x => [fmt_reg(aa)]
    F10t => [fmt_off(s8(aa))]
    F20t => [fmt_off(s16(u1))]
    F22x => [fmt_reg(aa), fmt_reg(u1)]
    F21t => [fmt_reg(aa), fmt_off(s16(u1))]
    F21s => [fmt_reg(aa), fmt_sint(s16(u1))]
    F21h =>
      if op == 0x15 {
        [fmt_reg(aa), fmt_sint(u1 << 16)]
      } else {
        let negative = (u1 & 0x8000) != 0
        let mag = if negative { 0x10000 - u1 } else { u1 }
        let text = if negative { "#-0x" } else { "#+0x" }
        [
          fmt_reg(aa),
          text + hex_u(mag.reinterpret_as_uint(), 1) + "000000000000",
        ]
      }
    F21c => [fmt_reg(aa), fmt_ref(ctx, kind, u1)]
    F23x => [fmt_reg(aa), fmt_reg(u1 & 0xff), fmt_reg((u1 >> 8) & 0xff)]
    F22b => [fmt_reg(aa), fmt_reg(u1 & 0xff), fmt_sint(s8((u1 >> 8) & 0xff))]
    F22t => [fmt_reg(a), fmt_reg(b), fmt_off(s16(u1))]
    F22s => [fmt_reg(a), fmt_reg(b), fmt_sint(s16(u1))]
    F22c => [fmt_reg(a), fmt_reg(b), fmt_ref(ctx, kind, u1)]
    F30t => [fmt_off(read_u32(data, foff + 2))]
    F32x => [fmt_reg(u1), fmt_reg(u2)]
    F31i => [fmt_reg(aa), fmt_sint(read_u32(data, foff + 2))]
    F31t => [fmt_reg(aa), fmt_off(read_u32(data, foff + 2))]
    F31c => [fmt_reg(aa), fmt_ref(ctx, kind, read_u32(data, foff + 2))]
    F35c => {
      let count = b
      let g = a
      let c = u2 & 0xf
      let d = (u2 >> 4) & 0xf
      let e = (u2 >> 8) & 0xf
      let f = (u2 >> 12) & 0xf
      let regs : Array[Int32] = []
      let all = [c, d, e, f, g]
      for i in 0..<count {
        regs.push(all[i])
      }
      [fmt_reg_list(regs), fmt_ref(ctx, kind, u1)]
    }
    F3rc => {
      let regs : Array[Int32] = []
      if aa > 0 {
        for i in 0..<aa {
          regs.push(u2 + i)
        }
      }
      [fmt_reg_list(regs, range=true), fmt_ref(ctx, kind, u1)]
    }
    F51l => {
      let w1 = read_u16(data, foff + 2)
      let w2 = read_u16(data, foff + 4)
      let w3 = read_u16(data, foff + 6)
      let w4 = read_u16(data, foff + 8)
      [fmt_reg(aa), fmt_sint64([w1, w2, w3, w4])]
    }
  }
}

///|
/// 三种 payload 伪指令的宽度与操作数（switch/数组初始值数据块）。
fn decode_payload(
  code_off : Int32,
  u : Int32,
  ident : Int32,
  insns_size : Int32,
  insns_start : Int32,
  data : Bytes,
) -> (Int32, String, Array[String]) raise DexError {
  let foff = insns_start + u * 2
  if ident == 0x0100 {
    // packed-switch-payload: ident, size, first_key, targets[size]
    if u + 4 > insns_size {
      raise DexError::BadCodeItem(code_off, "truncated packed-switch-payload")
    }
    let size = read_u16(data, foff + 2)
    let total = 4 + size * 2
    if size < 0 || u + total > insns_size {
      raise DexError::BadCodeItem(code_off, "truncated packed-switch-payload")
    }
    let first_key = read_u32(data, foff + 4)
    let operands : Array[String] = [
      "size=" + size.to_string(),
      "first_key=" + fmt_sint(first_key),
    ]
    for i in 0..<size {
      let target = read_u32(data, foff + 8 + i * 4)
      operands.push(fmt_sint(first_key + i) + "->" + fmt_off(target))
    }
    (total, "packed-switch-payload", operands)
  } else if ident == 0x0200 {
    // sparse-switch-payload: ident, size, keys[size], targets[size]
    if u + 2 > insns_size {
      raise DexError::BadCodeItem(code_off, "truncated sparse-switch-payload")
    }
    let size = read_u16(data, foff + 2)
    let total = 2 + size * 4
    if size < 0 || u + total > insns_size {
      raise DexError::BadCodeItem(code_off, "truncated sparse-switch-payload")
    }
    let operands : Array[String] = ["size=" + size.to_string()]
    for i in 0..<size {
      let key = read_u32(data, foff + 4 + i * 4)
      let target = read_u32(data, foff + 4 + (size + i) * 4)
      operands.push(fmt_sint(key) + "->" + fmt_off(target))
    }
    (total, "sparse-switch-payload", operands)
  } else if ident == 0x0300 {
    // fill-array-data-payload: ident, element_width, size(u32), data
    if u + 4 > insns_size {
      raise DexError::BadCodeItem(code_off, "truncated fill-array-data-payload")
    }
    let width = read_u16(data, foff + 2)
    let size = read_u32(data, foff + 4)
    if size < 0 || (width != 0 && size > 0x3fffffff / width) {
      raise DexError::BadCodeItem(code_off, "fill-array-data size overflow")
    }
    let data_bytes = size * width
    let total = 4 + (data_bytes + 1) / 2
    if u + total > insns_size {
      raise DexError::BadCodeItem(code_off, "truncated fill-array-data-payload")
    }
    (
      total,
      "fill-array-data-payload",
      ["width=" + width.to_string(), "size=" + size.to_string()],
    )
  } else {
    raise DexError::BadCodeItem(
      code_off,
      "unknown payload ident " + ident.to_string(),
    )
  }
}

///|
/// 解码指令流：code unit 偏移 `u` 上的每个指令 / payload 伪指令 → `Instruction`。
/// 非法 opcode 抛 `InvalidInstruction(偏移, opcode)`；截断抛 `BadCodeItem`。
fn decode_insns(
  ctx : Ctx,
  code_off : Int32,
  insns_start : Int32,
  insns_size : Int32,
  data : Bytes,
) -> Array[Instruction] raise DexError {
  let out : Array[Instruction] = []
  let mut u = 0
  while u < insns_size {
    let foff = insns_start + u * 2
    let word = read_u16(data, foff)
    let op = word.land(0xff)
    if op == 0x00 && word != 0 {
      // switch / 数组数据 payload（0x0100/0x0200/0x0300）
      if word != 0x0100 && word != 0x0200 && word != 0x0300 {
        raise DexError::BadCodeItem(
          code_off,
          "unexpected nop encoding " + word.to_string(),
        )
      }
      let (total, mnemonic, operands) = decode_payload(
        code_off, u, word, insns_size, insns_start, data,
      )
      out.push(Instruction::{
        offset: u,
        opcode: 0,
        mnemonic,
        operands,
        raw: slice_bytes(data, foff, total * 2),
      })
      u = u + total
    } else {
      match opcode_info(op) {
        None => raise DexError::InvalidInstruction(u, op)
        Some((mnemonic, fmt, kind)) => {
          let width = fmt_width(fmt)
          if u + width > insns_size {
            raise DexError::BadCodeItem(
              code_off,
              "truncated instruction at unit " + u.to_string(),
            )
          }
          let operands = decode_operands(ctx, op, fmt, kind, word, foff, data)
          out.push(Instruction::{
            offset: u,
            opcode: op,
            mnemonic,
            operands,
            raw: slice_bytes(data, foff, width * 2),
          })
          u = u + width
        }
      }
    }
  }
  out
}
