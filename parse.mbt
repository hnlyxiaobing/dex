///|
/// DEX 容器解析内部实现：字节读取、变长编码、MUTF-8、adler32 与六表解析。
/// 全部错误以 `DexError` 传播，禁止 panic；每个错误带 TableKind / 偏移 / 索引上下文。

///|
/// 取单字节（调用方保证 `off` 在界内）。
fn byte_at(data : Bytes, off : Int32) -> Int32 {
  data.at(off).to_int()
}

///|
/// 小端读 u16。
fn read_u16(data : Bytes, off : Int32) -> Int32 {
  byte_at(data, off) | (byte_at(data, off + 1) << 8)
}

///|
/// 小端读 u32，按位模式返回 `Int`（可能为负，用作偏移前须校验）。
fn read_u32(data : Bytes, off : Int32) -> Int32 {
  byte_at(data, off) |
  (byte_at(data, off + 1) << 8) |
  (byte_at(data, off + 2) << 16) |
  (byte_at(data, off + 3) << 24)
}

///|
/// 小端读 u32，返回 `UInt`（checksum / endian_tag / access_flags）。
fn read_u32u(data : Bytes, off : Int32) -> UInt32 {
  (byte_at(data, off).reinterpret_as_uint() & 0xFFU) |
  ((byte_at(data, off + 1).reinterpret_as_uint() & 0xFFU) << 8) |
  ((byte_at(data, off + 2).reinterpret_as_uint() & 0xFFU) << 16) |
  ((byte_at(data, off + 3).reinterpret_as_uint() & 0xFFU) << 24)
}

///|
/// 拷贝 `data[off..off+len]` 为独立 `Bytes`。
fn slice_bytes(data : Bytes, off : Int32, len : Int32) -> Bytes {
  let arr : Array[Byte] = []
  for i in 0..<len {
    arr.push(data.at(off + i))
  }
  Bytes::from_array(arr)
}

///|
/// 尝试读 uleb128，返回 `Some((值, 下一偏移))`；截断或超出 32 位返回 `None`。
fn try_uleb128(data : Bytes, off : Int32) -> (Int32, Int32)? {
  let mut result = 0
  let mut shift = 0
  let mut pos = off
  let mut answer : (Int32, Int32)? = None
  let mut failed = false
  while answer is None && !failed {
    if pos >= data.length() {
      failed = true
    } else {
      let b = byte_at(data, pos)
      pos = pos + 1
      if shift == 28 && (b & 0x70) != 0 {
        failed = true
      } else {
        result = result | ((b & 0x7f) << shift)
        if (b & 0x80) == 0 {
          answer = Some((result, pos))
        } else {
          shift = shift + 7
        }
      }
    }
  }
  answer
}

///|
/// 尝试读 sleb128（32 位有符号变长），返回 `Some((值, 下一偏移))`；
/// 截断或超出 32 位返回 `None`。
fn try_sleb128(data : Bytes, off : Int32) -> (Int32, Int32)? {
  let mut result = 0
  let mut shift = 0
  let mut pos = off
  let mut answer : (Int32, Int32)? = None
  let mut failed = false
  while answer is None && !failed {
    if pos >= data.length() {
      failed = true
    } else {
      let b = byte_at(data, pos)
      pos = pos + 1
      if shift == 28 && !((b & 0x78) == 0 || (b & 0x78) == 0x78) {
        failed = true
      } else {
        let contribution = if shift == 28 {
          (b & 0x0f) << 28
        } else {
          (b & 0x7f) << shift
        }
        result = result | contribution
        if (b & 0x80) == 0 {
          if shift < 28 && (b & 0x40) != 0 {
            result = result | (-1 << (shift + 7))
          }
          answer = Some((result, pos))
        } else {
          shift = shift + 7
        }
      }
    }
  }
  answer
}

///|
/// 在 code_item 内读 uleb128；失败抛 `BadCodeItem`。
fn uleb_code(
  data : Bytes,
  off : Int32,
  code_off : Int32,
) -> (Int32, Int32) raise DexError {
  match try_uleb128(data, off) {
    Some(r) => r
    None =>
      raise DexError::BadCodeItem(
        code_off,
        "malformed uleb128 at offset " + off.to_string(),
      )
  }
}

///|
/// 在 debug_info 内读 uleb128；失败抛 `BadDebugInfo`。
fn uleb_debug(
  data : Bytes,
  off : Int32,
  dbg_off : Int32,
) -> (Int32, Int32) raise DexError {
  match try_uleb128(data, off) {
    Some(r) => r
    None =>
      raise DexError::BadDebugInfo(
        dbg_off,
        "malformed uleb128 at offset " + off.to_string(),
      )
  }
}

///|
/// 在 class_data 内读 uleb128；失败抛 `BadTableOffset(ClassDef, ...)`。
fn uleb_data(
  data : Bytes,
  off : Int32,
  data_off : Int32,
) -> (Int32, Int32) raise DexError {
  match try_uleb128(data, off) {
    Some(r) => r
    None => raise DexError::BadTableOffset(TableKind::ClassDef, data_off)
  }
}

///|
/// 在 catch handler 内读 sleb128；失败抛 `BadCodeItem`。
fn sleb_code(
  data : Bytes,
  off : Int32,
  code_off : Int32,
) -> (Int32, Int32) raise DexError {
  match try_sleb128(data, off) {
    Some(r) => r
    None =>
      raise DexError::BadCodeItem(
        code_off,
        "malformed sleb128 at offset " + off.to_string(),
      )
  }
}

///|
/// 解码 MUTF-8 字符串（含 0xC0 0x80 编码的 NUL），返回 `Some((字符串, 终止符后偏移))`。
/// 非法序列或越界返回 `None`。
fn try_mutf8(data : Bytes, off : Int32) -> (String, Int32)? {
  let chars : Array[Char] = []
  let mut pos = off
  let mut answer : (String, Int32)? = None
  let mut failed = false
  while answer is None && !failed {
    if pos >= data.length() {
      failed = true
    } else {
      let b = byte_at(data, pos)
      if b == 0 {
        answer = Some((String::from_array(chars), pos + 1))
      } else if b < 0x80 {
        chars.push(b.unsafe_to_char())
        pos = pos + 1
      } else if (b & 0xe0) == 0xc0 {
        if pos + 1 >= data.length() {
          failed = true
        } else {
          let b2 = byte_at(data, pos + 1)
          if (b2 & 0xc0) != 0x80 {
            failed = true
          } else {
            chars.push((((b & 0x1f) << 6) | (b2 & 0x3f)).unsafe_to_char())
            pos = pos + 2
          }
        }
      } else if (b & 0xf0) == 0xe0 {
        if pos + 2 >= data.length() {
          failed = true
        } else {
          let b2 = byte_at(data, pos + 1)
          let b3 = byte_at(data, pos + 2)
          if (b2 & 0xc0) != 0x80 || (b3 & 0xc0) != 0x80 {
            failed = true
          } else {
            chars.push(
              (((b & 0x0f) << 12) | ((b2 & 0x3f) << 6) | (b3 & 0x3f)).unsafe_to_char(),
            )
            pos = pos + 3
          }
        }
      } else {
        failed = true
      }
    }
  }
  answer
}

///|
/// adler32 校验和（DEX checksum 字段算法），覆盖 `data[start..end]`。
fn adler32(data : Bytes, start : Int32, end : Int32) -> UInt32 {
  let m : UInt32 = 65521U
  let mut a : UInt32 = 1U
  let mut b : UInt32 = 0U
  let mut i = start
  while i < end {
    a = a + data.at(i).to_uint()
    if a >= m {
      a = a - m
    }
    b = b + a
    if b >= m {
      b = b - m
    }
    i = i + 1
  }
  (b << 16) | a
}

///|
/// 无符号十六进制格式化（小写、无前缀，至少 `min_digits` 位）。
fn hex_u(v : UInt32, min_digits : Int32) -> String {
  let digits = "0123456789abcdef"
  let mut s = ""
  let mut x = v
  let mut n = 0
  while x != 0U {
    let d = (x & 15U).to_byte().to_int()
    s = digits[d:d + 1].to_owned() + s
    x = x >> 4
    n = n + 1
  }
  while n < min_digits {
    s = "0" + s
    n = n + 1
  }
  if n == 0 {
    s = "0"
  }
  s
}

///|
/// 32 位有符号整数字面量的 smali 风格格式：`#+0x1` / `#-0x1`。
fn fmt_sint(v : Int32) -> String {
  if v < 0 {
    "#-0x" + hex_u((v.lnot() + 1).reinterpret_as_uint(), 1)
  } else {
    "#+0x" + hex_u(v.reinterpret_as_uint(), 1)
  }
}

///|
/// 64 位字面量（4 个 16 位字，低字在前）的 smali 风格格式。
fn fmt_sint64(words : Array[Int32]) -> String {
  let negative = (words[3] & 0x8000) != 0
  let out : Array[Int32] = []
  if negative {
    let mut carry = 1
    for i in 0..<4 {
      let t = 0xffff - words[i] + carry
      out.push(t & 0xffff)
      carry = t >> 16
    }
  } else {
    for i in 0..<4 {
      out.push(words[i])
    }
  }
  let mut s = ""
  let mut started = false
  let mut i = 3
  while i >= 0 {
    let w = out[i]
    if started {
      s = s + hex_u(w.reinterpret_as_uint(), 4)
    } else if w != 0 {
      s = s + hex_u(w.reinterpret_as_uint(), 1)
      started = true
    }
    i = i - 1
  }
  if !started {
    s = "0"
  }
  if negative {
    "#-0x" + s
  } else {
    "#+0x" + s
  }
}

///|
/// 相对跳转偏移的 smali 风格格式：`+0x5` / `-0x3`。
fn fmt_off(v : Int32) -> String {
  if v < 0 {
    "-0x" + hex_u((v.lnot() + 1).reinterpret_as_uint(), 1)
  } else {
    "+0x" + hex_u(v.reinterpret_as_uint(), 1)
  }
}

///|
/// 字符串数组连接。
fn join_str(arr : Array[String], sep : String) -> String {
  let mut s = ""
  let mut first = true
  for x in arr {
    if first {
      first = false
    } else {
      s = s + sep
    }
    s = s + x
  }
  s
}

///|
/// 寄存器助记：`v0`。
fn fmt_reg(n : Int32) -> String {
  "v" + n.to_string()
}

///|
/// 解析上下文：指令解码阶段需要的已解析表（引用解析用）。
priv struct Ctx {
  strings : Array[String]
  types : Array[String]
  protos : Array[ProtoId]
  fields : Array[FieldDef]
  methods : Array[MethodDef]
}

///|
/// 校验一张索引表的偏移与大小；`size == 0` 时不校验。
fn check_table(
  file_size : Int32,
  off : Int32,
  size : Int32,
  item_size : Int32,
  kind : TableKind,
) -> Unit raise DexError {
  if size == 0 {
    return
  }
  if off < 0x70 || off % 4 != 0 || size > (file_size - off) / item_size {
    raise DexError::BadTableOffset(kind, off)
  }
}

///|
/// 读 type_list（u32 size + u16 idx[]，4 字节对齐），返回类型索引数组。
fn read_type_list(
  data : Bytes,
  off : Int32,
  types : Array[String],
  kind : TableKind,
) -> Array[Int32] raise DexError {
  let file_size = data.length()
  if off < 0x70 || off % 4 != 0 || off + 4 > file_size {
    raise DexError::BadTableOffset(kind, off)
  }
  let size = read_u32(data, off)
  if size < 0 || size > (file_size - off - 4) / 2 {
    raise DexError::BadTableOffset(kind, off)
  }
  let out : Array[Int32] = []
  for i in 0..<size {
    let idx = read_u16(data, off + 4 + i * 2)
    if idx < 0 || idx >= types.length() {
      raise DexError::InvalidIndex(TableKind::TypeId, idx)
    }
    out.push(idx)
  }
  out
}

///|
/// 计算 debug_info 原始字节流长度（到 DBG_END_SEQUENCE 为止）。
fn debug_stream_len(data : Bytes, off : Int32) -> Int32 raise DexError {
  let mut pos = off
  let dbg = off
  let mut done = false
  let mut failed_msg : String? = None
  // prologue: line_start(uleb128p1), parameters_size(uleb128p1), parameter_names
  let (line_start, p1) = uleb_debug(data, pos, dbg)
  ignore(line_start)
  pos = p1
  let (raw_param_size, p2) = uleb_debug(data, pos, dbg)
  // uleb128p1：编码值 = 实际值 + 1
  let param_size = raw_param_size - 1
  pos = p2
  for _ in 0..<param_size {
    let (_, p) = uleb_debug(data, pos, dbg)
    pos = p
  }
  while !done && failed_msg is None {
    if pos >= data.length() {
      failed_msg = Some("debug_info stream truncated")
    } else {
      let op = byte_at(data, pos)
      pos = pos + 1
      if op == 0x00 {
        done = true
      } else if op == 0x01 {
        let (_, p) = uleb_debug(data, pos, dbg)
        pos = p
      } else if op == 0x02 {
        match try_sleb128(data, pos) {
          Some((_, p)) => pos = p
          None => failed_msg = Some("malformed sleb128")
        }
      } else if op == 0x03 {
        let (_, q1) = uleb_debug(data, pos, dbg)
        let (_, q2) = uleb_debug(data, q1, dbg)
        let (_, q3) = uleb_debug(data, q2, dbg)
        pos = q3
      } else if op == 0x04 {
        let (_, q1) = uleb_debug(data, pos, dbg)
        let (_, q2) = uleb_debug(data, q1, dbg)
        let (_, q3) = uleb_debug(data, q2, dbg)
        let (_, q4) = uleb_debug(data, q3, dbg)
        pos = q4
      } else if op == 0x05 || op == 0x06 {
        let (_, p) = uleb_debug(data, pos, dbg)
        pos = p
      } else if op == 0x07 || op == 0x08 {
        // no operands
      } else if op == 0x09 {
        let (_, p) = uleb_debug(data, pos, dbg)
        pos = p
      } else if op >= 0x0a {
        // special opcode: no operands
      } else {
        failed_msg = Some("unknown debug opcode " + op.to_string())
      }
    }
  }
  match failed_msg {
    Some(msg) => raise DexError::BadDebugInfo(dbg, msg)
    None => pos - off
  }
}

///|
/// 解析 code_item：寄存器、指令流（解码为 `Instruction`）、try/catch 表与 debug_info 原始字节。
fn parse_code_item(
  data : Bytes,
  code_off : Int32,
  ctx : Ctx,
) -> CodeItem raise DexError {
  let file_size = data.length()
  if code_off < 0x70 || code_off + 16 > file_size {
    raise DexError::BadCodeItem(code_off, "code_item header out of bounds")
  }
  let registers_size = read_u16(data, code_off)
  let ins_size = read_u16(data, code_off + 2)
  let outs_size = read_u16(data, code_off + 4)
  let tries_size = read_u16(data, code_off + 6)
  let debug_info_off = read_u32(data, code_off + 8)
  let insns_size = read_u32(data, code_off + 12)
  if insns_size < 0 || insns_size > (file_size - code_off - 16) / 2 {
    raise DexError::BadCodeItem(code_off, "insns_size out of bounds")
  }
  let insns = decode_insns(ctx, code_off, code_off + 16, insns_size, data)
  let mut pos = code_off + 16 + insns_size * 2
  if tries_size > 0 && insns_size % 2 == 1 {
    pos = pos + 2
  }
  let tries : Array[TryItem] = []
  if tries_size > 0 {
    if tries_size > (file_size - pos) / 8 {
      raise DexError::BadCodeItem(code_off, "try_item table out of bounds")
    }
    for i in 0..<tries_size {
      let start_addr = read_u32(data, pos + i * 8)
      let insn_count = read_u16(data, pos + i * 8 + 4)
      let handler_off = read_u16(data, pos + i * 8 + 6)
      tries.push(TryItem::{
        start_addr,
        insn_count,
        handler_off,
        catch_type_index: None,
      })
    }
    let list_off = pos + tries_size * 8
    let (count, hp) = uleb_code(data, list_off, code_off)
    // 解析 handler 列表；同时记录两种 handler_off 约定（含 / 不含 size uleb128）下的偏移。
    let handler_keys : Array[(Int32, Int32?)] = []
    let mut hpos = hp
    let mut seen = 0
    while seen < count {
      let entry_start = hpos
      let (size, p1) = sleb_code(data, hpos, code_off)
      hpos = p1
      let mut pairs = size
      if pairs < 0 {
        pairs = 0 - pairs
      }
      let mut first_type : Int32? = None
      for _ in 0..<pairs {
        let (type_idx, pa) = uleb_code(data, hpos, code_off)
        let (_, pb) = uleb_code(data, pa, code_off)
        hpos = pb
        if first_type is None {
          first_type = Some(type_idx)
        }
      }
      if size <= 0 {
        let (_, pc) = uleb_code(data, hpos, code_off)
        hpos = pc
      }
      handler_keys.push((entry_start - list_off, first_type))
      handler_keys.push((entry_start - hp, first_type))
      seen = seen + 1
    }
    for i in 0..<tries_size {
      let t = tries[i]
      let mut found = false
      let mut catch_type : Int32? = None
      for h in handler_keys {
        if h.0 == t.handler_off {
          found = true
          catch_type = h.1
        }
      }
      if !found {
        raise DexError::BadCodeItem(
          code_off,
          "unknown handler_off " + t.handler_off.to_string(),
        )
      }
      tries[i] = TryItem::{
        start_addr: t.start_addr,
        insn_count: t.insn_count,
        handler_off: t.handler_off,
        catch_type_index: catch_type,
      }
    }
  }
  let debug_info = if debug_info_off == 0 {
    Bytes::new(0)
  } else {
    if debug_info_off < 0x70 || debug_info_off >= file_size {
      raise DexError::BadDebugInfo(
        debug_info_off, "debug_info_off out of bounds",
      )
    }
    let len = debug_stream_len(data, debug_info_off)
    slice_bytes(data, debug_info_off, len)
  }
  CodeItem::{
    registers_size,
    ins_size,
    outs_size,
    tries_size,
    debug_info_off,
    insns,
    tries,
    debug_info,
  }
}

///|
/// 解析 class_data_item，返回 (static_fields, instance_fields, direct_methods, virtual_methods)；
/// 同时把 method 的 access_flags / code 回填进 `ctx.methods`。
fn parse_class_data(
  data : Bytes,
  data_off : Int32,
  ctx : Ctx,
) -> (Array[FieldDef], Array[FieldDef], Array[MethodDef], Array[MethodDef]) raise DexError {
  let file_size = data.length()
  if data_off < 0x70 || data_off >= file_size {
    raise DexError::BadTableOffset(TableKind::ClassDef, data_off)
  }
  let mut pos = data_off
  let (static_size, p1) = uleb_data(data, pos, data_off)
  let (instance_size, p2) = uleb_data(data, p1, data_off)
  let (direct_size, p3) = uleb_data(data, p2, data_off)
  let (virtual_size, p4) = uleb_data(data, p3, data_off)
  pos = p4
  let static_fields : Array[FieldDef] = []
  let instance_fields : Array[FieldDef] = []
  let direct_methods : Array[MethodDef] = []
  let virtual_methods : Array[MethodDef] = []
  // encoded_field × (static + instance)
  // DEX 规范：static_fields 与 instance_fields 是两个独立分段，
  // 每段首个条目的 field_idx_diff 即绝对索引（该段从 0 起累加）。
  let mut field_idx = 0
  for i in 0..<(static_size + instance_size) {
    if i == static_size {
      field_idx = 0 // 进入 instance_fields 分段，复位（AOSP libdex 行为）
    }
    let (diff, pa) = uleb_data(data, pos, data_off)
    let (flags, pb) = uleb_data(data, pa, data_off)
    pos = pb
    field_idx = field_idx + diff
    if field_idx < 0 || field_idx >= ctx.fields.length() {
      raise DexError::InvalidIndex(TableKind::FieldId, field_idx)
    }
    let f = ctx.fields[field_idx]
    let fd = FieldDef::{
      class_index: f.class_index,
      type_index: f.type_index,
      name_index: f.name_index,
      access_flags: flags.reinterpret_as_uint(),
    }
    if i < static_size {
      static_fields.push(fd)
    } else {
      instance_fields.push(fd)
    }
    ctx.fields[field_idx] = fd
  }
  // encoded_method × (direct + virtual)
  // DEX 规范：direct_methods 与 virtual_methods 是两个独立分段，
  // 每段首个条目的 method_idx_diff 即绝对索引（该段从 0 起累加）。
  let mut method_idx = 0
  for k in 0..<(direct_size + virtual_size) {
    if k == direct_size {
      method_idx = 0 // 进入 virtual_methods 分段，复位（AOSP libdex 行为）
    }
    let (diff, pa) = uleb_data(data, pos, data_off)
    let (flags, pb) = uleb_data(data, pa, data_off)
    let (code_off, pc) = uleb_data(data, pb, data_off)
    pos = pc
    method_idx = method_idx + diff
    if method_idx < 0 || method_idx >= ctx.methods.length() {
      raise DexError::InvalidIndex(TableKind::MethodId, method_idx)
    }
    let m = ctx.methods[method_idx]
    let code = if code_off == 0 {
      None
    } else {
      Some(parse_code_item(data, code_off, ctx))
    }
    let md = MethodDef::{
      class_index: m.class_index,
      name_index: m.name_index,
      proto_index: m.proto_index,
      access_flags: flags.reinterpret_as_uint(),
      code_off,
      code,
    }
    if k < direct_size {
      direct_methods.push(md)
    } else {
      virtual_methods.push(md)
    }
    ctx.methods[method_idx] = md
  }
  (static_fields, instance_fields, direct_methods, virtual_methods)
}

///|
/// 解析单个 DEX 字节流（公开接口 `parse` 的实现主体）。
fn parse_dex(data : Bytes) -> DexFile raise DexError {
  let file_size = data.length()
  if file_size < 2 {
    raise DexError::UnexpectedEof(file_size)
  }
  // 多 dex / 容器误喂检测
  if byte_at(data, 0) == 0x50 && byte_at(data, 1) == 0x4b {
    raise DexError::MultiDexNotMerged(
      "input is a ZIP/APK container, not a single DEX",
    )
  }
  if file_size < 0x70 {
    raise DexError::UnexpectedEof(file_size)
  }
  // magic "dex\nNNN\0"
  if byte_at(data, 0) != 0x64 ||
    byte_at(data, 1) != 0x65 ||
    byte_at(data, 2) != 0x78 ||
    byte_at(data, 3) != 0x0a {
    raise DexError::BadMagic("not a DEX file (magic mismatch)")
  }
  if byte_at(data, 7) != 0 {
    raise DexError::BadMagic("bad magic terminator")
  }
  let d1 = byte_at(data, 4)
  let d2 = byte_at(data, 5)
  let d3 = byte_at(data, 6)
  if d1 < 0x30 || d1 > 0x39 || d2 < 0x30 || d2 > 0x39 || d3 < 0x30 || d3 > 0x39 {
    raise DexError::BadMagic("bad version digits")
  }
  let ver = (d1 - 0x30) * 100 + (d2 - 0x30) * 10 + (d3 - 0x30)
  let version = match ver {
    35 => DexVersion::Dex035
    37 => DexVersion::Dex037
    38 => DexVersion::Dex038
    39 => DexVersion::Dex039
    40 => DexVersion::Dex040
    41 => DexVersion::Dex041
    _ =>
      raise DexError::UnsupportedVersion(
        "unsupported DEX version " + ver.to_string(),
      )
  }
  let checksum = read_u32u(data, 8)
  let signature = slice_bytes(data, 12, 20)
  let size_field = read_u32(data, 32)
  let header_size = read_u32(data, 36)
  let endian_tag = read_u32u(data, 40)
  if header_size != 0x70 {
    raise DexError::BadMagic("bad header_size " + header_size.to_string())
  }
  if endian_tag != 0x12345678U {
    raise DexError::BadMagic(
      "bad endian_tag (only little-endian 0x12345678 supported)",
    )
  }
  if size_field <= 0 || size_field > file_size {
    raise DexError::UnexpectedEof(file_size)
  }
  if size_field < file_size {
    raise DexError::MultiDexNotMerged(
      "trailing bytes after file_size; concatenated multi-dex?",
    )
  }
  // checksum：adler32 覆盖 signature 之后的全部字节
  let computed = adler32(data, 12, file_size)
  if computed != checksum {
    raise DexError::BadMagic(
      "checksum mismatch: header=" +
      hex_u(checksum, 8) +
      " computed=" +
      hex_u(computed, 8),
    )
  }
  // 六表位置
  let map_off = read_u32(data, 52)
  let string_ids_size = read_u32(data, 56)
  let string_ids_off = read_u32(data, 60)
  let type_ids_size = read_u32(data, 64)
  let type_ids_off = read_u32(data, 68)
  let proto_ids_size = read_u32(data, 72)
  let proto_ids_off = read_u32(data, 76)
  let field_ids_size = read_u32(data, 80)
  let field_ids_off = read_u32(data, 84)
  let method_ids_size = read_u32(data, 88)
  let method_ids_off = read_u32(data, 92)
  let class_defs_size = read_u32(data, 96)
  let class_defs_off = read_u32(data, 100)
  check_table(
    file_size,
    string_ids_off,
    string_ids_size,
    4,
    TableKind::StringId,
  )
  check_table(file_size, type_ids_off, type_ids_size, 4, TableKind::TypeId)
  check_table(file_size, proto_ids_off, proto_ids_size, 12, TableKind::ProtoId)
  check_table(file_size, field_ids_off, field_ids_size, 8, TableKind::FieldId)
  check_table(
    file_size,
    method_ids_off,
    method_ids_size,
    8,
    TableKind::MethodId,
  )
  check_table(
    file_size,
    class_defs_off,
    class_defs_size,
    32,
    TableKind::ClassDef,
  )
  // string_ids → strings
  let strings : Array[String] = []
  for i in 0..<string_ids_size {
    let s_off = read_u32(data, string_ids_off + i * 4)
    if s_off < 0x70 || s_off >= file_size {
      raise DexError::BadTableOffset(TableKind::StringId, s_off)
    }
    match try_uleb128(data, s_off) {
      Some((_, body_off)) =>
        match try_mutf8(data, body_off) {
          Some((s, _)) => strings.push(s)
          None => raise DexError::BadTableOffset(TableKind::StringId, s_off)
        }
      None => raise DexError::BadTableOffset(TableKind::StringId, s_off)
    }
  }
  // type_ids → type_descriptors
  let types : Array[String] = []
  for i in 0..<type_ids_size {
    let idx = read_u32(data, type_ids_off + i * 4)
    if idx < 0 || idx >= strings.length() {
      raise DexError::InvalidIndex(TableKind::StringId, idx)
    }
    types.push(strings[idx])
  }
  // proto_ids
  let protos : Array[ProtoId] = []
  for i in 0..<proto_ids_size {
    let base = proto_ids_off + i * 12
    let shorty_idx = read_u32(data, base)
    let return_idx = read_u32(data, base + 4)
    let params_off = read_u32(data, base + 8)
    if shorty_idx < 0 || shorty_idx >= strings.length() {
      raise DexError::InvalidIndex(TableKind::StringId, shorty_idx)
    }
    if return_idx < 0 || return_idx >= types.length() {
      raise DexError::InvalidIndex(TableKind::TypeId, return_idx)
    }
    let parameters = if params_off == 0 {
      ([] : Array[Int32])
    } else {
      read_type_list(data, params_off, types, TableKind::ProtoId)
    }
    let params : Array[String] = []
    for t in parameters {
      params.push(types[t])
    }
    protos.push(ProtoId::{
      shorty: strings[shorty_idx],
      return_type: types[return_idx],
      parameters: params,
    })
  }
  // field_ids
  let fields : Array[FieldDef] = []
  for i in 0..<field_ids_size {
    let base = field_ids_off + i * 8
    let class_idx = read_u16(data, base)
    let type_idx = read_u16(data, base + 2)
    let name_idx = read_u32(data, base + 4)
    if class_idx < 0 || class_idx >= types.length() {
      raise DexError::InvalidIndex(TableKind::TypeId, class_idx)
    }
    if type_idx < 0 || type_idx >= types.length() {
      raise DexError::InvalidIndex(TableKind::TypeId, type_idx)
    }
    if name_idx < 0 || name_idx >= strings.length() {
      raise DexError::InvalidIndex(TableKind::StringId, name_idx)
    }
    fields.push(FieldDef::{
      class_index: class_idx,
      type_index: type_idx,
      name_index: name_idx,
      access_flags: 0U,
    })
  }
  // method_ids
  let methods : Array[MethodDef] = []
  for i in 0..<method_ids_size {
    let base = method_ids_off + i * 8
    let class_idx = read_u16(data, base)
    let proto_idx = read_u16(data, base + 2)
    let name_idx = read_u32(data, base + 4)
    if class_idx < 0 || class_idx >= types.length() {
      raise DexError::InvalidIndex(TableKind::TypeId, class_idx)
    }
    if proto_idx < 0 || proto_idx >= protos.length() {
      raise DexError::InvalidIndex(TableKind::ProtoId, proto_idx)
    }
    if name_idx < 0 || name_idx >= strings.length() {
      raise DexError::InvalidIndex(TableKind::StringId, name_idx)
    }
    methods.push(MethodDef::{
      class_index: class_idx,
      name_index: name_idx,
      proto_index: proto_idx,
      access_flags: 0U,
      code_off: 0,
      code: None,
    })
  }
  let ctx = Ctx::{ strings, types, protos, fields, methods, }
  // class_defs
  let classes : Array[ClassDef] = []
  for i in 0..<class_defs_size {
    let base = class_defs_off + i * 32
    let class_idx = read_u32(data, base)
    let access_flags = read_u32u(data, base + 4)
    let superclass_idx = read_u32(data, base + 8)
    let interfaces_off = read_u32(data, base + 12)
    let source_file_idx = read_u32(data, base + 16)
    let class_data_off = read_u32(data, base + 24)
    if class_idx < 0 || class_idx >= types.length() {
      raise DexError::InvalidIndex(TableKind::TypeId, class_idx)
    }
    let superclass = if superclass_idx == -1 {
      None
    } else {
      if superclass_idx < 0 || superclass_idx >= types.length() {
        raise DexError::InvalidIndex(TableKind::TypeId, superclass_idx)
      }
      Some(superclass_idx)
    }
    let interfaces = if interfaces_off == 0 {
      ([] : Array[Int32])
    } else {
      read_type_list(data, interfaces_off, types, TableKind::ClassDef)
    }
    let source_file = if source_file_idx == -1 {
      None
    } else {
      if source_file_idx < 0 || source_file_idx >= strings.length() {
        raise DexError::InvalidIndex(TableKind::StringId, source_file_idx)
      }
      Some(strings[source_file_idx])
    }
    let (static_fields, instance_fields, direct_methods, virtual_methods) = if class_data_off ==
      0 {
      (
        ([] : Array[FieldDef]),
        ([] : Array[FieldDef]),
        ([] : Array[MethodDef]),
        ([] : Array[MethodDef]),
      )
    } else {
      parse_class_data(data, class_data_off, ctx)
    }
    classes.push(ClassDef::{
      class_index: class_idx,
      type_descriptor: types[class_idx],
      superclass_index: superclass,
      interfaces,
      source_file,
      access_flags,
      class_data_off,
      static_fields,
      instance_fields,
      direct_methods,
      virtual_methods,
    })
  }
  // map_list 原始字节
  let map_list = if map_off == 0 {
    Bytes::new(0)
  } else {
    if map_off < 0x70 || map_off + 4 > file_size {
      raise DexError::UnexpectedEof(map_off)
    }
    let count = read_u32(data, map_off)
    if count < 0 || count > (file_size - map_off - 4) / 12 {
      raise DexError::UnexpectedEof(map_off)
    }
    slice_bytes(data, map_off, 4 + count * 12)
  }
  DexFile::{
    version,
    checksum,
    signature,
    file_size: size_field,
    header_size,
    endian_tag,
    strings,
    type_descriptors: types,
    protos,
    fields,
    methods,
    classes,
    map_list,
  }
}
