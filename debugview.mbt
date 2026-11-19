///|
/// debug_info_item 状态机展开视图（W5）。
///
/// 既有 `parse_code_item` 保留 debug 流原始字节（B8 深度限制），
/// 本文件按 DEX 规范 debug_info_item 状态机逐 opcode 展开为
/// `DebugEvent` 序列，含行号推进、局部变量、文件切换等信息。
/// 不改既有 raw `debug_info` 字段与 `BadDebugInfo` 触发口径（P4/P5 防火墙律）。
///
/// opcode 0x00–0xFF 规范：
///   - 0x00 DBG_END_SEQUENCE（终止，不产事件）
///   - 0x01 DBG_ADVANCE_PC(uleb128 addr_diff)
///   - 0x02 DBG_ADVANCE_LINE(sleb128 line_diff)
///   - 0x03 DBG_START_LOCAL(uleb reg, uleb name_idx, uleb type_idx)
///   - 0x04 DBG_START_LOCAL_EXTENDED(uleb reg, uleb name_idx, uleb type_idx, uleb sig_idx)
///   - 0x05 DBG_START_LOCAL(Same as 0x03 but end of scope; deprecated alias)
///   - 0x06 DBG_END_LOCAL(uleb reg)
///   - 0x07 DBG_RESTART_LOCAL(uleb reg)
///   - 0x08 DBG_SET_PROLOGUE_END
///   - 0x09 DBG_SET_EPILOGUE_BEGIN
///   - 0x0A DBG_SET_FILE(uleb name_idx)
///   - 0x0B reserved → BadDebugInfo
///   - 0x0C–0xFF special opcode: line += DBG_LINE_BASE + (adj % DBG_LINE_RANGE),
///     address += adj / DBG_LINE_RANGE（adj = opcode - 0x0A）
/// DBG_LINE_BASE = -4, DBG_LINE_RANGE = 15, DBG_FIRST_SPECIAL = 0x0A
///
/// 名字/类型经 string_ids / type_ids 表解析（MUTF-8）。
/// 越界/截断/坏 uleb/sleb → BadDebugInfo，无 panic。

///|
/// 当前文件名字符串表已解析（name_idx → String）。
priv struct StringCache {
  names : Array[String?]
}

///|
/// 状态机事件。
pub(all) enum DebugEvent {
  AdvancePc(Int32)
  AdvanceLine(Int32)
  StartLocal(Int32, String, String) // (reg, name, type)
  StartLocalExtended(Int32, String, String, String) // (reg, name, type, sig)
  EndLocal(Int32)
  RestartLocal(Int32)
  SetPrologueEnd
  SetEpilogueBegin
  SetFile(String)
}

///|
/// debug_info_item 展开视图。
pub(all) struct DebugInfoView {
  line_start : Int32
  parameter_names : Array[String?] // NO_INDEX(0xFFFFFFFF) → None
  events : Array[DebugEvent]
}

///|
/// 展开 `code_off` 处 code_item 的 debug_info 流为 `DebugInfoView`。
/// - `data`：完整 DEX 字节（需访问 string_ids / type_ids 表）。
/// - `code_off`：code_item 的字节偏移。
/// - debug_info_off == 0 时返回空 events（方法无 debug info）。
/// - 越界/截断/坏 uleb/sleb → BadDebugInfo；索引越界 → InvalidIndex。
pub fn debug_info_view(
  data : Bytes,
  code_off : Int32,
) -> DebugInfoView raise DexError {
  // validate code_off
  if code_off < 0x70 || code_off + 16 > data.length() {
    raise DexError::BadDebugInfo(code_off, "code_off out of bounds")
  }
  let debug_info_off = read_u32(data, code_off + 8)
  if debug_info_off == 0 {
    return DebugInfoView::{ line_start: 0, parameter_names: [], events: [], }
  }
  if debug_info_off < 0x70 || debug_info_off >= data.length() {
    raise DexError::BadDebugInfo(debug_info_off, "debug_info_off out of bounds")
  }
  let cache = build_string_cache(data)
  parse_debug_stream(data, debug_info_off, cache)
}

///|
/// 构建 string_ids + type_ids 的 String 缓存，用于 debug opcode 的名字/类型解析。
fn build_string_cache(data : Bytes) -> StringCache {
  let str_size = read_u32(data, 0x38)
  let str_off = read_u32(data, 0x3C)
  let names : Array[String?] = []
  // Pre-resolve string table
  for i in 0..<str_size {
    let s_off = read_u32(data, str_off + i * 4)
    if s_off < 0x70 || s_off >= data.length() {
      names.push(None)
    } else {
      match try_uleb128(data, s_off) {
        Some((_, body_off)) =>
          match try_mutf8(data, body_off) {
            Some((s, _)) => names.push(Some(s))
            _ => names.push(None)
          }
        _ => names.push(None)
      }
    }
  }
  StringCache::{ names, }
}

///|
/// type table: type_idx → descriptor string → resolved string table name.
fn type_name(
  data : Bytes,
  cache : StringCache,
  type_idx : Int32,
) -> String raise DexError {
  let type_size = read_u32(data, 0x40)
  let type_off = read_u32(data, 0x44)
  if type_idx < 0 || type_idx >= type_size {
    raise DexError::InvalidIndex(TableKind::TypeId, type_idx)
  }
  let string_idx = read_u32(data, type_off + type_idx * 4)
  if string_idx < 0 || string_idx >= cache.names.length() {
    raise DexError::InvalidIndex(TableKind::StringId, string_idx)
  }
  match cache.names[string_idx] {
    Some(s) => s
    None => raise DexError::InvalidIndex(TableKind::StringId, string_idx)
  }
}

///|
/// string table: name_idx → string。name_idx == NO_INDEX(-1) → "?" 占位。
fn string_name(
  cache : StringCache,
  name_idx : Int32,
  dbg_off : Int32,
) -> String raise DexError {
  let count = cache.names.length()
  if name_idx < -1 || name_idx >= count {
    raise DexError::BadDebugInfo(
      dbg_off,
      "name_idx " + name_idx.to_string() + " out of range",
    )
  }
  if name_idx == -1 {
    return "?" // NO_INDEX
  }
  match cache.names[name_idx] {
    Some(s) => s
    None =>
      raise DexError::BadDebugInfo(
        dbg_off,
        "name_idx " + name_idx.to_string() + " invalid",
      )
  }
}

///|
/// 核心状态机解析。与 `debug_stream_len` 同构但收集结构化事件。
/// DBG_LINE_BASE = -4, DBG_LINE_RANGE = 15, DBG_FIRST_SPECIAL = 0x0A.
fn parse_debug_stream(
  data : Bytes,
  dbg_off : Int32,
  cache : StringCache,
) -> DebugInfoView raise DexError {
  let mut pos = dbg_off
  // Prologue
  let (raw_line, p1) = uleb_debug(data, pos, dbg_off)
  let line_start = raw_line - 1 // uleb128p1
  pos = p1
  let (param_size_raw, p2) = uleb_debug(data, pos, dbg_off)
  let param_size = param_size_raw - 1
  pos = p2
  let params : Array[String?] = []
  for _ in 0..<param_size {
    let (raw_idx, pn) = uleb_debug(data, pos, dbg_off)
    // uleb128p1: encoded 0 → NO_INDEX; else string_ids index = value - 1
    if raw_idx == 0 {
      params.push(None)
    } else {
      let si = raw_idx - 1
      if si < 0 || si >= cache.names.length() {
        params.push(None)
      } else {
        params.push(cache.names[si])
      }
    }
    pos = pn
  }
  // State machine
  let events : Array[DebugEvent] = []
  let mut done = false
  let mut current_line = line_start
  let mut current_addr = 0
  while !done {
    if pos >= data.length() {
      raise DexError::BadDebugInfo(dbg_off, "debug_info stream truncated")
    }
    let op = byte_at(data, pos)
    pos = pos + 1
    if op == 0x00 {
      done = true
    } else if op == 0x01 {
      let (delta, p) = uleb_debug(data, pos, dbg_off)
      current_addr = current_addr + delta
      events.push(DebugEvent::AdvancePc(delta))
      pos = p
    } else if op == 0x02 {
      match try_sleb128(data, pos) {
        Some((delta, p)) => {
          current_line = current_line + delta
          events.push(DebugEvent::AdvanceLine(delta))
          pos = p
        }
        None =>
          raise DexError::BadDebugInfo(
            dbg_off,
            "malformed sleb128 at " + pos.to_string(),
          )
      }
    } else if op == 0x03 || op == 0x05 {
      let (reg, q1) = uleb_debug(data, pos, dbg_off)
      let (name_idx, q2) = uleb_debug(data, q1, dbg_off)
      let (type_idx, q3) = uleb_debug(data, q2, dbg_off)
      let name = string_name(cache, name_idx, dbg_off)
      let ty = type_name(data, cache, type_idx)
      events.push(DebugEvent::StartLocal(reg, name, ty))
      pos = q3
    } else if op == 0x04 {
      let (reg, q1) = uleb_debug(data, pos, dbg_off)
      let (name_idx, q2) = uleb_debug(data, q1, dbg_off)
      let (type_idx, q3) = uleb_debug(data, q2, dbg_off)
      let (sig_idx, q4) = uleb_debug(data, q3, dbg_off)
      let name = string_name(cache, name_idx, dbg_off)
      let ty = type_name(data, cache, type_idx)
      let sig = string_name(cache, sig_idx, dbg_off)
      events.push(DebugEvent::StartLocalExtended(reg, name, ty, sig))
      pos = q4
    } else if op == 0x06 {
      let (reg, p) = uleb_debug(data, pos, dbg_off)
      events.push(DebugEvent::EndLocal(reg))
      pos = p
    } else if op == 0x07 {
      let (reg, p) = uleb_debug(data, pos, dbg_off)
      events.push(DebugEvent::RestartLocal(reg))
      pos = p
    } else if op == 0x08 {
      events.push(DebugEvent::SetPrologueEnd)
    } else if op == 0x09 {
      events.push(DebugEvent::SetEpilogueBegin)
    } else if op == 0x0A {
      let (name_idx, p) = uleb_debug(data, pos, dbg_off)
      let name = string_name(cache, name_idx, dbg_off)
      events.push(DebugEvent::SetFile(name))
      pos = p
    } else if op == 0x0B {
      raise DexError::BadDebugInfo(dbg_off, "reserved debug opcode 0x0B")
    } else {
      // Special opcode: 0x0C–0xFF
      let adj = op - 0x0A
      let line_delta = -4 + adj % 15
      let addr_delta = adj / 15
      current_line = current_line + line_delta
      current_addr = current_addr + addr_delta
      events.push(DebugEvent::AdvancePc(addr_delta))
      if line_delta != 0 {
        events.push(DebugEvent::AdvanceLine(line_delta))
      }
    }
  }
  DebugInfoView::{ line_start, parameter_names: params, events, }
}
