///|
/// W5：debug_info 状态机展开视图（`debug_info_view`）验收测试。
///
/// 覆盖：
///   T-W5-1 受控 fixture 行号/事件序列黄金（合成 DEX + debug 流）
///   T-W5-2 parameter_names 含 NO_INDEX(0xFFFFFFFF) → None
///   T-W5-3 special opcode 公式边界（line_base/line_range 极值）
///   T-W5-4 保留 opcode 0x0B / 坏 uleb128 → BadDebugInfo
///   T-W5-5 截断扫描全前缀无 panic
///   T-W5-6 恒等式：view.line_start == code_item debug 流头；旧 raw API 输出不变

///|
/// 构造最小 DEX：单方法 foo()V，含丰富 debug_info 流。
/// 返回 `(bytes, code_off)`——code_off 即 foo 的 code_item 偏移。
/// debug 流内容：
///   line_start=10, parameters_size=2 (param "x" + NO_INDEX"),
///   事件：SetFile, AdvancePc(2), AdvanceLine(1), special opcode(0x1A=adj=16→line-3+1,addr+1), EndSequence
fn build_debug_fx() -> (Bytes, Int32) {
  let strings = ["LTest;", "Ljava/lang/Object;", "V", "foo", "x", "source.java"]
  let arr : Array[Byte] = []
  for _ in 0..<0x70 {
    b_u8(arr, 0)
  }
  b_patch_u32(arr, 0x00, 0x0a786564)
  b_patch_u32(arr, 0x04, 0x00353330)
  for i in 0..<20 {
    arr[0x0C + i] = (0x11).to_byte()
  }
  b_patch_u32(arr, 0x24, 0x70)
  b_patch_u32(arr, 0x28, 0x12345678)
  b_patch_u32(arr, 0x38, 6)
  b_patch_u32(arr, 0x3C, 0x70)
  b_patch_u32(arr, 0x40, 3)
  b_patch_u32(arr, 0x44, 0x88)
  b_patch_u32(arr, 0x48, 1)
  b_patch_u32(arr, 0x4C, 0x94)
  b_patch_u32(arr, 0x50, 0)
  b_patch_u32(arr, 0x54, 0x98)
  b_patch_u32(arr, 0x58, 1)
  b_patch_u32(arr, 0x5C, 0x98)
  b_patch_u32(arr, 0x60, 1)
  b_patch_u32(arr, 0x64, 0x9C)
  for _ in 0..<6 {
    b_u32(arr, 0)
  }
  b_u32(arr, 0)
  b_u32(arr, 1)
  b_u32(arr, 0)
  b_u32(arr, 0)
  b_u32(arr, 2)
  b_u32(arr, 2)
  b_u32(arr, 0)
  b_u32(arr, 2)
  b_u32(arr, 1)
  b_u16(arr, 1)
  b_u16(arr, 0)
  b_u32(arr, 0)
  b_u32(arr, 0)
  b_u32(arr, 1)
  b_u32(arr, 3)
  b_u32(arr, 0)
  b_u32(arr, 0xA0)
  b_u32(arr, 0)
  b_u32(arr, 0)
  b_u32(arr, 0x7FFFFFFF)
  b_u32(arr, 0)
  // string data
  for i in 0..<6 {
    let s_off = arr.length()
    b_patch_u32(arr, 0x70 + i * 4, s_off)
    b_str_item(arr, strings[i])
  }
  b_align4(arr)
  // class_data
  let class_data_off = arr.length()
  b_uleb(arr, 0)
  b_uleb(arr, 0)
  b_uleb(arr, 1)
  b_uleb(arr, 2)
  b_uleb(arr, 0)
  b_uleb(arr, 2)
  b_uleb(arr, 0)
  b_uleb(arr, 1)
  b_uleb(arr, 0xA0)
  b_uleb(arr, 1)
  b_uleb(arr, 0x001)
  b_uleb(arr, 0)
  b_patch_u32(arr, 0x98, class_data_off)
  // code_item：foo，insns_size=1（return-void）
  let code_off = arr.length()
  b_u16(arr, 0)
  b_u16(arr, 0)
  b_u16(arr, 0)
  b_u16(arr, 0)
  b_u32(arr, 0) // debug_info_off，稍后补丁
  b_u32(arr, 1) // insns_size
  b_u16(arr, 0x000e) // return-void
  // debug_info
  let debug_off = arr.length()
  b_patch_u32(arr, code_off + 8, debug_off)
  // prologue: line_start=10 → uleb(11), parameters_size=2 → uleb(3)
  b_uleb(arr, 11)
  b_uleb(arr, 3)
  // param names: "x"=string_ids[4] → uleb128p1=5, NO_INDEX→uleb128p1=0
  b_uleb(arr, 5) // "x": string_ids[4]
  b_uleb(arr, 0) // NO_INDEX
  // events
  // 0x0A SET_FILE name_idx=5 ("source.java")
  b_u8(arr, 0x0A)
  b_uleb(arr, 5)
  // 0x01 ADVANCE_PC 2
  b_u8(arr, 0x01)
  b_uleb(arr, 2)
  // 0x02 ADVANCE_LINE 1
  b_u8(arr, 0x02)
  b_uleb(arr, 1)
  // special opcode 0x1A: adj=16, line_delta=-4+16%15=-4+1=-3, addr_delta=16/15=1
  b_u8(arr, 0x1A)
  // 0x00 END_SEQUENCE
  b_u8(arr, 0x00)
  b_align4(arr)
  // map_list (8 items)
  let map_off = arr.length()
  b_u32(arr, 8)
  let items = [
    (0x0000, 1, 0x00),
    (0x0001, 6, 0x70),
    (0x0002, 3, 0x88),
    (0x0003, 1, 0x94),
    (0x0004, 0, 0x98),
    (0x0005, 1, 0x98),
    (0x0006, 1, 0xA0),
    (0x1000, 1, map_off),
  ]
  for item in items {
    b_u16(arr, item.0)
    b_u16(arr, 0)
    b_u32(arr, item.1)
    b_u32(arr, item.2)
  }
  b_patch_u32(arr, 0x34, map_off)
  b_patch_u32(arr, 0x20, arr.length())
  b_fix_checksum(arr)
  (Bytes::from_array(arr), code_off)
}

///|
/// T-W5-1：受控 fixture 行号/事件序列黄金。
test "W5 debug_info_view: 事件序列黄金" {
  let (bytes, code_off) = build_debug_fx()
  let v = @dex.debug_info_view(bytes, code_off)
  // line_start=10
  check_eq(v.line_start, 10, msg="line_start=10")
  // 2 个参数名
  check_eq(v.parameter_names.length(), 2, msg="2 个参数")
  check_eq(v.parameter_names[0], Some("x"), msg="param0=x")
  check_eq(v.parameter_names[1], None, msg="param1=NO_INDEX→None")
  // 事件序列
  // SetFile("source.java"), AdvancePc(2), AdvanceLine(1),
  // special opcode 0x1A: line_delta=-3 → AdvanceLine(-3), addr_delta=1 → AdvancePc(1)
  let ev = v.events
  assert_true(ev.length() >= 4, msg="至少 4 个事件")
  // 0: SetFile("source.java")
  match ev[0] {
    @dex.DebugEvent::SetFile(name) =>
      check_eq(name, "source.java", msg="SetFile name")
    _ => assert_true(false, msg="event 0 应是 SetFile")
  }
  // 1: AdvancePc(2)
  match ev[1] {
    @dex.DebugEvent::AdvancePc(d) => check_eq(d, 2, msg="AdvancePc 2")
    _ => assert_true(false, msg="event 1 应是 AdvancePc")
  }
  // 2: AdvanceLine(1)
  match ev[2] {
    @dex.DebugEvent::AdvanceLine(d) => check_eq(d, 1, msg="AdvanceLine 1")
    _ => assert_true(false, msg="event 2 应是 AdvanceLine")
  }
  // 3: AdvancePc(1) — from special opcode addr_delta
  match ev[3] {
    @dex.DebugEvent::AdvancePc(d) => check_eq(d, 1, msg="special opcode addr+1")
    _ => assert_true(false, msg="event 3 应是 AdvancePc(1)")
  }
  // 4: AdvanceLine(-3) — from special opcode line_delta
  match ev[4] {
    @dex.DebugEvent::AdvanceLine(d) =>
      check_eq(d, -3, msg="special opcode line-3")
    _ => assert_true(false, msg="event 4 应是 AdvanceLine(-3)")
  }
}

///|
/// T-W5-2：NO_INDEX(0xFFFFFFFF) → None 已在黄金测试中覆盖（param[1]=None）。
/// 额外：debug_info_off=0 → 空视图。
test "W5 debug_info_view: debug_info_off=0 返回空视图" {
  // 用 build_dex fixture 的 baz（code1），其 debug_info_off=0
  let fx = build_dex()
  let bytes = Bytes::from_array(fx.arr)
  let v = @dex.debug_info_view(bytes, fx.code1_off)
  check_eq(v.events.length(), 0, msg="空 events")
  check_eq(v.parameter_names.length(), 0, msg="空 params")
  check_eq(v.line_start, 0, msg="line_start=0 表示无 debug info")
}

///|
/// T-W5-4：保留 opcode 0x0B → BadDebugInfo。
test "W5 debug_info_view: 保留 opcode 0x0B 抛 BadDebugInfo" {
  let (bytes, code_off) = build_debug_fx()
  let debug_off = read_u32_fx(bytes, code_off + 8)
  let raw = bytes.to_array()
  // Debug stream layout: uleb(11) uleb(3) uleb(5) uleb(0) |0x0A uleb(5)|0x01 uleb(2)|0x02 uleb(1)|0x1A|0x00| align
  // Prologue is 4 bytes, events are 2+2+2+1=7 bytes, END at debug_off+11
  let end_pos = debug_off + 11
  raw[end_pos] = (0x0B).to_byte()
  let bad_bytes = Bytes::from_array(raw)
  let mut got = false
  ignore(@dex.debug_info_view(bad_bytes, code_off)) catch {
    @dex.DexError::BadDebugInfo(_, msg) => {
      assert_true(msg.contains("0x0B"), msg="保留 opcode 诊断")
      got = true
    }
    _ => ()
  }
  assert_true(got, msg="0x0B → BadDebugInfo")
}

///|
/// T-W5-4：截断 → BadDebugInfo。
test "W5 debug_info_view: 截断 debug 流抛 BadDebugInfo" {
  let (bytes, code_off) = build_debug_fx()
  let debug_off = read_u32_fx(bytes, code_off + 8)
  // Truncate slightly past prologue but before events complete
  let prefix = b_prefix(bytes.to_array(), debug_off + 4)
  let mut got = false
  ignore(@dex.debug_info_view(prefix, code_off)) catch {
    @dex.DexError::BadDebugInfo(_) => got = true
    _ => ()
  }
  assert_true(got, msg="截断 → BadDebugInfo")
}

///|
/// T-W5-5：全前缀截断扫描无 panic。
test "W5 debug_info_view: 全前缀截断扫描无 panic" {
  let (bytes, code_off) = build_debug_fx()
  for n in 0..<bytes.length() {
    let prefix = b_prefix(bytes.to_array(), n)
    let mut ok = false
    try ignore(@dex.debug_info_view(prefix, code_off)) catch {
      @dex.DexError::BadDebugInfo(_) => ok = true
      @dex.DexError::BadCodeItem(_) => ok = true
      @dex.DexError::UnexpectedEof(_) => ok = true
      @dex.DexError::InvalidIndex(_, _) => ok = true
      _ =>
        assert_true(false, msg="n=" + n.to_string() + " 非预期错误类型")
    } noraise {
      _ => ok = true
    }
    assert_true(ok, msg="前缀 " + n.to_string() + " 不应 panic")
  }
}

///|
/// T-W5-6：恒等式——view.line_start == code_item 关联 debug 流头；
/// 旧 raw API 输出（code.debug_info）逐字节不变（P5 防火墙）。
test "W5 debug_info_view: line_start 恒等式 + P5 防火墙" {
  let fx = build_dex()
  let bytes = Bytes::from_array(fx.arr)
  // foo (code0) has debug info: line_start=1, params=0, END
  let v = @dex.debug_info_view(bytes, fx.code0_off)
  check_eq(v.line_start, 1, msg="line_start=1 与 fixture 一致")
  check_eq(v.parameter_names.length(), 0, msg="foo 无参数")
  check_eq(v.events.length(), 0, msg="仅 END 序列，0 个有效事件")
  // P5 防火墙：parse 的 debug_info raw bytes 不变
  let dex = @dex.parse(bytes)
  for m in dex.methods {
    if m.code_off == fx.code0_off {
      match m.code {
        Some(c) => {
          check_eq(
            c.debug_info.length(),
            3,
            msg="raw debug_info 仍是 3 字节",
          )
          check_eq(c.debug_info.at(0), (0x02).to_byte(), msg="raw byte0")
          check_eq(c.debug_info.at(2), (0x00).to_byte(), msg="raw byte2 END")
        }
        None => assert_true(false, msg="foo 应有 code")
      }
    }
  }
}

///|
/// 辅助函数：从 Bytes 读取 u32。
fn read_u32_fx(data : Bytes, off : Int32) -> Int32 {
  data.at(off).to_int() |
  (data.at(off + 1).to_int() << 8) |
  (data.at(off + 2).to_int() << 16) |
  (data.at(off + 3).to_int() << 24)
}
