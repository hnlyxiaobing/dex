///|
/// W8：catch handler 多类型展开视图（`catch_handlers`）验收测试。
///
/// 覆盖：
///   T-W8-1 多类型 handler 全量展开黄金（2 个 type pair + catch-all）
///   T-W8-2 catch-all 标记 Some/None 正确（size>0 → None；size<0 → Some）
///   T-W8-3 恒等式 I5：`catch_handlers(...)[i].pairs[0].0 == 旧 catch_type_index`
///   T-W8-4 旧 API 输出不变（parse 语义不变，P5 防火墙）+ 快照纯加法（门禁）
///   DoD 全前缀截断扫描无 panic
/// 字节构造 helper 复用同包既有定义（dex_test.mbt）。

///|
/// 测试侧 sleb128（有符号 leb128，用于 catch handler size 与负值）。
fn b_sleb(arr : Array[Byte], value : Int32) -> Unit {
  let mut v = value
  let mut more = true
  while more {
    let b = v & 0x7f
    v = v >> 7
    if (v == 0 && (b & 0x40) == 0) || (v == -1 && (b & 0x40) != 0) {
      b_u8(arr, b)
      more = false
    } else {
      b_u8(arr, b | 0x80)
    }
  }
}

///|
/// 构造可解析 DEX：code0=foo()V（const-string），code1=baz(I)V 带
/// **多类型 handler**（2 个 type pair + catch-all）。返回 `(bytes, code1_off, list_off)`。
fn build_catch_fx() -> (Bytes, Int32, Int32) {
  let strings = [
    "LTest;", "Ljava/lang/Object;", "V", "I", "foo", "bar", "baz", "abs", "Source.java",
    "VI",
  ]
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
  b_patch_u32(arr, 0x38, 10)
  b_patch_u32(arr, 0x3C, 0x70)
  b_patch_u32(arr, 0x40, 4)
  b_patch_u32(arr, 0x44, 0x98)
  b_patch_u32(arr, 0x48, 2)
  b_patch_u32(arr, 0x4C, 0xA8)
  b_patch_u32(arr, 0x50, 1)
  b_patch_u32(arr, 0x54, 0xC0)
  b_patch_u32(arr, 0x58, 3)
  b_patch_u32(arr, 0x5C, 0xC8)
  b_patch_u32(arr, 0x60, 1)
  b_patch_u32(arr, 0x64, 0xE0)
  for _ in 0..<10 {
    b_u32(arr, 0)
  }
  for i in 0..<4 {
    b_u32(arr, i)
  }
  b_u32(arr, 2)
  b_u32(arr, 2)
  b_u32(arr, 0)
  b_u32(arr, 9)
  b_u32(arr, 2)
  b_u32(arr, 0)
  b_u16(arr, 0)
  b_u16(arr, 3)
  b_u32(arr, 5)
  b_u16(arr, 0)
  b_u16(arr, 0)
  b_u32(arr, 4)
  b_u16(arr, 0)
  b_u16(arr, 1)
  b_u32(arr, 6)
  b_u16(arr, 0)
  b_u16(arr, 0)
  b_u32(arr, 7)
  b_u32(arr, 0)
  b_u32(arr, 1)
  b_u32(arr, 1)
  b_u32(arr, 0)
  b_u32(arr, 8)
  b_u32(arr, 0)
  b_u32(arr, 0)
  b_u32(arr, 0)
  let tl_params_off = arr.length()
  b_u32(arr, 1)
  b_u16(arr, 3)
  b_u16(arr, 0)
  let tl_off = arr.length()
  b_u32(arr, 1)
  b_u16(arr, 1)
  b_u16(arr, 0)
  b_patch_u32(arr, 0xBC, tl_params_off)
  b_patch_u32(arr, 0xEC, tl_off)
  for i in 0..<10 {
    let s_off = arr.length()
    b_patch_u32(arr, 0x70 + i * 4, s_off)
    b_str_item(arr, strings[i])
  }
  b_align4(arr)
  // code0（foo）：const/4 v0,#1 ; const-string v0,"bar" ; return-void
  let code0_off = arr.length()
  b_u16(arr, 1)
  b_u16(arr, 0)
  b_u16(arr, 0)
  b_u16(arr, 0)
  b_u32(arr, 0)
  b_u32(arr, 4)
  b_u16(arr, 0x1012)
  b_u16(arr, 0x001a)
  b_u16(arr, 0x0005)
  b_u16(arr, 0x000e)
  // code1（baz）：const/4 v0,#1 ; throw v0 ; return-void + 多类型 try/catch
  let code1_off = arr.length()
  b_u16(arr, 2)
  b_u16(arr, 1)
  b_u16(arr, 0)
  b_u16(arr, 1) // tries_size=1
  b_u32(arr, 0) // debug_info_off
  b_u32(arr, 3) // insns_size
  b_u16(arr, 0x1012)
  b_u16(arr, 0x0027)
  b_u16(arr, 0x000e)
  b_u16(arr, 0) // padding（insns_size 奇数 + tries）
  // try_item: start_addr=0, insn_count=2, handler_off=0（相对 list 起点）
  b_u32(arr, 0)
  b_u16(arr, 2)
  b_u16(arr, 0)
  // list_off：code1_off + 16(header) + 3*2(insns) + 2(padding) + 8(try_item)
  let list_off = code1_off + 16 + 3 * 2 + 2 + 8
  // encoded_catch_handler_list：count=1；handler size=-2（2 对 + catch-all）
  b_uleb(arr, 1)
  b_sleb(arr, -2)
  b_uleb(arr, 0) // type@0
  b_uleb(arr, 2) // addr=2
  b_uleb(arr, 1) // type@1
  b_uleb(arr, 2) // addr=2
  b_uleb(arr, 2) // catch_all addr=2
  b_align4(arr)
  // class_data
  let class_data_off = arr.length()
  b_uleb(arr, 1)
  b_uleb(arr, 0)
  b_uleb(arr, 1)
  b_uleb(arr, 2)
  b_uleb(arr, 0)
  b_uleb(arr, 8)
  b_uleb(arr, 0)
  b_uleb(arr, 1)
  b_uleb(arr, code0_off)
  b_uleb(arr, 1)
  b_uleb(arr, 1)
  b_uleb(arr, code1_off)
  b_uleb(arr, 1)
  b_uleb(arr, 0x401)
  b_uleb(arr, 0)
  b_patch_u32(arr, 0xF8, class_data_off)
  b_patch_u32(arr, code0_off + 8, arr.length())
  b_u8(arr, 0x02)
  b_u8(arr, 0x01)
  b_u8(arr, 0x00)
  b_align4(arr)
  // map_list（8 项）
  let map_off = arr.length()
  b_u32(arr, 8)
  let map_items = [
    (0x0000, 1, 0x00),
    (0x0001, 10, 0x70),
    (0x0002, 4, 0x98),
    (0x0003, 2, 0xA8),
    (0x0004, 1, 0xC0),
    (0x0005, 3, 0xC8),
    (0x0006, 1, 0xE0),
    (0x1000, 1, map_off),
  ]
  for item in map_items {
    b_u16(arr, item.0)
    b_u16(arr, 0)
    b_u32(arr, item.1)
    b_u32(arr, item.2)
  }
  b_patch_u32(arr, 0x34, map_off)
  b_patch_u32(arr, 0x20, arr.length())
  b_fix_checksum(arr)
  (Bytes::from_array(arr), code1_off, list_off)
}

///|
/// T-W8-1 + T-W8-2：多类型 handler 全量展开 + catch-all Some 正确。
test "W8 catch_handlers: 多类型 handler 全量展开 + catch-all" {
  let (bytes, _, list_off) = build_catch_fx()
  let hs = @dex.catch_handlers(bytes, list_off)
  check_eq(hs.length(), 1, msg="1 个 handler")
  check_eq(hs[0].pairs.length(), 2, msg="2 个 type pair 全量展开")
  check_eq(hs[0].pairs[0].0, 0, msg="pair0 type@0")
  check_eq(hs[0].pairs[0].1, 2, msg="pair0 addr=2")
  check_eq(hs[0].pairs[1].0, 1, msg="pair1 type@1")
  check_eq(hs[0].pairs[1].1, 2, msg="pair1 addr=2")
  check_eq(hs[0].catch_all_offset, Some(2), msg="catch-all Some(2)")
}

///|
/// T-W8-2：size>0（无 catch-all）→ catch_all_offset=None。
test "W8 catch_handlers: 无 catch-all 时 None" {
  // 构造 size=1 的 handler（单 type pair，无 catch-all）。
  let arr : Array[Byte] = []
  b_uleb(arr, 1) // count=1
  b_uleb(arr, 1) // size=1（正，无 catch-all）
  b_uleb(arr, 3) // type@3
  b_uleb(arr, 4) // addr=4
  let bytes = Bytes::from_array(arr)
  let hs = @dex.catch_handlers(bytes, 0)
  check_eq(hs.length(), 1, msg="1 个 handler")
  check_eq(hs[0].pairs.length(), 1, msg="1 个 type pair")
  check_eq(hs[0].pairs[0].0, 3, msg="type@3")
  check_eq(hs[0].pairs[0].1, 4, msg="addr=4")
  check_eq(hs[0].catch_all_offset, None, msg="无 catch-all → None")
}

///|
/// T-W8-3（恒等式 I5）：`catch_handlers(...)[i].pairs[0].0 == 旧 catch_type_index`。
test "W8 catch_handlers: pairs[0].0 == 旧 catch_type_index (I5)" {
  let (bytes, code1_off, list_off) = build_catch_fx()
  // 解析 DEX，取 baz 的 code1 的 try_item.catch_type_index。
  let dex = @dex.parse(bytes)
  let hs = @dex.catch_handlers(bytes, list_off)
  let mut checked = false
  for m in dex.methods {
    if m.code_off == code1_off {
      match m.code {
        Some(c) => {
          check_eq(c.tries.length(), 1, msg="1 个 try_item")
          check_eq(
            c.tries[0].catch_type_index,
            Some(0),
            msg="旧 catch_type_index=Some(0)",
          )
          // I5：pairs[0].0 == 旧 catch_type_index
          check_eq(
            Some(hs[0].pairs[0].0),
            c.tries[0].catch_type_index,
            msg="pairs[0].0 == 旧 first_type",
          )
          checked = true
        }
        None => ()
      }
    }
  }
  assert_true(
    checked,
    msg="应找到 baz 的 code_item 并完成恒等式核对",
  )
}

///|
/// T-W8-4（P5 防火墙）：新增 `catch_handlers` 后，parse 语义不变——
/// 既有 code_item 的 tries/catch_type_index 逐字段不变（旧通道）。
test "W8 catch_handlers: 旧 API 输出不变（P5 防火墙）" {
  // 用 build_dex（既有基线）验证 parse 输出与历史一致：baz code1 的
  // try_item 字段与原样一致，说明新增函数不影响 parse 路径。
  let fx = build_dex()
  let dex = @dex.parse(Bytes::from_array(fx.arr))
  let mut found = false
  for m in dex.methods {
    if m.code_off == fx.code1_off {
      found = true
      match m.code {
        Some(c) => {
          check_eq(c.tries.length(), 1, msg="baz 1 个 try_item")
          check_eq(c.tries[0].start_addr, 0, msg="start_addr")
          check_eq(c.tries[0].insn_count, 2, msg="insn_count")
          check_eq(
            c.tries[0].catch_type_index,
            Some(1),
            msg="旧 first_type=Some(1)",
          )
        }
        None => assert_true(false, msg="baz 应有 code_item")
      }
    }
  }
  assert_true(found, msg="应找到 baz 的 code_item")
}

///|
/// DoD：新增解析路径进截断扫描——`catch_handlers` 对所有前缀不 panic。
test "W8 catch_handlers: 全前缀截断扫描无 panic" {
  let (bytes, _, list_off) = build_catch_fx()
  for n in 0..<bytes.length() {
    let prefix = b_prefix(bytes.to_array(), n)
    let mut ok = false
    try ignore(@dex.catch_handlers(prefix, list_off)) catch {
      @dex.DexError::BadCodeItem(_) => ok = true
      _ => assert_true(false, msg="截断只允许 BadCodeItem")
    } noraise {
      _ => ok = true
    }
    assert_true(ok, msg="前缀 " + n.to_string() + " 不应 panic")
  }
}
