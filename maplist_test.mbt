///|
/// W4：map_list 结构化视图（`map_items`）验收测试。
///
/// 覆盖：
///   T-W4-1 合成 DEX map_items 与 dexdump map list 黄金逐项一致
///   T-W4-2 0x0007 / 0x0008 type code 原样保留（不塞入冻结枚举）
///   T-W4-3 map_off 越界 / 截断 / unused 非 0 → 声明的错误变体，无 panic
///   T-W4-4 map_off=0 → 空数组
/// 快照 diff 纯加法（T-W4-5）由五门禁 Gate5 承载。
///
/// 字节构造 helper 复用同包既有定义（dex_test.mbt）：b_u8/b_u16/b_u32/
/// b_align4/b_patch_u32/b_fix_checksum/b_adler。

///|
/// 构造最小 DEX：header + 一处 map_list。
/// `with_unused` 为 true 时首项 unused 写非 0，构造 BadTableOffset 语料。
fn build_min_dex(map_off : Int32, with_unused : Bool) -> Bytes {
  let arr : Array[Byte] = []
  for _ in 0..<0x70 {
    b_u8(arr, 0)
  }
  b_patch_u32(arr, 0x00, 0x0a786564)
  b_patch_u32(arr, 0x04, 0x00353330)
  b_patch_u32(arr, 0x24, 0x70) // header_size
  // map_off = 0 → 空数组语料。
  if map_off == 0 {
    b_patch_u32(arr, 0x34, 0)
    b_patch_u32(arr, 0x20, arr.length())
    b_fix_checksum(arr)
    return Bytes::from_array(arr)
  }
  // 正常路径：map_list 紧随 header 之后。
  let list_off = 0x70
  b_patch_u32(arr, 0x34, list_off) // map_off
  b_u32(arr, 5) // count
  let items = [
    (0x0000, 1, 0x00), // header
    (0x0001, 3, 0x84), // string_id
    (0x0007, 1, 0x90), // call_site_id
    (0x0008, 2, 0x94), // method_handle
    (0x1000, 1, 0x70), // map_list
  ]
  for (ty, size, off) in items {
    b_u16(arr, ty)
    if with_unused {
      b_u16(arr, 0x1234) // unused 非 0 → BadTableOffset(MapList, …)
    } else {
      b_u16(arr, 0)
    }
    b_u32(arr, size)
    b_u32(arr, off)
  }
  b_align4(arr)
  b_patch_u32(arr, 0x20, arr.length()) // file_size
  b_fix_checksum(arr)
  Bytes::from_array(arr)
}

///|
/// T-W4-1 + T-W4-2：合成 DEX map_items 与黄金逐项一致，0x0007/0x0008 原样保留。
test "W4 map_items: 黄金逐项一致 + 0x0007/0x0008 原样保留" {
  let bytes = build_min_dex(0x70, false)
  let items = @dex.map_items(bytes)
  check_eq(items.length(), 5, msg="map_items 共 5 项")
  let gold : Array[(Int32, Int32, Int32)] = [
    (0x0000, 1, 0x00),
    (0x0001, 3, 0x84),
    (0x0007, 1, 0x90),
    (0x0008, 2, 0x94),
    (0x1000, 1, 0x70),
  ]
  for i in 0..<5 {
    check_eq(
      items[i].type_code,
      gold[i].0,
      msg="type_code[" + i.to_string() + "]",
    )
    check_eq(items[i].size, gold[i].1, msg="size[" + i.to_string() + "]")
    check_eq(items[i].offset, gold[i].2, msg="offset[" + i.to_string() + "]")
  }
  // 0x0007 / 0x0008 以原始 Int32 保留（不加枚举）。
  check_eq(items[2].type_code, 0x0007, msg="call_site_id type 原样保留")
  check_eq(items[3].type_code, 0x0008, msg="method_handle type 原样保留")
}

///|
/// T-W4-4：map_off = 0 → 空数组（map_list 可选）。
test "W4 map_items: map_off=0 返回空数组" {
  let bytes = build_min_dex(0, false)
  let items = @dex.map_items(bytes)
  check_eq(items.length(), 0, msg="map_off=0 → 空数组")
}

///|
/// T-W4-3：map_off 越界 → UnexpectedEof(map_off)。
test "W4 map_items: map_off 越界报 UnexpectedEof" {
  let arr : Array[Byte] = []
  for _ in 0..<0x70 {
    b_u8(arr, 0)
  }
  b_patch_u32(arr, 0x00, 0x0a786564)
  b_patch_u32(arr, 0x04, 0x00353330)
  b_patch_u32(arr, 0x24, 0x70)
  b_patch_u32(arr, 0x34, 0x123456) // map_off 远超文件长度
  b_patch_u32(arr, 0x20, 0x70)
  b_fix_checksum(arr)
  let bytes = Bytes::from_array(arr)
  let mut got = false
  ignore(@dex.map_items(bytes)) catch {
    @dex.DexError::UnexpectedEof(off) => {
      assert_eq(off, 0x123456)
      got = true
    }
    _ => ()
  }
  assert_true(got, msg="map_off 越界应报 UnexpectedEof")
}

///|
/// T-W4-3：count 截断（map_list 声明项数超出剩余字节）→ UnexpectedEof。
test "W4 map_items: count 截断报 UnexpectedEof" {
  let arr : Array[Byte] = []
  for _ in 0..<0x70 {
    b_u8(arr, 0)
  }
  b_patch_u32(arr, 0x00, 0x0a786564)
  b_patch_u32(arr, 0x04, 0x00353330)
  b_patch_u32(arr, 0x24, 0x70)
  b_patch_u32(arr, 0x34, 0x70) // map_off = 0x70
  b_patch_u32(arr, 0x20, 0x70)
  b_u32(arr, 1000) // count 远超实际字节
  b_fix_checksum(arr)
  let bytes = Bytes::from_array(arr)
  let mut got = false
  ignore(@dex.map_items(bytes)) catch {
    @dex.DexError::UnexpectedEof(off) => {
      assert_eq(off, 0x70)
      got = true
    }
    _ => ()
  }
  assert_true(got, msg="count 截断应报 UnexpectedEof")
}

///|
/// T-W4-3：unused 非 0 → BadTableOffset(MapList, …)。
test "W4 map_items: unused 非 0 报 BadTableOffset" {
  let bytes = build_min_dex(0x70, true)
  let mut got = false
  ignore(@dex.map_items(bytes)) catch {
    @dex.DexError::BadTableOffset(@dex.TableKind::MapList, p) => {
      assert_eq(p, 0x74)
      got = true
    }
    _ => ()
  }
  assert_true(got, msg="unused 非 0 应报 BadTableOffset")
}

///|
/// DoD：新增解析路径进截断扫描——`map_items` 对所有前缀不 panic，
/// 只允许成功或抛既有 `DexError` 变体。
test "W4 map_items: 全前缀截断扫描无 panic" {
  let bytes = build_min_dex(0x70, false)
  for n in 0..<bytes.length() {
    let prefix = b_prefix(bytes.to_array(), n)
    let mut ok = false
    try ignore(@dex.map_items(prefix)) catch {
      @dex.DexError::UnexpectedEof(_) => ok = true
      @dex.DexError::BadTableOffset(_) => ok = true
      _ => assert_true(false, msg="截断只允许声明错误变体")
    } noraise {
      _ => ok = true
    }
    assert_true(ok, msg="前缀 " + n.to_string() + " 不应 panic")
  }
}
