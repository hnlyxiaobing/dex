///|
/// W6：fill-array-data-payload 元素展开视图（`array_payload_view`）验收测试。
///
/// 覆盖：
///   T-W6-1 不同 element_width（1/2/4/8）逐元素切片全矩阵
///   T-W6-2 elements 保留原始小端字节序（不做端序转换，A1）
///   T-W6-3 错误路径：ident≠0x0300 / size 溢出 / width=0 且 size>0 / 截断 → BadCodeItem
///   T-W6-4 恒等式 I7：`array_payload_view` 的 width/size 与解析出的
///          fill-array-data-payload 指令 operand 一致
/// 字节构造 helper 复用同包既有定义（dex_test.mbt）。

///|
/// 构造最小 DEX：header + 单个 code_item，insns 内含 fill-array-data-payload。
/// 返回 `(bytes, code_off, payload 的 code-unit 偏移 u=2)`。
fn build_payload_fx(
  width : Int32,
  size : Int32,
  data : Array[Byte],
) -> (Bytes, Int32, Int32) {
  let arr : Array[Byte] = []
  for _ in 0..<0x70 {
    b_u8(arr, 0)
  }
  b_patch_u32(arr, 0x00, 0x0a786564)
  b_patch_u32(arr, 0x04, 0x00353330)
  b_patch_u32(arr, 0x24, 0x70)
  b_patch_u32(arr, 0x34, 0) // map_off = 0
  let code_off = 0x70
  b_u16(arr, 1) // registers_size
  b_u16(arr, 0) // ins_size
  b_u16(arr, 0) // outs_size
  b_u16(arr, 0) // tries_size
  b_u32(arr, 0) // debug_info_off
  let data_bytes = size * width
  let payload_units = 4 + (data_bytes + 1) / 2
  let insns_size = 2 + payload_units
  b_u32(arr, insns_size)
  // insns：u=0 fill-array-data v0, +0；u=1 offset 操作数；u=2 起 payload
  b_u16(arr, 0x0026)
  b_u16(arr, 0x0000)
  b_u16(arr, 0x0300) // ident
  b_u16(arr, width)
  b_u32(arr, size)
  for d in data {
    b_u8(arr, d.to_int())
  }
  // payload 数据区对齐到 code unit 边界（奇数字节末尾补零对齐）
  let payload_start = code_off + 16 + 2 * 2
  while (arr.length() - payload_start) % 2 != 0 {
    b_u8(arr, 0)
  }
  b_align4(arr)
  b_patch_u32(arr, 0x20, arr.length()) // file_size
  b_fix_checksum(arr)
  (Bytes::from_array(arr), code_off, 2)
}

///|
/// T-W6-1 + T-W6-2：width 1 四元素切片 + 原始字节序。
test "W6 array_payload_view: width=1 逐元素切片 + 原始字节序" {
  let (bytes, code_off, u) = build_payload_fx(1, 4, [
    b'\x01', b'\x02', b'\x03', b'\x04',
  ])
  let v = @dex.array_payload_view(bytes, code_off, u)
  check_eq(v.element_width, 1, msg="element_width=1")
  check_eq(v.elements.length(), 4, msg="4 元素")
  check_eq(v.elements[0].length(), 1, msg="e0 长度")
  check_eq(v.elements[0][0].to_int(), 0x01, msg="e0 值")
  check_eq(v.elements[1][0].to_int(), 0x02, msg="e1 值")
  check_eq(v.elements[2][0].to_int(), 0x03, msg="e2 值")
  check_eq(v.elements[3][0].to_int(), 0x04, msg="e3 值")
}

///|
/// T-W6-1 + T-W6-2：width=2 每元素为两字节原始小端序（不做端序转换）。
test "W6 array_payload_view: width=2 原始两字节小端序" {
  let (bytes, code_off, u) = build_payload_fx(2, 3, [
    b'\x01', b'\x00', b'\x02', b'\x00', b'\x03', b'\x00',
  ])
  let v = @dex.array_payload_view(bytes, code_off, u)
  check_eq(v.element_width, 2, msg="element_width=2")
  check_eq(v.elements.length(), 3, msg="3 元素")
  // 不做端序转换：elements[i] 就是 [0x01,0x00] 原样（小端 1），非 0x0100
  check_eq(v.elements[0][0].to_int(), 0x01, msg="e0 低字节")
  check_eq(v.elements[0][1].to_int(), 0x00, msg="e0 高字节")
  check_eq(v.elements[2][0].to_int(), 0x03, msg="e2 低字节")
}

///|
/// T-W6-1 + T-W6-2：width=4 每元素四字节原始序。
test "W6 array_payload_view: width=4 逐元素四字节" {
  let (bytes, code_off, u) = build_payload_fx(4, 2, [
    b'\x11', b'\x22', b'\x33', b'\x44', b'\xaa', b'\xbb', b'\xcc', b'\xdd',
  ])
  let v = @dex.array_payload_view(bytes, code_off, u)
  check_eq(v.element_width, 4, msg="element_width=4")
  check_eq(v.elements.length(), 2, msg="2 元素")
  check_eq(v.elements[0][0].to_int(), 0x11, msg="e0 b0")
  check_eq(v.elements[0][3].to_int(), 0x44, msg="e0 b3")
  check_eq(v.elements[1][0].to_int(), 0xaa, msg="e1 b0")
  check_eq(v.elements[1][3].to_int(), 0xdd, msg="e1 b3")
}

///|
/// T-W6-1：width=8 每元素八字节原始序（宽度矩阵收尾）。
test "W6 array_payload_view: width=8 逐元素八字节" {
  let (bytes, code_off, u) = build_payload_fx(8, 2, [
    b'\x01', b'\x02', b'\x03', b'\x04', b'\x05', b'\x06', b'\x07', b'\x08', b'\x09',
    b'\x0a', b'\x0b', b'\x0c', b'\x0d', b'\x0e', b'\x0f', b'\x10',
  ])
  let v = @dex.array_payload_view(bytes, code_off, u)
  check_eq(v.element_width, 8, msg="element_width=8")
  check_eq(v.elements.length(), 2, msg="2 元素")
  check_eq(v.elements[0].length(), 8, msg="e0 长度 8")
  check_eq(v.elements[0][0].to_int(), 0x01, msg="e0 b0")
  check_eq(v.elements[0][7].to_int(), 0x08, msg="e0 b7")
  check_eq(v.elements[1][0].to_int(), 0x09, msg="e1 b0")
  check_eq(v.elements[1][7].to_int(), 0x10, msg="e1 b7")
}

///|
/// T-W6-2：奇数总字节（width=1, size=3 → data_bytes=3 奇）→ 末元素按规范处理；
/// 对齐 pad 字节不产生元素，raw 数据区与视图长度恒等（size*width == Σ 元素宽）。
test "W6 array_payload_view: 奇数总字节 pad 不产元素 + 视图长度恒等式" {
  let (bytes, code_off, u) = build_payload_fx(1, 3, [b'\x0a', b'\x0b', b'\x0c'])
  let v = @dex.array_payload_view(bytes, code_off, u)
  check_eq(v.element_width, 1, msg="element_width=1")
  check_eq(v.elements.length(), 3, msg="3 元素（pad 不产元素）")
  check_eq(v.elements[0][0].to_int(), 0x0a, msg="e0")
  check_eq(v.elements[1][0].to_int(), 0x0b, msg="e1")
  check_eq(v.elements[2][0].to_int(), 0x0c, msg="e2")
  // 视图长度恒等式：Σ 元素宽 == size*width == data_bytes（不含对齐 pad）
  let mut total = 0
  for el in v.elements {
    total = total + el.length()
  }
  check_eq(total, 3, msg="Σ 元素宽 == data_bytes")
}

///|
/// T-W6-3：size 溢出（size > 0x3fffffff/width）→ BadCodeItem，无 panic。
test "W6 array_payload_view: size 溢出报 BadCodeItem" {
  let (bytes, code_off, u) = build_payload_fx(1, 0x40000000, [])
  let mut got = false
  ignore(@dex.array_payload_view(bytes, code_off, u)) catch {
    @dex.DexError::BadCodeItem(c, msg) => {
      assert_eq(c, code_off)
      assert_true(msg.contains("size overflow"), msg="size 溢出错误消息")
      got = true
    }
    _ => ()
  }
  assert_true(got, msg="size 溢出应报 BadCodeItem")
}

///|
/// T-W6-3：ident ≠ 0x0300 → BadCodeItem(code_off, "not a fill-array-data-payload")。
test "W6 array_payload_view: ident 非 0x0300 报 BadCodeItem" {
  // 直接把 payload 首 code unit 改成 0x0100（packed-switch）再重算 checksum。
  let (bytes, code_off, u) = build_payload_fx(1, 2, [b'\x01', b'\x02'])
  let arr : Array[Byte] = []
  for i in 0..<bytes.length() {
    arr.push(bytes[i])
  }
  // payload ident 字节位于 code_off+16+u*2 = code_off+20
  b_u16_patch(arr, code_off + 16 + u * 2, 0x0100)
  let sum = b_adler(arr, 12, arr.length())
  arr[8] = (sum & 0xff).to_byte()
  arr[9] = ((sum >> 8) & 0xff).to_byte()
  arr[10] = ((sum >> 16) & 0xff).to_byte()
  arr[11] = ((sum >> 24) & 0xff).to_byte()
  let bad = Bytes::from_array(arr)
  let mut got = false
  ignore(@dex.array_payload_view(bad, code_off, u)) catch {
    @dex.DexError::BadCodeItem(c, msg) => {
      assert_eq(c, code_off)
      assert_true(
        msg.contains("not a fill-array-data-payload"),
        msg="ident 错误消息",
      )
      got = true
    }
    _ => ()
  }
  assert_true(got, msg="ident 非 0x0300 应报 BadCodeItem")
}

///|
/// T-W6-3：size 溢出（width=0 且 size>0）→ BadCodeItem。
test "W6 array_payload_view: width=0 且 size>0 报 BadCodeItem" {
  let (bytes, code_off, u) = build_payload_fx(0, 3, [])
  let mut got = false
  ignore(@dex.array_payload_view(bytes, code_off, u)) catch {
    @dex.DexError::BadCodeItem(c, msg) => {
      assert_eq(c, code_off)
      assert_true(
        msg.contains("invalid element width"),
        msg="width=0 错误消息",
      )
      got = true
    }
    _ => ()
  }
  assert_true(got, msg="width=0 且 size>0 应报 BadCodeItem")
}

///|
/// DoD：新增解析路径进截断扫描——`array_payload_view` 对所有前缀不 panic，
/// 只允许成功或抛既有 `DexError::BadCodeItem`。
test "W6 array_payload_view: 全前缀截断扫描无 panic" {
  let (bytes, code_off, u) = build_payload_fx(2, 3, [
    b'\x01', b'\x00', b'\x02', b'\x00', b'\x03', b'\x00',
  ])
  for n in 0..<bytes.length() {
    let prefix = b_prefix(bytes.to_array(), n)
    let mut ok = false
    try ignore(@dex.array_payload_view(prefix, code_off, u)) catch {
      @dex.DexError::BadCodeItem(_) => ok = true
      _ => assert_true(false, msg="截断只允许 BadCodeItem")
    } noraise {
      _ => ok = true
    }
    assert_true(ok, msg="前缀 " + n.to_string() + " 不应 panic")
  }
}

///|
/// T-W6-3：数据区截断（size 超出剩余字节）→ BadCodeItem。
test "W6 array_payload_view: 数据区截断报 BadCodeItem" {
  // size=4 需要 4 字节数据，但截掉末尾 2 字节使 available < size*width。
  let (bytes, code_off, u) = build_payload_fx(1, 4, [
    b'\x01', b'\x02', b'\x03', b'\x04',
  ])
  let truncated = b_prefix(bytes.to_array(), bytes.length() - 2)
  let mut got = false
  ignore(@dex.array_payload_view(truncated, code_off, u)) catch {
    @dex.DexError::BadCodeItem(c, _) => {
      assert_eq(c, code_off)
      got = true
    }
    _ => ()
  }
  assert_true(got, msg="数据区截断应报 BadCodeItem")
}
