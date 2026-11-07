// WP-G / Q1 畸形派生用例（R2 准备轮新增文件）：从**真实** classes.dex 派生，
// 覆盖截断 / 偏移污染 / 错误 checksum / 表偏移（索引）污染。断言目标：报 `DexError`
// 而非 panic。样本来源与哈希见 fixtures/golden/ASSETS.md。

///|
/// 字节级变异：拷贝后把 `offset` 处改成 `value`。
fn fx_mut(src : Bytes, offset : Int32, value : Byte) -> Bytes {
  let arr : Array[Byte] = []
  for i in 0..<src.length() {
    arr.push(src[i])
  }
  if offset >= 0 && offset < arr.length() {
    arr[offset] = value
  }
  Bytes::from_array(arr)
}

///|
/// 截断到前 `n` 字节。
fn fx_cut(src : Bytes, n : Int32) -> Bytes {
  let arr : Array[Byte] = []
  let mut i = 0
  while i < n && i < src.length() {
    arr.push(src[i])
    i = i + 1
  }
  Bytes::from_array(arr)
}

///|
/// adler32（DEX checksum 算法，覆盖 `start..end`）。
fn fx_adler32(d : Array[Byte], start : Int32, end : Int32) -> UInt32 {
  let mut a : UInt32 = 1U
  let mut b : UInt32 = 0U
  let mut i = start
  while i < end {
    a = (a + d[i].to_uint()) % 65521U
    b = (b + a) % 65521U
    i = i + 1
  }
  (b << 16) | a
}

///|
/// 变异后**重算 header checksum**（偏移 8..11），用于越过完整性校验、
/// 直达结构性错误路径（表偏移 / map_off / 指令解码）。
fn fx_mut_fixed(src : Bytes, off : Int32, value : Byte) -> Bytes {
  let arr : Array[Byte] = []
  for i in 0..<src.length() {
    arr.push(src[i])
  }
  if off >= 0 && off < arr.length() {
    arr[off] = value
  }
  let sum = fx_adler32(arr, 12, arr.length())
  arr[8] = (sum & 0xFFU).to_byte()
  arr[9] = ((sum >> 8) & 0xFFU).to_byte()
  arr[10] = ((sum >> 16) & 0xFFU).to_byte()
  arr[11] = ((sum >> 24) & 0xFFU).to_byte()
  Bytes::from_array(arr)
}

///|
/// 写小端 u32 后重算 checksum。
fn fx_set_u32_fixed(src : Bytes, off : Int32, v : Int32) -> Bytes {
  let arr : Array[Byte] = []
  for i in 0..<src.length() {
    arr.push(src[i])
  }
  arr[off] = (v & 0xFF).to_byte()
  arr[off + 1] = ((v >> 8) & 0xFF).to_byte()
  arr[off + 2] = ((v >> 16) & 0xFF).to_byte()
  arr[off + 3] = ((v >> 24) & 0xFF).to_byte()
  let sum = fx_adler32(arr, 12, arr.length())
  arr[8] = (sum & 0xFFU).to_byte()
  arr[9] = ((sum >> 8) & 0xFFU).to_byte()
  arr[10] = ((sum >> 16) & 0xFFU).to_byte()
  arr[11] = ((sum >> 24) & 0xFFU).to_byte()
  Bytes::from_array(arr)
}

///|
/// 解析是否以 `DexError` 结束（true = 报错）。
fn fx_raises(b : Bytes) -> Bool {
  let mut raised = false
  try ignore(@dex.parse(b)) catch {
    _ => raised = true
  } noraise {
    _ => ()
  }
  raised
}

///|
test "dex malformed: 截断真实 dex 报错且不 panic" {
  let src = fixture_tvshell_dex()
  for cut in [0, 1, 100, 1000, 4000, 4367] {
    assert_true(
      fx_raises(fx_cut(src, cut)),
      msg="截断到 \{cut} 字节应报 DexError",
    )
  }
}

///|
test "dex malformed: magic 污染报 BadMagic" {
  let src = fixture_tvshell_dex()
  let mut detail = ""
  try ignore(@dex.parse(fx_mut(src, 0, b'\x78'))) catch {
    @dex.DexError::BadMagic(m) => detail = m
    _ => detail = "other"
  } noraise {
    _ => ()
  }
  assert_true(detail != "", msg="magic 污染应报 BadMagic")
}

///|
test "dex malformed: 错误 checksum 报 BadMagic(checksum mismatch)" {
  let src = fixture_tvshell_dex()
  // 只改 header 的 checksum 字段（偏移 8）
  let mut detail = ""
  try ignore(@dex.parse(fx_mut(src, 8, b'\x00'))) catch {
    @dex.DexError::BadMagic(m) => detail = m
    _ => detail = "other"
  } noraise {
    _ => ()
  }
  assert_true(detail.contains("checksum"), msg="应报 checksum mismatch")
  // 任意正文字节污染（不重算 checksum）同样必须被完整性校验拦下
  assert_true(
    fx_raises(fx_mut(src, 2000, b'\xff')),
    msg="正文污染应报错",
  )
}

///|
test "dex malformed: 表偏移污染越过 checksum 后报 BadTableOffset" {
  let src = fixture_tvshell_dex()
  // string_ids_off（header 偏移 60）改为 4（< 0x70）
  let mut detail = ""
  try ignore(@dex.parse(fx_set_u32_fixed(src, 60, 4))) catch {
    @dex.DexError::BadTableOffset(_, _) => detail = "BadTableOffset"
    _ => detail = "other"
  } noraise {
    _ => ()
  }
  assert_true(
    detail == "BadTableOffset",
    msg="表偏移污染应报 BadTableOffset",
  )
}

///|
/// map_off 越界检查位于 class_data 解析之后；`parse_class_data` 分段复位缺陷修复
/// （R2 主控，2026-11-07）后本用例启用。
test "dex malformed: map_off 越界报 UnexpectedEof" {
  let src = fixture_tvshell_dex()
  // map_off（header 偏移 52）指向文件尾之外 -> UnexpectedEof(map_off)
  let mut detail = ""
  try ignore(@dex.parse(fx_set_u32_fixed(src, 52, 4368 + 64))) catch {
    @dex.DexError::UnexpectedEof(_) => detail = "UnexpectedEof"
    _ => detail = "other"
  } noraise {
    _ => ()
  }
  assert_true(
    detail == "UnexpectedEof",
    msg="map_off 越界应报 UnexpectedEof",
  )
}

///|
test "dex malformed: 未知指令 opcode 报 InvalidInstruction 而非 panic" {
  let src = fixture_tvshell_dex()
  // code_item 首条指令位于 code_off(1384) + 16；把它改成 0xFF（Dalvik 未定义 opcode）
  let mut detail = ""
  try ignore(@dex.parse(fx_mut_fixed(src, 1384 + 16, b'\xff'))) catch {
    @dex.DexError::InvalidInstruction(_, _) => detail = "InvalidInstruction"
    _ => detail = "other"
  } noraise {
    _ => ()
  }
  assert_true(
    detail == "InvalidInstruction",
    msg="未定义 opcode 应报 InvalidInstruction",
  )
}

///|
/// DEX 是扁平表结构，没有 AXML/ZIP 那样的 chunk 概念；“未知 chunk 跳过”的等价
/// 用例在 axml/fixtures_malformed_test.mbt（未知 chunk 被跳过且不影响已有结构）。
#skip
test "dex malformed: 未知 chunk [SKIPPED: DEX 无 chunk 概念]" {
  println(
    "SKIPPED: DEX 无 chunk；等价用例见 axml 链（未知 chunk 跳过）",
  )
}

///|
/// 受控构建多 dex 样本（WP-4 2026-11-07）派生：两个 DEX 条目各自覆盖
/// 截断 / magic 污染 / 表偏移污染，同样只报 `DexError` 而非 panic。
/// 样本性质：受控自产（aapt2/d8/apksigner 构建），见 fixtures/golden/ASSETS.md。
test "dex malformed: 多 dex 样本截断与污染报错且不 panic" {
  let src = fixture_fx_multidex_dex()
  let src2 = fixture_fx_multidex2_dex()
  // 512 字节截断与 dex/tests/fixtures/edge-dex-truncated-512.dex（程序化派生样本）同字节。
  for cut in [0, 50, 500, 512, 1000, 2115] {
    assert_true(
      fx_raises(fx_cut(src, cut)),
      msg="桶 1 截断到 \{cut} 字节应报 DexError",
    )
  }
  for cut in [0, 50, 800, 1639] {
    assert_true(
      fx_raises(fx_cut(src2, cut)),
      msg="桶 2 截断到 \{cut} 字节应报 DexError",
    )
  }
  assert_true(
    fx_raises(fx_mut(src2, 0, b'\x58')),
    msg="桶 2 magic 污染应报 BadMagic",
  )
  // 表偏移污染（fx_set_u32_fixed 重算 checksum 越过完整性校验）：
  // string_ids 偏移（header +56）指向文件外。
  assert_true(
    fx_raises(fx_set_u32_fixed(src, 56, 0x0FFFFFFF)),
    msg="桶 1 string_ids 表偏移越界应报 BadTableOffset/UnexpectedEof",
  )
}
