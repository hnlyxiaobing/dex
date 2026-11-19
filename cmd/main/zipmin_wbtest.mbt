// Whitebox 测试：zipmin 宽松 ZIP 读取器的 CRC-32 校验与 fail-closed 语义。
// 覆盖验收 T-W3-1..T-W3-5（见 docs/2026-11-16-test-system-design.md / dev-plan W3）。
// 全部在测试内用 `Array[Byte]` 构造合成 ZIP/APK，不引入二进制 fixture。
// 可访问 cmd/main 私有函数（zip_min_entries / zip_min_extract / z_crc32 / zip_dex_collect 等）。

///|
/// 小端写 u16 到字节数组。
fn zw16(arr : Array[Byte], v : Int32) -> Unit {
  arr.push((v & 0xFF).to_byte())
  arr.push(((v >> 8) & 0xFF).to_byte())
}

///|
/// 小端写 u32 到字节数组。
fn zw32(arr : Array[Byte], v : Int32) -> Unit {
  arr.push((v & 0xFF).to_byte())
  arr.push(((v >> 8) & 0xFF).to_byte())
  arr.push(((v >> 16) & 0xFF).to_byte())
  arr.push(((v >> 24) & 0xFF).to_byte())
}

///|
/// 追加字符串的 UTF-8 字节（测试内只用 ASCII 条目名）。
fn zw_str(arr : Array[Byte], s : String) -> Unit {
  for c in s.iter() {
    arr.push(c.to_int().to_byte())
  }
}

///|
/// 条目规格（合成 ZIP 用）。`crc_c`/`crc_l` 分别为中央目录 / 本地头 CRC（位模式）。
struct ZEnt {
  name : String
  meth : Int32
  raw : Bytes // 存储字节（压缩后或原样）
  usize : Int32 // 解压后长度
  crc_c : Int32 // 中央目录 CRC-32
  crc_l : Int32 // 本地头 CRC-32
  local_extra : Bytes
}

///|
/// Store 条目：payload 原样存储，CRC 正确。
fn zb_store(name : String, payload : Bytes) -> ZEnt {
  let crc = z_crc32(payload).reinterpret_as_int()
  ZEnt::{
    name,
    meth: 0,
    raw: payload,
    usize: payload.length(),
    crc_c: crc,
    crc_l: crc,
    local_extra: b"",
  }
}

///|
/// Deflate 条目：payload 经 `@flate.deflate_all` 压缩，CRC 正确。
fn zb_deflate(name : String, payload : Bytes) -> ZEnt {
  let comp = @flate.deflate_all(payload.clamped_view())
  let crc = z_crc32(payload).reinterpret_as_int()
  ZEnt::{
    name,
    meth: 8,
    raw: comp,
    usize: payload.length(),
    crc_c: crc,
    crc_l: crc,
    local_extra: b"",
  }
}

///|
/// 合成 ZIP：local 头 + 数据 → 中央目录 → EOCD。
/// 本地头 CRC 在偏移 14，中央目录 CRC 在偏移 16，与读取器读取位置一致。
fn zb_build(ents : Array[ZEnt]) -> Bytes {
  let out : Array[Byte] = []
  let offs : Array[Int32] = []
  for e in ents {
    offs.push(out.length())
    // local 头（30 字节定长）
    zw32(out, 0x04034b50)
    zw16(out, 20) // version needed
    zw16(out, 0) // flag
    zw16(out, e.meth)
    zw16(out, 0) // mod time
    zw16(out, 0) // mod date
    zw32(out, e.crc_l) // CRC-32 @14
    zw32(out, e.raw.length())
    zw32(out, e.usize)
    zw16(out, e.name.length())
    zw16(out, e.local_extra.length())
    zw_str(out, e.name)
    for i in 0..<e.local_extra.length() {
      out.push(e.local_extra[i])
    }
    for i in 0..<e.raw.length() {
      out.push(e.raw[i])
    }
  }
  let cd_off = out.length()
  for i in 0..<ents.length() {
    let e = ents[i]
    // 中央目录记录（46 字节定长）
    zw32(out, 0x02014b50)
    zw16(out, 20) // version made by
    zw16(out, 20) // version needed
    zw16(out, 0) // flag
    zw16(out, e.meth)
    zw16(out, 0) // mod time
    zw16(out, 0) // mod date
    zw32(out, e.crc_c) // CRC-32 @16
    zw32(out, e.raw.length())
    zw32(out, e.usize)
    zw16(out, e.name.length())
    zw16(out, 0) // extra len（中央目录无 extra）
    zw16(out, 0) // comment len
    zw16(out, 0) // disk start
    zw16(out, 0) // internal attrs
    zw32(out, 0) // external attrs
    zw32(out, offs[i])
    zw_str(out, e.name)
  }
  let cd_size = out.length() - cd_off
  // EOCD（22 字节）
  zw32(out, 0x06054b50)
  zw16(out, 0) // disk
  zw16(out, 0) // cd disk
  zw16(out, ents.length())
  zw16(out, ents.length())
  zw32(out, cd_size)
  zw32(out, cd_off)
  zw16(out, 0) // comment len
  Bytes::from_array(out)
}

///|
/// 翻转字节数组 `bytes` 中索引 `idx` 处的一个 bit（用于构造损坏条目）。
fn zb_flip_bit(bytes : Bytes, idx : Int32) -> Bytes {
  let arr : Array[Byte] = []
  for i in 0..<bytes.length() {
    arr.push(bytes[i])
  }
  if idx >= 0 && idx < arr.length() {
    arr[idx] = (arr[idx].to_int() ^ 0x01).to_byte()
  }
  Bytes::from_array(arr)
}

///|
/// 覆写 EOCD 的 this-disk 与 total-entries 两字段（偏移 eocd+8 / +10）。
fn zb_patch_eocd_count(zip : Bytes, total : Int32) -> Bytes {
  let arr : Array[Byte] = []
  for i in 0..<zip.length() {
    arr.push(zip[i])
  }
  let eocd = arr.length() - 22
  arr[eocd + 8] = (total & 0xFF).to_byte()
  arr[eocd + 9] = ((total >> 8) & 0xFF).to_byte()
  arr[eocd + 10] = (total & 0xFF).to_byte()
  arr[eocd + 11] = ((total >> 8) & 0xFF).to_byte()
  Bytes::from_array(arr)
}

///|
/// 覆写中央目录某条目（偏移 cd_off + 46 * k）的 csize 字段（+20）为给定值。
fn zb_patch_csize(zip : Bytes, k : Int32, csize : Int32) -> Bytes {
  let arr : Array[Byte] = []
  for i in 0..<zip.length() {
    arr.push(zip[i])
  }
  let eocd = arr.length() - 22
  let cd_off = z_u32(zip, eocd + 16)
  let off = cd_off + 46 * k + 20
  arr[off] = (csize & 0xFF).to_byte()
  arr[off + 1] = ((csize >> 8) & 0xFF).to_byte()
  arr[off + 2] = ((csize >> 16) & 0xFF).to_byte()
  arr[off + 3] = ((csize >> 24) & 0xFF).to_byte()
  Bytes::from_array(arr)
}

///|
/// W3 前置：CRC-32 算法符合 IEEE 802.3 标准向量。
test "W3 CRC-32：IEEE 802.3 已知向量 123456789" {
  assert_eq(
    z_crc32(b"123456789"),
    0xCBF43926U,
    msg="CRC-32(\"123456789\") 应等于 0xCBF43926",
  )
  assert_eq(z_crc32(b""), 0U, msg="空串 CRC-32 应为 0")
  assert_eq(
    z_crc32(b"abc"),
    0x352441C2U,
    msg="CRC-32(\"abc\") 应等于 0x352441C2",
  )
}

///|
/// T-W3-1：合法 ZIP，Store 与 Deflate 双形态 → 条目字节正确、CRC 通过。
test "W3/T-W3-1：合法 ZIP Store 与 Deflate 双形态 CRC 通过" {
  let p1 = b"classes.dex payload (store)"
  let p2 = b"classes2.dex payload (deflate)"
  let zip = zb_build([
    zb_store("classes.dex", p1),
    zb_deflate("classes2.dex", p2),
  ])
  let ents = zip_min_entries(zip)
  assert_eq(ents.length(), 2, msg="应解析出两个条目")
  // 按条目名逐一提取并校验
  let mut store_seen = 0
  let mut deflate_seen = 0
  for e in ents {
    let r = zip_min_extract(zip, e)
    assert_true(r.ok, msg="条目 \{e.name} 应校验通过")
    if e.name == "classes.dex" {
      assert_eq(r.data, p1, msg="Store 条目字节应与原 payload 一致")
      store_seen = store_seen + 1
    } else if e.name == "classes2.dex" {
      assert_eq(
        r.data,
        p2,
        msg="Deflate 条目解压字节应与原 payload 一致",
      )
      deflate_seen = deflate_seen + 1
    }
  }
  assert_eq(store_seen, 1)
  assert_eq(deflate_seen, 1)
  // 经 zip_dex_entries 收集亦无诊断
  let c = zip_dex_collect(zip, None)
  assert_true(c.diag == "", msg="合法 ZIP 不应有诊断")
  assert_eq(c.entries.length(), 2)
}

///|
/// T-W3-2：Deflate 压缩体中间字节损坏 → 明确失败，不 panic。
test "W3/T-W3-2：Deflate 压缩体中间字节损坏 → 失败不 panic" {
  let payload = b"classes.dex deflate payload to be corrupted"
  let comp = @flate.deflate_all(payload.clamped_view())
  let crc = z_crc32(payload).reinterpret_as_int()
  // 破坏压缩体中部的一个 bit
  let bad = zb_flip_bit(comp, comp.length() / 2)
  let ent = ZEnt::{
    name: "classes.dex",
    meth: 8,
    raw: bad,
    usize: payload.length(),
    crc_c: crc,
    crc_l: crc,
    local_extra: b"",
  }
  let zip = zb_build([ent])
  let es = zip_min_entries(zip)
  assert_eq(es.length(), 1)
  let r = zip_min_extract(zip, es[0]) // 不得 panic
  assert_true(!r.ok, msg="压缩体损坏应判条目失败")
  assert_true(r.reason != "", msg="应给出失败原因")
}

///|
/// T-W3-3：两条 dex 中坏一条（CRC 字段与 payload 不符）→ `zip_dex_entries`
/// 返回空表、诊断非空——整体拒绝、无部分输出。
test "W3/T-W3-3：CRC 不符坏一条 dex → 整体拒绝无部分输出" {
  let good = zb_store("classes.dex", b"good dex payload")
  let bad = zb_store("classes2.dex", b"bad dex payload with wrong crc")
  // 翻转 classes2.dex 的中央目录 CRC（payload 不变 → 计算值 != 存储值）
  let bad2 = ZEnt::{
    name: bad.name,
    meth: bad.meth,
    raw: bad.raw,
    usize: bad.usize,
    crc_c: (bad.crc_c.reinterpret_as_uint() ^ 1U).reinterpret_as_int(),
    crc_l: bad.crc_l,
    local_extra: bad.local_extra,
  }
  let zip = zb_build([good, bad2])
  // 字典序 classes.dex 先于 classes2.dex：即便先收集到好条目，整体仍须拒绝。
  let ents = zip_dex_entries(zip, None)
  assert_true(
    ents.is_empty(),
    msg="整体拒绝：返回空表（无部分输出）",
  )
  let c = zip_dex_collect(zip, None)
  assert_true(
    c.entries.is_empty(),
    msg="收集结果亦为空，好条目不得泄漏",
  )
  assert_true(c.diag != "", msg="诊断非空")
  assert_true(
    c.diag.contains("classes2.dex"),
    msg="诊断应指明损坏条目",
  )
}

///|
/// T-W3-4：local extra 含 1~3 字节 aapt2 风格裸填充 → 仍正常读取（回归）。
test "W3/T-W3-4：local extra 1~3 字节 padding 仍正常读取" {
  for pad in 1..<=3 {
    let payload = b"classes.dex payload with padding"
    let crc = z_crc32(payload).reinterpret_as_int()
    let local_extra = Bytes::make(pad, b'\x00')
    let ent = ZEnt::{
      name: "classes.dex",
      meth: 0,
      raw: payload,
      usize: payload.length(),
      crc_c: crc,
      crc_l: crc,
      local_extra,
    }
    let zip = zb_build([ent])
    let es = zip_min_entries(zip)
    assert_eq(es.length(), 1, msg="pad=\{pad} 应解析出一个条目")
    let r = zip_min_extract(zip, es[0])
    assert_true(r.ok, msg="pad=\{pad} 应校验通过")
    assert_eq(r.data, payload, msg="pad=\{pad} 负载字节应一致")
  }
}

///|
/// T-W3-5：ZIP64 标记（中央目录 csize=0xFFFFFFFF / EOCD 计数 0xFFFF）→ 显式拒绝，
/// 行为与改动前一致（不 panic、判非法）。
test "W3/T-W3-5：ZIP64 标记显式拒绝（0xFFFFFFFF / EOCD 0xFFFF）" {
  // 情形 A：EOCD total-entries 0xFFFF（ZIP64 标记）
  let zip_a = zb_patch_eocd_count(
    zb_build([zb_store("classes.dex", b"x")]),
    0xFFFF,
  )
  let ents_a = zip_min_entries(zip_a)
  assert_true(ents_a.is_empty(), msg="EOCD 计数 0xFFFF 应显式拒绝")
  // 情形 B：中央目录 csize = 0xFFFFFFFF（ZIP64 尺寸标记）
  let zip_b = zb_patch_csize(
    zb_build([zb_store("classes.dex", b"x")]),
    0,
    0xFFFFFFFF,
  )
  let ents_b = zip_min_entries(zip_b)
  assert_true(ents_b.is_empty(), msg="csize=0xFFFFFFFF 应显式拒绝")
}
