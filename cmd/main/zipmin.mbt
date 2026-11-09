///|
/// 宽松 ZIP 读取器（axml-cli；dex-cli 有同构实现）。
/// 动机：moonbitlang/core/archive/zip 严格遍历 extra 字段链，会拒绝 aapt2 对齐填充
/// 产生的 1~3 字节裸填充 extra（真实第三方 APK 常见，unzip/zipinfo 等工具均容忍）。
/// 实测（开发期一个 52 MB 真实第三方 APK）：1028 个 local 头中
/// 403 个含 1~3 字节填充，core zip 报 `zip: truncated extra field header`。
/// 本读取器只解析中央目录（实测干净），提取时用 local 头的 name_len/extra_len 直接
/// 计算负载起点、跳过整个 extra 区域，**不遍历 extra 链**，对填充天然容忍。
/// 范围限定（如实登记）：不支持 ZIP64（开发期样本均无 ZIP64）、
/// 仅 method 0(Store)/8(Deflate)、不做 CRC-32 校验；条目名按 UTF-8 解码。

///|
/// 中央目录条目（宽松读取器视图）。
struct ZEntry {
  name : String
  usize : Int32
  csize : Int32
  comp : Int32
  local_off : Int32
}

///|
/// 字节串按 UTF-8 解码为字符串（非法序列按字节回退）。
fn z_str(b : Bytes) -> String {
  let chars : Array[Char] = []
  let n = b.length()
  let mut i = 0
  while i < n {
    let c0 = b.at(i).to_int()
    if c0 < 0x80 {
      chars.push(c0.unsafe_to_char())
      i = i + 1
    } else if (c0 & 0xE0) == 0xC0 && i + 1 < n {
      let v = ((c0 & 0x1F) << 6) | (b.at(i + 1).to_int() & 0x3F)
      chars.push(v.unsafe_to_char())
      i = i + 2
    } else if (c0 & 0xF0) == 0xE0 && i + 2 < n {
      let v = ((c0 & 0x0F) << 12) |
        ((b.at(i + 1).to_int() & 0x3F) << 6) |
        (b.at(i + 2).to_int() & 0x3F)
      chars.push(v.unsafe_to_char())
      i = i + 3
    } else {
      chars.push(c0.unsafe_to_char())
      i = i + 1
    }
  }
  let mut s = ""
  for c in chars {
    s = s + c.to_string()
  }
  s
}

///|
/// 小端读 u16。
fn z_u16(data : Bytes, off : Int32) -> Int32 {
  data.at(off).to_int() | (data.at(off + 1).to_int() << 8)
}

///|
/// 小端读 u32（按位模式 Int32；用作偏移/尺寸前校验非负）。
fn z_u32(data : Bytes, off : Int32) -> Int32 {
  data.at(off).to_int() |
  (data.at(off + 1).to_int() << 8) |
  (data.at(off + 2).to_int() << 16) |
  (data.at(off + 3).to_int() << 24)
}

///|
/// 拷贝 `data[off..off+len]` 为独立 `Bytes`。
fn z_slice(data : Bytes, off : Int32, len : Int32) -> Bytes {
  let arr : Array[Byte] = []
  for i in 0..<len {
    arr.push(data.at(off + i))
  }
  Bytes::from_array(arr)
}

///|
/// 解析中央目录 -> 条目表（结构异常时输出错误并返回空表）。
fn zip_min_entries(data : Bytes) -> Array[ZEntry] {
  let n = data.length()
  if n < 22 {
    eprintln("error: zip: 文件过短")
    return ([] : Array[ZEntry])
  }
  // EOCD：从尾部回扫（注释区最长 65535 字节）
  let mut eocd = -1
  let mut i = n - 22
  let limit = if n - 22 - 65535 > 0 { n - 22 - 65535 } else { 0 }
  while i >= limit {
    if z_u32(data, i) == 0x06054b50 {
      eocd = i
      break
    }
    i = i - 1
  }
  if eocd < 0 {
    eprintln(
      "error: zip: 找不到 EOCD（不是 ZIP/APK 或尾部结构损坏）",
    )
    return ([] : Array[ZEntry])
  }
  let count = z_u16(data, eocd + 10)
  let cd_off = z_u32(data, eocd + 16)
  if cd_off < 0 || cd_off + 4 > n {
    eprintln(
      "error: zip: 中央目录偏移异常（≥2GiB 或越界，不支持）",
    )
    return ([] : Array[ZEntry])
  }
  let out : Array[ZEntry] = []
  let mut pos = cd_off
  let mut k = 0
  while k < count {
    if pos + 46 > n || z_u32(data, pos) != 0x02014b50 {
      eprintln("error: zip: 中央目录记录签名异常（entry \{k}）")
      return ([] : Array[ZEntry])
    }
    let comp = z_u16(data, pos + 10)
    let csize = z_u32(data, pos + 20)
    let usize = z_u32(data, pos + 24)
    let name_len = z_u16(data, pos + 28)
    let extra_len = z_u16(data, pos + 30)
    let cmt_len = z_u16(data, pos + 32)
    let local_off = z_u32(data, pos + 42)
    if csize < 0 || usize < 0 || local_off < 0 {
      eprintln(
        "error: zip: 条目尺寸/偏移 ≥2GiB（不支持）：entry \{k}",
      )
      return ([] : Array[ZEntry])
    }
    if pos + 46 + name_len > n {
      eprintln("error: zip: 条目名越界（entry \{k}）")
      return ([] : Array[ZEntry])
    }
    let name = z_str(z_slice(data, pos + 46, name_len))
    out.push(ZEntry::{ name, usize, csize, comp, local_off, })
    pos = pos + 46 + name_len + extra_len + cmt_len
    k = k + 1
  }
  out
}

///|
/// 按条目提取负载（Store/Deflate；跳过 extra 区域、不遍历 extra 链）。
/// 返回空 `Bytes` 并打印错误表示提取失败（调用方按退出码 1 处理）。
fn zip_min_extract(data : Bytes, e : ZEntry) -> Bytes raise {
  let lo = e.local_off
  if lo < 0 || lo + 30 > data.length() || z_u32(data, lo) != 0x04034b50 {
    eprintln("error: zip: local 头异常：\{e.name}")
    return b""
  }
  let name_len = z_u16(data, lo + 26)
  let extra_len = z_u16(data, lo + 28)
  let start = lo + 30 + name_len + extra_len
  if start < 0 || start + e.csize > data.length() {
    eprintln("error: zip: 条目负载越界：\{e.name}")
    return b""
  }
  if e.comp == 0 {
    z_slice(data, start, e.csize)
  } else if e.comp == 8 {
    // 解压上限取中央目录 usize（防御 zip 炸弹；usize 未知时退化为 1GiB）
    @flate.inflate_exact(
      z_slice(data, start, e.csize).clamped_view(),
      max_output=if e.usize > 0 { e.usize } else { 1073741824 },
    )
  } else {
    eprintln("error: zip: 不支持的压缩方法 \{e.comp}：\{e.name}")
    b""
  }
}
