///|
/// CLI 公共辅助（dex-cli）：JSON 转义、hex/签名/magic/proto 渲染。
/// 仅使用 moonbitlang/core 与本模块公开 API；渲染口径与
/// dexdump 规范化黄金一致（黄金值内嵌于测试，见 tests/ASSETS.md §2）。

///|
/// JSON 字符串转义（RFC 8259 最小充分子集：引号、反斜杠、控制字符）。
fn json_escape(s : String) -> String {
  let out : Array[String] = []
  out.push("\"")
  for c in s.iter() {
    let v = c.to_int()
    if c == '"' {
      out.push("\\\"")
    } else if c == '\\' {
      out.push("\\\\")
    } else if c == '\n' {
      out.push("\\n")
    } else if c == '\r' {
      out.push("\\r")
    } else if c == '\t' {
      out.push("\\t")
    } else if v < 0x20 {
      out.push("\\u" + json_hex4(v))
    } else {
      out.push(c.to_string())
    }
  }
  out.push("\"")
  str_join(out)
}

///|
/// 四位小写十六进制（JSON \uXXXX 用）。
fn json_hex4(v : Int32) -> String {
  let digits = "0123456789abcdef"
  let mut s = ""
  let mut x = v
  let mut n = 0
  while n < 4 {
    let d = x & 0xF
    s = digits[d:d + 1].to_owned() + s
    x = x >> 4
    n = n + 1
  }
  s
}

///|
/// 片段拼接为字符串（无分隔符；JSON 构造用）。
fn str_join(parts : Array[String]) -> String {
  let mut s = ""
  for l in parts {
    s = s + l
  }
  s
}

///|
/// 文本行拼接（`\n` 分隔；帮助文本用）。
fn join_lines(lines : Array[String]) -> String {
  let mut s = ""
  let mut first = true
  for l in lines {
    if first {
      first = false
    } else {
      s = s + "\n"
    }
    s = s + l
  }
  s
}

///|
/// 无符号小写十六进制（至少 `min` 位；dexdump `0x%04x` 渲染一致）。
fn hex_min(v : UInt32, min : Int32) -> String {
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
  while n < min {
    s = "0" + s
    n = n + 1
  }
  if n == 0 {
    s = "0"
  }
  s
}

///|
/// 八位小写十六进制（checksum 等）。
fn hex8(v : UInt32) -> String {
  hex_min(v, 8)
}

///|
/// 两个十六进制数字（0..255）。
fn hex2(v : Int32) -> String {
  let digits = "0123456789abcdef"
  let hi = (v >> 4) & 0xF
  let lo = v & 0xF
  digits[hi:hi + 1].to_owned() + digits[lo:lo + 1].to_owned()
}

///|
/// dexdump 的 signature 渲染：前 2 字节 hex + "..." + 后 2 字节 hex。
fn sig_short(sig : Bytes) -> String {
  let n = sig.length()
  if n < 4 {
    ""
  } else {
    hex2(sig[0].to_int()) +
    hex2(sig[1].to_int()) +
    "..." +
    hex2(sig[n - 2].to_int()) +
    hex2(sig[n - 1].to_int())
  }
}

///|
/// magic 字段渲染（与 dexdump 的 `'dex\n035\0'` 一致）。
fn magic_str(v : @dex.DexVersion) -> String {
  let digits = match v {
    Dex035 => "035"
    Dex037 => "037"
    Dex038 => "038"
    Dex039 => "039"
    Dex040 => "040"
    Dex041 => "041"
    Unknown(_) => "???"
  }
  "'dex\\n\{digits}\\0'"
}

///|
/// dexdump 的 proto 渲染：`(参数串)返回类型`。
fn proto_str(p : @dex.ProtoId) -> String {
  let mut s = "("
  for x in p.parameters {
    s = s + x
  }
  s + ")" + p.return_type
}

///|
/// `String?` 渲染（None -> 空串）。
fn opt_str(v : String?) -> String {
  match v {
    Some(s) => s
    None => ""
  }
}

///|
/// XrefKind → 黄金口径固定标签（固定标签表；
/// 放 CLI 侧，库内不加 label 方法）。
fn xref_kind_label(kind : @dex.XrefKind) -> String {
  match kind {
    XrefCallVirtual => "call-virtual"
    XrefCallSuper => "call-super"
    XrefCallDirect => "call-direct"
    XrefCallStatic => "call-static"
    XrefCallInterface => "call-interface"
    XrefFieldReadStatic => "field-read-static"
    XrefFieldWriteStatic => "field-write-static"
    XrefFieldReadInstance => "field-read-instance"
    XrefFieldWriteInstance => "field-write-instance"
  }
}
