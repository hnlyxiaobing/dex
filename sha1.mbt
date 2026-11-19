///|
/// SHA-1 轮函数左旋（`UInt` 为 32 位无符号，`>>` 为逻辑右移；wasm/native 同语义）。
fn sha1_rotl(x : UInt32, n : Int32) -> UInt32 {
  (x << n) | (x >> (32 - n))
}

///|
/// 纯 MoonBit SHA-1（RFC 3174）：对 `data[start..]` 计算摘要，返回 20 字节大端。
/// 仅作 DEX header 的格式完整性校验，非安全签名用途。
fn sha1_from(data : Bytes, start : Int32) -> Bytes {
  let n = data.length() - start
  let padded_len = (n + 9 + 63) / 64 * 64
  let buf : Array[Byte] = Array::make(padded_len, b'\x00')
  for i in 0..<n {
    buf[i] = data[start + i]
  }
  buf[n] = b'\x80'
  // 末端 8 字节大端写入消息位长
  let bit_len = n.to_uint64() * 8
  for i in 0..<8 {
    let shift = (7 - i) * 8
    buf[padded_len - 8 + i] = ((bit_len >> shift).to_uint() & 0xffU).to_byte()
  }
  let mut h0 = 0x67452301U
  let mut h1 = 0xefcdab89U
  let mut h2 = 0x98badcfeU
  let mut h3 = 0x10325476U
  let mut h4 = 0xc3d2e1f0U
  let w : Array[UInt32] = Array::make(80, 0U)
  for block in 0..<(padded_len / 64) {
    let base = block * 64
    for i in 0..<16 {
      let j = base + i * 4
      // 每字节都 `& 0xFFU` 掩码，与 parse.mbt 的 read_u32u 模式一致，
      // 确保无符号语义——即便 to_int() 在某些后端发生符号扩展也不会污染高位。
      w[i] = ((buf[j].to_int().reinterpret_as_uint() & 0xFFU) << 24) |
        ((buf[j + 1].to_int().reinterpret_as_uint() & 0xFFU) << 16) |
        ((buf[j + 2].to_int().reinterpret_as_uint() & 0xFFU) << 8) |
        (buf[j + 3].to_int().reinterpret_as_uint() & 0xFFU)
    }
    for i in 16..<80 {
      w[i] = sha1_rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1)
    }
    let mut a = h0
    let mut b = h1
    let mut c = h2
    let mut d = h3
    let mut e = h4
    for i in 0..<80 {
      let fk = if i < 20 {
        ((b & c) | ((b ^ 0xffffffffU) & d), 0x5a827999U)
      } else if i < 40 {
        (b ^ c ^ d, 0x6ed9eba1U)
      } else if i < 60 {
        ((b & c) | (b & d) | (c & d), 0x8f1bbcdcU)
      } else {
        (b ^ c ^ d, 0xca62c1d6U)
      }
      let temp = sha1_rotl(a, 5) + fk.0 + e + fk.1 + w[i]
      e = d
      d = c
      c = sha1_rotl(b, 30)
      b = a
      a = temp
    }
    h0 = h0 + a
    h1 = h1 + b
    h2 = h2 + c
    h3 = h3 + d
    h4 = h4 + e
  }
  let out : Array[Byte] = Array::make(20, b'\x00')
  let hs : Array[UInt32] = [h0, h1, h2, h3, h4]
  for i in 0..<5 {
    out[i * 4] = (hs[i] >> 24).to_byte()
    out[i * 4 + 1] = (hs[i] >> 16).to_byte()
    out[i * 4 + 2] = (hs[i] >> 8).to_byte()
    out[i * 4 + 3] = hs[i].to_byte()
  }
  Bytes::from_array(out)
}

///|
/// 计算 `data[32..]` 的 SHA-1 并与 header[12..32] 的 signature 比对。
///
/// - 参数：`data` 为完整 DEX 文件字节（至少 32 字节）。
/// - 返回：一致为 `true`，否则 `false`（值化，不抛 checksum 类错误）。
/// - 错误：不足 32 字节抛 `DexError::UnexpectedEof(32)`。
/// - 非目标：不校验 adler32、不影响 `parse` 结果、不做 APK 签名验签。
/// - 注意：SHA-1 在此仅作格式完整性校验，「通过」不等于来源可信。
pub fn signature_ok(data : Bytes) -> Bool raise DexError {
  if data.length() < 32 {
    raise DexError::UnexpectedEof(32)
  }
  let digest = sha1_from(data, 32)
  let mut ok = true
  for i in 0..<20 {
    if data[12 + i] != digest[i] {
      ok = false
    }
  }
  ok
}
