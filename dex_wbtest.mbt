// Whitebox tests run within the package scope.
// Use them to validate internal helpers or invariants.
// Keep them focused; public behavior belongs in `_test.mbt`.
//
// 本文件覆盖内部原语：uleb128 / sleb128、MUTF-8、adler32、指令表完整性、
// 指令解码（含 payload）与 debug_info 流长度。

///|
/// assert_true 的包装：msg 为可选标签参数。
fn check(cond : Bool, msg? : StringView) -> Unit raise {
  match msg {
    Some(m) => assert_true(cond, msg=m)
    None => assert_true(cond)
  }
}

///|
/// assert_eq 的包装：msg 为可选标签参数。
fn[T : Eq + Debug] check_eq(a : T, b : T, msg? : String) -> Unit raise {
  match msg {
    Some(m) => assert_eq(a, b, msg=m)
    None => assert_eq(a, b)
  }
}

///|
/// uleb128：典型值、截断与 32 位溢出。
test "try_uleb128" {
  check(try_uleb128(b"\x00", 0) is Some((0, 1)))
  check(try_uleb128(b"\x7f", 0) is Some((127, 1)))
  check(try_uleb128(b"\x80\x01", 0) is Some((128, 2)))
  check(try_uleb128(b"\xe5\x8e\x26", 0) is Some((624485, 3)))
  check(try_uleb128(b"\xff\xff\xff\xff\x0f", 0) is Some((-1, 5)))
  check(try_uleb128(b"\x80", 0) is None, msg="truncated")
  check(try_uleb128(b"\x80\x80\x80\x80\x80", 0) is None, msg="overflow")
  check(try_uleb128(b"\x80\x80\x80\x80\x10", 0) is None, msg="33-bit")
}

///|
/// sleb128：正负值、截断。
test "try_sleb128" {
  check(try_sleb128(b"\x02", 0) is Some((2, 1)))
  check(try_sleb128(b"\x7f", 0) is Some((-1, 1)))
  check(try_sleb128(b"\xc0\xbb\x78", 0) is Some((-123456, 3)))
  check(try_sleb128(b"\xe5\x8e\x26", 0) is Some((624485, 3)))
  check(try_sleb128(b"\x80", 0) is None, msg="truncated")
}

///|
/// MUTF-8：ASCII、NUL（0xC0 0x80）、3 字节序列与非法序列。
test "try_mutf8" {
  check(try_mutf8(b"abc\x00", 0) is Some(("abc", 4)))
  let nul = match try_mutf8(b"\xc0\x80\x00", 0) {
    Some((s, _)) => s
    None => fail("expected decode")
  }
  check_eq(nul.to_array().length(), 1, msg="one UTF-16 unit")
  check_eq(nul.to_array()[0].to_int(), 0, msg="encoded NUL")
  check(try_mutf8(b"\xe4\xb8\xad\x00", 0) is Some(("中", 4)), msg="3-byte")
  check(try_mutf8(b"\xc0\x00", 0) is None, msg="bad continuation")
  check(try_mutf8(b"\xff\x00", 0) is None, msg="invalid lead byte")
  check(try_mutf8(b"\xe4\xb8", 0) is None, msg="truncated")
}

///|
/// adler32 已知向量（DEX checksum 算法）。
test "adler32 known vector" {
  check_eq(adler32(b"abc", 0, 3), 0x024D0127U)
  check_eq(adler32(b"", 0, 0), 1U)
}

///|
/// 十六进制与 smali 字面量格式。
test "hex and literal formatting" {
  check_eq(hex_u(0x1234U, 1), "1234")
  check_eq(hex_u(0x1U, 4), "0001")
  check_eq(hex_u(0U, 1), "0")
  check_eq(fmt_sint(0), "#+0x0")
  check_eq(fmt_sint(1), "#+0x1")
  check_eq(fmt_sint(-1), "#-0x1")
  check_eq(fmt_sint(-255), "#-0xff")
  check_eq(fmt_off(5), "+0x5")
  check_eq(fmt_off(-3), "-0x3")
  check_eq(fmt_sint64([0x0001, 0, 0, 0]), "#+0x1")
  check_eq(fmt_sint64([0, 0, 0, 0x8000]), "#-0x8000000000000000")
  check_eq(fmt_sint64([0, 0, 0, 0]), "#+0x0")
}

///|
/// 指令表完整性：0x00–0xE2 中恰有 218 条已定义指令，未定义 / 超范围为 None。
test "opcode table completeness" {
  let mut defined = 0
  for op in 0..<256 {
    if opcode_info(op) is Some(_) {
      defined = defined + 1
      check(op <= 0xe2, msg="no opcode beyond 0xE2")
    }
  }
  check_eq(defined, 218, msg="AOSP defined opcodes 0x00-0xE2")
  check(opcode_info(0x3e) is None, msg="unused 0x3E")
  check(opcode_info(0x73) is None, msg="unused 0x73")
  check(opcode_info(0xe2) is Some(_), msg="last defined opcode")
  check(opcode_info(0xfa) is None, msg="0xFA out of declared scope (W3)")
  check_eq(fmt_width(F51l), 5)
  check_eq(fmt_width(F35c), 3)
  check_eq(fmt_width(F10x), 1)
}

///|
/// 指令解码：const/4 + return-void。
test "decode_insns basics" {
  let ctx = Ctx::{
    strings: [],
    types: [],
    protos: [],
    fields: [],
    methods: [],
  }
  let insns = decode_insns(ctx, 0x70, 0, 2, b"\x12\x10\x0e\x00")
  check_eq(insns.length(), 2)
  check_eq(insns[0].offset, 0)
  check_eq(insns[0].opcode, 0x12)
  check_eq(insns[0].mnemonic, "const/4")
  check_eq(insns[0].operands[0], "v0")
  check_eq(insns[0].operands[1], "#+0x1")
  check_eq(insns[0].raw.length(), 2, msg="raw bytes")
  check_eq(insns[1].mnemonic, "return-void")
  check_eq(insns[1].offset, 1)
}

///|
/// 指令解码：invoke-virtual 的寄存器列表与 method@ 引用解析。
test "decode_insns invoke with refs" {
  let ctx = Ctx::{
    strings: ["LTest;", "V", "foo"],
    types: ["LTest;", "V"],
    protos: [ProtoId::{ shorty: "V", return_type: "V", parameters: [], }],
    fields: [],
    methods: [
      MethodDef::{
        class_index: 0,
        name_index: 2,
        proto_index: 0,
        access_flags: 0U,
        code_off: 0,
        code: None,
      },
    ],
  }
  let insns = decode_insns(ctx, 0x70, 0, 3, b"\x6e\x20\x00\x00\x10\x00")
  check_eq(insns.length(), 1)
  check_eq(insns[0].mnemonic, "invoke-virtual")
  check_eq(insns[0].operands[0], "{v0, v1}")
  check_eq(insns[0].operands[1], "LTest;->foo()V")
}

///|
/// 指令解码：packed-switch-payload 数据块整体跳过。
test "decode_insns payload" {
  let ctx = Ctx::{
    strings: [],
    types: [],
    protos: [],
    fields: [],
    methods: [],
  }
  let data = b"\x00\x01\x02\x00\x00\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00"
  let insns = decode_insns(ctx, 0x70, 0, 8, data)
  check_eq(insns.length(), 1, msg="payload is one pseudo-instruction")
  check_eq(insns[0].mnemonic, "packed-switch-payload")
  check_eq(insns[0].offset, 0)
  check_eq(insns[0].raw.length(), 16, msg="whole payload in raw")
  check_eq(insns[0].operands[0], "size=2")
}

///|
/// 指令解码：未定义 opcode → InvalidInstruction。
test "decode_insns invalid opcode" {
  let ctx = Ctx::{
    strings: [],
    types: [],
    protos: [],
    fields: [],
    methods: [],
  }
  let mut got = false
  ignore(decode_insns(ctx, 0x70, 0, 1, b"\x3e\x00")) catch {
    DexError::InvalidInstruction(off, op) => {
      check_eq(off, 0)
      check_eq(op, 0x3e)
      got = true
    }
    _ => ()
  }
  check(got, msg="expected InvalidInstruction")
}

///|
/// debug_info 流长度：序言 + 普通/扩展 opcode 到 END_SEQUENCE。
test "debug_stream_len" {
  check_eq(debug_stream_len(b"\x02\x01\x00", 0), 3)
  // line_start=1, params=0；ADVANCE_PC 5；ADVANCE_LINE +2；END
  check_eq(debug_stream_len(b"\x02\x01\x01\x05\x02\x02\x00", 0), 7)
  // START_LOCAL（3 个 uleb）；END
  check_eq(debug_stream_len(b"\x02\x01\x03\x00\x01\x02\x00", 0), 7)
  let mut got = false
  ignore(debug_stream_len(b"\x02", 0)) catch {
    DexError::BadDebugInfo(_, _) => got = true
    _ => ()
  }
  check(got, msg="expected BadDebugInfo")
}
