// Blackbox tests run against the package's public API. Use `@dex` to import.
// Prefer high-level behaviors over implementation details.
// Run `moon test` to execute and `moon test --update` to refresh snapshots.
//
// 本文件以编程方式构造合法 / 畸形 DEX 二进制样本（工作区无真实 APK 资产），
// 覆盖六表、class_def、code_item、方法名提取与 magic / checksum 错误路径。

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
/// 测试用字节流构造器：小端写入 + uleb128 + 补丁。
fn b_u8(arr : Array[Byte], v : Int32) -> Unit {
  arr.push((v & 0xff).to_byte())
}

///|
fn b_u16(arr : Array[Byte], v : Int32) -> Unit {
  b_u8(arr, v & 0xff)
  b_u8(arr, (v >> 8) & 0xff)
}

///|
fn b_u32(arr : Array[Byte], v : Int32) -> Unit {
  b_u16(arr, v & 0xffff)
  b_u16(arr, (v >> 16) & 0xffff)
}

///|
fn b_u16_patch(arr : Array[Byte], off : Int32, v : Int32) -> Unit {
  arr[off] = (v & 0xff).to_byte()
  arr[off + 1] = ((v >> 8) & 0xff).to_byte()
}

///|
fn b_uleb(arr : Array[Byte], value : Int32) -> Unit {
  let mut v = value
  let mut more = true
  while more {
    let mut b = v & 0x7f
    v = v >> 7
    if v != 0 {
      b = b | 0x80
    } else {
      more = false
    }
    b_u8(arr, b)
  }
}

///|
fn b_patch_u32(arr : Array[Byte], off : Int32, v : Int32) -> Unit {
  arr[off] = (v & 0xff).to_byte()
  arr[off + 1] = ((v >> 8) & 0xff).to_byte()
  arr[off + 2] = ((v >> 16) & 0xff).to_byte()
  arr[off + 3] = ((v >> 24) & 0xff).to_byte()
}

///|
fn b_align4(arr : Array[Byte]) -> Unit {
  while arr.length() % 4 != 0 {
    b_u8(arr, 0)
  }
}

///|
/// 测试侧 adler32（与解析器实现独立，用于交叉验证）。
fn b_adler(arr : Array[Byte], start : Int32, end : Int32) -> Int32 {
  let mut a = 1
  let mut b = 0
  let mut i = start
  while i < end {
    a = a + arr[i].to_int()
    if a >= 65521 {
      a = a - 65521
    }
    b = b + a
    if b >= 65521 {
      b = b - 65521
    }
    i = i + 1
  }
  (b << 16) | a
}

///|
fn b_fix_checksum(arr : Array[Byte]) -> Unit {
  b_patch_u32(arr, 0x08, b_adler(arr, 12, arr.length()))
}

///|
/// 取前 n 字节为独立 Bytes（截断样本用）。
fn b_prefix(arr : Array[Byte], n : Int32) -> Bytes {
  let out : Array[Byte] = []
  for i in 0..<n {
    out.push(arr[i])
  }
  Bytes::from_array(out)
}

///|
/// string_data_item：uleb128(utf16_size) + MUTF-8 + 0x00。
fn b_str_item(arr : Array[Byte], s : String) -> Unit {
  b_uleb(arr, s.length())
  for c in s.to_array() {
    let v = c.to_int()
    if v == 0 {
      b_u8(arr, 0xc0)
      b_u8(arr, 0x80)
    } else if v < 0x80 {
      b_u8(arr, v)
    } else if v < 0x800 {
      b_u8(arr, 0xc0 | (v >> 6))
      b_u8(arr, 0x80 | (v & 0x3f))
    } else {
      b_u8(arr, 0xe0 | (v >> 12))
      b_u8(arr, 0x80 | ((v >> 6) & 0x3f))
      b_u8(arr, 0x80 | (v & 0x3f))
    }
  }
  b_u8(arr, 0)
}

///|
/// 测试 fixture：10 字符串 / 4 类型 / 2 原型 / 1 字段 / 3 方法 / 1 类。
/// 方法：0=foo()V（const-string + debug_info）、1=baz(I)V（try/catch）、2=abs()V（abstract，无 code）。
struct Fixture {
  arr : Array[Byte]
  code0_off : Int32
  code1_off : Int32
}

///|
fn build_dex() -> Fixture {
  let strings = [
    "LTest;", "Ljava/lang/Object;", "V", "I", "foo", "bar", "baz", "abs", "Source.java",
    "VI",
  ]
  let arr : Array[Byte] = []
  // header 占位 0x70
  for _ in 0..<0x70 {
    b_u8(arr, 0)
  }
  // magic "dex\n035\0"
  b_patch_u32(arr, 0x00, 0x0a786564)
  b_patch_u32(arr, 0x04, 0x00353330)
  // signature（20 字节 0x11）
  for i in 0..<20 {
    arr[0x0C + i] = (0x11).to_byte()
  }
  b_patch_u32(arr, 0x24, 0x70) // header_size
  b_patch_u32(arr, 0x28, 0x12345678) // endian_tag
  // 六表 header 字段
  b_patch_u32(arr, 0x38, 10) // string_ids_size
  b_patch_u32(arr, 0x3C, 0x70) // string_ids_off
  b_patch_u32(arr, 0x40, 4) // type_ids_size
  b_patch_u32(arr, 0x44, 0x98) // type_ids_off
  b_patch_u32(arr, 0x48, 2) // proto_ids_size
  b_patch_u32(arr, 0x4C, 0xA8) // proto_ids_off
  b_patch_u32(arr, 0x50, 1) // field_ids_size
  b_patch_u32(arr, 0x54, 0xC0) // field_ids_off
  b_patch_u32(arr, 0x58, 3) // method_ids_size
  b_patch_u32(arr, 0x5C, 0xC8) // method_ids_off
  b_patch_u32(arr, 0x60, 1) // class_defs_size
  b_patch_u32(arr, 0x64, 0xE0) // class_defs_off
  // string_ids 表（占位，稍后补丁）
  for _ in 0..<10 {
    b_u32(arr, 0)
  }
  // type_ids 表：类型 0..3 → 字符串 0..3
  for i in 0..<4 {
    b_u32(arr, i)
  }
  // proto_ids：proto0=()V shorty "V"；proto1=(I)V shorty "VI"
  b_u32(arr, 2)
  b_u32(arr, 2)
  b_u32(arr, 0)
  b_u32(arr, 9)
  b_u32(arr, 2)
  b_u32(arr, 0) // parameters_off 稍后补丁
  // field_ids：field0 = LTest;.bar:I
  b_u16(arr, 0)
  b_u16(arr, 3)
  b_u32(arr, 5)
  // method_ids：0=foo()V 1=baz(I)V 2=abs()V
  b_u16(arr, 0)
  b_u16(arr, 0)
  b_u32(arr, 4)
  b_u16(arr, 0)
  b_u16(arr, 1)
  b_u32(arr, 6)
  b_u16(arr, 0)
  b_u16(arr, 0)
  b_u32(arr, 7)
  // class_defs：LTest; extends Ljava/lang/Object; source=Source.java
  b_u32(arr, 0) // class_idx
  b_u32(arr, 1) // access_flags public
  b_u32(arr, 1) // superclass_idx
  b_u32(arr, 0) // interfaces_off 稍后补丁
  b_u32(arr, 8) // source_file_idx
  b_u32(arr, 0) // annotations_off
  b_u32(arr, 0) // class_data_off 稍后补丁
  b_u32(arr, 0) // static_values_off
  // type_list（proto1 参数）：size=1, type_idx=3（I）
  let tl_params_off = arr.length()
  b_u32(arr, 1)
  b_u16(arr, 3)
  b_u16(arr, 0)
  // type_list（interfaces）：size=1, type_idx=1
  let tl_off = arr.length()
  b_u32(arr, 1)
  b_u16(arr, 1)
  b_u16(arr, 0)
  // 补丁：proto1 parameters_off（0xBC）与 class interfaces_off
  b_patch_u32(arr, 0xBC, tl_params_off)
  b_patch_u32(arr, 0xEC, tl_off)
  // string data
  for i in 0..<10 {
    let s_off = arr.length()
    b_patch_u32(arr, 0x70 + i * 4, s_off)
    b_str_item(arr, strings[i])
  }
  b_align4(arr)
  // code_item 0（foo）：const/4 v0,#1 ; const-string v0,"bar" ; return-void
  let code0_off = arr.length()
  b_u16(arr, 1) // registers_size
  b_u16(arr, 0) // ins_size
  b_u16(arr, 0) // outs_size
  b_u16(arr, 0) // tries_size
  b_u32(arr, 0) // debug_info_off 稍后补丁
  b_u32(arr, 4) // insns_size
  b_u16(arr, 0x1012) // const/4 v0, #+0x1
  b_u16(arr, 0x001a) // const-string v0, string@5
  b_u16(arr, 0x0005)
  b_u16(arr, 0x000e) // return-void
  // code_item 1（baz）：const/4 v0,#1 ; throw v0 ; return-void + try/catch
  let code1_off = arr.length()
  b_u16(arr, 2) // registers_size
  b_u16(arr, 1) // ins_size
  b_u16(arr, 0) // outs_size
  b_u16(arr, 1) // tries_size
  b_u32(arr, 0) // debug_info_off
  b_u32(arr, 3) // insns_size
  b_u16(arr, 0x1012) // const/4 v0, #+0x1
  b_u16(arr, 0x0027) // throw v0
  b_u16(arr, 0x000e) // return-void
  b_u16(arr, 0) // padding（insns_size 为奇数 + tries）
  // try_item: start_addr=0, insn_count=2, handler_off=1
  b_u32(arr, 0)
  b_u16(arr, 2)
  b_u16(arr, 1)
  // encoded_catch_handler_list: count=1；handler(size=1, type@1, addr=2)
  b_u8(arr, 1)
  b_u8(arr, 1)
  b_u8(arr, 1)
  b_u8(arr, 2)
  // debug_info（foo）：line_start=1, params=0, END
  b_u8(arr, 0x02)
  b_u8(arr, 0x01)
  b_u8(arr, 0x00)
  b_align4(arr)
  // class_data：1 static field；direct=[foo]；virtual=[baz, abs]
  let class_data_off = arr.length()
  b_uleb(arr, 1) // static_fields_size
  b_uleb(arr, 0) // instance_fields_size
  b_uleb(arr, 1) // direct_methods_size
  b_uleb(arr, 2) // virtual_methods_size
  b_uleb(arr, 0) // field_idx_diff=0
  b_uleb(arr, 8) // access_flags static
  b_uleb(arr, 0) // method_idx_diff=0（foo）
  b_uleb(arr, 1) // public
  b_uleb(arr, code0_off)
  b_uleb(arr, 1) // method_idx_diff=1（baz）
  b_uleb(arr, 1) // public
  b_uleb(arr, code1_off)
  b_uleb(arr, 1) // method_idx_diff=1（abs）
  b_uleb(arr, 0x401) // public abstract
  b_uleb(arr, 0) // 无 code
  // 补丁：class_data_off、code0 debug_info_off
  b_patch_u32(arr, 0xF8, class_data_off)
  b_patch_u32(arr, code0_off + 8, arr.length()) // debug_info 紧随 class_data 之后
  let dbg_off = arr.length()
  b_u8(arr, 0x02)
  b_u8(arr, 0x01)
  b_u8(arr, 0x00)
  ignore(dbg_off)
  // map_list：8 个 map_item
  b_align4(arr)
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
  // header 收尾：map_off / file_size / checksum
  b_patch_u32(arr, 0x34, map_off)
  b_patch_u32(arr, 0x20, arr.length())
  b_fix_checksum(arr)
  Fixture::{ arr, code0_off, code1_off, }
}

///|
fn fixture_bytes(fx : Fixture) -> Bytes {
  Bytes::from_array(fx.arr)
}

///|
/// header 字段与 checksum / signature。
test "parse: header, checksum, signature" {
  let fx = build_dex()
  let dex = @dex.parse(fixture_bytes(fx))
  check(dex.version is @dex.DexVersion::Dex035, msg="version")
  check_eq(dex.file_size, fx.arr.length(), msg="file_size")
  check_eq(dex.header_size, 0x70, msg="header_size")
  check_eq(dex.endian_tag, 0x12345678U, msg="endian_tag")
  check_eq(dex.signature.length(), 20, msg="signature length")
  check_eq(dex.signature.at(0), (0x11).to_byte(), msg="signature content")
  check_eq(
    dex.checksum,
    b_adler(fx.arr, 12, fx.arr.length()).reinterpret_as_uint(),
    msg="checksum",
  )
}

///|
/// 六表之一：string_ids → strings()。
test "parse: string table" {
  let fx = build_dex()
  let dex = @dex.parse(fixture_bytes(fx))
  let strings = dex.strings()
  check_eq(strings.length(), 10, msg="string count")
  check_eq(strings[0], "LTest;")
  check_eq(strings[1], "Ljava/lang/Object;")
  check_eq(strings[4], "foo")
  check_eq(strings[8], "Source.java")
  check_eq(strings[9], "VI")
}

///|
/// 六表之二：type_ids → type_descriptors。
test "parse: type table" {
  let fx = build_dex()
  let dex = @dex.parse(fixture_bytes(fx))
  check_eq(dex.type_descriptors.length(), 4, msg="type count")
  check_eq(dex.type_descriptors[0], "LTest;")
  check_eq(dex.type_descriptors[2], "V")
  check_eq(dex.type_descriptors[3], "I")
}

///|
/// 六表之三：proto_ids。
test "parse: proto table" {
  let fx = build_dex()
  let dex = @dex.parse(fixture_bytes(fx))
  check_eq(dex.protos.length(), 2, msg="proto count")
  check_eq(dex.protos[0].shorty, "V")
  check_eq(dex.protos[0].return_type, "V")
  check_eq(dex.protos[0].parameters.length(), 0, msg="proto0 params")
  check_eq(dex.protos[1].shorty, "VI")
  check_eq(dex.protos[1].parameters.length(), 1, msg="proto1 params")
  check_eq(dex.protos[1].parameters[0], "I")
}

///|
/// 六表之四：field_ids（access_flags 由 class_data 回填）。
test "parse: field table" {
  let fx = build_dex()
  let dex = @dex.parse(fixture_bytes(fx))
  check_eq(dex.fields.length(), 1, msg="field count")
  let f = dex.fields[0]
  check_eq(f.class_index, 0)
  check_eq(f.type_index, 3)
  check_eq(f.name_index, 5)
  check_eq(f.access_flags, 8U, msg="static flag from class_data")
}

///|
/// 六表之五：method_ids + 方法名提取。
test "parse: method table and name extraction" {
  let fx = build_dex()
  let dex = @dex.parse(fixture_bytes(fx))
  let strings = dex.strings()
  check_eq(dex.methods.length(), 3, msg="method count")
  check_eq(strings[dex.methods[0].name_index], "foo")
  check_eq(strings[dex.methods[1].name_index], "baz")
  check_eq(strings[dex.methods[2].name_index], "abs")
  check_eq(dex.methods[0].code_off, fx.code0_off, msg="code_off backfilled")
  check_eq(dex.methods[0].access_flags, 1U)
  check_eq(dex.methods[2].access_flags, 0x401U, msg="abstract method flags")
  check(dex.methods[0].code is Some(_), msg="foo has code")
  check(dex.methods[2].code is None, msg="abs is abstract")
}

///|
/// 六表之六 + class_def 结构化。
test "parse: class_def" {
  let fx = build_dex()
  let dex = @dex.parse(fixture_bytes(fx))
  check_eq(dex.classes.length(), 1, msg="class count")
  let c = dex.classes[0]
  check_eq(c.class_index, 0)
  check_eq(c.type_descriptor, "LTest;")
  check(c.superclass_index is Some(1), msg="superclass")
  check_eq(c.interfaces.length(), 1, msg="interfaces")
  check_eq(c.interfaces[0], 1)
  check(c.source_file is Some("Source.java"), msg="source file")
  check_eq(c.access_flags, 1U)
  check(c.class_data_off > 0, msg="class_data_off")
  check_eq(c.static_fields.length(), 1, msg="static fields")
  check_eq(c.static_fields[0].name_index, 5, msg="field name index")
  check_eq(c.instance_fields.length(), 0, msg="instance fields")
  check_eq(c.direct_methods.length(), 1, msg="direct methods")
  check_eq(c.virtual_methods.length(), 2, msg="virtual methods")
  check_eq(dex.strings()[c.direct_methods[0].name_index], "foo")
  check_eq(dex.strings()[c.virtual_methods[0].name_index], "baz")
  check_eq(dex.strings()[c.virtual_methods[1].name_index], "abs")
}

///|
/// code_item：指令流、try/catch 表、debug_info 原始字节。
test "parse: code_item" {
  let fx = build_dex()
  let dex = @dex.parse(fixture_bytes(fx))
  let c0 = match dex.code(0) {
    Some(c) => c
    None => fail("code(0) should exist")
  }
  check_eq(c0.registers_size, 1)
  check_eq(c0.insns.length(), 3, msg="foo insns")
  check_eq(c0.insns[0].mnemonic, "const/4")
  check_eq(c0.insns[0].operands[0], "v0")
  check_eq(c0.insns[0].operands[1], "#+0x1")
  check_eq(c0.insns[1].mnemonic, "const-string")
  check_eq(c0.insns[1].operands[1], "\"bar\"", msg="resolved string literal")
  check_eq(c0.insns[2].mnemonic, "return-void")
  check_eq(c0.insns[0].offset, 0)
  check_eq(c0.insns[2].offset, 3, msg="const-string occupies 2 units")
  check_eq(c0.tries.length(), 0)
  check_eq(c0.debug_info.length(), 3, msg="debug_info raw bytes")
  check_eq(c0.debug_info.at(0), (0x02).to_byte())
  check_eq(c0.debug_info.at(2), (0x00).to_byte())
  let c1 = match dex.code(1) {
    Some(c) => c
    None => fail("code(1) should exist")
  }
  check_eq(c1.registers_size, 2)
  check_eq(c1.ins_size, 1)
  check_eq(c1.insns.length(), 3, msg="baz insns")
  check_eq(c1.insns[1].mnemonic, "throw")
  check_eq(c1.tries.length(), 1, msg="tries")
  let t = c1.tries[0]
  check_eq(t.start_addr, 0)
  check_eq(t.insn_count, 2)
  check_eq(t.handler_off, 1)
  check(t.catch_type_index is Some(1), msg="catch type")
  check_eq(c1.debug_info.length(), 0, msg="no debug info")
  check(dex.code(2) is None, msg="abstract method has no code")
}

///|
/// map_list 原始字节。
test "parse: map_list raw bytes" {
  let fx = build_dex()
  let dex = @dex.parse(fixture_bytes(fx))
  check_eq(dex.map_list.length(), 4 + 8 * 12, msg="map_list size")
}

///|
/// DexFile::methods 访问器（direct + virtual）。
test "DexFile::methods accessor" {
  let fx = build_dex()
  let dex = @dex.parse(fixture_bytes(fx))
  let ms = dex.methods(0)
  check_eq(ms.length(), 3, msg="direct + virtual")
  let strings = dex.strings()
  check_eq(strings[ms[0].name_index], "foo")
  check_eq(strings[ms[1].name_index], "baz")
  check_eq(strings[ms[2].name_index], "abs")
}

///|
/// 访问器越界 → InvalidIndex。
test "accessors raise InvalidIndex on bad handle" {
  let fx = build_dex()
  let dex = @dex.parse(fixture_bytes(fx))
  let mut code_err = false
  ignore(dex.code(99)) catch {
    @dex.DexError::InvalidIndex(kind, idx) => {
      check(kind is @dex.TableKind::MethodId, msg="code() error kind")
      check_eq(idx, 99)
      code_err = true
    }
    _ => ()
  }
  check(code_err, msg="code(99) should raise")
  let mut methods_err = false
  ignore(dex.methods(5)) catch {
    @dex.DexError::InvalidIndex(kind, idx) => {
      check(kind is @dex.TableKind::ClassDef, msg="methods() error kind")
      check_eq(idx, 5)
      methods_err = true
    }
    _ => ()
  }
  check(methods_err, msg="methods(5) should raise")
}

///|
/// disasm：带 code 的方法（smali 风格黄金输出）。
test "disasm: method with code" {
  let fx = build_dex()
  let dex = @dex.parse(fixture_bytes(fx))
  let out = @dex.disasm(dex, 0)
  let expected = ".class public LTest;\n" +
    ".method public foo()V\n" +
    "    .registers 1\n" +
    "    const/4 v0, #+0x1\n" +
    "    const-string v0, \"bar\"\n" +
    "    return-void\n" +
    ".end method"
  check_eq(out, expected, msg="smali output")
}

///|
/// disasm：abstract 方法（无 code）。
test "disasm: abstract method" {
  let fx = build_dex()
  let dex = @dex.parse(fixture_bytes(fx))
  let out = @dex.disasm(dex, 2)
  let expected = ".class public LTest;\n" +
    ".method public abstract abs()V\n" +
    ".end method"
  check_eq(out, expected, msg="smali output")
}

///|
/// disasm：带参数方法与 throw 指令。
test "disasm: method with parameter and throw" {
  let fx = build_dex()
  let dex = @dex.parse(fixture_bytes(fx))
  let out = @dex.disasm(dex, 1)
  check(out.contains(".method public baz(I)V"), msg="signature")
  check(out.contains(".registers 2"), msg="registers")
  check(out.contains("throw v0"), msg="throw")
  check(out.contains("return-void"), msg="return")
}

///|
/// disasm：非法 handle → InvalidIndex。
test "disasm: invalid handle" {
  let fx = build_dex()
  let dex = @dex.parse(fixture_bytes(fx))
  let mut got = false
  ignore(@dex.disasm(dex, 3)) catch {
    @dex.DexError::InvalidIndex(kind, idx) => {
      check(kind is @dex.TableKind::MethodId)
      check_eq(idx, 3)
      got = true
    }
    _ => ()
  }
  check(got, msg="disasm(3) should raise")
}

///|
/// 错误：magic 非 "dex\n" → BadMagic。
test "error: bad magic" {
  let fx = build_dex()
  let arr = fx.arr.copy()
  arr[1] = (0x58).to_byte() // 'X'
  b_fix_checksum(arr)
  let mut got = false
  ignore(@dex.parse(Bytes::from_array(arr))) catch {
    @dex.DexError::BadMagic(_) => got = true
    _ => ()
  }
  check(got, msg="expected BadMagic")
}

///|
/// 错误：checksum 与内容不符 → BadMagic(checksum mismatch)。
test "error: bad checksum" {
  let fx = build_dex()
  let arr = fx.arr.copy()
  arr[0x200] = (arr[0x200].to_int() ^ 0xff).to_byte() // 破坏 body
  let mut got = false
  ignore(@dex.parse(Bytes::from_array(arr))) catch {
    @dex.DexError::BadMagic(msg) => {
      check(msg.contains("checksum"), msg="message names checksum")
      got = true
    }
    _ => ()
  }
  check(got, msg="expected checksum failure")
}

///|
/// 错误：版本号不在 035–041 → UnsupportedVersion。
test "error: unsupported version" {
  let fx = build_dex()
  let arr = fx.arr.copy()
  arr[6] = (0x32).to_byte() // "032"
  b_fix_checksum(arr)
  let mut got = false
  ignore(@dex.parse(Bytes::from_array(arr))) catch {
    @dex.DexError::UnsupportedVersion(_) => got = true
    _ => ()
  }
  check(got, msg="expected UnsupportedVersion")
}

///|
/// 错误：截断输入 → UnexpectedEof。
test "error: truncated input" {
  let fx = build_dex()
  let mut got = false
  let short = b_prefix(fx.arr, 40)
  ignore(@dex.parse(short)) catch {
    @dex.DexError::UnexpectedEof(_) => got = true
    _ => ()
  }
  check(got, msg="expected UnexpectedEof")
  let mut got2 = false
  let cut = b_prefix(fx.arr, fx.arr.length() - 8)
  ignore(@dex.parse(cut)) catch {
    @dex.DexError::UnexpectedEof(_) => got2 = true
    _ => ()
  }
  check(got2, msg="expected UnexpectedEof for file_size mismatch")
}

///|
/// 错误：ZIP/APK 容器或多 dex 拼接 → MultiDexNotMerged。
test "error: multi-dex / container input" {
  let mut got = false
  let zip = Bytes::from_array([
    (0x50).to_byte(),
    (0x4b).to_byte(),
    (0x03).to_byte(),
    (0x04).to_byte(),
  ])
  ignore(@dex.parse(zip)) catch {
    @dex.DexError::MultiDexNotMerged(_) => got = true
    _ => ()
  }
  check(got, msg="expected MultiDexNotMerged for zip")
  let fx = build_dex()
  let arr = fx.arr.copy()
  arr.push((0x00).to_byte())
  arr.push((0x00).to_byte())
  let mut got2 = false
  ignore(@dex.parse(Bytes::from_array(arr))) catch {
    @dex.DexError::MultiDexNotMerged(_) => got2 = true
    _ => ()
  }
  check(got2, msg="expected MultiDexNotMerged for trailing bytes")
}

///|
/// 错误：表偏移越界 → BadTableOffset。
test "error: bad table offset" {
  let fx = build_dex()
  let arr = fx.arr.copy()
  b_patch_u32(arr, 0x3C, 0x20) // string_ids_off 落进 header
  b_fix_checksum(arr)
  let mut got = false
  ignore(@dex.parse(Bytes::from_array(arr))) catch {
    @dex.DexError::BadTableOffset(kind, off) => {
      check(kind is @dex.TableKind::StringId)
      check_eq(off, 0x20)
      got = true
    }
    _ => ()
  }
  check(got, msg="expected BadTableOffset")
}

///|
/// 错误：表索引越界 → InvalidIndex。
test "error: invalid index" {
  let fx = build_dex()
  let arr = fx.arr.copy()
  b_patch_u32(arr, 0x98, 99) // type_ids[0] 指向不存在的 string
  b_fix_checksum(arr)
  let mut got = false
  ignore(@dex.parse(Bytes::from_array(arr))) catch {
    @dex.DexError::InvalidIndex(kind, idx) => {
      check(kind is @dex.TableKind::StringId)
      check_eq(idx, 99)
      got = true
    }
    _ => ()
  }
  check(got, msg="expected InvalidIndex")
}

///|
/// 错误：未定义 opcode（0x3E）→ InvalidInstruction。
test "error: invalid instruction" {
  let fx = build_dex()
  let arr = fx.arr.copy()
  arr[fx.code0_off + 16] = (0x3e).to_byte()
  b_fix_checksum(arr)
  let mut got = false
  ignore(@dex.parse(Bytes::from_array(arr))) catch {
    @dex.DexError::InvalidInstruction(off, op) => {
      check_eq(off, 0, msg="unit offset")
      check_eq(op, 0x3e, msg="opcode")
      got = true
    }
    _ => ()
  }
  check(got, msg="expected InvalidInstruction")
}

///|
/// 错误：code_item 越界 → BadCodeItem。
test "error: bad code_item" {
  let fx = build_dex()
  let arr = fx.arr.copy()
  b_patch_u32(arr, fx.code0_off + 12, 0x7fffffff) // insns_size 越界
  b_fix_checksum(arr)
  let mut got = false
  ignore(@dex.parse(Bytes::from_array(arr))) catch {
    @dex.DexError::BadCodeItem(off, _) => {
      check_eq(off, fx.code0_off)
      got = true
    }
    _ => ()
  }
  check(got, msg="expected BadCodeItem")
}

///|
/// 错误：try handler_off 无法解析 → BadCodeItem。
test "error: bad handler_off" {
  let fx = build_dex()
  let arr = fx.arr.copy()
  // try_item.handler_off 位于 code1：header 16 + insns 6 + pad 2 + start_addr 4 + insn_count 2
  b_u16_patch(arr, fx.code1_off + 30, 99)
  b_fix_checksum(arr)
  let mut got = false
  ignore(@dex.parse(Bytes::from_array(arr))) catch {
    @dex.DexError::BadCodeItem(_, msg) => {
      check(msg.contains("handler_off"), msg="message names handler_off")
      got = true
    }
    _ => ()
  }
  check(got, msg="expected BadCodeItem for handler_off")
}

///|
/// 错误：debug_info 流截断 → BadDebugInfo。
test "error: bad debug_info" {
  let fx = build_dex()
  let arr = fx.arr.copy()
  let tail = arr.length() - 1 // 指向文件末尾的残缺流
  b_patch_u32(arr, fx.code0_off + 8, tail)
  b_fix_checksum(arr)
  let mut got = false
  ignore(@dex.parse(Bytes::from_array(arr))) catch {
    @dex.DexError::BadDebugInfo(off, _) => {
      check_eq(off, tail)
      got = true
    }
    _ => ()
  }
  check(got, msg="expected BadDebugInfo")
}
